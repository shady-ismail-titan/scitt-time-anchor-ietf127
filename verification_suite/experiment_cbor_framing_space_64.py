#!/usr/bin/env python3
"""Scientific Experiment: 64-Variant CBOR Framing-Space Equivalence & Determinism Study.

Modeled on IETF SCITT draft `draft-templeman-scitt-framing-space-01`, RFC 8949 Section 4.2
(Core Deterministic CBOR), RFC 9052 Section 3 (COSE_Sign1 empty protected header), RFC 9921
Section 3.1.1 (bstr-wrapped signature imprint), and RFC 9942 Section 8 (header 394 receipts).

Systematically constructs all 2^6 = 64 pairwise-distinct CBOR wire encodings of a single
semantic SCITT COSE_Sign1 transparent statement across six independent RFC 8949 / RFC 9052
encoding freedoms:
  Bit 0: CBOR Tag 18 minimal (0xd2) vs overlong 2-byte uint (0xd8 0x12)
  Bit 1: Outer 4-element array minimal (0x84) vs overlong 2-byte length (0x98 0x04)
  Bit 2: Empty protected header canonical b"" (0x40) vs RFC 9052 Sec. 3 non-canonical b"\\xa0" (0x41 0xa0)
  Bit 3: Unprotected header map canonical key order {4: kid, 394: [receipt]} vs reversed {394: [receipt], 4: kid}
  Bit 4: Payload bstr minimal uint8 length (0x58 0x25) vs overlong uint16 length (0x59 0x00 0x25)
  Bit 5: Signature bstr minimal uint8 length (0x58 0x40) vs overlong uint16 length (0x59 0x00 0x40)

Verifies empirically across Python, Native Rust, and Offline WebAssembly (Node V8) with zero
divergences, and measures `scitt_ots_ctt` imprint invariance across unprotected header relays
versus outer `COSE_Sign1` raw-hash breakage.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import time
from typing import Any, Dict, List, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scitt_time_anchor_py"))

from scitt_time_anchor.cbor_scitt import (  # noqa: E402
    CborTag,
    SCITT_RECEIPTS_HEADER_LABEL,
    compute_scitt_ots_tbs_bytes,
    encode_det_cbor,
    parse_cose_sign1_statement,
)
from scitt_time_anchor.cli import evaluate_case  # noqa: E402
from scitt_time_anchor.ots_parser import (  # noqa: E402
    AttestationKind,
    BITCOIN_ATTESTATION_TAG,
    OP_APPEND,
    OP_SHA256,
    OtsBranch,
    OtsOp,
    OtsProof,
    ots_serialize,
)


def mine_synthetic_header(
    prev_hash_internal: bytes,
    merkle_root_internal: bytes,
    ntime: int,
    nbits: int = 0x207FFFFF,
) -> Tuple[bytes, bytes]:
    exp = (nbits >> 24) & 0xFF
    mant = nbits & 0x007FFFFF
    target = mant << (8 * (exp - 3)) if exp > 3 else mant >> (8 * (3 - exp))
    nonce = 0
    while True:
        hdr = struct.pack(
            "<I32s32sIII",
            0x20000000,
            prev_hash_internal,
            merkle_root_internal,
            ntime,
            nbits,
            nonce,
        )
        dsha = hashlib.sha256(hashlib.sha256(hdr).digest()).digest()
        if int.from_bytes(dsha, "little") <= target:
            return hdr, dsha
        nonce += 1


def build_synthetic_chain(
    start_h: int,
    count: int,
    merkle_overrides: Dict[int, bytes],
) -> Dict[str, str]:
    prev = b"\x64" * 32
    out: Dict[str, str] = {}
    for i in range(count):
        h = start_h + i
        mr = merkle_overrides.get(h, hashlib.sha256(f"framing64-{h}".encode()).digest())
        raw, dsha = mine_synthetic_header(prev, mr, 1783600000 + i * 600)
        out[str(h)] = raw.hex()
        prev = dsha
    return out


def make_single_btc_ots(msg_digest: bytes, nonce: bytes, height: int) -> bytes:
    return ots_serialize(
        OtsProof(
            version=1,
            file_hash_op=OP_SHA256,
            msg=msg_digest,
            branches=(
                OtsBranch(
                    ops=(OtsOp(OP_APPEND, nonce), OtsOp(OP_SHA256)),
                    attestation_kind=AttestationKind.BITCOIN,
                    attestation_tag=BITCOIN_ATTESTATION_TAG,
                    bitcoin_height=height,
                ),
            ),
        )
    )


AXES = [
    ("tag18_overlong", "Tag 18 minimal (0xd2) vs overlong 2-byte (0xd8 0x12)"),
    ("array_len_overlong", "Array(4) minimal (0x84) vs overlong (0x98 0x04)"),
    ("empty_prot_a0", 'Empty protected b"" (0x40) vs RFC 9052 Sec. 3 non-canonical b"\\xa0" (0x41 0xa0)'),
    ("unprot_key_order_reversed", "Unprotected map canonical {4, 394} vs reversed {394, 4}"),
    ("payload_len_overlong", "Payload bstr minimal uint8 len (0x58 25) vs overlong uint16 (0x59 00 25)"),
    ("signature_len_overlong", "Signature bstr minimal uint8 len (0x58 40) vs overlong uint16 (0x59 00 40)"),
]


def encode_variant(
    mask: int,
    kid: bytes,
    receipt: bytes,
    payload: bytes,
    signature: bytes,
) -> bytes:
    assert 24 <= len(payload) < 256
    assert 24 <= len(signature) < 256

    tag_bytes = b"\xd8\x12" if (mask & (1 << 0)) else b"\xd2"
    arr_bytes = b"\x98\x04" if (mask & (1 << 1)) else b"\x84"
    prot_bytes = b"\x41\xa0" if (mask & (1 << 2)) else b"\x40"

    kv_kid = encode_det_cbor(4) + encode_det_cbor(kid)
    kv_rcpt = encode_det_cbor(SCITT_RECEIPTS_HEADER_LABEL) + encode_det_cbor([receipt])
    if mask & (1 << 3):
        unprot_bytes = b"\xa2" + kv_rcpt + kv_kid
    else:
        unprot_bytes = b"\xa2" + kv_kid + kv_rcpt

    if mask & (1 << 4):
        payload_cbor = b"\x59" + len(payload).to_bytes(2, "big") + payload
    else:
        payload_cbor = b"\x58" + bytes([len(payload)]) + payload

    if mask & (1 << 5):
        sig_cbor = b"\x59" + len(signature).to_bytes(2, "big") + signature
    else:
        sig_cbor = b"\x58" + bytes([len(signature)]) + signature

    return tag_bytes + arr_bytes + prot_bytes + unprot_bytes + payload_cbor + sig_cbor


def run_triple_engine(cases: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    jsonl = "\n".join(json.dumps(c) for c in cases) + "\n"
    py_res = [evaluate_case(c) for c in cases]

    rs_bin = ROOT / "scitt_time_anchor_rs" / "target" / "release" / "scitt_time_anchor_rs"
    p_rs = subprocess.run([str(rs_bin)], input=jsonl, text=True, capture_output=True, check=True)
    rs_res = [json.loads(line) for line in p_rs.stdout.strip().splitlines()]

    p_wa = subprocess.run(
        ["node", str(ROOT / "verification_suite" / "wasm_batch_eval.mjs")],
        input=jsonl,
        text=True,
        capture_output=True,
        check=True,
    )
    wa_res = [json.loads(line) for line in p_wa.stdout.strip().splitlines()]
    assert len(py_res) == len(rs_res) == len(wa_res) == len(cases)
    return py_res, rs_res, wa_res


def main() -> None:
    t0 = time.perf_counter()

    kid = b"kid-scitt-v3-01"
    receipt = encode_det_cbor(["scitt-rfc9942-transparency-log", b"\xaa" * 32])
    payload = b'{"sbom":"pkg:oci/scitt-anchor@2.0.0"}'  # 37 bytes (0x25)
    signature = b"\x55" * 64  # 64 bytes (0x40)

    variants: List[Dict[str, Any]] = []
    raw_by_mask: Dict[int, bytes] = {}
    for mask in range(64):
        raw = encode_variant(mask, kid, receipt, payload, signature)
        raw_by_mask[mask] = raw
        flags = [AXES[b][0] for b in range(6) if mask & (1 << b)]
        variants.append({
            "mask": mask,
            "bits": f"{mask:06b}",
            "non_canonical_axes": flags,
            "byte_len": len(raw),
            "outer_sha256": hashlib.sha256(raw).hexdigest(),
        })

    # Verify all 64 wire encodings and all 64 outer SHA-256 hashes are pairwise distinct
    unique_wire_bytes = len(set(raw_by_mask.values()))
    unique_outer_hashes = len({v["outer_sha256"] for v in variants})
    assert unique_wire_bytes == 64, f"Expected 64 unique wire encodings, got {unique_wire_bytes}"
    assert unique_outer_hashes == 64, f"Expected 64 unique outer SHA-256 digests, got {unique_outer_hashes}"

    # Check optional third-party stock CBOR decoder (`cbor2`) if installed
    cbor2_available = False
    cbor2_accepted: int | None = None
    try:
        import cbor2  # type: ignore

        cbor2_available = True
        acc = 0
        for mask in range(64):
            try:
                cbor2.loads(raw_by_mask[mask])
                acc += 1
            except Exception:
                pass
        cbor2_accepted = acc
    except ImportError:
        pass

    # Parse checks & TBS imprint clustering across all 64 variants
    draft08_parse_accepted = 0
    strict_parse_accepted = 0
    tbs_imprints_by_mask: Dict[int, str] = {}
    for mask in range(64):
        raw = raw_by_mask[mask]
        st_d08 = parse_cose_sign1_statement(raw, strict_deterministic=False)
        st_str = parse_cose_sign1_statement(raw, strict_deterministic=True)
        if st_d08 is not None:
            draft08_parse_accepted += 1
            tbs = compute_scitt_ots_tbs_bytes(st_d08, require_receipt=True, strict=False)
            assert tbs is not None
            tbs_imprints_by_mask[mask] = hashlib.sha256(tbs).hexdigest()
        if st_str is not None:
            strict_parse_accepted += 1

    assert draft08_parse_accepted == 64, f"draft08 should parse 64/64, got {draft08_parse_accepted}"
    assert strict_parse_accepted == 1, f"strict must accept EXACTLY 1/64, got {strict_parse_accepted}"
    assert parse_cose_sign1_statement(raw_by_mask[0], strict_deterministic=True) is not None

    # Build synthetic chains anchored to canonical variant 0 (both outer SHA-256 and scitt_ots_ctt TBS imprint)
    nonce_outer = b"framing64-outer1"
    outer0_hash = hashlib.sha256(raw_by_mask[0]).digest()
    mr_outer = hashlib.sha256(outer0_hash + nonce_outer).digest()
    chain_outer = build_synthetic_chain(970000, 8, {970000: mr_outer})
    ots_outer = make_single_btc_ots(outer0_hash, nonce_outer, 970000)
    ots_outer_b64 = base64.b64encode(ots_outer).decode("ascii")

    nonce_tbs = b"framing64-tbs001"
    tbs0_hash = bytes.fromhex(tbs_imprints_by_mask[0])
    mr_tbs = hashlib.sha256(tbs0_hash + nonce_tbs).digest()
    chain_tbs = build_synthetic_chain(971000, 8, {971000: mr_tbs})
    ots_tbs = make_single_btc_ots(tbs0_hash, nonce_tbs, 971000)
    ots_tbs_b64 = base64.b64encode(ots_tbs).decode("ascii")

    # Build 256 end-to-end verification cases: 64 variants x {cose_sign1, scitt_ots_ctt} x {draft08, strict}
    cases: List[Dict[str, Any]] = []
    for mask in range(64):
        cose_b64 = base64.b64encode(raw_by_mask[mask]).decode("ascii")
        for mode in ("draft08", "strict"):
            cases.append({
                "id": f"F64_OUTER_{mode.upper()}_{mask:02d}",
                "mode": mode,
                "input_mode": "cose_sign1",
                "cose_sign1_b64": cose_b64,
                "ots_b64": ots_outer_b64,
                "claimed_hash": outer0_hash.hex(),
                "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_outer},
            })
            cases.append({
                "id": f"F64_CTT_{mode.upper()}_{mask:02d}",
                "mode": mode,
                "input_mode": "scitt_ots_ctt",
                "cose_sign1_b64": cose_b64,
                "ots_b64": ots_tbs_b64,
                "claimed_hash": tbs0_hash.hex(),
                "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_tbs},
            })

    # Relay invariance test: 5 canonical unprotected-header relay hops (adding mutable header 777)
    relay_hops = 5
    for hop in range(1, relay_hops + 1):
        relayed_cose = encode_det_cbor(
            CborTag(
                18,
                [
                    b"",
                    {
                        4: kid,
                        SCITT_RECEIPTS_HEADER_LABEL: [receipt],
                        777: f"scitt-relay-hop-{hop}",
                    },
                    payload,
                    signature,
                ],
            )
        )
        relayed_b64 = base64.b64encode(relayed_cose).decode("ascii")
        cases.append({
            "id": f"RELAY_OUTER_STRICT_HOP{hop}",
            "mode": "strict",
            "input_mode": "cose_sign1",
            "cose_sign1_b64": relayed_b64,
            "ots_b64": ots_outer_b64,
            "claimed_hash": outer0_hash.hex(),
            "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_outer},
        })
        cases.append({
            "id": f"RELAY_CTT_STRICT_HOP{hop}",
            "mode": "strict",
            "input_mode": "scitt_ots_ctt",
            "cose_sign1_b64": relayed_b64,
            "ots_b64": ots_tbs_b64,
            "claimed_hash": tbs0_hash.hex(),
            "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_tbs},
        })

    py_res, rs_res, wa_res = run_triple_engine(cases)

    py_rs_div = sum(1 for a, b in zip(py_res, rs_res) if a != b)
    rs_wa_div = sum(1 for a, b in zip(rs_res, wa_res) if a != b)
    py_wa_div = sum(1 for a, b in zip(py_res, wa_res) if a != b)
    total_div = py_rs_div + rs_wa_div + py_wa_div
    assert total_div == 0, f"Triple-engine divergence detected: {total_div}"

    by_id = {r["id"]: r for r in py_res}

    def tally(prefix: str) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for mask in range(64):
            r = by_id[f"{prefix}_{mask:02d}"]
            key = f"{r['outcome']}_step{r['step']}"
            counts[key] = counts.get(key, 0) + 1
        return counts

    outer_d08_tally = tally("F64_OUTER_DRAFT08")
    outer_str_tally = tally("F64_OUTER_STRICT")
    ctt_d08_tally = tally("F64_CTT_DRAFT08")
    ctt_str_tally = tally("F64_CTT_STRICT")

    assert outer_d08_tally == {"valid_step11": 1, "invalid_step2": 63}, outer_d08_tally
    assert outer_str_tally == {"valid_step11": 1, "invalid_step0": 63}, outer_str_tally
    assert ctt_d08_tally == {"valid_step11": 32, "invalid_step2": 32}, ctt_d08_tally
    assert ctt_str_tally == {"valid_step11": 1, "invalid_step0": 63}, ctt_str_tally

    relay_outer_valid = sum(
        1 for hop in range(1, relay_hops + 1) if by_id[f"RELAY_OUTER_STRICT_HOP{hop}"]["outcome"] == "valid"
    )
    relay_ctt_valid = sum(
        1 for hop in range(1, relay_hops + 1) if by_id[f"RELAY_CTT_STRICT_HOP{hop}"]["outcome"] == "valid"
    )
    assert relay_outer_valid == 0
    assert relay_ctt_valid == relay_hops

    unique_tbs_imprints = len(set(tbs_imprints_by_mask.values()))
    assert unique_tbs_imprints == 2  # 32 variants with b"" vs 32 variants with b"\xa0"

    elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
    report = {
        "experiment": "64-Variant CBOR Framing-Space Equivalence & Determinism Study (draft-templeman-scitt-framing-space-01)",
        "version": "2.0.0",
        "axes_count": 6,
        "total_variants": 64,
        "axes": [{"bit": idx, "name": name, "description": desc} for idx, (name, desc) in enumerate(AXES)],
        "uniqueness": {
            "unique_wire_encodings": unique_wire_bytes,
            "unique_outer_sha256_digests": unique_outer_hashes,
            "unique_scitt_ots_ctt_imprints": unique_tbs_imprints,
            "canonical_variant_0_bytes": len(raw_by_mask[0]),
            "max_variant_63_bytes": len(raw_by_mask[63]),
        },
        "parser_acceptance": {
            "cbor2_available": cbor2_available,
            "cbor2_accepted_of_64": cbor2_accepted,
            "draft08_permissive_accepted_of_64": draft08_parse_accepted,
            "strict_v3_accepted_of_64": strict_parse_accepted,
            "strict_v3_rejected_of_64": 64 - strict_parse_accepted,
        },
        "end_to_end_verification_matrix": {
            "cose_sign1_draft08": outer_d08_tally,
            "cose_sign1_strict": outer_str_tally,
            "scitt_ots_ctt_draft08": ctt_d08_tally,
            "scitt_ots_ctt_strict": ctt_str_tally,
        },
        "unprotected_header_relay_invariance": {
            "relay_hops_tested": relay_hops,
            "outer_cose_sign1_valid": relay_outer_valid,
            "scitt_ots_ctt_strict_valid": relay_ctt_valid,
        },
        "triple_engine_parity": {
            "total_cases_executed_per_engine": len(cases),
            "python_vs_rust_divergences": py_rs_div,
            "rust_vs_wasm_divergences": rs_wa_div,
            "python_vs_wasm_divergences": py_wa_div,
            "total_divergences": total_div,
        },
        "sample_variants": [variants[0], variants[1], variants[4], variants[8], variants[63]],
        "elapsed_ms": elapsed_ms,
        "verdict": "PASS",
    }

    report_json_path = ROOT / "verification_suite" / "cbor_framing_space_64_report.json"
    report_json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    md = f"""# 64-Variant CBOR Framing-Space Equivalence & Determinism Study

**Author:** Shady Ismail
**Verifier Release:** `v2.0.0` (Python 3 stdlib, Native Rust `#![forbid(unsafe_code)]`, Offline WebAssembly)
**Specifications:** `draft-templeman-scitt-framing-space-01`, `draft-fassbender-scitt-time-anchor-08`, RFC 8949 Section 4.2, RFC 9052 Section 3, RFC 9921 Section 3.1.1, RFC 9942 Section 8

## 1. Experimental Design

A single semantic SCITT `COSE_Sign1` transparent statement carrying an RFC 9942 Section 8 header `394` receipt and `kid` (`4`) was encoded across all **$2^6 = 64$** combinations of six orthogonal RFC 8949 / RFC 9052 framing freedoms:

| Bit | Axis | Canonical (`0`) | Non-Canonical (`1`) |
| --- | --- | --- | --- |
| 0 | COSE Tag 18 | `0xd2` (1 B) | `0xd8 0x12` (2 B overlong) |
| 1 | Outer Array(4) Length | `0x84` (1 B) | `0x98 0x04` (2 B overlong) |
| 2 | Empty Protected Header (RFC 9052 §3) | `0x40` (`b""`) | `0x41 0xa0` (`b"\\xa0"`) |
| 3 | Unprotected Map Key Order | `{{4: kid, 394: [receipt]}}` | `{{394: [receipt], 4: kid}}` |
| 4 | Payload `bstr` Length (37 B) | `0x58 0x25` | `0x59 0x00 0x25` |
| 5 | Signature `bstr` Length (64 B) | `0x58 0x40` | `0x59 0x00 0x40` |

## 2. Empirical Results

- **Wire & Outer-Hash Explosion:** All **64 / 64** encodings are pairwise distinct (`{len(raw_by_mask[0])}` B to `{len(raw_by_mask[63])}` B) and yield **64 / 64** distinct outer `SHA-256` data hashes.
- **Parser Acceptance:**
  - Permissive `draft08` CBOR/COSE decoder: accepts **64 / 64** (`100%`).
  - `v2.0.0 --mode strict` deterministic decoder (RFC 8949 §4.2 + RFC 9052 §3): accepts **1 / 64** (exclusively variant `000000`) and rejects **63 / 64** (`98.44%`) at Step 0.
- **End-to-End Verification Matrix (`256` variant cases + `10` relay cases = `266` cases per engine):**

| Input Mode & Profile | Valid (Step 11) | Invalid Step 0 (CBOR Gate) | Invalid Step 2 (`HASH_MISMATCH`) |
| --- | ---: | ---: | ---: |
| `cose_sign1` + `draft08` | `1 / 64` | `0 / 64` | `63 / 64` |
| `cose_sign1` + `strict` | `1 / 64` | `63 / 64` | `0 / 64` |
| `scitt_ots_ctt` + `draft08` | `32 / 64` | `0 / 64` | `32 / 64` |
| `scitt_ots_ctt` + `strict` | `1 / 64` | `63 / 64` | `0 / 64` |

- **Imprint Collapse & RFC 9052 §3 Finding:** Under `scitt_ots_ctt`, the 5 outer framing axes (Tag 18 width, Array length width, Unprotected key order, Payload length width, Signature length width) collapse **32** distinct outer `SHA-256` hashes into **1** single invariant commitment. However, encoding an empty protected header as `b"\\xa0"` instead of `b""` (Axis 2) splits the imprint into **2** distinct digests unless RFC 9052 §3 is enforced — directly motivating the `v2.0.0 --mode strict` rejection of `protected_hdr == b"\\xa0"`.
- **Unprotected Header Relay Invariance (`5` transit hops):**
  - Raw outer `cose_sign1`: **0 / 5** valid (breaks with Step 2 `HASH_MISMATCH` on every relay mutation).
  - `scitt_ots_ctt` (`--mode strict`): **5 / 5** valid (`100%` invariant while keeping RFC 9942 header `394` receipts cryptographically bound).
- **Triple-Engine Parity:** **0 divergences** across all `266` cases evaluated independently on Python, Native Rust, and Offline WebAssembly (`elapsed: {elapsed_ms} ms`).
"""
    md_path = ROOT / "verification_suite" / "CBOR_FRAMING_SPACE_64_STUDY.md"
    md_path.write_text(md, encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
