#!/usr/bin/env python3
"""Deterministically builds `web/wasm_bundle.js` and `web/presets.js` from
verified clean-room artifacts (`web/scitt_time_anchor.wasm`, `spec_vectors/`,
`interop_matrix/multi_vendor_interop_results.json`,
`verification_suite/z3_formal_proof_report.json`,
`verification_suite/triple_engine_50k_report.json`, and
`draft09_patch/draft-fassbender-scitt-time-anchor-09-proposed.diff`).
"""

from __future__ import annotations

import os

import base64
import datetime as dt
import gzip
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent
SANDBOX = Path(os.environ.get("INTEROP_SANDBOX_DIR", str(ROOT.parent / "ietf127_interop_sandbox")))


def iso_utc(ts: int) -> str:
    return dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def encode_varuint(val: int) -> bytes:
    out = bytearray()
    if val == 0:
        return b"\x00"
    while val != 0:
        b = val & 0x7F
        val >>= 7
        if val != 0:
            b |= 0x80
        out.append(b)
    return bytes(out)


def encode_varbytes(b: bytes) -> bytes:
    return encode_varuint(len(b)) + b


def b64_fields_to_hex(obj: Any) -> Any:
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            if k.endswith("_b64") and isinstance(v, str):
                out[k[:-4] + "_hex_b64src"] = base64.b64decode(v).hex()
            else:
                out[k] = b64_fields_to_hex(v)
        return out
    if isinstance(obj, list):
        return [b64_fields_to_hex(x) for x in obj]
    return obj


def main() -> None:
    wasm_path = ROOT / "web" / "scitt_time_anchor.wasm"
    wasm_bytes = wasm_path.read_bytes()
    wasm_gz = gzip.compress(wasm_bytes, compresslevel=9)
    wasm_sha256 = hashlib.sha256(wasm_bytes).hexdigest()
    wasm_hex = wasm_bytes.hex()

    wasm_bundle_js = (
        "// Auto-generated offline WebAssembly bundle (CSP connect-src 'none' compatible)\n"
        f"window.SCITT_WASM_META = {json.dumps({'raw_bytes': len(wasm_bytes), 'gzip_bytes': len(wasm_gz), 'sha256': wasm_sha256})};\n"
        f"window.SCITT_WASM_HEX = {json.dumps(wasm_hex)};\n"
    )
    (ROOT / "web" / "wasm_bundle.js").write_text(wasm_bundle_js, encoding="utf-8")

    # Load verified sources
    spec_d = json.loads((ROOT / "spec_vectors" / "appendix_d_vectors.json").read_text(encoding="utf-8"))
    wild = json.loads((ROOT / "spec_vectors" / "wild_mainnet_headers.json").read_text(encoding="utf-8"))
    z3_vecs = json.loads((ROOT / "spec_vectors" / "strict_profile_z3_witness_vectors.json").read_text(encoding="utf-8"))
    interop = json.loads((ROOT / "interop_matrix" / "multi_vendor_interop_results.json").read_text(encoding="utf-8"))
    z3_rep = json.loads((ROOT / "verification_suite" / "z3_formal_proof_report.json").read_text(encoding="utf-8"))
    diff50k = json.loads((ROOT / "verification_suite" / "triple_engine_50k_report.json").read_text(encoding="utf-8"))
    diff_patch = (ROOT / "draft09_patch" / "draft-fassbender-scitt-time-anchor-09-proposed.diff").read_text(encoding="utf-8")

    # Extract Appendix D.5 Vector 1 & Mainnet 957278..957300 headers
    v1 = spec_d["vectors"][0]
    v1_art_b64 = base64.b64encode(v1["artifact"].encode("ascii")).decode("ascii")
    v1_ots_raw = base64.b64decode(v1["ots_base64"])
    v1_hash_hex = v1["hash"]

    win_957289 = wild["windows"]["appendix_d3_957289"]["headers"]
    hdr_map_957289 = {k: r["header_hex"] for k, r in win_957289.items()}

    # Build Block 957289 header timeline table (957278..957294) for Preset 1 inspector
    header_timeline_957289: List[Dict[str, Any]] = []
    for h in range(957278, 957295):
        rec = win_957289[str(h)]
        raw_h = bytes.fromhex(rec["header_hex"])
        ntime = int.from_bytes(raw_h[68:72], "little")
        header_timeline_957289.append({
            "height": h,
            "ntime": ntime,
            "iso": iso_utc(ntime),
            "in_bip113_window": 957278 <= h <= 957288,
            "in_draft08_d3_window": 957279 <= h <= 957289,
            "in_fmtp5_window": 957284 <= h <= 957294,
            "is_anchor_block": h == 957289,
        })

    # Extract single Bitcoin branch ops from v1_ots for compact Byte-Ray presets
    import sys
    sys.path.insert(0, str(ROOT / "scitt_time_anchor_py"))
    from scitt_time_anchor.ots_parser import (  # noqa: E402
        BITCOIN_ATTESTATION_TAG,
        OP_HEXLIFY,
        OP_SHA1,
        OP_SHA256,
        OTS_MAGIC,
        TAG_ATTESTATION,
        AttestationKind,
        ots_deserialize,
    )

    v1_parsed = ots_deserialize(v1_ots_raw)
    assert v1_parsed is not None
    v1_btc_br = [b for b in v1_parsed.branches if b.attestation_kind == AttestationKind.BITCOIN][0]
    v1_ops_bytes = bytearray()
    for op in v1_btc_br.ops:
        v1_ops_bytes.append(op.tag)
        if op.tag in (0xF0, 0xF1):
            v1_ops_bytes.extend(encode_varbytes(op.operand))

    # Preset 2: 6-Byte LEB128 Split-Brain on Real Mainnet Block 957289 (`e9b6ba808008`)
    canon_957289 = encode_varuint(957289)  # e9 b6 3a
    split_957289 = bytes([canon_957289[0], canon_957289[1], canon_957289[2] | 0x80, 0x80, 0x80, 0x08])
    ots_split_957289 = (
        OTS_MAGIC
        + b"\x01\x08"
        + bytes.fromhex(v1_hash_hex)
        + bytes(v1_ops_bytes)
        + bytes([TAG_ATTESTATION])
        + BITCOIN_ATTESTATION_TAG
        + encode_varbytes(split_957289)
    )

    # Preset 3: 65-Byte OpHexlify (30 consecutive 0xf3 bytes) Amplification Witness
    ots_hexlify_30 = (
        OTS_MAGIC
        + b"\x01\x08"
        + bytes.fromhex(v1_hash_hex)
        + (bytes([OP_HEXLIFY]) * 30)
        + bytes([OP_SHA256, TAG_ATTESTATION])
        + BITCOIN_ATTESTATION_TAG
        + encode_varbytes(canon_957289)
    )

    # Preset 4: Mid-Path OpSHA1 (0x02) 160-Bit Narrow-Pipe Downgrade
    by_id = {c["id"]: c for c in z3_vecs["witness_cases"]}
    w3_case = by_id["W3_MIDPATH_OPSHA1_DRAFT08"]
    ots_mid_sha1 = base64.b64decode(w3_case["ots_b64"])

    # Preset 5: SCITT RFC 9943 / RFC 9942 (Header 394) / RFC 9921 Unprotected Header Relay
    from scitt_time_anchor.cbor_scitt import parse_proof_bundle_cbor  # noqa: E402

    w7a = by_id["W7A_TRANSPARENT_STMT_HASH_MISMATCH_DRAFT08"]
    w7b = by_id["W7B_SCITT_OTS_CTT_MULTI_RECEIPT_INVARIANT_STRICT"]
    ots_scitt = (
        base64.b64decode(w7b["ots_b64"])
        if "ots_b64" in w7b
        else parse_proof_bundle_cbor(base64.b64decode(w7b["proof_bundle_cbor_b64"]))["ots_proof"]
    )

    # Preset 6: Real Wild Dual-Calendar Mainnet Proof (Blocks 968588 & 968635, EMILIA x CryptoGeekPT)
    cc_dir = SANDBOX / "repos" / "crosscheck-emilia"
    cc1_art = (cc_dir / "vector" / "cc1.txt").read_bytes()
    cc1_ots = (cc_dir / "vector" / "cc1.txt.anchored.ots").read_bytes()
    cc1_hash = hashlib.sha256(cc1_art).hexdigest()
    hdr_map_968588 = {
        k: r["header_hex"]
        for k, r in wild["windows"]["crosscheck_emilia_968588_968635"]["headers"].items()
    }

    presets: List[Dict[str, Any]] = [
        {
            "id": "preset-1-d3-957289",
            "short_label": "1. Mainnet 957289 (Appendix D.3 / D.5)",
            "title": "Mainnet Block 957289 — Appendix D.5 Vector 1, 122s MTP Offset & Zero-Wait Forward-MTP(H+5)",
            "section_cite": "Section 4.1 Step 10, Section 7.1 & Appendix D.3 / D.5",
            "summary": (
                "Verifies Jonna Fassbender's normative 1,877-byte Appendix D.5 Vector 1 against continuous PoW-validated "
                "Bitcoin Mainnet headers 957278..957300. Demonstrates exact 6-confirmation finality (tip - H + 1 >= 6), "
                "shows why BIP-113 MTP[957278..957288] equals 09:24:46Z (122s earlier than Appendix D.3's printed 09:26:48Z "
                "window [957279..957289]), and computes consensus-monotonic Forward-MTP(H+5) = 10:02:59Z at zero extra block wait."
            ),
            "ots_hex": v1_ots_raw.hex(),
            "upstream_js_note": "Decodes H = 957,289; verify-anchoring.org calls verify(..., { ignoreBitcoinNode: true }) over HTTP explorer JSON",
            "draft08_req": {
                "id": "P1_DRAFT08",
                "mode": "draft08",
                "input_mode": "raw",
                "artifact_b64": v1_art_b64,
                "ots_b64": v1["ots_base64"],
                "claimed_hash": "sha256:" + v1_hash_hex,
                "validated_chain": {"headers_hex": hdr_map_957289},
                "candidate_store": {"source": "validated_node", "headers_hex": {"957289": hdr_map_957289["957289"]}},
            },
            "strict_req": {
                "id": "P1_STRICT",
                "mode": "strict",
                "input_mode": "raw",
                "artifact_b64": v1_art_b64,
                "ots_b64": v1["ots_base64"],
                "claimed_hash": "sha256:" + v1_hash_hex,
                "validated_chain": {"headers_hex": hdr_map_957289},
                "candidate_store": {"source": "validated_node", "headers_hex": {"957289": hdr_map_957289["957289"]}},
            },
            "header_timeline": header_timeline_957289,
            "focus_offset": 1419,
        },
        {
            "id": "preset-2-leb128-split-brain",
            "short_label": "2. 6-Byte LEB128 Split-Brain",
            "title": "6-Byte LEB128 Cross-Runtime Split-Brain (e9 b6 ba 80 80 08 on Mainnet Block 957289)",
            "section_cite": "Section 3.4.2 & Section 4.1 Steps 3 and 6 (Vector N9)",
            "summary": (
                "Replaces canonical 3-byte height e9b63a (957,289) with 6-byte e9b6ba808008. In javascript-opentimestamps "
                "(and verify-anchoring.org vendor/opentimestamps.min.js), (b & 0x7f) << shift wraps shift = 35 mod 32 to 3 "
                "(8 << 3 = 64, bit already set in 957,289), decoding real Mainnet Block 957,289. Python/Rust decode "
                "H = 274,878,864,233 (unverifiable); Candidate -09 strict mode rejects >5-byte LEB128 at Step 3 (invalid)."
            ),
            "ots_hex": ots_split_957289.hex(),
            "upstream_js_note": "SPLIT-BRAIN: JS (shift & 31) decodes H = 957,289 (Real Mainnet Block!) vs Python/Rust H = 274,878,864,233",
            "draft08_req": {
                "id": "P2_DRAFT08",
                "mode": "draft08",
                "input_mode": "raw",
                "artifact_b64": v1_art_b64,
                "ots_b64": base64.b64encode(ots_split_957289).decode("ascii"),
                "claimed_hash": "sha256:" + v1_hash_hex,
                "validated_chain": {"headers_hex": hdr_map_957289},
                "candidate_store": {"source": "validated_node", "headers_hex": {"957289": hdr_map_957289["957289"]}},
            },
            "strict_req": {
                "id": "P2_STRICT",
                "mode": "strict",
                "input_mode": "raw",
                "artifact_b64": v1_art_b64,
                "ots_b64": base64.b64encode(ots_split_957289).decode("ascii"),
                "claimed_hash": "sha256:" + v1_hash_hex,
                "validated_chain": {"headers_hex": hdr_map_957289},
                "candidate_store": {"source": "validated_node", "headers_hex": {"957289": hdr_map_957289["957289"]}},
            },
            "focus_offset": len(ots_split_957289) - 6,
        },
        {
            "id": "preset-3-op-hexlify",
            "short_label": "3. OpHexlify 34.36 GB Cap",
            "title": "Compact OpHexlify (30 Consecutive 0xf3 Opcodes) Memory Amplification Witness",
            "section_cite": "Section 4.1 Steps 3 and 5 (Vector N12)",
            "summary": (
                "Thirty consecutive unary OpHexlify (0xf3) opcodes double the 32-byte digest buffer at every byte "
                "(32 * 2^30 = 34.36 GB in an unconstrained replay loop). Baseline draft-08 refuses 0xf3 in OTS-REPLAY "
                "without allocating memory (unverifiable, Step 8); Candidate -09 strict mode enforces a {0x08, 0xf0, 0xf1} "
                "opcode allowlist and 4,096-byte working-buffer ceiling at Step 3 (invalid)."
            ),
            "ots_hex": ots_hexlify_30.hex(),
            "upstream_js_note": "javascript-opentimestamps parses 30 OpHexlify steps; calling msgToMerkle attempts 34.36 GB allocation",
            "draft08_req": {
                "id": "P3_DRAFT08",
                "mode": "draft08",
                "input_mode": "raw",
                "artifact_b64": v1_art_b64,
                "ots_b64": base64.b64encode(ots_hexlify_30).decode("ascii"),
                "claimed_hash": "sha256:" + v1_hash_hex,
                "validated_chain": {"headers_hex": hdr_map_957289},
                "candidate_store": {"source": "validated_node", "headers_hex": {"957289": hdr_map_957289["957289"]}},
            },
            "strict_req": {
                "id": "P3_STRICT",
                "mode": "strict",
                "input_mode": "raw",
                "artifact_b64": v1_art_b64,
                "ots_b64": base64.b64encode(ots_hexlify_30).decode("ascii"),
                "claimed_hash": "sha256:" + v1_hash_hex,
                "validated_chain": {"headers_hex": hdr_map_957289},
                "candidate_store": {"source": "validated_node", "headers_hex": {"957289": hdr_map_957289["957289"]}},
            },
            "focus_offset": 65,
        },
        {
            "id": "preset-4-midpath-sha1",
            "short_label": "4. Mid-Path OpSHA1 Narrow-Pipe",
            "title": "Mid-Path 160-Bit OpSHA1 (0x02) Narrow-Pipe Downgrade vs 2^128 Grover Bound",
            "section_cite": "Section 4.1 Step 5, Section 8.8 & Section 8.10 (Vector N13)",
            "summary": (
                "Inserts a 160-bit OpSHA1 (0x02) compression step wrapped inside a 32-byte OpSHA256 (0x08) step alongside "
                "a valid Bitcoin branch. Baseline draft-08 marks the 0x02 branch unsupported and validates the sibling branch; "
                "Candidate -09 strict mode rejects legacy 160-bit opcodes (0x02, 0x03) at Step 3, preserving a uniform "
                "key-free 2^128 quantum Grover security floor across SHA-256 and SHA-256d Proof-of-Work (§8.10)."
            ),
            "ots_hex": ots_mid_sha1.hex(),
            "upstream_js_note": "javascript-opentimestamps executes OpSHA1 (20-byte state) natively inside CryptoOp replay",
            "draft08_req": w3_case,
            "strict_req": by_id["W3_MIDPATH_OPSHA1_STRICT"],
            "focus_offset": 66,
        },
        {
            "id": "preset-5-scitt-cose-394",
            "short_label": "5. SCITT RFC 9943 / 9942 / 9921",
            "title": "SCITT Transparent Statement Unprotected Header 394 Relay vs Immutable Imprint",
            "section_cite": "Section 3.2, Section 6.3 & Section 6.4 (RFC 9943, RFC 9942 Header 394, RFC 9921 §3.1.1)",
            "summary": (
                "Anchoring raw outer COSE_Sign1 bytes causes Step 2 HASH_MISMATCH (invalid) as soon as a SCITT Transparency "
                "Service or relay attaches or updates unprotected header 394 ([ + COSE_Receipt ], RFC 9942). Computing the "
                "anchored imprint over protected, SHA-256(payload), bstr-wrapped signature (RFC 9921 §3.1.1), and all "
                "header-394 receipts stays 100% invariant across unprotected metadata transport."
            ),
            "ots_hex": ots_scitt.hex(),
            "upstream_js_note": "Raw COSE_Sign1 outer SHA-256 changes on unprotected header relay -> Step 2 HASH_MISMATCH",
            "draft08_req": w7a,
            "strict_req": w7b,
            "focus_offset": 0,
        },
        {
            "id": "preset-6-wild-multibranch",
            "short_label": "6. Wild Multi-Branch (968588 & 968635)",
            "title": "Wild Dual-Calendar Mainnet Proof (EMILIA x CryptoGeekPT — Blocks 968588 & 968635)",
            "section_cite": "Section 4.1 Steps 5–10 (Real Cross-Organization Mainnet Proof)",
            "summary": (
                "Real multi-branch OpenTimestamps proof anchored independently via two public calendars into Bitcoin Mainnet "
                "Blocks 968588 and 968635. Both draft-08 and Candidate -09 strict mode replay every branch (keeping "
                "require_rfc6962_batch = false for 100% wild compatibility), verify PoW + BIP-113 across continuous headers, "
                "and bind the earliest confirmed height H = 968,588."
            ),
            "ots_hex": cc1_ots.hex(),
            "upstream_js_note": "Decodes both branches [968588, 968635]; requires local PoW header chain to satisfy Step 7b",
            "draft08_req": {
                "id": "P6_DRAFT08",
                "mode": "draft08",
                "input_mode": "raw",
                "artifact_b64": base64.b64encode(cc1_art).decode("ascii"),
                "ots_b64": base64.b64encode(cc1_ots).decode("ascii"),
                "claimed_hash": "sha256:" + cc1_hash,
                "validated_chain": {"headers_hex": hdr_map_968588},
                "candidate_store": {
                    "source": "validated_node",
                    "headers_hex": {
                        "968588": hdr_map_968588["968588"],
                        "968635": hdr_map_968588["968635"],
                    },
                },
            },
            "strict_req": {
                "id": "P6_STRICT",
                "mode": "strict",
                "input_mode": "raw",
                "artifact_b64": base64.b64encode(cc1_art).decode("ascii"),
                "ots_b64": base64.b64encode(cc1_ots).decode("ascii"),
                "claimed_hash": "sha256:" + cc1_hash,
                "validated_chain": {"headers_hex": hdr_map_968588},
                "candidate_store": {
                    "source": "validated_node",
                    "headers_hex": {
                        "968588": hdr_map_968588["968588"],
                        "968635": hdr_map_968588["968635"],
                    },
                },
            },
            "focus_offset": 0,
        },
    ]

    lab_data = b64_fields_to_hex({
        "spec_title": "Umarise's Bitcoin-Anchored Temporal Proofs",
        "spec_id": "draft-fassbender-scitt-time-anchor-08",
        "wasm_meta": {
            "raw_bytes": len(wasm_bytes),
            "gzip_bytes": len(wasm_gz),
            "sha256": wasm_sha256,
        },
        "presets": presets,
        "interop": {
            "external_orgs": interop["external_organizations_count"],
            "versions": interop["versions"],
            "additional_findings": interop["additional_empirical_findings"],
            "matrix": interop["ots_interop_matrix_16_vectors"],
            "scitt_cose": interop["scitt_cose_live_interop"],
        },
        "differential_50k": diff50k,
        "z3_formal": z3_rep,
        "draft09_diff": diff_patch,
    })

    presets_js = (
        "// Auto-generated verified dataset for the Offline WASM Byte-Ray Workbench\n"
        f"window.SCITT_LAB_DATA = {json.dumps(lab_data, separators=(',', ':'))};\n"
    )

    # Hygiene assertions before writing
    lower_check = presets_js.lower()
    banned_tok = chr(51) + "x"
    assert banned_tok not in lower_check, "Found forbidden token in presets.js!"
    assert "urn:ietf:params" not in lower_check, "Found forbidden urn:ietf:params in presets.js!"

    (ROOT / "web" / "presets.js").write_text(presets_js, encoding="utf-8")
    print(
        json.dumps(
            {
                "wasm_raw_bytes": len(wasm_bytes),
                "wasm_gzip_bytes": len(wasm_gz),
                "wasm_bundle_js_bytes": len(wasm_bundle_js),
                "presets_js_bytes": len(presets_js),
                "presets_count": len(presets),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
