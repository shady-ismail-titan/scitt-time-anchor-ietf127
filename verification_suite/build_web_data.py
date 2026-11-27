#!/usr/bin/env python3
"""Deterministically builds `web/wasm_bundle.js` and `web/presets.js` from
verified clean-room artifacts (`web/scitt_time_anchor.wasm`, `spec_vectors/`,
`interop_matrix/multi_vendor_interop_results.json`,
`verification_suite/z3_formal_proof_report.json`,
`verification_suite/triple_engine_50k_report.json`, and
`draft09_patch/draft-fassbender-scitt-time-anchor-09-proposed.diff`).
"""

from __future__ import annotations

import base64
import datetime as dt
import gzip
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
from typing import Any, Dict, List, Tuple

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


def build_synthetic_slice(
    start_h: int,
    count: int,
    merkle_overrides: Dict[int, bytes],
    base_time: int = 1700000000,
    nbits: int = 0x207FFFFF,
    prev_seed: bytes = b"\x33" * 32,
) -> Dict[str, str]:
    prev = prev_seed
    out: Dict[str, str] = {}
    for i in range(count):
        h = start_h + i
        mr = merkle_overrides.get(h, hashlib.sha256(f"preset-synth-{h}".encode()).digest())
        nt = base_time + i * 600
        raw, dsha = mine_synthetic_header(prev, mr, nt, nbits=nbits)
        out[str(h)] = raw.hex()
        prev = dsha
    return out


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

    sys.path.insert(0, str(ROOT / "scitt_time_anchor_py"))
    from scitt_time_anchor.cbor_scitt import (  # noqa: E402
        CborTag,
        SCITT_RECEIPTS_HEADER_LABEL,
        compute_scitt_ots_tbs_bytes,
        encode_det_cbor,
        parse_cose_sign1_statement,
        parse_proof_bundle_cbor,
    )
    from scitt_time_anchor.cli import evaluate_case  # noqa: E402
    from scitt_time_anchor.ots_parser import (  # noqa: E402
        BITCOIN_ATTESTATION_TAG,
        OP_APPEND,
        OP_HEXLIFY,
        OP_SHA256,
        OTS_MAGIC,
        TAG_ATTESTATION,
        AttestationKind,
        OtsBranch,
        OtsOp,
        OtsProof,
        ots_deserialize,
        ots_serialize,
    )

    v1_parsed = ots_deserialize(v1_ots_raw)
    assert v1_parsed is not None
    v1_btc_br = [b for b in v1_parsed.branches if b.attestation_kind == AttestationKind.BITCOIN][0]
    v1_ops_bytes = bytearray()
    for op in v1_btc_br.ops:
        v1_ops_bytes.append(op.tag)
        if op.tag in (0xF0, 0xF1):
            v1_ops_bytes.extend(encode_varbytes(op.operand))

    by_id = {c["id"]: c for c in z3_vecs["witness_cases"]}

    # Preset 2: Slide 4 Forged Trivial-Target Bitcoin Header Chain (`N17A`)
    n17a_draft = by_id["N17A_FORGED_EASY_MAINNET_CHAIN_DRAFT08"]
    n17a_strict = by_id["N17A_FORGED_EASY_MAINNET_CHAIN_STRICT"]
    ots_n17a = base64.b64decode(n17a_draft["ots_b64"])

    # Preset 3: RFC 8259 Duplicate-Key JSONL Ambiguity (`N19`)
    dup_jsonl_draft = '{"id":"N19_DUP_KEY","mode":"draft08","mode":"strict","min_confirmations":6}'
    dup_jsonl_strict = '{"id":"N19_DUP_KEY","mode":"strict","mode":"draft08","min_confirmations":6}'

    # Preset 4: Non-Deterministic CBOR inside COSE_Sign1 protected header (`N20` divergence witness)
    # Encodes `{1: -7}` with non-minimal 2-byte uint `18 01` (`a1 18 01 26`).
    # `draft08` parses non-minimal CBOR leniently and verifies the matching anchor (`valid`, Step 11);
    # `strict` enforces RFC 8949 Section 4.2 canonical encoding inside `protected_hdr` and rejects (`invalid`, Step 0).
    non_min_prot = b"\xa1\x18\x01\x26"
    cose_payload = b'{"sbom":"pkg:cargo/scitt-time-anchor@2.0.0"}'
    cose_sig = b"\x55" * 64
    receipt_stub = encode_det_cbor(CborTag(18, [b"\xa1\x01\x26", {}, b"\x99" * 32, b"\x44" * 64]))
    nondet_cose = encode_det_cbor(
        CborTag(18, [non_min_prot, {SCITT_RECEIPTS_HEADER_LABEL: [receipt_stub]}, cose_payload, cose_sig])
    )
    nondet_stmt = parse_cose_sign1_statement(nondet_cose, strict_deterministic=False)
    assert nondet_stmt is not None
    assert parse_cose_sign1_statement(nondet_cose, strict_deterministic=True) is None
    tbs_nondet = compute_scitt_ots_tbs_bytes(nondet_stmt, require_receipt=True)
    assert tbs_nondet is not None
    tbs_nondet_hash = hashlib.sha256(tbs_nondet).digest()
    nondet_nonce = b"n20-cbor-strict-01"
    nondet_mr = hashlib.sha256(tbs_nondet_hash + nondet_nonce).digest()
    chain_nondet = build_synthetic_slice(920000, 8, {920000: nondet_mr})
    ots_nondet = ots_serialize(
        OtsProof(
            version=1,
            file_hash_op=OP_SHA256,
            msg=tbs_nondet_hash,
            branches=(
                OtsBranch(
                    ops=(OtsOp(OP_APPEND, nondet_nonce), OtsOp(OP_SHA256)),
                    attestation_kind=AttestationKind.BITCOIN,
                    attestation_tag=BITCOIN_ATTESTATION_TAG,
                    bitcoin_height=920000,
                ),
            ),
        )
    )
    pb_nondet_cbor = encode_det_cbor({
        "ots_proof": ots_nondet,
        "claimed_hash": tbs_nondet_hash.hex(),
        "origin_id": "00000000-0000-4000-8000-000000000020",
        "bitcoin_block_height": 920000,
    })
    nondet_req_draft = {
        "id": "P4_NONDET_CBOR_DRAFT08",
        "mode": "draft08",
        "input_mode": "scitt_ots_ctt",
        "cose_sign1_b64": base64.b64encode(nondet_cose).decode("ascii"),
        "proof_bundle_cbor_b64": base64.b64encode(pb_nondet_cbor).decode("ascii"),
        "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_nondet},
    }
    nondet_req_strict = {**nondet_req_draft, "id": "P4_NONDET_CBOR_STRICT", "mode": "strict"}

    # Preset 5: 6-Byte LEB128 Split-Brain on Real Mainnet Block 957289 (`e9b6ba808008`)
    canon_957289 = encode_varuint(957289)
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

    # Preset 6: 65-Byte OpHexlify (30 consecutive 0xf3 bytes) Amplification Witness
    ots_hexlify_30 = (
        OTS_MAGIC
        + b"\x01\x08"
        + bytes.fromhex(v1_hash_hex)
        + (bytes([OP_HEXLIFY]) * 30)
        + bytes([OP_SHA256, TAG_ATTESTATION])
        + BITCOIN_ATTESTATION_TAG
        + encode_varbytes(canon_957289)
    )

    # Preset 7: Mid-Path OpSHA1 (0x02) 160-Bit Narrow-Pipe Downgrade
    w3_case = by_id["W3_MIDPATH_OPSHA1_DRAFT08"]
    ots_mid_sha1 = base64.b64decode(w3_case["ots_b64"])

    # Preset 8: SCITT RFC 9943 / RFC 9942 (Header 394) / RFC 9921 Unprotected Header Relay
    w7a = by_id["W7A_TRANSPARENT_STMT_HASH_MISMATCH_DRAFT08"]
    w7b = by_id["W7B_SCITT_OTS_CTT_MULTI_RECEIPT_INVARIANT_STRICT"]
    ots_scitt = (
        base64.b64decode(w7b["ots_b64"])
        if "ots_b64" in w7b
        else parse_proof_bundle_cbor(base64.b64decode(w7b["proof_bundle_cbor_b64"]))["ots_proof"]
    )

    # Preset 9: Real Wild Dual-Calendar Mainnet Proof (Blocks 968588 & 968635)
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
            "short_label": "1. Valid Appendix D Receipt",
            "title": "Valid Appendix D.5 Mainnet Block 957289 Receipt (draft08 & strict PASS)",
            "section_cite": "Section 4.1 Steps 1–11, Slide 4 Consensus Targets & Appendix D.3 / D.5",
            "summary": (
                "Verifies the 1,877-byte Appendix D.5 Vector 1 against continuous PoW-validated Bitcoin Mainnet "
                "headers 957278..957300 (post-BIP113 target nBits 0x17021a42 <= 0x181fffff). Confirms 12-block "
                "finality (tip - H + 1), BIP-113 MTP 09:24:46Z (-122s vs printed D.3), and Forward-MTP(H+5) = 10:02:59Z."
            ),
            "wire_kind": "ots",
            "consensus_meta": {
                "chain_label": "Bitcoin Mainnet (Post-BIP113)",
                "nbits_hex": "0x17021a42",
                "height_range": "957278..957300",
                "ceiling_rule": "target <= post-BIP113 max (0x181fffff)",
            },
            "ots_hex": v1_ots_raw.hex(),
            "upstream_js_note": "Decodes H = 957,289; browser-only OTS JS defaults to ignoreBitcoinNode: true",
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
            "id": "preset-2-forged-easy-chain",
            "short_label": "2. Forged Trivial-Target Chain",
            "title": "Slide 4 Forged Easy-Target Bitcoin Header Chain (nBits = 0x207fffff on Mainnet)",
            "section_cite": "IETF 127 Slide 4 Consensus Target Enforcement (Vector N17A)",
            "summary": (
                "Supplies a self-consistent 6-block forged header chain claiming Mainnet genesis ledger_id at trivial "
                "difficulty nBits = 0x207fffff. Baseline draft08 accepts self-referential PoW (valid, Step 11); "
                "strict (v2.0) enforces Bitcoin Mainnet powLimit (0x1d00ffff) and post-BIP113 target ceiling (0x181fffff), "
                "rejecting the forged chain so VALIDATE-HEADER-ON-CHAIN yields unverifiable at Step 8."
            ),
            "wire_kind": "ots",
            "consensus_meta": {
                "chain_label": "Mainnet ID + Forged Trivial Chain",
                "nbits_hex": "0x207fffff",
                "height_range": "957289..957294",
                "ceiling_rule": "REJECTED in strict: 0x207fffff > 0x1d00ffff / 0x181fffff",
            },
            "ots_hex": ots_n17a.hex(),
            "upstream_js_note": "Self-referential sha256d <= 0x207fffff passes without Mainnet powLimit checks",
            "draft08_req": n17a_draft,
            "strict_req": n17a_strict,
            "focus_offset": len(ots_n17a) - 4,
        },
        {
            "id": "preset-3-rfc8259-dup-key",
            "short_label": "3. RFC 8259 Duplicate-Key JSONL",
            "title": "RFC 8259 / I-JSON Duplicate-Key JSONL Ambiguity (REJECTED: bad_json)",
            "section_cite": "I-JSON RFC 7493 Section 2.3 & Cross-Engine JSONL Parser Gate (Vector N19)",
            "summary": (
                "Sends raw JSONL containing duplicate key \"mode\" ({\"id\":\"N19_DUP_KEY\",\"mode\":\"draft08\",\"mode\":\"strict\"}). "
                "Standard parsers silently apply last-key-wins, creating split-brain profile selection across runtimes. "
                "v2.0.0 rejects duplicate keys, floats, NaN, over-i64 ints, lone surrogates, and depth > 64 identically across "
                "Python, Rust, and WASM with deterministic {\"error\": \"bad_json\"}."
            ),
            "wire_kind": "jsonl",
            "consensus_meta": {
                "chain_label": "Pre-Verification JSONL Parser Gate",
                "nbits_hex": "n/a (Step 0 rejected)",
                "height_range": "n/a",
                "ceiling_rule": "RFC 8259 / I-JSON duplicate key rejected -> bad_json",
            },
            "raw_jsonl_preview": dup_jsonl_draft,
            "raw_jsonl_draft08": dup_jsonl_draft,
            "raw_jsonl_strict": dup_jsonl_strict,
            "ots_hex": v1_ots_raw.hex(),
            "upstream_js_note": "Standard JSON.parse silently overwrites earlier duplicate keys (last-key-wins)",
            "draft08_req": {
                "id": "N19_DUP_KEY",
                "mode": "draft08",
                "input_mode": "raw",
                "artifact_b64": v1_art_b64,
                "ots_b64": v1["ots_base64"],
                "claimed_hash": "sha256:" + v1_hash_hex,
                "validated_chain": {"headers_hex": hdr_map_957289},
            },
            "strict_req": {
                "id": "N19_DUP_KEY",
                "mode": "strict",
                "input_mode": "raw",
                "artifact_b64": v1_art_b64,
                "ots_b64": v1["ots_base64"],
                "claimed_hash": "sha256:" + v1_hash_hex,
                "validated_chain": {"headers_hex": hdr_map_957289},
            },
            "focus_offset": 0,
        },
        {
            "id": "preset-4-nondet-cbor-cose",
            "short_label": "4. Non-Deterministic CBOR / COSE",
            "title": "Non-Deterministic CBOR inside COSE_Sign1 Protected Header (RFC 8949 §4.2)",
            "section_cite": "RFC 8949 §4.2 Core Deterministic CBOR & COSE_Sign1 Step 0 Gate (Vector N20)",
            "summary": (
                "Encodes COSE_Sign1 protected_hdr as a1 18 01 26 ({1: -7} using overlong 2-byte CBOR uint 18 01 instead of 01) "
                "with a matching scitt_ots_ctt receipt proof. Baseline draft08 parses the header leniently (valid, Step 11); "
                "strict (v2.0) enforces RFC 8949 deterministic CBOR on COSE protected headers and rejects at Step 0 (invalid)."
            ),
            "wire_kind": "cose",
            "consensus_meta": {
                "chain_label": "Synthetic Regtest (COSE Protected CBOR Gate)",
                "nbits_hex": "0x207fffff (synthetic_regtest)",
                "height_range": "920000..920007",
                "ceiling_rule": "strict rejects non-minimal CBOR uint 18 01 in protected_hdr",
            },
            "cose_hex_preview": nondet_cose.hex(),
            "ots_hex": ots_nondet.hex(),
            "upstream_js_note": "Lenient CBOR decoders accept non-minimal uint 0x18 0x01 inside COSE protected_hdr",
            "draft08_req": nondet_req_draft,
            "strict_req": nondet_req_strict,
            "focus_offset": len(ots_nondet) - 4,
        },
        {
            "id": "preset-5-leb128-split-brain",
            "short_label": "5. 6-Byte LEB128 Split-Brain",
            "title": "6-Byte LEB128 Cross-Runtime Split-Brain (e9 b6 ba 80 80 08 on Mainnet Block 957289)",
            "section_cite": "Section 3.4.2 & Section 4.1 Steps 3 and 6 (Vector N9)",
            "summary": (
                "Replaces canonical 3-byte height e9b63a (957,289) with 6-byte e9b6ba808008. In javascript-opentimestamps "
                "(b & 0x7f) << shift wraps shift = 35 mod 32 to 3, decoding real Mainnet Block 957,289. Python/Rust decode "
                "H = 274,878,864,233 (unverifiable); strict rejects >5-byte LEB128 at Step 3 (invalid)."
            ),
            "wire_kind": "ots",
            "ots_hex": ots_split_957289.hex(),
            "upstream_js_note": "SPLIT-BRAIN: JS (shift & 31) decodes H = 957,289 vs Python/Rust H = 274,878,864,233",
            "draft08_req": {
                "id": "P5_DRAFT08",
                "mode": "draft08",
                "input_mode": "raw",
                "artifact_b64": v1_art_b64,
                "ots_b64": base64.b64encode(ots_split_957289).decode("ascii"),
                "claimed_hash": "sha256:" + v1_hash_hex,
                "validated_chain": {"headers_hex": hdr_map_957289},
                "candidate_store": {"source": "validated_node", "headers_hex": {"957289": hdr_map_957289["957289"]}},
            },
            "strict_req": {
                "id": "P5_STRICT",
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
            "id": "preset-6-op-hexlify",
            "short_label": "6. OpHexlify 34.36 GB Cap",
            "title": "Compact OpHexlify (30 Consecutive 0xf3 Opcodes) Memory Amplification Witness",
            "section_cite": "Section 4.1 Steps 3 and 5 (Vector N12)",
            "summary": (
                "Thirty consecutive unary OpHexlify (0xf3) opcodes double the 32-byte digest buffer at every byte "
                "(32 * 2^30 = 34.36 GB in an unconstrained replay loop). Baseline draft08 refuses 0xf3 in OTS-REPLAY "
                "without allocating memory (unverifiable, Step 8); strict enforces {0x08, 0xf0, 0xf1} and 4,096 B cap at Step 3 (invalid)."
            ),
            "wire_kind": "ots",
            "ots_hex": ots_hexlify_30.hex(),
            "upstream_js_note": "javascript-opentimestamps parses 30 OpHexlify steps; replay attempts 34.36 GB allocation",
            "draft08_req": {
                "id": "P6_DRAFT08",
                "mode": "draft08",
                "input_mode": "raw",
                "artifact_b64": v1_art_b64,
                "ots_b64": base64.b64encode(ots_hexlify_30).decode("ascii"),
                "claimed_hash": "sha256:" + v1_hash_hex,
                "validated_chain": {"headers_hex": hdr_map_957289},
                "candidate_store": {"source": "validated_node", "headers_hex": {"957289": hdr_map_957289["957289"]}},
            },
            "strict_req": {
                "id": "P6_STRICT",
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
            "id": "preset-7-midpath-sha1",
            "short_label": "7. Mid-Path OpSHA1 Narrow-Pipe",
            "title": "Mid-Path 160-Bit OpSHA1 (0x02) Narrow-Pipe Downgrade vs 2^128 Grover Bound",
            "section_cite": "Section 4.1 Step 5, Section 8.8 & Section 8.10 (Vector N13)",
            "summary": (
                "Inserts a 160-bit OpSHA1 (0x02) compression step alongside a valid Bitcoin branch. Baseline draft08 "
                "marks the 0x02 branch unsupported and validates the sibling branch; strict rejects legacy 160-bit "
                "opcodes (0x02, 0x03) at Step 3, preserving a uniform key-free 2^128 quantum Grover security floor."
            ),
            "wire_kind": "ots",
            "ots_hex": ots_mid_sha1.hex(),
            "upstream_js_note": "javascript-opentimestamps executes OpSHA1 (20-byte state) natively inside CryptoOp replay",
            "draft08_req": w3_case,
            "strict_req": by_id["W3_MIDPATH_OPSHA1_STRICT"],
            "focus_offset": 66,
        },
        {
            "id": "preset-8-scitt-cose-394",
            "short_label": "8. SCITT Header 394 Relay",
            "title": "SCITT Transparent Statement Unprotected Header 394 Relay vs Immutable Imprint",
            "section_cite": "Section 3.2, Section 6.3 & Section 6.4 (RFC 9943, RFC 9942 Header 394, RFC 9921 §3.1.1)",
            "summary": (
                "Anchoring raw outer COSE_Sign1 bytes causes Step 2 HASH_MISMATCH (invalid) when a SCITT Transparency "
                "Service attaches receipts in unprotected header 394 (RFC 9942). Computing the imprint over protected, "
                "SHA-256(payload), bstr-wrapped signature (RFC 9921 §3.1.1), and header-394 receipts remains invariant."
            ),
            "wire_kind": "cose",
            "ots_hex": ots_scitt.hex(),
            "upstream_js_note": "Raw COSE_Sign1 outer SHA-256 changes on unprotected header relay -> Step 2 HASH_MISMATCH",
            "draft08_req": w7a,
            "strict_req": w7b,
            "focus_offset": 0,
        },
        {
            "id": "preset-9-wild-multibranch",
            "short_label": "9. Wild Dual-Calendar Mainnet",
            "title": "Wild Dual-Calendar Mainnet Proof (EMILIA x CryptoGeekPT — Blocks 968588 & 968635)",
            "section_cite": "Section 4.1 Steps 5–10 (Real Cross-Organization Mainnet Proof)",
            "summary": (
                "Real multi-branch OpenTimestamps proof anchored independently via two public calendars into Bitcoin Mainnet "
                "Blocks 968588 and 968635. Both draft08 and strict verify PoW + BIP-113 across continuous headers and bind H = 968,588."
            ),
            "wire_kind": "ots",
            "consensus_meta": {
                "chain_label": "Bitcoin Mainnet (Dual Calendar)",
                "nbits_hex": "0x170217b7",
                "height_range": "968577..968642",
                "ceiling_rule": "target <= post-BIP113 max (0x181fffff)",
            },
            "ots_hex": cc1_ots.hex(),
            "upstream_js_note": "Decodes both branches [968588, 968635]; requires local PoW header chain for Step 7b",
            "draft08_req": {
                "id": "P9_DRAFT08",
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
                "id": "P9_STRICT",
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

    # Ground-truth Python check on all generated presets before writing
    assert evaluate_case(presets[0]["draft08_req"])["outcome"] == "valid"
    assert evaluate_case(presets[0]["strict_req"])["outcome"] == "valid"
    assert evaluate_case(presets[1]["draft08_req"])["outcome"] == "valid"
    assert evaluate_case(presets[1]["strict_req"])["outcome"] == "unverifiable"
    assert evaluate_case(presets[3]["draft08_req"])["outcome"] == "valid"
    assert evaluate_case(presets[3]["strict_req"])["outcome"] == "invalid"

    lab_data = b64_fields_to_hex({
        "version": "2.0.0",
        "spec_title": "Bitcoin-Anchored Temporal Proofs",
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
        "// Auto-generated verified dataset for the Offline WASM Byte-Ray Workbench (v2.0.0)\n"
        f"window.SCITT_LAB_DATA = {json.dumps(lab_data, separators=(',', ':'))};\n"
    )

    # Hygiene assertions before writing
    lower_check = presets_js.lower()
    assert "fonts.googleapis" not in lower_check, "Found external font URL in presets.js!"
    assert "fonts.gstatic" not in lower_check, "Found external font CDN in presets.js!"
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
