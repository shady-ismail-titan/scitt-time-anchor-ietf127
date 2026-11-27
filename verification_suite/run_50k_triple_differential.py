#!/usr/bin/env python3
"""Stage 3: 50,000-Vector Triple-Engine Differential Verification Harness.

Generates 50,000 deterministic seeded conformance, boundary, and adversarial test cases
across 20 protocol families (2,500 cases each) in both `draft08` and `strict` profiles,
evaluates every vector independently through:
  1. Clean-Room Python Reference Engine (`scitt_time_anchor_py`)
  2. Clean-Room Native Rust CLI Binary (`scitt_time_anchor_rs`, `#![forbid(unsafe_code)]`)
  3. Compiled Offline WebAssembly Binary (`web/scitt_time_anchor.wasm` in Node V8)
and asserts 100.000% 12-field JSON output parity (`0` divergences across 50,000 vectors).
"""

from __future__ import annotations

import base64
from concurrent.futures import ProcessPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import random
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
    OP_HEXLIFY,
    OP_KECCAK256,
    OP_LEGACY_01,
    OP_PREPEND,
    OP_REVERSE,
    OP_RIPEMD160,
    OP_SHA1,
    OP_SHA256,
    OTS_MAGIC,
    OtsBranch,
    OtsOp,
    OtsProof,
    PENDING_ATTESTATION_TAG,
    TAG_ATTESTATION,
    TAG_BRANCH,
    batch_anchor_merkle,
    encode_varbytes,
    encode_varuint,
    ots_deserialize,
    ots_serialize,
)


def _eval_py_chunk(cases_chunk: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [evaluate_case(c) for c in cases_chunk]


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
    start_height: int,
    num_blocks: int,
    merkle_overrides: Dict[int, bytes],
    base_time: int = 1783580000,
    time_overrides: Dict[int, int] | None = None,
    nbits: int = 0x207FFFFF,
    prev_seed: bytes = b"\x11" * 32,
) -> Dict[str, str]:
    prev = prev_seed
    out: Dict[str, str] = {}
    for offset in range(num_blocks):
        h = start_height + offset
        mr = merkle_overrides.get(h, hashlib.sha256(f"blk-{h}".encode()).digest())
        nt = (
            time_overrides[h]
            if (time_overrides and h in time_overrides)
            else (base_time + offset * 600)
        )
        raw, dsha = mine_synthetic_header(prev, mr, nt, nbits=nbits)
        out[str(h)] = raw.hex()
        prev = dsha
    return out


def make_proof(msg: bytes, branches: List[OtsBranch], file_hash_op: int = OP_SHA256) -> bytes:
    return ots_serialize(
        OtsProof(
            version=1,
            file_hash_op=file_hash_op,
            msg=msg,
            branches=tuple(branches),
        )
    )


def make_btc_branch(ops: Tuple[OtsOp, ...], height: int) -> OtsBranch:
    return OtsBranch(
        ops=ops,
        attestation_kind=AttestationKind.BITCOIN,
        attestation_tag=BITCOIN_ATTESTATION_TAG,
        bitcoin_height=height,
    )


def generate_50000_cases(seed: int = 20261115) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    rng = random.Random(seed)
    spec = json.loads((ROOT / "spec_vectors" / "appendix_d_vectors.json").read_text())
    wild = json.loads((ROOT / "spec_vectors" / "wild_mainnet_headers.json").read_text())

    d3_full = {
        k: row["header_hex"]
        for k, row in wild["windows"]["appendix_d3_957289"]["headers"].items()
    }
    # Compact 8-block mainnet slice [957289..957296] for high-throughput cases
    d3_compact8 = {k: v for k, v in d3_full.items() if 957289 <= int(k) <= 957296}
    d3_slices_by_k = {
        k_conf: {
            k: v
            for k, v in d3_full.items()
            if 957288 <= int(k) <= (957289 + k_conf - 1)
        }
        for k_conf in range(1, 13)
    }

    vecs = spec["vectors"]
    base_raws = [base64.b64decode(v["ots_base64"]) for v in vecs]
    base_parsed = [ots_deserialize(r) for r in base_raws]
    assert all(p is not None for p in base_parsed)

    # Pre-mine reusable synthetic chains
    art_fixed = b"ietf127-triple-engine-50k-seed-artifact"
    art_fixed_b64 = base64.b64encode(art_fixed).decode("ascii")
    h_fixed = hashlib.sha256(art_fixed).digest()
    h_fixed_hex = h_fixed.hex()
    nonce_fixed = hashlib.sha256(b"nonce-50k").digest()[:16]
    mr_fixed = hashlib.sha256(h_fixed + nonce_fixed).digest()
    ops_fixed = (OtsOp(OP_APPEND, nonce_fixed), OtsOp(OP_SHA256))
    ots_fixed = make_proof(h_fixed, [make_btc_branch(ops_fixed, 850000)])
    ots_fixed_b64 = base64.b64encode(ots_fixed).decode("ascii")

    nt_inv: Dict[int, int] = {849989 + k: 1699999900 + k for k in range(11)}
    nt_inv[850000] = 1700007007
    for k in range(1, 13):
        nt_inv[850000 + k] = 1700000007 + k
    chain_inv = build_synthetic_chain(
        849989,
        23,
        {850000: mr_fixed, 850001: mr_fixed, 850002: mr_fixed},
        time_overrides=nt_inv,
    )
    chain_inv_compact = {k: v for k, v in chain_inv.items() if 850000 <= int(k) <= 850007}

    # BIP-113 violating chain (block 850000 ntime <= median of 849989..849999)
    nt_bip113_bad = dict(nt_inv)
    nt_bip113_bad[850000] = 1699999900  # <= median(1699999900..1699999910)=1699999905!
    chain_bip113_bad = build_synthetic_chain(
        849989,
        18,
        {850000: mr_fixed},
        time_overrides=nt_bip113_bad,
    )

    slice_short_800k = build_synthetic_chain(800000, 3, {800000: mr_fixed})
    sparse_combo = dict(slice_short_800k)
    sparse_combo.update(chain_inv_compact)

    fork_low_work = build_synthetic_chain(900000, 7, {}, nbits=0x207FFFFF, prev_seed=b"\x31" * 32)
    fork_high_work = build_synthetic_chain(
        900000, 7, {900000: mr_fixed}, nbits=0x201FFFFF, prev_seed=b"\x42" * 32
    )

    nonces_3 = [b"\xaa" * 16, b"\xbb" * 16, b"\xcc" * 16]
    items_3 = [("o1", h_fixed), ("o2", b"\x11" * 32), ("o3", b"\x22" * 32)]
    root_raw3, recs_raw3 = batch_anchor_merkle(items_3, nonces=nonces_3, rfc6962_domain_sep=False)
    root_6962, recs_6962 = batch_anchor_merkle(items_3, nonces=nonces_3, rfc6962_domain_sep=True)
    chain_m_raw = build_synthetic_chain(910000, 7, {910000: root_raw3})
    chain_m_6962 = build_synthetic_chain(910000, 7, {910000: root_6962})

    # Pre-built SCITT COSE_Sign1 & RFC 9942 header 394 envelopes
    prot_bstr = encode_det_cbor({1: -7})
    payload_bstr = b'{"statement":"ietf-127-scitt-time-anchor"}'
    sig_bstr = b"\x5a" * 64
    rcpt1 = encode_det_cbor(["rcpt-log-1", b"\x91" * 32])
    rcpt2 = encode_det_cbor(["rcpt-log-2", b"\x92" * 32])
    cose_bare = encode_det_cbor(CborTag(18, [prot_bstr, {}, payload_bstr, sig_bstr]))
    cose_multi = encode_det_cbor(
        CborTag(
            18,
            [
                prot_bstr,
                {SCITT_RECEIPTS_HEADER_LABEL: [rcpt1, rcpt2], 700: CborTag(1, 1783591379)},
                payload_bstr,
                sig_bstr,
            ],
        )
    )
    stmt_multi = parse_cose_sign1_statement(cose_multi)
    assert stmt_multi is not None
    tbs_multi = compute_scitt_ots_tbs_bytes(stmt_multi, require_receipt=True)
    assert tbs_multi is not None
    tbs_multi_h = hashlib.sha256(tbs_multi).digest()
    mr_tbs_multi = hashlib.sha256(tbs_multi_h + nonce_fixed).digest()
    chain_scitt = build_synthetic_chain(920000, 7, {920000: mr_tbs_multi})
    ots_scitt = make_proof(tbs_multi_h, [make_btc_branch(ops_fixed, 920000)])

    cases: List[Dict[str, Any]] = []
    family_counts: Dict[str, int] = {}
    PER_FAMILY = 2500

    def add_family(fname: str, items: List[Dict[str, Any]]) -> None:
        assert len(items) == PER_FAMILY, f"{fname} generated {len(items)} != {PER_FAMILY}"
        family_counts[fname] = len(items)
        cases.extend(items)

    # F01: Valid Appendix D.5 Mainnet Block 957289 proofs (full 23-header window & compact 8-header window)
    f01 = []
    for i in range(PER_FAMILY):
        v = vecs[i % 4]
        m = "strict" if (i % 2 == 1) else "draft08"
        pref = "sha256:" if (i % 3 == 0) else ""
        hdrs = d3_full if (i % 5 == 0) else d3_compact8
        f01.append({
            "id": f"F01_{i:04d}",
            "mode": m,
            "artifact_b64": base64.b64encode(v["artifact"].encode()).decode(),
            "ots_b64": v["ots_base64"],
            "claimed_hash": pref + v["hash"],
            "validated_chain": {"headers_hex": hdrs},
        })
    add_family("F01_valid_mainnet_d5", f01)

    # F02: Randomized valid synthetic multi-leaf Merkle proofs across heights
    f02 = []
    for i in range(PER_FAMILY):
        m = "strict" if (i % 2 == 1) else "draft08"
        target_h = 850000 + (i % 3)
        f02.append({
            "id": f"F02_{i:04d}",
            "mode": m,
            "artifact_b64": art_fixed_b64,
            "ots_b64": base64.b64encode(
                make_proof(h_fixed, [make_btc_branch(ops_fixed, target_h)])
            ).decode(),
            "claimed_hash": h_fixed_hex,
            "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_inv_compact},
        })
    add_family("F02_valid_synthetic_heights", f02)

    # F03: Truncated .ots byte cuts
    f03 = []
    for i in range(PER_FAMILY):
        v = vecs[i % 4]
        raw = base_raws[i % 4]
        cut = rng.randint(0, len(raw) - 1)
        f03.append({
            "id": f"F03_{i:04d}",
            "mode": "strict" if (i % 2) else "draft08",
            "artifact_b64": base64.b64encode(v["artifact"].encode()).decode(),
            "ots_b64": base64.b64encode(raw[:cut]).decode(),
            "claimed_hash": v["hash"],
            "validated_chain": {"headers_hex": d3_compact8},
        })
    add_family("F03_truncated_ots_cuts", f03)

    # F04: Bit-flipped msg digest, leaf nonce, or Merkle sibling
    f04 = []
    for i in range(PER_FAMILY):
        v = vecs[i % 4]
        p = base_parsed[i % 4]
        assert p is not None
        btc = [b for b in p.branches if b.attestation_kind == AttestationKind.BITCOIN][0]
        if i % 3 == 0:
            bad_msg = bytearray(p.msg)
            bad_msg[rng.randint(0, 31)] ^= 1 << rng.randint(0, 7)
            mut_ots = make_proof(bytes(bad_msg), [btc])
        else:
            ops_list = list(btc.ops)
            bin_idxs = [idx for idx, op in enumerate(ops_list) if op.tag in (OP_APPEND, OP_PREPEND)]
            t_idx = rng.choice(bin_idxs)
            old_op = ops_list[t_idx]
            mut_arg = bytearray(old_op.operand)
            mut_arg[rng.randint(0, len(mut_arg) - 1)] ^= 1 << rng.randint(0, 7)
            ops_list[t_idx] = OtsOp(old_op.tag, bytes(mut_arg))
            mut_ots = make_proof(p.msg, [make_btc_branch(tuple(ops_list), 957289)])
        f04.append({
            "id": f"F04_{i:04d}",
            "mode": "strict" if (i % 2) else "draft08",
            "artifact_b64": base64.b64encode(v["artifact"].encode()).decode(),
            "ots_b64": base64.b64encode(mut_ots).decode(),
            "claimed_hash": v["hash"],
            "validated_chain": {"headers_hex": d3_compact8},
        })
    add_family("F04_bitflip_msg_and_operands", f04)

    # F05: Non-canonical LEB128 varuints (overlong 0xe88700, 6-byte split-brain 80f0b380800a, >64-bit varuints)
    f05 = []
    noncanon_payloads = [
        bytes.fromhex("80f0b380800a"),
        bytes.fromhex("e88700"),
        bytes.fromhex("d0f03300"),
        bytes.fromhex("8080808010"),
        bytes.fromhex("ffffffffffffffffff7f"),
    ]
    for i in range(PER_FAMILY):
        pl = noncanon_payloads[i % len(noncanon_payloads)]
        raw_ots = (
            OTS_MAGIC
            + b"\x01"
            + bytes([OP_SHA256])
            + h_fixed
            + bytes([OP_APPEND])
            + encode_varbytes(nonce_fixed)
            + bytes([OP_SHA256, TAG_ATTESTATION])
            + BITCOIN_ATTESTATION_TAG
            + encode_varbytes(pl)
        )
        f05.append({
            "id": f"F05_{i:04d}",
            "mode": "strict" if (i % 2) else "draft08",
            "artifact_b64": art_fixed_b64,
            "ots_b64": base64.b64encode(raw_ots).decode(),
            "claimed_hash": h_fixed_hex,
            "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_inv_compact},
        })
    add_family("F05_noncanonical_leb128_varuints", f05)

    # F06: OpHexlify amplification & oversized operands (513..4200 bytes)
    f06 = []
    for i in range(PER_FAMILY):
        if i % 2 == 0:
            n_hex = 1 + (i % 35)
            raw_ots = (
                OTS_MAGIC
                + b"\x01"
                + bytes([OP_SHA256])
                + h_fixed
                + (bytes([OP_HEXLIFY]) * n_hex)
                + bytes([OP_SHA256, TAG_ATTESTATION])
                + BITCOIN_ATTESTATION_TAG
                + encode_varbytes(encode_varuint(850000))
            )
        else:
            op_sz = rng.choice([512, 513, 1024, 4096, 4097])
            big_arg = b"\x42" * op_sz
            raw_ots = (
                OTS_MAGIC
                + b"\x01"
                + bytes([OP_SHA256])
                + h_fixed
                + bytes([OP_APPEND])
                + encode_varbytes(big_arg)
                + bytes([OP_SHA256, TAG_ATTESTATION])
                + BITCOIN_ATTESTATION_TAG
                + encode_varbytes(encode_varuint(850000))
            )
        f06.append({
            "id": f"F06_{i:04d}",
            "mode": "strict" if (i % 3 == 0) else "draft08",
            "artifact_b64": art_fixed_b64,
            "ots_b64": base64.b64encode(raw_ots).decode(),
            "claimed_hash": h_fixed_hex,
            "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_inv_compact},
        })
    add_family("F06_op_hexlify_and_operand_caps", f06)

    # F07: Mid-path narrow-pipe & legacy opcodes (0x01, 0x02, 0x03, 0x67, 0xf2) solo & paired
    f07 = []
    legacy_ops = [OP_LEGACY_01, OP_SHA1, OP_RIPEMD160, OP_KECCAK256, OP_REVERSE]
    for i in range(PER_FAMILY):
        op_code = legacy_ops[i % len(legacy_ops)]
        bad_br = make_btc_branch((OtsOp(op_code), OtsOp(OP_SHA256)), 850000)
        branches = [bad_br, make_btc_branch(ops_fixed, 850000)] if (i % 2 == 0) else [bad_br]
        f07.append({
            "id": f"F07_{i:04d}",
            "mode": "strict" if ((i // 2) % 2 == 1) else "draft08",
            "artifact_b64": art_fixed_b64,
            "ots_b64": base64.b64encode(make_proof(h_fixed, branches)).decode(),
            "claimed_hash": h_fixed_hex,
            "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_inv_compact},
        })
    add_family("F07_midpath_narrow_pipe_opcodes", f07)

    # F08: Non-SHA-256 file_hash_op header bytes (0x01, 0x02, 0x03, 0x67, 0x99)
    f08 = []
    hdr_ops = [(OP_LEGACY_01, 20), (OP_SHA1, 20), (OP_RIPEMD160, 20), (OP_KECCAK256, 32), (0x99, 32)]
    for i in range(PER_FAMILY):
        fop, dlen = hdr_ops[i % len(hdr_ops)]
        raw_ots = (
            OTS_MAGIC
            + b"\x01"
            + bytes([fop])
            + h_fixed[:dlen]
            + bytes([OP_SHA256, TAG_ATTESTATION])
            + BITCOIN_ATTESTATION_TAG
            + encode_varbytes(encode_varuint(850000))
        )
        f08.append({
            "id": f"F08_{i:04d}",
            "mode": "strict" if (i % 2) else "draft08",
            "artifact_b64": art_fixed_b64,
            "ots_b64": base64.b64encode(raw_ots).decode(),
            "claimed_hash": h_fixed_hex,
            "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_inv_compact},
        })
    add_family("F08_file_hash_op_mismatch", f08)

    # F09: PendingAttestation URI validation (ALLOWED_URI_CHARS, >1000B cap) & Unknown attestations (>8192B cap)
    f09 = []
    uri_variants = [
        b"https://alice.btc.calendar.opentimestamps.org",
        b"https://calendar.example.org/bad?query=1",
        b"https://calendar.example.org/bad#frag",
        b"https://calendar.example.org/" + (b"a" * 990),  # > 1000 bytes!
        b"",
    ]
    for i in range(PER_FAMILY):
        if i % 3 < 2:
            u = uri_variants[i % len(uri_variants)]
            inner_pl = encode_varbytes(u)
            raw_ots = (
                OTS_MAGIC
                + b"\x01"
                + bytes([OP_SHA256])
                + h_fixed
                + bytes([TAG_ATTESTATION])
                + PENDING_ATTESTATION_TAG
                + encode_varbytes(inner_pl)
            )
        else:
            unk_sz = 16 if (i % 2 == 0) else 8200
            raw_ots = (
                OTS_MAGIC
                + b"\x01"
                + bytes([OP_SHA256])
                + h_fixed
                + bytes([TAG_ATTESTATION])
                + b"\xde\xad\xbe\xef\x01\x02\x03\x04"
                + encode_varbytes(b"\x00" * unk_sz)
            )
        f09.append({
            "id": f"F09_{i:04d}",
            "mode": "strict" if (i % 2) else "draft08",
            "artifact_b64": art_fixed_b64,
            "ots_b64": base64.b64encode(raw_ots).decode(),
            "claimed_hash": h_fixed_hex,
            "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_inv_compact},
        })
    add_family("F09_pending_uri_and_unknown_attestations", f09)

    # F10: Claimed hash formatting & modified artifact mismatches
    f10 = []
    for i in range(PER_FAMILY):
        kind = i % 5
        art_cur = art_fixed_b64
        if kind == 0:
            ch = h_fixed_hex.upper()
        elif kind == 1:
            ch = "sha256:" + h_fixed_hex[:-1] + "g"
        elif kind == 2:
            ch = h_fixed_hex[:62]
        elif kind == 3:
            ch = "SHA256:" + h_fixed_hex
        else:
            ch = h_fixed_hex
            art_cur = base64.b64encode(art_fixed + bytes([i & 0xFF])).decode()
        f10.append({
            "id": f"F10_{i:04d}",
            "mode": "strict" if (i % 2) else "draft08",
            "artifact_b64": art_cur,
            "ots_b64": ots_fixed_b64,
            "claimed_hash": ch,
            "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_inv_compact},
        })
    add_family("F10_claimed_hash_and_artifact_mutations", f10)

    # F11: Missing artifact_b64 commitment-only guard (Step 1 UNVERIFIABLE)
    f11 = []
    for i in range(PER_FAMILY):
        f11.append({
            "id": f"F11_{i:04d}",
            "mode": "strict" if (i % 2) else "draft08",
            "artifact_b64": None,
            "ots_b64": ots_fixed_b64,
            "claimed_hash": h_fixed_hex,
            "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_inv_compact},
        })
    add_family("F11_missing_artifact_guard", f11)

    # F12: Explorer-only / anchoring-service / !=80-byte candidate header store checks
    f12 = []
    for i in range(PER_FAMILY):
        kind = i % 4
        if kind == 0:
            vc = None
            cs = {"source": "public_explorer", "headers_hex": chain_inv_compact}
        elif kind == 1:
            vc = {"ledger_id": "synthetic_regtest", "headers_hex": chain_inv_compact}
            cs = {"source": "anchoring_service", "headers_hex": chain_inv_compact}
        elif kind == 2:
            vc = {"ledger_id": "synthetic_regtest", "headers_hex": chain_inv_compact}
            cs = {"source": "validated_node", "headers_hex": {"850000": "aa" * 79}}  # 79B != 80B!
        else:
            vc = {"ledger_id": "synthetic_regtest", "headers_hex": chain_inv_compact}
            tampered_hdr = "ff" + chain_inv_compact["850000"][2:]
            cs = {"source": "public_explorer", "headers_hex": {"850000": tampered_hdr}}
        f12.append({
            "id": f"F12_{i:04d}",
            "mode": "strict" if (i % 2) else "draft08",
            "artifact_b64": art_fixed_b64,
            "ots_b64": ots_fixed_b64,
            "claimed_hash": h_fixed_hex,
            "validated_chain": vc,
            "candidate_store": cs,
        })
    add_family("F12_explorer_and_candidate_store_checks", f12)

    # F13: Confirmations boundary k = 1..12 on Mainnet Block 957289
    f13 = []
    for i in range(PER_FAMILY):
        k_conf = 1 + (i % 12)
        v = vecs[i % 4]
        f13.append({
            "id": f"F13_{i:04d}",
            "mode": "strict" if (i % 2) else "draft08",
            "artifact_b64": base64.b64encode(v["artifact"].encode()).decode(),
            "ots_b64": v["ots_base64"],
            "claimed_hash": v["hash"],
            "validated_chain": {"headers_hex": d3_slices_by_k[k_conf]},
        })
    add_family("F13_confirmations_boundary_k1_to_k12", f13)

    # F14: BIP-113 consensus violation rejection & Forward-MTP(H+5) +7,000s skew
    f14 = []
    ots_multi_inv = base64.b64encode(
        make_proof(
            h_fixed,
            [make_btc_branch(ops_fixed, 850000), make_btc_branch(ops_fixed, 850001)],
        )
    ).decode()
    for i in range(PER_FAMILY):
        hdrs = chain_bip113_bad if (i % 2 == 0) else chain_inv
        f14.append({
            "id": f"F14_{i:04d}",
            "mode": "strict" if ((i // 2) % 2) else "draft08",
            "artifact_b64": art_fixed_b64,
            "ots_b64": ots_multi_inv,
            "claimed_hash": h_fixed_hex,
            "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": hdrs},
        })
    add_family("F14_bip113_and_forward_mtp_windows", f14)

    # F15: Sparse checkpoint premature argmin (draft08 UNVERIFIABLE vs strict VALID)
    f15 = []
    ots_sparse_b64 = base64.b64encode(
        make_proof(
            h_fixed,
            [make_btc_branch(ops_fixed, 800000), make_btc_branch(ops_fixed, 850000)],
        )
    ).decode()
    for i in range(PER_FAMILY):
        allow_sp = (i % 3) != 0
        f15.append({
            "id": f"F15_{i:04d}",
            "mode": "strict" if (i % 2) else "draft08",
            "artifact_b64": art_fixed_b64,
            "ots_b64": ots_sparse_b64,
            "claimed_hash": h_fixed_hex,
            "validated_chain": {
                "ledger_id": "synthetic_regtest",
                "headers_hex": sparse_combo,
                "allow_sparse_checkpoints": allow_sp,
            },
        })
    add_family("F15_sparse_checkpoint_argmin", f15)

    # F16: SetCompact negative/overflow nBits, Mainnet trivial-target forging, 64-hex min_chainwork, & ChainWork fork selection
    f16 = []
    bad_nbits_vals = [0x1DFBFFFF, 0x23010000, 0x00000000, 0x1D800001]
    ots_900k_b64 = base64.b64encode(
        make_proof(h_fixed, [make_btc_branch(ops_fixed, 900000)])
    ).decode()
    for i in range(PER_FAMILY):
        kind = i % 5
        if kind == 0:
            f16.append({
                "id": f"F16_{i:04d}",
                "mode": "strict" if ((i // 5) % 2) else "draft08",
                "artifact_b64": art_fixed_b64,
                "ots_b64": ots_900k_b64,
                "claimed_hash": h_fixed_hex,
                "candidate_chains": [
                    {"ledger_id": "synthetic_regtest", "headers_hex": fork_low_work},
                    {"ledger_id": "synthetic_regtest", "headers_hex": fork_high_work},
                ],
            })
        elif kind == 1:
            nb = bad_nbits_vals[(i // 5) % len(bad_nbits_vals)]
            bad_hdr = struct.pack("<I32s32sIII", 0x20000000, b"\x00" * 32, mr_fixed, 1700000000, nb, 0)
            f16.append({
                "id": f"F16_{i:04d}",
                "mode": "strict",
                "artifact_b64": art_fixed_b64,
                "ots_b64": ots_900k_b64,
                "claimed_hash": h_fixed_hex,
                "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": {"900000": bad_hdr.hex()}},
            })
        elif kind == 2:
            # Non-64-char min_chainwork_hex rejected cleanly by U256::from_hex / parse_u256_hex_64
            f16.append({
                "id": f"F16_{i:04d}",
                "mode": "strict",
                "artifact_b64": art_fixed_b64,
                "ots_b64": ots_fixed_b64,
                "claimed_hash": h_fixed_hex,
                "validated_chain": {
                    "ledger_id": "synthetic_regtest",
                    "headers_hex": chain_inv_compact,
                    "min_chainwork_hex": "1234",
                },
            })
        elif kind == 3:
            cw_64 = "0" * 62 + ("10" if ((i // 5) % 2 == 0) else "ff")
            f16.append({
                "id": f"F16_{i:04d}",
                "mode": "strict",
                "artifact_b64": art_fixed_b64,
                "ots_b64": ots_fixed_b64,
                "claimed_hash": h_fixed_hex,
                "validated_chain": {
                    "ledger_id": "synthetic_regtest",
                    "headers_hex": chain_inv_compact,
                    "min_chainwork_hex": cw_64,
                },
            })
        else:
            # Slide 4 forged trivial-target Mainnet chain (`ledger_id` defaults to Mainnet!)
            f16.append({
                "id": f"F16_{i:04d}",
                "mode": "strict" if ((i // 5) % 2 == 0) else "draft08",
                "artifact_b64": art_fixed_b64,
                "ots_b64": ots_fixed_b64,
                "claimed_hash": h_fixed_hex,
                "validated_chain": {"headers_hex": chain_inv_compact},
            })
    add_family("F16_setcompact_and_chainwork_forks", f16)

    # F17: Deterministic CBOR ProofBundle (valid int/str maps, non-minimal uints, unsorted keys, huge length claims)
    f17 = []
    valid_pb_str = encode_det_cbor({"ots_proof": ots_fixed, "claimed_hash": h_fixed_hex})
    valid_pb_int = encode_det_cbor({1: ots_fixed, 2: h_fixed, 3: 850000})
    # Unsorted CBOR map: {"ots_proof": ..., "claimed_hash": ...} ("ots_proof" len 9 < "claimed_hash" len 12, so reversed is unsorted!)
    unsorted_pb = (
        b"\xa2"
        + encode_det_cbor("claimed_hash")
        + encode_det_cbor(h_fixed_hex)
        + encode_det_cbor("ots_proof")
        + encode_det_cbor(ots_fixed)
    )
    # Non-minimal CBOR map header 0xb8 0x02 (24-byte uint encoding for 2)
    nonmin_pb = b"\xb8\x02" + valid_pb_int[1:]
    # Malicious CBOR claiming array/map of 4000 items in 5 bytes (tests pre-allocation guard!)
    oom_cbor = b"\x99\x0f\xa0\x01\x02"
    pb_variants = [valid_pb_str, valid_pb_int, unsorted_pb, nonmin_pb, oom_cbor]
    for i in range(PER_FAMILY):
        pb = pb_variants[i % len(pb_variants)]
        f17.append({
            "id": f"F17_{i:04d}",
            "mode": "strict" if (i % 2) else "draft08",
            "artifact_b64": art_fixed_b64,
            "proof_bundle_cbor_b64": base64.b64encode(pb).decode(),
            "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_inv_compact},
        })
    add_family("F17_cbor_proof_bundle_determinism", f17)

    # F18: SCITT COSE_Sign1 & RFC 9942 header 394 `[ + COSE_Receipt ]` multi-receipt invariance & protected-hdr determinism
    f18 = []
    ots_scitt_pb = base64.b64encode(
        encode_det_cbor({1: ots_scitt, 2: tbs_multi_h, 3: 920000})
    ).decode()
    cose_nonmin_prot = encode_det_cbor(
        CborTag(
            18,
            [
                b"\xa1\x18\x01\x26",  # non-minimal 2-byte uint `18 01` in protected_hdr
                {SCITT_RECEIPTS_HEADER_LABEL: [rcpt1, rcpt2]},
                payload_bstr,
                sig_bstr,
            ],
        )
    )
    for i in range(PER_FAMILY):
        kind = i % 5
        if kind == 0:
            # Relayed unprotected header mutation -> VALID in scitt_ots_ctt!
            relayed = encode_det_cbor(
                CborTag(
                    18,
                    [
                        prot_bstr,
                        {SCITT_RECEIPTS_HEADER_LABEL: [rcpt1, rcpt2], 700: f"hop-{i}"},
                        payload_bstr,
                        sig_bstr,
                    ],
                )
            )
            f18.append({
                "id": f"F18_{i:04d}",
                "mode": "strict",
                "input_mode": "scitt_ots_ctt",
                "cose_sign1_b64": base64.b64encode(relayed).decode(),
                "proof_bundle_cbor_b64": ots_scitt_pb,
                "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_scitt},
            })
        elif kind == 1:
            # Dropped second receipt from header 394 -> MUST fail hash comparison (Step 2 INVALID)!
            dropped = encode_det_cbor(
                CborTag(
                    18,
                    [
                        prot_bstr,
                        {SCITT_RECEIPTS_HEADER_LABEL: [rcpt1]},
                        payload_bstr,
                        sig_bstr,
                    ],
                )
            )
            f18.append({
                "id": f"F18_{i:04d}",
                "mode": "strict",
                "input_mode": "scitt_ots_ctt",
                "cose_sign1_b64": base64.b64encode(dropped).decode(),
                "proof_bundle_cbor_b64": ots_scitt_pb,
                "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_scitt},
            })
        elif kind == 2:
            # Bare receiptless statement -> rejected at Step 0 when require_receipt=True
            f18.append({
                "id": f"F18_{i:04d}",
                "mode": "strict",
                "input_mode": "scitt_ots_ctt",
                "cose_sign1_b64": base64.b64encode(cose_bare).decode(),
                "proof_bundle_cbor_b64": ots_scitt_pb,
                "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_scitt},
            })
        elif kind == 3:
            # Outer cose_sign1 mode
            f18.append({
                "id": f"F18_{i:04d}",
                "mode": "draft08",
                "input_mode": "cose_sign1",
                "cose_sign1_b64": base64.b64encode(cose_multi).decode(),
                "ots_b64": base64.b64encode(ots_scitt).decode(),
                "claimed_hash": tbs_multi_h.hex(),
                "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_scitt},
            })
        else:
            # Non-deterministic protected_hdr CBOR -> Step 0 INVALID in strict!
            f18.append({
                "id": f"F18_{i:04d}",
                "mode": "strict",
                "input_mode": "scitt_ots_ctt",
                "cose_sign1_b64": base64.b64encode(cose_nonmin_prot).decode(),
                "proof_bundle_cbor_b64": ots_scitt_pb,
                "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_scitt},
            })
    add_family("F18_scitt_cose_and_multi_receipt_394", f18)

    # F19: Producer-side RFC 6962 `0x00`/`0x01` batch option (disabled by default vs enabled)
    f19 = []
    ots_b_raw = base64.b64encode(
        make_proof(h_fixed, [make_btc_branch(recs_raw3[0].branch_ops, 910000)])
    ).decode()
    ots_b_6962 = base64.b64encode(
        make_proof(h_fixed, [make_btc_branch(recs_6962[0].branch_ops, 910000)])
    ).decode()
    for i in range(PER_FAMILY):
        use_6962 = (i % 2) == 1
        req_flag = ((i // 2) % 2) == 1
        f19.append({
            "id": f"F19_{i:04d}",
            "mode": "strict",
            "require_rfc6962_batch": req_flag,
            "artifact_b64": art_fixed_b64,
            "ots_b64": ots_b_6962 if use_6962 else ots_b_raw,
            "claimed_hash": h_fixed_hex,
            "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_m_6962 if use_6962 else chain_m_raw},
        })
    add_family("F19_producer_rfc6962_batch_trees", f19)

    # F20: Deep iterative O(1)-stack multi-branch & deep unary op chains (up to 65 branches & 300 ops)
    f20 = []
    for i in range(PER_FAMILY):
        if i % 2 == 0:
            n_ops = 100 + (i % 180)  # spans 128 strict cap boundary cleanly
            raw_ots = (
                OTS_MAGIC
                + b"\x01"
                + bytes([OP_SHA256])
                + h_fixed
                + (bytes([OP_SHA256]) * n_ops)
                + bytes([TAG_ATTESTATION])
                + BITCOIN_ATTESTATION_TAG
                + encode_varbytes(encode_varuint(850000))
            )
        else:
            n_br = 50 + (i % 25)  # spans 64 strict max_branches cap boundary cleanly!
            buf = bytearray(OTS_MAGIC + b"\x01" + bytes([OP_SHA256]) + h_fixed)
            att_bytes = (
                bytes([OP_SHA256, TAG_ATTESTATION])
                + BITCOIN_ATTESTATION_TAG
                + encode_varbytes(encode_varuint(850000))
            )
            for b_idx in range(n_br):
                if b_idx < n_br - 1:
                    buf.append(TAG_BRANCH)
                buf.extend(att_bytes)
            raw_ots = bytes(buf)
        f20.append({
            "id": f"F20_{i:04d}",
            "mode": "strict" if ((i // 2) % 2) else "draft08",
            "artifact_b64": art_fixed_b64,
            "ots_b64": base64.b64encode(raw_ots).decode(),
            "claimed_hash": h_fixed_hex,
            "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_inv_compact},
        })
    add_family("F20_deep_iterative_tree_stress", f20)

    return cases, family_counts


def main() -> None:
    t0 = time.perf_counter()
    cases, family_counts = generate_50000_cases(seed=20261115)
    total = len(cases)
    assert total == 50_000, f"Expected 50000 cases, got {total}"
    gen_ms = round((time.perf_counter() - t0) * 1000, 2)

    jsonl_payload = "\n".join(json.dumps(c) for c in cases) + "\n"

    # 1. Evaluate all 50,000 in Python (parallel worker pool across CPU cores)
    t_py0 = time.perf_counter()
    workers = min(8, os.cpu_count() or 4)
    chunk_sz = (total + workers - 1) // workers
    chunks = [cases[i : i + chunk_sz] for i in range(0, total, chunk_sz)]
    py_results: List[Dict[str, Any]] = []
    with ProcessPoolExecutor(max_workers=workers) as pool:
        for part in pool.map(_eval_py_chunk, chunks):
            py_results.extend(part)
    py_ms = round((time.perf_counter() - t_py0) * 1000, 2)

    # 2. Evaluate all 50,000 in Native Rust CLI (`scitt_time_anchor_rs`)
    rs_bin = ROOT / "scitt_time_anchor_rs" / "target" / "release" / "scitt_time_anchor_rs"
    t_rs0 = time.perf_counter()
    proc_rs = subprocess.run(
        [str(rs_bin)],
        input=jsonl_payload,
        text=True,
        capture_output=True,
        check=True,
    )
    rs_ms = round((time.perf_counter() - t_rs0) * 1000, 2)
    rs_results = [json.loads(line) for line in proc_rs.stdout.strip().splitlines()]

    # 3. Evaluate all 50,000 in Compiled Offline WASM (`web/scitt_time_anchor.wasm` via Node V8)
    wasm_runner = ROOT / "verification_suite" / "wasm_batch_eval.mjs"
    t_wa0 = time.perf_counter()
    proc_wa = subprocess.run(
        ["node", str(wasm_runner)],
        input=jsonl_payload,
        text=True,
        capture_output=True,
        check=True,
    )
    wasm_ms = round((time.perf_counter() - t_wa0) * 1000, 2)
    wasm_results = [json.loads(line) for line in proc_wa.stdout.strip().splitlines()]

    assert len(py_results) == total, f"py count {len(py_results)} != {total}"
    assert len(rs_results) == total, f"rs count {len(rs_results)} != {total}"
    assert len(wasm_results) == total, f"wasm count {len(wasm_results)} != {total}"

    py_vs_rs_div = 0
    rs_vs_wasm_div = 0
    py_vs_wasm_div = 0
    outcome_counts = {"valid": 0, "invalid": 0, "unverifiable": 0}
    mode_counts = {"draft08": 0, "strict": 0}

    for idx, (py_r, rs_r, wa_r) in enumerate(zip(py_results, rs_results, wasm_results)):
        outcome_counts[py_r["outcome"]] += 1
        mode_counts[py_r["mode"]] += 1
        if py_r != rs_r:
            py_vs_rs_div += 1
            if py_vs_rs_div <= 5:
                print(f"PY!=RS at {idx} ({cases[idx]['id']}): py={py_r} rs={rs_r}", file=sys.stderr)
        if rs_r != wa_r:
            rs_vs_wasm_div += 1
            if rs_vs_wasm_div <= 5:
                print(f"RS!=WASM at {idx} ({cases[idx]['id']}): rs={rs_r} wasm={wa_r}", file=sys.stderr)
        if py_r != wa_r:
            py_vs_wasm_div += 1

    wasm_path = ROOT / "web" / "scitt_time_anchor.wasm"
    wasm_raw_bytes = wasm_path.stat().st_size
    import gzip

    wasm_gzip_bytes = len(gzip.compress(wasm_path.read_bytes(), compresslevel=9))

    report = {
        "pass": "Stage 3 — 50,000-Vector Triple-Engine Differential Verification (Python == Native Rust == Offline WASM)",
        "seed": 20261115,
        "total_vectors_executed": total,
        "engines_compared": [
            "scitt_time_anchor_py (Python 3 stdlib)",
            "scitt_time_anchor_rs (Native Rust release binary, #![forbid(unsafe_code)])",
            "web/scitt_time_anchor.wasm (wasm32-unknown-unknown in Node V8)",
        ],
        "wasm_binary_metrics": {
            "uncompressed_bytes": wasm_raw_bytes,
            "uncompressed_kb": round(wasm_raw_bytes / 1024, 2),
            "gzipped_bytes": wasm_gzip_bytes,
            "gzipped_kb": round(wasm_gzip_bytes / 1024, 2),
        },
        "profile_distribution": mode_counts,
        "outcome_distribution": outcome_counts,
        "families_20": family_counts,
        "divergences": {
            "python_vs_rust": py_vs_rs_div,
            "rust_vs_wasm": rs_vs_wasm_div,
            "python_vs_wasm": py_vs_wasm_div,
            "total_divergences": py_vs_rs_div + rs_vs_wasm_div + py_vs_wasm_div,
        },
        "timings_ms": {
            "vector_generation_ms": gen_ms,
            "python_parallel_eval_ms": py_ms,
            "rust_native_cli_eval_ms": rs_ms,
            "wasm_node_v8_eval_ms": wasm_ms,
            "rust_us_per_vector": round((rs_ms * 1000.0) / total, 2),
            "wasm_us_per_vector": round((wasm_ms * 1000.0) / total, 2),
            "total_wall_ms": round((time.perf_counter() - t0) * 1000, 2),
        },
        "verdict": "PASS" if (py_vs_rs_div == 0 and rs_vs_wasm_div == 0 and py_vs_wasm_div == 0) else "FAIL",
    }

    out_path = ROOT / "verification_suite" / "triple_engine_50k_report.json"
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    if report["verdict"] != "PASS":
        sys.exit(1)


if __name__ == "__main__":
    main()
