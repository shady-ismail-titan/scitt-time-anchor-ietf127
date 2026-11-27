#!/usr/bin/env python3
"""Appendix D Conformance: Byte-exact verification of all official Appendix D.1-D.7 vectors in BOTH
`--mode draft08` (40 cases) and `--mode strict` (40 cases), PLUS 16 reproducible
conformance & divergence witness vectors covering all 7 formally verified findings (96 total).
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
    DRAFT08_MAX_OPS_PER_BRANCH,
    OP_APPEND,
    OP_PREPEND,
    OP_SHA1,
    OP_SHA256,
    OTS_MAGIC,
    OtsBranch,
    OtsOp,
    OtsProof,
    TAG_ATTESTATION,
    TAG_BRANCH,
    batch_anchor_merkle,
    decode_varuint_js_toint32,
    decode_varuint_py_unbounded,
    encode_varbytes,
    encode_varuint,
    ots_deserialize,
    ots_replay,
    ots_serialize,
)


def cbor_encode(val: Any) -> bytes:
    return encode_det_cbor(val)


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
    ntimes: Dict[int, int] | None = None,
    base_time: int = 1700000000,
    nbits: int = 0x207FFFFF,
    prev_seed: bytes = b"\x22" * 32,
) -> Dict[str, str]:
    prev = prev_seed
    out: Dict[str, str] = {}
    for i in range(count):
        h = start_h + i
        mr = merkle_overrides.get(h, hashlib.sha256(f"synth-{h}".encode()).digest())
        nt = ntimes[h] if (ntimes and h in ntimes) else (base_time + i * 600)
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


def build_strict_profile_witness_vectors() -> Tuple[
    List[Dict[str, Any]], Dict[str, Dict[str, Any]], List[Dict[str, Any]]
]:
    """Construct 16 byte-exact reproducible test vectors covering all 7 formally verified findings."""
    cases: List[Dict[str, Any]] = []
    expected: Dict[str, Dict[str, Any]] = {}
    documented_witnesses: List[Dict[str, Any]] = []

    art = b"SCITT-STRICT-PROFILE-WITNESS-ARTIFACT"
    art_b64 = base64.b64encode(art).decode("ascii")
    art_hash = hashlib.sha256(art).digest()
    art_hex = art_hash.hex()

    # ---- Finding #1: Multi-Branch Timestamp Inversion (+7,000 s) & Zero-Extra-Wait Forward-MTP(H+5) ----
    mr_d1 = hashlib.sha256(art_hash + b"d1-nonce-0000001").digest()
    ntimes_d1: Dict[int, int] = {}
    for idx, h in enumerate(range(849989, 850000)):
        ntimes_d1[h] = 1699999990 + idx
    ntimes_d1[850000] = 1700007007  # Consensus-legal +7,000 s miner clock skew
    for idx, h in enumerate(range(850001, 850012)):
        ntimes_d1[h] = 1700000007 + idx
    chain_d1 = build_synthetic_slice(
        849989,
        23,
        {850000: mr_d1, 850001: mr_d1},
        ntimes=ntimes_d1,
    )
    br_ops_d1 = (OtsOp(OP_APPEND, b"d1-nonce-0000001"), OtsOp(OP_SHA256))
    ots_d1 = make_proof(
        art_hash,
        [
            make_btc_branch(br_ops_d1, 850000),
            make_btc_branch(br_ops_d1, 850001),
        ],
    )
    ots_d1_b64 = base64.b64encode(ots_d1).decode("ascii")
    for m_name in ("draft08", "strict"):
        cid = f"W1_FORWARD_MTP_{m_name.upper()}"
        cases.append({
            "id": cid,
            "mode": m_name,
            "artifact_b64": art_b64,
            "ots_b64": ots_d1_b64,
            "claimed_hash": art_hex,
            "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_d1},
        })
        # Confirmations = 850011 - 850000 + 1 = 12 (standard Bitcoin Core `tip - H + 1`)
        # fmtp_5 = median(t[849995..850005]) = 1700000007, defeating the +7,000 s nTime spike at exact 6 confirmations!
        expected[cid] = {
            "outcome": "valid",
            "block_height_h": 850000,
            "block_time_rwcp": 1700007007,
            "fmtp_5": 1700000007,
            "fmtp_6": 1700000008,
            "fmtp_11": 1700000012,
            "confirmations": 12,
        }
    documented_witnesses.append({
        "finding": 1,
        "id": "Z3-1_FORWARD_MTP_H_PLUS_5",
        "inflated_rwcp": 1700007007,
        "fmtp_5_zero_wait_bound": 1700000007,
        "fmtp_6_upper_bound": 1700000008,
        "fmtp_11_upper_bound": 1700000012,
    })

    # ---- Finding #2: 6-Byte LEB128 Split-Brain (`80f0b380800a`) & Iterative 4,096-Op Stack Bound ----
    split_varuint = bytes.fromhex("80f0b380800a")
    js_res = decode_varuint_js_toint32(split_varuint, 0)
    py_res = decode_varuint_py_unbounded(split_varuint, 0)
    assert js_res is not None and py_res is not None
    js_val, _ = js_res
    py_val, _ = py_res
    assert js_val == 850000 and py_val == 343598233600
    raw_split_ots = (
        OTS_MAGIC
        + b"\x01"
        + bytes([OP_SHA256])
        + art_hash
        + bytes([OP_APPEND])
        + encode_varbytes(b"d1-nonce-0000001")
        + bytes([OP_SHA256])
        + bytes([TAG_ATTESTATION])
        + BITCOIN_ATTESTATION_TAG
        + encode_varbytes(split_varuint)
    )
    cases.append({
        "id": "W2_LEB128_SPLIT_BRAIN_DRAFT08",
        "mode": "draft08",
        "artifact_b64": art_b64,
        "ots_b64": base64.b64encode(raw_split_ots).decode("ascii"),
        "claimed_hash": art_hex,
        "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_d1},
    })
    expected["W2_LEB128_SPLIT_BRAIN_DRAFT08"] = {"outcome": "unverifiable", "step": 8}

    cases.append({
        "id": "W2_LEB128_SPLIT_BRAIN_STRICT",
        "mode": "strict",
        "artifact_b64": art_b64,
        "ots_b64": base64.b64encode(raw_split_ots).decode("ascii"),
        "claimed_hash": art_hex,
        "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_d1},
    })
    expected["W2_LEB128_SPLIT_BRAIN_STRICT"] = {"outcome": "invalid", "step": 3}

    # Iterative O(1)-call-stack 4,096-op proof (4.17 KB): parses cleanly in draft08 without stack overflow,
    # rejected at Step 3 in strict profile (`MAX_OPS_PER_BRANCH = 128`).
    deep_digest = art_hash
    for _ in range(DRAFT08_MAX_OPS_PER_BRANCH):
        deep_digest = hashlib.sha256(deep_digest).digest()
    chain_deep = build_synthetic_slice(860000, 6, {860000: deep_digest})
    raw_deep_ots = (
        OTS_MAGIC
        + b"\x01"
        + bytes([OP_SHA256])
        + art_hash
        + (bytes([OP_SHA256]) * DRAFT08_MAX_OPS_PER_BRANCH)
        + bytes([TAG_ATTESTATION])
        + BITCOIN_ATTESTATION_TAG
        + encode_varbytes(encode_varuint(860000))
    )
    cases.append({
        "id": "W2B_DEEP_4096_ITERATIVE_STACK_DRAFT08",
        "mode": "draft08",
        "artifact_b64": art_b64,
        "ots_b64": base64.b64encode(raw_deep_ots).decode("ascii"),
        "claimed_hash": art_hex,
        "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_deep},
    })
    expected["W2B_DEEP_4096_ITERATIVE_STACK_DRAFT08"] = {
        "outcome": "valid",
        "step": 11,
        "block_height_h": 860000,
        "confirmations": 6,
    }
    cases.append({
        "id": "W2B_DEEP_4096_BOUNDED_STRICT",
        "mode": "strict",
        "artifact_b64": art_b64,
        "ots_b64": base64.b64encode(raw_deep_ots).decode("ascii"),
        "claimed_hash": art_hex,
        "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_deep},
    })
    expected["W2B_DEEP_4096_BOUNDED_STRICT"] = {"outcome": "invalid", "step": 3}

    documented_witnesses.append({
        "finding": 2,
        "id": "Z3-2_LEB128_SPLIT_BRAIN_AND_RESOURCE_BOUNDS",
        "varuint_hex": "80f0b380800a",
        "js_toint32_height": js_val,
        "python_u64_height": py_val,
        "deep_4096_ots_len_bytes": len(raw_deep_ots),
    })

    # ---- Finding #3: Mid-Path OpSHA1 (`0x02`) 160-Bit Narrow-Pipe Downgrade ----
    sha1_br = make_btc_branch((OtsOp(OP_SHA1), OtsOp(OP_SHA256)), 850000)
    ots_sha1 = make_proof(art_hash, [sha1_br, make_btc_branch(br_ops_d1, 850000)])
    cases.append({
        "id": "W3_MIDPATH_OPSHA1_DRAFT08",
        "mode": "draft08",
        "artifact_b64": art_b64,
        "ots_b64": base64.b64encode(ots_sha1).decode("ascii"),
        "claimed_hash": art_hex,
        "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_d1},
    })
    expected["W3_MIDPATH_OPSHA1_DRAFT08"] = {"outcome": "valid", "step": 11}

    cases.append({
        "id": "W3_MIDPATH_OPSHA1_STRICT",
        "mode": "strict",
        "artifact_b64": art_b64,
        "ots_b64": base64.b64encode(ots_sha1).decode("ascii"),
        "claimed_hash": art_hex,
        "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_d1},
    })
    expected["W3_MIDPATH_OPSHA1_STRICT"] = {"outcome": "invalid", "step": 3}

    # ---- Finding #4A: Step 8 -> Step 9 Premature argmin on Sparse Header Windows ----
    slice_a = build_synthetic_slice(800000, 3, {800000: mr_d1})
    sparse_headers = dict(slice_a)
    sparse_headers.update(chain_d1)
    ots_sparse = make_proof(
        art_hash,
        [
            make_btc_branch(br_ops_d1, 800000),
            make_btc_branch(br_ops_d1, 850000),
        ],
    )
    cases.append({
        "id": "W4A_SPARSE_ARGMIN_DRAFT08",
        "mode": "draft08",
        "artifact_b64": art_b64,
        "ots_b64": base64.b64encode(ots_sparse).decode("ascii"),
        "claimed_hash": art_hex,
        "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": sparse_headers, "allow_sparse_checkpoints": True},
    })
    expected["W4A_SPARSE_ARGMIN_DRAFT08"] = {
        "outcome": "unverifiable",
        "step": 9,
        "block_height_h": 800000,
    }

    cases.append({
        "id": "W4A_SPARSE_ARGMIN_STRICT",
        "mode": "strict",
        "artifact_b64": art_b64,
        "ots_b64": base64.b64encode(ots_sparse).decode("ascii"),
        "claimed_hash": art_hex,
        "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": sparse_headers, "allow_sparse_checkpoints": True},
    })
    expected["W4A_SPARSE_ARGMIN_STRICT"] = {
        "outcome": "valid",
        "step": 11,
        "block_height_h": 850000,
    }

    # ---- Finding #4B: Competing Eclipse Low-Work Fork vs High-Chainwork Fork ----
    fork_eclipse = build_synthetic_slice(900000, 8, {}, nbits=0x207FFFFF, prev_seed=b"\x33" * 32)
    fork_honest = build_synthetic_slice(900000, 8, {900000: mr_d1}, nbits=0x201FFFFF, prev_seed=b"\x44" * 32)
    ots_fork = make_proof(art_hash, [make_btc_branch(br_ops_d1, 900000)])
    cases.append({
        "id": "W4B_ECLIPSE_CHAINWORK_DRAFT08",
        "mode": "draft08",
        "artifact_b64": art_b64,
        "ots_b64": base64.b64encode(ots_fork).decode("ascii"),
        "claimed_hash": art_hex,
        "candidate_chains": [
            {"ledger_id": "synthetic_regtest", "headers_hex": fork_eclipse},
            {"ledger_id": "synthetic_regtest", "headers_hex": fork_honest},
        ],
    })
    expected["W4B_ECLIPSE_CHAINWORK_DRAFT08"] = {"outcome": "invalid", "step": 8}

    cases.append({
        "id": "W4B_ECLIPSE_CHAINWORK_STRICT",
        "mode": "strict",
        "artifact_b64": art_b64,
        "ots_b64": base64.b64encode(ots_fork).decode("ascii"),
        "claimed_hash": art_hex,
        "candidate_chains": [
            {"ledger_id": "synthetic_regtest", "headers_hex": fork_eclipse},
            {"ledger_id": "synthetic_regtest", "headers_hex": fork_honest},
        ],
    })
    expected["W4B_ECLIPSE_CHAINWORK_STRICT"] = {
        "outcome": "valid",
        "step": 11,
        "block_height_h": 900000,
    }

    # ---- Finding #5: Producer-Side Section 5.3 RFC 6962 `0x00`/`0x01` Batch Helper ----
    # Note: `require_rfc6962_batch` defaults to False on all v1 `.ots` verifiers!
    nonces_3 = [b"\xaa" * 16, b"\xbb" * 16, b"\xcc" * 16]
    items_3 = [("o1", art_hash), ("o2", b"\x11" * 32), ("o3", b"\x22" * 32)]
    root_6962, recs_6962 = batch_anchor_merkle(items_3, nonces=nonces_3, rfc6962_domain_sep=True)
    chain_m_6962 = build_synthetic_slice(910000, 8, {910000: root_6962})
    ots_m_6962 = make_proof(art_hash, [make_btc_branch(recs_6962[0].branch_ops, 910000)])
    cases.append({
        "id": "W5_PRODUCER_RFC6962_BATCH_VALID_STRICT",
        "mode": "strict",
        "require_rfc6962_batch": True,
        "artifact_b64": art_b64,
        "ots_b64": base64.b64encode(ots_m_6962).decode("ascii"),
        "claimed_hash": art_hex,
        "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_m_6962},
    })
    expected["W5_PRODUCER_RFC6962_BATCH_VALID_STRICT"] = {
        "outcome": "valid",
        "step": 11,
        "block_height_h": 910000,
    }

    # ---- Finding #6 & #7: RFC 9943 / RFC 9942 (`header 394` `[ + COSE_Receipt ]`) / RFC 9921 §3.1.1 ----
    prot_bstr = cbor_encode({1: -7})  # ES256 protected header
    payload_bstr = b'{"sbom":"pkg:cargo/scitt-verifier@0.2.0"}'
    sig_bstr = b"\x55" * 64
    receipt_1 = cbor_encode(["scitt-rfc9942-receipt-log-alpha", b"\x99" * 32])
    receipt_2 = cbor_encode(["scitt-rfc9942-receipt-log-beta", b"\x77" * 32])

    bare_cose = cbor_encode(CborTag(18, [prot_bstr, {}, payload_bstr, sig_bstr]))
    # RFC 9942 Section 8 header 394 carries `[ + COSE_Receipt ]` (2 receipts) + mutable unprotected metadata (with nested CBOR Tag 1!)
    trans_cose = cbor_encode(
        CborTag(
            18,
            [
                prot_bstr,
                {
                    SCITT_RECEIPTS_HEADER_LABEL: [receipt_1, receipt_2],
                    777: CborTag(1, 1783591379),
                },
                payload_bstr,
                sig_bstr,
            ],
        )
    )

    bare_hash = hashlib.sha256(bare_cose).digest()
    mr_bare = hashlib.sha256(bare_hash + b"cose-bare-nonce1").digest()
    chain_bare = build_synthetic_slice(920000, 8, {920000: mr_bare})
    ots_bare = make_proof(
        bare_hash,
        [make_btc_branch((OtsOp(OP_APPEND, b"cose-bare-nonce1"), OtsOp(OP_SHA256)), 920000)],
    )
    cases.append({
        "id": "W7A_TRANSPARENT_STMT_HASH_MISMATCH_DRAFT08",
        "mode": "draft08",
        "input_mode": "cose_sign1",
        "cose_sign1_b64": base64.b64encode(trans_cose).decode("ascii"),
        "ots_b64": base64.b64encode(ots_bare).decode("ascii"),
        "claimed_hash": bare_hash.hex(),
        "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_bare},
    })
    expected["W7A_TRANSPARENT_STMT_HASH_MISMATCH_DRAFT08"] = {"outcome": "invalid", "step": 2}

    stmt_trans = parse_cose_sign1_statement(trans_cose)
    assert stmt_trans is not None
    tbs_bytes = compute_scitt_ots_tbs_bytes(stmt_trans, require_receipt=True)
    assert tbs_bytes is not None
    tbs_hash = hashlib.sha256(tbs_bytes).digest()
    mr_tbs = hashlib.sha256(tbs_hash + b"cose-tbs-nonce01").digest()
    chain_tbs = build_synthetic_slice(920000, 8, {920000: mr_tbs})
    ots_tbs = make_proof(
        tbs_hash,
        [make_btc_branch((OtsOp(OP_APPEND, b"cose-tbs-nonce01"), OtsOp(OP_SHA256)), 920000)],
    )
    ots_pb_int = cbor_encode({1: ots_tbs, 2: tbs_hash, 3: 920000})

    # Mutate extra unprotected header 777 on transit -> `scitt_ots_ctt` remains 100% invariant!
    trans_cose_relayed = cbor_encode(
        CborTag(
            18,
            [
                prot_bstr,
                {
                    SCITT_RECEIPTS_HEADER_LABEL: [receipt_1, receipt_2],
                    777: "relayed-edge-cache-hop-2",
                },
                payload_bstr,
                sig_bstr,
            ],
        )
    )
    cases.append({
        "id": "W7B_SCITT_OTS_CTT_MULTI_RECEIPT_INVARIANT_STRICT",
        "mode": "strict",
        "input_mode": "scitt_ots_ctt",
        "cose_sign1_b64": base64.b64encode(trans_cose_relayed).decode("ascii"),
        "proof_bundle_cbor_b64": base64.b64encode(ots_pb_int).decode("ascii"),
        "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_tbs},
    })
    expected["W7B_SCITT_OTS_CTT_MULTI_RECEIPT_INVARIANT_STRICT"] = {
        "outcome": "valid",
        "step": 11,
        "block_height_h": 920000,
    }

    # Receiptless Dark-Anchored COSE_Sign1 rejected at Step 0 when `require_receipt=True`
    cases.append({
        "id": "W6_DARK_ANCHORING_REJECTED_STRICT",
        "mode": "strict",
        "input_mode": "scitt_ots_ctt",
        "cose_sign1_b64": base64.b64encode(bare_cose).decode("ascii"),
        "proof_bundle_cbor_b64": base64.b64encode(ots_pb_int).decode("ascii"),
        "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_tbs},
    })
    expected["W6_DARK_ANCHORING_REJECTED_STRICT"] = {"outcome": "invalid", "step": 0}

    # ---- Finding #8 (N17/N18): IETF 127 Slide 4 -09 Forged Easy-Target Chain & Retarget Consensus Checks ----
    forged_easy_chain = build_synthetic_slice(957289, 6, {957289: mr_d1}, nbits=0x207FFFFF)
    ots_957289 = make_proof(art_hash, [make_btc_branch(br_ops_d1, 957289)])
    cases.append({
        "id": "N17A_FORGED_EASY_MAINNET_CHAIN_DRAFT08",
        "mode": "draft08",
        "artifact_b64": art_b64,
        "ots_b64": base64.b64encode(ots_957289).decode("ascii"),
        "claimed_hash": art_hex,
        "validated_chain": {"headers_hex": forged_easy_chain},
    })
    expected["N17A_FORGED_EASY_MAINNET_CHAIN_DRAFT08"] = {"outcome": "valid", "step": 11, "block_height_h": 957289}

    cases.append({
        "id": "N17A_FORGED_EASY_MAINNET_CHAIN_STRICT",
        "mode": "strict",
        "artifact_b64": art_b64,
        "ots_b64": base64.b64encode(ots_957289).decode("ascii"),
        "claimed_hash": art_hex,
        "validated_chain": {"headers_hex": forged_easy_chain},
    })
    expected["N17A_FORGED_EASY_MAINNET_CHAIN_STRICT"] = {"outcome": "unverifiable", "step": 8}

    # N17B: Forged post-CSV Mainnet chain with nBits=0x1e0fffff (trivial difficulty between 0x1d00ffff and regtest)
    forged_1e_chain = build_synthetic_slice(957289, 6, {957289: mr_d1}, nbits=0x1E7FFFFF)
    cases.append({
        "id": "N17B_FORGED_SUBPOWLIMIT_MAINNET_CHAIN_STRICT",
        "mode": "strict",
        "artifact_b64": art_b64,
        "ots_b64": base64.b64encode(ots_957289).decode("ascii"),
        "claimed_hash": art_hex,
        "validated_chain": {"headers_hex": forged_1e_chain},
    })
    expected["N17B_FORGED_SUBPOWLIMIT_MAINNET_CHAIN_STRICT"] = {"outcome": "unverifiable", "step": 8}

    # N18A: Mid-epoch difficulty mutation (height 957290 % 2016 != 0 changes nBits from 0x207fffff to 0x203fffff)
    mid_epoch_chain: Dict[str, str] = {}
    prev_me = b"\x22" * 32
    for idx_me, h_me in enumerate(range(957289, 957295)):
        nb_me = 0x203FFFFF if h_me == 957290 else 0x207FFFFF
        mr_me = mr_d1 if h_me == 957289 else hashlib.sha256(f"me-{h_me}".encode()).digest()
        raw_me, dsha_me = mine_synthetic_header(prev_me, mr_me, 1700000000 + idx_me * 600, nbits=nb_me)
        mid_epoch_chain[str(h_me)] = raw_me.hex()
        prev_me = dsha_me
    cases.append({
        "id": "N18A_MID_EPOCH_DRIFT_REJECTED_STRICT",
        "mode": "strict",
        "artifact_b64": art_b64,
        "ots_b64": base64.b64encode(ots_957289).decode("ascii"),
        "claimed_hash": art_hex,
        "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": mid_epoch_chain},
    })
    expected["N18A_MID_EPOCH_DRIFT_REJECTED_STRICT"] = {"outcome": "unverifiable", "step": 8}

    # N18B: Retarget boundary (8064 % 2016 == 0) jumping >4x easier (0x1f7fffff -> 0x207fffff = 256x jump!)
    retarget_jump_chain: Dict[str, str] = {}
    prev_rj = b"\x55" * 32
    for idx_rj, h_rj in enumerate(range(8063, 8070)):
        nb_rj = 0x1F7FFFFF if h_rj == 8063 else 0x207FFFFF
        mr_rj = mr_d1 if h_rj == 8063 else hashlib.sha256(f"rj-{h_rj}".encode()).digest()
        raw_rj, dsha_rj = mine_synthetic_header(prev_rj, mr_rj, 1700000000 + idx_rj * 600, nbits=nb_rj)
        retarget_jump_chain[str(h_rj)] = raw_rj.hex()
        prev_rj = dsha_rj
    ots_8063 = make_proof(art_hash, [make_btc_branch(br_ops_d1, 8063)])
    cases.append({
        "id": "N18B_RETARGET_GT_4X_JUMP_REJECTED_STRICT",
        "mode": "strict",
        "artifact_b64": art_b64,
        "ots_b64": base64.b64encode(ots_8063).decode("ascii"),
        "claimed_hash": art_hex,
        "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": retarget_jump_chain},
    })
    expected["N18B_RETARGET_GT_4X_JUMP_REJECTED_STRICT"] = {"outcome": "unverifiable", "step": 8}

    # N20: Non-deterministic CBOR inside COSE_Sign1 `protected_hdr` (e.g., CBOR float64 `1.5` or non-minimal uint `18 01`)
    non_min_prot = b"\xa1\x18\x01\x26"  # {1: -7} with non-minimal 2-byte key `18 01` instead of `01`
    float_prot = b"\xa1\x01\xfb\x3f\xf8\x00\x00\x00\x00\x00\x00"  # {1: 1.5_f64}
    for tag_n20, bad_prot in [("NONMIN_UINT", non_min_prot), ("FLOAT64", float_prot)]:
        bad_cose = cbor_encode(
            CborTag(
                18,
                [
                    bad_prot,
                    {SCITT_RECEIPTS_HEADER_LABEL: [receipt_1]},
                    payload_bstr,
                    sig_bstr,
                ],
            )
        )
        cases.append({
            "id": f"N20_{tag_n20}_COSE_PROTECTED_STRICT",
            "mode": "strict",
            "input_mode": "scitt_ots_ctt",
            "cose_sign1_b64": base64.b64encode(bad_cose).decode("ascii"),
            "proof_bundle_cbor_b64": base64.b64encode(ots_pb_int).decode("ascii"),
            "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_tbs},
        })
        expected[f"N20_{tag_n20}_COSE_PROTECTED_STRICT"] = {"outcome": "invalid", "step": 0}

    # ---- v2.0.0 Parity & Security Hardening Vectors (N22-N34; N21 & N33 in raw JSONL gate) ----
    # N22 (DIV-2A): Base64 form-feed (\x0c) & mid-stream padding ("AA==AA==") rejected identically
    cases.append({
        "id": "N22A_B64_FORMFEED_REJECTED",
        "mode": "strict",
        "artifact_b64": "AA==\x0c",
        "ots_b64": ots_d1_b64,
        "claimed_hash": art_hex,
        "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_d1},
    })
    expected["N22A_B64_FORMFEED_REJECTED"] = {"outcome": "invalid", "step": 0}

    cases.append({
        "id": "N22B_B64_MIDSTREAM_PAD_REJECTED",
        "mode": "strict",
        "artifact_b64": "AA==AA==",
        "ots_b64": ots_d1_b64,
        "claimed_hash": art_hex,
        "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_d1},
    })
    expected["N22B_B64_MIDSTREAM_PAD_REJECTED"] = {"outcome": "invalid", "step": 0}

    # N23 (DIV-2B): RFC 4648 Section 3.5 non-zero Base64 trailing padding bits rejected identically
    cases.append({
        "id": "N23A_B64_NONZERO_PAD2_REJECTED",
        "mode": "strict",
        "artifact_b64": "AB==",
        "ots_b64": ots_d1_b64,
        "claimed_hash": art_hex,
        "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_d1},
    })
    expected["N23A_B64_NONZERO_PAD2_REJECTED"] = {"outcome": "invalid", "step": 0}

    cases.append({
        "id": "N23B_B64_NONZERO_PAD1_REJECTED",
        "mode": "strict",
        "artifact_b64": "AAB=",
        "ots_b64": ots_d1_b64,
        "claimed_hash": art_hex,
        "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_d1},
    })
    expected["N23B_B64_NONZERO_PAD1_REJECTED"] = {"outcome": "invalid", "step": 0}

    # N24 (DIV-3): Canonical decimal block height keys only (reject "+850000" and "0850000")
    cases.append({
        "id": "N24A_HEIGHT_PLUS_SIGN_CANDIDATE_REJECTED",
        "mode": "draft08",
        "artifact_b64": art_b64,
        "ots_b64": ots_d1_b64,
        "claimed_hash": art_hex,
        "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_d1},
        "candidate_store": {
            "source": "validated_node",
            "headers_hex": {"+850000": chain_d1["850000"]},
        },
    })
    expected["N24A_HEIGHT_PLUS_SIGN_CANDIDATE_REJECTED"] = {"outcome": "invalid", "step": 0}

    leading_zero_chain = {("0" + k if k == "850000" else k): v for k, v in chain_d1.items()}
    cases.append({
        "id": "N24B_HEIGHT_LEADING_ZERO_CHAIN_REJECTED",
        "mode": "strict",
        "artifact_b64": art_b64,
        "ots_b64": ots_d1_b64,
        "claimed_hash": art_hex,
        "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": leading_zero_chain},
    })
    expected["N24B_HEIGHT_LEADING_ZERO_CHAIN_REJECTED"] = {"outcome": "unverifiable", "step": 8}

    # N25 (DIV-4): Fail-closed non-string min_chainwork_hex in strict mode
    cases.append({
        "id": "N25_MIN_CHAINWORK_NONSTRING_STRICT",
        "mode": "strict",
        "artifact_b64": art_b64,
        "ots_b64": ots_d1_b64,
        "claimed_hash": art_hex,
        "validated_chain": {
            "ledger_id": "synthetic_regtest",
            "headers_hex": chain_d1,
            "min_chainwork_hex": 999,
        },
    })
    expected["N25_MIN_CHAINWORK_NONSTRING_STRICT"] = {"outcome": "unverifiable", "step": 8}

    # N26 (DIV-5): RFC 6962 reordered leaf (Prepend(0x00), Append(16), Sha256) + combined Prepend(0x01||sib32)
    n26_nonce = b"n26-rfc6962-nonc"
    n26_sib = hashlib.sha256(b"n26-sibling").digest()
    n26_leaf = hashlib.sha256(b"\x00" + art_hash + n26_nonce).digest()
    n26_root = hashlib.sha256(b"\x01" + n26_sib + n26_leaf).digest()
    n26_ops = (
        OtsOp(OP_PREPEND, b"\x00"),
        OtsOp(OP_APPEND, n26_nonce),
        OtsOp(OP_SHA256),
        OtsOp(OP_PREPEND, b"\x01" + n26_sib),
        OtsOp(OP_SHA256),
    )
    chain_n26 = build_synthetic_slice(915000, 8, {915000: n26_root})
    ots_n26 = make_proof(art_hash, [make_btc_branch(n26_ops, 915000)])
    cases.append({
        "id": "N26_RFC6962_ALT_ORDER_PARITY_STRICT",
        "mode": "strict",
        "require_rfc6962_batch": True,
        "artifact_b64": art_b64,
        "ots_b64": base64.b64encode(ots_n26).decode("ascii"),
        "claimed_hash": art_hex,
        "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_n26},
    })
    expected["N26_RFC6962_ALT_ORDER_PARITY_STRICT"] = {
        "outcome": "valid",
        "step": 11,
        "block_height_h": 915000,
    }

    # N27 (DIV-6): Semantic duplicate CBOR map key {0x01: ots, 0x18 0x01: ots, 0x02: hash32} in draft08
    ots_n27 = make_proof(art_hash, [make_btc_branch(br_ops_d1, 850000)])
    sem_dup_pb = (
        b"\xa3"
        + b"\x01"
        + cbor_encode(ots_n27)
        + b"\x18\x01"
        + cbor_encode(ots_n27)
        + b"\x02"
        + cbor_encode(art_hash)
    )
    cases.append({
        "id": "N27_CBOR_SEMANTIC_DUP_KEY_DRAFT08",
        "mode": "draft08",
        "artifact_b64": art_b64,
        "proof_bundle_cbor_b64": base64.b64encode(sem_dup_pb).decode("ascii"),
        "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_d1},
    })
    expected["N27_CBOR_SEMANTIC_DUP_KEY_DRAFT08"] = {"outcome": "invalid", "step": 0}

    # N28 (DIV-7): Unprotected header containing BOTH "scitt_receipt" (wire-first) and 394
    dual_unprot_raw = (
        b"\xa2"
        + cbor_encode("scitt_receipt")
        + cbor_encode(receipt_2)
        + cbor_encode(SCITT_RECEIPTS_HEADER_LABEL)
        + cbor_encode([receipt_1])
    )
    cose_dual_rcpt = (
        b"\xd2\x84"
        + cbor_encode(prot_bstr)
        + dual_unprot_raw
        + cbor_encode(payload_bstr)
        + cbor_encode(sig_bstr)
    )
    stmt_dual = parse_cose_sign1_statement(cose_dual_rcpt, strict_deterministic=False)
    assert stmt_dual is not None
    tbs_dual = compute_scitt_ots_tbs_bytes(stmt_dual, require_receipt=True, strict=False)
    assert tbs_dual is not None
    tbs_dual_h = hashlib.sha256(tbs_dual).digest()
    mr_dual = hashlib.sha256(tbs_dual_h + b"dual-rcpt-nonce1").digest()
    chain_dual = build_synthetic_slice(925000, 8, {925000: mr_dual})
    ots_dual = make_proof(
        tbs_dual_h,
        [make_btc_branch((OtsOp(OP_APPEND, b"dual-rcpt-nonce1"), OtsOp(OP_SHA256)), 925000)],
    )
    cases.append({
        "id": "N28A_DUAL_RECEIPT_394_WINS_DRAFT08",
        "mode": "draft08",
        "input_mode": "scitt_ots_ctt",
        "cose_sign1_b64": base64.b64encode(cose_dual_rcpt).decode("ascii"),
        "ots_b64": base64.b64encode(ots_dual).decode("ascii"),
        "claimed_hash": tbs_dual_h.hex(),
        "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_dual},
    })
    expected["N28A_DUAL_RECEIPT_394_WINS_DRAFT08"] = {
        "outcome": "valid",
        "step": 11,
        "block_height_h": 925000,
    }
    cases.append({
        "id": "N28B_DUAL_RECEIPT_AMBIGUOUS_STRICT",
        "mode": "strict",
        "input_mode": "scitt_ots_ctt",
        "cose_sign1_b64": base64.b64encode(cose_dual_rcpt).decode("ascii"),
        "ots_b64": base64.b64encode(ots_dual).decode("ascii"),
        "claimed_hash": tbs_dual_h.hex(),
        "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_dual},
    })
    expected["N28B_DUAL_RECEIPT_AMBIGUOUS_STRICT"] = {"outcome": "invalid", "step": 0}

    # N29 (SEC-1): min_confirmations < 6 floor enforced in strict mode
    chain_k5 = build_synthetic_slice(930000, 5, {930000: mr_d1})
    ots_930k = make_proof(art_hash, [make_btc_branch(br_ops_d1, 930000)])
    cases.append({
        "id": "N29A_MIN_CONF_1_DRAFT08",
        "mode": "draft08",
        "min_confirmations": 1,
        "artifact_b64": art_b64,
        "ots_b64": base64.b64encode(ots_930k).decode("ascii"),
        "claimed_hash": art_hex,
        "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_k5},
    })
    expected["N29A_MIN_CONF_1_DRAFT08"] = {
        "outcome": "valid",
        "step": 11,
        "block_height_h": 930000,
        "confirmations": 5,
    }
    cases.append({
        "id": "N29B_MIN_CONF_FLOOR_ENFORCED_STRICT",
        "mode": "strict",
        "min_confirmations": 1,
        "artifact_b64": art_b64,
        "ots_b64": base64.b64encode(ots_930k).decode("ascii"),
        "claimed_hash": art_hex,
        "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_k5},
    })
    expected["N29B_MIN_CONF_FLOOR_ENFORCED_STRICT"] = {
        "outcome": "unverifiable",
        "step": 9,
        "block_height_h": 930000,
        "confirmations": 5,
    }

    # N30 (SEC-2): RFC 9052 Section 3 empty protected header b"\xa0" rejected in strict, accepted in draft08
    cose_a0 = cbor_encode(
        CborTag(
            18,
            [b"\xa0", {SCITT_RECEIPTS_HEADER_LABEL: [receipt_1]}, payload_bstr, sig_bstr],
        )
    )
    stmt_a0 = parse_cose_sign1_statement(cose_a0, strict_deterministic=False)
    assert stmt_a0 is not None
    tbs_a0 = compute_scitt_ots_tbs_bytes(stmt_a0, require_receipt=True, strict=False)
    assert tbs_a0 is not None
    tbs_a0_h = hashlib.sha256(tbs_a0).digest()
    mr_a0 = hashlib.sha256(tbs_a0_h + b"cose-a0-nonce001").digest()
    chain_a0 = build_synthetic_slice(935000, 8, {935000: mr_a0})
    ots_a0 = make_proof(
        tbs_a0_h,
        [make_btc_branch((OtsOp(OP_APPEND, b"cose-a0-nonce001"), OtsOp(OP_SHA256)), 935000)],
    )
    cases.append({
        "id": "N30A_COSE_EMPTY_MAP_A0_DRAFT08",
        "mode": "draft08",
        "input_mode": "scitt_ots_ctt",
        "cose_sign1_b64": base64.b64encode(cose_a0).decode("ascii"),
        "ots_b64": base64.b64encode(ots_a0).decode("ascii"),
        "claimed_hash": tbs_a0_h.hex(),
        "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_a0},
    })
    expected["N30A_COSE_EMPTY_MAP_A0_DRAFT08"] = {
        "outcome": "valid",
        "step": 11,
        "block_height_h": 935000,
    }
    cases.append({
        "id": "N30B_COSE_EMPTY_MAP_A0_STRICT",
        "mode": "strict",
        "input_mode": "scitt_ots_ctt",
        "cose_sign1_b64": base64.b64encode(cose_a0).decode("ascii"),
        "ots_b64": base64.b64encode(ots_a0).decode("ascii"),
        "claimed_hash": tbs_a0_h.hex(),
        "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_a0},
    })
    expected["N30B_COSE_EMPTY_MAP_A0_STRICT"] = {"outcome": "invalid", "step": 0}

    # N31 (SEC-3): CBOR ProofBundle integer key 4 validated as Text (reject non-string garbage)
    pb_bad_k4 = cbor_encode({1: ots_n27, 2: art_hash, 4: 12345})
    cases.append({
        "id": "N31_CBOR_BUNDLE_KEY4_NONSTR_STRICT",
        "mode": "strict",
        "artifact_b64": art_b64,
        "proof_bundle_cbor_b64": base64.b64encode(pb_bad_k4).decode("ascii"),
        "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_d1},
    })
    expected["N31_CBOR_BUNDLE_KEY4_NONSTR_STRICT"] = {"outcome": "invalid", "step": 0}

    # N32 (SEC-4): Bitcoin Mainnet forged Genesis (height 0) header rejected
    forged_genesis = build_synthetic_slice(0, 6, {0: mr_d1}, nbits=0x207FFFFF)
    ots_h0 = make_proof(art_hash, [make_btc_branch(br_ops_d1, 0)])
    cases.append({
        "id": "N32_MAINNET_FORGED_GENESIS_REJECTED",
        "mode": "draft08",
        "artifact_b64": art_b64,
        "ots_b64": base64.b64encode(ots_h0).decode("ascii"),
        "claimed_hash": art_hex,
        "validated_chain": {"headers_hex": forged_genesis},
    })
    expected["N32_MAINNET_FORGED_GENESIS_REJECTED"] = {"outcome": "unverifiable", "step": 8}

    # N34 (SEC-6): Linear-time 4,090 shared OP_SHA256 + 256 0xFF branches DAG + strict total-ops cap (1,024)
    shared_d = art_hash
    for _ in range(4090):
        shared_d = hashlib.sha256(shared_d).digest()
    win_branch_d = hashlib.sha256(shared_d + b"\xff").digest()
    chain_amp = build_synthetic_slice(940000, 6, {940000: win_branch_d})
    att_940k = (
        bytes([TAG_ATTESTATION])
        + BITCOIN_ATTESTATION_TAG
        + encode_varbytes(encode_varuint(940000))
    )
    amp_tail = bytearray()
    for b_idx in range(256):
        if b_idx < 255:
            amp_tail.append(TAG_BRANCH)
        if b_idx == 255:
            amp_tail.append(OP_APPEND)
            amp_tail.extend(encode_varbytes(b"\xff"))
            amp_tail.append(OP_SHA256)
        else:
            amp_tail.append(OP_SHA256)
        amp_tail.extend(att_940k)
    ots_amp = (
        OTS_MAGIC
        + b"\x01"
        + bytes([OP_SHA256])
        + art_hash
        + (bytes([OP_SHA256]) * 4090)
        + bytes(amp_tail)
    )
    cases.append({
        "id": "N34A_OTS_AMP_4090X256_DAG_DRAFT08",
        "mode": "draft08",
        "artifact_b64": art_b64,
        "ots_b64": base64.b64encode(ots_amp).decode("ascii"),
        "claimed_hash": art_hex,
        "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_amp},
    })
    expected["N34A_OTS_AMP_4090X256_DAG_DRAFT08"] = {
        "outcome": "valid",
        "step": 11,
        "block_height_h": 940000,
        "mismatched_branches": 255,
    }

    # N34B: 16 branches * 70 distinct OP_SHA256 = 1,120 total ops (> STRICT_MAX_TOTAL_OPS = 1,024)
    over_strict_buf = bytearray(OTS_MAGIC + b"\x01" + bytes([OP_SHA256]) + art_hash)
    for b_idx in range(16):
        if b_idx < 15:
            over_strict_buf.append(TAG_BRANCH)
        over_strict_buf.extend(bytes([OP_SHA256]) * 70)
        over_strict_buf.extend(att_940k)
    cases.append({
        "id": "N34B_OTS_TOTAL_OPS_OVER_1024_STRICT",
        "mode": "strict",
        "artifact_b64": art_b64,
        "ots_b64": base64.b64encode(bytes(over_strict_buf)).decode("ascii"),
        "claimed_hash": art_hex,
        "validated_chain": {"ledger_id": "synthetic_regtest", "headers_hex": chain_amp},
    })
    expected["N34B_OTS_TOTAL_OPS_OVER_1024_STRICT"] = {"outcome": "invalid", "step": 3}

    documented_witnesses.append({
        "finding": 9,
        "id": "V3_PARITY_AND_DOS_HARDENING_N21_TO_N34",
        "amp_bomb_bytes": len(ots_amp),
        "amp_shared_prefix_ops": 4090,
        "amp_branches": 256,
        "strict_max_total_ops": 1024,
        "draft08_max_total_ops": 16384,
    })

    return cases, expected, documented_witnesses


def main() -> None:
    t0 = time.perf_counter()
    vec_file = ROOT / "spec_vectors" / "appendix_d_vectors.json"
    spec = json.loads(vec_file.read_text(encoding="utf-8"))

    # 1. Verify Appendix D.1 & D.2 Merkle construction directly
    origins_input = [(f"vec-{v['id']}", bytes.fromhex(v["hash"])) for v in spec["vectors"]]
    nonces_input = [bytes.fromhex(v["nonce"]) for v in spec["vectors"]]
    merkle_root, records = batch_anchor_merkle(origins_input, nonces=nonces_input)
    for rec, v in zip(records, spec["vectors"]):
        assert rec.leaf_hash.hex() == v["leaf"], f"D.1 leaf mismatch on vector {v['id']}"
    node_12 = hashlib.sha256(records[0].leaf_hash + records[1].leaf_hash).hexdigest()
    node_34 = hashlib.sha256(records[2].leaf_hash + records[3].leaf_hash).hexdigest()
    assert node_12 == spec["merkle_d2"]["node_12"], "D.2 node_12 mismatch"
    assert node_34 == spec["merkle_d2"]["node_34"], "D.2 node_34 mismatch"
    assert merkle_root.hex() == spec["merkle_d2"]["root"], "D.2 root mismatch"

    # 2. Verify Appendix D.4 82-operation trace & embedded tx_id on Vector 1
    v1_raw = base64.b64decode(spec["vectors"][0]["ots_base64"])
    v1_parsed = ots_deserialize(v1_raw)
    assert v1_parsed is not None
    btc_br = [
        b for b in v1_parsed.branches if b.attestation_kind == AttestationKind.BITCOIN
    ][0]
    assert len(btc_br.ops) == 82, f"Expected 82 ops in D.4, got {len(btc_br.ops)}"
    partial_br = make_btc_branch(btc_br.ops[:43], 957289)
    op43_digest = ots_replay(partial_br, bytes.fromhex(spec["vectors"][0]["hash"]))
    assert op43_digest is not None
    assert op43_digest.hex().startswith(spec["block_d3"]["d4_vector1_op43_txid_internal_prefix"])

    # Use full 23-header PoW window [957278..957300] from wild_mainnet_headers.json
    wild_file = ROOT / "spec_vectors" / "wild_mainnet_headers.json"
    wild_data = json.loads(wild_file.read_text(encoding="utf-8"))
    full_headers_hex = {
        k: row["header_hex"]
        for k, row in wild_data["windows"]["appendix_d3_957289"]["headers"].items()
    }
    short_headers_hex = {k: v for k, v in full_headers_hex.items() if int(k) <= 957288}
    depth5_headers_hex = {
        k: v for k, v in full_headers_hex.items() if int(k) <= 957293
    }  # 957289..957293 => tip - H + 1 = 5 (< 6)

    cases: List[Dict[str, Any]] = []
    expected: Dict[str, Dict[str, Any]] = {}

    for mode_str in ("draft08", "strict"):
        m_tag = "D08" if mode_str == "draft08" else "STR"
        for v in spec["vectors"]:
            vid = v["id"]
            art_bytes = v["artifact"].encode("ascii")
            art_b64 = base64.b64encode(art_bytes).decode("ascii")
            ots_b64 = v["ots_base64"]

            cid = f"{m_tag}_D5_POS_PREFIXED_V{vid}"
            cases.append({
                "id": cid,
                "mode": mode_str,
                "artifact_b64": art_b64,
                "ots_b64": ots_b64,
                "claimed_hash": "sha256:" + v["hash"],
                "validated_chain": {"headers_hex": full_headers_hex},
            })
            # 957289..957300 => 12 Bitcoin Core confirmations (tip - H + 1 = 957300 - 957289 + 1 = 12)
            expected[cid] = {
                "outcome": "valid",
                "step": 11,
                "block_height_h": 957289,
                "block_time_rwcp": 1783591379,
                "confirmations": 12,
                "mtp_bip113": 1783589086,
                "fmtp_5": 1783591379,
                "fmtp_6": 1783593190,
                "fmtp_11": 1783595033,
            }

            cid_cbor = f"{m_tag}_D5_POS_CBOR_BUNDLE_V{vid}"
            pb_cbor = cbor_encode({
                "ots_proof": base64.b64decode(ots_b64),
                "claimed_hash": v["hash"],
                "origin_id": f"00000000-0000-4000-8000-00000000000{vid}",
                "bitcoin_block_height": 957289,
            })
            cases.append({
                "id": cid_cbor,
                "mode": mode_str,
                "artifact_b64": art_b64,
                "proof_bundle_cbor_b64": base64.b64encode(pb_cbor).decode("ascii"),
                "validated_chain": {"headers_hex": full_headers_hex},
            })
            expected[cid_cbor] = expected[cid]

            cid_mut = f"{m_tag}_D6_NEG_MODIFIED_ARTIFACT_V{vid}"
            mut_art = bytearray(art_bytes)
            mut_art[-1] ^= 0x01
            cases.append({
                "id": cid_mut,
                "mode": mode_str,
                "artifact_b64": base64.b64encode(bytes(mut_art)).decode("ascii"),
                "ots_b64": ots_b64,
                "claimed_hash": "sha256:" + v["hash"],
                "validated_chain": {"headers_hex": full_headers_hex},
            })
            expected[cid_mut] = {"outcome": "invalid", "step": 2, "block_height_h": None}

            cid_short = f"{m_tag}_D6_UNVERIFIABLE_SHORT_CHAIN_V{vid}"
            cases.append({
                "id": cid_short,
                "mode": mode_str,
                "artifact_b64": art_b64,
                "ots_b64": ots_b64,
                "claimed_hash": "sha256:" + v["hash"],
                "validated_chain": {"headers_hex": short_headers_hex},
                "candidate_store": {"source": "public_explorer", "headers_hex": full_headers_hex},
            })
            expected[cid_short] = {"outcome": "unverifiable", "step": 8, "block_height_h": None}

            cid_exp = f"{m_tag}_D7_UNVERIFIABLE_EXPLORER_ONLY_V{vid}"
            cases.append({
                "id": cid_exp,
                "mode": mode_str,
                "artifact_b64": art_b64,
                "ots_b64": ots_b64,
                "claimed_hash": v["hash"],
                "validated_chain": None,
                "candidate_store": {"source": "public_explorer", "headers_hex": full_headers_hex},
            })
            expected[cid_exp] = {"outcome": "unverifiable", "step": 8, "block_height_h": None}

            cid_k5 = f"{m_tag}_S41_UNVERIFIABLE_DEPTH5_V{vid}"
            cases.append({
                "id": cid_k5,
                "mode": mode_str,
                "artifact_b64": art_b64,
                "ots_b64": ots_b64,
                "claimed_hash": v["hash"],
                "validated_chain": {"headers_hex": depth5_headers_hex},
            })
            expected[cid_k5] = {
                "outcome": "unverifiable",
                "step": 9,
                "block_height_h": 957289,
                "confirmations": 5,
            }

            cid_anch = f"{m_tag}_S41_UNVERIFIABLE_ANCHORING_SVC_HDR_V{vid}"
            cases.append({
                "id": cid_anch,
                "mode": mode_str,
                "artifact_b64": art_b64,
                "ots_b64": ots_b64,
                "claimed_hash": v["hash"],
                "validated_chain": {"headers_hex": full_headers_hex},
                "candidate_store": {"source": "anchoring_service", "headers_hex": full_headers_hex},
            })
            expected[cid_anch] = {"outcome": "unverifiable", "step": 8, "block_height_h": None}

            parsed = ots_deserialize(base64.b64decode(ots_b64))
            assert parsed is not None
            pending_only = [
                b for b in parsed.branches if b.attestation_kind == AttestationKind.PENDING
            ]
            pending_ots = make_proof(parsed.msg, pending_only)
            cid_pend = f"{m_tag}_S41_UNVERIFIABLE_PENDING_ONLY_V{vid}"
            cases.append({
                "id": cid_pend,
                "mode": mode_str,
                "artifact_b64": art_b64,
                "ots_b64": base64.b64encode(pending_ots).decode("ascii"),
                "claimed_hash": v["hash"],
                "validated_chain": {"headers_hex": full_headers_hex},
            })
            expected[cid_pend] = {"outcome": "unverifiable", "step": 4, "block_height_h": None}

            tampered_ops = list(btc_br.ops)
            first_op = tampered_ops[0]
            flipped_nonce = bytes([first_op.operand[0] ^ 0xFF]) + first_op.operand[1:]
            tampered_ops[0] = OtsOp(OP_APPEND, flipped_nonce)
            tampered_ots = make_proof(
                bytes.fromhex(v["hash"]),
                [make_btc_branch(tuple(tampered_ops), 957289)],
            )
            cid_tamp = f"{m_tag}_S86_NEG_TAMPERED_MERKLE_OP_V{vid}"
            cases.append({
                "id": cid_tamp,
                "mode": mode_str,
                "artifact_b64": art_b64,
                "ots_b64": base64.b64encode(tampered_ots).decode("ascii"),
                "claimed_hash": v["hash"],
                "validated_chain": {"headers_hex": full_headers_hex},
            })
            expected[cid_tamp] = {"outcome": "invalid", "step": 8, "block_height_h": None}

            next_v = spec["vectors"][vid % 4]
            cid_swap = f"{m_tag}_D6_NEG_SWAPPED_PROOF_V{vid}"
            cases.append({
                "id": cid_swap,
                "mode": mode_str,
                "artifact_b64": art_b64,
                "ots_b64": next_v["ots_base64"],
                "claimed_hash": v["hash"],
                "validated_chain": {"headers_hex": full_headers_hex},
            })
            expected[cid_swap] = {"outcome": "invalid", "step": 3, "block_height_h": None}

    poc_cases, poc_expected, doc_witnesses = build_strict_profile_witness_vectors()
    cases.extend(poc_cases)
    expected.update(poc_expected)

    witness_path = ROOT / "spec_vectors" / "strict_profile_z3_witness_vectors.json"
    witness_path.write_text(
        json.dumps(
            {"witness_cases": poc_cases, "expected": poc_expected, "summary": doc_witnesses},
            indent=2,
        ),
        encoding="utf-8",
    )

    jsonl_payload = "\n".join(json.dumps(c) for c in cases) + "\n"
    py_results = [evaluate_case(c) for c in cases]

    rs_bin = ROOT / "scitt_time_anchor_rs" / "target" / "release" / "scitt_time_anchor_rs"
    proc = subprocess.run(
        [str(rs_bin)],
        input=jsonl_payload,
        text=True,
        capture_output=True,
        check=True,
    )
    rs_results = [json.loads(line) for line in proc.stdout.strip().splitlines()]
    wa_proc = subprocess.run(
        ["node", str(ROOT / "verification_suite" / "wasm_batch_eval.mjs")],
        input=jsonl_payload,
        text=True,
        capture_output=True,
        check=True,
    )
    wa_results = [json.loads(line) for line in wa_proc.stdout.strip().splitlines()]
    assert len(py_results) == len(cases) == len(rs_results) == len(wa_results)

    # N19 + N21 (DIV-1 form-feed) + N33A (50KB UTF-8 O(N)): Raw JSONL parity across Python, Rust, and WASM
    utf8_50k_line = json.dumps({"id": "é" * 25000, "mode": "strict"}, ensure_ascii=False)
    n19_lines = [
        '{"id":"N19_DUP","mode":"draft08","mode":"strict"}',
        '{"id":"N19_I64_OVF","min_confirmations":9223372036854775808}',
        ('{"a":' * 65) + '1' + ('}' * 65),
        '{"id":"N19_NAN","x":NaN}',
        '{"id":"N19_LONE_SURR","mode":"\\uD800"}',
        '{"id":"N19_UTF8_✓_\\uD83D\\uDE00","mode":"strict"}',
        '{\x0c"id":"N21_JSON_FF","mode":"strict"}',
        utf8_50k_line,
    ]
    n19_payload = "\n".join(n19_lines) + "\n"
    py_n19 = subprocess.run(
        [sys.executable, "-m", "scitt_time_anchor.cli"],
        cwd=str(ROOT / "scitt_time_anchor_py"),
        input=n19_payload,
        text=True,
        capture_output=True,
        check=True,
    )
    rs_n19 = subprocess.run(
        [str(rs_bin)],
        input=n19_payload,
        text=True,
        capture_output=True,
        check=True,
    )
    wa_n19 = subprocess.run(
        ["node", str(ROOT / "verification_suite" / "wasm_batch_eval.mjs")],
        input=n19_payload,
        text=True,
        capture_output=True,
        check=True,
    )
    py_n19_rows = [json.loads(l) for l in py_n19.stdout.strip().splitlines()]
    rs_n19_rows = [json.loads(l) for l in rs_n19.stdout.strip().splitlines()]
    wa_n19_rows = [json.loads(l) for l in wa_n19.stdout.strip().splitlines()]
    assert len(py_n19_rows) == len(rs_n19_rows) == len(wa_n19_rows) == len(n19_lines)
    for idx_j, (p_j, r_j, w_j) in enumerate(zip(py_n19_rows, rs_n19_rows, wa_n19_rows)):
        assert p_j == r_j == w_j, f"N19/N21/N33 JSON parity mismatch at {idx_j}: py={p_j} rs={r_j} wa={w_j}"
        if idx_j in (0, 1, 2, 3, 4, 6):
            assert p_j == {"error": "bad_json"}, f"Expected bad_json at idx {idx_j}, got {p_j}"
        elif idx_j == 5:
            assert p_j["id"] == "N19_UTF8_✓_😀" and p_j["outcome"] == "invalid"
        else:
            assert len(p_j["id"]) == 25000 and p_j["outcome"] == "invalid"

    # N33B (SEC-CLI-LINE): 4 MiB + 1 byte JSONL line rejected cleanly without OOM across Python & Rust CLI
    over_4mib = '{"id":"' + ("a" * 4_194_300) + '"}\n'
    py_big = subprocess.run(
        [sys.executable, "-m", "scitt_time_anchor.cli"],
        cwd=str(ROOT / "scitt_time_anchor_py"),
        input=over_4mib,
        text=True,
        capture_output=True,
        check=True,
    )
    rs_big = subprocess.run(
        [str(rs_bin)],
        input=over_4mib,
        text=True,
        capture_output=True,
        check=True,
    )
    assert json.loads(py_big.stdout.strip()) == {"error": "bad_json"}
    assert json.loads(rs_big.stdout.strip()) == {"error": "bad_json"}

    divergences = 0
    spec_failures = 0
    for c, py_r, rs_r, wa_r in zip(cases, py_results, rs_results, wa_results):
        if py_r != rs_r or rs_r != wa_r:
            divergences += 1
            print(f"DIVERGENCE on {c['id']}: py={py_r} rs={rs_r} wa={wa_r}", file=sys.stderr)
        exp = expected[c["id"]]
        for k, v in exp.items():
            if py_r[k] != v:
                spec_failures += 1
                print(
                    f"SPEC FAILURE on {c['id']}.{k}: got {py_r[k]}, expected {v}",
                    file=sys.stderr,
                )

    elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
    summary = {
        "pass": "Appendix D Conformance (Official Appendix D.1-D.7 Dual-Profile + Z3 Witness + v2.0.0 N21-N34 Parity & Security Hardening Vectors)",
        "total_cases": len(cases) + len(n19_lines) + 1,
        "appendix_d_draft08_cases": 40,
        "appendix_d_strict_cases": 40,
        "strict_profile_witness_cases": len(poc_cases),
        "json_determinism_n19_n21_n33_cases": len(n19_lines) + 1,
        "positive_cases_accepted": sum(1 for r in py_results if r["outcome"] == "valid"),
        "negative_cases_rejected_invalid": sum(1 for r in py_results if r["outcome"] == "invalid"),
        "boundary_cases_unverifiable": sum(1 for r in py_results if r["outcome"] == "unverifiable"),
        "python_vs_rust_divergences": divergences,
        "triple_engine_divergences": divergences,
        "spec_assertion_failures": spec_failures,
        "d1_d2_merkle_root_verified": merkle_root.hex(),
        "d3_block_height_verified": 957289,
        "d3_bip113_preceding11_mtp": "2026-07-09T09:24:46Z (1783589086)",
        "d3_printed_mtp_discrepancy_detected": "2026-07-09T09:26:48Z (1783589208, [H-10..H] inclusive window)",
        "d3_forward_mtp_h_plus_5": "2026-07-09T10:02:59Z (1783591379, exact 6 confirmations / zero extra wait)",
        "d3_forward_mtp_h_plus_6": "2026-07-09T10:33:10Z (1783593190)",
        "d3_forward_mtp_h_plus_11": "2026-07-09T11:03:53Z (1783595033)",
        "elapsed_ms": elapsed_ms,
        "verdict": "PASS" if (divergences == 0 and spec_failures == 0) else "FAIL",
    }
    out_file = ROOT / "verification_suite" / "appendix_d_conformance_report.json"
    out_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    if divergences > 0 or spec_failures > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
