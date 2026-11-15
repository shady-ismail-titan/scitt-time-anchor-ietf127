"""JSONL batch runner CLI for scitt_time_anchor_py (`--mode draft08` | `--mode strict`)."""

from __future__ import annotations

import argparse
import base64
import json
import sys
from typing import Any, Dict, Optional

from .bitcoin_chain import (
    BITCOIN_MAINNET_GENESIS_HEX,
    CandidateHeaderStore,
    HeaderSource,
    ValidatedHeaderChain,
    parse_u256_hex_64,
)
from .cbor_scitt import (
    compute_scitt_ots_tbs_bytes,
    parse_cose_sign1_statement,
    parse_proof_bundle_cbor,
)
from .ots_parser import VerifierMode
from .verifier import MIN_CONFIRMATIONS, Outcome, ProofBundle, verify_anchor


def _invalid_step0(case_id: str, mode: VerifierMode) -> Dict[str, Any]:
    return {
        "block_height_h": None,
        "block_time_rwcp": None,
        "confirmations": None,
        "fmtp_11": None,
        "fmtp_5": None,
        "fmtp_6": None,
        "id": case_id,
        "mismatched_branches": 0,
        "mode": mode.value,
        "mtp_bip113": None,
        "outcome": Outcome.INVALID.value,
        "step": 0,
    }


def _build_chain_from_cfg(
    vc_cfg: Dict[str, Any],
    mode: VerifierMode,
) -> Optional[ValidatedHeaderChain]:
    strict = mode == VerifierMode.STRICT
    try:
        hdr_map = {int(k): bytes.fromhex(v) for k, v in vc_cfg["headers_hex"].items()}
    except (KeyError, ValueError, TypeError):
        return None

    min_cw = 0
    if strict:
        cw_str = vc_cfg.get("min_chainwork_hex")
        if cw_str not in (None, "0", "0x0"):
            parsed_cw = parse_u256_hex_64(str(cw_str))
            if parsed_cw is None:
                return None
            min_cw = parsed_cw

    try:
        return ValidatedHeaderChain(
            hdr_map,
            ledger_id=vc_cfg.get("ledger_id", BITCOIN_MAINNET_GENESIS_HEX),
            verify_pow_and_links=vc_cfg.get("verify_pow_and_links", True),
            allow_sparse_checkpoints=vc_cfg.get("allow_sparse_checkpoints", False),
            enforce_retarget_4x_bound=(
                vc_cfg.get("enforce_retarget_4x_bound", False) and strict
            ),
            min_chainwork=min_cw,
        )
    except ValueError:
        return None


def evaluate_case(
    case: Dict[str, Any],
    default_mode: VerifierMode = VerifierMode.DRAFT08,
) -> Dict[str, Any]:
    case_id = str(case.get("id", "unknown"))
    mode_str = case.get("mode", default_mode.value)
    try:
        mode = VerifierMode(mode_str)
    except ValueError:
        return _invalid_step0(case_id, default_mode)

    strict = mode == VerifierMode.STRICT
    input_mode = case.get("input_mode", "raw")

    artifact_bytes: Optional[bytes]
    if input_mode == "cose_sign1":
        b64 = case.get("cose_sign1_b64")
        if not isinstance(b64, str):
            return _invalid_step0(case_id, mode)
        try:
            cose_raw = base64.b64decode(b64, validate=False)
        except Exception:
            return _invalid_step0(case_id, mode)
        stmt = parse_cose_sign1_statement(cose_raw, strict_deterministic=False)
        if stmt is None:
            return _invalid_step0(case_id, mode)
        artifact_bytes = stmt.raw_bytes
    elif input_mode == "scitt_ots_ctt":
        b64 = case.get("cose_sign1_b64")
        if not isinstance(b64, str):
            return _invalid_step0(case_id, mode)
        try:
            cose_raw = base64.b64decode(b64, validate=False)
        except Exception:
            return _invalid_step0(case_id, mode)
        stmt = parse_cose_sign1_statement(cose_raw, strict_deterministic=False)
        if stmt is None:
            return _invalid_step0(case_id, mode)
        rcpt_b64 = case.get("receipt_b64")
        rcpt_bytes = base64.b64decode(rcpt_b64) if isinstance(rcpt_b64, str) else None
        det_pl_b64 = case.get("detached_payload_b64")
        det_pl = base64.b64decode(det_pl_b64) if isinstance(det_pl_b64, str) else None
        req_rcpt = bool(case.get("require_receipt", strict))
        tbs = compute_scitt_ots_tbs_bytes(
            stmt,
            receipt_bytes=rcpt_bytes,
            detached_payload=det_pl,
            require_receipt=req_rcpt,
        )
        if tbs is None:
            return _invalid_step0(case_id, mode)
        artifact_bytes = tbs
    else:
        if case.get("artifact_b64") is None:
            artifact_bytes = None
        else:
            artifact_bytes = base64.b64decode(case["artifact_b64"])

    if case.get("proof_bundle_cbor_b64") is not None:
        pb_raw = base64.b64decode(case["proof_bundle_cbor_b64"])
        pb_dict = parse_proof_bundle_cbor(pb_raw, strict_deterministic=strict)
        if pb_dict is None:
            return _invalid_step0(case_id, mode)
        bundle = ProofBundle(
            ots_proof=pb_dict["ots_proof"],
            claimed_hash=pb_dict["claimed_hash"],
            origin_id=pb_dict.get("origin_id"),
            bitcoin_block_height=pb_dict.get("bitcoin_block_height"),
        )
    else:
        ots_b64 = case.get("ots_b64")
        claimed_hash = case.get("claimed_hash")
        if not isinstance(ots_b64, str) or not isinstance(claimed_hash, str):
            return _invalid_step0(case_id, mode)
        bundle = ProofBundle(
            ots_proof=base64.b64decode(ots_b64),
            claimed_hash=claimed_hash,
        )

    validated_chain: Optional[ValidatedHeaderChain] = None
    if isinstance(case.get("candidate_chains"), list):
        validated_chain = ValidatedHeaderChain.select_best_fork(
            case["candidate_chains"], mode
        )
    elif isinstance(case.get("validated_chain"), dict):
        validated_chain = _build_chain_from_cfg(case["validated_chain"], mode)

    cand_cfg = case.get("candidate_store")
    cand_store: Optional[CandidateHeaderStore] = None
    if isinstance(cand_cfg, dict):
        src_str = cand_cfg.get("source", "validated_node")
        try:
            source = HeaderSource(src_str)
        except ValueError:
            source = HeaderSource.PUBLIC_EXPLORER
        try:
            ch_map = {int(k): bytes.fromhex(v) for k, v in cand_cfg["headers_hex"].items()}
            cand_store = CandidateHeaderStore(ch_map, source=source)
        except (KeyError, ValueError, TypeError):
            return _invalid_step0(case_id, mode)

    res = verify_anchor(
        artifact_bytes=artifact_bytes,
        proof_bundle=bundle,
        validated_chain=validated_chain,
        candidate_store=cand_store,
        mode=mode,
        min_confirmations=int(case.get("min_confirmations", MIN_CONFIRMATIONS)),
        expected_ledger_id=case.get("expected_ledger_id"),
        require_rfc6962_batch=bool(case.get("require_rfc6962_batch", False)),
    )
    return {
        "block_height_h": res.block_height_h,
        "block_time_rwcp": res.block_time_rwcp,
        "confirmations": res.confirmations,
        "fmtp_11": res.fmtp_11,
        "fmtp_5": res.fmtp_5,
        "fmtp_6": res.fmtp_6,
        "id": case_id,
        "mismatched_branches": res.mismatched_branches,
        "mode": res.mode.value,
        "mtp_bip113": res.mtp_bip113,
        "outcome": res.outcome.value,
        "step": res.step,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Clean-room SCITT Time Anchor Verifier (Python)")
    ap.add_argument(
        "--mode",
        choices=["draft08", "strict"],
        default="draft08",
        help="Verification profile: draft08 (11-step baseline) or strict (Candidate -09 Strict Profile)",
    )
    args = ap.parse_args()
    default_mode = VerifierMode(args.mode)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        case = json.loads(line)
        out = evaluate_case(case, default_mode=default_mode)
        sys.stdout.write(json.dumps(out, sort_keys=True) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
