"""JSONL batch runner CLI for scitt_time_anchor_py (`--mode draft08` | `--mode strict`)."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import sys
from typing import Any, Dict, List, Optional, Tuple

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

MAX_JSON_DEPTH = 64
MAX_JSON_LINE_BYTES = 4_194_304
_I64_MIN = -(1 << 63)
_I64_MAX = (1 << 63) - 1
_U64_MAX = (1 << 64) - 1
_HEX_CHARS = frozenset("0123456789abcdefABCDEF")


def _parse_canonical_height_key(k: Any) -> Optional[int]:
    """Accept ONLY canonical unsigned decimal ASCII keys: '0' or '[1-9][0-9]*' <= u64::MAX."""
    if not isinstance(k, str) or not k or len(k) > 20:
        return None
    if len(k) > 1 and k[0] == "0":
        return None
    if not (k.isascii() and k.isdigit()):
        return None
    val = int(k)
    if val > _U64_MAX:
        return None
    return val


def _decode_hex_exact(s: Any) -> Optional[bytes]:
    if not isinstance(s, str) or (len(s) % 2) != 0:
        return None
    if not all(ch in _HEX_CHARS for ch in s):
        return None
    return bytes.fromhex(s)


def _decode_b64_exact(s: Any) -> Optional[bytes]:
    if not isinstance(s, str):
        return None
    cleaned = "".join(ch for ch in s if ch not in " \t\r\n")
    if not cleaned:
        return b""
    if (len(cleaned) % 4) != 0 or not cleaned.isascii():
        return None
    try:
        decoded = base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError):
        return None
    # RFC 4648 Section 3.5: reject non-zero trailing padding bits and non-final padding.
    if base64.b64encode(decoded).decode("ascii") != cleaned:
        return None
    return decoded


def _json_depth_exceeds(line: str, max_depth: int = MAX_JSON_DEPTH) -> bool:
    depth = 0
    in_str = False
    esc = False
    for ch in line:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "{[":
            depth += 1
            if depth > max_depth:
                return True
        elif ch in "}]":
            if depth > 0:
                depth -= 1
    return False


def _strict_object_pairs(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in pairs:
        try:
            k.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("Lone UTF-16 surrogate in JSON key") from exc
        if k in out:
            raise ValueError(f"Duplicate JSON object key: {k!r}")
        if isinstance(v, str):
            try:
                v.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ValueError("Lone UTF-16 surrogate in JSON string") from exc
        out[k] = v
    return out


def _strict_parse_int(tok: str) -> int:
    val = int(tok)
    if val < _I64_MIN or val > _I64_MAX:
        raise ValueError("Integer outside signed 64-bit range")
    return val


def _reject_json_float(_tok: str) -> Any:
    raise ValueError("Floating-point JSON numbers rejected in strict parser")


def _reject_json_constant(_tok: str) -> Any:
    raise ValueError("Non-RFC-8259 JSON constant rejected")


def parse_json_object_strict(line: str) -> Optional[Dict[str, Any]]:
    if len(line) > MAX_JSON_LINE_BYTES:
        return None
    if len(line.encode("utf-8", errors="surrogatepass")) > MAX_JSON_LINE_BYTES:
        return None
    if _json_depth_exceeds(line, MAX_JSON_DEPTH):
        return None
    try:
        obj = json.loads(
            line,
            object_pairs_hook=_strict_object_pairs,
            parse_int=_strict_parse_int,
            parse_float=_reject_json_float,
            parse_constant=_reject_json_constant,
        )
    except (ValueError, RecursionError, TypeError):
        return None
    if not isinstance(obj, dict):
        return None
    return obj


def _invalid_step0(case_id: str, mode: VerifierMode) -> Dict[str, Any]:
    return {
        "block_height_h": None,
        "block_time_rwcp": None,
        "confirmations": None,
        "cose_signature_verified": False,
        "fmtp_11": None,
        "fmtp_5": None,
        "fmtp_6": None,
        "id": case_id,
        "mismatched_branches": 0,
        "mode": mode.value,
        "mtp_bip113": None,
        "outcome": Outcome.INVALID.value,
        "step": 0,
        "verification_scope": "temporal_anchor_only",
    }


def _build_chain_from_cfg(
    vc_cfg: Dict[str, Any],
    mode: VerifierMode,
) -> Optional[ValidatedHeaderChain]:
    strict = mode == VerifierMode.STRICT
    raw_headers = vc_cfg.get("headers_hex")
    if not isinstance(raw_headers, dict):
        return None
    hdr_map: Dict[int, bytes] = {}
    for k, v in raw_headers.items():
        h_int = _parse_canonical_height_key(k)
        if h_int is None:
            return None
        raw_b = _decode_hex_exact(v)
        if raw_b is None:
            return None
        hdr_map[h_int] = raw_b

    min_cw = 0
    if strict:
        cw_str = vc_cfg.get("min_chainwork_hex")
        if cw_str not in (None, "0", "0x0"):
            if not isinstance(cw_str, str):
                return None
            parsed_cw = parse_u256_hex_64(cw_str)
            if parsed_cw is None:
                return None
            min_cw = parsed_cw

    ledger_id = vc_cfg.get("ledger_id", BITCOIN_MAINNET_GENESIS_HEX)
    if not isinstance(ledger_id, str):
        ledger_id = BITCOIN_MAINNET_GENESIS_HEX
    verify_pow = (
        True
        if strict
        else (
            vc_cfg["verify_pow_and_links"]
            if isinstance(vc_cfg.get("verify_pow_and_links"), bool)
            else True
        )
    )
    allow_sparse = (
        vc_cfg["allow_sparse_checkpoints"]
        if isinstance(vc_cfg.get("allow_sparse_checkpoints"), bool)
        else False
    )
    enforce_retarget = (
        True
        if strict
        else (
            vc_cfg["enforce_retarget_4x_bound"]
            if isinstance(vc_cfg.get("enforce_retarget_4x_bound"), bool)
            else False
        )
    )

    try:
        return ValidatedHeaderChain(
            hdr_map,
            ledger_id=ledger_id,
            verify_pow_and_links=verify_pow,
            allow_sparse_checkpoints=allow_sparse,
            enforce_retarget_4x_bound=enforce_retarget,
            enforce_consensus_targets=strict,
            min_chainwork=min_cw,
        )
    except ValueError:
        return None


def evaluate_case(
    case: Dict[str, Any],
    default_mode: VerifierMode = VerifierMode.DRAFT08,
) -> Dict[str, Any]:
    raw_id = case.get("id")
    case_id = raw_id if isinstance(raw_id, str) else "unknown"
    raw_mode = case.get("mode")
    mode_str = raw_mode if isinstance(raw_mode, str) else default_mode.value
    try:
        mode = VerifierMode(mode_str)
    except ValueError:
        return _invalid_step0(case_id, default_mode)

    strict = mode == VerifierMode.STRICT
    raw_im = case.get("input_mode")
    input_mode = raw_im if isinstance(raw_im, str) else "raw"

    artifact_bytes: Optional[bytes]
    if input_mode == "cose_sign1":
        cose_raw = _decode_b64_exact(case.get("cose_sign1_b64"))
        if cose_raw is None:
            return _invalid_step0(case_id, mode)
        stmt = parse_cose_sign1_statement(cose_raw, strict_deterministic=strict)
        if stmt is None:
            return _invalid_step0(case_id, mode)
        artifact_bytes = stmt.raw_bytes
    elif input_mode == "scitt_ots_ctt":
        cose_raw = _decode_b64_exact(case.get("cose_sign1_b64"))
        if cose_raw is None:
            return _invalid_step0(case_id, mode)
        stmt = parse_cose_sign1_statement(cose_raw, strict_deterministic=strict)
        if stmt is None:
            return _invalid_step0(case_id, mode)
        rcpt_raw = case.get("receipt_b64")
        if rcpt_raw is None:
            rcpt_bytes = None
        else:
            rcpt_bytes = _decode_b64_exact(rcpt_raw)
            if rcpt_bytes is None:
                return _invalid_step0(case_id, mode)
        det_raw = case.get("detached_payload_b64")
        if det_raw is None:
            det_pl = None
        else:
            det_pl = _decode_b64_exact(det_raw)
            if det_pl is None:
                return _invalid_step0(case_id, mode)
        req_rcpt_val = case.get("require_receipt")
        req_rcpt = req_rcpt_val if isinstance(req_rcpt_val, bool) else strict
        tbs = compute_scitt_ots_tbs_bytes(
            stmt,
            receipt_bytes=rcpt_bytes,
            detached_payload=det_pl,
            require_receipt=req_rcpt,
            strict=strict,
        )
        if tbs is None:
            return _invalid_step0(case_id, mode)
        artifact_bytes = tbs
    else:
        art_raw = case.get("artifact_b64")
        if art_raw is None:
            artifact_bytes = None
        else:
            artifact_bytes = _decode_b64_exact(art_raw)
            if artifact_bytes is None:
                return _invalid_step0(case_id, mode)

    pb_raw_val = case.get("proof_bundle_cbor_b64")
    if isinstance(pb_raw_val, str):
        pb_raw = _decode_b64_exact(pb_raw_val)
        if pb_raw is None:
            return _invalid_step0(case_id, mode)
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
        ots_raw = _decode_b64_exact(case.get("ots_b64"))
        claimed_hash = case.get("claimed_hash")
        if ots_raw is None or not isinstance(claimed_hash, str):
            return _invalid_step0(case_id, mode)
        bundle = ProofBundle(
            ots_proof=ots_raw,
            claimed_hash=claimed_hash,
        )

    validated_chain: Optional[ValidatedHeaderChain] = None
    if isinstance(case.get("candidate_chains"), list):
        valid_forks: List[ValidatedHeaderChain] = []
        for item in case["candidate_chains"]:
            if isinstance(item, dict):
                vc = _build_chain_from_cfg(item, mode)
                if vc is not None:
                    valid_forks.append(vc)
        if valid_forks:
            if mode == VerifierMode.DRAFT08:
                validated_chain = valid_forks[0]
            else:
                valid_forks.sort(key=lambda c: c.total_chainwork, reverse=True)
                validated_chain = valid_forks[0]
    elif isinstance(case.get("validated_chain"), dict):
        validated_chain = _build_chain_from_cfg(case["validated_chain"], mode)

    cand_cfg = case.get("candidate_store")
    cand_store: Optional[CandidateHeaderStore] = None
    if isinstance(cand_cfg, dict):
        src_str = cand_cfg.get("source", "validated_node")
        if not isinstance(src_str, str):
            src_str = "validated_node"
        try:
            source = HeaderSource(src_str)
        except ValueError:
            source = HeaderSource.PUBLIC_EXPLORER
        raw_ch = cand_cfg.get("headers_hex")
        if not isinstance(raw_ch, dict):
            return _invalid_step0(case_id, mode)
        ch_map: Dict[int, bytes] = {}
        for k, v in raw_ch.items():
            h_int = _parse_canonical_height_key(k)
            if h_int is None:
                return _invalid_step0(case_id, mode)
            raw_b = _decode_hex_exact(v)
            if raw_b is None:
                return _invalid_step0(case_id, mode)
            ch_map[h_int] = raw_b
        try:
            cand_store = CandidateHeaderStore(ch_map, source=source)
        except ValueError:
            return _invalid_step0(case_id, mode)

    mc_raw = case.get("min_confirmations")
    min_conf = (
        mc_raw
        if isinstance(mc_raw, int) and not isinstance(mc_raw, bool) and mc_raw >= 0
        else MIN_CONFIRMATIONS
    )
    exp_ledger = case.get("expected_ledger_id")
    if not isinstance(exp_ledger, str):
        exp_ledger = None
    req_batch_raw = case.get("require_rfc6962_batch")
    req_batch = req_batch_raw if isinstance(req_batch_raw, bool) else False

    res = verify_anchor(
        artifact_bytes=artifact_bytes,
        proof_bundle=bundle,
        validated_chain=validated_chain,
        candidate_store=cand_store,
        mode=mode,
        min_confirmations=min_conf,
        expected_ledger_id=exp_ledger,
        require_rfc6962_batch=req_batch,
    )
    return {
        "block_height_h": res.block_height_h,
        "block_time_rwcp": res.block_time_rwcp,
        "confirmations": res.confirmations,
        "cose_signature_verified": False,
        "fmtp_11": res.fmtp_11,
        "fmtp_5": res.fmtp_5,
        "fmtp_6": res.fmtp_6,
        "id": case_id,
        "mismatched_branches": res.mismatched_branches,
        "mode": res.mode.value,
        "mtp_bip113": res.mtp_bip113,
        "outcome": res.outcome.value,
        "step": res.step,
        "verification_scope": "temporal_anchor_only",
    }


def main() -> None:
    ap = argparse.ArgumentParser(
        description=(
            "Clean-room SCITT Time Anchor Verifier (Python). "
            "NOTE: Verifies temporal anchoring only; COSE cryptographic signature "
            "verification is delegated to your SCITT verifier / Trust Store."
        )
    )
    ap.add_argument(
        "--version",
        action="version",
        version="%(prog)s 2.0.0",
    )
    ap.add_argument(
        "--mode",
        choices=["draft08", "strict"],
        default="draft08",
        help="Verification profile: draft08 (11-step baseline) or strict (Candidate -09 Strict Profile)",
    )
    args = ap.parse_args()
    default_mode = VerifierMode(args.mode)

    stdin_buf = sys.stdin.buffer
    read_limit = MAX_JSON_LINE_BYTES + 2
    while True:
        raw = stdin_buf.readline(read_limit)
        if not raw:
            break
        if not raw.endswith(b"\n") and len(raw) >= read_limit:
            # Drain remainder of oversized line in bounded chunks without allocating unbounded memory.
            while True:
                drain = stdin_buf.readline(65_536)
                if not drain or drain.endswith(b"\n"):
                    break
            sys.stdout.write('{"error": "bad_json"}\n')
            continue
        if raw.endswith(b"\n"):
            raw = raw[:-1]
        if raw.endswith(b"\r"):
            raw = raw[:-1]
        if len(raw) > MAX_JSON_LINE_BYTES:
            sys.stdout.write('{"error": "bad_json"}\n')
            continue
        try:
            line = raw.decode("utf-8")
        except UnicodeDecodeError:
            sys.stdout.write('{"error": "bad_json"}\n')
            continue
        line = line.strip(" \t\r\n")
        if not line:
            continue
        case = parse_json_object_strict(line)
        if case is None:
            sys.stdout.write('{"error": "bad_json"}\n')
            continue
        out = evaluate_case(case, default_mode=default_mode)
        sys.stdout.write(json.dumps(out, sort_keys=True) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
