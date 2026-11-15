"""Normative 11-step `VERIFY-ANCHOR` (`draft08`) and Candidate `-09` Strict Profile (`strict`)
state machine.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Tuple

from .bitcoin_chain import BitcoinHeader, CandidateHeaderStore, ValidatedHeaderChain
from .ots_parser import (
    HARDENED_MAX_RUNNING_BYTES,
    OP_SHA256,
    AttestationKind,
    OtsBranch,
    VerifierMode,
    ots_deserialize,
    ots_replay,
    verify_rfc6962_batch_prefix,
)

MIN_CONFIRMATIONS = 6


class Outcome(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    UNVERIFIABLE = "unverifiable"


@dataclass(frozen=True)
class ProofBundle:
    ots_proof: bytes
    claimed_hash: str
    origin_id: Optional[str] = None
    bitcoin_block_height: Optional[int] = None


@dataclass(frozen=True)
class VerificationResult:
    outcome: Outcome
    step: int
    mode: VerifierMode
    block_height_h: Optional[int] = None
    block_time_rwcp: Optional[int] = None
    confirmations: Optional[int] = None
    mtp_bip113: Optional[int] = None
    fmtp_5: Optional[int] = None
    fmtp_6: Optional[int] = None
    fmtp_11: Optional[int] = None
    mismatched_branches: int = 0


def _strip_prefix(claimed: str) -> str:
    if claimed.startswith("sha256:"):
        return claimed[7:]
    return claimed


def _is_canonical_hex64(s: str) -> bool:
    if len(s) != 64:
        return False
    for ch in s:
        if ch not in "0123456789abcdef":
            return False
    return True


class _BranchState(str, Enum):
    VERIFIED = "verified"
    MISMATCHED = "mismatched"
    UNAVAILABLE = "unavailable"
    UNSUPPORTED = "unsupported"


def verify_anchor(
    artifact_bytes: Optional[bytes],
    proof_bundle: ProofBundle,
    validated_chain: Optional[ValidatedHeaderChain],
    candidate_store: Optional[CandidateHeaderStore] = None,
    *,
    mode: VerifierMode = VerifierMode.DRAFT08,
    min_confirmations: int = MIN_CONFIRMATIONS,
    expected_ledger_id: Optional[str] = None,
    require_rfc6962_batch: bool = False,
) -> VerificationResult:
    strict = mode == VerifierMode.STRICT

    if artifact_bytes is None:
        return VerificationResult(Outcome.UNVERIFIABLE, step=1, mode=mode)

    computed_hash_bytes = hashlib.sha256(artifact_bytes).digest()
    computed_hash_hex = computed_hash_bytes.hex()

    stripped_claimed = _strip_prefix(proof_bundle.claimed_hash)
    if strict and not _is_canonical_hex64(stripped_claimed):
        return VerificationResult(Outcome.INVALID, step=2, mode=mode)
    if computed_hash_hex != stripped_claimed:
        return VerificationResult(Outcome.INVALID, step=2, mode=mode)

    parsed = ots_deserialize(proof_bundle.ots_proof, mode=mode)
    if parsed is None:
        return VerificationResult(Outcome.INVALID, step=3, mode=mode)
    if parsed.file_hash_op != OP_SHA256 or parsed.msg != computed_hash_bytes:
        return VerificationResult(Outcome.INVALID, step=3, mode=mode)

    btc_branches: List[OtsBranch] = [
        b
        for b in parsed.branches
        if b.attestation_kind == AttestationKind.BITCOIN and b.bitcoin_height is not None
    ]
    if not btc_branches:
        return VerificationResult(Outcome.UNVERIFIABLE, step=4, mode=mode)

    if strict and require_rfc6962_batch:
        for b in btc_branches:
            if not verify_rfc6962_batch_prefix(b):
                return VerificationResult(Outcome.INVALID, step=3, mode=mode)

    branch_states: List[_BranchState] = []
    verified_headers: List[Tuple[int, BitcoinHeader]] = []
    mismatched_count = 0

    for branch in btc_branches:
        assert branch.bitcoin_height is not None
        h = branch.bitcoin_height

        digest = ots_replay(
            branch,
            computed_hash_bytes,
            max_running_bytes=HARDENED_MAX_RUNNING_BYTES,
        )

        if candidate_store is not None:
            candidate_raw = candidate_store.fetch_block_header_by_height(h)
        elif validated_chain is not None:
            candidate_raw = validated_chain.raw_header_at(h)
        else:
            candidate_raw = None

        validated_hdr: Optional[BitcoinHeader] = None
        if validated_chain is not None:
            validated_hdr = validated_chain.validate_header_on_chain(
                h,
                candidate_raw,
                expected_ledger_id=expected_ledger_id,
            )

        if digest is None:
            branch_states.append(_BranchState.UNSUPPORTED)
        elif validated_hdr is None:
            branch_states.append(_BranchState.UNAVAILABLE)
        elif digest == validated_hdr.merkle_root_internal:
            branch_states.append(_BranchState.VERIFIED)
            verified_headers.append((h, validated_hdr))
        else:
            branch_states.append(_BranchState.MISMATCHED)
            mismatched_count += 1

    if not verified_headers:
        if any(
            st in (_BranchState.UNAVAILABLE, _BranchState.UNSUPPORTED)
            for st in branch_states
        ):
            return VerificationResult(
                Outcome.UNVERIFIABLE,
                step=8,
                mode=mode,
                mismatched_branches=mismatched_count,
            )
        return VerificationResult(
            Outcome.INVALID,
            step=8,
            mode=mode,
            mismatched_branches=mismatched_count,
        )

    verified_headers.sort(key=lambda pair: pair[0])

    if validated_chain is None:
        return VerificationResult(
            Outcome.UNVERIFIABLE,
            step=9,
            mode=mode,
            block_height_h=verified_headers[0][0],
            mismatched_branches=mismatched_count,
        )

    if strict:
        confirmed_candidates: List[Tuple[int, BitcoinHeader, int]] = []
        for h, hdr in verified_headers:
            k = validated_chain.confirmations_on(h)
            if k is not None and k >= min_confirmations:
                confirmed_candidates.append((h, hdr, k))
        if not confirmed_candidates:
            first_h, _ = verified_headers[0]
            first_k = validated_chain.confirmations_on(first_h)
            return VerificationResult(
                Outcome.UNVERIFIABLE,
                step=9,
                mode=mode,
                block_height_h=first_h,
                confirmations=first_k,
                mismatched_branches=mismatched_count,
            )
        best_h, best_hdr, best_k = confirmed_candidates[0]
    else:
        first_h, first_hdr = verified_headers[0]
        first_k = validated_chain.confirmations_on(first_h)
        if first_k is None or first_k < min_confirmations:
            return VerificationResult(
                Outcome.UNVERIFIABLE,
                step=9,
                mode=mode,
                block_height_h=first_h,
                confirmations=first_k,
                mismatched_branches=mismatched_count,
            )
        best_h, best_hdr, best_k = first_h, first_hdr, first_k

    mtp = validated_chain.median_time_past(best_h)
    fmtp_5 = validated_chain.forward_mtp_5(best_h)
    fmtp_6 = validated_chain.forward_mtp_6(best_h)
    fmtp_11 = validated_chain.forward_mtp_11(best_h)

    return VerificationResult(
        outcome=Outcome.VALID,
        step=11,
        mode=mode,
        block_height_h=best_h,
        block_time_rwcp=best_hdr.ntime,
        confirmations=best_k,
        mtp_bip113=mtp,
        fmtp_5=fmtp_5,
        fmtp_6=fmtp_6,
        fmtp_11=fmtp_11,
        mismatched_branches=mismatched_count,
    )
