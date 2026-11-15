"""Clean-room dual-profile (`draft08` & `strict`) reference verifier for
`draft-fassbender-scitt-time-anchor-08` ("Umarise's Bitcoin-Anchored Temporal Proofs")
and Candidate `-09` Strict Profile.

Zero external dependencies (Python 3 standard library only).
"""

from .bitcoin_chain import (
    BITCOIN_MAINNET_BIP113_HEIGHT,
    BITCOIN_MAINNET_GENESIS_HEX,
    BitcoinHeader,
    CandidateHeaderStore,
    HeaderSource,
    ValidatedHeaderChain,
    block_work_from_target,
    parse_u256_hex_64,
    set_compact_exact,
)
from .cbor_scitt import (
    SCITT_RECEIPTS_HEADER_LABEL,
    compute_scitt_ots_tbs_bytes,
    decode_cbor,
    encode_det_cbor,
    extract_embedded_receipts,
    parse_cose_sign1_statement,
    parse_proof_bundle_cbor,
)
from .ots_parser import (
    AttestationKind,
    BatchOrigin,
    OtsBranch,
    OtsOp,
    OtsProof,
    VerifierMode,
    batch_anchor_merkle,
    decode_varuint_js_toint32,
    decode_varuint_py_unbounded,
    is_allowed_pending_uri_bytes,
    ots_deserialize,
    ots_replay,
    ots_serialize,
    verify_rfc6962_batch_prefix,
)
from .verifier import (
    MIN_CONFIRMATIONS,
    Outcome,
    ProofBundle,
    VerificationResult,
    verify_anchor,
)

__all__ = [
    "AttestationKind",
    "BITCOIN_MAINNET_BIP113_HEIGHT",
    "BITCOIN_MAINNET_GENESIS_HEX",
    "BatchOrigin",
    "BitcoinHeader",
    "CandidateHeaderStore",
    "HeaderSource",
    "MIN_CONFIRMATIONS",
    "OtsBranch",
    "OtsOp",
    "OtsProof",
    "Outcome",
    "ProofBundle",
    "SCITT_RECEIPTS_HEADER_LABEL",
    "ValidatedHeaderChain",
    "VerificationResult",
    "VerifierMode",
    "batch_anchor_merkle",
    "block_work_from_target",
    "compute_scitt_ots_tbs_bytes",
    "decode_cbor",
    "decode_varuint_js_toint32",
    "decode_varuint_py_unbounded",
    "encode_det_cbor",
    "extract_embedded_receipts",
    "is_allowed_pending_uri_bytes",
    "ots_deserialize",
    "ots_replay",
    "ots_serialize",
    "parse_cose_sign1_statement",
    "parse_proof_bundle_cbor",
    "parse_u256_hex_64",
    "set_compact_exact",
    "verify_anchor",
    "verify_rfc6962_batch_prefix",
]
