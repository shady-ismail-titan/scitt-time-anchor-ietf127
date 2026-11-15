"""Clean-room OpenTimestamps (.ots) parser, serializer, replay, and Merkle builders.

Uses an explicit O(1)-call-stack iterative state machine (`work` stack + single
`ops_stack` push/truncate), matching `scitt_time_anchor_rs/src/ots.rs` and
preventing stack overflow up to `DRAFT08_MAX_DEPTH = 4608` without raising
Python's recursion limit.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Sequence, Tuple

OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
OTS_VERSION = 1

OP_LEGACY_01 = 0x01
OP_SHA1 = 0x02
OP_RIPEMD160 = 0x03
OP_SHA256 = 0x08
OP_KECCAK256 = 0x67

OP_APPEND = 0xF0
OP_PREPEND = 0xF1
OP_REVERSE = 0xF2
OP_HEXLIFY = 0xF3

TAG_ATTESTATION = 0x00
TAG_BRANCH = 0xFF

BITCOIN_ATTESTATION_TAG = bytes.fromhex("0588960d73d71901")
PENDING_ATTESTATION_TAG = bytes.fromhex("83dfe30d2ef90c8e")

FILE_HASH_DIGEST_LENGTHS: Dict[int, int] = {
    OP_LEGACY_01: 20,
    OP_SHA1: 20,
    OP_RIPEMD160: 20,
    OP_SHA256: 32,
    OP_KECCAK256: 32,
}

DRAFT08_MAX_PROOF_BYTES = 1_048_576
DRAFT08_MAX_OPERAND_BYTES = 4_096
DRAFT08_MAX_BRANCHES = 256
DRAFT08_MAX_OPS_PER_BRANCH = 4_096
DRAFT08_MAX_DEPTH = 4_608

STRICT_MAX_PROOF_BYTES = 65_536
STRICT_MAX_OPERAND_BYTES = 512
HARDENED_MAX_RUNNING_BYTES = 4_096
STRICT_MAX_BRANCHES = 64
STRICT_MAX_OPS_PER_BRANCH = 128
STRICT_MAX_DEPTH = 256

# Matches `python-opentimestamps v0.4.5` `TimeAttestation.MAX_PAYLOAD_SIZE = 8192`
MAX_ATTESTATION_PAYLOAD_BYTES = 8_192
# Matches `python-opentimestamps v0.4.5` `PendingAttestation.MAX_URI_LENGTH = 1000`
DEFAULT_MAX_PENDING_URI_BYTES = 1_000

_ALLOWED_PENDING_URI_BYTES = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._/:"
)


class VerifierMode(str, Enum):
    DRAFT08 = "draft08"
    STRICT = "strict"
    # Backwards-compatible alias mapping to `"strict"`
    HARDENED20 = "strict"

    @classmethod
    def _missing_(cls, value: object) -> Optional["VerifierMode"]:
        return None


class AttestationKind(str, Enum):
    BITCOIN = "bitcoin"
    PENDING = "pending"
    UNKNOWN = "unknown"


def is_allowed_pending_uri_bytes(uri_bytes: bytes) -> bool:
    """Matches `PendingAttestation.ALLOWED_URI_CHARS` in `python-opentimestamps v0.4.5` (`notary.py:165`)."""
    return bool(uri_bytes) and all(b in _ALLOWED_PENDING_URI_BYTES for b in uri_bytes)


@dataclass(frozen=True)
class OtsOp:
    tag: int
    operand: bytes = b""


@dataclass(frozen=True)
class OtsBranch:
    ops: Tuple[OtsOp, ...]
    attestation_kind: AttestationKind
    attestation_tag: bytes
    bitcoin_height: Optional[int] = None
    pending_uri: Optional[str] = None
    raw_attestation_payload: bytes = b""


@dataclass(frozen=True)
class OtsProof:
    version: int
    file_hash_op: int
    msg: bytes
    branches: Tuple[OtsBranch, ...]


def encode_varuint(value: int) -> bytes:
    if value < 0:
        raise ValueError("varuint must be non-negative")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            break
    return bytes(out)


def encode_varbytes(data: bytes) -> bytes:
    return encode_varuint(len(data)) + data


def decode_varuint_py_unbounded(buf: bytes, pos: int) -> Optional[Tuple[int, int]]:
    """Baseline unsigned LEB128 bounded at 64 bits (allowing non-canonical trailing zeros)."""
    val = 0
    shift = 0
    n = len(buf)
    while True:
        if pos >= n or shift > 63:
            return None
        b = buf[pos]
        pos += 1
        if shift == 63 and (b & 0xFE) != 0:
            return None
        val |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return val, pos
        shift += 7


def decode_varuint_js_toint32(buf: bytes, pos: int) -> Optional[Tuple[int, int]]:
    """Exact model of `javascript-opentimestamps` (`src/context.js` / `verify-anchoring.org`):
    ECMAScript `<<` masks shift count modulo 32 (`shift & 31`) and coerces to signed `Int32`!
    """
    val = 0
    shift = 0
    n = len(buf)
    while True:
        if pos >= n:
            return None
        b = buf[pos]
        pos += 1
        masked_shift = shift & 31
        term = ((b & 0x7F) << masked_shift) & 0xFFFFFFFF
        if term & 0x80000000:
            term -= 0x100000000
        val |= term
        if val >= 0x80000000:
            val -= 0x100000000
        elif val < -0x80000000:
            val = ((val + 0x80000000) % 0x100000000) - 0x80000000
        if (b & 0x80) == 0:
            return val, pos
        shift += 7


def read_varuint(
    buf: bytes,
    pos: int,
    *,
    canonical_u32: bool,
) -> Optional[Tuple[int, int]]:
    if not canonical_u32:
        return decode_varuint_py_unbounded(buf, pos)

    val = 0
    n = len(buf)
    for idx in range(5):
        if pos >= n:
            return None
        b = buf[pos]
        pos += 1
        if idx > 0 and b == 0x00:
            return None
        if idx == 4 and (b & 0xF0) != 0:
            return None
        val |= (b & 0x7F) << (7 * idx)
        if (b & 0x80) == 0:
            return val, pos
    return None


def read_varbytes(
    buf: bytes,
    pos: int,
    *,
    min_len: int,
    max_len: int,
    canonical_u32: bool,
) -> Optional[Tuple[bytes, int]]:
    res = read_varuint(buf, pos, canonical_u32=canonical_u32)
    if res is None:
        return None
    ln, next_pos = res
    if ln < min_len or ln > max_len:
        return None
    end_pos = next_pos + ln
    if end_pos > len(buf):
        return None
    return buf[next_pos:end_pos], end_pos


def ots_deserialize(
    ots_bytes: bytes,
    mode: VerifierMode = VerifierMode.DRAFT08,
) -> Optional[OtsProof]:
    """Iterative O(1)-call-stack `.ots` parser matching `scitt_time_anchor_rs/src/ots.rs`."""
    strict = mode == VerifierMode.STRICT
    max_proof_bytes = STRICT_MAX_PROOF_BYTES if strict else DRAFT08_MAX_PROOF_BYTES
    if len(ots_bytes) < len(OTS_MAGIC) + 3 or len(ots_bytes) > max_proof_bytes:
        return None
    if ots_bytes[: len(OTS_MAGIC)] != OTS_MAGIC:
        return None

    pos = len(OTS_MAGIC)
    ver_res = read_varuint(ots_bytes, pos, canonical_u32=strict)
    if ver_res is None:
        return None
    version, pos = ver_res
    if version != OTS_VERSION or pos >= len(ots_bytes):
        return None

    file_hash_op = ots_bytes[pos]
    pos += 1
    if strict:
        if file_hash_op != OP_SHA256:
            return None
        digest_len = 32
    else:
        digest_len = FILE_HASH_DIGEST_LENGTHS.get(file_hash_op)  # type: ignore[assignment]
        if digest_len is None:
            return None

    if pos + digest_len > len(ots_bytes):
        return None
    msg = ots_bytes[pos : pos + digest_len]
    pos += digest_len

    max_operand_bytes = STRICT_MAX_OPERAND_BYTES if strict else DRAFT08_MAX_OPERAND_BYTES
    max_branches = STRICT_MAX_BRANCHES if strict else DRAFT08_MAX_BRANCHES
    max_ops_per_branch = STRICT_MAX_OPS_PER_BRANCH if strict else DRAFT08_MAX_OPS_PER_BRANCH
    max_depth = STRICT_MAX_DEPTH if strict else DRAFT08_MAX_DEPTH

    branches: List[OtsBranch] = []
    ops_stack: List[OtsOp] = []
    # Frame tuple: (state, ops_len, depth)
    work: List[Tuple[str, int, int]] = [("enter_ts", 0, 0)]
    total_len = len(ots_bytes)

    while work:
        state, ops_len, depth = work.pop()
        if state in ("enter_ts", "after_branch"):
            if depth > max_depth or pos >= total_len:
                return None
            del ops_stack[ops_len:]
            if ots_bytes[pos] == TAG_BRANCH:
                pos += 1
                work.append(("after_branch", ops_len, depth))
                work.append(("enter_step", ops_len, depth + 1))
            else:
                work.append(("enter_step", ops_len, depth + 1))
        else:
            if depth > max_depth or pos >= total_len:
                return None
            del ops_stack[ops_len:]
            tag = ots_bytes[pos]
            pos += 1

            if tag == TAG_ATTESTATION:
                if len(branches) >= max_branches or pos + 8 > total_len:
                    return None
                att_tag = ots_bytes[pos : pos + 8]
                pos += 8
                pl_res = read_varbytes(
                    ots_bytes,
                    pos,
                    min_len=0,
                    max_len=MAX_ATTESTATION_PAYLOAD_BYTES,
                    canonical_u32=strict,
                )
                if pl_res is None:
                    return None
                payload, pos = pl_res

                if att_tag == BITCOIN_ATTESTATION_TAG:
                    if not payload:
                        return None
                    h_res = read_varuint(payload, 0, canonical_u32=strict)
                    if h_res is None:
                        return None
                    height, p_end = h_res
                    if p_end != len(payload):
                        return None
                    branches.append(
                        OtsBranch(
                            ops=tuple(ops_stack),
                            attestation_kind=AttestationKind.BITCOIN,
                            attestation_tag=att_tag,
                            bitcoin_height=height,
                            raw_attestation_payload=payload,
                        )
                    )
                elif att_tag == PENDING_ATTESTATION_TAG:
                    uri_res = read_varbytes(
                        payload,
                        0,
                        min_len=1,
                        max_len=DEFAULT_MAX_PENDING_URI_BYTES,
                        canonical_u32=strict,
                    )
                    if uri_res is None:
                        return None
                    uri_bytes, p_end = uri_res
                    if p_end != len(payload):
                        return None
                    if not is_allowed_pending_uri_bytes(uri_bytes):
                        return None
                    uri_str = uri_bytes.decode("ascii")
                    branches.append(
                        OtsBranch(
                            ops=tuple(ops_stack),
                            attestation_kind=AttestationKind.PENDING,
                            attestation_tag=att_tag,
                            pending_uri=uri_str,
                            raw_attestation_payload=payload,
                        )
                    )
                else:
                    if strict:
                        return None
                    branches.append(
                        OtsBranch(
                            ops=tuple(ops_stack),
                            attestation_kind=AttestationKind.UNKNOWN,
                            attestation_tag=att_tag,
                            raw_attestation_payload=payload,
                        )
                    )
            elif tag in (OP_APPEND, OP_PREPEND):
                if len(ops_stack) >= max_ops_per_branch:
                    return None
                op_res = read_varbytes(
                    ots_bytes,
                    pos,
                    min_len=1,
                    max_len=max_operand_bytes,
                    canonical_u32=strict,
                )
                if op_res is None:
                    return None
                operand, pos = op_res
                ops_stack.append(OtsOp(tag=tag, operand=operand))
                work.append(("enter_ts", len(ops_stack), depth))
            elif tag == OP_SHA256:
                if len(ops_stack) >= max_ops_per_branch:
                    return None
                ops_stack.append(OtsOp(tag=OP_SHA256))
                work.append(("enter_ts", len(ops_stack), depth))
            elif tag in (
                OP_LEGACY_01,
                OP_SHA1,
                OP_RIPEMD160,
                OP_KECCAK256,
                OP_REVERSE,
                OP_HEXLIFY,
            ):
                if strict or len(ops_stack) >= max_ops_per_branch:
                    return None
                ops_stack.append(OtsOp(tag=tag))
                work.append(("enter_ts", len(ops_stack), depth))
            else:
                return None

    if pos != total_len or not branches:
        return None

    return OtsProof(
        version=version,
        file_hash_op=file_hash_op,
        msg=msg,
        branches=tuple(branches),
    )


def ots_replay(
    branch: OtsBranch,
    initial_digest: bytes,
    *,
    max_running_bytes: int = HARDENED_MAX_RUNNING_BYTES,
) -> Optional[bytes]:
    current = initial_digest
    for op in branch.ops:
        if op.tag == OP_APPEND:
            if len(current) + len(op.operand) > max_running_bytes:
                return None
            current = current + op.operand
        elif op.tag == OP_PREPEND:
            if len(op.operand) + len(current) > max_running_bytes:
                return None
            current = op.operand + current
        elif op.tag == OP_SHA256:
            current = hashlib.sha256(current).digest()
        else:
            return None
    if len(current) != 32:
        return None
    return current


def verify_rfc6962_batch_prefix(branch: OtsBranch) -> bool:
    """Optional producer-side Section 5.3 domain-separated batch helper (disabled by default on v1 `.ots`)."""
    ops = branch.ops
    if len(ops) < 3:
        return False
    if ops[0].tag != OP_APPEND or len(ops[0].operand) != 16:
        return False
    if ops[1] != OtsOp(tag=OP_PREPEND, operand=b"\x00"):
        return False
    if ops[2] != OtsOp(tag=OP_SHA256):
        return False

    idx = 3
    while idx < len(ops):
        cur = ops[idx]
        if cur.tag in (OP_APPEND, OP_PREPEND) and len(cur.operand) == 32:
            if idx + 2 < len(ops) and ops[idx + 1] == OtsOp(tag=OP_PREPEND, operand=b"\x01"):
                if ops[idx + 2] != OtsOp(tag=OP_SHA256):
                    return False
                idx += 3
                continue
        break
    return True


def ots_serialize_single_branch(
    msg_digest: bytes,
    ops: Sequence[OtsOp],
    *,
    bitcoin_height: Optional[int] = None,
    pending_uri: Optional[str] = None,
    file_hash_op: int = OP_SHA256,
) -> bytes:
    out = bytearray(OTS_MAGIC)
    out.extend(encode_varuint(OTS_VERSION))
    out.append(file_hash_op)
    out.extend(msg_digest)
    for op in ops:
        out.append(op.tag)
        if op.tag in (OP_APPEND, OP_PREPEND):
            out.extend(encode_varbytes(op.operand))
    out.append(TAG_ATTESTATION)
    if bitcoin_height is not None:
        out.extend(BITCOIN_ATTESTATION_TAG)
        out.extend(encode_varbytes(encode_varuint(bitcoin_height)))
    elif pending_uri is not None:
        out.extend(PENDING_ATTESTATION_TAG)
        out.extend(encode_varbytes(encode_varbytes(pending_uri.encode("ascii"))))
    else:
        raise ValueError("Specify bitcoin_height or pending_uri")
    return bytes(out)


def ots_serialize(proof: OtsProof) -> bytes:
    if not proof.branches:
        raise ValueError("Proof must contain at least one branch")
    out = bytearray(OTS_MAGIC)
    out.extend(encode_varuint(proof.version))
    out.append(proof.file_hash_op)
    out.extend(proof.msg)
    for idx, br in enumerate(proof.branches):
        if idx < len(proof.branches) - 1:
            out.append(TAG_BRANCH)
        for op in br.ops:
            out.append(op.tag)
            if op.tag in (OP_APPEND, OP_PREPEND):
                out.extend(encode_varbytes(op.operand))
        out.append(TAG_ATTESTATION)
        out.extend(br.attestation_tag)
        if br.attestation_kind == AttestationKind.BITCOIN and br.bitcoin_height is not None:
            out.extend(encode_varbytes(encode_varuint(br.bitcoin_height)))
        elif br.attestation_kind == AttestationKind.PENDING and br.pending_uri is not None:
            out.extend(encode_varbytes(encode_varbytes(br.pending_uri.encode("ascii"))))
        else:
            out.extend(encode_varbytes(br.raw_attestation_payload))
    return bytes(out)


@dataclass(frozen=True)
class BatchOrigin:
    origin_id: str
    claimed_hash: str
    nonce: bytes
    leaf_hash: bytes
    branch_ops: Tuple[OtsOp, ...]


def batch_anchor_merkle(
    items: Sequence[Tuple[str, bytes]],
    *,
    nonces: Optional[Sequence[bytes]] = None,
    rfc6962_domain_sep: bool = False,
) -> Tuple[bytes, List[BatchOrigin]]:
    if not items:
        raise ValueError("BATCH-ANCHOR requires at least 1 artifact")
    if nonces is not None and len(nonces) != len(items):
        raise ValueError("nonces length mismatch")

    per_item_ops: List[List[OtsOp]] = []
    origins_meta: List[Tuple[str, str, bytes, bytes]] = []
    level_hashes: List[bytes] = []

    for i, (origin_id, digest32) in enumerate(items):
        if len(digest32) != 32:
            raise ValueError("Expected 32-byte SHA-256 digest")
        nonce = nonces[i] if nonces is not None else secrets.token_bytes(16)
        if len(nonce) != 16:
            raise ValueError("Nonce must be 16 bytes")
        if rfc6962_domain_sep:
            ops = [
                OtsOp(OP_APPEND, nonce),
                OtsOp(OP_PREPEND, b"\x00"),
                OtsOp(OP_SHA256),
            ]
            leaf = hashlib.sha256(b"\x00" + digest32 + nonce).digest()
        else:
            ops = [
                OtsOp(OP_APPEND, nonce),
                OtsOp(OP_SHA256),
            ]
            leaf = hashlib.sha256(digest32 + nonce).digest()
        per_item_ops.append(ops)
        origins_meta.append((origin_id, digest32.hex(), nonce, leaf))
        level_hashes.append(leaf)

    member_indices: List[List[int]] = [[i] for i in range(len(items))]

    while len(level_hashes) > 1:
        next_hashes: List[bytes] = []
        next_members: List[List[int]] = []
        idx = 0
        while idx < len(level_hashes):
            if idx + 1 < len(level_hashes):
                left_h = level_hashes[idx]
                right_h = level_hashes[idx + 1]
                for m in member_indices[idx]:
                    per_item_ops[m].append(OtsOp(OP_APPEND, right_h))
                    if rfc6962_domain_sep:
                        per_item_ops[m].append(OtsOp(OP_PREPEND, b"\x01"))
                    per_item_ops[m].append(OtsOp(OP_SHA256))
                for m in member_indices[idx + 1]:
                    per_item_ops[m].append(OtsOp(OP_PREPEND, left_h))
                    if rfc6962_domain_sep:
                        per_item_ops[m].append(OtsOp(OP_PREPEND, b"\x01"))
                    per_item_ops[m].append(OtsOp(OP_SHA256))
                parent = (
                    hashlib.sha256(b"\x01" + left_h + right_h).digest()
                    if rfc6962_domain_sep
                    else hashlib.sha256(left_h + right_h).digest()
                )
                next_hashes.append(parent)
                next_members.append(member_indices[idx] + member_indices[idx + 1])
                idx += 2
            else:
                next_hashes.append(level_hashes[idx])
                next_members.append(member_indices[idx])
                idx += 1
        level_hashes = next_hashes
        member_indices = next_members

    root = level_hashes[0]
    results = [
        BatchOrigin(
            origin_id=origins_meta[i][0],
            claimed_hash=origins_meta[i][1],
            nonce=origins_meta[i][2],
            leaf_hash=origins_meta[i][3],
            branch_ops=tuple(per_item_ops[i]),
        )
        for i in range(len(items))
    ]
    return root, results
