"""Clean-room deterministic RFC 8949 CBOR codec for ProofBundle (Section 3.4.3),
`OTSProofBundleCBOR`, and RFC 9921 / RFC 9942 / RFC 9943 SCITT signature+receipt imprint binding.

Zero external dependencies (Python 3 standard library only).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

MAX_CBOR_DEPTH = 16
MAX_CBOR_BYTES = 262_144
COSE_SIGN1_TAG = 18
# RFC 9942 Section 8 IANA COSE Header parameter `receipts` (`394` => `[ + COSE_Receipt ]`)
SCITT_RECEIPTS_HEADER_LABEL = 394


@dataclass(frozen=True)
class CborTag:
    tag: int
    value: Any


def _encode_uint_header(major: int, val: int) -> bytes:
    prefix = major << 5
    if val < 24:
        return bytes([prefix | val])
    if val < 256:
        return bytes([prefix | 24, val])
    if val < 65_536:
        return bytes([prefix | 25]) + val.to_bytes(2, "big")
    if val < (1 << 32):
        return bytes([prefix | 26]) + val.to_bytes(4, "big")
    if val < (1 << 64):
        return bytes([prefix | 27]) + val.to_bytes(8, "big")
    raise ValueError("CBOR integer exceeds 64 bits")


def encode_det_cbor(obj: Any) -> bytes:
    """Deterministic CBOR encoder (RFC 8949 Section 4.2.1 Core Deterministic Encoding)."""
    if isinstance(obj, CborTag):
        return _encode_uint_header(6, obj.tag) + encode_det_cbor(obj.value)
    if obj is None:
        return b"\xf6"
    if obj is False:
        return b"\xf4"
    if obj is True:
        return b"\xf5"
    if isinstance(obj, int):
        if obj >= 0:
            return _encode_uint_header(0, obj)
        return _encode_uint_header(1, -1 - obj)
    if isinstance(obj, (bytes, bytearray)):
        b = bytes(obj)
        return _encode_uint_header(2, len(b)) + b
    if isinstance(obj, str):
        b = obj.encode("utf-8")
        return _encode_uint_header(3, len(b)) + b
    if isinstance(obj, (list, tuple)):
        parts = [encode_det_cbor(x) for x in obj]
        return _encode_uint_header(4, len(parts)) + b"".join(parts)
    if isinstance(obj, dict):
        encoded_pairs: List[Tuple[bytes, bytes]] = []
        for k, v in obj.items():
            ek = encode_det_cbor(k)
            ev = encode_det_cbor(v)
            encoded_pairs.append((ek, ev))
        encoded_pairs.sort(key=lambda kv: kv[0])
        for idx in range(1, len(encoded_pairs)):
            if encoded_pairs[idx][0] == encoded_pairs[idx - 1][0]:
                raise ValueError("Duplicate CBOR map key")
        body = b"".join(ek + ev for ek, ev in encoded_pairs)
        return _encode_uint_header(5, len(encoded_pairs)) + body
    raise TypeError(f"Unsupported CBOR type: {type(obj)!r}")


def _read_uint(
    buf: bytes, pos: int, add_info: int, *, strict_det: bool
) -> Optional[Tuple[int, int]]:
    if add_info < 24:
        return add_info, pos
    if add_info == 24:
        if pos + 1 > len(buf):
            return None
        val = buf[pos]
        if strict_det and val < 24:
            return None
        return val, pos + 1
    if add_info == 25:
        if pos + 2 > len(buf):
            return None
        val = int.from_bytes(buf[pos : pos + 2], "big")
        if strict_det and val < 256:
            return None
        return val, pos + 2
    if add_info == 26:
        if pos + 4 > len(buf):
            return None
        val = int.from_bytes(buf[pos : pos + 4], "big")
        if strict_det and val < 65_536:
            return None
        return val, pos + 4
    if add_info == 27:
        if pos + 8 > len(buf):
            return None
        val = int.from_bytes(buf[pos : pos + 8], "big")
        if strict_det and val < (1 << 32):
            return None
        return val, pos + 8
    return None


def _decode_item(
    buf: bytes,
    pos: int,
    depth: int,
    *,
    strict_det: bool,
    allow_any_tag: bool,
) -> Optional[Tuple[Any, int]]:
    if depth > MAX_CBOR_DEPTH or pos >= len(buf):
        return None
    initial = buf[pos]
    major = initial >> 5
    add_info = initial & 0x1F
    pos += 1

    if major == 0:
        return _read_uint(buf, pos, add_info, strict_det=strict_det)
    if major == 1:
        res = _read_uint(buf, pos, add_info, strict_det=strict_det)
        if res is None:
            return None
        val, next_pos = res
        return -1 - val, next_pos
    if major == 2:
        res = _read_uint(buf, pos, add_info, strict_det=strict_det)
        if res is None:
            return None
        ln, next_pos = res
        if next_pos + ln > len(buf):
            return None
        return buf[next_pos : next_pos + ln], next_pos + ln
    if major == 3:
        res = _read_uint(buf, pos, add_info, strict_det=strict_det)
        if res is None:
            return None
        ln, next_pos = res
        if next_pos + ln > len(buf):
            return None
        try:
            text = buf[next_pos : next_pos + ln].decode("utf-8")
        except UnicodeDecodeError:
            return None
        return text, next_pos + ln
    if major == 4:
        res = _read_uint(buf, pos, add_info, strict_det=strict_det)
        if res is None:
            return None
        ln, next_pos = res
        if ln > 4096 or ln > (len(buf) - next_pos):
            return None
        arr: List[Any] = []
        for _ in range(ln):
            item_res = _decode_item(
                buf,
                next_pos,
                depth + 1,
                strict_det=strict_det,
                allow_any_tag=allow_any_tag,
            )
            if item_res is None:
                return None
            item, next_pos = item_res
            arr.append(item)
        return arr, next_pos
    if major == 5:
        res = _read_uint(buf, pos, add_info, strict_det=strict_det)
        if res is None:
            return None
        ln, next_pos = res
        if ln > 4096 or (ln * 2) > (len(buf) - next_pos):
            return None
        out_map: Dict[Any, Any] = {}
        seen_raw_keys: List[bytes] = []
        for _ in range(ln):
            k_start = next_pos
            k_res = _decode_item(
                buf,
                next_pos,
                depth + 1,
                strict_det=strict_det,
                allow_any_tag=False,
            )
            if k_res is None:
                return None
            k_val, k_end = k_res
            if isinstance(k_val, (list, dict, CborTag, bool)) or k_val is None:
                return None
            raw_k = buf[k_start:k_end]
            if strict_det and seen_raw_keys and raw_k <= seen_raw_keys[-1]:
                return None
            if k_val in out_map:
                return None
            seen_raw_keys.append(raw_k)
            v_res = _decode_item(
                buf,
                k_end,
                depth + 1,
                strict_det=strict_det,
                allow_any_tag=allow_any_tag,
            )
            if v_res is None:
                return None
            v_val, next_pos = v_res
            out_map[k_val] = v_val
        return out_map, next_pos
    if major == 6:
        res = _read_uint(buf, pos, add_info, strict_det=strict_det)
        if res is None:
            return None
        tag_num, next_pos = res
        if not allow_any_tag and tag_num != COSE_SIGN1_TAG:
            return None
        inner_res = _decode_item(
            buf,
            next_pos,
            depth + 1,
            strict_det=strict_det,
            allow_any_tag=allow_any_tag,
        )
        if inner_res is None:
            return None
        inner_val, end_pos = inner_res
        return CborTag(tag=tag_num, value=inner_val), end_pos
    if major == 7:
        if add_info == 20:
            return False, pos
        if add_info == 21:
            return True, pos
        if add_info == 22:
            return None, pos
        return None
    return None


def decode_cbor(data: bytes, *, strict_deterministic: bool = True) -> Optional[Any]:
    if not data or len(data) > MAX_CBOR_BYTES:
        return None
    res = _decode_item(
        data,
        0,
        0,
        strict_det=strict_deterministic,
        allow_any_tag=(not strict_deterministic),
    )
    if res is None:
        return None
    val, end_pos = res
    if end_pos != len(data):
        return None
    return val


@dataclass(frozen=True)
class CoseSign1Statement:
    protected_hdr: bytes
    unprotected_hdr: Dict[Any, Any]
    payload: Optional[bytes]
    signature: bytes
    raw_bytes: bytes


def parse_cose_sign1_statement(
    cbor_bytes: bytes,
    *,
    strict_deterministic: bool = False,
) -> Optional[CoseSign1Statement]:
    if not cbor_bytes or len(cbor_bytes) > MAX_CBOR_BYTES:
        return None
    res = _decode_item(
        cbor_bytes,
        0,
        0,
        strict_det=strict_deterministic,
        allow_any_tag=True,
    )
    if res is None:
        return None
    decoded, end_pos = res
    if end_pos != len(cbor_bytes):
        return None
    if isinstance(decoded, CborTag):
        if decoded.tag != COSE_SIGN1_TAG:
            return None
        body = decoded.value
    else:
        body = decoded

    if not isinstance(body, list) or len(body) != 4:
        return None
    prot, unprot, payload, sig = body
    if not isinstance(prot, bytes) or not isinstance(unprot, dict) or not isinstance(sig, bytes):
        return None
    if payload is not None and not isinstance(payload, bytes):
        return None
    if len(sig) == 0:
        return None
    if strict_deterministic and len(prot) > 0:
        prot_res = _decode_item(prot, 0, 0, strict_det=True, allow_any_tag=True)
        if prot_res is None:
            return None
        prot_val, prot_end = prot_res
        # RFC 9052 Section 3: an empty protected header map MUST be encoded as zero-length bstr (b""),
        # never as the 1-byte empty CBOR map b"\xa0".
        if prot_end != len(prot) or not isinstance(prot_val, dict) or len(prot_val) == 0:
            return None
    return CoseSign1Statement(
        protected_hdr=prot,
        unprotected_hdr=unprot,
        payload=payload,
        signature=sig,
        raw_bytes=cbor_bytes,
    )


def _has_ambiguous_receipt_headers(stmt: CoseSign1Statement) -> bool:
    return (
        SCITT_RECEIPTS_HEADER_LABEL in stmt.unprotected_hdr
        and "scitt_receipt" in stmt.unprotected_hdr
    )


def extract_embedded_receipts(
    stmt: CoseSign1Statement,
    *,
    strict: bool = False,
) -> Optional[List[bytes]]:
    """Extract ALL RFC 9942 COSE Receipts (`header 394` => `[ + COSE_Receipt ]`, or single `bstr`).
    Prioritizes integer label `394` over legacy `"scitt_receipt"`. In `strict` mode, rejects
    statements containing BOTH `394` and `"scitt_receipt"` simultaneously as ambiguous.
    """
    if strict and _has_ambiguous_receipt_headers(stmt):
        return None
    for key in (SCITT_RECEIPTS_HEADER_LABEL, "scitt_receipt"):
        if key in stmt.unprotected_hdr:
            val = stmt.unprotected_hdr[key]
            if isinstance(val, bytes) and len(val) > 0:
                return [val]
            if isinstance(val, list) and len(val) > 0:
                out: List[bytes] = []
                for item in val:
                    if not isinstance(item, bytes) or len(item) == 0:
                        return None
                    out.append(item)
                return out
            return None
    return None


def compute_scitt_ots_tbs_bytes(
    stmt: CoseSign1Statement,
    *,
    receipt_bytes: Optional[bytes] = None,
    detached_payload: Optional[bytes] = None,
    require_receipt: bool = True,
    strict: bool = False,
) -> Optional[bytes]:
    """Deterministic CBOR commitment aligned with RFC 9921 §3.1.1 (`bstr`-wrapped `signature`),
    `protected` header, `SHA-256(payload)`, and all RFC 9942 receipts in `header 394` (`[ + COSE_Receipt ]`).
    Never emits `0xf6` (`null`) or unallocated IANA URNs.
    """
    eff_payload = stmt.payload if stmt.payload is not None else detached_payload
    if eff_payload is None:
        return None
    if strict and _has_ambiguous_receipt_headers(stmt):
        return None

    if receipt_bytes is not None:
        if len(receipt_bytes) == 0:
            return None
        receipts_list: List[bytes] = [receipt_bytes]
    else:
        receipts_list = extract_embedded_receipts(stmt, strict=strict) or []

    if require_receipt and not receipts_list:
        return None

    payload_digest = hashlib.sha256(eff_payload).digest()
    sig_bstr_cbor = encode_det_cbor(stmt.signature)

    if not receipts_list:
        return encode_det_cbor([stmt.protected_hdr, payload_digest, sig_bstr_cbor])

    rcpt_digests = [hashlib.sha256(r).digest() for r in receipts_list]
    rcpt_set_digest = hashlib.sha256(encode_det_cbor(rcpt_digests)).digest()
    return encode_det_cbor(
        [stmt.protected_hdr, payload_digest, sig_bstr_cbor, rcpt_set_digest]
    )


def parse_proof_bundle_cbor(
    cbor_bytes: bytes,
    *,
    strict_deterministic: bool = True,
) -> Optional[Dict[str, Any]]:
    decoded = decode_cbor(cbor_bytes, strict_deterministic=strict_deterministic)
    if not isinstance(decoded, dict) or not decoded:
        return None

    if 1 in decoded or 2 in decoded:
        if not all(
            isinstance(k, int) and not isinstance(k, bool) and k in (1, 2, 3, 4)
            for k in decoded
        ):
            return None
        ots_proof = decoded.get(1)
        tbs_hash = decoded.get(2)
        if not isinstance(ots_proof, bytes) or not isinstance(tbs_hash, bytes) or len(tbs_hash) != 32:
            return None
        out: Dict[str, Any] = {
            "ots_proof": ots_proof,
            "claimed_hash": tbs_hash.hex(),
        }
        if 3 in decoded:
            if not isinstance(decoded[3], int) or isinstance(decoded[3], bool) or decoded[3] < 0:
                return None
            out["bitcoin_block_height"] = decoded[3]
        if 4 in decoded:
            if not isinstance(decoded[4], str):
                return None
            out["origin_id"] = decoded[4]
        return out

    allowed_str_keys = {"ots_proof", "claimed_hash", "origin_id", "bitcoin_block_height"}
    if not all(isinstance(k, str) and k in allowed_str_keys for k in decoded):
        return None
    ots_proof = decoded.get("ots_proof")
    claimed_hash = decoded.get("claimed_hash")
    if not isinstance(ots_proof, bytes) or not isinstance(claimed_hash, str):
        return None
    out = {
        "ots_proof": ots_proof,
        "claimed_hash": claimed_hash,
    }
    if "origin_id" in decoded:
        if not isinstance(decoded["origin_id"], str):
            return None
        out["origin_id"] = decoded["origin_id"]
    if "bitcoin_block_height" in decoded:
        bh = decoded["bitcoin_block_height"]
        if not isinstance(bh, int) or isinstance(bh, bool) or bh < 0:
            return None
        out["bitcoin_block_height"] = bh
    return out
