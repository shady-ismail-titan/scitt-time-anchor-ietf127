"""Bitcoin 80-byte block header parser, exact `SetCompact` 256-bit PoW & `GetBlockProof`
chainwork calculator, BIP-113 Median-Time-Past enforcement, and Forward-MTP calculator.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Mapping, Optional

from .ots_parser import VerifierMode

BITCOIN_MAINNET_GENESIS_HEX = (
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
)
# Mainnet CSV / BIP-113 activation block height
BITCOIN_MAINNET_BIP113_HEIGHT = 419_328
UINT256_MAX = (1 << 256) - 1


class HeaderSource(str, Enum):
    VALIDATED_NODE = "validated_node"
    CHECKPOINT_HEADER_SET = "checkpoint_header_set"
    PUBLIC_EXPLORER = "public_explorer"
    ANCHORING_SERVICE = "anchoring_service"


def double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def parse_u256_hex_64(hex_str: str) -> Optional[int]:
    """Requires an exact 64-hex-character (256-bit) string (with optional `0x` prefix)."""
    trimmed = hex_str.strip()
    if trimmed.startswith("0x"):
        trimmed = trimmed[2:]
    if len(trimmed) != 64:
        return None
    try:
        raw = bytes.fromhex(trimmed)
    except ValueError:
        return None
    if len(raw) != 32:
        return None
    return int.from_bytes(raw, "big")


def set_compact_exact(nbits: int) -> Optional[int]:
    """Exact port of Bitcoin Core `arith_uint256::SetCompact(uint32_t nCompact)`."""
    if nbits < 0 or nbits > 0xFFFFFFFF:
        return None
    n_size = (nbits >> 24) & 0xFF
    n_word = nbits & 0x007FFFFF
    if n_size <= 3:
        n_word >>= 8 * (3 - n_size)
        target = n_word
    else:
        target = n_word << (8 * (n_size - 3))

    f_negative = (n_word != 0) and ((nbits & 0x00800000) != 0)
    f_overflow = (n_word != 0) and (
        (n_size > 34)
        or (n_word > 0xFF and n_size > 33)
        or (n_word > 0xFFFF and n_size > 32)
    )
    if target == 0 or f_negative or f_overflow or target > UINT256_MAX:
        return None
    return target


def block_work_from_target(target: int) -> int:
    """Exact port of Bitcoin Core `GetBlockProof`: `(~target / (target + 1)) + 1`."""
    if target <= 0 or target > UINT256_MAX:
        return 0
    not_target = UINT256_MAX ^ target
    if target == UINT256_MAX:
        return 1
    return (not_target // (target + 1)) + 1


@dataclass(frozen=True)
class BitcoinHeader:
    raw_bytes: bytes
    version: int
    prev_block_hash_internal: bytes
    merkle_root_internal: bytes
    ntime: int
    nbits: int
    nonce: int
    block_hash_internal: bytes

    @classmethod
    def parse(cls, raw: bytes) -> Optional["BitcoinHeader"]:
        if len(raw) != 80:
            return None
        version, prev_hash, merkle_root, ntime, nbits, nonce = struct.unpack(
            "<I32s32sIII", raw
        )
        bhash = double_sha256(raw)
        return cls(
            raw_bytes=raw,
            version=version,
            prev_block_hash_internal=prev_hash,
            merkle_root_internal=merkle_root,
            ntime=ntime,
            nbits=nbits,
            nonce=nonce,
            block_hash_internal=bhash,
        )

    @property
    def block_hash_display(self) -> str:
        return self.block_hash_internal[::-1].hex()

    @property
    def merkle_root_display(self) -> str:
        return self.merkle_root_internal[::-1].hex()

    def target(self) -> Optional[int]:
        return set_compact_exact(self.nbits)

    def check_pow(self) -> bool:
        tgt = self.target()
        if tgt is None:
            return False
        hash_int = int.from_bytes(self.block_hash_internal, "little")
        return hash_int <= tgt

    def work(self) -> int:
        tgt = self.target()
        if tgt is None:
            return 0
        return block_work_from_target(tgt)


class CandidateHeaderStore:
    """Models candidate block header acquisition (Step 7a). Rejects `!= 80`-byte slices."""

    def __init__(
        self,
        headers_by_height: Mapping[int, bytes],
        *,
        source: HeaderSource = HeaderSource.VALIDATED_NODE,
    ) -> None:
        self._headers: Dict[int, bytes] = {}
        for h, raw in headers_by_height.items():
            if len(raw) != 80:
                raise ValueError(f"Header at height {h} must be exactly 80 bytes")
            self._headers[int(h)] = raw
        self.source = source

    def fetch_block_header_by_height(self, height: int) -> Optional[bytes]:
        if self.source == HeaderSource.ANCHORING_SERVICE:
            return None
        return self._headers.get(height)


class ValidatedHeaderChain:
    """Models the verifier's established, PoW-validated Bitcoin header chain (Steps 7b & 9)."""

    def __init__(
        self,
        headers_by_height: Mapping[int, bytes],
        *,
        ledger_id: str = BITCOIN_MAINNET_GENESIS_HEX,
        verify_pow_and_links: bool = True,
        allow_sparse_checkpoints: bool = False,
        enforce_retarget_4x_bound: bool = False,
        min_chainwork: int = 0,
    ) -> None:
        self.ledger_id = ledger_id
        self._validated: Dict[int, BitcoinHeader] = {}
        self._slice_tip: Dict[int, int] = {}
        self.total_chainwork: int = 0

        if not headers_by_height:
            if min_chainwork > 0:
                raise ValueError("Empty chain below min_chainwork")
            self.tip_height: Optional[int] = None
            return

        sorted_heights = sorted(headers_by_height.keys())
        slices: List[List[int]] = []
        cur_slice: List[int] = []

        for h in sorted_heights:
            if cur_slice and h != cur_slice[-1] + 1:
                if not allow_sparse_checkpoints:
                    raise ValueError(
                        f"Non-contiguous header heights {cur_slice[-1]} -> {h}"
                    )
                slices.append(cur_slice)
                cur_slice = []
            raw = headers_by_height[h]
            parsed = BitcoinHeader.parse(raw)
            if parsed is None:
                raise ValueError(f"Malformed 80-byte header at height {h}")
            if verify_pow_and_links:
                if not parsed.check_pow():
                    raise ValueError(f"Invalid PoW at height {h}")
                if cur_slice:
                    prev_hdr = self._validated[cur_slice[-1]]
                    if parsed.prev_block_hash_internal != prev_hdr.block_hash_internal:
                        raise ValueError(f"Broken prev_block_hash link at height {h}")
                    if enforce_retarget_4x_bound:
                        prev_t = prev_hdr.target()
                        cur_t = parsed.target()
                        if prev_t is None or cur_t is None:
                            raise ValueError("Invalid target during retarget check")
                        if (h % 2016) != 0 and cur_t != prev_t:
                            raise ValueError(f"Mid-epoch difficulty mutation at {h}")
                        if cur_t > min(UINT256_MAX, prev_t * 4):
                            raise ValueError(f"Difficulty drop exceeds 4x bound at {h}")
                bip113_active = (
                    ledger_id != BITCOIN_MAINNET_GENESIS_HEX
                    or h >= BITCOIN_MAINNET_BIP113_HEIGHT
                )
                if bip113_active and len(cur_slice) >= 11 and h >= 11:
                    prev_times = sorted(
                        self._validated[h - 11 + off].ntime for off in range(11)
                    )
                    if parsed.ntime <= prev_times[5]:
                        raise ValueError(f"BIP-113 nTime violation at height {h}")

            self._validated[h] = parsed
            self.total_chainwork = min(UINT256_MAX, self.total_chainwork + parsed.work())
            cur_slice.append(h)

        if cur_slice:
            slices.append(cur_slice)

        for sl in slices:
            sl_tip = sl[-1]
            for h in sl:
                self._slice_tip[h] = sl_tip

        if self.total_chainwork < min_chainwork:
            raise ValueError(
                f"Accumulated chainwork {self.total_chainwork:#x} < min_chainwork {min_chainwork:#x}"
            )

        self.tip_height = sorted_heights[-1]

    @classmethod
    def select_best_fork(
        cls,
        candidates: List[Dict],
        mode: VerifierMode,
    ) -> Optional["ValidatedHeaderChain"]:
        strict = mode == VerifierMode.STRICT
        valid_chains: List[ValidatedHeaderChain] = []
        for cfg in candidates:
            try:
                h_map = {int(k): bytes.fromhex(v) for k, v in cfg["headers_hex"].items()}
                min_cw = 0
                if strict:
                    cw_str = cfg.get("min_chainwork_hex")
                    if cw_str not in (None, "0", "0x0"):
                        parsed_cw = parse_u256_hex_64(str(cw_str))
                        if parsed_cw is None:
                            continue
                        min_cw = parsed_cw
                vc = cls(
                    h_map,
                    ledger_id=cfg.get("ledger_id", BITCOIN_MAINNET_GENESIS_HEX),
                    verify_pow_and_links=cfg.get("verify_pow_and_links", True),
                    allow_sparse_checkpoints=cfg.get("allow_sparse_checkpoints", False),
                    enforce_retarget_4x_bound=(
                        cfg.get("enforce_retarget_4x_bound", False) and strict
                    ),
                    min_chainwork=min_cw,
                )
                valid_chains.append(vc)
            except (ValueError, KeyError):
                continue

        if not valid_chains:
            return None
        if mode == VerifierMode.DRAFT08:
            return valid_chains[0]
        valid_chains.sort(key=lambda c: c.total_chainwork, reverse=True)
        return valid_chains[0]

    def raw_header_at(self, height: int) -> Optional[bytes]:
        hdr = self._validated.get(height)
        return hdr.raw_bytes if hdr is not None else None

    def validate_header_on_chain(
        self,
        height: int,
        candidate_raw: Optional[bytes],
        *,
        expected_ledger_id: Optional[str] = None,
    ) -> Optional[BitcoinHeader]:
        if candidate_raw is None:
            return None
        if expected_ledger_id is not None and self.ledger_id != expected_ledger_id:
            return None
        established = self._validated.get(height)
        if established is None:
            return None
        if established.raw_bytes != candidate_raw:
            return None
        return established

    def confirmations_on(self, height: int) -> Optional[int]:
        """Standard Bitcoin Core confirmation count (`tip - H + 1`, counting block `H` per draft-08 §4.1)."""
        sl_tip = self._slice_tip.get(height)
        if sl_tip is None or sl_tip < height:
            return None
        return sl_tip - height + 1

    def _window_median_11(self, start_h: int) -> Optional[int]:
        if start_h < 0:
            return None
        times: List[int] = []
        for h in range(start_h, start_h + 11):
            hdr = self._validated.get(h)
            if hdr is None:
                return None
            times.append(hdr.ntime)
        times.sort()
        return times[5]

    def median_time_past(self, height: int) -> Optional[int]:
        return self._window_median_11(height - 11)

    def forward_mtp_5(self, height: int) -> Optional[int]:
        """Zero-extra-wait Forward-MTP at exact 6 Bitcoin confirmations (`tip = H + 5`):
        `median(nTime[H-5 .. H+5])`, equal to `MTP(H+6)` and monotonic non-decreasing (`>=`) under BIP-113.
        """
        return self._window_median_11(height - 5)

    def forward_mtp_6(self, height: int) -> Optional[int]:
        """Forward-MTP at 7 Bitcoin confirmations (`tip = H + 6`): `median(nTime[H-4 .. H+6])`."""
        return self._window_median_11(height - 4)

    def forward_mtp_11(self, height: int) -> Optional[int]:
        """Full disjoint forward 11-block window `[H+1 .. H+11]`."""
        return self._window_median_11(height + 1)
