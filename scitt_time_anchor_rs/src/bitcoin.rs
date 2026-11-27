//! Bitcoin 80-byte block header parser, exact `SetCompact` 256-bit PoW & `GetBlockProof`
//! chainwork calculator, BIP-113 Median-Time-Past enforcement, and Forward-MTP calculator.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::sha256::{decode_hex, hex_lower, sha256};

pub const BITCOIN_MAINNET_GENESIS_HEX: &str =
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

/// Mainnet activation height of BIP-113 (CSV soft-fork: block 419,328).
pub const BITCOIN_MAINNET_BIP113_HEIGHT: u64 = 419_328;
pub const BITCOIN_MAINNET_POW_LIMIT_NBITS: u32 = 0x1d00_ffff;
pub const BITCOIN_MAINNET_POST_BIP113_MAX_NBITS: u32 = 0x181f_ffff;
pub const BITCOIN_RETARGET_INTERVAL: u64 = 2016;
pub const BITCOIN_TARGET_TIMESPAN: u32 = 14 * 24 * 60 * 60;

/// Verified Bitcoin Mainnet historical milestone checkpoints (Genesis, Halvings, CSV/BIP-113, SegWit, Taproot).
pub const BITCOIN_MAINNET_CHECKPOINTS: &[(u64, &str)] = &[
    (0, BITCOIN_MAINNET_GENESIS_HEX),
    (
        210_000,
        "000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e",
    ),
    (
        419_328,
        "000000000000000004a1b34462cb8aeebd5799177f7a29cf28f2d1961716b5b5",
    ),
    (
        481_824,
        "0000000000000000001c8018d9cb3b742ef25114f27563e3fc4a1902167f9893",
    ),
    (
        630_000,
        "000000000000000000024bead8df69990852c202db0e0097c1a12ea637d7e96d",
    ),
    (
        709_632,
        "0000000000000000000687bca986194dc2c1f949318629b44bb54ec0a94d8244",
    ),
    (
        840_000,
        "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5",
    ),
];

pub fn mainnet_checkpoint_hash(height: u64) -> Option<&'static str> {
    for &(h, expected) in BITCOIN_MAINNET_CHECKPOINTS {
        if h == height {
            return Some(expected);
        }
    }
    None
}

/// Exact unsigned 256-bit integer (little-endian 64-bit limbs) with zero external crates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct U256(pub [u64; 4]);

impl PartialOrd for U256 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for U256 {
    fn cmp(&self, other: &Self) -> Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&other.0[i]) {
                Ordering::Equal => continue,
                non_eq => return non_eq,
            }
        }
        Ordering::Equal
    }
}

impl U256 {
    pub const ZERO: Self = Self([0, 0, 0, 0]);
    pub const ONE: Self = Self([1, 0, 0, 0]);
    pub const MAX: Self = Self([u64::MAX, u64::MAX, u64::MAX, u64::MAX]);

    pub fn from_u64(v: u64) -> Self {
        Self([v, 0, 0, 0])
    }

    pub fn from_le_bytes(b: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let mut chunk = [0u8; 8];
            chunk.copy_from_slice(&b[i * 8..(i + 1) * 8]);
            limbs[i] = u64::from_le_bytes(chunk);
        }
        Self(limbs)
    }

    /// Requires an exact 64-hex-character (256-bit) string (with optional `0x` prefix).
    pub fn from_hex(hex_str: &str) -> Option<Self> {
        let trimmed = hex_str.trim().strip_prefix("0x").unwrap_or(hex_str.trim());
        if trimmed.len() != 64 {
            return None;
        }
        let be = decode_hex(trimmed)?;
        let mut le = [0u8; 32];
        for i in 0..32 {
            le[i] = be[31 - i];
        }
        Some(Self::from_le_bytes(&le))
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0, 0, 0, 0]
    }

    pub fn bit_not(&self) -> Self {
        Self([!self.0[0], !self.0[1], !self.0[2], !self.0[3]])
    }

    pub fn shl_bits(&self, shift: usize) -> Self {
        if shift >= 256 {
            return Self::ZERO;
        }
        if shift == 0 {
            return *self;
        }
        let word_shift = shift / 64;
        let bit_shift = shift % 64;
        let mut out = [0u64; 4];
        for i in word_shift..4 {
            out[i] = self.0[i - word_shift] << bit_shift;
            if bit_shift > 0 && i > word_shift {
                out[i] |= self.0[i - word_shift - 1] >> (64 - bit_shift);
            }
        }
        Self(out)
    }

    pub fn shr_bits(&self, shift: usize) -> Self {
        if shift >= 256 {
            return Self::ZERO;
        }
        if shift == 0 {
            return *self;
        }
        let word_shift = shift / 64;
        let bit_shift = shift % 64;
        let mut out = [0u64; 4];
        for i in 0..(4 - word_shift) {
            out[i] = self.0[i + word_shift] >> bit_shift;
            if bit_shift > 0 && (i + word_shift + 1) < 4 {
                out[i] |= self.0[i + word_shift + 1] << (64 - bit_shift);
            }
        }
        Self(out)
    }

    pub fn bit_length(&self) -> usize {
        for i in (0..4).rev() {
            if self.0[i] != 0 {
                return i * 64 + (64 - self.0[i].leading_zeros() as usize);
            }
        }
        0
    }

    pub fn mul_div_u32(&self, mul: u32, div: u32) -> Self {
        if div == 0 || self.is_zero() || mul == 0 {
            return Self::ZERO;
        }
        let mut prod = [0u64; 5];
        let mut carry: u128 = 0;
        for i in 0..4 {
            let p = (self.0[i] as u128) * (mul as u128) + carry;
            prod[i] = p as u64;
            carry = p >> 64;
        }
        prod[4] = carry as u64;

        let mut quot = [0u64; 5];
        let mut rem: u128 = 0;
        let d = div as u128;
        for i in (0..5).rev() {
            let cur = (rem << 64) | (prod[i] as u128);
            quot[i] = (cur / d) as u64;
            rem = cur % d;
        }
        if quot[4] != 0 {
            Self::MAX
        } else {
            Self([quot[0], quot[1], quot[2], quot[3]])
        }
    }

    pub fn checked_add(&self, rhs: Self) -> Option<Self> {
        let mut out = [0u64; 4];
        let mut carry = false;
        for i in 0..4 {
            let (s1, c1) = self.0[i].overflowing_add(rhs.0[i]);
            let (s2, c2) = s1.overflowing_add(u64::from(carry));
            out[i] = s2;
            carry = c1 || c2;
        }
        if carry {
            None
        } else {
            Some(Self(out))
        }
    }

    pub fn saturating_add(&self, rhs: Self) -> Self {
        self.checked_add(rhs).unwrap_or(Self::MAX)
    }

    pub fn wrapping_sub(&self, rhs: Self) -> Self {
        let mut out = [0u64; 4];
        let mut borrow = false;
        for i in 0..4 {
            let (d1, b1) = self.0[i].overflowing_sub(rhs.0[i]);
            let (d2, b2) = d1.overflowing_sub(u64::from(borrow));
            out[i] = d2;
            borrow = b1 || b2;
        }
        Self(out)
    }

    pub fn mul_u32_overflow(&self, factor: u32) -> (Self, bool) {
        let mut out = [0u64; 4];
        let mut carry: u128 = 0;
        for i in 0..4 {
            let prod = (self.0[i] as u128) * (factor as u128) + carry;
            out[i] = prod as u64;
            carry = prod >> 64;
        }
        (Self(out), carry != 0)
    }

    pub fn div_exact(&self, den: Self) -> Option<Self> {
        if den.is_zero() {
            return None;
        }
        let mut quot = Self::ZERO;
        let mut rem = Self::ZERO;
        for bit in (0..256usize).rev() {
            let carry_out = (rem.0[3] >> 63) != 0;
            rem = rem.shl_bits(1);
            let in_bit = (self.0[bit / 64] >> (bit % 64)) & 1;
            rem.0[0] |= in_bit;
            if carry_out || rem >= den {
                rem = rem.wrapping_sub(den);
                quot.0[bit / 64] |= 1u64 << (bit % 64);
            }
        }
        Some(quot)
    }
}

/// Exact port of Bitcoin Core `arith_uint256::SetCompact(uint32_t nCompact)`.
pub fn set_compact_exact(nbits: u32) -> Option<U256> {
    let n_size = ((nbits >> 24) & 0xff) as usize;
    let n_word_raw = nbits & 0x007f_ffff;
    let (n_word, target) = if n_size <= 3 {
        let shifted = n_word_raw >> (8 * (3 - n_size));
        (shifted, U256::from_u64(shifted as u64))
    } else {
        let base = U256::from_u64(n_word_raw as u64);
        (n_word_raw, base.shl_bits(8 * (n_size - 3)))
    };

    let f_negative = (n_word != 0) && ((nbits & 0x0080_0000) != 0);
    let f_overflow = (n_word != 0)
        && ((n_size > 34)
            || (n_word > 0xff && n_size > 33)
            || (n_word > 0xffff && n_size > 32));
    if target.is_zero() || f_negative || f_overflow {
        return None;
    }
    Some(target)
}

/// Exact port of Bitcoin Core `arith_uint256::GetCompact(false)`.
pub fn target_to_compact_exact(target: U256) -> u32 {
    if target.is_zero() {
        return 0;
    }
    let mut n_size = target.bit_length().div_ceil(8);
    let shifted = if n_size <= 3 {
        target.shl_bits(8 * (3 - n_size))
    } else {
        target.shr_bits(8 * (n_size - 3))
    };
    let mut n_compact = (shifted.0[0] & 0x00ff_ffff) as u32;
    if (n_compact & 0x0080_0000) != 0 {
        n_compact >>= 8;
        n_size += 1;
    }
    (n_compact & 0x007f_ffff) | (((n_size & 0xff) as u32) << 24)
}

pub fn mainnet_pow_limit() -> U256 {
    set_compact_exact(BITCOIN_MAINNET_POW_LIMIT_NBITS).unwrap_or(U256::MAX)
}

pub fn mainnet_post_bip113_max_target() -> U256 {
    set_compact_exact(BITCOIN_MAINNET_POST_BIP113_MAX_NBITS).unwrap_or_else(mainnet_pow_limit)
}

pub fn calculate_next_work_required(
    last_target: U256,
    first_block_time: u32,
    last_block_time: u32,
    pow_limit: U256,
) -> u32 {
    let mut actual_timespan = last_block_time.saturating_sub(first_block_time);
    let min_ts = BITCOIN_TARGET_TIMESPAN / 4;
    let max_ts = BITCOIN_TARGET_TIMESPAN * 4;
    if actual_timespan < min_ts {
        actual_timespan = min_ts;
    } else if actual_timespan > max_ts {
        actual_timespan = max_ts;
    }
    let mut new_target = last_target.mul_div_u32(actual_timespan, BITCOIN_TARGET_TIMESPAN);
    if new_target > pow_limit {
        new_target = pow_limit;
    }
    if new_target.is_zero() {
        new_target = U256::ONE;
    }
    target_to_compact_exact(new_target)
}

/// Exact Bitcoin Core `GetBlockProof`: `(~target / (target + 1)) + 1`.
pub fn block_work_from_target(target: U256) -> U256 {
    if target.is_zero() {
        return U256::ZERO;
    }
    let not_target = target.bit_not();
    match target.checked_add(U256::ONE) {
        Some(den) => not_target
            .div_exact(den)
            .unwrap_or(U256::ZERO)
            .saturating_add(U256::ONE),
        None => U256::ONE,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderSource {
    ValidatedNode,
    CheckpointHeaderSet,
    PublicExplorer,
    AnchoringService,
}

impl HeaderSource {
    pub fn from_str_name(s: &str) -> Option<Self> {
        match s {
            "validated_node" => Some(Self::ValidatedNode),
            "checkpoint_header_set" => Some(Self::CheckpointHeaderSet),
            "public_explorer" => Some(Self::PublicExplorer),
            "anchoring_service" => Some(Self::AnchoringService),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitcoinHeader {
    pub raw_bytes: [u8; 80],
    pub version: u32,
    pub prev_block_hash_internal: [u8; 32],
    pub merkle_root_internal: [u8; 32],
    pub ntime: u32,
    pub nbits: u32,
    pub nonce: u32,
    pub block_hash_internal: [u8; 32],
}

impl BitcoinHeader {
    pub fn parse(raw: &[u8]) -> Option<Self> {
        if raw.len() != 80 {
            return None;
        }
        let mut raw_bytes = [0u8; 80];
        raw_bytes.copy_from_slice(raw);

        let version = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let mut prev_block_hash_internal = [0u8; 32];
        prev_block_hash_internal.copy_from_slice(&raw[4..36]);
        let mut merkle_root_internal = [0u8; 32];
        merkle_root_internal.copy_from_slice(&raw[36..68]);
        let ntime = u32::from_le_bytes([raw[68], raw[69], raw[70], raw[71]]);
        let nbits = u32::from_le_bytes([raw[72], raw[73], raw[74], raw[75]]);
        let nonce = u32::from_le_bytes([raw[76], raw[77], raw[78], raw[79]]);

        let first = sha256(&raw_bytes);
        let block_hash_internal = sha256(&first);

        Some(Self {
            raw_bytes,
            version,
            prev_block_hash_internal,
            merkle_root_internal,
            ntime,
            nbits,
            nonce,
            block_hash_internal,
        })
    }

    pub fn block_hash_display(&self) -> String {
        let mut rev = self.block_hash_internal;
        rev.reverse();
        hex_lower(&rev)
    }

    pub fn target(&self) -> Option<U256> {
        set_compact_exact(self.nbits)
    }

    pub fn check_pow(&self) -> bool {
        let tgt = match self.target() {
            Some(t) => t,
            None => return false,
        };
        let hash_u256 = U256::from_le_bytes(&self.block_hash_internal);
        hash_u256 <= tgt
    }

    pub fn work(&self) -> U256 {
        match self.target() {
            Some(t) => block_work_from_target(t),
            None => U256::ZERO,
        }
    }
}

pub struct CandidateHeaderStore {
    headers: BTreeMap<u64, [u8; 80]>,
    source: HeaderSource,
}

impl CandidateHeaderStore {
    /// Rejects any candidate header slice whose byte length is not exactly 80 bytes.
    pub fn new(raw_map: BTreeMap<u64, Vec<u8>>, source: HeaderSource) -> Option<Self> {
        let mut headers = BTreeMap::new();
        for (h, v) in raw_map {
            if v.len() != 80 {
                return None;
            }
            let mut arr = [0u8; 80];
            arr.copy_from_slice(&v);
            headers.insert(h, arr);
        }
        Some(Self { headers, source })
    }

    pub fn fetch_block_header_by_height(&self, height: u64) -> Option<[u8; 80]> {
        if self.source == HeaderSource::AnchoringService {
            return None;
        }
        self.headers.get(&height).copied()
    }
}

#[derive(Clone, Debug)]
pub struct ChainBuildOptions {
    pub ledger_id: String,
    pub verify_pow_and_links: bool,
    pub allow_sparse_checkpoints: bool,
    pub enforce_retarget_4x_bound: bool,
    pub enforce_consensus_targets: bool,
    pub min_chainwork: U256,
}

pub struct ValidatedHeaderChain {
    pub ledger_id: String,
    validated: BTreeMap<u64, BitcoinHeader>,
    slice_tip: BTreeMap<u64, u64>,
    pub total_chainwork: U256,
    pub tip_height: Option<u64>,
}

impl ValidatedHeaderChain {
    pub fn build_with_options(
        raw_map: BTreeMap<u64, Vec<u8>>,
        opts: ChainBuildOptions,
    ) -> Option<Self> {
        let mut validated: BTreeMap<u64, BitcoinHeader> = BTreeMap::new();
        let mut slice_tip = BTreeMap::new();
        let mut total_chainwork = U256::ZERO;

        if raw_map.is_empty() {
            if opts.min_chainwork > U256::ZERO {
                return None;
            }
            return Some(Self {
                ledger_id: opts.ledger_id,
                validated,
                slice_tip,
                total_chainwork,
                tip_height: None,
            });
        }

        let mut slices: Vec<Vec<u64>> = Vec::new();
        let mut cur_slice: Vec<u64> = Vec::new();
        let is_mainnet = opts.ledger_id == BITCOIN_MAINNET_GENESIS_HEX;
        let pow_limit = mainnet_pow_limit();
        let post_bip113_max_target = mainnet_post_bip113_max_target();

        for (h, raw) in raw_map {
            if let Some(&prev_h) = cur_slice.last() {
                if h != prev_h.checked_add(1)? {
                    if !opts.allow_sparse_checkpoints {
                        return None;
                    }
                    slices.push(cur_slice);
                    cur_slice = Vec::new();
                }
            }
            let parsed = BitcoinHeader::parse(&raw)?;
            if opts.verify_pow_and_links {
                if !parsed.check_pow() {
                    return None;
                }
                if is_mainnet {
                    if let Some(expected_hash) = mainnet_checkpoint_hash(h) {
                        if parsed.block_hash_display() != expected_hash {
                            return None;
                        }
                    }
                }
                let cur_t = parsed.target()?;
                if opts.enforce_consensus_targets && is_mainnet {
                    if cur_t > pow_limit {
                        return None;
                    }
                    if h >= BITCOIN_MAINNET_BIP113_HEIGHT && cur_t > post_bip113_max_target {
                        return None;
                    }
                }
                if let Some(&prev_h) = cur_slice.last() {
                    let prev_hdr = validated.get(&prev_h)?;
                    if parsed.prev_block_hash_internal != prev_hdr.block_hash_internal {
                        return None;
                    }
                    if opts.enforce_retarget_4x_bound {
                        let prev_t = prev_hdr.target()?;
                        if (h % BITCOIN_RETARGET_INTERVAL) != 0 {
                            if cur_t != prev_t {
                                return None;
                            }
                        } else {
                            let (four_prev, ovf) = prev_t.mul_u32_overflow(4);
                            let upper_t = if opts.enforce_consensus_targets && is_mainnet {
                                if ovf || four_prev > pow_limit {
                                    pow_limit
                                } else {
                                    four_prev
                                }
                            } else if ovf {
                                U256::MAX
                            } else {
                                four_prev
                            };
                            if cur_t > upper_t {
                                return None;
                            }
                            let quarter_prev = prev_t.shr_bits(2);
                            if prev_t >= U256::from_u64(4) {
                                let slack = cur_t.shr_bits(15);
                                let lower_adj = cur_t.saturating_add(slack);
                                if lower_adj < quarter_prev {
                                    return None;
                                }
                            }
                            if cur_slice.len() >= BITCOIN_RETARGET_INTERVAL as usize {
                                if let Some(epoch_start_h) = h.checked_sub(BITCOIN_RETARGET_INTERVAL) {
                                    if let Some(first_hdr) = validated.get(&epoch_start_h) {
                                        let expected_nbits = calculate_next_work_required(
                                            prev_t,
                                            first_hdr.ntime,
                                            prev_hdr.ntime,
                                            if is_mainnet { pow_limit } else { U256::MAX },
                                        );
                                        if parsed.nbits != expected_nbits {
                                            return None;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                // Enforce BIP-113 (nTime > median of preceding 11 blocks) whenever the 11 preceding
                // blocks are present and height >= CSV activation (419,328 on Bitcoin Mainnet).
                let bip113_active = opts.ledger_id != BITCOIN_MAINNET_GENESIS_HEX
                    || h >= BITCOIN_MAINNET_BIP113_HEIGHT;
                if bip113_active && cur_slice.len() >= 11 {
                    if let Some(start) = h.checked_sub(11) {
                        let mut prev_times = Vec::with_capacity(11);
                        for off in 0..11u64 {
                            let ph = start + off;
                            if let Some(phdr) = validated.get(&ph) {
                                prev_times.push(phdr.ntime);
                            }
                        }
                        if prev_times.len() == 11 {
                            prev_times.sort_unstable();
                            if parsed.ntime <= prev_times[5] {
                                return None;
                            }
                        }
                    }
                }
            }
            total_chainwork = total_chainwork.saturating_add(parsed.work());
            validated.insert(h, parsed);
            cur_slice.push(h);
        }

        if !cur_slice.is_empty() {
            slices.push(cur_slice);
        }

        for sl in slices {
            let sl_tip = *sl.last()?;
            for h in sl {
                slice_tip.insert(h, sl_tip);
            }
        }

        if total_chainwork < opts.min_chainwork {
            return None;
        }

        let tip_height = validated.keys().next_back().copied();
        Some(Self {
            ledger_id: opts.ledger_id,
            validated,
            slice_tip,
            total_chainwork,
            tip_height,
        })
    }

    pub fn raw_header_at(&self, height: u64) -> Option<[u8; 80]> {
        self.validated.get(&height).map(|h| h.raw_bytes)
    }

    pub fn validate_header_on_chain(
        &self,
        height: u64,
        candidate: Option<[u8; 80]>,
        expected_ledger_id: Option<&str>,
    ) -> Option<&BitcoinHeader> {
        let cand = candidate?;
        if let Some(exp_id) = expected_ledger_id {
            if self.ledger_id != exp_id {
                return None;
            }
        }
        let established = self.validated.get(&height)?;
        if established.raw_bytes != cand {
            return None;
        }
        Some(established)
    }

    /// Standard Bitcoin Core confirmation count (`tip - H + 1`, counting block `H` itself per draft-08 §4.1).
    pub fn confirmations_on(&self, height: u64) -> Option<u64> {
        let sl_tip = *self.slice_tip.get(&height)?;
        if sl_tip < height {
            return None;
        }
        Some(sl_tip - height + 1)
    }

    fn window_median_11(&self, start_h: u64) -> Option<u32> {
        let mut times = Vec::with_capacity(11);
        for offset in 0..11u64 {
            let h = start_h.checked_add(offset)?;
            let hdr = self.validated.get(&h)?;
            times.push(hdr.ntime);
        }
        times.sort_unstable();
        Some(times[5])
    }

    /// BIP-113 Median Time Past of block `H`: median of the 11 preceding blocks `[H-11 .. H-1]`.
    pub fn median_time_past(&self, height: u64) -> Option<u32> {
        let start = height.checked_sub(11)?;
        self.window_median_11(start)
    }

    /// Zero-extra-wait Forward-MTP at exact 6 Bitcoin confirmations (`tip = H + 5`):
    /// `median(nTime[H-5 .. H+5])`, equal to `MTP(H+6)` and monotonic non-decreasing (`>=`) under BIP-113.
    pub fn forward_mtp_5(&self, height: u64) -> Option<u32> {
        let start = height.checked_sub(5)?;
        self.window_median_11(start)
    }

    /// Forward-MTP at 7 Bitcoin confirmations (`tip = H + 6`): `median(nTime[H-4 .. H+6])`.
    pub fn forward_mtp_6(&self, height: u64) -> Option<u32> {
        let start = height.checked_sub(4)?;
        self.window_median_11(start)
    }

    /// Full disjoint forward 11-block window `[H+1 .. H+11]`.
    pub fn forward_mtp_11(&self, height: u64) -> Option<u32> {
        let start = height.checked_add(1)?;
        self.window_median_11(start)
    }
}
