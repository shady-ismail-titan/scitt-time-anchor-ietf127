//! Clean-room OpenTimestamps (.ots) parser, replay, and Merkle builders in safe Rust.
//! Uses an explicit O(1)-call-stack iterative state machine (`Vec<WorkFrame>` + single
//! `ops_stack` push/truncate) preventing wasm32 1 MB shadow-stack overflow and O(D^2) cloning.

use crate::sha256::sha256;

pub const OTS_MAGIC: &[u8; 31] = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";
pub const OTS_VERSION: u64 = 1;

pub const OP_LEGACY_01: u8 = 0x01;
pub const OP_SHA1: u8 = 0x02;
pub const OP_RIPEMD160: u8 = 0x03;
pub const OP_SHA256: u8 = 0x08;
pub const OP_KECCAK256: u8 = 0x67;
pub const OP_APPEND: u8 = 0xf0;
pub const OP_PREPEND: u8 = 0xf1;
pub const OP_REVERSE: u8 = 0xf2;
pub const OP_HEXLIFY: u8 = 0xf3;

pub const TAG_ATTESTATION: u8 = 0x00;
pub const TAG_BRANCH: u8 = 0xff;

pub const BITCOIN_ATTESTATION_TAG: [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];
pub const PENDING_ATTESTATION_TAG: [u8; 8] = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];

pub const DRAFT08_MAX_PROOF_BYTES: usize = 1_048_576;
pub const DRAFT08_MAX_OPERAND_BYTES: usize = 4_096;
pub const DRAFT08_MAX_BRANCHES: usize = 256;
pub const DRAFT08_MAX_OPS_PER_BRANCH: usize = 4_096;
pub const DRAFT08_MAX_DEPTH: usize = 4_608;

pub const STRICT_MAX_PROOF_BYTES: usize = 65_536;
pub const STRICT_MAX_OPERAND_BYTES: usize = 512;
pub const HARDENED_MAX_RUNNING_BYTES: usize = 4_096;
pub const STRICT_MAX_BRANCHES: usize = 64;
pub const STRICT_MAX_OPS_PER_BRANCH: usize = 128;
pub const STRICT_MAX_DEPTH: usize = 256;

/// Matches `python-opentimestamps v0.4.5` `TimeAttestation.MAX_PAYLOAD_SIZE = 8192`.
pub const MAX_ATTESTATION_PAYLOAD_BYTES: usize = 8_192;
/// Matches `python-opentimestamps v0.4.5` `PendingAttestation.MAX_URI_LENGTH = 1000`.
pub const DEFAULT_MAX_PENDING_URI_BYTES: usize = 1_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifierMode {
    Draft08,
    Strict,
}

impl VerifierMode {
    pub fn from_str_name(s: &str) -> Option<Self> {
        match s {
            "draft08" => Some(Self::Draft08),
            "strict" => Some(Self::Strict),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Draft08 => "draft08",
            Self::Strict => "strict",
        }
    }
}

/// Matches `PendingAttestation.ALLOWED_URI_CHARS` in `python-opentimestamps v0.4.5` (`notary.py:165`).
pub fn is_allowed_pending_uri_byte(b: u8) -> bool {
    matches!(
        b,
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'/' | b':'
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OtsOp {
    Append(Vec<u8>),
    Prepend(Vec<u8>),
    Sha256,
    UnsupportedUnary(u8),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Attestation {
    Bitcoin(u64),
    Pending(String),
    Unknown([u8; 8]),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OtsBranch {
    pub ops: Vec<OtsOp>,
    pub attestation: Attestation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OtsProof {
    pub version: u64,
    pub file_hash_op: u8,
    pub msg: Vec<u8>,
    pub branches: Vec<OtsBranch>,
}

fn file_hash_digest_len(op_byte: u8, strict: bool) -> Option<usize> {
    if strict {
        return if op_byte == OP_SHA256 { Some(32) } else { None };
    }
    match op_byte {
        OP_LEGACY_01 | OP_SHA1 | OP_RIPEMD160 => Some(20),
        OP_SHA256 | OP_KECCAK256 => Some(32),
        _ => None,
    }
}

pub fn decode_varuint_py_unbounded(buf: &[u8], mut pos: usize) -> Option<(u64, usize)> {
    let mut val: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        if pos >= buf.len() || shift > 63 {
            return None;
        }
        let b = buf[pos];
        pos += 1;
        if shift == 63 && (b & 0xfe) != 0 {
            return None;
        }
        val |= ((b & 0x7f) as u64) << shift;
        if (b & 0x80) == 0 {
            return Some((val, pos));
        }
        shift += 7;
    }
}

pub fn decode_varuint_js_toint32(buf: &[u8], mut pos: usize) -> Option<(i32, usize)> {
    let mut val: i32 = 0;
    let mut shift: u32 = 0;
    loop {
        if pos >= buf.len() {
            return None;
        }
        let b = buf[pos];
        pos += 1;
        let masked_shift = shift & 31;
        let term = ((b & 0x7f) as i32).wrapping_shl(masked_shift);
        val |= term;
        if (b & 0x80) == 0 {
            return Some((val, pos));
        }
        shift = shift.wrapping_add(7);
    }
}

pub fn read_varuint(buf: &[u8], mut pos: usize, canonical_u32: bool) -> Option<(u64, usize)> {
    if !canonical_u32 {
        return decode_varuint_py_unbounded(buf, pos);
    }
    let mut val: u64 = 0;
    for idx in 0..5usize {
        if pos >= buf.len() {
            return None;
        }
        let b = buf[pos];
        pos += 1;
        if idx > 0 && b == 0x00 {
            return None;
        }
        if idx == 4 && (b & 0xf0) != 0 {
            return None;
        }
        val |= ((b & 0x7f) as u64) << (7 * idx);
        if (b & 0x80) == 0 {
            return Some((val, pos));
        }
    }
    None
}

pub fn read_varbytes<'a>(
    buf: &'a [u8],
    pos: usize,
    min_len: usize,
    max_len: usize,
    canonical_u32: bool,
) -> Option<(&'a [u8], usize)> {
    let (ln_u64, next_pos) = read_varuint(buf, pos, canonical_u32)?;
    let ln = usize::try_from(ln_u64).ok()?;
    if ln < min_len || ln > max_len {
        return None;
    }
    let end = next_pos.checked_add(ln)?;
    if end > buf.len() {
        return None;
    }
    Some((&buf[next_pos..end], end))
}

enum WorkFrame {
    EnterTimestamp { ops_len: usize, depth: usize },
    AfterBranchStep { ops_len: usize, depth: usize },
    EnterStep { ops_len: usize, depth: usize },
}

pub fn ots_deserialize(ots_bytes: &[u8], mode: VerifierMode) -> Option<OtsProof> {
    let strict = mode == VerifierMode::Strict;
    let max_proof_bytes = if strict {
        STRICT_MAX_PROOF_BYTES
    } else {
        DRAFT08_MAX_PROOF_BYTES
    };
    if ots_bytes.len() < OTS_MAGIC.len() + 3 || ots_bytes.len() > max_proof_bytes {
        return None;
    }
    if &ots_bytes[..OTS_MAGIC.len()] != OTS_MAGIC {
        return None;
    }

    let (version, mut pos) = read_varuint(ots_bytes, OTS_MAGIC.len(), strict)?;
    if version != OTS_VERSION || pos >= ots_bytes.len() {
        return None;
    }

    let file_hash_op = ots_bytes[pos];
    pos += 1;
    let digest_len = file_hash_digest_len(file_hash_op, strict)?;
    if pos.checked_add(digest_len)? > ots_bytes.len() {
        return None;
    }
    let msg = ots_bytes[pos..pos + digest_len].to_vec();
    pos += digest_len;

    let max_operand_bytes = if strict {
        STRICT_MAX_OPERAND_BYTES
    } else {
        DRAFT08_MAX_OPERAND_BYTES
    };
    let max_branches = if strict {
        STRICT_MAX_BRANCHES
    } else {
        DRAFT08_MAX_BRANCHES
    };
    let max_ops_per_branch = if strict {
        STRICT_MAX_OPS_PER_BRANCH
    } else {
        DRAFT08_MAX_OPS_PER_BRANCH
    };
    let max_depth = if strict {
        STRICT_MAX_DEPTH
    } else {
        DRAFT08_MAX_DEPTH
    };

    let mut branches: Vec<OtsBranch> = Vec::new();
    let mut ops_stack: Vec<OtsOp> = Vec::new();
    let mut work: Vec<WorkFrame> = Vec::with_capacity(64);
    work.push(WorkFrame::EnterTimestamp {
        ops_len: 0,
        depth: 0,
    });

    while let Some(frame) = work.pop() {
        match frame {
            WorkFrame::EnterTimestamp { ops_len, depth }
            | WorkFrame::AfterBranchStep { ops_len, depth } => {
                if depth > max_depth || pos >= ots_bytes.len() {
                    return None;
                }
                ops_stack.truncate(ops_len);
                if ots_bytes[pos] == TAG_BRANCH {
                    pos += 1;
                    work.push(WorkFrame::AfterBranchStep { ops_len, depth });
                    work.push(WorkFrame::EnterStep {
                        ops_len,
                        depth: depth + 1,
                    });
                } else {
                    work.push(WorkFrame::EnterStep {
                        ops_len,
                        depth: depth + 1,
                    });
                }
            }
            WorkFrame::EnterStep { ops_len, depth } => {
                if depth > max_depth || pos >= ots_bytes.len() {
                    return None;
                }
                ops_stack.truncate(ops_len);
                let tag = ots_bytes[pos];
                pos += 1;

                match tag {
                    TAG_ATTESTATION => {
                        if branches.len() >= max_branches || pos.checked_add(8)? > ots_bytes.len() {
                            return None;
                        }
                        let mut att_tag = [0u8; 8];
                        att_tag.copy_from_slice(&ots_bytes[pos..pos + 8]);
                        pos += 8;
                        let (payload, end_pos) = read_varbytes(
                            ots_bytes,
                            pos,
                            0,
                            MAX_ATTESTATION_PAYLOAD_BYTES,
                            strict,
                        )?;
                        pos = end_pos;

                        let attestation = if att_tag == BITCOIN_ATTESTATION_TAG {
                            if payload.is_empty() {
                                return None;
                            }
                            let (height, p_end) = read_varuint(payload, 0, strict)?;
                            if p_end != payload.len() {
                                return None;
                            }
                            Attestation::Bitcoin(height)
                        } else if att_tag == PENDING_ATTESTATION_TAG {
                            let (uri_bytes, p_end) = read_varbytes(
                                payload,
                                0,
                                1,
                                DEFAULT_MAX_PENDING_URI_BYTES,
                                strict,
                            )?;
                            if p_end != payload.len() {
                                return None;
                            }
                            if !uri_bytes.iter().all(|&b| is_allowed_pending_uri_byte(b)) {
                                return None;
                            }
                            let uri = core::str::from_utf8(uri_bytes).ok()?.to_string();
                            Attestation::Pending(uri)
                        } else {
                            if strict {
                                return None;
                            }
                            Attestation::Unknown(att_tag)
                        };

                        branches.push(OtsBranch {
                            ops: ops_stack.clone(),
                            attestation,
                        });
                    }
                    OP_APPEND | OP_PREPEND => {
                        if ops_stack.len() >= max_ops_per_branch {
                            return None;
                        }
                        let (arg, next_pos) =
                            read_varbytes(ots_bytes, pos, 1, max_operand_bytes, strict)?;
                        pos = next_pos;
                        if tag == OP_APPEND {
                            ops_stack.push(OtsOp::Append(arg.to_vec()));
                        } else {
                            ops_stack.push(OtsOp::Prepend(arg.to_vec()));
                        }
                        let new_len = ops_stack.len();
                        work.push(WorkFrame::EnterTimestamp {
                            ops_len: new_len,
                            depth,
                        });
                    }
                    OP_SHA256 => {
                        if ops_stack.len() >= max_ops_per_branch {
                            return None;
                        }
                        ops_stack.push(OtsOp::Sha256);
                        let new_len = ops_stack.len();
                        work.push(WorkFrame::EnterTimestamp {
                            ops_len: new_len,
                            depth,
                        });
                    }
                    OP_LEGACY_01 | OP_SHA1 | OP_RIPEMD160 | OP_KECCAK256 | OP_REVERSE
                    | OP_HEXLIFY
                        if !strict =>
                    {
                        if ops_stack.len() >= max_ops_per_branch {
                            return None;
                        }
                        ops_stack.push(OtsOp::UnsupportedUnary(tag));
                        let new_len = ops_stack.len();
                        work.push(WorkFrame::EnterTimestamp {
                            ops_len: new_len,
                            depth,
                        });
                    }
                    _ => return None,
                }
            }
        }
    }

    if pos != ots_bytes.len() || branches.is_empty() {
        return None;
    }

    Some(OtsProof {
        version,
        file_hash_op,
        msg,
        branches,
    })
}

pub fn ots_replay(
    branch: &OtsBranch,
    initial_hash: &[u8],
    max_running_bytes: usize,
) -> Option<Vec<u8>> {
    if initial_hash.len() > max_running_bytes {
        return None;
    }
    let mut cur = initial_hash.to_vec();
    for op in &branch.ops {
        match op {
            OtsOp::Append(arg) => {
                if cur.len().checked_add(arg.len())? > max_running_bytes {
                    return None;
                }
                cur.extend_from_slice(arg);
            }
            OtsOp::Prepend(arg) => {
                let total = arg.len().checked_add(cur.len())?;
                if total > max_running_bytes {
                    return None;
                }
                let mut combined = Vec::with_capacity(total);
                combined.extend_from_slice(arg);
                combined.extend_from_slice(&cur);
                cur = combined;
            }
            OtsOp::Sha256 => {
                cur = sha256(&cur).to_vec();
            }
            OtsOp::UnsupportedUnary(_) => return None,
        }
    }
    if cur.len() != 32 {
        return None;
    }
    Some(cur)
}

/// Optional check for v2 producer-side RFC 6962 domain-separated batch trees (`0x00` leaf / `0x01` inner).
/// Disabled (`false`) by default in all v1 `.ots` verifiers to preserve 100% wild OpenTimestamps compatibility.
pub fn verify_rfc6962_batch_prefix(branch: &OtsBranch) -> bool {
    let ops = &branch.ops;
    if ops.len() < 3 {
        return false;
    }
    match (&ops[0], &ops[1], &ops[2]) {
        (OtsOp::Append(n), OtsOp::Prepend(p), OtsOp::Sha256)
            if n.len() == 16 && p.as_slice() == [0x00] => {}
        (OtsOp::Prepend(p), OtsOp::Append(n), OtsOp::Sha256)
            if p.as_slice() == [0x00] && n.len() == 16 => {}
        _ => return false,
    }
    let mut idx = 3usize;
    while idx < ops.len() {
        match &ops[idx] {
            OtsOp::Append(sib) | OtsOp::Prepend(sib) if sib.len() == 32 => {
                if idx + 2 < ops.len()
                    && ops[idx + 1] == OtsOp::Prepend(vec![0x01])
                    && ops[idx + 2] == OtsOp::Sha256
                {
                    idx += 3;
                    continue;
                }
                break;
            }
            OtsOp::Prepend(p) if p.as_slice() == [0x01] => {
                if idx + 2 >= ops.len() {
                    return false;
                }
                match (&ops[idx + 1], &ops[idx + 2]) {
                    (OtsOp::Append(sib), OtsOp::Sha256) if sib.len() == 32 => {
                        idx += 3;
                    }
                    _ => return false,
                }
            }
            OtsOp::Prepend(p) if p.len() == 33 && p[0] == 0x01 => {
                if idx + 1 >= ops.len() || ops[idx + 1] != OtsOp::Sha256 {
                    return false;
                }
                idx += 2;
            }
            _ => break,
        }
    }
    true
}

pub fn batch_merkle_root(leaves: &[[u8; 32]]) -> Option<[u8; 32]> {
    if leaves.is_empty() {
        return None;
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        let mut i = 0;
        while i + 1 < level.len() {
            let mut pair = [0u8; 64];
            pair[..32].copy_from_slice(&level[i]);
            pair[32..].copy_from_slice(&level[i + 1]);
            next.push(sha256(&pair));
            i += 2;
        }
        if level.len() % 2 == 1 {
            next.push(level[level.len() - 1]);
        }
        level = next;
    }
    Some(level[0])
}
