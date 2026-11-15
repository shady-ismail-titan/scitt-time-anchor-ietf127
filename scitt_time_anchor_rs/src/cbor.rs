//! Clean-room deterministic RFC 8949 CBOR codec for ProofBundle (Section 3.4.3),
//! `OTSProofBundleCBOR`, and RFC 9921 / RFC 9942 / RFC 9943 SCITT signature+receipt imprint binding.

use std::collections::BTreeSet;

use crate::sha256::{hex_lower, sha256};

const MAX_CBOR_DEPTH: usize = 16;
const MAX_CBOR_BYTES: usize = 262_144;
const COSE_SIGN1_TAG: u64 = 18;
/// RFC 9942 Section 8 IANA COSE Header parameter `receipts` (`394` => `[ + COSE_Receipt ]`).
pub const SCITT_RECEIPTS_HEADER_LABEL: u64 = 394;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CborValue {
    Uint(u64),
    NegInt(i128),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<CborValue>),
    Map(Vec<(CborValue, CborValue)>),
    Tag(u64, Box<CborValue>),
    Bool(bool),
    Null,
}

fn cbor_hdr(major: u8, val: u64) -> Vec<u8> {
    let prefix = major << 5;
    if val < 24 {
        vec![prefix | (val as u8)]
    } else if val < 256 {
        vec![prefix | 24, val as u8]
    } else if val < 65_536 {
        let b = (val as u16).to_be_bytes();
        vec![prefix | 25, b[0], b[1]]
    } else if val < (1u64 << 32) {
        let b = (val as u32).to_be_bytes();
        vec![prefix | 26, b[0], b[1], b[2], b[3]]
    } else {
        let b = val.to_be_bytes();
        vec![
            prefix | 27,
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]
    }
}

pub fn encode_cbor_bytes(data: &[u8]) -> Vec<u8> {
    let mut out = cbor_hdr(2, data.len() as u64);
    out.extend_from_slice(data);
    out
}

pub fn encode_cbor_text(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = cbor_hdr(3, b.len() as u64);
    out.extend_from_slice(b);
    out
}

fn read_uint(buf: &[u8], pos: usize, ai: u8, strict_det: bool) -> Option<(u64, usize)> {
    match ai {
        0..=23 => Some((ai as u64, pos)),
        24 => {
            if pos + 1 > buf.len() {
                return None;
            }
            let v = buf[pos] as u64;
            if strict_det && v < 24 {
                return None;
            }
            Some((v, pos + 1))
        }
        25 => {
            if pos + 2 > buf.len() {
                return None;
            }
            let v = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as u64;
            if strict_det && v < 256 {
                return None;
            }
            Some((v, pos + 2))
        }
        26 => {
            if pos + 4 > buf.len() {
                return None;
            }
            let v = u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]) as u64;
            if strict_det && v < 65_536 {
                return None;
            }
            Some((v, pos + 4))
        }
        27 => {
            if pos + 8 > buf.len() {
                return None;
            }
            let mut b = [0u8; 8];
            b.copy_from_slice(&buf[pos..pos + 8]);
            let v = u64::from_be_bytes(b);
            if strict_det && v < (1u64 << 32) {
                return None;
            }
            Some((v, pos + 8))
        }
        _ => None,
    }
}

fn decode_item(
    buf: &[u8],
    pos: usize,
    depth: usize,
    strict_det: bool,
    allow_any_tag: bool,
) -> Option<(CborValue, usize)> {
    if depth > MAX_CBOR_DEPTH || pos >= buf.len() {
        return None;
    }
    let initial = buf[pos];
    let major = initial >> 5;
    let ai = initial & 0x1f;
    let cur = pos + 1;

    match major {
        0 => {
            let (v, next) = read_uint(buf, cur, ai, strict_det)?;
            Some((CborValue::Uint(v), next))
        }
        1 => {
            let (v, next) = read_uint(buf, cur, ai, strict_det)?;
            Some((CborValue::NegInt(-1i128 - (v as i128)), next))
        }
        2 => {
            let (ln_u64, next) = read_uint(buf, cur, ai, strict_det)?;
            let ln = usize::try_from(ln_u64).ok()?;
            let end = next.checked_add(ln)?;
            if end > buf.len() {
                return None;
            }
            Some((CborValue::Bytes(buf[next..end].to_vec()), end))
        }
        3 => {
            let (ln_u64, next) = read_uint(buf, cur, ai, strict_det)?;
            let ln = usize::try_from(ln_u64).ok()?;
            let end = next.checked_add(ln)?;
            if end > buf.len() {
                return None;
            }
            let s = core::str::from_utf8(&buf[next..end]).ok()?.to_string();
            Some((CborValue::Text(s), end))
        }
        4 => {
            let (ln_u64, mut next) = read_uint(buf, cur, ai, strict_det)?;
            let ln = usize::try_from(ln_u64).ok()?;
            if ln > 4096 || ln > buf.len().saturating_sub(next) {
                return None;
            }
            let mut arr = Vec::with_capacity(ln);
            for _ in 0..ln {
                let (item, n2) = decode_item(buf, next, depth + 1, strict_det, allow_any_tag)?;
                arr.push(item);
                next = n2;
            }
            Some((CborValue::Array(arr), next))
        }
        5 => {
            let (ln_u64, mut next) = read_uint(buf, cur, ai, strict_det)?;
            let ln = usize::try_from(ln_u64).ok()?;
            if ln > 4096 || ln.saturating_mul(2) > buf.len().saturating_sub(next) {
                return None;
            }
            let mut pairs = Vec::with_capacity(ln);
            let mut seen_raw_keys = BTreeSet::new();
            let mut prev_raw_key: Option<Vec<u8>> = None;
            for _ in 0..ln {
                let k_start = next;
                let (k, k_end) = decode_item(buf, next, depth + 1, strict_det, false)?;
                match k {
                    CborValue::Uint(_)
                    | CborValue::NegInt(_)
                    | CborValue::Bytes(_)
                    | CborValue::Text(_) => {}
                    _ => return None,
                }
                let raw_key = buf[k_start..k_end].to_vec();
                if strict_det {
                    if let Some(ref prev) = prev_raw_key {
                        if raw_key <= *prev {
                            return None;
                        }
                    }
                }
                if !seen_raw_keys.insert(raw_key.clone()) {
                    return None;
                }
                prev_raw_key = Some(raw_key);
                // Allow nested semantic CBOR tags inside map values when parsing COSE envelopes
                let (v, v_end) = decode_item(buf, k_end, depth + 1, strict_det, allow_any_tag)?;
                pairs.push((k, v));
                next = v_end;
            }
            Some((CborValue::Map(pairs), next))
        }
        6 => {
            let (tag_num, next) = read_uint(buf, cur, ai, strict_det)?;
            if !allow_any_tag && tag_num != COSE_SIGN1_TAG {
                return None;
            }
            let (inner, end) = decode_item(buf, next, depth + 1, strict_det, allow_any_tag)?;
            Some((CborValue::Tag(tag_num, Box::new(inner)), end))
        }
        7 => match ai {
            20 => Some((CborValue::Bool(false), cur)),
            21 => Some((CborValue::Bool(true), cur)),
            22 => Some((CborValue::Null, cur)),
            _ => None,
        },
        _ => None,
    }
}

pub fn decode_cbor(data: &[u8], strict_deterministic: bool) -> Option<CborValue> {
    if data.is_empty() || data.len() > MAX_CBOR_BYTES {
        return None;
    }
    let (val, end) = decode_item(data, 0, 0, strict_deterministic, !strict_deterministic)?;
    if end != data.len() {
        return None;
    }
    Some(val)
}

#[derive(Clone, Debug)]
pub struct CoseSign1Statement {
    pub protected_hdr: Vec<u8>,
    pub unprotected_hdr: Vec<(CborValue, CborValue)>,
    pub payload: Option<Vec<u8>>,
    pub signature: Vec<u8>,
    pub raw_bytes: Vec<u8>,
}

pub fn parse_cose_sign1_statement(
    cbor_bytes: &[u8],
    strict_deterministic: bool,
) -> Option<CoseSign1Statement> {
    if cbor_bytes.is_empty() || cbor_bytes.len() > MAX_CBOR_BYTES {
        return None;
    }
    // Root may be Tag(18, Array(4)) or untagged Array(4); unprotected map values may carry nested tags.
    let (decoded, end) = decode_item(cbor_bytes, 0, 0, strict_deterministic, true)?;
    if end != cbor_bytes.len() {
        return None;
    }
    let body = match decoded {
        CborValue::Tag(tag, inner) => {
            if tag != COSE_SIGN1_TAG {
                return None;
            }
            *inner
        }
        other => other,
    };

    let mut arr = match body {
        CborValue::Array(items) if items.len() == 4 => items,
        _ => return None,
    };

    let sig = match arr.pop()? {
        CborValue::Bytes(s) if !s.is_empty() => s,
        _ => return None,
    };
    let payload = match arr.pop()? {
        CborValue::Bytes(p) => Some(p),
        CborValue::Null => None,
        _ => return None,
    };
    let unprot = match arr.pop()? {
        CborValue::Map(m) => m,
        _ => return None,
    };
    let prot = match arr.pop()? {
        CborValue::Bytes(b) => b,
        _ => return None,
    };

    Some(CoseSign1Statement {
        protected_hdr: prot,
        unprotected_hdr: unprot,
        payload,
        signature: sig,
        raw_bytes: cbor_bytes.to_vec(),
    })
}

/// Extract ALL RFC 9942 COSE Receipts (`header 394` => `[ + COSE_Receipt ]`, or single `bstr`).
pub fn extract_embedded_receipts(stmt: &CoseSign1Statement) -> Option<Vec<Vec<u8>>> {
    for (k, v) in &stmt.unprotected_hdr {
        let matches_label = matches!(k, CborValue::Uint(u) if *u == SCITT_RECEIPTS_HEADER_LABEL)
            || matches!(k, CborValue::Text(s) if s == "scitt_receipt");
        if matches_label {
            match v {
                CborValue::Bytes(b) if !b.is_empty() => return Some(vec![b.clone()]),
                CborValue::Array(items) if !items.is_empty() => {
                    let mut out = Vec::with_capacity(items.len());
                    for item in items {
                        match item {
                            CborValue::Bytes(b) if !b.is_empty() => out.push(b.clone()),
                            _ => return None,
                        }
                    }
                    return Some(out);
                }
                _ => return None,
            }
        }
    }
    None
}

/// Build deterministic CBOR commitment aligned with RFC 9921 §3.1.1 (`bstr`-wrapped `signature`),
/// `protected` header, `SHA-256(payload)`, and all RFC 9942 receipts in `header 394` (`[ + COSE_Receipt ]`).
/// Never emits `0xf6` (`null`) or unallocated IANA URNs.
pub fn compute_scitt_ots_tbs_bytes(
    stmt: &CoseSign1Statement,
    receipt_bytes: Option<&[u8]>,
    detached_payload: Option<&[u8]>,
    require_receipt: bool,
) -> Option<Vec<u8>> {
    let eff_payload: &[u8] = match stmt.payload.as_deref() {
        Some(p) => p,
        None => detached_payload?,
    };
    let receipts_list: Vec<Vec<u8>> = match receipt_bytes {
        Some(rb) if !rb.is_empty() => vec![rb.to_vec()],
        Some(_) => return None,
        None => extract_embedded_receipts(stmt).unwrap_or_default(),
    };
    if require_receipt && receipts_list.is_empty() {
        return None;
    }

    let payload_digest = sha256(eff_payload);
    let sig_bstr_cbor = encode_cbor_bytes(&stmt.signature);

    let mut out = Vec::with_capacity(160);
    if receipts_list.is_empty() {
        // 3-element deterministic CBOR array: [protected_bstr, sha256(payload), encode_cbor_bytes(signature)]
        out.push(0x83);
        out.extend_from_slice(&encode_cbor_bytes(&stmt.protected_hdr));
        out.extend_from_slice(&encode_cbor_bytes(&payload_digest));
        out.extend_from_slice(&encode_cbor_bytes(&sig_bstr_cbor));
    } else {
        // 4-element deterministic CBOR array binding ALL receipts in RFC 9942 header 394
        out.push(0x84);
        out.extend_from_slice(&encode_cbor_bytes(&stmt.protected_hdr));
        out.extend_from_slice(&encode_cbor_bytes(&payload_digest));
        out.extend_from_slice(&encode_cbor_bytes(&sig_bstr_cbor));
        let mut rcpt_arr_cbor = cbor_hdr(4, receipts_list.len() as u64);
        for r in &receipts_list {
            let rd = sha256(r);
            rcpt_arr_cbor.extend_from_slice(&encode_cbor_bytes(&rd));
        }
        let rcpt_set_digest = sha256(&rcpt_arr_cbor);
        out.extend_from_slice(&encode_cbor_bytes(&rcpt_set_digest));
    }
    Some(out)
}

#[derive(Clone, Debug)]
pub struct ParsedBundleCbor {
    pub ots_proof: Vec<u8>,
    pub claimed_hash: String,
    pub origin_id: Option<String>,
    pub bitcoin_block_height: Option<u64>,
}

pub fn parse_proof_bundle_cbor(
    cbor_bytes: &[u8],
    strict_deterministic: bool,
) -> Option<ParsedBundleCbor> {
    let decoded = decode_cbor(cbor_bytes, strict_deterministic)?;
    let pairs = match decoded {
        CborValue::Map(m) if !m.is_empty() => m,
        _ => return None,
    };

    let has_int_1_or_2 = pairs
        .iter()
        .any(|(k, _)| matches!(k, CborValue::Uint(1) | CborValue::Uint(2)));

    if has_int_1_or_2 {
        let mut ots_proof: Option<Vec<u8>> = None;
        let mut tbs_hash: Option<Vec<u8>> = None;
        let mut cached_h: Option<u64> = None;

        for (k, v) in pairs {
            let idx = match k {
                CborValue::Uint(u) if (1..=4).contains(&u) => u,
                _ => return None,
            };
            match idx {
                1 => match v {
                    CborValue::Bytes(b) => ots_proof = Some(b),
                    _ => return None,
                },
                2 => match v {
                    CborValue::Bytes(b) if b.len() == 32 => tbs_hash = Some(b),
                    _ => return None,
                },
                3 => match v {
                    CborValue::Uint(u) => cached_h = Some(u),
                    _ => return None,
                },
                4 => {}
                _ => return None,
            }
        }
        let th = tbs_hash?;
        return Some(ParsedBundleCbor {
            ots_proof: ots_proof?,
            claimed_hash: hex_lower(&th),
            origin_id: None,
            bitcoin_block_height: cached_h,
        });
    }

    let mut ots_proof: Option<Vec<u8>> = None;
    let mut claimed_hash: Option<String> = None;
    let mut origin_id: Option<String> = None;
    let mut bitcoin_block_height: Option<u64> = None;

    for (k, v) in pairs {
        let key = match k {
            CborValue::Text(s) => s,
            _ => return None,
        };
        match key.as_str() {
            "ots_proof" => match v {
                CborValue::Bytes(b) => ots_proof = Some(b),
                _ => return None,
            },
            "claimed_hash" => match v {
                CborValue::Text(s) => claimed_hash = Some(s),
                _ => return None,
            },
            "origin_id" => match v {
                CborValue::Text(s) => origin_id = Some(s),
                _ => return None,
            },
            "bitcoin_block_height" => match v {
                CborValue::Uint(u) => bitcoin_block_height = Some(u),
                _ => return None,
            },
            _ => return None,
        }
    }

    Some(ParsedBundleCbor {
        ots_proof: ots_proof?,
        claimed_hash: claimed_hash?,
        origin_id,
        bitcoin_block_height,
    })
}
