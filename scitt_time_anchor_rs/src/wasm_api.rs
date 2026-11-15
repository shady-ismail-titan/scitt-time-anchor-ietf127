//! Memory-safe (`#![forbid(unsafe_code)]`) WebAssembly FFI and iterative O(1)-stack
//! Byte-Ray wire dissector. Zero `unsafe` blocks, zero recursion.

use std::sync::Mutex;

use crate::engine::evaluate_line;
use crate::json_min::escape_json_str;
use crate::ots::{
    decode_varuint_js_toint32, decode_varuint_py_unbounded, ots_deserialize, read_varuint,
    VerifierMode, BITCOIN_ATTESTATION_TAG, DRAFT08_MAX_DEPTH, DRAFT08_MAX_OPERAND_BYTES,
    HARDENED_MAX_RUNNING_BYTES, MAX_ATTESTATION_PAYLOAD_BYTES, OP_APPEND, OP_HEXLIFY,
    OP_KECCAK256, OP_LEGACY_01, OP_PREPEND, OP_REVERSE, OP_RIPEMD160, OP_SHA1, OP_SHA256,
    OTS_MAGIC, PENDING_ATTESTATION_TAG, TAG_ATTESTATION, TAG_BRANCH,
};
use crate::sha256::hex_lower;

pub const MAX_WASM_IO_BYTES: usize = 4_194_304;

static INPUT_BUF: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static OUTPUT_BUF: Mutex<Vec<u8>> = Mutex::new(Vec::new());

fn write_output_str(s: String) -> usize {
    let mut out = match OUTPUT_BUF.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    out.clear();
    out.extend_from_slice(s.as_bytes());
    out.len()
}

pub extern "C" fn wasm_prepare_input(len: usize) -> usize {
    if len > MAX_WASM_IO_BYTES {
        return 0;
    }
    let mut buf = match INPUT_BUF.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    buf.clear();
    buf.resize(len, 0u8);
    buf.as_mut_ptr() as usize
}

pub extern "C" fn wasm_output_ptr() -> usize {
    let out = match OUTPUT_BUF.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    out.as_ptr() as usize
}

pub extern "C" fn wasm_output_len() -> usize {
    let out = match OUTPUT_BUF.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    out.len()
}

pub extern "C" fn wasm_evaluate_jsonl(default_mode_id: u32) -> usize {
    let default_mode = if default_mode_id == 1 {
        VerifierMode::Strict
    } else {
        VerifierMode::Draft08
    };

    let input_text = {
        let buf = match INPUT_BUF.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        core::str::from_utf8(&buf).ok().map(|s| s.to_string())
    };

    let text = match input_text {
        Some(t) => t,
        None => return write_output_str("{\"error\": \"invalid_utf8\"}".to_string()),
    };

    let mut lines_out: Vec<String> = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        lines_out.push(evaluate_line(trimmed, default_mode));
    }

    write_output_str(lines_out.join("\n"))
}

enum DissectFrame {
    EnterTimestamp {
        running_len: u64,
        step_idx: usize,
        record_growth: bool,
        depth: usize,
    },
    AfterBranchStep {
        running_len: u64,
        step_idx: usize,
        depth: usize,
    },
    EnterStep {
        running_len: u64,
        step_idx: usize,
        record_growth: bool,
        depth: usize,
    },
}

struct Dissector {
    spans_json: Vec<String>,
    varuints_json: Vec<String>,
    growth_json: Vec<String>,
    parse_error: Option<(usize, String)>,
}

impl Dissector {
    fn new() -> Self {
        Self {
            spans_json: Vec::new(),
            varuints_json: Vec::new(),
            growth_json: Vec::new(),
            parse_error: None,
        }
    }

    fn push_span(
        &mut self,
        start: usize,
        end: usize,
        kind: &str,
        label: &str,
        section: &str,
        detail: &str,
    ) {
        self.spans_json.push(format!(
            "{{\"start\": {}, \"end\": {}, \"kind\": {}, \"label\": {}, \"section\": {}, \"detail\": {}}}",
            start,
            end,
            escape_json_str(kind),
            escape_json_str(label),
            escape_json_str(section),
            escape_json_str(detail)
        ));
    }

    fn record_varuint(&mut self, buf: &[u8], pos: usize, role: &str) -> Option<(u64, usize)> {
        let (py_val, end_pos) = match decode_varuint_py_unbounded(buf, pos) {
            Some(x) => x,
            None => {
                self.parse_error = Some((pos, format!("Truncated or >64-bit varuint at {}", role)));
                return None;
            }
        };
        let js_val = decode_varuint_js_toint32(buf, pos).map(|(v, _)| v).unwrap_or(0);
        let canon_val = read_varuint(buf, pos, true).map(|(v, _)| v);
        let raw_slice = &buf[pos..end_pos];

        let mut byte_rows = Vec::with_capacity(raw_slice.len());
        for (idx, &b) in raw_slice.iter().enumerate() {
            let py_sh = 7 * idx;
            let js_sh = py_sh & 31;
            byte_rows.push(format!(
                "{{\"idx\": {}, \"byte_hex\": \"{:02x}\", \"low7\": {}, \"cont\": {}, \"py_shift\": {}, \"js_shift\": {}}}",
                idx,
                b,
                b & 0x7f,
                (b & 0x80) != 0,
                py_sh,
                js_sh
            ));
        }

        let canon_json = match canon_val {
            Some(v) => v.to_string(),
            None => "null".to_string(),
        };

        self.varuints_json.push(format!(
            "{{\"offset\": {}, \"end\": {}, \"role\": {}, \"raw_hex\": \"{}\", \"js_toint32\": {}, \"py_u64\": {}, \"canonical_u32\": {}, \"bytes\": [{}]}}",
            pos,
            end_pos,
            escape_json_str(role),
            hex_lower(raw_slice),
            js_val,
            py_val,
            canon_json,
            byte_rows.join(", ")
        ));
        Some((py_val, end_pos))
    }

    fn walk_iterative(&mut self, buf: &[u8], mut pos: usize, init_len: u64) -> Option<usize> {
        let mut stack: Vec<DissectFrame> = Vec::with_capacity(64);
        stack.push(DissectFrame::EnterTimestamp {
            running_len: init_len,
            step_idx: 1,
            record_growth: true,
            depth: 0,
        });

        while let Some(frame) = stack.pop() {
            match frame {
                DissectFrame::EnterTimestamp {
                    running_len,
                    step_idx,
                    record_growth,
                    depth,
                } => {
                    if depth > DRAFT08_MAX_DEPTH {
                        self.parse_error =
                            Some((pos, "Exceeded max depth bound (4608)".to_string()));
                        return None;
                    }
                    if pos >= buf.len() {
                        self.parse_error =
                            Some((pos, "Unexpected EOF expecting step or branch tag".to_string()));
                        return None;
                    }
                    if buf[pos] == TAG_BRANCH {
                        self.push_span(
                            pos,
                            pos + 1,
                            "branch",
                            "Branch Fork (0xff)",
                            "Section 3.4 / Step 5",
                            "Splits Merkle timestamp tree into an additional attestation branch",
                        );
                        pos += 1;
                        stack.push(DissectFrame::AfterBranchStep {
                            running_len,
                            step_idx,
                            depth,
                        });
                        stack.push(DissectFrame::EnterStep {
                            running_len,
                            step_idx,
                            record_growth,
                            depth: depth + 1,
                        });
                    } else {
                        stack.push(DissectFrame::EnterStep {
                            running_len,
                            step_idx,
                            record_growth,
                            depth: depth + 1,
                        });
                    }
                }
                DissectFrame::AfterBranchStep {
                    running_len,
                    step_idx,
                    depth,
                } => {
                    if depth > DRAFT08_MAX_DEPTH || pos >= buf.len() {
                        self.parse_error =
                            Some((pos, "Unexpected EOF after branch step".to_string()));
                        return None;
                    }
                    if buf[pos] == TAG_BRANCH {
                        self.push_span(
                            pos,
                            pos + 1,
                            "branch",
                            "Branch Fork (0xff)",
                            "Section 3.4 / Step 5",
                            "Splits Merkle timestamp tree into an additional attestation branch",
                        );
                        pos += 1;
                        stack.push(DissectFrame::AfterBranchStep {
                            running_len,
                            step_idx,
                            depth,
                        });
                        stack.push(DissectFrame::EnterStep {
                            running_len,
                            step_idx,
                            record_growth: false,
                            depth: depth + 1,
                        });
                    } else {
                        stack.push(DissectFrame::EnterStep {
                            running_len,
                            step_idx,
                            record_growth: false,
                            depth: depth + 1,
                        });
                    }
                }
                DissectFrame::EnterStep {
                    running_len,
                    step_idx,
                    record_growth,
                    depth,
                } => {
                    if pos >= buf.len() {
                        self.parse_error = Some((pos, "Unexpected EOF inside step".to_string()));
                        return None;
                    }
                    let tag = buf[pos];
                    match tag {
                        TAG_ATTESTATION => {
                            self.push_span(
                                pos,
                                pos + 1,
                                "att_marker",
                                "Attestation Marker (0x00)",
                                "Section 3.4.2 / Step 4",
                                "Introduces an 8-byte OpenTimestamps attestation type identifier",
                            );
                            pos += 1;
                            if pos.checked_add(8)? > buf.len() {
                                self.parse_error =
                                    Some((pos, "Truncated 8-byte attestation tag".to_string()));
                                return None;
                            }
                            let mut att_tag = [0u8; 8];
                            att_tag.copy_from_slice(&buf[pos..pos + 8]);
                            if att_tag == BITCOIN_ATTESTATION_TAG {
                                self.push_span(
                                    pos,
                                    pos + 8,
                                    "btc_tag",
                                    "Bitcoin Block Header Attestation Tag",
                                    "Section 3.4.2 / Step 4",
                                    "0588960d73d71901 — commits branch tip to Bitcoin block Merkle root at height H",
                                );
                            } else if att_tag == PENDING_ATTESTATION_TAG {
                                self.push_span(
                                    pos,
                                    pos + 8,
                                    "pending_tag",
                                    "Pending Calendar Attestation Tag",
                                    "Section 3.4.1 / Step 4",
                                    "83dfe30d2ef90c8e — unanchored calendar commitment URI (ignored once Bitcoin branch verifies)",
                                );
                            } else {
                                self.push_span(
                                    pos,
                                    pos + 8,
                                    "unknown_tag",
                                    "Unknown Attestation Tag",
                                    "Section 4.1 Step 4",
                                    &format!(
                                        "Tag {} — skipped up to 8192 B per notary.py",
                                        hex_lower(&att_tag)
                                    ),
                                );
                            }
                            pos += 8;

                            let (plen_u64, p_start) =
                                self.record_varuint(buf, pos, "attestation_payload_len")?;
                            self.push_span(
                                pos,
                                p_start,
                                "varuint_len",
                                "Attestation Payload Length",
                                "Section 3.4.2",
                                &format!("Payload byte length = {}", plen_u64),
                            );
                            let plen = match usize::try_from(plen_u64) {
                                Ok(v) if v <= MAX_ATTESTATION_PAYLOAD_BYTES => v,
                                _ => {
                                    self.parse_error = Some((
                                        pos,
                                        "Attestation payload length exceeds 8192-byte cap"
                                            .to_string(),
                                    ));
                                    return None;
                                }
                            };
                            let p_end = match p_start.checked_add(plen) {
                                Some(e) if e <= buf.len() => e,
                                _ => {
                                    self.parse_error = Some((
                                        p_start,
                                        "Truncated attestation payload".to_string(),
                                    ));
                                    return None;
                                }
                            };

                            if att_tag == BITCOIN_ATTESTATION_TAG {
                                let (py_h, h_end) =
                                    self.record_varuint(buf, p_start, "bitcoin_block_height")?;
                                let js_h = decode_varuint_js_toint32(buf, p_start)
                                    .map(|(v, _)| v)
                                    .unwrap_or(0);
                                let canon_h = read_varuint(buf, p_start, true).map(|(v, _)| v);
                                let detail = match canon_h {
                                    Some(ch) if h_end == p_end => format!(
                                        "Canonical LEB128 height H = {} (JS = {}, Python = {})",
                                        ch, js_h, py_h
                                    ),
                                    _ => format!(
                                        "NON-CANONICAL LEB128! Upstream JS (shift & 31) decodes H = {}, Python/draft-08 decodes H = {}, Strict Profile REJECTS",
                                        js_h, py_h
                                    ),
                                };
                                self.push_span(
                                    p_start,
                                    p_end,
                                    if canon_h.is_some() && h_end == p_end {
                                        "btc_height"
                                    } else {
                                        "btc_height_alert"
                                    },
                                    "Bitcoin Block Height (LEB128)",
                                    "Section 3.4.2 / Section 4.1 Step 3 & 6",
                                    &detail,
                                );
                            } else if att_tag == PENDING_ATTESTATION_TAG {
                                let uri_preview = core::str::from_utf8(&buf[p_start..p_end])
                                    .unwrap_or("<binary calendar payload>");
                                self.push_span(
                                    p_start,
                                    p_end,
                                    "pending_uri",
                                    "Calendar Server URI Payload",
                                    "Section 3.4.1 / Section 5.2",
                                    &format!("Pending calendar payload ({} B): {}", plen, uri_preview),
                                );
                            } else {
                                self.push_span(
                                    p_start,
                                    p_end,
                                    "unknown_payload",
                                    "Opaque Attestation Payload",
                                    "Section 4.1 Step 4",
                                    &format!("{} bytes", plen),
                                );
                            }
                            pos = p_end;
                        }
                        OP_APPEND | OP_PREPEND => {
                            let op_name = if tag == OP_APPEND {
                                "OpAppend (0xf0)"
                            } else {
                                "OpPrepend (0xf1)"
                            };
                            self.push_span(
                                pos,
                                pos + 1,
                                "op_concat",
                                op_name,
                                "Section 4.1 Step 5",
                                if tag == OP_APPEND {
                                    "Appends operand bytes to right of current digest state"
                                } else {
                                    "Prepends operand bytes to left of current digest state"
                                },
                            );
                            pos += 1;
                            let (alen_u64, a_start) =
                                self.record_varuint(buf, pos, "operand_len")?;
                            self.push_span(
                                pos,
                                a_start,
                                "varuint_len",
                                "Operand Length (varuint)",
                                "Section 4.1 Step 3",
                                &format!("{} bytes", alen_u64),
                            );
                            let alen = match usize::try_from(alen_u64) {
                                Ok(v) if v <= DRAFT08_MAX_OPERAND_BYTES => v,
                                _ => {
                                    self.parse_error = Some((
                                        pos,
                                        "Operand length exceeds 4096-byte parser cap".to_string(),
                                    ));
                                    return None;
                                }
                            };
                            let a_end = match a_start.checked_add(alen) {
                                Some(e) if e <= buf.len() => e,
                                _ => {
                                    self.parse_error =
                                        Some((a_start, "Truncated operand bytes".to_string()));
                                    return None;
                                }
                            };
                            self.push_span(
                                a_start,
                                a_end,
                                "operand",
                                &format!("Merkle / Nonce Operand ({} B)", alen),
                                "Section 3.5 / Section 4.1 Step 5",
                                &format!(
                                    "Hex: {}",
                                    hex_lower(&buf[a_start..core::cmp::min(a_end, a_start + 32)])
                                ),
                            );
                            let next_len = running_len.saturating_add(alen as u64);
                            if record_growth && self.growth_json.len() < 128 {
                                self.growth_json.push(format!(
                                    "{{\"step\": {}, \"op\": {}, \"bytes\": {}, \"exceeded_strict\": {}}}",
                                    step_idx,
                                    escape_json_str(op_name),
                                    next_len,
                                    next_len > HARDENED_MAX_RUNNING_BYTES as u64
                                ));
                            }
                            pos = a_end;
                            stack.push(DissectFrame::EnterTimestamp {
                                running_len: next_len,
                                step_idx: step_idx + 1,
                                record_growth,
                                depth,
                            });
                        }
                        OP_SHA256 => {
                            self.push_span(
                                pos,
                                pos + 1,
                                "op_sha256",
                                "OpSHA256 (0x08)",
                                "Section 4.1 Step 5",
                                "Compresses running buffer via SHA-256 to 32 bytes",
                            );
                            if record_growth && self.growth_json.len() < 128 {
                                self.growth_json.push(format!(
                                    "{{\"step\": {}, \"op\": \"OpSHA256 (0x08)\", \"bytes\": 32, \"exceeded_strict\": false}}",
                                    step_idx
                                ));
                            }
                            pos += 1;
                            stack.push(DissectFrame::EnterTimestamp {
                                running_len: 32,
                                step_idx: step_idx + 1,
                                record_growth,
                                depth,
                            });
                        }
                        OP_LEGACY_01 | OP_SHA1 | OP_RIPEMD160 | OP_KECCAK256 | OP_REVERSE
                        | OP_HEXLIFY => {
                            let (op_name, next_len, note) = match tag {
                                OP_SHA1 => (
                                    "OpSHA1 (0x02) [160-Bit Narrow-Pipe]",
                                    20u64,
                                    "160-bit SHA-1 mid-path compression (2^80 Grover bound) — rejected by Strict whitelist, unsupported in draft-08 Step 5",
                                ),
                                OP_RIPEMD160 => (
                                    "OpRIPEMD160 (0x03) [160-Bit Narrow-Pipe]",
                                    20u64,
                                    "160-bit RIPEMD-160 — disallowed to preserve 2^128 SHA-256 security floor (draft-08 §8.8)",
                                ),
                                OP_KECCAK256 => (
                                    "OpKeccak256 (0x67) [Non-Profile Hash]",
                                    32u64,
                                    "Keccak-256 — non-SHA-256 hash op",
                                ),
                                OP_HEXLIFY => (
                                    "OpHexlify (0xf3) [Buffer Doubling]",
                                    running_len.saturating_mul(2),
                                    "Doubles running buffer size every byte! 30 consecutive 0xf3 ops expand 32 B to 34.36 GB in unconstrained parsers",
                                ),
                                OP_REVERSE => (
                                    "OpReverse (0xf2) [Legacy Unary]",
                                    running_len,
                                    "Reverses running byte buffer — disallowed in SCITT profile",
                                ),
                                _ => ("OpLegacy01 (0x01)", 20u64, "Legacy opcode 0x01"),
                            };
                            self.push_span(
                                pos,
                                pos + 1,
                                "op_alert",
                                op_name,
                                "Section 4.1 Step 3 & Step 5 / Section 8.8",
                                note,
                            );
                            if record_growth && self.growth_json.len() < 128 {
                                self.growth_json.push(format!(
                                    "{{\"step\": {}, \"op\": {}, \"bytes\": {}, \"exceeded_strict\": {}}}",
                                    step_idx,
                                    escape_json_str(op_name),
                                    next_len,
                                    next_len > HARDENED_MAX_RUNNING_BYTES as u64
                                ));
                            }
                            pos += 1;
                            stack.push(DissectFrame::EnterTimestamp {
                                running_len: next_len,
                                step_idx: step_idx + 1,
                                record_growth,
                                depth,
                            });
                        }
                        other => {
                            self.push_span(
                                pos,
                                pos + 1,
                                "op_alert",
                                &format!("Unknown Opcode (0x{:02x})", other),
                                "Section 4.1 Step 3",
                                "Invalid wire tag — rejected immediately by OTS-DESERIALIZE",
                            );
                            self.parse_error = Some((pos, format!("Unknown opcode 0x{:02x}", other)));
                            return None;
                        }
                    }
                }
            }
        }
        Some(pos)
    }
}

pub extern "C" fn wasm_dissect_ots() -> usize {
    let raw = match INPUT_BUF.lock() {
        Ok(g) => g.clone(),
        Err(p) => p.into_inner().clone(),
    };
    let draft08_ok = ots_deserialize(&raw, VerifierMode::Draft08).is_some();
    let strict_ok = ots_deserialize(&raw, VerifierMode::Strict).is_some();

    let mut d = Dissector::new();

    if raw.len() < OTS_MAGIC.len() {
        let end = raw.len();
        if end > 0 {
            d.push_span(
                0,
                end,
                "op_alert",
                "Truncated OTS Header",
                "Section 4.1 Step 3",
                &format!(
                    "Expected 31-byte OpenTimestamps magic header, got {} bytes",
                    end
                ),
            );
        }
        d.parse_error = Some((0, format!("Input shorter than 31-byte OTS magic ({} B)", end)));
    } else if &raw[..OTS_MAGIC.len()] != OTS_MAGIC {
        d.push_span(
            0,
            OTS_MAGIC.len(),
            "op_alert",
            "Invalid Magic Header",
            "Section 4.1 Step 3",
            "First 31 bytes do not match \\x00OpenTimestamps\\x00\\x00Proof\\x00...",
        );
        d.parse_error = Some((0, "OTS header magic mismatch".to_string()));
    } else {
        d.push_span(
            0,
            OTS_MAGIC.len(),
            "magic",
            "OpenTimestamps Header Magic (31 B)",
            "Section 3.4 / [OTS]",
            "Fixed 31-byte signature identifying an OpenTimestamps proof container",
        );
        if let Some((ver, v_end)) = d.record_varuint(&raw, OTS_MAGIC.len(), "ots_version") {
            let ver_canon = read_varuint(&raw, OTS_MAGIC.len(), true).is_some();
            d.push_span(
                OTS_MAGIC.len(),
                v_end,
                if ver == 1 && ver_canon {
                    "version"
                } else {
                    "op_alert"
                },
                &format!("Proof Format Version ({})", ver),
                "Section 3.4.2 / Step 3",
                if ver == 1 && ver_canon {
                    "Canonical version 1"
                } else {
                    "Non-canonical or unsupported OTS version encoding"
                },
            );
            if v_end >= raw.len() {
                d.parse_error = Some((v_end, "Missing file_hash_op byte".to_string()));
            } else {
                let fop = raw[v_end];
                let (f_label, f_kind, dlen_opt, f_detail) = match fop {
                    OP_SHA256 => (
                        "File Hash Op: SHA-256 (0x08)",
                        "hash_op",
                        Some(32usize),
                        "Normative SHA-256 (32-byte artifact digest) required by Section 4.1 Step 3",
                    ),
                    OP_KECCAK256 => (
                        "File Hash Op: Keccak-256 (0x67) [Violation]",
                        "op_alert",
                        Some(32usize),
                        "32-byte Keccak-256 header — MUST fail Step 3 (file_hash_op != SHA-256), missed by CryptoGeekPT -03",
                    ),
                    OP_SHA1 => (
                        "File Hash Op: SHA-1 (0x02) [Violation]",
                        "op_alert",
                        Some(20usize),
                        "20-byte SHA-1 file hash — rejected by Step 3",
                    ),
                    OP_RIPEMD160 => (
                        "File Hash Op: RIPEMD-160 (0x03) [Violation]",
                        "op_alert",
                        Some(20usize),
                        "20-byte RIPEMD-160 file hash — rejected by Step 3",
                    ),
                    _ => (
                        "Unknown File Hash Op",
                        "op_alert",
                        None,
                        "Unrecognized file_hash_op tag",
                    ),
                };
                d.push_span(v_end, v_end + 1, f_kind, f_label, "Section 4.1 Step 3", f_detail);
                if let Some(dlen) = dlen_opt {
                    let m_start = v_end + 1;
                    if let Some(m_end) = m_start.checked_add(dlen) {
                        if m_end <= raw.len() {
                            d.push_span(
                                m_start,
                                m_end,
                                "digest",
                                &format!("Target Artifact Digest ({} B)", dlen),
                                "Section 4.1 Step 2 & Step 3",
                                &format!("Digest: {}", hex_lower(&raw[m_start..m_end])),
                            );
                            d.growth_json.push(format!(
                                "{{\"step\": 0, \"op\": \"Initial Digest\", \"bytes\": {}, \"exceeded_strict\": false}}",
                                dlen
                            ));
                            if let Some(final_pos) = d.walk_iterative(&raw, m_end, dlen as u64) {
                                if final_pos < raw.len() {
                                    d.push_span(
                                        final_pos,
                                        raw.len(),
                                        "op_alert",
                                        &format!("Trailing Bytes ({} B)", raw.len() - final_pos),
                                        "Section 4.1 Step 3",
                                        "Unconsumed trailing bytes after end of timestamp tree — rejected",
                                    );
                                    d.parse_error = Some((
                                        final_pos,
                                        format!("{} trailing unconsumed bytes", raw.len() - final_pos),
                                    ));
                                }
                            }
                        } else {
                            d.parse_error = Some((m_start, "Truncated target digest".to_string()));
                        }
                    }
                } else {
                    d.parse_error = Some((v_end, format!("Unsupported file_hash_op 0x{:02x}", fop)));
                }
            }
        }
    }

    let err_json = match d.parse_error {
        Some((off, msg)) => format!("{{\"offset\": {}, \"message\": {}}}", off, escape_json_str(&msg)),
        None => "null".to_string(),
    };

    let json = format!(
        "{{\"total_bytes\": {}, \"draft08_parse_ok\": {}, \"strict_parse_ok\": {}, \"parse_error\": {}, \"spans\": [{}], \"varuints\": [{}], \"buffer_growth\": [{}]}}",
        raw.len(),
        draft08_ok,
        strict_ok,
        err_json,
        d.spans_json.join(", "),
        d.varuints_json.join(", "),
        d.growth_json.join(", ")
    );
    write_output_str(json)
}
