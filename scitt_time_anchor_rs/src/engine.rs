//! Shared JSONL evaluation engine used identically by both the native CLI binary
//! (`scitt_time_anchor_rs`) and the zero-dependency WebAssembly target (`wasm32-unknown-unknown`).

use std::collections::BTreeMap;

use crate::bitcoin::{
    CandidateHeaderStore, ChainBuildOptions, HeaderSource, ValidatedHeaderChain,
    BITCOIN_MAINNET_GENESIS_HEX, U256,
};
use crate::cbor::{
    compute_scitt_ots_tbs_bytes, parse_cose_sign1_statement, parse_proof_bundle_cbor,
};
use crate::json_min::{escape_json_str, parse_json_object, JsonVal};
use crate::ots::VerifierMode;
use crate::sha256::{decode_base64, decode_hex};
use crate::verifier::{
    verify_anchor, Outcome, ProofBundle, VerificationResult, MIN_CONFIRMATIONS,
};

fn format_opt_u64(v: Option<u64>) -> String {
    match v {
        Some(n) => n.to_string(),
        None => "null".to_string(),
    }
}

fn format_opt_u32(v: Option<u32>) -> String {
    match v {
        Some(n) => n.to_string(),
        None => "null".to_string(),
    }
}

pub fn format_result_json(case_id: &str, r: &VerificationResult) -> String {
    format!(
        "{{\"block_height_h\": {}, \"block_time_rwcp\": {}, \"confirmations\": {}, \"fmtp_11\": {}, \"fmtp_5\": {}, \"fmtp_6\": {}, \"id\": {}, \"mismatched_branches\": {}, \"mode\": {}, \"mtp_bip113\": {}, \"outcome\": {}, \"step\": {}}}",
        format_opt_u64(r.block_height_h),
        format_opt_u32(r.block_time_rwcp),
        format_opt_u64(r.confirmations),
        format_opt_u32(r.fmtp_11),
        format_opt_u32(r.fmtp_5),
        format_opt_u32(r.fmtp_6),
        escape_json_str(case_id),
        r.mismatched_branches,
        escape_json_str(r.mode.as_str()),
        format_opt_u32(r.mtp_bip113),
        escape_json_str(r.outcome.as_str()),
        r.step
    )
}

fn invalid_step0(mode: VerifierMode) -> VerificationResult {
    VerificationResult::early(Outcome::Invalid, 0, mode)
}

fn parse_headers_map(obj: &BTreeMap<String, JsonVal>) -> Option<BTreeMap<u64, Vec<u8>>> {
    let mut out = BTreeMap::new();
    for (k, v) in obj {
        let h = k.parse::<u64>().ok()?;
        let hex_s = v.as_str()?;
        let raw = decode_hex(hex_s)?;
        out.insert(h, raw);
    }
    Some(out)
}

pub fn build_chain_from_json_obj(
    vc_obj: &BTreeMap<String, JsonVal>,
    mode: VerifierMode,
) -> Option<ValidatedHeaderChain> {
    let strict = mode == VerifierMode::Strict;
    let ledger_id = vc_obj
        .get("ledger_id")
        .and_then(|v| v.as_str())
        .unwrap_or(BITCOIN_MAINNET_GENESIS_HEX)
        .to_string();
    let verify_pow_and_links = vc_obj
        .get("verify_pow_and_links")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let allow_sparse_checkpoints = vc_obj
        .get("allow_sparse_checkpoints")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let enforce_retarget_4x_bound = vc_obj
        .get("enforce_retarget_4x_bound")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
        && strict;
    let min_chainwork = if strict {
        match vc_obj.get("min_chainwork_hex").and_then(|v| v.as_str()) {
            Some("0") | Some("0x0") | None => U256::ZERO,
            Some(hex_cw) => U256::from_hex(hex_cw)?,
        }
    } else {
        U256::ZERO
    };

    let h_obj = vc_obj.get("headers_hex")?.as_obj()?;
    let h_map = parse_headers_map(h_obj)?;
    ValidatedHeaderChain::build_with_options(
        h_map,
        ChainBuildOptions {
            ledger_id,
            verify_pow_and_links,
            allow_sparse_checkpoints,
            enforce_retarget_4x_bound,
            min_chainwork,
        },
    )
}

pub fn select_best_fork_from_json(
    items: &[JsonVal],
    mode: VerifierMode,
) -> Option<ValidatedHeaderChain> {
    let mut valid_chains: Vec<ValidatedHeaderChain> = Vec::new();
    for item in items {
        if let Some(obj) = item.as_obj() {
            if let Some(vc) = build_chain_from_json_obj(obj, mode) {
                valid_chains.push(vc);
            }
        }
    }
    if valid_chains.is_empty() {
        return None;
    }
    if mode == VerifierMode::Draft08 {
        return Some(valid_chains.remove(0));
    }
    valid_chains.sort_by(|a, b| b.total_chainwork.cmp(&a.total_chainwork));
    Some(valid_chains.remove(0))
}

pub fn evaluate_line(line: &str, default_mode: VerifierMode) -> String {
    let map = match parse_json_object(line) {
        Some(m) => m,
        None => return "{\"error\": \"bad_json\"}".to_string(),
    };

    let case_id = map
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let mode = match map.get("mode").and_then(|v| v.as_str()) {
        Some(ms) => match VerifierMode::from_str_name(ms) {
            Some(m) => m,
            None => return format_result_json(&case_id, &invalid_step0(default_mode)),
        },
        None => default_mode,
    };
    let strict = mode == VerifierMode::Strict;

    let input_mode = map
        .get("input_mode")
        .and_then(|v| v.as_str())
        .unwrap_or("raw");

    let artifact_opt: Option<Vec<u8>> = if input_mode == "cose_sign1" {
        let b64 = match map.get("cose_sign1_b64").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return format_result_json(&case_id, &invalid_step0(mode)),
        };
        let cose_raw = match decode_base64(b64) {
            Some(b) => b,
            None => return format_result_json(&case_id, &invalid_step0(mode)),
        };
        match parse_cose_sign1_statement(&cose_raw, false) {
            Some(stmt) => Some(stmt.raw_bytes),
            None => return format_result_json(&case_id, &invalid_step0(mode)),
        }
    } else if input_mode == "scitt_ots_ctt" {
        let b64 = match map.get("cose_sign1_b64").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return format_result_json(&case_id, &invalid_step0(mode)),
        };
        let cose_raw = match decode_base64(b64) {
            Some(b) => b,
            None => return format_result_json(&case_id, &invalid_step0(mode)),
        };
        let stmt = match parse_cose_sign1_statement(&cose_raw, false) {
            Some(s) => s,
            None => return format_result_json(&case_id, &invalid_step0(mode)),
        };
        let rcpt_vec: Option<Vec<u8>> = match map.get("receipt_b64") {
            None | Some(JsonVal::Null) => None,
            Some(JsonVal::Str(s)) => match decode_base64(s) {
                Some(b) => Some(b),
                None => return format_result_json(&case_id, &invalid_step0(mode)),
            },
            _ => return format_result_json(&case_id, &invalid_step0(mode)),
        };
        let det_vec: Option<Vec<u8>> = match map.get("detached_payload_b64") {
            None | Some(JsonVal::Null) => None,
            Some(JsonVal::Str(s)) => match decode_base64(s) {
                Some(b) => Some(b),
                None => return format_result_json(&case_id, &invalid_step0(mode)),
            },
            _ => return format_result_json(&case_id, &invalid_step0(mode)),
        };
        let req_rcpt = map
            .get("require_receipt")
            .and_then(|v| v.as_bool())
            .unwrap_or(strict);
        match compute_scitt_ots_tbs_bytes(
            &stmt,
            rcpt_vec.as_deref(),
            det_vec.as_deref(),
            req_rcpt,
        ) {
            Some(tbs) => Some(tbs),
            None => return format_result_json(&case_id, &invalid_step0(mode)),
        }
    } else {
        match map.get("artifact_b64") {
            None | Some(JsonVal::Null) => None,
            Some(JsonVal::Str(s)) => match decode_base64(s) {
                Some(b) => Some(b),
                None => return format_result_json(&case_id, &invalid_step0(mode)),
            },
            _ => return format_result_json(&case_id, &invalid_step0(mode)),
        }
    };

    let bundle: ProofBundle = match map.get("proof_bundle_cbor_b64") {
        Some(JsonVal::Str(pb_b64)) => {
            let pb_raw = match decode_base64(pb_b64) {
                Some(b) => b,
                None => return format_result_json(&case_id, &invalid_step0(mode)),
            };
            let parsed_pb = match parse_proof_bundle_cbor(&pb_raw, strict) {
                Some(p) => p,
                None => return format_result_json(&case_id, &invalid_step0(mode)),
            };
            ProofBundle {
                ots_proof: parsed_pb.ots_proof,
                claimed_hash: parsed_pb.claimed_hash,
                origin_id: parsed_pb.origin_id,
                bitcoin_block_height: parsed_pb.bitcoin_block_height,
            }
        }
        _ => {
            let ots_b64 = match map.get("ots_b64").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => return format_result_json(&case_id, &invalid_step0(mode)),
            };
            let ots_proof = match decode_base64(ots_b64) {
                Some(b) => b,
                None => return format_result_json(&case_id, &invalid_step0(mode)),
            };
            let claimed_hash = match map.get("claimed_hash").and_then(|v| v.as_str()) {
                Some(s) => s.to_string(),
                None => return format_result_json(&case_id, &invalid_step0(mode)),
            };
            ProofBundle {
                ots_proof,
                claimed_hash,
                origin_id: None,
                bitcoin_block_height: None,
            }
        }
    };

    let validated_chain: Option<ValidatedHeaderChain> =
        if let Some(JsonVal::Arr(arr)) = map.get("candidate_chains") {
            select_best_fork_from_json(arr, mode)
        } else if let Some(JsonVal::Obj(vc_obj)) = map.get("validated_chain") {
            build_chain_from_json_obj(vc_obj, mode)
        } else {
            None
        };

    let candidate_store: Option<CandidateHeaderStore> = match map.get("candidate_store") {
        Some(JsonVal::Obj(cs_obj)) => {
            let src_str = cs_obj
                .get("source")
                .and_then(|v| v.as_str())
                .unwrap_or("validated_node");
            let source =
                HeaderSource::from_str_name(src_str).unwrap_or(HeaderSource::PublicExplorer);
            let h_obj = match cs_obj.get("headers_hex").and_then(|v| v.as_obj()) {
                Some(o) => o,
                None => return format_result_json(&case_id, &invalid_step0(mode)),
            };
            let hm = match parse_headers_map(h_obj) {
                Some(m) => m,
                None => return format_result_json(&case_id, &invalid_step0(mode)),
            };
            match CandidateHeaderStore::new(hm, source) {
                Some(cs) => Some(cs),
                None => return format_result_json(&case_id, &invalid_step0(mode)),
            }
        }
        _ => None,
    };

    let min_conf = map
        .get("min_confirmations")
        .and_then(|v| v.as_i64())
        .and_then(|n| u64::try_from(n).ok())
        .unwrap_or(MIN_CONFIRMATIONS);

    let expected_ledger_id = map.get("expected_ledger_id").and_then(|v| v.as_str());
    // Default false on all v1 verifiers to preserve 100% wild OpenTimestamps compatibility.
    let require_rfc6962 = map
        .get("require_rfc6962_batch")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let res = verify_anchor(
        artifact_opt.as_deref(),
        &bundle,
        validated_chain.as_ref(),
        candidate_store.as_ref(),
        mode,
        min_conf,
        expected_ledger_id,
        require_rfc6962,
    );

    format_result_json(&case_id, &res)
}
