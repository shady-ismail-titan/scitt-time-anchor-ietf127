//! Normative 11-step `VERIFY-ANCHOR` (`draft08`) and Candidate `-09` Strict Profile (`strict`)
//! state machine in memory-safe `#![forbid(unsafe_code)]` Rust.

use crate::bitcoin::{BitcoinHeader, CandidateHeaderStore, ValidatedHeaderChain};
use crate::ots::{
    ots_deserialize_dag, verify_rfc6962_batch_prefix_ops, Attestation, OtsDagBranch, VerifierMode,
    HARDENED_MAX_RUNNING_BYTES, OP_SHA256,
};
use crate::sha256::{hex_lower, sha256};

pub const MIN_CONFIRMATIONS: u64 = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Valid,
    Invalid,
    Unverifiable,
}

impl Outcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::Unverifiable => "unverifiable",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProofBundle {
    pub ots_proof: Vec<u8>,
    pub claimed_hash: String,
    pub origin_id: Option<String>,
    pub bitcoin_block_height: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationResult {
    pub outcome: Outcome,
    pub step: u8,
    pub mode: VerifierMode,
    pub block_height_h: Option<u64>,
    pub block_time_rwcp: Option<u32>,
    pub confirmations: Option<u64>,
    pub mtp_bip113: Option<u32>,
    pub fmtp_5: Option<u32>,
    pub fmtp_6: Option<u32>,
    pub fmtp_11: Option<u32>,
    pub mismatched_branches: usize,
}

impl VerificationResult {
    pub fn early(outcome: Outcome, step: u8, mode: VerifierMode) -> Self {
        Self {
            outcome,
            step,
            mode,
            block_height_h: None,
            block_time_rwcp: None,
            confirmations: None,
            mtp_bip113: None,
            fmtp_5: None,
            fmtp_6: None,
            fmtp_11: None,
            mismatched_branches: 0,
        }
    }
}

pub fn strip_prefix(s: &str) -> &str {
    s.strip_prefix("sha256:").unwrap_or(s)
}

fn is_canonical_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BranchState {
    Verified,
    Mismatched,
    Unavailable,
    Unsupported,
}

#[allow(clippy::too_many_arguments)]
pub fn verify_anchor(
    artifact_bytes: Option<&[u8]>,
    proof_bundle: &ProofBundle,
    validated_chain: Option<&ValidatedHeaderChain>,
    candidate_store: Option<&CandidateHeaderStore>,
    mode: VerifierMode,
    min_confirmations: u64,
    expected_ledger_id: Option<&str>,
    require_rfc6962_batch: bool,
) -> VerificationResult {
    let strict = mode == VerifierMode::Strict;
    let effective_min_conf = if strict {
        min_confirmations.max(MIN_CONFIRMATIONS)
    } else {
        min_confirmations
    };

    let artifact = match artifact_bytes {
        Some(a) => a,
        None => return VerificationResult::early(Outcome::Unverifiable, 1, mode),
    };

    // Step 1: RECOMPUTE HASH
    let computed_hash = sha256(artifact);
    let computed_hex = hex_lower(&computed_hash);

    // Step 2: COMPARE HASH
    let stripped_claimed = strip_prefix(&proof_bundle.claimed_hash);
    if strict && !is_canonical_hex64(stripped_claimed) {
        return VerificationResult::early(Outcome::Invalid, 2, mode);
    }
    if computed_hex != stripped_claimed {
        return VerificationResult::early(Outcome::Invalid, 2, mode);
    }

    // Step 3: PARSE OTS PROOF (shared-prefix DAG with total-ops budget)
    let parsed = match ots_deserialize_dag(&proof_bundle.ots_proof, mode) {
        Some(p) => p,
        None => return VerificationResult::early(Outcome::Invalid, 3, mode),
    };

    if parsed.file_hash_op != OP_SHA256 || parsed.msg.as_slice() != computed_hash {
        return VerificationResult::early(Outcome::Invalid, 3, mode);
    }

    // Step 4: CHECK PROOF STATUS
    let btc_branches: Vec<(usize, &OtsDagBranch, u64)> = parsed
        .branches
        .iter()
        .enumerate()
        .filter_map(|(idx, b)| match b.attestation {
            Attestation::Bitcoin(h) => Some((idx, b, h)),
            _ => None,
        })
        .collect();

    if btc_branches.is_empty() {
        return VerificationResult::early(Outcome::Unverifiable, 4, mode);
    }

    if strict && require_rfc6962_batch {
        for (_, b, _) in &btc_branches {
            let ops = parsed.branch_ops(b);
            if !verify_rfc6962_batch_prefix_ops(&ops) {
                return VerificationResult::early(Outcome::Invalid, 3, mode);
            }
        }
    }

    // Steps 5, 6, 7a, 7b, 8 — evaluate shared prefix DAG once in O(total_wire_ops)
    let all_digests = parsed.eval_branch_digests(&computed_hash, HARDENED_MAX_RUNNING_BYTES);
    let mut states = Vec::with_capacity(btc_branches.len());
    let mut verified_headers: Vec<(u64, BitcoinHeader)> = Vec::new();
    let mut mismatched_count: usize = 0;

    for (br_idx, _branch, h) in btc_branches {
        let digest_opt = &all_digests[br_idx];

        let candidate_opt = if let Some(cs) = candidate_store {
            cs.fetch_block_header_by_height(h)
        } else if let Some(vc) = validated_chain {
            vc.raw_header_at(h)
        } else {
            None
        };

        let validated_hdr_opt = if let Some(vc) = validated_chain {
            vc.validate_header_on_chain(h, candidate_opt, expected_ledger_id)
                .cloned()
        } else {
            None
        };

        let st = match (digest_opt, &validated_hdr_opt) {
            (None, _) => BranchState::Unsupported,
            (Some(_), None) => BranchState::Unavailable,
            (Some(d), Some(hdr)) => {
                if d.as_slice() == hdr.merkle_root_internal {
                    verified_headers.push((h, hdr.clone()));
                    BranchState::Verified
                } else {
                    mismatched_count += 1;
                    BranchState::Mismatched
                }
            }
        };
        states.push(st);
    }

    if verified_headers.is_empty() {
        let has_unevaluated = states
            .iter()
            .any(|&s| s == BranchState::Unavailable || s == BranchState::Unsupported);
        return VerificationResult {
            outcome: if has_unevaluated {
                Outcome::Unverifiable
            } else {
                Outcome::Invalid
            },
            step: 8,
            mode,
            block_height_h: None,
            block_time_rwcp: None,
            confirmations: None,
            mtp_bip113: None,
            fmtp_5: None,
            fmtp_6: None,
            fmtp_11: None,
            mismatched_branches: mismatched_count,
        };
    }

    verified_headers.sort_by_key(|(h, _)| *h);

    let vc = match validated_chain {
        Some(v) => v,
        None => {
            return VerificationResult {
                outcome: Outcome::Unverifiable,
                step: 9,
                mode,
                block_height_h: Some(verified_headers[0].0),
                block_time_rwcp: None,
                confirmations: None,
                mtp_bip113: None,
                fmtp_5: None,
                fmtp_6: None,
                fmtp_11: None,
                mismatched_branches: mismatched_count,
            };
        }
    };

    let (best_h, best_hdr, best_k) = if strict {
        let mut confirmed: Vec<(u64, BitcoinHeader, u64)> = Vec::new();
        for (h, hdr) in &verified_headers {
            if let Some(k) = vc.confirmations_on(*h) {
                if k >= effective_min_conf {
                    confirmed.push((*h, hdr.clone(), k));
                }
            }
        }
        if confirmed.is_empty() {
            let first_h = verified_headers[0].0;
            let first_k = vc.confirmations_on(first_h);
            return VerificationResult {
                outcome: Outcome::Unverifiable,
                step: 9,
                mode,
                block_height_h: Some(first_h),
                block_time_rwcp: None,
                confirmations: first_k,
                mtp_bip113: None,
                fmtp_5: None,
                fmtp_6: None,
                fmtp_11: None,
                mismatched_branches: mismatched_count,
            };
        }
        confirmed.remove(0)
    } else {
        let (first_h, ref first_hdr) = verified_headers[0];
        match vc.confirmations_on(first_h) {
            Some(k) if k >= effective_min_conf => (first_h, first_hdr.clone(), k),
            other => {
                return VerificationResult {
                    outcome: Outcome::Unverifiable,
                    step: 9,
                    mode,
                    block_height_h: Some(first_h),
                    block_time_rwcp: None,
                    confirmations: other,
                    mtp_bip113: None,
                    fmtp_5: None,
                    fmtp_6: None,
                    fmtp_11: None,
                    mismatched_branches: mismatched_count,
                };
            }
        }
    };

    let mtp = vc.median_time_past(best_h);
    let fmtp_5 = vc.forward_mtp_5(best_h);
    let fmtp_6 = vc.forward_mtp_6(best_h);
    let fmtp_11 = vc.forward_mtp_11(best_h);

    VerificationResult {
        outcome: Outcome::Valid,
        step: 11,
        mode,
        block_height_h: Some(best_h),
        block_time_rwcp: Some(best_hdr.ntime),
        confirmations: Some(best_k),
        mtp_bip113: mtp,
        fmtp_5,
        fmtp_6,
        fmtp_11,
        mismatched_branches: mismatched_count,
    }
}
