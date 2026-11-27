#![forbid(unsafe_code)]

pub mod bitcoin;
pub mod cbor;
pub mod engine;
pub mod json_min;
pub mod ots;
pub mod sha256;
pub mod verifier;
pub mod wasm_api;

#[cfg(test)]
mod tests {
    use super::bitcoin::{block_work_from_target, set_compact_exact, U256};
    use super::ots::{
        batch_merkle_root, decode_varuint_js_toint32, decode_varuint_py_unbounded, read_varuint,
    };
    use super::sha256::{decode_hex, hex_lower, sha256};

    #[test]
    fn test_appendix_d1_d2_merkle_root() {
        let specs = [
            (
                "draft-fassbender-scitt-time-anchor-03 vector 1",
                "a183f624efbbda7d6208b9b5a6f9b0c2c95d90382eb209c44a1131954071f30b",
                "14ed82e243f4aff3f1794e6754bfae3b",
                "aafc3638a4795c8553b974d36c66aee2a7268ede5535a015fbcc73d01a3b8d52",
            ),
            (
                "draft-fassbender-scitt-time-anchor-03 vector 2",
                "0df073a986e5e5141c96ec32303b8552ded255e4404d0aff996936a846b48cff",
                "b0de8a5526115745c2801d65397db556",
                "7306ab5d2290e681f11699730c07e11a6b7b0b4babe30349f3c74d37ba100728",
            ),
            (
                "draft-fassbender-scitt-time-anchor-03 vector 3",
                "d82bf84f17057c0e3d7aa6f249dfc2e80a877b910ce4ce14dc40e653fd5be40b",
                "f6518213abf9ba8a92c3cb3bcdb82355",
                "d051a6258f904499056f475bfb69eea50a5018bf58144d25121bf5de22fab9dc",
            ),
            (
                "draft-fassbender-scitt-time-anchor-03 vector 4",
                "94a86d117047f2af9a2f5635d0c530cc85fc23d20f5d4b42926b94abee7a06ec",
                "2fb8ccfdfb881b481695a37deeced8e6",
                "8864a03154f5dae2ca5f77aab02ad7fa4ab56129dd1fbe2e2eb2615a5208413d",
            ),
        ];

        let mut leaves = [[0u8; 32]; 4];
        for (i, (art, exp_hash, nonce_hex, exp_leaf)) in specs.iter().enumerate() {
            let h = sha256(art.as_bytes());
            assert_eq!(hex_lower(&h), *exp_hash);
            let nonce = decode_hex(nonce_hex).unwrap();
            let mut combined = Vec::with_capacity(48);
            combined.extend_from_slice(&h);
            combined.extend_from_slice(&nonce);
            let leaf = sha256(&combined);
            assert_eq!(hex_lower(&leaf), *exp_leaf);
            leaves[i] = leaf;
        }

        let root = batch_merkle_root(&leaves).unwrap();
        assert_eq!(
            hex_lower(&root),
            "b4d19ae256a6c3bceb27d1a31fbb3dd3e4574616ebe99a367d6ad7224b7e0749"
        );
    }

    #[test]
    fn test_leb128_split_brain_80f0b380800a() {
        let exploit = decode_hex("80f0b380800a").unwrap();
        let (h_js, end_js) = decode_varuint_js_toint32(&exploit, 0).unwrap();
        let (h_py, end_py) = decode_varuint_py_unbounded(&exploit, 0).unwrap();
        assert_eq!(end_js, 6);
        assert_eq!(end_py, 6);
        assert_eq!(h_js, 850_000);
        assert_eq!(h_py, 343_598_233_600);
        assert!(read_varuint(&exploit, 0, true).is_none());
        let overlong = decode_hex("e88700").unwrap();
        assert!(read_varuint(&overlong, 0, true).is_none());
        let canonical = decode_hex("d0f033").unwrap();
        assert_eq!(read_varuint(&canonical, 0, true), Some((850_000, 3)));
    }

    #[test]
    fn test_set_compact_sign_bit_and_work() {
        assert!(set_compact_exact(0x1dfb_ffff).is_none());
        let tgt_gen = set_compact_exact(0x1d00_ffff).unwrap();
        let w_gen = block_work_from_target(tgt_gen);
        assert_eq!(w_gen, U256::from_u64(0x1_0001_0001));
        let tgt_reg = set_compact_exact(0x207f_ffff).unwrap();
        let w_reg = block_work_from_target(tgt_reg);
        assert_eq!(w_reg, U256::from_u64(2));
    }

    #[test]
    fn test_iterative_max_depth_no_stack_overflow() {
        use super::ots::{
            ots_deserialize, VerifierMode, BITCOIN_ATTESTATION_TAG, DRAFT08_MAX_OPS_PER_BRANCH,
            OP_SHA256, OTS_MAGIC, TAG_ATTESTATION,
        };
        let mut raw = Vec::with_capacity(4800);
        raw.extend_from_slice(OTS_MAGIC);
        raw.push(0x01); // version 1
        raw.push(OP_SHA256);
        raw.extend_from_slice(&[0xaa; 32]);
        raw.resize(raw.len() + DRAFT08_MAX_OPS_PER_BRANCH, OP_SHA256);
        raw.push(TAG_ATTESTATION);
        raw.extend_from_slice(&BITCOIN_ATTESTATION_TAG);
        raw.extend_from_slice(&[0x03, 0xd0, 0xf0, 0x33]); // varbytes(d0f033 => 850000)

        let parsed =
            ots_deserialize(&raw, VerifierMode::Draft08).expect("4096-op proof must parse");
        assert_eq!(parsed.branches.len(), 1);
        assert_eq!(parsed.branches[0].ops.len(), DRAFT08_MAX_OPS_PER_BRANCH);

        // Exceeding 4608 depth (5000 unary ops) returns None cleanly with O(1) call stack
        let mut deep = Vec::with_capacity(5100);
        deep.extend_from_slice(OTS_MAGIC);
        deep.push(0x01);
        deep.push(OP_SHA256);
        deep.extend_from_slice(&[0xaa; 32]);
        deep.resize(deep.len() + 5000, OP_SHA256);
        deep.push(TAG_ATTESTATION);
        deep.extend_from_slice(&BITCOIN_ATTESTATION_TAG);
        deep.extend_from_slice(&[0x03, 0xd0, 0xf0, 0x33]);
        assert!(ots_deserialize(&deep, VerifierMode::Draft08).is_none());
    }

    #[test]
    fn test_compact_roundtrip_and_json_determinism() {
        use super::bitcoin::{
            calculate_next_work_required, mainnet_pow_limit, target_to_compact_exact,
        };
        use super::json_min::{parse_json_object, MAX_JSON_DEPTH};

        for nb in [0x1d00_ffffu32, 0x1702_1a42u32, 0x1816_86f5u32, 0x207f_ffffu32] {
            let tgt = set_compact_exact(nb).unwrap();
            assert_eq!(target_to_compact_exact(tgt), nb);
        }
        let next_nb = calculate_next_work_required(
            mainnet_pow_limit(),
            1_000_000,
            1_000_000 + 1_209_600,
            mainnet_pow_limit(),
        );
        assert_eq!(next_nb, 0x1d00_ffff);

        // Duplicate JSON keys rejected cleanly
        assert!(parse_json_object("{\"a\":1,\"a\":2}").is_none());
        // Over-i64 integer rejected cleanly
        assert!(parse_json_object("{\"big\":9223372036854775808}").is_none());
        // Multi-byte UTF-8 and valid surrogate pair decoded without mangling
        let m = parse_json_object("{\"id\":\"ok-✓-\\uD83D\\uDE00\"}").unwrap();
        assert_eq!(m.get("id").and_then(|v| v.as_str()), Some("ok-✓-😀"));
        // Lone surrogate rejected
        assert!(parse_json_object("{\"id\":\"\\uD800\"}").is_none());
        // Depth > MAX_JSON_DEPTH rejected cleanly
        let deep_json = format!(
            "{}1{}",
            "{\"a\":".repeat(MAX_JSON_DEPTH + 1),
            "}".repeat(MAX_JSON_DEPTH + 1)
        );
        assert!(parse_json_object(&deep_json).is_none());
        // DIV-1: RFC 8259 rejects form-feed (0x0c) as JSON whitespace
        assert!(parse_json_object("{\x0c\"id\":\"x\"}").is_none());
    }

    #[test]
    fn test_v3_security_and_parity_invariants() {
        use super::bitcoin::{
            ChainBuildOptions, ValidatedHeaderChain, BITCOIN_MAINNET_GENESIS_HEX, U256,
        };
        use super::cbor::{
            compute_scitt_ots_tbs_bytes, decode_cbor, encode_cbor_bytes, encode_cbor_text,
            extract_embedded_receipts, parse_cose_sign1_statement, parse_proof_bundle_cbor,
        };
        use super::engine::evaluate_line;
        use super::json_min::parse_json_object;
        use super::ots::{
            ots_deserialize_dag, VerifierMode, BITCOIN_ATTESTATION_TAG, DRAFT08_MAX_TOTAL_OPS,
            HARDENED_MAX_RUNNING_BYTES, OP_SHA256, OTS_MAGIC, STRICT_MAX_TOTAL_OPS,
            TAG_ATTESTATION, TAG_BRANCH,
        };
        use super::sha256::decode_base64;
        use std::collections::BTreeMap;

        // DIV-2: Base64 rejects form-feed, mid-stream padding, and RFC 4648 §3.5 non-zero trailing bits
        assert!(decode_base64("AA==\x0c").is_none());
        assert!(decode_base64("AA==AA==").is_none());
        assert!(decode_base64("AB==").is_none());
        assert!(decode_base64("AAB=").is_none());
        assert_eq!(decode_base64("AA=="), Some(vec![0u8]));

        // DIV-6: Semantic duplicate CBOR map key {0x01: 1, 0x18 0x01: 2} rejected in BOTH modes
        let sem_dup = [0xa2, 0x01, 0x01, 0x18, 0x01, 0x02];
        assert!(decode_cbor(&sem_dup, false).is_none());
        assert!(decode_cbor(&sem_dup, true).is_none());

        // SEC-2: COSE_Sign1 with protected_hdr = b"\xa0" rejected in strict, accepted in draft08
        let mut cose_a0 = vec![0xd2, 0x84];
        cose_a0.extend_from_slice(&encode_cbor_bytes(&[0xa0])); // protected = b"\xa0"
        cose_a0.push(0xa0); // unprotected = {}
        cose_a0.extend_from_slice(&encode_cbor_bytes(b"msg"));
        cose_a0.extend_from_slice(&encode_cbor_bytes(&[0x55; 64]));
        assert!(parse_cose_sign1_statement(&cose_a0, false).is_some());
        assert!(parse_cose_sign1_statement(&cose_a0, true).is_none());

        // DIV-7: Unprotected header with both 394 and "scitt_receipt": 394 wins in draft08, rejected in strict
        let mut cose_both = vec![0xd2, 0x84];
        cose_both.extend_from_slice(&encode_cbor_bytes(&[])); // canonical empty protected
        cose_both.push(0xa2); // map(2): key "scitt_receipt" first, then 394
        cose_both.extend_from_slice(&encode_cbor_text("scitt_receipt"));
        cose_both.extend_from_slice(&encode_cbor_bytes(b"legacy-rcpt"));
        cose_both.extend_from_slice(&[0x19, 0x01, 0x8a]); // uint 394
        cose_both.extend_from_slice(&encode_cbor_bytes(b"rfc9942-rcpt"));
        cose_both.extend_from_slice(&encode_cbor_bytes(b"payload"));
        cose_both.extend_from_slice(&encode_cbor_bytes(&[0x55; 64]));
        let stmt_both = parse_cose_sign1_statement(&cose_both, false).unwrap();
        assert_eq!(
            extract_embedded_receipts(&stmt_both, false),
            Some(vec![b"rfc9942-rcpt".to_vec()])
        );
        assert!(extract_embedded_receipts(&stmt_both, true).is_none());
        assert!(compute_scitt_ots_tbs_bytes(&stmt_both, None, None, false, true).is_none());

        // SEC-3: CBOR ProofBundle integer key 4 validated as Text
        let mut pb_bad_k4 = vec![0xa3, 0x01];
        pb_bad_k4.extend_from_slice(&encode_cbor_bytes(b"ots"));
        pb_bad_k4.push(0x02);
        pb_bad_k4.extend_from_slice(&encode_cbor_bytes(&[0x11; 32]));
        pb_bad_k4.extend_from_slice(&[0x04, 0x18, 0x2a]); // key 4 => uint 42 (invalid!)
        assert!(parse_proof_bundle_cbor(&pb_bad_k4, true).is_none());
        assert!(parse_proof_bundle_cbor(&pb_bad_k4, false).is_none());

        // SEC-4: Forged height-0 header on Bitcoin Mainnet rejected
        let mut hdr_map = BTreeMap::new();
        hdr_map.insert(0u64, vec![0u8; 80]);
        assert!(ValidatedHeaderChain::build_with_options(
            hdr_map,
            ChainBuildOptions {
                ledger_id: BITCOIN_MAINNET_GENESIS_HEX.to_string(),
                verify_pow_and_links: true,
                allow_sparse_checkpoints: false,
                enforce_retarget_4x_bound: false,
                enforce_consensus_targets: false,
                min_chainwork: U256::ZERO,
            }
        )
        .is_none());

        // SEC-5: 50KB non-ASCII UTF-8 string parses linearly
        let big_utf8 = format!("{{\"id\":\"{}\"}}", "é".repeat(25_000));
        let parsed_utf8 = parse_json_object(&big_utf8).unwrap();
        assert_eq!(
            parsed_utf8.get("id").and_then(|v| v.as_str()).map(|s| s.len()),
            Some(50_000)
        );

        // SEC-6: 4,090 shared SHA256 + 256 branches evaluates in O(4,346) ops & total-op caps enforced
        let mut amp = Vec::with_capacity(9000);
        amp.extend_from_slice(OTS_MAGIC);
        amp.extend_from_slice(&[0x01, OP_SHA256]);
        amp.extend_from_slice(&[0xab; 32]);
        amp.resize(amp.len() + 4090, OP_SHA256);
        for i in 0..256 {
            if i < 255 {
                amp.push(TAG_BRANCH);
            }
            amp.push(OP_SHA256);
            amp.push(TAG_ATTESTATION);
            amp.extend_from_slice(&BITCOIN_ATTESTATION_TAG);
            amp.extend_from_slice(&[0x03, 0xd0, 0xf0, 0x33]);
        }
        let dag = ots_deserialize_dag(&amp, VerifierMode::Draft08).unwrap();
        assert_eq!(dag.nodes.len(), 4090 + 256);
        assert_eq!(dag.branches.len(), 256);
        let digests = dag.eval_branch_digests(&[0xab; 32], HARDENED_MAX_RUNNING_BYTES);
        assert_eq!(digests.len(), 256);
        assert!(digests.iter().all(|d| d.is_some()));

        // Exceeding STRICT_MAX_TOTAL_OPS (1024) with 16 branches * 70 ops = 1120 ops rejected in strict
        let mut over_strict = Vec::new();
        over_strict.extend_from_slice(OTS_MAGIC);
        over_strict.extend_from_slice(&[0x01, OP_SHA256]);
        over_strict.extend_from_slice(&[0xcd; 32]);
        for i in 0..16 {
            if i < 15 {
                over_strict.push(TAG_BRANCH);
            }
            over_strict.resize(over_strict.len() + 70, OP_SHA256);
            over_strict.push(TAG_ATTESTATION);
            over_strict.extend_from_slice(&BITCOIN_ATTESTATION_TAG);
            over_strict.extend_from_slice(&[0x03, 0xd0, 0xf0, 0x33]);
        }
        let over_strict_dag = ots_deserialize_dag(&over_strict, VerifierMode::Draft08).unwrap();
        assert_eq!(over_strict_dag.nodes.len(), 16 * 70);
        assert!(over_strict_dag.nodes.len() > STRICT_MAX_TOTAL_OPS);
        assert!(over_strict_dag.nodes.len() <= DRAFT08_MAX_TOTAL_OPS);
        assert!(ots_deserialize_dag(&over_strict, VerifierMode::Strict).is_none());

        // DIV-3 & DIV-4: Non-canonical height keys and non-string min_chainwork_hex rejected
        use super::engine::build_chain_from_json_obj;
        let bad_h_obj = parse_json_object("{\"headers_hex\":{\"+1\":\"00\"}}").unwrap();
        assert!(build_chain_from_json_obj(&bad_h_obj, VerifierMode::Draft08).is_none());
        let bad_lz_obj = parse_json_object("{\"headers_hex\":{\"01\":\"00\"}}").unwrap();
        assert!(build_chain_from_json_obj(&bad_lz_obj, VerifierMode::Draft08).is_none());
        let bad_cw_obj =
            parse_json_object("{\"headers_hex\":{},\"min_chainwork_hex\":999}").unwrap();
        assert!(build_chain_from_json_obj(&bad_cw_obj, VerifierMode::Strict).is_none());
        let bad_h_resp = evaluate_line(
            "{\"id\":\"H\",\"artifact_b64\":\"AA==\",\"ots_b64\":\"AA==\",\"claimed_hash\":\"00\",\"candidate_store\":{\"source\":\"validated_node\",\"headers_hex\":{\"+1\":\"00\"}}}",
            VerifierMode::Draft08,
        );
        assert!(bad_h_resp.contains("\"outcome\": \"invalid\""));
    }
}
