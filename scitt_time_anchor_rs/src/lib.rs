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
}
