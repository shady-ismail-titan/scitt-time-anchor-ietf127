# Multi-Vendor Real-World Interoperability Report (`draft-fassbender-scitt-time-anchor-08`)

## 1. Participating Implementations Executed Live (`7` External Organizations + Clean-Room Triple Engine)

| # | Organization / Author | Implementation / Artifact | Target Spec | Execution Runtime |
|---|---|---|---|---|
| 1 | **Umarise** (Jonna Fassbender) | `verify-anchoring.org` (`opentimestamps.min.js`, 1.59 MB) + `umarise==1.0.0` PyPI | `-08` Reference | Node V8 + Python 3 |
| 2 | **OpenTimestamps JS** | `javascript-opentimestamps` (`npm opentimestamps`) | OTS Wire v1 | Node V8 |
| 3 | **OpenTimestamps Python** (Peter Todd) | `python-opentimestamps==0.5.0` + `python-bitcoinlib==0.12.2` | OTS Wire v1 | Python 3 |
| 4 | **EMILIA Protocol** | `emiliaprotocol/scitt-time-anchor-verifier` (`v0.1.0`, commit `6ea9afb`) | `-06` Clean-Room | Python 3 |
| 5 | **CryptoGeekPT** (Tiago Pinto) | `interop-fassbender-scitt-time-anchor-03` (`verify.py` + Mainnet proofs) | `-03` Clean-Room | Python 3 |
| 6 | **DPS / Laurent Lemonnier** | `dps-scitt-decision-layer/interop/umarise/verify_anchor.py` | `-08` Clean-Room | Python 3 |
| 7 | **SCITT COSE Envelope Fixtures** (`WEXP` + `iSoluce`) | `wexp-interop` (`scitt-receipt-boundary-001`) + live `ts.isoluce.net/checkpoint` (`pycose 1.1.0` / `cbor2 5.9.0`) | Section 6 `COSE_Sign1` Header `394` (`RFC 9942` / `RFC 9864`) | Python 3 |
| 8 | **This Clean-Room Suite** | Triple-Engine Verifier (`Python` + `#![forbid(unsafe_code)]` `Rust` + `112.0 KB` / `44.7 KB gzip` `WASM`) | `-08` & Candidate `-09` `strict` | Python + Native + V8 WASM |

> **Methodology & Target-Revision Fairness Note:**
> - **Target Draft Evolution (`-03`, `-06`, `-08`, Candidate `-09`):** `CryptoGeekPT` targets `draft-fassbender-scitt-time-anchor-03` and `EMILIA Protocol` targets `-06`, whereas `Umarise`, `DPS / Lemonnier`, and `--mode draft08` target `-08`. Differences on newer tightening rules reflect specification evolution across draft revisions rather than defects in earlier clean-room implementations.
> - **Outcome Terminology (`draft-08` Section 4.1):** `valid` means cryptographic and chain confirmation checks succeeded at Step 11; `unverifiable` means no branch verified against the supplied chain slice while at least one branch remained unevaluated or lacked confirmations (e.g., pending calendar attestations, heights outside the supplied header window, or skipped non-SHA-256 branch ops in `-08`); `invalid` means deterministic wire-format, digest, or profile violation (Steps 2, 3, or 8 with zero unevaluated branches).
> - **Envelope Scope:** Row #7 (`WEXP` + `iSoluce`) evaluates Section 6 SCITT `COSE_Sign1` unprotected header `394` relay invariance rather than `.ots` binary deserialization.

## 2. Empirical `16 x 8` Cross-Implementation Conformance & Divergence Matrix

| Vector | Umarise Web / `npm` JS | `python-ots` `0.5.0` | EMILIA (`-06`) | CryptoGeekPT (`-03`) | DPS Lemonnier (`-08`) | Clean-Room `draft08` | Clean-Room `strict` (`-09`) |
|---|---|---|---|---|---|---|---|
| `V01_APPENDIX_D5_MAINNET_957289` | `H=957289` | `H=957289` | `valid (H=957289)` | `valid (H=957289)` | `valid (H=957289)` | `valid (s11)` | `valid (s11)` |
| `V02_APPENDIX_D7_EXPLORER_NO_CHAIN` | `H=957289` | `H=957289` | `unverifiable (no verified branch and at least one branch was unevaluated)` | `unverifiable (step 7)` | `unverifiable` | `unverifiable (s8)` | `unverifiable (s8)` |
| `V03_CRYPTOGEEK_WILD_960175` | `H=960175 (+1)` | `H=960175 (+1)` | `valid (H=960175)` | `valid (H=960175)` | `valid (H=960175)` | `valid (s11)` | `valid (s11)` |
| `V04_CRYPTOGEEK_SHA256SUMS_960468` | `H=960468` | `H=960468` | `valid (H=960468)` | `valid (H=960468)` | `valid (H=960468)` | `valid (s11)` | `valid (s11)` |
| `V05_EMILIA_CROSSCHECK_MULTI_968588_968635` | `H=968588 (+5)` | `PARSE_ERR` | `valid (H=968588)` | `valid (H=968588)` | `valid (H=968588)` | `valid (s11)` | `valid (s11)` |
| `V06_ADAPTER_ANCHOR_968752` | `H=968752 (+2)` | `H=968752 (+2)` | `valid (H=968752)` | `valid (H=968752)` | `valid (H=968752)` | `valid (s11)` | `valid (s11)` |
| `V07_UPSTREAM_OTS_HELLO_WORLD_358391` | `H=358391` | `H=358391` | `unverifiable (no verified branch and at least one branch was unevaluated)` | `unverifiable (step 8)` | `unverifiable` | `unverifiable (s8)` | `invalid (s3)` |
| `V08_UPSTREAM_OTS_PENDING_ONLY` | `pending (1)` | `pending (1)` | `unverifiable (proof carries no Bitcoin attestation)` | `unverifiable (step 4)` | `unverifiable` | `unverifiable (s4)` | `unverifiable (s4)` |
| `V09_Z3_SPLIT_BRAIN_MAINNET_957289` | `H=957289` | `PARSE_ERR` | `unverifiable (no verified branch and at least one branch was unevaluated)` | `unverifiable (step 7)` | `unverifiable` | `unverifiable (s8)` | `invalid (s3)` |
| `V10_Z3_SPLIT_BRAIN_80F0B380800A` | `H=850000` | `PARSE_ERR` | `unverifiable (no verified branch and at least one branch was unevaluated)` | `unverifiable (step 7)` | `unverifiable` | `unverifiable (s8)` | `invalid (s3)` |
| `V11_OVERLONG_LEB128_E9B6BA00` | `H=957289` | `H=957289` | `valid (H=957289)` | `valid (H=957289)` | `valid (H=957289)` | `valid (s11)` | `invalid (s3)` |
| `V12_KECCAK_HEADER_0X67_BYPASS` | `PARSE_ERR` | `PARSE_ERR` | `invalid (OTS proof initial hash operation is not sha256)` | `valid (H=957289)` | `invalid` | `invalid (s3)` | `invalid (s3)` |
| `V13_HEXLIFY_30_AMPLIFICATION_65B` | `PARSE_ERR` | `PARSE_ERR` | `invalid (OTS proof failed to parse)` | `unverifiable (step 8)` | `unverifiable` | `unverifiable (s8)` | `invalid (s3)` |
| `V14_MIDPATH_OPSHA1_NARROW_PIPE` | `H=957289 (+1)` | `H=957289 (+1)` | `valid (H=957289)` | `valid (H=957289)` | `valid (H=957289)` | `valid (s11)` | `invalid (s3)` |
| `V15_EMPTY_BTC_PAYLOAD_AND_TRAILING_BYTES` | `H=957289` | `PARSE_ERR` | `invalid (OTS proof failed to parse)` | `invalid (step 3)` | `valid (H=957289)` | `invalid (s3)` | `invalid (s3)` |
| `V16_DEEP_4096_OPS_STACK_STRESS` | `PARSE_ERR` | `PARSE_ERR` | `invalid (OTS proof failed to parse)` | `invalid (step 3)` | `invalid` | `invalid (s8)` | `invalid (s3)` |

## 3. Key Real-World Interoperability & Conformance Findings

1. **100% Positive Mainnet Interop Across Post-2016 `OP_RETURN` Proofs (`V01`, `V03`--`V06`) & Legacy 2015 P2PKH Discovery (`V07`)**:
   - Official `Appendix D.5` (`Block 957289`), `CryptoGeekPT` wild proofs (`Blocks 960175`, `960468`), `EMILIA + CryptoGeekPT` dual-calendar proof (`Blocks 968588 & 968635`), and `SHA256SUMS-adapter` (`Block 968752`) verify as **`valid`** with identical heights and `RWCP` `nTime` values across EMILIA, CryptoGeekPT, DPS, and both `draft08` and `strict` profiles of our Triple Engine.
   - By contrast, upstream OpenTimestamps' historical 2015 `hello-world.txt.ots` (`V07`, `Block 358391`) begins its branch with `OtsOp(tag=0x03, OpRIPEMD160)` from a legacy P2PKH script commitment: all `-03`/`-06`/`-08` verifiers classify the branch as unevaluated (`unverifiable` at Step 8), while `--mode strict` rejects the 160-bit digest downgrade at Step 3 (`invalid`), providing a real-world Mainnet witness for Section 3.3 opcode filtering.
2. **Live Cross-Language LEB128 Split-Brain (`V09` `e9b6ba808008` & `V10` `80f0b380800a`)**:
   - On `V09` (`e9b6ba808008`), Umarise's `verify-anchoring.org` bundle (`opentimestamps.min.js`) and `npm opentimestamps` decode **real Bitcoin Mainnet Block `957289`** due to ECMAScript `<<` masking shift counts modulo 32 (`35 & 31 == 3`, `8 << 3 == 64`, already set in `957289`), whereas `python-opentimestamps` rejects and EMILIA, CryptoGeekPT, DPS, and `draft08` decode height **`274,878,864,233`** (`unverifiable`). Candidate `-09` `strict` deterministically rejects non-canonical or `> 5`-byte varuints (`invalid`, Step 3).
3. **Overlong LEB128 & Trailing Attestation Payload Bytes (`V11` & `V15`)**:
   - Overlong `e9b6ba00` (`V11`) is accepted as **`valid (H=957289)`** by EMILIA (`-06`), CryptoGeekPT (`-03`), and DPS (`-08`). On `V15` (`e9b63adeadbeef`), Umarise Web / `npm` JS and DPS (`verify_anchor.py:180`) read the varint prefix without checking payload end-of-slice and return **`H=957289` / `valid (H=957289)`**, and DPS raises an uncaught `ValueError: truncated` when given a zero-length Bitcoin attestation payload.
4. **File Hash Opcode Check Omission (`V12`) & `SetCompact` Sign-Bit Witness (`0x1dfbffff`)**:
   - On `V12` (`file_hash_op = 0x67` `Keccak-256` with a 32-byte SHA-256 digest), CryptoGeekPT (`verify.py:51-55`) omits checking `parsed.hash_op == 'sha256'` and returns **`valid (H=957289)`**, whereas EMILIA, DPS, and our Triple Engine return **`invalid (Step 3)`**.
   - Independently, DPS (`verify_anchor.py:123`) implements `mant = bits & 0xFFFFFF` rather than Bitcoin Core `SetCompact`'s signed 23-bit mantissa mask (`0x007FFFFF`), empirically confirming our Z3 `0x1dfbffff` sign-bit divergence witness in live IETF 127 interop code.
5. **Resource Amplification & Recursive Stack Overflow (`V13` & `V16`)**:
   - On `V13` (`30` `0xf3` `OpHexlify` ops), EMILIA returns `invalid` at Step 3 while CryptoGeekPT and DPS return `unverifiable` at Step 8.
   - On `V16` (`4,096` `0x08` `OpSHA256` ops, `4,174` B), recursive Python parsers (`python-opentimestamps` and EMILIA) raise **`RecursionError`**, whereas our iterative `O(1)`-stack Rust/WASM/Python parser processes `4,096` ops with zero stack growth (and `strict` caps branch ops at `128`).
6. **Live SCITT `COSE_Sign1` Ecosystem Interop (`WEXP` & `Action State / iSoluce`)**:
   - `iSoluce` (`https://ts.isoluce.net/checkpoint`, `219` B) uses `RFC 9864` fully-specified `Ed25519` (`alg = -19`), causing `pycose==1.1.0` to fail (`CoseException: Unknown COSE attribute with value: [CoseAlgorithm - -19]`) while parsing cleanly in `cbor2` and our zero-dependency CBOR parser.
   - `WEXP` (`scitt-receipt-boundary-001/signed-statement.cose`, `836` B + `receipt.cbor`, `667` B) demonstrates that adding/relaying unprotected headers (`394`, `395`) changes outer `SHA-256(COSE_Sign1)` while our `RFC 9921 §3.1.1 / RFC 9942` imprint remains 100% invariant.
