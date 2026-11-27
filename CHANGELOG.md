# Changelog

All notable changes to this project are documented in this file.

## [2.0.0] - 2026-11-27

### Added
- **Bitcoin Mainnet Consensus Target, Retarget & Checkpoint Enforcement (`--mode strict`)**:
  - Added Mainnet `powLimit` (`0x1d00ffff`), post-BIP113 (`h >= 419,328`) maximum target ceiling (`0x181fffff`), mid-epoch target immutability, `4x` / `0.25x` `2016`-block retarget clamping, and exact `CalculateNextWorkRequired` (`target_to_compact_exact` / `GetCompact`) verification (`N17A`–`N18B`, Z3 Finding #8).
  - Verified Bitcoin Mainnet Genesis (height `0`) and canonical consensus milestone checkpoints (`210,000`, `419,328`, `481,824`, `630,000`, `709,632`, `840,000`) whenever present in Mainnet `ValidatedHeaderChain` (`N32`).
- **64-Variant CBOR Framing-Space Study (`verification_suite/experiment_cbor_framing_space_64.py`)**:
  - Empirical `2^6 = 64` variant study modeled on `draft-templeman-scitt-framing-space-01`, verifying `64/64` unique outer SHA-256 hashes, `1/64` acceptance under `v2.0.0 --mode strict` (`63/64` rejected), `100%` `scitt_ots_ctt` relay invariance, and `0` triple-engine divergences (`cbor_framing_space_64_report.json`, `CBOR_FRAMING_SPACE_64_STUDY.md`).
- **17-Gate Supply-Chain, Security & Scientific Reproducibility Hardening**:
  - Full canonical Apache-2.0 `LICENSE` & `LICENSES/Apache-2.0.txt`, FSFE REUSE 3.3 (`REUSE.toml`, `reuse.yml`), `SECURITY.md` (RFC 9116 Safe Harbor VDP), `THREAT_MODEL.md`, `CONTRIBUTING.md` (IETF RFC 8179), `CODE_OF_CONDUCT.md` (IETF RFC 7154 & Contributor Covenant 2.1), `CITATION.cff`, CodeMeta v3.0 `codemeta.json`, ACM/JOSS `REPRODUCIBILITY.md`, OWASP CycloneDX 1.5 `sbom.cdx.json`, OpenVEX v0.2.0 `openvex.json`, OpenSSF OSPS Baseline `v2026.08.28` `osps-baseline.json`, `.github/dependabot.yml`, OpenSSF Scorecard (`scorecard.yml`), 100% commit-SHA-pinned workflows, OpenSSF Gold reproducible WASM double-build + artifact forensics + anti-obfuscation + cross-manifest version parity CI gates, and SLSA v1 tag-release provenance (`release.yml`).
- **Strict RFC 8259 + I-JSON Parser Parity (`N19`) & Deterministic CBOR `COSE_Sign1` Protected Header Check (`N20`)**:
  - Synchronized strict JSONL parsing across Python, native Rust, and WebAssembly (`{"error": "bad_json"}`) and RFC 8949 Section 4.2 deterministic encoding on non-empty `protected_hdr` bytes.
- **Expanded Conformance, Fuzz & Leak Suites**:
  - Expanded conformance suite from `96` to `131` cases (`N17A`–`N34`) verified identically across Python, Native Rust, and Offline WebAssembly; `11/11` Z3 SMT theorems; `120,000` single-instance WASM calls (`0` B steady-state heap delta).
- **Reproducible Packaging & Upgraded Offline Browser WASM Lab (`web/`)**:
  - Added PEP 621 `pyproject.toml`, `--version` CLI flags, interactive `Mode: draft08` vs `Mode: strict (v2.0)` selector, step-by-step verdict trace banner, consensus telemetry panel, strict zero-egress CSP (`connect-src 'none'`), and 9 live verification presets.

### Fixed (All 8 Confirmed Python / Rust / WASM Divergences Eliminated -> 0/8)
- **DIV-1 (RFC 8259 Section 2 JSON Whitespace Parity)**: Restricted `skip_ws()` in `scitt_time_anchor_rs/src/json_min.rs` and line trimming in `main.rs`, `wasm_api.rs`, and `cli.py` to the four RFC 8259 whitespace bytes (`0x20`, `0x09`, `0x0a`, `0x0d`), rejecting form-feed (`0x0c`) identically across all three engines (`N21`).
- **DIV-2A & DIV-2B (RFC 4648 Section 3.5 Base64 Parity)**: Updated `decode_base64` (`sha256.rs`) and `_decode_b64_exact` (`cli.py`) to strip only RFC whitespace (` \t\r\n`), reject mid-stream `=` padding (`"AA==AA=="`), and reject non-zero trailing padding bits (`"AB=="`, `"AAB="`) (`N22`, `N23`).
- **DIV-3 (Canonical Block Height Keys)**: Restricted `headers_hex` keys in both `engine.rs` and `cli.py` / `bitcoin_chain.py` to canonical unsigned decimal ASCII (`"0"` or `[1-9][0-9]*` `<= u64::MAX`), rejecting leading `"+"`, leading zeros (`"01"`), negatives, and overflow (`N24`).
- **DIV-4 (Fail-Closed `min_chainwork_hex` in `strict`)**: Rejected non-null, non-string `min_chainwork_hex` values (integers, booleans, arrays, objects) in `engine.rs` and `bitcoin_chain.py`, matching `cli.py` (`N25`).
- **DIV-5 (`verify_rfc6962_batch_prefix` Sync)**: Synchronized `scitt_time_anchor_py/scitt_time_anchor/ots_parser.py` 100% with `scitt_time_anchor_rs/src/ots.rs` (`N26`).
- **DIV-6 (CBOR Semantic Duplicate Map Key Rejection)**: Updated `cbor.rs` to detect and reject duplicate semantic CBOR map keys (`{0x01: v1, 0x18 0x01: v2}`) in both `draft08` and `strict` profiles (`N27`).
- **DIV-7 (`extract_embedded_receipts` Precedence & Ambiguity Guard)**: Aligned Rust `cbor.rs` with Python's `394`-over-`"scitt_receipt"` priority in `draft08`, and rejected simultaneous `394` + `"scitt_receipt"` headers as ambiguous in `strict` across both Python and Rust (`N28`).

### Security & DoS Hardening (All 6 Hardening Targets Closed)
- **SEC-1 (6-Confirmation Floor in `--mode strict`)**: Enforced `effective_min_conf = max(min_confirmations, 6)` in `verifier.py` and `verifier.rs` (`N29`).
- **SEC-2 (RFC 9052 Section 3 Empty Protected Header)**: Rejected `COSE_Sign1` envelopes encoding an empty protected header as `b"\xa0"` instead of canonical zero-length `b""` in `--mode strict` (`N30`).
- **SEC-3 (CBOR ProofBundle Integer Key 4 Validation)**: Enforced `Text` (`origin_id`) typing on integer key `4` in `parse_proof_bundle_cbor` across Python and Rust (`N31`).
- **SEC-5 (`O(N)` UTF-8 JSON String Parsing)**: Replaced `O(N^2)` tail UTF-8 rescanning in `json_min.rs` with `O(1)`-per-scalar lead-byte width slicing, cutting 50 KB non-ASCII JSON parse latency from ~190–288 ms to `< 1 ms` (`N33A`).
- **SEC-CLI-LINE (Bounded 4 MiB JSONL Line Cap)**: Enforced `MAX_JSON_LINE_BYTES = 4_194_304` with bounded streaming line readers in both `cli.py` and `main.rs` (`N33B`).
- **SEC-6 (Linear-Time Shared-Prefix OTS DAG Evaluator & Total-Ops Cap)**: Replaced per-branch op-stack cloning and redundant replay with a topological shared-prefix DAG evaluator (`ots_deserialize_dag` / `eval_branch_digests`) plus hard total-operation caps (`DRAFT08_MAX_TOTAL_OPS = 16_384`, `STRICT_MAX_TOTAL_OPS = 1_024`), eliminating the 4,090×256 `0xFF` prefix-amplification bomb (`N34`).
- **SEC-WASM-DISSECT (WASM Dissector Explosion Cap)**: Enforced `MAX_DISSECT_SPANS = 2048` and `MAX_DISSECT_BRANCHES = 256` inside `wasm_api.rs::Dissector`.

### Changed
- Maintained `--mode draft08` as the backward-compatible default CLI profile.
- Rebuilt `web/scitt_time_anchor.wasm` with bit-for-bit reproducible `SOURCE_DATE_EPOCH` + `--remap-path-prefix` flags and regenerated `web/wasm_bundle.js` and `web/presets.js`.

## [1.0.0] - 2026-11-15

### Added
- Initial IETF 127 Hackathon clean-room release (`c647959`) targeting `draft-fassbender-scitt-time-anchor-08`:
  - Pure Python 3 standard-library verifier (`scitt_time_anchor_py`), safe `#![forbid(unsafe_code)]` Rust verifier (`scitt_time_anchor_rs`), and zero-import `wasm32-unknown-unknown` build.
  - `96`-case Appendix D.1–D.7 conformance + Z3 witness suite, `10` Z3 SMT theorems (`7` protocol findings + `3` soundness proofs), `50,000`-vector triple-engine differential suite, and `100,000`-mutation fuzz suite.
  - `16 × 8` cross-organization interoperability matrix across 7 external implementations (`MULTI_VENDOR_INTEROP_REPORT.md`).
  - Illustrative non-normative `-09` feedback diff (`draft09_patch/draft-fassbender-scitt-time-anchor-09-proposed.diff`) and wire-hex negative vectors `N9`–`N16`.
