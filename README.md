# SCITT Time-Anchor Triple-Engine Verifier (`v2.0.0`)

[![CI](https://github.com/shady-ismail-titan/scitt-time-anchor-ietf127/actions/workflows/ci.yml/badge.svg)](https://github.com/shady-ismail-titan/scitt-time-anchor-ietf127/actions/workflows/ci.yml)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/17201/badge)](https://www.bestpractices.dev/projects/17201)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/shady-ismail-titan/scitt-time-anchor-ietf127/badge)](https://scorecard.dev/viewer/?uri=github.com/shady-ismail-titan/scitt-time-anchor-ietf127)
[![REUSE Compliance](https://github.com/shady-ismail-titan/scitt-time-anchor-ietf127/actions/workflows/reuse.yml/badge.svg)](https://api.reuse.software/info/github.com/shady-ismail-titan/scitt-time-anchor-ietf127)
[![SWH](https://archive.softwareheritage.org/badge/swh:1:snp:fbd4659cafd38bc3d3c2009a97a3006530446640/)](https://archive.softwareheritage.org/swh:1:snp:fbd4659cafd38bc3d3c2009a97a3006530446640)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://github.com/shady-ismail-titan/scitt-time-anchor-ietf127/blob/main/LICENSE)

**Zero-Backend Offline Browser WASM Lab:** [https://shady-ismail-titan.github.io/scitt-time-anchor-ietf127/](https://shady-ismail-titan.github.io/scitt-time-anchor-ietf127/)  
**Permanent UNESCO Software Heritage Snapshot:** [`swh:1:snp:fbd4659cafd38bc3d3c2009a97a3006530446640`](https://archive.softwareheritage.org/swh:1:snp:fbd4659cafd38bc3d3c2009a97a3006530446640)

> **Verification Scope Boundary:** `scitt-time-anchor` verifies Bitcoin-anchored temporal inclusion (`verification_scope: "temporal_anchor_only"`, `cose_signature_verified: false`). Cryptographic COSE signature verification is delegated to your SCITT verifier / Trust Store per [`THREAT_MODEL.md`](https://github.com/shady-ismail-titan/scitt-time-anchor-ietf127/blob/main/THREAT_MODEL.md).

Independent clean-room reference verifiers for `draft-fassbender-scitt-time-anchor-08` implemented in Python 3, safe Rust (`#![forbid(unsafe_code)]`), and offline WebAssembly (`wasm32-unknown-unknown`), paired with Z3 SMT invariant proofs, a 64-variant `draft-templeman-scitt-framing-space-01` CBOR framing-space empirical study, a reproducible multi-vendor interoperability harness, and non-normative implementer feedback for the IETF SCITT Working Group.

The baseline `--mode draft08` profile implements the exact 11-step `VERIFY-ANCHOR` algorithm as the default for backward compatibility with deployed OpenTimestamps v1 proofs. The opt-in `--mode strict` profile enforces Bitcoin Mainnet consensus target/retarget constraints, `min_confirmations >= 6`, RFC 8259 / I-JSON parsing parity, RFC 8949 / RFC 9052 Section 3 deterministic CBOR rules, and hardened OTS wire bounds.

## Architecture & Execution Targets

- **`scitt_time_anchor_py/` (`scitt-time-anchor` `2.0.0`)**: Pure Python 3 (`>= 3.10`) standard-library package with `0` runtime dependencies, PEP 621 packaging (`pyproject.toml`), and console entrypoint `scitt-time-anchor`.
- **`scitt_time_anchor_rs/` (`scitt_time_anchor_rs` `2.0.0`)**: Safe Rust CLI and library (`#![forbid(unsafe_code)]`, `0` external crate dependencies, zero Clippy warnings under `-D warnings`) using an explicit iterative `O(1)` call-stack work loop and exact 256-bit `U256` arithmetic.
- **`web/scitt_time_anchor.wasm` (`scitt_time_anchor_wasm` `2.0.0`)**: Zero-import offline `wasm32-unknown-unknown` build (`110,888` bytes raw / `48,147` bytes gzipped, `0` host imports, enforced under `Content-Security-Policy: connect-src 'none'`, bit-for-bit reproducible under `SOURCE_DATE_EPOCH`; SHA-256 recorded in [`VERIFICATION_MASTER_SUMMARY.json`](./VERIFICATION_MASTER_SUMMARY.json) and [`SHA256SUMS.txt`](./SHA256SUMS.txt)).
- **Two Verification Profiles (100% Backward-Compatible Default)**:
  - `--mode draft08` (default): Executes the baseline 11-step `VERIFY-ANCHOR` algorithm across Appendix D.1–D.7 and wild post-2016 Bitcoin `OP_RETURN` `.ots` proofs without breaking existing calendars or v1 receipts.
  - `--mode strict`: Opt-in hardened verification profile enforcing Mainnet consensus ceilings (`powLimit` `0x1d00ffff`, post-BIP113 `0x181fffff`, `2016`-block `4x` retarget clamping), `min_confirmations >= 6`, RFC 8259 / I-JSON JSONL parity, RFC 8949 deterministic CBOR and RFC 9052 Section 3 empty protected header rejection (`b"\xa0"`), canonical `<= 5`-octet `u32` LEB128 varuints, `{0x08, 0xf0, 0xf1}` opcode allowlists, `MAX_RUNNING_BYTES = 4096`, and `BIP-113` / `Forward-MTP(H+5)` temporal monotonicity.

## What Changed in `v2.0.0`

1. **Slide 4 Bitcoin Mainnet Consensus Target & Retarget Enforcement (`--mode strict`)**:
   - Rejects forged Mainnet headers exceeding `powLimit` (`0x1d00ffff`), enforces the post-BIP113 (`h >= 419,328`) maximum target ceiling (`0x181fffff`), enforces mid-epoch target immutability, clamps `2016`-block retarget boundaries to `[0.25x, 4x]`, and verifies exact Bitcoin Core `CalculateNextWorkRequired` (`GetCompact` / `SetCompact`) transitions (`N17A`–`N18B`, Z3 Finding #8).
2. **8 Cross-Engine Parity Fixes (`Python == Rust == WASM`)**:
   - Eliminated boundary divergences across all three engines for RFC 8259 / I-JSON (`N19`) strict JSONL ingestion, RFC 8949 deterministic CBOR decoding (`N20`), duplicate semantic CBOR map-key rejection, Base64/JSON whitespace and padding validation, `COSE_Sign1` envelope handling, and strict-mode error classification.
3. **6 Parser DoS & Consensus Hardenings**:
   - **`O(1)` UTF-8 Decoding:** Replaced quadratic string rescanning in the zero-dependency Rust JSON parser (`json_min.rs`) with single-pass `O(1)` UTF-8 decoding.
   - **Shared-Prefix OTS DAG Deduplication & Op Budgets:** Added shared-prefix DAG deduplication and aggregate operation caps to prevent exponential branching replay amplification.
   - **Bounded CLI / WASM I/O & Dissector Caps:** Enforced a hard `4 MiB` (`4,194,304` B) I/O cap across CLI and WASM inputs plus bounded span/branch limits in the WASM Byte-Ray dissector.
   - **Strict Confirmation Floor (`min_confirmations >= 6`):** Enforced a non-downgradeable 6-confirmation minimum floor in `--mode strict`.
   - **RFC 9052 Section 3 Protected Header Rejection:** Rejected empty CBOR map `b"\xa0"` inside `COSE_Sign1` protected header buckets where RFC 9052 Section 3 mandates zero-length `b""`.
   - **Zero-Warning Rust Static Lint Gate:** Enforced `cargo clippy --manifest-path scitt_time_anchor_rs/Cargo.toml --all-targets -- -D warnings` across all targets in CI.
4. **64-Variant `draft-templeman-scitt-framing-space-01` CBOR Framing-Space Empirical Study**:
   - Added `verification_suite/experiment_cbor_framing_space_64.py` exercising all 64 CBOR/COSE framing-space combinations across Python, Rust, and WebAssembly to document deterministic vs. malleable encoding behavior for the IETF SCITT Working Group.
5. **17-Gate Supply-Chain, Security & Scientific Reproducibility Hardening**:
   - Canonical SPDX Apache-2.0 [`LICENSE`](./LICENSE) & [`LICENSES/Apache-2.0.txt`](./LICENSES/Apache-2.0.txt), 100% FSFE REUSE 3.3 compliance ([`REUSE.toml`](./REUSE.toml), [`.github/workflows/reuse.yml`](./.github/workflows/reuse.yml)), [`SECURITY.md`](./SECURITY.md), [`THREAT_MODEL.md`](./THREAT_MODEL.md), [`CONTRIBUTING.md`](./CONTRIBUTING.md) (IETF RFC 8179), [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md) (IETF RFC 7154 & Contributor Covenant 2.1), [`CITATION.cff`](./CITATION.cff), CodeMeta v3.0 [`codemeta.json`](./codemeta.json), ACM/JOSS [`REPRODUCIBILITY.md`](./REPRODUCIBILITY.md), OWASP CycloneDX 1.5 [`sbom.cdx.json`](./sbom.cdx.json), OpenVEX v0.2.0 [`openvex.json`](./openvex.json), OpenSSF OSPS Baseline `v2026.08.28` [`osps-baseline.json`](./osps-baseline.json) (EU CRA & NIST SSDF SP 800-218 crosswalk), [`.github/dependabot.yml`](./.github/dependabot.yml), OpenSSF Scorecard ([`.github/workflows/scorecard.yml`](./.github/workflows/scorecard.yml)), 100% commit-SHA-pinned Actions, OpenSSF Gold bit-for-bit reproducible WASM double-build + artifact forensics + anti-obfuscation + cross-manifest version parity gates in [`.github/workflows/ci.yml`](./.github/workflows/ci.yml), and SLSA v1 tag-release provenance in [`.github/workflows/release.yml`](./.github/workflows/release.yml).

## Verified Conformance & Formal Audit Summary

Authoritative machine-verified `v2.0.0` counts and hashes are recorded in [`VERIFICATION_MASTER_SUMMARY.json`](./VERIFICATION_MASTER_SUMMARY.json) and [`SHA256SUMS.txt`](./SHA256SUMS.txt).

| Suite / Artifact | Target | Verified Posture |
| :--- | :--- | :--- |
| Rust Core Library (`cargo test --release --lib` & `clippy -D warnings`) | `scitt_time_anchor_rs` (`#![forbid(unsafe_code)]`) | `6/6` PASS, `0` warnings, `0` unsafe blocks |
| Appendix D + Strict Witness Conformance (`test_appendix_d_conformance.py`) | Dual-profile (`draft08` + `strict`, `N1`–`N34`) | `131/131` PASS, `0` Python/Rust/WASM divergences |
| CBOR Framing-Space Study (`experiment_cbor_framing_space_64.py`) | `64` `draft-templeman-scitt-framing-space-01` variants | `1/64` canonical accepted (`63/64` rejected), `266/266` cases `0` divergences |
| Microsoft Z3 Formal SMT Audit (`prove_z3_invariants.py`) | Protocol findings & soundness theorems | `11/11` VERIFIED (`UNSAT` strict invariants) |
| Triple-Engine Differential (`run_50k_triple_differential.py`) | `20` vector families (`Python == Rust == WASM`) | `50,000/50,000` PASS, `0` divergences |
| Adversarial Mutation Fuzz (`test_100k_mutation_fuzz.py`) | Hostile OTS, CBOR/COSE & header chains | `100,000/100,000` PASS, `0` crashes, `0` divergences |
| WASM Memory Leak Sieve (`wasm_100k_leak_runner.mjs`) | Single `WebAssembly.Instance` (`100k + 20k` calls) | `120,000` calls, `0` B steady-state heap delta |
| OpenSSF Gold Reproducible WASM Build (`ci.yml`) | Independent dual-target `wasm32-unknown-unknown` builds | Bit-for-bit identical `sha256sum` under `SOURCE_DATE_EPOCH` |
| Multi-Vendor Interop Matrix (`interop_matrix/MULTI_VENDOR_INTEROP_REPORT.md`) | `16` vectors × `7` external codebases + triple engine | `100%` Mainnet positive parity (`V01`, `V03`–`V06`) |

## Quick Start

Requirements: Python `>= 3.10`, Rust `>= 1.75` (`cargo`, `clippy`, plus `wasm32-unknown-unknown` target to rebuild WASM), Node `>= 20` (for WASM differential/leak runners), `z3-solver` (for SMT proofs), and `reuse` (optional, for local REUSE 3.3 checks). See [`REPRODUCIBILITY.md`](./REPRODUCIBILITY.md) for single-command artifact reproduction and bit-for-bit WASM build verification.

```bash
# 1. Install the zero-dependency Python package and CLI
pip install .
scitt-time-anchor --mode strict < cases.jsonl

# 2. Run Rust Clippy (-D warnings), unit tests, and release CLI build
cargo clippy --manifest-path scitt_time_anchor_rs/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path scitt_time_anchor_rs/Cargo.toml --release --lib
cargo build --manifest-path scitt_time_anchor_rs/Cargo.toml --release
./scitt_time_anchor_rs/target/release/scitt_time_anchor_rs --mode draft08 < cases.jsonl

# 3. Run conformance, 64-variant CBOR framing study, Z3 SMT proofs, 50k differential, 100k fuzz & WASM leak sieve
python3 verification_suite/test_appendix_d_conformance.py
python3 verification_suite/experiment_cbor_framing_space_64.py
python3 verification_suite/prove_z3_invariants.py
python3 verification_suite/run_50k_triple_differential.py
python3 verification_suite/test_100k_mutation_fuzz.py
node verification_suite/wasm_100k_leak_runner.mjs

# 4. Verify FSFE REUSE 3.3 SPDX compliance
reuse lint

# 5. Launch the 100% offline browser WASM verifier locally
python3 web/server.py --host 127.0.0.1 --port 8080
```

## CLI Profile Usage (`draft08` vs `strict`)

Both `scitt-time-anchor` (Python) and `scitt_time_anchor_rs` (Rust) read newline-delimited JSON objects on `stdin` (capped at `4 MiB` per line) and write deterministic JSON verdicts on `stdout`:

```bash
# Backward-compatible baseline (11-step draft-fassbender-scitt-time-anchor-08 default)
scitt-time-anchor --mode draft08 < cases.jsonl

# Opt-in hardened profile (Mainnet consensus ceilings, min_confirmations >= 6, RFC 8259/8949/9052 strictness, OTS bounds)
scitt-time-anchor --mode strict < cases.jsonl
```

Per-case `"mode": "draft08"` or `"mode": "strict"` inside a JSONL object overrides the CLI `--mode` flag when present; callers ingesting untrusted JSONL should enforce policy at the outer boundary (see [`THREAT_MODEL.md`](./THREAT_MODEL.md)).

## Security, Reproducibility & Standards Artifacts (17 Gates)

| Artifact / Workflow | Standard / Purpose |
| :--- | :--- |
| [`LICENSE`](./LICENSE) & [`LICENSES/Apache-2.0.txt`](./LICENSES/Apache-2.0.txt) | Full canonical SPDX Apache License, Version 2.0. |
| [`REUSE.toml`](./REUSE.toml) & [`.github/workflows/reuse.yml`](./.github/workflows/reuse.yml) | FSFE REUSE 3.3 SPDX copyright and license compliance. |
| [`SECURITY.md`](./SECURITY.md) | RFC 9116 private vulnerability disclosure (GitHub Advisories + OpenPGP), `2.0.x` support policy, 48h acknowledgement SLA, and Safe Harbor. |
| [`THREAT_MODEL.md`](./THREAT_MODEL.md) | Trust boundaries, parser/DAG DoS budgets, LEB128/CBOR/JSON parity defenses, consensus downgrade mitigations, and WASM zero-egress isolation. |
| [`CONTRIBUTING.md`](./CONTRIBUTING.md) | IETF RFC 8179 IPR disclosure posture, Apache-2.0 inbound=outbound licensing, and triple-engine parity requirements. |
| [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md) | IETF RFC 7154 Guidelines for Conduct & Contributor Covenant v2.1. |
| [`CITATION.cff`](./CITATION.cff) | Machine-readable Citation File Format 1.2.0 metadata. |
| [`codemeta.json`](./codemeta.json) | CodeMeta v3.0 / Schema.org JSON-LD metadata (FAIR4RS, Software Heritage, Zenodo, OpenAIRE, HAL). |
| [`REPRODUCIBILITY.md`](./REPRODUCIBILITY.md) | ACM Artifact Evaluation (*Available*, *Functional*, *Reusable*), JOSS Statement of Need, and `SOURCE_DATE_EPOCH` WASM double-build guide. |
| [`sbom.cdx.json`](./sbom.cdx.json) | OWASP CycloneDX 1.5 zero-dependency SBOM covering Python, Rust, and WASM deliverables. |
| [`openvex.json`](./openvex.json) | OpenVEX v0.2.0 vulnerability exploitability baseline with zero synthetic CVE entries. |
| [`osps-baseline.json`](./osps-baseline.json) | OpenSSF OSPS Baseline `v2026.08.28` Level 2/3 self-attestation crosswalked to EU CRA (Reg. 2024/2847) and NIST SSDF SP 800-218. |
| [`.github/dependabot.yml`](./.github/dependabot.yml) | Weekly automated GitHub Actions, Cargo, and pip dependency checks. |
| [`.github/workflows/scorecard.yml`](./.github/workflows/scorecard.yml) | OpenSSF Scorecard continuous security assessment uploading SARIF to GitHub Security. |
| [`.github/workflows/ci.yml`](./.github/workflows/ci.yml) | SHA-pinned CI enforcing Clippy `-D warnings`, OpenSSF Gold reproducible WASM double-builds, artifact forensics, anti-obfuscation, cross-manifest version parity, conformance, framing-space, Z3, and 50k differential suites. |
| [`.github/workflows/release.yml`](./.github/workflows/release.yml) | Tag-triggered builds with artifact forensics, SBOM/OpenVEX/OSPS staging, SHA-256 release manifests, and SLSA v1 build provenance attestations. |
| [`.github/workflows/pages.yml`](./.github/workflows/pages.yml) | SHA-pinned offline WASM lab deployment with static zero-egress and relative-path verification. |

## Repository Layout

- `pyproject.toml` — PEP 621 package metadata for `scitt-time-anchor` (`2.0.0`, zero runtime dependencies).
- `scitt_time_anchor_py/` — Pure Python 3 reference verifier (`ots_parser.py`, `bitcoin_chain.py`, `cbor_scitt.py`, `verifier.py`, `cli.py`).
- `scitt_time_anchor_rs/` — `#![forbid(unsafe_code)]` Rust verifier crate and `wasm_cdylib/` zero-import WebAssembly export shim.
- `draft09_patch/` — Non-normative unified diff (`draft-fassbender-scitt-time-anchor-09-proposed.diff`) and test vectors `N9`–`N16` (`APPENDIX_D6_NEW_NEGATIVE_VECTORS_N9_N16.md`).
- `interop_matrix/` — Multi-vendor interoperability runner and `16 × 8` empirical report (`MULTI_VENDOR_INTEROP_REPORT.md`).
- `spec_vectors/` — Official Appendix D vectors, Bitcoin Mainnet header windows, and Z3 witness vectors (`N17A`–`N20`).
- `verification_suite/` — Conformance, 64-variant CBOR framing-space study, Z3 SMT, `50,000`-vector triple-engine differential, `100,000`-mutation fuzz, and single-instance WASM leak verification runners.
- `web/` — Self-contained offline browser WASM lab (`index.html`, `styles.css`, `app.js`, `presets.js`, `wasm_bundle.js`, `scitt_time_anchor.wasm`, `server.py`).
- `.github/workflows/` — SHA-pinned CI (`ci.yml`), GitHub Pages (`pages.yml`), OpenSSF Scorecard (`scorecard.yml`), FSFE REUSE (`reuse.yml`), and SLSA v1 tag release (`release.yml`) workflows.

## Attribution & License

- **Contributor:** Shady Ismail (`@shady-ismail-titan`, independent open-source contributor; IETF RFC 8179 disclosure posture).
- **License:** Apache License, Version 2.0 ([`LICENSE`](./LICENSE)).
