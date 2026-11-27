# Reproducibility & Artifact Evaluation Guide

This document supports **ACM Artifact Evaluation** (*Artifacts Available*, *Artifacts Evaluated — Functional*, *Artifacts Evaluated — Reusable*) and provides a concise **Statement of Need** following Journal of Open Source Software (JOSS) standards for **SCITT Time-Anchor Triple-Engine Verifier (`v2.0.0`)**.

---

## Statement of Need

IETF Supply Chain Integrity, Transparency, and Trust (SCITT) specifications (`RFC 9921`, `RFC 9942`, `RFC 9943`) and `draft-fassbender-scitt-time-anchor-08` combine OpenTimestamps (`.ots`) binary Merkle proofs, Bitcoin 80-byte PoW block headers, and CBOR/COSE (`RFC 8949`, `RFC 9052`) envelopes. Empirical multi-vendor interoperability testing revealed critical cross-runtime parser divergences across existing libraries—including ECMAScript 32-bit LEB128 shift wrapping (`N9`), overlong varuint acceptance (`N10`), omitted file-hash opcode validation (`N11`), unbounded `OpHexlify` memory amplification (`N12`), `SetCompact` sign-bit masking (`N14`), trailing attestation slice acceptance (`N15`), recursive stack overflows (`V16`), and CBOR framing-space ambiguity (`draft-templeman-scitt-framing-space-01`).

**SCITT Time-Anchor (`v2.0.0`)** addresses this gap by providing three independent, zero-dependency, clean-room verifiers (`Python 3`, `#![forbid(unsafe_code)]` `Rust`, and zero-import offline `WebAssembly`) engineered to produce bit-identical verdicts across both the backward-compatible `--mode draft08` baseline and the hardened `--mode strict` profile, backed by machine-checked Microsoft Z3 SMT invariants, a 64-variant CBOR framing-space empirical harness, `50,000`-vector differential testing, `100,000`-mutation fuzzing, and `120,000`-call single-instance WASM heap-stability verification.

---

## ACM Artifact Evaluation Alignment

| Badge Criterion | Repository Evidence |
| :--- | :--- |
| **Artifacts Available** | Publicly archived Apache-2.0 source, test vectors, and metadata ([`LICENSE`](./LICENSE), [`CITATION.cff`](./CITATION.cff), [`codemeta.json`](./codemeta.json), [`SHA256SUMS.txt`](./SHA256SUMS.txt)). |
| **Artifacts Evaluated — Functional** | Fully offline verification suites (`0` network calls required during execution), deterministic JSON reports, and automated CI checks ([`.github/workflows/ci.yml`](./.github/workflows/ci.yml)). |
| **Artifacts Evaluated — Reusable** | Zero third-party runtime dependencies across PEP 621 Python package (`scitt_time_anchor_py/`), safe Rust crate (`scitt_time_anchor_rs/`), and zero-import WASM module (`web/scitt_time_anchor.wasm`), paired with [`THREAT_MODEL.md`](./THREAT_MODEL.md) and [`sbom.cdx.json`](./sbom.cdx.json). |

---

## Hardware & Software Requirements

- **Compute:** Any standard `x86_64` or `arm64` Linux, macOS, or Windows/WSL workstation (`>= 2` vCPUs, `>= 4 GiB` RAM, `< 500 MiB` free disk space). Full verification completes in under 60 seconds offline.
- **Required Toolchains:**
  - Python `>= 3.10` (`python3`, standard library only for the verifier itself)
  - Rust `>= 1.75` (`cargo`, `clippy`, and `rustup target add wasm32-unknown-unknown`)
  - Node.js `>= 20` (`node`, for WASM differential and memory-leak verification)
- **Optional Verification Dependencies (Test Suites Only, Never Required at Runtime):**
  - `z3-solver` (`pip install z3-solver`, only to re-run `prove_z3_invariants.py`)
  - `reuse` (`pip install reuse`, only to re-run `reuse lint`)

---

## Single-Command Full Verification & 64-Variant Framing-Space Reproduction

From the repository root, run the complete deterministic verification pipeline:

```bash
sha256sum -c SHA256SUMS.txt \
  && cargo clippy --manifest-path scitt_time_anchor_rs/Cargo.toml --all-targets -- -D warnings \
  && cargo test --manifest-path scitt_time_anchor_rs/Cargo.toml --release --lib \
  && cargo build --manifest-path scitt_time_anchor_rs/Cargo.toml --release \
  && python3 verification_suite/test_appendix_d_conformance.py \
  && python3 verification_suite/experiment_cbor_framing_space_64.py \
  && python3 verification_suite/prove_z3_invariants.py \
  && python3 verification_suite/run_50k_triple_differential.py \
  && python3 verification_suite/test_100k_mutation_fuzz.py \
  && node verification_suite/wasm_batch_eval.mjs --stress-deep \
  && node verification_suite/wasm_100k_leak_runner.mjs \
  && reuse lint
```

Expected invariants on completion:
- `0` Rust Clippy warnings and `0` `unsafe` blocks.
- `0` Python / Rust / WASM divergences across Appendix D conformance, the 64-variant `draft-templeman-scitt-framing-space-01` framing-space study, the `50,000`-vector differential suite, and the `100,000`-mutation adversarial fuzz suite.
- `ALL_VERIFIED` (`UNSAT`) across all Z3 SMT formal invariants.
- `0` bytes steady-state linear-memory growth across `120,000` single-instance WASM evaluations.
- `0` FSFE REUSE 3.3 licensing errors.

---

## Bit-for-Bit Reproducible WASM Build Verification (`SOURCE_DATE_EPOCH`)

To independently verify bit-for-bit reproducibility of the zero-import `wasm32-unknown-unknown` binary across two separate build directories (matching the OpenSSF Gold reproducible-build gate in [`.github/workflows/ci.yml`](./.github/workflows/ci.yml)):

```bash
export SOURCE_DATE_EPOCH=1795737600
COMMON_FLAGS="--remap-path-prefix=$(pwd)=/src --remap-path-prefix=$HOME=/build"

RUSTFLAGS="$COMMON_FLAGS --remap-path-prefix=/tmp/wasm_repro_a=/target" \
CARGO_TARGET_DIR=/tmp/wasm_repro_a \
  cargo build --manifest-path scitt_time_anchor_rs/wasm_cdylib/Cargo.toml \
  --release --target wasm32-unknown-unknown

RUSTFLAGS="$COMMON_FLAGS --remap-path-prefix=/tmp/wasm_repro_b=/target" \
CARGO_TARGET_DIR=/tmp/wasm_repro_b \
  cargo build --manifest-path scitt_time_anchor_rs/wasm_cdylib/Cargo.toml \
  --release --target wasm32-unknown-unknown

HASH_A=$(sha256sum /tmp/wasm_repro_a/wasm32-unknown-unknown/release/scitt_time_anchor_wasm.wasm | awk '{print $1}')
HASH_B=$(sha256sum /tmp/wasm_repro_b/wasm32-unknown-unknown/release/scitt_time_anchor_wasm.wasm | awk '{print $1}')
echo "Build A: $HASH_A"
echo "Build B: $HASH_B"
test "$HASH_A" = "$HASH_B" && echo "BIT-FOR-BIT REPRODUCIBLE: PASS"
rm -rf /tmp/wasm_repro_a /tmp/wasm_repro_b
```

Note: Cross-machine SHA-256 identity requires matching the exact Rust compiler toolchain version (`rustc --version`). Within any fixed Rust toolchain version, independent clean builds produce byte-identical WASM binaries with zero embedded local filesystem paths.
