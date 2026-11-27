# Contributing

Thank you for contributing to the **SCITT Time-Anchor Triple-Engine Verifier**. This project is maintained as an independent, vendor-neutral clean-room implementation and formal test suite supporting interoperability work around `draft-fassbender-scitt-time-anchor-08` and related IETF SCITT specifications (`RFC 9921`, `RFC 9942`, `RFC 9943`, and `draft-templeman-scitt-framing-space-01`).

## Standards Culture & IPR Posture (IETF RFC 8179)

- **Vendor-Neutral Technical Scope:** Issues, pull requests, and specification notes should focus strictly on cryptographic correctness, wire-format precision, cross-implementation interoperability, formal verification, and parser hardening. Commercial marketing or product promotion is out of scope. All participants abide by [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md) (IETF RFC 7154 & Contributor Covenant 2.1).
- **Reproducibility & Artifact Standards:** See [`REPRODUCIBILITY.md`](./REPRODUCIBILITY.md) for single-command verification and bit-for-bit reproducible WASM build instructions.
- **IETF RFC 8179 Disclosure Posture:** Contributors submitting code, test vectors, or specification feedback acknowledge the intellectual property rights (IPR) disclosure principles of [IETF RFC 8179](https://datatracker.ietf.org/doc/html/rfc8179). If you are aware of any patent or patent application covering a contribution or referenced specification mechanism, disclose it in accordance with RFC 8179 before or alongside your contribution.
- **Inbound = Outbound Licensing (`Apache-2.0`):** All contributions are submitted under the terms of the **Apache License, Version 2.0** (see Section 5 of [`LICENSE`](./LICENSE)).
- **FSFE REUSE 3.3 Compliance:** All new or modified files must remain compliant with [`REUSE.toml`](./REUSE.toml) and pass `reuse lint`.

## Security Reports

Do **not** open public issues or pull requests for undisclosed security vulnerabilities. Follow [`SECURITY.md`](./SECURITY.md) for private disclosure.

## Triple-Engine Parity Requirement

Every normative, parser, consensus, or serialization change **must preserve exact behavioral parity across all three engines**:

1. **Python 3 Reference (`scitt_time_anchor_py/`)** — Pure Python `>= 3.10` standard library (`0` third-party runtime dependencies).
2. **Safe Native Rust (`scitt_time_anchor_rs/`)** — `#![forbid(unsafe_code)]`, `0` external crate dependencies.
3. **Offline WebAssembly (`scitt_time_anchor_rs/wasm_cdylib/` -> `web/scitt_time_anchor.wasm`)** — `wasm32-unknown-unknown`, `0` host imports, zero external web assets, strict `connect-src 'none'` CSP.

A pull request will not be merged if it introduces any verdict, step, or consensus-field divergence between Python, Rust, and WebAssembly (`0` divergences required).

## Required Local Verification Before Submitting a PR

Run the complete local verification pipeline before opening a pull request:

```bash
# 1. Rust static lint (zero warnings permitted) and unit tests
cargo clippy --manifest-path scitt_time_anchor_rs/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path scitt_time_anchor_rs/Cargo.toml --release --lib
cargo build --manifest-path scitt_time_anchor_rs/Cargo.toml --release

# 2. Reproducible zero-import WASM build (when Rust or WASM sources change)
RUSTFLAGS="--remap-path-prefix=$(pwd)=/src --remap-path-prefix=$HOME=/build" \
  cargo build --manifest-path scitt_time_anchor_rs/wasm_cdylib/Cargo.toml \
  --release --target wasm32-unknown-unknown

# 3. Appendix D + Strict conformance & 64-variant CBOR framing-space study
python3 verification_suite/test_appendix_d_conformance.py
python3 verification_suite/experiment_cbor_framing_space_64.py

# 4. Z3 SMT formal invariant proofs (requires z3-solver)
python3 verification_suite/prove_z3_invariants.py

# 5. Triple-engine 50k differential, 100k mutation fuzz, and WASM 120k leak sieve
python3 verification_suite/run_50k_triple_differential.py
python3 verification_suite/test_100k_mutation_fuzz.py
node verification_suite/wasm_batch_eval.mjs --stress-deep
node verification_suite/wasm_100k_leak_runner.mjs

# 6. FSFE REUSE 3.3 license compliance
reuse lint
```

## Coding & Hygiene Guidelines

- Keep `scitt_time_anchor_py/` and `scitt_time_anchor_rs/` free of third-party runtime dependencies.
- Never introduce `unsafe` blocks in `scitt_time_anchor_rs/` or `scitt_time_anchor_rs/wasm_cdylib/`.
- Keep all `web/` assets 100% self-contained with relative paths and zero dangerous DOM sinks (`innerHTML`, `eval`, or remote CDN imports).
- Include deterministic negative and boundary test vectors for every bug fix or hardening change.
- Update `CHANGELOG.md` and regenerate tracked artifact checksums (`SHA256SUMS.txt`) whenever release artifacts change.
