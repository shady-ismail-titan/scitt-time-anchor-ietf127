# Independent Verifier & Conformance Suite for `draft-fassbender-scitt-time-anchor-08`

Independent third-party clean-room verifiers (unaffiliated with the draft author or Umarise), implemented from `draft-fassbender-scitt-time-anchor-08` in Python 3, safe Rust (`#![forbid(unsafe_code)]`), and offline WebAssembly (`wasm32-unknown-unknown`), accompanied by Z3 SMT boundary models, a reproducible multi-vendor interoperability harness, and **non-normative implementer feedback & illustrative errata notes** offered respectfully to the Draft Editor and IETF SCITT Working Group (this repository implements `-08` faithfully by default and does **not** propose a competing fork).

## Overview

The Hackathon call for `draft-fassbender-scitt-time-anchor-08` asks two concrete questions:

1. Does an independent implementation built from the specification alone accept the positive vectors in Appendix D and reject the negative vectors in Appendix D.6?
2. Where did an implementer have to guess, or where were two readings of a step both defensible under the current text?

This repository provides:

- **Three independent execution targets** sharing identical JSON test I/O:
  - `scitt_time_anchor_py`: Pure Python 3 standard-library verifier (`0` runtime dependencies).
  - `scitt_time_anchor_rs`: Safe Rust CLI/library (`#![forbid(unsafe_code)]`, `0` external crate dependencies) with an explicit `O(1)` iterative work-stack parser.
  - `web/scitt_time_anchor.wasm`: Offline client-side WebAssembly module (`114,738` bytes raw / `45,822` bytes gzipped, `0` host imports, served under `Content-Security-Policy: connect-src 'none'`).
- **Two selectable verification profiles**:
  - `--mode draft08`: Exact 11-step `VERIFY-ANCHOR` baseline (`100%` match on Appendix D.1--D.7 and wild post-2016 Bitcoin `OP_RETURN` `.ots` proofs).
  - `--mode strict`: Opt-in diagnostic hardening profile (`--mode draft08` remains the default `100%`-ecosystem-compatible mode so deployed legacy v1 `.ots` proofs are never broken) testing candidate ambiguity resolutions (`N9`--`N16`) for Working Group discussion.
- **Multi-vendor empirical interoperability matrix** (`interop_matrix/MULTI_VENDOR_INTEROP_REPORT.md`): Live execution of `16` Mainnet and boundary vectors across `7` external codebases (`verify-anchoring.org` JS, `javascript-opentimestamps`, `python-opentimestamps 0.5.0`, `umarise 1.0.0`, `emiliaprotocol` `-06`, `CryptoGeekPT` `-03`, `DPS / Lemonnier` `-08`, plus `WEXP` and `iSoluce` SCITT `COSE_Sign1` artifacts).
- **Non-normative implementer feedback diff & byte-exact `COSE_Sign1` / `.ots` test witnesses (`C1`, `N9`--`N16`)**: Illustrative unified diff (`draft09_patch/draft-fassbender-scitt-time-anchor-09-proposed.diff`) and complete wire-hex vectors (`draft09_patch/APPENDIX_D6_NEW_NEGATIVE_VECTORS_N9_N16.md`) offered strictly as editorial input to assist the `-08` Editor and WG.

## Summary of Specification Ambiguities Surfaced (Non-Normative Implementer Feedback on `draft-08`)

| ID | Specification Section | Ambiguity / Defensible Dual Reading in `-08` | Empirical Manifestation | Non-Normative Editorial Option for Editor / WG Consideration (`--mode strict`) |
|---|---|---|---|---|
| `F1` | Section 3.3 (`OTS-DESERIALIZE`) | Unsigned LEB128 height width & canonical form are delegated to `[OTS]` without byte-length or trailing-zero rules | `0xe9b6ba808008` decodes to real Mainnet Block `957,289` in JS (`<<` masks shift mod 32) vs `274,878,864,233` (`unverifiable`) in Python/Rust; overlong `0xe9b6ba00` accepted by 3 verifiers | Canonical `<= 5`-octet `u32` LEB128; zero trailing attestation or outer proof bytes (`N9`, `N10`, `N15`) |
| `F2` | Section 3.3 (`OTS-REPLAY`) | Disallowed opcodes return `NULL` (unevaluated -> `unverifiable` if alone), and unary `OpHexlify` (`0xf3`) / recursion bounds are unspecified | `65`-byte `30 x 0xf3` proof amplifies buffer if replayed; `4,096`-op linear proof triggers `RecursionError` in recursive Python parsers (`V16`) | Explicit `{0x08, 0xf0, 0xf1}` allowlist at parse in `strict`, `MAX_RUNNING_BYTES = 4096`, iterative `O(1)` stack (`N12`) |
| `F3` | Sections 7.2 & 8.10 | `file_hash_op` requires SHA-256 (`0x08`), while legacy 160-bit branch ops (`OpSHA1` `0x02`, `OpRIPEMD160` `0x03`) narrow collision resistance to 80 bits | Upstream 2015 P2PKH `hello-world.txt.ots` (`V07`) starts with `OpRIPEMD160` (`0x03`), yielding `unverifiable` in `-08` vs `invalid` in `strict`; one `-03` verifier omits checking `file_hash_op` (`V12`) | Enforce `file_hash_op == 0x08` and SHA-256-only branch digests (`2^128` Grover preimage bound, zero long-term keys; `N11`, `N13`) |
| `F4` | Section 4.1 Steps 8--9 & Section 3.3 | Step 8 picks `min(b.H)` across `verified` before Step 9 checks `CONFIRMATIONS-ON >= 6`; `nBits` decoding is operational | Unconfirmed lower-height branch on a sparse checkpoint view causes `unverifiable` even when a sibling branch has `>= 6` confirmations; `0x1dfbffff` sign-bit accepted when masking `bits & 0xFFFFFF` (`N14`) | Filter `durable` branches (`k >= MIN_CONFIRMATIONS`) prior to `argmin(b.H)`; exact Bitcoin Core `SetCompact` + 256-bit `ChainWork` + `BIP-113` |
| `F5` | Section 7.1 & Appendix D.5 | Appendix D.5 prints `Median Time Past: 2026-07-09T09:26:48Z` (inclusive `957279..957289`), whereas `BIP-113` defines `median(H-11..H-1)` (`09:24:46Z`, 122s earlier) | `122`-second discrepancy on official Vector 1; single-block `RWCP` `nTime` can decrease between block `H` and `H+1` within consensus rules | Correct Appendix D.5 `MTP(H)` to `09:24:46Z`; document optional `Forward-MTP(H+5) = median(nTime[H-5..H+5])` at exact `6` confirmations (`0` extra block wait) |
| `F6` | Section 6 (`COSE_Sign1` Header `394`) | Hashing outer `COSE_Sign1` breaks when Transparency Services append or relay unprotected receipts in header `394` (`RFC 9942`) | Verified on `WEXP scitt-receipt-boundary-001` (`836` B): mutating unprotected header `394` invalidates outer-envelope `.ots` proofs | Commit to deterministic `Sig_structure` (`RFC 9942` / `RFC 9921` Section 3.1.1) or co-anchor `(SignedStatement, Receipt)` (`N16`) |
| `F7` | Section 5.1 (Merkle Batching) | Unprefixed binary Merkle trees allow 64-byte `L_0 || L_1` leaf/internal collisions if callers hash raw messages | Standard v1 `.ots` calendars omit `RFC 6962` `0x00`/`0x01` prefixes, so requiring them breaks wild `.ots` proofs | Keep v1 `.ots` verification unprefixed for `100%` ecosystem interop; note `0x00`/`0x01` domain separation for future v2 batch profiles |

## Quick Start

Requirements: Python `>= 3.10`, Rust `>= 1.75` (`cargo`), and `z3-solver` (only for re-running formal SMT proofs; neither verifier uses third-party runtime packages).

```bash
# Run Rust unit tests, CLI parity checks, Appendix D conformance, and Z3 proofs
make check

# Run the 50,000-vector Python / Rust / WebAssembly differential suite (requires node >= 20)
make test-differential

# Launch the offline WebAssembly verification lab locally on http://127.0.0.1:8080/
make serve
```

### Command-Line Usage

Both `scitt_time_anchor_py` and `scitt_time_anchor_rs` accept newline-delimited JSON test cases on `stdin` and emit deterministic JSON verdicts on `stdout`:

```bash
# Baseline 11-step draft-08 algorithm
python3 -m scitt_time_anchor.cli --mode draft08 < cases.jsonl

# Candidate -09 strict profile
./scitt_time_anchor_rs/target/release/scitt_time_anchor_rs --mode strict < cases.jsonl
```

## Repository Layout

- `scitt_time_anchor_py/` -- Pure Python 3 reference verifier (`ots_parser.py`, `bitcoin_chain.py`, `cbor_scitt.py`, `verifier.py`, `cli.py`).
- `scitt_time_anchor_rs/` -- `#![forbid(unsafe_code)]` Rust verifier crate and `wasm_cdylib/` zero-import WebAssembly target.
- `draft09_patch/` -- Proposed unified diff (`draft-fassbender-scitt-time-anchor-09-proposed.diff`) and hex test vectors `N9`--`N16` (`APPENDIX_D6_NEW_NEGATIVE_VECTORS_N9_N16.md`).
- `interop_matrix/` -- Multi-vendor interoperability runner and `16 x 8` empirical report (`MULTI_VENDOR_INTEROP_REPORT.md`).
- `spec_vectors/` -- Official Appendix D vectors, Bitcoin Mainnet headers (`957278..957300` and wild proof anchors), and Z3 witness vectors.
- `verification_suite/` -- Conformance, Z3 SMT proof (`prove_z3_invariants.py`), `50,000`-vector triple-engine differential (`run_50k_triple_differential.py`), and `100,000`-mutation fuzz reports.
- `web/` -- Self-contained offline browser verification lab (`index.html`, `scitt_time_anchor.wasm`, `server.py`).

## Threat Model & Empirical Suite Timings

### Verifier Threat Model
The verifier assumes an **untrusted proof submitter** (capable of supplying arbitrary malformed `.ots` byte sequences, overlong LEB128 varuints, cyclic or deep DAG branches, narrow-pipe legacy hash opcodes, unauthenticated COSE header `394` receipt mutations, or crafted `nBits` headers) and a **trusted local block-header store** (`min_confirmations >= 6`). Under `--mode strict`, any proof violating canonical `u32` LEB128 encoding, byte-consumption completeness, `{0x08, 0xf0, 0xf1}` opcode bounds, `MAX_RUNNING_BYTES = 4096`, or `CoseSign1` `Sig_structure` binding is deterministically rejected (`invalid`).

### Provenance of Parser Bounds & Backward-Compatibility Guarantee
- **Default `100%` Legacy Compatibility (`--mode draft08`)**: Baseline verification implements the exact 11-step `draft-fassbender-scitt-time-anchor-08` algorithm as the default profile, ensuring zero breakage of existing OpenTimestamps calendars or deployed v1 `.ots` proofs. `--mode strict` is strictly an **opt-in diagnostic profile** for evaluating candidate WG hardening options.
- **Upstream `[OTS]` Reference Provenance of Byte Caps**: All parser bounds in `--mode strict` derive directly from upstream `python-opentimestamps 0.5.0` reference constants rather than arbitrary thresholds: `MAX_RUNNING_BYTES = 4096` matches `Op.MAX_RESULT_LENGTH = 4096` and `Op.MAX_MSG_LENGTH = 4096` (`opentimestamps/core/op.py:41,60`), while the `9`-octet vs `5`-octet `varuint` divergence stems directly from `MAX_VARUINT_BYTES = 9` (`opentimestamps/core/serialize.py:192`) interacting with JavaScript 32-bit bitwise shift masking (`shift & 31`).

### Measured Execution Timings (Apple Silicon M-Series, Single Workstation)
- `make check` (Rust unit tests + CLI parity + `96` Appendix D conformance [`31.11 ms`] + `10` Z3 SMT proofs [`255.76 ms`]): **`~1.0s`--`2.3s`**
- `verification_suite/run_50k_triple_differential.py` (`50,000` vectors across Python `774.5 ms`, Native Rust `2,040.5 ms` [`40.8 us/vec`], and Node V8 WASM `2,572.4 ms` [`51.5 us/vec`]): **`5.88s` wall-clock**
- `verification_suite/test_100k_mutation_fuzz.py` (`100,000` hostile binary/CBOR/COSE mutations + `20,000` single-instance WASM leak probes across all 3 engines): **`6.43s` wall-clock**
- **Combined `150,096`-vector + `10`-theorem full suite wall-clock**: **`12.60s`**

## License

Apache License 2.0 (`LICENSE`).
