# Reproducible Multi-Vendor Interoperability Harness (`16 Vectors x 7 External Orgs`)

All external repositories and live artifacts evaluated in `interop_matrix/MULTI_VENDOR_INTEROP_REPORT.md` are pinned below by exact upstream Git URL, full 40-character commit SHA (or exact PyPI/npm package version), and full 64-character SHA-256 file digest.

> **Note on `draft09_patch/` Attribution**: `draft-fassbender-scitt-time-anchor-08.txt` (`SHA-256: 687000b938fcea6b15871f9ea20dc4694f89b7a78f719bacc72ef0ecf1da3394`) is the upstream IETF Internet-Draft authored by H. Fassbender (Umarise). Our unified diff in `draft09_patch/` patches that upstream `-08` text for Working Group discussion; our clean-room verifiers are completely independent of Umarise.

## 1. Pinned Upstream Repositories & Exact 40-Character Commit SHAs

| External Organization / Implementation | Upstream Repository / Artifact URL | Pinned Version / Full 40-Char Git Commit SHA |
|---|---|---|
| OpenTimestamps JS (`npm opentimestamps`) | `https://github.com/opentimestamps/javascript-opentimestamps.git` | `c07ba8be0dae4e8721a84f32820abf7b2547a6ce` |
| OpenTimestamps Python (`python-opentimestamps`) | `https://github.com/opentimestamps/python-opentimestamps.git` (`PyPI 0.5.0`) | `8c3dc6fbdf6fcba054e78643e9df5eccd8c9fce4` |
| EMILIA Protocol (`draft-06` Rust verifier) | `https://github.com/emiliaprotocol/scitt-time-anchor-verifier.git` | `6ea9afb257df9c9de28fc04001e9cc70124aa6fd` |
| CryptoGeekPT / Tiago Pinto (`draft-03` verifier) | `https://github.com/CryptoGeekPT/interop-fassbender-scitt-time-anchor-03.git` | `3958e75471588af513397c2d914b91d7318a9caf` |
| CryptoGeekPT (`crosscheck-emilia`) | `https://github.com/CryptoGeekPT/interop-fassbender-scitt-time-anchor-crosscheck-emilia.git` | `ad31c27bc1eaf2fbf4e12879a57d5f1c012e8e16` |
| DPS / Laurent Lemonnier (`draft-08` verifier) | `https://github.com/Laurent-Lemonnier/dps-scitt-decision-layer.git` | `099bb05a23de7202c60be0e531b133f52539eb05` |
| WEXP SCITT Receipt Interop | `https://github.com/WEXP-dev/wexp-interop.git` | `81475e755d5410922579342b3942fe936d754530` |

## 2. Full 64-Character SHA-256 Digests of Live Artifacts & Repository Deliverables

| Artifact / Deliverable | Size (Bytes) | Full SHA-256 Digest |
|---|---:|---|
| Upstream `draft-fassbender-scitt-time-anchor-08.txt` | `237,247` | `687000b938fcea6b15871f9ea20dc4694f89b7a78f719bacc72ef0ecf1da3394` |
| Live `verify-anchoring.org/opentimestamps.min.js` | `1,599,354` | `f6181ae00cce58773f8710894c99d0656058f6a1e08c57360b263cd46c54fbf2` |
| Live `iSoluce` SCITT `checkpoint.cose` | `219` | `5b20ffc55543cffef2866fcdfc396f7aff7083a6e780f43d947eb18182a8ea89` |
| `web/scitt_time_anchor.wasm` | `114,738` | `ba6485945a52eca8e3d1176855de91518b3224f60045276663abcc21bb24aff3` |
| `draft09_patch/draft-fassbender-scitt-time-anchor-09-proposed.diff` | `12,394` | `778c3e033127e2e276f05cdded72cd161d9aaf498f6e9fd5d6f14d95d47a9cd7` |
| `draft09_patch/APPENDIX_D6_NEW_NEGATIVE_VECTORS_N9_N16.md` | `10,513` | `bc7eef39756ba8a71d72b6a2d958b3acc94c6150d70ec28b20999a0b1019fe3c` |
| `interop_matrix/MULTI_VENDOR_INTEROP_REPORT.md` | `9,995` | `c72b270649fbc32b1632458c907043fc3d4047f8e8ebe8afcc9864b93fca908c` |

## 3. Automated Reproduction Steps

1. Clone the 7 pinned commits above into `$INTEROP_SANDBOX_DIR/repos/` and create `$INTEROP_SANDBOX_DIR/py_env` (`python-opentimestamps==0.5.0`, `python-bitcoinlib==0.12.2`, `umarise==1.0.0`, `pycose==1.1.0`, `pyscitt==0.15.0`, `cbor2==5.9.0`) and `$INTEROP_SANDBOX_DIR/js_env` (`npm install opentimestamps`).
2. Execute the deterministic multi-vendor harness directly from the repository root:
```bash
INTEROP_SANDBOX_DIR=/path/to/ietf127_interop_sandbox python3 interop_matrix/run_multi_vendor_interop.py
```
3. Run the self-contained clean-room triple-engine suites (requires zero external sandbox):
```bash
make check
python3 verification_suite/run_50k_triple_differential.py
python3 verification_suite/test_100k_mutation_fuzz.py
```
