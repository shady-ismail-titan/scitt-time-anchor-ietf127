# Security Policy

## Supported Versions

Only the latest major release line receives security fixes and conformance updates.

| Version | Status |
| :--- | :--- |
| `2.0.x` | Supported (active) |
| `1.0.x` | End-of-life (unsupported) |

## Reporting a Vulnerability (Private Disclosure)

Please **do not** disclose suspected security vulnerabilities in public GitHub issues, pull requests, or mailing lists before coordinated triage.

Report vulnerabilities privately through either of the following channels (aligned with RFC 9116 vulnerability disclosure practices):

1. **GitHub Private Vulnerability Reporting (Preferred):**
   Submit a private advisory via [GitHub Security Advisories](https://github.com/shady-ismail-titan/scitt-time-anchor-ietf127/security/advisories/new).
2. **Direct / Encrypted Email Fallback:**
   Send a report to `audit@titancapitalforensics.com`. Optional OpenPGP encryption is supported using the published Ed25519 key:
   - **OpenPGP Fingerprint:** `F38185B9E58B9AA560D9A0AC3DEEC6D7518051E1`

Please include:
- Affected component(s) (`scitt_time_anchor_py`, `scitt_time_anchor_rs`, `scitt_time_anchor_wasm`, or `web/`).
- Verification profile (`--mode draft08` or `--mode strict`).
- Minimal reproducible input (JSONL payload, hex/Base64 `.ots`, CBOR `ProofBundle`, or `COSE_Sign1` bytes).
- Expected versus observed verdict or resource behavior.

## Response & Triage Commitments

- **Acknowledgement SLA:** Within **48 hours** of receipt.
- **Initial Triage Target:** Within **14 calendar days** (severity assessment, reproduction confirmation, and remediation plan).
- **Disclosure:** Confirmed fixes are released with regression vectors across all three engines (`Python`, `Rust`, `WASM`), documented in `CHANGELOG.md`, and published via GitHub Security Advisories with CWE/CVE identifiers where applicable.

## Safe Harbor

Good-faith security research conducted against this open-source verifier, its reference test vectors, or the static offline WebAssembly lab—without disrupting third-party infrastructure, accessing unauthorized data, or violating privacy—is explicitly authorized. We will not pursue legal action against researchers who follow good-faith testing and coordinated private disclosure.

## Scope Boundaries

### In Scope

- **Parser & Resource-Exhaustion DoS:** Stack overflow, quadratic CPU blowup, unbounded memory allocation, or shared-prefix DAG amplification in `.ots`, CBOR, JSONL, hex/Base64, or the WASM Byte-Ray dissector.
- **Cross-Runtime Parity Divergences:** Any input for which the Python 3, native Rust, and WebAssembly engines disagree on `outcome`, `step`, consensus fields, or error classification (`Python != Rust != WASM`).
- **Consensus, PoW, & Temporal Bypasses:** Bypassing `SetCompact` target validation, Mainnet `powLimit` (`0x1d00ffff`) or post-BIP113 (`0x181fffff`) ceilings, `2016`-block retarget clamping, Genesis/checkpoint linkage, `min_confirmations >= 6` enforcement in `--mode strict`, or BIP-113 / Forward-MTP temporal bounds.
- **CBOR / COSE Framing & Encoding Bypasses:** Bypassing RFC 8949 deterministic CBOR rules, RFC 9052 Section 3 empty protected header checks (`b"\xa0"` rejection), duplicate semantic map-key rejection, or RFC 8259 / I-JSON strict parsing.
- **Browser WASM Isolation Regressions:** Violations of zero-egress CSP (`connect-src 'none'`), introduction of WASM host imports, `unsafe` Rust code, or unsafe DOM sinks in `web/`.

### Out of Scope

- **Bitcoin Network Consensus & Mining Economics:** 51% reorganizations, miner timestamp manipulation within Bitcoin protocol rules, or network-level eclipse attacks against an operator's Bitcoin node.
- **Third-Party OpenTimestamps Calendar Availability:** Uptime, latency, or aggregation policies of external OTS calendar servers.
- **COSE Cryptographic Signature Verification:** Per `draft-fassbender-scitt-time-anchor-08` Section 6.1, verifying COSE digital signatures and managing issuer/Transparency Service trust anchors is the responsibility of the enclosing SCITT verifier, not the temporal-anchoring module.
- **Unvalidated Public Block Explorers:** Headers sourced solely from untrusted explorers are intentionally classified as `unverifiable` (Appendix D.7 Route 4).

## Architectural Security Properties

- **Zero Runtime Dependencies:** Python standard library only (`scitt_time_anchor_py`); zero external crates (`scitt_time_anchor_rs` and `scitt_time_anchor_wasm`).
- **Memory Safety:** `#![forbid(unsafe_code)]` enforced in Rust core and CI.
- **Zero Secrets & Zero Egress:** No private keys, credentials, or outbound network calls in CLI, library, or WebAssembly builds.
- **Supply-Chain Provenance:** SHA-pinned GitHub Actions, FSFE REUSE 3.3 licensing metadata, CycloneDX 1.5 SBOM (`sbom.cdx.json`), OpenVEX v0.2.0 baseline (`openvex.json`), OpenSSF OSPS Baseline attestation (`osps-baseline.json`), OpenSSF Scorecard monitoring, bit-for-bit reproducible WASM builds, and SLSA v1 release attestations.
