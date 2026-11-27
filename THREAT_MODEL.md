# Threat Model

This document defines the security boundaries, adversary model, mitigated attack classes, and explicit non-goals for the **SCITT Time-Anchor Triple-Engine Verifier (`v2.0.0`)** implementing `draft-fassbender-scitt-time-anchor-08` (`--mode draft08`) and the hardened strict verification profile (`--mode strict`).

---

## 1. Trust Boundaries & Explicit Non-Goals

### 1.1 Architecture & Trust Boundary Diagram

```text
+-------------------------------------------------------------------------+
| UNTRUSTED INPUTS (Adversary-Controlled)                                 |
|  - Artifact bytes / COSE_Sign1 envelope / RFC 9942 receipt bytes        |
|  - OpenTimestamps (.ots) binary proof & CBOR ProofBundle                |
|  - JSONL stdin lines / Browser WASM input buffer                        |
|  - candidate_store headers (source: public_explorer | anchoring_service)|
+------------------------------------+------------------------------------+
                                     |
              [ TB-1: Bounded Deserialization & Strict Parsing ]
              (4 MiB I/O cap, RFC 8259 / I-JSON, RFC 8949 / 9052 CBOR,
               O(1)-stack OTS DAG parser, shared-prefix op budget)
                                     v
+-------------------------------------------------------------------------+
| VERIFIER CORE (Python 3 stdlib == Safe Rust == Zero-Import WASM)        |
|  - 11-step VERIFY-ANCHOR state machine (draft08 | strict)               |
|  - Exact 256-bit Bitcoin Core SetCompact / GetBlockProof arithmetic     |
|  - Zero network egress, zero filesystem writes, zero secrets            |
+------------------------------------+------------------------------------+
                                     ^
              [ TB-2: Trusted Chain & Policy Interface ]
                                     |
+-------------------------------------------------------------------------+
| TRUSTED OPERATOR-SUPPLIED INPUTS                                        |
|  - validated_chain (80-byte Bitcoin headers from a locally validated    |
|    full/pruned node or pinned checkpoint header set)                    |
|  - Verification policy: mode (draft08 vs strict), min_confirmations,    |
|    expected_ledger_id (Genesis hash), min_chainwork_hex                 |
+-------------------------------------------------------------------------+
```

### 1.2 Trust Boundary Definitions

| Boundary | Untrusted Side | Trusted Side | Enforced Invariant |
| :--- | :--- | :--- | :--- |
| **TB-1: Proof & Framing Ingress** | `.ots` proofs, `ProofBundle` CBOR, `COSE_Sign1`, JSONL lines, browser user/file payloads | Deterministic parser & replay engine | Hard size, depth, branch, span, and operation budgets; fail-closed rejection (`bad_json` or `invalid`) before any cryptographic replay. |
| **TB-2: Candidate vs. Validated Chain** | `candidate_store` (`public_explorer`, `anchoring_service`) | `validated_chain` (`validated_node`, `checkpoint_header_set`) | A candidate header is NEVER trusted on its own; Step 7b requires exact byte-match against `validated_chain` and valid PoW linkage, else returns `unverifiable` (Appendix D.7 Route 4). |
| **TB-3: Policy Configuration** | Per-case JSONL parameters from untrusted callers | Host CLI `--mode` / application policy | In `--mode strict`, consensus ceilings, `min_confirmations >= 6`, and deterministic wire rules cannot be weakened by weak defaults. Applications ingesting untrusted JSONL MUST NOT allow untrusted callers to inject arbitrary `mode` or `validated_chain` overrides. |
| **TB-4: Browser WASM Sandbox** | Hostile `.ots` / JSONL pasted into the offline web lab | User browser origin & DOM | Zero WASM host imports, `Content-Security-Policy: connect-src 'none'`, `#![forbid(unsafe_code)]`, zero dangerous DOM sinks. |

### 1.3 Explicit Non-Goals (Scope Boundaries)

1. **Not a Full Bitcoin Node:** This verifier validates 80-byte Bitcoin block headers, Proof-of-Work (`SetCompact`), chain linkage, `2016`-block retarget rules, cumulative chainwork (`GetBlockProof`), BIP-113 Median-Time-Past (`MTP`), and Merkle commitment paths. It does **not** download blocks, validate transaction scripts, maintain a UTXO set, or defend against a >50% Bitcoin network consensus reorganization.
2. **Not a COSE Signature Verifier (`draft-fassbender-scitt-time-anchor-08` §6.1):** In `cose_sign1` and `scitt_ots_ctt` input modes, this verifier parses RFC 9052 CBOR structure, enforces RFC 8949 / RFC 9052 §3 framing rules, and binds `protected`, `SHA-256(payload)`, `bstr(signature)`, and unprotected header `394` receipts (`RFC 9921` §3.1.1 / `RFC 9942` / `RFC 9943`). Cryptographic signature verification and issuer/Transparency Service key trust management remain the responsibility of the enclosing SCITT verifier.
3. **Not an OTS Calendar Client:** The verifier performs zero network I/O and never contacts external OpenTimestamps calendars to upgrade pending attestations (pending-only proofs deterministically yield `unverifiable` at Step 4).

---

## 2. Parser & Complexity Denial-of-Service (DoS) Vectors

| Threat Vector | Attack Mechanism | Mitigation & Hard Bounds |
| :--- | :--- | :--- |
| **Deep-Chain Stack Overflow** (`V16`) | Craft a `.ots` file containing 4,096+ chained `0x08` (`OpSHA256`) operations to trigger `RecursionError` or native stack overflow in recursive parsers. | Explicit iterative `O(1)` call-stack state machine (`work` stack + single `ops_stack`) in Python, Rust, and WASM; `DRAFT08_MAX_DEPTH = 4,608` and `STRICT_MAX_DEPTH = 256` (`STRICT_MAX_OPS_PER_BRANCH = 128`). |
| **Quadratic UTF-8 JSON Decoding (`O(N^2)`)** | Supply a large JSON string containing multibyte UTF-8 characters or escape sequences to trigger quadratic re-validation or repeated slice scans. | Single-pass `O(1)`-per-codepoint UTF-8 decoding in the zero-dependency Rust JSON parser (`json_min.rs`) with `MAX_JSON_DEPTH = 64` and rejection of lone UTF-16 surrogates. |
| **Shared-Prefix OTS DAG Amplification** | Construct a compact `.ots` proof with a long shared prefix followed by many `0xff` fork tags so naive branch-flattening replays or clones the shared prefix `O(B * D)` times. | Shared-prefix DAG deduplication and bounded total-operation / branch budgets across parsing and replay (`DRAFT08_MAX_BRANCHES = 256`, `STRICT_MAX_BRANCHES = 64`, plus aggregate op budget caps preventing quadratic expansion). |
| **`OpHexlify` (`0xf3`) Memory Bomb** (`N12` / `V13`) | Send a 65-byte `.ots` proof containing 30 consecutive `0xf3` opcodes expanding a 32-byte digest to `32 * 2^30 = 34.36 GB`. | Running digest buffer strictly capped at `HARDENED_MAX_RUNNING_BYTES = 4,096`; `--mode draft08` marks `0xf3` unevaluated without expanding (`unverifiable`), while `--mode strict` rejects any opcode outside `{0x08, 0xf0, 0xf1}` at Step 3 (`invalid`). |
| **Oversized CLI / WASM Payloads** | Pipe multi-hundred-megabyte JSONL lines or WASM buffers to exhaust heap or trigger OOM. | Hard **`4 MiB` (`4,194,304` bytes)** I/O cap enforced across CLI line ingestion and `MAX_WASM_IO_BYTES` in `wasm_prepare_input`; CBOR capped at `MAX_CBOR_BYTES = 262,144` and `MAX_CBOR_DEPTH = 16`; OTS proofs capped at `1 MiB` (`draft08`) / `64 KiB` (`strict`). |
| **WASM Dissector Output Blowup** | Feed a pathological branching `.ots` payload into `wasm_dissect_ots()` to blow up UI span tables or linear memory. | Bounded dissector span, varuint, growth-trace, and branch caps in `wasm_api.rs`; verified at `0` bytes steady-state heap delta across `120,000` single-instance WASM calls. |

---

## 3. Cross-Runtime Parity & Encoding-Malleability Attacks

A primary attack class against multi-implementation standards ecosystems is **parser differential split-brain**, where one verifier accepts a malformed proof as `valid` while another rejects it.

1. **LEB128 32-Bit JavaScript Shift Wrap (`N9` / `V09`, `V10`):**
   - *Attack:* Encode Bitcoin block height `957289` (`0x0e9b69`) as a 6-octet LEB128 varuint `e9 b6 ba 80 80 08`. JavaScript runtimes using 32-bit bitwise shifts (`value |= (b & 0x7f) << shift`) wrap `shift = 35` modulo `32` (`35 & 31 = 3`), computing `957289 | (8 << 3) == 957289`, whereas 64-bit/arbitrary-precision parsers decode `274,878,864,233`.
   - *Defense:* `--mode strict` enforces canonical minimal LEB128 varuints (`<= 5` octets, value `<= u32::MAX`, rejecting redundant trailing `0x00` continuation bytes as in `N10`) across Python, Rust, and WASM.
2. **Trailing Attestation Payload Bytes (`N15` / `V15`) & Non-SHA-256 Header Bypass (`N11` / `V12`):**
   - *Attack:* Append unconsumed bytes (`e9b63adeadbeef`) inside a Bitcoin attestation slice, or substitute `file_hash_op = 0x67` (`OpKeccak256`) with a 32-byte digest.
   - *Defense:* Both `draft08` and `strict` require exact slice exhaustion (`assert_eof`) on every attestation payload and strictly mandate `file_hash_op == 0x08` (`OpSHA256`) at Step 3.
3. **RFC 8949 & RFC 9052 §3 CBOR Framing-Space Ambiguity (`draft-templeman-scitt-framing-space-01`):**
   - *Attack:* Exploit encoding variations across the CBOR framing space — such as encoding an empty `COSE_Sign1` protected header bucket as `b"\xa0"` (a 1-byte empty CBOR map) instead of RFC 9052 §3's mandatory zero-length `b""`, using non-minimal integer prefixes (`0x18 0x01`), indefinite-length arrays/maps/byte strings, CBOR floating-point numbers, unsorted map keys, or **duplicate semantic CBOR keys** (e.g., identical keys encoded with different integer widths or repeated map entries).
   - *Defense:* `--mode strict` enforces RFC 8949 Section 4.2 Core Deterministic Encoding, rejects `b"\xa0"` as an empty protected header bucket per RFC 9052 §3, and rejects duplicate semantic CBOR map keys identically across Python, Rust, and WASM. Verified empirically across all **64 framing-space variants** (`verification_suite/experiment_cbor_framing_space_64.py`).
4. **RFC 8259 / I-JSON (`RFC 7493`) & Base64 Whitespace Parity (`N19`):**
   - *Attack:* Inject duplicate JSON object keys (relying on last-wins vs. first-wins parser discrepancy), floating-point numbers, `NaN`/`Infinity`, integers outside signed 64-bit `i64`, lone UTF-16 surrogates, or non-standard whitespace/padding in Base64 and hex fields.
   - *Defense:* Identical strict JSONL, hex, and Base64 parsers across Python, Rust, and WASM reject all non-conforming inputs deterministically with `{"error": "bad_json"}` or Step 0 `invalid`.

---

## 4. Consensus & Profile Downgrade Attacks

| Threat Vector | Attack Mechanism | Defense (`--mode strict`) |
| :--- | :--- | :--- |
| **Zero-Confirmation / Shallow-Reorg Downgrade** | Supply `"min_confirmations": 0` (or `1`..`5`) to accept unconfirmed or easily reorganized tip blocks as permanently anchored. | `--mode strict` enforces a hard **`min_confirmations >= 6`** floor regardless of lower caller-supplied values. |
| **Forged Low-Difficulty Mainnet Header Chain** (`N17A`–`N17B`) | Mine a synthetic private chain of 80-byte headers at minimal difficulty (`0x1d00ffff` or below) to forge an arbitrary historical timestamp. | Enforces Bitcoin Mainnet `powLimit` (`0x1d00ffff`), post-BIP113 (`h >= 419,328`) maximum target ceiling (`0x181fffff`), exact `SetCompact` negative sign-bit (`0x00800000`, `N14`) and overflow rejection, and optional operator `min_chainwork_hex` threshold. |
| **Difficulty Retarget Manipulation** (`N18A`–`N18B`) | Alter `nBits` mid-epoch (`(h % 2016) != 0`) or jump difficulty beyond `[0.25x, 4x]` across a `2016`-block boundary. | Enforces mid-epoch `nBits` immutability, `[0.25x, 4x]` retarget clamping, and exact Bitcoin Core `CalculateNextWorkRequired` (`GetCompact`/`SetCompact`) transitions when full `2016`-block windows are supplied. |
| **Cross-Ledger / Testnet Confusion & Eclipse Fork** | Substitute Testnet/Signet/Regtest headers or present a weaker side-fork ahead of the heaviest Mainnet chain. | Validates Genesis hash (`expected_ledger_id`, defaulting to Bitcoin Mainnet Genesis `000000000019d668...`), rejects non-contiguous/unlinked windows, and selects the heaviest cumulative `GetBlockProof` chainwork fork when `candidate_chains` are evaluated in `strict` mode. |
| **Miner Timestamp Backdating / Forward Skew** | Exploit Bitcoin's `nTime` variance (up to 2 hours ahead of network time or earlier than preceding blocks) to falsify monotonic temporal ordering. | Computes and verifies **BIP-113 Median-Time-Past (`MTP`)** over the 11 preceding headers and **Forward-MTP (`FMTP(H+5)`, `FMTP(H+6)`, `FMTP(H+11)`)** bounds (Z3 formally verified). |
| **Profile Downgrade (`strict` -> `draft08`)** | Rely on `--mode draft08` backward-compatible defaults when strict consensus & encoding enforcement is required. | The baseline `--mode draft08` vs. opt-in `--mode strict` boundary is explicitly returned in every verdict's `"mode"` field. Production verifiers requiring strict guarantees MUST invoke `--mode strict` and strip or reject untrusted per-case `"mode"` overrides at the ingress boundary. |

---

## 5. Browser WASM Zero-Egress & Memory Isolation

The offline browser verifier (`web/`) is engineered for air-gapped and high-assurance inspection:

1. **Zero Network Egress:** Enforced at both HTML `<meta>` and HTTP header (`web/server.py`) levels via:
   `Content-Security-Policy: default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; connect-src 'none'; object-src 'none'; base-uri 'self'` (plus `frame-ancestors 'none'` and `X-Content-Type-Options: nosniff` in `web/server.py`).
2. **Zero WASM Host Imports:** `web/scitt_time_anchor.wasm` (`wasm32-unknown-unknown`) exports only pure memory/evaluation functions (`wasm_prepare_input`, `wasm_output_ptr`, `wasm_output_len`, `wasm_evaluate_jsonl`, `wasm_dissect_ots`) and imports **0 host functions**, making outbound I/O or ambient browser authority structurally impossible from WASM.
3. **Zero Unsafe Rust & Zero Linear-Memory Leaks:** The core crate compiles with `#![forbid(unsafe_code)]`, the `wasm_cdylib` shim contains zero `unsafe` blocks (verified by CI), and `wasm_100k_leak_runner.mjs` confirms `0` bytes steady-state linear-memory growth over `120,000` calls inside a single `WebAssembly.Instance`.
4. **Zero Dangerous DOM Sinks & Zero External Assets:** `.github/workflows/pages.yml` statically verifies relative local paths and forbids external CDN/font URLs in `web/`; UI rendering uses safe DOM APIs without `eval` or unsanitized HTML injection.

---

## 6. Threat-to-Verification Mapping

| Threat Category | Automated Evidence in Repository |
| :--- | :--- |
| Conformance & Negative Wire Vectors (`N1`–`N20+`) | `verification_suite/test_appendix_d_conformance.py` (`Python == Rust == WASM`) |
| CBOR Framing Space (`RFC 8949` / `RFC 9052 §3`) | `verification_suite/experiment_cbor_framing_space_64.py` (64 variants across 3 engines) |
| Consensus, Retarget, `SetCompact`, & MTP Invariants | `verification_suite/prove_z3_invariants.py` (Microsoft Z3 SMT `UNSAT` proofs) |
| Cross-Engine Split-Brain & Encoding Parity | `verification_suite/run_50k_triple_differential.py` (`50,000` vectors, `0` divergences) |
| Adversarial Mutation & Crash Resistance | `verification_suite/test_100k_mutation_fuzz.py` (`100,000` hostile mutations, `0` crashes) |
| WASM Deep-Stack & Heap Stability | `verification_suite/wasm_batch_eval.mjs --stress-deep` & `wasm_100k_leak_runner.mjs` (`120,000` calls, `0` B delta) |
| Supply-Chain Integrity, Reproducibility & Forensics | `.github/workflows/ci.yml` (WASM double-build, artifact forensics, anti-obfuscation, version parity), `scorecard.yml`, `reuse.yml`, `release.yml`, `sbom.cdx.json`, `openvex.json`, `osps-baseline.json`, `SHA256SUMS.txt` |
