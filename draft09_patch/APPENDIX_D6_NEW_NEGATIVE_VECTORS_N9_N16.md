# Non-Normative Implementer Feedback: Suggested Appendix D.6 & SCITT `COSE_Sign1` Vectors (`C1`, `N9`–`N16`)

**Target Specification**: `draft-fassbender-scitt-time-anchor-08` (*"Umarise's Bitcoin-Anchored Temporal Proofs"*, Informational, `23 October 2026`)
**Purpose**: Companion negative, boundary, and cross-runtime divergence vectors extending Appendix D.6 (`N1`–`N8` in our Pass 1 conformance harness) with exact wire bytes observed across 7 independent external implementations and our Clean-Room Triple Engine (`Python 3`, `#![forbid(unsafe_code)]` `Rust`, and `< 45 KB` gzipped `wasm32-unknown-unknown`).

---

## Summary Table (`N9`–`N16`)

| Vector ID | Wire Mutation / Boundary Condition | Normative Section | Baseline `draft-08` Outcome | Candidate `-09` (`strict`) Outcome | Observed External Implementation Divergence |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`N9`** | 6-octet LEB128 height `e9b6ba808008` on Appendix D.5 Vector 1 (`Block 957289`) | §3.4.2, §4.1 Steps 3 & 6 | `unverifiable` (`H = 274,878,864,233`) | `invalid` (Step 3: non-canonical `> 5`-byte `varuint`) | `verify-anchoring.org` & `npm opentimestamps` (`shift & 31`) decode **`H = 957,289`**! |
| **`N10`** | Overlong 4-octet LEB128 height `e9b6ba00` (redundant trailing `0x00` continuation) | §3.4.2, §4.1 Step 3 | `valid` (`H = 957,289`) | `invalid` (Step 3: overlong LEB128 encoding) | Accepted as `valid (H=957289)` by `EMILIA (-06)`, `CryptoGeekPT (-03)`, and `DPS (-08)`. |
| **`N11`** | Non-SHA-256 `file_hash_op = 0x67` (`OpKeccak256`) with matching 32-byte digest | §3.4.2 F2, §4.1 Step 3 | `invalid` (Step 3: `file_hash_op != 0x08`) | `invalid` (Step 3: `file_hash_op != 0x08`) | **`CryptoGeekPT (-03)` returns `valid (H=957289)`** (`verify.py:51-55` omits header hash-op check). |
| **`N12`** | `65`-octet `.ots` proof carrying `30` consecutive `0xf3` (`OpHexlify`) opcodes | §4.1 Steps 3 & 5 | `unverifiable` (Step 5 -> NULL, Step 8 unevaluated) | `invalid` (Step 3: disallowed opcode & `4,096 B` cap) | Unbounded replay expands `32 B` to `34.36 GB` (`32 * 2^30`); `EMILIA (-06)` returns `invalid` while `CryptoGeekPT` & `DPS` return `unverifiable`. |
| **`N13`** | Mid-path `0x02` (`OpSHA1`) 160-bit narrow-pipe followed by `0x08` (`OpSHA256`) | §4.1 Step 5, §8.8, §8.10 | `unverifiable` (Step 5 -> NULL, Step 8 unevaluated) | `invalid` (Step 3: strict `{0x08, 0xf0, 0xf1}` allowlist) | Preserves uniform `2^128` Grover hash security floor with zero signing keys (§8.10). |
| **`N14`** | Adversarial 80-byte Bitcoin header with `nBits = 0x1dfbffff` (IEEE/compact sign bit `0x00800000` set) | §4.1 Step 7b (`VALIDATE-HEADER-ON-CHAIN`) | `unverifiable` (header rejected by `SetCompact`) | `unverifiable` (header rejected by `SetCompact`) | **`DPS (-08)` `bits_to_target` (`verify_anchor.py:123`) masks `bits & 0xFFFFFF`**, treating negative `0x1dfbffff` as a positive target! |
| **`N15`** | Extra trailing octets inside Bitcoin attestation payload (`len = 0x07`, payload `e9b63adeadbeef`) | §3.4.2, §4.1 Step 3 | `invalid` (Step 3: unconsumed payload bytes) | `invalid` (Step 3: unconsumed payload bytes) | **`DPS (-08)` (`verify_anchor.py:180`) returns `valid (H=957289)`**, ignoring `deadbeef` inside the attestation slice. |
| **`N16`** | `RFC 9943` `COSE_Sign1` statement after attaching `RFC 9942` receipt(s) in unprotected header `394` | §3.2, §6.3, §6.4 (`RFC 9921` §3.1.1) | `invalid` on raw outer `COSE_Sign1` (Step 2 `HASH_MISMATCH`) | `valid` under `scitt_ots_ctt` (`RFC 9921` §3.1.1 `bstr(signature)` + header `394` tuple) | Confirmed against `WEXP` `scitt-receipt-boundary-001` (`signed-statement.cose`, `836 B`) and live `ts.isoluce.net/checkpoint` (`219 B`). |

---

## Detailed Vector Specifications

### `N9` — 6-Octet LEB128 Cross-Runtime Split-Brain (`0xe9b6ba808008`)
- **Construction**: Take `Appendix D.5 Vector 1` (`1,877` octets, `artifact_bytes = "umarise-conformance-v1-alpha\n"`, `claimed_hash = a183f624efbbda7d6208b9b5a6f9b0c2c95d90382eb209c44a1131954071f30b`) and replace the 4-octet Bitcoin attestation payload (`03 e9 b6 3a`, encoding `H = 957289`) with the 7-octet sequence `06 e9 b6 ba 80 80 08`.
- **Arithmetic Mechanism**:
  - In `javascript-opentimestamps` (`StreamDeserializationContext.readVaruint`, shipped inside `https://verify-anchoring.org/vendor/opentimestamps.min.js`), `value |= (byte & 0x7f) << shift` wraps `shift = 35` mod `32` (`35 & 31 == 3`). Because `0x08 << 3 == 0x40` and bit `6` (`0x40`) is already `1` in `957289 = 0x0e9b69`, JavaScript evaluates `957289 | 64 == 957289` and looks up **real Bitcoin Mainnet Block `957289`**!
  - In Python, Rust, and Go, `957289 + (8 << 35) = 274,878,864,233`.
- **Expected Outcome**:
  - Baseline `draft-08`: `unverifiable` (Step 7b: no header at height `274,878,864,233`).
  - Candidate `-09` (`strict` profile): `invalid` (Step 3: `OTS-DESERIALIZE` rejects `> 5`-octet / `> u32::MAX` LEB128).

### `N10` — Overlong 4-Octet LEB128 Trailing Zero (`0xe9b6ba00`)
- **Construction**: Replace `03 e9 b6 3a` in `Appendix D.5 Vector 1` with `04 e9 b6 ba 00` (setting continuation bit `0x80` on the third byte `0x3a -> 0xba` and appending `0x00`).
- **Expected Outcome**:
  - Baseline `draft-08`: `valid` (`H = 957289`).
  - Candidate `-09` (`strict` profile): `invalid` (Step 3: non-canonical redundant zero continuation octet).

### `N11` — Non-SHA-256 `file_hash_op` (`0x67` `OpKeccak256`)
- **Construction**: Replace byte offset `32` (`file_hash_op = 0x08`) in `Appendix D.5 Vector 1` with `0x67` (`OpKeccak256`), keeping the 32-octet digest and Merkle path intact.
- **Expected Outcome**: `invalid` at Step 3 (`parsed.file_hash_op != SHA-256`) in both `draft-08` and `strict`.

### `N12` — `65`-Octet `OpHexlify` (`0xf3`) Memory Amplification Witness
- **Wire Hex (`109` octets total with 32-byte digest)**:
  `004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294` (31B magic)
  || `01` (version 1) || `08` (SHA-256) || `a183f624efbbda7d6208b9b5a6f9b0c2c95d90382eb209c44a1131954071f30b` (32B msg)
  || `f3` repeated `30` times (`30` octets)
  || `00 0588960d73d71901 03 e9b63a` (13B Bitcoin attestation for `957289`).
- **Expected Outcome**:
  - Baseline `draft-08`: `unverifiable` (Step 5 `OTS-REPLAY` refuses `0xf3` without allocating `32 * 2^30 = 34.36 GB`; Step 8 marks branch `unsupported`).
  - Candidate `-09` (`strict` profile): `invalid` (Step 3 opcode allowlist `{0x08, 0xf0, 0xf1}`).

### `N13` — Mid-Path `160`-Bit `OpSHA1` (`0x02`) Narrow-Pipe Witness
- **Wire Hex**:
  31B magic || `01 08` || 32B msg || `02` (`OpSHA1`, compressing state to 20 bytes / 80-bit collision bound) || `08` (`OpSHA256`, restoring 32-byte width) || `00 0588960d73d71901 03 e9b63a`.
- **Expected Outcome**:
  - Baseline `draft-08`: `unverifiable` (Step 5 refuses `0x02`).
  - Candidate `-09` (`strict` profile): `invalid` (Step 3).

### `N14` — Negative `SetCompact` Sign-Bit Header (`nBits = 0x1dfbffff`)
- **Construction**: Supply an 80-byte synthetic candidate block header whose `nBits` field (`bytes[72..76]` little-endian = `ff ff fb 1d`) sets the compact sign bit `0x00800000`.
- **Expected Outcome**: `VALIDATE-HEADER-ON-CHAIN` rejects the chain segment (`NULL`), yielding `unverifiable` at Step 7b/8. Implementations MUST NOT mask `nBits & 0x00ffffff` without rejecting `(nBits & 0x00800000) != 0`.

### `N15` — Unconsumed Trailing Bytes Inside Bitcoin Attestation Payload (`e9b63adeadbeef`)
- **Construction**: Replace `03 e9 b6 3a` at the Bitcoin attestation of `Appendix D.5 Vector 1` with `07 e9 b6 3a de ad be ef` (`payload_len = 7`, height `957289` consumes 3 bytes, leaving 4 unconsumed trailing bytes `deadbeef` inside the attestation payload).
- **Expected Outcome**: `invalid` at Step 3 (`OTS-DESERIALIZE` requires exact exhaustion of every attestation payload slice, matching upstream `[OTS]` `payload_ctx.assert_eof()`).

### `N16` — `RFC 9943` `COSE_Sign1` Unprotected Header `394` (`[ + COSE_Receipt ]`) Relay
- **Construction**: Anchor a `COSE_Sign1` Signed Statement, then attach one or more `RFC 9942` receipts in unprotected header label `394` (`receipts = [ + COSE_Receipt ]`) to form a Transparent Statement (`RFC 9943`).
- **Expected Outcome**:
  - Raw outer `COSE_Sign1` mode (`input_mode = "cose_sign1"`): `invalid` at Step 2 (`HASH_MISMATCH`) because outer CBOR bytes changed.
  - Immutable imprint mode (`input_mode = "scitt_ots_ctt"`, binding `protected`, `SHA-256(payload)`, `bstr(signature)` per `RFC 9921` §3.1.1, and all receipts in header `394`): `valid` with `0` hash mismatches across unprotected metadata transport updates.


### Byte-Exact `COSE_Sign1` (`Tag 18`) Reference Hex Vectors (`C1` Transparent Statement vs `N16` Unprotected Transport Relay)
- **`C1` Pre-Relay `COSE_Sign1` Transparent Statement (`188` octets, CBOR Tag `18`, receipt in header `394`)**:
  - **Hex**: `d28447a2012619018b01a119018a81584ad28443a10126a0f65840aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa581d756d61726973652d636f6e666f726d616e63652d76312d616c7068610a584030440220111111111111111111111111111111111111111111111111111111111111111102202222222222222222222222222222222222222222222222222222`
  - **Outer `SHA-256(C1)`**: `3f32539204f37966374ab16a22aec979123d87353d5bc045bb0dcd59806f60b0`
  - **Canonical `scitt_ots_ctt` Imprint `SHA-256(TBS)`**: `eb4d3df8932cda0a586f9689dd9e58543ea6228fbee7d00bbfe79937a99e409e`
- **`N16` Post-Relay `COSE_Sign1` Transparent Statement (`203` octets, adding unprotected relay metadata label `4`)**:
  - **Hex**: `d28447a2012619018b01a2044d656467652d72656c61792d303119018a81584ad28443a10126a0f65840aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa581d756d61726973652d636f6e666f726d616e63652d76312d616c7068610a584030440220111111111111111111111111111111111111111111111111111111111111111102202222222222222222222222222222222222222222222222222222`
  - **Outer `SHA-256(N16)`**: `2ed7f646fc8fc1d36093b76b7b021f4f3e9d5770ee57de9bbce8ceeea2f1298a` (*mutated!* Breaks naive outer-envelope `.ots` hash `Step 2 HASH_MISMATCH`)
  - **Canonical `scitt_ots_ctt` Imprint `SHA-256(TBS)`**: `eb4d3df8932cda0a586f9689dd9e58543ea6228fbee7d00bbfe79937a99e409e` (*100% identical to `C1`!* Preserves temporal anchor across unprotected transport header relays while still binding `protected`, `SHA-256(payload)`, `bstr(signature)`, and header `394` receipts per `RFC 9921` §3.1.1)
