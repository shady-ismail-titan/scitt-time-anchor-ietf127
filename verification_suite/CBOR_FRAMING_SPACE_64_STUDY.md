# 64-Variant CBOR Framing-Space Equivalence & Determinism Study

**Author:** Shady Ismail
**Verifier Release:** `v2.0.0` (Python 3 stdlib, Native Rust `#![forbid(unsafe_code)]`, Offline WebAssembly)
**Specifications:** `draft-templeman-scitt-framing-space-01`, `draft-fassbender-scitt-time-anchor-08`, RFC 8949 Section 4.2, RFC 9052 Section 3, RFC 9921 Section 3.1.1, RFC 9942 Section 8

## 1. Experimental Design

A single semantic SCITT `COSE_Sign1` transparent statement carrying an RFC 9942 Section 8 header `394` receipt and `kid` (`4`) was encoded across all **$2^6 = 64$** combinations of six orthogonal RFC 8949 / RFC 9052 framing freedoms:

| Bit | Axis | Canonical (`0`) | Non-Canonical (`1`) |
| --- | --- | --- | --- |
| 0 | COSE Tag 18 | `0xd2` (1 B) | `0xd8 0x12` (2 B overlong) |
| 1 | Outer Array(4) Length | `0x84` (1 B) | `0x98 0x04` (2 B overlong) |
| 2 | Empty Protected Header (RFC 9052 §3) | `0x40` (`b""`) | `0x41 0xa0` (`b"\xa0"`) |
| 3 | Unprotected Map Key Order | `{4: kid, 394: [receipt]}` | `{394: [receipt], 4: kid}` |
| 4 | Payload `bstr` Length (37 B) | `0x58 0x25` | `0x59 0x00 0x25` |
| 5 | Signature `bstr` Length (64 B) | `0x58 0x40` | `0x59 0x00 0x40` |

## 2. Empirical Results

- **Wire & Outer-Hash Explosion:** All **64 / 64** encodings are pairwise distinct (`199` B to `204` B) and yield **64 / 64** distinct outer `SHA-256` data hashes.
- **Parser Acceptance:**
  - Permissive `draft08` CBOR/COSE decoder: accepts **64 / 64** (`100%`).
  - `v2.0.0 --mode strict` deterministic decoder (RFC 8949 §4.2 + RFC 9052 §3): accepts **1 / 64** (exclusively variant `000000`) and rejects **63 / 64** (`98.44%`) at Step 0.
- **End-to-End Verification Matrix (`256` variant cases + `10` relay cases = `266` cases per engine):**

| Input Mode & Profile | Valid (Step 11) | Invalid Step 0 (CBOR Gate) | Invalid Step 2 (`HASH_MISMATCH`) |
| --- | ---: | ---: | ---: |
| `cose_sign1` + `draft08` | `1 / 64` | `0 / 64` | `63 / 64` |
| `cose_sign1` + `strict` | `1 / 64` | `63 / 64` | `0 / 64` |
| `scitt_ots_ctt` + `draft08` | `32 / 64` | `0 / 64` | `32 / 64` |
| `scitt_ots_ctt` + `strict` | `1 / 64` | `63 / 64` | `0 / 64` |

- **Imprint Collapse & RFC 9052 §3 Finding:** Under `scitt_ots_ctt`, the 5 outer framing axes (Tag 18 width, Array length width, Unprotected key order, Payload length width, Signature length width) collapse **32** distinct outer `SHA-256` hashes into **1** single invariant commitment. However, encoding an empty protected header as `b"\xa0"` instead of `b""` (Axis 2) splits the imprint into **2** distinct digests unless RFC 9052 §3 is enforced — directly motivating the `v2.0.0 --mode strict` rejection of `protected_hdr == b"\xa0"`.
- **Unprotected Header Relay Invariance (`5` transit hops):**
  - Raw outer `cose_sign1`: **0 / 5** valid (breaks with Step 2 `HASH_MISMATCH` on every relay mutation).
  - `scitt_ots_ctt` (`--mode strict`): **5 / 5** valid (`100%` invariant while keeping RFC 9942 header `394` receipts cryptographically bound).
- **Triple-Engine Parity:** **0 divergences** across all `266` cases evaluated independently on Python, Native Rust, and Offline WebAssembly (`elapsed: 100.25 ms`).
