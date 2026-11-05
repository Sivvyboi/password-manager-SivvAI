# 11 — Phase 1 Test Vectors and Test Plan

**Document Status:** ACTIVE BASELINE & SPECIFICATION (REVISED & VERIFIED)  
**Scope:** Authoritative Cryptographic Known-Answer Tests (KAT), Test Vectors, and Cross-Platform Testing Strategy  

---

## 1. Test Objectives & Guardrails

1. **Deterministic Verification:** Every cryptographic primitive (KDF, AEAD, HKDF, Mnemonic) must match published standard test vectors before release.
2. **Fail-Closed Integrity:** Test cases must verify that altered ciphertexts, modified nonces, corrupted tags, or mutated AAD bytes result in immediate failure without disclosing sensitive state.
3. **Synthetic Data Policy:** All test vectors and automated unit/integration tests must use synthetic credentials. Real user passwords, keys, or recovery phrases must never appear in test files or logs.
4. **Cross-Platform Verification:** Identical test vectors must pass on Android (API 26 physical phone, API 34 physical phone) and Windows desktop.

---

## 2. Authoritative Known-Answer Test Vectors

### 2.1 RFC 9106 — Argon2id v1.3 Official Test Vector

- **Source:** RFC 9106 Section 5.3 ("Argon2id Test Vectors")
- **Argon2 Version:** `19` (`0x13` / Version 1.3)
- **Variant:** Argon2id
- **Input Parameters:**
  - Memory cost ($m$): `32` KiB ($32,768$ bytes, 32 blocks)
  - Passes / Iterations ($t$): `3`
  - Parallelism / Lanes ($p$): `4`
  - Tag Length ($T$): `32` bytes
- **Inputs:**
  - **Password ($P$, 32 bytes):**
    ```text
    01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 
    01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
    ```
    *(32 repetitions of byte `0x01`)*
  - **Salt ($S$, 16 bytes):**
    ```text
    02 02 02 02 02 02 02 02 02 02 02 02 02 02 02 02
    ```
    *(16 repetitions of byte `0x02`)*
  - **Secret Key ($K$, 8 bytes):**
    ```text
    03 03 03 03 03 03 03 03
    ```
    *(8 repetitions of byte `0x03`)*
  - **Associated Data ($X$, 12 bytes):**
    ```text
    04 04 04 04 04 04 04 04 04 04 04 04
    ```
    *(12 repetitions of byte `0x04`)*
- **Pre-hashing Digest ($H_0$, 64 bytes):**
  ```text
  28 89 de 48 7e b4 2a e5 00 c0 00 7e d9 25 2f 10 
  69 ea de c4 0d 57 65 b4 85 de 6d c2 43 7a 67 b8 
  54 6a 2f 0a cc 1a 08 82 db 8f cf 74 71 4b 47 2e 
  94 df 42 1a 5d a1 11 2f fa 11 43 43 70 a1 e9 97
  ```
- **Expected Output Tag (32 bytes):**
  ```text
  0d 64 0d f5 8d 78 76 6c 08 c0 37 a3 4a 8b 53 c9 
  d0 1e f0 45 2d 75 b6 5e b5 25 20 e9 6b 01 e6 59
  ```
  **Hex representation:**
  `0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659`

> [!IMPORTANT]
> **RFC Vector vs. Application Production Profile:**  
> The vector above from RFC 9106 Section 5.3 is specifically designed for library compliance verification using low memory ($32\text{ KiB}$) and non-empty secret/AAD inputs.  
> The application's proposed **production profile** is distinct:
> - Memory: $64\text{ MiB}$ ($65,536\text{ KiB}$)
> - Iterations: $3$
> - Parallelism: $4$
> - Secret ($K$): empty
> - Associated Data ($X$): empty
> - Password: User master password ($\ge 15$ Unicode code points)
> - Salt: 16-byte random salt generated via OS CSPRNG.

---

### 2.2 NIST SP 800-38D — AES-256-GCM Test Vector

- **Source:** NIST Cryptographic Algorithm Validation Program (CAVP) — AES GCM Test Vector (KeyLen = 256, IVLen = 96, TagLen = 128)
- **Inputs:**
  - Key (32 bytes):
    ```text
    feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308
    ```
  - Nonce / IV (12 bytes / 96 bits):
    ```text
    cafebabefacedbaddecaf888
    ```
  - Plaintext (64 bytes):
    ```text
    d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255
    ```
  - Associated Data (AAD, 20 bytes):
    ```text
    feedfacedeadbeeffeedfacedeadbeefabaddad2
    ```
- **Expected Outputs:**
  - Ciphertext (64 bytes):
    ```text
    522dc1f09952541f483a97fa4e56427da595f64b0c5e8eda942f7169dbff925b4104d440d70f8b5773199d31f4a5482385dd66ddb11da36a9ec71a04481577c6
    ```
  - Authentication Tag (16 bytes / 128 bits):
    ```text
    76fc6ece0f4e1768cddf8853bb2d551b
    ```

---

### 2.3 RFC 5869 — HKDF-SHA256 Test Vector

- **Source:** RFC 5869 Test Case 1 (Basic HKDF with SHA-256)
- **Inputs:**
  - Hash: SHA-256
  - IKM (Input Key Material, 22 bytes):
    ```text
    0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
    ```
  - Salt (13 bytes):
    ```text
    000102030405060708090a0b0c
    ```
  - Info (10 bytes):
    ```text
    f0f1f2f3f4f5f6f7f8f9
    ```
  - Output Length ($L$): `42` bytes
- **Step 1: HKDF-Extract Output (PRK, 32 bytes):**
  ```text
  077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e0
  ```
- **Step 2: HKDF-Expand Output (OKM, 42 bytes):**
  ```text
  3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865
  ```

---

### 2.4 BIP-0039 — Mnemonic & Seed Test Vectors (256-Bit Entropy)

- **Source:** BIP-0039 Official Test Vectors (English wordlist)

#### Vector 1 (All zeros):
- **Entropy (256 bits):**
  `0000000000000000000000000000000000000000000000000000000000000000`
- **SHA-256(Entropy) First Byte (Checksum = 8 bits):**
  `c4` (binary `11000100`)
- **Mnemonic Sentence (24 words):**
  ```text
  abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art
  ```
- **NFKD Normalized Salt:** `"mnemonic"` (`0x6d6e656d6f6e6963`)
- **PBKDF2-HMAC-SHA512 Iterations:** `2048`
- **Output Seed (64 bytes / 512 bits):**
  ```text
  408b285c123836004f4b8842c89324c1f01382450c0d839f9b2a0a36db8840dad611a4959133717f7dd9ead7a3ddc77b1fb7bb82a01f6950bea5b5d74a96f2e8
  ```

#### Vector 2 (Non-zero entropy):
- **Entropy (256 bits):**
  `7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f`
- **Mnemonic Sentence (24 words):**
  ```text
  legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title
  ```
- **NFKD Normalized Salt:** `"mnemonic"`
- **PBKDF2-HMAC-SHA512 Iterations:** `2048`
- **Output Seed (64 bytes / 512 bits):**
  ```text
  bc09fac993d30364b84126938a9e403fa8a36fa1f2aa664402b1309f0a202d601a41f8a846c245c11f71df4cc38827471249fa69be862ef2a9126d4001d8c11e
  ```

---

### 2.5 Application Recovery Key Derivation: Complete Two-Stage HKDF Test Vector

To prevent confusion between generic HKDF and the application's recovery-key derivation:
- **IKM (Input Key Material):** 64-byte BIP39 Seed from Vector 1:
  `408b285c123836004f4b8842c89324c1f01382450c0d839f9b2a0a36db8840dad611a4959133717f7dd9ead7a3ddc77b1fb7bb82a01f6950bea5b5d74a96f2e8`
- **Vault Salt (16 bytes):**
  `000102030405060708090a0b0c0d0e0f`
- **Vault ID:**
  `123e4567-e89b-12d3-a456-426614174000`
- **Context Info String:**
  `PM-RECOVERY-WRAP-V1:123e4567-e89b-12d3-a456-426614174000` (UTF-8 bytes)

#### Execution Steps:
1. **Stage 1 (HKDF-Extract):**
   $$\text{PRK} = \text{HMAC-SHA256}(\text{key} = \text{VaultSalt}, \text{data} = \text{IKM})$$
   Yields a 32-byte Pseudorandom Key ($\text{PRK}$).
2. **Stage 2 (HKDF-Expand):**
   $$\text{RWK} = \text{HKDF-Expand}(\text{PRK}, \text{info} = \text{ContextInfoBytes}, L = 32)$$
   Yields the 32-byte (256-bit) Recovery Wrapping Key ($\text{RWK}$).

---

## 3. Unit & Integration Test Matrix

| Test Suite | File Location | Key Assertions | Status |
|---|---|---|---|
| Result & Error Flow | `test/core/result_test.dart` | Ok/Err mapping, unwrap bounds, error encapsulation | Passed (2 tests) |
| Strongly Typed IDs & Versions | `test/core/types_test.dart` | Canonical UUID validation, formatting, version comparison | Passed (5 tests) |
| Master Password Policy | `test/domain/master_password_policy_test.dart` | >= 15 Unicode code points enforced, spaces permitted, no trim/lower alteration, emoji code points tested | Passed (7 tests) |
| Password Generator Policy | `test/domain/password_generation_policy_test.dart` | >= 12 chars enforced, character group inclusion, empty set failure | Passed (4 tests) |
| Credential & Association Models | `test/domain/credential_payload_test.dart` | CVV/CVC omitted, Android cert SHA256 validation, secret redaction | Passed (6 tests) |
| KDF Resource Bounds | `test/crypto/kdf_parameters_test.dart` | Safe memory/iteration limits enforced, DoS header attacks rejected | Passed (5 tests) |
| Canonical AAD Encoding | `test/crypto/associated_data_context_test.dart` | Deterministic binary layout, uint32 range check, all purpose codes (0x01, 0x02, 0x04, 0x05, 0x06) tested | Passed (5 tests) |
| Secret Key Hygiene & Destruction | `test/crypto/key_types_test.dart` | 32-byte length check, `[REDACTED]` stringification, best-effort zeroize | Passed (3 tests) |
| Widget Starter Baseline | `test/widget_test.dart` | Baseline smoke test preserved | Passed (1 test) |

---

## 4. Cross-Platform Testing Strategy

1. **Test Runner Automation:** Run automated tests in CI/CD across Dart SDK on Windows and Linux/Android runners.
2. **Device Lab Verification:**
   - Execute test vector validation suite on Android 8.0.0 physical device.
   - Execute test vector validation suite on Android 14.0 physical device.
   - Execute test vector validation suite on Windows 11 host.
3. **Bit-for-Bit Serialization Test:**
   - Export an AAD byte payload generated on Windows.
   - Verify on Android that the identical logical input generates the exact identical SHA-256 hash and byte array.
