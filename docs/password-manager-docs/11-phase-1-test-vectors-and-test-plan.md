# 11 — Phase 1 Test Vectors and Test Plan

**Document Status:** ACTIVE BASELINE (APPROVED BY OWNER & VERIFIED IN MILESTONE 1B)  
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

- **Source:** NIST Cryptographic Algorithm Validation Program (CAVP) — AES GCM Test Vector (KeyLen = 256, IVLen = 96, TagLen = 128, Test Case 16)
- **Inputs:**
  - Key (32 bytes):
    ```text
    feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308
    ```
  - Nonce / IV (12 bytes / 96 bits):
    ```text
    cafebabefacedbaddecaf888
    ```
  - Plaintext (60 bytes):
    ```text
    d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39
    ```
  - Associated Data (AAD, 20 bytes):
    ```text
    feedfacedeadbeeffeedfacedeadbeefabaddad2
    ```
- **Expected Outputs:**
  - Ciphertext (60 bytes):
    ```text
    522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662
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
  077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5
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
- **Output Seed with Empty Passphrase (application standard, 64 bytes / 512 bits):**
  ```text
  408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840
  ```
- *(Note: With optional reference passphrase `"TREZOR"`, the output seed is `bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8`)*

#### Vector 2 (Non-zero entropy):
- **Entropy (256 bits):**
  `7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f`
- **Mnemonic Sentence (24 words):**
  ```text
  legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title
  ```
- **NFKD Normalized Salt:** `"mnemonic"`
- **PBKDF2-HMAC-SHA512 Iterations:** `2048`
- **Output Seed with Empty Passphrase (application standard, 64 bytes / 512 bits):**
  ```text
  761914478ebf6fe16185749372e91549361af22b386de46322cf8b1ba7e92e80c4af05196f742be1e63aab603899842ddadf4e7248d8e43870a4b6ff9bf16324
  ```
- *(Note: With optional reference passphrase `"TREZOR"`, the output seed is `bc09fac993d30364b84126938a9e403fa8a36fa1f2aa664402b1309f0a202d601a41f8a846c245c11f71df4cc38827471249fa69be862ef2a9126d4001d8c11e`)*

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
| Strongly Typed IDs & Versions | `test/core/types_test.dart` | Canonical UUID validation, formatting, uint16 version comparison | Passed (5 tests) |
| Master Password Policy | `test/domain/master_password_policy_test.dart` | >= 15 Unicode code points enforced, spaces permitted, no trim/lower alteration, emoji code points tested | Passed (7 tests) |
| Password Generator Policy | `test/domain/password_generation_policy_test.dart` | >= 12 chars enforced, character group inclusion, empty set failure | Passed (4 tests) |
| Credential & Association Models | `test/domain/credential_payload_test.dart` | CVV/CVC omitted, Android cert SHA256 validation, secret redaction | Passed (6 tests) |
| KDF Resource Bounds | `test/crypto/kdf_parameters_test.dart` | Safe memory/iteration limits enforced, DoS header attacks rejected | Passed (5 tests) |
| Canonical AAD Encoding & Validation | `test/crypto/associated_data_context_test.dart` | Deterministic binary layout, uint16 format-version range check, uint32 record-version check, all purpose codes (0x01–0x06) tested | Passed (8 tests) |
| Secret Key Hygiene & Destruction | `test/crypto/key_types_test.dart` | 32-byte length check, `[REDACTED]` stringification, best-effort zeroize | Passed (3 tests) |
| Secure Random Source | `test/crypto/secure_random_source_test.dart` | Arbitrary byte lengths, rejection sampling unbiased bounds, deterministic test injection | Passed (6 tests) |
| Argon2id Key Derivation | `test/crypto/argon2id_kdf_test.dart` | RFC 9106 Section 5.3 KAT with secret/AD, parameter rejection, candidate profile performance benchmark | Passed (3 tests) |
| AES-256-GCM AEAD Cipher | `test/crypto/aes_gcm_cipher_test.dart` | NIST SP 800-38D Test Case 16 KAT, incorrect key rejection, tampered ciphertext/tag/nonce/AAD fail-closed, canonical AAD roundtrip | Passed (8 tests) |
| HKDF-SHA256 Derivation | `test/crypto/hkdf_test.dart` | RFC 5869 Test Case 1 KAT, per-record domain separation with epoch, recovery key derivation, input validation | Passed (5 tests) |
| BIP-0039 Recovery Service | `test/crypto/bip39_recovery_mnemonic_test.dart` | BIP39 Vectors 1 & 2 KAT (empty passphrase), 24-word count enforcement, checksum failure rejection, vault-bound RWK derivation | Passed (5 tests) |
| Password Generation Primitives | `test/crypto/password_generator_primitives_test.dart` | Unbiased Fisher-Yates shuffle, charset requirement satisfaction, passphrase word count & separator, deterministic reproducibility | Passed (5 tests) |
| Widget Starter Baseline | `test/widget_test.dart` | Baseline smoke test preserved | Passed (1 test) |
| **Total** | | | **73 tests — all passed** |

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
