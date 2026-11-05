# 11 — Phase 1 Test Vectors and Test Plan

**Document Status:** ACTIVE BASELINE & SPECIFICATION  
**Scope:** Authoritative Cryptographic Known-Answer Tests (KAT), Test Vectors, and Cross-Platform Testing Strategy  

---

## 1. Test Objectives & Guardrails

1. **Deterministic Verification:** Every cryptographic primitive (KDF, AEAD, HKDF, Mnemonic) must match published standard test vectors before release.
2. **Fail-Closed Integrity:** Test cases must verify that altered ciphertexts, modified nonces, corrupted tags, or mutated AAD bytes result in immediate failure without disclosing sensitive state.
3. **Synthetic Data Policy:** All test vectors and automated unit/integration tests must use synthetic credentials. Real user passwords, keys, or recovery phrases must never appear in test files or logs.
4. **Cross-Platform Verification:** Identical test vectors must pass on Android (API 26 physical phone, API 34 physical phone) and Windows desktop.

---

## 2. Authoritative Known-Answer Test Vectors

### 2.1 RFC 9106 — Argon2id v1.3 Test Vector

- **Source:** RFC 9106 Section 5.3 (Argon2id test vector)
- **Inputs:**
  - Password: `password` (`0x70617373776f7264`)
  - Salt: `somesalt` (`0x736f6d6573616c74`)
  - Iterations ($t$): `2`
  - Memory ($m$): `65536` ($64\text{ MiB}$)
  - Parallelism ($p$): `4`
  - Tag Length: `32` bytes
  - Secret / Associated Data: empty
- **Expected Output (32-byte Hex):**
  ```text
  0d640df58d78766c08c037a34a8b53e9d099de8d837b988c92ec58cfbe219a3b
  ```

---

### 2.2 NIST SP 800-38D — AES-256-GCM Test Vector

- **Source:** NIST Cryptographic Algorithm Validation Program (CAVP) — AES GCM Test Vector (KeyLen = 256, IVLen = 96, TagLen = 128)
- **Inputs:**
  - Key:
    ```text
    feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308
    ```
  - Nonce (96-bit IV):
    ```text
    cafebabefacedbaddecaf888
    ```
  - Plaintext:
    ```text
    d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255
    ```
  - Associated Data (AAD):
    ```text
    feedfacedeadbeeffeedfacedeadbeefabaddad2
    ```
- **Expected Outputs:**
  - Ciphertext:
    ```text
    522dc1f09952541f483a97fa4e56427da595f64b0c5e8eda942f7169dbff925b4104d440d70f8b5773199d31f4a5482385dd66ddb11da36a9ec71a04481577c6
    ```
  - Authentication Tag (128-bit):
    ```text
    76fc6ece0f4e1768cddf8853bb2d551b
    ```

---

### 2.3 RFC 5869 — HKDF-SHA256 Test Vector

- **Source:** RFC 5869 Test Case 1 (Basic HKDF with SHA-256)
- **Inputs:**
  - Hash: SHA-256
  - IKM (Input Key Material):
    ```text
    0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
    ```
  - Salt:
    ```text
    000102030405060708090a0b0c
    ```
  - Info:
    ```text
    f0f1f2f3f4f5f6f7f8f9
    ```
  - Output Length ($L$): `42` bytes
- **Expected Outputs:**
  - PRK (Extract output):
    ```text
    077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e0
    ```
  - OKM (Expand output, 42 bytes):
    ```text
    3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865
    ```

---

### 2.4 BIP-0039 — 24-Word Mnemonic Test Vector

- **Source:** Official BIP-0039 Test Vectors (256-bit entropy)
- **Inputs:**
  - Entropy (256 bits):
    ```text
    0000000000000000000000000000000000000000000000000000000000000000
    ```
- **Expected Outputs:**
  - Mnemonic (24 words):
    ```text
    abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art
    ```
  - BIP39 Seed (PBKDF2 with passphrase `""`, 512 bits):
    ```text
    408b285c123836004f4b8842c89324c1f01382450c0d839f9b2a0a36db8840dad611a4959133717f7dd9ead7a3ddc77b1fb7bb82a01f6950bea5b5d74a96f2e8
    ```

---

## 3. Unit & Integration Test Matrix

| Test Suite | File Location | Key Assertions | Status |
|---|---|---|---|
| Result & Error Flow | `test/core/result_test.dart` | Ok/Err mapping, unwrap bounds, error encapsulation | Passed (2 tests) |
| Strongly Typed IDs & Versions | `test/core/types_test.dart` | UUID v4 validation, canonical formatting, version comparison | Passed (5 tests) |
| Master Password Policy | `test/domain/master_password_policy_test.dart` | >= 15 chars enforced, spaces permitted, no trim/lower alteration | Passed (6 tests) |
| Password Generator Policy | `test/domain/password_generation_policy_test.dart` | >= 12 chars enforced, character group inclusion, empty set failure | Passed (4 tests) |
| Credential & Association Models | `test/domain/credential_payload_test.dart` | CVV/CVC omitted, Android cert SHA256 validation, secret redaction | Passed (6 tests) |
| KDF Resource Bounds | `test/crypto/kdf_parameters_test.dart` | Safe memory/iteration limits enforced, DoS header attacks rejected | Passed (5 tests) |
| Canonical AAD Encoding | `test/crypto/associated_data_context_test.dart` | Deterministic binary layout, big-endian byte-for-byte reproducibility | Passed (3 tests) |
| Secret Key Hygiene & Destruction | `test/crypto/key_types_test.dart` | 32-byte length check, `[REDACTED]` stringification, memory zeroize | Passed (3 tests) |
| Widget Starter Baseline | `test/widget_test.dart` | Baseline smoke test preserved | Passed (1 test) |

**Total Phase 1A Test Baseline:** 35 passing tests. Zero failures. Zero analyzer issues.

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

