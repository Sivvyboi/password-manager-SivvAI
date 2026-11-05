# 10 — Phase 1 Cryptographic Design Proposal

**Document Status:** PROPOSAL / CANDIDATE FOR REVIEW (REMEDIATED & COMPREHENSIVE)  
**Scope:** Phase 1 — Cryptographic Architecture, Key Hierarchy, Primitives, Library Evaluation & Benchmark Plan  
**Target Environments:** Android (API 26 minimum, API 34 modern) and Windows Desktop  

---

## 1. Executive Summary & Design Principles

This proposal establishes the technical specification for the cryptographic foundation of the Password Manager. In accordance with project guardrails:
1. **No Improvised Primitives:** Only vetted, standard cryptographic algorithms (Argon2id RFC 9106, AES-256-GCM NIST SP 800-38D, HKDF-SHA256 RFC 5869, and BIP-0039) are employed.
2. **Explicit Key Separation:** No single key is ever reused across distinct operational domains or records.
3. **Rigorous AEAD Nonce Discipline:** Nonce uniqueness is maintained with per-record key isolation, explicit epoch tracking, and atomic VEK regeneration on restore to eliminate cross-timeline nonce reuse.
4. **Canonical Context Binding:** Every ciphertext is cryptographically bound to its format version, vault identifier, record identifier, and 1-byte purpose code via unambiguous Associated Authenticated Data (AAD).
5. **Fail-Closed Operations:** Any authentication tag mismatch or malformed header immediately aborts the operation without releasing partial plaintext or disclosing timing discrepancies.
6. **Realistic Memory Hygiene:** Memory cleanup is documented and implemented as **best-effort zeroization**, explicitly acknowledging managed runtime (Dart VM) limitations.

---

## 2. Master Password Processing Specification

### 2.1 Character Encoding & Unicode Policy
- **Encoding:** Strict UTF-8 without byte-order marks.
- **Length Counting Rule:** The master password length is measured strictly as the count of **Unicode scalar values / code points** (`password.runes.length`). Grapheme clusters and UTF-16 code units (`String.length`) are not used for length counting. This ensures identical, deterministic length evaluation across Dart on Android and Windows, Kotlin, and external test harnesses.
- **Length Boundaries:**
  - Minimum: 15 Unicode code points (per FR-002 and ADR-007).
  - Maximum: 256 Unicode code points (to prevent algorithmic Denial of Service in KDF computation).
- **Whitespace & Casing:** Raw whitespace (including leading, trailing, and internal spaces) and character casing are preserved exactly. Trimming or case folding is strictly prohibited.
- **Normalization:** Raw UTF-8 bytes are passed directly to the KDF without silent transformation.

---

## 3. Key Hierarchy & Derivation Architecture

### 3.1 Key Hierarchy Diagram

```mermaid
flowchart TD
    MP["Master Password (>= 15 code points)"] -->|UTF-8 + Vault Salt| KDF["Argon2id (RFC 9106)"]
    KDF --> MWK["Master Wrapping Key (MWK, 256-bit)"]

    CSPRNG["OS CSPRNG (/dev/urandom / BCryptGenRandom)"] -->|256 bits entropy| ENT["Recovery Entropy (256 bits)"]
    ENT -->|BIP-0039 + 8-bit SHA-256 Checksum| MNEM["24-word English Mnemonic"]
    MNEM -->|NFKD + PBKDF2-HMAC-SHA512 c=2048, salt='mnemonic'| B39_SEED["BIP39 Seed (512-bit)"]

    B39_SEED & VSALT["Vault Salt (16 bytes)"] -->|HKDF-Extract (HMAC-SHA256)| R_PRK["Recovery PRK (256-bit)"]
    R_PRK -->|HKDF-Expand info='PM-RECOVERY-WRAP-V1:' + vault_id, L=32| RWK["Recovery Wrapping Key (RWK, 256-bit)"]

    CSPRNG -->|256 bits| VEK["Vault Encryption Key (VEK, 256-bit)"]

    VEK & MWK -->|AES-256-GCM + AAD Purpose 0x01| MKW["master_key_wrapper (Vault Header)"]
    VEK & RWK -->|AES-256-GCM + AAD Purpose 0x02| RKW["recovery_key_wrapper (Vault Header)"]

    VEK & VSALT -->|HKDF-Extract (HMAC-SHA256)| REC_PRK["Record Master PRK (256-bit)"]
    REC_PRK -->|HKDF-Expand info='PM-RECORD-KEY-V1:' + record_id + ':' + key_epoch, L=32| REK["Per-Record Encryption Key (REK, 256-bit)"]

    REK -->|AES-256-GCM + AAD Purpose 0x04| REC_CIPHER["Encrypted Record Payload (SQLite)"]
    REK -->|AES-256-GCM + AAD Purpose 0x05| TOMB_CIPHER["Encrypted Tombstone Payload (SQLite)"]

    LOCAL_STORE["Local Device Keystore / DPAPI"] -.->|Device-Specific Wrap| DEV_WRAP["Local Device Wrapper (Local Only)"]
    VEK -.-> DEV_WRAP
```

### 3.2 Key Roles & Portable vs. Device-Local Boundary

| Key Identifier | Size | Purpose | Source / Derivation | Portability |
|---|---|---|---|---|
| **VEK** (Vault Encryption Key) | 256 bits | Primary root key protecting all records in the logical vault | OS CSPRNG at vault creation or restore | **Portable** (encrypted inside wrappers) |
| **MWK** (Master Wrapping Key) | 256 bits | Encrypts/decrypts the VEK in `master_key_wrapper` | Argon2id(MasterPassword, Salt, Params) | Derived locally as needed |
| **RWK** (Recovery Wrapping Key) | 256 bits | Encrypts/decrypts the VEK in `recovery_key_wrapper` | BIP39 Seed $\to$ HKDF-Extract & Expand bound to Vault ID | Derived locally as needed |
| **REK** (Record Encryption Key) | 256 bits | Encrypts/decrypts individual credential records | HKDF-SHA256(VEK, Salt, RecordID, KeyEpoch) | Ephemeral / derived per record |
| **Device Protection Key** | Varies | Unwraps VEK via biometrics or OS credential | Android Keystore / Windows DPAPI | **Device-Local Only** (never exported) |

---

## 4. Key Derivation Function: Argon2id

### 4.1 Specification & Resource Bounds
- **Algorithm:** Argon2id version 1.3 (`0x13` / Version 19).
- **Salt:** 16 bytes (128 bits) generated via OS CSPRNG. Unique per vault.
- **Output Length:** 32 bytes (256 bits).
- **Proposed Production Candidate Profile:**
  - Memory ($m$): $64\text{ MiB}$ ($65,536\text{ KiB}$).
  - Time / Iterations ($t$): 3 iterations.
  - Parallelism ($p$): 4 lanes / threads.
  - Secret ($K$): empty.
  - Associated Data ($X$): empty.
- **Resource Limits & DoS Protection:**
  - Vault headers specifying $m < 8\text{ MiB}$ or $m > 256\text{ MiB}$ are rejected immediately.
  - Iterations outside $[1, 10]$ are rejected.
  - Parallelism outside $[1, 8]$ are rejected.

### 4.2 RFC 9106 Compliance Vector vs. Production Profile
The RFC 9106 Section 5.3 compliance test vector uses low memory ($m=32\text{ KiB}$), $t=3$, $p=4$, with explicit 8-byte secret and 12-byte associated data. It exists exclusively to verify that the cryptographic engine implements the mathematical specification of Argon2id correctly. The application's production profile is configured for defense against offline GPU cracking ($64\text{ MiB}$ memory, empty secret/AAD) and will be benchmarked on target physical hardware.

### 4.3 Benchmark Plan for Hardware Validation
Parameters cannot be finalized based solely on desktop development. Before freezing the KDF profile:
1. **Device Matrix:**
   - Physical Device A: Android 8.0.0 / API 26 (low/mid-range hardware baseline).
   - Physical Device B: Android 14.0 / API 34 (modern flagship/mid-range).
   - Windows 10/11 Desktop environment.
2. **Metrics Measured:**
   - Total derivation latency (target: $\le 1000\text{ ms}$ on API 26, $\le 500\text{ ms}$ on modern devices).
   - Peak RAM consumption during derivation (must not trigger OS low-memory kills on 2GB RAM devices).
   - UI thread responsiveness (must confirm derivation executes off the main thread in a dedicated background Dart worker isolate).

---

## 5. Authenticated Encryption: AES-256-GCM & Nonce Policy

### 5.1 Parameter Specification
- **Cipher:** AES-256 in Galois/Counter Mode (GCM).
- **Key Length:** 32 bytes (256 bits).
- **Initialization Vector / Nonce Length:** 12 bytes (96 bits).
- **Authentication Tag Length:** 16 bytes (128 bits).

### 5.2 Nonce Policy & Probabilistic Collision Risk Analysis
Under standard AES-GCM, reusing a nonce with the same key compromises both confidentiality and authenticity (allowing recovery of the GHASH authentication subkey $H$).

> [!CAUTION]
> **Fundamental Cryptographic Rule:** Changing Associated Authenticated Data (AAD) or a record revision counter does **NOT** prevent AES-GCM nonce reuse under the same key. A nonce must NEVER be reused with the same key, regardless of whether AAD differs.

1. **Probabilistic Collision Analysis:**
   With a 96-bit random nonce generated via OS CSPRNG, the collision probability is governed by the Birthday Paradox:
   $$P \approx \frac{q^2}{2 \times 2^{96}} = \frac{q^2}{2^{97}}$$
   where $q$ is the number of invocations under that specific key.
   - If a single global key were used across a vault with $q = 2^{32}$ encryptions, $P \approx 2^{-33}$ (the NIST SP 800-38D limit).
   - **Per-Record Key Derivation:** By deriving a unique Record Encryption Key ($\text{REK}$) per record, $q$ represents only the number of writes to that single record under its current epoch. For $q = 1,000$ writes, $P \approx \frac{10^6}{2^{97}} \approx 6.3 \times 10^{-24} \approx 2^{-77}$.
   - While extremely small, this risk is **probabilistic, not mathematically zero**.

2. **Per-Record Key Epoch & Invocation Limits:**
   - Each record has an integer `key_epoch` column in SQLite (default `0`).
   - The HKDF context binds the record ID and epoch:
     $$\text{info} = \text{utf8Encode}(\text{"PM-RECORD-KEY-V1:"} \parallel \text{recordId} \parallel \text{":"} \parallel \text{keyEpoch})$$
   - **Threshold:** A single $\text{REK}$ must not exceed $2^{16}$ ($65,536$) encryptions. If a record's edits approach this threshold, the application increments `key_epoch = key_epoch + 1`, derives a new $\text{REK}$, and re-encrypts the record with a fresh CSPRNG nonce.
   - **Atomic Execution:** Record updates and re-encryption are committed within an atomic SQLite transaction (`BEGIN IMMEDIATE TRANSACTION ... COMMIT`). If interrupted, the transaction rolls back cleanly.

3. **Vault-Level Re-Keying ($2^{24}$ Writes):**
   - When cumulative vault write operations reach $2^{24}$ ($16,777,216$ writes), a full vault re-keying is triggered.
   - Generates a new 256-bit $\text{VEK}$ via OS CSPRNG.
   - Re-derives all record keys from the new $\text{VEK}$ with `key_epoch = 0`.
   - Re-encrypts every active record and tombstone.
   - Re-wraps the new $\text{VEK}$ into new `master_key_wrapper` and `recovery_key_wrapper` in `vault_header`.
   - Executed atomically in a staging database swap. If interrupted, the previous vault remains untouched.

4. **Backup Restore & Rollback Protection Architecture:**
   - **The Threat:** Restoring an older backup snapshot resets the database state. If the user subsequent edits records, the device could generate nonces under the same $\text{REK}$ and `key_epoch` that overlap with nonces already used on the previously active timeline before the restore occurred.
   - **The Protection (Atomic VEK Rotation on Restore):**
     To eliminate reliance on a potentially rolled-back epoch counter and guarantee zero key/nonce overlap:
     1. When a backup is restored, the application verifies and decrypts the backup records into memory using the backup key.
     2. It immediately generates a **brand new random 256-bit VEK** from OS CSPRNG.
     3. It derives fresh record keys for all imported records using the new VEK with `key_epoch = 0`.
     4. It re-encrypts all imported records with fresh CSPRNG nonces under the new VEK.
     5. It wraps the new VEK into new `master_key_wrapper` and `recovery_key_wrapper`.
     6. This entire operation is written to a temporary staging SQLite database.
     7. Only after full verification of all AEAD tags is the temporary database atomically swapped with the live vault database.
     8. If interrupted at any point prior to the swap, the staging file is discarded, leaving the existing vault intact.
     Because the restored vault operates under a completely fresh VEK, cross-timeline nonce collisions are mathematically impossible.

---

## 6. Canonical Associated Data (AAD) & Record Serialization

### 6.1 Canonical AAD Binary Format Specification

To bind ciphertext immutably to its operational context, all AEAD invocations authenticate the following canonical byte sequence:

| Offset | Length | Type | Description |
|---|---|---|---|
| 0 | 4 | Bytes | Magic ASCII identifier: `PMAA` (`0x50, 0x4D, 0x41, 0x41`) |
| 4 | 2 | uint16 BE | Format version (`0x0001` for Version 1, $1 \le v \le 65535$) |
| 6 | 1 | uint8 | Purpose code (from AAD Purpose Table below) |
| 7 | 1 | uint8 | Vault ID length ($L_V$, 36 for canonical UUID) |
| 8 | $L_V$ | UTF-8 | Canonical Vault UUID string (RFC 4122) |
| $8 + L_V$ | 1 | uint8 | Record ID length ($L_R$, 36 for record-level, 0 if vault-level) |
| $9 + L_V$ | $L_R$ | UTF-8 | Canonical Record UUID string (omitted if $L_R = 0$) |
| $9 + L_V + L_R$ | 4 | uint32 BE | Record Version / Revision counter ($0 \le \text{version} \le \text{0xFFFFFFFF}$) |

### 6.2 Complete AAD Purpose Codes & Context Constraints

| Code (Hex) | Identifier | Allowed Record ID | Allowed Record Version | Context Description |
|---|---|---|---|---|
| `0x01` | `AeadPurpose.masterKeyWrap` | Must be `null` | Must be `0` | Master Wrapping Key encrypting VEK in `vault_header` |
| `0x02` | `AeadPurpose.recoveryKeyWrap` | Must be `null` | Must be `0` | Recovery Wrapping Key encrypting VEK in `vault_header` |
| `0x04` | `AeadPurpose.recordPayload` | Required (Non-null) | $0 \le v \le \text{0xFFFFFFFF}$ | Encrypted credential payload in `vault_records` |
| `0x05` | `AeadPurpose.tombstonePayload` | Required (Non-null) | $0 \le v \le \text{0xFFFFFFFF}$ | Encrypted deletion tombstone in `vault_records` |
| `0x06` | `AeadPurpose.backupPackage` | Must be `null` | Must be `0` | Portable backup package container authentication |

*Any construction violating these combination constraints or specifying an invalid format version is rejected immediately with `ArgumentError` before encoding.*

### 6.3 Clear Distinction: AAD Purpose Codes vs. HKDF Context Labels

| Purpose / Operation | AEAD Purpose Code (1 Byte Binary) | HKDF Info String (RFC 5869 Context) |
|---|---|---|
| Master Key Wrapping | `0x01` in AAD header | N/A (Derived directly via Argon2id) |
| Recovery Key Derivation | `0x02` in AAD header | `'PM-RECOVERY-WRAP-V1:' + vaultId` |
| Record Key Derivation | `0x04` in AAD header | `'PM-RECORD-KEY-V1:' + recordId + ':' + keyEpoch` |
| Tombstone Payload | `0x05` in AAD header | Uses Record Key with same epoch |
| Portable Backup Package | `0x06` in AAD header | `'PM-BACKUP-KEY-V1:' + vaultId` |

---

## 7. Recovery Phrase & Derivation Specification

### 7.1 Mnemonic Generation & Validation
- **Entropy Source:** Exactly 256 bits of cryptographically secure random bytes from OS CSPRNG.
- **Checksum Calculation:** The SHA-256 hash of the 256-bit entropy is computed. The first 8 bits ($CS = ENT / 32 = 8$) of the hash are appended to the entropy, creating a 264-bit sequence.
- **Word Encoding:** The 264 bits are partitioned into 24 groups of 11 bits each ($24 \times 11 = 264$), indexing into the official BIP-0039 English wordlist.
- **Checksum Validation:** The 24 words are mapped back to 264 bits, and the 8-bit checksum is verified against SHA-256 of the 256-bit entropy.

### 7.2 BIP39 Binary Seed Derivation
1. **Sentence Formatting:** The 24 words are joined with a single ASCII space (`0x20`) between words, with no leading or trailing whitespace.
2. **NFKD Normalization:** The mnemonic sentence is normalized using Unicode Normalization Form KD (NFKD) and encoded into UTF-8 bytes.
3. **Salt Construction:** The salt is formed by the string constant `"mnemonic"` (`0x6d6e656d6f6e6963`) normalized in NFKD. **The application has no optional user-facing recovery passphrase feature; the passphrase component is strictly empty.**
4. **PBKDF2 Execution:** The 512-bit (64-byte) binary seed is derived via:
   $$\text{Seed}_{512} = \text{PBKDF2-HMAC-SHA512}(\text{password} = \text{MnemonicSentence}_{\text{NFKD}}, \text{salt} = \text{"mnemonic"}, c = 2048, \text{dkLen} = 64)$$

### 7.3 Application Recovery Key Derivation: Full Two-Stage HKDF
The application derives the 256-bit **Recovery Wrapping Key (RWK)** via a complete two-stage HKDF Extract-and-Expand construction (RFC 5869) using HMAC-SHA256:

1. **Stage 1 (HKDF-Extract):**
   - **Input Key Material (IKM):** The 64-byte $\text{Seed}_{512}$.
   - **Salt:** The 16-byte `vault_header.kdf_salt` ($S_{\text{vault}}$).
   - **PRK (Pseudorandom Key):**
     $$\text{PRK}_{\text{recovery}} = \text{HMAC-SHA256}(\text{key} = S_{\text{vault}}, \text{data} = \text{Seed}_{512}) \quad (32\text{ bytes})$$

2. **Stage 2 (HKDF-Expand):**
   - **Input PRK:** The 32-byte $\text{PRK}_{\text{recovery}}$ from Stage 1.
   - **Context Info String:** Bound specifically to the logical vault via:
     $$\text{info} = \text{utf8Encode}(\text{"PM-RECOVERY-WRAP-V1:"} \parallel \text{vaultId.value})$$
   - **Output Length ($L$):** 32 bytes (256 bits).
   - **Output Key:**
     $$\text{RWK} = \text{HKDF-Expand}(\text{PRK}_{\text{recovery}}, \text{info}, L = 32) \quad (32\text{ bytes})$$

3. **VEK Recovery:** The 256-bit RWK decrypts `recovery_key_wrapper` from the vault header using AES-256-GCM and canonical recovery AAD (`0x02`) to recover the identical 256-bit VEK.

---

## 8. Cryptographic Library Candidates Evaluation

| Package | Evaluated Version | Algorithms Covered | Platforms & Implementation Architecture | Maintenance & License | Implementation Details & Recommendation |
|---|---|---|---|---|---|
| **`cryptography`** (Core Dart) | `^2.9.0` | Argon2id v1.3, AES-256-GCM, HKDF-SHA256, CSPRNG | Pure Dart. Runs across Android, Windows, Linux, macOS, Web. | Active, **Apache 2.0**. Verified on pub.dev. | **Core Crypto Engine.** Implements exact standard algorithms in pure Dart (`DartArgon2id`). Runs consistently across Android and Windows. |
| **`cryptography_flutter`** (Flutter Plugin) | `^2.3.4` | AES-256-GCM, SHA-256, HMAC | Android, iOS, Web. | Active, **Apache 2.0**. Verified on pub.dev. | **Optional Platform Accelerator.** Accelerates AES-GCM and SHA-256 via Android OS crypto APIs. **Does NOT accelerate Argon2id.** |
| **`bip39`** | `^1.0.6` | BIP-0039 standard wordlist, entropy conversion, PBKDF2 seed derivation | Pure Dart. Compatible with all platforms. | Stable, MIT license. Wordlist verified against official standard. | **Recommended for BIP39 mnemonic handling.** |
| **`pointycastle`** | `^3.9.1` | AES-GCM, Argon2, HKDF | Pure Dart. Compatible with all platforms including API 26 and Windows. | Active community fork of Bouncy Castle. MIT license. | **Viable Alternative.** Slower execution for Argon2 in pure Dart. |
| **`crypto`** (dart.dev official) | `^3.0.6` | SHA-256, HMAC | All Dart platforms. | Maintained by Google/Dart team. BSD-3-Clause. | Standard HMAC-SHA256 only; lacks AES-GCM and Argon2id. |

### 8.1 Critical Architecture Note: Argon2id Off-Thread Execution
- Neither `cryptography` nor `cryptography_flutter` provides native C/assembly acceleration for Argon2id. It runs via `DartArgon2id`.
- **UI Thread Freezing Prevention:** Argon2id with 64 MiB memory and 3 iterations will block the execution thread for hundreds of milliseconds or several seconds on mobile hardware.
- **Isolate Mandate:** Argon2id **must be dispatched to a background Dart worker isolate** (`Isolate.run(...)`). This ensures the Flutter UI frame rendering is completely unaffected during vault unlock.
- **Hardware Disparity:** Pure Dart Argon2id performance on Android 8 (API 26 32-bit ARM cores) will be significantly slower than on a Windows 64-bit desktop CPU. The benchmark plan on the physical Android 8 device is essential before freezing production parameters.

---

## 9. Memory Cleanup & Hygiene Strategy

In managed language runtimes (Dart VM / Flutter):
- The runtime manages memory allocations through automatic garbage collection and string deduplication.
- When `SecretKeyBytes.destroy()` is invoked, it performs **best-effort zeroization** by overwriting the backing `Uint8List` byte array with zeros and setting an `_isDisposed` flag that prevents future access.
- **Explicit Limitation:** Dart runtime copies, immutable string allocations (e.g. temporary password inputs), and operating-system paging buffers cannot be guaranteed erased. Protections are designed to minimize secret lifetime in active state rather than claiming hardware-level zeroization.
