# 10 — Phase 1 Cryptographic Design Proposal

**Document Status:** PROPOSAL / CANDIDATE FOR REVIEW (REMEDIATED)  
**Scope:** Phase 1 — Cryptographic Architecture, Key Hierarchy, Primitives, Library Evaluation & Benchmark Plan  
**Target Environments:** Android (API 26 minimum, API 34 modern) and Windows Desktop  

---

## 1. Executive Summary & Design Principles

This proposal establishes the technical specification for the cryptographic foundation of the Password Manager. In accordance with project guardrails:
1. **No Improvised Primitives:** Only vetted, standard cryptographic algorithms (Argon2id RFC 9106, AES-256-GCM NIST SP 800-38D, HKDF-SHA256 RFC 5869, and BIP-0039) are employed.
2. **Explicit Key Separation:** No single key is ever reused across distinct operational domains or records.
3. **Strict AEAD Nonce Discipline:** Nonce uniqueness under AES-GCM is enforced through architecture to eliminate the risk of nonce reuse.
4. **Canonical Context Binding:** Every ciphertext is cryptographically bound to its format version, vault identifier, record identifier, and purpose code via unambiguous Associated Authenticated Data (AAD).
5. **Fail-Closed Operations:** Any authentication tag mismatch or malformed header immediately aborts the operation without releasing partial plaintext or disclosing timing discrepancies.

---

## 2. Master Password Processing Specification

### 2.1 Character Encoding & Unicode Policy
- **Encoding:** Strict UTF-8 without byte-order marks.
- **Normalization:** In modern cross-platform credential systems, automatic Unicode normalization (e.g. NFKD or NFKC) can alter user intent or break compatibility across platforms. We propose **preserving exact raw input** while recommending NFC normalization only if an explicit cross-keyboard discrepancy is demonstrated. UTF-8 byte sequences are passed directly to the KDF without modification.
- **Whitespace & Casing:** Raw whitespace (including leading, trailing, and internal spaces) and character casing are preserved exactly. Trimming or case folding is strictly prohibited.
- **Length Boundaries:**
  - Minimum: 15 characters (counted by Unicode code points / graphemes per FR-002 and ADR-007).
  - Maximum: 256 characters (to prevent algorithmic Denial of Service in KDF computation).
- **Cross-Platform Parity:** Standard Dart `utf8.encode(masterPassword)` operates identically on Windows and Android, ensuring bit-for-bit parity.

---

## 3. Key Hierarchy & Derivation Architecture

### 3.1 Key Hierarchy Diagram

```mermaid
flowchart TD
    MP["Master Password (>= 15 chars)"] -->|UTF-8 + Vault Salt| KDF["Argon2id (RFC 9106)"]
    KDF --> MWK["Master Wrapping Key (MWK, 256-bit)"]

    CSPRNG["OS CSPRNG (/dev/urandom / BCryptGenRandom)"] -->|256 bits entropy| ENT["Recovery Entropy (256 bits)"]
    ENT -->|BIP-0039 + 8-bit SHA-256 Checksum| MNEM["24-word English Mnemonic"]
    MNEM -->|NFKD + PBKDF2-HMAC-SHA512 c=2048, salt='mnemonic'| B39_SEED["BIP39 Seed (512-bit)"]

    B39_SEED & VSALT["Vault Salt (16 bytes)"] -->|HKDF-Extract (HMAC-SHA256)| R_PRK["Recovery PRK (256-bit)"]
    R_PRK -->|HKDF-Expand info='PM-RECOVERY-WRAP-V1:' + vault_id, L=32| RWK["Recovery Wrapping Key (RWK, 256-bit)"]

    CSPRNG -->|256 bits| VEK["Vault Encryption Key (VEK, 256-bit)"]

    VEK & MWK -->|AES-256-GCM + Vault AAD| MKW["master_key_wrapper (Vault Header)"]
    VEK & RWK -->|AES-256-GCM + Recovery AAD| RKW["recovery_key_wrapper (Vault Header)"]

    VEK & VSALT -->|HKDF-Extract (HMAC-SHA256)| REC_PRK["Record Master PRK (256-bit)"]
    REC_PRK -->|HKDF-Expand info='PM-RECORD-KEY-V1:' + record_id, L=32| REK["Per-Record Encryption Key (REK, 256-bit)"]

    REK -->|AES-256-GCM + Canonical Record AAD| REC_CIPHER["Encrypted Record Payload (SQLite)"]

    LOCAL_STORE["Local Device Keystore / DPAPI"] -.->|Device-Specific Wrap| DEV_WRAP["Local Device Wrapper (Local Only)"]
    VEK -.-> DEV_WRAP
```

### 3.2 Key Roles & Portable vs. Device-Local Boundary

| Key Identifier | Size | Purpose | Source / Derivation | Portability |
|---|---|---|---|---|
| **VEK** (Vault Encryption Key) | 256 bits | Primary root key protecting all records in the logical vault | OS CSPRNG at vault creation | **Portable** (encrypted inside wrappers) |
| **MWK** (Master Wrapping Key) | 256 bits | Encrypts/decrypts the VEK in `master_key_wrapper` | Argon2id(MasterPassword, Salt, Params) | Derived locally as needed |
| **RWK** (Recovery Wrapping Key) | 256 bits | Encrypts/decrypts the VEK in `recovery_key_wrapper` | BIP39 Seed $\to$ HKDF-Extract & Expand bound to Vault ID | Derived locally as needed |
| **REK** (Record Encryption Key) | 256 bits | Encrypts/decrypts individual credential records | HKDF-SHA256(VEK, Salt, RecordID) | Ephemeral / derived per record |
| **Device Protection Key** | Varies | Unwraps VEK via biometrics or OS credential | Android Keystore / Windows DPAPI | **Device-Local Only** (never exported) |

---

## 4. Key Derivation Function: Argon2id

### 4.1 Specification
- **Algorithm:** Argon2id version 1.3 (`0x13`).
- **Salt:** 16 bytes (128 bits) generated via OS CSPRNG. Unique per vault.
- **Output Length:** 32 bytes (256 bits).
- **Candidate Parameter Profile:**
  - Memory ($m$): $64\text{ MiB}$ ($65,536\text{ KiB}$).
  - Time / Iterations ($t$): 3 iterations.
  - Parallelism ($p$): 4 lanes / threads.
  - Secret ($K$): empty.
  - Associated Data ($X$): empty.
- **Resource Limits & DoS Protection:**
  - Headers specifying $m < 8\text{ MiB}$ or $m > 256\text{ MiB}$ are rejected immediately.
  - Iterations outside $[1, 10]$ are rejected.
  - Parallelism outside $[1, 8]$ is rejected.
- **RFC 9106 Section 5.3 Vector vs. Application Production Profile:**
  The RFC 9106 Section 5.3 vector uses $m=32\text{ KiB}$, $t=3$, $p=4$, with explicit 8-byte secret and 12-byte associated data. It serves solely as a library compliance check. The application's production profile uses $64\text{ MiB}$ memory without secret or associated data.
- **Upgrade Strategy:** KDF parameters and algorithm identifiers are stored explicitly in the versioned `vault_header`. When higher parameters are approved in the future, the vault automatically re-derives MWK and re-wraps the VEK upon successful unlock.

### 4.2 Benchmark Plan for Hardware Validation
Parameters cannot be finalized based solely on desktop development. Before freezing the KDF profile:
1. **Device Matrix:**
   - Physical Device A: Android 8.0.0 / API 26 (low/mid-range hardware baseline).
   - Physical Device B: Android 14.0 / API 34 (modern flagship/mid-range).
   - Windows 10/11 Desktop environment.
2. **Metrics Measured:**
   - Total derivation latency (target: $\le 1000\text{ ms}$ on API 26, $\le 500\text{ ms}$ on modern devices).
   - Peak RAM consumption during derivation (must not trigger OS low-memory process kills on 2GB RAM devices).
   - UI thread responsiveness (must confirm derivation executes off the main thread in a background Dart isolate or native worker thread).

---

## 5. Authenticated Encryption: AES-256-GCM

### 5.1 Parameter Specification
- **Cipher:** AES-256 in Galois/Counter Mode (GCM).
- **Key Length:** 32 bytes (256 bits).
- **Initialization Vector / Nonce Length:** 12 bytes (96 bits).
- **Authentication Tag Length:** 16 bytes (128 bits).

### 5.2 Nonce Uniqueness & Collision Risk Mitigation
NIST SP 800-38D dictates that random 96-bit nonces under a single key must not be used for more than $2^{32}$ encryptions. However, in local vault storage where records are repeatedly edited and saved:
- **Catastrophic Failure:** Reusing a nonce under the same key in AES-GCM allows an attacker to recover the authentication hash subkey ($H$) and forge or decrypt records.
- **Approved Mitigation Strategy (Per-Record Key Separation):**
  Instead of using a single global key to encrypt all records with random nonces:
  1. Each record utilizes its own **Record Encryption Key (REK)** derived deterministically via full HKDF-SHA256 Extract-and-Expand:
     $$\text{PRK}_{\text{record}} = \text{HMAC-SHA256}(\text{key} = \text{VaultSalt}, \text{data} = \text{VEK})$$
     $$\text{REK} = \text{HKDF-Expand}(\text{PRK}_{\text{record}}, \text{info} = \text{"PM-RECORD-KEY-V1:"} \parallel \text{RecordID}, L = 32)$$
  2. For each write/revision of that record, a fresh 96-bit random nonce is generated by the OS CSPRNG. Because the key is record-specific and record revisions remain well under tens of thousands over the app's lifetime, the probability of a nonce collision under that specific key is virtually zero ($< 2^{-64}$).
  3. Nonce exhaustion or reuse uncertainty triggers an immediate key rotation.

---

## 6. Canonical Associated Data (AAD) & Record Serialization

### 6.1 Canonical AAD Specification
To bind ciphertext immutably to its operational context, all AEAD invocations authenticate the following byte sequence:

| Offset | Length | Type | Description |
|---|---|---|---|
| 0 | 4 | Bytes | Magic ASCII identifier: `PMAA` (`0x50, 0x4D, 0x41, 0x41`) |
| 4 | 2 | uint16 BE | Format version (`0x0001` for Version 1) |
| 6 | 1 | uint8 | Purpose code (`0x01` MasterWrap, `0x02` RecoveryWrap, `0x04` RecordPayload) |
| 7 | 1 | uint8 | Vault ID length ($L_V$) |
| 8 | $L_V$ | UTF-8 | Canonical Vault UUID string |
| $8 + L_V$ | 1 | uint8 | Record ID length ($L_R$, 0 if vault-level wrapper) |
| $9 + L_V$ | $L_R$ | UTF-8 | Canonical Record UUID string (omitted if $L_R = 0$) |
| $9 + L_V + L_R$ | 4 | uint32 BE | Record Version / Revision counter |

### 6.2 Record Payload Serialization
Sensitive record attributes are serialized into a deterministic, canonical JSON format with sorted keys and UTF-8 encoding prior to encryption. This guarantees byte-for-byte serialization reproducibility across Dart on Android and Windows while permitting schema extensibility via versioned payload envelopes.

---

## 7. Recovery Phrase & Derivation Specification

### 7.1 Mnemonic Generation & Validation
- **Entropy Source:** Exactly 256 bits of cryptographically secure random bytes generated via the approved OS CSPRNG.
- **Checksum Calculation:** The SHA-256 hash of the 256-bit entropy is computed. The first 8 bits ($CS = ENT / 32 = 256 / 32 = 8$) of the hash are appended to the entropy, creating a 264-bit sequence.
- **Word Encoding:** The 264 bits are partitioned into 24 groups of 11 bits each ($24 \times 11 = 264$). Each 11-bit group serves as an index ($0$ to $2047$) into the official BIP-0039 English wordlist.
- **Checksum Validation:** During recovery entry, the 24 words are mapped back to 264 bits, and the 8-bit checksum is verified against SHA-256 of the 256-bit entropy. Invalid word count or invalid checksum immediately fails closed.

### 7.2 BIP39 Binary Seed Derivation
1. **Sentence Formatting:** The 24 words are joined with a single ASCII space (`0x20`) between words, with no leading or trailing whitespace.
2. **NFKD Normalization:** The mnemonic sentence is normalized using Unicode Normalization Form KD (NFKD) and encoded into UTF-8 bytes.
3. **Salt Construction:** The salt is formed by the string constant `"mnemonic"` (`0x6d6e656d6f6e6963`) normalized in NFKD. **The application has no optional user-facing recovery passphrase feature; the passphrase component is strictly empty.**
4. **PBKDF2 Execution:** The 512-bit (64-byte) binary seed is derived via:
   $$\text{Seed}_{512} = \text{PBKDF2-HMAC-SHA512}(\text{password} = \text{MnemonicSentence}_{\text{NFKD}}, \text{salt} = \text{"mnemonic"}, c = 2048, \text{dkLen} = 64)$$

### 7.3 Application Recovery Key Derivation: Full Two-Stage HKDF
The BIP39 seed alone is not directly used as an AES key. The application derives the 256-bit **Recovery Wrapping Key (RWK)** via a complete two-stage HKDF Extract-and-Expand construction (RFC 5869) using HMAC-SHA256:

1. **Stage 1 (HKDF-Extract):**
   - **Input Key Material (IKM):** The 64-byte $\text{Seed}_{512}$.
   - **Salt:** The 16-byte `vault_header.kdf_salt` ($S_{\text{vault}}$).
   - **PRK (Pseudorandom Key):**
     $$\text{PRK}_{\text{recovery}} = \text{HMAC-SHA256}(\text{key} = S_{\text{vault}}, \text{data} = \text{Seed}_{512})$$
     Yields a 32-byte $\text{PRK}_{\text{recovery}}$.

2. **Stage 2 (HKDF-Expand):**
   - **Input PRK:** The 32-byte $\text{PRK}_{\text{recovery}}$ from Stage 1.
   - **Context Info String:** Bound specifically to the logical vault via:
     $$\text{info} = \text{utf8Encode}(\text{"PM-RECOVERY-WRAP-V1:"} \parallel \text{vaultId.value})$$
   - **Output Length ($L$):** 32 bytes (256 bits).
   - **Output Key:**
     $$\text{RWK} = \text{HKDF-Expand}(\text{PRK}_{\text{recovery}}, \text{info}, L = 32)$$

3. **VEK Recovery:** The 256-bit RWK is used with AES-256-GCM and the canonical recovery AAD context to decrypt `recovery_key_wrapper` from the vault header and unwrap the identical 256-bit VEK.

---

## 8. Cryptographic Library Candidates Evaluation

| Package | Evaluated Version | Algorithms Covered | Platforms & API 26 | Maintenance & License | Assessment & Recommendation |
|---|---|---|---|---|---|
| **`cryptography`** (pedroslopez.me) | `^2.7.0` | Argon2id, AES-GCM, HKDF, CSPRNG | Pure Dart fallback + Web/Flutter. Android API 26+ compatible. Windows desktop supported. | Active, BSD-2-Clause. Extensive unit test coverage and standard algorithm parameters. | **Recommended Primary Candidate.** Supports pure Dart & native bindings, implements exact Argon2id and AES-256-GCM primitives. |
| **`pointycastle`** | `^3.9.1` | AES-GCM, Argon2, HKDF | Pure Dart. Compatible with all platforms including API 26 and Windows. | Active community fork of Bouncy Castle. MIT license. | **Viable Alternative.** Slower execution in pure Dart without native acceleration; requires isolates for Argon2id. |
| **`crypto`** (dart.dev official) | `^3.0.6` | SHA-256, HMAC | All Dart platforms. | Maintained by Google/Dart team. BSD-3-Clause. | Useful for standard HMAC-SHA256, but lacks AES-GCM and Argon2id. |
| **`bip39`** | `^1.0.6` | BIP39 wordlist, entropy conversion | Compatible with all platforms. | Stable, MIT license. Wordlist verified against official standard. | **Recommended for BIP39 mnemonic handling.** |

---

## 9. Password Generation Primitives Specification

1. **Unbiased Selection:** Modulo operations (`rand % N`) introduce modulo bias when $2^{32}$ is not divisible by $N$. Bounded integers are selected using **rejection sampling**:
   - Determine threshold $T = 2^{32} - (2^{32} \pmod N)$.
   - Sample 32-bit integer $R$ from CSPRNG. If $R \ge T$, discard and sample again.
   - Return $R \pmod N$.
2. **Fisher–Yates Shuffle:** The generated characters are shuffled in-place using unbiased rejection sampling for every swap index $i$ from $N-1$ down to 1.
3. **Guaranteed Group Representation:** If $K$ character groups are selected and total length $L \ge K$, one character is chosen from each group, followed by $L - K$ unbiased characters from the union pool, completed with an unbiased shuffle.
4. **Passphrase Words:** 6 words selected from a vetted wordlist (e.g. EFF Long Wordlist or BIP39) using unbiased bounded selection.
