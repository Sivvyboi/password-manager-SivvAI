# 06 — Data Model and Storage

## 1. Storage strategy

SQLite is the selected database direction, with sensitive record payloads encrypted individually before persistence. The exact SQLite package and whether a database-level encryption layer is also warranted remain implementation/prototype decisions.

Record-level encryption is not a substitute for protecting database metadata, temporary files, write-ahead logs, backups or device storage. Review all SQLite side files and backup paths.

## 2. Data separation

### Portable vault data
- Vault identifier and format version.
- KDF algorithm and parameters.
- Master-password key wrapper.
- Recovery-key wrapper.
- Encrypted credential records.
- Encrypted categories and renewal configuration.
- Record revisions and encrypted tombstones.

### Device-local data
- Android Keystore key references or Windows device/user key references.
- Biometric preference.
- Device-specific lock preference.
- Clipboard preference.
- Theme and local UI preferences.
- Notification scheduling identifiers.
- Device-specific wrapper material.

Device-local settings and wrappers are not part of the portable vault package.

## 3. Proposed tables

### `vault_header`
Fields (logical schema; exact SQL types and constraints to be specified in implementation):
- `vault_id`
- `format_version`
- `kdf_algorithm`
- `kdf_salt`
- `kdf_parameters`
- `master_key_wrapper_nonce`
- `master_key_wrapper_ciphertext`
- `master_key_wrapper_tag` (or combined AEAD output)
- `recovery_key_wrapper_nonce`
- `recovery_key_wrapper_ciphertext`
- `recovery_key_wrapper_tag`
- `created_at`
- `updated_at`

The header must not contain plaintext master password, recovery phrase or VEK.

### `vault_records`
- `record_id`
- `revision_id`
- `record_version`
- `record_type` only if the privacy review accepts this metadata exposure; otherwise include it inside ciphertext.
- `nonce`
- `ciphertext` (including authentication tag if the chosen library returns combined output)
- `updated_at` only if metadata exposure is explicitly accepted; otherwise keep inside encrypted payload.

Avoid exposing titles, URLs, usernames, passwords, notes or categories in plaintext columns or indexes.

### Optional tombstone representation
Tombstone records should contain only the minimum metadata needed to prevent stale restore/sync from resurrecting deleted data. The tombstone itself should be authenticated/encrypted. Define retention and cleanup rules before implementing sync.

## 4. Encrypted record payload

Sensitive fields should be serialized together and encrypted:
- title
- URL / website origin
- username
- password
- notes
- category
- favourite flag
- created/modified/password-changed timestamps
- renewal settings
- approved Autofill associations
- record type and type-specific fields

Type-specific fields:
- Login: username, password, URLs and associations.
- Secure note: note content.
- Payment card: cardholder, number, expiry and optional non-CVV metadata; never CVV/CVC.
- Wi-Fi: network name and password/security type.
- Software licence: product, licence key and related notes.

## 5. Search and health checks

No plaintext searchable index is planned. While unlocked, decrypt records as needed and search in memory. Password reuse checks compare decrypted values in memory. Do not persist plaintext password fingerprints or hashes for reuse detection.

This is a deliberate privacy/usability trade-off: search may require decrypting more records and could affect performance for large vaults. Benchmark and optimize without creating sensitive plaintext indexes.

## 6. Encryption design candidates

Current design candidates:
- VEK: 256 bits generated using a cryptographically secure random generator.
- Master-password KDF: Argon2id.
- Salt: 128 bits, random per vault/key derivation context.
- Derived wrapping key: 256 bits.
- Record encryption: AES-256-GCM.
- GCM nonce: 96 bits.
- Key derivation purpose separation: HKDF or equivalent domain-separated derivation.
- Recovery entropy: 256 bits represented as a 24-word BIP39-style mnemonic.

These are candidates pending library selection, implementation review, test vectors, nonce policy and benchmarking. Do not freeze parameters solely from this document.

### KDF profile candidate
A previously discussed starting profile was Argon2id with 64 MiB memory, 3 iterations and 4 lanes. Benchmark on the Android 8 physical device and review library support before adoption. Store all parameters and algorithm/version identifiers in the vault header so they can be migrated.

## 7. Nonce and key lifecycle requirements

AES-GCM nonce reuse under the same key can catastrophically undermine confidentiality and integrity. Before implementation:
- Define a per-key encryption limit and rotation policy.
- Define nonce generation and uniqueness strategy.
- Ensure record updates cannot reuse a nonce with the same key.
- Consider purpose-separated/per-record derived keys, but have the complete construction reviewed.
- Include nonce and associated-data fields in test vectors.
- Treat nonce exhaustion or uncertainty as a hard error requiring key rotation, not as a warning.

## 8. Associated data

Bind ciphertext to its context using authenticated associated data. Candidate fields include:
- vault ID
- record ID
- record version
- format/version domain label
- record purpose

The exact byte encoding must be canonical, unambiguous and versioned. Both Android and Windows must produce identical bytes.

## 9. Recovery phrase

The selected phrase is a 24-word, 256-bit-entropy recovery phrase using a standard BIP39-compatible mnemonic representation. Do not invent a custom wordlist or mnemonic encoding.

The exact conversion from mnemonic to recovery wrapping key must be specified using standard, reviewed derivation and domain separation. Do not store or log the plaintext phrase. The same recovery phrase recovers the same logical vault across Android and Windows; device-specific wrappers are recreated locally.

## 10. Deletion and tombstones

Deletion creates an authenticated encrypted tombstone/revision rather than simply forgetting a record identifier. This is needed for future sync and to stop an older backup from silently resurrecting deleted credentials.

Open design items:
- Tombstone retention period.
- How a restore handles a backup older than a tombstone.
- Whether restore requires explicit confirmation when it would reintroduce older records.
- Safe garbage collection once all supported devices/backups are known to have advanced.

## 11. Database migration

Every persistent schema and cryptographic format has a version. Migrations must:
1. Authenticate and unlock the current vault.
2. Read and verify old records.
3. Transform into a new temporary database.
4. Verify record counts and authentication tags.
5. Commit atomically.
6. Preserve a recoverable encrypted backup until migration success is confirmed.
