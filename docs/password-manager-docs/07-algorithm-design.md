# 07 — Algorithm Design

## 1. Status and principles

This document records the selected algorithm behaviour and candidate cryptographic construction. Cryptographic algorithms must be implemented through established, reviewed libraries. The construction, parameters, byte encodings and test vectors must be reviewed before a production format is frozen.

## 2. Confirmed product decisions

| Decision | Selected value |
|---|---|
| Minimum generated password length | 12 characters |
| Default passphrase length | 6 words |
| Strength estimation | Local zxcvbn |
| Autofill session | Separate short-lived session |
| Recovery portability | Same 24-word phrase for the logical vault on Android and Windows |

Other inherited decisions:
- Master password minimum 15 characters.
- VEK 256-bit candidate.
- Recovery phrase 24 words / 256-bit entropy.
- Record deletion uses encrypted tombstones.
- Immediate lock on app background.
- Strict exact Autofill associations.
- Manual encrypted backup/restore for MVP.

## 3. Vault creation

High-level pseudocode:

```text
createVault(masterPassword):
    validate masterPassword length >= 15 characters
    validate password encoding and normalization policy

    vek = secureRandom(256 bits)
    salt = secureRandom(128 bits)

    wrappingKey = Argon2id(
        password = masterPassword,
        salt = salt,
        parameters = versionedProfile
    )

    masterWrapper = AEAD_Encrypt(
        key = wrappingKey,
        plaintext = vek,
        associatedData = canonicalVaultWrapperContext
    )

    recoveryEntropy = secureRandom(256 bits)
    recoveryPhrase = standardMnemonicEncode(recoveryEntropy)
    recoveryKey = reviewedRecoveryKDF(recoveryPhrase, vaultContext)
    recoveryWrapper = AEAD_Encrypt(
        key = recoveryKey,
        plaintext = vek,
        associatedData = canonicalRecoveryWrapperContext
    )

    initialize temporary database and header
    display recoveryPhrase once and require user confirmation
    commit vault creation atomically
    clear temporary secret references where supported
```

Do not invent the `reviewedRecoveryKDF`; its exact standard, parameters and interoperability test vectors are an implementation gate.

## 4. Master-password unlock

```text
unlock(masterPassword):
    header = loadVaultHeader()
    validate header version and KDF parameters against safe limits
    wrappingKey = Argon2id(masterPassword, header.salt, header.parameters)
    vek = AEAD_Decrypt(
        key = wrappingKey,
        wrapper = header.masterWrapper,
        associatedData = canonicalVaultWrapperContext
    )

    if authentication fails:
        return genericAuthenticationFailure

    create bounded vault session using vek
    discard masterPassword and temporary wrappingKey references
```

The app may apply a persistent app-level retry delay, but copied vault files can be attacked offline outside the app. App rate limiting is not an offline-cracking defence.

## 5. Record encryption

```text
saveRecord(record):
    require unlocked session
    validate record by type
    plaintext = canonicalSerialize(record)
    nonce = generateNonceAccordingToApprovedNoncePolicy()
    aad = canonicalAssociatedData(vaultId, recordId, recordVersion)
    ciphertext = AEAD_Encrypt(recordKey, nonce, plaintext, aad)
    persist(recordId, revisionId, recordVersion, nonce, ciphertext)
    clear temporary plaintext references where supported
```

Read:
1. Load record metadata and ciphertext.
2. Reconstruct exactly the same associated data.
3. Authenticate and decrypt.
4. If tag verification fails, fail closed and do not display partial plaintext.
5. Parse and validate the payload.

The record-key derivation and nonce policy must be fully specified before production use. Do not improvise AES-GCM nonce handling.

## 6. Recovery

```text
recoverVault(recoveryPhrase, newMasterPassword):
    validate mnemonic checksum and phrase format
    validate new master password policy
    recoveryKey = reviewedRecoveryKDF(recoveryPhrase, vaultContext)
    vek = AEAD_Decrypt(recoveryKey, recoveryWrapper, recoveryAAD)

    newSalt = secureRandom(128 bits)
    newWrappingKey = Argon2id(newMasterPassword, newSalt, currentKdfProfile)
    newWrapper = AEAD_Encrypt(newWrappingKey, vek, masterWrapperAAD)

    write new wrapper and parameters transactionally
    read back and verify new wrapper
    commit only after verification
    initialize session
```

The recovery phrase remains valid unless the user separately rotates it. Recovery is for the same logical vault across platforms; each device must establish its own local device key protection.

## 7. Password generation

- Build the allowed character set from user-selected groups.
- Remove explicitly excluded characters.
- Reject invalid configurations (for example, an empty allowed set).
- Enforce length >= 12.
- Use a cryptographically secure random generator.
- Use unbiased bounded-integer selection (rejection sampling or a vetted equivalent).
- Ensure every selected character group appears at least once, if the final configuration can satisfy the constraints.
- Fill remaining positions using unbiased selection.
- Shuffle the final character array using a cryptographically unbiased Fisher–Yates shuffle.
- Return the generated value; never log it.

Passphrases use a vetted wordlist and secure random selection. Default word count is six. The exact wordlist and separator/format policy remain implementation choices and should be documented.

## 8. Password strength estimation

Use a locally running zxcvbn implementation:
- No network call.
- No external password submission.
- Evaluate only when needed and avoid retaining unnecessary plaintext.
- Treat the score as an estimate, not a guarantee.
- Do not automatically reject a password solely because of the score; provide actionable feedback.
- Review package maintenance, licensing, dependency tree and test coverage.

## 9. Password health

- Weakness: local zxcvbn-based assessment.
- Reuse: compare decrypted passwords in memory while unlocked; do not store plaintext fingerprints.
- Age: compare password-changed date to user-configured policy.
- Age alone does not prove compromise and should not trigger misleading security claims.

## 10. Locking

Lock triggers:
- App enters background.
- Device screen locks.
- User manually locks.
- Session expiry or security event.

On lock:
1. Stop new credential operations.
2. Cancel pending plaintext-return operations where possible.
3. Dismiss sensitive UI.
4. Clear in-memory credential state and transient buffers where supported.
5. Invalidate session tokens and key references.
6. Destroy the main vault session.
7. Ensure Autofill-only sessions are independently expired and destroyed.

Managed runtimes may retain copies; do not claim guaranteed memory zeroization.

## 11. Autofill

```text
handleAutofill(request):
    requester = identifyRequestingAppOrWebsite(request)
    candidates = findExactApprovedAssociations(requester)

    if candidates is empty:
        return noMatch

    if vault is locked:
        authenticate for Autofill-only session

    show candidates to user
    selected = requireExplicitUserSelection()
    revalidate requester identity and association
    release only selected credential to this request
    destroy Autofill-only session and transient plaintext
```

Application matching should include package identity and signing-certificate identity. Website matching should use a verified association mechanism and exact approved origins/hosts. Do not use substring or fuzzy URL matching. The exact website verification mechanism and canonicalization rules must be selected and tested.

## 12. Backup and restore

Export:
1. Require authentication.
2. Snapshot and validate logical vault records.
3. Construct versioned portable package.
4. Include portable wrappers and KDF metadata.
5. Exclude device-specific wrappers/settings.
6. Encrypt and authenticate the complete package.
7. Write to user-selected destination.
8. Re-read and verify package integrity.

Restore:
1. Validate package format/version and resource limits.
2. Authenticate using the approved master/recovery architecture.
3. Decrypt and verify package authentication.
4. Validate every record and tombstone.
5. Import into a new temporary database.
6. Verify record count, versions and integrity.
7. Commit atomically.
8. Establish new device-local key protection.

## 13. Deletion

- Require an authenticated vault session.
- Create a new revision identifier.
- Replace the active record with an authenticated encrypted tombstone.
- Commit transactionally.
- Ensure old backups do not silently resurrect deleted data.
- Define tombstone retention and restore conflict policy before cloud sync or automated backup pruning.

## 14. Cryptographic implementation gates

Before release, document and test:
- Exact algorithms and library versions.
- Argon2id parameter profile and upgrade strategy.
- Password encoding/normalization policy.
- Recovery mnemonic conversion and KDF.
- HKDF info/context strings and key hierarchy.
- AES-GCM nonce uniqueness policy and per-key usage limits.
- Canonical serialization and associated-data encoding.
- Key rotation and format migration behaviour.
- Cross-platform test vectors for Android and Windows.
