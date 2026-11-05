# 02 — Product Requirements

## 1. Requirement conventions

Requirement IDs are stable references for implementation tickets and tests.  
Priority:
- **MUST:** required for MVP.
- **SHOULD:** expected unless a documented reason prevents it.
- **FUTURE:** outside MVP.

## 2. Functional requirements

### Vault and authentication
- **FR-001 MUST** Create one logical vault.
- **FR-002 MUST** Require a master password of at least 15 characters.
- **FR-003 MUST** Permit long passphrases and spaces without forced character-class rules.
- **FR-004 MUST** Unlock the vault only after successful cryptographic verification.
- **FR-005 SHOULD** Support biometric convenience unlocking where the platform supports it.
- **FR-006 MUST** Lock immediately when the app enters the background.
- **FR-007 MUST** Lock when the device screen locks.
- **FR-008 MUST** Support manual locking.
- **FR-009 MUST** Provide a high-entropy recovery phrase and require the user to confirm that it has been saved.
- **FR-010 MUST** Never transmit the master password, recovery phrase or vault keys.

### Credential management
- **FR-011 MUST** Create, read, update and delete credential records.
- **FR-012 MUST** Support login, secure note, payment card, Wi-Fi and software licence records.
- **FR-013 MUST** Support built-in and custom categories.
- **FR-014 MUST** Support favourites.
- **FR-015 MUST** Exclude CVV/CVC fields from payment card records.
- **FR-016 MUST** Encrypt sensitive record content before persistence.
- **FR-017 MUST** Use encrypted tombstones for deletion rather than leaving deleted payloads available to ordinary restore/sync flows.

### Password generation
- **FR-018 MUST** Generate random passwords with configurable length and character groups.
- **FR-019 MUST** Support uppercase, lowercase, digits, symbols and excluded characters.
- **FR-020 MUST** Ensure each selected character group is represented when possible.
- **FR-021 MUST** Generate passphrases, defaulting to six words.
- **FR-022 MUST** Enforce a minimum generated password length of 12 characters.
- **FR-023 MUST** Use a cryptographically secure random number generator and unbiased selection/shuffling.
- **FR-024 MUST** Provide local strength estimation using zxcvbn.

### Password health and reminders
- **FR-025 MUST** Identify weak passwords locally.
- **FR-026 MUST** Identify reused passwords locally while the vault is unlocked.
- **FR-027 MUST** Identify password age according to user-visible policy.
- **FR-028 MUST** Allow renewal reminder intervals, specific dates or disabled reminders.
- **FR-029 MUST** Allow notification, snooze and reset actions.
- **FR-030 MUST** Keep reminder configuration encrypted as part of the credential.
- **FR-031 MUST** Use generic notification text by default.

### Clipboard
- **FR-032 MUST** Default to clearing copied secrets after 30 seconds where the OS permits.
- **FR-033 MUST** Describe clipboard clearing as best effort, not a guarantee.
- **FR-034 MUST** Prefer Android Autofill over clipboard use.
- **FR-035 MUST** On Android 8/9, disable copy by default unless the user explicitly opts in after a warning.

### Backup and recovery
- **FR-036 MUST** Export and restore an authenticated encrypted portable vault package manually.
- **FR-037 MUST** Use the same master-password/recovery-key architecture for backup protection; no separate backup password.
- **FR-038 MUST** Restore atomically; a failed import must not leave a partially replaced vault.
- **FR-039 MUST** Support recovery of the same logical vault on Android and Windows using the same recovery phrase.
- **FR-040 MUST** Exclude device-specific key wrappers and device-local settings from the portable vault package.

### Android Autofill
- **FR-041 MUST** Integrate with Android Autofill Framework.
- **FR-042 MUST** Require master password or biometrics when the vault is locked.
- **FR-043 MUST** Require explicit user selection before releasing a credential.
- **FR-044 MUST** Support multiple individually approved exact website/application associations per credential.
- **FR-045 MUST** Use strict matching; no fuzzy matching or wildcard associations.
- **FR-046 MUST** Verify the requesting app identity and signing certificate for application associations.
- **FR-047 MUST** Recheck the association before releasing the selected credential.
- **FR-048 MUST** Use a separate short-lived Autofill-only session, limited to one selected credential and one request.

### Privacy and platform behaviour
- **FR-049 MUST** Have no analytics, tracking or advertising telemetry.
- **FR-050 MUST** Warn when the device is rooted or otherwise appears compromised; disable high-risk convenience features where appropriate, but do not necessarily block all vault access.
- **FR-051 MUST** Warn about outdated Android security patches; do not automatically lock the user out solely for patch age.
- **FR-052 MUST** Avoid credential/site names in lock-screen notifications by default.
- **FR-053 MUST** Avoid logging secrets or sensitive record content.

### Deferred features
- **FR-054 FUTURE** TOTP secret storage and code generation.
- **FR-055 FUTURE** Encrypted cloud backup and synchronization.
- **FR-056 FUTURE** Attachments.

## 3. Non-functional requirements

- **NFR-001 Security:** cryptographic operations must use vetted libraries and documented formats.
- **NFR-002 Confidentiality:** no plaintext credentials or key material in persistent storage or logs.
- **NFR-003 Integrity:** authenticated encryption must detect record/package tampering.
- **NFR-004 Availability:** core vault functions must work offline.
- **NFR-005 Portability:** Android and Windows must implement the same versioned portable vault format.
- **NFR-006 Compatibility:** Android minimum API 26.
- **NFR-007 Performance:** KDF parameters must be benchmarked on the lowest-supported physical device; no untested performance promise is made.
- **NFR-008 Maintainability:** separate presentation, domain, data, cryptography and platform integration.
- **NFR-009 Testability:** business logic and cryptographic wrappers must have automated tests.
- **NFR-010 Privacy:** no telemetry or external password-strength service.
- **NFR-011 Reliability:** backup restore and key-wrapper changes must be atomic.
- **NFR-012 Accessibility:** support system text scaling, readable contrast and screen-reader semantics.

## 4. Acceptance principles

A feature is not complete merely because its UI works. It must:
1. Meet its requirement.
2. Have unit/integration tests appropriate to its risk.
3. Fail closed on authentication or integrity errors.
4. Avoid leaking sensitive data through logs, notifications, clipboard or crash reporting.
5. Be tested on relevant Android versions and, where applicable, Windows.
6. Have documentation updated if storage format, cryptographic behaviour or user-visible security policy changes.
