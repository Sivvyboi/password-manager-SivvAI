# 04 — Threat Model and Security Requirements

## 1. Scope and assumptions

This threat model covers the local Android-first MVP and its portable backup/restore format, with Windows portability in scope. It assumes the user may lose a device or backup file and that an attacker may obtain a copy of the encrypted database.

It does **not** promise protection when an attacker fully controls the operating system, captures secrets from an unlocked device, or compromises the app while secrets are in active use.

## 2. Assets

- Master password.
- Vault encryption key (VEK).
- Recovery phrase and recovery-derived key.
- Stored passwords, usernames, URLs and notes.
- Payment card details (excluding CVV/CVC).
- Wi-Fi credentials and software licence keys.
- Encrypted database and backups.
- Biometric-protected device key references.
- Unlocked session state and in-memory plaintext.
- Autofill request and released credential.
- Clipboard contents.
- Reminder metadata and notifications.

## 3. Threat actors

- Opportunistic thief who obtains a device or copied backup.
- Malware or malicious application on the device.
- Attacker with physical access to an unlocked device.
- Rooted-device or OS-level attacker.
- Phishing or impersonation application requesting Autofill.
- Supply-chain attacker targeting dependencies or build pipeline.
- Attacker attempting to tamper with or roll back a backup.

## 4. Threat catalogue

| ID | Threat | Primary controls |
|---|---|---|
| TH-001 | Database copied from device | Strong KDF, random VEK, authenticated encryption |
| TH-002 | Offline master-password guessing | Argon2id, minimum length policy, secure password guidance |
| TH-003 | Backup stolen | Authenticated encrypted package; no plaintext export |
| TH-004 | Malware reads app data | OS sandbox, Keystore, short sessions, minimize plaintext lifetime |
| TH-005 | Memory extraction while unlocked | Minimize copies/lifetime; lock and clear references where possible |
| TH-006 | Screenshots or shoulder surfing | Sensitive-screen protection where supported; user awareness |
| TH-007 | Clipboard exposure | Prefer Autofill; timed clearing best effort; API-specific restrictions |
| TH-008 | Biometric convenience bypass | Platform authentication APIs; biometric unlock only unwraps a protected key |
| TH-009 | Record tampering | AEAD authentication and associated data |
| TH-010 | Autofill impersonation | Verify package/signing identity or verified web association; strict matching; explicit selection |
| TH-011 | Notification leakage | Generic notification text by default |
| TH-012 | Secret leakage in logs/crash reports | Redaction policy; no secrets in logs or analytics |
| TH-013 | Malicious dependency/build input | Dependency pinning, review, reproducible CI where feasible, vulnerability checks |
| TH-014 | Rooted/compromised device | Risk warning; disable high-risk convenience features; do not rely on root detection as primary defence |
| TH-015 | Backup tampering or rollback | Authenticated package, format/version checks, integrity validation; rollback policy to be defined |
| TH-016 | Windows local storage theft | Device/user key protection and encrypted portable records |

## 5. Security boundaries and limitations

- A rooted or fully compromised OS may observe data while the vault is unlocked.
- A malicious keyboard or accessibility service may capture typed or displayed secrets.
- Clipboard clearing is best effort. Other applications may already have copied clipboard content.
- Android 8/9 have weaker background clipboard restrictions than newer Android versions.
- Hardware-backed Keystore is not guaranteed on every device.
- Root detection is bypassable and must not be treated as a cryptographic control.
- Locking cannot guarantee that every transient plaintext copy has been overwritten by the runtime or operating system.

## 6. Approved security policies

### Rooted/compromised devices
Warn the user and disable high-risk features such as Autofill and biometric convenience unlock when the risk assessment warrants it. Do not claim that detection is reliable or that vault access is safe under full OS compromise.

### Autofill
If locked, require master password or biometrics. The user must explicitly select a matching credential. No silent credential release.

### Recovery phrase
- Generate high-entropy recovery material.
- Display during initial setup and require confirmation that it was saved.
- Never send it to a server.
- Regeneration requires authentication through the existing master password or recovery process.
- When rotating recovery, verify the new wrapper before invalidating the old one; commit atomically.

### Android 8/9 clipboard
Copying should be disabled by default unless the user explicitly opts in after a warning. On supported newer Android versions, clear after 30 seconds by default, while describing this as best effort.

### Android security patch age
Warn when patches are outdated. Do not automatically lock the user out solely because of patch age. The precise warning threshold remains open.

## 7. Security engineering rules

- Use established cryptographic libraries; do not implement AES, Argon2id, HKDF or random generators manually.
- Authenticate all encrypted records and backup packages.
- Never reuse an AES-GCM nonce with the same key.
- Never store plaintext master passwords, recovery phrases or VEKs.
- Use generic authentication errors to avoid unnecessary information disclosure.
- Avoid custom cryptographic formats without versioning, test vectors and review.
- Clear secret buffers where supported, but do not claim guaranteed memory erasure in managed runtimes.
- Treat cryptographic format changes as migrations, not silent implementation refactors.

## 8. Security validation

Map implementation and tests to relevant OWASP MASVS controls and MASTG test cases. Prioritize storage, cryptography, authentication, platform interaction, network (future cloud only), resilience and privacy.
