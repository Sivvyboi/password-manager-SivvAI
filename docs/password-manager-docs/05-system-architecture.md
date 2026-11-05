# 05 — System Architecture

## 1. Architectural style

Use a modular monolith. The MVP does not need microservices or a backend. Keep clear boundaries so the app can evolve without splitting into distributed services prematurely.

## 2. High-level layers

1. **Presentation:** Flutter screens, navigation, view state and accessibility.
2. **Application:** use cases, orchestration, validation and session coordination.
3. **Domain:** entities, policies and business rules independent of Flutter and platform APIs.
4. **Security/cryptography:** KDF, key wrapping, AEAD, random generation, recovery derivation and secret handling.
5. **Data:** repositories, SQLite persistence, serialization and migrations.
6. **Platform adapters:** Kotlin Android integrations and Windows-native integrations.

## 3. Proposed module boundaries

| Module | Responsibility |
|---|---|
| `core` | Shared types, errors, result handling and utilities |
| `vault` | Vault lifecycle, session and authentication orchestration |
| `crypto` | KDF, key wrapping, AEAD, HKDF and secure randomness |
| `credentials` | Credential entities and use cases |
| `generator` | Password/passphrase generation and strength estimation |
| `security` | Security status, health checks and risk warnings |
| `reminders` | Renewal policy and notification scheduling |
| `autofill` | Autofill domain rules and request coordination |
| `backup` | Portable package export/import |
| `settings` | Device-local preferences |
| `storage` | SQLite repositories and migrations |
| `platform` | Interfaces and platform-specific adapters |

## 4. Android native boundary

Kotlin owns Android-specific capabilities:
- AutofillService implementation.
- Android Keystore access.
- BiometricPrompt integration.
- Notification scheduling.
- Clipboard interactions.
- App/package identity and signing-certificate verification.
- Android lifecycle and device security capability checks.

Flutter/Dart calls native functionality through a narrow, documented platform-channel interface. Do not duplicate vault business logic or cryptographic policy in Kotlin.

## 5. Windows boundary

Windows-specific adapters provide:
- Device/user key protection (DPAPI may be evaluated).
- Windows-native secure unlock integration where supported.
- Desktop lifecycle and notification integration.

Windows device keys are not portable and must not be included in a portable backup.

## 6. Session model

The main vault session is destroyed/locked when the app backgrounds. Autofill is an explicit exception: a separate, short-lived Autofill-only session may exist for one request and one selected credential. It must not restore the general vault session.

The app must not rely solely on Flutter lifecycle callbacks; process termination and OS behaviour may bypass expected callbacks. Design session expiry and native integration defensively.

## 7. Data flow: unlock

1. User enters master password.
2. Application loads vault header and KDF parameters.
3. KDF derives a wrapping key.
4. Authenticated unwrap attempts to recover the VEK.
5. On success, create a bounded unlocked session.
6. On failure, return a generic authentication failure.
7. Do not retain the master password after derivation.

## 8. Data flow: Autofill

1. Android AutofillService receives a request.
2. Native layer identifies requesting app/site.
3. App asks the vault domain for exact approved matches.
4. If locked, require authentication.
5. Show matching candidates.
6. User explicitly selects one.
7. Recheck the requesting identity and association.
8. Release only the selected credential to the current Autofill request.
9. Destroy the Autofill-only session and transient plaintext.

## 9. Data flow: backup and restore

Export:
1. Require authentication.
2. Read and validate records.
3. Build portable package with version and portable wrappers.
4. Authenticate and encrypt package.
5. Write to user-selected destination.
6. Verify written package integrity.

Restore:
1. Read package and validate format/version.
2. Authenticate and decrypt.
3. Validate all records and cryptographic tags.
4. Create a new database in a temporary location.
5. Verify import.
6. Atomically commit; never partially overwrite the current vault.

## 10. Dependency direction

Presentation may depend on application interfaces. Application may depend on domain and interfaces for data/platform services. Domain must not depend on Flutter, SQLite or Android APIs. Platform adapters implement interfaces defined by shared layers.

## 11. Architecture quality gates

- No cryptography implemented in UI widgets.
- No direct SQLite access from presentation code.
- No Android API calls from domain logic.
- No plaintext sensitive fields in database columns or indexes.
- Platform channels expose minimal operations and validate all inputs.
- All serialized formats are versioned.
