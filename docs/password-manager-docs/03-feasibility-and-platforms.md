# 03 — Feasibility and Platform Strategy

## 1. Feasibility conclusion

The proposed product is technically feasible as an offline-first application. The main complexity is not the basic Flutter UI; it is secure key management, Android Autofill integration, cross-platform portable vault handling, and reliable recovery/backup behaviour.

A backend is not required for the MVP.

## 2. Approved technology direction

| Area | Direction | Status |
|---|---|---|
| Shared UI and application logic | Flutter / Dart | Approved |
| Android platform integration | Kotlin | Approved |
| Windows UI | Flutter desktop | Approved |
| Windows device key protection | Windows native APIs, including DPAPI where appropriate | Direction approved; implementation details open |
| iOS | Swift native integration only if iOS is added | Deferred |
| Local database | SQLite | Candidate pending prototype |
| Record encryption | AES-256-GCM | Candidate pending crypto review |
| Password KDF | Argon2id | Candidate pending library and parameter validation |
| Password strength | Local zxcvbn | Approved direction; package selection open |

## 3. Android support

Minimum supported version: Android 8.0 / API 26.

Android Autofill Framework is available from API 26, making the selected minimum compatible with the MVP Autofill requirement. Android 8 and Android 9 have older clipboard behaviour and must receive the additional restrictions described in the requirements.

Do not assume every device has hardware-backed Keystore. Query platform capability and implement a documented fallback. A software-backed key store is not equivalent to a hardware-backed security boundary.

## 4. Development and test devices

- Physical device A: Android 8.0.0 / API 26.
- Physical device B: Android 14.0 / API 34.
- Android Studio emulator: additional API levels, screen sizes and repeatable test environments.

The emulator is useful for automated tests but cannot prove the behaviour of real device biometrics, secure hardware or vendor-specific Keystore implementations.

## 5. Backend and infrastructure

MVP:
- No backend.
- No user account system.
- No server-side credential storage.
- Manual encrypted backup/restore.
- Offline-first operation.

Future cloud:
- Cloud provider may store ciphertext and synchronization metadata only.
- Cloud service must not possess a decryption key.
- Conflict resolution, deletion propagation, device enrollment and rollback protection require a separate design phase before cloud sync is implemented.

## 6. Cross-platform key model

The logical vault format is shared. Each device has a local copy and a device-specific key wrapper:
- Android: Android Keystore-backed wrapping where supported.
- Windows: Windows user/device protection, potentially DPAPI.
- Portable backup: includes only portable key wrappers and encrypted records; excludes device-specific wrappers.

DPAPI and Android Keystore material must never be copied as if it were portable key material.

## 7. Security references

Use OWASP MASVS and OWASP MASTG/MSTG as security design and testing references. These are guidance and test references, not a substitute for a product-specific threat model, code review or independent assessment.

## 8. Feasibility risks

- API 26 devices may have limited or inconsistent hardware-backed security.
- Argon2id memory/time settings must be benchmarked on older devices.
- Flutter lifecycle callbacks cannot be the sole protection for session destruction.
- Android Autofill has native service requirements and must be implemented/tested in Kotlin.
- Windows key storage and recovery need a dedicated platform implementation.
- Cross-platform cryptographic interoperability must be proven with shared test vectors.
