# 08 — Testing Strategy

## 1. Test objectives

Demonstrate that the app:
- Meets functional requirements.
- Preserves confidentiality and integrity under the documented threat model.
- Fails closed on authentication and tampering errors.
- Works on Android 8/API 26 and Android 14/API 34.
- Supports portable backup/recovery across devices.
- Does not leak secrets through logs, notifications, clipboard or Autofill.
- Remains maintainable through automated tests and repeatable release checks.

Testing does not constitute a security certification.

## 2. Test environments

| Environment | Version | Primary use |
|---|---|---|
| Physical Android phone A | Android 8.0.0 / API 26 | Minimum-version compatibility, legacy clipboard and Autofill |
| Physical Android phone B | Android 14.0 / API 34 | Modern platform behaviour, biometrics, clipboard and notifications |
| Android Studio emulator | Configure API 26 and additional API levels | Repeatable automated tests, screen sizes and lifecycle scenarios |
| Windows machine | Supported Windows version to be selected | Desktop build, DPAPI/device wrapper and cross-platform restore |

Record device model, build fingerprint, patch level, app build and test date for security-relevant results.

## 3. Test levels

### Unit tests
- Password policy validation.
- Character-set construction and excluded-character handling.
- Secure random selection wrappers.
- Passphrase selection.
- zxcvbn adapter.
- Record validation and serialization.
- Associated-data encoding.
- KDF parameter validation.
- Tombstone/revision rules.
- Reminder policy.

### Cryptographic tests
- Known-answer tests for selected libraries and constructions.
- Wrong password must fail.
- Modified nonce/ciphertext/tag/AAD must fail.
- Wrong vault ID or record ID in AAD must fail.
- Nonce uniqueness strategy tests.
- Recovery phrase checksum/derivation test vectors.
- Android/Windows cross-platform interoperability vectors.
- KDF resource-limit tests against maliciously large header parameters.

### Integration tests
- Flutter-to-Kotlin method-channel contract.
- Android Keystore wrapper creation and use.
- BiometricPrompt integration.
- AutofillService request lifecycle.
- SQLite transaction and migration behaviour.
- Notification scheduling.
- Backup file provider and restore pipeline.

### System/end-to-end tests
- Create vault, add credentials, lock, unlock and edit.
- Generate password and save it.
- Search while unlocked.
- Trigger reminders.
- Autofill an approved app/site.
- Reject unapproved app/site.
- Export and restore on another device.
- Recover with the 24-word phrase.

### Security tests
- Copy app database and inspect for plaintext.
- Search logs, crash output and temporary files for test secrets.
- Tamper with encrypted records and backup packages.
- Attempt wrong master password and malformed recovery phrase.
- Test app backgrounding and process termination.
- Test clipboard behaviour on API 26 and API 34.
- Inspect notification text while device is locked.
- Test rooted-device warning behaviour on an authorized test device/environment.
- Test malicious or mismatched Autofill requester identity.
- Review dependency vulnerabilities and build provenance.

## 4. Core test cases

| ID | Scenario | Expected result |
|---|---|---|
| TC-001 | Create vault with 14-character master password | Rejected with clear policy message |
| TC-002 | Create vault with 15+ character passphrase | Accepted |
| TC-003 | Unlock with correct master password | Vault unlocks |
| TC-004 | Unlock with incorrect master password | Generic failure; no vault data exposed |
| TC-005 | Modify encrypted record ciphertext | Authentication fails; record not shown |
| TC-006 | Modify record AAD context | Authentication fails |
| TC-007 | Generate password below 12 characters | Configuration rejected |
| TC-008 | Generate password with required groups | Output satisfies configured groups |
| TC-009 | Generate passphrase with default settings | Six words selected |
| TC-010 | Run strength estimation offline | Result produced without network request |
| TC-011 | Save same password in two records | Reuse health check identifies reuse while unlocked |
| TC-012 | Background the app | Main vault session locks |
| TC-013 | Lock device screen | Vault is locked on return |
| TC-014 | Request Autofill while vault locked | Authentication required |
| TC-015 | Request from unapproved app/site | No credential released |
| TC-016 | Request from approved app/site | User selects candidate before release |
| TC-017 | Copy secret on API 26 | Copy disabled by default; explicit opt-in warning required |
| TC-018 | Copy secret on API 34 | Clipboard clear attempted after configured timeout |
| TC-019 | View notification on lock screen | Generic content; no site/title/credential |
| TC-020 | Tamper with backup | Restore rejected; existing vault unchanged |
| TC-021 | Restore valid backup to second phone | Records restored and accessible after authentication |
| TC-022 | Recover with same phrase on another platform | Same logical vault recovered; local device protection re-established |
| TC-023 | Interrupted restore | Existing vault remains intact |
| TC-024 | Delete record then restore older backup | Deletion conflict handled according to defined tombstone policy; no silent resurrection |
| TC-025 | Inspect DB/logs for test credentials | No plaintext sensitive fields or secrets found |

## 5. Cross-device test plan

1. Create vault on Android 8 phone.
2. Add test credentials using synthetic values only.
3. Export encrypted backup.
4. Restore on Android 14 phone.
5. Verify credential count and values after unlock.
6. Repeat in the reverse direction.
7. Recover using the same recovery phrase on the second phone.
8. Verify that device-local wrappers are recreated rather than copied.
9. Repeat using emulator as an additional restore target.
10. When Windows support exists, repeat Android-to-Windows and Windows-to-Android tests.

Never use real production passwords during development testing. Use synthetic credentials.

## 6. Compatibility test matrix

At minimum:
- Android API 26: app launch, vault lifecycle, database, crypto library, Autofill, clipboard warning, notifications.
- Android API 34: same flows plus modern clipboard and biometric behaviour.
- Additional emulator API levels: regression checks for OS changes.
- Windows: portable format, recovery and platform wrapper tests after Windows implementation begins.

## 7. Performance tests

Measure on Android 8 physical device and Android 14:
- Vault creation time.
- Unlock/KDF duration and memory use.
- Record save/read latency.
- Search time with increasing record counts.
- Password generation latency.
- Backup/export and restore duration.
- App memory use and lock responsiveness.

Set numeric performance targets after baseline measurements; do not guess targets before profiling the older device.

## 8. Suggested tools

- Flutter/Dart: `flutter test`, `flutter analyze`.
- Flutter integration: `integration_test`.
- Android: Android Studio, Gradle test tasks, Android instrumentation tests.
- Kotlin: JUnit and AndroidX test tooling as appropriate.
- Static analysis: Dart analyzer and Kotlin lint/static checks.
- Dependency review: dependency lockfiles, vulnerability scanning and manual package review.
- Security: OWASP MASVS/MASTG test guidance; authorized device inspection tools.

Tool versions should be pinned in the repository and CI configuration.

## 9. Release acceptance criteria

A release candidate must:
- Pass all required unit and integration tests.
- Pass core end-to-end flows on Android 8 and Android 14 physical devices.
- Pass backup/restore and recovery tests.
- Fail closed on tampering and wrong authentication.
- Show no plaintext credentials in database inspection, logs or notifications.
- Meet the documented Autofill authentication and strict matching rules.
- Have no unresolved critical/high security findings without explicit documented risk acceptance.
- Have a reviewed dependency list and reproducible build instructions.
- Have updated documentation and migration notes for any format changes.

## 10. Test evidence

For each test run, record:
- Test ID.
- App commit/build identifier.
- Device/API/build details.
- Preconditions and steps.
- Expected result.
- Actual result.
- Pass/fail.
- Logs/screenshots with secrets redacted.
- Defect reference and retest result.

Never attach screenshots or logs containing real credentials, recovery words or keys.
