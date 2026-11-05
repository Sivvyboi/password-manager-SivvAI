# 01 — Product Overview

## 1. Product summary

The Password Manager is an offline-first password manager and password generator. The initial release targets Android, followed by Windows. Its primary purpose is to let a user securely create, store, organize, retrieve and autofill credentials without requiring a cloud account or sending vault contents to a server.

The interface should remain simple. Security should operate automatically in the background, with clear explanations when user action is needed.

## 2. Product vision

Provide a practical, privacy-focused password manager whose vault is encrypted locally, whose data can be moved between supported platforms through an authenticated portable format, and whose future cloud features cannot decrypt user vault contents.

## 3. Product principles

- **Local-first:** core vault operations work offline.
- **Privacy by design:** no analytics, tracking or advertising telemetry.
- **Security by default:** short sessions, explicit Autofill release, encrypted storage and generic notifications.
- **Usable security:** avoid unnecessary security choices; explain exceptional risks.
- **Portability:** one logical vault format across Android and Windows.
- **Modular implementation:** shared Dart business logic with native platform adapters.
- **Honest security claims:** protections have limits, especially on rooted or compromised devices.

## 4. Target platforms and users

### Initial platform order
1. Android.
2. Windows.

The user has an Android 8.0.0 phone, an Android 14.0 phone and an Android Studio emulator for development and testing.

### Minimum Android version
Android 8.0 / API 26.

### Framework direction
Flutter and Dart for shared application code. Kotlin for Android-native integrations. Windows-specific native APIs may be used behind an adapter. Swift is not part of the current roadmap; it may be considered if iOS is added later.

## 5. MVP scope

### Included
- One logical vault per installation.
- Master-password-protected vault.
- Optional biometric convenience unlock where supported.
- Recovery phrase.
- Local encrypted storage.
- Credential creation, viewing, editing, categorization and deletion.
- Built-in and custom categories.
- Password generator and passphrase generator.
- Password strength estimation using a local zxcvbn implementation.
- Local password health checks for weak, reused and age-related credentials.
- User-configurable renewal reminders.
- Android Autofill with explicit authentication and selection.
- Encrypted manual backup and restore.
- Credential types: login, secure note, payment card, Wi-Fi credential and software licence key.
- Generic lock-screen notifications.
- Clipboard clearing after 30 seconds by default, best effort and subject to OS limitations.

### Excluded from MVP
- Cloud backup and cloud synchronization.
- TOTP/authenticator code generation.
- File attachments.
- CVV/CVC storage.
- Analytics, tracking and advertising telemetry.
- iOS support.
- Multiple independent vaults per installation.

## 6. Future possibilities

Potential premium features:
- Encrypted cloud backup.
- Multi-device synchronization.
- Advanced security reports.
- Additional customization.

Essential security controls should remain available in the free product. Any future cloud service must not receive keys that allow it to decrypt vault contents.

## 7. User experience principles

Primary navigation is expected to include:
- Vault
- Generator
- Security
- Settings

Renewal reminders should be accessible from the relevant credential and a central reminders view.

The user should not need to understand cryptographic details during normal use. Security warnings should be specific and actionable, not alarmist.

## 8. Key product constraints

- The master password must be at least 15 characters.
- Allow long passphrases and spaces; do not require arbitrary character composition.
- Generated passwords have a minimum length of 12 characters.
- Default passphrase length is six words.
- Payment card records must not contain CVV/CVC.
- The vault locks immediately when the app enters the background, and device screen locking also locks the vault.
- Security settings are local and device-specific.
- Android 8/9 clipboard behaviour is less controllable; copying should be disabled by default on these versions unless the user explicitly opts in after a warning.
