# 09 — Decision Register and Open Engineering Items

## 1. Approved decisions

| ID | Decision | State |
|---|---|---|
| ADR-001 | Android first, Windows second | Approved |
| ADR-002 | Flutter/Dart shared application; Kotlin Android integration | Approved |
| ADR-003 | Android minimum API 26 | Approved |
| ADR-004 | Offline-first MVP; no backend required | Approved |
| ADR-005 | One logical vault | Approved |
| ADR-006 | Manual encrypted backup/restore in MVP | Approved |
| ADR-007 | Master password minimum 15 characters | Approved |
| ADR-008 | Optional biometric convenience unlock where supported | Approved |
| ADR-009 | Immediate lock on app background; device lock also locks vault | Approved |
| ADR-010 | No analytics/tracking/advertising telemetry | Approved |
| ADR-011 | No CVV/CVC storage | Approved |
| ADR-012 | 30-second clipboard clearing default where supported; best effort | Approved |
| ADR-013 | Android 8/9 copy disabled by default unless explicit warned opt-in | Policy baseline |
| ADR-014 | Strict exact Autofill associations; multiple approved associations | Approved |
| ADR-015 | Autofill requires authentication if vault locked and explicit selection | Approved |
| ADR-016 | Separate one-request, one-credential Autofill-only session | Approved |
| ADR-017 | Encrypted record-level storage strategy | Approved |
| ADR-018 | Same portable logical vault format across Android and Windows | Approved |
| ADR-019 | Device-specific key wrappers remain local | Approved |
| ADR-020 | Recovery phrase is 24 words / 256-bit entropy, same across platforms | Approved |
| ADR-021 | Recovery rotation verifies new wrapper before invalidating old | Approved |
| ADR-022 | Encrypted tombstones for record deletion | Approved |
| ADR-023 | No TOTP in MVP | Deferred |
| ADR-024 | No attachments in MVP | Deferred |
| ADR-025 | Password minimum generated length 12 | Approved |
| ADR-026 | Default passphrase length six words | Approved |
| ADR-027 | Local zxcvbn strength estimation | Approved |
| ADR-028 | Security settings are local/device-specific | Approved |
| ADR-029 | Android test devices: API 26 and API 34 plus emulator | Confirmed |
| ADR-030 | Master password length counted strictly in Unicode code points (>= 15); raw UTF-8 preservation; no silent trim or lowercasing | Proposed (Doc 10) |
| ADR-031 | Canonical AAD binary encoding layout (`PMAA` header + big-endian fields + uint32 range check) | Proposed (Doc 10) |
| ADR-032 | Primary crypto library candidate: `cryptography` package (^2.9.0, Apache 2.0); `bip39` (^1.0.6) for mnemonic | Candidate (Doc 10) |
| ADR-033 | Per-record key derivation via HKDF-SHA256 with keyEpoch to bound AES-GCM nonce collision risks (max 2^16 writes per key) | Proposed (Doc 10) |
| ADR-034 | BIP39 Seed (PBKDF2-HMAC-SHA512, c=2048, salt='mnemonic') + two-stage HKDF-SHA256 Extract-and-Expand recovery derivation bound to Vault ID | Proposed (Doc 10) |
| ADR-035 | Atomic VEK rotation and record re-encryption upon backup restore to eliminate cross-timeline nonce reuse | Proposed (Doc 10) |

## 2. Candidate technical choices — not yet frozen

- SQLite implementation/package (Evaluation in Phase 2).
- Argon2id library (`cryptography` ^2.9.0 recommended, Apache 2.0, isolate execution) and parameters ($m=64\text{ MiB}, t=3, p=4$ pending physical API 26 benchmark).
- `cryptography_flutter` plugin (^2.3.4, Apache 2.0) for platform ciphers (does not accelerate Argon2id).
- AES-256-GCM library (`cryptography` package candidate) and per-record key derivation design (Proposed in ADR-033).
- Nonce generation: OS CSPRNG 96-bit random nonce with per-record key derivation (invocation limit $2^{16}$ writes per record key, $2^{24}$ vault writes).
- HKDF hierarchy and exact context strings (`PM-RECORD-KEY-V1:recordId:keyEpoch`, `PM-RECOVERY-WRAP-V1:vaultId`, `PM-BACKUP-KEY-V1:vaultId` proposed in Doc 10).
- Recovery mnemonic-to-key derivation (BIP39 seed + HKDF-SHA256 Extract-and-Expand proposed in Doc 10).
- Canonical serialization and associated-data byte encoding (Specified in Doc 10; unit tested).
- zxcvbn package and wordlist licensing/maintenance (Evaluation in Phase 3).
- Windows key wrapper implementation (Phase 5).
- Android 8/9 clipboard opt-in UX (Phase 5).
- Exact website association verification and URL canonicalization (Specified in Doc 10).
- KDF performance targets (To be established via Android 8 benchmark plan).

## 3. Open security and product decisions

1. Define Android security patch warning threshold.
2. Define tombstone retention and stale-backup restore policy.
3. Define key rotation and cryptographic format migration.
4. Define session timeout behaviour for Autofill-only requests.
5. Define exact biometric reauthentication policy and fallback behaviour.
6. Define whether credential type and minimal record metadata may be visible in the SQLite schema.
7. Define maximum supported vault size and resource limits for backup import.
8. Define recovery phrase rotation UX and backup compatibility.
9. Define Windows supported versions and Windows test environment.
10. Define release signing, key management and build/release pipeline.

## 4. Requirements traceability

| Requirement area | Main document | Main test evidence |
|---|---|---|
| Product scope and UX | 01, 02 | End-to-end tests |
| Platform compatibility | 03, 08 | API 26/API 34 device matrix |
| Threat controls | 04 | Security test suite |
| Architecture boundaries | 05 | Code review and integration tests |
| Storage and encryption | 06, 07 | Crypto tests and DB inspection |
| Generator and health | 02, 07 | Unit tests |
| Autofill | 02, 05, 07 | Native integration and requester identity tests |
| Backup and recovery | 02, 06, 07 | Cross-device restore/recovery tests |
| Locking and privacy | 02, 04, 07 | Lifecycle, notification and clipboard tests |

## 5. Change control

When changing an approved decision:
1. Identify the ADR and affected requirements.
2. Explain why the change is needed.
3. Assess impact on storage compatibility, recovery, platform support and tests.
4. Add a migration plan if persisted data or cryptographic format changes.
5. Update this register and affected module documents.
6. Obtain explicit project-owner approval before implementation.

## 6. Implementation handoff rules for Antigravity AI

Every coding prompt should include:
- The specific milestone and allowed scope.
- Relevant requirement IDs.
- Relevant architecture and data-model modules.
- Files/modules it may create or modify.
- Explicit prohibited changes (especially cryptographic format changes).
- Required tests and acceptance criteria.
- Request for a concise change summary and list of assumptions.
- Instruction to stop and ask questions when specifications conflict or security details are missing.

Antigravity must not silently decide cryptographic constructions, key formats, nonce policies, recovery derivation, database migrations or security trade-offs. Those require explicit design review.
