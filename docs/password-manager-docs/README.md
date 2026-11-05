# Password Manager — Project Documentation

**Documentation baseline:** Phases 1–8  
**Product direction:** Android-first, Windows second; offline-first; local encrypted vault  
**Status:** Planning baseline. These documents record agreed product and architecture decisions; cryptographic choices marked *candidate* still require implementation review and security validation.

## Purpose

This repository contains the approved planning documentation for the Password Manager project. It is modular so that Antigravity AI can work from one focused specification at a time, while GitHub remains the source of truth.

## Document map

| Module | Contents |
|---|---|
| `01-product-overview.md` | Vision, goals, scope, users, principles and roadmap |
| `02-requirements.md` | Functional and non-functional requirements, MVP boundaries |
| `03-feasibility-and-platforms.md` | Technology choices, platform constraints and feasibility |
| `04-threat-model-and-security.md` | Assets, threat actors, threats, controls and limitations |
| `05-system-architecture.md` | Layers, modules, boundaries, platform adapters and flows |
| `06-data-model-and-storage.md` | Vault schema, record model, encryption boundaries and portability |
| `07-algorithm-design.md` | Vault lifecycle, cryptography, generator, health, Autofill and backup algorithms |
| `08-testing-strategy.md` | Test levels, device matrix, security tests and acceptance criteria |
| `09-decisions-and-open-items.md` | Decision register, traceability and unresolved engineering work |

## Reading order

Read `01` through `08` in order. Read `09` before changing an approved decision or starting implementation.

## Project guardrails

1. Do not begin implementation by inventing requirements. Follow these documents and raise conflicts as questions.
2. Security-critical code must not be accepted solely because it compiles or passes happy-path tests.
3. Do not log, transmit, or persist plaintext credentials, master passwords, recovery phrases, derived keys or vault encryption keys.
4. Treat all cryptographic parameters as versioned format decisions. Never silently change them for existing vaults.
5. Keep Android platform-specific functionality behind Kotlin adapters and a narrow Flutter platform-channel boundary.
6. Keep the portable vault format independent of Android Keystore and Windows DPAPI.
7. Do not claim protection against a fully compromised operating system or an attacker controlling an unlocked device.
8. Every implementation change should include tests and update the relevant module when behaviour or format changes.

## Status vocabulary

- **Approved:** explicitly selected as a product or architecture decision.
- **Proposed:** a recommended design not yet explicitly approved.
- **Candidate:** a technology or parameter to prototype, benchmark and review before freezing.
- **Deferred:** intentionally excluded from the MVP.
- **Open:** requires a decision or technical validation.

## Implementation workflow

For each milestone:
1. Identify the relevant requirements and architecture modules.
2. Ask Antigravity to implement only the scoped task.
3. Review the generated diff and tests.
4. Run Flutter/Dart tests and Android tests in Android Studio.
5. Test on Android 8 and Android 14 physical devices where relevant.
6. Review security-sensitive code manually.
7. Commit the change with a clear message and update documentation if needed.

This documentation is a design baseline, not a security certification or independent audit.
