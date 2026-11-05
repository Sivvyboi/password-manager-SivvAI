import 'dart:convert';
import '../../core/errors.dart';
import '../../core/result.dart';

/// Policy governing master passwords per FR-002, FR-003, and ADR-007.
///
/// Rules:
/// 1. Minimum 15 characters, measured strictly in Unicode code points (runes).
/// 2. Long passphrases with arbitrary spacing allowed.
/// 3. NO forced character classes (e.g. mandatory symbols or numbers).
/// 4. Preserves exact raw input: no silent trim, lowercasing, or character replacement.
class MasterPasswordPolicy {
  /// Minimum allowed length for a master password (in Unicode code points).
  static const int minLength = 15;

  /// Maximum safe password length to protect against denial-of-service in KDF.
  static const int maxLength = 256;

  /// Validates [password] against the master password policy.
  ///
  /// Length is evaluated strictly by counting Unicode code points (runes).
  /// Returns [Result.ok] containing the raw UTF-8 byte representation,
  /// or [Result.err] with a [PolicyFailure].
  static Result<List<int>, PolicyFailure> validateAndEncode(String password) {
    final count = password.codePointCount;

    if (count < minLength) {
      return const Result.err(PolicyFailure.masterPasswordTooShort);
    }

    if (count > maxLength) {
      return const Result.err(
        PolicyFailure('Master password exceeds maximum supported length (256 code points).'),
      );
    }

    // Exact UTF-8 byte encoding without silent stripping or case transformation.
    // Canonical byte representation guaranteed identical across Android and Windows.
    final bytes = utf8.encode(password);
    return Result.ok(bytes);
  }

  /// Checks if [password] meets the length policy without returning bytes.
  static bool isValidLength(String password) {
    final count = password.codePointCount;
    return count >= minLength && count <= maxLength;
  }
}

extension _StringCodePoints on String {
  /// Counts Unicode scalar values / code points deterministically.
  int get codePointCount => runes.length;
}
