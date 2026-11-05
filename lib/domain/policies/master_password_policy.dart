import 'dart:convert';
import '../../core/errors.dart';
import '../../core/result.dart';

/// Policy governing master passwords per FR-002, FR-003, and ADR-007.
///
/// Rules:
/// 1. Minimum 15 characters (measured in unicode code points / graphemes).
/// 2. Long passphrases with arbitrary spacing allowed.
/// 3. NO forced character classes (e.g. mandatory symbols or numbers).
/// 4. Preserves exact raw input: no silent trim, lowercasing, or character replacement.
class MasterPasswordPolicy {
  /// Minimum allowed length for a master password.
  static const int minLength = 15;

  /// Maximum safe password length to protect against denial-of-service in KDF.
  static const int maxLength = 256;

  /// Validates [password] against the master password policy.
  ///
  /// Returns [Result.ok] containing the normalized UTF-8 byte representation,
  /// or [Result.err] with a [PolicyFailure].
  static Result<List<int>, PolicyFailure> validateAndEncode(String password) {
    if (password.charactersCount < minLength) {
      return const Result.err(PolicyFailure.masterPasswordTooShort);
    }

    if (password.charactersCount > maxLength) {
      return const Result.err(
        PolicyFailure('Master password exceeds maximum supported length (256 characters).'),
      );
    }

    // Exact UTF-8 byte encoding without silent stripping or case transformation.
    // Canonical byte representation guaranteed identical across Android and Windows.
    final bytes = utf8.encode(password);
    return Result.ok(bytes);
  }

  /// Checks if [password] meets the length policy without returning bytes.
  static bool isValidLength(String password) {
    final count = password.charactersCount;
    return count >= minLength && count <= maxLength;
  }
}

extension _StringCount on String {
  /// Counts Unicode code points safely without splitting surrogate pairs.
  int get charactersCount => runes.length;
}

