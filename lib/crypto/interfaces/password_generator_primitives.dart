import '../../core/errors.dart';
import '../../core/result.dart';
import '../../domain/policies/password_generation_policy.dart';

/// Primitives for unbiased, cryptographically secure password and passphrase generation.
///
/// Implements FR-018 through FR-023:
/// - Rejection sampling to eliminate modulo bias.
/// - Unbiased Fisher-Yates shuffling.
/// - Guaranteed representation of all selected character groups when possible.
/// - Standard passphrase word generation using vetted wordlists.
abstract interface class PasswordGeneratorPrimitives {
  /// Generates a random password string meeting [config].
  Result<String, PolicyFailure> generatePassword(PasswordGenerationConfig config);

  /// Generates a passphrase containing [wordCount] words separated by [separator].
  Result<String, PolicyFailure> generatePassphrase({
    int wordCount = 6,
    String separator = ' ',
  });

  /// Performs an in-place Fisher-Yates shuffle using an unbiased CSPRNG.
  void unbiasedShuffle<T>(List<T> list);
}

