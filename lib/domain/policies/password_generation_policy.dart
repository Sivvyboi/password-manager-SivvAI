import '../../core/errors.dart';
import '../../core/result.dart';

/// Configuration and validation policy for random password generation.
///
/// Implements FR-018, FR-019, FR-020, FR-021, FR-022, ADR-025, ADR-026.
class PasswordGenerationConfig {
  static const int minLength = 12;
  static const int defaultLength = 20;
  static const int defaultPassphraseWords = 6;
  static const int minPassphraseWords = 4;

  final int length;
  final bool includeUppercase;
  final bool includeLowercase;
  final bool includeDigits;
  final bool includeSymbols;
  final Set<String> excludedCharacters;

  const PasswordGenerationConfig({
    this.length = defaultLength,
    this.includeUppercase = true,
    this.includeLowercase = true,
    this.includeDigits = true,
    this.includeSymbols = true,
    this.excludedCharacters = const {},
  });

  /// Standard character pools
  static const String uppercasePool = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  static const String lowercasePool = 'abcdefghijklmnopqrstuvwxyz';
  static const String digitPool = '0123456789';
  static const String symbolPool = '!@#\$%^&*()-_=+[]{}|;:,.<>?';

  /// Validates the configuration and constructs the allowed character set.
  Result<ResolvedCharacterSet, PolicyFailure> resolveCharacterSet() {
    if (length < minLength) {
      return const Result.err(PolicyFailure.generatedPasswordTooShort);
    }

    final activeGroups = <List<String>>[];

    if (includeUppercase) {
      final filtered = uppercasePool.split('').where((c) => !excludedCharacters.contains(c)).toList();
      if (filtered.isNotEmpty) activeGroups.add(filtered);
    }

    if (includeLowercase) {
      final filtered = lowercasePool.split('').where((c) => !excludedCharacters.contains(c)).toList();
      if (filtered.isNotEmpty) activeGroups.add(filtered);
    }

    if (includeDigits) {
      final filtered = digitPool.split('').where((c) => !excludedCharacters.contains(c)).toList();
      if (filtered.isNotEmpty) activeGroups.add(filtered);
    }

    if (includeSymbols) {
      final filtered = symbolPool.split('').where((c) => !excludedCharacters.contains(c)).toList();
      if (filtered.isNotEmpty) activeGroups.add(filtered);
    }

    if (activeGroups.isEmpty) {
      return const Result.err(PolicyFailure.emptyCharacterSet);
    }

    final combinedSet = <String>{};
    for (final group in activeGroups) {
      combinedSet.addAll(group);
    }

    if (combinedSet.isEmpty) {
      return const Result.err(PolicyFailure.emptyCharacterSet);
    }

    return Result.ok(ResolvedCharacterSet(
      requiredGroups: activeGroups,
      combinedAlphabet: combinedSet.toList()..sort(),
      totalLength: length,
    ));
  }
}

/// Resolved character set ready for cryptographically unbiased selection.
class ResolvedCharacterSet {
  final List<List<String>> requiredGroups;
  final List<String> combinedAlphabet;
  final int totalLength;

  const ResolvedCharacterSet({
    required this.requiredGroups,
    required this.combinedAlphabet,
    required this.totalLength,
  });
}

