// ignore: implementation_imports
import 'package:bip39/src/wordlists/english.dart' as bip39_words;
import '../../core/errors.dart';
import '../../core/result.dart';
import '../../domain/policies/password_generation_policy.dart';
import '../interfaces/password_generator_primitives.dart';
import '../interfaces/secure_random_source.dart';
import 'standard_secure_random_source.dart';

/// Concrete implementation of [PasswordGeneratorPrimitives] implementing FR-018 through FR-023.
///
/// Features:
/// - Unbiased Fisher-Yates shuffling using OS CSPRNG rejection sampling.
/// - Guaranteed representation of all selected character pools.
/// - Unbiased selection from vetted wordlist for passphrases.
class PasswordGeneratorPrimitivesImpl implements PasswordGeneratorPrimitives {
  final SecureRandomSource _randomSource;

  PasswordGeneratorPrimitivesImpl({SecureRandomSource? randomSource})
      : _randomSource = randomSource ?? StandardSecureRandomSource();

  @override
  void unbiasedShuffle<T>(List<T> list) {
    for (var i = list.length - 1; i > 0; i--) {
      final j = _randomSource.nextBoundedInt(i + 1);
      final temp = list[i];
      list[i] = list[j];
      list[j] = temp;
    }
  }

  @override
  Result<String, PolicyFailure> generatePassword(PasswordGenerationConfig config) {
    final resolution = config.resolveCharacterSet();
    if (resolution case Err(:final error)) {
      return Result.err(error);
    }

    final resolved = (resolution as Ok<ResolvedCharacterSet, PolicyFailure>).value;
    final chars = <String>[];

    // Ensure at least one character from each active required group
    for (final group in resolved.requiredGroups) {
      final index = _randomSource.nextBoundedInt(group.length);
      chars.add(group[index]);
    }

    // Fill the remaining length from the combined alphabet
    final remainingCount = resolved.totalLength - chars.length;
    for (var i = 0; i < remainingCount; i++) {
      final index = _randomSource.nextBoundedInt(resolved.combinedAlphabet.length);
      chars.add(resolved.combinedAlphabet[index]);
    }

    // Perform unbiased in-place Fisher-Yates shuffle
    unbiasedShuffle(chars);

    return Result.ok(chars.join(''));
  }

  @override
  Result<String, PolicyFailure> generatePassphrase({
    int wordCount = PasswordGenerationConfig.defaultPassphraseWords,
    String separator = ' ',
  }) {
    if (wordCount < PasswordGenerationConfig.minPassphraseWords) {
      return const Result.err(
        PolicyFailure('Passphrase must contain at least 4 words.', code: 'POLICY_PASSPHRASE_TOO_SHORT'),
      );
    }

    final wordlist = bip39_words.WORDLIST;
    final selectedWords = List<String>.generate(wordCount, (_) {
      final index = _randomSource.nextBoundedInt(wordlist.length);
      return wordlist[index];
    });

    return Result.ok(selectedWords.join(separator));
  }
}
