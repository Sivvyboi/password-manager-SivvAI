import 'dart:math';
import 'package:flutter_test/flutter_test.dart';
import 'package:password_generator_and_manager/crypto/services/password_generator_primitives_impl.dart';
import 'package:password_generator_and_manager/crypto/services/standard_secure_random_source.dart';
import 'package:password_generator_and_manager/domain/policies/password_generation_policy.dart';

class _MockRandom implements Random {
  int _state = 0;
  @override
  bool nextBool() => true;
  @override
  double nextDouble() => 0.5;
  @override
  int nextInt(int max) {
    final res = _state % max;
    _state++;
    return res;
  }
}

void main() {
  group('PasswordGeneratorPrimitivesImpl', () {
    final generator = PasswordGeneratorPrimitivesImpl();

    test('Unbiased Fisher-Yates shuffle preserves all elements', () {
      final original = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
      final shuffled = List<int>.from(original);

      generator.unbiasedShuffle(shuffled);

      expect(shuffled.length, original.length);
      // All elements preserved
      expect(shuffled.toSet(), original.toSet());
    });

    test('generatePassword satisfies length and active character groups', () {
      const config = PasswordGenerationConfig(
        length: 20,
        includeUppercase: true,
        includeLowercase: true,
        includeDigits: true,
        includeSymbols: true,
      );

      final result = generator.generatePassword(config);
      expect(result.isOk, isTrue);
      final password = result.unwrap;
      expect(password.length, 20);

      // Verify at least one character from each active group
      expect(password.contains(RegExp(r'[A-Z]')), isTrue);
      expect(password.contains(RegExp(r'[a-z]')), isTrue);
      expect(password.contains(RegExp(r'[0-9]')), isTrue);
      expect(password.contains(RegExp(r'[!@#\$%^&*()\-_=+\[\]{}|;:,.<>?]')), isTrue);
    });

    test('generatePassphrase generates specified word count and separator', () {
      final result = generator.generatePassphrase(wordCount: 6, separator: '-');
      expect(result.isOk, isTrue);
      final passphrase = result.unwrap;

      final words = passphrase.split('-');
      expect(words.length, 6);
      for (final w in words) {
        expect(w.isNotEmpty, isTrue);
      }
    });

    test('generatePassphrase rejects word count below minimum (4 words)', () {
      final result = generator.generatePassphrase(wordCount: 3);
      expect(result.isErr, isTrue);
    });

    test('Deterministic test injection produces reproducible passwords', () {
      final mockRandom1 = _MockRandom();
      final mockRandom2 = _MockRandom();

      final gen1 = PasswordGeneratorPrimitivesImpl(
        randomSource: StandardSecureRandomSource(mockRandom1),
      );
      final gen2 = PasswordGeneratorPrimitivesImpl(
        randomSource: StandardSecureRandomSource(mockRandom2),
      );

      const config = PasswordGenerationConfig(length: 16);
      final pw1 = gen1.generatePassword(config).unwrap;
      final pw2 = gen2.generatePassword(config).unwrap;

      expect(pw1, pw2);
    });
  });
}
