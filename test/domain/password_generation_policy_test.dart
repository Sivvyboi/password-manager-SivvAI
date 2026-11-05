import 'package:flutter_test/flutter_test.dart';
import 'package:password_generator_and_manager/core/errors.dart';
import 'package:password_generator_and_manager/domain/policies/password_generation_policy.dart';

void main() {
  group('PasswordGenerationConfig (FR-018, FR-019, FR-020, FR-022, ADR-025, TC-007)', () {
    test('TC-007: Rejects generated password length below 12 characters', () {
      const config = PasswordGenerationConfig(length: 11);
      final result = config.resolveCharacterSet();
      expect(result.isErr, isTrue);
      expect(result.match(onOk: (_) => null, onErr: (e) => e), equals(PolicyFailure.generatedPasswordTooShort));
    });

    test('Accepts valid length >= 12 and combines active pools', () {
      const config = PasswordGenerationConfig(length: 16);
      final result = config.resolveCharacterSet();
      expect(result.isOk, isTrue);

      final resolved = result.unwrap;
      expect(resolved.totalLength, equals(16));
      expect(resolved.requiredGroups.length, equals(4)); // upper, lower, digits, symbols
      expect(resolved.combinedAlphabet.isNotEmpty, isTrue);
    });

    test('Accurately excludes configured characters from alphabet and required groups', () {
      const config = PasswordGenerationConfig(
        length: 14,
        includeUppercase: false,
        includeLowercase: true,
        includeDigits: true,
        includeSymbols: false,
        excludedCharacters: {'a', 'b', 'c', '0', '1'},
      );

      final result = config.resolveCharacterSet();
      expect(result.isOk, isTrue);

      final resolved = result.unwrap;
      expect(resolved.combinedAlphabet.contains('a'), isFalse);
      expect(resolved.combinedAlphabet.contains('0'), isFalse);
      expect(resolved.combinedAlphabet.contains('d'), isTrue);
      expect(resolved.combinedAlphabet.contains('2'), isTrue);
      expect(resolved.requiredGroups.length, equals(2)); // lower, digits
    });

    test('Fails with emptyCharacterSet error when no characters remain', () {
      const config = PasswordGenerationConfig(
        length: 16,
        includeUppercase: false,
        includeLowercase: false,
        includeDigits: false,
        includeSymbols: false,
      );

      final result = config.resolveCharacterSet();
      expect(result.isErr, isTrue);
      expect(result.match(onOk: (_) => null, onErr: (e) => e), equals(PolicyFailure.emptyCharacterSet));
    });
  });
}

