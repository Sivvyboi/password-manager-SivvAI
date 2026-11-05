import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:password_generator_and_manager/core/errors.dart';
import 'package:password_generator_and_manager/domain/policies/master_password_policy.dart';

void main() {
  group('MasterPasswordPolicy (FR-002, FR-003, ADR-007, TC-001, TC-002)', () {
    test('TC-001: Rejects master password shorter than 15 characters', () {
      final result = MasterPasswordPolicy.validateAndEncode('ShortPass123!');
      expect(result.isErr, isTrue);
      expect(result.match(onOk: (_) => null, onErr: (e) => e), equals(PolicyFailure.masterPasswordTooShort));
      expect(MasterPasswordPolicy.isValidLength('12345678901234'), isFalse);
    });

    test('TC-002: Accepts 15-character password and produces exact UTF-8 bytes', () {
      const pass15 = 'CorrectHorse15!';
      final result = MasterPasswordPolicy.validateAndEncode(pass15);
      expect(result.isOk, isTrue);
      expect(result.unwrap, equals(utf8.encode(pass15)));
      expect(MasterPasswordPolicy.isValidLength(pass15), isTrue);
    });

    test('Counts length strictly by Unicode code points (runes), not UTF-16 code units', () {
      // 14 emoji (surrogate pairs in UTF-16, 28 UTF-16 code units, but only 14 code points)
      final fourteenCodePoints = '🔒' * 14;
      expect(fourteenCodePoints.length, equals(28)); // 28 UTF-16 units
      expect(fourteenCodePoints.runes.length, equals(14)); // 14 code points
      expect(MasterPasswordPolicy.validateAndEncode(fourteenCodePoints).isErr, isTrue);

      // 15 emoji code points
      final fifteenCodePoints = '🔒' * 15;
      expect(fifteenCodePoints.runes.length, equals(15));
      expect(MasterPasswordPolicy.validateAndEncode(fifteenCodePoints).isOk, isTrue);
    });

    test('Accepts long passphrases with arbitrary spaces without forced character classes', () {
      const passphrase = 'battery staple horse staple correct blue moon';
      final result = MasterPasswordPolicy.validateAndEncode(passphrase);
      expect(result.isOk, isTrue);
      expect(result.unwrap, equals(utf8.encode(passphrase)));
    });

    test('Preserves raw whitespace and casing without silent alteration', () {
      const passWithLeadingTrailingSpaces = '   padded secret passphrase 123   ';
      final result = MasterPasswordPolicy.validateAndEncode(passWithLeadingTrailingSpaces);
      expect(result.isOk, isTrue);
      // Byte comparison proves no silent trim occurred
      expect(result.unwrap, equals(utf8.encode(passWithLeadingTrailingSpaces)));
    });

    test('Handles multibyte Unicode characters and accents accurately', () {
      const unicodePass = 'mot-de-passe-sécurisé-étendu';
      final result = MasterPasswordPolicy.validateAndEncode(unicodePass);
      expect(result.isOk, isTrue);
      expect(result.unwrap, equals(utf8.encode(unicodePass)));
    });

    test('Rejects passwords exceeding 256 code points to avoid KDF DoS', () {
      final excessivelyLong = 'A' * 257;
      final result = MasterPasswordPolicy.validateAndEncode(excessivelyLong);
      expect(result.isErr, isTrue);
    });
  });
}
