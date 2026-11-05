import 'package:flutter_test/flutter_test.dart';
import 'package:password_generator_and_manager/core/types/format_version.dart';
import 'package:password_generator_and_manager/core/types/record_id.dart';
import 'package:password_generator_and_manager/core/types/vault_id.dart';

void main() {
  group('VaultId & RecordId', () {
    test('Valid canonical UUID strings are accepted', () {
      const validUuid = '123e4567-e89b-12d3-a456-426614174000';
      final vaultId = VaultId.fromString(validUuid);
      expect(vaultId.value, equals(validUuid));
      expect(vaultId.toString(), equals(validUuid));

      final recordId = RecordId.fromString(validUuid);
      expect(recordId.value, equals(validUuid));
      expect(recordId.toString(), equals(validUuid));
    });

    test('Invalid UUID strings are rejected with ArgumentError', () {
      expect(() => VaultId.fromString('not-a-uuid'), throwsArgumentError);
      expect(() => RecordId.fromString('12345'), throwsArgumentError);
      expect(VaultId.tryParse('invalid'), isNull);
      expect(RecordId.tryParse(''), isNull);
    });

    test('Uppercase UUIDs are normalized to lowercase', () {
      const upper = '123E4567-E89B-12D3-A456-426614174000';
      final vaultId = VaultId.fromString(upper);
      expect(vaultId.value, equals(upper.toLowerCase()));
    });
  });

  group('FormatVersion', () {
    test('Format version properties and equality', () {
      expect(FormatVersion.v1.value, equals(1));
      expect(FormatVersion.v1.isSupported, isTrue);
      expect(const FormatVersion(2).isSupported, isFalse);
      expect(FormatVersion.v1, equals(const FormatVersion(1)));
      expect(const FormatVersion(2) > FormatVersion.v1, isTrue);
    });

    test('Negative or zero format versions are rejected', () {
      expect(() => FormatVersion(0), throwsAssertionError);
      expect(() => FormatVersion(-1), throwsAssertionError);
    });
  });
}

