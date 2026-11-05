import 'package:flutter_test/flutter_test.dart';
import 'package:password_generator_and_manager/crypto/models/key_types.dart';

void main() {
  group('KeyTypes & SecretKeyBytes (Hygiene & Zeroization)', () {
    final valid32Bytes = List<int>.filled(32, 0x42);

    test('Accepts exactly 32 bytes and redacts toString()', () {
      final vek = VaultEncryptionKey(valid32Bytes);
      expect(vek.length, equals(32));
      expect(vek.bytes, equals(valid32Bytes));
      expect(vek.toString(), equals('VaultEncryptionKey([REDACTED])'));
      expect(vek.toString().contains('42'), isFalse);
    });

    test('Rejects invalid key length with ArgumentError', () {
      expect(() => VaultEncryptionKey(List<int>.filled(16, 0x01)), throwsArgumentError);
      expect(() => MasterWrappingKey(List<int>.filled(64, 0x01)), throwsArgumentError);
      expect(() => RecoveryWrappingKey(List<int>.filled(31, 0x01)), throwsArgumentError);
      expect(() => RecordEncryptionKey(List<int>.filled(33, 0x01)), throwsArgumentError);
    });

    test('Zeroizes bytes on destroy() and prohibits subsequent access', () {
      final key = MasterWrappingKey(List<int>.filled(32, 0xAA));
      expect(key.isDisposed, isFalse);

      key.destroy();
      expect(key.isDisposed, isTrue);
      expect(() => key.bytes, throwsStateError);
    });
  });
}

