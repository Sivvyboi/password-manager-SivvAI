import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:password_generator_and_manager/core/errors.dart';
import 'package:password_generator_and_manager/core/result.dart';
import 'package:password_generator_and_manager/core/types/vault_id.dart';
import 'package:password_generator_and_manager/crypto/models/key_types.dart';
import 'package:password_generator_and_manager/crypto/services/hkdf_service_impl.dart';

Uint8List _hexToBytes(String hex) {
  final clean = hex.replaceAll(' ', '');
  final result = Uint8List(clean.length ~/ 2);
  for (var i = 0; i < result.length; i++) {
    result[i] = int.parse(clean.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return result;
}

String _bytesToHex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

void main() {
  group('HkdfServiceImpl', () {
    final hkdf = HkdfServiceImpl();

    test('RFC 5869 Test Case 1 (Extract, Expand, and ExtractAndExpand)', () async {
      final ikm = _hexToBytes('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
      final salt = _hexToBytes('000102030405060708090a0b0c');
      final info = _hexToBytes('f0f1f2f3f4f5f6f7f8f9');
      const outputLength = 42;

      // Stage 1: Extract
      final extractRes = await hkdf.extract(ikm: ikm, salt: salt);
      expect(extractRes.isOk, isTrue);
      final prk = (extractRes as Ok<Uint8List, CryptoFailure>).value;
      const expectedPrk =
          '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5';
      expect(_bytesToHex(prk), expectedPrk);

      // Stage 2: Expand
      final expandRes = await hkdf.expand(
        prk: prk,
        info: info,
        outputLength: outputLength,
      );
      expect(expandRes.isOk, isTrue);
      final okm = (expandRes as Ok<Uint8List, CryptoFailure>).value;
      const expectedOkm =
          '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf'
          '34007208d5b887185865';
      expect(_bytesToHex(okm), expectedOkm);

      // Combined ExtractAndExpand
      final ikmKey = MasterWrappingKey(Uint8List(32)..setRange(0, 22, ikm));
      final combinedRes = await hkdf.extractAndExpand(
        ikm: ikmKey,
        salt: salt,
        info: info,
        outputLength: outputLength,
      );
      expect(combinedRes.isOk, isTrue);
    });

    test('Per-record key derivation domain separation', () async {
      final vek = VaultEncryptionKey(Uint8List(32)..fillRange(0, 32, 0x11));
      final salt = Uint8List(16)..fillRange(0, 16, 0x22);

      const recordIdA = '11111111-1111-1111-1111-111111111111';
      const recordIdB = '22222222-2222-2222-2222-222222222222';

      // Record A, Epoch 0
      final resA0 = await hkdf.deriveRecordKey(
        vek: vek,
        salt: salt,
        recordId: recordIdA,
        keyEpoch: 0,
      );
      expect(resA0.isOk, isTrue);
      final keyA0 = (resA0 as Ok<RecordEncryptionKey, CryptoFailure>).value;

      // Record B, Epoch 0 (different record ID -> different key)
      final resB0 = await hkdf.deriveRecordKey(
        vek: vek,
        salt: salt,
        recordId: recordIdB,
        keyEpoch: 0,
      );
      expect(resB0.isOk, isTrue);
      final keyB0 = (resB0 as Ok<RecordEncryptionKey, CryptoFailure>).value;
      expect(_bytesToHex(keyA0.bytes), isNot(_bytesToHex(keyB0.bytes)));

      // Record A, Epoch 1 (same record ID, different epoch -> different key)
      final resA1 = await hkdf.deriveRecordKey(
        vek: vek,
        salt: salt,
        recordId: recordIdA,
        keyEpoch: 1,
      );
      expect(resA1.isOk, isTrue);
      final keyA1 = (resA1 as Ok<RecordEncryptionKey, CryptoFailure>).value;
      expect(_bytesToHex(keyA0.bytes), isNot(_bytesToHex(keyA1.bytes)));

      // Determinism: same inputs produce identical key
      final resA0Again = await hkdf.deriveRecordKey(
        vek: vek,
        salt: salt,
        recordId: recordIdA,
        keyEpoch: 0,
      );
      final keyA0Again = (resA0Again as Ok<RecordEncryptionKey, CryptoFailure>).value;
      expect(_bytesToHex(keyA0.bytes), _bytesToHex(keyA0Again.bytes));
    });

    test('Recovery key derivation determinism and purpose separation', () async {
      final seed64 = Uint8List(64)..fillRange(0, 64, 0x55);
      final salt1 = Uint8List(16)..fillRange(0, 16, 0x33);
      final salt2 = Uint8List(16)..fillRange(0, 16, 0x44);
      final vaultId1 = VaultId.fromString('123e4567-e89b-12d3-a456-426614174000');
      final vaultId2 = VaultId.fromString('987fcdeb-51a2-43f1-b987-123456789abc');

      final res1 = await hkdf.deriveRecoveryKey(
        bip39Seed64: seed64,
        salt: salt1,
        vaultId: vaultId1.value,
      );
      expect(res1.isOk, isTrue);
      final rwk1 = (res1 as Ok<RecoveryWrappingKey, CryptoFailure>).value;

      // Deterministic replay
      final res1Replay = await hkdf.deriveRecoveryKey(
        bip39Seed64: seed64,
        salt: salt1,
        vaultId: vaultId1.value,
      );
      final rwk1Replay = (res1Replay as Ok<RecoveryWrappingKey, CryptoFailure>).value;
      expect(_bytesToHex(rwk1.bytes), _bytesToHex(rwk1Replay.bytes));

      // Different vault ID produces different recovery key
      final resDiffVault = await hkdf.deriveRecoveryKey(
        bip39Seed64: seed64,
        salt: salt1,
        vaultId: vaultId2.value,
      );
      final rwkDiffVault = (resDiffVault as Ok<RecoveryWrappingKey, CryptoFailure>).value;
      expect(_bytesToHex(rwk1.bytes), isNot(_bytesToHex(rwkDiffVault.bytes)));

      // Different salt produces different recovery key
      final resDiffSalt = await hkdf.deriveRecoveryKey(
        bip39Seed64: seed64,
        salt: salt2,
        vaultId: vaultId1.value,
      );
      final rwkDiffSalt = (resDiffSalt as Ok<RecoveryWrappingKey, CryptoFailure>).value;
      expect(_bytesToHex(rwk1.bytes), isNot(_bytesToHex(rwkDiffSalt.bytes)));
    });

    test('Input validations fail closed', () async {
      final vek = VaultEncryptionKey(Uint8List(32));
      final salt16 = Uint8List(16);

      // Empty IKM
      final emptyIkm = await hkdf.extract(ikm: const [], salt: salt16);
      expect(emptyIkm.isErr, isTrue);

      // Disposed VEK
      vek.destroy();
      final disposedVek = await hkdf.deriveRecordKey(
        vek: vek,
        salt: salt16,
        recordId: 'record-1',
      );
      expect(disposedVek.isErr, isTrue);
      expect((disposedVek as Err<RecordEncryptionKey, CryptoFailure>).error.code, 'CRYPTO_KEY_DISPOSED');

      // Invalid salt length
      final liveVek = VaultEncryptionKey(Uint8List(32));
      final badSalt = await hkdf.deriveRecordKey(
        vek: liveVek,
        salt: Uint8List(15),
        recordId: 'record-1',
      );
      expect(badSalt.isErr, isTrue);
      expect((badSalt as Err<RecordEncryptionKey, CryptoFailure>).error.code, 'CRYPTO_INVALID_NONCE_LENGTH');

      // Negative epoch
      final negEpoch = await hkdf.deriveRecordKey(
        vek: liveVek,
        salt: salt16,
        recordId: 'record-1',
        keyEpoch: -1,
      );
      expect(negEpoch.isErr, isTrue);
      expect((negEpoch as Err<RecordEncryptionKey, CryptoFailure>).error.code, 'CRYPTO_INVALID_EPOCH');
    });
  });
}
