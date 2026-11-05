import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:password_generator_and_manager/core/errors.dart';
import 'package:password_generator_and_manager/core/result.dart';
import 'package:password_generator_and_manager/core/types/record_id.dart';
import 'package:password_generator_and_manager/core/types/vault_id.dart';
import 'package:password_generator_and_manager/crypto/models/associated_data_context.dart';
import 'package:password_generator_and_manager/crypto/models/key_types.dart';
import 'package:password_generator_and_manager/crypto/models/wrapped_key_payload.dart';
import 'package:password_generator_and_manager/crypto/services/aes_gcm_cipher_service.dart';

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
  group('AesGcmCipherService', () {
    final cipher = AesGcmCipherService();

    test('NIST SP 800-38D AES-256-GCM Known-Answer Test (Test Case 16)', () async {
      final keyBytes = _hexToBytes('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308');
      final nonce = _hexToBytes('cafebabefacedbaddecaf888');
      final plaintext = _hexToBytes(
        'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72'
        '1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
      );
      final aad = _hexToBytes('feedfacedeadbeeffeedfacedeadbeefabaddad2');

      final key = VaultEncryptionKey(keyBytes);

      // Encrypt and verify matching ciphertext and tag
      final encResult = await cipher.encrypt(
        key: key,
        nonce: nonce,
        plaintext: plaintext,
        associatedData: aad,
      );

      expect(encResult.isOk, isTrue);
      final payload = (encResult as Ok<WrappedKeyPayload, CryptoFailure>).value;

      final expectedCiphertext =
          '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa'
          '8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662';
      final expectedTag = '76fc6ece0f4e1768cddf8853bb2d551b';

      expect(_bytesToHex(payload.ciphertext), expectedCiphertext);
      expect(_bytesToHex(payload.macTag), expectedTag);
      expect(payload.isValidGcmWrapper, isTrue);

      // Decrypt and verify exact plaintext match
      final decResult = await cipher.decrypt(
        key: key,
        payload: payload,
        associatedData: aad,
      );

      expect(decResult.isOk, isTrue);
      final decrypted = (decResult as Ok<Uint8List, CryptoFailure>).value;
      expect(_bytesToHex(decrypted), _bytesToHex(plaintext));
    });

    test('Fails closed on incorrect decryption key', () async {
      final key1 = VaultEncryptionKey(Uint8List(32)..fillRange(0, 32, 1));
      final key2 = VaultEncryptionKey(Uint8List(32)..fillRange(0, 32, 2));
      final nonce = cipher.generateNonce();
      final plaintext = utf8.encode('SecretCredentialPayload12345');

      final encResult = await cipher.encrypt(
        key: key1,
        nonce: nonce,
        plaintext: plaintext,
      );
      final payload = (encResult as Ok<WrappedKeyPayload, CryptoFailure>).value;

      // Decrypt with wrong key
      final decResult = await cipher.decrypt(
        key: key2,
        payload: payload,
      );
      expect(decResult.isErr, isTrue);
      expect((decResult as Err<Uint8List, CryptoFailure>).error.code, 'CRYPTO_TAG_MISMATCH');
    });

    test('Fails closed on tampered ciphertext', () async {
      final key = VaultEncryptionKey(Uint8List(32)..fillRange(0, 32, 7));
      final nonce = cipher.generateNonce();
      final plaintext = utf8.encode('SensitiveData');

      final encResult = await cipher.encrypt(
        key: key,
        nonce: nonce,
        plaintext: plaintext,
      );
      final payload = (encResult as Ok<WrappedKeyPayload, CryptoFailure>).value;

      // Mutate one byte in ciphertext
      final tamperedCiphertext = Uint8List.fromList(payload.ciphertext);
      tamperedCiphertext[0] ^= 0xFF;

      final tamperedPayload = WrappedKeyPayload(
        nonce: payload.nonce,
        ciphertext: tamperedCiphertext,
        macTag: payload.macTag,
      );

      final decResult = await cipher.decrypt(
        key: key,
        payload: tamperedPayload,
      );
      expect(decResult.isErr, isTrue);
      expect((decResult as Err<Uint8List, CryptoFailure>).error.code, 'CRYPTO_TAG_MISMATCH');
    });

    test('Fails closed on tampered authentication tag', () async {
      final key = VaultEncryptionKey(Uint8List(32)..fillRange(0, 32, 7));
      final nonce = cipher.generateNonce();
      final plaintext = utf8.encode('SensitiveData');

      final encResult = await cipher.encrypt(
        key: key,
        nonce: nonce,
        plaintext: plaintext,
      );
      final payload = (encResult as Ok<WrappedKeyPayload, CryptoFailure>).value;

      // Mutate one byte in tag
      final tamperedTag = Uint8List.fromList(payload.macTag);
      tamperedTag[0] ^= 0x01;

      final tamperedPayload = WrappedKeyPayload(
        nonce: payload.nonce,
        ciphertext: payload.ciphertext,
        macTag: tamperedTag,
      );

      final decResult = await cipher.decrypt(
        key: key,
        payload: tamperedPayload,
      );
      expect(decResult.isErr, isTrue);
      expect((decResult as Err<Uint8List, CryptoFailure>).error.code, 'CRYPTO_TAG_MISMATCH');
    });

    test('Fails closed on tampered nonce', () async {
      final key = VaultEncryptionKey(Uint8List(32)..fillRange(0, 32, 7));
      final nonce = cipher.generateNonce();
      final plaintext = utf8.encode('SensitiveData');

      final encResult = await cipher.encrypt(
        key: key,
        nonce: nonce,
        plaintext: plaintext,
      );
      final payload = (encResult as Ok<WrappedKeyPayload, CryptoFailure>).value;

      // Mutate one byte in nonce
      final tamperedNonce = Uint8List.fromList(payload.nonce);
      tamperedNonce[0] ^= 0x01;

      final tamperedPayload = WrappedKeyPayload(
        nonce: tamperedNonce,
        ciphertext: payload.ciphertext,
        macTag: payload.macTag,
      );

      final decResult = await cipher.decrypt(
        key: key,
        payload: tamperedPayload,
      );
      expect(decResult.isErr, isTrue);
      expect((decResult as Err<Uint8List, CryptoFailure>).error.code, 'CRYPTO_TAG_MISMATCH');
    });

    test('Fails closed on modified or mismatched AAD', () async {
      final key = VaultEncryptionKey(Uint8List(32)..fillRange(0, 32, 9));
      final nonce = cipher.generateNonce();
      final plaintext = utf8.encode('AuthenticatedPayload');
      final validAad = Uint8List.fromList([1, 2, 3, 4, 5]);
      final modifiedAad = Uint8List.fromList([1, 2, 3, 4, 6]);

      final encResult = await cipher.encrypt(
        key: key,
        nonce: nonce,
        plaintext: plaintext,
        associatedData: validAad,
      );
      final payload = (encResult as Ok<WrappedKeyPayload, CryptoFailure>).value;

      // Decrypt with modified AAD
      final decWithModifiedAad = await cipher.decrypt(
        key: key,
        payload: payload,
        associatedData: modifiedAad,
      );
      expect(decWithModifiedAad.isErr, isTrue);
      expect((decWithModifiedAad as Err<Uint8List, CryptoFailure>).error.code, 'CRYPTO_TAG_MISMATCH');

      // Decrypt with missing AAD (null)
      final decWithNullAad = await cipher.decrypt(
        key: key,
        payload: payload,
        associatedData: null,
      );
      expect(decWithNullAad.isErr, isTrue);
      expect((decWithNullAad as Err<Uint8List, CryptoFailure>).error.code, 'CRYPTO_TAG_MISMATCH');
    });

    test('Rejects disposed key', () async {
      final key = VaultEncryptionKey(Uint8List(32));
      key.destroy();
      expect(key.isDisposed, isTrue);

      final encResult = await cipher.encrypt(
        key: key,
        nonce: Uint8List(12),
        plaintext: [1, 2, 3],
      );
      expect(encResult.isErr, isTrue);
      expect((encResult as Err<WrappedKeyPayload, CryptoFailure>).error.code, 'CRYPTO_KEY_DISPOSED');
    });

    test('Rejects invalid key and nonce lengths', () async {
      final key = VaultEncryptionKey(Uint8List(32));
      final badNonce = Uint8List(11); // should be 12

      final encResult = await cipher.encrypt(
        key: key,
        nonce: badNonce,
        plaintext: [1, 2, 3],
      );
      expect(encResult.isErr, isTrue);
      expect((encResult as Err<WrappedKeyPayload, CryptoFailure>).error.code, 'CRYPTO_INVALID_NONCE_LENGTH');
    });

    test('Roundtrip with canonical AAD encoding', () async {
      final rek = RecordEncryptionKey(Uint8List(32)..fillRange(0, 32, 0xBB));
      final vaultId = VaultId.fromString('123e4567-e89b-12d3-a456-426614174000');
      final recordId = RecordId.fromString('987fcdeb-51a2-43f1-b987-123456789abc');

      final aad = AssociatedDataContext.forRecordPayload(
        vaultId: vaultId,
        recordId: recordId,
        recordVersion: 1,
      ).toCanonicalBytes();

      final plaintext = utf8.encode('{"username": "alice", "password": "SuperSecretPassword123!"}');
      final nonce = cipher.generateNonce();

      final enc = await cipher.encrypt(
        key: rek,
        nonce: nonce,
        plaintext: plaintext,
        associatedData: aad,
      );
      expect(enc.isOk, isTrue);
      final payload = (enc as Ok<WrappedKeyPayload, CryptoFailure>).value;

      final dec = await cipher.decrypt(
        key: rek,
        payload: payload,
        associatedData: aad,
      );
      expect(dec.isOk, isTrue);
      final decrypted = (dec as Ok<Uint8List, CryptoFailure>).value;
      expect(utf8.decode(decrypted), utf8.decode(plaintext));
    });
  });
}
