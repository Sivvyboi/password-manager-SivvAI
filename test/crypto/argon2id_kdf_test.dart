import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:password_generator_and_manager/core/errors.dart';
import 'package:password_generator_and_manager/core/result.dart';
import 'package:password_generator_and_manager/crypto/models/kdf_parameters.dart';
import 'package:password_generator_and_manager/crypto/models/key_types.dart';
import 'package:password_generator_and_manager/crypto/services/argon2id_kdf_service.dart';

String _bytesToHex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

void main() {
  group('Argon2idKdfService', () {
    const kdf = Argon2idKdfService();

    test('RFC 9106 Section 5.3 Argon2id Official Known-Answer Test', () async {
      // RFC 9106 Section 5.3 parameters
      final password = Uint8List(32)..fillRange(0, 32, 0x01);
      final salt = Uint8List(16)..fillRange(0, 16, 0x02);
      final secret = Uint8List(8)..fillRange(0, 8, 0x03);
      final associatedData = Uint8List(12)..fillRange(0, 12, 0x04);

      final result = await kdf.deriveRaw(
        passwordBytes: password,
        salt: salt,
        memoryKiB: 32, // 32 KiB
        iterations: 3,
        parallelism: 4,
        hashLength: 32,
        optionalSecret: secret,
        associatedData: associatedData,
      );

      expect(result.isOk, isTrue);
      final tag = (result as Ok<Uint8List, CryptoFailure>).value;
      const expectedHex = '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659';
      expect(_bytesToHex(tag), expectedHex);
    });

    test('Rejects invalid KDF parameters', () async {
      final validPassword = utf8.encode('CorrectHorseBatteryStaple15!');
      final validSalt = Uint8List(16);

      // Memory below minimum safe bound (8 MiB = 8192 KiB)
      final lowMemResult = await kdf.deriveMasterKey(
        passwordBytes: validPassword,
        salt: validSalt,
        params: const KdfParameters(memoryKiB: 4096, iterations: 3, parallelism: 4),
      );
      expect(lowMemResult.isErr, isTrue);
      expect((lowMemResult as Err<MasterWrappingKey, CryptoFailure>).error.code, 'CRYPTO_RESOURCE_LIMIT_EXCEEDED');

      // Memory above maximum safe bound (256 MiB = 262144 KiB)
      final highMemResult = await kdf.deriveMasterKey(
        passwordBytes: validPassword,
        salt: validSalt,
        params: const KdfParameters(memoryKiB: 524288, iterations: 3, parallelism: 4),
      );
      expect(highMemResult.isErr, isTrue);
      expect((highMemResult as Err<MasterWrappingKey, CryptoFailure>).error.code, 'CRYPTO_RESOURCE_LIMIT_EXCEEDED');

      // Iterations outside safe bounds (1-10)
      final zeroIterResult = await kdf.deriveMasterKey(
        passwordBytes: validPassword,
        salt: validSalt,
        params: const KdfParameters(memoryKiB: 65536, iterations: 0, parallelism: 4),
      );
      expect(zeroIterResult.isErr, isTrue);
      expect((zeroIterResult as Err<MasterWrappingKey, CryptoFailure>).error.code, 'CRYPTO_RESOURCE_LIMIT_EXCEEDED');

      final highIterResult = await kdf.deriveMasterKey(
        passwordBytes: validPassword,
        salt: validSalt,
        params: const KdfParameters(memoryKiB: 65536, iterations: 11, parallelism: 4),
      );
      expect(highIterResult.isErr, isTrue);
      expect((highIterResult as Err<MasterWrappingKey, CryptoFailure>).error.code, 'CRYPTO_RESOURCE_LIMIT_EXCEEDED');

      // Parallelism outside safe bounds (1-8)
      final zeroParallelResult = await kdf.deriveMasterKey(
        passwordBytes: validPassword,
        salt: validSalt,
        params: const KdfParameters(memoryKiB: 65536, iterations: 3, parallelism: 0),
      );
      expect(zeroParallelResult.isErr, isTrue);
      expect((zeroParallelResult as Err<MasterWrappingKey, CryptoFailure>).error.code, 'CRYPTO_RESOURCE_LIMIT_EXCEEDED');

      // Salt length mismatch (not 16 bytes)
      final badSaltResult = await kdf.deriveMasterKey(
        passwordBytes: validPassword,
        salt: Uint8List(12),
        params: KdfParameters.candidateProfile,
      );
      expect(badSaltResult.isErr, isTrue);
      expect((badSaltResult as Err<MasterWrappingKey, CryptoFailure>).error.code, 'CRYPTO_INVALID_NONCE_LENGTH');

      // Empty password rejection
      final emptyPwResult = await kdf.deriveMasterKey(
        passwordBytes: const [],
        salt: validSalt,
        params: KdfParameters.candidateProfile,
      );
      expect(emptyPwResult.isErr, isTrue);
      expect((emptyPwResult as Err<MasterWrappingKey, CryptoFailure>).error.code, 'CRYPTO_EMPTY_PASSWORD');
    });

    test('Candidate production profile derivation with performance measurement', () async {
      final password = utf8.encode('CorrectHorseBatteryStaple15!#');
      final salt = Uint8List(16)..fillRange(0, 16, 0x42);

      final stopwatch = Stopwatch()..start();
      final result = await kdf.deriveMasterKey(
        passwordBytes: password,
        salt: salt,
        params: KdfParameters.candidateProfile,
      );
      stopwatch.stop();

      expect(result.isOk, isTrue);
      final mwk = (result as Ok<MasterWrappingKey, CryptoFailure>).value;
      expect(mwk.length, 32);
      expect(mwk.isDisposed, isFalse);
      expect(mwk.toString(), 'MasterWrappingKey([REDACTED])');

      // Ensure computation completed successfully and recorded practical time
      expect(stopwatch.elapsedMilliseconds, greaterThan(0));

      // Determinism test: same inputs produce identical key
      final result2 = await kdf.deriveMasterKey(
        passwordBytes: password,
        salt: salt,
        params: KdfParameters.candidateProfile,
      );
      final mwk2 = (result2 as Ok<MasterWrappingKey, CryptoFailure>).value;
      expect(_bytesToHex(mwk.bytes), _bytesToHex(mwk2.bytes));

      // Destroy keys
      mwk.destroy();
      mwk2.destroy();
      expect(mwk.isDisposed, isTrue);
    });
  });
}
