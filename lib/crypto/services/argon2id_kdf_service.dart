import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import '../../core/errors.dart';
import '../../core/result.dart';
import '../interfaces/kdf_service.dart';
import '../models/kdf_parameters.dart';
import '../models/key_types.dart';

/// Concrete Argon2id v1.3 implementation of [KdfService] backed by package:cryptography.
///
/// Argon2id parameters are strictly bounded against resource exhaustion and DoS attacks.
/// The underlying pure Dart implementation (`DartArgon2id`) automatically distributes
/// slice computation across worker isolates using FFI shared memory.
class Argon2idKdfService implements KdfService {
  const Argon2idKdfService();

  @override
  Future<Result<MasterWrappingKey, CryptoFailure>> deriveMasterKey({
    required List<int> passwordBytes,
    required Uint8List salt,
    required KdfParameters params,
  }) async {
    final validation = params.validateSafeLimits();
    if (validation case Err(:final error)) {
      return Result.err(error);
    }
    if (salt.length != params.saltLength) {
      return const Result.err(CryptoFailure.invalidNonceLength);
    }
    if (passwordBytes.isEmpty) {
      return const Result.err(
        CryptoFailure('Password bytes must not be empty.', code: 'CRYPTO_EMPTY_PASSWORD'),
      );
    }

    try {
      final argon2id = Argon2id(
        memory: params.memoryKiB,
        iterations: params.iterations,
        parallelism: params.parallelism,
        hashLength: params.keyLength,
      );

      final key = await argon2id.deriveKey(
        secretKey: SecretKey(passwordBytes),
        nonce: salt,
      );
      final derivedBytes = await key.extractBytes();
      if (derivedBytes.length != 32) {
        return const Result.err(CryptoFailure.invalidKeyLength);
      }
      return Result.ok(MasterWrappingKey(derivedBytes));
    } catch (e) {
      return Result.err(
        CryptoFailure('Argon2id derivation failed: $e', code: 'CRYPTO_KDF_ERROR'),
      );
    }
  }

  /// Low-level derivation supporting arbitrary RFC parameters for compliance testing.
  Future<Result<Uint8List, CryptoFailure>> deriveRaw({
    required List<int> passwordBytes,
    required Uint8List salt,
    required int memoryKiB,
    required int iterations,
    required int parallelism,
    required int hashLength,
    List<int> optionalSecret = const [],
    List<int> associatedData = const [],
  }) async {
    try {
      final argon2id = Argon2id(
        memory: memoryKiB,
        iterations: iterations,
        parallelism: parallelism,
        hashLength: hashLength,
      );
      final key = await argon2id.deriveKey(
        secretKey: SecretKey(passwordBytes),
        nonce: salt,
        optionalSecret: optionalSecret,
        associatedData: associatedData,
      );
      final bytes = await key.extractBytes();
      return Result.ok(Uint8List.fromList(bytes));
    } catch (e) {
      return Result.err(
        CryptoFailure('Argon2id raw derivation failed: $e', code: 'CRYPTO_KDF_ERROR'),
      );
    }
  }
}
