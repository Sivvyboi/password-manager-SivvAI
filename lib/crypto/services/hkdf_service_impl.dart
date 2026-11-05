import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import '../../core/errors.dart';
import '../../core/result.dart';
import '../interfaces/hkdf_service.dart';
import '../models/crypto_scheme.dart';
import '../models/key_types.dart';

/// Concrete implementation of [HkdfService] following RFC 5869 using HMAC-SHA256.
///
/// Implements full two-stage Extract-and-Expand for strict cryptographic domain
/// and purpose separation.
class HkdfServiceImpl implements HkdfService {
  final Hmac _hmac;

  HkdfServiceImpl({Hmac? hmac}) : _hmac = hmac ?? Hmac.sha256();

  @override
  Future<Result<Uint8List, CryptoFailure>> extract({
    required List<int> ikm,
    required Uint8List salt,
  }) async {
    if (ikm.isEmpty) {
      return const Result.err(
        CryptoFailure('Input key material (IKM) must not be empty.', code: 'CRYPTO_EMPTY_IKM'),
      );
    }

    try {
      // RFC 5869 Section 2.2: If salt is not provided, it is set to a string of HashLen zeros.
      final effectiveSalt = salt.isEmpty ? Uint8List(32) : salt;
      final prkMac = await _hmac.calculateMac(
        ikm,
        secretKey: SecretKey(effectiveSalt),
      );
      return Result.ok(Uint8List.fromList(prkMac.bytes));
    } catch (e) {
      return Result.err(
        CryptoFailure('HKDF-Extract failed: $e', code: 'CRYPTO_HKDF_ERROR'),
      );
    }
  }

  @override
  Future<Result<Uint8List, CryptoFailure>> expand({
    required Uint8List prk,
    required List<int> info,
    required int outputLength,
  }) async {
    const hashLength = 32; // SHA-256 hash length in bytes
    if (prk.length < hashLength) {
      return const Result.err(CryptoFailure.invalidKeyLength);
    }
    if (outputLength <= 0 || outputLength > 255 * hashLength) {
      return const Result.err(CryptoFailure.resourceLimitExceeded);
    }

    try {
      final n = (outputLength + hashLength - 1) ~/ hashLength;
      final okm = Uint8List(outputLength);
      var t = <int>[];
      var offset = 0;

      for (var i = 1; i <= n; i++) {
        final sink = await _hmac.newMacSink(secretKey: SecretKey(prk));
        sink.add(t);
        if (info.isNotEmpty) {
          sink.add(info);
        }
        sink.add([i]);
        sink.close();

        final mac = await sink.mac();
        t = mac.bytes;

        final bytesToCopy = (offset + hashLength <= outputLength)
            ? hashLength
            : (outputLength - offset);
        okm.setRange(offset, offset + bytesToCopy, t);
        offset += bytesToCopy;
      }

      return Result.ok(okm);
    } catch (e) {
      return Result.err(
        CryptoFailure('HKDF-Expand failed: $e', code: 'CRYPTO_HKDF_ERROR'),
      );
    }
  }

  @override
  Future<Result<Uint8List, CryptoFailure>> extractAndExpand({
    required SecretKeyBytes ikm,
    required Uint8List salt,
    required List<int> info,
    required int outputLength,
  }) async {
    if (ikm.isDisposed) {
      return const Result.err(
        CryptoFailure('Key has been destroyed and cannot be used.', code: 'CRYPTO_KEY_DISPOSED'),
      );
    }

    final extractResult = await extract(ikm: ikm.bytes, salt: salt);
    if (extractResult case Err(:final error)) {
      return Result.err(error);
    }
    final prk = (extractResult as Ok<Uint8List, CryptoFailure>).value;

    return expand(
      prk: prk,
      info: info,
      outputLength: outputLength,
    );
  }

  @override
  Future<Result<RecordEncryptionKey, CryptoFailure>> deriveRecordKey({
    required VaultEncryptionKey vek,
    required Uint8List salt,
    required String recordId,
    int keyEpoch = 0,
  }) async {
    if (vek.isDisposed) {
      return const Result.err(
        CryptoFailure('Key has been destroyed and cannot be used.', code: 'CRYPTO_KEY_DISPOSED'),
      );
    }
    if (vek.length != 32) {
      return const Result.err(CryptoFailure.invalidKeyLength);
    }
    if (salt.length != 16) {
      return const Result.err(CryptoFailure.invalidNonceLength);
    }
    if (recordId.isEmpty) {
      return const Result.err(
        CryptoFailure('Record ID must not be empty.', code: 'CRYPTO_INVALID_RECORD_ID'),
      );
    }
    if (keyEpoch < 0) {
      return const Result.err(
        CryptoFailure('Key epoch must be non-negative.', code: 'CRYPTO_INVALID_EPOCH'),
      );
    }

    final infoString = HkdfContext.recordKeyInfo(recordId, keyEpoch);
    final infoBytes = utf8.encode(infoString);

    final result = await extractAndExpand(
      ikm: vek,
      salt: salt,
      info: infoBytes,
      outputLength: 32,
    );

    if (result case Err(:final error)) {
      return Result.err(error);
    }

    final keyBytes = (result as Ok<Uint8List, CryptoFailure>).value;
    return Result.ok(RecordEncryptionKey(keyBytes));
  }

  /// Derives a [RecoveryWrappingKey] (32 bytes) from a 64-byte BIP39 seed and [vaultSalt]
  /// bound specifically to [vaultId].
  Future<Result<RecoveryWrappingKey, CryptoFailure>> deriveRecoveryKey({
    required List<int> bip39Seed64,
    required Uint8List salt,
    required String vaultId,
  }) async {
    if (bip39Seed64.length != 64) {
      return const Result.err(CryptoFailure.invalidKeyLength);
    }
    if (salt.length != 16) {
      return const Result.err(CryptoFailure.invalidNonceLength);
    }
    if (vaultId.isEmpty) {
      return const Result.err(
        CryptoFailure('Vault ID must not be empty.', code: 'CRYPTO_INVALID_VAULT_ID'),
      );
    }

    final extractResult = await extract(ikm: bip39Seed64, salt: salt);
    if (extractResult case Err(:final error)) {
      return Result.err(error);
    }
    final prk = (extractResult as Ok<Uint8List, CryptoFailure>).value;

    final infoString = HkdfContext.recoveryWrapInfo(vaultId);
    final infoBytes = utf8.encode(infoString);

    final expandResult = await expand(
      prk: prk,
      info: infoBytes,
      outputLength: 32,
    );

    if (expandResult case Err(:final error)) {
      return Result.err(error);
    }

    final keyBytes = (expandResult as Ok<Uint8List, CryptoFailure>).value;
    return Result.ok(RecoveryWrappingKey(keyBytes));
  }
}
