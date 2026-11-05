import 'dart:typed_data';
import 'package:cryptography/cryptography.dart' as crypto;
import '../../core/errors.dart';
import '../../core/result.dart';
import '../interfaces/aead_cipher.dart';
import '../interfaces/secure_random_source.dart';
import '../models/key_types.dart';
import '../models/wrapped_key_payload.dart';
import 'standard_secure_random_source.dart';

/// Concrete AES-256-GCM implementation of [AeadCipher] backed by package:cryptography.
///
/// Enforces:
/// - Exact 256-bit (32-byte) key length.
/// - Exact 96-bit (12-byte) nonce length.
/// - Exact 128-bit (16-byte) authentication tag.
/// - Authentication of associated authenticated data (AAD).
/// - Fail-closed semantics on any authentication, integrity, or length violation.
class AesGcmCipherService implements AeadCipher {
  final crypto.AesGcm _cipher;
  final SecureRandomSource _randomSource;

  AesGcmCipherService({
    crypto.AesGcm? cipher,
    SecureRandomSource? randomSource,
  })  : _cipher = cipher ?? crypto.AesGcm.with256bits(),
        _randomSource = randomSource ?? StandardSecureRandomSource();

  /// Generates a fresh 12-byte (96-bit) cryptographically secure random nonce.
  Uint8List generateNonce() => _randomSource.nextBytes(12);

  @override
  Future<Result<WrappedKeyPayload, CryptoFailure>> encrypt({
    required SecretKeyBytes key,
    required Uint8List nonce,
    required List<int> plaintext,
    Uint8List? associatedData,
  }) async {
    if (key.isDisposed) {
      return const Result.err(
        CryptoFailure('Key has been destroyed and cannot be used.', code: 'CRYPTO_KEY_DISPOSED'),
      );
    }
    if (key.length != 32) {
      return const Result.err(CryptoFailure.invalidKeyLength);
    }
    if (nonce.length != 12) {
      return const Result.err(CryptoFailure.invalidNonceLength);
    }

    try {
      final secretBox = await _cipher.encrypt(
        plaintext,
        secretKey: crypto.SecretKey(key.bytes),
        nonce: nonce,
        aad: associatedData ?? const [],
      );

      return Result.ok(WrappedKeyPayload(
        nonce: nonce,
        ciphertext: secretBox.cipherText,
        macTag: secretBox.mac.bytes,
      ));
    } catch (e) {
      return Result.err(
        CryptoFailure('AES-GCM encryption failed: $e', code: 'CRYPTO_ENCRYPTION_FAILED'),
      );
    }
  }

  @override
  Future<Result<Uint8List, CryptoFailure>> decrypt({
    required SecretKeyBytes key,
    required WrappedKeyPayload payload,
    Uint8List? associatedData,
  }) async {
    if (key.isDisposed) {
      return const Result.err(
        CryptoFailure('Key has been destroyed and cannot be used.', code: 'CRYPTO_KEY_DISPOSED'),
      );
    }
    if (key.length != 32) {
      return const Result.err(CryptoFailure.invalidKeyLength);
    }
    if (payload.nonce.length != 12) {
      return const Result.err(CryptoFailure.invalidNonceLength);
    }
    if (payload.macTag.length != 16) {
      return const Result.err(CryptoFailure.authenticationTagMismatch);
    }

    try {
      final secretBox = crypto.SecretBox(
        payload.ciphertext,
        nonce: payload.nonce,
        mac: crypto.Mac(payload.macTag),
      );

      final plaintext = await _cipher.decrypt(
        secretBox,
        secretKey: crypto.SecretKey(key.bytes),
        aad: associatedData ?? const [],
      );

      return Result.ok(Uint8List.fromList(plaintext));
    } on crypto.SecretBoxAuthenticationError {
      // Fail closed immediately on tag mismatch or ciphertext tampering.
      return const Result.err(CryptoFailure.authenticationTagMismatch);
    } catch (e) {
      // Fail closed on any other error to prevent disclosure.
      return const Result.err(CryptoFailure.authenticationTagMismatch);
    }
  }
}

