import 'dart:typed_data';
import '../../core/errors.dart';
import '../../core/result.dart';
import '../models/key_types.dart';
import '../models/wrapped_key_payload.dart';

/// Contract for Authenticated Encryption with Associated Data (AEAD) using AES-256-GCM.
///
/// Implementations MUST:
/// 1. Reject invalid key lengths (must be 32 bytes / 256 bits).
/// 2. Reject invalid nonce lengths (must be 12 bytes / 96 bits).
/// 3. Produce or verify a 16-byte (128-bit) authentication tag.
/// 4. Fail closed on tag mismatch (never release unauthenticated plaintext).
/// 5. Adhere to the approved nonce uniqueness and key rotation policies.
abstract interface class AeadCipher {
  /// Encrypts and authenticates [plaintext] with [key], [nonce], and optional [associatedData].
  Future<Result<WrappedKeyPayload, CryptoFailure>> encrypt({
    required SecretKeyBytes key,
    required Uint8List nonce,
    required List<int> plaintext,
    Uint8List? associatedData,
  });

  /// Decrypts and verifies [payload] using [key] and optional [associatedData].
  ///
  /// Returns decrypted plaintext bytes on authentication success.
  /// Returns [CryptoFailure.authenticationTagMismatch] on integrity or authentication failure.
  Future<Result<Uint8List, CryptoFailure>> decrypt({
    required SecretKeyBytes key,
    required WrappedKeyPayload payload,
    Uint8List? associatedData,
  });
}

