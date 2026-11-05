import 'dart:typed_data';
import '../../core/errors.dart';
import '../../core/result.dart';
import '../models/key_types.dart';

/// Contract for HMAC-based Extract-and-Expand Key Derivation (HKDF - RFC 5869).
///
/// Implements complete two-stage HKDF:
/// 1. HKDF-Extract: PRK = HMAC-Hash(Salt, IKM)
/// 2. HKDF-Expand:  OKM = HKDF-Expand(PRK, info, L)
///
/// Used strictly for domain and purpose separation to ensure keys derived for
/// distinct tasks (e.g. record payload encryption vs. recovery key derivation) are cryptographically isolated.
abstract interface class HkdfService {
  /// Stage 1: HKDF-Extract.
  /// Extracts a pseudorandom key [prk] of fixed length (32 bytes for SHA-256)
  /// from input key material [ikm] using [salt].
  Future<Result<Uint8List, CryptoFailure>> extract({
    required List<int> ikm,
    required Uint8List salt,
  });

  /// Stage 2: HKDF-Expand.
  /// Expands the pseudorandom key [prk] to an output key of [outputLength] bytes
  /// using context-specific [info] bytes.
  Future<Result<Uint8List, CryptoFailure>> expand({
    required Uint8List prk,
    required List<int> info,
    required int outputLength,
  });

  /// Full HKDF Extract-and-Expand execution in a single call.
  Future<Result<Uint8List, CryptoFailure>> extractAndExpand({
    required SecretKeyBytes ikm,
    required Uint8List salt,
    required List<int> info,
    required int outputLength,
  });

  /// Derives a [RecordEncryptionKey] (32 bytes) from the primary [VaultEncryptionKey]
  /// bound specifically to [recordId].
  Future<Result<RecordEncryptionKey, CryptoFailure>> deriveRecordKey({
    required VaultEncryptionKey vek,
    required Uint8List salt,
    required String recordId,
  });
}
