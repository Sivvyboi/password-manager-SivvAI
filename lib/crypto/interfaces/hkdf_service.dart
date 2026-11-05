import 'dart:typed_data';
import '../../core/errors.dart';
import '../../core/result.dart';
import '../models/key_types.dart';

/// Contract for HMAC-based Extract-and-Expand Key Derivation (HKDF - RFC 5869).
///
/// Used strictly for domain and purpose separation to ensure keys derived for
/// distinct tasks (e.g. record payload encryption vs. backup packaging) are cryptographically isolated.
abstract interface class HkdfService {
  /// Derives a purpose-separated subkey from input key material [ikm].
  Future<Result<Uint8List, CryptoFailure>> deriveKey({
    required SecretKeyBytes ikm,
    required Uint8List salt,
    required String info,
    required int outputLength,
  });

  /// Derives a [RecordEncryptionKey] (32 bytes) from the primary [VaultEncryptionKey].
  Future<Result<RecordEncryptionKey, CryptoFailure>> deriveRecordKey({
    required VaultEncryptionKey vek,
    required Uint8List salt,
    required String recordId,
  });
}

