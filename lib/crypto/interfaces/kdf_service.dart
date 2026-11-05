import 'dart:typed_data';
import '../../core/errors.dart';
import '../../core/result.dart';
import '../models/kdf_parameters.dart';
import '../models/key_types.dart';

/// Abstract contract for Key Derivation operations (Argon2id v1.3).
///
/// Execution must take place off the Flutter UI thread (in a worker isolate or native thread)
/// to prevent UI stutter or Application Not Responding (ANR) warnings.
abstract interface class KdfService {
  /// Derives a 256-bit [MasterWrappingKey] from [passwordBytes] and [salt] using [params].
  ///
  /// Fails closed with [CryptoFailure] if parameters exceed safe limits
  /// or derivation encounters an error.
  Future<Result<MasterWrappingKey, CryptoFailure>> deriveMasterKey({
    required List<int> passwordBytes,
    required Uint8List salt,
    required KdfParameters params,
  });
}

