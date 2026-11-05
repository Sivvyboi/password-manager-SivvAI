import 'dart:typed_data';
import '../../core/errors.dart';
import '../../core/result.dart';
import '../models/key_types.dart';

/// Contract for recovery phrase processing and recovery key derivation.
///
/// Follows BIP39 specification (RFC/BIP-0039 standard):
/// - 256 bits of initial entropy.
/// - 24-word English mnemonic.
/// - 8-bit checksum.
/// - Standard derivation pipeline yielding a 256-bit [RecoveryWrappingKey].
abstract interface class RecoveryMnemonicService {
  /// Generates a new 24-word recovery phrase from 256 bits of CSPRNG entropy.
  Result<List<String>, CryptoFailure> generateMnemonic({required Uint8List entropy256});

  /// Validates format, word count, and BIP39 checksum of [words].
  Result<bool, PolicyFailure> validateMnemonic(List<String> words);

  /// Derives the 256-bit [RecoveryWrappingKey] from the validated recovery [words] and vault [salt].
  Future<Result<RecoveryWrappingKey, CryptoFailure>> deriveRecoveryWrappingKey({
    required List<String> words,
    required Uint8List salt,
  });
}

