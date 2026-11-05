import 'dart:typed_data';
import '../../core/errors.dart';
import '../../core/result.dart';
import '../../core/types/vault_id.dart';
import '../models/key_types.dart';

/// Contract for recovery phrase processing and recovery key derivation.
///
/// Follows BIP39 specification (RFC/BIP-0039 standard) and RFC 5869 HKDF:
/// 1. 256 bits of initial entropy from approved CSPRNG.
/// 2. 24-word English mnemonic with 8-bit checksum.
/// 3. NFKD normalization of mnemonic sentence with single space separation.
/// 4. PBKDF2-HMAC-SHA512 with 2048 iterations and fixed salt "mnemonic" to yield 512-bit seed.
/// 5. Application recovery key derivation via HKDF-SHA256 Extract-and-Expand bound to [vaultId].
abstract interface class RecoveryMnemonicService {
  /// Generates a new 24-word recovery phrase from 256 bits of CSPRNG entropy.
  Result<List<String>, CryptoFailure> generateMnemonic({required Uint8List entropy256});

  /// Validates word count (24), vocabulary, and BIP39 checksum of [words].
  Result<bool, PolicyFailure> validateMnemonic(List<String> words);

  /// Converts the 24-word mnemonic into the standard 64-byte (512-bit) BIP39 binary seed.
  /// Applies NFKD normalization, joins with single spaces, and runs PBKDF2-HMAC-SHA512
  /// with 2048 iterations and UTF-8 salt "mnemonic".
  Future<Result<Uint8List, CryptoFailure>> mnemonicToBip39Seed(List<String> words);

  /// Derives the 256-bit [RecoveryWrappingKey] from [words], [vaultId], and [vaultSalt]
  /// using the full HKDF-SHA256 Extract-and-Expand pipeline.
  Future<Result<RecoveryWrappingKey, CryptoFailure>> deriveRecoveryWrappingKey({
    required List<String> words,
    required VaultId vaultId,
    required Uint8List vaultSalt,
  });
}
