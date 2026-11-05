import 'dart:typed_data';
import 'package:bip39/bip39.dart' as bip39;
import '../../core/errors.dart';
import '../../core/result.dart';
import '../../core/types/vault_id.dart';
import '../interfaces/recovery_mnemonic_service.dart';
import '../models/key_types.dart';
import 'hkdf_service_impl.dart';

/// Concrete BIP39 implementation of [RecoveryMnemonicService] using package:bip39.
///
/// Implements:
/// - 256-bit entropy to 24-word English mnemonic with 8-bit checksum.
/// - Exact 24-word count, vocabulary, and checksum validation.
/// - PBKDF2-HMAC-SHA512 seed derivation (2048 iterations, salt "mnemonic", no passphrase).
/// - Complete HKDF Extract-and-Expand to yield 32-byte [RecoveryWrappingKey].
/// - Best-effort zeroization of intermediate seed bytes.
class Bip39RecoveryMnemonicService implements RecoveryMnemonicService {
  final HkdfServiceImpl _hkdfService;

  Bip39RecoveryMnemonicService({HkdfServiceImpl? hkdfService})
      : _hkdfService = hkdfService ?? HkdfServiceImpl();

  @override
  Result<List<String>, CryptoFailure> generateMnemonic({required Uint8List entropy256}) {
    if (entropy256.length != 32) {
      return const Result.err(CryptoFailure.invalidKeyLength);
    }

    try {
      final hexEntropy = entropy256
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join();
      final sentence = bip39.entropyToMnemonic(hexEntropy);
      final words = sentence.trim().split(RegExp(r'\s+'));
      if (words.length != 24) {
        return const Result.err(
          CryptoFailure('Generated mnemonic must contain exactly 24 words.', code: 'CRYPTO_INVALID_MNEMONIC_COUNT'),
        );
      }
      return Result.ok(words);
    } catch (e) {
      return Result.err(
        CryptoFailure('Mnemonic generation failed: $e', code: 'CRYPTO_MNEMONIC_GENERATION_FAILED'),
      );
    }
  }

  @override
  Result<bool, PolicyFailure> validateMnemonic(List<String> words) {
    if (words.length != 24) {
      return const Result.err(PolicyFailure.invalidMnemonicLength);
    }

    // Join with single spaces per BIP39 specification
    final sentence = words.join(' ');
    if (!bip39.validateMnemonic(sentence)) {
      return const Result.err(PolicyFailure.invalidMnemonicChecksum);
    }

    return const Result.ok(true);
  }

  @override
  Future<Result<Uint8List, CryptoFailure>> mnemonicToBip39Seed(List<String> words) async {
    final validation = validateMnemonic(words);
    if (validation case Err(:final error)) {
      return Result.err(
        CryptoFailure(error.message, code: error.code),
      );
    }

    try {
      final sentence = words.join(' ');
      // Standard BIP39: salt is "mnemonic" (empty passphrase per architecture)
      final seed = bip39.mnemonicToSeed(sentence);
      if (seed.length != 64) {
        return const Result.err(CryptoFailure.invalidKeyLength);
      }
      return Result.ok(Uint8List.fromList(seed));
    } catch (e) {
      return Result.err(
        CryptoFailure('BIP39 seed derivation failed: $e', code: 'CRYPTO_SEED_DERIVATION_FAILED'),
      );
    }
  }

  @override
  Future<Result<RecoveryWrappingKey, CryptoFailure>> deriveRecoveryWrappingKey({
    required List<String> words,
    required VaultId vaultId,
    required Uint8List vaultSalt,
  }) async {
    final seedResult = await mnemonicToBip39Seed(words);
    if (seedResult case Err(:final error)) {
      return Result.err(error);
    }

    final seedBytes = (seedResult as Ok<Uint8List, CryptoFailure>).value;
    try {
      final rwkResult = await _hkdfService.deriveRecoveryKey(
        bip39Seed64: seedBytes,
        salt: vaultSalt,
        vaultId: vaultId.value,
      );
      return rwkResult;
    } finally {
      // Best-effort zeroization of intermediate sensitive seed buffer
      seedBytes.fillRange(0, seedBytes.length, 0);
    }
  }
}
