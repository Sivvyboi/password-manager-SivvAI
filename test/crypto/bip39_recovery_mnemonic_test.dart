import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:password_generator_and_manager/core/errors.dart';
import 'package:password_generator_and_manager/core/result.dart';
import 'package:password_generator_and_manager/core/types/vault_id.dart';
import 'package:password_generator_and_manager/crypto/models/key_types.dart';
import 'package:password_generator_and_manager/crypto/services/bip39_recovery_mnemonic_service.dart';

String _bytesToHex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

void main() {
  group('Bip39RecoveryMnemonicService', () {
    final service = Bip39RecoveryMnemonicService();

    test('BIP-0039 Vector 1 (256-bit all-zero entropy)', () async {
      final entropy = Uint8List(32); // 256 bits of zeros

      // 1. Entropy to 24-word Mnemonic
      final mnemResult = service.generateMnemonic(entropy256: entropy);
      expect(mnemResult.isOk, isTrue);
      final words = (mnemResult as Ok<List<String>, CryptoFailure>).value;
      expect(words.length, 24);
      expect(words.first, 'abandon');
      expect(words.last, 'art');
      for (var i = 0; i < 23; i++) {
        expect(words[i], 'abandon');
      }

      // 2. Validate Mnemonic
      final valResult = service.validateMnemonic(words);
      expect(valResult.isOk, isTrue);
      expect((valResult as Ok<bool, PolicyFailure>).value, isTrue);

      // 3. Mnemonic to 64-byte BIP39 Seed (with empty passphrase per architecture)
      final seedResult = await service.mnemonicToBip39Seed(words);
      expect(seedResult.isOk, isTrue);
      final seed = (seedResult as Ok<Uint8List, CryptoFailure>).value;
      expect(seed.length, 64);
      const expectedSeed =
          '408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf70'
          '5489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840';
      expect(_bytesToHex(seed), expectedSeed);
    });

    test('BIP-0039 Vector 2 (256-bit 0x7f entropy)', () async {
      final entropy = Uint8List(32)..fillRange(0, 32, 0x7f);

      final mnemResult = service.generateMnemonic(entropy256: entropy);
      expect(mnemResult.isOk, isTrue);
      final words = (mnemResult as Ok<List<String>, CryptoFailure>).value;
      expect(words.length, 24);
      expect(words.first, 'legal');
      expect(words.last, 'title');

      final valResult = service.validateMnemonic(words);
      expect(valResult.isOk, isTrue);

      final seedResult = await service.mnemonicToBip39Seed(words);
      expect(seedResult.isOk, isTrue);
      final seed = (seedResult as Ok<Uint8List, CryptoFailure>).value;
      expect(seed.length, 64);
      const expectedSeed =
          '761914478ebf6fe16185749372e91549361af22b386de46322cf8b1ba7e92e80'
          'c4af05196f742be1e63aab603899842ddadf4e7248d8e43870a4b6ff9bf16324';
      expect(_bytesToHex(seed), expectedSeed);
    });

    test('Validates word count strictly (rejects != 24 words)', () {
      final shortWords = List.filled(23, 'abandon');
      final longWords = List.filled(25, 'abandon');

      final shortRes = service.validateMnemonic(shortWords);
      expect(shortRes.isErr, isTrue);
      expect((shortRes as Err<bool, PolicyFailure>).error.code, 'POLICY_INVALID_MNEMONIC_LENGTH');

      final longRes = service.validateMnemonic(longWords);
      expect(longRes.isErr, isTrue);
      expect((longRes as Err<bool, PolicyFailure>).error.code, 'POLICY_INVALID_MNEMONIC_LENGTH');
    });

    test('Validates checksum and rejects corrupted word', () {
      final validWords = [...List.filled(23, 'abandon'), 'art'];
      expect(service.validateMnemonic(validWords).isOk, isTrue);

      // Corrupt the checksum word 'art' to 'about' (valid word but invalid checksum for this sequence)
      final corruptedWords = [...List.filled(23, 'abandon'), 'about'];
      final corruptedRes = service.validateMnemonic(corruptedWords);
      expect(corruptedRes.isErr, isTrue);
      expect((corruptedRes as Err<bool, PolicyFailure>).error.code, 'POLICY_INVALID_MNEMONIC_CHECKSUM');

      // Invalid word not in wordlist
      final bogusWord = [...List.filled(23, 'abandon'), 'notawordxyz'];
      final bogusRes = service.validateMnemonic(bogusWord);
      expect(bogusRes.isErr, isTrue);
      expect((bogusRes as Err<bool, PolicyFailure>).error.code, 'POLICY_INVALID_MNEMONIC_CHECKSUM');
    });

    test('Derives 32-byte RecoveryWrappingKey bound to VaultId and salt', () async {
      final words = [...List.filled(23, 'abandon'), 'art'];
      final vaultId = VaultId.fromString('123e4567-e89b-12d3-a456-426614174000');
      final salt = Uint8List(16)..fillRange(0, 16, 0x99);

      final rwkResult = await service.deriveRecoveryWrappingKey(
        words: words,
        vaultId: vaultId,
        vaultSalt: salt,
      );

      expect(rwkResult.isOk, isTrue);
      final rwk = (rwkResult as Ok<RecoveryWrappingKey, CryptoFailure>).value;
      expect(rwk.length, 32);
      expect(rwk.isDisposed, isFalse);
      expect(rwk.toString(), 'RecoveryWrappingKey([REDACTED])');

      // Deterministic derivation check
      final rwkResult2 = await service.deriveRecoveryWrappingKey(
        words: words,
        vaultId: vaultId,
        vaultSalt: salt,
      );
      final rwk2 = (rwkResult2 as Ok<RecoveryWrappingKey, CryptoFailure>).value;
      expect(_bytesToHex(rwk.bytes), _bytesToHex(rwk2.bytes));

      rwk.destroy();
      rwk2.destroy();
    });
  });
}
