import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:password_generator_and_manager/core/types/format_version.dart';
import 'package:password_generator_and_manager/core/types/record_id.dart';
import 'package:password_generator_and_manager/core/types/vault_id.dart';
import 'package:password_generator_and_manager/crypto/models/associated_data_context.dart';
import 'package:password_generator_and_manager/crypto/models/crypto_scheme.dart';

void main() {
  group('AssociatedDataContext (Canonical AAD Encoding & Validation)', () {
    final vaultId = VaultId.fromString('00000000-0000-0000-0000-000000000001');
    final recordId = RecordId.fromString('00000000-0000-0000-0000-000000000002');

    test('Encodes canonical master key wrap AAD with magic header and version', () {
      final context = AssociatedDataContext.forMasterKeyWrap(vaultId: vaultId);
      final bytes = context.toCanonicalBytes();

      // Magic header 'PMAA'
      expect(bytes.sublist(0, 4), equals([0x50, 0x4D, 0x41, 0x41]));

      // Format version 1 (uint16 big-endian) -> 0x00, 0x01
      expect(bytes.sublist(4, 6), equals([0x00, 0x01]));

      // Purpose code for masterKeyWrap -> 0x01
      expect(bytes[6], equals(AeadPurpose.masterKeyWrap.code));

      // Vault ID length (36 bytes for UUID)
      expect(bytes[7], equals(36));

      // Vault ID string
      final extractedVaultId = utf8.decode(bytes.sublist(8, 8 + 36));
      expect(extractedVaultId, equals(vaultId.value));

      // Record ID length should be 0 for vault-level wrap
      final recordIdLenIndex = 8 + 36;
      expect(bytes[recordIdLenIndex], equals(0));

      // Record version should be 0 (uint32 big-endian)
      expect(bytes.sublist(recordIdLenIndex + 1), equals([0x00, 0x00, 0x00, 0x00]));
    });

    test('Encodes canonical record payload AAD with record ID and version', () {
      final context = AssociatedDataContext.forRecordPayload(
        vaultId: vaultId,
        recordId: recordId,
        recordVersion: 5,
      );
      final bytes = context.toCanonicalBytes();

      // Purpose code for recordPayload -> 0x04
      expect(bytes[6], equals(AeadPurpose.recordPayload.code));

      // Record ID length is 36
      final recordIdLenIndex = 8 + 36;
      expect(bytes[recordIdLenIndex], equals(36));

      final extractedRecordId = utf8.decode(bytes.sublist(recordIdLenIndex + 1, recordIdLenIndex + 1 + 36));
      expect(extractedRecordId, equals(recordId.value));

      // Record version 5 (uint32 big-endian) -> 0x00, 0x00, 0x00, 0x05
      final versionOffset = recordIdLenIndex + 1 + 36;
      expect(bytes.sublist(versionOffset, versionOffset + 4), equals([0x00, 0x00, 0x00, 0x05]));
    });

    test('Encodes canonical tombstone (0x05) and backup package (0x06) contexts', () {
      final tombstoneCtx = AssociatedDataContext.forTombstone(
        vaultId: vaultId,
        recordId: recordId,
        recordVersion: 10,
      );
      expect(tombstoneCtx.toCanonicalBytes()[6], equals(AeadPurpose.tombstonePayload.code));

      final backupCtx = AssociatedDataContext.forBackupPackage(vaultId: vaultId);
      expect(backupCtx.toCanonicalBytes()[6], equals(AeadPurpose.backupPackage.code));
    });

    test('Enforces valid purpose/context combinations: vault-level vs record-level', () {
      // Vault-level contexts must reject non-null recordId
      expect(
        () => AssociatedDataContext(
          purpose: AeadPurpose.masterKeyWrap,
          vaultId: vaultId,
          recordId: recordId,
          recordVersion: 0,
        ),
        throwsArgumentError,
      );

      expect(
        () => AssociatedDataContext(
          purpose: AeadPurpose.recoveryKeyWrap,
          vaultId: vaultId,
          recordId: recordId,
          recordVersion: 0,
        ),
        throwsArgumentError,
      );

      expect(
        () => AssociatedDataContext(
          purpose: AeadPurpose.backupPackage,
          vaultId: vaultId,
          recordId: recordId,
          recordVersion: 0,
        ),
        throwsArgumentError,
      );

      // Vault-level contexts must reject non-zero recordVersion
      expect(
        () => AssociatedDataContext(
          purpose: AeadPurpose.masterKeyWrap,
          vaultId: vaultId,
          recordId: null,
          recordVersion: 1,
        ),
        throwsArgumentError,
      );

      // Record-level contexts must reject null recordId
      expect(
        () => AssociatedDataContext(
          purpose: AeadPurpose.recordPayload,
          vaultId: vaultId,
          recordId: null,
          recordVersion: 1,
        ),
        throwsArgumentError,
      );

      expect(
        () => AssociatedDataContext(
          purpose: AeadPurpose.tombstonePayload,
          vaultId: vaultId,
          recordId: null,
          recordVersion: 1,
        ),
        throwsArgumentError,
      );
    });

    test('Rejects record version exceeding uint32 range or negative values', () {
      expect(
        () => AssociatedDataContext(
          purpose: AeadPurpose.recordPayload,
          vaultId: vaultId,
          recordId: recordId,
          recordVersion: -1,
        ),
        throwsArgumentError,
      );

      expect(
        () => AssociatedDataContext(
          purpose: AeadPurpose.recordPayload,
          vaultId: vaultId,
          recordId: recordId,
          recordVersion: 0x100000000, // 2^32
        ),
        throwsArgumentError,
      );
    });

    test('Rejects format version exceeding uint16 range or zero', () {
      expect(
        () => AssociatedDataContext(
          formatVersion: const FormatVersion(65536),
          purpose: AeadPurpose.recordPayload,
          vaultId: vaultId,
          recordId: recordId,
          recordVersion: 1,
        ),
        throwsArgumentError,
      );
    });

    test('Deterministic output: multiple serializations produce identical bytes', () {
      final context1 = AssociatedDataContext.forRecordPayload(
        vaultId: vaultId,
        recordId: recordId,
        recordVersion: 1,
      );
      final context2 = AssociatedDataContext.forRecordPayload(
        vaultId: vaultId,
        recordId: recordId,
        recordVersion: 1,
      );

      expect(context1.toCanonicalBytes(), equals(context2.toCanonicalBytes()));
    });

    test('HkdfContext constructs canonical record key info with versioned keyEpoch', () {
      final info0 = HkdfContext.recordKeyInfo(recordId.value, 0);
      expect(info0, equals('PM-RECORD-KEY-V1:${recordId.value}:0'));

      final info5 = HkdfContext.recordKeyInfo(recordId.value, 5);
      expect(info5, equals('PM-RECORD-KEY-V1:${recordId.value}:5'));

      expect(() => HkdfContext.recordKeyInfo(recordId.value, -1), throwsArgumentError);
    });
  });
}
