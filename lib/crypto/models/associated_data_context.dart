import 'dart:convert';
import 'package:flutter/foundation.dart';
import '../../core/types/format_version.dart';
import '../../core/types/record_id.dart';
import '../../core/types/vault_id.dart';
import 'crypto_scheme.dart';

/// Builder and encoder for canonical Associated Authenticated Data (AAD).
///
/// Ensures strict binding between ciphertext and its cryptographic context,
/// preventing ciphertext transplant attacks across records, vaults, or purposes.
///
/// Binary Format Specification (Version 1):
/// - 4 bytes: Magic ASCII header `PMAA` (0x50, 0x4D, 0x41, 0x41)
/// - 2 bytes: Format Version (uint16 big-endian)
/// - 1 byte: Purpose Code (uint8, from [AeadPurpose])
/// - 1 byte: Vault ID Length (uint8)
/// - N bytes: Vault ID UTF-8 bytes
/// - 1 byte: Record ID Length (uint8, 0 if null/vault-level)
/// - M bytes: Record ID UTF-8 bytes (if present)
/// - 4 bytes: Record Version / Revision counter (uint32 big-endian, 0 if vault-level)
@immutable
class AssociatedDataContext {
  static const List<int> magicHeader = [0x50, 0x4D, 0x41, 0x41]; // 'PMAA'
  static const int maxUint32 = 0xFFFFFFFF;

  final FormatVersion formatVersion;
  final AeadPurpose purpose;
  final VaultId vaultId;
  final RecordId? recordId;
  final int recordVersion;

  AssociatedDataContext({
    this.formatVersion = FormatVersion.current,
    required this.purpose,
    required this.vaultId,
    this.recordId,
    this.recordVersion = 0,
  }) {
    if (recordVersion < 0 || recordVersion > maxUint32) {
      throw ArgumentError.value(
        recordVersion,
        'recordVersion',
        'Record version must be a valid unsigned 32-bit integer (0 to $maxUint32).',
      );
    }
  }

  /// Canonical AAD for wrapping the VEK with the Master Password Wrapping Key (0x01).
  factory AssociatedDataContext.forMasterKeyWrap({required VaultId vaultId}) {
    return AssociatedDataContext(
      purpose: AeadPurpose.masterKeyWrap,
      vaultId: vaultId,
      recordId: null,
      recordVersion: 0,
    );
  }

  /// Canonical AAD for wrapping the VEK with the Recovery Wrapping Key (0x02).
  factory AssociatedDataContext.forRecoveryKeyWrap({required VaultId vaultId}) {
    return AssociatedDataContext(
      purpose: AeadPurpose.recoveryKeyWrap,
      vaultId: vaultId,
      recordId: null,
      recordVersion: 0,
    );
  }

  /// Canonical AAD for encrypting a specific record payload (0x04).
  factory AssociatedDataContext.forRecordPayload({
    required VaultId vaultId,
    required RecordId recordId,
    required int recordVersion,
  }) {
    return AssociatedDataContext(
      purpose: AeadPurpose.recordPayload,
      vaultId: vaultId,
      recordId: recordId,
      recordVersion: recordVersion,
    );
  }

  /// Canonical AAD for encrypting an authenticated deletion tombstone (0x05).
  factory AssociatedDataContext.forTombstone({
    required VaultId vaultId,
    required RecordId recordId,
    required int recordVersion,
  }) {
    return AssociatedDataContext(
      purpose: AeadPurpose.tombstonePayload,
      vaultId: vaultId,
      recordId: recordId,
      recordVersion: recordVersion,
    );
  }

  /// Canonical AAD for encrypting a portable backup package (0x06).
  factory AssociatedDataContext.forBackupPackage({required VaultId vaultId}) {
    return AssociatedDataContext(
      purpose: AeadPurpose.backupPackage,
      vaultId: vaultId,
      recordId: null,
      recordVersion: 0,
    );
  }

  /// Serializes the context into deterministic canonical bytes.
  /// Identical byte output is guaranteed across Android, Windows, and all Dart platforms.
  Uint8List toCanonicalBytes() {
    if (recordVersion < 0 || recordVersion > maxUint32) {
      throw RangeError.range(recordVersion, 0, maxUint32, 'recordVersion');
    }

    final vaultIdBytes = utf8.encode(vaultId.value);
    final recordIdBytes = recordId != null ? utf8.encode(recordId!.value) : const <int>[];

    final totalSize = 4 + // magic header
        2 + // format version (uint16)
        1 + // purpose code (uint8)
        1 + // vaultId length (uint8)
        vaultIdBytes.length +
        1 + // recordId length (uint8)
        recordIdBytes.length +
        4; // recordVersion (uint32)

    final buffer = ByteData(totalSize);
    var offset = 0;

    // 1. Magic
    for (var i = 0; i < magicHeader.length; i++) {
      buffer.setUint8(offset++, magicHeader[i]);
    }

    // 2. Format Version
    buffer.setUint16(offset, formatVersion.value, Endian.big);
    offset += 2;

    // 3. Purpose code
    buffer.setUint8(offset++, purpose.code);

    // 4. Vault ID
    buffer.setUint8(offset++, vaultIdBytes.length);
    for (var i = 0; i < vaultIdBytes.length; i++) {
      buffer.setUint8(offset++, vaultIdBytes[i]);
    }

    // 5. Record ID
    buffer.setUint8(offset++, recordIdBytes.length);
    for (var i = 0; i < recordIdBytes.length; i++) {
      buffer.setUint8(offset++, recordIdBytes[i]);
    }

    // 6. Record Version
    buffer.setUint32(offset, recordVersion, Endian.big);
    offset += 4;

    return buffer.buffer.asUint8List();
  }
}
