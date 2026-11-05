/// Versioned cryptographic schemes and algorithm identifiers.
///
/// Cryptographic choices must be strictly versioned and cannot be silently refactored.
enum KdfAlgorithm {
  /// Argon2id version 1.3 (RFC 9106)
  argon2idV13('argon2id-v13');

  final String identifier;
  const KdfAlgorithm(this.identifier);

  static KdfAlgorithm fromIdentifier(String id) {
    if (id == argon2idV13.identifier) return argon2idV13;
    throw ArgumentError.value(id, 'id', 'Unsupported KDF algorithm identifier.');
  }
}

/// Versioned Authenticated Encryption with Associated Data (AEAD) algorithms.
enum AeadCipher {
  /// AES-256 in Galois/Counter Mode with 128-bit authentication tag and 96-bit nonce.
  aes256Gcm('aes-256-gcm');

  final String identifier;
  const AeadCipher(this.identifier);

  static AeadCipher fromIdentifier(String id) {
    if (id == aes256Gcm.identifier) return aes256Gcm;
    throw ArgumentError.value(id, 'id', 'Unsupported AEAD cipher identifier.');
  }
}

/// Explicit 1-byte purpose codes for AEAD Associated Authenticated Data (AAD).
///
/// Embedded at byte offset 6 in the canonical binary AAD header.
/// Strictly distinguishes the operational domain of each ciphertext.
enum AeadPurpose {
  /// 0x01: Wrapping of the primary Vault Encryption Key by the master password key.
  masterKeyWrap(0x01),

  /// 0x02: Wrapping of the primary Vault Encryption Key by the recovery phrase key.
  recoveryKeyWrap(0x02),

  /// 0x04: Record payload encryption.
  recordPayload(0x04),

  /// 0x05: Authenticated deletion tombstone payload.
  tombstonePayload(0x05),

  /// 0x06: Portable backup package encryption and authentication.
  backupPackage(0x06);

  final int code;
  const AeadPurpose(this.code);

  static AeadPurpose fromCode(int code) {
    for (final p in values) {
      if (p.code == code) return p;
    }
    throw ArgumentError.value(code, 'code', 'Unsupported AEAD purpose code.');
  }
}

/// Context labels used for RFC 5869 HKDF-Expand key derivation.
///
/// These strings provide domain separation for subkey derivation and are distinct
/// from the 1-byte binary AEAD purpose codes.
abstract final class HkdfContext {
  /// HKDF info prefix for deriving a per-record encryption key from VEK.
  /// Formatted as: 'PM-RECORD-KEY-V1:' + recordId
  static const String recordKeyPrefix = 'PM-RECORD-KEY-V1:';

  /// HKDF info prefix for deriving the recovery wrapping key from the BIP39 seed.
  /// Formatted as: 'PM-RECOVERY-WRAP-V1:' + vaultId
  static const String recoveryWrapPrefix = 'PM-RECOVERY-WRAP-V1:';

  /// HKDF info prefix for deriving a backup package encryption key.
  /// Formatted as: 'PM-BACKUP-KEY-V1:' + vaultId
  static const String backupKeyPrefix = 'PM-BACKUP-KEY-V1:';
}
