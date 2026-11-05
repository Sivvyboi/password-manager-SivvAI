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

/// Cryptographic purpose domain separation labels.
enum CryptoPurpose {
  /// Wrapping of the primary Vault Encryption Key by the master password key.
  masterKeyWrap(0x01, 'PM-VAULT-WRAP-V1'),

  /// Wrapping of the primary Vault Encryption Key by the recovery phrase key.
  recoveryKeyWrap(0x02, 'PM-RECOVERY-WRAP-V1'),

  /// Derivation of record encryption keys from the Vault Encryption Key.
  recordKeyDerivation(0x03, 'PM-RECORD-KEY-V1'),

  /// Record payload encryption.
  recordPayloadEncryption(0x04, 'PM-RECORD-PAYLOAD-V1'),

  /// Encrypted deletion tombstone.
  tombstonePayloadEncryption(0x05, 'PM-TOMBSTONE-PAYLOAD-V1'),

  /// Portable vault package authentication.
  backupPackageWrap(0x06, 'PM-BACKUP-PACKAGE-V1');

  final int purposeCode;
  final String domainString;
  const CryptoPurpose(this.purposeCode, this.domainString);
}

