/// Base container for sensitive secret bytes.
///
/// Designed to prevent accidental logging or exposure of cryptographic keys.
/// [toString] intentionally redacts key contents.
abstract class SecretKeyBytes {
  final List<int> _bytes;
  bool _isDisposed = false;

  SecretKeyBytes(List<int> bytes, int expectedLength) : _bytes = List<int>.from(bytes) {
    if (bytes.length != expectedLength) {
      throw ArgumentError(
        'Invalid key length: expected $expectedLength bytes, got ${bytes.length}.',
      );
    }
  }

  /// Read-only view of the underlying key bytes.
  /// Throws [StateError] if the key has been disposed/zeroized.
  List<int> get bytes {
    if (_isDisposed) {
      throw StateError('$runtimeType has been destroyed and cannot be accessed.');
    }
    return List.unmodifiable(_bytes);
  }

  int get length => _bytes.length;
  bool get isDisposed => _isDisposed;

  /// Best-effort zeroization of secret bytes in memory.
  void destroy() {
    if (!_isDisposed) {
      for (var i = 0; i < _bytes.length; i++) {
        _bytes[i] = 0;
      }
      _isDisposed = true;
    }
  }

  @override
  String toString() => '$runtimeType([REDACTED])';
}

/// 256-bit key derived from the master password using Argon2id.
/// Used strictly to wrap/unwrap the Vault Encryption Key (VEK).
class MasterWrappingKey extends SecretKeyBytes {
  MasterWrappingKey(List<int> bytes) : super(bytes, 32);
}

/// 256-bit key derived from the 24-word recovery phrase.
/// Used strictly to wrap/unwrap the Vault Encryption Key (VEK) during recovery.
class RecoveryWrappingKey extends SecretKeyBytes {
  RecoveryWrappingKey(List<int> bytes) : super(bytes, 32);
}

/// Primary 256-bit Vault Encryption Key (VEK).
/// Randomly generated during vault creation; never persisted in plaintext.
class VaultEncryptionKey extends SecretKeyBytes {
  VaultEncryptionKey(List<int> bytes) : super(bytes, 32);
}

/// 256-bit key derived from the VEK via HKDF for encrypting credential records.
class RecordEncryptionKey extends SecretKeyBytes {
  RecordEncryptionKey(List<int> bytes) : super(bytes, 32);
}
