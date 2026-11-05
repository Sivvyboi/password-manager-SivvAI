/// Base class for all domain and security errors in the application.
abstract class AppFailure {
  final String message;
  final String? code;

  const AppFailure(this.message, {this.code});

  @override
  String toString() => code != null ? '$runtimeType($code: $message)' : '$runtimeType($message)';
}

/// Failures relating to master password, authentication, or session validation.
class AuthenticationFailure extends AppFailure {
  const AuthenticationFailure(super.message, {super.code});

  /// Generic authentication failure used to avoid timing/oracle disclosure.
  static const AuthenticationFailure generic = AuthenticationFailure(
    'Authentication failed.',
    code: 'AUTH_INVALID_CREDENTIALS',
  );

  static const AuthenticationFailure sessionExpired = AuthenticationFailure(
    'The session has expired or is locked.',
    code: 'AUTH_SESSION_EXPIRED',
  );
}

/// Failures relating to cryptographic operations (KDF, AEAD, Key wrapping, Derivation).
class CryptoFailure extends AppFailure {
  const CryptoFailure(super.message, {super.code});

  static const CryptoFailure authenticationTagMismatch = CryptoFailure(
    'Cryptographic integrity verification failed.',
    code: 'CRYPTO_TAG_MISMATCH',
  );

  static const CryptoFailure invalidKeyLength = CryptoFailure(
    'Key length does not meet algorithm requirements.',
    code: 'CRYPTO_INVALID_KEY_LENGTH',
  );

  static const CryptoFailure invalidNonceLength = CryptoFailure(
    'Nonce length does not meet algorithm requirements.',
    code: 'CRYPTO_INVALID_NONCE_LENGTH',
  );

  static const CryptoFailure resourceLimitExceeded = CryptoFailure(
    'Cryptographic parameters exceed safe resource consumption limits.',
    code: 'CRYPTO_RESOURCE_LIMIT_EXCEEDED',
  );

  static const CryptoFailure unsupportedAlgorithmOrVersion = CryptoFailure(
    'The specified cryptographic algorithm or version is not supported.',
    code: 'CRYPTO_UNSUPPORTED_VERSION',
  );
}

/// Failures relating to domain rules, validation, or policy violations.
class PolicyFailure extends AppFailure {
  const PolicyFailure(super.message, {super.code});

  static const PolicyFailure masterPasswordTooShort = PolicyFailure(
    'Master password must be at least 15 characters long.',
    code: 'POLICY_MASTER_PASSWORD_TOO_SHORT',
  );

  static const PolicyFailure generatedPasswordTooShort = PolicyFailure(
    'Generated password must be at least 12 characters long.',
    code: 'POLICY_GENERATED_PASSWORD_TOO_SHORT',
  );

  static const PolicyFailure emptyCharacterSet = PolicyFailure(
    'Password generator configuration resulted in an empty character set.',
    code: 'POLICY_EMPTY_CHARSET',
  );

  static const PolicyFailure invalidMnemonicChecksum = PolicyFailure(
    'Recovery mnemonic checksum validation failed.',
    code: 'POLICY_INVALID_MNEMONIC_CHECKSUM',
  );

  static const PolicyFailure invalidMnemonicLength = PolicyFailure(
    'Recovery mnemonic must consist of exactly 24 words.',
    code: 'POLICY_INVALID_MNEMONIC_LENGTH',
  );
}

/// Failures relating to data format, serialization, or corruption.
class FormatFailure extends AppFailure {
  const FormatFailure(super.message, {super.code});

  static const FormatFailure corruptedHeader = FormatFailure(
    'Vault header is corrupted or unparseable.',
    code: 'FORMAT_CORRUPTED_HEADER',
  );

  static const FormatFailure unsupportedFormatVersion = FormatFailure(
    'Unsupported vault format version.',
    code: 'FORMAT_UNSUPPORTED_VERSION',
  );
}

