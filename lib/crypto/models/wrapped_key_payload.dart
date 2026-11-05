import 'package:flutter/foundation.dart';

/// Container for AEAD-wrapped key material (e.g. Master Key Wrapper or Recovery Key Wrapper).
@immutable
class WrappedKeyPayload {
  /// 96-bit (12-byte) initialization vector / nonce.
  final List<int> nonce;

  /// Encrypted ciphertext bytes.
  final List<int> ciphertext;

  /// 128-bit (16-byte) authentication tag.
  final List<int> macTag;

  const WrappedKeyPayload({
    required this.nonce,
    required this.ciphertext,
    required this.macTag,
  });

  /// Validates lengths for standard AES-256-GCM wrapper:
  /// - Nonce: 12 bytes (96 bits)
  /// - Tag: 16 bytes (128 bits)
  /// - Ciphertext for 32-byte VEK: 32 bytes
  bool get isValidGcmWrapper =>
      nonce.length == 12 && macTag.length == 16 && ciphertext.isNotEmpty;

  @override
  String toString() =>
      'WrappedKeyPayload(nonceLen: ${nonce.length}, cipherLen: ${ciphertext.length}, tagLen: ${macTag.length})';
}

