import 'package:flutter/foundation.dart';

/// Strongly typed, immutable identifier for a logical vault.
///
/// Encapsulates a valid canonical UUID string in RFC 4122 textual syntax
/// (8-4-4-4-12 lowercase hexadecimal format) to prevent raw string confusion
/// in domain and cryptographic contexts.
///
/// Note: This class validates canonical textual formatting and character set.
/// It intentionally does not restrict or enforce specific RFC 4122 version or
/// variant bits (such as UUID v4), ensuring full interoperability with canonical
/// UUIDs from system generators and cross-platform test vectors.
@immutable
class VaultId {
  final String value;

  const VaultId._(this.value);

  /// Validates and constructs a [VaultId] from a valid canonical UUID string.
  /// Throws [ArgumentError] if the format is invalid.
  factory VaultId.fromString(String raw) {
    final trimmed = raw.trim().toLowerCase();
    if (!_uuidRegex.hasMatch(trimmed)) {
      throw ArgumentError.value(raw, 'raw', 'VaultId must be a valid canonical UUID string.');
    }
    return VaultId._(trimmed);
  }

  /// Attempts to parse [raw] into a [VaultId], returning null if invalid.
  static VaultId? tryParse(String? raw) {
    if (raw == null) return null;
    final trimmed = raw.trim().toLowerCase();
    if (!_uuidRegex.hasMatch(trimmed)) return null;
    return VaultId._(trimmed);
  }

  static final RegExp _uuidRegex = RegExp(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
  );

  @override
  bool operator ==(Object other) =>
      identical(this, other) || (other is VaultId && other.value == value);

  @override
  int get hashCode => value.hashCode;

  @override
  String toString() => value;
}
