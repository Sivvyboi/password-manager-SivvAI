import 'package:flutter/foundation.dart';

/// Strongly typed, immutable identifier for a vault credential record.
@immutable
class RecordId {
  final String value;

  const RecordId._(this.value);

  /// Validates and constructs a [RecordId] from a valid canonical UUID string.
  factory RecordId.fromString(String raw) {
    final trimmed = raw.trim().toLowerCase();
    if (!_uuidRegex.hasMatch(trimmed)) {
      throw ArgumentError.value(raw, 'raw', 'RecordId must be a valid canonical UUID string.');
    }
    return RecordId._(trimmed);
  }

  /// Attempts to parse [raw] into a [RecordId], returning null if invalid.
  static RecordId? tryParse(String? raw) {
    if (raw == null) return null;
    final trimmed = raw.trim().toLowerCase();
    if (!_uuidRegex.hasMatch(trimmed)) return null;
    return RecordId._(trimmed);
  }

  static final RegExp _uuidRegex = RegExp(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
  );

  @override
  bool operator ==(Object other) =>
      identical(this, other) || (other is RecordId && other.value == value);

  @override
  int get hashCode => value.hashCode;

  @override
  String toString() => value;
}

