import 'package:flutter/foundation.dart';
import '../../core/types/format_version.dart';
import '../../core/types/vault_id.dart';

/// High-level vault metadata.
@immutable
class VaultMetadata {
  final VaultId id;
  final FormatVersion formatVersion;
  final DateTime createdAt;
  final DateTime updatedAt;

  const VaultMetadata({
    required this.id,
    required this.formatVersion,
    required this.createdAt,
    required this.updatedAt,
  });

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is VaultMetadata &&
          other.id == id &&
          other.formatVersion == formatVersion &&
          other.createdAt == createdAt &&
          other.updatedAt == updatedAt);

  @override
  int get hashCode => Object.hash(id, formatVersion, createdAt, updatedAt);

  @override
  String toString() => 'VaultMetadata(id: $id, version: $formatVersion, created: $createdAt)';
}

