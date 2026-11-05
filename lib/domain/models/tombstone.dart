import 'package:flutter/foundation.dart';
import '../../core/types/record_id.dart';

/// Represents an authenticated deletion tombstone per FR-017 and ADR-022.
///
/// Prevents older backups or future sync from resurrecting deleted records.
@immutable
class Tombstone {
  final RecordId recordId;
  final String revisionId;
  final DateTime deletedAt;

  const Tombstone({
    required this.recordId,
    required this.revisionId,
    required this.deletedAt,
  });

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is Tombstone &&
          other.recordId == recordId &&
          other.revisionId == revisionId &&
          other.deletedAt == deletedAt);

  @override
  int get hashCode => Object.hash(recordId, revisionId, deletedAt);

  @override
  String toString() => 'Tombstone(recordId: $recordId, revisionId: $revisionId, deletedAt: $deletedAt)';
}

