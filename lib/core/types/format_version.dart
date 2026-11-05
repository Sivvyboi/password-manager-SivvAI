import 'package:flutter/foundation.dart';

/// Strongly typed format version for vault headers and portable packages.
@immutable
class FormatVersion implements Comparable<FormatVersion> {
  final int value;

  const FormatVersion(this.value) : assert(value > 0, 'Format version must be positive.');

  /// Version 1: Initial format baseline (Phase 1).
  static const FormatVersion v1 = FormatVersion(1);

  /// Current supported format version.
  static const FormatVersion current = v1;

  /// Checks if this version is supported by the current codebase.
  bool get isSupported => value == 1;

  @override
  int compareTo(FormatVersion other) => value.compareTo(other.value);

  bool operator <(FormatVersion other) => value < other.value;
  bool operator <=(FormatVersion other) => value <= other.value;
  bool operator >(FormatVersion other) => value > other.value;
  bool operator >=(FormatVersion other) => value >= other.value;

  @override
  bool operator ==(Object other) =>
      identical(this, other) || (other is FormatVersion && other.value == value);

  @override
  int get hashCode => value.hashCode;

  @override
  String toString() => 'FormatVersion($value)';
}
