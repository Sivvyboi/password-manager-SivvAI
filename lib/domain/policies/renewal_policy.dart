import 'package:flutter/foundation.dart';

/// Policy and settings for credential renewal reminders per FR-028, FR-029, FR-030.
@immutable
class RenewalPolicy {
  final bool isEnabled;
  final int? reminderIntervalDays;
  final DateTime? specificReminderDate;

  const RenewalPolicy({
    this.isEnabled = false,
    this.reminderIntervalDays,
    this.specificReminderDate,
  });

  static const RenewalPolicy disabled = RenewalPolicy(isEnabled: false);

  /// Helper to calculate the next trigger date given the last password modification date.
  DateTime? calculateNextReminder(DateTime lastPasswordChange) {
    if (!isEnabled) return null;
    if (specificReminderDate != null) return specificReminderDate;
    if (reminderIntervalDays != null && reminderIntervalDays! > 0) {
      return lastPasswordChange.add(Duration(days: reminderIntervalDays!));
    }
    return null;
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is RenewalPolicy &&
          other.isEnabled == isEnabled &&
          other.reminderIntervalDays == reminderIntervalDays &&
          other.specificReminderDate == specificReminderDate);

  @override
  int get hashCode => Object.hash(isEnabled, reminderIntervalDays, specificReminderDate);
}

