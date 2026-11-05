import 'package:flutter/foundation.dart';

/// Categorization of security-relevant system and lifecycle events.
enum SecurityEventType {
  appBackgrounded,
  screenLocked,
  manualLockRequested,
  authFailed,
  authSucceeded,
  tamperDetected,
}

/// Represents an audited security event within the application.
/// Sensitive secrets are never attached to security events.
@immutable
class SecurityEvent {
  final SecurityEventType type;
  final DateTime timestamp;
  final String? details;

  const SecurityEvent({
    required this.type,
    required this.timestamp,
    this.details,
  });

  @override
  String toString() => 'SecurityEvent(type: $type, timestamp: $timestamp, details: $details)';
}

