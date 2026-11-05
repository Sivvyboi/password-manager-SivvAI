import 'package:flutter/foundation.dart';

/// Models the security and risk posture of the host device.
///
/// Implements requirements FR-050, FR-051, and TH-014.
@immutable
class DeviceRiskProfile {
  /// True if root indicators or test-keys build properties are detected.
  final bool isRootedOrCompromised;

  /// True if the Android security patch level is older than the configured threshold.
  final bool isSecurityPatchOutdated;

  /// Android API level (e.g. 26, 34).
  final int apiLevel;

  /// True if hardware-backed Keystore / StrongBox is confirmed present.
  final bool hasHardwareKeystore;

  /// True if biometric enrollment and hardware are available.
  final bool isBiometricAvailable;

  const DeviceRiskProfile({
    this.isRootedOrCompromised = false,
    this.isSecurityPatchOutdated = false,
    required this.apiLevel,
    this.hasHardwareKeystore = false,
    this.isBiometricAvailable = false,
  });

  /// Evaluates whether high-risk convenience features (Autofill, Biometric unlock)
  /// should be disabled due to elevated device risk.
  bool get shouldDisableConvenienceFeatures => isRootedOrCompromised;

  /// Evaluates whether clipboard copying should be disabled by default (API 26/27).
  bool get shouldDisableClipboardByDefault => apiLevel < 29;

  @override
  String toString() =>
      'DeviceRiskProfile(api: $apiLevel, compromised: $isRootedOrCompromised, outdatedPatch: $isSecurityPatchOutdated, hwKeystore: $hasHardwareKeystore)';
}

