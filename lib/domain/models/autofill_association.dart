import 'package:flutter/foundation.dart';

/// Represents an approved association between a credential and an application or website.
///
/// Strict matching rules apply per FR-044, FR-045, FR-046:
/// - No wildcards or regex.
/// - Applications must verify both package name and signing certificate hash.
/// - Websites must specify an exact scheme, host, and optional port.
@immutable
class AutofillAssociation {
  /// Target type: 'app' or 'web'.
  final String targetType;

  /// Android package name for apps, or canonical web origin for websites.
  final String identifier;

  /// SHA-256 fingerprint of the application signing certificate (mandatory for apps).
  final String? signingCertificateHash;

  /// User-friendly label or display title.
  final String? label;

  const AutofillAssociation._({
    required this.targetType,
    required this.identifier,
    this.signingCertificateHash,
    this.label,
  });

  /// Creates a strictly verified Android application association.
  factory AutofillAssociation.forAndroidApp({
    required String packageName,
    required String signingCertificateSha256,
    String? label,
  }) {
    final cleanPkg = packageName.trim();
    final cleanCert = signingCertificateSha256.trim().toLowerCase();

    if (cleanPkg.isEmpty || !cleanPkg.contains('.')) {
      throw ArgumentError.value(packageName, 'packageName', 'Invalid Android package name format.');
    }
    if (!RegExp(r'^[0-9a-f]{64}$').hasMatch(cleanCert)) {
      throw ArgumentError.value(
        signingCertificateSha256,
        'signingCertificateSha256',
        'Signing certificate hash must be a 64-character lowercase hex SHA-256 string.',
      );
    }

    return AutofillAssociation._(
      targetType: 'app',
      identifier: cleanPkg,
      signingCertificateHash: cleanCert,
      label: label,
    );
  }

  /// Creates an exact website origin association (e.g. 'https://example.com').
  factory AutofillAssociation.forWebsite({
    required String origin,
    String? label,
  }) {
    final uri = Uri.tryParse(origin.trim());
    if (uri == null || !uri.hasScheme || !uri.hasAuthority || uri.host.isEmpty) {
      throw ArgumentError.value(origin, 'origin', 'Website association must be a valid canonical origin.');
    }
    if (uri.scheme != 'https' && uri.scheme != 'http') {
      throw ArgumentError.value(origin, 'origin', 'Website association scheme must be http or https.');
    }

    // Canonical origin: scheme://host[:port]
    final canonicalOrigin = '${uri.scheme}://${uri.host}${uri.hasPort ? ':${uri.port}' : ''}'.toLowerCase();

    return AutofillAssociation._(
      targetType: 'web',
      identifier: canonicalOrigin,
      signingCertificateHash: null,
      label: label,
    );
  }

  bool get isApp => targetType == 'app';
  bool get isWeb => targetType == 'web';

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is AutofillAssociation &&
          other.targetType == targetType &&
          other.identifier == identifier &&
          other.signingCertificateHash == signingCertificateHash);

  @override
  int get hashCode => Object.hash(targetType, identifier, signingCertificateHash);

  @override
  String toString() =>
      'AutofillAssociation(targetType: $targetType, identifier: $identifier, cert: $signingCertificateHash)';
}

