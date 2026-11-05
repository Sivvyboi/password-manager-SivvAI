/// Supported credential record types in the password manager.
///
/// Corresponds to FR-012 in project requirements.
enum RecordType {
  /// Standard login credential (username, password, URLs, Autofill associations).
  login,

  /// Secure note containing arbitrary sensitive text.
  secureNote,

  /// Payment card metadata (cardholder, number, expiry).
  /// CVV/CVC is strictly forbidden per FR-015 / ADR-011.
  paymentCard,

  /// Wi-Fi network credential (SSID, password, security type).
  wifi,

  /// Software licence key and product entitlement information.
  softwareLicence;

  /// String identifier for serialization and associated data encoding.
  String get typeCode {
    switch (this) {
      case RecordType.login:
        return 'LOGIN';
      case RecordType.secureNote:
        return 'NOTE';
      case RecordType.paymentCard:
        return 'CARD';
      case RecordType.wifi:
        return 'WIFI';
      case RecordType.softwareLicence:
        return 'LICENCE';
    }
  }

  /// Parses a typeCode into a [RecordType], or throws [ArgumentError] if invalid.
  static RecordType fromCode(String code) {
    switch (code) {
      case 'LOGIN':
        return RecordType.login;
      case 'NOTE':
        return RecordType.secureNote;
      case 'CARD':
        return RecordType.paymentCard;
      case 'WIFI':
        return RecordType.wifi;
      case 'LICENCE':
        return RecordType.softwareLicence;
      default:
        throw ArgumentError.value(code, 'code', 'Unsupported record type code.');
    }
  }
}

