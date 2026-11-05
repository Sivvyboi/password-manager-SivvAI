import 'package:flutter/foundation.dart';
import '../../core/types/record_id.dart';
import 'autofill_association.dart';
import 'record_type.dart';

/// Represents the decrypted, sensitive payload of a vault credential record.
///
/// Plaintext instances exist only in memory during an authenticated, active session.
/// Plaintext must never be persisted or logged per NFR-002 and project guardrails.
@immutable
class CredentialPayload {
  final RecordId id;
  final RecordType type;
  final String title;
  final String? username;
  final String? password;
  final String? url;
  final String? notes;
  final String category;
  final bool isFavourite;
  final DateTime createdAt;
  final DateTime updatedAt;
  final DateTime? passwordChangedAt;
  final List<AutofillAssociation> associations;

  // Type-specific fields (Non-login):
  // Payment card: cardholderName, cardNumber, expiryMonth, expiryYear.
  // CVV/CVC is STRICTLY FORBIDDEN per FR-015 and ADR-011.
  final String? cardholderName;
  final String? cardNumber;
  final int? cardExpiryMonth;
  final int? cardExpiryYear;

  // Wi-Fi:
  final String? wifiSsid;
  final String? wifiSecurityType;

  // Software Licence:
  final String? licenceKey;
  final String? licenceRegisteredTo;

  const CredentialPayload({
    required this.id,
    required this.type,
    required this.title,
    this.username,
    this.password,
    this.url,
    this.notes,
    this.category = 'General',
    this.isFavourite = false,
    required this.createdAt,
    required this.updatedAt,
    this.passwordChangedAt,
    this.associations = const [],
    this.cardholderName,
    this.cardNumber,
    this.cardExpiryMonth,
    this.cardExpiryYear,
    this.wifiSsid,
    this.wifiSecurityType,
    this.licenceKey,
    this.licenceRegisteredTo,
  });

  /// Factory helper for creating standard Login credentials.
  factory CredentialPayload.login({
    required RecordId id,
    required String title,
    required String username,
    required String password,
    String? url,
    String? notes,
    String category = 'Logins',
    bool isFavourite = false,
    required DateTime now,
    List<AutofillAssociation> associations = const [],
  }) {
    return CredentialPayload(
      id: id,
      type: RecordType.login,
      title: title,
      username: username,
      password: password,
      url: url,
      notes: notes,
      category: category,
      isFavourite: isFavourite,
      createdAt: now,
      updatedAt: now,
      passwordChangedAt: now,
      associations: associations,
    );
  }

  /// Factory helper for creating Secure Notes.
  factory CredentialPayload.secureNote({
    required RecordId id,
    required String title,
    required String content,
    String category = 'Notes',
    bool isFavourite = false,
    required DateTime now,
  }) {
    return CredentialPayload(
      id: id,
      type: RecordType.secureNote,
      title: title,
      notes: content,
      category: category,
      isFavourite: isFavourite,
      createdAt: now,
      updatedAt: now,
    );
  }

  /// Factory helper for creating Payment Cards (CVV/CVC omitted by design).
  factory CredentialPayload.paymentCard({
    required RecordId id,
    required String title,
    required String cardholderName,
    required String cardNumber,
    required int expiryMonth,
    required int expiryYear,
    String? notes,
    String category = 'Cards',
    bool isFavourite = false,
    required DateTime now,
  }) {
    if (expiryMonth < 1 || expiryMonth > 12) {
      throw ArgumentError.value(expiryMonth, 'expiryMonth', 'Card expiry month must be between 1 and 12.');
    }
    return CredentialPayload(
      id: id,
      type: RecordType.paymentCard,
      title: title,
      cardholderName: cardholderName,
      cardNumber: cardNumber.replaceAll(RegExp(r'\s+'), ''),
      cardExpiryMonth: expiryMonth,
      cardExpiryYear: expiryYear,
      notes: notes,
      category: category,
      isFavourite: isFavourite,
      createdAt: now,
      updatedAt: now,
    );
  }

  /// Security: Never print credentials or secrets in logs.
  @override
  String toString() =>
      'CredentialPayload(id: $id, type: $type, title: $title, category: $category, isFav: $isFavourite)';
}

