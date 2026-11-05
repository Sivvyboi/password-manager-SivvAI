import 'package:flutter_test/flutter_test.dart';
import 'package:password_generator_and_manager/core/types/record_id.dart';
import 'package:password_generator_and_manager/domain/models/autofill_association.dart';
import 'package:password_generator_and_manager/domain/models/credential_payload.dart';
import 'package:password_generator_and_manager/domain/models/record_type.dart';

void main() {
  group('CredentialPayload (FR-011, FR-012, FR-015, ADR-011)', () {
    final testId = RecordId.fromString('11111111-2222-3333-4444-555555555555');
    final now = DateTime.utc(2026, 11, 5, 12, 0, 0);

    test('Creates valid Login credential with redacted toString()', () {
      final login = CredentialPayload.login(
        id: testId,
        title: 'Example Account',
        username: 'alice@example.com',
        password: 'SuperSecretPassword123!',
        url: 'https://example.com',
        now: now,
      );

      expect(login.type, equals(RecordType.login));
      expect(login.title, equals('Example Account'));
      expect(login.username, equals('alice@example.com'));
      expect(login.password, equals('SuperSecretPassword123!'));
      expect(login.toString().contains('SuperSecretPassword123!'), isFalse);
    });

    test('FR-015: Payment card enforces valid expiry month and strips whitespace', () {
      final card = CredentialPayload.paymentCard(
        id: testId,
        title: 'Work Visa',
        cardholderName: 'Alice Developer',
        cardNumber: '4111 2222 3333 4444',
        expiryMonth: 12,
        expiryYear: 2029,
        now: now,
      );

      expect(card.type, equals(RecordType.paymentCard));
      expect(card.cardNumber, equals('4111222233334444'));
      expect(card.cardExpiryMonth, equals(12));
      expect(card.cardExpiryYear, equals(2029));

      // Month out of range must be rejected
      expect(
        () => CredentialPayload.paymentCard(
          id: testId,
          title: 'Invalid Card',
          cardholderName: 'Alice',
          cardNumber: '4111',
          expiryMonth: 13,
          expiryYear: 2030,
          now: now,
        ),
        throwsArgumentError,
      );
    });
  });

  group('AutofillAssociation (FR-044, FR-045, FR-046)', () {
    test('Valid Android application association requires SHA-256 cert hash', () {
      const validHash = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90';
      final appAssoc = AutofillAssociation.forAndroidApp(
        packageName: 'com.example.secureapp',
        signingCertificateSha256: validHash,
      );

      expect(appAssoc.isApp, isTrue);
      expect(appAssoc.identifier, equals('com.example.secureapp'));
      expect(appAssoc.signingCertificateHash, equals(validHash));
    });

    test('Rejects invalid Android package name or invalid certificate hash', () {
      expect(
        () => AutofillAssociation.forAndroidApp(
          packageName: 'invalidpackage',
          signingCertificateSha256: 'a' * 64,
        ),
        throwsArgumentError,
      );

      expect(
        () => AutofillAssociation.forAndroidApp(
          packageName: 'com.example.app',
          signingCertificateSha256: 'short-hash',
        ),
        throwsArgumentError,
      );
    });

    test('Valid website association requires canonical scheme and host', () {
      final webAssoc = AutofillAssociation.forWebsite(
        origin: 'https://login.example.com/some/path',
      );

      expect(webAssoc.isWeb, isTrue);
      expect(webAssoc.identifier, equals('https://login.example.com'));
      expect(webAssoc.signingCertificateHash, isNull);
    });

    test('Rejects non-http(s) or invalid origins', () {
      expect(() => AutofillAssociation.forWebsite(origin: 'ftp://example.com'), throwsArgumentError);
      expect(() => AutofillAssociation.forWebsite(origin: 'not-a-url'), throwsArgumentError);
    });
  });
}

