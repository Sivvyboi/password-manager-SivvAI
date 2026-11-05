import 'package:flutter_test/flutter_test.dart';
import 'package:password_generator_and_manager/core/result.dart';

void main() {
  group('Result', () {
    test('Ok holds value and supports mapping', () {
      const result = Result<int, String>.ok(42);
      expect(result.isOk, isTrue);
      expect(result.isErr, isFalse);
      expect(result.unwrap, equals(42));
      expect(result.unwrapOr(0), equals(42));

      final mapped = result.map((v) => v * 2);
      expect(mapped.unwrap, equals(84));
    });

    test('Err holds error and supports mapErr', () {
      const result = Result<int, String>.err('Failed');
      expect(result.isOk, isFalse);
      expect(result.isErr, isTrue);
      expect(() => result.unwrap, throwsStateError);
      expect(result.unwrapOr(10), equals(10));

      final mapped = result.mapErr((e) => 'Prefix: $e');
      expect(mapped.match(onOk: (_) => '', onErr: (e) => e), equals('Prefix: Failed'));
    });
  });
}

