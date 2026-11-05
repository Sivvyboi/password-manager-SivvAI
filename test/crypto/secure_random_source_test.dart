import 'dart:math';
import 'package:flutter_test/flutter_test.dart';
import 'package:password_generator_and_manager/crypto/services/standard_secure_random_source.dart';

class _DeterministicTestRandom implements Random {
  int _counter = 0;

  @override
  bool nextBool() => (_counter++ % 2) == 0;

  @override
  double nextDouble() => (_counter++ % 100) / 100.0;

  @override
  int nextInt(int max) {
    final val = _counter % max;
    _counter++;
    return val;
  }
}

void main() {
  group('StandardSecureRandomSource', () {
    final randomSource = StandardSecureRandomSource();

    test('generates requested arbitrary byte lengths', () {
      expect(randomSource.nextBytes(0).length, 0);
      expect(randomSource.nextBytes(1).length, 1);
      expect(randomSource.nextBytes(16).length, 16);
      expect(randomSource.nextBytes(32).length, 32);
      expect(randomSource.nextBytes(64).length, 64);
      expect(randomSource.nextBytes(1024).length, 1024);
    });

    test('throws ArgumentError on negative length', () {
      expect(() => randomSource.nextBytes(-1), throwsArgumentError);
    });

    test('nextBoundedInt produces integers within [0, maxExclusive)', () {
      for (final max in [1, 2, 3, 5, 7, 10, 16, 26, 62, 100, 2048]) {
        for (var i = 0; i < 50; i++) {
          final val = randomSource.nextBoundedInt(max);
          expect(val, greaterThanOrEqualTo(0));
          expect(val, lessThan(max));
        }
      }
    });

    test('nextBoundedInt with maxExclusive = 1 returns 0', () {
      expect(randomSource.nextBoundedInt(1), 0);
    });

    test('nextBoundedInt throws ArgumentError on non-positive upper bound', () {
      expect(() => randomSource.nextBoundedInt(0), throwsArgumentError);
      expect(() => randomSource.nextBoundedInt(-5), throwsArgumentError);
    });

    test('allows deterministic injection in tests only', () {
      final mock = _DeterministicTestRandom();
      final deterministicSource = StandardSecureRandomSource(mock);

      final bytes1 = deterministicSource.nextBytes(4);
      expect(bytes1, [0, 1, 2, 3]);

      final intVal = deterministicSource.nextBoundedInt(10);
      expect(intVal, 7);
    });
  });
}
