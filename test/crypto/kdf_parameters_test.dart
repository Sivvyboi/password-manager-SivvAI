import 'package:flutter_test/flutter_test.dart';
import 'package:password_generator_and_manager/core/errors.dart';
import 'package:password_generator_and_manager/crypto/models/crypto_scheme.dart';
import 'package:password_generator_and_manager/crypto/models/kdf_parameters.dart';

void main() {
  group('KdfParameters (Resource Limits & Validation)', () {
    test('Candidate profile is valid and within safe limits', () {
      final params = KdfParameters.candidateProfile;
      expect(params.algorithm, equals(KdfAlgorithm.argon2idV13));
      expect(params.memoryKiB, equals(65536)); // 64 MiB
      expect(params.iterations, equals(3));
      expect(params.parallelism, equals(4));
      expect(params.saltLength, equals(16));
      expect(params.keyLength, equals(32));

      final validation = params.validateSafeLimits();
      expect(validation.isOk, isTrue);
    });

    test('Rejects memory below minimum safe bound (8 MiB)', () {
      const tooLowMemory = KdfParameters(
        memoryKiB: 4096, // 4 MiB
        iterations: 3,
        parallelism: 4,
      );
      final validation = tooLowMemory.validateSafeLimits();
      expect(validation.isErr, isTrue);
      expect(
        validation.match(onOk: (_) => null, onErr: (e) => e),
        equals(CryptoFailure.resourceLimitExceeded),
      );
    });

    test('Rejects memory exceeding maximum safe bound (256 MiB / DoS attack mitigation)', () {
      const excessiveMemory = KdfParameters(
        memoryKiB: 524288, // 512 MiB
        iterations: 3,
        parallelism: 4,
      );
      final validation = excessiveMemory.validateSafeLimits();
      expect(validation.isErr, isTrue);
      expect(
        validation.match(onOk: (_) => null, onErr: (e) => e),
        equals(CryptoFailure.resourceLimitExceeded),
      );
    });

    test('Rejects iterations out of safe bounds (1-10)', () {
      const zeroIter = KdfParameters(memoryKiB: 65536, iterations: 0, parallelism: 4);
      expect(zeroIter.validateSafeLimits().isErr, isTrue);

      const tooManyIter = KdfParameters(memoryKiB: 65536, iterations: 11, parallelism: 4);
      expect(tooManyIter.validateSafeLimits().isErr, isTrue);
    });

    test('Rejects parallelism out of safe bounds (1-8)', () {
      const zeroLanes = KdfParameters(memoryKiB: 65536, iterations: 3, parallelism: 0);
      expect(zeroLanes.validateSafeLimits().isErr, isTrue);

      const tooManyLanes = KdfParameters(memoryKiB: 65536, iterations: 3, parallelism: 9);
      expect(tooManyLanes.validateSafeLimits().isErr, isTrue);
    });
  });
}

