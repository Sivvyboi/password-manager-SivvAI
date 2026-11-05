import 'package:flutter/foundation.dart';
import '../../core/errors.dart';
import '../../core/result.dart';
import 'crypto_scheme.dart';

/// Parameters for Key Derivation Function (Argon2id).
///
/// Implements parameter validation and bounds checking to prevent Denial of Service (DoS)
/// or resource exhaustion attacks via tampered vault headers.
@immutable
class KdfParameters {
  final KdfAlgorithm algorithm;
  final int memoryKiB;
  final int iterations;
  final int parallelism;
  final int saltLength;
  final int keyLength;

  const KdfParameters({
    this.algorithm = KdfAlgorithm.argon2idV13,
    required this.memoryKiB,
    required this.iterations,
    required this.parallelism,
    this.saltLength = 16, // 128-bit salt
    this.keyLength = 32, // 256-bit output key
  });

  /// Candidate profile for Android/Windows evaluation:
  /// 64 MiB (65536 KiB), 3 iterations, 4 lanes.
  /// Subject to benchmarking on Android 8 (API 26) physical device.
  static const KdfParameters candidateProfile = KdfParameters(
    algorithm: KdfAlgorithm.argon2idV13,
    memoryKiB: 65536,
    iterations: 3,
    parallelism: 4,
    saltLength: 16,
    keyLength: 32,
  );

  /// Safe bounds to prevent memory/CPU exhaustion from untrusted/tampered headers
  static const int minMemoryKiB = 8192; // 8 MiB minimum
  static const int maxMemoryKiB = 262144; // 256 MiB maximum
  static const int minIterations = 1;
  static const int maxIterations = 10;
  static const int minParallelism = 1;
  static const int maxParallelism = 8;
  static const int expectedSaltLength = 16; // 128 bits
  static const int expectedKeyLength = 32; // 256 bits

  /// Validates that parameters fall within strictly enforced safe operational boundaries.
  Result<void, CryptoFailure> validateSafeLimits() {
    if (algorithm != KdfAlgorithm.argon2idV13) {
      return const Result.err(CryptoFailure.unsupportedAlgorithmOrVersion);
    }
    if (memoryKiB < minMemoryKiB || memoryKiB > maxMemoryKiB) {
      return const Result.err(CryptoFailure.resourceLimitExceeded);
    }
    if (iterations < minIterations || iterations > maxIterations) {
      return const Result.err(CryptoFailure.resourceLimitExceeded);
    }
    if (parallelism < minParallelism || parallelism > maxParallelism) {
      return const Result.err(CryptoFailure.resourceLimitExceeded);
    }
    if (saltLength != expectedSaltLength) {
      return const Result.err(CryptoFailure.invalidKeyLength);
    }
    if (keyLength != expectedKeyLength) {
      return const Result.err(CryptoFailure.invalidKeyLength);
    }
    return const Result.ok(null);
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      (other is KdfParameters &&
          other.algorithm == algorithm &&
          other.memoryKiB == memoryKiB &&
          other.iterations == iterations &&
          other.parallelism == parallelism &&
          other.saltLength == saltLength &&
          other.keyLength == keyLength);

  @override
  int get hashCode => Object.hash(
        algorithm,
        memoryKiB,
        iterations,
        parallelism,
        saltLength,
        keyLength,
      );

  @override
  String toString() =>
      'KdfParameters(${algorithm.identifier}, m=${memoryKiB}KiB, t=$iterations, p=$parallelism)';
}

