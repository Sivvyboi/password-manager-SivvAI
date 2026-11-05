import 'dart:math';
import 'dart:typed_data';
import '../interfaces/secure_random_source.dart';

/// Cryptographically secure random number and byte generator.
///
/// Backed by operating-system level CSPRNG (`Random.secure()`).
/// Modulo bias in bounded integer generation is eliminated via rejection sampling.
class StandardSecureRandomSource implements SecureRandomSource {
  final Random _random;

  /// Creates a secure random source.
  ///
  /// [random] is optional and should ONLY be injected in tests requiring
  /// deterministic behavior. Defaults to [Random.secure()].
  StandardSecureRandomSource([Random? random]) : _random = random ?? Random.secure();

  @override
  Uint8List nextBytes(int length) {
    if (length < 0) {
      throw ArgumentError.value(length, 'length', 'Byte length must be non-negative.');
    }
    final bytes = Uint8List(length);
    for (var i = 0; i < length; i++) {
      bytes[i] = _random.nextInt(256);
    }
    return bytes;
  }

  @override
  int nextBoundedInt(int maxExclusive) {
    if (maxExclusive <= 0) {
      throw ArgumentError.value(maxExclusive, 'maxExclusive', 'Upper bound must be strictly positive.');
    }
    if (maxExclusive == 1) {
      return 0;
    }

    // 32-bit unsigned rejection sampling: 0 <= v < 2^32.
    // Largest multiple of maxExclusive <= 2^32.
    const twoPow32 = 0x100000000;
    final limit = twoPow32 - (twoPow32 % maxExclusive);

    while (true) {
      final b0 = _random.nextInt(256);
      final b1 = _random.nextInt(256);
      final b2 = _random.nextInt(256);
      final b3 = _random.nextInt(256);
      final v = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;

      if (v < limit) {
        return v % maxExclusive;
      }
    }
  }
}

