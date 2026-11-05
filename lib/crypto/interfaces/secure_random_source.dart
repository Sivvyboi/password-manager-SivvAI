import 'dart:typed_data';

/// Interface for generating cryptographically secure pseudorandom numbers (CSPRNG).
///
/// Backed exclusively by operating-system level entropy (e.g. `/dev/urandom`, `getrandom`,
/// or Windows `BCryptGenRandom`). Insecure or pseudo-random sources (e.g. standard `Random`,
/// timestamps, or seeds) are strictly prohibited.
abstract interface class SecureRandomSource {
  /// Generates [length] cryptographically secure pseudorandom bytes.
  Uint8List nextBytes(int length);

  /// Selects an integer uniformly at random in the half-open range `[0, maxExclusive)`.
  /// Must use rejection sampling to guarantee zero modulo bias.
  int nextBoundedInt(int maxExclusive);
}

