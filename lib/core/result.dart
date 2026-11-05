/// Represents the outcome of an operation that can succeed with [T] or fail with [E].
///
/// Ensures failure handling is explicit and forces callers to handle both branches
/// without relying on unhandled runtime exceptions.
sealed class Result<T, E> {
  const Result();

  /// Creates a successful result holding [value].
  const factory Result.ok(T value) = Ok<T, E>;

  /// Creates a failed result holding [error].
  const factory Result.err(E error) = Err<T, E>;

  /// Returns true if this is an [Ok] instance.
  bool get isOk => this is Ok<T, E>;

  /// Returns true if this is an [Err] instance.
  bool get isErr => this is Err<T, E>;

  /// Returns the encapsulated value if [isOk], or throws [StateError] if [isErr].
  T get unwrap {
    if (this is Ok<T, E>) {
      return (this as Ok<T, E>).value;
    }
    throw StateError('Called unwrap on an Err result: ${(this as Err<T, E>).error}');
  }

  /// Returns the encapsulated value if [isOk], or returns [defaultValue] if [isErr].
  T unwrapOr(T defaultValue) {
    if (this is Ok<T, E>) {
      return (this as Ok<T, E>).value;
    }
    return defaultValue;
  }

  /// Maps a [Result<T, E>] to [Result<U, E>] by applying [fn] to a contained [Ok] value.
  Result<U, E> map<U>(U Function(T value) fn) {
    if (this is Ok<T, E>) {
      return Result.ok(fn((this as Ok<T, E>).value));
    }
    return Result.err((this as Err<T, E>).error);
  }

  /// Maps a [Result<T, E>] to [Result<T, F>] by applying [fn] to a contained [Err] value.
  Result<T, F> mapErr<F>(F Function(E error) fn) {
    if (this is Err<T, E>) {
      return Result.err(fn((this as Err<T, E>).error));
    }
    return Result.ok((this as Ok<T, E>).value);
  }

  /// Executes [onOk] if [isOk] or [onErr] if [isErr].
  R match<R>({
    required R Function(T value) onOk,
    required R Function(E error) onErr,
  }) {
    if (this is Ok<T, E>) {
      return onOk((this as Ok<T, E>).value);
    }
    return onErr((this as Err<T, E>).error);
  }
}

/// A successful [Result] containing [value].
final class Ok<T, E> extends Result<T, E> {
  final T value;
  const Ok(this.value);

  @override
  bool operator ==(Object other) =>
      identical(this, other) || (other is Ok<T, E> && other.value == value);

  @override
  int get hashCode => value.hashCode;

  @override
  String toString() => 'Result.ok($value)';
}

/// A failed [Result] containing [error].
final class Err<T, E> extends Result<T, E> {
  final E error;
  const Err(this.error);

  @override
  bool operator ==(Object other) =>
      identical(this, other) || (other is Err<T, E> && other.error == error);

  @override
  int get hashCode => error.hashCode;

  @override
  String toString() => 'Result.err($error)';
}

