/// Every deliberately reported OpenAlias lookup failure.
///
/// [message] is a developer diagnostic. [alias] is the alias the lookup was
/// for: the normalised domain when normalisation succeeded, otherwise the raw
/// input. [cause] keeps the constituent package's error and is never printed
/// by [toString].
sealed class CsOpenAliasException implements Exception {
  final String message;
  final String alias;
  final Object? cause;
  final StackTrace? causeStackTrace;
  const CsOpenAliasException(
    this.message, {
    required this.alias,
    this.cause,
    this.causeStackTrace,
  });

  @override
  String toString() => '$runtimeType: $message';
}

/// The input is not an OpenAlias name.
final class CsOpenAliasInvalidAliasException extends CsOpenAliasException {
  const CsOpenAliasInvalidAliasException(
    super.message, {
    required super.alias,
    super.cause,
    super.causeStackTrace,
  });
}

/// The name has no `oa1:xmr` record, or DNSSEC proved it has no TXT records.
final class CsOpenAliasNoRecordException extends CsOpenAliasException {
  const CsOpenAliasNoRecordException(
    super.message, {
    required super.alias,
    super.cause,
    super.causeStackTrace,
  });
}

/// The records name several recipient addresses or conflict.
final class CsOpenAliasAmbiguousException extends CsOpenAliasException {
  const CsOpenAliasAmbiguousException(
    super.message, {
    required super.alias,
    super.cause,
    super.causeStackTrace,
  });
}

/// A record was found but is unusable: malformed, duplicate or unsupported
/// fields, over a limit, or an address the wallet rejected.
final class CsOpenAliasInvalidRecordException extends CsOpenAliasException {
  const CsOpenAliasInvalidRecordException(
    super.message, {
    required super.alias,
    super.cause,
    super.causeStackTrace,
  });
}

enum CsOpenAliasDnssecStatus { insecure, bogus, indeterminate }

/// DNSSEC validation did not establish a secure answer.
final class CsOpenAliasDnssecException extends CsOpenAliasException {
  final CsOpenAliasDnssecStatus status;
  const CsOpenAliasDnssecException(
    super.message, {
    required super.alias,
    required this.status,
    super.cause,
    super.causeStackTrace,
  });

  @override
  String toString() => '$runtimeType(status: ${status.name}): $message';
}

/// The DNS exchange failed: an error rcode, a CNAME loop, chain or conflict,
/// a mismatched question, or a malformed or oversized response.
final class CsOpenAliasDnsException extends CsOpenAliasException {
  const CsOpenAliasDnsException(
    super.message, {
    required super.alias,
    super.cause,
    super.causeStackTrace,
  });
}

/// The connection, proxy, TLS or HTTP exchange failed, a deadline passed, or
/// the validator is unavailable. [timeout] is set when a deadline passed.
final class CsOpenAliasNetworkException extends CsOpenAliasException {
  final Duration? timeout;
  const CsOpenAliasNetworkException(
    super.message, {
    required super.alias,
    this.timeout,
    super.cause,
    super.causeStackTrace,
  });

  @override
  String toString() => timeout == null
      ? super.toString()
      : '$runtimeType(timeout: $timeout): $message';
}

/// The caller cancelled the lookup.
final class CsOpenAliasCancelledException extends CsOpenAliasException {
  const CsOpenAliasCancelledException(
    super.message, {
    required super.alias,
    super.cause,
    super.causeStackTrace,
  });
}
