enum CsOpenAliasError {
  invalidName,
  invalidRecord,
  limitExceeded,
  duplicateField,
  unsupportedField,
  invalidAddress,
  ambiguous,
  noRecord,
  noDnsRecord,
  dnsInvalidName,
  dnsAliasAmbiguous,
  dnsAliasTooLong,
  dnsAliasLoop,
  dnsQueryFailed,
  questionMismatch,
  privacyRevoked,
  responseTooLarge,
  malformedResponse,
  httpStatus,
  network,
  dnssec,
  unavailable,
  cancelled,
  timedOut,
}

sealed class CsOpenAliasException implements Exception {
  final CsOpenAliasError code;
  final String message;
  final Object? cause;
  final StackTrace? causeStackTrace;

  const CsOpenAliasException(
    this.code,
    this.message, {
    this.cause,
    this.causeStackTrace,
  });

  @override
  String toString() {
    final details = switch (this) {
      CsOpenAliasHttpException(:final statusCode) =>
        ', statusCode: $statusCode',
      CsOpenAliasTimeoutException(:final timeout, :final source) =>
        ', timeout: $timeout, source: ${source.name}',
      CsOpenAliasResponseTooLargeException(:final limitBytes)
          when limitBytes != null =>
        ', limitBytes: $limitBytes',
      CsOpenAliasLimitExceededException(:final maximum, :final actual) =>
        '${maximum == null ? '' : ', maximum: $maximum'}'
            '${actual == null ? '' : ', actual: $actual'}',
      CsOpenAliasDnsQueryFailedException(:final rcode) when rcode != null =>
        ', rcode: $rcode',
      CsOpenAliasDnssecException(:final status) when status != null =>
        ', status: ${status.name}',
      _ => '',
    };
    return '$runtimeType(code: ${code.name}$details): $message';
  }
}

final class CsOpenAliasInvalidNameException extends CsOpenAliasException {
  const CsOpenAliasInvalidNameException(
    String message, {
    super.cause,
    super.causeStackTrace,
  }) : super(CsOpenAliasError.invalidName, message);
}

final class CsOpenAliasInvalidRecordException extends CsOpenAliasException {
  const CsOpenAliasInvalidRecordException(
    String message, {
    super.cause,
    super.causeStackTrace,
  }) : super(CsOpenAliasError.invalidRecord, message);
}

final class CsOpenAliasLimitExceededException extends CsOpenAliasException {
  final int? maximum;
  final int? actual;

  const CsOpenAliasLimitExceededException(
    String message, {
    this.maximum,
    this.actual,
    super.cause,
    super.causeStackTrace,
  }) : super(CsOpenAliasError.limitExceeded, message);
}

final class CsOpenAliasDuplicateFieldException extends CsOpenAliasException {
  const CsOpenAliasDuplicateFieldException(
    String message, {
    super.cause,
    super.causeStackTrace,
  }) : super(CsOpenAliasError.duplicateField, message);
}

final class CsOpenAliasUnsupportedFieldException extends CsOpenAliasException {
  const CsOpenAliasUnsupportedFieldException(
    String message, {
    super.cause,
    super.causeStackTrace,
  }) : super(CsOpenAliasError.unsupportedField, message);
}

final class CsOpenAliasInvalidAddressException extends CsOpenAliasException {
  const CsOpenAliasInvalidAddressException(
    String message, {
    super.cause,
    super.causeStackTrace,
  }) : super(CsOpenAliasError.invalidAddress, message);
}

final class CsOpenAliasAmbiguousException extends CsOpenAliasException {
  const CsOpenAliasAmbiguousException(
    String message, {
    super.cause,
    super.causeStackTrace,
  }) : super(CsOpenAliasError.ambiguous, message);
}

final class CsOpenAliasNoRecordException extends CsOpenAliasException {
  const CsOpenAliasNoRecordException(
    String message, {
    super.cause,
    super.causeStackTrace,
  }) : super(CsOpenAliasError.noRecord, message);
}

final class CsOpenAliasDnsNoRecordException extends CsOpenAliasException {
  const CsOpenAliasDnsNoRecordException(
    String message, {
    super.cause,
    super.causeStackTrace,
  }) : super(CsOpenAliasError.noDnsRecord, message);
}

final class CsOpenAliasDnsInvalidNameException extends CsOpenAliasException {
  const CsOpenAliasDnsInvalidNameException(
    String message, {
    super.cause,
    super.causeStackTrace,
  }) : super(CsOpenAliasError.dnsInvalidName, message);
}

final class CsOpenAliasDnsAliasAmbiguousException extends CsOpenAliasException {
  const CsOpenAliasDnsAliasAmbiguousException(
    String message, {
    super.cause,
    super.causeStackTrace,
  }) : super(CsOpenAliasError.dnsAliasAmbiguous, message);
}

final class CsOpenAliasDnsAliasTooLongException extends CsOpenAliasException {
  const CsOpenAliasDnsAliasTooLongException(
    String message, {
    super.cause,
    super.causeStackTrace,
  }) : super(CsOpenAliasError.dnsAliasTooLong, message);
}

final class CsOpenAliasDnsAliasLoopException extends CsOpenAliasException {
  const CsOpenAliasDnsAliasLoopException(
    String message, {
    super.cause,
    super.causeStackTrace,
  }) : super(CsOpenAliasError.dnsAliasLoop, message);
}

final class CsOpenAliasDnsQueryFailedException extends CsOpenAliasException {
  final int? rcode;

  const CsOpenAliasDnsQueryFailedException(
    String message, {
    this.rcode,
    super.cause,
    super.causeStackTrace,
  }) : super(CsOpenAliasError.dnsQueryFailed, message);
}

final class CsOpenAliasQuestionMismatchException extends CsOpenAliasException {
  const CsOpenAliasQuestionMismatchException(
    String message, {
    super.cause,
    super.causeStackTrace,
  }) : super(CsOpenAliasError.questionMismatch, message);
}

final class CsOpenAliasPrivacyException extends CsOpenAliasException {
  const CsOpenAliasPrivacyException(
    String message, {
    super.cause,
    super.causeStackTrace,
  }) : super(CsOpenAliasError.privacyRevoked, message);
}

final class CsOpenAliasResponseTooLargeException extends CsOpenAliasException {
  final int? limitBytes;

  const CsOpenAliasResponseTooLargeException(
    String message, {
    this.limitBytes,
    super.cause,
    super.causeStackTrace,
  }) : super(CsOpenAliasError.responseTooLarge, message);
}

final class CsOpenAliasMalformedResponseException extends CsOpenAliasException {
  const CsOpenAliasMalformedResponseException(
    String message, {
    super.cause,
    super.causeStackTrace,
  }) : super(CsOpenAliasError.malformedResponse, message);
}

final class CsOpenAliasHttpException extends CsOpenAliasException {
  final int statusCode;

  const CsOpenAliasHttpException(
    String message, {
    required this.statusCode,
    super.cause,
    super.causeStackTrace,
  }) : super(CsOpenAliasError.httpStatus, message);
}

final class CsOpenAliasNetworkException extends CsOpenAliasException {
  const CsOpenAliasNetworkException(
    String message, {
    super.cause,
    super.causeStackTrace,
  }) : super(CsOpenAliasError.network, message);
}

enum CsOpenAliasDnssecStatus { secure, insecure, bogus, indeterminate }

final class CsOpenAliasDnssecException extends CsOpenAliasException {
  final CsOpenAliasDnssecStatus? status;

  const CsOpenAliasDnssecException(
    String message, {
    this.status,
    super.cause,
    super.causeStackTrace,
  }) : super(CsOpenAliasError.dnssec, message);
}

final class CsOpenAliasUnavailableException extends CsOpenAliasException {
  const CsOpenAliasUnavailableException(
    String message, {
    super.cause,
    super.causeStackTrace,
  }) : super(CsOpenAliasError.unavailable, message);
}

final class CsOpenAliasCancelledException extends CsOpenAliasException {
  const CsOpenAliasCancelledException(
    String message, {
    super.cause,
    super.causeStackTrace,
  }) : super(CsOpenAliasError.cancelled, message);
}

enum CsOpenAliasTimeoutSource { lookup, transportRequest, transportConnection }

final class CsOpenAliasTimeoutException extends CsOpenAliasException {
  final Duration timeout;
  final CsOpenAliasTimeoutSource source;

  const CsOpenAliasTimeoutException(
    String message, {
    required this.timeout,
    required this.source,
    super.cause,
    super.causeStackTrace,
  }) : super(CsOpenAliasError.timedOut, message);
}
