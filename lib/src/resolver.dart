import 'dart:async';
import 'dart:convert';

import 'package:dnssec_resolver/dnssec_resolver.dart';
import 'package:doh_transport/doh_transport.dart';
import 'package:openalias/openalias.dart' as oa;

import 'exceptions.dart';
import 'models.dart';
import 'transport.dart';

const _application = 'xmr';

/// Lowercases [input] and turns `user@domain` into `user.domain`, or throws
/// [CsOpenAliasInvalidAliasException].
String normalizeOpenAlias(String input) {
  try {
    return oa.normalizeOpenAlias(input);
  } on oa.OpenAliasException catch (error, stack) {
    throw CsOpenAliasInvalidAliasException(
      error.message,
      cause: error,
      causeStackTrace: stack,
    );
  }
}

/// Looks up [alias] over DNS over HTTPS, validates the answer with DNSSEC on
/// the device and returns the recipient of its one `oa1:xmr` record.
///
/// Without [proxy] the lookup connects directly to the resolver; with it,
/// only through the proxy. A non-numeric proxy address or an invalid port
/// throws [ArgumentError]. Every other failure is a [CsOpenAliasException]
/// from the operation's result, and errors thrown by [isValidAddress]
/// propagate unchanged.
CsOpenAliasOperation<CsOpenAliasRecipient> resolveOpenAlias(
  String alias, {
  required bool Function(String address) isValidAddress,
  CsOpenAliasProxy? proxy,
}) => startOpenAliasLookup(alias, isValidAddress: isValidAddress, proxy: proxy);

/// Starts a DNSSEC lookup for [domain] over [port].
typedef SecureLookup =
    DnssecOperation<DnssecResult> Function(
      String domain,
      DnssecWireTransport port,
      Duration timeout,
    );

DnssecOperation<DnssecResult> dnssecLookup(
  String domain,
  DnssecWireTransport port,
  Duration timeout, {
  String? trustAnchors,
}) => DnssecResolver(
  transport: port,
  timeout: timeout,
  maxQueries: 64,
  trustAnchors: trustAnchors,
).startLookup(domain);

/// [resolveOpenAlias] with its transport and DNSSEC lookup injectable.
CsOpenAliasOperation<CsOpenAliasRecipient> startOpenAliasLookup(
  String alias, {
  required bool Function(String address) isValidAddress,
  CsOpenAliasProxy? proxy,
  LookupTransportFactory openTransport = openDohTransport,
  SecureLookup lookup = dnssecLookup,
}) {
  if (proxy != null) proxyAddress(proxy);
  final String domain;
  try {
    domain = normalizeOpenAlias(alias);
  } on CsOpenAliasInvalidAliasException catch (error) {
    return CsOpenAliasOperation.failed(error);
  }

  final transport = openTransport(proxy);
  final result = Completer<CsOpenAliasRecipient>();
  var done = false;

  void release() {
    done = true;
    try {
      transport.close().ignore();
    } catch (_) {}
  }

  void finish(Object outcome, [StackTrace? stack]) {
    if (done) return;
    release();
    if (outcome is CsOpenAliasRecipient) {
      result.complete(outcome);
    } else {
      result.completeError(outcome, stack);
    }
  }

  final DnssecOperation<DnssecResult> dns;
  try {
    dns = lookup(
      domain,
      DohDnssecPort(transport.wire, transport.endpoint),
      deadlinesFor(proxy).lookup,
    );
  } catch (_) {
    release();
    rethrow;
  }

  unawaited(
    dns.result.then(
      (answer) {
        if (done) return;
        try {
          finish(_recipient(domain, answer, isValidAddress));
        } catch (error, stack) {
          finish(mapLookupFailure(error, stack), stack);
        }
      },
      onError: (Object error, StackTrace stack) =>
          finish(mapLookupFailure(error, stack), stack),
    ),
  );

  return CsOpenAliasOperation(result.future, () {
    if (done) return;
    try {
      dns.cancel();
    } catch (_) {}
    finish(const CsOpenAliasCancelledException('OpenAlias lookup cancelled'));
  });
}

final _xmrPrefix = ascii.encode('oa1:$_application');

bool _isXmrRecord(List<int> bytes) {
  final length = _xmrPrefix.length;
  if (bytes.length < length) return false;
  for (var i = 0; i < length; i++) {
    if (bytes[i] != _xmrPrefix[i]) return false;
  }
  return bytes.length == length ||
      bytes[length] == 0x20 ||
      bytes[length] == 0x09;
}

CsOpenAliasRecipient _recipient(
  String domain,
  DnssecResult answer,
  bool Function(String address) isValidAddress,
) {
  if (answer.question != domain || answer.recordType != 16) {
    throw const CsOpenAliasDnsException('DNS answer is not for the alias');
  }
  final txt = answer.secureTxt();
  final records = <String>[];
  for (final record in txt) {
    if (record.name != answer.canonicalName) {
      throw const CsOpenAliasDnsException('TXT owner is not the alias');
    }
    if (!_isXmrRecord(record.bytes)) continue;
    try {
      records.add(utf8.decode(record.bytes));
    } on FormatException catch (error, stack) {
      throw CsOpenAliasInvalidRecordException(
        'OpenAlias record is not UTF-8',
        cause: error,
        causeStackTrace: stack,
      );
    }
  }
  final selected = oa.selectOpenAliasRecipient(
    domain: domain,
    records: records,
    application: _application,
    validateAddress: isValidAddress,
  );
  final ttl = [
    for (final record in txt) record.ttl,
    for (final alias in answer.aliases) alias.ttl,
  ].reduce((a, b) => a < b ? a : b);
  return CsOpenAliasRecipient(
    domain: domain,
    address: selected.address,
    application: selected.application,
    canonicalName: answer.canonicalName,
    // RFC 2181 section 8: a TTL with the most significant bit set is zero.
    ttl: ttl > 0x7fffffff ? 0 : ttl,
    fields: selected.record.fields,
  );
}

/// The facade leaf for a constituent failure, or [error] itself when it is
/// not one (a programmer error).
Object mapLookupFailure(Object error, StackTrace stack) => switch (error) {
  CsOpenAliasException() => error,
  oa.OpenAliasException() => _fromOpenAlias(error, stack),
  DnssecTransportException(:final DohTransportException cause) => _fromDoh(
    cause,
    error.causeStackTrace ?? stack,
  ),
  DnssecException() => _fromDnssec(error, stack),
  DohTransportException() => _fromDoh(error, stack),
  _ => error,
};

CsOpenAliasException _fromOpenAlias(
  oa.OpenAliasException error,
  StackTrace stack,
) {
  final message = error.message;
  return switch (error) {
    oa.OpenAliasInvalidNameException() => CsOpenAliasInvalidAliasException(
      message,
      cause: error,
      causeStackTrace: stack,
    ),
    oa.OpenAliasNoRecordException() => CsOpenAliasNoRecordException(
      message,
      cause: error,
      causeStackTrace: stack,
    ),
    oa.OpenAliasAmbiguousException() => CsOpenAliasAmbiguousException(
      message,
      cause: error,
      causeStackTrace: stack,
    ),
    oa.OpenAliasInvalidRecordException() ||
    oa.OpenAliasDuplicateFieldException() ||
    oa.OpenAliasInvalidAddressException() ||
    oa.OpenAliasUnsupportedFieldException() ||
    oa.OpenAliasLimitExceededException() => CsOpenAliasInvalidRecordException(
      message,
      cause: error,
      causeStackTrace: stack,
    ),
  };
}

CsOpenAliasException _fromDnssec(DnssecException error, StackTrace stack) {
  final message = error.message;
  return switch (error) {
    DnssecValidationException(:final status) => CsOpenAliasDnssecException(
      message,
      status: switch (status) {
        DnssecStatus.insecure => CsOpenAliasDnssecStatus.insecure,
        DnssecStatus.bogus => CsOpenAliasDnssecStatus.bogus,
        DnssecStatus.indeterminate ||
        DnssecStatus.secure => CsOpenAliasDnssecStatus.indeterminate,
      },
      cause: error,
      causeStackTrace: stack,
    ),
    DnssecNoRecordsException() => CsOpenAliasNoRecordException(
      message,
      cause: error,
      causeStackTrace: stack,
    ),
    DnssecInvalidNameException() => CsOpenAliasInvalidAliasException(
      message,
      cause: error,
      causeStackTrace: stack,
    ),
    DnssecAliasAmbiguousException() ||
    DnssecAliasTooLongException() ||
    DnssecAliasLoopException() ||
    DnssecQueryFailedException() ||
    DnssecQuestionMismatchException() ||
    DnssecResponseTooLargeException() ||
    DnssecMalformedResponseException() => CsOpenAliasDnsException(
      message,
      cause: error,
      causeStackTrace: stack,
    ),
    DnssecTimeoutException(:final timeout) => CsOpenAliasNetworkException(
      message,
      timeout: timeout,
      cause: error,
      causeStackTrace: stack,
    ),
    DnssecTransportException() ||
    DnssecUnavailableException() => CsOpenAliasNetworkException(
      message,
      cause: error,
      causeStackTrace: stack,
    ),
    DnssecCancelledException() => CsOpenAliasCancelledException(
      message,
      cause: error,
      causeStackTrace: stack,
    ),
  };
}

CsOpenAliasException _fromDoh(DohTransportException error, StackTrace stack) {
  final message = error.message;
  return switch (error) {
    DohInvalidQueryException() ||
    DohMalformedResponseException() ||
    DohResponseTooLargeException() ||
    DohQuestionMismatchException() => CsOpenAliasDnsException(
      message,
      cause: error,
      causeStackTrace: stack,
    ),
    DohRequestTimeoutException(:final timeout) ||
    DohConnectionTimeoutException(
      :final timeout,
    ) => CsOpenAliasNetworkException(
      message,
      timeout: timeout,
      cause: error,
      causeStackTrace: stack,
    ),
    DohCancelledException(reason: DohCancellationReason.redirectRefused) ||
    DohHttpStatusException() ||
    DohConnectionException() ||
    DohQueueFullException() => CsOpenAliasNetworkException(
      message,
      cause: error,
      causeStackTrace: stack,
    ),
    DohCancelledException() => CsOpenAliasCancelledException(
      message,
      cause: error,
      causeStackTrace: stack,
    ),
  };
}
