import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:dnssec_resolver/dnssec_resolver.dart';
import 'package:doh_transport/doh_transport_io.dart';
import 'package:openalias/openalias.dart' as oa;

import 'exceptions.dart';
import 'models.dart';

final _application = RegExp(r'^[a-z0-9][a-z0-9_-]*$');

String normalizeCsOpenAlias(String input) {
  try {
    return oa.normalizeOpenAlias(input);
  } on oa.OpenAliasException catch (error, stack) {
    throw _mapOpenAlias(error, stack);
  }
}

final class CsOpenAliasResolver {
  final CsOpenAliasNetworkOptions network;
  final CsOpenAliasNetworkFactory _networkFactory;
  final Duration lookupTimeout;
  final int maxQueries;
  final String? trustAnchors;
  final String application;
  final bool Function(String) validateAddress;
  final bool Function() _isAllowed;

  CsOpenAliasResolver({
    required this.validateAddress,
    CsOpenAliasNetworkOptions? network,
    CsOpenAliasNetworkFactory? networkFactory,
    bool Function()? isAllowed,
    this.lookupTimeout = const Duration(seconds: 20),
    this.maxQueries = 64,
    this.trustAnchors,
    this.application = 'xmr',
  }) : network = network ?? CsOpenAliasNetworkOptions(),
       _networkFactory = networkFactory ?? const DohOpenAliasNetworkFactory(),
       _isAllowed = isAllowed ?? _alwaysAllowed {
    _validateConfiguration();
  }

  Future<CsOpenAliasRecipient> resolve(String input) =>
      startResolve(input).result;

  CsOpenAliasOperation<CsOpenAliasRecipient> startResolve(String input) {
    final permission = _Permission(_isAllowed);
    late final String domain;
    try {
      domain = normalizeCsOpenAlias(input);
    } on CsOpenAliasException catch (error) {
      return CsOpenAliasOperation.failed(error);
    } catch (error, stack) {
      return CsOpenAliasOperation.failed(
        CsOpenAliasInvalidNameException(
          'Invalid OpenAlias name',
          cause: error,
          causeStackTrace: stack,
        ),
      );
    }

    if (!permission.check()) {
      return CsOpenAliasOperation.failed(_privacyRevoked());
    }

    late final CsOpenAliasNetworkSession session;
    try {
      session = _networkFactory.create(network);
    } catch (error, stack) {
      return CsOpenAliasOperation.failed(
        CsOpenAliasNetworkException(
          'Unable to create the DNS transport',
          cause: error,
          causeStackTrace: stack,
        ),
      );
    }

    final result = Completer<CsOpenAliasRecipient>();
    DnssecOperation<DnssecResult>? dnsOperation;
    var finished = false;

    void finish({
      CsOpenAliasRecipient? value,
      Object? error,
      StackTrace? stack,
    }) {
      if (finished) return;
      finished = true;
      try {
        unawaited(session.close().catchError((_) {}));
      } catch (_) {}
      if (value != null) {
        result.complete(value);
      } else {
        result.completeError(
          error ?? const CsOpenAliasUnavailableException('Lookup failed'),
          stack,
        );
      }
    }

    try {
      final resolver = DnssecResolver(
        transport: _DnssecTransportAdapter(session, permission.check),
        endpoint: network.endpoint,
        timeout: lookupTimeout,
        maxQueries: maxQueries,
        trustAnchors: trustAnchors,
      );
      dnsOperation = resolver.startLookup(domain);
      dnsOperation.result
          .then((dns) async {
            if (!permission.check()) throw _privacyRevoked();
            final secureTxt = dns.secureTxt();
            final answer = oa.TxtAnswer(
              question: dns.question,
              records: [
                for (final record in secureTxt)
                  List<int>.unmodifiable(record.bytes),
              ],
              validator: DnssecResolver.validator,
            );
            final recipient = await oa.OpenAliasResolver(
              resolver: _FixedTxtResolver(answer),
              application: application,
              validateAddress: validateAddress,
              trustedValidators: [DnssecResolver.validator],
            ).resolve(domain);
            if (!permission.check()) throw _privacyRevoked();
            return CsOpenAliasRecipient(
              domain: recipient.domain,
              address: recipient.address,
              application: recipient.application ?? application,
              canonicalName: dns.canonicalName,
              ttl: [
                ...secureTxt.map((record) => record.ttl),
                ...dns.aliases.map((record) => record.ttl),
              ].reduce((left, right) => left < right ? left : right),
              fields: recipient.record?.fields ?? const {},
            );
          })
          .then(
            (value) => finish(value: value),
            onError: (Object error, StackTrace stack) => finish(
              error: permission.revoked
                  ? _privacyRevoked()
                  : _mapFailure(error, stack),
              stack: stack,
            ),
          );
    } catch (error, stack) {
      finish(error: _mapFailure(error, stack), stack: stack);
    }

    return CsOpenAliasOperation(result.future, () {
      if (finished) return;
      try {
        dnsOperation?.cancel();
      } catch (_) {}
      finish(
        error: const CsOpenAliasCancelledException(
          'OpenAlias lookup cancelled',
        ),
      );
    });
  }

  void _validateConfiguration() {
    if (!_application.hasMatch(application)) {
      throw ArgumentError.value(application, 'application');
    }
    final anchors = trustAnchors;
    if (anchors != null &&
        (anchors.trim().isEmpty || utf8.encode(anchors).length > 60000)) {
      throw ArgumentError.value(
        trustAnchors,
        'trustAnchors',
        'Expected nonblank DNSKEY text of at most 60000 UTF-8 bytes',
      );
    }
    var endpointPortValid = false;
    try {
      endpointPortValid =
          network.endpoint.port >= 1 && network.endpoint.port <= 65535;
    } on FormatException {
      // An unreadable/out-of-range port is rejected by endpointPortValid.
    }
    if (network.endpoint.scheme != 'https' ||
        network.endpoint.host.isEmpty ||
        network.endpoint.userInfo.isNotEmpty ||
        network.endpoint.hasFragment ||
        !endpointPortValid ||
        InternetAddress.tryParse(network.destinationAddress) == null ||
        network.connectionTimeout <= Duration.zero ||
        network.requestTimeout <= Duration.zero ||
        network.idleTimeout <= Duration.zero ||
        network.maxConcurrentRequests < 1 ||
        network.maxQueuedRequests < 0 ||
        lookupTimeout <= Duration.zero ||
        lookupTimeout > const Duration(minutes: 2) ||
        maxQueries < 1 ||
        maxQueries > 128) {
      throw ArgumentError('Invalid OpenAlias network configuration');
    }
    final proxy = network.proxy;
    if (proxy != null &&
        (InternetAddress.tryParse(proxy.address) == null ||
            proxy.port < 1 ||
            proxy.port > 65535)) {
      throw ArgumentError(
        'A numeric proxy address and valid port are required',
      );
    }
  }
}

bool _alwaysAllowed() => true;

final class _Permission {
  final bool Function() allowed;
  bool revoked = false;

  _Permission(this.allowed);

  bool check() {
    if (revoked) return false;
    try {
      if (allowed()) return true;
    } catch (_) {}
    revoked = true;
    return false;
  }
}

CsOpenAliasPrivacyException _privacyRevoked() =>
    const CsOpenAliasPrivacyException(
      'Privacy settings changed. Please look up the alias again.',
    );

final class _FixedTxtResolver implements oa.ValidatingTxtResolver {
  final oa.TxtAnswer answer;

  const _FixedTxtResolver(this.answer);

  @override
  Future<oa.TxtAnswer> lookupTxt(String name) async => answer;
}

final class _DnssecTransportAdapter implements DnssecWireTransport {
  final CsOpenAliasNetworkSession session;
  final bool Function() allowed;

  const _DnssecTransportAdapter(this.session, this.allowed);

  @override
  DnssecOperation<DnssecWireResponse> startWire(
    Uri endpoint,
    List<int> query, {
    required int maxResponseBytes,
  }) {
    if (!allowed()) {
      return DnssecOperation.failed(
        const DnssecCancelledException('DNS privacy permission was revoked'),
      );
    }
    try {
      final operation = session.startWire(
        endpoint,
        query,
        maxResponseBytes: maxResponseBytes,
      );
      return DnssecOperation(
        operation.result
            .then((response) {
              if (!allowed()) throw _privacyRevoked();
              return DnssecWireResponse(
                response.statusCode,
                response.body,
                age: response.age,
              );
            })
            .catchError((Object error, StackTrace stack) {
              throw _toDnssecFailure(error, stack);
            }),
        operation.cancel,
      );
    } catch (error, stack) {
      return DnssecOperation.failed(_toDnssecFailure(error, stack));
    }
  }
}

DnssecException _toDnssecFailure(Object error, StackTrace stack) {
  if (error is DnssecException) return error;
  return switch (error) {
    CsOpenAliasPrivacyException() || CsOpenAliasCancelledException() =>
      const DnssecCancelledException('DNS exchange cancelled'),
    CsOpenAliasTimeoutException() => DnssecTransportException(
      'DNS transport timed out',
      cause: error,
      causeStackTrace: stack,
    ),
    CsOpenAliasHttpException(:final statusCode) => DnssecTransportException(
      'DNS HTTPS request failed',
      httpStatus: statusCode,
      cause: error,
      causeStackTrace: stack,
    ),
    CsOpenAliasResponseTooLargeException() =>
      const DnssecResponseTooLargeException('DNS body exceeds limit'),
    CsOpenAliasQuestionMismatchException() =>
      const DnssecQuestionMismatchException('DNS response question mismatch'),
    CsOpenAliasMalformedResponseException() =>
      const DnssecMalformedResponseException('Malformed DNS response'),
    _ => DnssecTransportException(
      'DNS transport failed',
      cause: error,
      causeStackTrace: stack,
    ),
  };
}

Object _mapFailure(Object error, StackTrace stack) {
  if (error is CsOpenAliasException) return error;
  if (error is oa.OpenAliasException) return _mapOpenAlias(error, stack);
  if (error is DnssecException) return _mapDnssec(error, stack);
  return error;
}

CsOpenAliasException _mapOpenAlias(
  oa.OpenAliasException error,
  StackTrace stack,
) => switch (error) {
  oa.OpenAliasInvalidNameException() => CsOpenAliasInvalidNameException(
    error.message,
    cause: error,
    causeStackTrace: stack,
  ),
  oa.OpenAliasInvalidRecordException() => CsOpenAliasInvalidRecordException(
    error.message,
    cause: error,
    causeStackTrace: stack,
  ),
  oa.OpenAliasLimitExceededException(:final maximum, :final actual) =>
    CsOpenAliasLimitExceededException(
      error.message,
      maximum: maximum,
      actual: actual,
      cause: error,
      causeStackTrace: stack,
    ),
  oa.OpenAliasDuplicateFieldException() => CsOpenAliasDuplicateFieldException(
    error.message,
    cause: error,
    causeStackTrace: stack,
  ),
  oa.OpenAliasUnsupportedFieldException() =>
    CsOpenAliasUnsupportedFieldException(
      error.message,
      cause: error,
      causeStackTrace: stack,
    ),
  oa.OpenAliasInvalidAddressException() => CsOpenAliasInvalidAddressException(
    error.message,
    cause: error,
    causeStackTrace: stack,
  ),
  oa.OpenAliasAmbiguousException() => CsOpenAliasAmbiguousException(
    error.message,
    cause: error,
    causeStackTrace: stack,
  ),
  oa.OpenAliasNoRecordException() => CsOpenAliasNoRecordException(
    error.message,
    cause: error,
    causeStackTrace: stack,
  ),
  oa.OpenAliasQuestionMismatchException() =>
    CsOpenAliasQuestionMismatchException(
      error.message,
      cause: error,
      causeStackTrace: stack,
    ),
  oa.OpenAliasAuthenticationUnavailableException() =>
    CsOpenAliasAuthenticationException(
      error.message,
      cause: error,
      causeStackTrace: stack,
    ),
};

CsOpenAliasException _mapDnssec(DnssecException error, StackTrace stack) =>
    switch (error) {
      DnssecInvalidNameException() => CsOpenAliasDnsInvalidNameException(
        error.message,
        cause: error,
        causeStackTrace: stack,
      ),
      DnssecNoRecordsException() => CsOpenAliasDnsNoRecordException(
        error.message,
        cause: error,
        causeStackTrace: stack,
      ),
      DnssecAliasAmbiguousException() => CsOpenAliasDnsAliasAmbiguousException(
        error.message,
        cause: error,
        causeStackTrace: stack,
      ),
      DnssecAliasLoopException() => CsOpenAliasDnsAliasLoopException(
        error.message,
        cause: error,
        causeStackTrace: stack,
      ),
      DnssecAliasTooLongException() => CsOpenAliasDnsAliasTooLongException(
        error.message,
        cause: error,
        causeStackTrace: stack,
      ),
      DnssecQuestionMismatchException() => CsOpenAliasQuestionMismatchException(
        error.message,
        cause: error,
        causeStackTrace: stack,
      ),
      DnssecResponseTooLargeException() => CsOpenAliasResponseTooLargeException(
        error.message,
        limitBytes: 65535,
        cause: error,
        causeStackTrace: stack,
      ),
      DnssecMalformedResponseException() =>
        CsOpenAliasMalformedResponseException(
          error.message,
          cause: error,
          causeStackTrace: stack,
        ),
      DnssecTransportException(:final cause)
          when cause is CsOpenAliasException =>
        cause,
      DnssecTransportException(:final httpStatus) when httpStatus != null =>
        CsOpenAliasHttpException(
          error.message,
          statusCode: httpStatus,
          cause: error,
          causeStackTrace: stack,
        ),
      DnssecTransportException() => CsOpenAliasNetworkException(
        error.message,
        cause: error,
        causeStackTrace: stack,
      ),
      DnssecCancelledException() => CsOpenAliasCancelledException(
        error.message,
        cause: error,
        causeStackTrace: stack,
      ),
      DnssecTimeoutException(:final timeout) => CsOpenAliasTimeoutException(
        error.message,
        timeout: timeout,
        source: CsOpenAliasTimeoutSource.lookup,
        cause: error,
        causeStackTrace: stack,
      ),
      DnssecValidationException(:final status) => CsOpenAliasDnssecException(
        error.message,
        status: status == null ? null : _mapDnssecStatus(status),
        cause: error,
        causeStackTrace: stack,
      ),
      DnssecQueryFailedException(:final rcode) =>
        CsOpenAliasDnsQueryFailedException(
          error.message,
          rcode: rcode,
          cause: error,
          causeStackTrace: stack,
        ),
      DnssecUnavailableException() => CsOpenAliasUnavailableException(
        error.message,
        cause: error,
        causeStackTrace: stack,
      ),
    };

CsOpenAliasDnssecStatus _mapDnssecStatus(DnssecStatus status) =>
    switch (status) {
      DnssecStatus.secure => CsOpenAliasDnssecStatus.secure,
      DnssecStatus.insecure => CsOpenAliasDnssecStatus.insecure,
      DnssecStatus.bogus => CsOpenAliasDnssecStatus.bogus,
      DnssecStatus.indeterminate => CsOpenAliasDnssecStatus.indeterminate,
    };

final class DohOpenAliasNetworkFactory implements CsOpenAliasNetworkFactory {
  const DohOpenAliasNetworkFactory();

  @override
  CsOpenAliasNetworkSession create(CsOpenAliasNetworkOptions options) {
    final destination = InternetAddress.tryParse(options.destinationAddress)!;
    final proxy = options.proxy;
    return _DohNetworkSession(
      IoDohTransport(
        destination: destination,
        securityContext: options.securityContext,
        proxy: proxy == null
            ? null
            : SocksProxy(
                InternetAddress.tryParse(proxy.address)!,
                proxy.port,
                credentials: SocksCredentials.isolation(_isolationToken()),
              ),
        connectionTimeout: options.connectionTimeout,
        requestTimeout: options.requestTimeout,
        idleTimeout: options.idleTimeout,
        maxConcurrentRequests: options.maxConcurrentRequests,
        maxQueuedRequests: options.maxQueuedRequests,
        padQueries: options.padQueries,
        reuseConnections: options.reuseConnections,
        httpClientFactory: options.httpClientFactory,
      ),
    );
  }
}

final class _DohNetworkSession implements CsOpenAliasNetworkSession {
  final IoDohTransport transport;

  const _DohNetworkSession(this.transport);

  @override
  CsOpenAliasOperation<CsOpenAliasWireResponse> startWire(
    Uri endpoint,
    List<int> query, {
    required int maxResponseBytes,
  }) {
    try {
      final operation = transport.startWire(
        endpoint,
        query,
        maxResponseBytes: maxResponseBytes,
      );
      return CsOpenAliasOperation(
        operation.result.then(
          (response) => CsOpenAliasWireResponse(
            response.statusCode,
            response.body,
            age: response.age,
          ),
          onError: (Object error, StackTrace stack) =>
              throw _mapDohFailure(error, stack),
        ),
        operation.cancel,
      );
    } catch (error, stack) {
      return CsOpenAliasOperation.failed(_mapDohFailure(error, stack));
    }
  }

  @override
  Future<void> close() => transport.close();
}

CsOpenAliasException _mapDohFailure(Object error, StackTrace stack) =>
    switch (error) {
      DohQuestionMismatchException() => CsOpenAliasQuestionMismatchException(
        error.message,
        cause: error,
        causeStackTrace: stack,
      ),
      DohResponseTooLargeException(:final limitBytes) =>
        CsOpenAliasResponseTooLargeException(
          error.message,
          limitBytes: limitBytes,
          cause: error,
          causeStackTrace: stack,
        ),
      DohMalformedResponseException() ||
      DohInvalidQueryException() ||
      DohInvalidNameException() => CsOpenAliasMalformedResponseException(
        (error as DohTransportException).message,
        cause: error,
        causeStackTrace: stack,
      ),
      DohHttpStatusException(:final statusCode) => CsOpenAliasHttpException(
        error.message,
        statusCode: statusCode,
        cause: error,
        causeStackTrace: stack,
      ),
      DohRequestTimeoutException(:final timeout) => CsOpenAliasTimeoutException(
        error.message,
        timeout: timeout,
        source: CsOpenAliasTimeoutSource.transportRequest,
        cause: error,
        causeStackTrace: stack,
      ),
      DohConnectionTimeoutException(:final timeout) =>
        CsOpenAliasTimeoutException(
          error.message,
          timeout: timeout,
          source: CsOpenAliasTimeoutSource.transportConnection,
          cause: error,
          causeStackTrace: stack,
        ),
      DohCancelledException() => CsOpenAliasCancelledException(
        error.message,
        cause: error,
        causeStackTrace: stack,
      ),
      DohConnectionException() ||
      DohQueueFullException() => CsOpenAliasNetworkException(
        (error as DohTransportException).message,
        cause: error,
        causeStackTrace: stack,
      ),
      _ => CsOpenAliasNetworkException(
        'DNS transport failed',
        cause: error,
        causeStackTrace: stack,
      ),
    };

String _isolationToken() {
  final random = Random.secure();
  return List<String>.generate(
    16,
    (_) => random.nextInt(256).toRadixString(16).padLeft(2, '0'),
    growable: false,
  ).join();
}
