import 'dart:async';
import 'dart:io';

import 'exceptions.dart';

final class CsOpenAliasOperation<T> {
  final Future<T> result;
  final void Function() cancel;

  CsOpenAliasOperation(this.result, this.cancel) {
    result.ignore();
  }

  factory CsOpenAliasOperation.failed(CsOpenAliasException error) =>
      CsOpenAliasOperation(Future<T>.error(error), () {});
}

final class CsOpenAliasRecipient {
  final String domain;
  final String address;
  final String application;
  final String canonicalName;
  final int ttl;
  final Map<String, String> fields;

  CsOpenAliasRecipient({
    required this.domain,
    required this.address,
    required this.application,
    required this.canonicalName,
    required this.ttl,
    required Map<String, String> fields,
  }) : fields = Map<String, String>.unmodifiable(fields) {
    if (ttl < 0 || ttl > 0x7fffffff) {
      throw ArgumentError.value(ttl, 'ttl');
    }
  }
}

final class CsOpenAliasProxy {
  final String address;
  final int port;

  const CsOpenAliasProxy({required this.address, required this.port});
}

final class CsOpenAliasNetworkOptions {
  final Uri endpoint;
  final String destinationAddress;
  final CsOpenAliasProxy? proxy;
  final Duration connectionTimeout;
  final Duration requestTimeout;
  final Duration idleTimeout;
  final int maxConcurrentRequests;
  final int maxQueuedRequests;
  final bool padQueries;
  final bool reuseConnections;

  /// Optional trust store for embedding/tests. The endpoint hostname is still
  /// used for TLS verification; this never permits a certificate bypass.
  final SecurityContext? securityContext;

  /// Test/embedding client seam. A custom client bypasses the default
  /// transport's socket, TLS, numeric-destination, and proxy guarantees; its
  /// owner must provide and test equivalent guarantees.
  final HttpClient Function(SecurityContext? context)? httpClientFactory;

  CsOpenAliasNetworkOptions({
    Uri? endpoint,
    this.destinationAddress = '8.8.8.8',
    this.proxy,
    this.connectionTimeout = const Duration(seconds: 5),
    this.requestTimeout = const Duration(seconds: 12),
    this.idleTimeout = const Duration(seconds: 5),
    this.maxConcurrentRequests = 8,
    this.maxQueuedRequests = 64,
    this.padQueries = true,
    this.reuseConnections = true,
    this.securityContext,
    this.httpClientFactory,
  }) : endpoint = endpoint ?? Uri.https('dns.google', '/dns-query');
}

final class CsOpenAliasWireResponse {
  final int statusCode;
  final List<int> body;
  final Duration age;

  CsOpenAliasWireResponse(
    this.statusCode,
    List<int> body, {
    this.age = Duration.zero,
  }) : body = List<int>.unmodifiable(body) {
    if (statusCode < 100 || statusCode > 599) {
      throw ArgumentError.value(statusCode, 'statusCode');
    }
    if (age < Duration.zero) throw ArgumentError.value(age, 'age');
    if (this.body.any((byte) => byte < 0 || byte > 255)) {
      throw ArgumentError.value(body, 'body', 'DNS body must contain octets');
    }
  }
}

abstract interface class CsOpenAliasNetworkSession {
  CsOpenAliasOperation<CsOpenAliasWireResponse> startWire(
    Uri endpoint,
    List<int> query, {
    required int maxResponseBytes,
  });

  Future<void> close();
}

abstract interface class CsOpenAliasNetworkFactory {
  CsOpenAliasNetworkSession create(CsOpenAliasNetworkOptions options);
}
