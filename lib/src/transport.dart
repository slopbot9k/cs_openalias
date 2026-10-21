import 'dart:io';
import 'dart:math';

import 'package:dnssec_resolver/dnssec_resolver.dart';
import 'package:doh_transport/doh_transport_io.dart';

import 'models.dart';

typedef Deadlines = ({Duration connection, Duration request, Duration lookup});

const directDeadlines = (
  connection: Duration(seconds: 5),
  request: Duration(seconds: 12),
  lookup: Duration(seconds: 20),
);
const proxiedDeadlines = (
  connection: Duration(seconds: 10),
  request: Duration(seconds: 20),
  lookup: Duration(seconds: 40),
);

Deadlines deadlinesFor(CsOpenAliasProxy? proxy) =>
    proxy == null ? directDeadlines : proxiedDeadlines;

typedef ResolverTarget = ({Uri endpoint, InternetAddress destination});

// One record: the numeric destination must serve the endpoint's certificate.
final ResolverTarget defaultResolver = (
  endpoint: Uri.https('dns.google', '/dns-query'),
  destination: InternetAddress('8.8.8.8'),
);

/// The network one lookup owns: where its queries go and how to release it.
typedef LookupTransport = ({
  DohWireTransport wire,
  Uri endpoint,
  void Function() close,
});

typedef LookupTransportFactory =
    LookupTransport Function(CsOpenAliasProxy? proxy);

/// Throws [ArgumentError] unless [proxy] has a numeric address and a port.
InternetAddress proxyAddress(CsOpenAliasProxy proxy) {
  final address = InternetAddress.tryParse(proxy.address);
  if (address == null) {
    throw ArgumentError.value(
      proxy.address,
      'proxy.address',
      'Expected a numeric IP address',
    );
  }
  if (proxy.port < 1 || proxy.port > 65535) {
    throw ArgumentError.value(proxy.port, 'proxy.port');
  }
  return address;
}

/// A fresh [IoDohTransport] for one lookup. [resolver] and [securityContext]
/// exist for loopback integration tests.
LookupTransport openDohTransport(
  CsOpenAliasProxy? proxy, {
  ResolverTarget? resolver,
  SecurityContext? securityContext,
}) {
  final (:endpoint, :destination) = resolver ?? defaultResolver;
  final deadlines = deadlinesFor(proxy);
  final transport = IoDohTransport(
    proxy: proxy == null
        ? null
        : DohSocksProxy(
            proxyAddress(proxy),
            proxy.port,
            isolationToken: isolationToken(),
          ),
    destination: destination,
    securityContext: securityContext,
    connectionTimeout: deadlines.connection,
    requestTimeout: deadlines.request,
    padQueries: true,
    // The transport, and with a proxy its credentials, belong to one lookup.
    reuseConnections: true,
  );
  return (wire: transport, endpoint: endpoint, close: transport.close);
}

String isolationToken() {
  final random = Random.secure();
  return [
    for (var i = 0; i < 16; i++)
      random.nextInt(256).toRadixString(16).padLeft(2, '0'),
  ].join();
}

/// dnssec_resolver's port on a DoH wire transport. Transport failures pass
/// through unchanged; the resolver wraps them in [DnssecTransportException].
final class DohDnssecPort implements DnssecWireTransport {
  final DohWireTransport _transport;
  final Uri _endpoint;

  DohDnssecPort(this._transport, this._endpoint);

  @override
  DnssecOperation<DnssecWireResponse> startWire(
    List<int> query, {
    required int maxResponseBytes,
  }) {
    final operation = _transport.startWire(
      _endpoint,
      query,
      maxResponseBytes: maxResponseBytes,
    );
    return DnssecOperation(
      operation.result.then(
        (response) => DnssecWireResponse(response.body, age: response.age),
      ),
      operation.cancel,
    );
  }
}
