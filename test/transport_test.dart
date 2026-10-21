import 'dart:io';

import 'package:cs_openalias/cs_openalias.dart';
import 'package:cs_openalias/src/transport.dart';
import 'package:doh_transport/doh_transport_io.dart';
import 'package:test/test.dart';

import 'support/fakes.dart';

void main() {
  IoDohTransport io(LookupTransport transport) {
    addTearDown(transport.close);
    return transport.wire as IoDohTransport;
  }

  group('default transport', () {
    test('a direct lookup goes to dns.google at 8.8.8.8 only', () {
      final transport = openDohTransport(null);
      final wire = io(transport);
      expect(transport.endpoint, Uri.parse('https://dns.google/dns-query'));
      expect(wire.destination, InternetAddress('8.8.8.8'));
      expect(wire.proxy, isNull);
      expect(wire.securityContext, isNull);
      expect(wire.httpClientFactory, isNull);
      expect(wire.connectionTimeout, const Duration(seconds: 5));
      expect(wire.requestTimeout, const Duration(seconds: 12));
      expect(wire.padQueries, isTrue);
      expect(wire.reuseConnections, isTrue);
    });

    test('a proxied lookup has its own isolation credentials', () {
      const proxy = CsOpenAliasProxy(address: '127.0.0.1', port: 9050);
      final first = io(openDohTransport(proxy));
      final second = io(openDohTransport(proxy));
      for (final wire in [first, second]) {
        expect(wire.proxy!.host, InternetAddress.loopbackIPv4);
        expect(wire.proxy!.port, 9050);
        expect(wire.proxy!.isolationToken, matches(RegExp(r'^[0-9a-f]{32}$')));
        expect(wire.destination, InternetAddress('8.8.8.8'));
        expect(wire.connectionTimeout, const Duration(seconds: 10));
        expect(wire.requestTimeout, const Duration(seconds: 20));
        expect(wire.reuseConnections, isTrue);
      }
      expect(first.proxy!.isolationToken, isNot(second.proxy!.isolationToken));
    });

    test('isolation tokens are 128 random bits', () {
      final tokens = List.generate(64, (_) => isolationToken());
      expect(tokens.toSet(), hasLength(64));
      for (final token in tokens) {
        expect(token, matches(RegExp(r'^[0-9a-f]{32}$')));
      }
    });

    test('a proxy needs a numeric address and a port', () {
      for (final proxy in const [
        CsOpenAliasProxy(address: 'localhost', port: 9050),
        CsOpenAliasProxy(address: '::1', port: 0),
        CsOpenAliasProxy(address: '127.0.0.1', port: 65536),
      ]) {
        expect(() => openDohTransport(proxy), throwsArgumentError);
      }
    });
  });

  group('DohDnssecPort', () {
    test('sends to the endpoint and returns the body and Age', () async {
      final wire = FakeWire();
      final operation = DohDnssecPort(
        wire,
        endpoint,
      ).startWire([1, 2, 3], maxResponseBytes: 65535);
      final exchange = wire.exchanges.single;
      expect(exchange.uri, endpoint);
      expect(exchange.query, [1, 2, 3]);
      expect(exchange.maxResponseBytes, 65535);

      exchange.completer.complete(
        DohHttpResponse([4, 5], age: const Duration(seconds: 9)),
      );
      final response = await operation.result;
      expect(response.message, [4, 5]);
      expect(response.age, const Duration(seconds: 9));
    });

    test('passes transport failures through unchanged', () async {
      final wire = FakeWire();
      final operation = DohDnssecPort(
        wire,
        endpoint,
      ).startWire([1], maxResponseBytes: 512);
      const failure = DohConnectionException('refused');
      wire.exchanges.single.completer.completeError(failure);
      await expectLater(operation.result, throwsA(same(failure)));
    });

    test('cancel reaches the exchange', () {
      final wire = FakeWire();
      DohDnssecPort(wire, endpoint).startWire([1], maxResponseBytes: 512)
        ..cancel()
        ..cancel();
      expect(wire.exchanges.single.cancels, 2);
    });
  });
}
