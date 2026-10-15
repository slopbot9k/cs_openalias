import 'dart:async';
import 'dart:io';

import 'package:cs_openalias/cs_openalias.dart';
import 'package:test/test.dart';

import 'support/fixture_network.dart';
import 'support/test_pki.dart';
import 'support/tunnel_proxy.dart';

void main() {
  final fixtures = Fixtures();
  late TestPki pki;
  late HttpServer server;

  setUpAll(() => pki = TestPki.generate());
  setUp(() async {
    server = await HttpServer.bindSecure(
      InternetAddress.loopbackIPv4,
      0,
      pki.serverContext(),
    );
  });
  tearDown(() => server.close(force: true));

  Uri endpoint() => Uri.parse('https://localhost:${server.port}/dns-query');

  CsOpenAliasResolver resolver({
    CsOpenAliasProxy? proxy,
    SecurityContext? securityContext,
  }) => CsOpenAliasResolver(
    validateAddress: (_) => true,
    trustAnchors: fixtures.anchor,
    lookupTimeout: const Duration(seconds: 2),
    network: CsOpenAliasNetworkOptions(
      endpoint: endpoint(),
      destinationAddress: InternetAddress.loopbackIPv4.address,
      proxy: proxy,
      securityContext: securityContext,
      connectionTimeout: const Duration(seconds: 1),
      requestTimeout: const Duration(seconds: 1),
    ),
  );

  test('SOCKS failure has no direct HTTPS fallback', () async {
    var requests = 0;
    server.listen((request) {
      requests++;
      unawaited(request.response.close());
    });
    final proxy = TunnelProxy(replyCode: 5);
    await proxy.start();
    addTearDown(proxy.close);

    await expectLater(
      resolver(
        proxy: CsOpenAliasProxy(
          address: InternetAddress.loopbackIPv4.address,
          port: proxy.port,
        ),
        securityContext: pki.clientContext(),
      ).resolve('alice.example.test'),
      throwsA(isA<CsOpenAliasNetworkException>()),
    );
    await Future<void>.delayed(const Duration(milliseconds: 30));
    expect(requests, 0);
    expect(proxy.connections, 1);
    expect(proxy.target, InternetAddress.loopbackIPv4.address);
    expect(proxy.targetPort, server.port);
  });

  for (final failure in [
    'TLS rejection',
    'redirect refused',
    'wrong content type',
    'oversized body',
  ]) {
    test('$failure is typed and no retry is sent', () async {
      var requests = 0;
      server.listen((request) async {
        requests++;
        switch (failure) {
          case 'redirect refused':
            request.response
              ..statusCode = HttpStatus.found
              ..headers.set(HttpHeaders.locationHeader, endpoint().toString());
          case 'wrong content type':
            request.response
              ..headers.contentType = ContentType.json
              ..add([0]);
          case 'oversized body':
            request.response
              ..headers.contentType = ContentType('application', 'dns-message')
              ..add(List<int>.filled(65536, 0));
          case 'TLS rejection':
            request.response.headers.contentType = ContentType(
              'application',
              'dns-message',
            );
        }
        await request.response.close();
      }, onError: (Object _) {});

      final expected = switch (failure) {
        'redirect refused' => isA<CsOpenAliasHttpException>().having(
          (error) => error.statusCode,
          'statusCode',
          HttpStatus.found,
        ),
        'wrong content type' => isA<CsOpenAliasMalformedResponseException>(),
        'oversized body' => isA<CsOpenAliasResponseTooLargeException>(),
        _ => isA<CsOpenAliasNetworkException>(),
      };
      await expectLater(
        resolver(
          securityContext: failure == 'TLS rejection'
              ? null
              : pki.clientContext(),
        ).resolve('alice.example.test'),
        throwsA(expected),
      );
      expect(requests, failure == 'TLS rejection' ? 0 : 1);
      if (failure != 'TLS rejection') {
        expect(
          requests,
          1,
          reason: 'fixed numeric destination still verifies localhost TLS',
        );
      }
    });
  }

  test('each proxied lookup has fresh SOCKS isolation credentials', () async {
    await server.close(force: true);
    final socks = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(socks.close);
    final usernames = <String>[];
    socks.listen((socket) {
      final buffer = <int>[];
      var greeted = false;
      socket.listen((data) {
        buffer.addAll(data);
        if (!greeted) {
          if (buffer.length < 2 || buffer.length < 2 + buffer[1]) return;
          final methods = buffer.sublist(2, 2 + buffer[1]);
          buffer.removeRange(0, 2 + buffer[1]);
          greeted = true;
          if (!methods.contains(2)) {
            socket.destroy();
            return;
          }
          socket.add([5, 2]);
        }
        if (buffer.length < 2 || buffer.length < 3 + buffer[1]) return;
        final userLength = buffer[1];
        if (buffer.length < 3 + userLength + buffer[2 + userLength]) return;
        usernames.add(String.fromCharCodes(buffer.sublist(2, 2 + userLength)));
        socket.add([1, 1]);
        socket.destroy();
      }, onError: (_) {});
    });

    for (var i = 1; i <= 2; i++) {
      final subject = CsOpenAliasResolver(
        validateAddress: (_) => true,
        network: CsOpenAliasNetworkOptions(
          proxy: CsOpenAliasProxy(
            address: InternetAddress.loopbackIPv4.address,
            port: socks.port,
          ),
          connectionTimeout: const Duration(seconds: 1),
          requestTimeout: const Duration(seconds: 1),
        ),
      );
      await expectLater(
        subject.resolve('alice.example'),
        throwsA(isA<CsOpenAliasException>()),
      );
      expect(usernames.toSet(), hasLength(i));
    }
  });
}
