import 'package:cs_openalias/cs_openalias.dart';
import 'package:test/test.dart';

import 'support/harness.dart';
import 'support/test_pki.dart';
import 'support/tunnel_proxy.dart';

final _isolationToken = RegExp(r'^[0-9a-f]{32}$');

void main() {
  final fixtures = Fixtures.load();
  late TestPki pki;
  late FixtureServer server;
  late Harness harness;

  setUpAll(() => pki = TestPki.generate());
  setUp(() async {
    server = await FixtureServer.start(fixtures, pki);
    harness = Harness(server.endpoint, pki.clientContext(), fixtures);
  });
  tearDown(() => server.close());

  Future<TunnelProxy> socks({int? upstreamPort, int replyCode = 0}) async {
    final proxy = TunnelProxy(upstreamPort: upstreamPort, replyCode: replyCode);
    await proxy.start();
    addTearDown(proxy.close);
    return proxy;
  }

  CsOpenAliasProxy via(TunnelProxy proxy) =>
      CsOpenAliasProxy(address: '127.0.0.1', port: proxy.port);

  test('a refused SOCKS connection never falls back to direct', () async {
    final proxy = await socks(replyCode: 5);
    await expectLater(
      harness.start('alice.example.test', proxy: via(proxy)).result,
      throwsA(isA<CsOpenAliasNetworkException>()),
    );
    await Future<void>.delayed(const Duration(milliseconds: 50));
    expect(proxy.connections, greaterThan(0));
    expect(proxy.target, '127.0.0.1');
    expect(proxy.targetPort, server.port);
    expect(server.requests, 0);
    expect(harness.closes, 1);
  });

  test('each lookup through the tunnel has its own credentials', () async {
    final proxy = await socks(upstreamPort: server.port);
    final usernames = <String?>[];
    for (var i = 0; i < 2; i++) {
      final recipient = await harness
          .start('alice.example.test', proxy: via(proxy))
          .result;
      expect(recipient.address, 'valid');
      expect(proxy.username, matches(_isolationToken));
      expect(proxy.password, proxy.username);
      usernames.add(proxy.username);
    }
    expect(usernames.toSet(), hasLength(2));
    expect(harness.closes, 2);
  });

  test('the default resolver is reached only through the proxy', () async {
    final proxy = await socks(replyCode: 5);
    final usernames = <String?>[];
    for (var i = 0; i < 2; i++) {
      await expectLater(
        resolveOpenAlias(
          'donate@getmonero.org',
          isValidAddress: (address) => address.isNotEmpty,
          proxy: via(proxy),
        ).result,
        throwsA(isA<CsOpenAliasNetworkException>()),
      );
      expect(proxy.targetType, 1, reason: 'a numeric IPv4 destination');
      expect(proxy.target, '8.8.8.8');
      expect(proxy.targetPort, 443);
      expect(proxy.username, matches(_isolationToken));
      usernames.add(proxy.username);
    }
    expect(usernames.toSet(), hasLength(2));
  });
}
