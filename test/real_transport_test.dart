import 'dart:async';

import 'package:cs_openalias/cs_openalias.dart';
import 'package:test/test.dart';

import 'support/fake_http_client.dart';
import 'support/fixture_network.dart';

const _ecs = [0, 8, 0, 4, 0, 1, 0, 0];

final class _Loop {
  final FakeDohHttpClient fake;
  final CsOpenAliasResolver resolver;

  const _Loop(this.fake, this.resolver);
}

void main() {
  final fixtures = Fixtures();
  final endpoint = Uri.https('resolver.example', '/dns-query');

  _Loop loop({
    List<FakeDohHttpScript> scripts = const [],
    Duration lookupTimeout = const Duration(seconds: 2),
    Duration requestTimeout = const Duration(seconds: 1),
    int maxQueries = 64,
    int maxConcurrentRequests = 8,
  }) {
    final fake = FakeDohHttpClient(
      scripts: scripts,
      reply: (_, query) => fixtures.reply(query),
    );
    return _Loop(
      fake,
      CsOpenAliasResolver(
        validateAddress: (address) => address == 'valid',
        lookupTimeout: lookupTimeout,
        maxQueries: maxQueries,
        trustAnchors: fixtures.anchor,
        network: CsOpenAliasNetworkOptions(
          endpoint: endpoint,
          requestTimeout: requestTimeout,
          maxConcurrentRequests: maxConcurrentRequests,
          reuseConnections: true,
          httpClientFactory: fake.create,
        ),
      ),
    );
  }

  test(
    'secure multi-exchange chain reuses one real transport client',
    () async {
      final subject = loop();
      final recipient = await subject.resolver.resolve('alice.example.test');
      expect(recipient.address, 'valid');
      expect(subject.fake.createdClients, 1);
      expect(subject.fake.requests.length, greaterThan(1));
      for (final request in subject.fake.requests) {
        final query = request.body;
        expect(query.length % 128, 0);
        expect(query[2] & 1, 1, reason: 'RD required');
        expect(query[3] & 0x10, 0x10, reason: 'CD required');
        expect(query[3] & 0x20, 0, reason: 'AD must be clear');
        final questionEnd = Fixtures.question(query).$3;
        expect(query[questionEnd + 7] & 0x80, 0x80, reason: 'DO required');
        expect(_contains(query, _ecs), isTrue, reason: 'zero ECS required');
        expect(_contains(query, [0, 12]), isTrue, reason: 'padding required');
      }
    },
  );

  test('declared and streaming body bounds survive both adapters', () async {
    final declared = loop(
      scripts: const [FakeDohHttpScript(declaredContentLength: 65536)],
    );
    await expectLater(
      declared.resolver.resolve('alice.example.test'),
      throwsA(isA<CsOpenAliasResponseTooLargeException>()),
    );

    final fake = FakeDohHttpClient(
      scripts: const [
        FakeDohHttpScript(chunkSizes: [32768, 32768]),
      ],
      reply: (_, _) => List<int>.filled(65536, 0),
    );
    final chunked = CsOpenAliasResolver(
      validateAddress: (_) => true,
      trustAnchors: fixtures.anchor,
      network: CsOpenAliasNetworkOptions(
        endpoint: endpoint,
        httpClientFactory: fake.create,
      ),
    );
    await expectLater(
      chunked.resolve('alice.example.test'),
      throwsA(isA<CsOpenAliasResponseTooLargeException>()),
    );
  });

  test(
    'real transport HTTP status retains structured facade metadata',
    () async {
      final subject = loop(scripts: const [FakeDohHttpScript(statusCode: 500)]);
      await expectLater(
        subject.resolver.resolve('alice.example.test'),
        throwsA(
          isA<CsOpenAliasHttpException>().having(
            (error) => error.statusCode,
            'statusCode',
            500,
          ),
        ),
      );
    },
  );

  test('real HTTP Age reaches the final facade TTL once', () async {
    final subject = loop(
      scripts: List<FakeDohHttpScript>.filled(
        64,
        const FakeDohHttpScript(age: '120'),
      ),
    );
    final recipient = await subject.resolver.resolve('alice.example.test');
    expect(recipient.ttl, 180);
  });

  test('lookup deadline wins and aborts the real request', () async {
    final subject = loop(
      scripts: const [FakeDohHttpScript(hang: true)],
      lookupTimeout: const Duration(milliseconds: 30),
      requestTimeout: const Duration(seconds: 1),
    );
    await expectLater(
      subject.resolver.resolve('alice.example.test'),
      throwsA(
        isA<CsOpenAliasTimeoutException>().having(
          (error) => error.source,
          'source',
          CsOpenAliasTimeoutSource.lookup,
        ),
      ),
    );
    expect(subject.fake.aborts, greaterThan(0));
  });

  test('transport deadline remains distinct and aborts', () async {
    final subject = loop(
      scripts: const [FakeDohHttpScript(hang: true)],
      lookupTimeout: const Duration(seconds: 1),
      requestTimeout: const Duration(milliseconds: 20),
    );
    await expectLater(
      subject.resolver.resolve('alice.example.test'),
      throwsA(
        isA<CsOpenAliasTimeoutException>().having(
          (error) => error.source,
          'source',
          CsOpenAliasTimeoutSource.transportRequest,
        ),
      ),
    );
    expect(subject.fake.aborts, greaterThan(0));
  });

  test('cancellation stops the real transport operation', () async {
    final subject = loop(scripts: const [FakeDohHttpScript(hang: true)]);
    final operation = subject.resolver.startResolve('alice.example.test');
    await _until(() => subject.fake.requests.isNotEmpty);
    operation.cancel();
    await expectLater(
      operation.result,
      throwsA(isA<CsOpenAliasCancelledException>()),
    );
    expect(subject.fake.aborts, greaterThan(0));
    operation.cancel();
  });

  test('cancelling one lookup cannot cancel a concurrent lookup', () async {
    final subject = loop(scripts: const [FakeDohHttpScript(hang: true)]);
    final cancelled = subject.resolver.startResolve('alice.example.test');
    await _until(() => subject.fake.requests.isNotEmpty);
    final surviving = subject.resolver.resolve('alice.example.test');
    await _until(() => subject.fake.requests.length > 1);
    cancelled.cancel();
    await expectLater(
      cancelled.result,
      throwsA(isA<CsOpenAliasCancelledException>()),
    );
    expect((await surviving).address, 'valid');
    expect(subject.fake.createdClients, greaterThanOrEqualTo(2));
  });

  test('query budget bounds the real transport loop', () async {
    final subject = loop(maxQueries: 2);
    await expectLater(
      subject.resolver.resolve('alice.example.test'),
      throwsA(isA<CsOpenAliasException>()),
    );
    expect(subject.fake.requests.length, lessThanOrEqualTo(2));
  });

  test('default adapter overlaps only to its configured cap', () async {
    final fake = FakeDohHttpClient(
      scripts: List<FakeDohHttpScript>.filled(
        8,
        const FakeDohHttpScript(delay: Duration(milliseconds: 20)),
      ),
      reply: (_, query) => wireEcho(query),
    );
    final session = const DohOpenAliasNetworkFactory().create(
      CsOpenAliasNetworkOptions(
        endpoint: endpoint,
        maxConcurrentRequests: 2,
        maxQueuedRequests: 8,
        reuseConnections: true,
        httpClientFactory: fake.create,
      ),
    );
    addTearDown(session.close);
    final operations = [
      for (var id = 1; id <= 6; id++)
        session.startWire(
          endpoint,
          wireQuery(id: id, name: 'q$id.example'),
          maxResponseBytes: 512,
        ),
    ];
    await Future.wait(operations.map((operation) => operation.result));
    expect(fake.maxActiveRequests, 2);
  });
}

bool _contains(List<int> bytes, List<int> sequence) {
  for (var i = 0; i + sequence.length <= bytes.length; i++) {
    var matches = true;
    for (var j = 0; j < sequence.length; j++) {
      if (bytes[i + j] != sequence[j]) {
        matches = false;
        break;
      }
    }
    if (matches) return true;
  }
  return false;
}

Future<void> _until(bool Function() condition) async {
  for (var i = 0; i < 400 && !condition(); i++) {
    await Future<void>.delayed(const Duration(milliseconds: 5));
  }
  expect(condition(), isTrue);
}
