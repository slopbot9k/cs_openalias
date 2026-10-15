import 'dart:async';

import 'package:cs_openalias/cs_openalias.dart';
import 'package:test/test.dart';

import 'support/fixture_network.dart';

void main() {
  final fixtures = Fixtures();

  CsOpenAliasResolver resolver(
    FixtureNetworkFactory factory, {
    bool Function()? allowed,
    Duration timeout = const Duration(seconds: 2),
    int maxQueries = 64,
    bool Function(String)? validateAddress,
  }) => CsOpenAliasResolver(
    validateAddress: validateAddress ?? (address) => address == 'valid',
    networkFactory: factory,
    isAllowed: allowed,
    lookupTimeout: timeout,
    maxQueries: maxQueries,
    trustAnchors: fixtures.anchor,
    network: CsOpenAliasNetworkOptions(
      endpoint: Uri.https('resolver.example', '/dns-query'),
    ),
  );

  test(
    'secure chain returns a facade-owned recipient over one session',
    () async {
      final factory = FixtureNetworkFactory(fixtures);
      final result = await resolver(factory).resolve('ALICE@EXAMPLE.TEST.');
      expect(result.domain, 'alice.example.test');
      expect(result.canonicalName, 'alice.example.test');
      expect(result.address, 'valid');
      expect(result.application, 'xmr');
      expect(result.fields['recipient_address'], 'valid');
      expect(result.ttl, lessThanOrEqualTo(300));
      expect(factory.sessions, hasLength(1));
      expect(factory.sessions.single.queries.length, greaterThan(1));
      expect(factory.sessions.single.closes, 1);
    },
  );

  test('HTTP Age reaches the final TTL exactly once', () async {
    final factory = FixtureNetworkFactory(
      fixtures,
      age: const Duration(seconds: 120),
    );
    final result = await resolver(factory).resolve('alice.example.test');
    expect(result.ttl, 180);
  });

  test(
    'secure cross-zone CNAME evidence reaches facade-owned fields',
    () async {
      final factory = FixtureNetworkFactory(
        fixtures,
        mutate: (_, _, response) => _withTypeTtl(response, 5, 17),
      );
      final result = await resolver(factory).resolve('alias.example.test');
      expect(result.domain, 'alias.example.test');
      expect(result.canonicalName, 'bob.other.test');
      expect(result.address, 'valid');
      expect(result.ttl, 17, reason: 'CNAME lifetime bounds recipient caching');
    },
  );

  test('high-bit TTL reaches the facade as zero', () async {
    final factory = FixtureNetworkFactory(
      fixtures,
      mutate: (_, _, response) => _withHighBitTtls(response),
    );
    final result = await resolver(factory).resolve('alice.example.test');
    expect(result.ttl, 0);
  });

  for (final mutation in ['id', 'question', 'truncated', 'query', 'short']) {
    test('hostile $mutation wire response is rejected at facade', () async {
      final factory = FixtureNetworkFactory(
        fixtures,
        mutate: (_, _, response) {
          switch (mutation) {
            case 'id':
              response[1] ^= 1;
            case 'question':
              response[13] ^= 1;
            case 'truncated':
              response[2] |= 2;
            case 'query':
              response[2] &= 0x7f;
            case 'short':
              return [0];
          }
          return response;
        },
      );
      await expectLater(
        resolver(factory).resolve('alice.example.test'),
        throwsA(
          anyOf(
            isA<CsOpenAliasQuestionMismatchException>(),
            isA<CsOpenAliasMalformedResponseException>(),
          ),
        ),
      );
      expect(factory.sessions.single.closes, 1);
    });
  }

  for (final mutation in [
    'compression-loop',
    'edns-version',
    'duplicate-opt',
  ]) {
    test('hostile $mutation framing is rejected at facade', () async {
      final factory = FixtureNetworkFactory(
        fixtures,
        mutate: (_, _, response) {
          switch (mutation) {
            case 'compression-loop':
              response
                ..[12] = 0xc0
                ..[13] = 0x0c;
            case 'edns-version':
              response[11]++;
              response.addAll(_opt(version: 1));
            case 'duplicate-opt':
              response[11] += 2;
              response
                ..addAll(_opt())
                ..addAll(_opt());
          }
          return response;
        },
      );
      await expectLater(
        resolver(factory).resolve('alice.example.test'),
        throwsA(isA<CsOpenAliasMalformedResponseException>()),
      );
    });
  }

  test(
    'HTTP status and oversized bodies retain typed adapter errors',
    () async {
      final status = FixtureNetworkFactory(fixtures, statusCode: 503);
      await expectLater(
        resolver(status).resolve('alice.example.test'),
        throwsA(
          isA<CsOpenAliasHttpException>().having(
            (error) => error.statusCode,
            'statusCode',
            503,
          ),
        ),
      );

      final oversized = FixtureNetworkFactory(
        fixtures,
        mutate: (_, _, _) => List<int>.filled(65536, 0),
      );
      await expectLater(
        resolver(oversized).resolve('alice.example.test'),
        throwsA(isA<CsOpenAliasResponseTooLargeException>()),
      );
    },
  );

  test(
    'typed network failures cross both adapters without message parsing',
    () async {
      final factory = FixtureNetworkFactory(
        fixtures,
        failure: const CsOpenAliasHttpException('synthetic', statusCode: 429),
      );
      await expectLater(
        resolver(factory).resolve('alice.example.test'),
        throwsA(
          isA<CsOpenAliasHttpException>().having(
            (error) => error.statusCode,
            'statusCode',
            429,
          ),
        ),
      );
    },
  );

  test(
    'privacy revocation rejects completion and starts no next exchange',
    () async {
      var allowed = true;
      final factory = FixtureNetworkFactory(
        fixtures,
        onStart: (_) => allowed = false,
      );
      await expectLater(
        resolver(factory, allowed: () => allowed).resolve('alice.example.test'),
        throwsA(isA<CsOpenAliasPrivacyException>()),
      );
      expect(factory.sessions.single.queries, hasLength(1));
      expect(factory.sessions.single.closes, 1);
    },
  );

  for (final cancel in [false, true]) {
    test('${cancel ? 'cancellation' : 'deadline'} aborts and closes', () async {
      final factory = FixtureNetworkFactory(fixtures, hang: true);
      final operation = resolver(
        factory,
        timeout: const Duration(milliseconds: 30),
      ).startResolve('alice.example.test');
      await _until(
        () =>
            factory.sessions.isNotEmpty &&
            factory.sessions.single.queries.isNotEmpty,
      );
      if (cancel) operation.cancel();
      await expectLater(
        operation.result,
        throwsA(
          cancel
              ? isA<CsOpenAliasCancelledException>()
              : isA<CsOpenAliasTimeoutException>(),
        ),
      );
      expect(factory.sessions.single.cancellations, greaterThanOrEqualTo(1));
      expect(factory.sessions.single.closes, 1);
      operation.cancel();
    });
  }

  test('query budget remains bounded at the facade', () async {
    final factory = FixtureNetworkFactory(fixtures);
    await expectLater(
      resolver(factory, maxQueries: 2).resolve('alice.example.test'),
      throwsA(isA<CsOpenAliasException>()),
    );
    expect(factory.sessions.single.queries.length, lessThanOrEqualTo(2));
    expect(factory.sessions.single.closes, 1);
  });

  test('secure negative answer never supplies a recipient', () async {
    final factory = FixtureNetworkFactory(fixtures);
    await expectLater(
      resolver(factory).resolve('missing.example.test'),
      throwsA(isA<CsOpenAliasDnsNoRecordException>()),
    );
  });

  test('address validation remains caller-owned', () async {
    final factory = FixtureNetworkFactory(fixtures);
    await expectLater(
      resolver(
        factory,
        validateAddress: (_) => false,
      ).resolve('alice.example.test'),
      throwsA(isA<CsOpenAliasInvalidAddressException>()),
    );
  });

  test('facade composition retains OpenAlias XMR field policy', () async {
    final factory = FixtureNetworkFactory(fixtures);
    final result = await resolver(
      factory,
      validateAddress: (address) => address == 'valid',
    ).resolve('policy-fields.example.test');
    expect(result.address, 'valid');
    expect(result.fields['recipient_name'], 'Alice; Example');
    expect(result.fields['tx_amount'], '999');
    expect(result.fields['recipient_address'], 'valid');
  });

  for (final (domain, matcher) in [
    (
      'policy-payment-id.example.test',
      isA<CsOpenAliasUnsupportedFieldException>(),
    ),
    ('policy-ambiguous.example.test', isA<CsOpenAliasAmbiguousException>()),
    (
      'policy-duplicate.example.test',
      isA<CsOpenAliasDuplicateFieldException>(),
    ),
  ]) {
    test('facade composition rejects unsafe XMR policy at $domain', () async {
      final factory = FixtureNetworkFactory(fixtures);
      await expectLater(
        resolver(
          factory,
          validateAddress: (address) =>
              address == 'valid' || address == 'second',
        ).resolve(domain),
        throwsA(matcher),
      );
    });
  }

  test('native DNSSEC failure maps to a facade-owned typed status', () async {
    final factory = FixtureNetworkFactory(fixtures);
    await expectLater(
      resolver(factory).resolve('alice.bad-ds.test'),
      throwsA(
        isA<CsOpenAliasDnssecException>()
            .having(
              (error) => error.status,
              'status',
              CsOpenAliasDnssecStatus.bogus,
            )
            .having(
              (error) => error.toString(),
              'toString',
              contains('status: bogus'),
            ),
      ),
    );
  });

  test(
    'native validator loads before dispatching through the facade port',
    () async {
      final factory = FixtureNetworkFactory(
        fixtures,
        failure: const CsOpenAliasNetworkException(
          'expected transport failure',
        ),
      );
      await expectLater(
        resolver(factory).resolve('alice.example.test'),
        throwsA(isA<CsOpenAliasNetworkException>()),
      );
      expect(factory.sessions.single.queries, hasLength(1));
    },
  );

  test('caller callback defects remain ordinary Dart errors', () async {
    final factory = FixtureNetworkFactory(fixtures);
    final defect = StateError('validator defect');
    await expectLater(
      resolver(
        factory,
        validateAddress: (_) => throw defect,
      ).resolve('alice.example.test'),
      throwsA(same(defect)),
    );
    expect(factory.sessions.single.closes, 1);
  });

  test('independent concurrent lookups own separate sessions', () async {
    final factory = FixtureNetworkFactory(fixtures);
    final subject = resolver(factory);
    final results = await Future.wait([
      subject.resolve('alice.example.test'),
      subject.resolve('alice.example.test'),
    ]);
    expect(results.map((result) => result.address), ['valid', 'valid']);
    expect(factory.sessions, hasLength(2));
    expect(factory.sessions.every((session) => session.closes == 1), isTrue);
  });

  test('a dropped asynchronously failing resolver result is handled', () async {
    final uncaught = <Object>[];
    final factory = FixtureNetworkFactory(
      fixtures,
      failure: const CsOpenAliasNetworkException('asynchronous failure'),
    );
    await runZonedGuarded(() async {
      resolver(factory).startResolve('alice.example.test');
      await _until(
        () =>
            factory.sessions.isNotEmpty && factory.sessions.single.closes == 1,
      );
      await Future<void>.delayed(Duration.zero);
    }, (error, _) => uncaught.add(error));
    expect(uncaught, isEmpty);
  });
}

List<int> _withHighBitTtls(List<int> message) {
  final out = [...message];
  int skipName(int at) {
    while (true) {
      final length = out[at];
      if (length == 0) return at + 1;
      if (length & 0xc0 == 0xc0) return at + 2;
      at += 1 + length;
    }
  }

  int u16(int at) => out[at] << 8 | out[at + 1];
  var at = 12;
  for (var i = 0; i < u16(4); i++) {
    at = skipName(at) + 4;
  }
  for (var i = 0; i < u16(6) + u16(8) + u16(10); i++) {
    at = skipName(at);
    if (u16(at) != 41) out.setRange(at + 4, at + 8, [0x80, 0, 0, 0]);
    at += 10 + u16(at + 8);
  }
  return out;
}

List<int> _withTypeTtl(List<int> message, int recordType, int ttl) {
  final out = [...message];
  int u16(int at) => out[at] << 8 | out[at + 1];
  int skipName(int at) {
    while (true) {
      final length = out[at];
      if (length == 0) return at + 1;
      if (length & 0xc0 == 0xc0) return at + 2;
      at += 1 + length;
    }
  }

  var at = 12;
  for (var i = 0; i < u16(4); i++) {
    at = skipName(at) + 4;
  }
  for (var i = 0; i < u16(6) + u16(8) + u16(10); i++) {
    at = skipName(at);
    if (u16(at) == recordType) {
      out
        ..[at + 4] = ttl >> 24
        ..[at + 5] = ttl >> 16 & 0xff
        ..[at + 6] = ttl >> 8 & 0xff
        ..[at + 7] = ttl & 0xff;
    }
    at += 10 + u16(at + 8);
  }
  return out;
}

Future<void> _until(bool Function() condition) async {
  for (var i = 0; i < 1000 && !condition(); i++) {
    await Future<void>.delayed(const Duration(milliseconds: 1));
  }
  if (!condition()) throw StateError('condition was not reached');
}

List<int> _opt({int version = 0}) => [
  0,
  0,
  41,
  4,
  208,
  0,
  version,
  128,
  0,
  0,
  0,
];
