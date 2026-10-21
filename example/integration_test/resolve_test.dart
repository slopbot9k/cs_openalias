import 'dart:io';

import 'package:cs_openalias/cs_openalias.dart';
import 'package:test/test.dart';

import 'support/harness.dart';
import 'support/test_pki.dart';

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

  test('a signed alias resolves over TLS through the validator', () async {
    final recipient = await harness.start('ALICE@EXAMPLE.TEST.').result;
    expect(recipient.domain, 'alice.example.test');
    expect(recipient.address, 'valid');
    expect(recipient.fields, {'recipient_address': 'valid'});
    expect(server.requests, greaterThan(1));
    expect(harness.opened, 1);
    expect(harness.closes, 1);
  });

  test('a signed CNAME into another zone resolves the alias', () async {
    final recipient = await harness.start('alias.example.test').result;
    expect(recipient.domain, 'alias.example.test');
    expect(recipient.address, 'valid');
  });

  for (final (alias, status) in [
    ('unsigned.test', CsOpenAliasDnssecStatus.insecure),
    ('alice.bad-ds.test', CsOpenAliasDnssecStatus.bogus),
    ('tampered.example.test', CsOpenAliasDnssecStatus.bogus),
  ]) {
    test('$alias is rejected as ${status.name}', () async {
      var validated = 0;
      await expectLater(
        harness
            .start(
              alias,
              isValidAddress: (_) {
                validated++;
                return true;
              },
            )
            .result,
        throwsA(
          isA<CsOpenAliasDnssecException>().having(
            (error) => error.status,
            'status',
            status,
          ),
        ),
      );
      expect(validated, 0);
      expect(harness.closes, 1);
    });
  }

  for (final alias in ['missing.example.test', 'empty.example.test']) {
    test('a validated negative answer for $alias has no record', () async {
      await expectLater(
        harness.start(alias).result,
        throwsA(isA<CsOpenAliasNoRecordException>()),
      );
    });
  }

  test('a CNAME loop is a network failure', () async {
    await expectLater(
      harness.start('loop.example.test').result,
      throwsA(isA<CsOpenAliasNetworkException>()),
    );
  });

  test('the wallet decides whether the address is valid', () async {
    await expectLater(
      harness.start('alice.example.test', isValidAddress: (_) => false).result,
      throwsA(isA<CsOpenAliasInvalidRecordException>()),
    );
  });

  test('an HTTP error status is a network failure', () async {
    server.respond = (request) async {
      request.response.statusCode = HttpStatus.serviceUnavailable;
      await request.response.close();
    };
    await expectLater(
      harness.start('alice.example.test').result,
      throwsA(isA<CsOpenAliasNetworkException>()),
    );
    expect(server.requests, 1);
    expect(harness.closes, 1);
  });

  test('a response of another media type is a network failure', () async {
    server.respond = (request) async {
      request.response
        ..headers.contentType = ContentType.json
        ..write('{}');
      await request.response.close();
    };
    await expectLater(
      harness.start('alice.example.test').result,
      throwsA(isA<CsOpenAliasNetworkException>()),
    );
  });

  group('with a resolver that never answers', () {
    late SilentServer silent;
    setUp(() async {
      silent = await SilentServer.start(pki);
      harness = Harness(silent.endpoint, pki.clientContext(), fixtures);
    });
    tearDown(() => silent.close());

    test('cancel aborts the exchange and closes the transport', () async {
      final operation = harness.start('alice.example.test');
      await until(() => silent.received > 0);
      operation.cancel();
      await expectLater(
        operation.result,
        throwsA(isA<CsOpenAliasCancelledException>()),
      );
      expect(harness.closes, 1);
      await until(() => silent.closed == silent.connections);
      operation.cancel();
      expect(harness.closes, 1);
    });

    test('the lookup deadline closes the transport', () async {
      final operation = harness.start(
        'alice.example.test',
        lookupTimeout: const Duration(milliseconds: 300),
      );
      await until(() => silent.received > 0);
      await expectLater(
        operation.result,
        throwsA(
          isA<CsOpenAliasNetworkException>().having(
            (error) => error.timeout,
            'timeout',
            const Duration(milliseconds: 300),
          ),
        ),
      );
      expect(harness.closes, 1);
      await until(() => silent.closed == silent.connections);
    });
  });
}
