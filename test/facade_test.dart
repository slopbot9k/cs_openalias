import 'dart:async';

import 'package:cs_openalias/cs_openalias.dart';
import 'package:test/test.dart';

void main() {
  test('normalization failures occur before network creation', () async {
    final factory = _Factory();
    final resolver = CsOpenAliasResolver(
      validateAddress: (_) => true,
      networkFactory: factory,
    );
    await expectLater(
      resolver.resolve('not-a-domain'),
      throwsA(isA<CsOpenAliasInvalidNameException>()),
    );
    expect(factory.creates, 0);
  });

  test('revoked permission prevents network creation', () async {
    final factory = _Factory();
    final resolver = CsOpenAliasResolver(
      validateAddress: (_) => true,
      networkFactory: factory,
      isAllowed: () => false,
    );
    await expectLater(
      resolver.resolve('alice.example'),
      throwsA(isA<CsOpenAliasPrivacyException>()),
    );
    expect(factory.creates, 0);
  });

  test('network factory failures are typed and retain their cause', () async {
    final cause = StateError('factory failed');
    final resolver = CsOpenAliasResolver(
      validateAddress: (_) => true,
      networkFactory: _ThrowingFactory(cause),
    );
    await expectLater(
      resolver.resolve('alice.example'),
      throwsA(
        isA<CsOpenAliasNetworkException>()
            .having((error) => error.cause, 'cause', same(cause))
            .having(
              (error) => error.toString(),
              'toString',
              contains('CsOpenAliasNetworkException'),
            ),
      ),
    );
  });

  test('wire response and recipient are defensive snapshots', () {
    final body = [1, 2, 3];
    final response = CsOpenAliasWireResponse(
      200,
      body,
      age: const Duration(seconds: 4),
    );
    body[0] = 9;
    expect(response.body, [1, 2, 3]);
    expect(() => response.body.add(4), throwsUnsupportedError);

    final fields = {'recipient_address': 'address'};
    final recipient = CsOpenAliasRecipient(
      domain: 'alice.example',
      address: 'address',
      application: 'xmr',
      canonicalName: 'alice.example',
      ttl: 300,
      fields: fields,
    );
    fields['recipient_address'] = 'changed';
    expect(recipient.fields['recipient_address'], 'address');
    expect(
      () => recipient.fields['recipient_name'] = 'Alice',
      throwsUnsupportedError,
    );
  });

  test('invalid network configuration fails closed', () {
    for (final network in [
      CsOpenAliasNetworkOptions(
        endpoint: Uri.parse('http://dns.example/dns-query'),
      ),
      CsOpenAliasNetworkOptions(destinationAddress: 'dns.example'),
      CsOpenAliasNetworkOptions(
        proxy: const CsOpenAliasProxy(address: 'proxy.example', port: 9050),
      ),
    ]) {
      expect(
        () =>
            CsOpenAliasResolver(validateAddress: (_) => true, network: network),
        throwsArgumentError,
      );
    }
  });

  test('invalid application and trust anchors fail before networking', () {
    final factory = _Factory();
    for (final application in ['', 'XMR', 'xmr value']) {
      expect(
        () => CsOpenAliasResolver(
          validateAddress: (_) => true,
          networkFactory: factory,
          application: application,
        ),
        throwsArgumentError,
      );
    }
    for (final anchors in ['', '   ', 'x' * 60001]) {
      expect(
        () => CsOpenAliasResolver(
          validateAddress: (_) => true,
          networkFactory: factory,
          trustAnchors: anchors,
        ),
        throwsArgumentError,
      );
    }
    expect(factory.creates, 0);
  });

  test('exception leaves expose stable fields and readable types', () {
    final cause = StateError('socket');
    final stack = StackTrace.current;
    final http = CsOpenAliasHttpException(
      'resolver failed',
      statusCode: 503,
      cause: cause,
      causeStackTrace: stack,
    );
    expect(http.code, CsOpenAliasError.httpStatus);
    expect(http.statusCode, 503);
    expect(http.cause, same(cause));
    expect(http.causeStackTrace, same(stack));
    expect(http.toString(), contains('CsOpenAliasHttpException'));
    expect(http.toString(), contains('resolver failed'));
    expect(http.toString(), contains('statusCode: 503'));

    const limit = CsOpenAliasLimitExceededException(
      'too many fields',
      maximum: 16,
      actual: 17,
    );
    expect(limit.maximum, 16);
    expect(limit.actual, 17);
    expect(limit.toString(), contains('maximum: 16'));
    expect(limit.toString(), contains('actual: 17'));

    const body = CsOpenAliasResponseTooLargeException(
      'body too large',
      limitBytes: 65535,
    );
    expect(body.limitBytes, 65535);
    expect(body.toString(), contains('limitBytes: 65535'));

    const query = CsOpenAliasDnsQueryFailedException('query failed', rcode: 2);
    expect(query.rcode, 2);
    expect(query.toString(), contains('rcode: 2'));

    const timeout = CsOpenAliasTimeoutException(
      'deadline',
      timeout: Duration(seconds: 20),
      source: CsOpenAliasTimeoutSource.lookup,
    );
    expect(timeout.timeout, const Duration(seconds: 20));
    expect(timeout.code, CsOpenAliasError.timedOut);
    expect(timeout.toString(), contains('timeout: 0:00:20.000000'));

    const dnssec = CsOpenAliasDnssecException(
      'validation failed',
      status: CsOpenAliasDnssecStatus.bogus,
    );
    expect(dnssec.status, CsOpenAliasDnssecStatus.bogus);
    expect(dnssec.toString(), contains('status: bogus'));
  });

  test('dropped ordinary and failed facade operations are handled', () async {
    final uncaught = <Object>[];
    await runZonedGuarded(() async {
      CsOpenAliasOperation<void>(
        Future<void>.error(
          const CsOpenAliasNetworkException('ordinary dropped'),
        ),
        () {},
      );
      CsOpenAliasOperation<void>.failed(
        const CsOpenAliasCancelledException('dropped'),
      );
      await Future<void>.delayed(Duration.zero);
    }, (error, _) => uncaught.add(error));
    expect(uncaught, isEmpty);
  });
}

final class _Factory implements CsOpenAliasNetworkFactory {
  int creates = 0;

  @override
  CsOpenAliasNetworkSession create(CsOpenAliasNetworkOptions options) {
    creates++;
    return _Session();
  }
}

final class _ThrowingFactory implements CsOpenAliasNetworkFactory {
  final Object error;

  const _ThrowingFactory(this.error);

  @override
  CsOpenAliasNetworkSession create(CsOpenAliasNetworkOptions options) {
    throw error;
  }
}

final class _Session implements CsOpenAliasNetworkSession {
  @override
  Future<void> close() async {}

  @override
  CsOpenAliasOperation<CsOpenAliasWireResponse> startWire(
    Uri endpoint,
    List<int> query, {
    required int maxResponseBytes,
  }) =>
      CsOpenAliasOperation.failed(const CsOpenAliasNetworkException('unused'));
}
