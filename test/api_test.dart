import 'dart:async';

import 'package:cs_openalias/cs_openalias.dart';
import 'package:openalias/openalias.dart' show OpenAliasInvalidNameException;
import 'package:test/test.dart';

typedef _Resolve =
    CsOpenAliasOperation<CsOpenAliasRecipient> Function(
      String alias, {
      required bool Function(String address) isValidAddress,
      required CsOpenAliasProxy? proxy,
    });

// Fails to compile when a leaf is added or removed.
String _leaf(CsOpenAliasException error) => switch (error) {
  CsOpenAliasInvalidAliasException() => 'alias',
  CsOpenAliasNoRecordException() => 'no record',
  CsOpenAliasAmbiguousException() => 'ambiguous',
  CsOpenAliasInvalidRecordException() => 'record',
  CsOpenAliasDnssecException() => 'dnssec',
  CsOpenAliasDnsException() => 'dns',
  CsOpenAliasNetworkException() => 'network',
  CsOpenAliasCancelledException() => 'cancelled',
};

void main() {
  test('resolveOpenAlias is the one entry point', () {
    const _Resolve resolve = resolveOpenAlias;
    expect(resolve, isNotNull);
  });

  test('normalizeOpenAlias accepts user@domain and dotted names', () {
    expect(
      normalizeOpenAlias(' Donate@GetMonero.org. '),
      'donate.getmonero.org',
    );
    expect(normalizeOpenAlias('donate.getmonero.org'), 'donate.getmonero.org');
  });

  test('normalizeOpenAlias rejects input that is not an alias', () {
    for (final input in [
      '',
      'not-a-domain',
      'a@b@example.org',
      'alice.onion',
      'café.example',
      '${'a' * 64}.example',
    ]) {
      expect(
        () => normalizeOpenAlias(input),
        throwsA(
          isA<CsOpenAliasInvalidAliasException>()
              .having(
                (error) => error.cause,
                'cause',
                isA<OpenAliasInvalidNameException>(),
              )
              .having((error) => error.alias, 'alias', input),
        ),
        reason: input,
      );
    }
  });

  test('an invalid alias fails the operation before any network', () async {
    final operation = resolveOpenAlias(
      'not-a-domain',
      isValidAddress: (_) => true,
      proxy: null,
    );
    await expectLater(
      operation.result,
      throwsA(isA<CsOpenAliasInvalidAliasException>()),
    );
    operation.cancel();
  });

  test('a non-numeric proxy is a programmer error', () {
    expect(
      () => resolveOpenAlias(
        'alice.example',
        isValidAddress: (_) => true,
        proxy: const CsOpenAliasProxy(address: 'localhost', port: 9050),
      ),
      throwsArgumentError,
    );
  });

  group('exceptions', () {
    final cause = StateError('https://resolver.example secret');
    final stack = StackTrace.current;

    test('plain leaves print their type and message only', () {
      for (final error in <CsOpenAliasException>[
        CsOpenAliasInvalidAliasException('m', alias: 'a.example', cause: cause),
        CsOpenAliasNoRecordException('m', alias: 'a.example', cause: cause),
        CsOpenAliasAmbiguousException('m', alias: 'a.example', cause: cause),
        CsOpenAliasInvalidRecordException(
          'm',
          alias: 'a.example',
          cause: cause,
        ),
        CsOpenAliasDnsException('m', alias: 'a.example', cause: cause),
        CsOpenAliasNetworkException('m', alias: 'a.example', cause: cause),
        CsOpenAliasCancelledException('m', alias: 'a.example', cause: cause),
      ]) {
        expect(error.toString(), '${error.runtimeType}: m');
        expect(error.cause, same(cause));
        expect(_leaf(error), isNotEmpty);
      }
    });

    test('structured leaves print their fields', () {
      final dnssec = CsOpenAliasDnssecException(
        'not secure',
        alias: 'a.example',
        status: CsOpenAliasDnssecStatus.bogus,
        cause: cause,
        causeStackTrace: stack,
      );
      expect(dnssec.status, CsOpenAliasDnssecStatus.bogus);
      expect(dnssec.causeStackTrace, same(stack));
      expect(
        dnssec.toString(),
        'CsOpenAliasDnssecException(status: bogus): not secure',
      );

      final timeout = CsOpenAliasNetworkException(
        'deadline',
        alias: 'a.example',
        timeout: const Duration(seconds: 12),
        cause: cause,
      );
      expect(timeout.timeout, const Duration(seconds: 12));
      expect(
        timeout.toString(),
        'CsOpenAliasNetworkException(timeout: 0:00:12.000000): deadline',
      );
      expect(timeout.toString(), isNot(contains('secret')));
    });

    test('toString does not print the alias', () {
      const error = CsOpenAliasNoRecordException('m', alias: 'a.example');
      expect(error.toString(), 'CsOpenAliasNoRecordException: m');
    });

    test('userMessage is the ready-to-show text of each leaf', () {
      const a = 'alice.example';
      final expected = <CsOpenAliasException, String>{
        const CsOpenAliasInvalidAliasException('m', alias: a):
            'Enter a valid address or OpenAlias.',
        const CsOpenAliasNoRecordException('m', alias: a):
            'No Monero OpenAlias record was found for alice.example.',
        const CsOpenAliasAmbiguousException('m', alias: a):
            'This alias has multiple Monero addresses. '
            'Ask the recipient for an address.',
        const CsOpenAliasInvalidRecordException('m', alias: a):
            'This alias has an invalid or unsupported Monero record for '
            'this wallet.',
        const CsOpenAliasDnssecException(
          'm',
          alias: a,
          status: CsOpenAliasDnssecStatus.bogus,
        ): 'DNSSEC verification failed or is unavailable. '
            'Ask the recipient for a verified alias or address.',
        const CsOpenAliasDnsException('m', alias: a):
            'The DNS lookup for alice.example failed. '
            'No address was accepted.',
        const CsOpenAliasNetworkException('m', alias: a):
            'OpenAlias lookup failed. Check your connection and try again.',
        const CsOpenAliasCancelledException('m', alias: a):
            'OpenAlias lookup cancelled.',
      };
      expect(expected, hasLength(8));
      expected.forEach((error, text) => expect(error.userMessage, text));
      expect(openAliasLookupFailedTitle, 'OpenAlias lookup failed');
    });
  });

  test('a recipient keeps an unmodifiable copy of its fields', () {
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
    expect(() => recipient.fields['x'] = 'y', throwsUnsupportedError);
  });

  test('a dropped failed operation raises no uncaught error', () async {
    final uncaught = <Object>[];
    await runZonedGuarded(() async {
      CsOpenAliasOperation<void>.failed(
        CsOpenAliasCancelledException('dropped', alias: 'a.example'),
      );
      CsOpenAliasOperation<void>(
        Future<void>.error(
          CsOpenAliasNetworkException('dropped', alias: 'a.example'),
        ),
        () {},
      );
      await Future<void>.delayed(Duration.zero);
    }, (error, _) => uncaught.add(error));
    expect(uncaught, isEmpty);
  });
}
