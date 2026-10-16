import 'dart:async';

import 'package:cs_openalias/cs_openalias.dart';
import 'package:openalias/openalias.dart' show OpenAliasInvalidNameException;
import 'package:test/test.dart';

typedef _Resolve =
    CsOpenAliasOperation<CsOpenAliasRecipient> Function(
      String alias, {
      required bool Function(String address) isValidAddress,
      CsOpenAliasProxy? proxy,
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
          isA<CsOpenAliasInvalidAliasException>().having(
            (error) => error.cause,
            'cause',
            isA<OpenAliasInvalidNameException>(),
          ),
        ),
        reason: input,
      );
    }
  });

  test('an invalid alias fails the operation before any network', () async {
    final operation = resolveOpenAlias(
      'not-a-domain',
      isValidAddress: (_) => true,
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
        CsOpenAliasInvalidAliasException('m', cause: cause),
        CsOpenAliasNoRecordException('m', cause: cause),
        CsOpenAliasAmbiguousException('m', cause: cause),
        CsOpenAliasInvalidRecordException('m', cause: cause),
        CsOpenAliasDnsException('m', cause: cause),
        CsOpenAliasNetworkException('m', cause: cause),
        CsOpenAliasCancelledException('m', cause: cause),
      ]) {
        expect(error.toString(), '${error.runtimeType}: m');
        expect(error.cause, same(cause));
        expect(_leaf(error), isNotEmpty);
      }
    });

    test('structured leaves print their fields', () {
      final dnssec = CsOpenAliasDnssecException(
        'not secure',
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
    for (final ttl in [-1, 0x80000000]) {
      expect(
        () => CsOpenAliasRecipient(
          domain: 'alice.example',
          address: 'address',
          application: 'xmr',
          canonicalName: 'alice.example',
          ttl: ttl,
          fields: const {},
        ),
        throwsArgumentError,
      );
    }
  });

  test('a dropped failed operation raises no uncaught error', () async {
    final uncaught = <Object>[];
    await runZonedGuarded(() async {
      CsOpenAliasOperation<void>.failed(
        const CsOpenAliasCancelledException('dropped'),
      );
      CsOpenAliasOperation<void>(
        Future<void>.error(const CsOpenAliasNetworkException('dropped')),
        () {},
      );
      await Future<void>.delayed(Duration.zero);
    }, (error, _) => uncaught.add(error));
    expect(uncaught, isEmpty);
  });
}
