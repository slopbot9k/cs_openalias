import 'dart:async';
import 'dart:convert';

import 'package:cs_openalias/cs_openalias.dart';
import 'package:cs_openalias/src/resolver.dart';
import 'package:cs_openalias/src/transport.dart';
import 'package:dnssec_resolver/dnssec_resolver.dart';
import 'package:doh_transport/doh_transport.dart';
import 'package:openalias/openalias.dart' as oa;
import 'package:test/test.dart';

import 'support/fakes.dart';

const _alice = 'oa1:xmr recipient_address=valid; recipient_name=Alice;';

void main() {
  late FakeNetwork network;
  setUp(() => network = FakeNetwork());

  CsOpenAliasOperation<CsOpenAliasRecipient> start(
    FakeLookup lookup, {
    String alias = 'alice.example',
    bool Function(String)? isValidAddress,
    CsOpenAliasProxy? proxy,
  }) => startOpenAliasLookup(
    alias,
    isValidAddress: isValidAddress ?? (address) => address == 'valid',
    proxy: proxy,
    openTransport: network.open,
    lookup: lookup.start,
  );

  group('composition', () {
    test('a secure oa1:xmr record becomes the recipient', () async {
      final lookup = FakeLookup(() => answer('alice.example', [_alice]));
      final recipient = await start(lookup, alias: ' Alice@Example. ').result;

      expect(recipient.domain, 'alice.example');
      expect(recipient.address, 'valid');
      expect(recipient.application, 'xmr');
      expect(recipient.canonicalName, 'alice.example');
      expect(recipient.ttl, 300);
      expect(recipient.fields, {
        'recipient_address': 'valid',
        'recipient_name': 'Alice',
      });
      expect(lookup.calls.single.domain, 'alice.example');
      expect(lookup.calls.single.timeout, const Duration(seconds: 20));
      expect(lookup.calls.single.port, isA<DohDnssecPort>());
      expect(network.opened, [null]);
      expect(network.closes, 1);
    });

    test('a proxied lookup gets the proxy and the longer deadline', () async {
      const proxy = CsOpenAliasProxy(address: '127.0.0.1', port: 9050);
      final lookup = FakeLookup(() => answer('alice.example', [_alice]));
      await start(lookup, proxy: proxy).result;

      expect(network.opened, [same(proxy)]);
      expect(lookup.calls.single.timeout, const Duration(seconds: 40));
      expect(network.closes, 1);
    });

    test('the smallest TTL in the CNAME chain bounds caching', () async {
      final lookup = FakeLookup(
        () => answer(
          'alias.example',
          [_alice],
          canonicalName: 'bob.other.example',
          aliases: [
            DnssecRecord(
              name: 'alias.example',
              type: 5,
              ttl: 17,
              data: 'bob.other.example',
            ),
          ],
        ),
      );
      final recipient = await start(lookup, alias: 'alias.example').result;
      expect(recipient.domain, 'alias.example');
      expect(recipient.canonicalName, 'bob.other.example');
      expect(recipient.ttl, 17);
    });

    test('a TTL with the high bit set counts as zero', () async {
      final lookup = FakeLookup(
        () => answer('alice.example', [_alice], ttl: 0x80000000),
      );
      expect((await start(lookup).result).ttl, 0);
    });

    test('records of other applications are ignored undecoded', () async {
      final lookup = FakeLookup(
        () => answer('alice.example', [
          'v=spf1 -all',
          [0xff, 0xfe, 0x00],
          'oa1:btc recipient_address=bc1q;',
          'oa1:xmrv2 recipient_address=other;',
          _alice,
        ]),
      );
      expect((await start(lookup).result).address, 'valid');
    });

    test('a non-UTF-8 oa1:xmr record is an invalid record', () async {
      final lookup = FakeLookup(
        () => answer('alice.example', [
          [...ascii.encode('oa1:xmr recipient_address='), 0xff],
        ]),
      );
      await expectLater(
        start(lookup).result,
        throwsA(
          isA<CsOpenAliasInvalidRecordException>().having(
            (error) => error.cause,
            'cause',
            isA<oa.OpenAliasInvalidRecordException>(),
          ),
        ),
      );
      expect(network.closes, 1);
    });

    for (final (name, records, matcher, cause) in [
      (
        'no oa1:xmr record',
        ['oa1:btc recipient_address=bc1q;'],
        isA<CsOpenAliasNoRecordException>(),
        isA<oa.OpenAliasNoRecordException>(),
      ),
      (
        'two recipient addresses',
        [
          'oa1:xmr recipient_address=valid;',
          'oa1:xmr recipient_address=second;',
        ],
        isA<CsOpenAliasAmbiguousException>(),
        isA<oa.OpenAliasAmbiguousException>(),
      ),
      (
        'conflicting records for one address',
        [
          'oa1:xmr recipient_address=valid; recipient_name=A;',
          'oa1:xmr recipient_address=valid; recipient_name=B;',
        ],
        isA<CsOpenAliasAmbiguousException>(),
        isA<oa.OpenAliasAmbiguousException>(),
      ),
      (
        'tx_payment_id',
        ['oa1:xmr recipient_address=valid; tx_payment_id=abc;'],
        isA<CsOpenAliasInvalidRecordException>(),
        isA<oa.OpenAliasUnsupportedFieldException>(),
      ),
      (
        'a duplicate field',
        ['oa1:xmr recipient_address=valid; recipient_address=valid;'],
        isA<CsOpenAliasInvalidRecordException>(),
        isA<oa.OpenAliasDuplicateFieldException>(),
      ),
      (
        'a malformed record',
        ['oa1:xmr recipient_address'],
        isA<CsOpenAliasInvalidRecordException>(),
        isA<oa.OpenAliasInvalidRecordException>(),
      ),
      (
        'an oversized record',
        ['oa1:xmr recipient_address=valid; tx_description=${'x' * 4096};'],
        isA<CsOpenAliasInvalidRecordException>(),
        isA<oa.OpenAliasLimitExceededException>(),
      ),
      (
        'an address the wallet rejects',
        ['oa1:xmr recipient_address=invalid;'],
        isA<CsOpenAliasInvalidRecordException>(),
        isA<oa.OpenAliasInvalidAddressException>(),
      ),
    ]) {
      test('$name maps to its facade leaf', () async {
        final lookup = FakeLookup(() => answer('alice.example', records));
        await expectLater(
          start(lookup).result,
          throwsA(matcher.having((error) => error.cause, 'cause', cause)),
        );
        expect(network.closes, 1);
      });
    }

    for (final (status, expected) in [
      (DnssecStatus.insecure, CsOpenAliasDnssecStatus.insecure),
      (DnssecStatus.bogus, CsOpenAliasDnssecStatus.bogus),
      (DnssecStatus.indeterminate, CsOpenAliasDnssecStatus.indeterminate),
    ]) {
      test('a ${status.name} answer never reaches the selector', () async {
        var validated = 0;
        final lookup = FakeLookup(
          () => answer('alice.example', [_alice], status: status),
        );
        await expectLater(
          start(
            lookup,
            isValidAddress: (_) {
              validated++;
              return true;
            },
          ).result,
          throwsA(
            isA<CsOpenAliasDnssecException>()
                .having((error) => error.status, 'status', expected)
                .having(
                  (error) => error.cause,
                  'cause',
                  isA<DnssecValidationException>(),
                ),
          ),
        );
        expect(validated, 0);
      });
    }

    for (final (name, result) in [
      ('another question', answer('mallory.example', [_alice])),
      ('another record type', answer('alice.example', [_alice], recordType: 1)),
      (
        'a TXT owner other than the canonical name',
        _ForgedOwner(answer('alice.example', [_alice])),
      ),
      ('an inconsistent secure answer', answer('alice.example', [])),
    ]) {
      test('$name is a DNS failure', () async {
        var validated = 0;
        final lookup = FakeLookup(() => result);
        await expectLater(
          start(
            lookup,
            isValidAddress: (_) {
              validated++;
              return true;
            },
          ).result,
          throwsA(isA<CsOpenAliasDnsException>()),
        );
        expect(validated, 0);
        expect(network.closes, 1);
      });
    }
  });

  group('failure mapping', () {
    final stack = StackTrace.current;

    test('an invalid alias keeps the raw input', () async {
      final operation = start(FakeLookup(), alias: ' Not An Alias ');
      await expectLater(
        operation.result,
        throwsA(
          isA<CsOpenAliasInvalidAliasException>()
              .having((e) => e.alias, 'alias', ' Not An Alias ')
              .having(
                (e) => e.userMessage,
                'userMessage',
                'Enter a valid address or OpenAlias.',
              ),
        ),
      );
    });

    test('a mapped failure carries the normalised alias', () async {
      final lookup = FakeLookup(
        () => Future.error(const DnssecNoRecordsException('nx'), stack),
      );
      await expectLater(
        start(lookup, alias: ' Alice@Example. ').result,
        throwsA(
          isA<CsOpenAliasNoRecordException>()
              .having((e) => e.alias, 'alias', 'alice.example')
              .having(
                (e) => e.userMessage,
                'userMessage',
                'No Monero OpenAlias record was found for alice.example.',
              ),
        ),
      );
    });

    test('mapLookupFailure passes other errors through', () {
      final error = StateError('bug');
      expect(mapLookupFailure(error, stack, 'alice.example'), same(error));
    });
    for (final (error, matcher) in <(DnssecException, Matcher)>[
      (
        const DnssecNoRecordsException('nx'),
        isA<CsOpenAliasNoRecordException>(),
      ),
      (
        const DnssecInvalidNameException('name'),
        isA<CsOpenAliasInvalidAliasException>(),
      ),
      for (final error in const <DnssecException>[
        DnssecAliasAmbiguousException('ambiguous'),
        DnssecAliasTooLongException('long'),
        DnssecAliasLoopException('loop'),
        DnssecQueryFailedException('servfail'),
        DnssecQuestionMismatchException('question'),
        DnssecResponseTooLargeException('large'),
        DnssecMalformedResponseException('malformed'),
      ])
        (error, isA<CsOpenAliasDnsException>()),
      (
        DnssecValidationException('bogus', status: DnssecStatus.bogus),
        isA<CsOpenAliasDnssecException>().having(
          (error) => error.status,
          'status',
          CsOpenAliasDnssecStatus.bogus,
        ),
      ),
      (
        const DnssecTimeoutException(
          'deadline',
          timeout: Duration(seconds: 20),
        ),
        isA<CsOpenAliasNetworkException>().having(
          (error) => error.timeout,
          'timeout',
          const Duration(seconds: 20),
        ),
      ),
      (
        const DnssecUnavailableException('no validator'),
        isA<CsOpenAliasNetworkException>().having(
          (error) => error.timeout,
          'timeout',
          isNull,
        ),
      ),
      (
        DnssecTransportException('port', cause: StateError('port')),
        isA<CsOpenAliasNetworkException>(),
      ),
      (
        const DnssecCancelledException('cancelled'),
        isA<CsOpenAliasCancelledException>(),
      ),
    ]) {
      test('${error.runtimeType} keeps the error as cause', () async {
        final lookup = FakeLookup(() => Future.error(error, stack));
        await expectLater(
          start(lookup).result,
          throwsA(
            allOf(
              matcher,
              isA<CsOpenAliasException>()
                  .having((e) => e.cause, 'cause', same(error))
                  .having((e) => e.causeStackTrace, 'stack', same(stack))
                  .having((e) => e.message, 'message', error.message)
                  .having((e) => e.alias, 'alias', 'alice.example'),
            ),
          ),
        );
        expect(network.closes, 1);
      });
    }

    for (final (error, matcher) in <(DohTransportException, Matcher)>[
      for (final error in const <DohTransportException>[
        DohInvalidQueryException('query'),
        DohMalformedResponseException('content type'),
        DohResponseTooLargeException('large', limitBytes: 65535),
        DohQuestionMismatchException('question'),
      ])
        (error, isA<CsOpenAliasDnsException>()),
      for (final error in const <DohTransportException>[
        DohHttpStatusException('status', statusCode: 503),
        DohConnectionException('refused'),
        DohQueueFullException('full', maxQueuedRequests: 64),
      ])
        (
          error,
          isA<CsOpenAliasNetworkException>().having(
            (e) => e.timeout,
            'timeout',
            isNull,
          ),
        ),
      for (final error in const <DohTransportException>[
        DohRequestTimeoutException('request', timeout: Duration(seconds: 12)),
        DohConnectionTimeoutException(
          'connect',
          timeout: Duration(seconds: 12),
        ),
      ])
        (
          error,
          isA<CsOpenAliasNetworkException>().having(
            (e) => e.timeout,
            'timeout',
            const Duration(seconds: 12),
          ),
        ),
      for (final reason in [
        DohCancellationReason.caller,
        DohCancellationReason.transportClosed,
      ])
        (
          DohCancelledException('cancelled', reason: reason),
          isA<CsOpenAliasCancelledException>(),
        ),
    ]) {
      test('$error through the port keeps the transport error', () async {
        final transportStack = StackTrace.current;
        final lookup = FakeLookup(
          () => Future.error(
            DnssecTransportException(
              'DNS transport failed',
              cause: error,
              causeStackTrace: transportStack,
            ),
          ),
        );
        await expectLater(
          start(lookup).result,
          throwsA(
            allOf(
              matcher,
              isA<CsOpenAliasException>()
                  .having((e) => e.cause, 'cause', same(error))
                  .having(
                    (e) => e.causeStackTrace,
                    'stack',
                    same(transportStack),
                  )
                  .having((e) => e.message, 'message', error.message)
                  .having((e) => e.alias, 'alias', 'alice.example'),
            ),
          ),
        );
      });
    }

    test('programmer errors propagate unchanged', () async {
      final defect = StateError('validator defect');
      final lookup = FakeLookup(() => answer('alice.example', [_alice]));
      await expectLater(
        start(lookup, isValidAddress: (_) => throw defect).result,
        throwsA(same(defect)),
      );
      expect(network.closes, 1);

      final other = FakeLookup(() => throw defect);
      await expectLater(start(other).result, throwsA(same(defect)));
    });

    test('a lookup that throws on start closes the transport', () {
      expect(
        () => startOpenAliasLookup(
          'alice.example',
          isValidAddress: (_) => true,
          proxy: null,
          openTransport: network.open,
          lookup: (_, _, _) => throw ArgumentError('bad configuration'),
        ),
        throwsArgumentError,
      );
      expect(network.closes, 1);
    });
  });

  group('lifecycle', () {
    test('an invalid alias opens no transport', () async {
      final lookup = FakeLookup();
      await expectLater(
        start(lookup, alias: 'not-a-domain').result,
        throwsA(isA<CsOpenAliasInvalidAliasException>()),
      );
      expect(network.opened, isEmpty);
      expect(lookup.calls, isEmpty);
    });

    for (final proxy in const [
      CsOpenAliasProxy(address: 'localhost', port: 9050),
      CsOpenAliasProxy(address: '127.0.0.1', port: 0),
      CsOpenAliasProxy(address: '127.0.0.1', port: 65536),
    ]) {
      test('proxy ${proxy.address}:${proxy.port} is a programmer error', () {
        expect(() => start(FakeLookup(), proxy: proxy), throwsArgumentError);
        expect(network.opened, isEmpty);
      });
    }

    test('cancel ends the lookup and closes the transport once', () async {
      var validated = 0;
      final lookup = FakeLookup();
      final operation = start(
        lookup,
        isValidAddress: (_) {
          validated++;
          return true;
        },
      );
      await pumpEventQueue();
      expect(network.closes, 0);

      operation.cancel();
      operation.cancel();
      expect(lookup.cancels, 1);
      expect(network.closes, 1);
      await expectLater(
        operation.result,
        throwsA(
          isA<CsOpenAliasCancelledException>().having(
            (e) => e.alias,
            'alias',
            'alice.example',
          ),
        ),
      );

      lookup.completer.complete(answer('alice.example', [_alice]));
      await pumpEventQueue();
      expect(validated, 0);
      expect(network.closes, 1);
    });

    test('cancel after completion does nothing', () async {
      final lookup = FakeLookup(() => answer('alice.example', [_alice]));
      final operation = start(lookup);
      await operation.result;
      operation.cancel();
      expect(lookup.cancels, 0);
      expect(network.closes, 1);
    });

    test('concurrent lookups own their transports', () async {
      final first = FakeLookup();
      final second = FakeLookup();
      final cancelled = start(first);
      final surviving = start(second);
      cancelled.cancel();
      second.completer.complete(answer('alice.example', [_alice]));

      await expectLater(
        cancelled.result,
        throwsA(isA<CsOpenAliasCancelledException>()),
      );
      expect((await surviving.result).address, 'valid');
      expect(network.opened, hasLength(2));
      expect(network.closes, 2);
      expect(second.cancels, 0);
    });

    test('an unobserved failed lookup raises no uncaught error', () async {
      final uncaught = <Object>[];
      await runZonedGuarded(() async {
        start(FakeLookup(() => throw const DnssecUnavailableException('no')));
        start(FakeLookup(), alias: 'invalid');
        await pumpEventQueue();
      }, (error, _) => uncaught.add(error));
      expect(uncaught, isEmpty);
    });
  });
}

final class _ForgedOwner extends DnssecResult {
  _ForgedOwner(DnssecResult result)
    : super(
        question: result.question,
        recordType: result.recordType,
        canonicalName: result.canonicalName,
        status: result.status,
        records: result.records,
        aliases: result.aliases,
      );

  @override
  List<DnssecTxtRecord> secureTxt() => [
    for (final record in super.secureTxt())
      DnssecTxtRecord(
        name: 'mallory.example',
        ttl: record.ttl,
        bytes: record.bytes,
      ),
  ];
}
