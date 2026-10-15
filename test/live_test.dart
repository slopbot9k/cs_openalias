import 'dart:io';

import 'package:cs_openalias/cs_openalias.dart';
import 'package:test/test.dart';

void main() {
  final skip = Platform.environment['OPENALIAS_LIVE_TESTS'] != '1';
  final resolver = CsOpenAliasResolver(
    validateAddress: (address) => address.isNotEmpty,
  );

  test(
    'live signed alias resolves through native DNSSEC and default DoH',
    () async {
      final result = await resolver.resolve('donate.getmonero.org');
      expect(result.domain, 'donate.getmonero.org');
      expect(result.address, isNotEmpty);
    },
    skip: skip,
  );

  test(
    'live nonexistent name remains distinct from a transport failure',
    () async {
      await expectLater(
        resolver.resolve('dan@cypherstack'),
        throwsA(isA<CsOpenAliasDnsNoRecordException>()),
      );
    },
    skip: skip,
  );

  for (final domain in ['openalias.org', 'dnssec-failed.org']) {
    test('live unsigned or bogus DNS is rejected: $domain', () async {
      await expectLater(
        resolver.resolve(domain),
        throwsA(isA<CsOpenAliasDnssecException>()),
      );
    }, skip: skip);
  }
}
