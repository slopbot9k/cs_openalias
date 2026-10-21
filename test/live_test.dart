import 'dart:io';

import 'package:cs_openalias/cs_openalias.dart';
import 'package:test/test.dart';

void main() {
  final skip = Platform.environment['OPENALIAS_LIVE_TESTS'] != '1';

  Future<CsOpenAliasRecipient> resolve(String alias) => resolveOpenAlias(
    alias,
    isValidAddress: (address) => address.isNotEmpty,
    proxy: null,
  ).result;

  test('a signed alias resolves through dns.google', () async {
    final recipient = await resolve('donate@getmonero.org');
    expect(recipient.domain, 'donate.getmonero.org');
    expect(recipient.address, isNotEmpty);
  }, skip: skip);

  test('a name under a nonexistent TLD has no record', () async {
    await expectLater(
      resolve('dan@cypherstack'),
      throwsA(isA<CsOpenAliasNoRecordException>()),
    );
  }, skip: skip);

  for (final (alias, status) in [
    ('openalias.org', CsOpenAliasDnssecStatus.insecure),
    ('dnssec-failed.org', CsOpenAliasDnssecStatus.bogus),
  ]) {
    test('$alias is rejected as ${status.name}', () async {
      await expectLater(
        resolve(alias),
        throwsA(
          isA<CsOpenAliasDnssecException>().having(
            (error) => error.status,
            'status',
            status,
          ),
        ),
      );
    }, skip: skip);
  }
}
