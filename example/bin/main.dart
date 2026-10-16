import 'dart:io';

import 'package:cs_openalias/cs_openalias.dart';

const _usage =
    'Usage: dart run bin/main.dart <alias> [<proxy ip> <proxy port>]';

Future<void> main(List<String> args) async {
  final port = args.length == 3 ? int.tryParse(args[2]) : null;
  if (args.length != 1 && port == null) {
    stderr.writeln(_usage);
    exitCode = 64;
    return;
  }
  final operation = resolveOpenAlias(
    args[0],
    // A wallet checks that the address is valid for its network here.
    isValidAddress: (address) => address.isNotEmpty,
    proxy: port == null ? null : CsOpenAliasProxy(address: args[1], port: port),
  );
  try {
    final recipient = await operation.result;
    print('${recipient.domain}: ${recipient.address}');
    final name = recipient.fields['recipient_name'];
    if (name != null) print('recipient_name (unverified): $name');
  } on CsOpenAliasException catch (error) {
    stderr.writeln('${_describe(error)} ($error)');
    exitCode = 1;
  }
}

String _describe(CsOpenAliasException error) => switch (error) {
  CsOpenAliasInvalidAliasException() => 'Not an OpenAlias name',
  CsOpenAliasNoRecordException() => 'No Monero address is published there',
  CsOpenAliasAmbiguousException() => 'More than one address is published',
  CsOpenAliasInvalidRecordException() => 'The published record is unusable',
  CsOpenAliasDnssecException() => 'The answer is not signed with DNSSEC',
  CsOpenAliasDnsException() => 'The DNS lookup failed',
  CsOpenAliasNetworkException() => 'The resolver could not be reached',
  CsOpenAliasCancelledException() => 'Cancelled',
};
