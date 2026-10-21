import 'dart:async';

import 'exceptions.dart';

/// A SOCKS5 proxy, such as Tor, at a numeric IP [address]. Every lookup
/// through it uses fresh isolation credentials.
final class CsOpenAliasProxy {
  final String address;
  final int port;
  const CsOpenAliasProxy({required this.address, required this.port});
}

/// A recipient from a DNSSEC-secure `oa1:xmr` record.
final class CsOpenAliasRecipient {
  /// The normalised alias that was looked up.
  final String domain;
  final String address;

  /// Every field of the record. `recipient_name` and `tx_description` are
  /// untrusted display text.
  final Map<String, String> fields;

  CsOpenAliasRecipient({
    required this.domain,
    required this.address,
    required Map<String, String> fields,
  }) : fields = Map<String, String>.unmodifiable(fields);
}

/// A started lookup. [result] carries every failure; [cancel] is idempotent
/// and ends the lookup with [CsOpenAliasCancelledException].
final class CsOpenAliasOperation<T> {
  final Future<T> result;
  final void Function() cancel;

  CsOpenAliasOperation(this.result, this.cancel) {
    result.ignore();
  }

  factory CsOpenAliasOperation.failed(CsOpenAliasException error) =>
      CsOpenAliasOperation(Future<T>.error(error), () {});
}
