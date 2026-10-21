import 'dart:async';
import 'dart:convert';

import 'package:cs_openalias/cs_openalias.dart';
import 'package:cs_openalias/src/transport.dart';
import 'package:dnssec_resolver/dnssec_resolver.dart';
import 'package:doh_transport/doh_transport.dart';

final endpoint = Uri.https('resolver.example', '/dns-query');

/// Records every transport a lookup opens and every close.
final class FakeNetwork {
  final opened = <CsOpenAliasProxy?>[];
  final wire = FakeWire();
  int closes = 0;

  LookupTransport open(CsOpenAliasProxy? proxy) {
    opened.add(proxy);
    return (wire: wire, endpoint: endpoint, close: () => closes++);
  }
}

final class FakeExchange {
  final Uri uri;
  final List<int> query;
  final int maxResponseBytes;
  final completer = Completer<DohHttpResponse>();
  int cancels = 0;

  FakeExchange(this.uri, this.query, this.maxResponseBytes);
}

final class FakeWire implements DohWireTransport {
  final exchanges = <FakeExchange>[];

  @override
  DohTransportOperation<DohHttpResponse> startWire(
    Uri uri,
    List<int> query, {
    required int maxResponseBytes,
  }) {
    final exchange = FakeExchange(uri, query, maxResponseBytes);
    exchanges.add(exchange);
    return DohTransportOperation(
      exchange.completer.future,
      () => exchange.cancels++,
    );
  }
}

/// Stands in for the DNSSEC lookup; [answer] decides each outcome.
final class FakeLookup {
  final calls =
      <({String domain, DnssecWireTransport port, Duration timeout})>[];
  final completer = Completer<DnssecResult>();
  int cancels = 0;

  FakeLookup([FutureOr<DnssecResult> Function()? answer]) {
    if (answer != null) {
      completer.complete(Future.sync(answer));
    }
  }

  DnssecOperation<DnssecResult> start(
    String domain,
    DnssecWireTransport port,
    Duration timeout,
  ) {
    calls.add((domain: domain, port: port, timeout: timeout));
    return DnssecOperation(completer.future, () => cancels++);
  }
}

DnssecRecord txtRecord(String name, List<int> bytes, {int ttl = 300}) =>
    DnssecRecord(
      name: name,
      type: 16,
      ttl: ttl,
      data: latin1.decode(bytes),
      txt: bytes,
    );

DnssecResult answer(
  String question,
  List<Object> records, {
  DnssecStatus status = DnssecStatus.secure,
  String? canonicalName,
  List<DnssecRecord> aliases = const [],
  int ttl = 300,
}) {
  final owner = canonicalName ?? question;
  return DnssecResult(
    question: question,
    recordType: 16,
    canonicalName: owner,
    status: status,
    records: [
      for (final record in records)
        txtRecord(
          owner,
          record is String ? utf8.encode(record) : record as List<int>,
          ttl: ttl,
        ),
    ],
    aliases: aliases,
  );
}
