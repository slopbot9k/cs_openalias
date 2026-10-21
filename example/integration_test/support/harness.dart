import 'dart:convert';
import 'dart:io';

import 'package:cs_openalias/cs_openalias.dart';
import 'package:cs_openalias/src/resolver.dart';
import 'package:cs_openalias/src/transport.dart';

import 'test_pki.dart';

/// dnssec_resolver's signed zones, from `tool/generate_fixtures.sh`.
final class Fixtures {
  final String anchor;
  final Map<String, List<int>> _messages;

  Fixtures._(this.anchor, this._messages);

  factory Fixtures.load() {
    final json =
        jsonDecode(
              File('integration_test/support/zones.json').readAsStringSync(),
            )
            as Map<String, dynamic>;
    return Fixtures._(json['anchor'] as String, {
      for (final MapEntry(:key, :value)
          in (json['messages'] as Map<String, dynamic>).entries)
        key: base64Decode(value as String),
    });
  }

  /// The fixture answer to [query] with its ID and question, or an empty
  /// NOERROR answer for a name the zones do not cover.
  List<int> reply(List<int> query) {
    var offset = 12;
    final labels = <String>[];
    while (query[offset] != 0) {
      final length = query[offset];
      labels.add(ascii.decode(query.sublist(offset + 1, offset + 1 + length)));
      offset += 1 + length;
    }
    final questionEnd = offset + 5;
    final type = query[offset + 1] << 8 | query[offset + 2];
    final question = query.sublist(12, questionEnd);
    final message = _messages['${labels.join('.')}.:$type'];
    if (message == null) {
      return [
        query[0],
        query[1],
        0x81,
        0x80,
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        ...question,
      ];
    }
    var end = 12;
    while (message[end] != 0) {
      end += 1 + message[end];
    }
    return [
      query[0],
      query[1],
      ...message.sublist(2, 12),
      ...question,
      ...message.sublist(end + 5),
    ];
  }
}

/// A loopback DoH server over TLS that answers from [fixtures].
final class FixtureServer {
  final HttpServer _server;
  final Fixtures fixtures;
  int requests = 0;

  /// Replaces the fixture answer for every request when set.
  Future<void> Function(HttpRequest request)? respond;

  FixtureServer._(this._server, this.fixtures) {
    _server.listen(_handle);
  }

  static Future<FixtureServer> start(Fixtures fixtures, TestPki pki) async =>
      FixtureServer._(
        await HttpServer.bindSecure(
          InternetAddress.loopbackIPv4,
          0,
          pki.serverContext(),
        ),
        fixtures,
      );

  int get port => _server.port;
  Uri get endpoint => Uri.parse('https://localhost:$port/dns-query');

  Future<void> _handle(HttpRequest request) async {
    requests++;
    final query = [for (final chunk in await request.toList()) ...chunk];
    final respond = this.respond;
    if (respond != null) return respond(request);
    request.response
      ..headers.contentType = ContentType('application', 'dns-message')
      ..add(fixtures.reply(query));
    await request.response.close();
  }

  Future<void> close() => _server.close(force: true);
}

/// A TLS server that reads requests and never answers.
final class SilentServer {
  final SecureServerSocket _server;
  final _sockets = <Socket>[];
  int received = 0;
  int closed = 0;

  SilentServer._(this._server) {
    _server.listen((socket) {
      _sockets.add(socket);
      socket.listen(
        (data) => received += data.length,
        onDone: () {
          closed++;
          socket.destroy();
        },
        onError: (Object _) => closed++,
      );
    }, onError: (Object _) {});
  }

  static Future<SilentServer> start(TestPki pki) async => SilentServer._(
    await SecureServerSocket.bind(
      InternetAddress.loopbackIPv4,
      0,
      pki.serverContext(),
    ),
  );

  int get connections => _sockets.length;
  Uri get endpoint => Uri.parse('https://localhost:${_server.port}/dns-query');

  Future<void> close() async {
    for (final socket in _sockets) {
      socket.destroy();
    }
    await _server.close();
  }
}

/// Runs lookups through the real transport and validator against a loopback
/// resolver at [endpoint].
final class Harness {
  final Uri endpoint;
  final SecurityContext clientContext;
  final Fixtures fixtures;
  int opened = 0;
  int closes = 0;

  Harness(this.endpoint, this.clientContext, this.fixtures);

  CsOpenAliasOperation<CsOpenAliasRecipient> start(
    String alias, {
    CsOpenAliasProxy? proxy,
    bool Function(String address)? isValidAddress,
    Duration? lookupTimeout,
  }) => startOpenAliasLookup(
    alias,
    isValidAddress: isValidAddress ?? (address) => address == 'valid',
    proxy: proxy,
    openTransport: (proxy) {
      opened++;
      final transport = openDohTransport(
        proxy,
        resolver: (
          endpoint: endpoint,
          destination: InternetAddress.loopbackIPv4,
        ),
        securityContext: clientContext,
      );
      return (
        wire: transport.wire,
        endpoint: transport.endpoint,
        close: () {
          closes++;
          transport.close();
        },
      );
    },
    lookup: (domain, port, timeout) => dnssecLookup(
      domain,
      port,
      lookupTimeout ?? timeout,
      trustAnchors: fixtures.anchor,
    ),
  );
}

Future<void> until(bool Function() condition) async {
  for (var i = 0; i < 400 && !condition(); i++) {
    await Future<void>.delayed(const Duration(milliseconds: 5));
  }
  if (!condition()) throw StateError('Condition not reached');
}
