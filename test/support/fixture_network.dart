import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:cs_openalias/cs_openalias.dart';

final class Fixtures {
  final Map<String, dynamic> _json =
      jsonDecode(File('test/support/zones.json').readAsStringSync())
          as Map<String, dynamic>;

  String get anchor => _json['anchor'] as String;

  static (String, int, int) question(List<int> wire) {
    var offset = 12;
    final labels = <String>[];
    while (wire[offset] != 0) {
      final length = wire[offset++];
      labels.add(ascii.decode(wire.sublist(offset, offset + length)));
      offset += length;
    }
    offset++;
    return (
      '${labels.join('.')}.',
      wire[offset] * 256 + wire[offset + 1],
      offset + 4,
    );
  }

  List<int> reply(List<int> query) {
    final (name, type, end) = question(query);
    final encoded = (_json['messages'] as Map)['$name:$type'] as String?;
    var response = encoded == null
        ? <int>[
            0,
            0,
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
            ...query.sublist(12, end),
          ]
        : base64Decode(encoded).toList();
    if (encoded != null) {
      final responseQuestionEnd = question(response).$3;
      response = [
        ...response.sublist(0, 12),
        ...query.sublist(12, end),
        ...response.sublist(responseQuestionEnd),
      ];
    }
    response[0] = query[0];
    response[1] = query[1];
    return response;
  }
}

typedef ReplyMutation =
    List<int> Function(int request, List<int> query, List<int> reply);

final class FixtureNetworkFactory implements CsOpenAliasNetworkFactory {
  final Fixtures fixtures;
  final ReplyMutation? mutate;
  final Duration age;
  final int statusCode;
  final bool hang;
  final CsOpenAliasException? failure;
  final void Function(int request)? onStart;
  final List<FixtureNetworkSession> sessions = [];

  FixtureNetworkFactory(
    this.fixtures, {
    this.mutate,
    this.age = Duration.zero,
    this.statusCode = 200,
    this.hang = false,
    this.failure,
    this.onStart,
  });

  @override
  CsOpenAliasNetworkSession create(CsOpenAliasNetworkOptions options) {
    final session = FixtureNetworkSession._(
      fixtures,
      mutate: mutate,
      age: age,
      statusCode: statusCode,
      hang: hang,
      failure: failure,
      onStart: onStart,
    );
    sessions.add(session);
    return session;
  }
}

final class FixtureNetworkSession implements CsOpenAliasNetworkSession {
  final Fixtures fixtures;
  final ReplyMutation? mutate;
  final Duration age;
  final int statusCode;
  final bool hang;
  final CsOpenAliasException? failure;
  final void Function(int request)? onStart;
  final List<List<int>> queries = [];
  final List<Completer<CsOpenAliasWireResponse>> _pending = [];
  int cancellations = 0;
  int closes = 0;

  FixtureNetworkSession._(
    this.fixtures, {
    required this.mutate,
    required this.age,
    required this.statusCode,
    required this.hang,
    required this.failure,
    required this.onStart,
  });

  @override
  CsOpenAliasOperation<CsOpenAliasWireResponse> startWire(
    Uri endpoint,
    List<int> query, {
    required int maxResponseBytes,
  }) {
    final request = queries.length;
    final snapshot = List<int>.unmodifiable(query);
    queries.add(snapshot);
    onStart?.call(request);
    final configuredFailure = failure;
    if (configuredFailure != null) {
      return CsOpenAliasOperation.failed(configuredFailure);
    }
    final completer = Completer<CsOpenAliasWireResponse>();
    _pending.add(completer);
    if (!hang) {
      try {
        final reply = fixtures.reply(snapshot);
        completer.complete(
          CsOpenAliasWireResponse(
            statusCode,
            mutate == null ? reply : mutate!(request, snapshot, reply),
            age: age,
          ),
        );
      } catch (error, stack) {
        completer.completeError(
          CsOpenAliasNetworkException(
            'Fixture response construction failed',
            cause: error,
            causeStackTrace: stack,
          ),
          stack,
        );
      }
    }
    return CsOpenAliasOperation(completer.future, () {
      cancellations++;
      if (!completer.isCompleted) {
        completer.completeError(
          const CsOpenAliasCancelledException('fixture request cancelled'),
        );
      }
    });
  }

  @override
  Future<void> close() async {
    closes++;
    for (final pending in _pending) {
      if (!pending.isCompleted) {
        pending.completeError(
          const CsOpenAliasCancelledException('fixture session closed'),
        );
      }
    }
  }
}
