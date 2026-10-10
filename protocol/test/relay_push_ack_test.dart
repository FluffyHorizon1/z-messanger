// Push frames that wait for the relay's answer (phase 41).
//
// A registration and a withdrawal were fire-and-forget, so a client could not
// know the relay had either — and a withdrawal made with no connection was
// simply lost. `registerPushAcked` and `unregisterPushAcked` resolve on the
// relay's `push-ok`. The relay answers both with the same frame and handles
// frames concurrently, so the client keeps one in flight at a time: with two
// out, neither the answer nor the order the relay applied them in would say
// which one stands. This drives the Dart client against a scripted relay, so
// what is asserted is what the client sends and when it says it is done.
//
// Criteria, each a test below:
//   1. A push frame resolves only on the relay's `push-ok`, and a second one
//      is not sent until the first is answered — a frame sent after both is
//      on the wire before the second.
//   2. A refusal fails the waiting frame with the relay's code, and the next
//      queued frame still goes.
//   3. A connection that closes fails the waiting frame.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

/// A relay that authenticates anyone, records every frame after that, and
/// answers a push frame only when the test says how.
class ScriptedRelay {
  ScriptedRelay(this.server);
  final HttpServer server;
  final frames = <Map<String, Object?>>[];
  WebSocket? socket;
  final _arrived = StreamController<Map<String, Object?>>.broadcast();

  static Future<ScriptedRelay> start() async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final relay = ScriptedRelay(server);
    server.listen((req) async {
      final ws = await WebSocketTransformer.upgrade(req);
      relay.socket = ws;
      ws.add(jsonEncode({
        't': 'challenge',
        'nonce': base64Encode(List<int>.filled(32, 7)),
        'auth': 2,
      }));
      ws.listen((d) {
        final f = (jsonDecode(d as String) as Map).cast<String, Object?>();
        if (f['t'] == 'auth') {
          ws.add(jsonEncode({'t': 'ready', 'id': 'x'}));
          return;
        }
        if (f['t'] == 'ping') return;
        relay.frames.add(f);
        relay._arrived.add(f);
      });
    });
    return relay;
  }

  /// The next frame of type [t] to arrive, or one already here at [from].
  Future<Map<String, Object?>> frame(String t, {int from = 0}) async {
    for (final f in frames.skip(from)) {
      if (f['t'] == t) return f;
    }
    return _arrived.stream.firstWhere((f) => f['t'] == t);
  }

  void answer(Map<String, Object?> frame) => socket!.add(jsonEncode(frame));

  int get port => server.port;
  Future<void> close() => server.close(force: true);
}

void main() {
  late ScriptedRelay relay;
  late RelayClient client;

  setUp(() async {
    relay = await ScriptedRelay.start();
    client = await RelayClient.connect(
        'ws://127.0.0.1:${relay.port}', await ZIdentity.generate());
  });

  tearDown(() async {
    await client.close();
    await relay.close();
  });

  test('1. one push frame at a time, each done on its push-ok', () async {
    var registered = false, withdrawn = false;
    final reg = client
        .registerPushAcked(token: 'tok')
        .then((_) => registered = true);
    final unreg =
        client.unregisterPushAcked().then((_) => withdrawn = true);
    await relay.frame('push-register');
    // A barrier on the same socket: frames leave in order, so had the
    // withdrawal gone out with the registration it would be here first.
    client.ackReceived(id: 'barrier', from: '');
    await relay.frame('recv');
    expect(relay.frames.map((f) => f['t']), ['push-register', 'recv'],
        reason: 'the withdrawal went out before the registration was '
            'answered');
    expect(registered, isFalse, reason: 'done before the relay said so');

    relay.answer({'t': 'push-ok'});
    await reg;
    expect(registered, isTrue);
    await relay.frame('push-unregister');
    expect(withdrawn, isFalse);
    relay.answer({'t': 'push-ok'});
    await unreg;
    expect(withdrawn, isTrue);
  });

  test('2. a refusal fails the frame with its code; the next still goes',
      () async {
    final refused = client.registerPushAcked(token: 'tok');
    final next = client.unregisterPushAcked();
    await relay.frame('push-register');
    relay.answer({'t': 'error', 'code': 'push_refused'});
    await expectLater(
        refused,
        throwsA(isA<RelayException>()
            .having((e) => e.message, 'message', 'push_refused')));
    await relay.frame('push-unregister');
    relay.answer({'t': 'error', 'code': 'unknown_frame'});
    await expectLater(
        next,
        throwsA(isA<RelayException>()
            .having((e) => e.message, 'message', 'unknown_frame')));
  });

  test('3. a connection that closes fails the waiting frame', () async {
    final waiting = client.unregisterPushAcked();
    await relay.frame('push-unregister');
    await relay.socket!.close();
    await expectLater(
        waiting,
        throwsA(isA<RelayException>()
            .having((e) => e.message, 'message', 'connection closed')));
  });
}
