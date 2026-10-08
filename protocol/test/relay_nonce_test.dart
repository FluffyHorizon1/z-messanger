// The client refuses a relay challenge nonce that is not exactly 32 bytes
// (PROTOCOL §12.1, P1-16a).
//
// The v2 signature concatenates the relay's authority with the nonce. The
// nonce is the fixed-width last field, so the concatenation is unambiguous —
// but only if its width is fixed. A relay that could vary the nonce length
// could move where the authority ends and the nonce begins under the
// signature, which is a splicing surface. Every relay since v1.0.0 sends
// exactly `crypto.randomBytes(32)`, so refusing any other length breaks no
// real relay and refuses only one trying something.
//
// This drives the Dart client against a scripted WebSocket server that offers
// a challenge of a chosen nonce length, and asserts the client signs a 32-byte
// one and refuses a 31- or 33-byte one WITHOUT sending any auth frame.
//
// Criteria, each a test below:
//   1. a 31-byte nonce is refused, with a reason, and no signature is sent;
//   2. a 33-byte nonce is refused likewise;
//   3. a 32-byte nonce is accepted — so it is the length that decides, not the
//      harness.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

/// A relay that challenges with a nonce of [nonceLen] bytes and records any
/// auth frame it is sent.
class NonceRelay {
  NonceRelay(this.server, this.nonceLen);
  final HttpServer server;
  final int nonceLen;
  final auths = <Map<String, Object?>>[];

  /// Completes when the client's socket has closed. Frames on one socket
  /// arrive in order, so anything the client sent — an auth frame included —
  /// has been recorded by then.
  final clientGone = Completer<void>();

  static Future<NonceRelay> start(int nonceLen) async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final relay = NonceRelay(server, nonceLen);
    server.listen((req) async {
      final ws = await WebSocketTransformer.upgrade(req);
      ws.add(jsonEncode({
        't': 'challenge',
        'nonce': base64Encode(List<int>.generate(nonceLen, (i) => (i * 5 + 1) & 0xff)),
        'auth': 2,
      }));
      ws.listen((d) {
        final f = (jsonDecode(d as String) as Map).cast<String, Object?>();
        if (f['t'] == 'auth') {
          relay.auths.add(f);
          ws.add(jsonEncode({'t': 'ready', 'id': 'x'}));
        }
      }, onDone: () {
        if (!relay.clientGone.isCompleted) relay.clientGone.complete();
      });
    });
    return relay;
  }

  int get port => server.port;
  Future<void> close() => server.close(force: true);
}

Future<void> expectRefused(int nonceLen) async {
  final relay = await NonceRelay.start(nonceLen);
  addTearDown(relay.close);
  final me = await ZIdentity.generate();
  await expectLater(
    RelayClient.connect('ws://127.0.0.1:${relay.port}', me, timeout: const Duration(seconds: 3)),
    throwsA(isA<RelayException>().having(
        (e) => e.message, 'message', contains('$nonceLen-byte challenge nonce'))),
  );
  // Wait on the observable, not a clock: the refusing client closes its
  // socket, and by then any frame it sent has arrived.
  await relay.clientGone.future.timeout(const Duration(seconds: 5),
      onTimeout: () => fail('timed out waiting for: the client to close the refused socket'));
  expect(relay.auths, isEmpty,
      reason: 'the client signed nothing for a $nonceLen-byte nonce');
}

void main() {
  test('1. a 31-byte challenge nonce is refused, and nothing is signed', () async {
    await expectRefused(31);
  });

  test('2. a 33-byte challenge nonce is refused, and nothing is signed', () async {
    await expectRefused(33);
  });

  test('3. a 32-byte challenge nonce is accepted — it is the length that decides', () async {
    final relay = await NonceRelay.start(32);
    addTearDown(relay.close);
    final me = await ZIdentity.generate();
    final c = await RelayClient.connect('ws://127.0.0.1:${relay.port}', me);
    addTearDown(c.close);
    expect(relay.auths.length, 1, reason: 'a 32-byte nonce is signed');
    expect(relay.auths.single['v'], 2);
  });
}
