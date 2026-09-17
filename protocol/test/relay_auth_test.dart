// The client's half of relay authentication v2 (PROTOCOL §12.1).
//
// v1 signed the nonce alone, so a signature said nothing about WHICH relay
// had asked: a relay the user was induced to connect to could hand them the
// honest relay's nonce as its own challenge and replay the answer there,
// authenticated as that device (the 2026-09-14 review's finding 13). v2 puts
// the relay's authority — what the client dialled, as `relayAuthority`
// spells it — under the signature.
//
// The relay half is `server/test/auth_binding.test.js`. This file drives
// the Dart client against a scripted WebSocket server, so what is asserted
// is what the client sends and refuses, not what a relay does with it.
//
// Criteria, each a test below:
//   1. the client signs v2 over the authority it dialled, says so (`v: 2`),
//      and the signature verifies for that authority and for no other — in
//      particular not for a name the challenge itself offers, since a relay
//      that could name the authority could name the honest one;
//   2. a relay that does not advertise v2 gets no signature at all — not a
//      v1 one to be replayed — and the connection fails with a reason;
//   3. `relayAuthority` spells the authority the way the client's own Host
//      header does: lower-case, a default port dropped, a non-default one
//      kept, an IPv6 literal in brackets, a path and a trailing slash
//      ignored.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';
import 'package:z_protocol/src/util.dart' show concatBytes;
import 'package:z_protocol/z_protocol.dart';

/// A relay that only ever challenges, and records what it is answered.
class ScriptedRelay {
  ScriptedRelay(this.server, this.challenge);
  static const decoy = 'zmessengers.com';
  final HttpServer server;
  final Map<String, Object?> challenge;
  final auths = <Map<String, Object?>>[];
  final hosts = <String?>[];
  final nonce = Uint8List.fromList(List<int>.generate(32, (i) => (i * 7 + 3) & 0xff));

  static Future<ScriptedRelay> start({required bool advertiseV2}) async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final relay = ScriptedRelay(server, {
      't': 'challenge',
      'nonce': base64Encode(List<int>.generate(32, (i) => (i * 7 + 3) & 0xff)),
      if (advertiseV2) 'auth': 2,
      // Decoys: a hostile relay naming the honest one in its challenge. A
      // client that took the authority from the challenge rather than from
      // what it dialled would sign for the decoy — the replay, by invitation.
      'authority': decoy,
      'host': decoy,
    });
    server.listen((req) async {
      relay.hosts.add(req.headers.value('host'));
      final ws = await WebSocketTransformer.upgrade(req);
      ws.add(jsonEncode(relay.challenge));
      ws.listen((d) {
        final f = (jsonDecode(d as String) as Map).cast<String, Object?>();
        if (f['t'] == 'auth') {
          relay.auths.add(f);
          ws.add(jsonEncode({'t': 'ready', 'id': 'x'}));
        }
      });
    });
    return relay;
  }

  int get port => server.port;
  Future<void> close() => server.close(force: true);
}

Future<bool> verifies(Uint8List pub, List<int> msg, Uint8List sig) =>
    Ed25519().verify(msg,
        signature: Signature(sig, publicKey: SimplePublicKey(pub, type: KeyPairType.ed25519)));

void main() {
  test('1. the client signs v2 over the authority it dialled, and that alone', () async {
    final relay = await ScriptedRelay.start(advertiseV2: true);
    addTearDown(relay.close);
    final me = await ZIdentity.generate();
    final url = 'ws://127.0.0.1:${relay.port}';
    final c = await RelayClient.connect(url, me);
    addTearDown(c.close);
    expect(relay.auths.length, 1);
    final auth = relay.auths.single;
    expect(auth['v'], 2, reason: 'the frame says which form it is');
    expect(auth['pub'], b64(me.edPub));
    final sig = unb64(auth['sig'] as String);
    final authority = relayAuthority(url);
    expect(authority, '127.0.0.1:${relay.port}');
    expect(relay.hosts.single, authority, reason: 'and it is exactly the Host header the client sent');
    final over = (String a) => concatBytes([utf8.encode(authContextV2), utf8.encode(a), relay.nonce]);
    expect(await verifies(me.edPub, over(authority), sig), isTrue);
    expect(await verifies(me.edPub, over('127.0.0.1'), sig), isFalse, reason: 'the port is part of the name');
    expect(await verifies(me.edPub, over('evil.example'), sig), isFalse, reason: 'made for this relay and no other');
    expect(await verifies(me.edPub, over(ScriptedRelay.decoy), sig), isFalse,
        reason: 'the authority is what was dialled, not what the challenge says it is');
    expect(await verifies(me.edPub, concatBytes([utf8.encode(authContext), relay.nonce]), sig), isFalse,
        reason: 'and it is not a v1 signature under another name');
  });

  test('2. a relay that does not advertise v2 gets no signature, and the connection fails with a reason', () async {
    final relay = await ScriptedRelay.start(advertiseV2: false);
    addTearDown(relay.close);
    final me = await ZIdentity.generate();
    await expectLater(
        RelayClient.connect('ws://127.0.0.1:${relay.port}', me, timeout: const Duration(seconds: 3)),
        throwsA(isA<RelayException>().having((e) => e.message, 'message', contains('relay too old'))));
    await Future<void>.delayed(const Duration(milliseconds: 100));
    expect(relay.auths, isEmpty,
        reason: 'no v1 signature was produced for a relay that asked for one — that is the signature a hostile relay wants');
    // The anonymous connection is unaffected: it never answers the challenge.
    final anon = await RelayClient.connectAnonymous('ws://127.0.0.1:${relay.port}', me);
    addTearDown(anon.close);
    expect(anon.routingId, '');
    expect(relay.auths, isEmpty);
  });

  test('3. relayAuthority spells the name the way the Host header does', () {
    expect(relayAuthority('wss://zmessengers.com'), 'zmessengers.com');
    expect(relayAuthority('wss://ZMessengers.com/'), 'zmessengers.com');
    expect(relayAuthority('wss://relay.example:443'), 'relay.example');
    expect(relayAuthority('ws://relay.example:80/path'), 'relay.example');
    expect(relayAuthority('ws://relay.example:8080'), 'relay.example:8080');
    expect(relayAuthority('wss://relay.example:8443'), 'relay.example:8443');
    expect(relayAuthority('ws://127.0.0.1:1'), '127.0.0.1:1');
    expect(relayAuthority('ws://[::1]:8080'), '[::1]:8080');
    expect(relayAuthority('ws://[::1]'), '[::1]');
    expect(relayAuthority('  wss://zmessengers.com  '), 'zmessengers.com');
  });
}
