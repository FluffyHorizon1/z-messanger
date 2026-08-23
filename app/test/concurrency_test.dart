// Regression test for the ratchet-serialization fix.
//
// Before the per-conversation lock, concurrent encrypt/decrypt on the same
// Conversation could reuse a message index and silently drop messages. This
// test drives two REAL ChatService instances through the REAL Node relay and
// fires a burst of simultaneous sends in both directions, then asserts that
// every message arrives exactly once and in order.
@Tags(['integration'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:z_protocol/z_protocol.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  // The test binding stubs out networking; restore real sockets so we can talk
  // to the actual relay process.
  HttpOverrides.global = null;

  late Process relay;
  late int port;
  final temps = <Directory>[];

  setUpAll(() async {
    HttpOverrides.global = null;
    final serverDir =
        '${Directory.current.parent.path}${Platform.pathSeparator}server';
    port = 41000 + DateTime.now().millisecondsSinceEpoch % 20000;
    relay = await Process.start('node', ['server.js'],
        workingDirectory: serverDir,
        environment: {'PORT': '$port', 'LOG_LEVEL': 'silent'});
    for (var i = 0; i < 60; i++) {
      try {
        final res = await (await HttpClient()
                .getUrl(Uri.parse('http://127.0.0.1:$port/health')))
            .close();
        await res.drain<void>();
        if (res.statusCode == 200) return;
      } catch (_) {
        await Future<void>.delayed(const Duration(milliseconds: 100));
      }
    }
    fail('relay did not start');
  });

  tearDownAll(() async {
    relay.kill();
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<ChatService> makeClient(String name) async {
    final dir = await Directory.systemTemp.createTemp('z_$name');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    final identity = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(identity.toJson()));
    final transport =
        Transport(identity: identity, serverUrl: 'ws://127.0.0.1:$port');
    final svc = await ChatService.init(
      vault: vault,
      identity: identity,
      displayName: name,
      transport: transport,
    );
    return svc;
  }

  Future<void> waitUntil(bool Function() cond,
      {Duration timeout = const Duration(seconds: 20)}) async {
    final deadline = DateTime.now().add(timeout);
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met');
      }
      await Future<void>.delayed(const Duration(milliseconds: 30));
    }
  }

  test('concurrent bidirectional sends never lose or corrupt messages',
      () async {
    final alice = await makeClient('alice');
    final bob = await makeClient('bob');

    // Wait for both to link to the relay.
    await waitUntil(() =>
        alice.transport.isConnected && bob.transport.isConnected);

    // Exchange verified contact codes both ways.
    final aliceCode = await alice.myContactCode();
    final bobCode = await bob.myContactCode();
    await alice.addContactFromCode(bobCode);
    await bob.addContactFromCode(aliceCode);
    final aliceRid = alice.myRid;
    final bobRid = bob.myRid;

    // Let the initial hello handshake settle.
    await Future<void>.delayed(const Duration(seconds: 1));

    const n = 15;
    // Fire a burst from BOTH sides concurrently — the stressful case that used
    // to corrupt the ratchet.
    final futures = <Future<void>>[];
    for (var i = 0; i < n; i++) {
      futures.add(alice.sendText(bobRid, 'a$i'));
      futures.add(bob.sendText(aliceRid, 'b$i'));
    }
    await Future.wait(futures);

    // Bob must receive all of Alice's a0..a14; Alice all of Bob's b0..b14.
    Future<List<String>> incoming(ChatService svc, String rid) async {
      final msgs = await svc.loadMessages(rid);
      return msgs
          .where((m) => !m.outgoing && m.kind == 'text')
          .map((m) => m.body)
          .toList();
    }

    // Poll until Bob and Alice have all 15 inbound, or timeout.
    await waitUntil(() {
      final bobGot = bob.messagesByChat[aliceRid]
              ?.where((m) => !m.outgoing && m.kind == 'text')
              .length ??
          0;
      final aliceGot = alice.messagesByChat[bobRid]
              ?.where((m) => !m.outgoing && m.kind == 'text')
              .length ??
          0;
      return bobGot >= n && aliceGot >= n;
    });

    final bobInbox = await incoming(bob, aliceRid);
    final aliceInbox = await incoming(alice, bobRid);

    // No loss, no duplication.
    expect(bobInbox.length, n, reason: 'Bob lost/dup messages: $bobInbox');
    expect(aliceInbox.length, n, reason: 'Alice lost/dup: $aliceInbox');
    expect(bobInbox.toSet(), {for (var i = 0; i < n; i++) 'a$i'});
    expect(aliceInbox.toSet(), {for (var i = 0; i < n; i++) 'b$i'});

    // In-order (ratchet indices preserved).
    expect(bobInbox, [for (var i = 0; i < n; i++) 'a$i']);
    expect(aliceInbox, [for (var i = 0; i < n; i++) 'b$i']);

    await alice.transport.stop();
    await bob.transport.stop();
  }, timeout: const Timeout(Duration(minutes: 2)));
}
