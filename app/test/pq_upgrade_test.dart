// Protocol v2 end to end: two real ChatService instances over the real relay
// upgrade to the post-quantum hybrid within the first exchange, and keep
// talking afterwards. The offer/ciphertext choreography is exercised through
// the app's own send and inbound paths (outbox, sealing, dedupe).
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
  HttpOverrides.global = null;

  late Process relay;
  late int port;
  final temps = <Directory>[];
  final services = <ChatService>[];

  setUpAll(() async {
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
    for (final s in services) {
      await s.transport.stop();
    }
    relay.kill();
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<ChatService> makeClient(String name) async {
    final dir = await Directory.systemTemp.createTemp('z_pq_$name');
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
        transport: transport);
    services.add(svc);
    return svc;
  }

  Future<void> waitUntil(Future<bool> Function() cond,
      {Duration timeout = const Duration(seconds: 30), String? what}) async {
    final deadline = DateTime.now().add(timeout);
    while (!await cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: ${what ?? ''}');
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
  }

  List<String> texts(ChatService svc, String rid) => [
        for (final m in svc.messagesByChat[rid] ?? const [])
          if (m.kind == 'text') m.body
      ];

  test('a fresh pair becomes post-quantum during its first exchange', () async {
    final alice = await makeClient('alice');
    final bob = await makeClient('bob');
    await waitUntil(
        () async => alice.transport.isConnected && bob.transport.isConnected,
        what: 'clients connect');
    final aliceRid = alice.myRid, bobRid = bob.myRid;
    // Roles follow routing-id order: the lower id is the designated initiator
    // (it sends the contact-add hello and later encapsulates); the other side
    // offers the ML-KEM key.
    final initiator = aliceRid.compareTo(bobRid) < 0 ? alice : bob;
    final offerer = identical(initiator, alice) ? bob : alice;
    final initiatorRid = identical(initiator, alice) ? aliceRid : bobRid;
    final offererRid = identical(initiator, alice) ? bobRid : aliceRid;
    // The offerer adds the contact first so the initiator's hello is not
    // dropped as coming from a stranger (if it were, the upgrade would simply
    // happen one message later — see the note at the end).
    await offerer.addContactFromCode(await initiator.myContactCode());
    await initiator.addContactFromCode(await offerer.myContactCode());

    // Contact-add hello: the initiator opens the session, the offerer answers
    // with its ML-KEM key, the initiator encapsulates. Only the initiator can
    // prove it is post-quantum before anyone types.
    await waitUntil(() => initiator.isPostQuantumWith(offererRid),
        what: 'initiator holds the shared secret after the hello round trip');
    expect(await offerer.isPostQuantumWith(initiatorRid), isFalse,
        reason: 'the offerer needs a ciphertext first');

    // The first real message carries it; from then on both sides are pq.
    await initiator.sendText(offererRid, 'first');
    await waitUntil(() async => texts(offerer, initiatorRid).contains('first'),
        what: 'first message arrives');
    expect(await offerer.isPostQuantumWith(initiatorRid), isTrue);
    await offerer.sendText(initiatorRid, 'second');
    await waitUntil(() async => texts(initiator, offererRid).contains('second'),
        what: 'reply arrives');
    expect(await initiator.isPostQuantumWith(offererRid), isTrue);

    // Steady state: a burst in both directions still delivers everything.
    for (var i = 0; i < 5; i++) {
      await initiator.sendText(offererRid, 'i$i');
      await offerer.sendText(initiatorRid, 'o$i');
    }
    await waitUntil(
        () async =>
            texts(offerer, initiatorRid)
                .toSet()
                .containsAll({for (var i = 0; i < 5; i++) 'i$i'}) &&
            texts(initiator, offererRid)
                .toSet()
                .containsAll({for (var i = 0; i < 5; i++) 'o$i'}),
        what: 'burst delivered both ways');
  }, timeout: const Timeout(Duration(minutes: 2)), retry: 2);

  test('adding contacts in the other order upgrades one message later',
      () async {
    final carol = await makeClient('carol');
    final dave = await makeClient('dave');
    await waitUntil(
        () async => carol.transport.isConnected && dave.transport.isConnected,
        what: 'clients connect');
    final carolRid = carol.myRid, daveRid = dave.myRid;
    final initiator = carolRid.compareTo(daveRid) < 0 ? carol : dave;
    final offerer = identical(initiator, carol) ? dave : carol;
    final initiatorRid = identical(initiator, carol) ? carolRid : daveRid;
    final offererRid = identical(initiator, carol) ? daveRid : carolRid;
    // Initiator adds first: its hello reaches a stranger and is dropped.
    await initiator.addContactFromCode(await offerer.myContactCode());
    await offerer.addContactFromCode(await initiator.myContactCode());
    await Future<void>.delayed(const Duration(milliseconds: 500));

    // First real message is classical (the session opens on it); it makes
    // the offerer offer, the initiator encapsulate, and the second message
    // from the initiator is post-quantum.
    await initiator.sendText(offererRid, 'one');
    await waitUntil(() async => texts(offerer, initiatorRid).contains('one'),
        what: 'first message arrives');
    await waitUntil(() => initiator.isPostQuantumWith(offererRid),
        what: 'offer arrives at the initiator');
    await initiator.sendText(offererRid, 'two');
    await waitUntil(() async => texts(offerer, initiatorRid).contains('two'),
        what: 'second message arrives');
    expect(await offerer.isPostQuantumWith(initiatorRid), isTrue);
    await offerer.sendText(initiatorRid, 'three');
    await waitUntil(() async => texts(initiator, offererRid).contains('three'),
        what: 'reply arrives');
  }, timeout: const Timeout(Duration(minutes: 2)), retry: 2);
}
