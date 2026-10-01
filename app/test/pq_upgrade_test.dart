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
    // An OS-assigned free port. The old formula derived the port from the
    // clock, so two suites starting in the same millisecond got the SAME
    // port — and `flutter test` runs files concurrently, so one relay lost
    // the bind and its whole file failed in setUpAll with 'relay did not
    // start'. Asking the OS removes the shared input entirely.
    final portProbe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    port = portProbe.port;
    await portProbe.close();
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

  /// Envelopes the relay holds that their recipient has not acknowledged.
  /// The RAM store keeps an envelope until it is acknowledged, delivered or
  /// not, so zero means everything sent so far has been taken off the relay
  /// — and handled, since a client acknowledges after handling.
  Future<int> relayUnacked() async {
    final res = await (await HttpClient()
            .getUrl(Uri.parse('http://127.0.0.1:$port/health')))
        .close();
    final body = await res.transform(utf8.decoder).join();
    return ((jsonDecode(body) as Map)['queuedEnvelopes'] as num).toInt();
  }

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
    // "The offerer needs a ciphertext first" is a claim about one instant:
    // the initiator holds the secret, and the ciphertext that would give it
    // to the offerer has not left yet. That instant has a name. It is the
    // commit of the initiator's first envelope sealed WITH the secret —
    // sealed, so it carries the ciphertext; not yet committed, so the
    // ciphertext exists nowhere outside the initiator — and
    // `debugBeforeSendCommit` runs exactly there, inside the conversation
    // lock that the inbound path establishing the secret also takes. This
    // used to be sampled straight after the positive wait below, which raced
    // the initiator's own unprompted sends (its identity exchange, a pqack):
    // every envelope it seals once it holds the secret carries the
    // ciphertext, so by then the offerer could hold it too, legitimately,
    // and `retry: 2` absorbed the difference.
    bool? offererPqAtFirstCiphertext;
    initiator.debugBeforeSendCommit = (rid) async {
      if (rid != offererRid) return;
      if (!await initiator.isPostQuantumWith(offererRid)) return;
      initiator.debugBeforeSendCommit = null; // the first such envelope only
      offererPqAtFirstCiphertext =
          await offerer.isPostQuantumWith(initiatorRid);
    };

    // The offerer adds the contact first so the initiator's hello is not
    // dropped as coming from a stranger (if it were, the upgrade would simply
    // happen one message later — see the next test).
    await offerer.addContactFromCode(await initiator.myContactCode());
    await initiator.addContactFromCode(await offerer.myContactCode());

    // Contact-add hello: the initiator opens the session, the offerer answers
    // with its ML-KEM key, the initiator encapsulates. Only the initiator can
    // prove it is post-quantum before anyone types.
    await waitUntil(() => initiator.isPostQuantumWith(offererRid),
        what: 'initiator holds the shared secret after the hello round trip');

    // The first real message carries it; from then on both sides are pq.
    await initiator.sendText(offererRid, 'first');
    // 'first' is sealed with the secret, so the gate has fired by now —
    // on it, or on an envelope that went before it.
    expect(offererPqAtFirstCiphertext, isFalse,
        reason: 'the offerer needs a ciphertext first');
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
  }, timeout: const Timeout(Duration(minutes: 2)));

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
    // ...but only if it lands before the offerer's own add, which nothing
    // here used to ensure: the add followed at once, and whenever the hello
    // was the slower of the two the session could open on it and the pair
    // go post-quantum before 'one' — every assertion below holds that way
    // too, so the test would pass without exercising what it is named for.
    // So: the initiator's outbox empty — the relay has accepted the hello
    // (and the identity key sent with it) — and THEN the relay holding
    // nothing unacknowledged, which means the offerer has taken them off
    // again while it was still a stranger. In that order: the relay alone
    // reads zero before the hello has left the outbox, too.
    await waitUntil(
        () async =>
            (await initiator.vault.db.query('outbox', limit: 1)).isEmpty &&
            await relayUnacked() == 0,
        what: "the offerer has taken the initiator's hello off the relay");
    await offerer.addContactFromCode(await initiator.myContactCode());
    // A 500 ms sleep stood here, equal to `pqSendDebounce` and covering
    // nothing: every step below waits on what it needs.

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
  }, timeout: const Timeout(Duration(minutes: 2)));
}
