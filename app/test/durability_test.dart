// Crash/restart durability fuzz (roadmap Phase 0.2).
//
// Kills and restarts a client repeatedly while messages are in flight in both
// directions — a restart lands between an awaited send (which has queued to the
// durable outbox) and the async flush that actually ships it, and while inbound
// envelopes may be delivered-but-not-yet-acked. After the churn we assert the
// three durability properties: no message LOSS, no DUPLICATION, and no ratchet
// DESYNC (a fresh round-trip still decrypts).
//
// A "crash + restart" is: stop the socket, dispose the service, close the vault
// DB, then re-open a brand-new ChatService on the SAME on-disk vault. Nothing
// in memory carries over — everything that survives does so because it was
// persisted (outbox rows, ratchet state, inbox-dedupe rows).
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

typedef Client = ({ChatService svc, Vault vault});

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  late Process relay;
  late int port;
  final temps = <Directory>[];

  setUpAll(() async {
    HttpOverrides.global = null;
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
    relay.kill();
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<Client> open(Directory dir, ZIdentity id, String name) async {
    final vault = await Vault.open(rootOverride: dir);
    await vault.kvPut('identity', jsonEncode(id.toJson()));
    final transport =
        Transport(identity: id, serverUrl: 'ws://127.0.0.1:$port');
    final svc = await ChatService.init(
        vault: vault, identity: id, displayName: name, transport: transport);
    return (svc: svc, vault: vault);
  }

  // Simulate a crash + relaunch: nothing in memory survives.
  Future<Client> restart(Client c, Directory dir, ZIdentity id, String name) async {
    await c.svc.transport.stop();
    c.svc.dispose();
    await c.vault.db.close();
    return open(dir, id, name);
  }

  Future<void> waitUntil(bool Function() cond,
      {Duration timeout = const Duration(seconds: 45),
      required String what}) async {
    final deadline = DateTime.now().add(timeout);
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
  }

  Future<void> waitUntilAsync(Future<bool> Function() cond,
      {Duration timeout = const Duration(seconds: 45),
      required String what}) async {
    final deadline = DateTime.now().add(timeout);
    while (!await cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
  }

  /// Wait for a freshly-added pair to have finished introducing themselves,
  /// instead of sleeping a second and hoping — the same copied second, and
  /// the same wait that replaced it, as `settled()` in `replies_test.dart`
  /// (whose comments carry the reasoning): a positive signal first, each
  /// side holding the other's post-quantum key, which means the requests
  /// crossed, the hello landed and a session exists; then quiescence, the
  /// outbox read last and the send flag re-read after it.
  Future<void> settled(List<ChatService> pair) async {
    final deadline = DateTime.now().add(const Duration(seconds: 25));
    while (true) {
      var done = true;
      for (final s in pair) {
        for (final o in pair) {
          if (identical(s, o)) continue;
          final c = s.contacts[o.myRid];
          if (c == null) continue;
          if (c.pqPub == null && c.pqCandidate == null) done = false;
        }
      }
      if (done) {
        for (final s in pair) {
          if ((await s.vault.db.query('outbox', limit: 1)).isNotEmpty) {
            done = false;
            break;
          }
        }
      }
      if (done && pair.every((s) => !s.pqSendPending)) return;
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('the pair never settled');
      }
      await Future<void>.delayed(const Duration(milliseconds: 30));
    }
  }

  Future<List<String>> inbound(ChatService svc, String rid) async {
    final msgs = await svc.loadMessages(rid);
    return [
      for (final m in msgs)
        if (!m.outgoing && m.kind == 'text') m.body
    ];
  }

  test('messages survive repeated crash/restart: no loss, no dup, no desync',
      () async {
    final aliceDir = await Directory.systemTemp.createTemp('z_dur_alice');
    final bobDir = await Directory.systemTemp.createTemp('z_dur_bob');
    temps..add(aliceDir)..add(bobDir);
    final aliceId = await ZIdentity.generate();
    final bobId = await ZIdentity.generate();

    var alice = await open(aliceDir, aliceId, 'alice');
    var bob = await open(bobDir, bobId, 'bob');
    await waitUntil(
        () => alice.svc.transport.isConnected && bob.svc.transport.isConnected,
        what: 'both connected');

    // Verified contacts both ways.
    await alice.svc.addContactFromCode(await bob.svc.myContactCode());
    await bob.svc.addContactFromCode(await alice.svc.myContactCode());
    final aliceRid = alice.svc.myRid;
    final bobRid = bob.svc.myRid;
    // The churn below is meant to start from an established pair, not from
    // the middle of its introduction.
    await settled([alice.svc, bob.svc]);

    // Fire messages both directions, restarting a side at pseudo-random points
    // (index-derived, since Random() is unavailable in this harness). Each send
    // is awaited (so it is committed to the outbox), but the flush that ships it
    // is async — so a restart right after can catch queued-but-unshipped mail.
    const n = 30;
    var restarts = 0;
    for (var i = 0; i < n; i++) {
      await alice.svc.sendText(bobRid, 'a$i');
      await bob.svc.sendText(aliceRid, 'b$i');
      if (i % 5 == 2) {
        alice = await restart(alice, aliceDir, aliceId, 'alice');
        restarts++;
      }
      if (i % 7 == 4) {
        bob = await restart(bob, bobDir, bobId, 'bob');
        restarts++;
      }
      await Future<void>.delayed(const Duration(milliseconds: 25));
    }
    expect(restarts, greaterThan(6), reason: 'fuzz should have churned devices');

    // Everything must arrive exactly once on each side, despite the churn.
    await waitUntilAsync(() async {
      final b = (await inbound(bob.svc, aliceRid)).length;
      final a = (await inbound(alice.svc, bobRid)).length;
      return b >= n && a >= n;
    }, what: 'all $n messages each way stored after the churn');

    final bobInbox = await inbound(bob.svc, aliceRid);
    final aliceInbox = await inbound(alice.svc, bobRid);
    final wantFromAlice = {for (var i = 0; i < n; i++) 'a$i'};
    final wantFromBob = {for (var i = 0; i < n; i++) 'b$i'};

    // No loss.
    expect(bobInbox.toSet(), wantFromAlice,
        reason: 'Bob lost/gained messages: $bobInbox');
    expect(aliceInbox.toSet(), wantFromBob,
        reason: 'Alice lost/gained messages: $aliceInbox');
    // No duplication (set size == list length).
    expect(bobInbox.length, n, reason: 'Bob has duplicates: $bobInbox');
    expect(aliceInbox.length, n, reason: 'Alice has duplicates: $aliceInbox');

    // No desync: a fresh round-trip after all the churn still decrypts.
    await alice.svc.sendText(bobRid, 'after-a');
    await bob.svc.sendText(aliceRid, 'after-b');
    await waitUntilAsync(
        () async =>
            (await inbound(bob.svc, aliceRid)).contains('after-a') &&
            (await inbound(alice.svc, bobRid)).contains('after-b'),
        what: 'the post-churn round trip in both directions');

    await alice.svc.transport.stop();
    await bob.svc.transport.stop();
  }, timeout: const Timeout(Duration(minutes: 3)));
}
