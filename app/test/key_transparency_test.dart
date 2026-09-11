// The transparency log's client against the real log service (kt/server.js)
// and the real relay — ADR 0006's table, one row per test, driven from the
// outside: what a contact sees in each state, what is held, and what the
// account's owner is told.
//
// Criteria, each a test below:
//  1. two accounts that pair are in the log after their first check, and a
//     device list that arrives in-band and is published is confirmed;
//  2. a list that arrives in-band and is NOT published is unconfirmed, and
//     after the grace period the device only that list added is held — no
//     envelope is encrypted for it — until the list is published;
//  3. a list the log holds and the contact never received in-band is
//     fetched, verified and installed from the log (11.5);
//  4. a log entry at the same version as the in-band list with a different
//     fingerprint is a conflict: sends are held until "send anyway", and the
//     account's owner is told of the entry they did not issue;
//  5. a head that does not extend the accepted one is a log fault: nothing
//     new is confirmed, and resetting the history recovers;
//  6. an unreachable log degrades to in-band verification.
@Tags(['integration'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/key_transparency.dart';
import 'package:zapp/core/models.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:z_protocol/z_protocol.dart';

Future<int> freePort() async {
  final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final port = probe.port;
  await probe.close();
  return port;
}

Future<void> waitHealthy(int port) async {
  for (var i = 0; i < 80; i++) {
    try {
      final res = await (await HttpClient().getUrl(Uri.parse('http://127.0.0.1:$port/health'))).close();
      await res.drain<void>();
      if (res.statusCode == 200) return;
    } catch (_) {}
    await Future<void>.delayed(const Duration(milliseconds: 100));
  }
  fail('service on $port did not start');
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  final root = Directory.current.parent.path;
  late Process relay;
  late int relayPort;
  late Process log;
  late int logPort;
  late Uint8List logPub;
  final logSeed = Uint8List.fromList(List<int>.generate(32, (i) => (i * 7 + 3) & 0xff));
  final temps = <Directory>[];
  final services = <ChatService>[];
  final extraProcesses = <Process>[];

  Future<Process> startLog(int port, {Uint8List? seed}) async {
    final p = await Process.start('node', ['server.js'],
        workingDirectory: '$root${Platform.pathSeparator}kt',
        environment: {
          'KT_SEED': [for (final b in seed ?? logSeed) b.toRadixString(16).padLeft(2, '0')].join(),
          'KT_EPHEMERAL': '1',
          'KT_PORT': '$port',
          'PUBLISH_PER_MIN': '1000',
        });
    p.stderr.drain<void>();
    p.stdout.drain<void>();
    await waitHealthy(port);
    return p;
  }

  setUpAll(() async {
    HttpOverrides.global = null;
    relayPort = await freePort();
    relay = await Process.start('node', ['server.js'],
        workingDirectory: '$root${Platform.pathSeparator}server',
        environment: {'PORT': '$relayPort', 'LOG_LEVEL': 'silent'});
    await waitHealthy(relayPort);
    logPort = await freePort();
    log = await startLog(logPort);
    final kp = await Ed25519().newKeyPairFromSeed(logSeed);
    logPub = Uint8List.fromList((await kp.extractPublicKey()).bytes);
  });

  tearDownAll(() async {
    for (final s in services) {
      s.dispose();
      await s.transport.stop();
    }
    relay.kill();
    log.kill();
    for (final p in extraProcesses) {
      p.kill();
    }
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  KtConfig cfg({int? port}) =>
      KtConfig(logUrl: 'http://127.0.0.1:${port ?? logPort}', logPubB64: b64(logPub));

  Future<ChatService> start(String name, {KtConfig? config}) async {
    final dir = await Directory.systemTemp.createTemp('z_kt_$name');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    final id = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(id.toJson()));
    final transport = Transport(identity: id, serverUrl: 'ws://127.0.0.1:$relayPort');
    final svc = await ChatService.init(
        vault: vault,
        identity: id,
        displayName: name,
        transport: transport,
        ktConfig: config ?? cfg());
    svc.kt.recheckDelay = const Duration(milliseconds: 50);
    services.add(svc);
    return svc;
  }

  Future<void> waitUntil(bool Function() cond,
      {Duration timeout = const Duration(seconds: 25), String what = ''}) async {
    final deadline = DateTime.now().add(timeout);
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 30));
    }
  }

  Future<(ChatService, ChatService)> pair(String a, String b) async {
    final x = await start(a);
    final y = await start(b);
    await waitUntil(() => x.transport.isConnected && y.transport.isConnected, what: 'connected');
    await x.addContactFromCode(await y.myContactCode());
    await y.addContactFromCode(await x.myContactCode());
    await x.sendText(y.myRid, 'hi');
    await y.sendText(x.myRid, 'hi back');
    await waitUntil(() => x.messagesByChat[y.myRid]?.length == 2 && y.messagesByChat[x.myRid]?.length == 2,
        what: 'first exchange');
    return (x, y);
  }

  /// Re-check until [cond] holds: the periodic check is hours apart and a
  /// publish from the other side lands on its own time.
  Future<void> checkUntil(ChatService svc, bool Function() cond, {String what = ''}) async {
    final deadline = DateTime.now().add(const Duration(seconds: 25));
    while (true) {
      await svc.kt.check();
      if (cond()) return;
      if (DateTime.now().isAfter(deadline)) throw TimeoutException('condition not met: $what');
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
  }

  Future<void> heldVersion(ChatService svc, String rid, int v) async {
    var got = 0;
    await waitUntil(() {
      unawaited(svc.heldContactListVersion(rid).then((x) => got = x));
      return got >= v;
    }, what: 'held list reaches v$v');
  }

  Future<Map<String, Object?>> lookup(int port, Uint8List acctPub) async {
    final label = await ktLabel(acctPub);
    final hex = [for (final b in label) b.toRadixString(16).padLeft(2, '0')].join();
    final res = await (await HttpClient().getUrl(Uri.parse('http://127.0.0.1:$port/kt/v1/lookup/$hex'))).close();
    return (jsonDecode(await res.transform(utf8.decoder).join()) as Map).cast<String, Object?>();
  }

  Future<int> logVersionOf(int port, ChatService svc) async {
    final acct = await svc.accountIdentity();
    final j = await lookup(port, acct.accountEdPub);
    final e = j['entry'];
    return e == null ? 0 : ((e as Map)['v'] as num).toInt();
  }

  test('paired accounts are in the log after a check, and a published list is confirmed', () async {
    final (alice, ben) = await pair('alice', 'ben');
    // Each service ran a check at start; these make the order certain.
    await alice.kt.check();
    await ben.kt.check();
    await alice.kt.check();
    // Both roots published their baseline (version 1).
    expect(await logVersionOf(logPort, alice), 1);
    expect(await logVersionOf(logPort, ben), 1);
    expect(alice.kt.health, KtHealth.ok);
    expect(alice.kt.statusOf(ben.myRid)?.state, KtContactState.confirmed);
    expect(alice.kt.statusOf(ben.myRid)?.logVersion, 1);
    expect(ben.kt.statusOf(alice.myRid)?.state, KtContactState.confirmed);

    // Ben links a laptop: the list (v2) goes to Alice in-band and to the log.
    final acct = await ben.accountIdentity();
    final laptop = await ZIdentity.generate();
    final cert = await acct.signDeviceCert(deviceEdPub: laptop.edPub, deviceXPub: laptop.xPub, deviceId: 'laptop');
    await ben.addMyDevice(cert);
    await heldVersion(alice, ben.myRid, 2);
    await checkUntil(alice, () => alice.kt.statusOf(ben.myRid)?.logVersion == 2,
        what: 'the in-band list is checked against the log once the publish lands');
    expect(alice.kt.statusOf(ben.myRid)?.state, KtContactState.confirmed);
    expect(alice.kt.heldRids(ben.myRid), isEmpty);
    expect(await logVersionOf(logPort, ben), 2);
    expect(ben.kt.ownAlert, isNull);
  });

  test('a list that is not published is unconfirmed, and past the grace period the device it added is held', () async {
    final (alice, ben) = await pair('alice2', 'ben2');
    await alice.kt.check();
    await ben.kt.check();
    // Ben's log client goes quiet: a list he now signs reaches Alice in-band
    // and never the log — the split-view shape (T2) from Alice's side.
    ben.kt.config = KtConfig.off;
    final acct = await ben.accountIdentity();
    final rogue = await ZIdentity.generate();
    final cert = await acct.signDeviceCert(deviceEdPub: rogue.edPub, deviceXPub: rogue.xPub, deviceId: 'rogue');
    await ben.addMyDevice(cert);
    await heldVersion(alice, ben.myRid, 2);
    alice.kt.grace = const Duration(hours: 24);
    await alice.kt.check();
    final s = alice.kt.statusOf(ben.myRid)!;
    expect(s.state, KtContactState.unconfirmed);
    expect(s.logVersion, 1);
    expect(s.heldRids, isEmpty, reason: 'within the grace period nothing is held');
    // The grace period ends.
    alice.kt.grace = Duration.zero;
    await alice.kt.check();
    final rogueRid = await rogue.routingId();
    expect(alice.kt.heldRids(ben.myRid), {rogueRid});
    expect(alice.kt.sendsHeld(ben.myRid), isFalse, reason: 'unconfirmed holds a device, not the conversation');
    // A message from Alice: encrypted for Ben's phone, not for the rogue
    // device — counted in the outbox, which is where every envelope starts.
    await alice.sendText(ben.myRid, 'still here');
    await waitUntil(() => alice.messagesByChat[ben.myRid]!.last.status != MsgStatus.pending, what: 'sent');
    final rows = await alice.vault.db.query('outbox');
    expect(rows.where((r) => r['rid'] == rogueRid), isEmpty, reason: 'nothing was ever queued for the held device');
    // Ben publishes after all: the hold lifts on the next check.
    ben.kt.config = cfg();
    await ben.kt.check();
    expect(await logVersionOf(logPort, ben), 2);
    await alice.kt.check();
    expect(alice.kt.statusOf(ben.myRid)?.state, KtContactState.confirmed);
    expect(alice.kt.heldRids(ben.myRid), isEmpty);
  });

  test('a list the log holds and the contact never received is installed from the log (11.5)', () async {
    final (alice, ben) = await pair('alice3', 'ben3');
    await alice.kt.check();
    await ben.kt.check();
    // Alice goes offline; Ben links a device. The in-band list waits at the
    // relay; the log has it now.
    await alice.transport.stop();
    final acct = await ben.accountIdentity();
    final laptop = await ZIdentity.generate();
    final cert = await acct.signDeviceCert(deviceEdPub: laptop.edPub, deviceXPub: laptop.xPub, deviceId: 'laptop');
    await ben.addMyDevice(cert);
    var v = 0;
    for (var i = 0; i < 100 && v < 2; i++) {
      v = await logVersionOf(logPort, ben);
      if (v < 2) await Future<void>.delayed(const Duration(milliseconds: 50));
    }
    expect(v, 2, reason: 'the log holds v2');
    expect(await alice.heldContactListVersion(ben.myRid), 1);
    await alice.kt.check();
    expect(await alice.heldContactListVersion(ben.myRid), 2, reason: 'installed from the log');
    final s = alice.kt.statusOf(ben.myRid)!;
    expect(s.state, KtContactState.confirmed);
    expect(s.logVersion, 2);
    expect(s.confirmedDevs.length, 2);
  });

  test('a log entry at the held version with another fingerprint is a conflict: sends held until "send anyway"; the owner is told', () async {
    final (alice, ben) = await pair('alice4', 'ben4');
    await alice.kt.check();
    await ben.kt.check();
    // Someone holding Ben's account seed publishes a v2 list to the log that
    // Ben's own device never issued — then Ben's root issues an honest v2.
    final acct = await ben.accountIdentity();
    final fakeFp = Uint8List.fromList(List<int>.filled(16, 0x42));
    final req = await ktPublishRequest(
        accountEdSeed: acct.accountEdSeed!,
        version: 2,
        fp: fakeFp,
        value: await ktSealValue(acct.accountEdPub, utf8.encode('{"not":"a list"}')));
    final post = await (await HttpClient().postUrl(Uri.parse('http://127.0.0.1:$logPort/kt/v1/publish'))
          ..headers.contentType = ContentType.json
          ..write(jsonEncode(req)))
        .close();
    expect(post.statusCode, 201);
    await post.drain<void>();
    // Ben's owner check: an entry for his label he did not issue.
    await ben.kt.check();
    expect(ben.kt.ownAlert, isNotNull);
    expect(ben.kt.ownAlert!.version, 2);
    // Now Ben's honest v2 reaches Alice in-band (its publish is refused by
    // the log as stale — the rogue entry holds the version).
    final laptop = await ZIdentity.generate();
    final cert = await acct.signDeviceCert(deviceEdPub: laptop.edPub, deviceXPub: laptop.xPub, deviceId: 'laptop');
    await ben.addMyDevice(cert);
    await heldVersion(alice, ben.myRid, 2);
    await alice.kt.check();
    final s = alice.kt.statusOf(ben.myRid)!;
    expect(s.state, KtContactState.conflict);
    expect(alice.kt.sendsHeld(ben.myRid), isTrue);
    await expectLater(alice.sendText(ben.myRid, 'held?'), throwsA(isA<KtSendHeldException>()));
    // Receipts and the like still flow: nothing protocol-level is held.
    expect(alice.kt.heldRids(ben.myRid), isEmpty);
    await alice.kt.acknowledgeConflict(ben.myRid);
    expect(alice.kt.sendsHeld(ben.myRid), isFalse);
    await alice.sendText(ben.myRid, 'sent anyway');
    await waitUntil(() => ben.messagesByChat[alice.myRid]!.any((m) => m.body == 'sent anyway'), what: 'delivered');
    // The acknowledgement survives a check that finds the same conflict.
    await alice.kt.check();
    expect(alice.kt.statusOf(ben.myRid)!.state, KtContactState.conflict);
    expect(alice.kt.sendsHeld(ben.myRid), isFalse);
  });

  test('a head that does not extend the accepted one is a log fault; resetting the history recovers', () async {
    // A log of its own for this pair, so the sizes are known exactly.
    final honestPort = await freePort();
    extraProcesses.add(await startLog(honestPort));
    final alice = await start('alice5', config: cfg(port: honestPort));
    final ben = await start('ben5', config: cfg(port: honestPort));
    await waitUntil(() => alice.transport.isConnected && ben.transport.isConnected, what: 'connected');
    await alice.addContactFromCode(await ben.myContactCode());
    await ben.addContactFromCode(await alice.myContactCode());
    await alice.kt.check();
    await ben.kt.check();
    await alice.kt.check(); // a head that includes both publishes
    expect(alice.kt.health, KtHealth.ok);
    expect(alice.kt.head!.size, 2);
    // A second log under the same key, with a different history: what a
    // forked or replaced log looks like to a client holding the real head.
    final forkPort = await freePort();
    extraProcesses.add(await startLog(forkPort));
    final s1 = await start('stranger5a', config: cfg(port: forkPort));
    await s1.kt.check(); // the fork has one entry
    alice.kt.config = cfg(port: forkPort);
    await alice.kt.check();
    expect(alice.kt.health, KtHealth.fault);
    expect(alice.kt.fault!.reason, contains('shrank'));
    // Nothing new is confirmed while the fault stands: the held head is the real one.
    expect(alice.kt.head!.size, 2);
    // The fork grows past the real log's size: still refused, now as a fork —
    // its consistency proof from 2 to 3 cannot reach the real root at 2.
    final s2 = await start('stranger5b', config: cfg(port: forkPort));
    await s2.kt.check();
    final s3 = await start('stranger5c', config: cfg(port: forkPort));
    await s3.kt.check();
    alice.kt.fault = null; // the same client asking again, without a reset
    await alice.vault.kvDelete('kt_fault');
    await alice.kt.check();
    expect(alice.kt.health, KtHealth.fault);
    expect(alice.kt.fault!.reason, contains('fork'));
    expect(alice.kt.head!.size, 2);
    // The user resets the log's history (a deliberate change of log): the
    // fork's head is accepted as the new base.
    await alice.kt.resetHistory();
    await alice.kt.check();
    expect(alice.kt.health, KtHealth.ok);
    expect(alice.kt.head!.size, greaterThanOrEqualTo(3));
    // Ben is not in that log: unlogged, nothing held.
    expect(alice.kt.statusOf(ben.myRid)?.state, KtContactState.unlogged);
    expect(alice.kt.heldRids(ben.myRid), isEmpty);
  });

  test('an unreachable log degrades to in-band verification and says so', () async {
    final dead = await freePort();
    final (alice, ben) = await pair('alice6', 'ben6');
    await alice.kt.check();
    final before = alice.kt.statusOf(ben.myRid)?.state;
    alice.kt.config = cfg(port: dead);
    await alice.kt.check();
    // A recent head still counts: the log is "ok, last seen a moment ago"
    // until the unreachable threshold, a day in production.
    expect(alice.kt.health, KtHealth.ok);
    alice.kt.unreachableAfter = Duration.zero;
    expect(alice.kt.health, KtHealth.unreachable);
    expect(alice.kt.statusOf(ben.myRid)?.state, before, reason: 'what was known is kept');
    expect(alice.kt.sendsHeld(ben.myRid), isFalse);
    await alice.sendText(ben.myRid, 'still works');
    await waitUntil(() => ben.messagesByChat[alice.myRid]!.any((m) => m.body == 'still works'), what: 'delivered');
    // Back on the real log.
    alice.kt.config = cfg();
    alice.kt.unreachableAfter = const Duration(hours: 24);
    await alice.kt.check();
    expect(alice.kt.health, KtHealth.ok);
  });
}
