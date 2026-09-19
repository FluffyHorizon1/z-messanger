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
//     account's owner is told of the entry they did not issue — told on
//     disk, so the alert outlives the service that raised it; and a "send
//     anyway" is for the conflict on the screen: a later, different conflict
//     for the same contact holds sends again;
//  5. a head that does not extend the accepted one is a log fault: nothing
//     new is confirmed, and resetting the history recovers;
//  6. an unreachable log degrades to in-band verification.
@Tags(['integration'])
// Every test here pairs two clients through a real relay and then waits on
// a log round trip; 30 seconds (60 with the tag above) is not room for
// that on a loaded CI runner, and two of these were lost to it on a tag
// whose code was unchanged, both passing on the re-run. Two minutes is
// what `devlist_transparency_test.dart` already gives the same shape of
// test.
@Timeout(Duration(minutes: 2))
library;
//  7. a log that answers everything correctly EXCEPT that it leaves the
//     rogue entry out of the history is still caught: the authenticated
//     `latest` is judged too, not only what the history volunteers.
//  8. a test process contacts a log on loopback and no other: the defaults
//     name the production log, and every test that builds a ChatService
//     gets them.
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

/// A host with nothing in it: criterion 8 is about whether a request is made
/// at all, so there is nothing for the check to walk.
class _EmptyHost implements KtHost {
  @override
  Future<List<KtContactInput>> ktContacts() async => const [];
  @override
  Future<KtOwnInput?> ktOwn() async => null;
  @override
  Future<bool> ktInstallFromLog(String rid, SignedDeviceList list) async =>
      false;
  @override
  void ktChanged() {}
}

/// Counts what reached the network. Every answer is a failure, so a check
/// that DOES run cannot accidentally look like a check that was refused.
class _CountingFetcher implements KtFetcher {
  final List<Uri> gets = [];
  final List<Uri> posts = [];
  @override
  Future<KtResponse> get(Uri url) async {
    gets.add(url);
    return KtResponse(500, '{}');
  }

  @override
  Future<KtResponse> post(Uri url, String jsonBody) async {
    posts.add(url);
    return KtResponse(500, '{}');
  }
}

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
  final proxies = <HttpServer>[];

  Future<Process> startLog(int port, {Uint8List? seed}) async {
    final p = await Process.start('node', ['server.js'],
        workingDirectory: '$root${Platform.pathSeparator}kt',
        environment: {
          'KT_SEED': [for (final b in seed ?? logSeed) b.toRadixString(16).padLeft(2, '0')].join(),
          'KT_EPHEMERAL': '1',
          'KT_PORT': '$port',
          // Every publish gate is raised out of the way. One log service is
          // shared by the whole file (setUpAll), so all of these tests' publishes
          // — every pair()'s two first-publishes, every honest and every forged
          // v2 — share the four buckets, and the defaults (per-address 30, total
          // 120, per-account/day 20, new-accounts/min 10) trip partway through a
          // fast run: a later publish that should be 201 comes back 429. That is
          // what turned "a conflict … is held" into a red test on CI. These
          // limits are not what this file checks; kt/test/publish_limits.test.js
          // is where the gates themselves are exercised, one fresh service each.
          'PUBLISH_PER_MIN': '1000000',
          'PUBLISH_PER_MIN_TOTAL': '1000000',
          'PUBLISH_PER_ACCT_PER_DAY': '1000000',
          'PUBLISH_NEW_ACCOUNTS_PER_MIN': '1000000',
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
    for (final s in proxies) {
      await s.close(force: true);
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
    // A real-relay+log integration test: the grace-hold assertion is timing
    // bound and flaked once on a loaded CI runner, while passing alone (8/8)
    // and in the serialised suite. ADR 0010 does not touch this code path.
    // `retry:` matches this file's sibling tests and the wider suite — the
    // load-flake case, not the masking-a-behaviour case guarded elsewhere.
  }, retry: 2);

  test('re-sending the same list does not release a hold, and does not buy grace',
      () async {
    // The one cost ADR 0006 imposes on T2 used to be avoidable by
    // repetition. An attacker holding Ben's account root enrols a rogue
    // device and never publishes it; after the grace the rogue is held and
    // stops receiving; the attacker re-signs the SAME device set as a fresh
    // list and delivers it in-band, the hold drops the instant it arrives,
    // and the grace starts again. Every 23 hours, for ever.
    //
    // The list that "changed" did not remove the rogue — it re-asserted it,
    // which is the opposite of a reason to trust it again.
    final (alice, ben) = await pair('alice10', 'ben10');
    await alice.kt.check();
    await ben.kt.check();
    // Ben's log client goes quiet: the list he signs reaches Alice in-band
    // and never the log, which is the split-view shape (T2) the hold exists
    // to cost the attacker something for.
    ben.kt.config = KtConfig.off;
    final acct = await ben.accountIdentity();
    final rogue = await ZIdentity.generate();
    final cert = await acct.signDeviceCert(
        deviceEdPub: rogue.edPub, deviceXPub: rogue.xPub, deviceId: 'rogue');
    await ben.addMyDevice(cert);
    await heldVersion(alice, ben.myRid, 2);
    // Two checks, as test 2 does: the first records when the list went
    // unconfirmed, the second measures the grace against it.
    alice.kt.grace = const Duration(hours: 24);
    await alice.kt.check();
    alice.kt.grace = Duration.zero;
    await alice.kt.check();
    final rogueRid = await rogue.routingId();
    expect(alice.kt.heldRids(ben.myRid), {rogueRid}, reason: 'held to begin with');
    final since = alice.kt.statusOf(ben.myRid)!.unconfirmedSinceMs;
    expect(since, isNotNull);

    // The re-assertion: a fresh, genuinely signed list with the rogue still
    // on it. Nothing about it is forged — that is why the old code believed
    // it.
    alice.kt.noteContactListChanged(ben.myRid, stillPresent: {rogueRid, ben.myRid});
    expect(alice.kt.heldRids(ben.myRid), {rogueRid},
        reason: 'a list that still contains the device keeps its hold');
    expect(alice.kt.statusOf(ben.myRid)!.unconfirmedSinceMs, since,
        reason: 'and does not restart the grace, or re-sending would buy 24 hours');

    // And a list the install REFUSED must not clear it either. Ben sends a
    // device list signed by somebody else's account: `_installContactDeviceList`
    // returns early on the account-key check, so nothing was installed — and
    // the log used to be told a new list had arrived all the same, which made
    // "send a list the device will throw away" another way to buy 24 hours.
    // Ben's own list, with its signature corrupted: `list.verify()` fails, so
    // `_installContactDeviceList` returns without installing anything.
    final held = jsonDecode(
            (await alice.vault.kvGet('cdev_${ben.myRid}'))!)
        as Map<String, Object?>;
    final sigBytes = base64Decode(held['sig'] as String);
    sigBytes[0] ^= 0xff;
    held['sig'] = base64Encode(sigBytes);
    await ben.debugSendRawInner(
        alice.myRid,
        InnerMessage(
            kind: 'devlist',
            mid: newMessageId(),
            ts: DateTime.now().millisecondsSinceEpoch,
            data: {'list': jsonEncode(held)}));
    await Future<void>.delayed(const Duration(seconds: 2));
    expect(alice.kt.heldRids(ben.myRid), {rogueRid},
        reason: 'a list that was refused says nothing about the hold');
    expect(alice.kt.statusOf(ben.myRid)!.unconfirmedSinceMs, since,
        reason: 'nor about the grace');

    // A list that actually DROPS the rogue releases it, which is the whole
    // point of the hold being per-device.
    alice.kt.noteContactListChanged(ben.myRid, stillPresent: {ben.myRid});
    expect(alice.kt.heldRids(ben.myRid), isEmpty,
        reason: 'the device the new list removed is no longer held');
    expect(alice.kt.statusOf(ben.myRid)!.unconfirmedSinceMs, isNull,
        reason: 'and the clock restarts once there is nothing being held');
    // A real-relay+log grace test of the same shape as the two above it: it
    // passes alone (single-name isolation) but load-flakes in the full file,
    // where the shared relay carries every earlier test's traffic. It was the
    // last grace-hold case here without the `retry:` its siblings (this file's
    // "unconfirmed…held" and the loopback test) already carry; neutralising the
    // ADR 0011 add traffic did not change its flake rate, so this completes the
    // coverage rather than papering over that feature.
  }, retry: 2);

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
    // And the alert is on disk, not only in this object: a service built
    // over the same vault loads it. Until 2026-09-17 `kt_own_alert` was not
    // on `Vault.plainKeys`, so the write after the assignment above THREW —
    // this assertion passed on the in-memory field while the alert was never
    // persisted, the check pass aborted before its grace pass, and every
    // launch raised the exception again (finding 5). `check()` swallows,
    // which is why only a second service can tell.
    final reloaded = KeyTransparency(
        vault: ben.vault, host: _EmptyHost(), fetcher: _CountingFetcher(), config: cfg());
    await reloaded.load();
    expect(reloaded.ownAlert, isNotNull, reason: 'the alert survived the service that raised it');
    expect(reloaded.ownAlert!.version, 2);
    expect(reloaded.ownAlert!.fpB64, b64(fakeFp));
    await reloaded.acknowledgeOwnAlert();
    final again = KeyTransparency(
        vault: ben.vault, host: _EmptyHost(), fetcher: _CountingFetcher(), config: cfg());
    await again.load();
    expect(again.ownAlert, isNull, reason: 'and an acknowledgement is on disk too');
    reloaded.dispose();
    again.dispose();
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
    // And does NOT survive a different one. The log now serves a v3 entry
    // for Ben that does not open as his list at all — a more serious event
    // than the one Alice waved through, and until 2026-09-17 it arrived
    // acknowledged: no banner, no hold, no word (finding 11). "Send anyway"
    // was for what was on the screen.
    final rogue3 = await ktPublishRequest(
        accountEdSeed: acct.accountEdSeed!,
        version: 3,
        fp: Uint8List.fromList(List<int>.filled(16, 0x43)),
        value: await ktSealValue(acct.accountEdPub, utf8.encode('{"still":"not a list"}')));
    final post3 = await (await HttpClient().postUrl(Uri.parse('http://127.0.0.1:$logPort/kt/v1/publish'))
          ..headers.contentType = ContentType.json
          ..write(jsonEncode(rogue3)))
        .close();
    expect(post3.statusCode, 201);
    await post3.drain<void>();
    await alice.kt.check();
    final s3 = alice.kt.statusOf(ben.myRid)!;
    expect(s3.state, KtContactState.conflict);
    expect(s3.logVersion, 3);
    expect(s3.detail, contains('does not open'));
    expect(s3.acknowledged, isFalse, reason: 'new evidence, new question');
    expect(alice.kt.sendsHeld(ben.myRid), isTrue, reason: 'held again until the user answers this one');
    await expectLater(alice.sendText(ben.myRid, 'held again?'), throwsA(isA<KtSendHeldException>()));
    // Answered, it stays answered while the evidence stays.
    await alice.kt.acknowledgeConflict(ben.myRid);
    await alice.kt.check();
    expect(alice.kt.statusOf(ben.myRid)!.logVersion, 3);
    expect(alice.kt.sendsHeld(ben.myRid), isFalse, reason: 'the same v3 conflict, still acknowledged');
    // The longest round trip in the file, and the one observed to lose the
    // race with a loaded runner.
  }, retry: 2);

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

  test('7. a log that omits the rogue entry from its history is still caught',
      () async {
    // The failure this closes. `latest` is PROVED to be what the log serves
    // for this label, and it was read only to decide whether to publish;
    // everything that could raise an alert lived in the walk over the history
    // response. An empty history is not a fault — an account that has never
    // published legitimately has one — so a log that answered the head and
    // the lookup honestly and simply left the entry out of the history was
    // believed in full, and said nothing. The rogue value was authenticated,
    // served to every reader as current, and hidden from its owner.
    final honestPort = await freePort();
    extraProcesses.add(await startLog(honestPort));
    await waitHealthy(honestPort);

    // A proxy in front of it that forwards everything unchanged except the
    // history, which it empties. Nothing here forges anything: the head and
    // the lookup are the real log's, signed by the real key.
    final proxyPort = await freePort();
    final proxy = await HttpServer.bind(InternetAddress.loopbackIPv4, proxyPort);
    proxies.add(proxy);
    proxy.listen((req) async {
      final upstream = Uri.parse('http://127.0.0.1:$honestPort${req.uri}');
      try {
        if (req.method == 'POST') {
          final body = await utf8.decoder.bind(req).join();
          final r = await (await HttpClient().postUrl(upstream)
                ..headers.contentType = ContentType.json
                ..write(body))
              .close();
          final out = await utf8.decoder.bind(r).join();
          req.response.statusCode = r.statusCode;
          req.response.headers.contentType = ContentType.json;
          req.response.write(out);
          await req.response.close();
          return;
        }
        final r = await (await HttpClient().getUrl(upstream)).close();
        var out = await utf8.decoder.bind(r).join();
        if (req.uri.path.startsWith('/kt/v1/history/')) {
          final j = (jsonDecode(out) as Map).cast<String, Object?>();
          j['entries'] = <Object?>[]; // the one lie
          out = jsonEncode(j);
        }
        req.response.statusCode = r.statusCode;
        req.response.headers.contentType = ContentType.json;
        req.response.write(out);
        await req.response.close();
      } catch (_) {
        try {
          req.response.statusCode = 502;
          await req.response.close();
        } catch (_) {}
      }
    });

    final ben = await start('ben7', config: cfg(port: proxyPort));
    await ben.kt.check();
    expect(ben.kt.ownAlert, isNull, reason: 'nothing wrong yet');

    // Someone holding Ben's account seed publishes a list he never issued.
    final acct = await ben.accountIdentity();
    final fakeFp = Uint8List.fromList(List<int>.filled(16, 0x77));
    final req = await ktPublishRequest(
        accountEdSeed: acct.accountEdSeed!,
        version: 9,
        fp: fakeFp,
        value: await ktSealValue(
            acct.accountEdPub, utf8.encode('{"not":"his list"}')));
    final post = await (await HttpClient()
            .postUrl(Uri.parse('http://127.0.0.1:$honestPort/kt/v1/publish'))
          ..headers.contentType = ContentType.json
          ..write(jsonEncode(req)))
        .close();
    expect(post.statusCode, 201);
    await post.drain<void>();

    // The history says nothing. The lookup cannot: it is what the log is
    // serving, and it is signed.
    final h = await (await HttpClient().getUrl(Uri.parse(
            'http://127.0.0.1:$proxyPort/kt/v1/history/${[for (final b in await ktLabel(acct.accountEdPub)) b.toRadixString(16).padLeft(2, '0')].join()}')))
        .close();
    final hj = jsonDecode(await utf8.decoder.bind(h).join()) as Map;
    expect((hj['entries'] as List), isEmpty, reason: 'the log volunteers nothing');

    await ben.kt.check();
    expect(ben.kt.ownAlert, isNotNull,
        reason: 'the authenticated latest is judged, not only the history');
    expect(ben.kt.ownAlert!.version, 9);
    expect(ben.kt.ownAlert!.fpB64, b64(fakeFp));
  });

  test('8. a test process contacts a log on loopback and no other', () async {
    // The build-time defaults name the production log, and a test that builds
    // a ChatService gets them unless it says otherwise — which all but this
    // file did. That meant live lookups against kt.zmessengers.com from every
    // run, and publishes into it, because a test identity is a fresh account
    // root whose baseline list `ktOwn()` signs on demand. It also made the
    // suite depend on a network round trip: a check in flight overwrites a
    // contact status a test set on purpose.
    final dir = await Directory.systemTemp.createTemp('z_kt_guard');
    addTearDown(() => dir.delete(recursive: true).catchError((_) => dir));
    final vault = await Vault.open(rootOverride: dir);

    KeyTransparency ktWith(String url, _CountingFetcher f) => KeyTransparency(
          vault: vault,
          host: _EmptyHost(),
          fetcher: f,
          config: KtConfig(logUrl: url, logPubB64: b64(Uint8List(32))),
        );

    // The production log, named exactly as the shipped defaults name it.
    final live = _CountingFetcher();
    final toLive = ktWith('https://kt.zmessengers.com', live);
    toLive.start();
    await toLive.check();
    await Future<void>.delayed(const Duration(milliseconds: 50));
    expect(live.gets, isEmpty,
        reason: 'a test must not read from the production transparency log');
    expect(live.posts, isEmpty,
        reason: 'and must certainly not publish into it — an entry in an '
            'append-only log cannot be taken back');
    toLive.dispose();

    // Loopback is the exemption, and it has to actually work: this file's
    // other seven criteria are driven against a log on 127.0.0.1.
    final local = _CountingFetcher();
    final toLocal = ktWith('http://127.0.0.1:1', local);
    await toLocal.check();
    expect(local.gets, isNotEmpty,
        reason: 'a loopback log is what a test SHOULD be talking to');
    toLocal.dispose();
  });
}
