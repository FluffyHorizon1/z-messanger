// ADR 0017 stage 2 end to end: the v2-only device-list signer, switched on for
// ONE account through its test seam, among contacts running as shipped — the
// signer off, the stage-2a readers on — which is the population the flip will
// meet. Real clients, the real relay, and the real transparency log
// (kt/server.js) on loopback.
//
// Criteria, with the tests that cover them below. One flip is watched from
// every side it touches, so these are one test, the same one:
//   criteria 2 and 3 share a test,
//   criteria 3 and 4 share a test,
//   criteria 4 and 5 share a test,
//   criteria 5 and 6 share a test;
// and the floor and what the gossip makes of a refusal are one flow, so
//   criteria 7 and 8 share a test.
//   1. with the signer off everywhere — as shipped — nothing changes: a list
//      broadcast after linking a device is dual-signed, both sides report the
//      v1 fingerprint, the log confirms that fingerprint, and a restart moves
//      nothing;
//   2. with the signer on for one account, its next start republishes the
//      account's list once, at the next version, with sig3 alone — no sig, no
//      sig2 — and a second start republishes nothing;
//   3. every contact accepts it, and each computes the SAME fingerprint for it
//      as the account claims: the one over the v3 input;
//   4. the account's ML-DSA over it is over the v3 input — not the v1 or the
//      v2 one — and verifies at every contact, which reports the list
//      post-quantum verified;
//   5. the log commits to that fingerprint, and each contact's view of the
//      account in the log stays confirmed through the change — never a
//      conflict, nothing held;
//   6. the account's own monitor of the log raises nothing: the one expected
//      fingerprint change is a version it recorded as its own;
//   7. once a contact holds a v2-only list from an account, a list from it
//      that carries a v1 signature — dual-signed or v1-only, at a later version
//      or at the held one — is refused, and the log's install path reports
//      each refusal as one, the one at the held version included; the
//      account's own next v2-only list is accepted; an account that never
//      signed past its baseline is moved to version 2, never republished at
//      version 1;
//   8. the refusals accuse nobody: the two sides' claims about the list still
//      agree, and after messages both ways neither side shows a device-list
//      alert and the log raises nothing;
//   9. one contact's list installs run one at a time: a newer and an older
//      list arriving together leave the newer one held, and a dual-signed
//      list arriving with a v2-only one cannot step over the floor;
//  10. a flipped account stays flipped: restarted on a build with the signer
//      off — what a release that turned the constant back would ship — its
//      list stays v2-only with the same claim, its current version signed
//      again comes out exactly as it was, the next version it signs is
//      v2-only, and neither it nor its contact raises an alert.
@Tags(['integration'])
@Timeout(Duration(minutes: 4))
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart' show DatabaseException;
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/key_transparency.dart';
import 'package:zapp/core/models.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:z_protocol/z_protocol.dart';

Future<int> _freePort() async {
  final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final port = probe.port;
  await probe.close();
  return port;
}

Future<void> _healthy(int port) async {
  for (var i = 0; i < 100; i++) {
    try {
      final res = await (await HttpClient()
              .getUrl(Uri.parse('http://127.0.0.1:$port/health')))
          .close();
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
  late Process log;
  late int relayPort;
  late int logPort;
  late Uint8List logPub;
  final logSeed =
      Uint8List.fromList(List<int>.generate(32, (i) => (i * 13 + 7) & 0xff));
  final dirs = <String, Directory>{};
  final live = <ChatService>[];

  // Each service runs in an error zone of its own. A service [stop] has shut
  // down can still have work in flight — an inbound message part-way through
  // its handler, a flush — and that work then fails against the database
  // [stop] closed under it. That error, from a stopped service, is the one
  // expected here and is dropped; anything else raised inside a service is
  // kept, and fails the test that was running (tearDown below).
  final stopped = <ChatService>{};
  final strays = <String>[];
  tearDown(() {
    final found = [...strays];
    strays.clear();
    expect(found, isEmpty, reason: 'errors raised inside a running service');
  });

  setUpAll(() async {
    HttpOverrides.global = null;
    relayPort = await _freePort();
    relay = await Process.start('node', ['server.js'],
        workingDirectory: '$root${Platform.pathSeparator}server',
        environment: {'PORT': '$relayPort', 'LOG_LEVEL': 'silent'});
    await _healthy(relayPort);
    logPort = await _freePort();
    log = await Process.start('node', ['server.js'],
        workingDirectory: '$root${Platform.pathSeparator}kt',
        environment: {
          'KT_SEED': [
            for (final b in logSeed) b.toRadixString(16).padLeft(2, '0')
          ].join(),
          'KT_EPHEMERAL': '1',
          'KT_PORT': '$logPort',
          // One log serves the whole file, so its publish gates are raised
          // out of the way; what they do is kt/test/publish_limits.test.js's
          // business, not this file's.
          'PUBLISH_PER_MIN': '1000000',
          'PUBLISH_PER_MIN_TOTAL': '1000000',
          'PUBLISH_PER_ACCT_PER_DAY': '1000000',
          'PUBLISH_NEW_ACCOUNTS_PER_MIN': '1000000',
        });
    log.stdout.drain<void>();
    log.stderr.drain<void>();
    await _healthy(logPort);
    final kp = await Ed25519().newKeyPairFromSeed(logSeed);
    logPub = Uint8List.fromList((await kp.extractPublicKey()).bytes);
  });

  tearDownAll(() async {
    for (final s in live.toList()) {
      s.dispose();
      await s.transport.stop();
    }
    relay.kill();
    log.kill();
    for (final d in dirs.values) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  /// [name]'s client: a new account the first time, the same vault again
  /// after [stop] — which is how a test starts the next build of an app.
  /// [v2Only] is the stage-2b signer for this one service.
  Future<ChatService> start(String name, {bool v2Only = false}) async {
    final dir =
        dirs[name] ??= await Directory.systemTemp.createTemp('z_v2only_$name');
    final vault = await Vault.open(rootOverride: dir);
    final stored = await vault.kvGet('identity');
    final ZIdentity id;
    if (stored == null) {
      id = await ZIdentity.generate();
      await vault.kvPut('identity', jsonEncode(id.toJson()));
    } else {
      id = await ZIdentity.fromJson(
          (jsonDecode(stored) as Map).cast<String, Object?>());
    }
    final ready = Completer<ChatService>();
    ChatService? made;
    runZonedGuarded(() async {
      try {
        final svc = await ChatService.init(
          vault: vault,
          identity: id,
          displayName: name,
          transport:
              Transport(identity: id, serverUrl: 'ws://127.0.0.1:$relayPort'),
          ktConfig: KtConfig(
              logUrl: 'http://127.0.0.1:$logPort', logPubB64: b64(logPub)),
          signDevlistV2Only: v2Only,
        );
        made = svc;
        // A contact re-checks the log only when this test says so, so what
        // its status is between two checks is a fact the test can assert.
        svc.kt.recheckDelay = const Duration(hours: 1);
        // Hours in production; the delay is not what is under test here.
        svc.pqListDelay = const Duration(milliseconds: 150);
        // The post-quantum identity exchange runs on this debounce, and a
        // contact's nudge waits up to twenty of them. Shortened as
        // pq_identity_exchange_test.dart does: when that exchange completes
        // is not what this file is about, only that it has before an
        // assertion that needs the key.
        svc.pqSendDebounce = const Duration(milliseconds: 50);
        live.add(svc);
        ready.complete(svc);
      } catch (e, st) {
        ready.completeError(e, st);
      }
    }, (e, st) {
      final svc = made;
      if (svc != null &&
          stopped.contains(svc) &&
          e is DatabaseException &&
          e.isDatabaseClosedError()) {
        return;
      }
      strays.add('$name: $e\n$st');
    });
    return ready.future;
  }

  Future<void> stop(ChatService svc) async {
    stopped.add(svc);
    svc.dispose();
    await svc.transport.stop();
    live.remove(svc);
    await svc.vault.db.close();
  }

  Future<void> waitUntil(FutureOr<bool> Function() cond,
      {required String what,
      Duration timeout = const Duration(seconds: 30)}) async {
    final deadline = DateTime.now().add(timeout);
    while (!await cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
  }

  bool received(ChatService svc, String rid, String body) =>
      svc.messagesByChat[rid]?.any((m) => !m.outgoing && m.body == body) ==
      true;

  /// The traffic among [group] has run its course: every text sent among them
  /// is confirmed delivered, no post-quantum send is pending, and no outbox
  /// holds anything. Waited on before a [stop], so that a restart happens
  /// where it does in the field — between conversations rather than in the
  /// middle of one. (What is still in flight after it is the late work the
  /// error zone in [start] expects.)
  Future<void> quiet(List<ChatService> group) => waitUntil(() async {
        for (final s in group) {
          for (final o in group) {
            if (identical(s, o) || s.contacts[o.myRid] == null) continue;
            if ((s.messagesByChat[o.myRid] ?? const <ChatMessage>[]).any((m) =>
                m.outgoing &&
                m.kind == 'text' &&
                m.status < MsgStatus.delivered)) {
              return false;
            }
          }
        }
        for (final s in group) {
          if (s.pqSendPending) return false;
          if ((await s.vault.db.query('outbox', limit: 1)).isNotEmpty) {
            return false;
          }
        }
        return true;
      },
          what: 'the traffic among '
              '${group.map((s) => s.displayName).join(', ')} has settled');

  /// Two accounts that have exchanged codes and a message each way.
  Future<void> introduce(ChatService a, ChatService b) async {
    await waitUntil(() => a.transport.isConnected && b.transport.isConnected,
        what: 'both connected');
    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());
    await a.sendText(b.myRid, 'hello ${b.displayName}');
    await b.sendText(a.myRid, 'hello ${a.displayName}');
    await waitUntil(
        () =>
            received(a, b.myRid, 'hello ${a.displayName}') &&
            received(b, a.myRid, 'hello ${b.displayName}'),
        what: '${a.displayName} and ${b.displayName} have spoken');
  }

  Future<SignedDeviceList?> listAt(ChatService svc, String key) async {
    final j = await svc.vault.kvGet(key);
    return j == null
        ? null
        : SignedDeviceList.fromJson(
            (jsonDecode(j) as Map).cast<String, Object?>());
  }

  /// The list [svc] holds for [rid]'s account, as installed.
  Future<SignedDeviceList?> held(ChatService svc, String rid) =>
      listAt(svc, 'cdev_$rid');

  /// The list [svc]'s own account last signed (or, on a linked device, learned).
  Future<SignedDeviceList?> own(ChatService svc) =>
      listAt(svc, 'own_list_json');

  Future<void> holdsVersion(ChatService svc, String rid, int v) => waitUntil(
      () async => await svc.heldContactListVersion(rid) >= v,
      what: '${svc.displayName} holds v$v of the list');

  /// What the log serves as [svc]'s account's latest entry: (version, fp).
  Future<(int, String)?> logLatest(ChatService svc) async {
    final label = await ktLabel((await svc.accountIdentity()).accountEdPub);
    final hex = [for (final b in label) b.toRadixString(16).padLeft(2, '0')]
        .join();
    final res = await (await HttpClient().getUrl(
            Uri.parse('http://127.0.0.1:$logPort/kt/v1/lookup/$hex')))
        .close();
    final j = (jsonDecode(await res.transform(utf8.decoder).join()) as Map)
        .cast<String, Object?>();
    final e = j['entry'];
    if (e is! Map) return null;
    return ((e['v'] as num).toInt(), e['fp'] as String);
  }

  Future<void> logHas(ChatService svc, int v, String fp) => waitUntil(
      () async {
        final l = await logLatest(svc);
        return l != null && l.$1 == v && l.$2 == fp;
      },
      what: 'the log holds ${svc.displayName} v$v with that fingerprint');

  /// One explicit check of the log by [svc]; a conflict is never right here.
  Future<KtContactStatus?> checkLog(ChatService svc, String rid) async {
    await svc.kt.check();
    final s = svc.kt.statusOf(rid);
    expect(s?.state, isNot(KtContactState.conflict),
        reason: 'nothing in this file gives the log grounds for a conflict');
    return s;
  }

  Future<void> linkLaptop(ChatService svc, String id) async {
    final acct = await svc.accountIdentity();
    final laptop = await ZIdentity.generate();
    await svc.addMyDevice(await acct.signDeviceCert(
        deviceEdPub: laptop.edPub, deviceXPub: laptop.xPub, deviceId: id));
  }

  test(
      '1. with the signer off everywhere nothing changes: dual-signed, the v1 '
      'fingerprint on both sides and in the log, and a restart moves nothing',
      () async {
    expect(devlistSignV2Only, isFalse,
        reason: 'the constant ships off; the release that flips it changes '
            'this test with it (ADR 0017, "The flip itself")');
    var alice = await start('alice1');
    final ben = await start('ben1');
    expect(alice.debugDevlistSignV2Only, isFalse);
    expect(ben.debugDevlistSignV2Only, isFalse);
    await introduce(alice, ben);
    await linkLaptop(alice, 'laptop');
    await holdsVersion(ben, alice.myRid, 2);

    final list = (await held(ben, alice.myRid))!;
    expect(list.sig, isNotNull, reason: 'still dual-signed');
    expect(list.sig2, isNotNull);
    expect(list.isV2Only, isFalse);
    final v1 = b64(await deviceListFingerprint(2, list.devices));
    expect(b64(await list.fingerprint()), v1, reason: 'the reader reports v1');
    expect(await alice.vault.kvGet('own_list_h'), v1,
        reason: 'and so does the account, in the claim on every message');
    await logHas(alice, 2, v1);
    final status = await checkLog(ben, alice.myRid);
    expect(status?.state, KtContactState.confirmed);
    expect(status?.logFpB64, v1);
    // The 0010 floor, as before. Written after the list itself, so waited for.
    await waitUntil(
        () async =>
            await ben.vault.kvGet('cdev_sigfloor_${alice.myRid}') == '2',
        what: 'Ben\'s sig2 floor for Alice reaches 2');

    // A restart of the same build: no migration, nothing re-signed differently.
    await quiet([alice, ben]);
    final before = await alice.vault.kvGet('own_list_json');
    await stop(alice);
    alice = await start('alice1');
    expect(await alice.vault.kvGet('devlist_v2only_migrated'), isNull);
    expect(await alice.ownDeviceListVersion(), 2);
    expect(await alice.vault.kvGet('own_list_json'), before);
  });

  test(
      '2-6. the signer on for one account: one republish at the next version, '
      'the same v3 fingerprint at every contact, post-quantum verified, '
      'confirmed by the log throughout, and the owner\'s monitor quiet',
      () async {
    var alice = await start('alice2');
    final ben = await start('ben2');
    final cara = await start('cara2');
    await introduce(alice, ben);
    await introduce(alice, cara);
    await linkLaptop(alice, 'laptop');
    final contacts = [ben, cara];
    for (final c in contacts) {
      await holdsVersion(c, alice.myRid, 2);
    }
    final devices = (await own(alice))!.devices;
    final v1 = b64(await deviceListFingerprint(2, devices));
    await logHas(alice, 2, v1);
    for (final c in contacts) {
      expect((await checkLog(c, alice.myRid))?.state, KtContactState.confirmed);
      await waitUntil(
          () => c.deviceAssuranceWith(alice.myRid) == DeviceAssurance.hybrid,
          what: '${c.displayName}: the stage-1 list is post-quantum verified');
    }

    // The flip: Alice's next start is a build with the signer on.
    await quiet([alice, ben, cara]);
    await stop(alice);
    alice = await start('alice2', v2Only: true);
    expect(alice.debugDevlistSignV2Only, isTrue);

    // 2. Republished once, at the next version, with sig3 alone.
    expect(await alice.vault.kvGet('devlist_v2only_migrated'), '1');
    expect(await alice.ownDeviceListVersion(), 3);
    final mine = (await own(alice))!;
    expect(mine.version, 3);
    expect(mine.isV2Only, isTrue);
    expect(mine.toJson().containsKey('sig'), isFalse);
    expect(mine.toJson().containsKey('sig2'), isFalse);
    expect(mine.toJson()['sig3'], isA<String>());
    expect([for (final d in mine.devices) b64(d.deviceEdPub)],
        [for (final d in devices) b64(d.deviceEdPub)],
        reason: 'the same devices: only the signing moved');
    final soleFp = b64(await deviceListFingerprintV3(3, devices));
    expect(b64(await mine.fingerprint()), soleFp);
    expect(soleFp, isNot(b64(await deviceListFingerprint(3, devices))));
    expect(soleFp, isNot(b64(await deviceListFingerprintV2(3, devices))));
    expect(await alice.vault.kvGet('own_list_h'), soleFp,
        reason: 'the claim Alice now makes on every message');

    // 5, first half: the log commits to the v2-only list's fingerprint at v3.
    await logHas(alice, 3, soleFp);

    // 3. Every contact — signer off, a stage-2a reader — accepts it and
    // computes the same fingerprint from the same bytes.
    for (final c in contacts) {
      await holdsVersion(c, alice.myRid, 3);
      final got = (await held(c, alice.myRid))!;
      expect(got.isV2Only, isTrue, reason: '${c.displayName} holds sig3 alone');
      expect(b64(await got.fingerprint()), soleFp,
          reason: '${c.displayName} computes what Alice claims');
    }

    // 5, second half: confirmed before the contact looks again, and after.
    for (final c in contacts) {
      expect(c.kt.statusOf(alice.myRid)?.state, KtContactState.confirmed,
          reason: 'installing the new list did not unsettle the log status');
      final s = await checkLog(c, alice.myRid);
      expect(s?.state, KtContactState.confirmed);
      expect(s?.logVersion, 3);
      expect(s?.logFpB64, soleFp);
      expect(c.kt.heldRids(alice.myRid), isEmpty);
    }

    // 4. The ML-DSA over the v2-only list: over the v3 input, and verified
    // at every contact.
    final mlPub = (await alice.pqAccountPublic())!;
    final mlsig = (await alice.debugPqSignatureForCurrentList())!;
    expect(mlsig.version, 3);
    expect(
        pqDsaVerify(
            mlPub, SignedDeviceList.signingInputV3(3, devices), mlsig.mlSig),
        isTrue,
        reason: 'over the input that names the ratchet keys');
    for (final other in [
      SignedDeviceList.signingInput(3, devices),
      SignedDeviceList.signingInputV2(3, devices),
    ]) {
      expect(pqDsaVerify(mlPub, other, mlsig.mlSig), isFalse);
    }
    for (final c in contacts) {
      await waitUntil(
          () async =>
              await c.vault.kvGet('cdev_pq_ver_${alice.myRid}') == '3' &&
              c.deviceAssuranceWith(alice.myRid) == DeviceAssurance.hybrid,
          what: '${c.displayName}: the v2-only list is post-quantum verified');
      expect(await mlsig.verifies((await held(c, alice.myRid))!, mlPub),
          isTrue);
    }

    // 6. Alice's own monitor knows both (2, v1) and (3, v3) as hers.
    await alice.kt.check();
    expect(alice.kt.ownAlert, isNull);
    expect(alice.kt.health, KtHealth.ok);
    expect(alice.ownAccountAlert, isNull);
    for (final c in contacts) {
      expect(c.contactDevlistAlerts[alice.myRid], isNull);
    }

    // 2, second half: once. Another start with the signer on finds the list
    // already v2-only and republishes nothing.
    await quiet([alice, ben, cara]);
    final json = await alice.vault.kvGet('own_list_json');
    await stop(alice);
    alice = await start('alice2', v2Only: true);
    expect(await alice.ownDeviceListVersion(), 3);
    expect(await alice.vault.kvGet('own_list_json'), json);
    await alice.kt.check();
    expect(await logLatest(alice), (3, soleFp));
    expect(alice.kt.ownAlert, isNull);
  });

  test(
      '7-8. after a v2-only list, a list carrying a v1 signature is refused '
      'at any version, the account\'s next v2-only list is accepted, and '
      'nobody is accused', () async {
    // An account that has only ever signed its version-1 baseline — which
    // its first check of the log signs and publishes.
    var alice = await start('alice3');
    final ben = await start('ben3');
    await introduce(alice, ben);
    await waitUntil(() async => await own(alice) != null,
        what: 'Alice has signed her baseline');
    final baseline = (await own(alice))!;
    expect(baseline.version, 1);
    expect(baseline.isV2Only, isFalse);
    await logHas(alice, 1, b64(await baseline.fingerprint()));

    await quiet([alice, ben]);
    await stop(alice);
    alice = await start('alice3', v2Only: true);
    expect(await alice.ownDeviceListVersion(), 2,
        reason: 'moved to version 2: a v2-only list is never version 1, the '
            'baseline a contact computes for itself over the v1 input');
    await holdsVersion(ben, alice.myRid, 2);
    expect((await held(ben, alice.myRid))!.isV2Only, isTrue);

    // The account carries on, and from here on Ben's floor for it is at its
    // third level: a laptop linked now is announced v2-only, and that — the
    // shape the account signs — is accepted.
    await linkLaptop(alice, 'laptop');
    await holdsVersion(ben, alice.myRid, 3);
    final current = (await held(ben, alice.myRid))!;
    expect(current.isV2Only, isTrue);
    final devices = current.devices;
    final soleFp = b64(await deviceListFingerprintV3(3, devices));
    expect(b64(await current.fingerprint()), soleFp);

    // What the floor refuses: lists from this account carrying a v1 signature,
    // genuinely signed by its key. Read both from what Ben holds and from the
    // log path's own answer, which must say "refused" for the one at the held
    // version too — the held version alone used to answer, and it equals the
    // list's there whether the list was installed or not.
    final acct = await alice.accountIdentity();
    final dualNext = await acct.signDeviceList(devices, 4, v2Only: false);
    expect(dualNext.sig, isNotNull);
    expect(await dualNext.verify(), isTrue, reason: 'genuinely signed');
    final v1Next = SignedDeviceList(
        accountEdPub: dualNext.accountEdPub,
        version: 4,
        devices: devices,
        sig: dualNext.sig);
    final dualHeld = await acct.signDeviceList(devices, 3, v2Only: false);
    for (final (what, list) in [
      ('a dual-signed list at a later version', dualNext),
      ('a v1-only list at a later version', v1Next),
      ('a dual-signed list at the held version', dualHeld),
    ]) {
      expect(await list.verify(), isTrue, reason: what);
      expect(await ben.ktInstallFromLog(alice.myRid, list), isFalse,
          reason: '$what is reported refused');
      final still = (await held(ben, alice.myRid))!;
      expect(still.version, 3, reason: '$what is refused');
      expect(still.isV2Only, isTrue, reason: '$what is refused');
      expect(b64(await still.fingerprint()), soleFp, reason: what);
    }

    // 8. Nobody is accused. What Ben holds is still what Alice claims on
    // every message she sends, so there is no split for the gossip to find.
    expect(await alice.ownDeviceListVersion(), 3);
    final claimed = await alice.vault.kvGet('own_list_h');
    expect(claimed, soleFp,
        reason: 'what Ben holds is what Alice claims: no split to see');

    await alice.sendText(ben.myRid, 'still me');
    await ben.sendText(alice.myRid, 'still you');
    await waitUntil(
        () =>
            received(ben, alice.myRid, 'still me') &&
            received(alice, ben.myRid, 'still you'),
        what: 'messages both ways after the refusals');
    // Ben recorded Alice's claim from that message — the gossip ran — and it
    // is the list he holds.
    await waitUntil(() async {
      final raw = await ben.vault.kvGet('cdl_claims_${alice.myRid}');
      if (raw == null) return false;
      final c = (jsonDecode(raw) as Map)[alice.myRid];
      return c is Map && c['v'] == 3 && c['h'] == claimed;
    }, what: 'Ben has recorded Alice\'s claim at v3');
    await logHas(alice, 3, soleFp);
    expect((await checkLog(ben, alice.myRid))?.state, KtContactState.confirmed);
    await alice.kt.check();
    expect(ben.contactDevlistAlerts[alice.myRid], isNull,
        reason: 'no split view read into a refused list');
    expect(alice.contactDevlistAlerts[ben.myRid], isNull);
    expect(alice.ownAccountAlert, isNull);
    expect(alice.kt.ownAlert, isNull);
  });

  test(
      '9. one contact\'s list installs run one at a time: the newer of two '
      'arriving together stays held, and the floor cannot be stepped over',
      () async {
    final alice = await start('alice4');
    final ben = await start('ben4');
    await introduce(alice, ben);
    final acct = await alice.accountIdentity();
    final devices = await alice.myFullDeviceList();

    // Two lists from the account arriving at the same moment — a broadcast
    // and a re-send of an older one, or one in-band and one from the log —
    // the newer started first. Each install reads what is held, checks, and
    // writes; run side by side, the older read the held version before the
    // newer had written it, passed its staleness check, and wrote last.
    final newer = await acct.signDeviceList(devices, 6, v2Only: false);
    final older = await acct.signDeviceList(devices, 5, v2Only: false);
    await Future.wait([
      ben.ktInstallFromLog(alice.myRid, newer),
      ben.ktInstallFromLog(alice.myRid, older),
    ]);
    expect(await ben.heldContactListVersion(alice.myRid), 6,
        reason: 'the older list must not land on top of the newer one');

    // The floor is the same read-check-write. A v2-only list and a
    // dual-signed one at a later version, together: the dual-signed one must
    // see the level the v2-only one raised, not the one before it.
    final v2Only = await acct.signDeviceList(devices, 7, v2Only: true);
    final dual = await acct.signDeviceList(devices, 8, v2Only: false);
    await Future.wait([
      ben.ktInstallFromLog(alice.myRid, v2Only),
      ben.ktInstallFromLog(alice.myRid, dual),
    ]);
    final now = (await held(ben, alice.myRid))!;
    expect(now.version, 7, reason: 'the dual-signed list was refused');
    expect(now.isV2Only, isTrue);
  });

  test(
      '10. a flipped account stays flipped: on a build with the signer off its '
      'list stays v2-only, its next one is v2-only, and nobody is alerted',
      () async {
    // Alice's first start is a flipped build, which moves her account at
    // once. No device is linked before the restart; that once kept this test
    // clear of a race in the root's own signing — a device linked while the
    // root answered a new contact's first echo — closed since
    // (`own_list_race_test.dart`).
    var alice = await start('alice5', v2Only: true);
    final ben = await start('ben5');
    await introduce(alice, ben);
    await holdsVersion(ben, alice.myRid, 2);
    final before = (await own(alice))!;
    expect(before.version, 2);
    expect(before.isV2Only, isTrue);
    final claim = await alice.vault.kvGet('own_list_h');
    expect(claim, b64(await before.fingerprint()));

    // The next start is a build with the constant false — a release that
    // turned it back, a downgrade to this release, a backup restored onto it.
    await quiet([alice, ben]);
    await stop(alice);
    alice = await start('alice5', v2Only: false);
    expect(alice.debugDevlistSignV2Only, isFalse);

    // The current version signed again, as every path that re-asserts a list
    // signs it, and sent to Ben: it comes out exactly as it was.
    await alice.broadcastMyDeviceList();
    final after = (await own(alice))!;
    expect(after.version, 2);
    expect(after.isV2Only, isTrue, reason: 'v2 is not re-signed dual-signed');
    expect(after.toJson(), before.toJson());
    expect(await alice.vault.kvGet('own_list_h'), claim,
        reason: 'the claim on every message is unchanged');
    await alice.sendText(ben.myRid, 'after the restart');
    await ben.sendText(alice.myRid, 'still here');
    await waitUntil(
        () =>
            received(ben, alice.myRid, 'after the restart') &&
            received(alice, ben.myRid, 'still here'),
        what: 'messages both ways after the restart');
    await quiet([alice, ben]);
    expect((await held(ben, alice.myRid))!.toJson(), before.toJson(),
        reason: 'Ben still holds the list as it was');

    // The next version is signed v2-only as well.
    await linkLaptop(alice, 'laptop');
    final next = (await own(alice))!;
    expect(next.version, 3);
    expect(next.isV2Only, isTrue);
    await holdsVersion(ben, alice.myRid, 3);
    final atBen = (await held(ben, alice.myRid))!;
    expect(atBen.version, 3);
    expect(atBen.isV2Only, isTrue);
    expect(b64(await atBen.fingerprint()), b64(await next.fingerprint()));

    // Nobody is alerted, in the gossip or by the log.
    await alice.sendText(ben.myRid, 'with the laptop');
    await waitUntil(() => received(ben, alice.myRid, 'with the laptop'),
        what: 'a message carrying the v3 claim');
    await logHas(alice, 3, b64(await next.fingerprint()));
    expect((await checkLog(ben, alice.myRid))?.state, KtContactState.confirmed);
    await alice.kt.check();
    expect(alice.kt.ownAlert, isNull);
    expect(alice.ownAccountAlert, isNull);
    expect(ben.contactDevlistAlerts[alice.myRid], isNull);
    expect(alice.contactDevlistAlerts[ben.myRid], isNull);
  });
}
