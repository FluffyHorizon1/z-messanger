// ADR 0029: an account moves to v2-only device-list signing (ADR 0017 stage
// 2b) by itself, once every device that reads its lists has said, inside the
// end-to-end channel, that it can read one. Real clients — real linked
// laptops among them — the real relay, and the real transparency log
// (kt/server.js) on loopback.
//
// An older build is simulated with the seams the earlier migrations used:
// `debugPreAdr0029` (set at start, like `signDevlistV2Only`) makes a client
// say nothing about what it reads — a build from 3.9.9 up to ADR 0029, which
// reads a v2-only list and does not say so; and `debugOnDecrypted` dropping
// every v2-only list that reaches it, with no log configured, stands in for
// a build from before 3.9.9, whose parser throws on one.
//
// Criteria, with the tests that cover them below. The gate holding, opening
// and what the move then does are one flow, watched from every side it
// touches, so
//   criteria 2 and 3 share a test,
//   criteria 3 and 4 share a test;
// and the two screens are one widget test, so
//   criteria 8 and 9 share a test.
//   1. every device says what it reads, and each receiver records it per
//      device: a contact's primary device and its other device each at 3
//      under their own routing ids, the account's linked laptop at 3 from
//      the self-sync channel (and the root at 3 on the laptop), a build from
//      before ADR 0029 at 0 from its first decorated message; the records
//      survive a restart;
//   2. an account with a linked device and one contact whose device has not
//      said it reads a v2-only list does not move — not while it runs, not
//      at a restart — and its gate counts that one device;
//   3. it moves the moment that device says it does: the contact updated
//      sends one message, and the account moves without a restart, to the
//      next version, sig3 alone;
//   4. every contact installs that list and computes the fingerprint the
//      account claims, the laptop learns it, the log confirms it, and after
//      messages both ways no alert is raised anywhere — contacts, the owner's
//      devices, the log;
//   5. a contact on an older build added after the move: the account does
//      not move back — its list, version and claim unchanged, nothing signed
//      at a version it has published; one that reads v2-only lists installs
//      it and is confirmed by the log; the account withholds its claim from
//      both until one of their devices says it reads one, so one that cannot
//      read the list is not told "the update never arrived", and no alert is
//      raised on either side; the account names the old one on that
//      contact's screen state and counts it; when it updates, the claim
//      resumes and the notice goes;
//   6. the kill switch: an account whose gate is open does not move on a
//      build with the switch thrown, says so, and moves at its first start on
//      a build with it on; restarted with the switch thrown again it stays
//      moved — its list, re-signed, byte for byte what it was;
//   7. the account's own devices count too, every one: a linked laptop on an
//      older build holds the move until it updates, and then its start-up
//      announcement alone opens the gate; and an account with contacts and
//      no linked device does not move at all — R42 needs a linked device;
//   8. Settings' developer view shows the gate: the form the list is signed
//      in and "Contacts' devices not yet capable: N";
//   9. the contact's screen names a contact whose app has said it is an
//      older build, after the move, in the neutral tone;
//  10. the move silences no evidence: afterwards, a list the account key
//      signed and its devices never issued — v2-only, the next version,
//      adding a device — shown to one contact still raises the owner's
//      alarm on the root and on the linked device;
//  11. a contact whose devices differ — one reads a v2-only list, one
//      cannot — is sent the claim on the one that reads it and not on the
//      other, either way round (an older laptop beside an updated phone, an
//      older phone beside an updated laptop), so the other is not told the
//      update never arrived and nobody is alerted; the copy without the
//      claim is otherwise the message, its disappearing timer included.
//
// Criterion 11 was run against 9c8cf9f, where the claim was withheld per
// contact: Ben's old laptop and Carol's old phone each recorded Alice's
// claim, and the laptop, judging it, raised "the update never arrived". With
// the claim withheld per device but a copy that dropped its timer, Carol's
// phone kept the timed message for good.
@Tags(['integration'])
@Timeout(Duration(minutes: 4))
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart' show DatabaseException;
import 'package:zapp/core/app_lock.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/key_transparency.dart';
import 'package:zapp/core/models.dart';
import 'package:zapp/core/prefs.dart';
import 'package:zapp/core/push_service.dart';
import 'package:zapp/core/receipts.dart';
import 'package:zapp/core/system_messages.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/l10n/app_localizations.dart';
import 'package:zapp/l10n/app_localizations_en.dart';
import 'package:zapp/ui/contact_info_screen.dart';
import 'package:zapp/ui/settings_screen.dart';
import 'package:zapp/ui/theme.dart';
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

/// Whether [plaintext] is a `devlist` inner carrying a v2-only list — what a
/// build from before 3.9.9 cannot parse.
bool _isV2OnlyDevlist(Uint8List plaintext) {
  if (!InnerMessage.looksLikeKind(plaintext, 'devlist')) return false;
  try {
    final inner = InnerMessage.fromBytes(plaintext);
    final list = (jsonDecode(inner.data['list'] as String) as Map)
        .cast<String, Object?>();
    return !list.containsKey('sig');
  } catch (_) {
    return false;
  }
}

// ADR 0028 holds a receipt from 5 s to a minute, at random, so the relay
// cannot pair it with the message it answers (receipt_timing_test.dart). Every
// inner a client sends carries the device-list gossip, receipts included, the
// `dlr` that opens the gate among it — and "traffic has settled" waits for the
// ticks receipts turn. This suite is about the gate, not about when a tick
// turns, so its devices answer within 300 ms, as every device did before
// phase 41.
const promptReceipts =
    ReceiptTiming(floor: Duration.zero, ceiling: Duration(milliseconds: 300));

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
      Uint8List.fromList(List<int>.generate(32, (i) => (i * 29 + 3) & 0xff));
  final dirs = <String, Directory>{};
  final live = <ChatService>[];

  // Each service runs in an error zone of its own. A service [stop] has shut
  // down can still have work in flight, which then fails against the
  // database [stop] closed under it; that error, from a stopped service, is
  // the one expected here and is dropped. Anything else raised inside a
  // service is kept, and fails the test that was running.
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
          // out of the way (kt/test/publish_limits.test.js covers them).
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

  /// [name]'s client: a new account the first time, the same vault again
  /// after [stop] — which is how a test starts the next build of an app.
  /// [switchOn] is the build's kill switch for the move; [preAdr0029] runs
  /// it as a build from before the capability existed; [log] is off for a
  /// client with no transparency log; [grace] is its device-list grace.
  Future<ChatService> start(String name,
      {bool switchOn = true,
      bool preAdr0029 = false,
      bool log = true,
      Duration grace = const Duration(milliseconds: 700)}) async {
    final dir =
        dirs[name] ??= await Directory.systemTemp.createTemp('z_dlcap_$name');
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
          ktConfig: log
              ? KtConfig(
                  logUrl: 'http://127.0.0.1:$logPort', logPubB64: b64(logPub))
              : KtConfig.off,
          signDevlistV2Only: switchOn,
          receiptTiming: promptReceipts,
          debugPreAdr0029: preAdr0029,
        );
        made = svc;
        // A contact checks the log only when this test says so.
        svc.kt.scheduled = false;
        // Hours in production; not what is under test here.
        svc.pqListDelay = const Duration(milliseconds: 150);
        svc.pqSendDebounce = const Duration(milliseconds: 50);
        // Eight seconds in production. Short here; zero for a client whose
        // alarms a test asserts are never raised, so that one that would be
        // raised is raised the moment its message is read — not after a
        // grace the test would have to wait out.
        svc.devlistGrace = grace;
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

  bool up(ChatService s) =>
      s.transport.isConnected && s.transport.isSenderConnected;

  /// A laptop linked to [host]'s account, as an enrolment leaves one — its
  /// own keys, the account it joined, the device that linked it — running,
  /// and named [name] so [start] can bring it back. [preAdr0029], [log] and
  /// [grace] are [start]'s; [parsesV2Only] false makes it a build from before
  /// 3.9.9, which drops every v2-only list that reaches it, from the start.
  Future<ChatService> startLinked(String name, ChatService host,
      {bool preAdr0029 = false,
      bool log = true,
      Duration grace = const Duration(milliseconds: 700),
      bool parsesV2Only = true}) async {
    final dir =
        dirs[name] ??= await Directory.systemTemp.createTemp('z_dlcap_$name');
    final vault = await Vault.open(rootOverride: dir);
    final id = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(id.toJson()));
    final account = await host.accountIdentity();
    final cert = await account.signDeviceCert(
        deviceEdPub: id.edPub, deviceXPub: id.xPub, deviceId: name);
    final enrolled = await AccountIdentity.fromEnrollment(
      accountEdPub: account.accountEdPub,
      deviceEdSeed: id.edSeed,
      deviceXSeed: id.xSeed,
      deviceId: name,
      deviceCert: cert,
    );
    await vault.kvPut('account', jsonEncode(enrolled.toJson()));
    await vault.kvPut('my_devices', jsonEncode([account.deviceCert.toJson()]),
        sensitive: false);
    await vault.db.close();
    final svc =
        await start(name, preAdr0029: preAdr0029, log: log, grace: grace);
    if (!parsesV2Only) {
      svc.debugOnDecrypted =
          (path, from, dec) => _isV2OnlyDevlist(dec.plaintext);
    }
    await waitUntil(() => up(host) && up(svc),
        what: '$name and its host each up on both links');
    // As the app's pairing links one (`hostDeviceLink`): the version waits for
    // the device's proof of possession before it goes to the log (ADR 0022).
    await host.addMyDevice(cert, awaitProof: true);
    await waitUntil(() async => await svc.ownDeviceListVersion() >= 2,
        what: '$name holds its account\'s list');
    return svc;
  }

  bool received(ChatService svc, String rid, String body) =>
      svc.messagesByChat[rid]?.any((m) => !m.outgoing && m.body == body) ==
      true;

  /// [a] holds [b] as a contact — from b's code, as a scan leaves it — and
  /// counts b's device among its readers from this moment.
  Future<void> hold(ChatService a, ChatService b) async {
    if (a.contacts.containsKey(b.myRid)) return;
    await a.addContactFromCode(await b.myContactCode());
  }

  /// Two accounts that have exchanged codes and a message each way.
  Future<void> introduce(ChatService a, ChatService b) async {
    await waitUntil(() => up(a) && up(b), what: 'both connected');
    await hold(a, b);
    await hold(b, a);
    await a.sendText(b.myRid, 'hello ${b.displayName}');
    await b.sendText(a.myRid, 'hello ${a.displayName}');
    await waitUntil(
        () =>
            received(a, b.myRid, 'hello ${a.displayName}') &&
            received(b, a.myRid, 'hello ${b.displayName}'),
        what: '${a.displayName} and ${b.displayName} have spoken');
  }

  /// The traffic among [group] has run its course: every text confirmed
  /// delivered, no post-quantum send pending, no outbox holding anything.
  /// Waited on before a [stop], so a restart happens between conversations.
  Future<void> quiet(List<ChatService> group) async {
    var why = '';
    try {
      await waitUntil(() async {
        for (final s in group) {
          // A linked device's copy of a message its phone sent is marked
          // delivered only by a receipt that reached it, and the receipt for
          // a message sent before the contact knew the laptop never does: the
          // phone's copy is the one that says.
          if (!await s.holdsAccountRoot()) continue;
          for (final o in group) {
            if (identical(s, o) || s.contacts[o.myRid] == null) continue;
            final open = (s.messagesByChat[o.myRid] ?? const <ChatMessage>[])
                .where((m) =>
                    m.outgoing &&
                    m.kind == 'text' &&
                    m.status < MsgStatus.delivered)
                .toList();
            if (open.isNotEmpty) {
              why = '${s.displayName} → ${o.displayName}: '
                  '"${open.first.body}" at status ${open.first.status}';
              return false;
            }
          }
        }
        for (final s in group) {
          if (s.pqSendPending) {
            why = '${s.displayName}: a post-quantum send is pending';
            return false;
          }
          final rows = await s.vault.db.query('outbox', limit: 3);
          if (rows.isNotEmpty) {
            why = '${s.displayName}: outbox holds ${rows.length}+ rows, to '
                '${rows.map((r) => (r['rid'] as String).substring(0, 6)).join(', ')}';
            return false;
          }
        }
        return true;
      },
          what: 'the traffic among '
              '${group.map((s) => s.displayName).join(', ')} has settled');
    } on TimeoutException catch (e) {
      throw TimeoutException('${e.message} — still: $why');
    }
  }

  Future<SignedDeviceList?> listAt(ChatService svc, String key) async {
    final j = await svc.vault.kvGet(key);
    return j == null
        ? null
        : SignedDeviceList.fromJson(
            (jsonDecode(j) as Map).cast<String, Object?>());
  }

  Future<SignedDeviceList?> own(ChatService svc) =>
      listAt(svc, 'own_list_json');

  Future<SignedDeviceList?> held(ChatService svc, String rid) =>
      listAt(svc, 'cdev_$rid');

  Future<bool> moved(ChatService svc) async =>
      (await own(svc))?.isV2Only ?? false;

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

  /// No alert of any kind on [svc]: about a contact's list, about its own
  /// account from the gossip, or from the log.
  void noAlerts(ChatService svc) {
    expect(svc.contactDevlistAlerts, isEmpty,
        reason: '${svc.displayName}: no contact device-list alert');
    expect(svc.ownAccountAlert, isNull,
        reason: '${svc.displayName}: no own-account alert');
    expect(svc.removedDeviceAlert, isNull,
        reason: '${svc.displayName}: no removed-device alert');
    expect(svc.kt.ownAlert, isNull,
        reason: '${svc.displayName}: no alert from its own log check');
  }

  /// [svc]'s record of what [rid]'s device [deviceRid] said it reads.
  Future<void> says(ChatService svc, String rid, String deviceRid, int level,
          String who) =>
      waitUntil(() => svc.debugReaderLevel(rid, deviceRid) == level,
          what: '${svc.displayName} has recorded $who at $level');

  test(
      '1. every device says what it reads, and each receiver records it per '
      'device — the records survive a restart', () async {
    var alice = await start('alice1');
    final laptop = await startLinked('alice1-laptop', alice);
    final ben = await start('ben1');
    final benLaptop = await startLinked('ben1-laptop', ben);
    final dan = await start('dan1', preAdr0029: true);
    // Dan first: a contact Alice holds and has not heard from yet is a
    // reader that has not said it can read a v2-only list, so Alice cannot
    // move while this test looks at what she records.
    await hold(alice, dan);
    await introduce(alice, ben);
    await introduce(alice, dan);

    // Ben's laptop speaks to Alice: once Alice holds Ben's list naming it,
    // her next message reaches the laptop too, and its receipt comes back
    // to her from the laptop itself — then a message of its own, on the
    // session her message opened.
    await holdsVersion(alice, ben.myRid, 2);
    await waitUntil(() => benLaptop.contacts.containsKey(alice.myRid),
        what: 'Ben\'s laptop holds Alice, mirrored from Ben\'s phone');
    await alice.sendText(ben.myRid, 'to both of Ben\'s devices');
    await waitUntil(
        () => received(benLaptop, alice.myRid, 'to both of Ben\'s devices'),
        what: 'Ben\'s laptop has Alice\'s message');
    await benLaptop.sendText(alice.myRid, 'from Ben\'s laptop');
    await waitUntil(() => received(alice, ben.myRid, 'from Ben\'s laptop'),
        what: 'Alice has the laptop\'s message, in Ben\'s chat');

    // Each of a contact's devices under its own routing id.
    await says(alice, ben.myRid, ben.myRid, devlistReaderLevel, 'Ben\'s phone');
    await says(alice, ben.myRid, benLaptop.myRid, devlistReaderLevel,
        'Ben\'s laptop');
    // A build from before ADR 0029 decorates what it sends (7.7a's `dl`) and
    // says nothing about what it reads: 0.
    await says(alice, dan.myRid, dan.myRid, 0, 'Dan');
    // The account's own devices, from the self-sync channel, both ways.
    await waitUntil(
        () => alice.debugOwnReaderLevel(laptop.myRid) == devlistReaderLevel,
        what: 'Alice has recorded her laptop');
    await waitUntil(
        () => laptop.debugOwnReaderLevel(alice.myRid) == devlistReaderLevel,
        what: 'the laptop has recorded its root');

    // What Alice's gate sees: Ben's two devices and Dan's one; one behind.
    final g = alice.devlistGate;
    expect(g.decides, isTrue);
    expect(g.contacts, 2);
    expect(g.contactDevices, 3);
    expect(g.contactDevicesBehind, 1, reason: 'Dan, and only Dan');
    expect(g.ownDevices, 1);
    expect(g.ownDevicesBehind, 0);
    expect(g.open, isFalse);
    expect(laptop.devlistGate.decides, isFalse,
        reason: 'the root decides; a linked device shows what it sees');

    // Kept across a restart: the records are in the vault.
    await quiet([alice, ben, dan]);
    await stop(alice);
    alice = await start('alice1');
    expect(alice.debugReaderLevel(ben.myRid, ben.myRid), devlistReaderLevel);
    expect(alice.debugReaderLevel(ben.myRid, benLaptop.myRid),
        devlistReaderLevel);
    expect(alice.debugReaderLevel(dan.myRid, dan.myRid), 0);
    expect(alice.debugOwnReaderLevel(laptop.myRid), devlistReaderLevel);
    expect(alice.devlistGate.contactDevicesBehind, 1);
  });

  test(
      '2-4. one contact that has not said it reads a v2-only list holds the '
      'move; the moment it says so the account moves, without a restart, and '
      'every reader takes the new list with no alert anywhere', () async {
    var alice = await start('alice2');
    final laptop = await startLinked('alice2-laptop', alice);
    final ben = await start('ben2');
    var cara = await start('cara2', preAdr0029: true);
    // Cara is held before Ben speaks: from then on she is a reader Alice
    // has not heard say she reads a v2-only list.
    await hold(alice, cara);
    expect(alice.devlistGate.contactDevicesBehind, 1,
        reason: 'a contact not yet heard from counts as behind');
    await introduce(alice, ben);
    await introduce(alice, cara);
    await says(alice, ben.myRid, ben.myRid, devlistReaderLevel, 'Ben');
    await says(alice, cara.myRid, cara.myRid, 0, 'Cara');
    await waitUntil(
        () => alice.debugOwnReaderLevel(laptop.myRid) == devlistReaderLevel,
        what: 'Alice has recorded her laptop');

    // 2. Held: one device behind, and only that one.
    expect(alice.devlistGate.contactDevicesBehind, 1);
    expect(alice.devlistGate.ownDevicesBehind, 0);
    expect(alice.devlistGate.open, isFalse);
    await quiet([alice, ben, cara, laptop]);
    final before = (await own(alice))!;
    expect(before.isV2Only, isFalse, reason: 'not while it runs');
    expect(before.sig, isNotNull);
    expect(before.version, 2, reason: 'the link\'s version');
    // Nor at a restart, where the gate is read again.
    await stop(alice);
    alice = await start('alice2');
    expect((await own(alice))!.toJson(), before.toJson(),
        reason: 'not at a restart');
    expect(await alice.vault.kvGet('devlist_v2only_migrated'), isNull);

    // 3. Cara's app updates, and her next message says she reads it.
    await quiet([alice, ben, cara, laptop]);
    await stop(cara);
    cara = await start('cara2');
    await waitUntil(() => up(cara), what: 'Cara back');
    await cara.sendText(alice.myRid, 'updated');
    await waitUntil(() => moved(alice),
        what: 'Alice has moved, without a restart');
    final mine = (await own(alice))!;
    expect(mine.version, before.version + 1, reason: 'the next version');
    expect(mine.isV2Only, isTrue);
    expect(mine.toJson().containsKey('sig'), isFalse);
    expect(mine.toJson().containsKey('sig2'), isFalse);
    expect([for (final d in mine.devices) b64(d.deviceEdPub)],
        [for (final d in before.devices) b64(d.deviceEdPub)],
        reason: 'the same devices: only the signing moved');
    final soleFp = b64(await deviceListFingerprintV3(mine.version, mine.devices));
    expect(b64(await mine.fingerprint()), soleFp);
    expect(await alice.vault.kvGet('own_list_h'), soleFp,
        reason: 'the claim Alice now makes on every message');
    expect(alice.devlistGate.moved, isTrue);

    // 4. Every reader takes it.
    for (final c in [ben, cara]) {
      await holdsVersion(c, alice.myRid, mine.version);
      final got = (await held(c, alice.myRid))!;
      expect(got.isV2Only, isTrue, reason: '${c.displayName} holds sig3 alone');
      expect(b64(await got.fingerprint()), soleFp,
          reason: '${c.displayName} computes what Alice claims');
    }
    await waitUntil(
        () async =>
            (await own(laptop))?.version == mine.version &&
            await moved(laptop),
        what: 'the laptop has learned the v2-only list');
    await logHas(alice, mine.version, soleFp);
    for (final c in [ben, cara]) {
      final s = await checkLog(c, alice.myRid);
      expect(s?.state, KtContactState.confirmed);
      expect(s?.logVersion, mine.version);
      expect(s?.logFpB64, soleFp);
    }
    // Messages both ways, so each side's gossip compares the new claims.
    for (final c in [ben, cara]) {
      await alice.sendText(c.myRid, 'after the move');
      await c.sendText(alice.myRid, 'after the move too');
      await waitUntil(
          () =>
              received(c, alice.myRid, 'after the move') &&
              received(alice, c.myRid, 'after the move too'),
          what: 'messages both ways with ${c.displayName}');
    }
    await quiet([alice, ben, cara, laptop]);
    await Future.wait([
      for (final s in [alice, laptop, ben, cara]) s.kt.check()
    ]);
    for (final s in [alice, laptop, ben, cara]) {
      noAlerts(s);
    }
    expect(alice.kt.health, KtHealth.ok);
  });

  test(
      '5. a contact on an older build added after the move: the account '
      'does not move back, withholds its claim until they say they read the '
      'list, says so on their screen, and nobody is alerted', () async {
    final alice = await start('alice5');
    final laptop = await startLinked('alice5-laptop', alice);
    final ben = await start('ben5');
    await introduce(alice, ben);
    await waitUntil(() => moved(alice), what: 'Alice has moved');
    await quiet([alice, ben, laptop]);
    final mine = (await own(alice))!;
    final claim = await alice.vault.kvGet('own_list_h');
    final logged = await logLatest(alice);

    // Dan: from 3.9.9 up to ADR 0029 — reads a v2-only list, says nothing.
    var dan = await start('dan5', preAdr0029: true, grace: Duration.zero);
    // Eve: from before 3.9.9 — cannot parse a v2-only list at all (each one
    // that reaches her is dropped, as her parser would throw on it), and
    // here with no log, whose check would otherwise install it.
    final eve = await start('eve5',
        preAdr0029: true, log: false, grace: Duration.zero);
    eve.debugOnDecrypted = (path, from, dec) => _isV2OnlyDevlist(dec.plaintext);
    await introduce(alice, dan);
    await introduce(alice, eve);
    await says(alice, dan.myRid, dan.myRid, 0, 'Dan');
    await says(alice, eve.myRid, eve.myRid, 0, 'Eve');

    // Dan reads the list: in-band or from the log, and the log confirms it.
    await holdsVersion(dan, alice.myRid, mine.version);
    final atDan = (await held(dan, alice.myRid))!;
    expect(atDan.isV2Only, isTrue);
    expect(b64(await atDan.fingerprint()), claim);
    expect((await checkLog(dan, alice.myRid))?.state,
        KtContactState.confirmed);
    // Eve cannot: she holds Alice's one-device baseline, version 1, while
    // Alice's own devices hold a later version.
    expect(await eve.heldContactListVersion(alice.myRid), 1);

    // More traffic both ways, then more than the grace.
    for (final c in [dan, eve]) {
      await alice.sendText(c.myRid, 'to an older app');
      await c.sendText(alice.myRid, 'from an older app');
      await waitUntil(
          () =>
              received(c, alice.myRid, 'to an older app') &&
              received(alice, c.myRid, 'from an older app'),
          what: 'messages both ways with ${c.displayName}');
    }
    await quiet([alice, dan, eve, laptop]);
    // With no grace, a claim above the list held would have been judged an
    // update that never arrived the moment it was read; judged once more now.
    for (final c in [dan, eve]) {
      await c.debugEvaluateContact(alice.myRid);
    }

    // The account did not move back: the same list, version, claim and log
    // entry — nothing signed at a version it had published.
    expect((await own(alice))!.toJson(), mine.toJson());
    expect(await alice.vault.kvGet('own_list_h'), claim);
    expect(await logLatest(alice), logged);
    // Its claim was withheld from both: neither recorded one from Alice.
    expect(await dan.vault.kvGet('cdl_claims_${alice.myRid}'), isNull);
    expect(await eve.vault.kvGet('cdl_claims_${alice.myRid}'), isNull);
    // So Eve, who cannot read the list, was not told it never arrived; and
    // nobody anywhere was alerted.
    for (final s in [alice, laptop, ben, dan, eve]) {
      noAlerts(s);
    }
    // What Alice is told: on each contact's screen, and in the count.
    expect(alice.readerBehind(dan.myRid), isTrue);
    expect(alice.readerBehind(eve.myRid), isTrue);
    expect(alice.readerBehind(ben.myRid), isFalse);
    expect(alice.devlistGate.contactDevicesBehind, 2);

    // Dan updates. His next message says he reads it; Alice's claim to him
    // resumes, matches what he holds, and the notice goes.
    await stop(dan);
    dan = await start('dan5');
    await waitUntil(() => up(dan), what: 'Dan back');
    await dan.sendText(alice.myRid, 'updated');
    await says(alice, dan.myRid, dan.myRid, devlistReaderLevel, 'Dan');
    expect(alice.readerBehind(dan.myRid), isFalse);
    await alice.sendText(dan.myRid, 'with a claim');
    await waitUntil(() => received(dan, alice.myRid, 'with a claim'),
        what: 'Dan has Alice\'s next message');
    await waitUntil(() async {
      final raw = await dan.vault.kvGet('cdl_claims_${alice.myRid}');
      if (raw == null) return false;
      final c = (jsonDecode(raw) as Map)[alice.myRid];
      return c is Map && c['v'] == mine.version && c['h'] == claim;
    }, what: 'Dan has recorded Alice\'s claim, the list he holds');
    await quiet([alice, dan]);
    await dan.debugEvaluateContact(alice.myRid);
    noAlerts(dan);
    noAlerts(alice);
  });

  test(
      '6. the kill switch holds an account whose gate is open, and does not '
      'un-flip one that has moved', () async {
    var alice = await start('alice6', switchOn: false);
    final laptop = await startLinked('alice6-laptop', alice);
    final ben = await start('ben6');
    await introduce(alice, ben);
    await says(alice, ben.myRid, ben.myRid, devlistReaderLevel, 'Ben');
    await waitUntil(
        () => alice.debugOwnReaderLevel(laptop.myRid) == devlistReaderLevel,
        what: 'Alice has recorded her laptop');
    final g = alice.devlistGate;
    expect(g.contactDevicesBehind, 0);
    expect(g.ownDevicesBehind, 0);
    expect(g.moveAllowed, isFalse, reason: 'and the view says why');
    expect(g.open, isFalse);
    await quiet([alice, ben, laptop]);
    expect(await moved(alice), isFalse,
        reason: 'every reader is ready and the switch holds it');

    // The next start is a build with the switch on: it moves as it starts.
    await stop(alice);
    alice = await start('alice6');
    expect(await moved(alice), isTrue);
    final after = (await own(alice))!;
    await holdsVersion(ben, alice.myRid, after.version);

    // And the one after it throws the switch again: Alice stays moved.
    await quiet([alice, ben, laptop]);
    await stop(alice);
    alice = await start('alice6', switchOn: false);
    expect((await own(alice))!.toJson(), after.toJson());
    await alice.broadcastMyDeviceList();
    expect((await own(alice))!.toJson(), after.toJson(),
        reason: 'its version re-signed comes out exactly as it was');
    expect(alice.devlistGate.moved, isTrue);
    await alice.sendText(ben.myRid, 'still moved');
    await waitUntil(() => received(ben, alice.myRid, 'still moved'),
        what: 'Ben has the message');
    await quiet([alice, ben, laptop]);
    expect((await held(ben, alice.myRid))!.toJson(), after.toJson());
    await ben.debugEvaluateContact(alice.myRid);
    noAlerts(alice);
    noAlerts(ben);
  });

  test(
      '7. every one of the account\'s own devices counts: an older laptop '
      'holds the move until it updates; no linked device, no move', () async {
    final alice = await start('alice7');
    var laptop = await startLinked('alice7-laptop', alice, preAdr0029: true);
    final ben = await start('ben7');
    await introduce(alice, ben);
    await says(alice, ben.myRid, ben.myRid, devlistReaderLevel, 'Ben');
    await waitUntil(() => alice.debugOwnReaderLevel(laptop.myRid) == 0,
        what: 'Alice has recorded her laptop as an older build');
    expect(alice.devlistGate.ownDevicesBehind, 1);
    expect(alice.devlistGate.contactDevicesBehind, 0);
    await quiet([alice, ben, laptop]);
    expect(await moved(alice), isFalse, reason: 'the laptop holds it');

    // The laptop updates and says so with nothing but its start-up
    // announcement: it sends no message of its own.
    await stop(laptop);
    laptop = await start('alice7-laptop');
    await waitUntil(() => moved(alice), what: 'Alice has moved');
    await waitUntil(() => moved(laptop), what: 'the laptop has the new list');
    await quiet([alice, ben, laptop]);
    noAlerts(laptop);
    noAlerts(alice);

    // Contacts, every one ready, and no linked device: nothing to protect.
    final gil = await start('gil7');
    final hal = await start('hal7');
    await introduce(gil, hal);
    await says(gil, hal.myRid, hal.myRid, devlistReaderLevel, 'Hal');
    await says(hal, gil.myRid, gil.myRid, devlistReaderLevel, 'Gil');
    await quiet([gil, hal]);
    for (final s in [gil, hal]) {
      expect(s.devlistGate.ownDevices, 0);
      expect(s.devlistGate.contactDevicesBehind, 0);
      expect(s.devlistGate.open, isFalse);
      expect(await moved(s), isFalse);
    }
  });

  test(
      '10. after the move, a list the account key signed and its devices '
      'never issued still raises the alarm on the root and on the laptop',
      () async {
    final phone = await start('phone10');
    final laptop = await startLinked('phone10-laptop', phone);
    final carol = await start('carol10');
    await introduce(phone, carol);
    await waitUntil(() => moved(phone), what: 'the phone has moved');
    final mine = (await own(phone))!;
    await holdsVersion(carol, phone.myRid, mine.version);
    await waitUntil(
        () async => (await own(laptop))?.version == mine.version,
        what: 'the laptop has the moved list');
    await quiet([phone, carol, laptop]);
    noAlerts(phone);
    noAlerts(laptop);

    // Whoever holds the account seed signs — in the shape the account signs
    // now — a list adding a device of theirs, and shows it to Carol alone.
    final account = await phone.accountIdentity();
    final x = await ZIdentity.generate();
    final rogue = await account.signDeviceCert(
        deviceEdPub: x.edPub, deviceXPub: x.xPub, deviceId: 'rogue');
    final split = await account.signDeviceList(
        [...mine.devices, rogue], mine.version + 1,
        v2Only: true);
    expect(await carol.ktInstallFromLog(phone.myRid, split), isTrue,
        reason: 'a v2-only list above the held one, signed by the account');
    expect(await carol.heldContactListVersion(phone.myRid), mine.version + 1);

    // Carol's next message carries her echo of it, to both of the
    // account's devices.
    await carol.sendText(phone.myRid, 'after the split');
    await waitUntil(() => phone.ownAccountAlert != null,
        what: 'the root\'s alarm on a list it never signed');
    expect(jsonDecode(phone.ownAccountAlert!)['k'], OwnAlertKind.unissued);
    await waitUntil(() => laptop.ownAccountAlert != null,
        what: 'the laptop\'s alarm on a list its root never sent it');
    expect(jsonDecode(laptop.ownAccountAlert!)['k'], OwnAlertKind.unissued);
  });

  test(
      '11. a contact whose devices differ — one reads a v2-only list, one '
      'cannot — has the claim on the one and not the other, either way '
      'round, so the other is not told the update never arrived; and the '
      'copy without the claim keeps its timer', () async {
    final alice = await start('alice11');
    // Carol's list comes late to Alice's laptop too: Carol's old phone does
    // not know the laptop is there (that is in Alice's list, which it cannot
    // read), and Carol's laptop sends its list on only once a minute. That
    // is not what this test is about either, so this grace outlasts it.
    final laptop = await startLinked('alice11-laptop', alice,
        grace: const Duration(minutes: 10));
    final dave = await start('dave11');
    await introduce(alice, dave);
    await waitUntil(() => moved(alice), what: 'Alice has moved');
    await quiet([alice, dave, laptop]);
    final mine = (await own(alice))!;
    final claim = await alice.vault.kvGet('own_list_h');

    // Two contacts added after the move, each with two devices that differ.
    // Ben's phone reads v2-only lists; the laptop he has linked is a build
    // from before 3.9.9 — every v2-only list that reaches it is dropped, as
    // its parser would throw on one — with no log, whose check would
    // otherwise install it, and judging a claim the moment it reads one.
    final ben = await start('ben11');
    final benOld = await startLinked('ben11-old', ben,
        preAdr0029: true,
        log: false,
        grace: Duration.zero,
        parsesV2Only: false);
    // Carol is the other way round: her phone is that build, and the laptop
    // she has linked reads v2-only lists.
    final carol = await start('carol11',
        preAdr0029: true, log: false, grace: Duration.zero);
    carol.debugOnDecrypted =
        (path, from, dec) => _isV2OnlyDevlist(dec.plaintext);
    // The updated laptop is sent the claim, and the list it names comes to
    // it late here: the old phone beside it echoes first, and Alice resends a
    // list to one contact once a minute. A late list is not what this test is
    // about, so its grace outlasts the test, and it reads the list from the
    // log below.
    final carolNew = await startLinked('carol11-new', carol,
        grace: const Duration(minutes: 10));
    await introduce(alice, ben);
    await introduce(alice, carol);

    // Alice holds each list naming the second device, each second device
    // holds Alice, and each speaks to her once — so she has recorded what
    // all four read.
    for (final (c, second, what) in [
      (ben, benOld, 'Ben\'s old laptop'),
      (carol, carolNew, 'Carol\'s laptop'),
    ]) {
      await holdsVersion(alice, c.myRid, 2);
      await waitUntil(() => second.contacts.containsKey(alice.myRid),
          what: '$what holds Alice, mirrored from its phone');
      await alice.sendText(c.myRid, 'to both of ${c.displayName}\'s devices');
      await waitUntil(
          () => received(
              second, alice.myRid, 'to both of ${c.displayName}\'s devices'),
          what: '$what has Alice\'s message');
      await second.sendText(alice.myRid, 'from $what');
      await waitUntil(() => received(alice, c.myRid, 'from $what'),
          what: 'Alice has the message from $what');
    }
    await says(alice, ben.myRid, ben.myRid, devlistReaderLevel, 'Ben\'s phone');
    await says(alice, ben.myRid, benOld.myRid, 0, 'Ben\'s old laptop');
    await says(alice, carol.myRid, carol.myRid, 0, 'Carol\'s phone');
    await says(alice, carol.myRid, carolNew.myRid, devlistReaderLevel,
        'Carol\'s laptop');

    // Now what each device is sent: a message to each contact, on a timer.
    for (final c in [ben, carol]) {
      await alice.setDisappearingTimer(c.myRid, 3600);
      await alice.sendText(c.myRid, 'timed, to ${c.displayName}');
    }
    for (final (s, c) in [
      (ben, ben),
      (benOld, ben),
      (carol, carol),
      (carolNew, carol),
    ]) {
      await waitUntil(
          () => received(s, alice.myRid, 'timed, to ${c.displayName}'),
          what: '${s.displayName} has Alice\'s timed message');
    }
    await quiet([alice, laptop, dave, ben, benOld, carol, carolNew]);
    // With no grace, a claim above the list held would have been judged an
    // update that never arrived the moment it was read; judged once more now.
    await benOld.debugEvaluateContact(alice.myRid);
    await carol.debugEvaluateContact(alice.myRid);

    // The device that cannot read the list was sent no claim, and holds an
    // older list; the copy it was sent is otherwise the message, its timer
    // too. Carol's phone is the one that shows it: what it holds is the copy
    // Alice sent it, there before any its laptop could pass on.
    for (final s in [benOld, carol]) {
      expect(await s.vault.kvGet('cdl_claims_${alice.myRid}'), isNull,
          reason: '${s.displayName} was sent no claim');
      expect(await s.heldContactListVersion(alice.myRid),
          lessThan(mine.version));
    }
    for (final (s, c) in [(carol, carol), (benOld, ben)]) {
      final timed = s.messagesByChat[alice.myRid]!.firstWhere(
          (m) => !m.outgoing && m.body == 'timed, to ${c.displayName}');
      expect(timed.expireAtMs, greaterThan(0),
          reason: '${s.displayName}: a message its sender set to go does '
              'not keep on one device');
    }

    // The device that reads v2-only lists was sent the claim, and holds —
    // or, on Carol's laptop, reads from the log — the list it names.
    for (final s in [ben, carolNew]) {
      await waitUntil(() async {
        final raw = await s.vault.kvGet('cdl_claims_${alice.myRid}');
        final c = raw == null ? null : (jsonDecode(raw) as Map)[alice.myRid];
        return c is Map && c['v'] == mine.version && c['h'] == claim;
      }, what: '${s.displayName} has recorded Alice\'s claim');
    }
    await holdsVersion(ben, alice.myRid, mine.version);
    await checkLog(carolNew, alice.myRid);
    await holdsVersion(carolNew, alice.myRid, mine.version);
    await carolNew.debugEvaluateContact(alice.myRid);

    // Nobody anywhere was alerted.
    for (final s in [alice, laptop, dave, ben, benOld, carol, carolNew]) {
      noAlerts(s);
    }
    // And what Alice is told: each contact has a device behind.
    expect(alice.readerBehind(ben.myRid), isTrue);
    expect(alice.readerBehind(carol.myRid), isTrue);
    expect(alice.devlistGate.contactDevicesBehind, 2);
  });

  testWidgets(
      '8-9. Settings\' developer view shows the gate, and a contact\'s '
      'screen names an older app after the move', (t) async {
    await t.binding.setSurfaceSize(const Size(800, 9000));
    addTearDown(() => t.binding.setSurfaceSize(null));
    final en = AppLocalizationsEn();
    late ChatService alice, laptop, ben, dan;
    late Directory side;
    late PushService push;
    late AppLock lock;
    late AppPrefs prefs;
    await t.runAsync(() async {
      // No log for the account whose screens are shown: opening a contact's
      // screen asks the log for a refresh (§19.9.1), and that would run
      // against the vault on the widget test's fake clock. The gate and the
      // move do not involve the log.
      alice = await start('alice8', log: false);
      laptop = await startLinked('alice8-laptop', alice);
      ben = await start('ben8', preAdr0029: true);
      await introduce(alice, ben);
      await says(alice, ben.myRid, ben.myRid, 0, 'Ben');
      await waitUntil(
          () => alice.debugOwnReaderLevel(laptop.myRid) == devlistReaderLevel,
          what: 'Alice has recorded her laptop');
      await alice.setDevMode(true);
      side = await Directory.systemTemp.createTemp('z_dlcap_side');
      dirs['side8'] = side;
      push = PushService(transport: alice.transport, vault: alice.vault);
      lock = AppLock(root: side, store: MemorySecretStore());
      prefs = AppPrefs(root: side);
      await prefs.load();
    });
    Widget settings() => MultiProvider(
          providers: [
            ChangeNotifierProvider<ChatService>.value(value: alice),
            ChangeNotifierProvider<Transport>.value(value: alice.transport),
            ChangeNotifierProvider<PushService>.value(value: push),
            ChangeNotifierProvider<AppLock>.value(value: lock),
            ChangeNotifierProvider<AppPrefs>.value(value: prefs),
          ],
          child: MaterialApp(
            debugShowCheckedModeBanner: false,
            theme: ZTheme.light(),
            localizationsDelegates: AppLocalizations.localizationsDelegates,
            supportedLocales: AppLocalizations.supportedLocales,
            home: const SettingsScreen(),
          ),
        );

    // 8. Before the move: one contact's device behind, none of Alice's own.
    await t.pumpWidget(settings());
    await t.pump(const Duration(milliseconds: 50));
    expect(find.text(en.stDevlistSigning), findsOneWidget);
    expect(find.textContaining(en.stDevlistDual), findsOneWidget);
    expect(find.textContaining('Contacts\' devices not yet capable: 1'),
        findsOneWidget);
    expect(find.textContaining('Your other devices not yet capable: 0'),
        findsOneWidget);
    expect(find.textContaining(en.stDevlistWaiting), findsOneWidget);

    // Ben updates; Alice moves; the view says so.
    await t.runAsync(() async {
      await quiet([alice, ben, laptop]);
      await stop(ben);
      ben = await start('ben8');
      await waitUntil(() => up(ben), what: 'Ben back');
      await ben.sendText(alice.myRid, 'updated');
      await waitUntil(() => moved(alice), what: 'Alice has moved');
    });
    await t.pump(const Duration(milliseconds: 50));
    expect(find.textContaining(en.stDevlistMoved), findsOneWidget);
    expect(find.textContaining('Contacts\' devices not yet capable: 0'),
        findsOneWidget);

    // 9. Dan, on an older app, is added after the move: his screen says so.
    await t.runAsync(() async {
      dan = await start('dan8', preAdr0029: true);
      await introduce(alice, dan);
      await says(alice, dan.myRid, dan.myRid, 0, 'Dan');
    });
    await t.pumpWidget(ChangeNotifierProvider<ChatService>.value(
      value: alice,
      child: MaterialApp(
        debugShowCheckedModeBanner: false,
        theme: ZTheme.light(),
        localizationsDelegates: AppLocalizations.localizationsDelegates,
        supportedLocales: AppLocalizations.supportedLocales,
        home: ContactInfoScreen(rid: dan.myRid),
      ),
    ));
    await t.pump(const Duration(milliseconds: 50));
    expect(find.text(en.ciReaderBehind), findsOneWidget);
    expect(find.textContaining('older than 3.9.9'), findsOneWidget);
    // Not on the screen of a contact who has said he reads it.
    await t.pumpWidget(ChangeNotifierProvider<ChatService>.value(
      value: alice,
      child: MaterialApp(
        debugShowCheckedModeBanner: false,
        theme: ZTheme.light(),
        localizationsDelegates: AppLocalizations.localizationsDelegates,
        supportedLocales: AppLocalizations.supportedLocales,
        home: ContactInfoScreen(rid: ben.myRid),
      ),
    ));
    await t.pump(const Duration(milliseconds: 50));
    expect(find.text(en.ciReaderBehind), findsNothing);
    // Opening a contact's screen can arm a post-quantum identity nudge on
    // the widget test's fake clock (`pq_screens_test.dart`, settlePqSends):
    // move that clock, letting real work run, until none is pending.
    final deadline = DateTime.now().add(const Duration(seconds: 30));
    while (alice.pqSendPending) {
      if (DateTime.now().isAfter(deadline)) {
        fail('a post-quantum identity send was still pending after 30 s');
      }
      await t.pump(const Duration(seconds: 1));
      await t.runAsync(
          () => Future<void>.delayed(const Duration(milliseconds: 50)));
    }
    // Unmount, and let the screens' own async work finish against the live
    // vault, moving the fake clock as it does.
    await t.pumpWidget(const SizedBox());
    for (var i = 0; i < 10; i++) {
      await t.runAsync(
          () => Future<void>.delayed(const Duration(milliseconds: 50)));
      await t.pump(const Duration(milliseconds: 100));
    }
    await t.runAsync(() async {
      await quiet([alice, ben, dan, laptop]);
      for (final s in [alice, laptop, ben, dan]) {
        noAlerts(s);
      }
    });
  });

  test('the new strings are in both locales, translated', () async {
    final en = lookupAppLocalizations(const Locale('en'));
    final es = lookupAppLocalizations(const Locale('es'));
    for (final (a, b) in [
      (en.stDevlistSigning, es.stDevlistSigning),
      (en.stDevlistDual, es.stDevlistDual),
      (en.stDevlistMoved, es.stDevlistMoved),
      (en.stDevlistContactsBehind(2), es.stDevlistContactsBehind(2)),
      (en.stDevlistOwnBehind(2), es.stDevlistOwnBehind(2)),
      (en.stDevlistWaiting, es.stDevlistWaiting),
      (en.stDevlistMoving, es.stDevlistMoving),
      (en.stDevlistNeedsBoth, es.stDevlistNeedsBoth),
      (en.stDevlistSwitchedOff, es.stDevlistSwitchedOff),
      (en.stDevlistRootDecides, es.stDevlistRootDecides),
      (en.ciReaderBehind, es.ciReaderBehind),
      (en.ciReaderBehindBody('A'), es.ciReaderBehindBody('A')),
    ]) {
      expect(b, isNot(a), reason: 'translated, not copied: $a');
    }
    expect(es.stDevlistContactsBehind(2), contains('2'));
    expect(es.ciReaderBehindBody('Ana'), contains('Ana'));
  });
}
