// An alarm about your own account is raised only on evidence that somebody
// other than the account's key holder cannot make (phase 32, ADR 0026).
//
// Three banners tell the owner something is wrong with their own account —
// "a contact was given a device list for your account that this device never
// issued", "this device was removed from your account" and "a device list you
// did not issue has been published to the transparency log" — and the first two
// each tell the user to reset their identity. Until this change any contact,
// or any member of a group the user is in (who becomes a contact on joining),
// could raise the first with one message carrying a made-up echo of the
// user's device list, and the second with one bare removal notice: neither
// was signed, checked or rate-limited, and both came back after being
// dismissed. The log's banner came back at every check, which is how the
// own-list signing race (patch 42) left vaults that alarm on the account's
// own genuine log entry at every start.
//
// Real clients, the real relay and the real transparency log (kt/server.js)
// on loopback.
//
// Criteria, each a test below:
//   1. a contact running a modified client — one that echoes device lists
//      for the victim's account it was never given, sends removal notices
//      with nothing signed behind them (bare, with a forged list, with the
//      victim's own genuine list from before the device was linked) and
//      hands over lists unasked (forged, and that genuine one, which no echo
//      of hers named) — raises nothing on either of the victim's devices
//      over 50 rounds, leaves the victim's alarm and device-list state
//      exactly as it was, and is asked for the list behind its echo a
//      bounded number of times;
//   2. a list that verifies under the account's own key and that its devices
//      never issued — a split view handed to one contact — still raises "a
//      list your device never issued" on the root and on the linked device;
//   3. a genuine removal by the root still tells the removed device: from the
//      list a contact's removal notice carries, and, where no contact tells
//      it, from the log's copy of the list — while a device just linked,
//      whose first look at the log finds the account's list from before it,
//      is told nothing (two tests);
//   4. a dismissed alarm stays dismissed for the evidence it was raised on —
//      the same list echoed again, the same removal heard again, the same log
//      entry checked again, across a restart — and new evidence raises it
//      again (three tests: the echo, the removal, the log);
//   5. the own-list race repaired: a vault whose record of its own lists was
//      overwritten by the signing race (its end state written directly)
//      starts quietly and stays quiet across a restart, while an entry at a
//      version it recorded that names a device the account never held still
//      alarms — and so does one naming only its own devices that reached the
//      log after this build first ran; where the race left its list as the
//      log's latest entry, the root moves past it; and a reset of the log's
//      history ends the repair (five tests);
//   6. a log entry for the account that does not open as one of its lists
//      is not evidence of anything the account's key signed: the owner is
//      not told to check their devices, while a contact still holds sends to
//      the account as a conflict (adr/0006).
@Tags(['integration'])
@Timeout(Duration(minutes: 10))
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
import 'package:zapp/core/system_messages.dart';
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
  late int relayPort;
  late Process log;
  late int logPort;
  late Uint8List logPub;
  final logSeed =
      Uint8List.fromList(List<int>.generate(32, (i) => (i * 5 + 17) & 0xff));
  final dirs = <String, Directory>{};
  final live = <ChatService>[];

  // Each service runs in an error zone of its own, and an error raised
  // inside a running service fails the test that was running. A service
  // [stop] has shut down can still have work in flight that then fails
  // against the database it closed — a reconnect's re-assertion of the
  // root's list, say; that error, and only that one, is expected (as in
  // `own_list_race_test.dart`).
  final stopped = <ChatService>{};
  final strays = <String>[];

  /// Every envelope a tracked service reads goes through
  /// [ChatService.debugInbound], and the test keeps the future. The client
  /// acknowledges an envelope BEFORE the post-processing that judges what it
  /// carried — the device-list echo, a removal notice, a list handed over —
  /// so "the relay holds nothing" says every envelope was read, not that
  /// every judgement has been made. With the futures held, that can be
  /// waited for too.
  final inflight = <ChatService, Set<Future<void>>>{};

  /// Bare relay clients standing in for devices that exist only in a signed
  /// list: they read their mailbox and acknowledge everything, so a contact
  /// fanning out to them does not leave envelopes at the relay for ever.
  final drains = <Transport>[];

  // Short, so a deferred judgement resolves quickly; a test that needs the
  // judgement to happen the moment the message is read sets zero.
  const grace = Duration(milliseconds: 700);

  setUpAll(() async {
    HttpOverrides.global = null;
    logPort = await _freePort();
    log = await Process.start('node', ['server.js'],
        workingDirectory: '$root${Platform.pathSeparator}kt',
        environment: {
          'KT_SEED': [
            for (final b in logSeed) b.toRadixString(16).padLeft(2, '0')
          ].join(),
          'KT_EPHEMERAL': '1',
          'KT_PORT': '$logPort',
          // One log serves the whole file; its publish gates are not what
          // this file checks.
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

  // A relay per test, so "nothing is waiting at the relay" means this
  // test's traffic has all been read.
  setUp(() async {
    relayPort = await _freePort();
    relay = await Process.start('node', ['server.js'],
        workingDirectory: '$root${Platform.pathSeparator}server',
        environment: {
          'PORT': '$relayPort',
          'LOG_LEVEL': 'silent',
          'METRICS_TOKEN': 'z-apptest-metrics',
        });
    await _healthy(relayPort);
  });

  tearDown(() async {
    for (final s in live.toList()) {
      s.dispose();
      await s.transport.stop();
    }
    live.clear();
    inflight.clear();
    for (final t in drains) {
      await t.stop();
    }
    drains.clear();
    relay.kill();
    final found = [...strays];
    strays.clear();
    expect(found, isEmpty, reason: 'errors raised inside a running service');
  });

  tearDownAll(() async {
    log.kill();
    for (final d in dirs.values) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  KtConfig ktConfig() =>
      KtConfig(logUrl: 'http://127.0.0.1:$logPort', logPubB64: b64(logPub));

  /// [name]'s client: a new account the first time, the same vault after
  /// [stop].
  Future<ChatService> start(String name, {Duration? devlistGrace}) async {
    final dir =
        dirs[name] ??= await Directory.systemTemp.createTemp('z_alarm_$name');
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
          ktConfig: ktConfig(),
        );
        made = svc;
        svc.devlistGrace = devlistGrace ?? grace;
        // The log is checked when the test says so.
        svc.kt.scheduled = false;
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
    // A check started at init may still be running; let it finish before
    // the vault it writes to closes.
    await svc.kt.check();
    stopped.add(svc);
    svc.dispose();
    await svc.transport.stop();
    live.remove(svc);
    await svc.vault.db.close();
  }

  Future<void> waitUntil(FutureOr<bool> Function() cond,
      {required String what,
      Duration timeout = const Duration(seconds: 60)}) async {
    final deadline = DateTime.now().add(timeout);
    while (!await cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
  }

  bool linked(ChatService s) =>
      s.transport.isConnected && s.transport.isSenderConnected;

  bool received(ChatService svc, String rid, String body) =>
      svc.messagesByChat[rid]?.any((m) => !m.outgoing && m.body == body) ==
      true;

  /// How many inner messages [svc] has read from [from]'s primary device.
  Future<int> readFrom(ChatService svc, String from) async {
    final rows = await svc.vault.db.rawQuery(
        'SELECT COUNT(*) AS n FROM inbox_dedupe WHERE from_rid = ?', [from]);
    return (rows.first['n'] as num).toInt();
  }

  /// Envelopes the relay holds that nobody has acknowledged. Read from
  /// /metrics (z_queued_envelopes) since P1-14 trimmed /health to liveness;
  /// /metrics is token-gated and the relay is spawned with METRICS_TOKEN
  /// above. Absent means the scrape failed (a wrong token is a 401), not that
  /// the relay is empty: that fails loudly rather than reading as settled.
  Future<int> relayUnacked() async {
    final req = await HttpClient()
        .getUrl(Uri.parse('http://127.0.0.1:$relayPort/metrics'));
    req.headers.set('authorization', 'Bearer z-apptest-metrics');
    final res = await req.close();
    final body = await res.transform(utf8.decoder).join();
    final m = RegExp(r'^z_queued_envelopes (\d+)$', multiLine: true)
        .firstMatch(body);
    if (m == null) {
      throw StateError(
          'no z_queued_envelopes on /metrics (HTTP ${res.statusCode})');
    }
    return int.parse(m.group(1)!);
  }

  /// Nothing [group] sent is waiting in an outbox, and nothing is waiting at
  /// the relay: every envelope anyone sent has been read by whoever it was
  /// for.
  Future<bool> isQuiet(List<ChatService> group) async {
    for (final s in group) {
      if ((await s.vault.db.query('outbox', limit: 1)).isNotEmpty) {
        return false;
      }
    }
    return await relayUnacked() == 0;
  }

  /// [svc]'s inbound, from here on, through [ChatService.debugInbound], each
  /// future kept in [inflight] until it completes.
  void track(ChatService svc) {
    final set = inflight[svc] = <Future<void>>{};
    svc.transport.onMessage = (m) {
      late final Future<void> f;
      f = svc.debugInbound(m).whenComplete(() => set.remove(f));
      set.add(f);
    };
  }

  /// [group] has gone quiet: nothing in an outbox, nothing at the relay, and
  /// nothing read and still being handled — checked again after each wait,
  /// because handling a message can send one.
  Future<void> settle(List<ChatService> group, {required String what}) async {
    final deadline = DateTime.now().add(const Duration(seconds: 90));
    while (true) {
      final busy = [for (final s in group) ...?inflight[s]];
      if (busy.isEmpty && await isQuiet(group)) {
        // Read again: an inbound may have started while the outboxes and
        // the relay were being asked.
        if ([for (final s in group) ...?inflight[s]].isEmpty) return;
      }
      if (busy.isNotEmpty) await Future.wait(busy);
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('never settled: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
  }

  /// A device linked to [root]'s account, running as a client of its own,
  /// and listed by [root] (version 2 for a fresh account).
  /// A device of [root]'s account, enrolled and started but on no list yet:
  /// what a device is between pairing and its root's list reaching it.
  Future<({ChatService svc, DeviceCertificate cert})> joining(
      ChatService root, String name,
      {Duration? devlistGrace}) async {
    final account = await root.accountIdentity();
    final devId = await ZIdentity.generate();
    final cert = await account.signDeviceCert(
        deviceEdPub: devId.edPub, deviceXPub: devId.xPub, deviceId: name);
    final dir =
        dirs[name] = await Directory.systemTemp.createTemp('z_alarm_$name');
    final vault = await Vault.open(rootOverride: dir);
    await vault.kvPut('identity', jsonEncode(devId.toJson()));
    await vault.kvPut(
        'account',
        jsonEncode((await AccountIdentity.fromEnrollment(
          accountEdPub: account.accountEdPub,
          accountMlPub: await root.pqAccountPublic(),
          deviceEdSeed: devId.edSeed,
          deviceXSeed: devId.xSeed,
          deviceId: name,
          deviceCert: cert,
        ))
            .toJson()));
    await vault.kvPut('my_devices', jsonEncode([account.deviceCert.toJson()]),
        sensitive: false);
    await vault.db.close();
    final svc = await start(name, devlistGrace: devlistGrace);
    await waitUntil(() => linked(svc) && linked(root),
        what: '$name and its root connected');
    return (svc: svc, cert: cert);
  }

  Future<({ChatService svc, DeviceCertificate cert})> link(
      ChatService root, String name,
      {Duration? devlistGrace}) async {
    final d = await joining(root, name, devlistGrace: devlistGrace);
    final before = await root.ownDeviceListVersion();
    await root.addMyDevice(d.cert);
    await waitUntil(
        () async => await d.svc.ownDeviceListVersion() == before + 1,
        what: '$name learned the list that adds it');
    return d;
  }

  /// A device certificate [root]'s account signs for a device that runs no
  /// client — enough to sit in a list. [drained]: its mailbox is read and
  /// emptied by a bare relay client, for a test that waits for the relay to
  /// hold nothing while a contact fans out to it.
  Future<DeviceCertificate> paperDevice(ChatService root, String id,
      {bool drained = false}) async {
    final x = await ZIdentity.generate();
    if (drained) {
      final t = Transport(identity: x, serverUrl: 'ws://127.0.0.1:$relayPort');
      t.onMessage = (m) => t.ackReceived(id: m.id, from: m.from);
      t.start();
      drains.add(t);
    }
    return (await root.accountIdentity())
        .signDeviceCert(deviceEdPub: x.edPub, deviceXPub: x.xPub, deviceId: id);
  }

  /// [contact] and [account] (its root and any linked devices) know each
  /// other, and [contact] holds the account's current list and reaches every
  /// device on it. [settlePq]: and the two have finished exchanging their
  /// post-quantum keys, for a test that counts what one sends the other.
  Future<void> befriend(ChatService contact, ChatService root,
      List<ChatService> linkedDevices,
      {bool settlePq = false}) async {
    await waitUntil(() => linked(contact), what: '${contact.displayName} up');
    await contact.addContactFromCode(await root.myContactCode());
    await root.addContactFromCode(await contact.myContactCode());
    for (final d in linkedDevices) {
      // 13.7 may have carried the contact across already.
      if (!d.contacts.containsKey(contact.myRid)) {
        try {
          await d.addContactFromCode(await contact.myContactCode());
        } on FormatException {
          // Landed from the root while this scan was in flight.
        }
      }
    }
    final want = await root.ownDeviceListVersion();
    await contact.sendText(root.myRid, 'hello from ${contact.displayName}');
    await waitUntil(
        () async =>
            await contact.heldContactListVersion(root.myRid) >= want &&
            received(root, contact.myRid, 'hello from ${contact.displayName}'),
        what: '${contact.displayName} holds the account at v$want');
    final probe = 'reach ${contact.displayName}';
    await contact.sendText(root.myRid, probe);
    await waitUntil(
        () => [root, ...linkedDevices]
            .every((d) => received(d, contact.myRid, probe)),
        what: "${contact.displayName}'s messages reach every device");
    if (!settlePq) return;
    // The post-quantum exchange over: each side holds the other's key, so
    // nothing that exchange still owes is in flight when a test starts
    // counting what one side sends the other.
    await waitUntil(
        () =>
            [contact.contacts[root.myRid], root.contacts[contact.myRid]]
                .every((c) => c != null &&
                    (c.pqPub != null || c.pqCandidate != null)) &&
            !contact.pqSendPending &&
            !root.pqSendPending,
        what: '${contact.displayName} and ${root.displayName} hold each '
            "other's post-quantum key");
  }

  /// What the log serves as [svc]'s account's latest entry: (version, fp).
  Future<(int, String)?> logLatest(ChatService svc) async {
    final label = await ktLabel((await svc.accountIdentity()).accountEdPub);
    final hex =
        [for (final b in label) b.toRadixString(16).padLeft(2, '0')].join();
    final res = await (await HttpClient().getUrl(
            Uri.parse('http://127.0.0.1:$logPort/kt/v1/lookup/$hex')))
        .close();
    final j = (jsonDecode(await res.transform(utf8.decoder).join()) as Map)
        .cast<String, Object?>();
    final e = j['entry'];
    if (e is! Map) return null;
    return ((e['v'] as num).toInt(), e['fp'] as String);
  }

  /// Publish [list] to the log for its account, as whoever holds the
  /// account's seed can — [account] is that holder.
  Future<int> publish(AccountIdentity account, SignedDeviceList list,
      {List<int>? value}) async {
    final req = await ktPublishRequest(
        accountEdSeed: account.accountEdSeed!,
        version: list.version,
        fp: await list.fingerprint(),
        value: await ktSealValue(account.accountEdPub,
            value ?? utf8.encode(jsonEncode(list.toJson()))));
    final post = await (await HttpClient().postUrl(
            Uri.parse('http://127.0.0.1:$logPort/kt/v1/publish'))
          ..headers.contentType = ContentType.json
          ..write(jsonEncode(req)))
        .close();
    await post.drain<void>();
    return post.statusCode;
  }

  /// The alarm state, and the device-list state it is judged against, of
  /// one device — what a forgery must leave exactly as it was.
  Future<Map<String, Object?>> alarmState(ChatService svc) async => {
        'ownAccountAlert': svc.ownAccountAlert,
        'removedDeviceAlert': svc.removedDeviceAlert,
        'kt.ownAlert': svc.kt.ownAlert?.toJson(),
        for (final k in const [
          'own_alert',
          'own_alert_echo',
          'removed_alert',
          'own_list_v',
          'own_list_h',
          'own_list_json',
          'kt_own_known',
          'kt_own_first_v',
          'kt_own_alert',
          'my_devices',
          'my_devlist_version',
        ])
          k: await svc.vault.kvGet(k),
      };


  test(
      '1. a modified contact client: 50 rounds of bogus echoes, bare and '
      'forged removal notices and unasked forged lists raise nothing and '
      'change nothing', () async {
    // Judged the moment each message is read: an echo that is going to raise
    // an alarm raises it while that message is handled, not after a grace
    // this test would then have to wait out.
    final phone = await start('phone1', devlistGrace: Duration.zero);
    track(phone);
    final laptop = await link(phone, 'laptop1', devlistGrace: Duration.zero);
    track(laptop.svc);
    final mallory = await start('mallory1');
    track(mallory);
    await befriend(mallory, phone, [laptop.svc], settlePq: true);
    final account = await phone.accountIdentity();
    final victimAcct = account.accountEdPub;
    for (final s in [phone, laptop.svc, mallory]) {
      await s.kt.check(); // the start-up check, finished
    }
    await settle([phone, laptop.svc, mallory], what: 'set up');
    final phoneBefore = await alarmState(phone);
    final laptopBefore = await alarmState(laptop.svc);
    expect(phoneBefore['ownAccountAlert'], isNull);
    expect(laptopBefore['removedDeviceAlert'], isNull);
    final askedBefore = await readFrom(mallory, phone.myRid);

    // Lists Mallory's client presents as the victim's: her own account
    // signed them, so they verify under nobody's key but hers.
    final mAccount = await mallory.accountIdentity();
    Future<SignedDeviceList> forged(int version) async {
      final x = await ZIdentity.generate();
      final cert = await mAccount.signDeviceCert(
          deviceEdPub: x.edPub, deviceXPub: x.xPub, deviceId: 'forged');
      final real = await mAccount.signDeviceList([cert], version);
      return SignedDeviceList(
          accountEdPub: victimAcct,
          version: version,
          devices: real.devices,
          sig: real.sig,
          sig2: real.sig2);
    }

    // The victim's own genuine list from before the laptop was linked — the
    // log serves it to anyone who holds the account's public key. It names
    // the phone alone, so it does "omit" the laptop.
    final genuineV1 = await account.signDeviceList([account.deviceCert], 1);
    expect(await genuineV1.verify(), isTrue);

    var sent = 0;
    int now() => DateTime.now().millisecondsSinceEpoch;
    for (var i = 0; i < 50; i++) {
      // The echo. A modified client echoes whatever it likes; this one keeps
      // a forged list where the victim's list belongs, so the next message
      // it sends — and anything it hands over when asked — carries it.
      final bogus = await forged(3 + i);
      await mallory.vault.kvPut(
          'cdev_${phone.myRid}', jsonEncode(bogus.toJson()),
          sensitive: false);
      await mallory.debugSendRawInner(
          phone.myRid, InnerMessage.read(newMessageId(), now(), const []));
      sent++;

      // The removal notice: bare, with a forged list, or with the victim's
      // genuine v1 — the one signed list that really does omit the laptop.
      final variant = i % 3;
      final noteList = variant == 1
          ? await forged(100 + i)
          : variant == 2
              ? genuineV1
              : null;
      await mallory.debugSendRawInner(
          phone.myRid,
          InnerMessage(kind: 'dlrm', mid: newMessageId(), ts: now(), data: {
            'acct': b64(victimAcct),
            'v': noteList?.version ?? 200 + i,
            'h': b64(noteList == null
                ? Uint8List.fromList(List<int>.filled(16, i))
                : await noteList.fingerprint()),
            if (noteList != null) 'list': jsonEncode(noteList.toJson()),
          }));
      sent++;

      // And every fifth round, a list for the victim's account handed over
      // unasked, as the answer to a question nobody put: a forged one, or the
      // victim's own genuine v1 — signed by the account, but not the list
      // behind any echo of hers.
      if (i % 5 == 4) {
        final unasked = i % 10 == 4 ? await forged(300 + i) : genuineV1;
        await mallory.debugSendRawInner(
            phone.myRid,
            InnerMessage(
                kind: 'devlist',
                mid: newMessageId(),
                ts: now(),
                data: {'list': jsonEncode(unasked.toJson())}));
        sent++;
      }
    }

    await waitUntil(
        () async =>
            await readFrom(phone, mallory.myRid) >= sent &&
            await readFrom(laptop.svc, mallory.myRid) >= sent,
        what: "both of the victim's devices read all $sent of Mallory's "
            'messages');
    await settle([phone, laptop.svc, mallory],
        what: 'every message, question and answer handled');

    for (final d in [phone, laptop.svc]) {
      expect(d.ownAccountAlert, isNull,
          reason: '${d.displayName}: an echo with no list behind it is not '
              'evidence of a list the account never issued');
      expect(d.removedDeviceAlert, isNull,
          reason: '${d.displayName}: a removal notice with nothing the '
              'account signed behind it, at a version above its own, is not '
              'evidence of a removal');
      expect(d.kt.ownAlert, isNull, reason: d.displayName);
    }
    expect(await alarmState(phone), phoneBefore,
        reason: "the phone's alarm and device-list state are as they were");
    expect(await alarmState(laptop.svc), laptopBefore,
        reason: "the laptop's alarm and device-list state are as they were");
    // The phone may ask Mallory for the list behind her echoes; fifty echoes
    // buy her a handful of questions, not fifty.
    final asked = await readFrom(mallory, phone.myRid) - askedBefore;
    expect(asked, lessThanOrEqualTo(3),
        reason: 'the question is rate-limited per contact (asked $asked '
            'times)');
  });

  test(
      '2. a list the account key signed and its devices never issued still '
      'raises the alarm on the root and on the linked device', () async {
    final phone = await start('phone2');
    final laptop = await link(phone, 'laptop2');
    final carol = await start('carol2');
    await befriend(carol, phone, [laptop.svc]);

    // Whoever holds the account seed signs a list adding a device of theirs
    // and hands it to Carol alone — a split view. How it reached her does
    // not matter to the owner: she installs it as she would any list that
    // verifies under the account's key.
    final account = await phone.accountIdentity();
    final rogue = await paperDevice(phone, 'rogue');
    final split = await account
        .signDeviceList([...await phone.myFullDeviceList(), rogue], 3);
    expect(await carol.ktInstallFromLog(phone.myRid, split), isTrue);
    expect(await carol.heldContactListVersion(phone.myRid), 3);

    // Carol's next message carries her echo of it.
    await carol.sendText(phone.myRid, 'after the split');
    await waitUntil(() => phone.ownAccountAlert != null,
        what: "the root's alarm on a list it never signed");
    expect(jsonDecode(phone.ownAccountAlert!)['k'], OwnAlertKind.unissued);
    await waitUntil(() => laptop.svc.ownAccountAlert != null,
        what: "the linked device's alarm on a list its root never sent it");
    expect(
        jsonDecode(laptop.svc.ownAccountAlert!)['k'], OwnAlertKind.unissued);
  });

  test(
      '3a. a genuine removal by the root tells the removed device — from the '
      'list a removal notice carries, and from the log where nobody tells it',
      () async {
    final phone = await start('phone3');
    final laptop = await link(phone, 'laptop3');
    final carol = await start('carol3');
    await befriend(carol, phone, [laptop.svc]);
    expect(laptop.svc.removedDeviceAlert, isNull);

    await phone.removeMyDevice(laptop.cert); // version 3, without the laptop
    await waitUntil(() => laptop.svc.removedDeviceAlert != null,
        what: "carol's removal notice reaching the removed laptop");
    final alert = jsonDecode(laptop.svc.removedDeviceAlert!) as Map;
    expect(alert['k'], OwnAlertKind.removed);
    expect(alert['v'], 3);

    // An account no contact holds: nobody sends its removed device a notice,
    // and the log's copy of the list is what tells it.
    final phoneB = await start('phone3b');
    final laptopB = await link(phoneB, 'laptop3b');
    await phoneB.kt.check();
    await phoneB.removeMyDevice(laptopB.cert);
    expect(await phoneB.ownDeviceListVersion(), 3);
    await waitUntil(() async => (await logLatest(phoneB))?.$1 == 3,
        what: 'the log holds the list without the laptop');
    expect(laptopB.svc.removedDeviceAlert, isNull,
        reason: 'no contact, so no notice: nothing has told it yet');
    await laptopB.svc.kt.check();
    expect(laptopB.svc.removedDeviceAlert, isNotNull,
        reason: "the log's list — signed by the account, omitting this "
            'device, at a version above the one it holds — is the evidence');
    expect(jsonDecode(laptopB.svc.removedDeviceAlert!)['v'], 3);
  });

  test(
      '3b. a device just linked is not told it was removed by the lists its '
      'account signed before it was linked', () async {
    final phone = await start('phone3c');
    final laptop = await link(phone, 'laptop3c');
    await phone.kt.check();
    await waitUntil(() async => (await logLatest(phone))?.$1 == 2,
        what: 'the log holds v2, the list that added the laptop');

    // A third device, enrolled and started before its root has added it.
    // Every list the account has signed omits it, the log's latest among
    // them; it holds none of its own yet, so what it "holds" is a stand-in
    // at version 1, which v2 is above. Its start-up check of the log has
    // run; this one runs after it.
    final tablet = await joining(phone, 'tablet3c');
    await tablet.svc.kt.check();
    expect(tablet.svc.removedDeviceAlert, isNull,
        reason: 'v2 is from before this device was linked: it holds no list '
            'of its own that v2 could be above');

    await phone.addMyDevice(tablet.cert);
    await waitUntil(() async => await tablet.svc.ownDeviceListVersion() == 3,
        what: 'the tablet learned the list that adds it');
    await tablet.svc.kt.check();
    expect(tablet.svc.removedDeviceAlert, isNull);
    expect(await tablet.svc.vault.kvGet('removed_alert'), isNull);
    expect(laptop.svc.removedDeviceAlert, isNull);
  });

  test(
      '4a. a dismissed "list you never issued" stays dismissed for that list, '
      'across a restart, and a new list raises it again', () async {
    // The root judges at once: nothing honest can be unexplained to it, since
    // it signs every list itself.
    var phone = await start('phone4a', devlistGrace: Duration.zero);
    track(phone);
    final carol = await start('carol4a');
    track(carol);
    await befriend(carol, phone, const []);
    final account = await phone.accountIdentity();

    Future<SignedDeviceList> splitView(int version, String tag) async {
      final list = await account.signDeviceList([
        ...await phone.myFullDeviceList(),
        await paperDevice(phone, tag, drained: true)
      ], version);
      expect(await carol.ktInstallFromLog(phone.myRid, list), isTrue);
      return list;
    }

    /// Carol says something carrying her echo, and the phone has handled it
    /// and everything it set off.
    Future<void> carolEchoes(String what) async {
      await carol.debugSendRawInner(
          phone.myRid,
          InnerMessage.read(
              newMessageId(), DateTime.now().millisecondsSinceEpoch, const []));
      await settle([phone, carol], what: what);
    }

    final first = await splitView(2, 'rogue-a');
    await carolEchoes('the first echo of the unissued v2');
    expect(phone.ownAccountAlert, isNotNull,
        reason: 'a list the account key signed and the root never did');
    expect(await phone.vault.kvGet('own_alert_echo'),
        '2|${b64(await first.fingerprint())}');
    await phone.acknowledgeOwnAccountAlert();
    expect(phone.ownAccountAlert, isNull);

    await carolEchoes('the same echo again');
    expect(phone.ownAccountAlert, isNull,
        reason: 'the same list, already dismissed, is not new evidence');

    await stop(phone);
    phone = await start('phone4a', devlistGrace: Duration.zero);
    track(phone);
    await waitUntil(() => linked(phone), what: 'the phone back');
    expect(phone.ownAccountAlert, isNull);
    await carolEchoes('the same echo after a restart');
    expect(phone.ownAccountAlert, isNull,
        reason: 'the dismissal is on disk, not only in the service');

    final second = await splitView(3, 'rogue-b');
    await carolEchoes('the echo of a new unissued list, v3');
    expect(phone.ownAccountAlert, isNotNull,
        reason: 'new evidence raises the alarm again');
    expect(await phone.vault.kvGet('own_alert_echo'),
        '3|${b64(await second.fingerprint())}');
  });

  test(
      '4b. a dismissed "this device was removed" stays dismissed for that '
      'removal, across a restart, and a new removal raises it again',
      () async {
    final phone = await start('phone4b');
    track(phone);
    var laptop = await link(phone, 'laptop4b');
    track(laptop.svc);
    final carol = await start('carol4b');
    track(carol);
    final dave = await start('dave4b');
    track(dave);
    await befriend(carol, phone, [laptop.svc]);
    await befriend(dave, phone, [laptop.svc]);

    // Dave is away while the laptop is removed: his notice comes later.
    await dave.transport.stop();
    await phone.removeMyDevice(laptop.cert); // v3
    await waitUntil(() => laptop.svc.removedDeviceAlert != null,
        what: "carol's notice of the removal at v3");
    await laptop.svc.acknowledgeRemovedDeviceAlert();
    expect(laptop.svc.removedDeviceAlert, isNull);

    // The same removal heard again: Dave's notice, then the log's list.
    final fromDave = await readFrom(laptop.svc, dave.myRid);
    dave.transport.start();
    await waitUntil(
        () async => await readFrom(laptop.svc, dave.myRid) > fromDave,
        what: "dave's notice of the same removal read by the laptop");
    await settle([phone, laptop.svc, carol, dave], what: "dave's notice");
    expect(laptop.svc.removedDeviceAlert, isNull,
        reason: 'the same removal, already dismissed, is not new evidence');
    await laptop.svc.kt.check();
    expect(laptop.svc.removedDeviceAlert, isNull,
        reason: "nor is the log's copy of it");

    await stop(laptop.svc);
    laptop = (svc: await start('laptop4b'), cert: laptop.cert);
    await laptop.svc.kt.check();
    expect(laptop.svc.removedDeviceAlert, isNull,
        reason: 'the dismissal is on disk, not only in the service');

    // The root moves on: a list at v4, still without the laptop — a new
    // statement that it is not on the account, which the log carries.
    await phone.addMyDevice(await paperDevice(phone, 'tablet'));
    await waitUntil(() async => (await logLatest(phone))?.$1 == 4,
        what: 'the log holds v4');
    await laptop.svc.kt.check();
    expect(laptop.svc.removedDeviceAlert, isNotNull,
        reason: 'new evidence raises the alarm again');
    expect(jsonDecode(laptop.svc.removedDeviceAlert!)['v'], 4);
  });

  test(
      '4c. a dismissed log alarm stays dismissed for that entry, across a '
      'restart, and a new entry raises it again', () async {
    var phone = await start('phone4c');
    await phone.kt.check();
    final account = await phone.accountIdentity();
    expect(phone.kt.ownAlert, isNull);

    Future<SignedDeviceList> rogueEntry(int version, String tag) async {
      final list = await account.signDeviceList(
          [...await phone.myFullDeviceList(), await paperDevice(phone, tag)],
          version);
      expect(await publish(account, list), 201);
      return list;
    }

    final first = await rogueEntry(2, 'rogue-c');
    await phone.kt.check();
    expect(phone.kt.ownAlert?.version, 2);
    expect(phone.kt.ownAlert?.fpB64, b64(await first.fingerprint()));
    await phone.kt.acknowledgeOwnAlert();
    await phone.kt.check();
    expect(phone.kt.ownAlert, isNull,
        reason: 'the same entry, already dismissed, is not new evidence');

    await stop(phone);
    phone = await start('phone4c');
    await phone.kt.check();
    expect(phone.kt.ownAlert, isNull,
        reason: 'the dismissal is on disk, not only in the service');

    final second = await rogueEntry(3, 'rogue-d');
    await phone.kt.check();
    expect(phone.kt.ownAlert?.version, 3,
        reason: 'a new entry the account never issued is new evidence');
    expect(phone.kt.ownAlert?.fpB64, b64(await second.fingerprint()));
  });

  test(
      '5a. a vault whose own-list record the signing race overwrote starts '
      'quietly, and stays quiet across a restart', () async {
    var alice = await start('alice5a');
    await alice.kt.check(); // v1 in the log
    final laptopCert = await paperDevice(alice, 'laptop');
    final tabletCert = await paperDevice(alice, 'tablet');
    await alice.addMyDevice(laptopCert); // v2
    await alice.addMyDevice(tabletCert); // v3
    expect(await alice.ownDeviceListVersion(), 3);
    final fp3 = (await alice.debugOwnListClaim()).$2;
    await waitUntil(() async => (await logLatest(alice)) == (3, fp3),
        what: 'the log holds v1 to v3');
    await alice.kt.check();
    expect(alice.kt.ownAlert, isNull);

    // The race's end state, written directly: a re-send signing version 2
    // read the device set after the tablet's link had written it and the
    // version before, and its list overwrote the record of version 2 — over
    // the genuine one the log already held.
    final account = await alice.accountIdentity();
    final racer = await deviceListFingerprint(
        2, [account.deviceCert, laptopCert, tabletCert]);
    await stop(alice);
    final vault = await Vault.open(rootOverride: dirs['alice5a']!);
    final known = (jsonDecode((await vault.kvGet('kt_own_known'))!) as Map)
        .cast<String, Object?>();
    expect(known['2'], isNot(b64(racer)));
    known['2'] = b64(racer);
    await vault.kvPut('kt_own_known', jsonEncode(known), sensitive: false);
    // A vault from before the repair holds no mark of when this build first
    // ran; one this build made does, and the race could not have reached it.
    await vault.kvDelete('kt_own_legacy');
    await vault.db.close();

    alice = await start('alice5a');
    await alice.kt.check();
    expect(alice.kt.ownAlert, isNull,
        reason: "the log's v2 is the account's own genuine list, the one the "
            'race overwrote in the record');
    expect(alice.ownAccountAlert, isNull);

    await stop(alice);
    alice = await start('alice5a');
    await alice.kt.check();
    expect(alice.kt.ownAlert, isNull, reason: 'and at the next start too');
  });

  test(
      '5b. an entry at a version the record holds that names a device the '
      'account never held still alarms', () async {
    var bob = await start('bob5b');
    await bob.kt.check();
    final account = await bob.accountIdentity();
    await bob.addMyDevice(await paperDevice(bob, 'laptop')); // v2
    await waitUntil(() async => (await logLatest(bob))?.$1 == 2,
        what: 'the log holds v2');

    // Whoever holds the seed reaches the log first at v3, with a device of
    // their own; the account's own v3 (a tablet linked) arrives second.
    final rogue = await account.signDeviceList(
        [...await bob.myFullDeviceList(), await paperDevice(bob, 'rogue')], 3);
    expect(await publish(account, rogue), 201);
    await bob.addMyDevice(await paperDevice(bob, 'tablet')); // v3, refused
    await bob.kt.check();
    expect(bob.kt.ownAlert?.version, 3);

    // The same vault as one from before the repair, restarted: still an
    // alarm.
    await stop(bob);
    final vault = await Vault.open(rootOverride: dirs['bob5b']!);
    await vault.kvDelete('kt_own_legacy');
    await vault.kvDelete('kt_own_alert');
    await vault.db.close();
    bob = await start('bob5b');
    await bob.kt.check();
    expect(bob.kt.ownAlert?.version, 3,
        reason: 'a list naming a device this account never held is not the '
            "race's: the race only ever signed the account's own devices");
    expect(bob.kt.ownAlert?.fpB64, b64(await rogue.fingerprint()));
  });

  test(
      '5c. an entry naming only the account\'s own devices that reached the '
      'log after this build first ran still alarms', () async {
    var carl = await start('carl5c');
    await carl.kt.check();
    final account = await carl.accountIdentity();
    final laptop = await paperDevice(carl, 'laptop');
    await carl.addMyDevice(laptop); // v2
    await waitUntil(() async => (await logLatest(carl))?.$1 == 2,
        what: 'the log holds v2');
    // A vault from before the repair, started on this build: what the log
    // held then is all the repair may reconcile.
    await stop(carl);
    final vault = await Vault.open(rootOverride: dirs['carl5c']!);
    await vault.kvDelete('kt_own_legacy');
    await vault.db.close();
    carl = await start('carl5c');
    await carl.kt.check();
    expect(carl.kt.ownAlert, isNull);

    // Now the seed holder reaches the log first at v3 with a list of the
    // account's own devices, and the account's own v3 arrives second.
    final same = await account.signDeviceList([account.deviceCert, laptop], 3);
    expect(await publish(account, same), 201);
    await carl.addMyDevice(await paperDevice(carl, 'tablet')); // v3, refused
    await carl.kt.check();
    expect(carl.kt.ownAlert?.version, 3,
        reason: 'only what the log held before this build first ran can be '
            "the race's; a version recorded since keeps its first list");
    expect(carl.kt.ownAlert?.fpB64, b64(await same.fingerprint()));
  });

  test(
      '5d. where the race left its list as the log\'s latest entry, the vault '
      'starts quietly and the root moves past it to the next version',
      () async {
    var dora = await start('dora5d');
    await dora.kt.check();
    final account = await dora.accountIdentity();
    final laptop = await paperDevice(dora, 'laptop');
    await dora.addMyDevice(laptop); // v2
    await waitUntil(() async => (await logLatest(dora))?.$1 == 2,
        what: 'the log holds v2');

    // The race's other end state: a re-send signing version 3 read the
    // device set from before the tablet's link and the version after it,
    // and its list reached the log first; the link's own v3, with the
    // tablet, came second and was refused there.
    final racer =
        await account.signDeviceList([account.deviceCert, laptop], 3);
    expect(await publish(account, racer), 201);
    await dora.addMyDevice(await paperDevice(dora, 'tablet')); // v3, refused
    await dora.kt.check();
    expect(dora.kt.ownAlert?.version, 3,
        reason: 'the alarm such a vault showed at every start');

    // The same vault as one from before the repair, alarm and all.
    await stop(dora);
    final vault = await Vault.open(rootOverride: dirs['dora5d']!);
    await vault.kvDelete('kt_own_legacy');
    await vault.db.close();
    dora = await start('dora5d');
    await dora.kt.check();
    expect(dora.kt.ownAlert, isNull,
        reason: "the log's v3 is the account's own list, over its own "
            'devices, in the log before this build ran');

    // And the root moves past it, so the log and every contact that took
    // v3 from it converge on one list again.
    await waitUntil(() async => await dora.ownDeviceListVersion() == 4,
        what: 'the root moved to v4');
    final claim = await dora.debugOwnListClaim();
    await waitUntil(() async => (await logLatest(dora)) == claim,
        what: "the log holds the root's v4");
    await dora.kt.check();
    expect(dora.kt.ownAlert, isNull);
  });

  test(
      '5e. a reset of the log\'s history ends the repair: an entry it would '
      'have reconciled before the reset alarms after it', () async {
    var erin = await start('erin5e');
    await erin.kt.check(); // v1 in the log
    final laptopCert = await paperDevice(erin, 'laptop');
    final tabletCert = await paperDevice(erin, 'tablet');
    await erin.addMyDevice(laptopCert); // v2
    await erin.addMyDevice(tabletCert); // v3
    final fp3 = (await erin.debugOwnListClaim()).$2;
    await waitUntil(() async => (await logLatest(erin)) == (3, fp3),
        what: 'the log holds v1 to v3');

    // A vault from before the repair, started on this build: the mark of
    // what the log held then is made.
    await stop(erin);
    var vault = await Vault.open(rootOverride: dirs['erin5e']!);
    await vault.kvDelete('kt_own_legacy');
    await vault.db.close();
    erin = await start('erin5e');
    await erin.kt.check();
    expect(erin.kt.ownAlert, isNull);

    // The reset — after a fault, or to move to another log — which takes the
    // next head without asking that it extend the one held.
    await erin.kt.resetHistory();
    await erin.kt.check();

    // Only now the race's end state, as in 5a: the record of v2 overwritten
    // with the list the race signed, over the genuine one in the log.
    final account = await erin.accountIdentity();
    final racer = await deviceListFingerprint(
        2, [account.deviceCert, laptopCert, tabletCert]);
    await stop(erin);
    vault = await Vault.open(rootOverride: dirs['erin5e']!);
    final known = (jsonDecode((await vault.kvGet('kt_own_known'))!) as Map)
        .cast<String, Object?>();
    known['2'] = b64(racer);
    await vault.kvPut('kt_own_known', jsonEncode(known), sensitive: false);
    await vault.db.close();
    erin = await start('erin5e');
    await erin.kt.check();
    expect(erin.kt.ownAlert?.version, 2,
        reason: 'after a reset, the entries at those indices need not be the '
            'ones that were there when this build first ran');
  });

  test(
      '6. a log entry that does not open as one of the account\'s lists is '
      'no alarm for the owner, and still a conflict for a contact', () async {
    final dana = await start('dana6');
    final erin = await start('erin6');
    await befriend(erin, dana, const []);
    await dana.kt.check();
    await erin.kt.check();
    final account = await dana.accountIdentity();

    // A v2 entry whose value is not a list: what the log's operator can put
    // under any label without anybody's key (it can open values, §19.1).
    final junk = await account.signDeviceList([account.deviceCert], 2);
    expect(await publish(account, junk, value: utf8.encode('{"not":"a list"}')),
        201);
    await dana.kt.check();
    expect(dana.kt.ownAlert, isNull,
        reason: 'nothing here is signed by the account: it is not evidence '
            'that a device list was issued behind its back');
    await erin.kt.check();
    expect(erin.kt.statusOf(dana.myRid)?.state, KtContactState.conflict,
        reason: 'a contact still refuses to confirm the account against it');
    expect(erin.kt.sendsHeld(dana.myRid), isTrue);
  });
}
