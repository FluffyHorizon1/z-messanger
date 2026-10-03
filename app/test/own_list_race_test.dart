// A root's own device list is one snapshot, and a version keeps the list it
// was first recorded with.
//
// A root signs its list from two rows read one after the other — its device
// set and its version — and linking or removing a device writes those two
// rows one after the other. The signing runs from paths that run whenever
// they run: the re-send to a contact whose echo is behind, the hello's list,
// the re-assertion on every reconnect, the log check's baseline. One of them
// caught between a link's two writes signed the version before the link with
// the link's device set, and the record of what this device had issued was
// overwritten with it — over the genuine list already in the log at that
// version. After a restart the root's monitor of the log found that genuine
// entry, judged it never issued, and raised the alarm that tells a user to
// reset their identity. Probed on 50d9786: 2 rounds in 12 of a device linked
// while a re-send was in flight.
//
// Real clients, the real relay, and the real transparency log (kt/server.js)
// on loopback.
//
// Criteria, each a test below:
//   1. a device linked while the root is still answering a new contact's
//      first echo — the probe, run for 24 rounds: in every round the record
//      for each version is the list the root signed at it, none overwritten,
//      and after a restart the root's monitor of the log raises nothing;
//   2. a version already recorded is never recorded under another
//      fingerprint: the root asked to sign its current version over a device
//      set edited behind its back fails loudly — in a debug build, which is
//      what tests run — and records, publishes and sends nothing; the version
//      keeps the list it was first recorded with;
//   3. a linked device keeps the list it was first recorded with too: a
//      second list for its account at a version it already holds is not
//      adopted — not the device set, not the record — and, coming from
//      outside, it is not this device's bug, so nothing is raised loudly;
//   4. the order, forced rather than waited for: a signing paused between
//      reading the device set and reading the version holds the lock a
//      link's writes need, so the link waits — the signing is of the version
//      before the link with the devices before it, and the link's list
//      follows at the next version. (1 shows the race is gone under real
//      timing; this shows why, every run.)
@Tags(['integration'])
@Timeout(Duration(minutes: 8))
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
      Uint8List.fromList(List<int>.generate(32, (i) => (i * 7 + 11) & 0xff));
  final dirs = <String, Directory>{};
  final live = <ChatService>[];

  // Each service runs in an error zone of its own; an error raised inside a
  // running service fails the test that was running — which is how the
  // record's refusal (an assertion, in a debug build) would surface if a
  // signer got past the lock. A service [stop] has shut down can still have
  // work in flight that then fails against the database it closed; that
  // error, and only that one, is expected.
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
          // One log serves the whole file, and the probe makes many
          // accounts; its publish gates are raised out of the way.
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

  /// [name]'s client: a new account the first time, the same vault after
  /// [stop].
  Future<ChatService> start(String name) async {
    final dir =
        dirs[name] ??= await Directory.systemTemp.createTemp('z_ownlist_$name');
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
        );
        made = svc;
        // The log is checked when this file says so.
        svc.kt.recheckDelay = const Duration(hours: 1);
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

  bool linked(ChatService s) =>
      s.transport.isConnected && s.transport.isSenderConnected;

  bool received(ChatService svc, String rid, String body) =>
      svc.messagesByChat[rid]?.any((m) => !m.outgoing && m.body == body) ==
      true;

  /// Nothing [group] sent is still waiting in an outbox, and no
  /// post-quantum send is pending.
  Future<void> quiet(List<ChatService> group) => waitUntil(() async {
        for (final s in group) {
          if (s.pqSendPending) return false;
          if ((await s.vault.db.query('outbox', limit: 1)).isNotEmpty) {
            return false;
          }
        }
        return true;
      }, what: 'the outboxes of ${group.map((s) => s.displayName)} drained');

  Future<SignedDeviceList> own(ChatService svc) async =>
      SignedDeviceList.fromJson(
          (jsonDecode((await svc.vault.kvGet('own_list_json'))!) as Map)
              .cast<String, Object?>());

  Future<Map<String, Object?>> known(ChatService svc) async =>
      (jsonDecode(await svc.vault.kvGet('kt_own_known') ?? '{}') as Map)
          .cast<String, Object?>();

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

  /// A device linked to [root]'s account, as `hostDeviceLink` enrolls one,
  /// running as a client of its own; [root] still has to list it.
  Future<({ChatService svc, DeviceCertificate cert})> enroll(
      ChatService root, String name) async {
    final account = await root.accountIdentity();
    final devId = await ZIdentity.generate();
    final cert = await account.signDeviceCert(
        deviceEdPub: devId.edPub, deviceXPub: devId.xPub, deviceId: name);
    final dir =
        dirs[name] = await Directory.systemTemp.createTemp('z_ownlist_$name');
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
    return (svc: await start(name), cert: cert);
  }

  Future<DeviceCertificate> newDevice(ChatService root, String id) async {
    final x = await ZIdentity.generate();
    return (await root.accountIdentity())
        .signDeviceCert(deviceEdPub: x.edPub, deviceXPub: x.xPub, deviceId: id);
  }

  test(
      '1. a device linked while a re-send is in flight: over 24 rounds no '
      'version is recorded twice, and a restart raises no own alert',
      () async {
    const rounds = 24;
    final failures = <String>[];
    for (var i = 0; i < rounds; i++) {
      var alice = await start('alice$i');
      final ben = await start('ben$i');
      await waitUntil(() => linked(alice) && linked(ben),
          what: 'round $i: both connected');

      // Version 2, before Alice has any contact.
      await alice.addMyDevice(await newDevice(alice, 'laptop'));
      final fp2 = b64(await (await own(alice)).fingerprint());
      expect((await own(alice)).version, 2);

      // A new contact. Her hello's list is dropped until Ben has added her,
      // so his first message echoes the baseline, and she answers it by
      // signing and re-sending version 2 — and a device is linked at once.
      await alice.addContactFromCode(await ben.myContactCode());
      await ben.addContactFromCode(await alice.myContactCode());
      await alice.sendText(ben.myRid, 'hello ben');
      await ben.sendText(alice.myRid, 'hello alice');
      await waitUntil(
          () =>
              received(alice, ben.myRid, 'hello alice') &&
              received(ben, alice.myRid, 'hello ben'),
          what: 'round $i: spoken');
      await alice.addMyDevice(await newDevice(alice, 'tablet'));
      final v3 = await own(alice);
      expect(v3.version, 3);
      final fp3 = b64(await v3.fingerprint());

      // Settled: Ben holds version 3, the log has it, nothing is in flight.
      await waitUntil(
          () async => await ben.heldContactListVersion(alice.myRid) >= 3,
          what: 'round $i: Ben holds v3');
      await waitUntil(
          () async => (await logLatest(alice)) == (3, fp3),
          what: 'round $i: the log holds v3');
      await quiet([alice, ben]);

      final record = await known(alice);
      if (record['2'] != fp2 || record['3'] != fp3) {
        failures.add('round $i: recorded v2 '
            '${record['2'] == fp2 ? 'as signed' : 'OVERWRITTEN'}, v3 '
            '${record['3'] == fp3 ? 'as signed' : 'OVERWRITTEN'}');
      }

      // The next start, and its first check of the log.
      await stop(alice);
      alice = await start('alice$i');
      await alice.kt.check();
      if (alice.kt.ownAlert != null || alice.ownAccountAlert != null) {
        failures.add('round $i: an own alert after the restart '
            '(log monitor ${alice.kt.ownAlert?.version}, '
            'gossip ${alice.ownAccountAlert})');
      }
      await stop(alice);
      await stop(ben);
    }
    expect(failures, isEmpty,
        reason: '$rounds rounds, each a device linked while a re-send of '
            'the version before it was in flight');
  });

  test(
      '2. a version keeps the list it was first recorded with: signing it '
      'again over another device set fails loudly and records nothing',
      () async {
    final alice = await start('alice-record');
    final ben = await start('ben-record');
    await waitUntil(() => linked(alice) && linked(ben),
        what: 'both connected');
    await alice.addContactFromCode(await ben.myContactCode());
    await ben.addContactFromCode(await alice.myContactCode());
    await alice.sendText(ben.myRid, 'hello ben');
    await waitUntil(() => received(ben, alice.myRid, 'hello ben'),
        what: 'spoken');
    await alice.addMyDevice(await newDevice(alice, 'laptop'));
    final fp2 = b64(await (await own(alice)).fingerprint());
    await waitUntil(
        () async => await ben.heldContactListVersion(alice.myRid) >= 2,
        what: 'Ben holds v2');
    await waitUntil(
        () async => await alice.vault.kvGet('kt_pub_done') == '2|$fp2',
        what: 'the log has acknowledged v2');
    await quiet([alice, ben]);

    Future<Map<String, String?>> snapshot() async => {
          for (final k in [
            'own_list_json',
            'own_list_v',
            'own_list_h',
            'own_list_mlsig',
            'kt_own_known',
            'kt_pub_pending',
            'kt_pub_done',
          ])
            k: await alice.vault.kvGet(k),
        };
    final before = await snapshot();
    final heldAtBen = await ben.vault.kvGet('cdev_${alice.myRid}');

    // The device set edited behind the service's back, the version not
    // moved: the next signing of version 2 would be a second list at it.
    final asItWas = (await alice.vault.kvGet('my_devices'))!;
    final devices = [
      for (final d in (jsonDecode((await alice.vault.kvGet('my_devices'))!)
          as List))
        (d as Map).cast<String, Object?>(),
      (await newDevice(alice, 'stray')).toJson(),
    ];
    await alice.vault.kvPut('my_devices', jsonEncode(devices),
        sensitive: false);
    alice.forgetOwnListClaim();

    await expectLater(alice.broadcastMyDeviceList(),
        throwsA(isA<AssertionError>()),
        reason: 'a second fingerprint for a recorded version is a bug, and '
            'a debug build says so');
    expect(await snapshot(), before,
        reason: 'nothing recorded, signed under ML-DSA or queued for the log');

    // Nothing was sent either: what Alice says next reaches Ben, and the
    // list he holds for her is the one he held.
    await alice.sendText(ben.myRid, 'after the refusal');
    await waitUntil(() => received(ben, alice.myRid, 'after the refusal'),
        what: 'a message after the refusal arrives');
    await quiet([alice, ben]);
    expect(await ben.vault.kvGet('cdev_${alice.myRid}'), heldAtBen);

    // Put the device set back, so nothing after this test signs over it.
    await alice.vault.kvPut('my_devices', asItWas, sensitive: false);
    alice.forgetOwnListClaim();
  });

  test(
      '3. a linked device keeps the list it was first recorded with: a second '
      'list at a version it holds is not adopted', () async {
    final phone = await start('phone-linked');
    final laptop = await enroll(phone, 'laptop-linked');
    await waitUntil(() => linked(phone) && linked(laptop.svc),
        what: 'phone and laptop connected');
    await phone.addMyDevice(laptop.cert); // version 2, self-synced
    // `own_list_json` is the last of the record's writes.
    await waitUntil(
        () async => (await laptop.svc.vault.kvGet('own_list_json'))
            ?.contains('"ver":2') ==
            true,
        what: 'the laptop has learned version 2 from its root');
    await quiet([phone, laptop.svc]);

    Future<Map<String, String?>> snapshot() async => {
          for (final k in [
            'own_list_json',
            'own_list_v',
            'own_list_h',
            'kt_own_known',
            'my_devices',
            'my_devlist_version',
          ])
            k: await laptop.svc.vault.kvGet(k),
        };
    final before = await snapshot();

    // Another list for the account at version 2 — genuinely signed by its
    // key, over one more device — as a second signer would send it.
    final account = await phone.accountIdentity();
    final second = await account.signDeviceList(
        [...await phone.myFullDeviceList(), await newDevice(phone, 'other')],
        2);
    expect(await second.verify(), isTrue);
    await laptop.svc.debugApplyOwnDeviceList(second);
    expect(await snapshot(), before,
        reason: 'neither its devices nor its record are adopted');
  });

  test(
      '4. a link waits for a signing already under way, and each version is '
      'signed over its own device set', () async {
    final alice = await start('alice-order');
    await waitUntil(() => linked(alice), what: 'connected');
    await alice.addMyDevice(await newDevice(alice, 'laptop')); // version 2
    final v2 = await own(alice);
    expect(v2.version, 2);

    final paused = Completer<void>();
    final release = Completer<void>();
    alice.debugBetweenOwnListReads = () async {
      alice.debugBetweenOwnListReads = null;
      paused.complete();
      await release.future;
    };
    // A signing of the current version — as a re-send or a reconnect makes
    // one — stopped after reading the device set.
    final signing = alice.broadcastMyDeviceList();
    await paused.future;
    // A device linked now.
    final tablet = await newDevice(alice, 'tablet');
    final linking = alice.addMyDevice(tablet);
    await waitUntil(() => alice.debugOwnListWaiting,
        what: 'the link waiting on the lock the signing holds');
    expect(await alice.vault.kvGet('my_devlist_version'), '2',
        reason: 'the link writes nothing while the signing holds the lock');
    release.complete();
    await signing;
    await linking;

    final v3 = await own(alice);
    expect(v3.version, 3);
    expect(v3.devices.map((d) => b64(d.deviceEdPub)),
        contains(b64(tablet.deviceEdPub)));
    final record = await known(alice);
    expect(record['2'], b64(await v2.fingerprint()),
        reason: 'version 2 is the list with the devices before the link');
    expect(record['3'], b64(await v3.fingerprint()),
        reason: 'and version 3 the one with the tablet');
  });
}
