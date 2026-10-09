// A restored backup is the same account, and says so (phase 31).
//
// Restoring a `.zbk` is the documented way back from a lost phone, and until
// this phase it told the user to reset their identity over nothing. The
// archive carried the identity and the history but none of the account's
// device-list or transparency state, so a restored root started again at
// version 1: its own monitor found the versions it had signed before the
// backup in the log and called them lists it never issued, every contact saw
// its devices claim a version below one they had already seen (a rollback),
// and the next device it linked collided with a version the log already
// held. Every test here runs real `ChatService`s through a real relay and,
// where it matters, the real transparency log (`kt/server.js`), and wipes
// and restores a device the way a user does — `Restore.run` on a fresh vault.
//
// Criteria, each a test below:
//   1. an account that linked and then unlinked a device (its list at v3)
//      restores onto a wiped device with no alarm anywhere: its contact sees
//      no rollback or split, its own gossip and log monitors raise nothing,
//      and the first list it signs is v4 (max(log, held) + 1) — signed and
//      recorded before its transport even starts, so before it sends
//      anything — which the contact installs and the log confirms;
//   2. restarted twice after the restore it is still quiet, re-signs
//      nothing, and messages keep arriving both ways;
//   3. when the log is AHEAD of the archive (the account removed one device
//      and linked another after the backup was taken), the restored root
//      signs above the log's latest, takes the lists in between as its own
//      history rather than as lists it never issued, and re-asserts only the
//      devices the archive knew that the newer list still names — a removal
//      made after the backup stands, an addition is not adopted;
//   4. a backup taken on a LINKED device restores as that linked device of
//      the same account: never a root, never a log entry for its own key,
//      no alarm on any device, and it keeps exchanging with its root and
//      with a contact;
//   5. the block list, a pending inbound request, the push-off preference
//      and a custom transparency-log configuration survive the restore;
//   6. a first-flight envelope someone kept and replays after the restore
//      does not bring back a message the user deleted, and the session it
//      belonged to is not re-created: messages keep flowing both ways;
//   7. an archive whose format major version is newer than this build reads
//      is refused as such — on sight, before any code is asked for, and on
//      import — with nothing written to the vault;
//   8. a vault written by a newer build is refused rather than downgraded,
//      and left as it was; and a vault an OLDER build has already downgraded
//      opens and upgrades instead of failing on its next migration;
//   9. a record type this build does not know survives a re-backup when its
//      writer marked it safe to keep, byte for byte, and is dropped when it
//      did not;
//  10. an archive written before format 1.1 — every backup taken before
//      this phase, with no device-list state in it at all — restores as
//      quietly as criterion 1, from what the log holds;
//  11. an account that has moved to v2-only signing (ADR 0017 stage 2b)
//      restores as one: the list it signs next is v2-only too, one version
//      above, and nobody is alarmed;
//  12. what the owner's alarms stand on (ADR 0026) survives the restore: a
//      standing banner's evidence, every dismissal, and the own-list
//      repair's record of the head and versions held when it first ran —
//      which a restored vault must not record again from the archive's head,
//      or the repair would reconcile entries the device it came from still
//      reports.
@Tags(['integration'])
@Timeout(Duration(minutes: 4))
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as p;
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:zapp/core/alarm_evidence.dart';
import 'package:zapp/core/archive.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/key_transparency.dart';
import 'package:zapp/core/restore.dart';
import 'package:zapp/core/system_messages.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:z_protocol/z_protocol.dart';

/// A transport that remembers what its device had signed for its own
/// account at the moment it was started — before it could send anything —
/// and at its first send.
///
/// The reads are issued at those moments and resolve later. The vault runs
/// its statements in the order they are issued, so each one answers for the
/// state at the moment it was asked: everything the service awaited before
/// starting the transport is in it, and nothing after.
class _WatchedTransport extends Transport {
  _WatchedTransport(
      {required super.identity,
      required super.serverUrl,
      required this.vault});

  final Vault vault;
  Future<String?>? ownListAtStart;
  Future<String?>? ownListAtFirstSend;
  bool _started = false;
  int sendsBeforeStart = 0;

  @override
  void start() {
    if (!_started) {
      _started = true;
      ownListAtStart = vault.kvGet('own_list_json');
    }
    super.start();
  }

  @override
  Future<void> send(
      {required String to, required String id, required String payload}) {
    if (!_started) sendsBeforeStart++;
    ownListAtFirstSend ??= vault.kvGet('own_list_json');
    return super.send(to: to, id: id, payload: payload);
  }
}

Future<int> _freePort() async {
  final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final port = probe.port;
  await probe.close();
  return port;
}

Future<void> _waitHealthy(int port) async {
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

String _hex(List<int> b) =>
    [for (final x in b) x.toRadixString(16).padLeft(2, '0')].join();

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
      Uint8List.fromList(List<int>.generate(32, (i) => (i * 11 + 5) & 0xff));
  final temps = <Directory>[];
  final services = <ChatService>[];

  setUpAll(() async {
    HttpOverrides.global = null;
    logPort = await _freePort();
    log = await Process.start('node', ['server.js'],
        workingDirectory: '$root${Platform.pathSeparator}kt',
        environment: {
          'KT_SEED': _hex(logSeed),
          'KT_EPHEMERAL': '1',
          'KT_PORT': '$logPort',
          // One log serves the whole file; its publish gates are not what
          // this file is about (see key_transparency_test.dart).
          'PUBLISH_PER_MIN': '1000000',
          'PUBLISH_PER_MIN_TOTAL': '1000000',
          'PUBLISH_PER_ACCT_PER_DAY': '1000000',
          'PUBLISH_NEW_ACCOUNTS_PER_MIN': '1000000',
        });
    log.stderr.drain<void>();
    log.stdout.drain<void>();
    await _waitHealthy(logPort);
    final kp = await Ed25519().newKeyPairFromSeed(logSeed);
    logPub = Uint8List.fromList((await kp.extractPublicKey()).bytes);
  });

  // A relay per test, so nothing one test left queued is in the next one's
  // way.
  setUp(() async {
    HttpOverrides.global = null;
    relayPort = await _freePort();
    relay = await Process.start('node', ['server.js'],
        workingDirectory: '$root${Platform.pathSeparator}server',
        environment: {'PORT': '$relayPort', 'LOG_LEVEL': 'silent'});
    relay.stderr.drain<void>();
    relay.stdout.drain<void>();
    await _waitHealthy(relayPort);
  });

  tearDown(() async {
    for (final s in services) {
      s.dispose();
      await s.transport.stop();
    }
    services.clear();
    relay.kill();
  });

  tearDownAll(() async {
    log.kill();
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  KtConfig cfg() => KtConfig(
      logUrl: 'http://127.0.0.1:$logPort', logPubB64: b64(logPub));

  String relayUrl() => 'ws://127.0.0.1:$relayPort';

  Future<Directory> tempDir(String name) async {
    final d = await Directory.systemTemp.createTemp('z_rt_$name');
    temps.add(d);
    return d;
  }

  /// Start a service over [vault] the way the app does: the identity is the
  /// one the vault holds.
  Future<ChatService> boot(Vault vault, String name,
      {Transport? transport, KtConfig? ktConfig, bool? v2Only}) async {
    final id = await ZIdentity.fromJson(
        (jsonDecode((await vault.kvGet('identity'))!) as Map)
            .cast<String, Object?>());
    final svc = await ChatService.init(
        vault: vault,
        identity: id,
        displayName: name,
        transport:
            transport ?? Transport(identity: id, serverUrl: relayUrl()),
        ktConfig: ktConfig ?? cfg(),
        signDevlistV2Only: v2Only ?? devlistSignV2Only,
        // Asked for by name, the signer moves at the first start, as it did
        // before ADR 0029 made it wait on the account's readers: test 11 is
        // about a moved account's restore, not about when it moved.
        debugMoveUngated: v2Only ?? false);
    svc.kt.scheduled = false; // checked when the test says so
    svc.devlistGrace = const Duration(milliseconds: 700);
    services.add(svc);
    return svc;
  }

  Future<(ChatService, Directory)> fresh(String name, {bool? v2Only}) async {
    final dir = await tempDir(name);
    final vault = await Vault.open(rootOverride: dir);
    await vault.kvPut(
        'identity', jsonEncode((await ZIdentity.generate()).toJson()));
    // The account's post-quantum seed, which every account has after its
    // first start. Without one, `ChatService.pqIdentity` makes it on first
    // use and does not serialise that: two first uses at once — the log check
    // signing the account's first list in the background, and this file
    // asking for the contact code — can each make a seed of their own, so
    // the code commits to a key the account then never sends and the contact
    // refuses it for good ("alice has no post-quantum key of bob": three of
    // the seven tests that pair two accounts, in one run before this line).
    // That race is not what this file is about, so its accounts start past
    // it.
    await vault.kvPut('pq_seed', b64(randomBytes(32)));
    return (await boot(vault, name, v2Only: v2Only), dir);
  }

  Future<void> waitUntil(bool Function() cond,
      {Duration timeout = const Duration(seconds: 45),
      required String what}) async {
    final deadline = DateTime.now().add(timeout);
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('timed out waiting for: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 30));
    }
  }

  Future<void> waitFor(Future<bool> Function() cond,
      {Duration timeout = const Duration(seconds: 45),
      required String what}) async {
    final deadline = DateTime.now().add(timeout);
    while (!await cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('timed out waiting for: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
  }

  bool up(ChatService s) =>
      s.transport.isConnected && s.transport.isSenderConnected;

  List<String> texts(ChatService s, String rid) => [
        for (final m in s.messagesByChat[rid] ?? const [])
          if (m.kind == 'text') m.body
      ];

  /// Each side holds the other's post-quantum key (the exchange ran), then
  /// nothing is left to send — the wait `replies_test.dart` explains.
  Future<void> settled(List<ChatService> group) async {
    final deadline = DateTime.now().add(const Duration(seconds: 45));
    while (true) {
      final waiting = <String>[];
      for (final s in group) {
        for (final o in group) {
          if (identical(s, o)) continue;
          final c = s.contacts[o.myRid];
          if (c == null) continue;
          if (c.pqPub == null && c.pqCandidate == null) {
            waiting.add('${s.displayName} has no post-quantum key of '
                '${o.displayName}');
          }
        }
      }
      if (waiting.isEmpty) {
        for (final s in group) {
          final rows = await s.vault.db.query('outbox', columns: ['rid']);
          if (rows.isNotEmpty) {
            waiting.add('${s.displayName} has ${rows.length} envelope(s) '
                'queued for ${{for (final r in rows) r['rid']}}');
          }
        }
      }
      for (final s in group) {
        if (s.pqSendPending) waiting.add('${s.displayName} is sending a key');
      }
      if (waiting.isEmpty) return;
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('the group never settled: ${waiting.join('; ')}');
      }
      await Future<void>.delayed(const Duration(milliseconds: 30));
    }
  }

  /// One message each way, delivered — the claim and the echo of each side's
  /// device list have crossed.
  Future<void> exchange(ChatService a, ChatService b, String tag) async {
    await a.sendText(b.myRid, '$tag a');
    await waitUntil(() => texts(b, a.myRid).contains('$tag a'),
        what: "'$tag a' delivered");
    await b.sendText(a.myRid, '$tag b');
    await waitUntil(() => texts(a, b.myRid).contains('$tag b'),
        what: "'$tag b' delivered");
  }

  /// Contacts both ways, a message each way — a side that still lacks the
  /// other's post-quantum key asks for it when it hears from them — and then
  /// settled.
  Future<void> befriend(ChatService a, ChatService b) async {
    await waitUntil(() => up(a) && up(b), what: 'both up on both links');
    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());
    await exchange(a, b, 'hello ${a.displayName}');
    await settled([a, b]);
  }

  /// Wait until [contact] has weighed the claim [owner]'s device makes about
  /// its own list at version [v]: it has raised an alert about [owner], or it
  /// holds [owner]'s list at [v] and has recorded that claim.
  ///
  /// A message on the screen is not enough. An inbound message is stored
  /// first and its device-list claim checked afterwards, so the text can be
  /// there while the check that would raise a rollback has not yet run.
  Future<void> claimJudged(ChatService contact, String owner, int v) =>
      waitFor(() async {
        if (contact.contactDevlistAlerts[owner] != null) return true;
        if (await contact.heldContactListVersion(owner) < v) return false;
        final raw = await contact.vault.kvGet('cdl_claims_$owner');
        if (raw == null) return false;
        return (jsonDecode(raw) as Map)
            .values
            .any((c) => c is Map && c['v'] == v);
      }, what: "${contact.displayName} weighing $owner's claim of v$v");

  Future<Map<String, Object?>> ktGet(String path) async {
    final res = await (await HttpClient()
            .getUrl(Uri.parse('http://127.0.0.1:$logPort$path')))
        .close();
    return (jsonDecode(await res.transform(utf8.decoder).join()) as Map)
        .cast<String, Object?>();
  }

  /// The versions the log holds for [acct], oldest first.
  Future<List<int>> logVersions(Uint8List acct) async {
    final label = _hex(await ktLabel(acct));
    final out = <int>[];
    var start = 0;
    while (true) {
      final j = await ktGet('/kt/v1/history/$label?start=$start');
      final items = (j['entries'] as List?) ?? const [];
      for (final it in items) {
        out.add((((it as Map)['entry'] as Map)['v'] as num).toInt());
      }
      start += items.length;
      final total = j['total'];
      if (items.isEmpty || total is! int || start >= total) break;
    }
    return out;
  }

  Future<int> logLatest(Uint8List acct) async {
    final j = await ktGet('/kt/v1/lookup/${_hex(await ktLabel(acct))}');
    final e = j['entry'];
    return e == null ? 0 : ((e as Map)['v'] as num).toInt();
  }

  Future<void> logReaches(Uint8List acct, int v) => waitFor(
      () async => await logLatest(acct) >= v,
      what: 'the log holding v$v');

  Future<void> holds(ChatService s, String rid, int v) => waitFor(
      () async => await s.heldContactListVersion(rid) >= v,
      what: '${s.displayName} holding v$v of $rid');

  /// Take a backup of [s]'s vault: the archive file and its code.
  Future<(File, RecoveryCode)> backup(ChatService s, String name) async {
    final code = await RecoveryCode.generate();
    final file = File(p.join((await tempDir('${name}_zbk')).path, 'b.zbk'));
    final sink = file.openWrite();
    await BackupArchive.export(vault: s.vault, code: code, out: sink);
    await sink.close();
    return (file, code);
  }

  /// The device is lost: the service stops, and everything under [dir]
  /// goes.
  Future<void> lose(ChatService s, Directory dir) async {
    s.dispose();
    await s.transport.stop();
    services.remove(s);
    await s.vault.db.close();
    dir.deleteSync(recursive: true);
    dir.createSync(recursive: true);
  }

  /// A fresh install restores [file] the way the onboarding screen does.
  Future<Vault> restoreInto(
      Directory dir, File file, RecoveryCode code) async {
    final vault = await Vault.open(rootOverride: dir);
    await Restore.run(
      vault: vault,
      file: file,
      secret: await code.format(),
      kind: (await Restore.identify(file)).kind,
      serverUrl: relayUrl(),
    );
    return vault;
  }

  /// A linked device enrolled to [phone]'s account, its own service.
  Future<(ChatService, Directory, DeviceCertificate)> linkTo(
      ChatService phone, String name) async {
    final account = await phone.accountIdentity();
    final devId = await ZIdentity.generate();
    final cert = await account.signDeviceCert(
        deviceEdPub: devId.edPub, deviceXPub: devId.xPub, deviceId: name);
    final dir = await tempDir(name);
    final vault = await Vault.open(rootOverride: dir);
    await vault.kvPut('identity', jsonEncode(devId.toJson()));
    final enrolled = await AccountIdentity.fromEnrollment(
      accountEdPub: account.accountEdPub,
      accountMlPub: await phone.pqAccountPublic(),
      deviceEdSeed: devId.edSeed,
      deviceXSeed: devId.xSeed,
      deviceId: name,
      deviceCert: cert,
    );
    await vault.kvPut('account', jsonEncode(enrolled.toJson()));
    await vault.kvPut('my_devices', jsonEncode([account.deviceCert.toJson()]),
        sensitive: false);
    final svc = await boot(vault, name);
    await waitUntil(() => up(svc) && up(phone), what: '$name and its root up');
    await phone.addMyDevice(cert);
    return (svc, dir, cert);
  }

  Future<SignedDeviceList> ownList(ChatService s) async =>
      SignedDeviceList.fromJson(
          (jsonDecode((await s.vault.kvGet('own_list_json'))!) as Map)
              .cast<String, Object?>());

  Set<String> edsOf(SignedDeviceList l) =>
      {for (final d in l.devices) b64(d.deviceEdPub)};

  /// Nothing alarming on [s] about its own account, from the gossip or from
  /// the log, after a full check against the log.
  Future<void> quietOwner(ChatService s, String why) async {
    await s.kt.check();
    expect(s.kt.ownAlert, isNull,
        reason: '$why: the log monitor found a list "you did not issue"');
    expect(s.ownAccountAlert, isNull,
        reason: '$why: the gossip raised an own-account alarm');
    expect(s.removedDeviceAlert, isNull, reason: '$why: "device removed"');
  }

  /// Nothing alarming on [contact] about [rid]'s account, and its sends to
  /// it are not held.
  Future<void> quietContact(ChatService contact, String rid, String why) async {
    expect(contact.contactDevlistAlerts[rid], isNull,
        reason: '$why: ${contact.displayName} raised a device-list alarm '
            '(${contact.contactDevlistAlerts[rid]})');
    await contact.kt.check();
    expect(contact.kt.sendsHeld(rid), isFalse,
        reason: '$why: ${contact.displayName} holds sends to $rid');
    expect(contact.kt.statusOf(rid)?.state, isNot(KtContactState.conflict),
        reason: '$why: the log check reads a conflict');
  }

  // ---------------------------------------------------------------------------

  /// Alice (a root) and Bob, contacts; Alice links a laptop and removes it,
  /// so her list is at v3 everywhere — the log, Bob, her own record — and Bob
  /// has seen her device claim v3. Then Alice backs up, loses the phone and
  /// restores — the archive as [rewrite] leaves it, if given; the restored
  /// service is started on a [_WatchedTransport].
  Future<
      ({
        ChatService revived,
        ChatService bob,
        Directory dir,
        Uint8List acct,
        _WatchedTransport watch,
      })> linkedUnlinkedRestored(String tag,
      {Future<File> Function(File file, RecoveryCode code)? rewrite}) async {
    final (alice, aliceDir) = await fresh('alice$tag');
    final (bob, _) = await fresh('bob$tag');
    await befriend(alice, bob);
    final account = await alice.accountIdentity();
    final laptop = await ZIdentity.generate();
    final cert = await account.signDeviceCert(
        deviceEdPub: laptop.edPub, deviceXPub: laptop.xPub, deviceId: 'lap');
    await alice.addMyDevice(cert);
    await alice.removeMyDevice(cert);
    expect(await alice.ownDeviceListVersion(), 3);
    await holds(bob, alice.myRid, 3);
    await logReaches(account.accountEdPub, 3);
    await exchange(alice, bob, 'before $tag');
    await settled([alice, bob]);
    await quietContact(bob, alice.myRid, 'before the restore');

    final (taken, code) = await backup(alice, 'alice$tag');
    final file = rewrite == null ? taken : await rewrite(taken, code);
    await lose(alice, aliceDir);
    final vault = await restoreInto(aliceDir, file, code);
    final id = await ZIdentity.fromJson(
        (jsonDecode((await vault.kvGet('identity'))!) as Map)
            .cast<String, Object?>());
    final watch =
        _WatchedTransport(identity: id, serverUrl: relayUrl(), vault: vault);
    final revived = await boot(vault, 'alice$tag', transport: watch);
    await waitUntil(() => up(revived), what: 'the restored device up');
    return (
      revived: revived,
      bob: bob,
      dir: aliceDir,
      acct: account.accountEdPub,
      watch: watch
    );
  }

  test(
      '1. a restored root whose list was at v3 raises no alarm anywhere, and '
      'signs v4 before it sends anything', () async {
    final r = await linkedUnlinkedRestored('1');
    final aliceRid = r.revived.myRid;

    // What the contact sees: a message from the restored device. Its claim
    // about its own list rides on it.
    await r.revived.sendText(r.bob.myRid, 'back on a new phone');
    await waitUntil(
        () => texts(r.bob, aliceRid).contains('back on a new phone'),
        what: "Bob receiving the restored device's message");
    await claimJudged(r.bob, aliceRid, 4);
    expect(r.bob.contactDevlistAlerts[aliceRid], isNull,
        reason: 'the restored device claimed a list version below one Bob '
            'had seen from it: a rollback alarm');

    // What the owner sees: nothing.
    await quietOwner(r.revived, 'after the restore');

    // The new list: v4, the one device, at Bob and in the log.
    await holds(r.bob, aliceRid, 4);
    await logReaches(r.acct, 4);
    await quietContact(r.bob, aliceRid, 'after the restore');
    expect(r.bob.kt.statusOf(aliceRid)?.state, KtContactState.confirmed);
    expect(r.bob.kt.statusOf(aliceRid)?.logVersion, 4);
    // From the version the backup knew: one entry per version, the restored
    // one directly above it. (Whether the account's version-1 baseline made
    // it into the log before the first link is a race this test is not
    // about.)
    expect((await logVersions(r.acct)).where((v) => v >= 3), [3, 4],
        reason: 'one entry per version, the restored one directly above');

    // The ordering: v4 was signed and recorded before the transport started,
    // so the first envelope the restored device could send already carried
    // it — not a list at the old version, and not v1.
    final atStart = await r.watch.ownListAtStart;
    expect(atStart, isNotNull,
        reason: 'the transport started before the device held any list');
    final listAtStart = SignedDeviceList.fromJson(
        (jsonDecode(atStart!) as Map).cast<String, Object?>());
    expect(listAtStart.version, 4);
    expect(edsOf(listAtStart), {b64(r.revived.identity.edPub)});
    expect(r.watch.sendsBeforeStart, 0);
    final atFirstSend = await r.watch.ownListAtFirstSend;
    expect(
        SignedDeviceList.fromJson(
                (jsonDecode(atFirstSend!) as Map).cast<String, Object?>())
            .version,
        4);
    expect(await r.revived.ownDeviceListVersion(), 4);

    // And Bob's messages arrive.
    await exchange(r.bob, r.revived, 'after');
    expect(r.bob.contactDevlistAlerts[aliceRid], isNull);
    await quietOwner(r.revived, 'after an exchange');
  });

  test('2. restarted twice after the restore it stays quiet and in touch',
      () async {
    final r = await linkedUnlinkedRestored('2');
    var current = r.revived;
    await exchange(current, r.bob, 'first start');
    await holds(r.bob, current.myRid, 4);
    await logReaches(r.acct, 4);
    for (var round = 1; round <= 2; round++) {
      // A restart: the service and its vault close, and a new process opens
      // them.
      current.dispose();
      await current.transport.stop();
      services.remove(current);
      await current.vault.db.close();
      current = await boot(
          await Vault.open(rootOverride: r.dir), 'alice2',
          ktConfig: cfg());
      await waitUntil(() => up(current), what: 'restart $round up');
      expect(await current.ownDeviceListVersion(), 4,
          reason: 'restart $round re-signed the list');
      await quietOwner(current, 'restart $round');
      await exchange(current, r.bob, 'restart $round');
      await quietContact(r.bob, current.myRid, 'restart $round');
      expect((await logVersions(r.acct)).where((v) => v >= 3), [3, 4],
          reason: 'restart $round published another version');
    }
  });

  test(
      '3. a log ahead of the archive: signs above it, takes the lists in '
      'between as its own, keeps a removal and does not adopt an addition',
      () async {
    final (alice, aliceDir) = await fresh('alice3');
    final (bob, _) = await fresh('bob3');
    await befriend(alice, bob);
    final account = await alice.accountIdentity();
    final a = await ZIdentity.generate();
    final b = await ZIdentity.generate();
    final certA = await account.signDeviceCert(
        deviceEdPub: a.edPub, deviceXPub: a.xPub, deviceId: 'tab');
    final certB = await account.signDeviceCert(
        deviceEdPub: b.edPub, deviceXPub: b.xPub, deviceId: 'desk');
    await alice.addMyDevice(certA); // v2 = {alice, A}
    await holds(bob, alice.myRid, 2);
    await logReaches(account.accountEdPub, 2);
    await exchange(alice, bob, 'v2');
    await settled([alice, bob]);
    final (file, code) = await backup(alice, 'alice3'); // knows v2

    // After the backup: A is removed (lost, say) and B linked.
    await alice.removeMyDevice(certA); // v3 = {alice}
    await alice.addMyDevice(certB); // v4 = {alice, B}
    await holds(bob, alice.myRid, 4);
    await logReaches(account.accountEdPub, 4);
    await exchange(alice, bob, 'v4');
    await settled([alice, bob]);

    await lose(alice, aliceDir);
    final revived =
        await boot(await restoreInto(aliceDir, file, code), 'alice3');
    await waitUntil(() => up(revived), what: 'the restored device up');

    expect(await revived.ownDeviceListVersion(), 5,
        reason: 'max(log v4, archive v2) + 1');
    expect(edsOf(await ownList(revived)), {b64(revived.identity.edPub)},
        reason: 'A was removed after the backup and stays removed; B was '
            'never in the archive and is not taken from the log');
    await quietOwner(revived, 'v3 and v4 are this account\'s own history');
    await exchange(revived, bob, 'restored');
    await claimJudged(bob, revived.myRid, 5);
    expect(bob.contactDevlistAlerts[revived.myRid], isNull);
    await holds(bob, revived.myRid, 5);
    await logReaches(account.accountEdPub, 5);
    await quietContact(bob, revived.myRid, 'after the restore');
    expect(bob.kt.statusOf(revived.myRid)?.state, KtContactState.confirmed);
    expect((await logVersions(account.accountEdPub)).where((v) => v >= 2),
        [2, 3, 4, 5]);
  });

  test(
      '4. a linked device\'s backup restores as that linked device and '
      'publishes nothing for its own key', () async {
    final (phone, _) = await fresh('phone4');
    final (laptop, laptopDir, laptopCert) = await linkTo(phone, 'laptop4');
    final (carol, _) = await fresh('carol4');
    await waitFor(() async => await laptop.ownDeviceListVersion() >= 2,
        what: 'the laptop learning v2');
    await befriend(phone, carol);
    await waitUntil(() => laptop.contacts.containsKey(carol.myRid),
        what: 'the laptop learning Carol from its root');
    await holds(carol, phone.myRid, 2);
    await exchange(carol, phone, 'warm');
    await waitUntil(() => texts(laptop, carol.myRid).contains('warm a'),
        what: "Carol's message fanned to the laptop");
    await settled([phone, carol]);
    final account = await phone.accountIdentity();
    await logReaches(account.accountEdPub, 2);
    final accountVersions = await logVersions(account.accountEdPub);

    final (file, code) = await backup(laptop, 'laptop4');
    await lose(laptop, laptopDir);
    final revived =
        await boot(await restoreInto(laptopDir, file, code), 'laptop4');
    await waitUntil(() => up(revived), what: 'the restored laptop up');

    expect(await revived.holdsAccountRoot(), isFalse,
        reason: 'a linked device came back as the root of an account of '
            'its own');
    expect(await revived.isLinkedDevice, isTrue);
    expect(b64((await revived.accountIdentity()).accountEdPub),
        b64(account.accountEdPub),
        reason: 'the same account');
    await quietOwner(revived, 'the restored laptop');
    expect(await logLatest(laptopCert.deviceEdPub), 0,
        reason: 'a log entry was published for a key that is not an '
            'account root');
    expect(await logVersions(account.accountEdPub), accountVersions,
        reason: 'the account\'s own log history changed');

    // It is in touch: it speaks first (opening fresh sessions), and then
    // both its root and its contact reach it.
    await revived.sendText(carol.myRid, 'laptop back');
    await waitUntil(() => texts(carol, phone.myRid).contains('laptop back'),
        what: "Carol receiving the restored laptop's message");
    await phone.sendText(carol.myRid, 'from the phone');
    await waitUntil(
        () => texts(revived, carol.myRid).contains('from the phone'),
        what: "the phone's message mirrored to the restored laptop");
    await carol.sendText(phone.myRid, 'to both');
    await waitUntil(() => texts(revived, carol.myRid).contains('to both'),
        what: "Carol's message fanned to the restored laptop");
    await quietOwner(phone, 'the root');
    await quietContact(carol, phone.myRid, 'Carol');
    expect(await logLatest(laptopCert.deviceEdPub), 0);
  });

  test(
      '5. the block list, a pending request, push-off and a custom log '
      'configuration survive the restore', () async {
    final (alice, aliceDir) = await fresh('alice5');
    final (mallory, _) = await fresh('mallory5');
    final (carol, _) = await fresh('carol5');
    await waitUntil(() => up(alice) && up(mallory) && up(carol),
        what: 'everyone up');
    // Mallory asks and is blocked; Carol asks and waits.
    await mallory.addContactFromCode(await alice.myContactCode());
    await carol.addContactFromCode(await alice.myContactCode());
    await waitUntil(
        () =>
            alice.requestsByRid.containsKey(mallory.myRid) &&
            alice.requestsByRid.containsKey(carol.myRid),
        what: 'both requests at Alice');
    await alice.blockRequest(mallory.myRid);
    expect(alice.isBlocked(mallory.myRid), isTrue);
    // Push off, and a log of her own (a self-hoster's).
    await alice.vault.kvPut('push_enabled', '0', sensitive: false);
    await alice.setKtConfig(cfg());

    final (file, code) = await backup(alice, 'alice5');
    await lose(alice, aliceDir);
    // Started with the build's defaults, as the app is: whatever log it uses
    // is what the vault says.
    final revived = await boot(
        await restoreInto(aliceDir, file, code), 'alice5',
        ktConfig: KtConfig.defaults);
    expect(revived.isBlocked(mallory.myRid), isTrue,
        reason: 'a blocked person could reach the restored device again');
    expect(revived.requestsByRid.containsKey(mallory.myRid), isFalse);
    expect(revived.requestsByRid[carol.myRid]?.name, 'carol5',
        reason: 'the pending request was lost');
    expect(await revived.vault.kvGet('push_enabled'), '0',
        reason: 'push came back on');
    expect(revived.kt.config.logUrl, cfg().logUrl,
        reason: 'the restored device went back to the default log');
    expect(revived.kt.config.logPubB64, cfg().logPubB64);

    // The pending request is a real one: accepted, it becomes a contact who
    // can be talked to.
    await waitUntil(() => up(revived), what: 'the restored device up');
    await revived.acceptRequest(carol.myRid);
    await settled([revived, carol]);
    await exchange(revived, carol, 'accepted');
  });

  test(
      '6. a first-flight envelope replayed after the restore does not bring '
      'back a deleted message, and the session keeps working', () async {
    final (alice, aliceDir) = await fresh('alice6');
    final (bob, _) = await fresh('bob6');
    await befriend(alice, bob);
    await exchange(alice, bob, 'warm');
    await settled([alice, bob]);

    // Bob opens a fresh session while Alice is away, and his first flight
    // on it — the hello and a message — waits at the relay.
    await alice.transport.stop();
    await bob.resetSecureSession(alice.myRid);
    await bob.sendText(alice.myRid, 'the plan');
    await waitFor(
        () async => (await bob.vault.db.query('outbox', limit: 1)).isEmpty,
        what: "Bob's first flight handed to the relay");

    // Someone keeps a copy of everything delivered to Alice.
    final kept = <RelayInbound>[];
    final deliver = alice.transport.onMessage!;
    alice.transport.onMessage = (m) {
      kept.add(m);
      deliver(m);
    };
    alice.transport.start();
    await waitUntil(() => texts(alice, bob.myRid).contains('the plan'),
        what: "'the plan' at Alice");
    final plan = alice.messagesByChat[bob.myRid]!
        .firstWhere((m) => m.body == 'the plan');
    await alice.deleteMessage(bob.myRid, plan.mid);
    expect(texts(alice, bob.myRid), isNot(contains('the plan')));
    await exchange(alice, bob, 'after the plan');
    await settled([alice, bob]);

    // The envelopes of that first flight: sealed to Alice, from Bob, opening
    // a session (they carry its ephemeral key).
    final firstFlight = <RelayInbound>[];
    for (final m in kept) {
      final opened = await SealedEnvelope.open(
          myXSeed: alice.identity.xSeed,
          myXPub: alice.identity.xPub,
          blob: m.payload);
      if (opened == null || opened.fromRid != bob.myRid) continue;
      final Map<String, Object?> body;
      try {
        body = (jsonDecode(utf8.decode(base64Decode(opened.payload))) as Map)
            .cast<String, Object?>();
      } catch (_) {
        continue;
      }
      if (body['ek'] is String) firstFlight.add(m);
    }
    expect(firstFlight.length, greaterThanOrEqualTo(2),
        reason: 'the hello and the message both open the session');

    final (file, code) = await backup(alice, 'alice6');
    await lose(alice, aliceDir);
    final revived =
        await boot(await restoreInto(aliceDir, file, code), 'alice6');
    await waitUntil(() => up(revived), what: 'the restored device up');
    await exchange(revived, bob, 'restored');
    await settled([revived, bob]);
    await revived.loadMessages(bob.myRid);
    expect(texts(revived, bob.myRid), isNot(contains('the plan')));

    // How many envelopes from Bob the restored device has counted as
    // unreadable so far: every one of the replayed ones must be counted, or
    // read — and if one is read, the deleted message is back.
    Future<int> unreadable() async {
      var n = 0;
      for (final row in await revived.vault.db.query('messages',
          where: 'rid = ? AND kind = ?', whereArgs: [bob.myRid, 'system'])) {
        final body = await revived.vault.unseal(row['enc_body'] as String);
        if (!body.startsWith('{')) continue;
        final j = jsonDecode(body);
        if (j is Map && j['k'] == SystemKind.decryptFailed) {
          n += (j['n'] as num?)?.toInt() ?? 1;
        }
      }
      return n;
    }

    final before = await unreadable();
    final replayer = await RelayClient.connectAnonymous(
        relayUrl(), await ZIdentity.generate());
    for (final m in firstFlight) {
      await replayer.send(
          to: revived.myRid, id: newMessageId(), payload: m.payload);
    }
    await replayer.close();
    await waitFor(
        () async =>
            texts(revived, bob.myRid).contains('the plan') ||
            await unreadable() >= before + firstFlight.length,
        what: 'the restored device handling every replayed envelope');
    await revived.loadMessages(bob.myRid);
    expect(texts(revived, bob.myRid), isNot(contains('the plan')),
        reason: 'a replayed opener brought a deleted message back');
    expect(await unreadable(), before + firstFlight.length);

    // And the session the replay belonged to was not re-created: the pair
    // goes on talking on the one the restore opened.
    await exchange(revived, bob, 'still talking');
    await exchange(bob, revived, 'and back');
  });

  /// An archive with [header] and the given records, sealed under [code].
  Future<File> handMade(RecoveryCode code, Map<String, Object?> header,
      List<Map<String, Object?>> records, String name) async {
    final salt = unb64(header['salt'] as String);
    final np = unb64(header['np'] as String);
    final key = await ZArchive.deriveKey(await code.keyMaterial(), salt);
    final head = Uint8List.fromList(utf8.encode(jsonEncode(header)));
    final file = File(p.join((await tempDir(name)).path, '$name.zbk'));
    final sink = file.openWrite();
    sink.add(head);
    sink.add(const [0x0a]);
    final bodies = [
      for (final r in records) (ZArchive.kindRecord, utf8.encode(jsonEncode(r))),
      (
        ZArchive.kindEnd,
        utf8.encode(jsonEncode({'t': 'end', 'records': records.length}))
      ),
    ];
    for (var i = 0; i < bodies.length; i++) {
      final sealed = await ZArchive.sealFrame(
          key: key,
          header: head,
          noncePrefix: np,
          index: i,
          kind: bodies[i].$1,
          payload: bodies[i].$2);
      sink.add((ByteData(4)..setUint32(0, sealed.length)).buffer.asUint8List());
      sink.add(sealed);
    }
    await sink.close();
    return file;
  }

  /// Every record frame of [file], as the JSON text it carries.
  Future<List<String>> recordsOf(File file, RecoveryCode code) async {
    final bytes = await file.readAsBytes();
    final nl = bytes.indexOf(0x0a);
    final head = Uint8List.fromList(bytes.sublist(0, nl));
    final h = (jsonDecode(utf8.decode(head)) as Map).cast<String, Object?>();
    final key = await ZArchive.deriveKey(
        await code.keyMaterial(), unb64(h['salt'] as String));
    final np = unb64(h['np'] as String);
    final out = <String>[];
    var off = nl + 1;
    var i = 0;
    while (off < bytes.length) {
      final len = ByteData.sublistView(bytes, off, off + 4).getUint32(0);
      off += 4;
      final (kind, payload) = await ZArchive.openFrame(
          key: key,
          header: head,
          noncePrefix: np,
          index: i++,
          sealed: Uint8List.fromList(bytes.sublist(off, off + len)));
      off += len;
      if (kind == ZArchive.kindRecord) out.add(utf8.decode(payload));
    }
    return out;
  }

  Map<String, Object?> headerFor(int major) => {
        'z': 'zbk',
        'v': major,
        'app': 'z',
        'kdf': 'argon2id',
        'm': ZArchive.kdfMemoryKib,
        't': ZArchive.kdfIterations,
        'p': ZArchive.kdfParallelism,
        'salt': b64(randomBytes(16)),
        'np': b64(randomBytes(16)),
        'schema': Vault.schemaVersion,
        'created': DateTime.now().millisecondsSinceEpoch,
      };

  /// [file] as a build before format 1.1 wrote it — what every archive taken
  /// before this phase is: no `mv` in the header; no `state`, `blocked` or
  /// `request` record; no `account` beside the identity; a contact with only
  /// the members 1.0 gave it. Record frames only, so the vault it was taken
  /// from must hold no attachment.
  Future<File> asFormat10(File file, RecoveryCode code, String name) async {
    final bytes = await file.readAsBytes();
    final header = Map<String, Object?>.from(
        jsonDecode(utf8.decode(bytes.sublist(0, bytes.indexOf(0x0a)))) as Map)
      ..remove('mv');
    final records = <Map<String, Object?>>[];
    for (final text in await recordsOf(file, code)) {
      final r = Map<String, Object?>.from(jsonDecode(text) as Map);
      if (const {'state', 'blocked', 'request'}.contains(r['t'])) continue;
      if (r['t'] == 'identity') r.remove('account');
      if (r['t'] == 'contact') {
        for (final k in const ['req', 'kv', 'sids', 'xsids']) {
          r.remove(k);
        }
      }
      records.add(r);
    }
    return handMade(code, header, records, name);
  }

  test(
      '7. an archive of a newer major format is refused as such, on sight '
      'and on import, and nothing is written', () async {
    final code = await RecoveryCode.generate();
    final identity = await ZIdentity.generate();
    final file = await handMade(
        code,
        headerFor(2),
        [
          {'t': 'meta', 'app': 'z', 'schema': Vault.schemaVersion, 'name': 'N'},
          {'t': 'identity', 'identity': identity.toJson()},
        ],
        'major2');

    // On sight: the header is plaintext, so the app can say so before it
    // asks for a code it would then derive a key from for nothing.
    final preview = await Restore.identify(file);
    expect(preview.kind.name, 'newerFormat',
        reason: 'a newer archive was taken for one this build can read');
    expect(preview.carriesHistory, isFalse);

    // And on import, whatever the caller thought it was.
    final vault = await Vault.open(rootOverride: await tempDir('major2in'));
    await expectLater(
        Restore.run(
            vault: vault,
            file: file,
            secret: await code.format(),
            kind: BackupKind.archive),
        throwsA(isA<FormatException>().having((e) => e.message, 'message',
            contains('newer version of Z'))));
    expect(await vault.kvGet('identity'), isNull,
        reason: 'a refused archive wrote an identity');
    expect(await vault.db.query('kv'), isEmpty);
    await vault.db.close();
  });

  test(
      '8. a vault from a newer build is refused and left alone; one an older '
      'build downgraded upgrades again', () async {
    // A vault a future build wrote: one schema version past this one.
    final ahead = await tempDir('vault_ahead');
    final v1 = await Vault.open(rootOverride: ahead);
    await v1.kvPut('display_name', 'Future');
    await v1.db.close();
    final path = p.join(ahead.path, 'z.db');
    sqfliteFfiInit();
    final raw = await databaseFactoryFfi.openDatabase(path);
    await raw.execute('PRAGMA user_version = ${Vault.schemaVersion + 1}');
    await raw.close();
    await expectLater(Vault.open(rootOverride: ahead),
        throwsA(predicate((e) => '$e'.contains('newer version of Z'))),
        reason: 'this build opened a vault a newer one wrote');
    final after = await databaseFactoryFfi.openDatabase(path);
    expect(await after.getVersion(), Vault.schemaVersion + 1,
        reason: 'the refused vault was marked as this build\'s schema');
    await after.close();

    // A vault an older build already opened: it set the version back
    // without touching a table (that build had no rule against it), so the
    // columns of every later migration are already there.
    final behind = await tempDir('vault_behind');
    final v2 = await Vault.open(rootOverride: behind);
    await v2.db.insert('messages', {
      'mid': 'm1',
      'rid': 'peer',
      'outgoing': 1,
      'kind': 'text',
      'enc_body': await v2.seal('kept through it all'),
      'ts_ms': 1,
      'status': 1,
      'expire_at_ms': 0,
    });
    await v2.db.close();
    final older = await databaseFactoryFfi.openDatabase(
        p.join(behind.path, 'z.db'),
        options: OpenDatabaseOptions(version: Vault.schemaVersion - 1));
    expect(await older.getVersion(), Vault.schemaVersion - 1);
    await older.close();
    final reopened = await Vault.open(rootOverride: behind);
    expect(await reopened.db.getVersion(), Vault.schemaVersion);
    final row = (await reopened.db.query('messages')).single;
    expect(await reopened.unseal(row['enc_body'] as String),
        'kept through it all');
    await reopened.db.close();
  });

  test(
      '9. an unknown record marked keep survives a re-backup byte for byte; '
      'one that is not is dropped', () async {
    final code = await RecoveryCode.generate();
    final identity = await ZIdentity.generate();
    final header = headerFor(1)..['mv'] = 99; // a newer minor of this major
    final keep = {
      't': 'handlekey',
      'keep': 1,
      'k': 'aGFuZGxl',
      'n': [3, 1, 4]
    };
    final keepText = jsonEncode(keep);
    final file = await handMade(
        code,
        header,
        [
          {'t': 'meta', 'app': 'z', 'schema': Vault.schemaVersion, 'name': 'K'},
          {'t': 'identity', 'identity': identity.toJson()},
          keep,
          {'t': 'scratch', 'x': 1},
        ],
        'minor99');
    final vault = await Vault.open(rootOverride: await tempDir('minor99in'));
    await Restore.run(
        vault: vault,
        file: file,
        secret: await code.format(),
        kind: (await Restore.identify(file)).kind);
    expect(await vault.kvGet('display_name'), 'K');

    final again = File(p.join((await tempDir('rebackup')).path, 'r.zbk'));
    final sink = again.openWrite();
    await BackupArchive.export(vault: vault, code: code, out: sink);
    await sink.close();
    final out = await recordsOf(again, code);
    expect(out, contains(keepText),
        reason: 'a record its writer marked safe to keep was dropped');
    expect(out.where((r) => r.contains('"scratch"')), isEmpty,
        reason: 'a record nobody marked was carried forward');
    await vault.db.close();
  });

  test(
      '10. an archive written before format 1.1 — no device-list state at '
      'all — restores as quietly, from what the log holds', () async {
    final r = await linkedUnlinkedRestored('10',
        rewrite: (file, code) => asFormat10(file, code, 'alice10_1_0'));
    final aliceRid = r.revived.myRid;
    expect(await r.revived.vault.kvGet('own_list_json'), isNotNull);

    await r.revived.sendText(r.bob.myRid, 'back from an old backup');
    await waitUntil(
        () => texts(r.bob, aliceRid).contains('back from an old backup'),
        what: "Bob receiving the restored device's message");
    await claimJudged(r.bob, aliceRid, 4);
    expect(r.bob.contactDevlistAlerts[aliceRid], isNull,
        reason: 'the restored device claimed a list version below one Bob '
            'had seen from it: a rollback alarm');
    await quietOwner(r.revived, 'after restoring a 1.0 archive');
    await holds(r.bob, aliceRid, 4);
    await logReaches(r.acct, 4);
    await quietContact(r.bob, aliceRid, 'after restoring a 1.0 archive');
    expect((await logVersions(r.acct)).where((v) => v >= 3), [3, 4],
        reason: 'one entry per version, the restored one directly above');

    // Signed before the transport started, as from a 1.1 archive.
    final atStart = await r.watch.ownListAtStart;
    expect(atStart, isNotNull,
        reason: 'the transport started before the device held any list');
    expect(
        SignedDeviceList.fromJson(
                (jsonDecode(atStart!) as Map).cast<String, Object?>())
            .version,
        4);
    expect(r.watch.sendsBeforeStart, 0);

    await exchange(r.bob, r.revived, 'after');
    expect(r.bob.contactDevlistAlerts[aliceRid], isNull);
    await quietOwner(r.revived, 'after an exchange');
  });

  test(
      '11. an account moved to v2-only signing (ADR 0017 stage 2b) restores '
      'as one: the list it signs next is v2-only too, and nobody is alarmed',
      () async {
    final (alice, aliceDir) = await fresh('alice11', v2Only: true);
    final (bob, _) = await fresh('bob11');
    final account = await alice.accountIdentity();
    final moved = await ownList(alice);
    expect(moved.isV2Only, isTrue, reason: 'the account did not move');
    await befriend(alice, bob);
    await holds(bob, alice.myRid, moved.version);
    await logReaches(account.accountEdPub, moved.version);
    await exchange(alice, bob, 'moved');
    await settled([alice, bob]);

    final (file, code) = await backup(alice, 'alice11');
    await lose(alice, aliceDir);
    final revived = await boot(
        await restoreInto(aliceDir, file, code), 'alice11',
        v2Only: true);
    await waitUntil(() => up(revived), what: 'the restored device up');
    final next = await ownList(revived);
    expect(next.version, moved.version + 1,
        reason: 'max(log, archive) + 1, and only one version');
    expect(next.isV2Only, isTrue,
        reason: 'a moved account came back signing dual-signed lists');
    await quietOwner(revived, 'after the restore');

    await exchange(revived, bob, 'restored');
    await claimJudged(bob, revived.myRid, next.version);
    expect(bob.contactDevlistAlerts[revived.myRid], isNull);
    await holds(bob, revived.myRid, next.version);
    await logReaches(account.accountEdPub, next.version);
    await quietContact(bob, revived.myRid, 'after the restore');
    expect(
        (await logVersions(account.accountEdPub))
            .where((v) => v >= moved.version),
        [moved.version, next.version]);
  });

  test(
      "12. what the owner's alarms stand on survives the restore: a banner's "
      "evidence, every dismissal and the own-list repair's record", () async {
    final (alice, aliceDir) = await fresh('alice12');
    final account = await alice.accountIdentity();
    await waitUntil(() => up(alice), what: 'Alice up');
    // This build made the vault, so its first start recorded the own-list
    // repair's window empty (ADR 0026): no head was held then, and the
    // repair can never apply to this account.
    const emptyWindow = {'size': 0, 'v': <int>[]};
    expect(jsonDecode((await alice.vault.kvGet('kt_own_legacy'))!),
        emptyWindow);
    // By the backup the log holds the account's first list under a head
    // this device has accepted: the head and versions a restore that
    // recorded the window again would take. (Accepted at a check: since
    // phase 35 none runs at start.)
    await alice.kt.check();
    await logReaches(account.accountEdPub, 1);
    await waitUntil(
        () =>
            (alice.kt.head?.size ?? 0) > 0 &&
            alice.kt.knownOwnVersions.isNotEmpty,
        what: 'a head and a recorded version of the account');
    // A banner standing on its evidence, a dismissed one, and an entry the
    // repair reconciled.
    final shown = unissuedEvidence(9, b64(Uint8List(32)));
    final dismissed =
        logEntryEvidence(8, b64(Uint8List.fromList(List.filled(32, 1))));
    final reconciledFp = b64(Uint8List.fromList(List.filled(32, 2)));
    await alice.vault.kvPut(
        'own_alert', ownAlertBody(OwnAlertKind.unissued),
        sensitive: false);
    await alice.vault.kvPut('own_alert_ev', jsonEncode([shown]));
    await alice.kt.dismissals.add(dismissed);
    await alice.vault
        .kvPut('kt_own_reconciled', jsonEncode({'7': reconciledFp}));

    final (file, code) = await backup(alice, 'alice12');
    await lose(alice, aliceDir);
    final revived = await boot(
        await restoreInto(aliceDir, file, code), 'alice12');
    expect(jsonDecode((await revived.vault.kvGet('kt_own_legacy'))!),
        emptyWindow,
        reason: "the restored vault recorded the repair's window again from "
            "the archive's head, so the repair would now reconcile entries "
            'the device it came from still reports');
    expect(revived.kt.dismissals.contains(dismissed), isTrue,
        reason: 'a dismissal did not survive the restore');
    expect(jsonDecode((await revived.vault.kvGet('own_alert_ev'))!), [shown],
        reason: "the banner came back without what it stands on");
    expect(revived.ownAccountAlert, ownAlertBody(OwnAlertKind.unissued));
    expect(revived.kt.ownListReconciled(7, reconciledFp), isTrue,
        reason: "the repair's reconciled entries did not survive");
  });
}
