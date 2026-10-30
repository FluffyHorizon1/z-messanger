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
//      above, and nobody is alarmed; and the contact's next message, which
//      says what it reads — a restore keeps no reader levels — is taken in
//      before the receipt it earns is owed, so that receipt carries the
//      account's claim (before 2026-10-18 it could go without, and with
//      nothing more said, the contact never heard the claim);
//  12. what the owner's alarms stand on (ADR 0026) survives the restore: a
//      standing banner's evidence, every dismissal, and the own-list
//      repair's record of the head and versions held when it first ran —
//      which a restored vault must not record again from the archive's head,
//      or the repair would reconcile entries the device it came from still
//      reports;
//  13. (44.3, PROTOCOL §18.11) the device's sealing key comes back with it:
//      the archive carries the seed and the root's `pqdc` in a record of
//      their own marked `keep` (ADR 0025), and the restored device holds the
//      same seed and the same `pqdc`, byte for byte, and uses them; an
//      archive from before 44.3 restores, and a key is then drawn once — the
//      same across a restart; and a build from before 44.3 that restored the
//      archive kept the record unread, so updated, it takes the key from
//      there rather than drawing one;
//  14. (44.3, PROTOCOL §18.11) and its contact's comes back too: the archive
//      carries no other device's sealing key, and the contact — which had
//      heard the lost device hold its own — forgets that once the restored
//      device's new ratchet session reaches it, and announces its key again
//      on its clock; each ends holding the other's key, and having heard
//      that the other holds its own;
//  15. the same on the other two kinds of channel, for a restored LINKED
//      device: its root forgets over self-sync, and its account's contact
//      forgets on the door it takes a contact's other device by, and both
//      announce again; all three end holding one another's keys and having
//      heard that the others hold theirs;
//  16. (4.8.1, PROTOCOL §18.11) a device restored onto a NEW sealing key —
//      an archive that carried none, as every one from before 44.3 — is
//      heard: its contact holds its old key and says so on everything it
//      sends, and the restored device takes none of that as said of its new
//      key until it has announced it there, so it announces it, and the
//      contact ends holding the new key and saying so. Through 4.8.0 the
//      restored device took the stamp for its new key, and announced
//      nothing;
//  17. the same for a restored ROOT, over self-sync too: its linked laptop
//      and its contact each hold its old key and say so, and each ends
//      holding the new key, the root hearing both say so;
//  18. the same with a contact on 4.8.0's rules, which says it holds the
//      old key throughout: the contact ends holding the new key;
//  19. a pair stuck before this release: a device restored onto a new key
//      under 4.8.0's rules took its contact's word for its old key as word
//      for the new and announced nothing, so the contact holds the old key;
//      once the device starts on this build it announces its key, and the
//      contact ends holding it;
//  20. a session reset loses nothing and costs nothing: on the shipped
//      clock — six hours between announcements — each side goes on holding
//      the other's key and hearing that the other holds its own, within a
//      few messages of the reset, and neither announces again;
//  21. a device whose stored seed no longer reads as one draws a new key,
//      and what it held of devices holding the old one goes with it: it
//      announces the new key, and its contact ends holding it;
//  22. a contact whose store of the restored device's first envelope
//      fails, and is done again from the relay's redelivery, writes down
//      that the restored device no longer holds its key, so that after a
//      restart it still announces its key there, and the restored device
//      ends holding it.
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
import 'package:zapp/core/receipts.dart';
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

// ADR 0028 holds a receipt from 5 s to a minute, at random, so the relay
// cannot pair it with the message it answers (receipt_timing_test.dart). Every
// inner a client sends carries the device-list gossip, receipts included, and
// the claim (`dl`) a contact weighs after a restore often arrives on nothing
// but a receipt. This suite is about restores, not about when a tick turns,
// so its devices answer within 300 ms, as every device did before phase 41.
const promptReceipts =
    ReceiptTiming(floor: Duration.zero, ceiling: Duration(milliseconds: 300));

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
      // Best-effort: a stopped service's last write can still be closing its
      // journal while the directory goes, and a file gone first is no
      // failure of anything under test.
      try {
        if (d.existsSync()) d.deleteSync(recursive: true);
      } on FileSystemException {
        // Left for the system's own temp cleanup.
      }
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
  /// one the vault holds. [before481] starts it with 4.8.0's rule for a
  /// `pqs:1` (`ChatService.debugBuildBefore481`).
  Future<ChatService> boot(Vault vault, String name,
      {Transport? transport,
      KtConfig? ktConfig,
      bool? v2Only,
      bool before481 = false}) async {
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
        receiptTiming: promptReceipts,
        // Asked for by name, the signer moves at the first start, as it did
        // before ADR 0029 made it wait on the account's readers: test 11 is
        // about a moved account's restore, not about when it moved.
        debugMoveUngated: v2Only ?? false,
        debugBuildBefore481: before481);
    svc.kt.scheduled = false; // checked when the test says so
    svc.devlistGrace = const Duration(milliseconds: 700);
    services.add(svc);
    return svc;
  }

  Future<(ChatService, Directory)> fresh(String name,
      {bool? v2Only, bool before481 = false}) async {
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
    return (
      await boot(vault, name, v2Only: v2Only, before481: before481),
      dir
    );
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
  /// `request` record, nor the `seal` record of 44.3; no `account` beside
  /// the identity; a contact with only the members 1.0 gave it. Record
  /// frames only, so the vault it was taken from must hold no attachment.
  Future<File> asFormat10(File file, RecoveryCode code, String name) async {
    final bytes = await file.readAsBytes();
    final header = Map<String, Object?>.from(
        jsonDecode(utf8.decode(bytes.sublist(0, bytes.indexOf(0x0a)))) as Map)
      ..remove('mv');
    final records = <Map<String, Object?>>[];
    for (final text in await recordsOf(file, code)) {
      final r = Map<String, Object?>.from(jsonDecode(text) as Map);
      if (const {'state', 'blocked', 'request', 'seal'}.contains(r['t'])) {
        continue;
      }
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
    // What the restored device knows of what Bob's phone reads at the moment
    // it owes Bob a receipt — read there and then, before anything else runs.
    final knownAtOwe = <String, int?>{};
    revived.debugOnReceiptOwed = (rid, mids) {
      if (rid != bob.myRid) return;
      for (final m in mids) {
        knownAtOwe[m] = revived.debugReaderLevel(bob.myRid, bob.myRid);
      }
    };
    await waitUntil(() => up(revived), what: 'the restored device up');
    final next = await ownList(revived);
    expect(next.version, moved.version + 1,
        reason: 'max(log, archive) + 1, and only one version');
    expect(next.isV2Only, isTrue,
        reason: 'a moved account came back signing dual-signed lists');
    await quietOwner(revived, 'after the restore');

    await exchange(revived, bob, 'restored');
    // Bob's reply says what his phone reads, and the restored device, which
    // withholds its claim from a contact none of whose devices has said so,
    // has taken that in by the time it owes the reply a receipt — so the
    // receipt carries the claim, and with nothing more said Bob still hears
    // it. It used to be taken in last, after the receipt was owed.
    final reply = revived.messagesByChat[bob.myRid]!
        .firstWhere((m) => !m.outgoing && m.body == 'restored b');
    await waitUntil(() => knownAtOwe.containsKey(reply.mid),
        what: "the restored device owes Bob's reply a receipt");
    expect(knownAtOwe[reply.mid], devlistReaderLevel,
        reason: 'what the reply said Bob reads was known when its receipt '
            'was owed');
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

  test(
      '13. the sealing key and its pqdc come back byte for byte; an archive '
      'from before them restores and draws a key once; a kept record is '
      'taken up', () async {
    final (alice, aliceDir) = await fresh('alice13');
    final seed = await alice.vault.kvGet('seal_seed');
    final pqdc = await alice.vault.kvGet('pqdc');
    expect(seed, isNotNull, reason: 'the premise: a key from the first start');
    expect(pqdc, isNotNull, reason: 'and the root signed its pqdc');
    final identity = (await alice.vault.kvGet('identity'))!;
    final pqSeed = (await alice.vault.kvGet('pq_seed'))!;

    // The archive carries both in a record of their own, which a build that
    // does not know it keeps and writes back (ADR 0025).
    final (file, code) = await backup(alice, 'alice13');
    final texts = await recordsOf(file, code);
    final sealTexts = [
      for (final t in texts)
        if ((jsonDecode(t) as Map)['t'] == 'seal') t
    ];
    expect(sealTexts, hasLength(1), reason: 'one record of its own');
    final carried = jsonDecode(sealTexts.single) as Map;
    expect(carried['keep'], 1);
    expect(carried['seed'], seed);
    expect(carried['pqdc'], pqdc);

    // Restored onto the wiped device: the same key, and the same pqdc, kept
    // because it is this key's.
    await lose(alice, aliceDir);
    final restored = await restoreInto(aliceDir, file, code);
    expect(await restored.kvGet('seal_seed'), seed,
        reason: 'the restore wrote another seed');
    expect(await restored.kvGet('pqdc'), pqdc);
    final revived = await boot(restored, 'alice13');
    expect(await revived.vault.kvGet('seal_seed'), seed,
        reason: 'its first start drew a new key');
    expect(revived.debugSealingKey, SealingKey.fromSeed(unb64(seed!)).ek);
    expect(revived.debugOwnPqdc, unb64(pqdc!),
        reason: 'the restored pqdc was not kept');

    // Started elsewhere with the same identity, so on a relay nothing
    // listens on: one socket per routing id is the relay's rule.
    Future<ChatService> offline(Vault vault, String name) async {
      final id = await ZIdentity.fromJson(
          (jsonDecode((await vault.kvGet('identity'))!) as Map)
              .cast<String, Object?>());
      return boot(vault, name,
          transport: Transport(identity: id, serverUrl: 'ws://127.0.0.1:1'));
    }

    // An archive from before 44.3 carries no such record. It restores, and
    // the first start draws a key — once: a restart keeps it.
    final head = jsonDecode(utf8.decode(
            (await file.readAsBytes()).takeWhile((b) => b != 0x0a).toList()))
        as Map;
    final older = await handMade(
        code,
        Map<String, Object?>.from(head)
          ..['salt'] = b64(randomBytes(16))
          ..['np'] = b64(randomBytes(16)),
        [
          for (final t in texts)
            if ((jsonDecode(t) as Map)['t'] != 'seal')
              (jsonDecode(t) as Map).cast<String, Object?>()
        ],
        'alice13_old');
    final oldDir = await tempDir('alice13old');
    final oldVault = await restoreInto(oldDir, older, code);
    expect(await oldVault.kvGet('seal_seed'), isNull);
    var fromOld = await offline(oldVault, 'alice13old');
    final drawn = await fromOld.vault.kvGet('seal_seed');
    expect(drawn, isNotNull,
        reason: 'no key after restoring an archive from before 44.3');
    expect(drawn, isNot(seed));
    final acct = await fromOld.accountIdentity();
    expect(
        deviceAttestationValid(
            accountMlPub: (await fromOld.pqAccountPublic())!,
            accountEdPub: acct.accountEdPub,
            deviceEdPub: acct.deviceEdPub,
            deviceXPub: acct.deviceXPub,
            sealEk: fromOld.debugSealingKey!,
            pqdc: fromOld.debugOwnPqdc!),
        isTrue,
        reason: 'and the root signed a pqdc for the key it drew');
    fromOld.dispose();
    await fromOld.transport.stop();
    services.remove(fromOld);
    await fromOld.vault.db.close();
    fromOld = await offline(await Vault.open(rootOverride: oldDir), 'alice13old');
    expect(await fromOld.vault.kvGet('seal_seed'), drawn,
        reason: 'a second key drawn at the next start');

    // A build from before 44.3 that restored the archive kept the record,
    // unread, as the text it arrived as, to write back into its next
    // archive (`archive_kept`). Updated, this build takes the key from it.
    final keptVault = await Vault.open(rootOverride: await tempDir('alice13k'));
    await keptVault.kvPut('identity', identity);
    await keptVault.kvPut('pq_seed', pqSeed);
    await keptVault.kvPut(BackupArchive.keptKey, jsonEncode(sealTexts));
    final updated = await offline(keptVault, 'alice13k');
    expect(await updated.vault.kvGet('seal_seed'), seed,
        reason: 'drew a new key though the kept record held the old one');
    expect(await updated.vault.kvGet('pqdc'), pqdc);
    expect(await updated.vault.kvGet(BackupArchive.keptKey), isNull,
        reason: 'the record went on being kept beside the key it carries');
  });

  test(
      "14. a restored device and its contact each hold the other's sealing "
      'key again, and have heard so', () async {
    final (alice, aliceDir) = await fresh('alice14');
    final (bob, _) = await fresh('bob14');
    await befriend(alice, bob);
    var n = 0;
    await waitFor(() async {
      await exchange(alice, bob, 'k${n++}');
      return alice.debugPqSealOf(bob.myRid) != null &&
          bob.debugPqSealOf(alice.myRid) != null &&
          alice.debugHoldsMySealKey(bob.myRid) &&
          bob.debugHoldsMySealKey(alice.myRid);
    }, what: 'keys exchanged and stamped both ways');
    final aliceKey = alice.debugSealingKey!;
    final bobKey = bob.debugSealingKey!;

    // Bob has heard alice's device hold his key (the wait above), and goes
    // on holding that while the device is lost and restored. What changes
    // his mind is the restored device's first new session reaching him,
    // which may already have happened by the time it is up.
    final (file, code) = await backup(alice, 'alice14');
    await lose(alice, aliceDir);
    final revived =
        await boot(await restoreInto(aliceDir, file, code), 'alice14');
    await waitUntil(() => up(revived), what: 'the restored device up');
    expect(revived.debugSealingKey, aliceKey,
        reason: 'the premise: the same key comes back (13)');
    expect(revived.debugPqSealOf(bob.myRid), isNull,
        reason: "the premise: no other device's key is in the archive");
    // §17.4's clock, which the announcement runs on, compressed on both
    // sides: what is owed goes at the first message that may carry it.
    revived.pqOfferRetry = 300;
    bob.pqOfferRetry = 300;
    final bobBefore = bob.debugPqSealSends;
    var m = 0;
    await waitFor(() async {
      await exchange(revived, bob, 'after${m++}');
      return revived.debugPqSealOf(bob.myRid) != null &&
          bob.debugPqSealOf(revived.myRid) != null &&
          revived.debugHoldsMySealKey(bob.myRid) &&
          bob.debugHoldsMySealKey(revived.myRid);
    }, what: "each holds the other's sealing key again, and has heard so");
    expect(revived.debugPqSealOf(bob.myRid), bobKey);
    expect(bob.debugPqSealOf(revived.myRid), aliceKey);
    expect(bob.debugPqSealSends, greaterThan(bobBefore),
        reason: 'bob announced his key again');
  });

  test(
      "15. a restored linked device, its root and its contact hold one "
      "another's sealing keys again, over self-sync and to a contact's "
      'other device', () async {
    final (phone, _) = await fresh('phone15');
    final (laptop, laptopDir, _) = await linkTo(phone, 'laptop15');
    final (carol, _) = await fresh('carol15');
    await waitFor(() async => await laptop.ownDeviceListVersion() >= 2,
        what: 'the laptop learning v2');
    await befriend(phone, carol);
    await waitUntil(() => laptop.contacts.containsKey(carol.myRid),
        what: 'the laptop learning Carol from its root');
    await holds(carol, phone.myRid, 2);

    // [x] holds [y]'s key, and [y] has heard so, for every ordered pair of
    // the three: the self-sync channel both ways, the laptop and Carol both
    // ways (her door for a contact's other device, and the laptop's for a
    // contact), and the phone and Carol both ways.
    var lap = laptop;
    List<String> missing() => [
          for (final x in [phone, lap, carol])
            for (final y in [phone, lap, carol])
              if (!identical(x, y) &&
                  !(x.debugPqSealOf(y.myRid) != null &&
                      y.debugHoldsMySealKey(x.myRid)))
                "${x.displayName} holding ${y.displayName}'s, and heard so"
        ];
    bool everyHeld() => missing().isEmpty;
    // One text from each of the three, waited for where it cannot go
    // astray: right after the restore, what the phone and Carol send the
    // laptop can still go on sessions the restored laptop never held.
    var n = 0;
    Future<void> round(String tag) async {
      final i = n++;
      await phone.sendText(carol.myRid, '$tag p$i');
      await carol.sendText(phone.myRid, '$tag c$i');
      await lap.sendText(carol.myRid, '$tag l$i');
      await waitUntil(
          () =>
              texts(carol, phone.myRid).contains('$tag p$i') &&
              texts(carol, phone.myRid).contains('$tag l$i') &&
              texts(phone, carol.myRid).contains('$tag c$i'),
          what: '$tag round $i');
    }

    await waitFor(() async {
      await round('k');
      return everyHeld();
    }, what: 'every key held and every stamp heard, among the three');
    final laptopKey = laptop.debugSealingKey!;

    final (file, code) = await backup(laptop, 'laptop15');
    await lose(laptop, laptopDir);
    final revived =
        await boot(await restoreInto(laptopDir, file, code), 'laptop15');
    await waitUntil(() => up(revived), what: 'the restored laptop up');
    expect(revived.debugSealingKey, laptopKey,
        reason: 'the premise: the same key comes back (13)');
    expect(revived.debugPqSealOf(phone.myRid), isNull,
        reason: "the premise: no other device's key is in the archive");
    expect(revived.debugPqSealOf(carol.myRid), isNull);
    lap = revived;
    for (final s in [phone, revived, carol]) {
      s.pqOfferRetry = 300; // §17.4's clock, which the announcement runs on
    }
    final phoneBefore = phone.debugPqSealSends;
    final carolBefore = carol.debugPqSealSends;
    try {
      await waitFor(() async {
        await round('after');
        return everyHeld();
      }, what: 'every key held and every stamp heard again, among the three');
    } on TimeoutException {
      fail('after the restore, never again: ${missing()}');
    }
    expect(revived.debugPqSealOf(phone.myRid), phone.debugSealingKey);
    expect(revived.debugPqSealOf(carol.myRid), carol.debugSealingKey);
    expect(phone.debugPqSealOf(revived.myRid), laptopKey);
    expect(carol.debugPqSealOf(revived.myRid), laptopKey);
    expect(phone.debugPqSealSends, greaterThan(phoneBefore),
        reason: 'the root announced its key again, over self-sync');
    expect(carol.debugPqSealSends, greaterThan(carolBefore),
        reason: "Carol announced hers again, to her contact's other device");
  });

  /// [a] and [b] each hold the other's sealing key, and have heard so.
  Future<void> sealsStamped(ChatService a, ChatService b, String tag) async {
    var n = 0;
    await waitFor(() async {
      await exchange(a, b, '$tag${n++}');
      return a.debugPqSealOf(b.myRid) != null &&
          b.debugPqSealOf(a.myRid) != null &&
          a.debugHoldsMySealKey(b.myRid) &&
          b.debugHoldsMySealKey(a.myRid);
    }, what: 'keys exchanged and stamped both ways');
  }

  /// [s]'s device lost, and restored from an archive with no sealing key in
  /// it, as every one from before 44.3: its first start draws a new key.
  Future<ChatService> restoredOntoNewKey(
      ChatService s, Directory dir, String name,
      {bool before481 = false}) async {
    final (file, code) = await backup(s, name);
    await lose(s, dir);
    final vault = await restoreInto(dir, file, code);
    await vault.kvDelete('seal_seed');
    await vault.kvDelete('pqdc');
    final revived = await boot(vault, name, before481: before481);
    await waitUntil(() => up(revived), what: 'the restored $name up');
    return revived;
  }

  /// The app stopped and started again on the same vault, as this build.
  Future<ChatService> restart(ChatService s, String name) async {
    final vault = s.vault;
    s.dispose();
    await s.transport.stop();
    services.remove(s);
    final again = await boot(vault, name);
    await waitUntil(() => up(again), what: '$name up again');
    return again;
  }

  bool holdsKey(ChatService s, String rid, Uint8List key) {
    final held = s.debugPqSealOf(rid);
    return held != null && constantTimeEquals(held, key);
  }

  test(
      '16. a device restored onto a new sealing key is heard: it takes its '
      "contact's word for the old key for nothing until it has announced "
      'the new one, and the contact ends holding the new', () async {
    final (alice, aliceDir) = await fresh('alice16');
    final (bob, _) = await fresh('bob16');
    await befriend(alice, bob);
    var n = 0;
    await waitFor(() async {
      await exchange(alice, bob, 'k${n++}');
      return alice.debugPqSealOf(bob.myRid) != null &&
          bob.debugPqSealOf(alice.myRid) != null &&
          alice.debugHoldsMySealKey(bob.myRid) &&
          bob.debugHoldsMySealKey(alice.myRid);
    }, what: 'keys exchanged and stamped both ways');
    final oldKey = alice.debugSealingKey!;

    // Alice's phone is lost, and restored from an archive with no sealing
    // key in it: her first start draws a new one.
    final (file, code) = await backup(alice, 'alice16');
    await lose(alice, aliceDir);
    final vault = await restoreInto(aliceDir, file, code);
    await vault.kvDelete('seal_seed');
    await vault.kvDelete('pqdc');
    final revived = await boot(vault, 'alice16');
    await waitUntil(() => up(revived), what: 'the restored device up');
    final newKey = revived.debugSealingKey!;
    expect(newKey, isNot(oldKey), reason: 'the premise: a new key');
    expect(bob.debugPqSealOf(revived.myRid), oldKey,
        reason: 'the premise: Bob holds the old one, and has said so');
    revived.pqOfferRetry = 300;
    bob.pqOfferRetry = 300;
    var m = 0;
    await waitFor(() async {
      await exchange(revived, bob, 'after${m++}');
      final held = bob.debugPqSealOf(revived.myRid);
      return held != null &&
          constantTimeEquals(held, newKey) &&
          revived.debugHoldsMySealKey(bob.myRid);
    }, what: "Bob holding the restored device's new key, and saying so");
    expect(bob.debugPqSealOf(revived.myRid), newKey);
  });

  test(
      "17. a root restored onto a new sealing key is heard by its own linked "
      'laptop over self-sync and by its contact, and hears both', () async {
    final (phone, phoneDir) = await fresh('phone17');
    final (laptop, _, _) = await linkTo(phone, 'laptop17');
    final (carol, _) = await fresh('carol17');
    await waitFor(() async => await laptop.ownDeviceListVersion() >= 2,
        what: 'the laptop learning v2');
    await befriend(phone, carol);
    await waitUntil(() => laptop.contacts.containsKey(carol.myRid),
        what: 'the laptop learning Carol from its root');
    await holds(carol, phone.myRid, 2);
    var ph = phone;
    // [x] holds [y]'s key, and [y] has heard so, for every ordered pair of
    // the three: over self-sync both ways, the laptop and Carol both ways,
    // and the phone and Carol both ways.
    List<String> missing() => [
          for (final x in [ph, laptop, carol])
            for (final y in [ph, laptop, carol])
              if (!identical(x, y) &&
                  !(x.debugPqSealOf(y.myRid) != null &&
                      y.debugHoldsMySealKey(x.myRid)))
                "${x.displayName} holding ${y.displayName}'s, and heard so"
        ];
    var n = 0;
    Future<void> round(String tag) async {
      final i = n++;
      await ph.sendText(carol.myRid, '$tag p$i');
      await carol.sendText(ph.myRid, '$tag c$i');
      await laptop.sendText(carol.myRid, '$tag l$i');
      await waitUntil(
          () =>
              texts(carol, ph.myRid).contains('$tag p$i') &&
              texts(carol, ph.myRid).contains('$tag l$i') &&
              texts(ph, carol.myRid).contains('$tag c$i'),
          what: '$tag round $i');
    }

    await waitFor(() async {
      await round('k');
      return missing().isEmpty;
    }, what: 'every key held and every stamp heard, among the three');
    final oldKey = phone.debugSealingKey!;

    ph = await restoredOntoNewKey(phone, phoneDir, 'phone17');
    final newKey = ph.debugSealingKey!;
    expect(newKey, isNot(oldKey), reason: 'the premise: a new key');
    expect(laptop.debugPqSealOf(ph.myRid), oldKey,
        reason: 'the premise: the laptop holds the old one');
    expect(carol.debugPqSealOf(ph.myRid), oldKey,
        reason: 'and so does Carol');
    for (final s in [ph, laptop, carol]) {
      s.pqOfferRetry = 300; // §17.4's clock, which the announcement runs on
    }
    try {
      await waitFor(() async {
        await round('after');
        return holdsKey(laptop, ph.myRid, newKey) &&
            holdsKey(carol, ph.myRid, newKey) &&
            missing().isEmpty;
      }, what: "the laptop and Carol holding the root's new key, heard so");
    } on TimeoutException {
      fail('after the restore: the laptop holds the new key: '
          '${holdsKey(laptop, ph.myRid, newKey)}, Carol: '
          '${holdsKey(carol, ph.myRid, newKey)}; ${missing()}');
    }
  });

  test(
      "18. a device restored onto a new sealing key whose contact runs "
      "4.8.0's rules is heard: the contact ends holding the new key",
      () async {
    final (alice, aliceDir) = await fresh('alice18');
    final (bob, _) = await fresh('bob18', before481: true);
    await befriend(alice, bob);
    await sealsStamped(alice, bob, 'k');
    final oldKey = alice.debugSealingKey!;

    final revived = await restoredOntoNewKey(alice, aliceDir, 'alice18');
    final newKey = revived.debugSealingKey!;
    expect(newKey, isNot(oldKey), reason: 'the premise: a new key');
    expect(bob.debugPqSealOf(revived.myRid), oldKey,
        reason: 'the premise: Bob holds the old one, and says so');
    revived.pqOfferRetry = 300;
    bob.pqOfferRetry = 300;
    var m = 0;
    await waitFor(() async {
      await exchange(revived, bob, 'after${m++}');
      return holdsKey(bob, revived.myRid, newKey) &&
          revived.debugHoldsMySealKey(bob.myRid);
    }, what: "Bob holding the restored device's new key, and saying so");
  });

  test(
      '19. a pair stuck before this release: once the device restored onto '
      'a new key starts on this build, it announces it, and its contact ends '
      'holding it', () async {
    final (alice, aliceDir) = await fresh('alice19');
    final (bob, _) = await fresh('bob19', before481: true);
    await befriend(alice, bob);
    await sealsStamped(alice, bob, 'k');
    final oldKey = alice.debugSealingKey!;

    // Restored under 4.8.0's rules: Bob's word for the old key, taken for
    // the new one.
    var revived =
        await restoredOntoNewKey(alice, aliceDir, 'alice19', before481: true);
    final newKey = revived.debugSealingKey!;
    expect(newKey, isNot(oldKey), reason: 'the premise: a new key');
    revived.pqOfferRetry = 300;
    bob.pqOfferRetry = 300;
    var m = 0;
    await waitFor(() async {
      await exchange(revived, bob, 'stuck${m++}');
      return revived.debugHoldsMySealKey(bob.myRid);
    }, what: "the restored device taking Bob's word for its key");
    // A negative check over a window: six more exchanges, and still nothing
    // announced — the pair is stuck, as 4.8.0 left it.
    for (var i = 0; i < 6; i++) {
      await exchange(revived, bob, 'still$i');
    }
    expect(revived.debugPqSealSends, 0,
        reason: 'the premise: the restored device announced nothing');
    expect(bob.debugPqSealOf(revived.myRid), oldKey,
        reason: 'the premise: Bob holds the old key');

    // The restored device is updated, and starts on this build.
    revived = await restart(revived, 'alice19');
    expect(revived.debugHoldsMySealKey(bob.myRid), isFalse,
        reason: 'a word taken before any announcement is not kept');
    revived.pqOfferRetry = 300;
    var k = 0;
    await waitFor(() async {
      await exchange(revived, bob, 'updated${k++}');
      return holdsKey(bob, revived.myRid, newKey) &&
          revived.debugHoldsMySealKey(bob.myRid);
    }, what: "Bob holding the new key once the restored device updates");
  });

  test(
      '20. a session reset loses nothing and costs nothing on the shipped '
      'clock: each side goes on hearing that the other holds its key, and '
      'neither announces again', () async {
    final (alice, _) = await fresh('alice20');
    final (bob, _) = await fresh('bob20');
    await befriend(alice, bob);
    await sealsStamped(alice, bob, 'k');
    // The shipped clock: six hours between announcements (§17.4).
    expect(alice.pqOfferRetry, pqOfferRetryMs);
    expect(bob.pqOfferRetry, pqOfferRetryMs);
    final aliceSends = alice.debugPqSealSends;
    final bobSends = bob.debugPqSealSends;
    await bob.resetSecureSession(alice.myRid);
    // Bob speaks first after his reset: what Alice sends on the retired
    // session before his new one reaches her is not read (§4).
    var m = 0;
    try {
      await waitFor(() async {
        await exchange(bob, alice, 'after${m++}');
        return alice.debugHoldsMySealKey(bob.myRid) &&
            bob.debugHoldsMySealKey(alice.myRid);
      },
          timeout: const Duration(seconds: 20),
          what: 'each hearing that the other holds its key again');
    } on TimeoutException {
      fail('after $m exchanges: Alice hears Bob holds hers: '
          '${alice.debugHoldsMySealKey(bob.myRid)}, Bob hears Alice holds '
          'his: ${bob.debugHoldsMySealKey(alice.myRid)}');
    }
    expect(alice.debugPqSealSends, aliceSends, reason: 'no announcement');
    expect(bob.debugPqSealSends, bobSends, reason: 'none from Bob either');
  });

  test(
      '21. a device whose stored seed no longer reads as one draws a new key '
      'and is heard: its contact ends holding the new key', () async {
    final (alice, _) = await fresh('alice21');
    final (bob, _) = await fresh('bob21');
    await befriend(alice, bob);
    await sealsStamped(alice, bob, 'k');
    final oldKey = alice.debugSealingKey!;

    // The app stops, and the seed it stored is damaged: 12 bytes, not 64.
    final vault = alice.vault;
    alice.dispose();
    await alice.transport.stop();
    services.remove(alice);
    await vault.kvPut('seal_seed', b64(randomBytes(12)));
    final again = await boot(vault, 'alice21');
    await waitUntil(() => up(again), what: 'alice up again');
    final newKey = again.debugSealingKey!;
    expect(newKey, isNot(oldKey), reason: 'the premise: a new key drawn');
    expect(again.debugHoldsMySealKey(bob.myRid), isFalse,
        reason: "Bob's word was for the key that went");
    again.pqOfferRetry = 300;
    bob.pqOfferRetry = 300;
    var m = 0;
    await waitFor(() async {
      await exchange(again, bob, 'after${m++}');
      return holdsKey(bob, again.myRid, newKey) &&
          again.debugHoldsMySealKey(bob.myRid);
    }, what: "Bob holding Alice's new key, and saying so");
  });

  test(
      "22. a contact whose store of a restored device's first envelope fails "
      'and is done again writes down that the device holds none of its key: '
      'after a restart it still announces it there', () async {
    final (alice, _) = await fresh('alice22');
    final (bob, bobDir) = await fresh('bob22');
    await befriend(alice, bob);
    await sealsStamped(alice, bob, 'k');
    final aliceKey = alice.debugSealingKey!;

    // Bob's phone is lost and restored; the archive carries no other
    // device's key, so the restored device holds none of Alice's. Alice's
    // next store of an envelope from him fails, as a busy vault's does.
    final (file, code) = await backup(bob, 'bob22');
    await lose(bob, bobDir);
    alice.debugFailInboundStores = 1;
    final revived = await boot(await restoreInto(bobDir, file, code), 'bob22');
    await waitUntil(() => up(revived), what: 'the restored device up');
    expect(revived.debugPqSealOf(alice.myRid), isNull,
        reason: "the premise: no key of Alice's");
    await revived.sendText(alice.myRid, 'back');
    await waitUntil(() => alice.debugFailInboundStores == 0,
        what: 'the store failing once');
    // The envelope stayed with the relay, which hands it over again when
    // her link comes back.
    await alice.transport.stop();
    await waitUntil(() => !alice.transport.isConnected,
        what: 'alice offline');
    alice.transport.start();
    await waitUntil(() => texts(alice, revived.myRid).contains('back'),
        what: "'back' delivered again");

    // Her app restarts at once, before anything else of Bob's is written.
    final again = await restart(alice, 'alice22');
    expect(again.debugHoldsMySealKey(revived.myRid), isFalse,
        reason: 'the new session forgot that he holds her key, on disk');
    again.pqOfferRetry = 300;
    revived.pqOfferRetry = 300;
    var m = 0;
    await waitFor(() async {
      await exchange(revived, again, 'after${m++}');
      return holdsKey(revived, again.myRid, aliceKey) &&
          again.debugHoldsMySealKey(revived.myRid);
    }, what: "the restored device holding Alice's key, and saying so");
  });
}
