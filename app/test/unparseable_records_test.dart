// What the app does with a record it no longer parses: one a vault already
// holds, or one an archive carries (the 2026-10-28 review's F3).
//
// Since 2026-10-28 the library's parsers throw a FormatException for a
// member of the wrong type, where a cast threw a TypeError, and a device
// list's `ver` must be a whole number: a build before that read 2.5 as 2. No
// honest client writes either. An archive written by hand under the user's
// recovery code can carry one, though, and a build before this one checked
// such a list as version 2 — a list its account had signed — and stored it
// as the archive gave it. What is tested is that a record which does not
// parse costs that record and nothing more: not the start, not another
// contact, and not the transparency log's pass.
//
// Offline, as `small_order_keys_test.dart`: every client points at a port
// nothing listens on, and envelopes are carried by hand from one client's
// outbox to the other's inbound path (`debugInbound`).
//
// Each fails with the guard it is about taken out: 1 and 2 at the start
// ('device list member "ver" is missing or not an integer') when start-up
// parses a held list unguarded; 2 at the log's pass when the service's held
// claim (`_heldClaimFor`) does; and 3 at the restored row when a restore
// keeps any certificate, and past that line at the start ('device
// certificate member "id" is missing or not a string'). On 14a5b3c each
// fails where it asserts that the library refuses the record: that build
// reads 2.5 as 2, and its certificate parser threw a TypeError. Past that
// line there, 3's start throws it.
//
// Criteria, each a test below:
//   1. a vault holding a contact's device list this build does not parse,
//      beside an honest contact, starts: the list stays in the vault as it
//      was and is not installed, so its extra device is nobody's and a
//      message to that contact goes to the device it was added from and to
//      no other; and the honest contact's messages go both ways;
//   2. such a list is read as no list wherever a held list is read: the
//      transparency log's pass lists every contact, that one at the
//      baseline; and the first message to the contact echoes the baseline,
//      so its account sends its list again, which installs in its place;
//   3. an archive whose contact record carries a certificate this build
//      does not parse restores the contact without it, and the restored
//      device starts and talks to that contact both ways.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart' show DatabaseException;
import 'package:zapp/core/archive.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/restore.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:z_protocol/z_protocol.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  final temps = <Directory>[];
  final services = <ChatService>[];

  tearDownAll(() async {
    for (final s in services) {
      await s.transport.stop();
    }
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  // Each service runs in an error zone of its own, as in
  // small_order_keys_test: a service [stop] has stopped can still have work
  // in flight, failing against the database it closed, and that error is
  // dropped. Anything else raised inside a service — a crash, at start or
  // after — is kept, and fails the test that was running.
  final stopped = <ChatService>{};
  final strays = <String>[];
  tearDown(() {
    final found = [...strays];
    strays.clear();
    expect(found, isEmpty, reason: 'errors raised inside a running service');
  });

  Future<Directory> tempDir(String name) async {
    final d = await Directory.systemTemp.createTemp('z_unparsed_$name');
    temps.add(d);
    return d;
  }

  /// A client on [dir] (a new one when null) as [id]; [before] runs on its
  /// vault before the service starts, as an earlier build's writes would
  /// have.
  Future<ChatService> start(String name,
      {Directory? dir,
      ZIdentity? id,
      Future<void> Function(Vault v)? before}) async {
    dir ??= await tempDir(name);
    final vault = await Vault.open(rootOverride: dir);
    final me = id ?? await ZIdentity.generate();
    if (await vault.kvGet('identity') == null) {
      await vault.kvPut('identity', jsonEncode(me.toJson()));
    }
    if (before != null) await before(vault);
    final ready = Completer<ChatService>();
    ChatService? made;
    runZonedGuarded(() async {
      try {
        final svc = await ChatService.init(
            vault: vault,
            identity: me,
            displayName: name,
            transport: Transport(identity: me, serverUrl: 'ws://127.0.0.1:1'));
        made = svc;
        services.add(svc);
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
    services.remove(svc);
    await svc.vault.db.close();
  }

  Future<int> carry(ChatService from, ChatService to) async {
    final rows = await from.vault.db.query('outbox',
        where: 'rid = ?', whereArgs: [to.myRid], orderBy: 'seq');
    await from.vault.db
        .delete('outbox', where: 'rid = ?', whereArgs: [to.myRid]);
    for (final r in rows) {
      await to.debugInbound(RelayInbound(
          id: r['id'] as String,
          from: '',
          payload: r['payload'] as String,
          serverTs: DateTime.now().millisecondsSinceEpoch));
    }
    return rows.length;
  }

  Future<void> settle(List<ChatService> all) async {
    for (var round = 0; round < 8; round++) {
      var moved = 0;
      for (final x in all) {
        for (final y in all) {
          if (!identical(x, y)) moved += await carry(x, y);
        }
      }
      if (moved == 0) return;
    }
  }

  Future<void> befriend(ChatService a, ChatService b) async {
    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());
    await settle([a, b]);
  }

  /// Waits on [cond] with a deadline, carrying what [all] have queued for
  /// each other between looks.
  Future<void> deliverUntil(
      List<ChatService> all, FutureOr<bool> Function() cond,
      {required String what}) async {
    final deadline = DateTime.now().add(const Duration(seconds: 30));
    while (!await cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await settle(all);
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
  }

  List<String> texts(ChatService s, String thread) => [
        for (final m in s.messagesByChat[thread] ?? const [])
          if (m.kind == 'text') m.body
      ];

  Future<void> exchange(ChatService a, ChatService b, String tag) async {
    await a.sendText(b.myRid, '$tag: to ${b.displayName}');
    await settle([a, b]);
    expect(texts(b, a.myRid), contains('$tag: to ${b.displayName}'));
    await b.sendText(a.myRid, '$tag: to ${a.displayName}');
    await settle([a, b]);
    expect(texts(a, b.myRid), contains('$tag: to ${a.displayName}'));
  }

  /// Alice, a contact of Bob's and of Carol's. Carol links a laptop, so
  /// that her list is at v2 and Alice holds it, the laptop listed as
  /// Carol's. Then Alice's vault is left as a restore by a build before this
  /// one leaves it: Carol's list stored with its `ver` 2.5. Alice starts on
  /// it.
  Future<
      ({
        ChatService alice,
        ChatService bob,
        ChatService carol,
        String laptop,
        String held,
      })> heldListUnparsed(String tag) async {
    final alice0 = await start('alice$tag');
    final bob = await start('bob$tag');
    final carol = await start('carol$tag');
    await befriend(alice0, bob);
    await befriend(alice0, carol);

    final laptop = await ZIdentity.generate();
    final laptopRid = await laptop.routingId();
    final account = await carol.accountIdentity();
    await carol.addMyDevice(await account.signDeviceCert(
        deviceEdPub: laptop.edPub,
        deviceXPub: laptop.xPub,
        deviceId: 'laptop'));
    await deliverUntil([alice0, carol],
        () => alice0.debugListedDeviceOwner(laptopRid) == carol.myRid,
        what: "Alice installs Carol's list, naming her laptop");
    expect(await alice0.heldContactListVersion(carol.myRid), 2);

    // The list Carol's account signed, its version written 2.5: a build
    // before this one read that as 2, verified it as the list it is, and
    // stored it as the archive gave it. This one does not parse it.
    final signed = (jsonDecode((await alice0.vault.kvGet('cdev_${carol.myRid}'))!)
            as Map)
        .cast<String, Object?>();
    expect(signed['ver'], 2);
    expect(await SignedDeviceList.fromJson(signed).verify(), isTrue);
    final held = jsonEncode({...signed, 'ver': 2.5});
    expect(
        () => SignedDeviceList.fromJson(
            (jsonDecode(held) as Map).cast<String, Object?>()),
        throwsFormatException);

    final dir = Directory(alice0.vault.root.path);
    final id = alice0.identity;
    await stop(alice0);
    final alice = await start('alice$tag',
        dir: dir,
        id: id,
        before: (v) =>
            v.kvPut('cdev_${carol.myRid}', held, sensitive: false));
    return (
      alice: alice,
      bob: bob,
      carol: carol,
      laptop: laptopRid,
      held: held
    );
  }

  test('1. a held list that does not parse, beside an honest contact: the '
      'app starts, the list is not installed, and both are reached',
      () async {
    final s = await heldListUnparsed('1');
    final alice = s.alice, bob = s.bob, carol = s.carol;

    // It starts, with both contacts; the list is where it was, as it was,
    // and is not installed.
    expect(alice.contacts.keys, containsAll([bob.myRid, carol.myRid]));
    expect(await alice.vault.kvGet('cdev_${carol.myRid}'), s.held,
        reason: 'the list stays in the vault as it was');
    expect(alice.debugListedDeviceOwner(s.laptop), isNull,
        reason: 'a held list that does not parse is not installed');

    // A message to Carol goes to the device she was added from and to no
    // other. The fan-out to a contact's other devices decides before its
    // first await whether there are any (`_fanToContactExtras`), so once
    // the send has returned, nothing more is queued for the laptop.
    Future<int> forLaptop() async => (await alice.vault.db
            .query('outbox', where: 'rid = ?', whereArgs: [s.laptop]))
        .length;
    final queued = await forLaptop();
    await alice.sendText(carol.myRid, 'to the phone');
    expect(await forLaptop(), queued,
        reason: 'nothing is queued for a device the list named');
    await settle([alice, carol]);
    expect(texts(carol, alice.myRid), contains('to the phone'));

    // The honest contact's messages go both ways.
    await exchange(alice, bob, 'after the upgrade');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('2. it is read as no list: the log pass reads the baseline, and the '
      "account's next list takes its place", () async {
    final s = await heldListUnparsed('2');
    final alice = s.alice, bob = s.bob, carol = s.carol;

    // The transparency log's pass reads every contact: Carol's at the
    // baseline — version 1, no list — and Bob's as it was.
    final inputs = {for (final c in await alice.ktContacts()) c.rid: c};
    expect(inputs.keys, containsAll([bob.myRid, carol.myRid]));
    expect(inputs[carol.myRid]!.held, isNull);
    expect(inputs[carol.myRid]!.heldVersion, 1);
    expect(inputs[bob.myRid]!.heldVersion, 1);
    expect(await alice.heldContactListVersion(carol.myRid), 1);

    // Alice's next message echoes that baseline to Carol, whose account is
    // at v2: she sends her list again, and it installs in place of the one
    // that did not parse.
    await alice.sendText(carol.myRid, 'hello again');
    await deliverUntil([alice, carol],
        () => alice.debugListedDeviceOwner(s.laptop) == carol.myRid,
        what: "Carol's list, sent again, installs at Alice");
    expect(texts(carol, alice.myRid), contains('hello again'));
    expect(await alice.heldContactListVersion(carol.myRid), 2);
    final now = (jsonDecode((await alice.vault.kvGet('cdev_${carol.myRid}'))!)
            as Map)
        .cast<String, Object?>();
    expect(now['ver'], 2, reason: 'the list held is the one that arrived');
    await exchange(alice, bob, 'and Bob');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('3. an archive whose contact carries a certificate that does not '
      'parse restores the contact without it, and starts', () async {
    final aliceDir = await tempDir('alice3');
    final alice = await start('alice3', dir: aliceDir);
    final bob = await start('bob3');
    await befriend(alice, bob);
    await exchange(alice, bob, 'before the backup');

    // The archive Alice's vault exports with Bob's certificate replaced by
    // one whose id is a number: no build writes that, and an archive written
    // by hand can carry it. The restore reads what the archive says.
    final cert = {
      ...(await bob.accountIdentity()).deviceCert.toJson(),
      'id': 7,
    };
    expect(() => DeviceCertificate.fromJson(cert), throwsFormatException);
    await alice.vault.db.update('contacts', {'dev_cert': jsonEncode(cert)},
        where: 'rid = ?', whereArgs: [bob.myRid]);
    final code = await RecoveryCode.generate();
    final file = File(
        '${(await tempDir('alice3_zbk')).path}${Platform.pathSeparator}b.zbk');
    final sink = file.openWrite();
    await BackupArchive.export(vault: alice.vault, code: code, out: sink);
    await sink.close();
    final id = alice.identity;
    await stop(alice);

    // A fresh install restores it the way the onboarding screen does.
    final dir = await tempDir('alice3_restored');
    final vault = await Vault.open(rootOverride: dir);
    await Restore.run(
        vault: vault,
        file: file,
        secret: await code.format(),
        kind: (await Restore.identify(file)).kind);
    final row = (await vault.db
            .query('contacts', where: 'rid = ?', whereArgs: [bob.myRid]))
        .single;
    expect(row['dev_cert'], isNull,
        reason: 'a certificate that does not parse is not restored');
    await vault.db.close();

    // The next start, which reads every contact's certificate.
    final revived = await start('alice3', dir: dir, id: id);
    expect(revived.contacts[bob.myRid], isNotNull,
        reason: 'the contact is restored');
    expect(revived.contacts[bob.myRid]!.deviceCert, isNull);
    await exchange(revived, bob, 'after the restore');
  }, timeout: const Timeout(Duration(minutes: 3)));
}
