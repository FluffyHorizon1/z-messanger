// What the app does with an Ed25519 key of small order (the 2026-10-28
// review's F1): the two doors that let one in without anything tampered with
// at a scan — a group's member list (§11) and an inbound contact request
// (§8.1) — and the contact a vault from before this release may hold.
//
// The key below is the point of order 2, and every signature "by" it is R the
// identity and S = 0, which the library's lenient verifier takes over any
// message: what both doors asked, through `ContactBundle.verify` and
// `ContactRequest.verify`, until this release. The member, the requester and
// the stored contact each hold a genuine X25519 key, so nothing sealed to
// them is open to all. What the key gave away is that anybody could speak as
// them — sign their binding, their requests, their account's device lists —
// and through those lists add devices of their own to what the receiver fans
// out to them, a group's messages among it.
//
// Offline: every client points at a port nothing listens on, and envelopes
// are carried by hand from one client's outbox to the other's inbound path
// (`debugInbound`), as `malformed_inner_test.dart` does; what a receiver
// acknowledges is recorded by its transport.
//
// Run against 14a5b3c, each criterion fails there — the member is added, the
// request held, the stored list installed and the forged acceptance taken —
// on the first of those it asserts. What the honest contacts do is asserted
// beside it, and holds on both.
//
// Criteria, each a test below:
//   1. a group's member list naming a member whose key is of small order is
//      taken without them: the group is held, its sender and its honest
//      member are members, the one of small order is neither a member nor a
//      contact, and the group's messages go on;
//   2. a contact request from such a key is acknowledged and held as
//      nothing, and an honest stranger's request after it is held;
//   3. a vault holding such a contact — and the device list a build before
//      this one installed for it — beside an honest contact starts; the held
//      list is not installed, so its extra device is no one's; the honest
//      contact's messages go both ways; a forged acceptance from the key is
//      acknowledged and changes nothing; and a group list naming it again is
//      taken without it.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' show X25519;
import 'package:flutter_test/flutter_test.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart' show DatabaseException;
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:z_protocol/z_protocol.dart';

/// A transport that records every envelope id it was asked to acknowledge.
class _AckSpy extends Transport {
  _AckSpy(ZIdentity id) : super(identity: id, serverUrl: 'ws://127.0.0.1:1');
  final acked = <String>[];
  @override
  void ackReceived({required String id, required String from}) {
    acked.add(id);
    super.ackReceived(id: id, from: from);
  }
}

/// R the identity, S = 0: under the key below, the library's verifier takes
/// it over any message.
final Uint8List _forged = Uint8List(64)..[0] = 1;

/// The Ed25519 point of order 2.
final Uint8List _order2 = Uint8List.fromList(
    [0xec, for (var i = 0; i < 30; i++) 0xff, 0x7f]);

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
  // devlist_pq_suppression_test: a service [stop] has stopped can still have
  // work in flight, failing against the database it closed, and that error
  // is dropped. Anything else raised inside a service — a crash, at start or
  // after — is kept, and fails the test that was running.
  final stopped = <ChatService>{};
  final strays = <String>[];
  tearDown(() {
    final found = [...strays];
    strays.clear();
    expect(found, isEmpty, reason: 'errors raised inside a running service');
  });

  /// A client on [dir] (a new one when null) as [id]; [before] runs on its
  /// vault before the service starts, as an earlier build's writes would
  /// have.
  Future<(ChatService, _AckSpy)> start(String name,
      {Directory? dir,
      ZIdentity? id,
      Future<void> Function(Vault v)? before}) async {
    dir ??= await Directory.systemTemp.createTemp('z_small_$name');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    final me = id ?? await ZIdentity.generate();
    if (await vault.kvGet('identity') == null) {
      await vault.kvPut('identity', jsonEncode(me.toJson()));
    }
    if (before != null) await before(vault);
    final spy = _AckSpy(me);
    final ready = Completer<ChatService>();
    ChatService? made;
    runZonedGuarded(() async {
      try {
        final svc = await ChatService.init(
            vault: vault, identity: me, displayName: name, transport: spy);
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
    return (await ready.future, spy);
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
  /// each other between looks — a group's list and its messages leave
  /// through its fan-out queue, a step ahead of the outbox.
  Future<void> deliverUntil(List<ChatService> all, bool Function() cond,
      {required String what}) async {
    final deadline = DateTime.now().add(const Duration(seconds: 30));
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      for (final s in all) {
        await s.drainGroupFanoutForTest();
      }
      await settle(all);
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
  }

  List<String> texts(ChatService s, String thread, String kind) => [
        for (final m in s.messagesByChat[thread] ?? const [])
          if (m.kind == kind) m.body
      ];

  /// A "person" whose identity key is the point of order 2: a genuine X25519
  /// key, and a binding "signed" with R the identity and S = 0.
  Future<ContactBundle> smallOrderPerson(String name) async {
    final x = await (await X25519().newKeyPairFromSeed(randomBytes(32)))
        .extractPublicKey();
    return ContactBundle(
        edPub: _order2,
        xPub: Uint8List.fromList(x.bytes),
        bindingSig: _forged,
        displayName: name);
  }

  /// [b] as a contact row, written the way the app writes one — what a build
  /// before this release left in the vault of anyone it reached through a
  /// group's list or a request.
  Future<void> holdContact(Vault v, ContactBundle b,
      {bool requested = false}) async {
    await v.db.insert('contacts', {
      'rid': await b.routingId(),
      'enc_bundle': await v.seal(jsonEncode(b.toJson())),
      'enc_name': await v.seal(b.displayName ?? 'Unknown'),
      'ttl_seconds': 0,
      'verified': 0,
      'created_ms': DateTime.now().millisecondsSinceEpoch,
      'requested': requested ? 1 : 0,
    });
  }

  /// A contact request "from" [b], sealed to [to] as from [b]'s routing id,
  /// and handed to [to] as the relay would.
  Future<String> requestFrom(ContactBundle b, ChatService to,
      {required String id}) async {
    final req = ContactRequest(
        bundle: b,
        toRid: to.myRid,
        ts: DateTime.now().millisecondsSinceEpoch,
        sig: _forged);
    final blob = await SealedEnvelope.seal(
        toXPub: to.identity.xPub,
        fromRid: await b.routingId(),
        payload: req.encode());
    await to.debugInbound(RelayInbound(
        id: id,
        from: '',
        payload: blob,
        serverTs: DateTime.now().millisecondsSinceEpoch));
    return id;
  }

  test('1. a group list naming a member of small order is taken without them',
      () async {
    final (alice, _) = await start('alice');
    final (bob, _) = await start('bob');
    final (carol, _) = await start('carol');
    await befriend(alice, bob);
    await befriend(bob, carol); // Alice and Carol have never met
    final mallory = await smallOrderPerson('Mallory');
    final malRid = await mallory.routingId();
    // Bob's vault holds Mallory, as a build before this one would have taken
    // them in; his list carries every member's bundle as he holds it.
    await holdContact(bob.vault, mallory);
    await bob.reloadContacts();
    expect(bob.contacts[malRid], isNotNull);

    final gid =
        await bob.createGroup('Trio', [alice.myRid, carol.myRid, malRid]);
    await deliverUntil([alice, bob, carol],
        () => alice.groups[gid] != null && carol.groups[gid] != null,
        what: 'the list reaches Alice and Carol');

    final g = alice.groups[gid]!;
    expect(g.memberRids, isNot(contains(malRid)),
        reason: 'a member whose key is of small order is not taken in');
    expect(alice.contacts[malRid], isNull,
        reason: 'nor added as a contact');
    expect(g.memberRids, containsAll([bob.myRid, carol.myRid]),
        reason: 'the rest of the list applies');
    expect(alice.contacts[carol.myRid], isNotNull,
        reason: 'an honest member is taken in as the list says');

    await bob.sendGroupText(gid, 'hello group');
    await deliverUntil([alice, bob, carol],
        () =>
            texts(alice, gid, 'gtext').contains('hello group') &&
            texts(carol, gid, 'gtext').contains('hello group'),
        what: "Bob's group message reaches both");
    await alice.sendGroupText(gid, 'hi from alice');
    await deliverUntil([alice, bob, carol],
        () => texts(carol, gid, 'gtext').contains('hi from alice'),
        what: "Alice's group message reaches Carol");
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('2. a contact request from a key of small order is acknowledged and '
      'held as nothing', () async {
    final (alice, aliceSpy) = await start('alice');
    final (carol, _) = await start('carol');
    final mallory = await smallOrderPerson('Mallory');
    final malRid = await mallory.routingId();

    final id = await requestFrom(mallory, alice, id: 'small-order-request');
    expect(aliceSpy.acked, contains(id),
        reason: 'the envelope is acknowledged, not left wedging the mailbox');
    expect(alice.requestsByRid.containsKey(malRid), isFalse,
        reason: 'the request is refused');
    expect(alice.contacts[malRid], isNull);

    // An honest stranger's request after it is held, as it always was.
    await carol.addContactFromCode(await alice.myContactCode());
    await carry(carol, alice);
    expect(alice.requestsByRid.containsKey(carol.myRid), isTrue);
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('3. a stored contact of small order beside an honest one: the app '
      'starts, refuses it where it is read, and the honest one works',
      () async {
    final (alice0, _) = await start('alice');
    final (bob, _) = await start('bob');
    await befriend(alice0, bob);
    await bob.sendText(alice0.myRid, 'before the upgrade');
    await settle([alice0, bob]);
    expect(texts(alice0, bob.myRid, 'text'), contains('before the upgrade'));

    // What a build before this release left: Mallory, waiting on an answer
    // to Alice's request, and the device list it installed for them — every
    // signature R the identity and S = 0 under their key — naming a second
    // device of anyone's choosing.
    final mallory = await smallOrderPerson('Mallory');
    final malRid = await mallory.routingId();
    final stranger = await ZIdentity.generate();
    final strangerRid = await stranger.routingId();
    final heldList = SignedDeviceList(
      accountEdPub: _order2,
      version: 2,
      devices: [
        DeviceCertificate(
            deviceEdPub: _order2,
            deviceXPub: mallory.xPub,
            deviceId: 'm1',
            sig: _forged),
        DeviceCertificate(
            deviceEdPub: stranger.edPub,
            deviceXPub: stranger.xPub,
            deviceId: 'm2',
            sig: _forged),
      ],
      sig: _forged,
      sig2: _forged,
    );
    final aliceDir = Directory(alice0.vault.root.path);
    final aliceId = alice0.identity;
    await stop(alice0);

    final (alice, aliceSpy) = await start('alice',
        dir: aliceDir, id: aliceId, before: (v) async {
      await holdContact(v, mallory, requested: true);
      await v.kvPut('cdev_$malRid', jsonEncode(heldList.toJson()),
          sensitive: false);
      await v.kvPut('cdev_ver_$malRid', '2', sensitive: false);
    });
    // It starts, with both contacts.
    expect(alice.contacts.keys, containsAll([bob.myRid, malRid]));
    expect(alice.contacts[malRid]!.requested, isTrue);
    // The held list is not installed: its second device is nobody's here,
    // and nothing Alice sends Mallory goes to it.
    expect(alice.debugListedDeviceOwner(strangerRid), isNull,
        reason: 'a list held under a key of small order is not installed');

    // The honest contact's messages go both ways.
    await bob.sendText(alice.myRid, 'after the upgrade');
    await settle([alice, bob]);
    expect(texts(alice, bob.myRid, 'text'), contains('after the upgrade'));
    await alice.sendText(bob.myRid, 'and back');
    await settle([alice, bob]);
    expect(texts(bob, alice.myRid, 'text'), contains('and back'));

    // A forged "acceptance" from Mallory's key: acknowledged, and nothing
    // changes — Alice's request to them is still waiting.
    final id = await requestFrom(mallory, alice, id: 'forged-acceptance');
    expect(aliceSpy.acked, contains(id),
        reason: 'the envelope is acknowledged, not left wedging the mailbox');
    expect(alice.contacts[malRid]!.requested, isTrue,
        reason: 'a forged acceptance does not answer the request');

    // A group list naming them again, from the honest contact, is taken
    // without them; the group works.
    await holdContact(bob.vault, mallory);
    await bob.reloadContacts();
    final gid = await bob.createGroup('Pair', [alice.myRid, malRid]);
    await deliverUntil([alice, bob], () => alice.groups[gid] != null,
        what: 'the list reaches Alice');
    expect(alice.groups[gid]!.memberRids, isNot(contains(malRid)));
    expect(alice.groups[gid]!.memberRids, contains(bob.myRid));
    await bob.sendGroupText(gid, 'pair hello');
    await deliverUntil([alice, bob],
        () => texts(alice, gid, 'gtext').contains('pair hello'),
        what: "Bob's group message reaches Alice");
    expect(alice.contacts.keys, containsAll([bob.myRid, malRid]),
        reason: 'and the contact itself is where it was');
  }, timeout: const Timeout(Duration(minutes: 3)));
}
