// The client, read by strangers: the fixes for what four independent reviews
// found (2026-09-12). Each criterion here fails against 2.8.3.
//
// The relay's code had been written and reviewed in one context for five
// releases, and an independent review of it found three real bugs. The same
// argument applied harder to the client — more code, more releases, no
// stranger had ever read it — so four adversarial reviews were run in
// parallel. Every criterion below is a P0 they found and this session
// reproduced before fixing.
//
// The pattern in all of them is one thing: a claim that was true of the
// configuration it was tested in and false of the one that ships. The
// revocation test revoked the account's ONLY device, where the bug is masked.
// `myRid` is the account's routing id on the device the tests run on, and
// something else on every linked device. The backup flags were a platform
// default nobody had written down.
//
// Criteria, each asserted below:
//  1. a device revoked from my account receives no further mirror, and the
//     sync session forgets it rather than restoring it from disk — the
//     add-only restore meant a stolen, revoked laptop kept reading
//     everything the account sent and received, across restarts;
//  2. a linked device keeps its group membership when the group's membership
//     changes, and does not count my own account's devices as members —
//     comparing the invite against this install's routing id told every
//     secondary device it had been removed at the first change;
//  3. a mirror that could not be stored leaves the sync ratchet where it was,
//     so the relay's redelivery still decrypts — the acknowledgement now
//     waits for the store (see `ChatService._onInbound`), and without the
//     rollback that would strand the message instead;
//  4. a session this device has retired is not re-created by its own opening
//     envelope arriving again — after an explicit reset, and after a stale
//     session is pruned;
//  5. every file-picker call site deletes the picker's plaintext copy: the
//     picker hands over a copy of the chosen file in the app's cache
//     directory, outside the vault, which nothing used to delete.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/device_sync.dart';
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

  Future<Directory> tempDir(String name) async {
    final dir = await Directory.systemTemp.createTemp('z_p0_$name');
    temps.add(dir);
    return dir;
  }

  Future<ChatService> makeClient(String name,
      {ZIdentity? identity, Directory? dir}) async {
    dir ??= await tempDir(name);
    final vault = await Vault.open(rootOverride: dir);
    identity ??= await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(identity.toJson()));
    final svc = await ChatService.init(
      vault: vault,
      identity: identity,
      displayName: name,
      transport: Transport(identity: identity, serverUrl: 'ws://127.0.0.1:1'),
    );
    services.add(svc);
    return svc;
  }

  Future<List<Map<String, Object?>>> outboxFor(ChatService s, String rid) =>
      s.vault.db.query('outbox', where: 'rid = ?', whereArgs: [rid]);

  Future<void> carry(ChatService from, ChatService to) async {
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
  }

  // ---------------------------------------------------------------------
  test('1. a device revoked from my account gets no further mirror', () async {
    final me = await makeClient('root');
    final contact = await makeClient('contact');
    await me.addContactFromCode(await contact.myContactCode());

    // TWO linked devices, which is what the old test lacked: with only one,
    // removing it leaves the account with none and the sync channel is torn
    // down wholesale, masking the bug.
    final account = await me.accountIdentity();
    final laptopId = await ZIdentity.generate();
    final tabletId = await ZIdentity.generate();
    final laptopCert = await account.signDeviceCert(
        deviceEdPub: laptopId.edPub, deviceXPub: laptopId.xPub, deviceId: 'lt');
    final tabletCert = await account.signDeviceCert(
        deviceEdPub: tabletId.edPub, deviceXPub: tabletId.xPub, deviceId: 'tb');
    await me.addMyDevice(laptopCert);
    await me.addMyDevice(tabletCert);
    final laptopRid = await laptopId.routingId();
    final tabletRid = await tabletId.routingId();

    await me.sendText(contact.myRid, 'before the laptop was stolen');
    await Future<void>.delayed(const Duration(milliseconds: 300));
    expect(await outboxFor(me, laptopRid), isNotEmpty,
        reason: 'the laptop is mirrored to while it is mine');

    await me.removeMyDevice(laptopCert);
    await me.vault.db.delete('outbox');

    await me.sendText(contact.myRid, 'after the laptop was revoked');
    await Future<void>.delayed(const Duration(milliseconds: 300));
    expect(await outboxFor(me, laptopRid), isEmpty,
        reason: 'a revoked device is not a target of the self-sync fan');
    expect(await outboxFor(me, tabletRid), isNotEmpty,
        reason: 'the device I still hold is unaffected');

    // And it survives a restart: the stored session is what used to bring the
    // revoked device back, because restoring it only ever added targets.
    final restarted = await ChatService.init(
      vault: me.vault,
      identity: me.identity,
      displayName: 'root',
      transport: Transport(identity: me.identity, serverUrl: 'ws://127.0.0.1:1'),
    );
    services.add(restarted);
    await restarted.vault.db.delete('outbox');
    await restarted.sendText(contact.myRid, 'after a restart');
    await Future<void>.delayed(const Duration(milliseconds: 300));
    expect(await outboxFor(restarted, laptopRid), isEmpty,
        reason: 'the revoked device is not restored from sync_session');
    expect(await outboxFor(restarted, tabletRid), isNotEmpty);
  });

  // ---------------------------------------------------------------------
  test('2. a linked device keeps its group membership when the group changes',
      () async {
    // Bob's account has a phone (the root) and a laptop. Alice admins a group
    // holding Bob and Carol, then adds Dave.
    final alice = await makeClient('alice');
    final bob = await makeClient('bob');
    final carol = await makeClient('carol');
    final dave = await makeClient('dave');
    for (final other in [bob, carol, dave]) {
      await alice.addContactFromCode(await other.myContactCode());
      await other.addContactFromCode(await alice.myContactCode());
      await carry(alice, other);
      await carry(other, alice);
    }

    // Bob links a laptop, and the laptop knows the root device.
    final bobAccount = await bob.accountIdentity();
    final laptopId = await ZIdentity.generate();
    final laptopCert = await bobAccount.signDeviceCert(
        deviceEdPub: laptopId.edPub, deviceXPub: laptopId.xPub, deviceId: 'lt');
    await bob.addMyDevice(laptopCert);
    // Alice must learn Bob's device list, or her invite never fans to his
    // laptop at all and the test would prove nothing.
    await carry(bob, alice);
    final lapDir = await tempDir('laptop');
    final lapVault = await Vault.open(rootOverride: lapDir);
    await lapVault.kvPut('identity', jsonEncode(laptopId.toJson()));
    await lapVault.kvPut(
        'account',
        jsonEncode((await AccountIdentity.fromEnrollment(
          accountEdPub: bobAccount.accountEdPub,
          accountMlPub: bobAccount.accountMlPub,
          deviceEdSeed: laptopId.edSeed,
          deviceXSeed: laptopId.xSeed,
          deviceId: 'lt',
          deviceCert: laptopCert,
        ))
            .toJson()));
    await lapVault.kvPut(
        'my_devices', jsonEncode([bobAccount.deviceCert.toJson()]),
        sensitive: false);
    final laptop = await makeClient('bob-laptop',
        identity: laptopId, dir: null); // placeholder, replaced below
    services.remove(laptop);
    await laptop.transport.stop();
    final lap = await ChatService.init(
      vault: lapVault,
      identity: laptopId,
      displayName: 'bob-laptop',
      transport: Transport(identity: laptopId, serverUrl: 'ws://127.0.0.1:1'),
    );
    services.add(lap);
    // The laptop knows alice, so an invite from her is authorised.
    await lap.addContactFromCode(await alice.myContactCode());

    final gid = await alice.createGroup(
        'trip', [bob.myRid, carol.myRid]);
    await carry(alice, bob);
    await carry(alice, carol);
    // The laptop receives the invite as a contact's message would arrive.
    final inviteRows = await alice.vault.db.query('outbox',
        where: 'rid = ?', whereArgs: [await laptopId.routingId()]);
    for (final r in inviteRows) {
      await lap.debugInbound(RelayInbound(
          id: r['id'] as String,
          from: '',
          payload: r['payload'] as String,
          serverTs: DateTime.now().millisecondsSinceEpoch));
    }

    expect(lap.groups[gid], isNotNull, reason: 'the laptop holds the group');
    expect(lap.groups[gid]!.left, isFalse);
    expect(lap.groups[gid]!.memberRids.contains(bob.myRid), isFalse,
        reason: 'my own account is not a member of my own group');

    // Alice adds Dave: version 2 of the same group.
    await alice.addGroupMembers(gid, [dave.myRid]);
    final addRows = await alice.vault.db.query('outbox',
        where: 'rid = ?', whereArgs: [await laptopId.routingId()]);
    for (final r in addRows) {
      await lap.debugInbound(RelayInbound(
          id: r['id'] as String,
          from: '',
          payload: r['payload'] as String,
          serverTs: DateTime.now().millisecondsSinceEpoch));
    }
    expect(lap.groups[gid]!.left, isFalse,
        reason: 'the laptop was never removed from anything');
  });

  // ---------------------------------------------------------------------
  test('3. a mirror that could not be stored leaves the ratchet where it was',
      () async {
    // Two devices of one account, talking over the self-sync channel.
    final account = await AccountIdentity.generate();
    final oneId = await ZIdentity.generate();
    final twoId = await ZIdentity.generate();
    final oneCert = await account.signDeviceCert(
        deviceEdPub: oneId.edPub, deviceXPub: oneId.xPub, deviceId: 'one');
    final twoCert = await account.signDeviceCert(
        deviceEdPub: twoId.edPub, deviceXPub: twoId.xPub, deviceId: 'two');
    final oneAcct = await AccountIdentity.fromEnrollment(
        accountEdPub: account.accountEdPub,
        accountMlPub: account.accountMlPub,
        deviceEdSeed: oneId.edSeed,
        deviceXSeed: oneId.xSeed,
        deviceId: 'one',
        deviceCert: oneCert);
    final twoAcct = await AccountIdentity.fromEnrollment(
        accountEdPub: account.accountEdPub,
        accountMlPub: account.accountMlPub,
        deviceEdSeed: twoId.edSeed,
        deviceXSeed: twoId.xSeed,
        deviceId: 'two',
        deviceCert: twoCert);

    final sent = <String>[];
    final oneVault = await Vault.open(rootOverride: await tempDir('sync1'));
    final twoVault = await Vault.open(rootOverride: await tempDir('sync2'));
    final one = DeviceSyncService(
        vault: oneVault,
        reliableSend: (to, payload) async => sent.add(payload),
        account: oneAcct,
        myDevices: [twoCert]);
    final two = DeviceSyncService(
        vault: twoVault,
        reliableSend: (to, payload) async {},
        account: twoAcct,
        myDevices: [oneCert]);
    await one.init();
    await two.init();

    final oneRid = await oneId.routingId();
    sent.clear();
    await one.mirror(
        threadRid: 'thread',
        dir: 'in',
        inner: InnerMessage(
            kind: 'text',
            mid: newMessageId(),
            ts: DateTime.now().millisecondsSinceEpoch,
            data: {'b': 'hi'}));
    expect(sent, isNotEmpty, reason: 'the mirror went out');
    final payload = sent.last;

    final first = await two.handleInbound(oneRid, payload);
    expect(first.mirrored, isNotNull, reason: 'the mirror decrypted');
    expect(first.snapshot, isNotNull,
        reason: 'the caller is handed what it needs to roll back');

    // The store failed: roll the ratchet back and do not acknowledge.
    await two.restore(first.snapshot!);
    final again = await two.handleInbound(oneRid, payload);
    expect(again.mirrored, isNotNull,
        reason: 'the relay redelivers, and after the rollback it decrypts');
    expect(again.mirrored!.inner.data['b'], 'hi',
        reason: 'and it is the same message');

    // Without a rollback the same envelope is spent, which is why the
    // acknowledgement must wait for the store.
    final third = await two.handleInbound(oneRid, payload);
    expect(third.mirrored, isNull,
        reason: 'a second delivery on an advanced ratchet does not decrypt');
  });

  // ---------------------------------------------------------------------
  test('4. a retired session is not re-created by its own opening envelope',
      () async {
    Uint8List b(String s) => Uint8List.fromList(utf8.encode(s));
    final alice = await ZIdentity.generate();
    final bob = await ZIdentity.generate();

    // --- after an explicit reset ---
    var a = await Conversation.create(alice, await bob.bundle());
    var bConv = await Conversation.create(bob, await alice.bundle());
    final captured = [
      await a.encrypt(b('one')),
      await a.encrypt(b('two')),
    ];
    for (final p in captured) {
      await bConv.decrypt(p);
    }
    bConv.resetSessions();
    for (final p in captured) {
      await expectLater(bConv.decrypt(p), throwsA(isA<RatchetDecryptException>()),
          reason: 'a replayed opener must not re-create the session');
    }
    expect(bConv.retiredSids, isNotEmpty);

    // --- and it survives being written out and read back ---
    final reloaded = await Conversation.fromJson(bob, bConv.toJson());
    await expectLater(
        reloaded.decrypt(captured.first), throwsA(isA<RatchetDecryptException>()),
        reason: 'the retired ids are persisted with the conversation');

    // --- after a stale session is pruned ---
    a = await Conversation.create(alice, await bob.bundle());
    bConv = await Conversation.create(bob, await alice.bundle());
    final opener = await a.encrypt(b('from alice'));
    await bConv.decrypt(opener);
    await bConv.encrypt(b('from bob')); // bob's own session is the outbound one
    final outboundBefore = bConv.outboundSid;
    bConv.pruneStaleSessions(
        DateTime.now().millisecondsSinceEpoch + 8 * 24 * 3600 * 1000);
    await expectLater(
        bConv.decrypt(opener), throwsA(isA<RatchetDecryptException>()),
        reason: 'the opener of a pruned session cannot bring it back');
    expect(bConv.outboundSid, outboundBefore,
        reason: 'and so cannot be pinned as "the peer lost its state"');

    // The bound holds: the list does not grow without limit.
    for (var i = 0; i < Conversation.maxRetiredSids + 10; i++) {
      final conv = await Conversation.create(alice, await bob.bundle());
      final p = await conv.encrypt(b('x'));
      await bConv.decrypt(p);
      bConv.resetSessions();
    }
    expect(bConv.retiredSids.length, Conversation.maxRetiredSids);
  });

  // ---------------------------------------------------------------------
  test('5. every file-picker call site deletes the picker\'s plaintext copy',
      () async {
    // The picker does not hand over the file the user chose: it copies it
    // into the app's cache directory, outside the vault, and returns that.
    // Nothing deleted the copy, so every attachment ever sent was left in
    // the clear for as long as the OS kept the cache — through the sweeper,
    // the disappearing-message timer and "reset identity" alike. A source
    // check rather than a mock, because what matters is that no call site
    // anywhere is missing the clear (the same shape as the relay suite's
    // "server code contains no disk-write calls").
    final lib = Directory('lib');
    expect(lib.existsSync(), isTrue, reason: 'run from app/');
    final offenders = <String>[];
    var clears = 0;
    for (final f in lib
        .listSync(recursive: true)
        .whereType<File>()
        .where((f) => f.path.endsWith('.dart'))) {
      final src = f.readAsStringSync();
      clears += RegExp(r'clearTemporaryFiles\(').allMatches(src).length;
      if (RegExp(r'\bpickFiles\(').hasMatch(src) &&
          !src.contains('clearTemporaryFiles(')) {
        offenders.add(f.path);
      }
    }
    expect(offenders, isEmpty,
        reason: 'these pick files and never clear the picker cache');
    expect(clears, greaterThanOrEqualTo(2),
        reason: 'the per-pick clear and the one-off sweep at startup');
  });
}
