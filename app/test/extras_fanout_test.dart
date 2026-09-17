// M4 — the copy of a message that goes to a contact's OTHER devices.
//
// A contact with a phone and a laptop gets every message twice over from
// the sender: once to the phone on the pairwise session, once to the laptop
// on the extra-device session. The laptop copy used to be a direct
// `transport.send` inside the per-conversation lock: with the link down it
// threw and was swallowed (the laptop got the message later, from the
// phone's mirror, which is why nobody noticed), and with the link stalled
// it held the lock for the relay's 20-second ack timeout per device while
// every other send and receive for that contact waited behind it. It goes
// through the durable outbox now, like the phone's copy.
//
// No relay: the contact announces its second device through its outbox,
// which the test hands to the sender directly (`debugInbound`).
//
// The same shape had two smaller relatives: the 7.7a removal notice to a
// device a contact's list dropped — the whole of what tells a silently
// excluded device it was excluded — and the post-quantum key offer to a
// contact's extra device. Both were direct sends; both go through the
// outbox now.
//
// Exit criteria:
//   1. a text to a two-device contact leaves TWO envelopes in the sender's
//      outbox, one per device, whether or not the link is up — a down link
//      loses neither;
//   2. with the link stalled — a transport whose sends never return — a
//      second message to the same contact is accepted at once: the
//      conversation lock is not held across the network;
//   3. the removal notice to a device the contact's list dropped is an
//      outbox row with the link down, not a send that never happened;
//   4. the post-quantum key offer answered to a contact's extra device is an
//      outbox row too;
//   5. what was queued for a device the contact's list then dropped is not
//      delivered to it — the durable outbox must not turn a down link into
//      a delivery after the fact; only the removal notice remains;
//   6. the same for my own devices: removing one drops what was queued for
//      it on the self-sync channel.
//
// Two more, from the 2026-09-14 review. Everything above is about the SEND
// to a contact's other device. The receive from one had a single
// `catch (_) {}` over the decrypt, the session store and the parse, and
// acknowledged afterwards either way — so the two failures that want
// opposite answers got the same one, silence:
//
//   7. a chain that no longer agrees with that device's is reported, once,
//      with the hello that repairs it — it used to be an acknowledged
//      envelope, no row and no repair, so a contact's laptop went quiet for
//      good;
//   8. a session store that FAILS loses nothing: the envelope is left with
//      the relay and the ratchet put back, so the redelivery decrypts and the
//      message lands. It used to advance the ratchet in memory, fail to write
//      it down, and acknowledge — the relay forgetting a message that was
//      never stored, on a session that had moved on.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:z_protocol/z_protocol.dart';

/// A link that records what was acknowledged. Leaving an envelope with the
/// relay is half of what a failed store must do, and it is not observable
/// from the message list: without this a test that redelivers by hand passes
/// whether or not the acknowledgement went out — which is exactly what
/// happened the first time criterion 8 was written.
class AckSpy extends Transport {
  AckSpy({required super.identity}) : super(serverUrl: 'ws://127.0.0.1:1');
  final acked = <String>[];
  @override
  void ackReceived({required String id, required String from}) {
    acked.add(id);
    super.ackReceived(id: id, from: from);
  }
}

/// A link that looks up but never answers: every send waits for ever.
class StalledTransport extends Transport {
  StalledTransport({required super.identity})
      : super(serverUrl: 'ws://127.0.0.1:1');
  final hung = <Completer<void>>[];
  @override
  bool get isConnected => true;
  @override
  Future<void> send(
      {required String to, required String id, required String payload}) {
    final c = Completer<void>();
    hung.add(c);
    return c.future;
  }
}

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

  Future<ChatService> makeClient(String name,
      {Transport? transport, ZIdentity? identity}) async {
    final dir = await Directory.systemTemp.createTemp('z_extras_$name');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    identity ??= await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(identity.toJson()));
    final svc = await ChatService.init(
      vault: vault,
      identity: identity,
      displayName: name,
      transport: transport ??
          Transport(identity: identity, serverUrl: 'ws://127.0.0.1:1'),
    );
    services.add(svc);
    return svc;
  }

  Future<List<Map<String, Object?>>> outbox(ChatService a) =>
      a.vault.db.query('outbox', orderBy: 'seq');

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

  /// A sender who knows a contact with two devices. Returns the laptop's
  /// routing id, its keys and its certificate, for the tests that go on to
  /// run the laptop. The link is whatever [transport] says it is.
  Future<(ChatService, ChatService, String, ZIdentity, DeviceCertificate)>
      twoDeviceContactFull(
          {Transport? transport,
          ZIdentity? aIdentity,
          ZIdentity? laptopId}) async {
    final a = await makeClient('a', transport: transport, identity: aIdentity);
    final b = await makeClient('b');
    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());
    // A settled session, so the copies below are ordinary messages.
    await carry(a, b);
    await carry(b, a);
    await a.sendText(b.myRid, 'hello');
    await carry(a, b);
    await b.sendText(a.myRid, 'hello back');
    await carry(b, a);
    await a.vault.db.delete('outbox');

    // b links a laptop and tells its contacts.
    final laptop = laptopId ?? await ZIdentity.generate();
    final account = await b.accountIdentity();
    final cert = await account.signDeviceCert(
        deviceEdPub: laptop.edPub, deviceXPub: laptop.xPub, deviceId: 'lt');
    await b.addMyDevice(cert);
    await carry(b, a);
    // a re-offers its post-quantum key to the account now that it has a new
    // device (§18.2), a moment later; let that go before the outbox is
    // cleared, so what the tests count is only what they caused.
    while (a.pqSendPending) {
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
    await Future<void>.delayed(const Duration(milliseconds: 50));
    await a.vault.db.delete('outbox'); // whatever a said back is not the point
    return (a, b, await laptop.routingId(), laptop, cert);
  }

  Future<(ChatService a, ChatService b, String laptopRid)> twoDeviceContact(
      {Transport? transport}) async {
    final r = await twoDeviceContactFull(transport: transport);
    return (r.$1, r.$2, r.$3);
  }

  /// The laptop as a running client of b's account, offline, knowing a.
  Future<ChatService> runLaptop(
      ChatService b, ZIdentity laptop, DeviceCertificate cert) async {
    final dir = await Directory.systemTemp.createTemp('z_extras_lt');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    await vault.kvPut('identity', jsonEncode(laptop.toJson()));
    final account = await b.accountIdentity();
    final enrolled = await AccountIdentity.fromEnrollment(
      accountEdPub: account.accountEdPub,
      accountMlPub: account.accountMlPub,
      deviceEdSeed: laptop.edSeed,
      deviceXSeed: laptop.xSeed,
      deviceId: 'lt',
      deviceCert: cert,
    );
    await vault.kvPut('account', jsonEncode(enrolled.toJson()));
    await vault.kvPut('my_devices', jsonEncode([account.deviceCert.toJson()]),
        sensitive: false);
    final svc = await ChatService.init(
      vault: vault,
      identity: laptop,
      displayName: 'b-laptop',
      transport: Transport(identity: laptop, serverUrl: 'ws://127.0.0.1:1'),
    );
    services.add(svc);
    return svc;
  }

  test('a text to a two-device contact is two outbox rows, link or no link',
      () async {
    final (a, b, laptopRid) = await twoDeviceContact();
    expect(a.transport.isConnected, isFalse, reason: 'the link is down');

    await a.sendText(b.myRid, 'for both of your devices');
    // The laptop copy is queued a moment after the phone's.
    await Future<void>.delayed(const Duration(milliseconds: 300));

    final rows = await outbox(a);
    expect(rows.map((r) => r['rid']).toSet(), {b.myRid, laptopRid},
        reason: 'one envelope per device, both still here: ${rows.length}');
  });

  test('a stalled link does not stall the conversation', () async {
    final stalled = StalledTransport(identity: await ZIdentity.generate());
    final (a, b, _) = await twoDeviceContact(transport: stalled);
    // (The transport's identity is not the service's; nothing here relies on
    // it — sends never reach a relay.)

    await a.sendText(b.myRid, 'one');
    await Future<void>.delayed(const Duration(milliseconds: 300));
    expect(stalled.hung, isNotEmpty, reason: 'the outbox tried the link');

    // The lock this used to hold across the hung send is not held now.
    final started = DateTime.now();
    await a.sendText(b.myRid, 'two').timeout(const Duration(seconds: 5));
    expect(DateTime.now().difference(started).inMilliseconds, lessThan(2000),
        reason: 'the second message waited on nothing but its own writes');
    expect((await outbox(a)).where((r) => r['rid'] == b.myRid).length,
        greaterThanOrEqualTo(2),
        reason: 'both are queued for the phone');
    for (final c in stalled.hung) {
      c.complete(); // let the pending flush unwind before teardown
    }
  });

  test('a removal notice to a dropped device is an outbox row', () async {
    final (a, b, laptopRid, _, cert) = await twoDeviceContactFull();
    // b drops the laptop; a learns of it from b's next list and tells the
    // laptop, over the session it still holds with it, that it was removed.
    await b.removeMyDevice(cert);
    await carry(b, a);
    await Future<void>.delayed(const Duration(milliseconds: 300));

    final rows = await outbox(a);
    expect(rows.where((r) => r['rid'] == laptopRid).length, 1,
        reason: 'the notice waits for the link instead of vanishing — rows: '
            '${rows.map((r) => r['rid'] == laptopRid ? 'laptop' : r['rid'] == b.myRid ? 'phone' : r['rid']).toList()}');
  });

  test("the post-quantum offer to a contact's extra device is an outbox row",
      () async {
    // The side that OFFERS the ML-KEM key is the one that did not open the
    // session (§17), and that is decided by routing-id order: pick a laptop
    // identity that sorts below a's, so a is the offerer.
    final aId = await ZIdentity.generate();
    final aRid = await aId.routingId();
    var laptop = await ZIdentity.generate();
    while ((await laptop.routingId()).compareTo(aRid) > 0) {
      laptop = await ZIdentity.generate();
    }
    final (a, b, laptopRid, laptopId, cert) =
        await twoDeviceContactFull(aIdentity: aId, laptopId: laptop);

    final lt = await runLaptop(b, laptopId, cert);
    await lt.addContactFromCode(await a.myContactCode());
    await lt.sendText(a.myRid, 'from the laptop');
    await carry(lt, a);
    await Future<void>.delayed(const Duration(milliseconds: 300));

    expect(a.messagesByChat[b.myRid]!.last.body, 'from the laptop',
        reason: "the laptop's message was read on the extra-device session");
    final rows = await outbox(a);
    expect(rows.where((r) => r['rid'] == laptopRid).length, 1,
        reason: 'a offers its ML-KEM key to the laptop through the outbox — '
            'rows: ${rows.map((r) => r['rid'] == laptopRid ? 'laptop' : r['rid'] == b.myRid ? 'phone' : r['rid']).toList()}');
  });

  /// Like `carry`, but hands back what it delivered, so a test can deliver
  /// the same envelope twice — which is what the relay does when it never
  /// saw an acknowledgement.
  Future<List<RelayInbound>> carryKeep(ChatService from, ChatService to) async {
    final rows = await from.vault.db.query('outbox',
        where: 'rid = ?', whereArgs: [to.myRid], orderBy: 'seq');
    await from.vault.db
        .delete('outbox', where: 'rid = ?', whereArgs: [to.myRid]);
    final envelopes = [
      for (final r in rows)
        RelayInbound(
            id: r['id'] as String,
            from: '',
            payload: r['payload'] as String,
            serverTs: DateTime.now().millisecondsSinceEpoch)
    ];
    for (final e in envelopes) {
      await to.debugInbound(e);
    }
    return envelopes;
  }

  /// Close [s] and open the same vault again, as a restart does. It is also
  /// the only way to change the account session a contact's extra devices
  /// use: it is built at init from `cextra_<rid>`, which is exactly the key
  /// that was being written with a literal `$` in its name until 2026-09-14,
  /// so before that fix this helper could not have worked either.
  Future<ChatService> reopen(ChatService s, ZIdentity id, String name) async {
    final root = s.vault.root;
    s.dispose();
    await s.transport.stop();
    final vault = await Vault.open(rootOverride: root);
    final next = await ChatService.init(
      vault: vault,
      identity: id,
      displayName: name,
      transport: Transport(identity: id, serverUrl: 'ws://127.0.0.1:1'),
    );
    services.add(next);
    return next;
  }

  test("a contact's laptop whose chain has desynced is reported, and repaired",
      () async {
    final aId = await ZIdentity.generate();
    var (a, b, _, laptopId, cert) = await twoDeviceContactFull(aIdentity: aId);
    final lt = await runLaptop(b, laptopId, cert);
    await lt.addContactFromCode(await a.myContactCode());
    await lt.sendText(a.myRid, 'from the laptop');
    await carry(lt, a);
    await a.loadMessages(b.myRid);
    expect(a.messagesByChat[b.myRid]!.last.body, 'from the laptop');

    // Desync a's session with the laptop: the chain exists and no longer
    // derives the same keys. The account session holds one conversation per
    // extra device, and it is read at init — so this is written to the vault
    // and a is restarted, which is also how a stale stored session reaches a
    // running client in the field.
    final stored = jsonDecode(await a.vault.kvGet('cextra_${b.myRid}') ?? '{}')
        as Map<String, Object?>;
    var changed = 0;
    for (final conv in ((stored['convs'] as Map?) ?? {}).values) {
      for (final session in ((conv as Map)['sessions'] as Map).values) {
        final ratchet = (session as Map)['ratchet'] as Map;
        if (ratchet['ckr'] != null) {
          ratchet['ckr'] = base64.encode(List<int>.filled(32, 7));
          changed++;
        }
      }
    }
    expect(changed, greaterThan(0), reason: 'there was a chain to desync');
    await a.vault.kvPut('cextra_${b.myRid}', jsonEncode(stored));

    a = await reopen(a, aId, 'a');
    await a.loadMessages(b.myRid);
    final rows = a.messagesByChat[b.myRid]!.length;
    final hellosBefore = a.debugHellos;

    await lt.sendText(a.myRid, 'and this one cannot be read');
    await carry(lt, a);

    expect(a.messagesByChat[b.myRid]!.length, rows + 1,
        reason: 'the notice, where there used to be nothing at all');
    expect(a.messagesByChat[b.myRid]!.last.body, contains('decrypt_failed'));
    expect(a.debugHellos, hellosBefore + 1,
        reason: 'the hello goes to the account and reaches every device on it');
  });

  test('a session store that fails leaves the envelope with the relay',
      () async {
    final spy = AckSpy(identity: await ZIdentity.generate());
    final (a, b, _, laptopId, cert) =
        await twoDeviceContactFull(transport: spy);
    final lt = await runLaptop(b, laptopId, cert);
    await lt.addContactFromCode(await a.myContactCode());
    await lt.sendText(a.myRid, 'first, so the session is settled');
    await carry(lt, a);
    await a.loadMessages(b.myRid);
    final rows = a.messagesByChat[b.myRid]!.length;

    // The disk refuses while the next one is processed.
    a.debugFailExtraStore = true;
    await lt.sendText(a.myRid, 'written down or not at all');
    final envelopes = await carryKeep(lt, a);
    expect(envelopes, isNotEmpty);
    expect(a.messagesByChat[b.myRid]!.length, rows,
        reason: 'nothing was stored, which is the point');
    expect(a.debugHellos, 0,
        reason: 'a disk that refused is not a chain that disagreed');
    expect(spy.acked, isNot(contains(envelopes.single.id)),
        reason: 'and the relay still holds it: an acknowledged envelope that '
            'was never stored is a message gone for good');

    // The relay saw no acknowledgement, so it delivers again — onto the
    // session that was put back. Without the rollback the advanced ratchet
    // cannot read it and the message is gone for good.
    a.debugFailExtraStore = false;
    for (final e in envelopes) {
      await a.debugInbound(e);
    }
    expect(a.messagesByChat[b.myRid]!.last.body, 'written down or not at all');
    expect(spy.acked, contains(envelopes.single.id),
        reason: 'and now it may be forgotten');
  });

  test('a dropped device does not get what was queued for it', () async {
    final (a, b, laptopRid, _, cert) = await twoDeviceContactFull();
    await a.sendText(b.myRid, 'queued while the link was down');
    await Future<void>.delayed(const Duration(milliseconds: 300));
    expect((await outbox(a)).where((r) => r['rid'] == laptopRid), hasLength(1),
        reason: "the laptop's copy is waiting for the link");

    // b drops the laptop; a's queue for it is emptied and the notice queued.
    await b.removeMyDevice(cert);
    await carry(b, a);
    await Future<void>.delayed(const Duration(milliseconds: 300));
    final toLaptop =
        (await outbox(a)).where((r) => r['rid'] == laptopRid).toList();
    expect(toLaptop, hasLength(1), reason: 'the notice, and only the notice');
    // It is the notice, not the message: opened by the laptop it would say
    // so, but the cheaper check is that the message row is gone — the notice
    // was queued AFTER the delete, so it is the newer row.
    final msgRow = (await outbox(a)).where((r) =>
        r['rid'] == laptopRid &&
        (r['created_ms'] as int) < (toLaptop.single['created_ms'] as int));
    expect(msgRow, isEmpty);
  });

  test('removing my own device drops what was queued for it', () async {
    final (_, b, laptopRid, _, cert) = await twoDeviceContactFull();
    // b has a laptop and its link is down: a message b sends is mirrored to
    // the laptop through the outbox and waits there.
    final a2 = await makeClient('a2');
    await b.addContactFromCode(await a2.myContactCode());
    await b.sendText(a2.myRid, 'mirrored to my laptop');
    await Future<void>.delayed(const Duration(milliseconds: 300));
    expect((await outbox(b)).where((r) => r['rid'] == laptopRid), isNotEmpty,
        reason: 'the mirror waits for the link');

    await b.removeMyDevice(cert);
    expect((await outbox(b)).where((r) => r['rid'] == laptopRid), isEmpty,
        reason: 'a device I removed gets nothing I had queued for it');
  });
}
