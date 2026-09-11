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
//      outbox row too.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:z_protocol/z_protocol.dart';

/// A link that looks up but never answers: every send waits for ever.
class StalledTransport extends Transport {
  StalledTransport({required super.identity})
      : super(serverUrl: 'ws://127.0.0.1:1');
  final hung = <Completer<bool>>[];
  @override
  bool get isConnected => true;
  @override
  Future<bool> send(
      {required String to, required String id, required String payload}) {
    final c = Completer<bool>();
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
      c.complete(false); // let the pending flush unwind before teardown
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
}
