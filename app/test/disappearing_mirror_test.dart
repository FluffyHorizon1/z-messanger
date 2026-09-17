// A disappearing message that reached a device through a different door
// did not disappear.
//
// §6.1 is normative: `ttl` marks a disappearing message, the recipient
// deletes it `ttl` seconds after receipt and the sender `ttl` seconds after
// sending. `USING_Z.md` says "messages delete on both sides when it expires".
// Three doors stored the copy with no expiry at all, so the sweeper's
// predicate (`expire_at_ms > 0`) never matched it and the copy lived for the
// life of the vault — the 2026-09-14 review's finding 6:
//
//   `_insertMirrored`      a copy of my own message on my other device, and a
//                          message from a CONTACT's linked device, which
//                          arrives through the extra-device door;
//   `_insertMirroredFile`  the same for an attachment offer;
//   the history replay     the recent history a newly linked device is given,
//                          whose items carried no expiry at all.
//
// The first two are one fix: the copy keeps the `ttl` the inner message
// carries — from the message's own timestamp when it is my own message (the
// sender's copy goes when the original does), from this device's receipt when
// it is somebody else's (the same clock as the primary inbound path). The
// third is a wire member: a history item now carries `x`, the absolute time
// the sender's copy goes, and an item whose time has passed is not stored.
//
// Everything below runs offline: envelopes are carried between clients by
// hand (`debugInbound`), the way `extras_fanout_test.dart` does it, so what
// is asserted is a row's `expire_at_ms` and not a race with a timer.
//
// Criteria, each a test below:
//   1. a disappearing message I send is mirrored to my linked device with the
//      same expiry as my own copy, and a file offer likewise;
//   2. a disappearing message a contact sends from their LINKED device is
//      stored with an expiry counted from my receipt, exactly as one from
//      their phone is;
//   3. the history replayed to a newly linked device carries each item's
//      expiry, and an item that has already expired is not replayed at all;
//   4. and the sweeper then removes such a copy, which is the property all
//      three doors were failing.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/models.dart';
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

  Future<ChatService> makeClient(String name, {ZIdentity? identity}) async {
    final dir = await Directory.systemTemp.createTemp('z_dm_$name');
    temps.add(dir);
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

  /// Hand every outbox row addressed to [to] over, as the relay would.
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

  /// A mirror to my own devices is queued after the send returns
  /// (`unawaited`), so wait for the row before carrying it.
  Future<void> queued(ChatService from, ChatService to, {int atLeast = 1}) async {
    for (var i = 0; i < 100; i++) {
      final n = await from.vault.db
          .query('outbox', where: 'rid = ?', whereArgs: [to.myRid]);
      if (n.length >= atLeast) return;
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
    fail('nothing was queued from ${from.myRid} to ${to.myRid}');
  }

  /// Carry both ways until nothing moves, so sessions settle.
  Future<void> settle(ChatService x, ChatService y) async {
    for (var i = 0; i < 6; i++) {
      final n = await carry(x, y) + await carry(y, x);
      if (n == 0) return;
    }
  }

  /// A second device of [owner]'s account, offline, holding [owner]'s cert.
  Future<ChatService> runLinked(
      ChatService owner, ZIdentity dev, DeviceCertificate cert, String name) async {
    final dir = await Directory.systemTemp.createTemp('z_dm_$name');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    await vault.kvPut('identity', jsonEncode(dev.toJson()));
    final account = await owner.accountIdentity();
    final enrolled = await AccountIdentity.fromEnrollment(
      accountEdPub: account.accountEdPub,
      accountMlPub: account.accountMlPub,
      deviceEdSeed: dev.edSeed,
      deviceXSeed: dev.xSeed,
      deviceId: name,
      deviceCert: cert,
    );
    await vault.kvPut('account', jsonEncode(enrolled.toJson()));
    await vault.kvPut('my_devices', jsonEncode([account.deviceCert.toJson()]),
        sensitive: false);
    final svc = await ChatService.init(
      vault: vault,
      identity: dev,
      displayName: name,
      transport: Transport(identity: dev, serverUrl: 'ws://127.0.0.1:1'),
    );
    services.add(svc);
    return svc;
  }

  Future<Map<String, Object?>?> row(ChatService s, String mid) async {
    final r = await s.vault.db
        .query('messages', where: 'mid = ?', whereArgs: [mid], limit: 1);
    return r.isEmpty ? null : r.first;
  }

  /// The message [s] holds in [rid]'s thread with this [body] (or, for a
  /// file, this name).
  ChatMessage sentAs(ChatService s, String rid, String body) =>
      s.messagesByChat[rid]!.lastWhere((m) => m.body == body);

  /// Two people, sessions settled, and the second with a linked laptop that
  /// the first has been told about. Returns (a, b, laptop).
  Future<(ChatService, ChatService, ChatService)> pairWithLaptop() async {
    final a = await makeClient('a');
    final b = await makeClient('b');
    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());
    await settle(a, b);
    await a.sendText(b.myRid, 'hello');
    await settle(a, b);
    await b.sendText(a.myRid, 'hello back');
    await settle(a, b);

    final ltId = await ZIdentity.generate();
    final account = await b.accountIdentity();
    final cert = await account.signDeviceCert(
        deviceEdPub: ltId.edPub, deviceXPub: ltId.xPub, deviceId: 'lt');
    await b.addMyDevice(cert);
    final lt = await runLinked(b, ltId, cert, 'lt');
    await lt.addContactFromCode(await a.myContactCode());
    // b told a about the laptop, and the self-sync channel settles.
    await settle(b, a);
    await settle(b, lt);
    await settle(lt, a);
    // Whatever the link itself sent is not the point of any test below.
    for (final s in [a, b, lt]) {
      await s.vault.db.delete('outbox');
    }
    return (a, b, lt);
  }

  test('1. my own disappearing message is mirrored with its expiry, text and file',
      () async {
    final (a, b, lt) = await pairWithLaptop();
    await b.setDisappearingTimer(a.myRid, 3600);
    await settle(b, a);
    await settle(b, lt);

    await b.sendText(a.myRid, 'gone in an hour');
    final sent = sentAs(b, a.myRid, 'gone in an hour');
    final mine = (await row(b, sent.mid))!;
    expect(mine['expire_at_ms'] as int, greaterThan(0), reason: 'the original has a timer');
    await queued(b, lt);
    expect(await carry(b, lt), greaterThan(0), reason: 'a mirror was queued for the laptop');
    final copy = await row(lt, sent.mid);
    expect(copy, isNotNull, reason: 'the laptop holds the copy');
    expect(copy!['expire_at_ms'], mine['expire_at_ms'],
        reason: "the sender's copy on my other device goes when the original does");
    expect(lt.messagesByChat[a.myRid]!.firstWhere((m) => m.mid == sent.mid).expireAtMs,
        mine['expire_at_ms'],
        reason: 'and the loaded message says so, not only the row');

    // A file offer through the same door.
    await b.sendFile(a.myRid, 'note.txt', Uint8List.fromList(List<int>.filled(2048, 0x78)), 'text/plain');
    final offer = sentAs(b, a.myRid, 'note.txt');
    final mineFile = (await row(b, offer.mid))!;
    expect(mineFile['expire_at_ms'] as int, greaterThan(0));
    await queued(b, lt);
    await carry(b, lt);
    final copyFile = await row(lt, offer.mid);
    expect(copyFile, isNotNull);
    expect(copyFile!['expire_at_ms'], mineFile['expire_at_ms'], reason: 'an offer keeps its timer too');
  });

  test("2. a contact's disappearing message from their linked device keeps its timer",
      () async {
    final (a, b, lt) = await pairWithLaptop();
    // The laptop sets the timer for its own conversation with a, as a
    // phone would; the message it sends carries `ttl` like any other.
    await lt.setDisappearingTimer(a.myRid, 60);
    await settle(lt, a);
    final before = DateTime.now().millisecondsSinceEpoch;
    await lt.sendText(a.myRid, 'from the laptop, briefly');
    final sent = sentAs(lt, a.myRid, 'from the laptop, briefly');
    expect(await carry(lt, a), greaterThan(0));
    final got = await row(a, sent.mid);
    expect(got, isNotNull, reason: 'arrived through the extra-device door');
    final expireAt = got!['expire_at_ms'] as int;
    expect(expireAt, greaterThanOrEqualTo(before + 60 * 1000),
        reason: 'counted from my receipt, like a message from their phone');
    expect(expireAt, lessThanOrEqualTo(DateTime.now().millisecondsSinceEpoch + 60 * 1000));
    // For comparison: the same message from b's phone.
    await b.setDisappearingTimer(a.myRid, 60);
    await settle(b, a);
    await b.sendText(a.myRid, 'from the phone, briefly');
    final fromPhone = sentAs(b, a.myRid, 'from the phone, briefly');
    await carry(b, a);
    expect(((await row(a, fromPhone.mid))!['expire_at_ms'] as int), greaterThan(0));
  });

  test('3. the history replayed to a newly linked device carries each expiry, and not what has already gone',
      () async {
    final a = await makeClient('a3');
    final b = await makeClient('b3');
    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());
    await settle(a, b);
    await b.sendText(a.myRid, 'kept for ever');
    await settle(a, b);
    await b.setDisappearingTimer(a.myRid, 3600);
    await settle(b, a);
    await b.sendText(a.myRid, 'kept for an hour');
    final timed = sentAs(b, a.myRid, 'kept for an hour');
    await settle(b, a);
    // One whose hour has already passed, which the sweeper has not yet
    // collected: written directly, as a row the sweeper is about to take.
    await b.sendText(a.myRid, 'already gone');
    final gone = sentAs(b, a.myRid, 'already gone');
    await settle(b, a);
    await b.vault.db.update('messages', {'expire_at_ms': DateTime.now().millisecondsSinceEpoch - 1},
        where: 'mid = ?', whereArgs: [gone.mid]);
    final timedRow = (await row(b, timed.mid))!;

    // Now the laptop is linked: b replays the recent history to it.
    final ltId = await ZIdentity.generate();
    final account = await b.accountIdentity();
    final cert = await account.signDeviceCert(
        deviceEdPub: ltId.edPub, deviceXPub: ltId.xPub, deviceId: 'lt3');
    await b.vault.db.delete('outbox');
    await b.addMyDevice(cert);
    // The replay is queued a moment after the link.
    final ltRid = await ltId.routingId();
    for (var i = 0; i < 50; i++) {
      final n = await b.vault.db.query('outbox', where: 'rid = ?', whereArgs: [ltRid]);
      if (n.length >= 2) break;
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
    final lt = await runLinked(b, ltId, cert, 'lt3');
    await lt.addContactFromCode(await a.myContactCode());
    await settle(b, lt);

    final bodies = [for (final m in lt.messagesByChat[a.myRid] ?? const <ChatMessage>[]) m.body];
    expect(bodies, contains('kept for ever'));
    expect(bodies, contains('kept for an hour'));
    expect(bodies, isNot(contains('already gone')),
        reason: 'a message that has disappeared on the sender does not reappear on the laptop');
    expect((await row(lt, timed.mid))!['expire_at_ms'], timedRow['expire_at_ms'],
        reason: 'the replayed copy goes at the same moment as the original');
    final forever = lt.messagesByChat[a.myRid]!.firstWhere((m) => m.body == 'kept for ever');
    expect((await row(lt, forever.mid))!['expire_at_ms'], 0, reason: 'and one with no timer has none');
  });

  test('4. the sweeper removes such a copy', () async {
    final (a, b, lt) = await pairWithLaptop();
    await b.setDisappearingTimer(a.myRid, 1);
    await settle(b, a);
    await settle(b, lt);
    await b.sendText(a.myRid, 'blink');
    final sent = sentAs(b, a.myRid, 'blink');
    await queued(b, lt);
    await carry(b, lt);
    await carry(b, a);
    expect(await row(lt, sent.mid), isNotNull);
    expect(await row(a, sent.mid), isNotNull);
    await Future<void>.delayed(const Duration(milliseconds: 1200));
    await lt.debugSweep();
    await a.debugSweep();
    await b.debugSweep();
    expect(await row(lt, sent.mid), isNull, reason: 'the mirrored copy went');
    expect(await row(a, sent.mid), isNull, reason: 'the received one went');
    expect(await row(b, sent.mid), isNull, reason: 'and the original');
    expect(lt.messagesByChat[a.myRid]!.any((m) => m.mid == sent.mid), isFalse,
        reason: 'gone from the screen as well as the row');
  });
}
