// §18.2 — the post-quantum identity exchange, counted from the relay's side.
//
// A `pqid` carries an ML-DSA-65 public key and seals into the 16 384-byte
// bucket, the one size ordinary chat almost never has (`adr/0004`, addendum).
// Two mailboxes that each receive one within seconds of each other have
// announced to the relay that they just met — which is the cost §18.2 accepts
// for a key that does not fit in the QR code. Measured on 2026-09-11, a
// mutual add paid that cost TWICE in each direction, and the case the nudge
// exists for — an opening send that vanished — completed only because of the
// same accidental second send. Every reason to send now schedules one
// debounced send, the send says whether we hold the peer's key (`ack`), and a
// key that arrives with `ack` is not answered.
//
// No relay: outbox rows are handed to the receiver's inbound path directly,
// so what "the relay sees" is the list of sealed envelopes each side queued,
// and their buckets are read off the sealed blobs.
//
// Exit criteria:
//   1. a mutual add sends exactly ONE 16 384-bucket envelope in each
//      direction over the whole exchange, and both sides end hybrid;
//   2. when the opening send was dropped because the peer had not added us
//      yet, the exchange completes on the first traffic — both hybrid, ONE
//      more envelope each way — whichever order the batch arrives in;
//   3. a side whose commitment stays unmet keeps asking on inbound traffic
//      and stops at the bound — and a skipped ask does not count against
//      it; a side that keeps being asked answers, and stops at the bound.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/chat_service.dart';
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

  Future<ChatService> makeClient(String name) async {
    final dir = await Directory.systemTemp.createTemp('z_pqx_$name');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    final identity = await ZIdentity.generate();
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

  /// The designated initiator (§4: the smaller routing id) first, so the
  /// tests read the same way every run.
  Future<(ChatService, ChatService)> twoClients() async {
    final x = await makeClient('x');
    final y = await makeClient('y');
    return x.myRid.compareTo(y.myRid) < 0 ? (x, y) : (y, x);
  }

  int bucketOf(String sealed) {
    final raw = base64Url.decode(base64Url.normalize(sealed.substring(4)));
    return raw.length - 32 - 12 - 16;
  }

  /// Everything [a] has queued for [toRid], oldest first, removed from the
  /// outbox; the buckets go on [seen] so a test can count what the relay
  /// would have carried.
  Future<List<RelayInbound>> drain(
      ChatService a, String toRid, List<int> seen) async {
    final rows = await a.vault.db.query('outbox',
        where: 'rid = ?', whereArgs: [toRid], orderBy: 'created_ms ASC');
    await a.vault.db.delete('outbox', where: 'rid = ?', whereArgs: [toRid]);
    for (final r in rows) {
      seen.add(bucketOf(r['payload'] as String));
    }
    return [
      for (final r in rows)
        RelayInbound(
            id: r['id'] as String,
            from: '',
            payload: r['payload'] as String,
            serverTs: DateTime.now().millisecondsSinceEpoch)
    ];
  }

  /// Carries traffic both ways until nothing is queued, at most [rounds];
  /// [reverse] delivers each batch newest-first, the order a relay does not
  /// promise not to produce. Waits out the debounce between rounds.
  Future<void> settle(
      ChatService a, ChatService b, List<int> aToB, List<int> bToA,
      {int rounds = 16, bool reverse = false}) async {
    for (var i = 0; i < rounds; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 150));
      final ab = await drain(a, b.myRid, aToB);
      for (final m in reverse ? ab.reversed : ab) {
        await b.debugInbound(m);
      }
      final ba = await drain(b, a.myRid, bToA);
      for (final m in reverse ? ba.reversed : ba) {
        await a.debugInbound(m);
      }
      if (ab.isEmpty && ba.isEmpty && !a.pqSendPending && !b.pqSendPending) {
        return;
      }
    }
  }

  int big(List<int> buckets) => buckets.where((k) => k == 16384).length;

  void quick(ChatService s) =>
      s.pqSendDebounce = const Duration(milliseconds: 100);

  test('a mutual add sends one post-quantum identity each way, not two',
      () async {
    final (a, b) = await twoClients();
    quick(a);
    quick(b);
    final aToB = <int>[], bToA = <int>[];
    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());
    await settle(a, b, aToB, bToA);

    expect(a.contacts[b.myRid]!.pqPub, isNotNull, reason: "a holds b's key");
    expect(b.contacts[a.myRid]!.pqPub, isNotNull, reason: "b holds a's key");
    expect(big(aToB), 1, reason: 'A→B 16 384-bucket envelopes: $aToB');
    expect(big(bToA), 1, reason: 'B→A 16 384-bucket envelopes: $bToA');
    expect(a.debugPqSends + b.debugPqSends, 2);
  });

  for (final reverse in [false, true]) {
    test(
        'an opening send that vanished is made good on the first traffic '
        '(batches ${reverse ? 'newest' : 'oldest'} first)', () async {
      final (a, b) = await twoClients();
      quick(a);
      quick(b);
      final lost = <int>[], aToB = <int>[], bToA = <int>[];
      await a.addContactFromCode(await b.myContactCode());
      await Future<void>.delayed(const Duration(milliseconds: 250));
      // b has not added a: the hello and the key have no session to land in.
      final dropped = await drain(a, b.myRid, lost);
      expect(dropped, isNotEmpty);
      expect(big(lost), 1, reason: 'the opening key was in what vanished');

      await b.addContactFromCode(await a.myContactCode());
      await a.sendText(b.myRid, 'hi');
      await settle(a, b, aToB, bToA, reverse: reverse);

      expect(a.contacts[b.myRid]!.pqPub, isNotNull);
      expect(b.contacts[a.myRid]!.pqPub, isNotNull,
          reason: 'the key a lost with its opening send was offered again');
      // b asked once, a answered once — and a's own nudge, scheduled by
      // b's first traffic, found the key already there and stayed quiet.
      expect(big(bToA), 1, reason: 'B→A: $bToA');
      expect(big(aToB), 1, reason: 'A→B: $aToB');
    });
  }

  test('asking and answering are both bounded', () async {
    final (a, b) = await twoClients();
    quick(a);
    quick(b);
    final aToB = <int>[], bToA = <int>[];
    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());

    // b never receives a's key: every 16 384-bucket envelope from a is lost
    // on the way, so b's commitment stays unmet and it keeps asking — and
    // every ask reaches a, which keeps answering.
    // Each round outlasts the nudge's own wait (2× the debounce) and the
    // quiet period after any send (10×), so a nudge that is going to go has
    // gone before the next text arrives.
    Future<void> carryWithoutKeys() async {
      await Future<void>.delayed(const Duration(milliseconds: 1100));
      final before = aToB.length;
      final ab = await drain(a, b.myRid, aToB);
      for (var i = 0; i < ab.length; i++) {
        if (aToB[before + i] != 16384) await b.debugInbound(ab[i]);
      }
      for (final m in await drain(b, a.myRid, bToA)) {
        await a.debugInbound(m);
      }
    }

    for (var i = 0; i < 6; i++) {
      await a.sendText(b.myRid, 'still here $i');
      await carryWithoutKeys();
    }
    await carryWithoutKeys();
    expect(b.contacts[a.myRid]!.pqPub, isNull);
    expect(a.contacts[b.myRid]!.pqPub, isNotNull);
    // b: one volunteered on the hello, then exactly three nudges — six
    // texts arrived and the fourth, fifth and sixth were not answered.
    expect(big(bToA), 4, reason: 'B→A: $bToA');
    // a: one volunteered at add, then one answer per ask, bounded at three.
    expect(big(aToB), 4, reason: 'A→B: $aToB');
  });
}
