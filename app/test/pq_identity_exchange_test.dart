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
//
// And (44.3, PROTOCOL §18.11) each device's sealing key and its account's
// attestation of it, which ride the same exchange: a `pqseal` is a 4 096-
// bucket envelope beside a mixed message with no `pqct` in its header, and a
// 16 384-bucket one beside the ciphertext — what a header carries is read
// off the wire here, by opening each sealed envelope as its receiver does.
//   4. a `pqseal` never rides a message whose header carries `pqct`
//      (Finnian's decision of 2026-10-20): while a new contact's session is
//      in its encapsulating state — the side that encapsulates, before the
//      other's first mixed message reaches it — that side's announcement
//      waits, and it goes ahead of the first message it sends after the
//      answer; every `pqseal` either side sends is mixed, carries no `pqct`
//      and is a 4 096-bucket envelope, and each side ends holding the
//      other's key;
//   5. a `pqid` carries its device's `pqdc`, which verifies under the
//      account's ML-DSA key; and a contact that held the account's key from
//      a build before 44.3 gets one `pqid` more once the build is updated —
//      after the delay and not at the upgrade, carrying the `pqdc`, and once:
//      a restart sends no second;
//   6. the same rule as 4 on the other two kinds of channel — a device's own
//      other device over self-sync, and a contact's other device: with a
//      linked laptop's mixed envelopes held back from its root and from a
//      contact, both of which encapsulate toward it, every message either
//      sends the laptop carries `pqct` and no `pqseal` goes to it; once they
//      are let go, every `pqseal` any of the three sends, on every channel,
//      is mixed, carries no `pqct` and is a 4 096-bucket envelope, and each
//      of the six directed channels carries one;
//   7. a contact deleted and added back: the side that kept its state had
//      heard the other hold its sealing key, and the new ratchet session the
//      re-add opens makes it forget that (PROTOCOL §18.11), so it announces
//      its key again on its clock; each ends holding the other's key, and
//      having heard that the other holds its own;
// and every envelope any of them queues in 4 to 7 starts `zs1.`.
import 'dart:async';
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

  /// Shorten the post-quantum send debounce, because three of the four tests
  /// below do arithmetic on it: a nudge waits 2x it (20x on the side that
  /// opened the session) and any send quiets the next one for 10x, and the
  /// rounds those tests carry envelopes in are sized against those multiples.
  ///
  /// It is a knob with two jobs, and the flake the `retry: 2` here used to
  /// absorb came from the other one. The debounce is also what lets a
  /// volunteer scheduled on a `hello` be cancelled by the answer to the
  /// `pqid` that arrives right behind it — and at 100 ms it is competitive
  /// with the work in between (an ML-DSA check against the commitment, a
  /// vault seal, a sqlite write) on a loaded two-core box. Lose that race and
  /// the side sends twice, which is exactly what the first test counts and
  /// refuses. So the test that counts gets a debounce comfortably longer than
  /// that work, and costs nothing for it: `settle` returns as soon as both
  /// sides are quiet, so a longer debounce buys a few more polling rounds and
  /// no wall-clock. The tests whose arithmetic needs the short one keep it.
  void quick(ChatService s,
          {Duration d = const Duration(milliseconds: 100)}) =>
      s.pqSendDebounce = d;

  /// Long enough that the answer always wins the cancellation race above.
  const counting = Duration(milliseconds: 800);

  test('a mutual add sends one post-quantum identity each way, not two',
      () async {
    final (a, b) = await twoClients();
    quick(a, d: counting);
    quick(b, d: counting);
    final aToB = <int>[], bToA = <int>[];
    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());
    await settle(a, b, aToB, bToA);

    expect(a.contacts[b.myRid]!.pqPub, isNotNull, reason: "a holds b's key");
    expect(b.contacts[a.myRid]!.pqPub, isNotNull, reason: "b holds a's key");
    expect(big(aToB), 1, reason: 'A→B 16 384-bucket envelopes: $aToB');
    expect(big(bToA), 1, reason: 'B→A 16 384-bucket envelopes: $bToA');
    expect(a.debugPqSends + b.debugPqSends, 2);
    // retry: this add-and-settle races its own 100 ms PQ-send debounce against
    // the 150 ms settle rounds, and under a loaded suite can offer the identity
    // twice (a second 16 384-bucket envelope) before the first is acknowledged.
    // Its PQ siblings pq_rekey_test and pq_upgrade_test carry the same guard; a
    // real regression fails every attempt, not one run in a busy suite.
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

  // -------------------------------------------------------------------------
  // 44.3 (PROTOCOL §18.11).

  /// A client over the vault in [dir]: the identity it holds, or a new one.
  /// [before] starts it as a build from before 44.3.
  Future<ChatService> clientAt(Directory dir, String name,
      {bool before = false}) async {
    final vault = await Vault.open(rootOverride: dir);
    final stored = await vault.kvGet('identity');
    final identity = stored == null
        ? await ZIdentity.generate()
        : await ZIdentity.fromJson(
            (jsonDecode(stored) as Map).cast<String, Object?>());
    if (stored == null) {
      await vault.kvPut('identity', jsonEncode(identity.toJson()));
    }
    final svc = await ChatService.init(
      vault: vault,
      identity: identity,
      displayName: name,
      transport: Transport(identity: identity, serverUrl: 'ws://127.0.0.1:1'),
      debugBuildBeforeSealingKeys: before,
    );
    services.add(svc);
    return svc;
  }

  Future<Directory> dirFor(String name) async {
    final dir = await Directory.systemTemp.createTemp('z_pqx_$name');
    temps.add(dir);
    return dir;
  }

  Future<void> stop(ChatService s) async {
    s.dispose();
    await s.transport.stop();
    services.remove(s);
    await s.vault.db.close();
  }

  /// Polls [cond] until it holds, every 40 ms, for at most [timeout].
  Future<void> waitFor(FutureOr<bool> Function() cond, String what,
      {Duration timeout = const Duration(seconds: 30)}) async {
    final deadline = DateTime.now().add(timeout);
    while (!await cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
  }

  /// Every envelope [from] has queued for [to], oldest first: taken off the
  /// outbox, opened as the relay never can — with [to]'s own key — to read
  /// the ratchet header it carries, and handed to [to] unless [hold] says to
  /// keep it back (it goes on [held] then). Each is recorded on [log] with
  /// the kind [to] read in it ([watch]).
  Future<int> carry(ChatService from, ChatService to, List<Carried> log,
      {bool Function(Carried c)? hold, List<Carried>? held}) async {
    final rows = await from.vault.db.query('outbox',
        where: 'rid = ?', whereArgs: [to.myRid], orderBy: 'seq');
    for (final r in rows) {
      await from.vault.db
          .delete('outbox', where: 'seq = ?', whereArgs: [r['seq']]);
      final c = await Carried.open(from.myRid, to, r);
      log.add(c);
      if (hold != null && hold(c)) {
        held!.add(c);
        continue;
      }
      await deliver(to, c);
    }
    return rows.length;
  }

  test('4. a pqseal waits off a message carrying pqct, and goes in the '
      '4 096 bucket ahead of the first message without it', () async {
    final (a, b) = await twoClients(); // a encapsulates (§17.1), b offers
    quick(a, d: counting);
    quick(b, d: counting);
    watch(a);
    watch(b);
    final log = <Carried>[];
    final held = <Carried>[];
    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());

    // Carried both ways, except that b's MIXED envelopes are kept from a: a
    // encapsulates on b's offer, and until a message of b's mixed with the
    // secret reaches it, every message a sends carries the ciphertext.
    await waitFor(() async {
      await carry(a, b, log);
      await carry(b, a, log, hold: (c) => c.pq, held: held);
      return a.debugConversation(b.myRid)?.nextSendCarriesPqCiphertext ??
          false;
    }, 'a has encapsulated');
    await a.sendText(b.myRid, 'while a encapsulates');
    for (var i = 0; i < 5; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 200));
      await carry(a, b, log);
      await carry(b, a, log, hold: (c) => c.pq, held: held);
    }
    expect(a.debugConversation(b.myRid)!.nextSendCarriesPqCiphertext, isTrue,
        reason: 'the premise: a still encapsulating');
    expect(
        log.where((c) => c.from == a.myRid && c.kind == 'pqseal'), isEmpty,
        reason: 'a announced its key while every message it sent carried '
            'pqct (kind/bucket, header)');

    // The answer: b's mixed messages reach a — what was kept back, and a
    // message b now sends, mixed since a's ciphertext reached it — so a
    // holds the pair's secret as acknowledged and stops attaching the
    // ciphertext.
    for (final c in held) {
      await deliver(a, c);
    }
    held.clear();
    await b.sendText(a.myRid, 'the answer');
    await carry(b, a, log);
    expect(log.any((c) => c.from == b.myRid && c.kind == 'text' && c.pq),
        isTrue,
        reason: "the premise: b's answer was mixed");
    expect(a.debugConversation(b.myRid)!.nextSendCarriesPqCiphertext, isFalse);
    await a.sendText(b.myRid, 'after the answer');
    await waitFor(() async {
      await carry(a, b, log);
      await carry(b, a, log);
      return log.any(
          (c) => c.kind == 'text' && c.data?['body'] == 'after the answer');
    }, "a's text after the answer carried");

    final aSent = [
      for (final c in log)
        if (c.from == a.myRid) c
    ];
    expect(aSent.any((c) => c.kind == 'text' && c.pq && c.pqct), isTrue,
        reason: "the premise: a's text went beside the ciphertext: $aSent");
    // Waits, and goes ahead of the first message whose header carries none.
    expect(aSent.where((c) => c.kind == 'pqseal' && c.pqct), isEmpty,
        reason: 'a pqseal rode a message carrying pqct: $aSent');
    expect(aSent.firstWhere((c) => c.pq && !c.pqct).kind, 'pqseal',
        reason: "a's announcement goes ahead of the first message it sends "
            'without the ciphertext: $aSent');

    final seals = [
      for (final c in log)
        if (c.kind == 'pqseal') c
    ];
    final measured = seals.map((c) => '${c.from == a.myRid ? 'a' : 'b'}: '
        '${c.bucket}${c.pqct ? ' beside pqct' : ''}');
    expect(seals.map((c) => c.from).toSet(), {a.myRid, b.myRid},
        reason: 'each side announced its key: $measured');
    expect(seals.every((c) => c.pq && !c.pqct), isTrue, reason: '$measured');
    expect(seals.map((c) => c.bucket).toSet(), {4096}, reason: '$measured');
    expect(b.debugPqSealOf(a.myRid), a.debugSealingKey);
    expect(a.debugPqSealOf(b.myRid), b.debugSealingKey);
    expect(log.every((c) => c.payload.startsWith('zs1.')), isTrue,
        reason: 'an envelope was sealed otherwise than zs1.');
  });

  test('5. a pqid carries its pqdc, and a contact that held the key before '
      'gets one more, later and once', () async {
    final da = await dirFor('upa'), db = await dirFor('upb');
    var a = await clientAt(da, 'a', before: true);
    final b = await clientAt(db, 'b');
    quick(a, d: counting);
    quick(b, d: counting);
    watch(a);
    watch(b);
    final log = <Carried>[];
    Future<void> settleAll(ChatService x) async {
      for (var i = 0; i < 40; i++) {
        await Future<void>.delayed(const Duration(milliseconds: 100));
        final moved = await carry(x, b, log) + await carry(b, x, log);
        if (moved == 0 && !x.pqSendPending && !b.pqSendPending) return;
      }
    }

    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());
    await settleAll(a);
    expect(a.contacts[b.myRid]!.pqAcked, isTrue,
        reason: "the premise: b holds a's post-quantum key");
    expect(a.debugSealingKey, isNull, reason: 'a build from before 44.3');
    expect(b.debugPqdcOf(a.myRid), isNull,
        reason: "a's pqid carried no pqdc: there was none");
    // b runs this build: its own pqid to a carried its pqdc, which verifies
    // under b's account key over b's two keys and its sealing key.
    final bPqdc = b.debugOwnPqdc;
    expect(bPqdc, isNotNull);
    expect(
        deviceAttestationValid(
            accountMlPub: (await b.pqAccountPublic())!,
            accountEdPub: b.identity.edPub,
            deviceEdPub: b.identity.edPub,
            deviceXPub: b.identity.xPub,
            sealEk: b.debugSealingKey!,
            pqdc: bPqdc!),
        isTrue);
    expect(
        log.any((c) =>
            c.from == b.myRid &&
            c.kind == 'pqid' &&
            c.data?['pqdc'] == b64(bPqdc)),
        isTrue,
        reason: "b's pqid carried b's pqdc");

    // a is updated. Its next start draws a key and signs its own pqdc — and
    // b, which already holds a's account key, is owed one pqid more.
    await stop(a);
    a = await clientAt(da, 'a');
    quick(a, d: counting);
    watch(a);
    const delay = Duration(milliseconds: 1500);
    a.pqdcResendDelay = delay;
    final upgraded = DateTime.now();
    final aPqdc = a.debugOwnPqdc;
    expect(aPqdc, isNotNull, reason: 'a root signs its own at first start');
    final mark = log.length;
    await Future<void>.delayed(const Duration(milliseconds: 400));
    await carry(a, b, log);
    expect(log.skip(mark).where((c) => c.kind == 'pqid'), isEmpty,
        reason: 'the pqid is not sent at the upgrade');
    await waitFor(() async {
      await carry(a, b, log);
      await carry(b, a, log);
      return b.debugPqdcOf(a.myRid) != null;
    }, "b holds a's pqdc");
    final again = [
      for (final c in log.skip(mark))
        if (c.from == a.myRid && c.kind == 'pqid') c
    ];
    expect(again, hasLength(1), reason: 'once: $again');
    expect(again.single.bucket, 16384);
    expect(again.single.at.difference(upgraded), greaterThanOrEqualTo(delay),
        reason: 'scheduled, not immediate');
    expect(b.debugPqdcOf(a.myRid), aPqdc);

    // Once: a restart sends no second.
    await stop(a);
    a = await clientAt(da, 'a');
    quick(a, d: counting);
    watch(a);
    a.pqdcResendDelay = const Duration(milliseconds: 300);
    final mark2 = log.length;
    for (var i = 0; i < 8; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 200));
      await carry(a, b, log);
      await carry(b, a, log);
    }
    expect(log.skip(mark2).where((c) => c.from == a.myRid && c.kind == 'pqid'),
        isEmpty,
        reason: 'the one more pqid went once');
    expect(log.every((c) => c.payload.startsWith('zs1.')), isTrue);
  });

  /// A client named [name] with identity [id], over a vault of its own;
  /// [setup] writes to that vault before the service starts.
  Future<ChatService> clientWith(String name, ZIdentity id,
      {Future<void> Function(Vault vault)? setup}) async {
    final vault = await Vault.open(rootOverride: await dirFor(name));
    await vault.kvPut('identity', jsonEncode(id.toJson()));
    if (setup != null) await setup(vault);
    final svc = await ChatService.init(
      vault: vault,
      identity: id,
      displayName: name,
      transport: Transport(identity: id, serverUrl: 'ws://127.0.0.1:1'),
    );
    services.add(svc);
    return svc;
  }

  /// [x] and [y] each hold the other's sealing key and have heard that the
  /// other holds theirs.
  bool sealed(ChatService x, ChatService y) =>
      x.debugPqSealOf(y.myRid) != null &&
      y.debugPqSealOf(x.myRid) != null &&
      x.debugHoldsMySealKey(y.myRid) &&
      y.debugHoldsMySealKey(x.myRid);

  test('6. a pqseal waits off pqct on the other two kinds of channel too: to '
      "my own other device, and to a contact's", () async {
    // Ordered so that the root and the contact each encapsulate toward the
    // laptop (§17.1: the smaller routing id does): on both of its channels
    // the laptop is the side that offers, and its mixed envelopes — held
    // back below — are what would end the others' encapsulating state.
    final ids = [for (var i = 0; i < 3; i++) await ZIdentity.generate()];
    final rids = {for (final i in ids) i: await i.routingId()};
    ids.sort((x, y) => rids[x]!.compareTo(rids[y]!));
    final phone = await clientWith('phone', ids[0]);
    final carol = await clientWith('carol', ids[1]);
    final account = await phone.accountIdentity();
    final devId = ids[2];
    final cert = await account.signDeviceCert(
        deviceEdPub: devId.edPub, deviceXPub: devId.xPub, deviceId: 'lap');
    // Linked as pairing v2 links a device, the way every device linked
    // before 44.4 was.
    final laptop = await clientWith('laptop', devId, setup: (vault) async {
      final enrolled = await AccountIdentity.fromEnrollment(
        accountEdPub: account.accountEdPub,
        accountMlPub: await phone.pqAccountPublic(),
        deviceEdSeed: devId.edSeed,
        deviceXSeed: devId.xSeed,
        deviceId: 'lap',
        deviceCert: cert,
      );
      await vault.kvPut('account', jsonEncode(enrolled.toJson()));
      await vault.kvPut('my_devices', jsonEncode([account.deviceCert.toJson()]),
          sensitive: false);
    });
    final all = {'phone': phone, 'laptop': laptop, 'carol': carol};
    for (final s in all.values) {
      quick(s, d: counting);
      watch(s);
    }
    // What each of the six directed channels carried; and what is kept back
    // from the laptop's two, its MIXED envelopes, while [holding].
    final logs = {
      for (final x in all.keys)
        for (final y in all.keys)
          if (x != y) '$x->$y': <Carried>[]
    };
    final held = {'laptop->phone': <Carried>[], 'laptop->carol': <Carried>[]};
    var holding = false;
    final duringHold = <Carried>{};
    Future<void> carryAll() async {
      for (final x in all.keys) {
        for (final y in all.keys) {
          if (x == y) continue;
          final key = '$x->$y';
          final log = logs[key]!;
          final before = log.length;
          await carry(all[x]!, all[y]!, log,
              hold: held.containsKey(key) ? (c) => holding && c.pq : null,
              held: held[key]);
          if (holding) duringHold.addAll(log.skip(before));
        }
      }
    }

    bool got(ChatService s, ChatService from, String body) =>
        (s.messagesByChat[from.myRid] ?? const [])
            .any((m) => !m.outgoing && m.body == body);
    Conversation? syncTo(ChatService s, ChatService d) =>
        s.debugSyncSession?.targetConversation(d.myRid);
    Conversation? extraTo(ChatService s, ChatService owner, ChatService d) =>
        s.debugExtraSession(owner.myRid)?.targetConversation(d.myRid);

    await phone.addContactFromCode(await carol.myContactCode());
    await carol.addContactFromCode(await phone.myContactCode());
    await waitFor(() async {
      await carryAll();
      return phone.contacts[carol.myRid]!.pqPub != null &&
          carol.contacts[phone.myRid]!.pqPub != null &&
          !phone.pqSendPending &&
          !carol.pqSendPending;
    }, "the phone and carol hold each other's post-quantum keys");

    // The hold: the laptop is linked, and it adds carol; each channel to it
    // comes to carry pqct on every message the other side sends it.
    holding = true;
    await phone.addMyDevice(cert);
    await waitFor(() async {
      await carryAll();
      return syncTo(phone, laptop)?.nextSendCarriesPqCiphertext ?? false;
    }, 'the phone encapsulating toward the laptop, over self-sync');
    await laptop.addContactFromCode(await carol.myContactCode(),
        requested: false);
    // The laptop's offer rides what it says to carol, and carol's answer
    // what she says to the phone's account, which fans to the laptop.
    var n = 0;
    await waitFor(() async {
      final i = n++;
      await laptop.sendText(carol.myRid, 'reach l$i');
      await carol.sendText(phone.myRid, 'reach c$i');
      await carryAll();
      return extraTo(carol, phone, laptop)?.nextSendCarriesPqCiphertext ??
          false;
    }, "carol encapsulating toward the phone's laptop, its other device");
    for (var i = 0; i < 3; i++) {
      await phone.sendText(carol.myRid, 'held p$i');
      await carol.sendText(phone.myRid, 'held c$i');
      await laptop.sendText(carol.myRid, 'held l$i');
      await waitFor(() async {
        await carryAll();
        return got(carol, phone, 'held p$i') &&
            got(phone, carol, 'held c$i') &&
            got(laptop, carol, 'held c$i');
      }, 'round $i of the hold carried');
    }
    final syncHeld = [
      for (final c in logs['phone->laptop']!)
        if (duringHold.contains(c)) c
    ];
    final extraHeld = [
      for (final c in logs['carol->laptop']!)
        if (duringHold.contains(c)) c
    ];
    expect(syncHeld.where((c) => c.pq && c.pqct), isNotEmpty,
        reason: 'the premise: the phone encapsulating on self-sync: '
            '$syncHeld');
    expect(extraHeld.where((c) => c.pq && c.pqct), isNotEmpty,
        reason: 'the premise: carol encapsulating toward the laptop: '
            '$extraHeld');
    expect(syncHeld.where((c) => c.pq && !c.pqct), isEmpty,
        reason: 'the premise: every mixed message carried pqct: $syncHeld');
    expect(extraHeld.where((c) => c.pq && !c.pqct), isEmpty,
        reason: 'the premise: every mixed message carried pqct: $extraHeld');
    expect([...syncHeld, ...extraHeld].where((c) => c.kind == 'pqseal'),
        isEmpty,
        reason: 'a pqseal went to the laptop while every message to it '
            'carried pqct: ${[...syncHeld, ...extraHeld]}');

    // Let go: the laptop's mixed envelopes arrive, both sides stop carrying
    // the ciphertext, and each announcement that waited goes.
    holding = false;
    for (final e in held.entries) {
      final to = all[e.key.split('->').last]!;
      for (final c in e.value) {
        await deliver(to, c);
      }
      e.value.clear();
    }
    var m = 0;
    await waitFor(() async {
      final i = m++;
      await phone.sendText(carol.myRid, 'after p$i');
      await carol.sendText(phone.myRid, 'after c$i');
      await laptop.sendText(carol.myRid, 'after l$i');
      for (var j = 0; j < 3; j++) {
        await carryAll();
      }
      return logs.values.every((log) => log.any((c) => c.kind == 'pqseal'));
    }, 'each of the six directed channels carrying a pqseal',
        timeout: const Duration(seconds: 90));

    final seals = [
      for (final e in logs.entries)
        for (final c in e.value)
          if (c.kind == 'pqseal') '${e.key} $c'
    ];
    final wrong = [
      for (final e in logs.entries)
        for (final c in e.value)
          if (c.kind == 'pqseal' && (!c.pq || c.pqct || c.bucket != 4096))
            '${e.key} $c'
    ];
    expect(wrong, isEmpty,
        reason: 'a pqseal not mixed, beside pqct or out of the 4 096 '
            'bucket: $seals');
    expect(
        logs.values.every(
            (log) => log.every((c) => c.payload.startsWith('zs1.'))),
        isTrue,
        reason: 'an envelope was sealed otherwise than zs1.');
  }, timeout: const Timeout(Duration(minutes: 4)));

  test('7. a contact deleted and added back: each holds the other\'s sealing '
      'key again, the new session having forgotten the stamp', () async {
    final (a, b) = await twoClients();
    quick(a, d: counting);
    quick(b, d: counting);
    watch(a);
    watch(b);
    final log = <Carried>[];
    var n = 0;
    // A text each way, and what they set going carried a few times over.
    Future<void> round(String tag) async {
      final i = n++;
      await a.sendText(b.myRid, '$tag a$i');
      await b.sendText(a.myRid, '$tag b$i');
      for (var j = 0; j < 3; j++) {
        await carry(a, b, log);
        await carry(b, a, log);
      }
    }

    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());
    await waitFor(() async {
      await round('k');
      return sealed(a, b);
    }, 'keys exchanged and stamped both ways',
        timeout: const Duration(seconds: 60));

    // a forgets b and adds b back; b keeps everything, its having heard
    // a hold its key included.
    await a.deleteContact(b.myRid);
    expect(a.debugPqSealOf(b.myRid), isNull,
        reason: 'the premise: deleted with the contact');
    expect(b.debugHoldsMySealKey(a.myRid), isTrue,
        reason: 'the premise: b had heard a hold its key');
    await a.addContactFromCode(await b.myContactCode());
    // §17.4's clock, which the announcement runs on, compressed on both
    // sides: what is owed goes at the first message that may carry it.
    a.pqOfferRetry = 300;
    b.pqOfferRetry = 300;
    final bBefore = b.debugPqSealSends;
    await waitFor(() async {
      await round('again');
      return sealed(a, b);
    }, "each holds the other's sealing key again, and has heard so",
        timeout: const Duration(seconds: 60));
    expect(a.debugPqSealOf(b.myRid), b.debugSealingKey);
    expect(b.debugPqSealOf(a.myRid), a.debugSealingKey);
    expect(b.debugPqSealSends, greaterThan(bBefore),
        reason: 'b announced its key again');
    expect(log.every((c) => c.payload.startsWith('zs1.')), isTrue,
        reason: 'an envelope was sealed otherwise than zs1.');
  }, timeout: const Timeout(Duration(minutes: 3)));
}

/// One envelope as the relay was handed it, and as its receiver read it.
class Carried {
  final String from;
  final RelayInbound inbound;
  final int bucket;

  /// The ratchet header, read with the receiver's key: mixed (`pq:1`), and
  /// whether it carried the ML-KEM ciphertext (`pqct`).
  final bool pq;
  final bool pqct;
  final DateTime at = DateTime.now();

  /// The inner message's kind and members, as the receiver decrypted it;
  /// null for one kept back or not read.
  String? kind;
  Map<String, Object?>? data;

  Carried(this.from, this.inbound, this.bucket, this.pq, this.pqct);

  String get payload => inbound.payload;

  static Future<Carried> open(
      String from, ChatService to, Map<String, Object?> row) async {
    final payload = row['payload'] as String;
    var bucket = -1, pq = false, pqct = false;
    if (payload.startsWith('zs1.')) {
      bucket = base64Url.decode(base64Url.normalize(payload.substring(4))).length -
          60;
      final opened = await SealedEnvelope.open(
          myXSeed: to.identity.xSeed, myXPub: to.identity.xPub, blob: payload);
      try {
        final j = jsonDecode(utf8.decode(base64Decode(opened!.payload))) as Map;
        final h = j['h'];
        if (h is Map) {
          pq = h['pq'] == 1;
          pqct = h['pqct'] != null;
        }
      } catch (_) {
        // Not a ratchet message (a contact request): no header to read.
      }
    }
    return Carried(
        from,
        RelayInbound(
            id: row['id'] as String,
            from: '',
            payload: payload,
            serverTs: DateTime.now().millisecondsSinceEpoch),
        bucket,
        pq,
        pqct);
  }

  @override
  String toString() =>
      '${kind ?? '?'}/$bucket${pq ? ' pq' : ''}${pqct ? ' pqct' : ''}';
}

/// The envelope [to] is reading now, which its probe ([watch]) names.
Carried? _reading;

/// Hands [c] to [to]'s inbound path, noting the kind it reads in it.
Future<void> deliver(ChatService to, Carried c) async {
  _reading = c;
  try {
    await to.debugInbound(c.inbound);
  } finally {
    _reading = null;
  }
}

/// [svc]'s probe: the kind and members of the inner message in the envelope
/// [deliver] is handing it, read on a copy of the ratchet and let through.
void watch(ChatService svc) {
  svc.debugOnDecrypted = (path, from, dec) {
    final c = _reading;
    if (c != null) {
      try {
        final inner = InnerMessage.fromBytes(dec.plaintext);
        c.kind = inner.kind;
        c.data = inner.data;
      } catch (_) {}
    }
    return false;
  };
}
