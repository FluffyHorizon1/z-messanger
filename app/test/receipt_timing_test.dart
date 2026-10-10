// Phase 41 (ADR 0028) — what the relay sees of a delivery receipt.
//
// Sealed sender keeps the sender's name off an envelope, and the receipt that
// answers it put the name back: the recipient's app sealed a `dlv` to the
// sender's mailbox within 300 ms of the delivery, so a relay — or whoever
// terminates its TLS — that delivered envelope E to mailbox B and a moment
// later took a small envelope for mailbox A had A as E's sender (the 2026-10-03
// analysis, P1-15; Martiny et al., NDSS 2021). These tests watch from where
// that party stands: the relay is `server/test/support/observed_relay.js`,
// which prints when every envelope arrived and for which mailbox, and when it
// was written to its recipient's socket. Every service here hands its inbound
// envelopes to the app one at a time, so the test knows which envelope
// carried which message and which receipt turned which tick.
//
// Exit criteria:
//   1. Over M = 12 deliveries from six senders, at the app's own timing, no
//      receipt reaches the relay within N = 5 000 ms of the delivery of the
//      message it acknowledges, and none later than the 60 s ceiling (plus
//      the time to send it); the measured distribution is printed. Before
//      phase 41 every one of them arrived about 300 ms after.
//   2. Receipts are batched per person: a burst of six messages is answered
//      with fewer receipt envelopes than messages — one, unless the burst
//      straddles a release — each no sooner than the floor after every
//      delivery it acknowledges, and nothing else goes to the sender.
//   3. A receipt past its floor rides with the next message the user sends
//      that person, in the same flush, and the sender's tick turns with it; a
//      receipt still inside its floor does not ride, and is not lost.
//   4. Read receipts are held too: opening a chat sends nothing at once, the
//      read receipt reaches the relay no sooner than the floor after the
//      reading, and a message read as it arrives is answered — delivered
//      and read — no sooner than the floor after its delivery.
//   5. Receipts off: nothing is held or sent — not on a timer, not riding,
//      not when the chat is read — what was held is dropped from memory and
//      from the vault, the sender's messages stay at one tick, and the
//      choice is a preference the device keeps (and a backup carries).
//   6. A receipt held when the app stops is sent by the next start, no
//      sooner than the floor after the device is back online.
//   7. Ticks stay honest: a message whose receipt is held is not shown
//      delivered, and a group message turns delivered only once every
//      member's receipt has arrived — not on the first member's.
@Tags(['integration'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/archive.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/models.dart';
import 'package:zapp/core/receipts.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';

/// One line the observed relay printed (see `observed_relay.js`).
class RelayEvent {
  final String ev;
  final String? to;
  final String? id;
  final String? rid;
  final int at;
  final int bytes;
  final bool anon;
  RelayEvent(Map<String, Object?> j)
      : ev = j['ev'] as String,
        to = j['to'] as String?,
        id = j['id'] as String?,
        rid = j['rid'] as String?,
        at = (j['at'] as num).toInt(),
        bytes = (j['bytes'] as num?)?.toInt() ?? 0,
        anon = j['anon'] == true;
}

/// A sealed envelope in the smallest bucket (§8: 1 024 bytes of plaintext,
/// sealed and base64url-encoded, is about 1 450 characters): what a receipt
/// naming one to three messages is, and what a one-word text is too. Four to
/// sixty-four, and it is the 4 096 bucket, as a text of a hundred characters
/// is (measured for ADR 0028).
bool smallest(RelayEvent e) => e.bytes < 2000;

/// [svc]'s inbound envelopes, handed to the app one at a time, and what each
/// did: which incoming messages it brought, and which outgoing messages it
/// turned delivered or read. Keyed by the relay's envelope id, which is what
/// the observed relay prints too.
class Inbox {
  final ChatService svc;
  final arrivedIn = <String, String>{}; // incoming mid → envelope id
  final deliveredIn = <String, String>{}; // outgoing mid → envelope id
  final readIn = <String, String>{}; // outgoing mid → envelope id
  Future<void> _chain = Future<void>.value();

  Inbox(this.svc) {
    svc.transport.onMessage = (m) {
      _chain = _chain.then((_) => _one(m)).catchError((Object _) {});
    };
  }

  Future<void> _one(RelayInbound m) async {
    await svc.debugInbound(m);
    final rows = await svc.vault.db
        .query('messages', columns: ['mid', 'outgoing', 'status']);
    for (final r in rows) {
      final mid = r['mid'] as String;
      if (r['outgoing'] != 1) {
        arrivedIn.putIfAbsent(mid, () => m.id);
        continue;
      }
      final st = r['status'] as int;
      if (st >= MsgStatus.delivered) deliveredIn.putIfAbsent(mid, () => m.id);
      if (st >= MsgStatus.read) readIn.putIfAbsent(mid, () => m.id);
    }
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  late Process relay;
  late int port;
  final events = <RelayEvent>[];
  final temps = <Directory>[];
  final live = <ChatService>[];
  final inboxes = <ChatService, Inbox>{};

  setUpAll(() async {
    HttpOverrides.global = null;
    final serverDir =
        '${Directory.current.parent.path}${Platform.pathSeparator}server';
    final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    port = probe.port;
    await probe.close();
    relay = await Process.start('node', ['test/support/observed_relay.js'],
        workingDirectory: serverDir,
        environment: {'PORT': '$port', 'LOG_LEVEL': 'silent'});
    relay.stdout
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen((line) {
      if (line.startsWith('OBS ')) {
        events.add(RelayEvent(
            (jsonDecode(line.substring(4)) as Map).cast<String, Object?>()));
      }
    });
    relay.stderr.drain<void>();
    for (var i = 0; i < 60; i++) {
      try {
        final res = await (await HttpClient()
                .getUrl(Uri.parse('http://127.0.0.1:$port/health')))
            .close();
        await res.drain<void>();
        if (res.statusCode == 200) return;
      } catch (_) {
        await Future<void>.delayed(const Duration(milliseconds: 100));
      }
    }
    fail('relay did not start');
  });

  tearDownAll(() async {
    for (final s in live) {
      await s.transport.stop();
    }
    relay.kill();
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<void> waitUntil(FutureOr<bool> Function() cond,
      {Duration timeout = const Duration(seconds: 30),
      required String what}) async {
    final deadline = DateTime.now().add(timeout);
    while (!await cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
  }

  /// A short timing for criteria that are not about the delay itself.
  const quick =
      ReceiptTiming(floor: Duration(seconds: 2), ceiling: Duration(seconds: 6));

  Future<ChatService> start(Directory dir, String name,
      {ReceiptTiming timing = ReceiptTiming.standard}) async {
    final vault = await Vault.open(rootOverride: dir);
    final stored = await vault.kvGet('identity');
    final me = stored == null
        ? await ZIdentity.generate()
        : await ZIdentity.fromJson(
            (jsonDecode(stored) as Map).cast<String, Object?>());
    if (stored == null) await vault.kvPut('identity', jsonEncode(me.toJson()));
    final transport =
        Transport(identity: me, serverUrl: 'ws://127.0.0.1:$port');
    final svc = await ChatService.init(
        vault: vault,
        identity: me,
        displayName: name,
        transport: transport,
        receiptTiming: timing);
    live.add(svc);
    inboxes[svc] = Inbox(svc);
    await waitUntil(() => transport.isConnected && transport.isSenderConnected,
        what: '$name connected');
    return svc;
  }

  Future<ChatService> person(String name,
      {ReceiptTiming timing = ReceiptTiming.standard}) async {
    final dir = await Directory.systemTemp.createTemp('z_rt_');
    temps.add(dir);
    return start(dir, name, timing: timing);
  }

  /// Every pair in [all] that added each other holds the other's
  /// post-quantum key, nothing is waiting in an outbox, no post-quantum send
  /// is in flight and no receipt is held: the one-off traffic of a new
  /// contact is over, and a measurement starts from silence.
  Future<void> quiet(List<ChatService> all, {required String what}) async {
    Future<bool> settled() async {
      for (final s in all) {
        for (final o in all) {
          final c = s.contacts[o.myRid];
          if (identical(s, o) || c == null) continue;
          if (c.pqPub == null && c.pqCandidate == null) return false;
        }
      }
      for (final s in all) {
        if ((await s.vault.db.query('outbox', limit: 1)).isNotEmpty) {
          return false;
        }
      }
      return all.every((s) => !s.pqSendPending);
    }

    await waitUntil(settled, timeout: const Duration(seconds: 60), what: what);
    for (final s in all) {
      await s.flushDeliveryReceipts();
    }
    await waitUntil(() async {
      for (final s in all) {
        await inboxes[s]!._chain;
      }
      return await settled() && all.every((s) => s.pendingReceipts == 0);
    }, timeout: const Duration(seconds: 60), what: '$what, receipts sent');
  }

  /// [a] and [b] add each other and say hello both ways.
  Future<void> introduce(ChatService a, ChatService b) async {
    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());
    await a.sendText(b.myRid, 'hello from ${a.displayName}');
    await b.sendText(a.myRid, 'hello from ${b.displayName}');
    await waitUntil(
        () =>
            (a.messagesByChat[b.myRid] ?? []).any((m) => !m.outgoing) &&
            (b.messagesByChat[a.myRid] ?? []).any((m) => !m.outgoing),
        what: '${a.displayName} and ${b.displayName} have spoken');
  }

  /// [from] sends [body] to [to]'s thread; its mid.
  Future<String> say(ChatService from, String thread, String body) async {
    await from.sendText(thread, body);
    return from.messagesByChat[thread]!
        .lastWhere((m) => m.outgoing && m.body == body)
        .mid;
  }

  Future<void> holds(ChatService s, String thread, String body) => waitUntil(
      () => (s.messagesByChat[thread] ?? [])
          .any((m) => !m.outgoing && m.body == body),
      what: '${s.displayName} holds "$body"');

  Future<int?> statusOf(ChatService s, String thread, String mid) async {
    final rows = await s.vault.db.query('messages',
        columns: ['status'],
        where: 'mid = ? AND rid = ? AND outgoing = 1',
        whereArgs: [mid, thread]);
    return rows.isEmpty ? null : rows.single['status'] as int;
  }

  Future<void> reaches(ChatService s, String thread, String mid, int status,
          {Duration timeout = const Duration(seconds: 30)}) =>
      waitUntil(() async => (await statusOf(s, thread, mid) ?? 0) >= status,
          timeout: timeout,
          what: '${s.displayName} shows $mid at status $status');

  /// When the relay first wrote envelope [id] to its recipient's socket.
  RelayEvent delivery(String id) =>
      events.firstWhere((e) => e.ev == 'deliver' && e.id == id);

  /// When the relay took envelope [id].
  RelayEvent acceptance(String id) =>
      events.firstWhere((e) => e.ev == 'accept' && e.id == id);

  /// How long after the relay delivered [mid] to [receiver] it took the
  /// envelope that turned [mid] delivered (or [read]) at [sender].
  int gap(ChatService sender, ChatService receiver, String mid,
      {bool read = false}) {
    final carried = inboxes[receiver]!.arrivedIn[mid]!;
    final receipt = read
        ? inboxes[sender]!.readIn[mid]!
        : inboxes[sender]!.deliveredIn[mid]!;
    final r = acceptance(receipt);
    expect(r.anon, isTrue,
        reason: 'a receipt is sealed and sent on the anonymous link');
    return r.at - delivery(carried).at;
  }

  test(
      '1. no receipt reaches the relay within 5 s of the delivery it '
      'acknowledges, over 12 deliveries', () async {
    const n = 5000; // N: the floor (ADR 0028)
    const ceiling = 60000;
    expect(ReceiptTiming.standard.floor.inMilliseconds, n);
    expect(ReceiptTiming.standard.ceiling.inMilliseconds, ceiling);
    final bob = await person('Bob');
    final senders = [for (var i = 0; i < 6; i++) await person('S$i')];
    for (final s in senders) {
      await introduce(s, bob);
    }
    await quiet([bob, ...senders], what: 'everyone introduced');

    final gaps = <int>[];
    for (var round = 0; round < 2; round++) {
      final mids = <ChatService, String>{};
      // One at a time, so each delivery is the one message of its sender.
      for (final s in senders) {
        final body = 'round $round from ${s.displayName}';
        mids[s] = await say(s, bob.myRid, body);
        await holds(bob, s.myRid, body);
      }
      for (final s in senders) {
        await reaches(s, bob.myRid, mids[s]!, MsgStatus.delivered,
            timeout: const Duration(seconds: 90));
        await inboxes[s]!._chain;
        gaps.add(gap(s, bob, mids[s]!));
        expect(smallest(acceptance(inboxes[s]!.deliveredIn[mids[s]]!)), isTrue,
            reason: 'a receipt for one message is the smallest envelope');
      }
    }

    final sorted = [...gaps]..sort();
    // ignore: avoid_print
    print('receipt after delivery, ms, M=${gaps.length}: $sorted '
        '(min ${sorted.first}, median ${sorted[sorted.length ~/ 2]}, '
        'max ${sorted.last})');
    expect(gaps.length, 12);
    expect(sorted.first, greaterThanOrEqualTo(n),
        reason: 'a receipt reached the relay ${sorted.first} ms after the '
            'delivery it acknowledges: $sorted');
    expect(sorted.last, lessThan(ceiling + 10000),
        reason: 'a receipt waited past its ceiling: $sorted');
  }, timeout: const Timeout(Duration(minutes: 8)));

  test('2. receipts are batched per person, each past its floor', () async {
    final alice = await person('Alice2', timing: quick);
    final bob = await person('Bob2', timing: quick);
    await introduce(alice, bob);
    await quiet([alice, bob], what: 'introduced');

    final mark = events.length;
    final mids = [
      for (var i = 0; i < 6; i++) await say(alice, bob.myRid, 'burst $i')
    ];
    for (final mid in mids) {
      await reaches(alice, bob.myRid, mid, MsgStatus.delivered);
    }
    await inboxes[alice]!._chain;
    final receipts = {
      for (final mid in mids) inboxes[alice]!.deliveredIn[mid]!
    };
    // ignore: avoid_print
    print('six messages, ${receipts.length} receipt envelope(s) of '
        '${[for (final r in receipts) acceptance(r).bytes]} characters');
    expect(receipts.length, lessThan(mids.length),
        reason: 'receipts went one per message');
    for (final mid in mids) {
      expect(gap(alice, bob, mid), greaterThanOrEqualTo(2000),
          reason: 'a batch left inside the floor of a message it carried');
    }
    // Nothing else went to Alice: the relay took exactly those envelopes for
    // her mailbox.
    expect(
        events
            .skip(mark)
            .where((e) => e.ev == 'accept' && e.to == alice.myRid)
            .map((e) => e.id)
            .toSet(),
        receipts);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test(
      '3. a receipt past its floor rides with the next message to that '
      'person; one inside it does not, and is not lost', () async {
    final alice = await person('Alice3');
    final bob = await person('Bob3');
    await introduce(alice, bob);
    await quiet([alice, bob], what: 'introduced');
    bob.debugHoldReceipts = true; // only riding, or the test, sends one

    final m1 = await say(alice, bob.myRid, 'first');
    await holds(bob, alice.myRid, 'first');
    await waitUntil(() => bob.eligibleReceipts(alice.myRid) == 1,
        timeout: const Duration(seconds: 20),
        what: "Bob's receipt for 'first' is past its floor");
    expect(await statusOf(alice, bob.myRid, m1), MsgStatus.sent,
        reason: 'held, so not yet delivered on Alice\'s screen');

    final reply = await say(bob, alice.myRid, 'a reply');
    expect(bob.pendingDeliveryReceipts, 0,
        reason: 'the receipt went with the reply');
    await reaches(alice, bob.myRid, m1, MsgStatus.delivered);
    await inboxes[alice]!._chain;
    final carried = acceptance(inboxes[alice]!.arrivedIn[reply]!);
    final receipt = acceptance(inboxes[alice]!.deliveredIn[m1]!);
    expect(receipt.id, isNot(carried.id));
    expect(receipt.at - carried.at, inInclusiveRange(0, 3000),
        reason: 'the receipt left in the flush that carried the reply');

    // A message just arrived: its receipt is inside its floor, so a reply
    // sent at once leaves without it.
    final mark = events.length;
    final m2 = await say(alice, bob.myRid, 'second');
    await holds(bob, alice.myRid, 'second');
    await say(bob, alice.myRid, 'straight back');
    await holds(alice, bob.myRid, 'straight back');
    expect(bob.pendingDeliveryReceipts, 1,
        reason: "the second message's receipt is still held");
    expect(
        events
            .skip(mark)
            .where((e) => e.ev == 'accept' && e.to == alice.myRid)
            .length,
        1,
        reason: 'only the reply went to Alice');
    expect(await statusOf(alice, bob.myRid, m2), MsgStatus.sent);
    await bob.flushDeliveryReceipts();
    await reaches(alice, bob.myRid, m2, MsgStatus.delivered);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('4. read receipts are held, and leave no sooner than the floor',
      () async {
    final alice = await person('Alice4', timing: quick);
    final bob = await person('Bob4', timing: quick);
    await introduce(alice, bob);
    // Bob reads Alice's hello, so the reading measured below is of one
    // message.
    await bob.markChatOpened(alice.myRid);
    bob.markChatClosed(alice.myRid);
    await quiet([alice, bob], what: 'introduced, and the hello read');

    final m = await say(alice, bob.myRid, 'read me');
    await holds(bob, alice.myRid, 'read me');
    await bob.flushDeliveryReceipts();
    await reaches(alice, bob.myRid, m, MsgStatus.delivered);

    final mark = events.length;
    final openedAt = DateTime.now().millisecondsSinceEpoch;
    await bob.markChatOpened(alice.myRid);
    bob.markChatClosed(alice.myRid);
    expect(bob.pendingReceipts, 1, reason: 'the read receipt is held');
    expect(
        events.skip(mark).where((e) => e.ev == 'accept' && e.to == alice.myRid),
        isEmpty,
        reason: 'nothing left for Alice at the moment of reading');
    await reaches(alice, bob.myRid, m, MsgStatus.read);
    await inboxes[alice]!._chain;
    final read = acceptance(inboxes[alice]!.readIn[m]!);
    expect(read.at - openedAt, greaterThanOrEqualTo(2000),
        reason: 'the read receipt left inside its floor');

    // Read as it arrives: the chat is open on Bob's screen.
    await bob.markChatOpened(alice.myRid);
    final m2 = await say(alice, bob.myRid, 'while you look');
    await holds(bob, alice.myRid, 'while you look');
    await reaches(alice, bob.myRid, m2, MsgStatus.read);
    bob.markChatClosed(alice.myRid);
    await inboxes[alice]!._chain;
    expect(gap(alice, bob, m2), greaterThanOrEqualTo(2000),
        reason: 'the delivery receipt left inside its floor');
    expect(gap(alice, bob, m2, read: true), greaterThanOrEqualTo(2000),
        reason: 'the read receipt left inside the floor of the delivery');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('5. receipts off: nothing held, nothing sent, one tick', () async {
    final alice = await person('Alice5');
    final bob = await person('Bob5');
    await introduce(alice, bob);
    await quiet([alice, bob], what: 'introduced');
    bob.debugHoldReceipts = true;

    final m1 = await say(alice, bob.myRid, 'before off');
    await holds(bob, alice.myRid, 'before off');
    expect(bob.pendingDeliveryReceipts, 1);
    await waitUntil(
        () async => await bob.vault.kvGet('rcpt_${alice.myRid}') != null,
        what: 'the held receipt is in the vault');

    await bob.setSendsReceipts(false);
    expect(bob.sendsReceipts, isFalse);
    expect(bob.pendingReceipts, 0, reason: 'what was held is dropped');
    await waitUntil(
        () async => await bob.vault.kvGet('rcpt_${alice.myRid}') == null,
        what: 'and gone from the vault');

    final mark = events.length;
    final m2 = await say(alice, bob.myRid, 'while off');
    await holds(bob, alice.myRid, 'while off');
    await bob.markChatOpened(alice.myRid);
    bob.markChatClosed(alice.myRid);
    expect(bob.pendingReceipts, 0, reason: 'nothing is held while off');
    await say(bob, alice.myRid, 'a reply, alone');
    await bob.flushDeliveryReceipts();
    await holds(alice, bob.myRid, 'a reply, alone');
    final toAlice =
        events.skip(mark).where((e) => e.ev == 'accept' && e.to == alice.myRid);
    expect(toAlice.length, 1, reason: 'only the reply went to Alice');
    expect(await statusOf(alice, bob.myRid, m1), MsgStatus.sent,
        reason: 'one tick: nothing claims it arrived');
    expect(await statusOf(alice, bob.myRid, m2), MsgStatus.sent);

    // A preference the device keeps, and a backup carries.
    expect(await bob.vault.kvGet('receipts_enabled'), '0');
    expect(BackupArchive.stateKeys, contains('receipts_enabled'));

    // On again: from here on, as before.
    await bob.setSendsReceipts(true);
    final m3 = await say(alice, bob.myRid, 'on again');
    await holds(bob, alice.myRid, 'on again');
    await bob.flushDeliveryReceipts();
    await reaches(alice, bob.myRid, m3, MsgStatus.delivered);
    expect(await statusOf(alice, bob.myRid, m2), MsgStatus.sent,
        reason: 'what arrived while off is never acknowledged after');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test(
      '6. a receipt held at shutdown goes after the next start, past the '
      'floor', () async {
    final alice = await person('Alice6', timing: quick);
    final bobDir = await Directory.systemTemp.createTemp('z_rt_');
    temps.add(bobDir);
    var bob = await start(bobDir, 'Bob6', timing: quick);
    await introduce(alice, bob);
    await quiet([alice, bob], what: 'introduced');
    bob.debugHoldReceipts = true;

    final m = await say(alice, bob.myRid, 'before the restart');
    await holds(bob, alice.myRid, 'before the restart');
    await waitUntil(
        () async => await bob.vault.kvGet('rcpt_${alice.myRid}') != null,
        what: 'the held receipt is in the vault');

    // The app is killed: nothing more from this process. The database is
    // left open — anything the stopped service had started may still be
    // finishing, and a closed handle under it would fail this test for a
    // reason that is not the app's — and the next start opens the same file.
    bob.dispose();
    await bob.transport.stop();
    live.remove(bob);
    expect(await statusOf(alice, bob.myRid, m), MsgStatus.sent);

    final mark = events.length;
    bob = await start(bobDir, 'Bob6', timing: quick);
    final back = events
        .skip(mark)
        .firstWhere((e) => e.ev == 'ready' && e.rid == bob.myRid);
    await reaches(alice, bob.myRid, m, MsgStatus.delivered);
    await inboxes[alice]!._chain;
    final receipt = acceptance(inboxes[alice]!.deliveredIn[m]!);
    expect(receipt.at - back.at, greaterThanOrEqualTo(2000),
        reason: 'the receipt left inside the floor after the device came '
            'back');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('7. a group message is delivered only once every member has said so',
      () async {
    final alice = await person('Alice7', timing: quick);
    final bob = await person('Bob7', timing: quick);
    final carol = await person('Carol7', timing: quick);
    await introduce(alice, bob);
    await introduce(alice, carol);
    await introduce(bob, carol);
    await quiet([alice, bob, carol], what: 'introduced');
    final gid = await alice.createGroup('Seven', [bob.myRid, carol.myRid]);
    await waitUntil(
        () => bob.groups.containsKey(gid) && carol.groups.containsKey(gid),
        what: 'the group reached both');
    await quiet([alice, bob, carol], what: 'the group settled');

    bob.debugHoldReceipts = true;
    carol.debugHoldReceipts = true;
    await alice.sendGroupText(gid, 'to both of you');
    final gm = alice.messagesByChat[gid]!
        .lastWhere((m) => m.outgoing && m.body == 'to both of you')
        .mid;
    await holds(bob, gid, 'to both of you');
    await holds(carol, gid, 'to both of you');
    expect((await statusOf(alice, gid, gm))!, lessThan(MsgStatus.delivered),
        reason: 'both receipts held: nobody has said it arrived');

    bob.debugHoldReceipts = false; // Bob's goes at its own moment
    await waitUntil(
        () async => (await alice.vault.db.query('delivery',
                where: 'mid = ? AND from_rid = ?', whereArgs: [gm, bob.myRid]))
            .isNotEmpty,
        what: "Bob's receipt reached Alice");
    expect((await statusOf(alice, gid, gm))!, lessThan(MsgStatus.delivered),
        reason: 'one member of two has said so');

    carol.debugHoldReceipts = false;
    await reaches(alice, gid, gm, MsgStatus.delivered);
  }, timeout: const Timeout(Duration(minutes: 3)));
}
