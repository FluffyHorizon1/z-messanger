// 15.3 — what receiving a message actually costs, and where the
// out-of-order key cache is actually USED.
//
// The send side was measured, attributed and fixed (docs/PERFORMANCE.md).
// The receive side never was, and it is the half where the skipped-key
// cache does its work: an in-order message advances the receiving chain, a
// message that arrives early creates skipped keys, and a message that
// arrives late is decrypted with one of them. Each of those is a different
// amount of work, and since 15.3 each receive also re-seals the whole cache
// into its own cell — the exact cost that was removed from every SEND, now
// paid on every RECEIVE instead. Whether that trade was right is a number,
// not an argument, and this produces it.
//
// No network in any of these timings. The sender's outbox rows hold the
// sealed envelopes exactly as the relay would deliver them; they are handed
// to the receiver's inbound path directly (`debugInbound`). Both clients are
// pointed at a port nothing listens on, so nothing is delivered or acked.
//
// Not run in the ordinary sweep — it is a measurement, not an assertion:
//
//     flutter test test/receive_bench_test.dart --tags bench
@Tags(['bench'])
library;

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
    final dir = await Directory.systemTemp.createTemp('z_rbench_$name');
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

  /// Two clients who know each other, offline. Returns (a, b, b's rid as
  /// a sees it, a's rid as b sees it).
  Future<(ChatService, ChatService, String, String)> pair() async {
    final a = await makeClient('a');
    final b = await makeClient('b');
    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());
    return (a, b, b.myRid, a.myRid);
  }

  /// The sealed envelopes [a] has queued for [toRid], oldest first, exactly
  /// as the relay would hand them to the other side — and removed from the
  /// outbox so the next call sees only new ones.
  Future<List<RelayInbound>> drainOutbox(ChatService a, String toRid) async {
    final rows = await a.vault.db.query('outbox',
        where: 'rid = ?', whereArgs: [toRid], orderBy: 'created_ms ASC');
    await a.vault.db.delete('outbox', where: 'rid = ?', whereArgs: [toRid]);
    return [
      for (final r in rows)
        RelayInbound(
            id: r['id'] as String,
            from: '',
            payload: r['payload'] as String,
            serverTs: DateTime.now().millisecondsSinceEpoch)
    ];
  }

  Future<double> timeEach(
      ChatService b, List<RelayInbound> msgs, String label) async {
    final sw = Stopwatch()..start();
    for (final m in msgs) {
      await b.debugInbound(m);
    }
    sw.stop();
    final per = sw.elapsedMicroseconds / 1000.0 / msgs.length;
    // ignore: avoid_print
    print('  ${label.padRight(46)} ${per.toStringAsFixed(2)} ms/message '
        '(${msgs.length})');
    return per;
  }

  Future<void> seedCache(ChatService svc, String rid, int n) async {
    final row = (await svc.vault.db
            .query('conversations', where: 'rid = ?', whereArgs: [rid]))
        .single;
    final state =
        (jsonDecode(await svc.vault.unseal(row['enc_state'] as String)) as Map)
            .cast<String, Object?>();
    final sid = (state['sessions'] as Map).keys.first as String;
    final skipped = {
      sid: {
        for (var i = 0; i < n; i++)
          'seed$i': base64.encode(List.filled(32, i % 251))
      }
    };
    await svc.vault.db.update('conversations',
        {'enc_skipped': await svc.vault.seal(jsonEncode(skipped))},
        where: 'rid = ?', whereArgs: [rid]);
    await svc.reloadConversations();
  }

  /// Two exchanges each way, everything queued fed across. Not counted: the
  /// first messages carry one-off work — the session opening, the device
  /// list, the post-quantum offer — and adding a contact queues a hello of
  /// its own, so "the first envelope" is never just the first message.
  Future<void> bootstrap(
      ChatService a, ChatService b, String bRid, String aRid) async {
    for (var round = 0; round < 2; round++) {
      await a.sendText(bRid, 'hello $round');
      for (final m in await drainOutbox(a, bRid)) {
        await b.debugInbound(m);
      }
      await b.sendText(aRid, 'hello back $round');
      for (final m in await drainOutbox(b, aRid)) {
        await a.debugInbound(m);
      }
    }
  }

  test('receive: in order, out of order, and with a full cache', () async {
    final (a, b, bRid, aRid) = await pair();

    await bootstrap(a, b, bRid, aRid);

    const reps = 40;
    // ignore: avoid_print
    print('receive-side cost, empty cache:');

    // 1. In order: each message advances the receiving chain by one.
    for (var i = 0; i < reps; i++) {
      await a.sendText(bRid, 'in order $i');
    }
    final inOrder = await timeEach(b, await drainOutbox(a, bRid), 'in order');

    // 2. Out of order: the LAST of a batch arrives first. Decrypting it means
    //    stepping the chain past every earlier message and caching their
    //    keys — the cost of creating skipped keys. Then the rest arrive, each
    //    a cache HIT: no chain step, one lookup, one removal.
    const batch = 20;
    for (var i = 0; i < batch; i++) {
      await a.sendText(bRid, 'early/late $i');
    }
    final msgs = await drainOutbox(a, bRid);
    final last = msgs.removeLast();
    final sw = Stopwatch()..start();
    await b.debugInbound(last);
    sw.stop();
    final skipCreating = sw.elapsedMicroseconds / 1000.0;
    // ignore: avoid_print
    print('  ${'one message that skips $batch keys'.padRight(46)} '
        '${skipCreating.toStringAsFixed(2)} ms');
    expect(b.debugSkippedKeyCount(aRid), batch - 1,
        reason: 'the early arrival should have cached one key per message '
            'it stepped past');
    final hits = await timeEach(b, msgs, 'late arrivals (cache hits)');
    expect(b.debugSkippedKeyCount(aRid), 0,
        reason: 'every late arrival consumed its key');

    // 3. The same in-order receive, with the cache at its cap. This is the
    //    cost 15.3 moved off the send path: every receive re-seals the whole
    //    cache. If it is large here, the trade needs a second look.
    //    (1536 is maxSkippedStored in protocol/lib/src/ratchet.dart, which
    //    the package does not export.)
    const cap = 1536;
    await seedCache(b, aRid, cap);
    expect(b.debugSkippedKeyCount(aRid), cap);
    // ignore: avoid_print
    print('receive-side cost, cache at its cap ($cap keys):');
    for (var i = 0; i < reps; i++) {
      await a.sendText(bRid, 'full cache $i');
    }
    final inOrderFull =
        await timeEach(b, await drainOutbox(a, bRid), 'in order, full cache');

    // ignore: avoid_print
    print('\nsummary:');
    // ignore: avoid_print
    print('  in order                ${inOrder.toStringAsFixed(2)} ms');
    // ignore: avoid_print
    print('  skip $batch keys, once     ${skipCreating.toStringAsFixed(2)} ms');
    // ignore: avoid_print
    print('  cache hit               ${hits.toStringAsFixed(2)} ms');
    // ignore: avoid_print
    print('  in order, full cache    ${inOrderFull.toStringAsFixed(2)} ms  '
        '(+${(inOrderFull - inOrder).toStringAsFixed(2)} for the cache)');
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('breakdown: where a receive spends its time', () async {
    final (a, b, bRid, aRid) = await pair();
    await bootstrap(a, b, bRid, aRid);
    // The post-quantum exchange must be complete, or every inbound message
    // would also trigger a "nudge" — a full send — and the numbers below
    // would be measuring that.
    expect(b.assuranceWith(aRid), IdentityAssurance.hybrid,
        reason: 'the pqid exchange did not finish during bootstrap');
    expect(a.assuranceWith(bRid), IdentityAssurance.hybrid);

    const reps = 40;
    for (var i = 0; i < reps; i++) {
      await a.sendText(bRid, 'm $i');
    }
    final msgs = await drainOutbox(a, bRid);

    // Sealed-sender open, on its own: the ephemeral X25519 and the AEAD.
    var sw = Stopwatch()..start();
    for (final m in msgs) {
      final opened = await SealedEnvelope.open(
          myXSeed: b.identity.xSeed, myXPub: b.identity.xPub, blob: m.payload);
      expect(opened, isNotNull);
    }
    sw.stop();
    final open = sw.elapsedMicroseconds / 1000.0 / reps;

    // The whole path, for the same messages.
    sw = Stopwatch()..start();
    for (final m in msgs) {
      await b.debugInbound(m);
    }
    sw.stop();
    final whole = sw.elapsedMicroseconds / 1000.0 / reps;

    // The vault side alone: a sealed conversation write plus a message
    // insert, in one transaction, which is the shape of the receive
    // transaction. Timed by doing exactly that with the live state.
    sw = Stopwatch()..start();
    for (var i = 0; i < reps; i++) {
      await b.vault.db.transaction((txn) async {
        await txn.insert('messages', {
          'mid': 'bench-$i',
          'rid': aRid,
          'outgoing': 0,
          'kind': 'text',
          'enc_body': await b.vault.seal('m $i'),
          'ts_ms': i,
          'status': 1,
          'expire_at_ms': 0,
        });
      });
    }
    sw.stop();
    final insert = sw.elapsedMicroseconds / 1000.0 / reps;

    // The ratchet step alone: sealed-sender open first (not timed), then
    // decrypt on the live conversation. Fresh envelopes, because each one
    // can be decrypted exactly once.
    for (var i = 0; i < reps; i++) {
      await a.sendText(bRid, 'r $i');
    }
    final forRatchet = await drainOutbox(a, bRid);
    final conv = b.debugConversation(aRid)!;
    var ratchetUs = 0;
    for (final m in forRatchet) {
      final opened = await SealedEnvelope.open(
          myXSeed: b.identity.xSeed, myXPub: b.identity.xPub, blob: m.payload);
      final t = Stopwatch()..start();
      await conv.decrypt(opened!.payload);
      t.stop();
      ratchetUs += t.elapsedMicroseconds;
    }
    final ratchet = ratchetUs / 1000.0 / reps;

    // The conversation-state seal a receive writes (hot state, no cache).
    sw = Stopwatch()..start();
    for (var i = 0; i < reps; i++) {
      await b.vault.seal(jsonEncode(conv.toJson(includeSkipped: false)));
    }
    sw.stop();
    final stateSeal = sw.elapsedMicroseconds / 1000.0 / reps;

    // The own-device-list claim ('dl') that every outgoing message is
    // stamped with, and that every inbound message's gossip check reads.
    // Timed alone, with nothing else running.
    sw = Stopwatch()..start();
    for (var i = 0; i < reps; i++) {
      await b.debugOwnListClaim();
    }
    sw.stop();
    final ownClaim = sw.elapsedMicroseconds / 1000.0 / reps;

    // The delivery receipt. Every inbound text triggers one — an outbound
    // send of a tiny 'dlv' inner, unawaited, but it takes the same
    // per-conversation lock the next inbound needs, so a burst of inbound
    // messages pays for it in line. Timed here as the send it is.
    sw = Stopwatch()..start();
    for (var i = 0; i < reps; i++) {
      await b.sendRawInner(
          aRid,
          InnerMessage(kind: 'dlv', mid: newMessageId(), ts: i, data: {
            'mids': ['bench-$i']
          }));
    }
    sw.stop();
    final receipt = sw.elapsedMicroseconds / 1000.0 / reps;

    // ignore: avoid_print
    print('receive breakdown (ms/message):');
    // ignore: avoid_print
    print('  ratchet decrypt              ${ratchet.toStringAsFixed(2)}');
    // ignore: avoid_print
    print('  conversation-state seal      ${stateSeal.toStringAsFixed(2)}');
    // ignore: avoid_print
    print('  own-list claim (per message)  ${ownClaim.toStringAsFixed(2)}');
    // ignore: avoid_print
    print('  delivery receipt (a full send)  ${receipt.toStringAsFixed(2)}');
    // ignore: avoid_print
    print('  sealed-sender open           ${open.toStringAsFixed(2)}');
    // ignore: avoid_print
    print('  message-row transaction      ${insert.toStringAsFixed(2)}');
    // ignore: avoid_print
    print('  whole inbound path           ${whole.toStringAsFixed(2)}');
    // ignore: avoid_print
    print('  remainder (dedupe, bookkeeping, lock, notify) '
        '${(whole - open - insert - receipt - ratchet - stateSeal - ownClaim).toStringAsFixed(2)}');
  }, timeout: const Timeout(Duration(minutes: 5)));
}
