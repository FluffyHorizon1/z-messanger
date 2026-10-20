// What a relay refusal costs the outbox, and what a slow relay costs it.
//
// Five of the relay's refusals name the envelope they are about
// (`too_large`, `bad_send`, `queue_full`, `store_full`, `pow_required`). The
// rest — `rate_limited` above all, and `bad_json`, `internal`, `bad_auth`,
// `not_authed`, `unknown_frame` — arrive with no id, because there is
// nothing in a malformed or out-of-turn frame to attribute. The client
// matched errors to sends by id and simply dropped the ones without, so the
// sender's future stayed pending until its twenty-second timeout, and the
// flush held `_flushing` for all of it: one refusal, twenty seconds of a
// stopped outbox, for every message waiting.
//
// `rate_limited` is not an edge case. It is what a relay says to a client
// that has just come back online with a backlog — exactly when the outbox
// matters most.
//
// And the outbox used to send one envelope and wait for the relay's `sent`
// before the next, so a group text to 128 members — about 166 envelopes —
// took 166 round trips. Since 48.2 (ADR 0036 §3) it keeps up to 32 envelopes
// or 2 MiB in flight — no more payload than ten seconds of what the link has
// been seen to carry — never two to one mailbox, paced under the relay's
// limits, and a refusal holds its own mailbox rather than the outbox.
// Criteria 4–18 are that change. They put a small WebSocket proxy between
// the client and the real relay (`_Proxy`, below), which passes every frame
// through unchanged except that it can hold back the answers to a client's
// sends, in the order they came or each at its own time; can answer a send
// itself with exactly the error frame the relay sends (§12.2), in which case
// the relay never sees that envelope — which is what a refusal is; can pass
// the client's frames on no faster than a slow uplink would; and can drop a
// connection.
// Nothing in the client is replaced — the Transport, the RelayClient and the
// outbox are the shipped ones, and the relay is the real one, unchanged — and
// what the proxy counts (envelopes in flight, to each mailbox, in a second)
// is read off the wire, where a relay would count it.
//
// Criteria, each a test below:
//  1. a refusal the relay cannot attribute to one send fails that send at
//     once rather than after the send timeout;
//  2. a rate-limited pass comes back on its own timer and the messages
//     arrive, without waiting for a reconnect that may never come;
//  3. a permanently refused envelope marks ITS OWN message failed — named
//     by the row's mid and thread, not by the envelope id and the mailbox,
//     which stopped being the same string when the envelope id was
//     separated from the message id;
//  4. pipelining: with every answer held back 200 ms, 48 envelopes to 48
//     mailboxes take well under 48 × 200 ms — about that long on a build
//     that waited for each — and never are more than 32 envelopes, or more
//     than 2 MiB of payload, in flight;
//  5. one per mailbox: rows to one mailbox are never two in flight, and
//     they reach it in order, under a slow relay and under refusals of
//     every kind;
//  6. `store_full` holds its own mailbox for the pass while the rest of the
//     outbox drains; eight in a row, from different mailboxes, end the
//     pass, and the retry timer brings it back; more than eight in all,
//     with mailboxes the relay takes between them, do not end it;
//  7. `rate_limited` backs off from one second, doubling to the cap, and
//     starts from one second again once something has been sent;
//  8. a refusal that names no envelope, with several in flight: every one
//     of them goes again, and each receiver shows each message once;
//  9. pacing: never more than a burst of 192 sends, then 64 a second,
//     measured at the proxy — and the relay, at 80 and 240, refuses none;
//  10. the snapshot rule: with mailboxes interleaving, each member's
//     mailbox has taken a membership change before the next group message
//     to it is sent, and the member who was added reads that message;
//  11. a link dropped with envelopes in flight: every unacknowledged row
//     goes again once the link is back, and nothing is lost;
//  12. a slow uplink: five envelopes of a file chunk's size to five
//     mailboxes at 50 000 characters a second — nothing in flight times
//     out that one at a time would not have, nothing goes twice, and no
//     more is ever out than ten seconds of the link, or one envelope;
//  13. a row queued while the pass waits on an answer goes at once, not
//     when that answer comes;
//  14. a pass a refusal has stopped still waits for what it has out, and a
//     flush asked for meanwhile sends none of it again;
//  15. one retry timer, and the sooner wins: a rate limit after a held
//     mailbox comes back in a second, not when the hold's retry is due;
//  16. after a refusal that names nothing, the next pass starts from one in
//     flight and widens by one for each envelope the relay takes;
//  17. `pow_required` on an outbox row holds its own mailbox, not the
//     outbox;
//  18. answers out of order: eight `store_full`s in a row still end the
//     pass, seven among the rest do not, and one per mailbox holds.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:flutter_test/flutter_test.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/models.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  final temps = <Directory>[];
  final live = <ChatService>[];
  final relays = <Process>[];
  final proxies = <_Proxy>[];

  tearDownAll(() async {
    for (final s in live) {
      await s.transport.stop();
      await s.vault.db.close();
    }
    for (final p in proxies) {
      await p.close();
    }
    for (final r in relays) {
      r.kill();
    }
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<int> startRelay(Map<String, String> env) async {
    final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final port = probe.port;
    await probe.close();
    relays.add(await Process.start('node', ['server.js'],
        workingDirectory:
            '${Directory.current.parent.path}${Platform.pathSeparator}server',
        environment: {'PORT': '$port', 'LOG_LEVEL': 'silent', ...env}));
    for (var i = 0; i < 80; i++) {
      try {
        final res = await (await HttpClient()
                .getUrl(Uri.parse('http://127.0.0.1:$port/health')))
            .close();
        await res.drain<void>();
        if (res.statusCode == 200) return port;
      } catch (_) {
        await Future<void>.delayed(const Duration(milliseconds: 100));
      }
    }
    fail('relay did not start');
  }

  Future<ChatService> person(String name, int port) async {
    final dir = await Directory.systemTemp.createTemp('z_stall_');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    final me = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(me.toJson()));
    final transport =
        Transport(identity: me, serverUrl: 'ws://127.0.0.1:$port');
    final svc = await ChatService.init(
        vault: vault, identity: me, displayName: name, transport: transport);
    live.add(svc);
    for (var i = 0; i < 80 && !transport.isConnected; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    return svc;
  }

  // ---- 48.2's fixtures ------------------------------------------------------

  Future<void> waitUntil(bool Function() cond,
      {Duration timeout = const Duration(seconds: 30), String what = ''}) async {
    final deadline = DateTime.now().add(timeout);
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
  }

  Future<void> waitFor(Future<bool> Function() cond,
      {Duration timeout = const Duration(seconds: 30), String what = ''}) async {
    final deadline = DateTime.now().add(timeout);
    while (!await cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
  }

  Future<int> outboxCount(ChatService svc) async =>
      firstIntValue(
          await svc.vault.db.rawQuery('SELECT COUNT(*) FROM outbox')) ??
      0;

  Future<_Proxy> startProxy(int relayPort) async {
    final p = await _Proxy.start(relayPort);
    proxies.add(p);
    return p;
  }

  /// Someone with an app whose links both go to [url] — the relay itself, or
  /// a proxy in front of it — and are both up.
  Future<ChatService> personAt(String name, String url) async {
    final dir = await Directory.systemTemp.createTemp('z_stall_');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    final me = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(me.toJson()));
    final transport = Transport(identity: me, serverUrl: url);
    final svc = await ChatService.init(
        vault: vault, identity: me, displayName: name, transport: transport);
    live.add(svc);
    await waitUntil(
        () => transport.isConnected && transport.isSenderConnected,
        what: '$name connected');
    return svc;
  }

  /// A mailbox nobody holds: the relay keeps what is sent to it, and that
  /// is all.
  String nobody() => b64url(randomBytes(32));

  /// An envelope written straight into [svc]'s outbox, as the app writes a
  /// chunk's: no message behind it, sealed by its prefix — so it leaves on
  /// the anonymous link — and opaque to the relay, which reads only that.
  Future<String> queueRaw(ChatService svc, String to,
      {String? payload}) async {
    final id = newMessageId();
    await svc.vault.db.insert('outbox', {
      'id': id,
      'rid': to,
      'payload': payload ?? 'zs1.${newMessageId()}',
      'created_ms': DateTime.now().millisecondsSinceEpoch,
    });
    return id;
  }

  Future<void> introduce(ChatService a, ChatService b) async {
    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());
  }

  /// Everyone who added each other has finished introducing themselves —
  /// each holds the other's post-quantum key — and nobody has anything left
  /// to send: `settled()` in `group_test.dart`, whose comments carry the
  /// reasoning.
  Future<void> settled(List<ChatService> people) async {
    final deadline = DateTime.now().add(const Duration(seconds: 30));
    while (true) {
      var done = true;
      for (final s in people) {
        for (final o in people) {
          if (identical(s, o)) continue;
          final c = s.contacts[o.myRid];
          if (c == null) continue;
          if (c.pqPub == null && c.pqCandidate == null) done = false;
        }
      }
      if (done) {
        for (final s in people) {
          if (await outboxCount(s) > 0) {
            done = false;
            break;
          }
        }
      }
      if (done && people.every((s) => !s.pqSendPending)) return;
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('the contacts never settled');
      }
      await Future<void>.delayed(const Duration(milliseconds: 30));
    }
  }

  /// The texts [svc] holds from [rid], in the order it took them.
  List<String> textsFrom(ChatService svc, String rid) => [
        for (final m in svc.messagesByChat[rid] ?? const <ChatMessage>[])
          if (!m.outgoing && m.kind == 'text') m.body
      ];

  List<String> groupTexts(ChatService svc, String gid) => [
        for (final m in svc.messagesByChat[gid] ?? const <ChatMessage>[])
          if (m.kind == 'gtext') m.body
      ];

  /// What a mailbox holds, in the relay's order, read as its owner and
  /// acknowledged to nobody: once at least [distinct] different payloads
  /// have come.
  Future<List<String>> readMailbox(
      int port, ZIdentity owner, int distinct) async {
    final c = await RelayClient.connect('ws://127.0.0.1:$port', owner);
    final got = <String>[];
    final sub = c.messages.listen((m) => got.add(m.payload));
    try {
      await waitUntil(() => got.toSet().length >= distinct,
          what: 'the mailbox flushed');
    } finally {
      await sub.cancel();
      await c.close();
    }
    return got;
  }

  /// [svc]'s link has carried an envelope and the relay has answered it, so
  /// the outbox knows the link's rate: until then one envelope goes at a
  /// time (48.2), and a criterion about several in flight starts from here.
  Future<void> warm(ChatService svc) async {
    await queueRaw(svc, nobody());
    await svc.flushOutbox();
    await waitFor(() async => await outboxCount(svc) == 0,
        what: 'the link carried one envelope');
    await waitUntil(() => !svc.debugOutboxPassRunning,
        what: 'and that pass ended');
  }

  test('1. an unattributable refusal fails the send at once', () async {
    // One frame per second, so a handful of sends in a row is refused with
    // `rate_limited` — which carries no id, because the relay refuses the
    // frame before it has read one.
    final port = await startRelay({'RATE_PER_SEC': '1', 'RATE_BURST': '4'});
    final client =
        await RelayClient.connect('ws://127.0.0.1:$port', await ZIdentity.generate());
    final to = await (await ZIdentity.generate()).routingId();

    Object? refusal;
    final began = DateTime.now();
    for (var i = 0; i < 12 && refusal == null; i++) {
      try {
        await client.send(to: to, id: newMessageId(), payload: 'zs1.x$i');
      } catch (e) {
        refusal = e;
      }
    }
    final took = DateTime.now().difference(began);
    await client.close();

    expect(refusal, isA<RelayException>(),
        reason: 'the relay did refuse something');
    expect('$refusal', contains('rate_limited'),
        reason: 'and the sender is told which refusal it was');
    expect(took.inSeconds, lessThan(15),
        reason: 'not the twenty-second send timeout: the refusal is immediate');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('2. a rate-limited pass comes back on its own timer', () async {
    final port = await startRelay({'RATE_PER_SEC': '2', 'RATE_BURST': '6'});
    final alice = await person('Alice', port);
    final bobId = await ZIdentity.generate();
    final bobRid = await bobId.routingId();
    await alice.addContactFromCode(
        (await bobId.bundle(displayName: 'Bob')).encode(),
        alias: 'Bob');
    alice.outboxRetryDelay = const Duration(milliseconds: 400);

    // A backlog, which is exactly when a relay says slow down.
    for (var i = 0; i < 12; i++) {
      await alice.sendText(bobRid, 'backlog $i');
    }

    // No reconnect happens in this window: the link stays up throughout, so
    // anything that drains does so because the retry timer brought it back.
    final began = DateTime.now();
    var left = 1;
    while (left > 0 && DateTime.now().difference(began).inSeconds < 90) {
      await Future<void>.delayed(const Duration(milliseconds: 500));
      left = firstIntValue(await alice.vault.db
              .rawQuery('SELECT COUNT(*) FROM outbox')) ??
          0;
    }
    expect(alice.transport.isConnected, isTrue,
        reason: 'no reconnect was needed or used');
    expect(left, 0, reason: 'the backlog drains under a rate limit');
  }, timeout: const Timeout(Duration(minutes: 4)));

  test('3. a permanently refused envelope fails its own message', () async {
    // `bad_send` rather than `too_large`, because a size cap small enough to
    // refuse a text message is also small enough that the WebSocket refuses
    // the FRAME (`maxPayload` is the cap plus 4 KiB) and kills the socket —
    // which is a different failure with a different answer. An address the
    // relay will not accept gets the same permanent refusal, and it is the
    // one this line is about.
    final port = await startRelay({});
    final alice = await person('Alice', port);
    final bobId = await ZIdentity.generate();
    final bobRid = await bobId.routingId();
    await alice.addContactFromCode(
        (await bobId.bundle(displayName: 'Bob')).encode(),
        alias: 'Bob');
    await alice.sendText(bobRid, 'this one is fine');
    for (var i = 0; i < 20; i++) {
      await alice.flushOutbox();
      await Future<void>.delayed(const Duration(milliseconds: 150));
    }

    // A message whose envelope the relay will refuse outright. The row names
    // the message it carries; the envelope id and the mailbox are somebody
    // else's business, and reading them as the message is what this fixes.
    const mid = 'a-message-of-mine';
    await alice.vault.db.insert('messages', {
      'mid': mid,
      'rid': bobRid,
      'outgoing': 1,
      'kind': 'text',
      'enc_body': await alice.vault.seal(jsonEncode({'b': 'undeliverable'})),
      'ts_ms': DateTime.now().millisecondsSinceEpoch,
      'status': MsgStatus.pending,
      'expire_at_ms': 0,
    });
    await alice.vault.db.insert('outbox', {
      'id': newMessageId(),
      'mid': mid,
      'thread_rid': bobRid,
      'rid': 'not a routing id at all',
      'payload': 'zs1.whatever',
      'created_ms': DateTime.now().millisecondsSinceEpoch,
    });

    for (var i = 0; i < 30; i++) {
      await alice.flushOutbox();
      final rows = await alice.vault.db.query('messages',
          columns: ['status'], where: 'mid = ?', whereArgs: [mid]);
      if (rows.first['status'] as int == -1) break;
      await Future<void>.delayed(const Duration(milliseconds: 150));
    }
    final status = (await alice.vault.db
            .query('messages', columns: ['status'], where: 'mid = ?', whereArgs: [mid]))
        .single['status'] as int;
    expect(status, -1,
        reason: 'the message the refused envelope carried is marked failed');
    expect(
        await alice.vault.db
            .query('outbox', where: 'mid = ?', whereArgs: [mid]),
        isEmpty,
        reason: 'and it is not retried for ever');

    // The message that was fine is untouched: a refusal names one envelope.
    final other = await alice.vault.db.query('messages',
        columns: ['status'],
        where: 'rid = ? AND outgoing = 1 AND mid != ?',
        whereArgs: [bobRid, mid]);
    expect(other.every((r) => (r['status'] as int) >= MsgStatus.sent), isTrue,
        reason: 'the other message is not collateral');
  }, timeout: const Timeout(Duration(minutes: 4)));

  test(
      '4. pipelining: N envelopes take well under N round trips, and never '
      'more than 32 or 2 MiB are in flight', () async {
    const n = 48;
    const held = Duration(milliseconds: 200);
    final port = await startRelay({
      // The large envelopes at the end go to mailboxes nobody owns, which the
      // relay budgets by address; that budget is not what this is about.
      'UNOWNED_BYTES_PER_IP_PER_MIN': '${64 * 1024 * 1024}',
    });
    final proxy = await startProxy(port);
    final alice = await personAt('Alice', proxy.url);
    final rids = <String>[];
    for (var i = 0; i < n; i++) {
      final id = await ZIdentity.generate();
      final c = await alice.addContactFromCode(
          (await id.bundle(displayName: 'M$i')).encode(),
          alias: 'M$i');
      rids.add(c.rid);
    }
    // A first message to each, unhurried. A first message carries the
    // post-quantum offer with it (§17.4), so what is timed below is one
    // envelope to each mailbox and nothing else.
    for (final r in rids) {
      await alice.sendText(r, 'first');
    }
    await waitFor(() async => await outboxCount(alice) == 0,
        timeout: const Duration(seconds: 90), what: 'the first messages left');

    // The second, written while the link is down, so the pass meets them all
    // at once.
    await alice.transport.stop();
    for (final r in rids) {
      await alice.sendText(r, 'second');
    }
    final queued = await alice.vault.db.query('outbox', columns: ['rid']);
    expect(queued.length, n, reason: 'one envelope to each mailbox');
    expect(queued.map((r) => r['rid']).toSet().length, n);

    proxy.reset();
    proxy.replyDelay = held;
    final clock = Stopwatch()..start();
    alice.transport.start();
    await waitFor(() async => await outboxCount(alice) == 0,
        timeout: const Duration(seconds: 90), what: 'the second messages left');
    final took = clock.elapsed;
    // ignore: avoid_print
    print('48.2 pipelining: $n envelopes to $n mailboxes, every answer held '
        '${held.inMilliseconds} ms: ${took.inMilliseconds} ms (N × d = '
        '${n * held.inMilliseconds} ms), at most ${proxy.maxOpen} in flight');
    expect(took, lessThan(held * (n ~/ 4)),
        reason: 'well under one round trip an envelope: ${took.inMilliseconds} '
            'ms against ${n * held.inMilliseconds}');
    expect(proxy.maxOpen, greaterThan(1),
        reason: 'several envelopes were in flight at once');
    expect(proxy.maxOpen, lessThanOrEqualTo(32),
        reason: 'and never more than 32');

    // The window's other bound: six envelopes of 450 000 characters, which
    // 2 MiB holds four of, each answer held long enough that all six would
    // be out at once without it.
    proxy.reset();
    proxy.replyDelay = const Duration(milliseconds: 400);
    for (var i = 0; i < 6; i++) {
      await queueRaw(alice, nobody(), payload: 'zs1.${'x' * 450000}');
    }
    await alice.flushOutbox();
    await waitFor(() async => await outboxCount(alice) == 0,
        timeout: const Duration(seconds: 60), what: 'the large ones left');
    // ignore: avoid_print
    print('48.2 pipelining: six of 450 000 characters, at most '
        '${proxy.maxOpen} in flight, ${proxy.maxOpenBytes} characters');
    expect(proxy.maxOpen, greaterThan(1));
    expect(proxy.maxOpenBytes, lessThanOrEqualTo(2 * 1024 * 1024),
        reason: 'never more than 2 MiB of payload in flight');
  }, timeout: const Timeout(Duration(minutes: 5)));

  test(
      '5. one per mailbox: never two in flight to one, and each takes its '
      'rows in order, under a slow relay and refusals of every kind', () async {
    const m = 6, k = 8;
    final port = await startRelay({});
    final proxy = await startProxy(port);
    final alice = await personAt('Alice', proxy.url);
    alice.outboxRetryDelay = const Duration(seconds: 1);
    final owners = [for (var i = 0; i < m; i++) await ZIdentity.generate()];
    final boxes = [for (final o in owners) await o.routingId()];
    // Written while the link is down, a round at a time across every mailbox
    // — as a fan-out writes them — so the outbox interleaves the mailboxes.
    await alice.transport.stop();
    final ids = <(int, int), String>{};
    for (var j = 0; j < k; j++) {
      for (var i = 0; i < m; i++) {
        ids[(i, j)] = await queueRaw(alice, boxes[i], payload: 'zs1.$i.$j');
      }
    }
    // Each attributed refusal once, the first time its envelope is tried;
    // and, the first time six are in flight, one that names none of them.
    final once = {
      ids[(1, 2)]!: 'queue_full',
      ids[(2, 4)]!: 'store_full',
      ids[(3, 1)]!: 'pow_required',
    };
    var unnamed = false;
    proxy.replyDelay = const Duration(milliseconds: 40);
    proxy.answer = (link, f) {
      final id = f['id'] as String;
      final code = once.remove(id);
      if (code != null) {
        return {
          't': 'error',
          'code': code,
          'id': id,
          if (code == 'pow_required') ...{'bits': 20, 'day': 20000},
        };
      }
      if (!unnamed && link.openCount >= m) {
        unnamed = true;
        return {'t': 'error', 'code': 'rate_limited'};
      }
      return null;
    };
    alice.transport.start();
    await waitFor(() async => await outboxCount(alice) == 0,
        timeout: const Duration(seconds: 60), what: 'every row left');

    expect(once, isEmpty, reason: 'every refusal was met');
    expect(unnamed, isTrue,
        reason: 'six were in flight at once, and one refusal named none');
    for (var i = 0; i < m; i++) {
      expect(proxy.maxOpenPerMailbox[boxes[i]], 1,
          reason: 'mailbox $i never had two in flight');
    }
    for (var i = 0; i < m; i++) {
      final got = await readMailbox(port, owners[i], k);
      final rounds = [for (final p in got) int.parse(p.split('.').last)];
      expect(rounds.toSet(), {for (var j = 0; j < k; j++) j},
          reason: 'mailbox $i took every row');
      for (var x = 1; x < rounds.length; x++) {
        // A row sent again after a refusal that named nothing lands straight
        // after its first copy, never after a later row.
        expect(rounds[x], greaterThanOrEqualTo(rounds[x - 1]),
            reason: 'mailbox $i took its rows in order: $rounds');
      }
    }
  }, timeout: const Timeout(Duration(minutes: 3)));

  test(
      '6. store_full holds its own mailbox; eight in a row end the pass and '
      'the retry brings it back; more, with others taken between, do not',
      () async {
    final port = await startRelay({});
    final proxy = await startProxy(port);
    final alice = await personAt('Alice', proxy.url);

    // (a) One mailbox the store refuses, among four it takes.
    alice.outboxRetryDelay = const Duration(seconds: 4);
    final boxes = [for (var i = 0; i < 5; i++) nobody()];
    var full = true;
    proxy.answer = (link, f) => full && f['to'] == boxes[0]
        ? {'t': 'error', 'code': 'store_full', 'id': f['id']}
        : null;
    for (var j = 0; j < 3; j++) {
      for (final b in boxes) {
        await queueRaw(alice, b);
      }
    }
    await alice.flushOutbox();
    // In the one pass, well before its retry, everyone else's rows went.
    await waitFor(() async {
      final left = await alice.vault.db.query('outbox', columns: ['rid']);
      return left.length == 3 && left.every((r) => r['rid'] == boxes[0]);
    },
        timeout: const Duration(milliseconds: 2500),
        what: 'every mailbox but the refused one drained in the pass');
    expect(proxy.sendsTo(boxes[0]).length, 1,
        reason: 'the refused mailbox was held for the pass, not tried again');
    full = false;
    await waitFor(() async => await outboxCount(alice) == 0,
        timeout: const Duration(seconds: 15),
        what: 'the held mailbox drained on the retry');
    final tries = proxy.sendsTo(boxes[0]).toList();
    expect(tries[1].at - tries[0].at,
        greaterThanOrEqualTo(const Duration(milliseconds: 3900)),
        reason: 'it came back on the retry timer, and nothing sooner');

    // (b) The store refusing everyone: eight refusals in a row end the pass
    // before it has tried every mailbox, and the timer brings it back — by
    // when, here, the store has room again.
    proxy.reset();
    alice.outboxRetryDelay = const Duration(seconds: 3);
    final many = [for (var i = 0; i < 48; i++) nobody()];
    var refusing = true;
    Duration? previous;
    proxy.answer = (link, f) {
      final now = proxy.clock.elapsed;
      // The first send after a pause of over a second and a half opens the
      // next pass, which only the retry timer starts here.
      final last = previous;
      if (last != null && now - last > const Duration(milliseconds: 1500)) {
        refusing = false;
      }
      previous = now;
      return refusing
          ? {'t': 'error', 'code': 'store_full', 'id': f['id']}
          : null;
    };
    for (final b in many) {
      await queueRaw(alice, b);
    }
    await alice.flushOutbox();
    await waitFor(() async => await outboxCount(alice) == 0,
        timeout: const Duration(seconds: 20),
        what: 'all of them went once the store had room');
    final sends = proxy.sends;
    final cut = [
      for (var i = 1; i < sends.length; i++)
        if (sends[i].at - sends[i - 1].at >
            const Duration(milliseconds: 1500))
          i
    ].first;
    final firstPass = {for (final s in sends.take(cut)) s.to};
    // ignore: avoid_print
    print('48.2 store_full: the store refusing everyone, the first pass '
        'tried ${firstPass.length} of ${many.length} mailboxes');
    expect(firstPass.length, lessThan(many.length),
        reason: 'eight refusals in a row ended the pass');
    expect(firstPass.length, lessThanOrEqualTo(32 + 7),
        reason: 'what was in flight, and one more for each of the seven '
            'refusals before the eighth');
    expect(sends[cut].at - sends[cut - 1].at,
        greaterThanOrEqualTo(const Duration(milliseconds: 2900)),
        reason: 'it came back on the retry timer');

    // (c) The relay's own first-contact gate, which refuses only mailboxes
    // it has not seen (§12.4): ten of them refused in the one pass, but the
    // relay taking a mailbox it knows between them, so never eight in a row
    // — and the pass goes on to the end.
    final gated = await startRelay({'NEW_MAILBOX_PER_MIN': '10'});
    final proxy2 = await startProxy(gated);
    final ben = await personAt('Ben', proxy2.url);
    ben.outboxRetryDelay = const Duration(seconds: 60);
    final known = [for (var i = 0; i < 8; i++) nobody()];
    for (final b in known) {
      await queueRaw(ben, b);
    }
    await ben.flushOutbox();
    await waitFor(() async => await outboxCount(ben) == 0,
        what: 'eight of the gate\'s ten went on these');
    final fresh = [for (var i = 0; i < 12; i++) nobody()];
    for (var i = 0; i < 8; i++) {
      await queueRaw(ben, known[i]);
      await queueRaw(ben, fresh[i]);
    }
    for (var i = 8; i < 12; i++) {
      await queueRaw(ben, fresh[i]);
    }
    for (var j = 0; j < 2; j++) {
      for (final b in known) {
        await queueRaw(ben, b);
      }
    }
    proxy2.reset();
    await ben.flushOutbox();
    await waitFor(() async {
      final left = await ben.vault.db.query('outbox', columns: ['rid']);
      return left.every((r) => !known.contains(r['rid']));
    },
        timeout: const Duration(seconds: 10),
        what: 'every known mailbox drained in the one pass');
    final refused = proxy2.answered['store_full'] ?? 0;
    final left = await ben.vault.db.query('outbox', columns: ['rid']);
    // ignore: avoid_print
    print('48.2 store_full: the gate refused $refused fresh mailboxes, '
        'interleaved with ${known.length} it knew; ${left.length} rows held');
    expect(refused, greaterThanOrEqualTo(8),
        reason: 'eight refusals or more in all');
    expect(left.length, refused,
        reason: 'each refused mailbox held its one row, and nothing else '
            'waited');
    expect(left.every((r) => fresh.contains(r['rid'])), isTrue);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test(
      '7. rate_limited backs off from one second, doubling to the cap, and '
      'from one second again once something is sent', () async {
    final port = await startRelay({});
    final proxy = await startProxy(port);
    final alice = await personAt('Alice', proxy.url);
    alice.outboxRetryDelay = const Duration(seconds: 4);
    var limited = true;
    proxy.answer = (link, f) =>
        limited ? {'t': 'error', 'code': 'rate_limited'} : null;
    await queueRaw(alice, nobody());
    await alice.flushOutbox();
    await waitUntil(() => proxy.sends.length >= 5,
        timeout: const Duration(seconds: 40), what: 'five tries, each refused');
    final tries = [for (final s in proxy.sends.take(5)) s.at];
    final gaps = [
      for (var i = 1; i < tries.length; i++)
        (tries[i] - tries[i - 1]).inMilliseconds
    ];
    // ignore: avoid_print
    print('48.2 rate_limited: tries $gaps ms apart');
    const want = [1000, 2000, 4000, 4000];
    for (var i = 0; i < want.length; i++) {
      expect(gaps[i], greaterThanOrEqualTo(want[i] - 50),
          reason: 'try ${i + 2} waited its backoff of ${want[i]} ms: $gaps');
      expect(gaps[i], lessThan(want[i] + 1500),
          reason: 'and not much longer: $gaps');
    }
    // The relay lets it through, and the next try sends it: something sent.
    limited = false;
    await waitFor(() async => await outboxCount(alice) == 0,
        timeout: const Duration(seconds: 15), what: 'the row left');
    limited = true;
    final before = proxy.sends.length;
    await queueRaw(alice, nobody());
    await alice.flushOutbox(); // what a new message does
    await waitUntil(() => proxy.sends.length >= before + 2,
        timeout: const Duration(seconds: 20), what: 'two more tries');
    final again =
        (proxy.sends[before + 1].at - proxy.sends[before].at).inMilliseconds;
    // ignore: avoid_print
    print('48.2 rate_limited: after a send, the next backoff was $again ms');
    expect(again, greaterThanOrEqualTo(950));
    expect(again, lessThan(2500),
        reason: 'one second again, not the four it had reached: $again ms');
    limited = false;
    await waitFor(() async => await outboxCount(alice) == 0,
        timeout: const Duration(seconds: 15), what: 'the second row left');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test(
      '8. a refusal naming no envelope, with several in flight: every one '
      'goes again, and each receiver shows each message once', () async {
    final port = await startRelay({});
    final toAlice = await startProxy(port);
    final toThem = await startProxy(port);
    final alice = await personAt('Alice', toAlice.url);
    const names = ['Bob', 'Carol', 'Dave', 'Erin', 'Fay'];
    final them = <ChatService>[];
    for (final n in names) {
      final p = await personAt(n, toThem.url);
      await introduce(alice, p);
      them.add(p);
    }
    await settled([alice, ...them]);

    // Written while the link is down, so the pass meets them all at once.
    await alice.transport.stop();
    for (var j = 1; j <= 3; j++) {
      for (var i = 0; i < them.length; i++) {
        await alice.sendText(them[i].myRid, '$j to ${names[i]}');
      }
    }
    toAlice.reset();
    toAlice.replyDelay = const Duration(milliseconds: 150);
    Set<String>? failed;
    toAlice.answer = (link, f) {
      if (failed == null && link.openCount >= them.length) {
        failed = link.openIds;
        return {'t': 'error', 'code': 'rate_limited'};
      }
      return null;
    };
    final mark = {for (final l in toThem.links) l: l.msgIds.length};
    alice.transport.start();
    await waitUntil(() => failed != null,
        what: 'five in flight when the relay refused one, naming none');
    await waitFor(() async => await outboxCount(alice) == 0,
        timeout: const Duration(seconds: 60), what: 'everything left');
    for (final id in failed!) {
      expect(toAlice.sends.where((s) => s.id == id).length,
          greaterThanOrEqualTo(2),
          reason: 'envelope $id, failed by the refusal, went again');
    }
    for (var i = 0; i < them.length; i++) {
      await waitUntil(() => textsFrom(them[i], alice.myRid).length >= 3,
          what: '${names[i]} has all three');
    }
    // Nothing more is on its way: every envelope the relay pushed to each of
    // them has been acknowledged.
    await waitUntil(() => toThem.links.every((l) => l.recvs >= l.msgs),
        what: 'everything delivered was acknowledged');
    for (var i = 0; i < them.length; i++) {
      expect(textsFrom(them[i], alice.myRid),
          ['1 to ${names[i]}', '2 to ${names[i]}', '3 to ${names[i]}'],
          reason: '${names[i]} shows each message once, in order');
    }
    var copies = 0;
    for (final l in toThem.links) {
      final since = l.msgIds.sublist(mark[l] ?? 0);
      copies += since.length - since.toSet().length;
    }
    // ignore: avoid_print
    print('48.2 unattributed refusal: ${failed!.length} failed at once; '
        '$copies second copies reached the receivers and were dropped there');
    expect(copies, greaterThan(0),
        reason: 'the relay had taken some before the refusal: their second '
            'copies reached the receivers, who dropped them (§6.7)');
    expect(
        alice.messagesByChat.values.expand((l) => l).where((m) => m.status == -1),
        isEmpty,
        reason: 'and nothing was failed');
  }, timeout: const Timeout(Duration(minutes: 4)));

  test(
      '9. pacing: never more than a burst of 192, then 64 a second, at the '
      'proxy — and the relay refuses none', () async {
    final port = await startRelay({});
    final proxy = await startProxy(port);
    final alice = await personAt('Alice', proxy.url);
    final boxes = [for (var i = 0; i < 50; i++) nobody()];
    for (var j = 0; j < 8; j++) {
      for (final b in boxes) {
        await queueRaw(alice, b);
      }
    }
    proxy.reset();
    await alice.flushOutbox();
    await waitFor(() async => await outboxCount(alice) == 0,
        timeout: const Duration(seconds: 60), what: 'all 400 left');
    final at = [for (final s in proxy.sends) s.at.inMicroseconds / 1e6];
    // Over every span of sends, how far the count exceeds what the pace
    // allows in that time: 192 at once, and 64 a second on top.
    var worst = double.negativeInfinity;
    for (var i = 0; i < at.length; i++) {
      for (var j = i; j < at.length; j++) {
        worst = max(worst, (j - i + 1) - (192 + 64 * (at[j] - at[i])));
      }
    }
    // ignore: avoid_print
    print('48.2 pacing: 400 sends in ${(at.last - at.first).toStringAsFixed(2)} '
        's; the 192nd at ${(at[191] - at.first).toStringAsFixed(2)} s; the '
        'worst span exceeds the allowance by ${worst.toStringAsFixed(1)}');
    expect(worst, lessThanOrEqualTo(3),
        reason: 'no span carries more than 192 + 64 a second (and three '
            'for the wire\'s own jitter)');
    expect(proxy.answered['rate_limited'] ?? 0, 0,
        reason: 'and the relay, at 80 a second with a burst of 240, refused '
            'nothing');
    expect(at.length, 400,
        reason: 'so each went once: nothing was refused and sent again');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test(
      '10. the snapshot rule: each member\'s mailbox has taken a membership '
      'change before the next group message to it is sent', () async {
    final port = await startRelay({});
    final toAlice = await startProxy(port);
    final alice = await personAt('Alice', toAlice.url);
    final direct = 'ws://127.0.0.1:$port';
    const names = ['Bob', 'Carol', 'Dave'];
    final them = [for (final n in names) await personAt(n, direct)];
    for (final p in them) {
      await introduce(alice, p);
    }
    await settled([alice, ...them]);
    final [bob, carol, dave] = them;
    final gid = await alice.createGroup('Four', [bob.myRid, carol.myRid]);
    await waitUntil(
        () => bob.groups.containsKey(gid) && carol.groups.containsKey(gid),
        what: 'the group reached its members');
    await alice.waitForGroupFanout(gid);
    // Alice has nothing left to send. (Not `settled` over all four: Bob and
    // Carol now hold each other, adopted from the list, and never speak, so
    // neither ever has the other's post-quantum key to wait for.)
    await waitFor(
        () async => await outboxCount(alice) == 0 && !alice.pqSendPending,
        what: 'Alice\'s outbox is empty');

    // Dave is added and a message follows at once, both written while the
    // link is down so the pass meets them together.
    await alice.transport.stop();
    expect(await alice.addGroupMembers(gid, [dave.myRid]), isNull);
    await alice.sendGroupText(gid, 'after the add');
    await alice.waitForGroupFanout(gid);
    final textMid = (await alice.vault.db.query('messages',
            columns: ['mid'],
            where: 'rid = ? AND kind = ? AND outgoing = 1',
            whereArgs: [gid, 'gtext']))
        .single['mid'] as String;
    final rows = await alice.vault.db.query('outbox', orderBy: 'seq');
    final listIds = <String, String>{};
    final textIds = <String, String>{};
    for (var i = 0; i < them.length; i++) {
      final rid = them[i].myRid;
      final mine = rows.where((r) => r['rid'] == rid).toList();
      final list = mine
          .firstWhere((r) => r['thread_rid'] == gid && r['mid'] != textMid);
      final text = mine.firstWhere((r) => r['mid'] == textMid);
      expect(list['seq'] as int, lessThan(text['seq'] as int),
          reason: '${names[i]}\'s list is queued ahead of the message');
      listIds[rid] = list['id'] as String;
      textIds[rid] = text['id'] as String;
    }
    toAlice.reset();
    toAlice.replyDelay = const Duration(milliseconds: 120);
    alice.transport.start();
    await waitFor(() async => await outboxCount(alice) == 0,
        timeout: const Duration(seconds: 60), what: 'everything left');
    expect(toAlice.maxOpen, greaterThan(1),
        reason: 'the mailboxes interleaved: several were in flight at once');
    for (var i = 0; i < them.length; i++) {
      final rid = them[i].myRid;
      final list = toAlice.sends.firstWhere((s) => s.id == listIds[rid]);
      final text = toAlice.sends.firstWhere((s) => s.id == textIds[rid]);
      expect(list.settledAt, isNotNull);
      expect(text.at, greaterThan(list.settledAt!),
          reason: 'the message to ${names[i]} went only once the relay had '
              'taken the list before it');
    }
    await waitUntil(
        () => them.every((p) => groupTexts(p, gid).contains('after the add')),
        what: 'every member, Dave included, reads it in the group');
    expect(dave.groups[gid]!.memberRids,
        containsAll([alice.myRid, bob.myRid, carol.myRid]));
  }, timeout: const Timeout(Duration(minutes: 4)));

  test(
      '11. a link dropped with envelopes in flight: every unacknowledged row '
      'goes again once it is back, and nothing is lost', () async {
    final port = await startRelay({});
    final toAlice = await startProxy(port);
    final toThem = await startProxy(port);
    final alice = await personAt('Alice', toAlice.url);
    const names = ['Bob', 'Carol', 'Dave', 'Erin', 'Fay'];
    final them = <ChatService>[];
    for (final n in names) {
      final p = await personAt(n, toThem.url);
      await introduce(alice, p);
      them.add(p);
    }
    await settled([alice, ...them]);

    await alice.transport.stop();
    for (var j = 1; j <= 3; j++) {
      for (var i = 0; i < them.length; i++) {
        await alice.sendText(them[i].myRid, '$j to ${names[i]}');
      }
    }
    toAlice.reset();
    toAlice.replyDelay = const Duration(milliseconds: 300);
    Set<String>? unanswered;
    var droppedAt = 0;
    toAlice.answer = (link, f) {
      if (unanswered == null && link.openCount >= them.length) {
        unanswered = link.openIds;
        droppedAt = toAlice.links.length;
        // Once this send has been passed on: the relay may take it, and the
        // client never hears.
        Timer.run(toAlice.drop);
      }
      return null;
    };
    alice.transport.start();
    await waitUntil(() => unanswered != null,
        what: 'five in flight when the link dropped');
    await waitFor(() async => await outboxCount(alice) == 0,
        timeout: const Duration(seconds: 60), what: 'everything left');
    for (final id in unanswered!) {
      expect(
          toAlice.sends.any((s) => s.id == id && s.link.index >= droppedAt),
          isTrue,
          reason: 'envelope $id, unanswered when the link dropped, went again '
              'on a connection made after it');
    }
    for (var i = 0; i < them.length; i++) {
      await waitUntil(() => textsFrom(them[i], alice.myRid).length >= 3,
          what: '${names[i]} has all three');
    }
    await waitUntil(() => toThem.links.every((l) => l.recvs >= l.msgs),
        what: 'everything delivered was acknowledged');
    for (var i = 0; i < them.length; i++) {
      expect(textsFrom(them[i], alice.myRid),
          ['1 to ${names[i]}', '2 to ${names[i]}', '3 to ${names[i]}'],
          reason: '${names[i]} shows each message once, and in order');
    }
    expect(
        alice.messagesByChat.values.expand((l) => l).where((m) => m.status == -1),
        isEmpty,
        reason: 'and nothing was failed');
  }, timeout: const Timeout(Duration(minutes: 4)));

  test(
      '12. a slow uplink: nothing in flight times out that one at a time '
      'would not have, and nothing goes twice', () async {
    // A file chunk's envelope (ADR 0036) to each of five mailboxes, as a
    // group file stages it, over an uplink of 50 000 characters a second:
    // seven seconds a chunk. The relay client's send timeout, twenty
    // seconds, runs from when a frame is queued on the socket, so two
    // million characters queued at once would put the third chunk past it.
    const chunk = 349610, rate = 50000;
    final port = await startRelay({
      // Mailboxes nobody owns, which the relay budgets by address; that
      // budget is not what this is about.
      'UNOWNED_BYTES_PER_IP_PER_MIN': '${64 * 1024 * 1024}',
    });
    final proxy = await startProxy(port);
    final alice = await personAt('Alice', proxy.url);
    // The connection's own first pass has ended, so every chunk goes in the
    // pass below, over the slow link, and is counted.
    await waitUntil(() => !alice.debugOutboxPassRunning,
        what: 'the connection\'s first pass ended');
    proxy.reset();
    proxy.uplinkCharsPerSec = rate;
    final boxes = [for (var i = 0; i < 5; i++) nobody()];
    for (final b in boxes) {
      await queueRaw(alice, b, payload: 'zs1.${'x' * (chunk - 4)}');
    }
    final clock = Stopwatch()..start();
    unawaited(alice.flushOutbox());
    await waitFor(() async => await outboxCount(alice) == 0,
        timeout: const Duration(seconds: 150), what: 'every chunk left');
    final took = clock.elapsed;
    final perId = <String, int>{};
    for (final s in proxy.sends) {
      perId[s.id] = (perId[s.id] ?? 0) + 1;
    }
    final twice = perId.values.where((n) => n > 1).length;
    // ignore: avoid_print
    print('48.2 slow uplink: five chunks at $rate characters a second took '
        '${took.inMilliseconds} ms (the link alone: '
        '${boxes.length * chunk * 1000 ~/ rate} ms); ${proxy.sends.length} '
        'sends, $twice envelopes sent more than once; at most '
        '${proxy.maxOpen} in flight, ${proxy.maxOpenBytes} characters');
    expect(twice, 0,
        reason: 'no send timed out and went again, the relay having it');
    expect(proxy.sends.length, boxes.length);
    expect(proxy.maxOpenBytes, lessThanOrEqualTo(max(chunk, rate * 10)),
        reason: 'never more out than the link carries in ten seconds, or '
            'one envelope');
  }, timeout: const Timeout(Duration(minutes: 5)));

  test(
      '13. a row queued while the pass waits on an answer goes at once, not '
      'when that answer comes', () async {
    final port = await startRelay({});
    final proxy = await startProxy(port);
    final alice = await personAt('Alice', proxy.url);
    await warm(alice);
    final x = nobody(), y = nobody();
    proxy.reset();
    proxy.replyDelay = const Duration(seconds: 3);
    await queueRaw(alice, x);
    unawaited(alice.flushOutbox());
    await waitUntil(() => proxy.sendsTo(x).isNotEmpty, what: 'x out');
    final queuedAt = proxy.clock.elapsed;
    await queueRaw(alice, y);
    unawaited(alice.flushOutbox()); // what queueing a message does
    await waitUntil(() => proxy.sendsTo(y).isNotEmpty,
        timeout: const Duration(seconds: 10), what: 'y out');
    final toY = proxy.sendsTo(y).first;
    final toX = proxy.sendsTo(x).first;
    final lag = toY.at - queuedAt;
    // ignore: avoid_print
    print('48.2 a row queued while waiting: it went ${lag.inMilliseconds} ms '
        'after it was queued; the answer to x was held 3 000 ms');
    expect(lag, lessThan(const Duration(milliseconds: 1000)),
        reason: 'it did not wait for the answer to x, another mailbox');
    expect(toX.settledAt == null || toX.settledAt! > toY.at, isTrue,
        reason: 'x was still out when it went');
    await waitFor(() async => await outboxCount(alice) == 0,
        what: 'both left');
  }, timeout: const Timeout(Duration(minutes: 2)));

  test(
      '14. a pass a refusal has stopped still waits for what it has out: a '
      'flush meanwhile sends none of it again', () async {
    final port = await startRelay({});
    final proxy = await startProxy(port);
    final alice = await personAt('Alice', proxy.url);
    alice.outboxRetryDelay = const Duration(seconds: 30);
    await warm(alice);
    final slow = [for (var i = 0; i < 8; i++) nobody()];
    final refused = [for (var i = 0; i < 8; i++) nobody()];
    // The slow eight first, so all sixteen are out before the refusals —
    // which come back at once, ahead of the slow ones' `sent`, as a relay
    // whose store answers out of order can — and end the pass.
    for (final b in [...slow, ...refused]) {
      await queueRaw(alice, b);
    }
    proxy.reset();
    proxy.answer = (link, f) => refused.contains(f['to'])
        ? {'t': 'error', 'code': 'store_full', 'id': f['id']}
        : null;
    proxy.inOrder = false;
    proxy.delayOf = (link, f) => f['t'] == 'sent'
        ? const Duration(milliseconds: 2500)
        : Duration.zero;
    unawaited(alice.flushOutbox());
    await waitUntil(() => (proxy.answered['store_full'] ?? 0) >= 8,
        what: 'eight refused in a row');
    expect(
        slow.every((b) => proxy.sendsTo(b).single.settledAt == null), isTrue,
        reason: 'with the slow eight still out');
    // What a new message does.
    await alice.flushOutbox();
    await waitFor(() async => await outboxCount(alice) == refused.length,
        timeout: const Duration(seconds: 20),
        what: 'the slow eight answered and gone');
    await waitUntil(() => !alice.debugOutboxPassRunning,
        what: 'the pass ended');
    // ignore: avoid_print
    print('48.2 a stopped pass: ${proxy.sends.length} sends, '
        '${proxy.dupWhileOpen} of them an envelope already out');
    expect(proxy.dupWhileOpen, 0,
        reason: 'nothing was sent again while its first send was out');
    for (final b in slow) {
      expect(proxy.sendsTo(b).length, 1, reason: 'each slow one went once');
    }
    for (final b in refused) {
      expect(proxy.sendsTo(b).length, 1,
          reason: 'each refused one was held, and tried once');
    }
    final left = await alice.vault.db.query('outbox', columns: ['rid']);
    expect({for (final r in left) r['rid']}, refused.toSet());
  }, timeout: const Timeout(Duration(minutes: 2)));

  test(
      '15. one retry timer, and the sooner wins: a rate limit after a held '
      'mailbox comes back in a second, not when the hold\'s retry is due',
      () async {
    final port = await startRelay({});
    final proxy = await startProxy(port);
    final alice = await personAt('Alice', proxy.url);
    alice.outboxRetryDelay = const Duration(seconds: 30);
    await warm(alice);
    final full = nobody(), other = nobody();
    var limited = false;
    proxy.reset();
    proxy.answer = (link, f) {
      if (f['to'] == full) {
        return {'t': 'error', 'code': 'queue_full', 'id': f['id']};
      }
      if (f['to'] == other && !limited) {
        limited = true;
        return {'t': 'error', 'code': 'rate_limited'};
      }
      return null;
    };
    // A full mailbox: held, and the pass's retry set for thirty seconds.
    await queueRaw(alice, full);
    await alice.flushOutbox();
    await waitUntil(() => (proxy.answered['queue_full'] ?? 0) >= 1,
        what: 'the full mailbox refused');
    await waitUntil(() => !alice.debugOutboxPassRunning,
        what: 'that pass ended, its retry set');
    // Then a row to someone else, which the relay rate-limits once.
    await queueRaw(alice, other);
    unawaited(alice.flushOutbox());
    await waitUntil(() => proxy.sendsTo(other).length >= 2,
        timeout: const Duration(seconds: 10),
        what: 'the rate-limited row tried again');
    final tries = proxy.sendsTo(other).toList();
    final gap = tries[1].at - tries[0].at;
    // ignore: avoid_print
    print('48.2 the sooner retry: tried again ${gap.inMilliseconds} ms after '
        'the rate limit; the held mailbox\'s retry was due 30 000 ms after '
        'its refusal');
    expect(gap, greaterThanOrEqualTo(const Duration(milliseconds: 900)));
    expect(gap, lessThan(const Duration(milliseconds: 2500)),
        reason: 'the backoff\'s second, not the hold\'s thirty');
    await waitFor(
        () async => (await alice.vault.db
                .query('outbox', where: 'rid = ?', whereArgs: [other]))
            .isEmpty,
        what: 'the row left');
  }, timeout: const Timeout(Duration(minutes: 2)));

  test(
      '16. after a refusal that names nothing, the next pass starts from one '
      'in flight and widens by one for each envelope the relay takes',
      () async {
    final port = await startRelay({});
    final proxy = await startProxy(port);
    final alice = await personAt('Alice', proxy.url);
    await warm(alice);
    final boxes = [for (var i = 0; i < 40; i++) nobody()];
    for (final b in boxes) {
      await queueRaw(alice, b);
    }
    proxy.reset();
    proxy.replyDelay = const Duration(milliseconds: 60);
    Duration? refusedAt;
    proxy.answer = (link, f) {
      if (refusedAt == null && link.openCount >= 8) {
        refusedAt = proxy.clock.elapsed;
        return {'t': 'error', 'code': 'rate_limited'};
      }
      return null;
    };
    unawaited(alice.flushOutbox());
    await waitUntil(() => refusedAt != null,
        what: 'eight out when the relay refused one, naming none');
    await waitFor(() async => await outboxCount(alice) == 0,
        timeout: const Duration(seconds: 30), what: 'all forty left');
    // The pass after the refusal: for each of its sends, how many of its
    // own were out as it went, and how many the relay had taken by then.
    final after = [
      for (final s in proxy.sends)
        if (s.at > refusedAt! + const Duration(milliseconds: 500)) s
    ];
    var worst = 0, widest = 0;
    for (final s in after) {
      final out = after
          .where((o) =>
              o.at <= s.at && (o.settledAt == null || o.settledAt! > s.at))
          .length;
      final taken = after
          .where((o) =>
              o.settledBy == 'sent' &&
              o.settledAt != null &&
              o.settledAt! <= s.at)
          .length;
      worst = max(worst, out - (1 + taken));
      widest = max(widest, out);
    }
    // ignore: avoid_print
    print('48.2 slow start: ${after.length} sends after the refusal, the '
        'first with ${after.first.openAtSend} out; at most $widest out; out '
        'beyond one plus those taken by then: $worst');
    expect(after.first.openAtSend, 1, reason: 'the first went alone');
    expect(worst, lessThanOrEqualTo(0),
        reason: 'never more out than one plus what the relay had taken');
    expect(widest, greaterThan(8), reason: 'and it widened again');
  }, timeout: const Timeout(Duration(minutes: 2)));

  test(
      '17. pow_required on an outbox row holds its own mailbox, not the '
      'outbox', () async {
    final port = await startRelay({});
    final proxy = await startProxy(port);
    final alice = await personAt('Alice', proxy.url);
    // A retry long after the test, so the stamped mailbox is tried again
    // only if something other than its hold brings it back.
    alice.outboxRetryDelay = const Duration(seconds: 30);
    await warm(alice);
    final stamped = nobody();
    final others = [for (var i = 0; i < 4; i++) nobody()];
    await queueRaw(alice, stamped); // first in the outbox
    for (var j = 0; j < 3; j++) {
      for (final b in others) {
        await queueRaw(alice, b);
      }
    }
    proxy.reset();
    proxy.answer = (link, f) => f['to'] == stamped
        ? {
            't': 'error',
            'code': 'pow_required',
            'id': f['id'],
            'bits': 20,
            'day': 20000,
          }
        : null;
    final clock = Stopwatch()..start();
    unawaited(alice.flushOutbox());
    await waitFor(() async {
      final left = await alice.vault.db.query('outbox', columns: ['rid']);
      return left.length == 1 && left.single['rid'] == stamped;
    },
        timeout: const Duration(milliseconds: 3000),
        what: 'everyone else drained in the one pass');
    // ignore: avoid_print
    print('48.2 pow_required: the other twelve rows left in '
        '${clock.elapsed.inMilliseconds} ms; the stamped mailbox was tried '
        '${proxy.sendsTo(stamped).length} time(s)');
    expect(proxy.sendsTo(stamped).length, 1,
        reason: 'held for the pass, not tried again on a backoff');
  }, timeout: const Timeout(Duration(minutes: 2)));

  test(
      '18. answers out of order: eight store_fulls in a row still end the '
      'pass, seven among the rest do not, and one per mailbox holds',
      () async {
    final port = await startRelay({});
    final proxy = await startProxy(port);
    final alice = await personAt('Alice', proxy.url);
    alice.outboxRetryDelay = const Duration(seconds: 3);
    await warm(alice);
    final jitter = Random(18);
    proxy.inOrder = false;
    proxy.delayOf =
        (link, f) => Duration(milliseconds: jitter.nextInt(150));

    // (a) The store refusing everyone, its answers in any order: the pass
    // ends after eight, and the retry timer brings it back — by when, here,
    // the store has room again.
    final many = [for (var i = 0; i < 48; i++) nobody()];
    var refusing = true;
    Duration? previous;
    proxy.answer = (link, f) {
      final now = proxy.clock.elapsed;
      final last = previous;
      if (last != null && now - last > const Duration(milliseconds: 1500)) {
        refusing = false;
      }
      previous = now;
      return refusing
          ? {'t': 'error', 'code': 'store_full', 'id': f['id']}
          : null;
    };
    for (final b in many) {
      await queueRaw(alice, b);
    }
    proxy.reset();
    unawaited(alice.flushOutbox());
    await waitFor(() async => await outboxCount(alice) == 0,
        timeout: const Duration(seconds: 20),
        what: 'all of them went once the store had room');
    final sends = proxy.sends.toList();
    final cut = [
      for (var i = 1; i < sends.length; i++)
        if (sends[i].at - sends[i - 1].at >
            const Duration(milliseconds: 1500))
          i
    ].first;
    final firstPass = {for (final s in sends.take(cut)) s.to};
    // ignore: avoid_print
    print('48.2 out of order: the store refusing everyone, the first pass '
        'tried ${firstPass.length} of ${many.length} mailboxes');
    expect(firstPass.length, lessThan(many.length),
        reason: 'eight refusals in a row ended the pass');
    expect(firstPass.length, lessThanOrEqualTo(32 + 7));
    expect(sends[cut].at - sends[cut - 1].at,
        greaterThanOrEqualTo(const Duration(milliseconds: 2900)),
        reason: 'it came back on the retry timer');

    // (b) Seven refused among twenty mailboxes the relay takes, three rows
    // each, answers in any order: never eight in a row, so the one pass
    // drains every one of the twenty, and the seven are held.
    // (a)'s pass has ended — it can outlive the drain above by a refill — so
    // nothing below goes before the counts start.
    await waitUntil(() => !alice.debugOutboxPassRunning,
        what: '(a)\'s pass ended');
    alice.outboxRetryDelay = const Duration(seconds: 30);
    final known = [for (var i = 0; i < 20; i++) nobody()];
    final seven = [for (var i = 0; i < 7; i++) nobody()];
    proxy.answer = (link, f) => seven.contains(f['to'])
        ? {'t': 'error', 'code': 'store_full', 'id': f['id']}
        : null;
    proxy.reset();
    for (var j = 0; j < 3; j++) {
      for (final b in known) {
        await queueRaw(alice, b);
      }
    }
    for (final b in seven) {
      await queueRaw(alice, b);
    }
    unawaited(alice.flushOutbox());
    await waitFor(() async {
      final left = await alice.vault.db.query('outbox', columns: ['rid']);
      return left.length == seven.length &&
          left.every((r) => seven.contains(r['rid']));
    },
        timeout: const Duration(seconds: 5),
        what: 'every mailbox but the seven drained in the one pass');
    // ignore: avoid_print
    print('48.2 out of order: seven refused among twenty, '
        '${proxy.sends.length} sends; at most '
        '${proxy.maxOpenPerMailbox.values.fold(0, max)} in flight to one '
        'mailbox, ${proxy.dupWhileOpen} sent again while out');
    expect(proxy.sends.length, known.length * 3 + seven.length,
        reason: 'every row went once');
    for (final b in seven) {
      expect(proxy.sendsTo(b).length, 1,
          reason: 'each of the seven held, and tried once');
    }
    // (c) And with answers out of order, still never two to one mailbox.
    expect(proxy.maxOpenPerMailbox.values.every((n) => n == 1), isTrue,
        reason: 'never two in flight to one mailbox');
    expect(proxy.dupWhileOpen, 0);
  }, timeout: const Timeout(Duration(minutes: 2)));
}

/// One `send` frame, as the proxy saw it cross.
class _Send {
  _Send(this.at, this.link, this.to, this.id, this.bytes);

  /// When it reached the proxy, on the proxy's clock.
  final Duration at;
  final _Link link;
  final String to;
  final String id;

  /// Its payload's length.
  final int bytes;

  /// How many sends on its link were waiting for their answer as it came,
  /// itself included.
  int openAtSend = 0;

  /// When the client was handed what settles it — a `sent`, an error naming
  /// it, an error naming nothing (which fails everything in flight, §12.2),
  /// or its connection closing — and which: `sent`, the error's code, or
  /// `closed`. Null while the client still waits.
  Duration? settledAt;
  String? settledBy;
}

/// One client connection through the proxy, and its own on to the relay.
class _Link {
  _Link(this.index, this.down);

  /// The order it was made in.
  final int index;
  final WebSocket down;
  WebSocket? up;
  bool closed = false;

  /// The sends on it still waiting for their answer, by id: oldest first,
  /// for an id sent again while it was still out.
  final open = <String, List<_Send>>{};
  Iterable<_Send> get openSends => open.values.expand((l) => l);
  int get openCount => openSends.length;
  Set<String> get openIds => open.keys.toSet();

  /// The answers held back, handed on in the order they came.
  Future<void> held = Future<void>.value();

  /// The client's frames on their way on to the relay, in order, and when a
  /// throttled uplink is next free.
  Future<void> upward = Future<void>.value();
  Duration upFreeAt = Duration.zero;

  /// The ids of the `msg` frames the relay pushed down it, in order, and the
  /// `recv` frames the client sent back up.
  final msgIds = <String>[];
  int get msgs => msgIds.length;
  int recvs = 0;
}

/// A WebSocket proxy between clients and the real relay. It passes every
/// frame through as it is, except that:
/// - it holds each answer that names an envelope (`sent`, or an error with
///   an `id`) for [replyDelay], or for what [delayOf] says, keeping their
///   order — or, with [inOrder] off, handing each on at its own time, as a
///   relay whose store answers out of order can;
/// - it hands on an answer naming nothing at once, as the relay's own
///   `rate_limited` is written while the `sent` of envelopes it took just
///   before still waits on its store;
/// - it lets [answer] refuse a send in the relay's place, with the relay's
///   own frame, and then never passes that envelope on;
/// - with [uplinkCharsPerSec] set, it passes the client's frames on to the
///   relay no faster than that, in order, as a slow uplink behind the
///   client's socket does — so the relay's answers, and the client's send
///   timers, see the slow link;
/// - and [drop] closes every connection, both ways.
class _Proxy {
  _Proxy._(this._server, this._relayPort);

  final HttpServer _server;
  final int _relayPort;
  final clock = Stopwatch()..start();
  final links = <_Link>[];
  final sends = <_Send>[];

  Duration replyDelay = Duration.zero;

  /// How long to hold one answer that names an envelope, in place of
  /// [replyDelay]; null to use it.
  Duration? Function(_Link link, Map<String, Object?> answer)? delayOf;

  /// Whether held answers are handed on in the order they came.
  bool inOrder = true;

  /// The uplink's speed, in characters a second; null for as fast as the
  /// frames come.
  int? uplinkCharsPerSec;

  /// Asked about every `send`: a frame to answer it with in the relay's
  /// place, or null to pass it on.
  Map<String, Object?>? Function(_Link link, Map<String, Object?> send)?
      answer;

  /// The most sends one connection had waiting at once, the most to one
  /// mailbox — a send whose id is already out counted again — and the most
  /// payload.
  int maxOpen = 0;
  int maxOpenBytes = 0;
  final maxOpenPerMailbox = <String, int>{};

  /// Sends whose id was already out, unanswered, on the same connection.
  int dupWhileOpen = 0;

  /// What the clients were handed, by `sent` or by error code.
  final answered = <String, int>{};

  String get url => 'ws://127.0.0.1:${_server.port}';

  static Future<_Proxy> start(int relayPort) async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final p = _Proxy._(server, relayPort);
    server.listen((req) => unawaited(p._accept(req)));
    return p;
  }

  Iterable<_Send> sendsTo(String rid) => sends.where((s) => s.to == rid);

  /// Forgets what was counted so far.
  void reset() {
    sends.clear();
    maxOpen = 0;
    maxOpenBytes = 0;
    maxOpenPerMailbox.clear();
    dupWhileOpen = 0;
    answered.clear();
  }

  void drop() {
    for (final l in links) {
      _close(l);
    }
  }

  Future<void> close() async {
    drop();
    await _server.close(force: true);
  }

  Future<void> _accept(HttpRequest req) async {
    final WebSocket down;
    try {
      down = await WebSocketTransformer.upgrade(req);
    } catch (_) {
      req.response.statusCode = HttpStatus.badRequest;
      await req.response.close();
      return;
    }
    final l = _Link(links.length, down);
    links.add(l);
    final WebSocket up;
    try {
      // The Host header goes through unchanged, as a front passes it: a
      // client signs its authentication over the address it dialled (§12.1).
      up = await WebSocket.connect('ws://127.0.0.1:$_relayPort',
          headers: {'host': req.headers.value('host') ?? ''});
    } catch (_) {
      _close(l);
      return;
    }
    l.up = up;
    if (l.closed) {
      unawaited(up.close().catchError((Object _) {}));
      return;
    }
    down.listen((d) => _fromClient(l, d),
        onDone: () => _close(l), onError: (Object _) => _close(l));
    up.listen((d) => _fromRelay(l, d),
        onDone: () => _close(l), onError: (Object _) => _close(l));
  }

  void _fromClient(_Link l, dynamic d) {
    final f = _parse(d);
    if (f != null &&
        f['t'] == 'send' &&
        f['id'] is String &&
        f['to'] is String) {
      final payload = f['payload'];
      final s = _Send(clock.elapsed, l, f['to'] as String, f['id'] as String,
          payload is String ? payload.length : 0);
      sends.add(s);
      final same = l.open.putIfAbsent(s.id, () => <_Send>[]);
      if (same.isNotEmpty) dupWhileOpen++;
      same.add(s);
      final out = l.openSends.toList();
      s.openAtSend = out.length;
      maxOpen = max(maxOpen, out.length);
      maxOpenBytes = max(maxOpenBytes, out.fold(0, (a, o) => a + o.bytes));
      final toIt = out.where((o) => o.to == s.to).length;
      maxOpenPerMailbox[s.to] = max(maxOpenPerMailbox[s.to] ?? 0, toIt);
      final instead = answer?.call(l, f);
      if (instead != null) {
        _answer(l, instead, jsonEncode(instead));
        return;
      }
    } else if (f != null && f['t'] == 'recv') {
      l.recvs++;
    }
    _toRelay(l, d);
  }

  void _fromRelay(_Link l, dynamic d) {
    final f = _parse(d);
    if (f != null && f['t'] == 'msg' && f['id'] is String) {
      l.msgIds.add(f['id'] as String);
    }
    if (f != null && (f['t'] == 'sent' || f['t'] == 'error')) {
      _answer(l, f, d);
      return;
    }
    _toClient(l, d);
  }

  void _answer(_Link l, Map<String, Object?> f, dynamic raw) {
    if (f['id'] is! String) {
      _settle(l, f);
      _toClient(l, raw);
      return;
    }
    final delay = delayOf?.call(l, f) ?? replyDelay;
    if (!inOrder) {
      unawaited(Future<void>.delayed(delay, () {
        if (l.closed) return;
        _settle(l, f);
        _toClient(l, raw);
      }));
      return;
    }
    final due = clock.elapsed + delay;
    l.held = l.held.then((_) async {
      final wait = due - clock.elapsed;
      if (wait > Duration.zero) await Future<void>.delayed(wait);
      if (l.closed) return;
      _settle(l, f);
      _toClient(l, raw);
    });
  }

  void _settle(_Link l, Map<String, Object?> f) {
    final key = f['t'] == 'sent' ? 'sent' : '${f['code']}';
    answered[key] = (answered[key] ?? 0) + 1;
    final now = clock.elapsed;
    final id = f['id'];
    if (id is String) {
      final same = l.open[id];
      if (same == null || same.isEmpty) return;
      same.removeAt(0)
        ..settledAt = now
        ..settledBy = key;
      if (same.isEmpty) l.open.remove(id);
    } else {
      for (final s in l.openSends) {
        s
          ..settledAt = now
          ..settledBy = key;
      }
      l.open.clear();
    }
  }

  void _close(_Link l) {
    if (l.closed) return;
    l.closed = true;
    final now = clock.elapsed;
    for (final s in l.openSends) {
      s
        ..settledAt = now
        ..settledBy = 'closed';
    }
    l.open.clear();
    unawaited(l.down.close().catchError((Object _) {}));
    final up = l.up;
    if (up != null) unawaited(up.close().catchError((Object _) {}));
  }

  void _toClient(_Link l, dynamic d) {
    if (l.closed) return;
    try {
      l.down.add(d);
    } catch (_) {}
  }

  /// On to the relay, in order — after the time the frame takes on a
  /// throttled uplink, behind whatever went before it.
  void _toRelay(_Link l, dynamic d) {
    final rate = uplinkCharsPerSec;
    final size = d is String ? d.length : (d is List ? d.length : 0);
    final now = clock.elapsed;
    final from = l.upFreeAt > now ? l.upFreeAt : now;
    final done = rate == null
        ? from
        : from + Duration(microseconds: (size * 1e6 / rate).round());
    l.upFreeAt = done;
    l.upward = l.upward.then((_) async {
      final wait = done - clock.elapsed;
      if (wait > Duration.zero) await Future<void>.delayed(wait);
      final up = l.up;
      if (l.closed || up == null) return;
      try {
        up.add(d);
      } catch (_) {}
    });
  }

  static Map<String, Object?>? _parse(dynamic d) {
    if (d is! String) return null;
    try {
      final j = jsonDecode(d);
      return j is Map ? j.cast<String, Object?>() : null;
    } catch (_) {
      return null;
    }
  }
}
