// What a relay refusal costs the outbox.
//
// Four of the relay's refusals name the envelope they are about
// (`too_large`, `bad_send`, `queue_full`, `store_full`). The rest —
// `rate_limited` above all, and `bad_json`, `internal`, `bad_auth`,
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
// Criteria, each a test below:
//  1. a refusal the relay cannot attribute to one send fails that send at
//     once rather than after the send timeout;
//  2. a rate-limited pass comes back on its own timer and the messages
//     arrive, without waiting for a reconnect that may never come;
//  3. a permanently refused envelope marks ITS OWN message failed — named
//     by the row's mid and thread, not by the envelope id and the mailbox,
//     which stopped being the same string when the envelope id was
//     separated from the message id.
import 'dart:convert';
import 'dart:io';

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

  tearDownAll(() async {
    for (final s in live) {
      await s.transport.stop();
      await s.vault.db.close();
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
}
