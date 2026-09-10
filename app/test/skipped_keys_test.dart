// 15.3 — the ratchet's out-of-order key cache lives apart from the hot state.
//
// Measured in docs/PERFORMANCE.md: a conversation holding the full 1536
// skipped keys added ~20.7 ms per recipient to EVERY send, because the whole
// conversation — cache included — was encoded and sealed each time. The cache
// is receive-side state: a send never reads it and never changes it. It now
// lives in its own cell (`conversations.enc_skipped`, vault schema 9).
//
// The danger in this change is not performance, it is silent message loss: a
// cache that is dropped somewhere on the way costs the ability to decrypt
// messages already in flight, and nothing complains at the time. So the
// exit criteria are about the cache SURVIVING, and only the last one is
// about cost:
//
//   1. it round-trips a restart;
//   2. a send does not rewrite it — and does rewrite the hot state;
//   3. a vault written BEFORE schema 9, with the cache inside `enc_state`,
//      still has its keys after loading and after the next send;
//   4. a failed send rolls the ratchet back without emptying the cache;
//   5. a receive that leaves the cache untouched does not rewrite it — and
//      one that changes it does. Re-sealing an unchanged cache on every
//      receive was the send-side cost moved rather than removed (13.7 ms at
//      the cap, receive_bench_test.dart).
@Tags(['integration'])
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

  late Process relay;
  late int port;
  final temps = <Directory>[];
  final services = <ChatService>[];

  setUpAll(() async {
    HttpOverrides.global = null;
    final serverDir =
        '${Directory.current.parent.path}${Platform.pathSeparator}server';
    final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    port = probe.port;
    await probe.close();
    relay = await Process.start('node', ['server.js'],
        workingDirectory: serverDir,
        environment: {'PORT': '$port', 'LOG_LEVEL': 'silent'});
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
    for (final s in services) {
      await s.transport.stop();
    }
    relay.kill();
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<ChatService> open(Directory dir, String name,
      {bool offline = false}) async {
    final vault = await Vault.open(rootOverride: dir);
    final existing = await vault.kvGet('identity');
    final identity = existing != null
        ? await ZIdentity.fromJson(jsonDecode(existing) as Map<String, Object?>)
        : await ZIdentity.generate();
    if (existing == null) {
      await vault.kvPut('identity', jsonEncode(identity.toJson()));
    }
    final svc = await ChatService.init(
      vault: vault,
      identity: identity,
      displayName: name,
      transport: Transport(
          identity: identity,
          serverUrl: 'ws://127.0.0.1:${offline ? 1 : port}'),
    );
    services.add(svc);
    return svc;
  }

  Future<Directory> temp(String tag) async {
    final d = await Directory.systemTemp.createTemp('z_skip_$tag');
    temps.add(d);
    return d;
  }

  Future<String> addPhantom(ChatService svc, String tag) async {
    final id = await ZIdentity.generate();
    final code = (await id.bundle(displayName: tag)).encode();
    await svc.addContactFromCode(code);
    return (await ContactBundle.decode(code)).routingId();
  }

  /// Put keys into the live ratchet's cache the way a run of out-of-order
  /// arrivals would, then persist them through the normal receive-side path.
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
          'k$i': base64.encode(List.filled(32, i % 251))
      }
    };
    await svc.vault.db.update('conversations',
        {'enc_skipped': await svc.vault.seal(jsonEncode(skipped))},
        where: 'rid = ?', whereArgs: [rid]);
  }

  test('the cache survives a restart', () async {
    final dir = await temp('roundtrip');
    var svc = await open(dir, 'a');
    final rid = await addPhantom(svc, 'peer');
    await svc.sendText(rid, 'open the session');
    await seedCache(svc, rid, 40);
    await svc.transport.stop();

    svc = await open(dir, 'a2', offline: true);
    expect(svc.debugSkippedKeyCount(rid), 40,
        reason: 'the out-of-order keys did not come back after a restart — '
            'messages already in flight would now fail to decrypt');
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('a send rewrites the state and leaves the cache alone', () async {
    final dir = await temp('sendcost');
    final svc = await open(dir, 'b', offline: true);
    final rid = await addPhantom(svc, 'peer');
    await svc.sendText(rid, 'open the session');
    await seedCache(svc, rid, 200);

    Future<(String, String?)> cells() async {
      final r = (await svc.vault.db
              .query('conversations', where: 'rid = ?', whereArgs: [rid]))
          .single;
      return (r['enc_state'] as String, r['enc_skipped'] as String?);
    }

    final (stateBefore, skippedBefore) = await cells();
    await svc.sendText(rid, 'and another');
    final (stateAfter, skippedAfter) = await cells();

    expect(stateAfter, isNot(stateBefore),
        reason: 'a send advances the sending chain, so the hot state must '
            'have been rewritten — if it was not, this test is measuring '
            'nothing');
    expect(skippedAfter, skippedBefore,
        reason: 'the send rewrote the out-of-order key cache. That is the '
            'cost this split removed: ~20 ms per recipient at the cap, for '
            'state a send can neither read nor change');

    // Leaving `enc_skipped` alone is not enough on its own: if the cache also
    // went back into `enc_state`, the send would still be encoding and
    // sealing all of it and the win would be gone, silently and with every
    // other test still green. So the hot state is opened and checked to be
    // free of it.
    final hot = (jsonDecode(await svc.vault.unseal(stateAfter)) as Map)
        .cast<String, Object?>();
    for (final session in (hot['sessions'] as Map).values) {
      final ratchet = (session as Map)['ratchet'] as Map;
      expect(ratchet.containsKey('skipped'), isFalse,
          reason: 'the out-of-order cache is back inside enc_state, so the '
              'send is paying to encode and seal it again — which is the '
              'entire cost this change removed');
    }
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('a vault written before schema 9 keeps its keys', () async {
    final dir = await temp('legacy');
    var svc = await open(dir, 'c', offline: true);
    final rid = await addPhantom(svc, 'peer');
    await svc.sendText(rid, 'open the session');

    // Rewrite the row the way a pre-9 build left it: cache INSIDE enc_state,
    // and the new column empty.
    final row = (await svc.vault.db
            .query('conversations', where: 'rid = ?', whereArgs: [rid]))
        .single;
    final state =
        (jsonDecode(await svc.vault.unseal(row['enc_state'] as String)) as Map)
            .cast<String, Object?>();
    final sessions = (state['sessions'] as Map).cast<String, Object?>();
    final sid = sessions.keys.first;
    final ratchet =
        ((sessions[sid] as Map)['ratchet'] as Map).cast<String, Object?>();
    ratchet['skipped'] = {
      for (var i = 0; i < 25; i++)
        'old$i': base64.encode(List.filled(32, i + 1))
    };
    await svc.vault.db.update(
        'conversations',
        {
          'enc_state': await svc.vault.seal(jsonEncode(state)),
          'enc_skipped': null,
        },
        where: 'rid = ?',
        whereArgs: [rid]);
    await svc.transport.stop();

    svc = await open(dir, 'c2', offline: true);
    expect(svc.debugSkippedKeyCount(rid), 25,
        reason: 'keys stored the old way, inside enc_state, were dropped on '
            'load — every vault upgrading to schema 9 would lose its '
            'in-flight messages');

    // And a send must not throw them away either: the new state is written
    // without them, so they have to still be in memory afterwards.
    await svc.sendText(rid, 'after the upgrade');
    expect(svc.debugSkippedKeyCount(rid), 25,
        reason: 'a send after the upgrade emptied the cache');

    // In memory is not enough. That send rewrote enc_state WITHOUT the cache
    // — that is the whole point of the split — so unless something moved the
    // keys into enc_skipped first, the old location is now empty and the new
    // one was never written. Kill the app here and the keys are gone.
    await svc.transport.stop();
    svc = await open(dir, 'c3', offline: true);
    expect(svc.debugSkippedKeyCount(rid), 25,
        reason: 'the first send after upgrading to schema 9 rewrote the old '
            'location without the cache, and nothing had written the new '
            'one yet: a restart in that window loses every in-flight key');
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('a failed send rolls the ratchet back without emptying the cache',
      () async {
    final dir = await temp('rollback');
    final svc = await open(dir, 'd', offline: true);
    final rid = await addPhantom(svc, 'peer');
    await svc.sendText(rid, 'open the session');
    await seedCache(svc, rid, 30);
    // seedCache wrote the cell directly; bring it into the live object the
    // way a restart would, so the rollback has something to lose.
    await svc.reloadConversations();
    expect(svc.debugSkippedKeyCount(rid), 30);

    Future<String> hotState() async => (await svc.vault.db
            .query('conversations', where: 'rid = ?', whereArgs: [rid]))
        .single['enc_state'] as String;
    final stateBefore = await hotState();

    // Make the send's own transaction fail AFTER the ratchet has stepped and
    // the new state has been written inside it: the message-row insert is
    // the last thing in that transaction, and a trigger refusing it is
    // exactly the "vault write failing" the rollback exists for. No seam in
    // the service is needed for this, and none is added.
    await svc.vault.db
        .execute('CREATE TRIGGER induced_failure BEFORE INSERT ON messages '
            'BEGIN SELECT RAISE(ABORT, \'induced\'); END');
    await expectLater(svc.sendText(rid, 'this one fails'), throwsA(anything));
    await svc.vault.db.execute('DROP TRIGGER induced_failure');

    expect(await hotState(), stateBefore,
        reason: 'the transaction was rolled back, so the stored state must be '
            'the pre-send one');
    expect(svc.debugSkippedKeyCount(rid), 30,
        reason: 'the rollback rebuilt the conversation from a snapshot that '
            'deliberately omits the cache; the live keys have to be carried '
            'across by hand, and they were not');

    // And the rolled-back conversation still works: the next send succeeds
    // and, being a send, still leaves the cache alone.
    await svc.sendText(rid, 'and this one succeeds');
    expect(svc.debugSkippedKeyCount(rid), 30);
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('a receive rewrites the cache only when it changed it', () async {
    // Two real clients, offline: a's outbox rows are the envelopes the relay
    // would deliver, handed straight to b's inbound path.
    final a = await open(await temp('rx_a'), 'a', offline: true);
    final b = await open(await temp('rx_b'), 'b', offline: true);
    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());
    final aRid = a.myRid, bRid = b.myRid;

    Future<List<RelayInbound>> fromA() async {
      final rows = await a.vault.db.query('outbox',
          where: 'rid = ?', whereArgs: [bRid], orderBy: 'created_ms ASC');
      await a.vault.db.delete('outbox', where: 'rid = ?', whereArgs: [bRid]);
      return [
        for (final r in rows)
          RelayInbound(
              id: r['id'] as String,
              from: '',
              payload: r['payload'] as String,
              serverTs: 0)
      ];
    }

    Future<String?> cell() async => (await b.vault.db
            .query('conversations', where: 'rid = ?', whereArgs: [aRid]))
        .single['enc_skipped'] as String?;

    // Bootstrap both chains.
    for (var round = 0; round < 2; round++) {
      await a.sendText(bRid, 'hi $round');
      for (final m in await fromA()) {
        await b.debugInbound(m);
      }
      await b.sendText(aRid, 'hi back $round');
    }

    // One that arrives early: two keys are cached, and the cell is written.
    final empty = await cell();
    for (var i = 0; i < 3; i++) {
      await a.sendText(bRid, 'early $i');
    }
    final batch = await fromA();
    await b.debugInbound(batch.last);
    expect(b.debugSkippedKeyCount(aRid), 2);
    final withKeys = await cell();
    expect(withKeys, isNot(empty),
        reason: 'keys were added to the cache and enc_skipped was not '
            'rewritten — a restart would lose them');

    // Three NEW messages, in order, with those two keys still cached: the
    // cache is untouched, so the cell must not move. It has to be non-empty
    // for this to test anything — sealing is randomised, so re-sealing the
    // same two keys would produce different bytes and show up here, while
    // re-sealing an empty cache writes null over null and shows nothing.
    for (var i = 0; i < 3; i++) {
      await a.sendText(bRid, 'in order $i');
    }
    for (final m in await fromA()) {
      await b.debugInbound(m);
    }
    expect(b.debugSkippedKeyCount(aRid), 2);
    expect(await cell(), withKeys,
        reason: 'an in-order receive rewrote enc_skipped although nothing '
            'in the cache changed — that is the send-side cost moved onto '
            'every receive');

    // And a late arrival consumes one: the cell changes again.
    await b.debugInbound(batch.first);
    expect(b.debugSkippedKeyCount(aRid), 1);
    expect(await cell(), isNot(withKeys),
        reason: 'a key was consumed and enc_skipped still holds it — a '
            'restart would resurrect a key that must never be reused');
  }, timeout: const Timeout(Duration(minutes: 2)));
}
