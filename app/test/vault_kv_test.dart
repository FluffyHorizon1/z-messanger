// The vault's key-value store, after cold start was measured.
//
// `kvGet` used to try the sealed class ('s:') and then the plain one ('p:')
// as two queries, so every plain read — and every miss, which is what most
// per-contact keys are at startup — cost two round trips. It is one query
// now, and `kvScan` reads a whole key family in one, which is what
// ChatService.init does for the per-contact keys instead of one (or two)
// queries per contact per key. Unread counts moved to one GROUP BY for the
// same reason. Cold start with 400 contacts: 2.5 s → 0.5 s (PERFORMANCE.md).
//
// Exit criteria:
//   1. a plain value, a sealed value and a missing key each read back
//      correctly through the one-query kvGet;
//   2. kvScan returns every key of a family and only that family — a
//      prefix containing '_' (which LIKE treats as a wildcard) matches
//      itself, not any character;
//   3. unread counts from the single query equal one COUNT per chat, with
//      and without a `last_open_` row, and a chat with none counts every
//      inbound message.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:z_protocol/z_protocol.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final temps = <Directory>[];
  tearDownAll(() {
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<Vault> open() async {
    final dir = await Directory.systemTemp.createTemp('z_kv');
    temps.add(dir);
    return Vault.open(rootOverride: dir);
  }

  test('plain, sealed and missing keys read back through one query', () async {
    final v = await open();
    await v.kvPut('plain_one', 'p1', sensitive: false);
    await v.kvPut('sealed_one', 's1');
    expect(await v.kvGet('plain_one'), 'p1');
    expect(await v.kvGet('sealed_one'), 's1');
    expect(await v.kvGet('absent'), isNull);
    // The stored form is what the class says it is.
    final rows = await v.db.query('kv', orderBy: 'k');
    expect(rows.map((r) => r['k']), ['p:plain_one', 's:sealed_one']);
    expect(rows.last['v'], isNot('s1'), reason: 'sealed on disk');
    // Overwriting keeps the class of the write, and reads still resolve.
    await v.kvPut('plain_one', 'p2', sensitive: false);
    expect(await v.kvGet('plain_one'), 'p2');
    await v.db.close();
  });

  test('kvScan returns one family, and a prefix underscore is literal',
      () async {
    final v = await open();
    await v.kvPut('cdev_a', 'A', sensitive: false);
    await v.kvPut('cdev_b', 'B', sensitive: false);
    await v.kvPut('cdev_pq_a', 'PQ', sensitive: false);
    await v.kvPut('cdevXa', 'not this one', sensitive: false); // 'X' where
    // the prefix has '_': a LIKE wildcard would have matched it
    await v.kvPut('other_a', 'no', sensitive: false);
    await v.kvPut('cdev_sealed', 'S'); // sealed rows come back unsealed too
    final scan = await v.kvScan('cdev_');
    expect(scan, {
      'cdev_a': 'A',
      'cdev_b': 'B',
      'cdev_pq_a': 'PQ',
      'cdev_sealed': 'S',
    });
    expect(await v.kvScanMany(['cdev_', 'other_']), hasLength(5));
    expect(await v.kvScan('nothing_'), isEmpty);
    await v.db.close();
  });

  test('unread in one query agrees with one COUNT per chat', () async {
    // Through the service, so the query under test is the one it runs.
    final dir = await Directory.systemTemp.createTemp('z_kv_unread');
    temps.add(dir);
    var vault = await Vault.open(rootOverride: dir);
    final identity = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(identity.toJson()));
    var svc = await ChatService.init(
        vault: vault,
        identity: identity,
        displayName: 'me',
        transport:
            Transport(identity: identity, serverUrl: 'ws://127.0.0.1:1'));
    final chats = <String>[];
    for (var i = 0; i < 4; i++) {
      final peer = await ZIdentity.generate();
      final c = await svc
          .addContactFromCode((await peer.bundle(displayName: 'p$i')).encode());
      chats.add(c.rid);
    }
    final batch = vault.db.batch();
    var t = 1000;
    for (final rid in chats) {
      for (var k = 0; k < 20; k++) {
        batch.insert('messages', {
          'mid': '$rid-$k',
          'rid': rid,
          'outgoing': k % 4 == 0 ? 1 : 0,
          'kind': k == 5 ? 'system' : 'text',
          'enc_body': await vault.seal('x'),
          'ts_ms': t++,
          'status': 2,
          'expire_at_ms': 0,
        });
      }
    }
    await batch.commit(noResult: true);
    // chats[0]: never opened. [1]: opened half way. [2]: opened after
    // everything. [3]: opened before anything.
    await vault.kvPut('last_open_${chats[1]}', '${1000 + 20 + 10}',
        sensitive: false);
    await vault.kvPut('last_open_${chats[2]}', '${1000 + 60}',
        sensitive: false);
    await vault.kvPut('last_open_${chats[3]}', '1', sensitive: false);

    // Cold start: the counts are computed by the service's single query.
    svc.dispose();
    await svc.transport.stop();
    await vault.db.close();
    vault = await Vault.open(rootOverride: dir);
    svc = await ChatService.init(
        vault: vault,
        identity: identity,
        displayName: 'me',
        transport:
            Transport(identity: identity, serverUrl: 'ws://127.0.0.1:1'));

    for (final rid in chats) {
      final lastOpen =
          int.tryParse(await vault.kvGet('last_open_$rid') ?? '0') ?? 0;
      final perChat = (await vault.db.rawQuery(
              'SELECT COUNT(*) AS n FROM messages WHERE rid = ? AND '
              'outgoing = 0 AND ts_ms > ? AND kind != ?',
              [rid, lastOpen, 'system']))
          .first['n'] as int;
      expect(svc.unread[rid], perChat, reason: rid);
    }
    expect(svc.unread[chats[0]], 14,
        reason: 'never opened: every inbound non-system message');
    expect(svc.unread[chats[2]], 0, reason: 'opened after everything');
    svc.dispose();
    await svc.transport.stop();
    await vault.db.close();
  });
}
