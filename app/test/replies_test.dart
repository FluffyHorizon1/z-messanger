// Replies (8.1). Two halves:
//
//  * the schema migration — a vault written by the pre-8.1 build (schema 1)
//    must open on this build with every message intact and the new columns
//    in place;
//  * the wire behaviour — a reply carries only the quoted message's id, so
//    what the recipient sees is their own stored copy, and an id that names
//    nothing in that conversation degrades to an unavailable quote instead of
//    reaching across chats.
@Tags(['integration'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:z_protocol/z_protocol.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  group('schema migration', _migrationTests);
  group('over the wire', _wireTests);
}

// ---------------------------------------------------------------------------
// A vault from the previous release opens, keeps its messages, and gains the
// 8.1 columns.
// ---------------------------------------------------------------------------
void _migrationTests() {
  test('a schema-1 vault upgrades in place without losing messages', () async {
    final dir = await Directory.systemTemp.createTemp('z_migrate');
    // Build the OLD database by hand: exactly the schema 1 of the shipped
    // build, with a couple of rows in it.
    sqfliteFfiInit();
    final old = await databaseFactoryFfi.openDatabase(
      '${dir.path}/z.db',
      options: OpenDatabaseOptions(
        version: 1,
        onCreate: (db, _) async {
          await db.execute('''
            CREATE TABLE messages(
              mid TEXT NOT NULL, rid TEXT NOT NULL, outgoing INTEGER NOT NULL,
              kind TEXT NOT NULL, enc_body TEXT NOT NULL, fid TEXT,
              ts_ms INTEGER NOT NULL, status INTEGER NOT NULL DEFAULT 0,
              expire_at_ms INTEGER NOT NULL DEFAULT 0,
              receipt_sent INTEGER NOT NULL DEFAULT 0,
              PRIMARY KEY (rid, mid))''');
          await db
              .execute('CREATE TABLE kv(k TEXT PRIMARY KEY, v TEXT NOT NULL)');
          await db.execute('''
            CREATE TABLE contacts(rid TEXT PRIMARY KEY, enc_bundle TEXT NOT NULL,
              enc_name TEXT NOT NULL, ttl_seconds INTEGER NOT NULL DEFAULT 0,
              verified INTEGER NOT NULL DEFAULT 0, created_ms INTEGER NOT NULL)''');
          await db.execute('''
            CREATE TABLE conversations(rid TEXT PRIMARY KEY,
              enc_state TEXT NOT NULL, updated_ms INTEGER NOT NULL)''');
          await db.execute('''
            CREATE TABLE files(fid TEXT PRIMARY KEY, rid TEXT NOT NULL,
              mid TEXT NOT NULL, enc_meta TEXT NOT NULL,
              complete INTEGER NOT NULL DEFAULT 0,
              got_chunks INTEGER NOT NULL DEFAULT 0,
              total_chunks INTEGER NOT NULL DEFAULT 0)''');
          await db.execute('''
            CREATE TABLE chunks(fid TEXT NOT NULL, idx INTEGER NOT NULL,
              payload TEXT NOT NULL, PRIMARY KEY (fid, idx))''');
          await db.execute('''
            CREATE TABLE outbox(seq INTEGER PRIMARY KEY AUTOINCREMENT,
              id TEXT NOT NULL, rid TEXT NOT NULL, payload TEXT NOT NULL,
              created_ms INTEGER NOT NULL)''');
          await db.execute('''
            CREATE TABLE inbox_dedupe(from_rid TEXT NOT NULL, mid TEXT NOT NULL,
              seen_ms INTEGER NOT NULL, PRIMARY KEY (from_rid, mid))''');
        },
      ),
    );
    for (var i = 0; i < 3; i++) {
      await old.insert('messages', {
        'mid': 'old$i',
        'rid': 'peer',
        'outgoing': i % 2,
        'kind': 'text',
        'enc_body': 'sealed-$i', // opaque here; the vault key is not involved
        'ts_ms': 1000 + i,
        'status': 1,
        'expire_at_ms': 0,
      });
    }
    expect(await old.getVersion(), 1);
    await old.close();

    // Open with the current build: onUpgrade runs.
    final vault = await Vault.open(rootOverride: dir);
    expect(await vault.db.getVersion(), Vault.schemaVersion);
    final rows = await vault.db.query('messages',
        columns: ['mid', 'enc_body', 'reply_to'], orderBy: 'ts_ms');
    expect(rows.length, 3, reason: 'no message lost in the migration');
    expect(rows.map((r) => r['mid']), ['old0', 'old1', 'old2']);
    expect(rows.first['enc_body'], 'sealed-0');
    expect(rows.every((r) => r['reply_to'] == null), isTrue,
        reason: 'pre-8.1 messages are simply not replies');
    // The 8.1 columns and table are usable.
    await vault.db.update('messages', {'reply_to': 'old0', 'edited_ms': 5},
        where: 'mid = ?', whereArgs: ['old2']);
    await vault.db.insert('reactions', {
      'rid': 'peer',
      'mid': 'old0',
      'sender_rid': 'peer',
      'enc_emoji': 'sealed',
      'ts_ms': 1,
    });
    expect(
        (await vault.db
                .query('messages', where: 'mid = ?', whereArgs: ['old2']))
            .first['reply_to'],
        'old0');
    expect((await vault.db.query('reactions')).length, 1);
    await vault.db.close();

    // Re-opening an already-migrated vault is a no-op, not an error.
    final again = await Vault.open(rootOverride: dir);
    expect((await again.db.query('messages')).length, 3);
    await again.db.close();
    dir.deleteSync(recursive: true);
  });

  test('a fresh vault is created at the current schema', () async {
    final dir = await Directory.systemTemp.createTemp('z_fresh');
    final vault = await Vault.open(rootOverride: dir);
    expect(await vault.db.getVersion(), Vault.schemaVersion);
    await vault.db.insert('messages', {
      'mid': 'm1',
      'rid': 'r',
      'outgoing': 1,
      'kind': 'text',
      'enc_body': await vault.seal('hi'),
      'ts_ms': 1,
      'status': 1,
      'expire_at_ms': 0,
      'reply_to': null,
      'edited_ms': 0,
      'deleted': 0,
    });
    expect((await vault.db.query('messages')).length, 1);
    await vault.db.close();
    dir.deleteSync(recursive: true);
  });
}

// ---------------------------------------------------------------------------
// Two real clients through the real relay.
// ---------------------------------------------------------------------------
void _wireTests() {
  late Process relay;
  late int port;
  final temps = <Directory>[];
  final services = <ChatService>[];

  setUpAll(() async {
    final serverDir =
        '${Directory.current.parent.path}${Platform.pathSeparator}server';
    port = 41000 + DateTime.now().millisecondsSinceEpoch % 20000;
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

  Future<ChatService> makeClient(String name) async {
    final dir = await Directory.systemTemp.createTemp('z_reply_$name');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    final identity = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(identity.toJson()));
    final transport =
        Transport(identity: identity, serverUrl: 'ws://127.0.0.1:$port');
    final svc = await ChatService.init(
        vault: vault,
        identity: identity,
        displayName: name,
        transport: transport);
    services.add(svc);
    return svc;
  }

  Future<void> waitUntil(bool Function() cond,
      {Duration timeout = const Duration(seconds: 25)}) async {
    final deadline = DateTime.now().add(timeout);
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met');
      }
      await Future<void>.delayed(const Duration(milliseconds: 30));
    }
  }

  test('a reply travels as an id and is quoted from the receiver\'s own copy',
      () async {
    final alice = await makeClient('alice');
    final bob = await makeClient('bob');
    await waitUntil(
        () => alice.transport.isConnected && bob.transport.isConnected);
    await alice.addContactFromCode(await bob.myContactCode());
    await bob.addContactFromCode(await alice.myContactCode());
    await Future<void>.delayed(const Duration(seconds: 1));

    // Alice asks; Bob replies to that exact message.
    await alice.sendText(bob.myRid, 'are we still on for the hike?');
    await waitUntil(() => (bob.messagesByChat[alice.myRid] ?? [])
        .any((m) => m.body.contains('hike')));
    final asked =
        bob.messagesByChat[alice.myRid]!.firstWhere((m) => !m.outgoing);
    await bob.sendText(alice.myRid, 'yes — 7am', replyTo: asked.mid);

    // Bob's own copy quotes the message he answered.
    final bobsReply =
        bob.messagesByChat[alice.myRid]!.firstWhere((m) => m.outgoing);
    expect(bobsReply.replyTo, asked.mid);
    expect(bobsReply.quote!.preview, contains('hike'));
    expect(bobsReply.quote!.outgoing, isFalse, reason: 'Alice wrote it');

    // Alice receives it: the quote is resolved from HER stored copy.
    await waitUntil(() => (alice.messagesByChat[bob.myRid] ?? [])
        .any((m) => m.body.contains('7am')));
    final atAlice = alice.messagesByChat[bob.myRid]!
        .firstWhere((m) => m.body.contains('7am'));
    expect(atAlice.replyTo, asked.mid);
    expect(atAlice.quote, isNotNull);
    expect(atAlice.quote!.preview, contains('hike'));
    expect(atAlice.quote!.outgoing, isTrue, reason: 'Alice wrote the original');

    // Nothing of the quoted text is stored on the reply row itself: the link
    // is an id, and the body is only the reply's own words.
    final rows = await alice.vault.db.query('messages',
        columns: ['reply_to', 'enc_body'],
        where: 'rid = ? AND mid = ?',
        whereArgs: [bob.myRid, atAlice.mid]);
    expect(rows.first['reply_to'], asked.mid);
    expect((rows.first['enc_body'] as String).contains('hike'), isFalse);

    // Reloading from disk resolves the quote again.
    alice.messagesByChat.remove(bob.myRid);
    await alice.loadMessages(bob.myRid);
    expect(
        alice.messagesByChat[bob.myRid]!
            .firstWhere((m) => m.body.contains('7am'))
            .quote!
            .preview,
        contains('hike'));
  }, timeout: const Timeout(Duration(minutes: 2)), retry: 2);

  test('a reply id from another chat or an unknown id degrades to no quote',
      () async {
    final me = await makeClient('me');
    final pal = await makeClient('pal');
    final other = await makeClient('other');
    await waitUntil(() =>
        me.transport.isConnected &&
        pal.transport.isConnected &&
        other.transport.isConnected);
    for (final c in [pal, other]) {
      await me.addContactFromCode(await c.myContactCode());
      await c.addContactFromCode(await me.myContactCode());
    }
    await Future<void>.delayed(const Duration(seconds: 1));

    // A message that exists, but in the OTHER conversation.
    await other.sendText(me.myRid, 'secret in another chat');
    await waitUntil(() => (me.messagesByChat[other.myRid] ?? [])
        .any((m) => m.body.contains('secret')));
    final elsewhere = me.messagesByChat[other.myRid]!.first.mid;

    // Pal replies to it from a different conversation: the id must not
    // resolve, so nothing from the other chat can be surfaced (or probed).
    await pal.sendText(me.myRid, 'quoting across chats', replyTo: elsewhere);
    // …and to an id that exists nowhere at all.
    await pal.sendText(me.myRid, 'quoting thin air', replyTo: 'no-such-mid');
    await waitUntil(() =>
        (me.messagesByChat[pal.myRid] ?? []).where((m) => !m.outgoing).length >=
        2);

    for (final body in ['across chats', 'thin air']) {
      final m = me.messagesByChat[pal.myRid]!
          .firstWhere((m) => m.body.contains(body));
      expect(m.quote, isNull, reason: '$body must not resolve');
      expect(m.replyTo, isNull, reason: 'an unusable link is not stored');
    }
    // The other conversation is untouched.
    expect(me.messagesByChat[other.myRid]!.length, 1);
  }, timeout: const Timeout(Duration(minutes: 2)), retry: 2);

  test('an oversized or malformed reply id is ignored', () async {
    final dir = await Directory.systemTemp.createTemp('z_reply_raw');
    temps.add(dir);
    // The protocol layer alone: a 'rt' that is not a plausible id is dropped
    // before it can reach a query.
    final long = 'x' * 65;
    expect(InnerMessage.text('m', 1, 'hi', replyTo: long).replyTo, isNull);
    expect(InnerMessage.text('m', 1, 'hi', replyTo: '').replyTo, isNull);
    expect(
        InnerMessage.fromBytes(Uint8List.fromList(utf8
                .encode('{"k":"text","mid":"m","ts":1,"body":"hi","rt":7}')))
            .replyTo,
        isNull);
    // A well-formed one survives the round trip.
    final bytes = InnerMessage.text('m', 1, 'hi', replyTo: 'abc').toBytes();
    expect(InnerMessage.fromBytes(bytes).replyTo, 'abc');
  });
}
