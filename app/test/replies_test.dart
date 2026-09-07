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
import 'package:zapp/core/models.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:z_protocol/z_protocol.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  group('schema migration', _migrationTests);
  group('over the wire', _wireTests);
  group('reactions', _reactionTests);
  group('edit, delete and forward', _editDeleteTests);
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
    // An OS-assigned free port. The old formula derived the port from the
    // clock, so two suites starting in the same millisecond got the SAME
    // port — and `flutter test` runs files concurrently, so one relay lost
    // the bind and its whole file failed in setUpAll with 'relay did not
    // start'. Asking the OS removes the shared input entirely.
    final portProbe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    port = portProbe.port;
    await portProbe.close();
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

// ---------------------------------------------------------------------------
// 8.1b reactions. A reaction is a badge on an existing message: one per
// sender, replaceable, withdrawable, scoped to its conversation, and it never
// becomes a message of its own.
// ---------------------------------------------------------------------------
void _reactionTests() {
  late Process relay;
  late int port;
  final temps = <Directory>[];
  final services = <ChatService>[];

  setUpAll(() async {
    final serverDir =
        '${Directory.current.parent.path}${Platform.pathSeparator}server';
    // An OS-assigned free port. The old formula derived the port from the
    // clock, so two suites starting in the same millisecond got the SAME
    // port — and `flutter test` runs files concurrently, so one relay lost
    // the bind and its whole file failed in setUpAll with 'relay did not
    // start'. Asking the OS removes the shared input entirely.
    final portProbe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    port = portProbe.port;
    await portProbe.close();
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
    final dir = await Directory.systemTemp.createTemp('z_react_$name');
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

  List<MessageReaction> reactionsOn(ChatService s, String rid, String mid) =>
      s.messagesByChat[rid]!.firstWhere((m) => m.mid == mid).reactions;

  test('a reaction rides to the peer, replaces, and withdraws', () async {
    final ann = await makeClient('ann');
    final ben = await makeClient('ben');
    await waitUntil(
        () => ann.transport.isConnected && ben.transport.isConnected);
    await ann.addContactFromCode(await ben.myContactCode());
    await ben.addContactFromCode(await ann.myContactCode());
    await Future<void>.delayed(const Duration(seconds: 1));

    await ann.sendText(ben.myRid, 'shipping it today');
    await waitUntil(() => (ben.messagesByChat[ann.myRid] ?? [])
        .any((m) => m.body.contains('shipping')));
    final mid = ben.messagesByChat[ann.myRid]!.first.mid;

    // Ben reacts; Ann sees it on her own copy of the message she sent.
    expect(await ben.toggleReaction(ann.myRid, mid, '👍'), '👍');
    expect(reactionsOn(ben, ann.myRid, mid).single.mine, isTrue);
    await waitUntil(() => reactionsOn(ann, ben.myRid, mid).isNotEmpty);
    var atAnn = reactionsOn(ann, ben.myRid, mid).single;
    expect(atAnn.emoji, '👍');
    expect(atAnn.mine, isFalse);
    expect(atAnn.senderRid, ben.myRid);

    // A reaction is not a message: no row, no unread, no thread of its own.
    final rows = await ann.vault.db
        .query('messages', where: 'rid = ?', whereArgs: [ben.myRid]);
    expect(rows.length, 1, reason: 'still just the text message');
    expect(ann.unread[ben.myRid] ?? 0, 0);

    // A second reaction from the same sender REPLACES the first.
    expect(await ben.toggleReaction(ann.myRid, mid, '🙏'), '🙏');
    await waitUntil(
        () => reactionsOn(ann, ben.myRid, mid).single.emoji == '🙏');
    expect(reactionsOn(ann, ben.myRid, mid).length, 1);

    // Reacting again with the same emoji withdraws it.
    expect(await ben.toggleReaction(ann.myRid, mid, '🙏'), '');
    expect(reactionsOn(ben, ann.myRid, mid), isEmpty);
    await waitUntil(() => reactionsOn(ann, ben.myRid, mid).isEmpty);

    // It survives a reload from disk.
    expect(await ben.toggleReaction(ann.myRid, mid, '❤️'), '❤️');
    await waitUntil(() => reactionsOn(ann, ben.myRid, mid).isNotEmpty);
    ann.messagesByChat.remove(ben.myRid);
    await ann.loadMessages(ben.myRid);
    expect(reactionsOn(ann, ben.myRid, mid).single.emoji, '❤️');

    // …and the emoji is sealed at rest.
    final stored =
        await ann.vault.db.query('reactions', columns: ['enc_emoji']);
    expect(stored.single['enc_emoji'].toString().contains('❤'), isFalse);
  }, timeout: const Timeout(Duration(minutes: 2)), retry: 2);

  test('two members react in a group; each is kept separately', () async {
    final host = await makeClient('host');
    final m1 = await makeClient('m1');
    final m2 = await makeClient('m2');
    await waitUntil(() =>
        host.transport.isConnected &&
        m1.transport.isConnected &&
        m2.transport.isConnected);
    for (final c in [m1, m2]) {
      await host.addContactFromCode(await c.myContactCode());
      await c.addContactFromCode(await host.myContactCode());
    }
    await Future<void>.delayed(const Duration(seconds: 1));
    final gid = await host.createGroup('Crew', [m1.myRid, m2.myRid]);
    await waitUntil(
        () => m1.groups.containsKey(gid) && m2.groups.containsKey(gid));
    await host.sendGroupText(gid, 'launch at noon');
    await waitUntil(() =>
        (m1.messagesByChat[gid] ?? []).any((m) => m.body.contains('launch')) &&
        (m2.messagesByChat[gid] ?? []).any((m) => m.body.contains('launch')));
    final mid = m1.messagesByChat[gid]!
        .firstWhere((m) => m.body.contains('launch'))
        .mid;

    await m1.toggleReaction(gid, mid, '🎉');
    await m2.toggleReaction(gid, mid, '👍');
    await waitUntil(() => reactionsOn(host, gid, mid).length == 2);
    final byRid = {
      for (final r in reactionsOn(host, gid, mid)) r.senderRid: r.emoji
    };
    expect(byRid[m1.myRid], '🎉');
    expect(byRid[m2.myRid], '👍');
    // One member cannot clobber another's: m1 withdrawing leaves m2's.
    await m1.toggleReaction(gid, mid, '🎉');
    await waitUntil(() => reactionsOn(host, gid, mid).length == 1);
    expect(reactionsOn(host, gid, mid).single.senderRid, m2.myRid);
  }, timeout: const Timeout(Duration(minutes: 3)), retry: 2);

  test('a reaction to an unknown or cross-chat message is dropped', () async {
    final me = await makeClient('rme');
    final pal = await makeClient('rpal');
    final other = await makeClient('rother');
    await waitUntil(() =>
        me.transport.isConnected &&
        pal.transport.isConnected &&
        other.transport.isConnected);
    for (final c in [pal, other]) {
      await me.addContactFromCode(await c.myContactCode());
      await c.addContactFromCode(await me.myContactCode());
    }
    await Future<void>.delayed(const Duration(seconds: 1));

    await other.sendText(me.myRid, 'in the other chat');
    await waitUntil(() => (me.messagesByChat[other.myRid] ?? []).isNotEmpty);
    final elsewhere = me.messagesByChat[other.myRid]!.first.mid;

    // Pal reacts to a message that lives in a different conversation, and to
    // one that does not exist at all. Neither may land.
    // A well-behaved client refuses to send these, so play the hostile peer
    // directly: the receiver's check is what must hold.
    for (final target in [elsewhere, 'no-such-mid']) {
      await pal.sendRawInner(
          me.myRid,
          InnerMessage.reaction(
              newMessageId(), DateTime.now().millisecondsSinceEpoch,
              target: target, emoji: '👍'));
    }
    await pal.sendText(me.myRid, 'ping'); // ordering barrier
    await waitUntil(() =>
        (me.messagesByChat[pal.myRid] ?? []).any((m) => m.body == 'ping'));
    expect(await me.vault.db.query('reactions'), isEmpty);
    // The other conversation is untouched.
    expect(reactionsOn(me, other.myRid, elsewhere), isEmpty);
  }, timeout: const Timeout(Duration(minutes: 2)), retry: 2);

  test('an oversized or control-laden emoji never reaches the vault', () {
    // Protocol level: the payload is rejected before any storage.
    expect(
        InnerMessage.reaction('m', 1, target: 't', emoji: 'x' * 33)
            .reactionData,
        isNull);
    expect(
        InnerMessage.reaction('m', 1, target: 't', emoji: 'a\nb').reactionData,
        isNull);
    expect(InnerMessage.reaction('m', 1, target: '', emoji: '👍').reactionData,
        isNull);
    final ok = InnerMessage.reaction('m', 1, target: 'tgt', emoji: '👍');
    expect(ok.reactionData!.target, 'tgt');
    expect(ok.reactionData!.emoji, '👍');
    // The withdrawal form is valid and carries an empty emoji.
    expect(
        InnerMessage.reaction('m', 1, target: 'tgt', emoji: '')
            .reactionData!
            .emoji,
        '');
  });
}

// ---------------------------------------------------------------------------
// 8.1c edit / delete-for-everyone / forward. The security property is
// authorship: a peer may only change what it wrote, and in a group — where
// fan-out means anyone can address anyone — that has to be enforced against
// the recorded sender, not against who happens to be asking.
// ---------------------------------------------------------------------------
void _editDeleteTests() {
  late Process relay;
  late int port;
  final temps = <Directory>[];
  final services = <ChatService>[];

  setUpAll(() async {
    final serverDir =
        '${Directory.current.parent.path}${Platform.pathSeparator}server';
    // An OS-assigned free port. The old formula derived the port from the
    // clock, so two suites starting in the same millisecond got the SAME
    // port — and `flutter test` runs files concurrently, so one relay lost
    // the bind and its whole file failed in setUpAll with 'relay did not
    // start'. Asking the OS removes the shared input entirely.
    final portProbe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    port = portProbe.port;
    await portProbe.close();
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
    final dir = await Directory.systemTemp.createTemp('z_ed_$name');
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

  ChatMessage msgOf(ChatService s, String rid, String mid) =>
      s.messagesByChat[rid]!.firstWhere((m) => m.mid == mid);

  test('an edit reaches the peer, is marked, and keeps its place', () async {
    final ed = await makeClient('ed');
    final flo = await makeClient('flo');
    await waitUntil(
        () => ed.transport.isConnected && flo.transport.isConnected);
    await ed.addContactFromCode(await flo.myContactCode());
    await flo.addContactFromCode(await ed.myContactCode());
    await Future<void>.delayed(const Duration(seconds: 1));

    await ed.sendText(flo.myRid, 'see you at 6');
    await ed.sendText(flo.myRid, 'bring the tickets');
    await waitUntil(() => (flo.messagesByChat[ed.myRid] ?? []).length >= 2);
    final first = flo.messagesByChat[ed.myRid]!.first;
    final originalTs = first.ts;

    expect(await ed.editMessage(flo.myRid, first.mid, 'see you at 7'), isTrue);
    await waitUntil(() => msgOf(flo, ed.myRid, first.mid).body.endsWith('7'));
    final atFlo = msgOf(flo, ed.myRid, first.mid);
    expect(atFlo.editedMs, greaterThan(0), reason: 'an edit is never silent');
    expect(atFlo.ts, originalTs, reason: 'editing must not reorder');
    expect(flo.messagesByChat[ed.myRid]!.first.mid, first.mid);
    // The old text is gone from disk, not merely hidden.
    final rows = await flo.vault.db.query('messages',
        columns: ['enc_body'], where: 'mid = ?', whereArgs: [first.mid]);
    expect(await flo.vault.unseal(rows.first['enc_body'] as String),
        'see you at 7');

    // Flo cannot edit Ed's message, however she asks.
    await flo.sendRawInner(
        ed.myRid,
        InnerMessage.edit(newMessageId(), DateTime.now().millisecondsSinceEpoch,
            target: first.mid, body: 'I never said this'));
    await flo.sendText(ed.myRid, 'barrier');
    await waitUntil(() =>
        (ed.messagesByChat[flo.myRid] ?? []).any((m) => m.body == 'barrier'));
    expect(msgOf(ed, flo.myRid, first.mid).body, 'see you at 7');
    expect(msgOf(ed, flo.myRid, first.mid).editedMs, greaterThan(0));
  }, timeout: const Timeout(Duration(minutes: 2)), retry: 2);

  test('delete for everyone tombstones on both sides and takes the blob',
      () async {
    final gus = await makeClient('gus');
    final hal = await makeClient('hal');
    await waitUntil(
        () => gus.transport.isConnected && hal.transport.isConnected);
    await gus.addContactFromCode(await hal.myContactCode());
    await hal.addContactFromCode(await gus.myContactCode());
    await Future<void>.delayed(const Duration(seconds: 1));

    await gus.sendText(hal.myRid, 'oops wrong chat');
    await gus.sendFile(hal.myRid, 'private.pdf',
        Uint8List.fromList(List<int>.filled(2048, 7)), 'application/pdf');
    await waitUntil(() => (hal.messagesByChat[gus.myRid] ?? []).length >= 2);
    final textMid =
        hal.messagesByChat[gus.myRid]!.firstWhere((m) => m.kind == 'text').mid;
    final fileMsg =
        hal.messagesByChat[gus.myRid]!.firstWhere((m) => m.kind == 'file');
    await waitUntil(
        () => msgOf(hal, gus.myRid, fileMsg.mid).file?.complete == true);

    await gus.deleteForEveryone(hal.myRid, [textMid, fileMsg.mid]);
    await waitUntil(() => msgOf(hal, gus.myRid, textMid).deleted);
    await waitUntil(() => msgOf(hal, gus.myRid, fileMsg.mid).deleted);

    // Tombstone, not a hole: the row stays so the conversation keeps shape.
    expect(hal.messagesByChat[gus.myRid]!.length, 2);
    expect(msgOf(hal, gus.myRid, textMid).body, isEmpty);
    // Body and attachment are actually gone from disk.
    final rows = await hal.vault.db.query('messages',
        columns: ['enc_body', 'fid'], where: 'mid = ?', whereArgs: [textMid]);
    expect(await hal.vault.unseal(rows.first['enc_body'] as String), '');
    expect(await hal.vault.db.query('files'), isEmpty);
    expect(await hal.vault.db.query('chunks'), isEmpty);
    expect(File('${hal.vault.filesDir.path}/${fileMsg.fid}.bin').existsSync(),
        isFalse);
    // The sender's own copy is a tombstone too.
    expect(msgOf(gus, hal.myRid, textMid).deleted, isTrue);

    // Hal cannot delete Gus's remaining messages by asking.
    await gus.sendText(hal.myRid, 'still here');
    await waitUntil(() => (hal.messagesByChat[gus.myRid] ?? [])
        .any((m) => m.body == 'still here'));
    final survivor = hal.messagesByChat[gus.myRid]!
        .firstWhere((m) => m.body == 'still here')
        .mid;
    await hal.sendRawInner(
        gus.myRid,
        InnerMessage.deleteForEveryone(
            newMessageId(), DateTime.now().millisecondsSinceEpoch,
            targets: [survivor]));
    await hal.sendText(gus.myRid, 'barrier');
    await waitUntil(() =>
        (gus.messagesByChat[hal.myRid] ?? []).any((m) => m.body == 'barrier'));
    expect(msgOf(gus, hal.myRid, survivor).deleted, isFalse,
        reason: 'only the author may delete for everyone');
  }, timeout: const Timeout(Duration(minutes: 2)), retry: 2);

  test('a group member cannot edit or delete a neighbour\'s message', () async {
    final owner = await makeClient('owner');
    final rogue = await makeClient('rogue');
    final bystander = await makeClient('bystander');
    await waitUntil(() =>
        owner.transport.isConnected &&
        rogue.transport.isConnected &&
        bystander.transport.isConnected);
    for (final c in [rogue, bystander]) {
      await owner.addContactFromCode(await c.myContactCode());
      await c.addContactFromCode(await owner.myContactCode());
    }
    // The two members also know each other, so the rogue can address the
    // bystander directly — exactly the position a group member is in.
    await rogue.addContactFromCode(await bystander.myContactCode());
    await bystander.addContactFromCode(await rogue.myContactCode());
    await Future<void>.delayed(const Duration(seconds: 1));

    final gid =
        await owner.createGroup('Board', [rogue.myRid, bystander.myRid]);
    await waitUntil(() =>
        rogue.groups.containsKey(gid) && bystander.groups.containsKey(gid));
    await owner.sendGroupText(gid, 'the vote is on Thursday');
    await waitUntil(() => (bystander.messagesByChat[gid] ?? [])
        .any((m) => m.body.contains('Thursday')));
    final target = bystander.messagesByChat[gid]!
        .firstWhere((m) => m.body.contains('Thursday'))
        .mid;

    // The rogue is a legitimate member of this group, and sends the
    // bystander a gedit and a gdel naming the OWNER's message.
    await rogue.sendRawInner(
        bystander.myRid,
        InnerMessage.edit(newMessageId(), DateTime.now().millisecondsSinceEpoch,
            target: target, body: 'the vote is cancelled', gid: gid));
    await rogue.sendRawInner(
        bystander.myRid,
        InnerMessage.deleteForEveryone(
            newMessageId(), DateTime.now().millisecondsSinceEpoch,
            targets: [target], gid: gid));
    await rogue.sendGroupText(gid, 'barrier');
    await waitUntil(() =>
        (bystander.messagesByChat[gid] ?? []).any((m) => m.body == 'barrier'));

    final still = msgOf(bystander, gid, target);
    expect(still.body, contains('Thursday'),
        reason: 'a member may not rewrite another member\'s message');
    expect(still.editedMs, 0);
    expect(still.deleted, isFalse,
        reason: 'a member may not delete another member\'s message');

    // The owner CAN edit and delete their own, over the same channel.
    expect(await owner.editMessage(gid, target, 'the vote moved to Friday'),
        isTrue);
    await waitUntil(
        () => msgOf(bystander, gid, target).body.contains('Friday'));
    await owner.deleteForEveryone(gid, [target]);
    await waitUntil(() => msgOf(bystander, gid, target).deleted);
  }, timeout: const Timeout(Duration(minutes: 3)), retry: 2);

  test('forwarding sends a new message marked as forwarded', () async {
    final ida = await makeClient('ida');
    final jon = await makeClient('jon');
    final kim = await makeClient('kim');
    await waitUntil(() =>
        ida.transport.isConnected &&
        jon.transport.isConnected &&
        kim.transport.isConnected);
    for (final c in [jon, kim]) {
      await ida.addContactFromCode(await c.myContactCode());
      await c.addContactFromCode(await ida.myContactCode());
    }
    await Future<void>.delayed(const Duration(seconds: 1));

    await jon.sendText(ida.myRid, 'the venue changed to the old mill');
    await waitUntil(() => (ida.messagesByChat[jon.myRid] ?? []).isNotEmpty);
    final received = ida.messagesByChat[jon.myRid]!.first;

    await ida.forwardMessage(jon.myRid, received.mid, kim.myRid);
    await waitUntil(() => (kim.messagesByChat[ida.myRid] ?? []).isNotEmpty);
    final atKim = kim.messagesByChat[ida.myRid]!.first;
    expect(atKim.body, contains('old mill'));
    expect(atKim.forwarded, isTrue);
    // A NEW message, not a replay of Jon's: different id, and it is from Ida.
    expect(atKim.mid, isNot(received.mid));
    expect(atKim.outgoing, isFalse);
    // Ida's own copy is marked too, and survives a reload.
    expect(ida.messagesByChat[kim.myRid]!.single.forwarded, isTrue);
    ida.messagesByChat.remove(kim.myRid);
    await ida.loadMessages(kim.myRid);
    expect(ida.messagesByChat[kim.myRid]!.single.forwarded, isTrue);
    // Nothing about Jon travels with it: the marker is a flag, not provenance.
    expect(atKim.senderName, isNull);
  }, timeout: const Timeout(Duration(minutes: 2)), retry: 2);
}
