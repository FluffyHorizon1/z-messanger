// The relay envelope id, and what it used to give away (client review P1).
//
// A group message is ONE inner message fanned to N members over N pairwise
// ratchets — so N envelopes, to N mailboxes, from one socket. The outbox row
// carried the inner `mid` as its envelope id, so all N of those envelopes
// arrived at the relay bearing one identical string: the recipient set,
// handed over directly, needing none of the timing analysis R18 describes.
// And a `mid` is plaintext to every member of the group, so any one of them
// could name a message to the operator and be told retroactively who else
// received it.
//
// `PROTOCOL.md` §12.2 said the envelope id was "unrelated to `mid`" and
// `THREAT_MODEL.md`'s relay row said membership could not be learned "from
// any envelope". The rule was right from the start; the client broke it.
//
// The same confusion had a second, visible symptom: a group message's status
// update looked for its row under the MEMBER's routing id, while the row
// lives under the group's, so it matched nothing and the clock stayed grey
// for ever.
//
// Criteria, each a test below:
//  1. every envelope the relay receives carries a distinct id, and no id is
//     ever a message's mid — asserted against what the relay actually
//     delivered, not against what the client meant to send;
//  2. a group message reaches `sent` when the LAST member's envelope has
//     gone, and not before;
//  3. a 1:1 message still reaches `sent`, and its envelope id is not its mid;
//  4. an outbox queued by an older build still marks its message sent after
//     the migration.
//
// What is NOT here: the relay's own `delivered` frame names an ENVELOPE, and
// this client used to read it as a message id — unscoped by conversation, so
// whatever it matched, it flipped. It is ignored now, and nothing is lost by
// that: the relay sends it only for an envelope whose sender it knows, and
// every envelope this client sends is sealed and leaves on a connection that
// never authenticated (§12.1). Criterion 1 asserts the consequence — nothing
// reaches `delivered` off the back of a send.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/models.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  late Process relay;
  late int port;
  final temps = <Directory>[];
  final live = <ChatService>[];

  setUpAll(() async {
    HttpOverrides.global = null;
    sqfliteFfiInit();
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
    for (final s in live) {
      await s.transport.stop();
      await s.vault.db.close();
    }
    relay.kill();
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<ChatService> sender(String name) async {
    final dir = await Directory.systemTemp.createTemp('z_eid_');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    final me = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(me.toJson()));
    final transport =
        Transport(identity: me, serverUrl: 'ws://127.0.0.1:$port');
    final svc = await ChatService.init(
        vault: vault, identity: me, displayName: name, transport: transport);
    live.add(svc);
    for (var i = 0; i < 60 && !transport.isConnected; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    return svc;
  }

  /// A member who is never online: a mailbox, and an identity to be added as
  /// a contact. Their envelopes simply queue, which is what this is about.
  Future<(ZIdentity, String)> member(ChatService svc, String name) async {
    final id = await ZIdentity.generate();
    final code = (await id.bundle(displayName: name)).encode();
    final c = await svc.addContactFromCode(code, alias: name);
    return (id, c.rid);
  }

  /// Everything sitting in a mailbox, read without acknowledging it.
  Future<List<RelayInbound>> mailbox(ZIdentity id) async {
    final c = await RelayClient.connect('ws://127.0.0.1:$port', id);
    final got = <RelayInbound>[];
    final sub = c.messages.listen(got.add);
    await Future<void>.delayed(const Duration(milliseconds: 900));
    await sub.cancel();
    await c.close();
    return got;
  }

  Future<void> settle(ChatService svc) async {
    for (var i = 0; i < 40; i++) {
      await svc.flushOutbox();
      final left = firstIntValue(
              await svc.vault.db.rawQuery('SELECT COUNT(*) FROM outbox')) ??
          0;
      if (left == 0) return;
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
  }

  test('1. every envelope carries a distinct id, and never a message id',
      () async {
    final alice = await sender('Alice');
    final (bobId, bobRid) = await member(alice, 'Bob');
    final (carolId, carolRid) = await member(alice, 'Carol');

    final gid = await alice.createGroup('Three', [bobRid, carolRid]);
    await alice.sendGroupText(gid, 'hello both of you');
    await settle(alice);

    final mid = (await alice.vault.db.query('messages',
            columns: ['mid'],
            where: 'rid = ? AND outgoing = 1 AND kind = ?',
            whereArgs: [gid, 'gtext']))
        .single['mid'] as String;

    final bob = await mailbox(bobId);
    final carol = await mailbox(carolId);
    expect(bob, isNotEmpty, reason: 'the group message reached Bob');
    expect(carol, isNotEmpty, reason: 'and Carol');

    final all = [...bob, ...carol].map((e) => e.id).toList();
    expect(all.toSet().length, all.length,
        reason: 'one id per envelope: a shared id IS the recipient set');
    expect(all, isNot(contains(mid)),
        reason: 'and no envelope is named after the message inside it');

    // Stated the other way round, which is the property rather than a
    // consequence of it: two mailboxes never see one envelope id, so the
    // relay cannot pair them by matching one.
    expect(
        bob.map((e) => e.id).toSet().intersection(carol.map((e) => e.id).toSet()),
        isEmpty,
        reason: 'a shared id between two mailboxes IS the recipient set');

    // And nothing marked itself delivered on the way: a relay receipt names
    // an envelope, is never sent for a sealed one, and is no longer read as
    // a message id.
    final delivered = firstIntValue(await alice.vault.db.rawQuery(
        'SELECT COUNT(*) FROM messages WHERE outgoing = 1 AND status >= ?',
        [MsgStatus.delivered]));
    expect(delivered, 0);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('2. a group message is sent when the last member\'s envelope has gone',
      () async {
    // Its own relay, with a small mailbox cap, so ONE member can be made
    // unreachable while the other is not — which is the case the rule exists
    // for and the only honest way to stage it.
    final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final p2 = probe.port;
    await probe.close();
    final relay2 = await Process.start('node', ['server.js'],
        workingDirectory:
            '${Directory.current.parent.path}${Platform.pathSeparator}server',
        environment: {
          'PORT': '$p2',
          'LOG_LEVEL': 'silent',
          'MAX_QUEUE_MSGS_PER_USER': '12',
        });
    try {
      for (var i = 0; i < 60; i++) {
        try {
          final res = await (await HttpClient()
                  .getUrl(Uri.parse('http://127.0.0.1:$p2/health')))
              .close();
          await res.drain<void>();
          if (res.statusCode == 200) break;
        } catch (_) {
          await Future<void>.delayed(const Duration(milliseconds: 100));
        }
      }
      final url = 'ws://127.0.0.1:$p2';
      final dir = await Directory.systemTemp.createTemp('z_eid2_');
      temps.add(dir);
      final vault = await Vault.open(rootOverride: dir);
      final me = await ZIdentity.generate();
      await vault.kvPut('identity', jsonEncode(me.toJson()));
      final transport = Transport(identity: me, serverUrl: url);
      final alice = await ChatService.init(
          vault: vault, identity: me, displayName: 'Alice',
          transport: transport);
      live.add(alice);
      for (var i = 0; i < 60 && !transport.isConnected; i++) {
        await Future<void>.delayed(const Duration(milliseconds: 100));
      }

      final bobId = await ZIdentity.generate();
      final carolId = await ZIdentity.generate();
      final bobRid = (await alice.addContactFromCode(
              (await bobId.bundle(displayName: 'Bob')).encode(),
              alias: 'Bob'))
          .rid;
      final carolRid = (await alice.addContactFromCode(
              (await carolId.bundle(displayName: 'Carol')).encode(),
              alias: 'Carol'))
          .rid;
      final gid = await alice.createGroup('Three', [bobRid, carolRid]);
      await settle(alice);

      // Fill Carol's mailbox until the relay refuses it. Now Carol is the
      // member whose copy cannot leave, and Bob is the one whose can.
      final stuffer =
          await RelayClient.connect(url, await ZIdentity.generate());
      for (var i = 0; i < 200; i++) {
        try {
          await stuffer.send(
              to: carolRid, id: newMessageId(), payload: 'junk-$i');
        } on RelayException catch (e) {
          expect(e.message, contains('queue_full'));
          break;
        }
      }
      await stuffer.close();

      await alice.sendGroupText(gid, 'one of you is full');
      for (var i = 0; i < 6; i++) {
        await alice.flushOutbox();
        await Future<void>.delayed(const Duration(milliseconds: 150));
      }

      Future<int> status() async => (await alice.vault.db.query('messages',
              columns: ['status'],
              where: 'rid = ? AND outgoing = 1 AND kind = ?',
              whereArgs: [gid, 'gtext']))
          .single['status'] as int;
      final mid = (await alice.vault.db.query('messages',
              columns: ['mid'],
              where: 'rid = ? AND outgoing = 1 AND kind = ?',
              whereArgs: [gid, 'gtext']))
          .single['mid'] as String;
      final held = firstIntValue(await alice.vault.db.rawQuery(
          'SELECT COUNT(*) FROM outbox WHERE rid = ? AND mid = ?',
          [carolRid, mid]));
      expect(held, greaterThan(0),
          reason: "Carol's copy of THIS message is still queued");
      expect(await status(), MsgStatus.pending,
          reason: 'one member of two has it: that is not "sent"');

      // Carol reads her mailbox, so it drains and her copy can leave.
      final carol = await RelayClient.connect(url, carolId);
      final drained = <RelayInbound>[];
      final sub = carol.messages.listen(drained.add);
      await Future<void>.delayed(const Duration(seconds: 1));
      for (final e in drained) {
        carol.ackReceived(id: e.id, from: e.from);
      }
      await Future<void>.delayed(const Duration(milliseconds: 400));
      await sub.cancel();
      await carol.close();

      for (var i = 0; i < 10; i++) {
        await alice.flushOutbox();
        if (await status() == MsgStatus.sent) break;
        await Future<void>.delayed(const Duration(milliseconds: 200));
      }
      expect(await status(), MsgStatus.sent,
          reason: 'and once the last copy has gone, it is');
    } finally {
      relay2.kill();
    }
  }, timeout: const Timeout(Duration(minutes: 4)));

  test('3. a 1:1 message still reaches sent, under an id that is not its mid',
      () async {
    final alice = await sender('Alice');
    final (bobId, bobRid) = await member(alice, 'Bob');
    await alice.sendText(bobRid, 'just you');
    await settle(alice);

    final row = (await alice.vault.db.query('messages',
            columns: ['mid', 'status'],
            where: 'rid = ? AND outgoing = 1 AND kind = ?',
            whereArgs: [bobRid, 'text']))
        .single;
    expect(row['status'], MsgStatus.sent);

    final ids = (await mailbox(bobId)).map((e) => e.id).toList();
    expect(ids, isNotEmpty);
    expect(ids, isNot(contains(row['mid'])));
    expect(ids.toSet().length, ids.length);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('4. an outbox queued by an older build still marks its message sent',
      () async {
    final dir = await Directory.systemTemp.createTemp('z_eid_mig_');
    temps.add(dir);
    // A database written before the envelope id and the message id were told
    // apart: the outbox row's id IS the mid.
    final old = await databaseFactoryFfi.openDatabase(
      '${dir.path}${Platform.pathSeparator}z.db',
      options: OpenDatabaseOptions(
        version: 1,
        onCreate: (db, _) async {
          await db.execute('''
            CREATE TABLE messages(mid TEXT NOT NULL, rid TEXT NOT NULL,
              outgoing INTEGER NOT NULL, kind TEXT NOT NULL,
              enc_body TEXT NOT NULL, ts_ms INTEGER NOT NULL,
              status INTEGER NOT NULL, expire_at_ms INTEGER NOT NULL DEFAULT 0,
              PRIMARY KEY (mid, rid))''');
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
    await old.insert('messages', {
      'mid': 'oldmid',
      'rid': 'peer',
      'outgoing': 1,
      'kind': 'text',
      'enc_body': 'sealed',
      'ts_ms': 1000,
      'status': MsgStatus.pending,
      'expire_at_ms': 0,
    });
    await old.insert('outbox', {
      'id': 'oldmid', // the old convention
      'rid': 'peer',
      'payload': 'sealed',
      'created_ms': 1000,
    });
    await old.insert('outbox', {
      'id': 'a-chunk-envelope', // never a mid, even before
      'rid': 'peer',
      'payload': 'sealed',
      'created_ms': 1001,
    });
    await old.close();

    final vault = await Vault.open(rootOverride: dir);
    expect(await vault.db.getVersion(), Vault.schemaVersion);
    final rows = await vault.db.query('outbox', orderBy: 'seq');
    expect(rows.length, 2, reason: 'nothing queued was lost');
    expect(rows.first['mid'], 'oldmid',
        reason: 'the row that carried a message now says which');
    expect(rows.first['thread_rid'], 'peer');
    expect(rows.last['mid'], isNull,
        reason: 'a chunk envelope is given no mid it does not have');
    expect(rows.last['thread_rid'], isNull);
    await vault.db.close();
  }, timeout: const Timeout(Duration(minutes: 2)));
}
