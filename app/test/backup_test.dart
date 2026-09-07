// Encrypted backup and restore (phase 9). The claim being tested is the exit
// criterion from the roadmap: an archive taken on device A restores every
// message, contact, group and attachment onto a wiped device B, B then talks
// to a contact who never knew a restore happened, and the restored vault
// carries NO session state — because restoring a live ratchet onto a second
// device is the one thing this format must never do.
@Tags(['integration'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/archive.dart';
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

  Future<Directory> tempDir(String name) async {
    final d = await Directory.systemTemp.createTemp('z_bk_$name');
    temps.add(d);
    return d;
  }

  Future<ChatService> start(Directory dir, String name,
      {ZIdentity? identity}) async {
    final vault = await Vault.open(rootOverride: dir);
    final id = identity ??
        await () async {
          final stored = await vault.kvGet('identity');
          return stored == null
              ? await ZIdentity.generate()
              : await ZIdentity.fromJson(
                  (jsonDecode(stored) as Map).cast<String, Object?>());
        }();
    await vault.kvPut('identity', jsonEncode(id.toJson()));
    final transport =
        Transport(identity: id, serverUrl: 'ws://127.0.0.1:$port');
    final svc = await ChatService.init(
        vault: vault, identity: id, displayName: name, transport: transport);
    services.add(svc);
    return svc;
  }

  Future<void> waitUntil(bool Function() cond,
      {Duration timeout = const Duration(seconds: 25),
      String what = ''}) async {
    final deadline = DateTime.now().add(timeout);
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 30));
    }
  }

  test('a wiped device restores its history and keeps talking', () async {
    final aliceDir = await tempDir('alice');
    final alice = await start(aliceDir, 'Alice');
    final bob = await start(await tempDir('bob'), 'Bob');
    await waitUntil(
        () => alice.transport.isConnected && bob.transport.isConnected,
        what: 'both connected');
    await alice.addContactFromCode(await bob.myContactCode());
    await bob.addContactFromCode(await alice.myContactCode());
    await Future<void>.delayed(const Duration(seconds: 1));

    // A history worth losing: text both ways, a reply, a reaction, a group
    // and an attachment.
    await alice.sendText(bob.myRid, 'the survey data is ready');
    await waitUntil(() => (bob.messagesByChat[alice.myRid] ?? []).isNotEmpty,
        what: 'bob got the first message');
    final asked = bob.messagesByChat[alice.myRid]!.first.mid;
    await bob.sendText(alice.myRid, 'sending notes back', replyTo: asked);
    await bob.toggleReaction(alice.myRid, asked, '👍');
    await alice.sendFile(
        bob.myRid,
        'survey.csv',
        Uint8List.fromList(List<int>.generate(4096, (i) => i % 251)),
        'text/csv');
    final gid = await alice.createGroup('Field team', [bob.myRid]);
    await alice.sendGroupText(gid, 'meeting moved to Friday');
    await waitUntil(
        () =>
            (alice.messagesByChat[bob.myRid] ?? []).length >= 3 &&
            (alice.messagesByChat[gid] ?? []).isNotEmpty,
        what: 'alice has 3 direct + a group message');
    await waitUntil(
        () =>
            alice.messagesByChat[bob.myRid]!.any((m) => m.reactions.isNotEmpty),
        what: "alice sees bob's reaction");

    final beforeDirect = alice.messagesByChat[bob.myRid]!.length;
    final beforeGroup = alice.messagesByChat[gid]!.length;
    final aliceIdentity = alice.identity;

    // Take the backup.
    final code = await RecoveryCode.generate();
    final archive = File('${(await tempDir('file')).path}/z-backup.zbk');
    final sink = archive.openWrite();
    final written =
        await BackupArchive.export(vault: alice.vault, code: code, out: sink);
    await sink.close();
    expect(written, greaterThan(5));
    expect(await archive.length(), greaterThan(4096),
        reason: 'the attachment bytes are in there');

    // The phone is lost. Everything local is gone. (dispose() first: the
    // service's background timers would otherwise keep poking a closed db.)
    alice.dispose();
    await alice.transport.stop();
    services.remove(alice);
    await alice.vault.db.close();
    aliceDir.deleteSync(recursive: true);
    aliceDir.createSync(recursive: true);

    // A new device restores it.
    final freshVault = await Vault.open(rootOverride: aliceDir);
    final summary = await BackupArchive.import(
        vault: freshVault, file: archive, code: code);
    expect(summary.messages, beforeDirect + beforeGroup);
    expect(summary.contacts, 1);
    expect(summary.attachments, 1);

    // Session state is NOT restored: that is the point.
    expect(await freshVault.db.query('conversations'), isEmpty,
        reason: 'a restored ratchet could be used twice');

    await freshVault.db.close();
    final revived = await start(aliceDir, 'Alice', identity: aliceIdentity);
    await waitUntil(() => revived.transport.isConnected,
        what: 'restored device connected');
    await revived.loadMessages(bob.myRid);
    await revived.loadMessages(gid);

    // History is back, with its 8.1 structure intact.
    expect(revived.messagesByChat[bob.myRid]!.length, beforeDirect,
        reason: 'restored direct history');
    expect(revived.messagesByChat[gid]!.length, beforeGroup);
    expect(revived.contacts[bob.myRid]?.name, 'Bob');
    expect(revived.groups[gid]?.name, 'Field team');
    final reply = revived.messagesByChat[bob.myRid]!
        .firstWhere((m) => m.body.contains('notes back'));
    expect(reply.replyTo, asked);
    expect(reply.quote?.preview, contains('survey data'));
    expect(
        revived.messagesByChat[bob.myRid]!
            .firstWhere((m) => m.mid == asked)
            .reactions
            .single
            .emoji,
        '👍');

    // The attachment is readable again, byte for byte.
    final fileMsg =
        revived.messagesByChat[bob.myRid]!.firstWhere((m) => m.kind == 'file');
    final bytes = await revived.readAttachment(fileMsg.fid!);
    expect(bytes.length, 4096);
    expect(bytes[100], 100 % 251);

    // And the restored device can still talk to Bob, who knows nothing about
    // any of this: the session re-handshakes.
    await revived.sendText(bob.myRid, 'back on a new phone');
    await waitUntil(
        () => (bob.messagesByChat[revived.myRid] ?? [])
            .any((m) => m.body.contains('new phone')),
        what: 'bob got the post-restore message');
    // Bob now answers on the session the restored device opened. He keeps the
    // old one — he cannot tell a restore from a second device holding the same
    // key, so dropping it would let either cut the other off — but he must not
    // still be sending on it.
    final bobRows = await bob.vault.db
        .query('conversations', where: 'rid = ?', whereArgs: [revived.myRid]);
    final bobState = (jsonDecode(
            await bob.vault.unseal(bobRows.single['enc_state'] as String))
        as Map<String, Object?>);
    final revivedState0 = (jsonDecode(await revived.vault.unseal((await revived
            .vault.db
            .query('conversations', where: 'rid = ?', whereArgs: [bob.myRid]))
        .single['enc_state'] as String)) as Map<String, Object?>);
    expect((bobState['sessions'] as Map).keys, hasLength(2));
    expect(bobState['outboundSid'], revivedState0['outboundSid'],
        reason: 'Bob follows the restored device onto its new session');

    // And the reply comes back — over a re-established session AND a
    // re-established post-quantum layer, since the ML-KEM secret went with
    // the session the restore threw away.
    await bob.sendText(revived.myRid, 'welcome back');
    await waitUntil(
        () => (revived.messagesByChat[bob.myRid] ?? [])
            .any((m) => m.body.contains('welcome back')),
        what: 'restored device got a reply');
    final revivedState = (jsonDecode(await revived.vault.unseal((await revived
            .vault.db
            .query('conversations', where: 'rid = ?', whereArgs: [bob.myRid]))
        .single['enc_state'] as String)) as Map<String, Object?>);
    expect((revivedState['pq'] as Map)['k'], isNotNull,
        reason: 'the restored device is post-quantum again, not downgraded');
  }, timeout: const Timeout(Duration(minutes: 4)), retry: 1);

  test('a wrong code, a truncated file and a tampered byte all fail closed',
      () async {
    final dir = await tempDir('fail');
    final vault = await Vault.open(rootOverride: dir);
    await vault.kvPut(
        'identity', jsonEncode((await ZIdentity.generate()).toJson()));
    await vault.kvPut('display_name', 'Solo');
    await vault.db.insert('messages', {
      'mid': 'm1',
      'rid': 'peer',
      'outgoing': 1,
      'kind': 'text',
      'enc_body': await vault.seal('a message worth keeping'),
      'ts_ms': 1000,
      'status': 1,
      'expire_at_ms': 0,
    });

    final code = await RecoveryCode.generate();
    final archive = File('${dir.path}/a.zbk');
    final sink = archive.openWrite();
    await BackupArchive.export(vault: vault, code: code, out: sink);
    await sink.close();
    await vault.db.close();

    Future<Vault> emptyVault(String name) async =>
        Vault.open(rootOverride: await tempDir(name));

    // Wrong code: no oracle, just "it did not open".
    await expectLater(
        BackupArchive.import(
            vault: await emptyVault('w1'),
            file: archive,
            code: await RecoveryCode.generate()),
        throwsA(isA<FormatException>()));

    // Truncated: the terminator is missing, so the importer refuses rather
    // than restoring a silently shorter history.
    final full = await archive.readAsBytes();
    final cut = File('${dir.path}/cut.zbk')
      ..writeAsBytesSync(full.sublist(0, full.length - 40));
    await expectLater(
        BackupArchive.import(
            vault: await emptyVault('w2'), file: cut, code: code),
        throwsA(
            anyOf(isA<ArchiveIncompleteException>(), isA<FormatException>())));

    // A flipped byte in the body fails the tag.
    final bent = Uint8List.fromList(full);
    bent[bent.length - 20] ^= 0x01;
    final bentFile = File('${dir.path}/bent.zbk')..writeAsBytesSync(bent);
    await expectLater(
        BackupArchive.import(
            vault: await emptyVault('w3'), file: bentFile, code: code),
        throwsA(isA<Exception>()));

    // The good archive still restores, so the failures above are about the
    // damage and not about the format.
    final ok = await emptyVault('good');
    final summary =
        await BackupArchive.import(vault: ok, file: archive, code: code);
    expect(summary.messages, 1);
    expect(await ok.kvGet('display_name'), 'Solo');
    await ok.db.close();
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('an archive written at another schema still restores', () async {
    // A backup is only a backup if it opens on a build that is not the one
    // that wrote it. Both directions have to work: records from an OLDER
    // schema arrive without the columns added since (phase 8's reply, edit,
    // delete and forward fields), and a file from a NEWER one carries record
    // types and fields this build has never heard of — which it must skip
    // rather than refuse, or a user on a slightly older install is locked out
    // of their own history.
    final code = await RecoveryCode.generate();
    final salt = randomBytes(16);
    final noncePrefix = randomBytes(16);
    final key = await ZArchive.deriveKey(await code.keyMaterial(), salt);
    final header = ZArchive.buildHeader(
        salt: salt,
        noncePrefix: noncePrefix,
        schema: 1, // written long before the current schema
        createdMs: 1600000000000);

    final bodies = <(int, List<int>)>[
      (
        ZArchive.kindRecord,
        utf8.encode(jsonEncode({'t': 'meta', 'app': 'z', 'name': 'Vintage'}))
      ),
      // A schema-1 message: no reply_to, edited, deleted or forwarded.
      (
        ZArchive.kindRecord,
        utf8.encode(jsonEncode({
          't': 'message',
          'mid': 'old-1',
          'rid': 'peer',
          'out': 0,
          'kind': 'text',
          'body': 'written before any of this existed',
          'ts': 1600000000000,
          'status': 2,
          'expire': 0,
        }))
      ),
      // A record type from a future schema, with unknown fields.
      (
        ZArchive.kindRecord,
        utf8.encode(jsonEncode({
          't': 'poll',
          'mid': 'p1',
          'rid': 'peer',
          'options': ['a', 'b']
        }))
      ),
      (ZArchive.kindEnd, utf8.encode(jsonEncode({'t': 'end', 'records': 3}))),
    ];

    final dir = await tempDir('schema');
    final archive = File('${dir.path}/old.zbk');
    final sink = archive.openWrite();
    sink.add(header);
    sink.add(const [0x0a]);
    for (var i = 0; i < bodies.length; i++) {
      final sealed = await ZArchive.sealFrame(
          key: key,
          header: header,
          noncePrefix: noncePrefix,
          index: i,
          kind: bodies[i].$1,
          payload: bodies[i].$2);
      sink.add((ByteData(4)..setUint32(0, sealed.length)).buffer.asUint8List());
      sink.add(sealed);
    }
    await sink.close();

    final vault = await Vault.open(rootOverride: await tempDir('schema_in'));
    final summary =
        await BackupArchive.import(vault: vault, file: archive, code: code);
    expect(summary.schema, 1, reason: 'the archive says what wrote it');
    expect(summary.messages, 1);
    expect(await vault.kvGet('display_name'), 'Vintage');
    final row = (await vault.db.query('messages')).single;
    expect(await vault.unseal(row['enc_body'] as String),
        'written before any of this existed');
    // The columns phase 8 added take their defaults rather than failing.
    expect(row['reply_to'], isNull);
    expect(row['edited_ms'], 0);
    expect(row['deleted'], 0);
    expect(row['forwarded'], 0);
    await vault.db.close();
  }, timeout: const Timeout(Duration(minutes: 3)));
}
