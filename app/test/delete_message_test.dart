// Delete removed the row and kept the file.
//
// `deleteMessage` is the user saying "get this off my phone". It deleted the
// `messages` row and the delivery receipts, and stopped. What it left behind
// for an attachment was the whole attachment: the `files` row — which holds
// the NAME the user gave it and the key its blob is sealed under — the blob,
// any chunks that had not been drained, and the reactions on the message.
// Nothing in the app could reach any of it afterwards, and nothing ever
// collected it, so it stayed for the life of the vault.
//
// That is bad on its own and worse on the way out. `BackupArchive.export`
// walks `files` directly, not through `messages`, so a photo the user deleted
// was written into every archive taken after it, under the filename they
// deleted it by. A backup handed to somebody — the whole point of the format
// — carried the thing its owner had already decided nobody should have.
//
// The other three deletion paths (`_tombstone`, the disappearing-message
// sweeper, and removing a contact) already destroyed the blob, the row and
// the chunks. This one was the odd one out.
//
// Behind it sits a storage question the same size: a row deleted from SQLite
// leaves its bytes on a free page. A message body is sealed, but `mid`, `rid`
// and `ts_ms` are columns in the clear, so a freed page still testifies that
// a message existed in that conversation at that moment — and the sealed body
// sits beside it for whoever later gets the master key.
//
// Criteria, each a test below:
//  1. deleting a message with an attachment destroys the blob, the key it was
//     sealed under and the name it was stored under — not just the row that
//     pointed at them;
//  2. a backup taken after a delete does not carry what was deleted;
//  3. the reactions and delivery receipts on a message go when it goes;
//  4. a vault opened after an older build orphaned rows and blobs sweeps them,
//     and a deleted message's id is not left readable in the database file.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/archive.dart';
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
      s.dispose();
      await s.transport.stop();
    }
    relay.kill();
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<Directory> tempDir(String name) async {
    final d = await Directory.systemTemp.createTemp('z_del_$name');
    temps.add(d);
    return d;
  }

  Future<ChatService> start(Directory dir, String name) async {
    final vault = await Vault.open(rootOverride: dir);
    final id = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(id.toJson()));
    final transport =
        Transport(identity: id, serverUrl: 'ws://127.0.0.1:$port');
    final svc = await ChatService.init(
        vault: vault, identity: id, displayName: name, transport: transport);
    live.add(svc);
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

  /// A pair of connected, mutually-added devices.
  Future<(ChatService, ChatService)> pair(String tag) async {
    final a = await start(await tempDir('${tag}a'), 'Alice');
    final b = await start(await tempDir('${tag}b'), 'Bob');
    await waitUntil(() => a.transport.isConnected && b.transport.isConnected,
        what: 'both connected');
    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());
    await Future<void>.delayed(const Duration(milliseconds: 400));
    return (a, b);
  }

  test('a deleted attachment leaves no blob, no key and no filename',
      () async {
    final (alice, bob) = await pair('one');
    await alice.sendFile(bob.myRid, 'clinic-roster.csv',
        Uint8List.fromList(List<int>.generate(6000, (i) => i % 251)), 'text/csv');
    await waitUntil(
        () => (alice.messagesByChat[bob.myRid] ?? [])
            .any((m) => m.kind == 'file'),
        what: 'alice has the outgoing file row');
    final mid =
        alice.messagesByChat[bob.myRid]!.firstWhere((m) => m.kind == 'file').mid;

    // What is on disk before the delete, so the assertions after it are about
    // something that was really there.
    final before =
        await alice.vault.db.query('files', where: 'mid = ?', whereArgs: [mid]);
    expect(before, hasLength(1), reason: 'the attachment row exists');
    final fid = before.first['fid'] as String;
    final meta = (jsonDecode(await alice.vault.unseal(
        before.first['enc_meta'] as String)) as Map).cast<String, Object?>();
    expect(meta['name'], 'clinic-roster.csv');
    final blob = File('${alice.vault.filesDir.path}/$fid.bin');
    expect(blob.existsSync(), isTrue, reason: 'the sealed blob exists');

    await alice.deleteMessage(bob.myRid, mid);

    expect(
        await alice.vault.db.query('files', where: 'fid = ?', whereArgs: [fid]),
        isEmpty,
        reason: 'the row holding the name and the blob key is gone');
    expect(
        await alice.vault.db
            .query('chunks', where: 'fid = ?', whereArgs: [fid]),
        isEmpty);
    expect(blob.existsSync(), isFalse, reason: 'the blob is gone');
    expect(
        await alice.vault.db
            .query('messages', where: 'rid = ? AND mid = ?',
                whereArgs: [bob.myRid, mid]),
        isEmpty);
  });

  test('a backup taken after a delete does not carry what was deleted',
      () async {
    final (alice, bob) = await pair('two');
    await alice.sendFile(bob.myRid, 'kept.csv',
        Uint8List.fromList(List<int>.filled(2048, 7)), 'text/csv');
    await alice.sendFile(bob.myRid, 'deleted-payslip.pdf',
        Uint8List.fromList(List<int>.filled(4096, 42)), 'application/pdf');
    await waitUntil(
        () =>
            (alice.messagesByChat[bob.myRid] ?? [])
                .where((m) => m.kind == 'file')
                .length ==
            2,
        what: 'both attachments are in the thread');
    final files =
        alice.messagesByChat[bob.myRid]!.where((m) => m.kind == 'file').toList();
    // Which is which: the row's sealed metadata carries the name.
    String? doomed;
    for (final m in files) {
      final r = await alice.vault.db
          .query('files', where: 'mid = ?', whereArgs: [m.mid], limit: 1);
      final name = (jsonDecode(await alice.vault.unseal(
          r.first['enc_meta'] as String)) as Map)['name'];
      if (name == 'deleted-payslip.pdf') doomed = m.mid;
    }
    expect(doomed, isNotNull);

    await alice.deleteMessage(bob.myRid, doomed!);

    final code = await RecoveryCode.generate();
    final archive = File('${(await tempDir('arc')).path}/after-delete.zbk');
    final sink = archive.openWrite();
    await BackupArchive.export(vault: alice.vault, code: code, out: sink);
    await sink.close();

    // Restore it and look at what came back, rather than at the file: the
    // question is what a person holding this archive can recover.
    final freshDir = await tempDir('fresh');
    final fresh = await Vault.open(rootOverride: freshDir);
    final summary =
        await BackupArchive.import(vault: fresh, file: archive, code: code);
    expect(summary.attachments, 1,
        reason: 'only the attachment that was not deleted');
    final names = <Object?>[];
    for (final r in await fresh.db.query('files')) {
      names.add((jsonDecode(await fresh.unseal(r['enc_meta'] as String))
          as Map)['name']);
    }
    expect(names, ['kept.csv']);
    expect(freshDir.listSync(recursive: true).whereType<File>().length,
        greaterThan(0));
    await fresh.db.close();
  });

  test('reactions and delivery receipts go when the message goes', () async {
    final (alice, bob) = await pair('three');
    await alice.sendText(bob.myRid, 'the invoice is attached');
    await waitUntil(() => (bob.messagesByChat[alice.myRid] ?? []).isNotEmpty,
        what: 'bob has it');
    final mid = bob.messagesByChat[alice.myRid]!.first.mid;
    await bob.toggleReaction(alice.myRid, mid, '👍');
    await bob.flushDeliveryReceipts();
    await waitUntil(
        () => alice.messagesByChat[bob.myRid]!
            .any((m) => m.mid == mid && m.reactions.isNotEmpty),
        what: 'alice sees the reaction');
    await waitUntil(
        () => alice.messagesByChat[bob.myRid]!
            .any((m) => m.mid == mid && m.status >= MsgStatus.delivered),
        what: 'alice sees the tick');
    expect(
        await alice.vault.db.query('reactions',
            where: 'rid = ? AND mid = ?', whereArgs: [bob.myRid, mid]),
        isNotEmpty,
        reason: 'the reaction is stored');
    expect(
        await alice.vault.db.query('delivery',
            where: 'thread_rid = ? AND mid = ?', whereArgs: [bob.myRid, mid]),
        isNotEmpty,
        reason: 'the receipt is stored');

    await alice.deleteMessage(bob.myRid, mid);

    expect(
        await alice.vault.db.query('reactions',
            where: 'rid = ? AND mid = ?', whereArgs: [bob.myRid, mid]),
        isEmpty,
        reason: 'who reacted, and with what, is not a thing to keep');
    expect(
        await alice.vault.db.query('delivery',
            where: 'thread_rid = ? AND mid = ?', whereArgs: [bob.myRid, mid]),
        isEmpty);
  });

  test('an opened vault sweeps what an older build orphaned, and a deleted '
      'id is not left readable in the file', () async {
    final dir = await tempDir('sweep');
    final vault = await Vault.open(rootOverride: dir);

    // Exactly what the old `deleteMessage` left: a `files` row, its blob, its
    // chunks, a reaction and a receipt, with no message naming any of them.
    // Real file ids: §7 says sixteen base64url characters and `Vault` now
    // refuses anything else (`file_id_test.dart`), so a test that plants an
    // orphan has to plant one that could really have been written.
    final fid = b64url(randomBytes(12));
    const mid = 'ZZorphanMIDZZ';
    const rid = 'orphan-rid';
    final strayFid = b64url(randomBytes(12));
    final keyInfo = await vault.writeBlob(
        fid, Uint8List.fromList(List<int>.filled(1024, 9)));
    await vault.db.insert('files', {
      'fid': fid,
      'rid': rid,
      'mid': mid,
      'enc_meta': await vault.seal(jsonEncode(
          {'name': 'orphan-payslip.pdf', 'size': 1024, 'local': keyInfo})),
      'complete': 1,
      'got_chunks': 1,
      'total_chunks': 1,
    });
    await vault.db.insert(
        'chunks', {'fid': fid, 'idx': 0, 'payload': 'leftover'});
    await vault.db.insert('reactions', {
      'rid': rid,
      'mid': mid,
      'sender_rid': 'someone',
      'enc_emoji': await vault.seal('👍'),
      'ts_ms': 1,
    });
    await vault.db.insert(
        'delivery', {'mid': mid, 'thread_rid': rid, 'from_rid': 'x', 'at_ms': 1});
    // A blob nothing ever named at all — the crash window between writeBlob
    // and the transaction that records it.
    await vault.writeBlob(strayFid, Uint8List.fromList([1, 2, 3]));
    await vault.db.close();

    final reopened = await Vault.open(rootOverride: dir);
    expect(await reopened.db.query('files'), isEmpty,
        reason: 'the orphaned attachment row is swept');
    expect(await reopened.db.query('chunks'), isEmpty);
    expect(await reopened.db.query('reactions'), isEmpty);
    expect(await reopened.db.query('delivery'), isEmpty);
    expect(File('${reopened.filesDir.path}/$fid.bin').existsSync(), isFalse,
        reason: 'and so is its blob');
    expect(
        File('${reopened.filesDir.path}/$strayFid.bin').existsSync(), isFalse,
        reason: 'and a blob no row ever named');

    // The other half: a deleted row does not leave its plaintext columns on a
    // free page. `mid` is stored in the clear, so it is exactly what a
    // forensic reader would find.
    //
    // This passes today because the SQLite that `sqlite3_flutter_libs`
    // bundles is compiled with `secure_delete` already on — the pragma the
    // vault sets is a pin, not a fix, and removing it does not make this
    // test fail. What it is for is the day a dependency bump changes that
    // default: with the pin gone too, this is what notices.
    const doomedMid = 'QQdoomedMIDQQ';
    await reopened.db.insert('messages', {
      'mid': doomedMid,
      'rid': 'r1',
      'outgoing': 1,
      'kind': 'text',
      'enc_body': await reopened.seal('the part that was sealed'),
      'ts_ms': 1,
      'status': 0,
    });
    final dbFile = File('${dir.path}/z.db');
    expect(utf8.decode(dbFile.readAsBytesSync(), allowMalformed: true),
        contains(doomedMid),
        reason: 'it really is in the file while the row is there');
    await reopened.db
        .delete('messages', where: 'mid = ?', whereArgs: [doomedMid]);
    await reopened.db.close();
    expect(utf8.decode(dbFile.readAsBytesSync(), allowMalformed: true),
        isNot(contains(doomedMid)),
        reason: 'a freed page keeps nothing');
  });
}
