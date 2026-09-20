// 23.2 — a group FILE send goes through the durable fan-out like a text does.
//
// 15.3 queued text, reactions, edits and deletes through `group_fanout` and
// left `sendGroupFile` synchronous, because its fan-out carries per-recipient
// chunk payloads that "would have to be stored again per row". They are not
// stored at all now: the drain rebuilds each member's chunk rows from the
// vault blob when that member's turn comes — `chunkNonce` is derived from the
// file nonce and the index, so every rebuild is byte-identical — and commits
// them with that member's offer. The membership snapshot at queue time, which
// carries the security property, is the same one text has.
//
// Criteria, each a test below (the first four mirror group_fanout_test's):
//   1. sendGroupFile returns promptly for a large group;
//   2. every member is still served — the offer AND every chunk;
//      (Criteria 1 and 2 share a test, as in the text suite: the timing is
//      only meaningful if the same send is then shown to have reached everyone.)
//   3. a fan-out interrupted part-way is completed on the next start, and a
//      member already served is not served twice;
//   4. the file row, the message row and the fan-out rows are written together
//      or not at all; and a member's offer and chunks land together, so nobody
//      holds a key without its chunks or chunks without their key;
//   5. a member removed before the send receives neither the key nor a chunk,
//      and one removed after it still receives what was sent while they were
//      a member — the ordering the queue preserves.
@Tags(['integration'])
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

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

  Future<ChatService> makeClient(String name,
      {Directory? dir, bool offline = false}) async {
    final d = dir ?? await Directory.systemTemp.createTemp('z_gff_$name');
    if (dir == null) temps.add(d);
    final vault = await Vault.open(rootOverride: d);
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

  Future<String> addPhantom(ChatService svc, String tag) async {
    final id = await ZIdentity.generate();
    final code = (await id.bundle(displayName: tag)).encode();
    await svc.addContactFromCode(code);
    return (await ContactBundle.decode(code)).routingId();
  }

  Future<int> outboxCount(ChatService svc, String rid) async {
    final rows = await svc.vault.db
        .query('outbox', columns: ['id'], where: 'rid = ?', whereArgs: [rid]);
    return rows.length;
  }

  // Big enough for several chunks, so "every chunk" means something.
  final payload = Uint8List.fromList(List.generate(300 * 1024, (i) => i % 251));
  final chunkCount = splitChunks(payload).length;
  // What one member's fan-out puts in the outbox: the offer plus the chunks.
  final perMember = 1 + chunkCount;

  test('1+2. a large group file send returns promptly, and everyone is served',
      () async {
    expect(chunkCount, greaterThan(1), reason: 'the payload spans chunks');
    final svc = await makeClient('fast');
    final rids = <String>[];
    for (var i = 0; i < 20; i++) {
      rids.add(await addPhantom(svc, 'm$i'));
    }
    final gid = await svc.createGroup('Twenty', rids);
    await svc.waitForGroupFanout(gid);
    await svc.transport.stop();
    await svc.vault.db.delete('outbox');

    final sw = Stopwatch()..start();
    await svc.sendGroupFile(gid, 'clip.bin', payload, 'application/octet-stream');
    sw.stop();
    // Before 23.2 this awaited the offer and the sealed chunks for every one
    // of twenty members; now it writes the blob, the rows and the plan, and
    // returns. The bound is loose enough for the blob write on a slow disk
    // and far below twenty members' worth of sealing.
    expect(sw.elapsedMilliseconds, lessThan(400),
        reason: 'sendGroupFile took ${sw.elapsedMilliseconds}ms for 20 '
            'members; it should record the fan-out and return, not perform it');

    await svc.waitForGroupFanout(gid);
    for (final rid in rids) {
      expect(await outboxCount(svc, rid), perMember,
          reason: 'member $rid should hold the offer and every chunk');
    }
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('3. an interrupted file fan-out is finished on the next start, once',
      () async {
    final dir = await Directory.systemTemp.createTemp('z_gff_resume');
    temps.add(dir);
    var svc = await makeClient('resume', dir: dir);
    final rids = [for (var i = 0; i < 6; i++) await addPhantom(svc, 'r$i')];
    final gid = await svc.createGroup('Six', rids);
    await svc.waitForGroupFanout(gid);
    await svc.transport.stop();
    await svc.vault.db.delete('outbox');

    svc.debugPauseGroupFanout = true;
    await svc.sendGroupFile(gid, 'clip.bin', payload, 'application/octet-stream');
    expect((await svc.vault.db.query('group_fanout')).length, rids.length,
        reason: 'every recipient recorded before any is served');
    for (final rid in rids) {
      expect(await outboxCount(svc, rid), 0,
          reason: 'nothing performed yet — the drain is paused');
    }
    await svc.transport.stop();

    // Restart onto the same vault, offline: the drain runs from init and
    // rebuilds the chunks from the blob it finds there.
    svc = await makeClient('resume2', dir: dir, offline: true);
    await svc.waitForGroupFanout(gid);
    for (final rid in rids) {
      expect(await outboxCount(svc, rid), perMember,
          reason: 'member $rid served exactly once by the resumed fan-out');
    }
    expect((await svc.vault.db.query('group_fanout')).length, 0);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('4. file, message and plan are one transaction; offer and chunks too',
      () async {
    final svc = await makeClient('atomic', offline: true);
    final rids = [for (var i = 0; i < 3; i++) await addPhantom(svc, 'a$i')];
    final gid = await svc.createGroup('Three', rids);
    await svc.waitForGroupFanout(gid);
    svc.debugPauseGroupFanout = true;

    Future<int> messages() async => (await svc.vault.db.query('messages',
            where: 'rid = ? AND outgoing = 1', whereArgs: [gid]))
        .length;
    Future<int> files() async =>
        (await svc.vault.db.query('files', where: 'rid = ?', whereArgs: [gid]))
            .length;
    Future<int> queued() async =>
        (await svc.vault.db.query('group_fanout')).length;
    final m0 = await messages();
    final f0 = await files();

    // Refuse the fan-out rows: neither the file nor the message may survive.
    await svc.vault.db
        .execute('CREATE TRIGGER no_fanout BEFORE INSERT ON group_fanout '
            'BEGIN SELECT RAISE(ABORT, \'induced\'); END');
    await expectLater(
        svc.sendGroupFile(gid, 'lost.bin', payload, 'application/octet-stream'),
        throwsA(anything));
    await svc.vault.db.execute('DROP TRIGGER no_fanout');
    expect(await messages(), m0, reason: 'no message row without its plan');
    expect(await files(), f0, reason: 'no file row without its plan');
    expect(await queued(), 0);

    // Refuse the message row: no orphan plan for a message that never was.
    await svc.vault.db
        .execute('CREATE TRIGGER no_message BEFORE INSERT ON messages '
            'BEGIN SELECT RAISE(ABORT, \'induced\'); END');
    await expectLater(
        svc.sendGroupFile(gid, 'lost2.bin', payload, 'application/octet-stream'),
        throwsA(anything));
    await svc.vault.db.execute('DROP TRIGGER no_message');
    expect(await queued(), 0);
    expect(await files(), f0);

    // Nothing induced: all three land, one plan row per member.
    await svc.sendGroupFile(gid, 'real.bin', payload, 'application/octet-stream');
    expect(await messages(), m0 + 1);
    expect(await files(), f0 + 1);
    expect(await queued(), rids.length);

    // Per member, the offer and the chunks are one transaction: refuse the
    // second outbox row for a member and that member gets NOTHING, and the
    // plan row stays so the next drain serves them whole. (The invite rows
    // from createGroup are cleared first, so the counts below are this
    // send's alone.)
    await svc.vault.db.delete('outbox');
    await svc.vault.db.execute(
        'CREATE TRIGGER one_row BEFORE INSERT ON outbox WHEN '
        '(SELECT COUNT(*) FROM outbox WHERE rid = NEW.rid) >= 1 '
        'BEGIN SELECT RAISE(ABORT, \'induced\'); END');
    svc.debugPauseGroupFanout = false;
    await svc.drainGroupFanoutForTest();
    for (final rid in rids) {
      expect(await outboxCount(svc, rid), 0,
          reason: 'member $rid must not hold a key without its chunks');
    }
    expect(await queued(), rids.length, reason: 'nothing was consumed');
    await svc.vault.db.execute('DROP TRIGGER one_row');
    await svc.drainGroupFanoutForTest();
    await svc.waitForGroupFanout(gid);
    for (final rid in rids) {
      expect(await outboxCount(svc, rid), perMember);
    }
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('5. removed before the send: no key, no chunk; removed after: served',
      () async {
    final svc = await makeClient('ordering');
    final rids = [for (var i = 0; i < 4; i++) await addPhantom(svc, 'o$i')];
    final gid = await svc.createGroup('Four', rids);
    await svc.waitForGroupFanout(gid);
    await svc.transport.stop();

    final before = rids[0];
    await svc.removeGroupMember(gid, before);
    await svc.waitForGroupFanout(gid);
    // The removal itself told them; from here on they are owed nothing.
    await svc.vault.db.delete('outbox');

    await svc.sendGroupFile(gid, 'clip.bin', payload, 'application/octet-stream');
    // Removed AFTER the send was queued: still a recipient of that send.
    final after = rids[1];
    await svc.removeGroupMember(gid, after);
    await svc.waitForGroupFanout(gid);

    expect(await outboxCount(svc, before), 0,
        reason: 'removed before the send: not the offer, not a chunk');
    expect(await outboxCount(svc, after), greaterThanOrEqualTo(perMember),
        reason: 'removed after the send was queued: the file still goes, plus '
            'the invite that removes them');
    for (final rid in rids.sublist(2)) {
      expect(await outboxCount(svc, rid), greaterThanOrEqualTo(perMember));
    }
  }, timeout: const Timeout(Duration(minutes: 3)));
}
