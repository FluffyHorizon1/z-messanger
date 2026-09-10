// 15.3 — a group send must not make the user wait for the fan-out, and the
// fan-out must survive not finishing.
//
// Measured in `fanout_bench_test.dart` and written up in docs/PERFORMANCE.md:
// a fifty-member send costs ~1.2 s of per-recipient ratchet work, and
// `chat_screen.dart` awaited all of it with the composer disabled. The message
// was already on screen — only the method had not returned.
//
// Simply not awaiting would have removed the stall and made something worse.
// Before this, a crash part-way through the loop dropped every remaining
// recipient silently and forever; with a spinner on screen the user at least
// knew something was in flight. So the fan-out is now WRITTEN DOWN before it
// is performed, exactly as the outbox already does for delivery: the sender
// records one row per recipient in a single transaction, returns, and drains
// the queue in the background — resuming on the next start if it did not
// finish.
//
// These are the exit criteria for that change:
//
//   1. sendGroupText returns promptly for a large group.
//   2. Every member still receives the message.
//   3. A fan-out interrupted part-way is completed on the next start,
//      and the members already served are not served twice.
//   4. The message and its fan-out rows are written together or not at all.
//      Written apart, a kill between the two leaves a message on screen as
//      "pending" with nothing queued behind it — never sent, and nothing for
//      criterion 3 to resume.
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

  /// [offline] points the client at a port nothing is listening on, so the
  /// outbox cannot drain and its rows stay countable. It also models the real
  /// case this test is about: an app restarted without a network.
  Future<ChatService> makeClient(String name,
      {Directory? dir, bool offline = false}) async {
    final d = dir ?? await Directory.systemTemp.createTemp('z_gfo_$name');
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

  test('a large group send returns without waiting for the fan-out', () async {
    final svc = await makeClient('fast');
    final rids = <String>[];
    for (var i = 0; i < 20; i++) {
      rids.add(await addPhantom(svc, 'm$i'));
    }
    final gid = await svc.createGroup('Twenty', rids);
    // createGroup itself fans out an invite; let it settle so we time only
    // the message.
    await svc.waitForGroupFanout(gid);
    // Delivery off, so the outbox rows stay put and can be counted: they are
    // deleted the moment the relay acknowledges them. That is the right scope
    // anyway — what is under test is the SENDER's fan-out, not delivery.
    await svc.transport.stop();
    await svc.vault.db.delete('outbox');

    final sw = Stopwatch()..start();
    await svc.sendGroupText(gid, 'hello everyone');
    sw.stop();

    // The message is on screen immediately — that was already true — and now
    // the call returns without the per-recipient work. Measured at ~24 ms per
    // recipient, twenty recipients would be ~480 ms if it still awaited.
    expect(sw.elapsedMilliseconds, lessThan(250),
        reason: 'sendGroupText took ${sw.elapsedMilliseconds}ms for 20 '
            'members; it should record the fan-out and return, not perform it');

    // ...and every member is still served.
    await svc.waitForGroupFanout(gid);
    for (final rid in rids) {
      expect(await outboxCount(svc, rid), greaterThan(0),
          reason: 'member $rid never had anything queued');
    }
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('an interrupted fan-out is finished on the next start, once', () async {
    final dir = await Directory.systemTemp.createTemp('z_gfo_resume');
    temps.add(dir);

    var svc = await makeClient('resume', dir: dir);
    final rids = <String>[];
    for (var i = 0; i < 6; i++) {
      rids.add(await addPhantom(svc, 'r$i'));
    }
    final gid = await svc.createGroup('Six', rids);
    await svc.waitForGroupFanout(gid);
    await svc.transport.stop();
    await svc.vault.db.delete('outbox');

    // Stop the drain so the queue is written but not worked off — this is
    // what a kill part-way through looks like from the vault's point of view.
    svc.debugPauseGroupFanout = true;
    await svc.sendGroupText(gid, 'interrupted');

    final queued = await svc.vault.db.query('group_fanout');
    expect(queued.length, rids.length,
        reason: 'every recipient should be recorded before any is served');

    final before = <String, int>{
      for (final rid in rids) rid: await outboxCount(svc, rid)
    };

    await svc.transport.stop();

    // Restart onto the same vault, offline. The drain runs from init; the
    // outbox cannot flush, so what it produced stays visible.
    svc = await makeClient('resume2', dir: dir, offline: true);
    await svc.waitForGroupFanout(gid);

    for (final rid in rids) {
      expect(await outboxCount(svc, rid), before[rid]! + 1,
          reason: 'member $rid should have been served exactly once by the '
              'resumed fan-out — not zero times, and not twice');
    }
    expect((await svc.vault.db.query('group_fanout')).length, 0,
        reason: 'the queue should be empty once drained');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('the message row and its fan-out rows are one transaction', () async {
    final svc = await makeClient('atomic', offline: true);
    final rids = [for (var i = 0; i < 3; i++) await addPhantom(svc, 'a$i')];
    final gid = await svc.createGroup('Three', rids);
    await svc.waitForGroupFanout(gid);
    svc.debugPauseGroupFanout = true;

    Future<int> messages() async => (await svc.vault.db.query('messages',
            where: 'rid = ? AND outgoing = 1', whereArgs: [gid]))
        .length;
    Future<int> queued() async =>
        (await svc.vault.db.query('group_fanout')).length;
    final m0 = await messages();

    // Refuse the fan-out rows: the message row must not survive on its own.
    await svc.vault.db
        .execute('CREATE TRIGGER no_fanout BEFORE INSERT ON group_fanout '
            'BEGIN SELECT RAISE(ABORT, \'induced\'); END');
    await expectLater(svc.sendGroupText(gid, 'lost plan'), throwsA(anything));
    await svc.vault.db.execute('DROP TRIGGER no_fanout');
    expect(await messages(), m0,
        reason: 'the message row was committed without its fan-out rows: it '
            'shows as pending for ever and nothing will ever send it');
    expect(await queued(), 0);

    // And the other way round: refuse the message row, and no orphan plan
    // may be left behind to deliver a message that does not exist.
    await svc.vault.db
        .execute('CREATE TRIGGER no_message BEFORE INSERT ON messages '
            'BEGIN SELECT RAISE(ABORT, \'induced\'); END');
    await expectLater(
        svc.sendGroupText(gid, 'lost message'), throwsA(anything));
    await svc.vault.db.execute('DROP TRIGGER no_message');
    expect(await queued(), 0,
        reason: 'fan-out rows were committed for a message that was never '
            'written');
    expect(await messages(), m0);

    // Nothing induced: both land, and the plan has one row per member.
    await svc.sendGroupText(gid, 'this one is real');
    expect(await messages(), m0 + 1);
    expect(await queued(), rids.length);
    svc.debugPauseGroupFanout = false;
  }, timeout: const Timeout(Duration(minutes: 3)));
}
