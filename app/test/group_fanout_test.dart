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
//      (Criteria 1 and 2 share a test: the timing is only meaningful if the
//      same send is then shown to have reached everyone.)
//   3. A fan-out interrupted part-way is completed on the next start,
//      and the members already served are not served twice.
//   4. The message and its fan-out rows are written together or not at all.
//      Written apart, a kill between the two leaves a message on screen as
//      "pending" with nothing queued behind it — never sent, and nothing for
//      criterion 3 to resume.
//
// And since, each with a test of its own:
//
//   5. One member in transparency conflict does not wedge every group.
//   6. A retry asked for during a drain is not lost: the running drain,
//      which may already have stepped over the row the retry is for, sweeps
//      the queue once more before it stops.
//   7. 48.3 (ADR 0036 §4): the drain writes a member's file chunks only while
//      the outbox holds less than the staging bound. Past it the file waits,
//      queued, and only a change to who is in the group waits behind it — a
//      list removing one of them waits behind the file for both — while
//      everything else goes: the text after the file to all three, the
//      same members in another group; and once the outbox holds less, the
//      next member's file is staged, and its list after it.
//   8. Members' copies are staged under the bound, a member at a time, so
//      members' rows stay at or under the bound and one member's file; my
//      own devices' copies are queued at once, outside it, within the
//      budget.
//   9. On a SQLite without `octet_length` the vault falls back, at open, to
//      measuring with `length`, and the bound still holds.
//  10. A measure that fails stages nothing: the file waits, with any change
//      to who is in the group behind it, the text goes, and the next drain
//      that can measure stages it.
@Tags(['integration'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/models.dart';
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

  Future<void> waitUntil(FutureOr<bool> Function() cond,
      {Duration timeout = const Duration(seconds: 30),
      required String what}) async {
    final deadline = DateTime.now().add(timeout);
    while (!await cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
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

  test('5. one member in transparency conflict does not wedge every group',
      () async {
    // Every KT banner on the chat screen is gated on the chat NOT being a
    // group, and the kinds a conflict holds include every group kind. So a
    // group message to a member in conflict threw per-member inside the
    // drain, which caught it and left the row — and `_markSentIfLast` counts
    // every queued row, so the message stayed `pending` for EVERY member,
    // with nothing on screen to say why and no way to answer it.
    //
    // The second-order failure is the one that made it an outage rather than
    // a confusion: the drain reads a page of 32 ordered by `seq` and used to
    // read it from the head every time. Once 32 held rows accumulated there,
    // no group message to ANY member of ANY group was delivered at all.
    final svc = await makeClient('wedged', offline: true);
    final held = await addPhantom(svc, 'held');
    final fine = await addPhantom(svc, 'fine');
    final gid = await svc.createGroup('Two', [held, fine]);
    await svc.waitForGroupFanout(gid);

    // That member goes into conflict, which holds what the user says to them.
    svc.kt.debugForceConflict(held);
    expect(svc.kt.sendsHeld(held), isTrue);

    // A baseline: creating the group already fanned an invite out to each
    // member, and a key offer may have gone with it. What this test is about
    // is the forty sends below, so count from here.
    final fineBefore = await outboxCount(svc, fine);
    final heldBefore = await outboxCount(svc, held);

    // Forty group messages: more than the page of 32, so the old drain would
    // have had nothing but held rows in view.
    for (var i = 0; i < 40; i++) {
      await svc.sendGroupText(gid, 'm$i');
    }
    // Poll rather than call once: a drain is already running in the
    // background (every send kicks one) and the guard makes a second call
    // return immediately, so a single `retryGroupFanout` proves nothing
    // about when it finished.
    Future<int> queuedFor(String rid) async => (await svc.vault.db
            .query('group_fanout', where: 'rid = ?', whereArgs: [rid]))
        .length;
    final deadline = DateTime.now().add(const Duration(seconds: 60));
    while (await queuedFor(fine) > 0 && DateTime.now().isBefore(deadline)) {
      await svc.retryGroupFanout();
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }

    // The member who is fine received every one of them — which is what a
    // page permanently full of held rows prevented.
    expect(await queuedFor(fine), 0,
        reason: 'envelopes for the member in good standing were still queued '
            'behind the held ones');
    expect(await outboxCount(svc, fine), fineBefore + 40,
        reason: 'every group message reached the member who is fine');

    // The held member's rows are still there, so answering the conflict
    // delivers them rather than losing them.
    final stillHeld = await svc.vault.db
        .query('group_fanout', where: 'rid = ?', whereArgs: [held]);
    expect(stillHeld, hasLength(40), reason: 'kept, not dropped');
    expect(await outboxCount(svc, held), heldBefore,
        reason: 'and nothing was sent to them while the conflict stood');

    // And the screen can say so, naming them — which is the whole of what a
    // group chat had no way to do.
    expect(svc.groupSendsHeldFor, {held});
    expect(svc.groupSendsHeldNames, ['held']);

    // "Send anyway", as the 1:1 screen has always offered: the conflict is
    // acknowledged and the queue drains.
    await svc.kt.acknowledgeConflict(held);
    final d2 = DateTime.now().add(const Duration(seconds: 60));
    while (await queuedFor(held) > 0 && DateTime.now().isBefore(d2)) {
      await svc.retryGroupFanout();
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    expect(await queuedFor(held), 0,
        reason: 'answering the conflict sends what was waiting');
    expect(await outboxCount(svc, held), heldBefore + 40,
        reason: 'every message that was waiting goes, none lost');
  }, timeout: const Timeout(Duration(minutes: 5)));

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

  test('6. a retry asked for during a drain is not lost', () async {
    // A drain asked for while one ran — `retryGroupFanout`, a transparency
    // conflict lifting (`ktChanged`), a reconnect — returned at once and
    // recorded nothing. If the running drain had already stepped over the
    // row that call was for, and sent nothing else on that sweep, it
    // stopped, and the row waited for the next send or reconnect. Seen as
    // group_timers_test 11's copy for Max, held while Ada's own drain ran,
    // staying in her queue.
    final svc = await makeClient('again', offline: true);
    final member = await addPhantom(svc, 'again');
    Future<int> queuedFor(String rid) async => (await svc.vault.db
            .query('group_fanout', where: 'rid = ?', whereArgs: [rid]))
        .length;

    // Nothing drains until the test starts one: the group's invite and the
    // message are queued, and that one drain works them off.
    svc.debugPauseGroupFanout = true;
    final gid = await svc.createGroup('One', [member]);
    await svc.sendGroupText(gid, 'asked for again mid-drain');
    expect(await queuedFor(member), 2);
    final mid = svc.messagesByChat[gid]!
        .singleWhere((m) => m.body == 'asked for again mid-drain')
        .mid;

    // The message's row is held, and the hold is the seam at which the
    // drain is part-way: it is asked about the row once a sweep. The first
    // sweep sends the invite and steps over the message, so the drain sweeps
    // again. On that second sweep, with nothing else left to send, the hold
    // is lifted and a retry asked for — while the drain runs, the row just
    // stepped over — as an answered conflict asks for one in the field.
    var asked = 0;
    svc.debugHoldGroupFanout = (rid, inner) {
      if (rid != member || inner.mid != mid) return false;
      if (++asked == 2) {
        svc.debugHoldGroupFanout = null;
        unawaited(svc.retryGroupFanout());
      }
      return true;
    };
    svc.debugPauseGroupFanout = false;
    await svc.drainGroupFanoutForTest();
    expect(asked, 2,
        reason: 'the retry was asked for on the sweep that stepped over the '
            'row and sent nothing');

    await waitUntil(() async => await queuedFor(member) == 0,
        what: 'the row the drain had stepped over leaves the queue');
    final sent = await svc.vault.db.query('outbox',
        where: 'rid = ? AND mid = ?', whereArgs: [member, mid]);
    expect(sent, hasLength(1), reason: 'the message is served, once');
  }, timeout: const Timeout(Duration(minutes: 3)));

  // ---- 48.3: the staging bound -------------------------------------------

  const full = ChatService.chunkEnvelopeChars;

  /// The outbox's rows that carry a full chunk, by mailbox.
  Future<Map<String, int>> chunkRows(ChatService svc) async {
    final rows = await svc.vault.db.rawQuery(
        'SELECT rid, COUNT(*) AS n FROM outbox WHERE LENGTH(payload) = ? '
        'GROUP BY rid',
        [full]);
    return {for (final r in rows) r['rid'] as String: r['n'] as int};
  }

  /// The mailboxes the outbox holds [mid] for.
  Future<Set<String>> outboxTo(ChatService svc, String mid) async => {
        for (final r in await svc.vault.db.query('outbox',
            columns: ['rid'], where: 'mid = ?', whereArgs: [mid]))
          r['rid'] as String
      };

  /// What waits in [gid]'s queue, member by member, as (mid, kind), in order.
  Future<Map<String, List<(String, String)>>> queuedIn(
      ChatService svc, String gid) async {
    final out = <String, List<(String, String)>>{};
    for (final r in await svc.vault.db.query('group_fanout',
        where: 'gid = ?', whereArgs: [gid], orderBy: 'seq')) {
      final inner = InnerMessage.fromBytes(Uint8List.fromList(
          utf8.encode(await svc.vault.unseal(r['payload'] as String))));
      (out[r['rid'] as String] ??= []).add((inner.mid, inner.kind));
    }
    return out;
  }

  Future<int> queuedChars(ChatService svc) async =>
      firstIntValue(await svc.vault.db.rawQuery(
          'SELECT COALESCE(SUM(LENGTH(payload)), 0) FROM outbox')) ??
      0;

  /// A group of three for [svc] and a second group of the same three; the
  /// outbox emptied once both are made, as the relay would have taken it.
  Future<(List<String>, String, String)> twoGroups(ChatService svc) async {
    final rids = [for (var i = 0; i < 3; i++) await addPhantom(svc, 'b$i')];
    final gid = await svc.createGroup('Files', rids);
    final other = await svc.createGroup('Talk', rids);
    await svc.waitForGroupFanout(gid);
    await svc.waitForGroupFanout(other);
    await svc.vault.db.delete('outbox');
    return (rids, gid, other);
  }

  test(
      '7. a file past the staging bound waits for the outbox, and only a '
      'change to who is in the group waits behind it', () async {
    // Offline, so the outbox never drains and what the drain wrote stays to
    // be read.
    final svc = await makeClient('bound', offline: true);
    final (rids, gid, other) = await twoGroups(svc);

    // A file of three whole chunks: one member's are 1 048 830 characters,
    // and the bound is two chunks' envelopes.
    svc.groupStagingBound = 2 * full;
    final file = Uint8List(3 * defaultChunkSize);
    await svc.sendGroupFile(gid, 'big.bin', file, 'application/octet-stream');
    await svc.sendGroupText(gid, 'after the file');
    await svc.sendGroupText(other, 'in the other group');
    String midOf(String thread, bool Function(ChatMessage) which) =>
        svc.messagesByChat[thread]!.singleWhere(which).mid;
    final fileMid = midOf(gid, (m) => m.kind == 'file');
    final textMid = midOf(gid, (m) => m.body == 'after the file');
    final otherMid = midOf(other, (m) => m.body == 'in the other group');

    // The other group's text leaves the queue last, so once it has, the
    // drain has been over every row.
    await waitUntil(
        () async =>
            (await svc.vault.db.query('group_fanout',
                    where: 'gid = ?', whereArgs: [other]))
                .isEmpty &&
            (await outboxTo(svc, otherMid)).length == rids.length,
        what: 'the text sent to the other group went to all three, so the '
            'drain has been over every row');

    // One member's chunks were written; then the outbox was past the bound.
    final staged = await chunkRows(svc);
    expect(staged.values.toList(), [3],
        reason: 'one member\'s chunks, and no one else\'s');
    final first = staged.keys.single;
    expect(await queuedChars(svc), greaterThanOrEqualTo(svc.groupStagingBound),
        reason: 'what stopped the drain is the outbox it measured');
    final rest = {...rids}..remove(first);
    // The other two members' file waits, and nothing else does: the text
    // after the file went to all three, theirs included.
    expect(await queuedIn(svc, gid), {
      for (final r in rest) r: [(fileMid, 'gfile')]
    });
    expect(await outboxTo(svc, textMid), rids.toSet(),
        reason: 'the text after the file went to every member, the two '
            'whose file waits included');
    final firstRows = await svc.vault.db.rawQuery(
        'SELECT seq, mid, LENGTH(payload) AS n FROM outbox WHERE rid = ? '
        'ORDER BY seq',
        [first]);
    final lastChunk = firstRows.lastWhere((r) => r['n'] == full)['seq'] as int;
    expect(firstRows.singleWhere((r) => r['mid'] == textMid)['seq'] as int,
        greaterThan(lastChunk),
        reason: 'to the member whose chunks are staged, behind them');
    expect(await outboxTo(svc, otherMid), rids.toSet(),
        reason: 'another group is not held behind this one\'s file');

    // A change to who is in the group does wait: one of the two is removed,
    // and the list saying so waits behind the file for both — the one it
    // removes would read it first and then refuse the file. A text to the
    // other group after it leaves the queue last: once it has gone to all
    // three, the drain has been over the list.
    final gone = rest.first;
    await svc.removeGroupMember(gid, gone);
    await svc.sendGroupText(other, 'after the removal');
    final laterMid = midOf(other, (m) => m.body == 'after the removal');
    await waitUntil(
        () async => (await outboxTo(svc, laterMid)).length == rids.length,
        what: 'the text sent after the removal went to all three, so the '
            'drain has been over the list');
    final lists = {
      for (final rows in (await queuedIn(svc, gid)).values)
        for (final (mid, kind) in rows)
          if (kind == 'ginvite') mid
    };
    expect(lists, hasLength(1),
        reason: 'the list waits behind the file, and is the only one');
    final listMid = lists.single;
    expect(await outboxTo(svc, listMid), contains(first),
        reason: 'the list went to the member whose chunks are staged');
    expect(await queuedIn(svc, gid), {
      for (final r in rest) r: [(fileMid, 'gfile'), (listMid, 'ginvite')]
    }, reason: 'the list waits behind the file, for the member it removes '
        'and for the other');

    // The relay takes what was staged: the next member's file goes, and
    // the list behind it, and the third waits again.
    await svc.vault.db.delete('outbox');
    await svc.retryGroupFanout();
    await waitUntil(
        () async =>
            (await queuedIn(svc, gid)).length == 1 &&
            (await chunkRows(svc)).length == 1,
        what: 'the next member staged');
    final second = (await chunkRows(svc)).keys.single;
    expect(rest, contains(second));
    expect(await outboxTo(svc, listMid), contains(second),
        reason: 'its list went once its file had');
    expect(await queuedIn(svc, gid), {
      for (final r in rest.where((r) => r != second))
        r: [(fileMid, 'gfile'), (listMid, 'ginvite')]
    });

    await svc.vault.db.delete('outbox');
    await svc.retryGroupFanout();
    await svc.waitForGroupFanout(gid);
    expect((await chunkRows(svc)).values.toList(), [3],
        reason: 'and the last member\'s');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test(
      '8. members\' copies are staged under the bound, a member at a time; '
      'my own devices\' copies are queued at once, within the budget',
      () async {
    final svc = await makeClient('mirror', offline: true);
    final members = [for (var i = 0; i < 2; i++) await addPhantom(svc, 'm$i')];
    final gid = await svc.createGroup('Two', members);
    await svc.waitForGroupFanout(gid);
    final mine = <String>[];
    for (final name in ['laptop', 'tablet', 'desktop']) {
      final account = await svc.accountIdentity();
      final dev = await ZIdentity.generate();
      final cert = await account.signDeviceCert(
          deviceEdPub: dev.edPub, deviceXPub: dev.xPub, deviceId: name);
      await svc.addMyDevice(cert);
      mine.add(await cert.routingId());
    }
    await svc.vault.db.delete('outbox');
    svc.groupStagingBound = 2 * full;
    // Three envelopes of a chunk's length already queued to a mailbox that
    // has taken none of them yet: the outbox is past the bound before the
    // file is sent.
    final stuck = b64url(randomBytes(32));
    for (var i = 0; i < 3; i++) {
      await svc.vault.db.insert('outbox', {
        'id': newMessageId(),
        'rid': stuck,
        'payload': 'zs1.${'A' * (full - 4)}',
        'created_ms': DateTime.now().millisecondsSinceEpoch,
      });
    }
    Future<int> rowsTo(Iterable<String> rids) async {
      var n = 0;
      for (final r in rids) {
        n += (await chunkRows(svc))[r] ?? 0;
      }
      return n;
    }

    final file = Uint8List(3 * defaultChunkSize);
    final cost = svc.groupFileCost(gid, file.length);
    expect(cost.recipients, members.length + mine.length);
    expect(cost.refused, isFalse, reason: 'within the budget');
    await svc.sendGroupFile(gid, 'f.bin', file, 'application/octet-stream');
    await waitUntil(() async => await rowsTo(mine) == 3 * mine.length,
        what: 'every chunk queued to each of my three devices, at once');
    await svc.drainGroupFanoutForTest();
    expect(await rowsTo(members), 0,
        reason: 'the outbox is past the bound: the members\' file waits');
    expect(await rowsTo(mine), 3 * mine.length,
        reason: 'my own devices\' copies are not staged: all of them at once');

    // The relay takes the first rows: one member is staged, and then the
    // other — members' rows never more than the bound and one member's file.
    await svc.vault.db.delete('outbox');
    await svc.retryGroupFanout();
    await waitUntil(() async => await rowsTo(members) == 3,
        what: 'one member staged');
    expect((await svc.vault.db
            .query('group_fanout', where: 'gid = ?', whereArgs: [gid]))
        .length, 1, reason: 'and the other\'s file waits for it');
    expect(await rowsTo(members) * full,
        lessThanOrEqualTo(svc.groupStagingBound + 3 * full));
    await svc.vault.db.delete('outbox');
    await svc.retryGroupFanout();
    await svc.waitForGroupFanout(gid);
    expect(await rowsTo(members), 3, reason: 'then the other member');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test(
      '9. on a SQLite without octet_length the vault falls back to length, '
      'and the bound still holds', () async {
    // Opened as on a SQLite without `octet_length`: the vault looks for a
    // function no SQLite has, and the name stays so for the whole test.
    Vault.debugOctetLengthName = 'octet_length_absent';
    addTearDown(() => Vault.debugOctetLengthName = 'octet_length');
    final svc = await makeClient('nooctet', offline: true);
    expect(svc.vault.outboxLengthFunction, 'length',
        reason: 'looked for once at open, absent, and fallen back from');
    final (rids, gid, other) = await twoGroups(svc);
    svc.groupStagingBound = 2 * full;
    await svc.sendGroupFile(gid, 'big.bin', Uint8List(3 * defaultChunkSize),
        'application/octet-stream');
    await svc.sendGroupText(other, 'in the other group');
    final otherMid = svc.messagesByChat[other]!
        .singleWhere((m) => m.body == 'in the other group')
        .mid;
    await waitUntil(
        () async => (await outboxTo(svc, otherMid)).length == rids.length,
        what: 'the drain has been over every row');
    expect((await chunkRows(svc)).values.toList(), [3],
        reason: 'measured by length: one member staged, then the bound');
    expect((await queuedIn(svc, gid)).length, 2,
        reason: 'the other two wait');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test(
      '10. a measure that fails stages nothing: the file waits, a change to '
      'who is in the group waits behind it, the text goes', () async {
    final svc = await makeClient('nomeasure', offline: true);
    final (rids, gid, other) = await twoGroups(svc);
    svc.debugFailOutboxMeasure = true;
    await svc.sendGroupFile(gid, 'big.bin', Uint8List(3 * defaultChunkSize),
        'application/octet-stream');
    await svc.sendGroupText(gid, 'after the file');
    final fileMid =
        svc.messagesByChat[gid]!.singleWhere((m) => m.kind == 'file').mid;
    final textMid = svc.messagesByChat[gid]!
        .singleWhere((m) => m.body == 'after the file')
        .mid;
    await waitUntil(
        () async => (await outboxTo(svc, textMid)).length == rids.length,
        what: 'the text after the file went to all three');
    // A list, removing one of them, after it.
    await svc.removeGroupMember(gid, rids.first);
    await svc.sendGroupText(other, 'in the other group');
    final otherMid = svc.messagesByChat[other]!
        .singleWhere((m) => m.body == 'in the other group')
        .mid;
    await waitUntil(
        () async => (await outboxTo(svc, otherMid)).length == rids.length,
        what: 'the drain has been over every row');
    expect(await chunkRows(svc), isEmpty, reason: 'nothing staged unmeasured');
    final queued = await queuedIn(svc, gid);
    expect(queued.keys.toSet(), rids.toSet());
    for (final rows in queued.values) {
      expect(rows.map((r) => r.$2), ['gfile', 'ginvite'],
          reason: 'each member\'s file waits, and the list behind it');
      expect(rows.first.$1, fileMid);
    }

    // The next drain that can measure stages them.
    svc.debugFailOutboxMeasure = false;
    await svc.retryGroupFanout();
    await svc.waitForGroupFanout(gid);
    expect((await chunkRows(svc)).values.toList(), [3, 3, 3]);
  }, timeout: const Timeout(Duration(minutes: 3)));
}
