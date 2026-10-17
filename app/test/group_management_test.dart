// 23.1 — renaming a group. Three REAL ChatService instances over the REAL
// Node relay, as group_test.dart runs them. The name already travels in every
// invite, so a rename is nothing new on the wire: the admin bumps the
// membership version and re-invites, and members adopt the name from the
// newer invite. What is new is that the change is SAID — as a rename, not as
// "membership updated" — and that only the admin can make it.
//
// Criteria, each a test below:
//   1. the admin's rename reaches every member: each adopts the name, the
//      admin sees "you renamed", each member sees who renamed it and to what,
//      nobody sees a membership banner, and the member set is untouched;
//   2. a member who is not the admin cannot rename: locally a no-op (name and
//      version unchanged) and nothing reaches the others;
//   3. a change says what it is: an add produces a membership banner and no
//      rename banner; a rename produces a rename banner and no membership
//      banner — each on its own line;
//   4. ADR 0036, the cap: an admin of a group of 128 accounts, the admin's
//      own included, who adds one more issues nothing — no `group_fanout`
//      row, no list on any member, the would-be member included, and the
//      group as it was on every device — and is told why; a new group of
//      129 is not made, and nothing is written; and the list of 128, as it
//      travels, is in the 65 536-byte bucket and within what the issuer
//      measured before it went;
//   5. no list a frame cannot carry: one past the 262 144-byte bucket as it
//      travels — a group of three renamed to a name that long, a new group
//      given one — is refused with a notice, nothing is queued, and the
//      group is unchanged on every device, the admin's record byte for
//      byte;
//   6. a list of 200 from a build without the cap (the seam) is taken, the
//      current device holds the group as over the limit, and can remove a
//      member and rename it, both sent at that size, but not add;
//   7. the group's screen says so: a group of 128 is full and one of 129
//      over the limit, neither offers an add or a link, and the add-members
//      picker counts what room is left and stops there.
//
// 4–7 fill groups with members who exist, cryptographically, and are never
// started — real identities with real bundles, as fanout_bench_test.dart's.
// Each is added without a contact request, by an Alice whose routing id
// sorts after theirs, so she is not the side that opens a session (§5) and
// adding one sends it nothing; their copies of every list are held in the
// issuer's fan-out queue and let go (in 7 the queue just waits), so the
// relay is not handed hundreds of envelopes nobody will read — it rations
// first contacts, and that is not what these test. What the cap and the
// frame rule decide is decided before anything is queued, and the real
// members' copies go through the relay as any list does.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/system_messages.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/l10n/app_localizations.dart';
import 'package:zapp/l10n/app_localizations_en.dart';
import 'package:zapp/ui/group_screens.dart';
import 'package:zapp/ui/theme.dart';
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

  Future<ChatService> makeClient(String name, {ZIdentity? id}) async {
    final dir = await Directory.systemTemp.createTemp('z_grpm_$name');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    final identity = id ?? await ZIdentity.generate();
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
      {Duration timeout = const Duration(seconds: 30), String? what}) async {
    final deadline = DateTime.now().add(timeout);
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: ${what ?? ''}');
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
  }

  /// The system banners in [gid]'s thread, as (kind, params).
  List<Map<String, Object?>> banners(ChatService svc, String gid) => [
        for (final m in svc.messagesByChat[gid] ?? const [])
          if (m.kind == 'system')
            (jsonDecode(m.body) as Map).cast<String, Object?>()
      ];

  int countKind(ChatService svc, String gid, String kind) =>
      banners(svc, gid).where((b) => b['k'] == kind).length;

  /// An identity whose routing id sorts after all but a few: a device opens
  /// sessions (§5) only towards higher ids, so one holding this sends a
  /// member it adds and never starts nothing at all.
  Future<ZIdentity> highId() async {
    while (true) {
      final id = await ZIdentity.generate();
      if ((await id.routingId()).compareTo('y') > 0) return id;
    }
  }

  /// [n] members who are never started, added to [svc] without a contact
  /// request: their routing ids.
  Future<Set<String>> phantomsOf(ChatService svc, int n) async {
    final out = <String>{};
    for (var i = 0; i < n; i++) {
      final id = await ZIdentity.generate();
      final code = (await id.bundle(displayName: 'p$i')).encode();
      out.add((await svc.addContactFromCode(code, requested: false)).rid);
    }
    return out;
  }

  /// [svc]'s copies of its lists for [rids] stay in its fan-out queue.
  void holdFor(ChatService svc, Set<String> rids) {
    svc.debugHoldGroupFanout = (rid, _) => rids.contains(rid);
  }

  /// [svc]'s fan-out rows, for whom.
  Future<List<String>> fanoutRids(ChatService svc) async => [
        for (final r in await svc.vault.db.query('group_fanout'))
          r['rid'] as String
      ];

  /// Let go of what [svc] holds for [rids], once its other copies have left
  /// the queue — what sending them would have done.
  Future<void> dropHeld(ChatService svc, Set<String> rids) async {
    final deadline = DateTime.now().add(const Duration(seconds: 60));
    while ((await fanoutRids(svc)).any((r) => !rids.contains(r))) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('the real members\' copies never went out');
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
    final list = rids.toList();
    await svc.vault.db.delete('group_fanout',
        where: 'rid IN (${List.filled(list.length, '?').join(',')})',
        whereArgs: list);
  }

  late ChatService alice, bob, carol;
  late String gid;

  setUp(() async {
    alice = await makeClient('alice', id: await highId());
    bob = await makeClient('bob');
    carol = await makeClient('carol');
    await waitUntil(
        () =>
            alice.transport.isConnected &&
            bob.transport.isConnected &&
            carol.transport.isConnected,
        what: 'clients connect');
    await alice.addContactFromCode(await bob.myContactCode());
    await bob.addContactFromCode(await alice.myContactCode());
    await alice.addContactFromCode(await carol.myContactCode());
    await carol.addContactFromCode(await alice.myContactCode());
    await Future<void>.delayed(const Duration(seconds: 1)); // hellos settle
    gid = await alice.createGroup('Trio', [bob.myRid, carol.myRid]);
    await waitUntil(
        () => bob.groups.containsKey(gid) && carol.groups.containsKey(gid),
        what: 'invites arrive');
  });

  test('1. the admin renames; everyone adopts it and says so', () async {
    final membersBefore = {
      for (final s in [alice, bob, carol]) s.myRid: s.groups[gid]!.memberRids.toSet()
    };
    final verBefore = alice.groups[gid]!.ver;

    await alice.renameGroup(gid, '  Trio, renamed  ');

    expect(alice.groups[gid]!.name, 'Trio, renamed', reason: 'trimmed');
    expect(alice.groups[gid]!.ver, verBefore + 1);
    await waitUntil(
        () =>
            bob.groups[gid]!.name == 'Trio, renamed' &&
            carol.groups[gid]!.name == 'Trio, renamed',
        what: 'members adopt the name');

    expect(countKind(alice, gid, SystemKind.renamedYou), 1);
    expect(countKind(alice, gid, SystemKind.membershipUpdated), 0,
        reason: 'a rename is not a membership change');
    for (final s in [bob, carol]) {
      await waitUntil(() => countKind(s, gid, SystemKind.renamedBy) == 1,
          what: 'the rename banner');
      final b = banners(s, gid).firstWhere((b) => b['k'] == SystemKind.renamedBy);
      expect(b['name'], 'Trio, renamed');
      expect(b['by'], 'alice', reason: 'who renamed it');
      expect(countKind(s, gid, SystemKind.membershipUpdated), 0,
          reason: 'a pure rename shows no membership banner');
      expect(s.groups[gid]!.memberRids, membersBefore[s.myRid],
          reason: 'the member set is untouched by a rename');
    }
    expect(alice.groups[gid]!.memberRids, membersBefore[alice.myRid]);
  });

  test('2. a member who is not the admin cannot rename', () async {
    final verBefore = bob.groups[gid]!.ver;
    await bob.renameGroup(gid, 'Bob was here');
    expect(bob.groups[gid]!.name, 'Trio', reason: 'a local no-op');
    expect(bob.groups[gid]!.ver, verBefore, reason: 'no version bump');
    expect(countKind(bob, gid, SystemKind.renamedYou), 0);
    // Nothing reached the others: give the relay more than enough time.
    await Future<void>.delayed(const Duration(seconds: 2));
    expect(alice.groups[gid]!.name, 'Trio');
    expect(carol.groups[gid]!.name, 'Trio');
    expect(countKind(alice, gid, SystemKind.renamedBy), 0);
    expect(countKind(carol, gid, SystemKind.renamedBy), 0);
  });

  test('3. an add says "membership", a rename says "renamed" — never mixed',
      () async {
    // An add: the members see a membership banner and no rename banner.
    final dave = await makeClient('dave');
    await waitUntil(() => dave.transport.isConnected, what: 'dave connects');
    await alice.addContactFromCode(await dave.myContactCode());
    await dave.addContactFromCode(await alice.myContactCode());
    await Future<void>.delayed(const Duration(seconds: 1));
    await alice.addGroupMembers(gid, [dave.myRid]);
    await waitUntil(
        () =>
            bob.groups[gid]!.memberRids.contains(dave.myRid) &&
            carol.groups[gid]!.memberRids.contains(dave.myRid) &&
            dave.groups.containsKey(gid),
        what: 'the add lands');
    for (final s in [bob, carol]) {
      await waitUntil(
          () => countKind(s, gid, SystemKind.membershipUpdated) == 1,
          what: 'membership banner');
      expect(countKind(s, gid, SystemKind.renamedBy), 0,
          reason: 'the name did not change, so no rename banner');
    }
    // Then a rename: a rename banner and no NEW membership banner.
    await alice.renameGroup(gid, 'Quartet');
    for (final s in [bob, carol, dave]) {
      await waitUntil(() => s.groups[gid]!.name == 'Quartet',
          what: 'rename lands');
      await waitUntil(() => countKind(s, gid, SystemKind.renamedBy) == 1,
          what: 'rename banner');
    }
    expect(countKind(bob, gid, SystemKind.membershipUpdated), 1,
        reason: 'still exactly the one from the add');
    expect(countKind(carol, gid, SystemKind.membershipUpdated), 1);
  });

  /// [svc]'s record of [g], as it would be saved.
  String record(ChatService svc, String g) =>
      jsonEncode(svc.groups[g]!.toJson());

  /// What [env], a sealed envelope from [from] to [to], weighs: its
  /// characters at the relay, the bucket its padding chose, and the sealed
  /// plaintext with its four-byte length — the figure the bucket is chosen
  /// by, and the one [ChatService.debugListSealedBytes] bounds.
  Future<({int chars, int bucket, int need})> weigh(
      String env, ChatService to) async {
    expect(SealedEnvelope.looksSealed(env), isTrue);
    final bucket = unb64url(env.substring('zs1.'.length)).length - 32 - 12 - 16;
    final opened = (await SealedEnvelope.open(
        myXSeed: to.identity.xSeed, myXPub: to.identity.xPub, blob: env))!;
    final need = utf8
            .encode(jsonEncode({'f': opened.fromRid, 'p': opened.payload}))
            .length +
        4;
    return (chars: env.length, bucket: bucket, need: need);
  }

  test('4. an admin of a 128-member group who adds one more issues nothing, '
      'and is told why', () async {
    final dave = await makeClient('dave');
    await waitUntil(() => dave.transport.isConnected, what: 'dave connects');
    await alice.addContactFromCode(await dave.myContactCode());
    await dave.addContactFromCode(await alice.myContactCode());
    final phantoms = await phantomsOf(alice, 125);
    holdFor(alice, phantoms);

    // The Trio and 125 more: 128 accounts, Alice's own among them. Her link
    // is down while she issues it, so the copy for Bob can be weighed in her
    // outbox exactly as the relay will receive it.
    await alice.transport.stop();
    expect(await alice.addGroupMembers(gid, phantoms.toList()), isNull,
        reason: '128 is within the cap');
    expect(alice.groupRoom(gid), 0);
    final listMid = (await alice.vault.db.query('group_fanout',
            columns: ['mid'], distinct: true))
        .single['mid'] as String;
    var bobs = <Map<String, Object?>>[];
    final deadline = DateTime.now().add(const Duration(seconds: 60));
    while (bobs.isEmpty) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException("Bob's copy never reached Alice's outbox");
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
      bobs = await alice.vault.db.query('outbox',
          where: 'rid = ? AND mid = ?', whereArgs: [bob.myRid, listMid]);
    }
    final w = await weigh(bobs.single['payload'] as String, bob);
    final measured = alice.debugListSealedBytes(gid);
    // ignore: avoid_print
    print('a list of 128 as it travels: ${w.chars} characters, the '
        '${w.bucket}-byte bucket, ${w.need} bytes of sealed plaintext; '
        'measured before it went: $measured');
    expect(w.bucket, 65536, reason: 'the cap keeps a list in the 65 536 bucket');
    expect(w.need, lessThanOrEqualTo(measured),
        reason: 'what travels is within what the issuer measured');
    alice.transport.start();
    await waitUntil(
        () =>
            bob.groups[gid]!.memberRids.length == 127 &&
            carol.groups[gid]!.memberRids.length == 127,
        what: 'Bob and Carol hold the list of 128',
        timeout: const Duration(seconds: 90));
    await dropHeld(alice, phantoms);
    expect(await fanoutRids(alice), isEmpty);

    final aliceBefore = record(alice, gid);
    final verBefore = alice.groups[gid]!.ver;
    expect(bob.groups[gid]!.ver, verBefore);
    expect(carol.groups[gid]!.ver, verBefore);

    // One more: refused, with nothing issued.
    final refused = await alice.addGroupMembers(gid, [dave.myRid]);
    expect(await fanoutRids(alice), isEmpty,
        reason: 'no group_fanout row: the list was never issued');
    expect(record(alice, gid), aliceBefore,
        reason: "Alice's record is as it was");
    expect(refused, GroupListRefusal.full);
    final told = banners(alice, gid)
        .where((b) => b['k'] == SystemKind.groupFull)
        .toList();
    expect(told, hasLength(1), reason: 'Alice is told why');
    expect(told.single['max'], ChatService.maxGroupMembers);
    expect(countKind(alice, gid, SystemKind.addedYou), 1,
        reason: 'the 125, and nobody since');

    // No list reached anyone. Alice's next change goes out at the next
    // version, not the one after; and a text to Dave sent once that change
    // has left her queue arrives with no group before it.
    expect(await alice.renameGroup(gid, 'Full house'), isNull,
        reason: 'a rename goes out at any size');
    await waitUntil(
        () =>
            bob.groups[gid]!.name == 'Full house' &&
            carol.groups[gid]!.name == 'Full house',
        what: 'the rename lands',
        timeout: const Duration(seconds: 90));
    for (final s in [bob, carol]) {
      expect(s.groups[gid]!.ver, verBefore + 1,
          reason: 'nothing was issued between the two');
      expect(s.groups[gid]!.memberRids, isNot(contains(dave.myRid)));
    }
    await dropHeld(alice, phantoms);
    await alice.sendText(dave.myRid, 'still just us');
    await waitUntil(
        () => (dave.messagesByChat[alice.myRid] ?? const [])
            .any((m) => m.body == 'still just us'),
        what: "Dave reads Alice's text");
    expect(dave.groups.containsKey(gid), isFalse,
        reason: 'the would-be member never got a list');

    // Nor is a new group of 129 made: nothing is written.
    final held = alice.groups.keys.toSet();
    await expectLater(
        alice.createGroup(
            'Too many', [bob.myRid, carol.myRid, dave.myRid, ...phantoms]),
        throwsA(isA<GroupListRefused>()
            .having((e) => e.reason, 'reason', GroupListRefusal.full)));
    expect(alice.groups.keys.toSet(), held);
    expect(await fanoutRids(alice), isEmpty);
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('5. a list too large for any frame is refused with a notice, and the '
      'group is unchanged on every device', () async {
    final verBefore = alice.groups[gid]!.ver;
    final aliceBefore = record(alice, gid);
    // One name past the bucket on its own: the list carries it once, and
    // two base64 layers make 150 000 characters about 267 000 bytes sealed.
    final huge = 'Trio ${'x' * 150000}';
    expect(await alice.renameGroup(gid, huge), GroupListRefusal.tooLarge);
    expect(record(alice, gid), aliceBefore,
        reason: "Alice's record, byte for byte, as before");
    expect(await fanoutRids(alice), isEmpty, reason: 'nothing was queued');
    expect(countKind(alice, gid, SystemKind.listTooLarge), 1,
        reason: 'Alice is told');
    expect(countKind(alice, gid, SystemKind.renamedYou), 0);

    // Bob and Carol never held it: Alice's next rename is the next version.
    expect(await alice.renameGroup(gid, 'Trio, still'), isNull);
    for (final s in [bob, carol]) {
      await waitUntil(
          () =>
              s.groups[gid]!.name == 'Trio, still' &&
              countKind(s, gid, SystemKind.renamedBy) > 0,
          what: 'the next rename lands, and is said');
      expect(s.groups[gid]!.ver, verBefore + 1);
      expect(
          banners(s, gid)
              .where((b) => b['k'] == SystemKind.renamedBy)
              .map((b) => b['name']),
          ['Trio, still'],
          reason: 'the name too long to carry never arrived');
    }

    // A new group is held to the same measure, and writes nothing.
    final held = alice.groups.keys.toSet();
    await expectLater(
        alice.createGroup(huge, [bob.myRid, carol.myRid]),
        throwsA(isA<GroupListRefused>()
            .having((e) => e.reason, 'reason', GroupListRefusal.tooLarge)));
    expect(alice.groups.keys.toSet(), held);
    expect(await fanoutRids(alice), isEmpty);

    // Where the frame rule first bites, by the issuer's own measure, for a
    // list of entries shaped as this group's, names of two lengths, on a
    // device with no other devices of its own.
    final data = await alice.debugInviteData(gid);
    final entry = ((data['members'] as List).last as Map).cast<String, Object?>();
    for (final nameLength in [4, 20]) {
      Map<String, Object?> listOf(int n) => {
            ...data,
            'members': [
              for (var i = 0; i < n; i++)
                {
                  ...entry,
                  'b': {
                    ...(entry['b'] as Map).cast<String, Object?>(),
                    'name': 'm$i'.padRight(nameLength, '.'),
                  },
                  'n': 'm$i'.padRight(nameLength, '.'),
                }
            ],
          };
      expect(alice.debugListSealedBytes(gid, listOf(1024)),
          greaterThan(ChatService.maxListBucket),
          reason: "§11.1's 1 024 entries are past any frame");
      var lo = 1, hi = 1024;
      while (lo < hi) {
        final mid = (lo + hi) ~/ 2;
        if (alice.debugListSealedBytes(gid, listOf(mid)) >
            ChatService.maxListBucket) {
          hi = mid;
        } else {
          lo = mid + 1;
        }
      }
      // ignore: avoid_print
      print('with $nameLength-character names, the frame rule first bites '
          'at $lo members');
      expect(lo, greaterThan(ChatService.maxGroupMembers),
          reason: 'a group at the cap is never refused for its size');
    }
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('6. a list of 200 from a build without the cap is taken; the current '
      'device can remove and rename in it, but not add', () async {
    final phantoms = await phantomsOf(alice, 198);
    holdFor(alice, phantoms);
    holdFor(bob, phantoms);
    // Carol, whom Bob holds from the Trio's list, is someone he could add.
    expect(bob.contacts.containsKey(carol.myRid), isTrue);

    // Alice's build issues lists as one from before ADR 0036 did.
    alice.debugBuildBefore0036 = true;
    final crowd =
        await alice.createGroup('Crowd', [bob.myRid, ...phantoms]);
    expect(alice.groups[crowd]!.memberRids, hasLength(199));
    await waitUntil(() => bob.groups[crowd]?.memberRids.length == 199,
        what: 'Bob takes the list of 200',
        timeout: const Duration(seconds: 120));
    expect(bob.groupRoom(crowd), ChatService.maxGroupMembers - 200,
        reason: 'held as over the limit');
    await alice.promoteAdmin(crowd, bob.myRid);
    await waitUntil(() => bob.groups[crowd]!.iAmAdmin,
        what: 'Bob is an admin', timeout: const Duration(seconds: 120));
    await dropHeld(alice, phantoms);

    // Shrinking goes out at any size: a removal, then a rename, from Bob.
    final gone = phantoms.first;
    expect(await bob.removeGroupMember(crowd, gone), isNull);
    await waitUntil(() => !alice.groups[crowd]!.memberRids.contains(gone),
        what: "Alice takes Bob's removal",
        timeout: const Duration(seconds: 120));
    expect(await bob.renameGroup(crowd, 'Crowd, smaller'), isNull);
    await waitUntil(() => alice.groups[crowd]!.name == 'Crowd, smaller',
        what: "Alice takes Bob's rename",
        timeout: const Duration(seconds: 120));
    expect(alice.groups[crowd]!.memberRids, hasLength(198),
        reason: 'the rename went out at 199 accounts');
    await dropHeld(bob, phantoms);

    // Adding does not: nothing is issued, and Bob is told.
    final bobBefore = record(bob, crowd);
    expect(await bob.addGroupMembers(crowd, [carol.myRid]),
        GroupListRefusal.full);
    expect(await fanoutRids(bob), isEmpty, reason: 'nothing was issued');
    expect(record(bob, crowd), bobBefore);
    expect(countKind(bob, crowd, SystemKind.groupFull), 1);
    await bob.sendText(carol.myRid, 'not in the crowd');
    await waitUntil(
        () => (carol.messagesByChat[bob.myRid] ?? const [])
            .any((m) => m.body == 'not in the crowd'),
        what: "Carol reads Bob's text");
    expect(carol.groups.containsKey(crowd), isFalse,
        reason: 'Carol was never sent the group');
  }, timeout: const Timeout(Duration(minutes: 6)));

  testWidgets('7. the group screen says a group is full or over the limit, '
      'and the picker stops at the room left', (t) async {
    final l = AppLocalizationsEn();
    late String full, crowd, almost;
    await t.runAsync(() async {
      // Nothing here needs to reach anyone: the fan-out waits.
      alice.debugPauseGroupFanout = true;
      final phantoms = (await phantomsOf(alice, 128)).toList();
      full = await alice.createGroup('Full', phantoms.sublist(0, 127));
      almost = await alice.createGroup('Almost', phantoms.sublist(0, 126));
      alice.debugBuildBefore0036 = true;
      crowd = await alice.createGroup('Crowd', phantoms);
      alice.debugBuildBefore0036 = false;
    });
    expect(alice.groupRoom(full), 0);
    expect(alice.groupRoom(crowd), -1);
    expect(alice.groupRoom(almost), 1);

    Widget screen(String g) => ChangeNotifierProvider<ChatService>.value(
          value: alice,
          child: MaterialApp(
            theme: ZTheme.dark(),
            localizationsDelegates: AppLocalizations.localizationsDelegates,
            supportedLocales: AppLocalizations.supportedLocales,
            home: GroupInfoScreen(gid: g),
          ),
        );
    Future<void> show(String g) async {
      await t.pumpWidget(const SizedBox.shrink());
      await t.pumpWidget(screen(g));
      await t.pump();
    }

    Future<ButtonStyleButton> buttonAt(String key) async {
      await t.scrollUntilVisible(find.byKey(ValueKey(key)), 400,
          scrollable: find.byType(Scrollable).first);
      await t.pumpAndSettle();
      return t.widget<ButtonStyleButton>(find.byKey(ValueKey(key)));
    }

    // Full: said, and nothing offers an add.
    await show(full);
    expect(find.text(l.grpFullNote(ChatService.maxGroupMembers)),
        findsOneWidget);
    expect((await buttonAt('group-add-members')).onPressed, isNull);
    expect((await buttonAt('group-invite-by-link')).onPressed, isNull);

    // Over the limit: said, with the count, and nothing offers an add.
    await show(crowd);
    expect(find.text(l.grpOverLimit(129, ChatService.maxGroupMembers)),
        findsOneWidget);
    expect((await buttonAt('group-add-members')).onPressed, isNull);
    expect((await buttonAt('group-invite-by-link')).onPressed, isNull);

    // Room for one: the picker says so, and stops at one.
    await show(almost);
    expect(find.byKey(const ValueKey('group-size-note')), findsNothing);
    expect((await buttonAt('group-add-members')).onPressed, isNotNull);
    await t.tap(find.byKey(const ValueKey('group-add-members')));
    await t.pumpAndSettle();
    final dialog = find.byType(AlertDialog);
    Finder box(String name) => find.ancestor(
        of: find.descendant(of: dialog, matching: find.text(name)),
        matching: find.byType(CheckboxListTile));
    expect(find.descendant(of: dialog, matching: find.text(l.grpRoomFor(1))),
        findsOneWidget);
    expect(t.widget<CheckboxListTile>(box('carol')).onChanged, isNotNull);
    await t.tap(box('bob'));
    await t.pumpAndSettle();
    expect(
        find.descendant(
            of: dialog,
            matching: find.text(l.grpMaxMembers(ChatService.maxGroupMembers))),
        findsOneWidget);
    expect(t.widget<CheckboxListTile>(box('bob')).onChanged, isNotNull,
        reason: 'a pick can still be taken back');
    expect(t.widget<CheckboxListTile>(box('carol')).onChanged, isNull,
        reason: 'and nobody else can be picked');
    await t.tap(find.descendant(of: dialog, matching: find.text(l.cancel)));
    await t.pumpAndSettle();
    expect(alice.groups[almost]!.memberRids, hasLength(126));
    await t.pumpWidget(const SizedBox.shrink());
  }, timeout: const Timeout(Duration(minutes: 3)));
}
