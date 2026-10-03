// 23.1b — group admin roles (ADR 0019): one account on several devices, and
// members a list never reached. REAL ChatService instances over the REAL
// Node relay, as group_roles_test.dart runs them. A copy that "never arrives"
// is one taken out of the sender's durable fan-out queue before it was sent
// — what a relay restart, a member offline past the relay's 72 hours, or an
// app killed before the queue existed did to it.
//
// Criteria, each a test below:
//   1. a co-admin's list issued from her linked laptop names her account
//      once: no device holds the laptop as a second member or a second
//      contact; and when the owner then removes her, no fan-out row is
//      queued to any device of hers — by the owner or by a member — and both
//      her devices show her removed;
//   2. the owner's linked device cannot change the roles — promote, demote,
//      transfer, remove an admin: refused there, nothing queued — while it
//      can still rename, and the owner's main device can do all of it;
//   3. one admin changing the group on two devices at one version, before
//      they have synced, with members hearing the two in opposite orders:
//      every device keeps the same one of the two — the one whose digest
//      sorts first — and the device whose change lost is told so;
//   4. two role lists from one owner at one roles version (a modified
//      client, or the owner's two devices before roles were kept to one),
//      heard in opposite orders: every member ends on the same owner and the
//      same admins;
//   5. a member that never got the owner's leave refuses the co-admin's
//      later lists only until it has asked: the owner answers with its list
//      and its leave, and the member takes every list the co-admin issued;
//   6. a member that never got the owner's promotion of a co-admin asks the
//      owner, takes the owner's list, and with it the co-admin's change;
//   7. a list held back survives a restart, and is applied when what it
//      waited for arrives;
//   8. a list recorded but not yet sent when the app stops goes out when it
//      starts again — a list is queued like a message, not sent in a loop.
@Tags(['integration'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/models.dart';
import 'package:zapp/core/system_messages.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  late Process relay;
  late int port;
  final temps = <Directory>[];
  final live = <ChatService>[];
  final dirs = <String, Directory>{};

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

  /// A client named [name]; the same name again reopens the same vault.
  Future<ChatService> start(String name, {ZIdentity? identity}) async {
    final d = dirs[name] ??
        await Directory.systemTemp.createTemp('z_sync_').then((x) {
          temps.add(x);
          return dirs[name] = x;
        });
    final vault = await Vault.open(rootOverride: d);
    final stored = await vault.kvGet('identity');
    final id = identity ??
        (stored == null
            ? await ZIdentity.generate()
            : await ZIdentity.fromJson(
                (jsonDecode(stored) as Map).cast<String, Object?>()));
    if (stored == null) await vault.kvPut('identity', jsonEncode(id.toJson()));
    final svc = await ChatService.init(
        vault: vault,
        identity: id,
        displayName: name,
        transport: Transport(identity: id, serverUrl: 'ws://127.0.0.1:$port'));
    live.add(svc);
    return svc;
  }

  /// The app killed and opened again: same vault, same identity.
  Future<ChatService> restart(ChatService s) async {
    final name = s.displayName;
    final id = s.identity;
    s.dispose();
    await s.transport.stop();
    live.remove(s);
    await s.vault.db.close();
    return start(name, identity: id);
  }

  Future<void> waitUntil(bool Function() cond,
      {Duration timeout = const Duration(seconds: 30),
      required String what}) async {
    final deadline = DateTime.now().add(timeout);
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
  }

  /// Wait for clients that just added each other to finish introducing
  /// themselves (as `settled` in replies_test.dart).
  Future<void> settled(List<ChatService> all) async {
    final deadline = DateTime.now().add(const Duration(seconds: 30));
    while (true) {
      var done = true;
      for (final s in all) {
        for (final o in all) {
          if (identical(s, o)) continue;
          final c = s.contacts[o.myRid];
          if (c == null) continue;
          if (c.pqPub == null && c.pqCandidate == null) done = false;
        }
      }
      if (done) {
        for (final s in all) {
          if ((await s.vault.db.query('outbox', limit: 1)).isNotEmpty) {
            done = false;
            break;
          }
        }
      }
      if (done && all.every((s) => !s.pqSendPending)) return;
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('the clients never settled');
      }
      await Future<void>.delayed(const Duration(milliseconds: 30));
    }
  }

  Future<void> befriend(ChatService a, ChatService b) async {
    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());
  }

  /// Wait until [s] holds version [v] or later of [rid]'s device list.
  Future<void> knowsVersion(ChatService s, String rid, int v) async {
    final deadline = DateTime.now().add(const Duration(seconds: 30));
    while (await s.heldContactListVersion(rid) < v) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('${s.displayName} never learned $rid v$v');
      }
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
  }

  /// Link a new device to [main]'s account (as history_sync_test links one):
  /// its own identity, the account's certificate for it, the main device as
  /// its one sibling — and the main device told, so its contacts learn it.
  Future<ChatService> link(ChatService main, String name,
      {ZIdentity? identity}) async {
    final devId = identity ?? await ZIdentity.generate();
    final account = await main.accountIdentity();
    final cert = await account.signDeviceCert(
        deviceEdPub: devId.edPub, deviceXPub: devId.xPub, deviceId: name);
    final d = await Directory.systemTemp.createTemp('z_sync_').then((x) {
      temps.add(x);
      return dirs[name] = x;
    });
    final vault = await Vault.open(rootOverride: d);
    await vault.kvPut('identity', jsonEncode(devId.toJson()));
    final enrolled = await AccountIdentity.fromEnrollment(
      accountEdPub: account.accountEdPub,
      deviceEdSeed: devId.edSeed,
      deviceXSeed: devId.xSeed,
      deviceId: name,
      deviceCert: cert,
    );
    await vault.kvPut('account', jsonEncode(enrolled.toJson()));
    await vault.kvPut('my_devices', jsonEncode([account.deviceCert.toJson()]),
        sensitive: false);
    final svc = await ChatService.init(
        vault: vault,
        identity: devId,
        displayName: name,
        transport:
            Transport(identity: devId, serverUrl: 'ws://127.0.0.1:$port'));
    live.add(svc);
    await waitUntil(() => svc.transport.isConnected, what: '$name connects');
    await main.addMyDevice(cert);
    return svc;
  }

  /// [owner] creates a group of [members], each a contact of the owner's;
  /// returns once every member holds it.
  Future<String> groupOf(ChatService owner, List<ChatService> members) async {
    final all = [owner, ...members];
    await waitUntil(() => all.every((s) => s.transport.isConnected),
        what: 'everyone connects');
    for (final m in members) {
      await befriend(owner, m);
    }
    await settled(all);
    final gid =
        await owner.createGroup('Crew', [for (final m in members) m.myRid]);
    await waitUntil(() => members.every((m) => m.groups.containsKey(gid)),
        what: 'every member holds the group');
    return gid;
  }

  Future<void> atVersion(
          List<ChatService> all, String gid, int ver, String what) =>
      waitUntil(() => all.every((s) => s.groups[gid]?.ver == ver),
          what: '$what (every device at version $ver)');

  List<Map<String, Object?>> banners(ChatService s, String gid) => [
        for (final m in s.messagesByChat[gid] ?? const [])
          if (m.kind == 'system' && m.body.startsWith('{'))
            (jsonDecode(m.body) as Map).cast<String, Object?>()
      ];

  int countKind(ChatService s, String gid, String kind) =>
      banners(s, gid).where((b) => b['k'] == kind).length;

  List<String> texts(ChatService s, String gid) => [
        for (final m in s.messagesByChat[gid] ?? const [])
          if (m.kind == 'gtext') m.body
      ];

  /// A member entry as a list writes one.
  Future<Map<String, Object?>> entry(ChatService s) async => {
        'b': (await s.identity.bundle(displayName: s.displayName)).toJson(),
        'n': s.displayName,
      };

  InnerMessage invite(Map<String, Object?> data) =>
      InnerMessage(kind: 'ginvite', mid: newMessageId(), ts: 1, data: data);

  /// Whom [s]'s queued fan-out for [gid] is addressed to.
  Future<Set<String>> queuedFor(ChatService s, String gid) async => {
        for (final r in await s.vault.db.query('group_fanout',
            columns: ['rid'], where: 'gid = ?', whereArgs: [gid]))
          r['rid'] as String
      };

  /// Take [s]'s queued copies for [rid] out of its fan-out queue unsent:
  /// they never arrive.
  Future<int> lose(ChatService s, String gid, String rid) =>
      s.vault.db.delete('group_fanout',
          where: 'gid = ? AND rid = ?', whereArgs: [gid, rid]);

  /// Roles as one comparable string: the owner and the admins by account,
  /// the roles version and the version.
  String rolesOf(ChatService s, String gid, Map<String, String> names) {
    final g = s.groups[gid]!;
    String n(String rid) => rid.isEmpty ? s.displayName : (names[rid] ?? rid);
    return 'owner=${n(g.ownerRid)} admins=${(g.adminRids.map(n).toList()..sort())} '
        'rv=${g.rolesVer} ver=${g.ver}';
  }

  test('1. a co-admin on her laptop is one member, and her removal is total',
      () async {
    final owen = await start('Owen1');
    final ann = await start('Ann1');
    final bob = await start('Bob1');
    await waitUntil(() => [owen, ann, bob].every((s) => s.transport.isConnected),
        what: 'everyone connects');
    await befriend(owen, ann);
    await befriend(owen, bob);
    await befriend(ann, bob);
    await settled([owen, ann, bob]);
    final laptop = await link(ann, 'AnnLaptop1');
    await knowsVersion(owen, ann.myRid, 1);
    await knowsVersion(bob, ann.myRid, 1);

    final gid = await owen.createGroup('Crew', [ann.myRid, bob.myRid]);
    await waitUntil(
        () => [ann, bob, laptop].every((s) => s.groups.containsKey(gid)),
        what: "the group reaches Ann, Bob and Ann's laptop");
    await owen.promoteAdmin(gid, ann.myRid);
    final every = [owen, ann, bob, laptop];
    await atVersion(every, gid, owen.groups[gid]!.ver, 'Ann made an admin');
    expect(laptop.groups[gid]!.iAmAdmin, isTrue);

    // Ann changes the group from her laptop.
    await laptop.renameGroup(gid, 'Renamed on the laptop');
    await waitUntil(
        () => every.every((s) => s.groups[gid]!.name == 'Renamed on the laptop'),
        what: "the laptop's rename lands everywhere");
    for (final s in [owen, bob]) {
      final g = s.groups[gid]!;
      expect(g.memberRids, isNot(contains(laptop.myRid)),
          reason: '${s.displayName}: her laptop is not a second member');
      expect(s.contacts.containsKey(laptop.myRid), isFalse,
          reason: '${s.displayName}: nor a second contact');
      expect(g.by, ann.myRid, reason: "${s.displayName}: it is Ann's list");
      expect(g.memberRids, contains(ann.myRid));
    }
    expect(ann.groups[gid]!.by, '', reason: "her phone holds it as her own");
    expect(ann.groups[gid]!.memberRids, {owen.myRid, bob.myRid});

    // The owner removes Ann. Nothing of hers is left in anyone's group.
    await owen.removeGroupMember(gid, ann.myRid);
    await waitUntil(
        () =>
            [ann, laptop].every((s) =>
                s.groups[gid]!.left &&
                countKind(s, gid, SystemKind.removedFrom) == 1) &&
            !bob.groups[gid]!.memberRids.contains(ann.myRid),
        what: 'both her devices show her removed, and Bob holds the new list');
    final hers = {ann.myRid, laptop.myRid};
    for (final s in [owen, bob]) {
      await s.waitForGroupFanout(gid);
      s.debugPauseGroupFanout = true;
      await s.sendGroupText(gid, '${s.displayName}, after Ann');
      final rows = await queuedFor(s, gid);
      expect(rows.intersection(hers), isEmpty,
          reason: '${s.displayName} queues nothing to any device of hers');
      expect(rows, isNotEmpty);
      s.debugPauseGroupFanout = false;
      await s.drainGroupFanoutForTest();
    }
    await waitUntil(
        () =>
            texts(bob, gid).contains('Owen1, after Ann') &&
            texts(owen, gid).contains('Bob1, after Ann'),
        what: 'the others hear each other');
    for (final s in [ann, laptop]) {
      expect(texts(s, gid).where((t) => t.contains('after Ann')), isEmpty,
          reason: '${s.displayName} hears neither');
    }
  });

  test("2. the owner's linked device cannot change the roles", () async {
    final owen = await start('Owen2');
    final ada = await start('Ada2');
    final bob = await start('Bob2');
    await waitUntil(() => [owen, ada, bob].every((s) => s.transport.isConnected),
        what: 'everyone connects');
    await befriend(owen, ada);
    await befriend(owen, bob);
    await settled([owen, ada, bob]);
    final laptop = await link(owen, 'OwenLaptop2');
    await knowsVersion(ada, owen.myRid, 1);
    await knowsVersion(bob, owen.myRid, 1);
    final gid = await owen.createGroup('Crew', [ada.myRid, bob.myRid]);
    final every = [owen, laptop, ada, bob];
    await waitUntil(() => every.every((s) => s.groups.containsKey(gid)),
        what: 'the group everywhere, the laptop included');
    expect(laptop.groups[gid]!.iAmOwner, isTrue, reason: 'it is his group');
    expect(laptop.canChangeGroupRolesHere, isFalse);
    expect(owen.canChangeGroupRolesHere, isTrue);
    await owen.waitForGroupFanout(gid);

    // From the laptop: refused, and nothing goes out.
    final ver = laptop.groups[gid]!.ver;
    await laptop.promoteAdmin(gid, ada.myRid);
    await laptop.transferOwnership(gid, bob.myRid);
    expect(laptop.groups[gid]!.ver, ver);
    expect(laptop.groups[gid]!.adminRids, {''});
    expect(await queuedFor(laptop, gid), isEmpty);

    // From the main device: done.
    await owen.promoteAdmin(gid, ada.myRid);
    await atVersion(every, gid, ver + 1, 'Ada made an admin');
    expect(laptop.groups[gid]!.adminRids, {'', ada.myRid});
    await laptop.demoteAdmin(gid, ada.myRid);
    await laptop.removeGroupMember(gid, ada.myRid);
    expect(laptop.groups[gid]!.ver, ver + 1,
        reason: 'taking a role away is a change to the roles too');
    expect(await queuedFor(laptop, gid), isEmpty);

    // The name is anyone's to change who may issue a list, from any device.
    await laptop.renameGroup(gid, 'From the laptop');
    await waitUntil(
        () => every.every((s) => s.groups[gid]!.name == 'From the laptop'),
        what: "the laptop's rename lands everywhere");
    for (final s in every) {
      expect(s.groups[gid]!.rolesVer, 1, reason: s.displayName);
    }
  });

  test('3. one admin on two devices at once: every device keeps the same one',
      () async {
    final owen = await start('Owen3');
    final ann = await start('Ann3');
    final cat = await start('Cat3');
    final dan = await start('Dan3');
    final gid = await groupOf(owen, [ann, cat, dan]);
    final laptop = await link(ann, 'AnnLaptop3');
    for (final s in [owen, cat, dan]) {
      await knowsVersion(s, ann.myRid, 1);
    }
    // The laptop follows the group from its next list on.
    await owen.promoteAdmin(gid, ann.myRid);
    final every = [owen, ann, laptop, cat, dan];
    final ver = owen.groups[gid]!.ver;
    await atVersion(every, gid, ver, 'Ann made an admin');

    // Before her two devices have synced, Ann renames on each — her phone's
    // list reaching Cat first, her laptop's reaching Dan first.
    final phoneGo = Completer<void>();
    final laptopGo = Completer<void>();
    ann.debugBeforeGroupMirror = () => phoneGo.future;
    laptop.debugBeforeGroupMirror = () => laptopGo.future;
    final danRid = dan.myRid, catRid = cat.myRid;
    ann.debugHoldGroupFanout = (rid, _) => rid == danRid;
    laptop.debugHoldGroupFanout = (rid, _) => rid == catRid;
    await ann.renameGroup(gid, 'Named on the phone');
    await laptop.renameGroup(gid, 'Named on the laptop');
    expect(ann.groups[gid]!.ver, ver + 1);
    expect(laptop.groups[gid]!.ver, ver + 1);
    final phoneDigest = ann.groups[gid]!.digest;
    final laptopDigest = laptop.groups[gid]!.digest;
    expect(phoneDigest, isNot(laptopDigest));
    await waitUntil(
        () =>
            cat.groups[gid]!.name == 'Named on the phone' &&
            dan.groups[gid]!.name == 'Named on the laptop',
        what: 'Cat and Dan each hold a different one');

    // Everything is let through.
    ann.debugHoldGroupFanout = null;
    laptop.debugHoldGroupFanout = null;
    ann.debugBeforeGroupMirror = null;
    laptop.debugBeforeGroupMirror = null;
    phoneGo.complete();
    laptopGo.complete();
    await ann.retryGroupFanout();
    await laptop.retryGroupFanout();
    final phoneWins = phoneDigest.compareTo(laptopDigest) < 0;
    final winner = phoneWins ? 'Named on the phone' : 'Named on the laptop';
    await waitUntil(() => every.every((s) => s.groups[gid]!.name == winner),
        what: 'every device keeps the same one: $winner');
    for (final s in every) {
      expect(s.groups[gid]!.ver, ver + 1, reason: s.displayName);
      expect(s.groups[gid]!.digest, phoneWins ? phoneDigest : laptopDigest,
          reason: s.displayName);
    }
    final loser = phoneWins ? laptop : ann;
    final kept = phoneWins ? ann : laptop;
    await waitUntil(
        () => countKind(loser, gid, SystemKind.changeOverriddenMine) == 1,
        what: 'the device whose change lost is told');
    expect(countKind(kept, gid, SystemKind.changeOverriddenMine), 0);
    for (final s in [owen, cat, dan]) {
      expect(countKind(s, gid, SystemKind.changeOverriddenBy), 0,
          reason: '${s.displayName} issued nothing');
    }
  });

  test('4. two role lists from one owner at one roles version converge',
      () async {
    final owen = await start('Owen4');
    final ada = await start('Ada4');
    final bob = await start('Bob4');
    final m1 = await start('M1x4');
    final m2 = await start('M2x4');
    final gid = await groupOf(owen, [ada, bob, m1, m2]);
    final ver = owen.groups[gid]!.ver;
    final members = [
      for (final s in [owen, ada, bob, m1, m2]) await entry(s)
    ];
    // Both open roles version 1 at the same version: one hands the group to
    // Ada, the other makes Bob an admin.
    final transfer = {
      'gid': gid,
      'name': 'Crew',
      'ver': ver + 1,
      'owner': ada.myRid,
      'admins': [ada.myRid, owen.myRid]..sort(),
      'rv': 1,
      'members': members,
    };
    final promo = {
      'gid': gid,
      'name': 'Crew',
      'ver': ver + 1,
      'owner': owen.myRid,
      'admins': [owen.myRid, bob.myRid]..sort(),
      'rv': 1,
      'members': members,
    };
    for (final s in [ada, m1]) {
      await owen.debugSendRawInner(s.myRid, invite(transfer));
    }
    for (final s in [bob, m2]) {
      await owen.debugSendRawInner(s.myRid, invite(promo));
    }
    final four = [ada, bob, m1, m2];
    await waitUntil(() => four.every((s) => s.groups[gid]!.rolesVer == 1),
        what: 'the first of each lands');
    for (final s in [ada, m1]) {
      await owen.debugSendRawInner(s.myRid, invite(promo));
    }
    for (final s in [bob, m2]) {
      await owen.debugSendRawInner(s.myRid, invite(transfer));
    }
    await waitUntil(
        () => four.every((s) => s.debugListsJudgedFrom(gid, owen.myRid) >= 3),
        what: 'the second of each is judged');
    final names = {
      for (final s in [owen, ada, bob, m1, m2]) s.myRid: s.displayName
    };
    final winner = Group.listDigest(transfer).compareTo(Group.listDigest(promo)) < 0
        ? 'transfer'
        : 'promotion';
    final expected = winner == 'transfer'
        ? 'owner=Ada4 admins=[Ada4, Owen4] rv=1 ver=${ver + 1}'
        : 'owner=Owen4 admins=[Bob4, Owen4] rv=1 ver=${ver + 1}';
    await waitUntil(
        () => four.every((s) => rolesOf(s, gid, names) == expected),
        what: 'every member ends on the $winner: $expected');
    for (final s in four) {
      expect(s.debugHeldBackLists(gid), 0, reason: s.displayName);
    }
  });

  test("5. a member that missed the owner's leave asks, and catches up",
      () async {
    final owen = await start('Owen5');
    final ada = await start('Ada5'); // co-admin, runs the group afterwards
    final ben = await start('Ben5');
    final mo = await start('Mo5'); // never gets the owner's leave
    final gid = await groupOf(owen, [ada, ben, mo]);
    final all = [owen, ada, ben, mo];
    await owen.promoteAdmin(gid, ada.myRid);
    final ver = owen.groups[gid]!.ver;
    await atVersion(all, gid, ver, 'Ada made an admin');
    await owen.waitForGroupFanout(gid);

    // Owen leaves; his leave reaches Ada and Ben, and Mo's copy is lost.
    final moRid = mo.myRid;
    owen.debugHoldGroupFanout =
        (rid, inner) => rid == moRid && inner.kind == 'gleave';
    await owen.leaveGroup(gid);
    await waitUntil(
        () => [ada, ben]
            .every((s) => !s.groups[gid]!.memberRids.contains(owen.myRid)),
        what: 'Ada and Ben hear the leave');
    expect(await lose(owen, gid, moRid), 1);
    owen.debugHoldGroupFanout = null;
    expect(mo.groups[gid]!.memberRids, contains(owen.myRid));

    // Ada runs the group from here: renames, then removes Ben.
    await ada.renameGroup(gid, 'Run by Ada');
    await waitUntil(() => ben.groups[gid]!.name == 'Run by Ada',
        what: 'Ben takes it');
    await ada.removeGroupMember(gid, ben.myRid);
    await waitUntil(() => ben.groups[gid]!.left, what: 'Ben is removed');

    // Mo could not take either while it held Owen as an admin in the group;
    // it asked, Owen answered with his list and his leave, and Mo holds
    // Ada's latest list.
    await waitUntil(
        () =>
            mo.groups[gid]!.ver == ver + 2 &&
            mo.groups[gid]!.name == 'Run by Ada',
        what: "Mo holds Ada's latest list");
    final g = mo.groups[gid]!;
    expect(g.memberRids, {ada.myRid});
    expect(g.by, ada.myRid);
    // What Mo still held is retried, and dropped, once a newer list is in.
    await waitUntil(() => mo.debugHeldBackLists(gid) == 0,
        what: 'nothing left held back');
    await mo.waitForGroupFanout(gid);
    mo.debugPauseGroupFanout = true;
    await mo.sendGroupText(gid, 'Mo, after Ben was removed');
    expect(await queuedFor(mo, gid), {ada.myRid},
        reason: 'not Ben, whom Ada removed, nor Owen, who left');
    mo.debugPauseGroupFanout = false;
    await mo.drainGroupFanoutForTest();
    await waitUntil(
        () => texts(ada, gid).contains('Mo, after Ben was removed'),
        what: 'Ada hears Mo');
  });

  test("6. a member that missed a promotion asks the owner, and catches up",
      () async {
    final owen = await start('Owen6');
    final pia = await start('Pia6'); // promoted, then renames
    final dee = await start('Dee6'); // the promotion never reaches her
    final gid = await groupOf(owen, [pia, dee]);
    final ver = owen.groups[gid]!.ver;
    await owen.waitForGroupFanout(gid);

    final deeRid = dee.myRid;
    owen.debugHoldGroupFanout = (rid, _) => rid == deeRid;
    await owen.promoteAdmin(gid, pia.myRid);
    await waitUntil(() => pia.groups[gid]!.iAmAdmin, what: 'Pia is promoted');
    expect(await lose(owen, gid, deeRid), 1);
    owen.debugHoldGroupFanout = null;

    await pia.renameGroup(gid, 'Renamed by Pia');
    expect(pia.groups[gid]!.ver, ver + 2);
    await waitUntil(
        () =>
            dee.groups[gid]!.name == 'Renamed by Pia' &&
            dee.groups[gid]!.ver == ver + 2,
        what: "Dee holds Pia's change");
    final g = dee.groups[gid]!;
    expect(g.adminRids, {owen.myRid, pia.myRid});
    expect(g.rolesVer, 1);
    await waitUntil(() => dee.debugHeldBackLists(gid) == 0,
        what: 'nothing left held back');
  });

  test('7. a list held back survives a restart', () async {
    final owen = await start('Owen7');
    final pia = await start('Pia7');
    var dee = await start('Dee7');
    final max = await start('Max7');
    final gid = await groupOf(owen, [pia, dee, max]);
    final ver = owen.groups[gid]!.ver;
    await owen.waitForGroupFanout(gid);

    // The promotion reaches Pia and waits, for Dee, in Owen's queue; Owen
    // then goes offline, so nothing he holds can reach Dee meanwhile.
    final deeRid = dee.myRid;
    owen.debugHoldGroupFanout = (rid, _) => rid == deeRid;
    await owen.promoteAdmin(gid, pia.myRid);
    await waitUntil(() => pia.groups[gid]!.iAmAdmin, what: 'Pia is promoted');
    await owen.transport.stop();
    await pia.removeGroupMember(gid, max.myRid);
    await waitUntil(() => dee.debugHeldBackLists(gid) == 1,
        what: "Dee holds Pia's removal back");
    expect(dee.groups[gid]!.memberRids, contains(max.myRid));

    // Dee's app is killed and opened again.
    dee = await restart(dee);
    expect(dee.debugHeldBackLists(gid), 1, reason: 'kept with the group');
    await waitUntil(() => dee.transport.isConnected, what: 'Dee reconnects');

    // Owen comes back, and the promotion goes out.
    owen.debugHoldGroupFanout = null;
    owen.transport.start();
    await waitUntil(() => owen.transport.isConnected, what: 'Owen is back');
    await owen.retryGroupFanout();
    await waitUntil(
        () =>
            dee.groups[gid]!.ver == ver + 2 &&
            !dee.groups[gid]!.memberRids.contains(max.myRid),
        what: "Dee applies Pia's removal of Max");
    await waitUntil(() => dee.debugHeldBackLists(gid) == 0,
        what: 'nothing left held back');
    await dee.waitForGroupFanout(gid);
    dee.debugPauseGroupFanout = true;
    await dee.sendGroupText(gid, 'Dee, after Max');
    expect(await queuedFor(dee, gid), {owen.myRid, pia.myRid});
    dee.debugPauseGroupFanout = false;
    await dee.drainGroupFanoutForTest();
  });

  test('8. a list not yet sent when the app stops goes out when it starts',
      () async {
    var owen = await start('Owen8');
    final ada = await start('Ada8');
    final ben = await start('Ben8');
    final gid = await groupOf(owen, [ada, ben]);
    await owen.waitForGroupFanout(gid);

    owen.debugPauseGroupFanout = true;
    await owen.renameGroup(gid, 'Queued, not sent');
    expect(await queuedFor(owen, gid), {ada.myRid, ben.myRid},
        reason: 'written down for every member before anything is sent');
    owen = await restart(owen);
    await waitUntil(
        () => [ada, ben]
            .every((s) => s.groups[gid]!.name == 'Queued, not sent'),
        what: 'the list goes out from the queue on the next start');
    await owen.waitForGroupFanout(gid);
  });
}
