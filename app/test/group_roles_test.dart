// 23.1b — group admin roles (ADR 0019): an owner and co-admins, carried in
// the list itself, and one order — `(rv, ver, by)` — that every device applies
// to decide which of two lists stands. REAL ChatService instances over the
// REAL Node relay, as group_test.dart runs them; where a test needs a client
// that does what this app will not, it sends the inner message itself
// (`debugSendRawInner`), which is the only way such a list can be made.
//
// Criteria, each a test below:
//   1. a co-admin's add, removal and rename reach every member, the owner
//      included, and leave one version, one member set and one set of roles
//      on every device;
//   2. a demoted admin sees itself demoted, and a list it issues afterwards
//      — re-admitting itself, whether built on the list from before the
//      demotion or on the one after — is refused by every member;
//   3. two co-admins changing the group at the same version converge on ONE
//      list on every device — the one whose digest sorts first wins — and
//      the loser is told so and can make the change again;
//   4. the owner wins a race against a co-admin whatever the routing ids
//      (both orders, constructed): the owner demoting a co-admin who is
//      changing the group at that moment;
//   5. ownership transfers, and the old owner stays an admin or stops being
//      one, as chosen;
//   6. a member removed by a co-admin before a send is never sent it — no
//      fan-out row for them, from the co-admin or from a member holding the
//      new list (the snapshot property of 15.3 and 23.2);
//   7. a pre-0019 invite (no `owner`, no `admins`) is read as it always was,
//      and a co-admin's list that changes the admin set or the owner, or
//      opens a new roles version, is refused;
//   8. roles survive a restart, and a group stored before 0019 loads with
//      its creator as owner and only admin;
//   9. a member's leave crossing a co-admin's change does not cost the
//      change: it reaches every device, and the owner's next list keeps it;
//  10. a list that arrives before the promotion it rests on is held back,
//      not dropped, and applied when the promotion lands;
//  11. `owner`, `admins` and `rv` cost a fixed amount on the wire, about one
//      member's entry with three admins, against a group with no co-admins
//      — whose list carries none of them — so a group with co-admins fits
//      the 4 096-byte bucket with at most one member fewer; every size from
//      three members to fourteen is measured and printed;
//  12. a co-admin who sends its lists to everyone but the owner, running
//      the members' version ahead of the owner's, cannot outlast a demotion:
//      the owner's change to the roles outranks any version a co-admin has
//      reached, and replaces what that co-admin sent;
//  13. a group whose roles have never changed sends, byte for byte, the
//      list a client before 0019 would — no `owner`, `admins` or `rv` — and
//      once they have changed (even back to the owner alone) every list
//      carries all three, `rv` above 0;
//  14. a list that leaves the three out is a claim — "the sender owns it,
//      alone, at roles version 0" — and a co-admin or a member making it is
//      refused at every member exactly as the same claim written out is;
//  15. a linked device whose own account is in a race picks the winner
//      every other device picks — having taken the other list first;
//  16. a demoted admin, or a plain member, whose list states the held roles
//      exactly — so only the sender's own standing can refuse it — is
//      refused by every member;
//  17. a co-admin who left, still an admin on paper, cannot put herself
//      back or change the group: refused, and not even held for later;
//  18. two admins' lists decided at the same moment (held at the decision
//      and let go together): the one that outranks stands, whichever is
//      installed last — the decision has no await in it — and it is the
//      owner's, chosen to sort after the co-admin's by digest, so that only
//      the owner's precedence can make it stand;
//  19. a held-back list overtaken while it waits — by the owner's newer
//      list, his answer to the member asking — is dropped when retried, not
//      applied over the newer one;
//  20. a list not shaped as PROTOCOL §11 says — an owner or admin that is not
//      a routing id (an empty one read as "me" on every member), a version
//      that is not a whole number, a name or member list of the wrong type,
//      more than 1 024 member entries — is judged and refused, never thrown
//      on, and the next list lands;
//  21. a sender holds one place among held-back lists: a member's four junk
//      lists cannot push an honest one out, a non-member's is not held, and
//      the same list twice is held once;
//  22. the owner is told when a co-admin's later list — a version above his,
//      built on her own earlier change — undoes his removal of a member;
//  23. a member a list removes holds that list — its version and its
//      members, one it never got the add of included;
//  24. a retry of held-back lists that the held list changes under goes
//      round again, so a list the change made acceptable is applied then;
//  25. the owner can take the role away from an admin who has left;
//  26. deleting the contact of an admin does not freeze my lists: they still
//      name the admin, and every member takes them;
//  27. a co-admin added from her laptop's code (PROTOCOL §18.7) — held as a
//      full contact, her account known, on some members, and adopted from a
//      list on others — racing another co-admin at one version: every device
//      keeps the same list, routing ids constructed so that ranking her by
//      her account where known and by her laptop where not would split it,
//      and names chosen so that it is her list that must stand;
//  28. a list's digest — and the canonical JSON it hashes — is the one the
//      protocol vectors record, computed there from §11.1's words.
@Tags(['integration'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
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
        await Directory.systemTemp.createTemp('z_roles_').then((x) {
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

  /// A device linked to [account] (as history_sync_test links one): its own
  /// identity, the account's certificate for it, and the account's main
  /// device as its one sibling. With [accountMlPub] — the account's
  /// post-quantum key, which a real link hands over — its contact code says
  /// whose device it is (PROTOCOL §18.7); without it, the code is a plain
  /// device's.
  Future<ChatService> startLinked(String name, ZIdentity devId,
      AccountIdentity account, DeviceCertificate cert, DeviceCertificate host,
      {Uint8List? accountMlPub}) async {
    final d = await Directory.systemTemp.createTemp('z_roles_').then((x) {
      temps.add(x);
      return dirs[name] = x;
    });
    final vault = await Vault.open(rootOverride: d);
    await vault.kvPut('identity', jsonEncode(devId.toJson()));
    final enrolled = await AccountIdentity.fromEnrollment(
      accountEdPub: account.accountEdPub,
      accountMlPub: accountMlPub,
      deviceEdSeed: devId.edSeed,
      deviceXSeed: devId.xSeed,
      deviceId: 'laptop',
      deviceCert: cert,
    );
    await vault.kvPut('account', jsonEncode(enrolled.toJson()));
    await vault.kvPut('my_devices', jsonEncode([host.toJson()]),
        sensitive: false);
    final svc = await ChatService.init(
        vault: vault,
        identity: devId,
        displayName: name,
        transport:
            Transport(identity: devId, serverUrl: 'ws://127.0.0.1:$port'));
    live.add(svc);
    return svc;
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
  /// themselves — the same observable `settled` in replies_test.dart waits
  /// for: each holds the other's post-quantum key, and nobody has anything
  /// left to hand over.
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

  /// Wait until every one of [all] holds version [ver] of [gid].
  Future<void> atVersion(
          List<ChatService> all, String gid, int ver, String what) =>
      waitUntil(() => all.every((s) => s.groups[gid]?.ver == ver),
          what: '$what (every device at version $ver)');

  /// The owner makes [who] an admin; returns once [all] hold that list.
  Future<void> promote(ChatService owner, String gid, ChatService who,
      List<ChatService> all) async {
    await owner.promoteAdmin(gid, who.myRid);
    await atVersion(all, gid, owner.groups[gid]!.ver,
        '${who.displayName} made an admin');
  }

  /// How [s] holds [p]: `''` for itself, else p's routing id (every client
  /// here is one device, so the id it is held under is its own).
  String ridOn(ChatService s, ChatService p) =>
      identical(s, p) ? '' : p.myRid;

  /// Everyone in [gid] as [s] sees it, [s] included.
  Set<String> everyone(ChatService s, String gid) =>
      {s.myRid, ...s.groups[gid]!.memberRids};

  List<Map<String, Object?>> banners(ChatService s, String gid) => [
        for (final m in s.messagesByChat[gid] ?? const [])
          if (m.kind == 'system' && m.body.startsWith('{'))
            (jsonDecode(m.body) as Map).cast<String, Object?>()
      ];

  int countKind(ChatService s, String gid, String kind) =>
      banners(s, gid).where((b) => b['k'] == kind).length;

  Map<String, Object?> banner(ChatService s, String gid, String kind) =>
      banners(s, gid).lastWhere((b) => b['k'] == kind);

  List<String> texts(ChatService s, String gid) => [
        for (final m in s.messagesByChat[gid] ?? const [])
          if (m.kind == 'gtext') m.body
      ];

  List<String> files(ChatService s, String gid) => [
        for (final m in s.messagesByChat[gid] ?? const [])
          if (m.kind == 'file') m.body
      ];

  /// A member entry as `_inviteData` writes one.
  Future<Map<String, Object?>> entry(ChatService s) async => {
        'b': (await s.identity.bundle(displayName: s.displayName)).toJson(),
        'n': s.displayName,
      };

  InnerMessage invite(Map<String, Object?> data) =>
      InnerMessage(kind: 'ginvite', mid: newMessageId(), ts: 1, data: data);

  /// Every field of a held list, in a form two of them can be compared by.
  String snapshot(Group g) => jsonEncode({
        'name': g.name,
        'ver': g.ver,
        'owner': g.ownerRid,
        'admins': g.adminRids.toList()..sort(),
        'by': g.by,
        'rolesVer': g.rolesVer,
        'members': g.memberRids.toList()..sort(),
        'left': g.left,
      });

  test('1. a co-admin adds, removes and renames, and every member sees it',
      () async {
    final owen = await start('Owen1');
    final ada = await start('Ada1'); // the co-admin
    final ben = await start('Ben1');
    final cat = await start('Cat1'); // removed by Ada
    final dan = await start('Dan1'); // added by Ada: her contact, nobody else's
    final gid = await groupOf(owen, [ada, ben, cat]);
    await waitUntil(() => dan.transport.isConnected, what: 'Dan connects');
    await befriend(ada, dan);
    await settled([ada, dan]);
    await promote(owen, gid, ada, [owen, ada, ben, cat]);

    await ada.addGroupMembers(gid, [dan.myRid]);
    await waitUntil(
        () =>
            dan.groups.containsKey(gid) &&
            [owen, ben, cat]
                .every((s) => s.groups[gid]!.memberRids.contains(dan.myRid)),
        what: "Ada's add reaches everyone");
    expect(dan.groups[gid]!.ownerRid, owen.myRid,
        reason: "the newcomer learns who owns it from a co-admin's list");
    expect(dan.groups[gid]!.adminRids, {owen.myRid, ada.myRid});

    await ada.removeGroupMember(gid, cat.myRid);
    await waitUntil(
        () =>
            cat.groups[gid]!.left &&
            [owen, ben, dan]
                .every((s) => !s.groups[gid]!.memberRids.contains(cat.myRid)),
        what: "Ada's removal reaches everyone, Cat included");
    await waitUntil(() => countKind(cat, gid, SystemKind.removedFrom) == 1,
        what: 'Cat is told');

    await ada.renameGroup(gid, 'Renamed by Ada');
    final stay = [owen, ada, ben, dan];
    await waitUntil(
        () => stay.every((s) => s.groups[gid]!.name == 'Renamed by Ada'),
        what: "Ada's rename reaches everyone");
    final ver = ada.groups[gid]!.ver;
    for (final s in stay) {
      final g = s.groups[gid]!;
      expect(g.ver, ver, reason: '${s.displayName}: one version');
      expect(everyone(s, gid), {for (final p in stay) p.myRid},
          reason: '${s.displayName}: one member set');
      expect(g.ownerRid, ridOn(s, owen), reason: '${s.displayName}: owner');
      expect(g.adminRids, {ridOn(s, owen), ridOn(s, ada)},
          reason: '${s.displayName}: admins');
    }
    await waitUntil(() => countKind(owen, gid, SystemKind.renamedBy) == 1,
        what: 'the owner is told who renamed it');
    expect(banner(owen, gid, SystemKind.renamedBy)['by'], 'Ada1');
  });

  test('2. a demoted admin sees it, and its lists are refused everywhere',
      () async {
    final owen = await start('Owen2');
    final ada = await start('Ada2');
    final ben = await start('Ben2');
    final cat = await start('Cat2');
    final gid = await groupOf(owen, [ada, ben, cat]);
    final all = [owen, ada, ben, cat];
    await promote(owen, gid, ada, all);
    final rolesBefore = ada.groups[gid]!.rolesVer;
    final members = [
      await entry(ada),
      await entry(owen),
      await entry(ben),
      await entry(cat),
    ];

    await owen.demoteAdmin(gid, ada.myRid);
    final ver = owen.groups[gid]!.ver;
    await atVersion(all, gid, ver, 'the demotion');
    expect(ada.groups[gid]!.iAmAdmin, isFalse);
    await waitUntil(() => countKind(ada, gid, SystemKind.demotedMeBy) == 1,
        what: 'Ada is told');
    expect(banner(ada, gid, SystemKind.demotedMeBy)['by'], 'Owen2');
    for (final s in all) {
      expect(s.groups[gid]!.adminRids, {ridOn(s, owen)},
          reason: '${s.displayName} holds Owen as the only admin');
    }

    // Her own app will not issue one.
    await ada.renameGroup(gid, 'Ada was here');
    expect(ada.groups[gid]!.ver, ver, reason: 'a local no-op');

    // A modified one does: a newer version that renames the group and names
    // her an admin again — once built on the list from before the demotion
    // (an older roles version: dropped), once on the list after it (her
    // role gone: held back, never to be applied — only the owner could).
    Map<String, Object?> again(int rv) => {
          'gid': gid,
          'name': 'Ada was here',
          'ver': ver + 1,
          'owner': owen.myRid,
          'admins': [owen.myRid, ada.myRid],
          'rv': rv,
          'members': members,
        };
    final seen = {
      for (final s in [owen, ben, cat])
        s: s.debugListsJudgedFrom(gid, ada.myRid)
    };
    for (final s in [owen, ben, cat]) {
      await ada.debugSendRawInner(s.myRid, invite(again(rolesBefore)));
      await ada.debugSendRawInner(s.myRid, invite(again(rolesBefore + 1)));
    }
    await waitUntil(
        () => [owen, ben, cat].every((s) =>
            s.debugListsJudgedFrom(gid, ada.myRid) == seen[s]! + 2 &&
            s.debugHeldBackLists(gid) == 1),
        what: "both of Ada's lists reached every member and were judged");
    for (final s in [owen, ben, cat]) {
      final g = s.groups[gid]!;
      expect(g.name, 'Crew', reason: '${s.displayName} kept the name');
      expect(g.ver, ver, reason: '${s.displayName} kept the version');
      expect(g.adminRids, {ridOn(s, owen)},
          reason: '${s.displayName}: Ada did not re-admit herself');
    }
  });

  test('3. two co-admins racing converge on one list; the loser is told',
      () async {
    final owen = await start('Owen3');
    final ada = await start('Ada3');
    final bea = await start('Bea3');
    final cal = await start('Cal3');
    final gid = await groupOf(owen, [ada, bea, cal]);
    final all = [owen, ada, bea, cal];
    await promote(owen, gid, ada, all);
    await promote(owen, gid, bea, all);
    final ver = owen.groups[gid]!.ver;

    // Both change the group before either list has left: two lists, one
    // version. Each operation takes its version, and its list its digest,
    // before its first await.
    final fa = ada.renameGroup(gid, "Ada's name");
    final adaDigest = ada.groups[gid]!.digest;
    final fb = bea.renameGroup(gid, "Bea's name");
    final beaDigest = bea.groups[gid]!.digest;
    expect(ada.groups[gid]!.ver, ver + 1);
    expect(bea.groups[gid]!.ver, ver + 1);
    await Future.wait([fa, fb]);

    // §11.1: two co-admins' lists at one version rank by digest; the one
    // that sorts first wins.
    final adaWins = adaDigest.compareTo(beaDigest) < 0;
    final winner = adaWins ? ada : bea;
    final loser = adaWins ? bea : ada;
    final won = adaWins ? "Ada's name" : "Bea's name";
    final lost = adaWins ? "Bea's name" : "Ada's name";
    await waitUntil(() => all.every((s) => s.groups[gid]!.name == won),
        what: "every device holds the winner's list");
    for (final s in all) {
      expect(s.groups[gid]!.ver, ver + 1);
      expect(s.groups[gid]!.by, ridOn(s, winner),
          reason: "${s.displayName} holds the winner's list");
      expect(s.groups[gid]!.digest, adaWins ? adaDigest : beaDigest);
    }
    await waitUntil(
        () => countKind(loser, gid, SystemKind.changeOverriddenBy) == 1,
        what: 'the loser is told');
    expect(banner(loser, gid, SystemKind.changeOverriddenBy)['by'],
        winner.displayName);
    expect(countKind(winner, gid, SystemKind.changeOverriddenBy), 0);

    // And simply does it again, on the list it now holds.
    await loser.renameGroup(gid, lost);
    expect(loser.groups[gid]!.ver, ver + 2);
    await waitUntil(
        () => all.every(
            (s) => s.groups[gid]!.name == lost && s.groups[gid]!.ver == ver + 2),
        what: "the loser's second attempt reaches everyone");
  });

  test('4. the owner beats a co-admin in a race, whichever id sorts first',
      () async {
    final ownerId = await ZIdentity.generate();
    final ownerRid = await ownerId.routingId();
    Future<ZIdentity> idWhere(bool Function(int cmp) ok) async {
      while (true) {
        final id = await ZIdentity.generate();
        if (ok((await id.routingId()).compareTo(ownerRid))) return id;
      }
    }

    final owen = await start('Owen4', identity: ownerId);
    final low = await start('Low4', identity: await idWhere((c) => c < 0));
    final high = await start('High4', identity: await idWhere((c) => c > 0));
    final mem = await start('Mem4');
    expect(low.myRid.compareTo(owen.myRid), lessThan(0));
    expect(high.myRid.compareTo(owen.myRid), greaterThan(0));
    final gid = await groupOf(owen, [low, high, mem]);
    final all = [owen, low, high, mem];
    await promote(owen, gid, low, all);
    await promote(owen, gid, high, all);

    for (final co in [low, high]) {
      final ver = owen.groups[gid]!.ver;
      // At the same moment: the owner demotes the co-admin, and the co-admin
      // renames the group — the case ADR 0019 says must go the owner's way.
      final fo = owen.demoteAdmin(gid, co.myRid);
      final fc = co.renameGroup(gid, 'Renamed by ${co.displayName}');
      expect(owen.groups[gid]!.ver, ver + 1);
      expect(co.groups[gid]!.ver, ver + 1);
      await Future.wait([fo, fc]);
      await waitUntil(
          () => all.every((s) =>
              s.groups[gid]!.name == 'Crew' &&
              !s.groups[gid]!.adminRids.contains(ridOn(s, co))),
          what: "the owner's list everywhere (${co.displayName})");
      for (final s in all) {
        expect(s.groups[gid]!.ver, ver + 1);
        expect(s.groups[gid]!.by, ridOn(s, owen),
            reason: "${s.displayName} holds the owner's list");
      }
      expect(co.groups[gid]!.iAmAdmin, isFalse);
      await waitUntil(
          () => countKind(co, gid, SystemKind.changeOverriddenBy) == 1,
          what: '${co.displayName} is told the change did not stand');
    }
  });

  test('5. ownership transfers; the old owner is kept or demoted as chosen',
      () async {
    final owen = await start('Owen5');
    final ada = await start('Ada5');
    final ben = await start('Ben5');
    final gid = await groupOf(owen, [ada, ben]);
    final all = [owen, ada, ben];

    // Owen hands the group to Ada and stays on as an admin (the default).
    await owen.transferOwnership(gid, ada.myRid);
    var ver = owen.groups[gid]!.ver;
    await atVersion(all, gid, ver, 'the first transfer');
    for (final s in all) {
      expect(s.groups[gid]!.ownerRid, ridOn(s, ada));
      expect(s.groups[gid]!.adminRids, {ridOn(s, ada), ridOn(s, owen)});
    }
    expect(ada.groups[gid]!.iAmOwner, isTrue);
    expect(owen.groups[gid]!.iAmOwner, isFalse);
    expect(owen.groups[gid]!.iAmAdmin, isTrue);
    await waitUntil(() => countKind(ada, gid, SystemKind.ownerMeBy) == 1,
        what: 'Ada is told she owns it');
    await waitUntil(() => countKind(ben, gid, SystemKind.ownerBy) == 1,
        what: 'Ben is told who owns it');

    // Owen is a co-admin now: no more role changes, but he can still rename.
    await owen.promoteAdmin(gid, ben.myRid);
    expect(owen.groups[gid]!.ver, ver, reason: 'owner-only, refused locally');
    await owen.renameGroup(gid, "Still Owen's to rename");
    ver = owen.groups[gid]!.ver;
    await atVersion(all, gid, ver, "the old owner's rename");

    // Ada hands it to Ben and steps down in the same list.
    await ada.transferOwnership(gid, ben.myRid, keepAsAdmin: false);
    ver = ada.groups[gid]!.ver;
    await atVersion(all, gid, ver, 'the second transfer');
    for (final s in all) {
      expect(s.groups[gid]!.ownerRid, ridOn(s, ben));
      expect(s.groups[gid]!.adminRids, {ridOn(s, ben), ridOn(s, owen)},
          reason: '${s.displayName}: Ada is no longer an admin');
    }
    expect(ada.groups[gid]!.iAmAdmin, isFalse);
    await waitUntil(() => countKind(owen, gid, SystemKind.steppedDown) == 1,
        what: 'Owen is told Ada stepped down');
    await ada.renameGroup(gid, 'Ada again');
    expect(ada.groups[gid]!.ver, ver, reason: 'an ordinary member now');

    // The new owner runs the roles.
    await promote(ben, gid, ada, all);
    for (final s in all) {
      expect(s.groups[gid]!.adminRids,
          {ridOn(s, ben), ridOn(s, owen), ridOn(s, ada)});
    }
  });

  test('6. a member a co-admin removed before a send is never sent it',
      () async {
    final owen = await start('Owen6');
    final ada = await start('Ada6');
    final ben = await start('Ben6');
    final max = await start('Max6');
    final gid = await groupOf(owen, [ada, ben, max]);
    await promote(owen, gid, ada, [owen, ada, ben, max]);

    /// Who [s]'s queued fan-out for this group is addressed to — the
    /// membership snapshot taken when the message was queued.
    Future<Set<String>> queuedFor(ChatService s) async => {
          for (final r in await s.vault.db.query('group_fanout',
              columns: ['rid'], where: 'gid = ?', whereArgs: [gid]))
            r['rid'] as String
        };

    // Ada removes Max and sends straight away: a text and a file. (The list
    // removing him is itself fanned out through the queue, Max's copy
    // included; it is what comes after it that must not reach him.)
    await ada.waitForGroupFanout(gid);
    await ada.removeGroupMember(gid, max.myRid);
    await ada.waitForGroupFanout(gid);
    ada.debugPauseGroupFanout = true;
    await ada.sendGroupText(gid, 'after Max');
    await ada.sendGroupFile(gid, 'plan.pdf',
        Uint8List.fromList(List<int>.filled(3000, 7)), 'application/pdf');
    expect(await queuedFor(ada), {owen.myRid, ben.myRid},
        reason: 'the membership at queue time, and Max is not in it');
    ada.debugPauseGroupFanout = false;
    await ada.drainGroupFanoutForTest();
    await waitUntil(
        () => [owen, ben].every((s) =>
            texts(s, gid).contains('after Max') &&
            files(s, gid).contains('plan.pdf')),
        what: 'the others receive both');

    // Ben, once he holds Ada's list, does the same.
    await waitUntil(() => !ben.groups[gid]!.memberRids.contains(max.myRid),
        what: "Ben holds Ada's list");
    await ben.waitForGroupFanout(gid);
    ben.debugPauseGroupFanout = true;
    await ben.sendGroupText(gid, 'Ben, after Max');
    expect(await queuedFor(ben), {owen.myRid, ada.myRid});
    ben.debugPauseGroupFanout = false;
    await ben.drainGroupFanoutForTest();
    await waitUntil(
        () => [owen, ada].every((s) => texts(s, gid).contains('Ben, after Max')),
        what: "the others receive Ben's");
    expect(max.groups[gid]!.left, isTrue);
  });

  test('7. a pre-0019 invite reads as before; a co-admin cannot change roles',
      () async {
    // An old client's lists carry neither member: the sender owns the group
    // and is its only admin, exactly what such a list always meant.
    final old = await start('Old7');
    final mem = await start('Mem7');
    final third = await start('Third7');
    await waitUntil(
        () => [old, mem, third].every((s) => s.transport.isConnected),
        what: 'everyone connects');
    await befriend(old, mem);
    await befriend(old, third);
    await befriend(mem, third);
    await settled([old, mem, third]);
    final legacy = newGroupId();
    final legacyMembers = [
      await entry(old),
      await entry(mem),
      await entry(third),
    ];
    Future<void> oldList(ChatService from, List<ChatService> to, int ver,
        String name) async {
      final data = {
        'gid': legacy,
        'name': name,
        'ver': ver,
        'members': legacyMembers,
      };
      for (final s in to) {
        await from.debugSendRawInner(s.myRid, invite(data));
      }
    }

    await oldList(old, [mem, third], 1, 'Old style');
    await waitUntil(
        () => [mem, third].every((s) => s.groups.containsKey(legacy)),
        what: "the old client's group arrives");
    for (final s in [mem, third]) {
      final g = s.groups[legacy]!;
      expect(g.ownerRid, old.myRid, reason: 'the sender owns it');
      expect(g.adminRids, {old.myRid}, reason: 'and is its only admin');
      expect(g.by, old.myRid);
    }
    await oldList(old, [mem, third], 2, 'Old style, renamed');
    await waitUntil(
        () => [mem, third]
            .every((s) => s.groups[legacy]!.name == 'Old style, renamed'),
        what: "the old admin's next list is taken, as it always was");
    await oldList(mem, [third], 3, 'Mem took over');
    await waitUntil(() => third.debugHeldBackLists(legacy) == 1,
        what: "a non-admin's list is refused, as it always was");
    expect(third.groups[legacy]!.name, 'Old style, renamed');

    // A co-admin's list may not touch the roles.
    final owen = await start('Owen7');
    final ada = await start('Ada7');
    final ben = await start('Ben7');
    final gid = await groupOf(owen, [ada, ben]);
    final all = [owen, ada, ben];
    await promote(owen, gid, ada, all);
    final ver = owen.groups[gid]!.ver;
    final rv = owen.groups[gid]!.rolesVer;
    // Her app will not try.
    await ada.promoteAdmin(gid, ben.myRid);
    await ada.demoteAdmin(gid, owen.myRid);
    await ada.transferOwnership(gid, ada.myRid);
    expect(ada.groups[gid]!.ver, ver, reason: 'owner-only, refused locally');
    // A modified one sends four lists at newer versions: Ben promoted, the
    // owner removed from the group, Ada the owner — and one that changes
    // nothing but claims a new roles version, which only the owner may open.
    // (The owner cannot be left out of `admins`: whoever a list names as
    // owner is an admin.)
    final everybody = [await entry(ada), await entry(owen), await entry(ben)];
    final withoutOwen = [await entry(ada), await entry(ben)];
    Map<String, Object?> list(int v, String owner, List<String> admins,
            List<Map<String, Object?>> members, {int? roles}) =>
        {
          'gid': gid,
          'name': 'Crew',
          'ver': v,
          'owner': owner,
          'admins': admins,
          'rv': roles ?? rv,
          'members': members,
        };
    final forged = [
      list(ver + 1, owen.myRid, [owen.myRid, ada.myRid, ben.myRid], everybody),
      list(ver + 2, owen.myRid, [owen.myRid, ada.myRid], withoutOwen),
      list(ver + 3, ada.myRid, [owen.myRid, ada.myRid], everybody),
      list(ver + 4, owen.myRid, [owen.myRid, ada.myRid], everybody,
          roles: rv + 1),
    ];
    final seen = {
      for (final s in [owen, ben]) s: s.debugListsJudgedFrom(gid, ada.myRid)
    };
    for (final data in forged) {
      for (final s in [owen, ben]) {
        await ada.debugSendRawInner(s.myRid, invite(data));
      }
    }
    // Each is judged and refused; the newest is kept for later, one per
    // sender, which is all a sender gets.
    await waitUntil(
        () => [owen, ben].every((s) =>
            s.debugListsJudgedFrom(gid, ada.myRid) == seen[s]! + 4 &&
            s.debugHeldBackLists(gid) == 1),
        what: 'each member refuses all four');
    for (final s in [owen, ben]) {
      final g = s.groups[gid]!;
      expect(g.ver, ver, reason: '${s.displayName}: nothing applied');
      expect(g.rolesVer, rv);
      expect(g.ownerRid, ridOn(s, owen));
      expect(g.adminRids, {ridOn(s, owen), ridOn(s, ada)});
    }
    // What a co-admin may do, she still can.
    await ada.renameGroup(gid, 'Ada may rename');
    await waitUntil(
        () => all.every((s) => s.groups[gid]!.name == 'Ada may rename'),
        what: "a co-admin's rename still lands");
    for (final s in all) {
      expect(s.groups[gid]!.adminRids, {ridOn(s, owen), ridOn(s, ada)},
          reason: '${s.displayName}: and the roles are still the roles');
    }
  });

  test('8. roles survive a restart; a pre-0019 group loads as its creator\'s',
      () async {
    var owen = await start('Owen8');
    var ada = await start('Ada8');
    var ben = await start('Ben8');
    final gid = await groupOf(owen, [ada, ben]);
    await promote(owen, gid, ada, [owen, ada, ben]);
    await ada.renameGroup(gid, 'Before the restart');
    await atVersion([owen, ada, ben], gid, ada.groups[gid]!.ver, 'the rename');
    final before = {
      for (final s in [owen, ada, ben]) s.displayName: snapshot(s.groups[gid]!)
    };

    // Ben's vault also holds a group written by a build from before roles:
    // `admin` and nothing else.
    final legacy = newGroupId();
    Future<ChatService> restart(ChatService s, {String? plant}) async {
      final name = s.displayName;
      final id = s.identity;
      s.dispose();
      await s.transport.stop();
      live.remove(s);
      if (plant != null) {
        final stored = jsonDecode(await s.vault.kvGet('groups') ?? '[]') as List;
        stored.add({
          'gid': legacy,
          'name': 'From an older build',
          'admin': plant,
          'members': <String>[],
          'ver': 4,
        });
        await s.vault.kvPut('groups', jsonEncode(stored));
      }
      await s.vault.db.close();
      return start(name, identity: id);
    }

    owen = await restart(owen);
    ada = await restart(ada);
    ben = await restart(ben, plant: owen.myRid);
    for (final s in [owen, ada, ben]) {
      expect(snapshot(s.groups[gid]!), before[s.displayName],
          reason: '${s.displayName}: every field, as it was');
    }
    expect(owen.groups[gid]!.iAmOwner, isTrue);
    expect(ada.groups[gid]!.iAmAdmin, isTrue);
    expect(ben.groups[gid]!.iAmAdmin, isFalse);
    final g = ben.groups[legacy]!;
    expect(g.ownerRid, owen.myRid, reason: 'the creator owns it');
    expect(g.adminRids, {owen.myRid}, reason: 'and is its only admin');
    expect(g.by, owen.myRid, reason: 'and issued the list held');
    expect(g.rolesVer, 0, reason: 'roles nobody has changed yet');

    // The restored roles work: Ada, an admin since before, renames.
    final all = [owen, ada, ben];
    await waitUntil(() => all.every((s) => s.transport.isConnected),
        what: 'everyone reconnects');
    await ada.renameGroup(gid, 'After the restart');
    await waitUntil(
        () => all.every((s) => s.groups[gid]!.name == 'After the restart'),
        what: "a restarted co-admin's rename lands everywhere");
  });

  test('9. a leave crossing a co-admin\'s change does not cost the change',
      () async {
    final owen = await start('Owen9');
    final ada = await start('Ada9');
    final bea = await start('Bea9');
    final max = await start('Max9'); // leaves
    final nia = await start('Nia9');
    final xan = await start('Xan9'); // added by the owner afterwards
    final gid = await groupOf(owen, [ada, bea, max, nia]);
    final all = [owen, ada, bea, max, nia];
    await promote(owen, gid, ada, all);
    await promote(owen, gid, bea, all);
    await waitUntil(() => xan.transport.isConnected, what: 'Xan connects');
    await befriend(owen, xan);
    await settled([owen, xan]);
    final ver = owen.groups[gid]!.ver;

    // Bea renames, and her list is built and waiting to go out before she
    // has heard that Max is leaving.
    final built = Completer<void>();
    final go = Completer<void>();
    bea.debugBeforeSendCommit = (_) {
      if (!built.isCompleted) built.complete();
      return go.future;
    };
    final renamed = bea.renameGroup(gid, 'Renamed by Bea');
    await built.future;
    await max.leaveGroup(gid);
    await waitUntil(
        () => [owen, ada, nia]
            .every((s) => !s.groups[gid]!.memberRids.contains(max.myRid)),
        what: 'the leave reaches the owner, the other admin and a member');
    bea.debugBeforeSendCommit = null;
    go.complete();
    await renamed;

    // Her list is a version nobody else has issued, from an admin: every
    // device takes it. Before 23.1b the two admins had moved their version
    // on for the leave and refused it, while the member took it.
    await waitUntil(
        () => [owen, ada, nia]
            .every((s) => s.groups[gid]!.name == 'Renamed by Bea'),
        what: "Bea's rename reaches every device");
    // So the owner's next list is built on it, and keeps it.
    await owen.addGroupMembers(gid, [xan.myRid]);
    final stay = [owen, ada, bea, nia, xan];
    await atVersion(stay, gid, ver + 2, "the owner's next list");
    for (final s in stay) {
      expect(s.groups[gid]!.name, 'Renamed by Bea',
          reason: '${s.displayName}: the rename was not undone');
      // Whatever the list says of Max — a list issued before a leave puts
      // the leaver back, as an admin's always has (§11) — it says the same
      // thing on every device.
      expect(everyone(s, gid), everyone(owen, gid),
          reason: '${s.displayName}: one member set');
    }
  });

  test('10. a list that arrives before its promotion is applied when it lands',
      () async {
    final owen = await start('Owen10');
    final pia = await start('Pia10'); // promoted, then renames
    final dee = await start('Dee10'); // hears Pia before the promotion
    final gid = await groupOf(owen, [pia, dee]);
    final ver = owen.groups[gid]!.ver;

    // The owner's lists reach Pia at once and Dee only when let through; and
    // the owner goes offline, so nothing else of his — his answer to Dee
    // asking about the list she cannot apply included — reaches her first.
    final deeRid = dee.myRid;
    owen.debugHoldGroupFanout = (rid, _) => rid == deeRid;
    await owen.promoteAdmin(gid, pia.myRid);
    await waitUntil(() => pia.groups[gid]!.iAmAdmin, what: 'Pia is promoted');
    await owen.transport.stop();
    await pia.renameGroup(gid, 'Renamed by Pia');
    expect(pia.groups[gid]!.ver, ver + 2);

    // Dee has Pia's list and not the promotion it rests on: held back.
    await waitUntil(() => dee.debugHeldBackLists(gid) == 1,
        what: "Dee holds Pia's list back");
    expect(dee.groups[gid]!.name, 'Crew');
    expect(dee.groups[gid]!.ver, ver);

    owen.debugHoldGroupFanout = null;
    owen.transport.start();
    await waitUntil(() => owen.transport.isConnected, what: 'Owen is back');
    await owen.retryGroupFanout();
    await waitUntil(() => dee.groups[gid]!.name == 'Renamed by Pia',
        what: "Pia's list is applied once the promotion lands");
    expect(dee.groups[gid]!.ver, ver + 2);
    expect(dee.groups[gid]!.adminRids, {owen.myRid, pia.myRid});
    // Pia's own copy, still held, is dropped by the retry the new list
    // starts — a few steps after the list itself is installed.
    await waitUntil(() => dee.debugHeldBackLists(gid) == 0,
        what: 'nothing left held back');
    await atVersion([owen, pia, dee], gid, ver + 2, 'one list everywhere');
  });

  test('11. owner, admins and rv cost about one member entry on the wire',
      () async {
    final owen = await start('Owen Fairweather');
    final mia = await start('Mia Castellanos');
    await waitUntil(
        () => owen.transport.isConnected && mia.transport.isConnected,
        what: 'both connect');
    await befriend(owen, mia);
    await settled([owen, mia]);
    // A round trip each way, so the ratchet header is in its steady state:
    // the post-quantum ciphertext rides in it only until the peer has
    // answered (§17).
    await owen.sendText(mia.myRid, 'hello');
    await waitUntil(() => (mia.messagesByChat[owen.myRid] ?? []).isNotEmpty,
        what: 'Mia hears Owen');
    await mia.sendText(owen.myRid, 'hello back');
    await waitUntil(() => (owen.messagesByChat[mia.myRid] ?? []).length >= 2,
        what: 'Owen hears Mia');
    await settled([owen, mia]);

    // From here nothing leaves Owen's outbox, so every envelope for Mia can
    // be weighed exactly as the relay would receive it.
    await owen.transport.stop();

    /// The newest envelope for Mia matching [where]: the bytes its sealed
    /// plaintext needed (length prefix included) and the bucket it was
    /// padded to.
    Future<(int needed, int bucket)> weigh(
        String where, List<Object?> args) async {
      final row = (await owen.vault.db.query('outbox',
              where: 'rid = ? AND $where',
              whereArgs: [mia.myRid, ...args],
              orderBy: 'rowid DESC',
              limit: 1))
          .single;
      final env = row['payload'] as String;
      final bucket =
          unb64url(env.substring('zs1.'.length)).length - 32 - 12 - 16;
      final opened = (await SealedEnvelope.open(
          myXSeed: mia.identity.xSeed,
          myXPub: mia.identity.xPub,
          blob: env))!;
      final needed = utf8
              .encode(jsonEncode({'f': opened.fromRid, 'p': opened.payload}))
              .length +
          4;
      return (needed, bucket);
    }

    // A short text: the smallest bucket, so the header carries nothing big.
    await owen.sendText(mia.myRid, 'ok');
    final (_, textBucket) =
        await weigh('mid = ?', [owen.messagesByChat[mia.myRid]!.last.mid]);
    expect(textBucket, 1024, reason: 'the ratchet header is steady');

    Future<String> phantom(int i) async {
      final id = await ZIdentity.generate();
      await owen.addContactFromCode(
          (await id.bundle(displayName: 'Member Number $i')).encode());
      return id.routingId();
    }

    // Two groups with the same name and the same members, grown one member
    // at a time: one with three admins, one whose roles never changed — and
    // so whose lists carry none of the three, exactly as before 0019. The
    // second is renamed away and back so both stand at the same version, and
    // each size is the real list the app sent to Mia for each.
    final first = await phantom(1);
    final roles =
        await owen.createGroup('Weekend hiking club', [mia.myRid, first]);
    await owen.promoteAdmin(roles, mia.myRid);
    await owen.promoteAdmin(roles, first);
    final plain =
        await owen.createGroup('Weekend hiking club', [mia.myRid, first]);
    await owen.renameGroup(plain, 'Weekend hiking cluB');
    await owen.renameGroup(plain, 'Weekend hiking club');
    expect(owen.groups[roles]!.adminRids.length, 3);
    expect(owen.groups[plain]!.adminRids.length, 1);
    final rows = <(int, int, int, int, int)>[];
    for (var n = 3; n <= 14; n++) {
      if (n > 3) {
        final rid = await phantom(n);
        await owen.addGroupMembers(roles, [rid]);
        await owen.addGroupMembers(plain, [rid]);
      }
      expect(owen.groups[roles]!.memberRids.length + 1, n);
      expect(owen.groups[plain]!.ver, owen.groups[roles]!.ver);
      expect((await owen.debugInviteData(plain)).keys,
          ['gid', 'name', 'ver', 'members'],
          reason: 'the no-co-admin list is the list from before 0019');
      // A list goes out through the durable fan-out queue: weigh it once it
      // has reached the outbox.
      await owen.waitForGroupFanout(roles);
      await owen.waitForGroupFanout(plain);
      final (nw, bw) = await weigh('thread_rid = ?', [roles]);
      final (no, bo) = await weigh('thread_rid = ?', [plain]);
      rows.add((n, nw, bw, no, bo));
    }
    int lastFit(int Function((int, int, int, int, int)) bucketOf) =>
        rows.where((r) => bucketOf(r) == 4096).map((r) => r.$1).fold(0,
            (a, b) => b > a ? b : a);
    final fitWith = lastFit((r) => r.$3);
    final fitWithout = lastFit((r) => r.$5);
    final costs = {for (final r in rows) r.$2 - r.$4};
    debugPrint([
      'ginvite — members: needed with three admins (bucket) / with no '
          'co-admins, the pre-0019 bytes (bucket):',
      for (final r in rows) '  ${r.$1}: ${r.$2} (${r.$3}) / ${r.$4} (${r.$5})',
      'owner+admins+rv cost: $costs bytes on the wire; largest group in the '
          '4096 bucket: $fitWith members with co-admins, $fitWithout without',
    ].join('\n'));
    // What the three members cost is fixed — three admins throughout, so it
    // must not grow with the group; it moves only with base64's rounding —
    // and it is about one member's entry, so a group with co-admins fits the
    // 4 096-byte bucket with at most one member fewer.
    final perMember = (rows.last.$4 - rows.first.$4) / (rows.length - 1);
    final most = costs.reduce((a, b) => a > b ? a : b);
    final least = costs.reduce((a, b) => a < b ? a : b);
    expect(most - least, lessThanOrEqualTo(16),
        reason: 'the cost does not depend on how many members there are');
    expect(most, lessThan(perMember * 1.1),
        reason: 'about one member entry ($perMember bytes), not more');
    expect(fitWith, greaterThanOrEqualTo(fitWithout - 1));
    expect(fitWithout, greaterThan(3), reason: 'the table is not empty');
  });

  test('12. a co-admin running ahead of the owner cannot outlast a demotion',
      () async {
    final owen = await start('Owen12');
    final cy = await start('Cy12');
    final mo = await start('Mo12');
    final nell = await start('Nell12');
    final gid = await groupOf(owen, [cy, mo, nell]);
    final all = [owen, cy, mo, nell];
    await promote(owen, gid, cy, all);
    final ver = owen.groups[gid]!.ver;
    final rv = owen.groups[gid]!.rolesVer;
    final members = [
      await entry(cy),
      await entry(owen),
      await entry(mo),
      await entry(nell),
    ];
    Map<String, Object?> cys(int v, int roles) => {
          'gid': gid,
          'name': 'Cy runs it now',
          'ver': v,
          'owner': owen.myRid,
          'admins': [owen.myRid, cy.myRid],
          'rv': roles,
          'members': members,
        };

    // A modified client: three lists in a row, to everyone but the owner.
    // Each is a co-admin's ordinary list — the roles kept — so every member
    // takes it; the owner, never sent them, stays three versions behind.
    for (var i = 1; i <= 3; i++) {
      for (final s in [mo, nell]) {
        await cy.debugSendRawInner(s.myRid, invite(cys(ver + i, rv)));
      }
    }
    await atVersion([mo, nell], gid, ver + 3, "Cy's lists, kept from Owen");
    expect(owen.groups[gid]!.ver, ver);
    expect(mo.groups[gid]!.name, 'Cy runs it now');

    // The owner demotes Cy: a membership version behind what the members
    // hold, and a roles version ahead — which is what they rank first.
    await owen.demoteAdmin(gid, cy.myRid);
    expect(owen.groups[gid]!.ver, ver + 1);
    await waitUntil(
        () => [mo, nell, cy].every((s) => s.groups[gid]!.rolesVer == rv + 1),
        what: 'the demotion lands everywhere');
    for (final s in [mo, nell, cy]) {
      final g = s.groups[gid]!;
      expect(g.adminRids, {ridOn(s, owen)},
          reason: '${s.displayName}: Cy is no longer an admin');
      expect(g.name, 'Crew',
          reason: "${s.displayName}: the owner's list replaced Cy's wholesale");
      expect(g.ver, ver + 1);
    }

    // Cy, knowing the new roles version, tries once more: refused everywhere.
    for (final s in [owen, mo, nell]) {
      await cy.debugSendRawInner(s.myRid, invite(cys(ver + 9, rv + 1)));
    }
    await waitUntil(
        () => [owen, mo, nell].every((s) => s.debugHeldBackLists(gid) == 1),
        what: "each member holds Cy's list back");
    for (final s in [owen, mo, nell]) {
      expect(s.groups[gid]!.name, 'Crew');
      expect(s.groups[gid]!.ver, ver + 1);
    }
  });

  test('13. a group whose roles never changed sends the pre-0019 list', () async {
    final owen = await start('Owen13');
    final ada = await start('Ada13');
    final ben = await start('Ben13');
    final gid = await groupOf(owen, [ada, ben]);
    final all = [owen, ada, ben];

    /// What a client before ADR 0019 wrote for this group, as it wrote it:
    /// gid, name, version, then every member — the sender first — and
    /// nothing else.
    Future<String> before0019() async {
      final g = owen.groups[gid]!;
      return jsonEncode({
        'gid': gid,
        'name': g.name,
        'ver': g.ver,
        'members': [
          {
            'b': (await owen.identity.bundle(displayName: owen.displayName))
                .toJson(),
            'n': owen.displayName,
          },
          for (final rid in g.memberRids)
            if (owen.contacts[rid] != null)
              {
                'b': owen.contacts[rid]!.bundle.toJson(),
                'n': owen.contacts[rid]!.name,
              }
        ],
      });
    }

    expect(jsonEncode(await owen.debugInviteData(gid)), await before0019(),
        reason: 'a new group: byte for byte the list from before 0019');
    for (final s in [ada, ben]) {
      final g = s.groups[gid]!;
      expect(g.ownerRid, owen.myRid, reason: '${s.displayName}: read as ever');
      expect(g.adminRids, {owen.myRid});
      expect(g.rolesVer, 0);
    }
    await owen.renameGroup(gid, 'Crew, renamed');
    await atVersion(all, gid, owen.groups[gid]!.ver, 'the rename');
    expect(jsonEncode(await owen.debugInviteData(gid)), await before0019(),
        reason: 'a rename changes no roles, so it says nothing of them');

    // Once the roles have changed they are always written — even with the
    // admin set back to the owner alone, because leaving them out would now
    // read as roles version 0, older than what every member holds.
    await promote(owen, gid, ada, all);
    await owen.demoteAdmin(gid, ada.myRid);
    await atVersion(all, gid, owen.groups[gid]!.ver, 'promoted, then demoted');
    await owen.renameGroup(gid, 'Crew, after the roles');
    await atVersion(all, gid, owen.groups[gid]!.ver, 'a later rename');
    final data = await owen.debugInviteData(gid);
    expect(data['owner'], owen.myRid);
    expect(data['admins'], [owen.myRid]);
    expect(data['rv'], 2);
    for (final s in all) {
      expect(s.groups[gid]!.rolesVer, 2, reason: s.displayName);
      expect(s.groups[gid]!.name, 'Crew, after the roles', reason: s.displayName);
    }
  });

  test('14. leaving the roles out is a claim, refused like the claim written',
      () async {
    final owen = await start('Owen14');
    final ada = await start('Ada14'); // a co-admin
    final ben = await start('Ben14');
    final cat = await start('Cat14');
    final gid = await groupOf(owen, [ada, ben, cat]);
    final all = [owen, ada, ben, cat];
    await promote(owen, gid, ada, all);
    final ver = owen.groups[gid]!.ver;
    final rv = owen.groups[gid]!.rolesVer;
    expect(rv, greaterThan(0));

    // Ada's app writes all three: she is not the owner.
    final honest = await ada.debugInviteData(gid);
    expect(honest.keys, containsAll(['owner', 'admins', 'rv']));
    // A modified one leaves them out — which every member reads as "Ada owns
    // it and is its only admin, at roles version 0" — and, beside it, sends
    // that claim written out.
    final omitted = Map.of(honest)
      ..remove('owner')
      ..remove('admins')
      ..remove('rv')
      ..['ver'] = ver + 1
      ..['name'] = 'Ada left them out';
    final written = {
      ...omitted,
      'ver': ver + 2,
      'name': 'Ada wrote it out',
      'owner': ada.myRid,
      'admins': [ada.myRid],
      'rv': 0,
    };
    final members = [owen, ben, cat];
    final seen = {
      for (final s in members) s: s.debugListsJudgedFrom(gid, ada.myRid)
    };
    for (final s in members) {
      await ada.debugSendRawInner(s.myRid, invite(omitted));
      await ada.debugSendRawInner(s.myRid, invite(written));
    }
    await waitUntil(
        () => members.every(
            (s) => s.debugListsJudgedFrom(gid, ada.myRid) == seen[s]! + 2),
        what: "both of Ada's lists reach every member and are judged");
    // Roles version 0 is older than the roles every member holds: both are
    // discarded — not applied, and not held back for later either.
    for (final s in members) {
      final g = s.groups[gid]!;
      expect(g.name, 'Crew', reason: '${s.displayName}: neither applied');
      expect(g.ver, ver);
      expect(g.rolesVer, rv);
      expect(g.ownerRid, ridOn(s, owen));
      expect(s.debugHeldBackLists(gid), 0,
          reason: '${s.displayName}: stale, so nothing to try again');
    }

    // In a group whose roles never changed, a member who is not the owner
    // making the same claim — by omission or in writing — is not an admin
    // of the list held: both are held back, never applied.
    final second = await owen.createGroup('Second', [ben.myRid, cat.myRid]);
    await waitUntil(
        () => ben.groups.containsKey(second) && cat.groups.containsKey(second),
        what: 'the second group arrives');
    final bens = await ben.debugInviteData(second);
    expect(bens.keys, containsAll(['owner', 'admins', 'rv']),
        reason: 'Ben is not its owner, so his app would write them');
    final ver2 = owen.groups[second]!.ver;
    final omitted2 = Map.of(bens)
      ..remove('owner')
      ..remove('admins')
      ..remove('rv')
      ..['ver'] = ver2 + 1
      ..['name'] = 'Ben left them out';
    final written2 = {
      ...omitted2,
      'ver': ver2 + 2,
      'name': 'Ben wrote it out',
      'owner': ben.myRid,
      'admins': [ben.myRid],
      'rv': 0,
    };
    final seen2 = {
      for (final s in [owen, cat]) s: s.debugListsJudgedFrom(second, ben.myRid)
    };
    for (final s in [owen, cat]) {
      await ben.debugSendRawInner(s.myRid, invite(omitted2));
      await ben.debugSendRawInner(s.myRid, invite(written2));
    }
    // Both judged and refused; one is kept for later — a sender gets one.
    await waitUntil(
        () => [owen, cat].every((s) =>
            s.debugListsJudgedFrom(second, ben.myRid) == seen2[s]! + 2 &&
            s.debugHeldBackLists(second) == 1),
        what: 'each refuses both, and holds one back');
    for (final s in [owen, cat]) {
      final g = s.groups[second]!;
      expect(g.name, 'Second', reason: '${s.displayName}: neither applied');
      expect(g.ver, ver2);
      expect(g.ownerRid, ridOn(s, owen));
      expect(g.adminRids, {ridOn(s, owen)});
    }
  });

  test('15. a linked device decides a race its account is in as every device '
      'does', () async {
    final laptopId = await ZIdentity.generate();
    final owen = await start('Owen15');
    final ann = await start('Ann15');
    final bob = await start('Bob15');
    await waitUntil(
        () => [owen, ann, bob].every((s) => s.transport.isConnected),
        what: 'everyone connects');
    await befriend(owen, ann);
    await befriend(owen, bob);
    await settled([owen, ann, bob]);

    // Ann links a laptop before the group exists, so it follows the group
    // through her main device.
    final account = await ann.accountIdentity();
    final cert = await account.signDeviceCert(
        deviceEdPub: laptopId.edPub,
        deviceXPub: laptopId.xPub,
        deviceId: 'laptop');
    final laptop =
        await startLinked('Laptop15', laptopId, account, cert, account.deviceCert);
    await waitUntil(() => laptop.transport.isConnected, what: 'laptop connects');
    await ann.addMyDevice(cert);

    final gid = await owen.createGroup('Crew', [ann.myRid, bob.myRid]);
    await waitUntil(
        () => [ann, bob, laptop].every((s) => s.groups.containsKey(gid)),
        what: 'the group reaches Ann, Bob and Ann\'s laptop');
    await owen.promoteAdmin(gid, ann.myRid);
    await owen.promoteAdmin(gid, bob.myRid);
    final ver = owen.groups[gid]!.ver;
    final every = [owen, ann, bob, laptop];
    await atVersion(every, gid, ver, 'both made admins');
    expect(laptop.groups[gid]!.iAmAdmin, isTrue,
        reason: 'Ann is an admin, on her laptop too');

    // Ann, on her main device, and Bob change the group at once. Ann's list
    // — its fan-out and its mirror to her laptop — is held until her laptop
    // has taken Bob's, through Ann's phone, which mirrors to her laptop
    // every list it receives; only then does her own list go out. So the
    // laptop has to choose between Bob's list and its own account's at one
    // version — and it must choose as every other device does, whoever
    // it is and whoever it holds the two issuers as: the list whose digest
    // sorts first.
    final go = Completer<void>();
    ann.debugHoldGroupFanout = (_, inner) => inner.kind == 'ginvite';
    ann.debugBeforeGroupMirror = () => go.future;
    await ann.renameGroup(gid, "Ann's name");
    expect(ann.groups[gid]!.ver, ver + 1);
    final annDigest = ann.groups[gid]!.digest;
    await bob.renameGroup(gid, "Bob's name");
    final bobDigest = bob.groups[gid]!.digest;
    await waitUntil(() => laptop.groups[gid]!.name == "Bob's name",
        what: "Ann's laptop takes Bob's list first");
    ann.debugHoldGroupFanout = null;
    ann.debugBeforeGroupMirror = null;
    go.complete();
    await ann.retryGroupFanout();
    final annWins = annDigest.compareTo(bobDigest) < 0;
    final won = annWins ? "Ann's name" : "Bob's name";
    await waitUntil(() => every.every((s) => s.groups[gid]!.name == won),
        what: "every device, Ann's laptop included, holds the same list: $won");
    for (final s in every) {
      expect(s.groups[gid]!.ver, ver + 1, reason: s.displayName);
      expect(s.groups[gid]!.digest, annWins ? annDigest : bobDigest,
          reason: s.displayName);
    }
    expect(laptop.groups[gid]!.by, annWins ? '' : bob.myRid,
        reason: "the laptop names the winner's issuer: '' for its own account");
    final loser = annWins ? bob : ann;
    await waitUntil(
        () => countKind(loser, gid, SystemKind.changeOverriddenBy) == 1,
        what: '${loser.displayName} is told');
  });

  /// Take [s]'s queued copies for [rid] out of its fan-out queue unsent:
  /// they never arrive.
  Future<int> lose(ChatService s, String gid, String rid) =>
      s.vault.db.delete('group_fanout',
          where: 'gid = ? AND rid = ?', whereArgs: [gid, rid]);

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

  /// Link a new device to [main]'s account, and tell [main] so its contacts
  /// learn of it. What arrives FROM such a device is handled outside the
  /// inbound transaction (its envelope is not the primary path's), which is
  /// what lets a test hold two lists at the decision at once — on the
  /// primary path the database serialises them.
  Future<ChatService> link(ChatService main, String name) async {
    final devId = await ZIdentity.generate();
    final account = await main.accountIdentity();
    final cert = await account.signDeviceCert(
        deviceEdPub: devId.edPub, deviceXPub: devId.xPub, deviceId: name);
    final svc = await startLinked(name, devId, account, cert,
        account.deviceCert);
    await waitUntil(() => svc.transport.isConnected, what: '$name connects');
    await main.addMyDevice(cert);
    return svc;
  }

  test('16. a demoted admin or a plain member stating the held roles exactly '
      'is refused', () async {
    final owen = await start('Owen16');
    final ada = await start('Ada16');
    final ben = await start('Ben16');
    final cat = await start('Cat16');
    final gid = await groupOf(owen, [ada, ben, cat]);
    final all = [owen, ada, ben, cat];
    await promote(owen, gid, ada, all);
    await owen.demoteAdmin(gid, ada.myRid);
    final ver = owen.groups[gid]!.ver;
    await atVersion(all, gid, ver, 'the demotion');
    final rv = owen.groups[gid]!.rolesVer;
    final everybody = [
      for (final s in [ada, owen, ben, cat]) await entry(s)
    ];
    final withoutCat = [
      for (final s in [ada, owen, ben]) await entry(s)
    ];
    // Lists that get the roles exactly right — the owner, the admin set, the
    // roles version every member holds — so nothing but the sender's own
    // standing can refuse them.
    Map<String, Object?> list(int v, String name, List<Object?> m) => {
          'gid': gid,
          'name': name,
          'ver': v,
          'owner': owen.myRid,
          'admins': [owen.myRid],
          'rv': rv,
          'members': m,
        };
    int from(ChatService s, ChatService who) =>
        s.debugListsJudgedFrom(gid, who.myRid);
    final seenAda = {for (final s in [owen, ben, cat]) s: from(s, ada)};
    final seenBen = {for (final s in [owen, cat]) s: from(s, ben)};
    // Ada, demoted, removes Cat; Ben, never an admin, renames.
    for (final s in [owen, ben, cat]) {
      await ada.debugSendRawInner(
          s.myRid, invite(list(ver + 1, 'Ada removed Cat', withoutCat)));
    }
    for (final s in [owen, cat]) {
      await ben.debugSendRawInner(
          s.myRid, invite(list(ver + 2, 'Ben renamed it', everybody)));
    }
    await waitUntil(
        () =>
            [owen, ben, cat].every((s) => from(s, ada) == seenAda[s]! + 1) &&
            [owen, cat].every((s) => from(s, ben) == seenBen[s]! + 1),
        what: 'every forged list judged');
    for (final s in [owen, ben, cat]) {
      final g = s.groups[gid]!;
      expect(g.ver, ver, reason: '${s.displayName}: nothing applied');
      expect(g.name, 'Crew');
      expect(g.left, isFalse);
      expect(g.memberRids.contains(cat.myRid) || identical(s, cat), isTrue);
    }
  });

  test('17. a co-admin who left cannot put herself back or change the group',
      () async {
    final owen = await start('Owen17');
    final ada = await start('Ada17');
    final ben = await start('Ben17');
    final gid = await groupOf(owen, [ada, ben]);
    final all = [owen, ada, ben];
    await promote(owen, gid, ada, all);
    await ada.leaveGroup(gid);
    await waitUntil(
        () => [owen, ben]
            .every((s) => !s.groups[gid]!.memberRids.contains(ada.myRid)),
        what: 'the leave lands');
    final ver = owen.groups[gid]!.ver;
    final rv = owen.groups[gid]!.rolesVer;
    // Still an admin on paper — only the owner takes a role away — and
    // stating the roles exactly, she puts herself back and renames.
    final data = {
      'gid': gid,
      'name': 'Ada is back',
      'ver': ver + 1,
      'owner': owen.myRid,
      'admins': [owen.myRid, ada.myRid]..sort(),
      'rv': rv,
      'members': [for (final s in [ada, owen, ben]) await entry(s)],
    };
    final seen = {
      for (final s in [owen, ben]) s: s.debugListsJudgedFrom(gid, ada.myRid)
    };
    for (final s in [owen, ben]) {
      await ada.debugSendRawInner(s.myRid, invite(data));
    }
    await waitUntil(
        () => [owen, ben].every(
            (s) => s.debugListsJudgedFrom(gid, ada.myRid) == seen[s]! + 1),
        what: 'judged');
    for (final s in [owen, ben]) {
      final g = s.groups[gid]!;
      expect(g.ver, ver, reason: '${s.displayName}: nothing applied');
      expect(g.memberRids, isNot(contains(ada.myRid)));
      expect(s.debugHeldBackLists(gid), 0,
          reason: '${s.displayName}: not even held — she is not in the group');
    }
  });

  test('18. two lists decided at the same moment: the one that outranks stands',
      () async {
    final owen = await start('Owen18');
    final ada = await start('Ada18');
    final dee = await start('Dee18');
    await waitUntil(() => [owen, ada, dee].every((s) => s.transport.isConnected),
        what: 'everyone connects');
    await befriend(owen, ada);
    await befriend(owen, dee);
    await befriend(ada, dee);
    await settled([owen, ada, dee]);
    // The owner and Ada each change the group from a laptop: lists from a
    // contact's linked device are judged outside the inbound transaction, so
    // two of them can stand at the decision together, as they can in use.
    final ol = await link(owen, 'OwenLaptop18');
    final al = await link(ada, 'AdaLaptop18');
    for (final (s, of) in [(dee, owen), (dee, ada), (owen, ada), (ada, owen)]) {
      await knowsVersion(s, of.myRid, 1);
    }
    final gid = await owen.createGroup('Crew', [ada.myRid, dee.myRid]);
    await owen.promoteAdmin(gid, ada.myRid);
    final ver = owen.groups[gid]!.ver;
    final all = [owen, ol, ada, al, dee];
    await atVersion(all, gid, ver, 'Ada made an admin');
    expect(al.groups[gid]!.iAmAdmin, isTrue);

    // Dee lines the owner's list and Ada's up just before each is judged,
    // and lets them go together, the owner's first: the decision on Ada's
    // runs while the owner's is being installed. Ada's must not replace it.
    final waiting = <String, Completer<void>>{};
    final both = Completer<void>();
    var lined = false;
    final contenders = {owen.myRid, ada.myRid};
    dee.debugBeforeGroupDecision = (g, sender) {
      if (lined || g != gid || !contenders.contains(sender)) {
        return Future<void>.value();
      }
      final c = waiting[sender] = Completer<void>();
      if (waiting.length == 2) both.complete();
      return c.future;
    };
    // The names are chosen so that the owner's list sorts AFTER Ada's by
    // digest: it can only stand by the owner's precedence (§11.1).
    final ownerBase = await ol.debugInviteData(gid);
    final adaBase = await al.debugInviteData(gid);
    String digestOf(Map<String, Object?> base, String name) =>
        Group.listDigest({...base, 'name': name, 'ver': ver + 1});
    const adaName = "Ada's name";
    final adaDigest = digestOf(adaBase, adaName);
    var ownerName = "The owner's name";
    var tries = 1;
    while (digestOf(ownerBase, ownerName).compareTo(adaDigest) < 0) {
      ownerName = "The owner's name, ${++tries}";
    }
    await ol.renameGroup(gid, ownerName);
    expect(ol.groups[gid]!.digest, digestOf(ownerBase, ownerName));
    await al.renameGroup(gid, adaName);
    expect(al.groups[gid]!.digest, adaDigest);
    await both.future;
    lined = true;
    waiting[owen.myRid]!.complete();
    waiting[ada.myRid]!.complete();
    dee.debugBeforeGroupDecision = null;
    // Each account's main device hears both laptops' lists and keeps the
    // owner's — Dee among them, whichever was installed last.
    final mains = [owen, ada, dee];
    await waitUntil(
        () =>
            dee.debugListsJudgedFrom(gid, ada.myRid) >= 1 &&
            mains.every((s) =>
                s.groups[gid]!.ver == ver + 1 &&
                s.groups[gid]!.name == ownerName),
        what: "every main device, Dee included, holds the owner's list");
    expect(dee.groups[gid]!.by, owen.myRid);
  });

  test('19. a held-back list overtaken while it waits is dropped, not applied',
      () async {
    final owen = await start('Owen19');
    final pia = await start('Pia19');
    final dee = await start('Dee19');
    final gid = await groupOf(owen, [pia, dee]);
    final ver = owen.groups[gid]!.ver;
    await owen.waitForGroupFanout(gid);
    final deeRid = dee.myRid;

    // Every list of the owner's waits, for Dee, in his queue.
    owen.debugHoldGroupFanout =
        (rid, inner) => rid == deeRid && inner.kind == 'ginvite';
    await owen.promoteAdmin(gid, pia.myRid);
    await waitUntil(() => pia.groups[gid]!.iAmAdmin, what: 'Pia is promoted');
    // Pia renames; her copy for Dee waits too, until the owner has built on
    // her rename.
    pia.debugHoldGroupFanout = (rid, _) => rid == deeRid;
    await pia.renameGroup(gid, 'Renamed by Pia');
    await waitUntil(() => owen.groups[gid]!.name == 'Renamed by Pia',
        what: "the owner holds Pia's rename");
    await owen.renameGroup(gid, 'The owner, after Pia');
    expect(owen.groups[gid]!.ver, ver + 3);

    // Pia's list reaches Dee: held back, since Dee has not heard of the
    // promotion. Dee asks the owner, whose answer is his list now — newer
    // than Pia's — and once that is applied Pia's is stale.
    pia.debugHoldGroupFanout = null;
    await pia.retryGroupFanout();
    await waitUntil(
        () => dee.groups[gid]!.name == 'The owner, after Pia',
        what: "Dee holds the owner's latest list");
    // Envelopes from one contact are handled one after another: by the time
    // Dee has this text, the pass that retried Pia's list is over.
    await owen.sendGroupText(gid, 'after the answer');
    await waitUntil(() => texts(dee, gid).contains('after the answer'),
        what: "Dee has the owner's text");
    final g = dee.groups[gid]!;
    expect(g.ver, ver + 3, reason: "Pia's older list was not applied over it");
    expect(g.name, 'The owner, after Pia');
    expect(dee.debugHeldBackLists(gid), 0);
    // The copies the owner's queue held for Dee — the promotion and his
    // rename — now arrive, both older or no newer than what she holds.
    final judged = dee.debugListsJudgedFrom(gid, owen.myRid);
    owen.debugHoldGroupFanout = null;
    await owen.retryGroupFanout();
    await waitUntil(
        () => dee.debugListsJudgedFrom(gid, owen.myRid) >= judged + 2,
        what: "the owner's held copies judged");
    expect(dee.groups[gid]!.ver, ver + 3);
  });

  test('20. a list not shaped as §11 says is refused, never thrown on',
      () async {
    final owen = await start('Owen20');
    final ada = await start('Ada20');
    final ben = await start('Ben20');
    final gid = await groupOf(owen, [ada, ben]);
    final all = [owen, ada, ben];
    final ver = owen.groups[gid]!.ver;
    final members = [for (final s in all) await entry(s)];
    Map<String, Object?> good() => {
          'gid': gid,
          'name': 'Crew',
          'ver': ver + 1,
          'owner': owen.myRid,
          'admins': [owen.myRid],
          'rv': 1,
          'members': members,
        };
    // From the owner, so nothing but the shape can refuse them. An empty
    // owner used to read as "me" on every member.
    final bad = <Map<String, Object?>>[
      {...good(), 'owner': ''},
      {...good(), 'admins': ['', owen.myRid]},
      {...good(), 'admins': ['not a routing id']},
      {...good(), 'owner': 7},
      {...good(), 'ver': 'two'},
      {...good(), 'ver': 2.5},
      {...good(), 'rv': -1},
      {...good(), 'rv': '1'},
      {...good(), 'name': 42},
      {...good(), 'members': 'everyone'},
      // More member entries than §11.1 allows (1 024). Without the cap this
      // one is taken: the junk entries are skipped, the three real ones
      // kept, and the owner's list is otherwise sound.
      {
        ...good(),
        'members': [
          ...members,
          for (var i = members.length; i <= 1024; i++) <String, Object?>{}
        ],
      },
    ];
    expect((bad.last['members'] as List).length, 1025);
    final seen = {
      for (final s in [ada, ben]) s: s.debugListsJudgedFrom(gid, owen.myRid)
    };
    for (final data in bad) {
      for (final s in [ada, ben]) {
        await owen.debugSendRawInner(s.myRid, invite(data));
      }
    }
    await waitUntil(
        () => [ada, ben].every((s) =>
            s.debugListsJudgedFrom(gid, owen.myRid) == seen[s]! + bad.length),
        what: 'every malformed list judged — none of them thrown on');
    for (final s in [ada, ben]) {
      final g = s.groups[gid]!;
      expect(g.ver, ver, reason: '${s.displayName}: nothing applied');
      expect(g.iAmOwner, isFalse, reason: '${s.displayName} owns nothing');
      expect(g.ownerRid, owen.myRid);
      expect(s.debugHeldBackLists(gid), 0, reason: 'nor kept for later');
    }
    // And the next list is taken as ever: no envelope is stuck.
    await owen.renameGroup(gid, 'After the junk');
    await waitUntil(
        () => all.every((s) => s.groups[gid]!.name == 'After the junk'),
        what: "the owner's next list lands");
  });

  test('21. a sender holds one place among held-back lists', () async {
    final owen = await start('Owen21');
    final pia = await start('Pia21'); // promoted; her list waits at Dee
    final dee = await start('Dee21');
    final mal = await start('Mal21'); // a member, never an admin
    final zed = await start('Zed21'); // Dee's contact, not in the group
    final gid = await groupOf(owen, [pia, dee, mal]);
    await waitUntil(() => zed.transport.isConnected, what: 'Zed connects');
    await befriend(dee, zed);
    await settled([dee, zed]);
    final ver = owen.groups[gid]!.ver;
    await owen.waitForGroupFanout(gid);
    final deeRid = dee.myRid;

    // The promotion waits, for Dee, in the owner's queue; the owner goes
    // offline, so nothing of his reaches Dee while the lists pile up.
    owen.debugHoldGroupFanout = (rid, _) => rid == deeRid;
    await owen.promoteAdmin(gid, pia.myRid);
    await waitUntil(() => pia.groups[gid]!.iAmAdmin, what: 'Pia is promoted');
    await owen.transport.stop();
    await pia.renameGroup(gid, 'Renamed by Pia');
    await waitUntil(() => dee.debugHeldBackLists(gid) == 1,
        what: "Dee holds Pia's list back");

    // Mal sends four lists, Zed one, and Pia's list arrives a second time.
    final members = [for (final s in [mal, owen, dee, pia]) await entry(s)];
    for (var i = 0; i < 4; i++) {
      await mal.debugSendRawInner(
          deeRid,
          invite({
            'gid': gid,
            'name': 'junk $i',
            'ver': ver + 50 + i,
            'owner': mal.myRid,
            'admins': [mal.myRid],
            'rv': 9,
            'members': members,
          }));
    }
    await zed.debugSendRawInner(
        deeRid,
        invite({
          'gid': gid,
          'name': 'from outside',
          'ver': ver + 60,
          'members': members,
        }));
    await pia.debugSendRawInner(
        deeRid, invite(await pia.debugInviteData(gid)));
    await waitUntil(
        () =>
            dee.debugListsJudgedFrom(gid, mal.myRid) == 4 &&
            dee.debugListsJudgedFrom(gid, zed.myRid) == 1 &&
            dee.debugListsJudgedFrom(gid, pia.myRid) == 2,
        what: 'every list judged');
    expect(dee.debugHeldBackLists(gid), 2,
        reason: "Pia's once, Mal's newest once, Zed's not at all");

    // The owner comes back and the promotion lands: Pia's list, still held,
    // is applied; none of Mal's ever is.
    owen.debugHoldGroupFanout = null;
    owen.transport.start();
    await waitUntil(() => owen.transport.isConnected, what: 'Owen is back');
    await owen.retryGroupFanout();
    await waitUntil(() => dee.groups[gid]!.name == 'Renamed by Pia',
        what: "Pia's held-back rename survives Mal's junk");
    expect(dee.groups[gid]!.ver, ver + 2);
    // Mal's is tried again with it, and held again: never applied.
    await waitUntil(() => dee.debugHeldBackLists(gid) == 1,
        what: "Mal's list, held again");
    expect(dee.groups[gid]!.ver, ver + 2);
  });

  test("22. the owner is told when a co-admin's later list undoes a removal",
      () async {
    final owen = await start('Owen22');
    final ada = await start('Ada22');
    final ben = await start('Ben22');
    final max = await start('Max22');
    final gid = await groupOf(owen, [ada, ben, max]);
    final all = [owen, ada, ben, max];
    await promote(owen, gid, ada, all);
    final ver = owen.groups[gid]!.ver;

    // At the same moment: the owner removes Max; Ada renames twice, both
    // before she has heard of it. Her second list is a version above the
    // owner's and carries Max, built on her first.
    final fo = owen.removeGroupMember(gid, max.myRid);
    final f1 = ada.renameGroup(gid, 'Ada one');
    final f2 = ada.renameGroup(gid, 'Ada two');
    expect(owen.groups[gid]!.ver, ver + 1);
    expect(ada.groups[gid]!.ver, ver + 2);
    await Future.wait([fo, f1, f2]);
    await atVersion([owen, ada, ben], gid, ver + 2, "Ada's second list");
    // It stands everywhere — and the owner, whose removal it undid, is told.
    await waitUntil(
        () => countKind(owen, gid, SystemKind.changeOverriddenBy) == 1,
        what: 'the owner is told');
    expect(banner(owen, gid, SystemKind.changeOverriddenBy)['by'], 'Ada22');
    expect(owen.groups[gid]!.memberRids, contains(max.myRid));
    expect(countKind(ada, gid, SystemKind.changeOverriddenBy), 0,
        reason: "Ada's list stood");
  });

  test('23. a member a list removes holds that list', () async {
    final owen = await start('Owen23');
    final ada = await start('Ada23');
    final ben = await start('Ben23');
    final zed = await start('Zed23');
    final gid = await groupOf(owen, [ada, ben]);
    await promote(owen, gid, ada, [owen, ada, ben]);
    await waitUntil(() => zed.transport.isConnected, what: 'Zed connects');
    await befriend(ada, zed);
    await settled([ada, zed]);
    await ada.waitForGroupFanout(gid);
    final benRid = ben.myRid;

    // Ada adds Zed — the copy for Ben is held — then removes Ben.
    ada.debugHoldGroupFanout = (rid, _) => rid == benRid;
    await ada.addGroupMembers(gid, [zed.myRid]);
    await waitUntil(() => owen.groups[gid]!.memberRids.contains(zed.myRid),
        what: 'the add reaches the owner');
    // Taken out while still held, so no drain can send it first.
    expect(await lose(ada, gid, benRid), 1);
    ada.debugHoldGroupFanout = null;
    expect(ben.groups[gid]!.memberRids, isNot(contains(zed.myRid)));
    await ada.removeGroupMember(gid, ben.myRid);
    // The record changes as the list is judged; the line follows it.
    await waitUntil(
        () =>
            ben.groups[gid]!.left &&
            countKind(ben, gid, SystemKind.removedFrom) == 1,
        what: 'Ben is told');
    final g = ben.groups[gid]!;
    expect(g.memberRids, {owen.myRid, ada.myRid, zed.myRid},
        reason: 'the members of the list that removed him');
    expect(g.ver, ada.groups[gid]!.ver);
  });

  test('24. a retry pass goes round again when the list held changes under it',
      () async {
    final owen = await start('Owen24');
    final pia = await start('Pia24');
    final dee = await start('Dee24');
    final mal = await start('Mal24');
    final lou = await start('Lou24');
    final five = [owen, pia, dee, mal, lou];
    await waitUntil(() => five.every((s) => s.transport.isConnected),
        what: 'everyone connects');
    for (final s in [pia, dee, mal, lou]) {
      await befriend(owen, s);
    }
    await befriend(dee, lou);
    await settled(five);
    // Lou's laptop: what it sends Dee is handled outside the inbound
    // transaction, so the retry pass it starts can be paused without holding
    // up anything else Dee receives.
    final ll = await link(lou, 'LouLaptop24');
    await knowsVersion(dee, lou.myRid, 1);
    final gid = await owen.createGroup(
        'Crew', [pia.myRid, dee.myRid, mal.myRid, lou.myRid]);
    await waitUntil(
        () => [pia, dee, mal, lou, ll].every((s) => s.groups.containsKey(gid)),
        what: 'the group everywhere');
    final ver = owen.groups[gid]!.ver;
    await owen.waitForGroupFanout(gid);
    final members = [for (final s in five) await entry(s)];
    // The promotion of Pia, sent to Pia alone for now and never installed by
    // the owner himself — so no list of his can stand in for it at Dee.
    final promotion = {
      'gid': gid,
      'name': 'Crew',
      'ver': ver + 1,
      'owner': owen.myRid,
      'admins': [owen.myRid, pia.myRid]..sort(),
      'rv': 1,
      'members': members,
    };
    await owen.debugSendRawInner(pia.myRid, invite(promotion));
    await waitUntil(() => pia.groups[gid]!.iAmAdmin, what: 'Pia is promoted');

    // Dee holds back two lists: Pia's rename, waiting for that promotion,
    // and a member's junk, waiting for nothing that will ever come.
    await pia.renameGroup(gid, 'Renamed by Pia');
    await waitUntil(() => dee.debugHeldBackLists(gid) == 1,
        what: "Dee holds Pia's rename back");
    await mal.debugSendRawInner(
        dee.myRid,
        invite({
          ...promotion,
          'ver': ver + 9,
          'name': 'junk',
          'owner': mal.myRid,
          'admins': [mal.myRid],
          'rv': 5,
        }));
    await waitUntil(() => dee.debugHeldBackLists(gid) == 2,
        what: "Dee holds Mal's back too");

    // Lou leaves, from his laptop; Dee retries both held lists. While that
    // pass waits on Mal's, the promotion lands — and the retry it asks for
    // arrives while a pass is running.
    final paused = Completer<void>();
    final go = Completer<void>();
    final malRid = mal.myRid;
    dee.debugBeforeGroupDecision = (g, sender) {
      if (sender != malRid || paused.isCompleted) return Future<void>.value();
      paused.complete();
      return go.future;
    };
    await ll.leaveGroup(gid);
    await paused.future;
    expect(dee.groups[gid]!.memberRids, isNot(contains(lou.myRid)));
    await owen.debugSendRawInner(dee.myRid, invite(promotion));
    await waitUntil(() => dee.groups[gid]!.rolesVer == 1,
        what: 'the promotion lands on Dee mid-pass');
    dee.debugBeforeGroupDecision = null;
    go.complete();
    await waitUntil(() => dee.groups[gid]!.name == 'Renamed by Pia',
        what: "Pia's rename is applied: the pass went round again");
    expect(dee.groups[gid]!.ver, ver + 2);
    await waitUntil(() => dee.debugHeldBackLists(gid) == 1,
        what: "Mal's list, held again");
    expect(dee.groups[gid]!.ver, ver + 2, reason: "Mal's was never applied");
  });

  test('25. the owner can take the role from an admin who has left',
      () async {
    final owen = await start('Owen25');
    final ada = await start('Ada25');
    final ben = await start('Ben25');
    final gid = await groupOf(owen, [ada, ben]);
    await promote(owen, gid, ada, [owen, ada, ben]);
    await ada.leaveGroup(gid);
    await waitUntil(
        () => [owen, ben]
            .every((s) => !s.groups[gid]!.memberRids.contains(ada.myRid)),
        what: 'the leave lands');
    expect(owen.groups[gid]!.adminRids, {'', ada.myRid},
        reason: 'she keeps the role on paper');
    await owen.demoteAdmin(gid, ada.myRid);
    await waitUntil(
        () => owen.groups[gid]!.adminRids.length == 1 &&
            ben.groups[gid]!.adminRids.length == 1,
        what: 'the demotion lands');
    expect(ben.groups[gid]!.adminRids, {owen.myRid});
    expect(ben.groups[gid]!.rolesVer, owen.groups[gid]!.rolesVer);
  });

  test("26. deleting an admin's contact does not freeze my lists", () async {
    final owen = await start('Owen26');
    final bob = await start('Bob26');
    final cat = await start('Cat26');
    final gid = await groupOf(owen, [bob, cat]);
    final all = [owen, bob, cat];
    await promote(owen, gid, bob, all);
    final ver = owen.groups[gid]!.ver;

    // Bob deletes the owner as a contact. The owner is still in the group,
    // and still its owner: Bob's lists must go on saying so.
    await bob.deleteContact(owen.myRid);
    expect(bob.groups[gid]!.memberRids, contains(owen.myRid));
    final data = await bob.debugInviteData(gid);
    final eds = [
      for (final m in data['members'] as List)
        ((m as Map)['b'] as Map)['ed']
    ];
    final ownerEntry = await entry(owen);
    expect(eds, contains((ownerEntry['b'] as Map)['ed']),
        reason: "Bob's list still names the owner");
    await bob.renameGroup(gid, 'Renamed by Bob');
    await waitUntil(() => cat.groups[gid]!.name == 'Renamed by Bob',
        what: "Cat takes Bob's list");
    final g = cat.groups[gid]!;
    expect(g.ver, ver + 1);
    expect(g.memberRids, contains(owen.myRid));
    expect(g.ownerRid, owen.myRid);
    expect(cat.debugHeldBackLists(gid), 0);
  });

  test('27. a co-admin added from her laptop ranks the same on every member',
      () async {
    // Cora has two devices: her phone holds her account's root, her laptop
    // is linked to it. Owen (the owner) and Ana add her from the LAPTOP's
    // code, which says whose laptop it is (PROTOCOL §18.7): a full contact,
    // her account known. Bo knows only Owen, and adopts her from Owen's list
    // — under the laptop's routing id, knowing nothing of her account. Dan
    // adopts her too. Every one of them holds her as her laptop.
    //
    // Routing ids constructed so that ranking a person by their account
    // where it is known, and by the id they are held under where it is not,
    // splits a tie between Cora and Dan: her account sorts before Dan, her
    // laptop after him. Ranked so (the build before this test), Owen and Ana
    // kept Cora's list and Bo and Dan kept Dan's, for good.
    final phoneId = await ZIdentity.generate();
    final phoneRid = await phoneId.routingId();
    Future<ZIdentity> after(String rid) async {
      while (true) {
        final id = await ZIdentity.generate();
        if ((await id.routingId()).compareTo(rid) > 0) return id;
      }
    }

    final danId = await after(phoneRid);
    final laptopId = await after(await danId.routingId());
    final owen = await start('Owen27');
    final cora = await start('Cora27', identity: phoneId);
    final dan = await start('Dan27', identity: danId);
    final ana = await start('Ana27');
    final bo = await start('Bo27');
    final account = await cora.accountIdentity();
    final cert = await account.signDeviceCert(
        deviceEdPub: laptopId.edPub,
        deviceXPub: laptopId.xPub,
        deviceId: 'laptop');
    final laptop = await startLinked(
        'CoraLaptop27', laptopId, account, cert, account.deviceCert,
        accountMlPub: await cora.pqAccountPublic());
    await waitUntil(
        () => [owen, cora, dan, ana, bo, laptop]
            .every((s) => s.transport.isConnected),
        what: 'everyone connects');
    await cora.addMyDevice(cert);
    expect(b64url(await sha256Bytes(account.accountEdPub)), phoneRid,
        reason: "Cora's account id is her phone's");
    expect(phoneRid.compareTo(dan.myRid), lessThan(0));
    expect(laptop.myRid.compareTo(dan.myRid), greaterThan(0));

    await befriend(owen, laptop);
    await befriend(ana, laptop);
    await befriend(owen, dan);
    await befriend(owen, ana);
    await befriend(owen, bo);
    await settled([owen, laptop, dan, ana, bo]);
    for (final s in [owen, ana]) {
      expect(s.contacts[laptop.myRid]!.accountEdPub, account.accountEdPub,
          reason: "${s.displayName} added Cora's laptop knowing her account");
    }

    final gid = await owen.createGroup(
        'Crew', [laptop.myRid, dan.myRid, ana.myRid, bo.myRid]);
    final all = [owen, laptop, dan, ana, bo];
    await waitUntil(() => all.every((s) => s.groups.containsKey(gid)),
        what: 'everyone holds the group');
    for (final s in [bo, dan]) {
      expect(s.contacts[laptop.myRid], isNotNull,
          reason: '${s.displayName} adopted Cora from the list');
      expect(s.contacts[laptop.myRid]!.accountEdPub, isNull,
          reason: '${s.displayName} knows nothing of her account');
    }
    await owen.promoteAdmin(gid, laptop.myRid);
    await owen.promoteAdmin(gid, dan.myRid);
    final ver = owen.groups[gid]!.ver;
    await atVersion(all, gid, ver, 'Cora and Dan made admins');
    expect(laptop.groups[gid]!.iAmAdmin, isTrue);
    expect(dan.groups[gid]!.iAmAdmin, isTrue);

    // Cora, on her laptop, and Dan change the group at once: two lists at
    // one version, every member hearing both. The names are chosen so that
    // Cora's list is the one that must stand: then Bo, who knows her only
    // as the laptop he adopted, has to take a list she issued as well as
    // rank it — and the split that ranking by account where known gave
    // (Bo keeping Dan's) is the one this case shows.
    final coraBase = await laptop.debugInviteData(gid);
    final danBase = await dan.debugInviteData(gid);
    String digestOf(Map<String, Object?> base, String name) =>
        Group.listDigest({...base, 'name': name, 'ver': ver + 1});
    const danName = "Dan's name";
    final danDigest = digestOf(danBase, danName);
    var coraName = "Cora's name";
    var tries = 1;
    while (digestOf(coraBase, coraName).compareTo(danDigest) > 0) {
      coraName = "Cora's name, ${++tries}";
    }
    final coraDigest = digestOf(coraBase, coraName);
    int judged(ChatService s, String from) =>
        s.debugListsJudgedFrom(gid, from);
    final before = {
      for (final s in [owen, ana, bo])
        s: (judged(s, laptop.myRid), judged(s, dan.myRid)),
    };
    final danSawCora = judged(dan, laptop.myRid);
    final coraSawDan = judged(laptop, dan.myRid);
    final fc = laptop.renameGroup(gid, coraName);
    expect(laptop.groups[gid]!.digest, coraDigest,
        reason: 'the list as predicted');
    final fd = dan.renameGroup(gid, danName);
    expect(dan.groups[gid]!.digest, danDigest);
    expect(laptop.groups[gid]!.ver, ver + 1);
    expect(dan.groups[gid]!.ver, ver + 1);
    await Future.wait([fc, fd]);
    await waitUntil(
        () =>
            before.entries.every((e) =>
                judged(e.key, laptop.myRid) > e.value.$1 &&
                judged(e.key, dan.myRid) > e.value.$2) &&
            judged(dan, laptop.myRid) > danSawCora &&
            judged(laptop, dan.myRid) > coraSawDan,
        what: 'every member has judged both lists');

    // One list on every device — Cora's, whose digest sorts first — whoever
    // each device holds its issuer as.
    await waitUntil(() => all.every((s) => s.groups[gid]!.name == coraName),
        what: "every device holds Cora's list");
    for (final s in all) {
      final g = s.groups[gid]!;
      expect(g.ver, ver + 1, reason: s.displayName);
      expect(g.digest, coraDigest, reason: s.displayName);
      expect(s.debugHeldBackLists(gid), 0, reason: s.displayName);
    }
    for (final s in [owen, ana, bo, dan]) {
      expect(s.groups[gid]!.by, laptop.myRid, reason: s.displayName);
    }
    await waitUntil(
        () => countKind(dan, gid, SystemKind.changeOverriddenBy) == 1,
        what: 'Dan is told');
  });

  test("28. a list's digest is the one PROTOCOL §11.1 pins, byte for byte",
      () {
    // The vectors are computed by the protocol package's generator from the
    // section's own words, not by this code: the canonical JSON hashed, then
    // the digest — for two lists and one whose name needs every escape.
    final file = File('../docs/vectors/v1/inner_messages.json');
    final digests = ((jsonDecode(file.readAsStringSync()) as Map)[
            'group_list_digests'] as List)
        .cast<Map>();
    expect(digests, hasLength(3));
    for (final v in digests) {
      final list =
          (jsonDecode(v['list'] as String) as Map).cast<String, Object?>();
      expect(Group.listCanonical(list), v['canonical']);
      expect(
          utf8
              .encode(Group.listCanonical(list))
              .map((b) => b.toRadixString(16).padLeft(2, '0'))
              .join(),
          v['canonical_hex']);
      expect(Group.listDigest(list), v['digest']);
    }
  });
}
