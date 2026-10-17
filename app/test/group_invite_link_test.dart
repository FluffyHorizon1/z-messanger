// 23.3 — group invite links (ADR 0020): a connect invite that ends in a
// group. REAL ChatService instances and REAL connect ceremonies through the
// REAL Node relay, every frame of which passes through a recording tap (as
// protocol/test/connect_relay_test.dart records one), so what the relay saw
// is asserted rather than assumed.
//
// A group link IS an ordinary one-time connect invite with the group
// remembered on the inviter's device only. One sealed bit in message 3 says
// a group is attached, and nothing says which. The property every test here
// serves: no joiner's identity bundle reaches a group's members unless the
// joiner's own client told its person, before the digits, that the invite
// was to a group, and the person then went ahead (confirmed or skipped the
// comparison). The ceremony reaches the digits with nobody pressing
// anything, so the joiner's message 4 cannot carry that consent; the
// joiner's client says it afterwards, in a `gjoin` over the new pairwise
// session, and only that adds them.
//
// Criteria, each a test below:
//   1. a link minted for a group adds its joiner to that group and to no
//      other — nobody is added before the joiner goes ahead, and the link
//      adds them once;
//   2. the joiner's screen says that the invite is also to a group before
//      the digits (and the inviter's names the group, on the inviter's own
//      screen only); once the group's invite lands, the joiner's banner
//      names who added them and which group;
//   3. the link, in both renderings, contains neither the group id nor the
//      group's name — a byte-level search of the encoded invite — and
//      nothing the relay carried during the whole join contains either;
//   4. a spent link cannot add a second joiner; a revoked link adds nobody;
//      an expired link adds nobody — expired before anyone opened it, or
//      before its joiner's go-ahead arrived;
//   5. a link minted by an admin who is demoted (ADR 0019) before it is
//      spent adds nobody — whether the demotion lands before the admin goes
//      ahead with the joiner or after, before the joiner's go-ahead: the
//      inviter's device refuses, and a list it sends anyway is refused at
//      every member, none of whom takes the joiner in as a member or a
//      contact;
//   6. a joiner whose client predates group links — it cannot show the
//      notice and never sends the go-ahead — becomes a contact only, and the
//      inviter is told so: on the comparison screen before going ahead, and
//      in the group after;
//   7. a joiner who stops at the digits — "they do not match", or a ceremony
//      that aborts — is never added to the group, and their bundle reaches
//      no member's contact table;
//   8. the joiner is not marked `requested`; the confirmed path marks both
//      sides verified exactly as any CONNECT does — the tick over the pair's
//      own number — and the skipped path leaves them unverified, with the
//      JOINER answering first, so the go-ahead the inviter drops as a
//      stranger's (handed over by hand, so it is dropped for certain) is
//      sent again when the inviter speaks;
//   9. message 3 with the group bit and without it is the same size at the
//      relay, and the go-ahead is a sealed envelope in the smallest bucket;
//  10. a link made on a linked device, or opened on one, adds one account
//      once (a member is an account, ADR 0019): the device that made the
//      link is the one that waits and adds, the device that opened it the
//      one that goes ahead; the joiner's other device holds the group as
//      any member's does, and nobody holds a second device as a second
//      member. In a group whose roles have moved, each of the inviter's
//      devices names the inviter by its own id (§11.1), and the joiner
//      holds the owner and admins as every member does;
//  11. deleting the contact a link record names ends the record on that
//      device, sealed cell and all: an inviter that deletes the joiner while
//      waiting drops the go-ahead that arrives afterwards and adds nobody,
//      and a joiner that deletes the inviter while it owes the go-ahead
//      answers the inviter's next hello with nothing — the inviter's wait
//      then ends with the link's day, said in the group;
//  12. a go-ahead answers the ceremony it was given on and no other: given
//      on a link the inviter stopped, it does not add the joiner through a
//      later link — not one the joiner stopped, and not one they never
//      answered — though their client says it again in answer to the
//      inviter's hello, as it says any answer it still owes;
//  13. a joiner can connect without joining: "Also join the group" turned
//      off, they go ahead as a contact only, and the inviter's group says
//      at once that they chose not to join, not later that the link lapsed;
//  14. a joiner or an inviter who already holds the other goes ahead on a
//      group link with the contact they have, left exactly as it was — the
//      tick, the number behind it, the name and the bundle, as written
//      before the answer — and the joiner joins; and nothing is said for
//      the joiner before their person answers, though a session to say it
//      over already exists;
//  15. a go-ahead read just before the inviter's app stopped, and not yet
//      acted on, adds its joiner when the app starts again;
//  16. what a join adds on the wire: the go-ahead sent one to three times
//      — by who answers first, and which of the two opens the session —
//      and nothing owed once the group has come;
//  17. the inviter sees whom it is waiting for and can stop; a go-ahead
//      that arrives afterwards adds nobody, and the joiner stays a contact;
//  18. an answer cut short between adding the contact and the rest of it —
//      the app killed — finishes when the person gives it again: no
//      "already in your contacts" from its own add, the tick, the go-ahead;
//  19. the "Also join the group" switch belongs to its own comparison panel:
//      with two group links open, answering one leaves the other's switch
//      as its person set it, and "they match" on it does what it says;
//  20. an ORDINARY invite between two people who are contacts already is
//      still refused on both sides, and changes nothing either holds;
//  21. stopping a ceremony touches no answer owed from another: a link made
//      by someone holding the inviter's public code, revealing that code
//      with the group bit, and stopped at the digits, leaves the answer the
//      joiner owes the real inviter owed — and the real inviter, going
//      ahead, adds them;
//  22. a contact who opens a group link on another of their devices joins
//      as the contact they are: the inviter knows the device by the list
//      their account signed, holds no second contact for it, reads the
//      answer it sends, and adds the account once;
//  23. an answer cut short after its add does not tick a record that has
//      taken the added one's place: the contact deleted and added back
//      another way before the answer is given again is used as held;
//  24. two links between the same two people are two waits and two
//      answers: neither replaces the other, both add, and a go-ahead
//      already read stays read when the inviter goes ahead on another;
//  25. "Stop waiting" stops a go-ahead already read and not yet acted on;
//      once the add has begun it is too late, and the screen says so;
//  26. a go-ahead into a full group adds nobody (ADR 0036's cap of 128,
//      asked again when the go-ahead lands, as the admin's role is in 5):
//      a link answered while the group had room for one, and acted on
//      after it filled, issues no list — the joiner reaches no member's
//      group — and the inviter's group says why; the joiner stays a
//      contact.
@Tags(['integration'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/connect_invites.dart';
import 'package:zapp/core/models.dart';
import 'package:zapp/core/system_messages.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/l10n/app_localizations.dart';
import 'package:zapp/l10n/app_localizations_en.dart';
import 'package:zapp/l10n/system_text.dart';
import 'package:zapp/ui/connect_tab.dart';
import 'package:zapp/ui/theme.dart';

typedef Person = ({ChatService svc, Vault vault, ConnectInvites invites});

/// The group every test makes. Two words, so that no base64 or hex string on
/// the wire can contain it by chance: a space is in neither alphabet.
const crewName = 'Crew Quarters';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  late Process relay;
  late HttpServer tap;
  late String url;
  final temps = <Directory>[];
  final live = <Person>[];

  // Every frame the tap carried, raw and decoded. Cleared per test.
  final raw = <String>[];
  final seen = <Map<String, Object?>>[];

  setUpAll(() async {
    HttpOverrides.global = null;
    final serverDir =
        '${Directory.current.parent.path}${Platform.pathSeparator}server';
    final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final port = probe.port;
    await probe.close();
    relay = await Process.start('node', ['server.js'],
        workingDirectory: serverDir,
        environment: {'PORT': '$port', 'LOG_LEVEL': 'silent'});
    var up = false;
    for (var i = 0; i < 60 && !up; i++) {
      try {
        final res = await (await HttpClient()
                .getUrl(Uri.parse('http://127.0.0.1:$port/health')))
            .close();
        await res.drain<void>();
        up = res.statusCode == 200;
      } catch (_) {
        await Future<void>.delayed(const Duration(milliseconds: 100));
      }
    }
    if (!up) fail('relay did not start');

    // The tap: both directions piped to the relay verbatim and written down.
    // The Host header goes through unchanged, as a front passes it: a client
    // signs its authentication over the address it dialled.
    tap = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    tap.listen((req) async {
      WebSocket down;
      try {
        down = await WebSocketTransformer.upgrade(req);
      } catch (_) {
        req.response.statusCode = HttpStatus.badRequest;
        await req.response.close();
        return;
      }
      final upstream = await WebSocket.connect('ws://127.0.0.1:$port',
          headers: {'host': req.headers.value('host') ?? ''});
      void note(dynamic d) {
        if (d is! String) return;
        raw.add(d);
        try {
          final j = jsonDecode(d);
          if (j is Map) seen.add(j.cast<String, Object?>());
        } catch (_) {}
      }

      down.listen((d) {
        note(d);
        upstream.add(d);
      }, onDone: () => upstream.close(), onError: (_) => upstream.close());
      upstream.listen((d) {
        note(d);
        down.add(d);
      }, onDone: () => down.close(), onError: (_) => down.close());
    });
    url = 'ws://127.0.0.1:${tap.port}';
  });

  tearDownAll(() async {
    // Everyone's link down first, then nothing else. The vaults are left
    // open, as the multi-device suites leave theirs: a linked device may
    // still be mirroring the last envelope it read to its sibling, which
    // writes the sync session, and a database closed under it is an error
    // charged to whichever test ran last. The process closes them.
    for (final p in live) {
      p.invites.pause();
      // Bounded: a transport whose last work began under a widget test's
      // clock can wait on something that clock will never run again, and a
      // teardown that never ends fails every test in the file.
      await p.svc.transport
          .stop()
          .timeout(const Duration(seconds: 10), onTimeout: () {});
    }
    for (final p in live) {
      p.svc.dispose();
    }
    await tap.close(force: true);
    relay.kill();
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  setUp(() {
    raw.clear();
    seen.clear();
  });

  // Where each person's app keeps its vault, and who it is: what a restart
  // opens again.
  final homes = <ChatService, (Directory, ZIdentity)>{};

  /// A person with an app: a vault, a service, and the CONNECT tab's
  /// invites. [beforeLinks]: their app predates group links (the seam stands
  /// in for that build — it neither reads nor repeats the group bit).
  /// [identity]: who they are, when a test needs a particular routing id.
  Future<Person> person(String name,
      {bool beforeLinks = false, ZIdentity? identity}) async {
    final dir = await Directory.systemTemp.createTemp('z_gil_');
    temps.add(dir);
    final id = identity ?? await ZIdentity.generate();
    final vault = await Vault.open(rootOverride: dir);
    await vault.kvPut('identity', jsonEncode(id.toJson()));
    final svc = await ChatService.init(
        vault: vault,
        identity: id,
        displayName: name,
        transport: Transport(identity: id, serverUrl: url));
    final invites = ConnectInvites(svc)..debugBeforeGroupLinks = beforeLinks;
    final p = (svc: svc, vault: vault, invites: invites);
    homes[svc] = (dir, id);
    live.add(p);
    return p;
  }

  /// [p]'s app stopped and started again: the same vault and identity, a
  /// new service.
  Future<Person> restart(Person p) async {
    final (dir, id) = homes[p.svc]!;
    final name = p.svc.displayName;
    p.invites.pause();
    await p.svc.transport.stop();
    p.svc.dispose();
    live.remove(p);
    await p.vault.db.close();
    final vault = await Vault.open(rootOverride: dir);
    final svc = await ChatService.init(
        vault: vault,
        identity: id,
        displayName: name,
        transport: Transport(identity: id, serverUrl: url));
    final q = (svc: svc, vault: vault, invites: ConnectInvites(svc));
    homes[svc] = (dir, id);
    live.add(q);
    return q;
  }

  Future<void> waitUntil(bool Function() cond,
      {Duration timeout = const Duration(seconds: 60),
      required String what}) async {
    final deadline = DateTime.now().add(timeout);
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
  }

  /// Clients that just added each other have finished introducing
  /// themselves: each holds the other's post-quantum key and nobody has
  /// anything left to send — the observable `settled` waits for in
  /// group_roles_test.dart.
  Future<void> settled(List<Person> all) async {
    final deadline = DateTime.now().add(const Duration(seconds: 60));
    while (true) {
      var done = true;
      for (final s in all) {
        for (final o in all) {
          if (identical(s, o)) continue;
          final c = s.svc.contacts[o.svc.myRid];
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
      if (done && all.every((s) => !s.svc.pqSendPending)) return;
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('the clients never settled');
      }
      await Future<void>.delayed(const Duration(milliseconds: 30));
    }
  }

  /// [owner] makes a group of [members], each first a contact of the
  /// owner's by an ordinary scan; returns once every member holds it.
  Future<String> groupOf(Person owner, List<Person> members,
      {String name = crewName}) async {
    final all = [owner, ...members];
    await waitUntil(() => all.every((p) => p.svc.transport.isConnected),
        what: 'everyone connects');
    for (final m in members) {
      await owner.svc.addContactFromCode(await m.svc.myContactCode());
      await m.svc.addContactFromCode(await owner.svc.myContactCode());
    }
    await settled(all);
    final gid = await owner.svc
        .createGroup(name, [for (final m in members) m.svc.myRid]);
    await waitUntil(() => members.every((m) => m.svc.groups.containsKey(gid)),
        what: 'every member holds "$name"');
    return gid;
  }

  /// Carry both sides of the two invites forward until both show digits.
  /// Each pump is a whole connect-act-disconnect round, awaited, so this
  /// never sleeps on the ceremony.
  Future<void> danceTo(Person a, PendingInvite ai, Person b,
      PendingInvite bi) async {
    for (var i = 0; i < 8 && (ai.sas == null || bi.sas == null); i++) {
      await a.invites.pump();
      await b.invites.pump();
    }
  }

  /// [inviter] makes an invite — a link to [gid] when given — and [joiner]
  /// opens it; returns both sides at the digits.
  Future<(PendingInvite, PendingInvite)> ceremony(Person inviter, Person joiner,
      {String? gid}) async {
    await waitUntil(() => joiner.svc.transport.isConnected,
        what: '${joiner.svc.displayName} connects');
    final mine = await inviter.invites.create(gid: gid);
    final theirs = await joiner.invites.open(mine.link);
    await danceTo(inviter, mine, joiner, theirs);
    expect(mine.sas, isNotNull, reason: 'the inviter reached the digits');
    expect(theirs.sas, mine.sas, reason: 'and the joiner, the same digits');
    return (mine, theirs);
  }

  List<Map<String, Object?>> banners(Person p, String gid) => [
        for (final m in p.svc.messagesByChat[gid] ?? const <ChatMessage>[])
          if (m.kind == 'system' && m.body.startsWith('{'))
            (jsonDecode(m.body) as Map).cast<String, Object?>()
      ];

  Map<String, Object?>? bannerOf(Person p, String gid, String kind) {
    final all = banners(p, gid).where((b) => b['k'] == kind).toList();
    return all.isEmpty ? null : all.last;
  }

  /// Every routing id in [p]'s vault `contacts` table — the record a bundle
  /// that reached them would be in, read from the database, not from memory.
  Future<Set<String>> contactRows(Person p) async => {
        for (final r in await p.vault.db.query('contacts', columns: ['rid']))
          r['rid'] as String
      };

  /// What [p] holds of the contact [rid], as written: the tick and the
  /// number behind it, read from the vault's row, and the name and the
  /// bundle — copied, so a later change to the live record cannot change
  /// what was taken. Until 2026-10-03 test 14 compared the live record with
  /// itself, and a tick set on it by the answer passed unseen.
  Future<Map<String, Object?>> saved(Person p, String rid) async {
    final row = (await p.vault.db.query('contacts',
            columns: ['verified', 'verified_sn'],
            where: 'rid = ?',
            whereArgs: [rid]))
        .single;
    final c = p.svc.contacts[rid]!;
    return {
      'row verified': row['verified'],
      'row verified_sn': row['verified_sn'],
      'verified': c.verified,
      'verifiedSn': c.verifiedSn,
      'name': c.name,
      'bundle': jsonEncode(c.bundle.toJson()),
    };
  }

  /// Whether [p] holds [who] as a member of [gid].
  bool memberOf(Person p, String gid, Person who) =>
      p.svc.groups[gid]?.memberRids.contains(who.svc.myRid) ?? false;

  /// Hand [to] what [from] queued for it while [from]'s link to the relay
  /// was down — read, by the time this returns, exactly as the relay would
  /// have delivered it (as contact_erasure_test.dart carries one). What a
  /// test does next sees [to] after reading it, not while it might still.
  Future<int> carry(Person from, Person to) async {
    final rows = await from.vault.db.query('outbox',
        where: 'rid = ?', whereArgs: [to.svc.myRid], orderBy: 'seq');
    for (final r in rows) {
      await from.vault.db
          .delete('outbox', where: 'seq = ?', whereArgs: [r['seq']]);
    }
    for (final r in rows) {
      await to.svc.debugInbound(RelayInbound(
          id: r['id'] as String,
          from: '',
          payload: r['payload'] as String,
          serverTs: DateTime.now().millisecondsSinceEpoch));
    }
    return rows.length;
  }

  /// An identity whose routing id [ok] accepts — so a test can choose which
  /// of two people is the pair's designated initiator (the lower id).
  Future<ZIdentity> identityWhere(bool Function(String rid) ok) async {
    while (true) {
      final id = await ZIdentity.generate();
      if (ok(await id.routingId())) return id;
    }
  }

  /// Let real work run under a widget test until [cond] holds — a button on
  /// these screens starts vault and relay work the test's clock cannot
  /// finish — or fail, saying [what] never happened.
  Future<void> settleUntil(WidgetTester t, bool Function() cond,
      {required String what}) async {
    final deadline = DateTime.now().add(const Duration(seconds: 60));
    await t.pump(const Duration(milliseconds: 50));
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await t.runAsync(
          () => Future<void>.delayed(const Duration(milliseconds: 50)));
      await t.pump(const Duration(milliseconds: 50));
    }
    await t.pump();
  }

  /// The comparison panel as the CONNECT tab shows it, for [p].
  Widget screen(Person p, Widget child) => MultiProvider(
        providers: [
          ChangeNotifierProvider<ChatService>.value(value: p.svc),
          ChangeNotifierProvider<ConnectInvites>.value(value: p.invites),
        ],
        child: MaterialApp(
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          theme: ZTheme.dark(),
          home: Scaffold(body: SingleChildScrollView(child: child)),
        ),
      );

  /// The link clock a day and an hour ahead: everything else stays put.
  int dayLater() =>
      DateTime.now().millisecondsSinceEpoch +
      connectInviteLifetime.inMilliseconds +
      const Duration(hours: 1).inMilliseconds;

  /// A device linked to [main]'s account, as group_roles_sync_test.dart
  /// links one: its own identity, the account's certificate for it, the
  /// main device as its one sibling — and the main device told, so its
  /// contacts learn it. It has a CONNECT tab of its own.
  ///
  /// Linked as this build links one (`hostDeviceLink`): with the account's
  /// post-quantum public key, so its code names the ACCOUNT beside its own
  /// keys (§18.7). Without it the device is one linked by a build from
  /// before v3, whose code is a bare v1 bundle: whoever adds it holds the
  /// device as a person of its own, and refuses the account's device list
  /// as signed by someone else — so the person never hears from the
  /// account's other devices.
  Future<Person> linked(Person main, String name) async {
    final devId = await ZIdentity.generate();
    final account = await main.svc.accountIdentity();
    final cert = await account.signDeviceCert(
        deviceEdPub: devId.edPub, deviceXPub: devId.xPub, deviceId: name);
    final dir = await Directory.systemTemp.createTemp('z_gil_');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    await vault.kvPut('identity', jsonEncode(devId.toJson()));
    final enrolled = await AccountIdentity.fromEnrollment(
      accountEdPub: account.accountEdPub,
      accountMlPub: await main.svc.pqAccountPublic(),
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
        transport: Transport(identity: devId, serverUrl: url));
    final p = (svc: svc, vault: vault, invites: ConnectInvites(svc));
    live.add(p);
    await waitUntil(() => svc.transport.isConnected,
        what: "${main.svc.displayName}'s new device connects");
    await main.svc.addMyDevice(cert);
    return p;
  }

  /// Wait until [p] holds version [v] or later of [rid]'s device list.
  Future<void> knowsVersion(Person p, String rid, int v) async {
    final deadline = DateTime.now().add(const Duration(seconds: 60));
    while (await p.svc.heldContactListVersion(rid) < v) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException(
            '${p.svc.displayName} never learned $rid\'s device list v$v');
      }
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
  }

  test('1. a link for a group adds its joiner to that group and no other',
      () async {
    final owen = await person('Owen');
    final mia = await person('Mia');
    final jay = await person('Jay');
    final crew = await groupOf(owen, [mia]);
    final other = await owen.svc.createGroup('Other Crew', [mia.svc.myRid]);
    await waitUntil(() => mia.svc.groups.containsKey(other),
        what: 'Mia holds the other group too');

    final (link, jaySide) = await ceremony(owen, jay, gid: crew);
    expect(jaySide.offersGroup, isTrue,
        reason: "Jay's client read the bit: a group is attached");
    expect(link.joinerKnowsGroup, isTrue,
        reason: "and Owen's read it back: Jay's client can say so");

    // Owen goes ahead first. That makes Jay his contact and nothing more:
    // nobody joins a group until they have gone ahead themselves.
    await owen.invites.confirm(link);
    expect(owen.svc.debugAwaitingLinkJoin(jay.svc.myRid), isTrue);
    expect(memberOf(owen, crew, jay), isFalse);
    expect(await contactRows(mia), isNot(contains(jay.svc.myRid)),
        reason: "nothing of Jay's has reached Mia yet");

    await jay.invites.confirm(jaySide);
    await waitUntil(
        () =>
            jay.svc.groups.containsKey(crew) &&
            memberOf(owen, crew, jay) &&
            memberOf(mia, crew, jay),
        what: 'Jay is in the group on every device');

    // That group, and no other.
    expect(jay.svc.groups.keys.toList(), [crew]);
    expect(memberOf(owen, other, jay), isFalse);
    expect(memberOf(mia, other, jay), isFalse);
    expect(jay.svc.groups[crew]!.memberRids, {owen.svc.myRid, mia.svc.myRid});
    // Once: the go-ahead was consumed by the add, and Owen's group says
    // who joined from his link.
    expect(owen.svc.debugAwaitingLinkJoin(jay.svc.myRid), isFalse);
    expect(bannerOf(owen, crew, SystemKind.linkJoined)?['name'], 'Jay');
    expect(bannerOf(owen, crew, SystemKind.addedYou), isNull,
        reason: 'said as a join from the link, not as an add Owen made');
    expect(jay.svc.debugOwesLinkJoin(owen.svc.myRid), isFalse,
        reason: 'the group was what Jay was owed, and it came');
  }, timeout: const Timeout(Duration(minutes: 4)));

  testWidgets('2. the joiner is told before the digits, and named the group '
      'after', (t) async {
    late Person owen, jay;
    late String crew;
    late PendingInvite link, jaySide;
    await t.runAsync(() async {
      owen = await person('Owen');
      final mia = await person('Mia');
      jay = await person('Jay');
      crew = await groupOf(owen, [mia]);
      (link, jaySide) = await ceremony(owen, jay, gid: crew);
    });
    final l = AppLocalizationsEn();

    // Jay's screen. The notice is there, and above the eight digits and
    // the three ways out: it is what Jay reads before choosing.
    final semantics = t.ensureSemantics();
    await t.pumpWidget(screen(jay, ConnectConfirmPanel(invite: jaySide)));
    await t.pumpAndSettle();
    final notice = find.text(l.connectGroupNotice);
    final digits = find.text(jaySide.sas!);
    expect(notice, findsOneWidget);
    expect(digits, findsOneWidget);
    expect(t.getTopLeft(notice).dy, lessThan(t.getTopLeft(digits).dy),
        reason: 'the group is said before the digits');
    expect(t.getTopLeft(notice).dy,
        lessThan(t.getTopLeft(find.text(l.connectMatch)).dy));
    // A card merges its children's labels into one node, so this asks
    // whether the notice is IN what a screen reader announces.
    expect(
        find.bySemanticsLabel(RegExp(RegExp.escape(l.connectGroupNotice))),
        findsWidgets,
        reason: 'and a screen reader says it too');
    expect(find.textContaining(crewName), findsNothing,
        reason: "Jay's client does not know which group: the link says not");
    // Going ahead joins, unless Jay says otherwise, beside the buttons it
    // changes (criterion 13 turns it off).
    final join = find.byKey(const ValueKey('connect-join-group'));
    expect(t.widget<SwitchListTile>(join).value, isTrue);
    expect(find.text(l.connectJoinGroup), findsOneWidget);
    semantics.dispose();

    // Owen's screen names the group — his own, the only place it is shown —
    // and has no notice meant for a joiner.
    await t.pumpWidget(screen(owen, ConnectConfirmPanel(invite: link)));
    await t.pumpAndSettle();
    expect(find.text(l.connectGroupNotice), findsNothing);
    expect(find.text(l.connectGroupLinkGoAhead(crewName)), findsOneWidget);
    expect(find.text(l.connectGroupLinkTooOld(crewName)), findsNothing);
    expect(find.byKey(const ValueKey('connect-join-group')), findsNothing,
        reason: 'the choice is the joiner\'s');
    // The same screen once the link's 24 hours are over says, before Owen
    // goes ahead, that the link can no longer add Jay.
    owen.svc.debugLinkClock = dayLater;
    await t.pumpWidget(const SizedBox.shrink());
    await t.pumpWidget(screen(owen, ConnectConfirmPanel(invite: link)));
    await t.pumpAndSettle();
    expect(find.text(l.connectGroupLinkExpired(crewName)), findsOneWidget);
    expect(find.text(l.connectGroupLinkGoAhead(crewName)), findsNothing);
    owen.svc.debugLinkClock = null;
    await t.pumpWidget(const SizedBox.shrink());

    await t.runAsync(() async {
      await owen.invites.defer(link);
      await jay.invites.confirm(jaySide);
      // The banner is the last thing the arriving invite writes: wait for
      // whichever it is, then say which it must be.
      await waitUntil(
          () =>
              bannerOf(jay, crew, SystemKind.addedFromLinkBy) != null ||
              bannerOf(jay, crew, SystemKind.addedToBy) != null,
          what: "the group's invite reaches Jay");
    });
    await t.pumpWidget(const SizedBox.shrink());

    // The banner: who, and which group, from the link Jay opened.
    final row = bannerOf(jay, crew, SystemKind.addedFromLinkBy);
    expect(row, isNotNull, reason: 'the join is said as one from the link');
    expect(row!['by'], 'Owen');
    expect(row['name'], crewName);
    expect(bannerOf(jay, crew, SystemKind.addedToBy), isNull);
    final stored = jsonEncode(row);
    expect(systemText(l, stored),
        'Owen added you to "$crewName" from the link you opened.');
    final es = await AppLocalizations.delegate.load(const Locale('es'));
    expect(systemText(es, stored),
        'Owen te añadió a «$crewName» desde el enlace que abriste.');
  }, timeout: const Timeout(Duration(minutes: 4)));

  test('3. the link names no group, and neither does anything on the wire',
      () async {
    final owen = await person('Owen');
    final mia = await person('Mia');
    final jay = await person('Jay');
    final crew = await groupOf(owen, [mia]);
    raw.clear();
    seen.clear();

    final link = await owen.invites.create(gid: crew);
    final needles = <String, List<int>>{
      'the group id': utf8.encode(crew),
      "the group id's bytes": unb64url(crew.substring(1)),
      'the group name': utf8.encode(crewName),
    };
    bool holds(List<int> hay, List<int> needle) {
      for (var i = 0; i + needle.length <= hay.length; i++) {
        var all = true;
        for (var k = 0; k < needle.length && all; k++) {
          all = hay[i + k] == needle[k];
        }
        if (all) return true;
      }
      return false;
    }

    for (final rendering in [link.link, link.code]) {
      final bytes = utf8.encode(rendering);
      needles.forEach((what, needle) {
        expect(holds(bytes, needle), isFalse,
            reason: '$what is in the rendering "$rendering"');
      });
    }
    // Both renderings are ten random bytes, nothing more: the code decodes
    // to exactly the secret the run holds, and that is all there is.
    expect(ConnectCode.parse(link.code).secret, link.run.code.secret);
    expect(ConnectCode.fromLink(link.link)!.secret, link.run.code.secret);
    expect(link.run.code.secret.length, 10);
    // The run — everything the ceremony knows — holds a bit, not a group.
    final run = jsonEncode(link.run.toJson());
    expect(run.contains(crew), isFalse);
    expect(run.contains(crewName), isFalse);

    // The whole join, through the tap.
    final jaySide = await jay.invites.open(link.link);
    await danceTo(owen, link, jay, jaySide);
    await owen.invites.confirm(link);
    await jay.invites.confirm(jaySide);
    await waitUntil(
        () => jay.svc.groups.containsKey(crew) && memberOf(mia, crew, jay),
        what: 'Jay joins');

    final wire = raw.join('\n');
    expect(wire, isNotEmpty);
    final nameBytes = utf8.encode(crewName);
    final forbidden = <String, String>{
      'the group id': crew,
      'the group name': crewName,
      'the group name, base64': b64(nameBytes),
      'the group name, base64url': b64url(nameBytes),
      "the group id's bytes, base64": b64(unb64url(crew.substring(1))),
    };
    forbidden.forEach((what, needle) {
      expect(wire.contains(needle), isFalse,
          reason: '$what crossed the relay');
    });
  }, timeout: const Timeout(Duration(minutes: 4)));

  test('4. spent, revoked and expired links add nobody', () async {
    final owen = await person('Owen');
    final mia = await person('Mia');
    final jay = await person('Jay');
    final kim = await person('Kim');
    final lee = await person('Lee');
    final max = await person('Max');
    final nia = await person('Nia');
    final crew = await groupOf(owen, [mia]);

    /// Nobody but [who]'s own client knows of [who]: not the inviter, not
    /// the group on any device.
    Future<void> addedNowhere(Person who) async {
      expect(owen.svc.contacts.containsKey(who.svc.myRid), isFalse);
      expect(memberOf(owen, crew, who), isFalse);
      expect(memberOf(mia, crew, who), isFalse);
      expect(await contactRows(mia), isNot(contains(who.svc.myRid)));
    }

    // Spent: Jay joins through the link, then Kim opens the same one.
    final (link, jaySide) = await ceremony(owen, jay, gid: crew);
    await owen.invites.confirm(link);
    await jay.invites.confirm(jaySide);
    await waitUntil(() => memberOf(mia, crew, jay) && memberOf(owen, crew, jay),
        what: 'Jay joins through the link');
    final kimSide = await kim.invites.open(link.link);
    for (var i = 0; i < 4; i++) {
      await owen.invites.pump();
      await kim.invites.pump();
    }
    expect(kimSide.sas, isNull, reason: 'nobody answers a spent invite');
    await addedNowhere(kim);
    expect(owen.svc.groups[crew]!.memberRids, {mia.svc.myRid, jay.svc.myRid},
        reason: 'one link, one joiner');

    // Revoked: discarded after its first message was already posted.
    final revoked = await owen.invites.create(gid: crew);
    await owen.invites.pump();
    await owen.invites.discard(revoked);
    final leeSide = await lee.invites.open(revoked.link);
    for (var i = 0; i < 4; i++) {
      await owen.invites.pump();
      await lee.invites.pump();
    }
    expect(leeSide.sas, isNull, reason: 'a revoked link is answered by nobody');
    await addedNowhere(lee);

    // Expired before anyone opened it: made a day and an hour ago.
    final stale = await owen.invites.create(
        gid: crew,
        nowMs: DateTime.now().millisecondsSinceEpoch -
            connectInviteLifetime.inMilliseconds -
            const Duration(hours: 1).inMilliseconds);
    final maxSide = await max.invites.open(stale.link);
    for (var i = 0; i < 3; i++) {
      await owen.invites.pump();
      await max.invites.pump();
    }
    expect(stale.progress, ConnectProgress.expired);
    expect(maxSide.sas, isNull);
    await addedNowhere(max);

    // Expired before the go-ahead arrived: the ceremony completed and Owen
    // went ahead within the day, and Nia's go-ahead reaches him after it.
    final (lateLink, niaSide) = await ceremony(owen, nia, gid: crew);
    await owen.invites.confirm(lateLink);
    expect(owen.svc.debugAwaitingLinkJoin(nia.svc.myRid), isTrue);
    owen.svc.debugLinkClock = dayLater;
    try {
      await nia.invites.confirm(niaSide);
      await waitUntil(
          () => (owen.svc.debugLinkJoinsRead[nia.svc.myRid] ?? 0) > 0,
          what: "Owen reads Nia's go-ahead, a day late");
      await owen.svc.debugSweepLinks();
    } finally {
      owen.svc.debugLinkClock = null;
    }
    expect(bannerOf(owen, crew, SystemKind.linkExpired)?['name'], 'Nia',
        reason: 'the group says the link ran out before Nia joined');
    expect(owen.svc.debugAwaitingLinkJoin(nia.svc.myRid), isFalse);
    expect(memberOf(owen, crew, nia), isFalse);
    expect(memberOf(mia, crew, nia), isFalse);
    expect(await contactRows(mia), isNot(contains(nia.svc.myRid)));
    expect(nia.svc.groups, isEmpty);
  }, timeout: const Timeout(Duration(minutes: 8)));

  test('5. a link minted by an admin since demoted adds nobody', () async {
    final owen = await person('Owen');
    final ada = await person('Ada');
    final mia = await person('Mia');
    final jay = await person('Jay');
    final kim = await person('Kim');
    final crew = await groupOf(owen, [ada, mia]);
    final everyone = [owen, ada, mia];
    await owen.svc.promoteAdmin(crew, ada.svc.myRid);
    final promoted = owen.svc.groups[crew]!.ver;
    await waitUntil(
        () => everyone.every((p) => p.svc.groups[crew]!.ver == promoted),
        what: 'everyone holds Ada as an admin');

    // Ada, an admin, mints two links: she may add members, so she may.
    expect(ada.svc.mayIssueGroupList(crew, ''), isTrue);
    final first = await ada.invites.create(gid: crew);
    final second = await ada.invites.create(gid: crew);

    // Jay answers the first, and Ada goes ahead while still an admin: her
    // device waits for Jay's go-ahead.
    await waitUntil(
        () => jay.svc.transport.isConnected && kim.svc.transport.isConnected,
        what: 'the joiners connect');
    final jaySide = await jay.invites.open(first.link);
    await danceTo(ada, first, jay, jaySide);
    await ada.invites.confirm(first);
    expect(ada.svc.debugAwaitingLinkJoin(jay.svc.myRid), isTrue);

    // The owner demotes her before either link is spent.
    await owen.svc.demoteAdmin(crew, ada.svc.myRid);
    final demoted = owen.svc.groups[crew]!.ver;
    await waitUntil(
        () => everyone.every((p) => p.svc.groups[crew]!.ver == demoted),
        what: 'everyone holds the demotion');
    expect(ada.svc.mayIssueGroupList(crew, ''), isFalse);

    // Kim answers the second; it still says a group is attached — the bit
    // was sealed when it was minted — but when Ada goes ahead her device
    // refuses at once, and her group says why.
    final kimSide = await kim.invites.open(second.link);
    await danceTo(ada, second, kim, kimSide);
    expect(kimSide.offersGroup, isTrue);
    await ada.invites.confirm(second);
    expect(ada.svc.debugAwaitingLinkJoin(kim.svc.myRid), isFalse);
    expect(bannerOf(ada, crew, SystemKind.linkRefused)?['name'], 'Kim');

    // Both joiners go ahead, with their links to the relay down, and what
    // they say is handed to Ada by hand: each go-ahead is judged in front of
    // this test, and what it did is asserted at once rather than waited for.
    await jay.svc.transport.stop();
    await kim.svc.transport.stop();
    await jay.invites.confirm(jaySide);
    await kim.invites.confirm(kimSide);
    expect(await carry(jay, ada), greaterThan(0));
    expect(await carry(kim, ada), greaterThan(0));
    // Jay's found Ada waiting, and was judged against the list held when
    // it arrived: refused, and said so. Kim's found nothing waiting.
    expect(ada.svc.debugLinkJoinsRead[jay.svc.myRid], 1);
    expect(ada.svc.debugLinkJoinsRead[kim.svc.myRid], 1);
    expect(ada.svc.debugAwaitingLinkJoin(jay.svc.myRid), isFalse);
    expect(
        banners(ada, crew).where((b) =>
            b['k'] == SystemKind.linkRefused && b['name'] == 'Jay'),
        hasLength(1),
        reason: "Ada's device refused Jay's go-ahead, and said why");
    // Who was added: nobody, anywhere.
    expect(ada.svc.groups[crew]!.ver, demoted, reason: 'no list was issued');
    for (final p in everyone) {
      for (final who in [jay, kim]) {
        expect(memberOf(p, crew, who), isFalse,
            reason: '${p.svc.displayName} holds ${who.svc.displayName}');
      }
    }

    // And a list her device sends anyway — a modified client, adding Jay on
    // the strength of the role she lost — is refused at every member, none
    // of whom takes Jay in, as a member or as a contact.
    final forged = Map<String, Object?>.of(await ada.svc.debugInviteData(crew));
    forged['ver'] = demoted + 1;
    forged['members'] = [
      ...(forged['members'] as List),
      {
        'b': (await jay.svc.identity.bundle(displayName: 'Jay')).toJson(),
        'n': 'Jay',
      },
    ];
    // Counted per sender: a member that refuses a list asks the owner about
    // it (`gsync`), and the owner's answer is a list judged too.
    final judged = {
      for (final p in [owen, mia])
        p: p.svc.debugListsJudgedFrom(crew, ada.svc.myRid)
    };
    for (final p in [owen, mia]) {
      await ada.svc.debugSendRawInner(
          p.svc.myRid,
          InnerMessage(
              kind: 'ginvite', mid: newMessageId(), ts: 1, data: forged));
    }
    await waitUntil(
        () => judged.entries.every((e) =>
            e.key.svc.debugListsJudgedFrom(crew, ada.svc.myRid) > e.value),
        what: "Owen and Mia judge Ada's list");
    for (final p in [owen, mia]) {
      expect(memberOf(p, crew, jay), isFalse,
          reason: '${p.svc.displayName} refused the list');
      expect(p.svc.groups[crew]!.ver, demoted);
      final rows = await contactRows(p);
      expect(rows, isNot(contains(jay.svc.myRid)),
          reason: "Jay's bundle reached ${p.svc.displayName}'s contacts");
      expect(rows, isNot(contains(kim.svc.myRid)));
      // What ADR 0019 does with a member's refused list: keeps it, sealed in
      // the group's record, in case what it rests on has not arrived yet,
      // and judges it again whenever the list held changes — refused for as
      // long as Ada is not an admin, and stale once a promotion opens a
      // newer roles version.
      expect(p.svc.debugHeldBackLists(crew), 1,
          reason: '${p.svc.displayName} holds the refused list back');
    }
  }, timeout: const Timeout(Duration(minutes: 6)));

  testWidgets('6. a joiner whose app predates links is a contact only, and '
      'the inviter is told', (t) async {
    late Person owen, mia, jay;
    late String crew;
    late PendingInvite link, jaySide;
    await t.runAsync(() async {
      owen = await person('Owen');
      mia = await person('Mia');
      jay = await person('Jay', beforeLinks: true);
      crew = await groupOf(owen, [mia]);
      (link, jaySide) = await ceremony(owen, jay, gid: crew);
    });
    final l = AppLocalizationsEn();
    expect(jaySide.offersGroup, isFalse,
        reason: 'that client never read the bit');
    expect(link.joinerKnowsGroup, isFalse,
        reason: 'and never said it back, so Owen knows');

    // Owen is told before he goes ahead, naming the group, on his screen.
    await t.pumpWidget(screen(owen, ConnectConfirmPanel(invite: link)));
    await t.pumpAndSettle();
    expect(find.text(l.connectGroupLinkTooOld(crewName)), findsOneWidget);
    expect(find.text(l.connectGroupLinkGoAhead(crewName)), findsNothing);
    // Jay's screen says nothing about a group: his app cannot.
    await t.pumpWidget(screen(jay, ConnectConfirmPanel(invite: jaySide)));
    await t.pumpAndSettle();
    expect(find.text(l.connectGroupNotice), findsNothing);
    await t.pumpWidget(const SizedBox.shrink());

    await t.runAsync(() async {
      await owen.invites.confirm(link);
      await jay.invites.confirm(jaySide);
      // They are contacts: a message gets through. The link added nothing.
      await owen.svc.sendText(jay.svc.myRid, 'welcome');
      await waitUntil(
          () => (jay.svc.messagesByChat[owen.svc.myRid] ?? const [])
              .any((m) => m.body == 'welcome'),
          what: 'Jay hears from Owen');
    });
    expect(owen.svc.debugAwaitingLinkJoin(jay.svc.myRid), isFalse,
        reason: 'Owen never waited for a go-ahead that cannot come');
    expect(jay.svc.debugLinkJoinMids, isEmpty,
        reason: 'and none was ever sent');
    expect(jay.svc.groups, isEmpty);
    expect(memberOf(owen, crew, jay), isFalse);
    expect(memberOf(mia, crew, jay), isFalse);
    late Set<String> miaRows;
    await t.runAsync(() async => miaRows = await contactRows(mia));
    expect(miaRows, isNot(contains(jay.svc.myRid)));
    final row = bannerOf(owen, crew, SystemKind.linkTooOld);
    expect(row?['name'], 'Jay', reason: "Owen's group says so");
    expect(
        systemText(l, jsonEncode(row)),
        'Jay is your contact, but was not added to this group: their app is '
        'too old to join from a link. Add them by hand.');
  }, timeout: const Timeout(Duration(minutes: 4)));

  test('7. a joiner who stops at the digits is never added', () async {
    final owen = await person('Owen');
    final mia = await person('Mia');
    final jay = await person('Jay');
    final kim = await person('Kim');
    final crew = await groupOf(owen, [mia]);

    // Jay says the digits do not match; Owen had already gone ahead.
    final (link, jaySide) = await ceremony(owen, jay, gid: crew);
    await owen.invites.confirm(link);
    expect(owen.svc.debugAwaitingLinkJoin(jay.svc.myRid), isTrue);
    await jay.invites.mismatch(jaySide);
    expect(jay.svc.contacts, isEmpty, reason: 'Jay added nobody');
    expect(jay.svc.debugLinkJoinMids, isEmpty,
        reason: 'and sent no go-ahead: there is nobody to send it to');
    // The day ends on Owen's device; the group says Jay never joined.
    owen.svc.debugLinkClock = dayLater;
    try {
      await owen.svc.debugSweepLinks();
    } finally {
      owen.svc.debugLinkClock = null;
    }
    expect(bannerOf(owen, crew, SystemKind.linkExpired)?['name'], 'Jay');
    expect(owen.svc.debugAwaitingLinkJoin(jay.svc.myRid), isFalse);

    // A ceremony that aborts: whoever else holds the link writes a malformed
    // opening into Kim's mailbox, her client refuses it, and the invite is
    // spent on her side with no digits ever shown.
    final second = await owen.invites.create(gid: crew);
    final kimSide = await kim.invites.open(second.link);
    await owen.invites.pump(); // message 1 is in Kim's mailbox
    await kim.invites.pump(); // message 2 is in Owen's
    final impostor = await RelayClient.connect(
        url, await mailboxIdentity(second.run.code, 'i'));
    await impostor.send(
      to: await (await mailboxIdentity(second.run.code, 'r')).routingId(),
      id: 'z-connect-c3',
      payload: jsonEncode(
          {'k': 'x3', 'ephx': b64(Uint8List(8)), 'blob': b64(Uint8List(40))}),
    );
    await impostor.close();
    await kim.invites.pump();
    expect(kimSide.progress, ConnectProgress.aborted);
    expect(kimSide.sas, isNull);
    for (var i = 0; i < 2; i++) {
      await owen.invites.pump();
      await kim.invites.pump();
    }
    expect(second.sas, isNull, reason: "Owen never heard Kim's reveal");
    expect(kim.svc.contacts, isEmpty);
    expect(kim.svc.debugLinkJoinMids, isEmpty);

    // Neither reached the group, and neither's bundle reached a member who
    // was not party to their ceremony. (Owen holds Jay because Owen went
    // ahead with him: that is the CONNECT, which is not the group.)
    for (final who in [jay, kim]) {
      expect(memberOf(owen, crew, who), isFalse);
      expect(memberOf(mia, crew, who), isFalse);
      expect(await contactRows(mia), isNot(contains(who.svc.myRid)),
          reason: "${who.svc.displayName}'s bundle reached Mia");
    }
    expect(await contactRows(owen), isNot(contains(kim.svc.myRid)));
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('8. not requested; confirmed is verified, skipped is not', () async {
    final owen = await person('Owen');
    final mia = await person('Mia');
    final jay = await person('Jay');
    final kim = await person('Kim');
    final crew = await groupOf(owen, [mia]);

    // Both confirm — and the JOINER first. Jay goes ahead while Owen does
    // not hold him yet, so his go-ahead reaches Owen as a stranger's and is
    // dropped — handed over by hand here, so it is dropped for certain
    // rather than raced against Owen's own answer. Once Owen goes ahead he
    // speaks first, and Jay's client answers with the go-ahead again.
    final (link, jaySide) = await ceremony(owen, jay, gid: crew);
    await jay.svc.transport.stop();
    await jay.invites.confirm(jaySide);
    expect(jay.svc.debugOwesLinkJoin(owen.svc.myRid), isTrue);
    expect(jay.svc.debugLinkJoinMids, hasLength(1));
    expect(await carry(jay, owen), greaterThan(0));
    expect(owen.svc.debugLinkJoinsRead[jay.svc.myRid], isNull,
        reason: 'dropped as a stranger\'s, unread');
    jay.svc.transport.start();
    await owen.invites.confirm(link);
    await waitUntil(
        () =>
            jay.svc.groups.containsKey(crew) &&
            memberOf(owen, crew, jay) &&
            memberOf(mia, crew, jay),
        what: 'Jay joins, having answered first');
    expect(jay.svc.debugLinkJoinMids.length, greaterThanOrEqualTo(2),
        reason: "the go-ahead was said again, answering Owen's hello");
    // Both have finished introducing themselves, post-quantum keys included,
    // so the number each shows now is the number it will go on showing.
    await settled([owen, jay]);

    for (final (side, svc, peer) in [
      ('Owen', owen.svc, jay.svc.myRid),
      ('Jay', jay.svc, owen.svc.myRid),
    ]) {
      final c = svc.contacts[peer]!;
      expect(c.requested, isFalse, reason: '$side: not a pending request');
      expect(c.verified, isTrue, reason: '$side: the digits were confirmed');
      // The tick stands over the pair's own number, recorded as any CONNECT
      // records it (`setVerified`, adr/0009): the number showing when the
      // person confirmed. That is the classical one if the peer's
      // post-quantum key had not landed yet and the post-quantum one if it
      // had — a race the CONNECT path has always run, which a group link
      // neither adds to nor changes — and the state follows from which.
      final classical = await safetyNumber(
          (await svc.accountIdentity()).accountEdPub, c.accountEd);
      final now = await svc.safetyNumberWith(peer);
      expect(c.verifiedSn, anyOf(classical, now),
          reason: "$side: the pair's own number, never another");
      expect(
          svc.verificationWith(peer),
          c.verifiedSn == now
              ? VerificationState.verified
              : VerificationState.upgradedReverify,
          reason: '$side: the tick reads as any CONNECT tick reads');
    }
    // Mia meets Jay through the group: an ordinary member, unverified,
    // never a request.
    final miasJay = mia.svc.contacts[jay.svc.myRid]!;
    expect(miasJay.requested, isFalse);
    expect(miasJay.verified, isFalse);

    // Both skip the comparison — again the joiner first, and again her
    // first go-ahead dropped for certain.
    final (link2, kimSide) = await ceremony(owen, kim, gid: crew);
    await kim.svc.transport.stop();
    await kim.invites.defer(kimSide);
    expect(await carry(kim, owen), greaterThan(0));
    expect(owen.svc.debugLinkJoinsRead[kim.svc.myRid], isNull);
    kim.svc.transport.start();
    await owen.invites.defer(link2);
    await waitUntil(
        () =>
            kim.svc.groups.containsKey(crew) &&
            memberOf(owen, crew, kim) &&
            memberOf(mia, crew, kim),
        what: 'Kim joins without a comparison');
    for (final (side, svc, peer) in [
      ('Owen', owen.svc, kim.svc.myRid),
      ('Kim', kim.svc, owen.svc.myRid),
    ]) {
      final c = svc.contacts[peer]!;
      expect(c.requested, isFalse, reason: '$side: not a pending request');
      expect(c.verified, isFalse, reason: '$side: nobody compared');
      expect(c.verifiedSn, isNull);
      expect(svc.verificationWith(peer), VerificationState.unverified);
    }
  }, timeout: const Timeout(Duration(minutes: 6)));

  test('9. message 3 is one size with the bit or without; the go-ahead is '
      'the smallest envelope', () async {
    final owen = await person('Owen');
    final mia = await person('Mia');
    final jay = await person('Jay');
    final kim = await person('Kim');
    final crew = await groupOf(owen, [mia]);
    seen.clear();

    // A link to the group and an ordinary invite, made by the same person,
    // both answered as far as the digits.
    final (link, jaySide) = await ceremony(owen, jay, gid: crew);
    final (plain, kimSide) = await ceremony(owen, kim);
    expect(jaySide.offersGroup, isTrue);
    expect(kimSide.offersGroup, isFalse);

    /// Message 3 of [inv] exactly as the relay received it.
    Future<String> openingOf(PendingInvite inv) async {
      final to = await (await mailboxIdentity(inv.run.code, 'r')).routingId();
      return seen
          .where((f) =>
              f['t'] == 'send' && f['id'] == 'z-connect-c3' && f['to'] == to)
          .single['payload'] as String;
    }

    final withBit = await openingOf(link);
    final withoutBit = await openingOf(plain);
    expect((jsonDecode(withBit) as Map).keys.toSet(), {'k', 'ephx', 'blob'},
        reason: 'nothing outside the seal');
    expect(withBit.length, withoutBit.length,
        reason: 'message 3 is one length at the relay, group or not');
    // ignore: avoid_print
    print('message 3 at the relay: group link ${withBit.length} bytes, '
        'ordinary invite ${withoutBit.length} bytes');

    // The go-ahead, weighed in Jay's outbox with his link to the relay down,
    // exactly as the relay will receive it.
    await owen.invites.confirm(link);
    await jay.svc.transport.stop();
    await jay.invites.confirm(jaySide);
    final mid = jay.svc.debugLinkJoinMids.single;
    final env = (await jay.vault.db
            .query('outbox', where: 'mid = ?', whereArgs: [mid]))
        .single['payload'] as String;
    expect(SealedEnvelope.looksSealed(env), isTrue,
        reason: 'sealed: the relay learns no sender');
    final bucket = unb64url(env.substring('zs1.'.length)).length - 32 - 12 - 16;
    final opened = (await SealedEnvelope.open(
        myXSeed: owen.svc.identity.xSeed,
        myXPub: owen.svc.identity.xPub,
        blob: env))!;
    final needed =
        utf8.encode(jsonEncode({'f': opened.fromRid, 'p': opened.payload}))
                .length +
            4;
    expect(bucket, sealedBuckets.first,
        reason: 'the smallest bucket, where a read receipt goes');
    // ignore: avoid_print
    print('the go-ahead: $needed bytes of sealed plaintext, '
        'in the $bucket-byte bucket');
    jay.svc.transport.start();
    await waitUntil(
        () => jay.svc.groups.containsKey(crew) && memberOf(mia, crew, jay),
        what: 'and it still adds Jay once it goes');
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('10. a link made on a linked device, or opened on one, adds one '
      'account, once', () async {
    final owen = await person('Owen');
    final mia = await person('Mia');
    final jay = await person('Jay');
    final kim = await person('Kim');
    await waitUntil(
        () => [owen, mia, jay, kim].every((p) => p.svc.transport.isConnected),
        what: 'everyone connects');
    // Owen links a laptop, and Mia holds the device list that names it,
    // before the group exists.
    await owen.svc.addContactFromCode(await mia.svc.myContactCode());
    await mia.svc.addContactFromCode(await owen.svc.myContactCode());
    await settled([owen, mia]);
    final owensLaptop = await linked(owen, 'Owen');
    final withLaptop = await owen.svc.ownDeviceListVersion();
    await knowsVersion(mia, owen.svc.myRid, withLaptop);
    final kimsLaptop = await linked(kim, 'Kim');
    final crew = await owen.svc.createGroup(crewName, [mia.svc.myRid]);
    await waitUntil(
        () => [mia, owensLaptop].every((p) => p.svc.groups.containsKey(crew)),
        what: "the group reaches Mia and Owen's laptop");
    // Roles that have moved — Mia a co-admin, made one on Owen's phone, the
    // device that holds his account's root — so every list names its owner
    // and its admins (§11.1).
    await owen.svc.promoteAdmin(crew, mia.svc.myRid);
    await waitUntil(
        () => [mia, owensLaptop]
            .every((p) => p.svc.groups[crew]!.adminRids.length == 2),
        what: 'Mia is a co-admin on every device');
    expect(owensLaptop.svc.mayIssueGroupList(crew, ''), isTrue,
        reason: 'adding a member needs no root (ADR 0019)');
    final laptopRid = owensLaptop.svc.myRid;
    // A device names itself by its own routing id, and the laptop is the
    // one id of Owen's that whoever connects with it holds.
    final fromTheLaptop = await owensLaptop.svc.debugInviteData(crew);
    expect(fromTheLaptop['owner'], laptopRid);
    expect(fromTheLaptop['admins'], unorderedEquals([laptopRid, mia.svc.myRid]));

    // (a) Owen makes the link on his laptop; Jay opens it on his phone.
    final (fromLaptop, jaySide) = await ceremony(owensLaptop, jay, gid: crew);
    expect(jaySide.offersGroup, isTrue);
    await owensLaptop.invites.confirm(fromLaptop);
    expect(owensLaptop.svc.debugAwaitingLinkJoin(jay.svc.myRid), isTrue);
    expect(owen.svc.debugAwaitingLinkJoin(jay.svc.myRid), isFalse,
        reason: 'the record is on the device that made the link');
    await jay.invites.confirm(jaySide);
    await waitUntil(
        () =>
            bannerOf(jay, crew, SystemKind.addedFromLinkBy) != null &&
            [owen, owensLaptop, mia].every((p) => memberOf(p, crew, jay)),
        what: "Jay is told he joined, and is a member on every device, "
            "Owen's phone included");
    expect(bannerOf(owensLaptop, crew, SystemKind.linkJoined)?['name'], 'Jay');
    expect(bannerOf(owen, crew, SystemKind.linkJoined), isNull,
        reason: "Owen's phone made no link and added nobody from one");
    expect(owensLaptop.svc.debugAwaitingLinkJoin(jay.svc.myRid), isFalse);
    expect(bannerOf(jay, crew, SystemKind.addedFromLinkBy),
        {'k': SystemKind.addedFromLinkBy, 'by': 'Owen', 'name': crewName});
    expect(jay.svc.debugOwesLinkJoin(laptopRid), isFalse);
    // Jay holds Owen as one member, by the device he connected with — and,
    // from the first list, the group's roles as every member holds them.
    final held = jay.svc.groups[crew]!;
    expect(held.memberRids, {laptopRid, mia.svc.myRid});
    expect(held.ownerRid, laptopRid);
    expect(held.adminRids, {laptopRid, mia.svc.myRid});
    expect(jay.svc.mayIssueGroupList(crew, laptopRid), isTrue);
    // Once Jay has Owen's device list — which the laptop hands on, signed by
    // Owen's account — a change Owen makes on his phone, naming himself by
    // the phone, is Owen's.
    await knowsVersion(jay, laptopRid, withLaptop);
    await owen.svc.renameGroup(crew, 'Crew Deck');
    await waitUntil(() => jay.svc.groups[crew]!.name == 'Crew Deck',
        what: 'Jay takes the rename Owen made on his phone');
    final renamed = jay.svc.groups[crew]!;
    expect(renamed.memberRids, {laptopRid, mia.svc.myRid},
        reason: "Owen's phone is Owen, not a second member");
    expect(renamed.ownerRid, laptopRid);
    expect(renamed.adminRids, {laptopRid, mia.svc.myRid});

    // (b) Owen makes a link on his phone; Kim opens it on her laptop.
    final (fromPhone, kimSide) = await ceremony(owen, kimsLaptop, gid: crew);
    expect(kimSide.offersGroup, isTrue);
    await owen.invites.confirm(fromPhone);
    await kimsLaptop.invites.confirm(kimSide);
    final kimRid = kimsLaptop.svc.myRid;
    final others = [owen, owensLaptop, mia, jay];
    await waitUntil(
        () =>
            bannerOf(kimsLaptop, crew, SystemKind.addedFromLinkBy) != null &&
            bannerOf(kim, crew, SystemKind.addedToBy) != null &&
            others.every((p) =>
                p.svc.groups[crew]?.memberRids.contains(kimRid) ?? false),
        what: 'Kim is in the group on both her devices, and a member on '
            'every other');
    // One member for Kim's account — her laptop, which is how Owen holds
    // her; nobody holds her phone as a second member, or a second contact.
    for (final p in others) {
      expect(p.svc.groups[crew]!.memberRids, isNot(contains(kim.svc.myRid)),
          reason: p.svc.displayName);
      expect(p.svc.contacts.containsKey(kim.svc.myRid), isFalse,
          reason: p.svc.displayName);
    }
    // The laptop opened the link, so the laptop went ahead and is told it
    // joined from it. Her phone joined as her account: it says who added
    // her, never owed anyone a go-ahead, and sent none.
    expect(bannerOf(kimsLaptop, crew, SystemKind.addedFromLinkBy)?['by'],
        'Owen');
    expect(kimsLaptop.svc.debugOwesLinkJoin(owen.svc.myRid), isFalse);
    expect(bannerOf(kim, crew, SystemKind.addedFromLinkBy), isNull);
    expect(kim.svc.debugLinkJoinMids, isEmpty);
    for (final k in [kim, kimsLaptop]) {
      final g = k.svc.groups[crew]!;
      expect(g.left, isFalse, reason: k.svc.displayName);
      expect(g.memberRids.intersection({kimRid, kim.svc.myRid}), isEmpty,
          reason: '${k.svc.displayName}: Kim is herself, not a member entry');
      // Owen's list named him by the phone it came from: the id Kim's
      // laptop holds him under, and the one her phone is told of.
      expect(g.ownerRid, owen.svc.myRid, reason: k.svc.displayName);
      expect(g.adminRids, {owen.svc.myRid, mia.svc.myRid},
          reason: k.svc.displayName);
    }
    expect(bannerOf(owen, crew, SystemKind.linkJoined)?['name'], 'Kim');
  }, timeout: const Timeout(Duration(minutes: 6)));

  test('11. deleting the contact a link record names ends the record, and '
      'nothing of theirs is acted on afterwards', () async {
    final owen = await person('Owen');
    final mia = await person('Mia');
    final jay = await person('Jay');
    final kim = await person('Kim');
    final crew = await groupOf(owen, [mia]);
    final before = owen.svc.groups[crew]!.ver;

    /// Whether [p]'s sealed link records name [rid] at all.
    Future<bool> recordsName(Person p, String rid) async {
      final rows = await p.vault.db
          .query('kv', where: 'k = ?', whereArgs: ['s:group_links']);
      if (rows.isEmpty) return false;
      return (await p.vault.unseal(rows.single['v'] as String)).contains(rid);
    }

    // (a) Owen, the inviter, deletes Jay while waiting for his go-ahead —
    // which Jay sends with his link to the relay down, so it is still in
    // his outbox when Owen deletes him.
    final (link, jaySide) = await ceremony(owen, jay, gid: crew);
    await owen.invites.confirm(link);
    expect(owen.svc.debugAwaitingLinkJoin(jay.svc.myRid), isTrue);
    expect(await recordsName(owen, jay.svc.myRid), isTrue);
    await jay.svc.transport.stop();
    await jay.invites.confirm(jaySide);
    expect(jay.svc.debugLinkJoinMids, hasLength(1));
    await owen.svc.deleteContact(jay.svc.myRid);
    expect(owen.svc.debugAwaitingLinkJoin(jay.svc.myRid), isFalse);
    expect(await recordsName(owen, jay.svc.myRid), isFalse,
        reason: 'the record went with the contact');
    // The go-ahead arrives after all, from someone Owen no longer holds:
    // dropped before anything reads it as a go-ahead, and nobody is added.
    expect(await carry(jay, owen), greaterThan(0));
    expect(owen.svc.debugLinkJoinsRead[jay.svc.myRid], isNull);
    expect(owen.svc.groups[crew]!.ver, before, reason: 'no list was issued');
    expect(memberOf(owen, crew, jay), isFalse);
    expect(await contactRows(owen), isNot(contains(jay.svc.myRid)));
    expect(await contactRows(mia), isNot(contains(jay.svc.myRid)));

    // (b) Kim, the joiner, goes ahead first — her go-ahead reaches Owen,
    // who has not, as a stranger's — and then deletes Owen while she still
    // owes it to him.
    final (link2, kimSide) = await ceremony(owen, kim, gid: crew);
    await kim.invites.confirm(kimSide);
    expect(kim.svc.debugOwesLinkJoin(owen.svc.myRid), isTrue);
    expect(await recordsName(kim, owen.svc.myRid), isTrue);
    await kim.svc.deleteContact(owen.svc.myRid);
    expect(kim.svc.debugOwesLinkJoin(owen.svc.myRid), isFalse);
    expect(await recordsName(kim, owen.svc.myRid), isFalse,
        reason: 'the record went with the contact');
    // Owen goes ahead now, with his link down. His hello is what Kim's app
    // would have answered with her go-ahead again; it reaches someone who
    // no longer holds him, and is answered with nothing.
    await owen.svc.transport.stop();
    await owen.invites.confirm(link2);
    expect(owen.svc.debugAwaitingLinkJoin(kim.svc.myRid), isTrue);
    expect(await carry(owen, kim), greaterThan(0));
    expect(kim.svc.debugLinkJoinMids, hasLength(1),
        reason: 'the go-ahead is not sent again');
    expect(kim.svc.groups, isEmpty);
    // Owen's wait ends with the link's day, as for anyone who never goes
    // ahead — and his group says so.
    owen.svc.debugLinkClock = dayLater;
    await owen.svc.debugSweepLinks();
    expect(owen.svc.debugAwaitingLinkJoin(kim.svc.myRid), isFalse);
    expect(bannerOf(owen, crew, SystemKind.linkExpired)?['name'], 'Kim');
    expect(owen.svc.groups[crew]!.ver, before, reason: 'no list was issued');
    expect(memberOf(owen, crew, kim), isFalse);
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('12. a go-ahead answers the ceremony it was given on, and no other',
      () async {
    final owen = await person('Owen');
    final mia = await person('Mia');
    final jay = await person('Jay');
    final kim = await person('Kim');
    final crew = await groupOf(owen, [mia]);
    final deck = await owen.svc.createGroup('Secret Deck', [mia.svc.myRid]);
    await waitUntil(() => mia.svc.groups.containsKey(deck),
        what: 'Mia holds the second group');

    // (a) Jay goes ahead on a link to Crew Quarters; Owen stops it.
    final (a, jayA) = await ceremony(owen, jay, gid: crew);
    await jay.invites.confirm(jayA);
    expect(jay.svc.debugOwesLinkJoin(owen.svc.myRid), isTrue);
    final tagA = await jayA.run.session!.goAheadTag();
    await owen.invites.mismatch(a);
    // A second link, to Secret Deck. Jay is told again, and this time he
    // stops — which touches nothing of the first: the identity a stopped
    // ceremony revealed is one nobody verified, so the answer he gave the
    // first link is still owed, with the first link's tag.
    final (b, jayB) = await ceremony(owen, jay, gid: deck);
    expect(jayB.offersGroup, isTrue);
    expect(await jayB.run.session!.goAheadTag(), isNot(tagA),
        reason: 'another ceremony, another tag');
    await jay.invites.mismatch(jayB);
    expect(jay.svc.debugOwesLinkJoin(owen.svc.myRid), isTrue,
        reason: 'stopping one ceremony touches no answer owed from another');
    // Owen goes ahead on the second link and speaks first. Jay's client
    // answers his hello with the answer it still owes — the first link's —
    // and Owen reads it, and it adds nobody: it answers another ceremony.
    final read = owen.svc.debugLinkJoinsRead[jay.svc.myRid] ?? 0;
    await owen.invites.confirm(b);
    expect(owen.svc.debugAwaitingLinkJoin(jay.svc.myRid), isTrue);
    await waitUntil(
        () => (owen.svc.debugLinkJoinsRead[jay.svc.myRid] ?? 0) > read,
        what: "Owen reads the answer Jay still owes from the first link");
    expect(owen.svc.pendingLinkJoins.map((w) => w.rid),
        contains(jay.svc.myRid),
        reason: 'still waiting, for an answer to this link');
    expect(memberOf(owen, deck, jay), isFalse);
    expect(await contactRows(mia), isNot(contains(jay.svc.myRid)));

    // (b) Kim goes ahead on a link to Crew Quarters with her link to the
    // relay down, and Owen, waiting, deletes her before it arrives: the
    // answer she owes him stays owed. On a second link, to Secret Deck, she
    // never answers at all; Owen goes ahead, and his hello is answered with
    // the first link's go-ahead — read, and adding nobody.
    final (c, kimC) = await ceremony(owen, kim, gid: crew);
    await owen.invites.confirm(c);
    await kim.svc.transport.stop();
    await kim.invites.confirm(kimC);
    await owen.svc.deleteContact(kim.svc.myRid);
    expect(await carry(kim, owen), greaterThan(0),
        reason: 'what she said reaches someone who no longer holds her');
    kim.svc.transport.start();
    expect(kim.svc.debugOwesLinkJoin(owen.svc.myRid), isTrue);
    final (d, kimD) = await ceremony(owen, kim, gid: deck);
    expect(kimD.answered, isFalse);
    final readKim = owen.svc.debugLinkJoinsRead[kim.svc.myRid] ?? 0;
    await owen.invites.confirm(d);
    await waitUntil(
        () => (owen.svc.debugLinkJoinsRead[kim.svc.myRid] ?? 0) > readKim,
        what: "Kim's client answers Owen's hello with the first go-ahead");
    expect(owen.svc.debugAwaitingLinkJoin(kim.svc.myRid), isTrue,
        reason: 'Owen still waits for an answer to the second link');
    expect(memberOf(owen, deck, kim), isFalse);
    expect(memberOf(owen, crew, kim), isFalse);
    expect(await contactRows(mia), isNot(contains(kim.svc.myRid)));
  }, timeout: const Timeout(Duration(minutes: 6)));

  testWidgets('13. a joiner can connect without joining, and the inviter is '
      'told that is what they chose', (t) async {
    late Person owen, mia, jay;
    late String crew;
    late PendingInvite link, jaySide;
    await t.runAsync(() async {
      owen = await person('Owen');
      mia = await person('Mia');
      jay = await person('Jay');
      crew = await groupOf(owen, [mia]);
      (link, jaySide) = await ceremony(owen, jay, gid: crew);
      await owen.invites.confirm(link);
    });
    final l = AppLocalizationsEn();

    // Jay turns "Also join the group" off; his screen says what that means.
    await t.pumpWidget(screen(jay, ConnectConfirmPanel(invite: jaySide)));
    await t.pumpAndSettle();
    final join = find.byKey(const ValueKey('connect-join-group'));
    expect(find.text(l.connectJoinGroupOff('Owen')), findsNothing);
    await t.tap(join);
    await t.pumpAndSettle();
    expect(t.widget<SwitchListTile>(join).value, isFalse);
    expect(find.text(l.connectJoinGroupOff('Owen')), findsOneWidget);

    // "They match": a contact, verified — and not the group.
    // The tap's own work runs on this test's clock, which no socket should
    // be opened under: Jay's link is down while it runs, so his answer is
    // written to his outbox, and it goes when his link is back — in real
    // time, below.
    await t.runAsync(() => jay.svc.transport.stop());
    await t.tap(find.text(l.connectMatch));
    await settleUntil(t, () => jaySide.answered, what: 'Jay answers');
    // The answer's own line has its time on screen, on that clock.
    await t.pump(const Duration(seconds: 10));
    await t.pumpWidget(const SizedBox.shrink());
    await t.runAsync(() async {
      jay.svc.transport.start();
      await waitUntil(
          () => bannerOf(owen, crew, SystemKind.linkDeclined) != null,
          what: "Owen's group says Jay chose not to join");
    });

    expect(bannerOf(owen, crew, SystemKind.linkDeclined)?['name'], 'Jay');
    expect(owen.svc.debugAwaitingLinkJoin(jay.svc.myRid), isFalse,
        reason: 'an answer, not a lapse: nothing is waited for any more');
    expect(bannerOf(owen, crew, SystemKind.linkExpired), isNull);
    expect(owen.svc.contacts[jay.svc.myRid], isNotNull);
    expect(jay.svc.contacts[owen.svc.myRid]!.verified, isTrue,
        reason: 'the digits were compared, group or no group');
    expect(memberOf(owen, crew, jay), isFalse);
    expect(memberOf(mia, crew, jay), isFalse);
    expect(await t.runAsync(() => contactRows(mia)),
        isNot(contains(jay.svc.myRid)));
    expect(jay.svc.groups, isEmpty);
  }, timeout: const Timeout(Duration(minutes: 4)));

  test('14. someone already a contact goes ahead on a group link like '
      'anyone, and nothing is said for them before they answer', () async {
    final owen = await person('Owen');
    final mia = await person('Mia');
    final jay = await person('Jay');
    final kim = await person('Kim');
    final crew = await groupOf(owen, [mia]);
    await waitUntil(
        () => [jay, kim].every((p) => p.svc.transport.isConnected),
        what: 'the joiners connect');

    // (a) Jay once scanned Owen's code: he holds Owen, and Owen holds a
    // request from him, not a contact.
    await jay.svc.addContactFromCode(await owen.svc.myContactCode());
    final jays = await saved(jay, owen.svc.myRid);
    expect(owen.svc.contacts.containsKey(jay.svc.myRid), isFalse);
    final (link, jaySide) = await ceremony(owen, jay, gid: crew);
    expect(jaySide.offersGroup, isTrue);
    // At the digits, before Jay answers: nothing said, nothing owed — though
    // his client already has a session it could say it over.
    expect(jay.svc.debugLinkJoinMids, isEmpty);
    expect(jay.svc.debugOwesLinkJoin(owen.svc.myRid), isFalse);
    await owen.invites.confirm(link);
    await jay.invites.confirm(jaySide);
    expect(jaySide.peerWasHeld, isTrue);
    await waitUntil(
        () =>
            bannerOf(jay, crew, SystemKind.addedFromLinkBy) != null &&
            memberOf(owen, crew, jay) &&
            memberOf(mia, crew, jay),
        what: 'Jay joins');
    // The contact he held is as it was: the comparison, run at a distance,
    // neither marks an existing record as compared nor replaces it.
    expect(await saved(jay, owen.svc.myRid), jays);

    // (b) Owen once scanned Kim's code: he holds her. He goes ahead on his
    // link with the contact he has, and she joins when she does.
    await owen.svc.addContactFromCode(await kim.svc.myContactCode());
    final owensKim = await saved(owen, kim.svc.myRid);
    final (link2, kimSide) = await ceremony(owen, kim, gid: crew);
    await owen.invites.confirm(link2);
    expect(link2.peerWasHeld, isTrue);
    expect(owen.svc.debugAwaitingLinkJoin(kim.svc.myRid), isTrue);
    expect(await saved(owen, kim.svc.myRid), owensKim,
        reason: "Owen's record of Kim is as it was");
    await kim.invites.defer(kimSide);
    expect(kimSide.peerWasHeld, isFalse);
    await waitUntil(
        () =>
            kim.svc.groups.containsKey(crew) &&
            memberOf(owen, crew, kim) &&
            memberOf(mia, crew, kim),
        what: 'Kim joins');
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('15. a go-ahead read just before the app stopped adds its joiner at '
      'the next start', () async {
    var owen = await person('Owen');
    final mia = await person('Mia');
    final jay = await person('Jay');
    final crew = await groupOf(owen, [mia]);
    final (link, jaySide) = await ceremony(owen, jay, gid: crew);
    await owen.invites.confirm(link);
    // Owen's app will stop between reading Jay's go-ahead and acting on it.
    owen.svc.debugHoldLinkAdds = true;
    await jay.invites.confirm(jaySide);
    await waitUntil(
        () =>
            (owen.svc.debugLinkJoinsRead[jay.svc.myRid] ?? 0) > 0 &&
            owen.svc.pendingLinkJoins.isEmpty,
        what: "Owen's device records Jay's go-ahead");
    expect(owen.svc.debugAwaitingLinkJoin(jay.svc.myRid), isTrue,
        reason: 'recorded, and not acted on');
    expect(memberOf(owen, crew, jay), isFalse);
    // Jay's link down, so nothing he says can set the add off after the
    // restart: only the start itself can. And Owen's outbox empty first, so
    // the app that stops has nothing left half-written.
    await jay.svc.transport.stop();
    await settled([owen]);
    owen = await restart(owen);
    await waitUntil(
        () => memberOf(owen, crew, jay) && memberOf(mia, crew, jay),
        what: 'the next start adds Jay');
    expect(owen.svc.debugAwaitingLinkJoin(jay.svc.myRid), isFalse);
  }, timeout: const Timeout(Duration(minutes: 4)));

  test('16. what a join adds on the wire: the go-ahead once to three times, '
      'by who answers first and who opens the session', () async {
    final counts = <String>[];
    for (final joinerInitiates in [true, false]) {
      for (final joinerFirst in [true, false]) {
        final owen = await person('Owen');
        final mia = await person('Mia');
        final jay = await person('Jay',
            identity: await identityWhere((rid) => joinerInitiates
                ? rid.compareTo(owen.svc.myRid) < 0
                : rid.compareTo(owen.svc.myRid) > 0));
        final crew = await groupOf(owen, [mia]);
        final (link, jaySide) = await ceremony(owen, jay, gid: crew);
        if (joinerFirst) {
          await jay.invites.defer(jaySide);
          await owen.invites.defer(link);
        } else {
          await owen.invites.defer(link);
          await jay.invites.defer(jaySide);
        }
        await waitUntil(
            () => memberOf(mia, crew, jay) && jay.svc.groups.containsKey(crew),
            what: 'Jay joins');
        await settled([owen, jay]);
        final sent = jay.svc.debugLinkJoinMids.length;
        final read = owen.svc.debugLinkJoinsRead[jay.svc.myRid] ?? 0;
        counts.add('joiner opens the session: $joinerInitiates, joiner '
            'answers first: $joinerFirst — go-aheads sent $sent, read $read');
        expect(sent, inInclusiveRange(1, 3));
        expect(read, inInclusiveRange(1, sent));
        expect(jay.svc.debugOwesLinkJoin(owen.svc.myRid), isFalse,
            reason: 'nothing more is owed once the group has come');
      }
    }
    // ignore: avoid_print
    print(counts.join('\n'));
  }, timeout: const Timeout(Duration(minutes: 8)));

  testWidgets('17. the inviter sees whom it is waiting for, and can stop',
      (t) async {
    late Person owen, mia, jay;
    late String crew;
    late PendingInvite link, jaySide;
    await t.runAsync(() async {
      owen = await person('Owen');
      mia = await person('Mia');
      jay = await person('Jay');
      crew = await groupOf(owen, [mia]);
      (link, jaySide) = await ceremony(owen, jay, gid: crew);
      await owen.invites.confirm(link);
    });
    final l = AppLocalizationsEn();
    await t.pumpWidget(screen(owen, const ConnectLinkWaits()));
    await t.pumpAndSettle();
    expect(find.text(l.connectLinkWaitsTitle), findsOneWidget);
    expect(find.text(l.connectLinkWait('Jay', crewName)), findsOneWidget);

    await t.tap(find.text(l.connectLinkWaitStop));
    await settleUntil(
        t,
        () =>
            bannerOf(owen, crew, SystemKind.linkCancelled) != null &&
            find.text(l.connectLinkWaitsTitle).evaluate().isEmpty,
        what: 'Owen stops waiting, and the screen and the group say so');
    expect(owen.svc.debugAwaitingLinkJoin(jay.svc.myRid), isFalse);
    expect(bannerOf(owen, crew, SystemKind.linkCancelled)?['name'], 'Jay');

    // Jay goes ahead after all: his go-ahead is read, and adds nobody.
    await t.runAsync(() async {
      await jay.invites.confirm(jaySide);
      await waitUntil(
          () => (owen.svc.debugLinkJoinsRead[jay.svc.myRid] ?? 0) > 0,
          what: "Owen reads Jay's go-ahead");
    });
    await t.pumpWidget(const SizedBox.shrink());
    expect(memberOf(owen, crew, jay), isFalse);
    expect(memberOf(mia, crew, jay), isFalse);
    expect(owen.svc.contacts[jay.svc.myRid], isNotNull,
        reason: 'still a contact');
  }, timeout: const Timeout(Duration(minutes: 4)));

  test('18. an answer cut short after its add finishes when it is given '
      'again', () async {
    final owen = await person('Owen');
    final mia = await person('Mia');
    final jay = await person('Jay');
    final crew = await groupOf(owen, [mia]);
    final (link, jaySide) = await ceremony(owen, jay, gid: crew);
    await owen.invites.confirm(link);
    // Jay presses "they match", and his app is killed between adding Owen
    // and the rest: no tick, no go-ahead, the invite still at the digits.
    jay.invites.debugStopAfterAdd = true;
    await expectLater(jay.invites.confirm(jaySide), throwsStateError);
    expect(jay.svc.contacts[owen.svc.myRid], isNotNull);
    expect(jay.svc.contacts[owen.svc.myRid]!.verified, isFalse);
    expect(jay.svc.debugLinkJoinMids, isEmpty);
    // The app again: the invite is read back from the vault, still at the
    // digits, and the same answer given again finishes it — as this
    // answer's own contact, so the tick lands, and the go-ahead goes.
    final again = ConnectInvites(jay.svc);
    await again.load();
    final pending = again.invites.single;
    expect(pending.added, isTrue);
    expect(pending.sas, jaySide.sas);
    await again.confirm(pending);
    expect(pending.peerWasHeld, isFalse,
        reason: 'the contact is the one this answer added, not one held '
            'from before');
    expect(jay.svc.contacts[owen.svc.myRid]!.verified, isTrue);
    await waitUntil(
        () => jay.svc.groups.containsKey(crew) && memberOf(mia, crew, jay),
        what: 'Jay joins');
  }, timeout: const Timeout(Duration(minutes: 4)));

  testWidgets('19. the join switch belongs to its own panel', (t) async {
    late Person owen, mia, jay;
    late String crew, deck;
    late PendingInvite l1, j1, j2;
    await t.runAsync(() async {
      owen = await person('Owen');
      mia = await person('Mia');
      jay = await person('Jay');
      crew = await groupOf(owen, [mia]);
      deck = await owen.svc.createGroup('Deck Two', [mia.svc.myRid]);
      await waitUntil(() => mia.svc.groups.containsKey(deck),
          what: 'Mia holds the second group');
      (l1, j1) = await ceremony(owen, jay, gid: crew);
      (_, j2) = await ceremony(owen, jay, gid: deck);
      await owen.invites.confirm(l1);
    });
    expect(j1.offersGroup && j2.offersGroup, isTrue);
    final l = AppLocalizationsEn();
    await t.pumpWidget(screen(jay, const ConnectTab()));
    await t.pumpAndSettle();
    final switches = find.byKey(const ValueKey('connect-join-group'));
    expect(switches, findsNWidgets(2));
    final panels = find.byType(ConnectConfirmPanel);
    expect(t.widget<ConnectConfirmPanel>(panels.first).invite.id, j1.id);
    // Jay turns "Also join the group" off on the Crew link's panel.
    await t.ensureVisible(switches.first);
    await t.pumpAndSettle();
    await t.tap(switches.first);
    await t.pumpAndSettle();
    expect(t.widget<SwitchListTile>(switches.first).value, isFalse);
    expect(t.widget<SwitchListTile>(switches.last).value, isTrue);
    // He answers the other link, and its panel goes.
    await t.runAsync(() => jay.invites.defer(j2));
    await t.pump();
    await t.pumpAndSettle();
    expect(switches, findsOneWidget);
    expect(t.widget<ConnectConfirmPanel>(panels).invite.id, j1.id);
    expect(t.widget<SwitchListTile>(switches).value, isFalse,
        reason: 'the switch Jay turned off on this panel is still off');
    expect(find.text(l.connectJoinGroupOff('Owen')), findsOneWidget);
    // And "they match" on it does what the switch says: a contact, not
    // Crew. The tap's work runs on this test's clock, with Jay's link down
    // under it; his answer goes when the link is back, in real time.
    await t.runAsync(() => jay.svc.transport.stop());
    await t.ensureVisible(find.text(l.connectMatch));
    await t.pumpAndSettle();
    await t.tap(find.text(l.connectMatch));
    await settleUntil(t, () => j1.answered, what: 'Jay answers the Crew link');
    await t.pump(const Duration(seconds: 10));
    await t.pumpWidget(const SizedBox.shrink());
    await t.runAsync(() async {
      jay.svc.transport.start();
      await waitUntil(
          () => bannerOf(owen, crew, SystemKind.linkDeclined) != null,
          what: "Owen's Crew says Jay chose not to join it");
    });
    expect(memberOf(owen, crew, jay), isFalse);
    expect(memberOf(mia, crew, jay), isFalse);
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('20. an ordinary invite between two contacts is still refused, and '
      'changes nothing', () async {
    final owen = await person('Owen');
    final jay = await person('Jay');
    await waitUntil(
        () => [owen, jay].every((p) => p.svc.transport.isConnected),
        what: 'both connect');
    await owen.svc.addContactFromCode(await jay.svc.myContactCode());
    await jay.svc.addContactFromCode(await owen.svc.myContactCode());
    await settled([owen, jay]);
    final owens = await saved(owen, jay.svc.myRid);
    final jays = await saved(jay, owen.svc.myRid);
    final (mine, theirs) = await ceremony(owen, jay);
    expect(theirs.offersGroup, isFalse);
    final refused = throwsA(isA<FormatException>().having(
        (e) => e.message, 'message', contains('already in your contacts')));
    // "They match" on either side: refused, as it always was — a remote
    // ceremony does not re-verify, or replace, a contact already held.
    await expectLater(jay.invites.confirm(theirs), refused);
    await expectLater(owen.invites.confirm(mine), refused);
    expect(theirs.peerWasHeld || mine.peerWasHeld, isFalse);
    expect(await saved(owen, jay.svc.myRid), owens);
    expect(await saved(jay, owen.svc.myRid), jays);
    expect(jay.svc.debugLinkJoinMids, isEmpty);
    expect(owen.svc.debugAwaitingLinkJoin(jay.svc.myRid), isFalse);
    // Both invites are left at the digits, for each person to discard.
    expect(jay.invites.invites.map((i) => i.id), contains(theirs.id));
    expect(owen.invites.invites.map((i) => i.id), contains(mine.id));
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('21. stopping a ceremony touches no answer owed from another', () async {
    final owen = await person('Owen');
    final mia = await person('Mia');
    final jay = await person('Jay');
    final crew = await groupOf(owen, [mia]);
    // Owen's real link. Jay answers first, with his link down; his answer is
    // handed to Owen, who does not hold him yet, and dropped: he owes it
    // until Owen speaks.
    final (a, jayA) = await ceremony(owen, jay, gid: crew);
    await jay.svc.transport.stop();
    await jay.invites.confirm(jayA);
    expect(await carry(jay, owen), greaterThan(0));
    jay.svc.transport.start();
    await waitUntil(() => jay.svc.transport.isConnected, what: 'Jay is back');
    expect(jay.svc.debugOwesLinkJoin(owen.svc.myRid), isTrue);

    // Eve holds Owen's contact code — it is handed out — and makes a link
    // whose ceremony reveals it, with the group bit set. Jay's screen names
    // Owen; the digits match nothing Owen sees, and Jay stops.
    final owenCode = await owen.svc.myContactCode();
    final eve = await ConnectRun.invite(
        me: await ConnectIdentity.fromCode(owenCode, displayName: 'Owen'),
        group: true);
    final jayEve = await jay.invites.open(eve.code.link());
    for (var i = 0; i < 8 && jayEve.sas == null; i++) {
      await eve.step(relayUrl: url, poll: const Duration(milliseconds: 300));
      await jay.invites.pump();
    }
    expect(jayEve.sas, isNotNull, reason: "Jay's client reaches the digits");
    expect(jayEve.offersGroup, isTrue);
    expect(jayEve.peer!.contactCode, owenCode);
    await jay.invites.mismatch(jayEve);
    expect(jay.svc.debugOwesLinkJoin(owen.svc.myRid), isTrue,
        reason: 'a stopped ceremony says nothing about the real Owen');

    // Owen goes ahead on his real link, and speaks first: Jay's client
    // answers with what it owes him, and Jay joins.
    await owen.invites.confirm(a);
    await waitUntil(
        () =>
            memberOf(owen, crew, jay) &&
            memberOf(mia, crew, jay) &&
            jay.svc.groups.containsKey(crew),
        what: 'Jay joins Crew from the link he answered');
    expect(bannerOf(owen, crew, SystemKind.linkExpired), isNull);
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('22. a contact who opens a group link on another of their devices '
      'joins as the contact they are', () async {
    final owen = await person('Owen');
    final mia = await person('Mia');
    final jay = await person('Jay');
    final crew = await groupOf(owen, [mia]);
    await owen.svc.addContactFromCode(await jay.svc.myContactCode());
    await jay.svc.addContactFromCode(await owen.svc.myContactCode());
    await settled([owen, jay]);
    final laptop = await linked(jay, 'Jay');
    // Owen holds the list that names the laptop as Jay's — waited for as the
    // device it names, not as the list's version, which is written down
    // before the device is taken in.
    await waitUntil(
        () =>
            owen.svc.debugListedDeviceOwner(laptop.svc.myRid) ==
            jay.svc.myRid,
        what: "Owen holds Jay's laptop as Jay's, by the list Jay signed");
    final owens = await saved(owen, jay.svc.myRid);

    final (link, lapSide) = await ceremony(owen, laptop, gid: crew);
    expect(lapSide.offersGroup, isTrue);
    await owen.invites.confirm(link);
    // Owen's device knows the laptop as Jay's, by the list Jay's account
    // signed: it waits for Jay, and holds no second contact for him.
    expect(link.peerWasHeld, isTrue);
    expect(owen.svc.contacts.containsKey(laptop.svc.myRid), isFalse);
    expect(owen.svc.debugAwaitingLinkJoin(jay.svc.myRid), isTrue);
    await laptop.invites.confirm(lapSide);
    // The laptop's banner is waited for as itself: a device holds the group
    // a few writes before it has said so.
    await waitUntil(
        () =>
            memberOf(owen, crew, jay) &&
            memberOf(mia, crew, jay) &&
            jay.svc.groups.containsKey(crew) &&
            bannerOf(laptop, crew, SystemKind.addedFromLinkBy) != null,
        what: "Jay's account joins, and both his devices hold the group");
    // The answer the laptop sent was read as Jay's; the account is one
    // member, and Owen's record of Jay is as it was.
    expect(owen.svc.debugLinkJoinsRead[jay.svc.myRid], greaterThan(0));
    for (final p in [owen, mia]) {
      expect(p.svc.groups[crew]!.memberRids,
          isNot(contains(laptop.svc.myRid)), reason: p.svc.displayName);
      expect(p.svc.contacts.containsKey(laptop.svc.myRid), isFalse,
          reason: p.svc.displayName);
    }
    expect(await saved(owen, jay.svc.myRid), owens);
    expect(bannerOf(owen, crew, SystemKind.linkJoined)?['name'], 'Jay');
    expect(bannerOf(laptop, crew, SystemKind.addedFromLinkBy)?['by'], 'Owen');
    expect(owen.svc.debugAwaitingLinkJoin(jay.svc.myRid), isFalse);
  }, timeout: const Timeout(Duration(minutes: 6)));

  test('23. an answer cut short after its add does not tick a record that '
      'has taken its place', () async {
    final owen = await person('Owen');
    final mia = await person('Mia');
    final jay = await person('Jay');
    final crew = await groupOf(owen, [mia]);
    final (link, jaySide) = await ceremony(owen, jay, gid: crew);
    await owen.invites.confirm(link);
    // Jay presses "they match", and his app is killed after adding Owen.
    jay.invites.debugStopAfterAdd = true;
    await expectLater(jay.invites.confirm(jaySide), throwsStateError);
    expect(jay.svc.contacts[owen.svc.myRid], isNotNull);
    // Before he answers again, the contact that answer added is deleted,
    // and Owen is added back another way: by his code, scanned.
    await jay.svc.deleteContact(owen.svc.myRid);
    await jay.svc.addContactFromCode(await owen.svc.myContactCode());
    final jays = await saved(jay, owen.svc.myRid);
    final again = ConnectInvites(jay.svc);
    await again.load();
    final pending = again.invites.single;
    expect(pending.added, isTrue);
    await again.confirm(pending);
    expect(pending.peerWasHeld, isTrue,
        reason: 'the record held now is not the one the answer added');
    expect(await saved(jay, owen.svc.myRid), jays,
        reason: 'and this answer does not tick it as compared');
    // The answer itself still stands: Jay joins.
    await waitUntil(
        () => jay.svc.groups.containsKey(crew) && memberOf(mia, crew, jay),
        what: 'Jay joins');
  }, timeout: const Timeout(Duration(minutes: 4)));

  test('24. two links between the same two people are two waits and two '
      'answers', () async {
    final owen = await person('Owen');
    final mia = await person('Mia');
    final jay = await person('Jay');
    final crew = await groupOf(owen, [mia]);
    final deck = await owen.svc.createGroup('Deck Two', [mia.svc.myRid]);
    final third = await owen.svc.createGroup('Third Watch', [mia.svc.myRid]);
    await waitUntil(
        () => [deck, third].every(mia.svc.groups.containsKey),
        what: 'Mia holds the other groups');

    // (a) Two links. Jay answers both before Owen has gone ahead on either:
    // each answer is owed, with its own tag, and each wait Owen then starts
    // is its own — so both add him.
    final (l1, j1) = await ceremony(owen, jay, gid: crew);
    final (l2, j2) = await ceremony(owen, jay, gid: deck);
    await jay.invites.confirm(j1);
    await jay.invites.defer(j2);
    await owen.invites.confirm(l1);
    await owen.invites.defer(l2);
    await waitUntil(
        () => memberOf(mia, crew, jay) && memberOf(mia, deck, jay),
        what: 'Jay joins both groups');
    expect(bannerOf(owen, crew, SystemKind.linkJoined)?['name'], 'Jay');
    expect(bannerOf(owen, deck, SystemKind.linkJoined)?['name'], 'Jay');

    // (b) A go-ahead read and not yet acted on stays read when Owen goes
    // ahead on another link with Jay.
    final (l3, j3) = await ceremony(owen, jay, gid: third);
    final (l4, _) = await ceremony(owen, jay, gid: third);
    owen.svc.debugHoldLinkAdds = true;
    await owen.invites.confirm(l3);
    final third3 = owen.svc.pendingLinkJoins.single.id;
    await jay.invites.confirm(j3);
    await waitUntil(
        () => !owen.svc.pendingLinkJoins.any((w) => w.id == third3),
        what: "Owen's device reads Jay's go-ahead for the third link");
    await owen.invites.confirm(l4);
    expect(owen.svc.pendingLinkJoins.map((w) => w.id),
        isNot(contains(third3)),
        reason: 'the go-ahead read for the third link is still read');
    owen.svc.debugHoldLinkAdds = false;
    await owen.svc.debugFinishLinkAdds();
    await waitUntil(() => memberOf(mia, third, jay), what: 'Jay joins Third');
  }, timeout: const Timeout(Duration(minutes: 6)));

  testWidgets('25. "Stop waiting" stops a go-ahead already read; once the add '
      'has begun, the screen says it is too late', (t) async {
    late Person owen, mia, jay, kim;
    late String crew, jayWait, kimWait;
    late PendingInvite kimSide;
    await t.runAsync(() async {
      owen = await person('Owen');
      mia = await person('Mia');
      jay = await person('Jay');
      kim = await person('Kim');
      crew = await groupOf(owen, [mia]);
      final (lj, jaySide) = await ceremony(owen, jay, gid: crew);
      final (lk, ks) = await ceremony(owen, kim, gid: crew);
      kimSide = ks;
      await owen.invites.confirm(lj);
      await owen.invites.confirm(lk);
      jayWait = owen.svc.pendingLinkJoins
          .singleWhere((w) => w.rid == jay.svc.myRid)
          .id;
      kimWait = owen.svc.pendingLinkJoins
          .singleWhere((w) => w.rid == kim.svc.myRid)
          .id;
      // (a) Jay's go-ahead is read, and not yet acted on: stopping the wait
      // still stops it.
      owen.svc.debugHoldLinkAdds = true;
      await jay.invites.confirm(jaySide);
      await waitUntil(
          () => !owen.svc.pendingLinkJoins.any((w) => w.id == jayWait),
          what: "Owen's device reads Jay's go-ahead");
      expect(await owen.svc.cancelLinkJoin(jayWait), LinkWaitStop.stopped);
      owen.svc.debugHoldLinkAdds = false;
      await owen.svc.debugFinishLinkAdds();
      expect(bannerOf(owen, crew, SystemKind.linkCancelled)?['name'], 'Jay');
    });
    expect(memberOf(owen, crew, jay), isFalse);
    expect(memberOf(mia, crew, jay), isFalse);

    // (b) Kim's wait is on Owen's screen. Her answer comes, and the add
    // begins, after it was drawn; Owen taps "Stop waiting" on the row still
    // there, and is told it is too late.
    final l = AppLocalizationsEn();
    await t.pumpWidget(screen(owen, const ConnectLinkWaits()));
    await t.pumpAndSettle();
    final row = find.byKey(ValueKey('connect-link-wait-$kimWait'));
    expect(row, findsOneWidget);
    final gate = Completer<void>();
    await t.runAsync(() async {
      owen.svc.debugBeforeLinkAdd = gate;
      await kim.invites.confirm(kimSide);
      await waitUntil(() => owen.svc.debugLinkAdding.contains(kimWait),
          what: "Owen's device begins adding Kim");
    });
    await t.tap(find.descendant(
        of: row, matching: find.text(l.connectLinkWaitStop)));
    await t.pump();
    expect(find.text(l.connectLinkWaitTooLate('Kim', crewName)),
        findsOneWidget);
    // Waited with the test's clock pumped between real waits, as 17 waits
    // after its tap. A wait run wholly inside runAsync left the add stuck at
    // its first write to the vault (`_saveGroups`) until the wait gave up,
    // and only then did the write return.
    gate.complete();
    await settleUntil(
        t, () => memberOf(owen, crew, kim) && memberOf(mia, crew, kim),
        what: 'the add that had begun finishes');
    owen.svc.debugBeforeLinkAdd = null;
    expect(bannerOf(owen, crew, SystemKind.linkJoined)?['name'], 'Kim');
    await t.pumpWidget(const SizedBox.shrink());
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('26. a go-ahead into a full group adds nobody, and the admin is told',
      () async {
    // Owen's routing id sorts after nearly every other, so the members he
    // adds and never starts — real identities, as fanout_bench_test.dart's —
    // are sent nothing: a session is opened by the lower id (§5). Their
    // copies of his lists stay in his queue and are let go once Mia's has
    // left it, so the relay is not handed envelopes nobody will read.
    final owen = await person('Owen',
        identity: await identityWhere((rid) => rid.compareTo('y') > 0));
    final mia = await person('Mia');
    final jay = await person('Jay');
    final crew = await groupOf(owen, [mia]);
    final phantoms = <String>[];
    for (var i = 0; i < 126; i++) {
      final id = await ZIdentity.generate();
      final code = (await id.bundle(displayName: 'p$i')).encode();
      phantoms.add(
          (await owen.svc.addContactFromCode(code, requested: false)).rid);
    }
    owen.svc.debugHoldGroupFanout = (rid, _) => phantoms.contains(rid);
    Future<List<String>> queued() async => [
          for (final r in await owen.vault.db.query('group_fanout'))
            r['rid'] as String
        ];
    Future<void> letGo() async {
      final deadline = DateTime.now().add(const Duration(seconds: 60));
      while (!(await queued()).every(phantoms.contains)) {
        if (DateTime.now().isAfter(deadline)) {
          throw TimeoutException("Mia's copy never left Owen's queue");
        }
        await Future<void>.delayed(const Duration(milliseconds: 40));
      }
      await owen.vault.db.delete('group_fanout',
          where: 'rid IN (${List.filled(phantoms.length, '?').join(',')})',
          whereArgs: phantoms);
    }

    // Owen, Mia and 125 more: 127 accounts, room for one.
    expect(await owen.svc.addGroupMembers(crew, phantoms.sublist(0, 125)),
        isNull);
    await waitUntil(() => mia.svc.groups[crew]!.memberRids.length == 126,
        what: 'Mia holds the list of 127', timeout: const Duration(seconds: 90));
    await letGo();
    expect(owen.svc.groupRoom(crew), 1);

    // Jay answers a link while there is room, and Owen goes ahead: his device
    // waits. Jay's go-ahead is read, and not yet acted on.
    final (link, jaySide) = await ceremony(owen, jay, gid: crew);
    await owen.invites.confirm(link);
    expect(owen.svc.debugAwaitingLinkJoin(jay.svc.myRid), isTrue);
    owen.svc.debugHoldLinkAdds = true;
    await jay.invites.confirm(jaySide);
    await waitUntil(
        () =>
            (owen.svc.debugLinkJoinsRead[jay.svc.myRid] ?? 0) > 0 &&
            owen.svc.pendingLinkJoins.isEmpty,
        what: "Owen's device records Jay's go-ahead");

    // Meanwhile Owen fills the group by hand.
    expect(await owen.svc.addGroupMembers(crew, [phantoms.last]), isNull);
    await waitUntil(() => mia.svc.groups[crew]!.memberRids.length == 127,
        what: 'Mia holds the list of 128', timeout: const Duration(seconds: 90));
    await letGo();
    expect(owen.svc.groupRoom(crew), 0);
    final full = owen.svc.groups[crew]!.ver;

    // The go-ahead is acted on now, and asked again: the group is full.
    owen.svc.debugHoldLinkAdds = false;
    await owen.svc.debugFinishLinkAdds();
    expect(await queued(), isEmpty, reason: 'no list was issued');
    expect(owen.svc.groups[crew]!.ver, full);
    expect(memberOf(owen, crew, jay), isFalse);
    expect(bannerOf(owen, crew, SystemKind.linkFull)?['name'], 'Jay',
        reason: "Owen's group says why Jay was not added");
    expect(bannerOf(owen, crew, SystemKind.linkFull)?['max'],
        ChatService.maxGroupMembers);
    expect(bannerOf(owen, crew, SystemKind.linkJoined), isNull);
    expect(owen.svc.debugAwaitingLinkJoin(jay.svc.myRid), isFalse,
        reason: 'the wait is over');
    expect(owen.svc.contacts.containsKey(jay.svc.myRid), isTrue,
        reason: 'Jay stays a contact');

    // Nothing reached Mia: Owen's next change is her next version. Nor Jay:
    // a text Owen sends him once that change has left the queue comes with
    // no group before it.
    expect(await owen.svc.renameGroup(crew, 'Crew, full'), isNull);
    await waitUntil(() => mia.svc.groups[crew]!.name == 'Crew, full',
        what: 'the rename reaches Mia', timeout: const Duration(seconds: 90));
    expect(mia.svc.groups[crew]!.ver, full + 1);
    expect(memberOf(mia, crew, jay), isFalse);
    expect(await contactRows(mia), isNot(contains(jay.svc.myRid)));
    await letGo();
    await owen.svc.sendText(jay.svc.myRid, 'the crew is full');
    await waitUntil(
        () => (jay.svc.messagesByChat[owen.svc.myRid] ?? const <ChatMessage>[])
            .any((m) => m.body == 'the crew is full'),
        what: "Jay reads Owen's text");
    expect(jay.svc.groups.containsKey(crew), isFalse);
  }, timeout: const Timeout(Duration(minutes: 6)));
}
