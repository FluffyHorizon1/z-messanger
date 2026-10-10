// 23.4–23.5 — disappearing messages in a group, and a leaver who stays gone
// (ADR 0030, PROTOCOL §11.2).
//
// A group's timer is part of its list, as its name is: set by whoever may
// change the group, carried to every member, and stamped by every device of
// every member on what it sends afterwards (§6.1's `ttl`). And a leave is
// remembered, with the position of the membership it ends, so that a list
// issued before the leave reached its issuer — which still names the leaver
// — is taken without them, until a list adds them back at a later position.
//
// REAL ChatService instances over the REAL Node relay, as group_roles_test
// runs them; a member's linked laptop is enrolled as linked_kinds_test
// enrols one. Where a test needs a client that does what this app will not,
// it sends the inner message itself (`debugSendRawInner`), and a member on a
// build from before ADR 0030 is this build with `debugBuildBefore0030` set.
//
// Criteria, each a test below:
//   1. a co-admin sets the group's timer and every device of every member —
//      a linked laptop included — takes it, with the notice; every group
//      message sent afterwards, text or file, from the owner, a plain member
//      or the laptop, carries it: the sender's copy, and its mirror on the
//      sender's other device, go that long after it was sent, every other
//      copy that long after it arrived; one sent before the timer never
//      goes; and with the timer shortened, the sweeper takes each copy on
//      every device at its time and not before;
//   2. only an admin sets it: a plain member's attempt issues nothing, and a
//      list a plain member makes with a timer is refused by every member; an
//      admin turning it off says so, and what is sent afterwards is kept;
//   3. a member on a build from before group timers keeps every message and
//      sends without a timer, and the notice every other member reads says
//      exactly that, in both languages; a list from an admin on such a build
//      turns the timer off, and is said as what it did — and, naming nobody
//      at a position, takes a member who left and was added back out of the
//      group on every device that remembers the leave, theirs included (the
//      limit ADR 0030 states);
//   4. two admins setting two timers at one version end, on every device, on
//      the timer whose list's state digest sorts first, and the other is
//      told its change did not stand;
//   5. a co-admin's list issued before a member's leave reached her does not
//      put the leaver back: every device takes its change without them, the
//      leaver's own device stays out of the group, and nothing sent there
//      afterwards is queued for the leaver;
//   6. an admin who adds the leaver back after the leave does put them back
//      — on every device, the leaver's own included, which says who added
//      them — naming them at the position of that list; a member that never
//      got that list takes them from the next one built on it; and the
//      member is heard by everyone again;
//   7. the timer and the leaves a device heard survive its restart, and a
//      list issued before the leave is still taken without the leaver after
//      it; deleting the leaver's contact lets go of their leave, so the
//      group's record names them nowhere; and someone added to the group
//      afterwards holds its timer and is told of it as they arrive;
//   8. a list's timer and its members' positions, the state digest that
//      ranks two lists §11.1's digest calls equal, and the timer, position
//      and `ttl` members of `ginvite`, `gleave` and `gmsg` are the ones
//      `docs/vectors/v1/group_state.json` records;
//   9. what a position costs: a group grown one member at a time sends a
//      list at most thirteen bytes a member longer than the same group made
//      with all of them — at most one 256-byte padding block on the wire,
//      up to fourteen members — every size measured and printed;
//  10. a leave that reaches a device after the list adding its leaver back
//      takes nobody out: a member that took that list first keeps them, and
//      so does the leaver's own laptop, which took it before the copy of its
//      phone's leave; the next list keeps them everywhere, and they are heard;
//  11. the owner's list issued before a leave, at the version of a co-admin's
//      list adding the leaver back, outranks it on every device — the
//      leaver's own included, which takes the owner's list without itself,
//      saying nothing, and so does not take the co-admin's either; the
//      co-admin is told, and adding the leaver back on top of the list
//      everyone holds does put them back.
@Tags(['integration'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/foundation.dart' show debugPrint;
import 'package:flutter/widgets.dart' show Locale;
import 'package:flutter_test/flutter_test.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/models.dart';
import 'package:zapp/core/system_messages.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/l10n/app_localizations.dart';
import 'package:zapp/l10n/system_text.dart';

int now() => DateTime.now().millisecondsSinceEpoch;

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
        environment: {
          'PORT': '$port',
          'LOG_LEVEL': 'silent',
          'METRICS_TOKEN': 'z-apptest-metrics',
        });
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

  Future<Directory> dirFor(String name) async =>
      dirs[name] ??
      await Directory.systemTemp.createTemp('z_gtm_').then((d) {
        temps.add(d);
        return dirs[name] = d;
      });

  /// A client named [name]; the same name again reopens the same vault.
  Future<ChatService> start(String name) async {
    final vault = await Vault.open(rootOverride: await dirFor(name));
    final stored = await vault.kvGet('identity');
    final id = stored == null
        ? await ZIdentity.generate()
        : await ZIdentity.fromJson(
            (jsonDecode(stored) as Map).cast<String, Object?>());
    if (stored == null) await vault.kvPut('identity', jsonEncode(id.toJson()));
    final svc = await ChatService.init(
        vault: vault,
        identity: id,
        displayName: name,
        transport: Transport(identity: id, serverUrl: 'ws://127.0.0.1:$port'));
    live.add(svc);
    return svc;
  }

  Future<void> stop(ChatService s) async {
    s.dispose();
    await s.transport.stop();
    live.remove(s);
    await s.vault.db.close();
  }

  Future<void> waitUntil(FutureOr<bool> Function() cond,
      {Duration timeout = const Duration(seconds: 40),
      required String what}) async {
    final deadline = DateTime.now().add(timeout);
    while (!await cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
  }

  Future<int> metric(String name) async {
    // /metrics is token-gated (P1-14): the relay is spawned with
    // METRICS_TOKEN set to this value above.
    final req =
        await HttpClient().getUrl(Uri.parse('http://127.0.0.1:$port/metrics'));
    req.headers.set('authorization', 'Bearer z-apptest-metrics');
    final res = await req.close();
    final text = await res.transform(utf8.decoder).join();
    if (res.statusCode != 200) {
      throw StateError('/metrics answered HTTP ${res.statusCode}');
    }
    for (final line in const LineSplitter().convert(text)) {
      if (line.startsWith('$name ')) {
        return int.parse(line.substring(name.length + 1).trim());
      }
    }
    return -1;
  }

  /// Nothing left anywhere: no client has an envelope or a group fan-out row
  /// still to send, and the relay holds nothing undelivered (as `quiet` in
  /// linked_kinds_test). Read three times running, because processing one
  /// envelope can queue another.
  Future<void> quiet(List<ChatService> all,
      {required String what,
      Duration timeout = const Duration(seconds: 90)}) async {
    var calm = 0;
    await waitUntil(() async {
      for (final s in all) {
        await s.flushOutbox();
        if ((await s.vault.db.query('outbox', limit: 1)).isNotEmpty ||
            (await s.vault.db.query('group_fanout', limit: 1)).isNotEmpty) {
          calm = 0;
          return false;
        }
      }
      if (await metric('z_queued_envelopes') != 0) {
        calm = 0;
        return false;
      }
      return ++calm >= 3;
    }, timeout: timeout, what: what);
  }

  /// [all] have nothing left to send — no envelope in an outbox, no group
  /// fan-out row — read three times running: [quiet] without the relay's
  /// count, which a client an earlier test took offline (9 stops Owen9's
  /// transport) keeps above zero for the rest of the file.
  Future<void> drained(List<ChatService> all, {required String what}) async {
    var calm = 0;
    await waitUntil(() async {
      for (final s in all) {
        await s.flushOutbox();
        if ((await s.vault.db.query('outbox', limit: 1)).isNotEmpty ||
            (await s.vault.db.query('group_fanout', limit: 1)).isNotEmpty) {
          calm = 0;
          return false;
        }
      }
      return ++calm >= 3;
    }, timeout: const Duration(seconds: 90), what: what);
  }

  /// Clients that just added each other have finished introducing
  /// themselves (as `settled` in replies_test.dart): each holds the other's
  /// post-quantum key, and nobody has anything left to hand over.
  Future<void> settled(List<ChatService> all) async {
    await waitUntil(() async {
      for (final s in all) {
        for (final o in all) {
          if (identical(s, o)) continue;
          final c = s.contacts[o.myRid];
          if (c == null) continue;
          if (c.pqPub == null && c.pqCandidate == null) return false;
        }
      }
      for (final s in all) {
        if ((await s.vault.db.query('outbox', limit: 1)).isNotEmpty) {
          return false;
        }
      }
      return all.every((s) => !s.pqSendPending);
    }, what: 'the contacts settled');
  }

  Future<void> befriend(ChatService a, ChatService b) async {
    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());
  }

  /// A laptop linked to [main]'s account as linked_kinds_test links one: its
  /// own keys, the account's certificate for them and the account's
  /// post-quantum key, holding [knows] as contacts from the start, and then
  /// listed by [main], which tells its contacts.
  Future<ChatService> laptopOf(
      ChatService main, String name, List<ChatService> knows) async {
    final devId = await ZIdentity.generate();
    final account = await main.accountIdentity();
    final cert = await account.signDeviceCert(
        deviceEdPub: devId.edPub, deviceXPub: devId.xPub, deviceId: name);
    final vault = await Vault.open(rootOverride: await dirFor(name));
    await vault.kvPut('identity', jsonEncode(devId.toJson()));
    final enrolled = await AccountIdentity.fromEnrollment(
      accountEdPub: account.accountEdPub,
      accountMlPub: await main.pqAccountPublic(),
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
    for (final k in knows) {
      // No contact request: an enrolment hands contacts over and asks nobody.
      await svc.addContactFromCode(await k.myContactCode(), requested: false);
    }
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

  /// Wait until every one of [all] holds [gid] with the timer [sec].
  Future<void> atTimer(List<ChatService> all, String gid, int sec) =>
      waitUntil(() => all.every((s) => s.groups[gid]?.ttlSec == sec),
          what: 'every device holds the timer at $sec s');

  List<Map<String, Object?>> banners(ChatService s, String gid) => [
        for (final m in s.messagesByChat[gid] ?? const [])
          if (m.kind == 'system' && m.body.startsWith('{'))
            (jsonDecode(m.body) as Map).cast<String, Object?>()
      ];

  int countKind(ChatService s, String gid, String kind) =>
      banners(s, gid).where((b) => b['k'] == kind).length;

  Map<String, Object?>? bannerOf(ChatService s, String gid, String kind) {
    for (final b in banners(s, gid).reversed) {
      if (b['k'] == kind) return b;
    }
    return null;
  }

  /// The notice [kind] in [s]'s copy of [gid], once it is there: a list is
  /// installed a step before what it changed is said, so a device holding
  /// the new list may not have said so yet.
  Future<Map<String, Object?>> told(ChatService s, String gid, String kind,
      {required String what}) async {
    await waitUntil(() => bannerOf(s, gid, kind) != null, what: what);
    return bannerOf(s, gid, kind)!;
  }

  /// Everyone in [gid] as [s] sees it, [s] included.
  Set<String> everyone(ChatService s, String gid) =>
      {s.myRid, ...s.groups[gid]!.memberRids};

  List<String> texts(ChatService s, String gid) => [
        for (final m in s.messagesByChat[gid] ?? const [])
          if (m.kind == 'gtext') m.body
      ];

  /// Who [s]'s queued fan-out for [gid] is addressed to — the membership
  /// snapshot taken when each row was queued.
  Future<Set<String>> queuedFor(ChatService s, String gid) async => {
        for (final r in await s.vault.db.query('group_fanout',
            columns: ['rid'], where: 'gid = ?', whereArgs: [gid]))
          r['rid'] as String
      };

  /// The id of the message [body] in [gid] once every one of [at] holds it.
  Future<String> everywhere(
      List<ChatService> at, String gid, String body) async {
    String? mid;
    await waitUntil(() {
      for (final s in at) {
        final m = (s.messagesByChat[gid] ?? const <ChatMessage>[])
            .where((m) => m.body == body)
            .firstOrNull;
        if (m == null) return false;
        mid ??= m.mid;
      }
      return true;
    }, what: '"$body" reaches every device');
    return mid!;
  }

  Future<Map<String, Object?>?> row(
      ChatService s, String thread, String mid) async {
    final r = await s.vault.db.query('messages',
        where: 'rid = ? AND mid = ?', whereArgs: [thread, mid], limit: 1);
    return r.isEmpty ? null : r.first;
  }

  /// When [s]'s copy of [mid] goes (0 never).
  Future<int> expiry(ChatService s, String gid, String mid) async =>
      (await row(s, gid, mid))!['expire_at_ms'] as int;

  InnerMessage invite(Map<String, Object?> data) =>
      InnerMessage(kind: 'ginvite', mid: newMessageId(), ts: now(), data: data);

  test('1. a co-admin sets the timer, and every device of every member keeps '
      'it on what is sent afterwards', () async {
    final owen = await start('Owen1');
    final ada = await start('Ada1'); // the co-admin who sets it
    final ben = await start('Ben1'); // a member with a laptop
    final cat = await start('Cat1'); // a plain member
    final phones = [owen, ada, ben, cat];
    await waitUntil(() => phones.every((s) => s.transport.isConnected),
        what: 'everyone connects');
    for (var i = 0; i < phones.length; i++) {
      for (var j = i + 1; j < phones.length; j++) {
        await befriend(phones[i], phones[j]);
      }
    }
    await settled(phones);
    final lap = await laptopOf(ben, 'BenLaptop1', [owen, ada, cat]);
    await waitUntil(
        () => [owen, ada, cat]
            .every((s) => s.debugListedDeviceOwner(lap.myRid) == ben.myRid),
        what: "everyone holds Ben's list naming his laptop");
    await quiet([...phones, lap], what: 'everyone has introduced themselves');
    final gid =
        await owen.createGroup('Crew', [ada.myRid, ben.myRid, cat.myRid]);
    final all = [owen, ada, ben, lap, cat];
    await waitUntil(() => all.every((s) => s.groups.containsKey(gid)),
        what: 'the group reaches every device, the laptop included');
    await promote(owen, gid, ada, all);

    // Before the timer: kept for ever, everywhere.
    await cat.sendGroupText(gid, 'before the timer');
    final before = await everywhere(all, gid, 'before the timer');
    for (final s in all) {
      expect(await expiry(s, gid, before), 0,
          reason: '${s.displayName}: sent before the timer, never goes');
    }

    // Ada, a co-admin, sets it: a list, at the next version, everywhere.
    final ver = owen.groups[gid]!.ver;
    await ada.setGroupTimer(gid, 3600);
    await atTimer(all, gid, 3600);
    await atVersion(all, gid, ver + 1, 'the timer');
    expect(bannerOf(ada, gid, SystemKind.groupTtlSetYou)?['sec'], 3600);
    for (final s in [owen, ben, lap, cat]) {
      final b = await told(s, gid, SystemKind.groupTtlSetBy,
          what: '${s.displayName} is told');
      expect(b['by'], 'Ada1', reason: '${s.displayName}: by whom');
      expect(b['sec'], 3600);
    }
    expect((await ada.debugInviteData(gid))['tmr'], 3600,
        reason: 'the list carries it');

    // What each sends from now on carries it: from the owner, from a plain
    // member, and from Ben's laptop — whose own copy and its mirror on Ben's
    // phone go an hour after it was sent, and every other copy an hour
    // after it arrived.
    for (final (sender, body) in [
      (owen, 'from the owner'),
      (cat, 'from a member'),
      (lap, 'from the laptop'),
    ]) {
      final sentAt = now();
      await sender.sendGroupText(gid, body);
      final mid = await everywhere(all, gid, body);
      final arrived = now();
      final mine = (await row(sender, gid, mid))!;
      expect(mine['expire_at_ms'], (mine['ts_ms'] as int) + 3600 * 1000,
          reason: "${sender.displayName}'s own copy goes an hour after it "
              'was sent');
      for (final s in all) {
        if (identical(s, sender)) continue;
        final x = await expiry(s, gid, mid);
        if (identical(sender, lap) && identical(s, ben)) {
          expect(x, mine['expire_at_ms'],
              reason: "Ben's phone holds his laptop's message as his own: "
                  'it goes when the original does');
          continue;
        }
        expect(x - 3600 * 1000, inInclusiveRange(sentAt, arrived),
            reason: '${s.displayName}: "$body" goes an hour after it '
                'arrived');
      }
    }
    // An attachment, the same.
    final sentAt = now();
    await owen.sendGroupFile(gid, 'plan.txt',
        Uint8List.fromList(List<int>.filled(2048, 0x70)), 'text/plain');
    final fileMid = await everywhere(all, gid, 'plan.txt');
    final arrived = now();
    final ownFile = (await row(owen, gid, fileMid))!;
    expect(ownFile['expire_at_ms'], (ownFile['ts_ms'] as int) + 3600 * 1000);
    for (final s in [ada, ben, lap, cat]) {
      expect((await expiry(s, gid, fileMid)) - 3600 * 1000,
          inInclusiveRange(sentAt, arrived),
          reason: '${s.displayName}: the file goes an hour after it arrived');
    }

    // The owner shortens it to five seconds; what is sent now goes, on every
    // device, at its time — and not before.
    await owen.setGroupTimer(gid, 5);
    await atTimer(all, gid, 5);
    final sentBlink = now();
    await ada.sendGroupText(gid, 'blink');
    // Each device's time for it, read the moment that device holds it: a
    // device that had it seconds before the slowest one may already have
    // let it go by the time the slowest has it.
    final due = <ChatService, int>{};
    String? blink;
    await waitUntil(() {
      for (final s in all) {
        if (due.containsKey(s)) continue;
        final m = (s.messagesByChat[gid] ?? const <ChatMessage>[])
            .where((m) => m.body == 'blink')
            .firstOrNull;
        if (m == null) continue;
        blink ??= m.mid;
        due[s] = m.expireAtMs;
      }
      return due.length == all.length;
    }, what: '"blink" reaches every device');
    for (final s in all) {
      expect(due[s]! - 5000, inInclusiveRange(sentBlink, now()),
          reason: '${s.displayName} times it: five seconds');
    }
    final gone = <ChatService>{};
    await waitUntil(() async {
      for (final s in all) {
        if (gone.contains(s)) continue;
        await s.debugSweep();
        if (await row(s, gid, blink!) == null) {
          expect(now(), greaterThanOrEqualTo(due[s]!),
              reason: '${s.displayName} took it before its time');
          expect(texts(s, gid), isNot(contains('blink')),
              reason: '${s.displayName}: gone from the screen too');
          gone.add(s);
        }
      }
      return gone.length == all.length;
    }, what: '"blink" goes from every device at its time');
    for (final s in all) {
      expect(await row(s, gid, before), isNotNull,
          reason: '${s.displayName}: what was sent before the timer stays');
      expect(texts(s, gid), contains('from the owner'),
          reason: '${s.displayName}: what is set for an hour is still here');
    }
  }, timeout: const Timeout(Duration(minutes: 6)));

  test('2. only an admin sets the timer, and turning it off is said',
      () async {
    final owen = await start('Owen2');
    final ada = await start('Ada2'); // co-admin
    final cat = await start('Cat2'); // a plain member
    final gid = await groupOf(owen, [ada, cat]);
    final all = [owen, ada, cat];
    await promote(owen, gid, ada, all);
    final ver = owen.groups[gid]!.ver;

    // Cat may not: nothing is issued, here or anywhere.
    await cat.waitForGroupFanout(gid);
    await cat.setGroupTimer(gid, 300);
    expect(cat.groups[gid]!.ttlSec, 0);
    expect(cat.groups[gid]!.ver, ver);
    expect(await queuedFor(cat, gid), isEmpty, reason: 'no list was issued');
    expect(countKind(cat, gid, SystemKind.groupTtlSetYou), 0);

    // A modified client of Cat's makes the list anyway — the held roles
    // stated exactly, so only her own standing can refuse it — and every
    // member refuses it, holding it back for a promotion that never comes.
    final forged = {
      ...await cat.debugInviteData(gid),
      'ver': ver + 1,
      'tmr': 300,
    };
    final seen = {
      for (final s in [owen, ada]) s: s.debugListsJudgedFrom(gid, cat.myRid)
    };
    for (final s in [owen, ada]) {
      await cat.debugSendRawInner(s.myRid, invite(forged));
    }
    await waitUntil(
        () => [owen, ada].every(
            (s) => s.debugListsJudgedFrom(gid, cat.myRid) == seen[s]! + 1),
        what: "Cat's list is judged");
    for (final s in [owen, ada]) {
      expect(s.groups[gid]!.ttlSec, 0,
          reason: "${s.displayName}: a plain member's timer is refused");
      expect(s.groups[gid]!.ver, ver);
      expect(s.debugHeldBackLists(gid), 1);
      expect(countKind(s, gid, SystemKind.groupTtlSetBy), 0);
    }

    // Ada may: on, then off — said as a 1:1 chat says it.
    await ada.setGroupTimer(gid, 600);
    await atTimer(all, gid, 600);
    await ada.setGroupTimer(gid, 0);
    await atTimer(all, gid, 0);
    await atVersion(all, gid, ver + 2, 'on, then off');
    expect((await ada.debugInviteData(gid))['tmr'], 0,
        reason: 'once a group has had a timer, its lists say it is off');
    expect(countKind(ada, gid, SystemKind.ttlOffYou), 1);
    for (final s in [owen, cat]) {
      final b = await told(s, gid, SystemKind.ttlOffThem,
          what: '${s.displayName} is told it is off');
      expect(b['name'], 'Ada2', reason: '${s.displayName}: Ada turned it off');
      expect(countKind(s, gid, SystemKind.groupTtlDroppedBy), 0);
    }
    await cat.sendGroupText(gid, 'kept again');
    final mid = await everywhere(all, gid, 'kept again');
    for (final s in all) {
      expect(await expiry(s, gid, mid), 0,
          reason: '${s.displayName}: sent with the timer off, kept');
    }
  });

  test('3. a member on an older build keeps the messages, and the notice '
      'says so', () async {
    final en = await AppLocalizations.delegate.load(const Locale('en'));
    final es = await AppLocalizations.delegate.load(const Locale('es'));
    final owen = await start('Owen3');
    final ada = await start('Ada3');
    final old = await start('Old3');
    final max = await start('Max3'); // leaves, and is added back
    old.debugBuildBefore0030 = true;
    final gid = await groupOf(owen, [ada, old, max]);
    final all = [owen, ada, old, max];

    await owen.setGroupTimer(gid, 3600);
    await atVersion(all, gid, owen.groups[gid]!.ver, 'the timer');
    await atTimer([owen, ada], gid, 3600);
    expect(old.groups[gid]!.ttlSec, 0,
        reason: 'an older build reads no group timer');
    expect(countKind(old, gid, SystemKind.groupTtlSetBy), 0);

    // What the members who can read it are told: the limit, in their
    // language.
    final setBy = jsonEncode(await told(ada, gid, SystemKind.groupTtlSetBy,
        what: 'Ada is told'));
    expect(systemText(en, setBy),
        'Owen3 set disappearing messages to 1 hour. A member whose app is '
        'older than this version keeps the messages, and theirs do not '
        'disappear.');
    expect(systemText(es, setBy),
        'Owen3 configuró los mensajes temporales a 1 hora. Un miembro cuya '
        'app es anterior a esta versión conserva los mensajes, y los suyos '
        'no desaparecen.');
    final setYou = jsonEncode(bannerOf(owen, gid, SystemKind.groupTtlSetYou));
    expect(systemText(en, setYou),
        startsWith('You set disappearing messages to 1 hour. A member whose '
            'app is older than this version keeps the messages'));

    // Which is what it does: it keeps Ada's message, and sends its own with
    // no timer, which nobody's device then times.
    await ada.sendGroupText(gid, 'from Ada, for an hour');
    final fromAda = await everywhere(all, gid, 'from Ada, for an hour');
    expect(await expiry(old, gid, fromAda), 0,
        reason: 'the older build keeps it');
    expect(await expiry(owen, gid, fromAda), greaterThan(0));
    await old.sendGroupText(gid, 'from the older build');
    final fromOld = await everywhere(all, gid, 'from the older build');
    for (final s in all) {
      expect(await expiry(s, gid, fromOld), 0,
          reason: '${s.displayName}: what it sends carries no timer');
    }

    // Max leaves, and Owen adds him back: everyone holds him again, the
    // older build too, which reads no position.
    await promote(owen, gid, old, all);
    await max.leaveGroup(gid);
    await waitUntil(
        () => [owen, ada, old]
            .every((s) => !s.groups[gid]!.memberRids.contains(max.myRid)),
        what: "Max's leave lands");
    await owen.addGroupMembers(gid, [max.myRid]);
    await atVersion(all, gid, owen.groups[gid]!.ver, 'Max added back');
    expect(max.groups[gid]!.left, isFalse);

    // The older build, an admin now, renames. Its list carries no timer —
    // and so turns it off, which the others are told as what happened — and
    // names Max at no position: on every device that remembers his leave
    // it reads as a list from before it, and takes him out.
    await old.renameGroup(gid, 'Renamed on an older build');
    await waitUntil(
        () => [owen, ada].every(
            (s) => s.groups[gid]!.name == 'Renamed on an older build'),
        what: "the older build's rename lands");
    for (final s in [owen, ada]) {
      expect(s.groups[gid]!.ttlSec, 0, reason: s.displayName);
      final b = await told(s, gid, SystemKind.groupTtlDroppedBy,
          what: '${s.displayName} is told why');
      expect(b['by'], 'Old3', reason: '${s.displayName}: by whom');
    }
    expect(
        systemText(en,
            jsonEncode(bannerOf(owen, gid, SystemKind.groupTtlDroppedBy))),
        "Disappearing messages are now off: Old3's change to the group came "
        "without the group's timer. An app older than this version cannot "
        'carry it.');
    for (final s in [owen, ada]) {
      expect(s.groups[gid]!.memberRids, isNot(contains(max.myRid)),
          reason: "${s.displayName}: the older build's list names Max where "
              'he left, and is read so — the limit ADR 0030 states');
    }
    await told(max, gid, SystemKind.removedFrom,
        what: "Max's own device reads it so too");
    expect(max.groups[gid]!.left, isTrue);
    expect(old.groups[gid]!.memberRids, contains(max.myRid),
        reason: 'the older build itself holds him');
    // Owen, who added him back, is told his change did not stand.
    await told(owen, gid, SystemKind.changeOverriddenBy,
        what: 'Owen is told his add did not stand');
  });

  test('4. two admins setting two timers at once end on one, everywhere',
      () async {
    final owen = await start('Owen4');
    final ada = await start('Ada4');
    final bea = await start('Bea4');
    final cat = await start('Cat4');
    final gid = await groupOf(owen, [ada, bea, cat]);
    final all = [owen, ada, bea, cat];
    await promote(owen, gid, ada, all);
    await promote(owen, gid, bea, all);
    final ver = owen.groups[gid]!.ver;

    // Each sets a timer on the same list, neither having heard the other.
    for (final s in [ada, bea]) {
      s.debugHoldGroupFanout = (_, inner) => inner.kind == 'ginvite';
    }
    await ada.setGroupTimer(gid, 3600);
    await bea.setGroupTimer(gid, 60);
    final aList = await ada.debugInviteData(gid);
    final bList = await bea.debugInviteData(gid);
    expect(Group.listDigest(aList), Group.listDigest(bList),
        reason: 'one list but for the timer: §11.1 cannot tell them apart');
    final adaWins =
        Group.stateDigestOf(aList).compareTo(Group.stateDigestOf(bList)) < 0;
    final (winner, loser, timer) =
        adaWins ? (ada, bea, 3600) : (bea, ada, 60);
    for (final s in [ada, bea]) {
      s.debugHoldGroupFanout = null;
      await s.retryGroupFanout();
    }
    await waitUntil(
        () => all.every((s) =>
            s.groups[gid]!.ttlSec == timer && s.groups[gid]!.ver == ver + 1),
        what: 'every device ends on one timer');
    await quiet(all, what: 'both lists have been judged everywhere');
    for (final s in all) {
      expect(s.groups[gid]!.ttlSec, timer,
          reason: '${s.displayName}: the state digest that sorts first wins');
    }
    await waitUntil(
        () => countKind(loser, gid, SystemKind.changeOverriddenBy) == 1,
        what: '${loser.displayName} is told the change did not stand');
    expect(countKind(winner, gid, SystemKind.changeOverriddenBy), 0);
  });

  test('5. a list issued before a leave reached its issuer does not put the '
      'leaver back', () async {
    final owen = await start('Owen5');
    final ada = await start('Ada5'); // co-admin: renames before she hears
    final max = await start('Max5'); // leaves
    final nia = await start('Nia5');
    final gid = await groupOf(owen, [ada, max, nia]);
    final all = [owen, ada, max, nia];
    await promote(owen, gid, ada, all);
    final ver = owen.groups[gid]!.ver;

    // Ada renames. Her list is recorded for every member it names — Max
    // among them, since she has not heard he is going — and held in her
    // queue until his leave has reached every device, hers included.
    ada.debugHoldGroupFanout = (_, inner) => inner.kind == 'ginvite';
    await ada.renameGroup(gid, 'Renamed before the leave');
    expect(await queuedFor(ada, gid), contains(max.myRid),
        reason: 'her list was built while Max was still in the group');
    await max.leaveGroup(gid);
    await waitUntil(
        () => [owen, ada, nia]
            .every((s) => !s.groups[gid]!.memberRids.contains(max.myRid)),
        what: "Max's leave reaches every device, Ada's included");
    final maxJudged = max.debugListsJudgedFrom(gid, ada.myRid);
    ada.debugHoldGroupFanout = null;
    await ada.retryGroupFanout();
    await waitUntil(
        () => [owen, nia]
            .every((s) => s.groups[gid]!.name == 'Renamed before the leave'),
        what: "Ada's list lands on the others");
    await waitUntil(
        () => max.debugListsJudgedFrom(gid, ada.myRid) > maxJudged,
        what: "Max's device has judged Ada's list");

    // Her change stands everywhere — and without the man who left.
    for (final s in [owen, ada, nia]) {
      final g = s.groups[gid]!;
      expect(g.ver, ver + 1, reason: '${s.displayName}: her list is held');
      expect(g.memberRids, isNot(contains(max.myRid)),
          reason: '${s.displayName}: a list issued before the leave reached '
              'its issuer does not put the leaver back');
    }
    for (final s in [ada, nia]) {
      expect(everyone(s, gid), everyone(owen, gid),
          reason: '${s.displayName}: one member set');
    }
    final g = max.groups[gid]!;
    expect(g.left, isTrue, reason: "the leaver's own device stays out");
    expect(countKind(max, gid, SystemKind.removedFrom), 0,
        reason: 'and is not told it was removed: it left');

    // What the members send from now on is not queued for him.
    for (final s in [owen, nia]) {
      await s.waitForGroupFanout(gid);
      s.debugPauseGroupFanout = true;
      await s.sendGroupText(gid, 'after the leave, from ${s.displayName}');
      expect(await queuedFor(s, gid), isNot(contains(max.myRid)),
          reason: '${s.displayName} queues nothing for the leaver');
      s.debugPauseGroupFanout = false;
      await s.drainGroupFanoutForTest();
    }
    await waitUntil(
        () => [owen, ada, nia].every((s) =>
            texts(s, gid).contains('after the leave, from Owen5') &&
            texts(s, gid).contains('after the leave, from Nia5')),
        what: 'the members hear each other');
    expect(texts(max, gid), isNot(contains('after the leave, from Owen5')));
  });

  test('6. an admin adding the leaver back after the leave does put them '
      'back, everywhere', () async {
    final owen = await start('Owen6');
    final ada = await start('Ada6'); // co-admin
    final max = await start('Max6'); // leaves, and is added back
    final nia = await start('Nia6'); // never gets the list adding him back
    final gid = await groupOf(owen, [ada, max, nia]);
    final all = [owen, ada, max, nia];
    await promote(owen, gid, ada, all);
    await max.leaveGroup(gid);
    await waitUntil(
        () => [owen, ada, nia]
            .every((s) => !s.groups[gid]!.memberRids.contains(max.myRid)),
        what: 'the leave lands');
    expect(max.groups[gid]!.left, isTrue);

    // Owen adds him back. Nia's copy of that list is lost on the way.
    final niaRid = nia.myRid;
    await owen.waitForGroupFanout(gid);
    owen.debugHoldGroupFanout =
        (rid, inner) => rid == niaRid && inner.kind == 'ginvite';
    final niaVer = nia.groups[gid]!.ver;
    // His device was told once already, when the group was made.
    final addedBefore = countKind(max, gid, SystemKind.addedToBy);
    await owen.addGroupMembers(gid, [max.myRid]);
    final back = owen.groups[gid]!;
    final at = (back.rolesVer, back.ver);
    final data = await owen.debugInviteData(gid);
    final maxEd = b64(max.identity.edPub);
    final maxEntry = (data['members'] as List)
        .cast<Map>()
        .firstWhere((m) => (m['b'] as Map)['ed'] == maxEd);
    expect(maxEntry['e'], [at.$1, at.$2],
        reason: 'the list names him at its own position');
    await atVersion([owen, ada, max], gid, back.ver, 'the list adding him');
    await owen.vault.db
        .delete('group_fanout', where: 'rid = ?', whereArgs: [niaRid]);
    owen.debugHoldGroupFanout = null;

    for (final s in [owen, ada]) {
      expect(s.groups[gid]!.memberRids, contains(max.myRid),
          reason: '${s.displayName}: added back after his leave, he is back');
      expect(s.groups[gid]!.epochs[max.myRid], at);
    }
    final mg = max.groups[gid]!;
    expect(mg.left, isFalse, reason: "his own device is back in the group");
    expect(mg.epochs[''], at);
    expect(everyone(max, gid), everyone(owen, gid));
    await waitUntil(
        () => countKind(max, gid, SystemKind.addedToBy) == addedBefore + 1,
        what: 'his device says he was added back');
    expect(bannerOf(max, gid, SystemKind.addedToBy)?['by'], 'Owen6',
        reason: 'and says who added him back');
    expect(nia.groups[gid]!.ver, niaVer, reason: 'Nia never got that list');

    // Ada's next change is built on it, and names him at that position:
    // Nia takes it, and him with it.
    await ada.renameGroup(gid, 'Max is back');
    await waitUntil(
        () => all.every((s) => s.groups[gid]!.name == 'Max is back'),
        what: "Ada's rename reaches every device");
    for (final s in [owen, ada, nia]) {
      expect(s.groups[gid]!.memberRids, contains(max.myRid),
          reason: s.displayName);
    }
    expect(nia.groups[gid]!.epochs[max.myRid], at);
    for (final s in [ada, max, nia]) {
      expect(everyone(s, gid), everyone(owen, gid),
          reason: '${s.displayName}: one member set');
    }
    await max.sendGroupText(gid, 'back again');
    await waitUntil(
        () => [owen, ada, nia]
            .every((s) => texts(s, gid).contains('back again')),
        what: 'everyone hears him again');
  });

  test('7. the timer and the leaves heard survive a restart; deleting the '
      "leaver's contact lets go of the leave", () async {
    final owen = await start('Owen7');
    final ada = await start('Ada7'); // co-admin
    final max = await start('Max7'); // leaves
    var nia = await start('Nia7'); // restarts
    final gid = await groupOf(owen, [ada, max, nia]);
    await promote(owen, gid, ada, [owen, ada, max, nia]);
    await owen.setGroupTimer(gid, 3600);
    await atTimer([owen, ada, max, nia], gid, 3600);

    // Ada's rename is built before Max's leave and held while it lands.
    ada.debugHoldGroupFanout = (_, inner) => inner.kind == 'ginvite';
    await ada.renameGroup(gid, 'Renamed before the leave');
    await max.leaveGroup(gid);
    await waitUntil(
        () => [owen, ada, nia]
            .every((s) => !s.groups[gid]!.memberRids.contains(max.myRid)),
        what: "Max's leave lands");

    // Nia restarts: the timer and the leave she heard are kept. Stopped
    // only once her vault holds the leave: it is written in the step that
    // acknowledges its envelope, a moment after her memory has it, and an
    // envelope stopped before that step is delivered again on the next start
    // rather than kept.
    await waitUntil(() async {
      final stored = await nia.vault.kvGet('groups');
      if (stored == null) return false;
      for (final g in jsonDecode(stored) as List) {
        if ((g as Map)['gid'] != gid) continue;
        final left = g['leftAt'];
        return left is Map && left.containsKey(max.myRid);
      }
      return false;
    }, what: "Nia's vault holds Max's leave");
    await stop(nia);
    nia = await start('Nia7');
    expect(nia.groups[gid]!.ttlSec, 3600, reason: 'the timer survives');
    expect(nia.groups[gid]!.leftAt.containsKey(max.myRid), isTrue,
        reason: 'the leave she heard survives');
    await waitUntil(() => nia.transport.isConnected, what: 'Nia is back');

    ada.debugHoldGroupFanout = null;
    await ada.retryGroupFanout();
    await waitUntil(
        () => [owen, nia]
            .every((s) => s.groups[gid]!.name == 'Renamed before the leave'),
        what: "Ada's list lands");
    for (final s in [owen, nia]) {
      expect(s.groups[gid]!.memberRids, isNot(contains(max.myRid)),
          reason: '${s.displayName}: still without the leaver');
      expect(s.groups[gid]!.ttlSec, 3600);
    }

    // Owen deletes Max's contact: the leave he remembered goes with him, and
    // the group's sealed record names Max nowhere.
    expect(owen.groups[gid]!.leftAt.containsKey(max.myRid), isTrue);
    await owen.deleteContact(max.myRid);
    expect(owen.groups[gid]!.leftAt.containsKey(max.myRid), isFalse);
    final record = await owen.vault.kvGet('groups');
    expect(record, isNotNull);
    expect(record!, isNot(contains(max.myRid)),
        reason: "the group's record lets go of him");

    // Someone added now holds the timer, and is told of it as they arrive.
    final zed = await start('Zed7');
    await waitUntil(() => zed.transport.isConnected, what: 'Zed connects');
    await befriend(owen, zed);
    await settled([owen, zed]);
    await owen.addGroupMembers(gid, [zed.myRid]);
    await waitUntil(() => zed.groups.containsKey(gid),
        what: 'the group reaches Zed');
    expect(zed.groups[gid]!.ttlSec, 3600);
    final arrived = await told(zed, gid, SystemKind.groupTtlIs,
        what: 'Zed is told the group has a timer');
    expect(arrived['sec'], 3600);
  });

  test("8. a list's timer, positions and state digest are the recorded ones",
      () async {
    // `dart test` runs from app/, so the vectors are one level up.
    final file = File('${Directory.current.parent.path}'
        '${Platform.pathSeparator}docs${Platform.pathSeparator}vectors'
        '${Platform.pathSeparator}v1${Platform.pathSeparator}group_state.json');
    final v = (jsonDecode(file.readAsStringSync()) as Map)
        .cast<String, Object?>();
    final lists = (v['lists'] as List).cast<Map>();
    expect(lists.length, greaterThanOrEqualTo(4));
    for (final l in lists) {
      final data =
          (jsonDecode(l['list'] as String) as Map).cast<String, Object?>();
      expect(Group.listDigest(data), l['digest'], reason: '§11.1 digest');
      final canonical = Group.stateCanonical(data);
      expect(canonical, l['state_canonical']);
      expect(
          utf8
              .encode(canonical)
              .map((b) => b.toRadixString(16).padLeft(2, '0'))
              .join(),
          l['state_canonical_hex']);
      expect(Group.stateDigestOf(data), l['state_digest']);
    }
    // The pair the state digest exists for: one list but for the timer.
    final pair = (v['tie'] as Map).cast<String, Object?>();
    final a = lists[pair['a'] as int], b = lists[pair['b'] as int];
    expect(a['digest'], b['digest']);
    expect(a['state_digest'], isNot(b['state_digest']));
    expect(pair['first'],
        (a['state_digest'] as String).compareTo(b['state_digest'] as String) <
                0
            ? pair['a']
            : pair['b']);
    // The members as the wire carries them, read back as this client reads.
    for (final m in (v['inner'] as List).cast<Map>()) {
      final inner = InnerMessage.fromBytes(
          Uint8List.fromList(utf8.encode(m['json'] as String)));
      expect(inner.kind, m['kind']);
      switch (inner.kind) {
        case 'ginvite':
          expect(inner.data['tmr'], m['tmr']);
          expect(Group.stateDigestOf(inner.data), m['state_digest']);
        case 'gleave':
          expect(Group.posFrom(inner.data['e']), isNotNull);
        case 'gmsg':
          expect(inner.ttlSec, m['ttl']);
      }
    }
  });

  test('9. a position costs about a dozen bytes a member added, measured',
      () async {
    final owen = await start('Owen Fairweather9');
    final mia = await start('Mia Castellanos9');
    await waitUntil(
        () => owen.transport.isConnected && mia.transport.isConnected,
        what: 'both connect');
    await befriend(owen, mia);
    await settled([owen, mia]);
    // A round trip each way, so the ratchet header is in its steady state,
    // as group_roles_test 11 weighs lists.
    await owen.sendText(mia.myRid, 'hello');
    await waitUntil(() => (mia.messagesByChat[owen.myRid] ?? []).isNotEmpty,
        what: 'Mia hears Owen');
    await mia.sendText(owen.myRid, 'hello back');
    await waitUntil(() => (owen.messagesByChat[mia.myRid] ?? []).length >= 2,
        what: 'Owen hears Mia');
    await settled([owen, mia]);
    // From here nothing leaves Owen's outbox: every list for Mia is weighed
    // as the relay would receive it.
    await owen.transport.stop();

    /// The sealed bytes the newest envelope for Mia in [gid] needed.
    Future<int> weigh(String gid) async {
      await owen.waitForGroupFanout(gid);
      final row = (await owen.vault.db.query('outbox',
              where: 'rid = ? AND thread_rid = ?',
              whereArgs: [mia.myRid, gid],
              orderBy: 'rowid DESC',
              limit: 1))
          .single;
      final opened = (await SealedEnvelope.open(
          myXSeed: mia.identity.xSeed,
          myXPub: mia.identity.xPub,
          blob: row['payload'] as String))!;
      return utf8
              .encode(jsonEncode({'f': opened.fromRid, 'p': opened.payload}))
              .length +
          4;
    }

    Future<String> phantom(int i) async {
      final id = await ZIdentity.generate();
      await owen.addContactFromCode(
          (await id.bundle(displayName: 'Member Number $i')).encode());
      return id.routingId();
    }

    // One group grown a member at a time, every member after the third
    // named at the position of the list that added them; and, for each
    // size, the same group made with all of them at once, which names none.
    final others = [await phantom(1)];
    final grown =
        await owen.createGroup('Weekend hiking club', [mia.myRid, ...others]);
    final rows = <(int, int, int, int)>[];
    for (var n = 3; n <= 14; n++) {
      if (n > 3) {
        final rid = await phantom(n);
        others.add(rid);
        await owen.addGroupMembers(grown, [rid]);
      }
      final made = await owen
          .createGroup('Weekend hiking club', [mia.myRid, ...others]);
      final g = await owen.debugInviteData(grown);
      final m = await owen.debugInviteData(made);
      final positions = [
        for (final e in g['members'] as List)
          if ((e as Map).containsKey('e')) e['e']
      ];
      expect(positions.length, n - 3,
          reason: 'every member added after the group was made, and only '
              'they, carry a position');
      expect((m['members'] as List).any((e) => (e as Map).containsKey('e')),
          isFalse);
      // The version is the only other difference: one digit at most.
      final extra = utf8.encode(jsonEncode(g)).length -
          utf8.encode(jsonEncode(m)).length -
          ('${g['ver']}'.length - '${m['ver']}'.length);
      expect(extra, lessThanOrEqualTo(13 * (n - 3)),
          reason: 'about a dozen bytes a member added');
      rows.add((n, extra, await weigh(grown), await weigh(made)));
    }
    debugPrint([
      'ginvite — members: position bytes in the list; sealed bytes needed, '
          'grown a member at a time / made at once:',
      for (final r in rows) '  ${r.$1}: ${r.$2}; ${r.$3} / ${r.$4}',
    ].join('\n'));
    for (final r in rows) {
      expect(r.$3 - r.$4, inInclusiveRange(0, 460),
          reason: '${r.$1} members: at most one 256-byte padding block, '
              'which the sealed envelope carries as about 456 bytes');
    }
  });

  test('10. a leave that arrives after the list adding its leaver back takes '
      'nobody out', () async {
    final owen = await start('Owen10');
    final ada = await start('Ada10'); // co-admin: adds Max back
    final max = await start('Max10'); // leaves on his phone
    final cal = await start('Cal10'); // gets the leave only after the add
    final phones = [owen, ada, max, cal];
    await waitUntil(() => phones.every((s) => s.transport.isConnected),
        what: 'everyone connects');
    for (var i = 0; i < phones.length; i++) {
      for (var j = i + 1; j < phones.length; j++) {
        await befriend(phones[i], phones[j]);
      }
    }
    await settled(phones);
    final lap = await laptopOf(max, 'MaxLaptop10', [owen, ada, cal]);
    await waitUntil(
        () => [owen, ada, cal]
            .every((s) => s.debugListedDeviceOwner(lap.myRid) == max.myRid),
        what: "everyone holds Max's list naming his laptop");
    await drained([...phones, lap], what: 'everyone has introduced themselves');
    final gid =
        await owen.createGroup('Crew', [ada.myRid, max.myRid, cal.myRid]);
    final all = [owen, ada, max, lap, cal];
    await waitUntil(() => all.every((s) => s.groups.containsKey(gid)),
        what: 'the group reaches every device, the laptop included');
    await promote(owen, gid, ada, all);
    await drained(all, what: 'the promotion has gone out from every device');

    // Max leaves on his phone. Its copy for Cal, and the copy for his own
    // laptop, are held back.
    final calRid = cal.myRid;
    max.debugHoldGroupFanout =
        (rid, inner) => rid == calRid && inner.kind == 'gleave';
    final mirror = Completer<void>();
    max.debugBeforeGroupMirror = () => mirror.future;
    await max.leaveGroup(gid);
    await waitUntil(
        () => [owen, ada]
            .every((s) => !s.groups[gid]!.memberRids.contains(max.myRid)),
        what: "Max's leave reaches Owen and Ada");
    expect(cal.groups[gid]!.memberRids, contains(max.myRid));
    expect(lap.groups[gid]!.left, isFalse);

    // Ada, who has heard it, adds him back. Cal and the laptop take that
    // list first, and hold him at its position.
    final addedBefore = countKind(max, gid, SystemKind.addedToBy);
    await ada.addGroupMembers(gid, [max.myRid]);
    final back = ada.groups[gid]!;
    final at = (back.rolesVer, back.ver);
    await waitUntil(
        () => [owen, max, lap, cal].every((s) => s.groups[gid]!.ver == at.$2),
        what: 'the list adding him back reaches every device');
    expect(cal.groups[gid]!.epochs[max.myRid], at);
    expect(lap.groups[gid]!.epochs[''], at);
    expect(max.groups[gid]!.left, isFalse, reason: 'his phone is back in');
    await waitUntil(
        () => countKind(max, gid, SystemKind.addedToBy) == addedBefore + 1,
        what: 'his phone says he was added back');
    expect(bannerOf(max, gid, SystemKind.addedToBy)?['by'], 'Ada10');

    // Now the leave reaches Cal, and its copy the laptop: each a leave of
    // the membership that list replaced. Remembered, and he stays.
    max.debugHoldGroupFanout = null;
    await max.retryGroupFanout();
    await waitUntil(() => cal.groups[gid]!.leftAt.containsKey(max.myRid),
        what: "Cal hears Max's leave");
    mirror.complete();
    await waitUntil(() => lap.groups[gid]!.leftAt.containsKey(''),
        what: "Max's laptop hears the leave his phone sent");
    max.debugBeforeGroupMirror = null;
    expect(cal.groups[gid]!.memberRids, contains(max.myRid),
        reason: 'a leave of the membership the list replaced takes nobody out');
    expect(cal.groups[gid]!.epochs[max.myRid], at);
    expect(countKind(cal, gid, SystemKind.memberLeft), 0);
    expect(lap.groups[gid]!.left, isFalse,
        reason: "nor does its copy on the leaver's own laptop");
    expect(countKind(lap, gid, SystemKind.leftYou), 0);

    // The next list keeps him on every device, and everyone hears him.
    await owen.renameGroup(gid, 'Max stays');
    await waitUntil(
        () => all.every((s) => s.groups[gid]!.name == 'Max stays'),
        what: "Owen's rename reaches every device");
    for (final s in [owen, ada, cal]) {
      expect(s.groups[gid]!.memberRids, contains(max.myRid),
          reason: s.displayName);
    }
    for (final s in [ada, max, cal]) {
      expect(everyone(s, gid), everyone(owen, gid),
          reason: '${s.displayName}: one member set');
    }
    expect(lap.groups[gid]!.left, isFalse);
    expect(lap.groups[gid]!.memberRids,
        everyone(owen, gid).difference({max.myRid}),
        reason: 'the laptop holds the members its account does');
    await lap.sendGroupText(gid, 'from the laptop, still in');
    await waitUntil(
        () => [owen, ada, cal]
            .every((s) => texts(s, gid).contains('from the laptop, still in')),
        what: 'everyone hears him');
  });

  test("11. the owner's list from before a leave outranks a co-admin's list "
      "adding the leaver back at its version, on the leaver's own device too",
      () async {
    final owen = await start('Owen11');
    final ada = await start('Ada11'); // co-admin: adds Max back
    final max = await start('Max11'); // leaves
    final nia = await start('Nia11');
    final gid = await groupOf(owen, [ada, max, nia]);
    final all = [owen, ada, max, nia];
    await promote(owen, gid, ada, all);
    final ver = owen.groups[gid]!.ver;

    // Owen renames before he hears that Max is going: his list, naming Max,
    // waits in his queue.
    owen.debugHoldGroupFanout = (_, inner) => inner.kind == 'ginvite';
    await owen.renameGroup(gid, 'Renamed before the leave');
    expect(await queuedFor(owen, gid), contains(max.myRid));
    await max.leaveGroup(gid);
    await waitUntil(
        () => [owen, ada, nia]
            .every((s) => !s.groups[gid]!.memberRids.contains(max.myRid)),
        what: "Max's leave reaches every device, Owen's included");

    // Ada, who has heard it, adds him back: a list at the version of Owen's.
    // Her copy for Max is held until Owen's has reached him.
    final maxRid = max.myRid;
    ada.debugHoldGroupFanout =
        (rid, inner) => rid == maxRid && inner.kind == 'ginvite';
    final fromOwen = {
      for (final s in [ada, max, nia])
        s: s.debugListsJudgedFrom(gid, owen.myRid)
    };
    final fromAda = {
      for (final s in [owen, max, nia])
        s: s.debugListsJudgedFrom(gid, ada.myRid)
    };
    await ada.addGroupMembers(gid, [max.myRid]);
    expect(ada.groups[gid]!.ver, ver + 1, reason: 'one version, two lists');
    // His device was told once already, when the group was made.
    final added = countKind(max, gid, SystemKind.addedToBy);
    owen.debugHoldGroupFanout = null;
    await owen.retryGroupFanout();
    await waitUntil(
        () => max.debugListsJudgedFrom(gid, owen.myRid) > fromOwen[max]!,
        what: "Max's device judges Owen's list");
    expect(max.groups[gid]!.left, isTrue);

    ada.debugHoldGroupFanout = null;
    await ada.retryGroupFanout();
    await waitUntil(
        () =>
            fromOwen.entries.every((e) =>
                e.key.debugListsJudgedFrom(gid, owen.myRid) > e.value) &&
            fromAda.entries.every(
                (e) => e.key.debugListsJudgedFrom(gid, ada.myRid) > e.value),
        what: 'both lists have been judged on every device they went to');
    await drained(all, what: 'nothing is left to send');

    // The owner's list wins the tie on every device, so Max is out on every
    // one — his own included, which holds that list as the others do, and
    // has said nothing at all.
    expect(max.groups[gid]!.left, isTrue,
        reason: 'the list adding him back lost the tie, on his device as on '
            'every other');
    expect(countKind(max, gid, SystemKind.addedToBy), added);
    expect(countKind(max, gid, SystemKind.removedFrom), 0);
    for (final s in all) {
      expect(s.groups[gid]!.ver, ver + 1, reason: s.displayName);
      expect(s.groups[gid]!.name, 'Renamed before the leave',
          reason: "${s.displayName}: the owner's list");
    }
    for (final s in [owen, ada, nia]) {
      expect(s.groups[gid]!.memberRids, isNot(contains(max.myRid)),
          reason: '${s.displayName}: without the leaver');
    }
    for (final s in [ada, nia]) {
      expect(everyone(s, gid), everyone(owen, gid),
          reason: '${s.displayName}: one member set');
    }
    await told(ada, gid, SystemKind.changeOverriddenBy,
        what: 'Ada is told her add did not stand');

    // Added back on top of the list everyone holds, he is back everywhere.
    await ada.addGroupMembers(gid, [max.myRid]);
    await atVersion(all, gid, ver + 2, 'Max added back again');
    expect(max.groups[gid]!.left, isFalse);
    await waitUntil(
        () => countKind(max, gid, SystemKind.addedToBy) == added + 1,
        what: 'his device says he was added back');
    expect(bannerOf(max, gid, SystemKind.addedToBy)?['by'], 'Ada11');
    for (final s in [ada, max, nia]) {
      expect(everyone(s, gid), everyone(owen, gid),
          reason: '${s.displayName}: one member set');
    }
  });
}
