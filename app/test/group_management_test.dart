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
//      banner — each on its own line.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/system_messages.dart';
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

  Future<ChatService> makeClient(String name) async {
    final dir = await Directory.systemTemp.createTemp('z_grpm_$name');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    final identity = await ZIdentity.generate();
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

  late ChatService alice, bob, carol;
  late String gid;

  setUp(() async {
    alice = await makeClient('alice');
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
}
