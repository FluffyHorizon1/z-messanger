// Integration test for group chats (pairwise fan-out over 1:1 ratchets).
//
// Three REAL ChatService instances over the REAL Node relay:
//   * Alice knows Bob and Carol; Bob and Carol have NEVER exchanged codes.
//   * Alice creates a group with both. The invite carries every member's
//     signature-verified bundle, so Bob and Carol auto-add each other.
//   * Every member's messages reach every other member, in the group thread,
//     with correct sender attribution — including Bob -> Carol, whose pairwise
//     session springs into existence on first use.
//   * When Bob leaves, the others are told, drop him from the member list,
//     and nothing sent afterwards reaches him.
@Tags(['integration'])
library;

import 'dart:async';
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
    port = 41000 + DateTime.now().millisecondsSinceEpoch % 20000;
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
    final dir = await Directory.systemTemp.createTemp('z_grp_$name');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    final identity = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(identity.toJson()));
    final transport =
        Transport(identity: identity, serverUrl: 'ws://127.0.0.1:$port');
    final svc = await ChatService.init(
        vault: vault, identity: identity, displayName: name, transport: transport);
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

  List<String> groupTexts(ChatService svc, String gid) => [
        for (final m in svc.messagesByChat[gid] ?? const [])
          if (m.kind == 'gtext') m.body
      ];

  String? senderOf(ChatService svc, String gid, String body) {
    for (final m in svc.messagesByChat[gid] ?? const []) {
      if (m.kind == 'gtext' && m.body == body) return m.senderName;
    }
    return null;
  }

  test('create, auto-add, cross-message, and leave — all enforced E2E',
      () async {
    final alice = await makeClient('alice');
    final bob = await makeClient('bob');
    final carol = await makeClient('carol');
    await waitUntil(
        () =>
            alice.transport.isConnected &&
            bob.transport.isConnected &&
            carol.transport.isConnected,
        what: 'clients connect');

    // Alice <-> Bob and Alice <-> Carol; Bob and Carol do NOT know each other.
    await alice.addContactFromCode(await bob.myContactCode());
    await bob.addContactFromCode(await alice.myContactCode());
    await alice.addContactFromCode(await carol.myContactCode());
    await carol.addContactFromCode(await alice.myContactCode());
    final aliceRid = alice.myRid;
    final bobRid = bob.myRid;
    final carolRid = carol.myRid;
    await Future<void>.delayed(const Duration(seconds: 1)); // hellos settle

    // Alice creates the group.
    final gid = await alice.createGroup('Trio', [bobRid, carolRid]);

    // Bob and Carol both receive it — and auto-add each other from the invite.
    await waitUntil(
        () => bob.groups.containsKey(gid) && carol.groups.containsKey(gid),
        what: 'invites arrive');
    expect(bob.groups[gid]!.name, 'Trio');
    expect(carol.groups[gid]!.name, 'Trio');
    expect(bob.contacts.containsKey(carolRid), isTrue,
        reason: 'Bob should have auto-added Carol from the invite');
    expect(carol.contacts.containsKey(bobRid), isTrue,
        reason: 'Carol should have auto-added Bob from the invite');
    expect(bob.groups[gid]!.memberRids, containsAll([aliceRid, carolRid]));
    expect(carol.groups[gid]!.memberRids, containsAll([aliceRid, bobRid]));

    // Everyone speaks; everyone hears everyone, with attribution.
    await alice.sendGroupText(gid, 'hi from alice');
    await bob.sendGroupText(gid, 'hi from bob');
    await carol.sendGroupText(gid, 'hi from carol');

    await waitUntil(
        () =>
            groupTexts(alice, gid)
                .toSet()
                .containsAll({'hi from alice', 'hi from bob', 'hi from carol'}) &&
            groupTexts(bob, gid)
                .toSet()
                .containsAll({'hi from alice', 'hi from bob', 'hi from carol'}) &&
            groupTexts(carol, gid)
                .toSet()
                .containsAll({'hi from alice', 'hi from bob', 'hi from carol'}),
        what: 'all three see all three messages');

    // Attribution: Carol sees Bob's message as from "bob" — a sender she only
    // knows through the invite's auto-added bundle.
    expect(senderOf(carol, gid, 'hi from bob'), 'bob');
    expect(senderOf(alice, gid, 'hi from carol'), 'carol');
    expect(senderOf(bob, gid, 'hi from alice'), 'alice');

    // Bob leaves. The others are told and drop him.
    await bob.leaveGroup(gid);
    await waitUntil(
        () =>
            !(alice.groups[gid]!.memberRids.contains(bobRid)) &&
            !(carol.groups[gid]!.memberRids.contains(bobRid)),
        what: 'leave propagates');
    expect(bob.groups[gid]!.left, isTrue);

    // Messages sent after the leave do not reach Bob.
    final bobCountBefore = groupTexts(bob, gid).length;
    await alice.sendGroupText(gid, 'post-leave');
    await waitUntil(
        () =>
            groupTexts(carol, gid).contains('post-leave') &&
            groupTexts(alice, gid).contains('post-leave'),
        what: 'post-leave reaches the remaining members');
    await Future<void>.delayed(const Duration(milliseconds: 600));
    expect(groupTexts(bob, gid).length, bobCountBefore,
        reason: 'Bob must receive nothing after leaving');
    expect(groupTexts(bob, gid), isNot(contains('post-leave')));
  }, timeout: const Timeout(Duration(minutes: 3)), retry: 2);
}
