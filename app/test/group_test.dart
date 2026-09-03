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
            groupTexts(alice, gid).toSet().containsAll(
                {'hi from alice', 'hi from bob', 'hi from carol'}) &&
            groupTexts(bob, gid).toSet().containsAll(
                {'hi from alice', 'hi from bob', 'hi from carol'}) &&
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

  /// The assembled bytes of the attachment named [name] in [svc]'s copy of
  /// the group thread, or null if it never (completely) arrives.
  Future<Uint8List?> awaitGroupFile(ChatService svc, String gid, String name,
      {Duration timeout = const Duration(seconds: 25)}) async {
    final deadline = DateTime.now().add(timeout);
    while (DateTime.now().isBefore(deadline)) {
      for (final m in svc.messagesByChat[gid] ?? const []) {
        if (m.kind == 'file' && m.body == name && m.fid != null) {
          try {
            return await svc.readAttachment(m.fid!);
          } catch (_) {
            // offer known, chunks still arriving
          }
        }
      }
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
    return null;
  }

  String? fileSenderOf(ChatService svc, String gid, String name) {
    for (final m in svc.messagesByChat[gid] ?? const []) {
      if (m.kind == 'file' && m.body == name) return m.senderName;
    }
    return null;
  }

  test('group attachments reach every member; a removed member is cut off',
      () async {
    final alice = await makeClient('alice2');
    final bob = await makeClient('bob2');
    final carol = await makeClient('carol2');
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
    final bobRid = bob.myRid;
    final carolRid = carol.myRid;
    await Future<void>.delayed(const Duration(seconds: 1)); // hellos settle

    final gid = await alice.createGroup('Photos', [bobRid, carolRid]);
    await waitUntil(
        () => bob.groups.containsKey(gid) && carol.groups.containsKey(gid),
        what: 'invites arrive');

    // A 1,000,000-byte photo — three chunks at the 480 KiB chunk size — from
    // Alice reaches Bob and Carol byte-for-byte, attributed to her.
    final photo =
        Uint8List.fromList(List<int>.generate(1000000, (i) => (i * 13) % 256));
    await alice.sendGroupFile(gid, 'beach.jpg', photo, 'image/jpeg');
    final bobGot = await awaitGroupFile(bob, gid, 'beach.jpg');
    final carolGot = await awaitGroupFile(carol, gid, 'beach.jpg');
    expect(bobGot, isNotNull, reason: 'Bob never assembled the group photo');
    expect(carolGot, isNotNull,
        reason: 'Carol never assembled the group photo');
    expect(bobGot, equals(photo));
    expect(carolGot, equals(photo));
    expect(fileSenderOf(bob, gid, 'beach.jpg'), 'alice2');
    expect(fileSenderOf(carol, gid, 'beach.jpg'), 'alice2');
    // The sender keeps a local, already-complete copy.
    expect(await awaitGroupFile(alice, gid, 'beach.jpg'), equals(photo));

    // A non-admin member can send too — Carol's file reaches Alice AND Bob,
    // whose pairwise session with Carol exists only via the invite.
    final doc = Uint8List.fromList(List<int>.generate(5000, (i) => i % 251));
    await carol.sendGroupFile(gid, 'notes.txt', doc, 'text/plain');
    final aliceNotes = await awaitGroupFile(alice, gid, 'notes.txt');
    final bobNotes = await awaitGroupFile(bob, gid, 'notes.txt');
    expect(aliceNotes, equals(doc));
    expect(bobNotes, equals(doc));
    expect(fileSenderOf(bob, gid, 'notes.txt'), 'carol2');

    // Alice removes Bob. The next photo must not be decryptable by Bob: he
    // never receives the offer (so never the file key), and the members'
    // chunks are not queued for him at all.
    await alice.removeGroupMember(gid, bobRid);
    await waitUntil(
        () =>
            bob.groups[gid]!.left &&
            !carol.groups[gid]!.memberRids.contains(bobRid),
        what: 'removal propagates');
    final secret =
        Uint8List.fromList(List<int>.generate(30000, (i) => (i * 7) % 256));
    await alice.sendGroupFile(gid, 'secret.png', secret, 'image/png');
    expect(await awaitGroupFile(carol, gid, 'secret.png'), equals(secret));
    expect(fileSenderOf(carol, gid, 'secret.png'), 'alice2');
    expect(
        await awaitGroupFile(bob, gid, 'secret.png',
            timeout: const Duration(seconds: 2)),
        isNull,
        reason: 'a removed member must not be able to obtain the file');
    expect(
        (bob.messagesByChat[gid] ?? const [])
            .where((m) => m.kind == 'file')
            .map((m) => m.body),
        isNot(contains('secret.png')));
  }, timeout: const Timeout(Duration(minutes: 3)), retry: 2);
}
