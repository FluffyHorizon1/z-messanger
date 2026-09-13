// A group id is also a thread key, and the sender chose it.
//
// §11 says a group id is `"g" || b64url(12 random bytes)` — `g` and sixteen
// more characters. The client generated exactly that and accepted anything:
// `_applyGroupInvite` took any non-empty string.
//
// The id is not just a label. It is the key messages are filed under
// (`messages.rid`), and the chat screen decides what a conversation IS by
// looking it up: `groups[rid] != null` means group. A routing id is 43
// base64url characters, so the two can only collide if nobody checks — and
// nobody did.
//
// So a contact could send a `ginvite` naming ANOTHER contact's routing id.
// Measured, before the fix, with three real clients through a real relay:
//
//   GROUPS=[D5R9H30EV96KmLg6SV70gu69yv_rXPOYJbz4Kfmhf8k]
//   HIJACKED=true name=Alice (verified)
//   THREAD=[null:the real Alice,
//           null:{"k":"added_to_by","by":"Mallory","name":"Alice (verified)"},
//           Mallory:transfer the money to this account]
//
// Alice's conversation, with Alice's real message still in it, now titled
// whatever Mallory typed and subtitled "2 members". The injected message does
// carry Mallory's name, and a system message says she added you — so this is
// not a clean impersonation. What it is:
//
//   * the thread's title and membership are a third party's to choose;
//   * every banner the chat screen draws ONLY for a 1:1 stops being drawn —
//     the device-list warning about Alice, the transparency log's conflict
//     hold, the disappearing-messages control. The service still refuses the
//     send (`kt.sendsHeld` is checked in `_sendInner`, not only on screen),
//     so what the victim gets is messages that do not go and no explanation
//     of why, which is the worst of both.
//
// Criteria, each a test below:
//  1. a `ginvite` naming a contact's routing id is refused, and that
//     conversation stays what it was;
//  2. so is anything else that is not a group id — a bare word, a path, the
//     receiver's own routing id, sixteen characters without the `g`;
//  3. a group planted by an older build is dropped when the vault opens, and
//     the conversation underneath it comes back;
//  4. and an honest group is untouched: made, joined, messaged.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  late Process relay;
  late int port;
  final temps = <Directory>[];
  final live = <ChatService>[];

  setUpAll(() async {
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

  final dirs = <String, Directory>{};

  Future<ChatService> start(String name, {ZIdentity? identity}) async {
    final d = dirs[name] ??
        await Directory.systemTemp.createTemp('z_gid_$name').then((x) {
          temps.add(x);
          dirs[name] = x;
          return x;
        });
    final vault = await Vault.open(rootOverride: d);
    final stored = await vault.kvGet('identity');
    final id = identity ??
        (stored == null
            ? await ZIdentity.generate()
            : await ZIdentity.fromJson(
                (jsonDecode(stored) as Map).cast<String, Object?>()));
    await vault.kvPut('identity', jsonEncode(id.toJson()));
    final svc = await ChatService.init(
        vault: vault,
        identity: id,
        displayName: name,
        transport: Transport(identity: id, serverUrl: 'ws://127.0.0.1:$port'));
    live.add(svc);
    return svc;
  }

  Future<void> waitUntil(bool Function() c,
      {Duration timeout = const Duration(seconds: 25), String what = ''}) async {
    final end = DateTime.now().add(timeout);
    while (!c()) {
      if (DateTime.now().isAfter(end)) throw StateError('not met: $what');
      await Future<void>.delayed(const Duration(milliseconds: 30));
    }
  }

  /// A member entry as `_inviteData` builds one.
  Future<Map<String, Object?>> member(ChatService s, String shownAs) async => {
        'b': (await s.identity.bundle(displayName: shownAs)).toJson(),
        'n': shownAs,
      };

  test('1. a contact cannot name another contact as a group', () async {
    final victim = await start('Victim1');
    final alice = await start('Alice1');
    final mallory = await start('Mallory1');
    await waitUntil(
        () =>
            victim.transport.isConnected &&
            alice.transport.isConnected &&
            mallory.transport.isConnected,
        what: 'connected');
    await victim.addContactFromCode(await alice.myContactCode());
    await alice.addContactFromCode(await victim.myContactCode());
    await victim.addContactFromCode(await mallory.myContactCode());
    await mallory.addContactFromCode(await victim.myContactCode());
    await Future<void>.delayed(const Duration(milliseconds: 600));

    await alice.sendText(victim.myRid, 'the real Alice');
    await waitUntil(() => (victim.messagesByChat[alice.myRid] ?? []).isNotEmpty,
        what: 'the victim has a conversation with Alice');
    final before = victim.messagesByChat[alice.myRid]!.length;

    await mallory.debugSendRawInner(
        victim.myRid,
        InnerMessage(kind: 'ginvite', mid: newMessageId(), ts: 1, data: {
          'gid': alice.myRid,
          'name': 'Alice (verified)',
          'ver': 1,
          'members': [
            await member(mallory, 'Alice'),
            await member(victim, 'Victim'),
          ],
        }));
    await mallory.debugSendRawInner(
        victim.myRid,
        InnerMessage(kind: 'gmsg', mid: newMessageId(), ts: 2, data: {
          'gid': alice.myRid,
          'body': 'transfer the money to this account',
        }));
    await Future<void>.delayed(const Duration(seconds: 2));

    expect(victim.groups[alice.myRid], isNull,
        reason: "a contact's routing id is not a group id");
    expect(victim.groups, isEmpty);
    expect(victim.contacts[alice.myRid]?.name, 'Alice1',
        reason: 'and the conversation is still the one it was');
    await victim.loadMessages(alice.myRid);
    expect(victim.messagesByChat[alice.myRid]!.length, before,
        reason: 'nothing was added to it: '
            '${victim.messagesByChat[alice.myRid]!.map((m) => m.body)}');
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('2. nor anything else that is not a group id', () async {
    final victim = await start('Victim2');
    final mallory = await start('Mallory2');
    await waitUntil(
        () => victim.transport.isConnected && mallory.transport.isConnected,
        what: 'connected');
    await victim.addContactFromCode(await mallory.myContactCode());
    await mallory.addContactFromCode(await victim.myContactCode());
    await Future<void>.delayed(const Duration(milliseconds: 600));

    final bad = <String>[
      'lunch',
      '../escaped',
      victim.myRid, // my own conversation with myself
      mallory.myRid, // the sender's own routing id
      b64url(randomBytes(12)), // the right length, no `g`
      'gshort',
      'g${b64url(randomBytes(16))}', // a `g` and too many characters
      '',
    ];
    for (final gid in bad) {
      await mallory.debugSendRawInner(
          victim.myRid,
          InnerMessage(kind: 'ginvite', mid: newMessageId(), ts: 1, data: {
            'gid': gid,
            'name': 'nope',
            'ver': 1,
            'members': [
              await member(mallory, 'Mallory'),
              await member(victim, 'Victim'),
            ],
          }));
    }
    await Future<void>.delayed(const Duration(seconds: 3));
    expect(victim.groups, isEmpty,
        reason: 'not one of them made a group: ${victim.groups.keys}');
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('3. a group an older build accepted is dropped when the vault opens',
      () async {
    final victim = await start('Victim3');
    final alice = await start('Alice3');
    await waitUntil(
        () => victim.transport.isConnected && alice.transport.isConnected,
        what: 'connected');
    await victim.addContactFromCode(await alice.myContactCode());
    await alice.addContactFromCode(await victim.myContactCode());
    await Future<void>.delayed(const Duration(milliseconds: 600));
    await alice.sendText(victim.myRid, 'still the real Alice');
    await waitUntil(() => (victim.messagesByChat[alice.myRid] ?? []).isNotEmpty,
        what: 'a conversation with Alice');

    // Exactly what a build before the check would have written.
    final honest = newGroupId();
    await victim.vault.kvPut(
        'groups',
        jsonEncode([
          {
            'gid': alice.myRid,
            'name': 'Alice (verified)',
            'admin': 'someone',
            'members': <String>[],
            'ver': 1,
          },
          {
            'gid': honest,
            'name': 'Field team',
            'admin': 'someone',
            'members': <String>[],
            'ver': 1,
          },
        ]));
    final id = victim.identity;
    victim.dispose();
    await victim.transport.stop();
    live.remove(victim);
    await victim.vault.db.close();

    final again = await start('Victim3', identity: id);
    expect(again.groups.containsKey(alice.myRid), isFalse,
        reason: 'the planted group is gone');
    expect(again.groups.containsKey(honest), isTrue,
        reason: 'and an honest one beside it is not');
    await again.loadMessages(alice.myRid);
    expect(again.contacts[alice.myRid]?.name, 'Alice3',
        reason: 'the conversation underneath it is back to being hers');
    expect(again.messagesByChat[alice.myRid], isNotEmpty);
    // And it stays gone: the sweep rewrote what is stored.
    expect(
        (jsonDecode(await again.vault.kvGet('groups') ?? '[]') as List)
            .map((e) => (e as Map)['gid'])
            .toList(),
        [honest]);
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('4. an honest group is untouched', () async {
    final ann = await start('Ann4');
    final ben = await start('Ben4');
    await waitUntil(
        () => ann.transport.isConnected && ben.transport.isConnected,
        what: 'connected');
    await ann.addContactFromCode(await ben.myContactCode());
    await ben.addContactFromCode(await ann.myContactCode());
    await Future<void>.delayed(const Duration(milliseconds: 600));

    final gid = await ann.createGroup('Field team', [ben.myRid]);
    expect(isWellFormedGid(gid), isTrue,
        reason: 'what this app generates is what it accepts: $gid');
    await waitUntil(() => ben.groups[gid] != null,
        what: 'Ben joined the group');
    expect(ben.groups[gid]!.name, 'Field team');
    await ann.sendGroupText(gid, 'meeting moved to Friday');
    await waitUntil(
        () => (ben.messagesByChat[gid] ?? [])
            .any((m) => m.body == 'meeting moved to Friday'),
        what: 'Ben got the group message');
  }, timeout: const Timeout(Duration(minutes: 2)));
}
