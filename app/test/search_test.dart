// Message search (7.6). Search runs against the encrypted vault, decrypting
// bodies in memory only. These tests build a service with a few conversations,
// then assert matches across direct text, group text and attachment names —
// and that the on-disk cells stay sealed (the plaintext is never persisted).
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
    final dir = await Directory.systemTemp.createTemp('z_search_$name');
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
      {Duration timeout = const Duration(seconds: 25)}) async {
    final deadline = DateTime.now().add(timeout);
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met');
      }
      await Future<void>.delayed(const Duration(milliseconds: 30));
    }
  }

  test('search finds direct text, group text and attachment names', () async {
    final me = await makeClient('me');
    final alice = await makeClient('alice');
    final bob = await makeClient('bob');
    await waitUntil(() =>
        me.transport.isConnected &&
        alice.transport.isConnected &&
        bob.transport.isConnected);

    for (final other in [alice, bob]) {
      await me.addContactFromCode(await other.myContactCode());
      await other.addContactFromCode(await me.myContactCode());
    }
    final aliceRid = alice.myRid, bobRid = bob.myRid;
    await Future<void>.delayed(const Duration(seconds: 1));

    // Direct messages both ways.
    await me.sendText(aliceRid, 'the quarterly penguin report is ready');
    await alice.sendText(me.myRid, 'thanks, sending the PENGUIN photos now');
    await me.sendText(bobRid, 'lunch tomorrow?');
    await me.sendFile(aliceRid, 'penguin-habitat.pdf',
        Uint8List.fromList(List<int>.filled(2048, 3)), 'application/pdf');

    // A group message.
    final gid = await me.createGroup('Field team', [aliceRid, bobRid]);
    await waitUntil(() => me.groups.containsKey(gid));
    await me.sendGroupText(gid, 'penguin sightings up this week');

    // Let inbound settle so the reply from Alice is stored too.
    await waitUntil(() => (me.messagesByChat[aliceRid] ?? [])
        .any((m) => !m.outgoing && m.body.contains('photos')));

    final hits = await me.searchMessages('penguin');
    final bodies = hits.map((h) => h.snippet.toLowerCase()).toList();
    // Direct outgoing, direct incoming, the attachment name, and the group msg.
    expect(hits.any((h) => h.rid == aliceRid && h.kind == 'text' && h.outgoing),
        isTrue,
        reason: 'own direct text');
    expect(
        hits.any((h) => h.rid == aliceRid && h.kind == 'text' && !h.outgoing),
        isTrue,
        reason: 'received direct text');
    expect(hits.any((h) => h.kind == 'file' && h.snippet.contains('penguin')),
        isTrue,
        reason: 'attachment name');
    expect(hits.any((h) => h.rid == gid && h.isGroup), isTrue,
        reason: 'group text');
    // The unrelated message is not a hit.
    expect(bodies.every((b) => !b.contains('lunch')), isTrue);

    // Case-insensitive, and a non-match returns nothing.
    expect((await me.searchMessages('PENGUIN')).length, hits.length);
    expect(await me.searchMessages('platypus'), isEmpty);
    expect(await me.searchMessages('   '), isEmpty);
  }, timeout: const Timeout(Duration(minutes: 2)), retry: 2);

  test('search decrypts in memory only — stored cells stay sealed', () async {
    final me = await makeClient('sealed');
    final pal = await makeClient('pal');
    await waitUntil(
        () => me.transport.isConnected && pal.transport.isConnected);
    await me.addContactFromCode(await pal.myContactCode());
    await pal.addContactFromCode(await me.myContactCode());
    await Future<void>.delayed(const Duration(seconds: 1));

    const secret = 'xyzzy-marker-42';
    await me.sendText(pal.myRid, 'a message containing $secret here');
    expect(await me.searchMessages(secret), isNotEmpty);

    // The raw stored body must not contain the plaintext marker anywhere.
    final rows = await me.vault.db.query('messages',
        columns: ['enc_body'], where: 'kind = ?', whereArgs: ['text']);
    for (final r in rows) {
      expect((r['enc_body'] as String).contains(secret), isFalse,
          reason: 'plaintext leaked into a stored cell');
    }
  }, timeout: const Timeout(Duration(minutes: 2)), retry: 2);
}
