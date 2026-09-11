// A full mailbox at the relay (PROTOCOL §12.4, `error{queue_full}`) is that
// recipient's problem for as long as they stay offline, and nobody else's:
// the envelope that did not fit waits in the outbox, still pending, the rest
// of the outbox keeps flowing to everyone else, and once the recipient has
// drained their mailbox the waiting envelope goes without anyone touching it.
// Run against the real relay with its count cap lowered to six.
//
// Criteria, each asserted below:
//  1. the seventh message to an offline recipient is held, not lost and not
//     marked failed — its status stays pending;
//  2. a message to another contact goes through while it is held;
//  3. when the recipient returns and drains, the held message is delivered
//     by the retry, in order, without a reconnect or a new send.
@Tags(['integration'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/models.dart';
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
  const cap = 6;

  Future<Map<String, int>> metrics() async {
    final res = await (await HttpClient().getUrl(Uri.parse('http://127.0.0.1:$port/metrics'))).close();
    final body = await res.transform(utf8.decoder).join();
    final out = <String, int>{};
    for (final line in body.split('\n')) {
      final m = RegExp(r'^(z_[a-z_]+) (\d+)$').firstMatch(line);
      if (m != null) out[m.group(1)!] = int.parse(m.group(2)!);
    }
    return out;
  }

  setUpAll(() async {
    HttpOverrides.global = null;
    final serverDir = '${Directory.current.parent.path}${Platform.pathSeparator}server';
    final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    port = probe.port;
    await probe.close();
    relay = await Process.start('node', ['server.js'], workingDirectory: serverDir, environment: {
      'PORT': '$port',
      'LOG_LEVEL': 'silent',
      'MAX_QUEUE_MSGS_PER_USER': '$cap',
    });
    for (var i = 0; i < 60; i++) {
      try {
        final res = await (await HttpClient().getUrl(Uri.parse('http://127.0.0.1:$port/health'))).close();
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
      s.dispose();
      await s.transport.stop();
    }
    relay.kill();
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<ChatService> start(String name) async {
    final dir = await Directory.systemTemp.createTemp('z_qfull_$name');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    final id = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(id.toJson()));
    final transport = Transport(identity: id, serverUrl: 'ws://127.0.0.1:$port');
    final svc = await ChatService.init(vault: vault, identity: id, displayName: name, transport: transport);
    svc.outboxRetryDelay = const Duration(seconds: 2);
    services.add(svc);
    return svc;
  }

  Future<void> waitUntil(bool Function() cond, {Duration timeout = const Duration(seconds: 25), String what = ''}) async {
    final deadline = DateTime.now().add(timeout);
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) throw TimeoutException('condition not met: $what');
      await Future<void>.delayed(const Duration(milliseconds: 30));
    }
  }

  Future<int> outboxRowsFor(ChatService svc, String rid) async =>
      (await svc.vault.db.query('outbox', where: 'rid = ?', whereArgs: [rid])).length;

  late ChatService alice;
  late ChatService ben;
  late ChatService carol;

  test('1. the envelope that does not fit is held, still pending, not marked failed', () async {
    alice = await start('alice');
    ben = await start('ben');
    carol = await start('carol');
    await waitUntil(
        () => [alice, ben, carol].every((s) => s.transport.isConnected && s.transport.isSenderConnected),
        what: 'everyone up');
    await alice.addContactFromCode(await ben.myContactCode());
    await ben.addContactFromCode(await alice.myContactCode());
    await alice.addContactFromCode(await carol.myContactCode());
    await carol.addContactFromCode(await alice.myContactCode());
    await alice.sendText(ben.myRid, 'hello ben');
    await alice.sendText(carol.myRid, 'hello carol');
    await waitUntil(() => ben.messagesByChat[alice.myRid]?.length == 1, what: 'ben has hello');
    await waitUntil(() => carol.messagesByChat[alice.myRid]?.length == 1, what: 'carol has hello');
    // Let the first-contact exchange (keys, receipts) drain from Ben's mailbox.
    await Future<void>.delayed(const Duration(milliseconds: 1500));

    // Ben goes away; Alice writes seven. The relay holds six for him and
    // refuses the seventh, which stays in Alice's outbox as pending.
    await ben.transport.stop();
    await Future<void>.delayed(const Duration(milliseconds: 300));
    final before = await metrics();
    for (var i = 1; i <= cap + 1; i++) {
      await alice.sendText(ben.myRid, 'while away $i');
    }
    var refused = 0;
    for (var i = 0; i < 100 && refused < 1; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 100));
      refused = (await metrics())['z_refused_total']! - before['z_refused_total']!;
    }
    expect(refused, 1, reason: 'the relay refused exactly the seventh');
    await waitUntil(() => alice.messagesByChat[ben.myRid]!.where((m) => m.status == MsgStatus.pending).length == 1,
        what: 'exactly one message still pending');
    expect(alice.messagesByChat[ben.myRid]!.last.body, 'while away ${cap + 1}');
    expect(alice.messagesByChat[ben.myRid]!.last.status, MsgStatus.pending);
    expect(await outboxRowsFor(alice, ben.myRid), 1, reason: 'the refused envelope waits in the outbox');
    expect(alice.messagesByChat[ben.myRid]!.where((m) => m.status == -1), isEmpty, reason: 'nothing marked failed');
  });

  test('2. a message to another contact goes through while it is held', () async {
    await alice.sendText(carol.myRid, 'still here');
    await waitUntil(() => carol.messagesByChat[alice.myRid]?.length == 2, what: 'carol still reachable');
    expect(await outboxRowsFor(alice, ben.myRid), 1, reason: "ben's envelope is still waiting");
  });

  test('3. when the recipient returns and drains, the retry delivers the held envelope in order', () async {
    // Alice neither reconnects nor sends anything new: the retry timer
    // (two seconds here, a minute in the app) is what moves it.
    ben.transport.start();
    await waitUntil(() => ben.messagesByChat[alice.myRid]?.length == 1 + cap + 1,
        timeout: const Duration(seconds: 40), what: 'all seven reached ben');
    expect(ben.messagesByChat[alice.myRid]!.map((m) => m.body).toList(),
        ['hello ben', for (var i = 1; i <= cap + 1; i++) 'while away $i']);
    await waitUntil(() => alice.messagesByChat[ben.myRid]!.every((m) => m.status != MsgStatus.pending),
        what: 'nothing pending at alice');
    expect(await outboxRowsFor(alice, ben.myRid), 0);
  });
}
