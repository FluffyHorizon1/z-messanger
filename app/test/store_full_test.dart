// The relay's shared store full (PROTOCOL §12.4, `error{store_full}`): a
// temporary, global condition — nobody's envelope fits — that heals as
// mailboxes drain. The client's outbox treats it as such: it stops the pass,
// keeps every row pending, marks nothing failed, and comes back on its own
// timer rather than on the next reconnect. Run against the real relay in
// Redis mode with the store's memory limit lowered to a few megabytes.
//
// Criteria, each asserted below:
//  1. once the store is full, further messages stay pending in the outbox —
//     none is marked failed — and the outbox keeps knocking on its own timer,
//     which the relay's refusal counter shows rising with nothing new sent;
//  2. when the recipient drains the store, the retry timer alone delivers
//     everything that waited, in order, without a reconnect or a new send.
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

  late Process redis;
  late Process relay;
  late int port;
  final temps = <Directory>[];
  final services = <ChatService>[];

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

  Future<int> freePort() async {
    final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final p = probe.port;
    await probe.close();
    return p;
  }

  setUpAll(() async {
    HttpOverrides.global = null;
    final serverDir = '${Directory.current.parent.path}${Platform.pathSeparator}server';
    final redisPort = await freePort();
    redis = await Process.start('redis-server', [
      '--port', '$redisPort', '--save', '', '--appendonly', 'no', '--bind', '127.0.0.1',
      '--maxmemory', '3mb', '--maxmemory-policy', 'noeviction',
    ]);
    await Future<void>.delayed(const Duration(milliseconds: 700));
    port = await freePort();
    relay = await Process.start('node', ['server.js'], workingDirectory: serverDir, environment: {
      'PORT': '$port',
      'LOG_LEVEL': 'silent',
      'REDIS_URL': 'redis://127.0.0.1:$redisPort',
    });
    for (var i = 0; i < 60; i++) {
      try {
        final res = await (await HttpClient().getUrl(Uri.parse('http://127.0.0.1:$port/health'))).close();
        final body = await res.transform(utf8.decoder).join();
        if (res.statusCode == 200 && body.contains('"coordinator":"redis"')) return;
      } catch (_) {
        await Future<void>.delayed(const Duration(milliseconds: 100));
      }
    }
    fail('relay did not start in Redis mode');
  });

  tearDownAll(() async {
    for (final s in services) {
      s.dispose();
      await s.transport.stop();
    }
    relay.kill();
    redis.kill();
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<ChatService> start(String name) async {
    final dir = await Directory.systemTemp.createTemp('z_sfull_$name');
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

  Future<void> waitUntil(bool Function() cond, {Duration timeout = const Duration(seconds: 30), String what = ''}) async {
    final deadline = DateTime.now().add(timeout);
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) throw TimeoutException('condition not met: $what');
      await Future<void>.delayed(const Duration(milliseconds: 30));
    }
  }

  Future<int> outboxRows(ChatService svc) async => (await svc.vault.db.query('outbox')).length;

  late ChatService alice;
  late ChatService ben;
  const total = 40; // 60 KB texts → 65 536-bucket envelopes; a 3 MB store holds well under forty
  final text = List.filled(60 * 1024, 'z').join();

  test('1. once the store is full, further messages stay pending and nothing is marked failed', () async {
    alice = await start('alice');
    ben = await start('ben');
    await waitUntil(() => [alice, ben].every((s) => s.transport.isConnected && s.transport.isSenderConnected), what: 'up');
    await alice.addContactFromCode(await ben.myContactCode());
    await ben.addContactFromCode(await alice.myContactCode());
    await alice.sendText(ben.myRid, 'hello');
    await waitUntil(() => ben.messagesByChat[alice.myRid]?.length == 1, what: 'hello delivered');
    await Future<void>.delayed(const Duration(milliseconds: 1500));
    await ben.transport.stop();
    await Future<void>.delayed(const Duration(milliseconds: 300));
    for (var i = 1; i <= total; i++) {
      await alice.sendText(ben.myRid, '$i:$text');
    }
    // The store fills part-way through; the rest is refused, promptly.
    var refused = 0;
    for (var i = 0; i < 200 && refused == 0; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 100));
      refused = (await metrics())['z_store_full_total'] ?? 0;
    }
    expect(refused, greaterThan(0), reason: 'the relay refused for want of room, and counted it');
    // The outbox keeps trying on its own timer (two seconds here) while the
    // store stays full: each retry is refused again and counted, so the
    // relay's counter rises with nobody sending anything new.
    final refusedBefore = (await metrics())['z_store_full_total']!;
    await Future<void>.delayed(const Duration(seconds: 5));
    final refusedAfter = (await metrics())['z_store_full_total']!;
    expect(refusedAfter - refusedBefore, greaterThanOrEqualTo(2), reason: 'the retry timer kept knocking');
    final pending = alice.messagesByChat[ben.myRid]!.where((m) => m.status == MsgStatus.pending).length;
    expect(pending, greaterThan(0), reason: 'what did not fit is still pending');
    expect(pending, lessThan(total), reason: 'what fit was sent');
    expect(await outboxRows(alice), pending, reason: 'the pending ones are exactly the outbox rows');
    expect(alice.messagesByChat[ben.myRid]!.where((m) => m.status == -1), isEmpty, reason: 'nothing marked failed');
  });

  test('2. when the recipient drains the store, the retry delivers the rest in order', () async {
    ben.transport.start();
    await waitUntil(() => ben.messagesByChat[alice.myRid]?.length == 1 + total,
        timeout: const Duration(seconds: 90), what: 'everything reached ben');
    final bodies = ben.messagesByChat[alice.myRid]!.map((m) => m.body.split(':').first).toList();
    expect(bodies, ['hello', for (var i = 1; i <= total; i++) '$i']);
    await waitUntil(() => alice.messagesByChat[ben.myRid]!.every((m) => m.status != MsgStatus.pending), what: 'nothing pending');
    expect(await outboxRows(alice), 0);
  });
}
