// Sealed sender against the relay PROCESS, not only its stored data (16.1,
// THREAT_MODEL R21). A sealed envelope names no sender; a connection that
// authenticated has an identity; so every sealed envelope this app sends
// leaves on a connection that never authenticated. Counted from the relay's
// side: its /metrics say how many sealed envelopes arrived on connections it
// could not attribute, and that number must move by every message sent,
// while the number of sealed envelopes on attributable connections stays at
// zero.
//
// Criteria, each a test below:
//  1. every sealed envelope a conversation produces — hellos, texts,
//     receipts, the mirror to a linked device — arrives unattributable, and
//     none arrives on the authenticated link;
//  2. with the anonymous link down, a sealed send is not sent on the
//     authenticated link instead: it waits in the outbox and goes when the
//     link is back.
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
    relay = await Process.start('node', ['server.js'],
        workingDirectory: serverDir, environment: {'PORT': '$port', 'LOG_LEVEL': 'silent'});
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
    final dir = await Directory.systemTemp.createTemp('z_anon_$name');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    final id = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(id.toJson()));
    final transport = Transport(identity: id, serverUrl: 'ws://127.0.0.1:$port');
    final svc = await ChatService.init(vault: vault, identity: id, displayName: name, transport: transport);
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

  test('every sealed envelope arrives on a connection the relay cannot attribute', () async {
    final alice = await start('alice');
    final ben = await start('ben');
    await waitUntil(() => alice.transport.isConnected && ben.transport.isConnected && alice.transport.isSenderConnected && ben.transport.isSenderConnected,
        what: 'both links up on both sides');
    final before = await metrics();
    await alice.addContactFromCode(await ben.myContactCode());
    await ben.addContactFromCode(await alice.myContactCode());
    for (var i = 0; i < 5; i++) {
      await alice.sendText(ben.myRid, 'message $i');
    }
    await waitUntil(() => ben.messagesByChat[alice.myRid]?.length == 5, what: 'five delivered');
    await ben.sendText(alice.myRid, 'back');
    await waitUntil(() => alice.messagesByChat[ben.myRid]?.length == 6, what: 'reply delivered');
    // Receipts and the identity exchange ride on the same path; let them settle.
    await Future<void>.delayed(const Duration(milliseconds: 800));
    final after = await metrics();
    final sealed = after['z_sealed_total']! - before['z_sealed_total']!;
    final unattributable = after['z_sealed_unattributable_total']! - before['z_sealed_unattributable_total']!;
    expect(sealed, greaterThanOrEqualTo(6), reason: 'the conversation produced sealed envelopes');
    expect(unattributable, sealed, reason: 'every one of them arrived on an anonymous connection');
    // And the relay stored none with a sender: the queue is empty (delivered
    // live) and the attributed counter did not move.
    expect(after['z_enqueued_total']! - before['z_enqueued_total']!, sealed,
        reason: 'no unsealed envelope was sent at all');
  });

  test('with the anonymous link down, a sealed send waits rather than using the authenticated link', () async {
    final alice = await start('alice2');
    final ben = await start('ben2');
    await waitUntil(() => alice.transport.isConnected && alice.transport.isSenderConnected && ben.transport.isConnected,
        what: 'up');
    await alice.addContactFromCode(await ben.myContactCode());
    await ben.addContactFromCode(await alice.myContactCode());
    await alice.sendText(ben.myRid, 'first');
    await waitUntil(() => ben.messagesByChat[alice.myRid]?.length == 1, what: 'first delivered');
    // Bring the whole transport down and up again, then send while only the
    // authenticated link is back: the sender link's reconnect is what the
    // message waits for.
    await alice.transport.stop();
    final before = await metrics();
    alice.transport.start();
    await waitUntil(() => alice.transport.isConnected, what: 'authenticated link back');
    await alice.sendText(ben.myRid, 'second');
    await waitUntil(() => ben.messagesByChat[alice.myRid]?.length == 2, what: 'second delivered once both links are up');
    await Future<void>.delayed(const Duration(milliseconds: 300));
    final after = await metrics();
    final sealed = after['z_sealed_total']! - before['z_sealed_total']!;
    expect(after['z_sealed_unattributable_total']! - before['z_sealed_unattributable_total']!, sealed,
        reason: 'nothing sealed went on the authenticated link');
    expect(alice.messagesByChat[ben.myRid]!.last.status, isNot(MsgStatus.pending));
  });
}
