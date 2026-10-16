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
//     link is back;
//  3. a send to a key of small order — which agrees all zeros with every
//     ephemeral, so the envelope would be open to anyone holding it, the
//     relay first — is refused before anything leaves or changes: nothing
//     queued, unsealed or otherwise, and the conversation as it was, so the
//     next message, with an honest key back, arrives with no gap behind it;
//  4. holding such a key for someone does not cost what they send: their
//     messages are taken and acknowledged, and nothing goes to that key —
//     the post-quantum offer their first message prompts included;
//  5. a contact code carrying such a key is refused at the door, though its
//     owner signed it, and nothing of it is kept.
@Tags(['integration'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' show Ed25519;
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
    // /metrics needs a bearer token now (P1-14); the relay is spawned with
    // METRICS_TOKEN set to this value below.
    final req = await HttpClient().getUrl(Uri.parse('http://127.0.0.1:$port/metrics'));
    req.headers.set('authorization', 'Bearer z-apptest-metrics');
    final res = await req.close();
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
        workingDirectory: serverDir, environment: {'PORT': '$port', 'LOG_LEVEL': 'silent', 'METRICS_TOKEN': 'z-apptest-metrics'});
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

  Future<void> waitUntil(FutureOr<bool> Function() cond, {Duration timeout = const Duration(seconds: 25), String what = ''}) async {
    final deadline = DateTime.now().add(timeout);
    while (!await cond()) {
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

  // u = 0: the point every spelling of small order agrees with (PROTOCOL §8;
  // protocol/test/sealed_test.dart runs all fourteen through `seal`).
  final smallOrder = Uint8List(32);

  Future<List<Map<String, Object?>>> outboxFor(ChatService s, String rid) =>
      s.vault.db.query('outbox', where: 'rid = ?', whereArgs: [rid]);

  int skippedKeys(ChatService s, String rid) => [
        for (final x in s.debugConversation(rid)!.sessions.values)
          x.ratchet.skipped.length
      ].fold(0, (a, b) => a + b);

  test('a send to a key of small order is refused before anything leaves or changes', () async {
    final alice = await start('alice3');
    final ben = await start('ben3');
    await waitUntil(() => alice.transport.isConnected && alice.transport.isSenderConnected && ben.transport.isConnected,
        what: 'up');
    await alice.addContactFromCode(await ben.myContactCode());
    await ben.addContactFromCode(await alice.myContactCode());
    await alice.sendText(ben.myRid, 'first');
    await waitUntil(() => ben.messagesByChat[alice.myRid]?.length == 1, what: 'first delivered');
    await waitUntil(() async => (await outboxFor(alice, ben.myRid)).isEmpty, what: 'alice has sent everything');
    // Let the identity exchange and receipts settle, so nothing else moves
    // the conversation while the refusal is looked at.
    await Future<void>.delayed(const Duration(milliseconds: 800));
    final honest = alice.debugSealKey(ben.myRid)!;
    final before = jsonEncode(alice.debugConversation(ben.myRid)!.toJson(includeSkipped: false));
    final skippedBefore = skippedKeys(ben, alice.myRid);

    alice.debugSetSealKey(ben.myRid, smallOrder);
    await expectLater(alice.sendText(ben.myRid, 'refused'), throwsA(isA<SealRefusedException>()));
    expect(await outboxFor(alice, ben.myRid), isEmpty,
        reason: 'nothing queued: not the envelope, and not the payload unsealed in its place');
    expect(jsonEncode(alice.debugConversation(ben.myRid)!.toJson(includeSkipped: false)), before,
        reason: 'the ratchet did not step for a message that never left');
    expect(alice.messagesByChat[ben.myRid]!.where((m) => m.body == 'refused'), isEmpty,
        reason: 'no row for a message that was not sent');

    alice.debugSetSealKey(ben.myRid, honest);
    await alice.sendText(ben.myRid, 'after');
    await waitUntil(() => ben.messagesByChat[alice.myRid]?.any((m) => m.body == 'after') ?? false,
        what: 'the next message, with the honest key back');
    expect(skippedKeys(ben, alice.myRid), skippedBefore,
        reason: 'it arrived on the index the refused one would have used: no key skipped');
  });

  test('a key of small order held for someone does not cost what they send', () async {
    final s1 = await start('p4a');
    final s2 = await start('p4b');
    // Roles follow routing-id order: the lower id opens the session with its
    // hello, and the other side, on hearing it, offers its post-quantum key
    // on the receive path — sealed to the key it holds for the sender.
    final initiator = s1.myRid.compareTo(s2.myRid) < 0 ? s1 : s2;
    final offerer = identical(initiator, s1) ? s2 : s1;
    await waitUntil(() => s1.transport.isConnected && s1.transport.isSenderConnected && s2.transport.isConnected && s2.transport.isSenderConnected,
        what: 'up');
    await offerer.addContactFromCode(await initiator.myContactCode());
    offerer.debugSetSealKey(initiator.myRid, smallOrder);
    final before = await metrics();
    await initiator.addContactFromCode(await offerer.myContactCode());
    await initiator.sendText(offerer.myRid, 'hello there');
    await waitUntil(() => offerer.messagesByChat[initiator.myRid]?.any((m) => m.body == 'hello there') ?? false,
        what: 'their message taken');
    // Everything they sent was acknowledged: nothing waits at the relay for
    // a retry that would fail the same way.
    await waitUntil(() async => (await metrics())['z_queued_envelopes'] == 0, what: 'nothing left at the relay');
    expect(offerer.messagesByChat[initiator.myRid]!.where((m) => m.kind == 'system'), isEmpty,
        reason: 'no message of theirs was dropped as one that could not be read');
    expect(await outboxFor(offerer, initiator.myRid), isEmpty,
        reason: 'nothing queued to the key, the offer included');
    final after = await metrics();
    expect(after['z_sealed_total']! - before['z_sealed_total']!,
        after['z_sealed_unattributable_total']! - before['z_sealed_unattributable_total']!,
        reason: 'and nothing unsealed or attributed went in its place');
  });

  test('a contact code carrying a key of small order is refused at the door', () async {
    final alice = await start('alice5');
    final mal = await start('mal5');
    final code = await mal.myContactCode();
    final j = jsonDecode(utf8.decode(unb64url(code.substring(4)))) as Map<String, Object?>;
    final ed = await Ed25519().newKeyPairFromSeed(mal.identity.edSeed);
    j['x'] = b64(smallOrder);
    j['sig'] = b64(Uint8List.fromList(
        (await Ed25519().sign([...utf8.encode(bindContext), ...smallOrder], keyPair: ed)).bytes));
    final hostile = code.substring(0, 4) + b64url(utf8.encode(jsonEncode(j)));
    await expectLater(alice.addContactFromCode(hostile),
        throwsA(isA<ContactCodeRefused>().having((e) => e.kind, 'kind', ContactCodeRefusal.invalidCode)));
    expect(alice.contacts.containsKey(mal.myRid), isFalse);
    expect(await outboxFor(alice, mal.myRid), isEmpty);
    // Mal's own code, unaltered, is still read: the refusal is the key's.
    await alice.addContactFromCode(code);
    expect(alice.contacts.containsKey(mal.myRid), isTrue);
  });
}
