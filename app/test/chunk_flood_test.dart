// A file chunk is the one inbound thing with nobody to hold responsible.
//
// It travels OUTSIDE the ratchet, sealed under its own file key, and its MAC
// is checkable only with key material that arrives in the offer. So before
// the offer is here, a chunk is a bag of bytes addressed to this mailbox by
// whoever knows the routing id — which is anyone holding the contact code,
// and that code is meant to be handed out. It said so on the contact screen:
// "someone who copies it can add you, and that is all".
//
// It was not all. Every chunk was stored unconditionally, under any `fid`,
// at any index, however many arrived — and then relayed to every one of the
// receiver's own linked devices, so a stranger's junk became N envelopes the
// victim's phone emitted on their behalf. Nothing ever swept a chunk whose
// offer never came.
//
// Criteria, each a test below:
//  1. chunks for an offer this device has not seen are HELD, bounded, and
//     oldest-first out — so a flood costs a fixed amount of storage and no
//     more;
//  2. an unexplained chunk is not relayed to my own devices: a stranger
//     cannot make my phone send envelopes;
//  3. a chunk that does not fit the offer it names — an index outside the
//     range, or a file already assembled — is not stored;
//  4. and none of that breaks the case it exists for: chunks that arrive
//     BEFORE their offer still assemble, and still reach my other devices,
//     once the offer explains them.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

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
    HttpOverrides.global = null;
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
      await s.transport.stop();
      await s.vault.db.close();
    }
    relay.kill();
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<ChatService> victim(String name) async {
    final dir = await Directory.systemTemp.createTemp('z_flood_');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    final me = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(me.toJson()));
    final transport =
        Transport(identity: me, serverUrl: 'ws://127.0.0.1:$port');
    final svc = await ChatService.init(
        vault: vault, identity: me, displayName: name, transport: transport);
    live.add(svc);
    for (var i = 0; i < 60 && !transport.isConnected; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    return svc;
  }

  /// A chunk envelope, as anyone who knows a routing id can build one: the
  /// wire shape is public and nothing in it is signed.
  ///
  /// The ids are the shape §7 specifies (`file_id_test.dart` covers the ones
  /// that are not, which are refused before they are held). Matching a shape
  /// costs an attacker nothing, so the cap below is what actually bounds a
  /// flood and this test must not be allowed to pass because of the other
  /// check.
  String junkChunk(String fid, int idx) => base64Encode(utf8.encode(jsonEncode({
        'v': 1,
        't': 'f',
        'fid': fid,
        'idx': idx,
        'ct': b64(Uint8List.fromList(List.filled(64, 7))),
        'mac': b64(Uint8List.fromList(List.filled(32, 9))),
      })));

  Future<int> chunkCount(ChatService svc) async =>
      firstIntValue(await svc.vault.db.rawQuery('SELECT COUNT(*) FROM chunks')) ??
      0;

  Future<void> flood(ChatService svc, int n, {String? fid}) async {
    final rid = await svc.identity.routingId();
    final sender = await RelayClient.connect(
        'ws://127.0.0.1:$port', await ZIdentity.generate());
    // Paced: the relay rate-limits a sender (RATE_PER_SEC), which is part of
    // the defence and not what this is testing. An attacker has all the time
    // in the world, so the interesting question is what the DEVICE does with
    // what does get through.
    for (var i = 0; i < n; i++) {
      try {
        await sender.send(
            to: rid,
            id: newMessageId(),
            payload: junkChunk(
                fid ?? b64url(randomBytes(12)), fid == null ? 0 : i));
      } on RelayException {
        await Future<void>.delayed(const Duration(seconds: 1));
      }
      if (i % 40 == 39) {
        await Future<void>.delayed(const Duration(milliseconds: 700));
      }
    }
    await sender.close();
    for (var i = 0; i < 80; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 100));
      if (await chunkCount(svc) >= ChatService.maxHeldChunks) break;
    }
    await Future<void>.delayed(const Duration(milliseconds: 600));
  }

  test('1. a flood of chunks nobody offered is bounded', () async {
    final me = await victim('Me');
    expect(await chunkCount(me), 0);
    await flood(me, ChatService.maxHeldChunks + 60);
    final held = await chunkCount(me);
    expect(held, lessThanOrEqualTo(ChatService.maxHeldChunks),
        reason: 'unexplained chunks are held, and the holding is bounded');
    expect(held, greaterThan(0),
        reason: 'but they are held, because a chunk may precede its offer');
  }, timeout: const Timeout(Duration(minutes: 4)));

  test('2. an unexplained chunk is never relayed to my own devices', () async {
    // This account has a linked laptop, so the fan-out has somewhere to go —
    // without one, `_sync` is null and this would pass for the wrong reason.
    // What is counted is what ARRIVES in the laptop's mailbox, not what sits
    // in the outbox: the outbox drains, so counting it measures the timing of
    // the flusher rather than the behaviour under test.
    final me = await victim('Me');
    final account = await me.accountIdentity();
    final laptop = await ZIdentity.generate();
    await me.addMyDevice(await account.signDeviceCert(
        deviceEdPub: laptop.edPub,
        deviceXPub: laptop.xPub,
        deviceId: 'laptop'));

    Future<int> drainLaptop() async {
      final c = await RelayClient.connect('ws://127.0.0.1:$port', laptop);
      final got = <RelayInbound>[];
      final sub = c.messages.listen(got.add);
      await Future<void>.delayed(const Duration(milliseconds: 900));
      for (final e in got) {
        c.ackReceived(id: e.id, from: e.from);
      }
      await Future<void>.delayed(const Duration(milliseconds: 300));
      await sub.cancel();
      await c.close();
      return got.length;
    }

    // Linking itself sends the laptop its share of state; clear it, so what
    // arrives afterwards is the flood's doing and nothing else.
    for (var i = 0; i < 10; i++) {
      await me.flushOutbox();
      if (await drainLaptop() == 0) break;
    }

    await flood(me, 40);
    expect(await chunkCount(me), greaterThan(0), reason: 'they did arrive');
    await me.flushOutbox();
    expect(await drainLaptop(), 0,
        reason: 'a stranger must not make this phone emit envelopes');
  }, timeout: const Timeout(Duration(minutes: 4)));

  test('3. a chunk that does not fit the offer it names is not stored',
      () async {
    final me = await victim('Me');
    // An offer as a real one is recorded: over the ratchet, so this fid is
    // one a contact really sent, with a shape that bounds what belongs to it.
    await me.vault.db.insert('files', {
      'fid': 'real',
      'rid': 'peer',
      'mid': 'm1',
      'enc_meta': await me.vault.seal(jsonEncode({'name': 'a.bin'})),
      'complete': 0,
      'got_chunks': 0,
      'total_chunks': 3,
    });
    final rid = await me.identity.routingId();
    final sender = await RelayClient.connect(
        'ws://127.0.0.1:$port', await ZIdentity.generate());
    for (final idx in [3, 99, -1, 1000000]) {
      await sender.send(
          to: rid, id: newMessageId(), payload: junkChunk('real', idx));
    }
    await sender.close();
    await Future<void>.delayed(const Duration(seconds: 2));
    final stored = await me.vault.db
        .query('chunks', where: 'fid = ?', whereArgs: ['real']);
    expect(stored, isEmpty,
        reason: 'an index outside the offer is not a chunk of that file');

    // And a file already assembled needs nothing more.
    await me.vault.db.update('files', {'complete': 1},
        where: 'fid = ?', whereArgs: ['real']);
    final again = await RelayClient.connect(
        'ws://127.0.0.1:$port', await ZIdentity.generate());
    await again.send(to: rid, id: newMessageId(), payload: junkChunk('real', 0));
    await again.close();
    await Future<void>.delayed(const Duration(seconds: 2));
    expect(
        await me.vault.db.query('chunks', where: 'fid = ?', whereArgs: ['real']),
        isEmpty);
  }, timeout: const Timeout(Duration(minutes: 4)));

  test('4. a chunk that arrives before its offer still assembles', () async {
    // The case the holding exists for, end to end and unchanged: a real
    // attachment whose chunks reach the recipient before the offer does.
    final alice = await victim('Alice');
    final bob = await victim('Bob');
    final bobCode = await bob.myContactCode();
    final aliceCode = await alice.myContactCode();
    await alice.addContactFromCode(bobCode, alias: 'Bob');
    final aliceRid = (await bob.addContactFromCode(aliceCode, alias: 'Alice')).rid;

    final bytes = Uint8List.fromList(List.generate(9000, (i) => i % 251));
    final bobRid = await bob.identity.routingId();
    await alice.sendFile(bobRid, 'note.bin', bytes, 'application/octet-stream');
    for (var i = 0; i < 60; i++) {
      await alice.flushOutbox();
      final done = await bob.vault.db
          .query('files', where: 'complete = 1', whereArgs: []);
      if (done.isNotEmpty) break;
      await Future<void>.delayed(const Duration(milliseconds: 200));
    }
    final files =
        await bob.vault.db.query('files', where: 'complete = 1', whereArgs: []);
    expect(files, isNotEmpty,
        reason: 'the attachment still assembles, whatever order it arrived in');
    expect(aliceRid, isNotEmpty);
    // And nothing was left held: every chunk belongs to a known offer.
    final orphans = firstIntValue(await bob.vault.db.rawQuery(
        'SELECT COUNT(*) FROM chunks WHERE fid NOT IN (SELECT fid FROM files)'));
    expect(orphans, 0);
  }, timeout: const Timeout(Duration(minutes: 4)));
}
