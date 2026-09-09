// 15.3 — what a group send actually costs the sender.
//
// Z has no group key. Every group message is encrypted separately for every
// recipient DEVICE over that device's own pairwise ratchet. That is the design
// decision the whole group story rests on — a removed member cannot read what
// comes after, because there was never a shared key to rotate — and it is
// bought with fan-out that grows as members x devices.
//
// The reason to measure it rather than assume it: the cost is exactly the
// argument someone will one day make for adding a shared group key, and that
// argument should be answered with a number instead of a shrug. If a 50-member
// group is fine, the design holds. If it is not, we want to know before a user
// finds out, and we want to know WHERE the time goes.
//
// This measures the sender's side only, deliberately. The recipients are real
// identities with real bundles but are never started: what is being timed is
// N ratchet encryptions, N seals and N vault transactions, which is the part
// that scales. Delivery is the relay's problem and is measured elsewhere
// (server/test/load.test.js).
//
// Not run in the ordinary sweep — it is a measurement, not an assertion about
// behaviour. Run it deliberately:
//
//     flutter test test/fanout_bench_test.dart --tags bench
//
// The one thing it DOES assert is that the cost stays roughly linear in the
// member count. Linear is the design's promise; anything worse means a
// per-member cost that should have been paid once, which is a bug rather than
// a property.
@Tags(['bench'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:cryptography/cryptography.dart';
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
    for (final s in services) {
      await s.transport.stop();
    }
    relay.kill();
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<ChatService> makeClient(String name) async {
    final dir = await Directory.systemTemp.createTemp('z_bench_$name');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    final identity = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(identity.toJson()));
    final svc = await ChatService.init(
      vault: vault,
      identity: identity,
      displayName: name,
      transport:
          Transport(identity: identity, serverUrl: 'ws://127.0.0.1:$port'),
    );
    services.add(svc);
    return svc;
  }

  /// A contact who exists, cryptographically, but is never running. Enough to
  /// open a session and encrypt to — which is all the sender-side cost needs.
  Future<String> addPhantom(ChatService svc, int i) async {
    final id = await ZIdentity.generate();
    final code = (await id.bundle(displayName: 'p$i')).encode();
    await svc.addContactFromCode(code);
    return (await ContactBundle.decode(code)).routingId();
  }

  final results = <int, double>{};

  Future<double> timeGroupSend(ChatService svc, int members) async {
    final rids = <String>[];
    for (var i = 0; i < members; i++) {
      rids.add(await addPhantom(svc, results.length * 1000 + i));
    }
    final gid = await svc.createGroup('bench-$members', rids);

    // One warm send so session setup is not counted as message cost.
    await svc.sendGroupText(gid, 'warm');

    const reps = 5;
    final sw = Stopwatch()..start();
    for (var r = 0; r < reps; r++) {
      await svc.sendGroupText(gid, 'message $r');
    }
    sw.stop();
    return sw.elapsedMicroseconds / 1000.0 / reps;
  }

  test('group send cost grows linearly in the member count', () async {
    final svc = await makeClient('sender');
    const sizes = [2, 5, 10, 25, 50];

    for (final n in sizes) {
      results[n] = await timeGroupSend(svc, n);
    }

    // ignore: avoid_print
    print('\n  members   total ms   ms/member');
    for (final n in sizes) {
      final t = results[n]!;
      // ignore: avoid_print
      print('  ${n.toString().padLeft(7)}   ${t.toStringAsFixed(1).padLeft(8)}'
          '   ${(t / n).toStringAsFixed(2).padLeft(9)}');
    }

    // Linearity, stated as a bound rather than a hope: if per-member cost at
    // 50 members is much worse than at 5, something is O(n^2) — a scan, a
    // re-read, or a lock held across the loop.
    final perMemberSmall = results[5]! / 5;
    final perMemberLarge = results[50]! / 50;
    // ignore: avoid_print
    print('\n  per-member at 5:  ${perMemberSmall.toStringAsFixed(2)} ms');
    // ignore: avoid_print
    print('  per-member at 50: ${perMemberLarge.toStringAsFixed(2)} ms');
    // ignore: avoid_print
    print('  growth factor:    '
        '${(perMemberLarge / perMemberSmall).toStringAsFixed(2)}x\n');

    expect(perMemberLarge, lessThan(perMemberSmall * 3),
        reason: 'per-member cost grew ${(perMemberLarge / perMemberSmall)
            .toStringAsFixed(1)}x between a 5-member and a 50-member group. '
            'Linear fan-out is the design; worse than linear means a '
            'per-member cost that should have been paid once.');
  }, timeout: const Timeout(Duration(minutes: 10)));

  // Where does the per-member cost go? Guessing at this is how you optimise
  // the wrong thing, so the three candidates are timed separately: the
  // ratchet step, sealing the conversation state, and the vault transaction.
  test('breakdown: ratchet vs conversation state vs vault write', () async {
    final svc = await makeClient('split');
    final rid = await addPhantom(svc, 99000);
    await svc.sendText(rid, 'warm');

    final vault = svc.vault;
    const reps = 40;

    // 1. A vault transaction with one outbox insert — what _sendInner does
    //    once per member.
    var sw = Stopwatch()..start();
    for (var i = 0; i < reps; i++) {
      await vault.db.transaction((txn) async {
        await txn.insert('outbox', {
          'id': 'bench$i',
          'rid': rid,
          'payload': 'x' * 1200,
          'created_ms': DateTime.now().millisecondsSinceEpoch,
        });
      });
    }
    sw.stop();
    final perTxn = sw.elapsedMicroseconds / 1000.0 / reps;

    // 2. The same N inserts inside ONE transaction — the batched alternative.
    sw = Stopwatch()..start();
    await vault.db.transaction((txn) async {
      for (var i = 0; i < reps; i++) {
        await txn.insert('outbox', {
          'id': 'batch$i',
          'rid': rid,
          'payload': 'x' * 1200,
          'created_ms': DateTime.now().millisecondsSinceEpoch,
        });
      }
    });
    sw.stop();
    final perBatched = sw.elapsedMicroseconds / 1000.0 / reps;

    // 3. Sealing a payload — the vault's per-cell AEAD.
    sw = Stopwatch()..start();
    for (var i = 0; i < reps; i++) {
      await vault.seal('x' * 1200);
    }
    sw.stop();
    final perSeal = sw.elapsedMicroseconds / 1000.0 / reps;

    // ignore: avoid_print
    print('\n  one transaction per insert : ${perTxn.toStringAsFixed(2)} ms');
    // ignore: avoid_print
    print('  all inserts in one txn    : ${perBatched.toStringAsFixed(2)} ms'
        '  (${(perTxn / perBatched).toStringAsFixed(1)}x cheaper)');
    // ignore: avoid_print
    print('  vault.seal of one payload : ${perSeal.toStringAsFixed(2)} ms\n');
  }, timeout: const Timeout(Duration(minutes: 5)));

  // The transaction was only 3.7 ms of ~24. So where is the rest? The two
  // remaining candidates are both per-recipient and both asymmetric: the
  // ratchet step, and the ephemeral X25519 that sealed sender does for every
  // envelope. If the cost is cryptographic rather than I/O, it cannot be
  // batched away — it is what per-recipient encryption costs, and the fix is
  // to stop making the user wait for it rather than to make it cheaper.
  test('breakdown: the asymmetric operations', () async {
    const reps = 40;
    final me = await ZIdentity.generate();
    final them = await ZIdentity.generate();

    // Sealed sender: one ephemeral X25519 keypair + DH + AEAD per envelope.
    var sw = Stopwatch()..start();
    for (var i = 0; i < reps; i++) {
      await SealedEnvelope.seal(
        toXPub: them.xPub,
        fromRid: 'r' * 22,
        payload: 'p' * 800,
      );
    }
    sw.stop();
    final perSeal = sw.elapsedMicroseconds / 1000.0 / reps;

    // A bare X25519 shared secret, to see how much of that is the DH itself.
    final x = X25519();
    final kp = await x.newKeyPairFromSeed(randomBytes(32));
    sw = Stopwatch()..start();
    for (var i = 0; i < reps; i++) {
      final eph = await x.newKeyPairFromSeed(randomBytes(32));
      await x.sharedSecretKey(
          keyPair: eph,
          remotePublicKey: SimplePublicKey(them.xPub, type: KeyPairType.x25519));
    }
    sw.stop();
    final perDh = sw.elapsedMicroseconds / 1000.0 / reps;

    // ignore: avoid_print
    print('\n  SealedEnvelope.seal        : ${perSeal.toStringAsFixed(2)} ms');
    // ignore: avoid_print
    print('  bare X25519 keygen + DH   : ${perDh.toStringAsFixed(2)} ms'
        '  (${(perDh / perSeal * 100).toStringAsFixed(0)}% of the seal)');
    // ignore: avoid_print
    print('  (kp warm: ${kp.runtimeType})\n');
  }, timeout: const Timeout(Duration(minutes: 5)));

  // Six of the twenty-four milliseconds are accounted for. Rather than guess
  // at the rest, time a single 1:1 send — which is exactly one iteration of
  // the group loop — and then time it again with the transport stopped. The
  // difference is what the unawaited flushOutbox() costs in contention: it is
  // fired once per member, so fifty sends means fifty concurrent flushes
  // competing for the same event loop.
  test('breakdown: one 1:1 send, with and without the network', () async {
    final svc = await makeClient('solo');
    final rid = await addPhantom(svc, 98000);
    await svc.sendText(rid, 'warm');

    const reps = 30;
    var sw = Stopwatch()..start();
    for (var i = 0; i < reps; i++) {
      await svc.sendText(rid, 'msg $i');
    }
    sw.stop();
    final withNet = sw.elapsedMicroseconds / 1000.0 / reps;

    await svc.transport.stop();
    await Future<void>.delayed(const Duration(milliseconds: 200));

    sw = Stopwatch()..start();
    for (var i = 0; i < reps; i++) {
      await svc.sendText(rid, 'offline $i');
    }
    sw.stop();
    final offline = sw.elapsedMicroseconds / 1000.0 / reps;

    // ignore: avoid_print
    print('\n  one 1:1 send, connected   : ${withNet.toStringAsFixed(2)} ms');
    // ignore: avoid_print
    print('  one 1:1 send, offline     : ${offline.toStringAsFixed(2)} ms');
    // ignore: avoid_print
    print('  attributable to delivery  : '
        '${(withNet - offline).toStringAsFixed(2)} ms\n');
  }, timeout: const Timeout(Duration(minutes: 5)));

  // Every send serialises the whole conversation — once for the rollback
  // snapshot, once to persist — and that state includes the ratchet's cache of
  // skipped message keys, which is capped at 1536. In this benchmark the
  // phantoms never reply, so the cache is empty and the numbers above are a
  // BEST case. A real conversation that has seen out-of-order delivery carries
  // that cache, and pays for it on every subsequent send.
  //
  // Synthesising the cache rather than provoking it: what is being measured is
  // the cost of encoding and sealing a map of that size, which is the marginal
  // cost the send path would pay. It is an estimate of one term, not an
  // end-to-end send, and is labelled as such in docs/PERFORMANCE.md.
  test('estimate: what a full skipped-key cache adds to every send', () async {
    final svc = await makeClient('skip');
    final vault = svc.vault;
    const reps = 20;

    Future<double> costFor(int n) async {
      final skipped = <String, String>{
        for (var i = 0; i < n; i++) 'k$i': base64.encode(List.filled(32, i % 251))
      };
      final state = {
        'sid': 's' * 22,
        'ratchet': {'skipped': skipped, 'ns': 7, 'nr': 3},
        'receivedAny': true,
      };
      final sw = Stopwatch()..start();
      for (var i = 0; i < reps; i++) {
        // Twice, because the send path encodes it twice.
        jsonEncode(state);
        await vault.seal(jsonEncode(state));
      }
      sw.stop();
      return sw.elapsedMicroseconds / 1000.0 / reps;
    }

    final empty = await costFor(0);
    final half = await costFor(768);
    final full = await costFor(1536);

    // ignore: avoid_print
    print('\n  skipped keys   encode+seal, per send');
    // ignore: avoid_print
    print('     0          ${empty.toStringAsFixed(2)} ms');
    // ignore: avoid_print
    print('   768          ${half.toStringAsFixed(2)} ms');
    // ignore: avoid_print
    print('  1536 (cap)    ${full.toStringAsFixed(2)} ms'
        '   (+${(full - empty).toStringAsFixed(2)} ms per recipient)\n');
  }, timeout: const Timeout(Duration(minutes: 5)));
}
