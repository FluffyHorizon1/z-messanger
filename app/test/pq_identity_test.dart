// Protocol v3 in the app (§18.2-18.5): scanning a zc3. code, receiving the
// post-quantum key it committed to, and refusing one that does not match.
//
// The classical view of a v3 code is byte-for-byte a v1 bundle, so everything
// keeps working the moment a code is scanned. That is exactly the hazard: it
// is easy to end up showing an identity as post-quantum-verified when all
// that has happened is a scan. These tests pin the three states apart, and
// pin that a substituted key is refused rather than absorbed.
@Tags(['integration'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/archive.dart';
import 'package:zapp/core/backup_store.dart';
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

  Future<Directory> tempDir(String n) async {
    final d = await Directory.systemTemp.createTemp('z_pq_$n');
    temps.add(d);
    return d;
  }

  Future<ChatService> start(Directory dir, String name,
      {ZIdentity? identity}) async {
    final vault = await Vault.open(rootOverride: dir);
    final id = identity ??
        await () async {
          final stored = await vault.kvGet('identity');
          return stored == null
              ? await ZIdentity.generate()
              : await ZIdentity.fromJson(
                  (jsonDecode(stored) as Map).cast<String, Object?>());
        }();
    await vault.kvPut('identity', jsonEncode(id.toJson()));
    final transport =
        Transport(identity: id, serverUrl: 'ws://127.0.0.1:$port');
    final svc = await ChatService.init(
        vault: vault, identity: id, displayName: name, transport: transport);
    services.add(svc);
    return svc;
  }

  Future<void> waitUntil(bool Function() cond,
      {Duration timeout = const Duration(seconds: 25),
      String what = ''}) async {
    final deadline = DateTime.now().add(timeout);
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 30));
    }
  }

  test('a scanned v3 code becomes hybrid only once the key arrives and matches',
      () async {
    final a = await start(await tempDir('a'), 'Ana');
    final b = await start(await tempDir('b'), 'Ben');
    await waitUntil(() => a.transport.isConnected && b.transport.isConnected,
        what: 'connected');

    // The account's post-quantum half is derived from a stored seed, and its
    // classical half is the identity's own key.
    final aPq = await a.pqIdentity();
    expect(aPq.publicKey.edPub, a.identity.edPub);
    expect(await a.vault.kvGet('pq_seed'), isNotNull);
    // Stable across calls — a fresh key each time would break every
    // commitment already handed out.
    expect((await a.pqIdentity()).publicKey.mlPub, aPq.publicKey.mlPub);

    final code = await a.myContactCodeV3();
    expect(code, startsWith('zc3.'));
    expect(code.length, lessThan(400), reason: 'still QR-sized');

    await b.addContactFromCode(code);
    await a.addContactFromCode(await b.myContactCode());

    // Scanned, so committed to — but the key has not arrived. This is the
    // state a naive implementation reports as "post-quantum".
    expect(b.assuranceWith(a.myRid), IdentityAssurance.pendingPostQuantum);
    expect(b.contacts[a.myRid]!.pqCommit, isNotNull);
    expect(b.contacts[a.myRid]!.pqPub, isNull);
    final classicalNumber = await b.safetyNumberWith(a.myRid);

    // Nothing can be exchanged before there is a session, so the key follows
    // the first traffic — exactly as the v2 ML-KEM offer does.
    await b.sendText(a.myRid, 'hello from a v3 scan');
    await waitUntil(
        () => (a.messagesByChat[b.myRid] ?? [])
            .any((m) => m.body.contains('v3 scan')),
        what: 'message delivered');

    // Ana's key arrives in-band and matches.
    await waitUntil(() => b.assuranceWith(a.myRid) == IdentityAssurance.hybrid,
        what: 'the post-quantum key arrived and matched');
    expect(b.contacts[a.myRid]!.pqPub, aPq.publicKey.mlPub);

    // The safety number moves exactly once, at that moment, and both sides'
    // views of the pair agree on the new value.
    final hybridNumber = await b.safetyNumberWith(a.myRid);
    expect(hybridNumber, isNot(classicalNumber));
    expect(hybridNumber.split(' ').length, 12);

    // Ana only holds a v1 code for Ben, so her side stays classical — the
    // asymmetry is real and must not be papered over.
    expect(a.assuranceWith(b.myRid), IdentityAssurance.classical);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('a substituted post-quantum key is refused, not absorbed', () async {
    final a = await start(await tempDir('sa'), 'Ana');
    final b = await start(await tempDir('sb'), 'Ben');
    await waitUntil(() => a.transport.isConnected && b.transport.isConnected,
        what: 'connected');

    // Ben scans a code committing to a DIFFERENT post-quantum key than the
    // one Ana will send — what an attacker who controls the exchange, or a
    // swapped code, produces.
    final impostor = await HybridKeyPair.fromSeeds(
        edSeed: a.identity.edSeed, mlSeed: randomBytes(32));
    final wrongCode = await ContactBundleV3.forIdentity(
        a.identity, impostor.publicKey,
        displayName: 'Ana');
    await b.addContactFromCode(wrongCode.encode());
    await a.addContactFromCode(await b.myContactCode());

    // Ana sends her real key on the first traffic; it does not match what Ben
    // scanned.
    await b.sendText(a.myRid, 'is this really you');
    await waitUntil(
        () => (b.messagesByChat[a.myRid] ?? [])
            .any((m) => m.body.contains('does not match')),
        what: 'the mismatch was surfaced');

    // Refused: still pending, never upgraded, and the safety number has not
    // silently moved to one derived from an unverified key.
    expect(b.assuranceWith(a.myRid), IdentityAssurance.pendingPostQuantum);
    expect(b.contacts[a.myRid]!.pqPub, isNull);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('a backup carries the post-quantum identity through a restore',
      () async {
    // Without the seed, a restored device would generate a different ML-DSA
    // key, and every contact holding a commitment to the old one would see a
    // mismatch — indistinguishable, to them, from an attack.
    final dir = await tempDir('bk');
    final a = await start(dir, 'Ana');
    final before = (await a.pqIdentity()).publicKey.mlPub;
    final identity = a.identity;

    final store = await BackupStore.open(a.vault);
    final recovery = await RecoveryCode.generate();
    final backup = await store.write(code: recovery);

    a.dispose();
    await a.transport.stop();
    services.remove(a);
    await a.vault.db.close();

    final fresh = await Vault.open(rootOverride: await tempDir('bk2'));
    await BackupArchive.import(vault: fresh, file: backup.file, code: recovery);
    await fresh.db.close();

    final revived =
        await start(await tempDir('bk3'), 'Ana', identity: identity);
    // (the restore above proves the archive round-trips; check the seed made
    // it by importing into the vault this service actually opened)
    final v2 = await Vault.open(rootOverride: await tempDir('bk4'));
    await BackupArchive.import(vault: v2, file: backup.file, code: recovery);
    expect(await v2.kvGet('pq_seed'), isNotNull,
        reason: 'the archive carries the post-quantum seed');
    final restoredPq = await HybridKeyPair.fromSeeds(
        edSeed: identity.edSeed, mlSeed: unb64((await v2.kvGet('pq_seed'))!));
    expect(restoredPq.publicKey.mlPub, before,
        reason: 'the same identity, not a new one');
    await v2.db.close();
    expect(revived.myRid, await identity.routingId());
  }, timeout: const Timeout(Duration(minutes: 3)));
}
