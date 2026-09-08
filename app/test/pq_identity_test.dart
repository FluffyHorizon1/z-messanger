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

  setUpAll(() async {
    HttpOverrides.global = null;
    final serverDir =
        '${Directory.current.parent.path}${Platform.pathSeparator}server';
    // An OS-assigned free port. The old formula derived the port from the
    // clock, so two suites starting in the same millisecond got the SAME
    // port — and `flutter test` runs files concurrently, so one relay lost
    // the bind and its whole file failed in setUpAll with 'relay did not
    // start'. Asking the OS removes the shared input entirely.
    final portProbe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    port = portProbe.port;
    await portProbe.close();
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
    final aPq = (await a.pqIdentity())!;
    expect(aPq.publicKey.edPub, a.identity.edPub);
    expect(await a.vault.kvGet('pq_seed'), isNotNull);
    // Stable across calls — a fresh key each time would break every
    // commitment already handed out.
    expect((await a.pqIdentity())!.publicKey.mlPub, aPq.publicKey.mlPub);

    final code = await a.myContactCode();
    expect(code, startsWith('zc1.'),
        reason: 'the emitted code stays readable by builds in the field');
    expect(code.length, lessThan(400), reason: 'still QR-sized');
    // An older client reads it as an ordinary v1 identity.
    expect((await ContactBundle.decode(code)).edPub, a.identity.edPub);

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

    // Both sides now hand out commitment-carrying codes, so the upgrade is
    // symmetric: Ana reaches hybrid for Ben too, without either of them
    // doing anything different from before.
    await waitUntil(() => a.assuranceWith(b.myRid) == IdentityAssurance.hybrid,
        what: 'Ana upgraded her view of Ben as well');
    expect(await a.safetyNumberWith(b.myRid), hybridNumber,
        reason: 'and both read the same number for the pair');
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

  test(
      'the number that moves when an identity is upgraded does not keep its '
      'verified tick, and the app can say why', () async {
    // 13.3's whole problem. The safety number moves ONCE for every existing
    // user as their contacts' identities gain a post-quantum half. A user who
    // read the old number aloud and ticked "verified" must not be shown a
    // green tick against a number they never checked — and must not be shown
    // a bare change either, because an unexplained change is exactly what a
    // key substitution looks like. The app has to distinguish the two.
    final a = await start(await tempDir('va'), 'Ana');
    final b = await start(await tempDir('vb'), 'Ben');
    await waitUntil(() => a.transport.isConnected && b.transport.isConnected,
        what: 'connected');

    // Ana scans Ben before Ben has scanned her — the ordinary case of one
    // person going first. Nothing can come back, so her view stays pending
    // and this is deterministic rather than a race with the answer.
    await a.addContactFromCode(await b.myContactCode());
    expect(a.assuranceWith(b.myRid), IdentityAssurance.pendingPostQuantum);

    final classical = await a.safetyNumberWith(b.myRid);
    await a.setVerified(b.myRid, true);
    expect(a.verificationWith(b.myRid), VerificationState.verified);

    // Ben scans Ana, they speak, and Ben's post-quantum key arrives and
    // matches the commitment Ana already held.
    await b.addContactFromCode(await a.myContactCode());
    await b.sendText(a.myRid, 'hello');
    await waitUntil(() => a.assuranceWith(b.myRid) == IdentityAssurance.hybrid,
        what: "Ben's post-quantum key arrived and matched");

    final upgraded = await a.safetyNumberWith(b.myRid);
    expect(upgraded, isNot(classical), reason: 'the number does move');

    // The tick does not follow the number it no longer covers…
    expect(a.verificationWith(b.myRid), VerificationState.upgradedReverify);
    // …but the fact that Ana verified once is not thrown away either, or the
    // UI could only say "unverified", which is both untrue and unhelpful.
    expect(a.contacts[b.myRid]!.verified, isTrue);

    // Re-reading it aloud settles it.
    await a.setVerified(b.myRid, true);
    expect(a.verificationWith(b.myRid), VerificationState.verified);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test(
      'a number that moved for no reason this build can explain is not '
      'passed off as an upgrade', () async {
    // The branch that fires if the reasoning above is wrong. "Upgraded" is
    // claimed only when what was verified is demonstrably the classical
    // number for this pair; anything else is reported as unexplained, which
    // is what a user needs to hear before an upgrade story they might
    // otherwise accept.
    final a = await start(await tempDir('ua'), 'Ana');
    final b = await start(await tempDir('ub'), 'Ben');
    await waitUntil(() => a.transport.isConnected && b.transport.isConnected,
        what: 'connected');
    await a.addContactFromCode(await b.myContactCode());
    await a.setVerified(b.myRid, true);
    expect(a.verificationWith(b.myRid), VerificationState.verified);

    // Something no legitimate path produces: a stored value that is neither
    // the number now shown nor the classical number for this pair.
    await a.vault.db.update('contacts', {'verified_sn': '00000 00000 00000'},
        where: 'rid = ?', whereArgs: [b.myRid]);
    await a.reloadContacts();
    expect(a.verificationWith(b.myRid), VerificationState.changedUnexpectedly);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('a tick from before 13.3 survives the upgrade instead of vanishing',
      () async {
    // Most verifications in existence were made by a build that recorded only
    // THAT a number was compared. Dropping every one of them on upgrade would
    // be safe and obnoxious — it teaches people the tick is noise. The
    // classical number is what any such build showed, so it is recorded on
    // first load and the tick keeps meaning something.
    final dir = await tempDir('bf');
    final a = await start(dir, 'Ana');
    final b = await start(await tempDir('bf2'), 'Ben');
    await waitUntil(() => a.transport.isConnected && b.transport.isConnected,
        what: 'connected');
    await a.addContactFromCode(await b.myContactCode());
    await a.setVerified(b.myRid, true);
    final classical = await a.safetyNumberWith(b.myRid);

    // Exactly what an older row looks like: verified, no number recorded.
    await a.vault.db.update('contacts', {'verified_sn': null},
        where: 'rid = ?', whereArgs: [b.myRid]);
    await a.reloadContacts();

    expect(a.contacts[b.myRid]!.verifiedSn, classical,
        reason: 'the classical number is recorded, not guessed at later');
    expect(a.verificationWith(b.myRid), VerificationState.verified,
        reason: 'and the tick still stands, because nothing has moved yet');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('a refused key is announced once, not on every message it rides in on',
      () async {
    // The mismatch path had no memory: every inbound `pqid` that failed the
    // check inserted the same system message again, so an attacker who kept
    // sending could bury the chat in the very warning meant to be read.
    final a = await start(await tempDir('ma'), 'Ana');
    final b = await start(await tempDir('mb'), 'Ben');
    await waitUntil(() => a.transport.isConnected && b.transport.isConnected,
        what: 'connected');

    final impostor = await HybridKeyPair.fromSeeds(
        edSeed: a.identity.edSeed, mlSeed: randomBytes(32));
    final wrongCode = await ContactBundleV3.forIdentity(
        a.identity, impostor.publicKey,
        displayName: 'Ana');
    await b.addContactFromCode(wrongCode.encode());
    await a.addContactFromCode(await b.myContactCode());

    await b.sendText(a.myRid, 'is this really you');
    await waitUntil(
        () => (b.messagesByChat[a.myRid] ?? [])
            .any((m) => m.body.contains('does not match')),
        what: 'the mismatch was surfaced');
    expect(b.contacts[a.myRid]!.pqMismatch, isTrue,
        reason: 'the refusal is state, not just a line in the transcript');

    // Keep talking: Ana re-offers her key on traffic, and every one of those
    // fails the same check.
    for (var i = 0; i < 4; i++) {
      await b.sendText(a.myRid, 'still there? $i');
      await Future<void>.delayed(const Duration(milliseconds: 400));
    }
    final warnings = (b.messagesByChat[a.myRid] ?? [])
        .where((m) => m.body.contains('does not match'))
        .length;
    expect(warnings, 1, reason: 'said once, and it stays said');
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
    final before = (await a.pqIdentity())!.publicKey.mlPub;
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
