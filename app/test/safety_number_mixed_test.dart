// Two people who could not verify each other (ADR 0021).
//
// Published 3.7.0: Alice adds Bob from his current code, which carries his
// post-quantum commitment; Bob adds Alice from a classical code — an older
// build's code, a contact accepted from a request (ADR 0011), or a record
// made before v3. Bob's key reaches Alice and matches, so Alice is HYBRID
// toward Bob and shows the post-quantum (v3) safety number. Alice's key
// reaches Bob too, but Bob holds no commitment to check it against, so
// §18.2 told him to DROP it: he stayed classical and showed the v1 number.
// Two screens, two numbers, a ceremony that cannot be completed, and no way
// out — re-scanning Alice's code threw "already in your contacts".
//
// ADR 0021: a key with no commitment is KEPT, as a candidate, for the number
// only; the two sides show the post-quantum number once each holds the
// other's key and has said so; and comparing that number is what confirms
// the candidate. Re-scanning is kept as the second path, for two people who
// are in the same room.
//
// Criteria, each a test below:
//   1. a commitment on one side only still reaches ONE number, and it is the
//      post-quantum one;
//   2. neither side holding a commitment reaches one post-quantum number too;
//   3. a peer that never says it holds our key — a build from before this
//      ADR, run as one — leaves BOTH screens on the classical number, which
//      is the number that peer is showing; and (3b) the one shape this ADR
//      cannot fix, pinned: an old peer that DID scan our code establishes our
//      key, shows the post-quantum number and never acknowledges, so the two
//      still differ until it updates. Criteria 3 and 3b are the two halves of
//      what "mixed version" means here;
//   4. confirming the number establishes the candidate: hybrid assurance, the
//      number that was actually compared recorded, and both surviving a
//      restart;
//   5. until it is confirmed, a candidate is a NUMBER and nothing else — not
//      hybrid, and not usable to verify a device list;
//   6. re-scanning a contact's current code upgrades the record without a
//      comparison, and a code committing to a different key is refused;
//   7. the candidate and the two flags survive a restart, and the key is
//      sealed at rest;
//   8. a second, different key does not replace a candidate already held, and
//      a contact whose key was refused is not given one as a consolation;
//   9. a backup carries the candidate and both flags, so a restore is on the
//      number the backup was taken on.
//
// Criterion 4 has a second half (4b): confirming the CLASSICAL number must
// establish nothing, which is where this had a hole while it was written.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/archive.dart';
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
  final dirs = <String, Directory>{};

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

  Future<ChatService> makeClient(String name, {Directory? reuse}) async {
    final dir = reuse ?? await Directory.systemTemp.createTemp('z_snm_$name');
    if (reuse == null) {
      temps.add(dir);
      dirs[name] = dir;
    }
    final vault = await Vault.open(rootOverride: dir);
    final ZIdentity identity;
    final stored = await vault.kvGet('identity');
    if (stored == null) {
      identity = await ZIdentity.generate();
      await vault.kvPut('identity', jsonEncode(identity.toJson()));
    } else {
      identity = await ZIdentity.fromJson(
          (jsonDecode(stored) as Map).cast<String, Object?>());
    }
    final svc = await ChatService.init(
        vault: vault,
        identity: identity,
        displayName: name,
        transport:
            Transport(identity: identity, serverUrl: 'ws://127.0.0.1:$port'));
    services.add(svc);
    return svc;
  }

  Future<void> waitUntil(bool Function() cond,
      {Duration timeout = const Duration(seconds: 20), String? what}) async {
    final deadline = DateTime.now().add(timeout);
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: ${what ?? ''}');
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
  }

  /// The code an older build hands out: the classical identity, no commitment.
  Future<String> classicalCodeOf(ChatService svc, String name) async =>
      (await svc.identity.bundle(displayName: name)).encode();

  /// Both sides settled on what they will show, and agree on it.
  Future<void> expectOneNumber(ChatService a, ChatService b,
      {required bool postQuantum}) async {
    await waitUntil(
        () =>
            a.contacts[b.myRid]!.showsPostQuantumNumber == postQuantum &&
            b.contacts[a.myRid]!.showsPostQuantumNumber == postQuantum,
        what: 'both sides settle on the '
            '${postQuantum ? 'post-quantum' : 'classical'} number');
    final shown = await a.safetyNumberWith(b.myRid);
    expect(shown, await b.safetyNumberWith(a.myRid),
        reason: 'the two screens must show ONE number or the ceremony cannot '
            'be completed');
    // And it is the number it claims to be: v1 and v3 use different salts, so
    // for one pair they can never coincide (§18.5).
    final classical = await safetyNumber(
        (await a.accountIdentity()).accountEdPub,
        a.contacts[b.myRid]!.accountEd);
    expect(shown == classical, !postQuantum,
        reason: postQuantum
            ? 'the post-quantum number must not be the classical one'
            : 'the classical number is what both sides can compute');
  }

  test('1. a commitment on one side only still reaches one post-quantum number',
      () async {
    final alice = await makeClient('alice');
    final bob = await makeClient('bob');
    await waitUntil(
        () => alice.transport.isConnected && bob.transport.isConnected);

    // Alice scans Bob's CURRENT code: classical keys + post-quantum commitment.
    await alice.addContactFromCode(await bob.myContactCode());
    // Bob adds Alice from a CLASSICAL code — what an older build hands out,
    // and what accepting a contact request amounts to.
    await bob.addContactFromCode(await classicalCodeOf(alice, 'alice'));

    await expectOneNumber(alice, bob, postQuantum: true);
    // Each side knows exactly what it has. Alice checked Bob's key against the
    // commitment she scanned; Bob checked nothing, and his screen says so.
    expect(alice.contacts[bob.myRid]!.pqDisplay, PqDisplay.postQuantum);
    expect(alice.assuranceWith(bob.myRid), IdentityAssurance.hybrid);
    expect(bob.contacts[alice.myRid]!.pqDisplay, PqDisplay.unverified);
    expect(bob.assuranceWith(alice.myRid), IdentityAssurance.classical,
        reason: 'a candidate is a number, not an assurance');
  });

  test('2. neither side holding a commitment reaches one number too', () async {
    final alice = await makeClient('alice2');
    final bob = await makeClient('bob2');
    await waitUntil(
        () => alice.transport.isConnected && bob.transport.isConnected);
    await alice.addContactFromCode(await classicalCodeOf(bob, 'bob2'));
    await bob.addContactFromCode(await classicalCodeOf(alice, 'alice2'));

    await expectOneNumber(alice, bob, postQuantum: true);
    for (final pair in [[alice, bob], [bob, alice]]) {
      final me = pair[0], them = pair[1];
      expect(me.contacts[them.myRid]!.pqDisplay, PqDisplay.unverified);
      expect(me.contacts[them.myRid]!.pqCommit, isNull);
      expect(me.assuranceWith(them.myRid), IdentityAssurance.classical);
      expect(me.contacts[them.myRid]!.pqTold, isTrue,
          reason: 'each side said it holds the other\'s key — which is the '
              'only reason either number moved');
    }
    // What it cost to say so. A `pqack` is the small envelope, but it is still
    // an envelope, and the ADR promises at most one per contact: the flag is
    // durable precisely so that ordinary traffic afterwards is silent.
    final acks = alice.debugPqAcks + bob.debugPqAcks;
    expect(acks, lessThanOrEqualTo(2), reason: 'at most one each way');
    for (var i = 0; i < 4; i++) {
      await alice.sendText(bob.myRid, 'chatter $i');
      await bob.sendText(alice.myRid, 'chatter back $i');
    }
    await Future<void>.delayed(const Duration(seconds: 2));
    expect(alice.debugPqAcks + bob.debugPqAcks, acks,
        reason: 'and traffic afterwards earns no more of them');
  });

  test('3. a peer from before this ADR leaves both screens classical',
      () async {
    final alice = await makeClient('alice3');
    final old = await makeClient('old3');
    // `old` drops a key it holds no commitment for and never says it holds
    // ours — exactly what 3.7.0 does.
    old.debugPreAdr0021 = true;
    await waitUntil(
        () => alice.transport.isConnected && old.transport.isConnected);
    await alice.addContactFromCode(await classicalCodeOf(old, 'old3'));
    await old.addContactFromCode(await classicalCodeOf(alice, 'alice3'));

    // Alice keeps their key — there is no harm in holding it — but shows the
    // classical number, because that is the number the old build is showing.
    await waitUntil(() => alice.contacts[old.myRid]!.pqCandidate != null,
        what: 'Alice keeps the key the old client sent');
    await Future<void>.delayed(const Duration(seconds: 2)); // let both settle
    await expectOneNumber(alice, old, postQuantum: false);
    expect(alice.contacts[old.myRid]!.pqDisplay, PqDisplay.waitingForThem);
    expect(old.contacts[alice.myRid]!.pqCandidate, isNull,
        reason: 'the old build drops a key with no commitment, as §18.2 said');
  });

  test('3b. an old peer that scanned our code: the rule, and its limit',
      () async {
    // The shape this ADR cannot fix, pinned so that it is a known limit
    // rather than a surprise. The old peer holds our commitment, so it
    // ESTABLISHES our key and shows the post-quantum number whatever we do.
    // Whether we can join it there depends on one thing only: whether it ever
    // told us it holds ours — which a pre-0021 client can say only as `ack`
    // on the single `pqid` it sends, so it says it if and only if our key had
    // already reached it by then. Both orderings occur; the DISPLAY RULE is
    // the same in each, and that is what is asserted here rather than an
    // outcome that depends on which envelope won.
    final alice = await makeClient('alice3b');
    final old = await makeClient('old3b');
    old.debugPreAdr0021 = true;
    await waitUntil(
        () => alice.transport.isConnected && old.transport.isConnected);
    await old.addContactFromCode(await alice.myContactCode());
    await alice.addContactFromCode(await classicalCodeOf(old, 'old3b'));

    await waitUntil(() => old.contacts[alice.myRid]!.pqPub != null,
        what: 'the old peer matches our key against the commitment it scanned');
    await waitUntil(() => alice.contacts[old.myRid]!.pqCandidate != null,
        what: 'we keep the key it sent, having nothing to check it against');
    await Future<void>.delayed(const Duration(seconds: 2)); // let both settle

    final theirs = old.contacts[alice.myRid]!;
    final ours = alice.contacts[old.myRid]!;
    expect(theirs.showsPostQuantumNumber, isTrue,
        reason: 'an established key shows the post-quantum number, and no '
            'change of ours reaches a build already in the field');
    final agree = await alice.safetyNumberWith(old.myRid) ==
        await old.safetyNumberWith(alice.myRid);
    expect(agree, ours.pqAcked,
        reason: ours.pqAcked
            ? 'it acknowledged, so both screens show the post-quantum number'
            : 'it never acknowledged, so the numbers differ — the documented '
              'limit, which ends when that side updates');
  });

  test('4. confirming the number establishes the key it was derived from',
      () async {
    final alice = await makeClient('alice4');
    final bob = await makeClient('bob4');
    await waitUntil(
        () => alice.transport.isConnected && bob.transport.isConnected);
    await alice.addContactFromCode(await classicalCodeOf(bob, 'bob4'));
    await bob.addContactFromCode(await classicalCodeOf(alice, 'alice4'));
    await expectOneNumber(alice, bob, postQuantum: true);

    final compared = await alice.safetyNumberWith(bob.myRid);
    final candidate = alice.contacts[bob.myRid]!.pqCandidate;
    expect(candidate, isNotNull);

    await alice.setVerified(bob.myRid, true);

    final c = alice.contacts[bob.myRid]!;
    expect(c.pqPub, candidate,
        reason: 'the key the compared number was derived from is established');
    expect(c.pqCandidate, isNull);
    expect(c.pqDisplay, PqDisplay.postQuantum);
    expect(alice.assuranceWith(bob.myRid), IdentityAssurance.hybrid);
    expect(c.verifiedSn, compared,
        reason: '13.3: WHICH number was compared, not just that one was');
    expect(alice.verificationWith(bob.myRid), VerificationState.verified);
    expect(await alice.safetyNumberWith(bob.myRid), compared,
        reason: 'confirming must not move the number that was confirmed');

    // It survives a restart, and the tick still means what it said.
    await alice.transport.stop();
    final again = await makeClient('alice4', reuse: dirs['alice4']);
    expect(again.contacts[bob.myRid]!.pqPub, candidate);
    expect(again.assuranceWith(bob.myRid), IdentityAssurance.hybrid);
    expect(again.verificationWith(bob.myRid), VerificationState.verified);
  });

  test('4b. confirming the CLASSICAL number establishes nothing', () async {
    // The other half of criterion 4, and the regression test for a hole this
    // had while it was being written: the number and the promotion decision
    // were read either side of an await, so a peer's acknowledgement landing
    // in that gap turned a confirmation of the classical number into the
    // establishment of a post-quantum key nobody had compared.
    final alice = await makeClient('alice4b');
    final old = await makeClient('old4b');
    old.debugPreAdr0021 = true; // never acknowledges, so Alice stays classical
    await waitUntil(
        () => alice.transport.isConnected && old.transport.isConnected);
    await alice.addContactFromCode(await classicalCodeOf(old, 'old4b'));
    await old.addContactFromCode(await classicalCodeOf(alice, 'alice4b'));
    await waitUntil(() => alice.contacts[old.myRid]!.pqCandidate != null,
        what: 'Alice holds their key, unacknowledged');
    expect(alice.contacts[old.myRid]!.pqDisplay, PqDisplay.waitingForThem);
    final classical = await alice.safetyNumberWith(old.myRid);

    await alice.setVerified(old.myRid, true);

    final c = alice.contacts[old.myRid]!;
    expect(c.pqPub, isNull,
        reason: 'the digits she read were the classical ones; nothing about '
            'the post-quantum key was checked, so nothing is established');
    expect(c.pqCandidate, isNotNull, reason: 'it is still only a candidate');
    expect(c.verifiedSn, classical);
    expect(alice.assuranceWith(old.myRid), IdentityAssurance.classical);
    expect(alice.verificationWith(old.myRid), VerificationState.verified,
        reason: 'the classical comparison is a real one and still counts');
  });

  test('5. an unconfirmed candidate verifies nothing', () async {
    final alice = await makeClient('alice5');
    final bob = await makeClient('bob5');
    await waitUntil(
        () => alice.transport.isConnected && bob.transport.isConnected);
    await alice.addContactFromCode(await classicalCodeOf(bob, 'bob5'));
    await bob.addContactFromCode(await classicalCodeOf(alice, 'alice5'));
    await expectOneNumber(alice, bob, postQuantum: true);

    final c = alice.contacts[bob.myRid]!;
    expect(c.pqCandidate, isNotNull);
    // The three things `pqPub` gates, all still closed (§18.3, §18.9).
    expect(c.pqPub, isNull);
    expect(c.hybridKey, isNull,
        reason: 'a candidate is never the key a device list is checked against');
    expect(c.assurance, IdentityAssurance.classical);

    // Bob links a laptop and publishes a post-quantum-signed device list.
    // Alice can use the list — but not verify its post-quantum half, because
    // that needs a key she has confirmed.
    final laptop = await ZIdentity.generate();
    final cert = await (await bob.accountIdentity()).signDeviceCert(
        deviceEdPub: laptop.edPub, deviceXPub: laptop.xPub, deviceId: 'lt');
    await bob.addMyDevice(cert);
    bob.pqListDelay = const Duration(milliseconds: 50); // §18.9, now not hours
    var held = 0;
    final deadline = DateTime.now().add(const Duration(seconds: 30));
    while (held < 2 && DateTime.now().isBefore(deadline)) {
      held = await alice.heldContactListVersion(bob.myRid);
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
    expect(held, 2, reason: 'Alice installed the list, as she always could');
    // The signature must actually ARRIVE, or this test would pass because
    // nothing was there to check rather than because the candidate was
    // refused as the thing to check it with.
    String? sig;
    final sigBy = DateTime.now().add(const Duration(seconds: 30));
    while (sig == null && DateTime.now().isBefore(sigBy)) {
      sig = await alice.debugHeldPqListSignature(bob.myRid);
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
    expect(sig, isNotNull,
        reason: "Bob's post-quantum list signature never reached Alice");
    expect(alice.deviceAssuranceWith(bob.myRid), DeviceAssurance.classical,
        reason: 'the signature is HERE and still unusable: verifying it needs '
            'a CONFIRMED key, and a candidate is not one');

    // And once the candidate is confirmed, the same held signature verifies —
    // so what was blocking it was the candidate's standing, nothing else.
    await alice.setVerified(bob.myRid, true);
    await waitUntil(
        () => alice.deviceAssuranceWith(bob.myRid) == DeviceAssurance.hybrid,
        what: 'the held signature verifies once the key is established');
  });

  test('6. re-scanning the current code upgrades the record', () async {
    final alice = await makeClient('alice6');
    final bob = await makeClient('bob6');
    await waitUntil(
        () => alice.transport.isConnected && bob.transport.isConnected);
    await bob.addContactFromCode(await classicalCodeOf(alice, 'alice6'));
    await alice.addContactFromCode(await classicalCodeOf(bob, 'bob6'));
    expect(bob.assuranceWith(alice.myRid), IdentityAssurance.classical);
    await waitUntil(() => bob.contacts[alice.myRid]!.pqCandidate != null,
        what: "Alice's key arrives with nothing to check it against");

    // The two of them are in the same room after all. Bob scans Alice's
    // current code; its commitment checks the key he is already holding, so
    // the identity is established with no number read out at all.
    final same = await bob.addContactFromCode(await alice.myContactCode());
    expect(same.rid, alice.myRid, reason: 'the record was upgraded, not added');
    expect(bob.contacts.length, 1);
    expect(bob.assuranceWith(alice.myRid), IdentityAssurance.hybrid);
    expect(bob.contacts[alice.myRid]!.pqCandidate, isNull);
    expect(bob.contacts[alice.myRid]!.pqDisplay, PqDisplay.postQuantum);

    // Scanning it again now says what it always said.
    await expectLater(bob.addContactFromCode(await alice.myContactCode()),
        throwsA(isA<FormatException>()));

    // A code that commits to a DIFFERENT post-quantum key for the same
    // classical identity is refused: a person's post-quantum half does not
    // change under the same Ed25519 key unless something is wrong.
    final impostor = await HybridKeyPair.generate();
    final forged = ContactBundleV3(
      edPub: alice.identity.edPub,
      xPub: alice.identity.xPub,
      bindingSig: (await alice.identity.bundle()).bindingSig,
      pqCommit: await HybridPublicKey(
              edPub: alice.identity.edPub, mlPub: impostor.publicKey.mlPub)
          .pqCommitment(),
      displayName: 'alice6',
    ).encode();
    await expectLater(
        bob.addContactFromCode(forged), throwsA(isA<FormatException>()));
    expect(bob.contacts[alice.myRid]!.pqPub, isNotNull,
        reason: 'the key that was already established is untouched');
  });

  test('7. a candidate and what was said about it survive a restart',
      () async {
    final alice = await makeClient('alice7');
    final bob = await makeClient('bob7');
    await waitUntil(
        () => alice.transport.isConnected && bob.transport.isConnected);
    await alice.addContactFromCode(await classicalCodeOf(bob, 'bob7'));
    await bob.addContactFromCode(await classicalCodeOf(alice, 'alice7'));
    await expectOneNumber(alice, bob, postQuantum: true);
    final shown = await alice.safetyNumberWith(bob.myRid);
    final candidate = alice.contacts[bob.myRid]!.pqCandidate;
    await waitUntil(() => alice.contacts[bob.myRid]!.pqTold,
        what: 'Alice tells Bob she holds his key');

    await alice.transport.stop();
    final again = await makeClient('alice7', reuse: dirs['alice7']);
    final c = again.contacts[bob.myRid]!;
    expect(c.pqCandidate, candidate, reason: 'the key itself, sealed at rest');
    expect(c.pqAcked, isTrue, reason: 'that they hold ours');
    expect(c.pqTold, isTrue, reason: 'that we told them we hold theirs');
    expect(c.pqDisplay, PqDisplay.unverified);
    expect(await again.safetyNumberWith(bob.myRid), shown,
        reason: 'a restart does not move the number');

    // And the sealed cell really is sealed: the key is not in the database
    // file in the clear, the way no other secret in this vault is.
    final raw = await File('${dirs['alice7']!.path}/z.db').readAsBytes();
    expect(_contains(raw, candidate!), isFalse,
        reason: 'the candidate key is sealed at rest, like enc_pq_pub');
  });
  test('8. a candidate is not swapped, and a refused key is not softened',
      () async {
    final alice = await makeClient('alice8');
    final bob = await makeClient('bob8');
    await waitUntil(
        () => alice.transport.isConnected && bob.transport.isConnected);
    await alice.addContactFromCode(await classicalCodeOf(bob, 'bob8'));
    await bob.addContactFromCode(await classicalCodeOf(alice, 'alice8'));
    await expectOneNumber(alice, bob, postQuantum: true);
    final first = alice.contacts[bob.myRid]!.pqCandidate;
    final shown = await alice.safetyNumberWith(bob.myRid);

    // Bob's client is replaced by one that sends a DIFFERENT key. The ratchet
    // authenticates both as Bob, so nothing distinguishes the second arrival
    // from the first — which is exactly why the first one stands. Swapping
    // would move a number Alice may be reading aloud at that moment.
    final impostor = await HybridKeyPair.generate();
    await bob.debugSendRawInner(
        alice.myRid,
        InnerMessage.pqIdentity(
            'swap-attempt', DateTime.now().millisecondsSinceEpoch,
            impostor.publicKey.mlPub));
    // A positive control: a message sent after the forged key, on the same
    // ordered channel, arriving proves the forged envelope was delivered too.
    // Without it this assertion also passes when nothing was sent at all.
    await bob.sendText(alice.myRid, 'after the swap attempt');
    await waitUntil(
        () => (alice.messagesByChat[bob.myRid] ?? [])
            .any((m) => m.body == 'after the swap attempt'),
        what: 'the channel delivered what followed the forged key');
    expect(alice.contacts[bob.myRid]!.pqCandidate, first,
        reason: 'the first key to arrive is the candidate, and it stands');
    expect(await alice.safetyNumberWith(bob.myRid), shown,
        reason: 'so the number on screen did not move under her');

    // And a contact whose key was REFUSED against a commitment does not get a
    // candidate as a consolation: the refusal is the stronger statement, and
    // softening it into "well, here is a number anyway" is how a rejected key
    // would quietly come back as the thing two people compare.
    final carol = await makeClient('carol8');
    await waitUntil(() => carol.transport.isConnected);
    // Carol scans a code for Alice that commits to somebody else's key — the
    // substitution §18.2 exists to catch. Alice's genuine key then arrives
    // in-band and does not match it.
    final wrong = await HybridKeyPair.generate();
    final badCode = ContactBundleV3(
      edPub: alice.identity.edPub,
      xPub: alice.identity.xPub,
      bindingSig: (await alice.identity.bundle()).bindingSig,
      pqCommit: await HybridPublicKey(
              edPub: alice.identity.edPub, mlPub: wrong.publicKey.mlPub)
          .pqCommitment(),
      displayName: 'alice8',
    ).encode();
    await carol.addContactFromCode(badCode);
    await alice.addContactFromCode(await classicalCodeOf(carol, 'carol8'));
    await waitUntil(() => carol.contacts[alice.myRid]!.pqMismatch,
        what: 'the key that does not match the scanned commitment is refused');
    expect(carol.contacts[alice.myRid]!.pqCandidate, isNull);
    expect(carol.contacts[alice.myRid]!.showsPostQuantumNumber, isFalse,
        reason: 'a refused contact shows the classical number');

    // Even with the commitment gone — the state a restore of a build that
    // recorded only the refusal would leave — the refusal still stands.
    await carol.vault.db.update('contacts', {'pq_commit': null},
        where: 'rid = ?', whereArgs: [alice.myRid]);
    await carol.reloadContacts();
    await alice.debugSendRawInner(
        carol.myRid,
        InnerMessage.pqIdentity('after-refusal',
            DateTime.now().millisecondsSinceEpoch, wrong.publicKey.mlPub));
    await alice.sendText(carol.myRid, 'after the refusal');
    await waitUntil(
        () => (carol.messagesByChat[alice.myRid] ?? [])
            .any((m) => m.body == 'after the refusal'),
        what: 'the channel delivered what followed the refused key');
    expect(carol.contacts[alice.myRid]!.pqCandidate, isNull,
        reason: 'a refused contact is not given a candidate instead');
    expect(carol.contacts[alice.myRid]!.showsPostQuantumNumber, isFalse);
  });

  test('9. a backup carries the candidate and both flags', () async {
    final alice = await makeClient('alice9');
    final bob = await makeClient('bob9');
    await waitUntil(
        () => alice.transport.isConnected && bob.transport.isConnected);
    await alice.addContactFromCode(await classicalCodeOf(bob, 'bob9'));
    await bob.addContactFromCode(await classicalCodeOf(alice, 'alice9'));
    await expectOneNumber(alice, bob, postQuantum: true);
    final candidate = alice.contacts[bob.myRid]!.pqCandidate;
    final shown = await alice.safetyNumberWith(bob.myRid);

    // Export, then restore into a brand-new vault and read the number back.
    final dir = await Directory.systemTemp.createTemp('z_snm_backup');
    temps.add(dir);
    final file = File('${dir.path}/z.zbk');
    final code = await RecoveryCode.generate();
    final sink = file.openWrite();
    await BackupArchive.export(vault: alice.vault, code: code, out: sink);
    await sink.close();

    final restoredDir = await Directory.systemTemp.createTemp('z_snm_restored');
    temps.add(restoredDir);
    final restoredVault = await Vault.open(rootOverride: restoredDir);
    await BackupArchive.import(
        vault: restoredVault, code: code, file: file);
    final restored = await ChatService.init(
        vault: restoredVault,
        identity: alice.identity,
        displayName: 'alice9',
        transport: Transport(
            identity: alice.identity, serverUrl: 'ws://127.0.0.1:$port'));
    services.add(restored);

    final c = restored.contacts[bob.myRid]!;
    expect(c.pqCandidate, candidate,
        reason: 'a restore without the candidate would show the classical '
            'number again and ask for the ceremony a second time, for nothing');
    expect(c.pqAcked, isTrue, reason: 'and would not know to show it at all');
    expect(c.pqTold, isTrue);
    expect(await restored.safetyNumberWith(bob.myRid), shown,
        reason: 'the restored device is on the number the backup was taken on');
  });
}



bool _contains(Uint8List haystack, Uint8List needle) {
  if (needle.isEmpty || needle.length > haystack.length) return false;
  for (var i = 0; i + needle.length <= haystack.length; i++) {
    var hit = true;
    for (var j = 0; j < needle.length; j++) {
      if (haystack[i + j] != needle[j]) {
        hit = false;
        break;
      }
    }
    if (hit) return true;
  }
  return false;
}
