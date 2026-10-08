// 26.3 — what the screens say about post-quantum is true.
//
// Four things the analysis of 3 October found the app saying that were not
// so, each tested here against real clients over a real relay:
//
//  * every contact verified by a CONNECT ceremony flipped to "re-verify" a
//    few seconds after its post-quantum key landed, although the eight digits
//    had already covered both post-quantum commitments;
//  * the contact code's `pqc` was not covered by any signature, so anyone
//    holding a person's public code could rewrite it and have a contact of
//    theirs flagged "do not rely on this chat" for good, while the add screen
//    promised that a tampered code is rejected (ADR 0027 signs it);
//  * nothing on screen said whether MESSAGES were protected by the hybrid key
//    exchange — the green pill describes the identity — so a chat that stayed
//    classical looked exactly like one that did not;
//  * the device-list sentence said the set "cannot be forged", which is not
//    true of the devices' ratchet keys until ADR 0017 stage 2b.
//
// Criteria, each a test below:
//   1. a contact verified by a connect ceremony stays verified when the
//      post-quantum key the digits covered lands — never seen as
//      "re-verify", the tick moved onto the post-quantum number, on both
//      sides, and still so after a restart — and (1b) whichever of the key
//      and the tick is written first;
//   2. a key the ceremony did NOT cover still flips: (a) one that misses the
//      commitment the digits covered is refused and moves no tick onto a
//      post-quantum number; (b) after a ceremony that covered no commitment —
//      the peer revealed a classical code — the key that arrives later is a
//      candidate, and when its number shows, the tick asks for a comparison;
//   3. a pasted code whose UNSIGNED commitment was rewritten does not poison
//      an existing contact that holds a candidate key: the code is refused
//      and nothing changes;
//   4. one pasted before any key has arrived does not turn the key that then
//      arrives into a refusal (it is a candidate), while a GENUINE unsigned
//      commitment pasted the same way still establishes the key it commits
//      to — the upgrade an older peer's code gave, kept;
//   5. a SIGNED commitment that differs from what is held is a real key
//      change and gets today's answer: refused against a held commitment, and
//      against a held candidate the candidate is refused and the contact
//      flagged;
//   6. a code stripped of the signed commitment a contact is known to have —
//      both members removed, or the signature alone — is surfaced as such and
//      changes nothing, and what is known survives a restart;
//   7. the contact screen says whether messages are post-quantum right now,
//      and it is the session state: not before the first post-quantum round
//      trip, post-quantum after — with an accessibility label saying the
//      same;
//   8. the group screen names the members whose channels are not
//      post-quantum yet, and stops naming them once they are;
//   9. the device-list sentence: a list signed post-quantum over its
//      membership only no longer says its keys cannot be forged, and a
//      v2-only list (ADR 0017 stage 2) says its keys are covered.

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/connect_invites.dart';
import 'package:zapp/core/models.dart';
import 'package:zapp/core/system_messages.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/l10n/app_localizations.dart';
import 'package:zapp/ui/contact_info_screen.dart';
import 'package:zapp/ui/group_screens.dart';
import 'package:zapp/ui/theme.dart';

typedef Person = ({
  ChatService svc,
  Vault vault,
  ConnectInvites invites,
  Directory dir,
  ZIdentity id,
  String name,
});

bool isMismatchWarning(ChatMessage m) {
  if (m.kind != 'system' || !m.body.startsWith('{')) return false;
  final j = jsonDecode(m.body);
  return j is Map && j['k'] == SystemKind.pqMismatch;
}

/// A contact code with its JSON edited — what anyone holding someone's
/// PUBLIC code can produce, since nothing in it is secret.
String editCode(String code, void Function(Map<String, Object?> j) edit) {
  final prefix = code.substring(0, 4);
  final j = (jsonDecode(utf8.decode(unb64url(code.substring(4)))) as Map)
      .cast<String, Object?>();
  edit(j);
  return prefix + b64url(utf8.encode(jsonEncode(j)));
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  late Process relay;
  late int port;
  final temps = <Directory>[];
  final live = <Person>[];

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
    // Disposed, which stops every timer of theirs, and their vaults left
    // open, as the other relay-driven files leave them: closing one under a
    // periodic sweep that has just started fails that sweep against a closed
    // database, and the error lands on whichever test made the service.
    for (final p in live) {
      p.invites.pause();
      await p.svc.transport.stop();
      p.svc.dispose();
    }
    relay.kill();
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<Person> open(Directory dir, ZIdentity id, String name,
      {bool signDevlistV2Only = false}) async {
    final vault = await Vault.open(rootOverride: dir);
    await vault.kvPut('identity', jsonEncode(id.toJson()));
    final svc = await ChatService.init(
        vault: vault,
        identity: id,
        displayName: name,
        transport: Transport(identity: id, serverUrl: 'ws://127.0.0.1:$port'),
        signDevlistV2Only: signDevlistV2Only);
    // The production delay is hours; what is under test is not the delay.
    svc.pqListDelay = const Duration(milliseconds: 150);
    final p = (
      svc: svc,
      vault: vault,
      invites: ConnectInvites(svc),
      dir: dir,
      id: id,
      name: name,
    );
    live.add(p);
    return p;
  }

  Future<Person> person(String name, {bool signDevlistV2Only = false}) async {
    final dir = await Directory.systemTemp.createTemp('z_pqs_');
    temps.add(dir);
    return open(dir, await ZIdentity.generate(), name,
        signDevlistV2Only: signDevlistV2Only);
  }

  /// The app killed and started again on the same vault.
  Future<Person> restart(Person p) async {
    p.invites.pause();
    await p.svc.transport.stop();
    p.svc.dispose();
    await p.vault.db.close();
    live.remove(p);
    return open(p.dir, p.id, p.name);
  }

  Future<void> waitUntil(bool Function() cond,
      {Duration timeout = const Duration(seconds: 30),
      required String what}) async {
    final deadline = DateTime.now().add(timeout);
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
  }

  Future<void> connected(List<Person> people) => waitUntil(
      () => people.every((p) => p.svc.transport.isConnected),
      what: 'everyone connected to the relay');

  /// Step both sides of a connect ceremony until both show the digits.
  Future<void> danceTo(Person a, Person b) async {
    for (var i = 0; i < 8; i++) {
      await a.invites.pump();
      await b.invites.pump();
      if (a.invites.invites.any((x) => x.sas != null) &&
          b.invites.invites.any((x) => x.sas != null)) {
        return;
      }
    }
    fail('the ceremony did not reach the digits');
  }

  /// Both sides hold each other's post-quantum key and have finished saying
  /// so: nothing about either identity is still in the air.
  Future<void> keysSettled(Person a, Person b) => waitUntil(
      () =>
          a.svc.contacts[b.svc.myRid]?.numberKey != null &&
          b.svc.contacts[a.svc.myRid]?.numberKey != null &&
          !a.svc.pqSendPending &&
          !b.svc.pqSendPending,
      what: 'both post-quantum keys landed and the exchange went quiet');

  /// [from] says [body] to [to], and it arrives.
  Future<void> say(Person from, Person to, String body) async {
    await from.svc.sendText(to.svc.myRid, body);
    await waitUntil(
        () => (to.svc.messagesByChat[from.svc.myRid] ?? [])
            .any((m) => m.body == body),
        what: '"$body" arrived');
  }

  /// [a] and [b] talk until every channel between them is post-quantum both
  /// ways, as their sessions report it — which takes messages in both
  /// directions, and on the encapsulating side one more after the offerer
  /// has the ciphertext. Bounded: an exchange that never completes fails.
  Future<void> talkUntilPq(Person a, Person b) async {
    for (var round = 0; round < 8; round++) {
      if (a.svc.messagePqWith(b.svc.myRid).all &&
          b.svc.messagePqWith(a.svc.myRid).all) {
        return;
      }
      await say(a, b, 'ping $round');
      await say(b, a, 'pong $round');
    }
    await waitUntil(
        () =>
            a.svc.messagePqWith(b.svc.myRid).all &&
            b.svc.messagePqWith(a.svc.myRid).all,
        what: 'every channel between them post-quantum both ways');
  }

  /// Two people who have exchanged codes and spoken both ways.
  Future<(Person, Person)> pair(String a, String b,
      {bool signDevlistV2Only = false}) async {
    final x = await person(a);
    final y = await person(b, signDevlistV2Only: signDevlistV2Only);
    await connected([x, y]);
    await x.svc.addContactFromCode(await y.svc.myContactCode());
    await y.svc.addContactFromCode(await x.svc.myContactCode());
    await say(x, y, 'hi');
    await say(y, x, 'hi back');
    await keysSettled(x, y);
    return (x, y);
  }

  /// [b] added to [a] by accepting a request: no commitment held for [b].
  Future<(Person, Person)> accepted(String a, String b) async {
    final x = await person(a);
    final y = await person(b);
    await connected([x, y]);
    await y.svc.addContactFromCode(await x.svc.myContactCode());
    await waitUntil(() => x.svc.requestsByRid.containsKey(y.svc.myRid),
        what: "$b's request reached $a");
    await x.svc.acceptRequest(y.svc.myRid);
    await say(x, y, 'hi');
    await keysSettled(x, y);
    return (x, y);
  }

  Future<String> classicalNumber(Person a, Contact c) async => safetyNumber(
      (await a.svc.accountIdentity()).accountEdPub, c.accountEd);

  test(
      '1. a contact verified by a connect ceremony stays verified when the '
      'post-quantum key the digits covered lands', () async {
    final alice = await person('Alice');
    final bob = await person('Bob');
    await connected([alice, bob]);
    final invite = await alice.invites.create();
    await bob.invites.open(invite.link);
    await danceTo(alice, bob);

    // Both read the eight digits and they matched. The digits covered both
    // account keys AND both post-quantum commitments (§20.4).
    final seen = <VerificationState>[];
    late final String bobRid;
    void watch() {
      final st = alice.svc.verificationWith(bobRid);
      if (seen.isEmpty || seen.last != st) seen.add(st);
    }

    final added = await alice.invites.confirm(alice.invites.invites.single);
    bobRid = added.rid;
    alice.svc.addListener(watch);
    await bob.invites.confirm(bob.invites.invites.single);
    expect(alice.svc.verificationWith(bobRid), VerificationState.verified);

    // The keys land a few seconds later, on the first traffic.
    await alice.svc.sendText(bobRid, 'hello');
    await keysSettled(alice, bob);
    alice.svc.removeListener(watch);

    final c = alice.svc.contacts[bobRid]!;
    expect(c.assurance, IdentityAssurance.hybrid,
        reason: 'the key matched the commitment the digits covered');
    expect(seen, isNot(contains(VerificationState.upgradedReverify)),
        reason: 'the eight digits already covered this key: asking for '
            'another comparison is the bug');
    expect(alice.svc.verificationWith(bobRid), VerificationState.verified);
    final shown = await alice.svc.safetyNumberWith(bobRid);
    expect(shown, isNot(await classicalNumber(alice, c)),
        reason: 'the number shown is the post-quantum one');
    expect(c.verifiedSn, shown,
        reason: 'and the tick now stands on the number being shown');
    expect(await alice.vault.kvGet('vpqc_$bobRid'), isNull,
        reason: 'what the ceremony covered has been used, and is gone');
    final bobSide = bob.svc.contacts[alice.svc.myRid]!;
    expect(bob.svc.verificationWith(bobSide.rid), VerificationState.verified,
        reason: 'the same holds on the other side of the ceremony');
    expect(await bob.svc.safetyNumberWith(bobSide.rid), shown,
        reason: 'and both screens show one post-quantum number');

    // A restart reads the moved tick back from disk.
    final again = await restart(alice);
    await connected([again]);
    expect(again.svc.verificationWith(bobRid), VerificationState.verified);
    expect(again.svc.contacts[bobRid]!.verifiedSn, shown);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test(
      '1b. a key already installed when the tick is read back moves it too',
      () async {
    // The order is not guaranteed: the two people answer the digits
    // independently, and the peer's key can land between the add and the
    // tick, or the app can stop between the two. Whichever comes first, the
    // next read of the tick reaches the same answer.
    final alice = await person('Alice1b');
    final bob = await person('Bob1b');
    await connected([alice, bob]);
    final invite = await alice.invites.create();
    await bob.invites.open(invite.link);
    await danceTo(alice, bob);
    // Alice answers; Bob never does, so his app never adds her and his key
    // never travels — the tick is on the classical number, holding what the
    // digits covered.
    final added = await alice.invites.confirm(alice.invites.invites.single);
    final bobRid = added.rid;
    final held = alice.svc.contacts[bobRid]!;
    expect(held.verifiedPqc, isNotNull);
    expect(held.verifiedSn, await classicalNumber(alice, held));

    // The key is installed exactly as an inbound `pqid` installs it, behind
    // the tick's back, and the record is read again from disk.
    final bobMl = (await bob.svc.pqAccountPublic())!;
    await alice.vault.db.update(
        'contacts', {'enc_pq_pub': await alice.vault.seal(b64(bobMl))},
        where: 'rid = ?', whereArgs: [bobRid]);
    await alice.svc.reloadContacts();

    final c = alice.svc.contacts[bobRid]!;
    expect(c.assurance, IdentityAssurance.hybrid);
    expect(alice.svc.verificationWith(bobRid), VerificationState.verified,
        reason: 'the digits covered this key, however late the tick is read');
    expect(c.verifiedSn, await alice.svc.safetyNumberWith(bobRid));
    expect(c.verifiedSn, isNot(await classicalNumber(alice, c)));
    expect(await alice.vault.kvGet('vpqc_$bobRid'), isNull);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test(
      '2a. a key that misses the commitment the digits covered is refused, '
      'and moves no tick', () async {
    final alice = await person('Alice2');
    final bob = await person('Bob2');
    await connected([alice, bob]);
    // Bob's side of the ceremony reveals a code committing to a key his app
    // does not hold — what a broken app, or someone in his seat, produces.
    // It is a genuine, signed code of his identity; only the key differs.
    final impostor = await HybridKeyPair.fromSeeds(
        edSeed: bob.id.edSeed, mlSeed: randomBytes(32));
    bob.invites.debugMyCode = (await ContactBundleV3.forIdentity(
            bob.id, impostor.publicKey,
            displayName: 'Bob2'))
        .encode();
    final invite = await alice.invites.create();
    await bob.invites.open(invite.link);
    await danceTo(alice, bob);
    // The digits covered the impostor commitment on both screens, so they
    // match and Alice confirms.
    final added = await alice.invites.confirm(alice.invites.invites.single);
    final bobRid = added.rid;
    await bob.invites.confirm(bob.invites.invites.single);
    expect(alice.svc.contacts[bobRid]!.verifiedPqc,
        await impostor.publicKey.pqCommitment(),
        reason: 'the tick carries what the digits covered');

    // Bob's app then sends the key it really holds. The refusal is recorded
    // first and announced in the chat after it, so wait for both.
    await say(alice, bob, 'hello');
    await waitUntil(
        () =>
            alice.svc.contacts[bobRid]!.pqMismatch &&
            (alice.svc.messagesByChat[bobRid] ?? []).any(isMismatchWarning),
        what: "Bob's key reached Alice, was refused, and the chat said so");

    final c = alice.svc.contacts[bobRid]!;
    expect(c.pqPub, isNull, reason: 'refused: never established');
    expect(c.assurance, isNot(IdentityAssurance.hybrid));
    expect(c.pqDisplay, PqDisplay.mismatch,
        reason: 'the contact screen shows the refusal');
    expect(
        (alice.svc.messagesByChat[bobRid] ?? []).where(isMismatchWarning),
        hasLength(1),
        reason: 'and the chat says so once');
    final classical = await classicalNumber(alice, c);
    expect(c.verifiedSn, classical,
        reason: 'the tick did not move onto any post-quantum number: the '
            'digits never covered this key');
    expect(await alice.svc.safetyNumberWith(bobRid), classical);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test(
      '2b. after a ceremony that covered no commitment, the key that arrives '
      'later still asks for a comparison', () async {
    final alice = await person('Alice3');
    final bob = await person('Bob3');
    await connected([alice, bob]);
    // Bob reveals his CLASSICAL code: the digits cover his account key and
    // 32 zero bytes where a commitment would be. His app still has a
    // post-quantum key, and sends it in-band afterwards.
    bob.invites.debugMyCode =
        (await bob.id.bundle(displayName: 'Bob3')).encode();
    final invite = await alice.invites.create();
    await bob.invites.open(invite.link);
    await danceTo(alice, bob);
    final added = await alice.invites.confirm(alice.invites.invites.single);
    final bobRid = added.rid;
    await bob.invites.confirm(bob.invites.invites.single);
    expect(alice.svc.verificationWith(bobRid), VerificationState.verified);
    expect(alice.svc.contacts[bobRid]!.pqCommit, isNull);
    expect(alice.svc.contacts[bobRid]!.verifiedPqc, isNull,
        reason: 'nothing post-quantum was covered, so nothing is carried');

    await say(alice, bob, 'hello');
    await say(bob, alice, 'hello back');
    // Bob's key reaches Alice as an ADR 0021 candidate; once Bob says he
    // holds hers, its number is the one shown.
    await waitUntil(
        () => alice.svc.contacts[bobRid]!.showsPostQuantumNumber,
        what: "Bob's candidate's number is shown");
    expect(alice.svc.contacts[bobRid]!.pqCandidate, isNotNull);
    expect(alice.svc.verificationWith(bobRid),
        VerificationState.upgradedReverify,
        reason: 'the digits did not cover this key, so the tick asks');
    final c = alice.svc.contacts[bobRid]!;
    expect(c.verifiedSn, await classicalNumber(alice, c));
  }, timeout: const Timeout(Duration(minutes: 3)));

  test(
      '3. a pasted code whose unsigned commitment was rewritten does not '
      'poison an existing contact', () async {
    // Ana accepted Ben's request, so she holds no commitment of his: his key
    // reaches her as an ADR 0021 candidate.
    final (ana, ben) = await accepted('Ana', 'Ben');
    final held = ana.svc.contacts[ben.svc.myRid]!;
    expect(held.pqCommit, isNull);
    expect(held.pqCandidate, isNotNull);

    // Mallory holds Ben's PUBLIC code and rewrites the commitment in it,
    // removing the signature that would give the edit away: what is left is
    // what every code from before ADR 0027 looks like.
    final forged = editCode(await ben.svc.myContactCode(), (j) {
      j['pqc'] = b64(randomBytes(32));
      j.remove('pqcs');
    });
    final before = await ana.svc.safetyNumberWith(ben.svc.myRid);
    Object? error;
    try {
      await ana.svc.addContactFromCode(forged);
    } on FormatException catch (e) {
      error = e;
    }
    expect(error, isA<ContactCodeRefused>(),
        reason: 'the code is refused, not taken');
    expect((error as ContactCodeRefused).kind,
        ContactCodeRefusal.unsignedCommitMismatch);
    final after = ana.svc.contacts[ben.svc.myRid]!;
    expect(after.pqMismatch, isFalse,
        reason: 'an unsigned commitment is not evidence against a key');
    expect(after.pqCandidate, held.pqCandidate,
        reason: 'the key held for the number stays');
    expect(after.pqCommit, isNull);
    expect(after.pqcHint, isNull);
    expect((ana.svc.messagesByChat[ben.svc.myRid] ?? []).any(isMismatchWarning),
        isFalse,
        reason: 'no "do not rely on this chat" was written into the chat');
    expect(await ana.svc.safetyNumberWith(ben.svc.myRid), before);

    // Ben's own current code — signed — still upgrades her record, as a
    // re-scan always has (ADR 0021).
    await ana.svc.addContactFromCode(await ben.svc.myContactCode());
    final up = ana.svc.contacts[ben.svc.myRid]!;
    expect(up.assurance, IdentityAssurance.hybrid);
    expect(up.pqcSigned, isTrue);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test(
      '4. an unsigned commitment pasted before the key arrives is a candidate '
      'for it: a forged one cannot refuse the key, a genuine one establishes '
      'it', () async {
    // Cleo added Dan from his CLASSICAL code; Dan has not added her back, so
    // nothing of his has reached her yet.
    final cleo = await person('Cleo');
    final dan = await person('Dan');
    final eli = await person('Eli');
    await connected([cleo, dan, eli]);
    await cleo.svc.addContactFromCode(
        (await dan.id.bundle(displayName: 'Dan')).encode());
    expect(cleo.svc.contacts[dan.svc.myRid]!.numberKey, isNull);

    final forged = editCode(await dan.svc.myContactCode(), (j) {
      j['pqc'] = b64(randomBytes(32));
      j.remove('pqcs');
    });
    await cleo.svc.addContactFromCode(forged);
    final hinted = cleo.svc.contacts[dan.svc.myRid]!;
    expect(hinted.pqCommit, isNull,
        reason: 'held as a candidate, never as a commitment');
    expect(hinted.pqcHint, isNotNull);
    expect(hinted.assurance, IdentityAssurance.classical);

    // Now Dan adds Cleo and they talk: his real key reaches her.
    await dan.svc.addContactFromCode(await cleo.svc.myContactCode());
    await say(dan, cleo, 'hello Cleo');
    await say(cleo, dan, 'hello Dan');
    // Dan's key has reached Cleo and been decided on — kept, or refused.
    await waitUntil(() {
      final c = cleo.svc.contacts[dan.svc.myRid]!;
      return c.pqMismatch || c.numberKey != null;
    }, what: "Dan's key reached Cleo and was decided on");

    final c = cleo.svc.contacts[dan.svc.myRid]!;
    expect(c.pqMismatch, isFalse,
        reason: "the forged commitment must not turn Dan's real key into a "
            '"do not rely on this chat"');
    expect(
        (cleo.svc.messagesByChat[dan.svc.myRid] ?? []).any(isMismatchWarning),
        isFalse);
    expect(c.pqCandidate, isNotNull, reason: "Dan's key is a candidate");
    expect(c.pqcHint, isNull, reason: 'the hint that missed is dropped');

    // The same with a GENUINE older-format code: Eli's own code with its
    // signature removed, as a build before ADR 0027 hands it out.
    await cleo.svc.addContactFromCode(
        (await eli.id.bundle(displayName: 'Eli')).encode());
    await cleo.svc.addContactFromCode(
        editCode(await eli.svc.myContactCode(), (j) => j.remove('pqcs')));
    expect(cleo.svc.contacts[eli.svc.myRid]!.pqcHint, isNotNull);
    await eli.svc.addContactFromCode(await cleo.svc.myContactCode());
    await say(eli, cleo, 'hello Cleo');
    await say(cleo, eli, 'hello Eli');
    await waitUntil(() => cleo.svc.contacts[eli.svc.myRid]!.pqPub != null,
        what: "Eli's key established against the commitment Cleo pasted");
    final e = cleo.svc.contacts[eli.svc.myRid]!;
    expect(e.assurance, IdentityAssurance.hybrid,
        reason: 'two candidates that agree establish the key (ADR 0021)');
    expect(e.pqCommit, isNotNull);
    expect(e.pqcHint, isNull);
    expect(await cleo.vault.kvGet('pqcc_${eli.svc.myRid}'), isNull);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test(
      '5. a signed commitment that differs from what is held is a real key '
      'change', () async {
    // (a) Against a held commitment: refused, and nothing changes.
    final (ivy, jon) = await pair('Ivy', 'Jon');
    final jonRid = jon.svc.myRid;
    final heldCommit = ivy.svc.contacts[jonRid]!.pqCommit;
    final other = await HybridKeyPair.fromSeeds(
        edSeed: jon.id.edSeed, mlSeed: randomBytes(32));
    final reset = (await ContactBundleV3.forIdentity(jon.id, other.publicKey,
            displayName: 'Jon'))
        .encode();
    await expectLater(ivy.svc.addContactFromCode(reset),
        throwsA(predicate((e) =>
            e is FormatException &&
            e is! ContactCodeRefused &&
            e.message.contains('not the one you hold'))));
    expect(ivy.svc.contacts[jonRid]!.pqCommit, heldCommit);
    expect(ivy.svc.contacts[jonRid]!.pqMismatch, isFalse);

    // (b) Against a held candidate: the candidate is refused and the contact
    // flagged — a commitment the contact's own key signed disagrees with the
    // key that arrived as theirs.
    final (kim, lee) = await accepted('Kim', 'Lee');
    final leeRid = lee.svc.myRid;
    expect(kim.svc.contacts[leeRid]!.pqCandidate, isNotNull);
    final otherLee = await HybridKeyPair.fromSeeds(
        edSeed: lee.id.edSeed, mlSeed: randomBytes(32));
    final signedOther = (await ContactBundleV3.forIdentity(
            lee.id, otherLee.publicKey,
            displayName: 'Lee'))
        .encode();
    await expectLater(kim.svc.addContactFromCode(signedOther),
        throwsA(isA<FormatException>()));
    final c = kim.svc.contacts[leeRid]!;
    expect(c.pqMismatch, isTrue);
    expect(c.pqCandidate, isNull);
    expect(c.pqcSigned, isTrue);
    expect((kim.svc.messagesByChat[leeRid] ?? []).any(isMismatchWarning),
        isTrue);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test(
      '6. a code stripped of the signed commitment a contact is known to have '
      'is surfaced, and changes nothing', () async {
    final (eveFirst, fay) = await pair('Eve', 'Fay');
    var eve = eveFirst;
    final fayRid = fay.svc.myRid;
    expect(eve.svc.contacts[fayRid]!.pqcSigned, isTrue,
        reason: 'Eve added Fay from a code that signs its commitment');
    expect(await eve.vault.kvGet('pqcs_$fayRid'), '1');

    final current = await fay.svc.myContactCode();
    for (final (what, stripped) in [
      (
        'the commitment and its signature',
        editCode(current, (j) {
          j.remove('pqc');
          j.remove('pqcs');
        })
      ),
      ('the signature alone', editCode(current, (j) => j.remove('pqcs'))),
    ]) {
      Object? error;
      try {
        await eve.svc.addContactFromCode(stripped);
      } on FormatException catch (e) {
        error = e;
      }
      expect(error, isA<ContactCodeRefused>(), reason: what);
      expect((error as ContactCodeRefused).kind,
          ContactCodeRefusal.commitStripped,
          reason: what);
      expect(error.message, contains('post-quantum'), reason: what);
      final after = eve.svc.contacts[fayRid]!;
      expect(after.assurance, IdentityAssurance.hybrid, reason: what);
      expect(after.pqMismatch, isFalse, reason: what);
      expect(after.pqcHint, isNull, reason: what);
    }
    // Her current code is what it always was: nothing new.
    await expectLater(eve.svc.addContactFromCode(current),
        throwsA(predicate((e) =>
            e is FormatException &&
            e is! ContactCodeRefused &&
            e.message.contains('already in your contacts'))));

    // What is known survives the app restarting.
    eve = await restart(eve);
    expect(eve.svc.contacts[fayRid]!.pqcSigned, isTrue);
    await expectLater(
        eve.svc.addContactFromCode(editCode(current, (j) => j.remove('pqcs'))),
        throwsA(isA<ContactCodeRefused>()));
  }, timeout: const Timeout(Duration(minutes: 3)));

  Widget wrap(ChatService svc, Widget child) =>
      ChangeNotifierProvider<ChatService>.value(
        value: svc,
        child: MaterialApp(
          debugShowCheckedModeBanner: false,
          theme: ZTheme.light(),
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: child,
        ),
      );

  /// Rebuild until [cond] holds against the widget tree, letting real work
  /// run in between (a widget test's clock is fake).
  Future<void> settleUntil(WidgetTester t, bool Function() cond,
      {required String what}) async {
    final deadline = DateTime.now().add(const Duration(seconds: 30));
    await t.pump(const Duration(milliseconds: 50));
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        fail('the screen never showed: $what');
      }
      await t.runAsync(
          () => Future<void>.delayed(const Duration(milliseconds: 100)));
      await t.pump(const Duration(milliseconds: 50));
    }
  }

  /// Opening a contact's screen on a contact whose post-quantum key is not
  /// held asks them for it (ADR 0021, `requestPqIdentity`), and that nudge
  /// waits on a debounce — two or twenty `pqSendDebounce`s, by how the two
  /// routing ids sort — armed on the widget test's FAKE clock, which only
  /// `pump` moves. When nothing in the exchange supersedes it, a test that
  /// ends there fails on a pending timer, one run in a few depending on the
  /// random ids. So: move the fake clock, letting real work run in between,
  /// until [svc] has no post-quantum identity send pending
  /// (`pqSendPending`, which counts that timer) — it has fired, finding the
  /// key held and sending nothing, or been superseded.
  Future<void> settlePqSends(WidgetTester t, ChatService svc) async {
    final deadline = DateTime.now().add(const Duration(seconds: 30));
    while (svc.pqSendPending) {
      if (DateTime.now().isAfter(deadline)) {
        fail('a post-quantum identity send was still pending after 30 s');
      }
      await t.pump(const Duration(seconds: 1));
      await t.runAsync(
          () => Future<void>.delayed(const Duration(milliseconds: 50)));
    }
  }

  /// Unmount, and let the screen's own async work finish against a live
  /// vault before the next test.
  Future<void> leave(WidgetTester t) async {
    await t.pumpWidget(const SizedBox());
    await t.runAsync(
        () => Future<void>.delayed(const Duration(milliseconds: 300)));
  }

  testWidgets(
      '7. the contact screen says whether messages are post-quantum right '
      'now, as the session does', (t) async {
    await t.binding.setSurfaceSize(const Size(800, 3000));
    addTearDown(() => t.binding.setSurfaceSize(null));
    final semantics = t.ensureSemantics();
    late Person gil, hal;
    await t.runAsync(() async {
      gil = await person('Gil');
      hal = await person('Hal');
      await connected([gil, hal]);
      // Gil adds Hal; Hal has not answered, so nothing post-quantum has run.
      await gil.svc.addContactFromCode(await hal.svc.myContactCode());
    });
    final halRid = hal.svc.myRid;
    final before = gil.svc.messagePqWith(halRid);
    expect(before.contact, isFalse);
    expect(before.all, isFalse);
    expect(gil.svc.debugConversation(halRid)?.isPostQuantumBothWays ?? false,
        isFalse,
        reason: 'the line and the session agree');
    await t.pumpWidget(wrap(gil.svc, ContactInfoScreen(rid: halRid)));
    await settleUntil(
        t,
        () =>
            find.text('Messages: not post-quantum yet').evaluate().isNotEmpty,
        what: 'not post-quantum before the first round trip');
    expect(find.textContaining("Hal's device"), findsOneWidget,
        reason: 'it names the channel that is not');
    expect(find.text('Messages: post-quantum'), findsNothing);
    expect(
        find.bySemanticsLabel(RegExp('^Messages: not post-quantum yet')),
        findsOneWidget,
        reason: 'and a screen reader is told the same');

    // Hal adds Gil and they talk both ways: the exchange completes.
    await t.runAsync(() async {
      await hal.svc.addContactFromCode(await gil.svc.myContactCode());
      await talkUntilPq(gil, hal);
    });
    expect(gil.svc.debugConversation(halRid)!.isPostQuantumBothWays, isTrue);
    expect(gil.svc.debugConversation(halRid)!.isPostQuantum, isTrue);
    await settleUntil(
        t, () => find.text('Messages: post-quantum').evaluate().isNotEmpty,
        what: 'post-quantum after it');
    expect(find.text('Messages: not post-quantum yet'), findsNothing);
    expect(find.bySemanticsLabel(RegExp('^Messages: post-quantum')),
        findsOneWidget);
    // The nudge the screen armed when it opened, before Hal answered.
    await settlePqSends(t, gil.svc);
    await leave(t);
    semantics.dispose();
  }, timeout: const Timeout(Duration(minutes: 3)));

  testWidgets(
      '8. the group screen names the members whose channels are not '
      'post-quantum yet', (t) async {
    await t.binding.setSurfaceSize(const Size(800, 3000));
    addTearDown(() => t.binding.setSurfaceSize(null));
    late Person ann, bea, cal;
    late String gid;
    await t.runAsync(() async {
      (ann, bea) = await pair('Ann', 'Bea');
      await talkUntilPq(ann, bea);
      cal = await person('Cal');
      await connected([cal]);
      // Ann adds Cal, who has not answered: no post-quantum exchange yet.
      await ann.svc.addContactFromCode(await cal.svc.myContactCode());
      gid = await ann.svc.createGroup('Trio', [bea.svc.myRid, cal.svc.myRid]);
    });
    final pq = ann.svc.groupMessagePq(gid);
    expect(pq.notYet, [cal.svc.myRid], reason: 'Cal, and only Cal');
    await t.pumpWidget(wrap(ann.svc, GroupInfoScreen(gid: gid)));
    await settleUntil(
        t,
        () =>
            find.text('Messages: not post-quantum yet').evaluate().isNotEmpty,
        what: 'the group line, not post-quantum yet');
    expect(find.textContaining('has not completed with Cal'), findsOneWidget,
        reason: 'the member it is not post-quantum with is named');
    expect(find.textContaining('Bea,'), findsNothing,
        reason: 'and the member it is post-quantum with is not');

    await t.runAsync(() async {
      await cal.svc.addContactFromCode(await ann.svc.myContactCode());
      await talkUntilPq(ann, cal);
      await waitUntil(() => ann.svc.groupMessagePq(gid).all,
          what: "every member's channel is post-quantum both ways");
    });
    await settleUntil(
        t, () => find.text('Messages: post-quantum').evaluate().isNotEmpty,
        what: 'the group line, post-quantum');
    expect(find.textContaining('New messages in this group'), findsOneWidget);
    await leave(t);
  }, timeout: const Timeout(Duration(minutes: 3)));

  Future<void> linkLaptop(Person p) async {
    final acct = await p.svc.accountIdentity();
    final laptop = await ZIdentity.generate();
    await p.svc.addMyDevice(await acct.signDeviceCert(
        deviceEdPub: laptop.edPub, deviceXPub: laptop.xPub, deviceId: 'laptop'));
  }

  testWidgets(
      '9a. a device list signed post-quantum over its membership only does not '
      'claim its keys cannot be forged', (t) async {
    await t.binding.setSurfaceSize(const Size(800, 3000));
    addTearDown(() => t.binding.setSurfaceSize(null));
    late Person ivy, jon;
    await t.runAsync(() async {
      (ivy, jon) = await pair('Ivo', 'Joe');
      // Joe links a laptop, so his list names a device whose ratchet key the
      // stage-1 post-quantum signature does not cover.
      await linkLaptop(jon);
      await waitUntil(
          () =>
              ivy.svc.deviceAssuranceWith(jon.svc.myRid) ==
              DeviceAssurance.hybrid,
          what: "Joe's list is post-quantum verified at Ivo");
    });
    expect(ivy.svc.deviceListCoversKeys(jon.svc.myRid), isFalse);
    await t.pumpWidget(wrap(ivy.svc, ContactInfoScreen(rid: jon.svc.myRid)));
    await settleUntil(
        t, () => find.textContaining('device list').evaluate().isNotEmpty,
        what: 'the device-list sentence');
    expect(find.textContaining('cannot be forged'), findsNothing,
        reason: "the ML-DSA covers the list's membership, not the ratchet keys "
            'of its devices, until ADR 0017 stage 2b');
    expect(find.textContaining('does not yet cover the key'), findsOneWidget,
        reason: 'and the sentence says what it does not cover');
    await leave(t);
  }, timeout: const Timeout(Duration(minutes: 3)));

  testWidgets('9b. a v2-only device list says its keys are covered',
      (t) async {
    await t.binding.setSurfaceSize(const Size(800, 3000));
    addTearDown(() => t.binding.setSurfaceSize(null));
    late Person kai, lou;
    await t.runAsync(() async {
      // Lou's build signs device lists v2-only (ADR 0017 stage 2).
      (kai, lou) = await pair('Kai', 'Lou', signDevlistV2Only: true);
      await linkLaptop(lou);
      await waitUntil(
          () => kai.svc.deviceListCoversKeys(lou.svc.myRid),
          what: "Lou's v2-only list is post-quantum verified at Kai");
    });
    expect(kai.svc.deviceAssuranceWith(lou.svc.myRid), DeviceAssurance.hybrid);
    await t.pumpWidget(wrap(kai.svc, ContactInfoScreen(rid: lou.svc.myRid)));
    await settleUntil(
        t, () => find.textContaining('device list').evaluate().isNotEmpty,
        what: 'the device-list sentence');
    expect(
        find.textContaining(
            'including the key each of their devices receives messages on'),
        findsOneWidget);
    await leave(t);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('the new strings are in both locales', () async {
    final en = lookupAppLocalizations(const Locale('en'));
    final es = lookupAppLocalizations(const Locale('es'));
    for (final (a, b) in [
      (en.ciMsgPqTitle, es.ciMsgPqTitle),
      (en.ciMsgNotYetTitle, es.ciMsgNotYetTitle),
      (en.ciMsgNotYetBody('x'), es.ciMsgNotYetBody('x')),
      (en.grpMsgPqBody, es.grpMsgPqBody),
      (en.ciDevListHybrid, es.ciDevListHybrid),
      (en.ciDevListHybridKeys, es.ciDevListHybridKeys),
      (en.addRefusedCommitStripped('A'), es.addRefusedCommitStripped('A')),
      (en.addRefusedUnsignedCommit('A'), es.addRefusedUnsignedCommit('A')),
      (en.contactUpgradedUnsigned('A'), es.contactUpgradedUnsigned('A')),
    ]) {
      expect(b, isNot(a), reason: 'translated, not copied: $a');
    }
    expect(en.ciDevListHybrid, isNot(contains('cannot be forged')));
    expect(en.addSignatureNote, isNot(contains('a tampered code is rejected')));
    expect(en.ciMsgChanTheirOther(2, 'Ana'), "2 of Ana's other devices");
    expect(es.ciMsgChanMine(1), '1 de tus otros dispositivos');
  });
}
