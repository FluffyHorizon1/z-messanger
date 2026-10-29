// 44.6 — CONNECT version 3, read here and run here as the acceptor
// (ADR 0033 §4 and decision 2; PROTOCOL §20.9).
//
// This build OPENS an invite of version 3 and runs its ceremony as the
// acceptor; it still MAKES version 2 only. Version 3 is minted a release
// after the release that reads it, so an acceptor on the release before is
// never handed an invite its app cannot open (Finnian's decision of
// 2026-10-17). The inviter in these tests is the seam that stands in for
// that next release (`ConnectInvites.debugMintV3`), which nothing in lib/
// sets (9).
//
// REAL ChatService instances run REAL ceremonies through the REAL Node relay
// behind a recording tap, which can also rewrite a frame on its way in — as
// whoever carries the frames can, and (4) as a party holding the inviter's
// own secrets could. An older build handed a version-3 invite refuses it as
// every build has: `protocol/test/connect_v3_test.dart` 7 holds every
// rendering of 200 of them to the library's version-2 reader — which is the
// whole of 4.7.2's, and which this change leaves as it was — and to verbatim
// copies of Release 4.3.2's and of every build's before ADR 0024.
//
// Criteria, each a test below:
//   1. an invite of version 3, made by the seam and pasted as its code, is
//      run by this build's acceptor through a real relay on version 3's own
//      mailboxes, the inviter's KEM key in message 1 and the acceptor's
//      ciphertext in message 2: both screens show the same digits; both
//      confirm, each then holding the other as a contact verified on the
//      post-quantum number; and messages flow both ways;
//   2. what each side holds is §20.9's: the other account's ML-DSA key,
//      established from the reveal, and the other device's sealing key,
//      with no `pqdc` — and neither side sends a `pqid` or a `pqseal`, though
//      their sessions are post-quantum both ways; the side that compared the
//      digits holds the device link post-quantum and its contact screen says
//      so beside the post-quantum number, and the side that went on without
//      comparing holds the same keys, unverified, and says nothing of a link;
//   3. the four frames at the relay are §20.9's sizes: message 1 and message
//      2 about 1.6 KB, messages 3 and 4 about 6.3 KB, each posted once;
//   4. a reveal whose ML-DSA key was stripped — message 3 rewritten on its
//      way by a party holding the inviter's own secrets, its code still
//      committing to a key — is refused: the acceptor stops at message 3,
//      posts no message 4 and so reveals itself to nobody, and nobody is
//      added on either side;
//   5. a ciphertext tampered in message 2 leaves the acceptor unable to open
//      message 3: it stops there, posts no message 4, and nobody is added;
//   6. a mismatched comparison adds nothing and keeps nothing: the
//      acceptor's "they do not match" spends the invite with no contact, no
//      sealing key and no mark of the ceremony left, and the inviter's the
//      same;
//   7. a version-3 invite never runs as version 2 (ADR 0024): a version-2
//      message 1 posted into its acceptor's mailbox by someone holding the
//      invite stops that acceptor before it posts anything; and the same
//      ten bytes opened as a version-2 invite run on version 2's mailboxes
//      alone and never meet the version-3 inviter;
//   8. the deep link and paste paths take a version-3 invite as they take a
//      version-2 one: E4's filter passes a genuine `/i` link carrying one,
//      which is held until its person says yes; the link and the code —
//      without dashes, in lower case, with spaces — are read by the CONNECT
//      tab's reader; one on any other page is not; and the same invite
//      twice is one;
//   9. production mints nothing new: `connectInviteVersion` is 2, invites
//      made without the seam — plain, and from the CONNECT tab's button —
//      are version 2, and in lib/ the seam is never set and the version-3
//      inviter is reached from behind it alone;
//  10. a version-3 invite pending on the acceptor survives the app being
//      killed — in the middle of the round that posts its message 2, once
//      the relay has taken it; after posting its message 2; opened and not
//      yet carried forward; and again at its digits — and completes, message
//      2 drawn once, the contact then holding the keys its reveal carried;
//      and a stored version-3 record this build cannot read costs that
//      invite alone, written back as it was;
//  11. a version-3 invite whose link drops as this build's acceptor posts
//      its message 2, or as the inviter posts its message 3, goes on to the
//      digits: that message is posted again on a later round, as it was —
//      until 2026-10-29 the run had moved past drawing it and nothing
//      posted it again, and both sides waited until the invite expired.
@Tags(['integration'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:cryptography/cryptography.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/connect_invites.dart';
import 'package:zapp/core/deep_links.dart';
import 'package:zapp/core/models.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/l10n/app_localizations.dart';
import 'package:zapp/ui/connect_tab.dart';
import 'package:zapp/ui/contact_info_screen.dart';
import 'package:zapp/ui/theme.dart';

typedef Person = ({
  ChatService svc,
  Vault vault,
  ConnectInvites invites,
  ZIdentity id
});

final _x = X25519();
final _aead = Chacha20.poly1305Aead();

Future<Uint8List> _hkdf(
    List<int> ikm, List<int> salt, String info, int length) async {
  final k = await Hkdf(hmac: Hmac.sha256(), outputLength: length).deriveKey(
      secretKey: SecretKey(ikm), nonce: salt, info: utf8.encode(info));
  return Uint8List.fromList(await k.extractBytes());
}

/// The channel key of [mine]'s ceremony as its inviter derived it (§20.9):
/// `HKDF(dh || K, inviteKey3, "z-connect-channel-v3")`, from what the
/// inviter's own record holds once message 3 is made — its ephemeral's seed,
/// the acceptor's ephemeral and the K it decapsulated. Whoever holds these
/// holds what the inviter holds, and nobody else does.
Future<Uint8List> _inviterChannel(PendingInvite mine) async {
  final i = (mine.run.toJson()['i'] as Map).cast<String, Object?>();
  final dh = await _x.sharedSecretKey(
      keyPair: await _x.newKeyPairFromSeed(unb64(i['eph'] as String)),
      remotePublicKey: SimplePublicKey(unb64(i['peerEph'] as String),
          type: KeyPairType.x25519));
  return _hkdf([...await dh.extractBytes(), ...unb64(i['k'] as String)],
      (await mine.run.code.inviteKey())!, 'z-connect-channel-v3', 32);
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  // The widget binding answers every HTTP request with 400, which would fail
  // the relay's health probe and every socket below.
  HttpOverrides.global = null;

  late Process relay;
  late HttpServer tap;
  late String url;
  final temps = <Directory>[];
  final live = <Person>[];
  final homes = <ChatService, Directory>{};

  // Every frame the tap carried, decoded. Cleared per test.
  final seen = <Map<String, Object?>>[];

  // When set, a ceremony frame on its way in to the relay is replaced by
  // what this returns.
  Future<String> Function(String payload)? rewrite;

  // When set, the post of the ceremony envelope it names is where the link
  // drops, once: the connection carrying it is cut before the relay has it.
  String? dropAt;

  // When set, the relay's answer to the post of the ceremony envelope it
  // names is held back, once, the connection left open, and `taken`
  // completed with the means to cut it: the relay has the message, and the
  // app that posted it has not heard.
  ({String id, Completer<void Function()> taken})? holdAt;

  setUpAll(() async {
    HttpOverrides.global = null;
    final serverDir =
        '${Directory.current.parent.path}${Platform.pathSeparator}server';
    final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final port = probe.port;
    await probe.close();
    relay = await Process.start('node', ['server.js'],
        workingDirectory: serverDir,
        environment: {'PORT': '$port', 'LOG_LEVEL': 'silent'});
    var up = false;
    for (var i = 0; i < 60 && !up; i++) {
      try {
        final res = await (await HttpClient()
                .getUrl(Uri.parse('http://127.0.0.1:$port/health')))
            .close();
        await res.drain<void>();
        up = res.statusCode == 200;
      } catch (_) {
        await Future<void>.delayed(const Duration(milliseconds: 100));
      }
    }
    if (!up) fail('relay did not start');

    // The tap: both directions written down, and a ceremony frame on its
    // way in handed to [rewrite] when one is set. Each connection's frames
    // keep their order: a rewrite is awaited before the next frame goes.
    tap = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    tap.listen((req) async {
      WebSocket down;
      try {
        down = await WebSocketTransformer.upgrade(req);
      } catch (_) {
        req.response.statusCode = HttpStatus.badRequest;
        await req.response.close();
        return;
      }
      final upstream = await WebSocket.connect('ws://127.0.0.1:$port',
          headers: {'host': req.headers.value('host') ?? ''});
      Map<String, Object?>? note(dynamic d) {
        if (d is! String) return null;
        try {
          final j = jsonDecode(d);
          if (j is Map) {
            final m = j.cast<String, Object?>();
            seen.add(m);
            return m;
          }
        } catch (_) {}
        return null;
      }

      var inOrder = Future<void>.value();
      var dead = false; // the link dropped: nothing more goes either way
      down.listen((d) {
        inOrder = inOrder.then((_) async {
          if (dead) return;
          final f = note(d);
          if (f != null && f['t'] == 'send' && f['id'] == dropAt) {
            dropAt = null;
            dead = true;
            await down.close();
            await upstream.close();
            return;
          }
          final edit = rewrite;
          final payload = f?['payload'];
          if (edit != null &&
              f != null &&
              f['t'] == 'send' &&
              '${f['id']}'.startsWith('z-connect-c') &&
              payload is String) {
            upstream.add(jsonEncode({...f, 'payload': await edit(payload)}));
          } else {
            upstream.add(d);
          }
        });
      },
          onDone: () => inOrder = inOrder.then((_) => upstream.close()),
          onError: (_) => inOrder = inOrder.then((_) => upstream.close()));
      upstream.listen((d) {
        if (dead) return;
        final f = note(d);
        final hold = holdAt;
        if (hold != null &&
            f != null &&
            f['t'] == 'sent' &&
            f['id'] == hold.id) {
          holdAt = null;
          hold.taken.complete(() {
            dead = true;
            unawaited(down.close());
            unawaited(upstream.close());
          });
          return;
        }
        down.add(d);
      }, onDone: () => down.close(), onError: (_) => down.close());
    });
    url = 'ws://127.0.0.1:${tap.port}';
  });

  tearDownAll(() async {
    for (final p in live) {
      p.invites.pause();
      await p.svc.transport
          .stop()
          .timeout(const Duration(seconds: 10), onTimeout: () {});
    }
    for (final p in live) {
      p.svc.dispose();
    }
    await tap.close(force: true);
    relay.kill();
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  setUp(() {
    seen.clear();
    rewrite = null;
    dropAt = null;
    holdAt = null;
  });

  Future<Person> openApp(Directory dir, ZIdentity id, String name,
      {String? relayUrl}) async {
    final vault = await Vault.open(rootOverride: dir);
    if (await vault.kvGet('identity') == null) {
      await vault.kvPut('identity', jsonEncode(id.toJson()));
    }
    final svc = await ChatService.init(
        vault: vault,
        identity: id,
        displayName: name,
        transport: Transport(identity: id, serverUrl: relayUrl ?? url));
    final p = (svc: svc, vault: vault, invites: ConnectInvites(svc), id: id);
    homes[svc] = dir;
    live.add(p);
    return p;
  }

  /// A person with an app, through the tap to the relay — or, with
  /// [relayUrl], to whatever that names.
  Future<Person> person(String name, {String? relayUrl}) async {
    final dir = await Directory.systemTemp.createTemp('z_cpq_');
    temps.add(dir);
    return openApp(dir, await ZIdentity.generate(), name, relayUrl: relayUrl);
  }

  /// The inviter: the next release, as the seam stands in for it.
  Future<Person> nextRelease(String name) async {
    final p = await person(name);
    p.invites.debugMintV3 = true;
    return p;
  }

  /// [p]'s app killed and started again: the same vault and identity,
  /// nothing in memory.
  Future<Person> restart(Person p) async {
    final dir = homes[p.svc]!;
    final name = p.svc.displayName;
    p.invites.pause();
    await p.svc.transport.stop();
    p.svc.dispose();
    live.remove(p);
    await p.vault.db.close();
    return openApp(dir, p.id, name);
  }

  Future<void> waitUntil(bool Function() cond,
      {Duration timeout = const Duration(seconds: 60),
      required String what}) async {
    final deadline = DateTime.now().add(timeout);
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
  }

  Future<void> connected(List<Person> all) => waitUntil(
      () => all.every((p) => p.svc.transport.isConnected),
      what: 'everyone connected to the relay');

  /// Both sides' rounds until each has digits or has stopped — every pump a
  /// whole connect-act-disconnect, awaited.
  Future<void> dance(
      Person a, PendingInvite ai, Person b, PendingInvite bi) async {
    bool over(PendingInvite i) =>
        i.sas != null ||
        i.progress == ConnectProgress.aborted ||
        i.progress == ConnectProgress.spent;
    for (var i = 0; i < 8 && !(over(ai) && over(bi)); i++) {
      await a.invites.pump();
      await b.invites.pump();
    }
  }

  /// Both people answer the digits — [aCompared]: [a] confirms them, or goes
  /// on without comparing — the one that does not open the session first,
  /// so the opening `hello` of the one that does finds itself held.
  Future<void> answer(Person a, PendingInvite ai, Person b, PendingInvite bi,
      {bool aCompared = true, bool bCompared = true}) async {
    Future<void> go(Person p, PendingInvite i, bool compared) =>
        compared ? p.invites.confirm(i) : p.invites.defer(i);
    if (a.svc.myRid.compareTo(b.svc.myRid) < 0) {
      await go(b, bi, bCompared);
      await go(a, ai, aCompared);
    } else {
      await go(a, ai, aCompared);
      await go(b, bi, bCompared);
    }
  }

  /// [from] says [body] to [to], and it arrives.
  Future<void> say(Person from, Person to, String body) async {
    await from.svc.sendText(to.svc.myRid, body);
    await waitUntil(
        () => (to.svc.messagesByChat[from.svc.myRid] ?? const <ChatMessage>[])
            .any((m) => !m.outgoing && m.body == body),
        what: '"$body" arrived');
  }

  /// [a] and [b] talk until every channel between them is post-quantum both
  /// ways — the moment a `pqseal` owed to either could first ride — and
  /// then until nothing is left to send.
  Future<void> talkUntilPq(Person a, Person b) async {
    for (var round = 0; round < 8; round++) {
      if (a.svc.messagePqWith(b.svc.myRid).all &&
          b.svc.messagePqWith(a.svc.myRid).all) {
        break;
      }
      await say(a, b, 'ping $round');
      await say(b, a, 'pong $round');
    }
    await waitUntil(
        () =>
            a.svc.messagePqWith(b.svc.myRid).all &&
            b.svc.messagePqWith(a.svc.myRid).all,
        what: 'every channel between them post-quantum both ways');
    // One more each way on the post-quantum sessions: whatever is owed then
    // has had a message to ride.
    await say(a, b, 'after');
    await say(b, a, 'after, back');
    final deadline = DateTime.now().add(const Duration(seconds: 60));
    while (true) {
      final queued = [
        for (final p in [a, b])
          (await p.vault.db.query('outbox', limit: 1)).length
      ];
      if (queued.every((n) => n == 0) &&
          !a.svc.pqSendPending &&
          !b.svc.pqSendPending) {
        return;
      }
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('the two never went quiet');
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
  }

  /// Every ceremony frame the clients asked the relay to carry.
  List<Map<String, Object?>> ceremonyFrames() => [
        for (final f in seen)
          if (f['t'] == 'send' && '${f['id']}'.startsWith('z-connect-c')) f
      ];

  int sends(String id) =>
      seen.where((f) => f['t'] == 'send' && f['id'] == id).length;

  /// The routing ids of both of [code]'s mailboxes.
  Future<Set<String>> mailboxes(ConnectCode code) async => {
        for (final role in const ['i', 'r'])
          await (await mailboxIdentity(code, role)).routingId()
      };

  /// What [p] keeps of [rid] in its vault that a ceremony of version 3 would
  /// have put there.
  Future<Map<String, String?>> ceremonyRows(Person p, String rid) async => {
        'cvia_': await p.vault.kvGet('cvia_$rid'),
        'cseal_': await p.vault.kvGet('cseal_$rid'),
      };

  Widget wrap(ChatService svc, Widget child) =>
      ChangeNotifierProvider<ChatService>.value(
        value: svc,
        child: MaterialApp(
          theme: ZTheme.light(),
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: child,
        ),
      );

  /// Rebuild until [cond] holds against the widget tree, letting real work
  /// run in between; fail saying [what] if it never does.
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
    await t.pump(const Duration(milliseconds: 350));
  }

  /// Unmount once the screen's own work is done: the safety number it works
  /// out as it opens is on it, the spinner gone — the one thing it starts
  /// that runs on against the vault — so nothing of it is left running.
  Future<void> leave(WidgetTester t) async {
    await settleUntil(
        t, () => find.byType(CircularProgressIndicator).evaluate().isEmpty,
        what: 'the safety number worked out, on the screen');
    await t.pumpWidget(const SizedBox());
  }

  test(
      '1. a version-3 invite made by the seam, pasted as its code, runs '
      'through a real relay; both confirm, and messages flow', () async {
    final alice = await nextRelease('Alice');
    final bob = await person('Bob');
    await connected([alice, bob]);

    final mine = await alice.invites.create();
    expect(mine.run.code.version, 3, reason: 'the seam makes version 3');
    expect(mine.code, startsWith('8'));
    expect(mine.link, startsWith('https://www.zmessengers.com/i#8'));
    // Bob pastes the printed code into the CONNECT tab's field.
    final theirs = await bob.invites.open(mine.code);
    expect(theirs.run.code.version, 3);
    expect(theirs.run.code.secret, mine.run.code.secret);
    expect(theirs.held, isFalse, reason: 'a paste and Open is the yes');

    await dance(alice, mine, bob, theirs);
    expect(mine.sas, isNotNull, reason: 'the inviter reached the digits');
    expect(theirs.sas, mine.sas, reason: 'and the acceptor, the same ones');
    expect(theirs.peer?.displayName, 'Alice');
    expect(mine.peer?.displayName, 'Bob');
    expect(theirs.run.session, isA<ConnectSessionV3>());

    // Version 3's own mailboxes, and nothing else; the KEM key in message
    // 1, the ciphertext in message 2.
    final v3 = await mailboxes(mine.run.code);
    final older = {
      ...await mailboxes(ConnectCode(mine.run.code.secret, version: 2)),
      ...await mailboxes(ConnectCode(mine.run.code.secret)),
    };
    final frames = ceremonyFrames();
    expect(frames.map((f) => f['id']).toSet(),
        {'z-connect-c1', 'z-connect-c2', 'z-connect-c3', 'z-connect-c4'});
    for (final f in frames) {
      expect(v3, contains(f['to']), reason: '${f['id']} to a v3 mailbox');
      expect(older, isNot(contains(f['to'])));
    }
    Map<String, Object?> frame(String id) => (jsonDecode(frames
            .firstWhere((f) => f['id'] == id)['payload'] as String) as Map)
        .cast<String, Object?>();
    expect(unb64(frame('z-connect-c1')['ek'] as String), hasLength(1184));
    expect(unb64(frame('z-connect-c2')['ct'] as String), hasLength(1088));

    await answer(alice, mine, bob, theirs);
    expect(alice.invites.invites, isEmpty);
    expect(bob.invites.invites, isEmpty);
    for (final (me, them) in [(alice, bob), (bob, alice)]) {
      final c = me.svc.contacts[them.svc.myRid]!;
      expect(c.verified, isTrue, reason: '${me.svc.displayName} confirmed');
      expect(c.requested, isFalse, reason: 'not a pending request (ADR 0012)');
      expect(me.svc.verificationWith(c.rid), VerificationState.verified);
      final number = await me.svc.safetyNumberWith(c.rid);
      expect(c.verifiedSn, number,
          reason: 'the tick stands on the number this pair has');
      final classical = await safetyNumber(
          (await me.svc.accountIdentity()).accountEdPub, c.accountEd);
      expect(number, isNot(classical),
          reason: 'and that number is the post-quantum one, at once');
    }

    await connected([alice, bob]);
    await say(alice, bob, 'hello from a post-quantum invite');
    await say(bob, alice, 'and back');
  }, timeout: const Timeout(Duration(minutes: 4)));

  testWidgets(
      "2. each side holds §20.9's keys, sends no pqid and no pqseal, and the "
      'screen says what the comparison bought', (t) async {
    await t.binding.setSurfaceSize(const Size(800, 3000));
    addTearDown(() => t.binding.setSurfaceSize(null));
    late Person alice, bob;
    late Uint8List aliceMl, bobMl;
    await t.runAsync(() async {
      alice = await nextRelease('Alice');
      bob = await person('Bob');
      await connected([alice, bob]);
      aliceMl = (await alice.svc.pqAccountPublic())!;
      bobMl = (await bob.svc.pqAccountPublic())!;
      final mine = await alice.invites.create();
      final theirs = await bob.invites.open(mine.link);
      await dance(alice, mine, bob, theirs);
      expect(theirs.sas, mine.sas);
      expect(theirs.sas, isNotNull);
      // Bob, this build's acceptor, compares the digits and they match;
      // Alice goes on without comparing.
      await answer(alice, mine, bob, theirs, aCompared: false);
      await connected([alice, bob]);
      await talkUntilPq(alice, bob);
    });
    final aRid = alice.svc.myRid, bRid = bob.svc.myRid;
    final bobsAlice = bob.svc.contacts[aRid]!;
    final alicesBob = alice.svc.contacts[bRid]!;

    // The ML-DSA key: established from the reveal, on both sides, and the
    // one the other account holds — no pqid carried it, before the messages
    // or after.
    expect(bobsAlice.pqPub, aliceMl);
    expect(alicesBob.pqPub, bobMl);
    for (final c in [bobsAlice, alicesBob]) {
      expect(c.assurance, IdentityAssurance.hybrid);
      expect(c.pqDisplay, PqDisplay.postQuantum);
      expect(c.pqCandidate, isNull);
      expect(c.connectV3, isTrue);
      expect(c.pqFromConnect, isTrue);
    }
    expect(bob.svc.debugPqSends, 0, reason: 'the acceptor sent no pqid');
    expect(alice.svc.debugPqSends, 0, reason: 'nor did the inviter (R17)');

    // The sealing key: each holds the other device's, from the reveal, and
    // has said so — neither ever announced its own, though their sessions
    // are post-quantum both ways, where an owed pqseal would have ridden.
    expect(bob.svc.debugPqSealOf(aRid), alice.svc.sealingKey);
    expect(alice.svc.debugPqSealOf(bRid), bob.svc.sealingKey);
    expect(bob.svc.debugHoldsMySealKey(aRid), isTrue);
    expect(alice.svc.debugHoldsMySealKey(bRid), isTrue);
    expect(bob.svc.debugPqSealSends, 0, reason: 'no pqseal from the acceptor');
    expect(alice.svc.debugPqSealSends, 0, reason: 'nor from the inviter');
    expect(bob.svc.debugPqdcOf(aRid), isNull, reason: 'no pqdc was needed');
    expect(alice.svc.debugPqdcOf(bRid), isNull);
    expect(bob.svc.debugConversation(aRid)!.isPostQuantumBothWays, isTrue);

    // The device link: post-quantum where the digits were compared, and
    // only there.
    expect(bob.svc.deviceLinkedByCeremony(aRid), isTrue);
    expect(alice.svc.deviceLinkedByCeremony(bRid), isFalse);
    expect(bobsAlice.verified, isTrue);
    expect(alicesBob.verified, isFalse);
    expect(alice.svc.verificationWith(bRid), VerificationState.unverified);

    // And what the screens say. Bob's, of Alice: post-quantum, the key from
    // the invite, the device link beside the number, verified.
    final l = lookupAppLocalizations(const Locale('en'));
    await t.pumpWidget(wrap(bob.svc, ContactInfoScreen(rid: aRid)));
    await settleUntil(
        t,
        () => find
            .byKey(const ValueKey('ci-device-link-connect'))
            .evaluate()
            .isNotEmpty,
        what: "the device link on Bob's screen");
    expect(find.text(l.ciDeviceLinkConnect), findsOneWidget);
    expect(find.text(l.ciBlurbHybridConnect), findsOneWidget);
    expect(find.text(l.ciBlurbHybrid), findsNothing,
        reason: 'the key did not arrive over the session from a scan');
    expect(find.text(l.ciPillPq), findsOneWidget);
    // The tick, as the switch shows it ("Verified" is also the notice's
    // heading above it).
    expect(
        t
            .widget<SwitchListTile>(
                find.widgetWithText(SwitchListTile, l.ciSwitchVerified))
            .value,
        isTrue);
    await leave(t);

    // Alice's, of Bob: the same keys, unverified, and no link said.
    await t.pumpWidget(wrap(alice.svc, ContactInfoScreen(rid: bRid)));
    await settleUntil(
        t, () => find.text(l.ciBlurbHybridConnect).evaluate().isNotEmpty,
        what: "the blurb on Alice's screen");
    expect(find.byKey(const ValueKey('ci-device-link-connect')), findsNothing,
        reason: 'nothing vouches for the link where nobody compared');
    expect(find.text(l.ciPillPq), findsOneWidget);
    expect(
        t
            .widget<SwitchListTile>(
                find.widgetWithText(SwitchListTile, l.ciSwitchMarkVerified))
            .value,
        isFalse);
    await leave(t);

    // All of it survives a restart.
    await t.runAsync(() async {
      bob = await restart(bob);
      alice = await restart(alice);
    });
    expect(bob.svc.contacts[aRid]!.pqFromConnect, isTrue);
    expect(bob.svc.contacts[aRid]!.connectV3, isTrue);
    expect(bob.svc.deviceLinkedByCeremony(aRid), isTrue);
    expect(bob.svc.debugPqSealOf(aRid), isNotNull);
    expect(alice.svc.contacts[bRid]!.connectV3, isTrue);
    expect(alice.svc.deviceLinkedByCeremony(bRid), isFalse);
    await t.runAsync(() async {
      await alice.svc.transport
          .stop()
          .timeout(const Duration(seconds: 10), onTimeout: () {});
      await bob.svc.transport
          .stop()
          .timeout(const Duration(seconds: 10), onTimeout: () {});
    });
  }, timeout: const Timeout(Duration(minutes: 5)));

  test("3. the four frames are §20.9's sizes at the relay", () async {
    final alice = await nextRelease('Alice');
    final bob = await person('Bob');
    final mine = await alice.invites.create();
    final theirs = await bob.invites.open(mine.link);
    await dance(alice, mine, bob, theirs);
    expect(theirs.sas, mine.sas);
    expect(theirs.sas, isNotNull);

    final sizes = <String, int>{};
    for (final (n, id) in const [
      ('x1', 'z-connect-c1'),
      ('x2', 'z-connect-c2'),
      ('x3', 'z-connect-c3'),
      ('x4', 'z-connect-c4'),
    ]) {
      expect(sends(id), 1, reason: '$id posted once');
      sizes[n] = (ceremonyFrames().singleWhere((f) => f['id'] == id)['payload']
              as String)
          .length;
    }
    // Messages 1 and 2 are fixed width: a commitment and the KEM key, an
    // ephemeral, a commitment and the ciphertext.
    expect(sizes['x1'], 1649);
    expect(sizes['x2'], 1575);
    // Messages 3 and 4 carry a contact code, a name, an ML-DSA key and a
    // sealing key, sealed.
    for (final n in const ['x3', 'x4']) {
      expect(sizes[n], inInclusiveRange(6000, 6700), reason: n);
    }
    // ignore: avoid_print
    print('CONNECT v3 frames at the relay, payload characters: $sizes');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('4. a reveal whose ML-DSA key was stripped stops the acceptor at '
      'message 3, before it reveals itself', () async {
    final alice = await nextRelease('Alice');
    final bob = await person('Bob');
    final mine = await alice.invites.create();
    final theirs = await bob.invites.open(mine.link);

    // Message 3, rewritten on its way by a party holding what the inviter
    // holds: Alice's own reveal, her code still committing to her key, with
    // the key taken out and the reveal sealed again under the same channel.
    var stripped = 0;
    Object? failure;
    rewrite = (payload) async {
      final j = (jsonDecode(payload) as Map).cast<String, Object?>();
      if (j['k'] != 'x3') return payload;
      try {
        final key = await _inviterChannel(mine);
        final clear = await _aead.decrypt(
            SecretBox.fromConcatenation(unb64(j['blob'] as String),
                nonceLength: 12, macLength: 16),
            secretKey: SecretKey(key));
        final reveal =
            (jsonDecode(utf8.decode(clear)) as Map).cast<String, Object?>();
        if (reveal.remove(connectPqKeyMember) == null) {
          failure = 'message 3 carried no ML-DSA key to strip';
          return payload;
        }
        final box = await _aead.encrypt(utf8.encode(jsonEncode(reveal)),
            secretKey: SecretKey(key), nonce: _aead.newNonce());
        stripped++;
        return jsonEncode({...j, 'blob': b64(box.concatenation())});
      } catch (e) {
        failure = e;
        return payload;
      }
    };

    await dance(alice, mine, bob, theirs);
    expect(failure, isNull);
    expect(stripped, greaterThan(0), reason: 'message 3 was rewritten');
    expect(theirs.progress, ConnectProgress.aborted,
        reason: 'the acceptor refused the reveal');
    expect(theirs.run.abortReason, contains('carries no ML-DSA key'));
    expect(theirs.sas, isNull);
    expect(sends('z-connect-c4'), 0,
        reason: 'the acceptor revealed itself to nobody');
    expect(mine.sas, isNull, reason: 'and the inviter never had a reveal');
    expect(alice.svc.contacts, isEmpty);
    expect(bob.svc.contacts, isEmpty);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('5. a tampered ciphertext leaves the acceptor unable to open message '
      '3: it stops there, and nobody is added', () async {
    final alice = await nextRelease('Alice');
    final bob = await person('Bob');
    final mine = await alice.invites.create();
    final theirs = await bob.invites.open(mine.link);

    var tampered = 0;
    rewrite = (payload) async {
      final j = (jsonDecode(payload) as Map).cast<String, Object?>();
      if (j['k'] != 'x2') return payload;
      final ct = unb64(j['ct'] as String);
      ct[ct.length ~/ 2] ^= 0x01;
      tampered++;
      return jsonEncode({...j, 'ct': b64(ct)});
    };

    await dance(alice, mine, bob, theirs);
    expect(tampered, greaterThan(0), reason: 'message 2 was rewritten');
    expect(sends('z-connect-c3'), greaterThan(0),
        reason: 'the inviter decapsulated what it was given and answered');
    expect(theirs.progress, ConnectProgress.aborted);
    expect(theirs.run.abortReason, contains('did not open'));
    expect(theirs.sas, isNull);
    expect(sends('z-connect-c4'), 0,
        reason: 'the acceptor revealed itself to nobody');
    expect(mine.sas, isNull);
    expect(alice.svc.contacts, isEmpty);
    expect(bob.svc.contacts, isEmpty);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('6. a mismatched comparison adds nothing and keeps nothing', () async {
    final alice = await nextRelease('Alice');
    final bob = await person('Bob');
    final mine = await alice.invites.create();
    final theirs = await bob.invites.open(mine.link);
    await dance(alice, mine, bob, theirs);
    expect(theirs.sas, mine.sas);
    expect(theirs.sas, isNotNull);
    expect(theirs.run.ceremonyKeys, isNotNull,
        reason: "the acceptor had Alice's keys in hand");

    await bob.invites.mismatch(theirs);
    await alice.invites.mismatch(mine);
    for (final (me, them) in [(bob, alice), (alice, bob)]) {
      final rid = them.svc.myRid;
      expect(me.svc.contacts, isEmpty, reason: me.svc.displayName);
      expect(me.invites.invites, isEmpty, reason: 'the invite is spent');
      expect(await ceremonyRows(me, rid), {'cvia_': null, 'cseal_': null},
          reason: 'none of the ceremony is kept');
      expect(me.svc.debugPqSealOf(rid), isNull);
      expect(me.svc.deviceLinkedByCeremony(rid), isFalse);
    }
    expect(theirs.run.finished, isTrue);
    expect(mine.run.finished, isTrue);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('7. a version-3 invite never runs as version 2', () async {
    final alice = await nextRelease('Alice');
    final bob = await person('Bob');
    final carol = await person('Carol');

    // Someone holding the invite posts a version-2 message 1 for the same
    // ten bytes into the version-3 acceptor's mailbox, as version 3's
    // inviter mailbox — it holds both mailbox keys.
    final first = await alice.invites.create();
    final opened = await bob.invites.open(first.link);
    final code = first.run.code;
    final v2 = await ConnectInviter.create(
        me: await ConnectIdentity.fromCode(await carol.svc.myContactCode(),
            displayName: 'Carol'),
        code: ConnectCode(code.secret, version: 2));
    final poster = await RelayClient.connect(url, await mailboxIdentity(code, 'i'));
    await poster.send(
        to: await (await mailboxIdentity(code, 'r')).routingId(),
        id: 'z-connect-c1',
        payload: jsonEncode({'k': 'x1', ...await v2.commit()}));
    await poster.close();
    await bob.invites.pump();
    expect(opened.progress, ConnectProgress.aborted,
        reason: 'a version-2 message 1 is not one version 3 takes');
    expect(opened.run.abortReason, contains('"ek"'));
    expect(sends('z-connect-c2'), 0, reason: 'the acceptor posted nothing');

    // The same ten bytes as a version-2 invite: they run on version 2's
    // mailboxes and never meet the version-3 inviter. (A new invite, the
    // first given up, so every frame from here on is the second's.)
    await alice.invites.discard(first);
    seen.clear();
    final second = await alice.invites.create();
    final asV2 = ConnectCode(second.run.code.secret, version: 2);
    final carols = await carol.invites.open(asV2.text);
    expect(carols.run.code.version, 2);
    for (var n = 0; n < 3; n++) {
      await alice.invites.pump();
      await carol.invites.pump();
    }
    expect(second.sas, isNull);
    expect(carols.sas, isNull);
    expect(second.progress, ConnectProgress.waiting);
    expect(carols.progress, ConnectProgress.waiting);
    final v3boxes = await mailboxes(second.run.code);
    final v2boxes = await mailboxes(asV2);
    expect(v3boxes.intersection(v2boxes), isEmpty);
    final carolsBox = await mailboxIdentity(asV2, 'r');
    expect(
        seen.any((f) => f['t'] == 'auth' && f['pub'] == b64(carolsBox.edPub)),
        isTrue,
        reason: "the version-2 run read version 2's mailbox");
    for (final f in ceremonyFrames()) {
      expect(v3boxes, contains(f['to']),
          reason: 'every frame posted was the version-3 inviter\'s, to its own');
    }
    expect(sends('z-connect-c2'), 0, reason: 'nobody met anybody');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('8. the deep link and paste paths take a version-3 invite as they '
      'take a version-2 one', () async {
    final bob = await person('Bob');
    final links = DeepLinks(bob.invites,
        channel: const MethodChannel('z/deeplink/connect-pq'));

    // Tapped: E4's filter passes the genuine invite page, and the invite is
    // held until its person says yes — no connection, no frame.
    final tapped = ConnectCode.generate(version: 3);
    expect(DeepLinks.filterClaims(tapped.link()), isTrue);
    expect(DeepLinks.filterClaims(tapped.link(host: 'zmessengers.com')),
        isTrue);
    final held = await links.handle(tapped.link());
    expect(held, isNotNull, reason: 'the link was taken');
    expect(held!.run.code.version, 3);
    expect(held.run.code.secret, tapped.secret);
    expect(held.held, isTrue);
    expect(identical(links.takeUnshown(), held), isTrue);
    await bob.invites.pump();
    final box = await mailboxIdentity(tapped, 'r');
    expect(seen.where((f) => f['t'] == 'auth' && f['pub'] == b64(box.edPub)),
        isEmpty,
        reason: 'nothing of a held invite reaches the relay');
    expect(await links.handle(tapped.link()), isNull,
        reason: 'the same invite twice is one');

    // Pasted: each rendering, read by the CONNECT tab's reader.
    final printed = ConnectCode.generate(version: 3);
    for (final r in [
      printed.link(),
      printed.link(host: 'relay.example.org'),
      printed.link().replaceFirst('/i#', '/i?from=chat#'),
      printed.link().replaceFirst('/i#', '/i/#'),
      printed.link().replaceFirst('https://', ''),
      printed.text,
      printed.text.replaceAll('-', ''),
      printed.text.toLowerCase(),
      printed.text.replaceAll('-', ' '),
      ' ${printed.text} ',
    ]) {
      final read = ConnectInvites.parseInvite(r);
      expect(read?.version, 3, reason: r);
      expect(read?.secret, printed.secret, reason: r);
    }
    final pasted = await bob.invites.open(printed.text.toLowerCase());
    expect(pasted.run.code.version, 3);
    await expectLater(
        bob.invites.open(printed.link()),
        throwsA(isA<FormatException>().having(
            (e) => e.message, 'message', 'that invite is already open')));

    // A version-3 fragment on any page but the invite page is not one.
    final fragment = printed.link().split('#').last;
    for (final r in [
      'https://www.zmessengers.com/index.html#$fragment',
      'https://www.zmessengers.com/c#$fragment',
      'https://www.zmessengers.com/x/i#$fragment',
      'https://www.zmessengers.com/info#$fragment',
    ]) {
      expect(ConnectInvites.parseInvite(r), isNull, reason: r);
      expect(await links.handle(r), isNull, reason: r);
    }
    // And a version-2 invite is taken exactly as it was.
    final two = ConnectCode.generate();
    expect(ConnectInvites.parseInvite(two.link())?.version, 2);
    expect(ConnectInvites.parseInvite(two.text)?.version, 2);
    expect((await links.handle(two.link()))?.run.code.version, 2);
    expect(bob.invites.invites, hasLength(3));
    await links.dispose();
  }, timeout: const Timeout(Duration(minutes: 2)));

  testWidgets('9. production mints nothing new', (t) async {
    expect(connectInviteVersion, 2);

    // Without the seam: version 2, made as every release since ADR 0024.
    // No relay for this one: making an invite is local work.
    late Person ann;
    await t.runAsync(() async {
      ann = await person('Ann', relayUrl: 'ws://127.0.0.1:1');
      final plain = await ann.invites.create();
      expect(plain.run.code.version, 2);
      expect(plain.code, startsWith('9'));
      await ann.invites.discard(plain);
    });

    // And from the CONNECT tab's own button.
    await t.pumpWidget(MultiProvider(
      providers: [
        ChangeNotifierProvider<ChatService>.value(value: ann.svc),
        ChangeNotifierProvider<ConnectInvites>.value(value: ann.invites),
      ],
      child: MaterialApp(
        localizationsDelegates: AppLocalizations.localizationsDelegates,
        supportedLocales: AppLocalizations.supportedLocales,
        theme: ZTheme.dark(),
        home: const Scaffold(body: ConnectTab()),
      ),
    ));
    await t.pumpAndSettle();
    await t.tap(find.text('Create an invite'));
    await settleUntil(
        t, () => find.byType(SelectableText).evaluate().isNotEmpty,
        what: 'an invite from the button, on the card');
    expect(ann.invites.invites.single.run.code.version, 2,
        reason: "the tab's button makes version 2");
    expect(
        find.byWidgetPredicate((w) =>
            w is SelectableText && (w.data?.startsWith('9') ?? false)),
        findsOneWidget,
        reason: 'and the code on the card says so');
    // The round the tab runs behind the button meets a refused socket, and
    // the card says so once that round is over: nothing of it is left in
    // flight when the tab goes.
    await settleUntil(
        t,
        () => find
            .textContaining('Could not reach the relay')
            .evaluate()
            .isNotEmpty,
        what: "the button's round over, its failure on the card");
    await t.pumpWidget(const SizedBox());

    // In lib/, the seam is set nowhere, and the version-3 inviter is reached
    // from behind it alone: one call to the library's version-3 run as an
    // inviter, in the one function the seam guards, called once, there.
    final code = <String, String>{};
    for (final f in Directory('lib')
        .listSync(recursive: true)
        .whereType<File>()
        .where((f) => f.path.endsWith('.dart'))) {
      // Comments say what the code may not: only the code is held to it.
      code[f.path] = [
        for (final line in f.readAsLinesSync())
          if (!line.trimLeft().startsWith('//')) line
      ].join('\n');
    }
    expect(code.length, greaterThanOrEqualTo(50), reason: 'lib/ was read');
    List<String> where(Pattern p) => [
          for (final e in code.entries)
            for (final _ in p.allMatches(e.value)) e.key
        ];
    final invites = code.keys.singleWhere(
        (p) => p.endsWith('${Platform.pathSeparator}connect_invites.dart'));
    expect(where(RegExp(r'debugMintV3\s*=(?!=)')), [invites],
        reason: 'the declaration, false, and no assignment anywhere');
    expect(code[invites], contains('bool debugMintV3 = false;'));
    expect(where('ConnectRunV3.invite('), [invites]);
    expect(where('ConnectInviterV3'), isEmpty);
    expect(where(RegExp(r'version:\s*3')), isEmpty,
        reason: 'no version-3 code minted, or built, anywhere');
    expect(where('_mintV3ForTests('), [invites, invites],
        reason: 'its definition and one call');
    expect(
        RegExp(r'debugMintV3\s*\?\s*await\s+_mintV3ForTests\(')
            .allMatches(code[invites]!),
        hasLength(1),
        reason: 'the one call is the seam\'s branch');
    final body = RegExp(r'_mintV3ForTests\([^)]*\)\s*async\s*\{(.*?)\n  \}',
            dotAll: true)
        .firstMatch(code[invites]!);
    expect(body?.group(1), contains('ConnectRunV3.invite('),
        reason: 'and the version-3 run is made in that function alone');
  });

  test('10. a pending version-3 invite survives the app being killed, and a '
      'stored one this build cannot read costs that invite alone', () async {
    final alice = await nextRelease('Alice');
    var bob = await person('Bob');

    // Killed in the middle of the round that posts its message 2, once the
    // relay has taken it: the tap holds the relay's answer back while the
    // app is killed, so nothing the round would have done after the post
    // happens. It comes back to the record written before the post, holding
    // that message, and posts it again rather than drawing another — until
    // 2026-10-29 it came back to the record from before the round, drew a
    // second encapsulation the relay dropped for the first it held, and
    // could not open message 3.
    final mid = await alice.invites.create();
    await alice.invites.pump();
    await bob.invites.open(mid.link);
    final taken = Completer<void Function()>();
    holdAt = (id: 'z-connect-c2', taken: taken);
    final dying = bob.invites.pump();
    final cut = await taken.future.timeout(const Duration(seconds: 30));
    bob = await restart(bob);
    await bob.invites.load();
    cut();
    await dying.then((_) {}, onError: (Object _) {});
    final after = bob.invites.invites.single;
    await dance(alice, mid, bob, after);
    final drawn = {
      for (final f in seen)
        if (f['t'] == 'send' && f['id'] == 'z-connect-c2') f['payload']
    };
    final why = after.run.abortReason;
    final ended = after.sas != null && after.sas == mid.sas
        ? 'one string'
        : 'acceptor ${after.progress.name}${why == null ? '' : ' ($why)'}, '
            'inviter ${mid.progress.name}';
    expect('$ended; z-connect-c2 messages: ${drawn.length}',
        'one string; z-connect-c2 messages: 1',
        reason: 'killed after the relay took its message 2, it went on with '
            'that message');
    await bob.invites.mismatch(after);
    await alice.invites.mismatch(mid);
    seen.clear();

    // Killed after posting its message 2: the ephemeral its commitment
    // covers and its encapsulation were drawn in that round, and message 1
    // acknowledged away.
    final first = await alice.invites.create();
    await alice.invites.pump();
    await bob.invites.open(first.link);
    await bob.invites.pump();
    expect(sends('z-connect-c2'), 1);
    bob = await restart(bob);
    await bob.invites.load();
    final resumed = bob.invites.invites.single;
    await dance(alice, first, bob, resumed);
    expect(resumed.sas, isNotNull,
        reason: 'it went on from its message 2 after the restart');
    expect(resumed.sas, first.sas);
    expect(sends('z-connect-c2'), 1,
        reason: 'nothing was drawn or posted again');
    await bob.invites.mismatch(resumed);
    await alice.invites.mismatch(first);

    final mine = await alice.invites.create();
    await alice.invites.pump(); // message 1 waits in Bob's mailbox
    final opened = await bob.invites.open(mine.link);

    // Killed with the invite opened and not yet carried forward.
    bob = await restart(bob);
    await bob.invites.load();
    final back = bob.invites.invites.single;
    expect(back.id, opened.id);
    expect(back.run.code.version, 3, reason: 'read back as version 3');
    expect(back.run.code.secret, mine.run.code.secret);
    await dance(alice, mine, bob, back);
    expect(back.sas, isNotNull, reason: 'it completes after the restart');
    expect(back.sas, mine.sas);

    // Killed again at the digits, and answered after it: the reveal's two
    // keys come back with the ceremony, and the add holds them.
    bob = await restart(bob);
    await bob.invites.load();
    final atDigits = bob.invites.invites.single;
    expect(atDigits.sas, mine.sas);
    expect(atDigits.awaitingConfirmation, isTrue);
    expect(atDigits.run.ceremonyKeys?.sealKey, alice.svc.sealingKey);
    await answer(alice, mine, bob, atDigits);
    final held = bob.svc.contacts[alice.svc.myRid]!;
    expect(held.pqPub, await alice.svc.pqAccountPublic());
    expect(held.pqFromConnect, isTrue);
    expect(held.verified, isTrue);
    expect(bob.svc.debugPqSealOf(alice.svc.myRid), alice.svc.sealingKey);
    expect(bob.svc.deviceLinkedByCeremony(alice.svc.myRid), isTrue);

    // Three records: a version-2 invite, a version-3 one whose peer revealed
    // a code under the Ed25519 point of order 2 — which a build before
    // 2026-10-28 took in, and this one refuses — and a sound version-3 one.
    final carol = await person('Carol');
    final dir = homes[carol.svc]!;
    await carol.invites.create();
    await carol.invites.open(ConnectCode.generate(version: 3).link());
    await carol.invites.open(ConnectCode.generate(version: 3).link());
    Future<List<Map<String, Object?>>> stored(Person p) async => [
          for (final r in jsonDecode((await p.vault.kvGet('connect_invites'))!)
              as List)
            (r as Map).cast<String, Object?>()
        ];
    final three = await stored(carol);
    expect([for (final r in three) (r['run'] as Map)['cv']], [2, 3, 3]);
    final peer = ContactBundle(
            edPub: Uint8List.fromList(
                [0xec, for (var i = 0; i < 30; i++) 0xff, 0x7f]),
            xPub: (await ZIdentity.generate()).xPub,
            bindingSig: Uint8List(64)..[0] = 1,
            displayName: 'Mallory')
        .encode();
    final unread = {
      ...three[1],
      'run': {
        ...(three[1]['run'] as Map).cast<String, Object?>(),
        'session': {
          'key': b64(randomBytes(32)),
          'sas': '1234 5678',
          'peer': peer,
          'pqseal': b64(carol.svc.sealingKey!),
        },
      },
    };
    await carol.vault
        .kvPut('connect_invites', jsonEncode([three[0], unread, three[2]]));
    final carol2 = await restart(carol);
    expect(homes[carol2.svc], dir);
    await carol2.invites.load();
    expect(carol2.invites.invites.map((i) => i.id),
        [three[0]['id'], three[2]['id']],
        reason: 'the two that parse are read, and only they');
    expect(carol2.invites.invites.last.run.code.version, 3);
    final made = await carol2.invites.create();
    final kept = await stored(carol2);
    expect(kept.map((r) => r['id']),
        unorderedEquals([for (final r in three) r['id'], made.id]));
    expect(kept.singleWhere((r) => r['id'] == unread['id']), equals(unread),
        reason: 'the one that does not parse, as it was');
  }, timeout: const Timeout(Duration(minutes: 4)));

  test('11. a version-3 invite whose link drops as message 2 or message 3 is '
      'posted goes on to the digits, that message posted again as it was',
      () async {
    // Where each ended: one string on both screens, or what each card was
    // left at; and how many posts went under the id that dropped — the one
    // the link dropped and the one after it, nothing more once one lands —
    // and how many different messages they carried.
    final ended = <String>[];
    for (final at in const ['z-connect-c2', 'z-connect-c3']) {
      seen.clear();
      final alice = await nextRelease('Alice');
      final bob = await person('Bob');
      final mine = await alice.invites.create();
      await alice.invites.pump(); // message 1 waits for Bob
      final theirs = await bob.invites.open(mine.link);
      if (at == 'z-connect-c2') dropAt = at;
      await bob.invites.pump();
      if (at == 'z-connect-c3') {
        dropAt = at;
        await alice.invites.pump();
      }
      expect(dropAt, isNull, reason: 'the link dropped at $at');
      expect((at == 'z-connect-c2' ? theirs : mine).lastFailure, isNotNull,
          reason: 'the card says the round did not get through');
      await dance(alice, mine, bob, theirs);
      final posts = {
        for (final f in seen)
          if (f['t'] == 'send' && f['id'] == at) f['payload']
      };
      final where = mine.sas != null && mine.sas == theirs.sas
          ? 'one string'
          : 'acceptor ${theirs.progress.name}, inviter ${mine.progress.name}';
      ended.add('$where; $at posts: ${sends(at)}, messages: ${posts.length}');
    }
    expect(ended, [
      'one string; z-connect-c2 posts: 2, messages: 1',
      'one string; z-connect-c3 posts: 2, messages: 1',
    ]);
  }, timeout: const Timeout(Duration(minutes: 3)));
}
