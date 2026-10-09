@Tags(['integration'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

// 17.2 — the connect ceremony over the REAL relay, asynchronously.
//
// 17.1 proved the ceremony's cryptography with the two sides in the same
// isolate, handing maps to each other. That is not the situation it exists
// for. Device pairing can assume both ends are awake at once because they are
// in the same pair of hands; this is the part that is different — **an invite
// sent at lunchtime may be opened at midnight**, and the two people are never
// online together at all. So every message is posted to a mailbox and left
// there, each side's state is written to storage after every step, and the
// ceremony advances whenever either side next has a network.
//
// The mailboxes are two throwaway relay identities HKDF'd from the invite
// secret, one per role. Nothing in `server/` changes: a routing id is
// SHA-256(ed25519 pub), so a keypair derived from a shared secret is a mailbox
// both sides can hold, and it queues like any other.
//
// Criteria, each asserted below:
//  1. the acceptor completes against a rendezvous the inviter posted to and
//     then disconnected from — store-and-forward through the mailbox, with
//     the two sides never once connected at the same moment;
//  2. both sides resume after a restart: the state is durable, and the
//     ceremony finishes without either person re-opening anything (and
//     without the resumed side redoing a step it had already done);
//  3. an invite past its lifetime is refused BY THE CLIENT even though the
//     mailbox still holds the envelope — the relay was never told the
//     lifetime and does not enforce it;
//  4. a second attempt on a spent invite is refused: one-time, and the
//     finished ceremony leaves nothing in relay RAM to replay;
//  5. the relay sees only two ephemeral mailboxes — neither party's routing
//     id, account key, or contact code appears anywhere in the exchange;
//  6. (ADR 0020) an invite whose message 3 carries the group bit runs the
//     same four frames through the relay: the acceptor that knows the bit
//     reads it and says so back, one from before the bit completes the
//     same ceremony without it, both runs survive storage with the bit
//     intact, and the message 3 the relay carried is the same length with
//     the bit set and clear;
//  7. (ADR 0024) a relay in the middle — the tap rewriting every frame it
//     carries, with identities of its own toward each side, and everything
//     the relay holds except the invite — cannot complete an invite made
//     now: the acceptor stops at message 3 without revealing itself, and
//     the relay opens nothing it carried;
//  8. the same relay DOES complete an invite of version 1 — one made by a
//     client from before ADR 0024, which a new client still opens: both
//     legs finish, each side holds the relay's identity under the name it
//     expected, and only the digits differ. That is the residual R25 states
//     for such an invite, pinned here so it cannot change unnoticed;
//  9. a side that refuses the identity the other revealed ends the
//     ceremony there: an acceptor that refuses the inviter never sends
//     message 4, and an inviter that refuses the acceptor holds no session.
//
// Criteria 5, 6 and 7 are asserted against what the relay actually saw, not
// against what the client meant to send: every frame passes through a
// recording WebSocket tap standing between the clients and the relay.
//
// One more, unnumbered test covers the transport's half of 17.1's criterion
// 2: what a refusal does to an invite once the frames are coming out of a
// mailbox anyone holding the code can write to.
void main() {
  late Process relay;
  late HttpServer tap;
  late String url;

  // Every frame that crossed the tap, decoded and raw. Cleared per test.
  final seen = <Map<String, Object?>>[];
  final raw = <String>[];

  // When set, the tap is the relay in the middle (criterion 7).
  RelayInTheMiddle? mitm;

  setUpAll(() async {
    final serverDir =
        '${Directory.current.parent.path}${Platform.pathSeparator}server';
    // Ask the OS for a free port rather than derive one from the clock:
    // `dart test` runs files concurrently, so two files computing a port from
    // the same millisecond collided and one relay lost the bind (the app
    // tests already bind port 0 for exactly this reason).
    final portProbe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final port = portProbe.port;
    await portProbe.close();
    relay = await Process.start('node', ['server.js'],
        workingDirectory: serverDir,
        environment: {'PORT': '$port', 'LOG_LEVEL': 'silent'});
    relay.stderr
        .transform(utf8.decoder)
        .listen((s) => print('[relay-err] ${s.trimRight()}'));

    var up = false;
    for (var i = 0; i < 50 && !up; i++) {
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

    // The tap: a WebSocket that pipes both directions to the relay verbatim
    // and writes down everything it carries.
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
      // As a front passes the Host header through (nginx.ha.conf, Cloudflare,
      // Render), so does the tap: the client signs its authentication over
      // the address it dialled, and the relay verifies it against the Host it
      // is given. A tap that presented its own upstream address would be the
      // machine-in-the-middle that binding exists to refuse — and was, when
      // this test first ran against it.
      final upstream = await WebSocket.connect('ws://127.0.0.1:$port',
          headers: {'host': req.headers.value('host') ?? ''});
      void note(dynamic d) {
        if (d is! String) return;
        raw.add(d);
        try {
          final j = jsonDecode(d);
          if (j is Map) seen.add(j.cast<String, Object?>());
        } catch (_) {}
      }

      // A ceremony frame on its way in is handed to the relay in the
      // middle, when there is one, and what it returns is what the relay
      // stores. Each connection's frames keep their order: a rewrite is
      // awaited before the next frame goes, and the close after both.
      var inOrder = Future<void>.value();
      down.listen((d) {
        inOrder = inOrder.then((_) async {
          note(d);
          final m = mitm;
          Map<String, Object?>? f;
          try {
            final j = jsonDecode(d as String);
            if (j is Map) f = j.cast<String, Object?>();
          } catch (_) {}
          final payload = f?['payload'];
          if (m != null &&
              f != null &&
              f['t'] == 'send' &&
              '${f['id']}'.startsWith('z-connect-c') &&
              payload is String) {
            upstream
                .add(jsonEncode({...f, 'payload': await m.rewrite(payload)}));
          } else {
            upstream.add(d);
          }
        });
      },
          onDone: () => inOrder = inOrder.then((_) => upstream.close()),
          onError: (_) => inOrder = inOrder.then((_) => upstream.close()));
      upstream.listen((d) {
        note(d);
        down.add(d);
      }, onDone: () => down.close(), onError: (_) => down.close());
    });
    url = 'ws://127.0.0.1:${tap.port}';
  });

  tearDownAll(() async {
    await tap.close(force: true);
    relay.kill();
  });

  setUp(() {
    seen.clear();
    raw.clear();
    mitm = null;
  });

  const p = Duration(milliseconds: 500);

  /// A v3 contact code for a fresh identity — what the app puts in a QR —
  /// alongside the device identity whose routing id the relay must never see.
  Future<(ConnectIdentity, ZIdentity)> person(String name) async {
    final edSeed = randomBytes(32);
    final id =
        await ZIdentity.fromSeeds(edSeed: edSeed, xSeed: randomBytes(32));
    final pq =
        await HybridKeyPair.fromSeeds(edSeed: edSeed, mlSeed: randomBytes(32));
    final code =
        await ContactBundleV3.forIdentity(id, pq.publicKey, displayName: name);
    return (
      await ConnectIdentity.fromCode(code.encode(), displayName: name),
      id
    );
  }

  /// Through storage and back — the app closing and reopening.
  Future<ConnectRun> reopen(ConnectRun r) async => ConnectRun.fromJson(
      jsonDecode(jsonEncode(r.toJson())) as Map<String, Object?>);

  /// How many envelopes with this id the relay was asked to carry.
  int sends(String id) =>
      seen.where((f) => f['t'] == 'send' && f['id'] == id).length;

  /// Everything left in a mailbox, read without acknowledging it.
  Future<List<RelayInbound>> peek(ConnectCode code, String role) async {
    final c = await RelayClient.connect(url, await mailboxIdentity(code, role));
    final got = <RelayInbound>[];
    final sub = c.messages.listen(got.add);
    await Future<void>.delayed(const Duration(milliseconds: 700));
    await sub.cancel();
    await c.close();
    return got;
  }

  test('1. the acceptor completes against a rendezvous the inviter left behind',
      () async {
    final (alice, _) = await person('Alice');
    final (bob, _) = await person('Bob');

    // Alice makes an invite over lunch, posts it, and closes the app.
    final inv = await ConnectRun.invite(me: alice);
    final link = inv.code.link();
    expect(await inv.step(relayUrl: url, poll: p), ConnectProgress.waiting);

    // Midnight. Bob opens the link. Alice is not online, and never will be
    // at the same moment as Bob in this test: each step below is a whole
    // connect-act-disconnect, one side at a time.
    final code = ConnectCode.fromLink(link);
    expect(code, isNotNull, reason: 'the link round-trips to the code');
    final acc = ConnectRun.accept(me: bob, code: code!);

    expect(await acc.step(relayUrl: url, poll: p), ConnectProgress.waiting);
    expect(await inv.step(relayUrl: url, poll: p), ConnectProgress.waiting);
    expect(await acc.step(relayUrl: url, poll: p), ConnectProgress.confirm);
    expect(await inv.step(relayUrl: url, poll: p), ConnectProgress.confirm);

    // Both screens show the same eight digits, over the same channel.
    expect(inv.session!.sas, matches(RegExp(r'^\d{4} \d{4}$')));
    expect(acc.session!.sas, inv.session!.sas);
    expect(b64(acc.session!.channelKey), b64(inv.session!.channelKey));

    // One ceremony added both people, and each ends holding something its
    // existing scan path accepts.
    expect(inv.session!.peer.displayName, 'Bob');
    expect(acc.session!.peer.displayName, 'Alice');
    expect(
        b64((await ContactBundleV3.decode(inv.session!.peer.contactCode))
            .accountEdPub),
        b64(bob.accountEdPub));
    expect(
        b64((await ContactBundleV3.decode(acc.session!.peer.contactCode))
            .accountEdPub),
        b64(alice.accountEdPub));
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('2. both sides resume after a restart and the ceremony still finishes',
      () async {
    final (alice, _) = await person('Alice');
    final (bob, _) = await person('Bob');

    // Written to storage before anything is posted, and re-read after every
    // step: nothing below ever holds a run in memory across two steps.
    var inv = await reopen(await ConnectRun.invite(me: alice));
    final code = inv.code;

    expect(await inv.step(relayUrl: url, poll: p), ConnectProgress.waiting);
    inv = await reopen(inv);

    var acc = await reopen(ConnectRun.accept(me: bob, code: code));
    expect(await acc.step(relayUrl: url, poll: p), ConnectProgress.waiting);
    acc = await reopen(acc);

    expect(await inv.step(relayUrl: url, poll: p), ConnectProgress.waiting);
    inv = await reopen(inv);

    expect(await acc.step(relayUrl: url, poll: p), ConnectProgress.confirm);
    acc = await reopen(acc);

    expect(await inv.step(relayUrl: url, poll: p), ConnectProgress.confirm);
    inv = await reopen(inv);

    expect(inv.session, isNotNull);
    expect(acc.session!.sas, inv.session!.sas);
    expect(b64(acc.session!.channelKey), b64(inv.session!.channelKey));
    expect(inv.session!.peer.displayName, 'Bob');
    expect(acc.session!.peer.displayName, 'Alice');
    expect(b64(inv.code.secret), b64(code.secret),
        reason: 'the reopened run is the same invite, not a new one');

    // Durable means the resumed side knows where it got to. A run that had
    // forgotten it was already open would re-post its commitment; the relay
    // was asked to carry each of the four exactly once.
    for (final id in const [
      'z-connect-c1',
      'z-connect-c2',
      'z-connect-c3',
      'z-connect-c4'
    ]) {
      expect(sends(id), 1, reason: '$id posted once, by a run read from JSON');
    }
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('3. an invite past its lifetime is refused while the mailbox still '
      'holds the envelope', () async {
    final (alice, _) = await person('Alice');
    final (bob, _) = await person('Bob');

    final t0 = DateTime.now().millisecondsSinceEpoch;
    final inv = await ConnectRun.invite(me: alice, nowMs: t0);
    expect(await inv.step(relayUrl: url, nowMs: t0, poll: p),
        ConnectProgress.waiting);

    // Bob opens the link a day and a half later.
    final late = t0 + connectInviteLifetime.inMilliseconds + 1;
    final acc = ConnectRun.accept(me: bob, code: inv.code, nowMs: t0);
    expect(await acc.step(relayUrl: url, nowMs: late, poll: p),
        ConnectProgress.expired);
    expect(acc.session, isNull);
    expect(sends('z-connect-c2'), 0,
        reason: 'a refused invite posts nothing: the step never connects');

    // The relay was never told the lifetime, and enforces nothing: the
    // envelope Bob refused to act on is still sitting in his mailbox.
    final held = await peek(inv.code, 'r');
    expect(held.map((e) => e.id), contains('z-connect-c1'),
        reason: 'the refusal is the client keeping a rule, not the store');

    // And the inviter refuses too, once its own clock is past the lifetime.
    expect(await inv.step(relayUrl: url, nowMs: late, poll: p),
        ConnectProgress.expired);

    // One millisecond earlier it would still have worked, which is what
    // makes the boundary the lifetime rather than an accident.
    expect(
        await inv.step(
            relayUrl: url,
            nowMs: t0 + connectInviteLifetime.inMilliseconds,
            poll: p),
        ConnectProgress.waiting);
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('4. a second attempt on a spent invite is refused', () async {
    final (alice, _) = await person('Alice');
    final (bob, _) = await person('Bob');

    final inv = await ConnectRun.invite(me: alice);
    final acc = ConnectRun.accept(me: bob, code: inv.code);
    expect(await inv.step(relayUrl: url, poll: p), ConnectProgress.waiting);
    expect(await acc.step(relayUrl: url, poll: p), ConnectProgress.waiting);
    expect(await inv.step(relayUrl: url, poll: p), ConnectProgress.waiting);
    expect(await acc.step(relayUrl: url, poll: p), ConnectProgress.confirm);
    expect(await inv.step(relayUrl: url, poll: p), ConnectProgress.confirm);

    // Before the two humans have compared the digits the run is complete but
    // not yet spent; confirming (or abandoning) spends it.
    expect(await inv.step(relayUrl: url, poll: p), ConnectProgress.done);
    inv.confirmed();
    acc.confirmed();
    expect(inv.finished, isTrue);
    expect(await inv.step(relayUrl: url, poll: p), ConnectProgress.spent);

    // Somebody else who got hold of the same link gets nowhere: the inviter
    // will not answer a second ceremony on a spent invite.
    final (mallory, _) = await person('Mallory');
    final second = ConnectRun.accept(me: mallory, code: inv.code);
    expect(await second.step(relayUrl: url, poll: p), ConnectProgress.waiting);
    expect(await inv.step(relayUrl: url, poll: p), ConnectProgress.spent);
    expect(await second.step(relayUrl: url, poll: p), ConnectProgress.waiting);
    expect(second.session, isNull);

    // Nor is there a transcript left in relay RAM for it to replay: the
    // finished ceremony acknowledged its mailboxes empty.
    for (final role in const ['i', 'r']) {
      final left = await peek(inv.code, role);
      expect(left.where((e) => e.id.startsWith('z-connect-c')), isEmpty,
          reason: 'mailbox $role was left empty');
    }
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('5. the relay sees two throwaway mailboxes and nothing else', () async {
    // Two-word names on purpose: a space cannot occur inside base64, so the
    // sweep below cannot pass by luck and cannot fail by coincidence either.
    final (alice, aliceDev) = await person('Alice Quartermain');
    final (bob, bobDev) = await person('Bob Wickersham');

    final inv = await ConnectRun.invite(me: alice);
    final acc = ConnectRun.accept(me: bob, code: inv.code);
    expect(await inv.step(relayUrl: url, poll: p), ConnectProgress.waiting);
    expect(await acc.step(relayUrl: url, poll: p), ConnectProgress.waiting);
    expect(await inv.step(relayUrl: url, poll: p), ConnectProgress.waiting);
    expect(await acc.step(relayUrl: url, poll: p), ConnectProgress.confirm);
    expect(await inv.step(relayUrl: url, poll: p), ConnectProgress.confirm);
    expect(inv.session!.sas, acc.session!.sas);

    final mailboxes = {
      for (final role in const ['i', 'r'])
        await (await mailboxIdentity(inv.code, role)).routingId()
    };
    expect(mailboxes.length, 2);

    // Every routing id the relay handled, in any direction, in any frame.
    final handled = <String>{};
    for (final f in seen) {
      switch (f['t']) {
        case 'ready':
          handled.add(f['id'] as String);
        case 'send':
        case 'delivered':
          final to = f['to'];
          if (to is String) handled.add(to);
        case 'msg':
          final from = f['from'];
          if (from is String && from.isNotEmpty) handled.add(from);
      }
    }
    expect(handled, mailboxes,
        reason: 'the exchange names the two mailboxes and nobody else');

    // Every key the relay was asked to authenticate belongs to a mailbox.
    final authed = {
      for (final f in seen.where((f) => f['t'] == 'auth')) f['pub'] as String
    };
    final mailboxKeys = {
      for (final role in const ['i', 'r'])
        b64((await mailboxIdentity(inv.code, role)).edPub)
    };
    expect(authed, mailboxKeys);

    // And nothing about either real identity crossed the wire in any form:
    // the reveals travel sealed under the channel the ephemerals derive.
    final wire = raw.join('\n');
    expect(wire, isNotEmpty);
    final forbidden = <String, String>{
      "Alice's routing id": await aliceDev.routingId(),
      "Bob's routing id": await bobDev.routingId(),
      "Alice's account key": b64(alice.accountEdPub),
      "Bob's account key": b64(bob.accountEdPub),
      "Alice's account key (url)": b64url(alice.accountEdPub),
      "Bob's account key (url)": b64url(bob.accountEdPub),
      "Alice's contact code": alice.contactCode,
      "Bob's contact code": bob.contactCode,
      "Alice's display name": 'Alice Quartermain',
      "Bob's display name": 'Bob Wickersham',
    };
    forbidden.forEach((what, needle) {
      expect(wire.contains(needle), isFalse, reason: '$what reached the relay');
    });

    // Belt and braces: a mailbox is not a real routing id.
    expect(mailboxes, isNot(contains(await aliceDev.routingId())));
    expect(mailboxes, isNot(contains(await bobDev.routingId())));
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('6. the group bit rides the same four frames, read or ignored',
      () async {
    final (alice, _) = await person('Alice');
    final (bob, _) = await person('Bob');

    /// One whole ceremony through the tap, each side through storage after
    /// every step. Returns both runs and message 3 as the relay carried it.
    Future<(ConnectRun, ConnectRun, String)> through(
        bool? group, bool aware) async {
      seen.clear();
      var inv = await reopen(await ConnectRun.invite(me: alice, group: group));
      var acc = await reopen(
          ConnectRun.accept(me: bob, code: inv.code, groupAware: aware));
      expect(await inv.step(relayUrl: url, poll: p), ConnectProgress.waiting);
      inv = await reopen(inv);
      expect(await acc.step(relayUrl: url, poll: p), ConnectProgress.waiting);
      acc = await reopen(acc);
      expect(await inv.step(relayUrl: url, poll: p), ConnectProgress.waiting);
      inv = await reopen(inv);
      expect(await acc.step(relayUrl: url, poll: p), ConnectProgress.confirm);
      acc = await reopen(acc);
      expect(await inv.step(relayUrl: url, poll: p), ConnectProgress.confirm);
      inv = await reopen(inv);
      expect(acc.session!.sas, inv.session!.sas);
      final x3 = seen
          .where((f) => f['t'] == 'send' && f['id'] == 'z-connect-c3')
          .single['payload'] as String;
      for (final id in const [
        'z-connect-c1',
        'z-connect-c2',
        'z-connect-c3',
        'z-connect-c4'
      ]) {
        expect(sends(id), 1, reason: 'the same four frames, $id once');
      }
      return (inv, acc, x3);
    }

    // Both sides know the bit, and it came through storage on both.
    final (inv, acc, x3Set) = await through(true, true);
    expect(acc.session!.group, isTrue,
        reason: 'the acceptor read that a group is attached');
    expect(inv.session!.group, isTrue,
        reason: 'and the inviter read it back');
    expect((jsonDecode(x3Set) as Map).keys.toSet(), {'k', 'ephx', 'blob'},
        reason: 'nothing outside the seal');

    // An acceptor from before the bit: the same ceremony, completed, and
    // neither side's session claims anything about a group.
    final (invOld, accOld, _) = await through(true, false);
    expect(accOld.session!.group, isNull);
    expect(invOld.session!.group, isNull,
        reason: 'no repetition came back: that client knows of no group');

    // The same inviter's plain invite: message 3 is the same length at the
    // relay, so the relay cannot tell the two kinds of invite apart by size.
    final (_, accPlain, x3Clear) = await through(false, true);
    expect(accPlain.session!.group, isFalse);
    expect(x3Clear.length, x3Set.length,
        reason: 'message 3 as the relay received it: one length, bit or no');
    print('message 3 at the relay: bit set ${x3Set.length} bytes, '
        'bit clear ${x3Clear.length} bytes');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('7. a relay in the middle cannot complete an invite made now',
      () async {
    final (alice, _) = await person('Alice');
    final (bob, _) = await person('Bob');
    final (m1, _) = await person('Bob');
    final (m2, _) = await person('Alice');
    final middle = RelayInTheMiddle(
        asInviter: (code: m2.contactCode, name: 'Alice'),
        asAcceptor: (code: m1.contactCode, name: 'Bob'));
    mitm = middle;

    final inv = await ConnectRun.invite(me: alice);
    final acc = ConnectRun.accept(me: bob, code: inv.code);
    final progress = <ConnectProgress>[];
    for (var i = 0; i < 3; i++) {
      progress.add(await inv.step(relayUrl: url, poll: p));
      progress.add(await acc.step(relayUrl: url, poll: p));
    }

    expect(middle.replaced, containsAll(['x1', 'x2', 'x3']),
        reason: 'the relay rewrote what it carried');
    expect(acc.session, isNull, reason: 'the acceptor never had a peer');
    expect(acc.abortReason, isNotNull,
        reason: 'it stopped at the opening it could not open');
    expect(acc.finished, isTrue, reason: 'and the invite is spent');
    expect(inv.session, isNull, reason: 'nor did the inviter');
    expect(sends('z-connect-c4'), 0,
        reason: 'the acceptor revealed itself to nobody');
    expect(middle.readFromInviter, isNull,
        reason: "the relay could not open the inviter's reveal");
    expect(middle.readFromAcceptor, isNull);
    print('relay in the middle, an invite made now: $progress');
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('8. the same relay completes an invite of version 1', () async {
    final (alice, _) = await person('Alice');
    final (bob, _) = await person('Bob');
    final (m1, _) = await person('Bob');
    final (m2, _) = await person('Alice');
    final middle = RelayInTheMiddle(
        asInviter: (code: m2.contactCode, name: 'Alice'),
        asAcceptor: (code: m1.contactCode, name: 'Bob'));
    mitm = middle;

    // An inviter from before ADR 0024 makes version 1; this client opens it.
    final inv = await ConnectRun.invite(
        me: alice, code: ConnectCode.generate(version: 1));
    final acc = ConnectRun.accept(
        me: bob, code: ConnectCode.parse(inv.code.text), groupAware: true);
    expect(acc.code.version, 1);
    for (var i = 0; i < 3 && (inv.session == null || acc.session == null); i++) {
      await inv.step(relayUrl: url, poll: p);
      await acc.step(relayUrl: url, poll: p);
    }

    expect(middle.replaced, ['x1', 'x2', 'x3', 'x4']);
    expect(inv.session, isNotNull, reason: 'the inviter reached the digits');
    expect(acc.session, isNotNull, reason: 'and so did the acceptor');
    expect(inv.session!.peer.displayName, 'Bob');
    expect(acc.session!.peer.displayName, 'Alice');
    expect(b64(inv.session!.peer.accountEdPub), b64(m1.accountEdPub),
        reason: "the inviter's \"Bob\" is the relay");
    expect(b64(acc.session!.peer.accountEdPub), b64(m2.accountEdPub),
        reason: "the acceptor's \"Alice\" is the relay");
    expect(middle.readFromInviter?['code'], alice.contactCode,
        reason: "the relay read the inviter's reveal");
    expect(middle.readFromAcceptor?['code'], bob.contactCode,
        reason: "and the acceptor's");
    expect(acc.session!.sas, isNot(inv.session!.sas),
        reason: 'what a comparison of the digits would have caught');
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('9. a side that refuses whom the other revealed ends it there',
      () async {
    final (alice, _) = await person('Alice');
    final (bob, _) = await person('Bob');
    Future<bool> isAlice(ConnectIdentity p) async =>
        b64(p.accountEdPub) == b64(alice.accountEdPub);
    Future<bool> isBob(ConnectIdentity p) async =>
        b64(p.accountEdPub) == b64(bob.accountEdPub);

    // Bob refuses Alice the moment her reveal opens: no message 4.
    final inv = await ConnectRun.invite(me: alice);
    final acc = ConnectRun.accept(me: bob, code: inv.code);
    expect(await inv.step(relayUrl: url, poll: p), ConnectProgress.waiting);
    expect(await acc.step(relayUrl: url, poll: p, refusePeer: isAlice),
        ConnectProgress.waiting);
    expect(await inv.step(relayUrl: url, poll: p), ConnectProgress.waiting);
    expect(await acc.step(relayUrl: url, poll: p, refusePeer: isAlice),
        ConnectProgress.aborted);
    expect(acc.session, isNull);
    expect(acc.finished, isTrue, reason: 'the invite is spent');
    expect(sends('z-connect-c4'), 0, reason: 'Bob never revealed himself');
    expect(await inv.step(relayUrl: url, poll: p), ConnectProgress.waiting,
        reason: 'Alice is left waiting, and is told nothing');

    // Alice refuses Bob the moment his reveal opens: no session.
    final inv2 = await ConnectRun.invite(me: alice);
    final acc2 = ConnectRun.accept(me: bob, code: inv2.code);
    expect(await inv2.step(relayUrl: url, poll: p, refusePeer: isBob),
        ConnectProgress.waiting);
    expect(await acc2.step(relayUrl: url, poll: p), ConnectProgress.waiting);
    expect(await inv2.step(relayUrl: url, poll: p, refusePeer: isBob),
        ConnectProgress.waiting);
    expect(await acc2.step(relayUrl: url, poll: p), ConnectProgress.confirm);
    expect(await inv2.step(relayUrl: url, poll: p, refusePeer: isBob),
        ConnectProgress.aborted);
    expect(inv2.session, isNull);
    expect(inv2.finished, isTrue);
    // And the refusal outlives the app: read back, the run is spent.
    expect(await (await reopen(inv2)).step(relayUrl: url, poll: p),
        ConnectProgress.spent);
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('a refused frame spends the invite, and the refusal is durable',
      () async {
    final (alice, _) = await person('Alice');
    var inv = await ConnectRun.invite(me: alice);
    expect(await inv.step(relayUrl: url, poll: p), ConnectProgress.waiting);

    // Anyone holding the code holds BOTH mailbox keys — that is what makes an
    // invite a bearer token, and why it is one-time and short-lived. So post
    // rubbish into the inviter's mailbox from the acceptor's.
    final impostor =
        await RelayClient.connect(url, await mailboxIdentity(inv.code, 'r'));
    await impostor.send(
      to: await (await mailboxIdentity(inv.code, 'i')).routingId(),
      id: 'z-connect-c2',
      payload: jsonEncode(
          {'k': 'x2', 'ephx': b64(Uint8List(8)), 'c': b64(Uint8List(32))}),
    );
    await impostor.close();

    expect(await inv.step(relayUrl: url, poll: p), ConnectProgress.aborted);
    expect(inv.abortReason, isNotNull);

    // And the refusal outlives the app: a reopened run does not walk back
    // into the same rubbish, or into whoever posted it.
    inv = await reopen(inv);
    expect(inv.abortReason, isNotNull);
    expect(inv.finished, isTrue);
    expect(await inv.step(relayUrl: url, poll: p), ConnectProgress.spent);
  }, timeout: const Timeout(Duration(minutes: 2)));
}

/// The relay in the middle of a ceremony: it rewrites the four frames as
/// they pass, running one leg with each side under identities of its own.
///
/// It holds everything the relay holds — the frames, the mailboxes they go
/// to, the order they come in — and nothing it does not: the invite secret
/// travels in a link the relay never carries. So it derives every key the
/// way §20.3 does for an invite of version 1, which is the only way that
/// needs no secret: the channel key from the two ephemerals alone, the
/// commitments from what they commit to alone. Written from the primitives,
/// sharing no code with the library, so what it can do is what the
/// specification lets it do.
class RelayInTheMiddle {
  RelayInTheMiddle({required this.asInviter, required this.asAcceptor});

  /// What it reveals to the acceptor, and to the inviter.
  final ({String code, String name}) asInviter, asAcceptor;

  final _x = X25519();
  final _aead = Chacha20.poly1305Aead();
  SimpleKeyPair? _towardAcceptor, _towardInviter;
  Uint8List? _acceptorEph;
  int _inviterGroup = 0;
  Uint8List? _keyWithInviter, _keyWithAcceptor;

  /// What it read of each side's reveal, if it could open it.
  Map<String, Object?>? readFromInviter, readFromAcceptor;

  /// The frames it replaced, by kind.
  final List<String> replaced = [];

  Future<Uint8List> _pub(SimpleKeyPair k) async =>
      Uint8List.fromList((await k.extractPublicKey()).bytes);

  Future<Uint8List> _commit(Uint8List eph, String code, String name) async {
    final c = utf8.encode(code);
    return Uint8List.fromList((await Sha256().hash([
      ...utf8.encode('z-connect-commit-v1:'),
      ...eph,
      (c.length >> 8) & 0xff,
      c.length & 0xff,
      ...c,
      ...utf8.encode(name),
    ]))
        .bytes);
  }

  Future<Uint8List> _channel(SimpleKeyPair mine, Uint8List theirs) async {
    final dh = await _x.sharedSecretKey(
        keyPair: mine,
        remotePublicKey: SimplePublicKey(theirs, type: KeyPairType.x25519));
    final k = await Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
        secretKey: SecretKey(await dh.extractBytes()),
        nonce: Uint8List(32),
        info: utf8.encode('z-connect-channel-v1'));
    return Uint8List.fromList(await k.extractBytes());
  }

  Future<Map<String, Object?>?> _open(Uint8List key, String blob) async {
    try {
      final clear = await _aead.decrypt(
          SecretBox.fromConcatenation(base64Decode(blob),
              nonceLength: 12, macLength: 16),
          secretKey: SecretKey(key));
      return (jsonDecode(utf8.decode(clear)) as Map).cast<String, Object?>();
    } catch (_) {
      return null;
    }
  }

  Future<String> _seal(Uint8List key, Map<String, Object?> m) async {
    final box = await _aead.encrypt(utf8.encode(jsonEncode(m)),
        secretKey: SecretKey(key), nonce: _aead.newNonce());
    return base64Encode(box.concatenation());
  }

  /// The payload the relay stores in place of [payload], a frame of the
  /// ceremony on its way in. Every rewrite of one kind is the same, so a
  /// side re-posting its frame meets the same substitute.
  Future<String> rewrite(String payload) async {
    final j = (jsonDecode(payload) as Map).cast<String, Object?>();
    switch (j['k']) {
      case 'x1':
        _towardAcceptor ??= await _x.newKeyPair();
        replaced.add('x1');
        return jsonEncode({
          'k': 'x1',
          'c': base64Encode(await _commit(await _pub(_towardAcceptor!),
              asInviter.code, asInviter.name)),
        });
      case 'x2':
        _acceptorEph = base64Decode(j['ephx'] as String);
        _towardInviter ??= await _x.newKeyPair();
        replaced.add('x2');
        final eph = await _pub(_towardInviter!);
        return jsonEncode({
          'k': 'x2',
          'ephx': base64Encode(eph),
          'c': base64Encode(
              await _commit(eph, asAcceptor.code, asAcceptor.name)),
        });
      case 'x3':
        _keyWithInviter = await _channel(
            _towardInviter!, base64Decode(j['ephx'] as String));
        readFromInviter = await _open(_keyWithInviter!, j['blob'] as String);
        final grp = readFromInviter?['grp'];
        _inviterGroup = grp is int ? grp : 0;
        _keyWithAcceptor = await _channel(_towardAcceptor!, _acceptorEph!);
        replaced.add('x3');
        return jsonEncode({
          'k': 'x3',
          'ephx': base64Encode(await _pub(_towardAcceptor!)),
          'blob': await _seal(_keyWithAcceptor!, {
            'code': asInviter.code,
            'name': asInviter.name,
            'grp': _inviterGroup,
          }),
        });
      case 'x4':
        readFromAcceptor =
            await _open(_keyWithAcceptor!, j['blob'] as String);
        replaced.add('x4');
        return jsonEncode({
          'k': 'x4',
          'blob': await _seal(_keyWithInviter!, {
            'code': asAcceptor.code,
            'name': asAcceptor.name,
            'grp': _inviterGroup,
          }),
        });
    }
    return payload;
  }
}
