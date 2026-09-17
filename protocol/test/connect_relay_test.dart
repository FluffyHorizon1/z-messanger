@Tags(['integration'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

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
//     id, account key, or contact code appears anywhere in the exchange.
//
// Criterion 5 is asserted against what the relay actually saw, not against
// what the client meant to send: every frame passes through a recording
// WebSocket tap standing between the clients and the relay.
//
// A sixth, unnumbered test covers the transport's half of 17.1's criterion 2:
// what a refusal does to an invite once the frames are coming out of a
// mailbox anyone holding the code can write to.
void main() {
  late Process relay;
  late HttpServer tap;
  late String url;

  // Every frame that crossed the tap, decoded and raw. Cleared per test.
  final seen = <Map<String, Object?>>[];
  final raw = <String>[];

  setUpAll(() async {
    final serverDir =
        '${Directory.current.parent.path}${Platform.pathSeparator}server';
    final port = 43000 + DateTime.now().millisecondsSinceEpoch % 15000;
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

      down.listen((d) {
        note(d);
        upstream.add(d);
      }, onDone: () => upstream.close(), onError: (_) => upstream.close());
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
