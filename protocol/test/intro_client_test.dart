// The client's half of introduction mailboxes (PROTOCOL §21.6, §21.7; phase
// 38): the `intro` frame, the stamped send and the relay's `pow_required`
// refusal as the Dart relay client speaks them, against the real relay; and
// the `ia` member a contact request carries on the acceptance of a handle
// request. The relay's own half is `server/test/intro_mailbox.test.js`; the
// app's, `app/test/handles_test.dart`.
//
// Criteria, each a test below:
//   1. a contact request without `ia` encodes exactly as it did before the
//      member existed, one with it round-trips with `ia` last, and an `ia`
//      that is not a string reads as none — the request itself still parses
//      and verifies;
//   2. `intro` on a connection authenticated (v2) as the introduction key is
//      answered `intro_ok`; with a difficulty outside 16–28 it fails
//      `bad_intro`, and on a connection that never authenticated
//      `not_authed`;
//   3. a send to the flagged mailbox without a stamp fails with
//      RelayPowRequired naming the difficulty and the relay's day; a stamp
//      for that day is accepted, and the owner receives the envelope as
//      sent; a stamp for another day is refused the same way.
@Tags(['integration'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

void main() {
  late Process relay;
  late int port;
  String url() => 'ws://127.0.0.1:$port';

  setUpAll(() async {
    final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    port = probe.port;
    await probe.close();
    relay = await Process.start('node', ['server.js'],
        workingDirectory:
            '${Directory.current.parent.path}${Platform.pathSeparator}server',
        environment: {'PORT': '$port', 'LOG_LEVEL': 'silent'});
    relay.stdout.drain<void>();
    relay.stderr.drain<void>();
    for (var i = 0; i < 80; i++) {
      try {
        final res = await (await HttpClient()
                .getUrl(Uri.parse('http://127.0.0.1:$port/health')))
            .close();
        await res.drain<void>();
        if (res.statusCode == 200) return;
      } catch (_) {}
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    fail('relay did not start');
  });

  tearDownAll(() async {
    relay.kill();
    await relay.exitCode;
  });

  test('1. ia is an optional last member: absent, the bytes are unchanged',
      () async {
    final alice = await ZIdentity.generate();
    final bob = await ZIdentity.generate();
    final bobRid = await bob.routingId();
    final plain = await ContactRequest.create(
        me: alice, toRid: bobRid, displayName: 'Alice', ts: 1791460800000);
    // What a request was before the member existed, byte for byte.
    final before = base64Encode(utf8.encode(jsonEncode({
      'v': 1,
      't': 'creq',
      'to': bobRid,
      'ts': 1791460800000,
      'bundle': plain.bundle.toJson(),
      'sig': b64(plain.sig),
    })));
    expect(plain.encode(), before);
    expect(ContactRequest.tryParse(before)!.ia, isNull);

    final withIa = ContactRequest(
        bundle: plain.bundle,
        toRid: plain.toRid,
        ts: plain.ts,
        sig: plain.sig,
        ia: 'aWEtZm9yLXRlc3Q');
    final json = jsonDecode(utf8.decode(base64Decode(withIa.encode())))
        as Map<String, Object?>;
    expect(json.keys.last, 'ia');
    final back = ContactRequest.tryParse(withIa.encode())!;
    expect(back.ia, 'aWEtZm9yLXRlc3Q');
    expect(await back.verify(expectedTo: bobRid), isTrue,
        reason: '§8.1\'s signature does not cover ia');

    final odd = Map<String, Object?>.from(json)..['ia'] = 42;
    final parsed =
        ContactRequest.tryParse(base64Encode(utf8.encode(jsonEncode(odd))))!;
    expect(parsed.ia, isNull);
    expect(await parsed.verify(expectedTo: bobRid), isTrue);
  });

  test('2. intro: intro_ok as the introduction key, refused otherwise',
      () async {
    final intro = await handleIntroIdentity(randomBytes(32));
    final owner = await RelayClient.connect(url(), intro);
    try {
      await owner.intro(16);
      await expectLater(
          owner.intro(15),
          throwsA(isA<RelayException>()
              .having((e) => e.message, 'code', 'bad_intro')));
      await expectLater(
          owner.intro(29),
          throwsA(isA<RelayException>()
              .having((e) => e.message, 'code', 'bad_intro')));
      await owner.intro(20); // a new difficulty replaces the old one
    } finally {
      await owner.close();
    }
    final anon = await RelayClient.connectAnonymous(
        url(), await ZIdentity.generate());
    try {
      await expectLater(
          anon.intro(16),
          throwsA(isA<RelayException>()
              .having((e) => e.message, 'code', 'not_authed')));
    } finally {
      await anon.close();
    }
  });

  test('3. a send without the work fails pow_required with the relay\'s day; '
      'the stamp it names is taken', () async {
    final introSeed = randomBytes(32);
    final intro = await handleIntroIdentity(introSeed);
    final introRid = await intro.routingId();
    final owner = await RelayClient.connect(url(), intro);
    final inbox = <RelayInbound>[];
    final sub = owner.messages.listen(inbox.add);
    final sender = await RelayClient.connectAnonymous(
        url(), await ZIdentity.generate());
    try {
      await owner.intro(16);
      final bob = await ZIdentity.generate();
      final creq = await ContactRequest.create(
          me: bob, toRid: introRid, displayName: 'Bob');
      final payload = await SealedEnvelope.seal(
          toXPub: intro.xPub,
          fromRid: await bob.routingId(),
          payload: creq.encode());
      final id = newMessageId();
      RelayPowRequired? refused;
      try {
        await sender.send(to: introRid, id: id, payload: payload);
      } on RelayPowRequired catch (e) {
        refused = e;
      }
      expect(refused, isNotNull, reason: 'a flagged mailbox takes no stamp-less send');
      expect(refused!.bits, 16);
      final today = introPowDay(DateTime.now().millisecondsSinceEpoch);
      expect(refused.day, inInclusiveRange(today - 1, today + 1));
      expect(refused.message, 'pow_required',
          reason: 'the code is the message, as for every refusal');

      // A stamp for a day the relay does not take (three days on): refused
      // in the same words.
      final wrongDay = createIntroPowStamp(
          introRid: introRid,
          day: refused.day + 3,
          envelope: utf8.encode(payload),
          bits: 16);
      await expectLater(
          sender.send(to: introRid, id: id, payload: payload, pow: b64url(wrongDay)),
          throwsA(isA<RelayPowRequired>()));

      // The stamp for the relay's day: taken, and delivered as sent.
      final stamp = createIntroPowStamp(
          introRid: introRid,
          day: refused.day,
          envelope: utf8.encode(payload),
          bits: 16);
      await sender.send(to: introRid, id: id, payload: payload, pow: b64url(stamp));
      await waitFor(() => inbox.isNotEmpty, what: 'the owner receiving it');
      expect(inbox, hasLength(1), reason: 'one envelope, once');
      expect(inbox.single.payload, payload);
      expect(inbox.single.from, '', reason: 'sealed: no sender at the relay');
      final opened = await SealedEnvelope.open(
          myXSeed: intro.xSeed, myXPub: intro.xPub, blob: inbox.single.payload);
      expect(ContactRequest.tryParse(opened!.payload), isNotNull);
    } finally {
      await sub.cancel();
      await owner.close();
      await sender.close();
    }
  });
}

/// Wait on [cond] — an observable, polled — for up to [timeout], or fail
/// naming [what].
Future<void> waitFor(bool Function() cond,
    {required String what, Duration timeout = const Duration(seconds: 10)}) async {
  final until = DateTime.now().add(timeout);
  while (!cond()) {
    if (DateTime.now().isAfter(until)) fail('timed out waiting for $what');
    await Future<void>.delayed(const Duration(milliseconds: 20));
  }
}
