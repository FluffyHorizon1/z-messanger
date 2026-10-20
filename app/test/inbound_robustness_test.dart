// Every inbound envelope is acknowledged once its fate is decided (30.2).
//
// The receive path used to leave an envelope UNACKNOWLEDGED whenever
// processing it threw an Error rather than one of the exceptions it caught: a
// validly-encrypted inner message whose members had unexpected types (a
// numeric `body`, a `mids` that is not a list of strings), a non-finite
// number (`ts:1e999`), or a session opener carrying a wrong-length key. Each
// such envelope stayed in the mailbox for the relay's 72 h and was
// redelivered on every connect, so enough of them filled the byte cap and
// valid messages were refused. Two related defects: a transient vault-write
// failure on the self-sync receive path was acknowledged away (the message
// lost from the relay and the device both), and an `internal` refusal stopped
// the outbox until the next send or reconnect. And a 1:1 edit/delete/reaction/
// timer made while a transparency conflict held sends applied locally and was
// then never sent.
//
// Two real ChatService instances through the REAL in-process relay, as the
// nearest test files do. A hostile peer's malformed inner messages are built
// with the protocol library and encrypted on a real session (`debugSealRaw`),
// and a wrong-length opener is a transport payload crafted by hand; both are
// delivered through the relay by a raw anonymous socket, the way anyone who
// holds a routing id can send. Each case is asserted to drain the mailbox
// (the relay reports nothing queued), leave the receiver's state unchanged or
// advanced exactly as designed, and still deliver the next valid message.
//
// Exit criteria, each a test below:
//   1. an inner message with wrong member types (for several kinds) is
//      acknowledged, not left wedging the mailbox, and the chat goes on;
//   2. a non-finite number (`ts`, a kind member) is acknowledged likewise;
//   3. a session opener with a wrong-length ephemeral key is acknowledged and
//      leaves NO session behind, and the next valid message still arrives;
//   4. 300 malformed envelopes do not fill the mailbox: every one drains, and
//      a valid message sent after them arrives;
//   5. a transient vault-write failure on the self-sync receive path leaves
//      the envelope with the relay and the mirrored message arrives on the
//      redelivery, rather than being acknowledged away and lost;
//   6. the outbox retries after an `internal` refusal, on its own timer,
//      while the link stays up — the message is delivered without a reconnect;
//   7. a 1:1 edit made while a transparency conflict holds sends is queued
//      durably and delivered when the hold is answered;
//   8. a reaction or a receipt naming a message the device does not hold
//      yet is kept for it only within bounds (30.3): nothing naming an id
//      longer than 64 characters, which no message of ours has, and a 1:1
//      reaction without the `gid` member it carried, which nothing reads —
//      so a contact cannot make the device hold a frame's worth of their
//      text for an hour — and what is kept still counts when its message
//      lands.
@Tags(['integration'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/models.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  late Process relay;
  late int port;
  final temps = <Directory>[];
  final live = <ChatService>[];
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
        environment: {
          'PORT': '$port',
          'LOG_LEVEL': 'silent',
          'METRICS_TOKEN': 'z-apptest-metrics',
        });
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
      s.dispose();
      await s.transport.stop();
    }
    relay.kill();
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<Directory> dirFor(String name) async =>
      dirs[name] ??
      await Directory.systemTemp.createTemp('z_inbound_').then((d) {
        temps.add(d);
        return dirs[name] = d;
      });

  Future<ChatService> start(String name,
      {Transport Function(ZIdentity)? transportFor}) async {
    final vault = await Vault.open(rootOverride: await dirFor(name));
    final stored = await vault.kvGet('identity');
    final id = stored == null
        ? await ZIdentity.generate()
        : await ZIdentity.fromJson(
            (jsonDecode(stored) as Map).cast<String, Object?>());
    if (stored == null) await vault.kvPut('identity', jsonEncode(id.toJson()));
    final svc = await ChatService.init(
        vault: vault,
        identity: id,
        displayName: name,
        transport: transportFor?.call(id) ??
            Transport(identity: id, serverUrl: 'ws://127.0.0.1:$port'));
    live.add(svc);
    return svc;
  }

  Future<void> waitUntil(FutureOr<bool> Function() cond,
      {Duration timeout = const Duration(seconds: 30),
      required String what}) async {
    final deadline = DateTime.now().add(timeout);
    while (!await cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
  }

  Future<int> metric(String name) async {
    // /metrics is token-gated (P1-14): the relay is spawned with
    // METRICS_TOKEN set to this value above. A refused scrape fails loudly
    // rather than reading as a relay that never empties.
    final req =
        await HttpClient().getUrl(Uri.parse('http://127.0.0.1:$port/metrics'));
    req.headers.set('authorization', 'Bearer z-apptest-metrics');
    final res = await req.close();
    final text = await res.transform(utf8.decoder).join();
    if (res.statusCode != 200) {
      throw StateError('/metrics answered HTTP ${res.statusCode}');
    }
    for (final line in const LineSplitter().convert(text)) {
      if (line.startsWith('$name ')) {
        return int.parse(line.substring(name.length + 1).trim());
      }
    }
    return -1;
  }

  /// Nothing undelivered at the relay and no client holding an outbox row:
  /// for online clients, every envelope has been processed and acknowledged.
  Future<void> quiet(List<ChatService> all,
      {required String what,
      Duration timeout = const Duration(seconds: 90)}) async {
    var calm = 0;
    await waitUntil(() async {
      for (final s in all) {
        await s.flushOutbox();
        if ((await s.vault.db.query('outbox', limit: 1)).isNotEmpty ||
            (await s.vault.db.query('group_fanout', limit: 1)).isNotEmpty) {
          calm = 0;
          return false;
        }
      }
      if (await metric('z_queued_envelopes') != 0) {
        calm = 0;
        return false;
      }
      return ++calm >= 3;
    }, timeout: timeout, what: what);
  }

  Future<void> settled(List<ChatService> all) async {
    await waitUntil(() async {
      for (final s in all) {
        for (final o in all) {
          if (identical(s, o)) continue;
          final c = s.contacts[o.myRid];
          if (c == null) continue;
          if (c.pqPub == null && c.pqCandidate == null) return false;
        }
      }
      for (final s in all) {
        if ((await s.vault.db.query('outbox', limit: 1)).isNotEmpty) {
          return false;
        }
      }
      return all.every((s) => !s.pqSendPending);
    }, what: 'the contacts settled');
  }

  Future<void> befriend(ChatService a, ChatService b) async {
    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());
  }

  Future<(ChatService, ChatService)> pair(String tag) async {
    final a = await start('A$tag');
    final b = await start('B$tag');
    await waitUntil(() => a.transport.isConnected && b.transport.isConnected,
        what: 'both connect');
    await befriend(a, b);
    await settled([a, b]);
    return (a, b);
  }

  List<String> texts(ChatService s, String rid) => [
        for (final m in s.messagesByChat[rid] ?? const <ChatMessage>[])
          if (m.kind == 'text') m.body
      ];

  /// Post raw sealed envelopes straight into [to]'s mailbox, from an anonymous
  /// socket, the way anyone holding the routing id can. Each is sealed to
  /// [to], stamped with sender [fromRid] so [to] routes it to that contact.
  Future<void> post(ChatService to, String fromRid, List<String> transport,
      {bool alreadySealed = false}) async {
    final c = await RelayClient.connectAnonymous(
        'ws://127.0.0.1:$port', await ZIdentity.generate());
    for (final p in transport) {
      final blob = alreadySealed
          ? p
          : await SealedEnvelope.seal(
              toXPub: to.identity.xPub, fromRid: fromRid, payload: p);
      await c.send(to: to.myRid, id: newMessageId(), payload: blob);
    }
    await c.close();
  }

  /// Deliver [badBytes] to [b] as an authenticated-but-malformed inner from
  /// [a]: encrypt it on the real a→b session and post the sealed envelope.
  Future<void> deliverBadInner(
      ChatService a, ChatService b, Uint8List badBytes) async {
    final sealed = await a.debugSealRaw(b.myRid, badBytes);
    await post(b, a.myRid, [sealed], alreadySealed: true);
  }

  Uint8List raw(String json) => Uint8List.fromList(utf8.encode(json));

  test('1. wrong member types are acknowledged, and the chat goes on',
      () async {
    final (a, b) = await pair('1');
    await a.sendText(b.myRid, 'before');
    await waitUntil(() => texts(b, a.myRid).contains('before'),
        what: 'the first message arrives');

    // A spread of wrong-typed members across several kinds, each a validly
    // encrypted envelope whose plaintext an honest client would never emit.
    final mid = newMessageId();
    for (final bad in <String>[
      '{"k":123,"mid":"$mid","ts":1}', // kind not a string
      '{"k":"text","mid":"$mid","ts":1,"body":5}', // body not a string
      '{"k":"read","mid":"$mid","ts":1,"mids":5}', // mids not a list
      '{"k":"read","mid":"$mid","ts":1,"mids":[1,2]}', // mids not strings
      '{"k":"del","mid":"$mid","ts":1,"mids":{"x":1}}', // mids not a list
      '{"k":"timer","mid":"$mid","ts":1,"sec":"soon"}', // sec not a number
      '{"k":"gmsg","mid":"$mid","ts":1,"gid":9,"body":"x"}', // gid not a string
    ]) {
      await deliverBadInner(a, b, raw(bad));
    }

    await quiet([a, b], what: 'the malformed envelopes drain');
    expect(await metric('z_queued_envelopes'), 0,
        reason: 'no malformed envelope is left wedging the mailbox');

    await a.sendText(b.myRid, 'after');
    await waitUntil(() => texts(b, a.myRid).contains('after'),
        what: 'the next valid message arrives');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('2. a non-finite number is acknowledged, and the chat goes on',
      () async {
    final (a, b) = await pair('2');
    await a.sendText(b.myRid, 'before');
    await waitUntil(() => texts(b, a.myRid).contains('before'),
        what: 'the first message arrives');

    final mid = newMessageId();
    for (final bad in <String>[
      '{"k":"text","mid":"$mid","ts":1e999,"body":"hi"}', // ts not finite
      '{"k":"text","mid":"$mid","ts":1,"ttl":1e999,"body":"hi"}', // ttl
      '{"k":"timer","mid":"$mid","ts":1,"sec":1e999}', // a kind member
      '{"k":"text","mid":"$mid","ts":1,"body":"x","dl":{"v":1e999,"h":"z"}}',
    ]) {
      await deliverBadInner(a, b, raw(bad));
    }

    await quiet([a, b], what: 'the non-finite envelopes drain');
    expect(await metric('z_queued_envelopes'), 0);

    await a.sendText(b.myRid, 'after');
    await waitUntil(() => texts(b, a.myRid).contains('after'),
        what: 'the next valid message arrives');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('3. an opener with a wrong-length key is acknowledged and leaves no '
      'session', () async {
    final (a, b) = await pair('3');
    await a.sendText(b.myRid, 'before');
    await waitUntil(() => texts(b, a.myRid).contains('before'),
        what: 'the first message arrives');
    final sessionsBefore = b.debugConversation(a.myRid)!.sessions.length;

    // A session opener whose ephemeral key is 31 bytes, not 32: it can never
    // open a session, and handed to the DH it threw an ArgumentError that
    // escaped the receiver and left the envelope unacknowledged. The sid
    // matches the key, so the check it fails is the length.
    final ek = randomBytes(31);
    final sid = await sessionIdFromEk(ek);
    final opener = base64Encode(utf8.encode(jsonEncode({
      'v': 1,
      't': 'r',
      'sid': sid,
      'ek': b64(ek),
      'h': {'dh': b64(randomBytes(32)), 'n': 0, 'pn': 0},
      'n': b64(Uint8List(24)),
      'ct': b64(Uint8List(16)),
      'mac': b64(Uint8List(16)),
    })));
    await post(b, a.myRid, [opener]);

    await quiet([a, b], what: 'the malformed opener drains');
    expect(await metric('z_queued_envelopes'), 0,
        reason: 'the opener is acknowledged, not left wedging the mailbox');
    expect(b.debugConversation(a.myRid)!.sessions.length, sessionsBefore,
        reason: 'a failed opener commits no session');

    await a.sendText(b.myRid, 'after');
    await waitUntil(() => texts(b, a.myRid).contains('after'),
        what: 'the next valid message arrives');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('4. 300 malformed envelopes do not fill the mailbox', () async {
    final (a, b) = await pair('4');
    for (var i = 0; i < 300; i++) {
      await deliverBadInner(
          a, b, raw('{"k":"text","mid":"${newMessageId()}","ts":1,"body":$i}'));
    }
    await quiet([a, b], what: 'all 300 malformed envelopes drain',
        timeout: const Duration(minutes: 3));
    expect(await metric('z_queued_envelopes'), 0,
        reason: '300 malformed envelopes leave nothing queued');

    await a.sendText(b.myRid, 'survivor');
    await waitUntil(() => texts(b, a.myRid).contains('survivor'),
        what: 'a valid message after the flood arrives');
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('5. a transient vault failure on self-sync is redelivered, not lost',
      () async {
    // A phone holding the account root, a laptop linked to it, and a contact.
    final phone = await start('phone5');
    final carol = await start('carol5');
    await waitUntil(
        () => phone.transport.isConnected && carol.transport.isConnected,
        what: 'phone and carol connect');

    final account = await phone.accountIdentity();
    final laptopId = await ZIdentity.generate();
    final laptopCert = await account.signDeviceCert(
        deviceEdPub: laptopId.edPub,
        deviceXPub: laptopId.xPub,
        deviceId: 'laptop');
    final lvault = await Vault.open(rootOverride: await dirFor('laptop5'));
    await lvault.kvPut('identity', jsonEncode(laptopId.toJson()));
    final myMl = await phone.pqAccountPublic();
    final acct = myMl == null ? account : account.withAccountMlPub(myMl);
    final enrolled = await AccountIdentity.fromEnrollment(
      accountEdPub: acct.accountEdPub,
      accountMlPub: acct.accountMlPub,
      deviceEdSeed: laptopId.edSeed,
      deviceXSeed: laptopId.xSeed,
      deviceId: 'laptop',
      deviceCert: laptopCert,
    );
    await lvault.kvPut('account', jsonEncode(enrolled.toJson()));
    await lvault.kvPut('my_devices', jsonEncode([account.deviceCert.toJson()]),
        sensitive: false);
    final laptop = await ChatService.init(
        vault: lvault,
        identity: laptopId,
        displayName: 'laptop',
        transport:
            Transport(identity: laptopId, serverUrl: 'ws://127.0.0.1:$port'));
    live.add(laptop);
    await waitUntil(() => laptop.transport.isConnected, what: 'laptop connects');
    await phone.addMyDevice(laptopCert);
    // Befriend Carol AFTER linking, so the phone mirrors the new contact to
    // the laptop — the laptop must hold Carol to file her mirrored message.
    await befriend(phone, carol);
    await settled([phone, carol]);
    await waitUntil(() => laptop.contacts.containsKey(carol.myRid),
        what: 'the laptop learns Carol');
    // Let the link settle completely, so the ONLY thing queued for the laptop
    // while it is away below is Carol's mirror — and the armed failure hits
    // that envelope and no other.
    await quiet([phone, carol, laptop], what: 'the link settles');

    // The laptop goes offline; Carol speaks; the phone mirrors it to the
    // laptop, which queues at the relay for the offline laptop.
    await laptop.transport.stop();
    await waitUntil(() => !laptop.transport.isConnected,
        what: 'the laptop is offline');
    await carol.sendText(phone.myRid, 'while the laptop was away');
    await waitUntil(
        () => texts(phone, carol.myRid).contains('while the laptop was away'),
        what: 'the phone received and mirrored it');

    // Arm a one-shot vault-write failure, then bring the laptop back: the
    // relay flushes the mirror, and the first store of it fails. On the old
    // code that failure was swallowed and the envelope acknowledged away —
    // the message lost from the relay and the device both. Now it is left
    // with the relay, so a reconnect redelivers it and it lands.
    expect(laptop.debugFailNextSyncSave(), isTrue,
        reason: 'the laptop has self-sync (a device is linked)');
    laptop.transport.start();
    // The first flush delivers the mirror and its store fails once.
    await waitUntil(() => laptop.debugSyncSaveFailures == 1,
        what: 'the transient save failure fired on first delivery',
        timeout: const Duration(seconds: 60));
    // The envelope was left with the relay (not acknowledged away). The
    // in-process relay reflushes only on a reconnect, so bounce the link to
    // trigger the redelivery; the one-shot is spent, so this store succeeds
    // and the message lands. On the old code the first delivery acknowledged
    // the envelope away, so this reconnect brings nothing and the message is
    // gone for good.
    await laptop.transport.stop();
    await waitUntil(() => !laptop.transport.isConnected, what: 'laptop offline');
    laptop.transport.start();
    await waitUntil(
        () => texts(laptop, carol.myRid).contains('while the laptop was away'),
        what: 'the mirrored message survives a transient save failure',
        timeout: const Duration(seconds: 90));
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('6. the outbox retries after an internal refusal', () async {
    // A transport whose sends are refused with `internal` a few times while
    // the link is up, then succeed. The relay never says why in a way the
    // sender can match to one envelope, so the outbox used to stop until the
    // next reconnect; now it comes back on its own backoff timer.
    var failsLeft = 0; // clean setup; the refusals are armed just before the send
    final a = await start('A6', transportFor: (id) {
      return _FlakyTransport(id, 'ws://127.0.0.1:$port', () {
        if (failsLeft > 0) {
          failsLeft--;
          return true;
        }
        return false;
      });
    });
    final b = await start('B6');
    await waitUntil(() => a.transport.isConnected && b.transport.isConnected,
        what: 'both connect');
    a.outboxRetryDelay = const Duration(milliseconds: 400);
    await befriend(a, b);
    await settled([a, b]);

    failsLeft = 3; // now arm the refusals for the real send
    await a.sendText(b.myRid, 'through the internal errors');
    await waitUntil(
        () => texts(b, a.myRid).contains('through the internal errors'),
        what: 'the outbox retried past the internal refusals',
        timeout: const Duration(seconds: 60));
    expect(a.transport.isConnected, isTrue,
        reason: 'no reconnect was needed: the retry timer did it');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('7. a held 1:1 edit is delivered when the conflict is answered',
      () async {
    final (a, b) = await pair('7');
    await a.sendText(b.myRid, 'original');
    await waitUntil(() => texts(b, a.myRid).contains('original'),
        what: 'the original arrives');
    final mid = a.messagesByChat[b.myRid]!
        .firstWhere((m) => m.body == 'original')
        .mid;

    // A transparency conflict holds sends to B. The edit applies locally at
    // once; the send is held.
    a.kt.debugForceConflict(b.myRid);
    expect(a.kt.sendsHeld(b.myRid), isTrue);
    await a.editMessage(b.myRid, mid, 'edited while held');
    // The edit is applied locally and queued durably, not sent, while the
    // conflict stands: an observable (a fan-out row for B) rather than a wait.
    await waitUntil(
        () async => (await a.vault.db.query('group_fanout',
                where: 'rid = ?', whereArgs: [b.myRid]))
            .isNotEmpty,
        what: 'the held edit is queued durably');
    expect(
        b.messagesByChat[a.myRid]!.firstWhere((m) => m.mid == mid).body,
        'original',
        reason: 'the edit is held, not delivered, while the conflict stands');

    // Answer the conflict: the held edit drains and reaches B.
    await a.kt.acknowledgeConflict(b.myRid);
    await waitUntil(
        () =>
            b.messagesByChat[a.myRid]!
                .firstWhere((m) => m.mid == mid)
                .body ==
            'edited while held',
        what: 'the held edit is delivered once the conflict is answered');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('8. what a contact names ahead of its message is kept only within '
      'bounds', () async {
    final (a, b) = await pair('8');
    final now = DateTime.now().millisecondsSinceEpoch;
    final ahead = newMessageId(); // an id like ours, of no message B holds
    final long = 'L' * 65; // one character over the bound on an id (§6.4)
    final text = 'G' * 4096; // a 1:1 reaction's gid, which nothing reads

    // From A, on the real session: a 1:1 reaction to a message B does not
    // hold yet, carrying a gid; a reaction naming the over-long id; and a
    // delivery and a read receipt naming it, the delivery a plausible id
    // too. Each is well formed; only their sizes are the sender's choice.
    for (final m in <Map<String, Object?>>[
      {
        'k': 'react',
        'mid': newMessageId(),
        'ts': now,
        'rt': ahead,
        'emo': '👍',
        'gid': text,
      },
      {
        'k': 'react',
        'mid': newMessageId(),
        'ts': now,
        'rt': long,
        'emo': '👍',
      },
      {
        'k': 'dlv',
        'mid': newMessageId(),
        'ts': now,
        'mids': [long, ahead],
      },
      {
        'k': 'read',
        'mid': newMessageId(),
        'ts': now,
        'mids': [long],
      },
    ]) {
      await deliverBadInner(a, b, raw(jsonEncode(m)));
    }
    await quiet([a, b], what: 'B has taken all four');

    // Kept: the reaction naming the plausible id, without its gid, and the
    // receipt naming that id. Not the reaction or the receipts naming the
    // over-long one.
    final held = b.debugEarlyHeld;
    expect({
      'reactions': [
        for (final r in held.reactions)
          (r.thread, r.mid, r.sender, r.gid?.length),
      ],
      'receipts': [
        for (final m in held.receipts) m.length > 64 ? '${m.length} chars' : m,
      ],
    }, {
      'reactions': [(a.myRid, ahead, a.myRid, null)],
      'receipts': [ahead],
    }, reason: 'held within bounds: no over-long id, and no gid kept');

    // What is kept still counts when its message lands.
    await a.debugSendRawInner(
        b.myRid, InnerMessage.text(ahead, now, 'the one it named'));
    await waitUntil(() => b.debugEarlyHeld.reactions.isEmpty,
        what: 'the message lands and takes the reaction kept for it');
    final named =
        (await b.loadMessages(a.myRid)).firstWhere((m) => m.mid == ahead);
    expect({for (final r in named.reactions) r.senderRid: r.emoji},
        {a.myRid: '👍'});
  }, timeout: const Timeout(Duration(minutes: 3)));
}

/// A transport that refuses a send with `internal` whenever [shouldFail]
/// returns true (the link staying up), and otherwise behaves normally.
class _FlakyTransport extends Transport {
  _FlakyTransport(ZIdentity id, String url, this.shouldFail)
      : super(identity: id, serverUrl: url);
  final bool Function() shouldFail;

  @override
  Future<void> send(
      {required String to, required String id, required String payload}) {
    if (shouldFail()) {
      throw RelayException('internal');
    }
    return super.send(to: to, id: id, payload: payload);
  }
}
