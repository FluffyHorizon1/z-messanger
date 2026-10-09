// 40 — a connect invite bound to its secret, an add that asks first, and
// contact requests that cannot be replayed (ADR 0024).
//
// REAL ChatService instances. The ceremonies run through the REAL Node relay
// behind a tap that can stand in for the relay itself: it sees every frame,
// knows every mailbox, and rewrites what it carries — everything the relay,
// or Cloudflare in front of it, can do — while never holding the invite,
// which travels outside it. The requests and the groups are carried by hand,
// envelope by envelope, as `contact_requests_test.dart` carries them.
//
// Criteria, each a test below:
//   1. a relay in the middle that substitutes the frames of an invite made
//      now cannot complete it: the ceremony fails before either side has
//      the other's identity, the joiner never reveals its own, and the relay
//      opens nothing it carried;
//   2. opening an invite link posts nothing — not on opening, and not when
//      the poll runs — until the person says yes;
//   3. a contact request already declined, delivered again, is refused, and
//      so is one older than the bound or from too far in the future;
//   4. pending requests are capped at 100, the oldest unseen going first;
//   5. someone you blocked is not taken in through somebody else's group:
//      not made a contact, sent nothing, and nothing of theirs arrives;
//   6. the same relay still completes an invite of version 1 — made by a
//      client from before ADR 0024, and opened by this one — and only the
//      digits show it: skipped on both sides, each adds the relay under the
//      name it expected. The residual R25 names, pinned;
//   7. a client from before ADR 0024 refuses an invite made now, by link and
//      by code, as "not a Z invite", and posts nothing; the invite waits;
//   8. an invite a client from before ADR 0024 made still works, on its own
//      mailboxes, exactly as it always did;
//   9. the comparison screen of a version-1 invite says that until the
//      digits are compared even the relay could be in the middle — and that
//      of an invite made now does not;
//  10. an invite opened from a link shows, before anything is sent, what
//      connecting sends and to whom, and its Connect button is what starts
//      the ceremony;
//  11. a held invite stays held through a restart, and after the yes the
//      ceremony completes as any other;
//  12. a declined request's mark outlives a restart; a NEW request from the
//      same person, made later, is shown; and the age bound is 30 days by
//      the request's own signed time;
//  13. requests the person has seen are the last the cap pushes out: with
//      all of them seen, a new one is the one that goes;
//  14. an invite — a group link — answered by someone the inviter blocked
//      ends refused: nobody is added, to the contacts or to the group, and
//      the block stands;
//  15. an invite made by someone the person blocked ends refused on the
//      joiner's side before the joiner reveals itself.
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
import 'package:zapp/ui/theme.dart';

typedef Person = ({
  ChatService svc,
  Vault vault,
  ConnectInvites invites,
  ZIdentity id
});

/// The relay in the middle of a ceremony: it rewrites the four frames as
/// they pass, running one leg with each side under identities of its own.
///
/// It holds everything the relay holds — the frames, the mailboxes they go
/// to, the order they come in — and nothing it does not: the invite secret
/// travels in a link the relay never carries. So it derives every key the
/// way a client before ADR 0024 does, which is the only way that needs no
/// secret: the channel key from the two ephemerals alone, the commitments
/// from what they commit to alone. Against such an invite it completes both
/// legs. It is written from the primitives, sharing no code with the
/// client, so what it can do is what the specification lets it do.
class RelayInTheMiddle {
  RelayInTheMiddle({required this.asInviter, required this.asAcceptor});

  /// What it reveals to the person who opened the invite, and to the person
  /// who made it.
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

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  late Process relay;
  late HttpServer tap;
  late String url;
  final temps = <Directory>[];
  final live = <Person>[];

  // Every frame the tap carried, decoded. Cleared per test.
  final seen = <Map<String, Object?>>[];

  // When set, the tap is the relay in the middle.
  RelayInTheMiddle? mitm;

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

    // The tap. Both directions are written down; a ceremony frame on its
    // way in is handed to the relay in the middle, when there is one, and
    // what it returns is what the relay stores. Each connection's frames
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
      down.listen((d) {
        inOrder = inOrder.then((_) async {
          final f = note(d);
          final m = mitm;
          final payload = f?['payload'];
          if (m != null &&
              f != null &&
              f['t'] == 'send' &&
              '${f['id']}'.startsWith('z-connect-c') &&
              payload is String) {
            upstream.add(jsonEncode({...f, 'payload': await m.rewrite(payload)}));
          } else {
            upstream.add(d);
          }
        });
      },
          // After whatever is still being rewritten, not before it.
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
    mitm = null;
  });

  // Where each person's app keeps its vault, what it dials, and who it is:
  // what a restart opens again.
  final homes = <ChatService, (Directory, String)>{};

  Future<Person> openApp(Directory dir, ZIdentity id, String name,
      String serverUrl) async {
    final vault = await Vault.open(rootOverride: dir);
    if (await vault.kvGet('identity') == null) {
      await vault.kvPut('identity', jsonEncode(id.toJson()));
    }
    final svc = await ChatService.init(
        vault: vault,
        identity: id,
        displayName: name,
        transport: Transport(identity: id, serverUrl: serverUrl));
    final p = (svc: svc, vault: vault, invites: ConnectInvites(svc), id: id);
    homes[svc] = (dir, serverUrl);
    live.add(p);
    return p;
  }

  /// A person with an app. [online]: through the tap to the relay; offline,
  /// the relay is a port nothing listens on and envelopes are carried by
  /// hand.
  Future<Person> person(String name, {bool online = true}) async {
    final dir = await Directory.systemTemp.createTemp('z_bind_');
    temps.add(dir);
    return openApp(dir, await ZIdentity.generate(), name,
        online ? url : 'ws://127.0.0.1:1');
  }

  /// [p]'s app killed and started again: the same vault and identity,
  /// nothing in memory.
  Future<Person> restart(Person p) async {
    final (dir, serverUrl) = homes[p.svc]!;
    final name = p.svc.displayName;
    p.invites.pause();
    await p.svc.transport.stop();
    p.svc.dispose();
    live.remove(p);
    await p.vault.db.close();
    return openApp(dir, p.id, name, serverUrl);
  }

  /// The relay's two faces: an identity of its own toward each side, named
  /// as each side expects the other to be. Returns the relay in the middle
  /// and the identities it shows the inviter and the acceptor.
  Future<(RelayInTheMiddle, ZIdentity, ZIdentity)> relayFaces() async {
    final asBob = await ZIdentity.generate(), asAlice = await ZIdentity.generate();
    final middle = RelayInTheMiddle(
        asInviter: (
          code: (await asAlice.bundle(displayName: 'Alice')).encode(),
          name: 'Alice'
        ),
        asAcceptor: (
          code: (await asBob.bundle(displayName: 'Bob')).encode(),
          name: 'Bob'
        ));
    return (middle, asBob, asAlice);
  }

  /// The CONNECT tab, or a part of it, wired to [p].
  Widget tab(Person p, Widget child) => MultiProvider(
        providers: [
          ChangeNotifierProvider<ChatService>.value(value: p.svc),
          ChangeNotifierProvider<ConnectInvites>.value(value: p.invites),
        ],
        child: MaterialApp(
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          theme: ZTheme.dark(),
          home: Scaffold(body: child),
        ),
      );

  /// Rebuild until [cond] holds on the widget tree, letting real work — a
  /// socket refused, a vault written — happen in between, as
  /// `connect_invite_test.dart` does; fail saying [what] if it never does.
  Future<void> settleUntil(WidgetTester t, bool Function() cond,
      {required String what}) async {
    final deadline = DateTime.now().add(const Duration(seconds: 30));
    await t.pump(const Duration(milliseconds: 50));
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await t.runAsync(
          () => Future<void>.delayed(const Duration(milliseconds: 100)));
      await t.pump(const Duration(milliseconds: 50));
    }
    await t.pump(const Duration(milliseconds: 350));
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

  /// Both sides' rounds, until each has digits or has stopped — each pump a
  /// whole connect-act-disconnect, awaited.
  Future<void> dance(Person a, PendingInvite ai, Person b,
      PendingInvite bi) async {
    bool over(PendingInvite i) =>
        i.sas != null ||
        i.progress == ConnectProgress.aborted ||
        i.progress == ConnectProgress.spent;
    for (var i = 0; i < 8 && !(over(ai) && over(bi)); i++) {
      await a.invites.pump();
      await b.invites.pump();
    }
  }

  /// How many times a client asked the relay to carry the envelope [id].
  int sends(String id) =>
      seen.where((f) => f['t'] == 'send' && f['id'] == id).length;

  /// Every envelope queued in [from]'s outbox for [to], taken out and handed
  /// to [to] as the relay would hand it over; how many there were.
  Future<int> carry(Person from, Person to) async {
    final rows = await from.vault.db.query('outbox',
        where: 'rid = ?', whereArgs: [to.svc.myRid], orderBy: 'seq');
    await from.vault.db
        .delete('outbox', where: 'rid = ?', whereArgs: [to.svc.myRid]);
    for (final r in rows) {
      await to.svc.debugInbound(RelayInbound(
          id: r['id'] as String,
          from: '',
          payload: r['payload'] as String,
          serverTs: DateTime.now().millisecondsSinceEpoch));
    }
    return rows.length;
  }

  /// Carry everything queued among [all] — group fan-out and receipts too —
  /// until nothing is left on the way, or fail saying so.
  Future<void> settleAll(List<Person> all) async {
    final deadline = DateTime.now().add(const Duration(seconds: 60));
    while (true) {
      for (final x in all) {
        await x.svc.drainGroupFanoutForTest();
        await x.svc.flushDeliveryReceipts();
      }
      var moved = 0;
      for (final x in all) {
        for (final y in all) {
          if (!identical(x, y)) moved += await carry(x, y);
        }
      }
      if (moved == 0 &&
          all.every((x) => x.svc.pendingDeliveryReceipts == 0) &&
          await Future.wait([
            for (final x in all) x.vault.db.query('group_fanout', limit: 1)
          ]).then((r) => r.every((rows) => rows.isEmpty))) {
        return;
      }
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('everything queued among them delivered');
      }
    }
  }

  /// A request from [from] to [to], made at [ts], sealed as the relay would
  /// carry it: the transport payload a `creq` travels in.
  Future<String> requestEnvelope(ZIdentity from, String name, Person to,
      {int? ts}) async {
    final req = await ContactRequest.create(
        me: from, toRid: to.svc.myRid, displayName: name, ts: ts);
    return SealedEnvelope.seal(
        toXPub: to.id.xPub,
        fromRid: await from.routingId(),
        payload: req.encode());
  }

  var delivered = 0;
  Future<void> deliver(Person to, String sealed) => to.svc.debugInbound(
      RelayInbound(
          id: 'by-hand-${delivered++}',
          from: '',
          payload: sealed,
          serverTs: DateTime.now().millisecondsSinceEpoch));

  test('1. a relay in the middle cannot complete an invite made now',
      () async {
    final alice = await person('Alice');
    final bob = await person('Bob');
    // The relay's two faces: an identity of its own toward each side, named
    // as each side expects the other to be.
    final m1 = await ZIdentity.generate(), m2 = await ZIdentity.generate();
    final relayAsBob =
        (code: (await m1.bundle(displayName: 'Bob')).encode(), name: 'Bob');
    final relayAsAlice =
        (code: (await m2.bundle(displayName: 'Alice')).encode(), name: 'Alice');
    final middle =
        RelayInTheMiddle(asInviter: relayAsAlice, asAcceptor: relayAsBob);
    mitm = middle;

    final mine = await alice.invites.create();
    final theirs = await bob.invites.open(mine.link);
    await dance(alice, mine, bob, theirs);

    expect(middle.replaced, containsAll(['x1', 'x2', 'x3']),
        reason: 'the relay did rewrite the frames it carried');
    expect(theirs.sas, isNull,
        reason: 'the joiner never reached the digits');
    expect(theirs.progress, ConnectProgress.aborted,
        reason: 'it stopped at the message it could not open');
    expect(mine.sas, isNull, reason: 'nor did the inviter');
    expect(sends('z-connect-c4'), 0,
        reason: 'the joiner never revealed itself, to anyone');
    expect(middle.readFromInviter, isNull,
        reason: "the relay could not open the inviter's reveal");
    expect(middle.readFromAcceptor, isNull);
    expect(alice.svc.contacts, isEmpty);
    expect(bob.svc.contacts, isEmpty);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('2. opening an invite link posts nothing until the person says yes',
      () async {
    final alice = await person('Alice');
    final bob = await person('Bob');
    final mine = await alice.invites.create();
    await alice.invites.pump(); // message 1 waits in Bob's mailbox

    final links = DeepLinks(bob.invites,
        channel: const MethodChannel('z/deeplink/invite-binding'));
    final opened = await links.handle(mine.link);
    expect(opened, isNotNull, reason: 'the link was taken');
    // What the app's poll does while the person has not answered yet.
    await bob.invites.pump();
    await bob.invites.pump();

    final bobsMailbox = await mailboxIdentity(opened!.run.code, 'r');
    expect(
        seen.where((f) => f['t'] == 'auth' && f['pub'] == b64(bobsMailbox.edPub)),
        isEmpty,
        reason: "Bob's side of the invite never even connected to the relay");
    expect(sends('z-connect-c2'), 0, reason: 'nothing was posted');
    await alice.invites.pump();
    expect(mine.sas, isNull);
    expect(bob.svc.contacts, isEmpty);
    await links.dispose();
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('3. a request declined, delivered again, is refused; so is a stale one',
      () async {
    final alice = await person('Alice', online: false);
    final bob = await person('Bob', online: false);

    // Bob adds Alice by her code; his request is in his outbox, sealed.
    await bob.svc.addContactFromCode(await alice.svc.myContactCode());
    String? sealedRequest;
    for (final r in await bob.vault.db.query('outbox',
        where: 'rid = ?', whereArgs: [alice.svc.myRid])) {
      final opened = await SealedEnvelope.open(
          myXSeed: alice.id.xSeed,
          myXPub: alice.id.xPub,
          blob: r['payload'] as String);
      if (opened != null && ContactRequest.tryParse(opened.payload) != null) {
        sealedRequest = r['payload'] as String;
      }
    }
    expect(sealedRequest, isNotNull, reason: 'the request was queued');
    await carry(bob, alice);
    expect(alice.svc.requests.map((r) => r.rid), [bob.svc.myRid]);

    await alice.svc.declineRequest(bob.svc.myRid);
    expect(alice.svc.requests, isEmpty);

    // The relay kept a copy, and hands it over again.
    await deliver(alice, sealedRequest!);
    expect(alice.svc.requests, isEmpty,
        reason: 'a request already answered is not shown again');

    // A request made two months ago, never seen before: too old.
    final carol = await ZIdentity.generate();
    final old = DateTime.now()
        .subtract(const Duration(days: 60))
        .millisecondsSinceEpoch;
    await deliver(alice, await requestEnvelope(carol, 'Carol', alice, ts: old));
    expect(alice.svc.requests, isEmpty, reason: 'a stale request is refused');

    // And one dated two days from now.
    final dave = await ZIdentity.generate();
    final ahead =
        DateTime.now().add(const Duration(days: 2)).millisecondsSinceEpoch;
    await deliver(alice, await requestEnvelope(dave, 'Dave', alice, ts: ahead));
    expect(alice.svc.requests, isEmpty,
        reason: 'a request from too far in the future is refused');
  });

  test('4. pending requests are capped at 100, the oldest unseen first',
      () async {
    final alice = await person('Alice', online: false);
    final senders = <String>[];
    for (var i = 0; i < 101; i++) {
      final someone = await ZIdentity.generate();
      senders.add(await someone.routingId());
      await deliver(alice, await requestEnvelope(someone, 'Asker $i', alice));
    }
    expect(alice.svc.requests, hasLength(100),
        reason: 'a hundred and one asked; a hundred are held');
    expect(alice.svc.requests.map((r) => r.rid), isNot(contains(senders.first)),
        reason: 'the oldest unseen went');
    expect(alice.svc.requests.map((r) => r.rid), contains(senders.last));
    expect(await alice.vault.db.query('requests'), hasLength(100),
        reason: 'and the table holds what the list shows');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('5. someone you blocked is not taken in through somebody else\'s group',
      () async {
    final alice = await person('Alice', online: false);
    final carol = await person('Carol', online: false);
    final mallory = await person('Mallory', online: false);
    final all = [alice, carol, mallory];

    // Mallory asks Alice to connect, and Alice blocks her. Mallory is not
    // told, and goes on holding Alice as someone she asked.
    await mallory.svc.addContactFromCode(await alice.svc.myContactCode());
    await carry(mallory, alice);
    expect(alice.svc.requests.map((r) => r.rid), [mallory.svc.myRid]);
    await alice.svc.blockRequest(mallory.svc.myRid);
    expect(alice.svc.isBlocked(mallory.svc.myRid), isTrue);

    // Carol knows both, and puts the three of them in a group.
    for (final x in [alice, mallory]) {
      await carol.svc.addContactFromCode(await x.svc.myContactCode());
      await x.svc.addContactFromCode(await carol.svc.myContactCode());
    }
    await settleAll(all);
    final gid =
        await carol.svc.createGroup('Book club', [alice.svc.myRid, mallory.svc.myRid]);
    await settleAll(all);
    expect(alice.svc.groups[gid], isNotNull, reason: 'Alice is in the group');

    expect(alice.svc.contacts.containsKey(mallory.svc.myRid), isFalse,
        reason: 'the group did not make Mallory her contact');
    expect(alice.svc.isBlocked(mallory.svc.myRid), isTrue,
        reason: 'and the block stands');

    // Each writes in the group, and Mallory tries Alice directly.
    await alice.svc.sendGroupText(gid, 'from Alice');
    await mallory.svc.sendGroupText(gid, 'from Mallory');
    await settleAll(all);
    if (mallory.svc.contacts.containsKey(alice.svc.myRid)) {
      await mallory.svc.sendText(alice.svc.myRid, 'it is me');
      await settleAll(all);
    }
    final aliceSaw = [
      for (final ms in alice.svc.messagesByChat.values)
        for (final m in ms) m.body
    ];
    expect(aliceSaw, isNot(contains('from Mallory')));
    expect(aliceSaw, isNot(contains('it is me')),
        reason: 'nothing of hers arrives');
    final mallorySaw = [
      for (final m in mallory.svc.messagesByChat[gid] ?? const <ChatMessage>[])
        m.body
    ];
    expect(mallorySaw, isNot(contains('from Alice')),
        reason: "Alice's device sends her nothing");
    expect(carol.svc.messagesByChat[gid]!.map((m) => m.body),
        containsAll(['from Alice', 'from Mallory']),
        reason: 'the rest of the group is untouched');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('6. the same relay still completes an invite of version 1', () async {
    // Alice's app predates ADR 0024: it makes version 1. Bob's is this one.
    final alice = await person('Alice');
    alice.invites.debugBeforeBinding = true;
    final bob = await person('Bob');
    final (middle, asBob, asAlice) = await relayFaces();
    mitm = middle;

    final mine = await alice.invites.create();
    expect(mine.run.code.version, 1);
    final theirs = await bob.invites.open(mine.link);
    expect(theirs.unbound, isTrue, reason: 'a new client opens it as it is');
    await dance(alice, mine, bob, theirs);

    expect(middle.replaced, ['x1', 'x2', 'x3', 'x4']);
    expect(mine.sas, isNotNull, reason: 'the inviter reached the digits');
    expect(theirs.sas, isNotNull, reason: 'and so did the joiner');
    expect(theirs.sas, isNot(mine.sas), reason: 'only the digits show it');
    expect(middle.readFromInviter?['name'], 'Alice',
        reason: 'the relay read what each side revealed');
    expect(middle.readFromAcceptor?['name'], 'Bob');

    // Neither compares: each adds the relay, under the name it expected.
    final a = await alice.invites.defer(mine);
    final b = await bob.invites.defer(theirs);
    expect((a.name, a.rid), ('Bob', await asBob.routingId()));
    expect((b.name, b.rid), ('Alice', await asAlice.routingId()));
    expect(alice.svc.verificationWith(a.rid), VerificationState.unverified);
    expect(bob.svc.verificationWith(b.rid), VerificationState.unverified);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('7. an older client refuses an invite made now, and posts nothing',
      () async {
    final alice = await person('Alice');
    final bob = await person('Bob');
    bob.invites.debugBeforeBinding = true;
    final mine = await alice.invites.create();
    expect(mine.run.code.version, 2);
    expect(mine.link, contains('/i#9'));
    expect(mine.code, startsWith('9'));
    await alice.invites.pump();

    for (final handed in [mine.link, mine.code]) {
      await expectLater(
          bob.invites.open(handed),
          throwsA(isA<FormatException>().having(
              (e) => e.message, 'message', 'that is not a Z invite')),
          reason: 'pasted: "$handed"');
    }
    final links = DeepLinks(bob.invites,
        channel: const MethodChannel('z/deeplink/invite-binding-7'));
    expect(await links.handle(mine.link), isNull,
        reason: 'tapped: ignored, as an old build ignores it');
    expect(links.lastRejected, mine.link);
    await links.dispose();
    expect(bob.invites.invites, isEmpty);

    await alice.invites.pump();
    expect(sends('z-connect-c2'), 0, reason: 'nothing reached the relay');
    expect(mine.progress, ConnectProgress.waiting,
        reason: 'the invite waits, until it is discarded or runs out');
    expect(mine.sas, isNull);
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('8. an invite an older client made still works as it always did',
      () async {
    final alice = await person('Alice');
    alice.invites.debugBeforeBinding = true;
    final bob = await person('Bob');
    final mine = await alice.invites.create();
    expect(mine.run.code.version, 1);
    expect(mine.code, matches(RegExp(r'^[A-Z2-7-]+$')));
    final theirs = await bob.invites.open(mine.link);
    expect(theirs.run.code.version, 1);
    await dance(alice, mine, bob, theirs);
    expect(mine.sas, isNotNull);
    expect(theirs.sas, mine.sas);

    // On the mailboxes version 1 names, both of them.
    final authed = {
      for (final f in seen.where((f) => f['t'] == 'auth')) f['pub'] as String
    };
    for (final role in ['i', 'r']) {
      expect(authed,
          contains(b64((await mailboxIdentity(mine.run.code, role)).edPub)));
    }
    final a = await alice.invites.confirm(mine);
    final b = await bob.invites.confirm(theirs);
    expect(alice.svc.contacts[a.rid]!.verified, isTrue);
    expect(bob.svc.contacts[b.rid]!.verified, isTrue);
    expect((a.name, b.name), ('Bob', 'Alice'));
  }, timeout: const Timeout(Duration(minutes: 3)));

  testWidgets('9. the comparison of a version-1 invite says the relay could be '
      'in the middle', (t) async {
    late Person bob;
    late PendingInvite oldOne, newOne;
    await t.runAsync(() async {
      final alice = await person('Alice');
      alice.invites.debugBeforeBinding = true;
      final carol = await person('Carol');
      bob = await person('Bob');
      final a = await alice.invites.create();
      oldOne = await bob.invites.open(a.link);
      await dance(alice, a, bob, oldOne);
      final c = await carol.invites.create();
      newOne = await bob.invites.open(c.link);
      await dance(carol, c, bob, newOne);
    });
    expect(oldOne.sas, isNotNull);
    expect(newOne.sas, isNotNull);
    for (final (invite, shown) in [(oldOne, true), (newOne, false)]) {
      await t.pumpWidget(tab(bob,
          SingleChildScrollView(child: ConnectConfirmPanel(invite: invite))));
      await t.pump();
      expect(find.byKey(const ValueKey('connect-old-invite')),
          shown ? findsOneWidget : findsNothing,
          reason: 'version ${invite.run.code.version}');
      expect(find.textContaining('even the relay could be in the middle'),
          shown ? findsOneWidget : findsNothing);
    }
    await t.pumpWidget(const SizedBox());
  }, timeout: const Timeout(Duration(minutes: 3)));

  testWidgets('10. a linked invite says what connecting sends, and Connect is '
      'what starts it', (t) async {
    // Nothing listens at Bob's relay: a round that runs is a refusal, which
    // the card shows — the evidence that the button ran one.
    late Person bob;
    late PendingInvite held;
    await t.runAsync(() async {
      bob = await person('Bob', online: false);
      final links = DeepLinks(bob.invites,
          channel: const MethodChannel('z/deeplink/invite-binding-10'));
      held = (await links.handle(ConnectCode.generate().link()))!;
      await links.dispose();
    });
    expect(held.held, isTrue);
    await t.pumpWidget(tab(bob, const ConnectTab()));
    await settleUntil(
        t, () => find.text('Opened from a link — nothing sent yet').evaluate().isNotEmpty,
        what: 'the held card');
    expect(find.textContaining('sends your contact code to whoever made this invite'),
        findsOneWidget);
    expect(held.lastFailure, isNull,
        reason: 'the tab opening ran no round for a held invite');

    // Below the fold of the test's 800x600 screen: scrolled to, as a person
    // would scroll to it.
    final connect = find.byKey(ValueKey('connect-consent-${held.id}'));
    await t.ensureVisible(connect);
    await t.pump();
    await t.tap(connect);
    await settleUntil(
        t, () => find.textContaining('Could not reach the relay').evaluate().isNotEmpty,
        what: 'the round Connect started');
    expect(held.consented, isTrue);
    expect(held.lastFailure, isNotNull);
    expect(find.text('Opened from a link — nothing sent yet'), findsNothing);
    await t.runAsync(() => Future<void>.delayed(const Duration(seconds: 1)));
    await t.pump(const Duration(seconds: 20));
    await t.pump(const Duration(seconds: 20));
    bob.invites.pause();
    await t.pumpWidget(const SizedBox());
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('11. a held invite stays held through a restart, and the yes completes '
      'it', () async {
    final alice = await person('Alice');
    var bob = await person('Bob');
    final mine = await alice.invites.create();
    await alice.invites.pump();
    final links = DeepLinks(bob.invites,
        channel: const MethodChannel('z/deeplink/invite-binding-11'));
    final opened = (await links.handle(mine.link))!;
    await links.dispose();
    expect(opened.held, isTrue);

    bob = await restart(bob);
    await bob.invites.load();
    final held = bob.invites.invites.single;
    expect(held.held, isTrue, reason: 'read back out of the vault still held');
    await bob.invites.pump();
    expect(sends('z-connect-c2'), 0, reason: 'and still nothing sent');

    await bob.invites.consent(held);
    expect(held.held, isFalse);
    await dance(alice, mine, bob, held);
    expect(mine.sas, isNotNull);
    expect(held.sas, mine.sas);
    expect(sends('z-connect-c2'), 1);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('12. a decline outlives a restart; a later request is shown; the bound '
      'is 30 days', () async {
    var alice = await person('Alice', online: false);
    final bob = await ZIdentity.generate();
    final day = const Duration(days: 1).inMilliseconds;
    final now = DateTime.now().millisecondsSinceEpoch;

    final first = await requestEnvelope(bob, 'Bob', alice, ts: now - day);
    await deliver(alice, first);
    final bobRid = await bob.routingId();
    expect(alice.svc.requests.map((r) => r.rid), [bobRid]);
    await alice.svc.declineRequest(bobRid);

    alice = await restart(alice);
    await deliver(alice, first);
    expect(alice.svc.requests, isEmpty,
        reason: 'the copy is refused after a restart too');
    // An older request of his, arriving late, is no newer than the one
    // declined.
    await deliver(alice,
        await requestEnvelope(bob, 'Bob', alice, ts: now - 2 * day));
    expect(alice.svc.requests, isEmpty);
    // A NEW request, made after the decline: declining is not blocking.
    await deliver(alice, await requestEnvelope(bob, 'Bob', alice));
    expect(alice.svc.requests.map((r) => r.rid), [bobRid]);

    // The bound: 29 days old is shown, 31 is not.
    final kept = await ZIdentity.generate(), stale = await ZIdentity.generate();
    await deliver(alice,
        await requestEnvelope(kept, 'Kept', alice, ts: now - 29 * day));
    await deliver(alice,
        await requestEnvelope(stale, 'Stale', alice, ts: now - 31 * day));
    final shown = alice.svc.requests.map((r) => r.rid).toSet();
    expect(shown, contains(await kept.routingId()));
    expect(shown, isNot(contains(await stale.routingId())));
    expect(ChatService.requestMaxAge, const Duration(days: 30));
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('13. what the person has seen is the last the cap pushes out',
      () async {
    final alice = await person('Alice', online: false);
    Future<String> ask(String name) async {
      final someone = await ZIdentity.generate();
      await deliver(alice, await requestEnvelope(someone, name, alice));
      return someone.routingId();
    }

    final first = <String>[for (var i = 0; i < 100; i++) await ask('First $i')];
    expect(alice.svc.requests, hasLength(100));
    await alice.svc.markRequestsSeen();
    expect(first.every(alice.svc.debugRequestSeen), isTrue);

    // All a hundred seen: the newcomer is the only one nobody has looked at,
    // and the one that goes.
    final late = await ask('Late');
    expect(alice.svc.requests.map((r) => r.rid).toSet(), first.toSet());
    expect(alice.svc.requests.map((r) => r.rid), isNot(contains(late)));

    // Ten answered; fifteen more arrive. Five go — the five oldest of the
    // new ones, unseen — and every seen one stays.
    for (final rid in first.take(10)) {
      await alice.svc.declineRequest(rid);
    }
    final next = <String>[for (var i = 0; i < 15; i++) await ask('Next $i')];
    final held = alice.svc.requests.map((r) => r.rid).toSet();
    expect(held, hasLength(100));
    expect(held.containsAll(first.skip(10)), isTrue,
        reason: 'nothing the person had seen was pushed out');
    expect(held.containsAll(next.skip(5)), isTrue);
    expect(held.intersection(next.take(5).toSet()), isEmpty,
        reason: 'the oldest unseen went');
    expect(ChatService.maxPendingRequests, 100);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('14. a group link answered by someone the inviter blocked adds nobody',
      () async {
    final alice = await person('Alice');
    final carol = await person('Carol');
    final mallory = await person('Mallory');
    await waitUntil(
        () => [alice, carol, mallory].every((p) => p.svc.transport.isConnected),
        what: 'everyone connects');

    // Mallory asked once; Alice blocked her.
    await mallory.svc.addContactFromCode(await alice.svc.myContactCode());
    await waitUntil(() => alice.svc.requests.isNotEmpty,
        what: "Mallory's request arrives");
    await alice.svc.blockRequest(mallory.svc.myRid);

    // Alice's group, with Carol in it, and a link to it that Mallory takes.
    await alice.svc.addContactFromCode(await carol.svc.myContactCode());
    await carol.svc.addContactFromCode(await alice.svc.myContactCode());
    final gid = await alice.svc.createGroup('Garden', [carol.svc.myRid]);
    await waitUntil(() => carol.svc.groups.containsKey(gid),
        what: 'Carol holds the group');
    final link = await alice.invites.create(gid: gid);
    final taken = await mallory.invites.open(link.link);
    await dance(alice, link, mallory, taken);

    expect(link.progress, ConnectProgress.aborted,
        reason: 'refused at the reveal of someone blocked');
    expect(link.sas, isNull);
    expect(alice.svc.contacts.containsKey(mallory.svc.myRid), isFalse);
    expect(alice.svc.isBlocked(mallory.svc.myRid), isTrue);
    expect(alice.svc.groups[gid]!.memberRids, {carol.svc.myRid},
        reason: 'and nobody joined the group');
    expect(alice.svc.pendingLinkJoins, isEmpty);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test("15. an invite from someone the joiner blocked ends before the joiner "
      'reveals itself', () async {
    final alice = await person('Alice');
    final mallory = await person('Mallory');
    await waitUntil(
        () => [alice, mallory].every((p) => p.svc.transport.isConnected),
        what: 'both connect');
    // Mallory asked once; Alice blocked her.
    await mallory.svc.addContactFromCode(await alice.svc.myContactCode());
    await waitUntil(() => alice.svc.requests.isNotEmpty,
        what: "Mallory's request arrives");
    await alice.svc.blockRequest(mallory.svc.myRid);

    // Mallory sends Alice an invite under some other pretext; Alice opens it.
    final mine = await mallory.invites.create();
    final theirs = await alice.invites.open(mine.link);
    await dance(mallory, mine, alice, theirs);
    expect(theirs.progress, ConnectProgress.aborted,
        reason: "refused the moment Mallory's reveal opened");
    expect(theirs.sas, isNull);
    expect(sends('z-connect-c4'), 0, reason: 'Alice never revealed herself');
    expect(mine.sas, isNull, reason: 'so Mallory never learns who opened it');
    expect(alice.svc.contacts.containsKey(mallory.svc.myRid), isFalse);
    expect(alice.svc.isBlocked(mallory.svc.myRid), isTrue);
  }, timeout: const Timeout(Duration(minutes: 3)));
}
