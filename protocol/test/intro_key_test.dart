// The introduction key in the protocol library (44.9; ADR 0033 addendum A,
// PROTOCOL §8.3 and §12.7): a device's sealing key, which its relay keeps,
// signed by the Ed25519 key its mailbox is the hash of; the rule a sender
// accepts what a relay serves by; `sk` in contact codes; an introduction
// mailbox's own key; and the relay client's frames. Nothing in the app calls
// any of it yet (44.11–44.12 do), so this drives the library directly and
// the frames against a scripted relay. The values are pinned again, from the
// recorded seeds, by `vectors_test.dart` and the Node verifier.
//
// Criteria, each a test below:
//   1. `iks` is the mailbox key's Ed25519 signature over
//      "z-intro-key-v1:" || edPub || SHA-256(ek), deterministic, and it
//      verifies under §21.4's one rule only: not under another key, not over
//      another key, not with S + L or R the identity, not truncated;
//   2. the entry a relay keeps is ek || iks, 1 248 bytes, splits back into
//      its halves and nothing of another length, and the hint `ready` names
//      it by is b64url of the first 16 bytes of its SHA-256;
//   3. FIPS 203 §7.2's check takes every key keygen makes and refuses a key
//      of any other length or with any one of its 768 coefficients at q —
//      at q − 1 it takes it — and does not look at ρ; it agrees with the
//      library's own encapsulation, which throws for the keys it refuses;
//   4. an introduction mailbox's key is HKDF(introSeed, "z-handle-intro-k-v1",
//      ∅, 64) as `d || z`, one per seed, apart from its X25519 key, and
//      decapsulates what is encapsulated to it;
//   5. the acceptance rule takes the genuine entry and refuses each
//      alteration with the reason for the check it breaks — the length of
//      either half, the modulus check, a key that is not the mailbox's, the
//      signature — and, for a code that carries `sk`, a key that is not the
//      one it names, which without `sk` it would take;
//   6. a contact code carries `sk` only when given one, beside `pqc` and
//      after `pqcs`; every decoder path reads it, and a code without it is
//      byte for byte the code before; a code with `sk` and no `pqc`, or
//      with an `sk` of the wrong length or type, is refused; a stored bundle
//      keeps it;
//   7. the relay client reads `ik:1` from the challenge on both kinds of
//      connection and `ready.ik` on an authenticated one, publishes only on
//      an authenticated connection and fetches only on an anonymous one —
//      each to a relay that said `ik:1`, a StateError otherwise with nothing
//      sent — sends exactly the frames §12.7 names, resolves on `ikey_ok` and
//      `ikey_for` (both halves, neither, or a malformed answer), and fails
//      with the relay's code (`bad_ikey`, `anon_only`) or when the connection
//      closes.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart' show DartSha256;
import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

Uint8List _seed(int n, int fill) => Uint8List(n)..fillRange(0, n, fill);

Uint8List _sha256(List<int> b) => Uint8List.fromList(
    const DartSha256().hashSync(b).bytes);

/// [ek] with coefficient [index] (0–767) of t̂ set to [value], in FIPS 203's
/// ByteEncode12 layout.
Uint8List _withCoefficient(Uint8List ek, int index, int value) {
  final out = Uint8List.fromList(ek);
  final at = (index ~/ 2) * 3;
  if (index.isEven) {
    out[at] = value & 0xff;
    out[at + 1] = (out[at + 1] & 0xf0) | ((value >> 8) & 0x0f);
  } else {
    out[at + 1] = (out[at + 1] & 0x0f) | ((value & 0x0f) << 4);
    out[at + 2] = (value >> 4) & 0xff;
  }
  return out;
}

final BigInt _l = (BigInt.one << 252) +
    BigInt.parse('27742317777372353535851937790883648493');

BigInt _leBig(List<int> b) =>
    b.reversed.fold(BigInt.zero, (n, x) => (n << 8) | BigInt.from(x));

Uint8List _bigLe32(BigInt n) => Uint8List.fromList(
    [for (var i = 0; i < 32; i++) ((n >> (8 * i)) & BigInt.from(0xff)).toInt()]);

/// A relay that answers the challenge as told, authenticates anyone,
/// records every frame after that from every socket, and answers what the
/// test says.
class ScriptedRelay {
  ScriptedRelay(this.server, this.challengeIk, this.readyIk);
  final HttpServer server;
  final Object? challengeIk;
  final String? readyIk;
  final frames = <Map<String, Object?>>[];
  final sockets = <WebSocket>[];
  final _arrived = StreamController<Map<String, Object?>>.broadcast();

  static Future<ScriptedRelay> start(
      {Object? challengeIk = 1, String? readyIk}) async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final relay = ScriptedRelay(server, challengeIk, readyIk);
    server.listen((req) async {
      final ws = await WebSocketTransformer.upgrade(req);
      relay.sockets.add(ws);
      ws.add(jsonEncode({
        't': 'challenge',
        'nonce': base64Encode(List<int>.filled(32, 7)),
        'auth': 2,
        if (challengeIk != null) 'ik': challengeIk,
      }));
      ws.listen((d) {
        final f = (jsonDecode(d as String) as Map).cast<String, Object?>();
        if (f['t'] == 'auth') {
          ws.add(jsonEncode(
              {'t': 'ready', 'id': 'x', if (readyIk != null) 'ik': readyIk}));
          return;
        }
        if (f['t'] == 'ping') return;
        relay.frames.add(f);
        relay._arrived.add(f);
      });
    });
    return relay;
  }

  Future<Map<String, Object?>> frame(String t) async {
    for (final f in frames) {
      if (f['t'] == t) return f;
    }
    return _arrived.stream.firstWhere((f) => f['t'] == t);
  }

  /// Resolves once [n] frames of type [t] have arrived.
  Future<void> holds(String t, int n) async {
    if (frames.where((f) => f['t'] == t).length >= n) return;
    await _arrived.stream
        .firstWhere((_) => frames.where((f) => f['t'] == t).length >= n);
  }

  /// Answers on the newest socket — the one the test just opened.
  void answer(Map<String, Object?> frame) => sockets.last.add(jsonEncode(frame));

  int get port => server.port;
  Future<void> close() => server.close(force: true);
}

void main() {
  late ZIdentity me;
  late Uint8List ek;
  late IntroKeyEntry entry;
  late String rid;

  setUpAll(() async {
    me = await ZIdentity.fromSeeds(edSeed: _seed(32, 0x11), xSeed: _seed(32, 0x12));
    ek = pqKeyPairFromSeed(_seed(64, 0x13)).$1;
    entry = await introKeyEntry(edSeed: me.edSeed, ek: ek);
    rid = await me.routingId();
  });

  test('1. iks: the mailbox key over the context, its own key and the key '
      'hash, under the one rule only', () async {
    final input = introKeySigningInput(me.edPub, ek);
    expect(input, [...utf8.encode('z-intro-key-v1:'), ...me.edPub, ..._sha256(ek)]);
    expect(input.length, 15 + 32 + 32);
    final plain = await Ed25519().sign(input, keyPair: me.edKeyPair);
    expect(entry.iks, plain.bytes, reason: 'RFC 8032, by the mailbox key');
    expect(await signIntroKey(edSeed: me.edSeed, ek: ek), entry.iks,
        reason: 'deterministic: one entry per device');
    expect(introKeySignatureValid(edPub: me.edPub, ek: ek, iks: entry.iks), isTrue);

    final other = await ZIdentity.fromSeeds(edSeed: _seed(32, 0x21), xSeed: _seed(32, 0x22));
    final (otherEk, _) = pqKeyPairFromSeed(_seed(64, 0x23));
    expect(introKeySignatureValid(edPub: other.edPub, ek: ek, iks: entry.iks), isFalse,
        reason: 'under another key');
    expect(introKeySignatureValid(edPub: me.edPub, ek: otherEk, iks: entry.iks), isFalse,
        reason: 'over another key');
    final sPlusL = Uint8List.fromList([
      ...entry.iks.sublist(0, 32),
      ..._bigLe32(_leBig(entry.iks.sublist(32)) + _l),
    ]);
    expect(introKeySignatureValid(edPub: me.edPub, ek: ek, iks: sPlusL), isFalse,
        reason: 'S + L: a lenient verifier takes it; §21.4 does not');
    final identityR = Uint8List(64)..[0] = 1;
    expect(introKeySignatureValid(edPub: me.edPub, ek: ek, iks: identityR), isFalse,
        reason: 'R the identity');
    expect(introKeySignatureValid(edPub: me.edPub, ek: ek, iks: entry.iks.sublist(0, 63)),
        isFalse, reason: 'a byte short');

    // What one strict verification costs, which a sender pays once per key it
    // fetches (the addendum estimated "a few ms in Dart").
    const n = 20;
    final sw = Stopwatch()..start();
    for (var i = 0; i < n; i++) {
      introKeySignatureValid(edPub: me.edPub, ek: ek, iks: entry.iks);
    }
    sw.stop();
    // ignore: avoid_print
    print('strict Ed25519 verification of an iks (with SHA-256 of the key): '
        '${(sw.elapsedMicroseconds / n / 1000).toStringAsFixed(2)} ms, mean of $n, JIT');
  });

  test('2. the entry is ek || iks, and its hint is the first 16 bytes of its hash',
      () {
    expect(entry.bytes.length, 1248);
    expect(entry.bytes, [...ek, ...entry.iks]);
    final back = IntroKeyEntry.fromBytes(entry.bytes)!;
    expect(back.ek, ek);
    expect(back.iks, entry.iks);
    expect(IntroKeyEntry.fromBytes(entry.bytes.sublist(0, 1247)), isNull);
    expect(IntroKeyEntry.fromBytes([...entry.bytes, 0]), isNull);
    expect(entry.hint, b64url(_sha256(entry.bytes).sublist(0, 16)));
    expect(entry.hint.length, 22);
    final other = IntroKeyEntry(ek, Uint8List.fromList(entry.iks)..[0] ^= 1);
    expect(other.hint, isNot(entry.hint), reason: 'a different entry, a different hint');
  });

  test('3. FIPS 203 §7.2: every keygen key passes; any coefficient at q, or '
      'any other length, fails; rho is not looked at', () {
    for (var i = 0; i < 8; i++) {
      final (k, _) = pqKeyPairFromSeed(_seed(64, 0x40 + i));
      expect(mlKemEncapsulationKeyValid(k), isTrue, reason: 'keygen $i');
    }
    expect(mlKemEncapsulationKeyValid(ek.sublist(0, 1183)), isFalse);
    expect(mlKemEncapsulationKeyValid([...ek, 0]), isFalse);
    expect(mlKemEncapsulationKeyValid(const []), isFalse);
    // Every one of the 768 coefficients, at q and at q - 1.
    var refused = 0;
    for (var i = 0; i < 768; i++) {
      if (!mlKemEncapsulationKeyValid(_withCoefficient(ek, i, 3329))) refused++;
      expect(mlKemEncapsulationKeyValid(_withCoefficient(ek, i, 3328)), isTrue,
          reason: 'coefficient $i at q - 1');
      expect(mlKemEncapsulationKeyValid(_withCoefficient(ek, i, 4095)), isFalse,
          reason: 'coefficient $i at 2^12 - 1');
    }
    expect(refused, 768, reason: 'coefficient at q refused at every position');
    // rho: the last 32 bytes, a seed, are any bytes at all.
    final rho = Uint8List.fromList(ek);
    for (var i = 1152; i < 1184; i++) {
      rho[i] = 0xff;
    }
    expect(mlKemEncapsulationKeyValid(rho), isTrue);
    // And the library's encapsulation agrees, key for key.
    bool encapsulates(Uint8List k) {
      try {
        pqEncapsulate(k, m: Uint8List(32));
        return true;
      } catch (_) {
        return false;
      }
    }

    for (final (k, why) in [
      (ek, 'genuine'),
      (_withCoefficient(ek, 0, 3329), 'first at q'),
      (_withCoefficient(ek, 767, 3329), 'last at q'),
      (_withCoefficient(ek, 400, 3328), 'q - 1'),
      (rho, 'rho'),
      (ek.sublist(0, 1183), 'short'),
    ]) {
      expect(encapsulates(k), mlKemEncapsulationKeyValid(k), reason: why);
    }
  });

  test('4. an introduction mailbox\'s key: HKDF of its seed as d || z, one per '
      'seed, apart from its X25519 key', () async {
    final introSeed = _seed(32, 0x51);
    final k = await handleIntroKem(introSeed);
    final okm = await Hkdf(hmac: Hmac.sha256(), outputLength: 64).deriveKey(
        secretKey: SecretKey(introSeed),
        nonce: utf8.encode('z-handle-intro-k-v1'),
        info: const <int>[]);
    expect(k.seed, await okm.extractBytes());
    final (e2, d2) = pqKeyPairFromSeed(k.seed);
    expect(k.ek, e2);
    expect(k.dk, d2);
    expect((await handleIntroKem(introSeed)).ek, k.ek, reason: 'one key per seed');
    expect((await handleIntroKem(_seed(32, 0x52))).ek, isNot(k.ek),
        reason: 'a new seed rotates it');
    expect(k.seed.sublist(0, 32), isNot(await handleIntroXSeed(introSeed)),
        reason: 'apart from the X25519 seed of the same mailbox');
    final (ct, secret) = pqEncapsulate(k.ek);
    expect(pqDecapsulate(k.seed, ct), secret, reason: 'it decapsulates');
    // Its entry is signed by the introduction key, whose hash is the mailbox.
    final intro = await handleIntroIdentity(introSeed);
    final e = await introKeyEntry(edSeed: introSeed, ek: k.ek);
    expect(
        checkServedIntroKey(
            rid: await introRoutingId(intro.edPub),
            edPub: intro.edPub,
            ek: e.ek,
            iks: e.iks),
        isNull);
    expect(() => handleIntroKem(Uint8List(31)), throwsArgumentError);
  });

  test('5. the acceptance rule: the genuine entry taken, each alteration '
      'refused for the check it breaks, sk binding the key', () async {
    IntroKeyRefusal? check(
            {String? r,
            Uint8List? ed,
            List<int>? k,
            List<int>? s,
            List<int>? sk}) =>
        checkServedIntroKey(
            rid: r ?? rid, edPub: ed ?? me.edPub, ek: k ?? ek, iks: s ?? entry.iks, sk: sk);
    expect(check(), isNull);
    expect(check(sk: sealKeyHash(ek)), isNull);
    expect(check(k: ek.sublist(0, 1183)), IntroKeyRefusal.keyLength);
    expect(check(s: entry.iks.sublist(0, 63)), IntroKeyRefusal.signatureLength);
    final bad = _withCoefficient(ek, 5, 3329);
    final badIks = await signIntroKey(edSeed: me.edSeed, ek: bad);
    expect(introKeySignatureValid(edPub: me.edPub, ek: bad, iks: badIks), isTrue,
        reason: 'signed by the genuine key, so only the modulus check stands between');
    expect(check(k: bad, s: badIks), IntroKeyRefusal.keyEncoding);
    final other = await ZIdentity.fromSeeds(edSeed: _seed(32, 0x61), xSeed: _seed(32, 0x62));
    expect(check(r: await other.routingId()), IntroKeyRefusal.wrongMailbox);
    final otherEntry = await introKeyEntry(edSeed: other.edSeed, ek: ek);
    expect(check(s: otherEntry.iks), IntroKeyRefusal.badSignature,
        reason: 'an iks under another ed');
    final (otherEk, _) = pqKeyPairFromSeed(_seed(64, 0x63));
    expect(check(k: otherEk), IntroKeyRefusal.badSignature,
        reason: 'an iks over another key');
    // The model's adversary forges iks at the fetch: without sk it is taken —
    // the residual — and a code's sk refuses it.
    final forged = await signIntroKey(edSeed: me.edSeed, ek: otherEk);
    expect(check(k: otherEk, s: forged), isNull);
    expect(check(k: otherEk, s: forged, sk: sealKeyHash(ek)),
        IntroKeyRefusal.notTheCodesKey);
  });

  test('6. sk in contact codes: emitted only when given, read on every path, '
      'refused without pqc or malformed, kept by a stored bundle', () async {
    final pq = await HybridKeyPair.fromSeeds(edSeed: me.edSeed, mlSeed: _seed(32, 0x71));
    final sk = sealKeyHash(ek);
    final plain = await ContactBundleV3.forIdentity(me, pq.publicKey, displayName: 'Finn');
    final withSk = await ContactBundleV3.forIdentity(me, pq.publicKey,
        displayName: 'Finn', sealKeyCommit: sk);
    expect(plain.sealKeyCommit, isNull);
    final plainJson = jsonDecode(utf8.decode(unb64url(plain.encode().substring(4)))) as Map;
    expect(plainJson.containsKey('sk'), isFalse, reason: 'not emitted unless given');
    final j = jsonDecode(utf8.decode(unb64url(withSk.encode().substring(4)))) as Map;
    expect(j.keys.toList(), ['v', 'ed', 'x', 'sig', 'pqc', 'pqcs', 'sk', 'name']);
    expect(unb64(j['sk'] as String), sk);
    final without = Map.of(j)..remove('sk');
    expect('zc1.${b64url(utf8.encode(jsonEncode(without)))}', plain.encode(),
        reason: 'the code without sk is the code before, byte for byte');
    // Every path that decodes a code.
    final scanned = await scanContactCode(withSk.encode());
    expect(scanned.sealKeyCommit, sk);
    expect((await ContactBundleV3.decode(withSk.encode())).sealKeyCommit, sk);
    expect((await scanContactCode(withSk.encodeStrict())).sealKeyCommit, sk);
    expect((await ContactBundle.decode(withSk.encode())).edPub, me.edPub,
        reason: 'the v1 decoder reads the identity and ignores sk');
    expect((await ConnectIdentity.fromCode(withSk.encode())).pqCommit, withSk.pqCommit);
    expect((await scanContactCode(plain.encode())).sealKeyCommit, isNull);
    // Refused.
    String edit(void Function(Map<String, Object?>) f) {
      final m = (jsonDecode(utf8.decode(unb64url(withSk.encode().substring(4)))) as Map)
          .cast<String, Object?>();
      f(m);
      return 'zc1.${b64url(utf8.encode(jsonEncode(m)))}';
    }

    for (final (code, why) in [
      (edit((m) => m..remove('pqc')..remove('pqcs')), 'sk without pqc'),
      (edit((m) => m['sk'] = b64(sk.sublist(0, 31))), 'sk 31 bytes'),
      (edit((m) => m['sk'] = b64([...sk, 0])), 'sk 33 bytes'),
      (edit((m) => m['sk'] = 7), 'sk not a string'),
    ]) {
      await expectLater(scanContactCode(code), throwsA(isA<FormatException>()),
          reason: why);
    }
    // A null member is an absent one, as it is for pqcs.
    expect((await scanContactCode(edit((m) => m['sk'] = null))).sealKeyCommit, isNull);
    expect(() => ContactBundleV3.forIdentity(me, pq.publicKey, sealKeyCommit: Uint8List(31)),
        throwsFormatException);
    // A stored bundle keeps it, and one stored before keeps none.
    final stored = ContactBundleV3.fromJson(withSk.toJson());
    expect(stored.sealKeyCommit, sk);
    expect(ContactBundleV3.fromJson(plain.toJson()).sealKeyCommit, isNull);
    expect(plain.toJson().containsKey('sk'), isFalse);
  });

  group('7. the relay client\'s frames', () {
    late ScriptedRelay relay;
    tearDown(() => relay.close());

    test('7. ik and ready.ik read; ikey and ikey_get on the right connection '
        'only, answered, refused and closed', () async {
      relay = await ScriptedRelay.start(readyIk: entry.hint);
      final url = 'ws://127.0.0.1:${relay.port}';
      final authed = await RelayClient.connect(url, me);
      expect(authed.relayKeepsIntroKeys, isTrue);
      expect(authed.readyIntroKeyHint, entry.hint);
      final anon = await RelayClient.connectAnonymous(url, me);
      expect(anon.relayKeepsIntroKeys, isTrue, reason: 'read on an anonymous connection too');
      expect(anon.readyIntroKeyHint, isNull);

      // Publishing: on the authenticated connection, exactly §12.7's frame.
      expect(() => anon.publishIntroKey(entry), throwsStateError);
      final published = authed.publishIntroKey(entry);
      final f = await relay.frame('ikey');
      expect(f, {'t': 'ikey', 'ek': b64(entry.ek), 'iks': b64(entry.iks)});
      var done = false;
      unawaited(published.then((_) => done = true));
      // A round trip on the same socket: had the frame been taken as done
      // when it left, it would be by the time the relay holds the barrier.
      authed.ackReceived(id: 'barrier', from: '');
      await relay.frame('recv');
      expect(done, isFalse, reason: 'done only on ikey_ok');
      relay.sockets.first.add(jsonEncode({'t': 'ikey_ok'}));
      await published;
      final refused = authed.publishIntroKey(entry);
      relay.sockets.first.add(jsonEncode({'t': 'error', 'code': relayErrorBadIkey}));
      await expectLater(refused,
          throwsA(isA<RelayException>().having((e) => e.message, 'message', 'bad_ikey')));

      // Fetching: on the anonymous connection, the frame names the mailbox.
      expect(() => authed.ikeyGet(rid), throwsStateError);
      final got = anon.ikeyGet(rid);
      expect(await relay.frame('ikey_get'), {'t': 'ikey_get', 'to': rid});
      relay.answer({'t': 'ikey_for', 'to': rid, 'ek': b64(entry.ek), 'iks': b64(entry.iks)});
      final a = await got;
      expect(a.held, isTrue);
      expect(a.ek, entry.ek);
      expect(a.iks, entry.iks);
      final none = anon.ikeyGet(rid);
      relay.answer({'t': 'ikey_for', 'to': rid});
      final n = await none;
      expect(n.held, isFalse);
      expect(n.malformed, isFalse);
      final half = anon.ikeyGet(rid);
      relay.answer({'t': 'ikey_for', 'to': rid, 'ek': b64(entry.ek)});
      expect((await half).malformed, isTrue, reason: 'one half is no answer a relay may give');
      final anonOnly = anon.ikeyGet(rid);
      relay.answer({'t': 'error', 'code': relayErrorAnonOnly});
      await expectLater(anonOnly,
          throwsA(isA<RelayException>().having((e) => e.message, 'message', 'anon_only')));
      final closing = anon.ikeyGet(rid);
      await relay.holds('ikey_get', 5); // it reached the relay, then the socket goes
      await relay.sockets.last.close();
      await expectLater(closing,
          throwsA(isA<RelayException>().having((e) => e.message, 'message', 'connection closed')));

      // Nothing published or fetched on the wrong connection reached the relay.
      expect(relay.frames.where((x) => x['t'] == 'ikey').length, 2);
      expect(relay.frames.where((x) => x['t'] == 'ikey_get').length, 5);
      expect(relay.frames.where((x) => x['t'] == 'recv').length, 1);
      await authed.close();
      await anon.close();
    });

    test('7. a relay whose challenge does not say ik:1 is sent neither frame',
        () async {
      relay = await ScriptedRelay.start(challengeIk: null);
      final url = 'ws://127.0.0.1:${relay.port}';
      final authed = await RelayClient.connect(url, me);
      final anon = await RelayClient.connectAnonymous(url, me);
      expect(authed.relayKeepsIntroKeys, isFalse);
      expect(anon.relayKeepsIntroKeys, isFalse);
      expect(authed.readyIntroKeyHint, isNull);
      expect(() => authed.publishIntroKey(entry), throwsStateError);
      expect(() => anon.ikeyGet(rid), throwsStateError);
      // A barrier: frames leave in order, so either would be here first.
      authed.ackReceived(id: 'barrier', from: '');
      await relay.frame('recv');
      expect(relay.frames.map((x) => x['t']), ['recv']);
      await authed.close();
      await anon.close();
    });
  });
}
