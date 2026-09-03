// Test-vector generator for the Z protocol (Phase 5.1 — audit prep).
//
// Produces the JSON documents under `docs/vectors/v1/`. Everything here is
// driven through the PUBLIC library API with all randomness replaced by a
// seeded, fully-specified DRBG (splitmix64), so the files are reproducible
// bit-for-bit and every "random" value (ephemeral seeds, nonces, ids) is
// recorded alongside the outputs it produced. A third party can therefore
// replay each vector with their own implementation from the inputs alone.
//
// Where this file recomputes intermediate values (shared secrets, chain keys,
// message keys) it does so with the `cryptography` package primitives and
// ASSERTS that the library's observable state agrees — so the generator is
// also a conformance check of the library against the formulas in
// docs/PROTOCOL.md. The independent check is `server/test/vectors.test.js`,
// which re-derives every vector with Node's crypto and no shared code.
//
// Usage: `dart run tool/gen_vectors.dart` (from protocol/). The regression lock
// `test/vectors_test.dart` regenerates in-memory and diffs against the files.

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:z_protocol/src/util.dart'
    show concatBytes, pad, randomOverrideKey;
import 'package:z_protocol/z_protocol.dart';

const int vectorsVersion = 1;

// ---------------------------------------------------------------------------
// Deterministic randomness (splitmix64) — every draw is recorded.
// ---------------------------------------------------------------------------

class Drbg {
  int _state;
  final List<Uint8List> draws = [];
  Drbg(int seed) : _state = seed;

  int _next64() {
    _state += 0x9E3779B97F4A7C15;
    var z = _state;
    z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9;
    z = (z ^ (z >>> 27)) * 0x94D049BB133111EB;
    return z ^ (z >>> 31);
  }

  Uint8List next(int n) {
    final out = Uint8List(n);
    var i = 0;
    while (i < n) {
      var w = _next64();
      for (var k = 0; k < 8 && i < n; k++, i++) {
        out[i] = w & 0xff;
        w >>>= 8;
      }
    }
    draws.add(out);
    return out;
  }

  /// Run [body] with every protocol random draw served by this DRBG.
  Future<T> run<T>(Future<T> Function() body) =>
      runZoned(body, zoneValues: {randomOverrideKey: next});

  /// Take the draws made since the last call (and forget them).
  List<Uint8List> takeDraws() {
    final d = List<Uint8List>.from(draws);
    draws.clear();
    return d;
  }
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

String hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

Uint8List unhex(String s) => Uint8List.fromList([
      for (var i = 0; i < s.length; i += 2)
        int.parse(s.substring(i, i + 2), radix: 16)
    ]);

Uint8List utf8b(String s) => Uint8List.fromList(utf8.encode(s));

void check(bool ok, String what) {
  if (!ok) throw StateError('generator self-check failed: $what');
}

bool eq(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Reference primitives (cryptography package) used to expose intermediates
// ---------------------------------------------------------------------------

final _x = X25519();
final _ed = Ed25519();

Future<Uint8List> refXPub(Uint8List seed) async => Uint8List.fromList(
    (await (await _x.newKeyPairFromSeed(seed)).extractPublicKey()).bytes);

Future<Uint8List> refEdPub(Uint8List seed) async => Uint8List.fromList(
    (await (await _ed.newKeyPairFromSeed(seed)).extractPublicKey()).bytes);

Future<Uint8List> refDh(Uint8List seed, Uint8List pub) async {
  final s = await _x.sharedSecretKey(
    keyPair: await _x.newKeyPairFromSeed(seed),
    remotePublicKey: SimplePublicKey(pub, type: KeyPairType.x25519),
  );
  return Uint8List.fromList(await s.extractBytes());
}

Future<Uint8List> refHkdf(
    Uint8List ikm, List<int> salt, List<int> info, int len) async {
  final k = await Hkdf(hmac: Hmac.sha256(), outputLength: len)
      .deriveKey(secretKey: SecretKey(ikm), nonce: salt, info: info);
  return Uint8List.fromList(await k.extractBytes());
}

Future<Uint8List> refHmac(Uint8List key, List<int> data) async =>
    Uint8List.fromList(
        (await Hmac.sha256().calculateMac(data, secretKey: SecretKey(key)))
            .bytes);

Future<Uint8List> refSha256(List<int> data) async =>
    Uint8List.fromList((await Sha256().hash(data)).bytes);

Future<Uint8List> refEdSign(Uint8List seed, List<int> msg) async =>
    Uint8List.fromList(
        (await _ed.sign(msg, keyPair: await _ed.newKeyPairFromSeed(seed)))
            .bytes);

/// KDF_RK exactly as specified: HKDF(secret=dh, salt=rk, info="Z-RK-v1", 64).
Future<(Uint8List, Uint8List)> refKdfRk(Uint8List rk, Uint8List dh) async {
  final out = await refHkdf(dh, rk, utf8.encode('Z-RK-v1'), 64);
  return (out.sublist(0, 32), out.sublist(32));
}

/// KDF_CK exactly as specified: (HMAC(ck,0x01), HMAC(ck,0x02)).
Future<(Uint8List, Uint8List)> refKdfCk(Uint8List ck) async =>
    (await refHmac(ck, const [0x01]), await refHmac(ck, const [0x02]));

// ---------------------------------------------------------------------------
// Fixed actors
// ---------------------------------------------------------------------------

class Actor {
  final String name;
  final String displayName;
  final ZIdentity id;
  final String rid;
  Actor(this.name, this.displayName, this.id, this.rid);
}

Future<List<Actor>> actors() async {
  final d = Drbg(0x0001);
  final out = <Actor>[];
  for (final (name, display) in [
    ('alice', 'Alice'),
    ('bob', 'Bob'),
    ('carol', 'Carol'),
  ]) {
    final id = await ZIdentity.fromSeeds(edSeed: d.next(32), xSeed: d.next(32));
    out.add(Actor(name, display, id, await id.routingId()));
  }
  return out;
}

Map<String, Object?> ratchetStateJson(RatchetState s) => {
      'root_key': hex(s.rootKey),
      'dhs_seed': hex(s.dhsSeed),
      'dhs_pub': hex(s.dhsPub),
      'dhr_pub': s.dhrPub == null ? null : hex(s.dhrPub!),
      'cks': s.cks == null ? null : hex(s.cks!),
      'ckr': s.ckr == null ? null : hex(s.ckr!),
      'ns': s.ns,
      'nr': s.nr,
      'pn': s.pn,
      'skipped': {
        for (final e in s.skipped.entries)
          e.key: hex(base64Decode(e.value)) // "b64(dh)|n" -> mk
      },
    };

// ---------------------------------------------------------------------------
// Suites
// ---------------------------------------------------------------------------

Future<Map<String, Object?>> suiteIdentity(List<Actor> a) async {
  final vectors = <Map<String, Object?>>[];
  for (final x in a) {
    final bindMsg = concatBytes([utf8.encode('z-bind-v1:'), x.id.xPub]);
    final sig = await x.id.bindingSignature();
    check(eq(sig, await refEdSign(x.id.edSeed, bindMsg)), 'binding sig');
    check(eq(await refEdPub(x.id.edSeed), x.id.edPub), 'ed pub');
    check(eq(await refXPub(x.id.xSeed), x.id.xPub), 'x pub');
    check(b64url(await refSha256(x.id.edPub)) == x.rid, 'routing id');
    final bundle = await x.id.bundle(displayName: x.displayName);
    final code = bundle.encode();
    check((await ContactBundle.decode(code)).displayName == x.displayName,
        'contact code round trip');
    vectors.add({
      'name': x.name,
      'display_name': x.displayName,
      'ed_seed': hex(x.id.edSeed),
      'x_seed': hex(x.id.xSeed),
      'ed_pub': hex(x.id.edPub),
      'x_pub': hex(x.id.xPub),
      'routing_id': x.rid,
      'binding_message': hex(bindMsg),
      'binding_sig': hex(sig),
      'contact_code_json':
          utf8.decode(base64Url.decode(base64Url.normalize(code.substring(4)))),
      'contact_code': code,
    });
  }

  final safety = <Map<String, Object?>>[];
  for (final (p, q) in [(a[0], a[1]), (a[1], a[0]), (a[0], a[2])]) {
    final sn = await safetyNumber(p.id.edPub, q.id.edPub);
    final lo = hex(p.id.edPub).compareTo(hex(q.id.edPub)) < 0 ? p : q;
    final hi = identical(lo, p) ? q : p;
    final okm = await refHkdf(concatBytes([lo.id.edPub, hi.id.edPub]),
        utf8.encode('z-safety-v1'), utf8.encode('display'), 60);
    safety.add({
      'a': p.name,
      'b': q.name,
      'lo_ed_pub': hex(lo.id.edPub),
      'hi_ed_pub': hex(hi.id.edPub),
      'hkdf_okm': hex(okm),
      'safety_number': sn,
    });
  }
  check(safety[0]['safety_number'] == safety[1]['safety_number'],
      'safety number symmetric');

  final d = Drbg(0x0011);
  final auth = <Map<String, Object?>>[];
  for (final x in a.take(2)) {
    final nonce = d.next(32);
    final sig = await x.id.signAuthChallenge(nonce);
    final msg = concatBytes([utf8.encode('z-relay-auth-v1:'), nonce]);
    check(eq(sig, await refEdSign(x.id.edSeed, msg)), 'auth sig');
    auth.add({
      'identity': x.name,
      'challenge_frame': {'t': 'challenge', 'nonce': base64Encode(nonce)},
      'nonce': hex(nonce),
      'signed_message': hex(msg),
      'sig': hex(sig),
      'auth_frame': {
        't': 'auth',
        'pub': base64Encode(x.id.edPub),
        'sig': base64Encode(sig)
      },
      'ready_frame': {'t': 'ready', 'id': x.rid},
    });
  }

  return {
    'suite': 'identity',
    'version': vectorsVersion,
    'description':
        'Ed25519/X25519 identities from seeds, routing ids, the X25519 '
            'binding signature, zc1. contact codes, safety numbers and the relay '
            'auth challenge/response.',
    'identities': vectors,
    'safety_numbers': safety,
    'relay_auth': auth,
  };
}

Future<Map<String, Object?>> suiteHandshake(List<Actor> a) async {
  // Recompute X3DH explicitly; the ratchet suite proves the library derives
  // the same SK (its initiator root key is KDF_RK(sk, ...)).
  final alice = a[0], bob = a[1];
  final d = Drbg(0x0002);
  final ekSeed = d.next(32);
  final ekPub = await refXPub(ekSeed);
  final dh1 = await refDh(alice.id.xSeed, bob.id.xPub);
  final dh2 = await refDh(ekSeed, bob.id.xPub);
  check(eq(dh1, await refDh(bob.id.xSeed, alice.id.xPub)), 'dh1 mirror');
  check(eq(dh2, await refDh(bob.id.xSeed, ekPub)), 'dh2 mirror');
  final ikm = concatBytes([Uint8List(32)..fillRange(0, 32, 0xff), dh1, dh2]);
  final sk = await refHkdf(ikm, Uint8List(32), utf8.encode('Z-X3DH-v1'), 32);
  final adInput =
      concatBytes([utf8.encode('Z-AD-v1'), alice.id.edPub, bob.id.edPub]);
  final ad = await refSha256(adInput);
  final sid = await sessionIdFromEk(ekPub);
  check(sid == b64url(await refSha256(ekPub)).substring(0, 22), 'sid');
  return {
    'suite': 'handshake',
    'version': vectorsVersion,
    'description':
        'X3DH-style session establishment (no server prekeys): the responder\'s '
            'identity X25519 key stands in for the signed prekey.',
    'initiator': alice.name,
    'responder': bob.name,
    'ek_seed': hex(ekSeed),
    'ek_pub': hex(ekPub),
    'dh1': hex(dh1),
    'dh2': hex(dh2),
    'ikm': hex(ikm),
    'hkdf_salt': hex(Uint8List(32)),
    'hkdf_info': 'Z-X3DH-v1',
    'sk': hex(sk),
    'ad_input': hex(adInput),
    'ad': hex(ad),
    'sid': sid,
  };
}

Future<Map<String, Object?>> suiteRatchet(List<Actor> a) async {
  final alice = a[0], bob = a[1];
  final d = Drbg(0x0003);
  final convA = await Conversation.create(
      alice.id, await bob.id.bundle(displayName: bob.displayName));
  final convB = await Conversation.create(
      bob.id, await alice.id.bundle(displayName: alice.displayName));

  final steps = <Map<String, Object?>>[];
  final transcript = <Map<String, Object?>>[];
  Map<String, Object?>? init;
  Map<String, Object?>? handshake;

  Future<Map<String, Object?>> encryptStep({
    required String label,
    required Conversation conv,
    required String sender,
    required InnerMessage inner,
  }) async {
    final plaintext = inner.toBytes();
    final sidBefore = conv.outboundSid;
    final before =
        sidBefore == null ? null : conv.sessions[sidBefore]!.ratchet.clone();
    final payload = await d.run(() => conv.encrypt(plaintext, nowMs: 1));
    final draws = d.takeDraws();
    final sid = conv.outboundSid!;
    final session = conv.sessions[sid]!;
    final after = session.ratchet;
    final j = jsonDecode(utf8.decode(base64Decode(payload))) as Map;
    final header = (j['h'] as Map).cast<String, Object?>();
    final headerBytes = RatchetHeader.fromJson(header).encode();
    final nonce = base64Decode(j['n'] as String);
    final ct = base64Decode(j['ct'] as String);
    final mac = base64Decode(j['mac'] as String);

    Uint8List ckBefore;
    if (before == null) {
      // First message on a brand-new session: draws are ekSeed, dhsSeed, nonce.
      check(draws.length == 3, 'draw count on session creation');
      final ekSeed = draws[0], dhsSeed = draws[1];
      check(eq(await refXPub(ekSeed), session.ekPub), 'ek seed labelling');
      check(eq(dhsSeed, after.dhsSeed), 'dhs seed labelling');
      check(eq(draws[2], nonce), 'nonce labelling');
      // Recompute the handshake + initial ratchet state from scratch.
      final dh1 = await refDh(alice.id.xSeed, bob.id.xPub);
      final dh2 = await refDh(ekSeed, bob.id.xPub);
      final sk = await refHkdf(
          concatBytes([Uint8List(32)..fillRange(0, 32, 0xff), dh1, dh2]),
          Uint8List(32),
          utf8.encode('Z-X3DH-v1'),
          32);
      final ad = await refSha256(
          concatBytes([utf8.encode('Z-AD-v1'), alice.id.edPub, bob.id.edPub]));
      check(eq(ad, after.ad), 'ad');
      final dhOut = await refDh(dhsSeed, bob.id.xPub);
      final (rk, cks) = await refKdfRk(sk, dhOut);
      check(eq(rk, after.rootKey), 'initiator root key == KDF_RK(sk, dh)');
      ckBefore = cks;
      handshake = {
        'ek_seed': hex(ekSeed),
        'ek_pub': hex(session.ekPub),
        'dh1': hex(dh1),
        'dh2': hex(dh2),
        'sk': hex(sk),
        'ad': hex(ad),
        'sid': sid,
      };
      init = {
        'dhs_seed': hex(dhsSeed),
        'dhs_pub': hex(after.dhsPub),
        'dh_out': hex(dhOut),
        'root_key': hex(rk),
        'cks': hex(cks),
      };
    } else {
      check(draws.length == 1 && eq(draws[0], nonce), 'nonce draw');
      ckBefore = before.cks!;
    }
    final (mk, ckAfter) = await refKdfCk(ckBefore);
    check(eq(ckAfter, after.cks!), 'chain key advance');
    final padded = pad(plaintext);
    final aad = concatBytes([after.ad, headerBytes]);
    // Independent AEAD check of the library's ciphertext.
    final box = await Xchacha20.poly1305Aead()
        .encrypt(padded, secretKey: SecretKey(mk), nonce: nonce, aad: aad);
    check(eq(box.cipherText, ct) && eq(box.mac.bytes, mac), 'aead');

    transcript.add({'op': 'encrypt', 'mid': inner.mid, 'by': sender});
    final step = <String, Object?>{
      'mid': inner.mid,
      'label': label,
      'sender': sender,
      'sid': sid,
      'inner_json': utf8.decode(plaintext),
      'plaintext': hex(plaintext),
      'padded': hex(padded),
      'ck_before': hex(ckBefore),
      'mk': hex(mk),
      'ck_after': hex(ckAfter),
      'header': header,
      'header_bytes': hex(headerBytes),
      'aad': hex(aad),
      'nonce': hex(nonce),
      'ciphertext': hex(ct),
      'mac': hex(mac),
      'ek_attached': j.containsKey('ek'),
      'random_draws': [for (final x in draws) hex(x)],
      'payload_json': utf8.decode(base64Decode(payload)),
      'payload': payload,
      'sender_state_after': ratchetStateJson(after),
    };
    steps.add(step);
    return step;
  }

  Future<void> decryptStep({
    required Map<String, Object?> step,
    required Conversation conv,
    required String receiver,
  }) async {
    final payload = step['payload'] as String;
    final sid = step['sid'] as String;
    final before = conv.sessions[sid]?.ratchet.clone();
    final res = await d.run(() => conv.decrypt(payload, nowMs: 2));
    final draws = d.takeDraws();
    final after = conv.sessions[sid]!.ratchet;
    check(hex(res.plaintext) == step['plaintext'], 'plaintext round trip');
    final recv = <String, Object?>{
      'receiver': receiver,
      'created_session': res.createdNewSession,
      'random_draws': [for (final x in draws) hex(x)],
      'state_before': before == null ? null : ratchetStateJson(before),
    };
    transcript.add({'op': 'decrypt', 'mid': step['mid'], 'by': receiver});
    final headerDh = Uint8List.fromList(
        base64Decode((step['header'] as Map)['dh'] as String));
    final sameDh = before?.dhrPub != null && eq(before!.dhrPub!, headerDh);
    if (!sameDh) {
      // DH ratchet step: exactly one draw (the new sending ratchet seed).
      check(draws.length == 1, 'dh step draws');
      final newSeed = draws[0];
      check(eq(newSeed, after.dhsSeed), 'new dhs seed');
      final rk0 = before?.rootKey ?? unhex(handshake!['sk'] as String);
      final dhsSeed0 = before?.dhsSeed ?? conv.me.xSeed;
      final dhRecv = await refDh(dhsSeed0, headerDh);
      final (rk1, ckr) = await refKdfRk(rk0, dhRecv);
      final dhSend = await refDh(newSeed, headerDh);
      final (rk2, cks) = await refKdfRk(rk1, dhSend);
      check(eq(rk2, after.rootKey) && eq(cks, after.cks!), 'dh step result');
      recv['dh_ratchet_step'] = {
        'root_key_in': hex(rk0),
        'dhs_seed_in': hex(dhsSeed0),
        'their_dh_pub': hex(headerDh),
        'dh_recv': hex(dhRecv),
        'root_key_1': hex(rk1),
        'ckr': hex(ckr),
        'new_dhs_seed': hex(newSeed),
        'new_dhs_pub': hex(after.dhsPub),
        'dh_send': hex(dhSend),
        'root_key_2': hex(rk2),
        'cks': hex(cks),
      };
    } else {
      check(draws.isEmpty, 'no draws on plain receive');
      recv['dh_ratchet_step'] = null;
    }
    recv['state_after'] = ratchetStateJson(after);
    step['receive'] = recv;
  }

  final ts = 1700000000000;
  // 1. Alice opens the session with a silent hello (ek attached).
  final s1 = await encryptStep(
      label: 'm1 A->B hello (opens session, ek attached)',
      conv: convA,
      sender: 'alice',
      inner: InnerMessage.hello('m1', ts));
  await decryptStep(step: s1, conv: convB, receiver: 'bob');
  // 2. Alice sends text before any reply (ek still attached).
  final s2 = await encryptStep(
      label: 'm2 A->B text (no reply yet, ek still attached)',
      conv: convA,
      sender: 'alice',
      inner: InnerMessage.text('m2', ts + 1, 'hello bob', ttlSec: 0));
  await decryptStep(step: s2, conv: convB, receiver: 'bob');
  // 3. Bob replies (his DH step happened on m1; Alice steps on receipt).
  final s3 = await encryptStep(
      label: 'm3 B->A text (first reply; Alice performs a DH ratchet step)',
      conv: convB,
      sender: 'bob',
      inner: InnerMessage.text('m3', ts + 2, 'hi alice', ttlSec: 86400));
  await decryptStep(step: s3, conv: convA, receiver: 'alice');
  // 4–6. Alice sends three on her new chain; Bob gets m4, then m6 before m5.
  final s4 = await encryptStep(
      label: 'm4 A->B text (new sending chain, ek no longer attached)',
      conv: convA,
      sender: 'alice',
      inner: InnerMessage.text('m4', ts + 3, 'one'));
  final s5 = await encryptStep(
      label: 'm5 A->B text (delivered LAST: exercises skipped-key cache)',
      conv: convA,
      sender: 'alice',
      inner: InnerMessage.text('m5', ts + 4, 'two'));
  final s6 = await encryptStep(
      label: 'm6 A->B text (delivered before m5)',
      conv: convA,
      sender: 'alice',
      inner: InnerMessage.text('m6', ts + 5, 'three'));
  await decryptStep(step: s4, conv: convB, receiver: 'bob');
  await decryptStep(step: s6, conv: convB, receiver: 'bob');
  await decryptStep(step: s5, conv: convB, receiver: 'bob');
  check(convB.sessions.length == 1 && convA.sessions.length == 1,
      'single session');

  return {
    'suite': 'ratchet',
    'version': vectorsVersion,
    'description':
        'A complete Double Ratchet transcript between alice (initiator) and bob '
            '(responder) driven through Conversation.encrypt/decrypt, including '
            'both DH ratchet steps and an out-of-order delivery. States are the '
            'library\'s RatchetState after each operation; every random draw is '
            'recorded.',
    'initiator': alice.name,
    'responder': bob.name,
    'designated_initiator_by_rid_order':
        convA.isDesignatedInitiator ? alice.name : bob.name,
    'handshake': handshake,
    'initiator_init': init,
    'transcript': transcript,
    'steps': steps,
  };
}

Future<Map<String, Object?>> suiteSealed(List<Actor> a) async {
  final alice = a[0], bob = a[1], carol = a[2];
  final d = Drbg(0x0004);
  final vectors = <Map<String, Object?>>[];
  final payloads = <(String, String)>[
    ('short', 'ratchet-ciphertext-placeholder'),
    (
      'bucket_1024_exact_fit',
      'A' * (1024 - 4 - '{"f":"","p":""}'.length - alice.rid.length)
    ),
    (
      'bucket_4096_by_one_byte',
      'B' * (1024 - 4 - '{"f":"","p":""}'.length - alice.rid.length + 1)
    ),
    ('bucket_16384', 'C' * 6000),
  ];
  for (final (name, payload) in payloads) {
    final blob = await d.run(() => SealedEnvelope.seal(
        toXPub: bob.id.xPub, fromRid: alice.rid, payload: payload));
    final draws = d.takeDraws();
    check(draws.length == 2, 'sealed draws');
    final ephSeed = draws[0], nonce = draws[1];
    final raw = Uint8List.fromList(
        base64Url.decode(base64Url.normalize(blob.substring(4))));
    final ephPub = raw.sublist(0, 32);
    check(eq(ephPub, await refXPub(ephSeed)), 'eph seed labelling');
    check(eq(raw.sublist(32, 44), nonce), 'nonce labelling');
    final ct = raw.sublist(44, raw.length - 16);
    final mac = raw.sublist(raw.length - 16);
    final shared = await refDh(ephSeed, bob.id.xPub);
    check(eq(shared, await refDh(bob.id.xSeed, ephPub)), 'shared mirror');
    final info = concatBytes([utf8.encode('z-sealed-v1'), ephPub, bob.id.xPub]);
    final key = await refHkdf(shared, Uint8List(0), info, 32);
    final innerJson = jsonEncode({'f': alice.rid, 'p': payload});
    final plainLen = utf8.encode(innerJson).length;
    final bucket = sealedBuckets.firstWhere((b) => b >= plainLen + 4);
    check(ct.length == bucket, 'bucket size');
    final opened = await SealedEnvelope.open(
        myXSeed: bob.id.xSeed, myXPub: bob.id.xPub, blob: blob);
    check(
        opened != null &&
            opened.fromRid == alice.rid &&
            opened.payload == payload,
        'open');
    check(
        await SealedEnvelope.open(
                myXSeed: carol.id.xSeed, myXPub: carol.id.xPub, blob: blob) ==
            null,
        'wrong recipient');
    vectors.add({
      'name': name,
      'to': bob.name,
      'to_x_seed': hex(bob.id.xSeed),
      'to_x_pub': hex(bob.id.xPub),
      'from_rid': alice.rid,
      'payload_len': payload.length,
      'payload': payload,
      'inner_json': innerJson,
      'inner_len': plainLen,
      'bucket': bucket,
      'eph_seed': hex(ephSeed),
      'eph_pub': hex(ephPub),
      'shared': hex(shared),
      'hkdf_info': hex(info),
      'key': hex(key),
      'nonce': hex(nonce),
      'aad': 'z-sealed-v1',
      'ciphertext_sha256': hex(await refSha256(ct)),
      'mac': hex(mac),
      'envelope': blob,
      'wrong_recipient': carol.name,
    });
  }
  return {
    'suite': 'sealed_sender',
    'version': vectorsVersion,
    'description':
        'Sealed-sender envelopes (zs1.): ephemeral X25519 -> HKDF-SHA256 -> '
            'ChaCha20-Poly1305 over a size-bucketed {f,p} JSON. The relay never '
            'sees a sender. ciphertext_sha256 is provided because the ciphertext '
            'itself is inside `envelope`.',
    'buckets': sealedBuckets,
    'vectors': vectors,
  };
}

Future<Map<String, Object?>> suiteAttachments(List<Actor> a) async {
  final d = Drbg(0x0005);
  final km = await d.run(() async => FileKeyMaterial.generate());
  final draws = d.takeDraws();
  check(draws.length == 3 && km.fid == b64url(draws[0]), 'fid draw');
  final chunks = <Map<String, Object?>>[];
  for (final (index, plain) in [
    (0, Uint8List.fromList(List.generate(100, (i) => i & 0xff))),
    (1, Uint8List(0)),
    (4294967301, Uint8List.fromList(utf8.encode('Z' * 64))),
  ]) {
    final payload = await encryptChunk(km, index, plain);
    final j = jsonDecode(utf8.decode(base64Decode(payload))) as Map;
    final nonce = chunkNonce(km.fn, index);
    final aad = 'z-file-v1:${km.fid}';
    final parsed = tryParseChunk(payload)!;
    final back =
        await decryptChunk(fk: km.fk, fn: km.fn, fid: km.fid, chunk: parsed);
    check(eq(back, plain), 'chunk round trip');
    chunks.add({
      'index': index,
      'plaintext': hex(plain),
      'nonce': hex(nonce),
      'aad': aad,
      'ciphertext': hex(base64Decode(j['ct'] as String)),
      'mac': hex(base64Decode(j['mac'] as String)),
      'payload_json': utf8.decode(base64Decode(payload)),
      'payload': payload,
    });
  }
  final file = Uint8List.fromList(List.generate(1000, (i) => (i * 31) & 0xff));
  return {
    'suite': 'attachments',
    'version': vectorsVersion,
    'description':
        'Attachment chunks: XChaCha20-Poly1305 under the per-file key with '
            'nonce = fn(16) || uint64le(index), aad = "z-file-v1:" || fid. The '
            'file offer (inner kind "file") carries fk/fn/fid inside the ratchet.',
    'fid': km.fid,
    'fid_bytes': hex(draws[0]),
    'fk': hex(km.fk),
    'fn': hex(km.fn),
    'chunks': chunks,
    'split_example': {
      'file_len': file.length,
      'chunk_size': 400,
      'chunk_lens': [
        for (final c in splitChunks(file, chunkSize: 400)) c.length
      ],
      'file_sha256': hex(await refSha256(file)),
    },
  };
}

Future<Map<String, Object?>> suiteMultidevice(List<Actor> a) async {
  final d = Drbg(0x0006);
  final me = await d.run(() => AccountIdentity.generate());
  final draws = d.takeDraws();
  check(draws.length == 3 && eq(draws[0], me.accountEdSeed!), 'account seed');
  final dev2EdSeed = d.next(32), dev2XSeed = d.next(32);
  final dev2EdPub = await refEdPub(dev2EdSeed);
  final dev2XPub = await refXPub(dev2XSeed);
  const dev2Id = 'second-device';
  final cert2 = await me.signDeviceCert(
      deviceEdPub: dev2EdPub, deviceXPub: dev2XPub, deviceId: dev2Id);
  check(await cert2.verify(me.accountEdPub), 'cert2 verifies');
  final in1 = DeviceCertificate.signingInput(
      me.deviceEdPub, me.deviceXPub, me.deviceId);
  final in2 = DeviceCertificate.signingInput(dev2EdPub, dev2XPub, dev2Id);
  check(
      eq(me.deviceCert.sig, await refEdSign(me.accountEdSeed!, in1)), 'cert1');
  check(eq(cert2.sig, await refEdSign(me.accountEdSeed!, in2)), 'cert2');
  final bundle =
      me.toAccountBundle(displayName: 'Alice', otherDevices: [cert2]);
  final code = bundle.encode();
  check((await AccountBundle.decode(code)).devices.length == 2, 'zc2 decode');
  // Deliberately pass the devices in non-sorted order: the signing input
  // sorts device Ed25519 keys lexicographically.
  final list = await me.signDeviceList([cert2, me.deviceCert], 3);
  check(await list.verify(), 'device list verifies');
  final listInput = SignedDeviceList.signingInput(3, [cert2, me.deviceCert]);
  check(
      eq(list.sig, await refEdSign(me.accountEdSeed!, listInput)), 'list sig');
  // Legacy: a zc1. code reads as a one-device account.
  final legacy = await AccountBundle.decode(
      (await a[1].id.bundle(displayName: 'Bob')).encode());

  Future<Map<String, Object?>> certJson(
          DeviceCertificate c, Uint8List input) async =>
      {
        'device_ed_pub': hex(c.deviceEdPub),
        'device_x_pub': hex(c.deviceXPub),
        'device_id': c.deviceId,
        'routing_id': await c.routingId(),
        'signing_input': hex(input),
        'sig': hex(c.sig),
        'json': c.toJson(),
      };
  final c1 = await certJson(me.deviceCert, in1);
  final c2 = await certJson(cert2, in2);

  return {
    'suite': 'multidevice',
    'version': vectorsVersion,
    'description':
        'Account key (Ed25519 trust root), device certificates, zc2. account '
            'codes and account-signed device lists. Device #1\'s Ed25519 key IS '
            'the account key (so a one-device account matches the v1 shape).',
    'account_ed_seed': hex(me.accountEdSeed!),
    'account_ed_pub': hex(me.accountEdPub),
    'account_id': await me.accountId(),
    'device1': {
      'ed_seed': hex(me.deviceEdSeed),
      'x_seed': hex(me.deviceXSeed),
      'device_id_bytes': hex(draws[2]),
      ...c1,
    },
    'device2': {
      'ed_seed': hex(dev2EdSeed),
      'x_seed': hex(dev2XSeed),
      ...c2,
    },
    'account_code_json':
        utf8.decode(base64Url.decode(base64Url.normalize(code.substring(4)))),
    'account_code': code,
    'device_list': {
      'version': 3,
      'devices_in_given_order': [dev2Id, me.deviceId],
      'signing_input': hex(listInput),
      'sig': hex(list.sig),
      'json': list.toJson(),
    },
    'legacy_zc1_as_account': {
      'contact_code': (await a[1].id.bundle(displayName: 'Bob')).encode(),
      'account_ed_pub': hex(legacy.accountEdPub),
      'device_id': legacy.devices.single.deviceId,
      'legacy': legacy.devices.single.legacy,
    },
  };
}

Future<Map<String, Object?>> suitePairing(List<Actor> a) async {
  final d = Drbg(0x0007);
  final code = PairingCode(d.next(10));
  final relayI = await RelayPairing.relayIdentity(code, 'i');
  final relayR = await RelayPairing.relayIdentity(code, 'r');
  final okmI = await refHkdf(
      code.secret, Uint8List(0), utf8.encode('z-pair-relay:i'), 64);
  check(eq(okmI.sublist(0, 32), relayI.edSeed), 'relay identity i');

  final me = await d.run(() => AccountIdentity.generate());
  d.takeDraws();
  final n = await d
      .run(() => PairingInitiator.create(code: code, deviceId: 'new-phone'));
  final nDraws = d.takeDraws();
  check(nDraws.length == 3 && eq(nDraws[2], n.ephXSeed), 'initiator draws');
  final hello = n.hello();
  final (reply, sessionR) = await d.run(() => PairingResponder.respond(hello));
  final rDraws = d.takeDraws();
  check(rDraws.length == 1, 'responder draws');
  final rEphSeed = rDraws[0];
  final rEphPub = await refXPub(rEphSeed);
  check(base64Encode(rEphPub) == reply['ephx'], 'responder eph labelling');
  final sessionI = await n.complete(reply);
  check(
      eq(sessionI.channelKey, sessionR.channelKey) &&
          sessionI.sas == sessionR.sas,
      'pairing agreement');
  final dh = await refDh(n.ephXSeed, rEphPub);
  final channelKey =
      await refHkdf(dh, Uint8List(32), utf8.encode('z-pair-channel-v1'), 32);
  check(eq(channelKey, sessionI.channelKey), 'channel key');
  final lo = hex(n.ephXPub).compareTo(hex(rEphPub)) < 0 ? n.ephXPub : rEphPub;
  final hi = identical(lo, n.ephXPub) ? rEphPub : n.ephXPub;
  final sasOkm = await refHkdf(dh, concatBytes([lo, hi]),
      concatBytes([utf8.encode('z-pair-sas-v1'), n.deviceEdPub]), 8);

  final bobBundle = (await AccountBundle.decode(
      (await a[1].id.bundle(displayName: 'Bob')).encode()));
  final sealed = await d.run(() => sessionR.sealEnrollment(me,
      contacts: [bobBundle], includeAccountRoot: false, displayName: 'Alice'));
  final sDraws = d.takeDraws();
  check(sDraws.length == 1 && eq(sDraws[0], sealed.sublist(0, 12)),
      'enrollment nonce');
  final data = await sessionI.openEnrollment(sealed);
  final installed = await n.installFromData(data);
  check(eq(installed.deviceEdPub, n.deviceEdPub) && !installed.holdsAccountRoot,
      'install');
  final cert = await sessionR.signedPeerCert(me);
  // Reconstruct the exact plaintext the host sealed (same key order).
  final plaintext = jsonEncode({
    'acct': base64Encode(me.accountEdPub),
    'name': 'Alice',
    'cert': cert.toJson(),
    'hostcert': me.deviceCert.toJson(),
    'contacts': [bobBundle.toJson()],
  });
  final box = await Chacha20.poly1305Aead().decrypt(
      SecretBox.fromConcatenation(sealed, nonceLength: 12, macLength: 16),
      secretKey: SecretKey(channelKey));
  check(utf8.decode(box) == plaintext, 'enrollment plaintext reconstruction');

  return {
    'suite': 'pairing',
    'version': vectorsVersion,
    'description':
        'Relay-mediated device pairing: pairing code -> rendezvous mailboxes, '
            'ephemeral X25519 -> channel key + SAS, then the sealed enrollment '
            'blob (ChaCha20-Poly1305, nonce||ct||mac).',
    'pairing_code': {
      'secret': hex(code.secret),
      'text': code.text,
      'rendezvous_input':
          hex(concatBytes([utf8.encode('z-pair-rendezvous-v1:'), code.secret])),
      'rendezvous_routing_id': await code.rendezvousRoutingId(),
    },
    'relay_identities': {
      for (final (role, id, okm) in [
        ('i', relayI, okmI),
        (
          'r',
          relayR,
          await refHkdf(
              code.secret, Uint8List(0), utf8.encode('z-pair-relay:r'), 64)
        ),
      ])
        role: {
          'hkdf_info': 'z-pair-relay:$role',
          'hkdf_okm': hex(okm),
          'ed_seed': hex(id.edSeed),
          'x_seed': hex(id.xSeed),
          'ed_pub': hex(id.edPub),
          'routing_id': await id.routingId(),
        }
    },
    'account': {
      'account_ed_seed': hex(me.accountEdSeed!),
      'account_ed_pub': hex(me.accountEdPub),
      'device_x_seed': hex(me.deviceXSeed),
      'device_id': me.deviceId,
      'device_cert_json': me.deviceCert.toJson(),
    },
    'new_device': {
      'device_ed_seed': hex(n.deviceEdSeed),
      'device_x_seed': hex(n.deviceXSeed),
      'device_ed_pub': hex(n.deviceEdPub),
      'device_x_pub': hex(n.deviceXPub),
      'device_id': n.deviceId,
      'eph_seed': hex(n.ephXSeed),
      'eph_pub': hex(n.ephXPub),
      'hello': hello,
    },
    'existing_device': {
      'eph_seed': hex(rEphSeed),
      'eph_pub': hex(rEphPub),
      'reply': reply,
    },
    'dh': hex(dh),
    'channel_key': hex(channelKey),
    'sas_salt': hex(concatBytes([lo, hi])),
    'sas_info': hex(concatBytes([utf8.encode('z-pair-sas-v1'), n.deviceEdPub])),
    'sas_okm': hex(sasOkm),
    'sas': sessionI.sas,
    'enrollment': {
      'new_device_cert_signing_input': hex(DeviceCertificate.signingInput(
          n.deviceEdPub, n.deviceXPub, n.deviceId)),
      'new_device_cert_sig': hex(cert.sig),
      'plaintext': plaintext,
      'nonce': hex(sealed.sublist(0, 12)),
      'sealed': hex(sealed),
      'enroll_frame': {'k': 'enroll', 'blob': base64Encode(sealed)},
    },
  };
}

Future<Map<String, Object?>> suiteInnerMessages(List<Actor> a) async {
  const ts = 1700000000000;
  final bobBundle = (await a[1].id.bundle(displayName: 'Bob')).toJson();
  final aliceBundle = (await a[0].id.bundle(displayName: 'Alice')).toJson();
  final kinds = <InnerMessage>[
    InnerMessage.hello('mid-hello', ts),
    InnerMessage.text('mid-text', ts, 'hello, world — héllo 🌍', ttlSec: 3600),
    InnerMessage.timer('mid-timer', ts, 604800),
    InnerMessage.read('mid-read', ts, ['mid-text', 'mid-file']),
    InnerMessage(kind: 'file', mid: 'mid-file', ts: ts, ttlSec: 0, data: {
      'fid': 'AAECAwQFBgcICQoL',
      'name': 'photo.jpg',
      'size': 1000,
      'mime': 'image/jpeg',
      'sha256': base64Encode(List.filled(32, 0xab)),
      'fk': base64Encode(List.filled(32, 0x01)),
      'fn': base64Encode(List.filled(16, 0x02)),
      'chunks': 1,
    }),
    InnerMessage(kind: 'dlv', mid: 'mid-dlv', ts: ts, data: {
      'mids': ['mid-text']
    }),
    InnerMessage(kind: 'devlist', mid: 'mid-devlist', ts: ts, data: {
      'list': jsonEncode({'acct': '...', 'ver': 3, 'devs': [], 'sig': '...'}),
    }),
    InnerMessage(kind: 'ginvite', mid: 'mid-ginvite', ts: ts, data: {
      'gid': 'gAAECAwQFBgcICQoL',
      'name': 'Weekend plans',
      'ver': 2,
      'members': [
        {'b': aliceBundle, 'n': 'Alice'},
        {'b': bobBundle, 'n': 'Bob'},
      ],
    }),
    InnerMessage(kind: 'gmsg', mid: 'mid-gmsg', ts: ts, data: {
      'gid': 'gAAECAwQFBgcICQoL',
      'body': 'who is in?',
    }),
    InnerMessage(kind: 'gfile', mid: 'mid-gfile', ts: ts, data: {
      'gid': 'gAAECAwQFBgcICQoL',
      'fid': 'AAECAwQFBgcICQoL',
      'name': 'beach.jpg',
      'size': 1000,
      'mime': 'image/jpeg',
      'sha256': base64Encode(List.filled(32, 0xab)),
      'fk': base64Encode(List.filled(32, 0x01)),
      'fn': base64Encode(List.filled(16, 0x02)),
      'chunks': 1,
    }),
    InnerMessage(kind: 'gleave', mid: 'mid-gleave', ts: ts, data: {
      'gid': 'gAAECAwQFBgcICQoL',
    }),
  ];
  final vectors = <Map<String, Object?>>[];
  for (final m in kinds) {
    final bytes = m.toBytes();
    final back = InnerMessage.fromBytes(bytes);
    check(back.kind == m.kind && back.mid == m.mid && back.ttlSec == m.ttlSec,
        'inner round trip');
    vectors.add({
      'kind': m.kind,
      'json': utf8.decode(bytes),
      'bytes': hex(bytes),
      'padded_len': pad(bytes).length,
    });
  }
  final syncEnvelope = jsonEncode({
    'thread': a[1].rid,
    'dir': 'out',
    'inner': base64Encode(kinds[1].toBytes()),
  });
  return {
    'suite': 'inner_messages',
    'version': vectorsVersion,
    'description':
        'Plaintext (post-decryption) message encodings for every inner kind, '
            'plus the self-sync envelope. Inner messages are parsed, never '
            'compared byte-wise, so only field names/types are normative; the '
            'bytes shown are what this implementation emits.',
    'vectors': vectors,
    'sync_envelope': {
      'json': syncEnvelope,
      'bytes': hex(utf8.encode(syncEnvelope)),
    },
  };
}

/// Generate every suite. Keys are the file names (without `.json`).
Future<Map<String, Map<String, Object?>>> generateAll() async {
  final a = await actors();
  return {
    'identity': await suiteIdentity(a),
    'handshake': await suiteHandshake(a),
    'ratchet': await suiteRatchet(a),
    'sealed_sender': await suiteSealed(a),
    'attachments': await suiteAttachments(a),
    'multidevice': await suiteMultidevice(a),
    'pairing': await suitePairing(a),
    'inner_messages': await suiteInnerMessages(a),
  };
}

String encodeVectorFile(Map<String, Object?> doc) =>
    '${const JsonEncoder.withIndent('  ').convert(doc)}\n';
