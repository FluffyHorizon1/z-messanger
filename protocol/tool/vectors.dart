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

/// Frozen v1 suites (never change) and the v2 post-quantum suites.
const int vectorsVersion = 1;
const int vectorsVersionPq = 2;
const int vectorsVersionV3 = 3;

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

/// Relay authentication, v2: the authority under the signature.
///
/// `signed_message` is `utf8("z-relay-auth-v2:") || utf8(authority) || nonce`
/// with the authority as the client computes it from the URL it dialled —
/// and as a relay normalises it back from the client's own Host header,
/// which is what `host_header` records for each case. The v1 vectors in
/// `identity.json` stay as they are: a relay still accepts them while its
/// operator lets it, and no client produces them.
Future<Map<String, Object?>> suiteRelayAuthV2(List<Actor> a) async {
  final d = Drbg(0x0039);
  final cases = <(String, String)>[
    // url, the Host header a client sends for it
    ('wss://zmessengers.com', 'zmessengers.com'),
    ('wss://Relay.Example.net:443', 'relay.example.net'),
    ('ws://192.168.1.50:8080', '192.168.1.50:8080'),
    ('ws://[::1]:8080', '[::1]:8080'),
    ('wss://z-relay-x.onrender.com/', 'z-relay-x.onrender.com'),
  ];
  final auth = <Map<String, Object?>>[];
  var i = 0;
  for (final (url, hostHeader) in cases) {
    final x = a[i % 2];
    i++;
    final authority = relayAuthority(url);
    final nonce = d.next(32);
    final sig = await x.id.signAuthChallengeV2(nonce, authority);
    final msg = concatBytes(
        [utf8.encode('z-relay-auth-v2:'), utf8.encode(authority), nonce]);
    check(eq(sig, await refEdSign(x.id.edSeed, msg)), 'auth v2 sig');
    auth.add({
      'identity': x.name,
      'url': url,
      'host_header': hostHeader,
      'authority': authority,
      'challenge_frame': {
        't': 'challenge',
        'nonce': base64Encode(nonce),
        'auth': 2
      },
      'nonce': hex(nonce),
      'signed_message': hex(msg),
      'sig': hex(sig),
      'auth_frame': {
        't': 'auth',
        'v': 2,
        'pub': base64Encode(x.id.edPub),
        'sig': base64Encode(sig)
      },
      'ready_frame': {'t': 'ready', 'id': x.rid},
    });
  }
  // The normalisation on its own, for a relay to check its half against.
  final normalization = <Map<String, Object?>>[
    for (final (url, hostHeader) in [
      ...cases,
      ('ws://relay.example:80', 'relay.example'),
      ('wss://RELAY.EXAMPLE', 'RELAY.EXAMPLE'),
      ('wss://relay.example:8443', 'relay.example:8443'),
    ])
      {'url': url, 'host_header': hostHeader, 'authority': relayAuthority(url)},
  ];
  return {
    'suite': 'relay_auth_v2',
    'version': vectorsVersion,
    'description':
        'Relay authentication bound to the relay: Ed25519 over '
            'utf8("z-relay-auth-v2:") || utf8(authority) || nonce, where the '
            'authority is the dialled host, lower-case, with the port only when '
            'it is not the default for the scheme. A relay derives the same '
            'authority from the Host header.',
    'relay_auth_v2': auth,
    'normalization': normalization,
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
  // v1 vectors: the post-quantum extension (v2) is switched off, so the
  // transcript is exactly what a v1 implementation produces.
  final convA = await Conversation.create(
      alice.id, await bob.id.bundle(displayName: bob.displayName),
      postQuantum: false, intervals: PqIntervals.disabled);
  final convB = await Conversation.create(
      bob.id, await alice.id.bundle(displayName: alice.displayName),
      postQuantum: false, intervals: PqIntervals.disabled);

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
  // sorts device Ed25519 keys lexicographically. Dual-signed by name, not by
  // default: this is the stage-1 list, and it stays one when the v2-only
  // signer (`devlistSignV2Only`) is switched on — the frozen file must not
  // move with that constant.
  final list =
      await me.signDeviceList([cert2, me.deviceCert], 3, v2Only: false);
  check(await list.verify(), 'device list verifies');
  final listInput = SignedDeviceList.signingInput(3, [cert2, me.deviceCert]);
  check(
      eq(list.sig!, await refEdSign(me.accountEdSeed!, listInput)), 'list sig');
  // ADR 0010: the list also carries sig2, the account's Ed25519 over the v2
  // input, which covers each device's X25519 key and id. Its presence makes
  // this a v2 list for the floor; because it still carries `sig`, what it
  // commits to — fingerprint and ML-DSA — is the v1 input (ADR 0017).
  final listInputV2 =
      SignedDeviceList.signingInputV2(3, [cert2, me.deviceCert]);
  check(
      list.sig2 != null &&
          eq(list.sig2!, await refEdSign(me.accountEdSeed!, listInputV2)),
      'list sig2');
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

  // ADR 0017 stage 2: the list this account's root republishes once the
  // v2-only signer is on — the same two devices, at the next version, signed
  // with `sig3` alone over the v2 content under its own context. Everything
  // here is deterministic and draws nothing from the DRBG, so every value
  // above is unchanged by it.
  final v2oDevices = [cert2, me.deviceCert];
  final v2o = await me.signDeviceList(v2oDevices, 4, v2Only: true);
  final v3Input = SignedDeviceList.signingInputV3(4, v2oDevices);
  final v2Input4 = SignedDeviceList.signingInputV2(4, v2oDevices);
  check(v2o.sig == null && v2o.sig2 == null && v2o.isV2Only,
      'v2-only: sig3 and nothing else');
  check(await v2o.verify(), 'v2-only: verifies on sig3 alone');
  check(eq(v2o.sig3!, await refEdSign(me.accountEdSeed!, v3Input)),
      'v2-only: sig3 is the reference Ed25519 over the v3 input');
  check(
      eq(v3Input.sublist(0, 13), utf8.encode('z-devlist-v3:')) &&
          eq(v2Input4.sublist(0, 13), utf8.encode('z-devlist-v2:')) &&
          eq(v3Input.sublist(13), v2Input4.sublist(13)),
      'the v3 input is the v2 content under a context of its own');
  check(eq(v2o.commitmentInput, v3Input), 'v2-only: commits to the v3 input');
  check(
      eq(await v2o.fingerprint(), (await refSha256(v3Input)).sublist(0, 16)),
      'v2-only: fingerprint = SHA-256(v3 input)[0..16]');
  check(
      !eq(await v2o.fingerprint(),
              await deviceListFingerprint(4, v2oDevices)) &&
          !eq(await v2o.fingerprint(),
              await deviceListFingerprintV2(4, v2oDevices)),
      'v2-only: and neither the v1 nor the v2 one');
  // Refused 1: the list with its only signature taken off.
  final noSig = SignedDeviceList(
      accountEdPub: me.accountEdPub, version: 4, devices: v2oDevices);
  check(!await noSig.verify(), 'a list with no signature is refused');
  // Refused 2: device 2's ratchet key replaced by one the attacker holds, its
  // certificate re-signed by the account key — what an adversary who can
  // forge Ed25519 produces — and the genuine sig3 carried over. The v1 input
  // cannot see the change; the v3 input, and so sig3, can.
  final attackerXSeed = Uint8List.fromList(List<int>.filled(32, 0x42));
  final attackerXPub = await refXPub(attackerXSeed);
  final forgedCert2 = await me.signDeviceCert(
      deviceEdPub: dev2EdPub, deviceXPub: attackerXPub, deviceId: dev2Id);
  check(await forgedCert2.verify(me.accountEdPub),
      'the substituted certificate is itself well signed');
  final swapped = SignedDeviceList(
      accountEdPub: me.accountEdPub,
      version: 4,
      devices: [forgedCert2, me.deviceCert],
      sig3: v2o.sig3);
  check(!await swapped.verify(), 'a swapped deviceXPub under sig3 is refused');
  check(
      eq(SignedDeviceList.signingInput(4, swapped.devices),
          SignedDeviceList.signingInput(4, v2oDevices)),
      'the v1 input is blind to the swap');
  check(!eq(await swapped.fingerprint(), await v2o.fingerprint()),
      'the v3 fingerprint is not');
  // Refused 3: the stage-1 list above with `sig` deleted — what anyone who
  // passes a list on can make of any dual-signed list, the log operator
  // included (a log value is sealed under a key derived from the account's
  // public key, §19.1). What is left is the genuine sig2, which verifies over
  // the v2 input: only the shape refuses it.
  final sigStripped = SignedDeviceList(
      accountEdPub: list.accountEdPub,
      version: list.version,
      devices: list.devices,
      sig2: list.sig2);
  check(!await sigStripped.verify(),
      'a dual-signed list with sig deleted is refused');
  // Refused 4: the same sig2 moved into sig3. It is over the v2 input, and a
  // sig3 must be over the v3 one.
  final relabelled = SignedDeviceList(
      accountEdPub: list.accountEdPub,
      version: list.version,
      devices: list.devices,
      sig3: list.sig2);
  check(!await relabelled.verify(), 'a sig2 presented as sig3 is refused');
  // Refused 5: every other way of combining the three signatures, each one
  // genuine — made for this vector over the same version and devices as the
  // v2-only list, which a real account never does (it signs a version one way
  // only) — so that each list is refused for its shape and nothing else.
  final dual4 = await me.signDeviceList(v2oDevices, 4, v2Only: false);
  check(await dual4.verify(), 'the dual-signed list at version 4 verifies');
  final otherShapes = <String, SignedDeviceList>{
    'sig2': SignedDeviceList(
        accountEdPub: me.accountEdPub,
        version: 4,
        devices: v2oDevices,
        sig2: dual4.sig2),
    'sig+sig3': SignedDeviceList(
        accountEdPub: me.accountEdPub,
        version: 4,
        devices: v2oDevices,
        sig: dual4.sig,
        sig3: v2o.sig3),
    'sig2+sig3': SignedDeviceList(
        accountEdPub: me.accountEdPub,
        version: 4,
        devices: v2oDevices,
        sig2: dual4.sig2,
        sig3: v2o.sig3),
    'sig+sig2+sig3': SignedDeviceList(
        accountEdPub: me.accountEdPub,
        version: 4,
        devices: v2oDevices,
        sig: dual4.sig,
        sig2: dual4.sig2,
        sig3: v2o.sig3),
  };
  for (final e in otherShapes.entries) {
    check(!await e.value.verify(), 'a {${e.key}} list is refused');
  }
  // Refused 6: a signature member present with the value null, beside a valid
  // shape. Read as absent, the first three would be admitted as the shape
  // they then are, while a reader going by which members are present refuses
  // them: two answers for one list. So present means a signature, and a list
  // with a null one is malformed — it does not parse (§3.4).
  final v1OnlyJson = Map<String, Object?>.of(list.toJson())..remove('sig2');
  final nullMembers = <(String, Map<String, Object?>)>[
    ('sig3', {...list.toJson(), 'sig3': null}),
    ('sig', {...v2o.toJson(), 'sig': null}),
    ('sig2', {...v1OnlyJson, 'sig2': null}),
    ('sig3', {...v1OnlyJson, 'sig3': null}),
    ('sig2', {...v2o.toJson(), 'sig2': null}),
  ];
  for (final (member, json) in nullMembers) {
    var refused = false;
    try {
      SignedDeviceList.fromJson(json);
    } on FormatException {
      refused = true;
    }
    check(refused, 'a list with a null $member member does not parse');
  }

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
      'signing_input_v2': hex(listInputV2),
      'sig': hex(list.sig!),
      'sig2': hex(list.sig2!),
      // 7.7a: SHA-256(signing_input)[0..16] — the value gossiped as the
      // device-list fingerprint and the leaf the transparency log commits to.
      // This list carries `sig`, so it commits to the v1 input (ADR 0017) and
      // `fingerprint` equals `fingerprint_v1`; the v2-only list below is the
      // one whose fingerprint is over the v2 input.
      'fingerprint': hex(await list.fingerprint()),
      'fingerprint_v1':
          hex(await deviceListFingerprint(3, [cert2, me.deviceCert])),
      'json': list.toJson(),
    },
    'device_list_v2_only': {
      'note': 'ADR 0017 stage 2: the same account and devices at the next '
          'version, signed v2-only — the list a root republishes once the '
          'v2-only signer is on. Its one signature is sig3, over '
          'signing_input_v3: the v2 content (each device\'s Ed25519 key, '
          'X25519 ratchet key and length-prefixed id) under the context '
          '"z-devlist-v3:" rather than "z-devlist-v2:", so that no signature '
          'ever made beside sig — every sig2 — can stand alone. A list has one '
          'of three shapes, {sig}, {sig, sig2} or {sig3}, and any other is '
          'refused before a signature is checked. It commits to the strongest '
          'signature that is alone: the v1 input while it carries sig, the v3 '
          'input once it carries sig3 alone. So this list\'s fingerprint, '
          'gossiped and committed to by a log leaf, is '
          'SHA-256(signing_input_v3)[0..16]; v1_fingerprint_not_reported and '
          'v2_fingerprint_not_reported are what the other two inputs would '
          'give, and no reader reports either. must_refuse: the list with no '
          'signature; the list with device "$dev2Id"\'s X25519 key replaced by '
          'the one derived from attacker_x_seed — its certificate re-signed by '
          'the account key, as an adversary who can forge Ed25519 would — and '
          'the genuine sig3 carried over; device_list above with its sig '
          'deleted, which leaves a genuine sig2 that verifies over its own '
          'input; the same sig2 moved into sig3; and every other combination '
          'of the three signatures, each genuine (made over this version and '
          'set for this vector only: a real account signs a version one way), '
          'refused for its shape alone; and the valid lists with a signature '
          'member added as null — {sig, sig2, "sig3": null}, '
          '{"sig": null, sig3} and the like — which do not parse: a '
          'signature member that is present is a signature, and a reader that '
          'read null as absent would admit what one going by the members '
          'present refuses.',
      'version': 4,
      'signing_input_v3': hex(v3Input),
      'sig3': hex(v2o.sig3!),
      'fingerprint': hex(await v2o.fingerprint()),
      'v1_fingerprint_not_reported':
          hex(await deviceListFingerprint(4, v2oDevices)),
      'v2_fingerprint_not_reported':
          hex(await deviceListFingerprintV2(4, v2oDevices)),
      'json': v2o.toJson(),
      'must_refuse': {
        'no_signature_json': noSig.toJson(),
        'swapped_ratchet_key': {
          'device_id': dev2Id,
          'attacker_x_seed': hex(attackerXSeed),
          'attacker_x_pub': hex(attackerXPub),
          'signing_input_v3':
              hex(SignedDeviceList.signingInputV3(4, swapped.devices)),
          'fingerprint': hex(await swapped.fingerprint()),
          'json': swapped.toJson(),
        },
        'sig_stripped_json': sigStripped.toJson(),
        'sig2_as_sig3_json': relabelled.toJson(),
        'other_shapes': [
          for (final e in otherShapes.entries)
            {'shape': e.key, 'json': e.value.toJson()},
        ],
        'null_members': [
          for (final (member, json) in nullMembers)
            {'member': member, 'json': json},
        ],
      },
    },
    'legacy_zc1_as_account': {
      'contact_code': (await a[1].id.bundle(displayName: 'Bob')).encode(),
      'account_ed_pub': hex(legacy.accountEdPub),
      'device_id': legacy.devices.single.deviceId,
      'legacy': legacy.devices.single.legacy,
    },
  };
}

/// ADR 0022: a device certificate's proof of possession (`pop`). A new file
/// beside `multidevice.json`, which it leaves byte-identical: the same
/// account and second device, regenerated from the same seed, so the list
/// here IS that file's dual-signed list with the second device's proof
/// attached — and its signatures and fingerprint are that file's.
Future<Map<String, Object?>> suiteDevicePop(List<Actor> a) async {
  final d = Drbg(0x0006); // multidevice.json's seed: the same account
  final me = await d.run(() => AccountIdentity.generate());
  final draws = d.takeDraws();
  check(draws.length == 3 && eq(draws[0], me.accountEdSeed!), 'account seed');
  final dev2EdSeed = d.next(32), dev2XSeed = d.next(32);
  final dev2EdPub = await refEdPub(dev2EdSeed);
  final dev2XPub = await refXPub(dev2XSeed);
  const dev2Id = 'second-device';
  final cert2 = await me.signDeviceCert(
      deviceEdPub: dev2EdPub, deviceXPub: dev2XPub, deviceId: dev2Id);
  final acctPub = me.accountEdPub;

  // The proof: the device's own Ed25519 over the context, the account key,
  // its two keys and its id — rebuilt from the formula, not read back.
  final popIn = DeviceCertificate.popInput(acctPub, dev2EdPub, dev2XPub, dev2Id);
  check(
      eq(
          popIn,
          concatBytes(
              [utf8b('z-device-pop-v1:'), acctPub, dev2EdPub, dev2XPub, utf8b(dev2Id)])),
      'pop input');
  check(popIn.length == 16 + 32 * 3 + utf8b(dev2Id).length, 'fixed-width fields');
  final pop = await cert2.makePop(dev2EdSeed, acctPub);
  check(eq(pop, await refEdSign(dev2EdSeed, popIn)),
      'pop is the reference Ed25519 by the DEVICE key (RFC 8032, deterministic)');
  final proven2 = cert2.withPop(pop);
  check(await proven2.verify(acctPub), 'the certificate with its proof verifies');
  check(await proven2.provesPossession(acctPub), 'and proves possession');
  check(await cert2.verify(acctPub) && !await cert2.provesPossession(acctPub),
      'the same certificate without it verifies and proves nothing');
  check(await me.deviceCert.provesPossession(acctPub),
      'device #1 proves possession with no pop: its key is the account key');
  // The device's own view of it: a linked device makes the same bytes.
  final dev2 = await AccountIdentity.fromEnrollment(
      accountEdPub: acctPub,
      deviceEdSeed: dev2EdSeed,
      deviceXSeed: dev2XSeed,
      deviceId: dev2Id,
      deviceCert: cert2);
  check(eq(await dev2.devicePop(), pop), 'AccountIdentity.devicePop');
  check(eq((await dev2.provenDeviceCert()).pop!, pop), 'provenDeviceCert');
  check((await me.provenDeviceCert()).pop == null,
      'device #1 presents its certificate as it is');

  // multidevice.json's dual-signed list, version 3, the devices in the same
  // (unsorted) order — with and without the proof.
  final plain =
      await me.signDeviceList([cert2, me.deviceCert], 3, v2Only: false);
  final proven =
      await me.signDeviceList([proven2, me.deviceCert], 3, v2Only: false);
  check(await proven.verify(), 'the list carrying the proof verifies');
  check(eq(plain.sig!, proven.sig!) && eq(plain.sig2!, proven.sig2!),
      'a proof changes no signature the account makes');
  check(eq(await plain.fingerprint(), await proven.fingerprint()),
      'nor the fingerprint');
  Map<String, Object?> withoutPop(Map<String, Object?> listJson) => {
        ...listJson,
        'devs': [
          for (final dv in (listJson['devs'] as List).cast<Map>())
            {
              for (final e in dv.cast<String, Object?>().entries)
                if (e.key != 'pop') e.key: e.value
            }
        ],
      };
  check(
      jsonEncode(withoutPop(proven.toJson())) == jsonEncode(plain.toJson()),
      'with the member taken off, it is the list a reader before it holds');
  // And the v2-only shape (ADR 0017 stage 2) the same way.
  final v2oPlain =
      await me.signDeviceList([cert2, me.deviceCert], 4, v2Only: true);
  final v2oProven =
      await me.signDeviceList([proven2, me.deviceCert], 4, v2Only: true);
  check(await v2oProven.verify() && eq(v2oPlain.sig3!, v2oProven.sig3!),
      'v2-only: the same sig3, and it verifies');
  check(eq(await v2oPlain.fingerprint(), await v2oProven.fingerprint()),
      'v2-only: the same fingerprint');
  // A zc2. account code carrying it.
  final code = me
      .toAccountBundle(displayName: 'Alice', otherDevices: [proven2]).encode();
  final decoded = await AccountBundle.decode(code);
  check(decoded.devices.length == 2 && eq(decoded.devices[1].pop!, pop),
      'zc2 decode keeps the proof');

  // Lists that must be refused by a reader that knows the member. Each is
  // version 3 of the account's list, signed by the account over whatever
  // certificates it carries, so that the proof is the only thing wrong.
  Future<Map<String, Object?>> listWith(DeviceCertificate c2) async =>
      (await me.signDeviceList([c2, me.deviceCert], 3, v2Only: false))
          .toJson();
  final otherAcct = (await AccountIdentity.fromV1(a[1].id, deviceId: 'bob'))
      .accountEdPub; // Bob's, from the fixed actors
  final otherXSeed = Uint8List.fromList(List<int>.filled(32, 0x42));
  final otherXPub = await refXPub(otherXSeed);
  final swappedCert = await me.signDeviceCert(
      deviceEdPub: dev2EdPub, deviceXPub: otherXPub, deviceId: dev2Id);
  final renamedCert = await me.signDeviceCert(
      deviceEdPub: dev2EdPub, deviceXPub: dev2XPub, deviceId: 'renamed');
  final refusals = <(String, String, DeviceCertificate)>[
    (
      'signed_by_account_key',
      'the "proof" made by the ACCOUNT key over the right input: what a root '
          'can make for a device it does not hold',
      cert2.withPop(await refEdSign(me.accountEdSeed!, popIn))
    ),
    (
      'for_another_account',
      'the device\'s own signature over the input for ANOTHER account (Bob\'s '
          'key from identity.json): a proof names one account',
      cert2.withPop(await refEdSign(dev2EdSeed,
          DeviceCertificate.popInput(otherAcct, dev2EdPub, dev2XPub, dev2Id)))
    ),
    (
      'ratchet_key_swapped',
      'the device\'s genuine proof kept while its certificate is re-signed by '
          'the account over another X25519 key (derived from other_x_seed): '
          'the proof covers the ratchet key',
      swappedCert.withPop(pop)
    ),
    (
      'id_changed',
      'the genuine proof kept while the certificate names another id',
      renamedCert.withPop(pop)
    ),
    (
      'pop_63_bytes',
      'a proof one byte short',
      cert2.withPop(Uint8List.fromList(pop.sublist(0, 63)))
    ),
    (
      'pop_bit_flipped',
      'the genuine proof with its last byte changed',
      cert2.withPop(Uint8List.fromList([...pop.sublist(0, 63), pop[63] ^ 1]))
    ),
  ];
  final mustRefuse = <Map<String, Object?>>[];
  for (final (name, why, c) in refusals) {
    check(!await c.verify(acctPub), 'refused certificate: $name');
    final j = await listWith(c);
    final back = SignedDeviceList.fromJson(j);
    check(!await back.verify(), 'refused list: $name');
    mustRefuse.add({'case': name, 'why': why, 'list_json': j});
  }
  // A member present as anything but a base64 string does not parse.
  final notParsed = <Map<String, Object?>>[];
  for (final (name, value) in <(String, Object?)>[
    ('pop_null', null),
    ('pop_number', 7),
    ('pop_list', <int>[1, 2]),
  ]) {
    final j = {...proven2.toJson(), 'pop': value};
    var threw = false;
    try {
      DeviceCertificate.fromJson(j);
    } on FormatException {
      threw = true;
    }
    check(threw, 'a certificate with $name does not parse');
    notParsed.add({'case': name, 'cert_json': j});
  }

  // A claim: another account's list naming device 2's keys. Carol's
  // account (identity.json's third actor) signs a certificate over them —
  // an account signs whatever it is handed — and lists it.
  final carol = await AccountIdentity.fromV1(a[2].id, deviceId: 'carol');
  final claimedCert = await carol.signDeviceCert(
      deviceEdPub: dev2EdPub, deviceXPub: dev2XPub, deviceId: dev2Id);
  final claimBare = await carol
      .signDeviceList([carol.deviceCert, claimedCert], 2, v2Only: false);
  final claimWithPop = await carol.signDeviceList(
      [carol.deviceCert, claimedCert.withPop(pop)], 2,
      v2Only: false);
  check(await claimBare.verify(),
      'the bare claim verifies: the account signed it, which is all §3.1 asks');
  check(!await claimedCert.provesPossession(carol.accountEdPub),
      'and proves nothing for device 2');
  check(!await claimWithPop.verify(),
      'device 2\'s proof carried into it does not verify: it names Alice\'s account');

  return {
    'suite': 'device_pop',
    'version': vectorsVersion,
    'description':
        'ADR 0022 (PROTOCOL 3.1, 3.4): a device certificate\'s proof of '
            'possession. pop = Ed25519 by the DEVICE key over '
            'utf8("z-device-pop-v1:") || account_ed (32) || device_ed (32) || '
            'device_x (32) || utf8(device_id), as an optional member of the '
            'certificate. No signature the account makes covers it, so a list '
            'or zc2. code with it and the same one without have the same '
            'signatures and the same fingerprint, and a reader from before it '
            'admits both. A reader that knows it refuses a certificate whose '
            'pop is present and does not verify — and with it the list or code '
            'that carries it. A certificate proves possession when it verifies '
            'and either carries a pop or its device key IS the account key '
            '(device #1, a legacy record), where sig is already the device\'s '
            'own signature. What a receiver then does with a list that names a '
            'device proven for another account, or names a device it has seen '
            'proven without the proof, is §3.4\'s receiver rule: state, not a '
            'property of the bytes, so not vectored here.',
    'context': devicePopContext,
    'account_ed_seed': hex(me.accountEdSeed!),
    'account_ed_pub': hex(acctPub),
    'device1': {
      'device_ed_pub': hex(me.deviceEdPub),
      'device_id': me.deviceId,
      'proves_possession': true,
      'why': 'its key is the account key: the certificate is the device '
          'key\'s own signature, and carries no pop',
    },
    'device2': {
      'ed_seed': hex(dev2EdSeed),
      'x_seed': hex(dev2XSeed),
      'device_ed_pub': hex(dev2EdPub),
      'device_x_pub': hex(dev2XPub),
      'device_id': dev2Id,
      'pop_input': hex(popIn),
      'pop': hex(pop),
      'cert_json': proven2.toJson(),
      'cert_json_without_pop': cert2.toJson(),
    },
    'device_list': {
      'note': 'multidevice.json\'s device_list with device 2\'s proof '
          'attached; json_without_pop is that file\'s device_list.json byte '
          'for byte, and sig, sig2 and fingerprint are that file\'s.',
      'version': 3,
      'sig': hex(proven.sig!),
      'sig2': hex(proven.sig2!),
      'fingerprint': hex(await proven.fingerprint()),
      'json': proven.toJson(),
      'json_without_pop': plain.toJson(),
    },
    'device_list_v2_only': {
      'note': 'the same, v2-only (ADR 0017 stage 2) at version 4: the same '
          'sig3 and fingerprint with the proof or without it.',
      'version': 4,
      'sig3': hex(v2oProven.sig3!),
      'fingerprint': hex(await v2oProven.fingerprint()),
      'json': v2oProven.toJson(),
      'json_without_pop': v2oPlain.toJson(),
    },
    'account_code_json':
        utf8.decode(base64Url.decode(base64Url.normalize(code.substring(4)))),
    'account_code': code,
    'claim': {
      'note': 'Carol\'s account (identity.json\'s third identity, read as an '
          'account) lists device 2\'s keys under a certificate of its own. '
          'Without a pop the list verifies — the account signed it — and '
          'device 2 proves nothing in it: a receiver that has seen device 2 '
          'proven for Alice\'s account refuses it, and one that has not holds '
          'it to the first-come rule (§3.4). With device 2\'s genuine pop '
          'carried over it does not verify: that proof names Alice\'s account.',
      'claimant_ed_seed': hex(a[2].id.edSeed),
      'claimant_account_ed_pub': hex(carol.accountEdPub),
      'json_without_pop': claimBare.toJson(),
      'json_with_pop': claimWithPop.toJson(),
    },
    'other_x_seed': hex(otherXSeed),
    'must_refuse': mustRefuse,
    'must_not_parse': notParsed,
  };
}

Future<Map<String, Object?>> suiteConnect(List<Actor> a) async {
  final d = Drbg(0x0019);
  final code = ConnectCode(d.next(10));
  check(ConnectCode.parse(code.text).secret.length == 10, 'connect code parse');
  check(ConnectCode.fromLink(code.link())!.secret[0] == code.secret[0],
      'connect link round-trip');
  final rvInput = concatBytes([utf8.encode('z-connect-rendezvous-v1:'), code.secret]);
  check(await code.rendezvousRoutingId() == base64Url.encode(await refSha256(rvInput)).replaceAll('=', ''),
      'connect rendezvous');

  // Two v3 identities, each with the contact code the app would put in a QR.
  final ids = <ConnectIdentity>[];
  final raw = <Map<String, Object?>>[];
  for (final (name, tag) in [('Alice', 'inviter'), ('Bob', 'acceptor')]) {
    final edSeed = d.next(32);
    final xSeed = d.next(32);
    final mlSeed = d.next(32);
    final zid = await ZIdentity.fromSeeds(edSeed: edSeed, xSeed: xSeed);
    final pq = await HybridKeyPair.fromSeeds(edSeed: edSeed, mlSeed: mlSeed);
    // The code as a client before ADR 0027 emits it, with no `pqcs`: what
    // this frozen file records.
    final bundle = await ContactBundleV3.forIdentity(zid, pq.publicKey,
        displayName: name, signCommitment: false);
    final ci = await ConnectIdentity.fromCode(bundle.encode(), displayName: name);
    check(eq(ci.accountEdPub, zid.edPub), '$tag account key');
    check(eq(ci.pqCommit, await refSha256(concatBytes([
      utf8.encode('z-pqid-v3:'),
      pq.publicKey.mlPub,
    ]))), '$tag pq commitment');
    ids.add(ci);
    raw.add({
      'role': tag,
      'display_name': name,
      'ed_seed': hex(edSeed),
      'x_seed': hex(xSeed),
      'ml_seed': hex(mlSeed),
      'account_ed_pub': hex(ci.accountEdPub),
      'pq_commit': hex(ci.pqCommit),
      'contact_code': ci.contactCode,
    });
  }
  final alice = ids[0], bob = ids[1];

  // Message 1: the inviter's commitment. Clear the draws the seeds above
  // consumed first, so what `takeDraws` returns is the ceremony's own.
  d.takeDraws();
  final inviter = await d.run(() => ConnectInviter.create(me: alice, code: code));
  final iDraws = d.takeDraws();
  check(iDraws.length == 1, 'inviter ephemeral draw');
  final iEphSeed = iDraws[0];
  final iEphPub = await refXPub(iEphSeed);
  check(eq(iEphPub, inviter.ephPub), 'inviter ephemeral labelling');
  final aCode = utf8.encode(alice.contactCode);
  final commitInputA = concatBytes([
    utf8.encode('z-connect-commit-v1:'),
    iEphPub,
    [(aCode.length >> 8) & 0xff, aCode.length & 0xff],
    aCode,
    utf8.encode('Alice'),
  ]);
  final commitA = await refSha256(commitInputA);
  final commitFrame = await inviter.commit();
  check(base64Encode(commitA) == commitFrame['c'], 'inviter commitment');

  // Message 2: the acceptor answers, committing to itself against a hash.
  final (reply, acceptor) =
      await d.run(() => ConnectAcceptor.reply(commitFrame, me: bob, code: code));
  final rDraws = d.takeDraws();
  check(rDraws.length == 1, 'acceptor ephemeral draw');
  final rEphSeed = rDraws[0];
  final rEphPub = await refXPub(rEphSeed);
  check(base64Encode(rEphPub) == reply['ephx'], 'acceptor ephemeral labelling');
  final bCode = utf8.encode(bob.contactCode);
  final commitInputB = concatBytes([
    utf8.encode('z-connect-commit-v1:'),
    rEphPub,
    [(bCode.length >> 8) & 0xff, bCode.length & 0xff],
    bCode,
    utf8.encode('Bob'),
  ]);
  check(base64Encode(await refSha256(commitInputB)) == reply['c'],
      'acceptor commitment');

  // Message 3: the inviter's opening, its identity sealed.
  final dh = await refDh(iEphSeed, rEphPub);
  final channelKey =
      await refHkdf(dh, Uint8List(32), utf8.encode('z-connect-channel-v1'), 32);
  final open = await d.run(() => inviter.open(reply));
  final openDraws = d.takeDraws();
  check(openDraws.length == 1, 'inviter seal nonce');

  // Message 4: the acceptor checks, reveals, and both have the session.
  final (revealB, sessionB) = await d.run(() => acceptor.accept(open));
  final revealDraws = d.takeDraws();
  check(revealDraws.length == 1, 'acceptor seal nonce');
  final sessionA = await inviter.complete(revealB);
  check(sessionA.sas == sessionB.sas, 'connect agreement');
  check(eq(sessionA.channelKey, channelKey), 'connect channel key');

  // The SAS, recomputed independently. The two parties are sorted by account
  // key, so the input — and therefore the string — does not depend on which
  // of them invited.
  final aFirst = hex(alice.accountEdPub).compareTo(hex(bob.accountEdPub)) < 0;
  final lo = aFirst ? alice : bob, hi = aFirst ? bob : alice;
  final loEph = aFirst ? iEphPub : rEphPub, hiEph = aFirst ? rEphPub : iEphPub;
  final sasSalt = concatBytes([loEph, hiEph]);
  final sasInfo = concatBytes([
    utf8.encode('z-connect-sas-v1'),
    lo.accountEdPub,
    lo.pqCommit,
    hi.accountEdPub,
    hi.pqCommit,
  ]);
  final sasOkm = await refHkdf(dh, sasSalt, sasInfo, 8);
  var n = 0;
  for (var i = 0; i < 7; i++) {
    n = (n << 8) | sasOkm[i];
  }
  final digits = (n % 100000000).toString().padLeft(8, '0');
  final sasText = '${digits.substring(0, 4)} ${digits.substring(4)}';
  check(sasText == sessionA.sas, 'connect SAS');

  // Each side ends holding the other's code, which its scan path accepts.
  check(sessionA.peer.contactCode == bob.contactCode, 'inviter learned bob');
  check(sessionB.peer.contactCode == alice.contactCode, 'acceptor learned alice');

  return {
    'suite': 'connect',
    'version': vectorsVersion,
    'description':
        'The connect ceremony (PROTOCOL 20): a one-time invite code, a '
            'rendezvous mailbox derived from it, and four messages in which '
            'BOTH sides commit before either reveals. The eight-digit '
            'confirmation string is bound to both account keys and both '
            'post-quantum commitments in canonical order, so it says what a '
            'safety-number comparison says; each side reveals its contact '
            'code sealed under the channel, so one ceremony adds both people.',
    'connect_code': {
      'secret': hex(code.secret),
      'text': code.text,
      'link': code.link(),
      'rendezvous_input': hex(rvInput),
      'rendezvous_routing_id': await code.rendezvousRoutingId(),
      'relay_context': connectRelayCtx,
    },
    'parties': raw,
    'inviter_ephemeral': {'seed': hex(iEphSeed), 'pub': hex(iEphPub)},
    'acceptor_ephemeral': {'seed': hex(rEphSeed), 'pub': hex(rEphPub)},
    'commitments': {
      'inviter_input': hex(commitInputA),
      'inviter': hex(commitA),
      'acceptor_input': hex(commitInputB),
      'acceptor': hex(await refSha256(commitInputB)),
    },
    'frames': {
      'commit': {'k': 'x1', ...commitFrame},
      'reply': {'k': 'x2', ...reply},
      'open': {'k': 'x3', ...open},
      'reveal': {'k': 'x4', ...revealB},
    },
    'dh': hex(dh),
    'channel_key': hex(channelKey),
    'sas_salt': hex(sasSalt),
    'sas_info': hex(sasInfo),
    'sas_okm': hex(sasOkm),
    'sas': sasText,
    'canonical_order': aFirst ? ['inviter', 'acceptor'] : ['acceptor', 'inviter'],
  };
}

/// The connect ceremony with the group bit (ADR 0020, PROTOCOL §20.3).
///
/// `connect.json` is the ceremony as a client before ADR 0020 runs it and is
/// left exactly as it was. This is the same four messages with the bit:
/// message 3's sealed reveal carries `"grp":1` — a group is attached, and
/// nothing about which — and message 4's repeats it. Both plaintexts and
/// both seal nonces are recorded, and each blob is recomputed here from
/// them with the `cryptography` primitives, so a second implementation can
/// see the member's exact bytes and check its own seal against them.
Future<Map<String, Object?>> suiteConnectGroup() async {
  final d = Drbg(0x0020);
  final code = ConnectCode(d.next(10));
  final ids = <ConnectIdentity>[];
  final raw = <Map<String, Object?>>[];
  for (final (name, tag) in [('Ana', 'inviter'), ('Joe', 'acceptor')]) {
    final edSeed = d.next(32);
    final xSeed = d.next(32);
    final mlSeed = d.next(32);
    final zid = await ZIdentity.fromSeeds(edSeed: edSeed, xSeed: xSeed);
    final pq = await HybridKeyPair.fromSeeds(edSeed: edSeed, mlSeed: mlSeed);
    // The code as a client before ADR 0027 emits it, with no `pqcs`: what
    // this frozen file records.
    final bundle = await ContactBundleV3.forIdentity(zid, pq.publicKey,
        displayName: name, signCommitment: false);
    final ci = await ConnectIdentity.fromCode(bundle.encode(), displayName: name);
    ids.add(ci);
    raw.add({
      'role': tag,
      'display_name': name,
      'ed_seed': hex(edSeed),
      'x_seed': hex(xSeed),
      'ml_seed': hex(mlSeed),
      'contact_code': ci.contactCode,
    });
  }
  final ana = ids[0], joe = ids[1];

  d.takeDraws();
  final inviter = await d.run(
      () => ConnectInviter.create(me: ana, code: code, group: true));
  final iEphSeed = d.takeDraws().single;
  final commitFrame = await inviter.commit();
  final (reply, acceptor) = await d.run(() =>
      ConnectAcceptor.reply(commitFrame,
          me: joe, code: code, groupAware: true));
  final rEphSeed = d.takeDraws().single;
  final rEphPub = await refXPub(rEphSeed);
  final open = await d.run(() => inviter.open(reply));
  final openNonce = d.takeDraws().single;
  final (reveal, sessionJ) = await d.run(() => acceptor.accept(open));
  final revealNonce = d.takeDraws().single;
  final sessionA = await inviter.complete(reveal);
  check(sessionJ.group == true, 'the acceptor read the bit');
  check(sessionA.group == true, 'the inviter read it back');
  check(sessionA.sas == sessionJ.sas, 'connect group agreement');

  // The two reveals, rebuilt from their plaintexts: the member is one byte
  // of value, `0` or `1`, written whichever it is.
  final dh = await refDh(iEphSeed, rEphPub);
  final channelKey =
      await refHkdf(dh, Uint8List(32), utf8.encode('z-connect-channel-v1'), 32);
  final aead = Chacha20.poly1305Aead();
  Future<String> sealed(String plain, Uint8List nonce) async => base64Encode(
      (await aead.encrypt(utf8.encode(plain),
              secretKey: SecretKey(channelKey), nonce: nonce))
          .concatenation());
  final openPlain = jsonEncode(
      {'code': ana.contactCode, 'name': 'Ana', connectGroupMember: 1});
  final revealPlain = jsonEncode(
      {'code': joe.contactCode, 'name': 'Joe', connectGroupMember: 1});
  check(await sealed(openPlain, openNonce) == open['blob'],
      'message 3 is the recorded plaintext, sealed');
  check(await sealed(revealPlain, revealNonce) == reveal['blob'],
      'message 4 is the recorded plaintext, sealed');

  // The go-ahead tag (PROTOCOL 20.6): what the acceptor's `gjoin` carries so
  // that it answers this ceremony and no other — the same at both ends, and
  // nothing but HKDF of the channel key under its own label.
  final tag = await sessionA.goAheadTag();
  check(eq(tag, await sessionJ.goAheadTag()), 'one tag at both ends');
  check(
      eq(
          tag,
          await refHkdf(channelKey, Uint8List(32),
              utf8.encode(connectGoAheadLabel), connectGoAheadTagBytes)),
      'the go-ahead tag is HKDF-SHA256 of the channel key, 16 bytes');

  return {
    'suite': 'connect_group',
    'version': vectorsVersion,
    'description':
        'The connect ceremony (PROTOCOL 20) with the group bit of ADR 0020: '
            'message 3 seals "grp":1 beside the inviter\'s code and name — the '
            'invite also brings the acceptor into a group, and nothing says '
            'which — and message 4 repeats it. A client that knows the member '
            'writes it in every reveal, 0 or 1, so the length of a frame never '
            'depends on it; one that does not neither writes nor reads it. The '
            'commitments do not cover it (they are computed exactly as in '
            'connect.json): it is protected by the AEAD under the channel key. '
            'go_ahead is the tag the acceptor\'s go-ahead (gjoin) carries: '
            'HKDF-SHA256 with the channel key as input, a salt of 32 zero bytes '
            'and the label as info, 16 bytes, so a go-ahead answers this '
            'ceremony and no other. '
            'Everything not recorded here is computed as connect.json shows.',
    'connect_code': {
      'secret': hex(code.secret),
      'text': code.text,
    },
    'parties': raw,
    'inviter_ephemeral': {'seed': hex(iEphSeed), 'pub': hex(inviter.ephPub)},
    'acceptor_ephemeral': {'seed': hex(rEphSeed), 'pub': hex(rEphPub)},
    'channel_key': hex(channelKey),
    'group_member': connectGroupMember,
    'go_ahead': {
      'label': connectGoAheadLabel,
      'tag': hex(tag),
      'tag_b64url': b64url(tag),
    },
    'reveals': {
      'open_plaintext': openPlain,
      'open_nonce': hex(openNonce),
      'reveal_plaintext': revealPlain,
      'reveal_nonce': hex(revealNonce),
    },
    'frames': {
      'commit': {'k': 'x1', ...commitFrame},
      'reply': {'k': 'x2', ...reply},
      'open': {'k': 'x3', ...open},
      'reveal': {'k': 'x4', ...reveal},
    },
    'sas': sessionA.sas,
  };
}

/// An invite of version 2: the ceremony bound to its secret (ADR 0024,
/// PROTOCOL §20.8).
///
/// `connect.json`, `mailboxes.json` and `group.json` are version 1 and stay
/// exactly as they were; this file is the new version beside them. Every
/// value §20.8 changes is recomputed here from the primitives — the invite
/// key from the secret, the two keyed commitments, the channel key salted
/// with the invite key, the digits under their own context, both mailboxes
/// under theirs — and checked against what the library produced. The
/// version-1 value of each, from the same inputs, is recorded beside it, so
/// a second implementation that computes the old one by mistake sees it.
Future<Map<String, Object?>> suiteConnectV2() async {
  final d = Drbg(0x0024);
  final code = ConnectCode(d.next(10), version: 2);
  final v1 = ConnectCode(code.secret);
  check(code.text.startsWith(connectV2Marker), 'the marker leads the text');
  check(ConnectCode.parse(code.text).version == 2, 'text parses as v2');
  final fromLink = ConnectCode.fromLink(code.link())!;
  check(fromLink.version == 2 && eq(fromLink.secret, code.secret),
      'link parses as v2');

  // The invite key.
  final keyInfo = utf8b(connectInviteKeyCtx);
  final inviteKey = await refHkdf(code.secret, Uint8List(0), keyInfo, 32);
  check(eq((await code.inviteKey())!, inviteKey), 'invite key');

  // Both mailboxes, and the rendezvous, under the version-2 contexts.
  final mailboxes = <Map<String, Object?>>[];
  final v1Mailboxes = <String>[];
  for (final (role, who) in [('i', 'inviter'), ('r', 'acceptor')]) {
    final info = concatBytes([utf8.encode(connectRelayCtxV2), utf8.encode(role)]);
    final okm = await refHkdf(code.secret, Uint8List(0), info, 64);
    final edSeed = Uint8List.fromList(okm.sublist(0, 32));
    final xSeed = Uint8List.fromList(okm.sublist(32, 64));
    final edPub = await refEdPub(edSeed);
    final routingId =
        base64Url.encode(await refSha256(edPub)).replaceAll('=', '');
    final id = await mailboxIdentity(code, role);
    check(eq(id.edPub, edPub), '$who v2 mailbox');
    check(await id.routingId() == routingId, '$who v2 mailbox routing id');
    mailboxes.add({
      'role': role,
      'who': who,
      'info': hex(info),
      'okm': hex(okm),
      'ed_seed': hex(edSeed),
      'x_seed': hex(xSeed),
      'ed_pub': hex(edPub),
      'x_pub': hex(await refXPub(xSeed)),
      'routing_id': routingId,
    });
    v1Mailboxes.add(await (await mailboxIdentity(v1, role)).routingId());
  }
  final rvInput =
      concatBytes([utf8.encode('z-connect-rendezvous-v2:'), code.secret]);
  final rendezvous =
      base64Url.encode(await refSha256(rvInput)).replaceAll('=', '');
  check(await code.rendezvousRoutingId() == rendezvous, 'v2 rendezvous');
  final distinct = {
    'v1_mailbox_i': v1Mailboxes[0],
    'v1_mailbox_r': v1Mailboxes[1],
    'v1_rendezvous': await v1.rendezvousRoutingId(),
  };
  for (final m in mailboxes) {
    for (final e in distinct.entries) {
      check(m['routing_id'] != e.value, 'v2 mailbox vs ${e.key}');
    }
  }
  check(rendezvous != distinct['v1_rendezvous'], 'v2 rendezvous vs v1');

  // Two v3 identities, with the codes a client emits today (`pqcs` signed).
  final ids = <ConnectIdentity>[];
  final raw = <Map<String, Object?>>[];
  for (final (name, tag) in [('Ivy', 'inviter'), ('Rob', 'acceptor')]) {
    final edSeed = d.next(32);
    final xSeed = d.next(32);
    final mlSeed = d.next(32);
    final zid = await ZIdentity.fromSeeds(edSeed: edSeed, xSeed: xSeed);
    final pq = await HybridKeyPair.fromSeeds(edSeed: edSeed, mlSeed: mlSeed);
    final bundle = await ContactBundleV3.forIdentity(zid, pq.publicKey,
        displayName: name);
    final ci =
        await ConnectIdentity.fromCode(bundle.encode(), displayName: name);
    ids.add(ci);
    raw.add({
      'role': tag,
      'display_name': name,
      'ed_seed': hex(edSeed),
      'x_seed': hex(xSeed),
      'ml_seed': hex(mlSeed),
      'account_ed_pub': hex(ci.accountEdPub),
      'pq_commit': hex(ci.pqCommit),
      'contact_code': ci.contactCode,
    });
  }
  final ivy = ids[0], rob = ids[1];

  // The four messages, as a client of this version sends them: the group
  // bit written, 0, in both reveals (ADR 0020).
  d.takeDraws();
  final inviter = await d.run(
      () => ConnectInviter.create(me: ivy, code: code, group: false));
  final iEphSeed = d.takeDraws().single;
  final iEphPub = await refXPub(iEphSeed);
  final commitFrame = await inviter.commit();
  final (reply, acceptor) = await d.run(() => ConnectAcceptor.reply(
      commitFrame,
      me: rob,
      code: code,
      groupAware: true));
  final rEphSeed = d.takeDraws().single;
  final rEphPub = await refXPub(rEphSeed);
  final open = await d.run(() => inviter.open(reply));
  final openNonce = d.takeDraws().single;
  final (reveal, sessionR) = await d.run(() => acceptor.accept(open));
  final revealNonce = d.takeDraws().single;
  final sessionI = await inviter.complete(reveal);
  check(sessionI.sas == sessionR.sas, 'v2 agreement');

  // The commitments: HMAC-SHA256 under the invite key.
  Uint8List committed(Uint8List eph, ConnectIdentity id) {
    final c = utf8.encode(id.contactCode);
    return concatBytes([
      eph,
      [(c.length >> 8) & 0xff, c.length & 0xff],
      c,
      utf8.encode(id.displayName ?? ''),
    ]);
  }

  final commitInputI =
      concatBytes([utf8.encode('z-connect-commit-v2:'), committed(iEphPub, ivy)]);
  final commitInputR =
      concatBytes([utf8.encode('z-connect-commit-v2:'), committed(rEphPub, rob)]);
  final commitI = await refHmac(inviteKey, commitInputI);
  final commitR = await refHmac(inviteKey, commitInputR);
  check(base64Encode(commitI) == commitFrame['c'], 'v2 inviter commitment');
  check(base64Encode(commitR) == reply['c'], 'v2 acceptor commitment');

  // The channel key: the X25519 output, salted with the invite key.
  final dh = await refDh(iEphSeed, rEphPub);
  final channelKey =
      await refHkdf(dh, inviteKey, utf8b('z-connect-channel-v2'), 32);
  check(eq(sessionI.channelKey, channelKey), 'v2 channel key');
  final aead = Chacha20.poly1305Aead();
  Future<String> sealed(String plain, Uint8List nonce) async => base64Encode(
      (await aead.encrypt(utf8.encode(plain),
              secretKey: SecretKey(channelKey), nonce: nonce))
          .concatenation());
  final openPlain = jsonEncode(
      {'code': ivy.contactCode, 'name': 'Ivy', connectGroupMember: 0});
  final revealPlain = jsonEncode(
      {'code': rob.contactCode, 'name': 'Rob', connectGroupMember: 0});
  check(await sealed(openPlain, openNonce) == open['blob'], 'v2 message 3');
  check(await sealed(revealPlain, revealNonce) == reveal['blob'],
      'v2 message 4');

  // The digits, under their own context.
  final aFirst = hex(ivy.accountEdPub).compareTo(hex(rob.accountEdPub)) < 0;
  final lo = aFirst ? ivy : rob, hi = aFirst ? rob : ivy;
  final sasSalt =
      concatBytes([aFirst ? iEphPub : rEphPub, aFirst ? rEphPub : iEphPub]);
  Uint8List sasInfo(String ctx) => concatBytes([
        utf8.encode(ctx),
        lo.accountEdPub,
        lo.pqCommit,
        hi.accountEdPub,
        hi.pqCommit,
      ]);
  String digits(Uint8List okm) {
    var n = 0;
    for (var i = 0; i < 7; i++) {
      n = (n << 8) | okm[i];
    }
    final s = (n % 100000000).toString().padLeft(8, '0');
    return '${s.substring(0, 4)} ${s.substring(4)}';
  }

  final sasOkm = await refHkdf(dh, sasSalt, sasInfo('z-connect-sas-v2'), 8);
  check(digits(sasOkm) == sessionI.sas, 'v2 SAS');

  // What version 1 computes from the very same inputs — none of it is used.
  final v1Commit = await refSha256(
      concatBytes([utf8.encode('z-connect-commit-v1:'), committed(iEphPub, ivy)]));
  final v1Channel =
      await refHkdf(dh, Uint8List(32), utf8b('z-connect-channel-v1'), 32);
  final v1Sas =
      digits(await refHkdf(dh, sasSalt, sasInfo('z-connect-sas-v1'), 8));
  check(!eq(v1Commit, commitI) && !eq(v1Channel, channelKey),
      'v2 is not v1');

  final tag = await sessionI.goAheadTag();
  check(eq(tag, await sessionR.goAheadTag()), 'one tag at both ends');

  return {
    'suite': 'connect_invite_v2',
    'version': vectorsVersion,
    'description':
        'An invite of version 2 (PROTOCOL 20.8, ADR 0024): the connect '
            'ceremony bound to its secret. Both renderings start with the '
            'marker "9", which no base32 parser accepts, so a client from '
            'before it refuses the invite rather than running version 1. '
            'invite_key = HKDF-SHA256(secret, salt="", '
            'info="z-connect-invite-v2", 32). Each commitment is '
            'HMAC-SHA256(invite_key, "z-connect-commit-v2:" || eph || '
            'u16be(len(code)) || code || name); the channel key is '
            'HKDF-SHA256(dh, salt=invite_key, info="z-connect-channel-v2", 32); '
            'the digits are computed as in connect.json under '
            '"z-connect-sas-v2"; the mailboxes and the rendezvous id as in '
            'mailboxes.json and connect.json under "z-connect-relay-v2:" and '
            '"z-connect-rendezvous-v2:". The frames have the same members and '
            'lengths as version 1. A party without the secret — the relay '
            'carrying the frames — can derive none of these keys, so a frame '
            'it substitutes is refused before either side has the other\'s '
            'identity. version_1_of_the_same_inputs records what version 1 '
            'computes from the same ephemerals and identities; a client of '
            'version 2 computes none of it. The go-ahead tag is derived from '
            'the channel key exactly as group.json shows.',
    'connect_code': {
      'secret': hex(code.secret),
      'version': 2,
      'text': code.text,
      'link': code.link(),
      'marker': connectV2Marker,
      'text_as_version_1': v1.text,
      'rendezvous_input': hex(rvInput),
      'rendezvous_routing_id': rendezvous,
    },
    'invite_key': {
      'info': hex(keyInfo),
      'salt': '',
      'key': hex(inviteKey),
    },
    'mailboxes': mailboxes,
    'distinct_from': distinct,
    'parties': raw,
    'inviter_ephemeral': {'seed': hex(iEphSeed), 'pub': hex(iEphPub)},
    'acceptor_ephemeral': {'seed': hex(rEphSeed), 'pub': hex(rEphPub)},
    'commitments': {
      'inviter_input': hex(commitInputI),
      'inviter': hex(commitI),
      'acceptor_input': hex(commitInputR),
      'acceptor': hex(commitR),
    },
    'reveals': {
      'open_plaintext': openPlain,
      'open_nonce': hex(openNonce),
      'reveal_plaintext': revealPlain,
      'reveal_nonce': hex(revealNonce),
    },
    'frames': {
      'commit': {'k': 'x1', ...commitFrame},
      'reply': {'k': 'x2', ...reply},
      'open': {'k': 'x3', ...open},
      'reveal': {'k': 'x4', ...reveal},
    },
    'dh': hex(dh),
    'channel_key': hex(channelKey),
    'sas_salt': hex(sasSalt),
    'sas_info': hex(sasInfo('z-connect-sas-v2')),
    'sas_okm': hex(sasOkm),
    'sas': sessionI.sas,
    'canonical_order':
        aFirst ? ['inviter', 'acceptor'] : ['acceptor', 'inviter'],
    'go_ahead_tag': hex(tag),
    'version_1_of_the_same_inputs': {
      'inviter_commitment': hex(v1Commit),
      'channel_key': hex(v1Channel),
      'sas': v1Sas,
    },
  };
}

Future<Map<String, Object?>> suitePairingV2(List<Actor> a) async {
  final d = Drbg(0x0017);
  final code = PairingCode(d.next(10));
  final relayI = await RelayPairing.relayIdentityV2(code, 'i');
  final relayR = await RelayPairing.relayIdentityV2(code, 'r');
  final okmI = await refHkdf(
      code.secret, Uint8List(0), utf8.encode('z-pair-relay-v2:i'), 64);
  check(eq(okmI.sublist(0, 32), relayI.edSeed), 'v2 relay identity i');
  check(await relayI.routingId() != await (await RelayPairing.relayIdentity(code, 'i')).routingId(),
      'v2 mailbox is not the v1 mailbox');

  final me = await d.run(() => AccountIdentity.generate());
  d.takeDraws();
  final n = await d.run(
      () => PairingInitiatorV2.create(code: code, deviceId: 'new-phone'));
  final nDraws = d.takeDraws();
  check(nDraws.length == 3 && eq(nDraws[2], n.ephXSeed), 'v2 initiator draws');

  // Message 1: the commitment, over every field the host will certify.
  final commitInput = concatBytes([
    utf8.encode('z-pair-commit-v2:'),
    n.ephXPub,
    n.deviceEdPub,
    n.deviceXPub,
    utf8.encode(n.deviceId),
  ]);
  final commitment = await refSha256(commitInput);
  final commitFrame = await n.commit();
  check(base64Encode(commitment) == commitFrame['c'], 'v2 commitment');

  // Message 2: the responder answers without having seen the opening.
  final (reply, pending) = await d.run(() => PairingResponderV2.reply(commitFrame));
  final rDraws = d.takeDraws();
  check(rDraws.length == 1, 'v2 responder draws');
  final rEphSeed = rDraws[0];
  final rEphPub = await refXPub(rEphSeed);
  check(base64Encode(rEphPub) == reply['ephx'], 'v2 responder eph labelling');

  // Message 3: the opening, checked against the commitment.
  final (open, sessionI) = await n.open(reply);
  final sessionR = await pending.accept(open);
  check(
      eq(sessionI.channelKey, sessionR.channelKey) && sessionI.sas == sessionR.sas,
      'v2 pairing agreement');

  final dh = await refDh(n.ephXSeed, rEphPub);
  final channelKey =
      await refHkdf(dh, Uint8List(32), utf8.encode('z-pair-channel-v2'), 32);
  check(eq(channelKey, sessionI.channelKey), 'v2 channel key');
  // Role order, not lexicographic: v2's commitment already fixes the roles.
  final sasSalt = concatBytes([n.ephXPub, rEphPub]);
  final sasInfo = concatBytes([
    utf8.encode('z-pair-sas-v2'),
    n.deviceEdPub,
    n.deviceXPub,
    utf8.encode(n.deviceId),
  ]);
  final sasOkm = await refHkdf(dh, sasSalt, sasInfo, 8);
  var sasN = 0;
  for (var i = 0; i < 7; i++) {
    sasN = (sasN << 8) | sasOkm[i];
  }
  final sasDigits = (sasN % 100000000).toString().padLeft(8, '0');
  final sasText =
      '${sasDigits.substring(0, 4)} ${sasDigits.substring(4)}';
  check(sasText == sessionI.sas, 'v2 SAS');

  // The substitution v1 allowed: the same ceremony with only `dx` changed
  // must produce a DIFFERENT string, or nothing on the screen would say so.
  // A literal seed, not a DRBG draw: `next()` records every draw, and this
  // one is the generator's own arithmetic rather than a protocol random.
  final attackerXPub = await refXPub(
      Uint8List.fromList(List<int>.generate(32, (i) => (i * 7 + 3) & 0xff)));
  final swappedInfo = concatBytes([
    utf8.encode('z-pair-sas-v2'),
    n.deviceEdPub,
    attackerXPub,
    utf8.encode(n.deviceId),
  ]);
  final swappedOkm = await refHkdf(dh, sasSalt, swappedInfo, 8);
  check(!eq(swappedOkm, sasOkm), 'v2 SAS covers the ratchet key');

  final bobBundle = await AccountBundle.decode(
      (await a[1].id.bundle(displayName: 'Bob')).encode());
  final sealed = await d.run(() => sessionR.sealEnrollment(me,
      contacts: [bobBundle], includeAccountRoot: false, displayName: 'Alice'));
  final sDraws = d.takeDraws();
  check(sDraws.length == 1 && eq(sDraws[0], sealed.sublist(0, 12)),
      'v2 enrollment nonce');
  final data = await sessionI.openEnrollment(sealed);
  final installed = await n.installFromData(data);
  check(eq(installed.deviceEdPub, n.deviceEdPub) && !installed.holdsAccountRoot,
      'v2 install');
  final cert = await sessionR.signedPeerCert(me);
  check(eq(cert.deviceXPub, n.deviceXPub),
      'the certificate binds the ratchet key the SAS covered');
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
  check(utf8.decode(box) == plaintext, 'v2 enrollment plaintext');

  return {
    'suite': 'pairing_v2',
    'version': vectorsVersion,
    'description':
        'Device pairing v2 (PROTOCOL 10.1): commitment, reply, opening. The '
            'initiator commits to its ephemeral AND to every field the host '
            'will certify before the responder chooses its own ephemeral, and '
            'the eight-digit SAS covers all of them — so neither side can aim '
            'the SAS at a value it has already read aloud, and a rendezvous '
            'frame whose ratchet key was rewritten no longer reads the same '
            'on both screens.',
    'pairing_code': {
      'secret': hex(code.secret),
      'text': code.text,
      'rendezvous_input': hex(
          concatBytes([utf8.encode('z-pair-rendezvous-v2:'), code.secret])),
      'rendezvous_routing_id': await code.rendezvousRoutingIdV2(),
    },
    'relay_identities': {
      for (final (role, id, okm) in [
        ('i', relayI, okmI),
        (
          'r',
          relayR,
          await refHkdf(code.secret, Uint8List(0),
              utf8.encode('z-pair-relay-v2:r'), 64)
        ),
      ])
        role: {
          'hkdf_info': 'z-pair-relay-v2:$role',
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
      'commit_input': hex(commitInput),
      'commit_frame': {'k': 'commit-v2', ...commitFrame},
      'open_frame': {'k': 'open-v2', ...open},
    },
    'existing_device': {
      'eph_seed': hex(rEphSeed),
      'eph_pub': hex(rEphPub),
      'reply_frame': {'k': 'reply-v2', ...reply},
    },
    'dh': hex(dh),
    'channel_key': hex(channelKey),
    'sas_salt': hex(sasSalt),
    'sas_info': hex(sasInfo),
    'sas_okm': hex(sasOkm),
    'sas': sasText,
    'enrollment': {
      'new_device_cert_signing_input': hex(DeviceCertificate.signingInput(
          n.deviceEdPub, n.deviceXPub, n.deviceId)),
      'new_device_cert_sig': hex(cert.sig),
      'plaintext': plaintext,
      'nonce': hex(sealed.sublist(0, 12)),
      'sealed': hex(sealed),
      'enroll_frame': {'k': 'enroll-v2', 'blob': base64Encode(sealed)},
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
    // 7.7a device-list removal notice.
    InnerMessage.deviceListRemoved('mid-dlrm', ts,
        acct: Uint8List.fromList(List.filled(32, 0x11)),
        v: 4,
        h: Uint8List.fromList(List.filled(16, 0x22))),
    // 7.7a: any inner may carry the device-list claim ('dl') and the echo of
    // the recipient's list ('pdl'). Shown here on a text message.
    InnerMessage.text('mid-dl', ts, 'gossip rides here')
      ..data['dl'] = {'v': 3, 'h': base64Encode(List.filled(16, 0x33))}
      ..data['pdl'] = {'v': 1, 'h': base64Encode(List.filled(16, 0x44))},
    // 7.4: a voice note is a file offer with the optional voice/dur members.
    InnerMessage(kind: 'file', mid: 'mid-voice', ts: ts, data: {
      'fid': 'AAECAwQFBgcICQoM',
      'name': 'voice-1700000000000.m4a',
      'size': 48000,
      'mime': 'audio/mp4',
      'sha256': base64Encode(List.filled(32, 0xcd)),
      'fk': base64Encode(List.filled(32, 0x03)),
      'fn': base64Encode(List.filled(16, 0x04)),
      'chunks': 1,
      'voice': true,
      'dur': 7,
    }),
    // 8.1: a reply carries only the quoted message's id ('rt'), never its
    // text — 1:1 and in a group.
    InnerMessage.text('mid-reply', ts, 'yes, 7am works', replyTo: 'mid-text'),
    InnerMessage(kind: 'gmsg', mid: 'mid-greply', ts: ts, data: {
      'gid': 'gAAECAwQFBgcICQoL',
      'body': 'me too',
      'rt': 'mid-gmsg',
    }),
    // 8.1b: a reaction names its target and one emoji; the empty emoji
    // withdraws it.
    InnerMessage.reaction('mid-react', ts, target: 'mid-text', emoji: '👍'),
    InnerMessage.reaction('mid-unreact', ts, target: 'mid-text', emoji: ''),
    InnerMessage.reaction('mid-greact', ts,
        target: 'mid-gmsg', emoji: '🎉', gid: 'gAAECAwQFBgcICQoL'),
    // 8.1c: edit and delete-for-everyone name the sender's OWN messages; the
    // receiver enforces that, the wire format merely asks.
    InnerMessage.edit('mid-edit', ts,
        target: 'mid-text', body: 'hello there (fixed)'),
    InnerMessage.edit('mid-gedit', ts,
        target: 'mid-gmsg', body: 'who is in? (fixed)',
        gid: 'gAAECAwQFBgcICQoL'),
    InnerMessage.deleteForEveryone('mid-del', ts,
        targets: ['mid-text', 'mid-voice']),
    InnerMessage.deleteForEveryone('mid-gdel', ts,
        targets: ['mid-gmsg'], gid: 'gAAECAwQFBgcICQoL'),
    // A forwarded message is an ordinary one with a marker.
    InnerMessage.text('mid-fw', ts, 'passing this on')..data['fw'] = true,
    // ADR 0019: a list that carries its roles — the owner, every admin (the
    // owner included) and the roles version. A client from before 0019
    // ignores all three; one after reads their absence as "the sender owns
    // the group and is its only admin, roles version 0".
    InnerMessage(kind: 'ginvite', mid: 'mid-ginvite-roles', ts: ts, data: {
      'gid': 'gAAECAwQFBgcICQoL',
      'name': 'Weekend plans',
      'ver': 3,
      'owner': a[0].rid,
      'admins': [a[0].rid, a[1].rid]..sort(),
      'rv': 1,
      'members': [
        {'b': aliceBundle, 'n': 'Alice'},
        {'b': bobBundle, 'n': 'Bob'},
      ],
    }),
    // ADR 0019: a member that had to refuse a list asks the owner — or an
    // admin whose leave it may have missed — for what it lacks; the answer
    // is that admin's `ginvite`, and its `gleave` if it has left. Keyless:
    // the group id is all it says.
    InnerMessage(
        kind: 'gsync',
        mid: 'mid-gsync',
        ts: ts,
        data: {'gid': 'gAAECAwQFBgcICQoL'}),
    // ADR 0020: a joiner's answer to a group invite link, sent over the new
    // pairwise session once its person was told, before the digits, that
    // the invite was to a group and answered: `go` 1 to join, 0 to stay a
    // contact only. It names no group — only the receiver knows which group
    // its invite was for — and `t`, the ceremony's go-ahead tag (§20.6),
    // says which invite it answers. (Sixteen fixed bytes here; group.json
    // records a real one, derived from a recorded channel key.)
    InnerMessage(kind: 'gjoin', mid: 'mid-gjoin', ts: ts, data: {
      't': b64url(Uint8List.fromList(List<int>.generate(16, (i) => i))),
      'go': 1,
    }),
  ];
  final vectors = <Map<String, Object?>>[];
  for (final m in kinds) {
    final bytes = m.toBytes();
    final back = InnerMessage.fromBytes(bytes);
    check(back.kind == m.kind && back.mid == m.mid && back.ttlSec == m.ttlSec,
        'inner round trip');
    check(back.replyTo == m.replyTo, 'reply id round trip');
    check(back.deleteTargets.length == m.deleteTargets.length, 'del targets');
    check(back.reactionData?.emoji == m.reactionData?.emoji, 'reaction rt');
    check(back.reactionData?.target == m.reactionData?.target, 'reaction tgt');
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
  // PROTOCOL §11.1: the digest that ranks two lists at one `(rv, ver)`,
  // computed here from the section's own words — the two `ginvite`s above,
  // and one more whose name needs every escape the canonical JSON has and
  // whose `admins` and members arrive unsorted. The bytes hashed are
  // recorded too, so a second implementation can compare those first.
  final lists = <Map<String, Object?>>[
    for (final m in kinds)
      if (m.kind == 'ginvite') m.data,
    {
      'gid': 'gAAECAwQFBgcICQoL',
      // An unpaired surrogate can arrive too — as `\ud800` in the JSON —
      // and is written back the same way.
      'name': 'Caf\u00e9 "plans" \\ / \b\f\n\r\t\u0001\u007f \u2028 \u{1F389} '
          '${String.fromCharCode(0xD800)}.',
      'ver': 4,
      'owner': a[1].rid,
      'admins': [a[1].rid, a[0].rid],
      'rv': 2,
      'members': [
        {'b': bobBundle, 'n': 'Bob'},
        {'b': aliceBundle, 'n': 'Alice'},
      ],
    },
  ];
  final listDigests = <Map<String, Object?>>[];
  for (final d in lists) {
    final admins = d['admins'] as List?;
    final canonical = jsonEncode([
      d['gid'],
      d['name'],
      d['ver'],
      d['rv'],
      d['owner'],
      admins == null ? null : ([...admins.cast<String>()]..sort()),
      [
        for (final m in d['members'] as List)
          ((m as Map)['b'] as Map)['ed'] as String
      ]..sort(),
    ]);
    final bytes = utf8.encode(canonical);
    listDigests.add({
      'list': jsonEncode(d),
      'canonical': canonical,
      'canonical_hex': hex(bytes),
      'digest': b64url(await sha256Bytes(bytes)),
    });
  }
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
    'group_list_digests': listDigests,
  };
}

/// ADR 0030 (PROTOCOL §11.2): a group's timer and its members' join
/// positions, as the lists carry them, and the state digest that ranks two
/// lists §11.1's digest calls equal — computed here from the section's own
/// words, sharing no code with the client (`app/test/group_timers_test` 8
/// checks the client against this file). Appended as a file of its own: the
/// files already in `v1/` are untouched.
Future<Map<String, Object?>> suiteGroupState(List<Actor> a) async {
  const ts = 1700000000000;
  const gid = 'gAAECAwQFBgcICQoL';
  final alice = (await a[0].id.bundle(displayName: 'Alice')).toJson();
  final bob = (await a[1].id.bundle(displayName: 'Bob')).toJson();
  final carol = (await a[2].id.bundle(displayName: 'Carol')).toJson();
  final roles = {
    'owner': a[0].rid,
    'admins': [a[0].rid, a[1].rid]..sort(),
    'rv': 1,
  };
  final lists = <Map<String, Object?>>[
    // A list as every client before ADR 0030 writes it: no timer, nobody
    // added after the group was made.
    {
      'gid': gid,
      'name': 'Weekend plans',
      'ver': 6,
      ...roles,
      'members': [
        {'b': alice, 'n': 'Alice'},
        {'b': bob, 'n': 'Bob'},
      ],
    },
    // The same list, and the next version, set to an hour by one admin...
    {
      'gid': gid,
      'name': 'Weekend plans',
      'ver': 7,
      ...roles,
      'tmr': 3600,
      'members': [
        {'b': alice, 'n': 'Alice'},
        {'b': bob, 'n': 'Bob'},
      ],
    },
    // ...and to a minute by another, at that same version: one list to
    // §11.1's digest, which leaves the timer out; the state digest decides.
    {
      'gid': gid,
      'name': 'Weekend plans',
      'ver': 7,
      ...roles,
      'tmr': 60,
      'members': [
        {'b': alice, 'n': 'Alice'},
        {'b': bob, 'n': 'Bob'},
      ],
    },
    // Carol, who left, added back by the list at (1, 8) — so she is named at
    // that position — and Bob, added by the list at (0, 3), with the timer
    // since turned off, which the list says as `0`; the entries arrive in
    // the opposite order to the one their positions sort in.
    {
      'gid': gid,
      'name': 'Weekend plans',
      'ver': 9,
      ...roles,
      'tmr': 0,
      'members': [
        {
          'b': carol,
          'n': 'Carol',
          'e': [1, 8],
        },
        {'b': alice, 'n': 'Alice'},
        {
          'b': bob,
          'n': 'Bob',
          'e': [0, 3],
        },
      ],
    },
  ];
  String digestText(Map<String, Object?> d) {
    final admins = d['admins'] as List?;
    return jsonEncode([
      d['gid'],
      d['name'],
      d['ver'],
      d['rv'],
      d['owner'],
      admins == null ? null : ([...admins.cast<String>()]..sort()),
      [
        for (final m in d['members'] as List)
          ((m as Map)['b'] as Map)['ed'] as String
      ]..sort(),
    ]);
  }

  // §11.2: `[tmr, positions]` — the timer or null, and for each member
  // entry carrying `e` the string `<ed> <rv> <ver>`, sorted.
  String stateText(Map<String, Object?> d) {
    final positions = <String>[
      for (final m in d['members'] as List)
        if ((m as Map)['e'] is List)
          '${(m['b'] as Map)['ed']} ${(m['e'] as List)[0]} '
              '${(m['e'] as List)[1]}'
    ]..sort();
    return jsonEncode([d['tmr'], positions]);
  }

  final out = <Map<String, Object?>>[];
  for (final d in lists) {
    final state = stateText(d);
    out.add({
      'list': jsonEncode(d),
      'digest': b64url(await sha256Bytes(utf8.encode(digestText(d)))),
      'state_canonical': state,
      'state_canonical_hex': hex(utf8.encode(state)),
      'state_digest': b64url(await sha256Bytes(utf8.encode(state))),
    });
  }
  check(out[1]['digest'] == out[2]['digest'], 'the tie is a tie');
  final first = (out[1]['state_digest'] as String)
              .compareTo(out[2]['state_digest'] as String) <
          0
      ? 1
      : 2;
  final inner = <Map<String, Object?>>[];
  for (final m in [
    InnerMessage(kind: 'ginvite', mid: 'mid-ginvite-tmr', ts: ts,
        data: lists[3]),
    // Carol leaving again: the position of the membership she leaves.
    InnerMessage(kind: 'gleave', mid: 'mid-gleave-e', ts: ts, data: {
      'gid': gid,
      'e': [1, 8],
    }),
    // A group text sent while the group's timer is an hour: §6.1's `ttl`.
    InnerMessage(kind: 'gmsg', mid: 'mid-gmsg-ttl', ts: ts, ttlSec: 3600,
        data: {'gid': gid, 'body': 'gone in an hour'}),
  ]) {
    final bytes = m.toBytes();
    final back = InnerMessage.fromBytes(bytes);
    check(back.kind == m.kind && back.ttlSec == m.ttlSec, 'round trip');
    inner.add({
      'kind': m.kind,
      'json': utf8.decode(bytes),
      'bytes': hex(bytes),
      if (m.kind == 'ginvite') 'tmr': m.data['tmr'],
      if (m.kind == 'ginvite')
        'state_digest':
            b64url(await sha256Bytes(utf8.encode(stateText(m.data)))),
      if (m.kind == 'gmsg') 'ttl': m.ttlSec,
    });
  }
  return {
    'suite': 'group_state',
    'version': vectorsVersion,
    'description':
        'ADR 0030: a group list\'s timer (`tmr`) and its members\' join '
            'positions (`e`), and the state digest that ranks two lists at '
            'one (rv, ver) whose §11.1 digests are equal — SHA-256 of the '
            'compact JSON [tmr, positions], positions the sorted strings '
            '"<ed> <rv> <ver>" of the entries that carry one; plus a '
            'ginvite, a gleave and a gmsg carrying the new members.',
    'lists': out,
    'tie': {'a': 1, 'b': 2, 'first': first},
    'inner': inner,
  };
}

// ---------------------------------------------------------------------------
// v2 — post-quantum hybrid
// ---------------------------------------------------------------------------

/// ML-KEM-768 known-answer vectors produced by the library from fixed seeds.
/// They are NOT self-certifying: `tool/verify_mlkem.py` re-derives every one
/// with kyber-py (an independent implementation validated against the NIST
/// KATs) in CI. Includes implicit-rejection cases (a flipped ciphertext byte
/// must decapsulate to a different, deterministic secret).
Future<Map<String, Object?>> suiteMlKem() async {
  final d = Drbg(0x0020);
  final vectors = <Map<String, Object?>>[];
  for (var i = 0; i < 10; i++) {
    final seed = d.next(64);
    final m = d.next(32);
    final (ek, dk) = pqKeyPairFromSeed(seed);
    final (ct, k) = pqEncapsulate(ek, m: m);
    check(eq(pqDecapsulate(seed, ct), k), 'decaps');
    final bad = Uint8List.fromList(ct);
    bad[i * 97 % bad.length] ^= 0x01;
    final kBad = pqDecapsulate(seed, bad);
    check(!eq(kBad, k), 'implicit rejection');
    vectors.add({
      'd': hex(seed.sublist(0, 32)),
      'z': hex(seed.sublist(32)),
      'ek': hex(ek),
      'dk': hex(dk),
      'm': hex(m),
      'c': hex(ct),
      'K': hex(k),
      'c_bad': hex(bad),
      'K_bad': hex(kBad),
    });
  }
  return {
    'suite': 'mlkem768',
    'version': vectorsVersionPq,
    'description':
        'ML-KEM-768 (FIPS 203) known answers: KeyGen_internal(d, z) -> (ek, dk); '
            'Encaps_internal(ek, m) -> (K, c); Decaps(dk, c) -> K; and implicit '
            'rejection Decaps(dk, c_bad) -> K_bad. Verified against kyber-py by '
            'tool/verify_mlkem.py.',
    'vectors': vectors,
  };
}

Map<String, Object?> pqStateJson(PqState p) => {
      'dk_seed': p.dkSeed == null ? null : hex(p.dkSeed!),
      'k': p.k == null ? null : hex(p.k!),
      'ct': p.ct == null ? null : hex(p.ct!),
      'acked': p.acked,
      'offered': p.offered,
      // 7.5b generation fields — emitted only once a re-key is involved, so the
      // generation-0 transcript (pq_ratchet.json) is byte-unchanged.
      if (p.gen > 0) 'gen': p.gen,
      if (p.oldGen != null) 'old_gen': p.oldGen,
      if (p.oldK != null) 'old_k': hex(p.oldK!),
      if (p.offerGen > 0) 'offer_gen': p.offerGen,
    };

/// The v2 upgrade transcript: classical hello, the offerer's `pqek` offer,
/// the encapsulator's first mixed message carrying `pqct`, the offerer's
/// mixed reply, and the steady state. Everything a v1 implementation already
/// does is unchanged; this suite pins what v2 adds.
Future<Map<String, Object?>> suitePqRatchet(List<Actor> a) async {
  final alice = a[0], bob = a[1];
  final d = Drbg(0x0021);
  final convA = await Conversation.create(
      alice.id, await bob.id.bundle(displayName: bob.displayName),
      intervals: PqIntervals.disabled);
  final convB = await Conversation.create(
      bob.id, await alice.id.bundle(displayName: alice.displayName),
      intervals: PqIntervals.disabled);
  // Roles are fixed by routing-id order (the designated initiator
  // encapsulates, the other side offers); resolve them from the actors.
  final enc = convA.isDesignatedInitiator ? 'alice' : 'bob';
  final off = enc == 'alice' ? 'bob' : 'alice';
  final convs = {'alice': convA, 'bob': convB};
  final convEnc = convs[enc]!, convOff = convs[off]!;
  check(convEnc.isDesignatedInitiator && convOff.isPqOfferer, 'roles');
  final steps = <Map<String, Object?>>[];

  Future<Map<String, Object?>> stepEncrypt(
      String by, String label, Uint8List plaintext) async {
    final conv = convs[by]!;
    final pqBefore = conv.pq.clone();
    final payload = await d.run(() => conv.encrypt(plaintext, nowMs: 1));
    final draws = d.takeDraws();
    final j = jsonDecode(utf8.decode(base64Decode(payload))) as Map;
    final header = (j['h'] as Map).cast<String, Object?>();
    final sid = conv.outboundSid!;
    final st = conv.sessions[sid]!.ratchet;
    final step = <String, Object?>{
      'op': 'encrypt',
      'by': by,
      'label': label,
      'sid': sid,
      'plaintext': hex(plaintext),
      'random_draws': [for (final x in draws) hex(x)],
      'header': header,
      'header_bytes': hex(RatchetHeader.fromJson(header).encode()),
      'pq_before': pqStateJson(pqBefore),
      'pq_after': pqStateJson(conv.pq),
      'ck_after': hex(st.cks!),
      'payload': payload,
    };
    steps.add(step);
    return step;
  }

  Future<Map<String, Object?>> stepDecrypt(
      String by, String label, String payload) async {
    final conv = convs[by]!;
    final pqBefore = conv.pq.clone();
    final res = await d.run(() => conv.decrypt(payload, nowMs: 2));
    final draws = d.takeDraws();
    final step = <String, Object?>{
      'op': 'decrypt',
      'by': by,
      'label': label,
      'sid': res.sid,
      'payload': payload,
      'plaintext': hex(res.plaintext),
      'random_draws': [for (final x in draws) hex(x)],
      'pq_before': pqStateJson(pqBefore),
      'pq_after': pqStateJson(conv.pq),
      'offer_payload': res.pqOfferPayload,
      'is_post_quantum': conv.isPostQuantum,
    };
    steps.add(step);
    return step;
  }

  const ts = 1700000000000;
  // 1. the encapsulator opens with a classical hello.
  final s1 = await stepEncrypt(
      enc,
      'm1 hello from the encapsulator (classical)',
      InnerMessage.hello('m1', ts).toBytes());
  // 2. the offerer decrypts it and produces the pqek offer.
  final s2 = await stepDecrypt(
      off, 'offerer receives m1; offers ML-KEM key', s1['payload'] as String);
  check(s2['offer_payload'] != null, 'offer produced');
  final offerPayload = s2['offer_payload'] as String;
  final offerJ = jsonDecode(utf8.decode(base64Decode(offerPayload))) as Map;
  final offerHeader = (offerJ['h'] as Map).cast<String, Object?>();
  final dkSeed = unhex((s2['pq_after'] as Map)['dk_seed'] as String);
  final (ek, dk) = pqKeyPairFromSeed(dkSeed);
  // 3. the encapsulator decrypts the offer: its DH step, then it encapsulates.
  final s3 = await stepDecrypt(
      enc, 'encapsulator receives the offer; encapsulates', offerPayload);
  final offerInner = InnerMessage.fromBytes(unhex(s3['plaintext'] as String));
  check(offerInner.kind == 'pqek' && offerInner.data['ek'] == base64Encode(ek),
      'offer inner');
  final kA = unhex((s3['pq_after'] as Map)['k'] as String);
  final ct = unhex((s3['pq_after'] as Map)['ct'] as String);
  final m = (s3['random_draws'] as List).last as String; // last draw = m
  final (ct2, k2) = pqEncapsulate(ek, m: unhex(m));
  check(eq(ct2, ct) && eq(k2, kA), 'encaps from recorded m');
  check(eq(pqDecapsulate(dkSeed, ct), kA), 'decaps');
  // 4. the encapsulator's first mixed message, carrying the ciphertext.
  final s4 = await stepEncrypt(enc, 'm2 first pq message (+pqct)',
      InnerMessage.text('m2', ts + 1, 'quantum-safe hello').toBytes());
  check(
      (s4['header'] as Map)['pq'] == 1 && (s4['header'] as Map)['pqct'] != null,
      'pq header');
  // 5. the offerer decapsulates and decrypts.
  await stepDecrypt(
      off, 'offerer receives m2; decapsulates', s4['payload'] as String);
  check(
      hex(convOff.pq.k!) == hex(kA) && convOff.pq.dkSeed == null, 'offerer K');
  // 6. the offerer's mixed reply (flag only).
  final s6 = await stepEncrypt(off, 'm3 pq reply (flag only)',
      InnerMessage.text('m3', ts + 2, 'same here').toBytes());
  check(
      (s6['header'] as Map)['pq'] == 1 && (s6['header'] as Map)['pqct'] == null,
      'reply header');
  // 7. the encapsulator learns the peer holds K and stops attaching it.
  await stepDecrypt(enc, 'encapsulator receives m3; ciphertext acknowledged',
      s6['payload'] as String);
  check(convEnc.pq.acked, 'acked');
  final s8 = await stepEncrypt(enc, 'm4 steady state',
      InnerMessage.text('m4', ts + 3, 'steady').toBytes());
  check((s8['header'] as Map)['pqct'] == null, 'no more ct');
  await stepDecrypt(off, 'offerer receives m4', s8['payload'] as String);
  // Sanity: a v1 receiver cannot decrypt a pq message (no shared secret).
  final v1 = await Conversation.create(convOff.me, await convEnc.me.bundle(),
      postQuantum: false, intervals: PqIntervals.disabled);
  var v1Failed = false;
  try {
    await v1.decrypt(s1['payload'] as String); // fine: classical hello
    await v1.decrypt(s4['payload'] as String);
  } on RatchetDecryptException {
    v1Failed = true;
  }
  check(v1Failed, 'v1 rejects pq message');

  return {
    'suite': 'pq_ratchet',
    'version': vectorsVersionPq,
    'description':
        'Protocol v2 upgrade transcript between the designated initiator '
            '(encapsulator) and the other party (offerer). Random draws are recorded per '
            'operation in the order the library makes them; the ML-KEM values '
            'are cross-checked by tool/verify_mlkem.py, the rest by '
            'server/test/vectors.test.js.',
    'encapsulator': enc,
    'offerer': off,
    'mix_info': 'Z-PQ-MK-v2',
    'offer': {
      'dk_seed': hex(dkSeed),
      'ek': hex(ek),
      'dk': hex(dk),
      'inner_json': utf8.decode(unhex(s3['plaintext'] as String)),
      'header': offerHeader,
    },
    'encapsulation': {'m': m, 'c': hex(ct), 'K': hex(kA)},
    'steps': steps,
  };
}

/// 7.5b periodic re-key transcript: a pair reaches the steady generation-0
/// state, then the offerer rotates to generation 1. Pins the second ML-KEM
/// encapsulation, the `pqg` header field, the crossover (an old-generation
/// message still decrypting), and the retained old secret.
Future<Map<String, Object?>> suitePqRekey(List<Actor> a) async {
  final alice = a[0], bob = a[1];
  final d = Drbg(0x0031);
  final convA = await Conversation.create(
      alice.id, await bob.id.bundle(displayName: bob.displayName),
      intervals: PqIntervals.disabled);
  final convB = await Conversation.create(
      bob.id, await alice.id.bundle(displayName: alice.displayName),
      intervals: PqIntervals.disabled);
  final enc = convA.isDesignatedInitiator ? 'alice' : 'bob';
  final off = enc == 'alice' ? 'bob' : 'alice';
  final convs = {'alice': convA, 'bob': convB};
  final convEnc = convs[enc]!, convOff = convs[off]!;
  check(convEnc.isDesignatedInitiator && convOff.isPqOfferer, 'roles');
  final steps = <Map<String, Object?>>[];

  Future<Map<String, Object?>> stepEncrypt(
      String by, String label, Uint8List plaintext,
      {String? using}) async {
    final conv = convs[by]!;
    final pqBefore = conv.pq.clone();
    final payload = using != null
        ? using
        : await d.run(() => conv.encrypt(plaintext, nowMs: 1));
    final draws = d.takeDraws();
    final j = jsonDecode(utf8.decode(base64Decode(payload))) as Map;
    final header = (j['h'] as Map).cast<String, Object?>();
    final step = <String, Object?>{
      'op': 'encrypt',
      'by': by,
      'label': label,
      'sid': conv.outboundSid!,
      'plaintext': hex(plaintext),
      'random_draws': [for (final x in draws) hex(x)],
      'header': header,
      'header_bytes': hex(RatchetHeader.fromJson(header).encode()),
      'pq_before': pqStateJson(pqBefore),
      'pq_after': pqStateJson(conv.pq),
      'payload': payload,
    };
    steps.add(step);
    return step;
  }

  Future<Map<String, Object?>> stepDecrypt(
      String by, String label, String payload,
      {String? rekeyOffer}) async {
    final conv = convs[by]!;
    final pqBefore = conv.pq.clone();
    final res = await d.run(() => conv.decrypt(payload, nowMs: 2));
    final draws = d.takeDraws();
    final step = <String, Object?>{
      'op': 'decrypt',
      'by': by,
      'label': label,
      'sid': res.sid,
      'payload': payload,
      'plaintext': hex(res.plaintext),
      'random_draws': [for (final x in draws) hex(x)],
      'pq_before': pqStateJson(pqBefore),
      'pq_after': pqStateJson(conv.pq),
      'offer_payload': res.pqOfferPayload,
      'is_post_quantum': conv.isPostQuantum,
      'pq_generation': conv.pqGeneration,
    };
    steps.add(step);
    return step;
  }

  const ts = 1700000000000;
  // Establish generation 0 (same shape as pq_ratchet, condensed).
  final e1 =
      await stepEncrypt(enc, 'hello', InnerMessage.hello('k1', ts).toBytes());
  final d1 = await stepDecrypt(off, 'offer gen0', e1['payload'] as String);
  // Capture the generation-0 offer so a clean-room verifier can reproduce it.
  final gen0DkSeed = unhex((d1['pq_after'] as Map)['dk_seed'] as String);
  final (gen0Ek, _) = pqKeyPairFromSeed(gen0DkSeed);
  final de0 =
      await stepDecrypt(enc, 'encapsulate gen0', d1['offer_payload'] as String);
  final gen0OfferJson = utf8.decode(unhex(de0['plaintext'] as String));
  final e2 = await stepEncrypt(enc, 'first mixed (gen0)',
      InnerMessage.text('k2', ts + 1, 'g0').toBytes());
  await stepDecrypt(off, 'offerer decapsulates gen0', e2['payload'] as String);
  final e3 = await stepEncrypt(off, 'offerer reply (gen0)',
      InnerMessage.text('k3', ts + 2, 'ok').toBytes());
  await stepDecrypt(enc, 'ack gen0', e3['payload'] as String);
  check(convEnc.pqGeneration == 0 && convOff.pqGeneration == 0, 'gen0 settled');
  final k0 = hex(convEnc.pq.k!);

  // An old-generation message from the encapsulator, delayed past the re-key.
  final delayed = await stepEncrypt(enc, 'delayed gen0 message',
      InnerMessage.text('k4', ts + 3, 'late g0').toBytes());

  // The offerer starts the re-key; its offer rides an ordinary message.
  final rk = d.run(() => convOff.forcePqRekey(nowMs: 3));
  final rekeyOffer = await rk;
  final rekeyDraws = d.takeDraws();
  check(rekeyOffer != null && convOff.pq.offerGen == 1, 'rekey offered');
  final rekeyDkSeed = hex(convOff.pq.dkSeed!);
  steps.add({
    'op': 'rekey_offer',
    'by': off,
    'label': 'offerer starts re-key to generation 1',
    'payload': rekeyOffer,
    'random_draws': [for (final x in rekeyDraws) hex(x)],
    'pq_after': pqStateJson(convOff.pq),
  });
  final (ek1, dk1) = pqKeyPairFromSeed(unhex(rekeyDkSeed));

  // The encapsulator consumes the re-key offer and encapsulates generation 1.
  final de = await stepDecrypt(
      enc, 'encapsulator receives re-key; encapsulates gen1', rekeyOffer!);
  check(convEnc.pqGeneration == 1 && hex(convEnc.pq.oldK!) == k0,
      'gen1 on enc; gen0 retained');
  final k1 = hex(convEnc.pq.k!);
  final ct1 = hex(convEnc.pq.ct!);
  final m1 = (de['random_draws'] as List).last as String;
  final (ct1b, k1b) = pqEncapsulate(ek1, m: unhex(m1));
  check(eq(ct1b, unhex(ct1)) && eq(k1b, unhex(k1)), 'gen1 encaps from m');

  // The delayed gen-0 message still decrypts on the offerer (old secret).
  await stepDecrypt(off, 'offerer receives the delayed gen0 message',
      delayed['payload'] as String);

  // The encapsulator's first gen-1 message (carries the new ciphertext, pqg=1).
  final e4 = await stepEncrypt(enc, 'first mixed (gen1, +pqct)',
      InnerMessage.text('k5', ts + 4, 'g1').toBytes());
  check(
      (e4['header'] as Map)['pqg'] == 1 &&
          (e4['header'] as Map)['pqct'] != null,
      'gen1 header');
  // The offerer decapsulates generation 1.
  final d4 = await stepDecrypt(
      off, 'offerer decapsulates gen1', e4['payload'] as String);
  check(
      d4['pq_generation'] == 1 && hex(convOff.pq.k!) == k1, 'offerer on gen1');
  check(k1 != k0, 'secret rotated');
  // Steady state on generation 1.
  final e5 = await stepEncrypt(off, 'offerer reply (gen1)',
      InnerMessage.text('k6', ts + 5, 'g1 ok').toBytes());
  await stepDecrypt(enc, 'encapsulator acks gen1', e5['payload'] as String);
  check(convEnc.pq.acked, 'gen1 acked');

  return {
    'suite': 'pq_rekey',
    'version': vectorsVersionPq,
    'description':
        'Protocol v2 periodic re-key (7.5b): after establishing generation 0, '
            'the offerer rotates the ML-KEM secret to generation 1. Pins the '
            'second encapsulation, the pqg header field, the crossover (a '
            'delayed generation-0 message still decrypts), and the retained '
            'old secret. Verified by tool/verify_mlkem.py and '
            'server/test/vectors.test.js.',
    'encapsulator': enc,
    'offerer': off,
    'mix_info': 'Z-PQ-MK-v2',
    'gen0_secret': k0,
    'gen0_offer': {
      'dk_seed': hex(gen0DkSeed),
      'ek_b64': base64Encode(gen0Ek),
      'inner_json': gen0OfferJson,
    },
    'rekey': {
      'dk_seed': rekeyDkSeed,
      'ek': hex(ek1),
      'dk': hex(dk1),
      'm': m1,
      'c': ct1,
      'K': k1,
    },
    'steps': steps,
  };
}

/// Generate every suite: `{ 'v1': {name: doc}, 'v2': {name: doc} }`.
// ---------------------------------------------------------------------------
// Backup archive (§9) — recovery code + `.zbk` frame layer
// ---------------------------------------------------------------------------

Future<Map<String, Object?>> suiteBackup() async {
  final d = Drbg(0x0009);

  // The recovery code: 120 bits, Crockford base32, one checksum character.
  final code = await d.run(() async => RecoveryCode.generate());
  final entropyDraws = d.takeDraws();
  check(entropyDraws.length == 1 && entropyDraws[0].length == 15,
      'recovery code draws 15 bytes and nothing else');
  final formatted = await code.format();
  final material = await code.keyMaterial();
  check(formatted.startsWith('ZBK-') && formatted.length == 4 + 25 + 4,
      'formatted code shape');
  check(utf8.decode(material) == formatted.substring(4).replaceAll('-', ''),
      'key material is the canonical 25 characters');

  // A transcription mangled the way people actually mangle one — lower case,
  // spaces for dashes, letter-o for zero, letter-l for one — parses back to
  // the same 120 bits.
  final mangled = formatted
      .toLowerCase()
      .replaceAll('-', ' ')
      .replaceAll('0', 'o')
      .replaceAll('1', 'l');
  final reparsed = await RecoveryCode.parse(mangled);
  check(eq(reparsed.entropy, code.entropy), 'mangled code parses back');

  // Every character of the code, flipped one at a time, must be caught by the
  // checksum or the alphabet — never silently accepted as a different code.
  var typosCaught = 0, typosTried = 0;
  final canonical = formatted.substring(4).replaceAll('-', '');
  for (var i = 0; i < canonical.length; i++) {
    for (final c in RecoveryCode.alphabet.split('')) {
      if (c == canonical[i]) continue;
      typosTried++;
      final bad = canonical.replaceRange(i, i + 1, c);
      try {
        final got = await RecoveryCode.parse(bad);
        check(!eq(got.entropy, code.entropy), 'a typo cannot be the same code');
      } on FormatException {
        typosCaught++;
      }
    }
  }

  // The archive itself: header line, then sealed frames.
  final salt = d.next(16);
  final noncePrefix = d.next(16);
  final key = await ZArchive.deriveKey(material, salt);
  final keyBytes = Uint8List.fromList(await key.extractBytes());
  const createdMs = 1700000000000;
  const schema = 3;
  final header = ZArchive.buildHeader(
      salt: salt,
      noncePrefix: noncePrefix,
      schema: schema,
      createdMs: createdMs);

  final blobBytes =
      Uint8List.fromList(List.generate(48, (i) => (i * 7) & 0xff));
  final bodies = <(int, List<int>)>[
    (
      ZArchive.kindRecord,
      utf8.encode(jsonEncode(
          {'t': 'meta', 'app': 'z', 'schema': schema, 'name': 'Alice'}))
    ),
    (
      ZArchive.kindRecord,
      utf8.encode(jsonEncode({
        't': 'message',
        'mid': 'm-0001',
        'rid': 'contact-rid',
        'out': 1,
        'kind': 'text',
        'body': 'the survey data is ready',
        'ts': createdMs,
        'status': 2,
        'expire': 0,
      }))
    ),
    (ZArchive.kindBlob, ZArchive.blobPayload('F1', blobBytes)),
    (ZArchive.kindEnd, utf8.encode(jsonEncode({'t': 'end', 'records': 2}))),
  ];

  final frames = <Map<String, Object?>>[];
  final file = BytesBuilder()
    ..add(header)
    ..addByte(0x0a);
  final sealedAll = <Uint8List>[];
  for (var i = 0; i < bodies.length; i++) {
    final (kind, payload) = bodies[i];
    final sealed = await ZArchive.sealFrame(
        key: key,
        header: header,
        noncePrefix: noncePrefix,
        index: i,
        kind: kind,
        payload: payload);
    sealedAll.add(sealed);
    final (gotKind, gotPayload) = await ZArchive.openFrame(
        key: key,
        header: header,
        noncePrefix: noncePrefix,
        index: i,
        sealed: sealed);
    check(gotKind == kind && eq(gotPayload, payload), 'frame $i round trip');
    final nonce = Uint8List(24)..setRange(0, 16, noncePrefix);
    ByteData.view(nonce.buffer).setUint64(16, i);
    final len = ByteData(4)..setUint32(0, sealed.length);
    file
      ..add(len.buffer.asUint8List())
      ..add(sealed);
    frames.add({
      'index': i,
      'kind': kind,
      'nonce': hex(nonce),
      'plaintext': hex([kind, ...payload]),
      if (kind != ZArchive.kindBlob) 'payload_json': utf8.decode(payload),
      'ciphertext': hex(sealed.sublist(0, sealed.length - 16)),
      'mac': hex(sealed.sublist(sealed.length - 16)),
    });
  }
  final (blobFid, blobBack) = ZArchive.parseBlobPayload(
      bodies[2].$2 is Uint8List
          ? bodies[2].$2 as Uint8List
          : Uint8List.fromList(bodies[2].$2));
  check(blobFid == 'F1' && eq(blobBack, blobBytes), 'blob frame body layout');

  // Negative cases, recorded so another implementation can check that it also
  // refuses them: a frame moved to another index, and the wrong code.
  var moved = false;
  try {
    await ZArchive.openFrame(
        key: key,
        header: header,
        noncePrefix: noncePrefix,
        index: 0,
        sealed: sealedAll[1]);
  } on FormatException {
    moved = true;
  }
  check(moved, 'a frame moved to another index fails');

  final wrongKey = await ZArchive.deriveKey(
      await RecoveryCode(Uint8List(15)).keyMaterial(), salt);
  var wrong = false;
  try {
    await ZArchive.openFrame(
        key: wrongKey,
        header: header,
        noncePrefix: noncePrefix,
        index: 0,
        sealed: sealedAll[0]);
  } on FormatException {
    wrong = true;
  }
  check(wrong, 'the wrong recovery code fails');

  final fileBytes = file.takeBytes();
  return {
    'suite': 'backup_archive',
    'version': vectorsVersion,
    'description':
        'Backup archive (.zbk): a plaintext header line, then length-prefixed '
            'XChaCha20-Poly1305 frames under one Argon2id-derived key. '
            'nonce = np(16) || uint64be(index); aad = header_bytes || '
            'uint64be(index), which pins each frame to its position in this '
            'archive. Frame plaintext is [kind byte][body]; the last frame is '
            'the terminator, whose absence means the file was truncated.',
    'recovery_code': {
      'entropy': hex(code.entropy),
      'alphabet': RecoveryCode.alphabet,
      'formatted': formatted,
      'canonical': canonical,
      'key_material': hex(material),
      'checksum_rule': 'sha256(entropy)[0] & 0x1f indexes the alphabet',
      'mangled_input': mangled,
      'typo_variants_tried': typosTried,
      'typo_variants_rejected': typosCaught,
    },
    'kdf': {
      'name': 'argon2id',
      'rfc': 9106,
      'memory_kib': ZArchive.kdfMemoryKib,
      'iterations': ZArchive.kdfIterations,
      'parallelism': ZArchive.kdfParallelism,
      'password': hex(material),
      'salt': hex(salt),
      'tag_len': 32,
      'key': hex(keyBytes),
    },
    'header': {
      'bytes': hex(header),
      'json': utf8.decode(header),
      'nonce_prefix': hex(noncePrefix),
      'aad_rule': 'header_bytes || uint64be(frame_index)',
    },
    'frame_kinds': {
      'record': ZArchive.kindRecord,
      'blob': ZArchive.kindBlob,
      'end': ZArchive.kindEnd,
    },
    'blob_body': {
      'layout': 'uint8 id_len || id || bytes',
      'fid': 'F1',
      'bytes': hex(blobBytes),
    },
    'frames': frames,
    'must_fail': {
      'frame_1_opened_at_index_0': hex(sealedAll[1]),
      'wrong_code_entropy': hex(Uint8List(15)),
    },
    'file': {
      'bytes': hex(fileBytes),
      'len': fileBytes.length,
      'sha256': hex(await refSha256(fileBytes)),
    },
  };
}

/// Format 1.1 of the backup archive (phase 31, `BACKUP.md` §4.1 and §5): the
/// same frame layer as [suiteBackup], under a header that names its minor
/// revision (`mv`), carrying the records minor 1 adds — a linked device's
/// identity with the account it belongs to, the account's device-list and
/// transparency `state`, a contact with its own state and its past session
/// ids, a blocked id, a pending request — and a record of a type no reader
/// knows, marked `keep`, which a reader of this major that does not know it
/// carries into its next archive byte for byte. Plus the refusal: the same
/// header at major version 2.
Future<Map<String, Object?>> suiteBackupMinor1() async {
  final d = Drbg(0x000A);
  final code = await d.run(() async => RecoveryCode.generate());
  d.takeDraws();
  final formatted = await code.format();
  final material = await code.keyMaterial();
  final salt = d.next(16);
  final noncePrefix = d.next(16);
  final key = await ZArchive.deriveKey(material, salt);
  final keyBytes = Uint8List.fromList(await key.extractBytes());
  const createdMs = 1700000000000;
  const schema = 13;
  final header = ZArchive.buildHeader(
      salt: salt,
      noncePrefix: noncePrefix,
      schema: schema,
      createdMs: createdMs,
      minor: ZArchive.minorVersion);
  check(ZArchive.minorVersion == 1, 'this suite pins minor 1');
  final parsedHead = ZArchive.parseHeader(header);
  check(ZArchive.minorOf(parsedHead) == 1 && !ZArchive.isNewerMajor(parsedHead),
      'a minor-1 header reads as minor 1 of this major');

  // The account (a root on a phone) and the device this backup was taken on
  // (a laptop it linked): fixed seeds, Ed25519 signing is deterministic.
  final root = await ZIdentity.fromSeeds(edSeed: d.next(32), xSeed: d.next(32));
  final account = await AccountIdentity.fromV1(root, deviceId: 'phone');
  final laptopId =
      await ZIdentity.fromSeeds(edSeed: d.next(32), xSeed: d.next(32));
  final laptopCert = await account.signDeviceCert(
      deviceEdPub: laptopId.edPub,
      deviceXPub: laptopId.xPub,
      deviceId: 'laptop');
  final laptop = await AccountIdentity.fromEnrollment(
    accountEdPub: account.accountEdPub,
    deviceEdSeed: laptopId.edSeed,
    deviceXSeed: laptopId.xSeed,
    deviceId: 'laptop',
    deviceCert: laptopCert,
  );
  // Dual-signed, named rather than defaulted, so the vector does not move
  // when the stage-2b signer is switched on (ADR 0017).
  final list = await account
      .signDeviceList([account.deviceCert, laptopCert], 2, v2Only: false);
  check(await list.verify(), 'the account list verifies');
  final fp = b64(await list.fingerprint());

  final bob = await ZIdentity.fromSeeds(edSeed: d.next(32), xSeed: d.next(32));
  final carol =
      await ZIdentity.fromSeeds(edSeed: d.next(32), xSeed: d.next(32));
  final mallory =
      await ZIdentity.fromSeeds(edSeed: d.next(32), xSeed: d.next(32));
  final sid = await sessionIdFromEk(d.next(32));

  final records = <Map<String, Object?>>[
    {'t': 'meta', 'app': 'z', 'schema': schema, 'name': 'Alice'},
    {
      't': 'identity',
      'identity': laptopId.toJson(),
      'account': laptop.toJson(),
    },
    {
      't': 'state',
      'kv': {
        'my_devices': jsonEncode([account.deviceCert.toJson()]),
        'my_devlist_version': '2',
        'own_list_v': '2',
        'own_list_h': fp,
        'own_list_json': jsonEncode(list.toJson()),
        'kt_own_known': jsonEncode({'2': fp}),
        'kt_own_first_v': '2',
        'kt_config': jsonEncode({
          'url': 'https://kt.example',
          'pub': b64(Uint8List(32)..fillRange(0, 32, 7)),
          'wurl': '',
          'wpub': '',
        }),
        'push_enabled': '0',
      },
    },
    {
      't': 'contact',
      'rid': await bob.routingId(),
      'bundle': (await bob.bundle(displayName: 'Bob')).toJson(),
      'name': 'Bob',
      'ttl': 0,
      'verified': 0,
      'created': createdMs,
      'req': 1,
      'kv': {'cdev_sigfloor_': '1', 'last_open_': '$createdMs'},
      'sids': [sid],
    },
    {'t': 'blocked', 'rid': await mallory.routingId(), 'created': createdMs},
    {
      't': 'request',
      'rid': await carol.routingId(),
      'bundle': (await carol.bundle(displayName: 'Carol')).toJson(),
      'name': 'Carol',
      'created': createdMs,
    },
    {
      't': 'example',
      ZArchive.keepField: 1,
      'note': 'a reader that does not know this type writes it into its '
          'next archive as it is',
    },
  ];
  final bodies = <(int, List<int>)>[
    for (final r in records)
      (ZArchive.kindRecord, utf8.encode(jsonEncode(r))),
    (
      ZArchive.kindEnd,
      utf8.encode(jsonEncode({'t': 'end', 'records': records.length}))
    ),
  ];

  final frames = <Map<String, Object?>>[];
  final file = BytesBuilder()
    ..add(header)
    ..addByte(0x0a);
  for (var i = 0; i < bodies.length; i++) {
    final (kind, payload) = bodies[i];
    final sealed = await ZArchive.sealFrame(
        key: key,
        header: header,
        noncePrefix: noncePrefix,
        index: i,
        kind: kind,
        payload: payload);
    final (gotKind, gotPayload) = await ZArchive.openFrame(
        key: key,
        header: header,
        noncePrefix: noncePrefix,
        index: i,
        sealed: sealed);
    check(gotKind == kind && eq(gotPayload, payload), 'frame $i round trip');
    final nonce = Uint8List(24)..setRange(0, 16, noncePrefix);
    ByteData.view(nonce.buffer).setUint64(16, i);
    final len = ByteData(4)..setUint32(0, sealed.length);
    file
      ..add(len.buffer.asUint8List())
      ..add(sealed);
    frames.add({
      'index': i,
      'kind': kind,
      'nonce': hex(nonce),
      'plaintext': hex([kind, ...payload]),
      'payload_json': utf8.decode(payload),
      'ciphertext': hex(sealed.sublist(0, sealed.length - 16)),
      'mac': hex(sealed.sublist(sealed.length - 16)),
    });
  }

  // The refusal: the same header one major version on. A reader of this
  // major refuses it on sight, before any key is derived.
  final newer = (jsonDecode(utf8.decode(header)) as Map).cast<String, Object?>()
    ..['v'] = ZArchive.version + 1;
  final newerBytes = Uint8List.fromList(utf8.encode(jsonEncode(newer)));
  var refused = false;
  try {
    ZArchive.parseHeader(newerBytes);
  } on ArchiveTooNewException {
    refused = true;
  }
  check(refused && ZArchive.isNewerMajor(newer), 'a newer major is refused');

  final fileBytes = file.takeBytes();
  return {
    'suite': 'backup_archive_1_1',
    'version': vectorsVersion,
    'description':
        'Backup archive (.zbk), format 1.1: the frame layer of archive.json '
            'unchanged, under a header that names its minor revision ("mv"). '
            'Minor 1 adds a linked device\'s "account" beside its identity, '
            'the account\'s device-list and transparency "state", a '
            'contact\'s own state ("kv"), past session ids ("sids") and '
            'pending flag ("req"), "blocked" and "request" records, and the '
            '"keep" member: a record whose type a reader does not know is '
            'carried into that reader\'s next archive, as the same text, '
            'when it says "keep":1, and skipped when it does not. A header '
            'whose "v" is above the reader\'s major is refused before any '
            'key is derived.',
    'recovery_code': {
      'entropy': hex(code.entropy),
      'formatted': formatted,
      'key_material': hex(material),
    },
    'kdf': {
      'name': 'argon2id',
      'rfc': 9106,
      'memory_kib': ZArchive.kdfMemoryKib,
      'iterations': ZArchive.kdfIterations,
      'parallelism': ZArchive.kdfParallelism,
      'password': hex(material),
      'salt': hex(salt),
      'tag_len': 32,
      'key': hex(keyBytes),
    },
    'header': {
      'bytes': hex(header),
      'json': utf8.decode(header),
      'nonce_prefix': hex(noncePrefix),
      'major': ZArchive.version,
      'minor': ZArchive.minorVersion,
      'aad_rule': 'header_bytes || uint64be(frame_index)',
    },
    'frame_kinds': {
      'record': ZArchive.kindRecord,
      'blob': ZArchive.kindBlob,
      'end': ZArchive.kindEnd,
    },
    'keep_member': ZArchive.keepField,
    'kept_record_index': records.length - 1,
    'frames': frames,
    'must_fail': {
      'newer_major_header': hex(newerBytes),
      'newer_major_header_json': utf8.decode(newerBytes),
    },
    'file': {
      'bytes': hex(fileBytes),
      'len': fileBytes.length,
      'sha256': hex(await refSha256(fileBytes)),
    },
  };
}

// ---------------------------------------------------------------------------
// ML-DSA-65 (FIPS 204) — the v3 hybrid-signature primitive
// ---------------------------------------------------------------------------

Future<Map<String, Object?>> suiteMlDsa() async {
  // Seeded keygen and DETERMINISTIC signing (rnd = 0^32), so every value here
  // is reproducible by any FIPS 204 implementation from the recorded seed and
  // message alone. Production signing is hedged; determinism is a property of
  // the vector, not of the protocol.
  final vectors = <Map<String, Object?>>[];
  for (var i = 0; i < 4; i++) {
    final seed = Uint8List(32)..fillRange(0, 32, i + 1);
    final (pk, sk) = pqDsaKeyPairSeeded(seed);
    final msg = Uint8List.fromList(utf8.encode('z-device-cert-v1:device-$i'));
    final sig = pqDsaSignDeterministic(sk, msg);
    check(pqDsaVerify(pk, msg, sig), 'ml-dsa vector $i verifies');
    // A flipped byte anywhere in the signature must fail.
    final bent = Uint8List.fromList(sig)..[i * 97 % sig.length] ^= 0x01;
    check(!pqDsaVerify(pk, msg, bent), 'ml-dsa vector $i tamper rejected');
    vectors.add({
      'seed': hex(seed),
      'pk': hex(pk),
      'sk': hex(sk),
      'message': utf8.decode(msg),
      'message_hex': hex(msg),
      'signature': hex(sig),
      'tampered_signature': hex(bent),
    });
  }

  // The commitment ADR 0003 puts in a zc3. contact code, in place of the
  // 1952-byte key it binds.
  final kp = await HybridKeyPair.fromSeeds(
      edSeed: Uint8List(32)..fillRange(0, 32, 0xA1),
      mlSeed: Uint8List(32)..fillRange(0, 32, 0xB2));
  final commit = await kp.publicKey.pqCommitment();
  final m = Uint8List.fromList(utf8.encode('z-device-cert-v1:hybrid'));
  // Deterministic: production signing is hedged, so a recorded hedged
  // signature could never be reproduced — which the freeze test catches.
  final hs = await kp.sign(m, deterministic: true);
  check(await hybridVerify(kp.publicKey, m, hs), 'hybrid verifies');
  check(
      !await hybridVerify(
          kp.publicKey,
          m,
          HybridSignature(
              ed: hs.ed,
              ml: (await kp.sign(Uint8List(1), deterministic: true)).ml)),
      'classical-only half rejected');

  return {
    'suite': 'mldsa65',
    'version': vectorsVersionV3,
    'description':
        'ML-DSA-65 (FIPS 204) known answers from seeds, plus the hybrid '
            'Ed25519+ML-DSA-65 construction of protocol v3 (§13.1). Keygen is '
            'KeyGen_internal(zeta) and signing is deterministic (rnd = 0^32) '
            'so a third implementation reproduces every value from the seed '
            'and message alone; production signing is hedged. A signature '
            'verifies only if BOTH halves verify over identical bytes — the '
            'downgrade an adversary who breaks Ed25519 would otherwise '
            'attempt. The 32-byte commitment is what a zc3. contact code '
            'carries in place of the public key (docs/adr/0003).',
    'algorithm': hybridAlgorithm,
    'public_key_bytes': mlDsaPublicKeyBytes,
    'signature_bytes': mlDsaSignatureBytes,
    'deterministic_rnd': hex(Uint8List(32)),
    'vectors': vectors,
    'hybrid': {
      'ed_seed': hex(kp.edSeed),
      'ml_seed': hex(kp.mlSeed),
      'ed_pub': hex(kp.publicKey.edPub),
      'ml_pub': hex(kp.publicKey.mlPub),
      'message': utf8.decode(m),
      'ed_sig': hex(hs.ed),
      'ml_sig': hex(hs.ml),
      'commit_context': pqCommitContext,
      'pq_commitment': hex(commit),
    },
  };
}

Future<Map<String, Object?>> suiteContactCodeV3() async {
  final d = Drbg(0x000A);
  final id = await d.run(() async => ZIdentity.generate());
  final draws = d.takeDraws();
  check(draws.length == 2, 'identity draws ed and x seeds');
  final mlSeed = d.next(32);
  final pq = await HybridKeyPair.fromSeeds(edSeed: id.edSeed, mlSeed: mlSeed);
  // The code as a client before ADR 0027 emits it — no `pqcs` — which is
  // what this frozen file records; `contact_code_pqc_sig.json` has the
  // signed one.
  final code = await ContactBundleV3.forIdentity(id, pq.publicKey,
      displayName: 'Finn', signCommitment: false);
  final encoded = code.encode();

  // The properties a third implementation must reproduce.
  check(await code.acceptsPqKey(pq.publicKey), 'committed key accepted');
  final wrongSeed = d.next(32);
  final wrong =
      await HybridKeyPair.fromSeeds(edSeed: id.edSeed, mlSeed: wrongSeed);
  check(!await code.acceptsPqKey(wrong.publicKey), 'substituted key refused');

  final scanned = await scanContactCode(encoded);
  check(scanned.assurance == IdentityAssurance.pendingPostQuantum,
      'a v3 scan is pending, not hybrid');
  final v1scan = await scanContactCode((await id.bundle()).encode());
  check(v1scan.assurance == IdentityAssurance.classical,
      'a plain v1 code, with no commitment, is classical');

  // The compatibility claim, checkable by a third party: the emitted code is
  // a v1 code, so the SHIPPED v1 decoder reads it — which is why emission
  // could be switched on without waiting for the population to upgrade.
  final asV1 = await ContactBundle.decode(encoded);
  check(eq(asV1.edPub, id.edPub) && eq(asV1.xPub, id.xPub),
      'the v1 decoder reads the emitted code');
  final strict = code.encodeStrict();
  var strictRejected = false;
  try {
    await ContactBundle.decode(strict);
  } on FormatException {
    strictRejected = true;
  }
  check(strictRejected, 'the strict zc3. form is NOT readable by a v1 client');
  check((await ContactBundleV3.decode(strict)).pqCommit.isNotEmpty,
      'both forms carry the same commitment');

  // §18.7: the same account, seen from a LINKED device. The code describes
  // that device — its keys are the reachable mailbox — while naming the
  // account it belongs to and carrying the account's certificate for it, so
  // scanning a laptop and scanning a phone are the same act.
  final laptop = await d.run(() async => ZIdentity.generate());
  final account = await AccountIdentity.fromV1(id, deviceId: 'phone');
  final laptopCert = await account.signDeviceCert(
      deviceEdPub: laptop.edPub, deviceXPub: laptop.xPub, deviceId: 'laptop');
  final anchored = await ContactBundleV3.forIdentity(laptop, pq.publicKey,
      displayName: 'Finn',
      accountEdPub: id.edPub,
      cert: laptopCert,
      signCommitment: false);
  final anchoredCode = anchored.encode();
  final anchoredScan = await scanContactCode(anchoredCode);
  check(eq(anchoredScan.classical.edPub, laptop.edPub),
      'the session opens with the device in the code');
  check(eq(anchoredScan.accountEdPub, id.edPub),
      'but the identity is the account');
  check(
      await safetyNumber(anchoredScan.accountEdPub, wrong.publicKey.edPub) ==
          await safetyNumber(scanned.accountEdPub, wrong.publicKey.edPub),
      'so the number is the same whichever device was scanned');
  check(await anchored.acceptsPqKey(pq.publicKey),
      "the commitment is the account's, carried by a device");
  final anchoredAsV1 = await ContactBundle.decode(anchoredCode);
  check(eq(anchoredAsV1.edPub, laptop.edPub),
      'an older client still reads it as the device, unchanged');

  final inner =
      InnerMessage.pqIdentity('mid-pqid', 1700000000000, pq.publicKey.mlPub);

  return {
    'suite': 'contact_code_v3',
    'version': vectorsVersionV3,
    'description':
        'Contact code v3 (§13.2): classical keys in full, the post-quantum '
            'half bound by a 32-byte commitment so the code still fits a QR '
            '(docs/adr/0003). The ML-DSA key is delivered in-band as inner '
            'kind "pqid" and checked against the commitment; a substituted '
            'key must be refused rather than silently accepted, which is the '
            'whole security of the arrangement.',
    'prefix': contactCodePrefixV3,
    'commit_context': pqCommitContext,
    'identity': {
      'ed_seed': hex(id.edSeed),
      'x_seed': hex(id.xSeed),
      'ed_pub': hex(id.edPub),
      'x_pub': hex(id.xPub),
      'binding_sig': hex(await id.bindingSignature()),
      'routing_id': await id.routingId(),
    },
    'pq': {
      'ml_seed': hex(mlSeed),
      'ml_pub': hex(pq.publicKey.mlPub),
      'commitment': hex(code.pqCommit),
    },
    'code': encoded,
    'code_json':
        utf8.decode(unb64url(encoded.substring(contactCodePrefix.length))),
    'code_len': encoded.length,
    'strict_code': strict,
    'strict_code_json':
        utf8.decode(unb64url(strict.substring(contactCodePrefixV3.length))),
    'compatibility':
        'the emitted code declares v1 and carries pqc as an extra member, so '
            'a client that predates v3 reads the classical identity and '
            'ignores it (PROTOCOL §14); the zc3. form is rejected outright by '
            'such a client and is therefore never emitted',
    // §18.7. The same account, emitted by a linked device.
    'anchored': {
      'device_ed': b64(laptop.edPub),
      'device_x': b64(laptop.xPub),
      'account_ed': b64(id.edPub),
      'cert': laptopCert.toJson(),
      'code': anchoredCode,
      'code_json': utf8
          .decode(unb64url(anchoredCode.substring(contactCodePrefix.length))),
      'code_len': anchoredCode.length,
      'note':
          'the code describes the DEVICE (ed, x, sig) and names the ACCOUNT '
              '(acct) with that account\'s certificate for the device (cert). '
              'A verifier must check the binding signature against ed, the '
              'certificate against acct, AND that the certificate is for the '
              'ed/x in this code — otherwise anyone holding a genuine '
              'certificate of that account could present it beside their own '
              'keys. The safety number and the pqc commitment are anchored to '
              'acct, so scanning any device of an account gives one identity.',
    },
    'pqid_inner': {
      'json':
          utf8.decode(inner.toBytes()).replaceAll(RegExp(r'\x80[\x00]*$'), ''),
      'bytes': hex(inner.toBytes()),
    },
    'must_refuse': {
      'reason': 'a different ML-DSA key under the same classical identity',
      'ml_seed': hex(wrongSeed),
      'ml_pub': hex(wrong.publicKey.mlPub),
      'commitment': hex(await wrong.publicKey.pqCommitment()),
    },
  };
}

/// A code's JSON with one edit applied, re-encoded under its own prefix —
/// what anyone holding a public code can produce.
String _editCode(String code, void Function(Map<String, Object?> j) edit) {
  final prefix = code.substring(0, 4);
  final j = (jsonDecode(utf8.decode(unb64url(code.substring(4)))) as Map)
      .cast<String, Object?>();
  edit(j);
  return prefix + b64url(utf8.encode(jsonEncode(j)));
}

/// Decodes [code] and reports whether the v3 decoder REFUSED it.
Future<bool> _refused(String code) async {
  try {
    await scanContactCode(code);
    return false;
  } on FormatException {
    return true;
  }
}

/// ADR 0027 (§18.10): the contact code's signature over its post-quantum
/// commitment. A new file beside `contact_code_v3.json`, which stays what a
/// client before ADR 0027 emits.
Future<Map<String, Object?>> suiteContactCodePqcSig() async {
  final d = Drbg(0x0027);
  final id = await d.run(() async => ZIdentity.generate());
  check(d.takeDraws().length == 2, 'identity draws ed and x seeds');
  final mlSeed = d.next(32);
  final pq = await HybridKeyPair.fromSeeds(edSeed: id.edSeed, mlSeed: mlSeed);
  final code =
      await ContactBundleV3.forIdentity(id, pq.publicKey, displayName: 'Finn');
  final encoded = code.encode();
  final commit = code.pqCommit;

  // The signing input, rebuilt from the formula rather than read back.
  final input = concatBytes([utf8b('z-pqc-sig-v1:'), id.edPub, commit]);
  check(eq(input, pqCommitSigningInput(id.edPub, commit)), 'signing input');
  check(input.length == 13 + 32 + 32, 'fixed-width input');
  final sig = code.pqCommitSig!;
  check(eq(sig, await refEdSign(id.edSeed, input)),
      'Ed25519 by the code\'s own key over the input (RFC 8032, deterministic)');
  final decoded = await ContactBundleV3.decode(encoded);
  check(decoded.commitSigned, 'a decoded code says its commitment is signed');
  check(await decoded.commitSignatureValid(), 'and the signature verifies');
  final scanned = await scanContactCode(encoded);
  check(scanned.commitSigned, 'scanContactCode reports it');

  // Compatibility, checkable by a third party: still a v1 code to an older
  // client, and the same code without `pqcs` is every code issued before.
  final asV1 = await ContactBundle.decode(encoded);
  check(eq(asV1.edPub, id.edPub) && eq(asV1.xPub, id.xPub),
      'the v1 decoder reads the signed code');
  final unsigned = (await ContactBundleV3.forIdentity(id, pq.publicKey,
          displayName: 'Finn', signCommitment: false))
      .encode();
  check(unsigned == _editCode(encoded, (j) => j.remove('pqcs')),
      'the code without pqcs is the pre-0027 code byte for byte');
  check(!(await scanContactCode(unsigned)).commitSigned,
      'which decodes, as an unsigned commitment');
  final strict = code.encodeStrict();
  check((await ContactBundleV3.decode(strict)).commitSigned,
      'the strict form carries the signature too');

  // §18.7 from a LINKED device: the device signs, over the ACCOUNT's key.
  d.takeDraws();
  final laptop = await d.run(() async => ZIdentity.generate());
  check(d.takeDraws().length == 2, 'laptop draws ed and x seeds');
  final account = await AccountIdentity.fromV1(id, deviceId: 'phone');
  final laptopCert = await account.signDeviceCert(
      deviceEdPub: laptop.edPub, deviceXPub: laptop.xPub, deviceId: 'laptop');
  final anchored = await ContactBundleV3.forIdentity(laptop, pq.publicKey,
      displayName: 'Finn', accountEdPub: id.edPub, cert: laptopCert);
  final anchoredCode = anchored.encode();
  final anchoredInput =
      concatBytes([utf8b('z-pqc-sig-v1:'), id.edPub, commit]);
  check(eq(anchored.pqCommitSig!, await refEdSign(laptop.edSeed, anchoredInput)),
      'the linked device signs the account\'s commitment under the account key');
  check((await scanContactCode(anchoredCode)).commitSigned,
      'and the anchored code decodes as signed');

  // What must be refused — each is a code anyone holding the public one
  // could make.
  final otherMlSeed = d.next(32);
  final otherCommit = await (await HybridKeyPair.fromSeeds(
          edSeed: id.edSeed, mlSeed: otherMlSeed))
      .publicKey
      .pqCommitment();
  final rewritten =
      _editCode(encoded, (j) => j['pqc'] = b64(otherCommit));
  final deviceAnchoredSig = await refEdSign(laptop.edSeed,
      concatBytes([utf8b('z-pqc-sig-v1:'), laptop.edPub, commit]));
  final wrongAnchor = _editCode(
      anchoredCode, (j) => j['pqcs'] = b64(deviceAnchoredSig));
  final transplanted =
      _editCode(anchoredCode, (j) => j['pqcs'] = b64(sig));
  final noCommit = _editCode(encoded, (j) => j.remove('pqc'));
  final short = _editCode(
      encoded, (j) => j['pqcs'] = b64(sig.sublist(0, 63)));
  final notAString = _editCode(encoded, (j) => j['pqcs'] = 7);
  final refusals = {
    'pqc_rewritten': (
      rewritten,
      'the commitment replaced and the signature kept: the signature does '
          'not cover the new commitment'
    ),
    'signed_over_device_key': (
      wrongAnchor,
      'a linked device\'s code whose pqcs names the DEVICE key in the input '
          'rather than the account the code names (acct)'
    ),
    'signature_transplanted': (
      transplanted,
      'the root device\'s valid pqcs moved into the linked device\'s code: '
          'right input, wrong signer'
    ),
    'pqc_removed': (
      noCommit,
      'pqcs with no pqc: a commitment that was stripped, refused rather than '
          'read as a classical code'
    ),
    'pqcs_63_bytes': (short, 'a signature one byte short'),
    'pqcs_not_a_string': (notAString, 'a member of the wrong type'),
  };
  for (final e in refusals.entries) {
    check(await _refused(e.value.$1), 'refused: ${e.key}');
  }
  check(_editCode(anchoredCode, (_) {}) == anchoredCode,
      'an edit that changes nothing re-encodes the code byte for byte');

  return {
    'suite': 'contact_code_pqc_sig',
    'version': vectorsVersionV3,
    'description':
        'ADR 0027 (PROTOCOL 18.10): a contact code\'s post-quantum commitment '
            'signed by the key the code names, so it cannot be rewritten by '
            'anyone holding the public code. pqcs = Ed25519 by `ed` over '
            'utf8("z-pqc-sig-v1:") || account_ed (32) || pqc (32), where '
            'account_ed is `acct` when the code names one and `ed` otherwise. '
            'An optional member, ignored by every client before it; a code '
            'that carries it and does not verify is refused, and a code '
            'without it is an unsigned commitment — every code issued before.',
    'context': pqCommitSigContext,
    'identity': {
      'ed_seed': hex(id.edSeed),
      'x_seed': hex(id.xSeed),
      'ed_pub': hex(id.edPub),
      'x_pub': hex(id.xPub),
      'binding_sig': hex(await id.bindingSignature()),
    },
    'pq': {
      'ml_seed': hex(mlSeed),
      'ml_pub': hex(pq.publicKey.mlPub),
      'commitment': hex(commit),
    },
    'signing_input': hex(input),
    'pqcs': hex(sig),
    'code': encoded,
    'code_json': utf8.decode(unb64url(encoded.substring(4))),
    'code_len': encoded.length,
    'unsigned_code': unsigned,
    'strict_code': strict,
    'anchored': {
      'device_ed_seed': hex(laptop.edSeed),
      'device_ed': hex(laptop.edPub),
      'account_ed': hex(id.edPub),
      'cert': laptopCert.toJson(),
      'signing_input': hex(anchoredInput),
      'pqcs': hex(anchored.pqCommitSig!),
      'code': anchoredCode,
      'code_json': utf8.decode(unb64url(anchoredCode.substring(4))),
      'code_len': anchoredCode.length,
    },
    'must_refuse': {
      'other_ml_seed': hex(otherMlSeed),
      'other_commitment': hex(otherCommit),
      for (final e in refusals.entries)
        e.key: {'code': e.value.$1, 'why': e.value.$2},
    },
  };
}

Future<Map<String, Object?>> suiteDeviceCertV3(List<Actor> a) async {
  final d = Drbg(0x000B);
  final acct =
      await HybridKeyPair.fromSeeds(edSeed: d.next(32), mlSeed: d.next(32));
  final dev = await d.run(() async => ZIdentity.generate());
  d.takeDraws();

  final cert = await HybridDeviceCertificate.sign(
    accountKey: acct,
    deviceEdPub: dev.edPub,
    deviceXPub: dev.xPub,
    deviceId: 'laptop',
    deterministic: true, // vectors only; production signing is hedged
  );
  check(await cert.verify(acct.publicKey), 'hybrid cert verifies');
  check(await cert.classical.verify(acct.publicKey.edPub),
      'its classical half is a plain v2 certificate');

  // The exit criterion for §13: a certificate whose classical half is
  // genuine but whose post-quantum half attests to a different device.
  final decoy = await HybridDeviceCertificate.sign(
    accountKey: acct,
    deviceEdPub:
        (await ZIdentity.fromSeeds(edSeed: d.next(32), xSeed: d.next(32)))
            .edPub,
    deviceXPub: dev.xPub,
    deviceId: 'rogue',
    deterministic: true,
  );
  final forged =
      HybridDeviceCertificate(classical: cert.classical, mlSig: decoy.mlSig);
  check(!await forged.verify(acct.publicKey), 'classical-only cert refused');
  check(await forged.classical.verify(acct.publicKey.edPub),
      '…even though its classical half still passes');

  // Safety number v2 over both halves of both accounts.
  final peer =
      await HybridKeyPair.fromSeeds(edSeed: d.next(32), mlSeed: d.next(32));
  final sn = await safetyNumberV3(acct.publicKey, peer.publicKey);
  check(sn == await safetyNumberV3(peer.publicKey, acct.publicKey),
      'safety number v2 is symmetric');
  final v1sn = await safetyNumber(acct.publicKey.edPub, peer.publicKey.edPub);
  check(sn != v1sn, 'v2 and v1 numbers differ for the same pair');

  // §18.9 / ADR 0004: the account's post-quantum signature over its DEVICE
  // LIST, which is what actually travels to contacts. Over the set, not over
  // each certificate — an adversary who can forge Ed25519 can otherwise
  // present a SUBSET of a genuine hybrid list, since every certificate left
  // in it is untouched.
  final acctId = await AccountIdentity.fromV1(
      await ZIdentity.fromSeeds(edSeed: acct.edSeed, xSeed: d.next(32)),
      deviceId: 'phone');
  final devices = <DeviceCertificate>[acctId.deviceCert];
  for (final name in ['laptop', 'tablet']) {
    final x = await ZIdentity.fromSeeds(edSeed: d.next(32), xSeed: d.next(32));
    devices.add(await acctId.signDeviceCert(
        deviceEdPub: x.edPub, deviceXPub: x.xPub, deviceId: name));
  }
  // Stage-1 (dual-signed) lists by name, as in the multidevice suite, so this
  // file does not move when the v2-only signer is switched on.
  final list = await acctId.signDeviceList(devices, 3, v2Only: false);
  final listSig = await HybridDeviceListSignature.sign(
      accountKey: acct, list: list, deterministic: true);
  check(await listSig.verifies(list, acct.publicKey.mlPub),
      'the list signature verifies');
  final subset =
      await acctId.signDeviceList(devices.sublist(0, 2), 3, v2Only: false);
  check(await subset.verify(),
      'the excluded list is classically perfect — that is the point');
  check(!await listSig.verifies(subset, acct.publicKey.mlPub),
      'but the account never signed THAT set post-quantum');
  final rolledBack = await acctId.signDeviceList(devices, 2, v2Only: false);
  check(!await listSig.verifies(rolledBack, acct.publicKey.mlPub),
      'nor an earlier version of it');

  // ADR 0010: the substitution the v1 input was blind to. Swap one device's
  // X25519 ratchet key — keep every Ed key, so membership, the routing ids and
  // the v1 input are byte-identical — and replay the genuine ML-DSA signature.
  // Signing the swapped cert with the account key models the adversary who has
  // broken Ed25519 (the premise of §18): every classical half is forgeable,
  // only the ML-DSA one is not, and it is now over the v2 input.
  final swapX = devices[0].deviceXPub; // any key other than device 1's own
  final swapped = <DeviceCertificate>[...devices];
  swapped[1] = await acctId.signDeviceCert(
      deviceEdPub: devices[1].deviceEdPub,
      deviceXPub: swapX,
      deviceId: devices[1].deviceId);
  check(
      eq(SignedDeviceList.signingInput(3, devices),
          SignedDeviceList.signingInput(3, swapped)),
      'v1 signing input is blind to an X-only swap');
  check(
      !eq(SignedDeviceList.signingInputV2(3, devices),
          SignedDeviceList.signingInputV2(3, swapped)),
      'v2 signing input is not');
  check(
      eq(await deviceListFingerprint(3, devices),
          await deviceListFingerprint(3, swapped)),
      'v1 fingerprint unchanged by the swap');
  check(
      !eq(await deviceListFingerprintV2(3, devices),
          await deviceListFingerprintV2(3, swapped)),
      'v2 fingerprint moves with the ratchet key');
  // A full list carrying both signatures still fails verify(): the v1 sig
  // verifies (its input did not move) but sig2 is over the moved v2 input, so
  // the substitution is caught there. The ML-DSA is held at the v1 input during
  // the mixed-version transition (ADR 0017) so a not-yet-migrated client can
  // verify it; that input is blind to an X-only swap, so the ML-DSA does not
  // catch the swap here — its post-quantum coverage of the ratchet keys returns
  // in stage 2, when signing moves to v2-only.
  final swappedList = SignedDeviceList(
      accountEdPub: list.accountEdPub,
      version: list.version,
      devices: swapped,
      sig: list.sig,
      sig2: list.sig2);
  check(!await swappedList.verify(),
      'the swapped list fails verify — sig2 is over the moved v2 input');
  check(await listSig.verifies(swappedList, acct.publicKey.mlPub),
      'the ML-DSA is held at v1 (ADR 0017), blind to the swap; verify() catches it');

  // ADR 0017 stage 2: the account's list at the next version signed v2-only —
  // `sig3` alone, over the v2 content under its own context — and its ML-DSA,
  // over the same v3 input because the list carries no v1 signature. The swap
  // above is tried again at this version: in stage 1 only sig2 caught it, here
  // the post-quantum half refuses it as well. Deterministic throughout;
  // nothing is drawn from the DRBG.
  final v2oList = await acctId.signDeviceList(devices, 4, v2Only: true);
  final v3Input = SignedDeviceList.signingInputV3(4, devices);
  check(v2oList.isV2Only && await v2oList.verify(),
      'the v2-only list verifies');
  final v2oSig = await HybridDeviceListSignature.sign(
      accountKey: acct, list: v2oList, deterministic: true);
  check(await v2oSig.verifies(v2oList, acct.publicKey.mlPub),
      'its ML-DSA verifies');
  check(pqDsaVerify(acct.publicKey.mlPub, v3Input, v2oSig.mlSig),
      'over the v3 input');
  check(
      !pqDsaVerify(acct.publicKey.mlPub,
          SignedDeviceList.signingInput(4, devices), v2oSig.mlSig),
      'and not over the v1 one');
  check(
      !pqDsaVerify(acct.publicKey.mlPub,
          SignedDeviceList.signingInputV2(4, devices), v2oSig.mlSig),
      'nor over the v2 one');
  check(!await listSig.verifies(v2oList, acct.publicKey.mlPub),
      'the stage-1 signature does not carry over to it');
  final v2oSwapped = SignedDeviceList(
      accountEdPub: v2oList.accountEdPub,
      version: 4,
      devices: swapped,
      sig3: v2oList.sig3);
  check(!await v2oSwapped.verify(), 'the swapped v2-only list fails sig3');
  check(!await v2oSig.verifies(v2oSwapped, acct.publicKey.mlPub),
      'and its ML-DSA no longer verifies either');
  // The stage-1 list with `sig` deleted. Its sig2 is genuine and the v1 input
  // is untouched by the deletion, so the genuine stage-1 ML-DSA still verifies
  // over those bytes: neither signature can refuse it. The shape does — in
  // verify(), and in the ML-DSA check, which takes no list in no shape.
  final sigStripped = SignedDeviceList(
      accountEdPub: list.accountEdPub,
      version: list.version,
      devices: list.devices,
      sig2: list.sig2);
  check(!await sigStripped.verify(), 'the sig-stripped list is refused');
  check(
      pqDsaVerify(acct.publicKey.mlPub, SignedDeviceList.signingInput(3, devices),
          listSig.mlSig),
      'though the stage-1 ML-DSA still covers its v1 input');
  check(!await listSig.verifies(sigStripped, acct.publicKey.mlPub),
      'and the ML-DSA check refuses it for its shape');

  final certJson = jsonEncode(cert.toJson());
  return {
    'suite': 'device_cert_v3',
    'version': vectorsVersionV3,
    'description':
        'Hybrid device certificates (§18.4) and safety number v2 (§18.5). '
            'Both signatures cover the SAME signing input, and a certificate '
            'verifies only if both halves do — the "must_refuse" record here '
            'has a genuine Ed25519 signature over this device and a genuine '
            'ML-DSA signature over a different one, which is exactly what an '
            'adversary who has broken Ed25519 can produce. Signing is '
            'deterministic for reproducibility; production signing is hedged.',
    'signing_context': deviceCertContext,
    'device_list': {
      'note':
          'ADR 0004, ADR 0010 and ADR 0017. The account signs its device LIST '
              'under ML-DSA-65 as well as Ed25519. Over the SET rather than per '
              'certificate: given a genuine hybrid list, an adversary who can '
              'forge Ed25519 but not ML-DSA can present "excluded" below — a '
              'classically perfect list whose every remaining certificate is '
              'genuine and untouched — and only a signature over the SET catches '
              'that. The input is held at the v1 format (version + membership) '
              'while any client in the field still signs v1 (ADR 0017, the '
              'mixed-version fix): a not-yet-migrated client verifies this '
              'ML-DSA, and the v1 input is blind to an X-only swap, so '
              '"substitution" below is caught by verify() (sig2), not here. The '
              'v2 input — which also covers each device\'s X25519 ratchet key and '
              'id (the 0010 change, §3.4) — takes over in stage 2, once v1 '
              'signing stops. The signature travels as its own message on an '
              'unrelated schedule, so the list keeps its 1024-byte padding bucket '
              'and its timing.',
      'list_json': jsonEncode(list.toJson()),
      'signing_input':
          hex(SignedDeviceList.signingInput(list.version, list.devices)),
      'signing_input_v2':
          hex(SignedDeviceList.signingInputV2(list.version, list.devices)),
      'ml_sig': hex(listSig.mlSig),
      'v1_fingerprint':
          hex(await deviceListFingerprint(list.version, list.devices)),
      'v2_fingerprint':
          hex(await deviceListFingerprintV2(list.version, list.devices)),
      'sig_json': jsonEncode(listSig.toJson()),
      'sig_json_bytes': jsonEncode(listSig.toJson()).length,
      'must_refuse': {
        'excluded_list_json': jsonEncode(subset.toJson()),
        'excluded_signing_input':
            hex(SignedDeviceList.signingInput(subset.version, subset.devices)),
        'excluded_signing_input_v2': hex(
            SignedDeviceList.signingInputV2(subset.version, subset.devices)),
        'rolled_back_list_json': jsonEncode(rolledBack.toJson()),
        'rolled_back_signing_input': hex(SignedDeviceList.signingInput(
            rolledBack.version, rolledBack.devices)),
        'rolled_back_signing_input_v2': hex(SignedDeviceList.signingInputV2(
            rolledBack.version, rolledBack.devices)),
      },
      'substitution': {
        'note': 'ADR 0010 and ADR 0017. Device "${devices[1].deviceId}" keeps '
            'its Ed25519 key and gets a different X25519 ratchet key. The v1 '
            'input and fingerprint are byte-identical to the genuine list; the '
            'v2 input and fingerprint are not. In stage 1 the ML-DSA is held at '
            'the v1 input (ADR 0017), so the genuine ML-DSA signature DOES verify '
            'this swapped list — the substitution is caught by verify() instead, '
            'whose sig2 is over the moved v2 input. Stage 2 moves the ML-DSA to '
            'the v2 input and catches it there too.',
        'swapped_device_id': devices[1].deviceId,
        'swapped_x_pub': hex(swapX),
        'v1_signing_input': hex(SignedDeviceList.signingInput(3, swapped)),
        'signing_input_v2': hex(SignedDeviceList.signingInputV2(3, swapped)),
        'v1_fingerprint': hex(await deviceListFingerprint(3, swapped)),
        'v2_fingerprint': hex(await deviceListFingerprintV2(3, swapped)),
        'swapped_list_json': jsonEncode(swappedList.toJson()),
      },
    },
    'device_list_v2_only': {
      'note': 'ADR 0017 stage 2: the same account and devices at version 4, '
          'signed v2-only — sig3 alone, over signing_input_v3, which is the '
          'v2 content under the context "z-devlist-v3:" so that no sig2 can '
          'stand alone — and the account\'s ML-DSA-65 over it. A list commits '
          'to the strongest signature that is alone, so with no v1 sig the '
          'ML-DSA is over signing_input_v3, which names each device\'s X25519 '
          'ratchet key and id, and NOT over v1_signing_input or '
          'v2_signing_input; the fingerprint is over the same bytes. '
          'must_refuse: the substitution from device_list again, at this '
          'version — device "${devices[1].deviceId}" keeps its Ed25519 key, '
          'gets another ratchet key and a re-signed certificate, and carries '
          'the genuine sig3 and ml_sig; here both refuse it, the ML-DSA '
          'included, which in stage 1 was blind to this — and device_list '
          'with its sig deleted (sig_stripped_list_json). Its sig2 is genuine, '
          'and device_list\'s ml_sig still verifies over its v1 input, which '
          'the deletion does not move: neither signature can refuse it, and '
          'the list is refused for its shape, {sig2}, which is not one of the '
          'three. device_list\'s ml_sig does not verify the v2-only list.',
      'list_json': jsonEncode(v2oList.toJson()),
      'signing_input_v3': hex(v3Input),
      'v1_signing_input': hex(SignedDeviceList.signingInput(4, devices)),
      'v2_signing_input': hex(SignedDeviceList.signingInputV2(4, devices)),
      'fingerprint': hex(await v2oList.fingerprint()),
      'ml_sig': hex(v2oSig.mlSig),
      'sig_json': jsonEncode(v2oSig.toJson()),
      'must_refuse': {
        'swapped_device_id': devices[1].deviceId,
        'swapped_x_pub': hex(swapX),
        'swapped_signing_input_v3':
            hex(SignedDeviceList.signingInputV3(4, swapped)),
        'swapped_fingerprint': hex(await v2oSwapped.fingerprint()),
        'swapped_list_json': jsonEncode(v2oSwapped.toJson()),
        'sig_stripped_list_json': jsonEncode(sigStripped.toJson()),
      },
    },
    'account': {
      'ed_pub': hex(acct.publicKey.edPub),
      'ml_pub': hex(acct.publicKey.mlPub),
    },
    'device': {
      'ed_pub': hex(dev.edPub),
      'x_pub': hex(dev.xPub),
      'device_id': 'laptop',
      'routing_id': await cert.classical.routingId(),
    },
    'signing_input': hex(cert.signingInput),
    'cert': {
      'ed_sig': hex(cert.classical.sig),
      'ml_sig': hex(cert.mlSig),
      'json': certJson,
      'json_bytes': certJson.length,
    },
    'must_refuse': {
      'reason': 'genuine classical half, post-quantum half over another device',
      'ed_sig': hex(forged.classical.sig),
      'ml_sig': hex(forged.mlSig),
    },
    'safety_number_v2': {
      'context': safetyContextV3,
      'peer_ed_pub': hex(peer.publicKey.edPub),
      'peer_ml_pub': hex(peer.publicKey.mlPub),
      'ikm_rule': 'lo.ed || lo.ml || hi.ed || hi.ml, ordered by Ed25519 key',
      'value': sn,
      'v1_value_for_comparison': v1sn,
    },
  };
}

/// The two throwaway relay mailboxes an invite derives (§20, 17.2).
///
/// Small, and the most silently breakable thing in the ceremony: get this
/// derivation wrong in a second implementation and both sides authenticate
/// successfully, listen politely, and never meet. Recomputed here from the
/// composition — HKDF-SHA256 over the invite secret with an EMPTY salt and
/// `info = "z-connect-relay-v1:" || role`, 64 bytes split into the Ed25519
/// and X25519 seeds in that order — rather than by calling the transport.
///
/// An empty salt is RFC 5869's "not provided" case: HMAC pads a short key
/// with zeroes, so it is the same extract as a HashLen run of zeroes.
Future<Map<String, Object?>> suiteConnectMailboxes() async {
  final d = Drbg(0x001a);
  final code = ConnectCode(d.next(10));
  final mailboxes = <Map<String, Object?>>[];
  for (final (role, who) in [('i', 'inviter'), ('r', 'acceptor')]) {
    final info = concatBytes([utf8.encode(connectRelayCtx), utf8.encode(role)]);
    final okm = await refHkdf(code.secret, Uint8List(0), info, 64);
    final edSeed = Uint8List.fromList(okm.sublist(0, 32));
    final xSeed = Uint8List.fromList(okm.sublist(32, 64));
    final edPub = await refEdPub(edSeed);
    final xPub = await refXPub(xSeed);
    final routingId =
        base64Url.encode(await refSha256(edPub)).replaceAll('=', '');

    final id = await mailboxIdentity(code, role);
    check(eq(id.edPub, edPub), '$who mailbox ed key');
    check(eq(id.xPub, xPub), '$who mailbox x key');
    check(await id.routingId() == routingId, '$who mailbox routing id');

    mailboxes.add({
      'role': role,
      'who': who,
      'info': hex(info),
      'okm': hex(okm),
      'ed_seed': hex(edSeed),
      'x_seed': hex(xSeed),
      'ed_pub': hex(edPub),
      'x_pub': hex(xPub),
      'routing_id': routingId,
    });
  }

  // Distinct from each other, from the code's own rendezvous id, and from
  // either pairing rendezvous the same ten bytes would derive.
  final rendezvous = await code.rendezvousRoutingId();
  final pairing = PairingCode(code.secret);
  final others = {
    'rendezvous': rendezvous,
    'pairing_v1': await pairing.rendezvousRoutingId(),
    'pairing_v2': await pairing.rendezvousRoutingIdV2(),
  };
  check(mailboxes[0]['routing_id'] != mailboxes[1]['routing_id'],
      'the two mailboxes differ');
  for (final m in mailboxes) {
    for (final e in others.entries) {
      check(m['routing_id'] != e.value, 'mailbox vs ${e.key}');
    }
  }

  return {
    'suite': 'connect_mailboxes',
    'version': vectorsVersion,
    'description':
        'The transport half of the connect ceremony (PROTOCOL 20): the two '
            'throwaway relay identities an invite secret derives, one per '
            'role. HKDF-SHA256(secret, salt="", info="z-connect-relay-v1:" || '
            'role, 64), split into the Ed25519 seed and then the X25519 seed; '
            'the routing id is base64url(SHA-256(ed_pub)) unpadded, as for '
            'any identity. Both keypairs are derivable by anyone holding the '
            'code, which is what makes the invite a bearer token and why it '
            'is one-time and short-lived. Disjoint by context from the '
            "code's own rendezvous id and from both pairing rendezvous.",
    'connect_code': {
      'secret': hex(code.secret),
      'text': code.text,
      'relay_context': connectRelayCtx,
      'salt': '',
    },
    'mailboxes': mailboxes,
    'distinct_from': others,
  };
}

// ---------------------------------------------------------------------------
// Handles (PROTOCOL 21, ADR 0015 revision 2)
// ---------------------------------------------------------------------------

/// Argon2id through the `cryptography` package directly — the reference the
/// library's [handleLabel] is checked against, and the source of the
/// small-parameter answers an independent Argon2id is checked against.
Future<Uint8List> refArgon2id(List<int> password, List<int> salt,
    {required int memoryKib,
    required int iterations,
    required int parallelism,
    int length = 32,
    List<int> secret = const [],
    List<int> ad = const []}) async {
  final k = await Argon2id(
          memory: memoryKib,
          parallelism: parallelism,
          iterations: iterations,
          hashLength: length)
      .deriveKey(
          secretKey: SecretKey(password),
          nonce: salt,
          optionalSecret: secret,
          associatedData: ad);
  return Uint8List.fromList(await k.extractBytes());
}

Future<Map<String, Object?>> suiteHandles() async {
  final d = Drbg(0x0036);

  // The KDF instance first: the package reproduces RFC 9106 §5.3 (Argon2id,
  // with a secret and associated data, four lanes) before it is trusted
  // with anything below.
  check(
      hex(await refArgon2id(List.filled(32, 1), List.filled(16, 2),
              memoryKib: 32,
              iterations: 3,
              parallelism: 4,
              secret: List.filled(8, 3),
              ad: List.filled(12, 4))) ==
          '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659',
      'Argon2id reproduces RFC 9106 \u00a75.3');

  // --- §21.1 the grammar ----------------------------------------------------
  final valid = <(String, String)>[
    ('alice.42', 'already canonical'),
    ('@Alice.42', 'one leading @ removed and A-Z lower-cased'),
    (' \t@ALICE.42\r\n', 'surrounding ASCII whitespace trimmed first'),
    ('alice.042', 'digits are a string: 042 is a different handle from 42'),
    ('bob_smith.07', 'an underscore inside the nick, and a leading zero kept'),
    ('a1b.123456', 'six digits, and a digit inside the nick'),
    ('abc.00', 'the shortest nick and the fewest digits'),
    ('abcdefghijklmnopqrst.99', 'twenty characters, the longest nick'),
    ('admins.12', 'a reserved nick with a letter added is not reserved'),
  ];
  final invalid = <(String, HandleProblem, String)>[
    ('', HandleProblem.empty, 'nothing'),
    (' \t ', HandleProblem.empty, 'only whitespace'),
    ('@', HandleProblem.empty, 'only the @'),
    ('@@alice.42', HandleProblem.badCharacter, 'only ONE leading @ is removed'),
    ('@ alice.42', HandleProblem.badCharacter,
        'trimming happens before the @ is removed, not after'),
    ('ali ce.42', HandleProblem.badCharacter, 'a space inside'),
    ('alice-x.42', HandleProblem.badCharacter, 'punctuation other than _ and one .'),
    ('alice.42\u00a0', HandleProblem.badCharacter,
        'a no-break space (U+00A0) is not trimmed: only ASCII whitespace is'),
    ('alice.42\u200b', HandleProblem.badCharacter, 'a zero-width space (U+200B)'),
    ('f\u0456nn\u0456an.42', HandleProblem.badCharacter,
        'Cyrillic \u0456 (U+0456) in place of Latin i'),
    ('\u0430dmin.12', HandleProblem.badCharacter,
        'Cyrillic \u0430 (U+0430) in place of Latin a: a reserved nick\'s look-alike'),
    ('\u212aate.42', HandleProblem.badCharacter,
        'the Kelvin sign (U+212A), which Unicode lower-cases to ASCII k'),
    ('\u017fam.42', HandleProblem.badCharacter,
        'long s (U+017F), which Unicode upper-cases to ASCII S'),
    ('\u0130nan.42', HandleProblem.badCharacter,
        'dotted capital I (U+0130), which Unicode lower-cases to i + a combining dot'),
    ('\uff41lice.42', HandleProblem.badCharacter, 'a fullwidth a (U+FF41)'),
    ('alice\uff0e42', HandleProblem.badCharacter, 'a fullwidth full stop (U+FF0E)'),
    ('alice.\u0664\u0662', HandleProblem.badCharacter,
        'Arabic-Indic digits (U+0664 U+0662)'),
    ('ali\u0301ce.42', HandleProblem.badCharacter,
        'a combining acute accent (U+0301)'),
    ('alice', HandleProblem.missingDigits, 'no discriminator'),
    ('alice.', HandleProblem.missingDigits, 'nothing after the dot'),
    ('alice.4a', HandleProblem.digitsNotDigits, 'a letter after the dot'),
    ('alice.42.42', HandleProblem.digitsNotDigits, 'a second dot'),
    ('alice.7', HandleProblem.digitsTooShort, 'one digit'),
    ('alice.1234567', HandleProblem.digitsTooLong, 'seven digits'),
    ('al.42', HandleProblem.nickTooShort, 'two characters'),
    ('.42', HandleProblem.nickTooShort, 'no nick at all'),
    ('abcdefghijklmnopqrstu.42', HandleProblem.nickTooLong, 'twenty-one characters'),
    ('1alice.42', HandleProblem.nickStartsWithNonLetter, 'a digit first'),
    ('_alice.42', HandleProblem.nickStartsWithNonLetter, 'an underscore first'),
    ('ali__ce.42', HandleProblem.nickDoubleUnderscore, 'two underscores in a row'),
    ('alice_.42', HandleProblem.nickEndsWithUnderscore, 'a trailing underscore'),
    for (final n in reservedHandleNicks)
      ('$n.12', HandleProblem.reserved, 'reserved'),
    for (final n in reservedHandleNicks)
      ('@${n[0].toUpperCase()}${n.substring(1)}.99', HandleProblem.reserved,
          'reserved, after normalisation'),
  ];
  final validOut = <Map<String, Object?>>[];
  for (final (input, note) in valid) {
    final h = Handle.parse(input);
    final norm = normaliseHandleInput(input);
    check(norm == h.canonical, 'valid input normalises to its canonical form');
    validOut.add({
      'input': input,
      'canonical': h.canonical,
      'display': h.display,
      'note': note,
    });
  }
  final invalidOut = <Map<String, Object?>>[];
  for (final (input, problem, note) in invalid) {
    check(Handle.problemWith(input) == problem, 'refused as $problem: $input');
    invalidOut.add({
      'input': input,
      'normalised': normaliseHandleInput(input),
      'problem': problem.name,
      'note': note,
    });
  }

  // --- §21.2 labels -----------------------------------------------------------
  final saltBytes = utf8.encode(handleLabelSalt);
  final labels = <String, Uint8List>{};
  final labelOut = <Map<String, Object?>>[];
  for (final name in ['alice.42', 'alice.042', 'bob_smith.07']) {
    final h = Handle.parse(name);
    final label = await handleLabel(h);
    check(
        eq(
            label,
            await refArgon2id(h.canonicalBytes, saltBytes,
                memoryKib: handleLabelMemoryKib,
                iterations: handleLabelIterations,
                parallelism: handleLabelParallelism)),
        'label of $name');
    labels[name] = label;
    labelOut.add({
      'handle': name,
      'password': hex(h.canonicalBytes),
      'label': hex(label),
    });
  }
  check(!eq(labels['alice.42']!, labels['alice.042']!),
      '42 and 042 are different handles');
  final smallOut = <Map<String, Object?>>[];
  for (final (pw, m, t, p) in [
    ('alice.42', 8, 1, 1),
    ('alice.42', 64, 2, 1),
    ('bob_smith.07', 256, 3, 1),
    ('abc.00', 64, 2, 2),
  ]) {
    smallOut.add({
      'password': hex(utf8.encode(pw)),
      'salt': hex(saltBytes),
      'memory_kib': m,
      'iterations': t,
      'parallelism': p,
      'tag_len': 32,
      'tag': hex(await refArgon2id(utf8.encode(pw), saltBytes,
          memoryKib: m, iterations: t, parallelism: p)),
    });
  }

  // --- §21.3 keys ----------------------------------------------------------------
  final label = labels['alice.42']!;
  final otherLabel = labels['bob_smith.07']!;
  final seeds = <String, Uint8List>{};
  final pubs = <String, Uint8List>{};
  for (final name in [
    'owner_a', 'intro_a1', 'intro_a2', 'owner_b', 'intro_b', //
    'owner_m', 'intro_m',
  ]) {
    seeds[name] = d.next(32);
    pubs[name] = await handleKeyPublic(seeds[name]!);
    check(eq(pubs[name]!, await refEdPub(seeds[name]!)), '$name pub');
  }
  // Each introduction seed's X25519 half (Amendment 1): the key a request
  // is sealed to, `xintro` in the record.
  final xseeds = <String, Uint8List>{};
  final xpubs = <String, Uint8List>{};
  for (final name in seeds.keys.where((n) => n.startsWith('intro'))) {
    final xs = await refHkdf(
        seeds[name]!, utf8b(handleIntroXSalt), Uint8List(0), 32);
    final id = await handleIntroIdentity(seeds[name]!);
    check(eq(xs, await handleIntroXSeed(seeds[name]!)), '$name x seed');
    check(eq(id.xSeed, xs) && eq(id.edPub, pubs[name]!), '$name identity');
    xseeds[name] = xs;
    xpubs[name] = await refXPub(xs);
    check(eq(id.xPub, xpubs[name]!), '$name x pub');
  }
  final keyOut = <Map<String, Object?>>[
    for (final name in seeds.keys)
      {
        'name': name,
        'seed': hex(seeds[name]!),
        'pub': hex(pubs[name]!),
        if (name.startsWith('intro')) ...{
          'routing_id': await introRoutingId(pubs[name]!),
          'rid_bytes': hex(await refSha256(pubs[name]!)),
          'x_hkdf_salt': handleIntroXSalt,
          'x_seed': hex(xseeds[name]!),
          'x_pub': hex(xpubs[name]!),
        },
      },
  ];
  final codes = <String, RecoveryCode>{
    'r1': RecoveryCode(d.next(15)),
    'r2': RecoveryCode(d.next(15)),
    'r_m': RecoveryCode(d.next(15)),
  };
  final rkeys = <String, HandleRecoveryKey>{};
  final recoveryOut = <Map<String, Object?>>[];
  for (final e in codes.entries) {
    final rk = await handleRecoveryKey(e.value, label);
    rkeys[e.key] = rk;
    final seed = await refHkdf(e.value.entropy, utf8b(handleRecoverySalt), label, 32);
    check(eq(seed, rk.seed), '${e.key} recovery seed');
    check(eq(rk.pub, await refEdPub(seed)), '${e.key} recovery pub');
    final rcInput = concatBytes([utf8.encode(handleRcContext), rk.pub]);
    check(eq(rk.rc, await refSha256(rcInput)), '${e.key} rc');
    final formatted = await formatHandleRecoveryCode(e.value);
    check(formatted.startsWith('$handleRecoveryCodePrefix-'), 'prefix');
    check(eq((await parseHandleRecoveryCode(formatted)).entropy, e.value.entropy),
        'the formatted code parses back');
    recoveryOut.add({
      'name': e.key,
      'entropy': hex(e.value.entropy),
      'formatted': formatted,
      'canonical': formatted.substring(4).replaceAll('-', ''),
      'for_label': 'alice.42',
      'hkdf_salt': handleRecoverySalt,
      'hkdf_info': hex(label),
      'seed': hex(rk.seed),
      'pub': hex(rk.pub),
      'rc_input': hex(rcInput),
      'rc': hex(rk.rc),
    });
  }
  // The same code for another handle derives another key: one code, one handle.
  check(!eq((await handleRecoveryKey(codes['r1']!, otherLabel)).pub, rkeys['r1']!.pub),
      'a recovery key is per label');

  // --- §21.4 records, entries, histories -------------------------------------------
  final entries = <String, HandleEntry>{};
  final entryOut = <Map<String, Object?>>[];
  Future<void> add(String name, String note, String signer, HandleEntry e,
      {Map<String, Object?>? extra}) async {
    entries[name] = e;
    final pi = await handlePublishInput(
        label: e.label, version: e.version, value: e.value);
    final want = concatBytes([
      utf8.encode(handlePublishContext),
      e.label,
      _u64(e.version),
      await refSha256(e.value),
    ]);
    check(eq(pi, want), '$name publish input');
    check(eq(e.sig, await refEdSign(seeds[signer]!, pi)), '$name sig');
    entryOut.add({
      'name': name,
      'note': note,
      'label': hex(e.label),
      'v': e.version,
      'value_text': utf8.decode(e.value, allowMalformed: true),
      'value': hex(e.value),
      'value_sha256': hex(await refSha256(e.value)),
      'publish_input': hex(pi),
      'signer': signer,
      'sig': hex(e.sig),
      'publish_json': e.toPublishJson(),
      ...?extra,
    });
  }

  /// An entry whose value is [value] verbatim (to record what must be
  /// refused), signed by [signer] the way an honest one would be.
  Future<HandleEntry> signRaw(Uint8List lbl, int v, Uint8List value, String signer) async {
    final pi = await handlePublishInput(label: lbl, version: v, value: value);
    return HandleEntry(
        label: lbl, version: v, value: value, sig: await refEdSign(seeds[signer]!, pi));
  }

  Future<HandleEntry> signed(Uint8List lbl, int v, HandleRecord r, String signer) =>
      signRaw(lbl, v, r.encode(), signer);

  final rc1 = rkeys['r1']!.rc, rc2 = rkeys['r2']!.rc, rcM = rkeys['r_m']!.rc;
  final claim = HandleRecord.claim(
      owner: pubs['owner_a']!, intro: pubs['intro_a1']!, xintro: xpubs['intro_a1']!, pow: 20, rc: rc1);
  await add('claim', 'Alice claims alice.42: owner A, introduction key A1, 20 bits, rc from r1',
      'owner_a', await signHandleEntry(label: label, version: 1, record: claim, ownerSeed: seeds['owner_a']!));
  final rotate = HandleRecord.update(
      owner: pubs['owner_a']!, intro: pubs['intro_a2']!, xintro: xpubs['intro_a2']!, pow: 22, rc: rc1);
  await add('update_rotate', 'Alice rotates the introduction key to A2 and raises the difficulty',
      'owner_a', await signHandleEntry(label: label, version: 2, record: rotate, ownerSeed: seeds['owner_a']!));
  final pause = HandleRecord.update(owner: pubs['owner_a']!, intro: null, xintro: null, pow: 22, rc: rc1);
  await add('update_pause', 'Alice pauses the handle: it resolves, and cannot be reached',
      'owner_a', await signHandleEntry(label: label, version: 3, record: pause, ownerSeed: seeds['owner_a']!));
  final rsig = await signHandleRecovery(
      recoverySeed: rkeys['r1']!.seed, label: label, version: 4, owner: pubs['owner_b']!, rc: rc2);
  final rInput = handleRecoverInput(label: label, version: 4, owner: pubs['owner_b']!, rc: rc2);
  check(eq(rInput, concatBytes([utf8.encode(handleRecoverContext), label, _u64(4), pubs['owner_b']!, rc2])),
      'recover input');
  check(eq(rsig, await refEdSign(rkeys['r1']!.seed, rInput)), 'rsig');
  final recover = HandleRecord.recover(
      owner: pubs['owner_b']!, intro: pubs['intro_b']!, xintro: xpubs['intro_b']!, pow: 20, rc: rc2,
      rpub: rkeys['r1']!.pub, rsig: rsig);
  await add('recover', 'Alice, without key A, recovers with the code r1: new owner B, new rc from r2',
      'owner_b', await signHandleEntry(label: label, version: 4, record: recover, ownerSeed: seeds['owner_b']!),
      extra: {'recover_input': hex(rInput), 'rsig_by': 'r1', 'rsig': hex(rsig)});
  final after = HandleRecord.update(owner: pubs['owner_b']!, intro: pubs['intro_b']!, xintro: xpubs['intro_b']!, pow: 24, rc: rc2);
  await add('update_after_recover', 'the new owner B updates', 'owner_b',
      await signHandleEntry(label: label, version: 5, record: after, ownerSeed: seeds['owner_b']!));

  // Entries every reader must refuse, each where it would land.
  await add('m_claim_taken', "Mallory's claim on alice.42 at v2", 'owner_m',
      await signed(label, 2, HandleRecord.claim(owner: pubs['owner_m']!, intro: pubs['intro_m']!, xintro: xpubs['intro_m']!, pow: 16, rc: rcM), 'owner_m'));
  await add('m_update_foreign_sig', "an update keeping Alice's owner and rc, signed by Mallory", 'owner_m',
      await signed(label, 2, HandleRecord.update(owner: pubs['owner_a']!, intro: pubs['intro_m']!, xintro: xpubs['intro_m']!, pow: 16, rc: rc1), 'owner_m'));
  await add('m_update_foreign_owner', 'an update naming Mallory as the owner, signed by Mallory', 'owner_m',
      await signed(label, 2, HandleRecord.update(owner: pubs['owner_m']!, intro: pubs['intro_m']!, xintro: xpubs['intro_m']!, pow: 16, rc: rc1), 'owner_m'));
  await add('a_update_rc_change', 'an update by Alice that changes rc: only a recover may', 'owner_a',
      await signed(label, 2, HandleRecord.update(owner: pubs['owner_a']!, intro: pubs['intro_a2']!, xintro: xpubs['intro_a2']!, pow: 22, rc: rcM), 'owner_a'));
  await add('a_update_stale', 'a second update at v2, after the one at v2', 'owner_a',
      await signed(label, 2, HandleRecord.update(owner: pubs['owner_a']!, intro: pubs['intro_a1']!, xintro: xpubs['intro_a1']!, pow: 20, rc: rc1), 'owner_a'));
  final padded = Uint8List.fromList([...rotate.encode(), ...List.filled(handleMaxValueBytes + 1 - rotate.encode().length, 0x20)]);
  check(padded.length == handleMaxValueBytes + 1, 'one byte over');
  await add('a_update_oversize', 'an update padded to 1025 bytes', 'owner_a', await signRaw(label, 2, padded, 'owner_a'));
  final spaced = Uint8List.fromList(utf8.encode(utf8.decode(rotate.encode()).replaceFirst('"k":', '"k": ')));
  await add('a_update_not_canonical', 'an update with one space added', 'owner_a', await signRaw(label, 2, spaced, 'owner_a'));
  final rM = rkeys['r_m']!;
  final mRsig = await signHandleRecovery(recoverySeed: rM.seed, label: label, version: 4, owner: pubs['owner_m']!, rc: rcM);
  await add('m_recover_wrong_key', "Mallory recovers with a code of her own (r_m): its rpub is not the one rc commits to", 'owner_m',
      await signed(label, 4, HandleRecord.recover(owner: pubs['owner_m']!, intro: pubs['intro_m']!, xintro: xpubs['intro_m']!, pow: 16, rc: rcM, rpub: rM.pub, rsig: mRsig), 'owner_m'));
  final wrongRsig = await signHandleRecovery(recoverySeed: rkeys['r1']!.seed, label: label, version: 4, owner: pubs['owner_b']!, rc: rcM);
  await add('recover_rsig_other_rc', 'the right rpub, with an rsig over a different rc than the record installs', 'owner_b',
      await signed(label, 4, HandleRecord.recover(owner: pubs['owner_b']!, intro: pubs['intro_b']!, xintro: xpubs['intro_b']!, pow: 20, rc: rc2, rpub: rkeys['r1']!.pub, rsig: wrongRsig), 'owner_b'));
  final noRsigText = utf8.decode(recover.encode()).replaceFirst(',"rsig":"${b64url(rsig)}"', '');
  check(!noRsigText.contains('rsig'), 'rsig removed');
  await add('recover_without_rsig', 'a recover that changes owner and rc with no rsig', 'owner_b',
      await signRaw(label, 4, Uint8List.fromList(utf8.encode(noRsigText)), 'owner_b'));
  await add('recover_signed_by_old_owner', 'a correct rpub and rsig, the entry signed by the OLD owner A', 'owner_a',
      await signed(label, 4, recover, 'owner_a'));
  await add('a_update_after_recover', 'the old owner A, after the recover, signing an update that names B', 'owner_a',
      await signed(label, 5, after, 'owner_a'));
  await add('m_claim_names_a', "a claim naming Alice's key, signed by Mallory", 'owner_m',
      await signed(label, 1, claim, 'owner_m'));
  await add('a_update_other_label', "Alice's update, for another handle's label, inside alice.42's history", 'owner_a',
      await signed(otherLabel, 2, rotate, 'owner_a'));

  final histories = <(String, List<String>, int?, HandleRefusal?)>[
    ('claim, rotate, pause, recover, update', ['claim', 'update_rotate', 'update_pause', 'recover', 'update_after_recover'], null, null),
    ('an update as the first entry', ['update_rotate'], 0, HandleRefusal.notClaimed),
    ('a claim on a label that exists', ['claim', 'm_claim_taken'], 1, HandleRefusal.taken),
    ("a foreign key signs an update keeping the owner", ['claim', 'm_update_foreign_sig'], 1, HandleRefusal.badSignature),
    ('an update that names a new owner', ['claim', 'm_update_foreign_owner'], 1, HandleRefusal.ownerChanged),
    ('an update that changes rc', ['claim', 'a_update_rc_change'], 1, HandleRefusal.rcChanged),
    ('a version that does not increase', ['claim', 'update_rotate', 'a_update_stale'], 2, HandleRefusal.staleVersion),
    ('an entry replayed', ['claim', 'update_rotate', 'update_rotate'], 2, HandleRefusal.staleVersion),
    ('an oversize value', ['claim', 'a_update_oversize'], 1, HandleRefusal.tooLarge),
    ('a value that is not canonical', ['claim', 'a_update_not_canonical'], 1, HandleRefusal.malformed),
    ('a recover with the wrong recovery key', ['claim', 'update_rotate', 'update_pause', 'm_recover_wrong_key'], 3, HandleRefusal.wrongRecoveryKey),
    ('a recover whose rsig is over another rc', ['claim', 'update_rotate', 'update_pause', 'recover_rsig_other_rc'], 3, HandleRefusal.badRecoverySignature),
    ('a recover without rsig', ['claim', 'update_rotate', 'update_pause', 'recover_without_rsig'], 3, HandleRefusal.malformed),
    ('a recover signed by the old owner', ['claim', 'update_rotate', 'update_pause', 'recover_signed_by_old_owner'], 3, HandleRefusal.badSignature),
    ('the old owner after a recover', ['claim', 'update_rotate', 'update_pause', 'recover', 'a_update_after_recover'], 4, HandleRefusal.badSignature),
    ('a claim not signed by the owner it names', ['m_claim_names_a'], 0, HandleRefusal.badSignature),
    ("another label's entry in the history", ['claim', 'a_update_other_label'], 1, HandleRefusal.otherLabel),
  ];
  final historyOut = <Map<String, Object?>>[];
  for (final (name, names, at, reason) in histories) {
    final v = await checkHandleHistory([for (final n in names) entries[n]!]);
    check(v.refusedAt == at && v.reason == reason, 'history: $name');
    historyOut.add({
      'name': name,
      'entries': names,
      'verdict': at == null
          ? {
              'ok': true,
              'version': v.state!.version,
              'owner': hex(v.state!.owner),
              'rc': hex(v.state!.rc),
              'intro': v.state!.record.intro == null ? null : hex(v.state!.record.intro!),
              'pow': v.state!.record.pow,
            }
          : {'ok': false, 'refused_at': at, 'reason': reason!.name},
    });
  }

  // Values that are not records: each the canonical claim with one thing
  // changed, every one of which a lenient parser would read as the same
  // record or as a record at all.
  final canon = utf8.decode(claim.encode());
  final cj = claim.toJson();
  String swapAlphabet(String s) => s.replaceAll('-', '+').replaceAll('_', '/');
  final b64member = ['owner', 'intro', 'xintro', 'rc'].firstWhere(
      (m) => (cj[m] as String).contains(RegExp(r'[-_]')),
      orElse: () => throw StateError('no member with - or _'));
  final ownerB64 = cj['owner'] as String;
  final lastIx = _b64urlAlphabet.indexOf(ownerB64[42]);
  final noncanonicalTail = ownerB64.substring(0, 42) + _b64urlAlphabet[lastIx | 1];
  check(lastIx & 3 == 0 && noncanonicalTail != ownerB64, 'unused bits flipped');
  final notRecords = <(String, String)>[
    (canon.replaceFirst('"k":', '"k": '), 'whitespace'),
    ('$canon\n', 'a trailing newline'),
    ('\ufeff$canon', 'a byte-order mark'),
    (canon.replaceFirst('{"k":"claim",', '{').replaceFirst('}', ',"k":"claim"}'), 'members out of order'),
    (canon.replaceFirst(',"intro":"${cj['intro']}"', ''), 'intro absent rather than present'),
    (canon.replaceFirst('}', ',"x":1}'), 'an extra member'),
    (canon.replaceFirst('}', ',"rpub":null}'), 'rpub, as null, on a claim'),
    (canon.replaceFirst('}', ',"rpub":"${cj['owner']}","rsig":"${b64url(rsig)}"}'), 'rpub and rsig on a claim'),
    (canon.replaceFirst('"k":"claim"', '"k":"Claim"'), 'k in another case'),
    (canon.replaceFirst('"k":"claim"', '"k":"\\u0063laim"'), 'an escaped character'),
    (canon.replaceFirst('"k":"claim",', '"k":"claim","k":"claim",'), 'a duplicated member'),
    (canon.replaceFirst('"pow":20', '"pow":20.0'), 'pow as 20.0'),
    (canon.replaceFirst('"pow":20', '"pow":15'), 'pow below 16'),
    (canon.replaceFirst('"pow":20', '"pow":29'), 'pow above 28'),
    (canon.replaceFirst('"pow":20', '"pow":"20"'), 'pow as a string'),
    (canon.replaceFirst(ownerB64, '$ownerB64='), 'padded base64url'),
    (canon.replaceFirst(cj[b64member] as String, swapAlphabet(cj[b64member] as String)), 'the standard base64 alphabet'),
    (canon.replaceFirst(ownerB64, noncanonicalTail), 'base64url whose unused low bits are set'),
    (canon.replaceFirst(ownerB64, ownerB64.substring(0, 42)), 'an owner key one byte short'),
    (canon.replaceFirst('"rc":"${cj['rc']}"', '"rc":null'), 'rc as null'),
    (canon.replaceFirst('"xintro":"${cj['xintro']}"', '"xintro":null'), 'xintro null while intro is not'),
    (canon.replaceFirst('"intro":"${cj['intro']}"', '"intro":null'), 'intro null while xintro is not'),
    (canon.replaceFirst(',"xintro":"${cj['xintro']}"', ''), 'xintro absent'),
    (canon.replaceFirst('"intro":"${cj['intro']}","xintro":"${cj['xintro']}"',
        '"xintro":"${cj['xintro']}","intro":"${cj['intro']}"'), 'xintro before intro'),
    (canon.replaceFirst(cj['xintro'] as String, (cj['xintro'] as String).substring(0, 42)),
        'an xintro key one byte short'),
    (utf8.decode(pause.encode()).replaceFirst('"xintro":null', '"xintro":"${cj['xintro']}"'),
        'a paused record that still names an xintro'),
  ];
  final notRecordOut = <Map<String, Object?>>[];
  for (final (text, why) in notRecords) {
    check(text != canon, 'changed: $why');
    var refused = false;
    try {
      HandleRecord.decode(utf8.encode(text));
    } on HandleRecordFormatException {
      refused = true;
    }
    check(refused, 'refused: $why');
    notRecordOut.add({'why': why, 'value': hex(utf8.encode(text))});
  }

  // --- §21.7 the request, sealed to xintro ---------------------------------------------
  const nowMs = 1791460800000; // 2026-10-08T12:00:00Z
  final day = introPowDay(nowMs);
  check(day == 20734, 'day');
  final rid = await introRoutingId(pubs['intro_a1']!);
  final ridBytes = await refSha256(pubs['intro_a1']!);
  final otherRid = await introRoutingId(pubs['intro_a2']!);
  final bob = await ZIdentity.fromSeeds(edSeed: d.next(32), xSeed: d.next(32));
  final alice = await ZIdentity.fromSeeds(edSeed: d.next(32), xSeed: d.next(32));
  final carol = await ZIdentity.fromSeeds(edSeed: d.next(32), xSeed: d.next(32));
  final bobRid = await bob.routingId();
  final creq = await ContactRequest.create(
      me: bob, toRid: rid, displayName: 'Bob', ts: nowMs);
  d.takeDraws();
  final envelope = await d.run(() => SealedEnvelope.seal(
      toXPub: xpubs['intro_a1']!, fromRid: bobRid, payload: creq.encode()));
  final sealDraws = d.takeDraws();
  check(sealDraws.length == 2 && sealDraws[0].length == 32 && sealDraws[1].length == 12,
      'a seal draws an ephemeral seed and a nonce, nothing else');
  final introId = await handleIntroIdentity(seeds['intro_a1']!);
  final opened = await SealedEnvelope.open(
      myXSeed: introId.xSeed, myXPub: introId.xPub, blob: envelope);
  check(opened != null && opened.fromRid == bobRid && opened.payload == creq.encode(),
      'the introduction identity opens the request');
  check(
      await SealedEnvelope.open(
              myXSeed: xseeds['intro_a2']!, myXPub: xpubs['intro_a2']!, blob: envelope) ==
          null,
      'another introduction key does not');
  check(
      await ContactRequest.tryParse(opened!.payload)!
          .verify(expectedTo: rid, sealedFrom: opened.fromRid),
      'the request is addressed to the introduction mailbox');

  // --- §21.7 the proof-of-work stamp, over that envelope ------------------------------
  final envBytes = utf8.encode(envelope);
  final stampsOut = <Map<String, Object?>>[];
  Uint8List? firstNonce;
  var firstZeros = 0;
  for (final bits in [16, 18]) {
    final start = d.next(16);
    final nonce = createIntroPowStamp(
        introRid: rid, day: day, envelope: envBytes, bits: bits, startNonce: start);
    final input = concatBytes([
      utf8.encode(introPowContext),
      ridBytes,
      (ByteData(4)..setUint32(0, day)).buffer.asUint8List(),
      await refSha256(envBytes),
      nonce,
    ]);
    check(eq(input, introPowInput(ridBytes: ridBytes, day: day, envelopeHash: await refSha256(envBytes), nonce: nonce)),
        'pow input');
    final digest = await refSha256(input);
    final zeros = introPowZeroBits(digest);
    check(zeros >= bits, 'stamp has $bits bits');
    firstNonce ??= nonce;
    if (bits == 16) firstZeros = zeros;
    stampsOut.add({
      'routing_id': rid,
      'rid_bytes': hex(ridBytes),
      'day': day,
      'envelope': envelope,
      'envelope_sha256': hex(await refSha256(envBytes)),
      'bits': bits,
      'start_nonce': hex(start),
      'nonce': hex(nonce),
      'frame_member': b64url(nonce),
      'input': hex(input),
      'digest': hex(digest),
      'zero_bits': zeros,
    });
  }
  Future<Map<String, Object?>> refusal(String why,
      {String? r, int? dy, String? env, int? bits}) async {
    final rr = r ?? rid;
    final dd = dy ?? day;
    final ee = utf8.encode(env ?? envelope);
    final bb = bits ?? 16;
    check(
        !await verifyIntroPowStamp(
            introRid: rr, day: dd, envelope: ee, nonce: firstNonce!, bits: bb),
        'refused: $why');
    final digest = await refSha256(concatBytes([
      utf8.encode(introPowContext),
      unb64url(rr),
      (ByteData(4)..setUint32(0, dd)).buffer.asUint8List(),
      await refSha256(ee),
      firstNonce!,
    ]));
    check(introPowZeroBits(digest) < bb, 'the refusal is the bits');
    return {
      'why': why,
      'routing_id': rr,
      'day': dd,
      'envelope': env ?? envelope,
      'bits': bb,
      'digest': hex(digest),
    };
  }

  final powRefusals = <Map<String, Object?>>[];
  final wrongRid = await refusal('the stamp sent to another mailbox', r: otherRid);
  powRefusals.add(wrongRid);
  powRefusals.add(await refusal('the stamp on another envelope', env: '${envelope}A'));
  powRefusals.add(await refusal('the stamp read for another day', dy: day - 2));
  powRefusals.add(await refusal('one bit more than the stamp has', bits: firstZeros + 1));
  final window = <Map<String, Object?>>[];
  for (final (offsetDays, ok) in [(0, true), (1, true), (2, false), (-1, false)]) {
    final at = nowMs + offsetDays * 86400000;
    check(
        await introPowAcceptable(
                introRid: rid,
                envelope: envBytes,
                nonce: firstNonce!,
                bits: 16,
                nowMs: at) ==
            ok,
        'window $offsetDays');
    window.add({'relay_now_ms': at, 'relay_day': introPowDay(at), 'accepted': ok});
  }

  // --- §21.7 the acknowledgement ------------------------------------------------------
  final creqInput = ContactRequest.signingInput(creq.bundle, creq.toRid, creq.ts);
  final creqId = await contactRequestId(creq);
  check(eq(creqId, await refSha256(creqInput)), 'creq id');
  final again = await ContactRequest.create(
      me: bob, toRid: rid, displayName: 'Bob', ts: nowMs + 1);
  final otherCreqId = await contactRequestId(again);
  final ia = await signIntroAck(
      introSeed: seeds['intro_a1']!,
      requesterRid: bobRid,
      ownerAccountEdPub: alice.edPub,
      creqId: creqId);
  final ackInput = concatBytes([
    utf8.encode(introAckContext),
    unb64url(bobRid),
    alice.edPub,
    creqId,
  ]);
  check(eq(unb64url(ia), await refEdSign(seeds['intro_a1']!, ackInput)), 'ia');
  final accept = await ContactRequest.create(
      me: alice, toRid: bobRid, displayName: 'Alice', ts: nowMs + 60000);
  final acceptJson = {
    'v': 1,
    't': 'creq',
    'to': accept.toRid,
    'ts': accept.ts,
    'bundle': accept.bundle.toJson(),
    'sig': b64(accept.sig),
    'ia': ia,
  };
  final acceptPayload = base64Encode(utf8.encode(jsonEncode(acceptJson)));
  final reparsed = ContactRequest.tryParse(acceptPayload);
  check(reparsed != null && await reparsed.verify(expectedTo: bobRid),
      'the acceptance with ia is still a valid creq to a reader that ignores ia');
  final ackRefusals = <Map<String, Object?>>[];
  for (final (why, pub, req, owner, id) in [
    ('verified against another introduction key', pubs['intro_a2']!, bobRid, alice.edPub, creqId),
    ('presented to another requester', pubs['intro_a1']!, await carol.routingId(), alice.edPub, creqId),
    ('worn by another account', pubs['intro_a1']!, bobRid, carol.edPub, creqId),
    ("matched to the requester's other request", pubs['intro_a1']!, bobRid, alice.edPub, otherCreqId),
  ]) {
    check(
        !await verifyIntroAck(
            ia: ia, introPub: pub, requesterRid: req, ownerAccountEdPub: owner, creqId: id),
        'ack refused: $why');
    ackRefusals.add({
      'why': why,
      'intro_pub': hex(pub),
      'requester_rid': req,
      'owner_account_ed_pub': hex(owner),
      'creq_id': hex(id),
    });
  }

  return {
    'suite': 'handles',
    'version': vectorsVersion,
    'description':
        'Handles (PROTOCOL 21, ADR 0015 revision 2): the grammar (what a person '
            'types -> a canonical nick.digits, or why not, including Unicode '
            'look-alikes and every reserved nick); labels (Argon2id of the '
            'canonical handle, production parameters, plus small-parameter '
            'answers for checking an independent Argon2id); owner, '
            'introduction and recovery keys from seeds, the introduction '
            'seed giving both intro (Ed25519) and xintro (X25519, by HKDF); '
            'claim, update and recover records with their publish inputs and '
            'signatures; owner-rule histories with their verdicts; values '
            'that are not records; a contact request sealed to xintro and '
            'opened with the introduction identity; proof-of-work stamps at '
            'low difficulty over that envelope, with the cases a relay '
            'refuses; and an introduction acknowledgement with the cases a '
            'requester refuses. The log (21.5) and the relay (21.6) pin their '
            'own halves elsewhere.',
    'grammar': {
      'nick': '3-20 of [a-z0-9_], first a letter, no "__", not ending "_"',
      'digits': '2-6 ASCII digits, compared as a string',
      'normalisation':
          'trim ASCII whitespace (U+0009-U+000D, U+0020), remove ONE leading '
              '"@", lower-case A-Z; nothing else is folded',
      'reserved': reservedHandleNicks,
      'valid': validOut,
      'invalid': invalidOut,
    },
    'labels': {
      'kdf': {
        'name': 'argon2id',
        'rfc': 9106,
        'version': 19,
        'salt': handleLabelSalt,
        'memory_kib': handleLabelMemoryKib,
        'iterations': handleLabelIterations,
        'parallelism': handleLabelParallelism,
        'tag_len': handleLabelLength,
        'password': 'the canonical handle, ASCII',
      },
      'production': labelOut,
      'small_parameters': smallOut,
    },
    'keys': keyOut,
    'recovery': recoveryOut,
    'record_rules': {
      'publish_context': handlePublishContext,
      'recover_context': handleRecoverContext,
      'rc_context': handleRcContext,
      'max_value_bytes': handleMaxValueBytes,
      'pow_min': handlePowMinBits,
      'pow_max': handlePowMaxBits,
    },
    'entries': entryOut,
    'histories': historyOut,
    'not_records': notRecordOut,
    'request': {
      'sealed_to': 'x_pub of intro_a1: the record\'s xintro',
      'to_x_pub': hex(xpubs['intro_a1']!),
      'to_routing_id': rid,
      'from_rid': bobRid,
      'payload': creq.encode(),
      'eph_seed': hex(sealDraws[0]),
      'nonce': hex(sealDraws[1]),
      'envelope': envelope,
    },
    'pow': {
      'context': introPowContext,
      'input_rule':
          'utf8(context) || rid_bytes(32) || u32be(day) || SHA-256(utf8(envelope)) || nonce(16)',
      'now_ms': nowMs,
      'stamps': stampsOut,
      'must_refuse': powRefusals,
      'acceptance_window': window,
    },
    'intro_ack': {
      'context': introAckContext,
      'intro_key': 'intro_a1',
      'intro_pub': hex(pubs['intro_a1']!),
      'requester': {
        'ed_seed': hex(bob.edSeed),
        'x_seed': hex(bob.xSeed),
        'ed_pub': hex(bob.edPub),
        'routing_id': bobRid,
      },
      'owner_account': {
        'ed_seed': hex(alice.edSeed),
        'x_seed': hex(alice.xSeed),
        'ed_pub': hex(alice.edPub),
        'routing_id': await alice.routingId(),
      },
      'creq_payload': creq.encode(),
      'creq_signing_input': hex(creqInput),
      'creq_id': hex(creqId),
      'ack_input': hex(ackInput),
      'ia': ia,
      'acceptance_json': jsonEncode(acceptJson),
      'acceptance_payload': acceptPayload,
      'must_refuse': ackRefusals,
    },
  };
}

const String _b64urlAlphabet =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

Uint8List _u64(int n) => (ByteData(8)..setUint64(0, n)).buffer.asUint8List();

Future<Map<String, Map<String, Map<String, Object?>>>> generateAll() async {
  final a = await actors();
  return {
    'v1': {
      'identity': await suiteIdentity(a),
      'handshake': await suiteHandshake(a),
      'ratchet': await suiteRatchet(a),
      'sealed_sender': await suiteSealed(a),
      'attachments': await suiteAttachments(a),
      'multidevice': await suiteMultidevice(a),
      'pairing': await suitePairing(a),
      'inner_messages': await suiteInnerMessages(a),
      // ADR 0022: a new file; every one above is unchanged by it.
      'device_pop': await suiteDevicePop(a),
      'group_state': await suiteGroupState(a),
    },
    'v2': {
      'mlkem768': await suiteMlKem(),
      'pq_ratchet': await suitePqRatchet(a),
      'pq_rekey': await suitePqRekey(a),
    },
    'v3': {
      'mldsa65': await suiteMlDsa(),
      'contact_code_v3': await suiteContactCodeV3(),
      'contact_code_pqc_sig': await suiteContactCodePqcSig(),
      'device_cert_v3': await suiteDeviceCertV3(a),
    },
    'pair-v2': {
      'pairing_v2': await suitePairingV2(a),
    },
    'relay-auth-v2': {
      'relay_auth_v2': await suiteRelayAuthV2(a),
    },
    'connect': {
      'connect': await suiteConnect(a),
      'mailboxes': await suiteConnectMailboxes(),
      'group': await suiteConnectGroup(),
      'invite_v2': await suiteConnectV2(),
    },
    'backup': {
      'archive': await suiteBackup(),
      'archive_1_1': await suiteBackupMinor1(),
    },
    'handles': {
      'handles': await suiteHandles(),
    },
  };
}

String encodeVectorFile(Map<String, Object?> doc) =>
    '${const JsonEncoder.withIndent('  ').convert(doc)}\n';
