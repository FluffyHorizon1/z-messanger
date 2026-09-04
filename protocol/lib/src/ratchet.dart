import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'pq.dart';
import 'util.dart';

/// Double Ratchet (Signal specification) with:
///   - X25519 for the Diffie-Hellman ratchet
///   - HKDF-SHA256 for the root chain
///   - HMAC-SHA256 for the symmetric chains
///   - XChaCha20-Poly1305 for message encryption
///   - (v2) an ML-KEM-768 shared secret mixed into message keys, see pq.dart
///
/// Every message is encrypted with a fresh, single-use message key. Old keys
/// are deleted as soon as they are used (forward secrecy); every round trip
/// injects fresh DH entropy (post-compromise healing).

const int maxSkipPerChain = 512; // max out-of-order gap within a chain
const int maxSkippedStored = 1536; // global cap on cached skipped keys

class RatchetHeader {
  final Uint8List dhPub;
  final int pn;
  final int n;

  /// v2: the message key of this message is PQ-mixed (the sender holds the
  /// ML-KEM shared secret).
  final bool pq;

  /// v2: ML-KEM-768 ciphertext, attached by the encapsulating side until the
  /// peer proves it holds the secret. Authenticated: it is part of the AAD.
  final Uint8List? pqCt;

  /// v2 (7.5b): which post-quantum generation this message's mix key belongs
  /// to. 0 is the first (and, without periodic re-keying, only) generation and
  /// is NOT emitted — a generation-0 header is byte-identical to the original
  /// v2 encoding. A re-key increments it, and the field appears from 1 on.
  final int pqGen;

  RatchetHeader({
    required this.dhPub,
    required this.pn,
    required this.n,
    this.pq = false,
    this.pqCt,
    this.pqGen = 0,
  });

  /// Byte-stable encoding, used both on the wire and as AEAD associated data.
  /// A header without v2 fields encodes exactly as in v1; a generation-0 v2
  /// header exactly as the original v2 encoding.
  Uint8List encode() {
    final sb = StringBuffer('{"dh":"${b64(dhPub)}","n":$n,"pn":$pn');
    if (pq) sb.write(',"pq":1');
    if (pqGen > 0) sb.write(',"pqg":$pqGen');
    if (pqCt != null) sb.write(',"pqct":"${b64(pqCt!)}"');
    sb.write('}');
    return Uint8List.fromList(utf8.encode(sb.toString()));
  }

  Map<String, Object?> toJson() => {
        'dh': b64(dhPub),
        'n': n,
        'pn': pn,
        if (pq) 'pq': 1,
        if (pqGen > 0) 'pqg': pqGen,
        if (pqCt != null) 'pqct': b64(pqCt!),
      };

  static RatchetHeader fromJson(Map<String, Object?> j) => RatchetHeader(
        dhPub: unb64(j['dh'] as String),
        pn: (j['pn'] as num).toInt(),
        n: (j['n'] as num).toInt(),
        pq: j['pq'] == 1,
        pqCt: j['pqct'] == null ? null : unb64(j['pqct'] as String),
        pqGen: (j['pqg'] as num?)?.toInt() ?? 0,
      );
}

/// v2 post-quantum state of one conversation (shared by all its sessions —
/// the KEM secret is between the two parties, not tied to a DH session).
class PqState {
  /// Offerer: seed of my pending ML-KEM key pair, until a ciphertext arrives.
  Uint8List? dkSeed;

  /// The agreed shared secret for the current generation [gen] (both sides).
  Uint8List? k;

  /// Encapsulator: ciphertext to attach until the peer sends a `pq` message
  /// of the current generation.
  Uint8List? ct;

  /// The peer has sent a PQ-mixed message of the current generation: it holds
  /// [k].
  bool acked;

  /// Offerer: the initial (generation-0) offer has been handed to the caller.
  bool offered;

  /// 7.5b: the established generation of [k]. 0 is the first establishment;
  /// every periodic re-key increments it, giving the PQ layer post-compromise
  /// security (a stolen state does not reveal the next generation's secret).
  int gen;

  /// 7.5b: the immediately previous generation and its secret, retained only
  /// across a re-key crossover so messages still in flight under the old
  /// generation decrypt. Dropped/overwritten at the next re-key.
  int? oldGen;
  Uint8List? oldK;

  /// 7.5b offerer: the generation the pending [dkSeed] was generated for (0 for
  /// the initial offer, gen+1 for a re-key offer).
  int offerGen;

  /// 7.5b offerer: when this side last STARTED a re-key, for interval pacing.
  int lastRekeyMs;

  PqState({
    this.dkSeed,
    this.k,
    this.ct,
    this.acked = false,
    this.offered = false,
    this.gen = 0,
    this.oldGen,
    this.oldK,
    this.offerGen = 0,
    this.lastRekeyMs = 0,
  });

  bool get established => k != null;

  /// The secret to mix for a message tagged with generation [g], or null if
  /// this side holds no secret for it (fail closed).
  Uint8List? secretFor(int g) {
    if (k != null && g == gen) return k;
    if (oldK != null && g == oldGen) return oldK;
    return null;
  }

  PqState clone() => PqState(
        dkSeed: dkSeed == null ? null : Uint8List.fromList(dkSeed!),
        k: k == null ? null : Uint8List.fromList(k!),
        ct: ct == null ? null : Uint8List.fromList(ct!),
        acked: acked,
        offered: offered,
        gen: gen,
        oldGen: oldGen,
        oldK: oldK == null ? null : Uint8List.fromList(oldK!),
        offerGen: offerGen,
        lastRekeyMs: lastRekeyMs,
      );

  void copyFrom(PqState o) {
    dkSeed = o.dkSeed;
    k = o.k;
    ct = o.ct;
    acked = o.acked;
    offered = o.offered;
    gen = o.gen;
    oldGen = o.oldGen;
    oldK = o.oldK;
    offerGen = o.offerGen;
    lastRekeyMs = o.lastRekeyMs;
  }

  Map<String, Object?> toJson() => {
        if (dkSeed != null) 'dkSeed': b64(dkSeed!),
        if (k != null) 'k': b64(k!),
        if (ct != null) 'ct': b64(ct!),
        'acked': acked,
        'offered': offered,
        if (gen > 0) 'gen': gen,
        if (oldGen != null) 'oldGen': oldGen,
        if (oldK != null) 'oldK': b64(oldK!),
        if (offerGen > 0) 'offerGen': offerGen,
        if (lastRekeyMs > 0) 'lastRekeyMs': lastRekeyMs,
      };

  static PqState fromJson(Map<String, Object?>? j) => j == null
      ? PqState()
      : PqState(
          dkSeed: j['dkSeed'] == null ? null : unb64(j['dkSeed'] as String),
          k: j['k'] == null ? null : unb64(j['k'] as String),
          ct: j['ct'] == null ? null : unb64(j['ct'] as String),
          acked: j['acked'] == true,
          offered: j['offered'] == true,
          gen: (j['gen'] as num?)?.toInt() ?? 0,
          oldGen: (j['oldGen'] as num?)?.toInt(),
          oldK: j['oldK'] == null ? null : unb64(j['oldK'] as String),
          offerGen: (j['offerGen'] as num?)?.toInt() ?? 0,
          lastRekeyMs: (j['lastRekeyMs'] as num?)?.toInt() ?? 0,
        );
}

class RatchetMessage {
  final RatchetHeader header;
  final Uint8List nonce;
  final Uint8List cipherText;
  final Uint8List mac;
  RatchetMessage(
      {required this.header,
      required this.nonce,
      required this.cipherText,
      required this.mac});
}

class RatchetDecryptException implements Exception {
  final String message;
  RatchetDecryptException(this.message);
  @override
  String toString() => 'RatchetDecryptException: $message';
}

class RatchetState {
  Uint8List rootKey;
  Uint8List dhsSeed; // our current ratchet private seed
  Uint8List dhsPub; // our current ratchet public key
  Uint8List? dhrPub; // their current ratchet public key
  Uint8List? cks; // sending chain key
  Uint8List? ckr; // receiving chain key
  int ns;
  int nr;
  int pn;
  final Uint8List ad; // associated data binding both identities
  /// Cached message keys for out-of-order delivery: "b64(dh)|n" -> b64(mk)
  final LinkedHashMap<String, String> skipped;

  RatchetState({
    required this.rootKey,
    required this.dhsSeed,
    required this.dhsPub,
    required this.dhrPub,
    required this.cks,
    required this.ckr,
    required this.ns,
    required this.nr,
    required this.pn,
    required this.ad,
    LinkedHashMap<String, String>? skipped,
  }) : skipped = skipped ?? LinkedHashMap();

  RatchetState clone() => RatchetState(
        rootKey: Uint8List.fromList(rootKey),
        dhsSeed: Uint8List.fromList(dhsSeed),
        dhsPub: Uint8List.fromList(dhsPub),
        dhrPub: dhrPub == null ? null : Uint8List.fromList(dhrPub!),
        cks: cks == null ? null : Uint8List.fromList(cks!),
        ckr: ckr == null ? null : Uint8List.fromList(ckr!),
        ns: ns,
        nr: nr,
        pn: pn,
        ad: Uint8List.fromList(ad),
        skipped: LinkedHashMap.from(skipped),
      );

  Map<String, Object?> toJson() => {
        'rk': b64(rootKey),
        'dhsSeed': b64(dhsSeed),
        'dhsPub': b64(dhsPub),
        'dhrPub': dhrPub == null ? null : b64(dhrPub!),
        'cks': cks == null ? null : b64(cks!),
        'ckr': ckr == null ? null : b64(ckr!),
        'ns': ns,
        'nr': nr,
        'pn': pn,
        'ad': b64(ad),
        'skipped': skipped,
      };

  static RatchetState fromJson(Map<String, Object?> j) => RatchetState(
        rootKey: unb64(j['rk'] as String),
        dhsSeed: unb64(j['dhsSeed'] as String),
        dhsPub: unb64(j['dhsPub'] as String),
        dhrPub: j['dhrPub'] == null ? null : unb64(j['dhrPub'] as String),
        cks: j['cks'] == null ? null : unb64(j['cks'] as String),
        ckr: j['ckr'] == null ? null : unb64(j['ckr'] as String),
        ns: (j['ns'] as num).toInt(),
        nr: (j['nr'] as num).toInt(),
        pn: (j['pn'] as num).toInt(),
        ad: unb64(j['ad'] as String),
        skipped: LinkedHashMap<String, String>.from(
            (j['skipped'] as Map).cast<String, String>()),
      );
}

// ---------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------

final _x25519 = X25519();
final _aead = Xchacha20.poly1305Aead();

Future<Uint8List> _dh(Uint8List privSeed, Uint8List remotePub) async {
  final kp = await _x25519.newKeyPairFromSeed(privSeed);
  final secret = await _x25519.sharedSecretKey(
    keyPair: kp,
    remotePublicKey: SimplePublicKey(remotePub, type: KeyPairType.x25519),
  );
  return Uint8List.fromList(await secret.extractBytes());
}

/// KDF_RK: (rootKey, dhOutput) -> (newRootKey, chainKey)
Future<(Uint8List, Uint8List)> _kdfRk(Uint8List rk, Uint8List dhOut) async {
  final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 64);
  final out = Uint8List.fromList(await (await hkdf.deriveKey(
    secretKey: SecretKey(dhOut),
    nonce: rk,
    info: utf8.encode('Z-RK-v1'),
  ))
      .extractBytes());
  return (out.sublist(0, 32), out.sublist(32, 64));
}

/// KDF_CK: chainKey -> (messageKey, nextChainKey)
Future<(Uint8List, Uint8List)> _kdfCk(Uint8List ck) async {
  final hmac = Hmac.sha256();
  final mk = await hmac.calculateMac(const [0x01], secretKey: SecretKey(ck));
  final next = await hmac.calculateMac(const [0x02], secretKey: SecretKey(ck));
  return (Uint8List.fromList(mk.bytes), Uint8List.fromList(next.bytes));
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

/// Initiator ("Alice"): [sk] from the handshake, [theirDhPub] is the
/// responder's initial ratchet public key (their identity X25519 key).
Future<RatchetState> ratchetInitInitiator({
  required Uint8List sk,
  required Uint8List theirDhPub,
  required Uint8List ad,
}) async {
  final dhsSeed = randomBytes(32);
  final kp = await _x25519.newKeyPairFromSeed(dhsSeed);
  final dhsPub = Uint8List.fromList((await kp.extractPublicKey()).bytes);
  final (rk, cks) = await _kdfRk(sk, await _dh(dhsSeed, theirDhPub));
  return RatchetState(
    rootKey: rk,
    dhsSeed: dhsSeed,
    dhsPub: dhsPub,
    dhrPub: theirDhPub,
    cks: cks,
    ckr: null,
    ns: 0,
    nr: 0,
    pn: 0,
    ad: ad,
  );
}

/// Responder ("Bob"): uses his identity X25519 pair as the initial ratchet
/// key pair; the first incoming message triggers the first DH ratchet step.
Future<RatchetState> ratchetInitResponder({
  required Uint8List sk,
  required Uint8List myXSeed,
  required Uint8List myXPub,
  required Uint8List ad,
}) async {
  return RatchetState(
    rootKey: sk,
    dhsSeed: Uint8List.fromList(myXSeed),
    dhsPub: Uint8List.fromList(myXPub),
    dhrPub: null,
    cks: null,
    ckr: null,
    ns: 0,
    nr: 0,
    pn: 0,
    ad: ad,
  );
}

// ---------------------------------------------------------------------------
// Encrypt / decrypt
// ---------------------------------------------------------------------------

/// Encrypts [plaintext]; mutates [state] (advances the sending chain).
/// Callers must persist the new state BEFORE handing the ciphertext to the
/// network, so a crash can never reuse a message key.
Future<RatchetMessage> ratchetEncrypt(RatchetState state, Uint8List plaintext,
    {PqState? pq}) async {
  final cks = state.cks;
  if (cks == null) {
    throw StateError(
        'sending chain not initialized (responder must receive before sending '
        'on this session)');
  }
  final (mk0, nextCk) = await _kdfCk(cks);
  // v2: once the ML-KEM secret is established every message key is mixed
  // with it, and the header says so. The encapsulating side also carries the
  // ciphertext until the peer has demonstrably decapsulated it.
  final pqK = pq?.k;
  final mk = pqK == null ? mk0 : await pqMixMessageKey(mk0, pqK);
  final header = RatchetHeader(
    dhPub: state.dhsPub,
    pn: state.pn,
    n: state.ns,
    pq: pqK != null,
    pqGen: pqK != null ? pq!.gen : 0,
    pqCt: pqK != null && !(pq!.acked) ? pq.ct : null,
  );
  final nonce = randomBytes(24);
  final box = await _aead.encrypt(
    pad(plaintext),
    secretKey: SecretKey(mk),
    nonce: nonce,
    aad: concatBytes([state.ad, header.encode()]),
  );
  state.cks = nextCk;
  state.ns += 1;
  return RatchetMessage(
    header: header,
    nonce: nonce,
    cipherText: Uint8List.fromList(box.cipherText),
    mac: Uint8List.fromList(box.mac.bytes),
  );
}

/// Decrypts a message, handling out-of-order delivery and DH ratchet steps.
/// On success returns the plaintext and REPLACES the contents of [state].
/// On any failure the state is left completely untouched.
Future<Uint8List> ratchetDecrypt(RatchetState state, RatchetMessage msg,
    {PqState? pq}) async {
  final work = state.clone();
  final pqWork = pq?.clone();
  final plaintext = await _decryptInner(work, msg, pqWork);
  // Commit.
  pq?.copyFrom(pqWork!);
  state
    ..rootKey = work.rootKey
    ..dhsSeed = work.dhsSeed
    ..dhsPub = work.dhsPub
    ..dhrPub = work.dhrPub
    ..cks = work.cks
    ..ckr = work.ckr
    ..ns = work.ns
    ..nr = work.nr
    ..pn = work.pn;
  state.skipped
    ..clear()
    ..addAll(work.skipped);
  return plaintext;
}

Future<Uint8List> _decryptInner(
    RatchetState s, RatchetMessage msg, PqState? pq) async {
  // 0. v2: a ciphertext in the header establishes the ML-KEM secret for its
  //    generation (only the side that offered a key for that generation can
  //    decapsulate; anyone else must reject). 7.5b: a ciphertext for gen+1
  //    rotates the secret, retaining the previous one for in-flight messages.
  final ct = msg.header.pqCt;
  final hg = msg.header.pqGen;
  if (ct != null && pq != null && pq.secretFor(hg) == null) {
    final seed = pq.dkSeed;
    if (seed == null || pq.offerGen != hg) {
      throw RatchetDecryptException('pq ciphertext but no pending key');
    }
    final newK =
        pqDecapsulate(seed, ct); // wrong ct → pseudorandom k → MAC fails
    if (pq.k != null) {
      pq.oldGen = pq.gen; // retain the outgoing generation across the crossover
      pq.oldK = pq.k;
    }
    pq
      ..k = newK
      ..gen = hg
      ..dkSeed = null // single use; erased on commit
      ..acked = false;
  }
  if (msg.header.pq && (pq == null || pq.secretFor(hg) == null)) {
    throw RatchetDecryptException('pq message without a shared secret');
  }

  // 1. Try skipped message keys (out-of-order arrivals).
  final skipKey = '${b64(msg.header.dhPub)}|${msg.header.n}';
  final cachedMk = s.skipped.remove(skipKey);
  if (cachedMk != null) {
    return _aeadOpen(unb64(cachedMk), s, msg, pq);
  }

  // 2. New ratchet public key? Perform a DH ratchet step.
  final sameDh =
      s.dhrPub != null && constantTimeEquals(s.dhrPub!, msg.header.dhPub);
  if (!sameDh) {
    await _skipMessageKeys(s, msg.header.pn); // finish the previous chain
    await _dhRatchetStep(s, msg.header.dhPub);
  }

  // 3. Skip forward within the current receiving chain if needed.
  await _skipMessageKeys(s, msg.header.n);

  final ckr = s.ckr;
  if (ckr == null) {
    throw RatchetDecryptException('no receiving chain');
  }
  final (mk, nextCk) = await _kdfCk(ckr);
  final plain = await _aeadOpen(mk, s, msg, pq);
  s.ckr = nextCk;
  s.nr += 1;
  return plain;
}

Future<Uint8List> _aeadOpen(
    Uint8List mk0, RatchetState s, RatchetMessage msg, PqState? pq) async {
  final mk = msg.header.pq
      ? await pqMixMessageKey(mk0, pq!.secretFor(msg.header.pqGen)!)
      : mk0;
  try {
    final clear = await _aead.decrypt(
      SecretBox(msg.cipherText, nonce: msg.nonce, mac: Mac(msg.mac)),
      secretKey: SecretKey(mk),
      aad: concatBytes([s.ad, msg.header.encode()]),
    );
    // The peer provably holds the CURRENT generation's secret: the encapsulator
    // can stop attaching its ciphertext. An in-flight message from an older
    // generation (during a re-key crossover) does not count.
    if (msg.header.pq && msg.header.pqGen == pq!.gen) pq.acked = true;
    return unpad(clear);
  } on SecretBoxAuthenticationError {
    throw RatchetDecryptException('authentication failed');
  } on FormatException {
    throw RatchetDecryptException('bad padding');
  }
}

Future<void> _skipMessageKeys(RatchetState s, int until) async {
  if (s.ckr == null) {
    if (until > 0) {
      // No receiving chain yet and the sender says messages preceded this
      // one on a chain we never had — nothing we can do.
    }
    return;
  }
  if (until - s.nr > maxSkipPerChain) {
    throw RatchetDecryptException('too many skipped messages ($until)');
  }
  var ckr = s.ckr!;
  while (s.nr < until) {
    final (mk, next) = await _kdfCk(ckr);
    s.skipped['${b64(s.dhrPub!)}|${s.nr}'] = b64(mk);
    // Bound memory: forget the oldest cached keys first.
    while (s.skipped.length > maxSkippedStored) {
      s.skipped.remove(s.skipped.keys.first);
    }
    ckr = next;
    s.nr += 1;
  }
  s.ckr = ckr;
}

Future<void> _dhRatchetStep(RatchetState s, Uint8List theirNewPub) async {
  s.pn = s.ns;
  s.ns = 0;
  s.nr = 0;
  s.dhrPub = Uint8List.fromList(theirNewPub);
  final (rk1, ckr) = await _kdfRk(s.rootKey, await _dh(s.dhsSeed, s.dhrPub!));
  s.rootKey = rk1;
  s.ckr = ckr;
  final newSeed = randomBytes(32);
  final kp = await _x25519.newKeyPairFromSeed(newSeed);
  s.dhsSeed = newSeed;
  s.dhsPub = Uint8List.fromList((await kp.extractPublicKey()).bytes);
  final (rk2, cks) = await _kdfRk(s.rootKey, await _dh(s.dhsSeed, s.dhrPub!));
  s.rootKey = rk2;
  s.cks = cks;
}
