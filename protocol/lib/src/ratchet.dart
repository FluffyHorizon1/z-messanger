import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'util.dart';

/// Double Ratchet (Signal specification) with:
///   - X25519 for the Diffie-Hellman ratchet
///   - HKDF-SHA256 for the root chain
///   - HMAC-SHA256 for the symmetric chains
///   - XChaCha20-Poly1305 for message encryption
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
  RatchetHeader({required this.dhPub, required this.pn, required this.n});

  /// Byte-stable encoding, used both on the wire and as AEAD associated data.
  Uint8List encode() =>
      Uint8List.fromList(utf8.encode('{"dh":"${b64(dhPub)}","n":$n,"pn":$pn}'));

  Map<String, Object?> toJson() => {'dh': b64(dhPub), 'n': n, 'pn': pn};

  static RatchetHeader fromJson(Map<String, Object?> j) => RatchetHeader(
        dhPub: unb64(j['dh'] as String),
        pn: (j['pn'] as num).toInt(),
        n: (j['n'] as num).toInt(),
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
Future<RatchetMessage> ratchetEncrypt(
    RatchetState state, Uint8List plaintext) async {
  final cks = state.cks;
  if (cks == null) {
    throw StateError(
        'sending chain not initialized (responder must receive before sending '
        'on this session)');
  }
  final (mk, nextCk) = await _kdfCk(cks);
  final header =
      RatchetHeader(dhPub: state.dhsPub, pn: state.pn, n: state.ns);
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
Future<Uint8List> ratchetDecrypt(
    RatchetState state, RatchetMessage msg) async {
  final work = state.clone();
  final plaintext = await _decryptInner(work, msg);
  // Commit.
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

Future<Uint8List> _decryptInner(RatchetState s, RatchetMessage msg) async {
  // 1. Try skipped message keys (out-of-order arrivals).
  final skipKey = '${b64(msg.header.dhPub)}|${msg.header.n}';
  final cachedMk = s.skipped.remove(skipKey);
  if (cachedMk != null) {
    return _aeadOpen(unb64(cachedMk), s, msg);
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
  final plain = await _aeadOpen(mk, s, msg);
  s.ckr = nextCk;
  s.nr += 1;
  return plain;
}

Future<Uint8List> _aeadOpen(
    Uint8List mk, RatchetState s, RatchetMessage msg) async {
  try {
    final clear = await _aead.decrypt(
      SecretBox(msg.cipherText, nonce: msg.nonce, mac: Mac(msg.mac)),
      secretKey: SecretKey(mk),
      aad: concatBytes([s.ad, msg.header.encode()]),
    );
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
