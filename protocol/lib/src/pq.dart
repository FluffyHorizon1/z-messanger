import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:pqcrypto/pqcrypto.dart' as pqc;

import 'util.dart';

/// Post-quantum hybrid (protocol v2): ML-KEM-768 (FIPS 203) mixed into the
/// Double Ratchet's message keys.
///
/// Threat: harvest-now-decrypt-later. Everything in v1 rests on X25519; an
/// adversary recording traffic today could decrypt it once a cryptographically
/// relevant quantum computer exists. v2 adds a key-encapsulation step after
/// session establishment, so that every message from the first round trip on
/// also depends on a secret no quantum adversary can recover from the
/// recording (the responder's decapsulation key never leaves its device and is
/// erased once used).
///
/// Shape (see docs/PROTOCOL.md §17):
///   * the RESPONDER of a session generates an ephemeral ML-KEM-768 key pair
///     when it accepts the session and offers `ek` to the initiator INSIDE the
///     ratchet, as an inner message of kind `pqek` — encrypted, authenticated,
///     and ignored by a v1 peer, so the offer is a no-op against old clients
///     and cannot be tampered with or stripped by a network attacker;
///   * the INITIATOR encapsulates to `ek` and carries the ciphertext in the
///     (AAD-authenticated) ratchet header of its next messages until the
///     responder proves it holds the secret;
///   * both sides then derive every message key as
///     `mk' = HKDF(ikm = mk, salt = K, info = "Z-PQ-MK-v2", L = 32)` for
///     messages whose header carries `"pq":1`.
///
/// Neither side ever sends a v2 header field to a peer that has not proven v2
/// support (the responder by sending `pqek`, the initiator by sending `pqct`),
/// which is what keeps v1 interoperability intact without any unauthenticated
/// negotiation.
///
/// Implementation: `package:pqcrypto` (pure Dart, zero dependencies). Its
/// ML-KEM-768 is byte-exact against kyber-py and PQClean on the seeded vectors
/// in docs/vectors/v2/mlkem768.json (checked in CI). Constant-time behaviour
/// in Dart is best-effort; in this hybrid a timing leak in the KEM can at
/// worst reduce security to v1 (X25519 alone), never below it.

const String pqAlgorithm = 'ML-KEM-768';
const String pqMixContext = 'Z-PQ-MK-v2';
const int pqSeedLength = 64; // d || z (FIPS 203 KeyGen_internal)
const int pqEkLength = 1184;
const int pqDkLength = 2400;
const int pqCtLength = 1088;
const int pqSecretLength = 32;

final _kem = pqc.PqcKem.kyber768;

/// Deterministic key generation from a 64-byte seed `d || z` (FIPS 203
/// Algorithm 16 / KeyGen_internal). Returns (ek, dk).
(Uint8List ek, Uint8List dk) pqKeyPairFromSeed(Uint8List seed) {
  if (seed.length != pqSeedLength) {
    throw ArgumentError('ML-KEM seed must be $pqSeedLength bytes');
  }
  final (ek, dk) = _kem.generateKeyPair(Uint8List.fromList(seed));
  return (Uint8List.fromList(ek), Uint8List.fromList(dk));
}

/// Fresh key pair: returns the seed (persist this; the keys are regenerated
/// from it) together with the encapsulation key.
(Uint8List seed, Uint8List ek) pqGenerate() {
  final seed = randomBytes(pqSeedLength);
  final (ek, _) = pqKeyPairFromSeed(seed);
  return (seed, ek);
}

/// Encapsulate to [ek]: returns (ciphertext, shared secret). [m] is the
/// 32-byte randomness of FIPS 203 Encaps_internal; it is drawn from the
/// protocol RNG (so test vectors can record it) when not supplied.
(Uint8List ct, Uint8List k) pqEncapsulate(Uint8List ek, {Uint8List? m}) {
  if (ek.length != pqEkLength) {
    throw ArgumentError(
        'ML-KEM-768 encapsulation key must be $pqEkLength bytes');
  }
  final (ct, k) =
      _kem.encapsulate(Uint8List.fromList(ek), m ?? randomBytes(32));
  return (Uint8List.fromList(ct), Uint8List.fromList(k));
}

/// Decapsulate [ct] with the key pair regenerated from [seed]. Never throws on
/// a wrong ciphertext: FIPS 203 implicit rejection yields a pseudorandom
/// secret, and the message MAC then fails.
Uint8List pqDecapsulate(Uint8List seed, Uint8List ct) {
  if (ct.length != pqCtLength) {
    throw ArgumentError('ML-KEM-768 ciphertext must be $pqCtLength bytes');
  }
  final (_, dk) = pqKeyPairFromSeed(seed);
  return Uint8List.fromList(_kem.decapsulate(dk, Uint8List.fromList(ct)));
}

/// Message-key mixing: `HKDF-SHA256(ikm = mk, salt = K, info = "Z-PQ-MK-v2")`.
Future<Uint8List> pqMixMessageKey(Uint8List mk, Uint8List k) async {
  final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
  final out = await hkdf.deriveKey(
    secretKey: SecretKey(mk),
    nonce: k,
    info: pqMixContext.codeUnits,
  );
  return Uint8List.fromList(await out.extractBytes());
}
