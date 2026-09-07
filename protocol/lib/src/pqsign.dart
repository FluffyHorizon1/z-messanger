// Hybrid signatures (protocol v3, §13.1): Ed25519 AND ML-DSA-65, both
// required.
//
// v2 protects confidentiality against a future quantum adversary by mixing an
// ML-KEM-768 secret into every message key. It does nothing for
// AUTHENTICATION: account keys, device keys and device certificates are all
// still Ed25519, so a cryptographically relevant quantum computer could forge
// a device certificate — mint a device that appears to belong to someone's
// account — even though it could not read a word of the past traffic it
// recorded. This closes that.
//
// Three properties this module exists to guarantee:
//
//   1. **Both halves, always.** A signature verifies only if Ed25519 AND
//      ML-DSA-65 both verify over the same bytes. Anything else is a
//      downgrade, and a downgrade is the whole attack: an adversary who can
//      break Ed25519 strips the half they cannot forge and presents the half
//      they can.
//   2. **A missing half is a failure, not a default.** Parsing a signature
//      that carries only the classical half throws rather than yielding
//      something a verifier might accept. Stripping must not be expressible.
//   3. **Seeds, not secret keys.** An ML-DSA-65 secret key is 4 032 bytes; its
//      seed is 32. Identities here are already seed-derived (`ZIdentity`), and
//      keeping that true means a backup archive (§9) carries 32 more bytes
//      rather than four kilobytes, and the vault stores one more small secret
//      of exactly the kind it already stores.
//
// Sizes, measured against pqcrypto 0.4.1 and matching FIPS 204 Table 2:
// public key 1 952 B, signature 3 309 B, secret key 4 032 B. Verification is
// ~3 ms, paid per certificate when a device list is installed rather than per
// message — see `docs/adr/0003-pq-identity-qr.md`, which also explains why
// these keys travel in-band under a commitment instead of inside the QR.

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:pqcrypto/pqcrypto.dart' as pqc;

import 'util.dart';

final _ed = Ed25519();
final _mlParams = pqc.DilithiumParams.mlDsa65;

/// The algorithm pair, as it appears on the wire.
const String hybridAlgorithm = 'Ed25519+ML-DSA-65';

/// Domain separator for the commitment that binds a post-quantum public key
/// to an out-of-band exchange (ADR 0003). Distinct from every other context
/// string in the protocol so a commitment can never be mistaken for, or
/// replayed as, another digest.
const String pqCommitContext = 'z-pqid-v3:';

const int mlDsaPublicKeyBytes = 1952;
const int mlDsaSignatureBytes = 3309;
const int ed25519SignatureBytes = 64;

/// Thrown when a signature or key is not a well-formed hybrid one. Separate
/// from "it did not verify": a stripped signature is a structural fault and
/// must never reach a verifier that could return false and be retried.
class HybridFormatException implements Exception {
  final String message;
  const HybridFormatException(this.message);
  @override
  String toString() => 'HybridFormatException: $message';
}

/// The public half of a hybrid identity.
class HybridPublicKey {
  final Uint8List edPub; // 32
  final Uint8List mlPub; // 1952

  HybridPublicKey({required this.edPub, required this.mlPub}) {
    if (edPub.length != 32) {
      throw const HybridFormatException('Ed25519 public key must be 32 bytes');
    }
    if (mlPub.length != mlDsaPublicKeyBytes) {
      throw HybridFormatException(
          'ML-DSA-65 public key must be $mlDsaPublicKeyBytes bytes');
    }
  }

  /// The 32-byte commitment carried out-of-band (in a `zc3.` contact code)
  /// so the post-quantum half can be delivered in-band and still be bound to
  /// the exchange the two people actually performed. See ADR 0003.
  Future<Uint8List> pqCommitment() =>
      sha256Bytes(concatBytes([utf8.encode(pqCommitContext), mlPub]));

  Map<String, Object?> toJson() => {'ed': b64(edPub), 'ml': b64(mlPub)};

  static HybridPublicKey fromJson(Map<String, Object?> j) {
    final ed = j['ed'], ml = j['ml'];
    if (ed is! String || ml is! String) {
      throw const HybridFormatException(
          'a hybrid public key needs both halves');
    }
    return HybridPublicKey(edPub: unb64(ed), mlPub: unb64(ml));
  }
}

/// A signature under both algorithms, over identical bytes.
class HybridSignature {
  final Uint8List ed; // 64
  final Uint8List ml; // 3309

  HybridSignature({required this.ed, required this.ml}) {
    if (ed.length != ed25519SignatureBytes) {
      throw const HybridFormatException('Ed25519 signature must be 64 bytes');
    }
    if (ml.length != mlDsaSignatureBytes) {
      throw HybridFormatException(
          'ML-DSA-65 signature must be $mlDsaSignatureBytes bytes');
    }
  }

  Map<String, Object?> toJson() => {'ed': b64(ed), 'ml': b64(ml)};

  /// A signature missing either half does not parse. This is the point: the
  /// downgrade attack is to present a v3 signature with the post-quantum half
  /// removed, and it must not be possible to hand a verifier something it
  /// could evaluate at all.
  static HybridSignature fromJson(Map<String, Object?> j) {
    final ed = j['ed'], ml = j['ml'];
    if (ed is! String || ml is! String) {
      throw const HybridFormatException(
          'a hybrid signature needs both halves; one alone is a downgrade');
    }
    return HybridSignature(ed: unb64(ed), ml: unb64(ml));
  }
}

/// A hybrid key pair, derived from two 32-byte seeds.
///
/// Both seeds are as sensitive as the secret keys they produce and live where
/// the existing identity seeds live: sealed in the vault, never on the wire.
class HybridKeyPair {
  final Uint8List edSeed;
  final Uint8List mlSeed;
  final HybridPublicKey publicKey;
  final SimpleKeyPair _edKp;
  final Uint8List _mlSecret;

  HybridKeyPair._(
      this.edSeed, this.mlSeed, this.publicKey, this._edKp, this._mlSecret);

  static Future<HybridKeyPair> generate() =>
      fromSeeds(edSeed: randomBytes(32), mlSeed: randomBytes(32));

  /// Derives the pair. ML-DSA keygen is FIPS 204 `KeyGen_internal`, which is
  /// deterministic in its seed — the same relationship Ed25519 and X25519
  /// already have to theirs here, and what lets an identity be restored from
  /// a backup without carrying a 4 KB secret key around.
  static Future<HybridKeyPair> fromSeeds({
    required Uint8List edSeed,
    required Uint8List mlSeed,
  }) async {
    if (edSeed.length != 32 || mlSeed.length != 32) {
      throw const HybridFormatException('both seeds must be 32 bytes');
    }
    final edKp = await _ed.newKeyPairFromSeed(edSeed);
    final edPub = Uint8List.fromList((await edKp.extractPublicKey()).bytes);
    final (mlPub, mlSecret) =
        pqc.MlDsa.generateKeyPairSeeded(_mlParams, mlSeed);
    return HybridKeyPair._(
      Uint8List.fromList(edSeed),
      Uint8List.fromList(mlSeed),
      HybridPublicKey(edPub: edPub, mlPub: mlPub),
      edKp,
      mlSecret,
    );
  }

  /// Signs [message] under both algorithms, over the identical bytes. The
  /// caller domain-separates the message (as `z-device-cert-v1:` and friends
  /// already do); this layer deliberately adds no framing of its own, so that
  /// what the two algorithms attest to is provably the same string.
  ///
  /// [deterministic] forces ML-DSA's `rnd` to zero. **Known-answer vectors
  /// only.** Ed25519 is deterministic by construction (RFC 8032), but ML-DSA
  /// signing is hedged by default and FIPS 204 recommends keeping it that
  /// way: a deterministic signature is materially easier to attack with
  /// fault injection, because the same input always produces the same
  /// intermediate values to glitch. Nothing in the protocol passes true here;
  /// the vector generator does, so a third implementation can reproduce the
  /// recorded bytes.
  Future<HybridSignature> sign(Uint8List message,
      {bool deterministic = false}) async {
    final edSig = await _ed.sign(message, keyPair: _edKp);
    return HybridSignature(
      ed: Uint8List.fromList(edSig.bytes),
      ml: deterministic
          ? pqc.MlDsa.signDeterministic(_mlSecret, message, _mlParams)
          : pqc.MlDsa.sign(_mlSecret, message, _mlParams),
    );
  }
}

/// Verifies [sig] over [message] under [key]. True only if BOTH halves
/// verify.
///
/// Both are always evaluated — no short-circuit — so that the work done does
/// not depend on which half failed. Nothing secret is involved either way,
/// but a verifier whose cost advertises where the forgery is invites someone
/// to go looking, and the cost of not finding out is one ML-DSA verification.
Future<bool> hybridVerify(
  HybridPublicKey key,
  Uint8List message,
  HybridSignature sig,
) async {
  final edOk = await _ed.verify(
    message,
    signature: Signature(sig.ed,
        publicKey: SimplePublicKey(key.edPub, type: KeyPairType.ed25519)),
  );
  // Returns false rather than throwing for any malformed input, per the
  // package contract — so a hostile signature cannot turn a verification into
  // an exception the caller might handle as something other than a failure.
  final mlOk = pqc.MlDsa.verify(key.mlPub, message, sig.ml, _mlParams);
  return edOk && mlOk;
}

// ---------------------------------------------------------------------------
// Primitive entry points
// ---------------------------------------------------------------------------
// Thin, explicit wrappers over ML-DSA-65. They exist so the known-answer
// vectors (docs/vectors/v3/mldsa65.json) are produced through the same code
// path the protocol uses, and so an independent FIPS 204 implementation can
// reproduce every recorded value from a seed and a message.

/// FIPS 204 `ML-DSA.KeyGen_internal(zeta)` — deterministic in [seed].
(Uint8List pk, Uint8List sk) pqDsaKeyPairSeeded(Uint8List seed) {
  if (seed.length != 32) {
    throw const HybridFormatException('ML-DSA seed must be 32 bytes');
  }
  return pqc.MlDsa.generateKeyPairSeeded(_mlParams, seed);
}

/// Deterministic signing (`rnd = 0^32`). Vectors only: production signing is
/// hedged, which is the FIPS 204 recommendation and what [HybridKeyPair.sign]
/// uses. Recorded here so a third implementation can reproduce the bytes.
Uint8List pqDsaSignDeterministic(Uint8List sk, Uint8List message) =>
    pqc.MlDsa.signDeterministic(sk, message, _mlParams);

/// Raw ML-DSA-65 verification. Callers in the protocol use [hybridVerify],
/// which requires the classical half too; this is for vector checking.
bool pqDsaVerify(Uint8List pk, Uint8List message, Uint8List sig) =>
    pqc.MlDsa.verify(pk, message, sig, _mlParams);
