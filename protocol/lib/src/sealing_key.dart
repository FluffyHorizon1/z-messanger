/// A device's sealing key and its account's attestation of it (ADR 0033 §1,
/// PROTOCOL.md §18.11): the library half of 44.1.
///
/// Every device gets one more key pair, for its life, as it has an X25519
/// key for its life: an ML-KEM-768 pair from a 64-byte seed, which a sender
/// encapsulates to in every `zs2.` envelope (§8.2, `SealedEnvelopeV2`) so
/// that a recording of the envelope no longer tells a future quantum
/// computer who sent it. And the account vouches for it post-quantum: the
/// root signs, under the account's ML-DSA-65 key, that this sealing key
/// belongs to the device with these two classical keys in this account —
/// `pqdc`, which a contact checks before it shows the device link as
/// post-quantum (ADR 0033 §2).
///
/// What lives here, and nothing here talks to the network:
///
/// * [SealingKey]: the seed, and the encapsulation key it makes;
/// * `pqdc`: its input ([deviceAttestationInput]), the root's signature
///   ([signDeviceAttestation]) and the check ([deviceAttestationValid]);
///   and the same input and signature from the sealing key's hash
///   ([deviceAttestationInputFromHash], [signDeviceAttestationFromHash]),
///   for the root in pairing v3, which holds the new device's hash and not
///   yet its key.
///
/// The wire members that carry them — the inner kind `pqseal`, the member
/// `pqs` and `pqid`'s optional `pqdc` — are built and read in
/// `messages.dart`, beside the kinds they extend. No client sends any of them
/// before 44.3, and none seals or opens `zs2.` before 44.7, which waits for
/// constant-time ML-KEM upstream (ADR 0033 decision 4).
library;

import 'dart:convert';
import 'dart:typed_data';

import 'intro_key.dart'
    show mlKemEncapsulationKeyValid, sealKeyHash, sealKeyHashBytes;
import 'pq.dart'
    show pqDecapsulate, pqEkLength, pqGenerate, pqKeyPairFromSeed, pqSeedLength;
import 'pqsign.dart';
import 'util.dart';

/// The context `pqdc` is signed under (§18.11). Distinct from every other
/// context in the protocol and a prefix of none: it begins `z-device-` as the
/// certificate's (`deviceCertContext`) and the proof of possession's
/// (`devicePopContext`) do, and differs from the first at its tenth byte and
/// from the second at its eleventh.
const String devicePqContext = 'z-device-pq-v1:';

/// What `pqdc` signs: the context and four 32-byte fields — the account key,
/// the device's Ed25519 and X25519 keys, SHA-256 of its sealing key. Fixed
/// width, so the concatenation is unambiguous.
const int deviceAttestationInputBytes = 15 + 4 * 32; // 143

/// `pqdc` itself: an ML-DSA-65 signature.
const int deviceAttestationBytes = mlDsaSignatureBytes; // 3 309

/// A device's sealing key (ADR 0033 §1): an ML-KEM-768 pair from a 64-byte
/// seed `d || z`, FIPS 203 `KeyGen_internal(d, z)`, which `pq.dart` already
/// wraps. One per device, for the device's life, like its X25519 key; the
/// seed is what the vault keeps (`seal_seed`) and the archive carries, since
/// a restore that drew a new one would leave contacts sealing to a key
/// nobody holds (44.3).
///
/// It holds the seed and the encapsulation key, and nothing else: the
/// decapsulation key is made from the seed when it is needed, as
/// [pqDecapsulate] makes it, so the only secret held is 64 bytes.
class SealingKey {
  /// `d || z`, [pqSeedLength] bytes. Secret.
  final Uint8List seed;

  /// The encapsulation key, [pqEkLength] bytes. Public: what a device
  /// announces in `pqseal` and its relay keeps (§8.3).
  final Uint8List ek;

  SealingKey._(this.seed, this.ek);

  /// The pair [seed] makes. Throws [ArgumentError] unless it is 64 bytes.
  factory SealingKey.fromSeed(List<int> seed) {
    if (seed.length != pqSeedLength) {
      throw ArgumentError.value(seed.length, 'seed',
          'a sealing key is made from a $pqSeedLength-byte seed, d || z');
    }
    final s = Uint8List.fromList(seed);
    final (ek, _) = pqKeyPairFromSeed(s);
    return SealingKey._(s, ek);
  }

  /// A fresh key, from the protocol's RNG.
  factory SealingKey.generate() {
    final (seed, ek) = pqGenerate();
    return SealingKey._(seed, ek);
  }

  /// `sk = SHA-256(ek)`: what `pqdc` signs over, what a contact code carries
  /// (§8.3) and what pairing v3 binds (§10.2) — [sealKeyHash], defined once.
  Uint8List get hash => sealKeyHash(ek);

  /// The shared secret a `zs2.` envelope's KEM ciphertext [ct] carries, from
  /// the seed, as [pqDecapsulate] computes it. Never throws for a ciphertext
  /// of the right length that is not ours: FIPS 203's implicit rejection
  /// gives a pseudorandom secret, and the envelope's AEAD then fails. Not
  /// constant-time in `pqcrypto` 0.4.1 — see `SealedEnvelopeV2.open`.
  Uint8List decapsulate(List<int> ct) =>
      pqDecapsulate(seed, Uint8List.fromList(ct));
}

/// The bytes `pqdc` signs (§18.11):
/// `utf8("z-device-pq-v1:") || acct || ded || dx || SHA-256(sealEk)`, where
/// [accountEdPub] is the account key, [deviceEdPub] and [deviceXPub] the
/// device's two keys as its certificate names them (`ded`, `dx`), and
/// [sealEk] its sealing key, hashed here ([sealKeyHash]). Throws
/// [ArgumentError] for a field of the wrong length: there is no input to
/// sign or check then.
Uint8List deviceAttestationInput({
  required List<int> accountEdPub,
  required List<int> deviceEdPub,
  required List<int> deviceXPub,
  required List<int> sealEk,
}) {
  if (sealEk.length != pqEkLength) {
    throw ArgumentError.value(sealEk.length, 'sealEk',
        'an ML-KEM-768 encapsulation key is $pqEkLength bytes');
  }
  return deviceAttestationInputFromHash(
    accountEdPub: accountEdPub,
    deviceEdPub: deviceEdPub,
    deviceXPub: deviceXPub,
    sk: sealKeyHash(sealEk),
  );
}

/// The same input from the sealing key's hash, [sk] `= SHA-256(sealEk)`,
/// for a signer that holds the hash and not the key: the root in pairing
/// v3, which learns the new device's `sk` from its opening (§10.2) and signs
/// that device's `pqdc` before the key itself has reached it. Byte for byte
/// what [deviceAttestationInput] builds from the key [sk] is the hash of.
/// Throws [ArgumentError] for a field of the wrong length.
Uint8List deviceAttestationInputFromHash({
  required List<int> accountEdPub,
  required List<int> deviceEdPub,
  required List<int> deviceXPub,
  required List<int> sk,
}) {
  for (final (name, key) in [
    ('accountEdPub', accountEdPub),
    ('deviceEdPub', deviceEdPub),
    ('deviceXPub', deviceXPub),
  ]) {
    if (key.length != 32) {
      throw ArgumentError.value(key.length, name, 'a public key is 32 bytes');
    }
  }
  if (sk.length != sealKeyHashBytes) {
    throw ArgumentError.value(sk.length, 'sk',
        "a sealing key's hash is $sealKeyHashBytes bytes");
  }
  return concatBytes([
    utf8.encode(devicePqContext),
    accountEdPub,
    deviceEdPub,
    deviceXPub,
    sk,
  ]);
}

/// `pqdc` (§18.11): the account's ML-DSA-65 signature that the sealing key
/// [sealEk] belongs to the device with keys [deviceEdPub] and [deviceXPub]
/// in this account. Only the root holds the account's ML-DSA seed, so only
/// the root can make one — its own device's at first start, an
/// earlier-linked device's over self-sync (44.3), and a new device's in
/// pairing v3, where it holds the key's hash and not the key
/// ([signDeviceAttestationFromHash]).
///
/// Signed through [HybridKeyPair.sign], as the device-list signature is
/// (§18.9), and its ML-DSA half kept: `pqdc` is the post-quantum half alone,
/// since what it adds against the adversary of ADR 0033 is exactly what
/// Ed25519 cannot. Hedged unless [deterministic], which is for the
/// known-answer vectors only (see [HybridKeyPair.sign]).
///
/// Refuses ([ArgumentError]) a key FIPS 203 §7.2 does not accept: a root
/// never vouches for a key nobody can encapsulate to.
Future<Uint8List> signDeviceAttestation({
  required HybridKeyPair accountKey,
  required List<int> deviceEdPub,
  required List<int> deviceXPub,
  required List<int> sealEk,
  bool deterministic = false,
}) async {
  if (!mlKemEncapsulationKeyValid(sealEk)) {
    throw ArgumentError.value(sealEk.length, 'sealEk',
        'not an ML-KEM-768 encapsulation key FIPS 203 §7.2 accepts');
  }
  return signDeviceAttestationFromHash(
    accountKey: accountKey,
    deviceEdPub: deviceEdPub,
    deviceXPub: deviceXPub,
    sk: sealKeyHash(sealEk),
    deterministic: deterministic,
  );
}

/// `pqdc` from the sealing key's hash [sk] rather than the key: what the
/// root signs in pairing v3 (§10.2), where it holds the new device's `sk`
/// from the opening, bound into the digits both screens showed, and not yet
/// the key. The input is byte for byte the one [signDeviceAttestation]
/// signs over the key [sk] is the hash of, so the signature is checked as
/// any `pqdc` is, with the key, once the device's `pqseal` has brought it
/// ([deviceAttestationValid]). A hash cannot be put to FIPS 203 §7.2's
/// check; the key is, where it is held — that check, and its SHA-256 equal
/// to the [sk] signed here, is what the receiver asks of it. Throws
/// [ArgumentError] for a field of the wrong length.
Future<Uint8List> signDeviceAttestationFromHash({
  required HybridKeyPair accountKey,
  required List<int> deviceEdPub,
  required List<int> deviceXPub,
  required List<int> sk,
  bool deterministic = false,
}) async {
  final input = deviceAttestationInputFromHash(
    accountEdPub: accountKey.publicKey.edPub,
    deviceEdPub: deviceEdPub,
    deviceXPub: deviceXPub,
    sk: sk,
  );
  final both = await accountKey.sign(input, deterministic: deterministic);
  return both.ml;
}

/// Whether [pqdc] is the account's attestation (§18.11) that [sealEk] is the
/// sealing key of the device with keys [deviceEdPub] and [deviceXPub] in the
/// account whose keys are [accountEdPub] and [accountMlPub].
///
/// False — never a throw — for an input of the wrong length, for a `pqdc`
/// made over any other account key, device key, ratchet key or sealing key
/// (each is a field of the signed input), and for a sealing key FIPS 203
/// §7.2 refuses. That last is the key's own check: a `pqdc` made in pairing
/// v3 is signed over the key's hash ([signDeviceAttestationFromHash]), which
/// says nothing about the key, so whoever holds the key checks it. A caller
/// holds [accountMlPub] as established (a commitment met, or the number
/// confirmed, ADR 0021) before a true here means anything; one it holds
/// only as a candidate proves nothing (§18.2).
bool deviceAttestationValid({
  required List<int> accountMlPub,
  required List<int> accountEdPub,
  required List<int> deviceEdPub,
  required List<int> deviceXPub,
  required List<int> sealEk,
  required List<int> pqdc,
}) {
  if (accountMlPub.length != mlDsaPublicKeyBytes ||
      accountEdPub.length != 32 ||
      deviceEdPub.length != 32 ||
      deviceXPub.length != 32 ||
      sealEk.length != pqEkLength ||
      pqdc.length != deviceAttestationBytes ||
      !mlKemEncapsulationKeyValid(sealEk)) {
    return false;
  }
  try {
    return pqDsaVerify(
      Uint8List.fromList(accountMlPub),
      deviceAttestationInput(
        accountEdPub: accountEdPub,
        deviceEdPub: deviceEdPub,
        deviceXPub: deviceXPub,
        sealEk: sealEk,
      ),
      Uint8List.fromList(pqdc),
    );
  } catch (_) {
    return false;
  }
}
