import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'intro_key.dart' show mlKemEncapsulationKeyValid;
import 'pq.dart' show pqCtLength, pqEncapsulate;
import 'sealing_key.dart';
import 'util.dart';

/// Sealed sender (anonymous outer envelope).
///
/// Without this layer the relay learns, for every envelope, WHO sent it (the
/// server-authenticated `from`) and to which mailbox — enough to reconstruct
/// the social graph even though content is end-to-end encrypted. A sealed
/// envelope removes the sender from the relay's view entirely:
///
///   * the sender generates a fresh ephemeral X25519 key pair per envelope,
///     derives a key against the RECIPIENT's public X25519 key, and encrypts
///     `{sender routing id, inner payload}` to it;
///   * the relay stores and delivers the blob with no sender attribution and
///     matches acks by envelope id alone;
///   * the recipient opens the envelope with its private key, learns the
///     sender ONLY inside the ciphertext, and routes the inner payload through
///     the normal (already authenticated) machinery.
///
/// Authenticity is NOT provided by this layer and doesn't need to be: the
/// inner payload is Double-Ratchet ciphertext (or an AEAD-sealed file chunk)
/// that only the claimed sender's session state can produce. A spoofed
/// `sender` here simply fails inner decryption and is dropped.
///
/// Plaintext is padded to size buckets so the relay also can't distinguish
/// messages by exact length.
///
/// A key of small order is refused ([SealRefusedException]). X25519 with
/// such a key — the zero point, or one of the few points of order 2, 4 or 8,
/// in any of their spellings — gives all zeros whatever the ephemeral is
/// (RFC 7748 §6.1), so the envelope's key would be HKDF of zeros and two
/// public keys: anyone holding the envelope, the relay first of all, could
/// open it and read the sender. An honest key is never one (it is a clamped
/// scalar times the base point), so the refusal costs an honest send
/// nothing.

final _x = X25519();
final _aead = Chacha20.poly1305Aead();

const String _prefix = 'zs1.';
const String _context = 'z-sealed-v1';

/// Padded sizes. The +40ish overhead of the envelope rides on top; what
/// matters is that many different inner payloads share each bucket.
const List<int> sealedBuckets = [
  1024,
  4096,
  16384,
  65536,
  262144,
  1120 * 1024, // fits a max-size chunk comfortably
];

Uint8List _pad(Uint8List plain) {
  final needed = plain.length + 4;
  final bucket = sealedBuckets.firstWhere((b) => b >= needed,
      orElse: () => needed); // oversize: no padding beyond exact fit
  final out = Uint8List(bucket);
  ByteData.view(out.buffer).setUint32(0, plain.length);
  out.setRange(4, 4 + plain.length, plain);
  return out;
}

Uint8List? _unpad(Uint8List padded) {
  if (padded.length < 4) return null;
  final len = ByteData.view(padded.buffer, padded.offsetInBytes).getUint32(0);
  if (len > padded.length - 4) return null;
  return Uint8List.sublistView(padded, 4, 4 + len);
}

Future<SecretKey> _deriveKey(
    Uint8List shared, Uint8List ephPub, Uint8List toXPub) async {
  final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
  final okm = await hkdf.deriveKey(
    secretKey: SecretKey(shared),
    nonce: Uint8List(0),
    info: concatBytes([utf8.encode(_context), ephPub, toXPub]),
  );
  return okm;
}

/// [SealedEnvelope.seal] (or [SealedEnvelopeV2.seal]) was asked to seal to a
/// key of small order, whose agreement with any ephemeral is all zeros: the
/// envelope would be open to anyone who holds it. Nothing was produced.
class SealRefusedException implements Exception {
  const SealRefusedException();

  @override
  String toString() =>
      'SealRefusedException: the recipient key is a point of small order';
}

/// X25519 of [ephKp] with the recipient's [toXPub], refused when it is all
/// zeros — the one output a key of small order can give, and every such key
/// gives it (the comment at the top of this file). Both prefixes seal
/// through this, so `zs2.` refuses exactly the keys `zs1.` does.
Future<Uint8List> _agreeOrRefuse(SimpleKeyPair ephKp, Uint8List toXPub) async {
  final shared = await _x.sharedSecretKey(
    keyPair: ephKp,
    remotePublicKey: SimplePublicKey(toXPub, type: KeyPairType.x25519),
  );
  final agreed = Uint8List.fromList(await shared.extractBytes());
  // Checked in constant time, as the RFC asks.
  var any = 0;
  for (final b in agreed) {
    any |= b;
  }
  if (any == 0) throw const SealRefusedException();
  return agreed;
}

/// What both prefixes seal: `{f, p}` as JSON, padded to its bucket.
Uint8List _paddedInner(String fromRid, String payload) => _pad(
    Uint8List.fromList(utf8.encode(jsonEncode({'f': fromRid, 'p': payload}))));

/// What both prefixes open to, from the decrypted, padded body; null when it
/// is not `{f, p}` with two strings. Throws on what is not JSON at all, and
/// both callers take that for a bad envelope.
({String fromRid, String payload})? _openedInner(Uint8List plain) {
  final unpadded = _unpad(plain);
  if (unpadded == null) return null;
  final j = (jsonDecode(utf8.decode(unpadded)) as Map).cast<String, Object?>();
  final f = j['f'] as String?;
  final p = j['p'] as String?;
  if (f == null || p == null) return null;
  return (fromRid: f, payload: p);
}

class SealedEnvelope {
  /// True if [payload] looks like a sealed envelope (vs. legacy plaintext-
  /// routed ratchet/chunk payloads).
  static bool looksSealed(String payload) => payload.startsWith(_prefix);

  /// Seal `payload` to the device whose public X25519 key is [toXPub],
  /// embedding [fromRid] so only the recipient learns who sent it.
  ///
  /// Throws [SealRefusedException], and produces nothing, when [toXPub] is
  /// a point of small order (RFC 7748 §6.1; the comment at the top of this
  /// file says why).
  static Future<String> seal({
    required Uint8List toXPub,
    required String fromRid,
    required String payload,
  }) async {
    final ephSeed = randomBytes(32);
    final ephKp = await _x.newKeyPairFromSeed(ephSeed);
    final ephPub =
        Uint8List.fromList((await ephKp.extractPublicKey()).bytes);
    final agreed = await _agreeOrRefuse(ephKp, toXPub);
    final key = await _deriveKey(agreed, ephPub, toXPub);

    final plain = _paddedInner(fromRid, payload);
    final nonce = randomBytes(12);
    final box = await _aead.encrypt(plain,
        secretKey: key, nonce: nonce, aad: utf8.encode(_context));
    return _prefix +
        b64url(concatBytes(
            [ephPub, nonce, Uint8List.fromList(box.cipherText), Uint8List.fromList(box.mac.bytes)]));
  }

  /// Open a sealed envelope with my private X25519 seed. Returns the sender's
  /// routing id and the inner payload, or null if it isn't ours / is invalid.
  static Future<({String fromRid, String payload})?> open({
    required Uint8List myXSeed,
    required Uint8List myXPub,
    required String blob,
  }) async {
    if (!looksSealed(blob)) return null;
    try {
      final raw = unb64url(blob.substring(_prefix.length));
      if (raw.length < 32 + 12 + 16) return null;
      final ephPub = Uint8List.sublistView(raw, 0, 32);
      final nonce = Uint8List.sublistView(raw, 32, 44);
      final cipherText = Uint8List.sublistView(raw, 44, raw.length - 16);
      final mac = Uint8List.sublistView(raw, raw.length - 16);

      final kp = await _x.newKeyPairFromSeed(myXSeed);
      final shared = await _x.sharedSecretKey(
        keyPair: kp,
        remotePublicKey: SimplePublicKey(ephPub, type: KeyPairType.x25519),
      );
      final key = await _deriveKey(
          Uint8List.fromList(await shared.extractBytes()), ephPub, myXPub);
      final plain = Uint8List.fromList(await _aead.decrypt(
        SecretBox(cipherText, nonce: nonce, mac: Mac(mac)),
        secretKey: key,
        aad: utf8.encode(_context),
      ));
      return _openedInner(plain);
    } catch (_) {
      return null; // wrong recipient, tampered, or not a sealed envelope
    }
  }
}

/// The hybrid sealed outer layer, `zs2.` (ADR 0033 §5, PROTOCOL.md §8.2):
/// `zs1.` with an ML-KEM-768 encapsulation to the recipient DEVICE's sealing
/// key ([SealingKey]) mixed into the envelope's key, so that a recording of
/// the envelope tells a future quantum computer nothing — not even who sent
/// it, which is what `zs1.`, resting on X25519 alone, would tell it.
///
/// ```
/// (ct, K)  = ML-KEM-768.Encaps(recipient's sealEk); eph = fresh X25519 pair     per envelope
/// key      = HKDF(X25519(eph, recipientXPub) || K, ∅,
///                 "z-sealed-v2" || ephPub || recipientXPub || SHA-256(ct), 32)
/// envelope = "zs2." || b64url(ephPub(32) || ct(1088) || nonce(12) || box || mac(16))
/// box      = ChaCha20-Poly1305(key, nonce, aad = "z-sealed-v2", §8's padded {f, p})
/// ```
///
/// * **One length per bucket.** The KEM ciphertext sits outside the
///   padding, which is §8's unchanged, so a message lands in the bucket it
///   lands in as `zs1.` and every `zs2.` envelope of a bucket has one length:
///   [extraChars] more than its `zs1.` one, the same in all six buckets.
///   It is the same because every bucket leaves one remainder mod 3: with
///   `zs1.`'s 60 bytes added each is one more than a multiple of three, so
///   every `zs1.` body ends in a two-character base64url group and every
///   `zs2.` body, 1 088 bytes longer, in a full one.
/// * **Stripping.** A `zs2.` envelope cannot be made a `zs1.` one: without
///   `K` the key is another, the AEAD fails and the envelope is dropped. A
///   ciphertext swapped for another encapsulation, to this key or any other,
///   fails the same way, and so does a `zs1.` body under this prefix.
/// * **Small order.** A recipient X25519 key of small order is refused
///   ([SealRefusedException]), as `zs1.` refuses it, through the same check:
///   the KEM would still hide the sender, but a key no honest device has is
///   not one to seal to, and the refusal costs an honest send nothing.
///
/// **Nothing seals or opens `zs2.` before 44.7**, which switches it on
/// behind a build constant and waits for constant-time ML-KEM decapsulation
/// upstream ([open]; ADR 0033 decision 4). Until then this is the library's
/// construction and its vectors (`docs/vectors/sealed-v2/`), and the relay's
/// acceptance of the prefix (44.2).
class SealedEnvelopeV2 {
  /// The prefix: [SealedEnvelope.looksSealed] does not take it, so nothing
  /// that reads `zs1.` reads this.
  static const String prefix = 'zs2.';

  /// The HKDF context, and the AEAD's associated data, as `z-sealed-v1` is
  /// both for `zs1.`.
  static const String context = 'z-sealed-v2';

  /// `ephPub || ct || nonce` before the box, and the MAC after it: the
  /// shortest body that can be one.
  static const int _headBytes = 32 + pqCtLength + 12;
  static const int _minBytes = _headBytes + 16;

  /// How many characters longer a `zs2.` envelope is than the `zs1.` one in
  /// the same bucket: what the 1 088-byte KEM ciphertext adds to a body of
  /// that remainder (above) — 1 450, where the ciphertext alone would be
  /// 1 451 characters of base64url.
  static const int extraChars = 1450;

  /// True if [payload] has the `zs2.` prefix.
  static bool looksSealed(String payload) => payload.startsWith(prefix);

  /// Seals `{f: fromRid, p: payload}` to the device whose X25519 key is
  /// [toXPub] and whose sealing key is [toSealEk].
  ///
  /// Throws [ArgumentError] when [toSealEk] is not a key FIPS 203 §7.2
  /// accepts (`mlKemEncapsulationKeyValid`), before anything is drawn from
  /// the RNG; and [SealRefusedException] when [toXPub] is a point of small
  /// order, once the ephemeral seed is drawn — the check needs it, as
  /// `zs1.`'s does — and before the encapsulation or the nonce is. Either
  /// way nothing is produced, so a refused send leaves nothing behind.
  ///
  /// Draws three values, in this order: the ephemeral X25519 seed (32), the
  /// encapsulation's randomness `m` (32) and the nonce (12). The vectors
  /// record them; the only way to choose them is the zone-scoped override
  /// `randomBytes` reads, which a product build compiles out (`util.dart`).
  static Future<String> seal({
    required Uint8List toXPub,
    required List<int> toSealEk,
    required String fromRid,
    required String payload,
  }) async {
    if (!mlKemEncapsulationKeyValid(toSealEk)) {
      throw ArgumentError.value(toSealEk.length, 'toSealEk',
          'not an ML-KEM-768 encapsulation key FIPS 203 §7.2 accepts');
    }
    final ephSeed = randomBytes(32);
    final ephKp = await _x.newKeyPairFromSeed(ephSeed);
    final ephPub = Uint8List.fromList((await ephKp.extractPublicKey()).bytes);
    final agreed = await _agreeOrRefuse(ephKp, toXPub);
    final (ct, k) = pqEncapsulate(Uint8List.fromList(toSealEk));
    final key = await _deriveKeyV2(agreed, k, ephPub, toXPub, ct);

    final plain = _paddedInner(fromRid, payload);
    final nonce = randomBytes(12);
    final box = await _aead.encrypt(plain,
        secretKey: key, nonce: nonce, aad: utf8.encode(context));
    return prefix +
        b64url(concatBytes([
          ephPub,
          ct,
          nonce,
          Uint8List.fromList(box.cipherText),
          Uint8List.fromList(box.mac.bytes),
        ]));
  }

  /// Opens a `zs2.` envelope with this device's X25519 seed and key and its
  /// sealing key. Returns the sender's routing id and the inner payload, or
  /// null — exactly what [SealedEnvelope.open] returns for a bad envelope —
  /// when it is not ours, was tampered with, carries a swapped or stripped
  /// KEM ciphertext, or is not a `zs2.` envelope at all.
  ///
  /// **Not constant-time, and that is why `zs2.` is off.** Decapsulation
  /// here is `pqcrypto` 0.4.1's ([SealingKey.decapsulate]): it branches on
  /// secret coefficients when it decodes the message (`Indcpa._msgFromPoly`),
  /// its re-encryption divides secret-dependent numerators by 2q when it
  /// compresses (`Pack.compress`, the KyberSlash class), and Dart guarantees
  /// nothing about the timing of what it compiles (THREAT_MODEL.md R43). A
  /// sealing key lives as long as its device and decapsulates whatever
  /// anyone addresses to its mailbox, and the relay sees when each envelope
  /// is acknowledged: a timing leak here meets chosen ciphertexts. So no
  /// client opens — or seals — `zs2.` until
  /// upstream `pqcrypto` decapsulates in constant time (ADR 0033 decision 4,
  /// 44.7). Even then a recovered sealing key reduces that device's envelopes
  /// to `zs1.`'s protection, never below it.
  static Future<({String fromRid, String payload})?> open({
    required Uint8List myXSeed,
    required Uint8List myXPub,
    required SealingKey mySealKey,
    required String blob,
  }) async {
    if (!looksSealed(blob)) return null;
    try {
      final raw = unb64url(blob.substring(prefix.length));
      if (raw.length < _minBytes) return null;
      final ephPub = Uint8List.sublistView(raw, 0, 32);
      final ct = Uint8List.sublistView(raw, 32, 32 + pqCtLength);
      final nonce = Uint8List.sublistView(raw, 32 + pqCtLength, _headBytes);
      final cipherText =
          Uint8List.sublistView(raw, _headBytes, raw.length - 16);
      final mac = Uint8List.sublistView(raw, raw.length - 16);

      final kp = await _x.newKeyPairFromSeed(myXSeed);
      final shared = await _x.sharedSecretKey(
        keyPair: kp,
        remotePublicKey: SimplePublicKey(ephPub, type: KeyPairType.x25519),
      );
      final k = mySealKey.decapsulate(ct);
      final key = await _deriveKeyV2(
          Uint8List.fromList(await shared.extractBytes()),
          k,
          ephPub,
          myXPub,
          ct);
      final plain = Uint8List.fromList(await _aead.decrypt(
        SecretBox(cipherText, nonce: nonce, mac: Mac(mac)),
        secretKey: key,
        aad: utf8.encode(context),
      ));
      return _openedInner(plain);
    } catch (_) {
      return null; // wrong recipient, tampered, stripped, or not zs2.
    }
  }
}

/// `zs2.`'s key: HKDF-SHA256 with no salt over the X25519 agreement and the
/// KEM secret, its info the context, both public keys and SHA-256 of the
/// KEM ciphertext — so the key, and with it the AEAD, covers every byte of
/// the envelope before the box.
Future<SecretKey> _deriveKeyV2(Uint8List shared, Uint8List k, Uint8List ephPub,
    Uint8List toXPub, Uint8List ct) async {
  final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
  return hkdf.deriveKey(
    secretKey: SecretKey(concatBytes([shared, k])),
    nonce: Uint8List(0),
    info: concatBytes([
      utf8.encode(SealedEnvelopeV2.context),
      ephPub,
      toXPub,
      await sha256Bytes(ct),
    ]),
  );
}
