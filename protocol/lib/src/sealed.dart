import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

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

/// [SealedEnvelope.seal] was asked to seal to a key of small order, whose
/// agreement with any ephemeral is all zeros: the envelope would be open to
/// anyone who holds it. Nothing was produced.
class SealRefusedException implements Exception {
  const SealRefusedException();

  @override
  String toString() =>
      'SealRefusedException: the recipient key is a point of small order';
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
    final shared = await _x.sharedSecretKey(
      keyPair: ephKp,
      remotePublicKey: SimplePublicKey(toXPub, type: KeyPairType.x25519),
    );
    final agreed = Uint8List.fromList(await shared.extractBytes());
    // All zeros is the one output a key of small order can give, and every
    // such key gives it. Checked in constant time, as the RFC asks.
    var any = 0;
    for (final b in agreed) {
      any |= b;
    }
    if (any == 0) throw const SealRefusedException();
    final key = await _deriveKey(agreed, ephPub, toXPub);

    final plain = _pad(Uint8List.fromList(
        utf8.encode(jsonEncode({'f': fromRid, 'p': payload}))));
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
      final unpadded = _unpad(plain);
      if (unpadded == null) return null;
      final j = (jsonDecode(utf8.decode(unpadded)) as Map)
          .cast<String, Object?>();
      final f = j['f'] as String?;
      final p = j['p'] as String?;
      if (f == null || p == null) return null;
      return (fromRid: f, payload: p);
    } catch (_) {
      return null; // wrong recipient, tampered, or not a sealed envelope
    }
  }
}
