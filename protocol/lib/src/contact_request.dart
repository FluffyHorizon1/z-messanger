import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'identity.dart';
import 'util.dart';

/// A contact request (`creq`): a self-contained, signed offer to connect,
/// delivered sealed to the recipient **outside any ratchet** — because when it
/// arrives there is no session with the sender yet, and the receiving client
/// drops unknown senders before it would ever decrypt one.
///
/// The sealed-sender layer (`sealed.dart`) hides the sender from the relay but
/// proves nothing to the recipient: it is encrypted to the recipient's public
/// X25519 key, which is public, so anyone can seal anything to anyone and set
/// the `from` field to any routing id they like. On its own, then, a request
/// carrying a real person's public contact code would let an attacker show the
/// recipient "<that person> wants to connect" over a request that person never
/// made.
///
/// So a request carries its own signature. The requester's Ed25519 identity key
/// — the key whose SHA-256 *is* the requester's routing id — signs the
/// recipient's routing id, a timestamp, and the exact bundle being offered. A
/// recipient accepts only a request whose signature verifies under the bundle's
/// own identity key and whose bundle self-verifies (its X25519 key is bound to
/// that identity, `ContactBundle.verify`). An attacker who does not hold the
/// private key cannot produce the signature, and cannot replay a genuine
/// request to a different recipient because the recipient's routing id is
/// signed in.
///
/// The bundle is exactly the classical `zc1.` code the requester would have
/// shown in a QR, so **accepting a request is the same act as scanning that
/// code**: the contact is added at the classical assurance floor, and the
/// account identity and post-quantum key follow in-band on the first traffic
/// (PROTOCOL §18.2), precisely as they do after a scan. Nothing here ends a
/// contact *verified*; that is still the safety-number comparison.
class ContactRequest {
  /// The requester's own contact bundle — self-verifying, and the same thing a
  /// scan of their code would yield.
  final ContactBundle bundle;

  /// The recipient's routing id, bound by the signature so a captured request
  /// cannot be replayed at anyone else.
  final String toRid;

  /// Creation time (ms since epoch), for the recipient's own expiry/pruning.
  final int ts;

  /// Ed25519 over [signingInput], by [bundle].edPub.
  final Uint8List sig;

  ContactRequest({
    required this.bundle,
    required this.toRid,
    required this.ts,
    required this.sig,
  });

  static const String context = 'z-contact-request-v1:';

  /// The bytes the signature covers. Every variable field is length-prefixed,
  /// so no two distinct requests share an encoding.
  static Uint8List signingInput(ContactBundle bundle, String toRid, int ts) {
    final to = utf8.encode(toRid);
    final name = utf8.encode(bundle.displayName ?? '');
    final tsb = Uint8List(8);
    ByteData.view(tsb.buffer).setUint64(0, ts);
    return concatBytes([
      utf8.encode(context),
      bundle.edPub,
      bundle.xPub,
      u16be(to.length),
      to,
      tsb,
      u16be(name.length),
      name,
    ]);
  }

  /// Build and sign a request from [me] to the routing id [toRid].
  ///
  /// [displayName] is the name the recipient will see and is covered by the
  /// signature; it is the same name [me]'s contact code would carry.
  static Future<ContactRequest> create({
    required ZIdentity me,
    required String toRid,
    String? displayName,
    int? ts,
  }) async {
    final bundle = await me.bundle(displayName: displayName);
    final at = ts ?? DateTime.now().millisecondsSinceEpoch;
    final sig = await Ed25519().sign(
      signingInput(bundle, toRid, at),
      keyPair: me.edKeyPair,
    );
    return ContactRequest(
      bundle: bundle,
      toRid: toRid,
      ts: at,
      sig: Uint8List.fromList(sig.bytes),
    );
  }

  /// The transport payload — base64(JSON), the inner `p` slot of a sealed
  /// envelope. Shares the versioned `{v,t}` shape file chunks use, with
  /// `t: 'creq'`, so [tryParse] and `tryParseChunk` never claim each other's
  /// payloads and neither is a ratchet message.
  String encode() => base64Encode(utf8.encode(jsonEncode({
        'v': 1,
        't': 'creq',
        'to': toRid,
        'ts': ts,
        'bundle': bundle.toJson(),
        'sig': b64(sig),
      })));

  /// Parse a transport payload as a request, or null if it is not one — so a
  /// caller can fall through to the ratchet path. Never throws.
  static ContactRequest? tryParse(String transportPayload) {
    try {
      final j = jsonDecode(utf8.decode(base64Decode(transportPayload)))
          as Map<String, Object?>;
      if (j['v'] != 1 || j['t'] != 'creq') return null;
      return ContactRequest(
        bundle:
            ContactBundle.fromJson((j['bundle'] as Map).cast<String, Object?>()),
        toRid: j['to'] as String,
        ts: (j['ts'] as num).toInt(),
        sig: unb64(j['sig'] as String),
      );
    } catch (_) {
      return null;
    }
  }

  /// Full verification. The bundle self-verifies (its X key is bound to its
  /// identity), the request is addressed to us, the requester's routing id is
  /// the one the bundle names (and, when known, the sealed sender), and the
  /// signature is by the bundle's identity key over exactly these bytes.
  Future<bool> verify({required String expectedTo, String? sealedFrom}) async {
    if (toRid != expectedTo) return false;
    if (bundle.edPub.length != 32 || bundle.xPub.length != 32) return false;
    if (!await bundle.verify()) return false;
    final rid = await bundle.routingId();
    if (sealedFrom != null && rid != sealedFrom) return false;
    try {
      return await Ed25519().verify(
        signingInput(bundle, toRid, ts),
        signature: Signature(
          sig,
          publicKey: SimplePublicKey(bundle.edPub, type: KeyPairType.ed25519),
        ),
      );
    } catch (_) {
      return false;
    }
  }

  /// The requester's routing id (the verified identity to add on accept).
  Future<String> fromRid() => bundle.routingId();
}
