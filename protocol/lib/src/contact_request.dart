import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'identity.dart';
import 'multidevice.dart';
import 'util.dart';

/// The account a request from a LINKED device speaks for (§8.1, phase 33),
/// once [ContactRequest.anchor] has checked it: the account's key, the
/// bundle its root device is held under, and the account's certificate for
/// the device that sent the request.
class RequestAnchor {
  final Uint8List accountEdPub;
  final ContactBundle root;
  final DeviceCertificate cert;
  const RequestAnchor(this.accountEdPub, this.root, this.cert);
}

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

  /// §8.1's optional account anchor (phase 33), sent by a device that does
  /// not hold its account's root: the root device's own bundle, the
  /// account's certificate for THIS device, and this device's signature
  /// over the account's key, the recipient and the time ([anchorInput]). All
  /// three or none; [anchor] is what checks them. A client from before them
  /// ignores all three and reads the request as it always did.
  final ContactBundle? root;
  final DeviceCertificate? cert;
  final Uint8List? anchorSig;

  ContactRequest({
    required this.bundle,
    required this.toRid,
    required this.ts,
    required this.sig,
    this.root,
    this.cert,
    this.anchorSig,
  });

  static const String context = 'z-contact-request-v1:';

  /// The anchor signature's context (§8.1).
  static const String anchorContext = 'z-contact-request-acct-v1:';

  /// What [anchorSig] covers: the account's key — fixed width — then the
  /// recipient and the time, as in [signingInput]. It ties the account to
  /// THIS request: a certificate and a root bundle are public, and without
  /// it anyone passing a request on (a recipient's own device mirroring it,
  /// §18.8) could put another account's beside it.
  static Uint8List anchorInput(Uint8List accountEdPub, String toRid, int ts) {
    final to = utf8.encode(toRid);
    final tsb = Uint8List(8);
    ByteData.view(tsb.buffer).setUint64(0, ts);
    return concatBytes([
      utf8.encode(anchorContext),
      accountEdPub,
      u16be(to.length),
      to,
      tsb,
    ]);
  }

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
  ///
  /// [root] and [cert] (phase 33): on a device that does not hold its
  /// account's root, the root device's bundle and the account's certificate
  /// for [me] — so the request is the ACCOUNT's (§8.1) and the anchor is
  /// signed. Both or neither.
  static Future<ContactRequest> create({
    required ZIdentity me,
    required String toRid,
    String? displayName,
    int? ts,
    ContactBundle? root,
    DeviceCertificate? cert,
  }) async {
    if ((root == null) != (cert == null)) {
      throw ArgumentError('an account anchor needs both the root bundle and '
          'the certificate');
    }
    final bundle = await me.bundle(displayName: displayName);
    final at = ts ?? DateTime.now().millisecondsSinceEpoch;
    final sig = await Ed25519().sign(
      signingInput(bundle, toRid, at),
      keyPair: me.edKeyPair,
    );
    final anchorSig = root == null
        ? null
        : await Ed25519().sign(anchorInput(root.edPub, toRid, at),
            keyPair: me.edKeyPair);
    return ContactRequest(
      bundle: bundle,
      toRid: toRid,
      ts: at,
      sig: Uint8List.fromList(sig.bytes),
      root: root,
      cert: cert,
      anchorSig:
          anchorSig == null ? null : Uint8List.fromList(anchorSig.bytes),
    );
  }

  /// The transport payload — base64(JSON), the inner `p` slot of a sealed
  /// envelope. Shares the versioned `{v,t}` shape file chunks use, with
  /// `t: 'creq'`, so [tryParse] and `tryParseChunk` never claim each other's
  /// payloads and neither is a ratchet message. The anchor's members come
  /// after the ones every reader has always read.
  String encode() => base64Encode(utf8.encode(jsonEncode({
        'v': 1,
        't': 'creq',
        'to': toRid,
        'ts': ts,
        'bundle': bundle.toJson(),
        'sig': b64(sig),
        if (root != null) 'root': root!.toJson(),
        if (cert != null) 'cert': cert!.toJson(),
        if (anchorSig != null) 'asig': b64(anchorSig!),
      })));

  /// Parse a transport payload as a request, or null if it is not one — so a
  /// caller can fall through to the ratchet path. Never throws. An anchor
  /// whose members do not parse is left out: the request is then read as
  /// every request was read before it existed.
  static ContactRequest? tryParse(String transportPayload) {
    try {
      final j = jsonDecode(utf8.decode(base64Decode(transportPayload)))
          as Map<String, Object?>;
      if (j['v'] != 1 || j['t'] != 'creq') return null;
      ContactBundle? root;
      DeviceCertificate? cert;
      Uint8List? anchorSig;
      try {
        final r = j['root'], c = j['cert'], s = j['asig'];
        if (r is Map && c is Map && s is String) {
          root = ContactBundle.fromJson(r.cast<String, Object?>());
          cert = DeviceCertificate.fromJson(c.cast<String, Object?>());
          anchorSig = unb64(s);
        }
      } catch (_) {
        root = null;
        cert = null;
        anchorSig = null;
      }
      return ContactRequest(
        bundle:
            ContactBundle.fromJson((j['bundle'] as Map).cast<String, Object?>()),
        toRid: j['to'] as String,
        ts: (j['ts'] as num).toInt(),
        sig: unb64(j['sig'] as String),
        root: root,
        cert: cert,
        anchorSig: anchorSig,
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

  /// The account this request speaks for, when it carries an anchor that
  /// holds (§8.1, phase 33) — call it after [verify]. Null when it carries
  /// none, or one that fails any check, and the request is then read as the
  /// device's own, as every request was before.
  ///
  /// What it checks, in order: the certificate is a real one (not a legacy
  /// record, whose rule is "the device key IS the account key") and is for
  /// the device that signed the request — its Ed25519 AND its X25519 key, or
  /// a stranger holding any certificate of the account could put it beside
  /// their own keys (§18.7's rule 3); the root bundle is another device's
  /// and binds its own X25519 key; the certificate verifies under the root's
  /// key, which for an account's root device IS the account key; and the
  /// requester signed that account into this request.
  Future<RequestAnchor?> anchor() async {
    final r = root, c = cert, s = anchorSig;
    if (r == null || c == null || s == null) return null;
    try {
      if (c.legacy) return null;
      if (!constantTimeEquals(c.deviceEdPub, bundle.edPub) ||
          !constantTimeEquals(c.deviceXPub, bundle.xPub)) {
        return null;
      }
      if (r.edPub.length != 32 || r.xPub.length != 32) return null;
      if (constantTimeEquals(r.edPub, bundle.edPub)) return null;
      if (!await r.verify()) return null;
      if (!await c.verify(r.edPub)) return null;
      final ok = await Ed25519().verify(
        anchorInput(r.edPub, toRid, ts),
        signature: Signature(s,
            publicKey: SimplePublicKey(bundle.edPub, type: KeyPairType.ed25519)),
      );
      if (!ok) return null;
      return RequestAnchor(r.edPub, r, c);
    } catch (_) {
      return null;
    }
  }
}
