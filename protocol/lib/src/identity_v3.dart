// Contact code v3 (§13.2): a post-quantum identity that fits in a QR.
//
// The problem and the shape of the answer are set out in
// `docs/adr/0003-pq-identity-qr.md`. In short: an ML-DSA-65 public key is
// 1 952 bytes and a hybrid device certificate is 5 389, so a v3 account code
// carrying them outright is ~7.4 KB against a 2 953-byte absolute QR ceiling
// — nine times over what actually scans. Scanning is the core onboarding
// flow, so the format has to give.
//
// It gives by noticing that the out-of-band channel never needed to
// TRANSPORT the post-quantum key. It needed to BIND it. So the code carries a
// 32-byte commitment, the key itself arrives inside the resulting ratchet
// session, and the receiver checks one against the other. An attacker who
// wants to substitute a post-quantum key must find a SHA-256 preimage.
//
// Two things this file is careful about:
//
//   * **A commitment, not a reference.** A lookup identifier — a URL, a key
//     id — binds nothing, and a code carrying one degrades to
//     trust-on-first-use: an attacker present at the exchange supplies their
//     own ML-DSA key and passes every hybrid check afterwards, which would
//     make the whole phase decorative.
//   * **The device list is not in the code.** `zc2.` carries one as a
//     convenience; under v3 each device certificate would be 5 389 bytes.
//     Device lists already reach contacts in-band, signed by the account key
//     and verified against it (§3.4, §10.4) — including contacts who were
//     offline for an entire enrollment. The code carries the account
//     identity, which is the thing that must be established by a human
//     looking at a screen; everything else follows from it.

import 'dart:convert';
import 'dart:typed_data';

import 'identity.dart';
import 'pqsign.dart';
import 'util.dart';

const String contactCodePrefixV3 = 'zc3.';

/// How much is known about the authenticity of a contact's identity.
enum IdentityAssurance {
  /// A v1/v2 code: classical keys only. Nothing post-quantum was promised,
  /// so nothing is missing — but a future quantum adversary could forge this
  /// identity, and the UI should not imply otherwise.
  classical,

  /// A v3 code was scanned, so a post-quantum key is COMMITTED TO but has not
  /// arrived yet. Authentication is classical until it does. This state is
  /// normal and brief; it must not be displayed as if it were [hybrid].
  pendingPostQuantum,

  /// The post-quantum key arrived and matched the commitment from the scan.
  hybrid,
}

/// A v3 contact code: classical keys in full, the post-quantum half bound by
/// a 32-byte commitment.
class ContactBundleV3 {
  final Uint8List edPub; // 32 — account Ed25519
  final Uint8List xPub; // 32 — account X25519
  final Uint8List bindingSig; // 64 — binds xPub to edPub, as in v1
  final Uint8List pqCommit; // 32 — SHA-256("z-pqid-v3:" || ml_pub)
  final String? displayName;

  ContactBundleV3({
    required this.edPub,
    required this.xPub,
    required this.bindingSig,
    required this.pqCommit,
    this.displayName,
  });

  /// The classical view of this identity — what every existing code path
  /// (routing, sessions, safety numbers) already consumes.
  ContactBundle get classical => ContactBundle(
      edPub: edPub,
      xPub: xPub,
      bindingSig: bindingSig,
      displayName: displayName);

  Future<String> routingId() => classical.routingId();

  /// Builds the code for [me], committing to [pqPublic].
  static Future<ContactBundleV3> forIdentity(
    ZIdentity me,
    HybridPublicKey pqPublic, {
    String? displayName,
  }) async {
    if (!constantTimeEquals(me.edPub, pqPublic.edPub)) {
      // The classical half of the hybrid key IS this identity's key. If they
      // differ, the code would commit to a post-quantum key belonging to a
      // different identity — the exact substitution the commitment exists to
      // prevent, self-inflicted.
      throw const FormatException(
          'the hybrid key does not belong to this identity');
    }
    return ContactBundleV3(
      edPub: me.edPub,
      xPub: me.xPub,
      bindingSig: await me.bindingSignature(),
      pqCommit: await pqPublic.pqCommitment(),
      displayName: displayName,
    );
  }

  String encode() {
    final j = <String, Object?>{
      'v': 3,
      'ed': b64(edPub),
      'x': b64(xPub),
      'sig': b64(bindingSig),
      'pqc': b64(pqCommit),
      if (displayName != null && displayName!.isNotEmpty) 'name': displayName,
    };
    return contactCodePrefixV3 + b64url(utf8.encode(jsonEncode(j)));
  }

  /// Parses and VERIFIES a v3 code.
  static Future<ContactBundleV3> decode(String code) async {
    final trimmed = code.trim();
    if (!trimmed.startsWith(contactCodePrefixV3)) {
      throw const FormatException('not a Z v3 contact code');
    }
    final Map<String, Object?> j;
    try {
      j = jsonDecode(utf8
              .decode(unb64url(trimmed.substring(contactCodePrefixV3.length))))
          as Map<String, Object?>;
    } catch (_) {
      throw const FormatException('corrupt contact code');
    }
    if (j['v'] != 3) throw const FormatException('unsupported version');
    final pqc = j['pqc'];
    if (pqc is! String) {
      // A v3 code without a commitment is a downgrade attempt, not an old
      // code: old codes say v1 or v2 and are handled by their own decoders.
      throw const FormatException(
          'a v3 contact code must carry a post-quantum commitment');
    }
    final b = ContactBundleV3(
      edPub: unb64(j['ed'] as String),
      xPub: unb64(j['x'] as String),
      bindingSig: unb64(j['sig'] as String),
      pqCommit: unb64(pqc),
      displayName: j['name'] as String?,
    );
    if (b.edPub.length != 32 || b.xPub.length != 32) {
      throw const FormatException('bad key length');
    }
    if (b.pqCommit.length != 32) {
      throw const FormatException('bad commitment length');
    }
    if (!await b.classical.verify()) {
      throw const FormatException(
          'contact code signature invalid (possible tampering)');
    }
    return b;
  }

  /// Checks a post-quantum key delivered in-band against the commitment from
  /// the scan. Constant-time, and the ONLY way a [pendingPostQuantum]
  /// identity becomes [hybrid].
  ///
  /// A false here is not a retryable failure. It means the key that arrived
  /// over the session is not the key the person in front of you committed to,
  /// which is either a broken implementation or an active attacker; the
  /// caller must refuse the identity rather than carry on classically.
  Future<bool> acceptsPqKey(HybridPublicKey candidate) async {
    if (!constantTimeEquals(candidate.edPub, edPub)) return false;
    return constantTimeEquals(await candidate.pqCommitment(), pqCommit);
  }

  Map<String, Object?> toJson() => {
        'ed': b64(edPub),
        'x': b64(xPub),
        'sig': b64(bindingSig),
        'pqc': b64(pqCommit),
        'name': displayName,
      };

  static ContactBundleV3 fromJson(Map<String, Object?> j) => ContactBundleV3(
        edPub: unb64(j['ed'] as String),
        xPub: unb64(j['x'] as String),
        bindingSig: unb64(j['sig'] as String),
        pqCommit: unb64(j['pqc'] as String),
        displayName: j['name'] as String?,
      );
}

/// The result of scanning any Z contact code, whatever its version.
class ScannedIdentity {
  final ContactBundle classical;
  final IdentityAssurance assurance;

  /// Present only for a v3 code; what an in-band post-quantum key is checked
  /// against.
  final ContactBundleV3? v3;

  const ScannedIdentity(this.classical, this.assurance, {this.v3});
}

/// Parses a `zc1.`, `zc2.` or `zc3.` code, so a caller never has to ask the
/// user which kind of code they are holding — and so a v1 identity is
/// reported as classical rather than being quietly treated as post-quantum.
///
/// `zc2.` account codes are decoded by `AccountBundle` in `multidevice.dart`;
/// this returns their classical view too, via [accountFallback], which the
/// app supplies so this module does not depend on the multi-device layer.
Future<ScannedIdentity> scanContactCode(
  String code, {
  Future<ContactBundle> Function(String code)? accountFallback,
}) async {
  final t = code.trim();
  if (t.startsWith(contactCodePrefixV3)) {
    final b = await ContactBundleV3.decode(t);
    return ScannedIdentity(b.classical, IdentityAssurance.pendingPostQuantum,
        v3: b);
  }
  if (t.startsWith(contactCodePrefix)) {
    return ScannedIdentity(
        await ContactBundle.decode(t), IdentityAssurance.classical);
  }
  if (accountFallback != null && t.startsWith('zc2.')) {
    return ScannedIdentity(
        await accountFallback(t), IdentityAssurance.classical);
  }
  throw const FormatException('not a Z contact code');
}
