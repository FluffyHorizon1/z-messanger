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
import 'multidevice.dart';
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
  final Uint8List edPub; // 32 — the Ed25519 key of the DEVICE showing this
  final Uint8List xPub; // 32 — that device's X25519 key
  final Uint8List bindingSig; // 64 — binds xPub to edPub, as in v1
  final Uint8List pqCommit; // 32 — SHA-256("z-pqid-v3:" || ml_pub)
  final String? displayName;

  /// The ACCOUNT's Ed25519 key, when the code says one (§18.7).
  ///
  /// Null means the code is self-anchored: the device showing it *is* the
  /// account, which is the §3.5 legacy mapping and the only case a v1 code
  /// could express. Use [accountEdPub], never this.
  final Uint8List? declaredAccountEdPub;

  /// The account's certificate for the device in this code, present exactly
  /// when [declaredAccountEdPub] is — it is what makes the claim checkable.
  final DeviceCertificate? deviceCert;

  ContactBundleV3({
    required this.edPub,
    required this.xPub,
    required this.bindingSig,
    required this.pqCommit,
    this.displayName,
    this.declaredAccountEdPub,
    this.deviceCert,
  });

  /// The identity this code is ABOUT: an account, not a device.
  ///
  /// Everything a human confirms — the safety number, the post-quantum
  /// commitment — is anchored here, so that scanning someone's laptop and
  /// scanning their phone are the same act. Where a code says nothing, the
  /// device is the account (§3.5).
  Uint8List get accountEdPub => declaredAccountEdPub ?? edPub;

  /// The classical view of this identity — what every existing code path
  /// (routing, sessions, safety numbers) already consumes.
  ContactBundle get classical => ContactBundle(
      edPub: edPub,
      xPub: xPub,
      bindingSig: bindingSig,
      displayName: displayName);

  Future<String> routingId() => classical.routingId();

  /// Builds the code [me] hands out, committing to [pqPublic].
  ///
  /// [accountEdPub] and [cert] together make the code account-anchored
  /// (§18.7): pass them on a device that is not the account root, so what a
  /// contact scans is the person rather than the laptop in front of them.
  /// Omit both on a root device, where the two are the same identity and
  /// saying so twice only makes the code bigger.
  static Future<ContactBundleV3> forIdentity(
    ZIdentity me,
    HybridPublicKey pqPublic, {
    String? displayName,
    Uint8List? accountEdPub,
    DeviceCertificate? cert,
  }) async {
    if ((accountEdPub == null) != (cert == null)) {
      // One without the other is either an unprovable claim or a proof of
      // nothing. Refusing here means no caller can build the shape the
      // decoder would have to reject.
      throw const FormatException(
          'an account-anchored code needs both the account key and a '
          'certificate for this device');
    }
    final anchor = accountEdPub ?? me.edPub;
    if (!constantTimeEquals(anchor, pqPublic.edPub)) {
      // The classical half of the hybrid key IS the ACCOUNT's key. If they
      // differ, the code would commit to a post-quantum key belonging to a
      // different identity — the exact substitution the commitment exists to
      // prevent, self-inflicted.
      throw const FormatException(
          'the hybrid key does not belong to this identity');
    }
    if (cert != null) {
      if (!constantTimeEquals(cert.deviceEdPub, me.edPub) ||
          !constantTimeEquals(cert.deviceXPub, me.xPub)) {
        throw const FormatException(
            'the certificate is not for the device in this code');
      }
      if (!await cert.verify(anchor)) {
        throw const FormatException(
            'the certificate is not signed by that account');
      }
    }
    return ContactBundleV3(
      edPub: me.edPub,
      xPub: me.xPub,
      bindingSig: await me.bindingSignature(),
      pqCommit: await pqPublic.pqCommitment(),
      displayName: displayName,
      declaredAccountEdPub: accountEdPub,
      deviceCert: cert,
    );
  }

  /// The explicit v3 form. **Not what clients emit** — see [encode].
  String encodeStrict() {
    final j = <String, Object?>{
      'v': 3,
      'ed': b64(edPub),
      'x': b64(xPub),
      'sig': b64(bindingSig),
      'pqc': b64(pqCommit),
      if (declaredAccountEdPub != null) 'acct': b64(declaredAccountEdPub!),
      if (deviceCert != null) 'cert': deviceCert!.toJson(),
      if (displayName != null && displayName!.isNotEmpty) 'name': displayName,
    };
    return contactCodePrefixV3 + b64url(utf8.encode(jsonEncode(j)));
  }

  /// The code clients hand out: a **v1 code carrying one extra member**.
  ///
  /// PROTOCOL.md §14 is explicit that "new optional JSON members" are
  /// compatible evolution and do not warrant a version bump — only a change
  /// to bytes an existing implementation would compute differently does. The
  /// commitment changes nothing anyone computes; it is pure addition. A
  /// `zc3.` prefix, by contrast, is rejected outright by every build already
  /// in the field, so emitting one would mean handing out a code most people
  /// cannot scan in order to convey information they would have ignored.
  ///
  /// So the commitment rides in a `zc1.` code. An older client reads the
  /// classical identity and ignores `pqc`; a v3 client sees the commitment
  /// and knows a post-quantum key is coming. Same information, no flag day.
  String encode() {
    final j = <String, Object?>{
      'v': 1,
      'ed': b64(edPub),
      'x': b64(xPub),
      'sig': b64(bindingSig),
      'pqc': b64(pqCommit),
      if (declaredAccountEdPub != null) 'acct': b64(declaredAccountEdPub!),
      if (deviceCert != null) 'cert': deviceCert!.toJson(),
      if (displayName != null && displayName!.isNotEmpty) 'name': displayName,
    };
    return contactCodePrefix + b64url(utf8.encode(jsonEncode(j)));
  }

  /// Parses and VERIFIES a code carrying a commitment, in either form: the
  /// `zc1.`-with-`pqc` one clients emit, or the explicit `zc3.` one.
  static Future<ContactBundleV3> decode(String code) async {
    final trimmed = code.trim();
    final int expectVersion;
    final String body;
    if (trimmed.startsWith(contactCodePrefixV3)) {
      expectVersion = 3;
      body = trimmed.substring(contactCodePrefixV3.length);
    } else if (trimmed.startsWith(contactCodePrefix)) {
      expectVersion = 1;
      body = trimmed.substring(contactCodePrefix.length);
    } else {
      throw const FormatException('not a Z contact code');
    }
    final Map<String, Object?> j;
    try {
      j = jsonDecode(utf8.decode(unb64url(body))) as Map<String, Object?>;
    } catch (_) {
      throw const FormatException('corrupt contact code');
    }
    if (j['v'] != expectVersion) {
      throw const FormatException('unsupported version');
    }
    final pqc = j['pqc'];
    if (pqc is! String) {
      // For a zc3. code this is a downgrade attempt: it announced a version
      // that requires one. For a zc1. code it simply means a classical
      // identity, which `scanContactCode` sorts out before reaching here.
      throw const FormatException(
          'this contact code carries no post-quantum commitment');
    }
    // §18.7: a code may name the ACCOUNT it belongs to and prove that the
    // device it describes is one of that account's, so scanning someone's
    // laptop adds the person rather than the laptop. The two members come as
    // a pair — a claim without a certificate is an assertion, and a
    // certificate without a claim is a proof of nothing.
    final acct = j['acct'], cert = j['cert'];
    if ((acct == null) != (cert == null)) {
      throw const FormatException(
          'an account-anchored contact code needs both the account key and a '
          'certificate');
    }
    Uint8List? acctEd;
    DeviceCertificate? deviceCert;
    if (acct != null) {
      if (acct is! String || cert is! Map) {
        throw const FormatException('malformed account anchor');
      }
      acctEd = unb64(acct);
      if (acctEd.length != 32) {
        throw const FormatException('bad account key length');
      }
      try {
        deviceCert = DeviceCertificate.fromJson(cert.cast<String, Object?>());
      } catch (_) {
        throw const FormatException('malformed device certificate');
      }
      if (deviceCert.legacy) {
        // The legacy rule says "the device key IS the account key", which is
        // precisely what an account-anchored code is not. Accepting one here
        // would let a v1 binding signature stand in for an account's
        // endorsement of a device it never signed for.
        throw const FormatException(
            'a legacy record cannot anchor a code to an account');
      }
    }
    final b = ContactBundleV3(
      edPub: unb64(j['ed'] as String),
      xPub: unb64(j['x'] as String),
      bindingSig: unb64(j['sig'] as String),
      pqCommit: unb64(pqc),
      displayName: j['name'] as String?,
      declaredAccountEdPub: acctEd,
      deviceCert: deviceCert,
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
    if (deviceCert != null) {
      // The certificate must be FOR the device in this code, not merely a
      // genuine certificate of that account's. Without this check anyone
      // holding any device certificate of Bob's could present their own keys
      // beside it and be scanned as Bob.
      if (!constantTimeEquals(deviceCert.deviceEdPub, b.edPub) ||
          !constantTimeEquals(deviceCert.deviceXPub, b.xPub)) {
        throw const FormatException(
            'the certificate in this code is for a different device');
      }
      if (!await deviceCert.verify(acctEd!)) {
        throw const FormatException(
            'this device is not certified by the account it claims');
      }
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
    // Against the ACCOUNT key: a post-quantum identity belongs to the person,
    // not to whichever of their devices was scanned (§18.7).
    if (!constantTimeEquals(candidate.edPub, accountEdPub)) return false;
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

  /// The account this code identifies (§18.7).
  ///
  /// [classical] describes the DEVICE — its keys are what a session is opened
  /// with and what a routing id is derived from — while this is the identity
  /// a human confirms. They differ only when someone's linked device was
  /// scanned; for every code that predates §18.7 they are the same key, which
  /// is why every existing safety number is unchanged.
  Uint8List get accountEdPub => v3?.accountEdPub ?? classical.edPub;

  /// The account's certificate for the scanned device, when the code carried
  /// one. It is the evidence behind [accountEdPub], and it is what lets this
  /// contact's device list be checked later.
  DeviceCertificate? get deviceCert => v3?.deviceCert;
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
    // A v1 code may carry a post-quantum commitment as an extra member
    // (§18.2). If it does, this is a v3 identity wearing a v1 shape so that
    // clients already in the field can still read it; if not, it is a plain
    // v1 identity and nothing post-quantum was promised.
    if (_carriesV3Members(t)) {
      final b = await ContactBundleV3.decode(t);
      return ScannedIdentity(b.classical, IdentityAssurance.pendingPostQuantum,
          v3: b);
    }
    return ScannedIdentity(
        await ContactBundle.decode(t), IdentityAssurance.classical);
  }
  if (accountFallback != null && t.startsWith('zc2.')) {
    return ScannedIdentity(
        await accountFallback(t), IdentityAssurance.classical);
  }
  throw const FormatException('not a Z contact code');
}

// ---------------------------------------------------------------------------
// Hybrid device certificates (§18.4) and safety number v2 (§18.5)
// ---------------------------------------------------------------------------

/// How well a device's membership of an account has been established.
enum DeviceAssurance {
  /// The account signed this device classically only — a v1/v2 account, or a
  /// v3 one whose post-quantum signature has not arrived yet. Correct today,
  /// forgeable by a quantum adversary later.
  classical,

  /// Both halves of the account's signature check out.
  hybrid,
}

/// The account's ML-DSA-65 signature over its device list (§18.9, ADR 0004).
///
/// **Over the LIST, not over each certificate**, and that is the point rather
/// than an economy. An adversary who can forge Ed25519 but not ML-DSA — the
/// whole premise of phase 13 — can take a genuine hybrid list for
/// `{phone, laptop, tablet}` and present one for `{phone, tablet}`: the
/// classical list signature is forged, and each remaining certificate's
/// post-quantum half is *genuine*, copied unchanged. Every check passes and
/// the honest device has been excluded (`adr/0001` T2). A signature over the
/// list covers the membership and the version, so neither can be changed.
///
/// It travels as its own message, on a schedule unrelated to the list's, so
/// the 16 384-byte envelope it needs says nothing about when a device set
/// changed. See ADR 0004 for the measurements behind that.
class HybridDeviceListSignature {
  final Uint8List accountEdPub;
  final int version;

  /// ML-DSA-65 over exactly [SignedDeviceList.signingInput] — the same bytes
  /// the classical signature covers, so no valid pair can attest to different
  /// device sets.
  final Uint8List mlSig;

  HybridDeviceListSignature({
    required this.accountEdPub,
    required this.version,
    required this.mlSig,
  }) {
    if (accountEdPub.length != 32) {
      throw const HybridFormatException('account key must be 32 bytes');
    }
    if (mlSig.length != mlDsaSignatureBytes) {
      throw HybridFormatException(
          'ML-DSA-65 signature must be $mlDsaSignatureBytes bytes');
    }
  }

  /// Signs [list] with the account's hybrid key. Only a device holding the
  /// account root can do this.
  static Future<HybridDeviceListSignature> sign({
    required HybridKeyPair accountKey,
    required SignedDeviceList list,
    bool deterministic = false,
  }) async {
    if (!constantTimeEquals(accountKey.publicKey.edPub, list.accountEdPub)) {
      throw const HybridFormatException(
          'that hybrid key does not belong to this account');
    }
    final both = await accountKey.sign(
        SignedDeviceList.signingInput(list.version, list.devices),
        deterministic: deterministic);
    return HybridDeviceListSignature(
      accountEdPub: list.accountEdPub,
      version: list.version,
      mlSig: both.ml,
    );
  }

  /// Checks this signature against a list and the account's ML-DSA key.
  ///
  /// Every part must line up: the key must be the one this list claims, the
  /// version must match, and the signature must cover the list's own signing
  /// input. A caller that has not yet established [accountMlPub] against the
  /// commitment from a scanned code (§18.2) has nothing to check with and
  /// must hold the signature rather than accept it.
  Future<bool> verifies(SignedDeviceList list, Uint8List accountMlPub) async {
    if (!constantTimeEquals(accountEdPub, list.accountEdPub)) return false;
    if (version != list.version) return false;
    try {
      return pqDsaVerify(accountMlPub,
          SignedDeviceList.signingInput(list.version, list.devices), mlSig);
    } catch (_) {
      return false;
    }
  }

  Map<String, Object?> toJson() => {
        'acct': b64(accountEdPub),
        'ver': version,
        'mlsig': b64(mlSig),
      };

  static HybridDeviceListSignature fromJson(Map<String, Object?> j) {
    final acct = j['acct'], ver = j['ver'], sig = j['mlsig'];
    if (acct is! String || ver is! num || sig is! String) {
      throw const HybridFormatException(
          'a device-list signature needs an account, a version and a signature');
    }
    return HybridDeviceListSignature(
      accountEdPub: unb64(acct),
      version: ver.toInt(),
      mlSig: unb64(sig),
    );
  }
}

/// A device certificate signed under both of an account's keys.
///
/// The certificate is the whole ballgame for §13: it is the account's
/// statement that a device belongs to it, so forging one inserts a rogue
/// device into every contact's fan-out and reads everything from then on.
/// That is the one thing a quantum adversary could do to this design without
/// touching a single recorded ciphertext, and it is what the post-quantum half
/// is here to stop.
///
/// Both signatures cover the **identical** bytes — `DeviceCertificate
/// .signingInput` — so there is no way to obtain a valid pair attesting to
/// different devices.
class HybridDeviceCertificate {
  /// The classical certificate, unchanged in shape from v2. A v3-unaware
  /// client reads exactly this and is none the wiser.
  final DeviceCertificate classical;

  /// ML-DSA-65 over the same signing input. 3 309 bytes.
  final Uint8List mlSig;

  HybridDeviceCertificate({required this.classical, required this.mlSig}) {
    if (classical.legacy) {
      // A legacy record is a v1 identity read as a device: the "signature" is
      // the v1 binding signature and there is no account key separate from
      // the device key. There is nothing for a post-quantum half to attest
      // to, and pretending otherwise would let a v1 identity be presented as
      // post-quantum verified.
      throw const HybridFormatException(
          'a legacy v1 record cannot be a hybrid certificate');
    }
    if (mlSig.length != mlDsaSignatureBytes) {
      throw HybridFormatException(
          'ML-DSA-65 signature must be $mlDsaSignatureBytes bytes');
    }
  }

  Uint8List get signingInput => DeviceCertificate.signingInput(
      classical.deviceEdPub, classical.deviceXPub, classical.deviceId);

  /// Signs [deviceEdPub]/[deviceXPub]/[deviceId] under an account's hybrid
  /// key. Only a device holding the account root can do this.
  static Future<HybridDeviceCertificate> sign({
    required HybridKeyPair accountKey,
    required Uint8List deviceEdPub,
    required Uint8List deviceXPub,
    required String deviceId,
    bool deterministic = false,
  }) async {
    final input =
        DeviceCertificate.signingInput(deviceEdPub, deviceXPub, deviceId);
    final both = await accountKey.sign(input, deterministic: deterministic);
    return HybridDeviceCertificate(
      classical: DeviceCertificate(
        deviceEdPub: deviceEdPub,
        deviceXPub: deviceXPub,
        deviceId: deviceId,
        sig: both.ed,
      ),
      mlSig: both.ml,
    );
  }

  /// True only if BOTH halves verify under [accountKey].
  ///
  /// There is deliberately no way to ask this object for a classical-only
  /// verdict: a caller that wants one uses [classical] and gets
  /// [DeviceAssurance.classical] back from wherever it is tracking that, so
  /// the weaker check is always a visible choice rather than a fallback.
  Future<bool> verify(HybridPublicKey accountKey) async {
    if (!await classical.verify(accountKey.edPub)) return false;
    return pqDsaVerify(accountKey.mlPub, signingInput, mlSig);
  }

  Map<String, Object?> toJson() => {
        ...classical.toJson(),
        'mlsig': b64(mlSig),
      };

  /// A certificate without its post-quantum half does not parse as a hybrid
  /// one. Stripping must not produce something a verifier could evaluate.
  static HybridDeviceCertificate fromJson(Map<String, Object?> j) {
    final ml = j['mlsig'];
    if (ml is! String) {
      throw const HybridFormatException(
          'a hybrid device certificate needs its post-quantum half');
    }
    return HybridDeviceCertificate(
      classical: DeviceCertificate.fromJson(j),
      mlSig: unb64(ml),
    );
  }
}

/// Safety number v2 (§18.5): the number two people compare, derived from
/// **both halves of both account keys**.
///
/// Same shape as v1 — twelve five-digit groups, symmetric in the two
/// identities — and the same rule about which keys go in: the ACCOUNT keys,
/// so the number does not move when either side links or drops a device.
/// (That rule was specified from the start and was still got wrong once; see
/// the phase-10 fix.)
///
/// The salt differs from v1's, so a v2 number can never coincide with a v1
/// number for the same pair. That matters because the change is visible to
/// every user exactly once, and a client showing the new number must say so
/// rather than letting it look like a key substitution.
Future<String> safetyNumberV3(HybridPublicKey a, HybridPublicKey b) async {
  final aFirst = _lexLessBytes(a.edPub, b.edPub);
  final lo = aFirst ? a : b;
  final hi = aFirst ? b : a;
  return safetyNumberFromMaterial(
      concatBytes([lo.edPub, lo.mlPub, hi.edPub, hi.mlPub]),
      context: safetyContextV3);
}

const String safetyContextV3 = 'z-safety-v2';

bool _lexLessBytes(Uint8List a, Uint8List b) {
  final n = a.length < b.length ? a.length : b.length;
  for (var i = 0; i < n; i++) {
    if (a[i] != b[i]) return a[i] < b[i];
  }
  return a.length < b.length;
}

/// Peeks at a `zc1.` code for members only a v3 client writes, without
/// verifying anything — [scanContactCode] uses it only to choose which
/// decoder to run, and both decoders verify what they parse.
///
/// `acct` counts as well as `pqc`, and that matters: without it, a code that
/// anchors itself to an account would be handed to the v1 decoder, which
/// ignores members it does not know — silently reducing the person to the
/// device they were standing at. Routing it here instead means the v3 decoder
/// gets it, and a code that anchors to an account without also committing to
/// its post-quantum key is refused rather than quietly downgraded.
bool _carriesV3Members(String code) {
  try {
    final j = jsonDecode(
            utf8.decode(unb64url(code.substring(contactCodePrefix.length))))
        as Map<String, Object?>;
    return j['pqc'] is String || j['acct'] is String;
  } catch (_) {
    return false;
  }
}
