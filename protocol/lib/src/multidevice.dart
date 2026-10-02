import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'identity.dart';
import 'util.dart';

/// Multi-device data model (M1).
///
/// An identity is promoted into an ACCOUNT. The Ed25519 account key is the
/// trust root: it never runs a ratchet and never routes — it only *signs
/// device certificates* and anchors the (stable) safety number. Each device
/// holds its own Ed25519 key (relay auth + its own routing id) and its own
/// X25519 key (its ratchets). A [DeviceCertificate] is the account key's
/// signature that a device's public keys belong to the account.
///
/// The relay is unchanged: every device is just another routing id. The
/// account→devices mapping lives only in these client-side bundles.
///
/// Backward compatibility: a v1 identity migrates so that device #1's keys ARE
/// the old identity keys (same routing id, same X25519 → existing sessions and
/// contacts keep working). A v1 contact code (`zc1.`) reads as a one-device
/// account whose single device is that identity.

const String deviceCertContext = 'z-device-cert-v1:';
const String accountCodePrefix = 'zc2.';

/// Stage 2b of ADR 0017: a root signs its device lists v2-only — with `sig3`
/// alone, over the v2 content under a context of its own
/// ([SignedDeviceList.signingInputV3]) — and produces neither the v1 `sig` nor
/// the `sig2` that sits beside it. **Off.**
///
/// While this is `false` nothing has changed from stage 1: [AccountIdentity
/// .signDeviceList] dual-signs, every list reports the v1 fingerprint and its
/// ML-DSA is over the v1 input, byte for byte as before. What the release that
/// carries it does change is the reading side (stage 2a, always on): every
/// client now verifies, fingerprints and ML-DSA-checks a list signed with
/// `sig3` alone, and refuses any list in a shape other than the three the
/// protocol defines — see [SignedDeviceList.hasValidShape] and
/// [SignedDeviceList.commitmentInput].
///
/// Setting it to `true` is the whole of the flip. On its next start each root
/// re-signs its account's list once, at the next version, with `sig3` alone
/// (the app's `_migrateDeviceListToV2Only`), and sends it to its own devices,
/// to every contact and to the log; the list's fingerprint and its ML-DSA then
/// cover each device's ratchet key, and from then on every list it signs is
/// v2-only. A contact that has seen such a list refuses any later list from
/// that account that carries a v1 signature.
///
/// So the flip is one way, by design. Turning this back to `false` does not
/// un-flip an account that has moved: the stored state decides, not this
/// constant, and a root that has signed v2-only keeps signing v2-only on any
/// build from this release on — one that turns the constant back, a
/// downgrade to this release, a post-flip backup restored onto it. Were it
/// otherwise, the version it re-signed would gain a second fingerprint, and
/// every contact would raise a split alarm. Turning the constant off only
/// stops roots that have not moved from moving. A build OLDER than this
/// release cannot read a v2-only list at all, and cannot even start on a
/// vault that holds a contact's: going below this release after the flip is
/// not supported.
///
/// What must be true before flipping it, and both halves matter:
///
///  * no client from the 3.5.7 era is left. Such a client verifies `sig` and
///    nothing else; it is what stage 1 dual-signs for. The evidence is the one
///    `RELAY_AUTH_V1` in `server/server.js` waits on: the relay's
///    `z_auth_v1_total` at zero for as long as the operator cares to wait.
///  * no client from before stage 2a is left either — which is the real floor,
///    and the stricter one. Every build before the release that introduced this
///    constant reads `sig` unconditionally when it parses a list, so a list
///    without it is thrown away unread. To that client a flipped account's new
///    devices do not exist, its user is told after the grace that the
///    contact's list update never arrived, and the account's new log entry
///    does not open as its list — which the log check treats as a conflict
///    and holds sends to that account. Its own linked devices on such a build
///    never learn the account's list, and raise a false own-account alert
///    (an unissued list) when contacts echo the version they cannot parse.
///    "No v1 signer left" is therefore not enough; the flip waits until
///    everyone — linked devices included — runs at least the release that
///    shipped this line (ADR 0017, "Stage 2").
///
/// Tests turn the signer on for one service at a time through
/// `ChatService.init(signDevlistV2Only:)` and for one call through
/// [AccountIdentity.signDeviceList]'s `v2Only`; the constant itself is read
/// nowhere else. The commit that flips it also updates the tests written for
/// stage 1 — ADR 0017 lists the ones a run with it on turned up.
const bool devlistSignV2Only = false;

final _ed = Ed25519();
final _x = X25519();

Future<Uint8List> _edPubFromSeed(Uint8List seed) async {
  final kp = await _ed.newKeyPairFromSeed(seed);
  return Uint8List.fromList((await kp.extractPublicKey()).bytes);
}

Future<Uint8List> _xPubFromSeed(Uint8List seed) async {
  final kp = await _x.newKeyPairFromSeed(seed);
  return Uint8List.fromList((await kp.extractPublicKey()).bytes);
}

/// The account key's attestation that a device belongs to it. Self-contained:
/// it carries the device's public keys, so it doubles as the device's public
/// record inside an [AccountBundle].
class DeviceCertificate {
  final Uint8List deviceEdPub;
  final Uint8List deviceXPub;
  final String deviceId;
  final Uint8List sig; // account Ed25519 signature over [signingInput]

  /// True when this record is a v1 identity read as a device (it came from a
  /// `zc1.` code): the device key is the account key and [sig] is the v1
  /// binding signature. [verify] checks exactly that rule for such records.
  final bool legacy;

  DeviceCertificate({
    required this.deviceEdPub,
    required this.deviceXPub,
    required this.deviceId,
    required this.sig,
    this.legacy = false,
  });

  static Uint8List signingInput(
          Uint8List deviceEdPub, Uint8List deviceXPub, String deviceId) =>
      concatBytes([
        utf8.encode(deviceCertContext),
        deviceEdPub,
        deviceXPub,
        utf8.encode(deviceId),
      ]);

  Future<String> routingId() async => b64url(await sha256Bytes(deviceEdPub));

  /// Verify this certificate against an account Ed25519 public key.
  ///
  /// The [legacy] flag selects WHICH rule is checked — it never skips the
  /// check. A legacy record is exactly what a v1 (`zc1.`) contact code decodes
  /// to: the device key IS the account key, the id is `legacy-v1`, and [sig]
  /// is the v1 binding signature over the X25519 key. Anything else flagged
  /// legacy (e.g. a crafted `zc2.` code or device list) fails.
  Future<bool> verify(Uint8List accountEdPub) async {
    if (deviceEdPub.length != 32 ||
        deviceXPub.length != 32 ||
        accountEdPub.length != 32) {
      return false;
    }
    try {
      final key = SimplePublicKey(accountEdPub, type: KeyPairType.ed25519);
      if (legacy) {
        if (deviceId != 'legacy-v1' ||
            !constantTimeEquals(deviceEdPub, accountEdPub)) {
          return false;
        }
        return await _ed.verify(
          concatBytes([utf8.encode(bindContext), deviceXPub]),
          signature: Signature(sig, publicKey: key),
        );
      }
      return await _ed.verify(
        signingInput(deviceEdPub, deviceXPub, deviceId),
        signature: Signature(sig, publicKey: key),
      );
    } catch (_) {
      return false;
    }
  }

  Map<String, Object?> toJson() => {
        'ded': b64(deviceEdPub),
        'dx': b64(deviceXPub),
        'id': deviceId,
        'sig': b64(sig),
        if (legacy) 'legacy': true,
      };

  static DeviceCertificate fromJson(Map<String, Object?> j) =>
      DeviceCertificate(
        deviceEdPub: unb64(j['ded'] as String),
        deviceXPub: unb64(j['dx'] as String),
        deviceId: j['id'] as String,
        sig: unb64(j['sig'] as String),
        legacy: j['legacy'] == true,
      );
}

/// The PUBLIC account: the account key plus the set of member devices. This is
/// the v2 contact code, and the fan-out target list for a contact.
class AccountBundle {
  final Uint8List accountEdPub;
  final List<DeviceCertificate> devices;
  final String? displayName;

  AccountBundle({
    required this.accountEdPub,
    required this.devices,
    this.displayName,
  });

  /// Stable account id (does not change as devices come and go).
  Future<String> accountId() async => b64url(await sha256Bytes(accountEdPub));

  /// The routing ids to fan a message out to (one per member device).
  Future<List<String>> deviceRoutingIds() async =>
      [for (final d in devices) await d.routingId()];

  /// Symmetric safety number vs. my account — stable across device changes,
  /// because it derives only from the two account keys.
  Future<String> safetyNumberWith(Uint8List myAccountEdPub) =>
      safetyNumber(myAccountEdPub, accountEdPub);

  /// Every device cert must validate against the account key.
  Future<bool> verifyAll() async {
    if (accountEdPub.length != 32 || devices.isEmpty) return false;
    for (final d in devices) {
      if (!await d.verify(accountEdPub)) return false;
    }
    return true;
  }

  String encode() {
    final j = <String, Object?>{
      'v': 2,
      'acct': b64(accountEdPub),
      'devs': [for (final d in devices) d.toJson()],
      if (displayName != null && displayName!.isNotEmpty) 'name': displayName,
    };
    return accountCodePrefix + b64url(utf8.encode(jsonEncode(j)));
  }

  /// Parse AND verify a contact code. Accepts both v2 (`zc2.`) account codes
  /// and legacy v1 (`zc1.`) codes (read as a one-device account). Throws
  /// [FormatException] on anything malformed or tampered.
  static Future<AccountBundle> decode(String code) async {
    final trimmed = code.trim();
    if (trimmed.startsWith(contactCodePrefix)) {
      // Legacy v1 → a one-device account. ContactBundle.decode verifies the
      // binding signature; we wrap it as a legacy (pre-verified) device.
      final b = await ContactBundle.decode(trimmed);
      return AccountBundle(
        accountEdPub: b.edPub,
        devices: [
          DeviceCertificate(
            deviceEdPub: b.edPub,
            deviceXPub: b.xPub,
            deviceId: 'legacy-v1',
            sig: b.bindingSig,
            legacy: true,
          )
        ],
        displayName: b.displayName,
      );
    }
    if (!trimmed.startsWith(accountCodePrefix)) {
      throw const FormatException('not a Z contact code');
    }
    final Map<String, Object?> j;
    try {
      j = jsonDecode(utf8
              .decode(unb64url(trimmed.substring(accountCodePrefix.length))))
          as Map<String, Object?>;
    } catch (_) {
      throw const FormatException('corrupt contact code');
    }
    if (j['v'] != 2) throw const FormatException('unsupported version');
    final bundle = AccountBundle(
      accountEdPub: unb64(j['acct'] as String),
      devices: [
        for (final d in (j['devs'] as List))
          DeviceCertificate.fromJson((d as Map).cast<String, Object?>())
      ],
      displayName: j['name'] as String?,
    );
    if (!await bundle.verifyAll()) {
      throw const FormatException(
          'account code failed verification (possible tampering)');
    }
    return bundle;
  }

  Map<String, Object?> toJson() => {
        'acct': b64(accountEdPub),
        'devs': [for (final d in devices) d.toJson()],
        'name': displayName,
      };

  static AccountBundle fromJson(Map<String, Object?> j) => AccountBundle(
        accountEdPub: unb64(j['acct'] as String),
        devices: [
          for (final d in (j['devs'] as List))
            DeviceCertificate.fromJson((d as Map).cast<String, Object?>())
        ],
        displayName: j['name'] as String?,
      );
}

/// The LOCAL (private) view of an account on THIS device. Holds this device's
/// secret seeds and — only on devices that hold the account root — the account
/// secret needed to sign new device certificates.
class AccountIdentity {
  final Uint8List accountEdPub;
  final Uint8List? accountEdSeed; // present iff this device holds the root

  /// v3 (§18): the ACCOUNT's ML-DSA public key, where known. A device holding
  /// the root derives it from the account seed; a linked device receives it
  /// at enrollment. Null on a device linked by a build that predates v3.
  final Uint8List? accountMlPub;
  final Uint8List deviceEdSeed;
  final Uint8List deviceXSeed;
  final Uint8List deviceEdPub;
  final Uint8List deviceXPub;
  final String deviceId;
  final DeviceCertificate deviceCert;

  AccountIdentity._({
    required this.accountEdPub,
    required this.accountEdSeed,
    this.accountMlPub,
    required this.deviceEdSeed,
    required this.deviceXSeed,
    required this.deviceEdPub,
    required this.deviceXPub,
    required this.deviceId,
    required this.deviceCert,
  });

  bool get holdsAccountRoot => accountEdSeed != null;

  /// This device's relay mailbox.
  Future<String> routingId() async => b64url(await sha256Bytes(deviceEdPub));

  /// Stable account id.
  Future<String> accountId() async => b64url(await sha256Bytes(accountEdPub));

  static Future<DeviceCertificate> _signCert({
    required Uint8List accountEdSeed,
    required Uint8List deviceEdPub,
    required Uint8List deviceXPub,
    required String deviceId,
  }) async {
    final kp = await _ed.newKeyPairFromSeed(accountEdSeed);
    final sig = await _ed.sign(
      DeviceCertificate.signingInput(deviceEdPub, deviceXPub, deviceId),
      keyPair: kp,
    );
    return DeviceCertificate(
      deviceEdPub: deviceEdPub,
      deviceXPub: deviceXPub,
      deviceId: deviceId,
      sig: Uint8List.fromList(sig.bytes),
    );
  }

  /// Create a brand-new account (this becomes device #1, whose device key IS
  /// the account key — so a one-device account code matches the v1 shape).
  static Future<AccountIdentity> generate() async {
    final accountEdSeed = randomBytes(32);
    final deviceXSeed = randomBytes(32);
    final deviceId = b64url(randomBytes(9));
    final accountEdPub = await _edPubFromSeed(accountEdSeed);
    final deviceXPub = await _xPubFromSeed(deviceXSeed);
    final cert = await _signCert(
      accountEdSeed: accountEdSeed,
      deviceEdPub: accountEdPub, // device #1 == account key
      deviceXPub: deviceXPub,
      deviceId: deviceId,
    );
    return AccountIdentity._(
      accountEdPub: accountEdPub,
      accountEdSeed: accountEdSeed,
      deviceEdSeed: accountEdSeed,
      deviceXSeed: deviceXSeed,
      deviceEdPub: accountEdPub,
      deviceXPub: deviceXPub,
      deviceId: deviceId,
      deviceCert: cert,
    );
  }

  /// Migrate a v1 [ZIdentity] in place: the old Ed25519 becomes the account key
  /// AND device #1's key (routing id unchanged), and the old X25519 stays as
  /// device #1's ratchet key (existing sessions keep working).
  static Future<AccountIdentity> fromV1(ZIdentity old,
      {String? deviceId}) async {
    final id = deviceId ?? b64url(randomBytes(9));
    final cert = await _signCert(
      accountEdSeed: old.edSeed,
      deviceEdPub: old.edPub,
      deviceXPub: old.xPub,
      deviceId: id,
    );
    return AccountIdentity._(
      accountEdPub: old.edPub,
      accountEdSeed: old.edSeed,
      deviceEdSeed: old.edSeed,
      deviceXSeed: old.xSeed,
      deviceEdPub: old.edPub,
      deviceXPub: old.xPub,
      deviceId: id,
      deviceCert: cert,
    );
  }

  /// Sign an account-wide device list (M4): the authenticated statement of
  /// which devices make up this account, at a monotonic [version]. Contacts
  /// verify it against the account key and update their fan-out set. Requires
  /// the account root.
  ///
  /// Dual-signed (`sig` and `sig2`) unless [v2Only] (ADR 0017 stage 2b), which
  /// signs `sig3` alone instead. It defaults to [devlistSignV2Only] — off — and
  /// the app passes it explicitly, so that a test can turn it on for one
  /// account.
  Future<SignedDeviceList> signDeviceList(
      List<DeviceCertificate> devices, int version,
      {bool v2Only = devlistSignV2Only}) async {
    final seed = accountEdSeed;
    if (seed == null) {
      throw StateError('this device does not hold the account root');
    }
    final kp = await _ed.newKeyPairFromSeed(seed);
    if (v2Only) {
      // Stage 2: one signature, over an input no dual-signed list is ever
      // signed over (see [SignedDeviceList.signingInputV3] for why).
      final sig3 = await _ed.sign(
        SignedDeviceList.signingInputV3(version, devices),
        keyPair: kp,
      );
      return SignedDeviceList(
        accountEdPub: accountEdPub,
        version: version,
        devices: devices,
        sig3: Uint8List.fromList(sig3.bytes),
      );
    }
    // ADR 0010: dual-sign. `sig` (v1) keeps a pre-0010 contact verifying; `sig2`
    // covers the ratchet keys and ids too, and its presence makes this a v2
    // list, which the floor rule then requires.
    final sig = await _ed.sign(
      SignedDeviceList.signingInput(version, devices),
      keyPair: kp,
    );
    final sig2 = await _ed.sign(
      SignedDeviceList.signingInputV2(version, devices),
      keyPair: kp,
    );
    return SignedDeviceList(
      accountEdPub: accountEdPub,
      version: version,
      devices: devices,
      sig: Uint8List.fromList(sig.bytes),
      sig2: Uint8List.fromList(sig2.bytes),
    );
  }

  /// Sign a certificate for another (newly enrolling) device. Requires this
  /// device to hold the account root. Used by the enrollment ceremony (M3).
  Future<DeviceCertificate> signDeviceCert({
    required Uint8List deviceEdPub,
    required Uint8List deviceXPub,
    required String deviceId,
  }) async {
    final seed = accountEdSeed;
    if (seed == null) {
      throw StateError('this device does not hold the account root');
    }
    return _signCert(
      accountEdSeed: seed,
      deviceEdPub: deviceEdPub,
      deviceXPub: deviceXPub,
      deviceId: deviceId,
    );
  }

  /// A copy carrying the account's ML-DSA public key. Used when handing an
  /// enrollment to a new device: the key is public, so it travels even though
  /// the account root does not, and without it the new device would have no
  /// account post-quantum identity to show (§18).
  AccountIdentity withAccountMlPub(Uint8List mlPub) => AccountIdentity._(
        accountEdPub: accountEdPub,
        accountEdSeed: accountEdSeed,
        accountMlPub: mlPub,
        deviceEdSeed: deviceEdSeed,
        deviceXSeed: deviceXSeed,
        deviceEdPub: deviceEdPub,
        deviceXPub: deviceXPub,
        deviceId: deviceId,
        deviceCert: deviceCert,
      );

  /// Build the newly-enrolled device's local identity from material handed to
  /// it during the ceremony. [accountEdSeed] is optional — pass it only if the
  /// new device should also be able to enroll further devices;
  /// [accountMlPub] is public and should always be passed when the host has
  /// one, or the new device has no account post-quantum identity (§18.2).
  static Future<AccountIdentity> fromEnrollment({
    required Uint8List accountEdPub,
    Uint8List? accountEdSeed,
    Uint8List? accountMlPub,
    required Uint8List deviceEdSeed,
    required Uint8List deviceXSeed,
    required String deviceId,
    required DeviceCertificate deviceCert,
  }) async {
    return AccountIdentity._(
      accountEdPub: accountEdPub,
      accountEdSeed: accountEdSeed,
      accountMlPub: accountMlPub,
      deviceEdSeed: deviceEdSeed,
      deviceXSeed: deviceXSeed,
      deviceEdPub: await _edPubFromSeed(deviceEdSeed),
      deviceXPub: await _xPubFromSeed(deviceXSeed),
      deviceId: deviceId,
      deviceCert: deviceCert,
    );
  }

  /// The public account bundle to share as a contact code. Pass the other
  /// devices' certs (learned via the device list) to advertise the full set;
  /// with none, this is a one-device bundle.
  AccountBundle toAccountBundle({
    String? displayName,
    List<DeviceCertificate> otherDevices = const [],
  }) {
    return AccountBundle(
      accountEdPub: accountEdPub,
      devices: [deviceCert, ...otherDevices],
      displayName: displayName,
    );
  }

  Map<String, Object?> toJson() => {
        'accountEdPub': b64(accountEdPub),
        if (accountEdSeed != null) 'accountEdSeed': b64(accountEdSeed!),
        if (accountMlPub != null) 'accountMlPub': b64(accountMlPub!),
        'deviceEdSeed': b64(deviceEdSeed),
        'deviceXSeed': b64(deviceXSeed),
        'deviceId': deviceId,
        'deviceCert': deviceCert.toJson(),
      };

  static Future<AccountIdentity> fromJson(Map<String, Object?> j) async {
    final deviceEdSeed = unb64(j['deviceEdSeed'] as String);
    final deviceXSeed = unb64(j['deviceXSeed'] as String);
    return AccountIdentity._(
      accountEdPub: unb64(j['accountEdPub'] as String),
      accountEdSeed: j['accountEdSeed'] == null
          ? null
          : unb64(j['accountEdSeed'] as String),
      accountMlPub:
          j['accountMlPub'] == null ? null : unb64(j['accountMlPub'] as String),
      deviceEdSeed: deviceEdSeed,
      deviceXSeed: deviceXSeed,
      deviceEdPub: await _edPubFromSeed(deviceEdSeed),
      deviceXPub: await _xPubFromSeed(deviceXSeed),
      deviceId: j['deviceId'] as String,
      deviceCert: DeviceCertificate.fromJson(
          (j['deviceCert'] as Map).cast<String, Object?>()),
    );
  }
}

/// An account-signed statement of the account's device set at a monotonic
/// [version]. A contact keeps the highest version it has seen and fans messages
/// out to exactly these devices.
class SignedDeviceList {
  final Uint8List accountEdPub;
  final int version;
  final List<DeviceCertificate> devices;

  /// The account Ed25519 signature over [signingInput], the frozen v1 format.
  /// Alone on a list from before ADR 0010, and beside [sig2] on every list
  /// signed until the stage-2 signer is switched on (ADR 0017). A v2-only list
  /// carries neither: its one signature is [sig3].
  final Uint8List? sig;

  /// The account Ed25519 signature over [signingInputV2] — the v2 format that
  /// also covers each device's X25519 ratchet key and id (ADR 0010). Never
  /// alone: it is made beside [sig], on every dual-signed list, and a list that
  /// carries it without [sig] is a dual-signed list with its v1 signature
  /// deleted, which [verify] refuses. Its presence makes a list a "v2 list" for
  /// the floor (the app refuses a later version from an account without it);
  /// verifying what is present here and requiring what the floor demands there
  /// is the split ADR 0010 draws.
  final Uint8List? sig2;

  /// The account Ed25519 signature over [signingInputV3], and the only
  /// signature a v2-only list carries (ADR 0017 stage 2). Never beside [sig]
  /// or [sig2]: a list that carries it with either is refused.
  final Uint8List? sig3;

  SignedDeviceList({
    required this.accountEdPub,
    required this.version,
    required this.devices,
    this.sig,
    this.sig2,
    this.sig3,
  });

  /// The three shapes a list can have, and the only three (ADR 0017):
  ///
  ///  * `{sig}` — a list from before ADR 0010;
  ///  * `{sig, sig2}` — dual-signed: every list signed until the stage-2
  ///    signer is switched on;
  ///  * `{sig3}` — v2-only (stage 2).
  ///
  /// Anything else is malformed, and [verify] refuses it before it checks a
  /// signature: no signature at all; `sig2` alone, which is what deleting `sig`
  /// from any dual-signed list leaves; `sig3` beside `sig` or `sig2`. The shape
  /// is checked, not inferred, because a reader must not be able to turn one
  /// shape into another by taking something away. (On the wire a member is
  /// present or absent; a `null` one does not parse at all — [fromJson].)
  bool get hasValidShape {
    if (sig3 != null) return sig == null && sig2 == null;
    return sig != null;
  }

  /// Signed with `sig3` and nothing else: a stage-2, v2-only list (ADR 0017).
  /// A list carrying `sig2` alone is not one — see [hasValidShape].
  bool get isV2Only => sig3 != null && sig == null && sig2 == null;

  static Uint8List signingInput(int version, List<DeviceCertificate> devices) {
    final eds = [for (final d in devices) d.deviceEdPub]..sort(_lexCompare);
    return concatBytes([
      utf8.encode('z-devlist-v1:'),
      utf8.encode('$version:'),
      for (final e in eds) e,
    ]);
  }

  /// The v2 signing input (ADR 0010): like [signingInput], but each device
  /// contributes its X25519 ratchet key and id as well as its Ed25519 key, so
  /// the signature — and the fingerprint derived from it — commit to the keys
  /// contacts actually open ratchets to. Devices are ordered by their Ed25519
  /// key, as in v1; within a device the id is length-prefixed with a u16 because
  /// it is variable and is not the last field of its element.
  static Uint8List signingInputV2(
          int version, List<DeviceCertificate> devices) =>
      _v2Content('z-devlist-v2:', version, devices);

  /// The input a v2-only list's [sig3] is made over (ADR 0017 stage 2): byte
  /// for byte the content of [signingInputV2] — the version, then each
  /// device's Ed25519 key, ratchet key and length-prefixed id, in the same
  /// order — under the context `z-devlist-v3:` instead of `z-devlist-v2:`.
  ///
  /// Why a context of its own. A list with one signature must not be
  /// obtainable from a list with two by taking one away. `sig2` is made beside
  /// `sig`, over the v2 input; were a v2-only list signed over those same
  /// bytes, deleting `sig` from ANY dual-signed list the account ever signed
  /// would leave a list that verifies — fingerprinted over a different input
  /// from the one every other reader holds for that version, and lifting a
  /// contact's floor to a level the account never reached. Deleting is within
  /// reach of anyone who passes a list on, the transparency-log operator
  /// included: a log value is sealed under a key derived from the account's
  /// PUBLIC key (§19.1), so the operator can open one, delete `sig` and seal
  /// it again. Under `z-devlist-v3:` nothing signed for a dual-signed list
  /// verifies alone, and a `sig2` moved into `sig3` does not verify either.
  ///
  /// Why this string. It keeps the `z-devlist-vN:` form of the other two
  /// inputs, so the three differ in one byte at the same offset and no input
  /// of one kind can equal an input of another; no other context the account
  /// key signs begins with `z-devlist-`. The "v3" counts the inputs a list is
  /// signed over, not formats of its content: the content is v2's.
  static Uint8List signingInputV3(
          int version, List<DeviceCertificate> devices) =>
      _v2Content('z-devlist-v3:', version, devices);

  static Uint8List _v2Content(
      String context, int version, List<DeviceCertificate> devices) {
    final sorted = [...devices]
      ..sort((a, b) => _lexCompare(a.deviceEdPub, b.deviceEdPub));
    return concatBytes([
      utf8.encode(context),
      utf8.encode('$version:'),
      for (final d in sorted) ...[
        d.deviceEdPub,
        d.deviceXPub,
        u16be(utf8.encode(d.deviceId).length),
        utf8.encode(d.deviceId),
      ],
    ]);
  }

  /// What this list commits to: the bytes its fingerprint is taken over, and
  /// the bytes the account's ML-DSA signature over it (§18.9) is made over.
  /// **The rule, written down once** — [fingerprint] here and
  /// `_devlistSigningInputFor` in `identity_v3.dart` both take it from this
  /// getter and from nowhere else (ADR 0017):
  ///
  /// > The fingerprint and the ML-DSA input follow the strongest signature
  /// > that is *alone*: v1 while a v1 signature is produced; once it is not,
  /// > the input of the one signature the list carries.
  ///
  /// So a list that carries `sig` — `{sig}` from before ADR 0010, or
  /// `{sig, sig2}`, every list signed until the stage-2 signer is on — commits
  /// to [signingInput], and a v2-only list, `{sig3}`, commits to
  /// [signingInputV3], which also names each device's ratchet key and id.
  ///
  /// It is the presence of the v1 signature that decides, because of who else
  /// reads the list. A client from before ADR 0010 admits a list on `sig`,
  /// knows only the v1 input, and fingerprints it and checks its ML-DSA over
  /// that. For as long as a list is signed so that such a client can read it,
  /// every reader has to commit to the bytes that client does, or the two hold
  /// one list at one version and disagree about its fingerprint — which each is
  /// built to treat as an attack (the mixed-version P0). A v2-only list is one
  /// that client cannot read at all, so nothing is lost by committing to the
  /// wider input there, and that is where the ratchet-key commitment ADR 0010
  /// asked for takes effect. The rule reads only the list itself, so two
  /// parties holding the same bytes always agree.
  ///
  /// A list in no valid shape ([hasValidShape]) commits to nothing: [verify]
  /// refuses it, `HybridDeviceListSignature.verifies` refuses it too, and no
  /// reader computes anything from a list it has not admitted. (This getter
  /// returns the v1 input for one; nothing uses it.)
  Uint8List get commitmentInput => isV2Only
      ? signingInputV3(version, devices)
      : signingInput(version, devices);

  /// A short (16-byte) commitment to this list: the first half of the SHA-256
  /// of [commitmentInput]. Two parties holding the same list compute the same
  /// value however each of them learned it. This is the value gossiped for
  /// device-list transparency (7.7a) and the fingerprint a log leaf commits to
  /// (7.7b, §19).
  ///
  /// For every list signed before the stage-2 signer is on that is the v1
  /// fingerprint — every such list carries `sig` — and a v2-only list reports
  /// [deviceListFingerprintV3], which also moves when a device's ratchet key
  /// does. While the fingerprint is held at v1 the ratchet keys are still
  /// covered where a list is admitted or refused: a present [sig2] must verify
  /// in [verify].
  Future<Uint8List> fingerprint() async =>
      Uint8List.sublistView(await sha256Bytes(commitmentInput), 0, 16);

  Future<List<String>> routingIds() async =>
      [for (final d in devices) await d.routingId()];

  /// Whether the account signed this list: it has one of the three shapes
  /// ([hasValidShape]), every certificate verifies under the account key, and
  /// so does every signature the list carries, each over its own input — `sig`
  /// over [signingInput], `sig2` over [signingInputV2], `sig3` over
  /// [signingInputV3]. On a dual-signed list BOTH must verify, so a forged
  /// `sig2` cannot ride beside a genuine `sig`.
  ///
  /// The shape comes first, and it is what refuses a dual-signed list with
  /// `sig` deleted: the `sig2` left behind is genuine and verifies over its
  /// input, so no signature check could.
  ///
  /// Which of the valid shapes an account may still send is not decided here.
  /// That is the floor in the app (`cdev_sigfloor_`, and its third level): a
  /// policy about what this reader has already seen from the account, not a
  /// fact about the signatures in front of it.
  Future<bool> verify() async {
    if (accountEdPub.length != 32 || devices.isEmpty) return false;
    if (!hasValidShape) return false;
    for (final d in devices) {
      if (!await d.verify(accountEdPub)) return false;
    }
    final s1 = sig, s2 = sig2, s3 = sig3;
    try {
      final key = SimplePublicKey(accountEdPub, type: KeyPairType.ed25519);
      if (s1 != null &&
          !await _ed.verify(signingInput(version, devices),
              signature: Signature(s1, publicKey: key))) {
        return false;
      }
      if (s2 != null &&
          !await _ed.verify(signingInputV2(version, devices),
              signature: Signature(s2, publicKey: key))) {
        return false;
      }
      if (s3 != null &&
          !await _ed.verify(signingInputV3(version, devices),
              signature: Signature(s3, publicKey: key))) {
        return false;
      }
      return true;
    } catch (_) {
      return false;
    }
  }

  Map<String, Object?> toJson() => {
        'acct': b64(accountEdPub),
        'ver': version,
        'devs': [for (final d in devices) d.toJson()],
        if (sig != null) 'sig': b64(sig!),
        if (sig2 != null) 'sig2': b64(sig2!),
        if (sig3 != null) 'sig3': b64(sig3!),
      };

  /// Parses a list from its JSON. A signature member is either absent or a
  /// base64 string; one that is present with any other value — `null`
  /// included — makes the list malformed, and this throws a
  /// [FormatException] (§3.4). Absent and `null` are not the same thing here:
  /// were a `null` member read as absent, `{sig, sig2, "sig3": null}` would
  /// be admitted as dual-signed and `{"sig": null, sig3}` as v2-only, while a
  /// reader that goes by which members are present refuses both — two
  /// readers of one list reaching two answers. Every reader handed a list it
  /// did not write catches the exception and treats the list as refused.
  static SignedDeviceList fromJson(Map<String, Object?> j) => SignedDeviceList(
        accountEdPub: unb64(j['acct'] as String),
        version: (j['ver'] as num).toInt(),
        devices: [
          for (final d in (j['devs'] as List))
            DeviceCertificate.fromJson((d as Map).cast<String, Object?>())
        ],
        // A v2-only list has no `sig`. Every build before stage 2a cast this
        // member to a String unconditionally, so such a list does not even
        // parse there — the reason the flip waits for those builds to be gone.
        sig: _signatureMember(j, 'sig'),
        sig2: _signatureMember(j, 'sig2'),
        sig3: _signatureMember(j, 'sig3'),
      );

  static Uint8List? _signatureMember(Map<String, Object?> j, String key) {
    if (!j.containsKey(key)) return null;
    final value = j[key];
    if (value is! String) {
      throw FormatException(
          'device list member "$key" is present but not a signature');
    }
    return unb64(value);
  }
}

/// The device-list fingerprint for an arbitrary (version, device set), without
/// needing a signed list in hand — used to compute the baseline fingerprint of
/// a one-device account (version 1 over its single device) and to verify a
/// gossiped claim. See [SignedDeviceList.fingerprint].
Future<Uint8List> deviceListFingerprint(
        int version, List<DeviceCertificate> devices) async =>
    Uint8List.sublistView(
        await sha256Bytes(SignedDeviceList.signingInput(version, devices)),
        0,
        16);

/// The v2 device-list fingerprint (ADR 0010): the same truncated SHA-256, over
/// [SignedDeviceList.signingInputV2], so it moves when a device's X25519 key or
/// id does — the substitution the v1 fingerprint was blind to. What clients
/// between ADR 0010 and ADR 0017 reported for a list carrying `sig2`; no list
/// reports it now — one that carries `sig` reports [deviceListFingerprint], a
/// v2-only one [deviceListFingerprintV3].
Future<Uint8List> deviceListFingerprintV2(
        int version, List<DeviceCertificate> devices) async =>
    Uint8List.sublistView(
        await sha256Bytes(SignedDeviceList.signingInputV2(version, devices)),
        0,
        16);

/// The fingerprint a v2-only list reports (ADR 0017 stage 2): the same
/// truncated SHA-256, over [SignedDeviceList.signingInputV3]. It moves with a
/// device's ratchet key or id, as the v2 one does, and differs from every v1
/// and v2 fingerprint of the same version and set.
Future<Uint8List> deviceListFingerprintV3(
        int version, List<DeviceCertificate> devices) async =>
    Uint8List.sublistView(
        await sha256Bytes(SignedDeviceList.signingInputV3(version, devices)),
        0,
        16);

int _lexCompare(Uint8List a, Uint8List b) {
  for (var i = 0; i < a.length && i < b.length; i++) {
    if (a[i] != b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}
