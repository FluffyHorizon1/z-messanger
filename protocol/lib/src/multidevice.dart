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
  final Uint8List deviceEdSeed;
  final Uint8List deviceXSeed;
  final Uint8List deviceEdPub;
  final Uint8List deviceXPub;
  final String deviceId;
  final DeviceCertificate deviceCert;

  AccountIdentity._({
    required this.accountEdPub,
    required this.accountEdSeed,
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
  Future<SignedDeviceList> signDeviceList(
      List<DeviceCertificate> devices, int version) async {
    final seed = accountEdSeed;
    if (seed == null) {
      throw StateError('this device does not hold the account root');
    }
    final kp = await _ed.newKeyPairFromSeed(seed);
    final sig = await _ed.sign(
      SignedDeviceList.signingInput(version, devices),
      keyPair: kp,
    );
    return SignedDeviceList(
      accountEdPub: accountEdPub,
      version: version,
      devices: devices,
      sig: Uint8List.fromList(sig.bytes),
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

  /// Build the newly-enrolled device's local identity from material handed to
  /// it during the ceremony. [accountEdSeed] is optional — pass it only if the
  /// new device should also be able to enroll further devices.
  static Future<AccountIdentity> fromEnrollment({
    required Uint8List accountEdPub,
    Uint8List? accountEdSeed,
    required Uint8List deviceEdSeed,
    required Uint8List deviceXSeed,
    required String deviceId,
    required DeviceCertificate deviceCert,
  }) async {
    return AccountIdentity._(
      accountEdPub: accountEdPub,
      accountEdSeed: accountEdSeed,
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
  final Uint8List sig;

  SignedDeviceList({
    required this.accountEdPub,
    required this.version,
    required this.devices,
    required this.sig,
  });

  static Uint8List signingInput(int version, List<DeviceCertificate> devices) {
    final eds = [for (final d in devices) d.deviceEdPub]..sort(_lexCompare);
    return concatBytes([
      utf8.encode('z-devlist-v1:'),
      utf8.encode('$version:'),
      for (final e in eds) e,
    ]);
  }

  Future<List<String>> routingIds() async =>
      [for (final d in devices) await d.routingId()];

  Future<bool> verify() async {
    if (accountEdPub.length != 32 || devices.isEmpty) return false;
    for (final d in devices) {
      if (!await d.verify(accountEdPub)) return false;
    }
    try {
      return await _ed.verify(
        signingInput(version, devices),
        signature: Signature(sig,
            publicKey:
                SimplePublicKey(accountEdPub, type: KeyPairType.ed25519)),
      );
    } catch (_) {
      return false;
    }
  }

  Map<String, Object?> toJson() => {
        'acct': b64(accountEdPub),
        'ver': version,
        'devs': [for (final d in devices) d.toJson()],
        'sig': b64(sig),
      };

  static SignedDeviceList fromJson(Map<String, Object?> j) => SignedDeviceList(
        accountEdPub: unb64(j['acct'] as String),
        version: (j['ver'] as num).toInt(),
        devices: [
          for (final d in (j['devs'] as List))
            DeviceCertificate.fromJson((d as Map).cast<String, Object?>())
        ],
        sig: unb64(j['sig'] as String),
      );
}

int _lexCompare(Uint8List a, Uint8List b) {
  for (var i = 0; i < a.length && i < b.length; i++) {
    if (a[i] != b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}
