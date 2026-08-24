import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'multidevice.dart';
import 'util.dart';

/// Relay-mediated device pairing — cryptographic core (M3).
///
/// A NEW device and an EXISTING device meet at a one-time rendezvous on the
/// relay (derived from a short [PairingCode] the user transcribes), exchange
/// ephemeral X25519 keys, and derive a channel key plus a Short Authentication
/// String (SAS). The user compares the SAS on both screens: a machine-in-the-
/// middle would see a different ephemeral key on each side and therefore a
/// different SAS, so a match rules the attacker out. The existing device then
/// signs the new device's [DeviceCertificate] and seals the enrollment payload
/// (account key + contacts) to the channel.
///
/// This file is transport-agnostic: it produces/consumes the wire maps and the
/// sealed bytes; how they travel over the relay (the rendezvous choreography)
/// and the UI live in the app layer.

const String _rendezvousCtx = 'z-pair-rendezvous-v1:';
const String _channelCtx = 'z-pair-channel-v1';
const String _sasCtx = 'z-pair-sas-v1';

final _x = X25519();
final _aead = Chacha20.poly1305Aead();

const String _b32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

String _base32Encode(Uint8List data) {
  final sb = StringBuffer();
  var buffer = 0, bits = 0;
  for (final b in data) {
    buffer = (buffer << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      sb.write(_b32Alphabet[(buffer >> bits) & 0x1f]);
    }
  }
  if (bits > 0) sb.write(_b32Alphabet[(buffer << (5 - bits)) & 0x1f]);
  return sb.toString();
}

Uint8List _base32Decode(String s) {
  var buffer = 0, bits = 0;
  final out = <int>[];
  for (final ch in s.toUpperCase().codeUnits) {
    final v = _b32Alphabet.indexOf(String.fromCharCode(ch));
    if (v < 0) continue; // skip separators / whitespace
    buffer = (buffer << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.add((buffer >> bits) & 0xff);
    }
  }
  return Uint8List.fromList(out);
}

Future<Uint8List> _dh(Uint8List seed, Uint8List remotePub) async {
  final kp = await _x.newKeyPairFromSeed(seed);
  final secret = await _x.sharedSecretKey(
    keyPair: kp,
    remotePublicKey: SimplePublicKey(remotePub, type: KeyPairType.x25519),
  );
  return Uint8List.fromList(await secret.extractBytes());
}

bool _lexLess(Uint8List a, Uint8List b) {
  for (var i = 0; i < a.length && i < b.length; i++) {
    if (a[i] != b[i]) return a[i] < b[i];
  }
  return a.length < b.length;
}

/// A one-time code the user reads off the new device and enters on the
/// existing one. It provides rendezvous and guess-resistance only; the SAS is
/// what actually defeats a man-in-the-middle.
class PairingCode {
  final Uint8List secret; // 10 bytes → 16 base32 chars

  PairingCode(this.secret);

  static PairingCode generate() => PairingCode(randomBytes(10));

  /// Grouped, upper-case, easy to read aloud/type (e.g. `ABCDE-FGHIJ-KLMNO-P`).
  String get text {
    final raw = _base32Encode(secret);
    final groups = <String>[];
    for (var i = 0; i < raw.length; i += 5) {
      groups.add(raw.substring(i, i + 5 > raw.length ? raw.length : i + 5));
    }
    return groups.join('-');
  }

  static PairingCode parse(String code) {
    final secret = _base32Decode(code);
    if (secret.length < 8) throw const FormatException('pairing code too short');
    return PairingCode(Uint8List.fromList(secret.sublist(0, 10)));
  }

  /// The relay mailbox both sides use to find each other.
  Future<String> rendezvousRoutingId() async => b64url(await sha256Bytes(
      concatBytes([utf8.encode(_rendezvousCtx), secret])));
}

/// What the new device ends up installing.
class EnrollmentData {
  final Uint8List accountEdPub;
  final Uint8List? accountEdSeed; // present iff the new device may enroll others
  final List<AccountBundle> contacts;
  final String? displayName;
  final DeviceCertificate deviceCert; // this (new) device's cert
  final DeviceCertificate hostDeviceCert; // the existing device that linked us

  EnrollmentData({
    required this.accountEdPub,
    required this.accountEdSeed,
    required this.contacts,
    required this.displayName,
    required this.deviceCert,
    required this.hostDeviceCert,
  });
}

/// A completed handshake: the channel key + SAS both sides derive. The existing
/// device also carries the new device's identifiers here, to sign its cert.
class PairingSession {
  final Uint8List channelKey;
  final String sas;
  final Uint8List? peerDeviceEdPub; // set on the existing (responder) side
  final Uint8List? peerDeviceXPub;
  final String? peerDeviceId;

  PairingSession({
    required this.channelKey,
    required this.sas,
    this.peerDeviceEdPub,
    this.peerDeviceXPub,
    this.peerDeviceId,
  });

  Future<Uint8List> _seal(Uint8List plain) async {
    final box = await _aead.encrypt(plain,
        secretKey: SecretKey(channelKey), nonce: _aead.newNonce());
    return Uint8List.fromList(box.concatenation());
  }

  Future<Uint8List> _open(Uint8List sealed) async {
    final box = SecretBox.fromConcatenation(sealed, nonceLength: 12, macLength: 16);
    final clear = await _aead.decrypt(box, secretKey: SecretKey(channelKey));
    return Uint8List.fromList(clear);
  }

  /// The certificate this (existing) device signs for the peer being enrolled —
  /// so the host can remember the device it just linked.
  Future<DeviceCertificate> signedPeerCert(AccountIdentity me) async {
    if (peerDeviceEdPub == null) {
      throw StateError('this side has no peer device info to enroll');
    }
    return me.signDeviceCert(
      deviceEdPub: peerDeviceEdPub!,
      deviceXPub: peerDeviceXPub!,
      deviceId: peerDeviceId!,
    );
  }

  /// EXISTING device: sign the new device's cert and seal the enrollment blob.
  Future<Uint8List> sealEnrollment(
    AccountIdentity me, {
    required List<AccountBundle> contacts,
    required bool includeAccountRoot,
    String? displayName,
  }) async {
    final cert = await signedPeerCert(me);
    final root = includeAccountRoot ? me.accountEdSeed : null;
    final payload = <String, Object?>{
      'acct': b64(me.accountEdPub),
      if (root != null) 'root': b64(root),
      'name': displayName,
      'cert': cert.toJson(),
      'hostcert': me.deviceCert.toJson(),
      'contacts': [for (final c in contacts) c.toJson()],
    };
    return _seal(Uint8List.fromList(utf8.encode(jsonEncode(payload))));
  }

  /// NEW device: open the enrollment blob.
  Future<EnrollmentData> openEnrollment(Uint8List sealed) async {
    final j = jsonDecode(utf8.decode(await _open(sealed))) as Map<String, Object?>;
    return EnrollmentData(
      accountEdPub: unb64(j['acct'] as String),
      accountEdSeed: j['root'] == null ? null : unb64(j['root'] as String),
      displayName: j['name'] as String?,
      deviceCert:
          DeviceCertificate.fromJson((j['cert'] as Map).cast<String, Object?>()),
      hostDeviceCert: DeviceCertificate.fromJson(
          (j['hostcert'] as Map).cast<String, Object?>()),
      contacts: [
        for (final c in (j['contacts'] as List))
          AccountBundle.fromJson((c as Map).cast<String, Object?>())
      ],
    );
  }
}

Future<Uint8List> _deriveChannelKey(Uint8List dh) async {
  final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
  final k = await hkdf.deriveKey(
    secretKey: SecretKey(dh),
    nonce: Uint8List(32),
    info: utf8.encode(_channelCtx),
  );
  return Uint8List.fromList(await k.extractBytes());
}

/// SAS binds both ephemeral keys and the new device's identity key, so a MITM
/// (different ephemeral on each leg) yields a different string on each screen.
Future<String> _deriveSas(
    Uint8List dh, Uint8List ephA, Uint8List ephB, Uint8List deviceEdPub) async {
  final lo = _lexLess(ephA, ephB) ? ephA : ephB;
  final hi = identical(lo, ephA) ? ephB : ephA;
  final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 8);
  final k = await hkdf.deriveKey(
    secretKey: SecretKey(dh),
    nonce: concatBytes([lo, hi]),
    info: concatBytes([utf8.encode(_sasCtx), deviceEdPub]),
  );
  final b = await k.extractBytes();
  final n = ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) & 0x7fffffff;
  final digits = (n % 1000000).toString().padLeft(6, '0');
  return '${digits.substring(0, 3)} ${digits.substring(3)}';
}

/// NEW device. Generates its permanent device keys and a pairing ephemeral.
class PairingInitiator {
  final PairingCode code;
  final Uint8List deviceEdSeed, deviceXSeed, deviceEdPub, deviceXPub;
  final String deviceId;
  final Uint8List ephXSeed, ephXPub;

  PairingInitiator._(this.code, this.deviceEdSeed, this.deviceXSeed,
      this.deviceEdPub, this.deviceXPub, this.deviceId, this.ephXSeed,
      this.ephXPub);

  static Future<PairingInitiator> create(
      {PairingCode? code, String? deviceId}) async {
    final edSeed = randomBytes(32);
    final xSeed = randomBytes(32);
    final ephSeed = randomBytes(32);
    final edPub =
        Uint8List.fromList((await (await Ed25519().newKeyPairFromSeed(edSeed))
                .extractPublicKey())
            .bytes);
    final xPub = Uint8List.fromList(
        (await (await _x.newKeyPairFromSeed(xSeed)).extractPublicKey()).bytes);
    final ephPub = Uint8List.fromList(
        (await (await _x.newKeyPairFromSeed(ephSeed)).extractPublicKey()).bytes);
    return PairingInitiator._(
      code ?? PairingCode.generate(),
      edSeed, xSeed, edPub, xPub,
      deviceId ?? b64url(randomBytes(9)),
      ephSeed, ephPub,
    );
  }

  /// Message the new device publishes to the rendezvous.
  Map<String, Object?> hello() => {
        'ephx': b64(ephXPub),
        'ded': b64(deviceEdPub),
        'dx': b64(deviceXPub),
        'id': deviceId,
      };

  /// Derive the shared session from the existing device's reply.
  Future<PairingSession> complete(Map<String, Object?> responderReply) async {
    final theirEph = unb64(responderReply['ephx'] as String);
    final dh = await _dh(ephXSeed, theirEph);
    return PairingSession(
      channelKey: await _deriveChannelKey(dh),
      sas: await _deriveSas(dh, ephXPub, theirEph, deviceEdPub),
    );
  }

  /// After the SAS matches and the sealed blob arrives, build the local
  /// account identity for this newly-linked device.
  Future<AccountIdentity> install(
      PairingSession session, Uint8List sealed) async {
    return installFromData(await session.openEnrollment(sealed));
  }

  /// Build the local identity from already-opened enrollment data. Verifies the
  /// certificate is for OUR device keys and signed by the account we joined.
  Future<AccountIdentity> installFromData(EnrollmentData data) async {
    final okKeys = _eq(data.deviceCert.deviceEdPub, deviceEdPub) &&
        _eq(data.deviceCert.deviceXPub, deviceXPub);
    if (!okKeys || !await data.deviceCert.verify(data.accountEdPub)) {
      throw const FormatException('enrollment certificate did not verify');
    }
    return AccountIdentity.fromEnrollment(
      accountEdPub: data.accountEdPub,
      accountEdSeed: data.accountEdSeed,
      deviceEdSeed: deviceEdSeed,
      deviceXSeed: deviceXSeed,
      deviceId: deviceId,
      deviceCert: data.deviceCert,
    );
  }
}

/// EXISTING device. Consumes the new device's hello and produces the reply +
/// the shared session (which also carries the new device's identifiers).
class PairingResponder {
  static Future<(Map<String, Object?>, PairingSession)> respond(
      Map<String, Object?> hello) async {
    final theirEph = unb64(hello['ephx'] as String);
    final deviceEdPub = unb64(hello['ded'] as String);
    final ephSeed = randomBytes(32);
    final ephPub = Uint8List.fromList(
        (await (await _x.newKeyPairFromSeed(ephSeed)).extractPublicKey()).bytes);
    final dh = await _dh(ephSeed, theirEph);
    final session = PairingSession(
      channelKey: await _deriveChannelKey(dh),
      sas: await _deriveSas(dh, theirEph, ephPub, deviceEdPub),
      peerDeviceEdPub: deviceEdPub,
      peerDeviceXPub: unb64(hello['dx'] as String),
      peerDeviceId: hello['id'] as String,
    );
    return ({'ephx': b64(ephPub)}, session);
  }
}

bool _eq(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
