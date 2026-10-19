import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'identity.dart';
import 'intro_key.dart' show mlKemEncapsulationKeyValid, sealKeyHash;
import 'multidevice.dart';
import 'pq.dart'
    show pqCtLength, pqDecapsulate, pqEkLength, pqEncapsulate, pqGenerate;
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

// v2 (§10.1). Disjoint context strings, so nothing existing computes anything
// differently and a v1 implementation cannot be talked into a v2 ceremony or
// the reverse: the two run on different rendezvous mailboxes and derive
// different keys from the same code.
const String _rendezvousCtxV2 = 'z-pair-rendezvous-v2:';
const String _channelCtxV2 = 'z-pair-channel-v2';
const String _sasCtxV2 = 'z-pair-sas-v2';
const String _commitCtxV2 = 'z-pair-commit-v2:';

// v3 (§10.2, ADR 0033 §3): the channel and the digits are hybrid with
// ML-KEM-768, and the code is bound into the keys. Every context is new
// again, so v3 shares no mailbox, no key and no string with v2 or v1 for one
// code.
const String _rendezvousCtxV3 = 'z-pair-rendezvous-v3:';
const String _pairKeyCtxV3 = 'z-pair-key-v3';
const String _commitCtxV3 = 'z-pair-commit-v3:';
const String _channelCtxV3 = 'z-pair-channel-v3';
const String _sasCtxV3 = 'z-pair-sas-v3';

final _x = X25519();
final _aead = Chacha20.poly1305Aead();

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
  String get text => base32Groups(secret);

  static PairingCode parse(String code) {
    final secret = base32Decode(code);
    // The bound has to match the sublist below, not sit two bytes under it: a
    // code that decodes to 8 or 9 bytes passed `< 8` and then threw a
    // `RangeError` on `sublist(0, 10)` instead of the intended "too short"
    // FormatException (the 2026-09-14 review's finding 43; `connect.dart`
    // parses with the right `< 10`).
    if (secret.length < 10) {
      throw const FormatException('pairing code too short');
    }
    return PairingCode(Uint8List.fromList(secret.sublist(0, 10)));
  }

  /// The relay mailbox both sides use to find each other.
  Future<String> rendezvousRoutingId() async => b64url(await sha256Bytes(
      concatBytes([utf8.encode(_rendezvousCtx), secret])));

  /// The same for a v2 ceremony (§10.1) — a different mailbox from the same
  /// code, so a v2 device and a v1 device never meet at all.
  Future<String> rendezvousRoutingIdV2() async => b64url(await sha256Bytes(
      concatBytes([utf8.encode(_rendezvousCtxV2), secret])));

  /// The same for a v3 ceremony (§10.2): a third mailbox from the same code,
  /// so a v3 device meets neither a v2 one nor a v1 one there.
  Future<String> rendezvousRoutingIdV3() async => b64url(await sha256Bytes(
      concatBytes([utf8.encode(_rendezvousCtxV3), secret])));

  Future<Uint8List>? _pairKey;

  /// `pairKey` (§10.2): HKDF-SHA256 of the code, an empty salt and
  /// `z-pair-key-v3`, 32 bytes. Pairing v3 keys its commitment with it and
  /// salts its channel key with it, as §20.8 binds an invite's secret into
  /// that ceremony, so a relay that does not hold the code can make no frame
  /// either side will take. Defence in depth only: eighty bits, with the
  /// mailboxes' routing ids an oracle for a guess, are no long-term secret.
  /// v1 and v2 derive nothing from it.
  Future<Uint8List> pairKey() => _pairKey ??= () async {
        final k = await Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
          secretKey: SecretKey(secret),
          nonce: Uint8List(0),
          info: utf8.encode(_pairKeyCtxV3),
        );
        return Uint8List.fromList(await k.extractBytes());
      }();
}

/// What the new device ends up installing.
class EnrollmentData {
  final Uint8List accountEdPub;
  final Uint8List? accountEdSeed; // present iff the new device may enroll others

  /// v3 (§18): the ACCOUNT's ML-DSA public key.
  ///
  /// Public, so it travels even when the account root does not. A linked
  /// device needs it for the same reason it needs `accountEdPub`: the
  /// identity a contact verifies belongs to the account, not to whichever
  /// device happens to be showing it. Without this a linked device would
  /// derive a post-quantum key of its own and hand out a contact code
  /// committing to it — a different identity wearing the account's name.
  /// Absent from an enrollment performed by a build that predates v3.
  final Uint8List? accountMlPub;
  final List<AccountBundle> contacts;
  final String? displayName;
  final DeviceCertificate deviceCert; // this (new) device's cert
  final DeviceCertificate hostDeviceCert; // the existing device that linked us

  /// §10, `cstate` (phase 33): what the host holds about each contact beyond
  /// the account bundle in [contacts] — the scanned device's own bundle, the
  /// tick and the number it was given on, the post-quantum commitment and
  /// key and the records kept beside them, the contact's device list. One
  /// JSON object per contact, each naming its routing id (`rid`). Null from
  /// a host that predates it, and from one whose contacts did not fit
  /// (§10's size rule); the receiving app checks every record before it
  /// believes any of it, exactly as it checks a restored archive's.
  final List<Map<String, Object?>>? contactState;

  /// §10, `hostbundle` (phase 33): the host's own contact bundle — its keys
  /// and the binding signature over them. The host is the account's root, so
  /// this is the bundle a contact holds the account under; a linked device
  /// needs it to send a request as the account rather than as itself
  /// (§8.1). Null from a host that predates it.
  final ContactBundle? hostBundle;

  /// §10.2, `enroll-v3`: the new device's attestation, ADR 0033 §1's `pqdc`
  /// — the account's ML-DSA-65 signature over the account key, this
  /// device's two keys and the hash of its sealing key — as the root sealed
  /// it. Carried here as bytes, unread: whoever installs the enrolment checks
  /// it. Null from a v1 or v2 enrolment, and from a host that sent none.
  final Uint8List? pqdc;

  EnrollmentData({
    required this.accountEdPub,
    required this.accountEdSeed,
    this.accountMlPub,
    required this.contacts,
    required this.displayName,
    required this.deviceCert,
    required this.hostDeviceCert,
    this.contactState,
    this.hostBundle,
    this.pqdc,
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
        secretKey: SecretKey(channelKey), nonce: randomBytes(12));
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
  ///
  /// [contactState] and [hostBundle] are §10's two optional members (phase
  /// 33), added after every member a device built before them reads, and
  /// only when given: without them the plaintext is byte for byte what it
  /// always was (the `pairing` and `pair-v2` vectors), and a device that
  /// predates them reads [contacts] and ignores the rest.
  Future<Uint8List> sealEnrollment(
    AccountIdentity me, {
    required List<AccountBundle> contacts,
    required bool includeAccountRoot,
    String? displayName,
    List<Map<String, Object?>>? contactState,
    ContactBundle? hostBundle,
  }) async {
    final cert = await signedPeerCert(me);
    final root = includeAccountRoot ? me.accountEdSeed : null;
    final payload = <String, Object?>{
      'acct': b64(me.accountEdPub),
      if (root != null) 'root': b64(root),
      if (me.accountMlPub != null) 'pqpub': b64(me.accountMlPub!),
      'name': displayName,
      'cert': cert.toJson(),
      'hostcert': me.deviceCert.toJson(),
      'contacts': [for (final c in contacts) c.toJson()],
      if (contactState != null) 'cstate': contactState,
      if (hostBundle != null) 'hostbundle': hostBundle.toJson(),
    };
    return _seal(Uint8List.fromList(utf8.encode(jsonEncode(payload))));
  }

  /// NEW device: open the enrollment blob.
  ///
  /// The two optional members are read leniently: one in a shape this build
  /// does not understand is left out — the enrolment then carries what it
  /// carried before them — rather than failing a link the user has already
  /// confirmed on both screens. Each `cstate` record is checked again,
  /// member by member, by the app that installs it.
  Future<EnrollmentData> openEnrollment(Uint8List sealed) async {
    final j = jsonDecode(utf8.decode(await _open(sealed))) as Map<String, Object?>;
    return EnrollmentData(
      accountEdPub: unb64(j['acct'] as String),
      accountEdSeed: j['root'] == null ? null : unb64(j['root'] as String),
      accountMlPub: j['pqpub'] == null ? null : unb64(j['pqpub'] as String),
      displayName: j['name'] as String?,
      deviceCert:
          DeviceCertificate.fromJson((j['cert'] as Map).cast<String, Object?>()),
      hostDeviceCert: DeviceCertificate.fromJson(
          (j['hostcert'] as Map).cast<String, Object?>()),
      contacts: [
        for (final c in (j['contacts'] as List))
          AccountBundle.fromJson((c as Map).cast<String, Object?>())
      ],
      contactState: _contactState(j['cstate']),
      hostBundle: _hostBundle(j['hostbundle']),
    );
  }

  static List<Map<String, Object?>>? _contactState(Object? v) {
    if (v is! List) return null;
    return [
      for (final r in v)
        if (r is Map && r['rid'] is String) r.cast<String, Object?>()
    ];
  }

  static ContactBundle? _hostBundle(Object? v) {
    if (v is! Map) return null;
    try {
      return ContactBundle.fromJson(v.cast<String, Object?>());
    } catch (_) {
      return null;
    }
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

/// Thrown when the ceremony cannot go on: the peer is on another version, or
/// the opening did not match the commitment. Never a reason to fall back.
class PairingAbort implements Exception {
  final String message;
  const PairingAbort(this.message);
  @override
  String toString() => 'PairingAbort: $message';
}

/// A v3 existing device heard the new device speak an older ceremony
/// (§10.2): [version] is the one it spoke, 1 or 2. Recognised so that the app
/// can say which device to update; never answered, because detecting an old
/// peer must not turn into completing the old ceremony.
class PairingPeerOutdated extends PairingAbort {
  final int version;
  const PairingPeerOutdated(this.version)
      : super('the other device is running an older version of Z: update '
            'it, then pair again');
}

/// A rendezvous frame's fixed-width field: a string that decodes to exactly
/// [length] bytes, or the ceremony aborts.
///
/// Every key in these frames is 32 bytes, and until 2026-09-17 nobody
/// checked: `accept` decoded whatever was there and hashed it. The
/// commitment and the SAS concatenate the fixed fields and then the
/// variable-length `deviceId`, and a concatenation is only unambiguous while
/// the fixed fields are exactly their width — a relay that moved the last
/// byte of `dx` onto the front of `id` (an X25519 public key's last byte is
/// below 0x80, so it is always a one-byte UTF-8 codepoint) produced the same
/// bytes, so the opening matched the commitment, both screens showed the same
/// eight digits, and the host certified a 31-byte ratchet key that every
/// contact then refused — the account's device list broken for good by
/// whoever carried the frame (the 2026-09-14 review's finding 9). Widths are
/// enforced here, on every field of every frame, and a value that is not a
/// string is an abort rather than a type error.
Uint8List _fixed(Map<String, Object?> frame, String key, int length) {
  final v = frame[key];
  if (v is! String) throw PairingAbort('malformed frame: $key');
  final Uint8List bytes;
  try {
    bytes = unb64(v);
  } catch (_) {
    throw PairingAbort('malformed frame: $key');
  }
  if (bytes.length != length) throw PairingAbort('malformed frame: $key');
  return bytes;
}

/// The one variable-length field, bounded: a device id is what the account
/// signs into a certificate and shows in a device list, not a payload.
String _deviceIdField(Map<String, Object?> frame) {
  final v = frame['id'];
  if (v is! String || v.isEmpty || v.length > maxDeviceIdLength) {
    throw const PairingAbort('malformed frame: id');
  }
  return v;
}

/// The most a device id may be. The reference app generates twelve
/// characters (`b64url` of nine random bytes).
const int maxDeviceIdLength = 64;

/// The bytes the initiator commits to in v2, and reveals afterwards.
///
/// Everything the responder will later act on is in here: the ephemeral the
/// SAS is derived from, and the three device fields the responder signs a
/// certificate over. `deviceId` is variable-length and therefore last, so the
/// concatenation is unambiguous — given that the three fields before it are
/// exactly 32 bytes each, which [_fixed] enforces on every frame before
/// anything is hashed.
Future<Uint8List> _commitmentV2(
    Uint8List ephXPub, Uint8List deviceEdPub, Uint8List deviceXPub, String deviceId) {
  return sha256Bytes(concatBytes([
    utf8.encode(_commitCtxV2),
    ephXPub,
    deviceEdPub,
    deviceXPub,
    utf8.encode(deviceId),
  ]));
}

/// v2 SAS: eight digits, over both ephemerals AND the device fields.
///
/// Two things are different from v1, and each closes something that was
/// exploitable.
///
/// The ephemerals are in ROLE order (initiator then responder) rather than
/// lexicographic order, because v2's commitment already fixes which side is
/// which; there is no symmetric case left to canonicalise.
///
/// And `deviceXPub` and `deviceId` are in the input. v1's SAS covered the
/// ephemerals and `deviceEdPub` only, while the responder signed a
/// certificate over the `dx` and `id` it read from an unauthenticated
/// rendezvous frame — so a relay that rewrote nothing but `dx` left BOTH
/// screens showing the same six digits while the host certified an X25519 key
/// the attacker held, at the real device's routing id. Every field the
/// certificate binds is now a field the two users compare.
///
/// Eight digits, and taken from seven bytes rather than four: the modulo of a
/// 31-bit value by 10^8 is visibly biased, and the point of the extra width is
/// to make a guess expensive.
Future<String> _deriveSasV2(Uint8List dh, Uint8List ephI, Uint8List ephR,
    Uint8List deviceEdPub, Uint8List deviceXPub, String deviceId) async {
  final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 8);
  final k = await hkdf.deriveKey(
    secretKey: SecretKey(dh),
    nonce: concatBytes([ephI, ephR]),
    info: concatBytes([
      utf8.encode(_sasCtxV2),
      deviceEdPub,
      deviceXPub,
      utf8.encode(deviceId),
    ]),
  );
  final b = await k.extractBytes();
  var n = 0;
  for (var i = 0; i < 7; i++) {
    n = (n << 8) | b[i];
  }
  final digits = (n % 100000000).toString().padLeft(8, '0');
  return '${digits.substring(0, 4)} ${digits.substring(4)}';
}

Future<Uint8List> _deriveChannelKeyV2(Uint8List dh) async {
  final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
  final k = await hkdf.deriveKey(
    secretKey: SecretKey(dh),
    nonce: Uint8List(32),
    info: utf8.encode(_channelCtxV2),
  );
  return Uint8List.fromList(await k.extractBytes());
}

/// NEW device, v2 (§10.1): commit, then open.
///
/// The reason for the extra round trip is that v1 let the responder choose its
/// ephemeral AFTER seeing the initiator's, which is the whole input to the
/// SAS — so a responder (or anyone who could speak in its place) could search
/// ephemerals until the SAS came out at a value it had already read aloud.
/// Six digits is about a million tries. Here the initiator publishes a hash
/// first and reveals nothing until the responder has committed to its own
/// ephemeral by sending it.
class PairingInitiatorV2 {
  final PairingCode code;
  final Uint8List deviceEdSeed, deviceXSeed, deviceEdPub, deviceXPub;
  final String deviceId;
  final Uint8List ephXSeed, ephXPub;

  PairingInitiatorV2._(this.code, this.deviceEdSeed, this.deviceXSeed,
      this.deviceEdPub, this.deviceXPub, this.deviceId, this.ephXSeed,
      this.ephXPub);

  static Future<PairingInitiatorV2> create(
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
    return PairingInitiatorV2._(
      code ?? PairingCode.generate(),
      edSeed, xSeed, edPub, xPub,
      deviceId ?? b64url(randomBytes(9)),
      ephSeed, ephPub,
    );
  }

  /// Message 1: the commitment, and nothing else. The relay and the responder
  /// learn nothing from it that they could grind against.
  Future<Map<String, Object?>> commit() async => {
        'c': b64(await _commitmentV2(ephXPub, deviceEdPub, deviceXPub, deviceId)),
      };

  /// Message 3, with the session it derives: the opening, sent only after the
  /// responder's reply is in hand.
  Future<(Map<String, Object?>, PairingSession)> open(
      Map<String, Object?> responderReply) async {
    final theirEph = _fixed(responderReply, 'ephx', 32);
    final dh = await _dh(ephXSeed, theirEph);
    final session = PairingSession(
      channelKey: await _deriveChannelKeyV2(dh),
      sas: await _deriveSasV2(
          dh, ephXPub, theirEph, deviceEdPub, deviceXPub, deviceId),
    );
    return (
      {
        'ephx': b64(ephXPub),
        'ded': b64(deviceEdPub),
        'dx': b64(deviceXPub),
        'id': deviceId,
      },
      session,
    );
  }

  /// Same as v1: adopt the account this enrollment describes.
  Future<AccountIdentity> installFromData(EnrollmentData d) =>
      _installFromData(d, deviceEdSeed, deviceXSeed, deviceEdPub, deviceXPub,
          deviceId);
}

/// EXISTING device, v2. Holds its ephemeral and the commitment it answered,
/// so the opening can be checked against what was promised.
class PairingResponderV2 {
  final Uint8List _ephSeed, _ephPub, _commitment;
  PairingResponderV2._(this._ephSeed, this._ephPub, this._commitment);

  Uint8List get ephXPub => _ephPub;

  /// Message 2: answer a commitment with a fresh ephemeral. This side cannot
  /// know what it is committing against, which is the point.
  static Future<(Map<String, Object?>, PairingResponderV2)> reply(
      Map<String, Object?> commit) async {
    final commitment = _fixed(commit, 'c', 32);
    final ephSeed = randomBytes(32);
    final ephPub = Uint8List.fromList(
        (await (await _x.newKeyPairFromSeed(ephSeed)).extractPublicKey()).bytes);
    return (
      {'ephx': b64(ephPub)},
      PairingResponderV2._(ephSeed, ephPub, commitment),
    );
  }

  /// Message 3: check the opening against the commitment, then derive the
  /// session. A mismatch ABORTS — it is not a reason to carry on at reduced
  /// assurance, because the only thing that produces one is someone changing
  /// what the initiator said.
  Future<PairingSession> accept(Map<String, Object?> open) async {
    final theirEph = _fixed(open, 'ephx', 32);
    final deviceEdPub = _fixed(open, 'ded', 32);
    final deviceXPub = _fixed(open, 'dx', 32);
    final deviceId = _deviceIdField(open);
    final expected =
        await _commitmentV2(theirEph, deviceEdPub, deviceXPub, deviceId);
    if (!constantTimeEquals(expected, _commitment)) {
      throw const PairingAbort('the opening does not match the commitment');
    }
    final dh = await _dh(_ephSeed, theirEph);
    return PairingSession(
      channelKey: await _deriveChannelKeyV2(dh),
      sas: await _deriveSasV2(
          dh, theirEph, _ephPub, deviceEdPub, deviceXPub, deviceId),
      peerDeviceEdPub: deviceEdPub,
      peerDeviceXPub: deviceXPub,
      peerDeviceId: deviceId,
    );
  }
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
    final theirEph = _fixed(responderReply, 'ephx', 32);
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
  Future<AccountIdentity> installFromData(EnrollmentData data) =>
      _installFromData(
          data, deviceEdSeed, deviceXSeed, deviceEdPub, deviceXPub, deviceId);
}

/// Shared by both ceremonies: adopt the account an enrollment describes, after
/// checking the certificate in it is for THIS device's keys and verifies under
/// the account key it claims. Identical for v1 and v2 — the enrollment payload
/// did not change, only how the channel carrying it was agreed.
Future<AccountIdentity> _installFromData(
  EnrollmentData data,
  Uint8List deviceEdSeed,
  Uint8List deviceXSeed,
  Uint8List deviceEdPub,
  Uint8List deviceXPub,
  String deviceId,
) async {
  final okKeys = _eq(data.deviceCert.deviceEdPub, deviceEdPub) &&
      _eq(data.deviceCert.deviceXPub, deviceXPub);
  if (!okKeys || !await data.deviceCert.verify(data.accountEdPub)) {
    throw const FormatException('enrollment certificate did not verify');
  }
  return AccountIdentity.fromEnrollment(
    accountEdPub: data.accountEdPub,
    accountEdSeed: data.accountEdSeed,
    accountMlPub: data.accountMlPub,
    deviceEdSeed: deviceEdSeed,
    deviceXSeed: deviceXSeed,
    deviceId: deviceId,
    deviceCert: data.deviceCert,
  );
}

/// EXISTING device. Consumes the new device's hello and produces the reply +
/// the shared session (which also carries the new device's identifiers).
class PairingResponder {
  static Future<(Map<String, Object?>, PairingSession)> respond(
      Map<String, Object?> hello) async {
    final theirEph = _fixed(hello, 'ephx', 32);
    final deviceEdPub = _fixed(hello, 'ded', 32);
    final deviceXPub = _fixed(hello, 'dx', 32);
    final deviceId = _deviceIdField(hello);
    final ephSeed = randomBytes(32);
    final ephPub = Uint8List.fromList(
        (await (await _x.newKeyPairFromSeed(ephSeed)).extractPublicKey()).bytes);
    final dh = await _dh(ephSeed, theirEph);
    final session = PairingSession(
      channelKey: await _deriveChannelKey(dh),
      sas: await _deriveSas(dh, theirEph, ephPub, deviceEdPub),
      peerDeviceEdPub: deviceEdPub,
      peerDeviceXPub: deviceXPub,
      peerDeviceId: deviceId,
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

// ---------------------------------------------------------------------------
// Pairing v3 (§10.2, ADR 0033 §3): v2's four frames, hybrid with ML-KEM-768.
//
// v2's channel key and digits come from two X25519 ephemerals, so a recording
// of the rendezvous yields the account's contacts to whoever later breaks
// X25519 — and one who breaks it live passes the ephemerals through, swaps
// whatever else it likes, and reads the enrolment. In v3 the new device offers
// a fresh ML-KEM-768 key beside its commitment, the existing device
// encapsulates to it in its reply, and the KEM secret K joins the X25519
// output in both the channel key and the digits.
//
// Who does what is the point. The side that commits offers the KEM key, and
// the other encapsulates: each side's contribution is fixed before it sees
// what it would need in order to aim the digits — the new device's by its
// commitment, which covers SHA-256 of the key it offers, and the existing
// device's because it encapsulates before the opening. Were the existing
// device to offer the key, whoever speaks for the new one would choose its
// encapsulation after seeing everything, and grind encapsulations until the
// eight digits came out at a value already read aloud.
//
// Nothing in the app runs this before 44.4: v2 above is what it pairs with.
// ---------------------------------------------------------------------------

/// X25519 for v3, refusing an all-zero output (RFC 7748 §6.1), as §20.3
/// requires of the connect ceremony. A peer ephemeral of small order makes the
/// output zeros whatever this side's key is; an honest ephemeral never is
/// one, so the refusal costs an honest ceremony nothing, and each side checks
/// the value it computes. v1 and v2 are left as they are.
Future<Uint8List> _dhV3(Uint8List seed, Uint8List remotePub) async {
  final out = await _dh(seed, remotePub);
  var any = 0;
  for (final b in out) {
    any |= b;
  }
  if (any == 0) {
    throw const PairingAbort(
        "the other device's ephemeral key is a point of small order");
  }
  return out;
}

/// `sk = SHA-256(sealEk)` (ADR 0033 §3, addendum A1), under a name the
/// initiator's own `sealKeyHash` field does not hide.
Uint8List _skOf(List<int> sealEk) => sealKeyHash(sealEk);

/// The KEM key a v3 commit frame offers: [pqEkLength] bytes that pass FIPS
/// 203 §7.2's input check (`mlKemEncapsulationKeyValid`), or the ceremony
/// aborts before anything is encapsulated to it.
Uint8List _kemKeyField(Map<String, Object?> frame) {
  final ek = _fixed(frame, 'ek', pqEkLength);
  if (!mlKemEncapsulationKeyValid(ek)) {
    throw const PairingAbort('malformed frame: ek');
  }
  return ek;
}

/// The v3 commitment: HMAC-SHA256 under `pairKey` over the context and then
/// everything the existing device will act on — the ephemeral the digits
/// come from, the two keys it certifies, SHA-256 of the KEM key offered beside
/// the commitment, `sk` — and the device id, variable-length and therefore
/// last. Every field before it is exactly 32 bytes, which every frame is
/// checked for before anything is hashed (§10.1 rule 6 stands).
Future<Uint8List> _commitmentV3(
    Uint8List pairKey,
    Uint8List ephXPub,
    Uint8List deviceEdPub,
    Uint8List deviceXPub,
    Uint8List kemEk,
    Uint8List sk,
    String deviceId) async {
  final mac = await Hmac.sha256().calculateMac(
      concatBytes([
        utf8.encode(_commitCtxV3),
        ephXPub,
        deviceEdPub,
        deviceXPub,
        await sha256Bytes(kemEk),
        sk,
        utf8.encode(deviceId),
      ]),
      secretKey: SecretKey(pairKey));
  return Uint8List.fromList(mac.bytes);
}

/// `channelKey = HKDF(dh || K, pairKey, "z-pair-channel-v3", 32)`: neither
/// the X25519 output alone, nor K alone, nor either without the code.
Future<Uint8List> _deriveChannelKeyV3(Uint8List ikm, Uint8List pairKey) async {
  final k = await Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
    secretKey: SecretKey(ikm),
    nonce: pairKey,
    info: utf8.encode(_channelCtxV3),
  );
  return Uint8List.fromList(await k.extractBytes());
}

/// The v3 digits: eight, from seven bytes, as v2's, over `dh || K`, salted
/// with the two ephemerals in role order, with everything the commitment
/// fixed and SHA-256 of the KEM key and ciphertext in the info. `id` is the
/// one variable-length field and is not last, which is still unambiguous:
/// every other field has a fixed width.
///
/// The digits cover K. Without it, someone who breaks X25519 while the
/// ceremony runs could pass both ephemerals through, swap only the KEM, read
/// the enrolment under both channel keys, and leave both screens agreeing.
Future<String> _deriveSasV3(
    Uint8List ikm,
    Uint8List ephN,
    Uint8List ephE,
    Uint8List deviceEdPub,
    Uint8List deviceXPub,
    Uint8List sk,
    String deviceId,
    Uint8List kemEk,
    Uint8List ct) async {
  final k = await Hkdf(hmac: Hmac.sha256(), outputLength: 8).deriveKey(
    secretKey: SecretKey(ikm),
    nonce: concatBytes([ephN, ephE]),
    info: concatBytes([
      utf8.encode(_sasCtxV3),
      deviceEdPub,
      deviceXPub,
      sk,
      utf8.encode(deviceId),
      await sha256Bytes(concatBytes([kemEk, ct])),
    ]),
  );
  final b = await k.extractBytes();
  var n = 0;
  for (var i = 0; i < 7; i++) {
    n = (n << 8) | b[i];
  }
  final digits = (n % 100000000).toString().padLeft(8, '0');
  return '${digits.substring(0, 4)} ${digits.substring(4)}';
}

/// A completed v3 handshake: the channel key and the digits both sides
/// derive, and on the existing side what the new device opened — its keys,
/// its id and `sk` — for the certificate and the attestation the root signs.
///
/// Its enrolment is §10's with one member more, `pqdc`, and one never:
/// `root`. There is no way to put the account root in it, and [openEnrollment]
/// refuses an enrolment that carries one — if the root ever travels, the
/// ML-DSA seed must travel with it, and nothing here carries that.
class PairingSessionV3 {
  final Uint8List channelKey;
  final String sas;
  final Uint8List? peerDeviceEdPub; // set on the existing (responder) side
  final Uint8List? peerDeviceXPub;
  final String? peerDeviceId;

  /// `sk`, SHA-256 of the new device's sealing key (ADR 0033 §1), as the
  /// opening carried it: covered by the commitment and by the digits, and
  /// what the root's `pqdc` for the new device signs over.
  final Uint8List? peerSealKeyHash;

  // The AEAD and the certificate are v2's, unchanged; only how the channel
  // was agreed, and two members of what it carries, differ.
  final PairingSession _s;

  PairingSessionV3({
    required this.channelKey,
    required this.sas,
    this.peerDeviceEdPub,
    this.peerDeviceXPub,
    this.peerDeviceId,
    this.peerSealKeyHash,
  }) : _s = PairingSession(
            channelKey: channelKey,
            sas: sas,
            peerDeviceEdPub: peerDeviceEdPub,
            peerDeviceXPub: peerDeviceXPub,
            peerDeviceId: peerDeviceId);

  /// The certificate this (existing) device signs for the new one.
  Future<DeviceCertificate> signedPeerCert(AccountIdentity me) =>
      _s.signedPeerCert(me);

  /// EXISTING device: sign the new device's certificate and seal `enroll-v3`.
  ///
  /// The members are §10's in §10's order — without `root`, which v3 never
  /// carries — and then [pqdc], the root's attestation of the new device
  /// (ADR 0033 §1), as opaque bytes, when given.
  Future<Uint8List> sealEnrollment(
    AccountIdentity me, {
    required List<AccountBundle> contacts,
    String? displayName,
    List<Map<String, Object?>>? contactState,
    ContactBundle? hostBundle,
    Uint8List? pqdc,
  }) async {
    final cert = await signedPeerCert(me);
    final payload = <String, Object?>{
      'acct': b64(me.accountEdPub),
      if (me.accountMlPub != null) 'pqpub': b64(me.accountMlPub!),
      'name': displayName,
      'cert': cert.toJson(),
      'hostcert': me.deviceCert.toJson(),
      'contacts': [for (final c in contacts) c.toJson()],
      if (contactState != null) 'cstate': contactState,
      if (hostBundle != null) 'hostbundle': hostBundle.toJson(),
      if (pqdc != null) 'pqdc': b64(pqdc),
    };
    return _s._seal(Uint8List.fromList(utf8.encode(jsonEncode(payload))));
  }

  /// NEW device: open `enroll-v3`. As [PairingSession.openEnrollment], with
  /// `pqdc` read as bytes — leniently, like the other optional members: one
  /// that is not a base64 string is left out — and an enrolment carrying
  /// the account root refused outright.
  Future<EnrollmentData> openEnrollment(Uint8List sealed) async {
    final j = jsonDecode(utf8.decode(await _s._open(sealed)))
        as Map<String, Object?>;
    if (j['root'] != null) {
      throw const FormatException(
          'a v3 enrolment never carries the account root');
    }
    final pqdc = j['pqdc'];
    Uint8List? attestation;
    if (pqdc is String) {
      try {
        attestation = unb64(pqdc);
      } on FormatException {
        attestation = null;
      }
    }
    return EnrollmentData(
      accountEdPub: unb64(j['acct'] as String),
      accountEdSeed: null,
      accountMlPub: j['pqpub'] == null ? null : unb64(j['pqpub'] as String),
      displayName: j['name'] as String?,
      deviceCert:
          DeviceCertificate.fromJson((j['cert'] as Map).cast<String, Object?>()),
      hostDeviceCert: DeviceCertificate.fromJson(
          (j['hostcert'] as Map).cast<String, Object?>()),
      contacts: [
        for (final c in (j['contacts'] as List))
          AccountBundle.fromJson((c as Map).cast<String, Object?>())
      ],
      contactState: PairingSession._contactState(j['cstate']),
      hostBundle: PairingSession._hostBundle(j['hostbundle']),
      pqdc: attestation,
    );
  }
}

/// NEW device, v3 (§10.2): commit and offer a KEM key, then open.
///
/// [sealKeyHash] is `sk`, SHA-256 of this device's sealing key (ADR 0033 §1):
/// [create] takes the key itself and keeps only its hash, which the
/// commitment, the opening and the digits all carry, and which the root's
/// `pqdc` for this device signs over.
class PairingInitiatorV3 {
  final PairingCode code;
  final Uint8List deviceEdSeed, deviceXSeed, deviceEdPub, deviceXPub;
  final String deviceId;
  final Uint8List ephXSeed, ephXPub;

  /// The ceremony's own ML-KEM-768 pair: the 64-byte seed `d || z` it is
  /// generated from, and the encapsulation key the commit frame offers.
  /// Fresh for every ceremony, and used for one decapsulation.
  final Uint8List kemSeed, kemEk;

  /// `sk` (§10.2).
  final Uint8List sealKeyHash;

  bool _opened = false;

  PairingInitiatorV3._(
      this.code,
      this.deviceEdSeed,
      this.deviceXSeed,
      this.deviceEdPub,
      this.deviceXPub,
      this.deviceId,
      this.ephXSeed,
      this.ephXPub,
      this.kemSeed,
      this.kemEk,
      this.sealKeyHash);

  /// [sealKey] is this device's ML-KEM-768 sealing key (ADR 0033 §1), the
  /// encapsulation key's bytes; refused unless it passes FIPS 203 §7.2's
  /// check, since the account would attest its hash.
  static Future<PairingInitiatorV3> create(
      {required List<int> sealKey, PairingCode? code, String? deviceId}) async {
    if (!mlKemEncapsulationKeyValid(sealKey)) {
      throw ArgumentError.value(sealKey.length, 'sealKey',
          'not an ML-KEM-768 encapsulation key');
    }
    final edSeed = randomBytes(32);
    final xSeed = randomBytes(32);
    final ephSeed = randomBytes(32);
    final (kemSeed, kemEk) = pqGenerate();
    final edPub =
        Uint8List.fromList((await (await Ed25519().newKeyPairFromSeed(edSeed))
                .extractPublicKey())
            .bytes);
    final xPub = Uint8List.fromList(
        (await (await _x.newKeyPairFromSeed(xSeed)).extractPublicKey()).bytes);
    final ephPub = Uint8List.fromList(
        (await (await _x.newKeyPairFromSeed(ephSeed)).extractPublicKey()).bytes);
    return PairingInitiatorV3._(
      code ?? PairingCode.generate(),
      edSeed, xSeed, edPub, xPub,
      deviceId ?? b64url(randomBytes(9)),
      ephSeed, ephPub, kemSeed, kemEk,
      _skOf(sealKey),
    );
  }

  /// Message 1: the commitment, and beside it the KEM key it covers. Nothing
  /// in it can be searched against a target string without the opening.
  Future<Map<String, Object?>> commit() async => {
        'c': b64(await _commitmentV3(await code.pairKey(), ephXPub,
            deviceEdPub, deviceXPub, kemEk, sealKeyHash, deviceId)),
        'ek': b64(kemEk),
      };

  /// Message 3, with the session it derives: the opening, sent only once the
  /// reply — the existing device's ephemeral and its encapsulation — is in
  /// hand. Once per ceremony: a second call is refused.
  Future<(Map<String, Object?>, PairingSessionV3)> open(
      Map<String, Object?> responderReply) async {
    if (_opened) {
      throw StateError('a v3 opening is made once: its KEM key is spent');
    }
    final theirEph = _fixed(responderReply, 'ephx', 32);
    final ct = _fixed(responderReply, 'ct', pqCtLength);
    final dh = await _dhV3(ephXSeed, theirEph);
    // pqcrypto 0.4.1 does not decapsulate in constant time, and that gates
    // `zs2.` (44.7, ADR 0033 decision 4) but not this. What separates the two
    // is how many ciphertexts one key ever meets. `zs2.`'s sealing key lives
    // as long as the device and decapsulates whatever anyone addresses to its
    // mailbox, with the relay timing every acknowledgement: the stream of
    // chosen ciphertexts a KyberSlash-class leak is exploited with. This key
    // was drawn for this ceremony and decapsulates exactly once — the first
    // reply's ciphertext; [open] refuses a second — and is dropped with the
    // ceremony. Whoever chose that ciphertext gets one measurement of a key
    // that never decapsulates again.
    _opened = true;
    final k = pqDecapsulate(kemSeed, ct);
    final ikm = concatBytes([dh, k]);
    final session = PairingSessionV3(
      channelKey: await _deriveChannelKeyV3(ikm, await code.pairKey()),
      sas: await _deriveSasV3(ikm, ephXPub, theirEph, deviceEdPub, deviceXPub,
          sealKeyHash, deviceId, kemEk, ct),
    );
    return (
      {
        'ephx': b64(ephXPub),
        'ded': b64(deviceEdPub),
        'dx': b64(deviceXPub),
        'sk': b64(sealKeyHash),
        'id': deviceId,
      },
      session,
    );
  }

  /// As v1 and v2: adopt the account this enrolment describes.
  Future<AccountIdentity> installFromData(EnrollmentData d) =>
      _installFromData(d, deviceEdSeed, deviceXSeed, deviceEdPub, deviceXPub,
          deviceId);
}

/// EXISTING device, v3. Holds its ephemeral, the commitment and KEM key it
/// answered, and its encapsulation, so the opening can be checked against what
/// was promised.
class PairingResponderV3 {
  final Uint8List _pairKey, _ephSeed, _ephPub, _commitment, _kemEk, _ct, _k;
  PairingResponderV3._(this._pairKey, this._ephSeed, this._ephPub,
      this._commitment, this._kemEk, this._ct, this._k);

  Uint8List get ephXPub => _ephPub;

  /// Message 2: answer a commitment with a fresh ephemeral and an
  /// encapsulation to the KEM key beside it — chosen holding only the
  /// commitment, so this side cannot aim the digits either. [code] is the
  /// pairing code typed in here: its `pairKey` keys the commitment and salts
  /// the channel.
  static Future<(Map<String, Object?>, PairingResponderV3)> reply(
      Map<String, Object?> commit,
      {required PairingCode code}) async {
    final commitment = _fixed(commit, 'c', 32);
    final kemEk = _kemKeyField(commit);
    final ephSeed = randomBytes(32);
    final ephPub = Uint8List.fromList(
        (await (await _x.newKeyPairFromSeed(ephSeed)).extractPublicKey()).bytes);
    final (ct, k) = pqEncapsulate(kemEk);
    return (
      {'ephx': b64(ephPub), 'ct': b64(ct)},
      PairingResponderV3._(
          await code.pairKey(), ephSeed, ephPub, commitment, kemEk, ct, k),
    );
  }

  /// Message 3: check the opening against the commitment — which covers the
  /// KEM key this side encapsulated to — then derive the session. A mismatch
  /// ABORTS: nothing but a substitution produces one.
  Future<PairingSessionV3> accept(Map<String, Object?> open) async {
    final theirEph = _fixed(open, 'ephx', 32);
    final deviceEdPub = _fixed(open, 'ded', 32);
    final deviceXPub = _fixed(open, 'dx', 32);
    final sk = _fixed(open, 'sk', 32);
    final deviceId = _deviceIdField(open);
    final expected = await _commitmentV3(
        _pairKey, theirEph, deviceEdPub, deviceXPub, _kemEk, sk, deviceId);
    if (!constantTimeEquals(expected, _commitment)) {
      throw const PairingAbort('the opening does not match the commitment');
    }
    final dh = await _dhV3(_ephSeed, theirEph);
    final ikm = concatBytes([dh, _k]);
    return PairingSessionV3(
      channelKey: await _deriveChannelKeyV3(ikm, _pairKey),
      sas: await _deriveSasV3(ikm, theirEph, _ephPub, deviceEdPub, deviceXPub,
          sk, deviceId, _kemEk, _ct),
      peerDeviceEdPub: deviceEdPub,
      peerDeviceXPub: deviceXPub,
      peerDeviceId: deviceId,
      peerSealKeyHash: sk,
    );
  }
}
