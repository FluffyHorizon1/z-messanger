import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'util.dart';

const String bindContext = 'z-bind-v1:';
const String authContext = 'z-relay-auth-v1:';
const String safetyContext = 'z-safety-v1';
const String contactCodePrefix = 'zc1.';

/// A user's full identity: an Ed25519 signing key pair and an X25519
/// Diffie-Hellman key pair. Private seeds never leave the device.
class ZIdentity {
  final SimpleKeyPair edKeyPair;
  final SimpleKeyPair xKeyPair;
  final Uint8List edSeed;
  final Uint8List xSeed;
  final Uint8List edPub;
  final Uint8List xPub;

  ZIdentity._(this.edKeyPair, this.xKeyPair, this.edSeed, this.xSeed,
      this.edPub, this.xPub);

  static Future<ZIdentity> generate() async {
    final edSeed = randomBytes(32);
    final xSeed = randomBytes(32);
    return fromSeeds(edSeed: edSeed, xSeed: xSeed);
  }

  static Future<ZIdentity> fromSeeds(
      {required Uint8List edSeed, required Uint8List xSeed}) async {
    final ed = Ed25519();
    final x = X25519();
    final edKp = await ed.newKeyPairFromSeed(edSeed);
    final xKp = await x.newKeyPairFromSeed(xSeed);
    final edPub = Uint8List.fromList((await edKp.extractPublicKey()).bytes);
    final xPub = Uint8List.fromList((await xKp.extractPublicKey()).bytes);
    return ZIdentity._(edKp, xKp, edSeed, xSeed, edPub, xPub);
  }

  /// Stable routing identifier: SHA-256 of the Ed25519 public key. The relay
  /// only ever sees this hash, never a name, phone number, or email.
  Future<String> routingId() async => b64url(await sha256Bytes(edPub));

  /// Signature binding the X25519 key to the Ed25519 identity.
  Future<Uint8List> bindingSignature() async {
    final sig = await Ed25519().sign(
      concatBytes([utf8.encode(bindContext), xPub]),
      keyPair: edKeyPair,
    );
    return Uint8List.fromList(sig.bytes);
  }

  /// Sign a relay authentication challenge.
  Future<Uint8List> signAuthChallenge(Uint8List nonce) async {
    final sig = await Ed25519().sign(
      concatBytes([utf8.encode(authContext), nonce]),
      keyPair: edKeyPair,
    );
    return Uint8List.fromList(sig.bytes);
  }

  Future<ContactBundle> bundle({String? displayName}) async {
    return ContactBundle(
      edPub: edPub,
      xPub: xPub,
      bindingSig: await bindingSignature(),
      displayName: displayName,
    );
  }

  Map<String, Object?> toJson() => {
        'edSeed': b64(edSeed),
        'xSeed': b64(xSeed),
      };

  static Future<ZIdentity> fromJson(Map<String, Object?> j) => fromSeeds(
        edSeed: unb64(j['edSeed'] as String),
        xSeed: unb64(j['xSeed'] as String),
      );
}

/// The public part of an identity, exchanged out-of-band (QR code / paste).
class ContactBundle {
  final Uint8List edPub;
  final Uint8List xPub;
  final Uint8List bindingSig;
  final String? displayName;

  ContactBundle({
    required this.edPub,
    required this.xPub,
    required this.bindingSig,
    this.displayName,
  });

  Future<String> routingId() async => b64url(await sha256Bytes(edPub));

  /// Verifies that the X25519 key really belongs to the Ed25519 identity.
  Future<bool> verify() async {
    try {
      return await Ed25519().verify(
        concatBytes([utf8.encode(bindContext), xPub]),
        signature: Signature(
          bindingSig,
          publicKey: SimplePublicKey(edPub, type: KeyPairType.ed25519),
        ),
      );
    } catch (_) {
      return false;
    }
  }

  /// Encodes as a compact shareable string: `zc1.<base64url(json)>`.
  String encode() {
    final j = <String, Object?>{
      'v': 1,
      'ed': b64(edPub),
      'x': b64(xPub),
      'sig': b64(bindingSig),
      if (displayName != null && displayName!.isNotEmpty) 'name': displayName,
    };
    return contactCodePrefix + b64url(utf8.encode(jsonEncode(j)));
  }

  /// Parses and VERIFIES a contact code. Throws [FormatException] on any
  /// malformed or tampered input.
  static Future<ContactBundle> decode(String code) async {
    final trimmed = code.trim();
    if (!trimmed.startsWith(contactCodePrefix)) {
      throw const FormatException('not a Z contact code');
    }
    final Map<String, Object?> j;
    try {
      j = jsonDecode(
              utf8.decode(unb64url(trimmed.substring(contactCodePrefix.length))))
          as Map<String, Object?>;
    } catch (_) {
      throw const FormatException('corrupt contact code');
    }
    if (j['v'] != 1) throw const FormatException('unsupported version');
    final bundle = ContactBundle(
      edPub: unb64(j['ed'] as String),
      xPub: unb64(j['x'] as String),
      bindingSig: unb64(j['sig'] as String),
      displayName: j['name'] as String?,
    );
    if (bundle.edPub.length != 32 || bundle.xPub.length != 32) {
      throw const FormatException('bad key length');
    }
    if (!await bundle.verify()) {
      throw const FormatException(
          'contact code signature invalid (possible tampering)');
    }
    return bundle;
  }

  Map<String, Object?> toJson() => {
        'ed': b64(edPub),
        'x': b64(xPub),
        'sig': b64(bindingSig),
        'name': displayName,
      };

  static ContactBundle fromJson(Map<String, Object?> j) => ContactBundle(
        edPub: unb64(j['ed'] as String),
        xPub: unb64(j['x'] as String),
        bindingSig: unb64(j['sig'] as String),
        displayName: j['name'] as String?,
      );
}

/// A 60-digit safety number both parties can compare out-of-band to rule out
/// machine-in-the-middle key substitution. Symmetric: both devices show the
/// exact same digits.
Future<String> safetyNumber(Uint8List edPubA, Uint8List edPubB) async {
  final lo = _lexLess(edPubA, edPubB) ? edPubA : edPubB;
  final hi = identical(lo, edPubA) ? edPubB : edPubA;
  final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 60);
  final key = await hkdf.deriveKey(
    secretKey: SecretKey(concatBytes([lo, hi])),
    nonce: utf8.encode(safetyContext),
    info: utf8.encode('display'),
  );
  final bytes = await key.extractBytes();
  final groups = <String>[];
  for (var g = 0; g < 12; g++) {
    var acc = 0;
    for (var i = 0; i < 5; i++) {
      acc = (acc * 256 + bytes[g * 5 + i]) % 100000;
    }
    groups.add(acc.toString().padLeft(5, '0'));
  }
  return groups.join(' ');
}

bool _lexLess(Uint8List a, Uint8List b) {
  for (var i = 0; i < a.length && i < b.length; i++) {
    if (a[i] != b[i]) return a[i] < b[i];
  }
  return a.length < b.length;
}
