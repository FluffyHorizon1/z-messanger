/// The introduction key (ADR 0033 addendum A, PROTOCOL.md §8.3): a device's
/// sealing key — ADR 0033 §1's ML-KEM-768 pair, one per device for its life —
/// held at its relay so that a sender who has never heard from the device can
/// seal its first envelope to it post-quantum, and signed by the device's own
/// Ed25519 key, the key whose SHA-256 is the mailbox, so that a relay which
/// cannot forge Ed25519 at the moment it is asked cannot serve a key of its
/// own.
///
/// What lives here — and nothing here talks to the network (the frames are
/// `RelayClient.publishIntroKey` and `RelayClient.ikeyGet`):
///
/// * `iks`, Ed25519 by the mailbox's key over
///   `utf8("z-intro-key-v1:") || edPub || SHA-256(ek)` ([signIntroKey]),
///   checked under §21.4's one signature rule ([introKeySignatureValid]);
/// * the entry `(ek, iks)` a relay keeps, and the hint its `ready` names the
///   entry by ([IntroKeyEntry]);
/// * FIPS 203 §7.2's input check of an encapsulation key
///   ([mlKemEncapsulationKeyValid]);
/// * the rule a sender accepts what a relay served by
///   ([checkServedIntroKey]);
/// * `sk`, the key's hash a contact code may carry ([sealKeyHash]);
/// * an introduction mailbox's own key, from its seed ([handleIntroKem]).
///
/// No client publishes or fetches an introduction key before 44.11–44.12,
/// and no client seals `zs2.` before 44.7: until then this is a library and
/// its vectors, and the relay half that keeps the keys.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart' show DartSha256;

import 'ed25519_strict.dart';
import 'pq.dart' show pqEkLength, pqKeyPairFromSeed;
import 'util.dart';

/// The context `iks` signs under (§8.3). Distinct from every other context in
/// the protocol and a prefix of none.
const String introKeyContext = 'z-intro-key-v1:';

/// The HKDF salt of an introduction mailbox's sealing key (§21.3, §8.3),
/// beside `z-handle-intro-x-v1`, the salt of its X25519 key.
const String handleIntroKemSalt = 'z-handle-intro-k-v1';

/// An ML-KEM-768 encapsulation key: 384·k + 32 bytes with k = 3.
const int introKeyEkBytes = pqEkLength; // 1 184
const int introKeySigBytes = 64;

/// `ek || iks`, what the relay keeps for a mailbox.
const int introKeyEntryBytes = introKeyEkBytes + introKeySigBytes; // 1 248

/// `sk`, SHA-256 of the key.
const int sealKeyHashBytes = 32;

/// How much of SHA-256(ek || iks) a relay's `ready` names its entry by.
const int introKeyHintBytes = 16;

/// FIPS 203's q.
const int _q = 3329;

Uint8List _sha256(List<int> data) =>
    Uint8List.fromList(const DartSha256().hashSync(data).bytes);

/// `sk = SHA-256(ek)` (addendum A1): what a contact code carries to promise a
/// key and to bind it, and the value `iks` signs over. The same 32 bytes
/// ADR 0033 §3 and §1's `pqdc` hash the sealing key to.
Uint8List sealKeyHash(List<int> ek) => _sha256(ek);

/// The bytes `iks` signs: the context, the mailbox's Ed25519 key — the key
/// whose SHA-256 is the routing id (§2.2): the account key on a root device,
/// the device's `ded` on a linked one, `intro` for an introduction mailbox —
/// and SHA-256 of the key. The two fields after the context are fixed-width,
/// so the concatenation is unambiguous.
Uint8List introKeySigningInput(List<int> edPub, List<int> ek) {
  if (edPub.length != 32) {
    throw ArgumentError.value(
        edPub.length, 'edPub', 'an Ed25519 public key is 32 bytes');
  }
  return concatBytes([utf8.encode(introKeyContext), edPub, sealKeyHash(ek)]);
}

/// `iks = Ed25519.Sign(edSeed, introKeySigningInput(edPub, ek))`, by the key
/// the mailbox is the hash of. Deterministic (RFC 8032), so one device's
/// entry is one byte string however often it is signed.
Future<Uint8List> signIntroKey(
    {required Uint8List edSeed, required List<int> ek}) async {
  final ed = Ed25519();
  final kp = await ed.newKeyPairFromSeed(edSeed);
  final pub = (await kp.extractPublicKey()).bytes;
  final sig = await ed.sign(introKeySigningInput(pub, ek), keyPair: kp);
  return Uint8List.fromList(sig.bytes);
}

/// Whether [iks] is [edPub]'s signature over [ek], under §21.4's one rule
/// (`ed25519VerifyStrict`): a key or an R of small order, an S at or above
/// L, or a second spelling of either is refused, whatever a lenient verifier
/// would say. Never throws.
bool introKeySignatureValid(
    {required List<int> edPub, required List<int> ek, required List<int> iks}) {
  if (edPub.length != 32 || iks.length != introKeySigBytes) return false;
  return ed25519VerifyStrict(edPub, introKeySigningInput(edPub, ek), iks);
}

/// FIPS 203 §7.2's input check of an ML-KEM-768 encapsulation key, written
/// from the standard: the type check — 1 184 bytes — and the modulus check,
/// `ByteEncode12(ByteDecode12(ek[0 : 1152])) == ek[0 : 1152]`. ByteDecode12
/// reduces each 12-bit coefficient mod q (Algorithm 6, m = q for d = 12), so
/// the round trip gives back the bytes exactly when no coefficient of t̂ is q
/// or more. The last 32 bytes are ρ, a seed, and are not checked. The
/// library's encapsulation refuses such a key too, by throwing; the
/// acceptance rule (§8.3) is this check, said, so that another
/// implementation knows what it is held to. Not constant-time: the key is
/// public.
bool mlKemEncapsulationKeyValid(List<int> ek) {
  if (ek.length != introKeyEkBytes) return false;
  for (var i = 0; i < 1152; i += 3) {
    final b0 = ek[i], b1 = ek[i + 1], b2 = ek[i + 2];
    // ByteDecode12: two coefficients from three bytes, little-endian bits.
    final c0 = (b0 | ((b1 & 0x0f) << 8)) % _q;
    final c1 = ((b1 >> 4) | (b2 << 4)) % _q;
    // ByteEncode12 of what was decoded.
    if ((c0 & 0xff) != b0 ||
        (((c0 >> 8) & 0x0f) | ((c1 & 0x0f) << 4)) != b1 ||
        ((c1 >> 4) & 0xff) != b2) {
      return false;
    }
  }
  return true;
}

/// A mailbox's introduction key as a relay keeps it (§12.7): the sealing key
/// and the mailbox key's signature over it. Public, both halves.
class IntroKeyEntry {
  /// The ML-KEM-768 encapsulation key, [introKeyEkBytes] bytes.
  final Uint8List ek;

  /// [signIntroKey] over [ek], [introKeySigBytes] bytes.
  final Uint8List iks;

  IntroKeyEntry(List<int> ek, List<int> iks)
      : ek = Uint8List.fromList(ek),
        iks = Uint8List.fromList(iks);

  /// `ek || iks`, [introKeyEntryBytes] bytes: what a relay holds, raw
  /// (`ik:{rid}` in a shared store).
  Uint8List get bytes => concatBytes([ek, iks]);

  /// What a relay's `ready` names the entry it holds by:
  /// `b64url(SHA-256(ek || iks)[0..16])`, 22 characters. A device whose own
  /// entry's hint is not the one `ready` names publishes its entry (§12.7).
  String get hint => b64url(_sha256(bytes).sublist(0, introKeyHintBytes));

  /// Splits what a relay holds back into its two halves, or null when it is
  /// not [introKeyEntryBytes] long.
  static IntroKeyEntry? fromBytes(List<int> b) {
    if (b.length != introKeyEntryBytes) return null;
    return IntroKeyEntry(
        b.sublist(0, introKeyEkBytes), b.sublist(introKeyEkBytes));
  }
}

/// The entry a device publishes for its own mailbox: its sealing key and
/// [signIntroKey] by the mailbox's Ed25519 seed.
Future<IntroKeyEntry> introKeyEntry(
        {required Uint8List edSeed, required List<int> ek}) async =>
    IntroKeyEntry(ek, await signIntroKey(edSeed: edSeed, ek: ek));

/// Why a sender refuses what a relay served for a mailbox (§8.3), in the
/// order [checkServedIntroKey] asks.
enum IntroKeyRefusal {
  /// The key is not 1 184 bytes: FIPS 203's type check.
  keyLength,

  /// The signature is not 64 bytes.
  signatureLength,

  /// The key fails FIPS 203 §7.2's modulus check.
  keyEncoding,

  /// The Ed25519 key the route names is not the one whose SHA-256 is the
  /// mailbox that was asked about.
  wrongMailbox,

  /// `iks` does not verify under that key, over this key, by §21.4's rule.
  badSignature,

  /// The contact is being added from a code that carries `sk`, and this is
  /// not the key it names.
  notTheCodesKey,
}

/// The acceptance rule (addendum A3, §8.3): what a sender checks of a key a
/// relay served for [rid] before it seals anything to it. [edPub] is the key
/// the route names (§8.3's table: a code's `ed`, a request's `bundle.ed`, a
/// listed device's `ded`, a handle record's `intro`); [sk] the `sk` of the
/// code the contact is being added from, when it carries one. Null means
/// accepted: hold [ek] as the device's sealing key, exactly as if `pqseal`
/// had brought it. Anything else is refused, recorded and said once, and the
/// key is never tried again.
///
/// It says nothing about the device's account: a key checked this way is a
/// sealing key, never "post-quantum, verified" (ADR 0033 §2). Against an
/// adversary who can forge Ed25519 at the moment of the fetch it is as good
/// as `sk`, which is to say only a code that carries one binds the key.
IntroKeyRefusal? checkServedIntroKey({
  required String rid,
  required List<int> edPub,
  required List<int> ek,
  required List<int> iks,
  List<int>? sk,
}) {
  if (ek.length != introKeyEkBytes) return IntroKeyRefusal.keyLength;
  if (iks.length != introKeySigBytes) return IntroKeyRefusal.signatureLength;
  if (!mlKemEncapsulationKeyValid(ek)) return IntroKeyRefusal.keyEncoding;
  if (edPub.length != 32 || b64url(_sha256(edPub)) != rid) {
    return IntroKeyRefusal.wrongMailbox;
  }
  if (!introKeySignatureValid(edPub: edPub, ek: ek, iks: iks)) {
    return IntroKeyRefusal.badSignature;
  }
  if (sk != null && !constantTimeEquals(sealKeyHash(ek), sk)) {
    return IntroKeyRefusal.notTheCodesKey;
  }
  return null;
}

/// An introduction mailbox's sealing key (§21.3, addendum A1):
/// [seed] is `kintroSeed = HKDF-SHA256(ikm = introSeed, salt =
/// "z-handle-intro-k-v1", info = ∅, L = 64)`, read as FIPS 203's `d || z`,
/// and ([ek], [dk]) the ML-KEM-768 pair it makes. The third key one
/// introduction seed makes, beside `intro` and `xintro`, so rotating the seed
/// rotates all three. It is never in the handle record: the relay keeps it,
/// signed by `intro` ([signIntroKey] with the introduction seed).
class HandleIntroKem {
  final Uint8List seed;
  final Uint8List ek;
  final Uint8List dk;
  const HandleIntroKem(this.seed, this.ek, this.dk);
}

Future<HandleIntroKem> handleIntroKem(Uint8List introSeed) async {
  if (introSeed.length != 32) {
    throw ArgumentError.value(
        introSeed.length, 'introSeed', 'an Ed25519 seed is 32 bytes');
  }
  final okm = await Hkdf(hmac: Hmac.sha256(), outputLength: 64).deriveKey(
    secretKey: SecretKey(introSeed),
    nonce: utf8.encode(handleIntroKemSalt),
    info: const <int>[],
  );
  final seed = Uint8List.fromList(await okm.extractBytes());
  final (ek, dk) = pqKeyPairFromSeed(seed);
  return HandleIntroKem(seed, ek, dk);
}
