/// Adding a contact you cannot stand next to — the cryptographic core (17.1).
///
/// In person, adding someone is a QR code and the QR *is* the verification:
/// the channel is your eyes. Remotely there was only "copy your code, send it
/// over a channel you trust, they paste it", which is one-directional, hands
/// out a permanent identifier, ends unverified, and rests on advice — "a
/// channel you trust" — that the people who need it most do not have.
///
/// This is the same shape as device pairing (§10.1): a one-time code, a
/// rendezvous mailbox derived from it, an ephemeral X25519 exchange, a short
/// string two humans compare. Three things are different, and each is because
/// the code travels over a channel that may be hostile rather than between two
/// screens one person is holding.
///
/// **Both sides commit before either reveals.** Four messages, two
/// commitments. The inviter commits to its ephemeral and to what it will
/// reveal; the acceptor commits to the same about itself while holding only a
/// hash of the inviter's. So neither can choose its ephemeral — or its claimed
/// identity — knowing what the confirmation string will be, and a
/// machine-in-the-middle gets exactly one blind guess at eight digits.
///
/// **The confirmation string is bound to the identities, not only to the
/// channel.** It covers both account Ed25519 keys and both post-quantum
/// commitments (§18.2), canonically ordered, so a matching string says what a
/// safety-number comparison says: *the identity I have stored is the identity
/// you hold.* That is what lets a confirmed ceremony mark a contact verified.
///
/// **Both people are added by one ceremony.** Each side's contact code travels
/// sealed under the channel key, in both directions, so there is no second
/// round of copy-and-paste.
///
/// Transport-agnostic: this produces and consumes the wire maps and the sealed
/// bytes. The rendezvous choreography over a real relay is `connect_relay.dart`
/// (17.2); the invite's life in the app is 17.3.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'identity.dart';
import 'identity_v3.dart';
import 'util.dart';

const String _rendezvousCtx = 'z-connect-rendezvous-v1:';
const String _channelCtx = 'z-connect-channel-v1';
const String _sasCtx = 'z-connect-sas-v1';
const String _commitCtx = 'z-connect-commit-v1:';

/// The context the throwaway relay mailboxes are derived from (17.2). Here
/// rather than in the transport so every context string for this ceremony is
/// in one place and visibly disjoint from `z-pair-*`.
const String connectRelayCtx = 'z-connect-relay-v1:';

/// Where a `/i#…` invite link points by default.
const String connectLinkHost = 'zmessengers.com';

final _x = X25519();
final _aead = Chacha20.poly1305Aead();

/// Thrown when the ceremony must not continue: a reveal that does not match
/// its commitment, a malformed frame, or a step taken out of order. Never a
/// reason to fall back to something weaker.
class ConnectAbort implements Exception {
  final String message;
  const ConnectAbort(this.message);
  @override
  String toString() => 'ConnectAbort: $message';
}

/// The one-time invite secret, in its two renderings.
///
/// Ten random bytes, shown either as `ABCDE-FGHIJ-KLMNO-P` — for reading down
/// a phone line — or inside the **fragment** of a link, which no browser sends
/// to a server, so the site that serves the landing page never receives it.
/// Both renderings are the same secret; [text] and [link] cannot drift apart
/// because they are computed from the same bytes here.
class ConnectCode {
  final Uint8List secret;
  ConnectCode(this.secret) {
    if (secret.length != 10) {
      throw const FormatException('a connect code is 10 bytes');
    }
  }

  static ConnectCode generate() => ConnectCode(randomBytes(10));

  String get text => base32Groups(secret);

  static ConnectCode parse(String code) {
    final b = base32Decode(code);
    if (b.length < 10) throw const FormatException('connect code too short');
    return ConnectCode(Uint8List.fromList(b.sublist(0, 10)));
  }

  /// `https://<host>/i#<code>`. The code is in the fragment on purpose.
  String link({String host = connectLinkHost}) =>
      'https://$host/i#${text.replaceAll('-', '')}';

  /// The code in a link, or null if this is not one. Accepts the link with or
  /// without its scheme and with the groups' dashes present or absent, because
  /// people paste what they were sent.
  static ConnectCode? fromLink(String url) {
    final hash = url.indexOf('#');
    if (hash < 0 || hash == url.length - 1) return null;
    final before = url.substring(0, hash);
    if (!before.contains('/i')) return null;
    try {
      return ConnectCode.parse(url.substring(hash + 1));
    } on FormatException {
      return null;
    }
  }

  /// The rendezvous mailbox both sides meet at. Disjoint from a pairing
  /// code's by context, so a connect code can never address a pairing
  /// rendezvous or the reverse.
  Future<String> rendezvousRoutingId() async => b64url(
      await sha256Bytes(concatBytes([utf8.encode(_rendezvousCtx), secret])));
}

/// What one side reveals about itself: the contact code it would have shown in
/// a QR, and the name to label it with.
///
/// The two derived fields are what the confirmation string is bound to. They
/// are read out of the code rather than passed alongside it, so the string
/// cannot cover one identity while the code carries another.
class ConnectIdentity {
  /// A `zc1.`/`zc3.` contact code — exactly what a QR would have carried, so
  /// the receiving side feeds it to the same verification path a scan uses.
  final String contactCode;
  final String? displayName;

  /// The ACCOUNT key this code is about (§18.7), not the device's.
  final Uint8List accountEdPub;

  /// The account's post-quantum commitment (§18.2), or 32 zero bytes for a
  /// classical identity that has none. Zeroes rather than absence so the
  /// confirmation string's input is fixed-length — and so a classical identity
  /// and a post-quantum one for the same key read *differently*, which is
  /// right: they are different identities to confirm.
  final Uint8List pqCommit;

  ConnectIdentity._(
      this.contactCode, this.displayName, this.accountEdPub, this.pqCommit);

  static final Uint8List _noPq = Uint8List(32);

  /// Read the identity out of a contact code.
  static Future<ConnectIdentity> fromCode(String contactCode,
      {String? displayName}) async {
    try {
      final v3 = await ContactBundleV3.decode(contactCode);
      return ConnectIdentity._(
          contactCode, displayName ?? v3.displayName, v3.accountEdPub, v3.pqCommit);
    } on FormatException {
      // A classical code: no post-quantum commitment to bind, and by §3.5 the
      // device in it *is* the account.
      final b = await ContactBundle.decode(contactCode);
      return ConnectIdentity._(
          contactCode, displayName ?? b.displayName, b.edPub, _noPq);
    }
  }

  /// The bytes a commitment covers: this side's ephemeral and everything it
  /// will reveal. The code is length-prefixed because it is variable and is
  /// not last; the name is last.
  Future<Uint8List> _commitment(Uint8List ephPub) {
    final code = utf8.encode(contactCode);
    return sha256Bytes(concatBytes([
      utf8.encode(_commitCtx),
      ephPub,
      u16be(code.length),
      code,
      utf8.encode(displayName ?? ''),
    ]));
  }

  Map<String, Object?> _reveal() => {
        'code': contactCode,
        if (displayName != null) 'name': displayName,
      };
}

/// A completed ceremony: the channel, the confirmation string, and who the
/// other side turned out to be.
class ConnectSession {
  final Uint8List channelKey;

  /// Eight digits, `dddd dddd`. Both sides show the same; two humans compare
  /// them over a channel where they recognise each other.
  final String sas;

  /// The peer's identity, as revealed and checked against its commitment.
  final ConnectIdentity peer;

  ConnectSession(
      {required this.channelKey, required this.sas, required this.peer});
}

/// The side that made the invite. Sends messages 1 and 3.
class ConnectInviter {
  final ConnectCode code;
  final ConnectIdentity me;
  final Uint8List ephSeed, ephPub;

  Uint8List? _dh;
  Uint8List? _channelKey;
  Uint8List? _peerEph;
  Uint8List? _peerCommitment;

  ConnectInviter._(this.code, this.me, this.ephSeed, this.ephPub);

  static Future<ConnectInviter> create(
      {required ConnectIdentity me, ConnectCode? code}) async {
    final seed = randomBytes(32);
    final pub = Uint8List.fromList(
        (await (await _x.newKeyPairFromSeed(seed)).extractPublicKey()).bytes);
    return ConnectInviter._(code ?? ConnectCode.generate(), me, seed, pub);
  }

  /// Message 1: the commitment, and nothing else.
  Future<Map<String, Object?>> commit() async =>
      {'c': b64(await me._commitment(ephPub))};

  /// Message 3, from the acceptor's reply (message 2): this side's opening,
  /// with its identity sealed under the channel the reply completes.
  Future<Map<String, Object?>> open(Map<String, Object?> reply) async {
    final eph = _need(reply, 'ephx');
    final commitment = _need(reply, 'c');
    if (eph.length != 32 || commitment.length != 32) {
      throw const ConnectAbort('malformed reply');
    }
    _peerEph = eph;
    _peerCommitment = commitment;
    _dh = await _dhOf(ephSeed, eph);
    _channelKey = await _deriveChannelKey(_dh!);
    return {
      'ephx': b64(ephPub),
      'blob': b64(await _seal(_channelKey!, me._reveal())),
    };
  }

  /// Message 4: the acceptor's sealed reveal. Checks it against the
  /// commitment it made in message 2, and completes the ceremony.
  Future<ConnectSession> complete(Map<String, Object?> reveal) async {
    final key = _channelKey;
    if (key == null) {
      throw const ConnectAbort('complete() before open(): out of order');
    }
    final peer = await _openReveal(key, reveal);
    if (!constantTimeEquals(
        await peer._commitment(_peerEph!), _peerCommitment!)) {
      throw const ConnectAbort(
          'the other side revealed something it had not committed to');
    }
    return ConnectSession(
      channelKey: key,
      sas: await _deriveSas(_dh!, me, ephPub, peer, _peerEph!),
      peer: peer,
    );
  }
}

/// The side that opened the invite. Sends messages 2 and 4.
class ConnectAcceptor {
  final ConnectIdentity me;
  final Uint8List _ephSeed, _ephPub, _peerCommitment;

  ConnectAcceptor._(this.me, this._ephSeed, this._ephPub, this._peerCommitment);

  Uint8List get ephPub => _ephPub;

  /// Message 2: a fresh ephemeral and this side's own commitment, chosen
  /// while holding only a hash of the inviter's — which is what stops either
  /// side steering the confirmation string.
  static Future<(Map<String, Object?>, ConnectAcceptor)> reply(
      Map<String, Object?> commit,
      {required ConnectIdentity me}) async {
    final c = _need(commit, 'c');
    if (c.length != 32) throw const ConnectAbort('malformed commitment');
    final seed = randomBytes(32);
    final pub = Uint8List.fromList(
        (await (await _x.newKeyPairFromSeed(seed)).extractPublicKey()).bytes);
    final acceptor = ConnectAcceptor._(me, seed, pub, c);
    return (
      {'ephx': b64(pub), 'c': b64(await me._commitment(pub))},
      acceptor,
    );
  }

  /// Message 3 in, message 4 out: check the inviter's opening against its
  /// commitment, then reveal this side's identity over the channel.
  Future<(Map<String, Object?>, ConnectSession)> accept(
      Map<String, Object?> open) async {
    final eph = _need(open, 'ephx');
    if (eph.length != 32) throw const ConnectAbort('malformed opening');
    final dh = await _dhOf(_ephSeed, eph);
    final key = await _deriveChannelKey(dh);
    final peer = await _openReveal(key, open);
    if (!constantTimeEquals(await peer._commitment(eph), _peerCommitment)) {
      throw const ConnectAbort(
          'the other side revealed something it had not committed to');
    }
    return (
      {'blob': b64(await _seal(key, me._reveal()))},
      ConnectSession(
        channelKey: key,
        sas: await _deriveSas(dh, peer, eph, me, _ephPub),
        peer: peer,
      ),
    );
  }
}

// ---------------------------------------------------------------------------

Uint8List _need(Map<String, Object?> j, String k) {
  final v = j[k];
  if (v is! String) throw ConnectAbort('missing "$k"');
  try {
    return unb64(v);
  } on FormatException {
    throw ConnectAbort('malformed "$k"');
  }
}

Future<Uint8List> _dhOf(Uint8List seed, Uint8List peerPub) async {
  final s = await _x.sharedSecretKey(
    keyPair: await _x.newKeyPairFromSeed(seed),
    remotePublicKey: SimplePublicKey(peerPub, type: KeyPairType.x25519),
  );
  return Uint8List.fromList(await s.extractBytes());
}

Future<Uint8List> _deriveChannelKey(Uint8List dh) async {
  final k = await Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
    secretKey: SecretKey(dh),
    nonce: Uint8List(32),
    info: utf8.encode(_channelCtx),
  );
  return Uint8List.fromList(await k.extractBytes());
}

/// Eight digits over BOTH identities and BOTH ephemerals, with the two parties
/// in canonical order (by account key) so the string is a function of the pair
/// rather than of who invited whom.
///
/// Every field is fixed-length, so the concatenation is unambiguous. The digits
/// come from seven bytes because the modulo of a 31-bit value by 10^8 is
/// visibly biased, and the width is the point: with both sides committed, an
/// attacker in the middle has one blind guess, and it should be a bad one.
Future<String> _deriveSas(Uint8List dh, ConnectIdentity a, Uint8List ephA,
    ConnectIdentity b, Uint8List ephB) async {
  final aFirst = _lexLess(a.accountEdPub, b.accountEdPub);
  final lo = aFirst ? a : b, hi = aFirst ? b : a;
  final loEph = aFirst ? ephA : ephB, hiEph = aFirst ? ephB : ephA;
  final k = await Hkdf(hmac: Hmac.sha256(), outputLength: 8).deriveKey(
    secretKey: SecretKey(dh),
    nonce: concatBytes([loEph, hiEph]),
    info: concatBytes([
      utf8.encode(_sasCtx),
      lo.accountEdPub,
      lo.pqCommit,
      hi.accountEdPub,
      hi.pqCommit,
    ]),
  );
  final o = await k.extractBytes();
  var n = 0;
  for (var i = 0; i < 7; i++) {
    n = (n << 8) | o[i];
  }
  final d = (n % 100000000).toString().padLeft(8, '0');
  return '${d.substring(0, 4)} ${d.substring(4)}';
}

bool _lexLess(Uint8List a, Uint8List b) {
  final n = a.length < b.length ? a.length : b.length;
  for (var i = 0; i < n; i++) {
    if (a[i] != b[i]) return a[i] < b[i];
  }
  return a.length < b.length;
}

Future<Uint8List> _seal(Uint8List key, Map<String, Object?> payload) async {
  final box = await _aead.encrypt(
      Uint8List.fromList(utf8.encode(jsonEncode(payload))),
      secretKey: SecretKey(key),
      nonce: randomBytes(12));
  return Uint8List.fromList(box.concatenation());
}

Future<ConnectIdentity> _openReveal(
    Uint8List key, Map<String, Object?> frame) async {
  final sealed = _need(frame, 'blob');
  final Uint8List clear;
  try {
    clear = Uint8List.fromList(await _aead.decrypt(
        SecretBox.fromConcatenation(sealed, nonceLength: 12, macLength: 16),
        secretKey: SecretKey(key)));
  } catch (_) {
    throw const ConnectAbort('the sealed reveal did not open');
  }
  final Map<String, Object?> j;
  try {
    j = (jsonDecode(utf8.decode(clear)) as Map).cast<String, Object?>();
  } catch (_) {
    throw const ConnectAbort('malformed reveal');
  }
  final code = j['code'];
  if (code is! String) throw const ConnectAbort('reveal carries no code');
  try {
    return await ConnectIdentity.fromCode(code, displayName: j['name'] as String?);
  } on FormatException catch (e) {
    throw ConnectAbort('reveal carries an unusable contact code: ${e.message}');
  }
}
