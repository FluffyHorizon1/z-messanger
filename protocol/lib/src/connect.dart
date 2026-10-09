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
///
/// **An invite of version 2 is bound to its secret** (ADR 0024, PROTOCOL
/// §20.8). In version 1 the secret named the two mailboxes and nothing else:
/// the frames are plaintext, so whoever carries them — the relay, or the CDN
/// in front of it — could run one leg with each side under keys of its own,
/// and only a comparison of the digits would show it. Version 2 keys both
/// commitments and the channel with a key derived from the secret, so that
/// only someone holding the invite can produce a frame either side will
/// take: a carrier that substitutes them stops the ceremony before either
/// side has the other's identity. What remains is the person who holds the
/// link — the bearer token (R23) — which is what the digits are for.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'identity_v3.dart';
import 'util.dart';

const String _rendezvousCtx = 'z-connect-rendezvous-v1:';
const String _channelCtx = 'z-connect-channel-v1';
const String _sasCtx = 'z-connect-sas-v1';
const String _commitCtx = 'z-connect-commit-v1:';

// Version 2 (ADR 0024, §20.8): every value that is computed differently has
// a context of its own, so nothing of one version can be read as the other.
const String _rendezvousCtxV2 = 'z-connect-rendezvous-v2:';
const String _channelCtxV2 = 'z-connect-channel-v2';
const String _sasCtxV2 = 'z-connect-sas-v2';
const String _commitCtxV2 = 'z-connect-commit-v2:';

/// The context of a version-2 invite's key, derived from its secret
/// ([ConnectCode.inviteKey]), which keys both commitments and salts the
/// channel key (§20.8).
const String connectInviteKeyCtx = 'z-connect-invite-v2';

/// The context the throwaway relay mailboxes are derived from (17.2). Here
/// rather than in the transport so every context string for this ceremony is
/// in one place and visibly disjoint from `z-pair-*`.
const String connectRelayCtx = 'z-connect-relay-v1:';

/// The same for an invite of version 2: its mailboxes are not the ones a
/// version-1 invite of the same ten bytes names, so the two versions never
/// meet in a mailbox — a client that runs one cannot be made to answer, or
/// to wait on, the other (§20.8).
const String connectRelayCtxV2 = 'z-connect-relay-v2:';

/// The invite version this library mints ([ConnectCode.generate]).
///
/// A client that mints version 2 never runs version 1 for it: there is no
/// fallback, because the party that would choose to fall back is the one in
/// the middle (ADR 0009's "Rejected", ADR 0024). Version 1 is still
/// RECEIVED — an invite an older client made works as it always did — and
/// that is the whole compatibility surface.
const int connectInviteVersion = 2;

/// The first character of both renderings of a version-2 invite, `9`.
///
/// Not in RFC 4648's base32 alphabet, so every parser from before ADR 0024
/// refuses a version-2 invite outright — "not a connect code" — rather than
/// running version 1 on its ten bytes and waiting on mailboxes nobody
/// answers. Among the four characters base32 lacks (`0 1 8 9`) it is the
/// one that reads as itself: `0` is `O`, `1` is `I` or `L`, `8` is `B`.
const String connectV2Marker = '9';

/// Where a `/i#…` invite link points by default.
const String connectLinkHost = 'www.zmessengers.com';

/// The group bit: an optional member of a sealed reveal (ADR 0020, §20.3),
/// `0` or `1` and nothing else.
///
/// In message 3 it is the inviter saying whether the invite also brings the
/// acceptor into a group — not which group, not its name, not its size: the
/// acceptor's screen says so before the digits, and learns the rest from the
/// group's own invite once there is a session to carry it. In message 4 it
/// is the acceptor repeating what it read in message 3, which is also how
/// the inviter learns that the acceptor's client knows what the bit means.
///
/// A client that implements it writes it in EVERY reveal, `0` as readily as
/// `1`. Connect frames are attributed sends with the JSON as their payload,
/// not sealed envelopes padded to a bucket (§20.5), so the relay sees each
/// frame's exact length — and a member written only when a group is
/// attached would be a group invite announcing itself by eight bytes. A
/// client from before ADR 0020 neither writes nor reads it (§14), and
/// [ConnectInviter.create] and [ConnectAcceptor.reply] produce that client's
/// bytes when not asked for the bit — with a version-1 code, the bytes that
/// keep `vectors/connect/connect.json` what it was.
const String connectGroupMember = 'grp';

/// RFC 4648 base32, as code units — what [ConnectCode.parse] will accept.
final Set<int> _b32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.codeUnits.toSet();

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
///
/// [version] is part of the invite, carried in both renderings: a version-2
/// invite starts with [connectV2Marker] (`9ABCD-EFGHI-JKLMN-OP`), a
/// version-1 invite is base32 and nothing else, as it always was. The
/// version travels with the secret, outside the relay, because the relay is
/// the party a version read from the frames could be chosen by.
class ConnectCode {
  final Uint8List secret;

  /// 1 — the ceremony as ADR 0009 built it — or 2, bound to the secret
  /// (ADR 0024). The constructor's default is 1: ten bytes on their own, as
  /// every record and vector from before ADR 0024 holds them, are a
  /// version-1 invite. [generate] mints [connectInviteVersion].
  final int version;

  ConnectCode(this.secret, {this.version = 1}) {
    if (secret.length != 10) {
      throw const FormatException('a connect code is 10 bytes');
    }
    if (version != 1 && version != 2) {
      throw const FormatException('not an invite version this build knows');
    }
  }

  static ConnectCode generate({int version = connectInviteVersion}) =>
      ConnectCode(randomBytes(10), version: version);

  /// Whether this invite binds its secret into the ceremony (version 2).
  bool get bound => version >= 2;

  String get text {
    if (!bound) return base32Groups(secret);
    final raw = '$connectV2Marker${base32Encode(secret)}';
    return [
      for (var i = 0; i < raw.length; i += 5)
        raw.substring(i, i + 5 > raw.length ? raw.length : i + 5)
    ].join('-');
  }

  /// A printed code back into its ten bytes, and its version.
  ///
  /// [base32Decode] skips whatever it does not recognise, which is right for
  /// something read down a phone line — dashes, spaces, the wrong case — and
  /// wrong for deciding whether a string IS a code. Any URL, and most
  /// sentences, contain enough letters between the punctuation to make ten
  /// bytes; a public entry point that turns those into invites (17.3b: any
  /// app on the device can send a VIEW intent) would fill the user's list
  /// with ceremonies nobody can answer. So the separators are named, and
  /// anything else is a refusal rather than a character to skip.
  ///
  /// A code that starts with [connectV2Marker] is version 2, and must then
  /// be exactly the sixteen base32 characters of its ten bytes: no build has
  /// ever written one any other way, so there is no leniency to keep. One
  /// that does not is read by the version-1 rule, unchanged — which is also
  /// what every build from before ADR 0024 does with a version-2 code: the
  /// marker is not base32, so it refuses it.
  static ConnectCode parse(String code) {
    const separators = [0x2D, 0x20, 0x09, 0x0A, 0x0D]; // - space tab nl cr
    final chars = <int>[
      for (final ch in code.toUpperCase().codeUnits)
        if (!separators.contains(ch)) ch
    ];
    if (chars.isNotEmpty && chars.first == connectV2Marker.codeUnitAt(0)) {
      final rest = chars.sublist(1);
      if (rest.length != 16 || !rest.every(_b32Chars.contains)) {
        throw const FormatException('not a connect code');
      }
      return ConnectCode(base32Decode(String.fromCharCodes(rest)), version: 2);
    }
    for (final ch in chars) {
      if (!_b32Chars.contains(ch)) {
        throw const FormatException('not a connect code');
      }
    }
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

  /// The single mailbox id this code names, disjoint from a pairing code's by
  /// context — so a connect code can never address a pairing rendezvous or
  /// the reverse, which is the property `connect_test.dart` (6) asserts.
  ///
  /// Traffic does not go here. The transport (17.2) splits the rendezvous
  /// into **two** mailboxes, one per role, derived from the same secret under
  /// [connectRelayCtx] — see `mailboxIdentity`, and `connect/mailboxes.json`
  /// for the bytes. Two rather than one so that neither side is handed back
  /// its own frames on the relay's flush, and so the pair the relay sees is
  /// the shape §20 describes. A version-2 code names its own, under a
  /// context of its own.
  Future<String> rendezvousRoutingId() async {
    final ctx = bound ? _rendezvousCtxV2 : _rendezvousCtx;
    return b64url(
        await sha256Bytes(concatBytes([utf8.encode(ctx), secret])));
  }

  Future<Uint8List>? _inviteKey;

  /// The key a version-2 invite binds into its ceremony (§20.8):
  /// HKDF-SHA256 of the secret, an empty salt, [connectInviteKeyCtx] as its
  /// info, 32 bytes. It keys both commitments and salts the channel key, so
  /// nobody without the invite can make a frame either side will take — the
  /// relay included, which sees every frame and never the invite.
  ///
  /// Null for version 1, which binds nothing: that is what ADR 0024 changes,
  /// and what an invite made by an older client still is.
  Future<Uint8List?> inviteKey() {
    if (!bound) return Future.value(null);
    return _inviteKey ??= _deriveInviteKey(secret);
  }

  static Future<Uint8List> _deriveInviteKey(Uint8List secret) async {
    final k = await Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
      secretKey: SecretKey(secret),
      nonce: Uint8List(0),
      info: utf8.encode(connectInviteKeyCtx),
    );
    return Uint8List.fromList(await k.extractBytes());
  }
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
  ///
  /// Through `scanContactCode`, so this and a scan cannot disagree about what
  /// a code IS. Until 2026-09-14 this was a try-v3/catch-`FormatException`
  /// ladder of its own, and the fallback did not read `pqc`, `acct` or
  /// `cert` at all — so any malformed v3 member (a stale certificate, a
  /// stripped commitment, a truncated account key) quietly produced an
  /// identity anchored on the DEVICE key with a commitment of 32 zero bytes.
  ///
  /// That is worse than it sounds, because of what the digits are for. Both
  /// sides degrade the same way, so `_deriveSas` agrees, the humans compare
  /// eight digits that match, and the app records the contact as verified —
  /// over an identity the comparison never covered. `scanContactCode` has
  /// refused these codes since v3 shipped (`_carriesV3Members` exists for
  /// exactly this), and the contact is added by re-scanning the same string,
  /// so the record could be account-anchored while the number that "verified"
  /// it was the device's. The two paths now share one rule.
  static Future<ConnectIdentity> fromCode(String contactCode,
      {String? displayName}) async {
    final scanned = await scanContactCode(contactCode);
    final v3 = scanned.v3;
    if (v3 != null) {
      return ConnectIdentity._(
          contactCode, displayName ?? v3.displayName, v3.accountEdPub, v3.pqCommit);
    }
    // A genuinely classical code — one that carries no v3 member at all. No
    // post-quantum commitment to bind, and by §3.5 the device in it *is* the
    // account. A code that carries one and fails to decode does not reach
    // here; it raises, which is the whole change.
    final b = scanned.classical;
    return ConnectIdentity._(
        contactCode, displayName ?? b.displayName, b.edPub, _noPq);
  }

  /// The bytes a commitment covers: this side's ephemeral and everything it
  /// will reveal. The code is length-prefixed because it is variable and is
  /// not last; the name is last.
  ///
  /// With an [inviteKey] (version 2, §20.8) the commitment is keyed:
  /// HMAC-SHA256 under the invite key, over the same fields after a context
  /// of its own. Then only a holder of the invite can make a commitment
  /// either side will hold the other's reveal to — and only a holder can test
  /// a guess against one. Unkeyed, anyone with the frames and a candidate
  /// contact code could confirm who had committed, as soon as message 3 had
  /// shown the ephemeral.
  Future<Uint8List> _commitment(Uint8List ephPub, Uint8List? inviteKey) async {
    final code = utf8.encode(contactCode);
    final fields = <List<int>>[
      ephPub,
      u16be(code.length),
      code,
      utf8.encode(displayName ?? ''),
    ];
    if (inviteKey == null) {
      return sha256Bytes(concatBytes([utf8.encode(_commitCtx), ...fields]));
    }
    final mac = await Hmac.sha256().calculateMac(
        concatBytes([utf8.encode(_commitCtxV2), ...fields]),
        secretKey: SecretKey(inviteKey));
    return Uint8List.fromList(mac.bytes);
  }

  /// What this side seals into its message 3 or 4. [group] is the group
  /// bit ([connectGroupMember]), left out when null — the reveal a client
  /// before ADR 0020 sends. It is not part of the commitment: the
  /// commitment binds who this side says it is, and the bit travels inside
  /// the AEAD under the channel key, where the only party who could set it
  /// is one who holds that key — a machine in the middle, which is what the
  /// digits exist to catch.
  Map<String, Object?> _reveal({bool? group}) => {
        'code': contactCode,
        if (displayName != null) 'name': displayName,
        if (group != null) connectGroupMember: group ? 1 : 0,
      };
}

/// The label of a ceremony's go-ahead tag ([connectGoAheadTag]).
const String connectGoAheadLabel = 'z-connect-gjoin-v1';

/// How many bytes a go-ahead tag is ([connectGoAheadTag]).
const int connectGoAheadTagBytes = 16;

/// The go-ahead tag of the ceremony whose channel key is [channelKey] (ADR
/// 0020, PROTOCOL §20.6): HKDF-SHA256 with the channel key as its input, a
/// salt of 32 zero bytes (as the channel key's own derivation has) and
/// [connectGoAheadLabel] as its info, [connectGoAheadTagBytes] bytes long.
///
/// A group link's go-ahead (`gjoin`, §6.2) carries it, so a go-ahead answers
/// the one ceremony it was given on: both ends of that ceremony compute the
/// same tag, and nobody else can — not the relay, not a later or an earlier
/// ceremony between the same two people, whose channel key is another. A
/// go-ahead without the tag could not say which link it answered, and the
/// inviter took one given for an earlier link as the answer to a later one
/// the joiner had stopped.
///
/// Derived, rather than an HMAC keyed with the channel key itself, so that
/// the key which seals the two reveals is used for that and nothing else.
/// Until 2026-10-03 the tag was HMAC-SHA256 under the channel key directly.
Future<Uint8List> connectGoAheadTag(Uint8List channelKey) async {
  final hkdf =
      Hkdf(hmac: Hmac.sha256(), outputLength: connectGoAheadTagBytes);
  final k = await hkdf.deriveKey(
    secretKey: SecretKey(channelKey),
    nonce: Uint8List(32),
    info: utf8.encode(connectGoAheadLabel),
  );
  return Uint8List.fromList(await k.extractBytes());
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

  /// The group bit ([connectGroupMember]) as the PEER's reveal stated it,
  /// or null when its reveal carried none — a client from before ADR 0020,
  /// or a side that was not asked to read it.
  ///
  /// On the acceptor's side this is the inviter saying whether a group is
  /// attached: true is what the acceptor's screen must announce before the
  /// digits. On the inviter's side it is the acceptor repeating what it
  /// read, so null there means the acceptor's client cannot know the invite
  /// was to a group — and could not have told its person so.
  final bool? group;

  ConnectSession(
      {required this.channelKey,
      required this.sas,
      required this.peer,
      this.group});

  /// This ceremony's go-ahead tag ([connectGoAheadTag]).
  Future<Uint8List> goAheadTag() => connectGoAheadTag(channelKey);
}

/// The side that made the invite. Sends messages 1 and 3.
class ConnectInviter {
  final ConnectCode code;
  final ConnectIdentity me;
  final Uint8List ephSeed, ephPub;

  /// The group bit this side seals into message 3 ([connectGroupMember]):
  /// whether the invite also brings the acceptor into a group. Null writes
  /// no member at all and reads none back — exactly what a client before
  /// ADR 0020 does, which is what the recorded vectors are.
  final bool? group;

  Uint8List? _dh;
  Uint8List? _channelKey;
  Uint8List? _peerEph;
  Uint8List? _peerCommitment;

  ConnectInviter._(this.code, this.me, this.ephSeed, this.ephPub, this.group);

  /// A new invite, made with [code] or, without one, with a fresh code of
  /// [connectInviteVersion] — so an invite this library makes on its own is
  /// bound to its secret (§20.8). A version-1 [code] runs the ceremony as
  /// ADR 0009 built it, which is what the recorded vectors are.
  static Future<ConnectInviter> create(
      {required ConnectIdentity me, ConnectCode? code, bool? group}) async {
    final seed = randomBytes(32);
    final pub = Uint8List.fromList(
        (await (await _x.newKeyPairFromSeed(seed)).extractPublicKey()).bytes);
    return ConnectInviter._(
        code ?? ConnectCode.generate(), me, seed, pub, group);
  }

  /// Everything needed to pick this ceremony up after the app was closed.
  ///
  /// An invite sent at lunchtime may be opened at midnight, so the ceremony
  /// cannot live only in memory the way device pairing's can — that is the
  /// whole difference between linking two devices you are holding and
  /// reaching someone three time zones away (17.2).
  ///
  /// `cv` is the invite's version, written only for version 2, so a record
  /// of a version-1 invite is what it was before ADR 0024 — and one written
  /// before then reads back as the version-1 invite it is.
  Map<String, Object?> toJson() => {
        'code': b64(code.secret),
        if (code.version != 1) 'cv': code.version,
        'me': me.contactCode,
        if (me.displayName != null) 'name': me.displayName,
        'eph': b64(ephSeed),
        if (group != null) 'grp': group,
        if (_peerEph != null) 'peerEph': b64(_peerEph!),
        if (_peerCommitment != null) 'peerC': b64(_peerCommitment!),
      };

  static Future<ConnectInviter> fromJson(Map<String, Object?> j) async {
    final me = await ConnectIdentity.fromCode(j['me'] as String,
        displayName: j['name'] as String?);
    final seed = unb64(j['eph'] as String);
    final pub = Uint8List.fromList(
        (await (await _x.newKeyPairFromSeed(seed)).extractPublicKey()).bytes);
    final grp = j['grp'];
    final code = ConnectCode(unb64(j['code'] as String),
        version: connectRecordVersion(j['cv']));
    final out =
        ConnectInviter._(code, me, seed, pub, grp is bool ? grp : null);
    final pe = j['peerEph'], pc = j['peerC'];
    if (pe is String && pc is String) {
      try {
        final dh = await _dhOf(seed, unb64(pe));
        out._peerEph = unb64(pe);
        out._peerCommitment = unb64(pc);
        out._dh = dh;
        out._channelKey = await _deriveChannelKey(dh, await code.inviteKey());
      } on ConnectAbort {
        // A reply a build from before the small-order check took in. Read
        // back unopened: the run is spent or about to be, and the next step
        // meets the same refusal — rather than one bad record making every
        // pending invite beside it unreadable.
      }
    }
    return out;
  }

  /// True once [open] has been called, so a resumed run knows where it is.
  bool get opened => _channelKey != null;

  /// Message 1: the commitment, and nothing else.
  Future<Map<String, Object?>> commit() async =>
      {'c': b64(await me._commitment(ephPub, await code.inviteKey()))};

  /// Message 3, from the acceptor's reply (message 2): this side's opening,
  /// with its identity sealed under the channel the reply completes.
  Future<Map<String, Object?>> open(Map<String, Object?> reply) async {
    final eph = _need(reply, 'ephx');
    final commitment = _need(reply, 'c');
    if (eph.length != 32 || commitment.length != 32) {
      throw const ConnectAbort('malformed reply');
    }
    // The DH first: a reply this side refuses ([_dhOf]) is never written
    // into the state a resumed run reads back.
    final dh = await _dhOf(ephSeed, eph);
    _peerEph = eph;
    _peerCommitment = commitment;
    _dh = dh;
    _channelKey = await _deriveChannelKey(dh, await code.inviteKey());
    return {
      'ephx': b64(ephPub),
      'blob': b64(await _seal(_channelKey!, me._reveal(group: group))),
    };
  }

  /// Message 4: the acceptor's sealed reveal. Checks it against the
  /// commitment it made in message 2, and completes the ceremony.
  ///
  /// With a group bit of its own, this side also reads the acceptor's
  /// repetition of it ([ConnectSession.group]). Absent is a client from
  /// before ADR 0020 and is not an error. Present and different is: the two
  /// sides disagree about what this ceremony is, which only happens when
  /// message 3 did not arrive as it was sent, and §20.3's rule for a
  /// disagreement is to abort, not to carry on at a lower assurance.
  Future<ConnectSession> complete(Map<String, Object?> reveal) async {
    final key = _channelKey;
    if (key == null) {
      throw const ConnectAbort('complete() before open(): out of order');
    }
    final (peer, echo) =
        await _openReveal(key, reveal, readGroup: group != null);
    if (!constantTimeEquals(
        await peer._commitment(_peerEph!, await code.inviteKey()),
        _peerCommitment!)) {
      throw const ConnectAbort(
          'the other side revealed something it had not committed to');
    }
    if (echo != null && echo != group) {
      throw const ConnectAbort(
          'the other side read a different group bit from the one sent');
    }
    return ConnectSession(
      channelKey: key,
      sas: await _deriveSas(_dh!, me, ephPub, peer, _peerEph!,
          version: code.version),
      peer: peer,
      group: echo,
    );
  }
}

/// The side that opened the invite. Sends messages 2 and 4.
class ConnectAcceptor {
  final ConnectIdentity me;

  /// The invite this side was handed: its version decides how every value
  /// of the ceremony is computed, and a version-2 invite's key is in all of
  /// them (§20.8).
  final ConnectCode code;

  final Uint8List _ephSeed, _ephPub, _peerCommitment;

  /// Whether this side reads the group bit in message 3 and repeats it in
  /// message 4 ([connectGroupMember]). False neither reads nor writes it —
  /// exactly a client from before ADR 0020, which is what the recorded
  /// vectors are and what a test standing in for such a client needs.
  final bool groupAware;

  ConnectAcceptor._(this.me, this.code, this._ephSeed, this._ephPub,
      this._peerCommitment, this.groupAware);

  Uint8List get ephPub => _ephPub;

  /// As [ConnectInviter.toJson]: the acceptor may also be closed and
  /// reopened between the inviter's messages. The invite itself is not in
  /// it: the run that holds this side keeps it, and hands it back to
  /// [fromJson].
  Map<String, Object?> toJson() => {
        'me': me.contactCode,
        if (me.displayName != null) 'name': me.displayName,
        'eph': b64(_ephSeed),
        'peerC': b64(_peerCommitment),
        if (groupAware) 'ga': true,
      };

  static Future<ConnectAcceptor> fromJson(Map<String, Object?> j,
      {required ConnectCode code}) async {
    final me = await ConnectIdentity.fromCode(j['me'] as String,
        displayName: j['name'] as String?);
    final seed = unb64(j['eph'] as String);
    final pub = Uint8List.fromList(
        (await (await _x.newKeyPairFromSeed(seed)).extractPublicKey()).bytes);
    return ConnectAcceptor._(
        me, code, seed, pub, unb64(j['peerC'] as String), j['ga'] == true);
  }

  /// Message 2: a fresh ephemeral and this side's own commitment, chosen
  /// while holding only a hash of the inviter's — which is what stops either
  /// side steering the confirmation string.
  ///
  /// [code] is the invite this side was handed. Required: the version, and
  /// for version 2 the key, come from it and from nowhere else — not from
  /// the frames, which whoever carries them can write.
  static Future<(Map<String, Object?>, ConnectAcceptor)> reply(
      Map<String, Object?> commit,
      {required ConnectIdentity me,
      required ConnectCode code,
      bool groupAware = false}) async {
    final c = _need(commit, 'c');
    if (c.length != 32) throw const ConnectAbort('malformed commitment');
    final seed = randomBytes(32);
    final pub = Uint8List.fromList(
        (await (await _x.newKeyPairFromSeed(seed)).extractPublicKey()).bytes);
    final acceptor = ConnectAcceptor._(me, code, seed, pub, c, groupAware);
    return (
      {
        'ephx': b64(pub),
        'c': b64(await me._commitment(pub, await code.inviteKey()))
      },
      acceptor,
    );
  }

  /// Message 3 in, message 4 out: check the inviter's opening against its
  /// commitment, then reveal this side's identity over the channel.
  ///
  /// A group-aware acceptor also reads the inviter's group bit into
  /// [ConnectSession.group] and repeats it in message 4 — `0` when the
  /// inviter wrote none, so this side's reveal is the same length whatever
  /// the invite was.
  Future<(Map<String, Object?>, ConnectSession)> accept(
      Map<String, Object?> open) async {
    final eph = _need(open, 'ephx');
    if (eph.length != 32) throw const ConnectAbort('malformed opening');
    final inviteKey = await code.inviteKey();
    final dh = await _dhOf(_ephSeed, eph);
    final key = await _deriveChannelKey(dh, inviteKey);
    final (peer, group) = await _openReveal(key, open, readGroup: groupAware);
    if (!constantTimeEquals(
        await peer._commitment(eph, inviteKey), _peerCommitment)) {
      throw const ConnectAbort(
          'the other side revealed something it had not committed to');
    }
    return (
      {
        'blob': b64(await _seal(
            key, me._reveal(group: groupAware ? (group ?? false) : null)))
      },
      ConnectSession(
        channelKey: key,
        sas: await _deriveSas(dh, peer, eph, me, _ephPub,
            version: code.version),
        peer: peer,
        group: group,
      ),
    );
  }
}

/// The invite version a stored record names in its `cv` member: absent is
/// version 1, which is every record written before ADR 0024. Anything this
/// build does not know is refused rather than read as one it does.
int connectRecordVersion(Object? cv) {
  if (cv == null || cv == 1) return 1;
  if (cv == 2) return 2;
  throw const FormatException('not an invite version this build knows');
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

/// X25519 of this side's ephemeral with the peer's, refusing an all-zero
/// result (RFC 7748 §6.1).
///
/// A peer "ephemeral" of small order — the zero point, or any of the few
/// points of order 2, 4 or 8, in any of their encodings — makes the output
/// all zeros whatever this side's key is, so the channel key would be
/// HKDF of zeros: a constant anyone can compute, the same on every leg a
/// machine in the middle runs that way, and with it the go-ahead tag of
/// every such ceremony. An honest side never sends one (its ephemeral is a
/// clamped scalar times the base point), so refusing it costs an honest
/// ceremony nothing; and each side checks the output it computes, so the
/// refusal holds on both. Checked in constant time, as the RFC asks.
Future<Uint8List> _dhOf(Uint8List seed, Uint8List peerPub) async {
  final s = await _x.sharedSecretKey(
    keyPair: await _x.newKeyPairFromSeed(seed),
    remotePublicKey: SimplePublicKey(peerPub, type: KeyPairType.x25519),
  );
  final out = Uint8List.fromList(await s.extractBytes());
  var any = 0;
  for (final b in out) {
    any |= b;
  }
  if (any == 0) {
    throw const ConnectAbort(
        'the other side\'s ephemeral key is a point of small order');
  }
  return out;
}

/// The channel key: HKDF-SHA256 of the X25519 output.
///
/// Version 1 salts it with 32 zero bytes, so it is a function of the two
/// ephemerals alone — and a party that substitutes both of them, which is
/// what carrying the frames lets it do, holds a key for each leg. Version 2
/// salts it with the invite key ([ConnectCode.inviteKey]) under a context of
/// its own (§20.8), so a key for either leg also needs the invite: whoever
/// substitutes an ephemeral without it holds a key neither side has, and the
/// reveal it seals, or the one it is sent, does not open.
Future<Uint8List> _deriveChannelKey(Uint8List dh, Uint8List? inviteKey) async {
  final k = await Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
    secretKey: SecretKey(dh),
    nonce: inviteKey ?? Uint8List(32),
    info: utf8.encode(inviteKey == null ? _channelCtx : _channelCtxV2),
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
///
/// [version] 2 computes the same thing under a context of its own (§20.8),
/// so digits of one version are never the digits of the other.
Future<String> _deriveSas(Uint8List dh, ConnectIdentity a, Uint8List ephA,
    ConnectIdentity b, Uint8List ephB,
    {required int version}) async {
  final aFirst = _lexLess(a.accountEdPub, b.accountEdPub);
  final lo = aFirst ? a : b, hi = aFirst ? b : a;
  final loEph = aFirst ? ephA : ephB, hiEph = aFirst ? ephB : ephA;
  final k = await Hkdf(hmac: Hmac.sha256(), outputLength: 8).deriveKey(
    secretKey: SecretKey(dh),
    nonce: concatBytes([loEph, hiEph]),
    info: concatBytes([
      utf8.encode(version == 1 ? _sasCtx : _sasCtxV2),
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

/// Open a sealed reveal: the identity it carries, and — when [readGroup] —
/// its group bit ([connectGroupMember]), null when it carries none. A side
/// that does not read the bit ignores the member entirely, as a client from
/// before ADR 0020 does. One that does refuses a value other than 0 or 1,
/// the same answer a malformed name gets: a field that is not what it must
/// be is an abort, not a value to work around (§20.3).
Future<(ConnectIdentity, bool?)> _openReveal(
    Uint8List key, Map<String, Object?> frame,
    {required bool readGroup}) async {
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
  final name = j['name'];
  if (name != null && name is! String) {
    throw const ConnectAbort('reveal carries a malformed name');
  }
  bool? group;
  final grp = j[connectGroupMember];
  if (readGroup && grp != null) {
    if (grp is! int || (grp != 0 && grp != 1)) {
      throw const ConnectAbort('reveal carries a malformed group bit');
    }
    group = grp == 1;
  }
  try {
    return (
      await ConnectIdentity.fromCode(code, displayName: name as String?),
      group
    );
  } on FormatException catch (e) {
    // A code the ceremony cannot read is an abort, never a weaker identity:
    // the invite is spent and the pair start again, which costs a minute and
    // is the only answer that cannot be steered.
    throw ConnectAbort('reveal carries an unusable contact code: ${e.message}');
  }
}
