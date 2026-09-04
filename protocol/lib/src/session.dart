import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'identity.dart';
import 'messages.dart';
import 'pq.dart';
import 'ratchet.dart';
import 'util.dart';

/// Session establishment and management for one conversation (one contact).
///
/// Handshake ("X3DH without server-stored prekeys" — there is no server
/// storage in Z, so the responder's identity X25519 key stands in for the
/// signed prekey; both identity keys were exchanged and verified out-of-band
/// via contact codes):
///
///   SK = HKDF( 0xFF*32 || DH(IK_A, IK_B) || DH(EK_A, IK_B) )
///
/// The initiator's ephemeral key EK_A provides fresh entropy; the double
/// ratchet takes over from the first reply, adding forward secrecy and
/// post-compromise healing on every round trip.

const String _x3dhInfo = 'Z-X3DH-v1';
const String _adContext = 'Z-AD-v1';

final _x25519 = X25519();

class UnknownSessionException implements Exception {
  final String sid;
  UnknownSessionException(this.sid);
  @override
  String toString() =>
      'UnknownSessionException: no local state for session $sid';
}

Future<Uint8List> _deriveSk(Uint8List dh1, Uint8List dh2) async {
  final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
  final key = await hkdf.deriveKey(
    secretKey: SecretKey(
        concatBytes([Uint8List(32)..fillRange(0, 32, 0xff), dh1, dh2])),
    nonce: Uint8List(32), // zero salt
    info: utf8.encode(_x3dhInfo),
  );
  return Uint8List.fromList(await key.extractBytes());
}

Future<Uint8List> _deriveAd(
        Uint8List initiatorEdPub, Uint8List responderEdPub) =>
    sha256Bytes(
        concatBytes([utf8.encode(_adContext), initiatorEdPub, responderEdPub]));

Future<String> sessionIdFromEk(Uint8List ekPub) async =>
    b64url(await sha256Bytes(ekPub)).substring(0, 22);

/// One double-ratchet session. A conversation normally has exactly one; a
/// brief race where both sides initiate simultaneously can create two, which
/// [Conversation] converges deterministically.
class Session {
  final String sid;
  final String initiatorRid;
  final Uint8List ekPub;
  final RatchetState ratchet;
  bool receivedAny; // initiator stops attaching `ek` once a reply arrived
  int lastUsedMs;

  Session({
    required this.sid,
    required this.initiatorRid,
    required this.ekPub,
    required this.ratchet,
    this.receivedAny = false,
    this.lastUsedMs = 0,
  });

  Map<String, Object?> toJson() => {
        'sid': sid,
        'initiatorRid': initiatorRid,
        'ekPub': b64(ekPub),
        'ratchet': ratchet.toJson(),
        'receivedAny': receivedAny,
        'lastUsedMs': lastUsedMs,
      };

  static Session fromJson(Map<String, Object?> j) => Session(
        sid: j['sid'] as String,
        initiatorRid: j['initiatorRid'] as String,
        ekPub: unb64(j['ekPub'] as String),
        ratchet: RatchetState.fromJson(
            (j['ratchet'] as Map).cast<String, Object?>()),
        receivedAny: j['receivedAny'] as bool,
        lastUsedMs: (j['lastUsedMs'] as num).toInt(),
      );
}

class DecryptResult {
  final Uint8List plaintext;
  final String sid;
  final bool createdNewSession;

  /// v2: a ready-to-send transport payload carrying this side's ML-KEM offer,
  /// produced when the offering side has just heard from the peer for the
  /// first time. The caller sends it to the peer like any other payload
  /// (after persisting the conversation, whose state it advanced). Null when
  /// there is nothing to offer.
  final String? pqOfferPayload;

  DecryptResult(this.plaintext, this.sid, this.createdNewSession,
      {this.pqOfferPayload});
}

/// All E2E state for one contact. Serializable; the app persists it
/// (encrypted at rest) after EVERY encrypt/decrypt.
class Conversation {
  final ZIdentity me;
  final ContactBundle them;
  final String myRid;
  final String theirRid;
  final Map<String, Session> sessions;
  String? outboundSid;

  /// v2 post-quantum state, shared by every session of this conversation.
  final PqState pq;

  /// Whether this side takes part in the v2 post-quantum upgrade. Off, the
  /// conversation behaves exactly as protocol v1 (it neither offers nor
  /// accepts ML-KEM keys, but still interoperates with v2 peers, which then
  /// stay classical too). Only the v1 test-vector generator turns it off.
  final bool postQuantum;

  Conversation._(this.me, this.them, this.myRid, this.theirRid, this.sessions,
      this.outboundSid,
      {PqState? pq, this.postQuantum = true})
      : pq = pq ?? PqState();

  static Future<Conversation> create(ZIdentity me, ContactBundle them,
      {bool postQuantum = true}) async {
    return Conversation._(
        me, them, await me.routingId(), await them.routingId(), {}, null,
        postQuantum: postQuantum);
  }

  /// True if this side should proactively open the session at contact-add
  /// time (deterministic role assignment prevents most double-initiations).
  bool get isDesignatedInitiator => myRid.compareTo(theirRid) < 0;

  /// v2 roles, fixed per pair: the designated initiator ENCAPSULATES, the
  /// other side OFFERS the ML-KEM key. (Independent of which side happened to
  /// open the DH session first.)
  bool get isPqOfferer => !isDesignatedInitiator;

  /// True once both sides share the ML-KEM secret: every message from here on
  /// is protected against harvest-now-decrypt-later.
  bool get isPostQuantum => pq.established;

  String get _designatedInitiatorRid =>
      myRid.compareTo(theirRid) < 0 ? myRid : theirRid;

  void _converge() {
    // Prefer the session opened by the designated initiator; both sides apply
    // the same rule, so both settle on the same session.
    Session? preferred;
    for (final s in sessions.values) {
      if (s.initiatorRid == _designatedInitiatorRid) {
        if (preferred == null || s.lastUsedMs > preferred.lastUsedMs) {
          preferred = s;
        }
      }
    }
    if (preferred != null) {
      outboundSid = preferred.sid;
    } else if (sessions.isNotEmpty && outboundSid == null) {
      outboundSid = sessions.values.first.sid;
    }
  }

  Future<Session> _initiateSession() async {
    final ekSeed = randomBytes(32);
    final ekKp = await _x25519.newKeyPairFromSeed(ekSeed);
    final ekPub = Uint8List.fromList((await ekKp.extractPublicKey()).bytes);

    final dh1 = await _dhRaw(me.xSeed, them.xPub); // DH(IK_A, IK_B)
    final dh2 = await _dhRaw(ekSeed, them.xPub); // DH(EK_A, IK_B)
    final sk = await _deriveSk(dh1, dh2);
    final ad = await _deriveAd(me.edPub, them.edPub);

    final ratchet =
        await ratchetInitInitiator(sk: sk, theirDhPub: them.xPub, ad: ad);
    final session = Session(
      sid: await sessionIdFromEk(ekPub),
      initiatorRid: myRid,
      ekPub: ekPub,
      ratchet: ratchet,
    );
    sessions[session.sid] = session;
    _converge();
    return session;
  }

  Future<Session> _acceptSession(Uint8List ekPub) async {
    final dh1 = await _dhRaw(me.xSeed, them.xPub); // DH(IK_B, IK_A)
    final dh2 = await _dhRaw(me.xSeed, ekPub); // DH(IK_B, EK_A)
    final sk = await _deriveSk(dh1, dh2);
    final ad = await _deriveAd(them.edPub, me.edPub); // initiator first

    final ratchet = await ratchetInitResponder(
        sk: sk, myXSeed: me.xSeed, myXPub: me.xPub, ad: ad);
    final session = Session(
      sid: await sessionIdFromEk(ekPub),
      initiatorRid: theirRid,
      ekPub: Uint8List.fromList(ekPub),
      ratchet: ratchet,
    );
    sessions[session.sid] = session;
    _converge();
    return session;
  }

  static Future<Uint8List> _dhRaw(Uint8List seed, Uint8List remotePub) async {
    final kp = await _x25519.newKeyPairFromSeed(seed);
    final secret = await _x25519.sharedSecretKey(
      keyPair: kp,
      remotePublicKey: SimplePublicKey(remotePub, type: KeyPairType.x25519),
    );
    return Uint8List.fromList(await secret.extractBytes());
  }

  /// v2: if this side should offer its ML-KEM key and has not yet done so,
  /// returns the offer as an encrypted transport payload for the caller to
  /// send (it is an inner message of kind `pqek`, so a v1 peer just ignores
  /// it). The offer is made once per conversation, until [resetSessions].
  /// Persist this conversation BEFORE sending — this advances a ratchet.
  Future<String?> takePqOfferPayload({int? nowMs}) async {
    if (!postQuantum || !isPqOfferer || pq.established || pq.offered) {
      return null;
    }
    final (seed, ek) = pqGenerate();
    pq
      ..dkSeed = seed
      ..offered = true;
    final offer = InnerMessage.pqOffer(
        newMessageId(), nowMs ?? DateTime.now().millisecondsSinceEpoch, ek);
    return encrypt(offer.toBytes(), nowMs: nowMs);
  }

  /// Encrypts [plaintext] for this contact, creating a session if none
  /// exists. Returns the opaque transport payload (a base64 string the relay
  /// cannot interpret). Persist this conversation's state BEFORE sending.
  Future<String> encrypt(Uint8List plaintext, {int? nowMs}) async {
    Session? session = outboundSid == null ? null : sessions[outboundSid!];
    if (session == null || session.ratchet.cks == null) {
      // Either no session at all, or we only hold a responder session on
      // which we have not yet received anything (cannot send on it).
      final usable = sessions.values
          .where((s) => s.ratchet.cks != null)
          .toList()
        ..sort((a, b) => b.lastUsedMs.compareTo(a.lastUsedMs));
      session = usable.isNotEmpty ? usable.first : await _initiateSession();
    }
    final msg = await ratchetEncrypt(session.ratchet, plaintext, pq: pq);
    session.lastUsedMs = nowMs ?? DateTime.now().millisecondsSinceEpoch;

    final payload = <String, Object?>{
      'v': 1,
      't': 'r',
      'sid': session.sid,
      if (session.initiatorRid == myRid && !session.receivedAny)
        'ek': b64(session.ekPub),
      'h': msg.header.toJson(),
      'n': b64(msg.nonce),
      'ct': b64(msg.cipherText),
      'mac': b64(msg.mac),
    };
    return base64Encode(utf8.encode(jsonEncode(payload)));
  }

  /// Decrypts an incoming ratchet payload. May create a responder session on
  /// first contact. Throws [UnknownSessionException] if the payload
  /// references a session this device has no state for (e.g. the sender kept
  /// a session that predates our reinstall) — the app should then open a
  /// fresh session and/or surface a "session reset" notice.
  Future<DecryptResult> decrypt(String transportPayload, {int? nowMs}) async {
    final Map<String, Object?> j;
    try {
      j = jsonDecode(utf8.decode(base64Decode(transportPayload)))
          as Map<String, Object?>;
    } catch (_) {
      throw RatchetDecryptException('malformed payload');
    }
    if (j['v'] != 1 || j['t'] != 'r') {
      throw RatchetDecryptException('unsupported payload type');
    }
    final sid = j['sid'] as String;
    var created = false;

    var session = sessions[sid];
    if (session == null) {
      final ekB64 = j['ek'] as String?;
      if (ekB64 == null) throw UnknownSessionException(sid);
      final ekPub = unb64(ekB64);
      if (await sessionIdFromEk(ekPub) != sid) {
        throw RatchetDecryptException('session id does not match ek');
      }
      session = await _acceptSession(ekPub);
      created = true;
    }

    final msg = RatchetMessage(
      header: RatchetHeader.fromJson((j['h'] as Map).cast<String, Object?>()),
      nonce: unb64(j['n'] as String),
      cipherText: unb64(j['ct'] as String),
      mac: unb64(j['mac'] as String),
    );
    final plain = await ratchetDecrypt(session.ratchet, msg, pq: pq);
    session.receivedAny = true;
    session.lastUsedMs = nowMs ?? DateTime.now().millisecondsSinceEpoch;
    _converge();

    // v2: the encapsulating side acts on an inbound offer; the offering side
    // makes its offer as soon as it has heard from the peer.
    if (postQuantum && !isPqOfferer && !pq.established) _acceptPqOffer(plain);
    final offerPayload =
        isPqOfferer ? await takePqOfferPayload(nowMs: nowMs) : null;
    return DecryptResult(plain, sid, created, pqOfferPayload: offerPayload);
  }

  /// If [plain] is a `pqek` offer for the supported algorithm, encapsulate to
  /// it. Anything malformed is ignored (the peer simply stays classical).
  void _acceptPqOffer(Uint8List plain) {
    if (!InnerMessage.looksLikeKind(plain, 'pqek')) return;
    try {
      final inner = InnerMessage.fromBytes(plain);
      if (inner.data['alg'] != pqAlgorithm) return;
      final ek = unb64(inner.data['ek'] as String);
      final (ct, k) = pqEncapsulate(ek);
      pq
        ..k = k
        ..ct = ct
        ..acked = false;
    } catch (_) {
      // Not a usable offer.
    }
  }

  /// Drop sessions unused for [olderThanMs], but never the outbound one.
  void pruneStaleSessions(int nowMs, {int olderThanMs = 7 * 24 * 3600 * 1000}) {
    sessions.removeWhere(
        (sid, s) => sid != outboundSid && nowMs - s.lastUsedMs > olderThanMs);
  }

  /// Wipe all sessions (used for an explicit "reset secure session"). The
  /// post-quantum secret is dropped with them and re-established afresh.
  void resetSessions() {
    sessions.clear();
    outboundSid = null;
    pq.copyFrom(PqState());
  }

  Map<String, Object?> toJson() => {
        'them': them.toJson(),
        'outboundSid': outboundSid,
        'sessions': {for (final e in sessions.entries) e.key: e.value.toJson()},
        'pq': pq.toJson(),
      };

  static Future<Conversation> fromJson(ZIdentity me, Map<String, Object?> j,
      {bool postQuantum = true}) async {
    final them =
        ContactBundle.fromJson((j['them'] as Map).cast<String, Object?>());
    final conv = await create(me, them, postQuantum: postQuantum);
    final sess = (j['sessions'] as Map).cast<String, Object?>();
    for (final e in sess.entries) {
      conv.sessions[e.key] =
          Session.fromJson((e.value as Map).cast<String, Object?>());
    }
    conv.outboundSid = j['outboundSid'] as String?;
    conv.pq
        .copyFrom(PqState.fromJson((j['pq'] as Map?)?.cast<String, Object?>()));
    return conv;
  }
}
