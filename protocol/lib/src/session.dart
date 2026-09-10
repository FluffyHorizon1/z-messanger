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

  /// v2 post-quantum state for THIS session. It belongs to the session and
  /// not to the conversation: the ML-KEM secret is agreed inside a session's
  /// key schedule, and two sessions of the same pair can be alive at once
  /// (§4 initiation race, and a peer that restored from backup and opened a
  /// fresh one). A shared generation counter could not describe both eras,
  /// and mixing one era's secret into the other's messages makes them
  /// undecryptable.
  final PqState pq;

  Session({
    required this.sid,
    required this.initiatorRid,
    required this.ekPub,
    required this.ratchet,
    this.receivedAny = false,
    this.lastUsedMs = 0,
    PqState? pq,
  }) : pq = pq ?? PqState();

  Map<String, Object?> toJson({bool includeSkipped = true}) => {
        'sid': sid,
        'initiatorRid': initiatorRid,
        'ekPub': b64(ekPub),
        'ratchet': ratchet.toJson(includeSkipped: includeSkipped),
        'receivedAny': receivedAny,
        'lastUsedMs': lastUsedMs,
        'pq': pq.toJson(),
      };

  /// [inheritedPq] is the conversation-level state written by builds before
  /// the per-session split; a stored session without its own `pq` takes it,
  /// which is exactly right because those vaults only ever had one era.
  static Session fromJson(Map<String, Object?> j, {PqState? inheritedPq}) =>
      Session(
        sid: j['sid'] as String,
        initiatorRid: j['initiatorRid'] as String,
        ekPub: unb64(j['ekPub'] as String),
        ratchet: RatchetState.fromJson(
            (j['ratchet'] as Map).cast<String, Object?>()),
        receivedAny: j['receivedAny'] as bool,
        lastUsedMs: (j['lastUsedMs'] as num).toInt(),
        pq: j['pq'] != null
            ? PqState.fromJson((j['pq'] as Map).cast<String, Object?>())
            : inheritedPq?.clone(),
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

  /// The session the peer was last seen actually using, once they have shown
  /// us they no longer hold the one we were using (see [decrypt]). Null in
  /// the normal case, where [_converge] decides.
  String? pinnedSid;

  /// Post-quantum state for a conversation that has no session yet. Live
  /// state belongs to the session (see [Session.pq]); this only stands in so
  /// [pq] is never null, and is what a pre-split stored conversation loads
  /// into before its sessions inherit it.
  final PqState _idlePq;

  /// v2 post-quantum state of the session we currently send on.
  PqState get pq =>
      (outboundSid == null ? null : sessions[outboundSid!])?.pq ?? _idlePq;

  /// 7.5b: how often the offering side rotates the ML-KEM secret (post-compromise
  /// security for the PQ layer). 0 (the default, and what the frozen v2 vectors
  /// use) disables periodic re-keying — the secret is established once. The app
  /// sets a real interval; a re-key offer then rides the next message sent after
  /// the interval elapses (no traffic → nothing to protect → no re-key).
  int pqRekeyIntervalMs = 0;

  /// Whether this side takes part in the v2 post-quantum upgrade. Off, the
  /// conversation behaves exactly as protocol v1 (it neither offers nor
  /// accepts ML-KEM keys, but still interoperates with v2 peers, which then
  /// stay classical too). Only the v1 test-vector generator turns it off.
  final bool postQuantum;

  Conversation._(this.me, this.them, this.myRid, this.theirRid, this.sessions,
      this.outboundSid,
      {PqState? pq, this.postQuantum = true})
      : _idlePq = pq ?? PqState();

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

  /// 7.5b: the current post-quantum generation (0 after the first
  /// establishment, incremented by each completed re-key).
  int get pqGeneration => pq.gen;

  String get _designatedInitiatorRid =>
      myRid.compareTo(theirRid) < 0 ? myRid : theirRid;

  void _converge() {
    // A pinned session wins outright: the peer has demonstrably lost or
    // replaced state, and this is the session we last heard them speak on.
    final pinned = pinnedSid;
    if (pinned != null) {
      if (sessions.containsKey(pinned)) {
        outboundSid = pinned;
        return;
      }
      pinnedSid = null; // it was pruned; fall back to the standing rule
    }
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
    if (!postQuantum || !isPqOfferer) return null;
    final now = nowMs ?? DateTime.now().millisecondsSinceEpoch;
    // Read the state of the session the offer would actually go out on —
    // which is not always [outboundSid], and must not be created here unless
    // there is something to send.
    final existing = _sendableSession();
    final pq = existing?.pq ?? _idlePq;
    // Initial offer (generation 0), made once per SESSION. The re-key clock
    // starts here, so the interval is measured from establishment rather than
    // the epoch.
    if (!pq.established && !pq.offered) {
      final session = existing ?? await _initiateSession();
      final (seed, ek) = pqGenerate();
      session.pq
        ..dkSeed = seed
        ..offered = true
        ..offerGen = 0
        ..lastRekeyMs = now;
      final offer = InnerMessage.pqOffer(newMessageId(), now, ek);
      return _encryptOn(session, offer.toBytes(), nowMs: nowMs);
    }
    // 7.5b re-key offer: established, an interval is set and due, and no offer
    // for a higher generation is already outstanding.
    if (pq.established &&
        pqRekeyIntervalMs > 0 &&
        pq.offerGen <= pq.gen &&
        now - pq.lastRekeyMs >= pqRekeyIntervalMs) {
      final session = existing!; // established implies a sendable session
      final nextGen = session.pq.gen + 1;
      final (seed, ek) = pqGenerate();
      session.pq
        ..dkSeed = seed
        ..offerGen = nextGen
        ..lastRekeyMs = now;
      final offer = InnerMessage.pqOffer(newMessageId(), now, ek, gen: nextGen);
      return _encryptOn(session, offer.toBytes(), nowMs: nowMs);
    }
    return null;
  }

  /// 7.5b: force the offering side to start a re-key now, regardless of the
  /// interval (used by tests and vector generation; also available if the app
  /// wants a user-driven "rotate keys"). No-op off the offerer side.
  Future<String?> forcePqRekey({int? nowMs}) async {
    if (!postQuantum || !isPqOfferer) return null;
    final session = _sendableSession();
    if (session == null || !session.pq.established) return null;
    if (session.pq.offerGen > session.pq.gen) return null; // one outstanding
    final now = nowMs ?? DateTime.now().millisecondsSinceEpoch;
    final nextGen = session.pq.gen + 1;
    final (seed, ek) = pqGenerate();
    session.pq
      ..dkSeed = seed
      ..offerGen = nextGen
      ..lastRekeyMs = now;
    final offer = InnerMessage.pqOffer(newMessageId(), now, ek, gen: nextGen);
    return _encryptOn(session, offer.toBytes(), nowMs: nowMs);
  }

  /// Encrypts [plaintext] for this contact, creating a session if none
  /// exists. Returns the opaque transport payload (a base64 string the relay
  /// cannot interpret). Persist this conversation's state BEFORE sending.
  Future<String> encrypt(Uint8List plaintext, {int? nowMs}) async =>
      _encryptOn(await _outboundSession(), plaintext, nowMs: nowMs);

  /// The session outgoing traffic goes on, or null if there is none we can
  /// send on yet.
  Session? _sendableSession() {
    final session = outboundSid == null ? null : sessions[outboundSid!];
    if (session != null && session.ratchet.cks != null) return session;
    // Either no session at all, or we only hold a responder session on which
    // we have not yet received anything (cannot send on it).
    final usable = sessions.values.where((s) => s.ratchet.cks != null).toList()
      ..sort((a, b) => b.lastUsedMs.compareTo(a.lastUsedMs));
    return usable.isNotEmpty ? usable.first : null;
  }

  /// The session outgoing traffic goes on, opening one if there is none.
  Future<Session> _outboundSession() async =>
      _sendableSession() ?? await _initiateSession();

  Future<String> _encryptOn(Session session, Uint8List plaintext,
      {int? nowMs}) async {
    final msg =
        await ratchetEncrypt(session.ratchet, plaintext, pq: session.pq);
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
    final plain = await ratchetDecrypt(session.ratchet, msg, pq: session.pq);
    session.receivedAny = true;
    session.lastUsedMs = nowMs ?? DateTime.now().millisecondsSinceEpoch;

    // Which session do we answer on? Normally [_converge] decides, and both
    // sides apply the same rule. But a peer that opens a BRAND-NEW session
    // while we hold one that was already carrying traffic in both directions
    // has lost its state — a reinstall, or a restore from backup (§9), which
    // deliberately does not carry session state. Convergence keeps preferring
    // whichever session the designated initiator opened, so unless the peer
    // that restarted happens to be that initiator we would go on replying on
    // a session they cannot decrypt, and every reply would vanish. Pin the
    // one they opened instead.
    //
    // The condition is narrow on purpose: a session that has never received
    // anything is the simultaneous-initiation race (§4), which convergence
    // already resolves, and is left alone.
    //
    // The old session is KEPT. We cannot tell a peer that lost its state from
    // a second device holding the same identity key, and if the first one
    // speaks again we must still be able to read it — dropping the session
    // here would let anyone able to open one session cut the other off. So
    // once a peer has shown us they lose sessions, we simply follow whichever
    // one they actually speak on. Each session carries its own post-quantum
    // secret ([Session.pq]), so the new session re-handshakes from classical
    // while the old one keeps the secret of its own era.
    if (created) {
      if (sessions.values.any((s) => s.sid != sid && s.receivedAny)) {
        pinnedSid = sid;
      }
    } else if (pinnedSid != null && pinnedSid != sid) {
      pinnedSid = sid;
    }
    _converge();

    // v2: the encapsulating side acts on an inbound offer — the initial one and
    // (7.5b) every re-key offer; the offering side makes its offer as soon as
    // it has heard from the peer, and re-key offers ride later messages. Both
    // are scoped to the session the message arrived on.
    if (postQuantum && !isPqOfferer) _acceptPqOffer(session.pq, plain);
    final offerPayload =
        isPqOfferer ? await takePqOfferPayload(nowMs: nowMs) : null;
    return DecryptResult(plain, sid, created, pqOfferPayload: offerPayload);
  }

  /// If [plain] is a `pqek` offer for the supported algorithm, encapsulate to
  /// it. The initial offer (generation 0) establishes the secret; a re-key
  /// offer (generation gen+1) rotates it, retaining the outgoing generation for
  /// the crossover. Anything malformed or out-of-order is ignored.
  void _acceptPqOffer(PqState pq, Uint8List plain) {
    if (!InnerMessage.looksLikeKind(plain, 'pqek')) return;
    try {
      final inner = InnerMessage.fromBytes(plain);
      if (inner.data['alg'] != pqAlgorithm) return;
      final g = (inner.data['g'] as num?)?.toInt() ?? 0;
      if (pq.k == null) {
        if (g != 0) return; // cannot start mid-generation
      } else {
        if (g != pq.gen + 1) return; // only the next generation rotates
      }
      final ek = unb64(inner.data['ek'] as String);
      final (ct, k) = pqEncapsulate(ek);
      if (pq.k != null) {
        pq.oldGen =
            pq.gen; // retain the outgoing generation across the crossover
        pq.oldK = pq.k;
      }
      pq
        ..k = k
        ..ct = ct
        ..gen = g
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
    pinnedSid = null;
    _idlePq.copyFrom(PqState());
  }

  Map<String, Object?> toJson({bool includeSkipped = true}) => {
        'them': them.toJson(),
        'outboundSid': outboundSid,
        if (pinnedSid != null) 'pinnedSid': pinnedSid,
        'sessions': {
          for (final e in sessions.entries)
            e.key: e.value.toJson(includeSkipped: includeSkipped)
        },
        // The live session's state, also written at this level so a build
        // that predates the per-session split still reads a usable value.
        'pq': pq.toJson(),
      };

  static Future<Conversation> fromJson(ZIdentity me, Map<String, Object?> j,
      {bool postQuantum = true}) async {
    final them =
        ContactBundle.fromJson((j['them'] as Map).cast<String, Object?>());
    final conv = await create(me, them, postQuantum: postQuantum);
    final legacyPq =
        PqState.fromJson((j['pq'] as Map?)?.cast<String, Object?>());
    conv._idlePq.copyFrom(legacyPq);
    final sess = (j['sessions'] as Map).cast<String, Object?>();
    for (final e in sess.entries) {
      conv.sessions[e.key] = Session.fromJson(
          (e.value as Map).cast<String, Object?>(),
          inheritedPq: legacyPq);
    }
    conv.outboundSid = j['outboundSid'] as String?;
    conv.pinnedSid = j['pinnedSid'] as String?;
    return conv;
  }
}
