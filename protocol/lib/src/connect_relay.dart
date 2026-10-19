/// The connect ceremony over a real relay, asynchronously (17.2).
///
/// Device pairing assumes both devices are awake at once, because they are in
/// the same pair of hands. This is the part that is different: **an invite
/// sent at lunchtime may be opened at midnight.** So every message is posted
/// to a mailbox and left there, the ceremony's state is serialisable, and
/// each side advances it whenever it next has a network — not in one live
/// session with the other person present.
///
/// The mailboxes are two throwaway relay identities HKDF'd from the invite
/// secret, one per role, so the relay sees two ephemeral mailboxes exchange a
/// few envelopes and go quiet. Neither party's real routing id appears
/// anywhere in the exchange. Nothing in `server/` changes: a routing id is
/// `SHA-256(ed25519 pub)`, so a keypair derived from a shared secret is a
/// mailbox both sides can hold, and rendezvous mailboxes queue like any other
/// (RAM, `QUEUE_TTL_HOURS`).
library;

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'connect.dart';
import 'identity.dart';
import 'relay_client.dart';
import 'util.dart';

/// How long an invite may be completed for. Well inside the mailbox's
/// `QUEUE_TTL_HOURS` (72), so expiry is a rule the clients keep rather than a
/// property of the store — the relay is not told, and does not need to be.
const Duration connectInviteLifetime = Duration(hours: 24);

/// What one [ConnectRun.step] achieved, and therefore what to do next.
enum ConnectProgress {
  /// Something was posted, or nothing had arrived yet. Step again later.
  waiting,

  /// Both identities are in hand: show [ConnectRun.session]'s string and ask
  /// the two humans to compare it.
  confirm,

  /// The ceremony is over and this invite is spent.
  done,

  /// Past [connectInviteLifetime]. Nothing was posted, and nothing in the
  /// mailbox will be acted on — even though the relay may still hold it.
  expired,

  /// This invite has already been used. A second attempt on it does nothing.
  spent,

  /// Refused: a reveal that did not match its commitment, or a malformed
  /// frame. [ConnectRun.abortReason] says which.
  aborted,
}

/// One side's whole invite, durable across restarts.
///
/// Serialise with [toJson] after every [step] — that is what makes criterion
/// 2 ("the initiator resumes after a restart") true rather than aspirational.
class ConnectRun {
  /// True for the side that made the invite.
  final bool inviter;

  /// When the invite was made, for [connectInviteLifetime].
  final int issuedMs;

  ConnectInviter? _inviter;
  ConnectAcceptor? _acceptor;
  ConnectIdentity _me;

  /// Set once both sides have revealed.
  ConnectSession? session;

  /// Set when [ConnectProgress.aborted] is returned.
  String? abortReason;

  bool _spent = false;

  ConnectRun._(this.inviter, this.issuedMs, this._me, this._inviter,
      this._acceptor, this.session, this._spent);

  /// Make an invite: generates the code and the ephemeral, posts nothing yet.
  ///
  /// Without a [code], the invite is a fresh one of [connectInviteVersion]:
  /// bound to its secret (ADR 0024). Nothing here ever makes one of
  /// version 1 unless handed a version-1 code.
  ///
  /// [group] is the group bit message 3 carries (ADR 0020,
  /// [connectGroupMember]): whether this invite also brings the acceptor
  /// into a group. Never which one — the run does not know, and the bit is
  /// all that goes. Null writes no bit, as a client before ADR 0020 does; a
  /// client that implements it passes false for a plain invite, so the two
  /// kinds of message 3 are the same length (see [connectGroupMember]).
  static Future<ConnectRun> invite(
      {required ConnectIdentity me,
      ConnectCode? code,
      int? nowMs,
      bool? group}) async {
    final i = await ConnectInviter.create(me: me, code: code, group: group);
    return ConnectRun._(true, nowMs ?? DateTime.now().millisecondsSinceEpoch,
        me, i, null, null, false);
  }

  /// Open an invite somebody sent: the acceptor side. Its own clock starts
  /// now, which is deliberate — the acceptor cannot know when the invite was
  /// made, so it enforces the lifetime from when it was handed the code. The
  /// inviter's copy is what bounds the invite properly.
  ///
  /// [groupAware]: read the inviter's group bit and repeat it in message 4
  /// (ADR 0020). False is a client from before it, which neither reads nor
  /// writes the bit.
  ///
  /// A version-3 [code] is refused: it runs as [ConnectRunV3] and nothing
  /// else (§20.9).
  static ConnectRun accept(
      {required ConnectIdentity me,
      required ConnectCode code,
      int? nowMs,
      bool groupAware = false}) {
    if (code.version == 3) {
      throw ArgumentError.value(code.version, 'code',
          'a version-3 invite runs as version 3 and nothing else');
    }
    return ConnectRun._(false, nowMs ?? DateTime.now().millisecondsSinceEpoch,
        me, null, null, null, false)
      .._code = code
      .._groupAware = groupAware;
  }

  ConnectCode? _code;

  /// The acceptor's [groupAware], kept until message 1 arrives and makes
  /// the [ConnectAcceptor] that carries it from then on.
  bool _groupAware = false;

  /// The invite's code — the thing to render as a link or read aloud.
  ConnectCode get code => _inviter?.code ?? _code!;

  /// Whether this run can still do anything.
  bool get finished => _spent || session != null;

  Map<String, Object?> toJson() => {
        'inviter': inviter,
        'issued': issuedMs,
        'me': _me.contactCode,
        if (_me.displayName != null) 'name': _me.displayName,
        'code': b64(code.secret),
        // The invite's version (ADR 0024), only when it is not 1: a record
        // without it is a version-1 invite, as every record written before
        // ADR 0024 is.
        if (code.version != 1) 'cv': code.version,
        if (_groupAware) 'ga': true,
        if (_inviter != null) 'i': _inviter!.toJson(),
        if (_acceptor != null) 'a': _acceptor!.toJson(),
        if (session != null)
          'session': {
            'key': b64(session!.channelKey),
            'sas': session!.sas,
            'peer': session!.peer.contactCode,
            if (session!.peer.displayName != null)
              'peerName': session!.peer.displayName,
            if (session!.group != null) 'grp': session!.group,
          },
        'spent': _spent,
        if (abortReason != null) 'abort': abortReason,
      };

  static Future<ConnectRun> fromJson(Map<String, Object?> j) async {
    final me = await ConnectIdentity.fromCode(j['me'] as String,
        displayName: j['name'] as String?);
    final code = ConnectCode(unb64(j['code'] as String),
        version: connectRecordVersion(j['cv']));
    ConnectSession? session;
    final sj = j['session'];
    if (sj is Map) {
      final m = sj.cast<String, Object?>();
      final grp = m['grp'];
      session = ConnectSession(
        channelKey: unb64(m['key'] as String),
        sas: m['sas'] as String,
        peer: await ConnectIdentity.fromCode(m['peer'] as String,
            displayName: m['peerName'] as String?),
        group: grp is bool ? grp : null,
      );
    }
    final run = ConnectRun._(
      j['inviter'] as bool,
      (j['issued'] as num).toInt(),
      me,
      j['i'] == null
          ? null
          : await ConnectInviter.fromJson((j['i'] as Map).cast<String, Object?>()),
      j['a'] == null
          ? null
          : await ConnectAcceptor.fromJson(
              (j['a'] as Map).cast<String, Object?>(),
              code: code),
      session,
      j['spent'] as bool? ?? false,
    );
    run._code = code;
    run._groupAware = j['ga'] == true;
    run.abortReason = j['abort'] as String?;
    return run;
  }

  /// Connect, do everything that can be done right now, disconnect.
  ///
  /// Safe to call repeatedly and at any interval: each side's next action is
  /// decided by what is in its mailbox, not by a live handshake, so a run
  /// that is half finished simply continues.
  ///
  /// Every return value is a fact about the ceremony. A network failure is
  /// not one of those, so it is thrown rather than returned: an unreachable
  /// relay means try again, and nothing about the invite has changed.
  /// Persist the run after each call — see [toJson].
  ///
  /// [refusePeer]: asked about the identity the other side revealed, the
  /// moment this side has it checked against its commitment — and, on the
  /// acceptor's side, BEFORE this side reveals its own. True ends the
  /// ceremony there, as an abort: no session, the invite spent, and an
  /// acceptor's message 4 never sent. It is how a person who has blocked
  /// that identity is kept from it — and it from them — through an invite
  /// (ADR 0024).
  Future<ConnectProgress> step(
      {required String relayUrl,
      int? nowMs,
      Duration poll = const Duration(milliseconds: 1500),
      Future<bool> Function(ConnectIdentity peer)? refusePeer}) async {
    if (_spent) return ConnectProgress.spent;
    if (session != null) return ConnectProgress.done;
    final now = nowMs ?? DateTime.now().millisecondsSinceEpoch;
    if (now - issuedMs > connectInviteLifetime.inMilliseconds) {
      // Refused by the client even though the mailbox may still hold the
      // envelope: the relay was never told the lifetime and cannot enforce it.
      return ConnectProgress.expired;
    }

    final myRole = inviter ? 'i' : 'r';
    final theirRole = inviter ? 'r' : 'i';
    final mine = await mailboxIdentity(code, myRole);
    final theirs = await (await mailboxIdentity(code, theirRole)).routingId();
    final client = await RelayClient.connect(relayUrl, mine);
    final inbox = <RelayInbound>[];
    final spent = <RelayInbound>[];
    final sub = client.messages.listen(inbox.add);
    try {
      // Give the relay's flush a moment to deliver whatever was waiting.
      await Future<void>.delayed(poll);
      final progress = inviter
          ? await _stepInviter(client, theirs, inbox, spent, refusePeer)
          : await _stepAcceptor(client, theirs, inbox, spent, refusePeer);
      // Nothing this side has read will be read again, and the ceremony is
      // over for good once the session exists: acknowledge, so the relay
      // wipes it from RAM. Two reasons, neither cosmetic. A mailbox left
      // full is a transcript that anyone who later gets hold of the code can
      // still pull out of the relay for QUEUE_TTL_HOURS — the reveals inside
      // stay sealed under a channel whose ephemeral secrets were never
      // posted, but the ephemerals and the timing need not linger. And a
      // second party arriving on a spent invite would otherwise be answered
      // by the *stored* frames: the commitment binding makes that abort
      // rather than succeed (§20), which is the right outcome but not one
      // worth relying on when the frames can simply be gone.
      if (progress == ConnectProgress.confirm) spent.addAll(inbox);
      for (final e in spent) {
        client.ackReceived(id: e.id, from: e.from);
      }
      return progress;
    } on ConnectAbort catch (e) {
      // Spent, not retried, whichever kind of abort this was. A reveal that
      // did not match its commitment must never be retried on the same
      // invite, because the retry would meet whoever produced the mismatch;
      // and a malformed frame is not distinguishable from a hostile one, so
      // it gets the same answer. Anyone who can write a malformed frame into
      // the mailbox is holding the code, and could instead have completed
      // the ceremony as an impostor — killing the invite is the lesser thing
      // they can do with it, not a new exposure.
      abortReason = e.message;
      _spent = true;
      return ConnectProgress.aborted;
    } finally {
      await sub.cancel();
      await client.close();
    }
  }

  Future<ConnectProgress> _stepInviter(
      RelayClient client,
      String theirs,
      List<RelayInbound> inbox,
      List<RelayInbound> spent,
      Future<bool> Function(ConnectIdentity peer)? refusePeer) async {
    final i = _inviter!;
    if (!i.opened) {
      final reply = _take(inbox, 'x2', spent);
      if (reply == null) {
        // Post (or re-post) the commitment and leave it there.
        await client.send(
            to: theirs,
            id: 'z-connect-c1',
            payload: jsonEncode({'k': 'x1', ...await i.commit()}));
        return ConnectProgress.waiting;
      }
      final open = await i.open(reply);
      await client.send(
          to: theirs,
          id: 'z-connect-c3',
          payload: jsonEncode({'k': 'x3', ...open}));
      return ConnectProgress.waiting;
    }
    final reveal = _take(inbox, 'x4', spent);
    if (reveal == null) return ConnectProgress.waiting;
    final s = await i.complete(reveal);
    if (refusePeer != null && await refusePeer(s.peer)) {
      throw const ConnectAbort('refused: whoever answered is refused here');
    }
    session = s;
    return ConnectProgress.confirm;
  }

  Future<ConnectProgress> _stepAcceptor(
      RelayClient client,
      String theirs,
      List<RelayInbound> inbox,
      List<RelayInbound> spent,
      Future<bool> Function(ConnectIdentity peer)? refusePeer) async {
    if (_acceptor == null) {
      final commit = _take(inbox, 'x1', spent);
      if (commit == null) return ConnectProgress.waiting;
      final (reply, acceptor) = await ConnectAcceptor.reply(commit,
          me: _me, code: code, groupAware: _groupAware);
      _acceptor = acceptor;
      await client.send(
          to: theirs,
          id: 'z-connect-c2',
          payload: jsonEncode({'k': 'x2', ...reply}));
      return ConnectProgress.waiting;
    }
    final open = _take(inbox, 'x3', spent);
    if (open == null) return ConnectProgress.waiting;
    final (reveal, s) = await _acceptor!.accept(open);
    // Asked before this side's own reveal goes: a refused inviter is never
    // shown who opened its invite.
    if (refusePeer != null && await refusePeer(s.peer)) {
      throw const ConnectAbort('refused: whoever made it is refused here');
    }
    await client.send(
        to: theirs,
        id: 'z-connect-c4',
        payload: jsonEncode({'k': 'x4', ...reveal}));
    session = s;
    return ConnectProgress.confirm;
  }

  /// The two humans compared the string and it matched. Marks the invite
  /// spent: it is one-time, so a second person holding the same link cannot
  /// start again where this left off.
  void confirmed() => _spent = true;

  /// They did not compare it, or it did not match. Same spending rule — a
  /// mismatched ceremony must not be retried on the same invite, because the
  /// retry would meet whoever produced the mismatch.
  void abandon() => _spent = true;

  /// The first frame of [kind] in the mailbox, removing every copy of that
  /// kind from [inbox] and listing them in [spent] to be acknowledged.
  ///
  /// Copies happen by design: a side that steps twice before the other has
  /// answered re-posts its frame, and the relay dedupes those to one envelope
  /// — but a reconnect re-flushes anything not yet acknowledged, so the same
  /// envelope can be read more than once. Only kinds this side has finished
  /// with are taken, never one it is still waiting for.
  static Map<String, Object?>? _take(
      List<RelayInbound> inbox, String kind, List<RelayInbound> spent) {
    Map<String, Object?>? first;
    for (var n = 0; n < inbox.length;) {
      Map<String, Object?> j;
      try {
        j = jsonDecode(inbox[n].payload) as Map<String, Object?>;
      } catch (_) {
        n++;
        continue;
      }
      if (j['k'] != kind) {
        n++;
        continue;
      }
      first ??= j;
      spent.add(inbox.removeAt(n));
    }
    return first;
  }
}

/// One side's throwaway mailbox, derived from the invite secret.
///
/// `role` is `'i'` for the inviter and `'r'` for the acceptor. Disjoint from
/// pairing's mailboxes by context, so an invite can never address a pairing
/// rendezvous or the reverse — and a version-2 invite's from a version-1
/// invite's of the same ten bytes ([connectRelayCtxV2]), so a run of one
/// version never meets, or waits on, a run of the other (ADR 0024). A
/// version-3 invite's are its own again ([connectRelayCtxV3], §20.9).
Future<ZIdentity> mailboxIdentity(ConnectCode code, String role) async {
  final ctx = code.version == 3
      ? connectRelayCtxV3
      : code.bound
          ? connectRelayCtxV2
          : connectRelayCtx;
  final k = await Hkdf(hmac: Hmac.sha256(), outputLength: 64).deriveKey(
    secretKey: SecretKey(code.secret),
    nonce: Uint8List(0),
    info: utf8.encode('$ctx$role'),
  );
  final b = await k.extractBytes();
  return ZIdentity.fromSeeds(
    edSeed: Uint8List.fromList(b.sublist(0, 32)),
    xSeed: Uint8List.fromList(b.sublist(32, 64)),
  );
}

/// One side of a version-3 invite (§20.9), durable across restarts: the same
/// four frames, mailboxes of its own, and every rule of [ConnectRun] —
/// store-and-forward, the lifetime, spent on confirmation, an abandonment or
/// any abort, the mailbox acknowledged empty — around [ConnectInviterV3] and
/// [ConnectAcceptorV3].
///
/// Nothing in the app runs one before 44.6: [ConnectRun] refuses a
/// version-3 invite, [ConnectRun.fromJson] a version-3 record
/// ([connectRecordVersion]), and [fromJson] here any other.
class ConnectRunV3 {
  /// True for the side that made the invite.
  final bool inviter;

  /// When the invite was made, or opened, for [connectInviteLifetime].
  final int issuedMs;

  final ConnectIdentity _me;
  final Uint8List? _pqKey;
  final Uint8List _sealKey;
  ConnectInviterV3? _inviter;
  ConnectAcceptorV3? _acceptor;
  ConnectCode? _code;
  bool _groupAware = false;
  bool _spent = false;

  /// Set once both sides have revealed.
  ConnectSessionV3? session;

  /// Set when [ConnectProgress.aborted] is returned.
  String? abortReason;

  ConnectRunV3._(this.inviter, this.issuedMs, this._me, this._pqKey,
      this._sealKey);

  /// Make a version-3 invite, as [ConnectRun.invite]: without a [code], a
  /// fresh one of version 3. [sealKey] and [pqKey] are this side's own,
  /// sealed into its reveal (see [ConnectInviterV3]).
  static Future<ConnectRunV3> invite(
      {required ConnectIdentity me,
      required List<int> sealKey,
      List<int>? pqKey,
      ConnectCode? code,
      int? nowMs,
      bool? group}) async {
    final i = await ConnectInviterV3.create(
        me: me, sealKey: sealKey, pqKey: pqKey, code: code, group: group);
    return ConnectRunV3._(true, nowMs ?? DateTime.now().millisecondsSinceEpoch,
        me, i.pqKey, i.sealKey)
      .._inviter = i;
  }

  /// Open a version-3 invite somebody sent, as [ConnectRun.accept]. A
  /// [code] of another version is refused here, before anything is posted.
  static ConnectRunV3 accept(
      {required ConnectIdentity me,
      required List<int> sealKey,
      List<int>? pqKey,
      required ConnectCode code,
      int? nowMs,
      bool groupAware = false}) {
    if (code.version != 3) {
      throw ArgumentError.value(
          code.version, 'code', 'a version-3 run needs a version-3 invite');
    }
    checkConnectOwnKeysV3(me, sealKey: sealKey, pqKey: pqKey);
    return ConnectRunV3._(
        false,
        nowMs ?? DateTime.now().millisecondsSinceEpoch,
        me,
        pqKey == null ? null : Uint8List.fromList(pqKey),
        Uint8List.fromList(sealKey))
      .._code = code
      .._groupAware = groupAware;
  }

  /// The invite's code — the thing to render as a link or read aloud.
  ConnectCode get code => _inviter?.code ?? _code!;

  /// Whether this run can still do anything.
  bool get finished => _spent || session != null;

  Map<String, Object?> toJson() => {
        'inviter': inviter,
        'issued': issuedMs,
        'me': _me.contactCode,
        if (_me.displayName != null) 'name': _me.displayName,
        if (_pqKey != null) 'pqk': b64(_pqKey),
        'seal': b64(_sealKey),
        'code': b64(code.secret),
        'cv': 3,
        if (_groupAware) 'ga': true,
        if (_inviter != null) 'i': _inviter!.toJson(),
        if (_acceptor != null) 'a': _acceptor!.toJson(),
        if (session != null)
          'session': {
            'key': b64(session!.channelKey),
            'sas': session!.sas,
            'peer': session!.peer.contactCode,
            if (session!.peer.displayName != null)
              'peerName': session!.peer.displayName,
            if (session!.group != null) 'grp': session!.group,
            if (session!.peerPqKey != null) 'pqk': b64(session!.peerPqKey!),
            'pqseal': b64(session!.peerSealKey),
          },
        'spent': _spent,
        if (abortReason != null) 'abort': abortReason,
      };

  /// Reads back what [toJson] wrote — a record of version 3, and only that.
  static Future<ConnectRunV3> fromJson(Map<String, Object?> j) async {
    if (j['cv'] != 3) {
      throw const FormatException('not a version-3 invite record');
    }
    final me = await ConnectIdentity.fromCode(j['me'] as String,
        displayName: j['name'] as String?);
    final code = ConnectCode(unb64(j['code'] as String), version: 3);
    final pqk = j['pqk'];
    final run = ConnectRunV3._(
        j['inviter'] as bool,
        (j['issued'] as num).toInt(),
        me,
        pqk is String ? unb64(pqk) : null,
        unb64(j['seal'] as String));
    final ij = j['i'], aj = j['a'], sj = j['session'];
    if (ij is Map) {
      run._inviter = await ConnectInviterV3.fromJson(ij.cast<String, Object?>());
    }
    if (aj is Map) {
      run._acceptor = await ConnectAcceptorV3.fromJson(
          aj.cast<String, Object?>(),
          code: code);
    }
    if (sj is Map) {
      final m = sj.cast<String, Object?>();
      final grp = m['grp'], peerPq = m['pqk'];
      run.session = ConnectSessionV3(
        channelKey: unb64(m['key'] as String),
        sas: m['sas'] as String,
        peer: await ConnectIdentity.fromCode(m['peer'] as String,
            displayName: m['peerName'] as String?),
        group: grp is bool ? grp : null,
        peerPqKey: peerPq is String ? unb64(peerPq) : null,
        peerSealKey: unb64(m['pqseal'] as String),
      );
    }
    run._code = code;
    run._groupAware = j['ga'] == true;
    run._spent = j['spent'] as bool? ?? false;
    run.abortReason = j['abort'] as String?;
    return run;
  }

  /// [ConnectRun.step], for version 3: connect as this side's version-3
  /// mailbox, do everything that can be done now, acknowledge what was
  /// consumed, disconnect. The same answers, for the same reasons.
  Future<ConnectProgress> step(
      {required String relayUrl,
      int? nowMs,
      Duration poll = const Duration(milliseconds: 1500),
      Future<bool> Function(ConnectIdentity peer)? refusePeer}) async {
    if (_spent) return ConnectProgress.spent;
    if (session != null) return ConnectProgress.done;
    final now = nowMs ?? DateTime.now().millisecondsSinceEpoch;
    if (now - issuedMs > connectInviteLifetime.inMilliseconds) {
      return ConnectProgress.expired;
    }

    final mine = await mailboxIdentity(code, inviter ? 'i' : 'r');
    final theirs =
        await (await mailboxIdentity(code, inviter ? 'r' : 'i')).routingId();
    final client = await RelayClient.connect(relayUrl, mine);
    final inbox = <RelayInbound>[];
    final spent = <RelayInbound>[];
    final sub = client.messages.listen(inbox.add);
    try {
      // Give the relay's flush a moment to deliver whatever was waiting.
      await Future<void>.delayed(poll);
      final progress = inviter
          ? await _stepInviter(client, theirs, inbox, spent, refusePeer)
          : await _stepAcceptor(client, theirs, inbox, spent, refusePeer);
      if (progress == ConnectProgress.confirm) spent.addAll(inbox);
      for (final e in spent) {
        client.ackReceived(id: e.id, from: e.from);
      }
      return progress;
    } on ConnectAbort catch (e) {
      abortReason = e.message;
      _spent = true;
      return ConnectProgress.aborted;
    } finally {
      await sub.cancel();
      await client.close();
    }
  }

  Future<ConnectProgress> _stepInviter(
      RelayClient client,
      String theirs,
      List<RelayInbound> inbox,
      List<RelayInbound> spent,
      Future<bool> Function(ConnectIdentity peer)? refusePeer) async {
    final i = _inviter!;
    if (!i.opened) {
      final reply = ConnectRun._take(inbox, 'x2', spent);
      if (reply == null) {
        await client.send(
            to: theirs,
            id: 'z-connect-c1',
            payload: jsonEncode({'k': 'x1', ...await i.commit()}));
        return ConnectProgress.waiting;
      }
      final open = await i.open(reply);
      await client.send(
          to: theirs,
          id: 'z-connect-c3',
          payload: jsonEncode({'k': 'x3', ...open}));
      return ConnectProgress.waiting;
    }
    final reveal = ConnectRun._take(inbox, 'x4', spent);
    if (reveal == null) return ConnectProgress.waiting;
    final s = await i.complete(reveal);
    if (refusePeer != null && await refusePeer(s.peer)) {
      throw const ConnectAbort('refused: whoever answered is refused here');
    }
    session = s;
    return ConnectProgress.confirm;
  }

  Future<ConnectProgress> _stepAcceptor(
      RelayClient client,
      String theirs,
      List<RelayInbound> inbox,
      List<RelayInbound> spent,
      Future<bool> Function(ConnectIdentity peer)? refusePeer) async {
    if (_acceptor == null) {
      final commit = ConnectRun._take(inbox, 'x1', spent);
      if (commit == null) return ConnectProgress.waiting;
      final (reply, acceptor) = await ConnectAcceptorV3.reply(commit,
          me: _me,
          code: code,
          sealKey: _sealKey,
          pqKey: _pqKey,
          groupAware: _groupAware);
      _acceptor = acceptor;
      await client.send(
          to: theirs,
          id: 'z-connect-c2',
          payload: jsonEncode({'k': 'x2', ...reply}));
      return ConnectProgress.waiting;
    }
    final open = ConnectRun._take(inbox, 'x3', spent);
    if (open == null) return ConnectProgress.waiting;
    final (reveal, s) = await _acceptor!.accept(open);
    if (refusePeer != null && await refusePeer(s.peer)) {
      throw const ConnectAbort('refused: whoever made it is refused here');
    }
    await client.send(
        to: theirs,
        id: 'z-connect-c4',
        payload: jsonEncode({'k': 'x4', ...reveal}));
    session = s;
    return ConnectProgress.confirm;
  }

  /// As [ConnectRun.confirmed]: the comparison matched; the invite is spent.
  void confirmed() => _spent = true;

  /// As [ConnectRun.abandon]: not compared, or not matching; spent.
  void abandon() => _spent = true;
}
