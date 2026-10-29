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

/// The message a run draws in a round that also moves it past drawing it —
/// message 2 on the acceptor's side, with the ephemeral its commitment
/// covers; message 3 on the inviter's, its opening — held byte for byte,
/// with its envelope id, from just before it is posted until the relay has
/// taken it (§20.5): in the run, and in the record the step's `persist`
/// writes before every post. A post that fails leaves it held, and every later
/// round posts it again as it was, until a post of it lands or its answer
/// arrives. It is never drawn twice: the run has moved past that, and a
/// second message 2 would carry a second ephemeral. Posted again to a relay
/// that still holds it — taken, and only its answer lost — it is one
/// envelope there: the relay dedupes an attributed envelope on its id and
/// sender while it holds it. One that reaches the relay after the other side
/// has read and acknowledged the first is stored again and read by nobody.
/// Until 2026-10-29 nothing posted it again, and a link that dropped as it
/// went left this side waiting for an answer to a message the other side
/// never had, and the other side waiting for that message, both until the
/// invite expired. Shared by [ConnectRun] and [ConnectRunV3].
mixin _Unposted {
  ({String id, String payload})? _unposted;

  /// Posts [payload] as envelope [id] to [to], held until the relay takes
  /// it, and written down by [persist] with it held before it goes: once the
  /// relay may have it, the record says so.
  Future<void> _post(RelayClient client, String to, String id, String payload,
      Future<void> Function()? persist) async {
    _unposted = (id: id, payload: payload);
    if (persist != null) await persist();
    await client.send(to: to, id: id, payload: payload);
    _unposted = null;
  }

  /// Posts again the message a failed post left held, if there is one —
  /// written down by [persist] first, as before its first post. The record
  /// need not hold it yet: when the write before the first post was refused,
  /// that round ended there, and the write its caller makes after a round
  /// that threw can be refused too. A write refused again ends this round
  /// before the post as well. Until 2026-10-29 it went unwritten, and an app
  /// that died after the relay took it came back to the record from before
  /// the message was drawn, and drew another.
  Future<void> _repost(RelayClient client, String to,
      Future<void> Function()? persist) async {
    final u = _unposted;
    if (u == null) return;
    if (persist != null) await persist();
    await client.send(to: to, id: u.id, payload: u.payload);
    _unposted = null;
  }

  /// The record's member for it, present only while a message is held —
  /// from just before its post until the relay has taken it — so a record
  /// written once a round's posts have landed is what it was before
  /// 2026-10-29.
  Map<String, Object?> get _unpostedJson => {
        if (_unposted != null)
          'unposted': {'id': _unposted!.id, 'payload': _unposted!.payload},
      };

  /// Reads back what [_unpostedJson] wrote — nothing, or an id and a payload.
  void _readUnposted(Object? j) {
    if (j == null) return;
    final id = j is Map ? j['id'] : null;
    final payload = j is Map ? j['payload'] : null;
    if (id is! String || payload is! String) {
      throw const FormatException('an unposted message this build cannot read');
    }
    _unposted = (id: id, payload: payload);
  }
}

/// One side's whole invite, durable across restarts.
///
/// Serialise with [toJson] after every [step], whether it returned or threw
/// — that is what makes criterion 2 ("the initiator resumes after a
/// restart") true rather than aspirational, and a step that threw after
/// drawing its message may have moved the run ([_Unposted]).
class ConnectRun with _Unposted {
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
        ..._unpostedJson,
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
    run._readUnposted(j['unposted']);
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
  /// relay means try again. Nothing it read is acknowledged; but a round
  /// that drew its message 2 or 3 before the post of it failed has moved
  /// past drawing it, and holds that message for the next round to post
  /// again ([_Unposted]). Persist the run after each call, whether it
  /// returned or threw — see [toJson].
  ///
  /// [persist]: write the run down, as [toJson] has it, and only then
  /// return. It is called where a round needs the record to say already
  /// what the relay may know: once a message 2 or 3 is drawn and held,
  /// before its first post and before any post of it again; and once the
  /// round has taken in what it read, before the relay is told to forget
  /// it. So an app that dies anywhere in a round comes back to a record
  /// holding any message 2 or 3 the relay may have from it, and posts that
  /// message rather than drawing another — and never to a record from
  /// before something it acknowledged. What the round that reaches the
  /// digits read is left at the relay when the app dies between that
  /// round's write and its acknowledgements: a run that holds its session
  /// never connects again (§20.5). Until 2026-10-29 nothing was written
  /// until the round was over, and an app that died after the relay took
  /// its message 2 drew a second one, which the relay, holding the first
  /// under its id, dropped: the invite was spent at message 3. A throw from
  /// [persist] ends the round there, as a network failure does — nothing
  /// more posted, nothing acknowledged.
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
      Future<bool> Function(ConnectIdentity peer)? refusePeer,
      Future<void> Function()? persist}) async {
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
          ? await _stepInviter(client, theirs, inbox, spent, refusePeer, persist)
          : await _stepAcceptor(
              client, theirs, inbox, spent, refusePeer, persist);
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
      // worth relying on when the frames can simply be gone. Written down
      // first: once acknowledged, nothing can be read again, so the record
      // must already hold what the round made of it.
      if (progress == ConnectProgress.confirm) spent.addAll(inbox);
      if (spent.isNotEmpty && persist != null) await persist();
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
      _unposted = null;
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
      Future<bool> Function(ConnectIdentity peer)? refusePeer,
      Future<void> Function()? persist) async {
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
      await _post(client, theirs, 'z-connect-c3',
          jsonEncode({'k': 'x3', ...open}), persist);
      return ConnectProgress.waiting;
    }
    final reveal = _take(inbox, 'x4', spent);
    if (reveal == null) {
      // No answer to message 3 yet: post it again if its post failed.
      await _repost(client, theirs, persist);
      return ConnectProgress.waiting;
    }
    _unposted = null; // answered, so the relay had it
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
      Future<bool> Function(ConnectIdentity peer)? refusePeer,
      Future<void> Function()? persist) async {
    if (_acceptor == null) {
      final commit = _take(inbox, 'x1', spent);
      if (commit == null) return ConnectProgress.waiting;
      final (reply, acceptor) = await ConnectAcceptor.reply(commit,
          me: _me, code: code, groupAware: _groupAware);
      _acceptor = acceptor;
      await _post(client, theirs, 'z-connect-c2',
          jsonEncode({'k': 'x2', ...reply}), persist);
      return ConnectProgress.waiting;
    }
    final open = _take(inbox, 'x3', spent);
    if (open == null) {
      // No answer to message 2 yet: post it again if its post failed.
      await _repost(client, theirs, persist);
      return ConnectProgress.waiting;
    }
    _unposted = null; // answered, so the relay had it
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
/// store-and-forward, a message 2 or 3 whose post failed held and posted
/// again as it was ([_Unposted]), the lifetime, spent on confirmation, an
/// abandonment or any abort, the mailbox acknowledged empty — around
/// [ConnectInviterV3] and [ConnectAcceptorV3].
///
/// Nothing in the app ran one before 44.6, which runs it for an invite of
/// version 3 that it opens — and makes one only for a test (ADR 0033
/// decision 2). [ConnectRun] refuses a version-3 invite, [ConnectRun.fromJson]
/// a version-3 record ([connectRecordVersion]), and [fromJson] here any other.
class ConnectRunV3 with _Unposted {
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
        ..._unpostedJson,
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
    run._readUnposted(j['unposted']);
    return run;
  }

  /// [ConnectRun.step], for version 3: connect as this side's version-3
  /// mailbox, do everything that can be done now, acknowledge what was
  /// consumed, disconnect. The same answers, for the same reasons — a
  /// message 2 or 3 whose post failed among them, held and posted again
  /// ([_Unposted]) — and [persist] called at the same moments.
  Future<ConnectProgress> step(
      {required String relayUrl,
      int? nowMs,
      Duration poll = const Duration(milliseconds: 1500),
      Future<bool> Function(ConnectIdentity peer)? refusePeer,
      Future<void> Function()? persist}) async {
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
          ? await _stepInviter(client, theirs, inbox, spent, refusePeer, persist)
          : await _stepAcceptor(
              client, theirs, inbox, spent, refusePeer, persist);
      if (progress == ConnectProgress.confirm) spent.addAll(inbox);
      // Written down before anything read is acknowledged, as for version 2.
      if (spent.isNotEmpty && persist != null) await persist();
      for (final e in spent) {
        client.ackReceived(id: e.id, from: e.from);
      }
      return progress;
    } on ConnectAbort catch (e) {
      abortReason = e.message;
      _spent = true;
      _unposted = null;
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
      Future<bool> Function(ConnectIdentity peer)? refusePeer,
      Future<void> Function()? persist) async {
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
      // Opens once: its KEM key decapsulates this one ciphertext, and a
      // message 3 whose post fails is posted again rather than made again.
      final open = await i.open(reply);
      await _post(client, theirs, 'z-connect-c3',
          jsonEncode({'k': 'x3', ...open}), persist);
      return ConnectProgress.waiting;
    }
    final reveal = ConnectRun._take(inbox, 'x4', spent);
    if (reveal == null) {
      await _repost(client, theirs, persist);
      return ConnectProgress.waiting;
    }
    _unposted = null; // answered, so the relay had it
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
      Future<bool> Function(ConnectIdentity peer)? refusePeer,
      Future<void> Function()? persist) async {
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
      await _post(client, theirs, 'z-connect-c2',
          jsonEncode({'k': 'x2', ...reply}), persist);
      return ConnectProgress.waiting;
    }
    final open = ConnectRun._take(inbox, 'x3', spent);
    if (open == null) {
      await _repost(client, theirs, persist);
      return ConnectProgress.waiting;
    }
    _unposted = null; // answered, so the relay had it
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
