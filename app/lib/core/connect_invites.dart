import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:z_protocol/z_protocol.dart';

import 'chat_service.dart';
import 'models.dart';

/// One side of an invite's ceremony, whichever version the invite is.
///
/// The protocol library runs versions 1 and 2 as [ConnectRun] and version 3
/// (PROTOCOL §20.9, ADR 0033 §4) as [ConnectRunV3], and keeps the two apart:
/// each refuses the other's invite before it draws or posts anything, and
/// the other's stored record. So a version-3 invite is never run as version
/// 2 here either — [ConnectInvites.open] hands it to [InviteRun.hybrid] and
/// nothing else, and [fromJson] reads a record by the version it names.
/// This asks of either run only what both do.
abstract class InviteRun {
  /// The run of an invite of version 1 or 2, sealed under X25519 alone.
  factory InviteRun.classical(ConnectRun run) = _ClassicalRun;

  /// The run of an invite of version 3, hybrid with ML-KEM-768.
  factory InviteRun.hybrid(ConnectRunV3 run) = _HybridRun;

  /// A stored run, read by the reader of the version its record names
  /// (`cv`, 3 for version 3, and 2 or absent for the others).
  static Future<InviteRun> fromJson(Map<String, Object?> j) async =>
      j['cv'] == 3
          ? InviteRun.hybrid(await ConnectRunV3.fromJson(j))
          : InviteRun.classical(await ConnectRun.fromJson(j));

  bool get inviter;
  int get issuedMs;
  ConnectCode get code;

  /// Set once both sides have revealed: a [ConnectSessionV3] for version 3.
  ConnectSession? get session;
  bool get finished;
  String? get abortReason;
  Map<String, Object?> toJson();
  /// One round ([ConnectRun.step]), [persist] writing the run down at the
  /// moments in it that must be on disk before the round goes on.
  Future<ConnectProgress> step(
      {required String relayUrl,
      int? nowMs,
      Future<bool> Function(ConnectIdentity peer)? refusePeer,
      Future<void> Function()? persist});
  void confirmed();
  void abandon();

  /// What the peer's reveal carried beside its code, for the add (44.6):
  /// its account's ML-DSA key when the code commits to one, and its
  /// device's sealing key. Null before both sides have revealed, and always
  /// for versions 1 and 2, whose reveals carry neither.
  CeremonyKeys? get ceremonyKeys;
}

final class _ClassicalRun implements InviteRun {
  _ClassicalRun(this._run);
  final ConnectRun _run;

  @override
  bool get inviter => _run.inviter;
  @override
  int get issuedMs => _run.issuedMs;
  @override
  ConnectCode get code => _run.code;
  @override
  ConnectSession? get session => _run.session;
  @override
  bool get finished => _run.finished;
  @override
  String? get abortReason => _run.abortReason;
  @override
  Map<String, Object?> toJson() => _run.toJson();
  @override
  Future<ConnectProgress> step(
          {required String relayUrl,
          int? nowMs,
          Future<bool> Function(ConnectIdentity peer)? refusePeer,
          Future<void> Function()? persist}) =>
      _run.step(
          relayUrl: relayUrl,
          nowMs: nowMs,
          refusePeer: refusePeer,
          persist: persist);
  @override
  void confirmed() => _run.confirmed();
  @override
  void abandon() => _run.abandon();
  @override
  CeremonyKeys? get ceremonyKeys => null;
}

final class _HybridRun implements InviteRun {
  _HybridRun(this._run);
  final ConnectRunV3 _run;

  @override
  bool get inviter => _run.inviter;
  @override
  int get issuedMs => _run.issuedMs;
  @override
  ConnectCode get code => _run.code;
  @override
  ConnectSession? get session => _run.session;
  @override
  bool get finished => _run.finished;
  @override
  String? get abortReason => _run.abortReason;
  @override
  Map<String, Object?> toJson() => _run.toJson();
  @override
  Future<ConnectProgress> step(
          {required String relayUrl,
          int? nowMs,
          Future<bool> Function(ConnectIdentity peer)? refusePeer,
          Future<void> Function()? persist}) =>
      _run.step(
          relayUrl: relayUrl,
          nowMs: nowMs,
          refusePeer: refusePeer,
          persist: persist);
  @override
  void confirmed() => _run.confirmed();
  @override
  void abandon() => _run.abandon();
  @override
  CeremonyKeys? get ceremonyKeys {
    final s = _run.session;
    return s == null
        ? null
        : CeremonyKeys(pqKey: s.peerPqKey, sealKey: s.peerSealKey);
  }
}

/// Why the last round could not carry an invite forward, as a kind: the
/// card says each in the reader's words (`connect_text.dart`), and none of
/// them carries an exception's text.
enum ConnectFailure {
  /// The relay could not be reached, or did not answer in time: a socket,
  /// WebSocket, TLS or HTTP error, a link the relay client lost, or a
  /// timeout.
  relay,

  /// The relay was reached and refused a step, with one of its own refusals
  /// (`PROTOCOL.md` §12.2): the other side's mailbox there full, too many
  /// frames at once, its store full ([relayRefused]). Until 2026-10-31 it
  /// was said as a relay that could not be reached.
  refused,

  /// This device's vault refused a write of the invites
  /// ([ConnectWriteRefused]).
  vault,

  /// Anything else: a fault in this build rather than in the network.
  fault,
}

/// Whether [e] is the relay's own refusal of a frame — one of the error
/// codes of `PROTOCOL.md` §12.2, as the relay client puts it in a
/// [RelayException], `refused` when an error frame named none, and
/// `auth failed: ` and a code when it was the authentication that was
/// refused — rather than a link lost, an answer that did not come in time,
/// or something that is not a Z relay at all.
bool relayRefused(RelayException e) =>
    _relayRefusals.contains(e.message) || e.message.startsWith('auth failed: ');

const _relayRefusals = {
  'rate_limited', 'bad_json', 'internal', 'bad_auth', 'not_authed',
  'bad_send', 'too_large', 'bad_push', 'unknown_frame', 'queue_full',
  'store_full', 'pow_required', 'bad_intro', 'push_refused', 'intro_full',
  'bad_ikey', 'anon_only', 'refused',
};

/// A write of the invites that this device's vault refused — a full disk, a
/// locked or closed database. What refused it stays with it, for logs; the
/// screens word it in the reader's language.
class ConnectWriteRefused implements Exception {
  const ConnectWriteRefused(this.cause);

  /// What the vault threw.
  final Object cause;

  @override
  String toString() => 'the vault refused a write of the invites: $cause';
}

/// What [ConnectInvites.open] was handed is not an invite this build reads,
/// of any version. A [FormatException] still, its English the message, for
/// logs; the screens word it in the reader's language.
class ConnectNotAnInvite extends FormatException {
  const ConnectNotAnInvite() : super('that is not a Z invite');
}

/// The invite handed to [ConnectInvites.open] is one this device already
/// has open. A [FormatException] still, as [ConnectNotAnInvite] is.
class ConnectInviteAlreadyOpen extends FormatException {
  const ConnectInviteAlreadyOpen() : super('that invite is already open');
}

/// An invite of version 3 needs this device's sealing key, and this run of
/// the app holds none: the vault could not give one at start. A
/// [FormatException] still, as [ConnectNotAnInvite] is.
class ConnectNoSealingKey extends FormatException {
  const ConnectNoSealingKey()
      : super('this device has no sealing key yet, so it cannot run a '
            'post-quantum invite');
}

/// One invite in flight, and everything needed to pick it up later (17.3).
///
/// An invite is not a live screen. It is a thing you made at lunchtime, sent
/// over WhatsApp, and forgot about; the other person opens it at midnight
/// while your phone is in a drawer. So it is a record with an id, kept in the
/// vault, that survives the app closing — see [ConnectInvites].
class PendingInvite {
  /// Storage key. Random, and never leaves the device: the invite's own
  /// secret would do as an id, but then every log line and every widget key
  /// would carry a bearer token.
  final String id;

  /// True if this device made the invite; false if it opened somebody else's.
  final bool mine;

  final int createdMs;

  /// The group this invite is a link to (ADR 0020), or null for an ordinary
  /// invite. On the INVITER's side only, and only here: it is not in the
  /// link, not in any frame, and not in the run — message 3 carries one bit
  /// saying that a group is attached, and nothing that says which.
  final String? gid;

  /// The ceremony, of the invite's own version ([InviteRun]).
  InviteRun run;

  /// The last thing [ConnectInvites.pump] learned about this invite.
  ConnectProgress progress;

  /// The user has answered the comparison — matched, deferred or stopped.
  ///
  /// Separate from [progress] on purpose. `ConnectProgress.done` means the
  /// CEREMONY is over, which happens the moment both sides have revealed and
  /// says nothing about whether anyone has looked at the digits yet; this
  /// says the person has. Reading one for the other put a live "they match"
  /// button on screen for a ceremony nobody had answered, and took it away
  /// from one they had not.
  ///
  /// In memory only: an answered invite is removed from the list, so there
  /// is never one to write down.
  bool answered = false;

  /// Why the last [ConnectInvites.pump] could not carry this invite forward
  /// — the relay, a write the vault refused, or anything else — or null
  /// when it could. In memory only, and said on the card in the reader's
  /// words: until 2026-09-17 every failure was swallowed, so a relay that
  /// refused every step read "Waiting for them" for as long as the person
  /// cared to look; and until 2026-10-31 this held the failure's own text,
  /// which the card showed, in English, after "Could not reach the relay",
  /// whatever had failed — a write the vault refused among them.
  ConnectFailure? lastFailure;

  /// The record this answer added, by its creation time — written down
  /// before anything else the answer does, so an answer cut short after the
  /// add (the app killed before the go-ahead went) finishes when the person
  /// answers again, rather than meeting "already in your contacts" from its
  /// own add. The record, not the routing id: a contact deleted and added
  /// back another way in between is not this answer's, and is not ticked as
  /// compared by it.
  int? addedMs;

  /// This answer has added the peer as a contact ([addedMs]).
  bool get added => addedMs != null;

  /// Set by an answer to a group link (ADR 0020) whose peer was already a
  /// contact: the record was used as it was, neither replaced nor marked as
  /// compared, which is what the screen then says. In memory only.
  bool peerWasHeld = false;

  /// The run as the vault holds it: what the last write of the invites that
  /// returned wrote of it, as JSON, or null while none has. In memory only.
  /// A round asks whether the run is written down by this, not by what the
  /// run was when the round began — a write can be refused, and then the
  /// vault holds less than memory does ([ConnectInvites.pump]).
  String? _inVault;

  /// The person said yes to this invite on their own screen (ADR 0024).
  ///
  /// Always true for one made here, and for one opened by typing or pasting
  /// it and pressing Open — that press is the yes. False for one that
  /// arrived by tapping a link, until the person presses Connect: nothing
  /// of the ceremony is sent before that, not even message 2, so a link
  /// tapped by accident, or in someone else's message, tells nobody that it
  /// reached this device. Until 2026-10-09 a tapped link stepped the
  /// ceremony at once, and the contact code went out with message 4 before
  /// the person had seen anything. Durable: a held invite stays held across
  /// a restart.
  bool consented;

  PendingInvite({
    required this.id,
    required this.mine,
    required this.createdMs,
    required this.run,
    this.gid,
    this.progress = ConnectProgress.waiting,
    this.addedMs,
    this.consented = true,
  });

  /// Opened from a link and waiting for its person's yes ([consented]).
  bool get held => !mine && !consented;

  /// A version-1 invite (ADR 0024): made by a client from before invites
  /// were bound to their secret. It runs as it always did — and until the
  /// digits are compared, the relay could be in the middle of it too, which
  /// the comparison screen says.
  bool get unbound => !run.code.bound;

  /// A group invite link (ADR 0020) on either side: made here for a group,
  /// or opened here and saying a group is attached.
  bool get groupLink => mine ? gid != null : offersGroup;

  /// Opened by me, and its message 3 said the invite also brings me into a
  /// group (ADR 0020): what the comparison screen must say before the digits.
  bool get offersGroup => !mine && run.session?.group == true;

  /// Made by me as a group link, and whoever answered it has a client that
  /// repeated the group bit — so it could tell them, before the digits, and
  /// they can go ahead into the group. False for an answer from a client
  /// that predates group links: they can be a contact, not a member.
  bool get joinerKnowsGroup => mine && gid != null && run.session?.group == true;

  /// The invite's two renderings. One secret: the code is what you read down
  /// a phone line, the link is what you paste into a chat.
  String get code => run.code.text;
  String get link => run.code.link();

  /// The eight digits both people compare, once both have revealed.
  String? get sas => run.session?.sas;

  /// Who the other side turned out to be — only after [ConnectProgress.confirm].
  ConnectIdentity? get peer => run.session?.peer;

  bool get awaitingConfirmation => run.session != null && !answered;

  Map<String, Object?> toJson() => {
        'id': id,
        'mine': mine,
        'created': createdMs,
        if (gid != null) 'gid': gid,
        'progress': progress.name,
        'run': run.toJson(),
        if (addedMs != null) 'addedMs': addedMs,
        // Written only while held: a record without it was opened with a
        // yes, as every record written before ADR 0024 was.
        if (!consented) 'held': true,
      };

  static Future<PendingInvite> fromJson(Map<String, Object?> j) async {
    final run =
        await InviteRun.fromJson((j['run'] as Map).cast<String, Object?>());
    final stored = ConnectProgress.values.firstWhere(
        (p) => p.name == j['progress'],
        orElse: () => ConnectProgress.waiting);
    return PendingInvite(
      id: j['id'] as String,
      mine: j['mine'] as bool,
      createdMs: (j['created'] as num).toInt(),
      gid: j['gid'] as String?,
      run: run,
      // A run that holds its session is at the digits, whatever the record
      // says beside it: the round that reaches them writes the run down
      // before it acknowledges what it read (ConnectRun.step), and an app
      // killed before the round was over had not yet written the progress
      // it returned. Read as "waiting", the card would still offer the
      // invite's link and code beside the digits.
      progress: stored == ConnectProgress.waiting && run.session != null
          ? ConnectProgress.confirm
          : stored,
      addedMs: (j['addedMs'] as num?)?.toInt(),
      consented: j['held'] != true,
    );
  }
}

/// The app's half of the connect ceremony: making invites, opening them, and
/// carrying each one forward whenever there is a network (17.3, §20).
///
/// The protocol work is in `z_protocol`'s `ConnectRun` and `ConnectRunV3`,
/// state machines rather than conversations precisely because the two
/// people are never online together. This class is the part that owns those
/// runs: it writes them to the vault after every step, so closing the app is
/// not an event the ceremony has to survive so much as one it does not
/// notice.
///
/// It opens an invite of any version this build reads — 1, 2 and, from
/// 44.6, 3 (§20.9) — and makes version 2 only. Version 3 is made a release
/// after the release that reads it (ADR 0033 decision 2), so nobody on the
/// release before is handed an invite their app cannot open; until then
/// only a test makes one ([debugMintV3]).
class ConnectInvites extends ChangeNotifier {
  ConnectInvites(this._svc, {Duration pollEvery = defaultPollEvery})
      : _pollEvery = pollEvery;

  final ChatService _svc;

  /// How often a pending invite is carried forward while the app is in the
  /// foreground.
  ///
  /// The ceremony is four messages through two mailboxes, and each side can
  /// only act on what the other has already posted — so it takes two or three
  /// rounds per side, and until 2026-09-17 the only thing that ran a round
  /// was the CONNECT tab opening or its "Check now" button. Two people had to
  /// press it alternately, in the right order, four times, and an invite
  /// opened by tapping a link was never pumped at all. So this polls, at a
  /// pace where the worst case after the other person acts is one interval.
  /// Each round is one throwaway relay identity connecting, reading its
  /// mailbox and leaving, which is what a "Check now" always cost.
  static const Duration defaultPollEvery = Duration(seconds: 20);

  final Duration _pollEvery;
  Timer? _poll;
  bool _foreground = false;
  Future<void>? _inFlight;

  /// Set by [dispose]: nothing is carried forward after it — no pass starts,
  /// a pass in flight runs no round after the one it is in, no poll is
  /// armed, and nobody is told. Until 2026-10-31 a pass in flight when the
  /// object was disposed armed the polls as it ended, and they ran rounds
  /// for as long as the isolate lived, the object's listeners gone.
  bool _disposed = false;

  /// Sealed like everything else in the vault. It holds invite secrets, and
  /// an invite secret is a bearer token until it is spent.
  static const String _kvKey = 'connect_invites';

  /// Test seam: open invites as a client from before group links (ADR 0020)
  /// does — message 3's group bit is neither read nor repeated, so nothing
  /// is said about a group and no go-ahead is ever sent. That is the joiner
  /// the inviter has to recognise and refuse to add.
  @visibleForTesting
  bool debugBeforeGroupLinks = false;

  /// Test seam: make and open invites as a client from before ADR 0024 —
  /// it mints version 1, and refuses a version-2 or version-3 invite as its
  /// parser does ("that is not a Z invite"), because the marker that starts
  /// one is not base32. That is the old client either side of a new one
  /// meets.
  @visibleForTesting
  bool debugBeforeBinding = false;

  /// Test seam: make invites of version 3 (§20.9) — version 3's own run,
  /// with this device's sealing key and the account's ML-DSA key in its
  /// reveal — so a test can drive a version-3 inviter, through a real relay,
  /// against this build's acceptor.
  ///
  /// This release reads version 3 and makes version 2 only. Production
  /// minting is the NEXT release's work (ADR 0033 decision 2): an invite is
  /// minted a release after the release that reads it, so an acceptor on
  /// the release before is never handed one it cannot open. That release
  /// makes its invites this way, by version 3's run — not by moving
  /// [connectInviteVersion], which the version-2 run refuses whatever it
  /// says. Nothing outside a test sets this: `connect_pq_test.dart` holds
  /// lib/ to that, and to reaching the version-3 inviter from behind it
  /// alone.
  @visibleForTesting
  bool debugMintV3 = false;

  /// Test seam: an answer stops right after it has added the contact and
  /// written that down — where an app killed between the add and the rest
  /// of the answer leaves it.
  @visibleForTesting
  bool debugStopAfterAdd = false;

  /// Test seam: the contact code this device reveals in the ceremonies it
  /// starts or opens from now on, in place of [ChatService.myContactCode] —
  /// a peer whose revealed code says something other than what its app then
  /// sends (no commitment at all, or a commitment to some other key), which
  /// an honest client never produces and the receiving side must still get
  /// right.
  @visibleForTesting
  String? debugMyCode;

  /// Test seam: awaited before each pending invite's round in a pass, with
  /// that invite — where an app killed between one invite's round and the
  /// next's leaves it. Read once per round and called only if set.
  @visibleForTesting
  Future<void> Function(PendingInvite invite)? debugBeforeRound;

  final List<PendingInvite> _invites = [];

  /// The stored records [load] could not read, each as the JSON it was
  /// stored as, written back ahead of the invites by every [_save]. The
  /// stored list is the only copy of them, and a later build may read what
  /// this one does not.
  final List<Object?> _unread = [];
  bool _loaded = false;

  List<PendingInvite> get invites => List.unmodifiable(_invites);

  /// Read the pending invites back after a restart. Safe to call twice.
  ///
  /// One record at a time. A record this build cannot read is passed over —
  /// it is not worth losing the app over, and the invite it describes can be
  /// made again in two taps — and kept as it was ([_unread]). Until
  /// 2026-10-28 one such record left no invite loaded, and the next [_save]
  /// wrote the shorter list over the vault's copy: one record cost every
  /// invite. And since then a record whose shape is sound can be one: one
  /// whose peer revealed a code under an Ed25519 key of small order
  /// (PROTOCOL §2.4), which a build before took in and this one refuses. A
  /// stored value that is not a list, which no build writes, is read as no
  /// invites, as it always was.
  Future<void> load() async {
    if (_loaded) return;
    _loaded = true;
    final raw = await _svc.vault.kvGet(_kvKey);
    if (raw == null) return;
    Object? stored;
    try {
      stored = jsonDecode(raw);
    } catch (_) {}
    if (stored is List) {
      for (final e in stored) {
        try {
          final invite = await PendingInvite.fromJson(
              (e as Map).cast<String, Object?>());
          invite._inVault = jsonEncode(invite.run.toJson());
          _invites.add(invite);
        } catch (_) {
          _unread.add(e);
        }
      }
    }
    if (!_disposed) notifyListeners();
  }

  /// Writes the invites to the vault, and once the vault has taken them
  /// notes what it now holds of each run ([PendingInvite._inVault]). A write
  /// the vault refuses notes nothing, and throws [ConnectWriteRefused].
  Future<void> _save() async {
    final writing = [for (final i in _invites) (i, i.toJson())];
    final value = jsonEncode([..._unread, for (final (_, j) in writing) j]);
    try {
      await _svc.vault.kvPut(_kvKey, value);
    } catch (e) {
      throw ConnectWriteRefused(e);
    }
    for (final (i, j) in writing) {
      i._inVault = jsonEncode(j['run']);
    }
  }

  /// [_save] after an invite was made, opened or said yes to: the polls
  /// armed for it and the tab told whether or not the vault took the write.
  /// Refused, the invite is kept in memory and carried forward like any
  /// other until a write of the invites goes through, and
  /// [ConnectWriteRefused] goes on to the screen. Until 2026-11-01 the
  /// refusal was thrown before the polls were armed, so with no other
  /// invite pending such an invite had no round until the next resume,
  /// "Check now" or the tab opened again.
  Future<void> _keep() async {
    try {
      await _save();
    } finally {
      _arm();
      notifyListeners();
    }
  }

  Future<ConnectIdentity> _me() async => ConnectIdentity.fromCode(
      debugMyCode ?? await _svc.myContactCode(),
      displayName: _svc.displayName);

  /// Make an invite. Nothing is posted until the first [pump].
  /// [ConnectWriteRefused] when the vault refuses the write: the invite is
  /// kept in memory all the same and carried forward ([_keep]), and goes
  /// with the next write of the invites.
  ///
  /// [gid]: make it a link to that group (ADR 0020) — an ordinary one-time,
  /// 24-hour invite, with the group remembered here and nowhere else. The run
  /// is told one bit, "a group is attached", which message 3 carries sealed;
  /// an ordinary invite carries the same bit clear, so the two are the same
  /// length on the wire. Whether this device may add members is checked when
  /// the joiner's go-ahead arrives, not only now.
  Future<PendingInvite> create({int? nowMs, String? gid}) async {
    if (gid != null && !_svc.mayIssueGroupList(gid, '')) {
      // The screen offers this only to someone who may add members; a link
      // minted without that could never add anyone.
      throw StateError('a group link needs a group this device may add to');
    }
    await load();
    final now = nowMs ?? DateTime.now().millisecondsSinceEpoch;
    // ADR 0024: a fresh invite is version 2, bound to its secret — never
    // version 1, which a client before it still mints. Version 3 is the
    // next release's to mint (ADR 0033 decision 2), and here a test's alone.
    final InviteRun run = debugMintV3
        ? await _mintV3ForTests(now, group: gid != null)
        : InviteRun.classical(await ConnectRun.invite(
            me: await _me(),
            nowMs: now,
            group: gid != null,
            code:
                debugBeforeBinding ? ConnectCode.generate(version: 1) : null));
    final invite = PendingInvite(
      id: b64url(randomBytes(9)),
      mine: true,
      createdMs: now,
      gid: gid,
      run: run,
    );
    _invites.add(invite);
    await _keep();
    return invite;
  }

  /// The version-3 inviter [debugMintV3] stands in for — what the release
  /// after this one mints — reached from [create] behind that seam alone.
  Future<InviteRun> _mintV3ForTests(int now, {required bool group}) async {
    final (me, sealKey, pqKey) = await _ownV3Keys();
    return InviteRun.hybrid(await ConnectRunV3.invite(
        me: me, sealKey: sealKey, pqKey: pqKey, nowMs: now, group: group));
  }

  /// What this side brings to a ceremony of version 3 (§20.9): its contact
  /// code and name, this device's sealing key, which its reveal always
  /// carries, and the account's ML-DSA key, which it carries exactly when
  /// that code commits to one. The run holds both keys to those rules
  /// before it starts. [ConnectNoSealingKey] when this run of the app holds
  /// no sealing key (the vault could not give one at start).
  Future<(ConnectIdentity, Uint8List, Uint8List?)> _ownV3Keys() async {
    final me = await _me();
    final sealKey = _svc.sealingKey;
    if (sealKey == null) throw const ConnectNoSealingKey();
    final commits = me.pqCommit.any((b) => b != 0);
    return (me, sealKey, commits ? await _svc.pqAccountPublic() : null);
  }

  /// Open an invite somebody sent: a `https://…/i#<code>` link or the printed
  /// code itself, whichever the user has.
  ///
  /// Consumes the link entirely on this device — the code is in the URL
  /// fragment, which no browser sends to a server, and nothing here fetches
  /// the link either. This method touches no network at all.
  ///
  /// [consented]: whether the person has said yes to connecting (ADR 0024).
  /// The CONNECT tab's Open button is that yes — the person typed or pasted
  /// the invite and pressed it — so it is the default. An invite that
  /// arrived by tapping a link has had no yes yet: it is held, and nothing
  /// of the ceremony leaves the device until [consent].
  ///
  /// Any version this build reads, each run as itself: one a client before
  /// ADR 0024 made runs as version 1, as it always did; and from 44.6 one of
  /// version 3 (§20.9) runs as version 3 and nothing else — its own
  /// mailboxes, the ML-KEM exchange inside its four messages, and this
  /// side's reveal carrying this device's sealing key and the account's
  /// ML-DSA key.
  ///
  /// Refused with [ConnectNotAnInvite] or [ConnectInviteAlreadyOpen], and a
  /// version-3 invite with [ConnectNoSealingKey] on a run of the app that
  /// holds no sealing key. [ConnectWriteRefused] when the vault refuses the
  /// write: the invite is kept in memory all the same and carried forward
  /// ([_keep]), and goes with the next write of the invites.
  Future<PendingInvite> open(String linkOrCode,
      {int? nowMs, bool consented = true}) async {
    await load();
    final code = parseInvite(linkOrCode);
    if (code == null || (debugBeforeBinding && code.bound)) {
      throw const ConnectNotAnInvite();
    }
    for (final existing in _invites) {
      if (constantTimeEquals(existing.run.code.secret, code.secret)) {
        throw const ConnectInviteAlreadyOpen();
      }
    }
    final now = nowMs ?? DateTime.now().millisecondsSinceEpoch;
    final InviteRun run;
    if (code.version == 3) {
      final (me, sealKey, pqKey) = await _ownV3Keys();
      run = InviteRun.hybrid(ConnectRunV3.accept(
          me: me,
          sealKey: sealKey,
          pqKey: pqKey,
          code: code,
          nowMs: now,
          groupAware: !debugBeforeGroupLinks));
    } else {
      run = InviteRun.classical(ConnectRun.accept(
          me: await _me(),
          code: code,
          nowMs: now,
          groupAware: !debugBeforeGroupLinks));
    }
    final invite = PendingInvite(
      id: b64url(randomBytes(9)),
      mine: false,
      createdMs: now,
      run: run,
      consented: consented,
    );
    _invites.add(invite);
    await _keep();
    return invite;
  }

  /// **The person said yes** to an invite that arrived by link ([open]
  /// with `consented: false`): from now on it is carried forward like any
  /// other, starting at once.
  ///
  /// What the yes lets go: this side's message 2 now, and — once the
  /// inviter's reveal has arrived and been checked — its own contact code,
  /// sealed to whoever made the invite. With a version-2 invite that is
  /// someone holding the link, and nobody else.
  Future<void> consent(PendingInvite invite) async {
    if (invite.consented) return;
    invite.consented = true;
    // A yes the vault refuses to write down is kept in memory all the same,
    // and the invite carried forward from now ([_keep]); the refusal goes on
    // to the screen once its round has run.
    (Object, StackTrace)? refused;
    try {
      await _keep();
    } on ConnectWriteRefused catch (e, st) {
      refused = (e, st);
    }
    // A round already in flight passed this invite over while it was held:
    // let it finish, then run one that carries it.
    final running = _inFlight;
    if (running != null) await running;
    await pump();
    if (refused != null) Error.throwWithStackTrace(refused.$1, refused.$2);
  }

  /// A link or a printed code, whichever was handed over, of any version
  /// this build reads: 1 and 2 by the library's version-2 readers, as every
  /// release since ADR 0024 has read them, and 3 by its version-3 readers
  /// (§20.9, 44.6), asked only once those have refused. Each reads its own
  /// marker alone and a link on the invite page alone, so what an older
  /// reader took it still takes, as it did, and what it refused that is not
  /// a version-3 invite is still refused. Null if neither.
  static ConnectCode? parseInvite(String input) {
    final s = input.trim();
    if (s.isEmpty) return null;
    final fromLink = ConnectCode.fromLink(s) ?? ConnectCode.fromLinkV3(s);
    if (fromLink != null) return fromLink;
    for (final read in const [ConnectCode.parse, ConnectCode.parseV3]) {
      try {
        return read(s);
      } on FormatException {
        // Not this reader's: the next one, or nothing.
      }
    }
    return null;
  }

  /// Carry every pending invite as far as it will go right now.
  ///
  /// One connect-act-disconnect per invite, and what each round did is
  /// written to the vault as soon as it has run, before the next invite's
  /// round starts — so an app killed mid-ceremony, even during another
  /// invite's round, resumes from where it actually got to rather than from
  /// where it started.
  ///
  /// One at a time. A second call while one is in flight joins it rather than
  /// starting another, because two steps on the same run at once are not
  /// merely wasteful: the acceptor's step picks its ephemeral and posts it,
  /// and two of them pick two, the relay keeps the first, and the run keeps
  /// the second — so the inviter opens against one key and this side checks
  /// against the other, the reveal does not open, and the invite is spent on
  /// a mismatch nobody produced. With a poll running beside a button, that
  /// overlap is not hypothetical.
  ///
  /// After [dispose] it starts nothing: a pass still in flight is handed
  /// back, to be joined, and otherwise there is nothing to wait for.
  Future<void> pump({int? nowMs}) {
    final running = _inFlight;
    if (running != null) return running;
    if (_disposed) return Future<void>.value();
    late final Future<void> mine;
    mine = _pump(nowMs: nowMs).whenComplete(() {
      if (identical(_inFlight, mine)) _inFlight = null;
    });
    _inFlight = mine;
    return mine;
  }

  Future<void> _pump({int? nowMs}) async {
    // A tick that lands after the vault has gone — a wipe on its way to
    // exit(0), a test tearing down — has nothing to read or write to.
    if (!_svc.vault.db.isOpen) {
      _disarm();
      return;
    }
    // The polls are armed, or not, however the pass ends: a pass that
    // throws still leaves them as the invites need. Until 2026-10-30 they
    // were armed only once the last round was over, and a pass that left
    // early — a write the vault refused after a round that threw — never
    // armed them.
    try {
      await _rounds(nowMs: nowMs);
    } finally {
      _arm();
    }
  }

  /// One round for each pending invite, in turn — the pass [pump] runs.
  Future<void> _rounds({int? nowMs}) async {
    await load();
    if (_invites.isEmpty) return;
    for (final invite in List.of(_invites)) {
      // Disposed while this pass was in flight: the round it was in has
      // ended, and nothing more is carried forward ([_disposed]).
      if (_disposed) return;
      // Discarded since the pass began, or on its way out ([discard]).
      if (!_invites.contains(invite)) continue;
      // Spent, or finished and waiting on a human: nothing a round trip can
      // change. (Stepping a finished run only turns `confirm` into `done`,
      // which the card does not distinguish and the poll should not pay for.)
      if (invite.run.finished) continue;
      if (invite.progress == ConnectProgress.done) continue;
      // Waiting for its person's yes (ADR 0024): not even a connection.
      if (invite.held) continue;
      final hold = debugBeforeRound;
      if (hold != null) await hold(invite);
      // What the run holds before its round. A round can move it and leave
      // what the card shows as it was — the acceptor's message 2 draws the
      // ephemeral its commitment covers, the inviter's message 3 takes in the
      // reply it answers, and each acknowledges away the message it consumed
      // — so a round that moved the run is written down like one that changed
      // the card, and before the next invite's round, which is at least a
      // poll of its own (ConnectRun.step). Until 2026-10-28 such a round was
      // not written down, and an app killed after it, while the other side
      // was away, came back to the record from before it: it waited for a
      // message the relay no longer held, and with both sides killed the
      // acceptor drew a second ephemeral and spent the invite at message 3.
      // Until 2026-10-29 a pass wrote down what its rounds did once every
      // pending invite's round had run, and an app killed during a later
      // one's lost an earlier one's the same way. A round that throws is
      // compared too: one whose post of its message 2 or 3 failed has drawn
      // that message and holds it to post again (ConnectRun.step), so it is
      // written down with it whatever the card already said, and after a
      // restart that message goes, never a second one drawn in its place.
      // Until 2026-10-29 a round that threw was written down only when its
      // failure was new to the card. And inside the round, [persist] writes
      // the run down where the round asks: once it holds a message 2 or 3 it
      // has drawn, before each post of it, and once it has taken in what it
      // read and before that is acknowledged — so an app killed in the
      // middle of a round, after the relay took its message 2 and before the
      // round was over, comes back to that message, not to the record from
      // before the round, which until 2026-10-29 drew a second one. Whether
      // the run is written down is asked of what the vault holds of it
      // ([PendingInvite._inVault]), there and once the round is over, not of
      // the run as the round began: a write can be refused, and the vault
      // then holds less than memory does. Until 2026-10-29 it was asked of
      // the run as the round began, so the round after one whose writes were
      // both refused — the one before its post, and the one after it threw
      // — posted the message again over a record without it.
      final before = jsonEncode(invite.run.toJson());
      Future<void> persist() async {
        if (jsonEncode(invite.run.toJson()) == invite._inVault) return;
        await _save();
      }

      final ConnectProgress next;
      try {
        next = await invite.run.step(
            relayUrl: _svc.transport.serverUrl,
            nowMs: nowMs,
            refusePeer: _blockedHere,
            persist: persist);
      } on ConnectWriteRefused {
        // A write the round asked for ([persist]) and the vault refused,
        // which ended the round: this device's, and said as this device's.
        // Until 2026-10-31 it reached the card as the vault's exception,
        // after "Could not reach the relay".
        await _threw(invite, ConnectFailure.vault);
        continue;
      } on RelayException catch (e) {
        // The relay refused something, or nothing answered: not a fact about
        // the invite. Say which, and try again next time.
        await _threw(invite,
            relayRefused(e) ? ConnectFailure.refused : ConnectFailure.relay);
        continue;
      } on IOException {
        await _threw(invite, ConnectFailure.relay);
        continue;
      } on TimeoutException {
        await _threw(invite, ConnectFailure.relay);
        continue;
      } catch (_) {
        // Anything else is a fault in this build rather than in the network,
        // and the honest thing to do with one on a timer is to put it on the
        // card rather than to crash or to hide it behind "waiting".
        await _threw(invite, ConnectFailure.fault);
        continue;
      }
      var changed = false;
      if (invite.lastFailure != null) {
        invite.lastFailure = null;
        changed = true;
      }
      if (next != invite.progress) changed = true;
      // The round moved the run, or the vault does not hold it as it is.
      final now = jsonEncode(invite.run.toJson());
      if (now != before || now != invite._inVault) changed = true;
      invite.progress = next;
      if (changed) await _written(invite);
    }
  }

  /// What a round did, written to the vault and shown. A write the vault
  /// refuses is said on the card, as this device's ([ConnectFailure.vault]),
  /// when the card has no failure of the round to say already, and left for
  /// a later write to make — the invite's next round finds the run unlike
  /// what the vault holds ([PendingInvite._inVault]) and writes it again; a
  /// run its round finished has no next round, and goes with the next write
  /// of any invite, since [_save] writes them all — and the pass goes on to
  /// the next invite's round. Until 2026-10-30 it ended the pass there,
  /// before the rounds of the invites after it and before [_pump] armed the
  /// polls, so the first pass after [resume] that met one left the invites
  /// still for as long as the app stayed in front.
  Future<void> _written(PendingInvite invite) async {
    try {
      await _save();
    } on ConnectWriteRefused {
      invite.lastFailure ??= ConnectFailure.vault;
    } catch (_) {
      invite.lastFailure ??= ConnectFailure.fault;
    }
    // Written down all the same once disposed, for the next start to read;
    // but nobody is left to tell.
    if (!_disposed) notifyListeners();
  }

  /// A round that threw: why, on the card, and the invite written down when
  /// that is new or the vault does not hold the run as it now is — the round
  /// moved it before it threw, or a write of it was refused.
  Future<void> _threw(PendingInvite invite, ConnectFailure why) async {
    final told = _fail(invite, why);
    if (told || jsonEncode(invite.run.toJson()) != invite._inVault) {
      await _written(invite);
    }
  }

  /// Records why an invite could not be carried forward. True if the card
  /// has something new to say.
  bool _fail(PendingInvite invite, ConnectFailure why) {
    if (invite.lastFailure == why) return false;
    invite.lastFailure = why;
    return true;
  }

  /// The app is in the foreground: carry the invites forward now, and keep
  /// doing so every [defaultPollEvery] while any is pending.
  ///
  /// Called by the app on start and on every resume. Nothing here runs until
  /// it has been called once, so a test that constructs this class and drives
  /// [pump] by hand sees no timer it did not ask for.
  void resume() {
    _foreground = true;
    unawaited(pump());
  }

  /// The app has left the foreground: stop polling. The invites keep, and the
  /// next [resume] picks them up where they are.
  void pause() {
    _foreground = false;
    _disarm();
  }

  /// True while anything is worth a round trip. A held invite is not: it
  /// waits for its person, not for the network.
  bool get _anythingPending => _invites.any((i) =>
      !i.run.finished && i.progress != ConnectProgress.done && !i.held);

  /// Whether the identity a ceremony revealed is someone this device has
  /// blocked (ADR 0011). Asked by the run the moment it has that identity,
  /// and on the side that opened the invite before its own reveal goes: a
  /// block is every future request from them dropped without a trace, and
  /// an invite answered — or made — by them is one (ADR 0024). The invite
  /// ends there, refused; nothing is added, and they are not told.
  Future<bool> _blockedHere(ConnectIdentity peer) async {
    try {
      return _svc.isBlocked(await _peerRid(peer));
    } on FormatException {
      return false; // the run refuses an unusable code on its own
    }
  }

  void _arm() {
    if (_disposed || !_foreground || !_anythingPending) {
      _disarm();
      return;
    }
    _poll ??= Timer.periodic(_pollEvery, (_) => unawaited(pump()));
  }

  void _disarm() {
    _poll?.cancel();
    _poll = null;
  }

  @override
  void dispose() {
    _disposed = true;
    _disarm();
    super.dispose();
  }

  /// **The two people compared the digits and they matched.**
  ///
  /// Adds the contact and marks it verified. That second half is ADR 0009's
  /// decision, and it rests on one thing: the eight digits cover both account
  /// keys and both post-quantum commitments, in canonical order — the same
  /// facts a safety-number comparison establishes, in a different encoding.
  /// So the tick means here exactly what it means everywhere else, and
  /// `setVerified` records the safety number itself, so every reader of
  /// `verified_sn` — the prompt, the badge, `_classifyVerification` — treats a
  /// connect-verified contact identically to a scanned one.
  ///
  /// If that reasoning is ever rejected, this is the one line to change:
  /// drop the [ChatService.setVerified] call and the contact lands exactly
  /// where [defer] leaves it.
  ///
  /// The commitment the digits covered goes with the tick (26.3). The key it
  /// commits to arrives in-band seconds later and moves the number to the
  /// post-quantum one; until 2026-10-04 that read as a number nobody had
  /// compared, and every connect-verified contact flipped to "re-verify" as
  /// soon as its key landed. The digits had compared it, so the tick moves
  /// with the key that matches — and only with that key.
  ///
  /// [join]: for a group link opened here (ADR 0020), whether going ahead
  /// also joins the group — false makes the inviter a contact only, and
  /// tells them so. Ignored on any other invite.
  ///
  /// An invite of version 3 (§20.9, 44.6) carried their key in the reveal,
  /// so it was established at the add and the tick lands on the
  /// post-quantum number at once; and the device link goes with it: the
  /// sealing key the reveal gave for their device is as authentic as the
  /// digits just compared ([ChatService.noteComparedCeremony]).
  Future<Contact> confirm(PendingInvite invite, {bool join = true}) async {
    final (contact, ours) = await _contactFor(invite);
    // A contact this answer did not add is left exactly as it was: marking
    // an existing record as compared, from a ceremony run at a distance, is
    // the trust-model change [_add] describes.
    if (ours) {
      final keys = invite.run.ceremonyKeys;
      if (keys != null) {
        await _svc.noteComparedCeremony(contact.rid, keys.sealKey);
      }
      await _svc.setVerified(contact.rid, true,
          ceremonyCommit: invite.peer?.pqCommit);
    }
    try {
      await _goAhead(invite, contact, join: join);
    } finally {
      await _finish(invite);
    }
    return contact;
  }

  /// **Nobody compared the digits.** The contact is added at the unverified
  /// state, which is what the paste flow has always produced — the difference
  /// is that here the app knows a comparison was available and skipped, so
  /// the screen says so rather than leaving the user to infer it.
  Future<Contact> defer(PendingInvite invite, {bool join = true}) async {
    final (contact, _) = await _contactFor(invite);
    try {
      await _goAhead(invite, contact, join: join);
    } finally {
      await _finish(invite);
    }
    return contact;
  }

  /// What going ahead also means when the invite was a group link (ADR
  /// 0020). Matching and not comparing both count: the property is that the
  /// joiner's person was TOLD before the digits and went on, not that they
  /// compared them; a mismatch goes nowhere near here.
  ///
  /// The inviter's side starts waiting for the joiner's answer — or, for a
  /// joiner whose client never repeated the group bit, says in the group that
  /// they are a contact only. The joiner's side sends its answer: [join], or
  /// a contact only. Neither adds anyone: the add happens on the inviter's
  /// device when a go-ahead arrives, by the ordinary add path, re-checked
  /// then. Both sides bind the answer to THIS ceremony with its go-ahead tag
  /// (§20.6), which only the two of them can compute.
  Future<void> _goAhead(PendingInvite invite, Contact contact,
      {required bool join}) async {
    final session = invite.run.session;
    if (session == null) return;
    if (invite.mine) {
      final gid = invite.gid;
      if (gid == null) return;
      await _svc.expectLinkJoin(contact.rid, gid,
          issuedMs: invite.run.issuedMs,
          joinerKnows: invite.joinerKnowsGroup,
          tag: await session.goAheadTag());
    } else if (invite.offersGroup) {
      await _svc.acceptLinkJoin(contact.rid,
          tag: await session.goAheadTag(), join: join);
    }
  }

  /// **The digits did not match.** Nothing is added, and the invite is spent:
  /// retrying it would meet whoever produced the mismatch. There is no path
  /// from here that ends with a contact.
  ///
  /// Nothing else is touched — in particular no answer this device still
  /// owes to a group link (ADR 0020). A ceremony that is stopped revealed an
  /// identity nobody verified, so it says nothing about anyone: until
  /// 2026-10-03 stopping a group link ended any answer still owed to the
  /// identity it revealed, and anyone holding a person's public contact code
  /// could make a link that revealed it, and so cancel the answer that
  /// person was genuinely owed. An owed answer carries its own ceremony's
  /// tag, which no other link's wait accepts.
  Future<void> mismatch(PendingInvite invite) async {
    invite.run.abandon();
    await _finish(invite);
  }

  /// The user gave up on an invite. Like [mismatch], it ends this invite and
  /// nothing else.
  ///
  /// Ended once the vault holds the invites without it. A write the vault
  /// refuses leaves the invite as it was, in memory as in the vault — on
  /// the card, and carried forward — and throws [ConnectWriteRefused], for
  /// the screen to say. Until 2026-10-31 the run was ended and the invite
  /// taken out of memory first, and the refusal went uncaught; the vault
  /// held the invite until a later write of the invites went through, and a
  /// start before that read it back and carried it forward.
  Future<void> discard(PendingInvite invite) async {
    final at = _invites.indexWhere((i) => i.id == invite.id);
    if (at < 0) return;
    final going = _invites.removeAt(at);
    try {
      await _save();
    } on ConnectWriteRefused {
      _invites.insert(at.clamp(0, _invites.length), going);
      _arm();
      notifyListeners();
      rethrow;
    }
    going.run.abandon();
    _arm();
    notifyListeners();
  }

  static Future<String> _peerRid(ConnectIdentity peer) async =>
      (await scanContactCode(peer.contactCode)).classical.routingId();

  /// The contact an answer is about, and whether this answer added it.
  ///
  /// Normally that is a new contact, added now ([_add]) and noted on the
  /// invite before anything else happens ([PendingInvite.addedMs]). Two
  /// other cases:
  ///
  ///  * the invite records that this same answer added that very record
  ///    already — the app was killed between the add and the rest — so it
  ///    is this answer's;
  ///  * on a group link (ADR 0020), the peer was a contact before — the
  ///    device the ceremony revealed is the one the record was added from,
  ///    or one the record's own device list names under the account the
  ///    digits covered ([ChatService.contactForDevice]) — so the record is
  ///    used as it is, and the group's answer travels over the sessions that
  ///    already exist with that account. Until 2026-10-03 this was refused
  ///    like any existing contact, and a joiner who had once scanned the
  ///    inviter could never join from their link; and a contact who opened
  ///    the link on another of their devices was added again as a second
  ///    contact, whose answer the inviter never read.
  ///
  /// Anything else already in the contact list is refused, as it always was.
  Future<(Contact, bool)> _contactFor(PendingInvite invite) async {
    final peer = invite.run.session?.peer;
    if (peer == null) {
      throw StateError('the ceremony has not finished');
    }
    final rid = await _peerRid(peer);
    final held = _svc.contactForDevice(rid, peer.accountEdPub);
    if (held != null) {
      if (held.rid == rid && held.createdMs == invite.addedMs) {
        return (held, true);
      }
      if (invite.groupLink) {
        invite.peerWasHeld = true;
        return (held, false);
      }
    }
    final contact = await _add(invite);
    invite.addedMs = contact.createdMs;
    await _save();
    if (debugStopAfterAdd) throw StateError('stopped after the add');
    return (contact, true);
  }

  /// Add the peer the ceremony revealed.
  ///
  /// Someone already in the contact list is refused here, by
  /// [ChatService.addContactFromCode], and the invite is left pending for the
  /// user to discard. Using a connect ceremony to VERIFY an existing contact
  /// remotely would be a good feature — it is the same eight digits over the
  /// same bound identities — but it is a trust-model change (the revealed
  /// bundle may not be the one already held), so it belongs in an ADR rather
  /// than in this method.
  Future<Contact> _add(PendingInvite invite) async {
    final peer = invite.run.session?.peer;
    if (peer == null) {
      throw StateError('the ceremony has not finished');
    }
    // ADR 0012: the ceremony added both sides, so this is not a one-sided add —
    // no "requested" limbo to show, and no request to send (it would only fold).
    // `upgradeExisting: false` keeps the refusal this doc-comment describes.
    // ADR 0021 made a re-scan upgrade an existing record; that is a decision
    // about a code the user scanned in person, and it does not carry over to
    // a ceremony run at a distance, which is the trust-model change above.
    // 44.6: a version-3 ceremony's reveal carried their ML-DSA key and their
    // device's sealing key, and the add holds both, so no `pqid` and no
    // `pqseal` are needed for them (§20.9).
    return _svc.addContactFromCode(peer.contactCode,
        alias: peer.displayName ?? '',
        requested: false,
        upgradeExisting: false,
        ceremony: invite.run.ceremonyKeys);
  }

  Future<void> _finish(PendingInvite invite) async {
    invite.run.confirmed(); // one-time, whichever way it ended
    invite.answered = true;
    invite.progress = ConnectProgress.done;
    _invites.removeWhere((i) => i.id == invite.id);
    await _save();
    _arm();
    notifyListeners();
  }
}
