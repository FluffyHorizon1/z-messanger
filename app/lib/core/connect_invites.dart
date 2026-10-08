import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:z_protocol/z_protocol.dart';

import 'chat_service.dart';
import 'models.dart';

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

  ConnectRun run;

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

  /// Why the last [ConnectInvites.pump] could not carry this invite forward —
  /// an unreachable relay, a refused send — or null when it could. In memory
  /// only, and shown on the card: until 2026-09-17 every failure was
  /// swallowed, so a relay that refused every step read "Waiting for them"
  /// for as long as the person cared to look.
  String? lastFailure;

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

  PendingInvite({
    required this.id,
    required this.mine,
    required this.createdMs,
    required this.run,
    this.gid,
    this.progress = ConnectProgress.waiting,
    this.addedMs,
  });

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
      };

  static Future<PendingInvite> fromJson(Map<String, Object?> j) async =>
      PendingInvite(
        id: j['id'] as String,
        mine: j['mine'] as bool,
        createdMs: (j['created'] as num).toInt(),
        gid: j['gid'] as String?,
        run: await ConnectRun.fromJson(
            (j['run'] as Map).cast<String, Object?>()),
        progress: ConnectProgress.values.firstWhere(
            (p) => p.name == j['progress'],
            orElse: () => ConnectProgress.waiting),
        addedMs: (j['addedMs'] as num?)?.toInt(),
      );
}

/// The app's half of the connect ceremony: making invites, opening them, and
/// carrying each one forward whenever there is a network (17.3, §20).
///
/// The protocol work is in `z_protocol`'s `ConnectRun`, which is a state
/// machine rather than a conversation precisely because the two people are
/// never online together. This class is the part that owns those runs: it
/// writes them to the vault after every step, so closing the app is not an
/// event the ceremony has to survive so much as one it does not notice.
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

  /// Sealed like everything else in the vault. It holds invite secrets, and
  /// an invite secret is a bearer token until it is spent.
  static const String _kvKey = 'connect_invites';

  /// Test seam: open invites as a client from before group links (ADR 0020)
  /// does — message 3's group bit is neither read nor repeated, so nothing
  /// is said about a group and no go-ahead is ever sent. That is the joiner
  /// the inviter has to recognise and refuse to add.
  @visibleForTesting
  bool debugBeforeGroupLinks = false;

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

  final List<PendingInvite> _invites = [];
  bool _loaded = false;

  List<PendingInvite> get invites => List.unmodifiable(_invites);

  /// Read the pending invites back after a restart. Safe to call twice.
  Future<void> load() async {
    if (_loaded) return;
    _loaded = true;
    final raw = await _svc.vault.kvGet(_kvKey);
    if (raw == null) return;
    try {
      for (final e in (jsonDecode(raw) as List)) {
        _invites.add(
            await PendingInvite.fromJson((e as Map).cast<String, Object?>()));
      }
    } catch (_) {
      // A record this build cannot read is not worth losing the app over, and
      // the invite it describes can be made again in two taps.
      _invites.clear();
    }
    notifyListeners();
  }

  Future<void> _save() async {
    await _svc.vault
        .kvPut(_kvKey, jsonEncode([for (final i in _invites) i.toJson()]));
  }

  Future<ConnectIdentity> _me() async => ConnectIdentity.fromCode(
      debugMyCode ?? await _svc.myContactCode(),
      displayName: _svc.displayName);

  /// Make an invite. Nothing is posted until the first [pump].
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
    final invite = PendingInvite(
      id: b64url(randomBytes(9)),
      mine: true,
      createdMs: now,
      gid: gid,
      run: await ConnectRun.invite(
          me: await _me(), nowMs: now, group: gid != null),
    );
    _invites.add(invite);
    await _save();
    _arm();
    notifyListeners();
    return invite;
  }

  /// Open an invite somebody sent: a `https://…/i#<code>` link or the printed
  /// code itself, whichever the user has.
  ///
  /// Consumes the link entirely on this device — the code is in the URL
  /// fragment, which no browser sends to a server, and nothing here fetches
  /// the link either. This method touches no network at all.
  Future<PendingInvite> open(String linkOrCode, {int? nowMs}) async {
    await load();
    final code = parseInvite(linkOrCode);
    if (code == null) {
      throw const FormatException('that is not a Z invite');
    }
    for (final existing in _invites) {
      if (constantTimeEquals(existing.run.code.secret, code.secret)) {
        throw const FormatException('that invite is already open');
      }
    }
    final now = nowMs ?? DateTime.now().millisecondsSinceEpoch;
    final invite = PendingInvite(
      id: b64url(randomBytes(9)),
      mine: false,
      createdMs: now,
      run: ConnectRun.accept(
          me: await _me(),
          code: code,
          nowMs: now,
          groupAware: !debugBeforeGroupLinks),
    );
    _invites.add(invite);
    await _save();
    _arm();
    notifyListeners();
    return invite;
  }

  /// A link or a printed code, whichever was handed over. Null if neither.
  static ConnectCode? parseInvite(String input) {
    final s = input.trim();
    if (s.isEmpty) return null;
    final fromLink = ConnectCode.fromLink(s);
    if (fromLink != null) return fromLink;
    try {
      return ConnectCode.parse(s);
    } on FormatException {
      return null;
    }
  }

  /// Carry every pending invite as far as it will go right now.
  ///
  /// One connect-act-disconnect per invite, and the result is written to the
  /// vault before this returns — so an app killed mid-ceremony resumes from
  /// where it actually got to rather than from where it started.
  ///
  /// One at a time. A second call while one is in flight joins it rather than
  /// starting another, because two steps on the same run at once are not
  /// merely wasteful: the acceptor's step picks its ephemeral and posts it,
  /// and two of them pick two, the relay keeps the first, and the run keeps
  /// the second — so the inviter opens against one key and this side checks
  /// against the other, the reveal does not open, and the invite is spent on
  /// a mismatch nobody produced. With a poll running beside a button, that
  /// overlap is not hypothetical.
  Future<void> pump({int? nowMs}) {
    final running = _inFlight;
    if (running != null) return running;
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
    await load();
    if (_invites.isEmpty) {
      _disarm();
      return;
    }
    var changed = false;
    for (final invite in List.of(_invites)) {
      // Spent, or finished and waiting on a human: nothing a round trip can
      // change. (Stepping a finished run only turns `confirm` into `done`,
      // which the card does not distinguish and the poll should not pay for.)
      if (invite.run.finished) continue;
      if (invite.progress == ConnectProgress.done) continue;
      final ConnectProgress next;
      try {
        next = await invite.run
            .step(relayUrl: _svc.transport.serverUrl, nowMs: nowMs);
      } on RelayException catch (e) {
        // The relay refused something, or nothing answered: not a fact about
        // the invite. Leave it alone, say why, and try again next time.
        changed = _fail(invite, e.message) || changed;
        continue;
      } on IOException catch (e) {
        changed = _fail(invite, '$e') || changed;
        continue;
      } on TimeoutException catch (e) {
        changed = _fail(invite, e.message ?? 'timed out') || changed;
        continue;
      } catch (e) {
        // Anything else is a fault in this build rather than in the network,
        // and the honest thing to do with one on a timer is to put it on the
        // card rather than to crash or to hide it behind "waiting".
        changed = _fail(invite, '$e') || changed;
        continue;
      }
      if (invite.lastFailure != null) {
        invite.lastFailure = null;
        changed = true;
      }
      if (next != invite.progress) changed = true;
      invite.progress = next;
    }
    if (changed) {
      await _save();
      notifyListeners();
    }
    _arm();
  }

  /// Records why an invite could not be carried forward. True if the card
  /// has something new to say.
  bool _fail(PendingInvite invite, String why) {
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

  /// True while anything is worth a round trip.
  bool get _anythingPending => _invites
      .any((i) => !i.run.finished && i.progress != ConnectProgress.done);

  void _arm() {
    if (!_foreground || !_anythingPending) {
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
  Future<Contact> confirm(PendingInvite invite, {bool join = true}) async {
    final (contact, ours) = await _contactFor(invite);
    // A contact this answer did not add is left exactly as it was: marking
    // an existing record as compared, from a ceremony run at a distance, is
    // the trust-model change [_add] describes.
    if (ours) {
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
  Future<void> discard(PendingInvite invite) async {
    invite.run.abandon();
    _invites.removeWhere((i) => i.id == invite.id);
    await _save();
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
    return _svc.addContactFromCode(peer.contactCode,
        alias: peer.displayName ?? '', requested: false, upgradeExisting: false);
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
