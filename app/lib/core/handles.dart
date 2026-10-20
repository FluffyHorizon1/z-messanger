/// Handles in the app (phase 38; ADR 0015 revision 2; PROTOCOL.md §21).
///
/// A handle — `nick.digits` — is a name someone can be found by. It resolves,
/// through a log of its own (§21.5), to an **introduction mailbox**: a key
/// pair made for the handle and unrelated to the account, whose routing id
/// anybody who looks the handle up can write a contact request to. The
/// account key is never in the handle log, so R20's premise — that only
/// someone who already holds an account's key can compute its transparency
/// label — survives a guessable name.
///
/// This file is the app's half, on top of the protocol library's
/// (`handles.dart`, `transparency_bucket.dart`, the relay client's `intro`
/// frame and stamped send):
///
/// * where the handle log is and which key signs it, and the witness it is
///   held to ([HandleConfig]) — EMPTY by default, so until a build pins the
///   log and its witness every handle surface says handles are unavailable;
/// * the witness check ([HandleService.witnessState]): every lookup's head,
///   held to a witness's record under the key pinned for it (§19.5 step 3,
///   §21.8), and a lookup the record contradicts refused; and, after the
///   fact, the head of a lookup a request was sent on that the record did not
///   yet cover, kept, every head a later lookup ends with held to it, and the
///   first record that covers it held to it too — checked on its own, twice
///   at most, when nothing looks it up ([handleWitnessCheckBack]) — a fork
///   found so, a head the witness never covered, and one the log shows this
///   device two histories about while it is kept, said on what relied on it
///   ([HandleForkWarning]);
/// * claiming one ([HandleService.prepareClaim], [HandleService.commitClaim]):
///   the owner and introduction seeds, a recovery code shown once and never
///   stored, and a publish after a random delay (§21.8) so the moment of the
///   claim is not the moment of anything else the account did;
/// * the introduction mailbox ([HandleService.drain]): its own relay
///   connection, authenticated as the introduction identity and never the
///   account's, re-flagged with the record's difficulty after every
///   authentication, never registered for push, drained on the app's
///   foreground and on a jittered timer while the app is open — and only on
///   the account's primary device;
/// * finding someone and asking ([HandleService.find],
///   [HandleService.request]): the label off the UI thread, the handle's
///   bucket among decoys at a size the client counted itself
///   (`handle_lookups.dart`), verified against the pinned key, the record
///   held to its one encoding and its signatures and to what this device
///   found the last time, and an ordinary contact request sealed to the
///   introduction key with a proof of work computed off the UI thread;
/// * the acknowledgement both ways: the owner's acceptance signs `ia` with
///   the introduction key ([HandleService.acknowledgement]); the requester
///   recognises one against a request it sent
///   ([HandleService.matchAcknowledgement]);
/// * managing ([HandleService.pause], [HandleService.resume],
///   [HandleService.rotate], [HandleService.setDifficulty],
///   [HandleService.retire]) and recovering with the code
///   ([HandleService.prepareRecover], [HandleService.commitRecover]);
/// * what a backup carries ([HandleBackup]).
///
/// What it stores, all sealed in the vault: `handle` (this account's handle —
/// its canonical name, label, owner and introduction seeds, difficulty,
/// recovery commitment, version and phase; never the recovery code),
/// `handle_in` (for each pending request that came through the handle: the
/// handle, the mailbox it reached, the request's id, and whether it has been
/// seen — plus the introduction seeds of mailboxes since rotated or retired
/// that a pending request still needs to be acknowledged with), `handle_out`
/// (the requests this device sent to handles and is waiting on),
/// `handle_stamps` and `handle_stamps_<day>_<n>` (the introduction requests
/// decided here, by a keyed digest, for as long as their stamps could be
/// presented again, and what the drains dropped — [HandleStampLedger]),
/// `handle_lookup` (the resolver's decoy key,
/// the bucket size the log's answers bear out, and the owner key,
/// commitment, version and record hash of each handle found —
/// [HandleLookupMemory]), `handle_config`, and `handle_witness_ok_ms` and
/// `handle_witness_since_ms` (when the witness last agreed, and since when it
/// has been asked without an answer that counts, each with the configuration
/// it was recorded under), `handle_witness_heads` (the heads of lookups a
/// request was sent on that the witness had not yet covered, with what relied
/// on each, under the configuration they were taken under) and
/// `handle_witness_warnings` (the forks those heads were found to be after
/// the fact, and the heads that went before the witness covered them). A
/// contact made through a handle keeps the handle under
/// `hvia_<rid>`.
library;

import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:io';
import 'dart:isolate';
import 'dart:math';

import 'package:flutter/foundation.dart';
import 'package:z_protocol/z_protocol.dart';

import 'handle_lookups.dart';
import 'key_transparency.dart' show KtFetcher, KtResponse;
import 'vault.dart';

export 'handle_lookups.dart' show HandleChange;

// =============================================================================
// Configuration
// =============================================================================

/// Build-time defaults: EMPTY. The four handle values — the handle log's
/// address and key, and its witness's record address and key — are pinned
/// here, in this file, together, in one release: a log pinned without its
/// witness is a log whose readers cannot catch it showing two histories
/// (THREAT_MODEL R50), and `tool/check_ga.py` refuses a tree that sets some
/// of the four and not all. Until they are, there is no log to claim in or
/// resolve against, and the app says so on every handle surface rather than
/// pointing at a guess. The handle log is a second public service with its
/// own key (ADR 0015's Consequences 1), and its witness a third. Set them in
/// this file, as the transparency log's are set in `key_transparency.dart` —
/// not with a `--dart-define` on one build command (`tool/check_ga.py`
/// explains why a value on the command line is a value no rebuild
/// reproduces, and refuses `HANDLE_LOG_` and `HANDLE_WITNESS_` there).
///
/// The witness is a mirror of the handle log, run by somebody other than its
/// operator, that co-signs each head it has verified in the handle witness
/// context (§19.10, §21.5). Its address is that mirror's record, the
/// `/sth.json` it serves, fetched as it stands; its key is the `witness.pub`
/// inside it, handed over out of band. Both or neither
/// ([HandleConfig.witnessProblem]).
const String defaultHandleLogUrl =
    String.fromEnvironment('HANDLE_LOG_URL', defaultValue: '');
const String defaultHandleLogPub =
    String.fromEnvironment('HANDLE_LOG_PUB', defaultValue: '');
const String defaultHandleWitnessUrl =
    String.fromEnvironment('HANDLE_WITNESS_URL', defaultValue: '');
const String defaultHandleWitnessPub =
    String.fromEnvironment('HANDLE_WITNESS_PUB', defaultValue: '');

/// A configuration that cannot be saved ([HandleService.setConfig]):
/// [reason] is an l10n key, not a sentence, and one of the transparency
/// client's three (`KtConfigInvalid`) — the rule is the same rule, and the
/// screen says it in the same words.
class HandleConfigInvalid implements Exception {
  final String reason;
  HandleConfigInvalid(this.reason);
  @override
  String toString() => 'HandleConfigInvalid($reason)';
}

/// Where the handle log is and which key signs it — `kt/` run with
/// `KT_MODE=handles`, a separate instance under its own key (§21.5), never
/// the transparency log's — and the witness this device holds it to.
/// Persisted sealed under `handle_config`; absent, the build-time defaults
/// apply. A stored configuration from before the witness has no `wurl` or
/// `wpub`, and reads as one with no witness, as a stored `kt_config` from
/// before the transparency log's witness was pinned does: a device whose user
/// saved a handle log of their own keeps it as it was, and gets a witness
/// only by adding one beside it. A developer-mode setting, like the
/// transparency log's address and key.
class HandleConfig {
  final String logUrl;
  final String logPubB64;
  final String witnessUrl;
  final String witnessPubB64;

  const HandleConfig({
    required this.logUrl,
    required this.logPubB64,
    this.witnessUrl = '',
    this.witnessPubB64 = '',
  });

  static const HandleConfig defaults = HandleConfig(
    logUrl: defaultHandleLogUrl,
    logPubB64: defaultHandleLogPub,
    witnessUrl: defaultHandleWitnessUrl,
    witnessPubB64: defaultHandleWitnessPub,
  );

  static const HandleConfig off = HandleConfig(logUrl: '', logPubB64: '');

  /// The pinned key, or null when it is absent or not 32 bytes of base64.
  Uint8List? get logPub => _key(logPubB64);

  /// The key pinned for the witness, likewise.
  Uint8List? get witnessPub => _key(witnessPubB64);

  /// An address AND a key: a log nobody pinned is not one an answer can be
  /// checked against, so half a configuration is none. A witness is not
  /// needed for this: a self-hoster may run a handle log with no witness, as
  /// with the transparency log. That the shipped build pins all four values
  /// together is `tool/check_ga.py`'s rule, not this one's.
  bool get enabled => logUrl.trim().isNotEmpty && logPub != null;

  /// A witness is an address AND a key this device pinned (§19.5 step 3): a
  /// co-signature checked against the key the record carries says only that
  /// whoever served it could sign, which the log's own operator can. Half a
  /// pair is no witness, and its address is never fetched.
  bool get hasWitness => witnessUrl.trim().isNotEmpty && witnessPub != null;

  /// Why this configuration cannot be saved, or null — the transparency
  /// client's rule (`KtConfig.witnessProblem`) and its three reasons: half a
  /// witness is not a weaker witness, and being quietly ignored is how
  /// somebody ends up believing they have one.
  String? get witnessProblem {
    final hasUrl = witnessUrl.trim().isNotEmpty;
    final hasKey = witnessPubB64.trim().isNotEmpty;
    if (!hasUrl && !hasKey) return null;
    if (hasUrl && !hasKey) return 'urlWithoutKey';
    if (!hasUrl && hasKey) return 'keyWithoutUrl';
    if (witnessPub == null) return 'keyNotValid';
    return null;
  }

  static Uint8List? _key(String b64Key) {
    final b = b64Key.trim();
    if (b.isEmpty) return null;
    try {
      final k = unb64(b);
      return k.length == 32 ? k : null;
    } on FormatException {
      return null;
    }
  }

  /// The witness's two members are written only when set, so a
  /// configuration with no witness is stored — and archived — exactly as it
  /// was before there was one to set.
  Map<String, Object?> toJson() => {
        'url': logUrl,
        'pub': logPubB64,
        if (witnessUrl.isNotEmpty) 'wurl': witnessUrl,
        if (witnessPubB64.isNotEmpty) 'wpub': witnessPubB64,
      };

  static HandleConfig fromJson(Map<String, Object?> j) => HandleConfig(
        logUrl: (j['url'] as String?) ?? '',
        logPubB64: (j['pub'] as String?) ?? '',
        witnessUrl: (j['wurl'] as String?) ?? '',
        witnessPubB64: (j['wpub'] as String?) ?? '',
      );
}

// =============================================================================
// The numbers (PROTOCOL §21.8), and the pure functions over them
// =============================================================================

/// A claim is published at a moment drawn uniformly from this window after
/// the person confirms it (F5). Tens of minutes: long enough to clear the
/// burst of activity the claim sits in — the person is using the app, so
/// the account is connected to the relay, perhaps sending, perhaps checking
/// or publishing to the transparency log — so the publish cannot be lined up
/// with the account's own traffic by its timing; short enough that the
/// person who just claimed a name sees it go live while they still have the
/// app open, which is when it can be published at all. The log keeps only
/// the hour (§21.5), so the delay and the hour together put the claim in an
/// hour unrelated to the tap that made it.
const Duration handleClaimDelayMin = Duration(minutes: 10);
const Duration handleClaimDelayMax = Duration(minutes: 60);

/// A claim whose moment came while the app was closed is not published as
/// the app starts — a start is itself a burst (the relay connection, the
/// transparency log's check) — but at a moment drawn again from this window.
const Duration handleStartDelayMin = Duration(minutes: 3);
const Duration handleStartDelayMax = Duration(minutes: 20);

/// How often the introduction mailbox is drained while the app is open, give
/// or take a third (§21.8), and how long after the app comes to the
/// foreground the first drain waits — so that the introduction identity's
/// connection does not open in the same second as the account's own, which
/// the relay's operator would otherwise see side by side (R49).
const Duration handleDrainEvery = Duration(minutes: 15);
const double handleDrainSpread = 1 / 3;
const Duration handleForegroundDelayMin = Duration(seconds: 3);
const Duration handleForegroundDelayMax = Duration(seconds: 30);

/// A drain reads until nothing has arrived for [handleDrainQuiet], and never
/// for longer than [handleDrainMax]: the relay hands over what it holds as
/// soon as the connection authenticates, and an envelope left unread is
/// simply read at the next drain.
const Duration handleDrainQuiet = Duration(milliseconds: 1500);
const Duration handleDrainMax = Duration(seconds: 20);

/// At most this many pending requests that came through the handle, counted
/// apart from those that came by a code or a link (§21.8): past it the
/// oldest one not yet seen on the Requests screen goes, and a request the
/// person has looked at never does. A handle is a public door, so a wave
/// through it must never push out a request from someone who had the
/// person's code — which, when the two shared one cap, the drain did 3 to 30
/// seconds after the app opened, before anyone could look, as an
/// independent review of handles found (2026-10-09). The chat service
/// applies it as requests arrive (`ChatService.maxPendingHandleRequests`);
/// this file also bounds with it what a restore takes back of the handle's
/// records ([HandleBackup.restore]).
const int handleInboundCap = 100;

/// At most this many outgoing handle requests are remembered, and three
/// request ids for each: every acceptance that carries an `ia` is checked
/// against each of them, so this is also what one forged acceptance can cost
/// this device — at most sixty signature checks.
const int handleOutgoingCap = 20;
const int handleOutgoingIdsPerHandle = 3;

/// The difficulty a new claim asks of senders (§21.7): 2^20 hashes, about a
/// second of one core in the app's pure Dart and a few on a phone — a pause a
/// person sending one request accepts, and a million hashes for every request
/// in a wave. The owner can raise it (or lower it) with an update.
const int handleDefaultPow = 20;

/// The levels the app offers.
const List<int> handlePowLevels = [16, 18, 20, 22, 24];

/// After the difficulty changes, a stamp made for the previous one still
/// counts at the owner's check for this long (§21.8): a requester who
/// resolved the record just before a raise stamps at the old difficulty, and
/// so does every stamp the relay took before its flag was renewed — and a
/// stamp is good for one to two days of the relay's clock.
const Duration handlePowGrace = Duration(days: 2);

/// The witness's record is fetched at most once a lookup, and a record that
/// verified under the pinned key is used again, by every lookup under the
/// same configuration, for this long after it was fetched (§21.8). A record
/// used again is compared afresh with each lookup's head — the log, not the
/// witness, is asked for the proof between them — so reuse gives up only how
/// recent the witness's view is: the log re-signs its head at least every ten
/// minutes and the reference witness syncs every five, so a record this old
/// is a sync or two behind. What it saves is the witness's host learning the
/// address and the moment of every step — a claim's checks of up to five
/// free names, a person's run of lookups, a change with the read before it
/// and the drain after it. Nor is it fetched on a timer of its own, but for a
/// kept head's checks ([handleWitnessCheckBack]), which fetch it afresh: a
/// device that sent no handle request asks the witness nothing on a timer.
const Duration handleWitnessReuse = Duration(minutes: 10);

/// A witness's record over a head older than this is checked like any other
/// but is not the witness agreeing (§19.5): a witness that follows the log
/// co-signs a head it re-signs every ten minutes, so a record a day old is a
/// witness that stopped, or a replay.
const Duration handleWitnessStale = Duration(hours: 24);

/// Asking a witness for longer than this — from the first check whose end
/// was not its agreement to the latest, a lookup's or a kept head's check of
/// its own ([handleWitnessCheckBack]), which count alike — with no agreement
/// in between is a witness gone quiet. Measured over those checks and not by
/// the clock alone, since the client asks only when handles are used or a
/// kept head is due a check: a day of the calendar with neither is not a day
/// of the witness saying nothing.
const Duration handleWitnessQuietAfter = Duration(hours: 24);

/// After the fact (§21.8; Finnian's decision of 2026‑10‑20): the head a lookup
/// ended with, when the witness's record it was checked against did not cover
/// it — a record smaller than the head, or none that verified — is kept once a
/// request is sent on that lookup; every head a lookup on this device ends
/// with after it is held to it, and so is the first record that covers it —
/// but not the log's own head a lookup's check asks for beside a witness
/// ahead of it, nor the heads of a lookup that fails within itself
/// ([HandleService._accept]). A head no
/// contact holds is bounded by the outgoing list, and goes with its request,
/// in silence, as the request goes: so a burst of requests in honest
/// operation never raises a warning. Of the heads contacts hold, at most this
/// many are kept: past it, the one looked up longest ago goes first — and,
/// never covered, it is said on what relied on it, as at the lapse
/// ([handleWitnessKeepFor]). It is also the most consistency proofs one
/// lookup, or one check of a head's own, asks the log for to hold the kept
/// heads.
const int handleWitnessKeptCap = handleOutgoingCap;

/// ... and each for at most this long, or until covered. The reference
/// witness syncs every five minutes, so a head it has not reached in a month
/// is one it never will — a witness that stopped, or one this device cannot
/// reach, which Settings has called quiet since the second day of lookups
/// without it. A head that reaches this age is checked once more first, on
/// its own ([handleWitnessCheckBack]), and one that check leaves undecided —
/// a check made, with its answers, or one no moment in front could get its
/// answers for across [handleWitnessCheckFor] of trying — is not dropped in
/// silence: what relied on it is told the answer was never confirmed
/// ([HandleWarningKind]) — the contact, or the request while it still waits,
/// since an acceptance is matched to a request however old it is
/// ([HandleService.matchAcknowledgement] asks only that it is still waited
/// on).
const Duration handleWitnessKeepFor = Duration(days: 30);

/// A kept head that no lookup or drain has decided is checked on its own,
/// with no lookup, twice at most (§21.8): its check-back, at a moment drawn
/// for it as it is kept, uniformly from this long to
/// [handleWitnessCheckBackMax] after the request; and its last check, once it
/// is [handleWitnessKeepFor] old. Each is made at the first moment the app is
/// in front at or after its time — a start, a return to the front, or, while
/// it stays there, a one-shot timer — and never at that moment itself: a
/// moment drawn as the drain's first wait is, 3 to 30 seconds after it
/// ([handleForegroundDelayMin]), so that the check is not lined up with the
/// account's own connection coming back (R49). Each check fetches the
/// witness's record afresh — one used again cannot cover a head kept after
/// it was fetched — and the log's head, once for every head due, and holds
/// every kept head to them as a lookup's record and head hold them. The
/// reference witness syncs every five minutes and the log re-signs its head
/// at least every ten, so a record fetched this long after an honest head was
/// shown covers it, and the head goes with nothing said; a fork that departed
/// before that record's size is found then, as a fork — and one the log
/// keeps the device on while the record passes the kept head is said then as
/// an answer never confirmed ([HandleService._holdKept]). A check counts as
/// made only once it got its answers ([handleWitnessCheckAgain]). Nothing is
/// asked on a timer of its own while no head is kept: a device on which
/// nobody sent a handle request asks the witness nothing on a timer.
const Duration handleWitnessCheckBack = Duration(minutes: 20);
const Duration handleWitnessCheckBackMax = Duration(minutes: 30);

/// A check of a kept head's own is made only once it got its answers: a
/// record fetched afresh that verified, and the log's head and the proofs
/// the head needed — or the log refusing or withholding them, which is an
/// answer. One that did not — a fetch that failed, an app killed while it was
/// out, a proof not asked because a check of the head waited on the log
/// within [HandleService.witnessReuse], a write to the vault that failed —
/// spends nothing, and is tried again at later moments in front, at most
/// once in this long ...
const Duration handleWitnessCheckAgain = Duration(minutes: 10);

/// ... for up to this long of such moments, measured from the first that got
/// no answers to the latest, as a quiet witness is ([handleWitnessQuietAfter]):
/// a day of the calendar the app was not in front is not a day of trying.
/// Then it is given up on — the check-back, leaving the head kept for its
/// last check; the last check, leaving the head to lapse
/// ([handleWitnessKeepFor]).
const Duration handleWitnessCheckFor = Duration(hours: 24);

/// The fewest leading zero bits a stamp must reach for the owner's drain to
/// count it: [pow], the difficulty published — or, until [prevPowUntil], the
/// previous one when that was lower.
int handleStampFloor(int pow,
    {int? prevPow, int? prevPowUntil, required int nowMs}) {
  if (prevPow != null && prevPowUntil != null && nowMs < prevPowUntil) {
    return min(pow, prevPow);
  }
  return pow;
}

/// A stamp an introduction envelope came with, counted as the relay counts
/// it (§21.6, §21.7): the day it was made for, the SHA-256 of the envelope
/// (the payload string as delivered) and the leading zero bits of
/// `SHA-256(introPowInput(…))`.
class HandleStamp {
  final int day;
  final Uint8List envelopeHash;
  final int bits;
  const HandleStamp(
      {required this.day, required this.envelopeHash, required this.bits});
}

/// The stamp an envelope delivered to the introduction mailbox [introRid]
/// carries, as the owner's drain counts it — with the protocol library's own
/// [introPowInput], so it computes exactly what the relay did: the routing
/// id's 32 bytes, [powDay], the SHA-256 of [payload] and the nonce. Null when
/// there is nothing to count: no [pow] or [powDay] (a relay that lost the
/// mailbox's flag, or one that does not hand stamps on), a [pow] that is not
/// the canonical 22 characters of `b64url` for 16 bytes, or a [powDay] that
/// is neither the relay's day of the envelope's [serverTs] nor the day before
/// — the only two days the relay takes a stamp for.
Future<HandleStamp?> handleStampOf(
    {required String introRid,
    required String payload,
    required String? pow,
    required int? powDay,
    required int serverTs}) async {
  if (pow == null || powDay == null) return null;
  final Uint8List nonce;
  final Uint8List rid;
  try {
    nonce = unb64url(pow);
    rid = unb64url(introRid);
  } on FormatException {
    return null;
  }
  if (nonce.length != introPowNonceLength || b64url(nonce) != pow) return null;
  if (rid.length != 32) return null;
  final relayDay = introPowDay(serverTs);
  if (powDay != relayDay && powDay != relayDay - 1) return null;
  if (powDay < 0 || powDay > 0xffffffff) return null;
  final envelopeHash = await sha256Bytes(utf8.encode(payload));
  final h = await sha256Bytes(introPowInput(
      ridBytes: rid, day: powDay, envelopeHash: envelopeHash, nonce: nonce));
  return HandleStamp(
      day: powDay, envelopeHash: envelopeHash, bits: introPowZeroBits(h));
}

/// How many introduction requests [HandleStampLedger] remembers for one day
/// of stamps at most: about what the relay hands the owner in a day of
/// drains every quarter of an hour (`MAX_QUEUE_MSGS_PER_USER`, 5 000, a
/// drain; 96 drains: 480 000), so a day's flood is remembered whole; past
/// it a request is still filed, and the owner is told.
const int handleStampDayCap = 1 << 19;

/// How many digests one row of the ledger holds in the vault
/// (`handle_stamps_<day>_<n>`): a request costs one write of this row, and
/// a day at [handleStampDayCap] is a thousand such rows.
const int handleStampChunk = 512;

/// How many days of stamps the ledger keeps: a stamp for day D is taken by
/// the relay through D+1 (§21.6), and the relay holds an envelope for up to
/// 72 hours (`QUEUE_TTL_HOURS`), so the last copy it could hand over comes
/// before the end of D+4 — day D is kept until D+5 begins.
const int handleStampDaysKept = 5;

/// The introduction requests this device has decided, so that none is
/// decided twice (§21.8). A stamp binds its envelope and its day, not its
/// sender, and stays good at the relay for one to two days; an envelope the
/// drain has acknowledged is gone from the relay, so whoever kept a copy of
/// it — the relay's operator, or the sender — could send the same envelope
/// and stamp again, and before this ledger a request the cap had pushed out
/// was filed again with no new work.
///
/// What it remembers: every envelope that opened as a request signed by its
/// sender and addressed to the mailbox, whatever the rules then made of it —
/// filed, pushed out by the cap, or refused. Anything else is not a request
/// however often it comes, and costs nothing to decide again; so a flood of
/// stamped junk, which is the cheapest thing to send, takes no room here.
///
/// How: by a digest of the envelope — the first 6 bytes of
/// `SHA-256(salt ‖ SHA-256(envelope))`, the inner hash being the one the
/// stamp commits to, so a copy is known before it is opened, whoever stamps
/// it again; the [salt] is this device's own, so nobody outside can tell
/// which envelopes share a digest — under the day its stamp was made for,
/// exactly: one by one, in sorted order, 8 bytes each in memory. A digest
/// already held under any kept day is refused; two distinct envelopes share
/// one by chance alone, once in 2⁴⁸, so under a flood that fills every kept
/// day — 2.6 million digests — an honest request is refused by mistake once
/// in a hundred million, and no flood can raise that: the second review of
/// the handles fixes (2026-10-10) drove a Bloom filter of fixed size, which
/// this ledger had, to refuse 70 % of honest requests with 500 000 distinct
/// stamped requests in a day. A day's digests are kept for
/// [handleStampDaysKept] days.
///
/// Bounded: a day holds at most [perDay] digests ([handleStampDayCap],
/// 4 MiB), about what the relay hands over in a day; one more that day is
/// filed without being remembered, and counted ([tally]), so the owner is
/// told that copies of the rest of that day could be filed again and can
/// raise the work a request costs. In the vault a day is rows of [chunk]
/// digests ([HandleStampChunk]), each written as it fills, so a request
/// costs one small write however large the flood has made the day.
///
/// The tallies — requests dropped for their stamp, copies refused, requests
/// filed unremembered — are kept by the relay's day beside the digests, for
/// the same days, so the handle screen can say what the drains did.
class HandleStampLedger {
  HandleStampLedger(
      {Uint8List? salt,
      this.perDay = handleStampDayCap,
      this.chunk = handleStampChunk,
      Iterable<HandleStampChunk> chunks = const [],
      Map<int, HandleInboxTally>? tallies})
      : salt = salt ?? randomBytes(16) {
    final byDay = <int, List<HandleStampChunk>>{};
    for (final c in chunks) {
      (byDay[c.day] ??= []).add(c);
    }
    for (final e in byDay.entries) {
      _days[e.key] = _StampDay.fromChunks(e.value, chunk);
    }
    if (tallies != null) _tallies.addAll(tallies);
  }

  static const int dayMs = 86400000;

  /// The bytes of a digest, in the vault and in [HandleStampChunk.bytes].
  static const int digestBytes = 6;

  /// This device's key for the digests.
  final Uint8List salt;
  final int perDay;

  /// Digests a vault row holds. Set before the first digest is added; rows
  /// read back are taken as they are, whatever their length.
  int chunk;

  final SplayTreeMap<int, _StampDay> _days = SplayTreeMap();
  final SplayTreeMap<int, HandleInboxTally> _tallies = SplayTreeMap();

  /// How many digests the kept days hold.
  int get length => _days.values.fold(0, (n, d) => n + d.count);

  /// What the kept days take in memory: 8 bytes a digest, as [Int64List]
  /// holds them, and the row being filled.
  int get bytesInMemory => _days.values.fold(0, (n, d) => n + d.bytes);

  /// The days held, oldest first.
  Iterable<int> get days => _days.keys;

  /// Whether [day] holds [perDay] digests: a request for it is filed without
  /// being remembered.
  bool isFull(int day) => (_days[day]?.count ?? 0) >= perDay;

  /// The digest under which an envelope whose SHA-256 is [envelopeHash] is
  /// remembered: the first 6 bytes of `SHA-256(salt ‖ envelopeHash)`, as a
  /// number below 2⁴⁸.
  Future<int> digestOf(Uint8List envelopeHash) async {
    final h = await sha256Bytes([...salt, ...envelopeHash]);
    var v = 0;
    for (var i = 0; i < digestBytes; i++) {
      v = (v << 8) | h[i];
    }
    return v;
  }

  /// Whether the envelope with this [digest] has been decided here before,
  /// under any day still kept.
  bool refuses(int digest) => _days.values.any((d) => d.has(digest));

  /// Remember a request decided now, whose stamp was made for [day]: the
  /// vault row to write — the digests of the row being filled, [digest]
  /// among them — or null when it was held already or the day is full
  /// ([isFull]), in which case nothing changes.
  HandleStampChunk? add(int day, int digest) {
    final d = _days[day] ??= _StampDay();
    if (d.has(digest) || d.count >= perDay) return null;
    return d.add(day, digest, chunk);
  }

  /// The tally for [day], to count on.
  HandleInboxTally tally(int day) => _tallies[day] ??= HandleInboxTally();

  /// What the drains did over the kept days, summed.
  HandleInboxTally get tallied {
    final t = HandleInboxTally();
    for (final x in _tallies.values) {
      t.unstamped += x.unstamped;
      t.copies += x.copies;
      t.unremembered += x.unremembered;
    }
    return t;
  }

  /// Forget the days whose stamps can no longer be presented; the days that
  /// went, each with how many vault rows it had, so the rows can go too.
  Map<int, int> prune(int nowMs) {
    final gone = <int, int>{};
    _days.removeWhere((day, d) {
      if ((day + handleStampDaysKept) * dayMs > nowMs) return false;
      gone[day] = d.rows;
      return true;
    });
    _tallies.removeWhere(
        (day, _) => (day + handleStampDaysKept) * dayMs <= nowMs);
    return gone;
  }

  /// The ledger's own record (`handle_stamps`): the salt and the tallies.
  /// The digests are rows of their own ([HandleStampChunk]).
  Map<String, Object?> toJson() => {
        'v': 2,
        'salt': b64url(salt),
        'tally': {
          for (final e in _tallies.entries)
            if (!e.value.isEmpty) '${e.key}': e.value.toJson()
        },
      };

  /// The salt and tallies [j] records; null when it is not a record this
  /// build wrote.
  static ({Uint8List salt, Map<int, HandleInboxTally> tallies})? readJson(
      Object? j) {
    if (j is! Map || j['v'] != 2 || j['salt'] is! String) return null;
    final Uint8List salt;
    try {
      salt = unb64url(j['salt'] as String);
    } on FormatException {
      return null;
    }
    if (salt.length != 16) return null;
    final tallies = <int, HandleInboxTally>{};
    final t = j['tally'];
    if (t is Map) {
      for (final e in t.entries) {
        final day = int.tryParse('${e.key}');
        final tally = HandleInboxTally.fromJson(e.value);
        if (day != null && day >= 0 && tally != null) tallies[day] = tally;
      }
    }
    return (salt: salt, tallies: tallies);
  }
}

/// One vault row of [HandleStampLedger]: the digests of [day]'s row [seq],
/// [HandleStampLedger.digestBytes] each, big-endian, in the order they were
/// added.
class HandleStampChunk {
  const HandleStampChunk(
      {required this.day, required this.seq, required this.bytes});
  final int day;
  final int seq;
  final Uint8List bytes;

  /// The vault key of this row.
  String get key => '$handleStampRowPrefix${day}_$seq';

  List<int> get digests => [
        for (var i = 0;
            i + HandleStampLedger.digestBytes <= bytes.length;
            i += HandleStampLedger.digestBytes)
          _StampDay.digestAt(bytes, i)
      ];
}

/// The vault keys of the ledger's rows: `handle_stamps_<day>_<n>`.
const String handleStampRowPrefix = 'handle_stamps_';

/// What the drains did with one day's envelopes, for the handle screen
/// (§21.8): dropped for their stamp (none, too little work, another day),
/// refused as copies of requests already decided, and filed without being
/// remembered because the day's digests were full.
class HandleInboxTally {
  HandleInboxTally(
      {this.unstamped = 0, this.copies = 0, this.unremembered = 0});
  int unstamped;
  int copies;
  int unremembered;

  bool get isEmpty => unstamped == 0 && copies == 0 && unremembered == 0;

  List<int> toJson() => [unstamped, copies, unremembered];

  static HandleInboxTally? fromJson(Object? j) {
    if (j is! List || j.length != 3 || !j.every((x) => x is int && x >= 0)) {
      return null;
    }
    return HandleInboxTally(
        unstamped: j[0] as int, copies: j[1] as int, unremembered: j[2] as int);
  }
}

/// One day of [HandleStampLedger]: its digests sorted ([_sorted]) but for
/// the row being filled ([_tail]), which is searched as it is.
class _StampDay {
  _StampDay();

  /// The rows read back from the vault: every one but the last is done
  /// with; the last is the row being filled when it is short of [chunk].
  factory _StampDay.fromChunks(List<HandleStampChunk> rows, int chunk) {
    rows.sort((a, b) => a.seq.compareTo(b.seq));
    final d = _StampDay();
    final all = <int>[];
    for (final r in rows) {
      all.addAll(r.digests);
    }
    final last = rows.last;
    final tailLen = last.digests.length;
    if (tailLen < chunk) {
      d._tail = all.sublist(all.length - tailLen);
      d._seq = last.seq;
      all.length = all.length - tailLen;
    } else {
      d._seq = last.seq + 1;
    }
    all.sort();
    d._sorted = Int64List.fromList(all);
    return d;
  }

  Int64List _sorted = Int64List(0);
  List<int> _tail = [];

  /// The row [_tail] is, or will be, written as.
  int _seq = 0;

  int get count => _sorted.length + _tail.length;
  int get bytes => 8 * _sorted.length + 8 * _tail.length;

  /// Rows this day has in the vault.
  int get rows => _tail.isEmpty ? _seq : _seq + 1;

  static int digestAt(Uint8List b, int i) {
    var v = 0;
    for (var j = 0; j < HandleStampLedger.digestBytes; j++) {
      v = (v << 8) | b[i + j];
    }
    return v;
  }

  bool has(int digest) {
    if (_tail.contains(digest)) return true;
    var lo = 0;
    var hi = _sorted.length;
    while (lo < hi) {
      final mid = (lo + hi) >> 1;
      final v = _sorted[mid];
      if (v == digest) return true;
      if (v < digest) {
        lo = mid + 1;
      } else {
        hi = mid;
      }
    }
    return false;
  }

  /// Add [digest], not held yet, and say which row to write. A row that is
  /// now full is merged into the sorted digests, and the next add starts the
  /// row after it.
  HandleStampChunk add(int day, int digest, int chunk) {
    _tail.add(digest);
    final bytes = Uint8List(HandleStampLedger.digestBytes * _tail.length);
    for (var i = 0; i < _tail.length; i++) {
      var v = _tail[i];
      for (var j = HandleStampLedger.digestBytes - 1; j >= 0; j--) {
        bytes[i * HandleStampLedger.digestBytes + j] = v & 0xff;
        v >>= 8;
      }
    }
    final row = HandleStampChunk(day: day, seq: _seq, bytes: bytes);
    if (_tail.length >= chunk) {
      _tail.sort();
      final merged = Int64List(_sorted.length + _tail.length);
      var i = 0;
      var j = 0;
      var k = 0;
      while (i < _sorted.length && j < _tail.length) {
        merged[k++] = _sorted[i] <= _tail[j] ? _sorted[i++] : _tail[j++];
      }
      while (i < _sorted.length) {
        merged[k++] = _sorted[i++];
      }
      while (j < _tail.length) {
        merged[k++] = _tail[j++];
      }
      _sorted = merged;
      _tail = [];
      _seq++;
    }
    return row;
  }
}

/// Where the relay stands on guarding this handle's introduction mailbox, as
/// its answer to the last `intro` frame said (§21.6). Whatever it says, the
/// owner's drain counts every stamp itself ([handleStampOf]).
enum HandleRelayGuard {
  /// Not asked yet by this process.
  unknown,

  /// `intro_ok`: the relay checks the work on every send to the mailbox.
  guarded,

  /// `unknown_frame`: a relay that predates introduction mailbox flags. It
  /// checks no work, and hands no stamp on.
  tooOld,

  /// `intro_full`: the relay holds as many flags as it will, and refused a
  /// new one; it takes sends to the mailbox without checking their work.
  full,

  /// `rate_limited`: the frame came too soon after others. A flag the relay
  /// already held stays; one it did not hold is not set.
  paced,
}

/// What the log's latest record says about this device's own handle
/// ([HandleService._applyRecord]).
enum _RecordVerdict {
  /// Older than what this device holds: kept as it is.
  stale,

  /// This device's, live.
  current,

  /// This device's, paused.
  paused,

  /// Another owner key, or an introduction key this device does not hold.
  lost,
}

/// Uniform in [lo, hi].
Duration handleUniform(Random r, Duration lo, Duration hi) {
  final span = hi.inMilliseconds - lo.inMilliseconds;
  if (span <= 0) return lo;
  return Duration(milliseconds: lo.inMilliseconds + r.nextInt(span + 1));
}

/// [every], moved by up to [spread] of itself either way, uniformly.
Duration handleJittered(Random r, Duration every,
    {double spread = handleDrainSpread}) {
  final ms = every.inMilliseconds;
  final d = (ms * spread).round();
  if (d <= 0) return every;
  return Duration(milliseconds: ms - d + r.nextInt(2 * d + 1));
}

/// When a pending claim is published, judged at a start: [publishAt] if it is
/// still ahead, otherwise a moment drawn again from the start window.
int handlePublishAtAfterStart(int? publishAt, int nowMs, Random r,
    {Duration min = handleStartDelayMin, Duration max = handleStartDelayMax}) {
  if (publishAt != null && publishAt > nowMs) return publishAt;
  return nowMs + handleUniform(r, min, max).inMilliseconds;
}

/// The requests to drop to bring [held] to [cap]: the oldest UNSEEN ones, by
/// arrival. A request that has been seen is never dropped for a newer one —
/// when every older request has been seen, the one dropped is the newest.
List<String> handleRequestsToEvict(Map<String, HandleRequestMeta> held,
    {int cap = handleInboundCap}) {
  final over = held.length - cap;
  if (over <= 0) return const [];
  final unseen = [
    for (final e in held.entries)
      if (!e.value.seen) e
  ]..sort((a, b) => a.value.seq.compareTo(b.value.seq));
  return [for (final e in unseen.take(over)) e.key];
}

// =============================================================================
// State
// =============================================================================

/// Where this account's handle stands.
enum HandlePhase {
  /// Claimed here and waiting for its moment to be published.
  pending,

  /// A claim that was pending when the backup this device was restored from
  /// was made: a restore publishes nothing by itself, so it waits for the
  /// person to publish it or let it go.
  held,

  /// In the log under this device's owner key, and taking requests.
  live,

  /// In the log with no introduction key: it resolves, and cannot be
  /// reached.
  paused,

  /// Somebody else's claim reached the log first; this one was never
  /// published.
  taken,

  /// The log names another owner: the recovery code was used. This device
  /// can no longer change the handle.
  lost,
}

/// This account's handle, as this device holds it.
class OwnHandle {
  final Handle handle;
  final Uint8List label;
  final Uint8List ownerSeed;

  /// The introduction seed in use (kept while paused, so resuming restores
  /// the same mailbox).
  Uint8List introSeed;
  int pow;

  /// The recovery commitment the log holds: only the code it commits to can
  /// install another owner.
  Uint8List rc;

  /// The version of the last entry this device published or read back for
  /// it; 0 before the claim is published.
  int version;
  HandlePhase phase;

  /// [HandlePhase.pending]: when the claim is to be published (ms).
  int? publishAt;

  /// The last refusal or failure worth showing, as a code ([HandleFailure]'s
  /// name), or null. On a [HandlePhase.lost] handle, `introUnknown` says the
  /// log names this device's owner key with an introduction key it does not
  /// hold — the inbox was moved elsewhere — rather than another owner.
  String? problem;

  /// The difficulty before the last change, and until when (ms) a stamp
  /// made for it still counts at this device's check ([handlePowGrace]);
  /// null when there is none.
  int? prevPow;
  int? prevPowUntil;

  /// Derived from [introSeed], not stored: the mailbox, and the keys the
  /// record carries.
  late String introRid;

  OwnHandle({
    required this.handle,
    required this.label,
    required this.ownerSeed,
    required this.introSeed,
    required this.pow,
    required this.rc,
    required this.version,
    required this.phase,
    this.publishAt,
    this.problem,
    this.prevPow,
    this.prevPowUntil,
  });

  Map<String, Object?> toJson() => {
        'h': handle.canonical,
        'label': b64(label),
        'owner': b64(ownerSeed),
        'intro': b64(introSeed),
        'pow': pow,
        'rc': b64(rc),
        'v': version,
        'phase': phase.name,
        if (publishAt != null) 'at': publishAt,
        if (problem != null) 'problem': problem,
        if (prevPow != null && prevPowUntil != null) ...{
          'prevPow': prevPow,
          'prevUntil': prevPowUntil,
        },
      };

  /// Throws on anything that is not the shape [toJson] writes.
  static OwnHandle fromJson(Map<String, Object?> j) {
    Uint8List key(String k) {
      final v = unb64(j[k] as String);
      if (v.length != 32) throw FormatException('$k is not 32 bytes');
      return v;
    }

    final pow = j['pow'];
    final v = j['v'];
    if (pow is! int || pow < handlePowMinBits || pow > handlePowMaxBits) {
      throw const FormatException('pow out of range');
    }
    if (v is! int || v < 0) throw const FormatException('bad version');
    final at = j['at'];
    final problem = j['problem'];
    final prev = j['prevPow'];
    final prevUntil = j['prevUntil'];
    final hasPrev = prev is int &&
        prev >= handlePowMinBits &&
        prev <= handlePowMaxBits &&
        prevUntil is int;
    return OwnHandle(
      handle: Handle.parse(j['h'] as String),
      label: key('label'),
      ownerSeed: key('owner'),
      introSeed: key('intro'),
      pow: pow,
      rc: key('rc'),
      version: v,
      phase: HandlePhase.values.byName(j['phase'] as String),
      publishAt: at is int ? at : null,
      problem: problem is String ? problem : null,
      prevPow: hasPrev ? prev : null,
      prevPowUntil: hasPrev ? prevUntil : null,
    );
  }
}

/// What this device keeps about one pending request that came through the
/// handle: everything accepting it needs to sign the acknowledgement, and
/// whether the person has seen it.
class HandleRequestMeta {
  /// The handle it came through, canonical.
  final String handle;

  /// The introduction mailbox it reached — which introduction key signs the
  /// acknowledgement, after a rotation too.
  final String introRid;

  /// `contactRequestId` of the request (§21.7).
  final Uint8List creqId;

  final int at;

  /// Arrival order, for the cap.
  final int seq;
  bool seen;

  HandleRequestMeta({
    required this.handle,
    required this.introRid,
    required this.creqId,
    required this.at,
    required this.seq,
    this.seen = false,
  });

  Map<String, Object?> toJson() => {
        'h': handle,
        'intro': introRid,
        'id': b64(creqId),
        'at': at,
        'seq': seq,
        if (seen) 'seen': 1,
      };

  static HandleRequestMeta fromJson(Map<String, Object?> j) {
    final id = unb64(j['id'] as String);
    if (id.length != 32) throw const FormatException('creqId');
    Handle.parse(j['h'] as String);
    return HandleRequestMeta(
      handle: j['h'] as String,
      introRid: j['intro'] as String,
      creqId: id,
      at: (j['at'] as num).toInt(),
      seq: (j['seq'] as num).toInt(),
      seen: j['seen'] == 1,
    );
  }
}

/// A request this device sent to a handle and is waiting on: what an
/// acceptance's `ia` is checked against.
class OutgoingHandleRequest {
  final String handle;

  /// The record's owner key and introduction keys as they were resolved.
  final Uint8List ownerPub;
  final Uint8List introPub;
  final Uint8List xintroPub;

  /// The ids of the requests sent to it, oldest first (at most
  /// [handleOutgoingIdsPerHandle]): the owner keeps the latest one per
  /// requester, but may have accepted an earlier one before it arrived.
  final List<Uint8List> creqIds;
  final int sentMs;

  OutgoingHandleRequest({
    required this.handle,
    required this.ownerPub,
    required this.introPub,
    required this.xintroPub,
    required this.creqIds,
    required this.sentMs,
  });

  Map<String, Object?> toJson() => {
        'h': handle,
        'owner': b64(ownerPub),
        'intro': b64(introPub),
        'xintro': b64(xintroPub),
        'ids': [for (final i in creqIds) b64(i)],
        'at': sentMs,
      };

  static OutgoingHandleRequest fromJson(Map<String, Object?> j) {
    Uint8List k(String n) {
      final v = unb64(j[n] as String);
      if (v.length != 32) throw FormatException('$n is not 32 bytes');
      return v;
    }

    Handle.parse(j['h'] as String);
    final ids = [
      for (final i in (j['ids'] as List)) unb64(i as String),
    ];
    if (ids.isEmpty || ids.any((i) => i.length != 32)) {
      throw const FormatException('ids');
    }
    return OutgoingHandleRequest(
      handle: j['h'] as String,
      ownerPub: k('owner'),
      introPub: k('intro'),
      xintroPub: k('xintro'),
      creqIds: ids,
      sentMs: (j['at'] as num).toInt(),
    );
  }
}

/// What looking a handle up found.
enum HandleLookupState {
  /// Nobody has claimed it: the bucket is complete, so this is proved.
  notFound,

  /// Claimed, with no introduction key: it cannot be reached.
  paused,

  /// Claimed and taking requests.
  found,

  /// This account's own handle.
  own,

  /// The log answered with a record that is not one: not in its one
  /// encoding, or not signed by the owner it names. Nothing is sent.
  invalid,

  /// Not what this device found the last time it looked the handle up, in a
  /// way the owner rule does not explain from here ([HandleLookup.change]
  /// says how). Nothing is sent; [HandleService.lookUpAsNew] is the person's
  /// choice to take it as new.
  changed,
}

class HandleLookup {
  final Handle handle;
  final HandleLookupState state;
  final Uint8List label;
  final int? version;
  final HandleRecord? record;
  final String? introRid;

  /// For [HandleLookupState.changed], how the handle changed.
  final HandleChange? change;

  /// The head this lookup ended with, when the witness's record did not cover
  /// it (§21.8): kept by [HandleService.request] if a request is sent on this
  /// lookup, held to every head a later lookup ends with, and checked when a
  /// later record covers it. Null with no witness, or a record at or past the
  /// head.
  final _Unwitnessed? _unwitnessed;

  const HandleLookup._(
      this.handle, this.state, this.label, this.version, this.record,
      this.introRid,
      {this.change, _Unwitnessed? unwitnessed})
      : _unwitnessed = unwitnessed;

  /// A lookup in [state] without a log behind it, for a test of a screen.
  @visibleForTesting
  const HandleLookup.debug(this.handle, this.state,
      {required this.label, this.version, this.record, this.introRid, this.change})
      : _unwitnessed = null;
}

/// A head a lookup ended with that the witness's record did not cover: the
/// head, the configuration it was checked under, and when the lookup was
/// made.
class _Unwitnessed {
  final KtTreeHead head;
  final String w;
  final int at;
  const _Unwitnessed(this.head, this.w, this.at);
}

/// A head kept after the fact ([handleWitnessKeptCap]): an [_Unwitnessed]
/// head, what relied on its lookup — the handle, the requests sent on it and,
/// once its acceptance adds one, the contact — and where its check stands.
class _KeptHead {
  final KtTreeHead head;
  final int at;
  final String handle;
  final List<Uint8List> creqIds;
  String? rid;

  /// When it was kept: the request first sent on its lookup.
  final int keptAt;

  /// When its check-back is due: drawn as it is kept, from
  /// [handleWitnessCheckBack] to [handleWitnessCheckBackMax] after [keptAt].
  final int backAt;

  /// When its two checks of its own were made ([HandleService._checkBack]),
  /// with their answers, or given up on ([handleWitnessCheckFor]): the
  /// check-back, at [backAt], and the last, once it is [handleWitnessKeepFor]
  /// old. Each is made once; null until it is.
  int? back;
  int? last;

  /// When a check of its own last asked for it, made or not, so that one not
  /// made is asked again at most once in [handleWitnessCheckAgain] — written
  /// before anything is asked; and when each of its two checks first went
  /// without its answers, for [handleWitnessCheckFor]. Null while none has.
  int? tried;
  int? backFail;
  int? lastFail;

  /// Whether what relied on it has been told, while it is kept, that its
  /// answer was never confirmed ([HandleForkWarning.atFork]): told once, so
  /// that a warning the person dismissed is not said again by the next check
  /// that finds the same, nor by the lapse.
  bool told;

  /// The latest head the log signed that a lookup has shown extends [head]:
  /// a later head is held to it in [head]'s place, so that one proof serves
  /// every kept head it stands in for ([HandleService._holdKept]). Null until
  /// a later head is shown.
  KtTreeHead? ext;

  /// When a check of it was last left pending — the log withholding a proof,
  /// serving something in its place that is not one, or one that does not
  /// decide it — so that the log is asked again at most once in
  /// [HandleService.witnessReuse]. Null while nothing of it is pending.
  int? held;

  _KeptHead(
      {required this.head,
      required this.at,
      required this.handle,
      required this.creqIds,
      required this.keptAt,
      int? backAt,
      this.rid,
      this.ext,
      this.held,
      this.back,
      this.last,
      this.tried,
      this.backFail,
      this.lastFail,
      this.told = false})
      : backAt = backAt ?? keptAt + handleWitnessCheckBack.inMilliseconds;

  Map<String, Object?> toJson() => {
        'sth': head.toJson(),
        'at': at,
        'h': handle,
        'ids': [for (final i in creqIds) b64(i)],
        'kept': keptAt,
        'backAt': backAt,
        if (rid != null) 'rid': rid,
        if (ext != null) 'ext': ext!.toJson(),
        if (held != null) 'held': held,
        if (back != null) 'back': back,
        if (last != null) 'last': last,
        if (tried != null) 'tried': tried,
        if (backFail != null) 'backFail': backFail,
        if (lastFail != null) 'lastFail': lastFail,
        if (told) 'told': true,
      };

  /// Throws on anything that is not the shape [toJson] writes.
  static _KeptHead fromJson(Map<String, Object?> j) {
    final head = KtTreeHead.fromJson((j['sth'] as Map).cast<String, Object?>());
    final e = j['ext'];
    final ext =
        e == null ? null : KtTreeHead.fromJson((e as Map).cast<String, Object?>());
    if (ext != null && ext.size < head.size) throw const FormatException('ext');
    int? when(String key) {
      final v = j[key];
      if (v != null && v is! int) throw FormatException(key);
      return v as int?;
    }

    final at = j['at'] as int;
    final told = j['told'];
    if (told != null && told != true) throw const FormatException('told');
    return _KeptHead(
      head: head,
      at: at,
      handle: Handle.parse(j['h'] as String).canonical,
      creqIds: _creqIds(j['ids']),
      keptAt: when('kept') ?? at,
      backAt: when('backAt'),
      rid: _rid(j['rid']),
      ext: ext,
      held: when('held'),
      back: when('back'),
      last: when('last'),
      tried: when('tried'),
      backFail: when('backFail'),
      lastFail: when('lastFail'),
      told: told == true,
    );
  }
}

/// The request ids of a kept head or a warning: one to three of 32 bytes.
List<Uint8List> _creqIds(Object? ids) {
  final out = [for (final i in ids as List) unb64(i as String)];
  if (out.isEmpty ||
      out.length > handleOutgoingIdsPerHandle ||
      out.any((i) => i.length != 32)) {
    throw const FormatException('ids');
  }
  return out;
}

String? _rid(Object? rid) {
  if (rid == null) return null;
  if (rid is! String || rid.isEmpty) throw const FormatException('rid');
  return rid;
}

/// The handle log's witness, as Settings says it (§19.5, §21.8): [forked]
/// while a fork found after the fact stands ([HandleForkWarning]), whatever is
/// configured now, and once a lookup has been refused because the witness's
/// record contradicted the log, until the witness next agrees with it;
/// [unconfirmed] while a warning stands that the answer a request was sent on
/// was never confirmed ([HandleWarningKind.unconfirmed]), whatever is
/// configured now; otherwise [none] with no handle log or no witness
/// configured; [quiet] when lookups have asked it for more than
/// [handleWitnessQuietAfter] — from the first whose check ended without its
/// agreement to the latest — and none agreed; otherwise [agreed] once it has
/// agreed with the log over a current record, and [pending] before. A
/// witness gone quiet is one the handle log is not being checked against.
enum HandleWitnessState { none, pending, agreed, quiet, unconfirmed, forked }

/// What a warning found after the fact says (§21.8).
enum HandleWarningKind {
  /// A fork: the head the lookup was shown, contradicted by a head signed
  /// after it — the witness's co-signed head, or one the log showed this
  /// device since.
  forked,

  /// Never confirmed: the head the lookup was shown went before the
  /// witness's record covered it — it lapsed ([handleWitnessKeepFor]), the
  /// bound pushed it out ([handleWitnessKeptCap]), or another log or witness
  /// was set, whose records cannot cover it — or, still kept, the log showed
  /// this device two histories with a head that extends it
  /// ([HandleForkWarning.atFork]). Nothing showed it was a fork, and nothing
  /// showed it was not.
  unconfirmed,
}

/// Said after the fact (§21.8; Finnian's decision of 2026‑10‑20) about the
/// head a lookup ended with, kept because the witness's record did not yet
/// cover it: a fork ([HandleWarningKind.forked]) — a head signed after it
/// that does not extend it: one the log showed this device since, smaller,
/// the same size under other roots, or larger with the proof from the kept
/// size failing; or the witness's record, at the kept size under other
/// roots, behind it contradicting a head that extends it, or past it with
/// the proof from the kept size failing while the record and the head the
/// log shows agree — or an answer never confirmed
/// ([HandleWarningKind.unconfirmed]). It marks what relied on that lookup
/// and nothing else: the request sent on it, while it waits for an answer
/// ([HandleService.forkWarningForRequest]), and the contact its acceptance
/// added ([HandleService.forkWarningForContact]). Sealed, under
/// `handle_witness_warnings`, and not tied to the configuration: it stands,
/// whatever the witness says next, until the person dismisses it
/// ([HandleService.dismissForkWarning]) or the request or the contact is
/// deleted.
class HandleForkWarning {
  /// A fork, or an answer never confirmed.
  final HandleWarningKind kind;

  /// The handle that was looked up, canonical.
  final String handle;

  /// When it was looked up, and when the fork was found.
  final int lookedUpMs;
  final int foundMs;

  /// The requests sent on that lookup ...
  final List<Uint8List> creqIds;

  /// ... and the contact the acceptance of one of them added, once one is.
  String? rid;

  /// What it was found against: the head the lookup was shown, signed by the
  /// log, and — for a fork — the head it was held to then, the witness's
  /// co-signed head or a later one the log signed itself. At the same size
  /// under other roots, or a smaller one, the two signed heads show the fork
  /// themselves; across sizes it is the log's proof between them failing that
  /// does, and a proof is not signed (§21.8). Null for an answer never
  /// confirmed.
  final KtTreeHead shown;
  final KtTreeHead? against;

  /// An answer never confirmed said while its head is still kept, because the
  /// log showed this device two histories with a head that extends it — so
  /// what relied on it may have relied on the history the witness did not
  /// see (§21.8). A later check still decides the head: a fork replaces this
  /// warning, and a record that covers the head takes it away.
  final bool atFork;

  HandleForkWarning(
      {this.kind = HandleWarningKind.forked,
      required this.handle,
      required this.lookedUpMs,
      required this.foundMs,
      required this.creqIds,
      this.rid,
      required this.shown,
      this.against,
      this.atFork = false})
      : assert((kind == HandleWarningKind.forked) == (against != null)),
        assert(!atFork || kind == HandleWarningKind.unconfirmed);

  /// A fork, rather than an answer never confirmed.
  bool get isFork => kind == HandleWarningKind.forked;

  Map<String, Object?> toJson() => {
        'k': kind.name,
        'h': handle,
        'at': lookedUpMs,
        'found': foundMs,
        'ids': [for (final i in creqIds) b64(i)],
        if (rid != null) 'rid': rid,
        'sth': shown.toJson(),
        if (against != null) 'against': against!.toJson(),
        if (atFork) 'atFork': true,
      };

  /// Throws on anything that is not the shape [toJson] writes.
  static HandleForkWarning fromJson(Map<String, Object?> j) {
    final kind = switch (j['k']) {
      'forked' => HandleWarningKind.forked,
      'unconfirmed' => HandleWarningKind.unconfirmed,
      _ => throw const FormatException('k'),
    };
    final a = j['against'];
    final against =
        a == null ? null : KtTreeHead.fromJson((a as Map).cast<String, Object?>());
    if ((kind == HandleWarningKind.forked) != (against != null)) {
      throw const FormatException('against');
    }
    final atFork = j['atFork'];
    if (atFork != null &&
        (atFork != true || kind != HandleWarningKind.unconfirmed)) {
      throw const FormatException('atFork');
    }
    return HandleForkWarning(
      kind: kind,
      handle: Handle.parse(j['h'] as String).canonical,
      lookedUpMs: j['at'] as int,
      foundMs: j['found'] as int,
      creqIds: _creqIds(j['ids']),
      rid: _rid(j['rid']),
      shown: KtTreeHead.fromJson((j['sth'] as Map).cast<String, Object?>()),
      against: against,
      atFork: atFork == true,
    );
  }
}

/// What a witness's record says of the head a lookup ends with (§19.5
/// step 3), and so what becomes of the lookup.
enum _WitnessVerdict {
  /// Equal roots at equal size, or a consistency proof that verifies, in
  /// either direction: the lookup goes on.
  consistent,

  /// Two histories under one key: the same size under other roots, a proof
  /// that fails, or — with the witness ahead and no proof — a log whose head
  /// is now smaller than one it signed and the witness verified. The lookup
  /// fails as [HandleFailure.forked].
  forked,

  /// The sizes differ and the log served no proof of the way between them:
  /// step 3 requires one, and a lookup that fails keeps nothing on which a
  /// later lookup would ask again, so the lookup fails as
  /// [HandleFailure.unreachable] — as a missing proof inside one lookup does
  /// ([HandleService._accept]). A head kept after the fact whose proof is
  /// withheld stays kept, its check pending ([HandleService._holdKept]).
  unproven,

  /// The log served something in place of the proof that is not one: the
  /// lookup fails as [HandleFailure.badAnswer], as [HandleService._accept]
  /// takes it.
  unreadable,
}

/// A later head held to a kept one ([HandleService._holdKept]): shown to
/// extend it, shown not to, or neither — the proof withheld, not one, not
/// asked yet.
enum _Hold { extended, contradicted, unproven }

/// Where a kept head's check ends for one lookup: covered by the witness's
/// record, a fork, still kept with nothing pending, or pending.
enum _Kept { covered, forked, stays, pending }

/// The consistency proofs one lookup, or one check of a head's own, asked
/// the log for to hold the kept heads, by sizes — null where it served none,
/// or nothing that is one — those it got no answer to at all, and how many
/// more it may ask.
class _KeptProofs {
  _KeptProofs(this.left);
  int left;
  final answers = <String, List<Uint8List>?>{};
  final unanswered = <String>{};
}

/// Why a handle operation did not happen — one value per thing the app tells
/// the person. Never a sentence: core does not decide the language.
enum HandleFailure {
  /// No handle log is configured in this build or in the developer settings.
  unavailable,

  /// This is a linked device; only the account's primary device holds a
  /// handle (v1).
  linkedDevice,

  /// The handle log could not be reached, or answered with an error.
  unreachable,

  /// The handle log's answer did not verify under the pinned key, or was not
  /// a complete bucket: nothing it said is used.
  badAnswer,

  /// The handle log's answer was signed more than a day ago by this device's
  /// clock ([handleStaleHead]): a log that stopped, an old answer served
  /// again, or a clock that is wrong. Nothing it said is used.
  stale,

  /// The handle log showed this lookup a different history from the one its
  /// witness saw (§19.5 step 3, §21.8): a head the witness's record, verified
  /// under the pinned key, contradicts. Nothing the lookup returned is used,
  /// kept or sent.
  forked,

  /// The log refused an entry this device made, for a reason waiting will
  /// not change.
  refused,

  /// Someone else's claim is in the log.
  taken,

  /// The log changed between reading the handle and publishing to it; try
  /// again.
  changed,

  /// The log names another owner now (the recovery code was used).
  lost,

  /// The relay's anonymous link is down; nothing was sent.
  notConnected,

  /// The relay refused the request's proof of work twice (§21.7).
  powRefused,

  /// The relay refused the request.
  relayRefused,

  /// The handle is paused: nothing is sent to it.
  paused,

  /// Nobody holds the handle.
  notClaimed,

  /// The recovery code does not recover this handle.
  wrongCode,

  /// What was typed is not a recovery code (a character, the length or the
  /// checksum is wrong).
  badCode,

  /// What was typed is a backup recovery code (`ZBK-…`), not a handle's.
  backupCode,

  /// This account already has a handle.
  alreadyHasOne,

  /// There is no handle here to do that to.
  noHandle,
}

class HandleException implements Exception {
  final HandleFailure failure;
  const HandleException(this.failure);
  @override
  String toString() => 'HandleException(${failure.name})';
}

/// A claim between "show the code" and "it is confirmed": everything the
/// claim needs, the recovery code included — in memory only, and dropped
/// with this object.
class HandleClaimDraft {
  final Handle handle;
  final Uint8List label;
  final Uint8List ownerSeed;
  final Uint8List introSeed;
  final Uint8List rc;
  final int pow;

  /// The code, as it is shown once (`ZHR-…`), and parsed for the
  /// confirmation step. Never written anywhere.
  final String code;
  final RecoveryCode recoveryCode;

  HandleClaimDraft._(this.handle, this.label, this.ownerSeed, this.introSeed,
      this.rc, this.pow, this.code, this.recoveryCode);
}

/// A recovery between "the code is right" and "publish it": the recovery
/// key the old code derives (in memory only), and the new owner, mailbox and
/// code the recovered handle will have.
class HandleRecoverDraft {
  final Handle handle;
  final Uint8List label;
  final int version;
  final int pow;
  final HandleRecoveryKey oldKey;
  final Uint8List ownerSeed;
  final Uint8List introSeed;
  final Uint8List rc;
  final String code;
  final RecoveryCode recoveryCode;

  HandleRecoverDraft._(this.handle, this.label, this.version, this.pow,
      this.oldKey, this.ownerSeed, this.introSeed, this.rc, this.code,
      this.recoveryCode);
}

/// What the handle service needs from the chat service.
abstract class HandleHost {
  ZIdentity get identity;
  String get myRid;
  String get displayName;

  /// The relay this account talks to: the introduction mailbox is drained
  /// there too, on a connection of its own.
  String get relayUrl;

  /// Whether this device holds the account root — the only one that holds a
  /// handle in v1.
  bool get holdsRoot;

  /// A sealed envelope with a proof-of-work stamp, on the anonymous link.
  Future<void> sendStamped(
      {required String to,
      required String id,
      required String payload,
      required String pow});

  /// File a verified request that reached the introduction mailbox for
  /// [handle] as a pending request, under the rules every request is held to
  /// (its signed time and the last one taken in from the same requester) and
  /// the cap on pending handle requests, which counts them apart from those
  /// that came by a code or a link. False when it was dropped (blocked, a
  /// contact already, this account itself, refused by those rules, or pushed
  /// straight out by the cap).
  Future<bool> addHandleRequest(ContactRequest request,
      {required String requesterRid, required String handle});

  /// patch 57's classifier: whether a failure while filing an inbound
  /// envelope may succeed on redelivery (so it is left with the relay).
  bool isTransientFailure(Object e);

  void handlesChanged();
}

// =============================================================================
// The service
// =============================================================================

class HandleService extends ChangeNotifier {
  final Vault vault;
  final HandleHost host;
  final KtFetcher fetcher;
  int Function() now;
  Random random;

  HandleConfig config;

  // ---- the timings, settable for tests (§21.8 has the defaults' reasons) ----
  Duration claimDelayMin = handleClaimDelayMin;
  Duration claimDelayMax = handleClaimDelayMax;
  Duration startDelayMin = handleStartDelayMin;
  Duration startDelayMax = handleStartDelayMax;
  Duration drainEvery = handleDrainEvery;
  Duration foregroundDelayMin = handleForegroundDelayMin;
  Duration foregroundDelayMax = handleForegroundDelayMax;
  Duration drainQuiet = handleDrainQuiet;
  Duration drainMax = handleDrainMax;

  /// How soon a claim whose publish failed for a reason that passes (the log
  /// unreachable, busy, rate-limited) is tried again.
  Duration publishRetry = const Duration(minutes: 5);

  /// The witness's timings ([handleWitnessReuse], [handleWitnessStale],
  /// [handleWitnessQuietAfter]).
  Duration witnessReuse = handleWitnessReuse;
  Duration witnessStale = handleWitnessStale;
  Duration witnessQuietAfter = handleWitnessQuietAfter;

  /// When the witness last agreed with the handle log over a current record:
  /// its record verified under the pinned key, its head no older than
  /// [witnessStale], and a lookup's head shown consistent with it. Sealed,
  /// under `handle_witness_ok_ms`, with the configuration it was recorded
  /// under.
  int? witnessOkMs;

  /// When this device began asking the witness without an answer that
  /// counts — the first lookup, since the last agreement or ever, whose check
  /// ended in no agreement — and the latest such lookup. Sealed together,
  /// under `handle_witness_since_ms`, with the configuration they were
  /// recorded under; an agreement forgets both. A lookup the witness's record
  /// contradicts moves neither: that is the witness answering, and the
  /// lookup says it.
  int? witnessSinceMs;
  int? witnessLastAskMs;

  /// When a lookup was last refused because the witness's record contradicted
  /// the log ([HandleFailure.forked]) — a refresh, a change, a drain's read or
  /// a claim's read-back as much as a lookup someone made. Sealed, under
  /// `handle_witness_fork_ms`, with the configuration it was recorded under;
  /// the witness's next agreement forgets it, and so does a change of log or
  /// witness.
  int? witnessForkMs;

  /// The record last fetched that verified, for [witnessReuse]: the
  /// configuration it was fetched under, and when.
  ({String w, int at, KtWitnessRecord record})? _witnessHeld;

  /// The bound on heads kept after the fact ([handleWitnessKeptCap],
  /// [handleWitnessKeepFor]).
  int witnessKeptCap = handleWitnessKeptCap;
  Duration witnessKeepFor = handleWitnessKeepFor;

  /// When a kept head is checked on its own ([handleWitnessCheckBack],
  /// [handleWitnessCheckBackMax]) and how a check not made is tried again
  /// ([handleWitnessCheckAgain], [handleWitnessCheckFor]); the one-shot timer
  /// for the next such moment while the app is in front, and the moment it
  /// is for; the heads a check is deciding now; and how many checks this
  /// process asked for, made or not (a test reads it).
  Duration witnessCheckBack = handleWitnessCheckBack;
  Duration witnessCheckBackMax = handleWitnessCheckBackMax;
  Duration witnessCheckAgain = handleWitnessCheckAgain;
  Duration witnessCheckFor = handleWitnessCheckFor;
  Timer? _checkBackTimer;
  int? _checkBackTarget;
  bool _checkingBack = false;
  final Set<_KeptHead> _checking = {};
  @visibleForTesting
  int checksBack = 0;

  /// The heads kept after the fact, oldest first, all under the configuration
  /// configured now (a change forgets them): sealed, under
  /// `handle_witness_heads`.
  final List<_KeptHead> _kept = [];

  /// The forks found after the fact that stand, oldest first: sealed, under
  /// `handle_witness_warnings`.
  final List<HandleForkWarning> _warnings = [];

  OwnHandle? own;
  final Map<String, HandleRequestMeta> _inbound = {};

  /// Introduction seeds of mailboxes since rotated away from, or of a
  /// retired handle, kept while a pending request that reached them still
  /// has to be acknowledged with them: introRid → seed.
  final Map<String, Uint8List> _oldSeeds = {};
  final List<OutgoingHandleRequest> _outgoing = [];
  int _seq = 0;

  /// What the relay said to the last `intro` frame this process sent.
  HandleRelayGuard relayGuard = HandleRelayGuard.unknown;

  /// The relay said it is not guarding the mailbox right now — too old,
  /// full, or pacing — so it takes sends to it without checking their work;
  /// this device's own check ([handleStampOf]) still drops every one without.
  bool get relayUnguarded =>
      relayGuard == HandleRelayGuard.tooOld ||
      relayGuard == HandleRelayGuard.full ||
      relayGuard == HandleRelayGuard.paced;

  /// The introduction requests decided here, and what the drains dropped
  /// (`handle_stamps`, `handle_stamps_<day>_<n>`).
  HandleStampLedger _ledger = HandleStampLedger();
  bool _ledgerWritten = false;
  bool _tallyDirty = false;

  /// Digests a ledger row holds; a test lowers it to see rows fill.
  @visibleForTesting
  set stampChunk(int n) => _ledger.chunk = n;

  /// The ledger itself, for a test to set what a screen shows.
  @visibleForTesting
  HandleStampLedger get stampLedger => _ledger;
  @visibleForTesting
  set stampLedger(HandleStampLedger l) => _ledger = l;

  /// What the drains did over the kept days (§21.8): envelopes dropped for
  /// their stamp — none, short of the difficulty, for another day — copies
  /// of requests already decided refused, and requests filed without being
  /// remembered because a day's digests were full. Kept in the vault with
  /// the ledger, shown on the handle screen, and never sent anywhere.
  HandleInboxTally get inboxTally => _ledger.tallied;

  /// Whether a kept day holds all the digests it can ([handleStampDayCap]):
  /// a copy of a request filed past that could be filed again.
  bool get inboxSaturated => _ledger.days.any(_ledger.isFull);

  /// How many envelopes the drains of this process dropped for their stamp,
  /// and how many as copies (a test reads them).
  @visibleForTesting
  int droppedUnstamped = 0;
  @visibleForTesting
  int droppedReplays = 0;

  /// When the introduction mailbox was last drained, and how many drains
  /// this process has run (a test reads it).
  int? lastDrainMs;
  int drains = 0;

  /// How many proof-of-work stamps this process made (a test reads it).
  @visibleForTesting
  int stampsMade = 0;

  /// Test seam: applied to every stamp before it is sent — a sender whose
  /// stamps the relay can never accept, to show the client stamps again once
  /// and no more.
  @visibleForTesting
  String Function(String stamp)? debugStampFilter;

  /// Test seam: accept handle requests as a build that predates the
  /// acknowledgement does — no `ia` on the acceptance.
  @visibleForTesting
  bool debugOmitAcknowledgement = false;

  Timer? _publishTimer;
  Timer? _drainTimer;
  bool _started = false;
  bool _foreground = true;
  bool _disposed = false;
  Future<void> _ops = Future<void>.value();
  Future<int>? _draining;

  HandleService({
    required this.vault,
    required this.host,
    required this.fetcher,
    required this.config,
    int Function()? now,
    Random? random,
  })  : now = now ?? (() => DateTime.now().millisecondsSinceEpoch),
        random = random ?? Random.secure();

  /// True inside `flutter test`.
  static final bool _inFlutterTest =
      Platform.environment.containsKey('FLUTTER_TEST');

  /// Under `flutter test` a handle log that is not on loopback is never
  /// contacted, whatever the defaults say — the rule `KeyTransparency` keeps
  /// for the transparency log, for the same reason: a test that builds a
  /// ChatService gets the build-time defaults, and the day they name a real
  /// log every such test would claim and look up names in it.
  ///
  /// The witness's address is judged by the same rule, as the transparency
  /// client's has been since its witness was pinned (2026-10-17): the four
  /// handle values are pinned together, so the day the log's address is a
  /// real one the witness's is too, and a configuration pairing a loopback
  /// log with it would ask a stranger's server for a record at every lookup.
  bool get _offLimitsInTest {
    if (!_inFlutterTest) return false;
    return !(_loopbackOrEmpty(config.logUrl) &&
        _loopbackOrEmpty(config.witnessUrl));
  }

  static bool _loopbackOrEmpty(String url) {
    final host = Uri.tryParse(url.trim())?.host ?? '';
    return host.isEmpty ||
        host == 'localhost' ||
        host == '127.0.0.1' ||
        host == '::1';
  }

  /// Whether a handle log is configured: until one is, nothing here can be
  /// claimed or found, and every screen says so.
  bool get available => config.enabled && !_offLimitsInTest;

  /// What Settings says of the witness ([HandleWitnessState]).
  HandleWitnessState get witnessState {
    // A warning found after the fact is about a request already sent, so it
    // stands whatever is configured now: a fork before the rest, and an
    // answer never confirmed before all but a lookup refused as a fork —
    // whose sentence, that nothing from that answer was used or sent, is
    // still true beside it, unless the answer was said never confirmed
    // because the log showed this device that fork ([witnessForkRelied]).
    final warned = forkWarnings;
    if (warned.any((w) => w.isFork)) return HandleWitnessState.forked;
    final checked = available && config.hasWitness;
    if (checked && witnessForkMs != null) return HandleWitnessState.forked;
    if (warned.isNotEmpty) return HandleWitnessState.unconfirmed;
    if (!checked) return HandleWitnessState.none;
    final since = witnessSinceMs, last = witnessLastAskMs;
    if (since != null &&
        last != null &&
        last - since > witnessQuietAfter.inMilliseconds) {
      return HandleWitnessState.quiet;
    }
    return witnessOkMs != null
        ? HandleWitnessState.agreed
        : HandleWitnessState.pending;
  }

  /// What a quiet witness has been quiet since: its last agreement, or, with
  /// none, the first check that asked it without one.
  int? get witnessQuietSinceMs => witnessOkMs ?? witnessSinceMs;

  /// Whether an answer a request was sent on stands said never confirmed
  /// because the log showed this device two histories with a head that
  /// extends the one that answer came with ([HandleForkWarning.atFork]):
  /// what Settings says of a lookup refused as a fork is then not that
  /// nothing from it was used — a request sent on an earlier answer may have
  /// relied on that history (§21.8).
  bool get witnessForkRelied => forkWarnings.any((w) => w.atFork);

  /// Whether this device may hold and manage the account's handle: only the
  /// primary device, which holds the account root (v1).
  bool get canManage => host.holdsRoot;

  /// The requests this device sent to handles and is waiting on, newest
  /// first.
  List<OutgoingHandleRequest> get outgoing =>
      _outgoing.reversed.toList(growable: false);

  /// What this device holds about the pending request from [rid] that came
  /// through the handle, or null.
  HandleRequestMeta? inboundFor(String rid) => _inbound[rid];

  // ---------------------------------------------------------------------------
  // Loading, starting, the app's lifecycle
  // ---------------------------------------------------------------------------

  Future<void> load() async {
    final c = await vault.kvGet('handle_config');
    if (c != null) {
      try {
        config =
            HandleConfig.fromJson((jsonDecode(c) as Map).cast<String, Object?>());
      } catch (_) {}
    }
    await _loadWitness();
    final o = await vault.kvGet('handle');
    if (o != null) {
      try {
        own = OwnHandle.fromJson((jsonDecode(o) as Map).cast<String, Object?>());
        await _deriveIntro(own!);
      } catch (_) {
        own = null; // a record this build cannot read is not one it can act on
      }
    }
    final i = await vault.kvGet('handle_in');
    if (i != null) {
      try {
        final m = (jsonDecode(i) as Map).cast<String, Object?>();
        for (final e in ((m['reqs'] as Map?) ?? const {}).entries) {
          try {
            final meta = HandleRequestMeta.fromJson(
                (e.value as Map).cast<String, Object?>());
            _inbound[e.key as String] = meta;
            if (meta.seq > _seq) _seq = meta.seq;
          } catch (_) {}
        }
        for (final e in ((m['seeds'] as Map?) ?? const {}).entries) {
          try {
            final s = unb64(e.value as String);
            if (s.length == 32) _oldSeeds[e.key as String] = s;
          } catch (_) {}
        }
      } catch (_) {}
    }
    final out = await vault.kvGet('handle_out');
    if (out != null) {
      try {
        for (final j in (jsonDecode(out) as List)) {
          try {
            _outgoing.add(OutgoingHandleRequest.fromJson(
                (j as Map).cast<String, Object?>()));
          } catch (_) {}
        }
      } catch (_) {}
    }
    await _loadLedger();
    // After the requests they are tied to.
    await _loadKept();
  }

  /// The ledger: its record (`handle_stamps`, the salt and the tallies) and
  /// its rows of digests (`handle_stamps_<day>_<n>`). Rows without a record
  /// are digests under a salt nobody holds, and go; so does a row that is
  /// not one, and the days that have lapsed. An unreadable record makes an
  /// empty ledger: what it held was requests the drain had acknowledged,
  /// and a copy of one, while its stamp is still good, can be decided once
  /// more.
  Future<void> _loadLedger() async {
    final rows = await vault.kvScan(handleStampRowPrefix);
    final record = await vault.kvGet('handle_stamps');
    final head = record == null ? null : _readLedgerRecord(record);
    final stale = <String>[];
    final chunks = <HandleStampChunk>[];
    final name = RegExp(r'^(\d+)_(\d+)$');
    for (final e in rows.entries) {
      final m = name.firstMatch(e.key.substring(handleStampRowPrefix.length));
      Uint8List? bytes;
      if (m != null && head != null) {
        try {
          bytes = unb64(e.value);
        } on FormatException {
          bytes = null;
        }
      }
      if (bytes == null || bytes.isEmpty) {
        stale.add(e.key);
        continue;
      }
      chunks.add(HandleStampChunk(
          day: int.parse(m!.group(1)!),
          seq: int.parse(m.group(2)!),
          bytes: bytes));
    }
    if (head != null) {
      _ledger = HandleStampLedger(
          salt: head.salt, chunks: chunks, tallies: head.tallies);
      _ledgerWritten = true;
    }
    for (final e in _ledger.prune(now()).entries) {
      for (var i = 0; i < e.value; i++) {
        stale.add('$handleStampRowPrefix${e.key}_$i');
      }
    }
    for (final k in stale) {
      await vault.kvDelete(k);
    }
    // The record written back: what lapsed is out of its tallies too.
    if (head != null) await _saveLedgerRecord();
  }

  static ({Uint8List salt, Map<int, HandleInboxTally> tallies})?
      _readLedgerRecord(String record) {
    try {
      return HandleStampLedger.readJson(jsonDecode(record));
    } catch (_) {
      return null;
    }
  }

  /// Forget the handle requests whose pending request is gone — a request
  /// deleted while the app was not running to drop its record too.
  Future<void> keepInboundFor(Set<String> pendingRids) async {
    final gone = [
      for (final r in _inbound.keys)
        if (!pendingRids.contains(r)) r
    ];
    if (gone.isEmpty) return;
    for (final r in gone) {
      _inbound.remove(r);
    }
    _pruneSeeds();
    await _saveInbound();
  }

  /// Called once the service and the transport are running.
  void start() {
    _started = true;
    final o = own;
    if (o != null && o.phase == HandlePhase.pending) {
      final at = handlePublishAtAfterStart(o.publishAt, now(), random,
          min: startDelayMin, max: startDelayMax);
      if (at != o.publishAt) {
        o.publishAt = at;
        unawaited(_saveOwn().then((_) {}, onError: (_) {}));
      }
      _schedulePublish();
    }
    _scheduleDrain(first: true);
    _checkBackSoon(); // §21.8: a kept head due a check of its own
  }

  /// The app came to the foreground: drain soon, then on the timer.
  void onForeground() {
    _foreground = true;
    _scheduleDrain(first: true);
    _checkBackSoon();
  }

  /// The app left the foreground: no drains until it is back.
  void onBackground() {
    _foreground = false;
    _drainTimer?.cancel();
    _drainTimer = null;
    _cancelCheckBack();
  }

  @override
  void dispose() {
    if (_disposed) return; // a wipe stops it before the service is disposed
    _disposed = true;
    _publishTimer?.cancel();
    _drainTimer?.cancel();
    _cancelCheckBack();
    super.dispose();
  }

  @override
  void notifyListeners() {
    if (_disposed) return;
    super.notifyListeners();
    host.handlesChanged();
  }

  /// Save [c]. Half a witness is refused here, not only by the screen that
  /// edits it, as the transparency client refuses it: it is the one
  /// configuration that looks like protection and is not.
  Future<void> setConfig(HandleConfig c) async {
    final problem = c.witnessProblem;
    if (problem != null) throw HandleConfigInvalid(problem);
    final before = _witnessOf(config);
    config = c;
    await vault.kvPut('handle_config', jsonEncode(c.toJson()));
    // One witness's answer is not another's: a new address or key, the
    // witness removed, or another log under the same witness starts again.
    if (_witnessOf(c) != before) await _forgetWitness();
    notifyListeners();
    _scheduleDrain(first: true);
  }

  // ---------------------------------------------------------------------------
  // The witness's state (§19.5, §21.8)
  // ---------------------------------------------------------------------------

  static const String _witnessOkKey = 'handle_witness_ok_ms';
  static const String _witnessSinceKey = 'handle_witness_since_ms';
  static const String _witnessForkKey = 'handle_witness_fork_ms';

  /// What a witness's answer is an answer under: the key of the log whose
  /// heads it is held against, the witness's address and its key — as the
  /// transparency client keys its own. Empty with no witness to ask.
  static String _witnessOf(HandleConfig c) => c.hasWitness
      ? jsonEncode(
          [c.logPubB64.trim(), c.witnessUrl.trim(), c.witnessPubB64.trim()])
      : '';

  /// The witness's times from the vault, only when they were recorded under
  /// the witness configured now: a build can pin another witness under a
  /// vault that never saved a configuration of its own, which [setConfig]
  /// never sees. Anything else is forgotten, and the next lookup asks again.
  Future<void> _loadWitness() async {
    final w = _witnessOf(config);
    final okText = await vault.kvGet(_witnessOkKey);
    final sinceText = await vault.kvGet(_witnessSinceKey);
    final forkText = await vault.kvGet(_witnessForkKey);
    Map<String, Object?>? mine(String? text) {
      if (text == null || w.isEmpty) return null;
      try {
        final m = (jsonDecode(text) as Map).cast<String, Object?>();
        return m['w'] == w && m['at'] is int ? m : null;
      } catch (_) {
        return null;
      }
    }

    final ok = mine(okText), since = mine(sinceText), fork = mine(forkText);
    if ((okText != null && ok == null) ||
        (sinceText != null && (since == null || since['last'] is! int)) ||
        (forkText != null && fork == null)) {
      await _forgetWitnessTimes();
      return;
    }
    witnessOkMs = ok?['at'] as int?;
    witnessSinceMs = since?['at'] as int?;
    witnessLastAskMs = since?['last'] as int?;
    witnessForkMs = fork?['at'] as int?;
  }

  /// Forget when the witness last agreed, since when it has been asked
  /// without an answer, the last fork it showed, the record held for reuse,
  /// and the heads kept for it to cover: another witness's record, or one
  /// over another log, covers none of them here — so, never covered, each is
  /// said on what relied on it as an answer never confirmed, not dropped in
  /// silence, unless it has been said so already ([_KeptHead.told]). The
  /// warnings stay: they are about requests already sent.
  Future<void> _forgetWitness() async {
    await _forgetWitnessTimes();
    var warned = false;
    for (final k in _kept) {
      if (_relied(k.creqIds, k.rid) && !k.told) {
        warned = _warn(k, HandleWarningKind.unconfirmed) || warned;
      }
    }
    _kept.clear();
    if (warned) await _saveWarnings();
    await vault.kvDelete(_keptKey);
  }

  /// [_forgetWitness]'s times and record alone: at load, before the heads
  /// are read — [_loadKept] says what was kept under another witness.
  Future<void> _forgetWitnessTimes() async {
    witnessOkMs = null;
    witnessSinceMs = null;
    witnessLastAskMs = null;
    witnessForkMs = null;
    _witnessHeld = null;
    await vault.kvDelete(_witnessOkKey);
    await vault.kvDelete(_witnessSinceKey);
    await vault.kvDelete(_witnessForkKey);
  }

  /// The witness configured as [asked] has just agreed with the log over a
  /// current record: the asking without an answer is over, and so is the
  /// last fork it showed. Not recorded when the configuration changed while
  /// it was being asked — that answer is the last witness's.
  Future<void> _witnessAgreed(String asked) async {
    if (_witnessOf(config) != asked) return;
    witnessOkMs = now();
    witnessSinceMs = null;
    witnessLastAskMs = null;
    witnessForkMs = null;
    await vault.kvPut(
        _witnessOkKey, jsonEncode({'at': witnessOkMs, 'w': asked}));
    await vault.kvDelete(_witnessSinceKey);
    await vault.kvDelete(_witnessForkKey);
    notifyListeners();
  }

  /// A lookup's head contradicted the record of the witness configured as
  /// [asked]: kept, so Settings says so until the witness next agrees,
  /// whichever path the lookup was on — the drain's read of the owner's own
  /// record goes on without a word, and a claim's read-back is kept as the
  /// claim's problem. The asking without an answer is left as it was: this
  /// is the witness answering.
  Future<void> _witnessForked(String asked) async {
    if (_witnessOf(config) != asked) return;
    witnessForkMs = now();
    await vault.kvPut(
        _witnessForkKey, jsonEncode({'at': witnessForkMs, 'w': asked}));
    notifyListeners();
  }

  /// A lookup asked the witness configured as [asked] and its check ended in
  /// no agreement: no record, one that did not verify, one a day old, or a
  /// log that would not prove the way between the two heads (which fails the
  /// lookup as well).
  Future<void> _witnessUnanswered(String asked) async {
    if (_witnessOf(config) != asked) return;
    final t = now();
    witnessSinceMs ??= t;
    witnessLastAskMs = t;
    await vault.kvPut(_witnessSinceKey,
        jsonEncode({'at': witnessSinceMs, 'last': t, 'w': asked}));
    notifyListeners();
  }

  // ---------------------------------------------------------------------------
  // After the fact (§21.8; Finnian's decision of 2026‑10‑20)
  // ---------------------------------------------------------------------------
  //
  // A lookup's check passes a head that extends the witness's record: a
  // history that departs after the witness's latest co-signed head is shown
  // as agreement. So the head a request is sent on, when the record did not
  // cover it, is kept; every head a lookup ends with after it — the owner's
  // drain reads among them — is held to it, as the transparency client holds
  // the head it keeps; and so is the first record that covers it. Only a
  // head a request relied on is kept: a lookup that sends nothing leaves
  // nothing a warning could point to (what it found is remembered, and a
  // record that differs from it is refused, never sent to), and a head no
  // contact holds goes with its request, so the outgoing list bounds them.
  // The claim checks, a recovery's read and the owner's reads of its own
  // record keep nothing for the same reason; they all check. A kept head
  // nothing decides is checked on its own, twice at most — 20 to 30 minutes
  // after it was kept and once more at 30 days, each check made only once it
  // has its answers ([_checkBack]) — and one that goes before the witness
  // covered it is said on what relied on it, never dropped in silence.

  static const String _keptKey = 'handle_witness_heads';
  static const String _warningsKey = 'handle_witness_warnings';

  /// The warnings found after the fact that stand, forks and answers never
  /// confirmed, the one found last first: each on a request this device
  /// still waits on, or on a contact.
  List<HandleForkWarning> get forkWarnings => [
        for (final w in _warnings.reversed)
          if (_relied(w.creqIds, w.rid)) w
      ]..sort((a, b) => b.foundMs.compareTo(a.foundMs));

  /// The warning on [o], a request this device waits on, when the lookup it
  /// was sent on was found after the fact to be a history the witness never
  /// saw, or its answer was never confirmed — or null.
  HandleForkWarning? forkWarningForRequest(OutgoingHandleRequest o) {
    final ids = {for (final i in o.creqIds) b64(i)};
    return _shownOf([
      for (final w in _warnings)
        if (w.creqIds.any((i) => ids.contains(b64(i)))) w
    ]);
  }

  /// The warning on the contact [rid]: one the acceptance of such a request
  /// added — or null.
  HandleForkWarning? forkWarningForContact(String rid) =>
      _shownOf([for (final w in _warnings) if (w.rid == rid) w]);

  /// Of the warnings on one request or contact, the one shown: a fork before
  /// an answer never confirmed, and of those the one found last.
  static HandleForkWarning? _shownOf(List<HandleForkWarning> on) {
    HandleForkWarning? shown;
    for (final w in on) {
      if (shown == null ||
          (w.isFork && !shown.isFork) ||
          (w.isFork == shown.isFork && w.foundMs >= shown.foundMs)) {
        shown = w;
      }
    }
    return shown;
  }

  /// The person has read [w] — compared safety numbers, say — and clears it,
  /// with any other warning on the same contact or request. Nothing else
  /// does but deleting the request or the contact it is on.
  Future<void> dismissForkWarning(HandleForkWarning w) async {
    final ids = {for (final i in w.creqIds) b64(i)};
    final before = _warnings.length;
    _warnings.removeWhere((x) =>
        identical(x, w) ||
        (w.rid != null && x.rid == w.rid) ||
        (w.rid == null &&
            x.rid == null &&
            x.creqIds.any((i) => ids.contains(b64(i)))));
    if (_warnings.length == before) return;
    await _saveWarnings();
    notifyListeners();
  }

  /// The heads kept after the fact, for a test to read.
  @visibleForTesting
  List<({String handle, int size, int atMs, String? rid})> get keptHeads => [
        for (final k in _kept)
          (handle: k.handle, size: k.head.size, atMs: k.at, rid: k.rid)
      ];

  /// A warning as a fork found after the fact leaves one, for a test of a
  /// screen, where no log is driven to reach it.
  @visibleForTesting
  void debugWarn(HandleForkWarning w) {
    _warnings.add(w);
    notifyListeners();
  }

  /// Whether what a kept head or a warning is for still exists: a request
  /// this device waits on, or a contact — whose deletion takes them with it
  /// ([contactGone], [keepWarningsFor]).
  bool _relied(List<Uint8List> creqIds, String? rid) {
    if (rid != null) return true;
    final waiting = {
      for (final o in _outgoing)
        for (final i in o.creqIds) b64(i)
    };
    return creqIds.any((i) => waiting.contains(b64(i)));
  }

  /// The warnings and the heads kept, from the vault, each held to its shape,
  /// and all to the bound and to what relies on them. The heads only under
  /// the configuration configured now: a build can pin another witness under
  /// a vault that never saved a configuration of its own, which [setConfig]
  /// never sees, and a head kept for another witness is one no record here
  /// covers — said, as [_forgetWitness] says it.
  Future<void> _loadKept() async {
    final warnings = await vault.kvGet(_warningsKey);
    if (warnings != null) {
      try {
        for (final j in jsonDecode(warnings) as List) {
          try {
            _warnings.add(HandleForkWarning.fromJson(
                (j as Map).cast<String, Object?>()));
          } catch (_) {}
        }
      } catch (_) {}
    }
    final w = _witnessOf(config);
    final kept = await vault.kvGet(_keptKey);
    if (kept != null) {
      var mine = false;
      final heads = <_KeptHead>[];
      try {
        final m = (jsonDecode(kept) as Map).cast<String, Object?>();
        mine = w.isNotEmpty && m['w'] == w;
        for (final j in m['heads'] as List) {
          try {
            heads.add(_KeptHead.fromJson((j as Map).cast<String, Object?>()));
          } catch (_) {}
        }
      } catch (_) {}
      if (mine) {
        _kept.addAll(heads);
      } else {
        var warned = false;
        for (final k in heads) {
          if (_relied(k.creqIds, k.rid) && !k.told) {
            warned = _warn(k, HandleWarningKind.unconfirmed) || warned;
          }
        }
        if (warned) await _saveWarnings();
        await vault.kvDelete(_keptKey);
      }
    }
    await _settleWitness();
  }

  Future<void> _saveKept() async {
    if (_kept.isEmpty) {
      await vault.kvDelete(_keptKey);
      return;
    }
    await vault.kvPut(
        _keptKey,
        jsonEncode({
          'w': _witnessOf(config),
          'heads': [for (final k in _kept) k.toJson()],
        }));
  }

  Future<void> _saveWarnings() async {
    if (_warnings.isEmpty) {
      await vault.kvDelete(_warningsKey);
      return;
    }
    await vault.kvPut(
        _warningsKey, jsonEncode([for (final w in _warnings) w.toJson()]));
  }

  /// The bound ([witnessKeptCap], [witnessKeepFor]) and what relies on each
  /// head. One whose requests went with no contact to hold it goes, in
  /// silence, as its request went: an acceptance is matched only to a
  /// request still waited on ([matchAcknowledgement]), so one of them would
  /// arrive as an ordinary request that needs the person's consent — and so
  /// the outgoing list bounds the heads no contact holds, and a burst of
  /// requests raises no warning. The rest never go in silence: one looked up
  /// more than [witnessKeepFor] ago lapses once its last check of its own has
  /// been made and has not decided it, or been given up on ([_checkBack]);
  /// and past [witnessKeptCap] heads that contacts hold, the one looked up
  /// longest ago goes — each said, as an answer never confirmed, on the
  /// contact or the request that relied on it, unless it was said so while it
  /// was kept ([_KeptHead.told]). Whether the heads changed, and whether a
  /// warning was added.
  ({bool kept, bool warned}) _pruneKept() {
    final before = _kept.length;
    final t = now();
    var warned = false;
    _kept.removeWhere((k) => !_relied(k.creqIds, k.rid));
    for (final k in [..._kept]) {
      if (t - k.at > witnessKeepFor.inMilliseconds &&
          k.last != null &&
          !_checking.contains(k)) {
        _kept.remove(k);
        if (!k.told) {
          warned = _warn(k, HandleWarningKind.unconfirmed) || warned;
        }
      }
    }
    final held = [for (final k in _kept) if (k.rid != null) k];
    while (held.length > witnessKeptCap) {
      var out = held.first;
      for (final k in held) {
        if (k.at < out.at) out = k;
      }
      held.remove(out);
      _kept.remove(out);
      if (!out.told) {
        warned = _warn(out, HandleWarningKind.unconfirmed) || warned;
      }
    }
    return (kept: _kept.length != before, warned: warned);
  }

  /// A warning of [kind] on what relied on [k] — for a fork, [against] the
  /// head it was held to — unless the same one stands already; [atFork] for
  /// an answer said never confirmed while [k] is kept
  /// ([HandleForkWarning.atFork]). Whether one was added.
  bool _warn(_KeptHead k, HandleWarningKind kind,
      {KtTreeHead? against, bool atFork = false}) {
    final ids = {for (final i in k.creqIds) b64(i)};
    for (final w in _warnings) {
      if (w.kind == kind &&
          w.handle == k.handle &&
          w.lookedUpMs == k.at &&
          w.shown.sameRootsAs(k.head) &&
          w.creqIds.any((i) => ids.contains(b64(i)))) {
        return false;
      }
    }
    _warnings.add(HandleForkWarning(
        kind: kind,
        handle: k.handle,
        lookedUpMs: k.at,
        foundMs: now(),
        creqIds: [...k.creqIds],
        rid: k.rid,
        shown: k.head,
        against: against,
        atFork: atFork));
    return true;
  }

  /// [k] decided — covered, or a fork — so an answer said never confirmed
  /// while it was kept ([HandleForkWarning.atFork]) goes: covered, it would
  /// stay false once shown; a fork's warning takes its place. Whether one
  /// went.
  bool _unwarn(_KeptHead k) {
    final ids = {for (final i in k.creqIds) b64(i)};
    final before = _warnings.length;
    _warnings.removeWhere((w) =>
        w.atFork &&
        w.handle == k.handle &&
        w.lookedUpMs == k.at &&
        w.shown.sameRootsAs(k.head) &&
        w.creqIds.any((i) => ids.contains(b64(i))));
    return _warnings.length != before;
  }

  /// What the checks and the bound changed, written — the warnings before
  /// the heads, so that a head is never gone from the vault before what was
  /// found of it is there.
  Future<void> _saveAfterTheFact({bool kept = false, bool warned = false}) async {
    if (warned) await _saveWarnings();
    if (kept) await _saveKept();
  }

  /// What the kept heads and the warnings rely on, settled — whenever the
  /// outgoing list is written ([_saveOutgoing]): a request forgotten,
  /// answered, refused by the relay or pushed out by a newer one takes its
  /// head and its warning with it, unless a contact holds them — and at load.
  Future<void> _settleWitness() async {
    final pruned = _pruneKept();
    final before = _warnings.length;
    _warnings.removeWhere((w) => !_relied(w.creqIds, w.rid));
    try {
      await _saveAfterTheFact(
          kept: pruned.kept,
          warned: pruned.warned || _warnings.length != before);
    } catch (_) {
      // The vault busy: what went is gone here, and the next write or load
      // takes it out of the vault as well.
    }
    if (pruned.warned) notifyListeners();
  }

  /// [found]'s head, when the witness had not covered it, kept now that the
  /// request [creqId] is sent on it — before the send, as the request is
  /// remembered before it ([request]); a send that fails takes it back out
  /// with the request ([_settleWitness]). When the configuration changed
  /// since the lookup, no record here covers that head: the request is told
  /// at once that the answer was never confirmed, as one sent before the
  /// change is told at the change ([_forgetWitness]).
  Future<void> _keepUnwitnessed(HandleLookup found, Uint8List creqId) async {
    final u = found._unwitnessed;
    if (u == null || u.w.isEmpty) return;
    final handle = found.handle.canonical;
    if (u.w != _witnessOf(config)) {
      final never = _KeptHead(
          head: u.head,
          at: u.at,
          handle: handle,
          creqIds: [creqId],
          keptAt: now());
      if (_warn(never, HandleWarningKind.unconfirmed)) {
        await _saveWarnings();
        notifyListeners();
      }
      return;
    }
    _KeptHead? same;
    for (final k in _kept) {
      if (k.at == u.at && k.handle == handle && k.head.sameRootsAs(u.head)) {
        same = k;
      }
    }
    if (same != null) {
      // The same lookup sent on again: one head, and its latest requests.
      same.creqIds.add(creqId);
      if (same.creqIds.length > handleOutgoingIdsPerHandle) {
        same.creqIds.removeAt(0);
      }
    } else {
      final keptAt = now();
      _kept.add(_KeptHead(
          head: u.head,
          at: u.at,
          handle: handle,
          creqIds: [creqId],
          keptAt: keptAt,
          backAt: keptAt +
              handleUniform(random, witnessCheckBack, witnessCheckBackMax)
                  .inMilliseconds));
    }
    final pruned = _pruneKept();
    await _saveAfterTheFact(kept: true, warned: pruned.warned);
    if (pruned.warned) notifyListeners();
    _checkBackSoon();
  }

  /// The contact [rid] was added by the acceptance of [answered] (§21.7):
  /// the heads kept for its requests, and a warning on them, are the
  /// contact's now. Called before the request is forgotten
  /// ([completeOutgoing]), which would take them with it.
  Future<void> contactAddedThrough(
      String rid, OutgoingHandleRequest answered) async {
    final ids = {for (final i in answered.creqIds) b64(i)};
    bool theirs(List<Uint8List> c) => c.any((i) => ids.contains(b64(i)));
    var kept = false, warned = false;
    for (final k in _kept) {
      if (theirs(k.creqIds)) {
        k.rid = rid;
        kept = true;
      }
    }
    for (final w in _warnings) {
      if (theirs(w.creqIds)) {
        w.rid = rid;
        warned = true;
      }
    }
    await _saveAfterTheFact(kept: kept, warned: warned);
    if (warned) notifyListeners();
  }

  /// The contact [rid] was deleted: what was kept for it and its warning go
  /// with it.
  Future<void> contactGone(String rid) async {
    final k = _kept.length, w = _warnings.length;
    _kept.removeWhere((x) => x.rid == rid);
    _warnings.removeWhere((x) => x.rid == rid);
    if (_kept.length != k) await _saveKept();
    if (_warnings.length != w) {
      await _saveWarnings();
      notifyListeners();
    }
  }

  /// Forget what was kept for a contact that is not one any more — deleted
  /// while this build was not running, or not brought back by a restore.
  Future<void> keepWarningsFor(Set<String> contactRids) async {
    final k = _kept.length, w = _warnings.length;
    _kept.removeWhere((x) => x.rid != null && !contactRids.contains(x.rid));
    _warnings.removeWhere((x) => x.rid != null && !contactRids.contains(x.rid));
    if (_kept.length != k) await _saveKept();
    if (_warnings.length != w) await _saveWarnings();
  }

  /// Every head kept under [asked] held to [head], the head a lookup ended
  /// with, as the transparency client holds the head it keeps
  /// (`ktCheckHeadExtends`; `key_transparency.dart`'s `_adopt`): smaller, the
  /// log shrank under it; the same size under other roots, two histories;
  /// past it, the log's consistency proof from the kept size is required —
  /// failing, two histories again, which differ within the kept head's own
  /// entries, so what relied on it is told of a fork; withheld, or something
  /// in its place that is not one, the check is pending, and never passes.
  /// A later head shown to extend a kept one stands in for it at later
  /// lookups ([_KeptHead.ext]), so that one proof serves every kept head it
  /// stands in for; a proof from it that fails decides nothing — a fork that
  /// departs after the kept head and before the stand-in fails it, and the
  /// kept head is not that fork's — and the proof from the kept size itself
  /// is asked.
  ///
  /// Then, through [head], to [witnessed] — the head of the witness's record
  /// this lookup holds, fetched now or used again, when one verified — and to
  /// [verdict], what it says of [head]. At the kept size, the roots decide.
  /// Below it, a record that contradicts [head] contradicts the kept head
  /// [head] extends: the record differs from [head] within its own entries,
  /// and so from the kept head. Past it, a kept head [head] extends is
  /// covered when [head] and the record are consistent; otherwise the log's
  /// proof from the kept size to the record's size decides: verifying,
  /// covered; failing while [head] and the record are consistent, a fork;
  /// anything else, pending — a log that shows this device a history that
  /// forked after the kept head cannot prove the kept head to the record
  /// either, so a failure is not the kept head's. A covered head goes, and
  /// so does an answer said never confirmed while it was kept; a fork is
  /// said on what relied on the head ([HandleForkWarning]), in that answer's
  /// place.
  ///
  /// And when the record shows [head] two histories — the log showing this
  /// device one the witness did not see — a kept head [head] is shown to
  /// extend that stays pending is said at once, on what relied on it, as an
  /// answer never confirmed ([HandleForkWarning.atFork]): true, since no
  /// record has covered it, and no fork the device cannot show, since an
  /// honest head before the fork looks the same from here. It stays kept,
  /// and later checks go on deciding it.
  ///
  /// At most [witnessKeptCap] proofs are asked for one lookup, each once, and
  /// a check the lookup does not reach is pending; a check left pending is
  /// asked again at most once in [witnessReuse], whatever record the lookup
  /// holds. A check of a kept head's own ([_checkBack]) whose log could not
  /// be asked for a current head has no [head]: the record alone decides
  /// then, at the kept size by its roots and past it by the proof. Whether
  /// any check is pending now, so that this lookup is not the witness
  /// agreeing; and the heads left kept whose hold here went without an
  /// answer it needed — a proof the log did not answer at all, one not asked
  /// for want of room or because a check of the head waited on the log
  /// within [witnessReuse] — which a check of their own has not made.
  Future<({bool pending, Set<_KeptHead> unanswered})> _holdKept(
      String asked, KtTreeHead? head,
      {KtTreeHead? witnessed, _WitnessVerdict? verdict}) async {
    final pruned = _pruneKept();
    var kept = pruned.kept, warned = pruned.warned;
    final count = _kept.length;
    final t = now();
    final proofs = _KeptProofs(witnessKeptCap);
    final unanswered = <_KeptHead>{};
    for (final k in [..._kept]) {
      // The configuration changed meanwhile, or another lookup took it.
      if (_witnessOf(config) != asked) break;
      if (!_kept.contains(k)) continue;
      final keptHead = k.head;
      final heldAt = k.held;
      final waits = heldAt != null &&
          t >= heldAt &&
          t - heldAt < witnessReuse.inMilliseconds;
      final ext = k.ext;
      var answered = true;
      _Hold? hold;
      if (head == null) {
        hold = null;
      } else if (head.size < keptHead.size ||
          (head.size == keptHead.size && !head.sameRootsAs(keptHead))) {
        hold = _Hold.contradicted;
      } else if (head.size == keptHead.size) {
        hold = _Hold.extended;
      } else if (waits) {
        hold = _Hold.unproven;
        answered = false;
      } else {
        final held = await _holdOne(k, head, proofs);
        hold = held.hold;
        answered = held.answered;
      }
      if (_witnessOf(config) != asked) break;
      if (!_kept.contains(k)) continue;
      if (!identical(k.ext, ext)) kept = true;
      if (hold == _Hold.contradicted) {
        _kept.remove(k);
        _unwarn(k);
        _warn(k, HandleWarningKind.forked, against: head);
        kept = warned = true;
        continue;
      }
      final r = witnessed;
      _Kept out;
      if (r == null) {
        out = hold == _Hold.unproven ? _Kept.pending : _Kept.stays;
      } else if (r.size == keptHead.size) {
        out = r.sameRootsAs(keptHead) ? _Kept.covered : _Kept.forked;
      } else if (r.size < keptHead.size) {
        out = hold == null
            ? _Kept.stays
            : hold != _Hold.extended
                ? _Kept.pending
                : verdict == _WitnessVerdict.forked
                    ? _Kept.forked
                    : _Kept.stays;
      } else if (hold == _Hold.extended &&
          verdict == _WitnessVerdict.consistent) {
        out = _Kept.covered;
      } else if (waits) {
        out = _Kept.pending;
        answered = false;
      } else {
        final proof = await _keptProof(keptHead, r, proofs);
        answered = answered && proof.answered;
        if (_witnessOf(config) != asked) break;
        if (!_kept.contains(k)) continue;
        out = proof.ok == true
            ? _Kept.covered
            : proof.ok == false && verdict == _WitnessVerdict.consistent
                ? _Kept.forked
                : _Kept.pending;
      }
      switch (out) {
        case _Kept.covered:
          _kept.remove(k);
          kept = true;
          if (_unwarn(k)) warned = true;
        case _Kept.forked:
          _kept.remove(k);
          _unwarn(k);
          _warn(k, HandleWarningKind.forked, against: r);
          kept = warned = true;
        case _Kept.stays:
          if (k.held != null) {
            k.held = null;
            kept = true;
          }
          if (!answered) unanswered.add(k);
        case _Kept.pending:
          if (!waits) {
            k.held = t;
            kept = true;
          }
          if (!answered) unanswered.add(k);
          // The log is showing this device two histories, and the head it
          // shows extends this one: what relied on it may have relied on the
          // history the witness did not see. Said once.
          if (hold == _Hold.extended &&
              verdict == _WitnessVerdict.forked &&
              !k.told) {
            k.told = true;
            _warn(k, HandleWarningKind.unconfirmed, atFork: true);
            kept = warned = true;
          }
      }
    }
    await _saveAfterTheFact(kept: kept, warned: warned);
    if (warned || pruned.kept || _kept.length != count) notifyListeners();
    return (
      pending: _kept.any((k) => k.held != null),
      unanswered: {for (final k in unanswered) if (_kept.contains(k)) k},
    );
  }

  /// [head], past the kept head [k], held to it: the proof from the head that
  /// stands in for it when there is one and [head] reaches it, and — with
  /// none, or one that does not verify — the proof from the kept size itself.
  /// Shown to extend it, [head] stands in for it from now on. And whether the
  /// log answered what decided it.
  Future<({_Hold hold, bool answered})> _holdOne(
      _KeptHead k, KtTreeHead head, _KeptProofs proofs) async {
    final ext = k.ext;
    if (ext != null && ext.size > k.head.size && ext.size <= head.size) {
      final via = await _keptProof(ext, head, proofs);
      if (via.ok == true) {
        k.ext = head;
        return (hold: _Hold.extended, answered: true);
      }
    }
    final proof = await _keptProof(k.head, head, proofs);
    if (proof.ok == true) {
      k.ext = head;
      return (hold: _Hold.extended, answered: true);
    }
    return (
      hold: proof.ok == false ? _Hold.contradicted : _Hold.unproven,
      answered: proof.answered,
    );
  }

  /// [from] against [to], which is at or past it: equal roots at equal size;
  /// otherwise the log's consistency proof between the two sizes, asked at
  /// most once for one lookup ([proofs]) — [_KeptProofs]'s `ok` true when it
  /// verifies, false when it fails, and null when the log serves none,
  /// serves something that is not one, does not answer, or the lookup has
  /// asked all it may; `answered` false for the last two. The log, not the
  /// witness, is asked, as a lookup's own check asks it.
  Future<({bool? ok, bool answered})> _keptProof(
      KtTreeHead from, KtTreeHead to, _KeptProofs proofs) async {
    if (from.size == to.size) {
      return (ok: from.sameRootsAs(to), answered: true);
    }
    final key = '${from.size}:${to.size}';
    if (!proofs.answers.containsKey(key) && !proofs.unanswered.contains(key)) {
      if (proofs.left <= 0) return (ok: null, answered: false);
      proofs.left--;
      final c = await _askLog(
          '$_base/kt/v1/consistency?first=${from.size}&second=${to.size}');
      if (!c.answered) {
        proofs.unanswered.add(key);
      } else {
        List<Uint8List>? proof;
        final j = c.json;
        if (j != null) {
          try {
            proof = [for (final h in (j['proof'] as List)) unb64(h as String)];
          } catch (_) {}
        }
        proofs.answers[key] = proof;
      }
    }
    if (proofs.unanswered.contains(key)) return (ok: null, answered: false);
    final proof = proofs.answers[key];
    if (proof == null) return (ok: null, answered: true);
    return (
      ok: await ktVerifyConsistency(
          first: from.size,
          second: to.size,
          firstRoot: from.logRoot,
          secondRoot: to.logRoot,
          proof: proof),
      answered: true,
    );
  }

  /// Whether [k]'s check-back, or its last check, is due at [t] and not made.
  bool _backDue(_KeptHead k, int t) => k.back == null && t >= k.backAt;
  bool _lastDue(_KeptHead k, int t) =>
      k.last == null && t - k.at > witnessKeepFor.inMilliseconds;

  /// The heads a check of their own may ask for at [t]: one of their checks
  /// due and not made, and not asked for within [witnessCheckAgain].
  List<_KeptHead> _dueAt(int t) => [
        for (final k in _kept)
          if ((_backDue(k, t) || _lastDue(k, t)) &&
              (k.tried == null ||
                  t < k.tried! ||
                  t - k.tried! >= witnessCheckAgain.inMilliseconds))
            k
      ];

  /// The first moment a check of a head's own may be asked for: the earliest
  /// check not made, at its time or [witnessCheckAgain] after it was last
  /// asked for, whichever is later — or null with none.
  int? _nextCheck() {
    int? next;
    for (final k in _kept) {
      for (final due in [
        if (k.back == null) k.backAt,
        if (k.last == null) k.at + witnessKeepFor.inMilliseconds + 1,
      ]) {
        final tried = k.tried;
        final at = tried == null
            ? due
            : max(due, tried + witnessCheckAgain.inMilliseconds);
        next = next == null ? at : min(next, at);
      }
    }
    return next;
  }

  void _cancelCheckBack() {
    _checkBackTimer?.cancel();
    _checkBackTimer = null;
    _checkBackTarget = null;
  }

  /// A kept head nothing has decided is checked on its own, twice at most
  /// ([handleWitnessCheckBack]): at its check-back's moment
  /// ([_KeptHead.backAt]) and once it is [witnessKeepFor] old — each at the
  /// first moment the app is in front at or after that: [start], a return to
  /// the front ([onForeground]), or, while it stays in front, a one-shot
  /// timer, armed only while a kept head waits for a check and cancelled when
  /// the app leaves the front. Never at that moment itself: at one drawn
  /// after it, as the drain's first wait is ([foregroundDelayMin] to
  /// [foregroundDelayMax]), so that the check is not lined up with the
  /// account's own connection coming back at the same instant (R49). An
  /// earlier moment drawn already stands. A check that finds nothing due asks
  /// nothing, so a head decided before then costs nothing; and nothing is
  /// asked while no head is kept.
  void _checkBackSoon() {
    if (_disposed || !_started || !_foreground || !available || _kept.isEmpty) {
      _cancelCheckBack();
      return;
    }
    final next = _nextCheck();
    if (next == null) {
      _cancelCheckBack();
      return;
    }
    final t = now();
    final target = max(next, t) +
        handleUniform(random, foregroundDelayMin, foregroundDelayMax)
            .inMilliseconds;
    final armed = _checkBackTarget;
    if (_checkBackTimer != null &&
        armed != null &&
        armed > t &&
        armed <= target) {
      return;
    }
    _cancelCheckBack();
    // A day at most at a time: the clock is read again then.
    final day = const Duration(days: 1).inMilliseconds;
    final far = target - t > day;
    _checkBackTarget = target;
    _checkBackTimer = Timer(Duration(milliseconds: far ? day : target - t), () {
      _checkBackTimer = null;
      _checkBackTarget = null;
      if (far) {
        _checkBackSoon();
      } else {
        unawaited(_checkBack());
      }
    });
  }

  /// The kept heads due a check of their own ([_dueAt]), checked with one
  /// record for them all: each asked for first, and that written, so that a
  /// check not made is asked again at most once in [witnessCheckAgain] — a
  /// write that fails asks nothing; then the log's head and the witness's
  /// record fetched afresh, every kept head held to them as a lookup holds
  /// them ([_holdKept]) — the log asked for the proofs that needs — and the
  /// witness's state recorded as a lookup's check records it. A head's check
  /// is made once it got its answers ([handleWitnessCheckAgain]): the record,
  /// verified; the log's head, or its refusal; the proof between the two
  /// when their sizes differ; and the proofs that head needed. One not made
  /// spends nothing, unless it has gone without its answers for
  /// [witnessCheckFor] of trying, when it is given up on. What a last check
  /// made or given up on leaves undecided is then said as an answer never
  /// confirmed ([_pruneKept]).
  Future<void> _checkBack() async {
    if (_checkingBack) return;
    _checkingBack = true;
    final due = <_KeptHead>[];
    var asking = false;
    try {
      final asked = _witnessOf(config);
      final pub = config.logPub;
      if (_disposed || !available || asked.isEmpty || pub == null) return;
      // What nothing relies on any more is not checked.
      await _settleWitness();
      final t = now();
      due.addAll(_dueAt(t));
      if (due.isEmpty) return;
      final tried = {for (final k in due) k: k.tried};
      for (final k in due) {
        k.tried = t;
      }
      _checking.addAll(due);
      try {
        await _saveKept();
      } catch (_) {
        for (final k in due) {
          k.tried = tried[k];
        }
        return;
      }
      asking = true;
      final log = await _checkHead(pub);
      final head = log.head;
      final got = await _witnessRecord(asked, pub, fresh: true);
      if (_disposed || _witnessOf(config) != asked) return;
      _WitnessVerdict? verdict;
      var between = true;
      if (got != null && head != null) {
        final v = await _witnessVerdict(head, got.record.head, pub);
        verdict = v.verdict;
        between = v.answered;
        if (_disposed || _witnessOf(config) != asked) return;
      }
      final held = await _holdKept(asked, head,
          witnessed: got?.record.head, verdict: verdict);
      if (_disposed || _witnessOf(config) != asked) return;
      final answers = got != null && log.answered && between;
      final was = {
        for (final k in due) k: (k.back, k.last, k.backFail, k.lastFail)
      };
      final giveUp = witnessCheckFor.inMilliseconds;
      for (final k in due) {
        if (!_kept.contains(k)) continue; // decided
        final back = _backDue(k, t), last = _lastDue(k, t);
        if (answers && !held.unanswered.contains(k)) {
          if (back) {
            k.back = t;
            k.backFail = null;
          }
          if (last) {
            k.last = t;
            k.lastFail = null;
          }
        } else {
          if (back) {
            final from = k.backFail ??= t;
            if (t - from >= giveUp) k.back = t;
          }
          if (last) {
            final from = k.lastFail ??= t;
            if (t - from >= giveUp) k.last = t;
          }
        }
      }
      try {
        await _saveKept();
      } catch (_) {
        // Not written: nothing made, nothing given up on.
        for (final e in was.entries) {
          final (back, last, backFail, lastFail) = e.value;
          e.key
            ..back = back
            ..last = last
            ..backFail = backFail
            ..lastFail = lastFail;
        }
      }
      if (got == null) {
        await _witnessUnanswered(asked);
        return;
      }
      switch (verdict) {
        case _WitnessVerdict.forked:
          await _witnessForked(asked);
        case _WitnessVerdict.consistent
            when !held.pending &&
                now() - got.record.head.ts <= witnessStale.inMilliseconds:
          await _witnessAgreed(asked);
        default:
          await _witnessUnanswered(asked);
      }
    } catch (_) {
      // The vault busy, or an answer that is not one: what was made stays
      // made, and the rest is asked again.
    } finally {
      _checking.removeAll(due);
      _checkingBack = false;
      if (!_disposed) {
        await _settleWitness();
        _checkBackSoon();
      }
      if (asking) checksBack++;
    }
  }

  /// The log's head for a check of a kept head's own ([_checkBack]): whether
  /// the log answered at all — a head, a refusal, something that is not one
  /// — and the head when it is one this device believes, verified under
  /// [pub] and no older than [handleStaleHead].
  Future<({bool answered, KtTreeHead? head})> _checkHead(Uint8List pub) async {
    final r = await _askLog('$_base/kt/v1/sth');
    final j = r.json;
    if (j == null) return (answered: r.answered, head: null);
    try {
      final head = KtTreeHead.fromJson(j);
      if (!await ktVerifyHead(head, pub, KtLogMode.handles) ||
          now() - head.ts > handleStaleHead.inMilliseconds) {
        return (answered: true, head: null);
      }
      return (answered: true, head: head);
    } catch (_) {
      return (answered: true, head: null);
    }
  }

  // ---------------------------------------------------------------------------
  // Claiming
  // ---------------------------------------------------------------------------

  void _requireAvailable() {
    if (!available) throw const HandleException(HandleFailure.unavailable);
  }

  void _requireManage() {
    _requireAvailable();
    if (!canManage) throw const HandleException(HandleFailure.linkedDevice);
  }

  /// Whether [handle] is free: its bucket, verified, does not hold its
  /// label. A taken handle is reported as such — the person then picks other
  /// digits.
  Future<bool> isAvailable(Handle handle) async {
    _requireAvailable();
    final label = await handleLabelOffThread(handle);
    return await _resolve(label) == null;
  }

  /// A free handle for [nick] with random [digitCount] digits, trying a few
  /// draws; null when every draw was taken.
  Future<Handle?> availableWithRandomDigits(String nick,
      {int digitCount = 2, int tries = 5}) async {
    for (var i = 0; i < tries; i++) {
      final digits = [
        for (var d = 0; d < digitCount; d++) random.nextInt(10)
      ].join();
      final h = Handle.parse('$nick.$digits');
      if (await isAvailable(h)) return h;
    }
    return null;
  }

  /// Make everything a claim of [handle] needs, the recovery code included,
  /// without keeping any of it: the screen shows the code once, has it typed
  /// back, and only then [commitClaim]s.
  Future<HandleClaimDraft> prepareClaim(Handle handle,
      {int pow = handleDefaultPow}) async {
    _requireManage();
    final o = own;
    if (o != null && o.phase != HandlePhase.taken) {
      throw const HandleException(HandleFailure.alreadyHasOne);
    }
    final label = await handleLabelOffThread(handle);
    final code = await RecoveryCode.generate();
    final rk = await handleRecoveryKey(code, label);
    return HandleClaimDraft._(handle, label, randomBytes(32), randomBytes(32),
        rk.rc, pow, await formatHandleRecoveryCode(code), code);
  }

  /// The claim, confirmed: kept as [HandlePhase.pending] and published at a
  /// random moment (§21.8). The code is not kept.
  Future<void> commitClaim(HandleClaimDraft d) => _serial(() async {
        _requireManage();
        final o = own;
        if (o != null && o.phase != HandlePhase.taken) {
          throw const HandleException(HandleFailure.alreadyHasOne);
        }
        final next = OwnHandle(
          handle: d.handle,
          label: d.label,
          ownerSeed: d.ownerSeed,
          introSeed: d.introSeed,
          pow: d.pow,
          rc: d.rc,
          version: 0,
          phase: HandlePhase.pending,
          publishAt: now() +
              handleUniform(random, claimDelayMin, claimDelayMax).inMilliseconds,
        );
        await _deriveIntro(next);
        own = next;
        await _saveOwn();
        _schedulePublish();
        notifyListeners();
      });

  /// Drop a claim that is not published: pending, held after a restore, or
  /// beaten to the log. Nothing was published, so nothing needs undoing.
  Future<void> cancelClaim() => _serial(() async {
        final o = own;
        if (o == null) return;
        if (o.phase != HandlePhase.pending &&
            o.phase != HandlePhase.held &&
            o.phase != HandlePhase.taken) {
          return;
        }
        _publishTimer?.cancel();
        own = null;
        await vault.kvDelete('handle');
        notifyListeners();
      });

  /// A claim held after a restore (or refused for a reason waiting would not
  /// change), published now because the person said so.
  Future<void> publishHeld() => _serial(() async {
        final o = own;
        if (o == null || o.phase != HandlePhase.held) return;
        o.phase = HandlePhase.pending;
        o.publishAt = now();
        await _saveOwn();
        await _publishPendingNow();
      });

  void _schedulePublish() {
    _publishTimer?.cancel();
    _publishTimer = null;
    final o = own;
    if (_disposed || o == null || o.phase != HandlePhase.pending) return;
    final wait = max(0, (o.publishAt ?? now()) - now());
    _publishTimer = Timer(Duration(milliseconds: wait),
        () => unawaited(_publishPending().then((_) {}, onError: (_) {})));
  }

  /// Publish the pending claim. A refusal that time will not change ends it
  /// (taken, or a problem to show); one that it may (the log unreachable or
  /// busy) leaves it pending, tried again after [publishRetry].
  Future<void> _publishPending() => _serial(_publishPendingNow);

  Future<void> _publishPendingNow() async {
        final o = own;
        if (_disposed || o == null || o.phase != HandlePhase.pending) return;
        if (!available || !canManage) return;
        final record = await _record(o, HandleRecordKind.claim);
        final entry = await signHandleEntry(
            label: o.label, version: 1, record: record, ownerSeed: o.ownerSeed);
        final (int, String?) answer;
        try {
          answer = await _publish(entry);
        } on HandleException {
          _retryLater(o);
          return;
        }
        final (status, code) = answer;
        if (status == 201) {
          o.version = 1;
          o.phase = HandlePhase.live;
          o.publishAt = null;
          o.problem = null;
          await _saveOwn();
          notifyListeners();
          _drainSoon();
          return;
        }
        if (status == 429 || status >= 500) {
          _retryLater(o);
          return;
        }
        // Taken — or our own claim, accepted on an earlier try whose answer
        // never arrived. The log says which.
        final bool mine;
        try {
          mine = await _readBackOwn(o);
        } on HandleException catch (e) {
          // The read-back's head contradicted the witness (the only failure
          // _readBackOwn passes on): whose the label is cannot be read from
          // this log, so the claim is neither ours nor taken. It is held,
          // with the fork as its problem, for the person to publish again.
          o.phase = HandlePhase.held;
          o.publishAt = null;
          o.problem = e.failure.name;
          await _saveOwn();
          notifyListeners();
          return;
        }
        if (mine) {
          notifyListeners();
          _drainSoon();
          return;
        }
        o.phase = status == 409 && code == 'taken'
            ? HandlePhase.taken
            : HandlePhase.held;
        o.publishAt = null;
        o.problem = o.phase == HandlePhase.taken ? null : HandleFailure.refused.name;
        await _saveOwn();
        notifyListeners();
  }

  void _retryLater(OwnHandle o) {
    o.publishAt = now() + publishRetry.inMilliseconds;
    o.problem = HandleFailure.unreachable.name;
    unawaited(_saveOwn().then((_) {}, onError: (_) {}));
    _schedulePublish();
    notifyListeners();
  }

  /// Whether the log's latest record for [o] is one this device's owner key
  /// signed — and if so, adopt its version, difficulty and phase. Throws
  /// only [HandleFailure.forked]: a log its witness contradicts says nothing
  /// about whose the label is.
  Future<bool> _readBackOwn(OwnHandle o) async {
    try {
      final leaf = await _resolve(o.label);
      if (leaf == null) return false;
      final rec = await _checkedRecord(o.label, leaf);
      if (rec == null) return false;
      if (!constantTimeEquals(rec.owner, await handleKeyPublic(o.ownerSeed))) {
        return false;
      }
      o.version = leaf.version;
      o.pow = rec.pow;
      o.rc = rec.rc;
      o.phase = rec.intro == null ? HandlePhase.paused : HandlePhase.live;
      o.publishAt = null;
      o.problem = null;
      await _saveOwn();
      return true;
    } on HandleException catch (e) {
      if (e.failure == HandleFailure.forked) rethrow;
      return false;
    }
  }

  // ---------------------------------------------------------------------------
  // Managing (the primary device only)
  // ---------------------------------------------------------------------------

  /// Read this account's handle back from the log and say what it finds: the
  /// version and difficulty it holds, paused or not — or, when the log names
  /// another owner or an introduction key this device does not hold,
  /// [HandlePhase.lost]. Called when the handle screen opens and before
  /// every update; every drain reads the record too ([_recordBeforeDrain]).
  Future<void> refresh() => _serial(() async {
        final o = own;
        if (o == null || !available || !canManage) return;
        if (o.phase == HandlePhase.pending ||
            o.phase == HandlePhase.held ||
            o.phase == HandlePhase.taken) {
          return;
        }
        try {
          await _current(o);
        } on HandleException catch (e) {
          // Lost is a phase, already recorded with its reason; anything else
          // is a line on the screen until the next refresh clears it — but
          // never in place of why a handle was lost.
          if (e.failure != HandleFailure.lost && o.phase != HandlePhase.lost) {
            o.problem = e.failure.name;
            await _saveOwn();
          }
        }
        notifyListeners();
      });

  /// The log's latest record for [o], checked and taken in
  /// ([_applyRecord]); throws [HandleFailure.lost] when it says this device
  /// no longer holds the handle.
  Future<(KtBucketLeaf, HandleRecord)> _current(OwnHandle o) async {
    final leaf = await _resolve(o.label);
    if (leaf == null) throw const HandleException(HandleFailure.notClaimed);
    final rec = await _checkedRecord(o.label, leaf);
    if (rec == null) throw const HandleException(HandleFailure.badAnswer);
    if (await _applyRecord(o, leaf, rec) == _RecordVerdict.lost) {
      throw const HandleException(HandleFailure.lost);
    }
    return (leaf, rec);
  }

  /// Take in what the log's latest record [rec] (at [leaf]) says about this
  /// device's handle [o] (§21.8).
  ///
  /// * Older than the version this device published or read already: not
  ///   news — a log behind, or one showing an old history (R50) — and what
  ///   this device holds stands ([_RecordVerdict.stale]).
  /// * Naming another owner key — the code was used — or an introduction
  ///   key this device does not hold — the inbox was moved elsewhere, by
  ///   another copy of this account restored from an older backup, or by
  ///   whoever has its owner seed: [HandlePhase.lost]. This device stops
  ///   draining the mailbox it holds, which nobody resolves any more, and
  ///   does not flag it; only the recovery code brings the handle back to
  ///   it, and moves it to new keys, so whoever else holds the owner seed
  ///   loses it.
  /// * Otherwise it is this device's own handle: a newer record is taken in
  ///   — its version and its difficulty, the previous difficulty counting
  ///   for [handlePowGrace] from when the log took the change — and paused
  ///   or not as it says.
  Future<_RecordVerdict> _applyRecord(
      OwnHandle o, KtBucketLeaf leaf, HandleRecord rec) async {
    if (leaf.version < o.version) return _RecordVerdict.stale;
    final ownerOk =
        constantTimeEquals(rec.owner, await handleKeyPublic(o.ownerSeed));
    final intro = rec.intro;
    final introOk = intro == null ||
        constantTimeEquals(intro, await handleKeyPublic(o.introSeed));
    if (!ownerOk || !introOk) {
      final already = o.phase == HandlePhase.lost;
      o.phase = HandlePhase.lost;
      o.problem = ownerOk ? 'introUnknown' : null;
      o.publishAt = null;
      await _saveOwn();
      _drainTimer?.cancel();
      _drainTimer = null;
      if (!already) notifyListeners();
      return _RecordVerdict.lost;
    }
    if (leaf.version > o.version && rec.pow != o.pow) {
      o.prevPow = o.pow;
      o.prevPowUntil = (leaf.ts ?? now()) + handlePowGrace.inMilliseconds;
      o.pow = rec.pow;
    }
    o.version = leaf.version;
    o.rc = rec.rc;
    if (o.phase != HandlePhase.lost) {
      o.phase = intro == null ? HandlePhase.paused : HandlePhase.live;
    }
    o.problem = null;
    await _saveOwn();
    return intro == null ? _RecordVerdict.paused : _RecordVerdict.current;
  }

  OwnHandle _requirePublished() {
    _requireManage();
    final o = own;
    if (o == null ||
        o.phase == HandlePhase.pending ||
        o.phase == HandlePhase.held ||
        o.phase == HandlePhase.taken) {
      throw const HandleException(HandleFailure.noHandle);
    }
    if (o.phase == HandlePhase.lost) {
      throw const HandleException(HandleFailure.lost);
    }
    return o;
  }

  /// One update by the owner (§21.4 rule 3): the log's current version + 1,
  /// the owner and rc unchanged, the introduction keys and difficulty as
  /// given — [introSeed] null pauses.
  Future<void> _update(OwnHandle o,
      {required Uint8List? introSeed, required int pow}) async {
    final (leaf, rec) = await _current(o);
    final previous = o.pow;
    final intro = introSeed == null ? null : await handleIntroIdentity(introSeed);
    final record = HandleRecord.update(
        owner: rec.owner,
        intro: intro?.edPub,
        xintro: intro?.xPub,
        pow: pow,
        rc: rec.rc);
    final entry = await signHandleEntry(
        label: o.label,
        version: leaf.version + 1,
        record: record,
        ownerSeed: o.ownerSeed);
    final (status, code) = await _publish(entry);
    if (status != 201) {
      throw HandleException(switch ((status, code)) {
        (409, _) => HandleFailure.changed,
        (429, _) => HandleFailure.unreachable,
        (>= 500, _) => HandleFailure.unreachable,
        _ => HandleFailure.refused,
      });
    }
    o.version = leaf.version + 1;
    o.pow = pow;
    if (pow != previous) {
      // Stamps made for the difficulty before this one still count here for
      // a while: a requester who resolved the record a moment ago, and what
      // the relay took before its flag is renewed (§21.8).
      o.prevPow = previous;
      o.prevPowUntil = now() + handlePowGrace.inMilliseconds;
    }
    o.problem = null;
  }

  /// Stop taking requests: the record keeps the handle and loses its
  /// introduction keys, so whoever looks it up is told it is paused and
  /// sends nothing. The keys are kept to resume with.
  Future<void> pause() => _serial(() async {
        final o = _requirePublished();
        await _update(o, introSeed: null, pow: o.pow);
        o.phase = HandlePhase.paused;
        await _saveOwn();
        notifyListeners();
        // What was waiting is read once more, and then nothing until resumed.
        unawaited(_drainSeed(o.introSeed, renew: false)
            .then((_) {}, onError: (_) {}));
        _drainTimer?.cancel();
      });

  /// Take requests again, at the same mailbox.
  Future<void> resume() => _serial(() async {
        final o = _requirePublished();
        await _update(o, introSeed: o.introSeed, pow: o.pow);
        o.phase = HandlePhase.live;
        await _saveOwn();
        notifyListeners();
        _drainSoon();
      });

  /// A new introduction key and mailbox (to end a wave of requests): the
  /// old mailbox is read once more and then left; requests already pending
  /// from it can still be accepted, with the key they reached.
  Future<void> rotate() => _serial(() async {
        final o = _requirePublished();
        final old = o.introSeed;
        final oldRid = o.introRid;
        final fresh = randomBytes(32);
        await _update(o,
            introSeed: o.phase == HandlePhase.paused ? null : fresh, pow: o.pow);
        o.introSeed = fresh;
        await _deriveIntro(o);
        _oldSeeds[oldRid] = old;
        await _saveInbound();
        await _saveOwn();
        notifyListeners();
        // The old mailbox, once more and without renewing its flag: what
        // arrived before the record changed is still read.
        await _finalDrain(oldRid, old);
        if (o.phase == HandlePhase.live) _drainSoon();
      });

  /// Change what a request must prove (16–28 leading zero bits; the app
  /// offers [handlePowLevels]).
  Future<void> setDifficulty(int pow) => _serial(() async {
        if (pow < handlePowMinBits || pow > handlePowMaxBits) {
          throw ArgumentError.value(pow, 'pow');
        }
        final o = _requirePublished();
        await _update(o,
            introSeed: o.phase == HandlePhase.paused ? null : o.introSeed,
            pow: pow);
        await _saveOwn();
        notifyListeners();
        // The relay learns the new difficulty at the next `intro` frame.
        if (o.phase == HandlePhase.live) _drainSoon();
      });

  /// Give the handle up: the record loses its introduction keys for good, and
  /// this device forgets the handle's keys. The log keeps the name and its
  /// history (it is append-only); only the recovery code can bring it back.
  Future<void> retire() => _serial(() async {
        final o = _requirePublished();
        await _update(o, introSeed: null, pow: o.pow);
        _drainTimer?.cancel();
        await _finalDrain(o.introRid, o.introSeed);
        own = null;
        await vault.kvDelete('handle');
        notifyListeners();
      });

  /// Forget a handle this device can no longer manage ([HandlePhase.lost]).
  Future<void> forgetLost() => _serial(() async {
        final o = own;
        if (o == null || o.phase != HandlePhase.lost) return;
        _drainTimer?.cancel();
        own = null;
        await vault.kvDelete('handle');
        notifyListeners();
      });

  // ---------------------------------------------------------------------------
  // Recovering (§21.3, §21.4 rule 4)
  // ---------------------------------------------------------------------------

  /// Check [codeText] against [handleInput]'s current record and make the new
  /// owner, mailbox and code a recovery would install — nothing published,
  /// nothing kept. Throws [HandleFormatException] for an input that is not a
  /// handle, and [HandleException] for everything else.
  Future<HandleRecoverDraft> prepareRecover(
      String handleInput, String codeText) async {
    _requireManage();
    final handle = Handle.parse(handleInput);
    final o = own;
    if (o != null &&
        o.handle != handle &&
        o.phase != HandlePhase.taken &&
        o.phase != HandlePhase.lost) {
      throw const HandleException(HandleFailure.alreadyHasOne);
    }
    // A backup code is a real code for something else (§21.3): said by name.
    final typed = codeText.toUpperCase().replaceAll(RegExp(r'[\s\-_]'), '');
    if (typed.length == RecoveryCode.totalChars + 3 && typed.startsWith('ZBK')) {
      throw const HandleException(HandleFailure.backupCode);
    }
    final RecoveryCode code;
    try {
      code = await parseHandleRecoveryCode(codeText);
    } on FormatException {
      throw const HandleException(HandleFailure.badCode);
    }
    final label = await handleLabelOffThread(handle);
    final leaf = await _resolve(label);
    if (leaf == null) throw const HandleException(HandleFailure.notClaimed);
    final rec = await _checkedRecord(label, leaf);
    if (rec == null) throw const HandleException(HandleFailure.badAnswer);
    final oldKey = await handleRecoveryKey(code, label);
    if (!constantTimeEquals(oldKey.rc, rec.rc)) {
      throw const HandleException(HandleFailure.wrongCode);
    }
    final fresh = await RecoveryCode.generate();
    final newKey = await handleRecoveryKey(fresh, label);
    return HandleRecoverDraft._(
        handle,
        label,
        leaf.version,
        rec.pow,
        oldKey,
        randomBytes(32),
        randomBytes(32),
        newKey.rc,
        await formatHandleRecoveryCode(fresh),
        fresh);
  }

  /// Publish the recovery at once — not after a delay like a claim: `rsig`
  /// binds the version that follows the log's latest, which an update made
  /// in the meantime would overtake, and the code that signs it is not kept
  /// to sign again.
  Future<void> commitRecover(HandleRecoverDraft d) => _serial(() async {
        _requireManage();
        final ownerPub = await handleKeyPublic(d.ownerSeed);
        final intro = await handleIntroIdentity(d.introSeed);
        final v = d.version + 1;
        final rsig = await signHandleRecovery(
            recoverySeed: d.oldKey.seed,
            label: d.label,
            version: v,
            owner: ownerPub,
            rc: d.rc);
        final record = HandleRecord.recover(
            owner: ownerPub,
            intro: intro.edPub,
            xintro: intro.xPub,
            pow: d.pow,
            rc: d.rc,
            rpub: d.oldKey.pub,
            rsig: rsig);
        final entry = await signHandleEntry(
            label: d.label, version: v, record: record, ownerSeed: d.ownerSeed);
        final (status, code) = await _publish(entry);
        if (status != 201) {
          throw HandleException(switch ((status, code)) {
            (409, _) => HandleFailure.changed,
            (403, 'bad_recovery') => HandleFailure.wrongCode,
            (429, _) => HandleFailure.unreachable,
            (>= 500, _) => HandleFailure.unreachable,
            _ => HandleFailure.refused,
          });
        }
        final previous = own;
        if (previous != null && previous.handle == d.handle) {
          _oldSeeds[previous.introRid] = previous.introSeed;
          _pruneSeeds();
          await _saveInbound();
        }
        final next = OwnHandle(
          handle: d.handle,
          label: d.label,
          ownerSeed: d.ownerSeed,
          introSeed: d.introSeed,
          pow: d.pow,
          rc: d.rc,
          version: v,
          phase: HandlePhase.live,
        );
        await _deriveIntro(next);
        own = next;
        await _saveOwn();
        notifyListeners();
        _drainSoon();
      });

  // ---------------------------------------------------------------------------
  // Finding and asking (the requester's side; any device)
  // ---------------------------------------------------------------------------

  /// Look [input] up (§21.7, §21.8): parse it (throws [HandleFormatException]
  /// with the reason), compute its label off the UI thread, resolve it
  /// ([_resolve]: its bucket among decoys, verified under the pinned key),
  /// and hold the record to its one encoding and its owner's signature (and
  /// the recovery key's, on a recover) — and to what this device found the
  /// last time it looked the handle up ([handleKnownChange]). A record the
  /// owner rule does not lead to from there, or no record where there was
  /// one, is [HandleLookupState.changed], and nothing can be sent to it.
  /// Whatever else a lookup finds is remembered for the next.
  Future<HandleLookup> find(String input) async {
    _requireAvailable();
    final handle = Handle.parse(input);
    final label = await handleLabelOffThread(handle);
    final (leaf, unwitnessed) = await _resolveHead(label);
    final mem = await _lookupMemory();
    final known = mem.knownFor(label);
    if (leaf == null) {
      if (known != null) {
        return HandleLookup._(
            handle, HandleLookupState.changed, label, null, null, null,
            change: HandleChange.history);
      }
      return HandleLookup._(
          handle, HandleLookupState.notFound, label, null, null, null);
    }
    final rec = await _checkedRecord(label, leaf);
    if (rec == null) {
      return HandleLookup._(
          handle, HandleLookupState.invalid, label, leaf.version, null, null);
    }
    final o = own;
    if (o != null &&
        o.handle == handle &&
        constantTimeEquals(rec.owner, await handleKeyPublic(o.ownerSeed))) {
      return HandleLookup._(
          handle, HandleLookupState.own, label, leaf.version, rec, null);
    }
    final hash = await sha256Bytes(leaf.value!);
    if (known != null) {
      final change = await handleKnownChange(known,
          version: leaf.version, hash: hash, rec: rec);
      if (change != null) {
        return HandleLookup._(
            handle, HandleLookupState.changed, label, leaf.version, rec, null,
            change: change);
      }
    }
    mem.remember(
        label,
        KnownHandle(
            owner: rec.owner,
            rc: rec.rc,
            version: leaf.version,
            hash: hash,
            atMs: now()));
    await _saveMemory(mem);
    if (rec.intro == null) {
      return HandleLookup._(
          handle, HandleLookupState.paused, label, leaf.version, rec, null);
    }
    // The one result a request can be sent on carries the head the witness
    // had not covered, for the request to keep (§21.8).
    return HandleLookup._(handle, HandleLookupState.found, label, leaf.version,
        rec, await introRoutingId(rec.intro!),
        unwitnessed: unwitnessed);
  }

  /// Forget what this device found the last time it looked [lookup]'s handle
  /// up, and look it up again as if for the first time — the person's
  /// choice, after a lookup said [HandleLookupState.changed] and they checked
  /// the change some other way. What it finds is remembered from then on.
  Future<HandleLookup> lookUpAsNew(HandleLookup lookup) async {
    _requireAvailable();
    final mem = await _lookupMemory();
    mem.forget(lookup.label);
    await _saveMemory(mem);
    return find(lookup.handle.canonical);
  }

  /// Send [found]'s owner a contact request (§21.7): an ordinary `creq`
  /// addressed to the introduction mailbox, sealed to `xintro`, sent on the
  /// anonymous link with a proof of work at the record's difficulty computed
  /// off the UI thread — and, when the relay's clock says another day, made
  /// once more for the relay's day. The request is remembered first, so an
  /// acceptance that comes back can be matched to it.
  Future<void> request(HandleLookup found) async {
    _requireAvailable();
    if (found.state == HandleLookupState.paused) {
      throw const HandleException(HandleFailure.paused);
    }
    final rec = found.record;
    final introRid = found.introRid;
    if (found.state != HandleLookupState.found ||
        rec == null ||
        rec.intro == null ||
        introRid == null) {
      throw const HandleException(HandleFailure.notClaimed);
    }
    final creq = await ContactRequest.create(
        me: host.identity, toRid: introRid, displayName: host.displayName);
    final payload = await SealedEnvelope.seal(
        toXPub: rec.xintro!, fromRid: host.myRid, payload: creq.encode());
    final creqId = await contactRequestId(creq);
    await _remember(found.handle.canonical, rec, creqId);
    await _keepUnwitnessed(found, creqId); // §21.8, after the fact
    final id = newMessageId();
    final envelope = Uint8List.fromList(utf8.encode(payload));
    final first = await _stamp(introRid, introPowDay(now()), envelope, rec.pow);
    try {
      try {
        await host.sendStamped(to: introRid, id: id, payload: payload, pow: first);
      } on RelayPowRequired catch (e) {
        // The relay's day is not ours (near midnight): one stamp for its day,
        // at the difficulty the record asks, and no more (§21.7).
        final again = await _stamp(introRid, e.day, envelope, rec.pow);
        await host.sendStamped(to: introRid, id: id, payload: payload, pow: again);
      }
    } on RelayPowRequired {
      await _forgetSent(found.handle.canonical, creqId);
      throw const HandleException(HandleFailure.powRefused);
    } on RelayException catch (e) {
      await _forgetSent(found.handle.canonical, creqId);
      throw HandleException(e.message == 'not connected'
          ? HandleFailure.notConnected
          : HandleFailure.relayRefused);
    }
  }

  Future<String> _stamp(
      String introRid, int day, Uint8List envelope, int bits) async {
    stampsMade++;
    final s = b64url(await stampOffThread(introRid, day, envelope, bits));
    return debugStampFilter?.call(s) ?? s;
  }

  /// A proof-of-work stamp (§21.7) found in an isolate of its own: 2^bits
  /// hashes expected, a second or more on a phone at the default. Static, so
  /// the closure the isolate is handed captures the four values it needs and
  /// nothing of this service.
  static Future<Uint8List> stampOffThread(
          String introRid, int day, Uint8List envelope, int bits) =>
      Isolate.run(() => createIntroPowStamp(
          introRid: introRid, day: day, envelope: envelope, bits: bits));

  Future<void> _remember(
      String handle, HandleRecord rec, Uint8List creqId) async {
    final i = _outgoing.indexWhere((o) => o.handle == handle);
    final ids = <Uint8List>[
      if (i >= 0 && constantTimeEquals(_outgoing[i].introPub, rec.intro!))
        ..._outgoing[i].creqIds,
      creqId,
    ];
    if (i >= 0) _outgoing.removeAt(i);
    _outgoing.add(OutgoingHandleRequest(
      handle: handle,
      ownerPub: rec.owner,
      introPub: rec.intro!,
      xintroPub: rec.xintro!,
      creqIds: ids.length > handleOutgoingIdsPerHandle
          ? ids.sublist(ids.length - handleOutgoingIdsPerHandle)
          : ids,
      sentMs: now(),
    ));
    while (_outgoing.length > handleOutgoingCap) {
      _outgoing.removeAt(0);
    }
    await _saveOutgoing();
    notifyListeners();
  }

  Future<void> _forgetSent(String handle, Uint8List creqId) async {
    final i = _outgoing.indexWhere((o) => o.handle == handle);
    if (i < 0) return;
    final o = _outgoing[i];
    o.creqIds.removeWhere((x) => constantTimeEquals(x, creqId));
    if (o.creqIds.isEmpty) _outgoing.removeAt(i);
    await _saveOutgoing();
    notifyListeners();
  }

  /// Stop waiting for an answer from [handle]. An acceptance that arrives
  /// later is an ordinary request.
  Future<void> forgetOutgoing(String handle) async {
    _outgoing.removeWhere((o) => o.handle == handle);
    await _saveOutgoing();
    notifyListeners();
  }

  /// The outgoing request an acceptance's [ia] acknowledges (§21.7): the
  /// introduction key resolved for it signed this device's routing id, the
  /// accepting account's key [ownerAccountEdPub] and one of its request ids.
  /// Null when none does — and then the acceptance is an ordinary request.
  Future<OutgoingHandleRequest?> matchAcknowledgement(
      {required String ia, required Uint8List ownerAccountEdPub}) async {
    for (final o in _outgoing.reversed) {
      for (final id in o.creqIds) {
        if (await verifyIntroAck(
            ia: ia,
            introPub: o.introPub,
            requesterRid: host.myRid,
            ownerAccountEdPub: ownerAccountEdPub,
            creqId: id)) {
          return o;
        }
      }
    }
    return null;
  }

  /// The acknowledged request is answered: stop waiting on it.
  Future<void> completeOutgoing(OutgoingHandleRequest o) async {
    _outgoing.remove(o);
    await _saveOutgoing();
    notifyListeners();
  }

  // ---------------------------------------------------------------------------
  // The owner's side: requests that came through the handle
  // ---------------------------------------------------------------------------

  /// Record that the pending request from [rid] came through the handle. The
  /// cap is the chat service's, applied as it files the request
  /// ([HandleHost.addHandleRequest]); a request it pushes out is forgotten
  /// here through [forgetInbound].
  Future<void> recordInbound(String rid,
      {required String handle,
      required String introRid,
      required Uint8List creqId}) async {
    _inbound[rid] = HandleRequestMeta(
        handle: handle,
        introRid: introRid,
        creqId: creqId,
        at: now(),
        seq: ++_seq);
    _pruneSeeds();
    await _saveInbound();
  }

  /// The pending request from [rid] is gone (accepted, declined, blocked,
  /// replaced by one that did not come through the handle, or its sender
  /// deleted).
  Future<void> forgetInbound(String rid) async {
    if (_inbound.remove(rid) == null) return;
    _pruneSeeds();
    await _saveInbound();
  }

  /// The person has seen every pending handle request: none of them is the
  /// first the cap drops any more.
  Future<void> markInboundSeen() async {
    var changed = false;
    for (final m in _inbound.values) {
      if (!m.seen) {
        m.seen = true;
        changed = true;
      }
    }
    if (changed) await _saveInbound();
  }

  /// `ia` for accepting the request from [requesterRid] (§21.7), signed by
  /// the introduction key of the mailbox it reached; null when it did not
  /// come through the handle, or that key is no longer held.
  Future<String?> acknowledgement(String requesterRid,
      {required Uint8List ownerAccountEdPub}) async {
    if (debugOmitAcknowledgement) return null;
    final meta = _inbound[requesterRid];
    if (meta == null) return null;
    final seed = _seedFor(meta.introRid);
    if (seed == null) return null;
    return signIntroAck(
        introSeed: seed,
        requesterRid: requesterRid,
        ownerAccountEdPub: ownerAccountEdPub,
        creqId: meta.creqId);
  }

  Uint8List? _seedFor(String introRid) {
    final o = own;
    if (o != null && o.introRid == introRid) return o.introSeed;
    return _oldSeeds[introRid];
  }

  /// Old introduction seeds go once nothing pending still needs them — and
  /// not while their mailbox is being read for the last time, when what it
  /// holds may be a request that will.
  void _pruneSeeds() {
    final needed = {
      for (final m in _inbound.values) m.introRid,
      ..._finalDrains,
    };
    _oldSeeds.removeWhere((rid, _) => !needed.contains(rid));
  }

  /// The mailboxes of seeds being read once more after a rotation or a
  /// retirement.
  final Set<String> _finalDrains = {};

  /// Read the mailbox of [seed] once more without renewing its flag, the
  /// seed held in [_oldSeeds] meanwhile so that a request it holds can be
  /// acknowledged with it; then let the seed go unless something needs it.
  Future<void> _finalDrain(String rid, Uint8List seed) async {
    _oldSeeds[rid] = seed;
    _finalDrains.add(rid);
    try {
      await _drainSeed(seed, renew: false);
    } catch (_) {
      // Unreachable now: what it held expires at the relay.
    } finally {
      _finalDrains.remove(rid);
      _pruneSeeds();
      await _saveInbound();
    }
  }

  // ---------------------------------------------------------------------------
  // The introduction mailbox
  // ---------------------------------------------------------------------------

  bool get _shouldDrain =>
      _started &&
      !_disposed &&
      available &&
      canManage &&
      own?.phase == HandlePhase.live;

  void _scheduleDrain({bool first = false}) {
    _drainTimer?.cancel();
    _drainTimer = null;
    if (!_foreground || !_shouldDrain) return;
    final wait = first
        ? handleUniform(random, foregroundDelayMin, foregroundDelayMax)
        : handleJittered(random, drainEvery);
    _drainTimer = Timer(wait, () async {
      await drain().then((_) {}, onError: (_) {});
      _scheduleDrain();
    });
  }

  /// A drain now, and the timer from it.
  void _drainSoon() {
    if (!_shouldDrain) return;
    unawaited(drain().then((_) {}, onError: (_) {}));
    _scheduleDrain();
  }

  /// Read the introduction mailbox once: the account's record first
  /// ([_recordBeforeDrain]), then a connection of its own, authenticated as
  /// the introduction identity and never as the account, re-flagged with the
  /// record's difficulty, never registered for push; every envelope's stamp
  /// counted here before it is opened. Returns how many envelopes it
  /// decided. One drain at a time.
  Future<int> drain() {
    final running = _draining;
    if (running != null) return running;
    final o = own;
    if (!_shouldDrain || o == null) return Future.value(0);
    final run = _drainSeed(null, renew: true).whenComplete(() {
      _draining = null;
    });
    _draining = run;
    return run;
  }

  /// [once]: the seed of a mailbox to read once more without flagging it
  /// ([renew] false); a renewing drain reads the handle's own mailbox, as
  /// the record check left it.
  Future<int> _drainSeed(Uint8List? once, {required bool renew}) async {
    if (!available || !canManage) return 0;
    // The flag's difficulty, or null to read without flagging.
    int? flag;
    var seed = once;
    if (renew) {
      final (go, flagPow, current) = await _recordBeforeDrain();
      if (!go || current == null) return 0;
      flag = flagPow;
      seed = current;
    }
    if (seed == null) return 0;
    final o = own;
    final handle = o?.handle.canonical;
    // What a stamp has to reach to count here: the difficulty in force, and
    // for a while after a change the previous one (§21.8).
    final floorBits = o == null
        ? handlePowMinBits
        : handleStampFloor(o.pow,
            prevPow: o.prevPow, prevPowUntil: o.prevPowUntil, nowMs: now());
    final id = await handleIntroIdentity(seed);
    final rid = await id.routingId();
    final client = await RelayClient.connect(host.relayUrl, id);
    final inbox = <RelayInbound>[];
    var last = DateTime.now();
    final sub = client.messages.listen((m) {
      inbox.add(m);
      last = DateTime.now();
    });
    var decided = 0;
    try {
      if (flag != null) {
        try {
          await client.intro(flag);
          relayGuard = HandleRelayGuard.guarded;
        } on RelayException catch (e) {
          // The relay is not guarding the mailbox right now — too old to
          // know the frame, holding all the flags it will, or pacing them —
          // so it takes sends without checking their work. The mailbox is
          // still read, every stamp is still counted here, and the screen
          // says so (§21.6, §21.8).
          relayGuard = switch (e.message) {
                'unknown_frame' => HandleRelayGuard.tooOld,
                'intro_full' => HandleRelayGuard.full,
                'rate_limited' => HandleRelayGuard.paced,
                _ => null,
              } ??
              relayGuard;
        }
      }
      final started = DateTime.now();
      var next = 0;
      while (true) {
        while (next < inbox.length) {
          final m = inbox[next++];
          final ack = await _onIntroEnvelope(m, rid, id, handle, floorBits);
          if (ack) {
            decided++;
            try {
              client.ackReceived(id: m.id, from: m.from);
            } catch (_) {
              // The link went: the relay hands it over again next time.
            }
          }
        }
        final t = DateTime.now();
        if (t.difference(last) >= drainQuiet ||
            t.difference(started) >= drainMax ||
            !client.isOpen) {
          break;
        }
        await Future<void>.delayed(const Duration(milliseconds: 100));
      }
    } finally {
      await sub.cancel();
      await client.close();
    }
    try {
      await _settleLedger();
    } catch (_) {
      // The vault busy: the tallies wait for the next drain, in memory.
    }
    if (renew) {
      drains++;
      lastDrainMs = now();
      notifyListeners();
    }
    return decided;
  }

  /// One envelope from the introduction mailbox, and whether its fate is
  /// decided (acknowledge it) — patch 57's rule: anything that can never be a
  /// handle request is acknowledged and dropped, so it cannot wedge the
  /// mailbox; a failure that may pass (the vault busy) is left with the relay
  /// for the next drain.
  ///
  /// Never a request: an envelope whose stamp does not count here — none,
  /// fewer than [floorBits], made for a day the relay could not have taken
  /// it on ([handleStampOf]) — because a relay that lost the mailbox's flag
  /// takes sends without checking them, and this check is what guards the
  /// inbox then (§21.6, §21.8); one decided here before
  /// ([HandleStampLedger]), so a request is decided once whoever sends it
  /// again; and then, opened, one not sealed for this key, not a request,
  /// not addressed to this mailbox, or not signed by the identity it names.
  Future<bool> _onIntroEnvelope(RelayInbound m, String introRid, ZIdentity id,
      String? handle, int floorBits) async {
    try {
      if (m.from.isNotEmpty || handle == null) return true;
      final stamp = await handleStampOf(
          introRid: introRid,
          payload: m.payload,
          pow: m.pow,
          powDay: m.powDay,
          serverTs: m.serverTs);
      if (stamp == null || stamp.bits < floorBits) {
        droppedUnstamped++;
        _ledger.tally(introPowDay(m.serverTs)).unstamped++;
        _tallyDirty = true;
        return true;
      }
      final digest = await _ledger.digestOf(stamp.envelopeHash);
      if (_ledger.refuses(digest)) {
        droppedReplays++;
        _ledger.tally(stamp.day).copies++;
        _tallyDirty = true;
        return true;
      }
      if (await _decideIntroEnvelope(m, introRid, id, handle)) {
        // A request, decided: written down before the relay is told, and
        // before the next envelope can push it out of the cap, so a copy of
        // it is refused from now on, after a restart too.
        await _rememberDecided(stamp.day, digest);
      }
      return true;
    } catch (e) {
      return !host.isTransientFailure(e);
    }
  }

  /// Open, check and file an introduction envelope whose stamp counted.
  /// Returns whether it was a request — opened, a `creq` addressed to this
  /// mailbox and signed by the identity that sealed it — whatever the rules
  /// then made of it; false for one that can never be a request; throws for
  /// a failure that may pass.
  Future<bool> _decideIntroEnvelope(
      RelayInbound m, String introRid, ZIdentity id, String handle) async {
    final opened = await SealedEnvelope.open(
        myXSeed: id.xSeed, myXPub: id.xPub, blob: m.payload);
    if (opened == null) return false;
    final creq = ContactRequest.tryParse(opened.payload);
    if (creq == null) return false;
    if (!await creq.verify(expectedTo: introRid, sealedFrom: opened.fromRid)) {
      return false;
    }
    final rid = opened.fromRid;
    final filed =
        await host.addHandleRequest(creq, requesterRid: rid, handle: handle);
    if (filed) {
      await recordInbound(rid,
          handle: handle,
          introRid: introRid,
          creqId: await contactRequestId(creq));
    }
    return true;
  }

  /// Before a drain flags the mailbox, the account's own record from the log
  /// (§21.8), so that this device flags at the difficulty the record asks —
  /// after a restore of an older backup its own may be lower — and notices,
  /// without anyone opening the handle screen, that the handle is no longer
  /// its own: recovered by another owner key, or its inbox moved to a key
  /// this device does not hold ([_applyRecord]). Returns whether to drain, the
  /// difficulty to flag with — null to read the mailbox once more without
  /// flagging it, when the record says paused — and the mailbox's seed. A
  /// log that cannot be asked now changes nothing: the drain goes on with
  /// what this device holds.
  ///
  /// One management step among the others ([_serial]): a new inbox being
  /// published is never read back half done — the record already naming the
  /// new key while this device still holds the old one, which would look
  /// like an inbox moved elsewhere.
  Future<(bool, int?, Uint8List?)> _recordBeforeDrain() => _serial(() async {
        final o = own;
        if (o == null || o.phase != HandlePhase.live) {
          return (false, null, null);
        }
        final KtBucketLeaf? leaf;
        final HandleRecord? rec;
        try {
          leaf = await _resolve(o.label);
          rec = leaf == null ? null : await _checkedRecord(o.label, leaf);
        } on HandleException {
          return (true, o.pow, o.introSeed);
        }
        if (leaf == null || rec == null) return (true, o.pow, o.introSeed);
        return switch (await _applyRecord(o, leaf, rec)) {
          _RecordVerdict.lost => (false, null, null),
          _RecordVerdict.paused => (true, null, o.introSeed),
          _RecordVerdict.stale => (true, o.pow, o.introSeed),
          // Never below what the log publishes, nor below what this device
          // holds at the same version.
          _RecordVerdict.current => (true, max(o.pow, rec.pow), o.introSeed),
        };
      });

  // ---------------------------------------------------------------------------
  // The log
  // ---------------------------------------------------------------------------

  String get _base => config.logUrl.trim().replaceAll(RegExp(r'/+$'), '');

  /// The label of [handle], computed in an isolate of its own: Argon2id at
  /// 19 MiB is ~130 ms of pure Dart on a fast core and more on a phone.
  static Future<Uint8List> handleLabelOffThread(Handle handle) =>
      Isolate.run(() => handleLabel(handle));

  /// The latest leaf for [label], verified (§19.9, §21.8) — or null, a
  /// verified absence — asked without naming it (`handle_lookups.dart`):
  ///
  /// * the lookup holds the head it read first, and every answer in it is
  ///   under that head or one that extends it ([_accept]) — held for this
  ///   lookup, and kept past it only for the witness to cover, when a
  ///   request is sent on what it found ([_keepUnwitnessed], R50), every
  ///   head a later lookup ends with then held to it ([_holdKept]);
  /// * k is the estimate this install's own counts of labels bear out
  ///   ([HandleLookupMemory.bits], first made from random buckets by
  ///   [_probeBits]), never finer than the signed size allows nor than the
  ///   log's `bucketBits`, which is unsigned and so only ever lowers it;
  /// * the label's bucket is asked among its decoys' ([handleLookupBuckets]),
  ///   one request each, every answer verified under the pinned key and on a
  ///   head no older than [handleStaleHead];
  /// * a bucket the log refuses as too large is never narrowed to the half
  ///   that holds the label: the estimate is made again from random buckets
  ///   (a log that grew past it needs a finer one), once, and the lookup
  ///   asked again at that; refused again, the log is unreachable;
  /// * the buckets asked are counted, and k moves as [handleNextBits] says;
  /// * with a witness configured, the head the lookup ends with is held to
  ///   the witness's record ([_witnessCheck]): a head the record contradicts
  ///   fails the lookup as [HandleFailure.forked], and one the log will not
  ///   prove the way from as [HandleFailure.unreachable] — so every way a
  ///   head is taken here, a lookup, a claim's check that a name is free, the
  ///   owner's reads of its own record before a change, at a refresh, before
  ///   each drain and after a claim the log refused, and a recovery's read,
  ///   is checked, once — and the head each of them ends with, and the
  ///   record it holds, hold the heads kept after the fact ([_holdKept]);
  /// * a leaf no honest log could serve ([handleLeafProblem]) is a bad
  ///   answer.
  Future<KtBucketLeaf?> _resolve(Uint8List label) async =>
      (await _resolveHead(label)).$1;

  /// [_resolve], and the head the lookup ended with when the witness's record
  /// did not cover it ([_witnessCheck]): what [find] hands a request to keep.
  Future<(KtBucketLeaf?, _Unwitnessed?)> _resolveHead(Uint8List label) async {
    final pub = config.logPub;
    if (!available || pub == null) {
      throw const HandleException(HandleFailure.unavailable);
    }
    final mem = await _lookupMemory();
    final lookup = await _head(pub);
    final bySize = handleBitsFor(lookup.head.size);
    final held = mem.bits;
    for (var attempt = 0;; attempt++) {
      final estimate = mem.bits ?? await _probeBits(lookup, bySize);
      mem.bits = estimate;
      final k = min(min(estimate, bySize), lookup.recommended ?? ktMaxBucketBits);
      final asked = handleLookupBuckets(mem.key, label, k);
      final answers =
          await Future.wait([for (final q in asked) _bucket(lookup, q)]);
      if (answers.contains(null)) {
        mem.bits = null;
        if (attempt == 0) continue;
        if (held != null) await _saveMemory(mem);
        throw const HandleException(HandleFailure.unreachable);
      }
      // Asked side by side, so the heads come back in any order: accepted
      // smallest first, each extending the last.
      final heads = [for (final a in answers) a!.head]
        ..sort((a, b) => a.size - b.size);
      for (final h in heads) {
        await _accept(lookup, h);
      }
      // §19.5 step 3, once, on the head the lookup ends with: every answer
      // it used is under that head or one it extends. Two histories, or a
      // log that will not prove there are not, and nothing the lookup
      // counted or found is kept — the estimate included.
      _Unwitnessed? unwitnessed;
      if (config.hasWitness) {
        try {
          unwitnessed = await _witnessCheck(lookup);
        } on HandleException {
          mem.bits = held;
          rethrow;
        }
      }
      mem.bits = handleNextBits(
          estimate, k, [for (final a in answers) a!.bucket.leaves.length]);
      if (mem.bits != held) await _saveMemory(mem);
      final mine = answers.firstWhere((a) => a!.bucket.query.holds(label))!;
      final leaf = mine.bucket.leafFor(label);
      if (leaf != null && handleLeafProblem(leaf) != null) {
        throw const HandleException(HandleFailure.badAnswer);
      }
      return (leaf, unwitnessed);
    }
  }

  HandleLookupMemory? _memory;
  Future<void>? _memoryLoading;

  /// Test seam: called with each bucket an estimate asks ([_probeBits]) —
  /// a random one, which says nothing about any lookup — just before it is
  /// asked, so a test can tell it from a lookup's.
  @visibleForTesting
  void Function(KtBucketQuery q)? debugOnProbe;

  /// This install's lookup memory for the log configured now: read from the
  /// vault once, and begun afresh — a new decoy key, no estimate, nothing
  /// found — for a log with another key.
  Future<HandleLookupMemory> _lookupMemory() async {
    final pub = config.logPub;
    if (pub == null) throw const HandleException(HandleFailure.unavailable);
    final log = b64(pub);
    // One load at a time: two lookups at a first start must not draw two
    // keys.
    while (true) {
      final m = _memory;
      if (m != null && m.log == log) return m;
      final loading = _memoryLoading;
      if (loading == null) break;
      await loading;
    }
    final done = Completer<void>();
    _memoryLoading = done.future;
    try {
      final text = await vault.kvGet(handleLookupKey);
      final stored = text == null ? null : HandleLookupMemory.parse(text);
      if (stored != null && stored.log == log) return _memory = stored;
      // Kept before its first use: a lookup that fails after asking its
      // buckets must ask the same ones when it is tried again, after a
      // restart too, or the two sets would meet in the handle's.
      final fresh = HandleLookupMemory(log: log, key: _randomBytes32());
      await _saveMemory(fresh);
      return _memory = fresh;
    } finally {
      _memoryLoading = null;
      done.complete();
    }
  }

  Future<void> _saveMemory(HandleLookupMemory m) =>
      vault.kvPut(handleLookupKey, jsonEncode(m.toJson()));

  /// 32 bytes from [random] — `Random.secure()` unless a test gave its own.
  Uint8List _randomBytes32() =>
      Uint8List.fromList([for (var i = 0; i < 32; i++) random.nextInt(256)]);

  /// One lookup's view of the log: the head it read first, verified under
  /// [pub] and no older than [handleStaleHead], replaced only by one that
  /// extends it ([_accept]); and the `bucketBits` served beside it (null
  /// when absent or out of range). The signed size is what bounds k from
  /// above.
  Future<_HandleLookupHead> _head(Uint8List pub) async {
    final sth = await _getJson('$_base/kt/v1/sth');
    final KtTreeHead head;
    try {
      head = KtTreeHead.fromJson(sth);
    } on KtVerifyException {
      throw const HandleException(HandleFailure.badAnswer);
    } on FormatException {
      throw const HandleException(HandleFailure.badAnswer);
    }
    if (!await ktVerifyHead(head, pub, KtLogMode.handles)) {
      throw const HandleException(HandleFailure.badAnswer);
    }
    _requireFresh(head);
    final rb = sth['bucketBits'];
    return _HandleLookupHead(
        pub, head, rb is int && rb >= 0 && rb <= ktMaxBucketBits ? rb : null);
  }

  /// A head signed more than [handleStaleHead] ago, by this device's clock,
  /// is not believed (a head from the future is: a clock behind by a day is
  /// a clock, and a log that signs ahead gains nothing by it).
  void _requireFresh(KtTreeHead head) {
    if (now() - head.ts > handleStaleHead.inMilliseconds) {
      throw const HandleException(HandleFailure.stale);
    }
  }

  /// [fresh], served with an answer in [lookup], becomes its held head when
  /// it extends the one held — §19.5's steps as the transparency client
  /// takes them, for one lookup: the same roots, or a larger size with a
  /// consistency proof from the held size to it. A smaller size, the same
  /// size under other roots, or no proof is a log that contradicted itself
  /// within one lookup: a bad answer, and nothing it said is used. (Between
  /// lookups a head is held to this once a request was sent on its lookup
  /// before the witness covered it ([_holdKept]); two histories shown at two
  /// lookups are otherwise a witness's to catch — [_witnessCheck], R50. The
  /// heads of a lookup that fails here are not held to the kept heads: it
  /// fails before its check, which is what holds them.)
  Future<void> _accept(_HandleLookupHead lookup, KtTreeHead fresh) async {
    final held = lookup.head;
    if (held.sameRootsAs(fresh)) return;
    // Signed under the handle log's context already ([_bucket]); what is
    // left of §19.5's steps is that it extends the held head. (The
    // transparency library's `ktCheckHeadExtends` checks the signature too,
    // in the transparency log's context, so it is not used here.)
    if (fresh.size <= held.size) {
      // Smaller: the log shrank. The same size under other roots: a fork.
      throw const HandleException(HandleFailure.badAnswer);
    }
    final c = await _getJson(
        '$_base/kt/v1/consistency?first=${held.size}&second=${fresh.size}');
    final List<Uint8List> proof;
    try {
      proof = [for (final h in (c['proof'] as List)) unb64(h as String)];
    } catch (_) {
      throw const HandleException(HandleFailure.badAnswer);
    }
    if (!await ktVerifyConsistency(
        first: held.size,
        second: fresh.size,
        firstRoot: held.logRoot,
        secondRoot: fresh.logRoot,
        proof: proof)) {
      throw const HandleException(HandleFailure.badAnswer);
    }
    lookup.head = fresh;
  }

  /// §19.5 step 3 for one lookup, in the handle log's contexts: the witness's
  /// record ([_witnessRecord]) held against the head [lookup] ends with.
  /// Throws [HandleFailure.forked] when the two are two histories, and
  /// [HandleFailure.unreachable] (or [HandleFailure.badAnswer]) when their
  /// sizes differ and the log serves no proof of the way between them
  /// ([_witnessVerdict]): step 3 requires consistency or a proof that
  /// verifies, and a lookup that fails sends nothing, so nothing of it is
  /// kept for a later lookup to ask again: a proof withheld is refused rather
  /// than passed over.
  ///
  /// A witness that cannot be fetched, and a record that does not verify
  /// under the pinned key — one co-signed by any other key among them,
  /// however it compares — are no verdict, and the lookup goes on as it
  /// would with no witness (§19.5: "A witness that cannot be fetched, or
  /// whose record does not verify, is no verdict"). A record whose head is
  /// more than [witnessStale] old is held to every comparison all the same,
  /// and a fork it shows is a fork; it is not the witness agreeing. Only a
  /// current record the head is shown consistent with is.
  ///
  /// After the fact (Finnian's decision of 2026‑10‑20): every head kept for
  /// this witness is held to the head this lookup ends with and, through it,
  /// to the record ([_holdKept]), with no record as well as with one — and
  /// while a check of one waits on the log, this check is not the witness
  /// agreeing, whether the record was fetched now or is one used again; one
  /// used again is not the witness asked either, so the quiet timer stays.
  /// Then the head this lookup ends with, when the record does not cover it
  /// — smaller than the head, or none that verified — is returned, for a
  /// request sent on the lookup to keep: a history that departs after the
  /// witness's latest co-signed head passes this check, and is caught once
  /// the log shows this device a head that does not extend it, or a record
  /// that reaches it is held.
  ///
  /// A kept head nothing looks up is checked on its own as well, twice at
  /// most ([_checkBack]), so a device that looks nothing up again still
  /// decides it. And a lookup the record shows two histories says at once,
  /// as an answer never confirmed, what relied on a kept head its head
  /// extends and the check leaves pending ([_holdKept]). What still is not
  /// caught as a fork (§21.8, R50): a fork shown to a lookup that sent
  /// nothing; and a kept head nothing decides before it lapses
  /// ([witnessKeepFor]) — a witness that stops, or that will not follow a log
  /// whose next entry the owner rule refuses, a log that withholds the proof,
  /// or one that keeps the device on a history that forked between the kept
  /// head and the witness's record, where the kept head cannot be told from
  /// one before the fork — which is said as an answer never confirmed, not
  /// dropped in silence. Not held to the kept heads: the log's own head this
  /// check asks for beside a witness ahead of it ([_witnessVerdict]), which
  /// decides only this lookup's verdict. handle_lookup_test 26, 30, 31, 36,
  /// 37 and 38 to 48 pin these.
  Future<_Unwitnessed?> _witnessCheck(_HandleLookupHead lookup) async {
    final asked = _witnessOf(config);
    final at = now();
    final got = await _witnessRecord(asked, lookup.pub);
    if (got == null) {
      await _holdKept(asked, lookup.head);
      await _witnessUnanswered(asked);
      return _Unwitnessed(lookup.head, asked, at);
    }
    final rec = got.record;
    final verdict =
        (await _witnessVerdict(lookup.head, rec.head, lookup.pub)).verdict;
    final pending = (await _holdKept(asked, lookup.head,
            witnessed: rec.head, verdict: verdict))
        .pending;
    switch (verdict) {
      case _WitnessVerdict.forked:
        await _witnessForked(asked);
        throw const HandleException(HandleFailure.forked);
      case _WitnessVerdict.unproven:
        await _witnessUnanswered(asked);
        throw const HandleException(HandleFailure.unreachable);
      case _WitnessVerdict.unreadable:
        await _witnessUnanswered(asked);
        throw const HandleException(HandleFailure.badAnswer);
      case _WitnessVerdict.consistent:
        // `ts` is inside what the log signed and the witness co-signed;
        // `verifiedAt` is not, so it cannot say how old the record is.
        if (pending) {
          if (got.fresh) await _witnessUnanswered(asked);
        } else if (now() - rec.head.ts <= witnessStale.inMilliseconds) {
          await _witnessAgreed(asked);
        } else {
          await _witnessUnanswered(asked);
        }
    }
    return lookup.head.size > rec.head.size
        ? _Unwitnessed(lookup.head, asked, at)
        : null;
  }

  /// The witness's record, its two signatures verified in the handle log's
  /// contexts against the log's key and the witness key this device pinned —
  /// never the key the record carries — fetched from the address exactly as
  /// configured, at most once for this lookup, and `fresh` when it was. A
  /// record that verified within [witnessReuse], under the same
  /// configuration, is used again instead — unless [fresh] is asked for, as a
  /// kept head's check of its own asks ([_checkBack]): a record fetched
  /// before the head was kept cannot cover it. Null when it cannot be fetched
  /// or does not verify, which is not kept.
  Future<({KtWitnessRecord record, bool fresh})?> _witnessRecord(
      String asked, Uint8List logPub,
      {bool fresh = false}) async {
    final t = now();
    final held = _witnessHeld;
    if (!fresh &&
        held != null &&
        held.w == asked &&
        t >= held.at &&
        t - held.at < witnessReuse.inMilliseconds) {
      return (record: held.record, fresh: false);
    }
    final pinned = config.witnessPub;
    if (pinned == null) return null;
    final KtWitnessRecord rec;
    try {
      final r = await fetcher.get(Uri.parse(config.witnessUrl.trim()));
      if (r.status != 200) return null;
      rec = KtWitnessRecord.fromJson(r.json);
    } catch (_) {
      return null;
    }
    if (!await ktVerifyWitnessRecord(rec,
        logPub: logPub, expectedWitnessPub: pinned, mode: KtLogMode.handles)) {
      return null;
    }
    if (_witnessOf(config) == asked) {
      _witnessHeld = (w: asked, at: t, record: rec);
    }
    return (record: rec, fresh: true);
  }

  /// [witnessed] — the head of a record that verified — against [held], the
  /// head a lookup ends with: equal roots at equal size; otherwise the log's
  /// consistency proof between the two sizes, from the smaller to the larger.
  /// No proof is [_WitnessVerdict.unproven], whichever is ahead — except
  /// that with the witness ahead the log's own head is asked first, and one
  /// smaller than the witness's is a log gone back below a head it signed
  /// and the witness verified, a fork. (The transparency client takes no
  /// proof as no verdict, and asks again at its next check, on the head it
  /// keeps; a resolver keeps a head only once a request is sent on its
  /// lookup, which this one has not reached.) And whether the log answered
  /// what it was asked — a refusal is an answer, no answer at all is not
  /// ([_checkBack]).
  Future<({_WitnessVerdict verdict, bool answered})> _witnessVerdict(
      KtTreeHead held, KtTreeHead witnessed, Uint8List logPub) async {
    if (witnessed.size == held.size) {
      return (
        verdict: witnessed.sameRootsAs(held)
            ? _WitnessVerdict.consistent
            : _WitnessVerdict.forked,
        answered: true,
      );
    }
    final behind = witnessed.size < held.size;
    final first = behind ? witnessed : held;
    final second = behind ? held : witnessed;
    final c = await _askLog('$_base/kt/v1/consistency'
        '?first=${first.size}&second=${second.size}');
    final cj = c.json;
    if (cj != null) {
      final List<Uint8List> proof;
      try {
        proof = [for (final h in (cj['proof'] as List)) unb64(h as String)];
      } catch (_) {
        return (verdict: _WitnessVerdict.unreadable, answered: true);
      }
      return (
        verdict: await ktVerifyConsistency(
                first: first.size,
                second: second.size,
                firstRoot: first.logRoot,
                secondRoot: second.logRoot,
                proof: proof)
            ? _WitnessVerdict.consistent
            : _WitnessVerdict.forked,
        answered: true,
      );
    }
    var answered = c.answered;
    if (!behind) {
      final s = await _askLog('$_base/kt/v1/sth');
      answered = answered && s.answered;
      final j = s.json;
      if (j != null) {
        try {
          final current = KtTreeHead.fromJson(j);
          if (await ktVerifyHead(current, logPub, KtLogMode.handles) &&
              current.size < witnessed.size) {
            return (verdict: _WitnessVerdict.forked, answered: true);
          }
        } catch (_) {}
      }
    }
    return (verdict: _WitnessVerdict.unproven, answered: answered);
  }

  /// One bucket, verified under the pinned key on a fresh head, with that
  /// head; null when the log refuses it as too large. The head is the
  /// caller's to accept ([_accept]) — buckets asked side by side come back
  /// in any order.
  Future<_HandleBucketAnswer?> _bucket(
      _HandleLookupHead lookup, KtBucketQuery q) async {
    final KtResponse r;
    try {
      r = await fetcher.get(Uri.parse('$_base${q.path}'));
    } catch (_) {
      throw const HandleException(HandleFailure.unreachable);
    }
    if (r.status == 400 && _errorCode(r) == 'bucket_too_large') return null;
    if (r.status != 200) throw const HandleException(HandleFailure.unreachable);
    final Map<String, Object?> json;
    try {
      json = r.json;
    } catch (_) {
      throw const HandleException(HandleFailure.badAnswer);
    }
    final KtVerifiedBuckets v;
    try {
      v = await ktVerifyBucketAnswer(json,
          asked: [q], logPub: lookup.pub, mode: KtLogMode.handles);
    } on KtVerifyException {
      throw const HandleException(HandleFailure.badAnswer);
    } on FormatException {
      throw const HandleException(HandleFailure.badAnswer);
    }
    _requireFresh(v.head);
    return _HandleBucketAnswer(v.buckets.single, v.head);
  }

  /// A first estimate of k from buckets drawn at random — so they say
  /// nothing about any lookup, before or after — as the transparency client
  /// makes its first count (`_probeCeiling`): one at the finest k the signed
  /// size allows ([bySize]), then coarser by as much as it fell short of
  /// [handleProbeLabels] labels ([handleProbeNext]), until one holds that
  /// many or k is 0. A bucket counts only under the head held when it was
  /// drawn: one signed after could hold labels minted into it on seeing it
  /// asked, so under a head that grew (or says it did) the bucket is not
  /// counted and another is drawn. A bucket refused as too large is asked
  /// one bit finer, with a fresh random bucket — a refusal is never an
  /// estimate, so refusing cannot raise k, only deny it. At most
  /// [handleProbeSteps] buckets; a log that has not shown a count by then is
  /// unreachable.
  Future<int> _probeBits(_HandleLookupHead lookup, int bySize) async {
    var k = bySize;
    for (var step = 0; step < handleProbeSteps; step++) {
      final held = lookup.head;
      final q = KtBucketQuery.forLabel(_randomBytes32(), k);
      debugOnProbe?.call(q);
      final a = await _bucket(lookup, q);
      if (a == null) {
        if (k >= ktMaxBucketBits) break;
        k++;
        continue;
      }
      await _accept(lookup, a.head);
      if (!a.head.sameRootsAs(held)) continue;
      final count = a.bucket.leaves.length;
      final next = handleProbeNext(k, count);
      if (next == null) return min(bySize, handleBitsFor(count * (1 << k)));
      k = next;
    }
    throw const HandleException(HandleFailure.unreachable);
  }

  /// [leaf]'s record held to everything a reader can check without its
  /// history: its one encoding (§21.4), its kind against its version — a
  /// claim is version 1 and nothing else is (rules 1, 2 and 5) — the owner's
  /// signature over this entry — the owner the record names is the one that
  /// signs, for a claim, an update (which keeps the owner) and a recover
  /// (which names the new one) alike — and, on a recover, the recovery
  /// key's. Null when any fails.
  Future<HandleRecord?> _checkedRecord(Uint8List label, KtBucketLeaf leaf) async {
    final value = leaf.value, sig = leaf.sig;
    if (value == null || sig == null || leaf.version < 1) return null;
    final HandleRecord rec;
    try {
      rec = HandleRecord.decode(value);
    } on FormatException {
      return null;
    }
    if ((rec.kind == HandleRecordKind.claim) != (leaf.version == 1)) {
      return null;
    }
    final input = await handlePublishInput(
        label: label, version: leaf.version, value: value);
    if (!await _verifyEd(rec.owner, input, sig)) return null;
    if (rec.kind == HandleRecordKind.recover) {
      final rInput = handleRecoverInput(
          label: label, version: leaf.version, owner: rec.owner, rc: rec.rc);
      if (!await _verifyEd(rec.rpub!, rInput, rec.rsig!)) return null;
    }
    return rec;
  }

  Future<(int, String?)> _publish(HandleEntry e) async {
    if (!available) throw const HandleException(HandleFailure.unavailable);
    final KtResponse r;
    try {
      r = await fetcher.post(
          Uri.parse('$_base/kt/v1/publish'), jsonEncode(e.toPublishJson()));
    } catch (_) {
      throw const HandleException(HandleFailure.unreachable);
    }
    return (r.status, r.status == 201 ? null : _errorCode(r));
  }

  Future<Map<String, Object?>> _getJson(String url) async {
    final KtResponse r;
    try {
      r = await fetcher.get(Uri.parse(url));
    } catch (_) {
      throw const HandleException(HandleFailure.unreachable);
    }
    if (r.status != 200) throw const HandleException(HandleFailure.unreachable);
    try {
      return r.json;
    } catch (_) {
      throw const HandleException(HandleFailure.badAnswer);
    }
  }

  /// One of the witness check's questions to the log, whose silence the
  /// check judges itself — a proof not served is no proof, and a head not
  /// served leaves it at that — with whether it was answered at all: any
  /// status is an answer, a refusal or a withholding among them, and a
  /// request that reached nobody is not ([_checkBack]). The body when it was
  /// a `200` that parsed.
  Future<({bool answered, Map<String, Object?>? json})> _askLog(
      String url) async {
    final KtResponse r;
    try {
      r = await fetcher.get(Uri.parse(url));
    } catch (_) {
      return (answered: false, json: null);
    }
    if (r.status != 200) return (answered: true, json: null);
    try {
      return (answered: true, json: r.json);
    } catch (_) {
      return (answered: true, json: null);
    }
  }

  static String? _errorCode(KtResponse r) {
    try {
      final e = r.json['error'];
      return e is String ? e : null;
    } catch (_) {
      return null;
    }
  }

  /// §21.4's one signature rule — the log's and the library's — rather than
  /// `Ed25519().verify`, which compares points by x alone and so takes
  /// signatures the log refuses (`ed25519_strict.dart`).
  static Future<bool> _verifyEd(Uint8List pub, Uint8List data, Uint8List sig) =>
      verifyHandleSignature(pub, data, sig);

  Future<HandleRecord> _record(OwnHandle o, HandleRecordKind kind) async {
    final intro = await handleIntroIdentity(o.introSeed);
    final owner = await handleKeyPublic(o.ownerSeed);
    return kind == HandleRecordKind.claim
        ? HandleRecord.claim(
            owner: owner,
            intro: intro.edPub,
            xintro: intro.xPub,
            pow: o.pow,
            rc: o.rc)
        : HandleRecord.update(
            owner: owner,
            intro: intro.edPub,
            xintro: intro.xPub,
            pow: o.pow,
            rc: o.rc);
  }

  // ---------------------------------------------------------------------------
  // Persistence
  // ---------------------------------------------------------------------------

  static Future<void> _deriveIntro(OwnHandle o) async {
    o.introRid = await introRoutingId(await handleKeyPublic(o.introSeed));
  }

  Future<void> _saveOwn() async {
    final o = own;
    if (o == null) {
      await vault.kvDelete('handle');
    } else {
      await vault.kvPut('handle', jsonEncode(o.toJson()));
    }
  }

  Future<void> _saveInbound() => vault.kvPut(
      'handle_in',
      jsonEncode({
        'reqs': {for (final e in _inbound.entries) e.key: e.value.toJson()},
        'seeds': {for (final e in _oldSeeds.entries) e.key: b64(e.value)},
      }));

  Future<void> _saveOutgoing() async {
    await vault.kvPut(
        'handle_out', jsonEncode([for (final o in _outgoing) o.toJson()]));
    await _settleWitness(); // what relied on a request goes with it (§21.8)
  }

  /// Remember a request decided now, whose stamp was made for [day]: the
  /// ledger's record first, once, so its salt is in the vault before any
  /// digest made with it; then the one row the digest went into. A day that
  /// holds all it can ([handleStampDayCap]) remembers nothing more, and the
  /// request is counted as filed unremembered instead.
  Future<void> _rememberDecided(int day, int digest) async {
    if (!_ledgerWritten) await _saveLedgerRecord();
    final row = _ledger.add(day, digest);
    if (row == null) {
      if (_ledger.isFull(day)) {
        _ledger.tally(day).unremembered++;
        _tallyDirty = true;
      }
      return;
    }
    await vault.kvPut(row.key, b64(row.bytes));
  }

  /// The ledger's record: the salt and the tallies.
  Future<void> _saveLedgerRecord() async {
    await vault.kvPut('handle_stamps', jsonEncode(_ledger.toJson()));
    _ledgerWritten = true;
    _tallyDirty = false;
  }

  /// After a drain: the days that lapsed go with their rows, and the
  /// tallies are written if they moved — once a drain, not once an envelope.
  Future<void> _settleLedger() async {
    final gone = _ledger.prune(now());
    for (final e in gone.entries) {
      for (var i = 0; i < e.value; i++) {
        await vault.kvDelete('$handleStampRowPrefix${e.key}_$i');
      }
    }
    if (_tallyDirty || gone.isNotEmpty) await _saveLedgerRecord();
  }

  /// Management steps one at a time: a publish timer firing during a pause,
  /// say, must not interleave with it.
  Future<T> _serial<T>(Future<T> Function() op) {
    final run = _ops.then((_) => op());
    _ops = run.then((_) {}, onError: (_) {});
    return run;
  }
}

/// What one lookup holds of the log while it runs ([HandleService._head]):
/// the pinned key, the head accepted so far, and the `bucketBits` served
/// beside the first.
class _HandleLookupHead {
  final Uint8List pub;
  KtTreeHead head;
  final int? recommended;
  _HandleLookupHead(this.pub, this.head, this.recommended);
}

/// A bucket answer, verified, with the head it was served under.
class _HandleBucketAnswer {
  final KtVerifiedBucket bucket;
  final KtTreeHead head;
  _HandleBucketAnswer(this.bucket, this.head);
}

// =============================================================================
// Backup (archive format 1.1, a record older builds keep)
// =============================================================================

/// The handle's state in a backup archive: one record of type `handle`,
/// marked `"keep":1` (patch 53), so a build that predates handles carries it
/// into its own next archive unread rather than dropping it — and the keys
/// come back when the archive reaches a build that knows them.
abstract final class HandleBackup {
  static const String recordType = 'handle';

  static const List<String> _keys = [
    'handle',
    'handle_in',
    'handle_out',
    'handle_config',
    // The resolver's memory: carried so that a restored device asks the
    // buckets the old one asked for a handle (its decoy key — two sets would
    // intersect in the handle's bucket), and holds what it found to what the
    // old one remembered (a first lookup again for every handle is a first
    // lookup the log can answer with anything).
    handleLookupKey,
    // After the fact (§21.8): the heads kept for the witness to cover, so a
    // restored device goes on checking the requests the archive brings back,
    // and the forks found after the fact, so a contact that came through one
    // comes back with its warning.
    HandleService._keptKey,
    HandleService._warningsKey,
  ];

  /// The record, or null when this vault holds nothing about handles.
  static Future<Map<String, Object?>?> export(Vault vault) async {
    final kv = <String, Object?>{};
    for (final k in _keys) {
      final v = await vault.kvGet(k);
      if (v == null) continue;
      try {
        kv[k] = jsonDecode(v);
      } on FormatException {
        continue;
      }
    }
    if (kv.isEmpty) return null;
    return {'t': recordType, ZArchive.keepField: 1, 'v': 1, 'kv': kv};
  }

  /// The `kv` rows a restore writes for [record], each held to the shape the
  /// service reads — an archive is a file that can come from anywhere — and
  /// [pendingRids], the requests the archive restored. A claim that was still
  /// waiting to be published comes back [HandlePhase.held]: a restore
  /// publishes nothing by itself (it may have been published since, from the
  /// device the backup was taken on, or overtaken there).
  static Map<String, String> restore(
      Map<String, Object?> record, Set<String> pendingRids) {
    final out = <String, String>{};
    final kv = record['kv'];
    if (kv is! Map) return out;
    final own = kv['handle'];
    if (own is Map) {
      try {
        final o = OwnHandle.fromJson(own.cast<String, Object?>());
        if (o.phase == HandlePhase.pending) {
          o.phase = HandlePhase.held;
          o.publishAt = null;
        }
        out['handle'] = jsonEncode(o.toJson());
      } catch (_) {}
    }
    final inbound = kv['handle_in'];
    if (inbound is Map) {
      final reqs = <String, Object?>{};
      final seeds = <String, Object?>{};
      final r = inbound['reqs'];
      if (r is Map) {
        for (final e in r.entries) {
          if (e.key is! String || !pendingRids.contains(e.key)) continue;
          try {
            final m = HandleRequestMeta.fromJson(
                (e.value as Map).cast<String, Object?>());
            reqs[e.key as String] = m.toJson();
          } catch (_) {}
        }
      }
      final s = inbound['seeds'];
      if (s is Map) {
        for (final e in s.entries) {
          try {
            if (e.key is String && unb64(e.value as String).length == 32) {
              seeds[e.key as String] = e.value;
            }
          } catch (_) {}
        }
      }
      if (reqs.length > handleInboundCap) {
        // More than this build ever holds: the ones it would have kept.
        final metas = {
          for (final e in reqs.entries)
            e.key: HandleRequestMeta.fromJson(
                (e.value as Map).cast<String, Object?>())
        };
        for (final rid in handleRequestsToEvict(metas)) {
          reqs.remove(rid);
        }
      }
      out['handle_in'] = jsonEncode({'reqs': reqs, 'seeds': seeds});
    }
    final outgoing = kv['handle_out'];
    final waiting = <String>{};
    if (outgoing is List) {
      final kept = <Object?>[];
      for (final j in outgoing) {
        try {
          kept.add(OutgoingHandleRequest.fromJson(
                  (j as Map).cast<String, Object?>())
              .toJson());
        } catch (_) {}
      }
      if (kept.length > handleOutgoingCap) {
        kept.removeRange(0, kept.length - handleOutgoingCap);
      }
      out['handle_out'] = jsonEncode(kept);
      for (final o in kept) {
        waiting.addAll(((o as Map)['ids'] as List).cast<String>());
      }
    }
    // After the fact: a kept head or a warning is restored when the request
    // it is on was, or it is on a contact — and the first start forgets one
    // whose contact did not come back ([HandleService.keepWarningsFor]).
    bool relied(List<Uint8List> ids, String? rid) =>
        rid != null || ids.any((i) => waiting.contains(b64(i)));
    final heads = kv[HandleService._keptKey];
    if (heads is Map && heads['w'] is String && heads['heads'] is List) {
      final kept = <_KeptHead>[];
      for (final j in heads['heads'] as List) {
        try {
          final k = _KeptHead.fromJson((j as Map).cast<String, Object?>());
          if (relied(k.creqIds, k.rid)) kept.add(k);
        } catch (_) {}
      }
      // Those of the requests restored, which bound them; and of those on
      // contacts, no more than the service keeps.
      kept.sort((a, b) => a.at.compareTo(b.at));
      final held = [for (final k in kept) if (k.rid != null) k];
      if (held.length > handleWitnessKeptCap) {
        final out = held.take(held.length - handleWitnessKeptCap).toSet();
        kept.removeWhere(out.contains);
      }
      if (kept.isNotEmpty) {
        out[HandleService._keptKey] = jsonEncode({
          'w': heads['w'],
          'heads': [for (final k in kept) k.toJson()],
        });
      }
    }
    final warnings = kv[HandleService._warningsKey];
    if (warnings is List) {
      // One a contact — a fork before an answer never confirmed, the latest
      // found — and those on requests: no more than the service shows.
      final byContact = <String, HandleForkWarning>{};
      final onRequests = <HandleForkWarning>[];
      for (final j in warnings) {
        try {
          final w = HandleForkWarning.fromJson((j as Map).cast<String, Object?>());
          if (!relied(w.creqIds, w.rid)) continue;
          final rid = w.rid;
          final had = rid == null ? null : byContact[rid];
          if (rid == null) {
            onRequests.add(w);
          } else if (had == null ||
              (w.isFork && !had.isFork) ||
              (w.isFork == had.isFork && had.foundMs < w.foundMs)) {
            byContact[rid] = w;
          }
        } catch (_) {}
      }
      final restored = [...onRequests, ...byContact.values]
        ..sort((a, b) => a.foundMs.compareTo(b.foundMs));
      if (restored.isNotEmpty) {
        out[HandleService._warningsKey] =
            jsonEncode([for (final w in restored) w.toJson()]);
      }
    }
    final config = kv['handle_config'];
    if (config is Map) {
      try {
        out['handle_config'] = jsonEncode(
            HandleConfig.fromJson(config.cast<String, Object?>()).toJson());
      } catch (_) {}
    }
    final lookups = kv[handleLookupKey];
    if (lookups is Map) {
      final m = HandleLookupMemory.parse(jsonEncode(lookups));
      if (m != null) out[handleLookupKey] = jsonEncode(m.toJson());
    }
    return out;
  }
}
