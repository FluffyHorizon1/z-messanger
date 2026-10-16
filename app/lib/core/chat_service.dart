import 'dart:async';
import 'dart:convert';
import 'dart:io' show FileSystemException;
import 'dart:math';

import 'package:flutter/foundation.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:z_protocol/z_protocol.dart';

import 'alarm_evidence.dart';
import 'archive.dart' show BackupArchive;
import 'backup_store.dart';
import 'device_sync.dart';
import 'enrollment.dart' show enrollmentKvFamilies, isRootBundle, rootBundleKey;
import 'handles.dart';
import 'key_transparency.dart';
import 'models.dart';
import 'picked_file.dart' show pickerCacheDir, sweepPickerCopies;
import 'receipts.dart';
import 'system_messages.dart';
import 'relay_url.dart';
import 'transport.dart';
import 'vault.dart';

const int maxAttachmentBytes = 24 * 1024 * 1024; // fits relay RAM queue caps

/// 7.5b: how often a conversation rotates its post-quantum (ML-KEM) secret, for
/// post-compromise security of the PQ layer. Seven days balances protection
/// against the extra ~1.2 KB ciphertext a rotation puts on one message. The
/// offering side re-offers on the next message sent after this elapses.
const int pqRekeyIntervalMs = 7 * 24 * 3600 * 1000;

/// How long an unanswered initial ML-KEM offer waits before it is repeated
/// (PROTOCOL §17.4, R27). Six hours: long enough that a peer who is simply
/// offline is not chased, short enough that a conversation does not spend
/// days classical because one envelope was never delivered. The retry rides
/// the next message sent, like the re-key offer, so a silent conversation
/// costs nothing.
const int pqOfferRetryMs = 6 * 3600 * 1000;

/// What a group invite link's inviter can expect once its person has gone
/// ahead with whoever answered the link (ADR 0020,
/// [ChatService.expectLinkJoin]).
enum LinkJoinOutcome {
  /// Their client was told the invite is to a group; they join it when their
  /// own person goes ahead too.
  waiting,

  /// Their client predates group links and could not have told them: they
  /// are a contact only, and the group says so.
  tooOld,

  /// The link's 24 hours were over: a contact only, and the group says so.
  expired,

  /// This device may no longer add members to the group (demoted, or out of
  /// it): a contact only, and the group says so.
  refused,
}

/// What stopping a wait for a group link's answer did (ADR 0020).
enum LinkWaitStop {
  /// Stopped: the answer, come or to come, adds nobody, and the group says
  /// so.
  stopped,

  /// Too late: the answer had come and the add itself had begun.
  adding,

  /// Nothing to stop: the wait had already ended.
  gone,
}

/// The orchestrator: owns contacts, protocol conversations, the message
/// store, the outbox, attachments, receipts and disappearing messages.
///
/// Invariants it maintains:
///   1. Ratchet state is persisted (encrypted) BEFORE any ciphertext leaves
///      the device and BEFORE any received plaintext is acted upon.
///   2. The relay ack for an inbound envelope is sent only AFTER the message
///      is safely inside the local encrypted vault.
///   3. Plaintext never touches disk: message bodies, names, metadata and
///      attachment bytes are sealed before insert/write.
class ChatService extends ChangeNotifier implements KtHost, HandleHost {
  final Vault vault;
  @override
  final ZIdentity identity;
  @override
  final String myRid;
  @override
  String displayName;
  final Transport transport;

  /// Hidden Developer-mode toggle — reveals the custom-relay option in Settings.
  /// Persisted in the vault; off by default so normal users never see it.
  bool devMode = false;

  /// The transparency log's client (PROTOCOL.md §19, ADR 0006). Inert until a
  /// log is configured; then it checks every contact's device list against
  /// the log, publishes this account's, and holds what the log has not
  /// confirmed. This service is its host: it hands over contacts and the own
  /// list, installs lists the log serves, and consults it before fanning out.
  late final KeyTransparency kt;

  /// Handles (phase 38, ADR 0015 revision 2, PROTOCOL §21): this account's
  /// handle, its introduction mailbox, and finding other people by theirs.
  /// Inert until a handle log is configured. This service is its host: it
  /// files the requests that come through the handle beside every other
  /// request, and sends what the handle service stamps.
  HandleService get handles => _handles!;
  HandleService? _handles;

  /// Inner kinds a transparency conflict holds (ADR 0006): what a person
  /// says, not what the protocol says on their behalf — receipts, hellos,
  /// key offers and device lists still flow, so the conflict can resolve.
  static const Set<String> _ktHeldKinds = {
    'text', 'file', 'timer', 'react', 'edit', 'del',
    'gmsg', 'gfile', 'ginvite', 'gleave', 'greact', 'gedit', 'gdel',
  };

  /// 7.5b: the post-quantum re-key interval applied to conversations. Defaults
  /// to [pqRekeyIntervalMs]; tests set a short value. Changing it re-applies to
  /// every open conversation — on every channel: a contact's main device, a
  /// contact's other devices, and my own (26.2; PROTOCOL §17.8).
  int get pqRekeyInterval => _pqRekeyInterval;
  int _pqRekeyInterval = pqRekeyIntervalMs;

  set pqRekeyInterval(int ms) {
    _pqRekeyInterval = ms;
    _applyPqIntervals();
  }

  /// As [pqRekeyInterval], for the retry of an offer nobody answered
  /// (PROTOCOL §17.4, §17.7). Tests set a short value.
  int get pqOfferRetry => _pqOfferRetry;
  int _pqOfferRetry = pqOfferRetryMs;
  set pqOfferRetry(int ms) {
    _pqOfferRetry = ms;
    _applyPqIntervals();
  }

  /// Both clocks, as every conversation this service builds is built with
  /// them — required by the protocol library, so no channel can be built
  /// without them again. Each channel to a linked device, and every
  /// conversation a rollback rebuilt from a snapshot, used to run on none.
  PqIntervals get _pqIntervals =>
      PqIntervals(rekeyMs: _pqRekeyInterval, offerRetryMs: _pqOfferRetry);

  void _applyPqIntervals() {
    final i = _pqIntervals;
    for (final c in _convs.values) {
      c.pqIntervals = i;
    }
    for (final s in _contactExtras.values) {
      s.pqIntervals = i;
    }
    _sync?.applyPqIntervals();
  }

  final Map<String, Contact> contacts = {};
  final Map<String, Group> groups = {};
  final Map<String, Conversation> _convs = {};
  final Map<String, List<ChatMessage>> messagesByChat = {};
  final Map<String, int> unread = {};
  String? openChatRid;

  Timer? _sweeper;

  /// The disappearing-message sweep while one runs — the timer's or a
  /// test's ([debugSweep]) — so a tick never starts a second beside it and
  /// [wipeEverything] can wait for it before the vault goes.
  Future<void>? _sweeping;
  bool _flushing = false;

  /// A mailbox the relay reported full (`queue_full`), or a relay whose
  /// store is full (`store_full`), PROTOCOL §12.4, is tried again after this
  /// long; the rows wait in the outbox meanwhile. Overridable so a test need
  /// not wait a minute.
  Duration outboxRetryDelay = const Duration(seconds: 60);
  Timer? _outboxRetry;

  /// A refusal the relay could not attribute to one envelope — `internal`
  /// (the store unreachable), a send timeout, or any other code that is not
  /// one of the four the outbox treats specially — stops the pass with rows
  /// still queued. It used to return and wait for the next reconnect, so an
  /// `internal` from an otherwise-healthy link left the outbox stopped until
  /// the user sent again or the socket dropped. Now the pass comes back on
  /// its own timer while the link stays up, backing off from [_otherRetryMin]
  /// to [outboxRetryDelay] and resetting the moment anything sends.
  static const Duration _otherRetryMin = Duration(seconds: 1);
  Duration _otherRetryBackoff = _otherRetryMin;

  /// Self-sync across my own linked devices. Null until built; inert when I
  /// have no linked devices, so single-device behaviour is unchanged.
  DeviceSyncService? _sync;

  /// M4: per-device sessions with a CONTACT's non-primary devices, plus a map
  /// from those devices' routing ids back to the contact. Both empty for a
  /// single-device contact, so the primary messaging path is unchanged.
  final Map<String, AccountSession> _contactExtras = {};
  final Map<String, String> _extraRidToContact = {};

  // ---- 7.7a device-list transparency (gossip) ----------------------------
  //
  // Every inner message carries the sender's claim about its own device list
  // ('dl') and an echo of the recipient's ('pdl'). Cross-checking these — with
  // no new infrastructure, inside the existing E2E channel — makes silent
  // device enrolment, split views and silent removal detectable. See
  // docs/adr/0001-key-transparency.md and PROTOCOL.md §3.6.

  /// Grace before a "list changed but never confirmed" observation becomes an
  /// alert: a version bump seen from a contact before the owner's broadcast
  /// arrives is normal for a moment and must not cry wolf. Tests shorten it.
  Duration devlistGrace = const Duration(seconds: 8);

  /// Per-contact banner: their devices disagree, or a list we were handed is
  /// not confirmed by their devices. rid → message. Empty when all clear.
  final Map<String, String> contactDevlistAlerts = {};

  /// Loud alert to the owner: a contact was given a device list for MY account
  /// that this device never issued, or the account's own list went backwards
  /// (T1/T2). Null when clear. Holds the STORED form — an `OwnAlertKind` and
  /// its versions (`ownAlertBody`), not a sentence; `home_screen.dart` renders
  /// it in the reader's language through `account_alert_text.dart` (finding
  /// 38). A value an older build wrote is the English sentence and is shown as
  /// it is.
  String? ownAccountAlert;

  /// This device was removed from its own account's device list (T3), as a
  /// list signed by the account's key shows — carried in a contact's notice,
  /// or served by the log (ADR 0026). Null when clear. The stored form, as
  /// above.
  String? removedDeviceAlert;

  /// Latest claim each of a contact's devices has made about that account's
  /// list: contactRid → deviceRid → (version, fingerprint-b64, max-version-seen).
  final Map<String, Map<String, ({int v, String h, int mx})>> _contactClaims =
      {};

  /// Deferred checks awaiting the grace period. contactRid → first-seen time of
  /// an unconfirmed situation (held newer than any device admits, or a device
  /// claims newer than we hold and the broadcast hasn't arrived).
  final Map<String, DateTime> _pendingContact = {};

  /// Deferred owner-echo checks. source contactRid → (echoed version, fp, seen).
  final Map<String, ({int v, String h, DateTime seen})> _pendingOwnerEcho = {};

  /// The (version, fingerprint) of the list that raised [ownAccountAlert] as
  /// "unissued", kept so a later honest list from my root can clear the
  /// alert if it explains it.
  (int, String)? _ownAlertEcho;

  // ---- ADR 0026: an owner alarm is raised on evidence ---------------------
  //
  // An echo ('pdl') is a contact's CLAIM about the list it holds for my
  // account; anybody can type one. The evidence is the list itself, signed
  // by my account's key, and a contact on a current build hands it over when
  // asked ('pdlreq'). The removal notice ('dlrm') is the same: a notice is a
  // claim, the list that dropped this device is the evidence — carried in the
  // notice, or read from the log.

  /// Verified evidence behind a contact's echo that this device cannot
  /// explain: a list for my account, signed by its key, that this device
  /// never issued or learned. contactRid → (version, fingerprint, since).
  /// The "unissued" alarm is raised on this after the grace, never on an echo.
  final Map<String, ({int v, String fp, DateTime since})> _ownEvidence = {};

  /// When this device last asked each contact for the list behind its echo,
  /// and what about: contactRid → (window start, echoes asked about). At
  /// most [_maxOwnListAsks] questions per contact per [ownEvidenceWindow],
  /// and never the same echo twice in one, so a contact who echoes nonsense
  /// with every message buys a handful of questions, not one per message.
  final Map<String, ({int atMs, Set<(int, String)> asked})> _ownListAsked =
      {};

  /// How long a question about an echo stays open, and the window the
  /// per-contact limits are counted over. Tests shorten it.
  Duration ownEvidenceWindow = const Duration(minutes: 10);
  static const int _maxOwnListAsks = 3;

  /// The answering side: contactRid → (window start, answers given). The
  /// answer goes to the asker's whole account, so it is counted per account,
  /// whichever of its devices asks: more than [_maxOwnListAsks] in a window
  /// is asking for nothing new — and counted per device, a contact with many
  /// devices could have each of them ask, for an answer that goes to all.
  final Map<String, ({int atMs, int n})> _ownListAnswered = {};

  /// Lists a contact handed over for my account (asked for, or carried in a
  /// removal notice) that this device verified, per contact per window —
  /// each is a signature check, and a contact does not get to buy those in
  /// bulk.
  final Map<String, ({int atMs, int n})> _ownListJudged = {};
  static const int _maxOwnListJudged = 8;

  /// The quiet diagnostic (ADR 0026): per contact, how many echoes, removal
  /// notices and handed-over lists turned out to have nothing this account
  /// signed behind them. Counted here, shown nowhere: they are not evidence
  /// of anything, and an alarm on them is what a contact could raise at will.
  final Map<String, int> ownEvidenceRefused = {};

  /// The evidence ([unissuedEvidence], [olderListEvidence]) that
  /// [ownAccountAlert] stands on, and ([removalEvidence]) that
  /// [removedDeviceAlert] does: what a dismissal records. A list, because one
  /// banner can stand on more than one piece — evidence that arrives while it
  /// is up joins it rather than waiting, as an echo always did.
  final List<String> _ownAlertEvidence = [];
  final List<String> _removedAlertEvidence = [];

  /// When a bare removal notice last moved this device's own log check
  /// forward: once per [ownEvidenceWindow] at most.
  int _ownCheckNudgedMs = 0;

  Timer? _devlistTimer;

  /// Sealed sender: routing id → X25519 public key of every device we send
  /// to (contacts, their extra devices, my own linked devices). Every outbound
  /// envelope is sealed to its recipient so the relay never learns who sent
  /// it; a rid we hold no key for falls back to a legacy attributed send.
  final Map<String, Uint8List> _sealKeys = {};

  Future<String> _sealFor(String rid, String payload) async {
    final key = _sealKeys[rid];
    if (key == null) return payload;
    return SealedEnvelope.seal(toXPub: key, fromRid: myRid, payload: payload);
  }

  /// Per‑conversation async mutex. Ratchet state is a read‑modify‑write on
  /// shared in‑memory state that is NOT protected by the DB transaction, so
  /// every encrypt/decrypt+persist for a given contact must be serialized.
  final Map<String, Future<void>> _locks = {};

  Future<T> _withLock<T>(String rid, Future<T> Function() op) async {
    final prev = _locks[rid] ?? Future<void>.value();
    final done = Completer<void>();
    _locks[rid] = done.future;
    // Wait for the previous holder (ignore its errors — they belong to it).
    await prev.catchError((_) {});
    try {
      return await op();
    } finally {
      done.complete();
      if (identical(_locks[rid], done.future)) _locks.remove(rid);
    }
  }

  /// Test seam: run just before a send commits, INSIDE the per-contact lock.
  ///
  /// It exists so a test can put a send exactly where a loaded machine puts
  /// it — sealed, holding the lock, not yet committed — instead of waiting
  /// for the scheduler to do it by luck. See `contact_erasure_test.dart` 4.
  @visibleForTesting
  Future<void> Function(String rid)? debugBeforeSendCommit;

  /// Test seam: shown every envelope as it would decrypt — [path] is
  /// `primary` (a contact's main device), `extra` (one of a contact's other
  /// devices) or `sync` (one of my own) — on a COPY of the ratchet, before
  /// anything acts on it. Returning true discards the envelope as though the
  /// relay had never delivered it: the ratchet is left exactly as it was and
  /// the envelope is acknowledged. A test cannot pick one envelope out by
  /// kind from the sealed bytes on the wire, and withholding exactly one is
  /// what a relay can always do (R27). Null in production, where nothing is
  /// decrypted twice.
  @visibleForTesting
  bool Function(String path, String fromRid, DecryptResult dec)?
      get debugOnDecrypted => _debugOnDecrypted;
  @visibleForTesting
  set debugOnDecrypted(
      bool Function(String path, String fromRid, DecryptResult dec)? f) {
    _debugOnDecrypted = f;
    _wireSyncProbe();
  }

  bool Function(String path, String fromRid, DecryptResult dec)?
      _debugOnDecrypted;

  void _wireSyncProbe() {
    final f = _debugOnDecrypted;
    _sync?.debugOnDecrypted =
        f == null ? null : (from, dec) => f('sync', from, dec);
  }

  /// Runs [probe] over what [decryptCopy] — a decrypt on a copy of the
  /// ratchet — yields. False when the copy does not decrypt: the real
  /// attempt that follows reports that, as it always has.
  Future<bool> _debugPeek(
      bool Function(String path, String fromRid, DecryptResult dec) probe,
      String path,
      String fromRid,
      Future<DecryptResult> Function() decryptCopy) async {
    try {
      return probe(path, fromRid, await decryptCopy());
    } catch (_) {
      return false;
    }
  }

  ChatService._({
    required this.vault,
    required this.identity,
    required this.myRid,
    required this.displayName,
    required this.transport,
  });

  static Future<ChatService> init({
    required Vault vault,
    required ZIdentity identity,
    required String displayName,
    required Transport transport,
    KtFetcher? ktFetcher,
    KtConfig ktConfig = KtConfig.defaults,
    int Function()? ktNow,
    // Phase 38: the handle log (`kt/` with KT_MODE=handles). The build-time
    // defaults are empty, so handles are unavailable until a log is
    // configured; a test passes one on loopback.
    HandleConfig handleConfig = HandleConfig.defaults,
    KtFetcher? handleFetcher,
    int Function()? handleNow,
    // The ADR 0017 stage-2b signer for this service — since ADR 0029 the kill
    // switch for the move alone. Production never passes it, so it is the
    // protocol's constant — on; a test passes false to start one account as
    // a build with the switch thrown (see [debugDevlistSignV2Only]).
    bool signDevlistV2Only = devlistSignV2Only,
    // Test-only: start this service as a build from before ADR 0029, which
    // never says what device-list shape it reads ([debugPreAdr0029]) — set
    // here so that nothing sent during the start says otherwise.
    bool debugPreAdr0029 = false,
    // Test-only: move at the first chance whatever the gate says, as ADR
    // 0017's signer did before ADR 0029 gave it one ([debugMoveUngated]).
    bool debugMoveUngated = false,
    // ADR 0028: when held receipts may leave. Production never passes it; a
    // test that is not about the delay passes a shorter one, from the start,
    // so that receipts a previous run left are timed by it too.
    ReceiptTiming receiptTiming = ReceiptTiming.standard,
    // How often the disappearing-message sweep runs. Production never passes
    // it; a test of what a tick does passes a short one rather than wait.
    Duration sweepEvery = const Duration(seconds: 20),
  }) async {
    final svc = ChatService._(
      vault: vault,
      identity: identity,
      myRid: await identity.routingId(),
      displayName: displayName,
      transport: transport,
    );
    svc._signerV2Only = signDevlistV2Only;
    svc.debugPreAdr0029 = debugPreAdr0029;
    svc._debugMoveUngated = debugMoveUngated;
    svc._receipts.timing = receiptTiming;
    svc.kt = KeyTransparency(
      vault: vault,
      host: svc,
      fetcher: ktFetcher ?? HttpKtFetcher(),
      config: ktConfig,
      now: ktNow,
    );
    // ADR 0026: the log's latest list for this account, verified, is
    // evidence this device can act on — that it was removed, or (on a root)
    // that the latest entry is one the own-list repair reconciled.
    svc.kt.onOwnLatest = svc._onOwnLatestFromLog;
    svc.kt.holdOwnPublish = svc._holdsOwnPublish;
    await svc.kt.load();
    await svc._loadContacts();
    await svc._loadReceipts(); // ADR 0028: what a previous run still owed
    await svc._loadRequests(); // ADR 0011: pending inbound requests + blocklist
    await svc._refreshAllVerification();
    // Cold start read every per-contact key with its own query — fifteen
    // round trips per contact, 6 ms each contact, 2.5 s for four hundred
    // (PERFORMANCE.md, "Cold start"). Everything per-contact is read once
    // here, by prefix, and handed to the loaders.
    final kv = await vault.kvScanMany([
      'cdev_', // also cdev_pq_, cdev_ver_, cdev_pq_ver_
      'cextra_',
      'pql_alert_',
      'dlpq_sent_',
      'cdl_', // cdl_alert_, cdl_claims_
    ]);
    // One row written by every build before 2026-09-14, under a key with a
    // literal `$` in its name; see `_saveExtra`. It is nobody's session.
    unawaited(vault.kvDelete(r'cextra_$rid'));
    for (final rid in svc.contacts.keys.toList()) {
      await svc._refreshDeviceAssurance(rid, notify: false, kv: kv);
    }
    await svc._loadGroups();
    await svc._loadLinks(); // ADR 0020: group links in either direction
    // ADR 0019: who this account is in a group — its root device's routing
    // id, one more id that is me when a list names it; whether this device
    // may change roles; and the binding signature its own member entry
    // carries — read here, because the decision they feed runs inside the
    // inbound transaction and the list an admin issues is built in one
    // synchronous step.
    final account = await svc.accountIdentity();
    svc._rootRid = b64url(await sha256Bytes(account.accountEdPub));
    svc._holdsRoot = account.holdsAccountRoot;
    svc._myBindingSig = await identity.bindingSignature();
    await svc._loadConversations();
    await svc._computeUnread();
    svc.devMode = (await vault.kvGet('dev_mode')) == '1';
    await svc._initSync();
    await svc._loadHistoryDue(); // 26.2: replays still waiting; run on connect
    // ADR 0022: which devices have proved whose they are — before the held
    // lists are installed, which are held to it.
    await svc._loadProvenDevices();
    await svc._loadContactDeviceLists(kv: kv);
    await svc._loadDevlistState(kv: kv);
    // Phase 31: the first start after a restore re-asserts the account — a
    // list signed above every version the log and the archive know, or for
    // a linked device the account's newest list — before ANYTHING below can
    // sign, encrypt or send. Before the migrations too, which sign.
    await svc._resumeAfterRestore();
    // ADR 0010: re-sign this account's device list once under the v2 format
    // (bumping the version) BEFORE the transport or the log check start below,
    // so no other re-sign publishes a v2 fingerprint at a version the log
    // already holds a v1 fingerprint for. The local sign + record is awaited;
    // distribution to devices and contacts is durable and backgrounded.
    await svc._migrateDeviceListToV2();
    // ADR 0017 stage 2b: the same once more for the v2-only signer, at the
    // same point and for the same reason. Returns at once until this root's
    // gate is open (ADR 0029), and on a build with the switch off.
    await svc._migrateDeviceListToV2Only();
    // Phase 33: a list signature the vault's own key does not verify — what
    // the seed race left — is made again before anything offers it.
    await svc._repairOwnListPqSignature();
    svc._schedulePqListDelivery(); // §18.9, on its own clock
    // ADR 0022: a linked device whose account's list does not carry its
    // proof of possession hands it to its root — the first start of this
    // build on a device linked before it. Through the outbox, which the
    // transport empties once it connects.
    await svc._offerOwnPop();
    // Phase 38: the handle service, after the account's root-ness is known
    // (only the primary device holds a handle) and the requests are loaded
    // (it says which of them came through the handle).
    final handles = HandleService(
      vault: vault,
      host: svc,
      fetcher: handleFetcher ?? HttpKtFetcher(),
      config: handleConfig,
      now: handleNow,
    );
    await handles.load();
    await handles.keepInboundFor(svc.requestsByRid.keys.toSet());
    for (final e in svc.requestsByRid.entries) {
      e.value.via = handles.inboundFor(e.key)?.handle;
    }
    svc._handles = handles;

    transport.onMessage = (m) => unawaited(svc._onInbound(m));
    transport.onDelivered = (r) => unawaited(svc._onDelivered(r));
    transport.onConnected = () => unawaited(svc._onConnected());

    svc._sweeper = Timer.periodic(sweepEvery, (_) => svc._sweepTick());
    transport.start();
    // The transparency log: a first check now, then on its own clock. A
    // no-op until a log is configured.
    svc.kt.start();
    // Handles: a claim waiting for its moment, and the introduction mailbox
    // on its own clock — on the primary device, once a log is configured.
    svc.handles.start();
    // 9.5: a scheduled backup, if the user asked for one. Off by default, in
    // which case this costs two key-value reads and stops. Unawaited and
    // failure-swallowing on purpose — a backup is never worth delaying or
    // breaking the app's start over.
    unawaited(svc._runScheduledBackup());
    // 15.3: a group fan-out that did not finish — the app was killed, or a
    // vault write failed — is resumed here rather than abandoned. Before the
    // queue existed there was nothing to resume from: the remaining
    // recipients were simply lost.
    unawaited(svc._drainGroupFanout());
    // ADR 0019: a list held back before a restart is still waiting for
    // whatever it rests on — ask again, once, for what this device lacks.
    for (final g in svc.groups.values) {
      if (g.held.isNotEmpty) unawaited(svc._askAboutHeld(g));
    }
    // ADR 0020: a joiner's go-ahead read just before the app last stopped,
    // and not yet acted on, is acted on now — re-checked like any other.
    unawaited(svc._finishLinkAdds());
    return svc;
  }

  Future<void> _runScheduledBackup() async {
    try {
      final sched = BackupSchedule(vault);
      if (await sched.intervalDays() <= 0) return; // the common case
      await sched.runIfDue(await BackupStore.open(vault));
    } catch (_) {
      // A failed automatic backup is reported the next time the user opens
      // the backup screen (which shows when the last one actually ran), not
      // by interrupting whatever they were doing.
    }
  }

  bool _disposed = false;

  @override
  void dispose() {
    _stopClocks();
    super.dispose();
  }

  /// Everything this service runs on its own clock, stopped, so that nothing
  /// it starts from here on touches the vault: the disappearing-message
  /// sweep, the outbox retry, the device-list, receipt, history and
  /// post-quantum timers, the transparency log's and the handle's clocks.
  /// [dispose] does it; so does [wipeEverything], which must not have a
  /// sweep or a retry start against a vault it is deleting. Safe to call
  /// twice.
  void _stopClocks() {
    _disposed = true;
    kt.dispose();
    _handles?.dispose();
    _sweeper?.cancel();
    _outboxRetry?.cancel();
    _devlistTimer?.cancel();
    for (final t in _receiptTimers.values) {
      t.cancel();
    }
    _receiptTimers.clear();
    _historyTimer?.cancel();
    _pqListTimer?.cancel();
    for (final t in _pqTimers.values) {
      t.cancel();
    }
    _pqTimers.clear();
    _pqPending.clear();
    _pqDueMs.clear();
    // Receipts still waiting are not sent. A service being disposed must not
    // speak: the flush is a full send — lock, ratchet step, vault
    // transaction — started after the owner has decided the service is over
    // and usually a line before it closes the vault, so it either fails
    // against a closed database or writes after the owner thinks nothing
    // will. (The first version flushed here; backup_test.dart failed on it
    // for a different reason than was first supposed — see that test's
    // "every tick in" wait — but the rule stands on its own.) Since phase 41
    // they are held in the vault (`rcpt_<rid>`), so the next start sends
    // them, at a moment of its own (ADR 0028).
    _receipts.clear();
  }

  @override
  void notifyListeners() {
    // Inbound handlers and best-effort receipts can still be in flight when
    // the service is torn down (app shutdown, account switch, tests): their
    // late notifications must be no-ops, not crashes.
    if (_disposed) return;
    super.notifyListeners();
  }

  // ------------------------------------------------------------------
  // Loading
  // ------------------------------------------------------------------

  Future<void> _loadContacts() async {
    final rows = await vault.db.query('contacts');
    for (final r in rows) {
      final bundle = ContactBundle.fromJson(
          (jsonDecode(await vault.unseal(r['enc_bundle'] as String)) as Map)
              .cast<String, Object?>());
      final commit = r['pq_commit'] as String?;
      final sealedPq = r['enc_pq_pub'] as String?;
      final sealedCand = r['enc_pq_cand'] as String?;
      contacts[r['rid'] as String] = Contact(
        rid: r['rid'] as String,
        bundle: bundle,
        name: await vault.unseal(r['enc_name'] as String),
        ttlSec: r['ttl_seconds'] as int,
        verified: (r['verified'] as int) == 1,
        createdMs: r['created_ms'] as int,
        pqCommit: commit == null ? null : unb64(commit),
        pqPub: sealedPq == null ? null : unb64(await vault.unseal(sealedPq)),
        pqCandidate:
            sealedCand == null ? null : unb64(await vault.unseal(sealedCand)),
        pqAcked: (r['pq_acked'] as int? ?? 0) == 1,
        pqTold: (r['pq_told'] as int? ?? 0) == 1,
        verifiedSn: r['verified_sn'] as String?,
        pqMismatch: (r['pq_mismatch'] as int? ?? 0) == 1,
        requested: (r['requested'] as int? ?? 0) == 1,
        accountEdPub:
            r['acct_ed'] == null ? null : unb64(r['acct_ed'] as String),
        addedByDevice: r['added_by'] as String?,
        deviceCert: r['dev_cert'] == null
            ? null
            : DeviceCertificate.fromJson(
                (jsonDecode(r['dev_cert'] as String) as Map)
                    .cast<String, Object?>()),
      );
      _sealKeys[r['rid'] as String] = bundle.xPub;
    }
    // ADR 0027 and 26.3: three per-contact facts that live in `kv` rather
    // than in a column — whether their codes sign their commitment, the
    // commitment a connect ceremony's digits covered, and an unsigned
    // commitment held as a candidate. One query each, for every contact.
    final kv = await vault.kvScanMany(['pqcs_', 'vpqc_', 'pqcc_']);
    for (final c in contacts.values) {
      c.pqcSigned = kv['pqcs_${c.rid}'] == '1';
      final covered = kv['vpqc_${c.rid}'];
      c.verifiedPqc = covered == null ? null : unb64(covered);
      final hint = kv['pqcc_${c.rid}'];
      c.pqcHint = hint == null ? null : unb64(hint);
    }
  }

  /// Re-read the contact table from disk. Tests use it after writing a row
  /// behind the service's back; nothing in the app needs it.
  @visibleForTesting
  Future<void> reloadContacts() async {
    contacts.clear();
    _verification.clear();
    _deviceAssurance.clear();
    _devListCoversKeys.clear();
    await _loadContacts();
    await _refreshAllVerification();
    for (final rid in contacts.keys.toList()) {
      await _refreshDeviceAssurance(rid, notify: false);
    }
    notifyListeners();
  }

  /// 13.3. Cached because the UI asks on every rebuild — a chat header, a row
  /// in the contact list — while the answer changes at most twice in a
  /// contact's life: when the user ticks the box, and when the identity gains
  /// its post-quantum half. Computing it costs a safety-number derivation
  /// (~0.2 ms here) and only ever for a contact the user actually verified.
  final Map<String, VerificationState> _verification = {};

  Future<void> _refreshAllVerification() async {
    for (final rid in contacts.keys.toList()) {
      await _backfillVerifiedSn(rid);
      await _refreshVerification(rid, notify: false);
    }
  }

  /// A contact verified before 13.3 has a tick but no recorded number.
  ///
  /// Dropping every such tick on upgrade would be safe but obnoxious — it is
  /// most of the verifications in existence, and it would teach people that
  /// the tick is noise. Instead record the CLASSICAL number, which is what
  /// any earlier build showed for a contact still at classical assurance. The
  /// tick then survives where nothing has moved, and a contact that has since
  /// gone hybrid classifies as "upgraded, re-verify" — asking for a
  /// comparison rather than asserting one, which is the direction to be wrong
  /// in.
  Future<void> _backfillVerifiedSn(String rid) async {
    final c = contacts[rid];
    if (c == null || !c.verified || c.verifiedSn != null) return;
    final sn =
        await safetyNumber((await accountIdentity()).accountEdPub, c.accountEd);
    try {
      await vault.db.update('contacts', {'verified_sn': sn},
          where: 'rid = ?', whereArgs: [rid]);
    } catch (_) {
      return; // read-only or shutting down; next start tries again
    }
    c.verifiedSn = sn;
  }

  Future<void> _refreshVerification(String rid, {bool notify = true}) async {
    final was = _verification[rid];
    final now = await _computeVerification(rid);
    _setVerificationState(rid, now);
    if (notify && was != now) notifyListeners();
  }

  /// Re-read the conversation table from disk, the same way a restart
  /// does. Tests use it after writing a cell behind the service's back.
  @visibleForTesting
  Future<void> reloadConversations() async {
    _convs.clear();
    await _loadConversations();
  }

  Future<void> _loadConversations() async {
    final rows = await vault.db.query('conversations');
    for (final r in rows) {
      final rid = r['rid'] as String;
      final contact = contacts[rid];
      if (contact == null) continue;
      final stateJson =
          (jsonDecode(await vault.unseal(r['enc_state'] as String)) as Map)
              .cast<String, Object?>();
      final conv = await Conversation.fromJson(identity, stateJson,
          intervals: _pqIntervals);
      await _restoreSkipped(conv, r['enc_skipped']);
      _convs[rid] = conv;
      // A row from before schema 9 carries its cache inside `enc_state`,
      // and the next SEND rewrites `enc_state` without it — that is the
      // point of the split. So between the upgrade and the first receive,
      // a send followed by a kill loses every in-flight key: the old
      // location has been emptied and the new one was never written. The
      // keys are moved to their new home here, at load, before anything
      // can rewrite the old one. Once, per conversation; afterwards the
      // cell is non-null and this does nothing.
      if (r['enc_skipped'] == null && debugSkippedKeyCount(rid) > 0) {
        await _saveSkipped(rid);
      }
    }
  }

  /// Unread counts for every chat, in one query. `last_open_<rid>` has been
  /// a plain (`p:`) kv row since the first commit, so SQL can read it in a
  /// correlated subquery; a chat with no row counts everything, as before.
  /// Measured against one COUNT per chat: 274 → 0 ms for 400 chats of one
  /// message, 238 → 11 ms for 400 chats of fifty, 33 → 24 ms for 50 chats
  /// of a thousand — never slower, and the per-chat form is what made cold
  /// start linear in the contact count (PERFORMANCE.md, "Cold start").
  ///
  /// A message read on another of my devices (30.3), or read here while its
  /// chat was open, carries `receipt_sent` and is not counted: the time the
  /// chat was last opened here does not cover either.
  Future<void> _computeUnread() async {
    final rows = await vault.db
        .rawQuery("SELECT m.rid AS rid, COUNT(*) AS n FROM messages m "
            "WHERE m.outgoing = 0 AND m.kind != 'system' "
            "AND m.receipt_sent = 0 "
            "AND m.ts_ms > COALESCE((SELECT CAST(v AS INTEGER) FROM kv "
            "WHERE k = 'p:last_open_' || m.rid), 0) GROUP BY m.rid");
    final counts = {
      for (final r in rows) r['rid'] as String: (r['n'] as num).toInt()
    };
    for (final rid in [...contacts.keys, ...groups.keys]) {
      unread[rid] = counts[rid] ?? 0;
    }
  }

  Future<Conversation> _convFor(Contact contact) async {
    var conv = _convs[contact.rid];
    if (conv == null) {
      conv = await Conversation.create(identity, contact.bundle,
          intervals: _pqIntervals);
      _convs[contact.rid] = conv;
    }
    return conv;
  }

  /// A conversation put back from [snapshot] — a rollback. It is told the
  /// intervals as any conversation is: a snapshot is state, and the clocks
  /// are not state. Until 26.2 this was a bare `fromJson`, so every rollback
  /// left a conversation that neither retried nor re-keyed until the app
  /// restarted — and one garbage envelope from anyone holding the code is a
  /// rollback.
  Future<Conversation> _convFromSnapshot(String snapshot) =>
      Conversation.fromJson(identity, jsonDecode(snapshot),
          intervals: _pqIntervals);

  /// Persist a conversation's hot ratchet state — **without** the
  /// out-of-order key cache, which lives in its own cell (see
  /// [_saveSkipped]).
  ///
  /// This is the send path's cost, and the cache is why it used to be so
  /// much larger than it needed to be: at its 1536-entry cap, encoding and
  /// sealing it added ~20 ms per recipient to every message, for state that
  /// only a RECEIVE can read or change (`docs/PERFORMANCE.md`).
  Future<void> _saveConv(String rid, {DatabaseExecutor? txn}) async {
    final conv = _convs[rid];
    if (conv == null) return;
    final sealed =
        await vault.seal(jsonEncode(conv.toJson(includeSkipped: false)));
    // An upsert that names the columns it sets, NOT insert-or-replace.
    //
    // REPLACE deletes the conflicting row and inserts a new one, so every
    // column absent from the map comes back NULL — which silently emptied
    // `enc_skipped` on every send the moment the cache moved there. Nothing
    // failed at the time; the loss only shows up later as a late message
    // that will not decrypt. The test for this exists because the first
    // version of this change had exactly that bug.
    await (txn ?? vault.db).rawInsert(
        'INSERT INTO conversations (rid, enc_state, updated_ms) '
        'VALUES (?, ?, ?) '
        'ON CONFLICT(rid) DO UPDATE SET enc_state = excluded.enc_state, '
        'updated_ms = excluded.updated_ms',
        [rid, sealed, DateTime.now().millisecondsSinceEpoch]);
  }

  /// Persist the out-of-order key cache. Receive path only.
  ///
  /// Always written in the SAME transaction as [_saveConv], because the two
  /// halves have to agree: `nr` advancing without the keys it skipped past
  /// being stored would silently lose the ability to read those messages
  /// when they arrive.
  Future<void> _saveSkipped(String rid, {DatabaseExecutor? txn}) async {
    final conv = _convs[rid];
    if (conv == null) return;
    final skipped = <String, Map<String, String>>{
      for (final e in conv.sessions.entries)
        if (e.value.ratchet.skipped.isNotEmpty)
          e.key: Map<String, String>.from(e.value.ratchet.skipped),
    };
    await (txn ?? vault.db).update(
        'conversations',
        {
          'enc_skipped':
              skipped.isEmpty ? null : await vault.seal(jsonEncode(skipped))
        },
        where: 'rid = ?',
        whereArgs: [rid]);
  }

  /// A cheap fingerprint of the out-of-order key cache: per session, how
  /// many keys and which one was added last. Every change a decrypt can
  /// make moves it — adding keys appends a new last one, consuming a key
  /// changes the count, and eviction at the cap only ever happens alongside
  /// an add — so equal shapes before and after a decrypt mean the cache is
  /// untouched and need not be re-sealed.
  String _skippedShape(Conversation conv) => [
        for (final e in conv.sessions.entries)
          '${e.key}:${e.value.ratchet.skipped.length}:'
              '${e.value.ratchet.skipped.isEmpty ? '' : e.value.ratchet.skipped.keys.last}'
      ].join('|');

  /// Put the cache back into a freshly-loaded conversation.
  ///
  /// A row written before schema 9 has its cache inside `enc_state`, where
  /// `Conversation.fromJson` already picked it up — so a null column is not
  /// "no keys", it is "the keys came from the old place". Overwriting in
  /// that case would throw them away, which is why this only ever ADDS.
  Future<void> _restoreSkipped(Conversation conv, Object? cell) async {
    if (cell == null) return;
    final raw = (jsonDecode(await vault.unseal(cell as String)) as Map)
        .cast<String, Object?>();
    for (final e in raw.entries) {
      final session = conv.sessions[e.key];
      if (session == null) continue; // a session that has since been replaced
      session.ratchet.skipped.addAll((e.value as Map).cast<String, String>());
    }
  }

  /// How many out-of-order keys this conversation is holding, across all its
  /// sessions. Test seam: the property that matters about the cache is that
  /// it survives being stored apart from the state it belongs to.
  @visibleForTesting
  int debugSkippedKeyCount(String rid) {
    final conv = _convs[rid];
    if (conv == null) return 0;
    var n = 0;
    for (final s in conv.sessions.values) {
      n += s.ratchet.skipped.length;
    }
    return n;
  }

  // ------------------------------------------------------------------
  // Contacts
  // ------------------------------------------------------------------

  /// The code this device hands out (§18.2, §18.6).
  ///
  /// Where the account's post-quantum key can honestly be committed to, it
  /// carries the commitment — in a **v1-shaped** code, so a build already in
  /// the field reads the classical identity and ignores the extra member,
  /// while a v3 client sees the commitment and knows a post-quantum key is
  /// coming. There is no flag day, which is why emission could be switched on
  /// without waiting for the population to upgrade first.
  Future<String> myContactCode() async {
    final account = await accountIdentity();
    final mlPub = await pqAccountPublic();
    if (mlPub == null) {
      // No account post-quantum key reachable from here — a device linked by
      // a build that predates v3. Emit the plain v1 code rather than
      // committing to something this device made up; re-linking fixes it.
      return (await identity.bundle(displayName: displayName)).encode();
    }
    // §18.7. The code describes THIS DEVICE — its keys are the ones a contact
    // opens a session with — but the identity it is *about* is the account.
    // On a device holding the root those are the same key and saying so twice
    // only makes the QR bigger. On a linked device they differ, and the
    // account's certificate for this device is what makes the claim
    // checkable: without it a contact scanning a laptop adds the laptop, and
    // the commitment could not be carried at all, because it binds the
    // account's post-quantum key to whatever classical identity sits beside
    // it in the same code.
    final linked = !constantTimeEquals(identity.edPub, account.accountEdPub);
    return (await ContactBundleV3.forIdentity(
      identity,
      HybridPublicKey(edPub: account.accountEdPub, mlPub: mlPub),
      displayName: displayName,
      accountEdPub: linked ? account.accountEdPub : null,
      cert: linked ? account.deviceCert : null,
    ))
        .encode();
  }

  HybridKeyPair? _pq;

  /// The first [pqIdentity] while it is still running, which every caller
  /// that arrives meanwhile waits for instead of starting one of its own.
  Future<HybridKeyPair?>? _pqLoading;

  /// This account's hybrid key (§18.1). The ML-DSA half is derived from a
  /// 32-byte seed generated once and sealed in the vault — not from a stored
  /// 4 032-byte secret key, so a backup archive carries 32 more bytes rather
  /// than four kilobytes, and a restore reproduces the same identity.
  ///
  /// The classical half IS this identity's Ed25519 key: one identity, two
  /// signature algorithms over it.
  ///
  /// One seed, however many ask first. The seed used to be made by whoever
  /// asked first, with nothing to stop a second caller doing the same
  /// between the first one's read and its write — and two callers at once is
  /// the ordinary first start: the log check signing the account's first
  /// list, and the screen asking for the contact code. Each made a seed, the
  /// vault kept whichever was written last, and the code then shown could
  /// commit to a key the account never sent — which every contact who
  /// scanned it refuses, for good (phase 31's report; `linked_equals_test`
  /// 4). Now the first call is shared by everyone who arrives while it runs.
  Future<HybridKeyPair?> pqIdentity() {
    final cached = _pq;
    if (cached != null) return Future<HybridKeyPair?>.value(cached);
    return _pqLoading ??=
        _loadPqIdentity().whenComplete(() => _pqLoading = null);
  }

  Future<HybridKeyPair?> _loadPqIdentity() async {
    final rootSeed = (await accountIdentity()).accountEdSeed;
    if (rootSeed == null) return null; // linked device: see pqAccountPublic
    var seedB64 = await vault.kvGet('pq_seed');
    if (seedB64 == null) {
      seedB64 = b64(randomBytes(32));
      await vault.kvPut('pq_seed', seedB64);
    }
    final kp =
        await HybridKeyPair.fromSeeds(edSeed: rootSeed, mlSeed: unb64(seedB64));
    _pq = kp;
    return kp;
  }

  /// The account's ML-DSA **public** key, whichever device is asking.
  ///
  /// Derived on a device holding the root; received at enrollment on a linked
  /// one (`EnrollmentData.accountMlPub`). Null on a device linked by a build
  /// that predates v3 — honest, rather than inventing one: that device then
  /// shows the classical safety number and hands out a code with no
  /// commitment until it is re-enrolled.
  Future<Uint8List?> pqAccountPublic() async {
    final mine = await pqIdentity();
    if (mine != null) return mine.publicKey.mlPub;
    return (await accountIdentity()).accountMlPub;
  }

  /// The explicit `zc3.` form. Not handed out — [myContactCode] emits the
  /// compatible shape — but kept because the strict form is specified,
  /// vectored, and is what a future release could switch to if the prefix
  /// ever needs to signal something on its own.
  Future<String?> myContactCodeStrictV3() async {
    final mine = await pqIdentity();
    if (mine == null) return null;
    return (await ContactBundleV3.forIdentity(identity, mine.publicKey,
            displayName: displayName))
        .encodeStrict();
  }

  Future<Contact> addContactFromCode(String code,
      {String? alias, bool requested = true, bool upgradeExisting = true}) async {
    // Accepts zc1. and zc3.; a v3 code yields the same classical bundle plus
    // the commitment its post-quantum key must later match. (zc2. account
    // codes are for device linking, not contact exchange, and never reached
    // this path.)
    //
    // [requested] (ADR 0011/0012): a scan or paste is a one-sided add, so it
    // marks the contact "requested" and hands the other side a signed request.
    // The CONNECT ceremony passes false: both sides add each other as the
    // ceremony completes, so there is no one-sided limbo to show and no request
    // to send — the redundant creq would only fold on an existing contact.
    final ScannedIdentity scanned;
    try {
      scanned = await scanContactCode(code);
    } on FormatException catch (e) {
      // 42.3: the protocol library says why in English — "signature invalid
      // (possible tampering)" among its reasons — and the add screen used to
      // show that sentence in every language. The kind is what it shows now;
      // the reason stays the message, for logs.
      throw ContactCodeRefused(ContactCodeRefusal.invalidCode, '', e.message);
    }
    final bundle = scanned.classical;
    final rid = await bundle.routingId();
    if (_myAccountRids.contains(rid)) {
      // Mine, whichever of my devices the code names — a linked device
      // scanning the account's own code would otherwise add the account to
      // its own contact list.
      throw const ContactCodeRefused(
          ContactCodeRefusal.ownCode, '', 'that is your own contact code');
    }
    if (contacts.containsKey(rid)) {
      // ADR 0021: scanning a contact's CURRENT code again is the other way to
      // the post-quantum number — the one that needs no session and no
      // comparison. A code carrying a commitment the record lacks upgrades
      // the record; one that brings nothing new is what it always was.
      //
      // [upgradeExisting] is what the CONNECT ceremony turns off. Its own
      // rule — that someone already in the contact list is refused and the
      // invite left for the user to discard — predates this and rests on a
      // different question: whether a remote ceremony may re-verify an
      // existing record. That is a trust-model decision of its own and wants
      // its own ADR (`connect_invites.dart`); it is not something this one
      // should change by widening a method the ceremony happens to call.
      if (!upgradeExisting) {
        throw _alreadyContact(contacts[rid]!.name);
      }
      return _upgradeContactFromCode(contacts[rid]!, scanned);
    }
    final name = (alias?.trim().isNotEmpty ?? false)
        ? alias!.trim()
        : (bundle.displayName ?? 'Unknown');
    // ADR 0022: a device that has proved which account it is in is not added
    // as another account's, whatever a code says — a code naming an account
    // is that account's certificate for the device, which the account signs
    // over whatever keys it is handed. A code naming no account is the
    // device's own identity, which a linked device on a build before §18.7
    // hands out; phase 33 moves that record onto the device's account.
    final declared = scanned.v3?.declaredAccountEdPub;
    final provenFor = _provenDevices[rid]?.acct;
    if (declared != null &&
        provenFor != null &&
        provenFor != base64Encode(declared)) {
      throw ContactCodeRefused(
          ContactCodeRefusal.provenElsewhere,
          name,
          'this code names a device that has proved it belongs to another '
          'account');
    }
    // §18.7: the routing id is the DEVICE's, because that is the mailbox that
    // can be reached, while the identity is the ACCOUNT's. For a code that
    // predates §18.7 these are the same key, so nothing about an existing
    // contact changes.
    final contact = Contact(
      rid: rid,
      bundle: bundle,
      name: name,
      createdMs: DateTime.now().millisecondsSinceEpoch,
      pqCommit: scanned.v3?.pqCommit,
      accountEdPub: scanned.v3?.declaredAccountEdPub,
      deviceCert: scanned.deviceCert,
      // ADR 0011: we added them; we are waiting for them to accept. Clears on
      // their first traffic. On a mutual scan it clears at once, when the
      // other side's own hello/request arrives. The CONNECT ceremony sets this
      // false (ADR 0012): both sides add each other as it completes.
      requested: requested,
    );
    // 13.7 put a second writer on this table: the same contact can arrive from
    // one of my own devices while the user is scanning it here. The check
    // above and the insert below have to be one step, or the two interleave
    // and the insert dies on the primary key.
    final claimed = await _withLock<bool>(rid, () async {
      if (contacts.containsKey(rid)) return false;
      await vault.db.insert(
          'contacts',
          {
            'rid': rid,
            'enc_bundle': await vault.seal(jsonEncode(bundle.toJson())),
            'enc_name': await vault.seal(name),
            'ttl_seconds': 0,
            'verified': 0,
            'created_ms': contact.createdMs,
            'requested': requested ? 1 : 0,
            if (contact.pqCommit != null) 'pq_commit': b64(contact.pqCommit!),
            if (contact.accountEdPub != null)
              'acct_ed': b64(contact.accountEdPub!),
            if (contact.deviceCert != null)
              'dev_cert': jsonEncode(contact.deviceCert!.toJson()),
            if (contact.addedByDevice != null)
              'added_by': contact.addedByDevice,
          },
          conflictAlgorithm: ConflictAlgorithm.replace);
      // Adding someone we had blocked is a change of mind: the block goes, so
      // `contacts` and `blocked` never both name one id (ADR 0011) — in
      // memory too, which ADR 0024's checks read.
      await vault.db.delete('blocked', where: 'rid = ?', whereArgs: [rid]);
      _blocked.remove(rid);
      contacts[rid] = contact;
      return true;
    });
    if (!claimed) {
      // It landed from another of my devices while this scan was in flight.
      // The user gets the same answer either way, and it is true.
      throw _alreadyContact(contacts[rid]!.name);
    }
    // ADR 0027: their code signs its commitment, so from now on one that
    // does not is told apart from it. An unsigned commitment on a NEW
    // contact is held exactly as before: there is nothing yet to poison, and
    // someone able to alter the code before its first scan could replace the
    // whole identity in it, which is what comparing the number is for.
    if (scanned.commitSigned) await _markPqcSigned(contact);
    await _onContactAdded(contact);
    // ADR 0011: hand them a signed request so they can accept without scanning
    // us back. (On a mutual scan they already added us; their side folds the
    // duplicate.) The CONNECT ceremony (requested:false) skips it: the ceremony
    // already added both sides, so the request would only fold anyway.
    if (requested) await _sendContactRequest(contact);
    return contact;
  }

  /// The refusal of a code for someone already held as [name] (42.3: a
  /// kind, for the screen to word; the English is for logs).
  static ContactCodeRefused _alreadyContact(String name) => ContactCodeRefused(
      ContactCodeRefusal.alreadyContact,
      name,
      'already in your contacts as "$name"');

  /// ADR 0021: a contact's code scanned again. If it carries a post-quantum
  /// commitment the record lacks, the record takes it — and a key already
  /// held for the number is checked against it on the spot: a match is
  /// ESTABLISHED (no comparison needed; the code was scanned in person), a
  /// mismatch is refused exactly as an in-band one is. A code whose
  /// commitment differs from the one held, or that names a different
  /// identity, is refused outright: a person's post-quantum key does not
  /// change under the same classical identity unless something is wrong, and
  /// "delete the contact and add them again" is the honest path for a real
  /// reset. A code that brings nothing new is reported as it always was.
  ///
  /// ADR 0027 divides codes by whether their owner SIGNED the commitment in
  /// them. A signed commitment is evidence and is treated as every commitment
  /// was before. An unsigned one — every code from a build before ADR 0027,
  /// and any code whose `pqcs` was removed — is not: anyone holding the
  /// person's public code can write one, and pasting such a code used to set
  /// a permanent "do not rely on this chat" on a contact who had done nothing.
  /// So it is treated as ADR 0021 treats a key nothing commits to, a
  /// candidate: a key it matches is established, and one it misses is never
  /// refused on its strength — the CODE is refused, and nothing changes. And
  /// once a contact's codes are known to sign ([Contact.pqcSigned]), a code
  /// for them that does not is refused as one somebody may have stripped.
  Future<Contact> _upgradeContactFromCode(
      Contact c, ScannedIdentity scanned) async {
    final already = _alreadyContact(c.name);
    final signed = scanned.commitSigned;
    if (c.pqcSigned && !signed) {
      // The routing id matched, so this is their device's own key, with its
      // binding signature intact: an old code of theirs, or a current one with
      // the commitment or its signature taken out. Either way it is not read
      // as less than what is held, and nothing is changed by it.
      throw ContactCodeRefused(
          ContactCodeRefusal.commitStripped,
          c.name,
          'this code does not carry the signed post-quantum commitment that '
          '"${c.name}"\'s codes carry: it may be an old code of theirs, or '
          'someone removed it. Nothing was changed.');
    }
    final v3 = scanned.v3;
    if (v3 == null) throw already; // a classical code: nothing to upgrade
    final same = constantTimeEquals(v3.edPub, c.bundle.edPub) &&
        constantTimeEquals(v3.xPub, c.bundle.xPub) &&
        constantTimeEquals(scanned.accountEdPub, c.accountEd);
    if (!same) {
      throw ContactCodeRefused(
          ContactCodeRefusal.otherIdentity,
          c.name,
          'this code is for a different identity than the one you hold for '
          '"${c.name}"');
    }
    final held = c.pqCommit;
    if (held != null) {
      if (constantTimeEquals(held, v3.pqCommit)) {
        // The commitment already held — and now known to be one they sign.
        if (signed) await _markPqcSigned(c);
        throw already;
      }
      throw ContactCodeRefused(
          ContactCodeRefusal.commitChanged,
          c.name,
          'the post-quantum commitment in this code is not the one you hold '
          'for "${c.name}". If they reset their identity, delete the contact '
          'and add them again; otherwise do not trust this code.');
    }
    final commitFor = ContactBundleV3(
      edPub: c.accountEd,
      xPub: c.bundle.xPub,
      bindingSig: c.bundle.bindingSig,
      pqCommit: v3.pqCommit,
    );
    final established = c.pqPub;
    if (established != null) {
      // Confirmed by comparison earlier. The code must agree with it, or the
      // code is the thing that is wrong.
      if (!await commitFor.acceptsPqKey(
          HybridPublicKey(edPub: c.accountEd, mlPub: established))) {
        throw ContactCodeRefused(
            ContactCodeRefusal.commitMissesConfirmedKey,
            c.name,
            'the post-quantum commitment in this code does not match the key '
            'you confirmed for "${c.name}". Do not trust this code.');
      }
      await vault.db.update('contacts', {'pq_commit': b64(v3.pqCommit)},
          where: 'rid = ?', whereArgs: [c.rid]);
      c.pqCommit = v3.pqCommit;
      if (signed) await _markPqcSigned(c);
      await _setPqcHint(c, null);
      notifyListeners();
      return c;
    }
    final cand = c.pqCandidate;
    if (cand == null) {
      if (!signed) {
        // ADR 0027: nothing to check it against yet, and nothing signs it.
        // Held as a candidate for the key to be checked against when it
        // arrives — never as a commitment a key could be refused for.
        await _setPqcHint(c, v3.pqCommit);
        _offerPqIdentity(c, _PqReason.nudge);
        notifyListeners();
        return c;
      }
      // Nothing held yet: the commitment waits for the key, as after any v3
      // scan, and we ask for it now rather than on their next message.
      await vault.db.update('contacts', {'pq_commit': b64(v3.pqCommit)},
          where: 'rid = ?', whereArgs: [c.rid]);
      c.pqCommit = v3.pqCommit;
      await _markPqcSigned(c);
      await _setPqcHint(c, null);
      _offerPqIdentity(c, _PqReason.nudge);
      notifyListeners();
      return c;
    }
    final key = HybridPublicKey(edPub: c.accountEd, mlPub: cand);
    if (await commitFor.acceptsPqKey(key)) {
      // The number moves unless it was already showing this key (13.3).
      final tick =
          c.showsPostQuantumNumber ? null : await _tickAfterMove(c, key);
      await vault.db.update(
          'contacts',
          {
            'pq_commit': b64(v3.pqCommit),
            'enc_pq_pub': await vault.seal(b64(cand)),
            'enc_pq_cand': null,
            if (tick?.moveTo != null) 'verified_sn': tick!.moveTo,
          },
          where: 'rid = ?',
          whereArgs: [c.rid]);
      await _forgetCovered(c, tick);
      c.pqCommit = v3.pqCommit;
      c.pqPub = cand;
      c.pqCandidate = null;
      _applyTick(c, tick);
      if (signed) await _markPqcSigned(c);
      await _setPqcHint(c, null);
      unawaited(_refreshDeviceAssurance(c.rid).then((_) {}, onError: (_) {}));
    } else if (!signed) {
      // ADR 0027: the key their app sent and a commitment nobody signed
      // disagree, and only one of the two came from them. The code is what is
      // refused; the contact, its key and its number stay exactly as they
      // were — no flag, no line in the chat.
      throw ContactCodeRefused(
          ContactCodeRefusal.unsignedCommitMismatch,
          c.name,
          'the post-quantum commitment in this code does not match the key '
          '"${c.name}"\'s app sent, and nothing in the code signs it, so it '
          'may have been altered. Nothing was changed: compare the safety '
          'number with them instead.');
    } else {
      // The key that arrived in-band is not the one this code commits to — a
      // commitment its owner signed: the same refusal an in-band mismatch
      // gets, and it takes the candidate's number off the screen with it.
      await vault.db.update(
          'contacts',
          {
            'pq_commit': b64(v3.pqCommit),
            'enc_pq_cand': null,
            'pq_mismatch': 1,
          },
          where: 'rid = ?',
          whereArgs: [c.rid]);
      c.pqCommit = v3.pqCommit;
      c.pqCandidate = null;
      c.pqMismatch = true;
      await _markPqcSigned(c);
      await _setPqcHint(c, null);
      await _refreshVerification(c.rid, notify: false);
      await _insertSystemMessage(
          c.rid, systemBody(SystemKind.pqMismatch, {'name': c.name}));
      notifyListeners();
      // Everything above is recorded and durable; this throws so that the
      // screen says what happened. Returning normally here would pop a
      // "their commitment was taken from this code" confirmation at the one
      // moment the app holds hard evidence of a substituted key — the state
      // is the warning, and the user has to see it.
      throw ContactCodeRefused(
          ContactCodeRefusal.keyMismatch,
          c.name,
          'the post-quantum key held for "${c.name}" does not match the '
          'commitment in this code. It has been refused and the contact is '
          'flagged. Do not rely on this chat until you have spoken to them '
          'on another channel.');
    }
    notifyListeners();
    return c;
  }

  /// ADR 0027: record that a code of [c]'s carried a signed commitment.
  /// Best-effort: a write that fails leaves the contact where every contact
  /// was before, and the next signed code of theirs records it again.
  Future<void> _markPqcSigned(Contact c) async {
    if (c.pqcSigned || _disposed) return;
    try {
      await vault.kvPut('pqcs_${c.rid}', '1');
    } catch (_) {
      return;
    }
    c.pqcSigned = true;
  }

  /// ADR 0027: hold [hint] — an unsigned commitment — as a candidate for
  /// [c]'s key to be checked against, or drop the one held (null). The
  /// latest code wins: a hint moves no number and can refuse nothing, so
  /// there is nothing a second one could unsettle.
  Future<void> _setPqcHint(Contact c, Uint8List? hint) async {
    if (hint == null && c.pqcHint == null) return;
    try {
      if (hint == null) {
        await vault.kvDelete('pqcc_${c.rid}');
      } else {
        await vault.kvPut('pqcc_${c.rid}', b64(hint));
      }
    } catch (_) {
      return; // shutting down; a stale hint can only fail to match
    }
    c.pqcHint = hint;
  }

  /// The steps shared by every path that adds a NEW contact (a scan/paste, or
  /// accepting a request): the send keys, the empty thread, and the proactive
  /// session open. Factored so accepting a request establishes exactly as a
  /// scan does — the timing self-heal (`_noteUndecryptable`) then closes the
  /// case where our opening hello was dropped because they had not added us.
  Future<void> _onContactAdded(Contact contact) async {
    final rid = contact.rid;
    // If a request from them was pending (a mutual scan crossing in flight), it
    // is answered by the add itself — and a decline of an earlier one of
    // theirs is a decision the add has replaced (§18.8).
    await _removeRequest(rid);
    await vault.kvDelete('reqdecl_$rid');
    _sealKeys[rid] = contact.bundle.xPub;
    messagesByChat[rid] = [];
    unread[rid] = 0;

    // Open the secure session proactively if this side is the designated
    // initiator; otherwise the first message (ours or theirs) will.
    final conv = await _convFor(contact);
    if (conv.isDesignatedInitiator) {
      await _sendInner(contact, InnerMessage.hello(newMessageId(), _now()));
      // With the hello, not a debounce later: the two must reach the peer
      // in one batch, or their answer to the hello goes out before our key
      // has landed and says it does not hold it — and earns a second one.
      if (_pqSent.add(contact.rid)) await _sendPqIdentity(contact);
      // 7.7a hardening: a multi-device account introduces its device set with
      // the hello, so the new contact fans out to every device from the first
      // message. If they have not added us yet this is dropped like the hello;
      // the echo on their first message then triggers a re-send.
      if (await _myDevlistVersion() > 1) {
        final data = await _shareableDeviceList();
        if (data != null) await _sendInner(contact, _devlistInner(data));
      }
    }
    // 13.7: tell my own other devices, or they drop this person's messages as
    // an unknown sender for ever. Best-effort and unawaited — the contact is
    // already added here whether or not the sync lands.
    unawaited(_mirrorContact(contact).then((_) {}, onError: (_) {}));
    // ADR 0022: the device they were added from, if what they were added from
    // proves it is theirs, is not another account's because that account's
    // list reached this device first.
    unawaited(_claimAddedDevice(contact).then((_) {}, onError: (_) {}));
    _schedulePqListDelivery(); // §18.9: a new contact is owed the signature
    notifyListeners();
  }

  // --- ADR 0011: contact requests -----------------------------------------

  /// Pending INBOUND requests, rid → who is asking. The durable copy is the
  /// `requests` table; this is loaded from it on start and kept current for the
  /// Requests surface.
  final Map<String, PendingRequest> requestsByRid = {};

  /// Routing ids blocked here: a request or any traffic from one is dropped in
  /// silence. Cached from the `blocked` table.
  final Set<String> _blocked = {};

  /// Pending inbound requests, newest first.
  List<PendingRequest> get requests {
    final list = requestsByRid.values.toList();
    list.sort((a, b) => b.createdMs.compareTo(a.createdMs));
    return list;
  }

  bool isBlocked(String rid) => _blocked.contains(rid);

  // ADR 0024: a request is signed with its `ts`, and this device holds it to
  // it. Before, nothing read `ts`, so a request already declined came back
  // whenever the relay — which keeps every envelope it carries, for as long
  // as it likes — delivered its copy again, and a request two years old was
  // as good as one made a minute ago.

  /// How far behind this device's clock a request's signed `ts` may be.
  /// Ten times the relay's queue lifetime: a request waits in the
  /// requester's outbox while they are offline, then up to 72 hours at the
  /// relay, and an add made on a plane should still arrive. Older than this
  /// it is refused, whoever delivers it.
  static const Duration requestMaxAge = Duration(days: 30);

  /// How far ahead of this device's clock a request's `ts` may be: a phone's
  /// clock can be wrong by hours, and a request dated further ahead than
  /// this would stay new for longer than [requestMaxAge] says.
  static const Duration requestMaxSkew = Duration(days: 1);

  /// The most pending requests this device holds that came by a code
  /// someone scanned or pasted, or by a link. When one would be the 101st,
  /// the oldest the person has not seen goes — the newcomer, if every other
  /// has been seen — so a flood of new identities can push out only what
  /// nobody has looked at yet, and never a request the person has seen.
  static const int maxPendingRequests = 100;

  /// The most pending requests that came through this account's handle
  /// (§21.7, §21.8), counted apart from [maxPendingRequests] and held to the
  /// same rule within their own number. A handle is a public door: anyone
  /// who knows it can send, and the drain files what came 3 to 30 seconds
  /// after the app opens — so under one shared cap a wave through the handle
  /// pushed out the unseen request of someone who had the person's code
  /// before the person could look, as an independent review of handles
  /// found (2026-10-09). Apart, a flood through one door evicts only what
  /// came through it.
  static const int maxPendingHandleRequests = handleInboundCap;

  /// The `ts` of the newest request taken in from each requester, pending
  /// or answered: one whose `ts` is not newer is a copy, or an older one
  /// late, and is refused. Kept until [requestMaxAge] has passed `ts` — the
  /// age rule refuses it from then on — and dropped when the request is
  /// accepted, blocked, pushed out by the cap, or erased with the contact.
  /// Sealed, in the vault's `requests_meta` cell with [_requestsSeen].
  final Map<String, int> _requestMarks = {};

  /// Pending requests the person has had in front of them (the Requests
  /// screen): the ones the cap pushes out last.
  final Set<String> _requestsSeen = {};

  /// When the last request arrived, so each arrival is strictly later than
  /// the one before and "oldest" never depends on two sharing a millisecond.
  int _lastRequestMs = 0;

  Future<void> _loadRequests() async {
    for (final r in await vault.db.query('blocked')) {
      _blocked.add(r['rid'] as String);
    }
    for (final r in await vault.db.query('requests')) {
      try {
        final bundle = ContactBundle.fromJson(
            (jsonDecode(await vault.unseal(r['enc_bundle'] as String)) as Map)
                .cast<String, Object?>());
        final rid = r['rid'] as String;
        requestsByRid[rid] = PendingRequest(
          rid: rid,
          name: await vault.unseal(r['enc_name'] as String),
          bundle: bundle,
          createdMs: r['created_ms'] as int,
        );
        _lastRequestMs = max(_lastRequestMs, r['created_ms'] as int);
      } catch (_) {
        // A row we cannot open is not one we can act on; erasure still sweeps it.
      }
    }
    try {
      final raw = await vault.kvGet('requests_meta');
      if (raw != null) {
        final j = (jsonDecode(raw) as Map).cast<String, Object?>();
        for (final e in ((j['marks'] as Map?) ?? const {}).entries) {
          _requestMarks[e.key as String] = (e.value as num).toInt();
        }
        for (final rid in (j['seen'] as List?) ?? const []) {
          if (requestsByRid.containsKey(rid)) _requestsSeen.add(rid as String);
        }
      }
    } catch (_) {
      // Unreadable: no marks and nothing seen. Copies of answered requests
      // within their 30 days can show once more; nothing else changes.
      _requestMarks.clear();
      _requestsSeen.clear();
    }
  }

  /// Write [_requestMarks] and [_requestsSeen], dropping marks old enough
  /// that the age rule refuses their requests anyway.
  Future<void> _saveRequestMeta() async {
    final now = _now();
    _requestMarks.removeWhere(
        (_, ts) => now - ts > requestMaxAge.inMilliseconds);
    _requestsSeen.removeWhere((rid) => !requestsByRid.containsKey(rid));
    await vault.kvPut(
        'requests_meta',
        jsonEncode({
          'marks': _requestMarks,
          'seen': _requestsSeen.toList(),
        }));
  }

  /// The person has the Requests screen in front of them: every request on
  /// it is seen, so it is among the last the cap would push out. Changes
  /// nothing on screen, and so tells no listener. The handle service keeps
  /// its own record of the ones that came through the handle (§21.8), which
  /// a backup carries; it is marked too.
  Future<void> markRequestsSeen() async {
    await _handles?.markInboundSeen();
    final unseen = [
      for (final rid in requestsByRid.keys)
        if (!_requestsSeen.contains(rid)) rid
    ];
    if (unseen.isEmpty) return;
    _requestsSeen.addAll(unseen);
    await _saveRequestMeta();
  }

  /// Test seam: whether the person has seen [rid]'s pending request.
  @visibleForTesting
  bool debugRequestSeen(String rid) => _requestsSeen.contains(rid);

  /// Hold no more than [maxPendingRequests] that came by a code or a link,
  /// and apart from them no more than [maxPendingHandleRequests] that came
  /// through the handle: in each, the oldest the person has not seen goes
  /// first, by arrival here — and with it its mark, so a flood of one-off
  /// identities cannot grow the marks either. A request the person has seen
  /// is never pushed out: the newest arrival is never seen, so there is
  /// always an unseen one to go, and were there none the list would stay
  /// one over rather than lose something the person has looked at.
  Future<void> _capRequests() async {
    for (final viaHandle in [false, true]) {
      final cap = viaHandle ? maxPendingHandleRequests : maxPendingRequests;
      while (true) {
        final door = [
          for (final r in requestsByRid.values)
            if ((r.via != null) == viaHandle) r
        ];
        if (door.length <= cap) break;
        PendingRequest? out;
        for (final r in door) {
          if (_requestsSeen.contains(r.rid)) continue;
          if (out == null || r.createdMs < out.createdMs) out = r;
        }
        if (out == null) break;
        await _removeRequest(out.rid);
      }
    }
  }

  /// Seal a signed request to [contact] and queue it. It travels outside any
  /// ratchet (there is none yet) and is recognised by the receiver before it
  /// would be dropped as an unknown sender. [ia]: the introduction
  /// acknowledgement an acceptance of a handle request carries (§21.7).
  Future<void> _sendContactRequest(Contact contact, {String? ia}) async {
    // Not under the send lock (there is no session yet), so the membership
    // check is the whole fence here: a request queued for someone deleted
    // in the meantime would put their routing id back in `outbox`.
    if (!contacts.containsKey(contact.rid)) return;
    final key = _sealKeys[contact.rid];
    if (key == null) return;
    final anchor = await _requestAnchor();
    final req = await ContactRequest.create(
        me: identity,
        toRid: contact.rid,
        displayName: displayName,
        root: anchor?.root,
        cert: anchor?.cert,
        ia: ia);
    final sealed = await SealedEnvelope.seal(
        toXPub: key, fromRid: myRid, payload: req.encode());
    await vault.db.insert('outbox', {
      'id': newMessageId(),
      'rid': contact.rid,
      'payload': sealed,
      'created_ms': _now(),
    });
    unawaited(flushOutbox());
  }

  /// Test seam: send requests as a build from before phase 33 did — from
  /// this device alone, with nothing to say which account it is a device of.
  @visibleForTesting
  bool debugPlainContactRequests = false;

  /// What a request from this device names as its account (§8.1): on a
  /// device that does not hold the root, the root's bundle (§10
  /// `hostbundle`, or self-synced, [_applyOwnDeviceList]) and this device's
  /// certificate — so the person who accepts holds the account, under its
  /// root's routing id, as if the phone had asked. Null on the root, whose
  /// own bundle already IS the account; and on a linked device that does
  /// not hold its root's bundle yet, whose request is then the device's own
  /// and is made the account's in-band ([_reanchorFromList]).
  Future<({ContactBundle root, DeviceCertificate cert})?>
      _requestAnchor() async {
    if (debugPlainContactRequests) return null;
    final me = await accountIdentity();
    if (me.holdsAccountRoot) return null;
    final stored = await vault.kvGet(rootBundleKey);
    if (stored == null) return null;
    try {
      final root = ContactBundle.fromJson(
          (jsonDecode(stored) as Map).cast<String, Object?>());
      return (root: root, cert: me.deviceCert);
    } catch (_) {
      return null;
    }
  }

  /// The contact this vault holds for [account], under whichever routing
  /// id — the device they were added from, which for a person added from
  /// their laptop is the laptop (§18.7).
  Contact? _contactOfAccount(Uint8List account) {
    for (final c in contacts.values) {
      if (constantTimeEquals(c.accountEd, account)) return c;
    }
    return null;
  }

  /// A `creq` arrived — sealed, but with no session, so it is handled before
  /// the unknown-sender drop. Signed by the identity it names, addressed to us,
  /// and sealed by that same identity: a forged "X wants to connect" cannot
  /// pass [ContactRequest.verify].
  ///
  /// Phase 33, three things more. A request that names its account (§8.1,
  /// [ContactRequest.anchor]) is held as that account's — under its root's
  /// routing id and bundle, as if the root had sent it — so accepting it adds
  /// the person, not their laptop. A request from someone already held under
  /// another of their devices is their answer, as one from the same device
  /// always was. And a request is the account's, not this device's: it is
  /// passed to this account's other devices ([mirroredBy] is the device that
  /// passed it here), which hold it as pending too (§18.8).
  Future<void> _onContactRequest(String from, ContactRequest req,
      {String? mirroredBy}) async {
    if (mirroredBy == null) {
      if (!await req.verify(expectedTo: myRid, sealedFrom: from)) return;
    } else {
      // Passed on by one of my devices: addressed to THAT device (or another
      // of mine), and signed by whoever asked, as when it arrived there. The
      // sealed sender was that device's to check, and it checked it.
      if (req.toRid == myRid || !_myAccountRids.contains(req.toRid)) return;
      if (!await req.verify(expectedTo: req.toRid)) return;
    }
    final sender = await req.fromRid();
    final anchor = await req.anchor();
    final bundle = anchor?.root ?? req.bundle;
    final rid = await bundle.routingId();
    if (_blocked.contains(rid) || _blocked.contains(sender)) return; // silence
    if (_myAccountRids.contains(rid) || _myAccountRids.contains(sender)) {
      return; // one of my own devices: nothing to accept
    }
    // Phase 38 (§21.7): the acceptance of a request this device sent to a
    // handle carries the introduction key's acknowledgement. One that
    // verifies against a request still waiting here — that introduction key,
    // this device, the account this creq is signed by, that request — is the
    // answer to it. One that does not (absent, forged, made for another
    // account) is ignored, and this creq is what it would be without it. A
    // request another of my devices passed on is not an answer to one of
    // this device's.
    final ia = req.ia;
    final handles = _handles;
    final answered = mirroredBy != null || ia == null || handles == null
        ? null
        : await handles.matchAcknowledgement(
            ia: ia, ownerAccountEdPub: req.bundle.edPub);
    final known = contacts[rid] ??
        contacts[sender] ??
        _contactOfAccount(anchor?.accountEdPub ?? req.bundle.edPub);
    if (known != null) {
      // Already a contact: this is their ACCEPTANCE of a request we sent (or
      // the duplicate on a mutual scan) — from the device we added, or from
      // another device of the same account. Stop waiting on them, and — if
      // we are the side that opens the session — re-poke the hello they may
      // have dropped before they had added us. Passed on by another of my
      // devices, it was that device's to answer.
      if (mirroredBy != null) return;
      await _clearRequested(known.rid);
      await _pokeHello(known);
      if (answered != null) await _noteHandleAccepted(known.rid, answered);
      return;
    }
    if (answered != null) {
      await _addFromHandleAcceptance(rid, req, answered);
      return;
    }
    if (await _declinedSince(rid, req.ts)) return; // declined, here or there
    // Passed on: held only if nothing here holds it yet. A request that came
    // to this device itself outranks one passed on, because this device is
    // the one its sender holds and the one that answers it ([acceptRequest]).
    if (mirroredBy != null && requestsByRid.containsKey(rid)) return;
    // ADR 0024: the signed `ts`. Too old or too far ahead is refused, and so
    // is one no newer than the last request taken in from them — the copy of
    // a request already declined, or still pending, that the relay hands
    // over again, or an older one arriving late. In silence, as a decline.
    final arrived = _now();
    if (arrived - req.ts > requestMaxAge.inMilliseconds ||
        req.ts - arrived > requestMaxSkew.inMilliseconds) {
      return;
    }
    final mark = _requestMarks[rid];
    if (mark != null && req.ts <= mark) return;
    final name = (req.bundle.displayName?.trim().isNotEmpty ?? false)
        ? req.bundle.displayName!.trim()
        : 'Unknown';
    final now = _lastRequestMs = max(arrived, _lastRequestMs + 1);
    await vault.db.insert(
        'requests',
        {
          'rid': rid,
          'enc_bundle': await vault.seal(jsonEncode(bundle.toJson())),
          'enc_name': await vault.seal(name),
          'created_ms': now,
        },
        conflictAlgorithm: ConflictAlgorithm.replace);
    if (mirroredBy == null) {
      await vault.kvDelete('reqto_$rid');
    } else {
      await vault.kvPut('reqto_$rid', req.toRid);
    }
    // The newest request from them is this one, and it did not come through
    // the handle: accepting it is today's accept, with no acknowledgement.
    await handles?.forgetInbound(rid);
    requestsByRid[rid] =
        PendingRequest(rid: rid, name: name, bundle: bundle, createdMs: now);
    _requestMarks[rid] = req.ts;
    // A newer request from someone already on the list is new to look at.
    _requestsSeen.remove(rid);
    await _capRequests();
    await _saveRequestMeta();
    notifyListeners();
    if (mirroredBy == null) {
      unawaited(_sync
              ?.mirror(
                  threadRid: '',
                  dir: 'contact',
                  inner: InnerMessage(
                      kind: 'creq',
                      mid: newMessageId(),
                      ts: now,
                      data: {'req': req.encode()}))
              .then((_) {}, onError: (_) {}) ??
          Future<void>.value());
    }
  }

  /// How long a decline outranks a request made before it (§18.8):
  /// [requestMaxAge], the age past which a request is refused whatever else
  /// is true (ADR 0024). It was the relay's queue lifetime, 72 hours, on the
  /// view that a request older than its decline that had not arrived by then
  /// never would — but a relay can keep a copy and hand it over later, which
  /// ADR 0024 is about, and on a device the decline reached first the
  /// request would then be shown again.
  static const Duration _declineHold = requestMaxAge;

  /// Whether a request made at [ts] (its signed time) for [rid] was declined
  /// after it was made — on this device or, by `cdecl`, on another.
  ///
  /// A decline has to outlast the request it answers because the two do not
  /// arrive in order: a request one device passes on and the decline another
  /// sends after it reach a third device in one flush, and each is opened
  /// and decrypted on its own, so the decline can be read first, find
  /// nothing to remove, and leave the request it declined to arrive and be
  /// shown. A block needs no such record: it is the block list. A request
  /// made after the decline is a new one and is shown, as a new request
  /// always was (ADR 0011).
  Future<bool> _declinedSince(String rid, int ts) async {
    final at = int.tryParse(await vault.kvGet('reqdecl_$rid') ?? '');
    if (at == null) return false;
    if (_now() - at > _declineHold.inMilliseconds) {
      await vault.kvDelete('reqdecl_$rid');
      return false;
    }
    return ts <= at;
  }

  /// Tell this account's other devices what became of a request (§18.8):
  /// `cdecl` or `cblock`, naming the routing id it was held under. Accepting
  /// is told by the contact itself (`cadd`, [_mirrorContact]).
  void _mirrorRequestOutcome(String kind, String rid) {
    unawaited(_sync
            ?.mirror(
                threadRid: '',
                dir: 'contact',
                inner: InnerMessage(
                    kind: kind, mid: newMessageId(), ts: _now(), data: {'rid': rid}))
            .then((_) {}, onError: (_) {}) ??
        Future<void>.value());
  }

  /// Phase 38: the owner of a handle this device asked accepted, and said so
  /// with the introduction key (§21.7) — add them as a contact, at the
  /// classical floor and unverified, exactly as accepting their request
  /// would; record the handle they came through; say what it means in the
  /// chat; and hand them a request back, which is how a hello of theirs that
  /// arrived before this device held them gets sent again (ADR 0011).
  Future<void> _addFromHandleAcceptance(
      String rid, ContactRequest req, OutgoingHandleRequest answered) async {
    final name = (req.bundle.displayName?.trim().isNotEmpty ?? false)
        ? req.bundle.displayName!.trim()
        : 'Unknown';
    final contact =
        Contact(rid: rid, bundle: req.bundle, name: name, createdMs: _now());
    final claimed = await _withLock<bool>(rid, () async {
      if (contacts.containsKey(rid)) return false;
      await vault.db.insert(
          'contacts',
          {
            'rid': rid,
            'enc_bundle': await vault.seal(jsonEncode(contact.bundle.toJson())),
            'enc_name': await vault.seal(contact.name),
            'ttl_seconds': 0,
            'verified': 0,
            'created_ms': contact.createdMs,
            'requested': 0, // they accepted us; nobody is waiting
          },
          conflictAlgorithm: ConflictAlgorithm.replace);
      await vault.db.delete('blocked', where: 'rid = ?', whereArgs: [rid]);
      _blocked.remove(rid); // in memory too, which ADR 0024's checks read
      // Which handle they came through, before they are anybody's contact:
      // the record is never visible without it.
      await vault.kvPut('hvia_$rid', answered.handle);
      contacts[rid] = contact;
      return true;
    });
    if (!claimed) return;
    await _onContactAdded(contact);
    await _noteHandleAccepted(rid, answered);
    await _sendContactRequest(contact);
  }

  /// The contact [rid] is the account the handle [answered] introduced:
  /// remember which handle, stop waiting, and say so in the chat — "accepted,
  /// compare safety numbers to verify", because the acknowledgement proves
  /// which account answered and nothing about who it is.
  Future<void> _noteHandleAccepted(
      String rid, OutgoingHandleRequest answered) async {
    await vault.kvPut('hvia_$rid', answered.handle);
    await _insertSystemMessage(
        rid, systemBody(SystemKind.handleAccepted, {'h': answered.handle}));
    await handles.completeOutgoing(answered);
    notifyListeners();
  }

  /// The handle a contact was made through — an acceptance that carried the
  /// acknowledgement of a request this device sent to it — or null.
  Future<String?> handleViaOf(String rid) => vault.kvGet('hvia_$rid');

  /// Accept a pending request: add the requester as a contact — at the
  /// classical floor, exactly as scanning their code would — and hand them a
  /// request back, so their side stops waiting and the session establishes both
  /// ways. The account identity and post-quantum key follow in-band (§18.2).
  ///
  /// Phase 38: a request that came through the handle is answered with the
  /// introduction key's acknowledgement on that request back (§21.7), and
  /// it goes FIRST — the first message this account sends them — so that
  /// their app holds this account as a contact before the hello arrives.
  Future<Contact?> acceptRequest(String rid) async {
    final pending = requestsByRid[rid];
    if (pending == null) return contacts[rid];
    // §18.8 (phase 33): a request another of my devices passed on was sent
    // to THAT device, which is the one its sender holds, so that device
    // answers it — when the contact added here reaches it — and this one
    // does not: an answer from a device they never added is, to a build
    // from before phase 33, a second request. One this device received
    // itself it answers now, as always. Read before the add, which clears it.
    final addressedHere = await vault.kvGet('reqto_$rid') == null;
    // Signed before anything below forgets which mailbox the request reached.
    // The account key it names is this device's own key, which is what the
    // acceptance is signed with and carries as its bundle — the account key
    // itself, since only the primary device holds a handle (§21.8).
    final ia = pending.via == null
        ? null
        : await _handles?.acknowledgement(rid,
            ownerAccountEdPub: identity.edPub);
    final contact = Contact(
      rid: rid,
      bundle: pending.bundle,
      name: pending.name,
      createdMs: DateTime.now().millisecondsSinceEpoch,
    );
    final claimed = await _withLock<bool>(rid, () async {
      if (contacts.containsKey(rid)) return false;
      await vault.db.insert(
          'contacts',
          {
            'rid': rid,
            'enc_bundle': await vault.seal(jsonEncode(contact.bundle.toJson())),
            'enc_name': await vault.seal(contact.name),
            'ttl_seconds': 0,
            'verified': 0,
            'created_ms': contact.createdMs,
            'requested': 0, // we accepted; we are not the one waiting
          },
          conflictAlgorithm: ConflictAlgorithm.replace);
      await vault.db.delete('blocked', where: 'rid = ?', whereArgs: [rid]);
      _blocked.remove(rid);
      contacts[rid] = contact;
      return true;
    });
    if (claimed) {
      if (ia != null) {
        _sealKeys[rid] = contact.bundle.xPub;
        await _sendContactRequest(contact, ia: ia);
        await _onContactAdded(contact); // also removes the pending request
      } else {
        await _onContactAdded(contact); // also removes the pending request
        if (addressedHere) await _sendContactRequest(contact);
      }
    } else {
      await _removeRequest(rid);
    }
    notifyListeners();
    return contacts[rid];
  }

  // ---- HandleHost (phase 38) ----------------------------------------------

  @override
  String get relayUrl => transport.serverUrl;

  @override
  bool get holdsRoot => _holdsRoot;

  @override
  Future<void> sendStamped(
          {required String to,
          required String id,
          required String payload,
          required String pow}) =>
      transport.sendStamped(to: to, id: id, payload: payload, pow: pow);

  @override
  bool isTransientFailure(Object e) => _isTransientInboundFailure(e);

  @override
  void handlesChanged() => notifyListeners();

  /// A verified request that reached the introduction mailbox for [handle]:
  /// filed beside every other pending request, saying which handle it came
  /// through. Dropped like any other from someone blocked; from a contact it
  /// is what a contact's request always is — their answer (ADR 0011). And
  /// held to what every other request is held to (ADR 0024): its signed
  /// `ts` and the mark of the last request taken in from them — so a
  /// stamped request the relay hands over again after a drain, or one
  /// declined, does not come back — and the cap on pending handle requests
  /// ([maxPendingHandleRequests]), which pushes out the oldest unseen that
  /// came through the handle and never one that came by a code or a link.
  /// False when it was not filed, or the cap pushed it straight out again.
  @override
  Future<bool> addHandleRequest(ContactRequest request,
      {required String requesterRid, required String handle}) async {
    final rid = requesterRid;
    if (_blocked.contains(rid) || _myAccountRids.contains(rid)) return false;
    final known = contacts[rid];
    if (known != null) {
      await _clearRequested(rid);
      await _pokeHello(known);
      return false;
    }
    if (await _declinedSince(rid, request.ts)) return false;
    final arrived = _now();
    if (arrived - request.ts > requestMaxAge.inMilliseconds ||
        request.ts - arrived > requestMaxSkew.inMilliseconds) {
      return false;
    }
    final mark = _requestMarks[rid];
    if (mark != null && request.ts <= mark) return false;
    final name = (request.bundle.displayName?.trim().isNotEmpty ?? false)
        ? request.bundle.displayName!.trim()
        : 'Unknown';
    final now = _lastRequestMs = max(arrived, _lastRequestMs + 1);
    await vault.db.insert(
        'requests',
        {
          'rid': rid,
          'enc_bundle': await vault.seal(jsonEncode(request.bundle.toJson())),
          'enc_name': await vault.seal(name),
          'created_ms': now,
        },
        conflictAlgorithm: ConflictAlgorithm.replace);
    await vault.kvDelete('reqto_$rid');
    requestsByRid[rid] = PendingRequest(
        rid: rid,
        name: name,
        bundle: request.bundle,
        createdMs: now,
        via: handle);
    _requestMarks[rid] = request.ts;
    _requestsSeen.remove(rid);
    await _capRequests();
    await _saveRequestMeta();
    notifyListeners();
    return requestsByRid.containsKey(rid);
  }

  /// Decline a pending request: drop it, in silence to the sender (ADR 0011)
  /// — on every device of this account (§18.8, phase 33). Its mark stays
  /// (ADR 0024), so the relay handing the same request over again does not
  /// put it back in front of the person; a NEW request from them, made
  /// later, is shown — declining is not blocking.
  Future<void> declineRequest(String rid) async {
    await vault.kvPut('reqdecl_$rid', '${_now()}');
    await _removeRequest(rid, keepMark: true);
    _mirrorRequestOutcome('cdecl', rid);
    notifyListeners();
  }

  /// Block a routing id: drop this request and every future one from it without
  /// a trace — on every device of this account (§18.8, phase 33). A block
  /// held on one device only let the person reach another: the laptop,
  /// whose code they could scan as easily as the phone's.
  Future<void> blockRequest(String rid) async {
    await vault.db.insert('blocked', {'rid': rid, 'created_ms': _now()},
        conflictAlgorithm: ConflictAlgorithm.replace);
    _blocked.add(rid);
    await _removeRequest(rid);
    await vault.kvDelete('reqdecl_$rid');
    _mirrorRequestOutcome('cblock', rid);
    notifyListeners();
  }

  /// [rid]'s request goes from the list, with the record of which of my
  /// devices it was sent to ([acceptRequest]). Its mark goes too unless
  /// [keepMark] — a decline, whose request must not come back (ADR 0024);
  /// an accepted requester is a contact, whose requests fold, and a blocked
  /// one is refused before any mark is read.
  Future<void> _removeRequest(String rid, {bool keepMark = false}) async {
    await vault.db.delete('requests', where: 'rid = ?', whereArgs: [rid]);
    await vault.kvDelete('reqto_$rid');
    requestsByRid.remove(rid);
    final hadMeta = _requestsSeen.remove(rid) |
        (!keepMark && _requestMarks.remove(rid) != null);
    if (hadMeta || keepMark) await _saveRequestMeta();
    await _handles?.forgetInbound(rid);
  }

  /// Clear "waiting for them to accept" once they have answered.
  Future<void> _clearRequested(String rid) async {
    final c = contacts[rid];
    if (c == null || !c.requested) return;
    c.requested = false;
    await vault.db
        .update('contacts', {'requested': 0}, where: 'rid = ?', whereArgs: [rid]);
    notifyListeners();
  }

  /// When we last re-poked an opening hello per contact. Kept SEPARATE from
  /// `_helloSentMs` (the undecryptable-repair limiter) on purpose: a poke must
  /// not suppress that repair, nor be suppressed by it, and it must not touch
  /// `debugHellos`, which counts only the repair path.
  final Map<String, int> _pokeSentMs = {};

  /// Routing ids we have received a decryptable message from this run — i.e.
  /// the session is established. Used only to skip a redundant re-poke; nothing
  /// depends on it for correctness, so it need not persist.
  final Set<String> _heardFrom = {};

  /// Re-send our opening hello when a peer signals (with a request) that they
  /// have added us but our first hello may have been dropped — only if we are
  /// the designated initiator (so the two sides never both open), we have not
  /// already heard from them (the hello would then be redundant traffic), and
  /// not too soon after the last poke.
  Future<void> _pokeHello(Contact contact) async {
    if (_heardFrom.contains(contact.rid)) return;
    final conv = await _convFor(contact);
    if (!conv.isDesignatedInitiator) return;
    final now = _now();
    if (now - (_pokeSentMs[contact.rid] ?? 0) <
        helloMinInterval.inMilliseconds) {
      return;
    }
    _pokeSentMs[contact.rid] = now;
    await _sendInner(contact, InnerMessage.hello(newMessageId(), now));
  }

  /// Announce a contact to my account's other devices (13.7).
  ///
  /// Contacts used to travel only at LINK time (`contactsAsBundles`), so one
  /// added afterwards existed on exactly one device and the others dropped
  /// that person's messages as an unknown sender. This closes that, over the
  /// same self-sync channel the device list already uses.
  Future<void> _mirrorContact(Contact c) async {
    await _sync?.mirror(threadRid: '', dir: 'contact', inner: _contactInner(c));
  }

  InnerMessage _contactInner(Contact c) => InnerMessage(
        kind: 'cadd',
        mid: newMessageId(),
        ts: _now(),
        data: {
          'rid': c.rid,
          'bundle': c.bundle.toJson(),
          'name': c.name,
          if (c.pqCommit != null) 'pqc': b64(c.pqCommit!),
          if (c.accountEdPub != null) 'acct': b64(c.accountEdPub!),
          if (c.deviceCert != null) 'cert': c.deviceCert!.toJson(),
          // Deliberately NOT sent: `verified`/`verified_sn`. A tick records
          // that THIS user compared a number while holding THIS device; it is
          // not a fact one device can assert to another, and forwarding it
          // would let a rogue device inject a contact that already looks
          // checked. Linking is the one exception (§10 `cstate`, phase 33):
          // the root hands the tick over in the enrolment, on the channel
          // the user's own two screens just confirmed, to the device that
          // takes its whole account from that same payload — and any linked
          // device can send this record.
          if (c.pqPub != null) 'pqk': b64(c.pqPub!),
        },
      );

  /// A contact announced by one of MY devices (13.7).
  ///
  /// **Insert-only, and never an update.** A linked device is already trusted
  /// to read this account's messages and send as it, but it does not hold the
  /// account root and so cannot enroll devices. Letting it REPLACE a contact
  /// record would give it something strictly worse than either: silently
  /// re-pointing a name the user has already verified at keys of its
  /// choosing, with no scan and nothing on screen to notice. So an rid this
  /// device already holds is left exactly as it is.
  ///
  /// What remains is that a rogue device can make a NEW chat appear. That is
  /// bounded rather than eliminated — any device can add a contact, because
  /// the user scans on whichever one is in their hand — so the record is
  /// stored unverified and stamped with the device that sent it, and the
  /// contact screen says so.
  ///
  /// Phase 33 (§18.8): requests are the account's too. A request one of my
  /// devices received is passed on as `creq` and held as pending here; one
  /// declined there goes here (`cdecl`), one blocked there is blocked here
  /// (`cblock`); and one accepted there arrives as the contact (`cadd`),
  /// which settles it here — and if it was sent to THIS device, this device
  /// answers it ([acceptRequest]). None of the three carries a `bundle`, so
  /// a build from before them, which took any record with one for a
  /// contact, passes them by.
  Future<void> _applyMirroredContact(
      String fromDeviceRid, InnerMessage inner) async {
    switch (inner.kind) {
      case 'creq':
        final raw = inner.data['req'];
        final req = raw is String ? ContactRequest.tryParse(raw) : null;
        if (req != null) {
          await _onContactRequest('', req, mirroredBy: fromDeviceRid);
        }
        return;
      case 'cdecl':
        final r = inner.data['rid'];
        if (r is! String || r.isEmpty || r.length > 256) return;
        if (contacts.containsKey(r) || _myAccountRids.contains(r)) return;
        // Recorded whether or not the request is here yet ([_declinedSince]).
        final declined = min(inner.ts, _now());
        await vault.kvPut('reqdecl_$r', '$declined');
        // And as this device's mark for them (ADR 0024): a request no newer
        // than the decline — a copy of the one declined there, delivered
        // here before or after this — is refused here as it is there, for
        // as long as the age rule would take it in at all.
        _requestMarks[r] = max(_requestMarks[r] ?? 0, declined);
        if (requestsByRid.containsKey(r)) {
          await _removeRequest(r, keepMark: true);
          notifyListeners();
        } else {
          await _saveRequestMeta();
        }
        return;
      case 'cblock':
        final r = inner.data['rid'];
        if (r is! String || r.isEmpty || r.length > 256) return;
        // `contacts` and `blocked` never name one id (ADR 0011): a person
        // held here as a contact is not blocked by another device's word.
        if (contacts.containsKey(r) || _myAccountRids.contains(r)) return;
        await vault.db.insert('blocked', {'rid': r, 'created_ms': _now()},
            conflictAlgorithm: ConflictAlgorithm.replace);
        _blocked.add(r);
        await _removeRequest(r);
        await vault.kvDelete('reqdecl_$r');
        notifyListeners();
        return;
      case 'cadd':
        break;
      default:
        return; // a kind this build does not know
    }
    final rid = inner.data['rid'];
    final bundleJson = inner.data['bundle'];
    if (rid is! String || bundleJson is! Map) return;
    if (_myAccountRids.contains(rid) || contacts.containsKey(rid)) return;
    // Everything below is checks; the claim itself is taken under the lock at
    // the end, because a scan of the same code may be in flight here.
    final ContactBundle bundle;
    try {
      bundle = ContactBundle.fromJson(bundleJson.cast<String, Object?>());
    } catch (_) {
      return;
    }
    // The routing id must be the hash of the key claimed beside it. Every
    // honest path derives one from the other; a record where they disagree is
    // not a sync, it is an assertion about who someone is.
    if (await bundle.routingId() != rid) return;
    if (!await bundle.verify()) return;
    Uint8List? acct;
    DeviceCertificate? cert;
    final a = inner.data['acct'], cj = inner.data['cert'];
    if (a is String && cj is Map) {
      try {
        acct = unb64(a);
        cert = DeviceCertificate.fromJson(cj.cast<String, Object?>());
        // §18.7's rule, re-checked here rather than trusted: the certificate
        // must be this account's, and must be for the device in the bundle.
        if (cert.legacy ||
            !constantTimeEquals(cert.deviceEdPub, bundle.edPub) ||
            !constantTimeEquals(cert.deviceXPub, bundle.xPub) ||
            !await cert.verify(acct)) {
          return;
        }
        // ADR 0022: nor a device that has proved here that it is another
        // account's — as a scan here refuses it ([addContactFromCode]).
        final provenFor = _provenDevices[rid]?.acct;
        if (provenFor != null && provenFor != base64Encode(acct)) return;
      } catch (_) {
        return;
      }
    }
    final pqc = inner.data['pqc'];
    final pqk = inner.data['pqk'];
    final Uint8List? commit = pqc is String ? unb64(pqc) : null;
    // The post-quantum key is checked against the commitment before it is
    // installed, exactly as `_onPqIdentity` checks one that arrives in-band.
    //
    // Everything above this line is a check — the routing id re-derived from
    // the bundle, the bundle's own signature, §18.7's certificate rules — and
    // then `pqk` was taken straight into `Contact.pqPub`, whose doc-comment
    // says in as many words that it is never set from an unverified source,
    // because its being non-null is what `assurance` reports as hybrid. The
    // sender chooses `pqc` and `pqk` together, so a self-consistent pair
    // passed: one compromised linked device — no account root, well inside
    // the T1/T2 model — mirrors a contact with a commitment of its own
    // choosing and the matching key, and the receiving device shows hybrid
    // assurance and a safety number over a key the contact never published.
    //
    // A mismatch is recorded the way the in-band path records it: no key, and
    // `pq_mismatch` set, so the state is durable and the user is told once
    // rather than on every arrival.
    Uint8List? pqPub;
    var pqMismatch = false;
    if (pqk is String && commit != null) {
      try {
        final candidate = HybridPublicKey(
            edPub: acct ?? bundle.edPub, mlPub: unb64(pqk));
        final scanned = ContactBundleV3(
          edPub: acct ?? bundle.edPub,
          xPub: bundle.xPub,
          bindingSig: bundle.bindingSig,
          pqCommit: commit,
        );
        if (await scanned.acceptsPqKey(candidate)) {
          pqPub = candidate.mlPub;
        } else {
          pqMismatch = true;
        }
      } catch (_) {
        // A key of the wrong length is not a usable key, and not evidence of
        // anything either: the commitment stands and the contact waits for a
        // key that matches it.
      }
    }
    final contact = Contact(
      rid: rid,
      bundle: bundle,
      name: (inner.data['name'] as String?)?.trim().isNotEmpty == true
          ? (inner.data['name'] as String).trim()
          : (bundle.displayName ?? 'Unknown'),
      createdMs: _now(),
      pqCommit: commit,
      pqPub: pqPub,
      accountEdPub: acct,
      deviceCert: cert,
      pqMismatch: pqMismatch,
      addedByDevice: await _myDeviceLabel(fromDeviceRid),
    );
    final row = {
      'rid': rid,
      'enc_bundle': await vault.seal(jsonEncode(bundle.toJson())),
      'enc_name': await vault.seal(contact.name),
      'ttl_seconds': 0,
      'verified': 0,
      'created_ms': contact.createdMs,
      if (contact.pqCommit != null) 'pq_commit': b64(contact.pqCommit!),
      if (contact.pqPub != null)
        'enc_pq_pub': await vault.seal(b64(contact.pqPub!)),
      if (pqMismatch) 'pq_mismatch': 1,
      if (acct != null) 'acct_ed': b64(acct),
      if (cert != null) 'dev_cert': jsonEncode(cert.toJson()),
      'added_by': contact.addedByDevice,
    };
    final inserted = await _withLock<bool>(rid, () async {
      if (contacts.containsKey(rid)) return false; // a scan won the race
      await vault.db
          .insert('contacts', row, conflictAlgorithm: ConflictAlgorithm.ignore);
      contacts[rid] = contact;
      return true;
    });
    if (!inserted) return;
    _sealKeys[rid] = bundle.xPub;
    messagesByChat.putIfAbsent(rid, () => []);
    unread.putIfAbsent(rid, () => 0);
    // Phase 33 (§18.8): the account added them, so a request of theirs held
    // here was accepted, and a block of them goes, as an add here lifts one
    // (ADR 0011). A request that was sent to THIS device is answered from
    // it: this is the device its sender holds.
    final wasPending = requestsByRid.containsKey(rid);
    final addressedHere =
        wasPending && await vault.kvGet('reqto_$rid') == null;
    await vault.db.delete('blocked', where: 'rid = ?', whereArgs: [rid]);
    _blocked.remove(rid);
    await vault.kvDelete('reqdecl_$rid');
    if (wasPending) await _removeRequest(rid);
    if (addressedHere) {
      await _sendContactRequest(contact);
      await _pokeHello(contact);
    }
    // ADR 0022: as an add here would ([_onContactAdded]).
    unawaited(_claimAddedDevice(contact).then((_) {}, onError: (_) {}));
    notifyListeners();
  }

  /// A readable name for one of my own devices, from its routing id.
  Future<String> _myDeviceLabel(String deviceRid) async {
    for (final d in await myFullDeviceList()) {
      if (await d.routingId() == deviceRid) return d.deviceId;
    }
    return 'another device';
  }

  /// Assert a contact record to my own devices. Exists so a test can send the
  /// records an honest client never would; nothing in the app calls it.
  @visibleForTesting
  Future<void> debugAssertContactToMyDevices(
      {required String rid,
      required ContactBundle bundle,
      Uint8List? pqCommit,
      Uint8List? pqPub}) async {
    await _sync?.mirror(
        threadRid: '',
        dir: 'contact',
        inner: InnerMessage(
          kind: 'cadd',
          mid: newMessageId(),
          ts: _now(),
          data: {
            'rid': rid,
            'bundle': bundle.toJson(),
            'name': 'asserted',
            // What a compromised linked device would choose: the receiving
            // side must not take either on trust.
            if (pqCommit != null) 'pqc': b64(pqCommit),
            if (pqPub != null) 'pqk': b64(pqPub),
          },
        ));
  }

  /// Mirror [inner] to my own other devices exactly as given, as thread
  /// [threadRid] in direction [dir]. Exists so a test can send what a
  /// modified linked device could — a mirror an honest client never builds;
  /// nothing in the app calls it.
  @visibleForTesting
  Future<void> debugMirrorToMyDevices(
      {required String threadRid,
      required String dir,
      required InnerMessage inner}) async {
    await _sync?.mirror(threadRid: threadRid, dir: dir, inner: inner);
  }

  /// Record (or withdraw) the user's confirmation that they compared numbers.
  ///
  /// The number itself is stored alongside the flag (13.3). Without it the
  /// app knows a number was checked but not which, so when the identity gains
  /// its post-quantum half and the number moves it can neither keep the tick
  /// honestly nor explain why it is dropping one.
  ///
  /// [ceremonyCommit] (26.3): the contact's post-quantum commitment as a
  /// CONNECT ceremony's eight digits covered it (`adr/0009`, §20.4) — passed
  /// only by that ceremony. When it is the commitment this record holds and
  /// the key has not arrived yet, it is kept with the tick: the digits have
  /// already covered the key that will match it, so when that key lands the
  /// tick moves onto the post-quantum number with it instead of asking for a
  /// comparison that was made minutes ago. Any other confirmation, and any
  /// withdrawal, clears it.
  Future<void> setVerified(String rid, bool v,
      {Uint8List? ceremonyCommit}) async {
    final c = contacts[rid];
    if (c == null) return;
    // ADR 0021: confirming the post-quantum number confirms the candidate it
    // was computed over. The number binds both halves of both account keys,
    // so a match says the key that arrived in-band is the key on their
    // screen — the same fact a scanned commitment states, established the
    // same way: a person, a screen, a channel the adversary does not control.
    // It is ESTABLISHED from here: hybrid assurance, usable to check their
    // device list, and it stays if the tick is later withdrawn — withdrawing
    // a tick has never un-established a key, and the number it was compared
    // against does not change.
    //
    // What the number is derived from and what may be promoted are read ONCE,
    // here, before any await, and the number is then derived from that same
    // reading. Reading twice around the derivation is a real hole rather than
    // a tidiness point: the peer's acknowledgement can land in the gap, so the
    // user would confirm the CLASSICAL number on screen and this method would
    // establish a post-quantum key against it — exactly the "green tick over a
    // number nobody compared" that 13.3 exists to prevent.
    final theirs = c.showsPostQuantumNumber ? c.numberKey : null;
    final Uint8List? promoted =
        (v && c.pqPub == null && theirs != null) ? c.pqCandidate : null;
    // 26.3: what the digits covered, kept only while the number recorded is
    // the classical one and the commitment it must match is the one held.
    final held = c.pqCommit;
    final Uint8List? covered = (v &&
            theirs == null &&
            ceremonyCommit != null &&
            held != null &&
            constantTimeEquals(held, ceremonyCommit))
        ? Uint8List.fromList(ceremonyCommit)
        : null;
    final sn = v ? await _safetyNumberOver(c, theirs) : null;
    // Written BEFORE the tick: a tick on disk with no record of what its
    // ceremony covered asks for a comparison again when the key lands — the
    // old behaviour, and the safe way to be wrong — while the reverse leaves
    // a record with no tick behind it, which nothing reads.
    if (covered != null) {
      await vault.kvPut('vpqc_${c.rid}', b64(covered));
    } else if (c.verifiedPqc != null) {
      await vault.kvDelete('vpqc_${c.rid}');
    }
    c.verifiedPqc = covered;
    await vault.db.update(
        'contacts',
        {
          'verified': v ? 1 : 0,
          'verified_sn': sn,
          if (promoted != null) 'enc_pq_pub': await vault.seal(b64(promoted)),
          if (promoted != null) 'enc_pq_cand': null,
        },
        where: 'rid = ?',
        whereArgs: [rid]);
    c.verified = v;
    c.verifiedSn = sn;
    if (promoted != null) {
      c.pqPub = promoted;
      c.pqCandidate = null;
      // §18.9: a device-list signature held back until the key was
      // established can be checked now.
      unawaited(_refreshDeviceAssurance(rid).then((_) {}, onError: (_) {}));
    }
    await _refreshVerification(rid, notify: false);
    notifyListeners();
  }

  /// What the tick is worth right now (13.3) — see [VerificationState].
  ///
  /// Synchronous, so a list row or a chat header can ask on every rebuild.
  VerificationState verificationWith(String rid) =>
      _verification[rid] ?? VerificationState.unverified;

  /// The classification behind [verificationWith].
  ///
  /// "Upgraded" is claimed only when the recorded number is demonstrably the
  /// CLASSICAL number for this pair and the number now shown is the
  /// post-quantum one — over an established key, or (ADR 0021) over a
  /// candidate both sides hold, which is the number whose comparison
  /// confirms it. Any other change is reported as unexplained rather than
  /// assumed benign: the reassuring story is the one an attacker benefits
  /// from, so it has to be earned each time rather than inferred from "the
  /// number is different".
  Future<VerificationState> _computeVerification(String rid) async {
    final c = contacts[rid];
    // Never verified, or a tick with no number behind it — which after
    // [_backfillVerifiedSn] means only that the backfill could not be
    // written. Either way nothing here backs a tick, and no derivation is
    // needed to say so.
    if (c == null || !c.verified || c.verifiedSn == null) {
      return VerificationState.unverified;
    }
    final current = await safetyNumberWith(rid);
    final state = _classifyVerification(c, current,
        await safetyNumber((await accountIdentity()).accountEdPub, c.accountEd));
    // 26.3: the same rule `_tickAfterMove` applies as a key lands, applied
    // here too, so the outcome does not depend on order — a key that landed
    // while a connect ceremony's tick was still being written (the two sides
    // answer the digits independently, and the peer's key can arrive between
    // the add and the tick), or a restart in between. A tick whose ceremony
    // covered the key that is now established moves onto its number.
    final covered = c.verifiedPqc, key = c.hybridKey;
    if (state == VerificationState.upgradedReverify &&
        covered != null &&
        key != null &&
        constantTimeEquals(covered, await key.pqCommitment())) {
      final tick = (state: VerificationState.verified, moveTo: current);
      if (await _writeMovedTick(c, tick)) {
        await _forgetCovered(c, tick);
        _applyTick(c, tick);
        return VerificationState.verified;
      }
    }
    return state;
  }

  /// The judgement itself, given the two numbers — kept synchronous and
  /// separate so it can also be applied at the exact instant an identity is
  /// upgraded, with no await between the key landing and the tick being
  /// reclassified. A window there is a window in which the UI shows a green
  /// tick against a number the user never compared.
  VerificationState _classifyVerification(
      Contact c, String current, String classical) {
    final was = c.verifiedSn;
    if (!c.verified || was == null) return VerificationState.unverified;
    if (was == current) return VerificationState.verified;
    // The classical number is recomputed from the keys held NOW, so "was the
    // classical number" also says the classical half has not moved — and a
    // current number that is not the classical one is the post-quantum one.
    if (was == classical && current != classical) {
      return VerificationState.upgradedReverify;
    }
    return VerificationState.changedUnexpectedly;
  }

  void _setVerificationState(String rid, VerificationState st) {
    if (st == VerificationState.unverified) {
      _verification.remove(rid);
    } else {
      _verification[rid] = st;
    }
  }

  Future<void> renameContact(String rid, String name) async {
    final c = contacts[rid];
    if (c == null) return;
    c.name = name;
    await vault.db.update('contacts', {'enc_name': await vault.seal(name)},
        where: 'rid = ?', whereArgs: [rid]);
    notifyListeners();
  }

  /// Every per-contact family in `kv`, each stored as `<family><rid>`.
  ///
  /// [deleteContact] removes all of them. Until 2026-09-17 it removed none:
  /// the tables went and the `kv` rows stayed — the contact's account key,
  /// every device's public keys, the list version and its signature, the
  /// post-quantum material, the ratchet with their linked devices — each
  /// keyed by the routing id that says whose it is, unsealed where the
  /// family is declared plain, for the life of the install; and a contact
  /// added back met their own stale `cdev_ver_` and had every list below it
  /// refused as a replay (the 2026-09-14 review's finding 8).
  ///
  /// `contact_erasure_test.dart` checks this list against the SOURCE — every
  /// `kvPut` in `lib/` whose key is a family plus a routing id must name a
  /// family here — so the next per-contact key fails in CI rather than
  /// surviving the contact it belongs to.
  static const List<String> contactKvFamilies = [
    'cdev_', 'cdev_ver_', 'cdev_at_', 'cdev_sigfloor_', 'cdev_pq_',
    'cdev_pq_ver_', 'cdl_alert_', 'cdl_claims_', 'cextra_', 'dlpq_sent_',
    'ktc_', 'last_open_', 'pql_alert_',
    'pqcc_', 'pqcs_', 'vpqc_', // ADR 0027 and 26.3: see `Contact`
    // Phase 33: which of my devices a pending request was sent to, and when
    // one from them was last declined (§18.8).
    'reqto_', 'reqdecl_',
    'hvia_', // phase 38: the handle a contact was made through
    'cdl_dlr_', // ADR 0029: what each of their devices said it reads
    'rcpt_', // phase 41: receipts owed to them, held (ADR 0028)
  ];

  /// Forget a contact: every row, every blob, every `kv` family, and every
  /// piece of them this process is holding.
  ///
  /// Under the per-contact lock, because a deletion is not the only thing
  /// that writes under a routing id. A send is a sealed envelope and a
  /// ratchet step before it is a row, and it holds this lock for the whole
  /// of it; before 2026-09-20 the deletion took no lock at all, so a send
  /// that was mid-flight committed INTO the sweep — landing after the
  /// `outbox` delete and before or after the `conversations` one, so the
  /// leftovers differed run to run. The CI failure that made this a bug
  /// rather than a flake showed exactly that shape: `outbox.rid` and
  /// `outbox.thread_rid` alone on one attempt, those plus
  /// `conversations.rid` on the next two. Taking the lock puts the sweep
  /// after any send already in flight; the membership check in [_sendInner]
  /// stops one that was queued behind it from writing afterwards. Between
  /// them, "delete contact — nothing locally" (`DATA_MAP.md`) is true no
  /// matter what was in the air when the user pressed it.
  Future<void> deleteContact(String rid) async {
    await _withLock(rid, () => _deleteContactLocked(rid));
    // ADR 0029: one reader fewer; it may have been the last one this
    // account's move was waiting for.
    unawaited(_maybeMoveToV2Only());
  }

  Future<void> _deleteContactLocked(String rid) async {
    // ADR 0028: receipts owed to them go with them, first — nothing below
    // can then put a held one back into the vault or onto the wire.
    _receipts.drop(rid);
    _receiptTimers.remove(rid)?.cancel();
    // A group member, deleted as a contact, is still a member of the group:
    // deleting a contact is not a change to anyone's group. The lists this
    // device issues go on naming them, from the entry kept in the group's
    // own sealed record ([Group.orphans]) for as long as they are in it and
    // I am — without it they were silently dropped from my next list
    // (removing them from the group, for everyone), and an ADMIN dropped so
    // made every member refuse my lists, for good (ADR 0019). A group I have
    // left issues no lists and needs no entry: it lets go of them instead,
    // as its owner or its list's issuer too ([_forgetInLeft]) — so the plain
    // dialog, shown when no group I am in names them, is the whole truth —
    // and what I last changed in any group stops naming them. What a group
    // I am in still holds of them is what the other dialog lists
    // ([groupsNaming]; `contact_erasure_test` 6–13).
    final c = contacts[rid];
    var changed = false;
    for (final g in groups.values) {
      final mine = g.mine;
      if (mine != null) {
        for (final k in const ['add', 'rm']) {
          final l = mine[k];
          if (l is List && l.remove(rid)) changed = true;
        }
      }
      if (g.left) {
        if (_forgetInLeft(g, {rid})) changed = true;
      } else {
        if (c != null &&
            (g.memberRids.contains(rid) || g.adminRids.contains(rid))) {
          // An admin who has left is still named in `admins` until the owner
          // takes the role: the entry is what marks them as someone I
          // deleted, so that leaving lets go of them there too.
          g.orphans[rid] = {'b': c.bundle.toJson(), 'n': c.name};
          changed = true;
        }
        // ADR 0030: a leave of theirs this group remembers names them, and
        // so does the position of a membership they no longer hold. Both
        // go: deleting a contact keeps nothing of them that a group I am
        // in does not need to name them — which costs that leave, so a list
        // issued before it that still names them brings them back here
        // (THREAT_MODEL R38).
        if (g.leftAt.remove(rid) != null) changed = true;
        if (!g.memberRids.contains(rid) && g.epochs.remove(rid) != null) {
          changed = true;
        }
      }
    }
    if (changed) await _saveGroups();
    final fids = (await vault.db.query('files',
            columns: ['fid'], where: 'rid = ?', whereArgs: [rid]))
        .map((r) => r['fid'] as String)
        .toList();
    for (final fid in fids) {
      await vault.deleteBlob(fid);
      await vault.db.delete('chunks', where: 'fid = ?', whereArgs: [fid]);
    }
    // Their other devices: each has a routing id of its own that this vault
    // holds beside the contact's, and a dedupe row per envelope from it.
    final extraRids = [
      for (final e in _extraRidToContact.entries)
        if (e.value == rid) e.key
    ];
    await vault.db.delete('files', where: 'rid = ?', whereArgs: [rid]);
    await vault.db.delete('messages', where: 'rid = ?', whereArgs: [rid]);
    await vault.db.delete('reactions', where: 'rid = ?', whereArgs: [rid]);
    await vault.db
        .delete('delivery', where: 'thread_rid = ?', whereArgs: [rid]);
    await vault.db.delete('outbox', where: 'rid = ?', whereArgs: [rid]);
    // Group copies still queued for them: never sendable now (the drain
    // drops a row whose contact is gone), and until it ran each one named
    // them in the clear.
    await vault.db.delete('group_fanout', where: 'rid = ?', whereArgs: [rid]);
    for (final r in [rid, ...extraRids]) {
      await vault.db.delete('outbox', where: 'rid = ?', whereArgs: [r]);
      await vault.db
          .delete('inbox_dedupe', where: 'from_rid = ?', whereArgs: [r]);
    }
    await vault.db.delete('conversations', where: 'rid = ?', whereArgs: [rid]);
    await vault.db.delete('contacts', where: 'rid = ?', whereArgs: [rid]);
    // ADR 0011: any pending request from them is theirs too, so it goes with
    // them; the blocklist is left alone (adding them cleared it, so a deleted
    // contact is never on it, and a genuine block should outlive a delete).
    await vault.db.delete('requests', where: 'rid = ?', whereArgs: [rid]);
    requestsByRid.remove(rid);
    // ADR 0024: and what this device remembered of a request of theirs.
    if ((_requestMarks.remove(rid) != null) | _requestsSeen.remove(rid)) {
      await _saveRequestMeta();
    }
    // Phase 38: and what the handle service kept about that request.
    await _handles?.forgetInbound(rid);
    // ADR 0020: group links waiting on their answer, and answers owed to
    // them, name them too.
    final links = _linkAdds.length + _linkJoins.length;
    _linkAdds.removeWhere((_, r) => r.rid == rid);
    _linkJoins.removeWhere((_, r) => r.rid == rid);
    if (_linkAdds.length + _linkJoins.length != links) await _saveLinks();
    for (final family in contactKvFamilies) {
      await vault.kvDelete('$family$rid');
    }
    contacts.remove(rid);
    _convs.remove(rid);
    messagesByChat.remove(rid);
    unread.remove(rid);
    // And what this process holds about them, so a contact added back
    // starts from nothing rather than from the ratchets, the assurance and
    // the device set that belonged to the one just deleted.
    _contactExtras.remove(rid);
    for (final r in extraRids) {
      _extraRidToContact.remove(r);
      _sealKeys.remove(r);
    }
    _sealKeys.remove(rid);
    _deviceAssurance.remove(rid);
    _devListCoversKeys.remove(rid);
    _verification.remove(rid);
    // ADR 0028: and the receipts owed to them. Dropped before the sweep
    // above; a write of their queue that was already in flight lands before
    // this one, which removes what it wrote.
    _saveReceipts(rid);
    _helloSentMs.remove(rid);
    _pokeSentMs.remove(rid);
    _heardFrom.remove(rid);
    _dlResentAtMs.remove(rid);
    // ADR 0026: what this device asked them about my account, what they
    // handed over, and what it counted against them.
    _pendingOwnerEcho.remove(rid);
    _ownEvidence.remove(rid);
    _ownListAsked.remove(rid);
    _ownListJudged.remove(rid);
    ownEvidenceRefused.remove(rid);
    _ownListAnswered.remove(rid);
    _pqSent.remove(rid);
    _pqAckSent.remove(rid);
    _pqAckInFlight.remove(rid);
    _pqBlindNudged.remove(rid);
    _pqNudges.remove(rid);
    _pqAnswers.remove(rid);
    _pqPending.remove(rid);
    _pqTimers.remove(rid)?.cancel();
    _pqDueMs.remove(rid);
    _pqLastSentMs.remove(rid);
    _pqReqSent.remove(rid);
    _dlpqSent.remove(rid);
    _pqMissingSince.remove(rid);
    _readerLevels.remove(rid); // ADR 0029
    // Whom I asked about a group, and whom I answered: a contact added back
    // is asked and answered afresh.
    for (final asked in _asked.values) {
      asked.remove(rid);
    }
    for (final answered in _answered.values) {
      answered.remove(rid);
    }
    // Another contact's alert can name this one: "<A>'s list names a device
    // <this contact>'s list also names" (§3.4), or one that proved it is
    // theirs (ADR 0022). It is kept, without them — their routing id would
    // otherwise outlive them in the vault.
    for (final e in contactDevlistAlerts.entries.toList()) {
      if (e.key != rid && sharedDeviceAlertOther(e.value) == rid) {
        await _setContactAlert(e.key, withoutAlertOther(e.value));
      }
    }
    // ADR 0022: the devices that proved they are this account's, unless
    // another record of the same account is still held — their routing ids
    // do not outlive the account here either.
    final heldAccounts = {
      for (final c in contacts.values) base64Encode(c.accountEd),
    };
    final provenBefore = _provenDevices.length;
    _provenDevices.removeWhere((_, v) => !heldAccounts.contains(v.acct));
    if (_provenDevices.length != provenBefore) await _saveProvenDevices();
    await kt.noteContactRemoved(rid);
    notifyListeners();
  }

  // ------------------------------------------------------------------
  // 7.7b: the transparency log's host (KtHost). See key_transparency.dart.
  // ------------------------------------------------------------------

  @override
  Future<List<KtContactInput>> ktContacts() async {
    final out = <KtContactInput>[];
    for (final c in contacts.values.toList()) {
      SignedDeviceList? held;
      final stored = await vault.kvGet('cdev_${c.rid}');
      if (stored != null) {
        try {
          held = SignedDeviceList.fromJson(
              (jsonDecode(stored) as Map).cast<String, Object?>());
        } catch (_) {}
      }
      final (hv, hf) = await _heldClaimFor(c);
      out.add(KtContactInput(
        rid: c.rid,
        accountEdPub: c.accountEd,
        held: held,
        heldAtMs: int.tryParse(await vault.kvGet('cdev_at_${c.rid}') ?? ''),
        heldVersion: hv,
        heldFpB64: hf,
        primaryDeviceEdPub: c.bundle.edPub,
      ));
    }
    return out;
  }

  @override
  Future<KtOwnInput?> ktOwn() async {
    final me = await accountIdentity();
    var listJson = await vault.kvGet('own_list_json');
    if (listJson == null && me.holdsAccountRoot) {
      // A root that has never signed a list (one device, version 1) signs
      // its baseline so the account can be in the log at all: once it is,
      // a list that adds a device without being published is the
      // unconfirmed case rather than the unlogged one.
      listJson = await _signCurrentDeviceList();
    }
    final (v, fp) = await _ownListClaim();
    // The devices this account is known, from this device's own records, to
    // have held — what the own-list repair asks of a list (ADR 0026). The
    // log check adds the devices of every entry matching its record.
    final held = <String>{
      b64(me.accountEdPub),
      b64(me.deviceCert.deviceEdPub),
      for (final d in await _myDevices()) b64(d.deviceEdPub),
    };
    if (listJson != null) {
      try {
        final own = SignedDeviceList.fromJson(
            (jsonDecode(listJson) as Map).cast<String, Object?>());
        for (final d in own.devices) {
          held.add(b64(d.deviceEdPub));
        }
      } catch (_) {}
    }
    return KtOwnInput(
      accountEdPub: me.accountEdPub,
      version: v,
      fpB64: fp,
      listJson: listJson,
      accountEdSeed: me.accountEdSeed,
      deviceEdPub: me.deviceCert.deviceEdPub,
      devicesHeld: held,
    );
  }

  @override
  Future<bool> ktInstallFromLog(String rid, SignedDeviceList list) async {
    final contact = contacts[rid];
    if (contact == null) return false;
    // Installed, and still the version held. The held version alone used to
    // answer, which is as true of a list refused AT the held version as of
    // one installed there — and the floor's third level refuses exactly
    // there, so the log check would have confirmed a list it had refused.
    final ok = await _installContactDeviceList(contact, list, persist: true);
    final ver = int.tryParse(await vault.kvGet('cdev_ver_$rid') ?? '0') ?? 0;
    return ok && ver == list.version;
  }

  @override
  void ktChanged() {
    notifyListeners();
    // A transparency conflict lifting (answered, or resolved by the log
    // agreeing) is the moment a held send becomes sendable. The 1:1 mutators
    // queue a held edit/delete/reaction/timer in the fan-out queue; kicking
    // the drain here delivers it without waiting for the next send. Cheap
    // when nothing is held: one query that finds an empty queue.
    if (!_disposed) unawaited(_drainGroupFanout());
  }

  /// Settings: where the log is. Persisted; takes effect at once.
  Future<void> setKtConfig(KtConfig c) => kt.setConfig(c);

  /// v2: true once this device and [rid] share the ML-KEM secret, i.e. every
  /// message from here on is protected against harvest-now-decrypt-later.
  Future<bool> isPostQuantumWith(String rid) async {
    final c = contacts[rid];
    if (c == null) return false;
    return (await _convFor(c)).isPostQuantum;
  }

  /// 26.3: whether the messages of the chat with [rid] are protected by the
  /// post-quantum key exchange right now — on the ratchet with their device,
  /// on each of their other devices', and on the self-sync mirror to each of
  /// this account's own other devices, which carries every message. A
  /// channel counts only when it is post-quantum both ways
  /// (`Conversation.isPostQuantumBothWays`), and one that does not exist yet
  /// counts as not: the screen may say no more than the sessions do.
  ///
  /// Synchronous, read from the sessions in memory, so the screen can ask on
  /// every rebuild — and it is rebuilt by the inbound path, which is where
  /// a session's post-quantum state changes.
  MessagePq messagePqWith(String rid) {
    final mine = _myDevicesPq();
    final extras = _contactExtras[rid];
    final others = extras?.targetRoutingIds ?? const <String>[];
    return MessagePq(
      contact: _convs[rid]?.isPostQuantumBothWays ?? false,
      theirOther: others.length,
      theirOtherPq: others.where((d) => extras!.postQuantumWith(d)).length,
      mine: mine.$1,
      minePq: mine.$2,
    );
  }

  /// 26.3: [messagePqWith] for a group: which members' channels are not all
  /// post-quantum yet, and this account's own devices. A member who is not a
  /// contact here has no channel — nothing is sent to them — and is not
  /// listed.
  GroupMessagePq groupMessagePq(String gid) {
    final g = groups[gid];
    final mine = _myDevicesPq();
    final notYet = <String>[
      for (final rid in g?.memberRids ?? const <String>{})
        if (contacts[rid] != null && !messagePqWith(rid).theirs) rid
    ];
    return GroupMessagePq(notYet: notYet, mine: mine.$1, minePq: mine.$2);
  }

  /// This account's other devices, and how many of their mirrors are
  /// post-quantum both ways.
  (int, int) _myDevicesPq() {
    final sync = _sync;
    if (sync == null) return (0, 0);
    final devices = sync.deviceRoutingIds;
    return (
      devices.length,
      devices.where((d) => sync.postQuantumWith(d)).length,
    );
  }

  /// 7.5b: the current post-quantum generation with [rid] (0 after the first
  /// establishment, +1 per completed re-key). Exposed for diagnostics/tests.
  Future<int> pqGenerationWith(String rid) async {
    final c = contacts[rid];
    if (c == null) return -1;
    return (await _convFor(c)).pqGeneration;
  }

  /// The number two people read to each other to rule out a
  /// man-in-the-middle.
  ///
  /// It is anchored to the ACCOUNT key, never to this device's own key. On a
  /// device that holds the root the two are the same value, so nothing moves
  /// for an account that has never linked anything — but on a linked device
  /// they differ, and using the device key there would mean a phone and a
  /// laptop showing different numbers for the same contact. Someone who
  /// verified on one and then checked on the other would see a mismatch and
  /// conclude they were under attack; and a contact would see the number
  /// change every time a device was added, which makes a real substitution
  /// indistinguishable from someone opening the desktop app. Stability across
  /// device changes is the property that makes verification mean anything
  /// (`z-multidevice-design.md` §3).
  Future<String> safetyNumberWith(String rid) {
    final c = contacts[rid]!;
    // ADR 0021: the post-quantum number is shown over an ESTABLISHED key, or
    // over a candidate once the peer has said it holds ours — the rule in
    // [Contact.showsPostQuantumNumber], which is what keeps the two screens
    // on one number. A candidate's number is not an assurance: it is the
    // thing the comparison checks.
    return _safetyNumberOver(c, c.showsPostQuantumNumber ? c.numberKey : null);
  }

  /// The number for [c] derived from [theirs], or the classical one when it
  /// is null.
  ///
  /// Separate from [safetyNumberWith] because the choice of key and the
  /// derivation must come from ONE reading of the contact. Deriving the
  /// number and then asking again what it was derived from puts an await
  /// between two reads of state the inbound pump can change — see
  /// [setVerified], where that gap would have let a peer's acknowledgement
  /// land after the classical number had been computed and turn the
  /// confirmation of THAT number into the establishment of a post-quantum key
  /// nobody compared.
  Future<String> _safetyNumberOver(Contact c, HybridPublicKey? theirs) async {
    final myMl = theirs == null ? null : await pqAccountPublic();
    if (theirs != null && myMl != null) {
      // v3 (§18.5): both halves of both account keys.
      // Our own ACCOUNT key, never a per-device one, or two devices of one
      // account would show different numbers for the same contact.
      final mine = HybridPublicKey(
          edPub: (await accountIdentity()).accountEdPub, mlPub: myMl);
      return safetyNumberV3(mine, theirs);
    }
    return safetyNumber((await accountIdentity()).accountEdPub, c.accountEd);
  }

  /// ADR 0021: ask [rid] for its post-quantum key if we hold none — the
  /// contact screen calls this when it opens on a classical number, so the
  /// upgrade does not wait for the next message. Bounded like any nudge.
  void requestPqIdentity(String rid) {
    final c = contacts[rid];
    if (c == null || c.pqPub != null || c.pqCandidate != null) return;
    if (c.pqMismatch) return; // a refused key is not asked for again
    // Offline there is nothing to ask with, and arming a timer that will fire
    // into a dead socket only costs a wake-up. Their first traffic when the
    // link returns nudges anyway, which is the path this one short-circuits.
    if (!transport.isConnected) return;
    _offerPqIdentity(c, _PqReason.nudge);
  }

  /// Which safety number [safetyNumberWith] just produced, so the UI can
  /// explain a number that has changed rather than letting it read as a key
  /// substitution — the one failure mode worse than not upgrading at all.
  IdentityAssurance assuranceWith(String rid) =>
      contacts[rid]?.assurance ?? IdentityAssurance.classical;

  /// Sends this account's ML-DSA key (§18.2). It does not fit in the QR that
  /// bound it, so it travels here instead and is checked against the
  /// commitment the other side scanned.
  ///
  /// Sent to every contact, not only those we hold a v3 code for: whether the
  /// RECIPIENT scanned a v3 code of ours is not something the sender can
  /// know, and `contact.pqCommit` answers the opposite question — whether we
  /// scanned theirs. Volunteering it is safe because a delivered key is only
  /// ever accepted against a commitment (`_onPqIdentity`); one that arrives
  /// unasked-for is ignored. It costs ~2 KB of key — a 16 384-bucket
  /// envelope on the wire, the one size ordinary chat almost never has
  /// (`adr/0004`, addendum) — once per contact, at a moment when a burst of
  /// traffic between two previously unrelated mailboxes has already told the
  /// relay a contact was added.
  ///
  /// Once, that is, if it is sent once. Measured (2026-09-11), a mutual add
  /// sent it TWICE each way: the volunteering path and the nudging path both
  /// fired on the same hello, and the nudge fired again on the first envelope
  /// of the reply batch with the peer's key one envelope behind it. Worse,
  /// the case the nudge exists for — an opening that vanished because the
  /// peer had not added us yet — completed only because that same accidental
  /// nudge fired: the answer-in-kind path was gated by "already volunteered",
  /// which is exactly the send that vanished. So the exchange is now this:
  ///
  ///  * an answer — a key arrived without `ack` — goes at once and cancels
  ///    anything waiting, and any send counts as the once-per-contact offer;
  ///  * volunteering (on a hello) waits [pqSendDebounce] for the key that
  ///    usually follows the hello in the same batch, so it becomes an answer
  ///    instead; a nudge (bounded, while a commitment is unmet) waits longer
  ///    — and much longer on the designated initiator, whose key went with
  ///    its hello, so two sides nudging never cross — and either is dropped
  ///    at the last moment if a send went out meanwhile or (a nudge) the key
  ///    it was asking for came;
  ///  * the send carries `ack` when we hold the peer's key, and a key that
  ///    arrives with `ack` is not answered — the peer has ours.
  ///
  /// A mutual add is one 16 KB envelope each way; a vanished opening is
  /// made good by the peer's first key and our answer to it, whatever order
  /// the batch arrived in (`pq_identity_exchange_test.dart`).
  ///
  /// Best-effort, like the opening hello.
  final Set<String> _pqSent = {}; // volunteered once per contact per run
  final Map<String, int> _pqNudges = {}; // re-asks while a commitment is unmet
  final Map<String, int> _pqAnswers = {}; // answers, bounded like nudges
  static const int _maxPqNudges = 3;
  final Map<String, Set<_PqReason>> _pqPending = {};
  final Map<String, Timer> _pqTimers = {};
  final Map<String, int> _pqDueMs = {};
  final Map<String, int> _pqLastSentMs = {};

  /// How long a volunteered send waits for the key that usually follows a
  /// hello. A nudge waits twice this on the side that did not open the
  /// session and twenty times it on the side that did — it sent its key
  /// with the hello, so its nudge matters only against a peer that never
  /// answers, and it must not cross the other side's; a send within ten
  /// times it makes a waiting volunteer or nudge unnecessary.
  @visibleForTesting
  Duration pqSendDebounce = const Duration(milliseconds: 500);

  /// Sends that have begun and not finished. A `pqid` costs a vault read,
  /// an ML-DSA key fetch, a ratchet step and a seal, so "in flight" is a
  /// real interval, not an instant.
  int _pqInFlight = 0;

  /// True while a post-quantum identity send is scheduled OR in flight.
  ///
  /// Test seam, and the thing tests settle on — so it has to be true for the
  /// whole life of a send. Until 2026-09-27 it read `_pqTimers.isNotEmpty`
  /// alone, which is false in two places a send actually occupies: the
  /// ANSWER path never registers a timer at all (it calls [_sendPqIdentity]
  /// directly), and the timer path removes its entry before calling it. A
  /// settle loop polling this could therefore return while an envelope was
  /// still being sealed, and the test that followed would count one fewer
  /// than the exchange really sends — which is the flake a `retry:` was
  /// absorbing. A seam that lies is worse than no seam: it makes every test
  /// built on it unfalsifiable in one direction. A `pqack` (ADR 0021) counts
  /// too: it is part of the same exchange, and a test settling on this means
  /// "the two of them have finished introducing their keys", not "no `pqid`
  /// is in the air".
  @visibleForTesting
  bool get pqSendPending =>
      _pqTimers.isNotEmpty || _pqInFlight > 0 || _pqAckInFlight.isNotEmpty;

  /// `pqid` envelopes actually sent. Test seam.
  @visibleForTesting
  int debugPqSends = 0;

  /// Registers a reason to send our post-quantum identity to [contact]. An
  /// answer goes now and cancels anything waiting; volunteering and nudging
  /// wait, and are dropped at the last moment if a send has gone in the
  /// meantime or (a nudge) the key it was asking for has arrived. The gates
  /// are decided here, when the reason arises; what the send says (`ack`)
  /// is decided when it goes.
  void _offerPqIdentity(Contact contact, _PqReason why) {
    if (_disposed) return;
    final rid = contact.rid;
    switch (why) {
      case _PqReason.answer:
        final n = _pqAnswers[rid] ?? 0;
        if (n >= _maxPqNudges) return;
        _pqAnswers[rid] = n + 1;
        _pqTimers.remove(rid)?.cancel();
        _pqPending.remove(rid);
        _pqDueMs.remove(rid);
        unawaited(_sendPqIdentity(contact).then((_) {}, onError: (_) {}));
        return;
      case _PqReason.volunteer:
        if (!_pqSent.add(rid)) return;
      case _PqReason.nudge:
        if ((_pqNudges[rid] ?? 0) >= _maxPqNudges) return;
    }
    _pqPending.putIfAbsent(rid, () => {}).add(why);
    final delay = why == _PqReason.volunteer
        ? pqSendDebounce
        : pqSendDebounce * (myRid.compareTo(rid) < 0 ? 20 : 2);
    final due = _now() + delay.inMilliseconds;
    // A send already scheduled sooner covers this reason; one scheduled
    // later is brought forward, so a volunteer never waits on a nudge.
    final pending = _pqTimers[rid];
    if (pending != null && (_pqDueMs[rid] ?? 0) <= due) return;
    pending?.cancel();
    _pqDueMs[rid] = due;
    _pqTimers[rid] = Timer(delay, () {
      _pqTimers.remove(rid);
      _pqDueMs.remove(rid);
      final reasons = _pqPending.remove(rid) ?? const <_PqReason>{};
      final now = contacts[rid];
      if (now == null || _disposed) return;
      final sentAgo = _now() - (_pqLastSentMs[rid] ?? 0);
      if (sentAgo < pqSendDebounce.inMilliseconds * 10) {
        return; // a send went out while this waited; it said everything
      }
      if (!reasons.contains(_PqReason.volunteer)) {
        // A nudge alone. It counts against the bound only when it goes.
        if (now.pqPub != null || now.pqCandidate != null) {
          return; // what it was asking for has arrived
        }
        final n = _pqNudges[rid] ?? 0;
        if (n >= _maxPqNudges) return;
        _pqNudges[rid] = n + 1;
      }
      unawaited(_sendPqIdentity(now).then((_) {}, onError: (_) {}));
    });
  }

  Future<void> _sendPqIdentity(Contact contact) async {
    // Counted from before the first await to after the last, so
    // [pqSendPending] covers the whole send and not just the wait for it.
    _pqInFlight++;
    try {
      final mlPub = await pqAccountPublic();
      if (mlPub == null) return;
      _pqSent.add(contact.rid); // any send is the once-per-contact offer
      _pqLastSentMs[contact.rid] = _now();
      debugPqSends++;
      // `ack` (§18.2, ADR 0021): we hold their key — established, or a
      // candidate we are showing or will show the number over. It is what
      // lets THEIR candidate's number be shown, so it must not wait for a
      // commitment we may never hold. A client from before this ADR could
      // only ever mean the established case.
      final ack = debugPreAdr0021
          ? contact.pqPub != null
          : contact.numberKey != null;
      await _sendInner(contact,
          InnerMessage.pqIdentity(newMessageId(), _now(), mlPub, ack: ack));
      if (ack) await _markPqTold(contact);
    } catch (_) {
      // The next reason re-offers it; see _onInbound.
    } finally {
      _pqInFlight--;
    }
  }

  /// ADR 0021: tell [contact] we hold their post-quantum key — a `pqack`, a
  /// few dozen bytes in the smallest envelope bucket, the size of a read
  /// receipt, so unlike a `pqid` it is not a distinctive mark on the relay's
  /// view (§18.2). Sent when a message of theirs finds us holding their key
  /// without our ever having said so: their key arrived WITH `ack` (so no
  /// `pqid` of ours went in answer), or we came to hold it before either side
  /// kept candidates. A `pqid` we send in answer carries the same fact in its
  /// own `ack` and sets the same flag, so only one of the two ever goes.
  ///
  /// Best-effort and bounded by the durable flag: until [Contact.pqTold] is
  /// set this is re-earned on traffic, and once it is set it never fires
  /// again for that contact. The flag bounds the ENVELOPE, not the fact: it
  /// is set when the `pqack` is queued, and one lost at the relay used to be
  /// lost for good — so since 26.2 the fact also rides every message (`pqh`,
  /// [_decorateForWire]), and a peer from before that still gets this.
  final Set<String> _pqAckInFlight = {};

  /// Contacts told this run, whether or not the durable flag could be
  /// written. [_markPqTold] can fail — a full disk, a vault closing — and the
  /// gate that earns a `pqack` is re-tested on every inbound message, so
  /// without an in-memory bound a failing write would buy one envelope per
  /// message received, for ever. `_pqSent` bounds the `pqid` offer the same
  /// way and for the same reason.
  final Set<String> _pqAckSent = {};

  /// Contacts nudged for a key we were never promised (ADR 0021), once each
  /// per run — see the nudge gate in `_onInbound`.
  final Set<String> _pqBlindNudged = {};
  void _offerPqAck(Contact contact) {
    if (_disposed || debugPreAdr0021) return;
    if (!_pqAckSent.add(contact.rid)) return;
    if (!_pqAckInFlight.add(contact.rid)) return;
    unawaited(() async {
      try {
        await _sendInner(contact, InnerMessage.pqAck(newMessageId(), _now()));
        debugPqAcks++; // envelopes that actually went, not attempts
        await _markPqTold(contact);
      } catch (_) {
        // No session to send on yet, or shutting down. Allow exactly one more
        // attempt on later traffic rather than spinning: the send failed, so
        // nothing was said.
        _pqAckSent.remove(contact.rid);
      } finally {
        _pqAckInFlight.remove(contact.rid);
      }
    }());
  }

  /// `pqack` envelopes actually sent. Test seam.
  @visibleForTesting
  int debugPqAcks = 0;

  /// Test-only: behave like a client from before ADR 0021 — drop a
  /// post-quantum key that arrives with no commitment to check it against
  /// (§18.2 as it stood), and never tell a contact that we hold theirs.
  ///
  /// The mixed-version case is the one the display rule exists for, and the
  /// only honest way to run it is to have one side actually behave that way.
  /// `debugSuppressPqList` models a dropped signature for the same reason.
  @visibleForTesting
  bool debugPreAdr0021 = false;

  /// The `pqh` member (26.2): the sender holds our post-quantum key — a
  /// `pqack`'s statement, carried on every message they send (see
  /// [_decorateForWire]). A client running as one from before ADR 0021
  /// neither sends nor heeds it.
  bool _saysHoldsOurKey(InnerMessage inner) =>
      !debugPreAdr0021 && inner.data['pqh'] == 1;

  Future<void> _markPqTold(Contact contact) async {
    if (contact.pqTold || _disposed) return;
    try {
      await vault.db.update('contacts', {'pq_told': 1},
          where: 'rid = ?', whereArgs: [contact.rid]);
    } catch (_) {
      return; // shutting down; their next message earns another
    }
    contact.pqTold = true;
  }

  /// ADR 0021: they hold our key (`ack` on a `pqid`, or a `pqack`). Persist
  /// first, then memory, as everywhere in this exchange. If a candidate is
  /// held, its number becomes the one shown, so the tick is reclassified in
  /// the same step (13.3). Returns false if nothing could be recorded.
  Future<bool> _markPqAcked(Contact contact) async {
    if (contact.pqAcked) return false;
    try {
      if (_disposed) return false;
      await vault.db.update('contacts', {'pq_acked': 1},
          where: 'rid = ?', whereArgs: [contact.rid]);
    } catch (_) {
      return false;
    }
    _Tick? tick;
    final cand = contact.pqCandidate;
    if (cand != null && contact.pqPub == null && !contact.pqMismatch) {
      tick = await _tickAfterMove(
          contact, HybridPublicKey(edPub: contact.accountEd, mlPub: cand));
    }
    if (tick?.moveTo != null && !await _writeMovedTick(contact, tick!)) {
      tick = null; // not written: leave the tick where disk has it
    }
    await _forgetCovered(contact, tick);
    contact.pqAcked = true;
    _applyTick(contact, tick);
    return true;
  }

  /// 13.3: what the tick becomes once the number moves to the post-quantum
  /// one over [key] — worked out BEFORE the change lands, so the key and the
  /// reclassification are one step with no await between them, and nothing
  /// can observe a green tick against a number the user never compared.
  /// Null when no tick is recorded.
  ///
  /// 26.3: a tick recorded by a CONNECT ceremony whose eight digits covered
  /// [key]'s commitment ([Contact.verifiedPqc]) was a comparison of this key
  /// already — the digits bind both commitments, and a commitment binds its
  /// key. So that tick does not ask to be compared again: it moves onto the
  /// post-quantum number (`moveTo`), which the caller writes as
  /// `verified_sn` in the same update that installs the key. Every other tick
  /// is classified as before, so one recorded against a key the digits did
  /// not cover — a classical code's ceremony, a candidate — still asks.
  Future<_Tick?> _tickAfterMove(Contact contact, HybridPublicKey key) async {
    if (!contact.verified || contact.verifiedSn == null) return null;
    final acctEd = (await accountIdentity()).accountEdPub;
    final myMl = await pqAccountPublic();
    final classical = await safetyNumber(acctEd, contact.accountEd);
    final after = myMl == null
        ? classical
        : await safetyNumberV3(
            HybridPublicKey(edPub: acctEd, mlPub: myMl), key);
    final state = _classifyVerification(contact, after, classical);
    final covered = contact.verifiedPqc;
    if (state == VerificationState.upgradedReverify &&
        covered != null &&
        constantTimeEquals(covered, await key.pqCommitment())) {
      return (state: VerificationState.verified, moveTo: after);
    }
    return (state: state, moveTo: null);
  }

  /// Lands what [_tickAfterMove] decided, in memory — after the caller has
  /// written a moved tick to disk, and [_forgetCovered] what it consumed.
  void _applyTick(Contact c, _Tick? tick) {
    if (tick == null) return;
    final moved = tick.moveTo;
    if (moved != null) {
      c.verifiedSn = moved;
      c.verifiedPqc = null;
    }
    _setVerificationState(c.rid, tick.state);
  }

  /// A moved tick has used what its ceremony covered: drop it from disk.
  /// Best-effort — one left behind is never read again, because the tick it
  /// was kept for already stands on the number it was for.
  Future<void> _forgetCovered(Contact c, _Tick? tick) async {
    if (tick?.moveTo == null || c.verifiedPqc == null) return;
    try {
      await vault.kvDelete('vpqc_${c.rid}');
    } catch (_) {}
  }

  /// Writes a moved tick on its own, for the paths that do not install a key
  /// in the same update. False if it could not be written.
  Future<bool> _writeMovedTick(Contact c, _Tick tick) async {
    try {
      if (_disposed) return false;
      await vault.db.update('contacts', {'verified_sn': tick.moveTo},
          where: 'rid = ?', whereArgs: [c.rid]);
      return true;
    } catch (_) {
      return false;
    }
  }

  /// Handles an inbound `pqid`. Returns true if what the contact screen shows
  /// changed, so the caller can notify.
  ///
  /// With a commitment (§18.2): a key that does not match it is REFUSED and
  /// the mismatch recorded — never accepted, and never quietly ignored so the
  /// contact lingers as classical. It means the key that arrived is not the
  /// key the person in front of you committed to.
  ///
  /// Without one (ADR 0021): the key is kept as a CANDIDATE, for the safety
  /// number only. Its arrival upgrades nothing — the identity stays classical
  /// and the key verifies nothing — but the number can now include it once
  /// the peer holds ours too, and comparing that number is what confirms it.
  /// Before this ADR the key was dropped, so a contact added from a classical
  /// code — every accepted request (ADR 0011), every record from before v3 —
  /// could never show the number the other side was showing, and nothing
  /// short of deleting the contact could change that.
  Future<bool> _onPqIdentity(Contact contact, InnerMessage inner) async {
    var changed = false;
    // `ack`: they hold our key. Recorded whatever else this message does — it
    // is what lets a candidate's number be shown, and the arrival of an
    // established key is not the only message that carries it.
    if (inner.data['ack'] == true && await _markPqAcked(contact)) {
      changed = true;
    }
    if (contact.pqPub != null) return changed; // already established
    final raw = inner.data['pk'];
    if (inner.data['alg'] != 'ML-DSA-65' || raw is! String) return changed;
    final HybridPublicKey candidate;
    try {
      candidate = HybridPublicKey(edPub: contact.accountEd, mlPub: unb64(raw));
    } catch (_) {
      return changed; // wrong length: not a usable key
    }
    final commit = contact.pqCommit;
    if (commit == null) {
      if (debugPreAdr0021) return changed; // the old rule: no commitment, no key
      // Nothing was promised, so nothing can be checked — and nothing is.
      // The first key to arrive is the candidate; a later, different one is
      // not evidence of anything (the ratchet authenticated both as this
      // contact's), and swapping would move a number the user may be reading
      // aloud. A refused key is not replaced by a candidate either.
      if (contact.pqCandidate != null || contact.pqMismatch) return changed;
      // ADR 0027: a commitment from an unsigned code of theirs, scanned once
      // they were already held, is a candidate too. Two candidates that agree
      // — the key the ratchet authenticated as theirs, and a commitment to
      // exactly that key — establish it, as a re-scan with a candidate held
      // always has (ADR 0021). Two that disagree are not evidence against
      // the key: only the commitment could have been written by someone
      // else, so it is the commitment that goes, and the key is kept as the
      // candidate it would have been without it.
      final hint = contact.pqcHint;
      if (hint != null) {
        final hinted = ContactBundleV3(
          edPub: contact.accountEd,
          xPub: contact.bundle.xPub,
          bindingSig: contact.bundle.bindingSig,
          pqCommit: hint,
        );
        if (await hinted.acceptsPqKey(candidate)) {
          return await _establishPqKey(contact, candidate, commit: hint) ||
              changed;
        }
        await _setPqcHint(contact, null);
      }
      // If they have already acknowledged ours, the number moves the moment
      // this lands (13.3): reclassify in the same step.
      final tick =
          contact.pqAcked ? await _tickAfterMove(contact, candidate) : null;
      try {
        if (_disposed) return changed;
        await vault.db.update(
            'contacts',
            {
              'enc_pq_cand': await vault.seal(b64(candidate.mlPub)),
              if (tick?.moveTo != null) 'verified_sn': tick!.moveTo,
            },
            where: 'rid = ?',
            whereArgs: [contact.rid]);
      } catch (_) {
        return changed; // shutting down; the key arrives again on traffic
      }
      await _forgetCovered(contact, tick);
      contact.pqCandidate = candidate.mlPub;
      _applyTick(contact, tick);
      return true;
    }
    final scanned = ContactBundleV3(
      edPub: contact.accountEd,
      xPub: contact.bundle.xPub,
      bindingSig: contact.bundle.bindingSig,
      pqCommit: commit,
    );
    if (!await scanned.acceptsPqKey(candidate)) {
      // Refusal is durable state, and it is announced ONCE. The offer is
      // re-made on traffic (§18.2), so every message would otherwise
      // re-insert this warning — burying the thing it wants read under
      // copies of itself, at the request of whoever is sending the bad key.
      if (contact.pqMismatch) return changed;
      try {
        if (_disposed) return changed;
        await vault.db.update('contacts', {'pq_mismatch': 1},
            where: 'rid = ?', whereArgs: [contact.rid]);
      } catch (_) {
        return changed; // shutting down; the next arrival records it
      }
      contact.pqMismatch = true;
      await _insertSystemMessage(contact.rid,
          systemBody(SystemKind.pqMismatch, {'name': contact.name}));
      return true;
    }
    return await _establishPqKey(contact, candidate) || changed;
  }

  /// Installs [key] as [contact]'s ESTABLISHED post-quantum key — it matched
  /// the commitment held, or ([commit]) an unsigned commitment held as a
  /// candidate (ADR 0027), which becomes the commitment with it. False if
  /// nothing could be written.
  Future<bool> _establishPqKey(Contact contact, HybridPublicKey key,
      {Uint8List? commit}) async {
    // The number is about to move, which is the one moment in a contact's
    // life when a tick can go stale (13.3). Work out what it becomes BEFORE
    // installing the key, so the key and the reclassification land together
    // and nothing can observe a green tick against the new number — and so a
    // tick that moves with it (26.3) is written in the same update.
    final tick = await _tickAfterMove(contact, key);
    // Persist FIRST, then update memory. If the write fails the contact stays
    // pending and the key simply arrives again — whereas setting the field
    // first would leave memory claiming hybrid while disk says classical, so
    // a restart would silently downgrade an identity the user had been told
    // was upgraded.
    try {
      if (_disposed) return false;
      await vault.db.update(
          'contacts',
          {
            'enc_pq_pub': await vault.seal(b64(key.mlPub)),
            if (commit != null) 'pq_commit': b64(commit),
            if (tick?.moveTo != null) 'verified_sn': tick!.moveTo,
          },
          where: 'rid = ?',
          whereArgs: [contact.rid]);
    } catch (_) {
      // Shutting down, or the vault is gone. Best-effort: the nudge re-runs
      // the exchange next time.
      return false;
    }
    await _forgetCovered(contact, tick);
    // A hint that matched is the commitment now (ADR 0027). Its row goes
    // before memory changes, and memory changes in one step, so nothing can
    // read an established key beside a hint still held. A row a failed
    // delete leaves behind is never read: a hint is consulted only while no
    // commitment is held.
    if (commit != null) {
      try {
        await vault.kvDelete('pqcc_${contact.rid}');
      } catch (_) {}
      contact.pqCommit = commit;
      contact.pqcHint = null;
    }
    contact.pqPub = key.mlPub;
    _applyTick(contact, tick);
    // §18.9: a device-list signature that arrived before this key was held
    // rather than discarded. It can be checked now.
    unawaited(
        _refreshDeviceAssurance(contact.rid).then((_) {}, onError: (_) {}));
    return true;
  }

  /// Discard all ratchet sessions with this contact and open a fresh one.
  Future<void> resetSecureSession(String rid) async {
    final c = contacts[rid];
    if (c == null) return;
    // Mutating the ratchet must be serialized against in-flight send/receive.
    await _withLock(rid, () async {
      final conv = await _convFor(c);
      conv.resetSessions();
      await _saveConv(rid);
      // The sessions are gone; their cached keys would decrypt nothing.
      await _saveSkipped(rid);
    });
    await _insertSystemMessage(rid, systemBody(SystemKind.sessionReset));
    await _sendInner(c, InnerMessage.hello(newMessageId(), _now()));
    notifyListeners();
  }

  // ------------------------------------------------------------------
  // Sending
  // ------------------------------------------------------------------

  int _now() => DateTime.now().millisecondsSinceEpoch;

  /// Encrypts an inner message, persists ratchet state + outbox atomically,
  /// then kicks the flusher. Returns the message id.
  ///
  /// The whole encrypt→persist sequence runs under the per‑conversation lock
  /// so it can never interleave with another encrypt or with an inbound
  /// decrypt on the same ratchet (which would reuse a message index / key).
  /// If persistence fails, the in‑memory ratchet is rolled back so no send
  /// index is silently skipped.
  /// [threadRid] is where the MESSAGE row lives — a group id for a group
  /// send, the contact otherwise. It is not the mailbox the envelope goes to
  /// ([contact]'s), and the two were conflated: a group message's status
  /// update looked for its row under the member's rid, matched nothing, and
  /// left a grey clock for ever.
  Future<String> _sendInner(Contact contact, InnerMessage inner,
      {Future<void> Function(Transaction txn)? also, String? threadRid}) async {
    // ADR 0006: a conflict between the log and this contact's devices holds
    // what the user says to them until the next check agrees or the user
    // chooses to send anyway. The screen disables the composer first; this
    // is the rule the screen is enforcing.
    if (_ktHeldKinds.contains(inner.kind) && kt.sendsHeld(contact.rid)) {
      throw KtSendHeldException(contact.rid);
    }
    await _withLock(contact.rid, () async {
      // The contact can have been DELETED while this send waited for the
      // lock — [deleteContact] takes the same one. Writing now would put
      // their routing id back in `outbox`, their ciphertext back in the
      // vault and a fresh row back in `conversations`, in a vault that is
      // supposed to have forgotten them (`DATA_MAP.md`: "Delete contact —
      // nothing locally"). There is also nobody to send to: the ratchet,
      // the send key and the device set went with them. So this writes
      // nothing and says the message was accepted, which is what every
      // other send-side failure here does.
      if (!contacts.containsKey(contact.rid)) return;
      final conv = await _convFor(contact);
      // Rollback snapshot WITHOUT the out-of-order key cache. A send never
      // reads or changes that cache, so it does not belong in the thing a
      // send rolls back to — and encoding it here would have left half the
      // cost this split was meant to remove (docs/PERFORMANCE.md). The cache
      // is carried across by hand in the catch block below, from the live
      // object, which still holds the correct pre-send value precisely
      // because a send does not touch it.
      final snapshot = jsonEncode(conv.toJson(includeSkipped: false));
      // v2: if this side owes the peer its post-quantum key offer, it goes
      // out first (silent, ignored by v1 peers).
      final offer = await conv.takePqOfferPayload();
      final offerPayload =
          offer == null ? null : await _sealFor(contact.rid, offer);
      // 7.7a: stamp our device-list claim + an echo of theirs onto the wire.
      await _decorateForWire(inner, contact);
      // ADR 0029, per device: if the recipient's own (root) device is behind
      // — a mix where a linked device is capable but this one is not — the
      // `dl` claim is stripped from its copy, as from an incapable sibling's
      // in the fan ([_fanToContactExtras]). The common case keeps the inner
      // as decorated. The shared `inner` is not mutated: the fan reads it too.
      final rootBytes = (inner.data.containsKey('dl') &&
              _withholdsClaimFromDevice(contact.rid, contact.rid))
          ? _withoutClaim(inner).toBytes()
          : inner.toBytes();
      final payload =
          await _sealFor(contact.rid, await conv.encrypt(rootBytes));
      // Read once and call only if set: `await gate?.call(...)` would await a
      // null and so yield a microtask on EVERY send, which is enough to move
      // the debounce-versus-settle races the PQ exchange tests count
      // envelopes against.
      final gate = debugBeforeSendCommit;
      if (gate != null) await gate(contact.rid);
      try {
        await vault.db.transaction((txn) async {
          await _saveConv(contact.rid, txn: txn);
          if (offerPayload != null) {
            await txn.insert('outbox', {
              'id': newMessageId(),
              'rid': contact.rid,
              'payload': offerPayload,
              'created_ms': _now(),
            });
          }
          await txn.insert('outbox', {
            // The ENVELOPE id, which the relay sees — fresh per row, as
            // PROTOCOL §12.2 has always specified. It used to be the inner
            // `mid`, so a group send handed the relay one identical id
            // addressed to every member's mailbox: membership, deterministic,
            // needing none of R18's timing analysis. And because the mid is
            // plaintext to every member, any one of them could hand the
            // operator a mid and get the recipient set back.
            'id': newMessageId(),
            'mid': inner.mid,
            'thread_rid': threadRid ?? contact.rid,
            'rid': contact.rid,
            'payload': payload,
            'created_ms': _now(),
          });
          if (also != null) await also(txn);
        });
      } catch (e) {
        final restored = await _convFromSnapshot(snapshot);
        // Carry the out-of-order keys over from the object being replaced.
        // Without this the rollback would quietly empty the cache and lose
        // the ability to decrypt messages already in flight — a silent
        // message-loss bug hiding inside an error path.
        for (final e in conv.sessions.entries) {
          restored.sessions[e.key]?.ratchet.skipped
              .addAll(e.value.ratchet.skipped);
        }
        _convs[contact.rid] = restored;
        rethrow;
      }
    });
    // ADR 0028: receipts owed to this person that may go now ride with what
    // the user is sending them — queued behind it, one flush — instead of
    // leaving later at a moment of their own.
    if (_ridingKinds.contains(inner.kind) &&
        _receipts.anyEligible(contact.rid)) {
      await _releaseReceipts(contact.rid, riding: true);
    }
    unawaited(flushOutbox());
    unawaited(
        _fanToContactExtras(contact.rid, inner)); // M4: to their extra devices
    return inner.mid;
  }

  /// Send [inner] to a 1:1 [contact], but if a transparency conflict holds
  /// sends to them (ADR 0006), queue it durably instead of losing it.
  ///
  /// An `edit`, `del`, `react` or `timer` applies to the local copy the
  /// instant the user makes it and only then asks the peer to follow. While
  /// sends are held those four threw [KtSendHeldException] out of [_sendInner]
  /// and were simply dropped: the local copy changed, the peer's never did,
  /// and answering the conflict re-sent nothing — the group path already
  /// queues its fan-out durably and drains it on answer, and the 1:1 path did
  /// not. The queue is the same `group_fanout` table, with the thread and the
  /// recipient both the contact (a 1:1 is a group of one for this purpose);
  /// the drain skips a held row and [ktChanged] kicks it when the hold lifts.
  Future<void> _sendInnerOrHold(Contact contact, InnerMessage inner) async {
    if (_ktHeldKinds.contains(inner.kind) && kt.sendsHeld(contact.rid)) {
      await _queueHeldInner(contact, inner);
      return;
    }
    try {
      await _sendInner(contact, inner);
    } on KtSendHeldException {
      // A conflict appeared between the check above and the send: durable, so
      // answering it delivers this rather than dropping it.
      await _queueHeldInner(contact, inner);
    }
  }

  /// Record a 1:1 inner held by a transparency conflict in the durable
  /// fan-out queue (thread and recipient both the contact) and kick the
  /// drain, which skips it while the hold stands and sends it once it lifts.
  Future<void> _queueHeldInner(Contact contact, InnerMessage inner) async {
    await vault.db.insert(
      'group_fanout',
      {
        'mid': inner.mid,
        'gid': contact.rid, // a 1:1: the thread IS the contact
        'rid': contact.rid,
        'payload': await vault.seal(utf8.decode(inner.toBytes())),
        'created_ms': _now(),
      },
      conflictAlgorithm: ConflictAlgorithm.ignore,
    );
    unawaited(_drainGroupFanout());
  }

  /// [replyTo] (8.1) is the `mid` of a message in this same conversation;
  /// only the id is sent, and it is dropped if it names nothing we hold.
  Future<void> sendText(String rid, String body,
      {String? replyTo, bool forwarded = false}) async {
    final contact = contacts[rid]!;
    final ttl = contact.ttlSec;
    final ts = _now();
    final quoted = await _resolveQuote(rid, replyTo);
    final inner = InnerMessage.text(newMessageId(), ts, body,
        ttlSec: ttl, replyTo: quoted?.mid);
    if (forwarded) inner.data['fw'] = true;
    final expireAt = ttl > 0 ? ts + ttl * 1000 : 0;

    await _sendInner(contact, inner, also: (txn) async {
      await txn.insert('messages', {
        'mid': inner.mid,
        'rid': rid,
        'outgoing': 1,
        'kind': 'text',
        'enc_body': await vault.seal(body),
        'ts_ms': ts,
        'status': MsgStatus.pending,
        'expire_at_ms': expireAt,
        'reply_to': quoted?.mid,
        'forwarded': forwarded ? 1 : 0,
      });
    });

    _appendLoaded(
        rid,
        ChatMessage(
          mid: inner.mid,
          rid: rid,
          outgoing: true,
          kind: 'text',
          body: body,
          ts: ts,
          status: MsgStatus.pending,
          expireAtMs: expireAt,
          replyTo: quoted?.mid,
          quote: quoted,
          forwarded: forwarded,
        ));
    notifyListeners();
    // Mirror to my own other devices (no-op if none linked).
    unawaited(_sync?.mirror(threadRid: rid, dir: 'out', inner: inner) ??
        Future<void>.value());
  }

  /// 7.4: record-and-send convenience — a voice note is an ordinary encrypted
  /// attachment (same keys, chunks, mirroring) whose offer carries `voice` and
  /// `dur`, so receivers render a player instead of a file card.
  Future<void> sendVoiceNote(String rid, Uint8List bytes, int durSec,
          {String mime = 'audio/mp4'}) =>
      sendFile(rid, _voiceNoteName(mime), bytes, mime,
          voice: true, durSec: durSec);

  Future<void> sendFile(
      String rid, String fileName, Uint8List bytes, String mime,
      {bool voice = false,
      int durSec = 0,
      String? replyTo,
      bool forwarded = false}) async {
    if (bytes.length > maxAttachmentBytes) {
      throw const FormatException(
          'attachment too large (max 24 MB in this build)');
    }
    final contact = contacts[rid]!;
    final ttl = contact.ttlSec;
    final ts = _now();
    final quoted = await _resolveQuote(rid, replyTo);
    final km = FileKeyMaterial.generate();
    final chunks = splitChunks(bytes);
    final sha = b64(await sha256Bytes(bytes));

    final inner = InnerMessage(
      kind: 'file',
      mid: newMessageId(),
      ts: ts,
      ttlSec: ttl,
      data: {
        'fid': km.fid,
        'name': fileName,
        'size': bytes.length,
        'mime': mime,
        'sha256': sha,
        'fk': b64(km.fk),
        'fn': b64(km.fn),
        'chunks': chunks.length,
        if (voice) 'voice': true,
        if (durSec > 0) 'dur': durSec,
        if (quoted != null) 'rt': quoted.mid,
        if (forwarded) 'fw': true,
      },
    );
    final expireAt = ttl > 0 ? ts + ttl * 1000 : 0;

    // Local encrypted copy so the sender can re-open their own attachment.
    final keyInfo = await vault.writeBlob(km.fid, bytes);
    final meta = FileMeta(
      fid: km.fid,
      name: fileName,
      size: bytes.length,
      mime: mime,
      sha256b64: sha,
      complete: true,
      gotChunks: chunks.length,
      totalChunks: chunks.length,
      voice: voice,
      durSec: durSec,
    );

    // Pre-encrypt every chunk before the transaction.
    final chunkPayloads = <String>[];
    for (var i = 0; i < chunks.length; i++) {
      chunkPayloads.add(await encryptChunk(km, i, chunks[i]));
    }

    await _sendInner(contact, inner, also: (txn) async {
      await txn.insert('files', {
        'fid': km.fid,
        'rid': rid,
        'mid': inner.mid,
        'enc_meta': await vault.seal(jsonEncode({
          'name': fileName,
          'size': bytes.length,
          'mime': mime,
          'sha256': sha,
          'local': keyInfo,
          if (voice) 'voice': true,
          if (durSec > 0) 'dur': durSec,
        })),
        'complete': 1,
        'got_chunks': chunks.length,
        'total_chunks': chunks.length,
      });
      await txn.insert('messages', {
        'mid': inner.mid,
        'rid': rid,
        'outgoing': 1,
        'kind': 'file',
        'enc_body': await vault.seal(jsonEncode({'fid': km.fid})),
        'fid': km.fid,
        'ts_ms': ts,
        'status': MsgStatus.pending,
        'expire_at_ms': expireAt,
        'reply_to': quoted?.mid,
        'forwarded': forwarded ? 1 : 0,
      });
      for (final p in chunkPayloads) {
        await txn.insert('outbox', {
          'id': newMessageId(),
          'rid': rid,
          // Sealed per recipient; the raw chunk list is reused for the
          // own-device mirror, which seals per device in _syncSend.
          'payload': await _sealFor(rid, p),
          'created_ms': _now(),
        });
      }
    });

    _appendLoaded(
        rid,
        ChatMessage(
          mid: inner.mid,
          rid: rid,
          outgoing: true,
          kind: 'file',
          body: fileName,
          fid: km.fid,
          ts: ts,
          status: MsgStatus.pending,
          expireAtMs: expireAt,
          file: meta,
          replyTo: quoted?.mid,
          quote: quoted,
        ));
    notifyListeners();
    // Mirror to my own other devices: the offer (carrying the file key) over
    // the sync ratchet, then the sealed chunks as sidecar payloads they
    // reassemble exactly as a recipient would. No-op when no devices are linked.
    final sync = _sync;
    if (sync != null) {
      unawaited(() async {
        await sync.mirror(threadRid: rid, dir: 'out', inner: inner);
        for (final p in chunkPayloads) {
          await sync.fanChunk(p);
        }
      }());
    }
  }

  Future<void> setDisappearingTimer(String rid, int seconds) async {
    final contact = contacts[rid]!;
    contact.ttlSec = seconds;
    await vault.db.update('contacts', {'ttl_seconds': seconds},
        where: 'rid = ?', whereArgs: [rid]);
    await _insertSystemMessage(
        rid,
        seconds == 0
            ? systemBody(SystemKind.ttlOffYou)
            : systemBody(SystemKind.ttlSetYou, {'sec': seconds}));
    final inner = InnerMessage.timer(newMessageId(), _now(), seconds);
    await _sendInnerOrHold(contact, inner);
    // 30.3: and on my other devices, so what they send from now on carries
    // it too. It used to stay on the device it was set on: a timer set on
    // the phone did not govern what the laptop sent.
    unawaited(_sync?.mirror(threadRid: rid, dir: 'out', inner: inner) ??
        Future<void>.value());
    notifyListeners();
  }

  // ------------------------------------------------------------------
  // Outbox
  // ------------------------------------------------------------------

  Future<void> flushOutbox() async {
    if (_flushing || !transport.isConnected) return;
    _flushing = true;
    // Mailboxes the relay refused this pass as full: their rows stay where
    // they are, in order, and the pass goes on with everyone else's.
    final full = <String>{};
    // The relay's shared store itself full (`store_full`): nobody's envelope
    // fits right now, so the pass stops and everything waits for the retry.
    var storeFull = false;
    // The relay asked this connection to slow down: not one mailbox's
    // problem and not a reason to wait for a reconnect.
    var rateLimited = false;
    // An unattributable refusal (`internal`, a send timeout, …) while the
    // link is up: stop the pass and come back on a backoff timer, rather than
    // wait for a reconnect.
    var otherRefused = false;
    // Whether this flush delivered anything, so the backoff can reset.
    var sentAny = false;
    try {
      while (true) {
        final rows = full.isEmpty
            ? await vault.db.query('outbox', orderBy: 'seq', limit: 20)
            : await vault.db.query('outbox',
                where:
                    'rid NOT IN (${List.filled(full.length, '?').join(',')})',
                whereArgs: full.toList(),
                orderBy: 'seq',
                limit: 20);
        if (rows.isEmpty) break;
        for (final row in rows) {
          final id = row['id'] as String;
          final rid = row['rid'] as String;
          if (full.contains(rid)) continue; // keep that mailbox's rows in order
          try {
            await transport.send(
                to: rid, id: id, payload: row['payload'] as String);
            await vault.db
                .delete('outbox', where: 'seq = ?', whereArgs: [row['seq']]);
            sentAny = true;
            await _markSentIfLast(row);
          } on RelayException catch (e) {
            if (e.message.contains('too_large') ||
                e.message.contains('bad_send')) {
              // Permanent rejection: drop and surface failure. The message
              // is named by the row's own `mid` and `thread_rid`, not by the
              // envelope id and the mailbox — those were the same string
              // until the envelope id was separated from it, and this line
              // was the one place that still read them as one.
              await vault.db
                  .delete('outbox', where: 'seq = ?', whereArgs: [row['seq']]);
              final failedMid = row['mid'] as String?;
              if (failedMid != null) {
                final thread = row['thread_rid'] as String? ?? rid;
                await vault.db.update('messages', {'status': -1},
                    where: 'mid = ? AND rid = ?', whereArgs: [failedMid, thread]);
                _updateLoadedStatus(thread, failedMid, -1);
              }
            } else if (e.message.contains('queue_full')) {
              // That recipient's mailbox at the relay is at its cap
              // (PROTOCOL §12.4): theirs alone, and temporary — it empties
              // when they next connect. The row waits, still pending, and
              // is tried again shortly; nothing else is held up by it.
              full.add(rid);
            } else if (e.message.contains('store_full')) {
              // The relay's store has no room for anyone right now
              // (§12.4). Temporary: it heals as mailboxes drain. Stop this
              // pass — every row would get the same answer — and let the
              // retry timer bring it back, rather than the next reconnect.
              storeFull = true;
              return;
            } else if (e.message.contains('rate_limited')) {
              // This connection is being told to slow down, which is about
              // the sender and not about any one mailbox. Stop the pass and
              // come back on the retry timer: waiting for the next
              // *reconnect*, as this used to, can be a very long time on a
              // link that is working perfectly well.
              rateLimited = true;
              return;
            } else if (transport.isConnected) {
              // The link is up but the relay refused this envelope for a
              // reason it did not attribute (`internal`, a send timeout, a
              // malformed-frame code). The row stays queued and the relay
              // dedupes a retry on (id, sender), so stop the pass and come
              // back on the backoff timer rather than stall until a reconnect
              // that a healthy link will not produce.
              otherRefused = true;
              return;
            } else {
              return; // the link dropped: the reconnect flushes
            }
          }
        }
      }
      notifyListeners();
    } on DatabaseException {
      // The vault closed mid-flush (app shutting down). Nothing is lost:
      // unsent rows stay in the durable outbox and the next launch's first
      // connect flushes them. Flush is fire-and-forget, so don't propagate.
      return;
    } finally {
      _flushing = false;
      // Anything sent clears the backoff, whatever else happened this pass.
      if (sentAny) _otherRetryBackoff = _otherRetryMin;
      if (_disposed) {
        // No timer on the way out.
      } else if (full.isNotEmpty || storeFull || rateLimited) {
        _outboxRetry ??= Timer(outboxRetryDelay, () {
          _outboxRetry = null;
          unawaited(flushOutbox());
        });
      } else if (otherRefused) {
        final delay = _otherRetryBackoff;
        // Double for next time, capped at the full/store retry delay.
        final nextMs = min(delay.inMilliseconds * 2,
            outboxRetryDelay.inMilliseconds);
        _otherRetryBackoff = Duration(milliseconds: nextMs);
        _outboxRetry ??= Timer(delay, () {
          _outboxRetry = null;
          unawaited(flushOutbox());
        });
      }
    }
  }

  Future<void> _onConnected() async {
    // ADR 0028 first, before anything this connection sends: no held receipt
    // leaves sooner than its floor after the device came back.
    _receiptsOnConnect();
    await flushOutbox();
    // 15.3: a fan-out row that failed its vault write is left in place and
    // retried rather than dropped. Without a trigger it would sit until the
    // next group send, so a reconnect — the moment most likely to follow
    // whatever went wrong — kicks it.
    unawaited(_drainGroupFanout());
    await _sync?.prime(); // open the sync ratchet deterministically once online
    // ADR 0029: a linked device tells its root, once a run, which
    // device-list shape it reads — its root moves the account only once
    // every linked device has said so, and a device switched on only to
    // read may say nothing else of its own.
    final sync = _sync;
    if (sync != null && !_holdsRoot && !_announcedReader) {
      _announcedReader = true;
      unawaited(sync.announce().then((_) {}, onError: (Object _) {
        _announcedReader = false; // said with the next connection instead
      }));
    }
    if (_historyDue.isNotEmpty) unawaited(_runHistoryReplays());
    // 7.7a hardening: on every (re)connect a root re-asserts its newest signed
    // list to its own devices. Cheap, idempotent on the receiving side, and it
    // is what lets a device that was fed a list behind the root's back hear
    // the contradiction as soon as the root is reachable again.
    if (await holdsAccountRoot()) unawaited(_selfSyncCurrentDeviceList());
  }

  // ------------------------------------------------------------------
  // Receiving
  // ------------------------------------------------------------------

  /// Whether a failure raised while processing an inbound envelope is
  /// TRANSIENT — the operation can succeed on a later delivery, so the
  /// envelope is left with the relay unacknowledged — or PERMANENT — the
  /// envelope can never be processed, so it is acknowledged and counted and
  /// stops being redelivered (PROTOCOL §6.8). One place decides it for every
  /// inbound path (the contact's, a contact's extra device's, self-sync),
  /// rather than a different catch on each branch deciding differently, which
  /// is how one path ([DeviceSyncService.handleInbound]) came to acknowledge
  /// a vault-write failure away and lose the message it had already advanced
  /// its ratchet past.
  ///
  /// Transient: the vault busy, locked, closing, full, read-only or erroring;
  /// a file-system error; a send held by a transparency conflict; the relay
  /// or link refusing. Permanent: malformed plaintext, a wrong-typed member,
  /// a bad key or header (which the protocol library now raises as a
  /// [FormatException] or [RatchetDecryptException] before they reach here).
  /// The default is transient: an unforeseen failure is redelivered rather
  /// than dropped, because losing a message is worse than redelivering one.
  static bool _isTransientInboundFailure(Object e) {
    if (e is RatchetDecryptException) return false;
    if (e is FormatException) return false;
    if (e is ArgumentError || e is RangeError || e is TypeError) return false;
    if (e is KtSendHeldException) return true;
    if (e is RelayException) return true;
    if (e is FileSystemException) return true;
    if (e is TimeoutException) return true;
    if (e is DatabaseException) {
      // A constraint, schema or syntax fault is a logic error a redelivery
      // would hit again; everything else a vault throws on this path (busy,
      // locked, closed, full, read-only, I/O) clears on its own.
      return !(e.isUniqueConstraintError() ||
          e.isNotNullConstraintError() ||
          e.isNoSuchTableError() ||
          e.isDuplicateColumnError() ||
          e.isSyntaxError());
    }
    return true;
  }

  /// 30.3: mirrors from my other devices are applied one at a time, in the
  /// order the sync ratchet decrypted them — for a backlog the relay hands
  /// over in the order it was sent, that order. The transport hands over
  /// envelopes without waiting for the last, and the ratchet's own lock
  /// orders only the decrypts, so a device catching up could otherwise start
  /// applying an edit, a reaction or a receipt while the mirror of the
  /// message it names was still being stored, and drop it. The contact's
  /// door has its conversation lock around decrypt AND store; this is the
  /// same promise for this door.
  Future<void> _mirrorTurn = Future<void>.value();

  Future<void> _inMirrorOrder(Future<void> Function() apply) {
    final run = _mirrorTurn.then((_) => apply());
    _mirrorTurn = run.then((_) {}, onError: (Object _) {});
    return run;
  }

  /// The same for each contact's other devices ([_handleExtraInbound]): the
  /// turn of the last envelope from them taken for dispatch, per contact,
  /// while it is still running.
  final Map<String, Future<void>> _extraTurns = {};

  Future<void> _onInbound(RelayInbound m) async {
    // Sealed sender: an envelope with no relay-level sender. Open it with our
    // private key; the sender's routing id lives INSIDE the ciphertext, so the
    // relay never learns who sent what. Acks stay anonymous (m.from is empty),
    // and authenticity is enforced below by the inner ratchet — a forged
    // sender simply fails decryption for that session and is dropped.
    var from = m.from;
    var payload = m.payload;
    if (from.isEmpty) {
      final opened = await SealedEnvelope.open(
          myXSeed: identity.xSeed, myXPub: identity.xPub, blob: payload);
      if (opened == null) {
        transport.ackReceived(id: m.id, from: m.from); // not ours: free RAM
        return;
      }
      from = opened.fromRid;
      payload = opened.payload;
    }

    // File chunks travel outside the ratchet (sealed under their own file key)
    // and may arrive either from a contact or relayed from one of my own
    // devices, so recognise them before any by-sender routing below.
    final chunk = tryParseChunk(payload);
    if (chunk != null) {
      await _onChunk(m, chunk, from, payload);
      return;
    }

    // ADR 0011: a contact request rides sealed but OUTSIDE any ratchet (there
    // is none yet), so it is recognised here — before the unknown-sender drop
    // below, which is exactly what it replaces: an add stops being silent.
    final creq = ContactRequest.tryParse(payload);
    if (creq != null) {
      await _onContactRequest(from, creq);
      transport.ackReceived(id: m.id, from: m.from);
      return;
    }

    // Self-sync from one of my OWN linked devices takes a separate path.
    final sync = _sync;
    if (sync != null && sync.deviceRoutingIds.contains(from)) {
      // Store first, acknowledge second — the rule the contact path below
      // keeps and this one did not. A mirror the relay has been told to
      // forget must be on this device's disk; if it is not, the message is
      // gone from everywhere and the advanced sync ratchet makes the
      // redelivery undecryptable, so a failure rolls the ratchet back and
      // leaves the envelope with the relay.
      final r = await sync.handleInbound(from, payload);
      if (r.transientFailure) {
        // The sync ratchet advanced but could not be persisted (the vault
        // busy or closing). It has been rolled back; leaving the envelope
        // un-acked means the relay redelivers it onto the restored ratchet,
        // rather than the message being lost from everywhere.
        return;
      }
      final mirrored = r.mirrored;
      if (mirrored != null) {
        try {
          await _inMirrorOrder(() async {
            if (mirrored.dir == 'contact') {
              // Carries the sending device, which the sync ratchet
              // authenticates — so the label on an injected contact cannot
              // itself be forged.
              await _applyMirroredContact(from, mirrored.inner);
            } else if (mirrored.dir == 'pop') {
              // ADR 0022: the sending device's own proof of possession, held
              // to the certificate the root holds for that device.
              await _applyDevicePop(from, mirrored.inner);
            } else {
              await _insertMirrored(
                  mirrored.thread, mirrored.dir, mirrored.inner);
            }
          });
        } catch (e) {
          // The one classifier every door uses (§6.8). Transient — the vault
          // busy or closing — and the ratchet is put back and the envelope
          // left with the relay, which redelivers it. Permanent — a mirror
          // whose handler cannot read it — and it never will: the ratchet it
          // advanced is already saved, so it is acknowledged and dropped,
          // where every failure here used to be taken as transient and one
          // such mirror was redelivered, and refused, for the queue's life.
          if (_isTransientInboundFailure(e)) {
            if (r.snapshot != null) await sync.restore(r.snapshot!);
            return; // not acknowledged: the relay redelivers
          }
        }
      }
      transport.ackReceived(id: m.id, from: m.from);
      // ADR 0029: what that device of mine says it reads.
      final level = r.readerLevel;
      if (level != null) await _noteOwnReaderLevel(from, level);
      // 26.2: what just arrived may have made that device's channel
      // post-quantum — its offer, or the answer to ours — which is what a
      // waiting history replay is waiting for.
      if (_historyDue.containsKey(from)) unawaited(_runHistoryReplays());
      return;
    }

    // Inbound from a contact's non-primary device (M4).
    final extraContact = _extraRidToContact[from];
    if (extraContact != null) {
      await _handleExtraInbound(extraContact, from, payload, m);
      return;
    }

    final contact = contacts[from];
    if (contact == null) {
      // Unknown sender: we do not hold their verified identity bundle, so we
      // cannot authenticate a session. Drop (and free the relay queue).
      transport.ackReceived(id: m.id, from: m.from);
      return;
    }

    // Decrypt + persist run under the per-conversation lock (see _withLock)
    // so they cannot interleave with a concurrent send on the same ratchet.
    // Post-processing (ack, assembly, read receipts, session-reset hello) runs
    // AFTER the lock releases, because it may itself re-enter the lock.
    const int kOk = 0, kUnknownSession = 1, kDropped = 2, kReplay = 3;
    const int kMalformed = 4, kWithheld = 5;
    int status;
    InnerMessage? inner;
    // What became of an attachment offer, as its transaction decided (§7).
    _OfferFate? offerFate;

    try {
      final (s, parsedInner) =
          await _withLock<(int, InnerMessage?)>(contact.rid, () async {
        final conv = await _convFor(contact);
        final snapshot = jsonEncode(conv.toJson()); // for rollback
        final cacheBefore = _skippedShape(conv);
        final probe = _debugOnDecrypted;
        if (probe != null &&
            await _debugPeek(
                probe,
                'primary',
                from,
                () async =>
                    (await _convFromSnapshot(snapshot)).decrypt(payload))) {
          return (kWithheld, null);
        }
        final DecryptResult dec;
        try {
          dec = await conv.decrypt(payload);
        } on UnknownSessionException {
          // Their session predates our state (e.g. we restored from backup).
          await _saveConv(contact.rid);
          return (kUnknownSession, null);
        } on RatchetReplayException {
          // A message this chain is already past: the relay redelivering an
          // envelope whose acknowledgement was lost, or somebody replaying
          // one. Either way we consumed it once and there is nothing to
          // repair, so it is acknowledged in silence. This arm comes first
          // because it is a subtype of the one below.
          _convs[contact.rid] = await _convFromSnapshot(snapshot);
          return (kReplay, null);
        } on RatchetDecryptException {
          // The chain no longer agrees with the peer's. Restore state, drop
          // the envelope — and tell somebody: this used to fall through to
          // the acknowledgement below with no row, no count and no hello, so
          // a desync made the conversation simply stop. Nothing on screen,
          // nothing sent, and the peer believing every message arrived.
          _convs[contact.rid] = await _convFromSnapshot(snapshot);
          return (kDropped, null);
        }

        // The envelope decrypted, so the ratchet has validly advanced; the
        // plaintext inside can still be garbage — a peer's buggy or hostile
        // client can put anything in a well-encrypted envelope. Parsing it
        // used to be an unguarded `as String` OUTSIDE both try/catch blocks
        // here, so a wrong-typed field threw a `TypeError` that fell through
        // to the outer catch, which returns WITHOUT acknowledging: the relay
        // then redelivered the same envelope until the queue TTL, and — since
        // the vault write never ran — every launch decrypted the stale chain
        // and failed the same way, wedging that mailbox slot for good (finding
        // 42). Now a malformed inner is a drop that acknowledges. The ratchet
        // is NOT rolled back — the decryption was valid — so it is persisted
        // and this envelope is not decrypted again.
        final InnerMessage parsed;
        try {
          parsed = InnerMessage.fromBytes(dec.plaintext);
        } on FormatException {
          await _saveConv(contact.rid);
          return (kMalformed, null);
        }
        final now = _now();
        // v2: hearing from the peer for the first time triggers this side's
        // post-quantum key offer; it is queued with the same durability as
        // any message, in the transaction that persists the ratchet.
        final offerPayload = dec.pqOfferPayload == null
            ? null
            : await _sealFor(contact.rid, dec.pqOfferPayload!);
        try {
          await vault.db.transaction((txn) async {
            // Persist the advanced ratchet before acting on content — and
            // its skipped-key cache in the SAME transaction, because `nr`
            // advancing without the keys it stepped over would lose those
            // messages when they arrive.
            await _saveConv(contact.rid, txn: txn);
            // Only when the cache changed. An in-order message — the common
            // case — neither adds a key nor consumes one, and re-sealing an
            // unchanged cache cost 13.7 ms per receive at the cap (measured,
            // receive_bench_test.dart): the same cost 15.3 took off every
            // send, quietly moved onto every receive.
            if (_skippedShape(conv) != cacheBefore) {
              await _saveSkipped(contact.rid, txn: txn);
            }
            if (offerPayload != null) {
              await txn.insert('outbox', {
                'id': newMessageId(),
                'rid': contact.rid,
                'payload': offerPayload,
                'created_ms': now,
              });
            }
            final inserted = await txn.insert('inbox_dedupe',
                {'from_rid': from, 'mid': parsed.mid, 'seen_ms': now},
                conflictAlgorithm: ConflictAlgorithm.ignore);
            if (inserted == 0) {
              // A duplicate resend, already processed: an offer in it is
              // what the vault says it was, so one refused the first time is
              // not mirrored, receipted or assembled the second.
              offerFate = await _heldOfferFate(txn, contact.rid, parsed);
              return;
            }
            offerFate = await _persistInboundKind(txn, contact, parsed, now);
          });
        } catch (e) {
          // A transient persist failure (the vault busy or closing) rolls the
          // in-memory ratchet back so the relay's redelivery can be decrypted
          // again, and is not acknowledged (handled below). A PERMANENT
          // failure keeps the validly-advanced ratchet — the decryption was
          // real — so the content is dropped rather than the step lost
          // (§6.8), and the envelope is acknowledged rather than redelivered
          // for ever.
          if (_isTransientInboundFailure(e)) {
            _convs[contact.rid] = await _convFromSnapshot(snapshot);
          }
          rethrow;
        }
        return (kOk, parsed);
      });
      status = s;
      inner = parsedInner;
    } catch (e) {
      if (_isTransientInboundFailure(e)) {
        // Transient: the ratchet was rolled back above; leaving the envelope
        // un-acked means the relay redelivers it when the condition clears.
        return;
      }
      // Permanent: the ratchet advanced and was NOT rolled back. Persist that
      // advance (the transaction that failed rolled back its content), then
      // treat the envelope as a malformed drop — acknowledged and counted —
      // so it is not redelivered until the queue TTL.
      try {
        await _withLock(contact.rid, () => _saveConv(contact.rid));
      } catch (_) {
        return; // could not even persist the ratchet: redeliver instead
      }
      status = kMalformed;
      inner = null;
    }

    if (status == kWithheld) {
      // A test withheld it (debugOnDecrypted): gone, as if never delivered.
      transport.ackReceived(id: m.id, from: m.from);
      return;
    }
    if (status == kUnknownSession ||
        status == kDropped ||
        status == kMalformed) {
      // All three are "we cannot use this and a redelivery would fail the same
      // way", so all acknowledge; the difference is only in what went wrong,
      // and `_noteUndecryptable` coalesces a burst into one row and one hello
      // either way. The hello is the repair: it carries a new ratchet public
      // key, the peer steps on it, and their next message lands on a chain
      // this side can derive.
      transport.ackReceived(id: m.id, from: m.from);
      await _noteUndecryptable(contact);
      notifyListeners();
      return;
    }

    // Processed, or a duplicate the chain has already passed: the relay may
    // forget the envelope.
    transport.ackReceived(id: m.id, from: m.from);
    unawaited(flushOutbox()); // a queued v2 key offer, if any, goes out now
    // ADR 0011: any traffic from them means they have added us — stop showing
    // the chat as "requested", and the session is now established, so a later
    // request from them needs no re-poke. (Their acceptance also signals this.)
    _heardFrom.add(contact.rid);
    await _clearRequested(contact.rid);

    if (inner != null) {
      // An offer §7 refused is not this device's to confirm, to pass on to
      // its own other devices, or to assemble chunks for: it was not stored.
      final refused = offerFate == _OfferFate.refused;
      if (offerFate == _OfferFate.fresh) {
        await _offerLanded(inner.data['fid'] as String);
      }
      _readOnArrival(contact.rid, inner);
      if (!refused &&
          (inner.kind == 'text' ||
              inner.kind == 'file' ||
              inner.kind == 'gmsg' ||
              inner.kind == 'gfile')) {
        // E2E delivery receipt. With sealed sender the relay no longer knows
        // whom to notify of delivery, so the recipient tells the sender
        // directly — encrypted, like everything else. Best-effort: if the app
        // dies before it goes out the sender simply keeps a single grey tick.
        _queueDeliveryReceipt(contact.rid, inner.mid);
      }
      if (!refused &&
          (inner.kind == 'text' ||
              inner.kind == 'file' ||
              inner.kind == 'gmsg' ||
              inner.kind == 'gfile' ||
              inner.kind == 'ginvite' ||
              inner.kind == 'gleave')) {
        // Mirror the received message to my own other devices. For a file this
        // carries the offer (with its file key); the sealed chunks are relayed
        // separately in _onChunk as they arrive. Group traffic mirrors too so
        // linked devices track membership and history.
        unawaited(
            _sync?.mirror(threadRid: contact.rid, dir: 'in', inner: inner) ??
                Future<void>.value());
      }
      if (inner.kind == 'pqid') {
        // This whole path is best-effort and runs unawaited from the
        // transport, so a failure here must not escape as an unhandled async
        // error — the exchange re-runs.
        try {
          if (await _onPqIdentity(contact, inner)) notifyListeners();
        } catch (_) {}
        // Answer in kind unless they said they already hold ours — that is
        // how an exchange started by either side completes, and how one
        // whose opening send vanished completes too.
        if (inner.data['ack'] != true) {
          _offerPqIdentity(contact, _PqReason.answer);
        }
      }
      if (inner.kind == 'pqack' || _saysHoldsOurKey(inner)) {
        // ADR 0021: they hold our key, so a candidate's number can be shown.
        try {
          if (await _markPqAcked(contact)) notifyListeners();
        } catch (_) {}
      }
      if (inner.kind == 'hello') {
        _offerPqIdentity(contact, _PqReason.volunteer);
        // ADR 0020: an inviter I owe an answer to has opened a session —
        // perhaps after dropping it as a stranger's, or before it was
        // waiting for it.
        await _answerLinkHello(contact.rid);
      }
      if (inner.kind == 'gjoin') {
        await _finishLinkAdds(); // ADR 0020: act on the go-ahead just read
      }
      if (contact.pqPub == null &&
          contact.pqCandidate == null &&
          !contact.pqMismatch) {
        // We hold no post-quantum key of theirs — a commitment we still
        // cannot check, or (ADR 0021) a contact whose key an older build of
        // ours would have dropped. Speaking up is what prompts them to
        // answer, and it bypasses the once-per-contact gate: our own opening
        // send may have been dropped before either side had a session.
        //
        // A nudge is a 16 384-bucket envelope — the mark on the relay's view
        // §18.2 is careful about — so the two cases are not bounded alike. An
        // unmet COMMITMENT is a key we were promised and can check, worth the
        // three attempts it always had. Without one we are asking a contact
        // who may be running a build that has no answer to give: once per run
        // is enough to catch the vanished opening send, and repeating it at a
        // v1 peer buys nothing but envelopes.
        if (contact.pqCommit != null || _pqBlindNudged.add(contact.rid)) {
          _offerPqIdentity(contact, _PqReason.nudge);
        }
      }
      if (contact.numberKey != null &&
          !contact.pqTold &&
          !(inner.kind == 'pqid' && inner.data['ack'] != true)) {
        // ADR 0021: we hold their key and have never said so. A `pqid` we are
        // about to answer says it in its own `ack`; anything else earns a
        // `pqack`, once.
        _offerPqAck(contact);
      }
      if (inner.kind == 'devlist') {
        // M4: learn their devices.
        await _applyDevlistInner(contact, inner, primary: true);
      }
      if (inner.kind == 'dlpq') {
        await _onPqListSignature(contact, inner); // §18.9
      }
      if (inner.kind == 'dlpqreq') {
        await _onPqListRequest(contact); // §18.9 repair
      }
      final pql = inner.data['pql'];
      if (pql is num) {
        await _observePqListClaim(contact, pql.toInt()); // §18.9
      }
      if (inner.kind == 'dlrm') {
        // 7.7a: I was removed from my account — if the notice carries the
        // list to show it (ADR 0026).
        await _handleRemovalNotice(contact, inner);
      }
      if (inner.kind == 'pdlreq') {
        // ADR 0026: they want the list I hold for their account, to check
        // an echo of mine against their own key.
        await _answerOwnListRequest(contact);
      }
      // 7.7a: cross-check the device-list claim/echo on EVERY inbound. Runs
      // after any devlist install above so the "held" list is current.
      await _observeDevlistGossip(contact.rid, contact.rid, inner);
      // ADR 0029: and what this device of theirs says it reads.
      await _noteReaderLevel(contact.rid, contact.rid, inner);
      notifyListeners();
    }
  }

  /// DB writes + in-memory UI updates for one decrypted inner message.
  /// Runs inside the inbound transaction (and thus the conversation lock).
  /// Returns what became of an attachment offer, and null for anything else.
  Future<_OfferFate?> _persistInboundKind(
      Transaction txn, Contact contact, InnerMessage inner, int now) async {
    switch (inner.kind) {
      case 'text':
        final expireAt = inner.ttlSec > 0 ? now + inner.ttlSec * 1000 : 0;
        // 8.1: resolve the quote against THIS conversation only, so a reply
        // can neither quote another chat nor probe for ids outside it.
        final quoted =
            await _resolveQuote(contact.rid, inner.replyTo, txn: txn);
        await txn.insert(
            'messages',
            {
              'mid': inner.mid,
              'rid': contact.rid,
              'outgoing': 0,
              'kind': 'text',
              'enc_body': await vault.seal(inner.data['body'] as String? ?? ''),
              'ts_ms': now,
              'status': MsgStatus.delivered,
              'expire_at_ms': expireAt,
              'reply_to': quoted?.mid,
              'forwarded': inner.data['fw'] == true ? 1 : 0,
            },
            conflictAlgorithm: ConflictAlgorithm.ignore);
        _appendLoaded(
            contact.rid,
            ChatMessage(
              mid: inner.mid,
              rid: contact.rid,
              outgoing: false,
              kind: 'text',
              forwarded: inner.data['fw'] == true,
              body: inner.data['body'] as String? ?? '',
              ts: now,
              status: MsgStatus.delivered,
              expireAtMs: expireAt,
              replyTo: quoted?.mid,
              quote: quoted,
            ));
        if (openChatRid != contact.rid) {
          unread[contact.rid] = (unread[contact.rid] ?? 0) + 1;
        }
        break;

      case 'file':
        return _persistFileOffer(txn, contact.rid, inner, now,
            expireAt: inner.ttlSec > 0 ? now + inner.ttlSec * 1000 : 0);

      case 'gfile':
        return _persistGroupFile(contact, inner, now, txn: txn);

      case 'timer':
        final sec = (inner.data['sec'] as num?)?.toInt() ?? 0;
        contact.ttlSec = sec;
        await txn.update('contacts', {'ttl_seconds': sec},
            where: 'rid = ?', whereArgs: [contact.rid]);
        await _insertSystemMessage(
            contact.rid,
            sec == 0
                ? systemBody(SystemKind.ttlOffThem, {'name': contact.name})
                : systemBody(
                    SystemKind.ttlSetThem, {'name': contact.name, 'sec': sec}),
            txn: txn);
        break;

      case 'read':
        final mids = (inner.data['mids'] as List?)?.cast<String>() ?? [];
        for (final mid in mids) {
          await txn.update('messages', {'status': MsgStatus.read},
              where: 'mid = ? AND rid = ? AND outgoing = 1 AND status < ?',
              whereArgs: [mid, contact.rid, MsgStatus.read]);
          _updateLoadedStatus(contact.rid, mid, MsgStatus.read);
        }
        break;

      case 'dlv':
        // E2E delivery receipt (it replaces the relay's receipt under sealed
        // sender). "Wherever they live" is what this used to say and used to
        // do, and it was two mistakes in one line: a mid is plaintext to
        // every member of a group, so ANY contact could name one and flip
        // whatever it matched — including a 1:1 message to somebody else —
        // and a group message went to the double tick on the FIRST member's
        // receipt, a tick that says "they have it" while four people do not.
        final dlvMids = (inner.data['mids'] as List?)?.cast<String>() ?? [];
        for (final mid in dlvMids) {
          await _recordDelivery(txn, contact, mid);
        }
        break;

      case 'gmsg':
        await _persistGroupText(contact, inner, now, txn: txn);
        break;

      // 8.1b: a reaction is not a message — no row, no unread, no ordering.
      case 'react':
      case 'greact':
        await _applyReaction(contact, inner, txn: txn);
        break;

      // 8.1c: requests about the SENDER'S OWN messages; the checks inside
      // decide whether they apply (§6.6).
      case 'edit':
      case 'gedit':
        await _applyEdit(contact, inner, txn: txn);
        break;

      case 'del':
      case 'gdel':
        await _applyDelete(contact, inner, txn: txn);
        break;

      case 'ginvite':
        await _applyGroupInvite(contact.rid, inner.data, txn: txn);
        break;

      // ADR 0019: a member who had to refuse a list asks what it lacks.
      case 'gsync':
        _answerGroupSync(contact, inner.data);
        break;

      case 'gjoin':
        // ADR 0020: a joiner's answer to a link of mine. Marked here, in the
        // transaction that reads it; an add follows the commit.
        await _onLinkJoin(contact, inner, txn);
        break;

      case 'gleave':
        await _applyGroupLeave(contact.rid, inner.data, txn: txn);
        final leftGid = inner.data['gid'];
        if (leftGid is String) {
          // One fewer person the tick is waiting for. Outside the
          // transaction is wrong for atomicity and right for deadlock: this
          // reads and writes `messages` on its own connection.
          unawaited(Future<void>.microtask(
              () => _reevaluateGroupDelivery(leftGid)));
        }
        break;

      case 'hello':
      default:
        break; // session bootstrap or unknown-forward-compat: state saved
    }
    return null;
  }

  /// Record an inbound attachment offer (the file key rides inside it) and
  /// its placeholder message in thread [threadRid] — a contact's routing id
  /// for a direct message, a gid for a group. Chunks are thread-agnostic: they
  /// are matched to the offer by fid when they arrive (see [_onChunk]); the
  /// offer, and everything that reads or removes it, is bound to the message
  /// it arrived as ([_offerFate]).
  Future<_OfferFate> _persistFileOffer(
      DatabaseExecutor txn, String threadRid, InnerMessage inner, int now,
      {int expireAt = 0, String? senderName, String? senderRid}) async {
    // §7 says a file id is `b64url(12 random bytes)`. The SENDER picks it, so
    // that is a rule this side has to enforce rather than assume: it names
    // the blob's file on disk, and `../..`, a leading `/` and `C:` are all
    // strings a contact can put in an inner field. The size, the chunk count
    // and the key material are the sender's say-so too ([_FileOffer]).
    // Refused like any other malformed inner message — nothing stored, no
    // placeholder, no alarm, because an honest client cannot produce one.
    final offer = _FileOffer.read(inner.data);
    if (offer == null) return _OfferFate.refused;
    final fid = offer.fid;
    // A group offer names its sender; a 1:1 conversation is its sender.
    final fate = await _offerFate(
        txn, threadRid, inner.mid, fid, senderRid ?? threadRid);
    if (fate != _OfferFate.fresh) return fate;
    final name = offer.name;
    final quoted = await _resolveQuote(threadRid, inner.replyTo, txn: txn);
    await txn.insert('files', {
      'fid': fid,
      'rid': threadRid,
      'mid': inner.mid,
      'enc_meta': await vault.seal(jsonEncode(offer.meta)),
      'complete': 0,
      'got_chunks': 0,
      'total_chunks': offer.chunks,
    });
    await txn.insert(
        'messages',
        {
          'mid': inner.mid,
          'rid': threadRid,
          'outgoing': 0,
          'kind': 'file',
          'enc_body': await vault.seal(jsonEncode({
            'fid': fid,
            if (senderName != null) 'sn': senderName,
            if (senderRid != null) 'sr': senderRid,
          })),
          'fid': fid,
          'ts_ms': now,
          'status': MsgStatus.delivered,
          'expire_at_ms': expireAt,
          'reply_to': quoted?.mid,
          'forwarded': inner.data['fw'] == true ? 1 : 0,
        },
        conflictAlgorithm: ConflictAlgorithm.ignore);
    _appendLoaded(
        threadRid,
        ChatMessage(
          mid: inner.mid,
          rid: threadRid,
          outgoing: false,
          kind: 'file',
          forwarded: inner.data['fw'] == true,
          body: name,
          fid: fid,
          ts: now,
          status: MsgStatus.delivered,
          expireAtMs: expireAt,
          senderName: senderName,
          replyTo: quoted?.mid,
          quote: quoted,
          file: offer.fileMeta,
        ));
    if (openChatRid != threadRid) {
      unread[threadRid] = (unread[threadRid] ?? 0) + 1;
    }
    return _OfferFate.fresh;
  }

  /// A group attachment offer from [contact]: same membership rule as a group
  /// text (unknown group, left group or non-member sender → silent drop).
  ///
  /// [contact] is the ACCOUNT: an offer from one of their linked devices
  /// arrives here as them ([_dispatchExtraInner]), so the sender recorded
  /// with it — the one §6.6's rule later holds a delete to — is the person,
  /// whichever of their devices sent it.
  Future<_OfferFate> _persistGroupFile(
      Contact contact, InnerMessage inner, int now,
      {DatabaseExecutor? txn}) async {
    final gid = inner.data['gid'];
    final g = gid is String ? groups[gid] : null;
    if (g == null || g.left || !g.memberRids.contains(contact.rid)) {
      return _OfferFate.refused;
    }
    return _persistFileOffer(txn ?? vault.db, g.gid, inner, now,
        expireAt: _groupExpiry(inner),
        senderName: contact.name,
        senderRid: contact.rid);
  }

  /// When a group message from someone else goes here (ADR 0030): its `ttl`
  /// after its receipt on this device, the clock the primary inbound path
  /// keeps for a 1:1 message (§6.1) — or never, on a build before group
  /// timers, which kept every group message.
  int _groupExpiry(InnerMessage inner) {
    if (debugBuildBefore0030 || inner.ttlSec <= 0) return 0;
    return _now() + inner.ttlSec * 1000;
  }

  /// Whether an offer under [fid], arriving as message [mid] in [thread],
  /// may be stored (PROTOCOL §7).
  ///
  /// A file id is chosen by its sender, and every member of a group holds
  /// every member's: an id names nothing until it is bound to the message
  /// that brought it. It used to name the attachment ITSELF. The `files`
  /// insert was ignored when the id was already held, so another member's
  /// offer of it stored a message of theirs pointing at the first sender's
  /// file; their delete of that message, which the authorship rule allowed —
  /// it was theirs — removed the file it pointed at; and the id, free again,
  /// took their re-offer with their own bytes, which the first sender's
  /// message then showed under the first sender's name. No race was needed.
  ///
  /// Now an id held for any other message — in this conversation or another,
  /// from this sender or another — is refused, and so is a message id this
  /// conversation already holds, whatever it holds it for: the second would
  /// otherwise store an attachment no message shows, and a re-delivered offer
  /// of a message deleted for everyone would bring its file back. What
  /// remains is the same offer arriving twice ([_OfferFate.again]) — from
  /// the same [sender] (`''` for me, the contact's routing id otherwise): in
  /// a group, a member replaying another member's offer word for word names
  /// the same conversation, message and id, and is still not its sender.
  Future<_OfferFate> _offerFate(DatabaseExecutor db, String thread, String mid,
      String fid, String sender) async {
    final held = await db.query('files',
        columns: ['rid', 'mid'], where: 'fid = ?', whereArgs: [fid], limit: 1);
    if (held.isNotEmpty) {
      if (held.first['rid'] != thread || held.first['mid'] != mid) {
        return _OfferFate.refused;
      }
      return await _heldSender(db, thread, mid) == sender
          ? _OfferFate.again
          : _OfferFate.refused;
    }
    final taken = await db.query('messages',
        columns: ['mid'],
        where: 'rid = ? AND mid = ?',
        whereArgs: [thread, mid],
        limit: 1);
    return taken.isEmpty ? _OfferFate.fresh : _OfferFate.refused;
  }

  /// Who sent the message [mid] in [thread]: `''` when it is mine, the
  /// contact for a 1:1 chat, the routing id a group message recorded (`sr`);
  /// null when there is no such message or it does not say.
  Future<String?> _heldSender(
      DatabaseExecutor db, String thread, String mid) async {
    final rows = await db.query('messages',
        columns: ['outgoing', 'enc_body'],
        where: 'rid = ? AND mid = ?',
        whereArgs: [thread, mid],
        limit: 1);
    if (rows.isEmpty) return null;
    if ((rows.first['outgoing'] as int) == 1) return '';
    return _storedSenderRid(thread, rows.first);
  }

  /// What became of the offer in [inner] from contact [rid] when it was first
  /// processed — read back for a duplicate resend, which is not processed
  /// again. Null when [inner] is not an offer.
  Future<_OfferFate?> _heldOfferFate(
      DatabaseExecutor db, String rid, InnerMessage inner) async {
    if (inner.kind != 'file' && inner.kind != 'gfile') return null;
    final fid = inner.data['fid'];
    final thread = inner.kind == 'gfile' ? inner.data['gid'] : rid;
    if (fid is! String || thread is! String) return _OfferFate.refused;
    final held = await db.query('files',
        columns: ['fid'],
        where: 'fid = ? AND rid = ? AND mid = ?',
        whereArgs: [fid, thread, inner.mid],
        limit: 1);
    return held.isEmpty || await _heldSender(db, thread, inner.mid) != rid
        ? _OfferFate.refused
        : _OfferFate.again;
  }

  /// How many chunks may be held for an offer this device has not seen.
  ///
  /// A chunk is the one inbound thing with no sender to hold responsible: it
  /// travels outside the ratchet, sealed under its own file key, and its MAC
  /// is checkable only with key material that arrives in the OFFER. So until
  /// the offer is here, a chunk is a bag of bytes addressed to this mailbox
  /// by anybody who knows the routing id — which is anybody holding the
  /// contact code, and that code is meant to be handed out.
  ///
  /// They cannot simply be refused: they legitimately arrive before the offer
  /// (they are sent as sidecars, and the relay does not promise an order).
  /// So they are held, and the holding is bounded — oldest first out, which
  /// is the right direction because the offer that explains a chunk arrives
  /// within moments of it or not at all.
  static const int maxHeldChunks = 256;

  Future<void> _onChunk(
      RelayInbound m, FileChunk chunk, String from, String payload) async {
    // A chunk names its own fid, from outside the ratchet, so this is the
    // least trustworthy string the client handles. One that is not a file id
    // (§7) can belong to no offer this device will ever accept, so holding
    // it would be storing junk under a name that is itself the attack.
    if (!isWellFormedFid(chunk.fid)) {
      transport.ackReceived(id: m.id, from: m.from);
      return;
    }
    final offer = await vault.db.query('files',
        columns: ['total_chunks', 'complete', 'enc_meta'],
        where: 'fid = ?',
        whereArgs: [chunk.fid]);
    final known = offer.isNotEmpty;

    if (known) {
      // An offer arrived over the ratchet, so this fid is one a contact
      // really sent. Its shape still bounds what may be stored under it: an
      // index outside the offer's range is not a chunk of this file, a chunk
      // carrying more or fewer bytes than its index's share of the declared
      // size is not one either (§7), and a file already assembled needs
      // nothing more. The length is checked here, before anything is stored,
      // so the wrong chunk cannot take the place of the right one at its
      // index — and so nothing ever assembles past the size the offer said.
      if ((offer.first['complete'] as int) == 1) {
        transport.ackReceived(id: m.id, from: m.from);
        return;
      }
      final total = offer.first['total_chunks'] as int;
      final size = await _declaredSize(offer.first);
      if (chunk.index < 0 ||
          chunk.index >= total ||
          size == null ||
          chunk.cipherText.length != fileChunkLength(size, chunk.index)) {
        transport.ackReceived(id: m.id, from: m.from);
        return;
      }
    } else if (chunk.index < 0 ||
        chunk.index >= fileChunkCount(maxAttachmentBytes) ||
        chunk.cipherText.length > defaultChunkSize) {
      // No offer this device will ever take has a chunk like this one: past
      // the last index of the largest file there is, or longer than any
      // chunk of any file. Not worth one of the [maxHeldChunks] places.
      transport.ackReceived(id: m.id, from: m.from);
      return;
    }

    await vault.db.insert(
        'chunks', {'fid': chunk.fid, 'idx': chunk.index, 'payload': payload},
        conflictAlgorithm: ConflictAlgorithm.ignore);
    transport.ackReceived(id: m.id, from: m.from);

    if (!known) {
      // Held, not trusted, and trimmed to the cap rather than checked against
      // it: envelopes arrive concurrently, so a check-then-insert overshoots
      // by however many are in flight, and a cap that is only approximately a
      // cap is the kind of bound an attacker sends faster at. Trimming after
      // the fact is exact whatever the concurrency, under a lock so a burst
      // does not run it once per envelope. Oldest out first: the offer that
      // explains a chunk arrives within moments of it or not at all.
      //
      // Nothing is fanned to my other devices while a chunk is in this state
      // — an unexplained chunk must not become N envelopes this device emits
      // on a stranger's behalf. That happens when the offer lands and
      // explains it (see [_fanHeldChunks]).
      await _withLock('held-chunks', () async {
        await vault.db.rawDelete(
            'DELETE FROM chunks WHERE rowid IN (SELECT rowid FROM chunks '
            'WHERE fid NOT IN (SELECT fid FROM files) '
            'ORDER BY rowid DESC LIMIT -1 OFFSET ?)',
            [maxHeldChunks]);
      });
      return; // nothing to assemble and nothing to relay yet
    }

    // Relay a contact's chunk to my own other devices so the attachment lands
    // there too. Skip chunks that were themselves relayed from one of my
    // devices (matched on the OPENED sender), so the fan-out can't loop.
    final sync = _sync;
    if (sync != null && !sync.deviceRoutingIds.contains(from)) {
      unawaited(sync.fanChunk(payload));
    }
    await _tryAssemble(chunk.fid);
  }

  /// The size an offer declared, from its `files` row: the sealed meta's
  /// `size`, or null when the row's offer does not say one this device
  /// would accept — a chunk can then fit no part of it.
  Future<int?> _declaredSize(Map<String, Object?> row) async {
    try {
      final meta = jsonDecode(await vault.unseal(row['enc_meta'] as String));
      final size = meta is Map ? meta['size'] : null;
      return size is int && size >= 0 && size <= maxAttachmentBytes
          ? size
          : null;
    } catch (_) {
      return null;
    }
  }

  /// Relay to my own other devices every chunk already stored for [fid].
  ///
  /// Called once, when the offer lands. Chunks that arrive AFTER it are fanned
  /// one at a time by [_onChunk], so nothing is relayed twice.
  Future<void> _fanHeldChunks(String fid) async {
    final sync = _sync;
    if (sync == null) return;
    final rows = await vault.db.query('chunks',
        columns: ['payload'], where: 'fid = ?', whereArgs: [fid]);
    for (final r in rows) {
      unawaited(sync.fanChunk(r['payload'] as String));
    }
  }

  /// Assemble [fid] if the offer and every chunk are present. Serialized per
  /// fid: the offer's post-processing and the last chunk's arrival both call
  /// this, often within a millisecond of each other, and two concurrent
  /// assemblies each wrote the blob under a fresh random key — leaving the
  /// stored key and the bytes on disk from different runs, i.e. an
  /// attachment that could never be opened. Under the lock the second caller
  /// sees `complete = 1` and returns.
  Future<void> _tryAssemble(String fid) =>
      _withLock('assemble:$fid', () => _tryAssembleLocked(fid));

  /// An offer has arrived: whatever was held for it is explained now. What
  /// does not fit it is dropped, what does is relayed onward (which
  /// [_onChunk] deliberately would not do while it was unexplained), and
  /// then the file is assembled.
  Future<void> _offerLanded(String fid) async {
    await _withLock('assemble:$fid', () => _dropUnfitChunks(fid));
    await _fanHeldChunks(fid);
    await _tryAssemble(fid);
  }

  /// The chunk stored as [payload] at index [idx], if it can be chunk [idx]
  /// of [fid], a file of [size] bytes (§7); null if not. Null [size]: an
  /// offer that does not say one this device would accept, which nothing
  /// fits.
  FileChunk? _fitting(String fid, int? size, int idx, String payload) {
    if (size == null) return null;
    final fc = tryParseChunk(payload);
    return fc != null &&
            fc.fid == fid &&
            fc.index == idx &&
            fc.cipherText.length == fileChunkLength(size, idx)
        ? fc
        : null;
  }

  /// Chunks held for [fid] before its offer arrived that the offer now shows
  /// are not its own: past its last index, or not its index's share of the
  /// declared size (§7). They were held because there was nothing to check
  /// them against; now there is, and a misfit left in its place would only
  /// fail the whole file at assembly. Read one at a time — up to the
  /// [maxHeldChunks] of them are a few tens of megabytes.
  Future<void> _dropUnfitChunks(String fid) async {
    final offer = await vault.db.query('files',
        columns: ['total_chunks', 'complete', 'enc_meta'],
        where: 'fid = ?',
        whereArgs: [fid]);
    if (offer.isEmpty || (offer.first['complete'] as int) == 1) return;
    final total = offer.first['total_chunks'] as int;
    final size = await _declaredSize(offer.first);
    final held = await vault.db
        .query('chunks', columns: ['idx'], where: 'fid = ?', whereArgs: [fid]);
    for (final r in held) {
      final idx = r['idx'] as int;
      final c = await vault.db.query('chunks',
          columns: ['payload'],
          where: 'fid = ? AND idx = ?',
          whereArgs: [fid, idx]);
      if (c.isEmpty) continue;
      if (idx < total &&
          _fitting(fid, size, idx, c.first['payload'] as String) != null) {
        continue;
      }
      await vault.db.delete('chunks',
          where: 'fid = ? AND idx = ?', whereArgs: [fid, idx]);
    }
  }

  Future<void> _tryAssembleLocked(String fid) async {
    final rows =
        await vault.db.query('files', where: 'fid = ?', whereArgs: [fid]);
    if (rows.isEmpty) return; // chunks arrived before the offer — wait
    final row = rows.first;
    if ((row['complete'] as int) == 1) return;
    // The message this attachment arrived as. Everything written below is
    // bound to it, so an offer deleted while this runs is not written back
    // under its id for whatever offer may hold that id by then.
    final rid = row['rid'] as String;
    final mid = row['mid'] as String;
    const bound = 'fid = ? AND rid = ? AND mid = ?';

    final total = row['total_chunks'] as int;
    // Counted, not loaded. This used to read every chunk held for the file
    // — the payloads — on every chunk's arrival, just to count them: a file
    // of n chunks cost n²/2 chunk reads, and an offer that declared a
    // million chunks made each chunk sent for it re-read all the others.
    final got = firstIntValue(await vault.db.rawQuery(
            'SELECT COUNT(*) FROM chunks WHERE fid = ? AND idx >= 0 AND idx < ?',
            [fid, total])) ??
        0;
    if (got != row['got_chunks']) {
      await vault.db.update('files', {'got_chunks': got},
          where: bound, whereArgs: [fid, rid, mid]);
      _updateLoadedFileProgress(rid, mid, got, total, false);
      notifyListeners();
    }
    if (got < total) return;

    final meta =
        (jsonDecode(await vault.unseal(row['enc_meta'] as String)) as Map)
            .cast<String, Object?>();

    try {
      final size = meta['size'];
      if (size is! int ||
          size < 0 ||
          size > maxAttachmentBytes ||
          fileChunkCount(size) != total) {
        // Only a row stored before the offer itself was checked can say this.
        throw const FormatException('the offer does not add up');
      }
      final fk = unb64(meta['fk'] as String);
      final fn = unb64(meta['fn'] as String);
      // One buffer of exactly the declared size, filled a chunk at a time,
      // each chunk read when it is needed. This used to hold every chunk's
      // payload, then every decrypted chunk, then join them through
      // `expand(...).toList()` — a List<int> at eight bytes an element — so
      // an honest 24 MiB attachment peaked at hundreds of megabytes, and a
      // file whose chunks added up to more than its offer said was assembled
      // at whatever size they added up to.
      final out = Uint8List(size);
      var at = 0;
      for (var i = 0; i < total; i++) {
        final c = await vault.db.query('chunks',
            columns: ['payload'],
            where: 'fid = ? AND idx = ?',
            whereArgs: [fid, i]);
        if (c.isEmpty) return; // removed under us: the file is going
        final chunk = _fitting(fid, size, i, c.first['payload'] as String);
        if (chunk == null) {
          // Held before the offer could rule it out, and not this file's:
          // dropped, so the slot is free for the chunk that is — and counted
          // again, so the progress shown is what is actually held.
          await vault.db.delete('chunks',
              where: 'fid = ? AND idx = ?', whereArgs: [fid, i]);
          await _tryAssembleLocked(fid);
          return;
        }
        final part =
            await decryptChunk(fk: fk, fn: fn, fid: fid, chunk: chunk);
        out.setRange(at, at + part.length, part);
        at += part.length;
      }
      if (b64(await sha256Bytes(out)) != meta['sha256']) {
        throw const FormatException('attachment hash mismatch');
      }
      final still = await vault.db.query('files',
          columns: ['complete'], where: bound, whereArgs: [fid, rid, mid]);
      if (still.isEmpty || still.first['complete'] == 1) return;
      final keyInfo = await vault.writeBlob(fid, out);
      meta['local'] = keyInfo;
      meta.remove('fk');
      meta.remove('fn');
      await vault.db.update(
          'files',
          {
            'enc_meta': await vault.seal(jsonEncode(meta)),
            'complete': 1,
            'got_chunks': total,
          },
          where: bound,
          whereArgs: [fid, rid, mid]);
      await vault.db.delete('chunks', where: 'fid = ?', whereArgs: [fid]);
      _updateLoadedFileProgress(rid, mid, total, total, true);
    } catch (_) {
      await vault.db.delete('chunks', where: 'fid = ?', whereArgs: [fid]);
      await _insertSystemMessage(
          rid, systemBody(SystemKind.attachmentDiscarded));
    }
    notifyListeners();
  }

  /// Mark a message `sent` once the LAST envelope carrying it has gone.
  ///
  /// A 1:1 message is one envelope, so this is the moment it leaves. A group
  /// message is one envelope per member: reporting `sent` on the first would
  /// claim the message had left while some members' copies were still queued
  /// behind a stalled mailbox, which is the sort of small lie a status icon
  /// exists not to tell.
  Future<void> _markSentIfLast(Map<String, Object?> row) async {
    final mid = row['mid'] as String?;
    if (mid == null) return; // a key offer or a file chunk: no status to move
    final thread = row['thread_rid'] as String? ?? row['rid'] as String;
    final left = firstIntValue(await vault.db.rawQuery(
            'SELECT COUNT(*) FROM outbox WHERE mid = ? AND thread_rid = ?',
            [mid, thread])) ??
        0;
    if (left > 0) return;
    // A group's copies are queued one member at a time, so an empty outbox
    // is not the same as a finished fan-out: the first member's envelope can
    // be sent and deleted before the second has been queued at all, and an
    // outbox count alone would call that "sent". What is still to be queued
    // is exactly what `group_fanout` holds.
    final planned = firstIntValue(await vault.db.rawQuery(
            'SELECT COUNT(*) FROM group_fanout WHERE mid = ?', [mid])) ??
        0;
    if (planned > 0) return;
    final n = await vault.db.update('messages', {'status': MsgStatus.sent},
        where: 'mid = ? AND rid = ? AND outgoing = 1 AND status = ?',
        whereArgs: [mid, thread, MsgStatus.pending]);
    if (n > 0) _updateLoadedStatus(thread, mid, MsgStatus.sent);
  }

  /// The relay's own delivery receipt. Deliberately does not move a status.
  ///
  /// [DeliveredReceipt.id] is an ENVELOPE id, and this client's envelope ids
  /// are fresh per row and mean nothing outside the relay (PROTOCOL §12.2).
  /// Reading one as a message id was only ever right while the two were the
  /// same string — which is the thing that told the relay who was in a group
  /// — and it was unscoped by conversation, so any id a peer could guess
  /// flipped whatever it matched.
  ///
  /// Nothing is lost by ignoring it: the relay sends this frame only for an
  /// envelope whose sender it knows, and every envelope this client sends is
  /// sealed and leaves on a connection that never authenticated (§12.1), so
  /// it cannot produce one. Delivery is the peer's own `dlv` message, sent
  /// inside the ratchet and naming the mids it is about.
  Future<void> _onDelivered(DeliveredReceipt r) async {}

  // ------------------------------------------------------------------
  // Read receipts & chat lifecycle
  // ------------------------------------------------------------------

  Future<void> markChatOpened(String rid) async {
    openChatRid = rid;
    unread[rid] = 0;
    final group = groups.containsKey(rid);
    // A group's read state goes by when it was last opened (30.3).
    final before = group
        ? int.tryParse(await vault.kvGet('last_open_$rid') ?? '') ?? 0
        : 0;
    await vault.kvPut('last_open_$rid', '${_now()}', sensitive: false);
    if (group) {
      await _readGroupHere(rid, since: before);
    } else {
      await _sendReadReceipts(rid);
    }
    notifyListeners();
  }

  void markChatClosed(String rid) {
    if (openChatRid == rid) openChatRid = null;
  }

  // ------------------------------------------------------------------
  // Receipts, held (41; ADR 0028, PROTOCOL §6.3)
  //
  // A receipt is the one envelope this app sends because somebody ELSE did
  // something, and until phase 41 it went within 300 ms of the delivery it
  // answered (15.3 gathered a burst into one for 300 ms). Sealed sender keeps
  // the sender off the envelope; the receipt put them back: a relay — or
  // whoever terminates its TLS — that delivered E to mailbox B and a moment
  // later took a small envelope for mailbox A had A as E's sender, near
  // certainly after a few messages (THREAT_MODEL R41; Martiny et al., NDSS
  // 2021). So a receipt — delivered or read — is held now: never less than
  // `floor` after the message it answers arrived (or was read), nor after the
  // device came back online; at the latest at a moment drawn uniformly up to
  // `ceiling`; and all of one person's that may go, go together. Sooner than
  // its draw only beside a message the user sends that person, where the
  // envelope it would have been is one that was leaving anyway. Held in the
  // vault (`rcpt_<rid>`), so a backgrounded or killed app sends them later
  // rather than never. What the delay costs is the tick's promptness; what it
  // buys, and what it does not, is in the ADR.
  // ------------------------------------------------------------------

  late final ReceiptQueue _receipts = ReceiptQueue(now: _now);
  final Map<String, Timer> _receiptTimers = {};
  final Set<String> _receiptsDirty = {};
  Future<void>? _receiptWriter;
  bool _sendsReceipts = true;

  /// Whether this device sends delivery and read receipts at all (Settings;
  /// on unless turned off, per device, ADR 0028).
  bool get sendsReceipts => _sendsReceipts;

  /// The timing in force (ADR 0028): [ReceiptTiming.standard] in the app.
  ReceiptTiming get receiptTiming => _receipts.timing;

  /// Test seam: hold receipts to another timing. The app never sets it.
  @visibleForTesting
  set debugReceiptTiming(ReceiptTiming t) => _receipts.timing = t;

  /// At most this many mids in one `dlv` or `read`; a batch past it leaves as
  /// several, at its moment — never early, which is what 15.3's cap did.
  static const int _receiptBatchMax = 64;

  /// What the user sends to someone: the kinds a receipt owed to that person
  /// may ride with (ADR 0028). Not the kinds this client sends on its own in
  /// answer to something — a `hello`, a key, a list, a group's `ginvite` or
  /// `gsync` answer — which leave at moments other people's messages choose.
  static const Set<String> _ridingKinds = {
    'text', 'file', 'gmsg', 'gfile', 'react', 'greact', 'edit', 'gedit',
    'del', 'gdel', 'timer',
  };

  /// Test seam: no receipt leaves on its own timer while this is set — it
  /// still rides with a message, and [flushDeliveryReceipts] still sends
  /// everything. Lets a test look at what is held, and choose the moment.
  @visibleForTesting
  bool get debugHoldReceipts => _holdReceipts;
  @visibleForTesting
  set debugHoldReceipts(bool hold) {
    _holdReceipts = hold;
    if (!hold) {
      for (final rid in _receipts.rids.toList()) {
        _scheduleReceipts(rid);
      }
    }
  }

  bool _holdReceipts = false;

  /// How many of [rid]'s held receipts are past their floor. Test seam.
  @visibleForTesting
  int eligibleReceipts(String rid) => _receipts.eligible(rid);

  void _queueDeliveryReceipt(String rid, String mid) =>
      _owe(rid, [mid], read: false);

  /// [rid] is owed receipts for [mids]: held, written down, and timed.
  void _owe(String rid, List<String> mids, {required bool read}) {
    if (_disposed || !_sendsReceipts || mids.isEmpty) return;
    for (final m in mids) {
      _receipts.owe(rid, m, read: read);
    }
    _saveReceipts(rid);
    _scheduleReceipts(rid);
  }

  /// One timer per person, at their earliest due receipt.
  void _scheduleReceipts(String rid) {
    _receiptTimers.remove(rid)?.cancel();
    final due = _receipts.nextDueMs(rid);
    if (due == null || _disposed) return;
    _receiptTimers[rid] =
        Timer(Duration(milliseconds: max(0, due - _now())), () {
      _receiptTimers.remove(rid);
      unawaited(_releaseReceipts(rid).then((_) {}, onError: (Object _) {}));
    });
  }

  /// Send [rid]'s receipts that may go now — every one past its floor — or,
  /// with [all], every one held (the test seam). On its own timer a receipt
  /// waits for both links: one queued while the device is away would leave
  /// the moment it is back, which is a moment the relay sees, so it is kept
  /// and given a new one after the connection ([_receiptsOnConnect]).
  /// [riding]: beside a message the user is sending them, which goes when it
  /// goes.
  Future<void> _releaseReceipts(String rid,
      {bool riding = false, bool all = false}) async {
    if (_disposed || (!all && !riding && _holdReceipts)) return;
    final contact = contacts[rid];
    if (contact == null) {
      _receipts.drop(rid);
      _saveReceipts(rid);
      return;
    }
    if (!all &&
        !riding &&
        !(transport.isConnected && transport.isSenderConnected)) {
      return;
    }
    final taken = _receipts.take(rid, all: all);
    _scheduleReceipts(rid); // what is still held, at its own moment
    if (taken.delivered.isEmpty && taken.read.isEmpty) return;
    for (final (kind, mids) in [
      ('dlv', taken.delivered),
      ('read', taken.read),
    ]) {
      for (var i = 0; i < mids.length; i += _receiptBatchMax) {
        try {
          await _sendInner(
              contact,
              InnerMessage(
                  kind: kind,
                  mid: newMessageId(),
                  ts: _now(),
                  data: {
                    'mids': mids.sublist(
                        i, min(i + _receiptBatchMax, mids.length))
                  }));
        } catch (_) {
          // Best effort, as a receipt always was: the sender keeps a tick
          // that says less than it could, never one that says more.
        }
      }
    }
    // Written down after the envelopes are in the outbox, so a crash between
    // the two sends a receipt twice — which changes nothing — not never.
    _saveReceipts(rid);
  }

  /// Both links are up again: nothing held leaves sooner than the floor from
  /// now, and anything whose moment passed while the device was away gets a
  /// new one.
  void _receiptsOnConnect() {
    if (_disposed) return;
    _receipts.deferAfterConnect();
    for (final rid in _receipts.rids.toList()) {
      _saveReceipts(rid);
      _scheduleReceipts(rid);
    }
  }

  /// Turn receipts on or off for this device. Off sends none — not on their
  /// timer, not riding — and forgets the ones held.
  Future<void> setSendsReceipts(bool on) async {
    _sendsReceipts = on;
    await vault.kvPut('receipts_enabled', on ? '1' : '0');
    if (!on) {
      for (final t in _receiptTimers.values) {
        t.cancel();
      }
      _receiptTimers.clear();
      final rids = _receipts.rids.toList();
      _receipts.clear();
      for (final rid in rids) {
        _saveReceipts(rid);
      }
    }
    notifyListeners();
  }

  /// Write [rid]'s held receipts to the vault — one writer, the latest state,
  /// so two writes of one person's queue cannot land out of order.
  void _saveReceipts(String rid) {
    _receiptsDirty.add(rid);
    _receiptWriter ??= _writeReceipts().whenComplete(() {
      _receiptWriter = null;
      if (_receiptsDirty.isNotEmpty && !_disposed) {
        _saveReceipts(_receiptsDirty.first);
      }
    });
  }

  Future<void> _writeReceipts() async {
    while (_receiptsDirty.isNotEmpty && !_disposed) {
      final rid = _receiptsDirty.first;
      _receiptsDirty.remove(rid);
      final v = contacts.containsKey(rid) ? _receipts.encode(rid) : null;
      try {
        if (v == null) {
          await vault.kvDelete('rcpt_$rid');
        } else {
          await vault.kvPut('rcpt_$rid', v);
        }
      } catch (_) {}
    }
  }

  /// The receipts a previous run held, for the people this vault still has.
  /// Timed once the device connects ([_receiptsOnConnect]).
  Future<void> _loadReceipts() async {
    _sendsReceipts = (await vault.kvGet('receipts_enabled')) != '0';
    final held = await vault.kvScan('rcpt_');
    for (final e in held.entries) {
      final rid = e.key.substring('rcpt_'.length);
      if (!_sendsReceipts || !contacts.containsKey(rid)) {
        await vault.kvDelete(e.key);
        continue;
      }
      _receipts.load(rid, e.value);
    }
  }

  /// Test seam: send every receipt held, now — floors, timers and the links
  /// aside — and wait until they are in the outbox.
  @visibleForTesting
  Future<void> flushDeliveryReceipts() async {
    for (final rid in _receipts.rids.toList()) {
      _receiptTimers.remove(rid)?.cancel();
      await _releaseReceipts(rid, all: true);
    }
  }

  /// How many delivery receipts are held, across all senders. Test seam.
  @visibleForTesting
  int get pendingDeliveryReceipts => _receipts.count(read: false);

  /// How many receipts of either kind are held. Test seam.
  @visibleForTesting
  int get pendingReceipts => _receipts.count();

  /// Test seam: claim delivery of [mids] to [rid], whatever this device has
  /// actually received.
  ///
  /// It stands in for an attacker, who is likewise not bound by the queue
  /// this client keeps: a `mid` is plaintext to every member of a group, and
  /// the receipt is an ordinary inner message anyone can construct. The
  /// receiver's scoping is what makes the claim worthless, and that is what
  /// the test using this checks.
  @visibleForTesting
  Future<void> debugClaimDelivery(String rid, List<String> mids) async {
    final contact = contacts[rid];
    if (contact == null) return;
    await _sendInner(
        contact,
        InnerMessage(
            kind: 'dlv', mid: newMessageId(), ts: _now(), data: {'mids': mids}));
  }

  /// Test seam: send [inner] to [rid] exactly as given.
  ///
  /// A well-behaved sender builds its own messages and so never produces the
  /// ones the receiver's rules exist for. This stands in for a peer running
  /// modified code — the only kind that can — so that those rules can be
  /// tested against what they are actually meant to refuse rather than
  /// against what this client happens to emit.
  @visibleForTesting
  Future<void> debugSendRawInner(String rid, InnerMessage inner) async {
    final contact = contacts[rid];
    if (contact == null) return;
    await _sendInner(contact, inner);
  }

  Future<void> _sendReadReceipts(String rid) async {
    final contact = contacts[rid];
    if (contact == null) return;
    final rows = await vault.db.query('messages',
        columns: ['mid'],
        where:
            "rid = ? AND outgoing = 0 AND receipt_sent = 0 AND kind IN ('text','file')",
        whereArgs: [rid]);
    if (rows.isEmpty) return;
    final mids = rows.map((r) => r['mid'] as String).toList();
    await vault.db.update('messages', {'receipt_sent': 1},
        where:
            "rid = ? AND outgoing = 0 AND receipt_sent = 0 AND kind IN ('text','file')",
        whereArgs: [rid]);
    // 30.3: and my other devices count them read — first, so that a receipt
    // the contact cannot be sent does not leave them unread over there. At
    // once, as before: that envelope goes to my own devices, which the relay
    // groups by their timing anyway (R19), and releasing it WITH the receipt
    // below would put my laptop's mailbox beside the contact's at one moment.
    await _mirrorRead(rid, mids);
    // ADR 0028: the receipt itself is held like a delivery receipt, so it
    // does not leave at the moment of reading either.
    _owe(rid, mids, read: true);
  }

  // ------------------------------------------------------------------
  // 30.3: what I read on one of my devices is read on the others.
  //
  // A message counts as read on a device — out of the unread count, and no
  // receipt left to send for it — once it has been read there or on another
  // device of mine: `receipt_sent` on its row, which a 1:1 chat always set
  // when its receipt went and a group chat (which sends no receipts, §6.3)
  // now sets too. Whichever device reads mirrors the ids it read, as a
  // `read` with dir `out` over self-sync (PROTOCOL §9), and every other
  // device marks them. Until 30.3 a message read on the laptop stayed unread
  // on the phone, and the phone, opened, sent a second receipt for it.
  // ------------------------------------------------------------------

  /// At most this many ids in one mirrored `read`: a long absence must not
  /// make one envelope larger than the relay takes.
  static const int _readMirrorBatch = 500;

  /// What has just arrived while its chat is open on this device is read
  /// here: a 1:1 chat sends its receipt, as it always did; a group, which
  /// sends none, tells my other devices.
  void _readOnArrival(String contactRid, InnerMessage inner) {
    if (inner.kind == 'text' || inner.kind == 'file') {
      if (openChatRid == contactRid) {
        unawaited(_sendReadReceipts(contactRid));
      }
    } else if (inner.kind == 'gmsg' || inner.kind == 'gfile') {
      final gid = inner.data['gid'];
      if (gid is String && openChatRid == gid) {
        unawaited(_readGroupHere(gid).then((_) {}, onError: (Object _) {}));
      }
    }
  }

  /// A group's messages that arrived here since [since] — by default, since
  /// its chat was last opened here — and are not yet read here or on another
  /// of my devices: marked read, and my other devices told. Nothing goes to
  /// the members.
  Future<void> _readGroupHere(String gid, {int? since}) async {
    if (!groups.containsKey(gid)) return;
    final from = since ??
        int.tryParse(await vault.kvGet('last_open_$gid') ?? '') ??
        0;
    final rows = await vault.db.query('messages',
        columns: ['mid'],
        where: "rid = ? AND outgoing = 0 AND receipt_sent = 0 "
            "AND kind != 'system' AND ts_ms > ?",
        whereArgs: [gid, from]);
    if (rows.isEmpty) return;
    final mids = [for (final r in rows) r['mid'] as String];
    await _markRead(gid, mids);
    await _mirrorRead(gid, mids);
  }

  /// The incoming messages [mids] of [thread], read here or on another of my
  /// devices.
  Future<void> _markRead(String thread, List<String> mids) async {
    for (var i = 0; i < mids.length; i += _readMirrorBatch) {
      final part = mids.sublist(i, min(i + _readMirrorBatch, mids.length));
      await vault.db.update('messages', {'receipt_sent': 1},
          where: 'rid = ? AND outgoing = 0 AND receipt_sent = 0 AND mid IN '
              '(${List.filled(part.length, '?').join(',')})',
          whereArgs: [thread, ...part]);
    }
  }

  /// Tell my other devices that [mids] in [thread] were read on this one.
  /// Best effort, like the receipt to the contact: a lost one leaves a count
  /// over there, which reading there clears.
  Future<void> _mirrorRead(String thread, List<String> mids) async {
    final sync = _sync;
    if (sync == null || mids.isEmpty) return;
    try {
      for (var i = 0; i < mids.length; i += _readMirrorBatch) {
        await sync.mirror(
            threadRid: thread,
            dir: 'out',
            inner: InnerMessage.read(newMessageId(), _now(),
                mids.sublist(i, min(i + _readMirrorBatch, mids.length))));
      }
    } catch (_) {}
  }

  /// Messages read on another of my devices ([inner] is the `read` it
  /// mirrored): read here too, so this device's count clears and it sends no
  /// receipt of its own for them. Only the incoming messages of a chat this
  /// device holds are touched; the ids are the other device's say-so, and
  /// one that names nothing here is passed over.
  Future<void> _readElsewhere(String thread, InnerMessage inner) async {
    if (!contacts.containsKey(thread) && !groups.containsKey(thread)) return;
    final mids = [
      for (final m in (inner.data['mids'] as List?) ?? const [])
        if (m is String) m
    ];
    if (mids.isEmpty) return;
    await _markRead(thread, mids);
    if (openChatRid != thread) unread[thread] = await _unreadIn(thread);
    notifyListeners();
  }

  /// How many messages in [thread] this device counts unread: the incoming
  /// ones since the chat was last opened here, that no device of mine has
  /// read — [_computeUnread]'s rule, for one chat.
  Future<int> _unreadIn(String thread) async {
    final since =
        int.tryParse(await vault.kvGet('last_open_$thread') ?? '') ?? 0;
    return firstIntValue(await vault.db.rawQuery(
            "SELECT COUNT(*) FROM messages WHERE rid = ? AND outgoing = 0 "
            "AND kind != 'system' AND receipt_sent = 0 AND ts_ms > ?",
            [thread, since])) ??
        0;
  }

  /// One more unread message in [thread], unless it is open on this device.
  void _countUnread(String thread) {
    if (openChatRid != thread) unread[thread] = (unread[thread] ?? 0) + 1;
  }

  Future<bool> _holdsMessage(String thread, String mid) async =>
      (await vault.db.query('messages',
              columns: ['mid'],
              where: 'rid = ? AND mid = ?',
              whereArgs: [thread, mid],
              limit: 1))
          .isNotEmpty;

  // ------------------------------------------------------------------
  // Message loading & helpers
  // ------------------------------------------------------------------

  /// Window size for chat history paging (Phase 4.3): opening a 50k-message
  /// thread costs the same as a 60-message one; older pages load on scroll.
  static const int messagePageSize = 60;

  /// rid → whether older messages exist beyond what's loaded in memory.
  final Map<String, bool> hasMoreByChat = {};

  Future<ChatMessage> _rowToMessage(String rid, Map<String, Object?> r) async {
    final kind = r['kind'] as String;
    final deleted = ((r['deleted'] as int?) ?? 0) == 1;
    String body;
    String? senderName;
    FileMeta? fileMeta;
    if (kind == 'file') {
      // A tombstone keeps its kind and loses its id: nothing to load, and
      // reading it as a String threw, so a chat holding an attachment that
      // was deleted for everyone could not be opened again.
      final fid = r['fid'] as String?;
      fileMeta = deleted || fid == null
          ? null
          : await _loadFileMeta(rid, r['mid'] as String, fid);
      body = fileMeta?.name ?? 'file';
      try {
        final j =
            (jsonDecode(await vault.unseal(r['enc_body'] as String)) as Map)
                .cast<String, Object?>();
        senderName = j['sn'] as String?; // set for group attachments
      } catch (_) {}
    } else if (kind == 'gtext') {
      final j = (jsonDecode(await vault.unseal(r['enc_body'] as String)) as Map)
          .cast<String, Object?>();
      body = j['b'] as String? ?? '';
      senderName = j['sn'] as String?;
    } else {
      body = await vault.unseal(r['enc_body'] as String);
    }
    if (deleted) body = '';
    final replyTo = r['reply_to'] as String?;
    return ChatMessage(
      mid: r['mid'] as String,
      rid: rid,
      outgoing: (r['outgoing'] as int) == 1,
      kind: kind,
      body: body,
      fid: r['fid'] as String?,
      ts: r['ts_ms'] as int,
      status: r['status'] as int,
      expireAtMs: r['expire_at_ms'] as int,
      file: fileMeta,
      senderName: senderName,
      replyTo: replyTo,
      // Resolved on every load: the quoted message may since have expired.
      quote: await _resolveQuote(rid, replyTo),
      editedMs: (r['edited_ms'] as int?) ?? 0,
      deleted: deleted,
      forwarded: ((r['forwarded'] as int?) ?? 0) == 1,
    );
  }

  /// 7.6 message search. Scans stored messages, decrypting bodies (and file
  /// names) in memory ONLY — the query and its matches never touch disk, in
  /// keeping with the vault invariant — and returns the most recent matches.
  /// Case-insensitive substring over text, group text and attachment names.
  Future<List<SearchHit>> searchMessages(String query,
      {int limit = 100}) async {
    final q = query.trim().toLowerCase();
    if (q.isEmpty) return [];
    // Newest first; scan a bounded window so a huge history can't stall search.
    final rows = await vault.db.query('messages',
        where: 'kind IN (?, ?, ?)',
        whereArgs: ['text', 'gtext', 'file'],
        orderBy: 'ts_ms DESC',
        limit: 5000);
    final hits = <SearchHit>[];
    for (final r in rows) {
      final rid = r['rid'] as String;
      final isGroup = groups.containsKey(rid);
      // The chat must still exist locally to show and open the result.
      final title = isGroup ? groups[rid]?.name : contacts[rid]?.name;
      if (title == null) continue;
      final ChatMessage m;
      try {
        m = await _rowToMessage(rid, r);
      } catch (_) {
        continue; // unreadable cell (e.g. mid-wipe) — skip
      }
      final idx = m.body.toLowerCase().indexOf(q);
      if (idx < 0) continue;
      hits.add(SearchHit(
        rid: rid,
        mid: m.mid,
        title: title,
        isGroup: isGroup,
        outgoing: m.outgoing,
        kind: m.kind,
        snippet: _snippet(m.body, idx, q.length),
        ts: m.ts,
        senderName: m.senderName,
      ));
      if (hits.length >= limit) break;
    }
    return hits;
  }

  /// A short window of [body] around the match at [idx], with ellipses when it
  /// is clipped, so results read cleanly without leaking the whole message.
  static String _snippet(String body, int idx, int qlen) {
    const pad = 24;
    if (body.length <= 80) return body;
    var start = idx - pad;
    var end = idx + qlen + pad;
    final pre = start > 0 ? '…' : '';
    final post = end < body.length ? '…' : '';
    if (start < 0) start = 0;
    if (end > body.length) end = body.length;
    return '$pre${body.substring(start, end).trim()}$post';
  }

  /// Load the NEWEST page of a thread. Older history stays on disk until
  /// [loadOlderMessages] pulls it in.
  Future<List<ChatMessage>> loadMessages(String rid) async {
    final rows = await vault.db.query('messages',
        where: 'rid = ?',
        whereArgs: [rid],
        orderBy: 'ts_ms DESC',
        limit: messagePageSize + 1);
    hasMoreByChat[rid] = rows.length > messagePageSize;
    final list = <ChatMessage>[];
    for (final r in rows.take(messagePageSize).toList().reversed) {
      list.add(await _rowToMessage(rid, r));
    }
    await _attachReactions(rid, list);
    messagesByChat[rid] = list;
    return list;
  }

  /// How far back a search hit can be jumped to directly. Beyond this the chat
  /// opens normally (the hit is reachable by paging), so the window a jump
  /// loads is always bounded.
  static const int jumpWindowMax = 500;

  /// 7.6: open a thread so that message [mid] is on screen — the loaded window
  /// runs from that message to the newest one, so the existing "load older on
  /// scroll-up" paging still works from its far end. Returns false (and loads
  /// nothing) when the message is unknown or more than [jumpWindowMax]
  /// messages back; the caller then falls back to [loadMessages].
  Future<bool> loadMessagesAround(String rid, String mid) async {
    final target = await vault.db.query('messages',
        columns: ['ts_ms'],
        where: 'rid = ? AND mid = ?',
        whereArgs: [rid, mid],
        limit: 1);
    if (target.isEmpty) return false;
    final ts = target.first['ts_ms'] as int;
    final newer = firstIntValue(await vault.db.rawQuery(
            'SELECT COUNT(*) FROM messages WHERE rid = ? AND ts_ms >= ?',
            [rid, ts])) ??
        0;
    if (newer > jumpWindowMax) return false;
    final rows = await vault.db.query('messages',
        where: 'rid = ? AND ts_ms >= ?',
        whereArgs: [rid, ts],
        orderBy: 'ts_ms ASC');
    final list = <ChatMessage>[];
    for (final r in rows) {
      list.add(await _rowToMessage(rid, r));
    }
    final older = firstIntValue(await vault.db.rawQuery(
            'SELECT COUNT(*) FROM messages WHERE rid = ? AND ts_ms < ?',
            [rid, ts])) ??
        0;
    await _attachReactions(rid, list);
    hasMoreByChat[rid] = older > 0;
    messagesByChat[rid] = list;
    return true;
  }

  /// Prepend the next (older) page of a thread. Returns how many messages
  /// were added; 0 means the full history is already loaded.
  Future<int> loadOlderMessages(String rid) async {
    final current = messagesByChat[rid];
    if (current == null || current.isEmpty || hasMoreByChat[rid] != true) {
      return 0;
    }
    final oldestTs = current.first.ts;
    final rows = await vault.db.query('messages',
        where: 'rid = ? AND ts_ms < ?',
        whereArgs: [rid, oldestTs],
        orderBy: 'ts_ms DESC',
        limit: messagePageSize + 1);
    hasMoreByChat[rid] = rows.length > messagePageSize;
    final have = current.map((m) => m.mid).toSet();
    final older = <ChatMessage>[];
    for (final r in rows.take(messagePageSize).toList().reversed) {
      final msg = await _rowToMessage(rid, r);
      if (!have.contains(msg.mid)) older.add(msg);
    }
    await _attachReactions(rid, older);
    current.insertAll(0, older);
    notifyListeners();
    return older.length;
  }

  // ------------------------------------------------------------------
  // 8.1c edit / delete for everyone / forward
  // ------------------------------------------------------------------

  /// Text kinds an edit may touch. Attachments and system notices are not
  /// editable: there is no body to replace.
  static const Set<String> _editableKinds = {'text', 'gtext'};

  /// Replaces the text of one of MY messages and tells the other side. The
  /// original timestamp is kept and the message is marked edited — an edit is
  /// never silent. Returns false when the message is not mine, not text, or
  /// already deleted.
  Future<bool> editMessage(String rid, String mid, String newBody) async {
    final body = newBody.trim();
    if (body.isEmpty) return false;
    final isGroup = groups.containsKey(rid);
    if (isGroup && groups[rid]!.left) return false;
    final rows = await vault.db.query('messages',
        where: 'rid = ? AND mid = ?', whereArgs: [rid, mid], limit: 1);
    if (rows.isEmpty) return false;
    final r = rows.first;
    if ((r['outgoing'] as int) != 1) return false; // only my own
    if (((r['deleted'] as int?) ?? 0) == 1) return false;
    final kind = r['kind'] as String;
    if (!_editableKinds.contains(kind)) return false;

    final now = _now();
    await _applyEditLocally(rid, mid, kind, body, now);
    notifyListeners();

    final inner = InnerMessage.edit(newMessageId(), now,
        target: mid, body: body, gid: isGroup ? rid : null);
    if (isGroup) {
      await _queueGroupFanout(groups[rid]!, inner);
    } else {
      await _sendInnerOrHold(contacts[rid]!, inner);
    }
    unawaited(_sync?.mirror(threadRid: rid, dir: 'out', inner: inner) ??
        Future<void>.value());
    return true;
  }

  /// Writes the new body, preserving the sealed envelope's other members
  /// (sender name/rid, forwarded flag) so a group edit keeps its attribution.
  Future<void> _applyEditLocally(
      String rid, String mid, String kind, String body, int now,
      {DatabaseExecutor? txn}) async {
    final db = txn ?? vault.db;
    String sealed;
    if (kind == 'gtext') {
      Map<String, Object?> j = {};
      final rows = await db.query('messages',
          columns: ['enc_body'],
          where: 'rid = ? AND mid = ?',
          whereArgs: [rid, mid],
          limit: 1);
      if (rows.isNotEmpty) {
        try {
          j = (jsonDecode(await vault.unseal(rows.first['enc_body'] as String))
                  as Map)
              .cast<String, Object?>();
        } catch (_) {}
      }
      j['b'] = body;
      sealed = await vault.seal(jsonEncode(j));
    } else {
      sealed = await vault.seal(body);
    }
    await db.update('messages', {'enc_body': sealed, 'edited_ms': now},
        where: 'rid = ? AND mid = ?', whereArgs: [rid, mid]);
    final loaded = messagesByChat[rid];
    final idx = loaded?.indexWhere((m) => m.mid == mid) ?? -1;
    if (loaded != null && idx >= 0) {
      final old = loaded[idx];
      loaded[idx] = ChatMessage(
        mid: old.mid,
        rid: old.rid,
        outgoing: old.outgoing,
        kind: old.kind,
        body: body,
        fid: old.fid,
        ts: old.ts,
        status: old.status,
        expireAtMs: old.expireAtMs,
        file: old.file,
        senderName: old.senderName,
        replyTo: old.replyTo,
        quote: old.quote,
        reactions: old.reactions,
        editedMs: now,
        forwarded: old.forwarded,
      );
    }
  }

  /// Deletes MY messages for everyone: the body (and any attachment) is wiped
  /// here and the peers are asked to do the same. Best effort by nature — a
  /// recipient who already read it is beyond reach, which the UI states.
  Future<void> deleteForEveryone(String rid, List<String> mids) async {
    final isGroup = groups.containsKey(rid);
    if (isGroup && groups[rid]!.left) return;
    final mine = <String>[];
    for (final mid in mids) {
      final rows = await vault.db.query('messages',
          columns: ['outgoing'],
          where: 'rid = ? AND mid = ?',
          whereArgs: [rid, mid],
          limit: 1);
      if (rows.isNotEmpty && (rows.first['outgoing'] as int) == 1) {
        mine.add(mid);
      }
    }
    if (mine.isEmpty) return;
    for (final mid in mine) {
      await _tombstone(rid, mid);
    }
    notifyListeners();
    final inner = InnerMessage.deleteForEveryone(newMessageId(), _now(),
        targets: mine, gid: isGroup ? rid : null);
    if (isGroup) {
      await _queueGroupFanout(groups[rid]!, inner);
    } else {
      await _sendInnerOrHold(contacts[rid]!, inner);
    }
    unawaited(_sync?.mirror(threadRid: rid, dir: 'out', inner: inner) ??
        Future<void>.value());
  }

  /// Removes the attachment message [mid] in [rid] brought — the `files` row
  /// bound to that message under [fid], and the chunks still held for it —
  /// and says whether there was one, so the caller destroys the blob only
  /// then (§7).
  ///
  /// By the message, never by the id alone. Every delete path used to remove
  /// whatever the vault held under the id, and an id is chosen by its sender
  /// and seen by every member of a group: a member's message naming another
  /// member's id, deleted by its author as the authorship rule allows, took
  /// the other member's file with it.
  Future<bool> _dropAttachment(
      DatabaseExecutor db, String rid, String mid, String fid) async {
    final n = await db.delete('files',
        where: 'fid = ? AND rid = ? AND mid = ?', whereArgs: [fid, rid, mid]);
    if (n == 0) return false;
    await db.delete('chunks', where: 'fid = ?', whereArgs: [fid]);
    return true;
  }

  /// Turns one message into a tombstone: body wiped, attachment blob and
  /// chunks destroyed, reactions dropped, row kept so the conversation keeps
  /// its shape and replies to it still resolve (as "unavailable"). The
  /// attachment is the message's own ([_dropAttachment]).
  Future<void> _tombstone(String rid, String mid,
      {DatabaseExecutor? txn}) async {
    final db = txn ?? vault.db;
    final rows = await db.query('messages',
        columns: ['fid', 'kind'],
        where: 'rid = ? AND mid = ?',
        whereArgs: [rid, mid],
        limit: 1);
    if (rows.isEmpty) return;
    final fid = rows.first['fid'] as String?;
    if (fid != null && await _dropAttachment(db, rid, mid, fid)) {
      await vault.deleteBlob(fid);
    }
    await db.update(
        'messages',
        {
          'deleted': 1,
          'enc_body': await vault.seal(''),
          'fid': null,
          'reply_to': null,
        },
        where: 'rid = ? AND mid = ?',
        whereArgs: [rid, mid]);
    await db.delete('reactions',
        where: 'rid = ? AND mid = ?', whereArgs: [rid, mid]);
    final loaded = messagesByChat[rid];
    final idx = loaded?.indexWhere((m) => m.mid == mid) ?? -1;
    if (loaded != null && idx >= 0) {
      final old = loaded[idx];
      loaded[idx] = ChatMessage(
        mid: old.mid,
        rid: old.rid,
        outgoing: old.outgoing,
        kind: old.kind,
        body: '',
        ts: old.ts,
        status: old.status,
        senderName: old.senderName,
        deleted: true,
      );
    }
  }

  /// Who wrote a stored message, for the authorship rule. Returns null when
  /// the row is mine, unknown, or (a pre-8.1c group row) does not record it —
  /// all of which make an incoming edit/delete inapplicable.
  Future<String?> _storedSenderRid(String rid, Map<String, Object?> r) async {
    // Mine: nobody else may edit or delete it, whoever asks.
    if ((r['outgoing'] as int) == 1) return null;
    // 1:1: the conversation is the peer, and the ratchet already proved who
    // is speaking.
    if (!groups.containsKey(rid)) return rid;
    // Group: the sealed envelope records the sender's routing id ('sr').
    // A row written before 8.1c has none, and fails the check — deliberately,
    // since the alternative is letting a member delete a neighbour's message.
    try {
      final j = (jsonDecode(await vault.unseal(r['enc_body'] as String)) as Map)
          .cast<String, Object?>();
      final sr = j['sr'];
      return sr is String && sr.isNotEmpty ? sr : null;
    } catch (_) {
      return null;
    }
  }

  /// An edit that arrived from [contact]. Applied ONLY to a message that same
  /// contact wrote in that same conversation (§6.6).
  Future<void> _applyEdit(Contact contact, InnerMessage inner,
      {DatabaseExecutor? txn}) async {
    final target = inner.replyTo;
    final body = inner.data['body'];
    if (target == null || body is! String) return;
    final gid = inner.data['gid'] as String?;
    final String rid;
    if (inner.kind == 'gedit') {
      final g = gid == null ? null : groups[gid];
      if (g == null || g.left || !g.memberRids.contains(contact.rid)) return;
      rid = gid!;
    } else {
      rid = contact.rid;
    }
    final db = txn ?? vault.db;
    final rows = await db.query('messages',
        where: 'rid = ? AND mid = ?', whereArgs: [rid, target], limit: 1);
    if (rows.isEmpty) return;
    final r = rows.first;
    if (((r['deleted'] as int?) ?? 0) == 1) return;
    final kind = r['kind'] as String;
    if (!_editableKinds.contains(kind)) return;
    // The authorship rule.
    if (await _storedSenderRid(rid, r) != contact.rid) return;
    await _applyEditLocally(rid, target, kind, body, inner.ts, txn: txn);
  }

  /// A delete-for-everyone from [contact], subject to the same rule.
  Future<void> _applyDelete(Contact contact, InnerMessage inner,
      {DatabaseExecutor? txn}) async {
    final targets = inner.deleteTargets;
    if (targets.isEmpty) return;
    final gid = inner.data['gid'] as String?;
    final String rid;
    if (inner.kind == 'gdel') {
      final g = gid == null ? null : groups[gid];
      if (g == null || g.left || !g.memberRids.contains(contact.rid)) return;
      rid = gid!;
    } else {
      rid = contact.rid;
    }
    final db = txn ?? vault.db;
    for (final target in targets) {
      final rows = await db.query('messages',
          where: 'rid = ? AND mid = ?', whereArgs: [rid, target], limit: 1);
      if (rows.isEmpty) continue;
      if (await _storedSenderRid(rid, rows.first) != contact.rid) continue;
      await _tombstone(rid, target, txn: txn);
    }
  }

  /// Passes a message on to another conversation as a NEW message, marked
  /// "forwarded". An attachment is re-sent from this device's copy: the
  /// recipient gets fresh key material, since the original key belongs to the
  /// original conversation.
  Future<void> forwardMessage(String fromRid, String mid, String toRid) async {
    final rows = await vault.db.query('messages',
        where: 'rid = ? AND mid = ?', whereArgs: [fromRid, mid], limit: 1);
    if (rows.isEmpty) return;
    final r = rows.first;
    if (((r['deleted'] as int?) ?? 0) == 1) return;
    final msg = await _rowToMessage(fromRid, r);
    final toGroup = groups.containsKey(toRid);
    if (!toGroup && !contacts.containsKey(toRid)) return;
    if (toGroup && groups[toRid]!.left) return;
    if (msg.kind == 'file') {
      final fid = msg.fid;
      if (fid == null) return;
      // This message's own attachment — not whatever else holds its id.
      final bytes = await readAttachment(fid, rid: fromRid, mid: mid);
      final meta = msg.file;
      if (toGroup) {
        await sendGroupFile(toRid, meta?.name ?? 'file', bytes,
            meta?.mime ?? 'application/octet-stream',
            forwarded: true);
      } else {
        await sendFile(toRid, meta?.name ?? 'file', bytes,
            meta?.mime ?? 'application/octet-stream',
            forwarded: true);
      }
      return;
    }
    if (toGroup) {
      await sendGroupText(toRid, msg.body, forwarded: true);
    } else {
      await sendText(toRid, msg.body, forwarded: true);
    }
  }

  // ------------------------------------------------------------------
  // 8.1b reactions
  // ------------------------------------------------------------------

  /// The emoji offered in the picker. Kept short and unambiguous; any emoji
  /// that arrives from a peer still renders, this is only what we send.
  static const List<String> quickReactions = [
    '👍',
    '❤️',
    '😂',
    '😮',
    '😢',
    '🙏'
  ];

  /// Adds, replaces or withdraws MY reaction to [mid] in conversation [rid]:
  /// reacting with the emoji already showing withdraws it. Returns the emoji
  /// now in effect (empty when withdrawn).
  Future<String> toggleReaction(String rid, String mid, String emoji) async {
    final isGroup = groups.containsKey(rid);
    if (!isGroup && !contacts.containsKey(rid)) return '';
    if (isGroup && (groups[rid]!.left)) return '';
    // The target must exist here — the same conversation-scoped rule the
    // wire format uses (§6.4/§6.5).
    final target = await vault.db.query('messages',
        columns: ['mid'],
        where: 'rid = ? AND mid = ?',
        whereArgs: [rid, mid],
        limit: 1);
    if (target.isEmpty) return '';

    final current = await _myReaction(rid, mid);
    final next = current == emoji ? '' : emoji;
    await _storeReaction(rid: rid, mid: mid, senderRid: myRid, emoji: next);
    await _refreshLoadedReactions(rid, mid);
    notifyListeners();

    final inner = InnerMessage.reaction(newMessageId(), _now(),
        target: mid, emoji: next, gid: isGroup ? rid : null);
    if (isGroup) {
      await _queueGroupFanout(groups[rid]!, inner);
    } else {
      // _sendInner already fans out to the contact's other devices.
      await _sendInnerOrHold(contacts[rid]!, inner);
    }
    unawaited(_sync?.mirror(threadRid: rid, dir: 'out', inner: inner) ??
        Future<void>.value());
    return next;
  }

  /// Sends an arbitrary inner to [rid], bypassing the checks a well-behaved
  /// client applies before sending. Exists so tests can play a HOSTILE peer —
  /// the receiver's own validation is the security property, and it has to be
  /// exercised by traffic a friendly client would never produce.
  /// Feed one relay envelope straight into the inbound path, as the
  /// transport would. Test seam: the receive-side benchmark needs to time
  /// what happens AFTER the bytes arrive, without a network in the number.
  @visibleForTesting
  Future<void> debugInbound(RelayInbound m) => _onInbound(m);

  /// Test seam: make the next self-sync vault write throw once, to prove a
  /// transient failure on the self-sync receive path leaves the envelope with
  /// the relay rather than acknowledging it away. Returns false if this
  /// device has no self-sync (nothing linked), so a test can skip.
  @visibleForTesting
  bool debugFailNextSyncSave() {
    final s = _sync;
    if (s == null) return false;
    s.debugFailNextInboundSave = true;
    return true;
  }

  /// How many times the self-sync one-shot save failure has fired. Test seam
  /// paired with [debugFailNextSyncSave].
  @visibleForTesting
  int get debugSyncSaveFailures => _sync?.debugSaveFailures ?? 0;

  /// Encrypt arbitrary bytes to [rid] through the established conversation and
  /// seal them as a sealed-sender envelope, persisting the advanced ratchet.
  /// Test seam for finding 42: a peer's client can put anything inside a
  /// validly-encrypted envelope, and this crafts one whose inner PLAINTEXT is
  /// malformed so a test can prove the receiver acknowledges it rather than
  /// wedging the mailbox slot. Returns the transport payload.
  @visibleForTesting
  Future<String> debugSealRaw(String rid, Uint8List plaintext) async {
    final conv = await _convFor(contacts[rid]!);
    final payload = await _sealFor(rid, await conv.encrypt(plaintext));
    await _saveConv(rid);
    return payload;
  }

  /// The disappearing-message sweep, on demand: tests assert what it removes
  /// rather than wait twenty seconds for the timer that normally runs it.
  @visibleForTesting
  Future<void> debugSweep() => _sweepSerial();

  /// Whether the sweep's timer is still running — it stops itself once the
  /// service is disposed or its vault closed (42.4).
  @visibleForTesting
  bool get debugSweeperActive => _sweeper?.isActive ?? false;

  /// The live conversation object for [rid], or null. Test seam for the
  /// receive-side benchmark, which times the ratchet step on its own.
  @visibleForTesting
  Conversation? debugConversation(String rid) => _convs[rid];

  /// The own-device-list claim every message is stamped with. Test seam for
  /// the receive-side benchmark, which found it being recomputed per message.
  @visibleForTesting
  Future<(int, String)> debugOwnListClaim() => _ownListClaim();

  @visibleForTesting
  Future<void> sendRawInner(String rid, InnerMessage inner) async {
    final contact = contacts[rid];
    if (contact == null) return;
    await _sendInner(contact, inner);
  }

  Future<String> _myReaction(String rid, String mid) async {
    final rows = await vault.db.query('reactions',
        columns: ['enc_emoji'],
        where: 'rid = ? AND mid = ? AND sender_rid = ?',
        whereArgs: [rid, mid, myRid],
        limit: 1);
    if (rows.isEmpty) return '';
    try {
      return await vault.unseal(rows.first['enc_emoji'] as String);
    } catch (_) {
      return '';
    }
  }

  /// Writes one sender's reaction (empty [emoji] removes it). Emoji are
  /// sealed like any other content.
  Future<void> _storeReaction({
    required String rid,
    required String mid,
    required String senderRid,
    required String emoji,
    DatabaseExecutor? txn,
  }) async {
    final db = txn ?? vault.db;
    if (emoji.isEmpty) {
      await db.delete('reactions',
          where: 'rid = ? AND mid = ? AND sender_rid = ?',
          whereArgs: [rid, mid, senderRid]);
      return;
    }
    await db.insert(
        'reactions',
        {
          'rid': rid,
          'mid': mid,
          'sender_rid': senderRid,
          'enc_emoji': await vault.seal(emoji),
          'ts_ms': _now(),
        },
        conflictAlgorithm: ConflictAlgorithm.replace);
  }

  /// A reaction that arrived from [contact] (1:1 or group). Dropped unless it
  /// names a message in that same conversation.
  Future<void> _applyReaction(Contact contact, InnerMessage inner,
      {DatabaseExecutor? txn}) async {
    final r = inner.reactionData;
    if (r == null) return;
    final gid = inner.data['gid'] as String?;
    final String rid;
    if (inner.kind == 'greact') {
      final g = gid == null ? null : groups[gid];
      if (g == null || g.left || !g.memberRids.contains(contact.rid)) return;
      rid = gid!;
    } else {
      rid = contact.rid;
    }
    final target = await (txn ?? vault.db).query('messages',
        columns: ['mid'],
        where: 'rid = ? AND mid = ?',
        whereArgs: [rid, r.target],
        limit: 1);
    if (target.isEmpty) return; // unknown here: nothing to react to
    await _storeReaction(
        rid: rid,
        mid: r.target,
        senderRid: contact.rid,
        emoji: r.emoji,
        txn: txn);
    await _refreshLoadedReactions(rid, r.target, txn: txn);
  }

  /// Re-reads the reactions of one loaded message so the UI updates without
  /// reloading the thread. [txn] MUST be passed when called from inside the
  /// inbound transaction — going to `vault.db` there deadlocks against the
  /// lock the transaction already holds.
  Future<void> _refreshLoadedReactions(String rid, String mid,
      {DatabaseExecutor? txn}) async {
    final loaded = messagesByChat[rid];
    if (loaded == null) return;
    final idx = loaded.indexWhere((m) => m.mid == mid);
    if (idx < 0) return;
    loaded[idx].reactions =
        (await _loadReactions(rid, [mid], txn: txn))[mid] ?? [];
  }

  /// Reactions for a set of message ids in one query, decrypted in memory.
  Future<Map<String, List<MessageReaction>>> _loadReactions(
      String rid, List<String> mids,
      {DatabaseExecutor? txn}) async {
    if (mids.isEmpty) return {};
    final marks = List.filled(mids.length, '?').join(',');
    final rows = await (txn ?? vault.db).rawQuery(
        'SELECT mid, sender_rid, enc_emoji FROM reactions '
        'WHERE rid = ? AND mid IN ($marks) ORDER BY ts_ms ASC',
        [rid, ...mids]);
    final out = <String, List<MessageReaction>>{};
    for (final r in rows) {
      String emoji;
      try {
        emoji = await vault.unseal(r['enc_emoji'] as String);
      } catch (_) {
        continue;
      }
      if (emoji.isEmpty) continue;
      final sender = r['sender_rid'] as String;
      out.putIfAbsent(r['mid'] as String, () => []).add(MessageReaction(
            emoji: emoji,
            senderRid: sender,
            mine: _myAccountRids.contains(sender),
            senderName:
                _myAccountRids.contains(sender) ? null : contacts[sender]?.name,
          ));
    }
    return out;
  }

  /// Attaches reactions to a freshly loaded page (one query for the page).
  Future<void> _attachReactions(String rid, List<ChatMessage> list) async {
    if (list.isEmpty) return;
    final byMid = await _loadReactions(rid, [for (final m in list) m.mid]);
    if (byMid.isEmpty) return;
    for (final m in list) {
      m.reactions = byMid[m.mid] ?? [];
    }
  }

  /// 8.1: looks up [mid] **inside conversation [rid]** and builds what a
  /// reply will show of it. Returns null — an unavailable quote — when the id
  /// is malformed, names nothing here, names a system notice, or names a
  /// message in another chat; the caller then stores no reply link at all, so
  /// a peer cannot use `rt` to learn whether an id exists elsewhere.
  Future<QuotedMessage?> _resolveQuote(String rid, String? mid,
      {DatabaseExecutor? txn}) async {
    if (mid == null || mid.isEmpty || mid.length > 64) return null;
    final rows = await (txn ?? vault.db).query('messages',
        columns: ['mid', 'outgoing', 'kind', 'enc_body', 'fid'],
        where: 'rid = ? AND mid = ?',
        whereArgs: [rid, mid],
        limit: 1);
    if (rows.isEmpty) return null;
    final r = rows.first;
    final kind = r['kind'] as String;
    if (kind == 'system') return null;
    String preview;
    String? senderName;
    try {
      if (kind == 'file') {
        // Through [txn]: a reply is resolved inside the transaction that
        // stores it, and a read on the database's own connection there waits
        // for that transaction to end — which waits for this.
        final fid = r['fid'] as String?;
        preview = (fid == null
                    ? null
                    : await _loadFileMeta(rid, mid, fid, db: txn))
                ?.name ??
            'Attachment';
      } else if (kind == 'gtext') {
        final j =
            (jsonDecode(await vault.unseal(r['enc_body'] as String)) as Map)
                .cast<String, Object?>();
        preview = j['b'] as String? ?? '';
        senderName = j['sn'] as String?;
      } else {
        preview = await vault.unseal(r['enc_body'] as String);
      }
    } catch (_) {
      return null; // unreadable row: better no quote than a wrong one
    }
    return QuotedMessage(
      mid: mid,
      outgoing: (r['outgoing'] as int) == 1,
      kind: kind,
      preview: preview.length > 240 ? preview.substring(0, 240) : preview,
      senderName: senderName,
    );
  }

  /// The attachment message [mid] in conversation [rid] brought, under the
  /// file id [fid] its row names — and only that one (§7). A message used to
  /// show whatever the vault held under the id, so a member's message naming
  /// another member's id showed the other member's file, and the other
  /// member's message showed whatever had taken that id over.
  Future<FileMeta?> _loadFileMeta(String rid, String mid, String fid,
      {DatabaseExecutor? db}) async {
    final rows = await (db ?? vault.db).query('files',
        where: 'fid = ? AND rid = ? AND mid = ?', whereArgs: [fid, rid, mid]);
    if (rows.isEmpty) return null;
    final r = rows.first;
    final meta =
        (jsonDecode(await vault.unseal(r['enc_meta'] as String)) as Map)
            .cast<String, Object?>();
    return FileMeta(
      fid: fid,
      name: meta['name'] as String? ?? 'file',
      size: (meta['size'] as num?)?.toInt() ?? 0,
      mime: meta['mime'] as String? ?? 'application/octet-stream',
      sha256b64: meta['sha256'] as String? ?? '',
      complete: (r['complete'] as int) == 1,
      gotChunks: r['got_chunks'] as int,
      totalChunks: r['total_chunks'] as int,
      voice: meta['voice'] == true,
      durSec: (meta['dur'] as num?)?.toInt() ?? 0,
    );
  }

  /// Decrypted attachment bytes (for viewing/saving). Never touches disk in
  /// plaintext.
  ///
  /// A file id names one attachment in this vault — §7's rule refuses an id
  /// already held for another message — so [fid] alone finds the one a
  /// screen was shown. A caller re-sending a message's own attachment (a
  /// forward, a group fan-out) also passes the message, [rid] and [mid], and
  /// gets nothing if the id is no longer that message's.
  Future<Uint8List> readAttachment(String fid,
      {String? rid, String? mid}) async {
    final rows = await vault.db.query('files',
        where: [
          'fid = ?',
          if (rid != null) 'rid = ?',
          if (mid != null) 'mid = ?',
        ].join(' AND '),
        whereArgs: [fid, if (rid != null) rid, if (mid != null) mid]);
    if (rows.isEmpty) throw StateError('no such attachment');
    final meta =
        (jsonDecode(await vault.unseal(rows.first['enc_meta'] as String))
                as Map)
            .cast<String, Object?>();
    final local = (meta['local'] as Map?)?.cast<String, Object?>();
    if (local == null) throw StateError('attachment not complete yet');
    return vault.readBlob(fid, local);
  }

  List<ChatSummary> chatSummaries() {
    final out = <ChatSummary>[];
    for (final c in contacts.values) {
      final msgs = messagesByChat[c.rid];
      out.add(ChatSummary(
        contact: c,
        last: (msgs != null && msgs.isNotEmpty) ? msgs.last : null,
        unread: unread[c.rid] ?? 0,
      ));
    }
    for (final g in groups.values) {
      final msgs = messagesByChat[g.gid];
      out.add(ChatSummary(
        group: g,
        last: (msgs != null && msgs.isNotEmpty) ? msgs.last : null,
        unread: unread[g.gid] ?? 0,
      ));
    }
    out.sort((a, b) {
      final ta = a.last?.ts ?? a.contact?.createdMs ?? 0;
      final tb = b.last?.ts ?? b.contact?.createdMs ?? 0;
      return tb.compareTo(ta);
    });
    return out;
  }

  void _appendLoaded(String rid, ChatMessage msg) {
    var list = messagesByChat[rid];
    if (list == null) {
      // Only a contact or a group has a thread. Creating one for a rid that
      // is neither would put a conversation back on the home screen after
      // the user deleted it — the in-memory half of the same race the
      // per-contact lock closes in the vault (`contact_erasure_test` 4, 5).
      if (!contacts.containsKey(rid) && !groups.containsKey(rid)) return;
      list = messagesByChat[rid] = [];
    }
    // Idempotent: a rolled-back-then-redelivered message must not appear twice.
    if (list.any((m) => m.mid == msg.mid)) return;
    list.add(msg);
  }

  /// Re-decide the tick on this group's undelivered messages.
  ///
  /// "Delivered when every current member has confirmed" is a rule about a
  /// set that shrinks. Evaluating it only when a receipt ARRIVES would leave
  /// a message waiting for ever on somebody who has left — which is a worse
  /// lie than the one this replaced, because it never resolves. So membership
  /// changes ask the question again.
  Future<void> _reevaluateGroupDelivery(String gid) async {
    final g = groups[gid];
    if (g == null || g.memberRids.isEmpty) return;
    final marks = List.filled(g.memberRids.length, '?').join(',');
    final pending = await vault.db.query('messages',
        columns: ['mid'],
        where: 'rid = ? AND outgoing = 1 AND status < ?',
        whereArgs: [gid, MsgStatus.delivered]);
    for (final row in pending) {
      final mid = row['mid'] as String;
      final have = firstIntValue(await vault.db.rawQuery(
              'SELECT COUNT(DISTINCT from_rid) FROM delivery '
              'WHERE mid = ? AND thread_rid = ? AND from_rid IN ($marks)',
              [mid, gid, ...g.memberRids])) ??
          0;
      if (have < g.memberRids.length) continue;
      await vault.db.update('messages', {'status': MsgStatus.delivered},
          where: 'mid = ? AND rid = ? AND outgoing = 1 AND status < ?',
          whereArgs: [mid, gid, MsgStatus.delivered]);
      _updateLoadedStatus(gid, mid, MsgStatus.delivered, onlyUpgrade: true);
    }
  }

  /// Record that [contact] has confirmed [mid], and move the tick only if
  /// everyone the message was addressed to has now done so.
  ///
  /// Scoped to threads this contact is a party to — their own, and the groups
  /// they are in. A receipt naming a message in any other thread is a claim
  /// about somebody else's conversation and is simply not theirs to make.
  Future<void> _recordDelivery(
      DatabaseExecutor txn, Contact contact, String mid) async {
    final threads = <String>[
      contact.rid,
      for (final g in groups.values)
        if (!g.left && g.memberRids.contains(contact.rid)) g.gid,
    ];
    final marks = List.filled(threads.length, '?').join(',');
    final rows = await txn.query('messages',
        columns: ['rid'],
        where: 'mid = ? AND rid IN ($marks) AND outgoing = 1 AND status < ?',
        whereArgs: [mid, ...threads, MsgStatus.delivered]);
    if (rows.isEmpty) return; // not theirs to confirm, or already delivered
    final thread = rows.first['rid'] as String;

    await txn.insert(
        'delivery',
        {
          'mid': mid,
          'thread_rid': thread,
          'from_rid': contact.rid,
          'at_ms': _now(),
        },
        conflictAlgorithm: ConflictAlgorithm.ignore);

    // A 1:1 message is delivered when its one recipient says so. A group
    // message is delivered when every CURRENT member has — a member who has
    // left is no longer someone the tick is waiting for, which is the only
    // rule that cannot leave a message waiting for ever.
    final group = groups[thread];
    if (group != null) {
      final need = group.memberRids.length;
      final have = firstIntValue(await txn.rawQuery(
              'SELECT COUNT(DISTINCT from_rid) FROM delivery '
              'WHERE mid = ? AND thread_rid = ? AND from_rid IN '
              '(${List.filled(group.memberRids.length, '?').join(',')})',
              [mid, thread, ...group.memberRids])) ??
          0;
      if (need == 0 || have < need) return;
    }
    await txn.update('messages', {'status': MsgStatus.delivered},
        where: 'mid = ? AND rid = ? AND outgoing = 1 AND status < ?',
        whereArgs: [mid, thread, MsgStatus.delivered]);
    _updateLoadedStatus(thread, mid, MsgStatus.delivered, onlyUpgrade: true);
  }

  void _updateLoadedStatus(String rid, String mid, int status,
      {bool onlyUpgrade = false}) {
    final list = messagesByChat[rid];
    if (list == null) return;
    for (final m in list) {
      if (m.mid == mid && m.outgoing) {
        if (!onlyUpgrade || status > m.status) m.status = status;
      }
    }
  }

  void _updateLoadedFileProgress(
      String rid, String mid, int got, int total, bool complete) {
    final list = messagesByChat[rid];
    if (list == null) return;
    for (final m in list) {
      if (m.mid == mid && m.file != null) {
        m.file!.gotChunks = got;
        m.file!.totalChunks = total;
        m.file!.complete = complete;
      }
    }
  }

  /// An envelope arrived on a session this device does not hold — the
  /// peer's state predates ours, which is what a restore from backup looks
  /// like from the other side. Tell the user once per episode, and open a
  /// fresh session so the next thing they send can be read.
  ///
  /// After a restore, EVERYTHING queued at the relay while the device was
  /// gone arrives like this, one envelope after another: the peer's
  /// delivery receipts and typing state as much as their messages, and the
  /// device cannot tell which was which. One notice per envelope made a
  /// three-row history sprout a column of identical lines saying the same
  /// thing. So: if the last row of the chat is already this notice, its
  /// count goes up instead; a message that decrypts ends the episode by
  /// being a newer row. The hello that re-opens the session goes at most
  /// once per [helloMinInterval] per contact — one is enough for a burst,
  /// and a lost one is re-sent by the next stale envelope after the
  /// interval, which is the self-healing the per-envelope hello had.
  Future<void> _noteUndecryptable(Contact contact) async {
    final rid = contact.rid;
    // Inbound envelopes are handled concurrently; the read-then-write on
    // the last row has to be one step, or two stale envelopes arriving
    // together both see no notice and both write one.
    await _withLock(rid, () => _countUndecryptable(rid));
    final now = _now();
    // Checked and set without an await between: a burst sends one hello.
    if (now - (_helloSentMs[rid] ?? 0) >= helloMinInterval.inMilliseconds) {
      _helloSentMs[rid] = now;
      debugHellos++;
      await _sendInner(contact, InnerMessage.hello(newMessageId(), now));
    }
  }

  Future<void> _countUndecryptable(String rid) async {
    final last = await vault.db.query('messages',
        columns: ['mid', 'kind', 'enc_body'],
        where: 'rid = ?',
        whereArgs: [rid],
        orderBy: 'ts_ms DESC, rowid DESC',
        limit: 1);
    String? mid;
    int n = 1;
    if (last.isNotEmpty && last.single['kind'] == 'system') {
      final body = await vault.unseal(last.single['enc_body'] as String);
      if (body.startsWith('{')) {
        try {
          final j = jsonDecode(body);
          if (j is Map && j['k'] == SystemKind.decryptFailed) {
            mid = last.single['mid'] as String;
            n = ((j['n'] as num?)?.toInt() ?? 1) + 1;
          }
        } on FormatException {
          // an old row holding prose: not ours to count on
        }
      }
    }
    if (mid == null) {
      await _insertSystemMessage(
          rid, systemBody(SystemKind.decryptFailed, {'n': 1}));
    } else {
      final body = systemBody(SystemKind.decryptFailed, {'n': n});
      await vault.db.update('messages', {'enc_body': await vault.seal(body)},
          where: 'mid = ?', whereArgs: [mid]);
      final list = messagesByChat[rid];
      final i = list?.indexWhere((x) => x.mid == mid) ?? -1;
      if (list != null && i >= 0) {
        final old = list[i];
        list[i] = ChatMessage(
          mid: old.mid,
          rid: old.rid,
          outgoing: old.outgoing,
          kind: old.kind,
          body: body,
          ts: old.ts,
          status: old.status,
        );
      }
    }
  }

  /// When the last session-reopening hello went to each contact.
  final Map<String, int> _helloSentMs = {};

  /// How long after a hello the next stale envelope may send another.
  @visibleForTesting
  Duration helloMinInterval = const Duration(seconds: 10);

  /// Hellos sent by [_noteUndecryptable]. Test seam.
  @visibleForTesting
  int debugHellos = 0;

  Future<void> _insertSystemMessage(String rid, String text,
      {DatabaseExecutor? txn}) async {
    final mid = newMessageId();
    final ts = _now();
    await (txn ?? vault.db).insert('messages', {
      'mid': mid,
      'rid': rid,
      'outgoing': 0,
      'kind': 'system',
      'enc_body': await vault.seal(text),
      'ts_ms': ts,
      'status': MsgStatus.delivered,
      'expire_at_ms': 0,
    });
    _appendLoaded(
        rid,
        ChatMessage(
          mid: mid,
          rid: rid,
          outgoing: false,
          kind: 'system',
          body: text,
          ts: ts,
          status: MsgStatus.delivered,
        ));
  }

  // ------------------------------------------------------------------
  // Disappearing messages sweeper
  // ------------------------------------------------------------------

  /// One tick of the sweep's timer.
  ///
  /// 42.4: the timer runs for the life of the service, and the service does
  /// not own its vault — whoever made it closes it, and nothing made them
  /// call [dispose] first. A tick that found the vault closed used to query
  /// it anyway, and the error had nowhere to go: on a device an unhandled
  /// exception in the system log, in a test a failure pinned on whichever
  /// test happened to be running. So a tick does nothing once the service is
  /// disposed or its vault closed, and stops the timer; and it never starts
  /// a sweep beside one still running.
  void _sweepTick() {
    if (_disposed || !vault.db.isOpen) {
      _sweeper?.cancel();
      return;
    }
    if (_sweeping != null) return;
    unawaited(_sweepSerial());
  }

  /// One sweep, after any already running; [_sweeping] while it runs.
  Future<void> _sweepSerial() {
    final before = _sweeping;
    late final Future<void> run;
    run = (before == null ? _sweep() : _sweepAfter(before)).whenComplete(() {
      if (identical(_sweeping, run)) _sweeping = null;
    });
    _sweeping = run;
    return run;
  }

  Future<void> _sweepAfter(Future<void> before) async {
    try {
      await before;
    } catch (_) {
      // That sweep's failure is its own caller's to see.
    }
    await _sweep();
  }

  /// The sweep itself, on a vault that may close under it.
  ///
  /// The owner can close the vault between any two of the sweep's queries —
  /// it is closed after [dispose], which cannot wait for anything — and then
  /// the next query fails with SQLite's "database closed". That is not a
  /// fault to report: there is nothing left to sweep, and no later tick will
  /// find anything either.
  Future<void> _sweep() async {
    if (_disposed || !vault.db.isOpen) return;
    try {
      await _sweepOnce();
    } on DatabaseException catch (e) {
      if (!e.isDatabaseClosedError()) rethrow;
      _sweeper?.cancel();
    }
  }

  Future<void> _sweepOnce() async {
    await _sweepLinks(); // ADR 0020: a link's go-ahead that never came
    final now = _now();
    final doomed = await vault.db.query('messages',
        where: 'expire_at_ms > 0 AND expire_at_ms <= ?', whereArgs: [now]);
    if (doomed.isEmpty) return;
    for (final r in doomed) {
      final fid = r['fid'] as String?;
      if (fid != null &&
          await _dropAttachment(
              vault.db, r['rid'] as String, r['mid'] as String, fid)) {
        await vault.deleteBlob(fid);
      }
    }
    for (final r in doomed) {
      await vault.db.delete('reactions',
          where: 'rid = ? AND mid = ?',
          whereArgs: [r['rid'] as String, r['mid'] as String]);
      // Who confirmed a message goes with the message. A disappearing
      // message that leaves a row saying who received it and when has not
      // disappeared.
      await vault.db.delete('delivery',
          where: 'thread_rid = ? AND mid = ?',
          whereArgs: [r['rid'] as String, r['mid'] as String]);
    }
    await vault.db.delete('messages',
        where: 'expire_at_ms > 0 AND expire_at_ms <= ?', whereArgs: [now]);
    for (final entry in messagesByChat.entries) {
      entry.value.removeWhere((m) => m.expireAtMs > 0 && m.expireAtMs <= now);
    }
    // Housekeeping: dedupe entries older than 30 days.
    await vault.db.delete('inbox_dedupe',
        where: 'seen_ms < ?', whereArgs: [now - 30 * 24 * 3600 * 1000]);
    notifyListeners();
  }

  // ------------------------------------------------------------------
  // Settings / profile
  // ------------------------------------------------------------------

  Future<void> setDisplayName(String name) async {
    displayName = name;
    await vault.kvPut('display_name', name);
    notifyListeners();
  }

  /// Point this device at a different relay.
  ///
  /// Through [setRelayUrl], like every other writer of `server_url`: a public
  /// `ws://` address is refused unless [acceptedInsecure] says the user was
  /// asked and agreed. Returns what happened, so a caller that did not ask
  /// can say so rather than silently doing nothing.
  Future<RelayUrlOutcome> setServerUrl(String url,
      {bool acceptedInsecure = false}) async {
    final outcome =
        await setRelayUrl(vault, url, acceptedInsecure: acceptedInsecure);
    if (outcome != RelayUrlOutcome.saved) return outcome;
    await transport.setServer(normalizeRelayUrl(url));
    notifyListeners();
    return outcome;
  }

  Future<void> setDevMode(bool v) async {
    devMode = v;
    await vault.kvPut('dev_mode', v ? '1' : '0', sensitive: false);
    notifyListeners();
  }

  /// Re-attempt a permanently-failed outgoing message (status -1). The text is
  /// re-encrypted and re-queued to the durable outbox under its original id, so
  /// the recipient still de-duplicates it. Non-text failures can only be
  /// dismissed with [deleteMessage].
  Future<bool> retryFailedSend(String rid, String mid) async {
    final contact = contacts[rid];
    if (contact == null) return false;
    final rows = await vault.db.query('messages',
        where: 'rid = ? AND mid = ? AND outgoing = 1', whereArgs: [rid, mid]);
    if (rows.isEmpty) return false;
    final row = rows.first;
    if ((row['status'] as int) != -1 || row['kind'] != 'text') return false;
    final body = await vault.unseal(row['enc_body'] as String);
    await vault.db.update('messages', {'status': MsgStatus.pending},
        where: 'rid = ? AND mid = ?', whereArgs: [rid, mid]);
    _updateLoadedStatus(rid, mid, MsgStatus.pending);
    notifyListeners();
    // Rebuild the message the row records, not a bare one: retrying used to
    // send `InnerMessage.text(mid, _now(), body)`, dropping the disappearing
    // timer, the reply quote and the forwarded flag, and moving the timestamp
    // to now — so a retried disappearing message never disappeared, a reply
    // lost its quote, and a forward stopped being marked one (the 2026-09-14
    // review's finding 43). The row holds all of it.
    final ts = (row['ts_ms'] as int?) ?? _now();
    final expireAt = (row['expire_at_ms'] as int?) ?? 0;
    final ttlSec = expireAt > 0 ? ((expireAt - ts) / 1000).round() : 0;
    final inner = InnerMessage.text(mid, ts, body,
        ttlSec: ttlSec, replyTo: row['reply_to'] as String?);
    if ((row['forwarded'] as int?) == 1) inner.data['fw'] = true;
    await _sendInner(contact, inner);
    return true;
  }

  /// Remove a single message from this device (local only).
  ///
  /// Everything the message brought with it goes too. This used to delete the
  /// `messages` row and the delivery receipts and stop there, which left the
  /// `files` row — holding the attachment's NAME and the key its blob is
  /// sealed under — the blob itself, any chunks still undrained, and the
  /// reactions. None of it was reachable from the UI afterwards and nothing
  /// ever collected it, so it simply stayed; and since [BackupArchive.export]
  /// walks `files` directly rather than through `messages`, a photo the user
  /// deleted went on being written into every archive taken after it, under
  /// the filename they deleted it by. The other three deletion paths
  /// ([_tombstone], the disappearing-message [_sweep], and removing a
  /// contact) already did this correctly; this one was the odd one out.
  Future<void> deleteMessage(String rid, String mid) async {
    String? fid;
    await vault.db.transaction((txn) async {
      final rows = await txn.query('messages',
          columns: ['fid'],
          where: 'rid = ? AND mid = ?',
          whereArgs: [rid, mid],
          limit: 1);
      if (rows.isEmpty) return;
      final named = rows.first['fid'] as String?;
      // The message's own attachment; one it merely names stays (§7).
      if (named != null && await _dropAttachment(txn, rid, mid, named)) {
        fid = named;
      }
      await txn.delete('reactions',
          where: 'rid = ? AND mid = ?', whereArgs: [rid, mid]);
      await txn.delete('delivery',
          where: 'thread_rid = ? AND mid = ?', whereArgs: [rid, mid]);
      await txn.delete('messages',
          where: 'rid = ? AND mid = ?', whereArgs: [rid, mid]);
    });
    // After the commit, not before: a blob unlinked ahead of a transaction
    // that then fails leaves a message pointing at nothing. This way round
    // the worst case is a blob whose key has already been destroyed, which
    // is unreadable noise — and `Vault` sweeps it on the next open anyway.
    if (fid != null) await vault.deleteBlob(fid!);
    messagesByChat[rid]?.removeWhere((m) => m.mid == mid);
    notifyListeners();
  }

  // ------------------------------------------------------------------
  // Multi-device: account layer (M-app). Additive — the single-device
  // messaging path above is unchanged. Full cross-device message sync (the
  // fan-out adoption) is a separate step; this establishes the trusted link.
  // ------------------------------------------------------------------

  /// A stable per-install device id.
  Future<String> deviceId() async {
    var id = await vault.kvGet('device_id');
    if (id == null) {
      id = b64url(randomBytes(9));
      await vault.kvPut('device_id', id, sensitive: false);
    }
    return id;
  }

  /// This install's account identity. On a linked (secondary) device the full
  /// account was stored at enrollment; on the primary it derives from the
  /// existing identity (whose keys ARE device #1 of the account).
  Future<AccountIdentity> accountIdentity() async {
    final stored = await vault.kvGet('account');
    if (stored != null) {
      return AccountIdentity.fromJson(
          (jsonDecode(stored) as Map).cast<String, Object?>());
    }
    return AccountIdentity.fromV1(identity, deviceId: await deviceId());
  }

  /// True if this install is a linked secondary device.
  Future<bool> get isLinkedDevice async =>
      (await vault.kvGet('account')) != null;

  /// The v2 account contact code for this account (one device today).
  Future<String> myAccountCode() async => (await accountIdentity())
      .toAccountBundle(displayName: displayName)
      .encode();

  /// Contacts expressed as account bundles, to hand to a device being linked.
  List<AccountBundle> contactsAsBundles() => [
        for (final c in contacts.values)
          AccountBundle(
            accountEdPub: c.accountEd,
            devices: [c.deviceCert ?? _legacyCertOf(c)],
            displayName: c.name,
          )
      ];

  /// EXISTING device hosts a link: enter the code shown on the new device,
  /// confirm the safety string, then seal this account + contacts across. On
  /// success, remembers the linked device so messages mirror to it.
  ///
  /// Phase 33: each contact goes across as this device holds it (§10
  /// `cstate`, [enrollmentState]) — the tick and its number, the
  /// post-quantum commitment and key and the records beside them, the
  /// contact's device list — and so does this device's own bundle (§10
  /// `hostbundle`), which a linked device sends its requests as (§8.1). A
  /// new device used to keep a routing id, the scanned device's keys and a
  /// name, and showed every contact differently from the phone (P1-5).
  Future<bool> hostDeviceLink(
    String code, {
    required Future<bool> Function(String sas) confirmSas,
  }) async {
    // The new device needs the ACCOUNT's post-quantum public key, or it would
    // have no v3 identity to show and would fall back to classical codes
    // while the phone handed out hybrid ones (§18).
    final acct = await accountIdentity();
    final myMl = await pqAccountPublic();
    final bundles = contactsAsBundles();
    final asBefore = debugEnrollAsBefore;
    final linked = await RelayPairing.runExistingDeviceV2(
      relayUrl: transport.serverUrl,
      code: PairingCode.parse(code),
      me: myMl == null ? acct : acct.withAccountMlPub(myMl),
      contacts: bundles,
      includeAccountRoot: false, // the new device cannot enroll further devices
      displayName: displayName,
      contactState: asBefore ? null : await _enrollmentStateWithin(bundles),
      hostBundle:
          asBefore || !acct.holdsAccountRoot ? null : await identity.bundle(),
      confirm: confirmSas,
    );
    if (linked == null) return false;
    await addMyDevice(linked, awaitProof: true);
    return true;
  }

  /// Test seam: link as a build from before phase 33 does — no `cstate`, no
  /// `hostbundle` (§10). What a new device of this build makes of an
  /// enrolment from an older root is the case it models.
  @visibleForTesting
  bool debugEnrollAsBefore = false;

  /// How large the contacts may make an enrolment's plaintext, in bytes.
  ///
  /// The enrolment travels as ONE relay frame, and the relay refuses one
  /// over `MAX_ENVELOPE_BYTES` (1 000 000 by default, §12.4) — after base64,
  /// which the sealed blob grows by a third. A post-quantum key is 2.6 KB of
  /// base64 and a list's post-quantum signature 4.4 KB, so the per-contact
  /// state is the one part of the payload that can push an account that
  /// linked devices before over that line. 600 KiB leaves room for the rest
  /// and the encoding; [_enrollmentStateWithin] cuts the state down to fit.
  /// Tests shrink it.
  @visibleForTesting
  int enrollmentBudgetBytes = 600 * 1024;

  /// [enrollmentState] at the first level that fits [enrollmentBudgetBytes]
  /// beside [bundles], or null — no `cstate` at all, which is what an older
  /// root sends — when even the last does not.
  Future<List<Map<String, Object?>>?> _enrollmentStateWithin(
      List<AccountBundle> bundles) async {
    final base =
        utf8.encode(jsonEncode([for (final b in bundles) b.toJson()])).length;
    for (var level = 0; level <= 3; level++) {
      final state = await enrollmentState(level: level);
      if (base + utf8.encode(jsonEncode(state)).length <=
          enrollmentBudgetBytes) {
        return state;
      }
    }
    return null;
  }

  /// Each contact as this device holds it, one record per contact, for a
  /// device being linked (§10 `cstate`) — the archive's per-contact record
  /// (`archive.dart`) without what a device keeps for itself: no messages,
  /// sessions, claims or alarms.
  ///
  /// [level] is how much of the bulk goes when the whole will not fit in one
  /// frame, cut in an order chosen so each cut is made good in-band, with
  /// nothing anyone sees lost meanwhile: 1 drops each list's post-quantum
  /// signature, which a contact sends again when the new device asks for it
  /// (§18.9); 2 the lists themselves too, which come back when the contact
  /// sees the device's echo of them is behind (§3.6); 3 the post-quantum
  /// keys too — a key with no commitment beside it goes as its commitment,
  /// so the key the contact sends the new device is checked against it and
  /// established, as it was on this device, rather than held as a candidate.
  ///
  /// A tick given on the post-quantum number, at 3, goes as the classical
  /// number with the commitment that comparison covered — 26.3's record for
  /// a ceremony whose key had not landed. The new device then shows the
  /// contact verified on the number it can compute, and moves the tick onto
  /// the post-quantum one when the key arrives and matches, rather than
  /// calling a number it cannot compute yet a change nobody explained.
  Future<List<Map<String, Object?>>> enrollmentState({int level = 0}) async {
    final kv = await vault.kvScanMany(enrollmentKvFamilies);
    final mine = (await accountIdentity()).accountEdPub;
    final out = <Map<String, Object?>>[];
    for (final c in contacts.values.toList()) {
      final rid = c.rid;
      var pqCommit = c.pqCommit;
      if (level >= 3 && pqCommit == null && c.pqPub != null) {
        pqCommit = await HybridPublicKey(edPub: c.accountEd, mlPub: c.pqPub!)
            .pqCommitment();
      }
      final family = <String, String>{};
      for (final f in enrollmentKvFamilies) {
        if (level >= 1 && f == 'cdev_pq_') continue;
        if (level >= 2 && (f == 'cdev_' || f == 'cdev_sigfloor_')) continue;
        final v = kv['$f$rid'];
        if (v != null) family[f] = v;
      }
      var verifiedSn = c.verifiedSn;
      final key = c.showsPostQuantumNumber ? c.numberKey : null;
      if (level >= 3 &&
          c.verified &&
          key != null &&
          verifiedSn != null &&
          verifiedSn == await _safetyNumberOver(c, key)) {
        verifiedSn = await safetyNumber(mine, c.accountEd);
        family['vpqc_'] = b64(await key.pqCommitment());
      }
      out.add({
        'rid': rid,
        'bundle': c.bundle.toJson(),
        'name': c.name,
        'ttl': c.ttlSec,
        'verified': c.verified ? 1 : 0,
        'created': c.createdMs,
        if (pqCommit != null) 'pqc': b64(pqCommit),
        if (level < 3 && c.pqPub != null) 'pqk': b64(c.pqPub!),
        if (level < 3 && c.pqCandidate != null)
          'pqcand': b64(c.pqCandidate!),
        if (c.pqAcked) 'pqack': 1,
        if (c.pqTold) 'pqtold': 1,
        if (verifiedSn != null) 'vsn': verifiedSn,
        if (c.pqMismatch) 'pqbad': 1,
        if (c.accountEdPub != null) 'acct': b64(c.accountEdPub!),
        if (c.deviceCert != null) 'cert': c.deviceCert!.toJson(),
        if (c.addedByDevice != null) 'addedby': c.addedByDevice,
        if (c.requested) 'req': 1,
        'kv': family,
      });
    }
    return out;
  }

  // ---- self-sync plumbing -------------------------------------------------

  Future<List<DeviceCertificate>> _myDevices() async {
    final s = await vault.kvGet('my_devices');
    if (s == null) return [];
    return [
      for (final j in (jsonDecode(s) as List))
        DeviceCertificate.fromJson((j as Map).cast<String, Object?>())
    ];
  }

  /// Persist a newly-linked device of MY account and (re)build the sync channel.
  ///
  /// [awaitProof]: the device was just linked by this build's pairing
  /// ([hostDeviceLink]) and will hand over its proof of possession within
  /// seconds of its first start, so the version that first names it is held
  /// back from the transparency log until the proof is in or
  /// [popPublishHold] runs out — the log takes each version once, and the
  /// copy it takes is what a contact that reads the list from the log learns
  /// ([_applyDevicePop]). In-band nothing waits.
  Future<void> addMyDevice(DeviceCertificate cert,
      {bool awaitProof = false}) async {
    // The device set and its version change together, under the lock a
    // signer reads them under ([_signCurrentDeviceList]); the broadcast below
    // takes it again for the signing, after this has let it go.
    final isNew = await _withOwnListLock(() async {
      final list = await _myDevices();
      final isNew = !list.any((d) =>
          base64Encode(d.deviceEdPub) == base64Encode(cert.deviceEdPub));
      if (isNew) {
        list.add(cert);
        await vault.kvPut(
            'my_devices', jsonEncode([for (final d in list) d.toJson()]),
            sensitive: false);
        await vault.kvPut(
            'my_devlist_version', '${(await _myDevlistVersion()) + 1}',
            sensitive: false);
        _forgetOwnListClaim(); // after the writes; see _recordOwnList
      }
      return isNew;
    });
    await _initSync();
    // A contact's list that named this device before it was mine held it by
    // the first-come rule; it does not now (§3.4).
    if (isNew) await _withdrawClaimsOnMine();
    if (isNew && awaitProof && cert.pop == null && kt.config.enabled) {
      _popHoldTimer?.cancel();
      _popHold = (
        edPub: b64(cert.deviceEdPub),
        rid: await cert.routingId(),
        until: DateTime.now().add(popPublishHold),
      );
      _popHoldTimer = Timer(popPublishHold, () {
        _releasePopHold();
        unawaited(_signCurrentDeviceList().then((_) {}, onError: (_) {}));
      });
    }
    await broadcastMyDeviceList(); // tell contacts about the new device
    // 7.6b: a device that just joined starts with the recent history instead
    // of an empty screen (queued through the durable outbox, so it lands even
    // if the new device is briefly offline).
    if (isNew) unawaited(_syncHistoryTo(await cert.routingId()));
  }

  // ---- 7.6b history sync to a newly linked device ---------------------------

  /// How much recent history a newly linked device receives, per chat.
  static const int historySyncPerChat = 200;

  /// Items per self-sync envelope (~30 KB, well under the relay frame cap).
  static const int historySyncBatch = 100;

  /// 26.2: how long a history replay waits for the new device's self-sync
  /// channel to be post-quantum (PROTOCOL §17.8) — the relay's queue
  /// lifetime. A device that has not completed one round trip on that
  /// channel in 72 hours has not been online to take the replay anyway: an
  /// envelope sent to it would have expired at the relay. At the bound the
  /// replay is DROPPED, never sent classical: the new device keeps what it
  /// receives from then on, which is what a lost batch always meant. Tests
  /// shorten it.
  @visibleForTesting
  Duration historySyncPqWait = const Duration(hours: 72);

  /// Replays waiting for their device's channel to be post-quantum: device
  /// routing id → when the wait gives up (ms since the epoch). Also sealed in
  /// the vault (`hist_due`), so a restart resumes a wait rather than losing
  /// the replay — which a replay queued at once never risked.
  final Map<String, int> _historyDue = {};
  Timer? _historyTimer;
  bool _historyRunning = false;
  bool _historyAgain = false;

  /// Test seam: whether a history replay to [deviceRid] is still waiting.
  @visibleForTesting
  Future<bool> debugHistoryReplayPending(String deviceRid) async =>
      _historyDue.containsKey(deviceRid);

  Future<void> _loadHistoryDue() async {
    final stored = await vault.kvGet('hist_due');
    if (stored == null) return;
    try {
      final m = (jsonDecode(stored) as Map).cast<String, Object?>();
      for (final e in m.entries) {
        _historyDue[e.key] = (e.value as num).toInt();
      }
    } catch (_) {
      // Unreadable: nothing to resume. The replay is a convenience.
    }
  }

  Future<void> _saveHistoryDue() async {
    if (_historyDue.isEmpty) {
      await vault.kvDelete('hist_due');
    } else {
      await vault.kvPut('hist_due', jsonEncode(_historyDue));
    }
  }

  /// Start the replay to a device just linked: it waits for that device's
  /// channel to be post-quantum ([_runHistoryReplays]).
  ///
  /// Until 26.2 it went out at once, on whatever the channel was at that
  /// moment — which, whenever this device is the side that offers the
  /// ML-KEM key, was always classical: its history left before its own
  /// offer did. Up to 200 texts per chat, in the clear to anyone who records
  /// the traffic now and breaks X25519 later.
  Future<void> _syncHistoryTo(String deviceRid) async {
    _historyDue[deviceRid] = _now() + historySyncPqWait.inMilliseconds;
    try {
      await _saveHistoryDue();
    } catch (_) {
      // Held in memory for this run; only a restart can lose it now.
    }
    await _runHistoryReplays();
  }

  /// Every waiting replay, one pass: sent if its device's channel is
  /// post-quantum; given up if the device is no longer linked or the wait
  /// has reached [historySyncPqWait]; otherwise nudged along. Runs on link,
  /// on reconnect, after anything arrives from one of my devices, and on a
  /// timer while anything waits.
  Future<void> _runHistoryReplays() async {
    if (_historyRunning) {
      _historyAgain = true;
      return;
    }
    _historyRunning = true;
    try {
      do {
        _historyAgain = false;
        for (final e in _historyDue.entries.toList()) {
          if (_disposed) return;
          final rid = e.key;
          final sync = _sync;
          if (sync == null ||
              !sync.deviceRoutingIds.contains(rid) ||
              _now() >= e.value) {
            // Unlinked meanwhile, or the bound: dropped, not sent classical.
            _historyDue.remove(rid);
            await _saveHistoryDue();
            continue;
          }
          if (!sync.isPostQuantumWith(rid)) {
            // If this device offers on that channel, its offer — the first,
            // or one said again once its interval has passed — goes now
            // rather than with the next mirror, which may be a long time
            // coming. If the other device offers, its offer is coming
            // whether or not we speak; the answer it needs from this side
            // goes the moment it arrives (DeviceSyncService.handleInbound).
            await sync.offerPqTo(rid);
            continue;
          }
          if (await _replayHistoryTo(sync, rid)) {
            _historyDue.remove(rid);
            await _saveHistoryDue();
          }
        }
      } while (_historyAgain);
    } catch (_) {
      // A vault closing under us. What still waits is in the vault, and the
      // next start resumes it.
    } finally {
      _historyRunning = false;
      _armHistoryTimer();
    }
  }

  /// While a replay waits, look again by its deadline, and no later than the
  /// offer-retry interval, so an offer said again goes out on time.
  void _armHistoryTimer() {
    _historyTimer?.cancel();
    _historyTimer = null;
    if (_historyDue.isEmpty || _disposed) return;
    final now = _now();
    final due = _historyDue.values.reduce(min) - now;
    final wait = min(max(due, 0), _pqOfferRetry);
    _historyTimer = Timer(
        Duration(milliseconds: wait.clamp(1000, 3600 * 1000).toInt()), () {
      _historyTimer = null;
      unawaited(_runHistoryReplays());
    });
  }

  /// Replay the newest [historySyncPerChat] text messages of every chat to
  /// ONE of my devices (the one just linked), oldest first, in batches over
  /// the self-sync channel. Attachments are not replayed: their key material
  /// is not retained on the sender's side, and a placeholder that could never
  /// complete would be worse than the file simply living on the other device.
  ///
  /// Every batch goes post-quantum or not at all (26.2): false, and nothing
  /// further sent, the moment the channel is not. The device stores each item
  /// under its message id and ignores one it holds, so a replay begun again
  /// later repeats nothing that shows.
  Future<bool> _replayHistoryTo(
      DeviceSyncService sync, String deviceRid) async {
    final items = <Map<String, Object?>>[];
    var complete = true;
    Future<void> flush() async {
      if (items.isEmpty || !complete) return;
      final batch = List<Map<String, Object?>>.from(items);
      items.clear();
      try {
        complete = await sync.mirrorTo(
            deviceRid: deviceRid,
            threadRid: '',
            dir: 'hist',
            onlyPostQuantum: true,
            inner: InnerMessage(
                kind: 'hist',
                mid: newMessageId(),
                ts: _now(),
                data: {'items': batch}));
      } catch (_) {
        // Best effort: a lost batch only means a shorter history over there.
      }
    }

    // 30.3: first, each chat's disappearing timer. The enrolment hands the
    // new device every contact with none, so without this what it sent
    // would never disappear, though the chat's timer was on. Through the
    // same door as the history, and on the same terms: post-quantum or not
    // at all. Sent again if the replay is begun again; the device takes one
    // only where it still has none ([_applyMirroredTimer]).
    for (final c in contacts.values.toList()) {
      if (c.ttlSec <= 0) continue;
      try {
        if (!await sync.mirrorTo(
            deviceRid: deviceRid,
            threadRid: c.rid,
            dir: 'hist',
            onlyPostQuantum: true,
            inner: InnerMessage.timer(newMessageId(), _now(), c.ttlSec))) {
          return false;
        }
      } catch (_) {
        return false; // the vault closing: the next start resumes the replay
      }
    }
    for (final thread in [...contacts.keys, ...groups.keys]) {
      final rows = await vault.db.query('messages',
          where: 'rid = ? AND kind IN (?, ?)',
          whereArgs: [thread, 'text', 'gtext'],
          orderBy: 'ts_ms DESC',
          limit: historySyncPerChat);
      for (final r in rows.reversed) {
        final ChatMessage m;
        try {
          m = await _rowToMessage(thread, r);
        } catch (_) {
          continue;
        }
        items.add({
          't': thread,
          'mid': m.mid,
          'o': m.outgoing,
          'k': m.kind,
          'b': m.body,
          'ts': m.ts,
          if (m.senderName != null) 'sn': m.senderName,
          // A disappearing message carries WHEN it goes, absolute, so the
          // new device's copy goes at the same moment as this one. Older
          // receivers ignore the member and store the copy as they always
          // did — for ever, which is the 2026-09-14 review's finding 6.
          if (m.expireAtMs > 0) 'x': m.expireAtMs,
        });
        if (items.length >= historySyncBatch) await flush();
        if (!complete) return false;
      }
    }
    await flush();
    return complete;
  }

  /// Receiving side of [_syncHistoryTo]: store each item as an ordinary text /
  /// group-text row (deduplicated by message id, so an item that also arrived
  /// as a live mirror is not doubled), skipping threads this device does not
  /// hold, then refresh any thread that is currently loaded.
  Future<void> _applyHistoryBatch(InnerMessage inner) async {
    final items = (inner.data['items'] as List?)?.cast<Map>() ?? const [];
    final touched = <String>{};
    // Seal first, then one transaction for the batch: a hundred rows as a
    // hundred autocommits took 268 ms; sealed up front and written in one
    // transaction, 99 (measured, 2026-09-11). A new device replaying fifty
    // chats notices the difference.
    final rows = <Map<String, Object?>>[];
    final now = _now();
    for (final it in items) {
      final thread = it['t'] as String?;
      final mid = it['mid'] as String?;
      if (thread == null || mid == null) continue;
      if (!contacts.containsKey(thread) && !groups.containsKey(thread)) {
        continue;
      }
      // The expiry rides with the item (absolute ms; absent when none). One
      // that has already passed is not stored to be swept a moment later:
      // a message that has disappeared on the sender does not reappear
      // anywhere, even briefly.
      final x = (it['x'] as num?)?.toInt() ?? 0;
      final expireAt = x > 0 ? x : 0;
      if (expireAt > 0 && expireAt <= now) continue;
      final kind = it['k'] == 'gtext' ? 'gtext' : 'text';
      final body = it['b'] as String? ?? '';
      final outgoing = it['o'] == true;
      final sn = it['sn'] as String?;
      final encBody = kind == 'gtext'
          ? jsonEncode({'b': body, if (sn != null) 'sn': sn})
          : body;
      rows.add({
        'mid': mid,
        'rid': thread,
        'outgoing': outgoing ? 1 : 0,
        'kind': kind,
        'enc_body': await vault.seal(encBody),
        'ts_ms': (it['ts'] as num?)?.toInt() ?? now,
        'status': outgoing ? MsgStatus.sent : MsgStatus.delivered,
        'expire_at_ms': expireAt,
      });
      touched.add(thread);
    }
    if (rows.isNotEmpty) {
      await vault.db.transaction((txn) async {
        for (final r in rows) {
          await txn.insert('messages', r,
              conflictAlgorithm: ConflictAlgorithm.ignore);
        }
      });
    }
    for (final t in touched) {
      if (messagesByChat.containsKey(t)) await loadMessages(t);
    }
    if (touched.isNotEmpty) notifyListeners();
  }

  /// Revoke a linked device of MY account: drop it from the sync set, bump the
  /// signed-list version, and re-broadcast so contacts stop fanning to it and
  /// reject anything it sends. Only a root-holding device can do this.
  Future<void> removeMyDevice(DeviceCertificate cert) async {
    if (!await holdsAccountRoot()) return;
    // Under the signer's lock, as in [addMyDevice].
    final removed = await _withOwnListLock(() async {
      final list = await _myDevices();
      final before = list.length;
      list.removeWhere((d) =>
          base64Encode(d.deviceEdPub) == base64Encode(cert.deviceEdPub));
      if (list.length == before) return false; // nothing matched
      await vault.kvPut(
          'my_devices', jsonEncode([for (final d in list) d.toJson()]),
          sensitive: false);
      await vault.kvPut(
          'my_devlist_version', '${(await _myDevlistVersion()) + 1}',
          sensitive: false);
      _forgetOwnListClaim(); // after the writes; see _recordOwnList
      return true;
    });
    if (!removed) return;
    // Whatever was still queued for that device — mirrors, history — is
    // not delivered to it. Removing it is the statement that it is no longer
    // mine; the outbox being durable must not turn a link that was down at
    // the time into a delivery after the fact.
    final gone = await cert.routingId();
    await vault.db.delete('outbox', where: 'rid = ?', whereArgs: [gone]);
    // ADR 0029: and what it said it reads is no longer this account's to
    // count.
    if (_ownReaderLevels.remove(gone) != null) {
      try {
        await vault.kvPut('own_dlr', jsonEncode(_ownReaderLevels));
      } catch (_) {}
    }
    await _initSync();
    await broadcastMyDeviceList();
    notifyListeners();
    // One reader fewer: it may have been the last one the move waited for.
    unawaited(_maybeMoveToV2Only());
  }

  /// The linked (secondary) devices of my account, if any.
  Future<List<DeviceCertificate>> linkedDevices() async => _myDevices();

  /// This install's own device certificate.
  Future<DeviceCertificate> thisDeviceCert() async =>
      (await accountIdentity()).deviceCert;

  /// Whether this install holds the account root (can sign device lists, and so
  /// can add or revoke devices).
  Future<bool> holdsAccountRoot() async =>
      (await accountIdentity()).holdsAccountRoot;

  /// Rebuilds the self-sync service for the device list as it now stands.
  /// One rebuild at a time, in the order asked for, so the service left in
  /// place was built from the latest list and every one of them took over
  /// the same session.
  Future<void> _initSync() {
    final run = _syncRebuilds.then((_) => _rebuildSync());
    _syncRebuilds = run.then((_) {}, onError: (Object _) {});
    return run;
  }

  Future<void> _syncRebuilds = Future<void>.value();

  Future<void> _rebuildSync() async {
    final devices = await _myDevices();
    for (final d in devices) {
      _sealKeys[await d.routingId()] = d.deviceXPub; // seal self-sync too
    }
    if (devices.isEmpty) {
      _sync = null;
      return;
    }
    // 26.2: the new service takes over the old one's session and lock, and
    // replaces it once it is ready. It used to replace it at once, before
    // it knew which routing ids were mine — so for a moment an envelope from
    // my own device was taken for a stranger's — and to read its own copy of
    // the ratchet from the vault while the old one, still handling an
    // envelope, stepped and saved its copy (see [DeviceSyncService]).
    final next = DeviceSyncService(
      vault: vault,
      reliableSend: _syncSend,
      account: await accountIdentity(),
      myDevices: devices,
      pqIntervals: () => _pqIntervals,
      advertiseReaderLevel: () => !debugPreAdr0029, // ADR 0029
      replacing: _sync,
    );
    await next.init();
    _sync = next;
    _wireSyncProbe();
  }

  /// Test seam: the self-sync session, to read its post-quantum state.
  @visibleForTesting
  AccountSession? get debugSyncSession => _sync?.debugSession;

  /// Test seam: the session with [rid]'s other devices, likewise.
  @visibleForTesting
  AccountSession? debugExtraSession(String rid) => _contactExtras[rid];

  /// Reliable send for the self-sync channel: enqueue to the durable outbox and
  /// flush, so a mirrored message or file chunk gets the same relay-backed,
  /// retried delivery the contact path has — never dropped to a race or a brief
  /// disconnect.
  Future<void> _syncSend(String toRid, String payload) async {
    await vault.db.insert('outbox', {
      'id': newMessageId(),
      'rid': toRid,
      'payload': await _sealFor(toRid, payload),
      'created_ms': _now(),
    });
    unawaited(flushOutbox());
  }

  /// Insert a message mirrored from one of my other devices (no re-send).
  Future<void> _insertMirrored(
      String rid, String dir, InnerMessage inner) async {
    // 7.7a rule 8: my root device self-synced the account's latest signed list.
    // Learn it so this device's own-account version keeps pace and an echo of a
    // rogue list stands out.
    if (dir == 'acct') {
      await _applyOwnDeviceList(inner);
      return;
    }
    // One of my linked devices asks for the current list: the root answers by
    // self-sync (non-root devices have nothing authoritative to say).
    if (dir == 'acctreq') {
      await _selfSyncCurrentDeviceList();
      return;
    }
    // 7.6b: recent history replayed by my root when this device was linked —
    // and (30.3) each chat's disappearing timer, which this device, handed
    // its contacts with none, starts from.
    if (dir == 'hist') {
      if (inner.kind == 'timer') {
        await _applyMirroredTimer(rid, inner, linked: true);
      } else {
        await _applyHistoryBatch(inner);
      }
      return;
    }
    final outgoing = dir == 'out';
    // 30.3: what I did on another of my devices — an edit of a message of
    // mine, a timer set, messages read — is what this device shows too. Each
    // used to be dropped here. A contact's own edit, timer or receipt is not
    // mirrored: it reaches each of my devices from them, as their delete
    // does (below).
    if (inner.kind == 'edit' || inner.kind == 'gedit') {
      if (outgoing) await _applyMirroredEdit(rid, inner);
      return;
    }
    if (inner.kind == 'timer') {
      if (outgoing) await _applyMirroredTimer(rid, inner, linked: false);
      return;
    }
    if (inner.kind == 'read') {
      if (outgoing) await _readElsewhere(rid, inner);
      return;
    }
    // Group kinds route by the gid inside the payload, and an invite may
    // introduce contacts this device doesn't hold yet — so handle them before
    // the contacts guard below.
    if (inner.kind == 'ginvite') {
      await _applyGroupInvite(outgoing ? '' : rid, inner.data,
          mirroredOwn: outgoing);
      notifyListeners();
      return;
    }
    if (inner.kind == 'gleave') {
      if (outgoing) {
        final g = groups[inner.data['gid'] as String? ?? ''];
        if (g != null) {
          // My leave, from another of my devices: remembered here as there
          // (ADR 0030), at the position it states.
          final stated = Group.posFrom(inner.data['e']);
          final wasIn = !g.left;
          final before = g.leftAt[''];
          if (!debugBuildBefore0030 &&
              wasIn &&
              stated != null &&
              Group.comparePos(stated, g.epochs[''] ?? Group.origin) < 0) {
            // A leave of a membership before the one this device holds me
            // in: the list adding me back reached me here before the copy of
            // my leave did. Remembered, and I stay — as my device that left
            // does once that list reaches it.
            g.leftAt[''] =
                before == null ? stated : Group.laterPos(before, stated);
            if (before != g.leftAt['']) await _saveGroups();
          } else {
            _rememberMyLeave(g, stated);
            if (wasIn) {
              g.left = true;
              g.mine = null;
              _trimLeft(g);
            }
            if (wasIn || before != g.leftAt['']) await _saveGroups();
            if (wasIn) {
              await _insertSystemMessage(
                  g.gid, systemBody(SystemKind.leftYou));
            }
          }
        }
      } else {
        await _applyGroupLeave(rid, inner.data);
      }
      notifyListeners();
      return;
    }
    if (inner.kind == 'gmsg') {
      final gid = inner.data['gid'] as String?;
      final g = gid == null ? null : groups[gid];
      if (g == null) return;
      if (outgoing) {
        // My own group send, made on another of my devices — and, with the
        // group's timer on (ADR 0030), gone when the original goes, from the
        // message's own time, as a mirrored 1:1 message is.
        final body = inner.data['body'] as String? ?? '';
        final quoted = await _resolveQuote(gid!, inner.replyTo);
        final expireAt =
            debugBuildBefore0030 ? 0 : _mirroredExpiry(inner, true);
        await vault.db.insert(
            'messages',
            {
              'mid': inner.mid,
              'rid': gid,
              'outgoing': 1,
              'kind': 'gtext',
              'enc_body': await vault.seal(jsonEncode({'b': body})),
              'ts_ms': inner.ts,
              'status': MsgStatus.sent,
              'expire_at_ms': expireAt,
              'reply_to': quoted?.mid,
            },
            conflictAlgorithm: ConflictAlgorithm.ignore);
        _appendLoaded(
            gid,
            ChatMessage(
              mid: inner.mid,
              rid: gid,
              outgoing: true,
              kind: 'gtext',
              body: body,
              ts: inner.ts,
              status: MsgStatus.sent,
              expireAtMs: expireAt,
              replyTo: quoted?.mid,
              quote: quoted,
            ));
      } else {
        final c = contacts[rid];
        if (c != null) await _persistGroupText(c, inner, inner.ts);
      }
      notifyListeners();
      return;
    }
    if (inner.kind == 'gfile') {
      final gid = inner.data['gid'] as String?;
      final g = gid == null ? null : groups[gid];
      if (g == null || inner.data['fid'] is! String) return;
      if (outgoing) {
        // My own group attachment, sent from another of my devices: the
        // offer lands in the group thread; the sidecar chunks follow by fid.
        await _insertMirroredFile(gid!, true, inner);
      } else {
        final c = contacts[rid];
        if (c != null) {
          final fate = await vault.db.transaction(
              (txn) => _persistGroupFile(c, inner, inner.ts, txn: txn));
          notifyListeners();
          if (fate == _OfferFate.fresh) {
            await _offerLanded(inner.data['fid'] as String);
          }
        }
      }
      return;
    }
    // My own delete-for-everyone, made on another of my devices: my own
    // devices are me, so it removes my message here — and the attachment it
    // brought, which is mine (§7). A contact's delete is not mirrored: it
    // reaches each of my devices from them.
    if (inner.kind == 'del' || inner.kind == 'gdel') {
      if (!outgoing) return;
      final gid = inner.data['gid'];
      final thread = inner.kind == 'gdel' ? gid : rid;
      if (thread is! String) return;
      if (inner.kind == 'gdel' ? !groups.containsKey(thread)
          : !contacts.containsKey(thread)) {
        return;
      }
      await vault.db.transaction((txn) async {
        for (final mid in inner.deleteTargets) {
          final mine = await txn.query('messages',
              columns: ['mid'],
              where: 'rid = ? AND mid = ? AND outgoing = 1',
              whereArgs: [thread, mid],
              limit: 1);
          if (mine.isNotEmpty) await _tombstone(thread, mid, txn: txn);
        }
      });
      notifyListeners();
      return;
    }
    // 8.1b: a reaction mirrored from one of my devices (or replayed inbound)
    // applies here too, credited to whoever made it. Ahead of the contacts
    // guard below, which a group's thread fails — its key is a gid, and no
    // contact's — so a reaction I made in a group on one device never
    // reached my others (30.3).
    if (inner.kind == 'react' || inner.kind == 'greact') {
      final r = inner.reactionData;
      if (r == null) return;
      // Credited to a contact only if they are one, and in a group only if
      // they are in it — the rules of the door it would have come in by.
      if (!outgoing && !contacts.containsKey(rid)) return;
      final String thread;
      if (inner.kind == 'greact') {
        final gid = inner.data['gid'];
        final g = gid is String ? groups[gid] : null;
        if (g == null || (!outgoing && !g.memberRids.contains(rid))) return;
        thread = g.gid;
      } else {
        if (!contacts.containsKey(rid)) return;
        thread = rid;
      }
      final target = await vault.db.query('messages',
          columns: ['mid'],
          where: 'rid = ? AND mid = ?',
          whereArgs: [thread, r.target],
          limit: 1);
      if (target.isEmpty) return;
      await _storeReaction(
          rid: thread,
          mid: r.target,
          senderRid: outgoing ? myRid : rid,
          emoji: r.emoji);
      await _refreshLoadedReactions(thread, r.target);
      notifyListeners();
      return;
    }
    if (!contacts.containsKey(rid)) return;
    if (inner.kind == 'file') {
      await _insertMirroredFile(rid, outgoing, inner);
      return;
    }
    if (inner.kind != 'text') return; // only text/file/group self-sync
    final body = inner.data['body'] as String? ?? '';
    final status = outgoing ? MsgStatus.sent : MsgStatus.delivered;
    final quoted = await _resolveQuote(rid, inner.replyTo);
    final expireAt = _mirroredExpiry(inner, outgoing);
    await vault.db.insert(
      'messages',
      {
        'mid': inner.mid,
        'rid': rid,
        'outgoing': outgoing ? 1 : 0,
        'kind': 'text',
        'enc_body': await vault.seal(body),
        'ts_ms': inner.ts,
        'status': status,
        'expire_at_ms': expireAt,
        'reply_to': quoted?.mid,
      },
      conflictAlgorithm: ConflictAlgorithm.ignore,
    );
    _appendLoaded(
        rid,
        ChatMessage(
          mid: inner.mid,
          rid: rid,
          outgoing: outgoing,
          kind: 'text',
          body: body,
          ts: inner.ts,
          status: status,
          expireAtMs: expireAt,
          replyTo: quoted?.mid,
          quote: quoted,
        ));
    notifyListeners();
  }

  /// 30.3: an edit I made on another of my devices. My own devices are me,
  /// so it applies here — to a message of MINE, and only that: the rule
  /// [_applyEdit] holds a contact's edit to, with me as the author (§6.6). A
  /// mirror naming someone else's message, a system notice or an attachment
  /// is passed over, as their edit of it would be.
  Future<void> _applyMirroredEdit(String rid, InnerMessage inner) async {
    final target = inner.replyTo;
    final body = inner.data['body'];
    if (target == null || body is! String) return;
    final String thread;
    if (inner.kind == 'gedit') {
      final gid = inner.data['gid'];
      if (gid is! String || !groups.containsKey(gid)) return;
      thread = gid;
    } else {
      if (!contacts.containsKey(rid)) return;
      thread = rid;
    }
    final rows = await vault.db.query('messages',
        where: 'rid = ? AND mid = ?', whereArgs: [thread, target], limit: 1);
    if (rows.isEmpty) return;
    final r = rows.first;
    if ((r['outgoing'] as int) != 1) return; // mine, or not at all
    if (((r['deleted'] as int?) ?? 0) == 1) return;
    final kind = r['kind'] as String;
    if (!_editableKinds.contains(kind)) return;
    await _applyEditLocally(thread, target, kind, body, inner.ts);
    notifyListeners();
  }

  /// 30.3: a disappearing timer set on another of my devices, for the chat
  /// with [rid]: set here too, so what this device sends from now on carries
  /// it, and said in the chat as the device it was set on said it.
  ///
  /// [linked]: not a change but the timer the chat already has, handed to a
  /// device just linked ([_replayHistoryTo]), whose enrolment gave it every
  /// contact with none. Taken quietly, and only where this device still has
  /// none — a timer set here since then is the newer of the two.
  Future<void> _applyMirroredTimer(String rid, InnerMessage inner,
      {required bool linked}) async {
    final c = contacts[rid];
    final s = inner.data['sec'];
    if (c == null || s is! num) return;
    final sec = s.toInt();
    if (linked && (c.ttlSec != 0 || sec <= 0)) return;
    await vault.db.transaction((txn) async {
      await txn.update('contacts', {'ttl_seconds': sec},
          where: 'rid = ?', whereArgs: [rid]);
      if (!linked) {
        await _insertSystemMessage(
            rid,
            sec == 0
                ? systemBody(SystemKind.ttlOffYou)
                : systemBody(SystemKind.ttlSetYou, {'sec': sec}),
            txn: txn);
      }
    });
    c.ttlSec = sec;
    notifyListeners();
  }

  /// When a copy that arrived through the self-sync or extra-device door
  /// expires. §6.1: the sender deletes `ttl` seconds after sending, the
  /// recipient `ttl` seconds after receipt. A copy of my OWN message on my
  /// other device is the sender's copy, so it goes when the original does —
  /// from the message's own timestamp, which both devices hold. A copy of
  /// somebody else's message is a receipt, on this device, now — the same
  /// clock the primary inbound path uses (`_persistInboundKind`), so a
  /// message from a contact's laptop keeps time exactly as one from their
  /// phone. Until 2026-09-17 every copy through these doors was stored with
  /// no expiry at all: a disappearing message mirrored to a linked device, or
  /// sent from a contact's linked device, never disappeared.
  int _mirroredExpiry(InnerMessage inner, bool outgoing) {
    if (inner.ttlSec <= 0) return 0;
    return (outgoing ? inner.ts : _now()) + inner.ttlSec * 1000;
  }

  /// A mirrored file offer from one of my own devices: record the offer (with
  /// its file key, so the sidecar chunks can be assembled) and a placeholder
  /// message, then try to assemble in case those chunks already arrived.
  ///
  /// [outgoing]: mine, sent from another of my devices — my own devices are
  /// me. Otherwise it came from the contact whose conversation [rid] is,
  /// whichever of their devices sent it or mine passed it on.
  Future<_OfferFate> _insertMirroredFile(
      String rid, bool outgoing, InnerMessage inner) async {
    // The same rules as [_persistFileOffer], because this is the same offer
    // arriving through a different door: a contact's LINKED device sends its
    // attachment offers here rather than there (`_dispatchExtraInner`), and
    // that door was not checked when the id rule was written. `Vault.blobFile`
    // refuses to write a blob under a malformed id, so nothing was ever put
    // where it should not be — what got through was a `files` row and a
    // message placeholder under an id nothing can ever complete, which no
    // sweep collects because the message row it belongs to is real. An id
    // held for another message (§7) is refused here as there, or the
    // laptop's door would be the one the delete-and-replace went through.
    final offer = _FileOffer.read(inner.data);
    if (offer == null) return _OfferFate.refused;
    final fid = offer.fid;
    final name = offer.name;
    final status = outgoing ? MsgStatus.sent : MsgStatus.delivered;
    final expireAt = _mirroredExpiry(inner, outgoing);
    QuotedMessage? quoted;
    final fate = await vault.db.transaction((txn) async {
      final fate =
          await _offerFate(txn, rid, inner.mid, fid, outgoing ? '' : rid);
      if (fate != _OfferFate.fresh) return fate;
      quoted = await _resolveQuote(rid, inner.replyTo, txn: txn);
      await txn.insert('files', {
        'fid': fid,
        'rid': rid,
        'mid': inner.mid,
        'enc_meta': await vault.seal(jsonEncode(offer.meta)),
        'complete': 0,
        'got_chunks': 0,
        'total_chunks': offer.chunks,
      });
      await txn.insert('messages', {
        'mid': inner.mid,
        'rid': rid,
        'outgoing': outgoing ? 1 : 0,
        'kind': 'file',
        'enc_body': await vault.seal(jsonEncode({'fid': fid})),
        'fid': fid,
        'ts_ms': inner.ts,
        'status': status,
        'expire_at_ms': expireAt,
        'reply_to': quoted?.mid,
      });
      return _OfferFate.fresh;
    });
    if (fate != _OfferFate.fresh) return fate;
    _appendLoaded(
        rid,
        ChatMessage(
          mid: inner.mid,
          rid: rid,
          outgoing: outgoing,
          kind: 'file',
          body: name,
          fid: fid,
          ts: inner.ts,
          status: status,
          expireAtMs: expireAt,
          replyTo: quoted?.mid,
          quote: quoted,
          file: offer.fileMeta,
        ));
    notifyListeners();
    await _offerLanded(fid); // sidecar chunks may already be here
    return _OfferFate.fresh;
  }

  // ------------------------------------------------------------------
  // Groups — pairwise-encrypted fan-out over the existing 1:1 ratchets.
  //
  // Every group message is individually end-to-end encrypted to each member
  // over the already-established, authenticated pairwise conversation, with
  // the group id inside the plaintext. There is NO shared group key, so
  // removing a member needs no rekey: senders simply stop sending to them,
  // and anything they send is rejected by the membership check. The creator
  // is the admin; membership updates are applied only when they arrive over
  // the admin's channel with a higher version. Invites carry every member's
  // signature-verified key bundle, so members who aren't each other's
  // contacts yet are added automatically (unverified, verifiable later).
  // ------------------------------------------------------------------

  Future<void> _loadGroups() async {
    final s = await vault.kvGet('groups');
    if (s == null) return;
    var dropped = false;
    for (final j in (jsonDecode(s) as List)) {
      final g = Group.fromJson((j as Map).cast<String, Object?>());
      // A group written by a build that accepted any string as a group id
      // (before 2026-09-13) may be one a contact planted to take over
      // another contact's conversation — see [_applyGroupInvite]. It goes
      // rather than being shown: the thread underneath it is the real one,
      // and an honest group can be made again in two taps.
      if (!isWellFormedGid(g.gid)) {
        dropped = true;
        continue;
      }
      groups[g.gid] = g;
    }
    if (dropped) await _saveGroups();
  }

  /// Persist all groups. Matches the vault's sensitive-kv format so it can be
  /// written inside an inbound transaction (kvPut cannot take a txn).
  Future<void> _saveGroups({DatabaseExecutor? txn}) async {
    final v = await vault
        .seal(jsonEncode([for (final g in groups.values) g.toJson()]));
    await (txn ?? vault.db).insert('kv', {'k': 's:groups', 'v': v},
        conflictAlgorithm: ConflictAlgorithm.replace);
  }

  /// The invite payload for [g]: name, membership version, and every member's
  /// verified bundle (including mine), so recipients can auto-add anyone they
  /// don't know and detect their own removal.
  ///
  /// ADR 0019: `owner` and `admins` name who runs the group, as routing ids
  /// — mine for me, since `''` means nothing to anyone else — and `rv` is
  /// the version of those roles ([Group.rolesVer]). All three are optional
  /// members of an existing sealed inner message (PROTOCOL §11.1, §14): a
  /// client from before roles ignores them and treats whoever sent it its
  /// first invite as the one admin, and an invite without them is read here
  /// as "owner = sender, admins = {sender}, rv = 0", which is what it meant
  /// when it was written. What they cost against the envelope buckets is
  /// measured in group_roles_test 11.
  ///
  /// So they are written only when they say something their absence does
  /// not. For the owner of a group whose roles have never changed — I own
  /// it, I am its only admin, `rv` is 0 — absence says exactly that, and the
  /// list goes out as the bytes a client before 0019 would send: the relay
  /// sees the envelope it always saw, and nothing in it tells a 0019 client
  /// from an older one (group_roles_test 13). Every other list carries all
  /// three. The receiving rules need nothing for this, because an omission
  /// is never more than a claim they already judge: anyone else who leaves
  /// them out is claiming "I own it, I am its only admin, at roles version
  /// 0". Where the roles have ever changed, `rv` 0 is older than the version
  /// every member holds, and the list is discarded as stale (check 1 of
  /// [_applyGroupInvite]); where they have not, the sender is not in the
  /// held admin set and the list is held back (check 2) — at the held `rv`
  /// a different owner would fail check 3 too. Either way it is refused
  /// exactly as the same claim written out would be (group_roles_test 14).
  /// And the owner must write them once `rv` has moved, even with the admin
  /// set back to just themselves: an omission would read as `rv` 0, stale.
  ///
  /// A person is named on the wire by their ACCOUNT, never by one of its
  /// devices: I name myself by my account's routing id ([_rootRid]), and a
  /// linked device of mine writes no member entry for itself at all. Every
  /// receiver already names the sender by the contact the envelope came
  /// from, and an entry for the laptop was what made every member hold the
  /// laptop as a second member and a second contact — one an owner's later
  /// removal of the account named, and kept serving (group_roles_sync_test
  /// 1).
  /// My root device's entry cannot be written from here: the signature that
  /// binds its keys is its own, and a linked device does not hold it.
  ///
  /// A member whose contact I deleted is still named, from the entry kept in
  /// [Group.orphans]: deleting a contact is not a change to a group, and a
  /// list that dropped an admin would be refused everywhere.
  ///
  /// ADR 0030: the group's timer travels as `tmr` once the group has had
  /// one ([Group.tmr] — `0` for off from then on), and every member entry
  /// carries `e`, the position at which that member joined, when they joined
  /// after the group was made ([Group.epochs]). Both are optional members a
  /// client before 0030 ignores, and a group that never had either sends
  /// what it sent before.
  ///
  /// Synchronous, so the list that goes out is exactly the list [g] holds at
  /// the moment it is issued, and its digest is known before anything else
  /// can run.
  Map<String, Object?> _inviteData(Group g) {
    final rv = g.rolesVer;
    final roles = !(g.iAmOwner && g.adminRids.length == 1 && rv == 0);
    final owner = _wireRid(g.ownerRid);
    final admins = [for (final a in g.adminRids) _wireRid(a)]..sort();
    final v0030 = !debugBuildBefore0030;
    Map<String, Object?> entry(String rid, Map<String, Object?> e) {
      final at = g.epochs[rid];
      return {
        for (final x in e.entries)
          if (x.key != 'e') x.key: x.value,
        if (v0030 && at != null && at != Group.origin) 'e': Group.posJson(at),
      };
    }

    final others = [
      for (final rid in g.memberRids)
        if (contacts[rid] != null)
          entry(rid, {
            'b': contacts[rid]!.bundle.toJson(),
            'n': contacts[rid]!.name,
          })
        else if (g.orphans[rid] != null)
          entry(rid, g.orphans[rid]!)
    ];
    return {
      'gid': g.gid,
      'name': g.name,
      'ver': g.ver,
      if (roles) 'owner': owner,
      if (roles) 'admins': admins,
      if (roles) 'rv': rv,
      if (v0030 && g.tmr != null) 'tmr': g.tmr,
      'members': [
        if (_rootRid == null || _rootRid == myRid)
          entry('', {
            'b': ContactBundle(
                    edPub: identity.edPub,
                    xPub: identity.xPub,
                    bindingSig: _myBindingSig!,
                    displayName: displayName)
                .toJson(),
            'n': displayName,
          }),
        ...others,
      ],
    };
  }

  // ---------------------------------------------------------------- 15.3
  // Group fan-out: recorded first, performed after.
  //
  // A group message costs one ratchet encryption, one seal and one vault
  // transaction per recipient — about 24 ms each, measured (see
  // docs/PERFORMANCE.md). Performing all of them before returning made a
  // fifty-member send block the composer for over a second.
  //
  // Merely not awaiting would have traded a visible stall for an invisible
  // loss: a fan-out interrupted part-way used to drop its remaining
  // recipients silently and permanently. So the work is written down before
  // it is done, in one transaction, exactly as the outbox already does for
  // delivery. Recording fifty rows costs about 18 ms; performing them costs
  // 1 200 ms; and a queue that survives a kill is worth more than either.

  bool _fanoutDraining = false;

  /// Set when rows are queued while a drain is already running. Without it
  /// there is a window between the drain's last empty query and its return in
  /// which new rows land and nothing picks them up until the next send.
  bool _fanoutWanted = false;

  /// Set when a drain is asked for while one is already running: a retry
  /// ([retryGroupFanout]), a transparency conflict lifting ([ktChanged]), a
  /// reconnect, a 1:1 inner queued while held. The running drain may already
  /// have stepped over the rows that call wants tried again, so it sweeps the
  /// queue once more from the front before it stops. Until 2026-10-10 such a
  /// call returned leaving no trace, and a row the running drain had passed
  /// waited for the next send or reconnect (`group_fanout_test` 6).
  bool _fanoutAgain = false;

  /// Test hook: hold the queue so an interrupted fan-out can be observed.
  bool debugPauseGroupFanout = false;

  /// Test hook: rows this returns true for are stepped over and left queued
  /// — one recipient's copy delayed, or (deleted from the queue while held)
  /// lost, while every other row goes on being sent. Cleared, the next
  /// drain ([retryGroupFanout]) sends them.
  @visibleForTesting
  bool Function(String rid, InnerMessage inner)? debugHoldGroupFanout;

  /// Test seam: this device behaves as a build from before ADR 0030 did. It
  /// reads no group timer (`tmr`) and writes none; stamps no `ttl` on what
  /// it sends to a group and keeps every group message it receives, whatever
  /// `ttl` it carries; reads and writes no join positions (`e`) and
  /// remembers no leave; and ranks two lists at one version by §11.1's
  /// digest alone. It is how a test has a member on an older build — the
  /// only way to show what such a member does, which is the limit ADR 0030
  /// states. Nothing in the app sets it.
  @visibleForTesting
  bool debugBuildBefore0030 = false;

  /// Record one row per recipient, then drain in the background.
  ///
  /// [also] runs inside the same transaction as the rows — the caller's own
  /// message row goes here, so that the message and the plan to deliver it
  /// are written together or not at all. Written apart, a kill between the
  /// two leaves a message on screen as "pending" with nothing queued behind
  /// it: never sent, and nothing to resume on the next start. The 1:1 path
  /// has always done this (see [_sendInner]); the group path now does too.
  ///
  /// [extraRids]: recipients the list in [inner] no longer names but who
  /// must still be told — a member it removes, whose app marks the group as
  /// left on reading it.
  Future<void> _queueGroupFanout(Group g, InnerMessage inner,
      {Future<void> Function(Transaction txn)? also,
      Iterable<String> extraRids = const []}) async {
    final rids = [
      for (final rid in {...g.memberRids, ...extraRids})
        if (contacts[rid] != null) rid
    ];
    // A group with nobody else in it still records the caller's row.
    if (rids.isEmpty && also == null) return;
    final payload =
        rids.isEmpty ? null : await vault.seal(utf8.decode(inner.toBytes()));
    final now = _now();
    await vault.db.transaction((txn) async {
      if (also != null) await also(txn);
      for (final rid in rids) {
        await txn.insert(
          'group_fanout',
          {
            'mid': inner.mid,
            'gid': g.gid,
            'rid': rid,
            'payload': payload,
            'created_ms': now,
          },
          conflictAlgorithm: ConflictAlgorithm.ignore,
        );
      }
    });
    if (rids.isEmpty) return;
    _fanoutWanted = true;
    unawaited(_drainGroupFanout());
  }

  /// Work the queue off oldest-first, deleting each row only after the
  /// recipient's outbox row is committed. A row that fails is left in place
  /// and retried on the next drain rather than dropped — the failures worth
  /// worrying about here are vault write failures, which are systemic and
  /// transient, not per-recipient.
  /// Try the queue again now — after a conflict has been answered, the rows
  /// that were skipped are sendable and there is no reason to wait for a
  /// reconnect or the next send. With a drain already running, that drain
  /// sweeps once more instead, and this returns at once.
  Future<void> retryGroupFanout() => _drainGroupFanout();

  /// Members a group fan-out could not be sent to because the transparency
  /// log is in conflict with their device list.
  ///
  /// The 1:1 screen has said this since ADR 0006 shipped — a banner, and a
  /// "send anyway". The group screen said nothing at all: every KT banner was
  /// gated on the chat not being a group, while the held kinds include every
  /// group kind. So a group message to a conflicted member stayed pending for
  /// everyone, with no explanation on screen and no way to answer it.
  Set<String> groupSendsHeldFor = const {};

  /// The names behind [groupSendsHeldFor], for the screen.
  List<String> get groupSendsHeldNames => [
        for (final rid in groupSendsHeldFor) contacts[rid]?.name ?? rid
      ]..sort();

  Future<void> _drainGroupFanout() async {
    if (_fanoutDraining) {
      // Asked for while a drain runs: recorded, so that drain sweeps once
      // more ([_fanoutAgain]) rather than this call being lost.
      _fanoutAgain = true;
      return;
    }
    if (debugPauseGroupFanout) return;
    _fanoutDraining = true;
    // This drain starts from the front: every call before it is served.
    _fanoutAgain = false;
    try {
      // A cursor over the queue, and whether this sweep of it achieved
      // anything. A sweep that skipped rows and sent nothing must STOP —
      // restarting on the strength of having skipped something is an
      // infinite loop, since the rows it skipped are exactly the ones it
      // will skip again.
      var after = 0;
      var sentThisSweep = false;
      // Members a pass could not send to because of a transparency conflict.
      // Shown on the group screen, which had no way to say so at all.
      final heldMembers = <String>{};
      // 23.2: a file's encrypted chunks, rebuilt once per PAGE of rows and
      // reused for every member's rows on it (keyed by the offer's mid). A
      // file's rows are queued together so they are contiguous by seq; the
      // cache is dropped after each page, so a long queue of large files
      // holds at most a page's worth of ciphertext, not all of it.
      final chunkCache = <String, List<String>>{};
      while (!debugPauseGroupFanout) {
        _fanoutWanted = false;
        // Past `after`, not from the start. A row that cannot be sent yet —
        // a member in a transparency conflict — stays queued, and reading
        // from the head every time meant 32 such rows hid every row behind
        // them: no group message to ANY member could be delivered while one
        // member was in conflict. The cursor steps over what this pass
        // cannot do and comes back to it on the next one.
        final rows = await vault.db.query('group_fanout',
            where: 'seq > ?', whereArgs: [after], orderBy: 'seq ASC', limit: 32);
        // Empty, but something may have been queued during the query. Only
        // stop once a pass finds nothing AND nothing arrived while looking.
        if (rows.isEmpty) {
          // A drain asked for while this one ran wants what this sweep
          // stepped over tried again.
          final asked = _fanoutAgain;
          _fanoutAgain = false;
          if (after > 0) {
            // The end of the queue, reached by stepping over rows that could
            // not be sent. Sweep again from the front only if something DID
            // go this time — a skipped row may now be behind a sent one — or
            // a drain was asked for meanwhile, and otherwise stop, because
            // nothing has changed and nothing will until a conflict is
            // answered or a contact reconnects: each of those asks for a
            // drain, and finding this one running is how it was lost.
            final again = sentThisSweep || _fanoutWanted || asked;
            after = 0;
            sentThisSweep = false;
            if (again) continue;
            return;
          }
          if (_fanoutWanted || asked) continue;
          return;
        }
        var progressed = false;
        for (final r in rows) {
          if (debugPauseGroupFanout) return;
          final rid = r['rid'] as String;
          final contact = contacts[rid];
          if (contact == null) {
            // Deleted as a contact while queued. Nothing to send, and
            // leaving the row would spin forever. (A member who merely LEFT
            // the group is still a contact and is still served: the message
            // was sent while they were a member, and that is the ordering
            // the queue preserves — what was sent before a change reaches
            // everyone it was sent to; what is sent after does not.)
            await vault.db.delete('group_fanout',
                where: 'seq = ?', whereArgs: [r['seq']]);
            progressed = true;
            continue;
          }
          if (kt.sendsHeld(rid)) {
            // A transparency conflict with this member. Retrying is what a
            // temporary failure deserves and this is not one: the conflict
            // is sticky until the user answers it, so the row would spin for
            // ever, and — because `_markSentIfLast` counts every queued row
            // — the message would stay `pending` for EVERY member, with no
            // banner on a group screen to say why.
            //
            // Worse, the drain reads a page of 32 ordered by `seq` and stops
            // when a whole page fails, so once 32 held rows accumulated at
            // the head no group message to anybody was delivered at all.
            //
            // So it is skipped rather than attempted: the row stays, so
            // answering the conflict delivers it, and it does not count
            // towards progress or towards what the message is still waiting
            // for.
            //
            // A 1:1 held inner (an edit/delete/reaction/timer queued here
            // because the group path's durability is the mechanism it reuses)
            // has gid == rid: it is a conversation of one, surfaced by the
            // 1:1 screen's own conflict banner, so it is not folded into the
            // group screen's held-members set.
            if (r['gid'] != rid) heldMembers.add(rid);
            continue;
          }
          try {
            final inner = InnerMessage.fromBytes(Uint8List.fromList(
                utf8.encode(await vault.unseal(r['payload'] as String))));
            final hold = debugHoldGroupFanout;
            if (hold != null && hold(rid, inner)) continue;
            // 23.2: a file offer travels with its sealed chunks, in the same
            // transaction as the offer's outbox row, so a member gets the key
            // and every chunk or nothing. The chunks are rebuilt from the
            // vault blob, once per file per sweep.
            final chunks = inner.kind == 'gfile'
                ? await _groupFileChunks(inner, chunkCache)
                : null;
            if (inner.kind == 'gfile' && chunks == null) {
              // The file is gone (deleted before its fan-out finished). An
              // offer with no chunks behind it is a broken card on the other
              // side; drop the row rather than spin on it.
              await vault.db.delete('group_fanout',
                  where: 'seq = ?', whereArgs: [r['seq']]);
              progressed = true;
              continue;
            }
            // The message row lives under the GROUP, not under the member
            // whose mailbox this envelope is addressed to.
            await _sendInner(contact, inner,
                threadRid: r['gid'] as String,
                also: chunks == null
                    ? null
                    : (txn) async {
                        for (final p in chunks) {
                          await txn.insert('outbox', {
                            'id': newMessageId(),
                            'rid': rid,
                            'payload': await _sealFor(rid, p),
                            'created_ms': _now(),
                          });
                        }
                      });
            await vault.db.delete('group_fanout',
                where: 'seq = ?', whereArgs: [r['seq']]);
            progressed = true;
          } on KtSendHeldException {
            // The check above raced with a conflict appearing. Same answer
            // (and, as above, a 1:1 held row is not a group-screen concern).
            if (r['gid'] != rid) heldMembers.add(rid);
          } catch (e) {
            // Leave the row. The next drain retries it; the message stays
            // `pending`, which is the truth. Said in a debug build only:
            // `debugPrint` is not stripped from a release build, and this line
            // names a group member's routing id in the system log.
            if (kDebugMode) {
              debugPrint('group fan-out to $rid failed, will retry: $e');
            }
          }
        }
        if (progressed) {
          sentThisSweep = true;
        }
        if (!setEquals(heldMembers, groupSendsHeldFor)) {
          groupSendsHeldFor = Set.unmodifiable(heldMembers);
          notifyListeners();
        }
        // Step past this page either way: a row that could not be sent must
        // not hide the rows behind it, which may be for members who are
        // fine. The sweep ends when the query comes back empty.
        after = rows.last['seq'] as int;
        chunkCache.clear();
      }
    } on DatabaseException {
      // The vault closed under the drain (the app shutting down, or a
      // service disposed right after init — the reconnect kick runs
      // unawaited). Nothing is lost: the rows are durable and the next
      // launch drains them. Fire-and-forget, so do not propagate — an
      // unhandled error here is an app crash on the way out.
      return;
    } finally {
      _fanoutDraining = false;
    }
  }

  /// 23.2: the sealed chunk payloads for a queued group file offer, rebuilt
  /// from the vault blob and the key material the offer carries. Returns null
  /// if the file no longer exists locally. Cached in [cache] by mid for the
  /// rest of the sweep, since every member's rows are the same bytes.
  Future<List<String>?> _groupFileChunks(
      InnerMessage inner, Map<String, List<String>> cache) async {
    final cached = cache[inner.mid];
    if (cached != null) return cached;
    final fid = inner.data['fid'] as String?;
    final fk = inner.data['fk'] as String?;
    final fn = inner.data['fn'] as String?;
    final gid = inner.data['gid'] as String?;
    if (fid == null || fk == null || fn == null || gid == null) return null;
    final Uint8List bytes;
    try {
      // My own file as THIS message carries it. If the message was deleted
      // before its fan-out finished, its id may since have been taken by an
      // offer from somebody else (§7), whose bytes must not go out under my
      // key: nothing is found, and the row is dropped below.
      bytes = await readAttachment(fid, rid: gid, mid: inner.mid);
    } catch (_) {
      return null;
    }
    final km = FileKeyMaterial(fid: fid, fk: unb64(fk), fn: unb64(fn));
    final parts = splitChunks(bytes);
    final out = <String>[];
    for (var i = 0; i < parts.length; i++) {
      out.add(await encryptChunk(km, i, parts[i]));
    }
    cache[inner.mid] = out;
    return out;
  }

  /// Test helper: run one drain pass to completion, synchronously — so a test
  /// can put an obstacle in the vault, drain against it, and look.
  @visibleForTesting
  Future<void> drainGroupFanoutForTest() => _drainGroupFanout();

  /// Test helper: settle once the queue for [gid] is empty.
  @visibleForTesting
  Future<void> waitForGroupFanout(String gid,
      {Duration timeout = const Duration(seconds: 60)}) async {
    final deadline = DateTime.now().add(timeout);
    while (true) {
      final rows = await vault.db.query('group_fanout',
          columns: ['seq'], where: 'gid = ?', whereArgs: [gid], limit: 1);
      if (rows.isEmpty) return;
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('group fan-out for $gid did not drain');
      }
      await Future<void>.delayed(const Duration(milliseconds: 30));
    }
  }

  /// A routing id as the wire names it: for me, THIS device's — `''` is a
  /// convention of this device's records — and for anyone else the id this
  /// device holds them under. Every receiver maps either to the contact it
  /// holds for that account ([_canonRid]).
  ///
  /// This device's own id, not my account's root id, because it is the one
  /// id of mine every receiver of this list can map: to take the list at
  /// all, a receiver has mapped the device that sent it. The root id is
  /// known only to those who hold my device list — not to a member who
  /// adopted me from a list ([_adoptGroupContacts]) under the id of the
  /// device another admin added me from (PROTOCOL §18.7), which then read
  /// my lists as naming an admin who is not in the group, and refused them.
  String _wireRid(String rid) => rid.isEmpty ? myRid : rid;

  /// A routing id from a received list, as THIS device names the person:
  /// `''` for any device of my own account, the contact I hold for any
  /// device of a contact's account (their other devices are in
  /// [_extraRidToContact]), and otherwise the id itself — someone this
  /// device does not know yet. One account is one member, whichever of its
  /// devices a list was written on or names it by.
  String _canonRid(String rid) {
    if (rid == _rootRid || _myAccountRids.contains(rid)) return '';
    return _extraRidToContact[rid] ?? rid;
  }

  /// ADR 0019's authorisation rule, in one place: may [rid] issue a
  /// membership list for group [gid] — add, remove, rename — on the strength
  /// of the list this device holds now? [rid] is a routing id as this device
  /// holds the person; `''`, or any of my own account's routing ids, is me.
  ///
  /// Yes when they are in the held list's admin set AND in the group. A
  /// demoted admin is not in the set, so a list they issue on the strength
  /// of the one they still hold is refused by every member holding the newer
  /// — including a list that would put them back. An admin who has left or
  /// been removed keeps the role on paper (only the owner changes roles), but
  /// cannot use it until an admin adds them back: a list from outside the
  /// group is not one the group has to take, and an owner who left freezes
  /// the admin set, as ADR 0019 says it does, rather than running it from
  /// outside.
  ///
  /// Every local operation asks this about me, and every received list asks
  /// it about its sender before anything else is looked at.
  bool mayIssueGroupList(String gid, String rid) {
    final g = groups[gid];
    if (g == null) return false;
    final who = _myAccountRids.contains(rid) ? '' : rid;
    if (!g.adminRids.contains(who)) return false;
    return who.isEmpty ? !g.left : g.memberRids.contains(who);
  }

  /// Whether this device may change who the admins are, or who owns a group
  /// it owns: only the device holding the account's root, the one that links
  /// the others. Two devices of one owner, each changing the roles before
  /// they have synced, would each open the same roles version with roles of
  /// their own; members holding one would refuse every later list built on
  /// the other, for good (PROTOCOL §11.1). One device per account moves the
  /// roles, so a roles version is only ever opened once. Membership and the
  /// name can still be changed from any device.
  bool get canChangeGroupRolesHere => _holdsRoot;

  /// ADR 0019: may [rid] change who the admins are, or who owns [gid]? The
  /// owner alone, and only while they may issue a list at all — and for me,
  /// only on the device that holds my account's root
  /// ([canChangeGroupRolesHere]).
  bool mayChangeGroupRoles(String gid, String rid) {
    final g = groups[gid];
    if (g == null) return false;
    final who = _myAccountRids.contains(rid) ? '' : rid;
    if (who.isEmpty && !_holdsRoot) return false;
    return who == g.ownerRid && mayIssueGroupList(gid, rid);
  }

  /// Make [g]'s next list, issued by me, and return it as it goes out: the
  /// next version — and, for an owner's change to who the admins are or who
  /// owns the group ([roles]), the next version of the roles, which every
  /// member ranks above any membership version (PROTOCOL §11.1). [members]
  /// and [name] are what the held list said before this change, so what the
  /// change did can be remembered ([Group.mine]) and checked against
  /// whatever list replaces this one; [timer], for a change to the group's
  /// timer, is the timer before it (ADR 0030).
  Map<String, Object?> _issue(Group g, Set<String> members, String name,
      {bool roles = false, int? timer}) {
    g.ver += 1;
    g.by = '';
    if (roles) g.rolesVer += 1;
    g.opensRoles = roles;
    // ADR 0030: whoever this list brings in joins at its own position — later
    // than the position of any membership someone has left, since a list is
    // issued only on top of the one held — so a list that adds a member back
    // is told apart, everywhere, from one issued before their leave reached
    // its issuer. Nobody it takes out keeps one.
    final added = g.memberRids.difference(members);
    for (final r in added) {
      g.epochs[r] = (g.rolesVer, g.ver);
    }
    g.epochs.removeWhere((r, _) => r.isNotEmpty && !g.memberRids.contains(r));
    g.mine = {
      'add': added.toList(),
      // Not someone whose contact I deleted: removing them is how the group
      // lets go of them, and the record keeps nothing of them afterwards.
      'rm': members
          .difference(g.memberRids)
          .where(contacts.containsKey)
          .toList(),
      if (g.name != name) 'name': g.name,
      if (timer != null && timer != g.ttlSec) 'tmr': g.ttlSec,
    };
    g.orphans.removeWhere((rid, _) =>
        contacts.containsKey(rid) ||
        !(g.memberRids.contains(rid) || g.adminRids.contains(rid)));
    final data = _inviteData(g);
    g.digest = Group.listDigest(data);
    g.stateDigest = Group.stateDigestOf(data);
    return data;
  }

  /// Hand [data], a list of [g] just issued, to every member it names — and
  /// to [also], a member it no longer names, so their app marks the group as
  /// left — through the durable fan-out queue (15.3), and mirror it to my own
  /// devices, which apply it as their own action.
  ///
  /// Durable since 2026-10-02. A list sent member by member, with nothing
  /// written down first, lost its remaining recipients to a kill part-way
  /// through the loop, and to a transparency conflict with any one member
  /// (the send throws for a held contact, and the throw left the loop).
  /// With several admins a member a list never reaches can refuse every
  /// later list built on it; recorded first, it is sent on the next start
  /// instead.
  Future<void> _sendInvite(Group g, Map<String, Object?> data,
      {String? also}) async {
    final inner = InnerMessage(
        kind: 'ginvite', mid: newMessageId(), ts: _now(), data: data);
    await _queueGroupFanout(g, inner, extraRids: [if (also != null) also]);
    unawaited(_mirrorGroupChange(g.gid, inner));
  }

  /// Test hook: awaited before a list or a leave of mine is mirrored to my
  /// other devices, so a test can deliver the mirror after something else.
  @visibleForTesting
  Future<void> Function()? debugBeforeGroupMirror;

  Future<void> _mirrorGroupChange(String gid, InnerMessage inner) async {
    final gate = debugBeforeGroupMirror;
    if (gate != null) await gate();
    await (_sync?.mirror(threadRid: gid, dir: 'out', inner: inner) ??
        Future<void>.value());
  }

  /// Create a group with [memberRids] (existing contacts) and invite them.
  Future<String> createGroup(String name, List<String> memberRids) async {
    final gid = newGroupId();
    final g = Group(
      gid: gid,
      name: name,
      ownerRid: '', // I am the owner, and so far the only admin
      memberRids: memberRids.toSet()..removeAll(_myAccountRids),
      opensRoles: true,
    );
    final data = _inviteData(g);
    g.digest = Group.listDigest(data);
    g.stateDigest = Group.stateDigestOf(data);
    groups[gid] = g;
    await _saveGroups();
    unread[gid] = 0;
    await _insertSystemMessage(
        gid, systemBody(SystemKind.createdYou, {'name': name}));
    await _sendInvite(g, data);
    notifyListeners();
    return gid;
  }

  /// Any admin: add members and re-invite everyone at a higher version.
  /// Returns once the new list is recorded for every member; it is sent
  /// from the durable queue ([_sendInvite]).
  ///
  /// [fromLink]: the add a group invite link (ADR 0020) makes once its
  /// joiner has gone ahead — the same add in every respect, said in the
  /// group as a join from my link rather than as something I just did.
  Future<void> addGroupMembers(String gid, List<String> rids,
      {bool fromLink = false}) async {
    final g = groups[gid];
    if (g == null || !mayIssueGroupList(gid, '')) return;
    final added = rids
        .where((r) => !g.memberRids.contains(r) && !_myAccountRids.contains(r))
        .toList();
    if (added.isEmpty) return;
    final before = g.memberRids.toSet();
    g.memberRids.addAll(added);
    final data = _issue(g, before, g.name);
    await _saveGroups();
    // Names as a list; the screen joins them the way its locale does. A
    // missing name is a null, not the word for it.
    final names = [for (final r in added) contacts[r]?.name];
    await _insertSystemMessage(
        gid,
        fromLink
            ? systemBody(SystemKind.linkJoined, {'name': names.first})
            : systemBody(SystemKind.addedYou, {'names': names}));
    await _sendInvite(g, data);
    notifyListeners();
  }

  /// Any admin: remove a member. Remaining members get the new list; the
  /// removed member's next invite omits them, which their app reads as
  /// removal. Either way, everyone else now rejects what they send.
  ///
  /// Removing an ADMIN is the owner's alone (ADR 0019), and takes their role
  /// in the same list. A co-admin who could remove admins could remove the
  /// owner — and then nobody could demote them: an owner who is not in the
  /// group cannot issue a list. Members refuse such a list from a co-admin.
  Future<void> removeGroupMember(String gid, String rid) async {
    final g = groups[gid];
    if (g == null || !mayIssueGroupList(gid, '')) return;
    final wasAdmin = g.adminRids.contains(rid);
    if (wasAdmin && !mayChangeGroupRoles(gid, '')) return;
    if (!g.memberRids.contains(rid)) return;
    final before = g.memberRids.toSet();
    g.memberRids.remove(rid);
    g.adminRids.remove(rid);
    final data = _issue(g, before, g.name, roles: wasAdmin);
    await _saveGroups();
    await _insertSystemMessage(
        gid, systemBody(SystemKind.removedYou, {'name': contacts[rid]?.name}));
    // Tell the removed member too, so their app marks the group as left.
    await _sendInvite(g, data, also: rid);
    // The tick is no longer waiting for them.
    await _reevaluateGroupDelivery(gid);
    notifyListeners();
  }

  /// Any admin: rename the group (23.1). The name already travels in every
  /// invite, so a rename is a membership version bump and a re-invite; members
  /// adopt the new name from the newer invite and say so (`renamedBy`). Nothing
  /// new crosses the wire and no member set changes.
  Future<void> renameGroup(String gid, String name) async {
    final g = groups[gid];
    final trimmed = name.trim();
    if (g == null || !mayIssueGroupList(gid, '')) return;
    if (trimmed.isEmpty || trimmed == g.name) return;
    final before = g.name;
    g.name = trimmed;
    final data = _issue(g, g.memberRids.toSet(), before);
    await _saveGroups();
    await _insertSystemMessage(
        gid, systemBody(SystemKind.renamedYou, {'name': trimmed}));
    await _sendInvite(g, data);
    notifyListeners();
  }

  /// The longest group timer a list may carry (ADR 0030): far beyond any
  /// the app offers, and far inside what the arithmetic of an expiry holds.
  static const maxGroupTimer = 0x7fffffff;

  /// Any admin (ADR 0030, 23.4): set the group's disappearing-messages timer
  /// to [seconds], `0` for off. Who may is who may rename — the timer is
  /// part of the list, as the name is, so it is a version bump and a list
  /// to every member, and every member converges on it the way they
  /// converge on a name (PROTOCOL §11.2). Every group message sent from
  /// then on, by any device of any member that holds the list, carries it
  /// as its `ttl` (§6.1): the sender's copy goes that long after it was
  /// sent, every other copy that long after it arrived.
  ///
  /// A member whose app predates group timers ignores it: it keeps every
  /// message, and what it sends carries no timer — the notice says so, on
  /// every device of every member that can show it.
  Future<void> setGroupTimer(String gid, int seconds) async {
    final g = groups[gid];
    if (g == null || !mayIssueGroupList(gid, '')) return;
    if (seconds < 0 || seconds > maxGroupTimer || seconds == g.ttlSec) return;
    final before = g.ttlSec;
    g.tmr = seconds;
    final data = _issue(g, g.memberRids.toSet(), g.name, timer: before);
    await _saveGroups();
    await _insertSystemMessage(
        gid,
        seconds == 0
            ? systemBody(SystemKind.ttlOffYou)
            : systemBody(SystemKind.groupTtlSetYou, {'sec': seconds}));
    await _sendInvite(g, data);
    notifyListeners();
  }

  /// Owner only (ADR 0019), on the device holding the account root: make
  /// [rid], a member, a co-admin. From then on their lists are accepted by
  /// everyone who accepts this one.
  Future<void> promoteAdmin(String gid, String rid) async {
    final g = groups[gid];
    if (g == null || !mayChangeGroupRoles(gid, '')) return;
    if (!g.memberRids.contains(rid) || g.adminRids.contains(rid)) return;
    g.adminRids.add(rid);
    final data = _issue(g, g.memberRids.toSet(), g.name, roles: true);
    await _saveGroups();
    await _insertSystemMessage(gid,
        systemBody(SystemKind.promotedYou, {'name': contacts[rid]?.name}));
    await _sendInvite(g, data);
    notifyListeners();
  }

  /// Owner only (ADR 0019), on the device holding the account root: take
  /// [rid]'s admin role away. They stay a member. Every member then holds a
  /// list that does not name them, so a list they issue on the strength of
  /// the old one is refused everywhere — including a list that would put
  /// them back. An admin who has LEFT can be demoted too: their role stays
  /// in the list after they go, and only this takes it away.
  Future<void> demoteAdmin(String gid, String rid) async {
    final g = groups[gid];
    if (g == null || !mayChangeGroupRoles(gid, '')) return;
    if (rid == g.ownerRid || !g.adminRids.contains(rid)) return;
    g.adminRids.remove(rid);
    final data = _issue(g, g.memberRids.toSet(), g.name, roles: true);
    await _saveGroups();
    await _insertSystemMessage(
        gid, systemBody(SystemKind.demotedYou, {'name': contacts[rid]?.name}));
    await _sendInvite(g, data);
    notifyListeners();
  }

  /// Owner only (ADR 0019), on the device holding the account root: make
  /// [rid], a member, the owner. I stay a co-admin unless [keepAsAdmin] is
  /// false, in which case this same list demotes me. There is no undo from
  /// my side: only the new owner can give ownership back.
  Future<void> transferOwnership(String gid, String rid,
      {bool keepAsAdmin = true}) async {
    final g = groups[gid];
    if (g == null || !mayChangeGroupRoles(gid, '')) return;
    if (!g.memberRids.contains(rid)) return;
    g.ownerRid = rid;
    g.adminRids.add(rid);
    if (!keepAsAdmin) g.adminRids.remove('');
    final data = _issue(g, g.memberRids.toSet(), g.name, roles: true);
    await _saveGroups();
    await _insertSystemMessage(gid,
        systemBody(SystemKind.transferredYou, {'name': contacts[rid]?.name}));
    await _sendInvite(g, data);
    notifyListeners();
  }

  /// Leave a group: everyone is told directly (authenticated by the pairwise
  /// channel), and the local copy is kept read-only for history.
  ///
  /// Roles are untouched (ADR 0019): an admin who leaves keeps the role on
  /// paper and cannot use it from outside ([mayIssueGroupList]); an owner
  /// who leaves stays the owner of record, so the admin set is frozen until
  /// they are added back. The screen says so, and offers a transfer first.
  /// The leave goes out through the durable queue, like a list: a member it
  /// never reaches keeps the leaver as an admin in the group, and refuses
  /// the other admins' lists that leave them out — until it asks
  /// ([_askAbout]) and this device answers.
  ///
  /// ADR 0030: the leave is remembered, here and on every device it reaches,
  /// with the position of the membership it ends ([Group.leftAt]), which it
  /// states (`e`). A list that still names me there was issued before my
  /// leave reached its issuer: every device that heard the leave takes it
  /// without me, this one included, which stays out; and only a list that
  /// adds me back — naming me at its own, later position — brings me back
  /// in.
  Future<void> leaveGroup(String gid) async {
    final g = groups[gid];
    if (g == null || g.left) return;
    g.left = true;
    g.mine = null;
    _trimLeft(g);
    _rememberMyLeave(g, null);
    await _saveGroups();
    await _insertSystemMessage(gid, systemBody(SystemKind.leftYou));
    final inner = InnerMessage(
        kind: 'gleave', mid: newMessageId(), ts: _now(), data: _leaveData(g));
    await _queueGroupFanout(g, inner);
    unawaited(_mirrorGroupChange(gid, inner));
    notifyListeners();
  }

  /// ADR 0030: record that I have left [g] — at the position of my held
  /// membership, or a later one [stated] by the leave of mine another of my
  /// devices sent. Kept as the latest: a leave remembered is never
  /// forgotten for an older one.
  void _rememberMyLeave(Group g, (int, int)? stated) {
    if (debugBuildBefore0030) return;
    var at = Group.laterPos(
        g.epochs[''] ?? Group.origin, stated ?? Group.origin);
    final prev = g.leftAt[''];
    if (prev != null) at = Group.laterPos(prev, at);
    g.leftAt[''] = at;
  }

  /// A `gleave` for [g], mine: the group, and the position of the membership
  /// it ends (ADR 0030, `e`) — always, `[0, 0]` included, so that a leave
  /// without one is known to be from a build before 0030, and a device that
  /// holds me at a later position can tell this leave from one of that
  /// membership. A client before 0030 reads the group id alone.
  Map<String, Object?> _leaveData(Group g) {
    final at = g.leftAt[''] ?? g.epochs[''] ?? Group.origin;
    return {
      'gid': g.gid,
      if (!debugBuildBefore0030) 'e': Group.posJson(at),
    };
  }

  /// What a group I am out of — left, or removed — keeps of the people in it
  /// whose contact I deleted: nothing ([_forgetInLeft]). Deleting a contact
  /// keeps them only for as long as a group I am in names them; leaving is
  /// one way that ends, and the delete dialog says so.
  void _trimLeft(Group g) {
    _forgetInLeft(g, {
      ...g.orphans.keys,
      for (final r in g.memberRids)
        if (!contacts.containsKey(r)) r,
    });
  }

  /// Make [g], a group I am out of, name none of [gone] — people whose
  /// contact I deleted. They go from its members and its admins; where one
  /// of them is its owner of record, or issued the list it holds, that field
  /// holds [Group.nobody] instead, so the record keeps an owner among its
  /// admins and an issuer without naming anyone. The entries my lists named
  /// people by ([Group.orphans]) and the lists held back for later go too,
  /// whoever they name: a device out of the group has no use for either.
  /// If anyone went, [g] is [Group.trimmed] — no longer the list I held, and
  /// never sent as one. Returns whether [g] changed at all, so that a caller
  /// that saves only on a change saves this one.
  ///
  /// The owner and the issuer were kept until 2026-10-03, as what a later
  /// list is judged against: deleting the owner of a group one had left
  /// showed the plain delete dialog, which promises the contact is wiped,
  /// and left their routing id in this record for good. What naming nobody
  /// costs: a list for the group names its real owner, never this one (a
  /// list's `owner` is a routing id or it is refused), so it can no longer
  /// match the roles held — an admin's list adding me back is refused, where
  /// it used to be taken and to bring the owner back as a contact; the
  /// owner's own was refused already, deleting them having taken them out
  /// of its members (`contact_erasure_test` 14).
  bool _forgetInLeft(Group g, Set<String> gone) {
    // ADR 0030: when they joined and when they left go with them too.
    final positions = g.epochs.keys.any(gone.contains) ||
        g.leftAt.keys.any(gone.contains);
    g.epochs.removeWhere((r, _) => gone.contains(r));
    g.leftAt.removeWhere((r, _) => gone.contains(r));
    final changed = g.orphans.isNotEmpty || g.held.isNotEmpty || positions;
    g.orphans.clear();
    g.held.clear();
    var trimmed = false;
    if (g.memberRids.any(gone.contains)) {
      g.memberRids.removeAll(gone);
      trimmed = true;
    }
    if (gone.contains(g.ownerRid)) {
      g.ownerRid = Group.nobody;
      trimmed = true;
    }
    if (gone.contains(g.by)) {
      g.by = Group.nobody;
      trimmed = true;
    }
    if (g.adminRids.any(gone.contains)) {
      g.adminRids.removeAll(gone);
      trimmed = true;
    }
    g.adminRids.add(g.ownerRid);
    if (trimmed) g.trimmed = true;
    return changed || trimmed;
  }

  /// The groups I am in whose record names [rid] — as a member, an admin,
  /// the owner, the issuer of the list held, or in a list held back — and
  /// so goes on naming them if their contact is deleted: deleting a contact
  /// changes no group. The delete dialog names these groups and says what
  /// each keeps (`contact_erasure_test` 6–13). A group I am out of is not
  /// one of them: it lets go of them when they are deleted
  /// ([_forgetInLeft]).
  List<Group> groupsNaming(String rid) {
    final c = contacts[rid];
    final ed = c == null ? null : b64(c.bundle.edPub);
    bool names(Group g) =>
        g.memberRids.contains(rid) ||
        g.adminRids.contains(rid) ||
        g.ownerRid == rid ||
        g.by == rid ||
        g.held.any((h) =>
            h.from == rid || (ed != null && jsonEncode(h.data).contains(ed)));
    return [
      for (final g in groups.values)
        if (!g.left && names(g)) g
    ];
  }

  /// How [g]'s screen names [rid]: as the contact, or — for a member whose
  /// contact I deleted — by the name their entry in it keeps.
  String? groupMemberName(Group g, String rid) {
    final c = contacts[rid];
    if (c != null) return c.name;
    final n = g.orphans[rid]?['n'];
    return n is String ? n : null;
  }

  // ---------------------------------------------------------------- 23.3
  // Group invite links (ADR 0020).
  //
  // A group invite link IS a connect invite (§20): the group is remembered
  // on the inviter's device only — never in the link, never in a frame —
  // and when the ceremony is over the inviter's device does what its admin
  // would have done by hand, `addGroupMembers`. Two things stand between a
  // completed ceremony and that add, and both are about the JOINER's
  // consent, which is the property this section exists to keep: no
  // joiner's bundle reaches a group's members unless the joiner's own client
  // told its person, before the digits, that the invite was to a group, and
  // the person then went ahead.
  //
  //  * Message 3 carries one sealed bit, "a group is attached" (§20.3), and
  //    the joiner's client repeats it in message 4. A joiner whose client
  //    does not repeat it predates the bit and cannot have said anything:
  //    it ends a contact, and the inviter is told so in the group.
  //  * The ceremony carries itself to the digits with nobody pressing
  //    anything, so message 4 says only "my client can show the notice",
  //    never "my person accepted". What says that is `gjoin`: one sealed
  //    inner message, naming no group, which a joiner's client sends over
  //    the pairwise session when its person, having been told, answers the
  //    comparison — `go` 1 to join, 0 to be a contact only. It carries the
  //    ceremony's go-ahead tag (`t`, §20.6), derived from the channel key,
  //    which only the two ends of that ceremony can compute, so it answers
  //    that ceremony and no other. The inviter adds the joiner when a
  //    go-ahead for its own ceremony arrives — within the link's 24 hours,
  //    and only if it may still add members then.
  //
  // The records on both sides are per LINK, keyed by that tag: two links
  // between the same two people are two waits and two answers, and neither
  // replaces or resets the other. Either person can answer first. A `gjoin`
  // sent before the inviter has added the joiner arrives from a stranger and
  // is dropped, and one that arrives before the inviter is waiting finds
  // nothing it answers; so the inviter, once it is waiting, speaks first (a
  // `hello`), and the joiner's client answers any `hello` from that inviter
  // with every answer it still owes them. Both records are durable; neither
  // ever leaves the device.

  /// Inviter side: completed group links this device made, whose joiner my
  /// person went ahead with — keyed by the ceremony's go-ahead tag (unpadded
  /// base64url): who answered, the group, when the link's lifetime ends, the
  /// tag, and whether their go-ahead has arrived (set inside the inbound
  /// step that read it, acted on after — so a go-ahead read just before the
  /// app was killed still adds them at the next start).
  final Map<String,
          ({String rid, String gid, int until, Uint8List tag, bool go})>
      _linkAdds = {};

  /// Joiner side: answers my person gave to group links — keyed by the
  /// ceremony's go-ahead tag: to whom, until when a `hello` from them is
  /// answered with it again, the tag, and the answer (join, or be a contact
  /// only).
  final Map<String, ({String rid, int until, Uint8List tag, bool join})>
      _linkJoins = {};

  /// Inviter side: waits whose go-ahead [_finishLinkAdds] has taken and is
  /// adding now — past the point where stopping the wait can stop the add.
  final Set<String> _linkAdding = {};

  /// How long a joiner keeps answering, and keeps watching for the group:
  /// twice the link's own lifetime, because the joiner's clock starts when
  /// its person went ahead and the inviter's when the link was made, and
  /// a phone that was off has the rest of the relay's queue to catch up in.
  static final Duration linkJoinWindow = connectInviteLifetime * 2;

  /// Test seam: the clock the link records are judged by. Nothing else in
  /// the service reads it, so a test can put an inviter a day ahead without
  /// moving any other timestamp.
  @visibleForTesting
  int Function()? debugLinkClock;

  int _linkNow() => debugLinkClock?.call() ?? _now();

  /// Whether a group link made at [issuedMs] can still add anyone (its 24
  /// hours, by the clock the link records are judged by) — what the
  /// inviter's comparison screen says before its person goes ahead.
  bool linkStillOpen(int issuedMs) =>
      _linkNow() <= issuedMs + connectInviteLifetime.inMilliseconds;

  /// Test seam: the `mid` of every `gjoin` this device sent, newest last —
  /// so a test can find the envelope in the outbox and weigh it.
  @visibleForTesting
  final List<String> debugLinkJoinMids = [];

  /// Test seam: whether this device is waiting for [rid]'s answer to any
  /// group link it made.
  @visibleForTesting
  bool debugAwaitingLinkJoin(String rid) =>
      _linkAdds.values.any((r) => r.rid == rid);

  /// Test seam: whether this device still owes [rid] an answer to any of
  /// their group links.
  @visibleForTesting
  bool debugOwesLinkJoin(String rid) =>
      _linkJoins.values.any((r) => r.rid == rid);

  /// Test seam: how many `gjoin`s have been read from each contact, counted
  /// in the step that judges them — so a test can wait for a go-ahead to
  /// have been refused rather than sleeping on it.
  @visibleForTesting
  final Map<String, int> debugLinkJoinsRead = {};

  /// Test seam: while true, a go-ahead that arrives is recorded but not
  /// acted on — the state an app killed between reading one and adding its
  /// joiner leaves, which the next start must finish.
  @visibleForTesting
  bool debugHoldLinkAdds = false;

  /// Test seam: when set, [_finishLinkAdds] waits on it after taking a
  /// go-ahead and before adding its joiner — the moment at which stopping
  /// the wait comes too late.
  @visibleForTesting
  Completer<void>? debugBeforeLinkAdd;

  /// Test seam: the waits whose joiner is being added right now.
  @visibleForTesting
  Set<String> get debugLinkAdding => Set.unmodifiable(_linkAdding);

  /// Test seam: act now on every go-ahead that has arrived, as the step
  /// that read one, or the next start, does.
  @visibleForTesting
  Future<void> debugFinishLinkAdds() => _finishLinkAdds();

  /// The waits this device has for answers to its group links (ADR 0020),
  /// for the screen that lets my person stop one: which wait ([id], the
  /// ceremony's tag), who, which group, until when. A go-ahead already read
  /// and about to be acted on is not listed.
  List<({String id, String rid, String gid, int until})>
      get pendingLinkJoins => [
            for (final e in _linkAdds.entries)
              if (!e.value.go)
                (
                  id: e.key,
                  rid: e.value.rid,
                  gid: e.value.gid,
                  until: e.value.until
                )
          ];

  Future<void> _loadLinks() async {
    final raw = await vault.kvGet('group_links');
    if (raw == null) return;
    try {
      final j = (jsonDecode(raw) as Map).cast<String, Object?>();
      Uint8List tagOf(String id) {
        final t = unb64url(id);
        if (t.length != connectGoAheadTagBytes) {
          throw const FormatException('not a go-ahead tag');
        }
        return t;
      }

      for (final e in ((j['adds'] as Map?) ?? const {}).entries) {
        final id = e.key as String;
        final r = (e.value as Map).cast<String, Object?>();
        _linkAdds[id] = (
          rid: r['rid'] as String,
          gid: r['gid'] as String,
          until: (r['until'] as num).toInt(),
          tag: tagOf(id),
          go: r['go'] == true,
        );
      }
      for (final e in ((j['joins'] as Map?) ?? const {}).entries) {
        final id = e.key as String;
        final r = (e.value as Map).cast<String, Object?>();
        _linkJoins[id] = (
          rid: r['rid'] as String,
          until: (r['until'] as num).toInt(),
          tag: tagOf(id),
          join: r['join'] == true,
        );
      }
    } catch (_) {
      // A record this build cannot read adds nobody, which is the safe way
      // for it to fail: the person is a contact either way, and an admin can
      // add them by hand.
      _linkAdds.clear();
      _linkJoins.clear();
    }
  }

  /// Persist both sides' records. Sealed, in the vault's kv format so it can
  /// be written inside the inbound transaction, as [_saveGroups] is.
  Future<void> _saveLinks({DatabaseExecutor? txn}) async {
    final v = await vault.seal(jsonEncode({
      'adds': {
        for (final e in _linkAdds.entries)
          e.key: {
            'rid': e.value.rid,
            'gid': e.value.gid,
            'until': e.value.until,
            'go': e.value.go,
          }
      },
      'joins': {
        for (final e in _linkJoins.entries)
          e.key: {
            'rid': e.value.rid,
            'until': e.value.until,
            'join': e.value.join,
          }
      },
    }));
    await (txn ?? vault.db).insert('kv', {'k': 's:group_links', 'v': v},
        conflictAlgorithm: ConflictAlgorithm.replace);
  }

  /// **Inviter side.** My person went ahead (matched, or not compared) with
  /// [rid], who completed a link this device made for group [gid] at
  /// [issuedMs], in the ceremony whose go-ahead tag is [tag]. [joinerKnows]
  /// is whether the joiner's client repeated the group bit in message 4 —
  /// and so could tell its person, before the digits, that this was a group
  /// invite.
  ///
  /// Nothing is added here. Either the joiner's answer to THIS ceremony is
  /// now awaited, or the group's thread says, on this device only, why it
  /// will not come. A wait is the link's own: another link with the same
  /// person is another wait, and this one neither replaces it nor resets a
  /// go-ahead it has already read.
  Future<LinkJoinOutcome> expectLinkJoin(String rid, String gid,
      {required int issuedMs,
      required bool joinerKnows,
      required Uint8List tag,
      int? nowMs}) async {
    final now = nowMs ?? _linkNow();
    final until = issuedMs + connectInviteLifetime.inMilliseconds;
    final name = contacts[rid]?.name;
    if (groups[gid] == null) return LinkJoinOutcome.refused;
    if (!joinerKnows) {
      // Their client could not have told them the invite was to a group, so
      // their bundle goes nowhere: a contact, exactly as after any CONNECT.
      await _insertSystemMessage(
          gid, systemBody(SystemKind.linkTooOld, {'name': name}));
      notifyListeners();
      return LinkJoinOutcome.tooOld;
    }
    if (now > until) {
      await _insertSystemMessage(
          gid, systemBody(SystemKind.linkExpired, {'name': name}));
      notifyListeners();
      return LinkJoinOutcome.expired;
    }
    if (!mayIssueGroupList(gid, '')) {
      await _insertSystemMessage(
          gid, systemBody(SystemKind.linkRefused, {'name': name}));
      notifyListeners();
      return LinkJoinOutcome.refused;
    }
    _linkAdds[b64url(tag)] =
        (rid: rid, gid: gid, until: until, tag: tag, go: false);
    await _saveLinks();
    notifyListeners();
    // Speak first, now that an answer would be acted on. If they answered
    // before I added them, their `gjoin` came from a stranger and was
    // dropped, and if before I was waiting, it answered nothing; this is
    // what their client answers with it again. Sent even by the designated
    // initiator, whose opening hello went out before the record above
    // existed — a `gjoin` answering THAT one could arrive first and find
    // nothing waiting for it.
    final c = contacts[rid];
    if (c != null) {
      await _sendInner(c, InnerMessage.hello(newMessageId(), _now()));
    }
    return LinkJoinOutcome.waiting;
  }

  /// **Inviter side.** My person stops waiting on the link whose tag is
  /// [id] (from [pendingLinkJoins]): its go-ahead adds nobody — one still to
  /// come, and one already read and not yet acted on — and the group says
  /// so; they stay a contact. Too late only once the add itself has begun,
  /// and then the answer says so rather than nothing.
  Future<LinkWaitStop> cancelLinkJoin(String id) async {
    final rec = _linkAdds.remove(id);
    if (rec == null) {
      return _linkAdding.contains(id)
          ? LinkWaitStop.adding
          : LinkWaitStop.gone;
    }
    await _saveLinks();
    if (groups[rec.gid] != null) {
      await _insertSystemMessage(
          rec.gid,
          systemBody(
              SystemKind.linkCancelled, {'name': contacts[rec.rid]?.name}));
    }
    notifyListeners();
    return LinkWaitStop.stopped;
  }

  /// **Joiner side.** My person answered [rid]'s invite — which said, before
  /// the digits, that it also brings me into a group — in the ceremony whose
  /// go-ahead tag is [tag]: [join] to join, or false to be their contact
  /// only. Says so to them (`gjoin`, carrying the tag and the answer) and
  /// remembers to say it again whenever they say `hello`, until their group
  /// arrives or [linkJoinWindow] has passed. An answer is the link's own:
  /// one given to another link with the same inviter stays as it was.
  Future<void> acceptLinkJoin(String rid,
      {required Uint8List tag, bool join = true, int? nowMs}) async {
    if (contacts[rid] == null) return;
    final id = b64url(tag);
    _linkJoins[id] = (
      rid: rid,
      until: (nowMs ?? _linkNow()) + linkJoinWindow.inMilliseconds,
      tag: tag,
      join: join,
    );
    await _saveLinks();
    await _sendLinkJoin(id);
  }

  /// **Joiner side.** [rid] said `hello`, on whichever of their devices: an
  /// inviter whose links I answered has opened a session — perhaps after
  /// dropping an answer as a stranger's, or before it was waiting for one.
  /// Every answer still owed to them is said again.
  Future<void> _answerLinkHello(String rid) async {
    final now = _linkNow();
    for (final e in _linkJoins.entries.toList()) {
      if (e.value.rid == rid && now <= e.value.until) {
        await _sendLinkJoin(e.key);
      }
    }
  }

  Future<void> _sendLinkJoin(String id) async {
    final owed = _linkJoins[id];
    final c = owed == null ? null : contacts[owed.rid];
    if (owed == null || c == null) return;
    final mid = newMessageId();
    debugLinkJoinMids.add(mid);
    await _sendInner(
        c,
        InnerMessage(kind: 'gjoin', mid: mid, ts: _now(), data: {
          't': id,
          'go': owed.join ? 1 : 0,
        }));
  }

  /// A `gjoin` from [contact] — from any of their devices — read inside the
  /// step that stores it. A go-ahead only marks the wait it answers: the add
  /// is a list fan-out that takes locks of its own, so it runs after, from
  /// [_finishLinkAdds]. A refusal closes that wait, and the group says so.
  ///
  /// Only an answer carrying the tag of a ceremony this device went ahead on
  /// with [contact] counts — compared in constant time with each of theirs,
  /// never looked up by it. Until 2026-10-03 a `gjoin` said nothing of which
  /// ceremony it answered, so one given for an earlier link added the joiner
  /// through a later link they had stopped.
  Future<void> _onLinkJoin(
      Contact contact, InnerMessage inner, DatabaseExecutor txn) async {
    debugLinkJoinsRead[contact.rid] =
        (debugLinkJoinsRead[contact.rid] ?? 0) + 1;
    final t = inner.data['t'];
    final go = inner.data['go'];
    if (t is! String || (go != 0 && go != 1)) return;
    final Uint8List tag;
    try {
      tag = unb64url(t);
    } catch (_) {
      return;
    }
    if (tag.length != connectGoAheadTagBytes) return;
    String? id;
    for (final e in _linkAdds.entries) {
      if (e.value.rid == contact.rid &&
          !e.value.go &&
          constantTimeEquals(tag, e.value.tag)) {
        id = e.key;
      }
    }
    if (id == null) return; // an answer to some other ceremony, or read
    final rec = _linkAdds[id]!;
    if (_linkNow() > rec.until) return; // the sweep says so in the group
    if (go == 0) {
      // They answered, and chose to be a contact only: said now, as what
      // happened, rather than a day later as a link that ran out.
      _linkAdds.remove(id);
      await _saveLinks(txn: txn);
      if (groups[rec.gid] != null) {
        await _insertSystemMessage(rec.gid,
            systemBody(SystemKind.linkDeclined, {'name': contact.name}),
            txn: txn);
      }
      return;
    }
    _linkAdds[id] =
        (rid: rec.rid, gid: rec.gid, until: rec.until, tag: rec.tag, go: true);
    await _saveLinks(txn: txn);
  }

  bool _finishingLinkAdds = false;

  /// Act on every go-ahead that has arrived: re-check, at this moment, that
  /// I may still add members to the group — a link minted by an admin since
  /// demoted adds nobody — and add them by the ordinary path. Each wait is
  /// taken before its add, so one link adds one person once; and from the
  /// moment it is taken, stopping it says it is too late.
  Future<void> _finishLinkAdds() async {
    if (_finishingLinkAdds || debugHoldLinkAdds) return;
    _finishingLinkAdds = true;
    try {
      while (true) {
        final next = _linkAdds.entries.where((e) => e.value.go).firstOrNull;
        if (next == null) break;
        final id = next.key, rid = next.value.rid, gid = next.value.gid;
        _linkAdds.remove(id);
        _linkAdding.add(id);
        try {
          await _saveLinks();
          final gate = debugBeforeLinkAdd;
          if (gate != null) await gate.future;
          if (contacts[rid] == null || groups[gid] == null) continue;
          if (!mayIssueGroupList(gid, '')) {
            await _insertSystemMessage(gid,
                systemBody(SystemKind.linkRefused, {'name': contacts[rid]?.name}));
            notifyListeners();
            continue;
          }
          await addGroupMembers(gid, [rid], fromLink: true);
        } finally {
          _linkAdding.remove(id);
        }
      }
    } finally {
      _finishingLinkAdds = false;
    }
  }

  /// Records whose time is up. An inviter's go-ahead that never came is said
  /// in the group, once; a joiner stops answering and watching.
  Future<void> _sweepLinks() async {
    if (_linkAdds.isEmpty && _linkJoins.isEmpty) return;
    final now = _linkNow();
    final lapsed = [
      for (final e in _linkAdds.entries)
        if (!e.value.go && now > e.value.until) e
    ];
    final before = _linkJoins.length;
    _linkJoins.removeWhere((_, r) => now > r.until);
    if (lapsed.isEmpty && _linkJoins.length == before) return;
    for (final e in lapsed) {
      _linkAdds.remove(e.key);
    }
    await _saveLinks();
    for (final e in lapsed) {
      if (groups[e.value.gid] == null) continue;
      await _insertSystemMessage(
          e.value.gid,
          systemBody(
              SystemKind.linkExpired, {'name': contacts[e.value.rid]?.name}));
    }
    notifyListeners();
  }

  /// Test seam: run the link sweep now, as the 20-second timer does.
  @visibleForTesting
  Future<void> debugSweepLinks() => _sweepLinks();

  /// The `ttl` a group message I send now carries (ADR 0030): the group's
  /// timer as the list I hold states it — what every member's device that
  /// holds the same list stamps on theirs.
  int _groupTtl(Group g) => debugBuildBefore0030 ? 0 : g.ttlSec;

  /// Send a text to every member of [gid], each over their pairwise ratchet.
  /// With the group's timer on (ADR 0030) it carries it as its `ttl`, and my
  /// copy goes that long after it was sent (§6.1).
  Future<void> sendGroupText(String gid, String body,
      {String? replyTo, bool forwarded = false}) async {
    final g = groups[gid];
    if (g == null || g.left) return;
    final ts = _now();
    final ttl = _groupTtl(g);
    final expireAt = ttl > 0 ? ts + ttl * 1000 : 0;
    final quoted = await _resolveQuote(gid, replyTo);
    final inner = InnerMessage(
        kind: 'gmsg',
        mid: newMessageId(),
        ts: ts,
        ttlSec: ttl,
        data: {
          'gid': gid,
          'body': body,
          if (quoted != null) 'rt': quoted.mid,
          if (forwarded) 'fw': true,
        });
    final encBody = await vault.seal(jsonEncode({'b': body}));
    // The message row and its fan-out rows land in ONE transaction, so a
    // message either exists with its delivery plan or does not exist at all.
    await _queueGroupFanout(g, inner, also: (txn) async {
      await txn.insert('messages', {
        'mid': inner.mid,
        'rid': gid,
        'outgoing': 1,
        'kind': 'gtext',
        'enc_body': encBody,
        'ts_ms': ts,
        'status': MsgStatus.pending,
        'expire_at_ms': expireAt,
        'reply_to': quoted?.mid,
        'forwarded': forwarded ? 1 : 0,
      });
    });
    _appendLoaded(
        gid,
        ChatMessage(
          mid: inner.mid,
          rid: gid,
          outgoing: true,
          kind: 'gtext',
          body: body,
          ts: ts,
          status: MsgStatus.pending,
          expireAtMs: expireAt,
          replyTo: quoted?.mid,
          quote: quoted,
          forwarded: forwarded,
        ));
    notifyListeners();
    unawaited(_sync?.mirror(threadRid: gid, dir: 'out', inner: inner) ??
        Future<void>.value());
  }

  /// Send an attachment to every member of [gid]. One file key, one set of
  /// encrypted chunks; the offer (carrying the key) goes to each member over
  /// their pairwise ratchet and the sealed chunks are queued for each
  /// member's mailbox — so a member removed before the send never receives
  /// the key, and one removed afterwards cannot decrypt the next file.
  /// 7.4: voice note into a group — same pairwise fan-out as any attachment.
  Future<void> sendGroupVoiceNote(String gid, Uint8List bytes, int durSec,
          {String mime = 'audio/mp4'}) =>
      sendGroupFile(gid, _voiceNoteName(mime), bytes, mime,
          voice: true, durSec: durSec);

  Future<void> sendGroupFile(
      String gid, String fileName, Uint8List bytes, String mime,
      {bool voice = false,
      int durSec = 0,
      String? replyTo,
      bool forwarded = false}) async {
    final g = groups[gid];
    if (g == null || g.left) return;
    if (bytes.length > maxAttachmentBytes) {
      throw const FormatException(
          'attachment too large (max 24 MB in this build)');
    }
    final ts = _now();
    // ADR 0030: the group's timer, as on a text.
    final ttl = _groupTtl(g);
    final expireAt = ttl > 0 ? ts + ttl * 1000 : 0;
    final quoted = await _resolveQuote(gid, replyTo);
    final km = FileKeyMaterial.generate();
    final chunks = splitChunks(bytes);
    final sha = b64(await sha256Bytes(bytes));
    final inner = InnerMessage(
      kind: 'gfile',
      mid: newMessageId(),
      ts: ts,
      ttlSec: ttl,
      data: {
        'gid': gid,
        'fid': km.fid,
        'name': fileName,
        'size': bytes.length,
        'mime': mime,
        'sha256': sha,
        'fk': b64(km.fk),
        'fn': b64(km.fn),
        'chunks': chunks.length,
        if (voice) 'voice': true,
        if (durSec > 0) 'dur': durSec,
        if (quoted != null) 'rt': quoted.mid,
        if (forwarded) 'fw': true,
      },
    );
    final keyInfo = await vault.writeBlob(km.fid, bytes);
    // 23.2: the chunks are NOT encrypted on the send path. The fan-out is
    // queued like a text's, and the drain rebuilds each member's chunk rows
    // from the blob when that member's turn comes (`chunkNonce` is derived
    // from the file nonce and the index, so every rebuild is byte-identical).
    // Only the mirror to my own linked devices, below, needs them now.
    // Local copy, placeholder and the delivery plan land in ONE transaction,
    // so the file either exists with its fan-out rows or does not exist at
    // all (the same shape as sendGroupText; group_file_fanout_test 4).
    await _queueGroupFanout(g, inner, also: (txn) async {
      await txn.insert('files', {
        'fid': km.fid,
        'rid': gid,
        'mid': inner.mid,
        'enc_meta': await vault.seal(jsonEncode({
          'name': fileName,
          'size': bytes.length,
          'mime': mime,
          'sha256': sha,
          'local': keyInfo,
          if (voice) 'voice': true,
          if (durSec > 0) 'dur': durSec,
        })),
        'complete': 1,
        'got_chunks': chunks.length,
        'total_chunks': chunks.length,
      });
      await txn.insert('messages', {
        'mid': inner.mid,
        'rid': gid,
        'outgoing': 1,
        'kind': 'file',
        'enc_body': await vault.seal(jsonEncode({'fid': km.fid})),
        'fid': km.fid,
        'ts_ms': ts,
        'status': MsgStatus.pending,
        'expire_at_ms': expireAt,
        'reply_to': quoted?.mid,
        'forwarded': forwarded ? 1 : 0,
      });
    });
    _appendLoaded(
        gid,
        ChatMessage(
          mid: inner.mid,
          rid: gid,
          outgoing: true,
          kind: 'file',
          body: fileName,
          fid: km.fid,
          ts: ts,
          status: MsgStatus.pending,
          expireAtMs: expireAt,
          replyTo: quoted?.mid,
          quote: quoted,
          file: FileMeta(
            fid: km.fid,
            name: fileName,
            size: bytes.length,
            mime: mime,
            sha256b64: sha,
            complete: true,
            gotChunks: chunks.length,
            totalChunks: chunks.length,
            voice: voice,
            durSec: durSec,
          ),
        ));
    notifyListeners();
    // The per-member fan-out — the offer over the ratchet plus the sealed
    // chunks in the durable outbox — is performed by _drainGroupFanout, which
    // queues it above and runs in the background (23.2). Membership was
    // snapshotted at queue time, so a member removed before this send never
    // receives the key, exactly as before.
    final sync = _sync;
    if (sync != null) {
      final chunkPayloads = <String>[];
      for (var i = 0; i < chunks.length; i++) {
        chunkPayloads.add(await encryptChunk(km, i, chunks[i]));
      }
      unawaited(() async {
        await sync.mirror(threadRid: gid, dir: 'out', inner: inner);
        for (final p in chunkPayloads) {
          await sync.fanChunk(p);
        }
      }());
    }
  }

  /// Every routing id that is MINE: this install's, plus my account's other
  /// devices.
  ///
  /// Group membership is a property of the account, not of the install. An
  /// invite carries the member bundle the admin holds for my account, which
  /// resolves to whichever of my devices they added — normally my primary.
  /// Comparing that against `myRid` alone therefore answered "no" on every
  /// linked device, so the first membership change in any group told a
  /// secondary device it had been removed, and it then dropped the group's
  /// traffic and refused to send. It also listed my own primary device as a
  /// member of the group.
  Set<String> get _myAccountRids => {myRid, ...?_sync?.deviceRoutingIds};

  /// This ACCOUNT's routing id (ADR 0019): the routing id of its root
  /// device, `b64url(SHA-256(account Ed25519 key))` — what a contact who
  /// scanned my main device holds me under. One more id that is me when a
  /// list names it ([_canonRid]), and how a device knows whether it is the
  /// root, which alone writes a member entry for me ([_inviteData]).
  /// Computed once in [init]: the decision it feeds runs inside the inbound
  /// transaction, where a vault read would wait on that transaction for
  /// ever.
  String? _rootRid;

  /// Whether this device holds my account's root ([canChangeGroupRolesHere]).
  bool _holdsRoot = false;

  /// The signature binding this device's keys, for its own member entry —
  /// deterministic, so computed once ([init]) and a list is built without
  /// an await ([_inviteData]).
  Uint8List? _myBindingSig;

  /// Whether a list at roles version [rv] and version [ver] from [sender],
  /// whose [Group.listDigest] is [digest], is no newer than what [g] holds
  /// (ADR 0019's order, PROTOCOL §11.1): by `rv`, then `ver`; at both equal,
  /// the owner's list outranks any other admin's — the same owner for both,
  /// since within one roles version the owner cannot change — and otherwise
  /// the list whose digest sorts FIRST in plain byte order (`compareTo` on
  /// the base64url strings) wins, whoever sent it. The same list again has
  /// the same digest and changes nothing.
  ///
  /// By digest, not by who sent it. Two admins' lists used to be ranked by
  /// the issuers' routing ids — their accounts', so that a person ranked
  /// the same whichever of their devices sent a list. But which account a
  /// contact is, this device knows only for one added from a code that said
  /// so (§18.7): one adopted from a list is known by the device another
  /// admin added them from, and nothing it can check says more. So a
  /// co-admin added from her laptop's code ranked as her account on the
  /// members who had scanned it and as her laptop on those who had adopted
  /// her, and a tie between her and another admin went one way on some
  /// devices and the other way on the rest, for good (group_roles_test
  /// 27). A list's digest is computed from the list as it travels, the same
  /// on every device that receives it, whoever it holds the sender as.
  ///
  /// ADR 0030: two lists §11.1's digest calls equal — the same list, or two
  /// that differ only in what it leaves out, the group's timer and the
  /// members' join positions — are ranked by [stateDigest] the same way:
  /// the one that sorts first wins, and the same list again changes
  /// nothing. Two admins setting two timers on one list at once otherwise
  /// left each member with whichever reached it first, for good. A client
  /// before 0030 compares the first digest alone, so it ranks every pair it
  /// can tell apart exactly as this one does.
  bool _notNewer(Group g, int rv, int ver, String sender, String digest,
      String stateDigest) {
    if (rv != g.rolesVer) return rv < g.rolesVer;
    if (ver != g.ver) return ver < g.ver;
    final senderOwns = sender == g.ownerRid;
    final heldOwns = g.by == g.ownerRid;
    if (senderOwns != heldOwns) return heldOwns;
    if (g.digest.isEmpty) return true;
    final c = digest.compareTo(g.digest);
    if (c != 0) return c > 0;
    if (debugBuildBefore0030 || g.stateDigest.isEmpty) return true;
    return stateDigest.compareTo(g.stateDigest) >= 0;
  }

  /// Whether a list keeps in the group every admin who is in it on [g]:
  /// at the held roles version a list must (ADR 0019). A co-admin's list
  /// that dropped an admin from the members would demote them as surely as
  /// one that dropped them from `admins`, and dropping the owner would leave
  /// nobody able to demote that co-admin.
  bool _keepsAdmins(Group g, Set<String> members, bool includesMe) {
    for (final a in g.adminRids) {
      final inGroup = a.isEmpty ? !g.left : g.memberRids.contains(a);
      final kept = a.isEmpty ? includesMe : members.contains(a);
      if (inGroup && !kept) return false;
    }
    return true;
  }

  /// Whether a list replacing one I issued undoes what mine did ([mine],
  /// [Group.mine]): a member I added is not in it, one I removed is back, or
  /// the name I gave is gone. Whatever its version — a co-admin's second
  /// quick change, built on their own first, is a version above mine and
  /// carries none of it — so the owner whose removal a co-admin's list put
  /// back is told, where only a list at no higher a version used to say so.
  ///
  /// The timer I set (ADR 0030) is gone too when [timer], the replacing
  /// list's, is not it.
  bool _undoes(Map<String, Object?> mine, Set<String> members, String name,
      int timer) {
    final add = mine['add'], rm = mine['rm'], renamed = mine['name'];
    if (add is List && add.any((r) => !members.contains(r))) return true;
    if (rm is List && rm.any(members.contains)) return true;
    final t = mine['tmr'];
    if (t is int && t != timer) return true;
    return renamed is String && renamed != name;
  }

  /// Test seam: how many `ginvite`s for each group have been judged —
  /// applied, discarded or held back — counted once each, in the same
  /// synchronous step that acts on the judgement, so a test that sees the
  /// outcome also sees the count. It lets a test wait for a list it expects
  /// to be refused to have been judged, instead of sleeping on it.
  @visibleForTesting
  final Map<String, int> debugGroupListsHandled = {};
  final Map<String, Map<String, int>> _judgedFrom = {};

  /// Test seam: [debugGroupListsHandled] for one sender — `''` for my own
  /// account — so a test can wait for exactly the lists IT sent to have been
  /// judged, whatever else arrives meanwhile (an answer to a `gsync`, say).
  @visibleForTesting
  int debugListsJudgedFrom(String gid, String sender) =>
      _judgedFrom[gid]?[sender] ?? 0;

  void _judged(String gid, bool retry, String sender) {
    if (!retry) {
      debugGroupListsHandled[gid] = (debugGroupListsHandled[gid] ?? 0) + 1;
      final by = _judgedFrom.putIfAbsent(gid, () => {});
      by[sender] = (by[sender] ?? 0) + 1;
    }
  }

  /// Test seam: how many lists for [gid] are held back — the observable that
  /// a refused list ARRIVED and was refused, rather than not having arrived
  /// yet, so a test can assert a refusal without sleeping on it.
  @visibleForTesting
  int debugHeldBackLists(String gid) => groups[gid]?.held.length ?? 0;

  /// Test seam: the `ginvite` payload this device would send for [gid] now —
  /// so a test can weigh the list with and without ADR 0019's members, sent
  /// down the same path.
  @visibleForTesting
  Future<Map<String, Object?>> debugInviteData(String gid) async =>
      _inviteData(groups[gid]!);

  /// Test seam: awaited by every received list just before it is judged —
  /// after its member entries are verified, before the decision, which has
  /// no await in it. A test lines two lists up here and lets them go
  /// together, so the decision is exercised against a list another one is
  /// deciding at that moment. Only lists that arrive outside the inbound
  /// transaction — from a contact's linked device, or mirrored by my own —
  /// can be lined up so: one held here on the primary path holds the
  /// transaction, and every other envelope waits behind it.
  @visibleForTesting
  Future<void> Function(String gid, String sender)? debugBeforeGroupDecision;

  /// Hold [data], refused for its sender's role or the roles it carries,
  /// until the held list changes (ADR 0019): it may rest on a list that has
  /// not arrived — the owner's promotion of its sender, a leave it reflects.
  /// One per sender — that sender's newer list, the later one replacing
  /// their earlier wholesale anyway, and the same list twice (sent to me,
  /// and mirrored by my other device) kept once — so no member can push an
  /// honest list out with lists of their own; and at most [Group.maxHeld],
  /// the oldest going first. In the group's record, so a restart keeps them.
  void _holdBack(
      Group g, String fromRid, Map<String, Object?> data, bool mirrored,
      _WireList list) {
    final sender = mirrored ? '' : fromRid;
    final i = g.held.indexWhere((h) => h.sender == sender);
    if (i >= 0) {
      final kept = _parseList(g.held[i].data);
      if (kept != null && kept.newerThan(list)) return;
      g.held.removeAt(i);
    }
    g.held.add(HeldList(fromRid, data, mirrored));
    while (g.held.length > Group.maxHeld) {
      g.held.removeAt(0);
    }
  }

  /// Who I have asked about each group (`gsync`) since the list I hold for it
  /// last changed: each of them once per change, not once per list refused.
  final Map<String, Set<String>> _asked = {};

  /// Whom I have answered about each group, and at which held list: once
  /// per list I hold, however often they ask.
  final Map<String, Map<String, String>> _answered = {};

  /// Ask what this device lacks to apply a list it had to refuse (PROTOCOL
  /// §11.1, `gsync`): the held owner — whose current list carries any
  /// promotion, transfer or demotion that never arrived — and every admin
  /// who is a member here and missing from that list, who may have left
  /// with a leave that never arrived. Delivery is not guaranteed: the relay
  /// keeps an envelope 72 hours, in memory. Before roles a member that
  /// missed a list caught up at the next one; now a member that missed one
  /// admin's leave refuses every list the others issue without them, and
  /// would do so for good. Each is asked once until the list held changes.
  void _askAbout(Group g, Set<String> listMembers, String sender) {
    final targets = <String>{
      g.ownerRid,
      for (final a in g.adminRids)
        if (a.isNotEmpty &&
            g.memberRids.contains(a) &&
            !listMembers.contains(a))
          a,
    }
      ..remove('')
      ..remove(sender);
    final asked = _asked.putIfAbsent(g.gid, () => {});
    for (final rid in targets) {
      final c = contacts[rid];
      if (c == null || !asked.add(rid)) continue;
      final inner = InnerMessage(
          kind: 'gsync',
          mid: newMessageId(),
          ts: _now(),
          data: {'gid': g.gid});
      // Not awaited: this runs inside the inbound transaction, and a send
      // writes the outbox in a transaction of its own.
      unawaited(
          _sendInner(c, inner, threadRid: g.gid).then((_) {}, onError: (_) {}));
    }
  }

  /// [_askAbout] for every list [g] holds back — after a restart, when the
  /// asks made before it are forgotten.
  Future<void> _askAboutHeld(Group g) async {
    for (final h in [...g.held]) {
      final members = <String>{if (!h.mirrored) h.from};
      final ms = h.data['members'];
      if (ms is List) {
        for (final m in ms) {
          try {
            final e = (m as Map).cast<String, Object?>();
            final b =
                ContactBundle.fromJson((e['b'] as Map).cast<String, Object?>());
            members.add(_canonRid(await b.routingId()));
          } catch (_) {}
        }
      }
      _askAbout(g, members, h.sender);
    }
  }

  /// Answer a member who asked about [data]'s group (`gsync`): an admin
  /// sends the list it holds — an admin who has left included, since what
  /// it holds is what it left, unless it has since let go of someone in it
  /// ([Group.trimmed]: that list would drop them) — and a device that has
  /// left then sends its leave again. Only to someone this device holds as
  /// a member, or held when it left; anyone else learns nothing. Once per
  /// list held.
  void _answerGroupSync(Contact c, Map<String, Object?> data) {
    final gid = data['gid'];
    if (gid is! String) return;
    final g = groups[gid];
    if (g == null || !g.memberRids.contains(c.rid)) return;
    final at = '${g.rolesVer}/${g.ver}/${g.digest}/${g.left}';
    final done = _answered.putIfAbsent(gid, () => {});
    if (done[c.rid] == at) return;
    done[c.rid] = at;
    final replies = [
      if (g.iAmAdmin && !g.trimmed)
        InnerMessage(
            kind: 'ginvite',
            mid: newMessageId(),
            ts: _now(),
            data: _inviteData(g)),
      if (g.left)
        InnerMessage(
            kind: 'gleave',
            mid: newMessageId(),
            ts: _now(),
            data: _leaveData(g)),
    ];
    if (replies.isEmpty) return;
    // In order — the list, then the leave — and outside the inbound
    // transaction this is called from.
    unawaited(() async {
      for (final inner in replies) {
        try {
          await _sendInner(c, inner, threadRid: gid);
        } catch (_) {}
      }
    }());
  }

  final Set<String> _retryingHeldBack = {};
  final Set<String> _retryHeldBackAgain = {};

  /// Try [gid]'s held-back lists again, until a pass applies none of them.
  /// Each pass takes the whole queue; a list still not acceptable is held
  /// back again by its own attempt, and one now stale is dropped.
  /// Terminates: a list is only applied when it outranks what is held, and
  /// there are finitely many.
  ///
  /// A second call while a pass runs — the held list changed under it, from
  /// another contact's envelope — makes the running pass go round again
  /// rather than being lost: a list the pass had already tried may pass
  /// now. Without that, it waited for the next change.
  Future<void> _retryHeldBack(String gid, {DatabaseExecutor? txn}) async {
    if (!_retryingHeldBack.add(gid)) {
      _retryHeldBackAgain.add(gid);
      return;
    }
    try {
      var again = true;
      while (again) {
        again = false;
        _retryHeldBackAgain.remove(gid);
        final g = groups[gid];
        if (g == null || g.held.isEmpty) break;
        final waiting = [...g.held];
        g.held.clear();
        for (final h in waiting) {
          if (await _applyGroupInvite(h.from, h.data,
              txn: txn, mirroredOwn: h.mirrored, retry: true)) {
            again = true;
          }
        }
        if (_retryHeldBackAgain.contains(gid)) again = true;
      }
      await _saveGroups(txn: txn);
    } finally {
      _retryingHeldBack.remove(gid);
      _retryHeldBackAgain.remove(gid);
    }
  }

  static final RegExp _ridShape = RegExp(r'^[A-Za-z0-9_-]{43}$');

  /// The highest version a list may carry: far beyond any honest group, and
  /// low enough that the next one is still exact.
  static const _maxListVersion = 1 << 52;

  /// The most entries a list's `members` — or its `admins` — may have
  /// (PROTOCOL §11.1). Above anything the reference relay can carry: under
  /// its default frame cap a list travels in the 262 144-byte bucket at
  /// most, which holds fewer than 900 member entries with empty names, so
  /// no list that relay delivers is refused for it. What it bounds is the
  /// work and the room one list can cost: one signature check per entry,
  /// again for every held-back list each time the held list changes, and
  /// up to [Group.maxHeld] such lists kept per group. Unbounded, a member
  /// behind a relay configured with a larger frame could have each of those
  /// eight be a list of megabytes.
  static const _maxListEntries = 1024;

  /// [data] as a list, or null if it is not one: every member present with
  /// the type §11 gives it — a version a whole number, `owner` and each of
  /// `admins` a routing id (43 base64url characters; an empty string was
  /// read as "me" by every receiver, so each believed it owned the group),
  /// and no more than [_maxListEntries] members or admins. Absent members
  /// take the meaning they had before ADR 0019. Nothing here throws: this
  /// runs inside the inbound transaction, and an exception would leave the
  /// envelope unacknowledged, to be delivered and refused again for ever.
  _WireList? _parseList(Map<String, Object?> data) {
    final name = data['name'] ?? 'Group';
    final ver = data['ver'] ?? 1;
    final rv = data['rv'] ?? 0;
    final owner = data['owner'];
    final admins = data['admins'];
    final members = data['members'] ?? const <Object?>[];
    if (name is! String || ver is! int || rv is! int || members is! List) {
      return null;
    }
    if (members.length > _maxListEntries) return null;
    if (ver < 1 || ver > _maxListVersion || rv < 0 || rv > _maxListVersion) {
      return null;
    }
    if (owner != null && (owner is! String || !_ridShape.hasMatch(owner))) {
      return null;
    }
    if (admins != null &&
        (admins is! List ||
            admins.length > _maxListEntries ||
            admins.any((a) => a is! String || !_ridShape.hasMatch(a)))) {
      return null;
    }
    // ADR 0030: the timer a whole number of seconds, from none to
    // [maxGroupTimer]; a member's join position, where an entry carries
    // one, two whole numbers within a version's bounds. Refused otherwise,
    // as a version that is not a whole number is — and never read at all by
    // a build before 0030, which ignores both.
    final v0030 = !debugBuildBefore0030;
    final tmr = v0030 ? data['tmr'] : null;
    if (tmr != null && (tmr is! int || tmr < 0 || tmr > maxGroupTimer)) {
      return null;
    }
    if (v0030 &&
        members.any((m) =>
            m is Map && m.containsKey('e') && Group.posFrom(m['e']) == null)) {
      return null;
    }
    return _WireList(
      name: name,
      ver: ver,
      rv: rv,
      owner: owner as String?,
      admins: admins == null ? null : [for (final a in admins as List) a as String],
      members: members,
      digest: Group.listDigest(data),
      tmr: tmr as int?,
      stateDigest: Group.stateDigestOf(data),
    );
  }

  /// Apply a group invite. [fromRid] is the authenticated sender ('' when the
  /// invite is a mirror of my own admin action from my other device). True
  /// if the list was applied. [retry]: a held-back list tried again.
  ///
  /// ADR 0019 (PROTOCOL §11.1), for a group already held:
  ///   1. a list no newer than the one held is dropped — ordered by roles
  ///      version, then version, then rank ([_notNewer]);
  ///   2. its sender must be allowed to issue one by the list HELD, not the
  ///      one arriving ([mayIssueGroupList]) — so a demoted admin still
  ///      holding the old list cannot re-admit themselves: every member holds
  ///      the newer list, the sender is not in its admin set, and the list
  ///      goes no further, the same fate a removed member's messages meet in
  ///      [_persistGroupText];
  ///   3. a newer roles version only from the held owner, and at the held
  ///      one the roles kept ([_keepsAdmins]) — except the sibling of a list
  ///      that opened the roles version, which is the same owner's other
  ///      opening of it and is ranked against it instead.
  /// A list failing 2 or 3 is held back ([_holdBack]) — if its sender is in
  /// the group at all — and what it rests on is asked for ([_askAbout]).
  /// What passes replaces the held list wholesale: nothing is merged and
  /// nothing rolled back.
  ///
  /// Every routing id in the list is mapped to the person this device holds
  /// ([_canonRid]): a member's linked device is that member, and any device
  /// of my own account is me.
  Future<bool> _applyGroupInvite(String fromRid, Map<String, Object?> data,
      {DatabaseExecutor? txn,
      bool mirroredOwn = false,
      bool retry = false}) async {
    final gid = data['gid'];
    if (gid is! String || !isWellFormedGid(gid)) return false;
    // A group id is also the THREAD KEY: messages are filed under it, and a
    // chat is a group when `groups[rid]` exists. Until 2026-09-13 any
    // non-empty string was accepted here, so a contact could send a
    // `ginvite` naming ANOTHER contact's routing id and take that
    // conversation over — its title became the group's name, its members
    // became whoever the invite listed, and every banner the chat screen
    // draws only for a 1:1 (the device-list warning, the transparency log's
    // conflict, the disappearing-messages control) silently stopped being
    // drawn. The send is still refused by the service, so what the victim
    // saw was messages not going, with the explanation gone.
    //
    // §11's shape is what makes that impossible: a routing id is 43
    // base64url characters, a group id is `g` and sixteen more. The explicit
    // refusal below is belt and braces — it is the property that matters, so
    // it is written down rather than left to be deduced from two lengths.
    if (contacts.containsKey(gid) || gid == myRid) return false;
    final sender = mirroredOwn ? '' : fromRid;
    final list = _parseList(data);
    if (list == null) {
      _judged(gid, retry, sender);
      return false;
    }

    // Who the list says runs the group, as THIS device names them. An invite
    // from before ADR 0019 carries neither member and is read as it was
    // written: the sender owns the group and is its only admin, at roles
    // version 0.
    final owner = list.owner == null ? sender : _canonRid(list.owner!);
    final admins = <String>{
      for (final a in list.admins ?? const <String>[]) _canonRid(a),
      owner,
    };

    // A quick refusal before the bundles are verified, for the common case
    // of a list this device already holds (it arrives twice: directly and
    // mirrored by my other device). Decided again below, without an await.
    final early = groups[gid];
    if (early != null &&
        _notNewer(early, list.rv, list.ver, sender, list.digest,
            list.stateDigest)) {
      _judged(gid, retry, sender);
      return false;
    }

    // Verify every member bundle. Contacts we do not know yet are collected
    // here and added only once the list is accepted: a refused list must not
    // leave strangers in the address book. A list of my own account's,
    // mirrored from my other device, includes me whether or not it carries
    // an entry for me — a linked device writes none (see [_inviteData]).
    var includesMe = mirroredOwn;
    final memberRids = <String>{};
    final unknown = <(String, ContactBundle, String)>[];
    // ADR 0030: the position at which the list says each member joined (an
    // entry's `e`; none is the group's start), and mine — for every account
    // it has an entry for, which a sender writing from a linked device has
    // not, for itself.
    final joined = <String, (int, int)>{};
    (int, int)? myJoined;
    final v0030 = !debugBuildBefore0030;
    // ADR 0024: members this device has blocked. Members all the same — the
    // list is the group's, and a list of mine that dropped one would take
    // them out for everyone — but not taken in: kept as an entry, as a
    // member whose contact I deleted is ([Group.orphans]), never made a
    // contact. So my group messages skip them, theirs find no session here,
    // and the block stands. Until 2026-10-09 the list made them a contact,
    // and they could write to me directly.
    final blockedEntries = <String, Map<String, Object?>>{};
    for (final m in list.members) {
      ContactBundle bundle;
      String cname;
      (int, int) at;
      try {
        final e = (m as Map).cast<String, Object?>();
        bundle =
            ContactBundle.fromJson((e['b'] as Map).cast<String, Object?>());
        if (!await bundle.verify()) continue;
        final n = e['n'];
        cname = n is String ? n : 'Unknown';
        at = (v0030 ? Group.posFrom(e['e']) : null) ?? Group.origin;
      } catch (_) {
        continue;
      }
      final rid = _canonRid(await bundle.routingId());
      if (rid.isEmpty) {
        includesMe = true;
        myJoined = at;
        continue;
      }
      memberRids.add(rid);
      joined[rid] = at;
      if (contacts.containsKey(rid)) continue;
      if (_blocked.contains(rid)) {
        blockedEntries[rid] = {'b': bundle.toJson(), 'n': cname};
        continue;
      }
      unknown.add((rid, bundle, cname));
    }
    if (!mirroredOwn) memberRids.add(fromRid); // the sender is a member too

    final gate = debugBeforeGroupDecision;
    if (gate != null) await gate(gid, sender);

    // ---- The decision. No await from here until the held list has been
    // replaced: two lists for one group can be judged at once — the inbound
    // transaction serialises envelopes on the primary path, but a list from
    // a contact's linked device, or mirrored by my own, is judged outside it
    // — and an await between reading the held list and replacing it would
    // let the second overwrite the first without ever being ranked against
    // it (group_roles_test 18).
    _judged(gid, retry, sender);
    final existing = groups[gid];
    var opens = true;
    if (existing != null) {
      if (_notNewer(existing, list.rv, list.ver, sender, list.digest,
          list.stateDigest)) {
        return false;
      }
      final sameRoles =
          owner == existing.ownerRid && setEquals(admins, existing.adminRids);
      final sibling = list.rv == existing.rolesVer &&
          list.ver == existing.ver &&
          sender == existing.by;
      final bool ok;
      if (sibling && !sameRoles) {
        // The held list's issuer, at its versions, with other roles: their
        // other opening of this roles version — the owner on two devices, or
        // sending two lists. Accepted only where the held list opened it, so
        // it is ranked against its twin by digest ([_notNewer]) rather than
        // refused by the twin's roles, and every member keeps the same one.
        ok = existing.opensRoles;
      } else if (list.rv > existing.rolesVer) {
        ok = sender == existing.ownerRid && mayIssueGroupList(gid, sender);
      } else {
        ok = sameRoles &&
            _keepsAdmins(existing, memberRids, includesMe) &&
            mayIssueGroupList(gid, sender);
        opens = sibling && existing.opensRoles;
      }
      if (!ok) {
        // Held for later only from someone in the group as this device holds
        // it (or my own account): anyone else's list could only ever be
        // applied after a list adding them, which brings their next one.
        if (sender.isEmpty || existing.memberRids.contains(sender)) {
          _holdBack(existing, fromRid, data, mirroredOwn, list);
        }
        _askAbout(existing, memberRids, sender);
        await _saveGroups(txn: txn);
        return false;
      }
    }

    // ADR 0030 (23.5): a list that names someone whose leave this device has
    // heard, at the position of the membership they left or an earlier one,
    // was issued before that leave reached its issuer — no list adding them
    // back names them anywhere but at its own, later position. It is taken
    // for everything else, and without them, on every device that heard the
    // leave, whichever came first: the same members everywhere, and the
    // leaver's own device out. It only ever takes someone out, so a send this
    // device queues afterwards — snapshotted from the list held — reaches
    // nobody who left (15.3). Its sender is not read so: a list was taken
    // from them because the held list has them in the group.
    if (existing != null && v0030) {
      final gone = <String>{
        for (final r in memberRids)
          if (r != sender &&
              existing.leftAt[r] != null &&
              Group.comparePos(
                      joined[r] ?? Group.origin, existing.leftAt[r]!) <=
                  0)
            r
      };
      memberRids.removeAll(gone);
      unknown.removeWhere((u) => gone.contains(u.$1));
      blockedEntries.removeWhere((r, _) => gone.contains(r));
      final myLeave = existing.leftAt[''];
      if (includesMe &&
          myLeave != null &&
          Group.comparePos(
                  myJoined ?? existing.epochs[''] ?? Group.origin, myLeave) <=
              0) {
        // And me, when the leave is mine: the list is taken here as on every
        // other device, without me. Out of the group, I stay out, and nothing
        // is said — every list issued before my leave used to show the group
        // as joined again, until a list without me — and the list I now hold
        // ranks the next one as theirs does, so a list adding me back that
        // lost to this one there does not bring me back here either. Back in
        // the group, added after my leave, a newer list from before the leave
        // takes me out as it does everyone else who left. My own devices
        // never add me back, so one of their lists can only be such a list,
        // and is not taken.
        if (mirroredOwn) return false;
        includesMe = false;
      }
    }
    // The positions the held list will name members at: the list's own, and
    // where it has no entry — for its sender writing from a linked device, or
    // for me in a list of my own from one — what was held.
    final joinedAt = <String, (int, int)>{
      for (final r in memberRids)
        if ((joined[r] ?? existing?.epochs[r]) case final at?
            when at != Group.origin)
          r: at,
    };
    final meAt = myJoined ?? existing?.epochs[''];
    if (includesMe && meAt != null && meAt != Group.origin) {
      joinedAt[''] = meAt;
    }

    if (!mirroredOwn && existing != null && !includesMe) {
      // The new list omits me: I was removed. It is still the list I hold —
      // version, issuer, roles and members — so that a later list is judged
      // against it, and the group's screen says who is in it now; except
      // that, as on a leave, a member whose contact I deleted is let go of
      // rather than introduced to me again ([_trimLeft]). A device that had
      // already left — a list from before my leave, taken without me (ADR
      // 0030) — holds it as well, and is told nothing: it was not removed.
      final wasLeft = existing.left;
      final deleted = existing.orphans.keys.toSet();
      existing
        ..name = list.name
        ..ver = list.ver
        ..by = sender
        ..rolesVer = list.rv
        ..ownerRid = owner
        ..digest = list.digest
        ..stateDigest = list.stateDigest
        ..tmr = list.tmr
        ..opensRoles = opens
        ..mine = null
        ..left = true;
      existing.adminRids
        ..clear()
        ..addAll(admins);
      existing.memberRids
        ..clear()
        ..addAll(memberRids);
      existing.epochs
        ..clear()
        ..addAll(joinedAt);
      _asked.remove(gid);
      final adopted = _adoptGroupContacts(
          [for (final u in unknown) if (!deleted.contains(u.$1)) u]);
      _trimLeft(existing);
      await _persistGroupContacts(adopted, txn: txn);
      await _saveGroups(txn: txn);
      if (!wasLeft) {
        await _insertSystemMessage(
            gid, systemBody(SystemKind.removedFrom, {'name': list.name}),
            txn: txn);
      }
      return true;
    }

    final isNew = existing == null;
    final oldName = existing?.name;
    final oldMembers = existing?.memberRids.toSet();
    final oldOwner = existing?.ownerRid;
    final oldAdmins = existing?.adminRids.toSet();
    final oldTimer = existing?.ttlSec ?? 0;
    final backIn = existing != null && existing.left && !mirroredOwn;
    // A list I issued, replaced by one that undoes it ([_undoes]): said
    // before the lines describing the new list, because it explains them.
    final mine =
        existing != null && existing.by.isEmpty ? existing.mine : null;
    final undone = mine != null &&
        _undoes(mine, memberRids, list.name, list.tmr ?? 0);
    // The members it introduces become contacts in the same step as the list
    // is installed, so nothing that reads the group — a send's fan-out, which
    // skips a member it holds no contact for — finds a member it cannot reach.
    final adopted = _adoptGroupContacts(unknown);
    groups[gid] = Group(
      gid: gid,
      name: list.name,
      ownerRid: owner,
      adminRids: admins,
      by: sender,
      rolesVer: list.rv,
      memberRids: memberRids,
      ver: list.ver,
      digest: list.digest,
      opensRoles: opens,
      held: existing?.held,
      orphans: {
        for (final e in existing?.orphans.entries ??
            const <MapEntry<String, Map<String, Object?>>>[])
          if ((memberRids.contains(e.key) || admins.contains(e.key)) &&
              !contacts.containsKey(e.key))
            e.key: e.value,
        ...blockedEntries,
      },
      // ADR 0030: the timer and the positions are the list's; the leaves
      // heard are this device's, and stay.
      tmr: list.tmr,
      stateDigest: list.stateDigest,
      epochs: joinedAt,
      leftAt: existing?.leftAt,
    );
    unread.putIfAbsent(gid, () => 0);
    _asked.remove(gid);
    // ADR 0020: a first group from an inviter whose group link I answered
    // is one a link promised. Which link, the list cannot say — it names no
    // link — so with one answer owed to them it is that one, and the answer
    // is settled; with several, each stays owed until its own window ends
    // (an inviter that has added me through one ignores that one's tag when
    // it comes again). Settled in this same step, so nothing can see the
    // group held while the answer still reads as owed.
    final owed = <String>[
      if (isNew && !mirroredOwn)
        for (final e in _linkJoins.entries)
          if (e.value.rid == fromRid && _linkNow() <= e.value.until) e.key
    ];
    final fromLink = owed.any((id) => _linkJoins[id]!.join);
    final settled = owed.length == 1 && _linkJoins.remove(owed.single) != null;
    // ---- End of the decision; what follows records it.

    await _persistGroupContacts(adopted, txn: txn);
    await _saveGroups(txn: txn);
    if (settled) await _saveLinks(txn: txn);
    final timer = list.tmr ?? 0;
    if (isNew) {
      await _insertSystemMessage(
          gid,
          mirroredOwn
              ? systemBody(SystemKind.createdYou, {'name': list.name})
              : systemBody(
                  fromLink ? SystemKind.addedFromLinkBy : SystemKind.addedToBy,
                  {'by': contacts[fromRid]?.name, 'name': list.name}),
          txn: txn);
      // ADR 0030: a group that has a timer says so to whoever arrives in it,
      // with the limit every timer notice in a group states.
      if (timer > 0) {
        await _insertSystemMessage(
            gid, systemBody(SystemKind.groupTtlIs, {'sec': timer}),
            txn: txn);
      }
      return true;
    }
    if (backIn) {
      // A list naming me in a group I am out of, and not one issued before
      // my leave (above): I was added back, and am told by whom.
      await _insertSystemMessage(
          gid,
          systemBody(SystemKind.addedToBy,
              {'by': contacts[fromRid]?.name, 'name': list.name}),
          txn: txn);
    }
    if (undone) {
      await _insertSystemMessage(
          gid,
          mirroredOwn
              ? systemBody(SystemKind.changeOverriddenMine)
              : systemBody(SystemKind.changeOverriddenBy,
                  {'by': contacts[fromRid]?.name}),
          txn: txn);
    }
    // A newer invite says what changed: the name, the members, the roles.
    // Each gets its own line, so a rename does not read as "membership
    // updated" and a membership change does not read as a rename (23.1).
    if (oldName != list.name) {
      await _insertSystemMessage(
          gid,
          mirroredOwn
              ? systemBody(SystemKind.renamedYou, {'name': list.name})
              : systemBody(SystemKind.renamedBy,
                  {'by': contacts[fromRid]?.name, 'name': list.name}),
          txn: txn);
    }
    if (oldMembers == null ||
        oldMembers.length != memberRids.length ||
        !oldMembers.containsAll(memberRids)) {
      await _insertSystemMessage(gid, systemBody(SystemKind.membershipUpdated),
          txn: txn);
    }
    // ADR 0030: the timer, as a 1:1 chat says it — with, in a group, what a
    // member on an older version does with it. A list that turned it off by
    // saying `0` is said as that; one that turned it off by carrying no
    // timer at all is from an admin whose app predates group timers, or that
    // had not heard of this one, and is said as what it did.
    // Back in the group, I am told of a timer it has now as a newcomer is,
    // and of nothing that changed while I was out.
    if (backIn) {
      if (timer > 0 && timer != oldTimer) {
        await _insertSystemMessage(
            gid, systemBody(SystemKind.groupTtlIs, {'sec': timer}),
            txn: txn);
      }
    } else if (timer != oldTimer) {
      final by = contacts[fromRid]?.name;
      await _insertSystemMessage(
          gid,
          timer > 0
              ? (mirroredOwn
                  ? systemBody(SystemKind.groupTtlSetYou, {'sec': timer})
                  : systemBody(
                      SystemKind.groupTtlSetBy, {'by': by, 'sec': timer}))
              : mirroredOwn
                  ? systemBody(SystemKind.ttlOffYou)
                  : list.tmr == 0
                      ? systemBody(SystemKind.ttlOffThem, {'name': by})
                      : systemBody(SystemKind.groupTtlDroppedBy, {'by': by}),
          txn: txn);
    }
    await _sayRoleChanges(gid, fromRid, mirroredOwn,
        oldOwner: oldOwner!,
        oldAdmins: oldAdmins!,
        owner: owner,
        admins: admins,
        members: memberRids,
        txn: txn);
    await _retryHeldBack(gid, txn: txn);
    return true;
  }

  /// Contacts an accepted list introduced, made known in memory at once —
  /// synchronously, in the step that installs the list — and returned for
  /// [_persistGroupContacts] to write. One added meanwhile by other means
  /// is left as it is.
  List<Contact> _adoptGroupContacts(
      List<(String, ContactBundle, String)> unknown) {
    final adopted = <Contact>[];
    for (final (rid, bundle, cname) in unknown) {
      if (contacts.containsKey(rid)) continue;
      final c =
          Contact(rid: rid, bundle: bundle, name: cname, createdMs: _now());
      contacts[rid] = c;
      _sealKeys[rid] = bundle.xPub;
      messagesByChat.putIfAbsent(rid, () => []);
      unread.putIfAbsent(rid, () => 0);
      adopted.add(c);
    }
    return adopted;
  }

  /// Write the contacts [_adoptGroupContacts] made known.
  Future<void> _persistGroupContacts(List<Contact> adopted,
      {DatabaseExecutor? txn}) async {
    for (final c in adopted) {
      await (txn ?? vault.db).insert(
          'contacts',
          {
            'rid': c.rid,
            'enc_bundle': await vault.seal(jsonEncode(c.bundle.toJson())),
            'enc_name': await vault.seal(c.name),
            'ttl_seconds': 0,
            'verified': 0,
            'created_ms': c.createdMs,
          },
          conflictAlgorithm: ConflictAlgorithm.ignore);
    }
  }

  /// One line per role that changed between the held list and the accepted
  /// one (ADR 0019): who owns the group now, who became an admin, who
  /// stopped being one — as "you" for my own action mirrored from my other
  /// device, and as "{by} …" for a list that arrived. A member the list
  /// removed is not also said to be demoted: the removal covers it.
  Future<void> _sayRoleChanges(String gid, String fromRid, bool mirroredOwn,
      {required String oldOwner,
      required Set<String> oldAdmins,
      required String owner,
      required Set<String> admins,
      required Set<String> members,
      DatabaseExecutor? txn}) async {
    final by = contacts[fromRid]?.name;
    String? nameOf(String rid) => contacts[rid]?.name;
    Future<void> say(String kind, Map<String, Object?> params) =>
        _insertSystemMessage(gid, systemBody(kind, params), txn: txn);
    if (owner != oldOwner) {
      if (mirroredOwn) {
        await say(SystemKind.transferredYou, {'name': nameOf(owner)});
      } else if (owner.isEmpty) {
        await say(SystemKind.ownerMeBy, {'by': by});
      } else {
        await say(SystemKind.ownerBy, {'by': by, 'name': nameOf(owner)});
      }
    }
    for (final rid in admins.difference(oldAdmins)) {
      if (rid == owner && owner != oldOwner) continue; // said above
      if (mirroredOwn) {
        await say(SystemKind.promotedYou, {'name': nameOf(rid)});
      } else if (rid.isEmpty) {
        await say(SystemKind.promotedMeBy, {'by': by});
      } else {
        await say(SystemKind.promotedBy, {'by': by, 'name': nameOf(rid)});
      }
    }
    for (final rid in oldAdmins.difference(admins)) {
      if (rid.isNotEmpty && !members.contains(rid)) continue; // removed
      if (mirroredOwn) {
        // My own list: a transfer that let go of my role says so above,
        // and nothing else of mine demotes me.
        if (rid.isNotEmpty) {
          await say(SystemKind.demotedYou, {'name': nameOf(rid)});
        }
      } else if (rid.isEmpty) {
        await say(SystemKind.demotedMeBy, {'by': by});
      } else if (rid == fromRid) {
        await say(SystemKind.steppedDown, {'name': by});
      } else {
        await say(SystemKind.demotedBy, {'by': by, 'name': nameOf(rid)});
      }
    }
  }

  /// Persist an inbound group text from [contact] (any of their devices).
  ///
  /// A `ttl` on it (ADR 0030: the group's timer, as its sender's list had it)
  /// is kept as §6.1 says, from its receipt here — whichever door it came
  /// in by, since this is the step every one of them takes.
  Future<void> _persistGroupText(Contact contact, InnerMessage inner, int now,
      {DatabaseExecutor? txn}) async {
    final gid = inner.data['gid'] as String?;
    final g = gid == null ? null : groups[gid];
    // Unknown group or non-member sender (e.g. removed): drop silently.
    if (g == null || g.left || !g.memberRids.contains(contact.rid)) return;
    final body = inner.data['body'] as String? ?? '';
    final expireAt = _groupExpiry(inner);
    final quoted = await _resolveQuote(gid!, inner.replyTo, txn: txn);
    final inserted = await (txn ?? vault.db).insert(
        'messages',
        {
          'mid': inner.mid,
          'rid': gid,
          'outgoing': 0,
          'kind': 'gtext',
          // 'sr' (8.1c): WHO sent it. Display names are not identity, and a
          // group edit/delete has to be checked against the sender's rid.
          'enc_body': await vault.seal(
              jsonEncode({'b': body, 'sn': contact.name, 'sr': contact.rid})),
          'ts_ms': now,
          'status': MsgStatus.delivered,
          'expire_at_ms': expireAt,
          'reply_to': quoted?.mid,
          'forwarded': inner.data['fw'] == true ? 1 : 0,
        },
        conflictAlgorithm: ConflictAlgorithm.ignore);
    _appendLoaded(
        gid,
        ChatMessage(
          mid: inner.mid,
          rid: gid,
          outgoing: false,
          kind: 'gtext',
          forwarded: inner.data['fw'] == true,
          body: body,
          ts: now,
          status: MsgStatus.delivered,
          expireAtMs: expireAt,
          senderName: contact.name,
          replyTo: quoted?.mid,
          quote: quoted,
        ));
    // Once per message (30.3). A linked device holds a member's message twice
    // over — from the member, and mirrored by my other device — and counted
    // it unread each time, so every group message showed as two there.
    if (inserted != 0 && openChatRid != gid) {
      unread[gid] = (unread[gid] ?? 0) + 1;
    }
  }

  /// A member told us (over their authenticated channel) that they left.
  ///
  /// A leave takes the member out of this device's copy of the list and
  /// nothing else: the version and the issuer stay as they were, and so do
  /// the roles (ADR 0019 — only an owner's list changes those; an admin who
  /// left cannot use the role from outside, see [mayIssueGroupList]).
  ///
  /// Until 23.1b the admin moved the version on here, so that "future
  /// invites exclude them". With one admin that changed nothing — the
  /// admin's next list moved it anyway. With several it breaks the order the
  /// `(ver, by)` rule depends on: admins would hold the same list one
  /// version ahead of the members, so a co-admin who had not yet seen the
  /// leave and changed the group at that version would be refused by every
  /// admin and accepted by every member, and the owner's next list would
  /// then undo the change everywhere without a word (group_roles_test 9).
  ///
  /// ADR 0030: and the leave is remembered ([Group.leftAt]) at the position
  /// of the membership it ends — the one it states (`e`), or, from a build
  /// before 0030, the one held for them — so a list issued before it
  /// reached its issuer, which still names them there, is taken without them
  /// ([_applyGroupInvite]). A leave stating an earlier position than the one
  /// held ends a membership that a list adding them back has since replaced
  /// here: remembered, and they stay. Remembered for someone this device
  /// holds out of the group too, when it has known them in it — a leave
  /// after a re-add it never got — and not for anyone else, so nobody can
  /// plant a leave for a group they were never in.
  Future<void> _applyGroupLeave(String fromRid, Map<String, Object?> data,
      {DatabaseExecutor? txn}) async {
    final gid = data['gid'];
    final g = gid is String ? groups[gid] : null;
    if (g == null) return;
    final member = g.memberRids.contains(fromRid);
    if (!debugBuildBefore0030 &&
        (member ||
            g.epochs.containsKey(fromRid) ||
            g.leftAt.containsKey(fromRid))) {
      // ADR 0030: the membership a leave ends is the one it states (`e`,
      // which every client since 0030 writes) — or, for a leave from a build
      // before it, which states none, the one I hold them in.
      final held = member ? g.epochs[fromRid] ?? Group.origin : null;
      final ends = Group.posFrom(data['e']) ?? held ?? Group.origin;
      final prev = g.leftAt[fromRid];
      final at = prev == null ? ends : Group.laterPos(prev, ends);
      final noted = prev != at;
      g.leftAt[fromRid] = at;
      if (held != null && Group.comparePos(ends, held) < 0) {
        // A leave of a membership before the one I hold them in: the list
        // adding them back reached me before it did. It is remembered — a
        // list from before it is still read as one — and they stay, as on
        // every device that heard the two the other way round.
        if (noted) await _saveGroups(txn: txn);
        return;
      }
      g.epochs.remove(fromRid);
      if (noted && !member) await _saveGroups(txn: txn);
    }
    if (!g.memberRids.remove(fromRid)) return;
    // Someone my last list added has gone of their own accord: a later list
    // without them undoes nothing of mine.
    final added = g.mine?['add'];
    if (added is List) added.remove(fromRid);
    // An admin who left is still named in `admins`, and an entry marks
    // them as someone whose contact I deleted until it is not ([_trimLeft]).
    if (!g.adminRids.contains(fromRid)) g.orphans.remove(fromRid);
    _asked.remove(g.gid);
    await _saveGroups(txn: txn);
    await _insertSystemMessage(g.gid,
        systemBody(SystemKind.memberLeft, {'name': contacts[fromRid]?.name}),
        txn: txn);
    // A co-admin's list that took this member out — they were an admin, and
    // the list could not be told from a co-admin removing one — can be
    // applied now.
    await _retryHeldBack(g.gid, txn: txn);
  }

  // ---- M4: contact device-list distribution + fan-out --------------------

  Future<int> _myDevlistVersion() async =>
      int.tryParse(await vault.kvGet('my_devlist_version') ?? '1') ?? 1;

  /// Every device of MY account (this device + linked ones), as a list this
  /// account signs carries them: each linked device's certificate with the
  /// proof of possession it handed the root, where it has (ADR 0022,
  /// [_applyDevicePop]) — and this device's own with its own, where this is
  /// a linked device ([AccountIdentity.provenDeviceCert]).
  Future<List<DeviceCertificate>> myFullDeviceList() async =>
      [await _ownPresentedCert(), ...await _myDevices()];

  DeviceCertificate? _ownCertMemo;

  /// This device's certificate as it presents it: with its proof of
  /// possession unless its key is the account key (device #1, which needs
  /// none) or it models a build from before ADR 0022. Memoised: the proof is
  /// a signature, and this is asked on every install's check.
  Future<DeviceCertificate> _ownPresentedCert() async {
    final me = await accountIdentity();
    if (me.isAccountKeyDevice || debugNoDevicePop) return me.deviceCert;
    final memo = _ownCertMemo;
    if (memo != null &&
        constantTimeEquals(memo.deviceEdPub, me.deviceCert.deviceEdPub) &&
        constantTimeEquals(memo.sig, me.deviceCert.sig)) {
      return memo;
    }
    return _ownCertMemo = await me.provenDeviceCert();
  }

  /// Tell every contact my current device set (account-signed) so they fan
  /// messages out to all my devices and accept from any of them.
  /// Tell every contact my current device set (account-signed). [alsoOwnDevices]
  /// drives 7.7a rule 8 — self-syncing the same signed list to my own other
  /// devices so they always know the latest legitimate version. It defaults to
  /// true and the app never turns it off; the flag exists so a split-view
  /// adversary (which by definition keeps the owner's devices in the dark) can
  /// be modelled in tests.
  Future<void> broadcastMyDeviceList({bool alsoOwnDevices = true}) async {
    final data = await _signCurrentDeviceList();
    if (data == null) return; // only a root-holding device can sign
    // 7.7a root discipline (rule 8): my own other devices must always know the
    // latest legitimate version, so a rogue enrolment shows up as a version
    // they never saw. Self-sync the signed list to them before (or with) the
    // contacts. No-op when nothing is linked.
    if (alsoOwnDevices) await _selfSyncDeviceList(data);
    for (final rid in contacts.keys.toList()) {
      final contact = contacts[rid];
      if (contact == null) continue;
      await _sendInner(contact, _devlistInner(data));
    }
  }

  /// How long the first start after a restore waits for the transparency log
  /// before it re-asserts the account without it (see
  /// [_resumeAfterRestore]).
  @visibleForTesting
  static Duration restoreLogTimeout = const Duration(seconds: 20);

  /// Phase 31: the first start after a restore (`BackupArchive.resumeKey`,
  /// set by the `.zbk` and the `.zid` import alike) re-asserts this account
  /// before anything is sent — called from [init] ahead of every path that
  /// signs, encrypts or sends.
  ///
  /// A restored device is the same account, and until this it did not say
  /// so. It came back holding none of the account's device-list state, so a
  /// root signed version 1 again: its own log monitor met the versions it had
  /// signed before the backup and called them lists it never issued ("reset
  /// your identity now"), its contacts saw its devices claim a version below
  /// one they had already seen from them (a rollback), and the next device
  /// it linked landed on a version the log already held — every start, and
  /// every six hours (the 2026-10-03 analysis, P0-3). The archive now
  /// carries that state, and this is the other half: the version the
  /// restored device signs first is above everything the account has
  /// published, whenever the archive was taken.
  ///
  /// A root ([_resumeRoot]) signs at max(the log's latest, what the archive
  /// held) + 1; a linked device ([_resumeLinked]) adopts the account's
  /// newest list if it still names this device. Either way the log is asked
  /// first, bounded by [restoreLogTimeout]; a log that cannot be asked
  /// leaves only what the archive knew. The key is cleared once this has
  /// run, and left for the next start if it threw.
  Future<void> _resumeAfterRestore() async {
    if (await vault.kvGet(BackupArchive.resumeKey) == null) return;
    try {
      final me = await accountIdentity();
      if (me.holdsAccountRoot) {
        await _resumeRoot(me);
      } else {
        await _resumeLinked(me);
      }
      await vault.kvDelete(BackupArchive.resumeKey);
    } catch (_) {
      // The flag stays: the next start tries again. What this start does
      // without it is what every start did before phase 31.
    }
  }

  /// What the log holds for [account], or null — waited for at most
  /// [restoreLogTimeout].
  Future<KtOwnRecord?> _logRecordFor(Uint8List account) =>
      kt.ownRecord(account).timeout(restoreLogTimeout, onTimeout: () => null);

  /// A restored root: one new list, signed above every version the account
  /// has published, over the devices the archive knew that the account's
  /// newest list still names — and then to its own devices and to every
  /// contact, through the outbox, which nothing empties until the transport
  /// starts after [init] returns.
  ///
  /// The versions the log holds that the archive does not know were signed
  /// between the backup and the restore — by the device that was lost, or by
  /// someone else holding the account's root key; a restore cannot tell
  /// which. Each one that opens and verifies as this account's list is
  /// recorded as its own, so the monitor does not report the user's own
  /// history to them as an attack; the list signed here supersedes them all.
  /// One that does not open as this account's list is left unknown, and the
  /// monitor says so — an honest device never publishes one. A removal made
  /// after the backup stands: a device the newer list dropped is not put
  /// back. A device added after it is not adopted: the archive never knew
  /// it, and it is linked again from here if it was the user's (THREAT_MODEL
  /// R45).
  Future<void> _resumeRoot(AccountIdentity me) async {
    // A moved account stays moved ([_signsV2Only]): decided from what the
    // archive brought, before anything is signed.
    final ownJson = await vault.kvGet('own_list_json');
    var ownV2Only = false;
    if (ownJson != null) {
      try {
        ownV2Only = SignedDeviceList.fromJson(
                (jsonDecode(ownJson) as Map).cast<String, Object?>())
            .isV2Only;
      } catch (_) {}
    }
    if (ownV2Only || await vault.kvGet('devlist_v2only_migrated') == '1') {
      _signsV2Only = true;
    }
    var held = await _myDevlistVersion();
    final ownV = int.tryParse(await vault.kvGet('own_list_v') ?? '');
    if (ownV != null && ownV > held) held = ownV;
    for (final v in kt.knownOwnVersions) {
      if (v > held) held = v;
    }
    var top = held;
    SignedDeviceList? newer;
    final record = await _logRecordFor(me.accountEdPub);
    if (record != null) {
      final latest = record.latest;
      // A moved account stays moved even when the archive cannot say so — one
      // written before format 1.1 carries no list at all — because the log's
      // newest list, verified as this account's, does.
      if (latest?.list?.isV2Only ?? false) _signsV2Only = true;
      // An entry the device the backup was taken on had already reported as
      // one it never issued stays reported: the restore carried that alert,
      // and the entry is not the restored device's to absolve.
      final flagged = kt.ownAlert;
      for (final e in [...record.history, if (latest != null) latest]) {
        if (e.list == null || kt.knownOwnFingerprint(e.version) != null) {
          continue;
        }
        if (flagged != null &&
            flagged.version == e.version &&
            flagged.fpB64 == e.fpB64) {
          continue;
        }
        await kt.recordOwnList(e.version, e.fpB64);
      }
      if (latest != null) {
        if (latest.version > top) top = latest.version;
        if (latest.version > held) newer = latest.list;
      }
    }
    final keep = newer == null
        ? null
        : {for (final d in newer.devices) b64(d.deviceEdPub)};
    await _withOwnListLock(() async {
      if (keep != null) {
        final devices = [
          for (final d in await _myDevices())
            if (keep.contains(b64(d.deviceEdPub))) d
        ];
        await vault.kvPut(
            'my_devices', jsonEncode([for (final d in devices) d.toJson()]),
            sensitive: false);
      }
      await vault.kvPut('my_devlist_version', '${top + 1}', sensitive: false);
      _forgetOwnListClaim();
    });
    if (keep != null) await _initSync(); // the device set changed
    final data = await _signCurrentDeviceList();
    if (data == null) {
      throw StateError('a restored root could not sign its device list');
    }
    // Awaited, so these are the first rows in the outbox: the list reaches a
    // contact no later than the first message that claims it. The self-sync
    // also opens a fresh session with each of this account's own devices,
    // which is what lets them reach this one again.
    await _selfSyncDeviceList(data);
    for (final rid in contacts.keys.toList()) {
      final c = contacts[rid];
      if (c == null) continue;
      try {
        await _sendInner(c, _devlistInner(data));
      } catch (_) {
        // Delivered by the self-healing path instead: a contact whose echo
        // is behind is handed the list on its next message.
      }
    }
  }

  /// A restored linked device: it signs nothing (it holds no root), so it
  /// cannot publish anything either. What it does is catch up — the
  /// account's newest list from the log, if it is newer than the archive's
  /// and still names this device; and if it does not, this device was
  /// removed after the backup, and it says so (the "this device was removed"
  /// alarm, whose remedy is linking it again). Then it asks its root for the
  /// list, which also opens a fresh session with each of the account's
  /// devices.
  Future<void> _resumeLinked(AccountIdentity me) async {
    var held = await _myDevlistVersion();
    final ownV = int.tryParse(await vault.kvGet('own_list_v') ?? '');
    if (ownV != null && ownV > held) held = ownV;
    final record = await _logRecordFor(me.accountEdPub);
    final latest = record?.latest;
    final list = latest?.list;
    if (latest != null && list != null && latest.version > held) {
      final mine = list.devices
          .any((d) => constantTimeEquals(d.deviceEdPub, me.deviceEdPub));
      if (mine) {
        final others = [
          for (final d in list.devices)
            if (!constantTimeEquals(d.deviceEdPub, me.deviceEdPub)) d
        ];
        await _withOwnListLock(() async {
          await vault.kvPut(
              'my_devices', jsonEncode([for (final d in others) d.toJson()]),
              sensitive: false);
          await vault.kvPut('my_devlist_version', '${list.version}',
              sensitive: false);
          _forgetOwnListClaim();
        });
        await _recordOwnList(list);
        await _initSync();
        await _withdrawClaimsOnMine();
      } else if (await _isRemovalEvidence(list)) {
        // Raised as every removal banner is (ADR 0026): on the list that
        // omits this device, above a version it learned, and kept with that
        // evidence, so dismissing it holds across restarts.
        await _raiseRemoved(latest.version, latest.fpB64);
      }
    }
    await _requestOwnDeviceList();
  }

  /// ADR 0010: on the first start after upgrade, re-sign this account's device
  /// list once under the v2 format so its post-quantum signature covers the
  /// devices' ratchet keys and its fingerprint moves onto the v2 format in the
  /// log. Only a root device re-signs (a linked device receives the v2 list by
  /// self-sync, 7.7a rule 8). The version is bumped so the v2 fingerprint lands
  /// at a NEW version — the old v1 entry keeps its own version and fingerprint
  /// in the log, so there is no same-version conflict and no false transparency
  /// alarm, and the device set itself is unchanged. Runs once, gated by a vault
  /// flag and an in-memory guard; called from [init] before the transport and
  /// the log check start, so nothing else re-signs at the old version first.
  bool _v2MigrationDone = false;
  Future<void> _migrateDeviceListToV2() async {
    if (_v2MigrationDone) return;
    if (await vault.kvGet('devlist_v2_migrated') == '1') {
      _v2MigrationDone = true;
      return;
    }
    final me = await accountIdentity();
    if (!me.holdsAccountRoot) {
      _v2MigrationDone = true;
      await vault.kvPut('devlist_v2_migrated', '1', sensitive: false);
      return;
    }
    // Only an existing v1 list needs moving. A device that has never signed a
    // list (a fresh account) signs a v2 one the first time it does — there is
    // nothing published at an old version to conflict with — and a list we
    // already hold as v2 is done: dual-signed, or v2-only (ADR 0017 stage 2,
    // whose `sig3` covers what `sig2` does). All just mark the migration
    // complete.
    final ownJson = await vault.kvGet('own_list_json');
    SignedDeviceList? own;
    if (ownJson != null) {
      try {
        own = SignedDeviceList.fromJson(
            (jsonDecode(ownJson) as Map).cast<String, Object?>());
      } catch (_) {}
    }
    if (own == null || own.sig2 != null || own.sig3 != null) {
      _v2MigrationDone = true;
      await vault.kvPut('devlist_v2_migrated', '1', sensitive: false);
      return;
    }
    _v2MigrationDone = true; // set before the awaits so nothing re-enters
    await _withOwnListLock(() async {
      final cur = await _myDevlistVersion();
      await vault.kvPut('my_devlist_version', '${cur + 1}', sensitive: false);
      _forgetOwnListClaim();
    });
    // Sign + record + queue the log publish now (local and durable) so the rest
    // of start-up sees the v2 state; hand it to my devices and contacts in the
    // background through the durable outbox.
    final data = await _signCurrentDeviceList();
    await vault.kvPut('devlist_v2_migrated', '1', sensitive: false);
    if (data != null) {
      unawaited(_selfSyncDeviceList(data).then((_) {}, onError: (_) {}));
      for (final rid in contacts.keys.toList()) {
        final c = contacts[rid];
        if (c == null) continue;
        unawaited(
            _sendInner(c, _devlistInner(data)).then((_) {}, onError: (_) {}));
      }
    }
  }

  /// ADR 0017 stage 2b: whether this build moves an account that has not
  /// moved to v2-only signing (`sig3` alone) — once its gate is open (ADR
  /// 0029, [devlistGate]). Set from `init`'s `signDevlistV2Only`, which is the
  /// protocol's [devlistSignV2Only] — on — unless a test starts this one
  /// account as a build with the kill switch thrown. Whether an account that
  /// HAS moved keeps signing v2-only is not this switch's to say: see
  /// [_signsV2Only].
  bool _signerV2Only = devlistSignV2Only;

  /// The stage-2b signer as this service was started with it.
  @visibleForTesting
  bool get debugDevlistSignV2Only => _signerV2Only;

  /// True once this account has been moved to a version it signs with `sig3`
  /// alone — by this build or by any earlier one, as the vault records — and
  /// from then on every list this root signs is v2-only. Never true before the
  /// move, even with the signer on, and never false after it, even with the
  /// signer off: in both directions so that no version this device has signed
  /// is ever signed again the other way. A version keeps the fingerprint it
  /// was first published with (PROTOCOL §19.8).
  bool _signsV2Only = false;

  /// ADR 0029: the device-list shape each device of each contact last said it
  /// reads — contact rid → device rid → the `dlr` its last decorated message
  /// carried ([devlistReaderLevel] for a build from that ADR on; 0 for one
  /// that decorates its messages, 7.7a's `dl`, and does not say). A device
  /// that has said nothing is absent, and counts as unable to read a v2-only
  /// list until it does. Sealed in the vault as `cdl_dlr_<rid>`, written only
  /// when a device's answer changes.
  final Map<String, Map<String, int>> _readerLevels = {};

  /// The same for this account's other devices, from what each sends on the
  /// self-sync channel (`own_dlr`, sealed).
  final Map<String, int> _ownReaderLevels = {};

  /// Whether the list this device holds for its own account is v2-only — on
  /// a root, the same as [_signsV2Only]; on a linked device, what its root
  /// last self-synced. Kept in memory because the outbound path reads it.
  bool _ownV2Only = false;

  /// A move in progress ([_maybeMoveToV2Only]), so that two observations
  /// arriving together start one.
  bool _moving = false;

  /// Whether this run has told its own devices what it reads
  /// ([DeviceSyncService.announce]).
  bool _announcedReader = false;

  /// Test-only: behave like a client from before ADR 0029 — never say which
  /// device-list shape this device reads, to contacts or to its own devices,
  /// and never move its own account (that build's signer was off; an
  /// account it finds moved stays moved, as on any build from 3.9.9). Every
  /// client from 3.9.9 on reads a v2-only list; one from before ADR 0029
  /// does so in silence, and the gate below has to be met by — and wait for
  /// — exactly that. Set through `ChatService.init`, so that not even the
  /// first ping a start sends says otherwise.
  @visibleForTesting
  bool debugPreAdr0029 = false;

  /// Test-only, from `init`'s `debugMoveUngated`: the move waits on the kill
  /// switch alone, as it did before ADR 0029 — at the first start with the
  /// signer on. For the tests of what the move does (ADR 0017's), which
  /// give an account readers that never speak: a linked device that is only
  /// a certificate, a contact never heard from.
  bool _debugMoveUngated = false;

  /// What [inner], from one device, says about that device's build (ADR
  /// 0029): its `dlr`; 0 when it carries 7.7a's claim `dl` and no `dlr` (a
  /// build that decorates what it sends and does not say); null when it
  /// carries neither — a message nobody decorated (a removal notice, or one
  /// whose decoration failed) says nothing either way.
  static int? _readerLevelOf(InnerMessage inner) {
    final r = inner.data['dlr'];
    if (r is num && r.isFinite) return r.toInt();
    if (inner.data.containsKey('dl')) return 0;
    return null;
  }

  /// Records what [inner] from [deviceRid], one of [rid]'s devices, says it
  /// reads, and re-checks the gate when that device has just said it reads a
  /// v2-only list. Best-effort and silent: it runs on every inbound path and
  /// must never be the reason one fails.
  Future<void> _noteReaderLevel(
      String rid, String deviceRid, InnerMessage inner) async {
    final level = _readerLevelOf(inner);
    if (level == null || !contacts.containsKey(rid)) return;
    final levels = _readerLevels.putIfAbsent(rid, () => {});
    if (levels[deviceRid] == level) return;
    levels[deviceRid] = level;
    try {
      await vault.kvPut('cdl_dlr_$rid', jsonEncode(levels));
    } catch (_) {
      // Kept in memory; written again with the next change, and said again
      // by every message that device sends.
    }
    notifyListeners();
    if (level >= devlistReaderLevel) unawaited(_maybeMoveToV2Only());
  }

  /// The same for [deviceRid], one of this account's own devices, from an
  /// envelope on the self-sync channel.
  Future<void> _noteOwnReaderLevel(String deviceRid, int level) async {
    if (_ownReaderLevels[deviceRid] == level) return;
    _ownReaderLevels[deviceRid] = level;
    try {
      await vault.kvPut('own_dlr', jsonEncode(_ownReaderLevels));
    } catch (_) {}
    notifyListeners();
    if (level >= devlistReaderLevel) unawaited(_maybeMoveToV2Only());
  }

  /// Every device of [rid]'s account this device holds: the one they were
  /// added from, and each other device their installed list names — the
  /// devices this account's lists go to, and so the ones that read them.
  Map<String, List<String>> _contactDevices() {
    final out = <String, List<String>>{
      for (final rid in contacts.keys) rid: [rid]
    };
    for (final e in _extraRidToContact.entries) {
      out[e.value]?.add(e.key);
    }
    return out;
  }

  /// The same for one contact, [rid].
  Iterable<String> _devicesOf(String rid) sync* {
    yield rid;
    for (final e in _extraRidToContact.entries) {
      if (e.value == rid) yield e.key;
    }
  }

  /// Whether this build moves an account (ADR 0029): the kill switch allows
  /// it, and it is not running as a build from before the move existed.
  bool get _moveAllowed => _signerV2Only && !debugPreAdr0029;

  /// ADR 0029: where this account stands on the way to v2-only signing —
  /// for Settings' developer view, and the test of the gate itself.
  DevlistGate get devlistGate {
    var devices = 0, behind = 0;
    for (final e in _contactDevices().entries) {
      final levels = _readerLevels[e.key];
      for (final d in e.value) {
        devices++;
        if ((levels?[d] ?? 0) < devlistReaderLevel) behind++;
      }
    }
    final own = _sync?.deviceRoutingIds ?? const <String>{};
    var ownBehind = 0;
    for (final d in own) {
      if ((_ownReaderLevels[d] ?? 0) < devlistReaderLevel) ownBehind++;
    }
    return DevlistGate(
      moved: _holdsRoot ? _signsV2Only : _ownV2Only,
      decides: _holdsRoot,
      moveAllowed: _moveAllowed,
      contacts: contacts.length,
      contactDevices: devices,
      contactDevicesBehind: behind,
      ownDevices: own.length,
      ownDevicesBehind: ownBehind,
    );
  }

  /// ADR 0029: this account's lists are v2-only and one of [rid]'s devices
  /// has said — by what it sends — that it is an older build, which may not
  /// read them (one older than 3.9.9 cannot). The contact's screen says so;
  /// it is a fact about their app, not an alarm about either of you. A
  /// device that has said nothing yet — a contact just added — is not
  /// counted here: its first message says, and almost always says it can.
  bool readerBehind(String rid) {
    if (!_ownV2Only || !contacts.containsKey(rid)) return false;
    final levels = _readerLevels[rid];
    if (levels == null) return false;
    for (final d in _devicesOf(rid)) {
      final l = levels[d];
      if (l != null && l < devlistReaderLevel) return true;
    }
    return false;
  }

  /// Whether this device leaves its claim about its own list (7.7a's `dl`)
  /// off what it sends [rid] (ADR 0029): its account's lists are v2-only and
  /// none of [rid]'s devices has said it reads one. A claim names a list such
  /// a device may be unable to read, and a build that cannot read it turns
  /// "a claim above the list I hold" into "their device list changed and the
  /// update never arrived". Made again as soon as one of their devices says
  /// it reads a v2-only list — and never withheld from a contact one of whose
  /// devices has said so, whose record of the claim has to stay current.
  bool _withholdsClaimFrom(String rid) {
    if (!_ownV2Only) return false;
    final levels = _readerLevels[rid];
    if (levels == null) return true;
    for (final d in _devicesOf(rid)) {
      if ((levels[d] ?? 0) >= devlistReaderLevel) return false;
    }
    return true;
  }

  /// ADR 0029, per device: whether this account's `dl` claim is withheld from
  /// [deviceRid] — one of [rid]'s devices — because this account signs
  /// v2-only and THAT device has not said it reads a v2-only list. The
  /// per-contact [_withholdsClaimFrom] withholds only when NONE of a contact's
  /// devices has said so; this one leaves an incapable SIBLING of a capable
  /// contact out of the fan too. Without it the claim named a list that sibling
  /// cannot read, and the sibling, holding an older list, turned "a claim above
  /// the list I hold" into [DevlistAlertKind.missingUpdate] after the grace —
  /// the exact false alarm the withhold exists to suppress, raised on a device
  /// the per-contact rule could not see because a capable sibling spoke for the
  /// whole contact.
  bool _withholdsClaimFromDevice(String rid, String deviceRid) =>
      _ownV2Only && (_readerLevels[rid]?[deviceRid] ?? 0) < devlistReaderLevel;

  /// Test seam: what [deviceRid], one of [rid]'s devices, last said it reads
  /// (ADR 0029); null for a device that has said nothing.
  @visibleForTesting
  int? debugReaderLevel(String rid, String deviceRid) =>
      _readerLevels[rid]?[deviceRid];

  /// Test seam: the same for one of this account's own devices.
  @visibleForTesting
  int? debugOwnReaderLevel(String deviceRid) => _ownReaderLevels[deviceRid];

  /// ADR 0029: the move to v2-only signing, now, if this root's gate is open
  /// — called whenever something the gate reads has changed in the gate's
  /// favour: a device has said it reads a v2-only list, a contact or a
  /// device has gone, a contact's list has changed. One at a time.
  Future<void> _maybeMoveToV2Only() async {
    if (_moving || _signsV2Only || !_moveAllowed || !_holdsRoot) return;
    if (_disposed) return;
    _moving = true;
    try {
      await _migrateDeviceListToV2Only();
    } catch (_) {
      // Nothing moved that was not recorded; the next change in the gate's
      // favour, or the next start, tries again.
    } finally {
      _moving = false;
    }
  }

  /// ADR 0017 stage 2b: the one-time republish when the v2-only signer is on —
  /// [_migrateDeviceListToV2] once more, a stage later, for the same reasons.
  ///
  /// ADR 0029 decides WHEN: at start-up and at the moment anything it reads
  /// changes ([_maybeMoveToV2Only]), a root moves once its gate is open
  /// ([DevlistGate.open]) — it holds a contact and has a linked device, and
  /// every device of every contact and every one of its own linked devices
  /// has said it reads a v2-only list. Until then nothing moves, with the
  /// signer on or off; a reader that cannot read the list it would sign has
  /// not been heard to say it can.
  ///
  /// Once the gate is open, a root moves its account's list to
  /// the NEXT version and signs it there with `sig3` alone, then hands it to
  /// its own devices, to every contact and to the log by the paths a new
  /// device's list takes. The version moves rather than the current one being
  /// re-signed because a version keeps the fingerprint it was published with:
  /// the old (version, v1 fingerprint) stays in the log and in this device's
  /// record of its own lists, the v2-only list lands at a version nobody has
  /// seen, and the self-monitor, which accepts any (version, fingerprint) this
  /// device recorded as its own ([_recordOwnList]), sees one expected change
  /// and nothing it did not issue — exactly how the 0010 migration got past it.
  /// To a contact it is an ordinary device-list update.
  ///
  /// Every root moves, one that has never signed a list included, so the
  /// first v2-only list is never version 1. Version 1 is the baseline a
  /// contact computes for itself, over the v1 input, from the one device in
  /// the code it scanned; a v2-only list at version 1 would claim a
  /// fingerprint over a device id that code does not carry, and the gossip
  /// would read the mismatch as the account's devices disagreeing.
  ///
  /// Once, by a vault flag. A linked device signs nothing and has nothing to
  /// move.
  ///
  /// The vault decides before the constant does. An account that has moved
  /// stays moved on a build with the signer off — one that turns the
  /// constant back, a downgrade to this release, a post-flip backup restored
  /// onto it — because the alternative is worse than any revert could want:
  /// that build would re-sign the account's current version dual-signed,
  /// giving the version a second fingerprint, and every contact holding the
  /// v2-only list would raise a split alarm while the account's own monitor
  /// flagged its own genuine entry. Only the move itself waits on the
  /// constant; with the signer off and no move recorded — every account
  /// until the constant flips — this reads two rows and changes nothing.
  Future<void> _migrateDeviceListToV2Only() async {
    if (_signsV2Only) return;
    final me = await accountIdentity();
    if (!me.holdsAccountRoot) return;
    if (await vault.kvGet('devlist_v2only_migrated') == '1') {
      _signsV2Only = true;
      return;
    }
    // Already v2-only — the flag's write was all that a crash cut short, or a
    // restore brought the list without it: there is nothing to move.
    final ownJson = await vault.kvGet('own_list_json');
    if (ownJson != null) {
      try {
        final own = SignedDeviceList.fromJson(
            (jsonDecode(ownJson) as Map).cast<String, Object?>());
        if (own.isV2Only) {
          _signsV2Only = true;
          await vault.kvPut('devlist_v2only_migrated', '1', sensitive: false);
          return;
        }
      } catch (_) {}
    }
    // The kill switch: the move, and only the move, waits on it.
    if (!_moveAllowed) return;
    // ADR 0029: and on every reader of this account's lists having said it
    // can read the one the move signs.
    if (!_debugMoveUngated && !devlistGate.open) return;
    await _withOwnListLock(() async {
      final cur = await _myDevlistVersion();
      await vault.kvPut('my_devlist_version', '${cur + 1}', sensitive: false);
      _forgetOwnListClaim();
      _signsV2Only = true;
    });
    // Signed, recorded as this device's own and queued for the log here, so
    // the rest of start-up sees the new list; delivered in the background,
    // through the durable outbox, as the 0010 migration's was.
    final data = await _signCurrentDeviceList();
    await vault.kvPut('devlist_v2only_migrated', '1', sensitive: false);
    notifyListeners();
    if (data == null) return;
    unawaited(_selfSyncDeviceList(data).then((_) {}, onError: (_) {}));
    for (final rid in contacts.keys.toList()) {
      final c = contacts[rid];
      if (c == null) continue;
      unawaited(
          _sendInner(c, _devlistInner(data)).then((_) {}, onError: (_) {}));
    }
  }

  InnerMessage _devlistInner(String listJson) => InnerMessage(
      kind: 'devlist',
      mid: newMessageId(),
      ts: _now(),
      data: {'list': listJson});

  /// Sign the account's current device set at the current version (root
  /// only; null elsewhere) and record it as this device's own-list knowledge.
  ///
  /// Under [_ownListLock], from reading the device set to recording what was
  /// signed, so a list is always one snapshot. The set and the version are
  /// two rows, read one after the other here and written one after the
  /// other when a device is linked or removed, and this is called from paths
  /// that run whenever they run — the re-send to a contact whose echo is
  /// behind, the hello's list, the re-assertion on every reconnect, the log
  /// check's baseline. One of them caught between a link's two writes signed
  /// the version before the link with the link's device set (or the reverse)
  /// and recorded it, over the genuine list already published at that
  /// version; after a restart the self-monitor found the genuine entry in
  /// the log, judged it never issued, and said so — the alarm that tells a
  /// user to reset their identity. Measured on 50d9786: 2 rounds in 12 of a
  /// device linked while a re-send was in flight.
  ///
  /// The lock is held for the signing and the record, not for any send: the
  /// callers send what this returns, outside it.
  Future<String?> _signCurrentDeviceList() async {
    final me = await accountIdentity();
    if (!me.holdsAccountRoot) return null;
    return _withOwnListLock(() async {
      // Dual-signed, as in stage 1, unless this account has been moved to
      // v2-only signing ([_signsV2Only]); the fingerprint and the ML-DSA
      // below follow whichever the list is
      // (`SignedDeviceList.commitmentInput`).
      final devices = await myFullDeviceList();
      await debugBetweenOwnListReads?.call();
      final list = await me.signDeviceList(devices, await _myDevlistVersion(),
          v2Only: _signsV2Only);
      final fp = await list.fingerprint();
      // A version keeps the list it was first recorded with (§19.8). Signing
      // one under another fingerprint is a bug in this device, never a state
      // to accept: loud where it can be, and nothing sent where it cannot —
      // the callers fall back to the list on record, or send nothing.
      if (_ownVersionRecordedOtherwise(list.version, b64(fp))) {
        assert(
            false,
            'own device list v${list.version} signed into a second '
            'fingerprint; the first record stands');
        return null;
      }
      // §18.9: the same bytes, signed again under ML-DSA-65. Computed here so
      // it always exists for the list that exists — but NOT sent here. It
      // travels on its own schedule (`_deliverPqListSignatures`), which is
      // what stops a 16 KB envelope marking the moment a device set changed.
      await _signListPostQuantum(list);
      // 7.7a: this device now KNOWS the latest legitimate (version,
      // fingerprint) of its own account — record it so an echo from a contact
      // carrying a list this device never issued stands out (owner rule).
      await _recordOwnList(list);
      final json = jsonEncode(list.toJson());
      // 7.7b: the same list goes to the log (ADR 0006), through a durable
      // queue; a version the log already holds is skipped by the client.
      final seed = me.accountEdSeed;
      if (seed != null) {
        unawaited(kt.publishOwnList(
          accountEdSeed: seed,
          accountEdPub: me.accountEdPub,
          version: list.version,
          fp: fp,
          listJson: json,
        ));
      }
      return json;
    });
  }

  /// The lock key every read-sign-record of this account's own list holds,
  /// and every write of the two rows it reads — `my_devices` and
  /// `my_devlist_version` — holds too. Not a conversation's lock ([_withLock]
  /// is keyed by string, and this is its own key), and never held across a
  /// send: [_withLock] is not re-entrant, and [broadcastMyDeviceList] calls
  /// [_signCurrentDeviceList], which takes it.
  static const String _ownListLock = 'ownlist';

  /// [_withLock] on [_ownListLock], counting callers that found it held and
  /// are waiting for it.
  Future<T> _withOwnListLock<T>(Future<T> Function() op) {
    final held = _locks.containsKey(_ownListLock);
    if (held) _ownListWaiting++;
    return _withLock(_ownListLock, () {
      if (held) _ownListWaiting--;
      return op();
    });
  }

  int _ownListWaiting = 0;

  /// Test seam: whether anything found the own-list lock held and is waiting
  /// for it — so a test can see a link queued behind a signing rather than
  /// guess how long to give it.
  @visibleForTesting
  bool get debugOwnListWaiting => _ownListWaiting > 0;

  /// Test seam: run inside [_signCurrentDeviceList], under its lock, between
  /// reading the device set and reading the version — the gap a link's two
  /// writes used to fall into.
  @visibleForTesting
  Future<void> Function()? debugBetweenOwnListReads;

  /// Whether [version] of this account's list is already recorded under a
  /// fingerprint other than [fpB64].
  bool _ownVersionRecordedOtherwise(int version, String fpB64) {
    final known = kt.knownOwnFingerprint(version);
    return known != null && known != fpB64;
  }

  /// The account's ML-DSA-65 signature over its own current device list
  /// (§18.9). Root only — signing needs the account's post-quantum secret,
  /// which is derived from the account root seed.
  Future<void> _signListPostQuantum(SignedDeviceList list) async {
    final pq = await pqIdentity();
    if (pq == null) return; // not the root, or a pre-v3 account
    try {
      final sig =
          await HybridDeviceListSignature.sign(accountKey: pq, list: list);
      await vault.kvPut('own_list_mlsig', jsonEncode(sig.toJson()),
          sensitive: false);
      // Arm the delivery clock. Arming it HERE is fine and telling the
      // difference matters: what decorrelates the signature from the list is
      // the delay before it goes out, not pretending the client does not know
      // a new one exists.
      _schedulePqListDelivery();
    } catch (_) {
      // Best-effort: the list is still classically signed and usable, and the
      // signature is recomputed the next time the list is.
    }
  }

  /// Phase 33: the account's post-quantum signature over its own list, held
  /// to the key the vault keeps — re-made over the same list when it does
  /// not verify under it, and offered to every contact again.
  ///
  /// The seed race [pqIdentity] now prevents could leave the account's first
  /// list signed under a seed the vault did not keep: the log check signed
  /// with the key it made, and the vault kept the other caller's. A root
  /// re-signs only when its list changes, so an account that never links a
  /// device kept that signature for good: every contact it reached held a
  /// signature its key never verified, asked for it again (§18.9), was
  /// handed the same one, and was told after the grace that it never came.
  ///
  /// What can be checked is checked here: the signature is the one thing
  /// the account published under that seed that the vault also keeps. The
  /// commitment in a contact code cannot be: a code is made when it is shown
  /// and kept nowhere, so a code shown during the race committed to a key no
  /// device of the account can make again, and a contact holding it refuses
  /// this account's key until they add it again. Nothing on this side sees
  /// that happen: the refusal is theirs, and it says nothing back.
  Future<void> _repairOwnListPqSignature() async {
    final me = await accountIdentity();
    if (!me.holdsAccountRoot) return;
    // Nothing signed, nothing to check — and the key is not asked for, so a
    // fresh account does not make its seed here.
    if (await vault.kvGet('own_list_mlsig') == null) return;
    final pq = await pqIdentity();
    if (pq == null) return;
    var repaired = false;
    await _withOwnListLock(() async {
      final listJson = await vault.kvGet('own_list_json');
      final sigJson = await vault.kvGet('own_list_mlsig');
      if (listJson == null || sigJson == null) return;
      final SignedDeviceList list;
      try {
        list = SignedDeviceList.fromJson(
            (jsonDecode(listJson) as Map).cast<String, Object?>());
      } catch (_) {
        return;
      }
      if (!constantTimeEquals(list.accountEdPub, me.accountEdPub)) return;
      try {
        final sig = HybridDeviceListSignature.fromJson(
            (jsonDecode(sigJson) as Map).cast<String, Object?>());
        if (await sig.verifies(list, pq.publicKey.mlPub)) return;
      } catch (_) {
        // Unreadable: re-made below like one that does not verify.
      }
      await _signListPostQuantum(list);
      repaired = true;
    });
    if (!repaired) return;
    // Every contact handed the old one is handed the new one: the delivery
    // skips a contact already sent this version, so that record goes. Until
    // it is sent again this device claims nothing (`pql`), which a contact
    // reads as a build that does not sign its lists — never as an attack.
    for (final rid in _dlpqSent.keys.toList()) {
      try {
        await vault.kvDelete('dlpq_sent_$rid');
      } catch (_) {}
    }
    _dlpqSent.clear();
    _schedulePqListDelivery();
  }

  /// How long after a device list is signed its post-quantum signature is
  /// offered to contacts (§18.9, ADR 0004).
  ///
  /// This delay IS the mechanism. The signature does not fit in the 1 024-byte
  /// bucket that a device list and ordinary chat share — nothing 3.3 KB long
  /// does — so it cannot be hidden by size. What it can be is uncorrelated in
  /// time, and then the 16 384-byte envelope says only "this account runs a
  /// v3 client", never "this account changed its devices just now". Hours in
  /// production; tests set it small because the verification, not the delay,
  /// is what they are checking.
  Duration _pqListDelay = const Duration(hours: 2);
  Duration get pqListDelay => _pqListDelay;
  set pqListDelay(Duration d) {
    _pqListDelay = d;
    // Re-arm: a pending timer was scheduled against the OLD delay, and
    // [_schedulePqListDelivery] deliberately leaves a pending one alone so a
    // busy client cannot keep pushing delivery out for ever.
    _pqListTimer?.cancel();
    _pqListTimer = null;
    _schedulePqListDelivery();
  }

  Timer? _pqListTimer;

  void _schedulePqListDelivery() {
    if (_disposed || _pqListTimer != null) return;
    // Jittered, so several contacts are not served in one recognisable burst.
    final jitter = Duration(
        milliseconds:
            (_pqListDelay.inMilliseconds * 0.4 * _rand.nextDouble()).round());
    _pqListTimer = Timer(_pqListDelay + jitter, () {
      _pqListTimer = null;
      unawaited(_deliverPqListSignatures().then((_) {}, onError: (_) {}));
    });
  }

  final Random _rand = Random.secure();

  /// Offer the current list's post-quantum signature to any contact that has
  /// not had this version. Runs off the timer above, never off a device-list
  /// change.
  Future<void> _deliverPqListSignatures() async {
    final stored = await vault.kvGet('own_list_mlsig');
    if (stored == null) return;
    final sig = HybridDeviceListSignature.fromJson(
        (jsonDecode(stored) as Map).cast<String, Object?>());
    for (final rid in contacts.keys.toList()) {
      final contact = contacts[rid];
      if (contact == null) continue;
      final sent = _dlpqSent[rid] ?? 0;
      if (sent >= sig.version) continue;
      try {
        if (debugSuppressPqList == PqListSuppression.none) {
          await _sendInner(
              contact,
              InnerMessage(
                  kind: 'dlpq',
                  mid: newMessageId(),
                  ts: _now(),
                  data: {'sig': jsonEncode(sig.toJson())}));
        }
        // The claim records that we SENT it (§18.9), so it is stamped after
        // the send, never before. `silent` models a client with no such
        // notion at all, which must therefore claim nothing.
        if (debugSuppressPqList != PqListSuppression.silent) {
          await vault.kvPut('dlpq_sent_$rid', '${sig.version}',
              sensitive: false);
          _dlpqSent[rid] = sig.version;
        }
      } catch (_) {
        // Try again on the next tick; nothing depends on this arriving now.
        _schedulePqListDelivery();
      }
    }
  }

  /// Test-only: model a network attacker dropping the signature (§18.9).
  PqListSuppression debugSuppressPqList = PqListSuppression.none;

  /// Contacts whose post-quantum device-list signature was claimed but never
  /// arrived (§18.9). Keyed by routing id; the value is what to tell the user.
  final Map<String, String> pqListAlerts = {};

  /// How many times we have asked a contact to re-send it. Exposed so a test
  /// can tell "asked and repaired" from "never asked".
  int pqListRequestsSent(String rid) => _pqReqSent[rid] ?? 0;
  final Map<String, int> _pqReqSent = {};

  /// Which list version we have sent each contact (§18.9), in memory so the
  /// outbound decoration costs nothing. Loaded once at startup.
  final Map<String, int> _dlpqSent = {};
  final Map<String, DateTime> _pqMissingSince = {};
  static const int _maxPqListRequests = 3;

  /// A contact's claim that it has sent us its list signature (§18.9).
  ///
  /// Three outcomes, and telling them apart is the whole job:
  ///   * no claim — an older build that does not sign lists. Not an attack,
  ///     and saying so would make every future warning worthless.
  ///   * claim, and we hold the signature — nothing to do.
  ///   * claim, and we do not — it was lost or removed. Ask first, because
  ///     most losses are a dropped connection; alarm only if asking does not
  ///     help within the grace period.
  Future<void> _observePqListClaim(Contact contact, int claimed) async {
    final rid = contact.rid;
    final held =
        int.tryParse(await vault.kvGet('cdev_pq_ver_$rid') ?? '0') ?? 0;
    if (held >= claimed && deviceAssuranceWith(rid) == DeviceAssurance.hybrid) {
      _pqMissingSince.remove(rid);
      _pqReqSent.remove(rid);
      if (pqListAlerts.remove(rid) != null) {
        await vault.kvDelete('pql_alert_$rid');
        notifyListeners();
      }
      return;
    }
    final since = _pqMissingSince.putIfAbsent(rid, () => DateTime.now());
    final asked = _pqReqSent[rid] ?? 0;
    if (asked < _maxPqListRequests) {
      _pqReqSent[rid] = asked + 1;
      try {
        await _sendInner(
            contact,
            InnerMessage(
                kind: 'dlpqreq',
                mid: newMessageId(),
                ts: _now(),
                data: {'v': claimed}));
      } catch (_) {}
      return;
    }
    if (DateTime.now().difference(since) < devlistGrace) return;
    if (pqListAlerts.containsKey(rid)) return;
    // A kind, not the sentence. The sentence named the contact, and this
    // value is written unsealed next to a routing id that says whose name it
    // is; the screen has the contact and supplies the name when it renders
    // (`DevlistAlertKind`).
    final body = devlistAlertBody(DevlistAlertKind.pqSignatureMissing);
    pqListAlerts[rid] = body;
    await vault.kvPut('pql_alert_$rid', body, sensitive: false);
    notifyListeners();
  }

  /// A contact asking for the signature we told them we sent. Answering is
  /// free — it is public, account-signed, and they already hold the list it
  /// covers.
  Future<void> _onPqListRequest(Contact contact) async {
    if (debugSuppressPqList != PqListSuppression.none) return;
    final stored = await vault.kvGet('own_list_mlsig');
    if (stored == null) return;
    try {
      await _sendInner(
          contact,
          InnerMessage(
              kind: 'dlpq',
              mid: newMessageId(),
              ts: _now(),
              data: {'sig': stored}));
    } catch (_) {}
  }

  /// An inbound `dlpq` (§18.9).
  ///
  /// Stored FIRST and verified second, and stored even when it cannot be
  /// verified yet. The contact's account ML-DSA key arrives on its own
  /// independent schedule (§18.2) and may not be here yet; discarding a
  /// signature that arrives first would quietly make the two schedules depend
  /// on each other, which is exactly what ADR 0004 separates them to avoid.
  Future<void> _onPqListSignature(Contact contact, InnerMessage inner) async {
    final raw = inner.data['sig'];
    if (raw is! String) return;
    final HybridDeviceListSignature sig;
    try {
      sig = HybridDeviceListSignature.fromJson(
          (jsonDecode(raw) as Map).cast<String, Object?>());
    } catch (_) {
      return; // malformed or truncated: never reaches a verifier
    }
    if (base64Encode(sig.accountEdPub) != base64Encode(contact.accountEd)) {
      return; // not this contact's account
    }
    final held =
        int.tryParse(await vault.kvGet('cdev_pq_ver_${contact.rid}') ?? '0') ??
            0;
    if (sig.version < held) return; // stale replay
    await vault.kvPut('cdev_pq_${contact.rid}', raw, sensitive: false);
    await vault.kvPut('cdev_pq_ver_${contact.rid}', '${sig.version}',
        sensitive: false);
    await _refreshDeviceAssurance(contact.rid);
  }

  final Map<String, DeviceAssurance> _deviceAssurance = {};

  /// Whether this contact's device list is post-quantum verified (§18.4).
  ///
  /// `classical` is not a failure — it is correct today and forgeable later,
  /// and the two must be told apart rather than the second shown as the
  /// first. A list stays classical until a signature over exactly this
  /// version and this device set has been checked against the contact's
  /// account key.
  DeviceAssurance deviceAssuranceWith(String rid) =>
      _deviceAssurance[rid] ?? DeviceAssurance.classical;

  /// 26.3: whether the post-quantum signature over this contact's device list
  /// also covers each device's ratchet key — true only for a hybrid-verified
  /// v2-only list (`sig3` alone, ADR 0017 stage 2), whose ML-DSA is over the
  /// v3 input. On a dual-signed list, every list signed today, the ML-DSA is
  /// held at the v1 input: it fixes which devices are in the set and the
  /// version, and a device's ratchet key is covered classically only.
  bool deviceListCoversKeys(String rid) => _devListCoversKeys.contains(rid);
  final Set<String> _devListCoversKeys = {};

  Future<void> _refreshDeviceAssurance(String rid,
      {bool notify = true, Map<String, String>? kv}) async {
    final was = _deviceAssurance[rid];
    final wasKeys = _devListCoversKeys.contains(rid);
    final (now, keys) = await _computeDeviceAssurance(rid, kv: kv);
    if (now == DeviceAssurance.classical) {
      _deviceAssurance.remove(rid);
    } else {
      _deviceAssurance[rid] = now;
    }
    if (keys) {
      _devListCoversKeys.add(rid);
    } else {
      _devListCoversKeys.remove(rid);
    }
    if (notify && (was != now || wasKeys != keys)) notifyListeners();
  }

  /// [kv] is a startup snapshot of the per-contact keys (see `init`); without
  /// it the two values are read individually. The second value is
  /// [deviceListCoversKeys].
  Future<(DeviceAssurance, bool)> _computeDeviceAssurance(String rid,
      {Map<String, String>? kv}) async {
    const none = (DeviceAssurance.classical, false);
    final contact = contacts[rid];
    final mlPub = contact?.pqPub;
    if (contact == null || mlPub == null) return none;
    final listJson =
        kv != null ? kv['cdev_$rid'] : await vault.kvGet('cdev_$rid');
    final sigJson =
        kv != null ? kv['cdev_pq_$rid'] : await vault.kvGet('cdev_pq_$rid');
    if (listJson == null || sigJson == null) return none;
    try {
      final list = SignedDeviceList.fromJson(
          (jsonDecode(listJson) as Map).cast<String, Object?>());
      final sig = HybridDeviceListSignature.fromJson(
          (jsonDecode(sigJson) as Map).cast<String, Object?>());
      return await sig.verifies(list, mlPub)
          ? (DeviceAssurance.hybrid, list.isV2Only)
          : none;
    } catch (_) {
      return none;
    }
  }

  /// The stored signature for a contact's list, if one has arrived.
  @visibleForTesting
  Future<String?> debugHeldPqListSignature(String rid) =>
      vault.kvGet('cdev_pq_$rid');

  /// This account's own signature over its current list.
  @visibleForTesting
  Future<HybridDeviceListSignature?> debugPqSignatureForCurrentList() async {
    final stored = await vault.kvGet('own_list_mlsig');
    if (stored == null) return null;
    return HybridDeviceListSignature.fromJson(
        (jsonDecode(stored) as Map).cast<String, Object?>());
  }

  /// Self-sync a signed list to my own other devices (`dir:"acct"`).
  ///
  /// From the root it carries the root's own bundle too (`rootb`, phase 33):
  /// what a linked device sends its requests as (§8.1). A device linked by
  /// this build has it from its enrolment (§10 `hostbundle`); one linked
  /// before has it from here, the next time the root re-asserts its list —
  /// which it does on every connect. Only to my own devices: a contact's
  /// copy of the list is the list alone.
  Future<void> _selfSyncDeviceList(String listJson) async {
    final sync = _sync;
    if (sync == null) return;
    final inner = _devlistInner(listJson);
    if ((await accountIdentity()).holdsAccountRoot) {
      inner.data['rootb'] = (await identity.bundle()).toJson();
    }
    await sync.mirror(threadRid: '', dir: 'acct', inner: inner);
  }

  /// Root: push the current signed list to my own devices — at startup and
  /// whenever one of them asks (`acctreq`) — so a linked device that missed a
  /// broadcast (linked before 7.7a, lost sync) catches up instead of claiming
  /// a stale version to contacts or mistaking an honest echo for a rogue list.
  Future<void> _selfSyncCurrentDeviceList() async {
    if (_sync == null) return;
    final data = await _signCurrentDeviceList();
    if (data != null) await _selfSyncDeviceList(data);
  }

  /// Self-healing distribution (7.7a hardening): a contact whose echo of MY
  /// list is older than my current version never received it (added after a
  /// device was linked, or the broadcast was lost) — hand it over now. Root
  /// only (it can sign, and every contact already knows its routing id). A
  /// per-contact cooldown bounds the retries if their install keeps failing.
  final Map<String, int> _dlResentAtMs = {};
  static const int _dlResendCooldownMs = 60 * 1000;

  Future<void> _maybeResendDeviceList(String rid) async {
    final contact = contacts[rid];
    if (contact == null) return;
    final last = _dlResentAtMs[rid] ?? 0;
    if (_now() - last < _dlResendCooldownMs) return;
    final data = await _shareableDeviceList();
    if (data == null) return;
    _dlResentAtMs[rid] = _now();
    await _sendInner(contact, _devlistInner(data));
  }

  /// The account-signed device list THIS device can hand to a contact.
  ///
  /// A root signs a fresh one. A linked device cannot sign — but it holds the
  /// list its root signed and self-synced to it (7.7a rule 8), and passing an
  /// account-signed blob along is not a privilege: the recipient verifies the
  /// signature against the account key they already hold, so a forwarded list
  /// is worth exactly what the root's own copy is worth, and a tampered one
  /// is worth nothing.
  ///
  /// This became necessary with §18.7. A contact can now be added by scanning
  /// a LINKED device, and that device is then the only one the contact can
  /// reach — the root has never heard of them. Without this the contact would
  /// hold a one-device list, see the laptop claim a newer version on every
  /// message, and be told after the grace period that "the device list
  /// changed but the update never arrived" — an alarm raised by ordinary
  /// use, which is how a real one stops being read.
  Future<String?> _shareableDeviceList() async =>
      await _signCurrentDeviceList() ?? await vault.kvGet('own_list_json');

  /// Linked device: ask my root for the account's current signed list (it
  /// answers by self-sync). Sent when a contact's echo disagrees with what
  /// this device knows, so an honest update that never reached us is fetched
  /// before the grace period turns it into an alarm. Rate-limited.
  int _lastAcctReqMs = 0;
  Future<void> _requestOwnDeviceList() async {
    if (_sync == null || await holdsAccountRoot()) return;
    if (_now() - _lastAcctReqMs < 30 * 1000) return;
    _lastAcctReqMs = _now();
    await _sync?.mirror(
        threadRid: '',
        dir: 'acctreq',
        inner: InnerMessage.hello(newMessageId(), _now()));
  }

  /// A contact scanned before §18.7 as the one-device account it read as:
  /// the device key IS the account key, and the v1 binding signature is the
  /// certificate (§3.5). Never used for a contact whose code carried a real
  /// one — that is the whole difference.
  DeviceCertificate _legacyCertOf(Contact c) => DeviceCertificate(
        deviceEdPub: c.bundle.edPub,
        deviceXPub: c.bundle.xPub,
        deviceId: 'legacy-v1',
        sig: c.bundle.bindingSig,
        legacy: true,
      );

  List<DeviceCertificate> _extrasOf(Contact contact, SignedDeviceList list) => [
        for (final d in list.devices)
          if (base64Encode(d.deviceEdPub) != base64Encode(contact.bundle.edPub))
            d
      ];

  Future<void> _loadContactDeviceLists({Map<String, String>? kv}) async {
    for (final rid in contacts.keys.toList()) {
      final devJson =
          kv != null ? kv['cdev_$rid'] : await vault.kvGet('cdev_$rid');
      final contact = contacts[rid];
      if (devJson == null || contact == null) continue;
      final list = SignedDeviceList.fromJson(
          (jsonDecode(devJson) as Map).cast<String, Object?>());
      await _installContactDeviceList(contact, list, persist: false, kv: kv);
    }
  }

  /// Verify (on receipt), store, and reconcile a contact's device list — adding
  /// newly-learned devices AND dropping revoked ones, so the fan-out set matches
  /// the list exactly.
  /// Returns whether a persisted install actually happened — a refusal here
  /// must not look like an acceptance to the caller, because the caller tells
  /// the transparency log a new list arrived and that resets a hold.
  ///
  /// One contact's installs run one at a time. Each is a read of what is held
  /// — the version, the signature floor — then checks, then writes, and two
  /// for the same account used to be free to interleave: the in-band path
  /// installs after the ratchet lock is released, and the log check installs
  /// on its own clock. A re-sent broadcast still in flight when a newer list
  /// arrived could read the old version, pass its staleness check and write
  /// last, so the held version went backwards and the newer list was lost —
  /// and the floor, the same read-check-write, could be stepped over the same
  /// way. The lock is not the ratchet's (a send holds that while it steps and
  /// writes, and an install has no reason to wait on one or be waited on by
  /// one) but its own key in the same table.
  ///
  /// And it is one key for every contact, not one per contact, because one
  /// check reads across accounts: a list naming a device already held for
  /// another account is refused ([_deviceHeldElsewhere]). Two installs for
  /// two accounts naming one device, each checking before either wrote, would
  /// both pass and the second write would take the device. Installs are rare
  /// and short, and nothing that holds this lock installs again.
  Future<bool> _installContactDeviceList(Contact contact, SignedDeviceList list,
      {required bool persist, Map<String, String>? kv}) async {
    final installed = await _withLock('devlist', () async {
      final ok = await _installContactDeviceListLocked(contact, list,
          persist: persist, kv: kv);
      if (persist) {
        debugJudged
            ?.add((rid: contact.rid, version: list.version, installed: ok));
      }
      return ok;
    });
    // ADR 0029: their device set has changed, and a device it dropped may
    // have been the last reader the move was waiting for. After the install
    // lock, which the move never needs.
    if (installed && persist) unawaited(_maybeMoveToV2Only());
    return installed;
  }

  /// Test seam: while a test has set it, every list an install judged —
  /// in-band or from the log — in order: whose, its version, and whether it
  /// was installed. So that a test can tell a list refused in silence (the
  /// signature floor, a proof of possession taken off) from one not judged
  /// yet, whatever else arrives meanwhile. Null, and nothing recorded,
  /// otherwise.
  @visibleForTesting
  List<({String rid, int version, bool installed})>? debugJudged;

  Future<bool> _installContactDeviceListLocked(
      Contact contact, SignedDeviceList list,
      {required bool persist, Map<String, String>? kv}) async {
    final rid = contact.rid;
    var sigFloor = 0;
    if (persist) {
      if (base64Encode(list.accountEdPub) != base64Encode(contact.accountEd)) {
        return false; // not signed by this contact's account key
      }
      if (!await list.verify()) return false;
      // The signature floor, per contact account. It has three levels, and a
      // list below the level the account has reached is refused here exactly
      // as a list that does not verify is — nothing installed, the log told
      // nothing, no alert: a downgrade cannot be expressed.
      //
      //   0  nothing seen yet: any list that verifies.
      //   1  a list covering the ratchet keys seen — carrying sig2 (ADR 0010)
      //      or, v2-only, sig3 (ADR 0017). `cdev_sigfloor_` holds the highest
      //      version at which one was, and a LATER version arriving with
      //      neither is an Ed25519 forger stripping the ratchet-key coverage
      //      and replaying above it. A v1-only list at or below the floor is a
      //      genuine pre-0010 list and still admitted.
      //   2  a v2-only list seen — sig3 alone (ADR 0017 stage 2). The account
      //      has stopped producing v1 signatures, so a list from it that
      //      carries one — dual-signed or v1-only, at any version, the held
      //      one included — is refused: it can only be a forger putting back
      //      the format whose fingerprint is blind to a ratchet key, or a
      //      build that went backwards, and a contact can tell neither apart.
      //      This level is not stored beside the list; it IS the list. The
      //      account is at level 2 exactly when the list held for it is
      //      v2-only, because nothing at level 2 can replace that with a list
      //      carrying `sig`. So it is recorded in the same write that installs
      //      the list, and goes when the contact does. Only the account can
      //      raise it: a v2-only list is signed over an input no dual-signed
      //      list is signed over, so deleting `sig` from one of the account's
      //      dual-signed lists does not make one (`verify()` refuses `sig2`
      //      alone outright).
      //
      // Refusing in silence is also what keeps an innocent account from being
      // accused. Nothing is said about the list that was refused; what the
      // gossip goes on comparing is the account's own devices' claims, and
      // those agree with the v2-only list still held.
      sigFloor =
          int.tryParse(await vault.kvGet('cdev_sigfloor_$rid') ?? '0') ?? 0;
      if (list.sig2 == null &&
          list.sig3 == null &&
          sigFloor > 0 &&
          list.version > sigFloor) {
        return false;
      }
      if (!list.isV2Only && await _holdsV2OnlyListFor(rid)) return false;
      final storedVer =
          int.tryParse(await vault.kvGet('cdev_ver_$rid') ?? '0') ?? 0;
      if (list.version < storedVer) return false; // stale replay
    }

    // A device belongs to one account (§3.4). A certificate proves only that
    // the account SIGNED it — not that whoever holds the account holds the
    // device key it names — so any contact can put another person's public
    // keys in their own list: those of another contact, from a code or a
    // group's member list, or this device's own. Installed, that list would
    // take the device here. Inbound routing asks [_extraRidToContact] before
    // [contacts], so the other contact's messages would be decrypted against
    // the wrong account and dropped, and ours to them sealed beside a key of
    // the claimant's choosing. So the whole list is refused, whichever path
    // brought it — in-band, the log, or the vault at start-up, where a list
    // an earlier build installed is held to the same rule.
    //
    // What the user is told, for a list that arrived: the fact, naming both
    // parties, on the chat of the contact whose list was refused. Not an
    // accusation — without a proof this device cannot tell which of two
    // accounts is lying, and when the claim came first and the real owner's
    // list second, the one refused is the honest one. Silence would leave the
    // user nothing to ask either of them about.
    //
    // ADR 0022 settles what a proof of possession can: a device that has
    // signed for one account is that account's, here, for as long as a
    // contact of that account is ([_provenDevices]) — and a list proving a
    // device another contact's list holds only by the first-come rule takes
    // it from that list, which is then not used ([_judgeListClaims]).
    final verdict = await _judgeListClaims(contact, list, persist: persist);
    if (verdict.refused) {
      final alert = verdict.alert;
      if (persist && alert != null) {
        await _setContactAlert(rid, alert);
        notifyListeners();
      }
      return false;
    }
    for (final holder in verdict.evict) {
      await _withdrawContactDeviceList(holder,
          persist: persist,
          alert: devlistAlertBody(DevlistAlertKind.claimedDevice, {'with': rid}));
    }

    if (persist) {
      await vault.kvPut('cdev_$rid', jsonEncode(list.toJson()),
          sensitive: false);
      await vault.kvPut('cdev_ver_$rid', '${list.version}', sensitive: false);
      // Raise the floor when this list carries a verified sig2 or sig3, so a
      // later strip cannot be replayed beneath it.
      if ((list.sig2 != null || list.sig3 != null) &&
          list.version > sigFloor) {
        await vault.kvPut('cdev_sigfloor_$rid', '${list.version}',
            sensitive: false);
      }
      // When it arrived: the transparency grace period runs from here.
      await vault.kvPut('cdev_at_$rid', '${_now()}', sensitive: false);
      // A new list is classical until a signature over THIS version arrives
      // (§18.9); the one we hold, if any, is for an older set.
      await _refreshDeviceAssurance(rid, notify: false);
      // A list of theirs refused for naming a device held elsewhere is
      // superseded by this one, which names none.
      if (isSharedDeviceAlert(contactDevlistAlerts[rid])) {
        await _setContactAlert(rid, null);
      }
    }

    final extras = _extrasOf(contact, list);
    final acct = await accountIdentity();
    // The contact's extras session is changed under the conversation's lock
    // as well as this one: `_fanToContactExtras` and `_handleExtraInbound`
    // work on the same AccountSession under `_withLock(rid)`, and until
    // 2026-10-04 this did not, so the two interleaved at every await. A
    // fan-out iterates the session's devices across awaits, and the target
    // changes below made it throw part-way (the message silently not sent to
    // the contact's other devices); a fan-out and the removal notice could
    // step the removed device's ratchet at once; and `_handleExtraInbound`'s
    // rollback after a failed decrypt or store replaced the session object
    // with a snapshot while this install was still changing the old one, so
    // the changes — a removed device among them, still fanned out to — were
    // lost until the next install. (ADR 0017's follow-ups list it.)
    //
    // Nesting the two cannot deadlock, although `_withLock` is not
    // re-entrant: this is the only place either is taken inside the other,
    // always in this order ('devlist', then the conversation), and nothing
    // that holds a conversation's lock — or the own-list lock, or a chunk
    // lock — ever waits for 'devlist'. An install is reached only from
    // inbound post-processing, which runs after the conversation's lock is
    // released (the primary path's post-processing, `_dispatchExtraInner`),
    // from the log's check (`ktInstallFromLog`, run on its own timer, never
    // under a lock), and at start-up (`_loadContactDeviceLists`). Nor does
    // anything inside the section below take a lock: what it calls are the
    // session's own methods, the vault, `_sealFor`, and `flushOutbox` and
    // `_offerPqIdentity` unawaited — and `_saveProvenDevices`, whose own lock
    // ('devpop') holds nothing but the write, so nothing waits inside it.
    //
    // What remains (not changed here): `_handleExtraInbound` puts the whole
    // session back to its pre-decrypt snapshot when the dispatch AFTER the
    // lock fails, outside the lock — which can undo what anything did to the
    // session in between, an install's target changes and a fan-out's
    // sending chains included. Rolling back only what that decrypt advanced
    // needs the dispatch's stores moved under the lock, as the primary path
    // has them.
    final appeared = await _withLock(rid, () async {
      // Deleted while this waited for the lock: the session goes with them,
      // and is not to be rebuilt and stored again for someone forgotten.
      if (!contacts.containsKey(rid)) return const <String>[];
      var session = _contactExtras[rid];
      if (session == null) {
        final stored =
            kv != null ? kv['cextra_$rid'] : await vault.kvGet('cextra_$rid');
        session = stored != null
            ? await AccountSession.fromJson(
                acct, (jsonDecode(stored) as Map).cast<String, Object?>(),
                intervals: _pqIntervals)
            : await AccountSession.create(acct, const [],
                intervals: _pqIntervals);
        _contactExtras[rid] = session;
      }

      final newRids = <String>{};
      for (final d in extras) {
        final r = await d.routingId();
        newRids.add(r);
        _sealKeys[r] = d.deviceXPub; // sealed sender to their extra devices too
      }
      // 7.7a removal notice (T3): a device we previously held and that this
      // verified list drops is told once, over the still-open pairwise
      // session, that it was removed — so a device silently excluded by
      // whoever holds the account root hears of it from the people who
      // stopped delivering to it. A rogue cannot suppress this: it is sent by
      // the contact, not the account.
      final removed = [
        for (final r in session.targetRoutingIds.toList())
          if (!newRids.contains(r)) r
      ];
      if (persist && removed.isNotEmpty) {
        final fp = await list.fingerprint();
        var queued = false;
        for (final r in removed) {
          // Nothing queued for a dropped device is delivered to it: the list
          // that dropped it is the account's statement that it is no longer
          // theirs, and a durable outbox must not deliver after the fact what
          // a down link happened to hold. The notice below is the one thing
          // it still gets.
          await vault.db.delete('outbox', where: 'rid = ?', whereArgs: [r]);
          try {
            // With the list itself (ADR 0026): the dropped device believes a
            // notice only on a list its own account signed, and this is that
            // list. A notice without it — every build before this one sent
            // none — is a claim the device has no way to check.
            final note = InnerMessage.deviceListRemoved(newMessageId(), _now(),
                acct: list.accountEdPub,
                v: list.version,
                h: fp,
                list: jsonEncode(list.toJson()));
            // ADR 0029: every inner message says what this device reads; the
            // notice skips the rest of the decoration (§3.6), not this.
            if (!debugPreAdr0029) note.data['dlr'] = devlistReaderLevel;
            final fm = await session.encryptFor(r, note.toBytes());
            await _saveExtra(rid);
            if (fm != null) {
              // Through the outbox: this notice is the whole of what tells a
              // silently excluded device it was excluded (T3), and a direct
              // send with the link down was a notice never sent.
              await vault.db.insert('outbox', {
                'id': newMessageId(),
                'rid': r,
                'payload': await _sealFor(r, fm.payload),
                'created_ms': _now(),
              });
              queued = true;
            }
          } catch (_) {}
        }
        if (queued) unawaited(flushOutbox());
      }
      final appeared = [
        for (final r in newRids)
          if (!session.targetRoutingIds.contains(r)) r
      ];
      for (final r in removed) {
        session.removeTarget(r);
      }
      for (final d in extras) {
        await session.addTarget(DeviceTarget.fromCert(d));
      }
      _extraRidToContact.removeWhere((k, v) => v == rid);
      for (final r in newRids) {
        _extraRidToContact[r] = rid;
      }
      if (persist) await _saveExtra(rid);
      // ADR 0022: every device this list proves is recorded as this
      // account's, the first proof standing — from now on no other account's
      // list may name it, and none of this account's may name it without the
      // proof. Here, under the conversation's lock, which a deletion of the
      // contact takes too: one that ran before this has left nothing to
      // record for (above), and one after it forgets what this records.
      var provenChanged = false;
      for (final r in verdict.proven) {
        if (_noteProven(r, base64Encode(contact.accountEd), inList: true)) {
          provenChanged = true;
        }
      }
      if (provenChanged) await _saveProvenDevices();
      return appeared;
    });

    // §18.2: a device that has just appeared has never heard our post-quantum
    // key, because the offer went out before it existed. Left alone it shows
    // its owner a CLASSICAL safety number for us while their other devices
    // show a hybrid one — two numbers for one account, which is exactly the
    // confusion phase 10 exists to prevent, and worse here because the
    // mismatch reads as a key substitution.
    //
    // Re-offering is why the offer fans out at all: `_sendInner` reaches
    // every device on the list, so one send serves the whole account. Once
    // per device-list change, at a moment that has already generated traffic.
    if (persist && appeared.isNotEmpty) {
      // A new device set: nothing sent so far reached it, so the quiet
      // period after the last send does not apply either.
      _pqSent.remove(rid);
      _pqNudges.remove(rid);
      _pqAnswers.remove(rid);
      _pqLastSentMs.remove(rid);
      _offerPqIdentity(contact, _PqReason.volunteer);
      // 7.7a: nor has it been sent our device list. It holds at most the
      // one-device list from our code, which its own device passed on when
      // they added us, and every message we send it claims a newer one.
      unawaited(_sendOwnListToNewDevices(contact).then((_) {}, onError: (_) {}));
    }
    return true;
  }

  /// 7.7a, self-healing distribution: [contact]'s list has just named a
  /// device of theirs we have never sent our list to, so it goes to them now
  /// — to every device of theirs, as any send does — once per such list.
  ///
  /// Waiting for that device's echo is what the repair channel did until
  /// 2026-10-16 (after 4.2.0), and it was too slow. Two people who each had a
  /// linked device added each other, and the other's laptop raised "their
  /// device list changed and the update never arrived" in ordinary use: our
  /// claim reached it with our first message, its echo rode its receipt (5 s
  /// to a minute later, ADR 0028), and the re-send that echo asked for fell
  /// inside the cooldown of the one their phone's echo had already asked for,
  /// sent before we knew the laptop was there. Not cooldown-limited: a
  /// contact's list changes only when their account signs a new one.
  Future<void> _sendOwnListToNewDevices(Contact contact) async {
    final data = await _shareableDeviceList();
    if (data == null || !contacts.containsKey(contact.rid)) return;
    // A one-device account's list is the one in its code: nothing newer for
    // the new device to learn, and nothing claimed above what it holds.
    final v = (jsonDecode(data) as Map)['ver'];
    if (v is! num || v <= 1) return;
    _dlResentAtMs[contact.rid] = _now();
    await _sendInner(contact, _devlistInner(data));
  }

  /// What §3.4's rules make of the devices [list] — a list for [contact]'s
  /// account — names, against what this device already holds; decided before
  /// anything is written, so a list is installed whole or refused whole.
  ///
  /// Refused, with the alert to raise for a list that arrived ([persist]):
  ///  * a device of this account's own — [DevlistAlertKind.sharedWithMe];
  ///  * a device that has proved it belongs to ANOTHER account (ADR 0022,
  ///    [_provenDevices]), whether or not anybody holds it now —
  ///    [DevlistAlertKind.claimedDevice], naming a contact of that account;
  ///  * on a list that arrived, a device THIS account's lists have carried
  ///    proven, named here without the proof — silently, as the signature
  ///    floor refuses: only someone holding the account's key (or passing a
  ///    list on with the member taken off) makes such a list, and the
  ///    account's own devices go on claiming the list still held. That is
  ///    also what refuses a ratchet key swapped under a proven device's
  ///    certificate, since the proof covers the ratchet key;
  ///  * the device another contact of another account was added from —
  ///    [DevlistAlertKind.sharedDevice], first come even when this list
  ///    proves it: that contact's record IS that device's routing id, and a
  ///    list does not move a contact the user added (a code naming a device
  ///    already proven for another account is refused at the scan,
  ///    [addContactFromCode]);
  ///  * a device another account's installed list names, unless this list
  ///    PROVES it — [DevlistAlertKind.sharedDevice]: first come, as before
  ///    ADR 0022.
  ///
  /// Installed otherwise, with [_ClaimVerdict.evict]: the contacts of other
  /// accounts whose installed lists hold, by the first-come rule alone, a
  /// device this list proves. Theirs is withdrawn — a list naming a device
  /// that has proved it is someone else's is not used, whichever arrived
  /// first — and [_ClaimVerdict.proven] is what this list proves.
  ///
  /// Accounts are compared, not contact records. The same person added from
  /// two of their devices is two records for one account, and each record's
  /// list names the other's device; that is one account's device set seen
  /// twice, not a claim on anybody else's.
  ///
  /// Called under the install lock, which every install takes, so nothing
  /// else changes [_extraRidToContact] or [_provenDevices] between this
  /// answer and the writes that follow it.
  Future<_ClaimVerdict> _judgeListClaims(Contact contact, SignedDeviceList list,
      {required bool persist}) async {
    final acct = base64Encode(contact.accountEd);
    final mine = {
      ..._myAccountRids,
      for (final d in await myFullDeviceList()) await d.routingId(),
    };
    final proven = <String>{};
    final evict = <String>{};
    for (final d in list.devices) {
      final r = await d.routingId();
      final p = _carriesProof(d, contact.accountEd);
      if (p) proven.add(r);
      if (mine.contains(r)) {
        return _ClaimVerdict.refuse(
            devlistAlertBody(DevlistAlertKind.sharedWithMe));
      }
      final owner = _provenDevices[r];
      if (owner != null && owner.acct != acct) {
        return _ClaimVerdict.refuse(_claimedAlert(owner.acct, r));
      }
      if (persist && owner != null && owner.inList && !p) {
        return const _ClaimVerdict.refuse(null);
      }
      final added = contacts[r];
      if (added != null && base64Encode(added.accountEd) != acct) {
        return _ClaimVerdict.refuse(devlistAlertBody(
            DevlistAlertKind.sharedDevice, {'with': added.rid}));
      }
      final listedFor = _extraRidToContact[r];
      final lister = listedFor == null || listedFor == contact.rid
          ? null
          : contacts[listedFor];
      if (lister != null && base64Encode(lister.accountEd) != acct) {
        // Held for another account by the first-come rule alone: had that
        // account's list proved it, [_provenDevices] would name that account
        // and the list in hand would have been refused above.
        if (!p) {
          return _ClaimVerdict.refuse(devlistAlertBody(
              DevlistAlertKind.sharedDevice, {'with': lister.rid}));
        }
        evict.add(lister.rid);
      }
    }
    return _ClaimVerdict.install(proven: proven, evict: evict);
  }

  /// Whether [d], in a list for the account [accountEdPub] that has been
  /// verified, shows that the device itself is in that account (ADR 0022):
  /// its key IS the account key — device #1, or a `legacy` record, whose
  /// certificate the device key signed — or it carries a proof of
  /// possession. Read from the certificate without checking a signature
  /// again: a list that arrived was verified ([SignedDeviceList.verify],
  /// which checks every proof it carries) before this is asked, and one held
  /// at start-up was verified when it arrived. Every build before ADR 0022
  /// re-serialises a list without the member, so no list it stored carries
  /// one at all.
  bool _carriesProof(DeviceCertificate d, Uint8List accountEdPub) =>
      constantTimeEquals(d.deviceEdPub, accountEdPub) || d.pop != null;

  /// The [DevlistAlertKind.claimedDevice] alert for a list naming [deviceRid],
  /// which has proved it belongs to the account [ownerAcct] — naming a
  /// contact of that account if this device holds one: the one the device is
  /// held for, else the one added from it, else any record of the account.
  String _claimedAlert(String ownerAcct, String deviceRid) {
    bool ofOwner(String? r) =>
        r != null &&
        contacts[r] != null &&
        base64Encode(contacts[r]!.accountEd) == ownerAcct;
    final listedFor = _extraRidToContact[deviceRid];
    final String? other;
    if (ofOwner(listedFor)) {
      other = listedFor;
    } else if (ofOwner(deviceRid)) {
      other = deviceRid;
    } else {
      other = contacts.values
          .where((c) => base64Encode(c.accountEd) == ownerAcct)
          .map((c) => c.rid)
          .firstOrNull;
    }
    return devlistAlertBody(DevlistAlertKind.claimedDevice,
        {if (other != null) 'with': other});
  }

  /// ADR 0022: the devices this device has seen PROVE which account they are
  /// in — routing id → the account's key (base64), and whether the proof was
  /// seen in a device list that account signed ([_ClaimVerdict.proven]) or
  /// only on the code or request a contact was added from
  /// ([_claimAddedDevice]).
  ///
  /// The first proof for a device stands. From then on a list from any other
  /// account that names the device is refused, whether or not anybody holds
  /// the device here any more — "a device key once seen proven for one
  /// account is never accepted for another", nor is a code naming it for
  /// another ([addContactFromCode], [_applyMirroredContact]) — and, once a
  /// list from the account itself has carried the proof, a list from it
  /// naming the device without one is refused too. A proof seen only in a
  /// code does not set that second rule: it says what the device's build
  /// makes, not that the account's root carries proofs, and an account whose
  /// root predates ADR 0022 lists its devices without them.
  ///
  /// For as long as the account is known here: when the last contact record
  /// of an account is deleted, its devices are forgotten with it
  /// ([deleteContact]), so a deleted contact's routing ids do not outlive
  /// them in the vault. Sealed (`dev_pop`), and not in a backup: a restore
  /// rebuilds it at start-up from the lists the archive carries, which
  /// carry the proofs.
  final Map<String, ({String acct, bool inList})> _provenDevices = {};

  static const String _provenDevicesKey = 'dev_pop';

  Future<void> _loadProvenDevices() async {
    final stored = await vault.kvGet(_provenDevicesKey);
    if (stored == null) return;
    try {
      final m = (jsonDecode(stored) as Map).cast<String, Object?>();
      for (final e in m.entries) {
        final v = e.value;
        if (v is Map && v['a'] is String) {
          _provenDevices[e.key] = (acct: v['a'] as String, inList: v['l'] == 1);
        }
      }
    } catch (_) {
      // Unreadable: rebuilt from the lists held, as the start-up load
      // installs them.
    }
  }

  /// Writes [_provenDevices] as it stands when the write runs, one write at a
  /// time — so the last to run writes the latest map, whichever of two
  /// callers changed it first. Its own key: nothing inside takes a lock, so
  /// it can be reached under any other.
  Future<void> _saveProvenDevices() => _withLock('devpop', () async {
        if (_provenDevices.isEmpty) {
          await vault.kvDelete(_provenDevicesKey);
          return;
        }
        await vault.kvPut(
            _provenDevicesKey,
            jsonEncode({
              for (final e in _provenDevices.entries)
                e.key: {'a': e.value.acct, 'l': e.value.inList ? 1 : 0},
            }));
      });

  /// Records that [deviceRid] proved it is in the account [acct] — in a list
  /// that account signed ([inList]) or not. Whether anything changed. A
  /// proof for another account than the one recorded changes nothing: the
  /// first stands.
  bool _noteProven(String deviceRid, String acct, {required bool inList}) {
    final held = _provenDevices[deviceRid];
    if (held != null && (held.acct != acct || held.inList || !inList)) {
      return false;
    }
    _provenDevices[deviceRid] = (acct: acct, inList: inList);
    return true;
  }

  /// Test seam: the account (base64 key) [deviceRid] has proved it belongs
  /// to here, and whether a list of that account's carried the proof.
  @visibleForTesting
  ({String acct, bool inList})? debugProvenDevice(String deviceRid) =>
      _provenDevices[deviceRid];

  /// ADR 0022: stop using [rid]'s installed list — whole, as a refused list
  /// is refused whole — because it names a device that has proved it is
  /// someone else's: another account's ([_judgeListClaims],
  /// [_claimAddedDevice]) or this account's own ([_withdrawClaimsOnMine]).
  /// It held that device by the first-come rule, which is all a list could
  /// do before proofs existed, and the proof arrived after it.
  ///
  /// Every device it listed stops being theirs here: out of [_contactExtras]
  /// and [_extraRidToContact], and whatever was queued for those devices is
  /// not delivered — it was sealed beside keys their list chose, one of them
  /// for a device that is not theirs. No removal notice goes: that is the
  /// account's statement about its own devices, and nothing the account
  /// signed removed these. Their held list stays in the vault — it is what
  /// they still claim, and what their echo is compared with — and is held to
  /// the same rule at every start, where [_provenDevices] refuses it.
  ///
  /// Under the install lock ([_installContactDeviceList]); the contact's
  /// session is changed under the conversation's lock too, in that order,
  /// as an install does.
  Future<void> _withdrawContactDeviceList(String rid,
      {required bool persist, String? alert}) async {
    await _withLock(rid, () async {
      final session = _contactExtras[rid];
      final dropped = <String>{
        ...?session?.targetRoutingIds,
        for (final e in _extraRidToContact.entries)
          if (e.value == rid) e.key,
      };
      if (session != null) {
        for (final r in session.targetRoutingIds.toList()) {
          session.removeTarget(r);
        }
      }
      _extraRidToContact.removeWhere((_, v) => v == rid);
      for (final r in dropped) {
        await vault.db.delete('outbox', where: 'rid = ?', whereArgs: [r]);
      }
      if (persist && session != null && contacts.containsKey(rid)) {
        await _saveExtra(rid);
      }
    });
    if (persist && alert != null && contacts.containsKey(rid)) {
      await _setContactAlert(rid, alert);
      notifyListeners();
    }
  }

  /// §3.4: this account's own list is the authority on its devices. A
  /// contact's list that named one of them before this device knew it — a
  /// device linked since, learned from the root's list — held it by the
  /// first-come rule, and is withdrawn now that it is known
  /// ([DevlistAlertKind.sharedWithMe]). Run whenever this device's own
  /// device set grows. No proof is needed for it: a device this account's
  /// own list names is this account's.
  Future<void> _withdrawClaimsOnMine() => _withLock('devlist', () async {
        final mine = {
          ..._myAccountRids,
          for (final d in await myFullDeviceList()) await d.routingId(),
        };
        final claimants = {
          for (final r in mine)
            if (_extraRidToContact[r] case final String c) c,
        };
        if (claimants.isEmpty) return;
        for (final c in claimants) {
          await _withdrawContactDeviceList(c,
              persist: true,
              alert: devlistAlertBody(DevlistAlertKind.sharedWithMe));
        }
        // What is sealed to my own devices is sealed to the keys my own list
        // gives them, whichever install wrote the map last.
        for (final d in await _myDevices()) {
          _sealKeys[await d.routingId()] = d.deviceXPub;
        }
      });

  /// ADR 0022: a contact just added, from a device whose code or request
  /// proves which account it is in ([_addedDeviceProven]), takes that device
  /// from another account's list that held it by the first-come rule alone
  /// — the claim that reached this device before the contact did. That list
  /// is withdrawn ([_withdrawContactDeviceList]) and the device recorded as
  /// the new contact's account's.
  ///
  /// Unawaited from [_onContactAdded]: it takes the install lock, and no
  /// caller of that is to wait on it from wherever it was.
  Future<void> _claimAddedDevice(Contact contact) async {
    final rid = contact.rid;
    final acct = base64Encode(contact.accountEd);
    if (!await _addedDeviceProven(contact)) return;
    await _withLock('devlist', () async {
      // Recorded under the contact's lock as well, which their deletion
      // takes: a deletion before this leaves nothing to record, and one
      // after it forgets what this records (as an install does).
      final held = await _withLock(rid, () async {
        if (!identical(contacts[rid], contact)) return false; // deleted
        if (_noteProven(rid, acct, inList: false)) await _saveProvenDevices();
        return true;
      });
      if (!held) return;
      final owner = _provenDevices[rid];
      if (owner != null && owner.acct != acct) return; // proven there first
      final holder = _extraRidToContact[rid];
      if (holder == null || holder == rid) return;
      final h = contacts[holder];
      if (h == null || base64Encode(h.accountEd) == acct) return;
      await _withdrawContactDeviceList(holder,
          persist: true,
          alert:
              devlistAlertBody(DevlistAlertKind.claimedDevice, {'with': rid}));
      _sealKeys[rid] = contact.bundle.xPub;
    });
  }

  /// Whether the device [c] was added from proves that it is in [c]'s
  /// account — which a code or request can show only by the device key
  /// signing a statement that names the account: the certificate it came
  /// with carries a proof of possession, or (ADR 0027) the code signed its
  /// post-quantum commitment, the device key's signature over the account's
  /// key. Only for a contact anchored to an account other than the device's
  /// own key (§18.7).
  ///
  /// A device-anchored code proves nothing here, though its key is "the
  /// account": a code's binding signature (§2.3) is made by every identity —
  /// a linked device on a build before §18.7 hands out exactly such a code
  /// for its own key — and anyone who has seen it can present it again, so
  /// it cannot tell a phone from somebody's linked device. In a LIST the
  /// same equality is a proof ([_carriesProof]): there the account key itself
  /// signed that device's certificate.
  Future<bool> _addedDeviceProven(Contact c) async {
    if (constantTimeEquals(c.bundle.edPub, c.accountEd)) return false;
    final cert = c.deviceCert;
    if (cert != null &&
        constantTimeEquals(cert.deviceEdPub, c.bundle.edPub) &&
        await cert.provesPossession(c.accountEd)) {
      return true;
    }
    return c.pqcSigned;
  }

  /// Test seam: which contact a device's routing id is held for as one of
  /// their other devices, if any.
  @visibleForTesting
  String? debugListedDeviceOwner(String deviceRid) =>
      _extraRidToContact[deviceRid];

  /// The contact a device belongs to, as a connect ceremony reveals it (ADR
  /// 0020): the contact added from that device, or the contact whose device
  /// list — as this device holds it, signed by their account — names it,
  /// provided that contact's account is [accountEdPub], the account the
  /// ceremony's digits covered. Null for anyone else.
  ///
  /// By the list and not by the account alone: a certificate an account
  /// signed proves the account once vouched for the device, not that it
  /// still does — a device dropped from the list keeps its certificate. The
  /// account is compared as [_deviceHeldElsewhere] compares accounts.
  Contact? contactForDevice(String deviceRid, Uint8List accountEdPub) {
    final direct = contacts[deviceRid];
    if (direct != null) return direct;
    final owner = _extraRidToContact[deviceRid];
    final c = owner == null ? null : contacts[owner];
    if (c == null || !constantTimeEquals(c.accountEd, accountEdPub)) {
      return null;
    }
    return c;
  }

  /// Test seam: run the gossip's judgement of [rid] now, as an inbound claim
  /// would — so a test can tell what it decides apart from when it happens
  /// to run (inbound post-processing is not ordered against the next
  /// envelope).
  @visibleForTesting
  Future<void> debugEvaluateContact(String rid) => _evaluateContact(rid);

  /// The floor's third level for [rid]'s account (ADR 0017 stage 2): whether
  /// the list held for it is v2-only — `sig3` alone. See the floor in
  /// [_installContactDeviceList]. A held row that does not parse is not
  /// evidence of anything, and the next list that verifies replaces it.
  Future<bool> _holdsV2OnlyListFor(String rid) async {
    final held = await vault.kvGet('cdev_$rid');
    if (held == null) return false;
    try {
      return SignedDeviceList.fromJson(
              (jsonDecode(held) as Map).cast<String, Object?>())
          .isV2Only;
    } catch (_) {
      return false;
    }
  }

  /// The routing ids of every device in a list.
  Future<Set<String>> _routingIdsOf(SignedDeviceList list) async {
    final out = <String>{};
    for (final d in list.devices) {
      out.add(await d.routingId());
    }
    return out;
  }

  /// A test seam: the store this method performs fails for real only when
  /// the disk is full or the database is gone, and the behaviour that depends
  /// on it — the ratchet put back, the envelope left with the relay — is the
  /// whole of finding 20. Building that world for real means breaking the
  /// vault under a live service, which is how a case ends up untested. It
  /// was.
  @visibleForTesting
  bool debugFailExtraStore = false;

  Future<void> _saveExtra(String rid) async {
    if (debugFailExtraStore) {
      throw StateError('debugFailExtraStore: the extra-device session store');
    }
    final s = _contactExtras[rid];
    if (s != null) {
      // Sealed: this is a live ratchet with a contact's non-primary
      // devices, same as `sync_session` (see `Vault.plainKeys`).
      //
      // The `$` was escaped here and interpolated at both read sites, so
      // every contact's session was written to one key literally named
      // `cextra_$rid` and no launch ever found one. Nothing was lost by it —
      // the account session is rebuilt from the contact's device
      // certificates, and a message in flight across a restart, out of order
      // or not, still decrypted when this was measured — but `_saveExtra`
      // did not do the one thing it exists to do, and every caller was
      // written believing it did. It is fixed in the same change as the
      // notice-and-hello above, on purpose: a stored session that has gone
      // stale is only safe to start restoring once a device whose chain
      // disagrees says so and repairs itself.
      await vault.kvPut('cextra_$rid', jsonEncode(s.toJson()));
    }
  }

  /// Fan a just-sent inner message out to a contact's non-primary devices.
  ///
  /// Through the durable outbox, like the copy to their primary device — not
  /// a direct `transport.send`, which this used to be. That had two costs.
  /// A send while the link was down threw and was swallowed, so the
  /// contact's laptop simply did not get the message from us (their phone
  /// mirrors it across when it has it, which is the only reason that was
  /// never noticed). And it ran INSIDE the per-conversation lock, awaiting
  /// the relay's ack — up to 20 s per device on a stalled link — while
  /// every send and receive for that contact queued behind it. The lock now
  /// covers the ratchet step and the writes; the network is the outbox's.
  Future<void> _fanToContactExtras(String rid, InnerMessage inner) async {
    // Cheap check first, exactly as before: a contact with no extra devices
    // — the common case — must not pay a lock acquisition per send just to
    // discover it has nothing to do.
    final held = _contactExtras[rid];
    if (held == null || held.targetRoutingIds.isEmpty) return;
    var queued = false;
    await _withLock(rid, () async {
      // Re-read under the lock, and only for a contact this vault still
      // holds: this runs unawaited after the primary send, so a deletion can
      // land in between, and the session object captured before it would
      // otherwise queue envelopes to their laptop and re-write `cextra_`
      // for someone who has been forgotten.
      final s = _contactExtras[rid];
      final contact = contacts[rid];
      if (s == null || contact == null || s.targetRoutingIds.isEmpty) return;
      try {
        await _decorateForWire(inner, contact);
        // A device only an unconfirmed list added gets nothing (ADR 0006):
        // the hold is what makes a split view cost the attacker something.
        final held = kt.heldRids(rid);
        // ADR 0029, per device: an incapable sibling of a capable contact is
        // left out of the `dl` claim (it names a list it cannot read, and it
        // would raise `missingUpdate`). Only when `dl` is actually present —
        // not withheld for the whole contact, not a kind that carries none —
        // and some device is behind is there anything to split; the common
        // case takes the single pass it always did.
        final strip = inner.data.containsKey('dl')
            ? <String>{
                for (final r in s.targetRoutingIds)
                  if (_withholdsClaimFromDevice(rid, r)) r
              }
            : const <String>{};
        final fan = strip.isEmpty
            ? await s.encrypt(inner.toBytes(), except: held)
            : [
                ...await s.encrypt(inner.toBytes(),
                    except: {...held, ...strip}),
                ...await s.encrypt(_withoutClaim(inner).toBytes(), except: {
                  ...held,
                  for (final r in s.targetRoutingIds)
                    if (!strip.contains(r)) r
                }),
              ];
        // Persist the advanced ratchet BEFORE the envelopes exist anywhere,
        // so a redelivery is still decryptable.
        await _saveExtra(rid);
        final now = _now();
        final rows = [
          for (final f in fan)
            {
              'id': newMessageId(),
              'rid': f.routingId,
              'payload': await _sealFor(f.routingId, f.payload),
              'created_ms': now,
            }
        ];
        await vault.db.transaction((txn) async {
          for (final r in rows) {
            await txn.insert('outbox', r);
          }
        });
        queued = rows.isNotEmpty;
      } catch (_) {}
    });
    if (queued) unawaited(flushOutbox());
  }

  /// Inbound from a contact's non-primary device.
  Future<void> _handleExtraInbound(
      String rid, String fromDeviceRid, String payload, RelayInbound m) async {
    final contact = contacts[rid];
    if (contact == null || _contactExtras[rid] == null) {
      transport.ackReceived(id: m.id, from: m.from);
      return;
    }
    InnerMessage? inner;
    String? offer;
    // The session as it was before the decrypt. Everything this method does
    // with `inner` below is a store, and the acknowledgement now waits for
    // all of it; if any of it throws, this is what puts the ratchet back so
    // the relay's redelivery can be decrypted.
    //
    // Taken INSIDE the lock, and the session read inside it too. Both used to
    // be read before it, so two envelopes from the same account arriving
    // together snapshotted the same pre-state and the second one's rollback
    // undid the first one's success.
    String snapshot = '';
    // What happened, decided per step rather than by one `catch (_) {}` over
    // the decrypt, the save and the parse. Those three want three different
    // answers and used to get one: silence, followed by an acknowledgement.
    const int kOk = 0, kUndecryptable = 1, kReplay = 2, kUnpersisted = 3;
    const int kWithheld = 4;
    int outcome = kOk;
    await _withLock(rid, () async {
      final s = _contactExtras[rid];
      if (s == null) {
        outcome = kReplay; // nothing to do, and nothing to report
        return;
      }
      snapshot = jsonEncode(s.toJson());
      final probe = _debugOnDecrypted;
      if (probe != null &&
          await _debugPeek(
              probe,
              'extra',
              fromDeviceRid,
              () async => (await AccountSession.fromJson(
                      await accountIdentity(),
                      (jsonDecode(snapshot) as Map).cast<String, Object?>(),
                      intervals: _pqIntervals))
                  .decryptFrom(fromDeviceRid, payload))) {
        outcome = kWithheld;
        return;
      }
      final DecryptResult dec;
      try {
        dec = await s.decryptFrom(fromDeviceRid, payload);
      } on RatchetReplayException {
        // Already consumed: the relay redelivering, or a replay. Nothing to
        // repair, so nothing is said. The subtype arm comes first.
        await _restoreExtra(rid, snapshot);
        outcome = kReplay;
        return;
      } on RatchetDecryptException {
        await _restoreExtra(rid, snapshot);
        outcome = kUndecryptable;
        return;
      } on UnknownSessionException {
        // Their device's session predates ours; nothing advanced.
        outcome = kUndecryptable;
        return;
      }
      try {
        await _saveExtra(rid);
      } catch (_) {
        // The ratchet advanced and could not be written down. This is the
        // case the single catch swallowed: it left the advanced session in
        // memory, unsaved, and then acknowledged — so the relay forgot a
        // message that was never stored, on a session that had moved on.
        await _restoreExtra(rid, snapshot);
        outcome = kUnpersisted;
        return;
      }
      try {
        inner = InnerMessage.fromBytes(dec.plaintext);
      } on FormatException {
        // Authenticated bytes this build cannot parse — a newer peer, or a
        // peer bug. The ratchet is saved and a redelivery would parse no
        // better, so it is acknowledged: `inner` stays null below.
        return;
      }
      offer = dec.pqOfferPayload;
    });
    if (outcome == kWithheld) {
      // A test withheld it (debugOnDecrypted): gone, as if never delivered.
      transport.ackReceived(id: m.id, from: m.from);
      return;
    }
    if (outcome == kUnpersisted) {
      // Leave the envelope with the relay. It is redelivered onto the session
      // that is now back in memory, and the store is attempted again.
      return;
    }
    if (outcome == kUndecryptable) {
      transport.ackReceived(id: m.id, from: m.from);
      // A contact's linked device whose chain no longer agrees with ours. The
      // hello goes to the ACCOUNT and fans out to every device on its list,
      // including this one, so it is the repair here too.
      await _noteUndecryptable(contact);
      notifyListeners();
      return;
    }
    // 30.3: this envelope's turn to be dispatched, taken before the first
    // await below, so turns go in the order the session decrypted the
    // envelopes ([_extraTurns]); it is waited for just before the dispatch,
    // and given up once that is done. A message is parsed only on the path
    // that reaches the dispatch.
    Future<void>? before;
    Completer<void>? turn;
    if (inner != null) {
      before = _extraTurns[rid];
      final t = turn = Completer<void>();
      _extraTurns[rid] = t.future;
    }
    if (offer != null) {
      // v2: our post-quantum key offer for that device — through the outbox,
      // with the durability the primary path gives its offer, so a link that
      // is down at this moment does not leave that device's session
      // classical until the next thing it says.
      try {
        await vault.db.insert('outbox', {
          'id': newMessageId(),
          'rid': fromDeviceRid,
          'payload': await _sealFor(fromDeviceRid, offer!),
          'created_ms': _now(),
        });
        unawaited(flushOutbox());
      } catch (_) {}
    }
    if (inner == null) {
      // A replay, or plaintext this build cannot parse. Either way a
      // redelivery would end here too.
      transport.ackReceived(id: m.id, from: m.from);
      return;
    }
    try {
      if (before != null) await before;
      await _dispatchExtraInner(contact, rid, fromDeviceRid, inner!);
    } catch (e) {
      if (_isTransientInboundFailure(e)) {
        // Put the ratchet back and leave the envelope with the relay, exactly
        // as the primary path does — the alternative is an acknowledged
        // message that was never stored.
        //
        // Not under the conversation's lock, and the WHOLE session: whatever
        // touched it since the snapshot — a fan-out's sending chains, an
        // install's target changes — is put back too. Known and not fixed
        // here; see the note in `_installContactDeviceListLocked`.
        await _restoreExtra(rid, snapshot, persist: true);
        return;
      }
      // Permanent: the ratchet was saved before dispatch (above) and the
      // content cannot be stored. Keep the saved ratchet and acknowledge,
      // rather than redeliver an envelope that will fail here every time.
      transport.ackReceived(id: m.id, from: m.from);
      return;
    } finally {
      final t = turn;
      if (t != null) {
        t.complete();
        if (identical(_extraTurns[rid], t.future)) _extraTurns.remove(rid);
      }
    }
    transport.ackReceived(id: m.id, from: m.from);
  }

  /// Put [rid]'s account session back to [snapshot].
  ///
  /// [persist] only when the advanced state reached the disk: after a failed
  /// decrypt it never did, and writing the same bytes back would be a write
  /// per undecryptable envelope for no change.
  Future<void> _restoreExtra(String rid, String snapshot,
      {bool persist = false}) async {
    _contactExtras[rid] = await AccountSession.fromJson(
        await accountIdentity(),
        (jsonDecode(snapshot) as Map).cast<String, Object?>(),
        intervals: _pqIntervals);
    if (persist) await _saveExtra(rid);
  }

  /// The stores an inner message from a contact's non-primary device implies.
  /// Separated from [_handleExtraInbound] so a failure anywhere in it is one
  /// catch, before the acknowledgement rather than after it.
  Future<void> _dispatchExtraInner(Contact contact, String rid,
      String fromDeviceRid, InnerMessage message) async {
    final inner = message;
    // 7.7a: a removal notice about my own account can ride here too.
    if (inner.kind == 'dlrm') {
      await _handleRemovalNotice(contact, inner);
    }
    // ADR 0026: and a question about the list I hold for their account,
    // asked by whichever of their devices saw my echo.
    if (inner.kind == 'pdlreq') {
      await _answerOwnListRequest(contact);
    }
    if (inner.kind == 'pqid') {
      // §18.2 on the extra-device path. A contact's linked device runs its own
      // sessions and holds its own commitment, so the exchange has to complete
      // here too — otherwise their laptop stays classical while their phone is
      // hybrid, and one account shows two safety numbers.
      try {
        if (await _onPqIdentity(contact, inner)) notifyListeners();
      } catch (_) {}
      // Answer to the ACCOUNT: `_sendInner` fans to every device on its list,
      // which now includes the one that just asked. The once-per-contact gate
      // is cleared first, because that device is newer than our offer — it is
      // asking precisely because it never saw it.
      if (inner.data['ack'] != true) {
        _pqSent.remove(contact.rid);
        _pqLastSentMs.remove(contact.rid);
        _offerPqIdentity(contact, _PqReason.volunteer);
      }
    }
    if (inner.kind == 'pqack' || _saysHoldsOurKey(inner)) {
      try {
        if (await _markPqAcked(contact)) notifyListeners(); // ADR 0021
      } catch (_) {}
    }
    if (contact.numberKey != null &&
        !contact.pqTold &&
        !(inner.kind == 'pqid' && inner.data['ack'] != true)) {
      _offerPqAck(contact); // ADR 0021, as on the primary path
    }
    if (inner.kind == 'dlpq') {
      await _onPqListSignature(contact, inner); // §18.9, extra-device path
    }
    // A message this device now holds from them (text, attachment, group or
    // not): theirs as one from their phone is — acknowledged to them,
    // counted unread, and read if the chat is open (below).
    var stored = false;
    if (inner.kind == 'devlist') {
      await _applyDevlistInner(contact, inner);
    } else if (inner.kind == 'text') {
      final fresh = !await _holdsMessage(rid, inner.mid);
      await _insertMirrored(rid, 'in', inner);
      if (fresh) _countUnread(rid);
      stored = true;
    } else if (inner.kind == 'gmsg') {
      // A group message sent from one of the contact's other devices carries
      // the same authority as their primary (the cert bound it to the account).
      await _persistGroupText(contact, inner, _now());
      notifyListeners();
      stored = true;
    } else if (inner.kind == 'file' && inner.data['fid'] is String) {
      // An attachment offered from the contact's other device: same as a
      // mirrored-in offer — record it, chunks arrive by fid.
      final fate = await _insertMirroredFile(rid, false, inner);
      if (fate == _OfferFate.fresh) _countUnread(rid);
      stored = fate != _OfferFate.refused;
    } else if (inner.kind == 'gfile' && inner.data['fid'] is String) {
      final fate = await vault.db.transaction(
          (txn) => _persistGroupFile(contact, inner, _now(), txn: txn));
      notifyListeners();
      if (fate == _OfferFate.fresh) {
        await _offerLanded(inner.data['fid'] as String);
      }
      stored = fate != _OfferFate.refused;
    } else if (inner.kind == 'edit' ||
        inner.kind == 'gedit' ||
        inner.kind == 'react' ||
        inner.kind == 'greact' ||
        inner.kind == 'timer' ||
        inner.kind == 'read' ||
        inner.kind == 'dlv') {
      // 30.3: an edit, reaction, timer or receipt from one of the contact's
      // other devices is the CONTACT's, exactly as `del` below: the same
      // persist step as their phone's, with them as the sender, so §6.6's
      // authorship rule (only the author edits), §6.5's (only a member
      // reacts, one reaction per person) and §6.3's (a receipt counts only
      // for their own chat, or a group they are in, once per person) hold
      // whichever of their devices it came from. Every one of them used to
      // be dropped here: an edit on a laptop left the old text on every
      // other device, a timer set there did not govern what came after, and
      // a message sent FROM a laptop was never marked delivered or read.
      await vault.db.transaction(
          (txn) => _persistInboundKind(txn, contact, inner, _now()));
      notifyListeners();
    } else if (inner.kind == 'del' || inner.kind == 'gdel') {
      // A delete-for-everyone from one of the contact's other devices is the
      // CONTACT's: their account wrote the messages it names, whichever of
      // their devices it was on, so §6.6's authorship rule is applied with
      // them as the sender — and through it §7's, so what it removes is the
      // attachment their message brought and nothing another member's
      // message merely names. It used to be dropped here, so a laptop's
      // delete left the file on every other member's device.
      await vault.db
          .transaction((txn) => _applyDelete(contact, inner, txn: txn));
      notifyListeners();
    } else if (inner.kind == 'ginvite' || inner.kind == 'gleave') {
      if (inner.kind == 'ginvite') {
        await _applyGroupInvite(contact.rid, inner.data);
      } else {
        await _applyGroupLeave(contact.rid, inner.data);
      }
      // Mirrored to my other devices, as the primary path mirrors one: a
      // contact's laptop that has not yet learned my laptop sends it nothing,
      // and a list my laptop never holds is one it would build on stale.
      unawaited(_sync?.mirror(threadRid: contact.rid, dir: 'in', inner: inner) ??
          Future<void>.value());
      notifyListeners();
    } else if (inner.kind == 'gsync') {
      _answerGroupSync(contact, inner.data);
    }
    if (stored) {
      // The E2E delivery receipt the primary path sends, to their whole
      // account — so the device that sent it, and their others, see it
      // delivered. A message sent from a linked device used to get none, from
      // anyone, and stayed at one tick on every device for good.
      _queueDeliveryReceipt(contact.rid, inner.mid);
      _readOnArrival(contact.rid, inner);
    }
    // ADR 0020, from another of a contact's devices: their answer to a
    // group link of mine — given on whichever of their devices opened it —
    // and the hello that asks me again for an answer I owe them, from
    // whichever of their devices made the link. Until 2026-10-03 both were
    // ignored here, so a contact who opened a link on their laptop never
    // joined, and the inviter was told a day later that the link had run
    // out. The answer is stored before this envelope is acknowledged; the
    // add runs after, as on the primary path, and a start-up finishes it if
    // this one does not.
    if (inner.kind == 'gjoin') {
      await vault.db.transaction((txn) => _onLinkJoin(contact, inner, txn));
      unawaited(_finishLinkAdds().catchError((Object _) {}));
    }
    if (inner.kind == 'hello') {
      await _answerLinkHello(contact.rid);
    }
    // 7.7a: observe the claim/echo after any devlist install above, so the
    // "held" list this cross-check compares against is current.
    await _observeDevlistGossip(rid, fromDeviceRid, inner);
    // ADR 0029: and what this device of theirs says it reads.
    await _noteReaderLevel(rid, fromDeviceRid, inner);
  }

  /// [primary]: the list came over the session with the device [contact] was
  /// added from — which alone may make that device's account the contact's
  /// ([_reanchorFromList]).
  Future<void> _applyDevlistInner(Contact contact, InnerMessage inner,
      {bool primary = false}) async {
    try {
      final list = SignedDeviceList.fromJson(
          (jsonDecode(inner.data['list'] as String) as Map)
              .cast<String, Object?>());
      // ADR 0026: a list for MY account is not theirs to install. It is
      // their answer to my question about an echo of theirs ('pdlreq') —
      // evidence, judged against this device's own records and installed
      // nowhere. (Every build refuses to install it anyway: it is not signed
      // by the contact's account key.)
      if (base64Encode(list.accountEdPub) ==
          base64Encode((await accountIdentity()).accountEdPub)) {
        await _onOwnListEvidence(contact, list);
        return;
      }
      if (primary) await _reanchorFromList(contact, list);
      if (!await _installContactDeviceList(contact, list, persist: true)) {
        // Refused: not this account's list, or not verifiable, or a replay of
        // a version already held. It said nothing, so the log is told nothing
        // — a refused list used to reset the transparency hold and restart
        // the grace all the same, which made "send a list the device will
        // throw away" a way to keep a held device alive.
        return;
      }
      // A list that arrived in-band is checked against the log soon, and the
      // devices it still contains keep whatever hold they were under.
      kt.noteContactListChanged(contact.rid,
          stillPresent: await _routingIdsOf(list));
    } catch (_) {}
  }

  /// Phase 33: a contact held as an account of its own — the device they
  /// were added from — becomes the account that device belongs to, when that
  /// account's list reaches this device over that device's own session and
  /// names it.
  ///
  /// Who that is: anyone who accepted a request a linked device sent before
  /// requests could name their account (§8.1), and anyone who scanned a
  /// linked device's code from before §18.7. Their safety number was
  /// computed against the laptop's key, so two people who compared numbers
  /// read different ones; and every list the account signed was refused as
  /// not this contact's, so its other devices were never reached. Nothing
  /// healed it.
  ///
  /// Why the list is enough. It verifies under the account's key, and so
  /// does its certificate for exactly this device — both keys — so the
  /// account vouches for the device; and it came over the session that
  /// device's own key authenticates, so the device vouches for the account.
  /// Whoever holds that key could already sign lists for the record as it
  /// stood, which named the device itself as the account, so nothing is
  /// handed to them that they did not hold. What moves is the safety
  /// number, onto the account's key — where the account's devices had it
  /// all along — and a tick given on the old number says so (13.3).
  ///
  /// Not for a record that holds a post-quantum commitment, or a candidate
  /// commitment (ADR 0027): each was taken over the identity as it stood,
  /// and moving the identity under it could turn a key that matches it into
  /// a refusal.
  Future<bool> _reanchorFromList(Contact contact, SignedDeviceList list) async {
    if (contact.accountEdPub != null) return false;
    if (contact.pqCommit != null || contact.pqcHint != null) return false;
    if (constantTimeEquals(list.accountEdPub, contact.bundle.edPub)) {
      return false; // its own list: the device is the account already
    }
    DeviceCertificate? cert;
    for (final d in list.devices) {
      if (!d.legacy &&
          constantTimeEquals(d.deviceEdPub, contact.bundle.edPub) &&
          constantTimeEquals(d.deviceXPub, contact.bundle.xPub)) {
        cert = d;
      }
    }
    if (cert == null || !await list.verify()) return false;
    final account = Uint8List.fromList(list.accountEdPub);
    final moved = await _withLock<bool>(contact.rid, () async {
      if (!identical(contacts[contact.rid], contact) ||
          contact.accountEdPub != null) {
        return false;
      }
      try {
        if (_disposed) return false;
        await vault.db.update(
            'contacts',
            {'acct_ed': b64(account), 'dev_cert': jsonEncode(cert!.toJson())},
            where: 'rid = ?',
            whereArgs: [contact.rid]);
      } catch (_) {
        return false;
      }
      contact.accountEdPub = account;
      contact.deviceCert = cert;
      return true;
    });
    if (!moved) return false;
    await _refreshVerification(contact.rid, notify: false);
    notifyListeners();
    return true;
  }

  // ------------------------------------------------------------------
  // 7.7a device-list transparency (gossip). See docs/adr/0001-key-transparency.md.
  // ------------------------------------------------------------------

  /// Load persisted alerts and per-contact claims at startup.
  Future<void> _loadDevlistState({Map<String, String>? kv}) async {
    Future<String?> get(String key) async =>
        kv != null ? kv[key] : await vault.kvGet(key);
    // ADR 0029: what each device that reads this account's lists has said
    // it reads, and whether the list held for this account is v2-only.
    Map<String, int> levels(String? stored) {
      if (stored == null) return {};
      try {
        return {
          for (final e in (jsonDecode(stored) as Map).entries)
            if (e.key is String && e.value is num)
              e.key as String: (e.value as num).toInt()
        };
      } catch (_) {
        return {}; // unreadable: each device says it again with its next message
      }
    }

    for (final rid in contacts.keys.toList()) {
      final l = levels(await get('cdl_dlr_$rid'));
      if (l.isNotEmpty) _readerLevels[rid] = l;
    }
    _ownReaderLevels
      ..clear()
      ..addAll(levels(await vault.kvGet('own_dlr')));
    try {
      final own = await vault.kvGet('own_list_json');
      _ownV2Only = own != null &&
          SignedDeviceList.fromJson(
                  (jsonDecode(own) as Map).cast<String, Object?>())
              .isV2Only;
    } catch (_) {
      _ownV2Only = false;
    }
    for (final rid in contacts.keys.toList()) {
      final a = await get('pql_alert_$rid');
      // An alert written by a build before 2026-09-13 is an English sentence
      // with the contact's name in it, stored unsealed. It is removed rather
      // than shown, because the name is the defect. The cost is that this
      // one clears on upgrade: [_observePqListClaim] raises it again the next
      // time that contact claims a signature this device does not hold and
      // the grace period passes, which is a delay rather than a loss — and
      // the alternative is keeping the name on disk to preserve a banner.
      if (a != null && isDevlistAlertBody(a)) {
        pqListAlerts[rid] = a;
      } else if (a != null) {
        await vault.kvDelete('pql_alert_$rid');
      }
      final sent = int.tryParse(await get('dlpq_sent_$rid') ?? '0') ?? 0;
      if (sent > 0) _dlpqSent[rid] = sent;
    }
    ownAccountAlert = await vault.kvGet('own_alert');
    removedDeviceAlert = await vault.kvGet('removed_alert');
    final ae = await vault.kvGet('own_alert_echo');
    if (ae != null && ae.contains('|')) {
      final i = ae.indexOf('|');
      _ownAlertEcho =
          (int.tryParse(ae.substring(0, i)) ?? 0, ae.substring(i + 1));
    }
    // What each banner stands on (ADR 0026). A banner an earlier build
    // raised has none recorded: it is shown, and dismissing it records
    // nothing — that build raised it on no evidence anyone could name.
    List<String> evidence(String? stored) {
      if (stored == null) return const [];
      try {
        return (jsonDecode(stored) as List).whereType<String>().toList();
      } catch (_) {
        return const [];
      }
    }

    _ownAlertEvidence
      ..clear()
      ..addAll(evidence(await vault.kvGet('own_alert_ev')));
    _removedAlertEvidence
      ..clear()
      ..addAll(evidence(await vault.kvGet('removed_alert_ev')));
    for (final rid in contacts.keys.toList()) {
      final a = await get('cdl_alert_$rid');
      if (a != null && isDevlistAlertBody(a)) {
        contactDevlistAlerts[rid] = a;
      } else if (a != null) {
        // As above; this one is re-raised by the next device-list check,
        // which runs on `devlistGrace`.
        await vault.kvDelete('cdl_alert_$rid');
      }
      final c = await get('cdl_claims_$rid');
      if (c == null) continue;
      final m = (jsonDecode(c) as Map).cast<String, Object?>();
      _contactClaims[rid] = {
        for (final e in m.entries)
          e.key: (
            v: ((e.value as Map)['v'] as num).toInt(),
            h: (e.value as Map)['h'] as String,
            mx: ((e.value as Map)['mx'] as num).toInt(),
          )
      };
    }
  }

  /// This device's authenticated (version, fingerprint) claim about its OWN
  /// account's device list. A root device records the exact value it signed; a
  /// linked device records what it learned by self-sync; before either, the
  /// baseline is version 1 over the device set this install knows locally.
  /// The claim this device makes about its own device list: (version,
  /// fingerprint). Stamped on every outgoing message and compared on every
  /// inbound one.
  ///
  /// Memoised, because the receive-side benchmark found it being recomputed
  /// per message — twice per inbound text, once for the gossip check and
  /// once for the delivery receipt's stamp — and for the common case, a
  /// single-device account that has never signed a list, "recomputed" meant
  /// eleven vault reads and an Ed25519 signature over its own certificate:
  /// 13.8 ms alone, ~40 ms under contention. The answer changes only when
  /// the device list does, and every path that changes it calls
  /// [_forgetOwnListClaim].
  (int, String)? _ownClaimMemo;

  Future<(int, String)> _ownListClaim() async {
    final memo = _ownClaimMemo;
    if (memo != null) return memo;
    final vs = await vault.kvGet('own_list_v');
    final hs = await vault.kvGet('own_list_h');
    if (vs != null && hs != null) {
      return _ownClaimMemo = (int.parse(vs), hs);
    }
    final v = await _myDevlistVersion();
    return _ownClaimMemo =
        (v, b64(await deviceListFingerprint(v, await myFullDeviceList())));
  }

  void _forgetOwnListClaim() => _ownClaimMemo = null;

  /// Test seam: a test that rewrites the own-list keys in the vault behind
  /// the service's back (to simulate a device that never learned its list)
  /// has to say so, or the memo answers for the state it replaced.
  @visibleForTesting
  void forgetOwnListClaim() => _forgetOwnListClaim();

  /// Record [list] as this device's knowledge of its own account. Returns
  /// false, and records nothing, when its version is already recorded under
  /// another fingerprint: a version keeps the list it was first recorded
  /// with (§19.8). Overwriting it is how a device came to judge its own
  /// genuine entry in the log as one it never issued.
  Future<bool> _recordOwnList(SignedDeviceList list) async {
    final fp = b64(await list.fingerprint());
    if (_ownVersionRecordedOtherwise(list.version, fp)) return false;
    await vault.kvPut('own_list_v', '${list.version}', sensitive: false);
    await vault.kvPut('own_list_h', fp, sensitive: false);
    // 7.7b self-monitoring: a list this device signed or learned is one the
    // log may hold without alarm; any other entry for this account is not.
    await kt.recordOwnList(list.version, fp);
    // AFTER the writes, not before. Forgetting first left a window in which
    // a send or receive interleaved at an await recomputed the claim from
    // the old keys and cached it again, and the new list was then never
    // seen — devlist_distribution_test.dart flaked one run in three on it.
    _forgetOwnListClaim();
    // The blob itself, so a device that cannot SIGN a list can still hand
    // over the one its account signed. See [_shareableDeviceList].
    await vault.kvPut('own_list_json', jsonEncode(list.toJson()),
        sensitive: false);
    _ownV2Only = list.isV2Only; // ADR 0029: what the outbound path reads
    return true;
  }

  /// The newest verified (version, fingerprint) this device holds for a
  /// contact's account. Falls back to the baseline: version 1 over the single
  /// account-key device from their verified contact code.
  Future<(int, String)> _heldClaimFor(Contact c) async {
    final stored = await vault.kvGet('cdev_${c.rid}');
    if (stored != null) {
      final list = SignedDeviceList.fromJson(
          (jsonDecode(stored) as Map).cast<String, Object?>());
      return (list.version, b64(await list.fingerprint()));
    }
    return (
      1,
      b64(await deviceListFingerprint(1, [c.deviceCert ?? _legacyCertOf(c)]))
    );
  }

  /// Stamp an outgoing inner with our own-list claim ('dl') and an echo of the
  /// recipient's list ('pdl'), and (ADR 0029) with what this device reads
  /// ('dlr'). Ignored by v1 clients; observed by v2 ones.
  /// Best-effort: the transparency gossip must never break a send, so a failure
  /// to read local state (e.g. a vault closing on shutdown) just omits it.
  Future<void> _decorateForWire(InnerMessage inner, Contact contact) async {
    // ADR 0029: which device-list shape this device reads — on every message,
    // so a device that updates says so with the next one. Before the try
    // below and not inside it: it reads no state that can fail, and a
    // message that went out without it would tell its reader "an older
    // build" ([_readerLevelOf]).
    if (debugPreAdr0029) {
      inner.data.remove('dlr');
    } else {
      inner.data['dlr'] = devlistReaderLevel;
    }
    try {
      final (v, h) = await _ownListClaim();
      // Set or cleared per recipient, as `pqh` below: one inner can go to
      // several (a group).
      if (_withholdsClaimFrom(contact.rid)) {
        inner.data.remove('dl');
      } else {
        inner.data['dl'] = {'v': v, 'h': h};
      }
      final (pv, ph) = await _heldClaimFor(contact);
      inner.data['pdl'] = {'v': pv, 'h': ph};
      // §18.9: "I have SENT you my post-quantum list signature at this
      // version." Stamped only after delivery, so a claim with no signature
      // behind it means the envelope was lost or removed — not that the
      // sender is an older build, which says nothing here and is accused of
      // nothing. It rides inside the ratchet, so an attacker who drops the
      // signature cannot strip the evidence that they did.
      //
      // Read from memory: this is the outbound path of every message, and a
      // database round trip per send to fetch a number that changes once per
      // device-list version is not a trade worth making.
      final sent = _dlpqSent[contact.rid] ?? 0;
      if (sent > 0) inner.data['pql'] = sent;
      // ADR 0021, 26.2: "I hold your post-quantum key" — what a `pqack` says
      // — on every message, so the fact cannot be lost with one envelope.
      // `pq_told` is set when a `pqack` is QUEUED, not when it arrives (no
      // sender can know that), so one lost at the relay left the pair on two
      // numbers for good while "Waiting for them" promised they would match.
      // Set or cleared per recipient: one inner can go to several (a group).
      if (!debugPreAdr0021 && contact.numberKey != null) {
        inner.data['pqh'] = 1;
      } else {
        inner.data.remove('pqh');
      }
    } catch (_) {
      // Leave the message undecorated; gossip resumes on the next send.
    }
  }

  /// [inner] with its own-list claim (`dl`) taken off, for a recipient device
  /// withheld from per [_withholdsClaimFromDevice]. A shallow copy: the `data`
  /// map is new so the original — fanned to this contact's capable devices —
  /// keeps its claim. Everything else is the original's, the disappearing
  /// timer included: a copy without it would keep for good, on that device, a
  /// message its sender set to go.
  InnerMessage _withoutClaim(InnerMessage inner) => InnerMessage(
        kind: inner.kind,
        mid: inner.mid,
        ts: inner.ts,
        ttlSec: inner.ttlSec,
        data: {...inner.data}..remove('dl'),
      );

  /// Test seam: [list] as if this device's root had self-synced it — the
  /// one way a list for this account reaches a device that cannot sign one.
  @visibleForTesting
  Future<void> debugApplyOwnDeviceList(SignedDeviceList list) =>
      _applyOwnDeviceList(_devlistInner(jsonEncode(list.toJson())));

  /// A linked device keeps its root's bundle when the root sends it beside
  /// the account's list (`rootb`, phase 33): checked against that list,
  /// which this device has just verified under its own account's key — the
  /// bundle must be the list's root device's, the device whose key IS the
  /// account key, binding that device's own ratchet key.
  Future<void> _learnRootBundle(
      Object? raw, SignedDeviceList list, AccountIdentity me) async {
    if (raw is! Map || me.holdsAccountRoot) return;
    try {
      final root = ContactBundle.fromJson(raw.cast<String, Object?>());
      DeviceCertificate? rootCert;
      for (final d in list.devices) {
        if (constantTimeEquals(d.deviceEdPub, me.accountEdPub)) rootCert = d;
      }
      if (rootCert == null ||
          !await isRootBundle(root, me.accountEdPub, rootCert)) {
        return;
      }
      final json = jsonEncode(ContactBundle(
              edPub: root.edPub, xPub: root.xPub, bindingSig: root.bindingSig)
          .toJson());
      if (await vault.kvGet(rootBundleKey) == json) return;
      await vault.kvPut(rootBundleKey, json);
    } catch (_) {
      // Not a bundle: requests go out as this device's own until one comes.
    }
  }

  /// A linked device applies the account's latest signed list, self-synced from
  /// the root device (rule 8), keeping its own-account version in step.
  Future<void> _applyOwnDeviceList(InnerMessage inner) async {
    try {
      final list = SignedDeviceList.fromJson(
          (jsonDecode(inner.data['list'] as String) as Map)
              .cast<String, Object?>());
      final me = await accountIdentity();
      if (base64Encode(list.accountEdPub) != base64Encode(me.accountEdPub)) {
        return;
      }
      if (!await list.verify()) return;
      await _learnRootBundle(inner.data['rootb'], list, me);
      final knownV = await _myDevlistVersion();
      if (list.version < knownV) {
        // My root just sent an OLDER list than this device already holds. An
        // honest root never regresses (it re-asserts its newest signed list),
        // so the newer list this device holds was signed by someone else
        // holding the account key — the split-view attacker answering this
        // device's own request, or a device enrolled behind the root's back.
        //
        // Raised on that list and the version held (ADR 0026): the list
        // verified under this account's key above, and only this account's
        // own devices can send on this channel. The same older list
        // re-asserted at every reconnect is the same evidence, so a banner
        // the user dismissed does not come back for it.
        await _raiseOwnAccountAlert(
            ownAlertBody(OwnAlertKind.olderList,
                {'sent': list.version, 'held': knownV}),
            olderListEvidence(
                list.version, b64(await list.fingerprint()), knownV));
        return;
      }
      if (list.version == knownV &&
          b64(await list.fingerprint()) == (await _ownListClaim()).$2) {
        return; // already hold exactly this list (a reconnect re-assertion)
      }
      // A version this device already holds under another fingerprint is not
      // adopted: it keeps the list it was first recorded with (§19.8). Two
      // lists at one version are not something an honest root signs, and the
      // record kept is what lets this device's monitor of the log notice the
      // other one.
      if (_ownVersionRecordedOtherwise(
          list.version, b64(await list.fingerprint()))) {
        return;
      }
      final others = [
        for (final d in list.devices)
          if (base64Encode(d.deviceEdPub) != base64Encode(me.deviceEdPub)) d
      ];
      await vault.kvPut(
          'my_devices', jsonEncode([for (final d in others) d.toJson()]),
          sensitive: false);
      await vault.kvPut('my_devlist_version', '${list.version}',
          sensitive: false);
      await _recordOwnList(list); // which forgets the memo after its writes
      await _initSync();
      // A contact's list that named a device of mine this device had not
      // learned yet held it by the first-come rule; it does not now.
      await _withdrawClaimsOnMine();
      // ADR 0022: a list that names this device without its proof is one the
      // root has not had the proof for.
      await _offerOwnPop();
      // ADR 0029: a newer list from my root — the one that first names this
      // device, when it has just been linked — and the devices it names hear
      // what this one reads. The announcement at connect can reach a root
      // that has not yet added this device, and is then lost.
      final sync = _sync;
      if (sync != null) {
        unawaited(sync.announce().then((_) {}, onError: (Object _) {}));
      }
      // Catching up may resolve a pending owner-echo (the normal-update case),
      // or explain an alert already raised while the root was unreachable: if
      // the list that raised it is consistent with what the root just sent,
      // it was an honest update this device had merely missed.
      await _clearOwnAlertIfExplained();
      await _reevaluateDevlistPending();
      notifyListeners();
    } catch (_) {}
  }

  /// Test seam: this device models a build from before ADR 0022 — it never
  /// hands its proof of possession to its root, and as a root it takes none
  /// ([_offerOwnPop], [_applyDevicePop]). Reading a proof, and holding lists
  /// to the receiver's rules, is unchanged: that is what an older build
  /// cannot do and this one can whatever it models.
  @visibleForTesting
  bool debugNoDevicePop = false;

  bool _popOffering = false;

  /// ADR 0022, migration: a linked device's proof of possession can only be
  /// made by the device — the root, holding the account's key and not this
  /// device's, cannot make one — so the device hands its own to the root,
  /// over the self-sync channel (§9, `dir:"pop"`), and every list the root
  /// signs from then on carries it ([myFullDeviceList]).
  ///
  /// Sent when the account's list this device holds names it without a
  /// proof: on a device linked before ADR 0022, at the first start of a
  /// build with it; on a device linked since, when the root's first list
  /// naming it arrives; and after a restored root's list lost it. Once per
  /// list version (`pop_sent_v`), so a root that ignores it — one from
  /// before ADR 0022 — is not asked again until its list moves. Device #1
  /// needs none: its certificate is its own key's signature.
  Future<void> _offerOwnPop() async {
    if (debugNoDevicePop || _popOffering) return;
    _popOffering = true;
    try {
      final me = await accountIdentity();
      if (me.isAccountKeyDevice) return;
      final sync = _sync;
      final held = await vault.kvGet('own_list_json');
      if (sync == null || held == null) return; // no list yet to compare
      final list = SignedDeviceList.fromJson(
          (jsonDecode(held) as Map).cast<String, Object?>());
      if (!constantTimeEquals(list.accountEdPub, me.accountEdPub)) return;
      final listed = list.devices
          .where((d) => constantTimeEquals(d.deviceEdPub, me.deviceEdPub));
      // Not on its account's list: removed, or not listed yet.
      if (listed.isEmpty) return;
      if (await listed.first.provesPossession(me.accountEdPub)) return;
      final sentFor = int.tryParse(await vault.kvGet('pop_sent_v') ?? '');
      if (sentFor != null && sentFor >= list.version) return;
      await sync.mirror(
          threadRid: '',
          dir: 'pop',
          inner: InnerMessage(
              kind: 'devpop',
              mid: newMessageId(),
              ts: _now(),
              data: {'pop': b64(await me.devicePop())}));
      await vault.kvPut('pop_sent_v', '${list.version}');
    } catch (_) {
      // Best effort: the next list this device learns asks again.
    } finally {
      _popOffering = false;
    }
  }

  /// ADR 0022, migration, the root's half: a linked device's proof of
  /// possession, handed over self-sync by the device itself — the channel
  /// authenticates it, and the proof must verify for this account and for
  /// the certificate the root holds for THAT device, or it is not kept. Kept
  /// beside the certificate (`my_devices`), so every list the root signs
  /// from then on carries it.
  ///
  /// What that costs the list depends on the transparency log, which is
  /// keyed by version and takes each version once (§19.5: a re-publish of
  /// the held version is refused, 409 `stale_version`). A proof sits outside
  /// every signature and the fingerprint (§3.1), so the current version
  /// signed again with it is the same list — and a contact that learns the
  /// list from the log learns whatever copy of the version the log took. If
  /// that copy lacks the proof, the contact holds the device unproven and a
  /// first-come squatter on its keys keeps it there, with the genuine list
  /// refused whole ([_judgeListClaims]): exactly what the proof exists to
  /// stop (an independent review of handles, 2026-10-09). So:
  ///
  /// - the version this root is holding back from the log for this device
  ///   ([_popHold], set when [hostDeviceLink] links it): the held version is
  ///   signed again with the proof and published now, for the first time —
  ///   no version moves, which is the common case of a device just linked;
  /// - a version the log has already acknowledged: the list moves to the
  ///   next version, which carries the proof to the log
  ///   ([_supersedeOwnList]) — a device linked by a build that held nothing
  ///   back, or whose proof came after the hold ran out;
  /// - otherwise — the publish still queued, or no log — the current version
  ///   is signed again with the proof, which replaces a queued publish.
  ///
  /// A queued publish that the log acknowledges while this runs is the one
  /// case the second leaves to the log check, which compares what the log
  /// holds for the current version with the proofs held here and moves the
  /// version when they differ ([_onOwnLatestFromLog]); so does every account
  /// whose root applied proofs before this was built. In-band the proof
  /// reaches a new contact with the hello, a contact whose echo shows it
  /// behind — among them one that refused the list because another's claim
  /// held the device there first, which the proof now overrules — and this
  /// account's own devices, whose copy is what one of them hands a contact
  /// added from it.
  ///
  /// Idempotent: a proof already held for the device applies nothing and
  /// moves no version, so a device that re-offers costs one extra offer, not
  /// an unbounded climb.
  Future<void> _applyDevicePop(String fromDeviceRid, InnerMessage inner) async {
    if (debugNoDevicePop) return;
    final me = await accountIdentity();
    if (!me.holdsAccountRoot) return; // only a root's lists carry it
    final raw = inner.data['pop'];
    if (raw is! String) return;
    final Uint8List pop;
    try {
      pop = unb64(raw);
    } catch (_) {
      return;
    }
    final applied = await _withOwnListLock(() async {
      final devices = await _myDevices();
      for (var i = 0; i < devices.length; i++) {
        if (await devices[i].routingId() != fromDeviceRid) continue;
        final held = devices[i].pop;
        if (held != null && constantTimeEquals(held, pop)) return false;
        final proven = devices[i].withPop(pop);
        if (!await proven.provesPossession(me.accountEdPub)) return false;
        devices[i] = proven;
        await vault.kvPut(
            'my_devices', jsonEncode([for (final d in devices) d.toJson()]),
            sensitive: false);
        return true;
      }
      return false;
    });
    if (!applied || debugNoProofRepublish) return;
    final hold = _popHold;
    if (hold != null && hold.rid == fromDeviceRid) _releasePopHold();
    final json = await _signCurrentDeviceList(); // publishes unless the log has it
    if (json == null || hold?.rid == fromDeviceRid) return;
    final list = SignedDeviceList.fromJson(
        (jsonDecode(json) as Map).cast<String, Object?>());
    if (await kt.ownPublishAcknowledged(
        list.version, b64(await list.fingerprint()))) {
      await _supersedeOwnList(list.version);
    }
  }

  /// Test seam: this root applies a proof the way 4.2.0 did — kept beside the
  /// certificate, nothing signed or published for it — so a test can build
  /// the log copy that lacks it, as every account that ran 4.2.0 has.
  @visibleForTesting
  bool debugNoProofRepublish = false;

  /// How long [hostDeviceLink] holds a just-linked device's first version back
  /// from the transparency log for the device's proof of possession, which it
  /// hands over within seconds of its first start. Past it the version is
  /// published without the proof, and a proof that comes later moves the
  /// list to the next version ([_applyDevicePop]). Tests shorten it.
  @visibleForTesting
  Duration popPublishHold = const Duration(minutes: 2);

  /// The device [hostDeviceLink] is holding the list's log publish back for:
  /// its Ed25519 key (b64), its routing id, and until when.
  ({String edPub, String rid, DateTime until})? _popHold;
  Timer? _popHoldTimer;

  /// Whether the log publish of [listJson] waits for the held device's proof
  /// ([KeyTransparency.holdOwnPublish]): only while the hold runs, and only
  /// for a list that names that device without one.
  bool _holdsOwnPublish(String listJson) {
    final hold = _popHold;
    if (hold == null) return false;
    if (!DateTime.now().isBefore(hold.until)) {
      _releasePopHold();
      return false;
    }
    try {
      final devs = (jsonDecode(listJson) as Map)['devs'] as List;
      for (final d in devs) {
        final m = d as Map;
        if (m['ded'] == hold.edPub) return m['pop'] == null;
      }
    } catch (_) {
      // Not a list this can read: nothing to hold it for.
    }
    return false;
  }

  /// Ends the hold. The timer's end publishes the version as it stands.
  void _releasePopHold() {
    _popHold = null;
    _popHoldTimer?.cancel();
    _popHoldTimer = null;
  }

  /// Cross-check the claim ('dl') and echo ('pdl') carried by an inbound inner
  /// from [deviceRid] of contact [rid].
  Future<void> _observeDevlistGossip(
      String rid, String deviceRid, InnerMessage inner) async {
    if (!contacts.containsKey(rid)) return;
    // Best-effort: never let a transparency cross-check throw out of the
    // inbound path (e.g. the vault closing during shutdown/restart).
    try {
      final dl = inner.data['dl'];
      if (dl is Map && dl['v'] is num && dl['h'] is String) {
        await _observeContactClaim(
            rid, deviceRid, (dl['v'] as num).toInt(), dl['h'] as String);
      }
      final pdl = inner.data['pdl'];
      if (pdl is Map && pdl['v'] is num && pdl['h'] is String) {
        await _observeOwnEcho(
            rid, (pdl['v'] as num).toInt(), pdl['h'] as String);
      }
    } catch (_) {
      // Transient (closed vault, malformed member): skip this observation.
    }
  }

  Future<void> _observeContactClaim(
      String rid, String deviceRid, int v, String h) async {
    final claims = _contactClaims.putIfAbsent(rid, () => {});
    final prev = claims[deviceRid];
    final mx = prev == null ? v : (prev.mx > v ? prev.mx : v);
    claims[deviceRid] = (v: v, h: h, mx: mx);
    await _saveClaims(rid);
    await _evaluateContact(rid);
  }

  /// Owner rule: a contact echoes the list it holds for MY account. A version
  /// higher than this device knows, or the same version with a different
  /// fingerprint, would mean a device holding my account key issued a list
  /// this device never saw (T1/T2) — IF the contact can show the list.
  ///
  /// The echo itself is a claim (ADR 0026): two numbers any contact can type,
  /// and until 2026-10-04 typing them was enough to put "reset your identity
  /// now" on this device's screen, again after every dismissal. So the echo
  /// is never the alarm. It is a reason to ask the contact for the list
  /// behind it ([_askForOwnList]); the list, which verifies under my
  /// account's key or does not, is the evidence ([_onOwnListEvidence]), and
  /// the alarm is raised on it after the grace — so a normal bump seen before
  /// my own self-sync arrives still does not cry wolf.
  Future<void> _observeOwnEcho(String rid, int echoV, String echoH) async {
    final (knownV, knownH) = await _ownListClaim();
    if (echoV < knownV) {
      // They hold an older list than mine: they never got the current one
      // (added after a device was linked, or a broadcast was lost). Hand it
      // over — self-healing distribution. Never an alarm.
      _pendingOwnerEcho.remove(rid);
      await _maybeResendDeviceList(rid);
      return;
    }
    if (echoV == knownV && echoH == knownH) {
      _pendingOwnerEcho.remove(rid);
      return;
    }
    // Ahead of, or beside, what this device holds. A linked device asks its
    // root for the account's current list whatever comes of the echo: if it
    // simply missed an honest update, the answer arrives inside the grace
    // and settles this.
    await _requestOwnDeviceList();
    if (echoV <= knownV && kt.ownListKnown(echoV, echoH)) {
      // A list this device holds as its own at that version — one the
      // own-list repair reconciled (ADR 0026).
      _pendingOwnerEcho.remove(rid);
      return;
    }
    _pendingOwnerEcho[rid] = (
      v: echoV,
      h: echoH,
      seen: _pendingOwnerEcho[rid]?.seen ?? DateTime.now()
    );
    await _askForOwnList(rid, echoV, echoH);
    await _reevaluateDevlistPending();
  }

  /// ADR 0026: ask [rid] for the list it holds for my account — the one its
  /// echo ([v], [h]) named. At most [_maxOwnListAsks] questions per contact
  /// per [ownEvidenceWindow], and never the same echo twice in one: a
  /// contact echoing nonsense with every message buys a handful of
  /// questions, and the relay sees a handful of envelopes.
  Future<void> _askForOwnList(String rid, int v, String h) async {
    final contact = contacts[rid];
    if (contact == null) return;
    final now = _now();
    var asked = _ownListAsked[rid];
    if (asked == null ||
        now - asked.atMs >= ownEvidenceWindow.inMilliseconds) {
      asked = (atMs: now, asked: <(int, String)>{});
    }
    _ownListAsked[rid] = asked;
    final echo = (v, h);
    if (asked.asked.contains(echo) ||
        asked.asked.length >= _maxOwnListAsks) {
      return;
    }
    asked.asked.add(echo);
    try {
      await _sendInner(
          contact, InnerMessage.ownListRequest(newMessageId(), now, v: v, h: h));
    } catch (_) {
      // Best-effort: with no question asked, no answer comes, and an echo
      // with no list behind it raises nothing.
    }
  }

  /// ADR 0026: one of [contact]'s devices asks for the list this device
  /// holds for their account. The answer is that list, exactly as their
  /// account signed it, in an ordinary `devlist` — they verify it under their
  /// own key and tell it from a list of mine by its `acct`. It goes to their
  /// whole account, so at most [_maxOwnListAsks] answers go to one account in
  /// a window, whichever of its devices asks. A device holding only the
  /// baseline (their contact code's one device) has nothing signed to hand
  /// over, and says nothing.
  Future<void> _answerOwnListRequest(Contact contact) async {
    final rid = contact.rid;
    final now = _now();
    final prev = _ownListAnswered[rid];
    final fresh =
        prev == null || now - prev.atMs >= ownEvidenceWindow.inMilliseconds;
    final n = fresh ? 0 : prev.n;
    if (n >= _maxOwnListAsks) return;
    _ownListAnswered[rid] = (atMs: fresh ? now : prev.atMs, n: n + 1);
    final held = await vault.kvGet('cdev_${contact.rid}');
    if (held == null) return;
    try {
      await _sendInner(contact, _devlistInner(held));
    } catch (_) {}
  }

  /// ADR 0026: [contact] handed over a list for MY account — the answer to a
  /// question this device asked about their echo. The list is the evidence:
  /// it verifies under my account's key, or it is nothing.
  ///
  /// Weighed only when it is the list an echo of theirs named — one this
  /// device asked them about in the window, or the one it is still waiting
  /// on — and at most [_maxOwnListJudged] per contact per window: verifying
  /// lists is work, and a contact does not get to order it in bulk by
  /// sending answers nobody asked for. Holding the answer to the echo also
  /// keeps what a contact can present to the lists an echo can raise a
  /// question about, ahead of or beside this device's own: not some old list
  /// of the account's, dug up to be judged against records that may not
  /// reach back that far.
  Future<void> _onOwnListEvidence(
      Contact contact, SignedDeviceList list) async {
    final rid = contact.rid;
    // The version first, and the fingerprint only of a list that verified:
    // nothing is computed from a list before it is admitted.
    if (!_askedAbout(rid, list.version) ||
        !_judgeBudget(rid) ||
        !await list.verify()) {
      _refusedOwnEvidence(rid);
      return;
    }
    final fp = b64(await list.fingerprint());
    if (!_askedAbout(rid, list.version, fp)) {
      _refusedOwnEvidence(rid);
      return;
    }
    if (await _ownListExplained(list.version, fp)) {
      // A list this device holds as its own, or one it cannot judge: the
      // echo was honest, or is not this device's to call.
      _pendingOwnerEcho.remove(rid);
      _ownEvidence.remove(rid);
      return;
    }
    final prev = _ownEvidence[rid];
    _ownEvidence[rid] = (
      v: list.version,
      fp: fp,
      since: prev != null && prev.v == list.version && prev.fp == fp
          ? prev.since
          : DateTime.now()
    );
    await _reevaluateDevlistPending();
  }

  /// Whether ([v], [fp]) — a list for my account that verified under its key
  /// — is explained by this device's own records: its current claim; a list
  /// it signed, learned or reconciled at a version it has reached; one from
  /// before it knew the account; or, on a linked device, a version below its
  /// own that it never saw (it learns by self-sync and may skip some). Only
  /// an unexplained list is evidence of one issued behind this device's
  /// back. (A version above the claim is never explained by the record:
  /// nothing honest records a version without moving the claim to it.)
  Future<bool> _ownListExplained(int v, String fp) async {
    final (knownV, knownH) = await _ownListClaim();
    if (v == knownV && fp == knownH) return true;
    if (v <= knownV && kt.ownListKnown(v, fp)) return true;
    if (kt.ownVersionBeforeMyTime(v)) return true;
    if (v < knownV && !kt.ownVersionRecorded(v) && !await holdsAccountRoot()) {
      return true;
    }
    return false;
  }

  /// Whether an echo from [rid] at version [v] — with fingerprint [fp], when
  /// given — is one this device asked them about in the current window, or
  /// the one of theirs it is still waiting on.
  bool _askedAbout(String rid, int v, [String? fp]) {
    bool named(int ev, String eh) => ev == v && (fp == null || eh == fp);
    final asked = _ownListAsked[rid];
    if (asked != null &&
        _now() - asked.atMs < ownEvidenceWindow.inMilliseconds &&
        asked.asked.any((e) => named(e.$1, e.$2))) {
      return true;
    }
    final pending = _pendingOwnerEcho[rid];
    return pending != null && named(pending.v, pending.h);
  }

  /// One more list from [rid] verified this window, if the budget allows.
  bool _judgeBudget(String rid) {
    final now = _now();
    final prev = _ownListJudged[rid];
    final fresh =
        prev == null || now - prev.atMs >= ownEvidenceWindow.inMilliseconds;
    final n = fresh ? 0 : prev.n;
    if (n >= _maxOwnListJudged) return false;
    _ownListJudged[rid] = (atMs: fresh ? now : prev.atMs, n: n + 1);
    return true;
  }

  /// The quiet diagnostic (ADR 0026): something [rid] sent about my account
  /// had nothing my account's key signed behind it. Counted; never shown.
  void _refusedOwnEvidence(String rid) =>
      ownEvidenceRefused[rid] = (ownEvidenceRefused[rid] ?? 0) + 1;

  /// Raise [ownAccountAlert] ([body]) on [evidence] — unless the user
  /// dismissed it for that evidence, or it already stands on it. A banner
  /// already up keeps its words and takes the new evidence too, so that
  /// dismissing it dismisses everything it was showing.
  Future<void> _raiseOwnAccountAlert(String body, String evidence,
      {(int, String)? echo}) async {
    if (kt.dismissals.contains(evidence)) return;
    if (_ownAlertEvidence.contains(evidence)) return;
    ownAccountAlert ??= body;
    _ownAlertEvidence.add(evidence);
    if (echo != null &&
        (_ownAlertEcho == null || echo.$1 >= _ownAlertEcho!.$1)) {
      _ownAlertEcho = echo;
      await vault.kvPut('own_alert_echo', '${echo.$1}|${echo.$2}',
          sensitive: false);
    }
    await vault.kvPut('own_alert', ownAccountAlert!, sensitive: false);
    await vault.kvPut('own_alert_ev', jsonEncode(_ownAlertEvidence));
    notifyListeners();
  }

  /// Clear [ownAccountAlert] — not dismiss it: the user decided nothing —
  /// once every list it stands on is one this device can now explain: its
  /// root's later answer, or the own-list repair, accounted for it. A banner
  /// standing on an older list from the root stays; that is not explained by
  /// anything this device learns. One an earlier build raised has no
  /// evidence recorded, and is judged, as it always was, by the echo kept
  /// beside it.
  Future<void> _clearOwnAlertIfExplained() async {
    if (ownAccountAlert == null) return;
    if (_ownAlertEvidence.isEmpty) {
      final echo = _ownAlertEcho;
      if (echo == null || !await _ownListExplained(echo.$1, echo.$2)) return;
      await _clearOwnAccountAlert();
      return;
    }
    for (final e in _ownAlertEvidence) {
      final parts = e.split('|');
      final v = parts.length == 3 && parts[0] == 'list'
          ? int.tryParse(parts[1])
          : null;
      if (v == null || !await _ownListExplained(v, parts[2])) return;
    }
    await _clearOwnAccountAlert();
  }

  Future<void> _clearOwnAccountAlert() async {
    ownAccountAlert = null;
    _ownAlertEcho = null;
    _ownAlertEvidence.clear();
    await vault.kvDelete('own_alert');
    await vault.kvDelete('own_alert_echo');
    await vault.kvDelete('own_alert_ev');
    notifyListeners();
  }

  /// Whether [list] is evidence that this device was removed from its own
  /// account (ADR 0026): a list for the account that verifies under its key,
  /// does not name this device, and is at a version above the one this
  /// device holds. A list from before this device was linked omits it too —
  /// anyone holding the account's public key can read those from the log —
  /// which is what the version is for.
  ///
  /// So the version held has to be one this device learned: a list it
  /// signed, or its root's list naming it. A device just linked has learned
  /// none until its root's list reaches it — its claim meanwhile is a
  /// stand-in at version 1, which every list the account signed before it
  /// is above, the log's latest among them, read by the check that runs the
  /// moment it starts. It is told nothing until it holds one.
  Future<bool> _isRemovalEvidence(SignedDeviceList list) async {
    final me = await accountIdentity();
    if (base64Encode(list.accountEdPub) != base64Encode(me.accountEdPub)) {
      return false;
    }
    final mine = base64Encode(me.deviceCert.deviceEdPub);
    if (list.devices.any((d) => base64Encode(d.deviceEdPub) == mine)) {
      return false;
    }
    final held = int.tryParse(await vault.kvGet('own_list_v') ?? '');
    if (held == null || list.version <= held) return false;
    return list.verify();
  }

  /// Raise [removedDeviceAlert] on the list ([v], [fp]) that removed this
  /// device — unless dismissed for it, or already standing on it. A newer
  /// removal replaces the version shown.
  Future<void> _raiseRemoved(int v, String fp) async {
    final evidence = removalEvidence(v, fp);
    if (kt.dismissals.contains(evidence)) return;
    if (_removedAlertEvidence.contains(evidence)) return;
    _removedAlertEvidence.add(evidence);
    final shownV = removedDeviceAlert == null
        ? null
        : _storedVersion(removedDeviceAlert!);
    if (shownV == null || v >= shownV) {
      removedDeviceAlert = ownAlertBody(OwnAlertKind.removed, {'v': v});
    }
    await vault.kvPut('removed_alert', removedDeviceAlert!, sensitive: false);
    await vault.kvPut('removed_alert_ev', jsonEncode(_removedAlertEvidence));
    notifyListeners();
  }

  /// The `v` of a stored removal banner, or null for one an earlier build
  /// wrote as a sentence.
  static int? _storedVersion(String stored) {
    try {
      final d = jsonDecode(stored);
      return d is Map && d['v'] is num ? (d['v'] as num).toInt() : null;
    } catch (_) {
      return null;
    }
  }

  /// The log's latest entry for this account, opened and verified (ADR
  /// 0026) — handed over by every check of the log that reads one.
  ///
  /// It is how a removed device learns it was removed when no contact tells
  /// it: the account's own statement, in the log, that it is no longer on
  /// the list. And on a root it finishes the own-list repair: when the
  /// latest entry is one the repair reconciled — this root's own list,
  /// signed at the version it claims but over another device set — the log,
  /// and every contact that took the list from it, hold a list other than
  /// the one this root claims, and the root moves to the next version.
  Future<void> _onOwnLatestFromLog(SignedDeviceList list,
      {required bool reconciled}) async {
    try {
      if (await _isRemovalEvidence(list)) {
        await _raiseRemoved(list.version, b64(await list.fingerprint()));
      }
      // A banner raised from a contact's copy of a list the repair has just
      // reconciled — the gossip can get there before the log check does.
      await _clearOwnAlertIfExplained();
      if (reconciled && await holdsAccountRoot()) {
        final (v, h) = await _ownListClaim();
        if (list.version >= v && b64(await list.fingerprint()) != h) {
          unawaited(_supersedeOwnList(list.version)
              .then((_) {}, onError: (_) {}));
        }
      }
      // ADR 0022: the log's copy of the current version lacks a proof of
      // possession this root holds — applied after the log took the version,
      // by a build that published nothing for it (every root that ran 4.2.0),
      // or acknowledged while a copy carrying it was still queued
      // ([_applyDevicePop]). A contact that reads the list from the log would
      // hold that device unproven, so the list moves to the next version,
      // which carries every proof held here.
      if (!reconciled && !debugNoProofRepublish && await holdsAccountRoot()) {
        final (v, h) = await _ownListClaim();
        if (list.version == v &&
            b64(await list.fingerprint()) == h &&
            await _lacksHeldProof(list)) {
          unawaited(_supersedeOwnList(list.version)
              .then((_) {}, onError: (_) {}));
        }
      }
    } catch (_) {
      // A check of the log must not be taken down by what it hands over.
    }
  }

  /// Whether [list] — the log's copy of this account's current version —
  /// names a device without the proof of possession this root holds for it.
  Future<bool> _lacksHeldProof(SignedDeviceList list) async {
    final logged = {for (final d in list.devices) b64(d.deviceEdPub): d.pop};
    for (final d in await _myDevices()) {
      final pop = d.pop;
      if (pop == null) continue;
      final k = b64(d.deviceEdPub);
      if (!logged.containsKey(k)) continue;
      final inLog = logged[k];
      if (inLog == null || !constantTimeEquals(inLog, pop)) return true;
    }
    return false;
  }

  /// The own-list repair's last step, on a root (ADR 0026): move past the
  /// reconciled version [above] to the next one with the current device set
  /// — signed, recorded and published once — and hand it to this account's
  /// devices and its contacts, as the ADR 0010 and 0017 migrations moved.
  /// The version moves rather than being re-signed because a version keeps
  /// the list it was first recorded with (§19.8).
  bool _superseding = false;
  Future<void> _supersedeOwnList(int above) async {
    if (_superseding) return;
    _superseding = true;
    try {
      final moved = await _withOwnListLock(() async {
        if (await _myDevlistVersion() > above) return false;
        await vault.kvPut('my_devlist_version', '${above + 1}',
            sensitive: false);
        _forgetOwnListClaim();
        return true;
      });
      if (!moved) return;
      final data = await _signCurrentDeviceList();
      if (data == null) return;
      unawaited(_selfSyncDeviceList(data).then((_) {}, onError: (_) {}));
      for (final rid in contacts.keys.toList()) {
        final c = contacts[rid];
        if (c == null) continue;
        unawaited(
            _sendInner(c, _devlistInner(data)).then((_) {}, onError: (_) {}));
      }
    } finally {
      _superseding = false;
    }
  }

  Future<void> _evaluateContact(String rid) async {
    final claims = _contactClaims[rid];
    final contact = contacts[rid];
    if (claims == null || claims.isEmpty || contact == null) return;
    final (heldV, heldH) = await _heldClaimFor(contact);

    final byVersion = <int, Set<String>>{};
    var maxV = 0;
    var rollback = false;
    for (final c in claims.values) {
      (byVersion[c.v] ??= <String>{}).add(c.h);
      if (c.v > maxV) maxV = c.v;
      if (c.v < c.mx) rollback = true;
    }
    String? conflict;
    for (final hs in byVersion.values) {
      if (hs.length > 1) {
        conflict = 'disagree';
        break;
      }
    }
    conflict ??= rollback ? 'rollback' : null;
    if (conflict == null) {
      for (final c in claims.values) {
        if (c.v == heldV && c.h != heldH) {
          conflict = 'split';
          break;
        }
      }
    }
    if (conflict != null) {
      _pendingContact.remove(rid);
      await _setContactAlert(rid, _conflictMsg(conflict));
      return;
    }

    // Their last list was refused for naming a device held for another
    // account (§3.4), and the banner says so, naming both. Their devices go on
    // claiming that list, so the deferred case below would replace the banner,
    // after the grace, with "the update never arrived" — the same refusal
    // seen from the gossip, and saying less — and agreement would clear it.
    // It stands until their next list installs or the user dismisses it.
    if (isSharedDeviceAlert(contactDevlistAlerts[rid])) {
      _pendingContact.remove(rid);
      return;
    }

    // Deferred (grace) cases:
    //   maxV < heldV → I hold a list newer than any of their devices admits to
    //     (a split view handed to me / T2).
    //   maxV > heldV → a device claims a newer list and the broadcast that
    //     would install it never arrived.
    if (maxV != heldV) {
      final since = _pendingContact.putIfAbsent(rid, () => DateTime.now());
      if (DateTime.now().difference(since) >= devlistGrace) {
        _pendingContact.remove(rid);
        await _setContactAlert(
            rid,
            devlistAlertBody(maxV < heldV
                ? DevlistAlertKind.unconfirmed
                : DevlistAlertKind.missingUpdate));
      } else {
        _scheduleDevlistRecheck();
      }
    } else {
      _pendingContact.remove(rid);
      await _setContactAlert(rid, null);
    }
  }

  /// Re-run the deferred checks after the grace period.
  Future<void> _reevaluateDevlistPending() async {
    if (_disposed) return;
    try {
      await _reevaluateDevlistPendingInner();
    } catch (_) {
      // Vault closed or similar: the checks re-run on the next inbound event.
    }
  }

  Future<void> _reevaluateDevlistPendingInner() async {
    final now = DateTime.now();
    var anyPending = false;

    final (knownV, knownH) = await _ownListClaim();
    // Echoes (ADR 0026) are claims. One that what this device now holds
    // explains is settled; one it does not waits, for the grace, for the
    // list it was asked about — and then goes, raising nothing. An echo is
    // never the alarm.
    for (final key in _pendingOwnerEcho.keys.toList()) {
      final ec = _pendingOwnerEcho[key]!;
      final consistent = ec.v < knownV ||
          (ec.v == knownV && ec.h == knownH) ||
          (ec.v <= knownV && kt.ownListKnown(ec.v, ec.h));
      if (consistent) {
        _pendingOwnerEcho.remove(key);
      } else if (_ownEvidence.containsKey(key)) {
        // The list behind it is in hand, and judged below.
      } else if (now.difference(ec.seen) >= devlistGrace) {
        _pendingOwnerEcho.remove(key);
        _refusedOwnEvidence(key);
      } else {
        anyPending = true;
      }
    }
    // Evidence: a list my account's key signed that this device cannot
    // explain. Raised after the grace an echo always had — a linked device's
    // root may yet send it the list — unless what this device has learned
    // since explains it. The banner stands on the list, so that dismissing
    // it is dismissing that list, and the strongest such list is what lets
    // an honest root's later answer clear it (`_applyOwnDeviceList`).
    for (final key in _ownEvidence.keys.toList()) {
      final ev = _ownEvidence[key]!;
      if (await _ownListExplained(ev.v, ev.fp)) {
        _ownEvidence.remove(key);
        _pendingOwnerEcho.remove(key);
      } else if (now.difference(ev.since) >= devlistGrace) {
        _ownEvidence.remove(key);
        _pendingOwnerEcho.remove(key);
        await _raiseOwnAccountAlert(ownAlertBody(OwnAlertKind.unissued),
            unissuedEvidence(ev.v, ev.fp),
            echo: (ev.v, ev.fp));
      } else {
        anyPending = true;
      }
    }

    for (final rid in _pendingContact.keys.toList()) {
      await _evaluateContact(rid);
      if (_pendingContact.containsKey(rid)) anyPending = true;
    }
    if (anyPending) _scheduleDevlistRecheck();
    notifyListeners();
  }

  /// When the pending re-check is currently due, so a later request cannot
  /// push an earlier one back.
  DateTime? _devlistDueAt;

  void _scheduleDevlistRecheck() {
    if (_disposed) return;
    final due =
        DateTime.now().add(devlistGrace + const Duration(milliseconds: 200));
    // A re-check already scheduled SOONER covers this one. Blindly
    // cancelling and re-arming made the fuse a function of the last request
    // rather than the first, so one contact's steady traffic could push out
    // the re-check that another contact's echo was waiting for — the
    // `unissued` alert, "somebody is showing my contacts a device list I
    // never signed", delayed for as long as anyone kept talking. The
    // per-entry grace is measured from when each was first seen, so the
    // earliest deadline is the one that matters. `_offerPqIdentity` bounds
    // its own re-sends the same way and for the same reason.
    final pending = _devlistTimer;
    if (pending != null &&
        pending.isActive &&
        _devlistDueAt != null &&
        !_devlistDueAt!.isAfter(due)) {
      return;
    }
    pending?.cancel();
    _devlistDueAt = due;
    _devlistTimer = Timer(devlistGrace + const Duration(milliseconds: 200),
        () {
      _devlistDueAt = null;
      unawaited(_reevaluateDevlistPending());
    });
  }

  /// A contact told this device it was dropped from its own account's list.
  ///
  /// The notice is a claim (ADR 0026). Until 2026-10-04 its `acct` alone put
  /// "this device was removed … reset your identity" on the screen: any
  /// contact, or any member of a group this device is in, could send one,
  /// and send it again after every dismissal. Now the banner needs the list
  /// that removed this device — signed by the account's key, not naming this
  /// device, at a version above the one it holds ([_isRemovalEvidence]) —
  /// which a current contact carries in the notice. A notice with none,
  /// which is what a contact on an earlier build sends, is not evidence: it
  /// moves this device's own look at the log forward, where the account's
  /// list would be, at most once per [ownEvidenceWindow].
  Future<void> _handleRemovalNotice(Contact contact, InnerMessage inner) async {
    try {
      final acctB64 = inner.data['acct'];
      if (acctB64 is! String) return;
      final me = await accountIdentity();
      if (acctB64 != b64(me.accountEdPub)) return; // not about my account
      final carried = inner.data['list'];
      if (carried is! String) {
        _refusedOwnEvidence(contact.rid);
        final now = _now();
        if (now - _ownCheckNudgedMs >= ownEvidenceWindow.inMilliseconds) {
          _ownCheckNudgedMs = now;
          unawaited(kt.checkOwn());
        }
        return;
      }
      if (!_judgeBudget(contact.rid)) {
        _refusedOwnEvidence(contact.rid);
        return;
      }
      final list = SignedDeviceList.fromJson(
          (jsonDecode(carried) as Map).cast<String, Object?>());
      if (!await _isRemovalEvidence(list)) {
        _refusedOwnEvidence(contact.rid);
        return;
      }
      await _raiseRemoved(list.version, b64(await list.fingerprint()));
    } catch (_) {
      // A notice that does not parse is not evidence of anything.
      _refusedOwnEvidence(contact.rid);
    }
  }

  Future<void> _saveClaims(String rid) async {
    final claims = _contactClaims[rid];
    if (claims == null) return;
    await vault.kvPut(
        'cdl_claims_$rid',
        jsonEncode({
          for (final e in claims.entries)
            e.key: {'v': e.value.v, 'h': e.value.h, 'mx': e.value.mx}
        }),
        sensitive: false);
  }

  Future<void> _setContactAlert(String rid, String? msg) async {
    if (msg == null) {
      contactDevlistAlerts.remove(rid);
      await vault.kvDelete('cdl_alert_$rid');
    } else {
      contactDevlistAlerts[rid] = msg;
      await vault.kvPut('cdl_alert_$rid', msg, sensitive: false);
    }
  }

  String _conflictMsg(String kind) => devlistAlertBody(kind == 'rollback'
      ? DevlistAlertKind.rollback
      : DevlistAlertKind.conflict);

  /// The version of the device list this device believes is current for its OWN
  /// account. Exposed for diagnostics and tests.
  Future<int> ownDeviceListVersion() async => (await _ownListClaim()).$1;

  /// The version of the newest device list this device holds for [rid]'s
  /// account (1 = the baseline single-device list). Exposed for tests.
  Future<int> heldContactListVersion(String rid) async {
    final c = contacts[rid];
    if (c == null) return 0;
    return (await _heldClaimFor(c)).$1;
  }

  /// Dismiss a contact's device-list banner (until a new inconsistency arises).
  Future<void> acknowledgeContactDevlistAlert(String rid) async {
    await _setContactAlert(rid, null);
    notifyListeners();
  }

  /// The user dismissed [ownAccountAlert]: it stays dismissed for the
  /// evidence it stood on — the same list echoed again, the same older list
  /// re-asserted, before or after a restart, raises nothing — and new
  /// evidence raises it again (ADR 0026). Until 2026-10-04 the next echo
  /// raised it again, whatever it carried.
  Future<void> acknowledgeOwnAccountAlert() async {
    for (final e in _ownAlertEvidence) {
      await kt.dismissals.add(e);
    }
    await _clearOwnAccountAlert();
  }

  /// The user dismissed [removedDeviceAlert]: dismissed for the removal it
  /// stood on, as above. The same list heard again — another contact's
  /// notice, the log's copy — raises nothing; a later list without this
  /// device is a new removal and does.
  Future<void> acknowledgeRemovedDeviceAlert() async {
    for (final e in _removedAlertEvidence) {
      await kt.dismissals.add(e);
    }
    removedDeviceAlert = null;
    _removedAlertEvidence.clear();
    await vault.kvDelete('removed_alert');
    await vault.kvDelete('removed_alert_ev');
    notifyListeners();
  }

  /// Full local wipe: identity, contacts, messages, keys. Irreversible.
  ///
  /// 42.4: everything the service runs on its own clock stops first — the
  /// sweep, the retries, the log's and the handle's clocks — and a sweep
  /// already running is waited for, so nothing it started reads or writes
  /// the vault while the vault is being deleted.
  ///
  /// 42.2: the pickers' copies go too. They are not in the vault's
  /// directory but in the app's cache, where nothing here used to look, so a
  /// copy a pick had left there survived "Wipe everything". One that cannot
  /// be deleted fails the wipe, as a file left in the vault's directory
  /// does ([Vault.wipe]): the screen ends the process on the strength of
  /// this returning.
  Future<void> wipeEverything() async {
    _stopClocks(); // no sweep, retry, publish or drain may start under it
    await transport.stop();
    final sweeping = _sweeping;
    if (sweeping != null) {
      try {
        await sweeping;
      } catch (_) {
        // Its failure does not matter now: everything it touched goes next.
      }
    }
    final cache = await pickerCacheDir();
    final left =
        cache == null ? const <String>[] : await sweepPickerCopies(cache);
    await vault.wipe();
    if (left.isNotEmpty) {
      throw StateError('wipe left ${left.length} picker copy(ies) in the '
          'app cache: the device is not clean');
    }
  }
}

/// A default file name for a recorded voice note, from its container mime.
String _voiceNoteName(String mime) {
  final ext = switch (mime) {
    'audio/mp4' || 'audio/aac' || 'audio/m4a' => 'm4a',
    'audio/ogg' || 'audio/opus' => 'ogg',
    'audio/wav' || 'audio/x-wav' => 'wav',
    _ => 'bin',
  };
  return 'voice-${DateTime.now().millisecondsSinceEpoch}.$ext';
}

/// mm:ss display for a voice-note duration.
String describeDuration(int seconds) {
  final m = seconds ~/ 60, s = seconds % 60;
  return '$m:${s.toString().padLeft(2, '0')}';
}

int? firstIntValue(List<Map<String, Object?>> rows) {
  if (rows.isEmpty) return null;
  final v = rows.first.values.first;
  return v is int ? v : (v is num ? v.toInt() : null);
}

/// Why a post-quantum identity is being sent (§18.2); see
/// `ChatService._offerPqIdentity`.
enum _PqReason { volunteer, nudge, answer }

/// What became of an attachment offer (PROTOCOL §7), wherever it arrived.
enum _OfferFate {
  /// Stored, with its placeholder: chunks may now be fanned and assembled.
  fresh,

  /// The same offer again through another door — a linked device's mirror of
  /// one this device also had directly — and already stored. Nothing new,
  /// and nothing wrong: it is receipted and mirrored exactly as before.
  again,

  /// Refused: malformed, larger than the product limit, a chunk count its
  /// size does not imply, or a file id this device holds for another
  /// message, or a message id this conversation already holds. Nothing is
  /// stored, and nothing is receipted, mirrored or assembled on its account.
  refused,
}

/// An attachment offer's members (`file`, or `gfile` plus `gid`), checked.
///
/// Every one of them is the sender's say-so, and the receiver used to take
/// `size` and `chunks` as given: a 24 MiB offer declaring a million chunks
/// was stored, every chunk that then arrived for it was kept, and a file
/// assembled to whatever its chunks added up to, whatever the offer said.
/// The key material is checked for length here because an offer whose key
/// cannot open its own chunks is one that will never complete.
class _FileOffer {
  final String fid;
  final String name;
  final int size;
  final String mime;
  final String sha256;
  final String fk;
  final String fn;
  final int chunks;
  final bool voice;
  final int durSec;
  const _FileOffer(this.fid, this.name, this.size, this.mime, this.sha256,
      this.fk, this.fn, this.chunks, this.voice, this.durSec);

  /// The offer in [d], or null when §7 says no receiver may accept it.
  static _FileOffer? read(Map<String, Object?> d) {
    final fid = d['fid'], size = d['size'], chunks = d['chunks'];
    final sha = d['sha256'], fk = d['fk'], fn = d['fn'];
    if (fid is! String || !isWellFormedFid(fid)) return null;
    if (size is! int || size < 0 || size > maxAttachmentBytes) return null;
    if (chunks is! int || chunks != fileChunkCount(size)) return null;
    if (sha is! String || fk is! String || fn is! String) return null;
    try {
      if (unb64(sha).length != 32 ||
          unb64(fk).length != 32 ||
          unb64(fn).length != 16) {
        return null;
      }
    } catch (_) {
      return null;
    }
    final name = d['name'], mime = d['mime'], dur = d['dur'];
    return _FileOffer(
        fid,
        name is String ? name : 'file',
        size,
        mime is String ? mime : 'application/octet-stream',
        sha,
        fk,
        fn,
        chunks,
        d['voice'] == true,
        dur is num && dur > 0 ? dur.toInt() : 0);
  }

  /// The sealed `files.enc_meta` of a received offer: what the earlier
  /// builds stored, member for member.
  Map<String, Object?> get meta => {
        'name': name,
        'size': size,
        'mime': mime,
        'sha256': sha256,
        'fk': fk,
        'fn': fn,
        if (voice) 'voice': true,
        if (durSec > 0) 'dur': durSec,
      };

  FileMeta get fileMeta => FileMeta(
        fid: fid,
        name: name,
        size: size,
        mime: mime,
        sha256b64: sha256,
        totalChunks: chunks,
        voice: voice,
        durSec: durSec,
      );
}

/// What a tick becomes when the number moves (13.3): its new state, and —
/// when a connect ceremony had already covered the key the number moves to
/// (26.3) — the number it now stands on, which is written with the key.
typedef _Tick = ({VerificationState state, String? moveTo});

/// A `ginvite`'s fields as [ChatService._parseList] read them.
class _WireList {
  final String name;
  final int ver;
  final int rv;
  final String? owner;
  final List<String>? admins;
  final List<Object?> members;
  final String digest;

  /// ADR 0030: the group's timer as the list states it (`tmr`), or null.
  final int? tmr;

  /// ADR 0030: [Group.stateDigestOf] of the list as it travels.
  final String stateDigest;
  const _WireList({
    required this.name,
    required this.ver,
    required this.rv,
    required this.owner,
    required this.admins,
    required this.members,
    required this.digest,
    required this.tmr,
    required this.stateDigest,
  });

  /// Whether this list is newer than [o], both from one sender: the higher
  /// roles version, then the higher version, then the smaller digest — the
  /// order `ChatService._notNewer` applies between one issuer's lists — and
  /// at equal digests the smaller state digest (ADR 0030).
  bool newerThan(_WireList o) {
    if (rv != o.rv) return rv > o.rv;
    if (ver != o.ver) return ver > o.ver;
    final c = digest.compareTo(o.digest);
    if (c != 0) return c < 0;
    return stateDigest.compareTo(o.stateDigest) < 0;
  }
}

/// What `ChatService._judgeListClaims` decided about a device list's devices
/// (§3.4, ADR 0022): refused — with the alert to raise for a list that
/// arrived, or none — or installed, with the routing ids of the devices it
/// proves and the contacts whose lists it takes a device from.
class _ClaimVerdict {
  final bool refused;
  final String? alert;
  final Set<String> proven;
  final Set<String> evict;

  const _ClaimVerdict.refuse(this.alert)
      : refused = true,
        proven = const {},
        evict = const {};

  const _ClaimVerdict.install({required this.proven, required this.evict})
      : refused = false,
        alert = null;
}
