/// The transparency log's client (PROTOCOL.md §19, ADR 0006): what this
/// device does with the log — checks every contact's device list against it,
/// publishes its own, monitors its own label, and decides, per contact, one
/// of the states ADR 0006's table names. The verification itself is
/// `package:z_protocol`'s `transparency.dart`; this file fetches, persists,
/// schedules, and applies the policy.
///
/// The policy, in one paragraph. A head is accepted only when it is signed
/// by the pinned key, extends the last accepted head (a consistency proof),
/// and agrees with the witness if one is configured — anything else is a
/// **log fault**, after which nothing new is confirmed until the user resets
/// the log's history in Settings. Under an accepted head, a contact whose
/// held list matches the log is **confirmed**; one the log knows nothing of
/// is **unlogged** (an older client — gossip only, as before); one whose log
/// entry is newer has the newer list fetched, opened, verified and installed
/// (the log as a source, 11.5); one whose held list is newer than the log's
/// is **unconfirmed**, and after the grace period the devices only that list
/// added stop receiving messages; the same version with a different
/// fingerprint, or a log entry that does not verify, is a **conflict**, and
/// messages to that contact are held until the user says otherwise. The log
/// being unreachable degrades to in-band verification and says so after a
/// day; the grace period runs regardless.
///
/// How the log is asked (phase 35, `kt_private_lookups.dart`). Contacts are
/// checked by bucket, never by label: one `POST /kt/v1/buckets` carries the
/// bucket of every contact and this install's decoys, and an entry whose
/// value is needed is fetched by index among decoys. The account's own label
/// is still asked for by name — its history is only served that way, and the
/// log learns the account key at publish anyway. A refresh runs at a random
/// moment in each window, never at start and never because a contact's list
/// changed; a log that refuses buckets is unreachable to this client, with no
/// fallback to asking by name.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:flutter/foundation.dart';
import 'package:z_protocol/z_protocol.dart';

import 'alarm_evidence.dart';
import 'kt_private_lookups.dart';
import 'vault.dart';

/// Build-time defaults. The production log's key is set with
/// `--dart-define=KT_LOG_PUB=<base64>` (and the witness likewise) once the
/// log is live; an empty key means no log is configured and the client is
/// inert — `tool/check_ga.py` refuses G3 a tick while it is empty.
const String defaultKtLogUrl =
    String.fromEnvironment('KT_LOG_URL', defaultValue: 'https://kt.zmessengers.com');
const String defaultKtLogPub = String.fromEnvironment('KT_LOG_PUB',
    defaultValue: '7nyv9LNKMfr9u3QrfSRUBsP+g/jZapwI3uxfklIU7xA=');
const String defaultKtWitnessUrl = String.fromEnvironment('KT_WITNESS_URL', defaultValue: '');
const String defaultKtWitnessPub = String.fromEnvironment('KT_WITNESS_PUB', defaultValue: '');

/// A configuration that cannot be saved. [reason] is an l10n key, not a
/// sentence: this is core, and core does not decide what language the user
/// reads. The screen that catches it renders the word.
class KtConfigInvalid implements Exception {
  final String reason;
  KtConfigInvalid(this.reason);
  @override
  String toString() => 'KtConfigInvalid($reason)';
}

/// Where the log is and which key signs it. Persisted in the vault under
/// `kt_config`; absent, the build-time defaults apply.
class KtConfig {
  final String logUrl;
  final String logPubB64;
  final String witnessUrl;
  final String witnessPubB64;

  const KtConfig({
    required this.logUrl,
    required this.logPubB64,
    this.witnessUrl = '',
    this.witnessPubB64 = '',
  });

  static const KtConfig defaults = KtConfig(
    logUrl: defaultKtLogUrl,
    logPubB64: defaultKtLogPub,
    witnessUrl: defaultKtWitnessUrl,
    witnessPubB64: defaultKtWitnessPub,
  );

  static const KtConfig off = KtConfig(logUrl: '', logPubB64: '');

  Uint8List? get logPub => _key(logPubB64);
  Uint8List? get witnessPub => _key(witnessPubB64);
  bool get enabled => logUrl.trim().isNotEmpty && logPub != null;

  /// A witness is an address AND a key this device pinned.
  ///
  /// This used to be the address alone. A self-hoster who set a witness URL
  /// and left the key empty got a check that appears in the UI, sets
  /// `witnessOkMs`, and has zero assurance in it: with no key to compare
  /// against, the co-signature was verified against the key inside the record
  /// itself, so whoever answers that URL — the log's own operator included —
  /// co-signs agreement with any head the log serves. The point of a witness
  /// is that it is somebody else; a key that arrived with the answer is not
  /// somebody else.
  bool get hasWitness => witnessUrl.trim().isNotEmpty && witnessPub != null;

  /// Why this configuration cannot be saved, or null. Half a witness is not
  /// a weaker witness, so it is refused rather than quietly ignored — being
  /// quietly ignored is how somebody ends up believing they have one.
  String? get witnessProblem {
    final hasUrl = witnessUrl.trim().isNotEmpty;
    final hasKey = witnessPubB64.trim().isNotEmpty;
    if (!hasUrl && !hasKey) return null;
    if (hasUrl && !hasKey) return 'urlWithoutKey';
    if (!hasUrl && hasKey) return 'keyWithoutUrl';
    if (witnessPub == null) return 'keyNotValid';
    return null;
  }

  static Uint8List? _key(String b) {
    if (b.trim().isEmpty) return null;
    try {
      final k = unb64(b.trim());
      return k.length == 32 ? k : null;
    } on FormatException {
      return null;
    }
  }

  Map<String, Object?> toJson() => {
        'url': logUrl,
        'pub': logPubB64,
        'wurl': witnessUrl,
        'wpub': witnessPubB64,
      };

  static KtConfig fromJson(Map<String, Object?> j) => KtConfig(
        logUrl: (j['url'] as String?) ?? '',
        logPubB64: (j['pub'] as String?) ?? '',
        witnessUrl: (j['wurl'] as String?) ?? '',
        witnessPubB64: (j['wpub'] as String?) ?? '',
      );
}

/// A minimal HTTP surface, so tests can stand in for the network.
abstract class KtFetcher {
  Future<KtResponse> get(Uri url);
  Future<KtResponse> post(Uri url, String jsonBody);
}

class KtResponse {
  final int status;
  final String body;
  KtResponse(this.status, this.body);
  Map<String, Object?> get json => (jsonDecode(body) as Map).cast<String, Object?>();
}

/// `dart:io` over TLS; no third-party HTTP dependency in the app.
class HttpKtFetcher implements KtFetcher {
  final Duration timeout;
  HttpKtFetcher({this.timeout = const Duration(seconds: 15)});

  static const int _maxBody = 4 * 1024 * 1024;

  Future<KtResponse> _run(Future<HttpClientRequest> Function(HttpClient c) open,
      {String? body}) async {
    final client = HttpClient()..connectionTimeout = timeout;
    try {
      final req = await open(client).timeout(timeout);
      req.headers.set(HttpHeaders.acceptHeader, 'application/json');
      if (body != null) {
        req.headers.contentType = ContentType.json;
        req.write(body);
      }
      final res = await req.close().timeout(timeout);
      final chunks = <int>[];
      await for (final c in res.timeout(timeout)) {
        chunks.addAll(c);
        if (chunks.length > _maxBody) throw const HttpException('response too large');
      }
      return KtResponse(res.statusCode, utf8.decode(chunks));
    } finally {
      client.close(force: true);
    }
  }

  @override
  Future<KtResponse> get(Uri url) => _run((c) => c.getUrl(url));

  @override
  Future<KtResponse> post(Uri url, String jsonBody) =>
      _run((c) => c.postUrl(url), body: jsonBody);
}

/// ADR 0006's per-contact states. `logAhead` never persists: within one
/// check it becomes `confirmed` (the list installed) or `conflict`.
enum KtContactState { unlogged, confirmed, unconfirmed, conflict }

/// The log as a whole.
enum KtHealth { off, unknown, ok, unreachable, fault }

/// What the client currently holds about one contact's standing in the log.
class KtContactStatus {
  KtContactState state;

  /// The log's latest (version, fingerprint) for the label, when logged.
  int? logVersion;
  String? logFpB64;

  /// Where that entry sits in the log, when a bucket said (phase 35).
  int? logIndex;

  /// What a later refresh needs from that entry without fetching it again
  /// (phase 35): whether it failed to open as the account's list, and — when
  /// it did open and the device-list rules refused it — the list, so the
  /// next refresh tries again from here. Fetching the same entry at every
  /// refresh would single it out among the decoys beside it, which change.
  bool logUnopened;
  Map<String, Object?>? logList;

  /// The in-band version this status was computed against.
  int? heldVersion;

  /// When this status was last computed against an accepted head.
  int checkedAtMs;

  /// When the held in-band list first went unconfirmed (grace runs from here).
  int? unconfirmedSinceMs;

  /// Device Ed25519 keys (b64) of the last list the log confirmed for this
  /// account — or, before any confirmation, the baseline: the device the
  /// contact code named. Devices in the held list but not here are the ones
  /// an unconfirmed list added.
  Set<String> confirmedDevs;

  /// Routing ids that must not receive messages right now: the devices only
  /// an unconfirmed list (past grace) added.
  Set<String> heldRids;

  /// Why, for a conflict or a fault seen on this contact.
  String? detail;

  /// The user chose "send anyway" for the conflict currently shown.
  bool acknowledged;

  KtContactStatus({
    required this.state,
    this.logVersion,
    this.logFpB64,
    this.logIndex,
    this.logUnopened = false,
    this.logList,
    this.heldVersion,
    required this.checkedAtMs,
    this.unconfirmedSinceMs,
    Set<String>? confirmedDevs,
    Set<String>? heldRids,
    this.detail,
    this.acknowledged = false,
  })  : confirmedDevs = confirmedDevs ?? {},
        heldRids = heldRids ?? {};

  bool get sendsHeld => state == KtContactState.conflict && !acknowledged;

  Map<String, Object?> toJson() => {
        's': state.name,
        if (logVersion != null) 'lv': logVersion,
        if (logFpB64 != null) 'lf': logFpB64,
        if (logIndex != null) 'li': logIndex,
        if (logUnopened) 'lu': true,
        if (logList != null) 'll': logList,
        if (heldVersion != null) 'hv': heldVersion,
        'at': checkedAtMs,
        if (unconfirmedSinceMs != null) 'since': unconfirmedSinceMs,
        'cd': confirmedDevs.toList()..sort(),
        'hr': heldRids.toList()..sort(),
        if (detail != null) 'd': detail,
        if (acknowledged) 'ack': true,
      };

  static KtContactStatus fromJson(Map<String, Object?> j) => KtContactStatus(
        state: KtContactState.values.firstWhere((s) => s.name == j['s'],
            orElse: () => KtContactState.unlogged),
        logVersion: (j['lv'] as num?)?.toInt(),
        logFpB64: j['lf'] as String?,
        logIndex: (j['li'] as num?)?.toInt(),
        logUnopened: j['lu'] == true,
        logList: j['ll'] is Map ? (j['ll'] as Map).cast<String, Object?>() : null,
        heldVersion: (j['hv'] as num?)?.toInt(),
        checkedAtMs: (j['at'] as num?)?.toInt() ?? 0,
        unconfirmedSinceMs: (j['since'] as num?)?.toInt(),
        confirmedDevs: ((j['cd'] as List?) ?? const []).cast<String>().toSet(),
        heldRids: ((j['hr'] as List?) ?? const []).cast<String>().toSet(),
        detail: j['d'] as String?,
        acknowledged: j['ack'] == true,
      );
}

/// One contact as the check sees it.
class KtContactInput {
  final String rid;
  final Uint8List accountEdPub;

  /// The verified in-band list held for the account, or null when only the
  /// contact code's single device is known (§3.6's baseline, version 1).
  final SignedDeviceList? held;

  /// When [held] was received (ms), for the grace period; null if unknown,
  /// in which case the grace runs from the first check that sees it.
  final int? heldAtMs;

  /// The newest verified (version, fingerprint) held for the account — the
  /// service's §3.6 claim, which falls back to the baseline (version 1 over
  /// the single device the contact code named) when no list has arrived.
  final int heldVersion;
  final String heldFpB64;

  /// The device the contact code named: always deliverable, and the baseline
  /// confirmed set before the log has confirmed any list.
  final Uint8List primaryDeviceEdPub;

  KtContactInput({
    required this.rid,
    required this.accountEdPub,
    required this.held,
    required this.heldAtMs,
    required this.heldVersion,
    required this.heldFpB64,
    required this.primaryDeviceEdPub,
  });
}

/// The account's own standing.
class KtOwnInput {
  final Uint8List accountEdPub;
  final int version;
  final String fpB64;

  /// The signed list's JSON, when this device holds one to publish.
  final String? listJson;

  /// The account seed, on a device that holds the root — the only one that
  /// can publish.
  final Uint8List? accountEdSeed;

  /// This device's own Ed25519 key: a list for the account that omits it,
  /// at a version above [version], is this device's evidence that it was
  /// removed (ADR 0026). Null when the host does not say.
  final Uint8List? deviceEdPub;

  /// The Ed25519 keys (b64) of every device this account is known, from this
  /// device's own records, to have held. The own-list repair reconciles only
  /// a list that names nothing else (ADR 0026); the check adds the devices of
  /// every log entry that matches this device's record of its own lists.
  final Set<String> devicesHeld;

  KtOwnInput({
    required this.accountEdPub,
    required this.version,
    required this.fpB64,
    required this.listJson,
    required this.accountEdSeed,
    this.deviceEdPub,
    this.devicesHeld = const {},
  });
}

/// What the client needs from the service that owns contacts and lists.
abstract class KtHost {
  Future<List<KtContactInput>> ktContacts();
  Future<KtOwnInput?> ktOwn();

  /// Install a list the log served and this client verified (§3.4 rules
  /// apply again inside). True when installed.
  Future<bool> ktInstallFromLog(String rid, SignedDeviceList list);

  /// Something a screen shows changed.
  void ktChanged();
}

class KtFault {
  final String reason;
  final KtTreeHead? held;
  final KtTreeHead? served;
  final int atMs;
  KtFault({required this.reason, this.held, this.served, required this.atMs});

  Map<String, Object?> toJson() => {
        'r': reason,
        if (held != null) 'held': held!.toJson(),
        if (served != null) 'served': served!.toJson(),
        'at': atMs,
      };

  static KtFault fromJson(Map<String, Object?> j) => KtFault(
        reason: (j['r'] as String?) ?? '',
        held: j['held'] == null ? null : KtTreeHead.fromJson((j['held'] as Map).cast<String, Object?>()),
        served: j['served'] == null ? null : KtTreeHead.fromJson((j['served'] as Map).cast<String, Object?>()),
        atMs: (j['at'] as num?)?.toInt() ?? 0,
      );
}

/// An own-account finding from the log: an entry for our label this device
/// neither published nor learned by self-sync (T1/T2, with a record the
/// attacker cannot keep from the owner).
class KtOwnAlert {
  final int version;
  final String fpB64;
  final int atMs;
  KtOwnAlert({required this.version, required this.fpB64, required this.atMs});
  Map<String, Object?> toJson() => {'v': version, 'f': fpB64, 'at': atMs};
  static KtOwnAlert fromJson(Map<String, Object?> j) => KtOwnAlert(
      version: (j['v'] as num).toInt(), fpB64: j['f'] as String, atMs: (j['at'] as num?)?.toInt() ?? 0);
}

/// One entry the log holds for an account's label, verified under an
/// accepted head: its version and fingerprint, where it sits in the log, and
/// the list it opens to — null when it does not open, or does not verify, as
/// that account's list at that (version, fingerprint).
class KtOwnEntry {
  final int version;
  final String fpB64;
  final int index;
  final SignedDeviceList? list;
  KtOwnEntry(
      {required this.version,
      required this.fpB64,
      required this.index,
      required this.list});
}

/// What the log holds for an account: its latest entry (null for a label
/// the log has never held) and every entry in its history.
class KtOwnRecord {
  final KtOwnEntry? latest;
  final List<KtOwnEntry> history;
  KtOwnRecord({required this.latest, required this.history});
}

/// Thrown by the service when a send to a contact in conflict is attempted.
class KtSendHeldException implements Exception {
  final String rid;
  KtSendHeldException(this.rid);
  @override
  String toString() => 'KtSendHeldException: sends to $rid are held by a transparency conflict';
}

class KeyTransparency {
  final Vault vault;
  final KtHost host;
  final KtFetcher fetcher;
  int Function() now;

  KtConfig config;

  /// ADR 0006's numbers, settable for tests. [checkEvery] is the window a
  /// refresh runs once in, at a random moment (phase 35).
  Duration grace = const Duration(hours: 24);
  Duration checkEvery = const Duration(hours: 6);
  Duration staleHead = const Duration(hours: 24);
  Duration unreachableAfter = const Duration(hours: 24);

  /// A client that has had no refresh for a whole window catches up at a
  /// random moment this long after it is next running — never at start
  /// (phase 35). The app may not be running at a window's moment at all;
  /// these bound how long it has to have been, and how long it waits.
  ///
  /// This replaced a recheck 30 seconds after a contact's list changed and a
  /// check at every start. The first told the log, by its timing alone,
  /// whose list it was checking: a contact publishes, and 30 seconds later
  /// their contacts ask — whatever they ask for.
  Duration catchUpMin = const Duration(minutes: 1);
  Duration catchUpMax = const Duration(minutes: 10);

  /// Where scheduled refreshes draw their moments from; settable for tests.
  Random random = Random.secure();

  /// When the next scheduled refresh runs (ms), once one is planned.
  int? nextRefreshMs;

  /// Whether refreshes run on their own schedule. A test that checks when it
  /// says so turns them off; a refresh asked for explicitly still runs.
  bool get scheduled => _scheduled;
  set scheduled(bool on) {
    _scheduled = on;
    if (on) {
      unawaited(_arm());
    } else {
      _timer?.cancel();
      nextRefreshMs = null;
    }
  }

  bool _scheduled = true;

  /// How soon a publish the log answered "not now" (429) or could not take
  /// (5xx) is tried again — not at the next check, six hours off.
  Duration publishRetryDelay = const Duration(minutes: 1);

  /// True inside `flutter test`, which sets this for every test process.
  static final bool _inFlutterTest =
      Platform.environment.containsKey('FLUTTER_TEST');

  /// Under `flutter test`, a log that is not on loopback is not contacted.
  ///
  /// A test that builds a `ChatService` gets the build-time defaults unless
  /// it says otherwise, and since the log key was pinned those defaults name
  /// the **production** log. So every test that built one was doing live
  /// lookups against `kt.zmessengers.com` — and publishing to it: a test
  /// identity is a fresh account root, `ktOwn()` signs its baseline list on
  /// demand, so `canPublish` is true and `_checkOwn` publishes. That is one
  /// permanent label in an append-only log per test client, per run, from CI
  /// and from every developer's machine.
  ///
  /// It also made the suite's results depend on a network round trip.
  /// `_checkContacts` ends in `contacts[c.rid] = next`, which replaces a
  /// status wholesale — including one a test set deliberately. A check still
  /// in flight from `start()` when `group_fanout_test` forced a transparency
  /// conflict wiped that conflict part-way through the test, and rows that
  /// should have been held were sent instead. On a fast machine the check
  /// finished first and the test passed; on a loaded runner talking to a
  /// loaded log it did not, which is why that test failed only in CI.
  ///
  /// Loopback is exempt because that is what a test SHOULD be talking to:
  /// `key_transparency_test.dart` runs `kt/server.js` on 127.0.0.1 and
  /// drives it, and is unaffected by this.
  ///
  /// The WITNESS address is judged by the same rule. It was not, and the
  /// omission was invisible only because `defaultKtWitnessUrl` is still empty:
  /// the moment a build defines one, every test that stands up a ChatService
  /// would have asked a stranger's server for a record on a timer, which is
  /// the whole of what this guard exists to stop.
  bool get _offLimitsInTest {
    if (!_inFlutterTest) return false;
    return !(_loopbackOrEmpty(config.logUrl) && _loopbackOrEmpty(config.witnessUrl));
  }

  static bool _loopbackOrEmpty(String url) {
    final host = Uri.tryParse(url.trim())?.host ?? '';
    return host.isEmpty || host == 'localhost' || host == '127.0.0.1' || host == '::1';
  }

  KtTreeHead? head;
  KtFault? fault;
  KtOwnAlert? ownAlert;
  int lastOkMs = 0;
  int lastFailMs = 0;
  int? witnessOkMs;
  final Map<String, KtContactStatus> contacts = {};

  /// A publish waiting for the log's acknowledgement (durable across restarts).
  Map<String, Object?>? _pendingPublish;

  /// v → fp (b64) of every own list this device signed or learned.
  final Map<int, String> _knownOwn = {};
  int? _firstKnownV;

  /// v → fp (b64) of the log's entry at a version [_knownOwn] records under
  /// another fingerprint, reconciled by the own-list repair (ADR 0026): a
  /// list this account's key signed, over devices it held, that the signing
  /// race of patch 42 overwrote in this device's record before this build
  /// ran. Kept beside the record, not over it — the record is what a second
  /// list at a version is refused against.
  final Map<int, String> _reconciledOwn = {};

  /// What this device held when this build first ran on its vault: the size
  /// of the log head it had accepted, and the versions it had recorded. Only
  /// an entry inside that head, at a version recorded then, can be one the
  /// race left; the record has kept the first list at each version since.
  int _legacySize = 0;
  Set<int> _legacyVersions = const {};

  /// The last entry for this account that the log served and that does not
  /// open as one of its lists (§19.3): not signed by the account, so not
  /// evidence of anything the account issued, and not an alarm — a quiet
  /// diagnostic, kept for whoever looks (ADR 0026). The account's contacts
  /// treat the same entry as a conflict (adr/0006), unchanged.
  KtOwnAlert? ownUnverified;

  /// The evidence of every own-account alarm the user dismissed — this
  /// object's [ownAlert] and the service's banners alike (ADR 0026).
  late final OwnAlarmDismissals dismissals = OwnAlarmDismissals(vault);

  /// Handed the log's latest entry for this account, opened and verified as
  /// one of its lists, at every check that reads one — which is how a device
  /// the list omits learns it was removed when no contact tells it (ADR
  /// 0026), and how a root learns that the latest entry is one the own-list
  /// repair reconciled rather than its current list ([reconciled]).
  Future<void> Function(SignedDeviceList list, {required bool reconciled})?
      onOwnLatest;

  Timer? _timer;
  Timer? _publishRetry;
  Future<void>? _running;
  bool _disposed = false;
  bool _started = false;

  /// The bucket size the log recommends (`bucketBits` beside its head), as
  /// last served; unsigned, so only an upper bound on what is asked.
  int? _recommendedBits;

  /// This install's decoys and what it last asked (`kt_decoys`), loaded on
  /// first use.
  KtDecoys? _decoys;

  KeyTransparency({
    required this.vault,
    required this.host,
    required this.fetcher,
    required this.config,
    int Function()? now,
  }) : now = now ?? (() => DateTime.now().millisecondsSinceEpoch);

  // --- state --------------------------------------------------------------

  KtHealth get health {
    if (!config.enabled) return KtHealth.off;
    if (fault != null) return KtHealth.fault;
    if (lastOkMs == 0) {
      return lastFailMs == 0 ? KtHealth.unknown : KtHealth.unreachable;
    }
    if (now() - lastOkMs > unreachableAfter.inMilliseconds) return KtHealth.unreachable;
    return KtHealth.ok;
  }

  KtContactStatus? statusOf(String rid) => contacts[rid];

  /// Routing ids of [rid]'s devices that must not receive messages now.
  Set<String> heldRids(String rid) => contacts[rid]?.heldRids ?? const {};

  bool sendsHeld(String rid) => contacts[rid]?.sendsHeld ?? false;

  Future<void> load() async {
    final stored = await vault.kvGet('kt_config');
    if (stored != null) {
      try {
        config = KtConfig.fromJson((jsonDecode(stored) as Map).cast<String, Object?>());
      } catch (_) {}
    }
    final h = await vault.kvGet('kt_head');
    if (h != null) {
      try {
        head = KtTreeHead.fromJson((jsonDecode(h) as Map).cast<String, Object?>());
      } catch (_) {}
    }
    final f = await vault.kvGet('kt_fault');
    if (f != null) {
      try {
        fault = KtFault.fromJson((jsonDecode(f) as Map).cast<String, Object?>());
      } catch (_) {}
    }
    final a = await vault.kvGet('kt_own_alert');
    if (a != null) {
      try {
        ownAlert = KtOwnAlert.fromJson((jsonDecode(a) as Map).cast<String, Object?>());
      } catch (_) {}
    }
    final u = await vault.kvGet('kt_own_unverified');
    if (u != null) {
      try {
        ownUnverified = KtOwnAlert.fromJson((jsonDecode(u) as Map).cast<String, Object?>());
      } catch (_) {}
    }
    lastOkMs = int.tryParse(await vault.kvGet('kt_last_ok_ms') ?? '') ?? 0;
    lastFailMs = int.tryParse(await vault.kvGet('kt_last_fail_ms') ?? '') ?? 0;
    final w = await vault.kvGet('kt_witness_ok_ms');
    witnessOkMs = w == null ? null : int.tryParse(w);
    final p = await vault.kvGet('kt_pub_pending');
    if (p != null) {
      try {
        _pendingPublish = (jsonDecode(p) as Map).cast<String, Object?>();
      } catch (_) {}
    }
    final k = await vault.kvGet('kt_own_known');
    if (k != null) {
      try {
        final m = (jsonDecode(k) as Map).cast<String, Object?>();
        for (final e in m.entries) {
          _knownOwn[int.parse(e.key)] = e.value as String;
        }
      } catch (_) {}
    }
    _firstKnownV = int.tryParse(await vault.kvGet('kt_own_first_v') ?? '');
    final rec = await vault.kvGet('kt_own_reconciled');
    if (rec != null) {
      try {
        final m = (jsonDecode(rec) as Map).cast<String, Object?>();
        for (final e in m.entries) {
          _reconciledOwn[int.parse(e.key)] = e.value as String;
        }
      } catch (_) {}
    }
    // The first start of this build on this vault, recorded once: what the
    // log held then (the size of the head this device had accepted) and
    // which versions this device had recorded. A vault this build creates
    // records an empty head and no versions — there is no head yet — so the
    // own-list repair can never apply to it.
    final legacy = await vault.kvGet('kt_own_legacy');
    if (legacy == null) {
      _legacySize = head?.size ?? 0;
      _legacyVersions = _knownOwn.keys.toSet();
      await vault.kvPut(
          'kt_own_legacy',
          jsonEncode({
            'size': _legacySize,
            'v': _legacyVersions.toList()..sort(),
          }));
    } else {
      try {
        final m = (jsonDecode(legacy) as Map).cast<String, Object?>();
        _legacySize = (m['size'] as num).toInt();
        _legacyVersions = {
          for (final v in (m['v'] as List)) (v as num).toInt()
        };
      } catch (_) {
        _legacySize = 0;
        _legacyVersions = const {};
      }
    }
    await dismissals.load();
    final shown = ownAlert;
    if (shown != null &&
        dismissals.contains(logEntryEvidence(shown.version, shown.fpB64))) {
      ownAlert = null;
      await vault.kvDelete('kt_own_alert');
    }
    for (final e in (await vault.kvScan('ktc_')).entries) {
      try {
        contacts[e.key.substring(4)] =
            KtContactStatus.fromJson((jsonDecode(e.value) as Map).cast<String, Object?>());
      } catch (_) {}
    }
  }

  /// Start the scheduled refreshes (phase 35): the first at a random moment,
  /// never now — a refresh at every start would mark every start.
  void start() {
    _timer?.cancel();
    if (_offLimitsInTest) return;
    _started = true;
    unawaited(_arm());
    unawaited(_publishUnacknowledged());
  }

  /// At start, this account's current list goes to the log unless the log
  /// has acknowledged it: a publish still queued from before, or a list never
  /// sent — a fresh account's first above all (11.5), which used to wait for
  /// the check that ran at every start. A publish names this account and no
  /// other, which the log learns from every publish anyway; and every hour
  /// one waits is an hour of grace charged to this account's contacts. A
  /// list the log has acknowledged is not sent again ([publishOwnList]).
  Future<void> _publishUnacknowledged() async {
    try {
      if (!config.enabled) return;
      if (_pendingPublish == null) {
        final own = await host.ktOwn();
        final seed = own?.accountEdSeed;
        final listJson = own?.listJson;
        if (own != null && seed != null && listJson != null) {
          await publishOwnList(
            accountEdSeed: seed,
            accountEdPub: own.accountEdPub,
            version: own.version,
            fp: unb64(own.fpB64),
            listJson: listJson,
          );
          return;
        }
      }
      await _flushPublish();
    } catch (_) {
      // Sent at the next refresh instead.
    }
  }

  void dispose() {
    _disposed = true;
    _timer?.cancel();
    _publishRetry?.cancel();
  }

  /// Plan the next scheduled refresh and set the timer for it.
  Future<void> _arm() async {
    _timer?.cancel();
    if (_disposed || !_started || !_scheduled || _offLimitsInTest || !config.enabled) {
      return;
    }
    final stored = await vault.kvGet('kt_refresh');
    var plan = const KtRefreshSchedule();
    if (stored != null) {
      try {
        plan = KtRefreshSchedule.fromJson((jsonDecode(stored) as Map).cast<String, Object?>());
      } catch (_) {}
    }
    final t = now();
    final next = plan.next(
        nowMs: t, every: checkEvery, catchUpMin: catchUpMin, catchUpMax: catchUpMax, random: random);
    if (next.window != plan.window || next.atMs != plan.atMs) {
      await vault.kvPut('kt_refresh', jsonEncode(next.toJson()));
    }
    if (_disposed || !_scheduled) return;
    _timer?.cancel();
    nextRefreshMs = next.atMs;
    _timer = Timer(Duration(milliseconds: max(0, next.atMs! - t)), () {
      // A timer that fires well after its moment is one the app slept
      // through — a phone suspends an app it is not showing — and it fires
      // the moment the app is back, which is a refresh at start by another
      // door. Its moment is drawn again instead, from now.
      if (now() - next.atMs! > _lateTimer.inMilliseconds) {
        unawaited(_arm());
        return;
      }
      unawaited(check().then((_) => _arm()));
    });
  }

  static const Duration _lateTimer = Duration(minutes: 1);

  /// A refresh asked the log: the schedule's next moment counts from here.
  Future<void> _noteRefreshed() async {
    final stored = await vault.kvGet('kt_refresh');
    var plan = const KtRefreshSchedule();
    if (stored != null) {
      try {
        plan = KtRefreshSchedule.fromJson((jsonDecode(stored) as Map).cast<String, Object?>());
      } catch (_) {}
    }
    await vault.kvPut('kt_refresh', jsonEncode(plan.withLast(now()).toJson()));
  }

  Future<void> setConfig(KtConfig c) async {
    // The refusal lives here, not only in the screen that edits it: a
    // half-configured witness is the one configuration that looks like
    // protection and is not, and a UI is the wrong place to keep the only
    // copy of that rule.
    final problem = c.witnessProblem;
    if (problem != null) throw KtConfigInvalid(problem);
    config = c;
    await vault.kvPut('kt_config', jsonEncode(c.toJson()), sensitive: false);
    // Indexes are one log's; another log's are other entries. The decoys
    // stay: two logs shown the same buckets learn nothing by comparing.
    await vault.kvDelete('kt_seen');
    host.ktChanged();
    unawaited(check().then((_) => _arm()));
  }

  /// Forget the accepted head and any fault — for a deliberate change of log,
  /// or after a fault has been reported and understood. Contact statuses are
  /// re-derived by the next check.
  Future<void> resetHistory() async {
    head = null;
    fault = null;
    lastOkMs = 0;
    lastFailMs = 0;
    // The own-list repair (ADR 0026) reconciles only entries inside the head
    // this device held when this build first ran: a set nothing can join
    // while every head the log serves has to extend the one held. A reset
    // takes the next head as it comes, from this log or another, so what sits
    // at those indices afterwards need not be what sat there — the repair
    // ends here. What it has already reconciled stays: a fingerprint commits
    // to its device set, so the same (version, fingerprint) is the same list
    // in any log.
    _legacySize = 0;
    _legacyVersions = const {};
    await vault.kvPut('kt_own_legacy', jsonEncode({'size': 0, 'v': <int>[]}));
    await vault.kvDelete('kt_head');
    await vault.kvDelete('kt_fault');
    await vault.kvDelete('kt_last_ok_ms');
    await vault.kvDelete('kt_last_fail_ms');
    await vault.kvDelete('kt_seen');
    for (final rid in contacts.keys.toList()) {
      await vault.kvDelete('ktc_$rid');
    }
    contacts.clear();
    host.ktChanged();
    unawaited(check());
  }

  /// Put a contact into conflict without a log disagreeing with anything.
  ///
  /// A test seam: reaching this state for real needs a log serving one thing
  /// and a contact asserting another, which `key_transparency_test.dart` does
  /// against the real service. What the group fan-out needs to be tested
  /// against is the STATE, and building the world twice to get to it is how
  /// a case ends up untested — which this one was.
  @visibleForTesting
  void debugForceConflict(String rid) {
    contacts[rid] = KtContactStatus(
      state: KtContactState.conflict,
      checkedAtMs: now(),
      detail: 'forced by a test',
    );
    unawaited(_saveContact(rid));
    host.ktChanged();
  }

  /// "Send anyway" for a conflict: sends resume until the state changes.
  Future<void> acknowledgeConflict(String rid) async {
    final s = contacts[rid];
    if (s == null) return;
    s.acknowledged = true;
    await _saveContact(rid);
    host.ktChanged();
  }

  /// The user dismissed [ownAlert]. It is dismissed for its evidence — this
  /// entry, this version and fingerprint — and only for that: the same entry
  /// read again at the next check, or the next start, raises nothing, and
  /// another entry the account never issued raises it again (ADR 0026).
  /// Until 2026-10-04 the next check raised it again whatever it was, which
  /// is how a vault the own-list race had damaged showed it at every start.
  Future<void> acknowledgeOwnAlert() async {
    final shown = ownAlert;
    if (shown != null) {
      await dismissals.add(logEntryEvidence(shown.version, shown.fpB64));
    }
    ownAlert = null;
    await vault.kvDelete('kt_own_alert');
    host.ktChanged();
  }

  /// The fingerprint recorded for [version] of this device's own account, if
  /// one is. The service never records a second one for a version
  /// (`_recordOwnList`); this is what it asks first.
  String? knownOwnFingerprint(int version) => _knownOwn[version];

  /// Whether ([version], [fpB64]) is a list this device signed or learned
  /// for its own account, or one the own-list repair reconciled.
  bool ownListKnown(int version, String fpB64) =>
      _knownOwn[version] == fpB64 || _reconciledOwn[version] == fpB64;

  /// Whether ([version], [fpB64]) was reconciled by the own-list repair.
  bool ownListReconciled(int version, String fpB64) =>
      _reconciledOwn[version] == fpB64;

  /// Whether this device has recorded any list at [version].
  bool ownVersionRecorded(int version) => _knownOwn.containsKey(version);

  /// Whether [version] is from before this device knew its account: a linked
  /// device joins part-way through the account's history.
  bool ownVersionBeforeMyTime(int version) =>
      _firstKnownV != null && version < _firstKnownV!;

  /// Every version of this device's own account it has a record of.
  Iterable<int> get knownOwnVersions => _knownOwn.keys;

  /// What the log holds for [accountEdPub] — its latest entry and its whole
  /// history, every item verified under a head this client accepts (§19.5),
  /// exactly as the own-account check reads them — for a device resuming
  /// after a restore (`ChatService._resumeAfterRestore`), which has to know
  /// what the account published before it signs anything itself.
  ///
  /// Null when the log cannot be asked — off, off-limits in a test, already
  /// faulted, unreachable — or answered with something that does not verify
  /// (which faults it, as the check would). Serialised with [check].
  Future<KtOwnRecord?> ownRecord(Uint8List accountEdPub) {
    final prev = _running;
    final run = () async {
      if (prev != null) await prev;
      if (_disposed || !config.enabled || _offLimitsInTest || fault != null) {
        return null;
      }
      try {
        return await _ownRecordOnce(accountEdPub, config.logPub!);
      } catch (_) {
        return null;
      }
    }();
    _running = run.then((_) {});
    return run;
  }

  Future<KtOwnRecord?> _ownRecordOnce(
      Uint8List accountEdPub, Uint8List logPub) async {
    if (!await _acceptHead(logPub)) return null;
    await _markOk();
    final label = await ktLabel(accountEdPub);
    final j = await _getJson(_url('/kt/v1/lookup/${_hex(label)}'));
    if (j == null) {
      await _fail();
      return null;
    }
    KtLookupResult r;
    try {
      r = await ktVerifyLookup(await KtLookup.fromJson(j),
          label: label, logPub: logPub);
    } on KtVerifyException catch (e) {
      await _setFault('lookup for this account: ${e.reason}');
      return null;
    }
    if (!await _adopt(r.head, logPub)) return null;
    Future<KtOwnEntry> entry(KtEntry e) async => KtOwnEntry(
        version: e.version,
        fpB64: b64(e.fp),
        index: e.index,
        list: await _openList(accountEdPub, e));
    final latest = r.latest == null ? null : await entry(r.latest!);
    final history = <KtOwnEntry>[];
    var start = 0;
    while (true) {
      final hj =
          await _getJson(_url('/kt/v1/history/${_hex(label)}?start=$start'));
      if (hj == null) {
        await _fail();
        return null;
      }
      KtTreeHead hh;
      try {
        hh = KtTreeHead.fromJson((hj['sth'] as Map).cast<String, Object?>());
      } on KtVerifyException catch (e) {
        await _setFault('history for this account: ${e.reason}');
        return null;
      } catch (_) {
        await _setFault('history for this account could not be read');
        return null;
      }
      if (!await _adopt(hh, logPub)) return null;
      final items = hj['entries'] as List? ?? const [];
      final t = hj['total'];
      final total = t is int ? t : start + items.length;
      for (final item in items) {
        KtEntry e;
        try {
          e = await ktVerifyHistoryItem((item as Map).cast<String, Object?>(),
              head: hh, label: label);
        } on KtVerifyException catch (err) {
          await _setFault('history for this account: ${err.reason}');
          return null;
        } catch (_) {
          await _setFault('history for this account could not be read');
          return null;
        }
        history.add(await entry(e));
      }
      start += items.length;
      if (items.isEmpty || start >= total) break;
    }
    return KtOwnRecord(latest: latest, history: history);
  }

  /// The service records every list this device signed or learned for its
  /// own account, so an entry in the log's history that is none of them can
  /// be told apart from one this device simply issued.
  Future<void> recordOwnList(int version, String fpB64) async {
    _knownOwn[version] = fpB64;
    _firstKnownV ??= version;
    if (version < _firstKnownV!) _firstKnownV = version;
    await vault.kvPut('kt_own_known',
        jsonEncode({for (final e in _knownOwn.entries) '${e.key}': e.value}),
        sensitive: false);
    await vault.kvPut('kt_own_first_v', '$_firstKnownV', sensitive: false);
  }

  /// A new list was signed for our own account: publish it (root only). A
  /// (version, fingerprint) the log has already acknowledged is not sent
  /// again — the same list is re-signed at every start.
  Future<void> publishOwnList({
    required Uint8List accountEdSeed,
    required Uint8List accountEdPub,
    required int version,
    required Uint8List fp,
    required String listJson,
  }) async {
    if (!config.enabled) return;
    final tag = '$version|${b64(fp)}';
    if (await vault.kvGet('kt_pub_done') == tag) return;
    final pending = _pendingPublish;
    if (pending != null && pending['v'] == version && pending['fp'] == b64(fp)) return;
    final value = await ktSealValue(accountEdPub, utf8.encode(listJson));
    final req = await ktPublishRequest(
        accountEdSeed: accountEdSeed, version: version, fp: fp, value: value);
    _pendingPublish = req;
    await vault.kvPut('kt_pub_pending', jsonEncode(req), sensitive: false);
    unawaited(_flushPublish());
  }

  /// A contact's held list changed (installed in-band). It is checked at the
  /// next refresh, not now (phase 35): a check timed by the change would tell
  /// the log whose list this is, whatever it asked for. The contact's screen
  /// can ask sooner ([checkIfListChanged]).
  ///
  /// [stillPresent] is the routing ids the NEW list contains. A hold is kept
  /// for every device still on the list and dropped only for devices the new
  /// list actually removes.
  ///
  /// This used to clear the hold and restart the grace unconditionally, and
  /// that made the one cost `adr/0006` imposes on T2 avoidable by repetition.
  /// An attacker holding a contact's account root enrols a rogue device and
  /// never publishes it; after 24 hours the rogue is held and stops receiving;
  /// the attacker re-signs the same device set as a fresh list and delivers
  /// it, the hold drops the instant it arrives, and the grace starts again.
  /// Every 23 hours, for ever, and the device the log never saw keeps reading
  /// messages. The list that "changed" did not remove it — it re-asserted it,
  /// which is the opposite of a reason to trust it again.
  /// [stillPresent] is required rather than defaulted: a caller that forgot
  /// it would silently clear every hold, which is the bug this parameter
  /// exists to fix, and a default would leave that one edit away.
  void noteContactListChanged(String rid,
      {required Set<String> stillPresent}) {
    final s = contacts[rid];
    if (s != null) {
      final kept = {
        for (final r in s.heldRids)
          if (stillPresent.contains(r)) r
      };
      // The grace restarts only when the hold is actually released. A list
      // that keeps a held device keeps its clock too, or re-sending would buy
      // another 24 hours of grace for the same device.
      if (kept.isEmpty) s.unconfirmedSinceMs = null;
      s.heldRids = kept;
      unawaited(_saveContact(rid));
    }
  }

  /// The contact screen's check (phase 35): when [rid]'s list has changed
  /// since a refresh last looked at it, a refresh now — the whole of one,
  /// every bucket and every decoy, never a question about this contact
  /// alone. Nothing when the list has not changed. True when one ran.
  Future<bool> checkIfListChanged(String rid) async {
    if (_disposed || !config.enabled || _offLimitsInTest) return false;
    KtContactInput? input;
    for (final c in await host.ktContacts()) {
      if (c.rid == rid) input = c;
    }
    if (input == null) return false;
    final s = contacts[rid];
    if (s != null && s.heldVersion == input.heldVersion) return false;
    await check();
    return true;
  }

  Future<void> noteContactRemoved(String rid) async {
    contacts.remove(rid);
    await vault.kvDelete('ktc_$rid');
  }

  // --- the check ------------------------------------------------------------

  /// One full refresh (§19.5, §19.9.1 + ADR 0006's table) — every contact,
  /// by bucket, with the decoys. Serialised: a check while one runs waits
  /// for it.
  Future<void> check() {
    final prev = _running;
    _queued++;
    final run = () async {
      try {
        if (prev != null) await prev;
        if (_disposed) return;
        await _checkOnce();
      } catch (_) {
        // A check must never take the service down; the next one runs on
        // schedule and the health reflects what happened.
      } finally {
        _queued--;
      }
    }();
    _running = run;
    return run;
  }

  /// Whether a refresh is running or waiting to — one a screen started
  /// included ([checkIfListChanged]).
  bool get checking => _queued > 0;
  int _queued = 0;

  /// This account's own label alone, now: what a removal notice that carries
  /// no list moves forward (ADR 0026) — the list that removed this device,
  /// if one did, is the account's latest entry. Serialised with [check], and
  /// no contact is looked up, so it adds nothing to what the log learns of
  /// who this device's contacts are.
  Future<void> checkOwn() {
    final prev = _running;
    final run = () async {
      if (prev != null) await prev;
      if (_disposed || !config.enabled || _offLimitsInTest || fault != null) {
        return;
      }
      try {
        final logPub = config.logPub!;
        if (await _acceptHead(logPub)) {
          await _markOk();
          await _checkOwn(logPub);
        }
      } catch (_) {
        // As [check]: never takes the service down.
      }
      host.ktChanged();
    }();
    _running = run;
    return run;
  }

  Future<void> _checkOnce() async {
    if (!config.enabled || _offLimitsInTest) return;
    final logPub = config.logPub!;
    await _noteRefreshed();
    if (fault == null) {
      final accepted = await _acceptHead(logPub);
      if (accepted) {
        // The log is reachable to this client when it answers what the
        // client asks — the buckets — and not merely its head: a log that
        // refuses buckets (one older than 36.2) checks nobody, and after
        // `unreachableAfter` says so rather than "ok" for ever.
        if (await _checkContacts(logPub)) await _markOk();
        await _checkOwn(logPub);
        await _flushPublish();
      }
    }
    await _applyGrace();
    host.ktChanged();
  }

  Uri _url(String path) {
    final base = config.logUrl.trim().replaceAll(RegExp(r'/+$'), '');
    return Uri.parse('$base$path');
  }

  Future<Map<String, Object?>?> _getJson(Uri u) async {
    try {
      final r = await fetcher.get(u);
      if (r.status != 200) return null;
      return r.json;
    } catch (_) {
      return null;
    }
  }

  Future<void> _fail() async {
    lastFailMs = now();
    await vault.kvPut('kt_last_fail_ms', '$lastFailMs', sensitive: false);
  }

  Future<void> _setFault(String reason, {KtTreeHead? served}) async {
    fault = KtFault(reason: reason, held: head, served: served, atMs: now());
    await vault.kvPut('kt_fault', jsonEncode(fault!.toJson()), sensitive: false);
  }

  /// Steps 1–3 of §19.5 for the log's current head. True when a head was
  /// accepted (and persisted).
  Future<bool> _acceptHead(Uint8List logPub) async {
    final j = await _getJson(_url('/kt/v1/sth'));
    if (j == null) {
      await _fail();
      return false;
    }
    KtTreeHead fresh;
    try {
      fresh = KtTreeHead.fromJson(j);
    } on KtVerifyException catch (e) {
      await _setFault('the head could not be read: ${e.reason}');
      return false;
    }
    final rb = j['bucketBits'];
    _recommendedBits = rb is int && rb >= 0 && rb <= ktMaxBucketBits ? rb : null;
    return _adopt(fresh, logPub);
  }

  /// The log answered what this client asked of it.
  Future<void> _markOk() async {
    lastOkMs = now();
    await vault.kvPut('kt_last_ok_ms', '$lastOkMs', sensitive: false);
  }

  /// Steps 1–3 of §19.5 for any head the log serves — with a lookup or a
  /// history as much as on its own. The held head is only ever replaced
  /// here. True when [fresh] is now the held head.
  Future<bool> _adopt(KtTreeHead fresh, Uint8List logPub) async {
    final held = head;
    if (held != null && held.sameRootsAs(fresh) && fresh.ts <= held.ts) return true;
    List<Uint8List>? consistency;
    if (held != null && fresh.size > held.size) {
      final c = await _getJson(_url('/kt/v1/consistency?first=${held.size}&second=${fresh.size}'));
      if (c == null) {
        await _fail();
        return false;
      }
      try {
        consistency = [for (final h in (c['proof'] as List)) unb64(h as String)];
      } catch (_) {
        await _setFault('the consistency proof could not be read', served: fresh);
        return false;
      }
    }
    try {
      await ktCheckHeadExtends(held: held, fresh: fresh, consistency: consistency, logPub: logPub);
    } on KtVerifyException catch (e) {
      await _setFault(e.reason, served: fresh);
      return false;
    }
    if (now() - fresh.ts > staleHead.inMilliseconds) {
      // A frozen head is treated as unreachable, not as a fault (ADR 0006).
      await _fail();
      return false;
    }
    if (config.hasWitness) {
      final ok = await _checkWitness(fresh, logPub);
      if (!ok) return false;
    }
    head = fresh;
    await vault.kvPut('kt_head', jsonEncode(fresh.toJson()), sensitive: false);
    return true;
  }

  /// §19.5 step 3. A witness that cannot be fetched or does not verify is
  /// ignored for this check (recorded); one that verifies and disagrees with
  /// the log is a fault.
  Future<bool> _checkWitness(KtTreeHead fresh, Uint8List logPub) async {
    Map<String, Object?>? j;
    try {
      final r = await fetcher.get(Uri.parse(config.witnessUrl.trim()));
      if (r.status == 200) j = r.json;
    } catch (_) {}
    if (j == null) return true;
    KtWitnessRecord rec;
    try {
      rec = KtWitnessRecord.fromJson(j);
    } on KtVerifyException {
      return true;
    }
    // `hasWitness` is what got us here, and it is false unless the key parses
    // to 32 bytes, so this is a pinned comparison every time it runs.
    if (!await rec.verify(logPub, expectedWitnessPub: config.witnessPub!)) {
      return true;
    }
    witnessOkMs = now();
    await vault.kvPut('kt_witness_ok_ms', '$witnessOkMs', sensitive: false);
    if (rec.head.size == fresh.size) {
      if (!rec.head.sameRootsAs(fresh)) {
        await _setFault('the witness saw a different head of size ${fresh.size}', served: fresh);
        return false;
      }
      return true;
    }
    if (rec.head.size > fresh.size) return _witnessAhead(fresh, rec.head, logPub);
    final c = await _getJson(_url('/kt/v1/consistency?first=${rec.head.size}&second=${fresh.size}'));
    if (c == null) return true; // could not ask; not a verdict
    List<Uint8List> proof;
    try {
      proof = [for (final h in (c['proof'] as List)) unb64(h as String)];
    } catch (_) {
      return true;
    }
    final ok = await ktVerifyConsistency(
        first: rec.head.size,
        second: fresh.size,
        firstRoot: rec.head.logRoot,
        secondRoot: fresh.logRoot,
        proof: proof);
    if (!ok) {
      await _setFault('the log\'s head does not extend the one its witness verified', served: fresh);
      return false;
    }
    return true;
  }

  /// The witness has verified a head LARGER than the one being adopted.
  ///
  /// That is not a fork. A witness verifies the log every few minutes and the
  /// log grows in between, so a head fetched a moment before the witness's
  /// record can be smaller than the one the witness has just co-signed. Until
  /// 2026-10-04 that was a fault — "the log served a head older than the
  /// witness's" — raised against an honest log by a race that needs nothing
  /// but one publish between two requests, and a fault is permanent until
  /// the user resets the log's history. Latent while no witness is
  /// configured; on every client the day one is.
  ///
  /// It is a question the log can answer instead: prove [fresh] is a prefix
  /// of [witnessed]. A proof that verifies settles it; one that does not is
  /// a fault, as it is for a witness behind the client. No proof at all is
  /// either the network or the one case the old rule was right about — a log
  /// that has gone back to a smaller history than one it signed and the
  /// witness verified, which is what a restored snapshot looks like from
  /// here, and which refuses a `second` past its own head. The log's current
  /// head says which: smaller than the witness's is the fault; anything else
  /// is not a verdict, and the next check asks again.
  Future<bool> _witnessAhead(KtTreeHead fresh, KtTreeHead witnessed, Uint8List logPub) async {
    final c = await _getJson(_url('/kt/v1/consistency?first=${fresh.size}&second=${witnessed.size}'));
    if (c != null) {
      List<Uint8List> proof;
      try {
        proof = [for (final h in (c['proof'] as List)) unb64(h as String)];
      } catch (_) {
        return true; // could not read it; not a verdict
      }
      final ok = await ktVerifyConsistency(
          first: fresh.size,
          second: witnessed.size,
          firstRoot: fresh.logRoot,
          secondRoot: witnessed.logRoot,
          proof: proof);
      if (!ok) {
        await _setFault(
            'the log\'s head of size ${fresh.size} is not a prefix of the ${witnessed.size} its witness verified',
            served: fresh);
        return false;
      }
      return true;
    }
    final j = await _getJson(_url('/kt/v1/sth'));
    if (j == null) return true; // unreachable: not a verdict
    KtTreeHead current;
    try {
      current = KtTreeHead.fromJson(j);
    } on KtVerifyException {
      return true;
    }
    if (!await current.verify(logPub)) return true;
    if (current.size < witnessed.size) {
      await _setFault(
          'the log serves a head of size ${current.size}, smaller than the ${witnessed.size} its witness verified',
          served: current);
      return false;
    }
    return true;
  }

  Future<void> _saveContact(String rid) async {
    final s = contacts[rid];
    if (s == null) return;
    await vault.kvPut('ktc_$rid', jsonEncode(s.toJson()), sensitive: false);
  }

  /// The contact pass (phase 35, PROTOCOL §19.9.1): every contact's bucket
  /// and this install's decoys in one request; the entries whose values are
  /// needed fetched by index among decoys; then ADR 0006's table for each
  /// contact, exactly as a lookup used to feed it. False when the log could
  /// not be asked or did not answer — recorded as a failure, or as a fault
  /// when what it answered does not verify — and then nothing about any
  /// contact changes.
  Future<bool> _checkContacts(Uint8List logPub) async {
    final inputs = await host.ktContacts();
    final present = inputs.map((c) => c.rid).toSet();
    for (final rid in contacts.keys.toList()) {
      if (!present.contains(rid)) await noteContactRemoved(rid);
    }
    final labels = <String, Uint8List>{
      for (final c in inputs) c.rid: await ktLabel(c.accountEdPub),
    };
    final decoys = await _loadDecoys();
    final bits = ktRefreshBits(
        recommended: _recommendedBits,
        headSize: head!.size,
        ceiling: decoys.ceiling);
    final asked = decoys.plan(labels.values, bits);
    // Kept before asking: a refresh that fails is asked again the same way.
    await _saveDecoys(decoys);
    final buckets = await _askBuckets(asked, logPub);
    if (buckets == null) return false;
    decoys.observe(buckets, labels.values);
    await _saveDecoys(decoys);

    final leafAt = <int, KtBucketLeaf>{
      for (final b in buckets)
        for (final l in b.leaves) l.index: l,
    };
    final leaves = <String, KtBucketLeaf?>{};
    final needed = <int>{};
    for (final c in inputs) {
      final label = labels[c.rid]!;
      KtVerifiedBucket? holding;
      for (final b in buckets) {
        if (b.query.holds(label)) holding = b;
      }
      if (holding == null) continue; // every label's bucket was asked
      final leaf = holding.leafFor(label);
      leaves[c.rid] = leaf;
      if (leaf != null && _needsEntry(c, leaf, contacts[c.rid])) {
        needed.add(leaf.index);
      }
    }
    final want = ktEntriesToFetch(
        needed: needed,
        leaves: leafAt.keys.toSet(),
        seen: await _loadSeen(),
        key: decoys.key);
    var entries = const <int, KtEntry>{};
    if (want.isNotEmpty) {
      final got = await _fetchEntries(want, leafAt, logPub);
      if (got == null) return false;
      entries = got;
    }
    await vault.kvPut(
        'kt_seen', jsonEncode({'i': leafAt.keys.toList()..sort()}));

    for (final c in inputs) {
      if (fault != null) return false;
      if (!leaves.containsKey(c.rid)) continue;
      final leaf = leaves[c.rid];
      await _checkContact(c, leaf, leaf == null ? null : entries[leaf.index]);
    }
    return true;
  }

  /// Whether ADR 0006's table needs [leaf]'s entry for [c] — its fingerprint,
  /// or the list in it — or [prev] already holds what it needs from it. A
  /// label's versions only rise (§19.6), so a version names one entry: the
  /// same version is the same entry, already judged.
  static bool _needsEntry(
      KtContactInput c, KtBucketLeaf leaf, KtContactStatus? prev) {
    if (prev == null || prev.logVersion != leaf.version || prev.logFpB64 == null) {
      return true;
    }
    if (prev.logIndex != null && prev.logIndex != leaf.index) return true;
    final kept = prev.logUnopened || prev.logList != null;
    if (leaf.version == c.heldVersion) {
      if (c.heldFpB64 == prev.logFpB64 || c.held != null) return false;
      return !kept;
    }
    if (leaf.version > c.heldVersion) return !kept;
    return prev.confirmedDevs.isEmpty;
  }

  /// Every bucket in [queries], verified, under heads this client accepts:
  /// one request for up to [ktMaxBuckets] of them. A request the log refuses
  /// as too large is asked again as two halves, and a single bucket as its
  /// two halves one bit finer — both, so together they say what the bucket
  /// said. Null when the log could not be asked or did not answer.
  Future<List<KtVerifiedBucket>?> _askBuckets(
      List<KtBucketQuery> queries, Uint8List logPub) async {
    final out = <KtVerifiedBucket>[];
    final todo = <List<KtBucketQuery>>[
      for (var i = 0; i < queries.length; i += ktMaxBuckets)
        queries.sublist(i, min(i + ktMaxBuckets, queries.length)),
    ];
    while (todo.isNotEmpty) {
      final chunk = todo.removeAt(0);
      final r = await _postJson('/kt/v1/buckets', ktBucketsRequest(chunk));
      if (r == null) {
        await _fail();
        return null;
      }
      final (status, j) = r;
      if (status == 400 && j?['error'] == 'bucket_too_large') {
        if (chunk.length > 1) {
          final half = chunk.length ~/ 2;
          todo.insertAll(0, [chunk.sublist(0, half), chunk.sublist(half)]);
          continue;
        }
        final q = chunk.single;
        if (q.bits < ktMaxBucketBits) {
          todo.insertAll(0, [
            [ktChildBucket(q, 0)],
            [ktChildBucket(q, 1)],
          ]);
          continue;
        }
      }
      if (status != 200 || j == null) {
        // Refused, or not there at all (a log older than 36.2): this client
        // does not fall back to naming its contacts. Unreachable, as a log
        // that refused lookups was.
        await _fail();
        return null;
      }
      // A bucket at a time, with the event loop let through between them: a
      // bucket is ~250 hashes a label (§19.9), and sixteen of them done in
      // one go are a quarter of a second on the build box — frames dropped
      // on a phone, at a moment the user did not choose.
      final served = j['buckets'];
      if (served is! List || served.length != chunk.length) {
        await _setFault(
            'buckets for contacts: not the ${chunk.length} buckets asked for');
        return null;
      }
      KtTreeHead? at;
      for (var n = 0; n < chunk.length; n++) {
        KtVerifiedBuckets v;
        try {
          v = await ktVerifyBucketAnswer({
            'sth': j['sth'],
            'buckets': [served[n]],
          }, asked: [chunk[n]], logPub: logPub, mode: KtLogMode.kt);
        } on KtVerifyException catch (e) {
          await _setFault('buckets for contacts: ${e.reason}');
          return null;
        } catch (_) {
          await _setFault('buckets for contacts could not be read');
          return null;
        }
        at = v.head;
        out.addAll(v.buckets);
        await Future<void>.delayed(Duration.zero);
      }
      // Under the accepted head or an extension of it (§19.5), as a lookup.
      if (at == null || !await _adopt(at, logPub)) return null;
    }
    return out;
  }

  /// The entries at [indexes], each verified under a head this client
  /// accepts and checked against the leaf a bucket gave for it ([leafAt]):
  /// the map names an entry for a label, and the entry there must be that
  /// label's, at that version. Paged as the log pages it. Null when the log
  /// could not be asked or did not answer.
  Future<Map<int, KtEntry>?> _fetchEntries(List<int> indexes,
      Map<int, KtBucketLeaf> leafAt, Uint8List logPub) async {
    final out = <int, KtEntry>{};
    var rest = indexes;
    while (rest.isNotEmpty) {
      final page = rest.length > 1000 ? rest.sublist(0, 1000) : rest;
      final r = await _postJson('/kt/v1/entries', ktEntriesRequest(page));
      if (r == null || r.$1 != 200 || r.$2 == null) {
        await _fail();
        return null;
      }
      KtVerifiedEntries v;
      try {
        v = await ktVerifyEntriesAnswer(r.$2!, asked: page, logPub: logPub);
      } on KtVerifyException catch (e) {
        await _setFault('entries for contacts: ${e.reason}');
        return null;
      } catch (_) {
        await _setFault('entries for contacts could not be read');
        return null;
      }
      if (!await _adopt(v.head, logPub)) return null;
      for (final e in v.entries) {
        final leaf = leafAt[e.index];
        if (leaf == null ||
            !constantTimeEquals(e.label, leaf.label) ||
            e.version != leaf.version) {
          await _setFault(
              'the entry at index ${e.index} is not the one the map names for its label');
          return null;
        }
        out[e.index] = e;
      }
      rest = rest.sublist(v.entries.length);
    }
    return out;
  }

  /// A POST to the log: its status and, when it is one, its JSON object.
  /// Null when the log could not be reached.
  Future<(int, Map<String, Object?>?)?> _postJson(
      String path, Map<String, Object?> body) async {
    final KtResponse r;
    try {
      r = await fetcher.post(_url(path), jsonEncode(body));
    } catch (_) {
      return null;
    }
    try {
      return (r.status, r.json);
    } catch (_) {
      return (r.status, null);
    }
  }

  Future<KtDecoys> _loadDecoys() async {
    final held = _decoys;
    if (held != null) return held;
    final stored = await vault.kvGet('kt_decoys');
    return _decoys =
        (stored == null ? null : KtDecoys.parse(stored)) ?? KtDecoys.fresh();
  }

  /// Sealed: which buckets are decoys is the one thing the log must not
  /// learn, and the vault's plain class is for what it may.
  Future<void> _saveDecoys(KtDecoys d) =>
      vault.kvPut('kt_decoys', jsonEncode(d.toJson()));

  /// The indexes the asked buckets held at the last refresh, or null.
  Future<Set<int>?> _loadSeen() async {
    final s = await vault.kvGet('kt_seen');
    if (s == null) return null;
    try {
      return {
        for (final i in ((jsonDecode(s) as Map)['i'] as List)) (i as num).toInt()
      };
    } catch (_) {
      return null;
    }
  }

  /// ADR 0006's table for one contact, given what the log holds for its
  /// label: [leaf], the map's latest (index, version) from a verified
  /// bucket — null for a verified absence — and [entry], that entry when it
  /// was fetched. When it was not, the status from the refresh that last
  /// judged the same entry holds what is needed from it (see [_needsEntry]).
  Future<void> _checkContact(
      KtContactInput c, KtBucketLeaf? leaf, KtEntry? entry) async {
    final prev = contacts[c.rid];
    final t = now();
    final heldDevs = c.held == null
        ? {b64(c.primaryDeviceEdPub)}
        : {for (final d in c.held!.devices) b64(d.deviceEdPub)};
    final baseline = {b64(c.primaryDeviceEdPub)};
    final heldFp = c.heldFpB64;

    KtContactStatus next;
    if (leaf == null) {
      // Unlogged: an account that has never published — an older client, or
      // one that has not been online since upgrading. Gossip only, as
      // before the log; nothing is held (ADR 0006, the migration argument).
      next = KtContactStatus(
        state: KtContactState.unlogged,
        checkedAtMs: t,
        confirmedDevs: prev?.confirmedDevs.isNotEmpty == true ? prev!.confirmedDevs : baseline,
        acknowledged: false,
      );
    } else {
      final lv = leaf.version;
      final lf = entry != null ? b64(entry.fp) : prev!.logFpB64!;
      final hv = c.heldVersion;
      // The entry's list, opened and verified as this account's: from the
      // entry when it was fetched, or from what the last refresh kept of the
      // same entry. [unopened] and [refused] are kept in the status for the
      // next refresh, which will not fetch this entry again.
      var unopened = false;
      Map<String, Object?>? refused;
      Future<SignedDeviceList?> logList() async {
        SignedDeviceList? list;
        if (entry != null) {
          list = await _openList(c.accountEdPub, entry);
        } else if (prev?.logList != null && !prev!.logUnopened) {
          list = await _keptList(c.accountEdPub, prev.logList!, lv, lf);
        }
        unopened = list == null;
        return list;
      }

      Future<bool> install(SignedDeviceList list) async {
        final ok = await host.ktInstallFromLog(c.rid, list);
        if (!ok) refused = list.toJson();
        return ok;
      }

      if (lv == hv) {
        if (heldFp == lf) {
          next = KtContactStatus(
            state: KtContactState.confirmed,
            logVersion: lv,
            logFpB64: lf,
            checkedAtMs: t,
            confirmedDevs: heldDevs,
          );
        } else if (c.held == null) {
          // We hold only the baseline placeholder and the log has the account's
          // own signed list at this version. A v2 client publishes even its
          // version-1 baseline in the v2 format (ADR 0010), so its fingerprint
          // differs from our v1 baseline — and the baseline's device id, which
          // the v2 input commits to, is not in a root's contact code to
          // recompute from. Adopt the log's list: it opens and verifies under
          // the account key, and installing it runs the full device-list rules
          // (the floor included). A forged list does not open; a genuine one is
          // the truth the baseline stood in for. (A real held list disagreeing
          // at the same version, below, is a fork.)
          final list = await logList();
          if (list == null) {
            final detail = 'same version $lv, different fingerprint';
            next = KtContactStatus(
              state: KtContactState.conflict,
              logVersion: lv,
              logFpB64: lf,
              checkedAtMs: t,
              confirmedDevs: prev?.confirmedDevs ?? baseline,
              detail: detail,
              acknowledged: _stillAcknowledged(prev, lv, lf, detail),
            );
          } else {
            final installed = await install(list);
            final detail = installed
                ? null
                : 'the log\'s list (v$lv) was refused by the device-list rules';
            next = KtContactStatus(
              state: installed
                  ? KtContactState.confirmed
                  : KtContactState.conflict,
              logVersion: lv,
              logFpB64: lf,
              checkedAtMs: t,
              confirmedDevs: installed
                  ? {for (final d in list.devices) b64(d.deviceEdPub)}
                  : (prev?.confirmedDevs ?? baseline),
              detail: detail,
              acknowledged:
                  detail != null && _stillAcknowledged(prev, lv, lf, detail),
            );
          }
        } else {
          final detail = 'same version $lv, different fingerprint';
          next = KtContactStatus(
            state: KtContactState.conflict,
            logVersion: lv,
            logFpB64: lf,
            checkedAtMs: t,
            confirmedDevs: prev?.confirmedDevs ?? baseline,
            detail: detail,
            acknowledged: _stillAcknowledged(prev, lv, lf, detail),
          );
        }
      } else if (lv > hv) {
        // The log is ahead: it is a source (11.5).
        final list = await logList();
        if (list == null) {
          final detail = 'the log\'s entry (v$lv) does not open or verify as this account\'s list';
          next = KtContactStatus(
            state: KtContactState.conflict,
            logVersion: lv,
            logFpB64: lf,
            checkedAtMs: t,
            confirmedDevs: prev?.confirmedDevs ?? baseline,
            detail: detail,
            acknowledged: _stillAcknowledged(prev, lv, lf, detail),
          );
        } else {
          final installed = await install(list);
          final detail = installed ? null : 'the log\'s list (v$lv) was refused by the device-list rules';
          next = KtContactStatus(
            state: installed ? KtContactState.confirmed : KtContactState.conflict,
            logVersion: lv,
            logFpB64: lf,
            checkedAtMs: t,
            confirmedDevs: installed ? {for (final d in list.devices) b64(d.deviceEdPub)} : (prev?.confirmedDevs ?? baseline),
            detail: detail,
            acknowledged: detail != null && _stillAcknowledged(prev, lv, lf, detail),
          );
        }
      } else {
        // In-band ahead of the log: unconfirmed. The confirmed device set is
        // the log's last list, opened now if we never had it.
        var confirmed = prev?.confirmedDevs ?? const <String>{};
        if (confirmed.isEmpty || prev?.logVersion != lv) {
          final list = await logList();
          confirmed = list == null ? baseline : {for (final d in list.devices) b64(d.deviceEdPub)};
        }
        next = KtContactStatus(
          state: KtContactState.unconfirmed,
          logVersion: lv,
          logFpB64: lf,
          checkedAtMs: t,
          unconfirmedSinceMs: prev?.unconfirmedSinceMs ?? c.heldAtMs ?? t,
          confirmedDevs: confirmed,
          heldRids: prev?.heldRids,
          detail: 'held v$hv, log has v$lv',
        );
      }
      next.logIndex = leaf.index;
      if (next.state == KtContactState.conflict) {
        next.logUnopened = unopened;
        next.logList = refused;
      }
    }
    // A hold is computed by the grace pass; carry it while the state stays.
    if (next.state != KtContactState.unconfirmed) next.heldRids = {};
    next.heldVersion = c.heldVersion;
    contacts[c.rid] = next;
    await _saveContact(c.rid);
  }

  /// A list an earlier refresh opened from the log and kept (the device-list
  /// rules refused it then), held to what [_openList] holds one it opens to.
  Future<SignedDeviceList?> _keptList(Uint8List accountEdPub,
      Map<String, Object?> j, int version, String fpB64) async {
    try {
      final list = SignedDeviceList.fromJson(j);
      if (b64(list.accountEdPub) != b64(accountEdPub)) return null;
      if (list.version != version) return null;
      if (!await list.verify()) return null;
      if (b64(await list.fingerprint()) != fpB64) return null;
      return list;
    } catch (_) {
      return null;
    }
  }

  /// Open a log entry's value as this account's signed list and verify it;
  /// null when it does not open, does not verify, or is not the entry's
  /// (version, fingerprint).
  Future<SignedDeviceList?> _openList(Uint8List accountEdPub, KtEntry e) async {
    final plain = await ktOpenValue(accountEdPub, e.value);
    if (plain == null) return null;
    try {
      final list = SignedDeviceList.fromJson((jsonDecode(utf8.decode(plain)) as Map).cast<String, Object?>());
      if (b64(list.accountEdPub) != b64(accountEdPub)) return null;
      if (list.version != e.version) return null;
      if (!await list.verify()) return null;
      if (b64(await list.fingerprint()) != b64(e.fp)) return null;
      return list;
    } catch (_) {
      return null;
    }
  }

  Future<void> _checkOwn(Uint8List logPub) async {
    final own = await host.ktOwn();
    if (own == null) return;
    final label = await ktLabel(own.accountEdPub);
    // The log's latest for us, and our whole history.
    final j = await _getJson(_url('/kt/v1/lookup/${_hex(label)}'));
    if (j == null) {
      await _fail();
      return;
    }
    KtLookupResult r;
    try {
      r = await ktVerifyLookup(await KtLookup.fromJson(j), label: label, logPub: logPub);
    } on KtVerifyException catch (e) {
      await _setFault('lookup for this account: ${e.reason}');
      return;
    }
    final latest = r.latest;
    final canPublish = own.accountEdSeed != null && own.listJson != null;
    if (latest == null || latest.version < own.version) {
      // Not in the log, or behind it: publish what we hold (11.5 on first
      // run; otherwise a publish that never arrived).
      if (canPublish && _pendingPublish == null) {
        await publishOwnList(
          accountEdSeed: own.accountEdSeed!,
          accountEdPub: own.accountEdPub,
          version: own.version,
          fp: unb64(own.fpB64),
          listJson: own.listJson!,
        );
      }
    }
    // The whole history first, judged after: the own-list repair (ADR 0026)
    // asks which devices this device's own records name, and those are in
    // the entries that match the record. A walk that fails or faults has
    // said so; the authenticated latest is judged all the same, below.
    final history = <KtEntry>[];
    final walked = await _ownHistory(label, logPub, history);
    final judge = _OwnJudgement(this, own, history);
    // Self-monitoring, on the AUTHENTICATED latest first.
    //
    // `latest` is proved to be what the log is serving for this label, and
    // until now it was read only to decide whether to publish. Everything
    // that could raise an alert lived in the walk over the history response
    // below — and an empty history is not a fault, because an account that
    // has never published legitimately has one. So a log that served a
    // correct head, a correct lookup naming a version and fingerprint this
    // device never issued, and `entries: []` was believed in full and said
    // nothing: the rogue publish was authenticated, displayed to the reader
    // as current, and hidden from its owner. That is the exact failure
    // `adr/0006` says the log exists to make impossible.
    if (latest != null) {
      final raised = await _judgeOwnEntry(latest, judge);
      // And the latest, where it opens as one of this account's lists, to
      // the service: a list that omits this device, at a version above the
      // one it holds, is this device's evidence that it was removed (ADR
      // 0026) — whether or not any contact ever says so.
      final list = await judge.open(latest);
      final hook = onOwnLatest;
      if (list != null && hook != null) {
        await hook(list,
            reconciled: ownListReconciled(latest.version, b64(latest.fp)));
      }
      if (raised) return;
    }
    if (!walked) return;
    // And then every entry in our history must be one we know.
    for (final e in history) {
      if (await _judgeOwnEntry(e, judge)) return;
    }
    // An alert raised on an entry this device now holds as its own — one the
    // repair reconciled, or a list learned since — is not one to go on
    // showing. Cleared, not dismissed: the user decided nothing.
    final shown = ownAlert;
    if (shown != null && ownListKnown(shown.version, shown.fpB64)) {
      ownAlert = null;
      await vault.kvDelete('kt_own_alert');
    }
  }

  /// Every entry of this account's history, page by page, into [out]. False
  /// when the walk could not finish — the log unreachable, or a page that
  /// does not verify, which is a fault and is recorded as one here.
  ///
  /// Read as pages, because the log may answer with one. A version this
  /// device did not issue is what this walk exists to find, so stopping
  /// early would be a log able to hide an entry by serving a short page —
  /// the same failure as an empty `entries`, reached by a different road.
  /// The page says how many the label has in total, and we keep asking until
  /// we have seen them all; a page that does not verify is a log that is not
  /// answering the question, which is a fault rather than a clean bill.
  Future<bool> _ownHistory(
      Uint8List label, Uint8List logPub, List<KtEntry> out) async {
    var start = 0;
    var total = -1;
    while (true) {
      final hj = await _getJson(_url('/kt/v1/history/${_hex(label)}?start=$start'));
      if (hj == null) {
        await _fail();
        return false;
      }
      KtTreeHead hh;
      try {
        hh = KtTreeHead.fromJson((hj['sth'] as Map).cast<String, Object?>());
      } on KtVerifyException catch (e) {
        await _setFault('history for this account: ${e.reason}');
        return false;
      } catch (_) {
        await _setFault('history for this account could not be read');
        return false;
      }
      if (!await _adopt(hh, logPub)) return false;
      final items = hj['entries'] as List? ?? const [];
      // An older log served no `total`; then one response is the whole
      // history and this loop runs once, exactly as it did before.
      final t = hj['total'];
      total = t is int ? t : start + items.length;
      for (final item in items) {
        try {
          out.add(await ktVerifyHistoryItem((item as Map).cast<String, Object?>(), head: hh, label: label));
        } on KtVerifyException catch (err) {
          await _setFault('history for this account: ${err.reason}');
          return false;
        } catch (_) {
          await _setFault('history for this account could not be read');
          return false;
        }
      }
      start += items.length;
      // A log that stops short is NOT a fault, and the difference matters.
      // `fault` is sticky and suppresses every later check, the judgement of
      // the authenticated `latest` included — so a log that wanted to stop
      // being watched could do it by serving one short page. What a log
      // refuses to show is already covered, and covered better: `latest` is
      // map-proven under a signed head and is judged whatever this walk
      // returns, which is why an empty history says nothing here.
      if (items.isEmpty || start >= total) return true;
    }
  }

  /// Is this entry something this account issued? Raise the alert if it is
  /// not — and only on evidence. True when the alert now stands on it.
  ///
  /// One judgement, used for the authenticated `latest` AND for every history
  /// entry, because having it in only one of those places is how a log got to
  /// serve a rogue current value with an empty history and be believed.
  Future<bool> _judgeOwnEntry(KtEntry e, _OwnJudgement judge) async {
    final version = e.version;
    final fp = b64(e.fp);
    final own = judge.own;
    // Versions before this device knew the account are before its time — a
    // linked device joins mid-history.
    final first = _firstKnownV;
    if (first != null && version < first) return false;
    if (ownListKnown(version, fp)) return false;
    final recorded = _knownOwn.containsKey(version);
    if (!recorded && own.accountEdSeed == null) {
      // A linked device learns lists by self-sync and can skip versions (v4
      // to v6 while it was off), so a version it never saw is not evidence;
      // only the root, which signs every list, can say an unknown version is
      // one it did not issue. A KNOWN version with another fingerprint is a
      // contradiction on any device.
      return false;
    }
    // Evidence, or not (ADR 0026). The alert tells the owner a device list
    // was issued for their account behind their back, so it is raised on a
    // list the account's key signed: the entry's value opened as this
    // account's list, verified, at this version, with this fingerprint
    // (§19.3). An entry that does not open is not that. The log does not
    // serve the publish signature (§19.6), so nothing here says who put it
    // there, and its operator can put one under any label without anybody's
    // key — it can open values (§19.1) — which made this banner one the
    // operator could raise against every account at will. Kept as a quiet
    // diagnostic; the account's contacts still treat the entry as a conflict
    // and hold sends (adr/0006), and nothing about it installs a device
    // anywhere.
    final list = await judge.open(e);
    if (list == null) {
      await _noteOwnUnverified(version, fp);
      return false;
    }
    if (recorded && await _reconcilable(e, list, judge)) {
      _reconciledOwn[version] = fp;
      await vault.kvPut(
          'kt_own_reconciled',
          jsonEncode(
              {for (final r in _reconciledOwn.entries) '${r.key}': r.value}));
      return false;
    }
    if (dismissals.contains(logEntryEvidence(version, fp))) return false;
    if (ownAlert == null ||
        ownAlert!.version != version ||
        ownAlert!.fpB64 != fp) {
      ownAlert = KtOwnAlert(version: version, fpB64: fp, atMs: now());
      await vault.kvPut('kt_own_alert', jsonEncode(ownAlert!.toJson()),
          sensitive: false);
    }
    return true;
  }

  /// The own-list repair (ADR 0026): may the log's entry [e], at a version
  /// this device recorded under another fingerprint, be taken as the
  /// account's own list rather than raised as one it never issued?
  ///
  /// The signing race of patch 42 (fixed in 3.9.10) left vaults whose record
  /// of a version was overwritten by a second list the root signed at it —
  /// the version before a link with the devices after it, or the reverse —
  /// after the first had reached the log. Such a vault judged its own
  /// genuine entry never issued, and said so at every start. The record
  /// cannot say which of two lists at one version came first; these three
  /// conditions are what the race's end state always meets and an attack
  /// that wants to stay hidden cannot meet any more:
  ///
  ///  * it is from before this build: the entry was in the log under the
  ///    head this device held when this build first ran on its vault, and
  ///    the version was recorded then. The log takes no version at or below
  ///    one it holds, and a head that does not extend the held one is a
  ///    fault, so nothing can join that set afterwards — and since 3.9.10 a
  ///    version keeps the first list recorded at it, so no record made since
  ///    can have been overwritten;
  ///  * it is a list the account's key signed — opened and verified, which
  ///    the caller has done;
  ///  * every device it names is one this account is known to have held:
  ///    this device's records (`KtOwnInput.devicesHeld`) and the devices of
  ///    every entry in the log that matches its record of its own lists. The
  ///    race only ever signed the account's own devices.
  ///
  /// What whoever holds the root seed can still do under it is no more than
  /// before it: an entry they put in the log before this build ran, at a
  /// version this device had signed differently, naming only devices the
  /// account had held, no longer raises the banner — the same banner the race
  /// was raising at every start for the same reason, and which therefore
  /// told such a vault's owner nothing. Anything they publish from now on,
  /// and anything naming a device the account never held, alarms as before.
  Future<bool> _reconcilable(
      KtEntry e, SignedDeviceList list, _OwnJudgement judge) async {
    if (e.index >= _legacySize) return false;
    if (!_legacyVersions.contains(e.version)) return false;
    final held = await judge.held();
    return list.devices.every((d) => held.contains(b64(d.deviceEdPub)));
  }

  Future<void> _noteOwnUnverified(int version, String fp) async {
    final seen = ownUnverified;
    if (seen != null && seen.version == version && seen.fpB64 == fp) return;
    ownUnverified = KtOwnAlert(version: version, fpB64: fp, atMs: now());
    await vault.kvPut('kt_own_unverified', jsonEncode(ownUnverified!.toJson()));
  }

  Future<void>? _publishRun;
  bool _flushAgain = false;

  /// One flush at a time; a caller while one runs joins it — and is sent.
  ///
  /// A caller used to join whatever flush was running, and a flush reads the
  /// queue once, as it starts. So a list queued after that read — a root
  /// moving past a reconciled version (ADR 0026) does exactly that while the
  /// check that prompted it is still flushing — joined a flush that had
  /// already decided there was nothing to send, and waited in the queue for
  /// the next check. A check at every start and a recheck after every list
  /// change hid that; phase 35 runs neither. A caller now marks the queue for
  /// another look, the flush looks again before it lets go, and it lets go
  /// in the same step as its last look, so nothing can join it after that.
  Future<void> _flushPublish() {
    final running = _publishRun;
    if (running != null) {
      _flushAgain = true;
      return running;
    }
    final run = () async {
      try {
        Map<String, Object?>? tried;
        do {
          _flushAgain = false;
          tried = _pendingPublish;
          await _flushPublishOnce();
          // Again only for a publish queued since: the one just tried, if it
          // is still queued (429, 5xx), waits for its own retry.
        } while (_flushAgain &&
            _pendingPublish != null &&
            !identical(_pendingPublish, tried) &&
            !_disposed);
      } finally {
        _publishRun = null;
      }
    }();
    _publishRun = run;
    return run;
  }

  Future<void> _flushPublishOnce() async {
    final req = _pendingPublish;
    if (req == null || !config.enabled || _offLimitsInTest) return;
    try {
      KtResponse r;
      try {
        r = await fetcher.post(_url('/kt/v1/publish'), jsonEncode(req));
      } catch (_) {
        await _fail();
        return;
      }
      if (r.status == 201 || (r.status >= 400 && r.status < 500 && r.status != 429)) {
        // Accepted; or the log already holds this or a newer version (409 —
        // the history check says whether that is ours); or malformed, which
        // a retry will not fix. In every case the queue is cleared.
        if (_pendingPublish == req) {
          _pendingPublish = null;
          await vault.kvDelete('kt_pub_pending');
        }
        if (r.status == 201 || r.status == 409) {
          await vault.kvPut('kt_pub_done', '${req['v']}|${req['fp']}', sensitive: false);
        }
      } else {
        // 429 is a gate (PROTOCOL §19.7): the log said not now, not no. It
        // was read as a 4xx until 2026-09-17 and the publish was dropped —
        // to be re-queued by the next check, six hours later, if the log
        // still lacked it — which turned a minute's refusal into six hours
        // without the list in the log, exactly the delay ADR 0006's grace
        // period charges the account's contacts for. The log being at
        // capacity is not the log being unreachable, so it is not a
        // failure either; a 5xx is both kept and counted. Either way the
        // publish stays queued and is tried again soon.
        if (r.status != 429) await _fail();
        _publishRetry?.cancel();
        if (!_disposed) {
          _publishRetry = Timer(publishRetryDelay, () => unawaited(_flushPublish()));
        }
      }
    } catch (_) {
      // A flush must not take a check down.
    }
  }

  /// Whether the user's "send anyway" still stands.
  ///
  /// An acknowledgement is of a piece of evidence — this version, this
  /// fingerprint, this way of being wrong — and it is carried only while the
  /// evidence is the same. Until 2026-09-17 it was carried from any conflict
  /// to any conflict: the user waved through "same version 5, different
  /// fingerprint", and a v7 entry that did not even open as the account's
  /// list arrived acknowledged — no banner, no hold, no word (the 2026-09-14
  /// review's finding 11). ADR 0006 says "until the next check agrees or the
  /// user chooses to send anyway"; the user chose for what was on the screen.
  static bool _stillAcknowledged(KtContactStatus? prev, int lv, String lf, String detail) =>
      prev != null &&
      prev.state == KtContactState.conflict &&
      prev.acknowledged &&
      prev.logVersion == lv &&
      prev.logFpB64 == lf &&
      prev.detail == detail;

  /// The grace pass: every unconfirmed contact past the grace period has the
  /// devices only its held list added put on hold. Needs the current held
  /// lists, so it asks the host; runs whether or not the log was reachable.
  Future<void> _applyGrace() async {
    final due = [
      for (final e in contacts.entries)
        if (e.value.state == KtContactState.unconfirmed &&
            e.value.unconfirmedSinceMs != null &&
            now() - e.value.unconfirmedSinceMs! >= grace.inMilliseconds)
          e.key
    ];
    if (due.isEmpty) return;
    final inputs = {for (final c in await host.ktContacts()) c.rid: c};
    for (final rid in due) {
      final s = contacts[rid]!;
      final c = inputs[rid];
      if (c == null || c.held == null) continue;
      final held = <String>{};
      for (final d in c.held!.devices) {
        if (s.confirmedDevs.contains(b64(d.deviceEdPub))) continue;
        if (b64(d.deviceEdPub) == b64(c.primaryDeviceEdPub)) continue; // never the scanned device
        held.add(await d.routingId());
      }
      if (!setEquals(held, s.heldRids)) {
        s.heldRids = held;
        await _saveContact(rid);
      }
    }
  }

  static String _hex(Uint8List b) => [for (final x in b) x.toRadixString(16).padLeft(2, '0')].join();
}

/// One own-label check's view of the log (ADR 0026): the entries it read,
/// each opened at most once, and — computed only when the own-list repair
/// needs it — the devices this account is known to have held.
class _OwnJudgement {
  _OwnJudgement(this._kt, this.own, this._history);

  final KeyTransparency _kt;
  final KtOwnInput own;
  final List<KtEntry> _history;
  final Map<int, SignedDeviceList?> _opened = {};
  Set<String>? _held;

  /// [e] opened and verified as this account's list (§19.3), or null.
  Future<SignedDeviceList?> open(KtEntry e) async {
    if (_opened.containsKey(e.index)) return _opened[e.index];
    return _opened[e.index] = await _kt._openList(own.accountEdPub, e);
  }

  /// The devices (Ed25519 keys, b64) this account is known to have held:
  /// what the host's records say, the account key itself (device #1), and
  /// every device named by an entry in the log whose (version, fingerprint)
  /// is this device's own record of that version. The fingerprint commits
  /// to the device set, so such an entry names exactly the devices this
  /// device recorded — the log cannot widen it.
  Future<Set<String>> held() async {
    final known = _held;
    if (known != null) return known;
    final out = <String>{...own.devicesHeld, b64(own.accountEdPub)};
    final mine = own.deviceEdPub;
    if (mine != null) out.add(b64(mine));
    for (final e in _history) {
      if (_kt._knownOwn[e.version] != b64(e.fp)) continue;
      final list = await open(e);
      if (list == null) continue;
      for (final d in list.devices) {
        out.add(b64(d.deviceEdPub));
      }
    }
    return _held = out;
  }
}
