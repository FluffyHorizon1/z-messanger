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
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:z_protocol/z_protocol.dart';

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

  KtOwnInput({
    required this.accountEdPub,
    required this.version,
    required this.fpB64,
    required this.listJson,
    required this.accountEdSeed,
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

  /// ADR 0006's numbers, settable for tests.
  Duration grace = const Duration(hours: 24);
  Duration checkEvery = const Duration(hours: 6);
  Duration staleHead = const Duration(hours: 24);
  Duration unreachableAfter = const Duration(hours: 24);

  /// How soon after a contact's list changes it is re-checked.
  Duration recheckDelay = const Duration(seconds: 30);

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

  Timer? _timer;
  Timer? _recheck;
  Timer? _publishRetry;
  final Set<String> _dirty = {};
  Future<void>? _running;
  bool _disposed = false;

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
    for (final e in (await vault.kvScan('ktc_')).entries) {
      try {
        contacts[e.key.substring(4)] =
            KtContactStatus.fromJson((jsonDecode(e.value) as Map).cast<String, Object?>());
      } catch (_) {}
    }
  }

  /// Start the periodic check; the first runs at once.
  void start() {
    _timer?.cancel();
    if (_offLimitsInTest) return;
    _timer = Timer.periodic(checkEvery, (_) => unawaited(check()));
    unawaited(check());
  }

  void dispose() {
    _disposed = true;
    _timer?.cancel();
    _recheck?.cancel();
    _publishRetry?.cancel();
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
    host.ktChanged();
    unawaited(check());
  }

  /// Forget the accepted head and any fault — for a deliberate change of log,
  /// or after a fault has been reported and understood. Contact statuses are
  /// re-derived by the next check.
  Future<void> resetHistory() async {
    head = null;
    fault = null;
    lastOkMs = 0;
    lastFailMs = 0;
    await vault.kvDelete('kt_head');
    await vault.kvDelete('kt_fault');
    await vault.kvDelete('kt_last_ok_ms');
    await vault.kvDelete('kt_last_fail_ms');
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

  Future<void> acknowledgeOwnAlert() async {
    ownAlert = null;
    await vault.kvDelete('kt_own_alert');
    host.ktChanged();
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

  /// A contact's held list changed (installed in-band): re-check it soon.
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
    _dirty.add(rid);
    _recheck?.cancel();
    _recheck = Timer(recheckDelay, () => unawaited(check(only: _dirty.toSet())));
  }

  Future<void> noteContactRemoved(String rid) async {
    contacts.remove(rid);
    await vault.kvDelete('ktc_$rid');
  }

  // --- the check ------------------------------------------------------------

  /// One full check (§19.5 + ADR 0006's table). Serialised: a check while
  /// one runs waits for it. [only] limits the contact pass.
  Future<void> check({Set<String>? only}) {
    final prev = _running;
    final run = () async {
      if (prev != null) await prev;
      if (_disposed) return;
      try {
        await _checkOnce(only: only);
      } catch (_) {
        // A check must never take the service down; the next one runs on
        // schedule and the health reflects what happened.
      }
    }();
    _running = run;
    return run;
  }

  Future<void> _checkOnce({Set<String>? only}) async {
    if (!config.enabled || _offLimitsInTest) return;
    final logPub = config.logPub!;
    _dirty.removeAll(only ?? const {});
    if (fault == null) {
      final accepted = await _acceptHead(logPub);
      if (accepted) {
        await _checkContacts(logPub, only: only);
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
    return _adopt(fresh, logPub);
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
    lastOkMs = now();
    await vault.kvPut('kt_head', jsonEncode(fresh.toJson()), sensitive: false);
    await vault.kvPut('kt_last_ok_ms', '$lastOkMs', sensitive: false);
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
    if (rec.head.size > fresh.size) {
      await _setFault(
          'the log served a head of size ${fresh.size}, older than the witness\'s ${rec.head.size}',
          served: fresh);
      return false;
    }
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

  Future<void> _saveContact(String rid) async {
    final s = contacts[rid];
    if (s == null) return;
    await vault.kvPut('ktc_$rid', jsonEncode(s.toJson()), sensitive: false);
  }

  Future<void> _checkContacts(Uint8List logPub, {Set<String>? only}) async {
    final inputs = await host.ktContacts();
    final present = inputs.map((c) => c.rid).toSet();
    for (final rid in contacts.keys.toList()) {
      if (!present.contains(rid)) await noteContactRemoved(rid);
    }
    for (final c in inputs) {
      if (only != null && !only.contains(c.rid)) continue;
      if (fault != null) return;
      await _checkContact(c, logPub);
    }
  }

  Future<void> _checkContact(KtContactInput c, Uint8List logPub) async {
    final label = await ktLabel(c.accountEdPub);
    final j = await _getJson(_url('/kt/v1/lookup/${_hex(label)}'));
    if (j == null) {
      await _fail();
      return;
    }
    KtLookupResult r;
    try {
      r = await ktVerifyLookup(await KtLookup.fromJson(j), label: label, logPub: logPub);
    } on KtVerifyException catch (e) {
      // A proof that fails under a good head is the log misbehaving, not the
      // contact (§19.5).
      await _setFault('lookup for a contact: ${e.reason}');
      return;
    }
    // The lookup's head must be the accepted one or an extension of it
    // (§19.5): a lookup under a newer head goes through the same checks as
    // a head fetched on its own, and becomes the held head.
    if (!await _adopt(r.head, logPub)) return;
    final prev = contacts[c.rid];
    final t = now();
    final heldDevs = c.held == null
        ? {b64(c.primaryDeviceEdPub)}
        : {for (final d in c.held!.devices) b64(d.deviceEdPub)};
    final baseline = {b64(c.primaryDeviceEdPub)};
    final heldFp = c.heldFpB64;

    KtContactStatus next;
    final latest = r.latest;
    if (latest == null) {
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
      final lv = latest.version;
      final lf = b64(latest.fp);
      final hv = c.heldVersion;
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
          final list = await _openList(c.accountEdPub, latest);
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
            final installed = await host.ktInstallFromLog(c.rid, list);
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
        final list = await _openList(c.accountEdPub, latest);
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
          final installed = await host.ktInstallFromLog(c.rid, list);
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
          final list = await _openList(c.accountEdPub, latest);
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
    }
    // A hold is computed by the grace pass; carry it while the state stays.
    if (next.state != KtContactState.unconfirmed) next.heldRids = {};
    next.heldVersion = c.heldVersion;
    contacts[c.rid] = next;
    await _saveContact(c.rid);
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
      await _judgeOwnEntry(latest.version, b64(latest.fp), own);
      if (ownAlert != null) return;
    }
    // And then every entry in our history must be one we know.
    //
    // Read as pages, because the log may answer with one. A version this
    // device did not issue is what this walk exists to find, so stopping
    // early would be a log able to hide an entry by serving a short page —
    // the same failure as the empty `entries` above, reached by a different
    // road. The page says how many the label has in total, and we keep asking
    // until we have seen them all; a page that carries nothing new, or a
    // `total` that shrinks under us, is a log that is not answering the
    // question, which is a fault rather than a clean bill.
    var start = 0;
    var total = -1;
    while (true) {
      final hj = await _getJson(_url('/kt/v1/history/${_hex(label)}?start=$start'));
      if (hj == null) {
        await _fail();
        return;
      }
      KtTreeHead hh;
      try {
        hh = KtTreeHead.fromJson((hj['sth'] as Map).cast<String, Object?>());
      } on KtVerifyException catch (e) {
        await _setFault('history for this account: ${e.reason}');
        return;
      } catch (_) {
        await _setFault('history for this account could not be read');
        return;
      }
      if (!await _adopt(hh, logPub)) return;
      final items = hj['entries'] as List? ?? const [];
      // An older log served no `total`; then one response is the whole
      // history and this loop runs once, exactly as it did before.
      final t = hj['total'];
      total = t is int ? t : start + items.length;
      for (final item in items) {
        KtEntry e;
        try {
          e = await ktVerifyHistoryItem((item as Map).cast<String, Object?>(), head: hh, label: label);
        } on KtVerifyException catch (err) {
          await _setFault('history for this account: ${err.reason}');
          return;
        } catch (_) {
          await _setFault('history for this account could not be read');
          return;
        }
        await _judgeOwnEntry(e.version, b64(e.fp), own);
        if (ownAlert != null) return;
      }
      start += items.length;
      // A log that stops short is NOT a fault, and the difference matters.
      // `fault` is sticky and suppresses every later check, the judgement of
      // the authenticated `latest` above included — so a log that wanted to
      // stop being watched could do it by serving one short page. What a log
      // refuses to show is already covered, and covered better: `latest` is
      // map-proven under a signed head and is judged before this walk runs,
      // which is why an empty history says nothing here.
      if (items.isEmpty || start >= total) return;
    }
  }

  /// Is (version, fp) something this account issued? Raise the alert if not.
  ///
  /// One judgement, used for the authenticated `latest` AND for every history
  /// entry, because having it in only one of those places is how a log got to
  /// serve a rogue current value with an empty history and be believed.
  Future<void> _judgeOwnEntry(int version, String fp, KtOwnInput own) async {
    // Versions before this device knew the account are before its time — a
    // linked device joins mid-history.
    final first = _firstKnownV;
    if (first != null && version < first) return;
    final known = _knownOwn[version];
    if (known == fp) return;
    if (known == null && own.accountEdSeed == null) {
      // A linked device learns lists by self-sync and can skip versions (v4
      // to v6 while it was off), so a version it never saw is not evidence;
      // only the root, which signs every list, can say an unknown version is
      // one it did not issue. A KNOWN version with another fingerprint is a
      // contradiction on any device.
      return;
    }
    if (ownAlert == null ||
        ownAlert!.version != version ||
        ownAlert!.fpB64 != fp) {
      ownAlert = KtOwnAlert(version: version, fpB64: fp, atMs: now());
      await vault.kvPut('kt_own_alert', jsonEncode(ownAlert!.toJson()),
          sensitive: false);
    }
  }

  Future<void>? _publishRun;

  /// One flush at a time; a caller while one runs joins it.
  Future<void> _flushPublish() {
    final running = _publishRun;
    if (running != null) return running;
    final run = _flushPublishOnce().whenComplete(() => _publishRun = null);
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
