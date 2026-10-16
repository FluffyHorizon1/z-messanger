import 'dart:convert';
import 'dart:math';

/// When a held receipt may leave (ADR 0028, `PROTOCOL.md` §6.3).
///
/// A receipt never leaves sooner than [floor] after the message it answers
/// arrived — nor, after a reconnect, sooner than [floor] after the device
/// came back — and leaves at the latest at a moment drawn uniformly between
/// [floor] and [ceiling] after it became owed. Riding with a message the user
/// sends to the same person, it may go earlier than its draw, never earlier
/// than its floor.
class ReceiptTiming {
  final Duration floor;
  final Duration ceiling;

  /// [ceiling] at least [floor]; a ceiling below it acts as the floor.
  const ReceiptTiming({required this.floor, required this.ceiling});

  /// What the app uses: 5 s to a minute.
  static const standard = ReceiptTiming(
      floor: Duration(seconds: 5), ceiling: Duration(seconds: 60));
}

/// One receipt owed to a contact: [read] or delivered, for message [mid].
class HeldReceipt {
  final String mid;
  final bool read;

  /// Not before this (ms since the epoch) — the wall-clock floor, kept for the
  /// vault (the monotonic one below cannot be persisted) and re-floored on
  /// load and after a reconnect.
  int notBeforeMs;

  /// Not before this on a monotonic clock (ms): the floor that decides whether
  /// the receipt may leave now. A forward change to the wall clock — a
  /// sleep/wake, an NTP step, the user setting the time — moves [notBeforeMs]
  /// relative to `now` but not this, so it cannot bring a held receipt forward
  /// inside its real floor.
  int notBeforeMono;

  /// At the latest about then (ms since the epoch).
  int dueMs;

  HeldReceipt(this.mid,
      {required this.read,
      required this.notBeforeMs,
      required this.notBeforeMono,
      required this.dueMs});
}

/// The receipts this device owes, per contact, and when each may go.
///
/// Pure bookkeeping — no timers, no sending, no storage: `ChatService` owns
/// those and asks this what is due. Kept apart so the rule that decides what
/// the relay can see is in one place, readable in one sitting.
class ReceiptQueue {
  ReceiptTiming timing;
  final int Function() _now;
  final int Function() _mono;
  final Random _rng;
  final Map<String, List<HeldReceipt>> _held = {};

  /// [now] is the wall clock (ms since the epoch): kept for the vault, the due
  /// moment, and the re-floor after a reconnect. [mono] is a monotonic clock
  /// (ms) on which the floor that gates eligibility is measured, so a forward
  /// jump of the wall clock cannot defeat it; it defaults to a [Stopwatch]
  /// started here and is injected only by a test that drives it.
  ReceiptQueue(
      {this.timing = ReceiptTiming.standard,
      required int Function() now,
      int Function()? mono,
      Random? random})
      : _now = now,
        _mono = mono ?? _stopwatchMs(),
        _rng = random ?? Random.secure();

  static int Function() _stopwatchMs() {
    final w = Stopwatch()..start();
    return () => w.elapsedMilliseconds;
  }

  int _draw(int from) {
    final f = timing.floor.inMilliseconds, c = timing.ceiling.inMilliseconds;
    return from + f + (c > f ? _rng.nextInt(c - f + 1) : 0);
  }

  /// [rid] is owed a receipt for [mid], which arrived (or was read) now. One
  /// already held for the same message and kind keeps its own times.
  void owe(String rid, String mid, {required bool read}) {
    final list = _held.putIfAbsent(rid, () => []);
    if (list.any((r) => r.mid == mid && r.read == read)) return;
    final now = _now();
    list.add(HeldReceipt(mid,
        read: read,
        notBeforeMs: now + timing.floor.inMilliseconds,
        notBeforeMono: _mono() + timing.floor.inMilliseconds,
        dueMs: _draw(now)));
  }

  /// When [rid]'s next receipt is due, or null if none is held.
  int? nextDueMs(String rid) {
    final list = _held[rid];
    if (list == null || list.isEmpty) return null;
    return list.map((r) => r.dueMs).reduce(min);
  }

  /// Take [rid]'s receipts that may leave now — every one past its floor —
  /// or, with [all], every one held (a test's flush). What is taken is
  /// forgotten here: the caller sends it.
  ({List<String> delivered, List<String> read}) take(String rid,
      {bool all = false}) {
    final list = _held[rid];
    if (list == null) return (delivered: const [], read: const []);
    final mono = _mono();
    final go = [
      for (final r in list)
        if (all || r.notBeforeMono <= mono) r
    ];
    list.removeWhere(go.contains);
    if (list.isEmpty) _held.remove(rid);
    return (
      delivered: [
        for (final r in go)
          if (!r.read) r.mid
      ],
      read: [
        for (final r in go)
          if (r.read) r.mid
      ],
    );
  }

  /// Whether any of [rid]'s receipts may leave now.
  bool anyEligible(String rid) => eligible(rid) > 0;

  /// How many of [rid]'s receipts may leave now.
  int eligible(String rid) {
    final mono = _mono();
    return (_held[rid] ?? const [])
        .where((r) => r.notBeforeMono <= mono)
        .length;
  }

  /// The device has just (re)connected: nothing held leaves sooner than the
  /// floor from now, and a receipt whose moment fell while it was away — or
  /// would fall inside that floor — gets a new one.
  void deferAfterConnect() {
    final now = _now();
    final floorAt = now + timing.floor.inMilliseconds;
    final monoFloorAt = _mono() + timing.floor.inMilliseconds;
    for (final list in _held.values) {
      for (final r in list) {
        if (r.notBeforeMs < floorAt) r.notBeforeMs = floorAt;
        if (r.notBeforeMono < monoFloorAt) r.notBeforeMono = monoFloorAt;
        if (r.dueMs < floorAt) r.dueMs = _draw(now);
      }
    }
  }

  void drop(String rid) => _held.remove(rid);
  void clear() => _held.clear();

  Iterable<String> get rids => _held.keys;

  int count({bool? read}) => _held.values.fold(
      0,
      (n, list) =>
          n + list.where((r) => read == null || r.read == read).length);

  /// [rid]'s receipts as stored in the vault, or null when none is held.
  String? encode(String rid) {
    final list = _held[rid];
    if (list == null || list.isEmpty) return null;
    return jsonEncode([
      for (final r in list) [r.mid, r.read ? 'r' : 'd', r.notBeforeMs, r.dueMs]
    ]);
  }

  /// Restore [rid]'s receipts from [stored]; anything malformed is passed
  /// over — a receipt lost is a tick that stays grey, nothing worse.
  void load(String rid, String stored) {
    Object? v;
    try {
      v = jsonDecode(stored);
    } catch (_) {
      return;
    }
    if (v is! List) return;
    for (final e in v) {
      if (e is List &&
          e.length == 4 &&
          e[0] is String &&
          (e[0] as String).isNotEmpty &&
          (e[0] as String).length <= 64 &&
          (e[1] == 'r' || e[1] == 'd') &&
          e[2] is int &&
          e[3] is int) {
        final list = _held.putIfAbsent(rid, () => []);
        final read = e[1] == 'r';
        if (list.any((r) => r.mid == e[0] && r.read == read)) continue;
        // The monotonic floor cannot be persisted — this process's clock
        // started at its own zero — so a loaded receipt is floored afresh from
        // now, as a reconnect would, and `deferAfterConnect` re-floors it
        // again once the device is online.
        list.add(HeldReceipt(e[0] as String,
            read: read,
            notBeforeMs: e[2] as int,
            notBeforeMono: _mono() + timing.floor.inMilliseconds,
            dueMs: e[3] as int));
      }
    }
  }
}
