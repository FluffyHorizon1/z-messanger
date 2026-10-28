/// Public introduction links in the app (phase 39; ADR 0032; PROTOCOL §21.9).
///
/// A public link is a handle's introduction mailbox handed out directly — on a
/// web page, in an email signature, as a printed QR — with no handle log
/// between: `https://host/c#zi1.<code>`, carrying what a request through a
/// handle takes from the handle's record, the work it costs, the
/// introduction key and the key it is sealed to ([IntroLink], in the protocol
/// library). Everything else a link needs is what a handle has already, and
/// it lives beside the handle's in `handles.dart`: the owner's drain on a
/// connection of its own, the ledger that decides each request once, the cap
/// on pending requests, the acknowledgement, the outgoing list, the stamp.
/// None of it needs a handle log, and none of it asks one.
///
/// This file holds what is a link's alone: the build constant that turns
/// links on ([introLinksEnabled]); the owner's link as the vault keeps it,
/// with the seeds of the links it replaced or withdrew ([OwnIntroLink],
/// [IntroLinkOldSeed], one row sealed under `intro_link`: [IntroLinkRow]);
/// what a backup carries of it ([IntroLinkBackup]); and the numbers ADR 0032
/// gives the owner and the person who opens one.
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:z_protocol/z_protocol.dart';

import 'vault.dart';

/// Whether this build makes, opens and drains public introduction links
/// (ADR 0032). **Off**, and one flip in the release that turns links on.
///
/// Everything a person can see or do with a link is behind it: Settings ›
/// Your public link, a link taken by the Paste and Scan tabs, a QR image or
/// the handle search, the request sent through one, the owner's drain, and
/// an acceptance matched to a request sent through one. With it off none of
/// that is reachable: a `zi1.` code is what it was before phase 39 — not a
/// contact code — nothing connects as a link's mailbox, and a link the vault
/// holds from a restore is kept unread. The page a link lands on (`/c`,
/// `server/pages.js`) is the relay's and is served either way.
///
/// It is off because a link's mailbox is guarded by the hardened §21.6 at
/// the relay, which hands each stamp on with its envelope so the owner can
/// count it, and whether the deployed relay runs it is not yet confirmed
/// (ADR 0032 §5, decision 1). The release that sets this to `true` also adds
/// the Android `/c` path (`android:path="/c"` on both hosts); THREAT_MODEL's
/// rows for links are written ahead of it (39.5: R34, R47–R49, R55). A
/// constant, not a `--dart-define`: a value given on
/// one build command is a value no rebuild reproduces (`tool/check_ga.py`).
/// Tests turn it on through `ChatService.init`'s `introLinks`.
const bool introLinksEnabled = false;

/// The vault key of the owner's link: one row, sealed.
const String introLinkKey = 'intro_link';

/// The work an owner may print on a link, and ask of senders later: 16 to 24
/// bits (ADR 0032 §4, decision 5) — 24 is twelve seconds of one core in the
/// app's pure Dart, the most a person sending one request will wait. A link
/// itself may carry up to 28 ([handlePowMaxBits]); one made elsewhere and
/// read here is taken as it is.
const int introLinkMinPow = handlePowMinBits;
const int introLinkMaxOwnerPow = 24;

/// The levels the app offers, for making a link and for asking more work.
const List<int> introLinkPowLevels = [16, 18, 20, 22, 24];

/// After this long with no answer, the screen that shows a request sent
/// through a link says the link may have been replaced or withdrawn (ADR
/// 0032 §3): a printed link cannot be updated, so a copy whose owner has
/// moved on fails in silence, and this is how its holder hears.
const Duration introLinkUnanswered = Duration(days: 30);

/// The work of the one stamp made again after the relay refused a request
/// through a link as `pow_required` (ADR 0032 §3): the greater of the link's
/// printed work and the refusal's [refusalBits] — a printed link cannot learn
/// that its owner asked for more since, and the refusal is how its holder
/// hears — but never more than a link may carry: a refusal asking more than
/// [handlePowMaxBits] is not the protocol's, and the stamp stays at the
/// printed work. (A handle's re-stamp stays at the record's work, which the
/// requester has just read: PROTOCOL §21.8.)
int introLinkRestampBits(int printed, int refusalBits) =>
    refusalBits <= handlePowMaxBits ? max(printed, refusalBits) : printed;

/// What a field that takes codes — or handles — holds, as far as public
/// links go (ADR 0032 §3, PROTOCOL §21.9): a link to open ([link]); the
/// reason one cannot be read ([problem]: made by a newer Z, damaged on its
/// way, or not one a request can go through); or neither, when the text is
/// nothing like a link and the field reads it as it did before links. With
/// links off ([enabled] false) always neither: no field parses a link.
/// [handleField]: the field takes handles too, so §21.1 is asked first —
/// `zi1.42` is a handle, never a damaged link — before a link's reason is
/// named. Pure, and sends nothing: a link found is opened held.
({IntroLink? link, IntroLinkProblem? problem}) introLinkInField(String text,
    {required bool enabled, bool handleField = false}) {
  if (!enabled) return (link: null, problem: null);
  try {
    return (link: IntroLink.parse(text), problem: null);
  } on IntroLinkFormatException catch (e) {
    if (e.problem == IntroLinkProblem.notALink ||
        (handleField && Handle.tryParse(text) != null)) {
      return (link: null, problem: null);
    }
    return (link: null, problem: e.problem);
  }
}

/// A link as a list shows it, so two can be told apart: its prefix and the
/// first eight characters after it — the work and the start of its key.
String introLinkShort(IntroLink link) => '${link.code.substring(0, 12)}…';

/// Where the owner's link stands.
enum IntroLinkPhase {
  /// Drained and taking requests.
  live,

  /// Back from a restore, and not in use until its person says so (ADR 0032
  /// §4): the device the backup came from may have replaced or withdrawn it
  /// since, and there is no log to ask. Nothing connects as its mailbox until
  /// its person says to use it again — or replaces or withdraws it, either of
  /// which connects as it for one last read, as for a link in use.
  held,
}

/// The account's public link, as the main device keeps it: one per account
/// (decision 3), on the main device only, never made during setup.
class OwnIntroLink {
  /// The introduction seed (§21.3): the link's mailbox, its keys and the
  /// identity its drain authenticates as. Never leaves this device but in a
  /// backup.
  final Uint8List seed;

  /// The work printed on the link — what every copy of it asks, and what
  /// each stamp is counted at by this device, however much work was asked
  /// since ([askedPow]).
  final int printedPow;

  /// The work the relay is asked to require ([HandleService.askMoreWork]):
  /// the printed work or more, up to [introLinkMaxOwnerPow].
  int askedPow;

  /// When it was made (ms).
  final int madeMs;
  IntroLinkPhase phase;

  /// Derived from [seed], not stored.
  final IntroLink link;
  final String introRid;

  OwnIntroLink._(this.seed, this.printedPow, this.askedPow, this.madeMs,
      this.phase, this.link, this.introRid);

  /// The link [seed] makes, printed at [pow] and asking it, live.
  static Future<OwnIntroLink> make(Uint8List seed,
      {required int pow, required int nowMs}) async {
    final link = await IntroLink.fromSeed(seed, pow: pow);
    return OwnIntroLink._(Uint8List.fromList(seed), pow, pow, nowMs,
        IntroLinkPhase.live, link, await link.introRid());
  }

  /// `https://host/c#zi1.…`, the deployment's default host.
  String get url => link.link();

  /// What the owner copies onto a web page: the link, opened with
  /// `rel="noreferrer"` so that a browser following it does not tell the
  /// relay's host which page it came from (THREAT_MODEL R49).
  String get webAnchor => '<a href="$url" rel="noreferrer">$url</a>';

  Map<String, Object?> toJson() => {
        'v': 1,
        'seed': b64(seed),
        'pow': printedPow,
        'ask': askedPow,
        'at': madeMs,
        'phase': phase.name,
      };

  /// Throws on anything that is not the shape [toJson] writes, or a link no
  /// reader takes.
  static Future<OwnIntroLink> fromJson(Map<String, Object?> j) async {
    if (j['v'] != 1) throw const FormatException('intro_link version');
    final seed = unb64(j['seed'] as String);
    if (seed.length != 32) throw const FormatException('seed');
    final pow = j['pow'], ask = j['ask'], at = j['at'];
    if (pow is! int || pow < handlePowMinBits || pow > handlePowMaxBits) {
      throw const FormatException('pow');
    }
    if (ask is! int || ask < pow || ask > handlePowMaxBits) {
      throw const FormatException('ask');
    }
    if (at is! int) throw const FormatException('at');
    final phase = IntroLinkPhase.values.byName(j['phase'] as String);
    final made = await make(seed, pow: pow, nowMs: at);
    made.askedPow = ask;
    made.phase = phase;
    return made;
  }
}

/// A link since replaced or withdrawn, as the main device keeps it while a
/// pending request that reached its mailbox still has to be acknowledged
/// with its seed (ADR 0032 §4: "an old seed stays while a pending request
/// needs it"): the seed, and the work the link printed.
class IntroLinkOldSeed {
  final Uint8List seed;
  final int pow;
  IntroLinkOldSeed(Uint8List seed, this.pow) : seed = Uint8List.fromList(seed);

  Map<String, Object?> toJson() => {'seed': b64(seed), 'pow': pow};
}

/// The `intro_link` row, sealed (ADR 0032 §4): the account's link, when it
/// has one — [OwnIntroLink.toJson]'s members — and beside it the seeds of the
/// links since replaced or withdrawn that a pending request still needs,
/// `"old":{introRid:{"seed":…,"pow":…}}`. One row, so that what replaces a
/// link and the seed it leaves behind are written in one write, before the
/// old mailbox is read for the last time; and the row is what a backup's
/// `introlink` record carries ([IntroLinkBackup]). The old seeds are never
/// among a handle's, in `handle_in` or in the `handle` record.
abstract final class IntroLinkRow {
  /// The row for [link] — none, after a Withdraw — and [old], by mailbox;
  /// null when it would hold neither, and the row goes.
  static Map<String, Object?>? write(
      OwnIntroLink? link, Map<String, IntroLinkOldSeed> old) {
    if (link == null && old.isEmpty) return null;
    return {
      ...?link?.toJson(),
      'v': 1,
      if (old.isNotEmpty)
        'old': {for (final e in old.entries) e.key: e.value.toJson()},
    };
  }

  /// [write]'s row read back: the link, when it holds one, and the old
  /// seeds, each under the mailbox its seed makes rather than the name the
  /// row gives it — a row restored from an archive can come from anywhere.
  /// An old seed that is not one is left out; a link that is not one is none.
  /// Throws for a row of another version.
  static Future<({OwnIntroLink? link, Map<String, IntroLinkOldSeed> old})> read(
      Map<String, Object?> j) async {
    if (j['v'] != 1) throw const FormatException('intro_link version');
    OwnIntroLink? link;
    if (j.containsKey('seed')) {
      try {
        link = await OwnIntroLink.fromJson(j);
      } catch (_) {}
    }
    final old = <String, IntroLinkOldSeed>{};
    final o = j['old'];
    if (o is Map) {
      for (final v in o.values) {
        try {
          final m = (v as Map).cast<String, Object?>();
          final seed = unb64(m['seed'] as String);
          final pow = m['pow'];
          if (seed.length != 32 ||
              pow is! int ||
              pow < handlePowMinBits ||
              pow > handlePowMaxBits) {
            continue;
          }
          old[await introRoutingId(await handleKeyPublic(seed))] =
              IntroLinkOldSeed(seed, pow);
        } catch (_) {}
      }
    }
    return (link: link, old: old);
  }
}

/// The owner's link in a backup archive: one record of type `introlink`,
/// marked `"keep":1` (patch 53), so a build that predates links carries it
/// into its own next archive unread. It carries the link's row
/// ([IntroLinkRow]) — the link, and the seeds of links since replaced or
/// withdrawn that a pending request still needs — so those seeds travel in
/// this record and in no other: a build that knows handles but not links
/// keeps it as it came and finds no link's seed among its handle's. A
/// restore brings the link back [IntroLinkPhase.held] (ADR 0032 §4), and the
/// old seeds as they were.
abstract final class IntroLinkBackup {
  static const String recordType = 'introlink';

  /// The record, or null when this vault holds no link and no old seed.
  static Future<Map<String, Object?>?> export(Vault vault) async {
    final v = await vault.kvGet(introLinkKey);
    if (v == null) return null;
    final Object? j;
    try {
      j = jsonDecode(v);
    } on FormatException {
      return null;
    }
    return {
      't': recordType,
      ZArchive.keepField: 1,
      'v': 1,
      'kv': {introLinkKey: j},
    };
  }

  /// The `kv` row a restore writes for [record]: the link and its old seeds,
  /// held to the shape the service reads ([IntroLinkRow.read]) — an archive
  /// is a file that can come from anywhere — and the link held.
  static Future<Map<String, String>> restore(Map<String, Object?> record) async {
    final kv = record['kv'];
    if (kv is! Map) return const {};
    final row = kv[introLinkKey];
    if (row is! Map) return const {};
    try {
      final r = await IntroLinkRow.read(row.cast<String, Object?>());
      r.link?.phase = IntroLinkPhase.held;
      final out = IntroLinkRow.write(r.link, r.old);
      return out == null ? const {} : {introLinkKey: jsonEncode(out)};
    } catch (_) {
      return const {};
    }
  }
}
