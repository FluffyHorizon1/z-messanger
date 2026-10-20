// The handle resolver (phase 38; PROTOCOL.md §21.8, "Finding and asking";
// the 2026-10-09 review of handles, findings 3 and 5): real ChatService
// instances on the real relay (server/server.js), asking the real handle
// log's code (kt/) as its operator can run it (kt/test/handle_operator_log.js)
// — filled with labels nobody can name, its signed size inflated with
// versions, or with the owner rule taken out. A fetcher in front of the log
// writes down every request and plays the operator's other part: rewriting
// the unsigned `bucketBits`, or refusing buckets as too large.
//
// Criteria, each a test below:
//   1. the clamp: with `bucketBits` rewritten to 24, a lookup in a log of
//      1,001 handles asks at the k their number bears out (4) and no finer —
//      the handle's bucket among its decoys', each once, exactly the buckets
//      this install's decoy key gives — and finds it; a log of one handle is
//      asked whole (the review's P2a);
//   2. size inflation: in a log of 301 handles whose signed size four of
//      them inflate past 4,000 with versions, and `bucketBits` rewritten to
//      24, a fresh install's estimate starts at the k the size allows (7)
//      and its lookups ask where the handles put 16 or more in a bucket on
//      average (k ≤ 4), first lookup and every one after;
//   3. too large is never narrowed: with every bucket below 24 bits refused,
//      a lookup ends unreachable having asked the handle's bucket not at all
//      and only random ones, one bit finer each, within the probe's eight
//      (the review's P2b); with the lookup's own k refused, it ends
//      unreachable having asked the same buckets and nothing finer; and an
//      estimate the log outgrew (k = 1 in a log of 1,000, refused by the log
//      itself as too large) is made again from random buckets, and the
//      handle found at k = 4 with no k between asked;
//   4. decoys: looking a handle up again asks the same buckets in the same
//      order, a restart of the app keeps them, and another handle's are its
//      own — each set exactly what the install's key gives for the label;
//   5. the estimate moves with the evidence: one the handles do not bear out
//      (7 in the inflated log) falls in one lookup to what they do; one below
//      them (0 in a log of 201) rises a bit a lookup, 0, 1, 2;
//   6. a requester remembers the owner (the review's P4): a log without the
//      owner rule names another owner and mailbox, and the requester's next
//      lookup is refused as changed (owner), with nothing to send to; looked
//      up as new, the new owner is taken; a genuine recover — the code's key
//      opening the commitment remembered — and a new inbox after it are
//      found with no question; a recover followed by a change the requester
//      never saw is refused (one record cannot tell the code's work from the
//      log's);
//   7. history: another record at a version already seen, an older version,
//      and a handle the log no longer holds (the log restarted empty under
//      its key) are each refused as changed (history);
//   8. stale heads: an answer signed more than a day ago by the requester's
//      clock fails as stale, one 23 hours old does not, and a clock three
//      days behind is no failure;
//   9. versions no honest log serves: an update at 2^53 − 1 (a thief with the
//      owner key, a log without the next-version rule) makes a lookup, the
//      owner's own change and a recover with the code fail as a bad answer —
//      a HandleException, never an ArgumentError; so does an update at a
//      version past its index + 1; a claim at version 2 is invalid;
//  10. backup and restore carry the memory: the restored device asks the
//      buckets the old one asked for a handle and refuses the owner change
//      the old one would have; a memory in an archive that is not one is
//      left out;
//  11. the screen says why: a lookup refused as changed says so — owner or
//      history — in English and Spanish, offers no request and offers to look
//      it up as new; a stale answer has words of its own;
//  12. the rules on their own: k from a count, the probe's steps, the
//      estimate's fall and one-bit rise, decoys a function of key and label
//      that nest from one k to the next — and two installs' sets for one
//      handle meeting in exactly its bucket, the residual the trust table
//      names — the leaf rule (2^53 − 1 refused at an index that would allow
//      it), what one record can follow, and the stored memory held to its
//      shape and cap;
//  13. refusing cannot raise k (the second review's P2): in a log of 301
//      handles inflated to 16,000 entries, `bucketBits` rewritten to 24, an
//      operator that answers the first random bucket honestly and, when its
//      count alone would put k above the honest 3, refuses the coarser
//      bucket asked next, gets nothing: the probe asks a fresh bucket one bit
//      finer and goes on until one holds 32, and no lookup of the handle asks
//      its bucket finer than 3 (the base took the count before the refusal
//      as the estimate, and asked at 4 or finer);
//  14. a bucket counts only under the head held when it was drawn: an
//      operator that mints 32 labels into the first random bucket on seeing
//      it asked, and answers under the head that holds them, is not counted
//      — the probe draws again and the lookup asks at the honest k (the base
//      counted the 32 and asked at the 8 the inflated size allows); and
//      within one lookup the head only grows: an older answer served again
//      after the log grew is a bad answer, while a lookup that read an older
//      head and is answered under a newer one takes it with its consistency
//      proof.
//
// And the handle log's witness (phase 19, 2026-10-19). A resolver keeps no
// head between lookups but those a request was sent on (after the fact,
// below), so a log that shows one reader a history it showed nobody else is
// caught by a witness: a mirror, run by somebody else, that co-signs each
// head it verified. Each lookup's head is now held to the witness's record
// under the key pinned for it (§19.5 step 3, §21.8) — the reference
// witness's record (kt/tools/mirror.js --mode handles) over the real handle
// log, or one made here in the handle contexts:
//  15. a forked log — one key, two histories, the witness verifying the
//      other — fails the lookup as forked whether the witness's head is the
//      same size under other roots, behind with a proof that fails, or ahead
//      of a log that cannot reach it; nothing the lookup returned is kept or
//      sent (no record remembered, no request, no stamp, no `hvia_`); and
//      with no witness the same lookup takes the operator's mailbox, as the
//      base, which never asks, does;
//  16. every way a head is taken is held to it: a claim's check that a name
//      is free, at random digits too, a recovery's read, and the owner's own
//      reads — a refresh says why on the handle screen, a change is refused
//      before anything is published, a drain goes on with what the device
//      holds;
//  17. a witness behind the lookup's head (the witness service itself, over
//      loopback) and one ahead of it (the log grew between the head and the
//      question) both agree, the log proving the way between them, and the
//      agreement is recorded, sealed, with the configuration it answers;
//  18. a witness that cannot be reached, answers an error, or serves a
//      record whose co-signature or head signature does not verify, or that
//      is no record, is no verdict: the lookup goes on and the state says no
//      answer yet; a day of lookups asking without one is a witness gone
//      quiet since the first of them; an agreement ends it;
//  19. half a witness — an address, a key, a key that is not one — is
//      refused when it is set, and one held from before is never fetched;
//  20. a record co-signed by a key other than the pinned one is no agreement
//      and no verdict, one showing a fork included (§19.5: "A witness that
//      cannot be fetched, or whose record does not verify, is no verdict");
//      pinned to the key it is signed with, it counts;
//  21. a record a day old is held to consistency: consistent, the lookup goes
//      on and nothing is agreed, at the log's size and behind it; over other
//      roots it is a fork;
//  22. the build's four handle values are empty, together;
//  23. a witness off loopback stops a test process asking anything at all;
//  24. the record is fetched at most once a lookup and used again for ten
//      minutes under the same witness; fetched again after that, for
//      another witness, and after a record that did not verify; never
//      before a lookup, nor by one the log did not answer;
//  25. the witness's state belongs to the configuration it was recorded
//      under: kept across a restart, forgotten by a build that pins another
//      witness, and when Settings saves another witness, none, or another log
//      under the same one — not when it saves the same;
//  26. THE RESIDUAL, TURNED OVER ON PURPOSE (Finnian's decision of
//      2026-10-20; THREAT_MODEL R50, PROTOCOL §21.8): a history that departs
//      after the witness's latest co-signed head, shown at a first lookup,
//      still passes that lookup as agreement — but the head a request is
//      sent on is kept, and the next lookup after the witness moves on ends
//      in a fork found after the fact, on the contact the operator's
//      acceptance of that request added (a second history under the same
//      key begun after the witness's head, the operator's app accepting).
//      The record used again for ten minutes covers nothing kept; fetched
//      again, it does. And an update the owner rule refuses, appended after
//      the witness's head — the reference witness refuses to follow the
//      log, so no record ever covers the head kept for the request sent on
//      it — is said when the head lapses: 30 days on, the request still
//      waiting is told the answer it was sent on was never confirmed;
//  27. a log that will not prove the way between its head and its witness's
//      fails the lookup — the witness behind, or ahead with the log's own
//      head not below it — as unreachable, and one that serves something
//      that is not a proof as a bad answer; nothing the lookup returned is
//      kept or sent, and the witness has been asked without an answer that
//      counts; served, the proof shows the fork (15) or the agreement (17);
//  28. a fork is kept, sealed with its configuration, until the witness
//      agrees again: Settings says so after a drain's read refused as forked
//      (the drain goes on), across a restart; a claim the log refuses as
//      taken, whose read-back is refused as forked, is held with the fork as
//      its problem rather than taken; and another witness forgets it.
//
// And after the fact (2026-10-20): a head the witness had not covered, kept
// with the request sent on it; every head the log shows later held to it, as
// the transparency client holds the head it keeps; and the first record that
// covers it held to it too.
//  29. a kept head goes once a covering record agrees — at its size with its
//      roots, and ahead of it with the log's proof from the kept size — and
//      the witness agrees; only a request keeps one: a lookup that sends
//      nothing, a claim's check, a recovery's read and the owner's reads of
//      its own record keep none, a head the record already covers is not
//      kept, and with no witness nothing is; and every way a record is
//      fetched checks what is kept, the owner's drain read among them;
//  30. a fork found after the fact marks exactly what relied on its head and
//      nothing else: the contact the operator's acceptance of the request
//      added, and a request on a forked head still waiting — not a request
//      the record covered when it was sent, nor one whose kept head the
//      witness had covered before the histories parted, nor one on a head
//      the fork departs after (shown the history that forked, a device
//      cannot tell that head from one past the fork, so its check waits and
//      what relied on it is told at once its answer was never confirmed;
//      shown the witness's, it is covered and that warning goes, while a
//      forked head's is replaced by the fork's), nor a contact added by code;
//      and the warnings are sealed;
//  31. a proof the log withholds keeps the check pending: the head stays
//      kept, nothing is warned of, and the check is not the witness agreeing
//      (asked without an answer, quiet once that lasts) — a proof withheld,
//      and something served in its place that is not one; served, the proof
//      ends the check as consistent, and on a forked head as the fork; and a
//      record used again for ten minutes keeps a pending check pending,
//      asked again at most once in that time, neither the agreement nor the
//      quiet timer moving;
//  32. the bound: at most 20 heads that contacts hold, the one looked up
//      longest ago going first, and a head no contact holds bounded by the
//      outgoing list, not by them; each for at most 30 days; and a head the
//      bound or the lapse puts out of reach before the witness covered it is
//      said — never confirmed — on the contact or the waiting request that
//      relied on it;
//  33. a restart keeps the kept heads and the warnings, sealed, and a backup
//      carries them with the requests they are on; a restore leaves out one
//      whose request the archive does not hold, and one that is not their
//      shape, and the first start drops a warning whose contact the archive
//      did not bring back;
//  34. a change of log or witness puts the kept heads out of reach of a
//      check — another witness, none, another log under the same witness,
//      and a build that pins another witness under a vault that never saved
//      one — so what relied on each is told it was never confirmed, as is a
//      request sent after the change on a lookup made before it; and the
//      warnings stay;
//  35. a warning goes when the person dismisses it, when the request it is on
//      is forgotten, and when the contact it is on is deleted, taking what
//      was kept for that contact with it; and nothing else ends it — not the
//      witness agreeing again, nor the request being answered, which moves
//      it to the contact;
//  36. a fork padded past what the honest history reaches (the review's
//      PROBE A): kept on the fork, the witness's record below the kept head
//      contradicts the head the log shows next, and so the kept one; taken
//      back to the honest history, the log shows a head smaller than the one
//      kept — each ends in the warning on the contact and on the request
//      still waiting, and Settings says the request was sent;
//  37. a kept head the witness never covers is never dropped in silence: a
//      proof the log withholds for 30 days (the review's PROBE B), and a
//      witness that cannot be reached for 30 days and a day of tries after,
//      each end in the warning on the contact.
//
// And a kept head checked on its own (2026-10-24): twice at most, each time
// one record fetched afresh for every head due and every kept head held to
// it as a lookup's record is — 20 to 30 minutes after it was kept, and once
// more when it is 30 days old — a few seconds after the app is next in front.
//  38. no false alarm: a requester with no handle of her own, a log a head
//      past the witness when she looked up, a witness that follows it; half
//      an hour on, in front, one record covers the head, which goes with
//      nothing said, and 30 days on, offline for a day, there is nothing to
//      say;
//  39. a fork padded past what the honest history reaches, with no lookup
//      after it, is found at the check-back as a fork — kept on the fork and
//      taken back to the honest history alike — not said at the lapse as
//      never confirmed;
//  40. the fetches: one record for every head due, none with no head kept,
//      none again once a head is decided or its check-back spent, and the
//      last check once, at 30 days, after which what it leaves undecided is
//      said as never confirmed; and while the app stays in front, a one-shot
//      timer brings the moment of the check-back;
//  41. a head the check-back could not decide, the witness unreachable then,
//      is decided by the last check: covered by day 30, it goes with nothing
//      said.
//
// And what a second review of those checks found (2026-10-24):
//  42. a device kept on a fork the honest history has grown past is told at
//      once, on the contact its request added, that the answer it sent on was
//      never confirmed — no fork it cannot show, the head still kept, and the
//      check-back saying nothing more (PROBE D);
//  43. 30 days on, that warning stands and the head goes (PROBE D30);
//  44. a check that gets no answers spends nothing: offline at the one moment
//      after 30 days that is both its checks, it is tried again at a later
//      moment in front, and a head the witness covered goes with nothing said
//      (PROBE E);
//  45. so does one the app is killed during: the next start lapses nothing,
//      and a later check covers the head (PROBE E2);
//  46. and one a throttle stops: a check-back within ten minutes of a check
//      left pending asks nothing then, and is made at a later moment, the
//      proof asked then (PROBE H);
//  47. a burst of requests in honest operation raises no warning: twenty
//      inside one record's reuse, while an acceptance holds another head, are
//      bounded by the outgoing list, and the witness, following, covers them
//      all;
//  48. a check is never made at the moment the app comes to the front, but a
//      few seconds after it, drawn as the drain's first wait is; and the
//      check-back's moment is drawn from 20 to 30 minutes after the request
//      (PROBE F).
@Tags(['integration'])
@Timeout(Duration(minutes: 8))
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' show Ed25519;
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as p;
import 'package:zapp/core/archive.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/handle_lookups.dart';
import 'package:zapp/core/handles.dart';
import 'package:zapp/core/key_transparency.dart';
import 'package:zapp/core/restore.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/l10n/app_localizations.dart';
import 'package:zapp/l10n/app_localizations_en.dart';
import 'package:zapp/l10n/app_localizations_es.dart';
import 'package:zapp/l10n/handle_text.dart';
import 'package:zapp/ui/find_handle_screen.dart';
import 'package:zapp/ui/theme.dart';
import 'package:z_protocol/z_protocol.dart';

/// The operator's hand on the wire: the real fetcher, every URL written
/// down, and — as whoever runs the log or terminates its TLS can — the
/// unsigned `bucketBits` rewritten, or buckets refused as too large.
class _Operator implements KtFetcher {
  final _inner = HttpKtFetcher();
  final urls = <Uri>[];
  int? bucketBits;
  bool Function(KtBucketQuery q)? refuse;

  /// Called with each bucket asked, before the log answers it: the
  /// operator's moment to change the log on seeing what was asked.
  Future<void> Function(KtBucketQuery q)? onBucket;

  /// An operator that knows the honest k and waits for its chance: when a
  /// bucket's count alone would put k above it, the next bucket asked
  /// coarser than that one is refused — once.
  int? refuseAboveHonest;
  int? _armedBelow;
  int refusals = 0;

  /// Keep every answer (by path), and serve the kept one again.
  bool keep = false;
  bool replay = false;
  final kept = <String, KtResponse>{};

  /// The witness: [witnessUrl] answered by [witness] — when, and only when,
  /// the client asks there — rather than by the network. What it answers is
  /// the reference witness's record ([_Witness]), or one a test made.
  String? witnessUrl;
  Future<KtResponse> Function()? witness;

  static KtBucketQuery _query(Uri u) => KtBucketQuery.parse(
      u.queryParameters['prefix']!, int.parse(u.queryParameters['bits']!));

  static const _tooLarge =
      '{"error":"bucket_too_large","message":"ask for more bits"}';

  @override
  Future<KtResponse> get(Uri url) async {
    urls.add(url);
    final w = witness;
    if (w != null && url.toString() == witnessUrl) return w();
    final path = '${url.path}?${url.query}';
    if (replay && kept.containsKey(path)) return kept[path]!;
    final isBucket = url.path == '/kt/v1/bucket';
    if (isBucket) {
      final q = _query(url);
      if (refuse?.call(q) ?? false) return KtResponse(400, _tooLarge);
      final below = _armedBelow;
      if (below != null && q.bits < below) {
        _armedBelow = null;
        refusals++;
        return KtResponse(400, _tooLarge);
      }
      await onBucket?.call(q);
    }
    var r = await _inner.get(url);
    if (bucketBits != null && url.path == '/kt/v1/sth' && r.status == 200) {
      final j = (jsonDecode(r.body) as Map).cast<String, Object?>();
      j['bucketBits'] = bucketBits;
      r = KtResponse(r.status, jsonEncode(j));
    }
    final honest = refuseAboveHonest;
    if (isBucket && honest != null && r.status == 200 && refusals == 0) {
      final j = r.json;
      final count = (j['leaves'] as List).length;
      final bits = j['bits'] as int;
      if (handleBitsFor(count * (1 << bits)) > honest) _armedBelow = bits;
    }
    if (keep) kept[path] = r;
    return r;
  }

  @override
  Future<KtResponse> post(Uri url, String jsonBody) {
    urls.add(url);
    return _inner.post(url, jsonBody);
  }

}

/// A fetcher that never reaches the network: every URL written down, and
/// nothing answered.
class _Nowhere implements KtFetcher {
  final urls = <Uri>[];
  @override
  Future<KtResponse> get(Uri url) async {
    urls.add(url);
    return KtResponse(503, '{}');
  }

  @override
  Future<KtResponse> post(Uri url, String jsonBody) async {
    urls.add(url);
    return KtResponse(503, '{}');
  }
}

/// The operator's fetcher with every request for a consistency proof
/// refused — as a log that will not prove the way between two heads it signed
/// can refuse it — or, with [garbage], answered with something that is not a
/// proof.
class _Withholding implements KtFetcher {
  _Withholding(this.inner);
  final _Operator inner;
  final denied = <String>[];
  bool garbage = false;

  /// Off, every proof is served as the log serves it.
  bool withholding = true;

  @override
  Future<KtResponse> get(Uri url) async {
    if (url.path == '/kt/v1/consistency' && withholding) {
      inner.urls.add(url);
      denied.add(url.query);
      return garbage ? KtResponse(200, '{"proof":7}') : KtResponse(503, '{}');
    }
    return inner.get(url);
  }

  @override
  Future<KtResponse> post(Uri url, String jsonBody) => inner.post(url, jsonBody);
}

/// The operator answering the configured log's address from another history
/// under the same key once [on] — the log on port [from] served by the one
/// on [to] — and every other address, the witness's among them, as before.
class _Switch implements KtFetcher {
  _Switch(this.inner, this.from, this.to);
  final KtFetcher inner;
  final int from, to;
  bool on = false;
  Uri _route(Uri u) => on && u.port == from ? u.replace(port: to) : u;
  @override
  Future<KtResponse> get(Uri url) => inner.get(_route(url));
  @override
  Future<KtResponse> post(Uri url, String jsonBody) =>
      inner.post(_route(url), jsonBody);
}

/// A log that withholds only the proofs whose `first=` is [first] — a size it
/// knows it showed one reader — and serves every other.
class _WithholdFirst implements KtFetcher {
  _WithholdFirst(this.inner);
  final KtFetcher inner;
  int? first;
  final denied = <String>[];

  @override
  Future<KtResponse> get(Uri url) async {
    if (url.path == '/kt/v1/consistency' &&
        first != null &&
        url.queryParameters['first'] == '$first') {
      denied.add(url.query);
      return KtResponse(503, '{}');
    }
    return inner.get(url);
  }

  @override
  Future<KtResponse> post(Uri url, String jsonBody) => inner.post(url, jsonBody);
}

/// The network gone for a moment: while [offline], every request fails as a
/// socket that cannot connect, and nothing answers at all.
class _Flaky implements KtFetcher {
  _Flaky(this.inner);
  final KtFetcher inner;
  bool offline = false;
  int refused = 0;

  @override
  Future<KtResponse> get(Uri url) async {
    if (offline) {
      refused++;
      throw const SocketException('offline for a moment');
    }
    return inner.get(url);
  }

  @override
  Future<KtResponse> post(Uri url, String jsonBody) async {
    if (offline) {
      refused++;
      throw const SocketException('offline for a moment');
    }
    return inner.post(url, jsonBody);
  }
}

/// Requests that never complete while [hang]: the app is killed before an
/// answer arrives.
class _Hang implements KtFetcher {
  _Hang(this.inner);
  final KtFetcher inner;
  bool hang = false;
  int hung = 0;

  @override
  Future<KtResponse> get(Uri url) {
    if (hang) {
      hung++;
      return Completer<KtResponse>().future;
    }
    return inner.get(url);
  }

  @override
  Future<KtResponse> post(Uri url, String jsonBody) => inner.post(url, jsonBody);
}

/// Every request written down with the moment it was made.
class _Clocked implements KtFetcher {
  _Clocked(this.inner);
  final KtFetcher inner;
  final at = <(DateTime, Uri)>[];

  @override
  Future<KtResponse> get(Uri url) {
    at.add((DateTime.now(), url));
    return inner.get(url);
  }

  @override
  Future<KtResponse> post(Uri url, String jsonBody) {
    at.add((DateTime.now(), url));
    return inner.post(url, jsonBody);
  }
}

/// A handle log run by kt/test/handle_operator_log.js.
class _Log {
  _Log(this.process, this.port, this.seed, this.pub, this.size, this.labels);
  Process process;
  final int port;
  final Uint8List seed;
  final Uint8List pub;
  final int size;
  final int labels;
  HandleConfig get config =>
      HandleConfig(logUrl: 'http://127.0.0.1:$port', logPubB64: b64(pub));
}

/// The reference witness of a handle log, `kt/tools/mirror.js --mode
/// handles`, run once at each sync: it verifies that the log's head extends
/// the one it verified last, re-derives both roots from the entries, holds
/// every entry to the owner rule, co-signs the head in the handle witness
/// context with a key of its own, and writes [record] — the record a witness
/// serves at `/sth.json` — into [dir].
class _Witness {
  _Witness(this.seed, this.pub, this.dir, this.url);
  final Uint8List seed;
  final Uint8List pub;
  final String dir;

  /// Where the client is told the record is, on loopback: answered by the
  /// test's fetcher ([_Operator.witness]), never by the network.
  final String url;

  /// The record as the witness last wrote it.
  late String record;
}

/// A handle's owner outside the app, publishing straight to a log as any
/// client can.
class _Owner {
  _Owner(this.handle, this.label, this.ownerSeed, this.introSeed, this.rk);
  final String handle;
  final Uint8List label;
  Uint8List ownerSeed;
  Uint8List introSeed;
  HandleRecoveryKey rk;
  int version = 0;

  Future<String> introRid() async =>
      introRoutingId((await handleIntroIdentity(introSeed)).edPub);
}

/// One lookup as the log saw it.
class _Look {
  _Look(this.found, this.error, this.asked, this.probed);
  final HandleLookup? found;
  final Object? error;

  /// The lookup's own buckets, in the order asked ...
  final List<KtBucketQuery> asked;

  /// ... and the estimate's random ones, when it made one.
  final List<KtBucketQuery> probed;

  Set<int> get bits => {for (final q in asked) q.bits};
}

Matcher failsWith(HandleFailure f) => throwsA(
    isA<HandleException>().having((e) => e.failure, 'failure', f));

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  final root = Directory.current.parent.path;
  late Process relay;
  late int relayPort;
  final logs = <_Log>[];
  final temps = <Directory>[];
  final services = <ChatService>[];
  final witnessServices = <Process>[];
  var seeds = 0;

  String hex(List<int> b) =>
      [for (final x in b) x.toRadixString(16).padLeft(2, '0')].join();

  Future<int> freePort() async {
    final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final port = probe.port;
    await probe.close();
    return port;
  }

  Future<Uint8List> pubOf(Uint8List seed) async => Uint8List.fromList(
      (await (await Ed25519().newKeyPairFromSeed(seed)).extractPublicKey())
          .bytes);

  setUpAll(() async {
    relayPort = await freePort();
    relay = await Process.start('node', ['server.js'],
        workingDirectory: '$root/server',
        environment: {'PORT': '$relayPort', 'LOG_LEVEL': 'silent'});
    relay.stdout.drain<void>();
    relay.stderr.drain<void>();
    for (var i = 0; i < 150; i++) {
      try {
        final res = await (await HttpClient()
                .getUrl(Uri.parse('http://127.0.0.1:$relayPort/health')))
            .close();
        await res.drain<void>();
        if (res.statusCode == 200) return;
      } catch (_) {}
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    fail('the relay did not start');
  });

  tearDownAll(() async {
    for (final s in services) {
      s.dispose();
      await s.transport
          .stop()
          .timeout(const Duration(seconds: 10), onTimeout: () {});
    }
    relay.kill();
    for (final l in logs) {
      l.process.kill();
    }
    for (final w in witnessServices) {
      w.kill();
    }
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<Process> spawnLog(Uint8List seed, int port,
      {int labels = 0, String? versions, bool ruleless = false,
      required Completer<List<String>> ready}) async {
    final proc = await Process.start('node', ['test/handle_operator_log.js'],
        workingDirectory: '$root/kt',
        environment: {
          'KT_SEED': hex(seed),
          'KT_PORT': '$port',
          'FILL_LABELS': '$labels',
          if (versions != null) 'FILL_VERSIONS': versions,
          if (ruleless) 'RULELESS': '1',
        });
    proc.stdout
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen((line) {
      if (line.startsWith('READY ') && !ready.isCompleted) {
        ready.complete(line.split(' '));
      }
    });
    proc.stderr.drain<void>();
    return proc;
  }

  /// A handle log of [labels] handles nobody can name, [versions] ("a:v")
  /// inflating the first a of them to version v, the owner rule taken out
  /// when [ruleless] — under a key of its own, or under [key]'s: a second
  /// history the same operator signs.
  Future<_Log> startLog(
      {int labels = 0,
      String? versions,
      bool ruleless = false,
      Uint8List? key}) async {
    final n = ++seeds;
    final seed = key ??
        Uint8List.fromList(
            List<int>.generate(32, (i) => (i * 29 + n * 7 + 3) & 0xff));
    final ready = Completer<List<String>>();
    final proc = await spawnLog(seed, 0,
        labels: labels, versions: versions, ruleless: ruleless, ready: ready);
    final parts = await ready.future.timeout(const Duration(seconds: 120));
    final log = _Log(proc, int.parse(parts[1]), seed, await pubOf(seed),
        int.parse(parts[2]), int.parse(parts[3]));
    logs.add(log);
    return log;
  }

  /// The same log, stopped and started again under its key and on its port
  /// with nothing in it: a log that forgot.
  Future<void> restartEmpty(_Log log, {bool ruleless = true}) async {
    log.process.kill();
    await log.process.exitCode;
    final ready = Completer<List<String>>();
    log.process =
        await spawnLog(log.seed, log.port, ruleless: ruleless, ready: ready);
    await ready.future.timeout(const Duration(seconds: 60));
  }

  // Logs more than one test asks: started once, when first asked for.
  Future<_Log>? big, inflated, tall;
  Future<_Log> bigLog() => big ??= startLog(labels: 1000);
  Future<_Log> inflatedLog() => inflated ??= startLog(labels: 300, versions: '4:1000');
  // 301 handles and ~16,300 entries: the signed size allows k = 8 where the
  // handles bear out 3. Criterion 14 mints labels into it, so it is the last
  // to use it.
  Future<_Log> tallLog() => tall ??= startLog(labels: 300, versions: '4:4000');

  Future<(int, String)> publishTo(_Log log, HandleEntry e) async {
    final req = await HttpClient()
        .postUrl(Uri.parse('http://127.0.0.1:${log.port}/kt/v1/publish'));
    req.headers.contentType = ContentType.json;
    req.write(jsonEncode(e.toPublishJson()));
    final res = await req.close();
    return (res.statusCode, await res.transform(utf8.decoder).join());
  }

  Future<void> put(_Log log, Uint8List label, int version, HandleRecord rec,
      Uint8List ownerSeed) async {
    final e = await signHandleEntry(
        label: label, version: version, record: rec, ownerSeed: ownerSeed);
    final (st, body) = await publishTo(log, e);
    expect(st, 201, reason: body);
  }

  Future<HandleRecord> recordOf(HandleRecordKind kind, Uint8List ownerSeed,
      Uint8List introSeed, Uint8List rc) async {
    final owner = await handleKeyPublic(ownerSeed);
    final intro = await handleIntroIdentity(introSeed);
    return kind == HandleRecordKind.claim
        ? HandleRecord.claim(
            owner: owner, intro: intro.edPub, xintro: intro.xPub, pow: 16, rc: rc)
        : HandleRecord.update(
            owner: owner, intro: intro.edPub, xintro: intro.xPub, pow: 16, rc: rc);
  }

  /// [handle] claimed straight into [log], with a recovery code of its own.
  Future<_Owner> claimAt(_Log log, String handle) async {
    final label = await handleLabel(Handle.parse(handle));
    final code = await RecoveryCode.generate();
    final o = _Owner(handle, label, randomBytes(32), randomBytes(32),
        await handleRecoveryKey(code, label));
    await put(log, label, 1,
        await recordOf(HandleRecordKind.claim, o.ownerSeed, o.introSeed, o.rk.rc),
        o.ownerSeed);
    o.version = 1;
    return o;
  }

  /// A new inbox, by the owner.
  Future<void> newInbox(_Log log, _Owner o) async {
    o.introSeed = randomBytes(32);
    await put(log, o.label, o.version + 1,
        await recordOf(HandleRecordKind.update, o.ownerSeed, o.introSeed, o.rk.rc),
        o.ownerSeed);
    o.version++;
  }

  /// The recovery code used: a new owner, mailbox and code, `rsig` by the
  /// key the commitment names.
  Future<void> recoverAt(_Log log, _Owner o) async {
    final v = o.version + 1;
    final owner = randomBytes(32);
    final introSeed = randomBytes(32);
    final rk = await handleRecoveryKey(await RecoveryCode.generate(), o.label);
    final ownerPub = await handleKeyPublic(owner);
    final intro = await handleIntroIdentity(introSeed);
    final rsig = await signHandleRecovery(
        recoverySeed: o.rk.seed,
        label: o.label,
        version: v,
        owner: ownerPub,
        rc: rk.rc);
    await put(
        log,
        o.label,
        v,
        HandleRecord.recover(
            owner: ownerPub,
            intro: intro.edPub,
            xintro: intro.xPub,
            pow: 16,
            rc: rk.rc,
            rpub: o.rk.pub,
            rsig: rsig),
        owner);
    o
      ..ownerSeed = owner
      ..introSeed = introSeed
      ..rk = rk
      ..version = v;
  }

  /// The log's operator, with no rule to stop it: an update naming an owner
  /// and a mailbox of its own, signed by that owner and by no key of the
  /// handle's. Returns the operator's mailbox.
  Future<String> takeOver(_Log log, _Owner o) async {
    final owner = randomBytes(32);
    final introSeed = randomBytes(32);
    await put(log, o.label, o.version + 1,
        await recordOf(HandleRecordKind.update, owner, introSeed, randomBytes(32)),
        owner);
    o.version++;
    return introRoutingId((await handleIntroIdentity(introSeed)).edPub);
  }

  Future<ChatService> boot(String name,
      {required HandleConfig config,
      KtFetcher? fetcher,
      Vault? vault,
      ZIdentity? id,
      int? seed,
      int Function()? now}) async {
    final Vault v;
    final ZIdentity identity;
    if (vault == null) {
      final d = await Directory.systemTemp.createTemp('z_hlookup_$name');
      temps.add(d);
      v = await Vault.open(rootOverride: d);
      identity = id ?? await ZIdentity.generate();
      await v.kvPut('identity', jsonEncode(identity.toJson()));
    } else {
      v = vault;
      identity = id!;
    }
    final svc = await ChatService.init(
        vault: v,
        identity: identity,
        displayName: name,
        transport:
            Transport(identity: identity, serverUrl: 'ws://127.0.0.1:$relayPort'),
        ktConfig: KtConfig.off,
        handleConfig: config,
        handleFetcher: fetcher,
        handleNow: now);
    final h = svc.handles;
    if (seed != null) h.random = Random(seed);
    h.claimDelayMin = const Duration(milliseconds: 150);
    h.claimDelayMax = const Duration(milliseconds: 400);
    h.startDelayMin = const Duration(milliseconds: 50);
    h.startDelayMax = const Duration(milliseconds: 100);
    h.foregroundDelayMin = const Duration(milliseconds: 50);
    h.foregroundDelayMax = const Duration(milliseconds: 150);
    h.drainQuiet = const Duration(milliseconds: 400);
    h.drainEvery = const Duration(minutes: 30);
    services.add(svc);
    return svc;
  }

  Future<void> stop(ChatService s) async {
    services.remove(s);
    s.dispose();
    await s.transport
        .stop()
        .timeout(const Duration(seconds: 10), onTimeout: () {});
  }

  Future<void> waitUntil(FutureOr<bool> Function() cond,
      {Duration timeout = const Duration(seconds: 60),
      required String what}) async {
    final deadline = DateTime.now().add(timeout);
    while (!await cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
  }

  /// [s] looks [handle] up through [f]: what it found or threw, the buckets
  /// the lookup asked, and the estimate's random ones apart.
  Future<_Look> look(ChatService s, _Operator f, String handle) async {
    final from = f.urls.length;
    // An estimate's bucket is the request made right after it is announced.
    final probes = <int>{};
    s.handles.debugOnProbe = (_) => probes.add(f.urls.length);
    HandleLookup? found;
    Object? error;
    try {
      found = await s.handles.find(handle);
    } catch (e) {
      error = e;
    } finally {
      s.handles.debugOnProbe = null;
    }
    final asked = <KtBucketQuery>[], probed = <KtBucketQuery>[];
    for (var i = from; i < f.urls.length; i++) {
      if (f.urls[i].path != '/kt/v1/bucket') continue;
      (probes.contains(i) ? probed : asked).add(_Operator._query(f.urls[i]));
    }
    return _Look(found, error, asked, probed);
  }

  Future<HandleLookupMemory> memoryOf(ChatService s) async =>
      HandleLookupMemory.parse((await s.vault.kvGet(handleLookupKey))!)!;

  /// An estimate set before [s] has looked anything up in [log].
  Future<void> setEstimate(ChatService s, _Log log, int bits) =>
      s.vault.kvPut(
          handleLookupKey,
          jsonEncode(HandleLookupMemory(
                  log: b64(log.pub), key: randomBytes(32), bits: bits)
              .toJson()));

  Future<Uint8List> labelOf(String handle) => handleLabel(Handle.parse(handle));

  var witnesses = 0;

  /// [w] run once against [log]: the head it verified, co-signed, is
  /// [_Witness.record] — or the test fails with what the witness said, a
  /// divergence among it.
  Future<void> sync(_Witness w, _Log log) async {
    final r = await Process.run(
        'node',
        [
          'tools/mirror.js',
          '--log',
          'http://127.0.0.1:${log.port}',
          '--pub',
          b64(log.pub),
          '--dir',
          w.dir,
          '--mode',
          'handles',
          '--witness-seed-env',
          'Z_HANDLE_WITNESS_SEED',
        ],
        workingDirectory: '$root/kt',
        environment: {'Z_HANDLE_WITNESS_SEED': hex(w.seed)});
    expect(r.exitCode, 0,
        reason: 'the witness verified the log: ${r.stdout}${r.stderr}');
    w.record = File(p.join(w.dir, 'sth.json')).readAsStringSync();
  }

  /// A witness of [log] under a key of its own, synced once unless
  /// [synced] is false.
  Future<_Witness> witnessOf(_Log log, {bool synced = true}) async {
    final n = ++witnesses;
    final seed = Uint8List.fromList(
        List<int>.generate(32, (i) => (i * 53 + n * 11 + 1) & 0xff));
    final dir = await Directory.systemTemp.createTemp('z_hlookup_w');
    temps.add(dir);
    final w = _Witness(seed, await pubOf(seed), dir.path,
        'http://127.0.0.1:9/witness-$n/sth.json');
    if (synced) await sync(w, log);
    return w;
  }

  /// [w] as the witness service itself — `mirror.js --serve`, on a port of
  /// its own on loopback — following [log]: it syncs as it starts and then
  /// hourly, so it stays where it was while the test moves the log. The
  /// address of its record, once it serves one.
  Future<String> serveWitness(_Witness w, _Log log) async {
    final proc = await Process.start(
        'node',
        [
          'tools/mirror.js',
          '--log',
          'http://127.0.0.1:${log.port}',
          '--pub',
          b64(log.pub),
          '--dir',
          w.dir,
          '--mode',
          'handles',
          '--witness-seed-env',
          'Z_HANDLE_WITNESS_SEED',
          '--serve',
          '0',
          '--every',
          '3600',
        ],
        workingDirectory: '$root/kt',
        environment: {'Z_HANDLE_WITNESS_SEED': hex(w.seed)});
    witnessServices.add(proc);
    final port = Completer<int>();
    proc.stdout
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen((line) {
      final m = RegExp(r'serving on http://0\.0\.0\.0:(\d+)').firstMatch(line);
      if (m != null && !port.isCompleted) port.complete(int.parse(m.group(1)!));
    });
    proc.stderr.drain<void>();
    final url =
        'http://127.0.0.1:${await port.future.timeout(const Duration(seconds: 60))}/sth.json';
    final net = HttpKtFetcher();
    await waitUntil(() async {
      try {
        return (await net.get(Uri.parse(url))).status == 200;
      } catch (_) {
        return false;
      }
    }, what: 'the witness serving the head it verified');
    return url;
  }

  /// [log]'s current head, as it serves it.
  Future<KtTreeHead> headOf(_Log log) async => KtTreeHead.fromJson(
      (await HttpKtFetcher()
              .get(Uri.parse('http://127.0.0.1:${log.port}/kt/v1/sth')))
          .json);

  /// A head at [size] over [logRoot] and [mapRoot], signed at [ts] in the
  /// handle log's context by [log]'s own key: a head that log signed, so
  /// that only what a witness says of it is in doubt.
  Future<KtTreeHead> signedHead(_Log log,
      {required int size,
      required Uint8List logRoot,
      required Uint8List mapRoot,
      required int ts}) async {
    final unsigned = KtTreeHead(
        size: size, logRoot: logRoot, mapRoot: mapRoot, ts: ts, sig: Uint8List(64));
    final sig = await Ed25519().sign(ktHeadInput(unsigned, KtLogMode.handles),
        keyPair: await Ed25519().newKeyPairFromSeed(log.seed));
    return KtTreeHead(
        size: size,
        logRoot: logRoot,
        mapRoot: mapRoot,
        ts: ts,
        sig: Uint8List.fromList(sig.bytes));
  }

  /// [head] co-signed in the handle witness context by the key of [seed]:
  /// the record a witness under that key would serve (§19.10's shape).
  Future<String> recordFor(KtTreeHead head, Uint8List seed) async {
    final sig = await Ed25519().sign(
        ktWitnessInputFor(head, KtLogMode.handles),
        keyPair: await Ed25519().newKeyPairFromSeed(seed));
    return jsonEncode({
      'sth': head.toJson(),
      'verifiedAt': head.ts,
      'size': head.size,
      'witness': {'pub': b64(await pubOf(seed)), 'sig': b64(sig.bytes)},
    });
  }

  /// [log] with [w] as its witness: the record's address — [w]'s own, or
  /// [url] — and the key this device pins for it — [w]'s own, or [key].
  HandleConfig witnessed(_Log log, _Witness w, {String? url, Uint8List? key}) =>
      HandleConfig(
          logUrl: 'http://127.0.0.1:${log.port}',
          logPubB64: b64(log.pub),
          witnessUrl: url ?? w.url,
          witnessPubB64: b64(key ?? w.pub));

  int fetchesOf(_Operator f, String url) =>
      f.urls.where((u) => u.toString() == url).length;

  /// [f] answers [w]'s address with what [w] last wrote.
  void serve(_Operator f, _Witness w) => f
    ..witnessUrl = w.url
    ..witness = () async => KtResponse(200, w.record);

  Matcher forked() => isA<HandleException>()
      .having((e) => e.failure, 'failure', HandleFailure.forked);

  /// [s] claims [handle] in the log it is configured with: published, and
  /// its mailbox drained once (which flags it at the relay).
  Future<void> claimIn(ChatService s, String handle) async {
    final draft = await s.handles.prepareClaim(Handle.parse(handle), pow: 16);
    await s.handles.commitClaim(draft);
    await waitUntil(() => s.handles.own?.phase == HandlePhase.live,
        what: '$handle published');
    await waitUntil(() => s.handles.drains >= 1,
        what: '$handle\'s mailbox drained and flagged');
  }

  /// [owner] drains its mailbox until the request from [rid] is filed.
  Future<void> receives(ChatService owner, String rid) => waitUntil(() async {
        await owner.handles.drain();
        return owner.requestsByRid.containsKey(rid);
      }, what: '${owner.displayName} filing the request from $rid');

  /// [asker] holds [owner] as the contact its request to [handle] made, by
  /// the acknowledgement: the contact is there, and the request answered.
  Future<void> linked(ChatService asker, ChatService owner, String handle) =>
      waitUntil(
          () =>
              asker.contacts.containsKey(owner.myRid) &&
              asker.handles.outgoing.every((o) => o.handle != handle),
          what: '${asker.displayName} linked to ${owner.displayName} '
              'through $handle');

  /// The same claim of [handle] in each of [logs], in the same hour: their
  /// histories stay one.
  Future<void> claimInEach(List<_Log> logs, String handle) async {
    final label = await labelOf(handle);
    final rk = await handleRecoveryKey(await RecoveryCode.generate(), label);
    final owner = randomBytes(32), intro = randomBytes(32);
    final rec = await recordOf(HandleRecordKind.claim, owner, intro, rk.rc);
    for (final log in logs) {
      await put(log, label, 1, rec, owner);
    }
  }

  /// Two histories under one key — [y] the one a witness verifies, [x] the
  /// one a reader is shown — the same up to a claim of [shared] both
  /// accepted in the same hour; and a witness of [y], synced there.
  Future<(_Log, _Log, _Witness)> twoHistories(String shared) async {
    final y = await startLog();
    final x = await startLog(key: y.seed);
    await claimInEach([y, x], shared);
    expect((await headOf(x)).sameRootsAs(await headOf(y)), isTrue,
        reason: 'one prefix in both histories (accepted in the same hour)');
    return (x, y, await witnessOf(y));
  }

  /// A warning's request ids, for comparing with a request's.
  Set<String> idsOf(List<Uint8List> ids) => {for (final i in ids) b64(i)};

  /// The time [d] from now, for a restart that is that much later.
  int laterBy(Duration d) =>
      DateTime.now().millisecondsSinceEpoch + d.inMilliseconds;

  /// Whether [cond] comes true within [within], polled as [waitUntil] polls:
  /// for a step whose effect a criterion asserts afterwards, among the rest.
  Future<bool> settled(FutureOr<bool> Function() cond,
      {Duration within = const Duration(seconds: 10)}) async {
    final deadline = DateTime.now().add(within);
    while (!await cond()) {
      if (DateTime.now().isAfter(deadline)) return false;
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
    return true;
  }

  /// [s]'s clock moved [d] on from where it stands.
  void shiftClock(ChatService s, Duration d) {
    final was = s.handles.now;
    s.handles.now = () => was() + d.inMilliseconds;
  }

  // ---------------------------------------------------------------------------

  test('1. the clamp: a rewritten bucketBits is not followed; the bucket is '
      'asked among its decoys at the k the handles bear out', () async {
    final log = await bigLog();
    await claimAt(log, 'clara.41');
    final f = _Operator()..bucketBits = 24;
    final carol = await boot('Carol', config: log.config, fetcher: f);
    final l = await look(carol, f, '@clara.41');
    expect(l.error, isNull);
    expect(l.found!.state, HandleLookupState.found);
    final sth = await (await HttpClient()
            .getUrl(Uri.parse('http://127.0.0.1:${log.port}/kt/v1/sth')))
        .close();
    final size =
        (jsonDecode(await sth.transform(utf8.decoder).join()) as Map)['size'] as int;
    final want = handleBitsFor(size);
    expect(want, 4, reason: '⌊log₂(1,001 / 32)⌋');
    expect(l.bits, {want}, reason: 'not the 24 the operator wrote');
    final label = await labelOf('clara.41');
    final mem = await memoryOf(carol);
    expect(l.asked, handleLookupBuckets(mem.key, label, want),
        reason: 'the handle\'s bucket and its decoys\', each once, in order');
    expect(l.asked.where((q) => q.holds(label)), hasLength(1));
    expect(l.probed.first.bits, want,
        reason: 'the first estimate starts at the finest the signed size allows');
    // ignore: avoid_print
    print('LOOKUP 1: size $size, bucketBits rewritten to 24 -> estimate from '
        '${l.probed.map((q) => q.bits).toList()} bits, lookup asked '
        '${l.asked.length} buckets at ${l.bits}');

    // A log of one handle is one bucket, whatever bucketBits says.
    final tiny = await startLog();
    await claimAt(tiny, 'tia.42');
    final g = _Operator()..bucketBits = 24;
    final tom = await boot('Tom', config: tiny.config, fetcher: g);
    final t = await look(tom, g, '@tia.42');
    expect(t.found!.state, HandleLookupState.found);
    expect([...t.asked, ...t.probed].every((q) => q.bits == 0), isTrue);
  });

  test('2. size inflation: the estimate is of handles, not entries', () async {
    final log = await inflatedLog();
    await claimAt(log, 'ivy.52');
    final f = _Operator()..bucketBits = 24;
    final dan = await boot('Dan', config: log.config, fetcher: f, seed: 52);
    expect(log.labels, 300);
    expect(log.size, 300 + 4 * 999);
    final bySize = handleBitsFor(log.size + 1);
    expect(bySize, 7, reason: 'what the signed size alone would allow');
    // 301 handles put 16 or more in a bucket on average up to k = 4.
    final most = handleBitsFor(301 * 2);
    expect(most, 4);
    final ks = <Set<int>>[];
    final probes = <int>[];
    for (var i = 0; i < 3; i++) {
      final l = await look(dan, f, '@ivy.52');
      expect(l.error, isNull);
      expect(l.found!.state, HandleLookupState.found);
      ks.add(l.bits);
      probes.addAll([for (final q in l.probed) q.bits]);
    }
    // ignore: avoid_print
    print('LOOKUP 2: size ${log.size + 1}, 301 handles, bucketBits rewritten '
        'to 24 -> estimate from $probes bits, lookups asked $ks');
    expect(probes.first, bySize, reason: 'the estimate starts where the size allows');
    expect(ks.every((k) => k.single <= most), isTrue,
        reason: 'a bucket of 301 handles at k > 4 holds fewer than 16 on '
            'average — at the 7 the size allows, 2.4');
  });

  test('3. a bucket refused as too large is never narrowed to the handle\'s '
      'half', () async {
    // The review's P2b: everything below 24 bits refused.
    final tiny = await startLog();
    await claimAt(tiny, 'tess.31');
    final f = _Operator()..refuse = (q) => q.bits < 24;
    final ed = await boot('Ed', config: tiny.config, fetcher: f);
    final l = await look(ed, f, '@tess.31');
    expect(l.error, isA<HandleException>().having(
        (e) => e.failure, 'failure', HandleFailure.unreachable));
    expect(l.asked, isEmpty, reason: 'the handle\'s bucket is never asked');
    expect(l.probed.map((q) => q.bits), List.generate(handleProbeSteps, (i) => i),
        reason: 'random buckets, one bit finer at each refusal, eight at most');

    // The lookup's own k refused, after a first lookup set it.
    final log = await bigLog();
    await claimAt(log, 'fern.33');
    final g = _Operator();
    final fay = await boot('Fay', config: log.config, fetcher: g);
    final first = await look(fay, g, '@fern.33');
    expect(first.found!.state, HandleLookupState.found);
    final k = first.bits.single;
    g.refuse = (q) => q.bits == k;
    final refused = await look(fay, g, '@fern.33');
    expect(refused.error, isA<HandleException>().having(
        (e) => e.failure, 'failure', HandleFailure.unreachable));
    expect(refused.asked.toSet(), first.asked.toSet(),
        reason: 'the same buckets (asked again after the estimate was made '
            'again), and no others');
    expect(refused.asked.every((q) => q.bits == k), isTrue,
        reason: 'the handle\'s bucket nowhere finer');
    expect(refused.probed, isNotEmpty, reason: 'the estimate was made again');
    g.refuse = null;
    expect((await look(fay, g, '@fern.33')).found!.state,
        HandleLookupState.found);

    // An estimate the log outgrew: refused by the log itself, made again.
    final h = _Operator();
    final gil = await boot('Gil', config: log.config, fetcher: h);
    await setEstimate(gil, log, 1);
    final grown = await look(gil, h, '@fern.33');
    expect(grown.error, isNull);
    expect(grown.found!.state, HandleLookupState.found);
    expect(grown.bits, {1, 4},
        reason: 'the buckets at 1, refused as too large, then at 4');
    final label = await labelOf('fern.33');
    expect(grown.asked.where((q) => q.holds(label)).map((q) => q.bits), [1, 4],
        reason: 'the handle\'s bucket at each k once: no half of it alone');
    // ignore: avoid_print
    print('LOOKUP 3: all refused -> ${l.error}, asked ${l.asked.length} + '
        'probed ${l.probed.map((q) => q.bits).toList()}; own k=$k refused -> '
        '${refused.error}; stale estimate 1 -> asked bits '
        '${grown.asked.map((q) => q.bits).toList()}, probed '
        '${grown.probed.map((q) => q.bits).toList()}');
  });

  test('4. decoys: the same buckets every time for a handle, and its own for '
      'another', () async {
    final log = await bigLog();
    await claimAt(log, 'gwen.34');
    await claimAt(log, 'gabe.35');
    final f = _Operator();
    final gus = await boot('Gus', config: log.config, fetcher: f);
    final a1 = await look(gus, f, '@gwen.34');
    final a2 = await look(gus, f, '@gwen.34');
    final b = await look(gus, f, '@gabe.35');
    expect(a1.found!.state, HandleLookupState.found);
    expect(b.found!.state, HandleLookupState.found);
    expect(a2.asked, a1.asked);
    final k = a1.bits.single;
    final mem = await memoryOf(gus);
    expect(a1.asked, handleLookupBuckets(mem.key, await labelOf('gwen.34'), k));
    expect(b.asked, handleLookupBuckets(mem.key, await labelOf('gabe.35'), k));
    expect(b.asked, isNot(a1.asked));

    // The app restarted: the same buckets.
    final vault = gus.vault;
    final id = gus.identity;
    await stop(gus);
    final again = await boot('Gus', config: log.config, fetcher: f, vault: vault, id: id);
    final a3 = await look(again, f, '@gwen.34');
    expect(a3.probed, isEmpty, reason: 'the estimate was kept');
    expect(a3.asked, a1.asked);
  });

  test('5. the estimate falls at once to what the handles bear out, and rises '
      'a bit a lookup', () async {
    final log = await inflatedLog();
    await claimAt(log, 'hugo.36');
    final f = _Operator()..bucketBits = 24;
    final hal = await boot('Hal', config: log.config, fetcher: f);
    await setEstimate(hal, log, 7);
    final l1 = await look(hal, f, '@hugo.36');
    final l2 = await look(hal, f, '@hugo.36');
    expect(l1.bits, {7}, reason: 'the estimate it was given, which the size allows');
    expect(l2.bits.single, lessThanOrEqualTo(4),
        reason: 'one lookup of buckets holding ~2 handles each is enough');
    expect(l2.probed, isEmpty, reason: 'from the evidence, not a new estimate');

    final small = await startLog(labels: 200);
    await claimAt(small, 'ida.37');
    final g = _Operator();
    final ida = await boot('Ida', config: small.config, fetcher: g);
    await setEstimate(ida, small, 0);
    final ks = [
      for (var i = 0; i < 3; i++) (await look(ida, g, '@ida.37')).bits.single
    ];
    expect(ks, [0, 1, 2], reason: 'one bit a lookup: 201 handles bear out 2');
    // ignore: avoid_print
    print('LOOKUP 5: estimate 7 in a log of 302 handles -> asked '
        '${l1.bits} then ${l2.bits}; estimate 0 in a log of 201 -> asked $ks');
  });

  test('6. a requester remembers the owner: a change the rule does not '
      'explain is refused; a recovery is not', () async {
    final log = await startLog(ruleless: true);
    final frank = await claimAt(log, 'frank.61');
    final franksMailbox = await frank.introRid();
    final f = _Operator();
    final gina = await boot('Gina', config: log.config, fetcher: f);
    final before = await gina.handles.find('@frank.61');
    expect(before.state, HandleLookupState.found);
    expect(before.introRid, franksMailbox);

    // The operator names its own owner and mailbox.
    final operators = await takeOver(log, frank);
    final after = await gina.handles.find('@frank.61');
    // ignore: avoid_print
    print('LOOKUP 6: Gina resolves @frank.61 after the operator\'s update -> '
        '${after.state.name} (${after.change?.name}), mailbox ${after.introRid}'
        ' (Frank\'s $franksMailbox, the operator\'s $operators)');
    expect(after.state, HandleLookupState.changed);
    expect(after.change, HandleChange.owner);
    expect(after.introRid, isNull, reason: 'nothing to send a request to');
    await expectLater(
        gina.handles.request(after), failsWith(HandleFailure.notClaimed));
    expect((await gina.handles.find('@frank.61')).state,
        HandleLookupState.changed, reason: 'and again, until the person says');

    // Looked up as new — the person's choice — the new owner is taken.
    final asNew = await gina.handles.lookUpAsNew(after);
    expect(asNew.state, HandleLookupState.found);
    expect(asNew.introRid, operators);
    expect((await gina.handles.find('@frank.61')).state,
        HandleLookupState.found);

    // A genuine recover and a new inbox after it, each seen: no question.
    final rita = await claimAt(log, 'rita.62');
    expect((await gina.handles.find('@rita.62')).state, HandleLookupState.found);
    await recoverAt(log, rita);
    final recovered = await gina.handles.find('@rita.62');
    expect(recovered.state, HandleLookupState.found);
    expect(recovered.record!.kind, HandleRecordKind.recover);
    expect(recovered.introRid, await rita.introRid());
    await newInbox(log, rita);
    final moved = await gina.handles.find('@rita.62');
    expect(moved.state, HandleLookupState.found);
    expect(moved.introRid, await rita.introRid());

    // A recover and a new inbox after it, neither seen: one record cannot
    // tell the code's work from the log's.
    final sam = await claimAt(log, 'sam.63');
    expect((await gina.handles.find('@sam.63')).state, HandleLookupState.found);
    await recoverAt(log, sam);
    await newInbox(log, sam);
    final unseen = await gina.handles.find('@sam.63');
    expect(unseen.state, HandleLookupState.changed);
    expect(unseen.change, HandleChange.owner);
  });

  test('7. history: another record at a version seen, an older one, or none',
      () async {
    final log = await startLog(ruleless: true, labels: 4);
    final uma = await claimAt(log, 'uma.71');
    await newInbox(log, uma);
    final f = _Operator();
    final hana = await boot('Hana', config: log.config, fetcher: f);
    final seen = await hana.handles.find('@uma.71');
    expect(seen.state, HandleLookupState.found);
    expect(seen.version, 2);

    // Version 2 again, another record (an equivocation).
    await put(log, uma.label, 2,
        await recordOf(HandleRecordKind.update, uma.ownerSeed, randomBytes(32),
            uma.rk.rc),
        uma.ownerSeed);
    final twice = await hana.handles.find('@uma.71');
    expect(twice.state, HandleLookupState.changed);
    expect(twice.change, HandleChange.history);

    // An older version: a claim, by someone else.
    final other = randomBytes(32);
    await put(log, uma.label, 1,
        await recordOf(HandleRecordKind.claim, other, randomBytes(32),
            randomBytes(32)),
        other);
    final older = await hana.handles.find('@uma.71');
    expect(older.state, HandleLookupState.changed);
    expect(older.change, HandleChange.history);

    // None at all: the log, restarted empty under its key.
    await restartEmpty(log);
    final gone = await hana.handles.find('@uma.71');
    expect(gone.state, HandleLookupState.changed);
    expect(gone.change, HandleChange.history);
    expect((await hana.handles.find('@zed.79')).state,
        HandleLookupState.notFound, reason: 'a handle never seen is just absent');
  });

  test('8. a head signed more than a day ago is stale', () async {
    final log = await startLog();
    await claimAt(log, 'stan.81');
    final f = _Operator();
    final ivo = await boot('Ivo', config: log.config, fetcher: f);
    final real = ivo.handles.now;
    ivo.handles.now = () => real() + const Duration(hours: 25).inMilliseconds;
    await expectLater(
        ivo.handles.find('@stan.81'), failsWith(HandleFailure.stale));
    ivo.handles.now = () => real() + const Duration(hours: 23).inMilliseconds;
    expect((await ivo.handles.find('@stan.81')).state, HandleLookupState.found);
    ivo.handles.now = () => real() - const Duration(days: 3).inMilliseconds;
    expect((await ivo.handles.find('@stan.81')).state, HandleLookupState.found);
  });

  test('9. versions no honest log serves fail as a bad answer, never as '
      'arithmetic', () async {
    final log = await startLog(ruleless: true, labels: 2);
    final vic = await boot('Vic', config: log.config);
    final kim = await boot('Kim', config: log.config);
    final dana = await boot('Dana', config: log.config);
    final draft = await vic.handles.prepareClaim(Handle.parse('vic.91'), pow: 16);
    await vic.handles.commitClaim(draft);
    await waitUntil(() => vic.handles.own?.phase == HandlePhase.live,
        what: 'vic.91 published');
    expect((await kim.handles.find('@vic.91')).state, HandleLookupState.found);

    // A thief with Vic's owner key, and a log that does not hold it to the
    // next version: an update at 2^53 − 1.
    final thief = await handleIntroIdentity(randomBytes(32));
    await put(
        log,
        draft.label,
        handleMaxVersion,
        HandleRecord.update(
            owner: await handleKeyPublic(draft.ownerSeed),
            intro: thief.edPub,
            xintro: thief.xPub,
            pow: 16,
            rc: draft.rc),
        draft.ownerSeed);
    Object? rotated;
    try {
      await vic.handles.rotate();
    } catch (e) {
      rotated = e;
    }
    Object? recovered;
    try {
      await dana.handles.prepareRecover('vic.91', draft.code);
    } catch (e) {
      recovered = e;
    }
    // ignore: avoid_print
    print('LOOKUP 9: an update at 2^53-1 -> the owner\'s change: $rotated; '
        'a recover with the code: $recovered');
    expect(rotated, isA<HandleException>().having(
        (e) => e.failure, 'failure', HandleFailure.badAnswer));
    expect(recovered, isA<HandleException>().having(
        (e) => e.failure, 'failure', HandleFailure.badAnswer));
    await expectLater(
        kim.handles.find('@vic.91'), failsWith(HandleFailure.badAnswer));

    // A version past its index + 1.
    final wes = await claimAt(log, 'wes.92');
    await put(log, wes.label, 9,
        await recordOf(HandleRecordKind.update, wes.ownerSeed, wes.introSeed,
            wes.rk.rc),
        wes.ownerSeed);
    await expectLater(
        kim.handles.find('@wes.92'), failsWith(HandleFailure.badAnswer));

    // A claim at version 2: the rule's first entry is version 1.
    final xan = randomBytes(32);
    await put(log, await labelOf('xan.93'), 2,
        await recordOf(HandleRecordKind.claim, xan, randomBytes(32),
            randomBytes(32)),
        xan);
    expect((await kim.handles.find('@xan.93')).state, HandleLookupState.invalid);
  });

  test('10. backup and restore carry the memory', () async {
    final log = await startLog(ruleless: true, labels: 1000);
    final nina = await claimAt(log, 'nina.10');
    final f = _Operator();
    final jo = await boot('Jo', config: log.config, fetcher: f);
    final first = await look(jo, f, '@nina.10');
    expect(first.found!.state, HandleLookupState.found);

    final code = await RecoveryCode.generate();
    final file = File(p.join(
        (await Directory.systemTemp.createTemp('z_hlookup_zbk')).path, 'b.zbk'));
    temps.add(file.parent);
    final sink = file.openWrite();
    await BackupArchive.export(vault: jo.vault, code: code, out: sink);
    await sink.close();
    final dir = jo.vault.root;
    await stop(jo);
    await jo.vault.db.close();
    dir.deleteSync(recursive: true);
    dir.createSync(recursive: true);
    final vault = await Vault.open(rootOverride: dir);
    await Restore.run(
        vault: vault,
        file: file,
        secret: await code.format(),
        kind: (await Restore.identify(file)).kind,
        serverUrl: 'ws://127.0.0.1:$relayPort');
    final id = await ZIdentity.fromJson(
        (jsonDecode((await vault.kvGet('identity'))!) as Map)
            .cast<String, Object?>());
    final back = await boot('Jo', config: log.config, fetcher: f, vault: vault, id: id);
    final again = await look(back, f, '@nina.10');
    expect(again.found!.state, HandleLookupState.found);
    expect(again.probed, isEmpty, reason: 'the estimate came back');
    expect(again.asked, first.asked, reason: 'the decoy key came back');

    await takeOver(log, nina);
    final after = await back.handles.find('@nina.10');
    expect(after.state, HandleLookupState.changed,
        reason: 'what the old device found came back');
    expect(after.change, HandleChange.owner);

    // A memory that is not one stays out of the restored vault.
    final out = HandleBackup.restore({
      'kv': {
        handleLookupKey: {'log': 'x', 'key': b64(Uint8List(5))},
      }
    }, const {});
    expect(out.containsKey(handleLookupKey), isFalse);
  });

  testWidgets('11. the screen says why a lookup was refused, in both languages',
      (tester) async {
    final h = Handle.parse('frank.61');
    for (final (locale, l) in [
      (const Locale('en'), AppLocalizationsEn() as AppLocalizations),
      (const Locale('es'), AppLocalizationsEs() as AppLocalizations),
    ]) {
      var asNew = 0;
      Future<void> show(HandleChange change) async {
        await tester.pumpWidget(MaterialApp(
          debugShowCheckedModeBanner: false,
          theme: ZTheme.light(),
          locale: locale,
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: Scaffold(
              body: HandleLookupResult(
                  found: HandleLookup.debug(h, HandleLookupState.changed,
                      label: Uint8List(32), change: change),
                  busy: false,
                  sending: false,
                  onRequest: () => fail('a request was offered'),
                  onLookUpAsNew: () => asNew++)),
        ));
        await tester.pumpAndSettle();
      }

      await show(HandleChange.owner);
      expect(find.text(l.hdlFoundChangedOwner('frank.61')), findsOneWidget);
      expect(find.text(l.hdlChangedNote), findsOneWidget);
      expect(find.text(l.hdlSendRequest), findsNothing);
      await tester.tap(find.text(l.hdlLookUpAsNew));
      expect(asNew, 1);
      await show(HandleChange.history);
      expect(find.text(l.hdlFoundChangedHistory('frank.61')), findsOneWidget);
      expect(find.text(l.hdlSendRequest), findsNothing);
      expect(find.text(l.hdlLookUpAsNew), findsOneWidget);
      expect(handleFailureText(l, HandleFailure.stale), l.hdlErrStale);
    }
    expect(AppLocalizationsEs().hdlLookUpAsNew,
        isNot(AppLocalizationsEn().hdlLookUpAsNew));
  });

  test('12. the rules on their own', () async {
    expect([
      for (final n in [0, 63, 64, 127, 128, 1001, 1 << 29, 1 << 40])
        handleBitsFor(n)
    ], [0, 0, 1, 1, 2, 4, 24, 24]);

    // The probe: coarser by as much as the count fell short of 32.
    expect(handleProbeNext(7, 0), 2);
    expect(handleProbeNext(7, 2), 3);
    expect(handleProbeNext(7, 5), 4);
    expect(handleProbeNext(7, 16), 6);
    expect(handleProbeNext(7, 32), isNull);
    expect(handleProbeNext(3, 0), 0);
    expect(handleProbeNext(0, 3), isNull);

    // The evidence: falls at once, rises a bit, holds in between.
    expect(handleNextBits(7, 7, [2, 3, 1, 4]), 3,
        reason: '10 × 2^7 / 4 = 320 handles');
    expect(handleNextBits(6, 4, [40, 40]), 4, reason: 'asked coarser than held');
    expect(handleNextBits(2, 2, [500, 520, 480, 510]), 3,
        reason: 'one bit, though 2,000 handles bear out 5');
    expect(handleNextBits(4, 4, [70, 66, 80, 65]), 5);
    expect(handleNextBits(4, 4, [16, 30, 40, 63]), 4);
    expect(handleNextBits(4, 4, const []), 4);

    // Decoys: a function of key and label, each finer bucket inside the
    // coarser one.
    final key = randomBytes(32), a = randomBytes(32), b = randomBytes(32);
    expect(handleDecoyPoints(key, a), handleDecoyPoints(key, a));
    expect(handleDecoyPoints(randomBytes(32), a), isNot(handleDecoyPoints(key, a)));
    final da = handleDecoyPoints(key, a).map(b64).toSet();
    expect(handleDecoyPoints(key, b).map(b64).where(da.contains), isEmpty);
    for (var k = 0; k < ktMaxBucketBits; k++) {
      final coarse = handleLookupBuckets(key, a, k);
      for (final q in handleLookupBuckets(key, a, k + 1)) {
        final inside = ktParseBucketPrefix(q.prefix, q.bits)!;
        expect(coarse.any((c) => c.holds(inside)), isTrue);
      }
    }
    // Two installs — an account's two devices, or a reinstall without a
    // backup — ask one handle through two keys, and what their sets have in
    // common is its bucket: the residual THREAT_MODEL's trust row names.
    var exact = 0;
    for (var t = 0; t < 200; t++) {
      final mine = handleLookupBuckets(key, a, 9).map((q) => q.prefix).toSet();
      final theirs = handleLookupBuckets(randomBytes(32), a, 9)
          .map((q) => q.prefix)
          .toSet();
      final meet = mine.intersection(theirs);
      if (meet.length == 1 && meet.single == ktBucketPrefix(a, 9)) exact++;
    }
    expect(exact, greaterThan(190),
        reason: 'two keys\' decoys coincide by chance alone (3 × 3 / 512)');

    // The leaf rule.
    KtBucketLeaf leaf(int index, int version) =>
        KtBucketLeaf(label: a, index: index, version: version);
    expect(handleLeafProblem(leaf(0, 1)), isNull);
    expect(handleLeafProblem(leaf(4, 5)), isNull);
    expect(handleLeafProblem(leaf(4, 6)), isNotNull);
    expect(handleLeafProblem(leaf(3, 0)), isNotNull);
    expect(handleLeafProblem(leaf(handleMaxVersion - 2, handleMaxVersion - 1)),
        isNull);
    expect(handleLeafProblem(leaf(handleMaxVersion - 1, handleMaxVersion)),
        isNotNull, reason: 'index + 1 allows it; no version can follow it');

    // What one record can follow.
    final owner = randomBytes(32);
    final code = await RecoveryCode.generate();
    final rk = await handleRecoveryKey(code, a);
    final known = KnownHandle(
        owner: await handleKeyPublic(owner),
        rc: rk.rc,
        version: 3,
        hash: Uint8List(32),
        atMs: 0);
    Future<HandleRecord> update(Uint8List seed, Uint8List rc) async {
      final intro = await handleIntroIdentity(randomBytes(32));
      return HandleRecord.update(
          owner: await handleKeyPublic(seed),
          intro: intro.edPub,
          xintro: intro.xPub,
          pow: 16,
          rc: rc);
    }

    final same = await update(owner, rk.rc);
    final other = randomBytes(32);
    final foreign = await update(other, rk.rc);
    Future<HandleRecord> recover(HandleRecoveryKey by) async =>
        HandleRecord.recover(
            owner: await handleKeyPublic(other),
            intro: null,
            xintro: null,
            pow: 16,
            rc: randomBytes(32),
            rpub: by.pub,
            rsig: Uint8List(64));
    final h1 = Uint8List(32)..[0] = 1;
    expect(await handleKnownChange(known, version: 9, hash: h1, rec: same), isNull);
    expect(await handleKnownChange(known, version: 4, hash: h1, rec: foreign),
        HandleChange.owner);
    expect(await handleKnownChange(known, version: 5, hash: h1, rec: await recover(rk)),
        isNull, reason: 'the key the remembered commitment names');
    final wrong = await handleRecoveryKey(await RecoveryCode.generate(), a);
    expect(await handleKnownChange(known, version: 4, hash: h1, rec: await recover(wrong)),
        HandleChange.owner);
    expect(await handleKnownChange(known, version: 2, hash: h1, rec: same),
        HandleChange.history);
    expect(await handleKnownChange(known, version: 3, hash: h1, rec: same),
        HandleChange.history);
    expect(await handleKnownChange(known, version: 3, hash: Uint8List(32), rec: same),
        isNull);

    // The stored memory: its shape, and the cap.
    final m = HandleLookupMemory(log: 'L', key: randomBytes(32), bits: 5);
    for (var i = 0; i < handleKnownCap + 3; i++) {
      final l = Uint8List(32)..[0] = i & 0xff..[1] = i >> 8;
      m.remember(l, KnownHandle(owner: owner, rc: rk.rc, version: 1, hash: h1, atMs: 1000 + i));
    }
    expect(m.known, hasLength(handleKnownCap));
    expect(m.knownFor(Uint8List(32)), isNull, reason: 'the one found longest ago went');
    final back = HandleLookupMemory.parse(jsonEncode(m.toJson()))!;
    expect(back.bits, 5);
    expect(back.known, hasLength(handleKnownCap));
    expect(HandleLookupMemory.parse('{"log":"L","key":"${b64(Uint8List(31))}"}'), isNull);
    expect(HandleLookupMemory.parse('{"log":"L","key":"${b64(Uint8List(32))}","k":25}'), isNull);
    final odd = HandleLookupMemory.parse(jsonEncode({
      'log': 'L',
      'key': b64(Uint8List(32)),
      'known': {
        b64url(Uint8List(32)): {'o': b64(owner), 'rc': b64(rk.rc), 'v': 0, 'h': b64(h1), 'at': 1},
        'not-a-label': {'o': b64(owner), 'rc': b64(rk.rc), 'v': 1, 'h': b64(h1), 'at': 1},
      },
    }))!;
    expect(odd.known, isEmpty, reason: 'a version 0 and a key that is no label are left out');
  });

  test('13. refusing a bucket cannot raise k: the probe steps finer and goes '
      'on until one holds 32', () async {
    final log = await tallLog();
    await claimAt(log, 'rune.13');
    final label = await labelOf('rune.13');
    final honest = handleBitsFor(log.labels + 1);
    expect(honest, 3);
    expect(handleBitsFor(log.size + 1), 8, reason: 'what the size allows');
    // The operator's chance is a random bucket whose count alone puts k
    // above 3 — one in three at k = 8, where a bucket holds 1.2 handles on
    // average — so it waits for one across fresh installs, each with a
    // different seed and so a different first bucket; and the test waits for
    // it to have taken it.
    final lookups = <_Look>[];
    _Operator? got;
    var attempts = 0;
    for (var i = 0; i < 40 && got == null; i++) {
      final f = _Operator()
        ..bucketBits = 24
        ..refuseAboveHonest = honest;
      final s = await boot('Ron$i', config: log.config, fetcher: f, seed: 1300 + i);
      lookups.add(await look(s, f, '@rune.13'));
      await stop(s);
      attempts++;
      if (f.refusals > 0) got = f;
    }
    expect(got, isNotNull, reason: 'the operator never saw a count above honest');
    final last = lookups.last;
    // ignore: avoid_print
    print('LOOKUP 13: ${log.labels + 1} handles, size ${log.size + 1}, '
        'bucketBits rewritten to 24; the operator refused on attempt $attempts '
        '-> probed ${last.probed.map((q) => q.bits).toList()}, asked '
        '${last.asked.map((q) => q.bits).toList()}, '
        '${last.found?.state.name ?? last.error}');
    for (final l in lookups) {
      expect(l.asked.where((q) => q.holds(label)).every((q) => q.bits <= honest),
          isTrue,
          reason: 'a refusal must never put the handle\'s bucket finer than '
              'the handles bear out (§21.8: a refused bucket is asked finer '
              'with a fresh draw; the estimate is a bucket of 32)');
    }
    expect(last.found!.state, HandleLookupState.found);
    expect(last.bits, {honest});
  });

  test('14. a bucket counts only under the head held when it was drawn, and '
      'within a lookup the head only grows', () async {
    final log = await tallLog();
    await claimAt(log, 'mint.14');
    final label = await labelOf('mint.14');
    final honest = handleBitsFor(log.labels + 2);
    expect(honest, 3);

    // On seeing the first random bucket asked, the operator mints 32 labels
    // into it — as it can, holding no handle's key but its own — and
    // answers under the head that holds them.
    Uint8List within(KtBucketQuery q) {
      final p = ktParseBucketPrefix(q.prefix, q.bits)!;
      final out = randomBytes(32);
      for (var d = 0; d < q.bits; d++) {
        final mask = 1 << (7 - (d & 7));
        if (p[d >> 3] & mask != 0) {
          out[d >> 3] |= mask;
        } else {
          out[d >> 3] &= ~mask;
        }
      }
      return out;
    }

    var minted = 0;
    KtBucketQuery? mintedInto;
    final f = _Operator()..bucketBits = 24;
    f.onBucket = (q) async {
      f.onBucket = null;
      mintedInto = q;
      for (var i = 0; i < 32; i++) {
        final seed = randomBytes(32);
        await put(log, within(q), 1,
            await recordOf(HandleRecordKind.claim, seed, randomBytes(32), randomBytes(32)),
            seed);
        minted++;
      }
    };
    final mia = await boot('Mia', config: log.config, fetcher: f, seed: 14);
    final l = await look(mia, f, '@mint.14');
    // ignore: avoid_print
    print('LOOKUP 14: 32 labels minted into $mintedInto on seeing it -> '
        'probed ${l.probed.map((q) => q.bits).toList()}, asked '
        '${l.asked.map((q) => q.bits).toList()}, '
        '${l.found?.state.name ?? l.error}');
    expect(minted, 32);
    expect(mintedInto!.bits, 8, reason: 'the probe starts where the size allows');
    expect(l.error, isNull);
    expect(l.found!.state, HandleLookupState.found);
    expect(l.asked.where((q) => q.holds(label)).every((q) => q.bits <= honest),
        isTrue,
        reason: 'labels minted into a bucket on seeing it must not count');
    expect(l.probed.where((q) => q.bits == 8).length, greaterThanOrEqualTo(2),
        reason: 'the minted bucket is not counted: another is drawn at 8');

    // An older answer served again after the log grew: the lookup read the
    // newer head first, so the answer is under a head that shrank.
    final g = _Operator()..keep = true;
    final nat = await boot('Nat', config: log.config, fetcher: g, seed: 15);
    expect((await look(nat, g, '@mint.14')).found!.state, HandleLookupState.found);
    await claimAt(log, 'grow.14');
    g
      ..keep = false
      ..replay = true
      ..kept.removeWhere((path, _) => path.startsWith('/kt/v1/sth'));
    await expectLater(nat.handles.find('@mint.14'), failsWith(HandleFailure.badAnswer));

    // The other way round — an older head read first, newer answers — is a
    // log that grew during the lookup: taken, with its consistency proof.
    g
      ..kept.removeWhere((path, _) => !path.startsWith('/kt/v1/sth'))
      ..replay = false
      ..keep = true;
    final before = g.urls.length;
    expect((await look(nat, g, '@mint.14')).found!.state, HandleLookupState.found);
    await claimAt(log, 'more.14');
    g
      ..keep = false
      ..replay = true
      ..kept.removeWhere((path, _) => !path.startsWith('/kt/v1/sth'));
    final again = await look(nat, g, '@mint.14');
    expect(again.found!.state, HandleLookupState.found);
    expect(g.urls.skip(before).any((u) => u.path == '/kt/v1/consistency'), isTrue,
        reason: 'the newer head is taken only with a proof it extends the old');
  });

  // ---------------------------------------------------------------------------
  // The handle log's witness (phase 19, 2026-10-19).

  test('15. a forked log: a lookup its witness contradicts is refused, and '
      'nothing it returned is sent or kept', () async {
    // One key, two histories. x is what the log shows Carol; y is what its
    // witness verified. In y @fern.21 is Fern's; in x it is a mailbox of the
    // operator's.
    final x = await startLog();
    final y = await startLog(key: x.seed);
    expect(b64(y.pub), b64(x.pub), reason: 'one operator, one key');
    await claimAt(y, 'fern.21');
    final thief = await claimAt(x, 'fern.21');
    final w = await witnessOf(y);
    final f = _Operator();
    serve(f, w);
    final carol = await boot('Carol', config: witnessed(x, w), fetcher: f);
    final label = await labelOf('fern.21');

    // The same size, under other roots.
    final same = await look(carol, f, '@fern.21');
    expect(same.error, forked(),
        reason: 'the witness verified a head of the same size with other roots');
    expect(same.found, isNull);
    expect(f.urls.where((u) => u.toString() == w.url), hasLength(1),
        reason: 'the witness was asked, once');

    // The log grows: the witness is a head behind, and the log's proof from
    // that size does not lead from the witness's root to the log's.
    await claimAt(x, 'gail.22');
    final behind = await look(carol, f, '@fern.21');
    expect(behind.error, forked(),
        reason: 'the proof from the witness\'s head does not verify');
    expect(
        f.urls.any((u) =>
            u.path == '/kt/v1/consistency' && u.query == 'first=1&second=2'),
        isTrue,
        reason: 'the log was asked to prove the way from the witness\'s head');

    // The witness ahead: y grows past x and the witness follows it. The log
    // cannot prove the way to a head this history never signed, and the head
    // it serves is smaller: a log gone back below what its witness verified.
    await claimAt(y, 'hugo.23');
    await claimAt(y, 'iris.24');
    await sync(w, y);
    final g = _Operator();
    serve(g, w);
    final cy = await boot('Cy', config: witnessed(x, w), fetcher: g);
    final ahead = await look(cy, g, '@fern.21');
    expect(ahead.error, forked(),
        reason: 'the witness verified a head the log cannot reach');
    expect(
        g.urls.any((u) =>
            u.path == '/kt/v1/consistency' && u.query == 'first=2&second=3'),
        isTrue,
        reason: 'the log was asked to prove the way to the witness\'s head');

    // Nothing either lookup returned is used, kept or sent.
    for (final s in [carol, cy]) {
      expect((await memoryOf(s)).knownFor(label), isNull,
          reason: 'no record remembered');
      expect(s.handles.outgoing, isEmpty, reason: 'no request kept');
      expect(s.handles.stampsMade, 0, reason: 'no request made');
      expect(await s.vault.kvScan('hvia_'), isEmpty);
      expect(s.handles.witnessOkMs, isNull, reason: 'and no agreement');
    }

    // What the witness is for: without one, the same lookup takes the
    // operator's record, and a request would go to its mailbox.
    final dan = await boot('Dan', config: x.config);
    final taken = await dan.handles.find('@fern.21');
    expect(taken.state, HandleLookupState.found);
    expect(taken.introRid, await thief.introRid());
    // ignore: avoid_print
    print('LOOKUP 15: x and y under one key; Carol through y\'s witness -> '
        '${same.error}, ${behind.error}, ${ahead.error}; Dan with none -> '
        '${taken.state.name}, the operator\'s mailbox');
  });

  test('16. every way a head is taken is held to the witness: a claim\'s '
      'check that a name is free, a recovery\'s read, and the owner\'s reads '
      'of its own record — at a refresh, before a change, before a drain',
      () async {
    // x is what the log shows; y, under the same key, what the witness saw.
    final x = await startLog();
    final y = await startLog(key: x.seed);
    await claimAt(y, 'yuri.61');
    final w = await witnessOf(y);

    // Dora claims in x before any witness is set; then she is given one.
    final f = _Operator();
    serve(f, w);
    final dora = await boot('Dora', config: x.config, fetcher: f);
    final draft =
        await dora.handles.prepareClaim(Handle.parse('dora.62'), pow: 16);
    await dora.handles.commitClaim(draft);
    await waitUntil(() => dora.handles.own?.phase == HandlePhase.live,
        what: 'dora.62 published');
    expect(fetchesOf(f, w.url), 0, reason: 'no witness yet, none asked');
    await dora.handles.setConfig(witnessed(x, w));

    // The owner's refresh: the record read back is refused, and the handle
    // screen's line says why. The handle is hers still.
    await dora.handles.refresh();
    expect(dora.handles.own!.problem, HandleFailure.forked.name);
    expect(handleStoredProblemText(AppLocalizationsEn(), dora.handles.own!.problem),
        AppLocalizationsEn().hdlErrForked);
    expect(dora.handles.own!.phase, HandlePhase.live);
    // A change: refused before anything is published.
    await expectLater(dora.handles.pause(), failsWith(HandleFailure.forked));
    // A drain: its read of the record is refused, and it goes on with what
    // this device holds, as it does when the log cannot be asked.
    final drains = dora.handles.drains;
    await dora.handles.drain();
    expect(dora.handles.drains, drains + 1);
    expect(dora.handles.own!.phase, HandlePhase.live);
    // Her own handle, looked up.
    await expectLater(
        dora.handles.find('@dora.62'), failsWith(HandleFailure.forked));

    // Someone else: a claim's check that a name is free, at random digits
    // too, and the read a recovery makes first.
    final carol = await boot('Carol', config: witnessed(x, w), fetcher: f);
    await expectLater(carol.handles.isAvailable(Handle.parse('kim.63')),
        failsWith(HandleFailure.forked));
    await expectLater(carol.handles.availableWithRandomDigits('kim'),
        failsWith(HandleFailure.forked));
    final code = await formatHandleRecoveryCode(await RecoveryCode.generate());
    await expectLater(carol.handles.prepareRecover('dora.62', code),
        failsWith(HandleFailure.forked));

    // Nothing was published: with no witness, x still holds dora.62 as she
    // claimed it, taking requests.
    final dan = await boot('Dan', config: x.config);
    final seen = await dan.handles.find('@dora.62');
    expect(seen.state, HandleLookupState.found);
    expect(seen.version, 1);
    expect(fetchesOf(f, w.url), greaterThanOrEqualTo(1));
  });

  test('17. a witness behind the lookup\'s head and one ahead of it both '
      'agree, and the agreement is recorded', () async {
    final log = await startLog();
    await claimAt(log, 'lena.71');

    // Behind: the witness service itself, fetched over loopback as
    // configured; the log grows by two after it verified.
    final w = await witnessOf(log, synced: false);
    final url = await serveWitness(w, log);
    final verified = (await headOf(log)).size;
    await claimAt(log, 'lars.72');
    await claimAt(log, 'lea.73');
    final f = _Operator();
    final max = await boot('Max', config: witnessed(log, w, url: url), fetcher: f);
    final before = DateTime.now().millisecondsSinceEpoch;
    expect((await max.handles.find('@lena.71')).state, HandleLookupState.found);
    expect(fetchesOf(f, url), 1, reason: 'the record, from the witness service');
    expect(
        f.urls.any((u) =>
            u.path == '/kt/v1/consistency' &&
            u.query == 'first=$verified&second=${verified + 2}'),
        isTrue,
        reason: 'the log proved the way from the witness\'s head to its own');
    expect(max.handles.witnessOkMs, greaterThanOrEqualTo(before));
    expect(max.handles.witnessState, HandleWitnessState.agreed);

    // Ahead: between the lookup's head and its question to the witness the
    // log grows by two, and the witness verifies the larger head.
    final w2 = await witnessOf(log);
    late int held;
    final g = _Operator()
      ..witnessUrl = w2.url
      ..witness = () async {
        held = (await headOf(log)).size;
        await claimAt(log, 'liv.74');
        await claimAt(log, 'lou.75');
        await sync(w2, log);
        return KtResponse(200, w2.record);
      };
    final mo = await boot('Mo', config: witnessed(log, w2), fetcher: g);
    expect((await mo.handles.find('@lena.71')).state, HandleLookupState.found);
    expect(
        g.urls.any((u) =>
            u.path == '/kt/v1/consistency' &&
            u.query == 'first=$held&second=${held + 2}'),
        isTrue,
        reason: 'the log proved its head a prefix of the witness\'s');
    expect(mo.handles.witnessState, HandleWitnessState.agreed);

    // Recorded, sealed, with the configuration it is an answer under.
    final rows = await mo.vault.db.query('kv',
        columns: ['k'], where: 'k LIKE ?', whereArgs: ['%:handle_witness_ok_ms']);
    expect(rows.map((r) => r['k']), ['s:handle_witness_ok_ms'],
        reason: 'sealed, as nothing in Vault.plainKeys is');
    final stored =
        (jsonDecode((await mo.vault.kvGet('handle_witness_ok_ms'))!) as Map)
            .cast<String, Object?>();
    expect(stored['at'], mo.handles.witnessOkMs);
    expect(stored['w'], contains(b64(w2.pub)));
  });

  test('18. a witness that cannot be reached, or whose record does not '
      'verify, is no verdict: the lookup goes on, the state says no answer '
      'yet, and a day of asking without one is a witness gone quiet', () async {
    final log = await startLog();
    final nora = await claimAt(log, 'nora.81');
    final w = await witnessOf(log);

    // Nothing listening at the address.
    final closed = 'http://127.0.0.1:${await freePort()}/sth.json';
    final f0 = _Operator();
    final pat = await boot('Pat', config: witnessed(log, w, url: closed), fetcher: f0);
    final first = await pat.handles.find('@nora.81');
    expect(first.state, HandleLookupState.found);
    expect(first.introRid, await nora.introRid());
    expect(fetchesOf(f0, closed), 1, reason: 'asked, and nothing answered');
    expect(pat.handles.witnessState, HandleWitnessState.pending);
    expect(pat.handles.witnessSinceMs, isNotNull);
    expect(pat.handles.witnessOkMs, isNull);

    // One witness, asked over a day and a hour: unreachable, an error, and
    // records that do not verify — each no verdict, and the lookup found.
    String altered(void Function(Map<String, dynamic> r) change) {
      final r = jsonDecode(w.record) as Map<String, dynamic>;
      change(r);
      return jsonEncode(r);
    }

    String flipped(String b) {
      final x = unb64(b);
      x[5] ^= 1;
      return b64(x);
    }

    final answers = <String, Future<KtResponse> Function()>{
      'unreachable': () async => throw const SocketException('refused'),
      'an error': () async => KtResponse(404, '{}'),
      'the co-signature altered': () async => KtResponse(200,
          altered((r) => r['witness']['sig'] = flipped(r['witness']['sig'] as String))),
      'the log\'s signature altered': () async => KtResponse(200,
          altered((r) => r['sth']['sig'] = flipped(r['sth']['sig'] as String))),
      'not a record': () async => KtResponse(200, '{"sth":7}'),
    };
    final f = _Operator()..witnessUrl = w.url;
    final ola = await boot('Ola', config: witnessed(log, w), fetcher: f);
    final real = ola.handles.now;
    final t0 = real() - const Duration(hours: 25).inMilliseconds;
    var at = t0;
    ola.handles.now = () => at;
    for (final e in answers.entries) {
      f.witness = e.value;
      final l = await ola.handles.find('@nora.81');
      expect(l.state, HandleLookupState.found, reason: e.key);
      expect(ola.handles.witnessState, HandleWitnessState.pending, reason: e.key);
      at += const Duration(minutes: 10).inMilliseconds;
    }
    expect(ola.handles.witnessSinceMs, t0,
        reason: 'when it began asking without an answer');
    expect(fetchesOf(f, w.url), answers.length, reason: 'none kept for reuse');

    // A day on, the same: quiet since the first question.
    at = real();
    f.witness = answers['unreachable'];
    expect((await ola.handles.find('@nora.81')).state, HandleLookupState.found);
    expect(ola.handles.witnessState, HandleWitnessState.quiet);
    expect(ola.handles.witnessQuietSinceMs, t0);

    // It answers, agreeing: the asking without an answer is over.
    serve(f, w);
    expect((await ola.handles.find('@nora.81')).state, HandleLookupState.found);
    expect(ola.handles.witnessState, HandleWitnessState.agreed);
    expect(ola.handles.witnessSinceMs, isNull);
    expect(ola.handles.witnessLastAskMs, isNull);
    expect(await ola.vault.kvGet('handle_witness_since_ms'), isNull);
  });

  test('19. half a witness is refused when it is set, and one held from '
      'before is never asked', () async {
    final log = await startLog();
    await claimAt(log, 'halle.91');
    final w = await witnessOf(log);
    final f = _Operator();
    serve(f, w);
    final url = 'http://127.0.0.1:${log.port}';
    final pub = b64(log.pub);
    final quin = await boot('Quin', config: log.config, fetcher: f);
    Future<void> refused(HandleConfig c, String reason) => expectLater(
        quin.handles.setConfig(c),
        throwsA(isA<HandleConfigInvalid>().having((e) => e.reason, 'reason', reason)));
    await refused(
        HandleConfig(logUrl: url, logPubB64: pub, witnessUrl: w.url), 'urlWithoutKey');
    await refused(HandleConfig(logUrl: url, logPubB64: pub, witnessPubB64: b64(w.pub)),
        'keyWithoutUrl');
    await refused(
        HandleConfig(
            logUrl: url,
            logPubB64: pub,
            witnessUrl: w.url,
            witnessPubB64: b64(Uint8List(31))),
        'keyNotValid');
    expect(quin.handles.config.witnessUrl, isEmpty, reason: 'nothing was taken');
    expect(await quin.vault.kvGet('handle_config'), isNull, reason: 'nor stored');

    // Half a witness held already — as a configuration reads back from the
    // vault, written before the rule or restored from an archive — is no
    // witness: the lookup goes on and its address is never asked.
    for (final (name, half) in [
      ('Rae', {'url': url, 'pub': pub, 'wurl': w.url}),
      ('Ros', {'url': url, 'pub': pub, 'wpub': b64(w.pub)}),
      ('Rui', {'url': url, 'pub': pub, 'wurl': w.url, 'wpub': 'not base64'}),
    ]) {
      final d = await Directory.systemTemp.createTemp('z_hlookup_half');
      temps.add(d);
      final v = await Vault.open(rootOverride: d);
      final id = await ZIdentity.generate();
      await v.kvPut('identity', jsonEncode(id.toJson()));
      await v.kvPut('handle_config', jsonEncode(half));
      final s = await boot(name, config: log.config, fetcher: f, vault: v, id: id);
      expect(s.handles.config.witnessUrl.isNotEmpty || s.handles.config.witnessPubB64.isNotEmpty,
          isTrue, reason: 'the half it holds, as stored');
      expect(s.handles.config.hasWitness, isFalse);
      expect((await s.handles.find('@halle.91')).state, HandleLookupState.found);
      expect(s.handles.witnessState, HandleWitnessState.none);
    }
    expect(fetchesOf(f, w.url), 0, reason: 'half a witness is never fetched');

    // Both together are one, and it is asked.
    await quin.handles.setConfig(witnessed(log, w));
    expect(quin.handles.config.hasWitness, isTrue);
    expect((await quin.handles.find('@halle.91')).state, HandleLookupState.found);
    expect(fetchesOf(f, w.url), 1);
  });

  test('20. a record co-signed by a key other than the pinned one is no '
      'agreement and no verdict, however it compares', () async {
    // PROTOCOL §19.5: "A witness that cannot be fetched, or whose record
    // does not verify, is no verdict." A record co-signed under another key
    // does not verify against the pinned one, so it is neither agreement
    // nor a fork — as kt_witness_test 4 has it for the transparency log.
    final log = await startLog();
    await claimAt(log, 'sid.20');
    final w = await witnessOf(log);
    final f = _Operator();
    serve(f, w);
    final elsewhere = await pubOf(randomBytes(32));
    final sid = await boot('Sid', config: witnessed(log, w, key: elsewhere), fetcher: f);
    expect((await sid.handles.find('@sid.20')).state, HandleLookupState.found);
    expect(fetchesOf(f, w.url), 1, reason: 'it was asked');
    expect(sid.handles.witnessOkMs, isNull, reason: 'and the answer counted for nothing');
    expect(sid.handles.witnessState, HandleWitnessState.pending);
    // The same record pinned to the key it is signed with does count: the
    // refusal above was the pin, not the record.
    final ted = await boot('Ted', config: witnessed(log, w), fetcher: f);
    expect((await ted.handles.find('@sid.20')).state, HandleLookupState.found);
    expect(ted.handles.witnessState, HandleWitnessState.agreed);

    // A record that, under its own key, shows a fork — a head of the log's
    // size under the log's key over other roots — is still no verdict
    // under another pinned key: an unpinned signer is not evidence.
    final h = await headOf(log);
    final otherSeed = randomBytes(32);
    final other = await signedHead(log,
        size: h.size,
        logRoot: randomBytes(32),
        mapRoot: randomBytes(32),
        ts: DateTime.now().millisecondsSinceEpoch);
    final g = _Operator()
      ..witnessUrl = w.url
      ..witness = () async => KtResponse(200, await recordFor(other, otherSeed));
    final una = await boot('Una', config: witnessed(log, w), fetcher: g);
    expect((await una.handles.find('@sid.20')).state, HandleLookupState.found,
        reason: 'co-signed by a key that is not the one pinned');
    expect(una.handles.witnessState, HandleWitnessState.pending);
    // Pinned to that key, it is the fork it shows.
    final uri = await boot('Uri',
        config: witnessed(log, w, key: await pubOf(otherSeed)), fetcher: g);
    await expectLater(uri.handles.find('@sid.20'), failsWith(HandleFailure.forked));
  });

  test('21. a record a day old is held to consistency, and is not agreement',
      () async {
    final log = await startLog();
    await claimAt(log, 'ursa.21');
    final w = await witnessOf(log);
    final h = await headOf(log);
    final dayOld = DateTime.now().millisecondsSinceEpoch -
        const Duration(hours: 25).inMilliseconds;
    // The log's own roots, signed by its key a day and an hour ago and
    // co-signed then by the pinned witness: a witness that stopped there,
    // or whatever stands in front of it replaying what it saw.
    final stale = await recordFor(
        await signedHead(log,
            size: h.size, logRoot: h.logRoot, mapRoot: h.mapRoot, ts: dayOld),
        w.seed);
    final f = _Operator()
      ..witnessUrl = w.url
      ..witness = () async => KtResponse(200, stale);
    final val = await boot('Val', config: witnessed(log, w), fetcher: f);
    val.handles.witnessReuse = Duration.zero;
    expect((await val.handles.find('@ursa.21')).state, HandleLookupState.found,
        reason: 'consistent with the head, so no fork to refuse');
    expect(val.handles.witnessOkMs, isNull, reason: 'but it agreed with nothing since');
    expect(val.handles.witnessState, HandleWitnessState.pending);
    expect(val.handles.witnessSinceMs, isNotNull);

    // Behind the log's head, held to the proof between them: one entry on,
    // consistent still, and still not agreement.
    await claimAt(log, 'umi.21');
    expect((await val.handles.find('@ursa.21')).state, HandleLookupState.found);
    expect(
        f.urls.any((u) =>
            u.path == '/kt/v1/consistency' &&
            u.query == 'first=${h.size}&second=${h.size + 1}'),
        isTrue);
    expect(val.handles.witnessOkMs, isNull);

    // Still checked: a day-old record at the log's size over other roots is
    // the fork it always was.
    final now = await headOf(log);
    final forkedOld = await recordFor(
        await signedHead(log,
            size: now.size,
            logRoot: randomBytes(32),
            mapRoot: randomBytes(32),
            ts: dayOld),
        w.seed);
    f.witness = () async => KtResponse(200, forkedOld);
    await expectLater(val.handles.find('@ursa.21'), failsWith(HandleFailure.forked));
  });

  test('22. the build pins no handle log and no witness: the four values are '
      'empty together', () {
    expect(
        [
          defaultHandleLogUrl,
          defaultHandleLogPub,
          defaultHandleWitnessUrl,
          defaultHandleWitnessPub
        ],
        everyElement(isEmpty),
        reason: 'pinned together, in one release, with this test changed '
            'beside them (tool/check_ga.py refuses some set and not all)');
    const c = HandleConfig.defaults;
    expect(c.enabled, isFalse);
    expect(c.hasWitness, isFalse);
    expect(c.witnessProblem, isNull, reason: 'empty is not half');
  });

  test('23. a witness off loopback stops a test process asking anything at '
      'all', () async {
    final log = await startLog();
    await claimAt(log, 'oli.23');
    final nowhere = _Nowhere();
    final wes = await boot('Wes',
        config: HandleConfig(
            logUrl: 'http://127.0.0.1:${log.port}', // loopback, as a test's log must be
            logPubB64: b64(log.pub),
            witnessUrl: 'https://handle-witness.example/sth.json',
            witnessPubB64: b64(await pubOf(randomBytes(32)))),
        fetcher: nowhere);
    expect(wes.handles.config.hasWitness, isTrue,
        reason: 'the pair is whole; its address is the problem');
    expect(wes.handles.available, isFalse);
    await expectLater(
        wes.handles.find('@oli.23'), failsWith(HandleFailure.unavailable));
    await expectLater(wes.handles.isAvailable(Handle.parse('oli.24')),
        failsWith(HandleFailure.unavailable));
    expect(wes.handles.witnessState, HandleWitnessState.none);
    expect(nowhere.urls, isEmpty,
        reason: 'a witness on the internet is a stranger this suite must not ask');
  });

  test('24. the record is fetched at most once a lookup, used again for ten '
      'minutes under the same witness, and never without a lookup', () async {
    final log = await startLog();
    await claimAt(log, 'pia.24');
    final w = await witnessOf(log);
    final f = _Operator();
    serve(f, w);
    final pia = await boot('Pia', config: witnessed(log, w), fetcher: f);
    expect(pia.handles.witnessReuse, const Duration(minutes: 10));
    expect(fetchesOf(f, w.url), 0, reason: 'nothing asked before a lookup');
    await pia.handles.find('@pia.24');
    expect(fetchesOf(f, w.url), 1);
    // A run of lookups, a claim's check among them: the one record.
    await pia.handles.find('@pia.24');
    await pia.handles.isAvailable(Handle.parse('pia.25'));
    expect(fetchesOf(f, w.url), 1);
    expect(pia.handles.witnessState, HandleWitnessState.agreed);
    // Ten minutes on, the next lookup fetches again.
    final real = pia.handles.now;
    pia.handles.now = () => real() + const Duration(minutes: 10).inMilliseconds;
    await pia.handles.find('@pia.24');
    expect(fetchesOf(f, w.url), 2);
    // Another witness is asked for itself, whatever the last one said.
    final w2 = await witnessOf(log);
    serve(f, w2);
    await pia.handles.setConfig(witnessed(log, w2));
    await pia.handles.find('@pia.24');
    expect(fetchesOf(f, w2.url), 1);
    // A record that does not verify is not kept: each lookup asks again.
    f.witness = () async => KtResponse(200, '{"sth":7}');
    pia.handles.now = () => real() + const Duration(minutes: 30).inMilliseconds;
    await pia.handles.find('@pia.24');
    await pia.handles.find('@pia.24');
    expect(fetchesOf(f, w2.url), 3);
    // A lookup the log does not answer has no head to check: the witness is
    // not asked.
    final gone = _Operator()..refuse = (_) => true;
    serve(gone, w2);
    final quill = await boot('Quill', config: witnessed(log, w2), fetcher: gone);
    await expectLater(quill.handles.find('@pia.24'), failsWith(HandleFailure.unreachable));
    expect(fetchesOf(gone, w2.url), 0);
  });

  test('25. the witness\'s state is the configuration\'s it was recorded '
      'under: kept across a restart, forgotten when the log or the witness '
      'changes', () async {
    final log = await startLog();
    await claimAt(log, 'rhea.25');
    final w = await witnessOf(log);
    final w2 = await witnessOf(log);
    final f = _Operator();
    serve(f, w);
    // As a build pins them: from the defaults, never saved.
    final rex = await boot('Rex', config: witnessed(log, w), fetcher: f);
    await rex.handles.find('@rhea.25');
    expect(rex.handles.witnessState, HandleWitnessState.agreed);
    final agreedAt = rex.handles.witnessOkMs;
    final vault = rex.vault;
    final id = rex.identity;
    await stop(rex);
    // The same build, started again: kept.
    final again = await boot('Rex', config: witnessed(log, w), fetcher: f, vault: vault, id: id);
    expect(again.handles.witnessOkMs, agreedAt);
    expect(again.handles.witnessState, HandleWitnessState.agreed);
    await stop(again);
    // A build that pins another witness, over a vault that saved no
    // configuration of its own: setConfig never runs, and the last witness's
    // answer is not this one's.
    final rebuilt = await boot('Rex', config: witnessed(log, w2), fetcher: f, vault: vault, id: id);
    expect(rebuilt.handles.witnessOkMs, isNull);
    expect(rebuilt.handles.witnessState, HandleWitnessState.pending);
    expect(await vault.kvGet('handle_witness_ok_ms'), isNull);
    expect(await vault.kvGet('handle_witness_since_ms'), isNull);

    // Saved in Settings: the same witness again keeps its answer; another
    // witness, the witness removed, or another log under the same witness
    // starts again.
    final sue = await boot('Sue', config: log.config, fetcher: f);
    await sue.handles.setConfig(witnessed(log, w));
    await sue.handles.find('@rhea.25');
    expect(sue.handles.witnessState, HandleWitnessState.agreed);
    await sue.handles.setConfig(witnessed(log, w));
    expect(sue.handles.witnessState, HandleWitnessState.agreed);
    await sue.handles.setConfig(witnessed(log, w2));
    expect(sue.handles.witnessState, HandleWitnessState.pending);
    expect(await sue.vault.kvGet('handle_witness_ok_ms'), isNull);
    serve(f, w2);
    await sue.handles.find('@rhea.25');
    expect(sue.handles.witnessState, HandleWitnessState.agreed);
    await sue.handles.setConfig(log.config);
    expect(sue.handles.witnessState, HandleWitnessState.none);
    expect(await sue.vault.kvGet('handle_witness_ok_ms'), isNull);
    await sue.handles.setConfig(witnessed(log, w2));
    await sue.handles.find('@rhea.25');
    expect(sue.handles.witnessState, HandleWitnessState.agreed);
    final elsewhere = await startLog();
    await sue.handles.setConfig(HandleConfig(
        logUrl: 'http://127.0.0.1:${elsewhere.port}',
        logPubB64: b64(elsewhere.pub),
        witnessUrl: w2.url,
        witnessPubB64: b64(w2.pub)));
    expect(sue.handles.witnessOkMs, isNull,
        reason: 'another log under the same witness');
    expect(await sue.vault.kvGet('handle_witness_ok_ms'), isNull);
  });

  test('26. a history that departs after the witness\'s latest co-signed head '
      'passes a first lookup, and the request sent on it is warned of at the '
      'next lookup after the witness moves on; one that never moves on is '
      'said 30 days on, as an answer never confirmed', () async {
    // Until Finnian's decision of 2026-10-20 this criterion pinned the
    // residual as it stood: such a lookup passed as agreement, and nothing
    // was kept for a later lookup to look again. It is turned over on
    // purpose: the head a request is sent on, when the witness's record did
    // not cover it, is kept, and the first record fetched later that covers
    // it is held to it.
    //
    // (b) Two histories under one key, the same up to the witness's head: a
    // claim of @gwen.26 in both, the witness verifying y at that size; then
    // the operator's own app claims @hal.26 in x, and Hal claims it in y.
    final (x1, y1, w1) = await twoHistories('gwen.26');
    final thief = await boot('Thief', config: x1.config);
    await claimIn(thief, 'hal.26');
    final hal = await claimAt(y1, 'hal.26');
    final g = _Operator();
    serve(g, w1);
    final dee = await boot('Dee', config: witnessed(x1, w1), fetcher: g);
    final b = await look(dee, g, '@hal.26');
    expect(b.error, isNull, reason: 'x extends the head the witness co-signed');
    expect(b.found!.introRid, thief.handles.own!.introRid,
        reason: 'the operator\'s mailbox, not Hal\'s');
    expect(b.found!.introRid, isNot(await hal.introRid()));
    expect(dee.handles.witnessState, HandleWitnessState.agreed,
        reason: 'the lookup itself still passes as agreement');
    expect(dee.handles.keptHeads, isEmpty, reason: 'nothing kept until a request');
    // Dee asks, and the operator's app accepts: she holds the operator's
    // account as @hal.26, by an acknowledgement that verifies.
    await dee.handles.request(b.found!);
    final kept = dee.handles.keptHeads.single;
    expect(kept.handle, 'hal.26');
    expect(kept.size, (await headOf(x1)).size,
        reason: 'the head the lookup ended with');
    await receives(thief, dee.myRid);
    await thief.acceptRequest(dee.myRid);
    await linked(dee, thief, 'hal.26');
    expect(await dee.handleViaOf(thief.myRid), 'hal.26');
    expect(dee.handles.keptHeads.single.rid, thief.myRid,
        reason: 'the contact the acceptance added holds the head now');
    expect(dee.handles.forkWarningForContact(thief.myRid), isNull);
    // The witness follows y past that head. Dee's next lookup inside ten
    // minutes uses the record she holds, which covers nothing kept: it
    // passes, and nothing is said.
    await sync(w1, y1);
    expect((await look(dee, g, '@gwen.26')).error, isNull,
        reason: 'the record held for ten minutes is the one from before');
    expect(dee.handles.forkWarnings, isEmpty);
    expect(dee.handles.keptHeads, hasLength(1));
    // Ten minutes on, the record is fetched again. It covers the head kept
    // for her request — the same size under other roots: a history the
    // witness never saw, found after the fact, on the contact that request
    // added. The lookup itself is the fork 15 refuses.
    final real = dee.handles.now;
    dee.handles.now = () => real() + const Duration(minutes: 10).inMilliseconds;
    final later = await look(dee, g, '@gwen.26');
    expect(later.error, forked());
    final warning = dee.handles.forkWarningForContact(thief.myRid);
    expect(warning, isNotNull,
        reason: 'the contact the forked lookup brought, warned of after the fact');
    expect(warning!.handle, 'hal.26');
    expect(warning.lookedUpMs, kept.atMs, reason: 'when she looked it up');
    expect(warning.shown.size, kept.size);
    expect(warning.kind, HandleWarningKind.forked);
    expect(warning.against!.sameRootsAs(await headOf(y1)), isTrue,
        reason: 'the witness\'s co-signed head that contradicts it');
    expect(dee.handles.keptHeads, isEmpty, reason: 'checked, so no longer kept');
    expect(dee.handles.witnessState, HandleWitnessState.forked);

    // (a) What it does not catch as a fork. One log, its owner rule taken out
    // by its operator: the witness verifies it with Fern's claim in it, and
    // the operator then appends an update naming an owner and a mailbox of
    // its own. Carol's lookup passes as agreement, and her request keeps its
    // head.
    final x = await startLog(ruleless: true);
    final fern = await claimAt(x, 'fern.26');
    final w = await witnessOf(x);
    final witnessedSize = KtWitnessRecord.fromJson(
            (jsonDecode(w.record) as Map).cast<String, Object?>())
        .head
        .size;
    final mailbox = await takeOver(x, fern);
    final f = _Operator();
    serve(f, w);
    final carol = await boot('Carol', config: witnessed(x, w), fetcher: f);
    final a = await look(carol, f, '@fern.26');
    expect(a.error, isNull,
        reason: 'the log proves the way from the witness\'s head to its own');
    expect(
        f.urls.any((u) =>
            u.path == '/kt/v1/consistency' &&
            u.query == 'first=$witnessedSize&second=${witnessedSize + 1}'),
        isTrue);
    expect(a.found!.state, HandleLookupState.found);
    expect(a.found!.introRid, mailbox, reason: 'the operator\'s mailbox');
    expect(carol.handles.witnessState, HandleWitnessState.agreed);
    await carol.handles.request(a.found!);
    expect(carol.handles.keptHeads.single.size, witnessedSize + 1);
    // The reference witness, asked to follow the log now, refuses it (exit
    // 2, a divergence): the entry breaks the owner rule. It keeps the head
    // it had, so the record it serves never covers the one Carol's request
    // relied on: fetched again, it covers nothing, and nothing is said yet.
    final r = await Process.run(
        'node',
        [
          'tools/mirror.js',
          '--log',
          'http://127.0.0.1:${x.port}',
          '--pub',
          b64(x.pub),
          '--dir',
          w.dir,
          '--mode',
          'handles',
          '--witness-seed-env',
          'Z_HANDLE_WITNESS_SEED',
        ],
        workingDirectory: '$root/kt',
        environment: {'Z_HANDLE_WITNESS_SEED': hex(w.seed)});
    expect(r.exitCode, 2, reason: '${r.stdout}${r.stderr}');
    final realCarol = carol.handles.now;
    carol.handles.now =
        () => realCarol() + const Duration(minutes: 10).inMilliseconds;
    expect((await look(carol, f, '@fern.26')).error, isNull);
    expect(fetchesOf(f, w.url), 2, reason: 'the record fetched afresh');
    final carolKept = carol.handles.keptHeads.single;
    expect(carolKept.size, witnessedSize + 1,
        reason: 'still waiting for a record that covers it');
    expect(carol.handles.forkWarnings, isEmpty,
        reason: 'nothing to say yet: the head still waits');
    // Thirty days and a minute on, the head lapses never covered. Carol's
    // request still waits — an acceptance would still be matched to it — so
    // the request is told that the answer it was sent on was never confirmed.
    final carolVault = carol.vault;
    final carolId = carol.identity;
    await stop(carol);
    final lapsed = await boot('Carol',
        config: witnessed(x, w),
        fetcher: f,
        vault: carolVault,
        id: carolId,
        now: () => laterBy(const Duration(days: 30, minutes: 1)));
    // The head's last check of its own, as the app starts: the record still
    // stops short of it, so it is undecided, and said.
    await waitUntil(() => lapsed.handles.checksBack == 1,
        what: 'Carol\'s head decided by its last check');
    expect(lapsed.handles.keptHeads, isEmpty);
    final waiting = lapsed.handles.outgoing.single;
    final unconfirmed = lapsed.handles.forkWarningForRequest(waiting);
    // ignore: avoid_print
    print('LOOKUP 26: a second history after the witness\'s head -> '
        '${b.found!.state.name}, agreed, request kept at ${kept.size}; after '
        'the witness moved on -> ${later.error}, warning on the contact '
        '@${warning.handle}; an owner-rule break -> ${a.found!.state.name}, '
        'kept at ${witnessedSize + 1}, the witness stopped at $witnessedSize; '
        '30 days on -> kept ${lapsed.handles.keptHeads.length}, request '
        '@${waiting.handle} warned ${unconfirmed != null}');
    expect(waiting.handle, 'fern.26', reason: 'still waiting');
    expect(lapsed.handles.keptHeads, isEmpty, reason: 'lapsed');
    expect(unconfirmed, isNotNull,
        reason: 'never confirmed, and said so on the request still waiting');
    expect(unconfirmed!.handle, 'fern.26');
    expect(unconfirmed.lookedUpMs, carolKept.atMs);
    expect(unconfirmed.kind, HandleWarningKind.unconfirmed,
        reason: 'not a fork: nothing showed one');
    expect(unconfirmed.against, isNull);
    expect(lapsed.handles.witnessState, HandleWitnessState.unconfirmed);
  });

  test('27. a log that will not prove the way between its head and its '
      'witness\'s fails the lookup, and nothing it returned is kept or sent',
      () async {
    // 15's "behind" case — one key, two histories, the witness a head
    // behind the lookup's — with the operator refusing /kt/v1/consistency.
    final x = await startLog();
    final y = await startLog(key: x.seed);
    await claimAt(y, 'fern.27');
    await claimAt(x, 'fern.27');
    final w = await witnessOf(y);
    await claimAt(x, 'gail.27');
    final f = _Operator();
    serve(f, w);
    final withhold = _Withholding(f);
    final carol =
        await boot('Carol', config: witnessed(x, w), fetcher: withhold);
    final label = await labelOf('fern.27');
    await expectLater(
        carol.handles.find('@fern.27'), failsWith(HandleFailure.unreachable));
    expect(withhold.denied, ['first=1&second=2'],
        reason: 'the proof from the witness\'s head, withheld');
    expect((await memoryOf(carol)).knownFor(label), isNull,
        reason: 'no record remembered');
    expect(carol.handles.outgoing, isEmpty, reason: 'no request kept');
    expect(carol.handles.stampsMade, 0, reason: 'no request made');
    expect(await carol.vault.kvScan('hvia_'), isEmpty);
    expect(carol.handles.witnessOkMs, isNull);
    expect(carol.handles.witnessSinceMs, isNotNull,
        reason: 'asked, without an answer that counts');
    // Something in place of the proof that is not one: a bad answer.
    withhold.garbage = true;
    await expectLater(
        carol.handles.find('@fern.27'), failsWith(HandleFailure.badAnswer));
    // The proof served: the fork it is (15).
    final g = _Operator();
    serve(g, w);
    final dan = await boot('Dan', config: witnessed(x, w), fetcher: g);
    await expectLater(
        dan.handles.find('@fern.27'), failsWith(HandleFailure.forked));

    // The witness ahead: an honest log that grows between the lookup's head
    // and its question to the witness (17), the proof withheld. The log's
    // own head is not below the witness's, so no fork — and no proof, so no
    // pass either.
    final log = await startLog();
    await claimAt(log, 'lena.27');
    final w2 = await witnessOf(log);
    var grown = 0;
    final h = _Operator()
      ..witnessUrl = w2.url
      ..witness = () async {
        await claimAt(log, 'liv.${270 + grown++}');
        await sync(w2, log);
        return KtResponse(200, w2.record);
      };
    final ahead = _Withholding(h);
    final mo = await boot('Mo', config: witnessed(log, w2), fetcher: ahead);
    await expectLater(
        mo.handles.find('@lena.27'), failsWith(HandleFailure.unreachable));
    expect(ahead.denied, hasLength(1));
    expect(h.urls.where((u) => u.path == '/kt/v1/sth'), hasLength(2),
        reason: 'the lookup\'s head, then the log\'s own head beside the '
            'witness\'s');
    // The proof served: the agreement it is (17).
    final mia = await boot('Mia', config: witnessed(log, w2), fetcher: h);
    expect((await mia.handles.find('@lena.27')).state, HandleLookupState.found);
    expect(mia.handles.witnessState, HandleWitnessState.agreed);
    // ignore: avoid_print
    print('LOOKUP 27: the proof withheld behind -> unreachable, a non-proof '
        '-> bad answer, served -> forked; withheld ahead -> unreachable, '
        'served -> agreed');
  });

  test('28. a fork is kept until the witness agrees again, whichever path met '
      'it: a drain\'s read, and a claim\'s read-back, which holds the claim '
      'rather than calling it taken', () async {
    // x is what the log shows; y, under the same key, what the witness saw.
    final x = await startLog();
    final y = await startLog(key: x.seed);
    await claimAt(y, 'yuri.28');
    final w = await witnessOf(y);
    final f = _Operator();
    serve(f, w);

    // Ada claims ada.28 in x with the witness configured. Her claim is a
    // publish and takes no head; the drain it begins reads her record
    // first, and that read is refused — the drain goes on, as it does when
    // the log cannot be asked, but the fork is kept, sealed, with the
    // configuration it answers. (A drain counts itself when it ends, after
    // its read: one drain, waited for whole.)
    final ada = await boot('Ada', config: witnessed(x, w), fetcher: f);
    final before = DateTime.now().millisecondsSinceEpoch;
    final draft =
        await ada.handles.prepareClaim(Handle.parse('ada.28'), pow: 16);
    await ada.handles.commitClaim(draft);
    await waitUntil(() => ada.handles.own?.phase == HandlePhase.live,
        what: 'ada.28 published');
    await waitUntil(() => ada.handles.drains >= 1,
        what: 'the drain the publish began, gone on past its refused read');
    expect(ada.handles.own!.phase, HandlePhase.live);
    expect(ada.handles.witnessState, HandleWitnessState.forked);
    expect(ada.handles.witnessForkMs, greaterThanOrEqualTo(before));
    final rows = await ada.vault.db.query('kv',
        columns: ['k'],
        where: 'k LIKE ?',
        whereArgs: ['%:handle_witness_fork_ms']);
    expect(rows.map((r) => r['k']), ['s:handle_witness_fork_ms'],
        reason: 'sealed');
    final stored =
        (jsonDecode((await ada.vault.kvGet('handle_witness_fork_ms'))!) as Map)
            .cast<String, Object?>();
    expect(stored['at'], ada.handles.witnessForkMs);
    expect(stored['w'], contains(b64(w.pub)));
    // Kept across a restart: read back from the vault, not met again — the
    // restarted app's witness answers nothing, so its own drain's read is no
    // verdict and cannot record a fork of its own.
    final vault = ada.vault;
    final id = ada.identity;
    final forkAt = ada.handles.witnessForkMs;
    await stop(ada);
    final silent = _Operator()
      ..witnessUrl = w.url
      ..witness = () async => KtResponse(503, '{}');
    final again = await boot('Ada',
        config: witnessed(x, w), fetcher: silent, vault: vault, id: id);
    expect(again.handles.witnessForkMs, forkAt);
    expect(again.handles.witnessState, HandleWitnessState.forked);

    // Bea claims a name somebody claimed in x first. The log refuses her
    // claim as taken, and the read-back that would say whose it is meets
    // the fork: the claim is held, with the fork as its problem — not taken.
    await claimAt(x, 'bea.28');
    final bea = await boot('Bea', config: witnessed(x, w), fetcher: f);
    final d2 = await bea.handles.prepareClaim(Handle.parse('bea.28'), pow: 16);
    await bea.handles.commitClaim(d2);
    await waitUntil(() => bea.handles.own?.phase == HandlePhase.held,
        what: 'the claim held, not taken');
    expect(bea.handles.own!.problem, HandleFailure.forked.name);
    expect(bea.handles.witnessState, HandleWitnessState.forked);

    // The witness agreeing again — its key co-signing x's head now, a
    // witness that has followed x — ends the fork. (Bea, whose claim is
    // held, has no drain of her own to race this; the record she holds from
    // the read-back is not used again.)
    bea.handles.witnessReuse = Duration.zero;
    f.witness =
        () async => KtResponse(200, await recordFor(await headOf(x), w.seed));
    expect((await bea.handles.find('@bea.28')).state, HandleLookupState.found);
    expect(bea.handles.witnessState, HandleWitnessState.agreed);
    expect(bea.handles.witnessForkMs, isNull);
    expect(await bea.vault.kvGet('handle_witness_fork_ms'), isNull);

    // Another witness forgets it, as it forgets the rest (25); a drain of
    // Ada's still asking the last one cannot put it back.
    final w2 = await witnessOf(x);
    await again.handles.setConfig(witnessed(x, w2));
    expect(again.handles.witnessForkMs, isNull);
    expect(await again.vault.kvGet('handle_witness_fork_ms'), isNull);
    expect(again.handles.witnessState, isNot(HandleWitnessState.forked));
  });

  // ---- After the fact (Finnian's decision of 2026-10-20) --------------------

  test('29. a kept head goes once a covering record agrees, at its size or '
      'ahead of it with the log\'s proof; only a request keeps one, and every '
      'way a record is fetched checks them, the owner\'s drain read among them',
      () async {
    final log = await startLog();
    await claimAt(log, 'lena.29');
    final w = await witnessOf(log);
    final f = _Operator();
    serve(f, w);
    // Dee holds a handle of her own, so her drains read her record, and she
    // fetches the witness's record afresh at every question. Her claim puts
    // the log a head past the witness.
    final dee = await boot('Dee', config: witnessed(log, w), fetcher: f);
    dee.handles.witnessReuse = Duration.zero;
    await claimIn(dee, 'dee.29');
    expect(dee.handles.keptHeads, isEmpty,
        reason: 'the owner\'s reads of its own record keep nothing');
    // Eve, who holds no handle: a lookup that sends nothing, a claim's check
    // and a recovery's read keep nothing either.
    final eve = await boot('Eve', config: witnessed(log, w), fetcher: f);
    expect((await eve.handles.find('@lena.29')).state, HandleLookupState.found);
    expect(await eve.handles.isAvailable(Handle.parse('free.29')), isTrue);
    final wrong = await formatHandleRecoveryCode(await RecoveryCode.generate());
    await expectLater(eve.handles.prepareRecover('lena.29', wrong),
        failsWith(HandleFailure.wrongCode));
    expect(eve.handles.keptHeads, isEmpty);
    // Dee's lookup, past the record: nothing kept until she sends on it.
    final found = await dee.handles.find('@lena.29');
    expect(dee.handles.keptHeads, isEmpty, reason: 'nothing until a request');
    await dee.handles.request(found);
    final k1 = dee.handles.keptHeads.single;
    expect(k1.handle, 'lena.29');
    expect(k1.size, (await headOf(log)).size);
    expect(k1.rid, isNull);

    // At its size: the witness follows the log to exactly that head, and the
    // next record fetched — by Dee's drain, reading her own record — covers
    // it with the same roots. It goes, and the witness agrees.
    await sync(w, log);
    expect(
        KtWitnessRecord.fromJson(
                (jsonDecode(w.record) as Map).cast<String, Object?>())
            .head
            .size,
        k1.size);
    await waitUntil(() async {
      await dee.handles.drain();
      return dee.handles.keptHeads.isEmpty;
    }, what: 'the drain\'s record covering the kept head');
    expect(dee.handles.forkWarnings, isEmpty);
    expect(dee.handles.witnessState, HandleWitnessState.agreed);

    // Ahead of it: a second request kept at the log's size, the log grows,
    // the witness follows past it, and a claim's check — a record fetched
    // for another reason — covers it with the log's proof from the kept size.
    await claimAt(log, 'liv.29');
    await dee.handles.request(await dee.handles.find('@lena.29'));
    final k2 = dee.handles.keptHeads.single;
    expect(k2.size, k1.size + 1);
    await claimAt(log, 'lou.29');
    await sync(w, log);
    final from = f.urls.length;
    expect(await dee.handles.isAvailable(Handle.parse('free.29')), isTrue);
    expect(dee.handles.keptHeads, isEmpty);
    expect(
        f.urls.skip(from).any((u) =>
            u.path == '/kt/v1/consistency' &&
            u.query == 'first=${k2.size}&second=${k2.size + 1}'),
        isTrue,
        reason: 'the log proved the way from the kept head to the record\'s');
    expect(dee.handles.forkWarnings, isEmpty);
    expect(dee.handles.witnessState, HandleWitnessState.agreed);

    // A head the record already covers is not kept; with no witness nothing
    // is, and nothing is stored.
    final fay = await boot('Fay', config: witnessed(log, w), fetcher: f);
    await fay.handles.request(await fay.handles.find('@lena.29'));
    expect(fay.handles.outgoing, hasLength(1));
    expect(fay.handles.keptHeads, isEmpty, reason: 'the record covers its head');
    final gus = await boot('Gus', config: log.config);
    await gus.handles.request(await gus.handles.find('@lena.29'));
    expect(gus.handles.keptHeads, isEmpty);
    expect(await gus.vault.kvGet('handle_witness_heads'), isNull);
    // ignore: avoid_print
    print('LOOKUP 29: kept at ${k1.size}, covered at its size by the drain; '
        'kept at ${k2.size}, covered at ${k2.size + 1} with the proof by a '
        'claim\'s check; nothing kept without a request, a witness or an '
        'uncovered head');
  });

  test('30. a fork found after the fact marks exactly what relied on its head: '
      'the contact a forked request brought and a request still waiting on '
      'it, and nothing else — not a head the fork departs after', () async {
    final (x, y, w) = await twoHistories('gwen.30');
    final f = _Operator();
    serve(f, w);
    final sw = _Switch(f, x.port, y.port);
    final dee = await boot('Dee', config: witnessed(x, w), fetcher: sw);
    dee.handles.witnessReuse = Duration.zero;
    // Olga, added by her code: a contact no handle lookup brought.
    final olga = await boot('Olga', config: HandleConfig.off);
    await dee.addContactFromCode(await olga.myContactCode());
    expect(dee.contacts.containsKey(olga.myRid), isTrue);
    // A request the record covered when it was sent (both at the shared
    // head): nothing kept for it.
    await dee.handles.request(await dee.handles.find('@gwen.30'));
    expect(dee.handles.keptHeads, isEmpty);
    // A request kept while the histories are still one, whose head the
    // witness covers before they part: it goes, same roots.
    await claimInEach([y, x], 'nils.30');
    await dee.handles.request(await dee.handles.find('@nils.30'));
    expect(dee.handles.keptHeads.single.handle, 'nils.30');
    await sync(w, y);
    expect((await dee.handles.find('@gwen.30')).state, HandleLookupState.found);
    expect(dee.handles.keptHeads, isEmpty, reason: 'covered at its size');
    // A request kept on a head the two histories still share, which the
    // witness has not reached when they part: the fork departs after it.
    await claimInEach([y, x], 'otto.30');
    await dee.handles.request(await dee.handles.find('@otto.30'));
    expect(dee.handles.keptHeads.single.handle, 'otto.30');
    // The histories part: the operator's app claims @hal.30 in x, Hal in y;
    // and @ivo.30 is in x alone. Dee asks both, past the witness's head.
    final thief = await boot('Thief', config: x.config);
    await claimIn(thief, 'hal.30');
    await claimAt(y, 'hal.30');
    final halFound = await dee.handles.find('@hal.30');
    expect(halFound.introRid, thief.handles.own!.introRid);
    await dee.handles.request(halFound);
    await claimAt(x, 'ivo.30');
    await dee.handles.request(await dee.handles.find('@ivo.30'));
    expect(dee.handles.keptHeads.map((k) => k.handle),
        ['otto.30', 'hal.30', 'ivo.30']);
    // The operator's app accepts the request to @hal.30: the contact holds
    // its head.
    await receives(thief, dee.myRid);
    await thief.acceptRequest(dee.myRid);
    await linked(dee, thief, 'hal.30');
    // The witness follows y past all three heads. Dee, still shown x, is
    // refused as forked (15). Of what she kept, @ivo.30's head is at the
    // record's size under other roots: the fork, on the request still
    // waiting. @otto.30's and @hal.30's are below the record, on the history
    // the lookup was shown, and the log proves neither to the record — as it
    // could not for a head the fork departs after, which @otto.30's is — so
    // neither is called a fork from here; each is said at once, on what
    // relied on it, as an answer never confirmed, which is true.
    await claimAt(y, 'pia.30');
    await sync(w, y);
    await expectLater(dee.handles.find('@gwen.30'), failsWith(HandleFailure.forked));
    final byHandle = {for (final o in dee.handles.outgoing) o.handle: o};
    expect(byHandle.keys.toSet(), {'gwen.30', 'nils.30', 'otto.30', 'ivo.30'},
        reason: 'the request to @hal.30 was answered');
    final ottoTold = dee.handles.forkWarningForRequest(byHandle['otto.30']!);
    expect(ottoTold?.kind, HandleWarningKind.unconfirmed,
        reason: 'the fork departs after its head: never confirmed, no fork');
    final halTold = dee.handles.forkWarningForContact(thief.myRid);
    expect(halTold?.kind, HandleWarningKind.unconfirmed,
        reason: 'not decided from the history that forked');
    final ivoWarning = dee.handles.forkWarningForRequest(byHandle['ivo.30']!);
    expect(ivoWarning?.handle, 'ivo.30');
    expect(idsOf(ivoWarning!.creqIds), idsOf(byHandle['ivo.30']!.creqIds));
    expect(ivoWarning.rid, isNull);
    expect(ivoWarning.kind, HandleWarningKind.forked);
    expect(dee.handles.keptHeads.map((k) => k.handle), ['otto.30', 'hal.30'],
        reason: 'their checks pending');
    // The operator shows Dee y from now on, at the same address and under
    // the same key. The head she is shown is held to each one kept: the log
    // proves @otto.30's to it, so the record covers it and it goes, and so
    // does the warning said of it; it cannot prove @hal.30's — two
    // histories, the kept head not the witness's — and the fork's warning
    // takes the place of the one on the contact that request brought.
    sw.on = true;
    expect((await dee.handles.find('@gwen.30')).state, HandleLookupState.found);
    expect(dee.handles.keptHeads, isEmpty);
    expect(dee.handles.forkWarnings.map((x) => x.handle).toSet(),
        {'hal.30', 'ivo.30'});
    expect(dee.handles.forkWarnings, hasLength(2),
        reason: '@otto.30\'s gone, @hal.30\'s replaced');
    // The contact the forked request brought; the request still waiting on
    // a forked head; and nothing else.
    final halWarning = dee.handles.forkWarningForContact(thief.myRid);
    expect(halWarning?.handle, 'hal.30');
    expect(halWarning!.kind, HandleWarningKind.forked);
    expect(halWarning.against!.sameRootsAs(await headOf(y)), isTrue,
        reason: 'the head the log showed next, which does not extend it');
    expect(dee.handles.forkWarningForContact(olga.myRid), isNull,
        reason: 'a contact added by code');
    expect(dee.handles.forkWarningForRequest(byHandle['gwen.30']!), isNull,
        reason: 'its head was covered when it was sent');
    expect(dee.handles.forkWarningForRequest(byHandle['nils.30']!), isNull,
        reason: 'its head was covered before the histories parted');
    expect(dee.handles.forkWarningForRequest(byHandle['otto.30']!), isNull,
        reason: 'the fork departs after its head, which the witness covers');
    expect(dee.handles.witnessState, HandleWitnessState.forked);
    // Sealed, as nothing in Vault.plainKeys is.
    final rows = await dee.vault.db.query('kv',
        columns: ['k'], where: 'k LIKE ?', whereArgs: ['%:handle_witness_warnings']);
    expect(rows.map((r) => r['k']), ['s:handle_witness_warnings']);
    // ignore: avoid_print
    print('LOOKUP 30: after the fact -> the waiting request @ivo.30 warned on '
        'the forked history; shown it, @otto.30 and the contact @hal.30 told '
        '${ottoTold?.kind.name} and ${halTold?.kind.name}; shown the witness\'s, '
        'the contact @hal.30 ${dee.handles.forkWarningForContact(thief.myRid)!.kind.name}, '
        '@otto.30 covered and nothing on it; none on @gwen.30, @nils.30 or '
        'Olga');
  });

  test('31. a proof the log withholds keeps the check pending: the head kept, '
      'nothing warned of, not the witness agreeing; served, it ends the check',
      () async {
    final log = await startLog();
    await claimAt(log, 'lena.31');
    final w = await witnessOf(log);
    await claimAt(log, 'liv.31');
    final f = _Operator();
    serve(f, w);
    final withhold = _Withholding(f)..withholding = false;
    final dee = await boot('Dee', config: witnessed(log, w), fetcher: withhold);
    dee.handles.witnessReuse = Duration.zero;
    // Quiet as soon as two checks a moment apart end without agreement.
    dee.handles.witnessQuietAfter = const Duration(milliseconds: 1);
    await dee.handles.request(await dee.handles.find('@lena.31'));
    final kept = dee.handles.keptHeads.single;
    final agreedAt = dee.handles.witnessOkMs;
    expect(agreedAt, isNotNull);
    // The log grows and the witness follows it past the kept head. The log
    // now withholds the proof from the kept size — or serves something that
    // is not one. The lookup's own head is the record's, which needs none.
    await claimAt(log, 'lou.31');
    await sync(w, log);
    withhold.withholding = true;
    for (final garbage in [false, true]) {
      withhold.garbage = garbage;
      final l = await dee.handles.find('@lena.31');
      expect(l.state, HandleLookupState.found, reason: 'the lookup goes on');
      expect(withhold.denied.last, 'first=${kept.size}&second=${kept.size + 1}');
      expect(dee.handles.keptHeads.single.size, kept.size,
          reason: 'pending, so still kept (garbage: $garbage)');
      expect(dee.handles.forkWarnings, isEmpty);
      expect(dee.handles.witnessOkMs, agreedAt,
          reason: 'not the witness agreeing (garbage: $garbage)');
      expect(dee.handles.witnessSinceMs, isNotNull);
    }
    expect(dee.handles.witnessState, HandleWitnessState.quiet,
        reason: 'asked without an answer that counts');
    // Served: consistent, so covered; the head goes and the witness agrees.
    withhold.withholding = false;
    expect((await dee.handles.find('@lena.31')).state, HandleLookupState.found);
    expect(dee.handles.keptHeads, isEmpty);
    expect(dee.handles.witnessState, HandleWitnessState.agreed);
    expect(dee.handles.witnessOkMs, greaterThan(agreedAt!));

    // On a forked head: withheld, nothing passes and nothing is said — shown
    // the history that forked, the lookup's own head is the fork 15 refuses;
    // shown the witness's, it goes on and is not the witness agreeing — and
    // served, the fork: the log cannot prove the head it now shows extends
    // the one kept.
    final (x, y, wy) = await twoHistories('gwen.31');
    await claimAt(x, 'hal.31');
    final g = _Operator();
    serve(g, wy);
    final hold = _Withholding(g)..withholding = false;
    final sw = _Switch(hold, x.port, y.port);
    final eve = await boot('Eve', config: witnessed(x, wy), fetcher: sw);
    eve.handles.witnessReuse = Duration.zero;
    await eve.handles.request(await eve.handles.find('@hal.31'));
    expect(eve.handles.keptHeads, hasLength(1));
    // Both histories grow a head past the kept one, and the witness follows
    // y: covering the kept head takes the log's proof from it.
    await claimAt(x, 'ivy.31');
    await claimAt(y, 'hal.31');
    await claimAt(y, 'ida.31');
    await sync(wy, y);
    hold.withholding = true;
    await expectLater(
        eve.handles.find('@gwen.31'), failsWith(HandleFailure.forked));
    expect(hold.denied, ['first=2&second=3'],
        reason: 'the kept head\'s proof, withheld; the lookup\'s own head is '
            'the record\'s size, and needs none');
    expect(eve.handles.keptHeads, hasLength(1), reason: 'pending');
    expect(eve.handles.forkWarnings, isEmpty);
    sw.on = true;
    final eveOk = eve.handles.witnessOkMs;
    expect((await eve.handles.find('@gwen.31')).state, HandleLookupState.found);
    expect(hold.denied, ['first=2&second=3', 'first=2&second=3']);
    expect(eve.handles.keptHeads, hasLength(1), reason: 'pending');
    expect(eve.handles.forkWarnings, isEmpty);
    expect(eve.handles.witnessOkMs, eveOk, reason: 'not the witness agreeing');
    hold.withholding = false;
    expect((await eve.handles.find('@gwen.31')).state, HandleLookupState.found);
    expect(eve.handles.forkWarnings.single.handle, 'hal.31');
    expect(eve.handles.keptHeads, isEmpty);

    // A record used again for ten minutes — the default — while a kept
    // head's proof is withheld: the check stays pending across it, asked
    // again at most once in ten minutes, and neither the agreement nor the
    // quiet timer moves (the review's PROBE C).
    final log3 = await startLog();
    await claimAt(log3, 'mila.31');
    final w3 = await witnessOf(log3);
    await claimAt(log3, 'max.31');
    final h3 = _Operator();
    serve(h3, w3);
    final first = _WithholdFirst(h3);
    final fay = await boot('Fay', config: witnessed(log3, w3), fetcher: first);
    expect(fay.handles.witnessReuse, const Duration(minutes: 10));
    fay.handles.witnessQuietAfter = const Duration(milliseconds: 1);
    await fay.handles.request(await fay.handles.find('@mila.31'));
    final k3 = fay.handles.keptHeads.single;
    await claimAt(log3, 'moe.31');
    await sync(w3, log3);
    first.first = k3.size;
    final real = fay.handles.now;
    var shift = 0;
    fay.handles.now = () => real() + shift;
    // Two fresh records, ten minutes apart, the kept head's proof withheld
    // at each: the witness is quiet.
    for (var i = 1; i <= 2; i++) {
      shift = Duration(minutes: 10 * i).inMilliseconds;
      expect((await fay.handles.find('@mila.31')).state, HandleLookupState.found);
    }
    expect(first.denied, hasLength(2));
    expect(fay.handles.witnessState, HandleWitnessState.quiet);
    final okBefore = fay.handles.witnessOkMs;
    final sinceBefore = fay.handles.witnessSinceMs;
    final lastBefore = fay.handles.witnessLastAskMs;
    // A minute later, a lookup on the record held for ten minutes.
    shift += const Duration(minutes: 1).inMilliseconds;
    expect((await fay.handles.find('@max.31')).state, HandleLookupState.found);
    // ignore: avoid_print
    print('LOOKUP 31 (reuse): withheld ${first.denied}; after a lookup on the '
        'record held: ${fay.handles.witnessState}, agreement moved '
        '${fay.handles.witnessOkMs != okBefore}, quiet since moved '
        '${fay.handles.witnessSinceMs != sinceBefore}, kept '
        '${fay.handles.keptHeads.length}');
    expect(fay.handles.witnessState, HandleWitnessState.quiet,
        reason: 'a record used again is not the witness agreeing while a '
            'check is pending');
    expect(fay.handles.witnessOkMs, okBefore);
    expect(fay.handles.witnessSinceMs, sinceBefore);
    expect(fay.handles.witnessLastAskMs, lastBefore,
        reason: 'nor is it the witness asked again');
    expect(first.denied, hasLength(2),
        reason: 'the proof asked again at most once in ten minutes');
    expect(fay.handles.keptHeads.single.size, k3.size, reason: 'still pending');
    // ignore: avoid_print
    print('LOOKUP 31: withheld and garbage -> pending, quiet; served -> '
        'covered and agreed; on a forked head withheld -> nothing said, '
        'served -> the warning; a record used again -> still pending');
  });

  test('32. the bound: at most 20 heads that contacts hold, the one looked up '
      'longest ago going first, and a head no contact holds bounded by the '
      'outgoing list, not by them; each for at most 30 days; and a head the '
      'bound or the lapse puts out of reach before the witness covered it is '
      'said on what relied on it', () async {
    final log = await startLog();
    await claimAt(log, 'lena.32');
    final w = await witnessOf(log);
    await claimAt(log, 'liv.32');
    final f = _Operator();
    serve(f, w);
    final dee = await boot('Dee', config: witnessed(log, w), fetcher: f);
    expect(dee.handles.witnessKeptCap, 20);
    expect(handleWitnessKeptCap, handleOutgoingCap);
    expect(dee.handles.witnessKeepFor, const Duration(days: 30));
    // Twenty-five requests, each answered as an acceptance answers one — the
    // contact takes the head, the request goes. Twenty heads held by
    // contacts fill the bound; each later one, once its acceptance makes it
    // a contact's, pushes out the one looked up longest ago, and the contact
    // that one is on is told.
    for (var i = 0; i < 25; i++) {
      await dee.handles.request(await dee.handles.find('@lena.32'));
      final o = dee.handles.outgoing.single;
      await dee.handles.contactAddedThrough('contact-$i', o);
      await dee.handles.completeOutgoing(o);
    }
    final held = [for (final k in dee.handles.keptHeads) k.rid];
    final stored =
        (jsonDecode((await dee.vault.kvGet('handle_witness_heads'))!) as Map)
            ['heads'] as List;
    final told = {for (final x in dee.handles.forkWarnings) x.rid};
    final toldKinds = {for (final x in dee.handles.forkWarnings) x.kind};
    // And a request still waiting: bounded by the outgoing list, not by the
    // heads contacts hold, so kept, and nothing said.
    await dee.handles.request(await dee.handles.find('@liv.32'));
    final heldAfter = [for (final k in dee.handles.keptHeads) k.rid];
    final liv = dee.handles.outgoing.single;
    final livTold = dee.handles.forkWarningForRequest(liv);

    // Thirty days at most, covered or not: two requests still waiting, their
    // heads kept across a restart 29 days on; at one 30 days and a minute on
    // they have lapsed, and each request — still waiting, so an acceptance
    // would still be matched to it — is told.
    final eve = await boot('Eve', config: witnessed(log, w), fetcher: f);
    for (final h in ['lena.32', 'liv.32']) {
      await eve.handles.request(await eve.handles.find('@$h'));
    }
    final eveKept = eve.handles.keptHeads.length;
    final vault = eve.vault;
    final id = eve.identity;
    await stop(eve);
    final soon = await boot('Eve',
        config: witnessed(log, w),
        fetcher: f,
        vault: vault,
        id: id,
        now: () => laterBy(const Duration(days: 29)));
    // Their check-back, as the app starts: the witness has not moved, so
    // they stay kept.
    await waitUntil(() => soon.handles.checksBack == 1,
        what: 'the check-back 29 days on');
    final soonKept = soon.handles.keptHeads.length;
    final soonTold = soon.handles.forkWarnings.length;
    await stop(soon);
    final lapsed = await boot('Eve',
        config: witnessed(log, w),
        fetcher: f,
        vault: vault,
        id: id,
        now: () => laterBy(const Duration(days: 30, minutes: 1)));
    await waitUntil(() => lapsed.handles.checksBack == 1,
        what: 'the last check 30 days on');
    final lapsedTold = {
      for (final o in lapsed.handles.outgoing)
        if (lapsed.handles.forkWarningForRequest(o) != null) o.handle
    };
    // ignore: avoid_print
    print('LOOKUP 32: 25 answered -> kept $held, told $told; a waiting '
        'request -> kept ${heldAfter.length}, told ${livTold != null}; 29 days -> kept '
        '$soonKept, told $soonTold; 30 days and a minute -> kept '
        '${lapsed.handles.keptHeads.length}, waiting '
        '${lapsed.handles.outgoing.length}, told $lapsedTold');
    expect(held, [for (var i = 5; i < 25; i++) 'contact-$i'],
        reason: 'the one looked up longest ago went first');
    expect(stored, hasLength(20), reason: 'and so in the vault');
    expect(told, {for (var i = 0; i < 5; i++) 'contact-$i'},
        reason: 'pushed out before the witness covered them: said');
    expect(toldKinds, {HandleWarningKind.unconfirmed});
    expect(heldAfter, [...held, null],
        reason: 'a head no contact holds is bounded by the outgoing list');
    expect(livTold, isNull, reason: 'a request still waiting, its head kept');
    expect(eveKept, 2);
    expect(soonKept, 2);
    expect(soonTold, 0);
    expect(lapsed.handles.keptHeads, isEmpty);
    expect(lapsed.handles.outgoing, hasLength(2), reason: 'the requests still wait');
    expect(lapsedTold, {'lena.32', 'liv.32'});
    expect({for (final x in lapsed.handles.forkWarnings) x.kind},
        {HandleWarningKind.unconfirmed});
    expect(lapsed.handles.witnessState, HandleWitnessState.unconfirmed);
    expect(await vault.kvGet('handle_witness_heads'), isNull);
  });

  /// [name] on a device holding two histories' fork after the fact: a
  /// request to @[waiting] on a head the two histories share, and one to
  /// @[warned] on x's next head, the fork. The witness of y then covers both:
  /// the second at its size under other roots — found by the lookup that
  /// holds its record — and the first below it, which a device shown x
  /// cannot decide (30), so its head stays kept, its check pending, and the
  /// request is told at once that its answer was never confirmed (42).
  Future<({ChatService s, _Operator f, _Log x, _Log y, _Witness w})>
      warnedAndWaiting(String name, String shared, String warned,
          String waiting) async {
    final (x, y, w) = await twoHistories(shared);
    await claimInEach([y, x], waiting);
    final f = _Operator();
    serve(f, w);
    final s = await boot(name, config: witnessed(x, w), fetcher: f);
    s.handles.witnessReuse = Duration.zero;
    await s.handles.request(await s.handles.find('@$waiting'));
    await claimAt(x, warned);
    await s.handles.request(await s.handles.find('@$warned'));
    expect(s.handles.keptHeads.map((k) => k.handle), [waiting, warned]);
    await claimAt(y, warned);
    await sync(w, y);
    await expectLater(s.handles.find('@$shared'), failsWith(HandleFailure.forked));
    expect(s.handles.forkWarnings.where((x) => x.isFork).single.handle, warned);
    expect(s.handles.keptHeads.single.handle, waiting);
    expect(s.handles.forkWarnings.where((x) => !x.isFork).single.handle, waiting);
    return (s: s, f: f, x: x, y: y, w: w);
  }

  test('33. a restart keeps the kept heads and the warnings, sealed, and a '
      'backup carries them with the requests they are on', () async {
    final (:s, :f, :x, y: _, :w) =
        await warnedAndWaiting('Dee', 'gwen.33', 'hal.33', 'ivo.33');
    final kept = s.handles.keptHeads.single;
    final warning = s.handles.forkWarnings.firstWhere((x) => x.isFork);
    final told = s.handles.forkWarnings.firstWhere((x) => !x.isFork);
    for (final key in ['handle_witness_heads', 'handle_witness_warnings']) {
      final rows = await s.vault.db.query('kv',
          columns: ['k'], where: 'k LIKE ?', whereArgs: ['%:$key']);
      expect(rows.map((r) => r['k']), ['s:$key'], reason: 'sealed');
    }
    // A restart: both read back as they were.
    final vault = s.vault;
    final id = s.identity;
    await stop(s);
    final again =
        await boot('Dee', config: witnessed(x, w), fetcher: f, vault: vault, id: id);
    expect(again.handles.keptHeads.single, kept);
    expect(again.handles.forkWarnings, hasLength(2));
    final t2 = again.handles.forkWarnings.firstWhere((x) => !x.isFork);
    expect(t2.handle, told.handle);
    expect(t2.foundMs, told.foundMs);
    expect(t2.atFork, isTrue, reason: 'said at the fork, while its head is kept');
    final w2 = again.handles.forkWarnings.firstWhere((x) => x.isFork);
    expect(w2.handle, warning.handle);
    expect(w2.lookedUpMs, warning.lookedUpMs);
    expect(w2.foundMs, warning.foundMs);
    expect(idsOf(w2.creqIds), idsOf(warning.creqIds));
    expect(w2.kind, warning.kind);
    expect(w2.shown.sameRootsAs(warning.shown), isTrue);
    expect(w2.against!.sameRootsAs(warning.against!), isTrue);
    final hal = again.handles.outgoing.firstWhere((o) => o.handle == 'hal.33');
    expect(again.handles.forkWarningForRequest(hal)?.handle, 'hal.33');
    expect(again.handles.witnessState, HandleWitnessState.forked);

    // A backup, restored on a fresh vault: the requests come back, and with
    // them the head kept for one and the warning on the other. A warning on a
    // contact the archive does not hold — deleted while a build that kept it
    // was not running — comes back too, for the first start to drop.
    final onDisk = jsonDecode(
        (await again.vault.kvGet('handle_witness_warnings'))!) as List;
    await again.vault.kvPut(
        'handle_witness_warnings',
        jsonEncode([
          ...onDisk,
          {
            ...(onDisk.firstWhere((m) => (m as Map)['k'] == 'forked') as Map),
            'ids': [b64(Uint8List(32)..fillRange(0, 32, 9))],
            'rid': 'no-such-contact',
          },
        ]));
    final code = await RecoveryCode.generate();
    final file = File(p.join(
        (await Directory.systemTemp.createTemp('z_hlookup_zbk')).path, 'b.zbk'));
    temps.add(file.parent);
    final sink = file.openWrite();
    await BackupArchive.export(vault: again.vault, code: code, out: sink);
    await sink.close();
    final dir = again.vault.root;
    await stop(again);
    await again.vault.db.close();
    dir.deleteSync(recursive: true);
    dir.createSync(recursive: true);
    final restored = await Vault.open(rootOverride: dir);
    await Restore.run(
        vault: restored,
        file: file,
        secret: await code.format(),
        kind: (await Restore.identify(file)).kind,
        serverUrl: 'ws://127.0.0.1:$relayPort');
    final id2 = await ZIdentity.fromJson(
        (jsonDecode((await restored.kvGet('identity'))!) as Map)
            .cast<String, Object?>());
    expect(await restored.kvGet('handle_witness_warnings'),
        contains('no-such-contact'),
        reason: 'carried by the archive, as one on a contact is');
    final back = await boot('Dee',
        config: witnessed(x, w), fetcher: f, vault: restored, id: id2);
    expect(back.handles.outgoing.map((o) => o.handle).toSet(),
        {'hal.33', 'ivo.33'});
    expect(back.handles.keptHeads.single, kept);
    expect(back.handles.forkWarnings.map((x) => x.handle).toList()..sort(),
        ['hal.33', 'ivo.33'],
        reason: 'the one on a contact that did not come back is gone');
    expect(await restored.kvGet('handle_witness_warnings'),
        isNot(contains('no-such-contact')));
    expect(
        back.handles.forkWarningForRequest(
            back.handles.outgoing.firstWhere((o) => o.handle == 'hal.33')),
        isNotNull);

    // What a restore leaves out: a head or a warning on a request the
    // archive does not hold, and one that is not their shape. One on a
    // contact comes back, for the first start to hold to the contacts.
    final head = (await headOf(x)).toJson();
    final held = b64(Uint8List(32)..fillRange(0, 32, 1));
    final gone = b64(Uint8List(32)..fillRange(0, 32, 2));
    final small = KtTreeHead(
            size: 1,
            logRoot: Uint8List(32),
            mapRoot: Uint8List(32),
            ts: 1,
            sig: Uint8List(64))
        .toJson();
    Map<String, Object?> warningOn(String id, {String? rid, int found = 2}) => {
          'k': 'forked',
          'h': 'hal.33',
          'at': 1,
          'found': found,
          'ids': [id],
          if (rid != null) 'rid': rid,
          'sth': head,
          'against': head,
        };
    final out = HandleBackup.restore({
      'kv': {
        'handle_out': [
          {
            'h': 'hal.33',
            'owner': b64(Uint8List(32)),
            'intro': b64(Uint8List(32)),
            'xintro': b64(Uint8List(32)),
            'ids': [held],
            'at': 5,
          },
        ],
        'handle_witness_heads': {
          'w': 'the witness',
          'heads': [
            {
              'sth': head,
              'at': 1,
              'h': 'hal.33',
              'ids': [held],
              'ext': head,
              'held': 9,
            },
            {'sth': head, 'at': 2, 'h': 'hal.33', 'ids': [gone]},
            {'sth': 7, 'at': 3, 'h': 'hal.33', 'ids': [held]},
            {'sth': head, 'at': 4, 'h': 'hal.33', 'ids': [held], 'ext': small},
          ],
        },
        'handle_witness_warnings': [
          warningOn(held),
          warningOn(gone),
          warningOn(gone, rid: 'a-contact', found: 3),
          {...warningOn(gone, rid: 'a-contact', found: 4), 'k': 'unconfirmed'}
            ..remove('against'),
          {...warningOn(held), 'h': 'not a handle!'},
          {...warningOn(held), 'k': 'unconfirmed'},
          {...warningOn(held), 'k': 'maybe'},
        ],
      }
    }, const {});
    final heads = (jsonDecode(out['handle_witness_heads']!) as Map)['heads'] as List;
    expect(heads.map((h) => (h as Map)['at']), [1],
        reason: 'a stand-in smaller than the head is not one');
    expect((heads.single as Map)['held'], 9);
    final warnings = jsonDecode(out['handle_witness_warnings']!) as List;
    expect(warnings.map((x) => ((x as Map)['ids'] as List).single), [held, gone],
        reason: 'one a contact: a fork before an answer never confirmed found '
            'after it; and never one of a kind it does not know, nor an answer '
            'never confirmed that names a head against it');
    expect((warnings[1] as Map)['rid'], 'a-contact');
    expect((warnings[1] as Map)['k'], 'forked');
  });

  test('34. a change of log or witness puts the kept heads out of reach of '
      'a check, so what relied on each is told, and keeps the warnings',
      () async {
    final (:s, :f, :x, y: _, w: _) =
        await warnedAndWaiting('Dee', 'gwen.34', 'hal.34', 'ivo.34');
    HandleWarningKind? kindOn(ChatService c, String handle) => c.handles
        .forkWarningForRequest(
            c.handles.outgoing.firstWhere((o) => o.handle == handle))
        ?.kind;
    // Another witness: the kept head is not its record's to cover, so the
    // request it was kept for is told the answer was never confirmed.
    final w2 = await witnessOf(x);
    serve(f, w2);
    await s.handles.setConfig(witnessed(x, w2));
    expect(s.handles.keptHeads, isEmpty);
    expect(await s.vault.kvGet('handle_witness_heads'), isNull);
    expect(kindOn(s, 'ivo.34'), HandleWarningKind.unconfirmed);
    expect(kindOn(s, 'hal.34'), HandleWarningKind.forked,
        reason: 'about a request already sent');
    expect(s.handles.witnessState, HandleWitnessState.forked);
    // Kept again under that witness — x one head past it — and then the
    // witness removed.
    await claimAt(x, 'jon.34');
    await s.handles.request(await s.handles.find('@jon.34'));
    expect(s.handles.keptHeads.single.handle, 'jon.34');
    await s.handles.setConfig(x.config);
    expect(s.handles.keptHeads, isEmpty);
    expect(kindOn(s, 'jon.34'), HandleWarningKind.unconfirmed);
    expect(s.handles.forkWarnings, hasLength(3));
    expect(s.handles.witnessState, HandleWitnessState.forked,
        reason: 'the warnings stand with no witness configured');
    // Kept again, and then another log under the same witness.
    await s.handles.setConfig(witnessed(x, w2));
    await claimAt(x, 'kai.34');
    await s.handles.request(await s.handles.find('@kai.34'));
    expect(s.handles.keptHeads.single.handle, 'kai.34');
    final other = await startLog();
    await s.handles.setConfig(HandleConfig(
        logUrl: 'http://127.0.0.1:${other.port}',
        logPubB64: b64(other.pub),
        witnessUrl: w2.url,
        witnessPubB64: b64(w2.pub)));
    expect(s.handles.keptHeads, isEmpty);
    expect(kindOn(s, 'kai.34'), HandleWarningKind.unconfirmed);
    expect(s.handles.forkWarnings, hasLength(4));
    // A lookup made under one witness, its request sent after the witness
    // is removed: no record covers its head, and the request is told at once.
    await s.handles.setConfig(witnessed(x, w2));
    await claimAt(x, 'max.34');
    final maxFound = await s.handles.find('@max.34');
    await s.handles.setConfig(x.config);
    await s.handles.request(maxFound);
    expect(s.handles.keptHeads, isEmpty);
    expect(kindOn(s, 'max.34'), HandleWarningKind.unconfirmed);
    expect(s.handles.forkWarnings, hasLength(5));
    // A build that pins another witness, over a vault that never saved a
    // configuration of its own: setConfig never runs, and the heads are said
    // at load.
    final eve = await boot('Eve', config: witnessed(x, w2), fetcher: f);
    await claimAt(x, 'lia.34');
    await eve.handles.request(await eve.handles.find('@lia.34'));
    expect(eve.handles.keptHeads, hasLength(1));
    final vault = eve.vault;
    final id = eve.identity;
    await stop(eve);
    final same = await boot('Eve',
        config: witnessed(x, w2), fetcher: f, vault: vault, id: id);
    expect(same.handles.keptHeads, hasLength(1), reason: 'the same build keeps them');
    expect(same.handles.forkWarnings, isEmpty);
    await stop(same);
    final w3 = await witnessOf(x);
    final rebuilt = await boot('Eve',
        config: witnessed(x, w3), fetcher: f, vault: vault, id: id);
    expect(rebuilt.handles.keptHeads, isEmpty);
    expect(await vault.kvGet('handle_witness_heads'), isNull);
    expect(kindOn(rebuilt, 'lia.34'), HandleWarningKind.unconfirmed);
    expect(rebuilt.handles.witnessState, HandleWitnessState.unconfirmed);
  });

  test('35. a warning goes when it is dismissed, when its request is '
      'forgotten, and when its contact is deleted; nothing else ends it',
      () async {
    final (x, y, w) = await twoHistories('gwen.35');
    final thief = await boot('Thief', config: x.config);
    await claimIn(thief, 'hal.35');
    await claimAt(x, 'ivo.35');
    await claimAt(x, 'jan.35');
    final f = _Operator();
    serve(f, w);
    final dee = await boot('Dee', config: witnessed(x, w), fetcher: f);
    dee.handles.witnessReuse = Duration.zero;
    for (final h in ['hal.35', 'ivo.35', 'jan.35']) {
      await dee.handles.request(await dee.handles.find('@$h'));
    }
    expect(dee.handles.keptHeads, hasLength(3));
    // The operator's app accepts the first: answered, its head is the
    // contact's.
    await receives(thief, dee.myRid);
    await thief.acceptRequest(dee.myRid);
    await linked(dee, thief, 'hal.35');
    for (final h in ['hal.35', 'ivo.35', 'jan.35']) {
      await claimAt(y, h);
    }
    await sync(w, y);
    await expectLater(dee.handles.find('@gwen.35'), failsWith(HandleFailure.forked));
    expect(dee.handles.forkWarnings.map((x) => x.handle).toSet(),
        {'hal.35', 'ivo.35', 'jan.35'});
    expect(dee.handles.forkWarningForContact(thief.myRid)?.handle, 'hal.35',
        reason: 'the request was answered: the warning is on the contact');
    // Not ended by the witness agreeing again — its key co-signing x's head
    // now, as a witness that had followed x would.
    f.witness =
        () async => KtResponse(200, await recordFor(await headOf(x), w.seed));
    expect((await dee.handles.find('@gwen.35')).state, HandleLookupState.found);
    expect(dee.handles.witnessForkMs, isNull, reason: 'the lookup\'s fork is over');
    expect(dee.handles.forkWarnings, hasLength(3));
    expect(dee.handles.witnessState, HandleWitnessState.forked);
    // Dismissed.
    final jan = dee.handles.outgoing.firstWhere((o) => o.handle == 'jan.35');
    await dee.handles.dismissForkWarning(dee.handles.forkWarningForRequest(jan)!);
    expect(dee.handles.forkWarningForRequest(jan), isNull);
    expect(dee.handles.forkWarnings.map((x) => x.handle).toSet(),
        {'hal.35', 'ivo.35'});
    // The request forgotten.
    await dee.handles.forgetOutgoing('ivo.35');
    expect(dee.handles.forkWarnings.single.handle, 'hal.35');
    expect(await dee.vault.kvGet('handle_witness_warnings'),
        isNot(contains('ivo.35')));
    // The contact deleted.
    await dee.deleteContact(thief.myRid);
    expect(dee.handles.forkWarningForContact(thief.myRid), isNull);
    expect(dee.handles.forkWarnings, isEmpty);
    expect(await dee.vault.kvGet('handle_witness_warnings'), isNull);
    expect(dee.handles.witnessState, HandleWitnessState.agreed);
  });

  test('36. a fork padded past what the honest history reaches is found after '
      'the fact, by the head the log shows next: kept on the fork, the '
      'witness\'s record below the head kept contradicts it; taken back to '
      'the honest history, the head shown is smaller than the one kept '
      '(PROBE A of the review)', () async {
    final (x, y, w) = await twoHistories('gwen.36');
    final thief = await boot('Thief', config: x.config);
    await claimIn(thief, 'hal.36');
    // The operator pads the history it shows: @ivo.36 and five entries more,
    // in x alone. Hal claims @hal.36 in y, the history the witness follows.
    await claimAt(x, 'ivo.36');
    for (var i = 0; i < 5; i++) {
      await claimAt(x, 'pad$i.36');
    }
    await claimAt(y, 'hal.36');
    // Dee is kept on x. Eve is taken back to y later, at the same address
    // and under the same key.
    final fd = _Operator();
    serve(fd, w);
    final dee = await boot('Dee', config: witnessed(x, w), fetcher: fd);
    final fe = _Operator();
    serve(fe, w);
    final sw = _Switch(fe, x.port, y.port);
    final eve = await boot('Eve', config: witnessed(x, w), fetcher: sw);
    for (final s in [dee, eve]) {
      s.handles.witnessReuse = Duration.zero;
      final hal = await s.handles.find('@hal.36');
      expect(hal.introRid, thief.handles.own!.introRid,
          reason: 'the operator\'s mailbox');
      await s.handles.request(hal);
      await s.handles.request(await s.handles.find('@ivo.36'));
      expect(s.handles.keptHeads, hasLength(2));
      // The operator's app accepts the request to @hal.36.
      await receives(thief, s.myRid);
      await thief.acceptRequest(s.myRid);
      await linked(s, thief, 'hal.36');
    }
    final keptSize = dee.handles.keptHeads.first.size;
    // y grows honestly by two claims, and the witness follows it, healthy,
    // to a head below the one kept.
    await claimAt(y, 'ann.36');
    await claimAt(y, 'bob.36');
    await sync(w, y);
    final honest = (await headOf(y)).size;

    // (i) Dee, still shown x: her next lookup is the fork 15 refuses, and
    // the record below the head kept contradicts that head too.
    final onX = await look(dee, fd, '@gwen.36');
    // (ii) Eve, shown y: every head is smaller than the one kept.
    sw.on = true;
    final from = fe.urls.length;
    final onY = [
      for (final h in ['@gwen.36', '@ann.36', '@bob.36'])
        (await eve.handles.find(h)).state
    ];
    final again = await eve.handles.find('@hal.36');
    final askedFromKept = fe.urls
        .skip(from)
        .where((u) =>
            u.path == '/kt/v1/consistency' &&
            u.queryParameters['first'] == '$keptSize')
        .length;
    ({bool contact, bool request, int kept, HandleWitnessState state}) seen(
        ChatService s) {
      final ivo = s.handles.outgoing.where((o) => o.handle == 'ivo.36');
      return (
        contact: s.handles.forkWarningForContact(thief.myRid) != null,
        request: ivo.isNotEmpty && s.handles.forkWarningForRequest(ivo.single) != null,
        kept: s.handles.keptHeads.length,
        state: s.handles.witnessState,
      );
    }

    final d = seen(dee), e = seen(eve);
    // ignore: avoid_print
    print('LOOKUP 36: kept at $keptSize, honest at $honest, the record at '
        '$honest; (i) on x -> ${onX.error is HandleException ? (onX.error as HandleException).failure : onX.error}, '
        'contact warned ${d.contact}, request warned ${d.request}, kept '
        '${d.kept}, ${d.state}; (ii) on y -> $onY, @hal.36 ${again.state}, '
        'proofs asked from the kept size $askedFromKept, contact warned '
        '${e.contact}, request warned ${e.request}, kept ${e.kept}, ${e.state}');
    expect(keptSize, greaterThan(honest), reason: 'padded past it');
    expect(onX.error, forked());
    expect(d.contact, isTrue, reason: 'the contact the forked request brought');
    expect(d.request, isTrue, reason: 'the request still waiting on it');
    expect(d.kept, 0);
    expect(d.state, HandleWitnessState.forked);
    expect(dee.handles.forkWarnings.where((x) => x.isFork), isNotEmpty,
        reason: 'what Settings says: the request sent, not "nothing used"');
    for (final s in [dee, eve]) {
      final w = s.handles.forkWarningForContact(thief.myRid)!;
      expect(w.kind, HandleWarningKind.forked);
      expect(w.shown.size, keptSize);
      expect(w.against!.sameRootsAs(await headOf(y)), isTrue,
          reason: 'the witness\'s record (i), or the log\'s own smaller head '
              '(ii): the honest head');
    }
    expect(onY, everyElement(HandleLookupState.found));
    expect(again.state, HandleLookupState.changed,
        reason: 'the operator\'s record, remembered, is not Hal\'s');
    expect(askedFromKept, 0, reason: 'a smaller head needs no proof');
    expect(e.contact, isTrue);
    expect(e.request, isTrue);
    expect(e.kept, 0);
    expect(e.state, HandleWitnessState.forked);
  });

  test('37. a kept head the witness never covers is never dropped in '
      'silence: a proof the log withholds for 30 days (PROBE B of the '
      'review), and a witness unreachable for 30 days, end in a warning on '
      'the contact', () async {
    // (a) The operator shows Dee y once she holds the operator's account as
    // @hal.37, and withholds only the proof from the head she kept.
    final (x, y, w) = await twoHistories('gwen.37');
    final thief = await boot('Thief', config: x.config);
    await claimIn(thief, 'hal.37');
    await claimAt(y, 'hal.37');
    final f = _Operator();
    serve(f, w);
    final sw = _Switch(f, x.port, y.port);
    final hold = _WithholdFirst(sw);
    final dee = await boot('Dee', config: witnessed(x, w), fetcher: hold);
    dee.handles.witnessReuse = Duration.zero;
    dee.handles.witnessQuietAfter = const Duration(milliseconds: 1);
    final found = await dee.handles.find('@hal.37');
    expect(found.introRid, thief.handles.own!.introRid);
    await dee.handles.request(found);
    final kept = dee.handles.keptHeads.single;
    await receives(thief, dee.myRid);
    await thief.acceptRequest(dee.myRid);
    await linked(dee, thief, 'hal.37');
    sw.on = true;
    hold.first = kept.size;
    await claimAt(y, 'ann.37');
    await claimAt(y, 'bob.37');
    await sync(w, y);
    for (final h in ['@gwen.37', '@ann.37', '@bob.37']) {
      expect((await dee.handles.find(h)).state, HandleLookupState.found);
    }
    final denied = [...hold.denied];
    final state = dee.handles.witnessState;
    final keptNow = dee.handles.keptHeads.length;
    final toldNow = dee.handles.forkWarnings.length;
    final deeVault = dee.vault;
    final deeId = dee.identity;
    await stop(dee);
    final deeLater = await boot('Dee',
        config: witnessed(x, w),
        fetcher: hold,
        vault: deeVault,
        id: deeId,
        now: () => laterBy(const Duration(days: 30, minutes: 1)));
    await waitUntil(() => deeLater.handles.checksBack == 1,
        what: 'Dee\'s last check 30 days on');

    // (b) Fay's witness cannot be reached at all: she asks Olaf through his
    // handle, he accepts, and no record ever covers the head she kept.
    final log = await startLog();
    await claimAt(log, 'nia.37');
    final w2 = await witnessOf(log);
    final olaf = await boot('Olaf', config: log.config);
    await claimIn(olaf, 'olaf.37');
    final blocked = _Operator()
      ..witnessUrl = w2.url
      ..witness = () => Future<KtResponse>.error(
          const SocketException('the witness cannot be reached'));
    final fay = await boot('Fay', config: witnessed(log, w2), fetcher: blocked);
    await fay.handles.request(await fay.handles.find('@olaf.37'));
    final fayKept = fay.handles.keptHeads.length;
    await receives(olaf, fay.myRid);
    await olaf.acceptRequest(fay.myRid);
    await linked(fay, olaf, 'olaf.37');
    expect((await fay.handles.find('@nia.37')).state, HandleLookupState.found);
    final fayHeld = fay.handles.keptHeads.map((k) => k.rid).toList();
    final fayVault = fay.vault;
    final fayId = fay.identity;
    await stop(fay);
    final fayLater = await boot('Fay',
        config: witnessed(log, w2),
        fetcher: blocked,
        vault: fayVault,
        id: fayId,
        now: () => laterBy(const Duration(days: 30, minutes: 1)));
    await waitUntil(() => fayLater.handles.checksBack == 1,
        what: 'Fay\'s last check 30 days on');
    // No answer: nothing spent, nothing said. A day and a minute later, in
    // front, the witness still unreachable: after a day of tries the check
    // is given up on, and the head lapses, said.
    final fayAfterOne = fayLater.handles.keptHeads.length;
    final fayToldAfterOne = fayLater.handles.forkWarningForContact(olaf.myRid);
    shiftClock(fayLater, const Duration(days: 1, minutes: 1));
    fayLater.handles.onForeground();
    await waitUntil(() => fayLater.handles.checksBack == 2,
        what: 'Fay\'s last check tried again a day on');
    final deeTold = deeLater.handles.forkWarningForContact(thief.myRid);
    final fayTold = fayLater.handles.forkWarningForContact(olaf.myRid);
    // ignore: avoid_print
    print('LOOKUP 37: (a) withheld $denied -> $state, kept $keptNow, told '
        '$toldNow; 30 days on -> kept ${deeLater.handles.keptHeads.length}, '
        'contact told ${deeTold != null}; (b) the witness unreachable -> kept '
        '$fayKept, held by $fayHeld; 30 days on -> kept $fayAfterOne, told '
        '${fayToldAfterOne != null}; a day later -> kept '
        '${fayLater.handles.keptHeads.length}, contact told ${fayTold != null}');
    expect(denied, isNotEmpty);
    expect(state, HandleWitnessState.quiet);
    expect(keptNow, 1);
    expect(toldNow, 0, reason: 'pending: nothing is known yet');
    expect(deeLater.handles.keptHeads, isEmpty);
    expect(deeTold, isNotNull, reason: 'never confirmed, and said so');
    expect(deeTold!.handle, 'hal.37');
    expect(deeTold.lookedUpMs, kept.atMs);
    expect(deeTold.kind, HandleWarningKind.unconfirmed);
    expect(deeLater.handles.witnessState, HandleWitnessState.unconfirmed);
    expect(fayKept, 1);
    expect(fayHeld, [olaf.myRid]);
    expect(fayAfterOne, 1, reason: 'no answer: nothing spent');
    expect(fayToldAfterOne, isNull);
    expect(fayLater.handles.keptHeads, isEmpty);
    expect(fayTold, isNotNull, reason: 'never confirmed, and said so');
    expect(fayTold!.handle, 'olaf.37');
    expect(fayTold.kind, HandleWarningKind.unconfirmed);
    expect(fayLater.handles.witnessState, HandleWitnessState.unconfirmed);
  });

  // ---- A kept head checked on its own (2026-10-24) ------------------------

  test('38. a head the witness covers in the ordinary way is checked on its '
      'own when nothing looks it up: half an hour on, at the first moment in '
      'front, one record, and the head goes with nothing said — no false '
      'alarm 30 days on for a requester who looks nothing up again', () async {
    final log = await startLog();
    await claimAt(log, 'lena.38');
    final w = await witnessOf(log);
    // Olaf's own app holds @olaf.38: the log a head past the witness's record
    // when Dee looks him up.
    final olaf = await boot('Olaf', config: log.config);
    await claimIn(olaf, 'olaf.38');
    final f = _Operator();
    serve(f, w);
    final dee = await boot('Dee', config: witnessed(log, w), fetcher: f);
    expect(dee.handles.own, isNull, reason: 'a requester with no handle');
    await dee.handles.request(await dee.handles.find('@olaf.38'));
    expect(dee.handles.keptHeads, hasLength(1),
        reason: 'the record did not cover its head');
    await receives(olaf, dee.myRid);
    await olaf.acceptRequest(dee.myRid);
    await linked(dee, olaf, 'olaf.38');
    // The witness follows the log, as it does every five minutes.
    await sync(w, log);
    final before = fetchesOf(f, w.url);
    // Half an hour and a second on — past the check-back's moment, drawn 20
    // to 30 minutes after the request — Dee brings the app to the front
    // again and looks nothing up.
    shiftClock(dee, const Duration(minutes: 30, seconds: 1));
    dee.handles.onForeground();
    final covered = await settled(
        () async => await dee.vault.kvGet('handle_witness_heads') == null);
    final asked = fetchesOf(f, w.url) - before;
    // Thirty days and a minute on, with nothing answering at all — the
    // device offline — and again a day later, so that a check made then
    // could decide nothing, and would be given up on.
    final vault = dee.vault;
    final id = dee.identity;
    await stop(dee);
    final lapsed = await boot('Dee',
        config: witnessed(log, w),
        fetcher: _Nowhere(),
        vault: vault,
        id: id,
        now: () => laterBy(const Duration(days: 30, minutes: 1)));
    await waitUntil(
        () => lapsed.handles.keptHeads.isEmpty || lapsed.handles.checksBack >= 1,
        what: 'the first moment 30 days on');
    shiftClock(lapsed, const Duration(days: 1, minutes: 1));
    lapsed.handles.onForeground();
    await waitUntil(
        () => lapsed.handles.keptHeads.isEmpty || lapsed.handles.checksBack >= 2,
        what: 'a day later');
    await waitUntil(() => lapsed.handles.keptHeads.isEmpty,
        what: 'nothing left kept 31 days on');
    final told = lapsed.handles.forkWarningForContact(olaf.myRid);
    // ignore: avoid_print
    print('LOOKUP 38: half an hour on, in front -> covered $covered, records '
        'fetched $asked; 30 days on -> warning on the contact '
        '${told?.kind.name}, warnings ${lapsed.handles.forkWarnings.length}');
    expect(told, isNull, reason: 'no false alarm');
    expect(lapsed.handles.forkWarnings, isEmpty);
    expect(covered, isTrue, reason: 'the check-back covered it');
    expect(asked, 1, reason: 'one record, fetched afresh');
  });

  test('39. a fork padded past what the honest history reaches is found by '
      'the check-back, with no lookup after it, as a fork', () async {
    final (x, y, w) = await twoHistories('gwen.39');
    final thief = await boot('Thief', config: x.config);
    await claimIn(thief, 'hal.39');
    for (var i = 0; i < 5; i++) {
      await claimAt(x, 'pad$i.39');
    }
    await claimAt(y, 'hal.39');
    // Dee is kept on x; Eve is taken back to y, at the same address and
    // under the same key.
    final fd = _Operator();
    serve(fd, w);
    final dee = await boot('Dee', config: witnessed(x, w), fetcher: fd);
    final fe = _Operator();
    serve(fe, w);
    final sw = _Switch(fe, x.port, y.port);
    final eve = await boot('Eve', config: witnessed(x, w), fetcher: sw);
    for (final s in [dee, eve]) {
      final hal = await s.handles.find('@hal.39');
      expect(hal.introRid, thief.handles.own!.introRid,
          reason: 'the operator\'s mailbox');
      await s.handles.request(hal);
      await receives(thief, s.myRid);
      await thief.acceptRequest(s.myRid);
      await linked(s, thief, 'hal.39');
    }
    final keptSize = dee.handles.keptHeads.single.size;
    // The honest history grows past the fork point, and the witness follows
    // it.
    await claimAt(y, 'ann.39');
    await claimAt(y, 'bob.39');
    await sync(w, y);
    final honest = (await headOf(y)).size;
    // Half an hour and a second on, each brings the app to the front and
    // looks nothing up.
    sw.on = true;
    final found = <bool>[];
    for (final s in [dee, eve]) {
      shiftClock(s, const Duration(minutes: 30, seconds: 1));
      s.handles.onForeground();
      found.add(await settled(() async =>
          s.handles.forkWarningForContact(thief.myRid) != null &&
          await s.vault.kvGet('handle_witness_heads') == null));
    }
    // Thirty days and a minute on: what each says of the contact.
    final later = <ChatService>[];
    for (final (s, fetcher) in <(ChatService, KtFetcher)>[(dee, fd), (eve, sw)]) {
      final vault = s.vault;
      final id = s.identity;
      final name = s.displayName;
      await stop(s);
      final b = await boot(name,
          config: witnessed(x, w),
          fetcher: fetcher,
          vault: vault,
          id: id,
          now: () => laterBy(const Duration(days: 30, minutes: 1)));
      await waitUntil(() => b.handles.keptHeads.isEmpty,
          what: '$name: nothing left kept 30 days on');
      later.add(b);
    }
    final kinds = [
      for (final b in later) b.handles.forkWarningForContact(thief.myRid)?.kind
    ];
    // ignore: avoid_print
    print('LOOKUP 39: kept at $keptSize, the honest history at $honest; '
        'found at the check-back $found; 30 days on -> $kinds');
    expect(kinds, [HandleWarningKind.forked, HandleWarningKind.forked],
        reason: 'found as a fork at the check-back, not said at the lapse as '
            'never confirmed');
    expect(found, [true, true]);
  });

  test('40. a head is checked on its own at most twice — the check-back, and '
      'the last check at 30 days — each one record for every head due; '
      'nothing is asked with no head kept, nor again once a head is decided',
      () async {
    final log = await startLog();
    await claimAt(log, 'lena.40');
    final w = await witnessOf(log);
    final still = await witnessOf(log);
    await claimAt(log, 'liv.40');
    await claimAt(log, 'lou.40');
    // Fay sends nothing; Gus sends two requests on two lookups; Han one,
    // asking a witness that never moves on. Each asks afresh at every
    // lookup, so that a lookup's fetch is one of its own.
    final names = ['Fay', 'Gus', 'Han'];
    final ops = {for (final n in names) n: _Operator()};
    serve(ops['Fay']!, w);
    serve(ops['Gus']!, w);
    serve(ops['Han']!, still);
    final dev = <String, ChatService>{
      for (final n in names)
        n: await boot(n,
            config: witnessed(log, n == 'Han' ? still : w), fetcher: ops[n]!),
    };
    for (final s in dev.values) {
      s.handles.witnessReuse = Duration.zero;
    }
    int asked(String n) =>
        fetchesOf(ops[n]!, (n == 'Han' ? still : w).url);
    expect((await dev['Fay']!.handles.find('@lena.40')).state,
        HandleLookupState.found);
    for (final h in ['lena.40', 'liv.40']) {
      await dev['Gus']!.handles.request(await dev['Gus']!.handles.find('@$h'));
    }
    await dev['Han']!.handles.request(await dev['Han']!.handles.find('@lou.40'));
    expect(dev['Fay']!.handles.keptHeads, isEmpty);
    expect(dev['Gus']!.handles.keptHeads, hasLength(2));
    expect(dev['Han']!.handles.keptHeads, hasLength(1));
    // Gus's witness follows the log; Han's stays where it was.
    await sync(w, log);
    final start = {for (final n in names) n: asked(n)};
    // Half an hour and a second on, each comes to the front.
    for (final s in dev.values) {
      shiftClock(s, const Duration(minutes: 30, seconds: 1));
      s.handles.onForeground();
    }
    final gusDone = await settled(() async =>
        await dev['Gus']!.vault.kvGet('handle_witness_heads') == null);
    final hanDone = await settled(() async =>
        asked('Han') > start['Han']! &&
        ((await dev['Han']!.vault.kvGet('handle_witness_heads')) ?? '')
            .contains('"back"'));
    final atBack = {for (final n in names) n: asked(n) - start[n]!};
    // A lookup on each, its record fetched afresh — after anything the
    // moment in front asked, which would be asked before it.
    Future<Map<String, int>> lookOnce() async {
      final from = {for (final n in names) n: asked(n)};
      for (final s in dev.values) {
        expect((await s.handles.find('@lena.40')).state, HandleLookupState.found);
      }
      return {for (final n in names) n: asked(n) - from[n]!};
    }

    final first = await lookOnce();
    // Twenty minutes later, each in front again, and another lookup: no check
    // of its own again, decided or not.
    final from40 = {for (final n in names) n: asked(n)};
    for (final s in dev.values) {
      shiftClock(s, const Duration(minutes: 20));
      s.handles.onForeground();
    }
    final second = await lookOnce();
    final at40 = {for (final n in names) n: asked(n) - from40[n]!};
    // Thirty days and a minute on, Han's last check: one more record, and
    // then, never covered, the answer said as never confirmed.
    final han = dev['Han']!;
    final hanBefore = asked('Han');
    final vault = han.vault;
    final id = han.identity;
    await stop(han);
    final hanLater = await boot('Han',
        config: witnessed(log, still),
        fetcher: ops['Han']!,
        vault: vault,
        id: id,
        now: () => laterBy(const Duration(days: 30, minutes: 1)));
    await waitUntil(() => hanLater.handles.keptHeads.isEmpty,
        what: 'Han\'s head decided 30 days on');
    final atLast = asked('Han') - hanBefore;
    final hanTold = hanLater.handles.forkWarnings.singleOrNull;
    // ignore: avoid_print
    print('LOOKUP 40: records asked at the check-back $atBack (Gus covered '
        '$gusDone, Han spent $hanDone); with a lookup after it $first; in '
        'front again with a lookup $at40; Han at 30 days $atLast, then '
        '${hanTold?.kind.name}');
    expect(atBack['Fay'], 0, reason: 'nothing asked with no head kept');
    expect(atBack['Gus'], 1, reason: 'one record for both heads due');
    expect(atBack['Han'], 1);
    expect(gusDone, isTrue);
    expect(hanDone, isTrue);
    expect(first, {'Fay': 1, 'Gus': 1, 'Han': 1},
        reason: 'the lookup\'s own: none asked with no head kept');
    expect(second, {'Fay': 1, 'Gus': 1, 'Han': 1},
        reason: 'the lookup\'s own: none asked again, decided or spent');
    expect(at40, second);
    expect(atLast, 1, reason: 'the last check, once');
    expect(hanTold?.kind, HandleWarningKind.unconfirmed);

    // While the app stays in front, the moment comes by itself: a one-shot
    // timer, here a second after the head was kept, and one record. The
    // witness Ida asks co-signs the log's head as it is when asked.
    await claimAt(log, 'max.40');
    final fi = _Operator();
    serve(fi, w);
    final ida = await boot('Ida', config: witnessed(log, w), fetcher: fi);
    ida.handles.witnessCheckBack = const Duration(seconds: 1);
    ida.handles.witnessCheckBackMax = const Duration(seconds: 1);
    final maxFound = await ida.handles.find('@max.40');
    fi.witness = () async =>
        KtResponse(200, await recordFor(await headOf(log), w.seed));
    final idaBefore = fetchesOf(fi, w.url);
    await ida.handles.request(maxFound);
    expect(ida.handles.keptHeads, hasLength(1));
    await waitUntil(
        () async => await ida.vault.kvGet('handle_witness_heads') == null,
        what: 'the timer\'s check-back, the app in front');
    await waitUntil(() => ida.handles.checksBack == 1, what: 'one check');
    expect(fetchesOf(fi, w.url) - idaBefore, 1);
    expect(ida.handles.forkWarnings, isEmpty);
  });

  test('41. a head the check-back could not decide — the witness unreachable '
      'then — is decided by the last check, at 30 days: covered by then, it '
      'goes with nothing said', () async {
    final log = await startLog();
    await claimAt(log, 'lena.41');
    final w = await witnessOf(log);
    final olaf = await boot('Olaf', config: log.config);
    await claimIn(olaf, 'olaf.41');
    final f = _Operator();
    serve(f, w);
    final hana = await boot('Hana', config: witnessed(log, w), fetcher: f);
    await hana.handles.request(await hana.handles.find('@olaf.41'));
    expect(hana.handles.keptHeads, hasLength(1));
    await receives(olaf, hana.myRid);
    await olaf.acceptRequest(hana.myRid);
    await linked(hana, olaf, 'olaf.41');
    // The witness cannot be reached at the check-back.
    f.witness = () => Future<KtResponse>.error(
        const SocketException('the witness cannot be reached'));
    final lastAsk = hana.handles.witnessLastAskMs;
    final before = fetchesOf(f, w.url);
    shiftClock(hana, const Duration(minutes: 30, seconds: 1));
    hana.handles.onForeground();
    final checkedBack =
        await settled(() => hana.handles.witnessLastAskMs != lastAsk);
    final atBack = fetchesOf(f, w.url) - before;
    final keptAfter = hana.handles.keptHeads.length;
    // By day 30 the witness has followed the log and answers again; Hana has
    // looked nothing up.
    await sync(w, log);
    serve(f, w);
    final vault = hana.vault;
    final id = hana.identity;
    await stop(hana);
    final later = await boot('Hana',
        config: witnessed(log, w),
        fetcher: f,
        vault: vault,
        id: id,
        now: () => laterBy(const Duration(days: 30, minutes: 1)));
    await waitUntil(() => later.handles.keptHeads.isEmpty,
        what: 'decided 30 days on');
    final atLast = fetchesOf(f, w.url) - before - atBack;
    // ignore: avoid_print
    print('LOOKUP 41: the witness unreachable half an hour on -> checked '
        '$checkedBack, asked $atBack, kept $keptAfter; 30 days on -> asked '
        '$atLast, warnings ${later.handles.forkWarnings.length}');
    expect(later.handles.forkWarnings, isEmpty,
        reason: 'covered by day 30: no false alarm');
    expect(checkedBack, isTrue);
    expect(atBack, 1);
    expect(keptAfter, 1, reason: 'left pending; its check-back, unanswered, '
        'tried again at the next moment');
    expect(atLast, 1, reason: 'the last check, once');
  });

  // ---- A second review of the checks (2026-10-24) -------------------------

  /// The head of [w]'s record as it last wrote it.
  KtTreeHead recordHeadOf(_Witness w) => KtWitnessRecord.fromJson(
          (jsonDecode(w.record) as Map).cast<String, Object?>())
      .head;

  /// [name], with no handle of her own, holding the operator's account as
  /// @[handle] on the history x the operator shows her; the honest history y
  /// then grows two claims past the head she kept, and its witness follows
  /// it there (the second review's PROBE D): a fork of one entry, no padding.
  Future<
      ({
        ChatService s,
        ChatService thief,
        _Operator f,
        _Log x,
        _Log y,
        _Witness w,
        int kept
      })> keptOnAFork(String name, String n) async {
    final (x, y, w) = await twoHistories('gwen.$n');
    final thief = await boot('Thief', config: x.config);
    await claimIn(thief, 'hal.$n');
    await claimAt(y, 'hal.$n');
    final f = _Operator();
    serve(f, w);
    final s = await boot(name, config: witnessed(x, w), fetcher: f);
    s.handles.witnessReuse = Duration.zero;
    final hal = await s.handles.find('@hal.$n');
    expect(hal.introRid, thief.handles.own!.introRid,
        reason: 'the operator\'s mailbox');
    await s.handles.request(hal);
    final kept = s.handles.keptHeads.single.size;
    await receives(thief, s.myRid);
    await thief.acceptRequest(s.myRid);
    await linked(s, thief, 'hal.$n');
    await claimAt(y, 'ann.$n');
    await claimAt(y, 'bob.$n');
    await sync(w, y);
    expect(recordHeadOf(w).size, greaterThan(kept),
        reason: 'the honest history, and the record, past the kept head');
    return (s: s, thief: thief, f: f, x: x, y: y, w: w, kept: kept);
  }

  test('42. a device kept on a fork the honest history has grown past is told '
      'at once that the answer it sent on was never confirmed, on the contact '
      'that request added: no fork it cannot show, and the head still kept '
      '(PROBE D of the second review)', () async {
    final (:s, :thief, :f, x: _, y: _, :w, :kept) = await keptOnAFork('Dee', '42');
    // The operator goes on showing Dee x. Her next lookup is the fork 15
    // refuses; the head x shows extends the one she kept, and the log cannot
    // prove that one to the record past it.
    final onX = await look(s, f, '@gwen.42');
    final told = s.handles.forkWarningForContact(thief.myRid);
    final forks = s.handles.forkWarnings.where((x) => x.isFork).length;
    final keptNow = s.handles.keptHeads.length;
    final state = s.handles.witnessState;
    // Its check-back, half an hour on, in front, with no lookup: the same,
    // and said once.
    shiftClock(s, const Duration(minutes: 30, seconds: 1));
    s.handles.onForeground();
    await waitUntil(() => s.handles.checksBack == 1, what: 'the check-back');
    final afterBack = s.handles.forkWarningForContact(thief.myRid);
    final all = s.handles.forkWarnings.length;
    // ignore: avoid_print
    print('LOOKUP 42: kept at $kept, the record at ${recordHeadOf(w).size}; '
        'the next lookup on x -> ${onX.error}, $state; the contact told '
        '${told?.kind.name}, forks $forks, kept $keptNow; after the '
        'check-back -> ${afterBack?.kind.name}, warnings $all, kept '
        '${s.handles.keptHeads.length}');
    expect(onX.error, forked());
    expect(told?.kind, HandleWarningKind.unconfirmed,
        reason: 'said at once, and true: no record has confirmed it');
    expect(forks, 0, reason: 'no fork this device cannot show');
    expect(keptNow, 1, reason: 'still kept: a later check may decide it');
    expect(state, HandleWitnessState.forked);
    expect(afterBack?.kind, HandleWarningKind.unconfirmed);
    expect(all, 1, reason: 'said once');
    expect(s.handles.keptHeads, hasLength(1));
    // Dismissed — the person has compared safety numbers — it is not said
    // again by the next check that finds the same.
    await s.handles.dismissForkWarning(afterBack!);
    expect((await look(s, f, '@gwen.42')).error, forked());
    expect(s.handles.forkWarnings, isEmpty,
        reason: 'said once: a dismissed warning is not said again');
    expect(s.handles.keptHeads, hasLength(1));
  });

  test('43. 30 days on, the warning said at the fork stands and the head goes, '
      'never decided (PROBE D30 of the second review)', () async {
    final (:s, :thief, :f, :x, y: _, :w, kept: _) =
        await keptOnAFork('Dee', '43');
    expect((await look(s, f, '@gwen.43')).error, forked());
    final atFork = s.handles.forkWarningForContact(thief.myRid);
    final vault = s.vault;
    final id = s.identity;
    await stop(s);
    final later = await boot('Dee',
        config: witnessed(x, w),
        fetcher: f,
        vault: vault,
        id: id,
        now: () => laterBy(const Duration(days: 30, minutes: 1)));
    await waitUntil(() => later.handles.checksBack == 1, what: 'the last check');
    final told = later.handles.forkWarningForContact(thief.myRid);
    // ignore: avoid_print
    print('LOOKUP 43: at the fork -> ${atFork?.kind.name}; 30 days on -> kept '
        '${later.handles.keptHeads.length}, the contact told '
        '${told?.kind.name}, the one said at the fork '
        '${told != null && atFork != null && told.foundMs == atFork.foundMs}, '
        'warnings ${later.handles.forkWarnings.length}');
    expect(atFork?.kind, HandleWarningKind.unconfirmed);
    expect(later.handles.keptHeads, isEmpty,
        reason: 'undecided at its check at 30 days: the head goes');
    expect(told?.kind, HandleWarningKind.unconfirmed);
    expect(told!.foundMs, atFork!.foundMs,
        reason: 'the warning said at the fork stays');
    expect(later.handles.forkWarnings, hasLength(1));
  });

  test('44. a check of a head\'s own that gets no answers spends nothing: '
      'offline at the one moment after 30 days that is both its checks, it is '
      'tried again at a later moment in front, and a head the witness covered '
      'goes with nothing said (PROBE E of the second review)', () async {
    final log = await startLog();
    await claimAt(log, 'lena.44');
    final w = await witnessOf(log);
    final olaf = await boot('Olaf', config: log.config);
    await claimIn(olaf, 'olaf.44');
    final f = _Operator();
    serve(f, w);
    final net = _Flaky(f);
    final dee = await boot('Dee', config: witnessed(log, w), fetcher: net);
    expect(dee.handles.own, isNull, reason: 'a requester with no handle');
    await dee.handles.request(await dee.handles.find('@olaf.44'));
    final kept = dee.handles.keptHeads.single;
    await receives(olaf, dee.myRid);
    await olaf.acceptRequest(dee.myRid);
    await linked(dee, olaf, 'olaf.44');
    // The witness follows the log, as it does every five minutes: its record
    // covers the head kept. Dee leaves the app before her check-back, and
    // next brings it to the front 30 days and a minute later, at a moment
    // the network is not there.
    await sync(w, log);
    final rec = recordHeadOf(w);
    final vault = dee.vault;
    final id = dee.identity;
    await stop(dee);
    net.offline = true;
    final later = await boot('Dee',
        config: witnessed(log, w),
        fetcher: net,
        vault: vault,
        id: id,
        now: () => laterBy(const Duration(days: 30, minutes: 1)));
    await waitUntil(() => later.handles.checksBack == 1,
        what: 'the check, offline');
    final refused = net.refused;
    final keptOffline = later.handles.keptHeads.length;
    final toldOffline = later.handles.forkWarningForContact(olaf.myRid);
    // The network is back. Ten minutes and a second later, in front again.
    net.offline = false;
    shiftClock(later, const Duration(minutes: 10, seconds: 1));
    later.handles.onForeground();
    final covered = await settled(
        () async => await later.vault.kvGet('handle_witness_heads') == null);
    final told = later.handles.forkWarningForContact(olaf.myRid);
    // ignore: avoid_print
    print('LOOKUP 44: kept at ${kept.size}, the record at ${rec.size}; 30 days '
        'on, offline ($refused requests refused) -> kept $keptOffline, warning '
        '${toldOffline?.kind.name}; ten minutes later, answered -> covered '
        '$covered, warning ${told?.kind.name}');
    expect(rec.size, greaterThanOrEqualTo(kept.size));
    expect(keptOffline, 1, reason: 'no answers: nothing spent, nothing lapsed');
    expect(toldOffline, isNull, reason: 'no false alarm');
    expect(covered, isTrue, reason: 'tried again, and covered');
    expect(told, isNull);
    expect(later.handles.forkWarnings, isEmpty);
  });

  test('45. a check the app is killed during spends nothing: the next start '
      'does not lapse the head, and a later check covers it (PROBE E2 of the '
      'second review)', () async {
    final log = await startLog();
    await claimAt(log, 'lena.45');
    final w = await witnessOf(log);
    final olaf = await boot('Olaf', config: log.config);
    await claimIn(olaf, 'olaf.45');
    final f = _Operator();
    serve(f, w);
    final hang = _Hang(f);
    final dee = await boot('Dee', config: witnessed(log, w), fetcher: hang);
    await dee.handles.request(await dee.handles.find('@olaf.45'));
    await receives(olaf, dee.myRid);
    await olaf.acceptRequest(dee.myRid);
    await linked(dee, olaf, 'olaf.45');
    await sync(w, log); // covered at the witness
    final vault = dee.vault;
    final id = dee.identity;
    await stop(dee);
    hang.hang = true;
    final first = await boot('Dee',
        config: witnessed(log, w),
        fetcher: hang,
        vault: vault,
        id: id,
        now: () => laterBy(const Duration(days: 30, minutes: 1)));
    await waitUntil(() => hang.hung > 0, what: 'the check\'s fetch out');
    final hungAt = hang.hung;
    // Killed while it is out.
    await stop(first);
    hang.hang = false;
    final again = await boot('Dee',
        config: witnessed(log, w),
        fetcher: hang,
        vault: vault,
        id: id,
        now: () => laterBy(const Duration(days: 30, minutes: 2)));
    final keptAgain = again.handles.keptHeads.length;
    final toldAgain = again.handles.forkWarningForContact(olaf.myRid);
    // Ten minutes and a second later, in front: the check, answered.
    shiftClock(again, const Duration(minutes: 10, seconds: 1));
    again.handles.onForeground();
    final covered = await settled(
        () async => await again.vault.kvGet('handle_witness_heads') == null);
    final told = again.handles.forkWarningForContact(olaf.myRid);
    // ignore: avoid_print
    print('LOOKUP 45: fetches out when killed $hungAt; the next start -> kept '
        '$keptAgain, warning ${toldAgain?.kind.name}; ten minutes later -> '
        'covered $covered, warning ${told?.kind.name}');
    expect(keptAgain, 1, reason: 'a check the app was killed during spends '
        'nothing: no lapse');
    expect(toldAgain, isNull);
    expect(covered, isTrue);
    expect(told, isNull);
  });

  test('46. a throttle spends nothing: a check-back within ten minutes of a '
      'check left pending asks nothing then, and is made at a later moment in '
      'front, the proof asked then (PROBE H of the second review)', () async {
    final log = await startLog();
    await claimAt(log, 'lena.46');
    final w = await witnessOf(log);
    await claimAt(log, 'liv.46');
    final f = _Operator();
    serve(f, w);
    final first = _WithholdFirst(f);
    final dee = await boot('Dee', config: witnessed(log, w), fetcher: first);
    expect(dee.handles.witnessReuse, const Duration(minutes: 10));
    await dee.handles.request(await dee.handles.find('@lena.46'));
    final k = dee.handles.keptHeads.single;
    await claimAt(log, 'lou.46');
    await sync(w, log);
    List<String> fromKept(int from) => [
          for (final u in f.urls.skip(from))
            if (u.path == '/kt/v1/consistency' &&
                u.queryParameters['first'] == '${k.size}')
              u.query
        ];
    // Twenty-five minutes on, a lookup meets the proof from the kept size
    // withheld once — a moment's failure: pending.
    shiftClock(dee, const Duration(minutes: 25));
    first.first = k.size;
    expect((await dee.handles.find('@lena.46')).state, HandleLookupState.found);
    final deniedAtLookup = first.denied.length;
    first.first = null; // served from now on
    // Five minutes and a second later, in front: the check-back is due,
    // within ten minutes of the check left pending.
    shiftClock(dee, const Duration(minutes: 5, seconds: 1));
    final from = f.urls.length;
    dee.handles.onForeground();
    await waitUntil(() => dee.handles.checksBack == 1, what: 'the check-back');
    final atBack = fromKept(from);
    final keptAtBack = dee.handles.keptHeads.length;
    // Ten minutes and a second later, in front again.
    shiftClock(dee, const Duration(minutes: 10, seconds: 1));
    final from2 = f.urls.length;
    dee.handles.onForeground();
    final covered = await settled(
        () async => await dee.vault.kvGet('handle_witness_heads') == null);
    final atRetry = fromKept(from2);
    // ignore: avoid_print
    print('LOOKUP 46: kept at ${k.size}; withheld at the lookup '
        '$deniedAtLookup; the check-back, throttled -> proofs from the kept '
        'size $atBack, kept $keptAtBack; ten minutes later -> proofs $atRetry, '
        'covered $covered, warnings ${dee.handles.forkWarnings.length}');
    expect(deniedAtLookup, 1);
    expect(atBack, isEmpty, reason: 'throttled: nothing asked then');
    expect(keptAtBack, 1);
    expect(covered, isTrue, reason: 'the check-back made at the next moment');
    expect(atRetry, isNotEmpty, reason: 'the proof asked then');
    expect(dee.handles.forkWarnings, isEmpty);
  });

  test('47. a burst of requests in honest operation raises no warning: twenty '
      'inside one record\'s reuse, while an acceptance holds another head, '
      'are bounded by the outgoing list and none is said never confirmed; the '
      'witness, following, covers them all', () async {
    final log = await startLog();
    await claimAt(log, 'lena.47');
    final w = await witnessOf(log);
    final olaf = await boot('Olaf', config: log.config);
    await claimIn(olaf, 'olaf.47');
    final names = [for (var i = 0; i < 20; i++) 'bur$i.47'];
    for (final n in names) {
      await claimAt(log, n);
    }
    final f = _Operator();
    serve(f, w);
    final dee = await boot('Dee', config: witnessed(log, w), fetcher: f);
    expect(dee.handles.witnessReuse, const Duration(minutes: 10));
    // Olaf accepts Dee's request: the contact holds its head.
    await dee.handles.request(await dee.handles.find('@olaf.47'));
    await receives(olaf, dee.myRid);
    await olaf.acceptRequest(dee.myRid);
    await linked(dee, olaf, 'olaf.47');
    // Twenty requests, one to each handle, inside one record's reuse.
    for (final n in names) {
      await dee.handles.request(await dee.handles.find('@$n'));
    }
    final keptNow = dee.handles.keptHeads.length;
    final waiting = dee.handles.outgoing.length;
    final toldNow = dee.handles.forkWarnings.length;
    // The witness follows; the check-back, in front, covers them all.
    await sync(w, log);
    shiftClock(dee, const Duration(minutes: 30, seconds: 1));
    dee.handles.onForeground();
    final covered = await settled(
        () async => await dee.vault.kvGet('handle_witness_heads') == null,
        within: const Duration(seconds: 30));
    // ignore: avoid_print
    print('LOOKUP 47: one head a contact holds and twenty requests waiting -> '
        'kept $keptNow, waiting $waiting, told $toldNow; the check-back -> '
        'covered $covered, warnings ${dee.handles.forkWarnings.length}');
    expect(waiting, 20);
    expect(keptNow, 21, reason: 'the contact\'s head, and one for each request');
    expect(toldNow, 0, reason: 'a burst in honest operation is not "never '
        'confirmed"');
    expect(covered, isTrue);
    expect(dee.handles.forkWarnings, isEmpty);
  });

  test('48. a check of a head\'s own is never made at the moment the app comes '
      'to the front, but a few seconds after it, drawn as the drain\'s first '
      'wait is; and the check-back\'s moment is drawn from 20 to 30 minutes '
      'after the request (PROBE F of the second review)', () async {
    final log = await startLog();
    await claimAt(log, 'lena.48');
    final w = await witnessOf(log);
    final olaf = await boot('Olaf', config: log.config);
    await claimIn(olaf, 'olaf.48');
    final f = _Operator();
    serve(f, w);
    final clk = _Clocked(f);
    final dee = await boot('Dee', config: witnessed(log, w), fetcher: clk);
    // The drain's first wait: 3 to 30 seconds. Here a second and a half to
    // two, to be seen.
    expect(handleForegroundDelayMin, const Duration(seconds: 3));
    expect(handleForegroundDelayMax, const Duration(seconds: 30));
    dee.handles.foregroundDelayMin = const Duration(milliseconds: 1500);
    dee.handles.foregroundDelayMax = const Duration(milliseconds: 2000);
    await dee.handles.request(await dee.handles.find('@olaf.48'));
    final head = ((jsonDecode((await dee.vault.kvGet('handle_witness_heads'))!)
            as Map)['heads'] as List)
        .single as Map;
    final backAt = head['backAt'] as int?;
    final drawn = backAt == null ? null : backAt - (head['kept'] as int);
    await sync(w, log);
    shiftClock(dee, const Duration(minutes: 30, seconds: 1));
    final from = clk.at.length;
    final t0 = DateTime.now();
    dee.handles.onForeground();
    await waitUntil(
        () => clk.at.skip(from).any((e) => e.$2.toString() == w.url),
        what: 'the record fetched');
    final firstMs = clk.at.skip(from).first.$1.difference(t0).inMilliseconds;
    // ignore: avoid_print
    print('LOOKUP 48: the check-back drawn '
        '${drawn == null ? null : Duration(milliseconds: drawn)} after the '
        'request; after onForeground() its first request at +$firstMs ms '
        '(drawn from 1500..2000 ms here, 3..30 s by default)');
    expect(firstMs, greaterThanOrEqualTo(1500),
        reason: 'never at the moment the app comes to the front');
    expect(firstMs, lessThan(10000));
    expect(drawn, isNotNull, reason: 'drawn as the head is kept');
    expect(drawn!, inInclusiveRange(20 * 60000, 30 * 60000));
  });
}
