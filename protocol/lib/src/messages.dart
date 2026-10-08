import 'dart:convert';
import 'dart:typed_data';

import 'util.dart';

/// Inner (plaintext) message model — what actually rides inside the ratchet.
/// The relay can never see any of this.
///
/// Kinds:
///   'hello'  silent session opener (no user-visible content)
///   'text'   { body }
///   'file'   file offer { fid, name, size, mime, sha256, fk, fn, chunks, csize }
///   'timer'  disappearing-messages setting { sec } (0 = off)
///   'read'   read receipts { mids: [...] }
///   'pqid'   (v3) post-quantum identity key { alg, pk[, ack] } — checked
///            against the commitment carried by the zc3. contact code
///            (§13.2); kept as a candidate for the safety number when no
///            commitment is held (ADR 0021)
///   'pqack'  (ADR 0021) the sender holds the receiver's post-quantum key —
///            `ack` without a key; ignored by clients that predate it
///   'pqek'   (v2) post-quantum key offer { alg, ek } — consumed by the
///            session layer, never shown; ignored by v1 clients
///   'dlrm'   (7.7a) device-list removal notice { acct, v, h[, list] } — a
///            contact tells a device it just dropped from an account's list
///            that it was removed; ignored by v1 clients. `list` (ADR 0026)
///            is the signed list that dropped it, the evidence the device
///            needs: a notice without one says nothing it can check
///   'pdlreq' (ADR 0026) { v, h } — "send me the list you hold for MY
///            account": asked of a contact whose echo ('pdl') named a list
///            the asking device does not hold. Keyless. Answered with a
///            'devlist' whose list is the receiver's ACCOUNT's, not the
///            sender's (told apart by its `acct`); ignored by clients that
///            predate it
///
///   'edit'   (8.1c) new text for one of the SENDER'S OWN messages
///            { rt, body }; 'gedit' adds { gid }
///   'del'    (8.1c) delete-for-everyone of the sender's own messages
///            { mids:[...] }; 'gdel' adds { gid }
///   'react'  (8.1b) reaction to one message { rt, emo } — `rt` names the
///            target (same member as a reply, below), `emo` is the emoji or
///            "" to withdraw; one reaction per sender per message
///   'greact' (8.1b) the same inside a group { gid, rt, emo }
///
/// Message interactions (8.1) add one optional member to the content kinds
/// ('text', 'file', 'gmsg', 'gfile'), ignored by clients that predate it:
///   'rt'   string  the `mid` this message refers to, in the same
///                  conversation — the message being replied to, or (on
///                  'react'/'greact') reacted to. Only the id travels: the
///                  quoted text is whatever the RECEIVER already has stored
///                  for that id, so a reply can never put words in the quoted
///                  sender's mouth. An unknown id renders as unavailable.
///                  NB it is deliberately not called 'mid': that key already
///                  names the inner message's own id.
///
/// Device-list transparency (7.7a) also decorates EVERY inner message with two
/// optional members, carried alongside [data] and ignored by v1 clients:
///   'dl'   {v, h}  the sender's claim about ITS OWN account's current device
///                  list (version + [SignedDeviceList.fingerprint]).
///   'pdl'  {v, h}  the newest device list the sender holds for the RECIPIENT's
///                  account — an echo that lets the owner detect a list a
///                  contact was given but the owner's device never issued.
///
/// And (26.2, ADR 0021) one more, ignored by clients that predate it:
///   'pqh'  1       the sender holds the RECIPIENT's post-quantum key — what a
///                  'pqack' says, on every message, so a lost 'pqack' cannot
///                  leave the two on different safety numbers (§18.2).
class InnerMessage {
  final String kind;
  final String mid; // sender-chosen message id (unique per sender)
  final int ts; // sender clock, ms since epoch
  final int ttlSec; // disappearing timer in effect when sent (0 = keep)
  final Map<String, Object?> data;

  InnerMessage({
    required this.kind,
    required this.mid,
    required this.ts,
    this.ttlSec = 0,
    Map<String, Object?>? data,
  }) : data = data ?? {};

  Uint8List toBytes() => Uint8List.fromList(utf8.encode(jsonEncode({
        'k': kind,
        'mid': mid,
        'ts': ts,
        if (ttlSec > 0) 'ttl': ttlSec,
        ...data,
      })));

  /// Parse a decrypted inner message.
  ///
  /// This runs on plaintext that has already been authenticated by the
  /// ratchet, so it is not an attacker's direct input — but a peer's client
  /// (buggy, or hostile toward its own contact) can put anything inside a
  /// validly-encrypted envelope. A raw `as String` on a field that is a number
  /// throws a `TypeError`, an Error, not an Exception: it escapes every `on
  /// FormatException`/`on RatchetDecryptException` the caller has, and the
  /// 2026-09-14 review's finding 42 traced it to `chat_service` returning
  /// without acknowledging, so one malformed inner message wedged the mailbox
  /// slot for the whole queue TTL. Every field is type-checked, and anything
  /// wrong is a [FormatException] the caller can catch — the same shape
  /// `identity_v3.dart` uses for a contact code.
  static InnerMessage fromBytes(Uint8List bytes) {
    final Object? decoded;
    try {
      decoded = jsonDecode(utf8.decode(bytes));
    } catch (_) {
      throw const FormatException('inner message is not JSON');
    }
    if (decoded is! Map) {
      throw const FormatException('inner message is not an object');
    }
    // A JSON number with a huge exponent (`1e999`) decodes to a non-finite
    // double, and the first `.toInt()` on it — `ts`, `ttl`, a kind's `sec`,
    // `dur`, `v`, `g`, or the `pql` decoration read after the envelope is
    // acknowledged — throws an `UnsupportedError`. That is an Error, not an
    // Exception, so it escaped every `on FormatException` the caller has and
    // left the envelope unacknowledged: the same wedge `fromBytes`'s type
    // checks exist to stop, through a value no honest client sends. One pass
    // rejects a non-finite number wherever it sits, nested members included.
    _assertFinite(decoded);
    final j = decoded.cast<String, Object?>();
    final k = j['k'], mid = j['mid'], ts = j['ts'], ttl = j['ttl'];
    if (k is! String || mid is! String || ts is! num) {
      throw const FormatException('inner message is missing a required field');
    }
    if (ttl != null && ttl is! num) {
      throw const FormatException('inner message ttl is not a number');
    }
    const known = {'k', 'mid', 'ts', 'ttl'};
    final data = <String, Object?>{
      for (final e in j.entries)
        if (!known.contains(e.key)) e.key: e.value
    };
    // The members each kind acts on, checked for type and shape before any
    // caller reads them (§6.8). A peer's own client can put anything inside a
    // validly-encrypted envelope, and a member of the wrong type reached
    // unguarded — `mids` that is not a list of strings is the one a receiver
    // iterated — throws a `TypeError` deep in the receive transaction, which
    // escapes as an Error and leaves the envelope to be redelivered until the
    // queue TTL. A wrong-typed member is a [FormatException] the caller
    // catches and drops, the ratchet kept.
    _validateKind(k, data);
    return InnerMessage(
      kind: k,
      mid: mid,
      ts: ts.toInt(),
      ttlSec: (ttl as num?)?.toInt() ?? 0,
      data: data,
    );
  }

  /// Rejects a non-finite JSON number anywhere in the decoded message.
  static void _assertFinite(Object? v) {
    if (v is double && !v.isFinite) {
      throw const FormatException('inner message holds a non-finite number');
    }
    if (v is Map) {
      for (final e in v.values) {
        _assertFinite(e);
      }
    } else if (v is List) {
      for (final e in v) {
        _assertFinite(e);
      }
    }
  }

  /// Per-kind member validation (§6.8). Every member is checked only when
  /// present — an absent member keeps the meaning it had before the member
  /// existed, which is how §6.2 extends kinds compatibly — and an unknown
  /// kind passes untouched (§6.2: unknown kinds are ignored, not refused).
  ///
  /// This checks ONLY the members a receiver reads through a cast that throws
  /// on the wrong type — `body` and `gid` (`as String?`), `sec` (`as num?`),
  /// and `mids` (`as List?`, then iterated element by element). Members a
  /// receiver is specified to ignore when malformed rather than reject —
  /// `rt`, `emo` (§6.4/§6.5), and an attachment offer's own fields, which the
  /// offer reader defaults or refuses without throwing (§7) — are left to
  /// those tolerant readers, so a message is never dropped for a member the
  /// spec says to overlook. Non-finite numbers are rejected globally above.
  static void _validateKind(String kind, Map<String, Object?> d) {
    void str(String key) {
      if (d.containsKey(key) && d[key] is! String) {
        throw FormatException('$kind.$key must be a string');
      }
    }

    void num_(String key) {
      if (d.containsKey(key) && d[key] is! num) {
        throw FormatException('$kind.$key must be a number');
      }
    }

    // A list of strings, iterated element by element by the receiver — the
    // one shape whose wrong element type threw inside the receive
    // transaction (`read`/`dlv` read it as `List` and cast each element).
    void strList(String key) {
      final v = d[key];
      if (v == null) return;
      if (v is! List || v.any((e) => e is! String)) {
        throw FormatException('$kind.$key must be a list of strings');
      }
    }

    switch (kind) {
      case 'text':
        str('body');
        break;
      case 'gmsg':
        str('gid');
        str('body');
        break;
      case 'gedit':
        str('gid');
        break;
      case 'gdel':
        str('gid');
        break;
      case 'greact':
        str('gid');
        break;
      case 'timer':
        num_('sec');
        break;
      case 'read':
      case 'dlv':
        strList('mids');
        break;
      default:
        break; // other kinds read their members safely (getters, is-guards,
      // try/catch, or the offer reader); nothing throws on a wrong type
    }
  }

  static InnerMessage text(String mid, int ts, String body,
          {int ttlSec = 0, String? replyTo}) =>
      InnerMessage(kind: 'text', mid: mid, ts: ts, ttlSec: ttlSec, data: {
        'body': body,
        if (replyTo != null && replyTo.isNotEmpty) 'rt': replyTo,
      });

  static InnerMessage hello(String mid, int ts) =>
      InnerMessage(kind: 'hello', mid: mid, ts: ts);

  static InnerMessage timer(String mid, int ts, int seconds) =>
      InnerMessage(kind: 'timer', mid: mid, ts: ts, data: {'sec': seconds});

  static InnerMessage read(String mid, int ts, List<String> mids) =>
      InnerMessage(kind: 'read', mid: mid, ts: ts, data: {'mids': mids});

  /// v2 ML-KEM-768 encapsulation-key offer (see pq.dart). 7.5b: [gen] tags the
  /// generation being offered; generation 0 (the initial offer) omits it, so
  /// the offer's bytes are unchanged from the original v2 encoding.
  static InnerMessage pqOffer(String mid, int ts, Uint8List ek,
          {int gen = 0}) =>
      InnerMessage(kind: 'pqek', mid: mid, ts: ts, data: {
        'alg': 'ML-KEM-768',
        'ek': b64(ek),
        if (gen > 0) 'g': gen,
      });

  /// v3 (§13.2): this account's post-quantum public key, delivered inside the
  /// ratchet because it does not fit in the QR code that bound it. The
  /// receiver checks it against the commitment from the scan
  /// (`ContactBundleV3.acceptsPqKey`) and refuses the identity on a mismatch
  /// — a v2 peer simply ignores the unknown kind, as with `pqek`.
  ///
  /// [ack] says the sender already holds the receiver's key, checked against
  /// its own commitment — so the receiver need not answer in kind. Without
  /// it the exchange could only complete by each side answering every key
  /// it received, which is one round trip too many and, measured, sent the
  /// 16 KB envelope twice in each direction at a mutual add. Omitted when
  /// false, so a message without it is byte-for-byte what earlier builds
  /// send and the recorded vector.
  static InnerMessage pqIdentity(String mid, int ts, Uint8List mlPub,
          {bool ack = false}) =>
      InnerMessage(kind: 'pqid', mid: mid, ts: ts, data: {
        'alg': 'ML-DSA-65',
        'pk': b64(mlPub),
        if (ack) 'ack': true,
      });

  /// ADR 0021: the sender holds the receiver's post-quantum key — the same
  /// statement as `ack` on a `pqid`, without the key. Sent when that fact
  /// arose after the sender's own `pqid` had gone, so no message would
  /// otherwise carry it: the receiver's key arrived WITH `ack` (so it was not
  /// answered), or the sender came to hold the key before either side kept
  /// candidates. A few dozen bytes — the smallest envelope bucket, the size
  /// of a read receipt, so unlike a `pqid` it is not a distinctive mark on
  /// the relay's view. Clients that predate it ignore the kind (§6).
  static InnerMessage pqAck(String mid, int ts) =>
      InnerMessage(kind: 'pqack', mid: mid, ts: ts);

  /// 7.7a device-list removal notice: sent by a contact to a device it just
  /// dropped from account [acct]'s list (at version [v], fingerprint [h]), so
  /// a device silently excluded by whoever holds the account root learns of it.
  ///
  /// [list] (ADR 0026) is that list's JSON: the account-signed statement the
  /// device can check, and the only thing that makes the notice evidence.
  /// Optional on the wire — a notice from a client before it carries none,
  /// and the bytes without it are exactly what those clients send.
  static InnerMessage deviceListRemoved(String mid, int ts,
          {required Uint8List acct,
          required int v,
          required Uint8List h,
          String? list}) =>
      InnerMessage(kind: 'dlrm', mid: mid, ts: ts, data: {
        'acct': b64(acct),
        'v': v,
        'h': b64(h),
        if (list != null) 'list': list,
      });

  /// ADR 0026: ask a contact for the list it holds for the SENDER's own
  /// account, whose (version [v], fingerprint [h]) its echo named. Keyless:
  /// the answer is an ordinary 'devlist' carrying that list, which the asker
  /// verifies under its own account key — an echo is a claim, the list is
  /// the evidence.
  static InnerMessage ownListRequest(String mid, int ts,
          {required int v, required String h}) =>
      InnerMessage(kind: 'pdlreq', mid: mid, ts: ts, data: {'v': v, 'h': h});

  /// The `mid` this message replies to (8.1), or null when it is not a reply
  /// or the member is malformed. Length-capped: a reply id is one of our own
  /// message ids (22 base64url chars), and a peer cannot make us index a
  /// megabyte of attacker text by claiming it is an id.
  String? get replyTo {
    final v = data['rt'];
    if (v is! String || v.isEmpty || v.length > 64) return null;
    return v;
  }

  /// 8.1b: react to [target] with [emoji], or withdraw with an empty string.
  /// One reaction per sender per message: a second one replaces the first.
  static InnerMessage reaction(String mid, int ts,
          {required String target, required String emoji, String? gid}) =>
      InnerMessage(
          kind: gid == null ? 'react' : 'greact',
          mid: mid,
          ts: ts,
          data: {
            if (gid != null) 'gid': gid,
            'rt': target,
            'emo': emoji,
          });

  /// The reaction payload of a 'react'/'greact', or null when the members are
  /// missing or implausible. Emoji are bounded (a family sequence is already
  /// 11 UTF-16 units, so 32 is generous) and must not carry control
  /// characters — a reaction is a badge, not a channel for arbitrary text.
  ({String target, String emoji})? get reactionData {
    final target = replyTo; // same member, same bounds
    final emo = data['emo'];
    if (target == null) return null;
    if (emo is! String || emo.length > 32) return null;
    for (final unit in emo.codeUnits) {
      if (unit < 0x20 || unit == 0x7f) return null;
    }
    return (target: target, emoji: emo);
  }

  /// 8.1c: replacement text for one of the sender's own messages. The
  /// receiver enforces authorship — this is a request, not an instruction.
  static InnerMessage edit(String mid, int ts,
          {required String target, required String body, String? gid}) =>
      InnerMessage(
          kind: gid == null ? 'edit' : 'gedit',
          mid: mid,
          ts: ts,
          data: {
            if (gid != null) 'gid': gid,
            'rt': target,
            'body': body,
          });

  /// 8.1c: delete-for-everyone of the sender's own messages.
  static InnerMessage deleteForEveryone(String mid, int ts,
          {required List<String> targets, String? gid}) =>
      InnerMessage(
          kind: gid == null ? 'del' : 'gdel',
          mid: mid,
          ts: ts,
          data: {
            if (gid != null) 'gid': gid,
            'mids': targets,
          });

  /// The ids a 'del'/'gdel' asks to remove: strings of plausible id length,
  /// capped so one envelope cannot ask for unbounded work.
  List<String> get deleteTargets {
    final v = data['mids'];
    if (v is! List) return const [];
    final out = <String>[];
    for (final e in v) {
      if (e is String && e.isNotEmpty && e.length <= 64) out.add(e);
      if (out.length >= 256) break;
    }
    return out;
  }

  /// Cheap check of the kind without a full parse: [toBytes] always writes
  /// `{"k":"<kind>"` first.
  static bool looksLikeKind(Uint8List bytes, String kind) {
    final prefix = utf8.encode('{"k":"$kind"');
    if (bytes.length < prefix.length) return false;
    for (var i = 0; i < prefix.length; i++) {
      if (bytes[i] != prefix[i]) return false;
    }
    return true;
  }
}

/// Generates a collision-resistant message/envelope id (base64url, 16 bytes).
String newMessageId() => b64url(randomBytes(16));

/// A group id, as PROTOCOL.md §11 defines one: `"g" || b64url(12 random
/// bytes)`, so `g` followed by sixteen characters of the base64url alphabet.
String newGroupId() => 'g${b64url(randomBytes(12))}';

final RegExp _gidShape = RegExp(r'^g[A-Za-z0-9_-]{16}$');

/// True if [s] is a group id as §11 defines one.
///
/// A RECEIVER's check, and the important one. A `gid` arrives in a `ginvite`
/// chosen by whoever sent it, and it is also the THREAD KEY: the client files
/// messages under it, and a chat is a group if there is a group with that
/// key. A routing id is 43 characters and a group id is 17 beginning with
/// `g`, so the two cannot collide — unless nobody checks, in which case a
/// contact can name ANOTHER contact's routing id as their group's id and take
/// over that conversation's identity.
bool isWellFormedGid(String s) => _gidShape.hasMatch(s);
