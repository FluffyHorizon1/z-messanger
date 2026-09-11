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
///   'pqid'   (v3) post-quantum identity key { alg, pk } — checked against
///            the commitment carried by the zc3. contact code (§13.2)
///   'pqek'   (v2) post-quantum key offer { alg, ek } — consumed by the
///            session layer, never shown; ignored by v1 clients
///   'dlrm'   (7.7a) device-list removal notice { acct, v, h } — a contact
///            tells a device it just dropped from an account's list that it
///            was removed; ignored by v1 clients
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

  static InnerMessage fromBytes(Uint8List bytes) {
    final j = jsonDecode(utf8.decode(bytes)) as Map<String, Object?>;
    final known = {'k', 'mid', 'ts', 'ttl'};
    return InnerMessage(
      kind: j['k'] as String,
      mid: j['mid'] as String,
      ts: (j['ts'] as num).toInt(),
      ttlSec: ((j['ttl'] as num?) ?? 0).toInt(),
      data: {
        for (final e in j.entries)
          if (!known.contains(e.key)) e.key: e.value
      },
    );
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

  /// 7.7a device-list removal notice: sent by a contact to a device it just
  /// dropped from account [acct]'s list (at version [v], fingerprint [h]), so
  /// a device silently excluded by whoever holds the account root learns of it.
  static InnerMessage deviceListRemoved(String mid, int ts,
          {required Uint8List acct, required int v, required Uint8List h}) =>
      InnerMessage(
          kind: 'dlrm',
          mid: mid,
          ts: ts,
          data: {'acct': b64(acct), 'v': v, 'h': b64(h)});

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
