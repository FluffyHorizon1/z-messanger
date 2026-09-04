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
///   'pqek'   (v2) post-quantum key offer { alg, ek } — consumed by the
///            session layer, never shown; ignored by v1 clients
///   'dlrm'   (7.7a) device-list removal notice { acct, v, h } — a contact
///            tells a device it just dropped from an account's list that it
///            was removed; ignored by v1 clients
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

  static InnerMessage text(String mid, int ts, String body, {int ttlSec = 0}) =>
      InnerMessage(
          kind: 'text', mid: mid, ts: ts, ttlSec: ttlSec, data: {'body': body});

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
