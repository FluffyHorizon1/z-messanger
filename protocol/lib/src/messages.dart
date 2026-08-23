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
}

/// Generates a collision-resistant message/envelope id (base64url, 16 bytes).
String newMessageId() => b64url(randomBytes(16));
