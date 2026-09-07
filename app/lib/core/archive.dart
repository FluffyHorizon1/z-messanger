// Encrypted backup archive (phase 9): export the whole vault to a `.zbk`
// file the user holds, and restore it onto a wiped device.
//
// What travels: the identity, contacts, groups, every message, reactions and
// attachment bytes. What does NOT travel, deliberately:
//
//   * **session state** (`conversations`). Those rows are live double-ratchet
//     state. Restoring them could put the same ratchet on two devices —
//     reusing chain keys and message numbers — and the relay allows one
//     socket per routing id, so the two copies would also fight over the
//     mailbox. A restored device re-handshakes instead: the first message to
//     each contact opens a fresh session, which costs one round trip and is
//     the only safe answer.
//   * the outbox and inbox dedupe table, which are in-flight state, not
//     history.
//   * anything device-bound: the vault's own master key and device secret,
//     the biometric pass key, the device id. A restore builds a fresh vault
//     with fresh device keys.
//
// The file layout and its guarantees live in `ZArchive` (protocol package)
// and `docs/BACKUP.md`.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:z_protocol/z_protocol.dart';

import 'vault.dart';

/// Progress while exporting or importing, for a UI that must not look frozen
/// on a large vault.
class ArchiveProgress {
  final String stage;
  final int done;
  final int total;
  const ArchiveProgress(this.stage, this.done, this.total);
  double get fraction => total <= 0 ? 0 : done / total;
}

/// What an archive turned out to contain, once opened.
class ArchiveSummary {
  final int schema;
  final int createdMs;
  final int messages;
  final int contacts;
  final int groups;
  final int attachments;
  const ArchiveSummary({
    required this.schema,
    required this.createdMs,
    required this.messages,
    required this.contacts,
    required this.groups,
    required this.attachments,
  });
}

class ArchiveIncompleteException implements Exception {
  @override
  String toString() =>
      'ArchiveIncompleteException: the archive ends early — the file is '
      'truncated and restoring it would lose messages';
}

class BackupArchive {
  /// Attachment bytes are written in chunks of this size, so neither export
  /// nor import ever holds a whole large file — let alone the whole archive —
  /// in memory.
  static const int blobChunkBytes = 256 * 1024;

  // ------------------------------------------------------------------
  // Export
  // ------------------------------------------------------------------

  /// Streams the vault into [out], sealed under [code]. Returns the number of
  /// records written (the terminator's count).
  static Future<int> export({
    required Vault vault,
    required RecoveryCode code,
    required IOSink out,
    void Function(ArchiveProgress)? onProgress,
  }) async {
    final salt = randomBytes(16);
    final noncePrefix = randomBytes(16);
    final key = await ZArchive.deriveKey(await code.keyMaterial(), salt);
    final schema = await vault.db.getVersion();
    final header = ZArchive.buildHeader(
      salt: salt,
      noncePrefix: noncePrefix,
      schema: schema,
      createdMs: DateTime.now().millisecondsSinceEpoch,
    );
    out.add(header);
    out.add(const [0x0a]);

    var index = 0;
    var records = 0;

    Future<void> frame(int kind, List<int> payload) async {
      final sealed = await ZArchive.sealFrame(
        key: key,
        header: header,
        noncePrefix: noncePrefix,
        index: index,
        kind: kind,
        payload: payload,
      );
      final len = ByteData(4)..setUint32(0, sealed.length);
      out.add(len.buffer.asUint8List());
      out.add(sealed);
      index++;
    }

    Future<void> record(Map<String, Object?> r) async {
      await frame(ZArchive.kindRecord, utf8.encode(jsonEncode(r)));
      records++;
    }

    // Identity and profile.
    final idJson = await vault.kvGet('identity');
    final serverUrl = await vault.kvGet('server_url');
    await record({
      't': 'meta',
      'app': 'z',
      'schema': schema,
      'name': await vault.kvGet('display_name') ?? 'Me',
      if (serverUrl != null) 'server': serverUrl,
    });
    if (idJson != null) {
      // v3 (§18.1): the ML-DSA half of this identity is a 32-byte seed, so it
      // rides along here rather than as a 4 032-byte secret key. Without it a
      // restored device would generate a DIFFERENT post-quantum key, and
      // every contact holding a commitment to the old one would see a
      // mismatch — indistinguishable, to them, from an attack.
      await record({
        't': 'identity',
        'identity': jsonDecode(idJson),
        if (await vault.kvGet('pq_seed') != null)
          'pq_seed': await vault.kvGet('pq_seed'),
      });
    }

    // Contacts, including their v3 state: the commitment from the code that
    // was scanned and the post-quantum key that matched it. Losing those on a
    // restore would silently downgrade every verified contact to classical.
    for (final c in await vault.db.query('contacts')) {
      String? pqPub;
      if (c['enc_pq_pub'] != null) {
        try {
          pqPub = await vault.unseal(c['enc_pq_pub'] as String);
        } catch (_) {
          pqPub = null; // unreadable cell: the key re-arrives in-band
        }
      }
      await record({
        't': 'contact',
        'rid': c['rid'],
        'bundle': jsonDecode(await vault.unseal(c['enc_bundle'] as String)),
        'name': await vault.unseal(c['enc_name'] as String),
        'ttl': c['ttl_seconds'],
        'verified': c['verified'],
        'created': c['created_ms'],
        if (c['pq_commit'] != null) 'pqc': c['pq_commit'],
        if (pqPub != null) 'pqk': pqPub,
      });
    }

    // Groups (stored as one kv blob).
    final groupsJson = await vault.kvGet('groups');
    if (groupsJson != null) {
      await record({'t': 'groups', 'groups': jsonDecode(groupsJson)});
    }

    // Messages. Bodies are decrypted out of the vault and re-sealed by the
    // archive: the vault key is device-bound and never leaves.
    final messages = await vault.db.query('messages', orderBy: 'ts_ms ASC');
    var done = 0;
    for (final m in messages) {
      String body;
      try {
        body = await vault.unseal(m['enc_body'] as String);
      } catch (_) {
        continue; // unreadable cell: skip rather than abort the whole backup
      }
      final edited = (m['edited_ms'] as int?) ?? 0;
      await record({
        't': 'message',
        'mid': m['mid'],
        'rid': m['rid'],
        'out': m['outgoing'],
        'kind': m['kind'],
        'body': body,
        if (m['fid'] != null) 'fid': m['fid'],
        'ts': m['ts_ms'],
        'status': m['status'],
        'expire': m['expire_at_ms'],
        if (m['reply_to'] != null) 'rt': m['reply_to'],
        if (edited > 0) 'edited': edited,
        if (((m['deleted'] as int?) ?? 0) == 1) 'deleted': 1,
        if (((m['forwarded'] as int?) ?? 0) == 1) 'fw': 1,
      });
      if (++done % 200 == 0) {
        onProgress?.call(ArchiveProgress('messages', done, messages.length));
      }
    }
    onProgress
        ?.call(ArchiveProgress('messages', messages.length, messages.length));

    // Reactions.
    for (final r in await vault.db.query('reactions')) {
      String emoji;
      try {
        emoji = await vault.unseal(r['enc_emoji'] as String);
      } catch (_) {
        continue;
      }
      await record({
        't': 'reaction',
        'rid': r['rid'],
        'mid': r['mid'],
        'by': r['sender_rid'],
        'emo': emoji,
        'ts': r['ts_ms'],
      });
    }

    // Attachments: the metadata record, then the bytes in chunks. Only
    // complete files are worth carrying.
    final files = await vault.db
        .query('files', where: 'complete = 1', orderBy: 'fid ASC');
    var fileNo = 0;
    for (final f in files) {
      final fid = f['fid'] as String;
      Map<String, Object?> meta;
      try {
        meta = (jsonDecode(await vault.unseal(f['enc_meta'] as String)) as Map)
            .cast<String, Object?>();
      } catch (_) {
        continue;
      }
      Uint8List bytes;
      try {
        bytes = await vault.readBlob(fid, _localKeyInfo(meta));
      } catch (_) {
        continue; // blob gone or unreadable: keep the message, drop the file
      }
      await record({
        't': 'file',
        'fid': fid,
        'rid': f['rid'],
        'mid': f['mid'],
        'name': meta['name'],
        'size': bytes.length,
        'mime': meta['mime'],
        'sha256': meta['sha256'],
        if (meta['voice'] == true) 'voice': true,
        if (meta['dur'] != null) 'dur': meta['dur'],
      });
      for (var o = 0; o < bytes.length; o += blobChunkBytes) {
        final end = o + blobChunkBytes < bytes.length
            ? o + blobChunkBytes
            : bytes.length;
        await frame(ZArchive.kindBlob,
            ZArchive.blobPayload(fid, bytes.sublist(o, end)));
      }
      onProgress?.call(ArchiveProgress('attachments', ++fileNo, files.length));
    }

    // Terminator: an importer that does not see this refuses the archive.
    await frame(ZArchive.kindEnd,
        utf8.encode(jsonEncode({'t': 'end', 'records': records})));
    await out.flush();
    return records;
  }

  /// The sender's own copy of an attachment stores its key material under
  /// `local`; a received one keeps `fk`/`fn`.
  static Map<String, Object?> _localKeyInfo(Map<String, Object?> meta) {
    final local = meta['local'];
    if (local is Map) return local.cast<String, Object?>();
    return {'k': meta['fk'], 'n': meta['fn']};
  }

  // ------------------------------------------------------------------
  // Import
  // ------------------------------------------------------------------

  /// Restores [file] into [vault], which MUST be empty (a fresh install or a
  /// wiped one) — restoring over live data would interleave two histories.
  /// Throws [FormatException] for a wrong code or a damaged file, and
  /// [ArchiveIncompleteException] when the terminator is missing.
  static Future<ArchiveSummary> import({
    required Vault vault,
    required File file,
    required RecoveryCode code,
    void Function(ArchiveProgress)? onProgress,
  }) async {
    final raf = await file.open();
    try {
      final headerLine = await _readHeaderLine(raf);
      final head = ZArchive.parseHeader(headerLine);
      final salt = unb64(head['salt'] as String);
      final noncePrefix = unb64(head['np'] as String);
      final key = await ZArchive.deriveKey(await code.keyMaterial(), salt);

      var index = 0;
      var messages = 0, contacts = 0, groups = 0, attachments = 0;
      var sawEnd = false;
      var records = 0;
      final blobs = <String, BytesBuilder>{};
      final fileMeta = <String, Map<String, Object?>>{};

      await vault.db.transaction((txn) async {
        // Everything below runs inside this transaction, so every write must
        // go through `txn`: reaching for `vault.db` (as `vault.kvPut` does)
        // deadlocks against the lock the transaction already holds.
        Future<void> kv(String k, String v) async =>
            txn.insert('kv', {'k': 's:$k', 'v': await vault.seal(v)},
                conflictAlgorithm: ConflictAlgorithm.replace);

        while (true) {
          final lenBytes = await raf.read(4);
          if (lenBytes.isEmpty) break;
          if (lenBytes.length < 4) throw ArchiveIncompleteException();
          final len =
              ByteData.view(Uint8List.fromList(lenBytes).buffer).getUint32(0);
          final sealed = await raf.read(len);
          if (sealed.length < len) throw ArchiveIncompleteException();
          final (kind, payload) = await ZArchive.openFrame(
            key: key,
            header: headerLine,
            noncePrefix: noncePrefix,
            index: index++,
            sealed: Uint8List.fromList(sealed),
          );
          if (kind == ZArchive.kindBlob) {
            final (fid, bytes) = ZArchive.parseBlobPayload(payload);
            (blobs[fid] ??= BytesBuilder()).add(bytes);
            continue;
          }
          final r =
              (jsonDecode(utf8.decode(payload)) as Map).cast<String, Object?>();
          if (kind == ZArchive.kindEnd) {
            sawEnd = true;
            if (((r['records'] as num?)?.toInt() ?? -1) != records) {
              throw ArchiveIncompleteException();
            }
            break;
          }
          records++;
          switch (r['t']) {
            case 'meta':
              await kv('display_name', r['name'] as String? ?? 'Me');
              if (r['server'] is String) {
                await kv('server_url', r['server'] as String);
              }
            case 'identity':
              await kv('identity', jsonEncode(r['identity']));
              if (r['pq_seed'] is String) {
                await kv('pq_seed', r['pq_seed'] as String);
              }
            case 'contact':
              contacts++;
              await txn.insert(
                  'contacts',
                  {
                    'rid': r['rid'],
                    'enc_bundle': await vault.seal(jsonEncode(r['bundle'])),
                    'enc_name': await vault.seal(r['name'] as String? ?? '?'),
                    'ttl_seconds': (r['ttl'] as num?)?.toInt() ?? 0,
                    'verified': (r['verified'] as num?)?.toInt() ?? 0,
                    'created_ms': (r['created'] as num?)?.toInt() ?? 0,
                    'pq_commit': r['pqc'],
                    if (r['pqk'] is String)
                      'enc_pq_pub': await vault.seal(r['pqk'] as String),
                  },
                  conflictAlgorithm: ConflictAlgorithm.replace);
            case 'groups':
              groups = (r['groups'] as List?)?.length ?? 0;
              await kv('groups', jsonEncode(r['groups']));
            case 'message':
              messages++;
              await txn.insert(
                  'messages',
                  {
                    'mid': r['mid'],
                    'rid': r['rid'],
                    'outgoing': (r['out'] as num?)?.toInt() ?? 0,
                    'kind': r['kind'],
                    'enc_body': await vault.seal(r['body'] as String? ?? ''),
                    'fid': r['fid'],
                    'ts_ms': (r['ts'] as num?)?.toInt() ?? 0,
                    'status': (r['status'] as num?)?.toInt() ?? 0,
                    'expire_at_ms': (r['expire'] as num?)?.toInt() ?? 0,
                    'reply_to': r['rt'],
                    'edited_ms': (r['edited'] as num?)?.toInt() ?? 0,
                    'deleted': r['deleted'] == 1 ? 1 : 0,
                    'forwarded': r['fw'] == 1 ? 1 : 0,
                  },
                  conflictAlgorithm: ConflictAlgorithm.replace);
              if (messages % 200 == 0) {
                onProgress?.call(ArchiveProgress('messages', messages, 0));
              }
            case 'reaction':
              await txn.insert(
                  'reactions',
                  {
                    'rid': r['rid'],
                    'mid': r['mid'],
                    'sender_rid': r['by'],
                    'enc_emoji': await vault.seal(r['emo'] as String? ?? ''),
                    'ts_ms': (r['ts'] as num?)?.toInt() ?? 0,
                  },
                  conflictAlgorithm: ConflictAlgorithm.replace);
            case 'file':
              attachments++;
              fileMeta[r['fid'] as String] = r;
          }
        }

        if (!sawEnd) throw ArchiveIncompleteException();

        // Attachments last: the bytes are re-sealed under THIS device's vault
        // key, with fresh per-file key material.
        for (final entry in fileMeta.entries) {
          final fid = entry.key;
          final meta = entry.value;
          final bytes = blobs[fid]?.takeBytes();
          if (bytes == null) continue;
          final keyInfo = await vault.writeBlob(fid, bytes);
          await txn.insert(
              'files',
              {
                'fid': fid,
                'rid': meta['rid'],
                'mid': meta['mid'],
                'enc_meta': await vault.seal(jsonEncode({
                  'name': meta['name'],
                  'size': bytes.length,
                  'mime': meta['mime'],
                  'sha256': meta['sha256'],
                  'local': keyInfo,
                  if (meta['voice'] == true) 'voice': true,
                  if (meta['dur'] != null) 'dur': meta['dur'],
                })),
                'complete': 1,
                'got_chunks': 1,
                'total_chunks': 1,
              },
              conflictAlgorithm: ConflictAlgorithm.replace);
        }
      });

      onProgress?.call(const ArchiveProgress('done', 1, 1));
      return ArchiveSummary(
        schema: (head['schema'] as num?)?.toInt() ?? 0,
        createdMs: (head['created'] as num?)?.toInt() ?? 0,
        messages: messages,
        contacts: contacts,
        groups: groups,
        attachments: attachments,
      );
    } finally {
      await raf.close();
    }
  }

  /// Reads the header line without consuming the first frame.
  static Future<Uint8List> _readHeaderLine(RandomAccessFile raf) async {
    final out = BytesBuilder();
    while (out.length < 4096) {
      final b = await raf.read(1);
      if (b.isEmpty) throw const FormatException('not a Z backup archive');
      if (b.first == 0x0a) return out.takeBytes();
      out.add(b);
    }
    throw const FormatException('not a Z backup archive');
  }
}
