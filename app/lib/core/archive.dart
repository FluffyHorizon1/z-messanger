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

import 'package:cryptography/cryptography.dart' show SecretKey;
import 'package:path/path.dart' as p;
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:z_protocol/z_protocol.dart';

import 'relay_url.dart';
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
  /// Attachment bytes travel in frames of this size, so neither direction
  /// ever holds the archive in memory.
  ///
  /// What each direction DOES hold is one attachment, and that is a floor
  /// rather than a choice: a blob is sealed as a single AEAD message at rest
  /// (`Vault.writeBlob`), so producing one means having the whole plaintext
  /// and opening one means the same. The app's cap (24 MiB) is therefore the
  /// peak, and `BACKUP.md` says so rather than promising otherwise.
  ///
  /// Import used to hold *all* of them — every attachment in the archive
  /// accumulated in a `BytesBuilder` and written only after the terminator.
  /// See [import]; `restore_memory_test.dart` measures it.
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
        // 13.3: WHICH number the user compared, and whether a post-quantum
        // key has already been refused for this contact. Without them a
        // restore reinstates a tick it cannot account for, and forgets a
        // refusal — the two facts a restored device most needs to keep.
        if (c['verified_sn'] != null) 'vsn': c['verified_sn'],
        if ((c['pq_mismatch'] as int? ?? 0) == 1) 'pqbad': 1,
        // 13.6: the account this contact IS, and the certificate proving the
        // scanned device belongs to it. A restore that lost these would
        // re-anchor the contact to a device — moving their safety number and
        // making their device list stop verifying, both of which read to the
        // user as an attack.
        if (c['acct_ed'] != null) 'acct': c['acct_ed'],
        if (c['dev_cert'] != null) 'cert': jsonDecode(c['dev_cert'] as String),
        // 13.7: which of the user's own devices added this. A restore that
        // dropped it would present a contact nobody scanned here as one the
        // user added themselves.
        if (c['added_by'] != null) 'addedby': c['added_by'],
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
    // Attachment bytes go to a spill file each, not to memory.
    //
    // They used to go into a `Map<String, BytesBuilder>` drained only after
    // the terminator, so an import held EVERY attachment in the archive at
    // once: a vault with two hundred photographs was two hundred photographs
    // of heap on a phone, and the failure mode is the OS killing the app in
    // the middle of the one operation a user runs when they have already
    // lost the device. `BACKUP.md` promised the opposite in as many words.
    //
    // Declared out here so the `finally` can clean them up whatever happens:
    // a failed import must not leave an archive's attachments lying about
    // outside the vault's own files directory.
    //
    // A fid is `b64url(12 random bytes)` and is refused at the door when it
    // is not (§7), which is what makes it safe to use as a file name here.
    // `RandomAccessFile.writeFrom`, not an `IOSink`: a sink's `add` queues
    // the bytes and returns, so writing 80 MiB through one without awaiting a
    // flush holds 80 MiB in the sink instead of in a BytesBuilder. Measured:
    // the first version of this fix moved the memory and did not remove it.
    //
    // And SEALED. Until 2026-09-17 the spill held each attachment's bytes in
    // the clear, beside a database whose whole point is that attachments are
    // sealed, on the argument that the `finally` below removes it — which is
    // true of every exit but the one the spill exists for: the OS killing
    // the app for memory mid-restore, after which the directory sat there,
    // plaintext, for ever, collected by nothing (the 2026-09-14 review's
    // finding 7). Now each archive frame is re-sealed as it arrives under a
    // key that exists only in this process (`RestoreSpill`): a spill the
    // process did not live to delete is ciphertext under a key nobody holds,
    // `Vault.open` zeroes and removes whatever is left in the directory, and
    // the clean path zeroes before it unlinks, as `deleteBlob` does.
    final spillDir = Directory(p.join(vault.root.path, RestoreSpill.dirName));
    final spill = RestoreSpill(spillDir);
    final spills = <String, RandomAccessFile>{};
    File spillFile(String fid) => File(p.join(spillDir.path, fid));
    await spillDir.create(recursive: true);

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
      final fileMeta = <String, Map<String, Object?>>{};

      await vault.db.transaction((txn) async {
        // Everything below runs inside this transaction, so every write must
        // go through `txn`: reaching for `vault.db` (as `vault.kvPut` does)
        // deadlocks against the lock the transaction already holds.
        // Most restored values are sensitive and sealed. A few keys are
        // declared plain (`Vault.plainKeys`) and the live app stores them
        // plain — `server_url` among them; writing it through the sealing
        // branch put a restored address under `s:server_url` sealed, which
        // `kvGet` still reads but which no other write produces, so a
        // restored vault did not match the schema (the 2026-09-14 review's
        // finding 35). Honour the class here, so the restore path and the
        // live path store the same key the same way.
        Future<void> kv(String k, String v) async => Vault.mayBePlain(k)
            ? txn.insert('kv', {'k': 'p:$k', 'v': v},
                conflictAlgorithm: ConflictAlgorithm.replace)
            : txn.insert('kv', {'k': 's:$k', 'v': await vault.seal(v)},
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
            // The same rule as an inbound offer: a file id is `b64url(12
            // random bytes)` (§7) and an archive is a file that may have come
            // from anywhere. The id names the blob's file on disk, so a
            // record that carries a path instead is dropped rather than
            // restored -- the rest of the archive still comes back.
            if (!isWellFormedFid(fid)) continue;
            final out = spills[fid] ??=
                await spillFile(fid).open(mode: FileMode.writeOnly);
            await spill.append(out, bytes);
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
              // The relay address the archive was taken against. An archive
              // is a file, and a file can come from anywhere, so this one is
              // held to the rule a typed address is held to: a public `ws://`
              // relay is not adopted on the say-so of a document. `ws://` on
              // the local network still is, because that is what a restore
              // onto a LAN deployment needs and there is nobody on that path.
              final server = r['server'];
              if (server is String) {
                final url = normalizeRelayUrl(server);
                if (isSecureOrLocalRelay(url)) await kv('server_url', url);
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
                    'verified_sn': r['vsn'],
                    'pq_mismatch': (r['pqbad'] as num?)?.toInt() ?? 0,
                    'acct_ed': r['acct'],
                    if (r['cert'] != null) 'dev_cert': jsonEncode(r['cert']),
                    'added_by': r['addedby'],
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
              final fid = r['fid'];
              if (fid is! String || !isWellFormedFid(fid)) break;
              attachments++;
              fileMeta[fid] = r;
          }
        }

        if (!sawEnd) throw ArchiveIncompleteException();

        // Attachments last: the bytes are re-sealed under THIS device's vault
        // key, with fresh per-file key material. One at a time -- a blob is a
        // single AEAD message at rest, so sealing one means holding one, and
        // the largest attachment in the archive is the whole cost.
        for (final out in spills.values) {
          await out.flush();
          await out.close();
        }
        spills.clear();
        for (final entry in fileMeta.entries) {
          final fid = entry.key;
          final meta = entry.value;
          final spilled = spillFile(fid);
          if (!spilled.existsSync()) continue; // a record with no bytes
          final bytes = await spill.readBack(spilled);
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
      for (final out in spills.values) {
        try {
          await out.close();
        } catch (_) {}
      }
      RestoreSpill.shred(spillDir);
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


/// The importer's spill: each attachment's archive frames, re-sealed as they
/// arrive under a key that exists only for this restore, in this process.
///
/// A blob at rest is one AEAD message, so sealing an attachment into the
/// vault means holding all of it — and the spill is where it waits, frame by
/// frame, so that an archive of two hundred photographs is never two hundred
/// photographs of heap (C35). What waits there was plaintext until
/// 2026-09-17. It is not any more: a frame is sealed with the same
/// construction the archive itself uses, under a random key and nonce prefix
/// drawn when the restore starts and dropped when it ends, with one counter
/// across every frame of every attachment so no nonce is ever used twice
/// under the key. A spill left behind by a process that died is therefore
/// bytes nobody can open, and [shred] and [Vault.open] remove it besides.
///
/// Record layout, per frame: `u32 sealedLength`, `u32 frameIndex`, then the
/// sealed frame — the index is what [readBack] needs to rebuild the nonce.
class RestoreSpill {
  RestoreSpill(this.dir)
      : _key = SecretKey(randomBytes(32)),
        _noncePrefix = randomBytes(16);

  /// Under the vault root; `Vault.open` knows the name so it can sweep it.
  static const dirName = Vault.restoreSpillDirName;

  /// The AAD's fixed part: what this is, so a spill frame is not an archive
  /// frame and cannot be mistaken for one under any key.
  static final Uint8List _header = Uint8List.fromList(utf8.encode('z-restore-spill-v1'));

  final Directory dir;
  final SecretKey _key;
  final Uint8List _noncePrefix;
  int _index = 0;

  /// Seal [bytes] as the next frame and append the record to [out].
  Future<void> append(RandomAccessFile out, List<int> bytes) async {
    final index = _index++;
    final sealed = await ZArchive.sealFrame(
      key: _key,
      header: _header,
      noncePrefix: _noncePrefix,
      index: index,
      kind: ZArchive.kindBlob,
      payload: bytes,
    );
    final head = ByteData(8)
      ..setUint32(0, sealed.length)
      ..setUint32(4, index);
    await out.writeFrom(head.buffer.asUint8List());
    await out.writeFrom(sealed);
  }

  /// Open every record in [file], in order, and return the attachment whole.
  Future<Uint8List> readBack(File file) async {
    final raf = await file.open();
    final out = BytesBuilder(copy: false);
    try {
      while (true) {
        final head = await raf.read(8);
        if (head.isEmpty) break;
        if (head.length < 8) throw const FormatException('torn spill record');
        final bd = ByteData.view(Uint8List.fromList(head).buffer);
        final len = bd.getUint32(0);
        final index = bd.getUint32(4);
        final sealed = await raf.read(len);
        if (sealed.length < len) throw const FormatException('torn spill record');
        final (kind, payload) = await ZArchive.openFrame(
          key: _key,
          header: _header,
          noncePrefix: _noncePrefix,
          index: index,
          sealed: Uint8List.fromList(sealed),
        );
        if (kind != ZArchive.kindBlob) throw const FormatException('not a spill frame');
        out.add(payload);
      }
    } finally {
      await raf.close();
    }
    return out.takeBytes();
  }

  /// Zero and remove everything under [dir], then the directory — the same
  /// pass `Vault.open` makes over it, and the same one [Vault.deleteBlob]
  /// makes over a blob.
  static void shred(Directory dir) => Vault.shredDir(dir);
}
