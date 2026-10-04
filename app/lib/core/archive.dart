// Encrypted backup archive (phase 9): export the whole vault to a `.zbk`
// file the user holds, and restore it onto a wiped device.
//
// What travels: the identity — and, on a linked device, the account it is a
// device of — contacts, groups, every message, reactions and attachment
// bytes; and since minor 1 of the format (phase 31) what the account's
// device-list and transparency machinery needs to RESUME rather than start
// again: the list this account last signed or learned and every
// (version, fingerprint) it knows it issued, its linked devices, the log's
// head and configuration, each contact's list with its signature floor, the
// block list, pending requests and the push preference. A restore that
// carried none of it began again at device-list version 1 and told the user
// to reset their identity: its own log monitor found the versions it had
// signed before the backup and called them lists it never issued, and every
// contact saw its devices claim a version below one they had already seen
// (the 2026-10-03 analysis, P0-3). What does NOT travel, deliberately:
//
//   * **session state** (`conversations`). Those rows are live double-ratchet
//     state. Restoring them could put the same ratchet on two devices —
//     reusing chain keys and message numbers — and the relay allows one
//     socket per routing id, so the two copies would also fight over the
//     mailbox. A restored device re-handshakes instead: the first message to
//     each contact opens a fresh session, which costs one round trip and is
//     the only safe answer. What does travel is every session's ID, so the
//     restored device holds each one as retired: an opening envelope someone
//     kept cannot re-create a session it ended (see [BackupArchive.export]).
//   * the outbox and inbox dedupe table, which are in-flight state, not
//     history.
//   * anything device-bound: the vault's own master key and device secret,
//     the biometric pass key. A restore builds a fresh vault with fresh
//     device keys. (A root's device id travels: it is part of the
//     certificate every list the account signs names it by.)
//
// The file layout and its guarantees live in `ZArchive` (protocol package)
// and `docs/BACKUP.md`; what a restored device does first, in
// `ChatService` (`_resumeAfterRestore`).

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' show SecretKey;
import 'package:path/path.dart' as p;
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:z_protocol/z_protocol.dart';

import 'alarm_evidence.dart' show OwnAlarmDismissals;
import 'key_transparency.dart' show KtConfig;
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

  /// Records of a type this build does not know, kept to be written into
  /// the next archive because their writer marked them so
  /// ([ZArchive.keepField]), and the ones skipped because it did not.
  final int kept;
  final int skipped;
  const ArchiveSummary({
    required this.schema,
    required this.createdMs,
    required this.messages,
    required this.contacts,
    required this.groups,
    required this.attachments,
    this.kept = 0,
    this.skipped = 0,
  });
}

/// What a restore knows when it judges a `state` value: whose account the
/// archive's identity is — its own key on a root, the `account` record's on
/// a linked device.
class _Ctx {
  final Uint8List? account;
  const _Ctx(this.account);
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

  /// Set by [import] (and by the `.zid` path in `Restore`): this vault was
  /// restored and its first start has not yet re-asserted the account.
  /// `ChatService` clears it once it has (`_resumeAfterRestore`).
  static const String resumeKey = 'restore_resume';

  /// Records of a type this build does not know whose writer marked them
  /// [ZArchive.keepField]: their JSON text, in arrival order, sealed, until
  /// [export] writes them into the next archive.
  static const String keptKey = 'archive_kept';

  /// The account-level `kv` rows the `state` record carries (format minor 1),
  /// each with the shape a restore insists on before writing it: an archive
  /// is a file that can come from anywhere, and several of these are read at
  /// start-up by code that trusts what it finds.
  ///
  /// What is here and why: the account's own device list — its version, the
  /// list last signed or learned and its fingerprint, the linked devices, the
  /// post-quantum signature over it, which migrations have run — and the
  /// alarms about it the user has not dismissed; the transparency log's
  /// configuration (a self-hoster's own log), its accepted head (so a fork
  /// the old device would have seen is still seen) and every own
  /// (version, fingerprint) this account knows it issued, without which its
  /// monitor reads its own history as lists it never issued; the root's
  /// device id, which its certificate — named in every one of those lists —
  /// is signed over; and the push preference, which defaults to on. With
  /// ADR 0026, what each alarm stands on, the evidence of every one the user
  /// dismissed, and the own-list repair's record — the head and versions
  /// held when the repairing build first ran, and what it reconciled —
  /// without which the restored vault would start that record again from the
  /// archive's head, and reconcile entries the device it came from would
  /// still have reported. Deliberately absent: the publish queue and the
  /// log's timings, which re-derive; a log fault, which the carried head
  /// re-derives; and "this device was removed", which is about the device the
  /// backup was taken on.
  static final Map<String, Future<bool> Function(String, _Ctx)> _stateKeys = {
    'device_id': (v, _) async => _isShortText(v),
    'my_devices': (v, c) => _isOwnCertList(v, c),
    'my_devlist_version': (v, _) async => _isCount(v),
    'own_list_v': (v, _) async => _isCount(v),
    'own_list_h': (v, _) async => _isShortText(v),
    'own_list_json': (v, c) => _isOwnList(v, c),
    'own_list_mlsig': (v, _) async => _isPqListSig(v),
    'devlist_v2_migrated': (v, _) async => v == '1',
    'devlist_v2only_migrated': (v, _) async => v == '1',
    'own_alert': (v, _) async => _isText(v),
    'own_alert_echo': (v, _) async => _isText(v),
    'own_alert_ev': (v, _) async => _isTextList(v, OwnAlarmDismissals.cap),
    'own_alarm_dismissed': (v, _) async =>
        _isTextList(v, OwnAlarmDismissals.cap),
    'kt_config': (v, _) async => _isKtConfig(v),
    'kt_head': (v, _) async => _isJsonMap(v),
    'kt_own_known': (v, _) async => _isVersionMap(v),
    'kt_own_first_v': (v, _) async => _isCount(v),
    'kt_own_alert': (v, _) async => _isJsonMap(v),
    'kt_own_legacy': (v, _) async => _isLegacyRecord(v),
    'kt_own_reconciled': (v, _) async => _isVersionMap(v),
    'push_enabled': (v, _) async => v == '0' || v == '1',
  };

  /// The per-contact `kv` families a `contact` record carries (format minor
  /// 1), under its `kv` member keyed by family: the contact's device list and
  /// the floor it has reached (without which a list stripped of its
  /// ratchet-key signature is admitted again), when it arrived (the log's
  /// grace runs from there), its post-quantum list signature, what its
  /// devices last claimed (so a rollback is still a rollback), the log's
  /// standing for it — including a "send anyway" the user chose — any alarm
  /// not yet dismissed, and when the chat was last opened. Every one is in
  /// `ChatService.contactKvFamilies`, so deleting the contact still removes
  /// it. Not `cextra_`: those are ratchets (see [export]).
  static final Map<String, Future<bool> Function(String, _Ctx, Uint8List)>
      _contactFamilies = {
    'cdev_': (v, _, acct) => _isListOf(v, acct),
    'cdev_ver_': (v, _, __) async => _isCount(v),
    'cdev_at_': (v, _, __) async => _isCount(v),
    'cdev_sigfloor_': (v, _, __) async => _isCount(v),
    'cdev_pq_': (v, _, __) async => _isPqListSig(v),
    'cdev_pq_ver_': (v, _, __) async => _isCount(v),
    'cdl_claims_': (v, _, __) async => _isClaims(v),
    'cdl_alert_': (v, _, __) async => _isText(v),
    'pql_alert_': (v, _, __) async => _isText(v),
    'ktc_': (v, _, __) async => _isJsonMap(v),
    'last_open_': (v, _, __) async => _isCount(v),
  };

  /// The account-level keys a `state` record may carry, for tests and docs.
  static Iterable<String> get stateKeys => _stateKeys.keys;

  /// The per-contact families a `contact` record may carry.
  static Iterable<String> get contactFamilies => _contactFamilies.keys;

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
      minor: ZArchive.minorVersion,
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
      //
      // `account` (phase 31): on a LINKED device, the account this identity
      // is a device of — the account's public keys, this device's
      // certificate, and the device seeds the identity already carries;
      // never the account root, which no device this app links is given and
      // which is left out here even so: a linked device's archive is that
      // device and never more. Without it a restore read the device key as
      // an account root of its own: it signed device lists for a one-device
      // account nobody had, published them to the log under its own key, and
      // every contact who knew it as one of its account's devices saw it
      // claim lists that were not its account's (the 2026-10-03 analysis,
      // P1-8). With it the restore is that linked device again.
      final account = await vault.kvGet('account');
      await record({
        't': 'identity',
        'identity': jsonDecode(idJson),
        if (await vault.kvGet('pq_seed') != null)
          'pq_seed': await vault.kvGet('pq_seed'),
        if (account != null)
          'account': (Map<String, Object?>.from(jsonDecode(account) as Map)
            ..remove('accountEdSeed')),
      });
    }

    // The account's device-list and transparency state (format minor 1):
    // the allow-list and the reason for each key are at [_stateKeys].
    // Written before the contacts so a reader meets the account before the
    // lists its contacts hold for it.
    final state = <String, String>{};
    for (final k in _stateKeys.keys) {
      final v = await vault.kvGet(k);
      if (v != null) state[k] = v;
    }
    // This account's own devices' sessions, as ids only (see below).
    final syncIds = _accountSessionIds(await vault.kvGet('sync_session'));
    await record({
      't': 'state',
      'kv': state,
      if (syncIds.isNotEmpty) 'sync': syncIds,
    });

    // Per-contact state, read once by family rather than once per contact
    // (see `kvScanMany`), and every conversation's session ids.
    final perContact = await vault.kvScanMany(_contactFamilies.keys.toList());
    final extras = await vault.kvScan('cextra_');
    final convIds = <String, List<String>>{};
    for (final row in await vault.db.query('conversations')) {
      try {
        final j = (jsonDecode(await vault.unseal(row['enc_state'] as String))
                as Map)
            .cast<String, Object?>();
        convIds[row['rid'] as String] = _conversationIds(j);
      } catch (_) {
        // An unreadable cell: that conversation's ids are lost, which costs
        // only the replay protection below for it.
      }
    }

    // Contacts, including their v3 state: the commitment from the code that
    // was scanned and the post-quantum key that matched it. Losing those on a
    // restore would silently downgrade every verified contact to classical.
    for (final c in await vault.db.query('contacts')) {
      final rid = c['rid'] as String;
      String? pqPub;
      if (c['enc_pq_pub'] != null) {
        try {
          pqPub = await vault.unseal(c['enc_pq_pub'] as String);
        } catch (_) {
          pqPub = null; // unreadable cell: the key re-arrives in-band
        }
      }
      // ADR 0021: the candidate too. A restore that dropped it would show the
      // classical number again for every contact whose post-quantum half was
      // established by comparison rather than by a scanned commitment, and
      // would ask them to compare a second time for nothing.
      String? pqCand;
      if (c['enc_pq_cand'] != null) {
        try {
          pqCand = await vault.unseal(c['enc_pq_cand'] as String);
        } catch (_) {
          pqCand = null;
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
        if (pqCand != null) 'pqcand': pqCand,
        if ((c['pq_acked'] as int? ?? 0) == 1) 'pqack': 1,
        if ((c['pq_told'] as int? ?? 0) == 1) 'pqtold': 1,
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
        // ADR 0011: a contact this account added and is still waiting on.
        if ((c['requested'] as int? ?? 0) == 1) 'req': 1,
        // Phase 31: what this account knows about the contact's devices and
        // their standing in the log ([_contactFamilies]).
        'kv': {
          for (final f in _contactFamilies.keys)
            if (perContact['$f$rid'] != null) f: perContact['$f$rid'],
        },
        // And the ids — ids only, never a key — of every session this
        // device held with them, live or retired, and with each of their
        // other devices. A session's opening envelope re-derives its keys
        // from the two identities and its own ephemeral alone, so anyone who
        // kept one could replay it to a device that remembered nothing, and
        // the session it opened would be re-created: the message it carried
        // read again, a deleted one restored, and the pair's traffic pinned
        // to a session the peer had moved on from (the 2026-10-03
        // analysis's backup P2). A live device already refuses an opener for
        // a session it retired; a restored one now holds every id it had as
        // retired, so it refuses the same envelopes.
        if (convIds[rid]?.isNotEmpty ?? false) 'sids': convIds[rid],
        if (_accountSessionIds(extras['cextra_$rid']).isNotEmpty)
          'xsids': _accountSessionIds(extras['cextra_$rid']),
      });
    }

    // Groups (stored as one kv blob).
    final groupsJson = await vault.kvGet('groups');
    if (groupsJson != null) {
      await record({'t': 'groups', 'groups': jsonDecode(groupsJson)});
    }

    // ADR 0011: who is blocked, and who is waiting for an answer. A restore
    // that dropped the first let a blocked person reach the user again;
    // one that dropped the second lost a request the user had not yet seen
    // to (the 2026-10-03 analysis's backup P2).
    for (final b in await vault.db.query('blocked')) {
      await record(
          {'t': 'blocked', 'rid': b['rid'], 'created': b['created_ms']});
    }
    for (final q in await vault.db.query('requests')) {
      try {
        await record({
          't': 'request',
          'rid': q['rid'],
          'bundle': jsonDecode(await vault.unseal(q['enc_bundle'] as String)),
          'name': await vault.unseal(q['enc_name'] as String),
          'created': q['created_ms'],
        });
      } catch (_) {
        continue; // unreadable cell: the request re-arrives if they ask again
      }
    }

    // Records an earlier restore could not read and kept because their
    // writer said to: back into the archive as they came, byte for byte.
    final kept = await vault.kvGet(keptKey);
    if (kept != null) {
      for (final text in (jsonDecode(kept) as List).cast<String>()) {
        await frame(ZArchive.kindRecord, utf8.encode(text));
        records++;
      }
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

  /// Every session id a stored conversation knows: the ones it retired,
  /// oldest first, then the ones it holds — last, so they are the last a
  /// bounded list drops (`Conversation.maxRetiredSids`).
  static List<String> _conversationIds(Map<String, Object?> conv) {
    final out = <String>[];
    for (final r in (conv['retired'] as List?) ?? const []) {
      if (r is String && !out.contains(r)) out.add(r);
    }
    final sessions = conv['sessions'];
    if (sessions is Map) {
      for (final k in sessions.keys) {
        if (k is String && !out.contains(k)) out.add(k);
      }
    }
    return out;
  }

  /// The same for an account session — this account's own devices
  /// (`sync_session`) or a contact's other devices (`cextra_<rid>`): per
  /// device, its public bundle and its session ids. Nothing else of the
  /// session is read.
  static Map<String, Object?> _accountSessionIds(String? json) {
    if (json == null) return const {};
    try {
      final convs =
          ((jsonDecode(json) as Map)['convs'] as Map).cast<String, Object?>();
      final out = <String, Object?>{};
      for (final e in convs.entries) {
        final conv = e.value;
        if (conv is! Map) continue;
        final ids = _conversationIds(conv.cast<String, Object?>());
        if (ids.isEmpty || conv['them'] is! Map) continue;
        out[e.key] = {'them': conv['them'], 'sids': ids};
      }
      return out;
    } catch (_) {
      return const {};
    }
  }

  /// A conversation that holds no session and remembers [sids] as retired:
  /// what a restored device keeps of every session the archive names. Built
  /// by the protocol's own reader, so it is the shape any later load
  /// expects, bound included. Its post-quantum clocks are not part of that
  /// shape — nothing stored carries them, and the service tells every
  /// conversation it loads its own (26.2) — and nothing is sent on it here,
  /// so it is built with none.
  static Future<Map<String, Object?>> _retiredOnly(
      ZIdentity me, Object? them, Object? sids) async {
    final conv = await Conversation.fromJson(
        me,
        {
          'them': them,
          'outboundSid': null,
          'sessions': <String, Object?>{},
          'retired': [
            for (final s in (sids as List?) ?? const [])
              if (s is String) s
          ],
        },
        intervals: PqIntervals.disabled);
    return conv.toJson(includeSkipped: false);
  }

  /// An account session of [_retiredOnly] conversations, one per device
  /// [ids] names (as [_accountSessionIds] wrote it). Null when none is
  /// usable.
  static Future<Map<String, Object?>?> _retiredAccountSession(
      ZIdentity me, Object? ids) async {
    if (ids is! Map) return null;
    final convs = <String, Object?>{};
    for (final e in ids.entries) {
      final v = e.value;
      if (e.key is! String || v is! Map) continue;
      try {
        final them = ContactBundle.fromJson((v['them'] as Map).cast());
        if (await them.routingId() != e.key) continue; // not that device
        convs[e.key as String] = await _retiredOnly(me, v['them'], v['sids']);
      } catch (_) {
        continue;
      }
    }
    return convs.isEmpty ? null : {'convs': convs};
  }

  // ---- the shapes a restore insists on --------------------------------------

  static bool _isText(String v) => v.length <= 64 * 1024;
  static bool _isShortText(String v) => v.isNotEmpty && v.length <= 256;
  static bool _isCount(String v) => (int.tryParse(v) ?? -1) >= 0;

  static Object? _json(String v) {
    try {
      return jsonDecode(v);
    } on FormatException {
      return null;
    }
  }

  static bool _isJsonMap(String v) => _json(v) is Map;

  static bool _isVersionMap(String v) {
    final m = _json(v);
    return m is Map &&
        m.entries.every(
            (e) => int.tryParse('${e.key}') != null && e.value is String);
  }

  /// A JSON list of at most [max] short strings: an alarm's evidence keys.
  static bool _isTextList(String v, int max) {
    final l = _json(v);
    return l is List &&
        l.length <= max &&
        l.every((e) => e is String && _isShortText(e));
  }

  /// The own-list repair's record of its first run (`kt_own_legacy`): a
  /// head size and the versions recorded then.
  static bool _isLegacyRecord(String v) {
    final m = _json(v);
    return m is Map &&
        m['size'] is int &&
        (m['size'] as int) >= 0 &&
        m['v'] is List &&
        (m['v'] as List).every((e) => e is int && e >= 0);
  }

  static bool _isKtConfig(String v) {
    final m = _json(v);
    if (m is! Map) return false;
    try {
      final c = KtConfig.fromJson(m.cast<String, Object?>());
      return c.witnessProblem == null;
    } catch (_) {
      return false;
    }
  }

  static bool _isPqListSig(String v) {
    final m = _json(v);
    if (m is! Map) return false;
    try {
      HybridDeviceListSignature.fromJson(m.cast<String, Object?>());
      return true;
    } catch (_) {
      return false;
    }
  }

  static bool _isClaims(String v) {
    final m = _json(v);
    return m is Map &&
        m.values.every((c) =>
            c is Map && c['v'] is num && c['h'] is String && c['mx'] is num);
  }

  /// A signed list for the account [acct]: it parses, names that account and
  /// verifies under it.
  static Future<bool> _isListOf(String v, Uint8List? acct) async {
    final m = _json(v);
    if (m is! Map || acct == null) return false;
    try {
      final list = SignedDeviceList.fromJson(m.cast<String, Object?>());
      return constantTimeEquals(list.accountEdPub, acct) &&
          await list.verify();
    } catch (_) {
      return false;
    }
  }

  static Future<bool> _isOwnList(String v, _Ctx c) => _isListOf(v, c.account);

  /// This account's other devices: certificates its account key signed.
  static Future<bool> _isOwnCertList(String v, _Ctx c) async {
    final l = _json(v);
    final acct = c.account;
    if (l is! List || acct == null) return false;
    try {
      for (final d in l) {
        final cert =
            DeviceCertificate.fromJson((d as Map).cast<String, Object?>());
        if (!await cert.verify(acct)) return false;
      }
      return true;
    } catch (_) {
      return false;
    }
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
      // Phase 31 (format minor 1). The `state` record and each contact's
      // state are judged against the account the identity belongs to, so
      // they are applied after the last record, once that is known; so are
      // the block list and the requests, which name no contact.
      ZIdentity? me;
      Uint8List? accountPub;
      Map<String, Object?>? state;
      final contactAcct = <String, Uint8List>{};
      final contactBundle = <String, Object?>{};
      final contactKv = <String, Map>{};
      final contactSids = <String, Object?>{};
      final contactXsids = <String, Object?>{};
      final blocked = <Map<String, Object?>>[];
      final requests = <Map<String, Object?>>[];
      final kept = <String>[];
      var skipped = 0;

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
          // A frame kind is a major-version matter: a minor revision adds
          // record types inside `kindRecord` frames, never a kind of frame.
          if (kind != ZArchive.kindRecord && kind != ZArchive.kindEnd) {
            throw FormatException('unknown archive frame kind $kind');
          }
          final text = utf8.decode(payload);
          final r = (jsonDecode(text) as Map).cast<String, Object?>();
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
              final idMap = (r['identity'] as Map).cast<String, Object?>();
              me = await ZIdentity.fromJson(idMap);
              accountPub = me!.edPub;
              await kv('identity', jsonEncode(r['identity']));
              if (r['pq_seed'] is String) {
                await kv('pq_seed', r['pq_seed'] as String);
              }
              final account = r['account'];
              if (account != null) {
                // A linked device's backup: the account it is a device of.
                // Checked before it is believed — this record is what keeps
                // the restore from making the device a root of its own, so a
                // record that does not describe THIS identity as a device of
                // THAT account refuses the archive rather than being dropped
                // into exactly that.
                final acct = await AccountIdentity.fromJson(
                    (account as Map).cast<String, Object?>());
                final seed = acct.accountEdSeed;
                final consistent = idMap['edSeed'] == b64(acct.deviceEdSeed) &&
                    idMap['xSeed'] == b64(acct.deviceXSeed) &&
                    constantTimeEquals(
                        acct.deviceCert.deviceEdPub, acct.deviceEdPub) &&
                    constantTimeEquals(
                        acct.deviceCert.deviceXPub, acct.deviceXPub) &&
                    await acct.deviceCert.verify(acct.accountEdPub) &&
                    (seed == null ||
                        constantTimeEquals(
                            (await ZIdentity.fromSeeds(
                                    edSeed: seed, xSeed: acct.deviceXSeed))
                                .edPub,
                            acct.accountEdPub));
                if (!consistent) {
                  throw const FormatException(
                      'the archive names an account its identity is not a '
                      'device of');
                }
                accountPub = acct.accountEdPub;
                await kv('account', jsonEncode(account));
              }
            case 'state':
              state = r;
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
                    if (r['pqcand'] is String)
                      'enc_pq_cand': await vault.seal(r['pqcand'] as String),
                    'pq_acked': (r['pqack'] as num?)?.toInt() ?? 0,
                    'pq_told': (r['pqtold'] as num?)?.toInt() ?? 0,
                    'verified_sn': r['vsn'],
                    'pq_mismatch': (r['pqbad'] as num?)?.toInt() ?? 0,
                    'acct_ed': r['acct'],
                    if (r['cert'] != null) 'dev_cert': jsonEncode(r['cert']),
                    'added_by': r['addedby'],
                    'requested': r['req'] == 1 ? 1 : 0,
                  },
                  conflictAlgorithm: ConflictAlgorithm.replace);
              final rid = r['rid'];
              if (rid is String) {
                final bundle = (r['bundle'] as Map).cast<String, Object?>();
                // The account this contact IS: the one the record names, or
                // — for a contact from a v1 code — its own key (§3.5).
                contactAcct[rid] = r['acct'] is String
                    ? unb64(r['acct'] as String)
                    : unb64(bundle['ed'] as String);
                contactBundle[rid] = bundle;
                if (r['kv'] is Map) contactKv[rid] = r['kv'] as Map;
                if (r['sids'] != null) contactSids[rid] = r['sids'];
                if (r['xsids'] != null) contactXsids[rid] = r['xsids'];
              }
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
            case 'blocked':
              blocked.add(r);
            case 'request':
              requests.add(r);
            default:
              // A record type this build does not know: written by a newer
              // build of this major version. Kept for the next archive when
              // its writer said that is safe ([ZArchive.keepField]) — as the
              // text it arrived as, byte for byte — and skipped otherwise, as
              // every unknown record was before.
              if (r[ZArchive.keepField] == 1) {
                kept.add(text);
              } else {
                skipped++;
              }
          }
        }

        if (!sawEnd) throw ArchiveIncompleteException();

        // Phase 31: the account's state and each contact's, now that the
        // account is known. Every value is held to the shape the code that
        // reads it at start-up needs ([_stateKeys], [_contactFamilies]); one
        // that is not is left out, which costs what it would have restored
        // and nothing else.
        final ctx = _Ctx(accountPub);
        final stateKv = state?['kv'];
        if (stateKv is Map) {
          for (final e in stateKv.entries) {
            final check = _stateKeys[e.key];
            final v = e.value;
            if (check == null || v is! String) continue;
            if (await check(v, ctx)) await kv(e.key as String, v);
          }
        }
        for (final e in contactKv.entries) {
          final rid = e.key;
          for (final f in e.value.entries) {
            final check = _contactFamilies[f.key];
            final v = f.value;
            if (check == null || v is! String) continue;
            if (await check(v, ctx, contactAcct[rid]!)) {
              await kv('${f.key}$rid', v);
            }
          }
        }

        // Every session id the archive names, held as retired by a
        // conversation that has no session (see [export]): the contact's
        // own, each of its other devices', and this account's own devices'.
        final ident = me;
        if (ident != null) {
          final now = DateTime.now().millisecondsSinceEpoch;
          for (final e in contactSids.entries) {
            try {
              final conv =
                  await _retiredOnly(ident, contactBundle[e.key], e.value);
              await txn.insert(
                  'conversations',
                  {
                    'rid': e.key,
                    'enc_state': await vault.seal(jsonEncode(conv)),
                    'updated_ms': now,
                  },
                  conflictAlgorithm: ConflictAlgorithm.replace);
            } catch (_) {
              continue; // a malformed list costs this contact's protection
            }
          }
          for (final e in contactXsids.entries) {
            final session = await _retiredAccountSession(ident, e.value);
            if (session != null) {
              await kv('cextra_${e.key}', jsonEncode(session));
            }
          }
          final sync = await _retiredAccountSession(ident, state?['sync']);
          if (sync != null) await kv('sync_session', jsonEncode(sync));
        }

        // ADR 0011's two lists. Never a contact: adding a blocked id clears
        // the block and accepting a request makes the contact, so a row that
        // names one is not one this account could have held.
        for (final b in blocked) {
          final rid = b['rid'];
          if (rid is! String || !_isShortText(rid)) continue;
          if (contactBundle.containsKey(rid)) continue;
          await txn.insert(
              'blocked',
              {
                'rid': rid,
                'created_ms': (b['created'] as num?)?.toInt() ?? 0,
              },
              conflictAlgorithm: ConflictAlgorithm.replace);
        }
        for (final q in requests) {
          final rid = q['rid'];
          if (rid is! String || contactBundle.containsKey(rid)) continue;
          try {
            final bundle =
                ContactBundle.fromJson((q['bundle'] as Map).cast());
            // As the request was when it arrived: signed by the identity it
            // names. A `.zid` contact is held to the same rule.
            if (!await bundle.verify() || await bundle.routingId() != rid) {
              continue;
            }
            await txn.insert(
                'requests',
                {
                  'rid': rid,
                  'enc_bundle': await vault.seal(jsonEncode(bundle.toJson())),
                  'enc_name': await vault.seal(q['name'] as String? ?? '?'),
                  'created_ms': (q['created'] as num?)?.toInt() ?? 0,
                },
                conflictAlgorithm: ConflictAlgorithm.replace);
          } catch (_) {
            continue;
          }
        }
        if (kept.isNotEmpty) await kv(keptKey, jsonEncode(kept));
        // The first start re-asserts the account before it sends anything.
        await kv(resumeKey, '1');

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
        kept: kept.length,
        skipped: skipped,
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
