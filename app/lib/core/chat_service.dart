import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:z_protocol/z_protocol.dart';

import 'device_sync.dart';
import 'models.dart';
import 'relay_url.dart';
import 'transport.dart';
import 'vault.dart';

const int maxAttachmentBytes = 24 * 1024 * 1024; // fits relay RAM queue caps

/// The orchestrator: owns contacts, protocol conversations, the message
/// store, the outbox, attachments, receipts and disappearing messages.
///
/// Invariants it maintains:
///   1. Ratchet state is persisted (encrypted) BEFORE any ciphertext leaves
///      the device and BEFORE any received plaintext is acted upon.
///   2. The relay ack for an inbound envelope is sent only AFTER the message
///      is safely inside the local encrypted vault.
///   3. Plaintext never touches disk: message bodies, names, metadata and
///      attachment bytes are sealed before insert/write.
class ChatService extends ChangeNotifier {
  final Vault vault;
  final ZIdentity identity;
  final String myRid;
  String displayName;
  final Transport transport;

  final Map<String, Contact> contacts = {};
  final Map<String, Conversation> _convs = {};
  final Map<String, List<ChatMessage>> messagesByChat = {};
  final Map<String, int> unread = {};
  String? openChatRid;

  Timer? _sweeper;
  bool _flushing = false;

  /// Self-sync across my own linked devices. Null until built; inert when I
  /// have no linked devices, so single-device behaviour is unchanged.
  DeviceSyncService? _sync;

  /// M4: per-device sessions with a CONTACT's non-primary devices, plus a map
  /// from those devices' routing ids back to the contact. Both empty for a
  /// single-device contact, so the primary messaging path is unchanged.
  final Map<String, AccountSession> _contactExtras = {};
  final Map<String, String> _extraRidToContact = {};

  /// Per‑conversation async mutex. Ratchet state is a read‑modify‑write on
  /// shared in‑memory state that is NOT protected by the DB transaction, so
  /// every encrypt/decrypt+persist for a given contact must be serialized.
  final Map<String, Future<void>> _locks = {};

  Future<T> _withLock<T>(String rid, Future<T> Function() op) async {
    final prev = _locks[rid] ?? Future<void>.value();
    final done = Completer<void>();
    _locks[rid] = done.future;
    // Wait for the previous holder (ignore its errors — they belong to it).
    await prev.catchError((_) {});
    try {
      return await op();
    } finally {
      done.complete();
      if (identical(_locks[rid], done.future)) _locks.remove(rid);
    }
  }

  ChatService._({
    required this.vault,
    required this.identity,
    required this.myRid,
    required this.displayName,
    required this.transport,
  });

  static Future<ChatService> init({
    required Vault vault,
    required ZIdentity identity,
    required String displayName,
    required Transport transport,
  }) async {
    final svc = ChatService._(
      vault: vault,
      identity: identity,
      myRid: await identity.routingId(),
      displayName: displayName,
      transport: transport,
    );
    await svc._loadContacts();
    await svc._loadConversations();
    await svc._computeUnread();
    await svc._initSync();
    await svc._loadContactDeviceLists();

    transport.onMessage = (m) => unawaited(svc._onInbound(m));
    transport.onDelivered = (r) => unawaited(svc._onDelivered(r));
    transport.onConnected = () => unawaited(svc._onConnected());

    svc._sweeper =
        Timer.periodic(const Duration(seconds: 20), (_) => svc._sweep());
    transport.start();
    return svc;
  }

  @override
  void dispose() {
    _sweeper?.cancel();
    super.dispose();
  }

  // ------------------------------------------------------------------
  // Loading
  // ------------------------------------------------------------------

  Future<void> _loadContacts() async {
    final rows = await vault.db.query('contacts');
    for (final r in rows) {
      final bundle = ContactBundle.fromJson(
          (jsonDecode(await vault.unseal(r['enc_bundle'] as String)) as Map)
              .cast<String, Object?>());
      contacts[r['rid'] as String] = Contact(
        rid: r['rid'] as String,
        bundle: bundle,
        name: await vault.unseal(r['enc_name'] as String),
        ttlSec: r['ttl_seconds'] as int,
        verified: (r['verified'] as int) == 1,
        createdMs: r['created_ms'] as int,
      );
    }
  }

  Future<void> _loadConversations() async {
    final rows = await vault.db.query('conversations');
    for (final r in rows) {
      final rid = r['rid'] as String;
      final contact = contacts[rid];
      if (contact == null) continue;
      final stateJson =
          (jsonDecode(await vault.unseal(r['enc_state'] as String)) as Map)
              .cast<String, Object?>();
      _convs[rid] = await Conversation.fromJson(identity, stateJson);
    }
  }

  Future<void> _computeUnread() async {
    for (final rid in contacts.keys) {
      final lastOpen =
          int.tryParse(await vault.kvGet('last_open_$rid') ?? '0') ?? 0;
      final n = firstIntValue(await vault.db.rawQuery(
              'SELECT COUNT(*) FROM messages WHERE rid = ? AND outgoing = 0 '
              'AND ts_ms > ? AND kind != ?',
              [rid, lastOpen, 'system'])) ??
          0;
      unread[rid] = n;
    }
  }

  Future<Conversation> _convFor(Contact contact) async {
    var conv = _convs[contact.rid];
    if (conv == null) {
      conv = await Conversation.create(identity, contact.bundle);
      _convs[contact.rid] = conv;
    }
    return conv;
  }

  Future<void> _saveConv(String rid, {DatabaseExecutor? txn}) async {
    final conv = _convs[rid];
    if (conv == null) return;
    final sealed = await vault.seal(jsonEncode(conv.toJson()));
    await (txn ?? vault.db).insert(
        'conversations',
        {
          'rid': rid,
          'enc_state': sealed,
          'updated_ms': DateTime.now().millisecondsSinceEpoch,
        },
        conflictAlgorithm: ConflictAlgorithm.replace);
  }

  // ------------------------------------------------------------------
  // Contacts
  // ------------------------------------------------------------------

  Future<String> myContactCode() async =>
      (await identity.bundle(displayName: displayName)).encode();

  Future<Contact> addContactFromCode(String code, {String? alias}) async {
    final bundle = await ContactBundle.decode(code); // verifies signature
    final rid = await bundle.routingId();
    if (rid == myRid) {
      throw const FormatException('that is your own contact code');
    }
    if (contacts.containsKey(rid)) {
      throw FormatException(
          'already in your contacts as "${contacts[rid]!.name}"');
    }
    final name = (alias?.trim().isNotEmpty ?? false)
        ? alias!.trim()
        : (bundle.displayName ?? 'Unknown');
    final contact = Contact(
      rid: rid,
      bundle: bundle,
      name: name,
      createdMs: DateTime.now().millisecondsSinceEpoch,
    );
    await vault.db.insert('contacts', {
      'rid': rid,
      'enc_bundle': await vault.seal(jsonEncode(bundle.toJson())),
      'enc_name': await vault.seal(name),
      'ttl_seconds': 0,
      'verified': 0,
      'created_ms': contact.createdMs,
    });
    contacts[rid] = contact;
    messagesByChat[rid] = [];
    unread[rid] = 0;

    // Open the secure session proactively if this side is the designated
    // initiator; otherwise the first message (ours or theirs) will.
    final conv = await _convFor(contact);
    if (conv.isDesignatedInitiator) {
      await _sendInner(contact, InnerMessage.hello(newMessageId(), _now()));
    }
    notifyListeners();
    return contact;
  }

  Future<void> setVerified(String rid, bool v) async {
    contacts[rid]?.verified = v;
    await vault.db.update('contacts', {'verified': v ? 1 : 0},
        where: 'rid = ?', whereArgs: [rid]);
    notifyListeners();
  }

  Future<void> renameContact(String rid, String name) async {
    final c = contacts[rid];
    if (c == null) return;
    c.name = name;
    await vault.db.update('contacts', {'enc_name': await vault.seal(name)},
        where: 'rid = ?', whereArgs: [rid]);
    notifyListeners();
  }

  Future<void> deleteContact(String rid) async {
    final fids = (await vault.db
            .query('files', columns: ['fid'], where: 'rid = ?', whereArgs: [rid]))
        .map((r) => r['fid'] as String)
        .toList();
    for (final fid in fids) {
      await vault.deleteBlob(fid);
      await vault.db.delete('chunks', where: 'fid = ?', whereArgs: [fid]);
    }
    await vault.db.delete('files', where: 'rid = ?', whereArgs: [rid]);
    await vault.db.delete('messages', where: 'rid = ?', whereArgs: [rid]);
    await vault.db.delete('outbox', where: 'rid = ?', whereArgs: [rid]);
    await vault.db.delete('conversations', where: 'rid = ?', whereArgs: [rid]);
    await vault.db.delete('contacts', where: 'rid = ?', whereArgs: [rid]);
    contacts.remove(rid);
    _convs.remove(rid);
    messagesByChat.remove(rid);
    unread.remove(rid);
    notifyListeners();
  }

  Future<String> safetyNumberWith(String rid) async {
    final c = contacts[rid]!;
    return safetyNumber(identity.edPub, c.bundle.edPub);
  }

  /// Discard all ratchet sessions with this contact and open a fresh one.
  Future<void> resetSecureSession(String rid) async {
    final c = contacts[rid];
    if (c == null) return;
    // Mutating the ratchet must be serialized against in-flight send/receive.
    await _withLock(rid, () async {
      final conv = await _convFor(c);
      conv.resetSessions();
      await _saveConv(rid);
    });
    await _insertSystemMessage(rid, 'Secure session was reset.');
    await _sendInner(c, InnerMessage.hello(newMessageId(), _now()));
    notifyListeners();
  }

  // ------------------------------------------------------------------
  // Sending
  // ------------------------------------------------------------------

  int _now() => DateTime.now().millisecondsSinceEpoch;

  /// Encrypts an inner message, persists ratchet state + outbox atomically,
  /// then kicks the flusher. Returns the message id.
  ///
  /// The whole encrypt→persist sequence runs under the per‑conversation lock
  /// so it can never interleave with another encrypt or with an inbound
  /// decrypt on the same ratchet (which would reuse a message index / key).
  /// If persistence fails, the in‑memory ratchet is rolled back so no send
  /// index is silently skipped.
  Future<String> _sendInner(Contact contact, InnerMessage inner,
      {Future<void> Function(Transaction txn)? also}) async {
    await _withLock(contact.rid, () async {
      final conv = await _convFor(contact);
      final snapshot = jsonEncode(conv.toJson());
      final payload = await conv.encrypt(inner.toBytes());
      try {
        await vault.db.transaction((txn) async {
          await _saveConv(contact.rid, txn: txn);
          await txn.insert('outbox', {
            'id': inner.mid,
            'rid': contact.rid,
            'payload': payload,
            'created_ms': _now(),
          });
          if (also != null) await also(txn);
        });
      } catch (e) {
        _convs[contact.rid] =
            await Conversation.fromJson(identity, jsonDecode(snapshot));
        rethrow;
      }
    });
    unawaited(flushOutbox());
    unawaited(_fanToContactExtras(contact.rid, inner)); // M4: to their extra devices
    return inner.mid;
  }

  Future<void> sendText(String rid, String body) async {
    final contact = contacts[rid]!;
    final ttl = contact.ttlSec;
    final ts = _now();
    final inner = InnerMessage.text(newMessageId(), ts, body, ttlSec: ttl);
    final expireAt = ttl > 0 ? ts + ttl * 1000 : 0;

    await _sendInner(contact, inner, also: (txn) async {
      await txn.insert('messages', {
        'mid': inner.mid,
        'rid': rid,
        'outgoing': 1,
        'kind': 'text',
        'enc_body': await vault.seal(body),
        'ts_ms': ts,
        'status': MsgStatus.pending,
        'expire_at_ms': expireAt,
      });
    });

    _appendLoaded(
        rid,
        ChatMessage(
          mid: inner.mid,
          rid: rid,
          outgoing: true,
          kind: 'text',
          body: body,
          ts: ts,
          status: MsgStatus.pending,
          expireAtMs: expireAt,
        ));
    notifyListeners();
    // Mirror to my own other devices (no-op if none linked).
    unawaited(_sync?.mirror(threadRid: rid, dir: 'out', inner: inner) ??
        Future<void>.value());
  }

  Future<void> sendFile(
      String rid, String fileName, Uint8List bytes, String mime) async {
    if (bytes.length > maxAttachmentBytes) {
      throw const FormatException(
          'attachment too large (max 24 MB in this build)');
    }
    final contact = contacts[rid]!;
    final ttl = contact.ttlSec;
    final ts = _now();
    final km = FileKeyMaterial.generate();
    final chunks = splitChunks(bytes);
    final sha = b64(await sha256Bytes(bytes));

    final inner = InnerMessage(
      kind: 'file',
      mid: newMessageId(),
      ts: ts,
      ttlSec: ttl,
      data: {
        'fid': km.fid,
        'name': fileName,
        'size': bytes.length,
        'mime': mime,
        'sha256': sha,
        'fk': b64(km.fk),
        'fn': b64(km.fn),
        'chunks': chunks.length,
      },
    );
    final expireAt = ttl > 0 ? ts + ttl * 1000 : 0;

    // Local encrypted copy so the sender can re-open their own attachment.
    final keyInfo = await vault.writeBlob(km.fid, bytes);
    final meta = FileMeta(
      fid: km.fid,
      name: fileName,
      size: bytes.length,
      mime: mime,
      sha256b64: sha,
      complete: true,
      gotChunks: chunks.length,
      totalChunks: chunks.length,
    );

    // Pre-encrypt every chunk before the transaction.
    final chunkPayloads = <String>[];
    for (var i = 0; i < chunks.length; i++) {
      chunkPayloads.add(await encryptChunk(km, i, chunks[i]));
    }

    await _sendInner(contact, inner, also: (txn) async {
      await txn.insert('files', {
        'fid': km.fid,
        'rid': rid,
        'mid': inner.mid,
        'enc_meta': await vault.seal(jsonEncode({
          'name': fileName,
          'size': bytes.length,
          'mime': mime,
          'sha256': sha,
          'local': keyInfo,
        })),
        'complete': 1,
        'got_chunks': chunks.length,
        'total_chunks': chunks.length,
      });
      await txn.insert('messages', {
        'mid': inner.mid,
        'rid': rid,
        'outgoing': 1,
        'kind': 'file',
        'enc_body': await vault.seal(jsonEncode({'fid': km.fid})),
        'fid': km.fid,
        'ts_ms': ts,
        'status': MsgStatus.pending,
        'expire_at_ms': expireAt,
      });
      for (final p in chunkPayloads) {
        await txn.insert('outbox', {
          'id': newMessageId(),
          'rid': rid,
          'payload': p,
          'created_ms': _now(),
        });
      }
    });

    _appendLoaded(
        rid,
        ChatMessage(
          mid: inner.mid,
          rid: rid,
          outgoing: true,
          kind: 'file',
          body: fileName,
          fid: km.fid,
          ts: ts,
          status: MsgStatus.pending,
          expireAtMs: expireAt,
          file: meta,
        ));
    notifyListeners();
  }

  Future<void> setDisappearingTimer(String rid, int seconds) async {
    final contact = contacts[rid]!;
    contact.ttlSec = seconds;
    await vault.db.update('contacts', {'ttl_seconds': seconds},
        where: 'rid = ?', whereArgs: [rid]);
    await _insertSystemMessage(
        rid,
        seconds == 0
            ? 'You turned off disappearing messages.'
            : 'You set disappearing messages to ${describeTtl(seconds)}.');
    await _sendInner(
        contact, InnerMessage.timer(newMessageId(), _now(), seconds));
    notifyListeners();
  }

  // ------------------------------------------------------------------
  // Outbox
  // ------------------------------------------------------------------

  Future<void> flushOutbox() async {
    if (_flushing || !transport.isConnected) return;
    _flushing = true;
    try {
      while (true) {
        final rows = await vault.db.query('outbox', orderBy: 'seq', limit: 20);
        if (rows.isEmpty) break;
        for (final row in rows) {
          final id = row['id'] as String;
          final rid = row['rid'] as String;
          try {
            await transport.send(
                to: rid, id: id, payload: row['payload'] as String);
            await vault.db
                .delete('outbox', where: 'seq = ?', whereArgs: [row['seq']]);
            final n = await vault.db.update(
                'messages', {'status': MsgStatus.sent},
                where: 'mid = ? AND rid = ? AND outgoing = 1 AND status = ?',
                whereArgs: [id, rid, MsgStatus.pending]);
            if (n > 0) _updateLoadedStatus(rid, id, MsgStatus.sent);
          } on RelayException catch (e) {
            if (e.message.contains('too_large') ||
                e.message.contains('bad_send')) {
              // Permanent rejection: drop and surface failure.
              await vault.db
                  .delete('outbox', where: 'seq = ?', whereArgs: [row['seq']]);
              await vault.db.update('messages', {'status': -1},
                  where: 'mid = ? AND rid = ?', whereArgs: [id, rid]);
            } else {
              return; // connection trouble: retry on next connect
            }
          }
        }
      }
      notifyListeners();
    } finally {
      _flushing = false;
    }
  }

  Future<void> _onConnected() => flushOutbox();

  // ------------------------------------------------------------------
  // Receiving
  // ------------------------------------------------------------------

  Future<void> _onInbound(RelayInbound m) async {
    // Self-sync from one of my OWN linked devices takes a separate path.
    final sync = _sync;
    if (sync != null && sync.deviceRoutingIds.contains(m.from)) {
      final mirrored = await sync.handleInbound(m.from, m.payload);
      transport.ackReceived(id: m.id, from: m.from);
      if (mirrored != null) {
        await _insertMirrored(mirrored.thread, mirrored.dir, mirrored.inner);
      }
      return;
    }

    // Inbound from a contact's non-primary device (M4).
    final extraContact = _extraRidToContact[m.from];
    if (extraContact != null) {
      await _handleExtraInbound(extraContact, m);
      return;
    }

    // File chunks travel outside the ratchet (sealed under their file key).
    final chunk = tryParseChunk(m.payload);
    if (chunk != null) {
      await _onChunk(m, chunk);
      return;
    }

    final contact = contacts[m.from];
    if (contact == null) {
      // Unknown sender: we do not hold their verified identity bundle, so we
      // cannot authenticate a session. Drop (and free the relay queue).
      transport.ackReceived(id: m.id, from: m.from);
      return;
    }

    // Decrypt + persist run under the per-conversation lock (see _withLock)
    // so they cannot interleave with a concurrent send on the same ratchet.
    // Post-processing (ack, assembly, read receipts, session-reset hello) runs
    // AFTER the lock releases, because it may itself re-enter the lock.
    const int kOk = 0, kUnknownSession = 1, kDropped = 2;
    int status;
    InnerMessage? inner;

    try {
      final (s, parsedInner) =
          await _withLock<(int, InnerMessage?)>(contact.rid, () async {
        final conv = await _convFor(contact);
        final snapshot = jsonEncode(conv.toJson()); // for rollback
        final DecryptResult dec;
        try {
          dec = await conv.decrypt(m.payload);
        } on UnknownSessionException {
          // Their session predates our state (e.g. we restored from backup).
          await _saveConv(contact.rid);
          return (kUnknownSession, null);
        } on RatchetDecryptException {
          // Corrupt / replay: restore state and drop.
          _convs[contact.rid] =
              await Conversation.fromJson(identity, jsonDecode(snapshot));
          return (kDropped, null);
        }

        final parsed = InnerMessage.fromBytes(dec.plaintext);
        final now = _now();
        try {
          await vault.db.transaction((txn) async {
            // Persist the advanced ratchet before acting on content.
            await _saveConv(contact.rid, txn: txn);
            final inserted = await txn.insert(
                'inbox_dedupe',
                {'from_rid': m.from, 'mid': parsed.mid, 'seen_ms': now},
                conflictAlgorithm: ConflictAlgorithm.ignore);
            if (inserted == 0) return; // duplicate resend — already processed
            await _persistInboundKind(txn, contact, parsed, now);
          });
        } catch (_) {
          // Persist failed: roll the in-memory ratchet back so the relay's
          // redelivery can be decrypted again. Do NOT ack.
          _convs[contact.rid] =
              await Conversation.fromJson(identity, jsonDecode(snapshot));
          rethrow;
        }
        return (kOk, parsed);
      });
      status = s;
      inner = parsedInner;
    } catch (_) {
      // Persistence failed and the ratchet was rolled back; leaving the
      // envelope un-acked means the relay will redeliver it.
      return;
    }

    if (status == kUnknownSession) {
      transport.ackReceived(id: m.id, from: m.from);
      await _insertSystemMessage(contact.rid,
          'A message could not be decrypted (session reset). Ask them to resend.');
      await _sendInner(contact, InnerMessage.hello(newMessageId(), _now()));
      notifyListeners();
      return;
    }

    // Processed (or a benign drop/duplicate): the relay may forget the envelope.
    transport.ackReceived(id: m.id, from: m.from);

    if (inner != null) {
      if (inner.kind == 'file') {
        await _tryAssemble(inner.data['fid'] as String);
      }
      if (openChatRid == contact.rid &&
          (inner.kind == 'text' || inner.kind == 'file')) {
        unawaited(_sendReadReceipts(contact.rid));
      }
      if (inner.kind == 'text') {
        // Mirror the received text to my own other devices.
        unawaited(_sync?.mirror(threadRid: contact.rid, dir: 'in', inner: inner) ??
            Future<void>.value());
      }
      if (inner.kind == 'devlist') {
        await _applyDevlistInner(contact, inner); // M4: learn their devices
      }
      notifyListeners();
    }
  }

  /// DB writes + in-memory UI updates for one decrypted inner message.
  /// Runs inside the inbound transaction (and thus the conversation lock).
  Future<void> _persistInboundKind(
      Transaction txn, Contact contact, InnerMessage inner, int now) async {
    switch (inner.kind) {
      case 'text':
        final expireAt = inner.ttlSec > 0 ? now + inner.ttlSec * 1000 : 0;
        await txn.insert(
            'messages',
            {
              'mid': inner.mid,
              'rid': contact.rid,
              'outgoing': 0,
              'kind': 'text',
              'enc_body': await vault.seal(inner.data['body'] as String? ?? ''),
              'ts_ms': now,
              'status': MsgStatus.delivered,
              'expire_at_ms': expireAt,
            },
            conflictAlgorithm: ConflictAlgorithm.ignore);
        _appendLoaded(
            contact.rid,
            ChatMessage(
              mid: inner.mid,
              rid: contact.rid,
              outgoing: false,
              kind: 'text',
              body: inner.data['body'] as String? ?? '',
              ts: now,
              status: MsgStatus.delivered,
              expireAtMs: expireAt,
            ));
        if (openChatRid != contact.rid) {
          unread[contact.rid] = (unread[contact.rid] ?? 0) + 1;
        }
        break;

      case 'file':
        final expireAt = inner.ttlSec > 0 ? now + inner.ttlSec * 1000 : 0;
        final fid = inner.data['fid'] as String;
        await txn.insert(
            'files',
            {
              'fid': fid,
              'rid': contact.rid,
              'mid': inner.mid,
              'enc_meta': await vault.seal(jsonEncode({
                'name': inner.data['name'],
                'size': inner.data['size'],
                'mime': inner.data['mime'],
                'sha256': inner.data['sha256'],
                'fk': inner.data['fk'],
                'fn': inner.data['fn'],
              })),
              'complete': 0,
              'got_chunks': 0,
              'total_chunks': (inner.data['chunks'] as num).toInt(),
            },
            conflictAlgorithm: ConflictAlgorithm.ignore);
        await txn.insert(
            'messages',
            {
              'mid': inner.mid,
              'rid': contact.rid,
              'outgoing': 0,
              'kind': 'file',
              'enc_body': await vault.seal(jsonEncode({'fid': fid})),
              'fid': fid,
              'ts_ms': now,
              'status': MsgStatus.delivered,
              'expire_at_ms': expireAt,
            },
            conflictAlgorithm: ConflictAlgorithm.ignore);
        _appendLoaded(
            contact.rid,
            ChatMessage(
              mid: inner.mid,
              rid: contact.rid,
              outgoing: false,
              kind: 'file',
              body: inner.data['name'] as String? ?? 'file',
              fid: fid,
              ts: now,
              status: MsgStatus.delivered,
              expireAtMs: expireAt,
              file: FileMeta(
                fid: fid,
                name: inner.data['name'] as String? ?? 'file',
                size: (inner.data['size'] as num?)?.toInt() ?? 0,
                mime: inner.data['mime'] as String? ??
                    'application/octet-stream',
                sha256b64: inner.data['sha256'] as String? ?? '',
                totalChunks: (inner.data['chunks'] as num).toInt(),
              ),
            ));
        if (openChatRid != contact.rid) {
          unread[contact.rid] = (unread[contact.rid] ?? 0) + 1;
        }
        break;

      case 'timer':
        final sec = (inner.data['sec'] as num?)?.toInt() ?? 0;
        contact.ttlSec = sec;
        await txn.update('contacts', {'ttl_seconds': sec},
            where: 'rid = ?', whereArgs: [contact.rid]);
        await _insertSystemMessage(
            contact.rid,
            sec == 0
                ? '${contact.name} turned off disappearing messages.'
                : '${contact.name} set disappearing messages to ${describeTtl(sec)}.',
            txn: txn);
        break;

      case 'read':
        final mids = (inner.data['mids'] as List?)?.cast<String>() ?? [];
        for (final mid in mids) {
          await txn.update('messages', {'status': MsgStatus.read},
              where: 'mid = ? AND rid = ? AND outgoing = 1 AND status < ?',
              whereArgs: [mid, contact.rid, MsgStatus.read]);
          _updateLoadedStatus(contact.rid, mid, MsgStatus.read);
        }
        break;

      case 'hello':
      default:
        break; // session bootstrap or unknown-forward-compat: state saved
    }
  }

  Future<void> _onChunk(RelayInbound m, FileChunk chunk) async {
    await vault.db.insert(
        'chunks',
        {'fid': chunk.fid, 'idx': chunk.index, 'payload': m.payload},
        conflictAlgorithm: ConflictAlgorithm.ignore);
    transport.ackReceived(id: m.id, from: m.from);
    await _tryAssemble(chunk.fid);
  }

  Future<void> _tryAssemble(String fid) async {
    final rows =
        await vault.db.query('files', where: 'fid = ?', whereArgs: [fid]);
    if (rows.isEmpty) return; // chunks arrived before the offer — wait
    final row = rows.first;
    if ((row['complete'] as int) == 1) return;

    final total = row['total_chunks'] as int;
    final chunkRows = await vault.db.query('chunks',
        where: 'fid = ?', whereArgs: [fid], orderBy: 'idx');
    final got = chunkRows.length;
    if (got != row['got_chunks']) {
      await vault.db.update('files', {'got_chunks': got},
          where: 'fid = ?', whereArgs: [fid]);
      _updateLoadedFileProgress(row['rid'] as String, fid, got, total, false);
      notifyListeners();
    }
    if (got < total) return;

    final meta =
        (jsonDecode(await vault.unseal(row['enc_meta'] as String)) as Map)
            .cast<String, Object?>();
    final fk = unb64(meta['fk'] as String);
    final fn = unb64(meta['fn'] as String);

    try {
      final parts = <Uint8List>[];
      for (final cr in chunkRows) {
        final fc = tryParseChunk(cr['payload'] as String);
        if (fc == null) throw const FormatException('bad chunk');
        parts.add(await decryptChunk(fk: fk, fn: fn, fid: fid, chunk: fc));
      }
      final assembled =
          Uint8List.fromList(parts.expand((x) => x).toList());
      if (b64(await sha256Bytes(assembled)) != meta['sha256']) {
        throw const FormatException('attachment hash mismatch');
      }
      final keyInfo = await vault.writeBlob(fid, assembled);
      meta['local'] = keyInfo;
      meta.remove('fk');
      meta.remove('fn');
      await vault.db.update(
          'files',
          {
            'enc_meta': await vault.seal(jsonEncode(meta)),
            'complete': 1,
            'got_chunks': total,
          },
          where: 'fid = ?', whereArgs: [fid]);
      await vault.db.delete('chunks', where: 'fid = ?', whereArgs: [fid]);
      _updateLoadedFileProgress(row['rid'] as String, fid, total, total, true);
    } catch (_) {
      await vault.db.delete('chunks', where: 'fid = ?', whereArgs: [fid]);
      await _insertSystemMessage(row['rid'] as String,
          'An attachment failed integrity checks and was discarded.');
    }
    notifyListeners();
  }

  Future<void> _onDelivered(DeliveredReceipt r) async {
    final n = await vault.db.update('messages', {'status': MsgStatus.delivered},
        where: 'mid = ? AND outgoing = 1 AND status < ?',
        whereArgs: [r.id, MsgStatus.delivered]);
    if (n > 0) {
      for (final entry in messagesByChat.entries) {
        _updateLoadedStatus(entry.key, r.id, MsgStatus.delivered,
            onlyUpgrade: true);
      }
      notifyListeners();
    }
  }

  // ------------------------------------------------------------------
  // Read receipts & chat lifecycle
  // ------------------------------------------------------------------

  Future<void> markChatOpened(String rid) async {
    openChatRid = rid;
    unread[rid] = 0;
    await vault.kvPut('last_open_$rid', '${_now()}', sensitive: false);
    await _sendReadReceipts(rid);
    notifyListeners();
  }

  void markChatClosed(String rid) {
    if (openChatRid == rid) openChatRid = null;
  }

  Future<void> _sendReadReceipts(String rid) async {
    final contact = contacts[rid];
    if (contact == null) return;
    final rows = await vault.db.query('messages',
        columns: ['mid'],
        where:
            "rid = ? AND outgoing = 0 AND receipt_sent = 0 AND kind IN ('text','file')",
        whereArgs: [rid]);
    if (rows.isEmpty) return;
    final mids = rows.map((r) => r['mid'] as String).toList();
    await vault.db.update('messages', {'receipt_sent': 1},
        where:
            "rid = ? AND outgoing = 0 AND receipt_sent = 0 AND kind IN ('text','file')",
        whereArgs: [rid]);
    await _sendInner(
        contact, InnerMessage.read(newMessageId(), _now(), mids));
  }

  // ------------------------------------------------------------------
  // Message loading & helpers
  // ------------------------------------------------------------------

  Future<List<ChatMessage>> loadMessages(String rid) async {
    final rows = await vault.db.query('messages',
        where: 'rid = ?', whereArgs: [rid], orderBy: 'ts_ms', limit: 1000);
    final list = <ChatMessage>[];
    for (final r in rows) {
      final kind = r['kind'] as String;
      String body;
      FileMeta? fileMeta;
      if (kind == 'file') {
        final fid = r['fid'] as String;
        fileMeta = await _loadFileMeta(fid);
        body = fileMeta?.name ?? 'file';
      } else {
        body = await vault.unseal(r['enc_body'] as String);
      }
      list.add(ChatMessage(
        mid: r['mid'] as String,
        rid: rid,
        outgoing: (r['outgoing'] as int) == 1,
        kind: kind,
        body: body,
        fid: r['fid'] as String?,
        ts: r['ts_ms'] as int,
        status: r['status'] as int,
        expireAtMs: r['expire_at_ms'] as int,
        file: fileMeta,
      ));
    }
    messagesByChat[rid] = list;
    return list;
  }

  Future<FileMeta?> _loadFileMeta(String fid) async {
    final rows =
        await vault.db.query('files', where: 'fid = ?', whereArgs: [fid]);
    if (rows.isEmpty) return null;
    final r = rows.first;
    final meta = (jsonDecode(await vault.unseal(r['enc_meta'] as String)) as Map)
        .cast<String, Object?>();
    return FileMeta(
      fid: fid,
      name: meta['name'] as String? ?? 'file',
      size: (meta['size'] as num?)?.toInt() ?? 0,
      mime: meta['mime'] as String? ?? 'application/octet-stream',
      sha256b64: meta['sha256'] as String? ?? '',
      complete: (r['complete'] as int) == 1,
      gotChunks: r['got_chunks'] as int,
      totalChunks: r['total_chunks'] as int,
    );
  }

  /// Decrypted attachment bytes (for viewing/saving). Never touches disk in
  /// plaintext.
  Future<Uint8List> readAttachment(String fid) async {
    final rows =
        await vault.db.query('files', where: 'fid = ?', whereArgs: [fid]);
    if (rows.isEmpty) throw StateError('no such attachment');
    final meta = (jsonDecode(await vault.unseal(rows.first['enc_meta'] as String))
            as Map)
        .cast<String, Object?>();
    final local = (meta['local'] as Map?)?.cast<String, Object?>();
    if (local == null) throw StateError('attachment not complete yet');
    return vault.readBlob(fid, local);
  }

  List<ChatSummary> chatSummaries() {
    final out = <ChatSummary>[];
    for (final c in contacts.values) {
      final msgs = messagesByChat[c.rid];
      out.add(ChatSummary(
        contact: c,
        last: (msgs != null && msgs.isNotEmpty) ? msgs.last : null,
        unread: unread[c.rid] ?? 0,
      ));
    }
    out.sort((a, b) {
      final ta = a.last?.ts ?? a.contact.createdMs;
      final tb = b.last?.ts ?? b.contact.createdMs;
      return tb.compareTo(ta);
    });
    return out;
  }

  void _appendLoaded(String rid, ChatMessage msg) {
    final list = messagesByChat.putIfAbsent(rid, () => []);
    // Idempotent: a rolled-back-then-redelivered message must not appear twice.
    if (list.any((m) => m.mid == msg.mid)) return;
    list.add(msg);
  }

  void _updateLoadedStatus(String rid, String mid, int status,
      {bool onlyUpgrade = false}) {
    final list = messagesByChat[rid];
    if (list == null) return;
    for (final m in list) {
      if (m.mid == mid && m.outgoing) {
        if (!onlyUpgrade || status > m.status) m.status = status;
      }
    }
  }

  void _updateLoadedFileProgress(
      String rid, String fid, int got, int total, bool complete) {
    final list = messagesByChat[rid];
    if (list == null) return;
    for (final m in list) {
      if (m.fid == fid && m.file != null) {
        m.file!.gotChunks = got;
        m.file!.totalChunks = total;
        m.file!.complete = complete;
      }
    }
  }

  Future<void> _insertSystemMessage(String rid, String text,
      {DatabaseExecutor? txn}) async {
    final mid = newMessageId();
    final ts = _now();
    await (txn ?? vault.db).insert('messages', {
      'mid': mid,
      'rid': rid,
      'outgoing': 0,
      'kind': 'system',
      'enc_body': await vault.seal(text),
      'ts_ms': ts,
      'status': MsgStatus.delivered,
      'expire_at_ms': 0,
    });
    _appendLoaded(
        rid,
        ChatMessage(
          mid: mid,
          rid: rid,
          outgoing: false,
          kind: 'system',
          body: text,
          ts: ts,
          status: MsgStatus.delivered,
        ));
  }

  // ------------------------------------------------------------------
  // Disappearing messages sweeper
  // ------------------------------------------------------------------

  Future<void> _sweep() async {
    final now = _now();
    final doomed = await vault.db.query('messages',
        where: 'expire_at_ms > 0 AND expire_at_ms <= ?', whereArgs: [now]);
    if (doomed.isEmpty) return;
    for (final r in doomed) {
      final fid = r['fid'] as String?;
      if (fid != null) {
        await vault.deleteBlob(fid);
        await vault.db.delete('files', where: 'fid = ?', whereArgs: [fid]);
        await vault.db.delete('chunks', where: 'fid = ?', whereArgs: [fid]);
      }
    }
    await vault.db.delete('messages',
        where: 'expire_at_ms > 0 AND expire_at_ms <= ?', whereArgs: [now]);
    for (final entry in messagesByChat.entries) {
      entry.value.removeWhere(
          (m) => m.expireAtMs > 0 && m.expireAtMs <= now);
    }
    // Housekeeping: dedupe entries older than 30 days.
    await vault.db.delete('inbox_dedupe',
        where: 'seen_ms < ?', whereArgs: [now - 30 * 24 * 3600 * 1000]);
    notifyListeners();
  }

  // ------------------------------------------------------------------
  // Settings / profile
  // ------------------------------------------------------------------

  Future<void> setDisplayName(String name) async {
    displayName = name;
    await vault.kvPut('display_name', name);
    notifyListeners();
  }

  Future<void> setServerUrl(String url) async {
    final normalized = normalizeRelayUrl(url);
    await vault.kvPut('server_url', normalized, sensitive: false);
    await transport.setServer(normalized);
    notifyListeners();
  }

  // ------------------------------------------------------------------
  // Multi-device: account layer (M-app). Additive — the single-device
  // messaging path above is unchanged. Full cross-device message sync (the
  // fan-out adoption) is a separate step; this establishes the trusted link.
  // ------------------------------------------------------------------

  /// A stable per-install device id.
  Future<String> deviceId() async {
    var id = await vault.kvGet('device_id');
    if (id == null) {
      id = b64url(randomBytes(9));
      await vault.kvPut('device_id', id, sensitive: false);
    }
    return id;
  }

  /// This install's account identity. On a linked (secondary) device the full
  /// account was stored at enrollment; on the primary it derives from the
  /// existing identity (whose keys ARE device #1 of the account).
  Future<AccountIdentity> accountIdentity() async {
    final stored = await vault.kvGet('account');
    if (stored != null) {
      return AccountIdentity.fromJson(
          (jsonDecode(stored) as Map).cast<String, Object?>());
    }
    return AccountIdentity.fromV1(identity, deviceId: await deviceId());
  }

  /// True if this install is a linked secondary device.
  Future<bool> get isLinkedDevice async =>
      (await vault.kvGet('account')) != null;

  /// The v2 account contact code for this account (one device today).
  Future<String> myAccountCode() async =>
      (await accountIdentity()).toAccountBundle(displayName: displayName).encode();

  /// Contacts expressed as account bundles, to hand to a device being linked.
  List<AccountBundle> contactsAsBundles() => [
        for (final c in contacts.values)
          AccountBundle(
            accountEdPub: c.bundle.edPub,
            devices: [
              DeviceCertificate(
                deviceEdPub: c.bundle.edPub,
                deviceXPub: c.bundle.xPub,
                deviceId: 'legacy-v1',
                sig: c.bundle.bindingSig,
                legacy: true,
              )
            ],
            displayName: c.name,
          )
      ];

  /// EXISTING device hosts a link: enter the code shown on the new device,
  /// confirm the safety string, then seal this account + contacts across. On
  /// success, remembers the linked device so messages mirror to it.
  Future<bool> hostDeviceLink(
    String code, {
    required Future<bool> Function(String sas) confirmSas,
  }) async {
    final linked = await RelayPairing.runExistingDevice(
      relayUrl: transport.serverUrl,
      code: PairingCode.parse(code),
      me: await accountIdentity(),
      contacts: contactsAsBundles(),
      includeAccountRoot: false, // the new device cannot enroll further devices
      displayName: displayName,
      confirm: confirmSas,
    );
    if (linked == null) return false;
    await addMyDevice(linked);
    return true;
  }

  // ---- self-sync plumbing -------------------------------------------------

  Future<List<DeviceCertificate>> _myDevices() async {
    final s = await vault.kvGet('my_devices');
    if (s == null) return [];
    return [
      for (final j in (jsonDecode(s) as List))
        DeviceCertificate.fromJson((j as Map).cast<String, Object?>())
    ];
  }

  /// Persist a newly-linked device of MY account and (re)build the sync channel.
  Future<void> addMyDevice(DeviceCertificate cert) async {
    final list = await _myDevices();
    if (!list.any((d) => base64Encode(d.deviceEdPub) == base64Encode(cert.deviceEdPub))) {
      list.add(cert);
      await vault.kvPut('my_devices',
          jsonEncode([for (final d in list) d.toJson()]),
          sensitive: false);
      await vault.kvPut(
          'my_devlist_version', '${(await _myDevlistVersion()) + 1}',
          sensitive: false);
    }
    await _initSync();
    await broadcastMyDeviceList(); // tell contacts about the new device
  }

  /// Revoke a linked device of MY account: drop it from the sync set, bump the
  /// signed-list version, and re-broadcast so contacts stop fanning to it and
  /// reject anything it sends. Only a root-holding device can do this.
  Future<void> removeMyDevice(DeviceCertificate cert) async {
    if (!await holdsAccountRoot()) return;
    final list = await _myDevices();
    final before = list.length;
    list.removeWhere(
        (d) => base64Encode(d.deviceEdPub) == base64Encode(cert.deviceEdPub));
    if (list.length == before) return; // nothing matched
    await vault.kvPut('my_devices',
        jsonEncode([for (final d in list) d.toJson()]),
        sensitive: false);
    await vault.kvPut(
        'my_devlist_version', '${(await _myDevlistVersion()) + 1}',
        sensitive: false);
    await _initSync();
    await broadcastMyDeviceList();
    notifyListeners();
  }

  /// The linked (secondary) devices of my account, if any.
  Future<List<DeviceCertificate>> linkedDevices() async => _myDevices();

  /// This install's own device certificate.
  Future<DeviceCertificate> thisDeviceCert() async =>
      (await accountIdentity()).deviceCert;

  /// Whether this install holds the account root (can sign device lists, and so
  /// can add or revoke devices).
  Future<bool> holdsAccountRoot() async =>
      (await accountIdentity()).holdsAccountRoot;

  Future<void> _initSync() async {
    final devices = await _myDevices();
    if (devices.isEmpty) {
      _sync = null;
      return;
    }
    _sync = DeviceSyncService(
      vault: vault,
      transport: transport,
      account: await accountIdentity(),
      myDevices: devices,
    );
    await _sync!.init();
  }

  /// Insert a message mirrored from one of my other devices (no re-send).
  Future<void> _insertMirrored(String rid, String dir, InnerMessage inner) async {
    if (inner.kind != 'text') return; // attachments don't self-sync yet
    if (!contacts.containsKey(rid)) return;
    final outgoing = dir == 'out';
    final body = inner.data['body'] as String? ?? '';
    final status = outgoing ? MsgStatus.sent : MsgStatus.delivered;
    await vault.db.insert(
      'messages',
      {
        'mid': inner.mid,
        'rid': rid,
        'outgoing': outgoing ? 1 : 0,
        'kind': 'text',
        'enc_body': await vault.seal(body),
        'ts_ms': inner.ts,
        'status': status,
        'expire_at_ms': 0,
      },
      conflictAlgorithm: ConflictAlgorithm.ignore,
    );
    _appendLoaded(
        rid,
        ChatMessage(
          mid: inner.mid,
          rid: rid,
          outgoing: outgoing,
          kind: 'text',
          body: body,
          ts: inner.ts,
          status: status,
          expireAtMs: 0,
        ));
    notifyListeners();
  }

  // ---- M4: contact device-list distribution + fan-out --------------------

  Future<int> _myDevlistVersion() async =>
      int.tryParse(await vault.kvGet('my_devlist_version') ?? '1') ?? 1;

  /// Every device of MY account (this device + linked ones).
  Future<List<DeviceCertificate>> myFullDeviceList() async =>
      [(await accountIdentity()).deviceCert, ...await _myDevices()];

  /// Tell every contact my current device set (account-signed) so they fan
  /// messages out to all my devices and accept from any of them.
  Future<void> broadcastMyDeviceList() async {
    final me = await accountIdentity();
    if (!me.holdsAccountRoot) return; // only a root-holding device can sign
    final list = await me.signDeviceList(
        await myFullDeviceList(), await _myDevlistVersion());
    final data = jsonEncode(list.toJson());
    for (final rid in contacts.keys.toList()) {
      final contact = contacts[rid];
      if (contact == null) continue;
      await _sendInner(
          contact,
          InnerMessage(
              kind: 'devlist',
              mid: newMessageId(),
              ts: _now(),
              data: {'list': data}));
    }
  }

  List<DeviceCertificate> _extrasOf(Contact contact, SignedDeviceList list) => [
        for (final d in list.devices)
          if (base64Encode(d.deviceEdPub) != base64Encode(contact.bundle.edPub))
            d
      ];

  Future<void> _loadContactDeviceLists() async {
    for (final rid in contacts.keys.toList()) {
      final devJson = await vault.kvGet('cdev_$rid');
      final contact = contacts[rid];
      if (devJson == null || contact == null) continue;
      final list = SignedDeviceList.fromJson(
          (jsonDecode(devJson) as Map).cast<String, Object?>());
      await _installContactDeviceList(contact, list, persist: false);
    }
  }

  /// Verify (on receipt), store, and reconcile a contact's device list — adding
  /// newly-learned devices AND dropping revoked ones, so the fan-out set matches
  /// the list exactly.
  Future<void> _installContactDeviceList(
      Contact contact, SignedDeviceList list,
      {required bool persist}) async {
    final rid = contact.rid;
    if (persist) {
      if (base64Encode(list.accountEdPub) !=
          base64Encode(contact.bundle.edPub)) {
        return; // not signed by this contact's account key
      }
      if (!await list.verify()) return;
      final storedVer =
          int.tryParse(await vault.kvGet('cdev_ver_$rid') ?? '0') ?? 0;
      if (list.version < storedVer) return; // stale replay
      await vault.kvPut('cdev_$rid', jsonEncode(list.toJson()),
          sensitive: false);
      await vault.kvPut('cdev_ver_$rid', '${list.version}', sensitive: false);
    }

    final extras = _extrasOf(contact, list);
    final acct = await accountIdentity();
    var session = _contactExtras[rid];
    if (session == null) {
      final stored = await vault.kvGet('cextra_$rid');
      session = stored != null
          ? await AccountSession.fromJson(
              acct, (jsonDecode(stored) as Map).cast<String, Object?>())
          : await AccountSession.create(acct, const []);
      _contactExtras[rid] = session;
    }

    final newRids = <String>{};
    for (final d in extras) {
      newRids.add(await d.routingId());
    }
    for (final r in session.targetRoutingIds.toList()) {
      if (!newRids.contains(r)) session.removeTarget(r); // revoked device
    }
    for (final d in extras) {
      await session.addTarget(DeviceTarget.fromCert(d));
    }
    _extraRidToContact.removeWhere((k, v) => v == rid);
    for (final r in newRids) {
      _extraRidToContact[r] = rid;
    }
    if (persist) await _saveExtra(rid);
  }

  Future<void> _saveExtra(String rid) async {
    final s = _contactExtras[rid];
    if (s != null) {
      await vault.kvPut('cextra_$rid', jsonEncode(s.toJson()), sensitive: false);
    }
  }

  /// Fan a just-sent inner message out to a contact's non-primary devices.
  Future<void> _fanToContactExtras(String rid, InnerMessage inner) async {
    final s = _contactExtras[rid];
    if (s == null || s.targetRoutingIds.isEmpty) return;
    await _withLock(rid, () async {
      try {
        final fan = await s.encrypt(inner.toBytes());
        await _saveExtra(rid);
        for (final f in fan) {
          try {
            await transport.send(
                to: f.routingId, id: newMessageId(), payload: f.payload);
          } catch (_) {}
        }
      } catch (_) {}
    });
  }

  /// Inbound from a contact's non-primary device.
  Future<void> _handleExtraInbound(String rid, RelayInbound m) async {
    final contact = contacts[rid];
    final s = _contactExtras[rid];
    if (contact == null || s == null) {
      transport.ackReceived(id: m.id, from: m.from);
      return;
    }
    InnerMessage? inner;
    await _withLock(rid, () async {
      try {
        final dec = await s.decryptFrom(m.from, m.payload);
        await _saveExtra(rid);
        inner = InnerMessage.fromBytes(dec.plaintext);
      } catch (_) {}
    });
    transport.ackReceived(id: m.id, from: m.from);
    if (inner == null) return;
    if (inner!.kind == 'devlist') {
      await _applyDevlistInner(contact, inner!);
    } else if (inner!.kind == 'text') {
      await _insertMirrored(rid, 'in', inner!);
    }
  }

  Future<void> _applyDevlistInner(Contact contact, InnerMessage inner) async {
    try {
      final list = SignedDeviceList.fromJson(
          (jsonDecode(inner.data['list'] as String) as Map)
              .cast<String, Object?>());
      await _installContactDeviceList(contact, list, persist: true);
    } catch (_) {}
  }

  /// Full local wipe: identity, contacts, messages, keys. Irreversible.
  Future<void> wipeEverything() async {
    await transport.stop();
    await vault.wipe();
  }
}

String describeTtl(int seconds) {
  if (seconds == 0) return 'off';
  if (seconds < 60) return '$seconds seconds';
  if (seconds < 3600) return '${seconds ~/ 60} minutes';
  if (seconds < 86400) return '${seconds ~/ 3600} hours';
  if (seconds < 604800) return '${seconds ~/ 86400} days';
  return '${seconds ~/ 604800} weeks';
}

int? firstIntValue(List<Map<String, Object?>> rows) {
  if (rows.isEmpty) return null;
  final v = rows.first.values.first;
  return v is int ? v : (v is num ? v.toInt() : null);
}
