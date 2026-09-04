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

  /// Hidden Developer-mode toggle — reveals the custom-relay option in Settings.
  /// Persisted in the vault; off by default so normal users never see it.
  bool devMode = false;

  final Map<String, Contact> contacts = {};
  final Map<String, Group> groups = {};
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

  // ---- 7.7a device-list transparency (gossip) ----------------------------
  //
  // Every inner message carries the sender's claim about its own device list
  // ('dl') and an echo of the recipient's ('pdl'). Cross-checking these — with
  // no new infrastructure, inside the existing E2E channel — makes silent
  // device enrolment, split views and silent removal detectable. See
  // docs/adr/0001-key-transparency.md and PROTOCOL.md §3.6.

  /// Grace before a "list changed but never confirmed" observation becomes an
  /// alert: a version bump seen from a contact before the owner's broadcast
  /// arrives is normal for a moment and must not cry wolf. Tests shorten it.
  Duration devlistGrace = const Duration(seconds: 8);

  /// Per-contact banner: their devices disagree, or a list we were handed is
  /// not confirmed by their devices. rid → message. Empty when all clear.
  final Map<String, String> contactDevlistAlerts = {};

  /// Loud alert to the owner: a contact was given a device list for MY account
  /// that this device never issued (T1/T2). Null when clear.
  String? ownAccountAlert;

  /// This device was told by a contact that it was removed from its own
  /// account's device list (T3). Null when clear.
  String? removedDeviceAlert;

  /// Latest claim each of a contact's devices has made about that account's
  /// list: contactRid → deviceRid → (version, fingerprint-b64, max-version-seen).
  final Map<String, Map<String, ({int v, String h, int mx})>> _contactClaims =
      {};

  /// Deferred checks awaiting the grace period. contactRid → first-seen time of
  /// an unconfirmed situation (held newer than any device admits, or a device
  /// claims newer than we hold and the broadcast hasn't arrived).
  final Map<String, DateTime> _pendingContact = {};

  /// Deferred owner-echo checks. source contactRid → (echoed version, fp, seen).
  final Map<String, ({int v, String h, DateTime seen})> _pendingOwnerEcho = {};

  Timer? _devlistTimer;

  /// Sealed sender: routing id → X25519 public key of every device we send
  /// to (contacts, their extra devices, my own linked devices). Every outbound
  /// envelope is sealed to its recipient so the relay never learns who sent
  /// it; a rid we hold no key for falls back to a legacy attributed send.
  final Map<String, Uint8List> _sealKeys = {};

  Future<String> _sealFor(String rid, String payload) async {
    final key = _sealKeys[rid];
    if (key == null) return payload;
    return SealedEnvelope.seal(toXPub: key, fromRid: myRid, payload: payload);
  }

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
    await svc._loadGroups();
    await svc._loadConversations();
    await svc._computeUnread();
    svc.devMode = (await vault.kvGet('dev_mode')) == '1';
    await svc._initSync();
    await svc._loadContactDeviceLists();
    await svc._loadDevlistState();

    transport.onMessage = (m) => unawaited(svc._onInbound(m));
    transport.onDelivered = (r) => unawaited(svc._onDelivered(r));
    transport.onConnected = () => unawaited(svc._onConnected());

    svc._sweeper =
        Timer.periodic(const Duration(seconds: 20), (_) => svc._sweep());
    transport.start();
    return svc;
  }

  bool _disposed = false;

  @override
  void dispose() {
    _disposed = true;
    _sweeper?.cancel();
    _devlistTimer?.cancel();
    super.dispose();
  }

  @override
  void notifyListeners() {
    // Inbound handlers and best-effort receipts can still be in flight when
    // the service is torn down (app shutdown, account switch, tests): their
    // late notifications must be no-ops, not crashes.
    if (_disposed) return;
    super.notifyListeners();
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
      _sealKeys[r['rid'] as String] = bundle.xPub;
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
    for (final rid in [...contacts.keys, ...groups.keys]) {
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
    _sealKeys[rid] = bundle.xPub;
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
    final fids = (await vault.db.query('files',
            columns: ['fid'], where: 'rid = ?', whereArgs: [rid]))
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

  /// v2: true once this device and [rid] share the ML-KEM secret, i.e. every
  /// message from here on is protected against harvest-now-decrypt-later.
  Future<bool> isPostQuantumWith(String rid) async {
    final c = contacts[rid];
    if (c == null) return false;
    return (await _convFor(c)).isPostQuantum;
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
      // v2: if this side owes the peer its post-quantum key offer, it goes
      // out first (silent, ignored by v1 peers).
      final offer = await conv.takePqOfferPayload();
      final offerPayload =
          offer == null ? null : await _sealFor(contact.rid, offer);
      // 7.7a: stamp our device-list claim + an echo of theirs onto the wire.
      await _decorateForWire(inner, contact);
      final payload =
          await _sealFor(contact.rid, await conv.encrypt(inner.toBytes()));
      try {
        await vault.db.transaction((txn) async {
          await _saveConv(contact.rid, txn: txn);
          if (offerPayload != null) {
            await txn.insert('outbox', {
              'id': newMessageId(),
              'rid': contact.rid,
              'payload': offerPayload,
              'created_ms': _now(),
            });
          }
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
    unawaited(
        _fanToContactExtras(contact.rid, inner)); // M4: to their extra devices
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

  /// 7.4: record-and-send convenience — a voice note is an ordinary encrypted
  /// attachment (same keys, chunks, mirroring) whose offer carries `voice` and
  /// `dur`, so receivers render a player instead of a file card.
  Future<void> sendVoiceNote(String rid, Uint8List bytes, int durSec,
          {String mime = 'audio/mp4'}) =>
      sendFile(rid, _voiceNoteName(mime), bytes, mime,
          voice: true, durSec: durSec);

  Future<void> sendFile(
      String rid, String fileName, Uint8List bytes, String mime,
      {bool voice = false, int durSec = 0}) async {
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
        if (voice) 'voice': true,
        if (durSec > 0) 'dur': durSec,
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
      voice: voice,
      durSec: durSec,
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
          if (voice) 'voice': true,
          if (durSec > 0) 'dur': durSec,
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
          // Sealed per recipient; the raw chunk list is reused for the
          // own-device mirror, which seals per device in _syncSend.
          'payload': await _sealFor(rid, p),
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
    // Mirror to my own other devices: the offer (carrying the file key) over
    // the sync ratchet, then the sealed chunks as sidecar payloads they
    // reassemble exactly as a recipient would. No-op when no devices are linked.
    final sync = _sync;
    if (sync != null) {
      unawaited(() async {
        await sync.mirror(threadRid: rid, dir: 'out', inner: inner);
        for (final p in chunkPayloads) {
          await sync.fanChunk(p);
        }
      }());
    }
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
    } on DatabaseException {
      // The vault closed mid-flush (app shutting down). Nothing is lost:
      // unsent rows stay in the durable outbox and the next launch's first
      // connect flushes them. Flush is fire-and-forget, so don't propagate.
      return;
    } finally {
      _flushing = false;
    }
  }

  Future<void> _onConnected() async {
    await flushOutbox();
    await _sync?.prime(); // open the sync ratchet deterministically once online
  }

  // ------------------------------------------------------------------
  // Receiving
  // ------------------------------------------------------------------

  Future<void> _onInbound(RelayInbound m) async {
    // Sealed sender: an envelope with no relay-level sender. Open it with our
    // private key; the sender's routing id lives INSIDE the ciphertext, so the
    // relay never learns who sent what. Acks stay anonymous (m.from is empty),
    // and authenticity is enforced below by the inner ratchet — a forged
    // sender simply fails decryption for that session and is dropped.
    var from = m.from;
    var payload = m.payload;
    if (from.isEmpty) {
      final opened = await SealedEnvelope.open(
          myXSeed: identity.xSeed, myXPub: identity.xPub, blob: payload);
      if (opened == null) {
        transport.ackReceived(id: m.id, from: m.from); // not ours: free RAM
        return;
      }
      from = opened.fromRid;
      payload = opened.payload;
    }

    // File chunks travel outside the ratchet (sealed under their own file key)
    // and may arrive either from a contact or relayed from one of my own
    // devices, so recognise them before any by-sender routing below.
    final chunk = tryParseChunk(payload);
    if (chunk != null) {
      await _onChunk(m, chunk, from, payload);
      return;
    }

    // Self-sync from one of my OWN linked devices takes a separate path.
    final sync = _sync;
    if (sync != null && sync.deviceRoutingIds.contains(from)) {
      final mirrored = await sync.handleInbound(from, payload);
      transport.ackReceived(id: m.id, from: m.from);
      if (mirrored != null) {
        await _insertMirrored(mirrored.thread, mirrored.dir, mirrored.inner);
      }
      return;
    }

    // Inbound from a contact's non-primary device (M4).
    final extraContact = _extraRidToContact[from];
    if (extraContact != null) {
      await _handleExtraInbound(extraContact, from, payload, m);
      return;
    }

    final contact = contacts[from];
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
          dec = await conv.decrypt(payload);
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
        // v2: hearing from the peer for the first time triggers this side's
        // post-quantum key offer; it is queued with the same durability as
        // any message, in the transaction that persists the ratchet.
        final offerPayload = dec.pqOfferPayload == null
            ? null
            : await _sealFor(contact.rid, dec.pqOfferPayload!);
        try {
          await vault.db.transaction((txn) async {
            // Persist the advanced ratchet before acting on content.
            await _saveConv(contact.rid, txn: txn);
            if (offerPayload != null) {
              await txn.insert('outbox', {
                'id': newMessageId(),
                'rid': contact.rid,
                'payload': offerPayload,
                'created_ms': now,
              });
            }
            final inserted = await txn.insert('inbox_dedupe',
                {'from_rid': from, 'mid': parsed.mid, 'seen_ms': now},
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
    unawaited(flushOutbox()); // a queued v2 key offer, if any, goes out now

    if (inner != null) {
      if ((inner.kind == 'file' || inner.kind == 'gfile') &&
          inner.data['fid'] is String) {
        await _tryAssemble(inner.data['fid'] as String);
      }
      if (openChatRid == contact.rid &&
          (inner.kind == 'text' || inner.kind == 'file')) {
        unawaited(_sendReadReceipts(contact.rid));
      }
      if (inner.kind == 'text' ||
          inner.kind == 'file' ||
          inner.kind == 'gmsg' ||
          inner.kind == 'gfile') {
        // E2E delivery receipt. With sealed sender the relay no longer knows
        // whom to notify of delivery, so the recipient tells the sender
        // directly — encrypted, like everything else. Best-effort: if the app
        // dies mid-send the sender simply keeps a single grey tick.
        unawaited(_sendInner(
            contact,
            InnerMessage(kind: 'dlv', mid: newMessageId(), ts: _now(), data: {
              'mids': [inner.mid]
            })).then((_) {}, onError: (_) {}));
      }
      if (inner.kind == 'text' ||
          inner.kind == 'file' ||
          inner.kind == 'gmsg' ||
          inner.kind == 'gfile' ||
          inner.kind == 'ginvite' ||
          inner.kind == 'gleave') {
        // Mirror the received message to my own other devices. For a file this
        // carries the offer (with its file key); the sealed chunks are relayed
        // separately in _onChunk as they arrive. Group traffic mirrors too so
        // linked devices track membership and history.
        unawaited(
            _sync?.mirror(threadRid: contact.rid, dir: 'in', inner: inner) ??
                Future<void>.value());
      }
      if (inner.kind == 'devlist') {
        await _applyDevlistInner(contact, inner); // M4: learn their devices
      }
      if (inner.kind == 'dlrm') {
        await _handleRemovalNotice(
            inner); // 7.7a: I was removed from my account
      }
      // 7.7a: cross-check the device-list claim/echo on EVERY inbound. Runs
      // after any devlist install above so the "held" list is current.
      await _observeDevlistGossip(contact.rid, contact.rid, inner);
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
        await _persistFileOffer(txn, contact.rid, inner, now,
            expireAt: inner.ttlSec > 0 ? now + inner.ttlSec * 1000 : 0);
        break;

      case 'gfile':
        await _persistGroupFile(contact, inner, now, txn: txn);
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

      case 'dlv':
        // E2E delivery receipt (replaces the relay's receipt under sealed
        // sender): mark those outgoing messages delivered, wherever they live.
        final dlvMids = (inner.data['mids'] as List?)?.cast<String>() ?? [];
        for (final mid in dlvMids) {
          await txn.update('messages', {'status': MsgStatus.delivered},
              where: 'mid = ? AND outgoing = 1 AND status < ?',
              whereArgs: [mid, MsgStatus.delivered]);
          for (final e in messagesByChat.entries) {
            _updateLoadedStatus(e.key, mid, MsgStatus.delivered,
                onlyUpgrade: true);
          }
        }
        break;

      case 'gmsg':
        await _persistGroupText(contact, inner, now, txn: txn);
        break;

      case 'ginvite':
        await _applyGroupInvite(contact.rid, inner.data, txn: txn);
        break;

      case 'gleave':
        await _applyGroupLeave(contact.rid, inner.data, txn: txn);
        break;

      case 'hello':
      default:
        break; // session bootstrap or unknown-forward-compat: state saved
    }
  }

  /// Record an inbound attachment offer (the file key rides inside it) and
  /// its placeholder message in thread [threadRid] — a contact's routing id
  /// for a direct message, a gid for a group. Chunks are thread-agnostic: they
  /// are matched to the offer by fid when they arrive (see [_onChunk]).
  Future<void> _persistFileOffer(
      DatabaseExecutor txn, String threadRid, InnerMessage inner, int now,
      {int expireAt = 0, String? senderName}) async {
    final fid = inner.data['fid'] as String;
    final name = inner.data['name'] as String? ?? 'file';
    final voice = inner.data['voice'] == true;
    final durSec = (inner.data['dur'] as num?)?.toInt() ?? 0;
    await txn.insert(
        'files',
        {
          'fid': fid,
          'rid': threadRid,
          'mid': inner.mid,
          'enc_meta': await vault.seal(jsonEncode({
            'name': name,
            'size': inner.data['size'],
            'mime': inner.data['mime'],
            'sha256': inner.data['sha256'],
            'fk': inner.data['fk'],
            'fn': inner.data['fn'],
            if (voice) 'voice': true,
            if (durSec > 0) 'dur': durSec,
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
          'rid': threadRid,
          'outgoing': 0,
          'kind': 'file',
          'enc_body': await vault.seal(jsonEncode({
            'fid': fid,
            if (senderName != null) 'sn': senderName,
          })),
          'fid': fid,
          'ts_ms': now,
          'status': MsgStatus.delivered,
          'expire_at_ms': expireAt,
        },
        conflictAlgorithm: ConflictAlgorithm.ignore);
    _appendLoaded(
        threadRid,
        ChatMessage(
          mid: inner.mid,
          rid: threadRid,
          outgoing: false,
          kind: 'file',
          body: name,
          fid: fid,
          ts: now,
          status: MsgStatus.delivered,
          expireAtMs: expireAt,
          senderName: senderName,
          file: FileMeta(
            fid: fid,
            name: name,
            size: (inner.data['size'] as num?)?.toInt() ?? 0,
            mime: inner.data['mime'] as String? ?? 'application/octet-stream',
            sha256b64: inner.data['sha256'] as String? ?? '',
            totalChunks: (inner.data['chunks'] as num).toInt(),
            voice: voice,
            durSec: durSec,
          ),
        ));
    if (openChatRid != threadRid) {
      unread[threadRid] = (unread[threadRid] ?? 0) + 1;
    }
  }

  /// A group attachment offer from [contact]: same membership rule as a group
  /// text (unknown group, left group or non-member sender → silent drop).
  Future<void> _persistGroupFile(Contact contact, InnerMessage inner, int now,
      {DatabaseExecutor? txn}) async {
    final gid = inner.data['gid'] as String?;
    final g = gid == null ? null : groups[gid];
    if (g == null || g.left || !g.memberRids.contains(contact.rid)) return;
    if (inner.data['fid'] is! String || inner.data['chunks'] is! num) return;
    await _persistFileOffer(txn ?? vault.db, gid!, inner, now,
        senderName: contact.name);
  }

  Future<void> _onChunk(
      RelayInbound m, FileChunk chunk, String from, String payload) async {
    await vault.db.insert(
        'chunks', {'fid': chunk.fid, 'idx': chunk.index, 'payload': payload},
        conflictAlgorithm: ConflictAlgorithm.ignore);
    transport.ackReceived(id: m.id, from: m.from);
    // Relay a contact's chunk to my own other devices so the attachment lands
    // there too. Skip chunks that were themselves relayed from one of my
    // devices (matched on the OPENED sender), so the fan-out can't loop.
    final sync = _sync;
    if (sync != null && !sync.deviceRoutingIds.contains(from)) {
      unawaited(sync.fanChunk(payload));
    }
    await _tryAssemble(chunk.fid);
  }

  /// Assemble [fid] if the offer and every chunk are present. Serialized per
  /// fid: the offer's post-processing and the last chunk's arrival both call
  /// this, often within a millisecond of each other, and two concurrent
  /// assemblies each wrote the blob under a fresh random key — leaving the
  /// stored key and the bytes on disk from different runs, i.e. an
  /// attachment that could never be opened. Under the lock the second caller
  /// sees `complete = 1` and returns.
  Future<void> _tryAssemble(String fid) =>
      _withLock('assemble:$fid', () => _tryAssembleLocked(fid));

  Future<void> _tryAssembleLocked(String fid) async {
    final rows =
        await vault.db.query('files', where: 'fid = ?', whereArgs: [fid]);
    if (rows.isEmpty) return; // chunks arrived before the offer — wait
    final row = rows.first;
    if ((row['complete'] as int) == 1) return;

    final total = row['total_chunks'] as int;
    final chunkRows = await vault.db
        .query('chunks', where: 'fid = ?', whereArgs: [fid], orderBy: 'idx');
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
      final assembled = Uint8List.fromList(parts.expand((x) => x).toList());
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
          where: 'fid = ?',
          whereArgs: [fid]);
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
    await _sendInner(contact, InnerMessage.read(newMessageId(), _now(), mids));
  }

  // ------------------------------------------------------------------
  // Message loading & helpers
  // ------------------------------------------------------------------

  /// Window size for chat history paging (Phase 4.3): opening a 50k-message
  /// thread costs the same as a 60-message one; older pages load on scroll.
  static const int messagePageSize = 60;

  /// rid → whether older messages exist beyond what's loaded in memory.
  final Map<String, bool> hasMoreByChat = {};

  Future<ChatMessage> _rowToMessage(String rid, Map<String, Object?> r) async {
    final kind = r['kind'] as String;
    String body;
    String? senderName;
    FileMeta? fileMeta;
    if (kind == 'file') {
      final fid = r['fid'] as String;
      fileMeta = await _loadFileMeta(fid);
      body = fileMeta?.name ?? 'file';
      try {
        final j =
            (jsonDecode(await vault.unseal(r['enc_body'] as String)) as Map)
                .cast<String, Object?>();
        senderName = j['sn'] as String?; // set for group attachments
      } catch (_) {}
    } else if (kind == 'gtext') {
      final j = (jsonDecode(await vault.unseal(r['enc_body'] as String)) as Map)
          .cast<String, Object?>();
      body = j['b'] as String? ?? '';
      senderName = j['sn'] as String?;
    } else {
      body = await vault.unseal(r['enc_body'] as String);
    }
    return ChatMessage(
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
      senderName: senderName,
    );
  }

  /// Load the NEWEST page of a thread. Older history stays on disk until
  /// [loadOlderMessages] pulls it in.
  Future<List<ChatMessage>> loadMessages(String rid) async {
    final rows = await vault.db.query('messages',
        where: 'rid = ?',
        whereArgs: [rid],
        orderBy: 'ts_ms DESC',
        limit: messagePageSize + 1);
    hasMoreByChat[rid] = rows.length > messagePageSize;
    final list = <ChatMessage>[];
    for (final r in rows.take(messagePageSize).toList().reversed) {
      list.add(await _rowToMessage(rid, r));
    }
    messagesByChat[rid] = list;
    return list;
  }

  /// Prepend the next (older) page of a thread. Returns how many messages
  /// were added; 0 means the full history is already loaded.
  Future<int> loadOlderMessages(String rid) async {
    final current = messagesByChat[rid];
    if (current == null || current.isEmpty || hasMoreByChat[rid] != true) {
      return 0;
    }
    final oldestTs = current.first.ts;
    final rows = await vault.db.query('messages',
        where: 'rid = ? AND ts_ms < ?',
        whereArgs: [rid, oldestTs],
        orderBy: 'ts_ms DESC',
        limit: messagePageSize + 1);
    hasMoreByChat[rid] = rows.length > messagePageSize;
    final have = current.map((m) => m.mid).toSet();
    final older = <ChatMessage>[];
    for (final r in rows.take(messagePageSize).toList().reversed) {
      final msg = await _rowToMessage(rid, r);
      if (!have.contains(msg.mid)) older.add(msg);
    }
    current.insertAll(0, older);
    notifyListeners();
    return older.length;
  }

  Future<FileMeta?> _loadFileMeta(String fid) async {
    final rows =
        await vault.db.query('files', where: 'fid = ?', whereArgs: [fid]);
    if (rows.isEmpty) return null;
    final r = rows.first;
    final meta =
        (jsonDecode(await vault.unseal(r['enc_meta'] as String)) as Map)
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
      voice: meta['voice'] == true,
      durSec: (meta['dur'] as num?)?.toInt() ?? 0,
    );
  }

  /// Decrypted attachment bytes (for viewing/saving). Never touches disk in
  /// plaintext.
  Future<Uint8List> readAttachment(String fid) async {
    final rows =
        await vault.db.query('files', where: 'fid = ?', whereArgs: [fid]);
    if (rows.isEmpty) throw StateError('no such attachment');
    final meta =
        (jsonDecode(await vault.unseal(rows.first['enc_meta'] as String))
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
    for (final g in groups.values) {
      final msgs = messagesByChat[g.gid];
      out.add(ChatSummary(
        group: g,
        last: (msgs != null && msgs.isNotEmpty) ? msgs.last : null,
        unread: unread[g.gid] ?? 0,
      ));
    }
    out.sort((a, b) {
      final ta = a.last?.ts ?? a.contact?.createdMs ?? 0;
      final tb = b.last?.ts ?? b.contact?.createdMs ?? 0;
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
      entry.value.removeWhere((m) => m.expireAtMs > 0 && m.expireAtMs <= now);
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

  Future<void> setDevMode(bool v) async {
    devMode = v;
    await vault.kvPut('dev_mode', v ? '1' : '0', sensitive: false);
    notifyListeners();
  }

  /// Re-attempt a permanently-failed outgoing message (status -1). The text is
  /// re-encrypted and re-queued to the durable outbox under its original id, so
  /// the recipient still de-duplicates it. Non-text failures can only be
  /// dismissed with [deleteMessage].
  Future<bool> retryFailedSend(String rid, String mid) async {
    final contact = contacts[rid];
    if (contact == null) return false;
    final rows = await vault.db.query('messages',
        where: 'rid = ? AND mid = ? AND outgoing = 1', whereArgs: [rid, mid]);
    if (rows.isEmpty) return false;
    final row = rows.first;
    if ((row['status'] as int) != -1 || row['kind'] != 'text') return false;
    final body = await vault.unseal(row['enc_body'] as String);
    await vault.db.update('messages', {'status': MsgStatus.pending},
        where: 'rid = ? AND mid = ?', whereArgs: [rid, mid]);
    _updateLoadedStatus(rid, mid, MsgStatus.pending);
    notifyListeners();
    await _sendInner(contact, InnerMessage.text(mid, _now(), body));
    return true;
  }

  /// Remove a single message from this device (local only).
  Future<void> deleteMessage(String rid, String mid) async {
    await vault.db.delete('messages',
        where: 'rid = ? AND mid = ?', whereArgs: [rid, mid]);
    messagesByChat[rid]?.removeWhere((m) => m.mid == mid);
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
  Future<String> myAccountCode() async => (await accountIdentity())
      .toAccountBundle(displayName: displayName)
      .encode();

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
    if (!list.any(
        (d) => base64Encode(d.deviceEdPub) == base64Encode(cert.deviceEdPub))) {
      list.add(cert);
      await vault.kvPut(
          'my_devices', jsonEncode([for (final d in list) d.toJson()]),
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
    await vault.kvPut(
        'my_devices', jsonEncode([for (final d in list) d.toJson()]),
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
    for (final d in devices) {
      _sealKeys[await d.routingId()] = d.deviceXPub; // seal self-sync too
    }
    if (devices.isEmpty) {
      _sync = null;
      return;
    }
    _sync = DeviceSyncService(
      vault: vault,
      reliableSend: _syncSend,
      account: await accountIdentity(),
      myDevices: devices,
    );
    await _sync!.init();
  }

  /// Reliable send for the self-sync channel: enqueue to the durable outbox and
  /// flush, so a mirrored message or file chunk gets the same relay-backed,
  /// retried delivery the contact path has — never dropped to a race or a brief
  /// disconnect.
  Future<void> _syncSend(String toRid, String payload) async {
    await vault.db.insert('outbox', {
      'id': newMessageId(),
      'rid': toRid,
      'payload': await _sealFor(toRid, payload),
      'created_ms': _now(),
    });
    unawaited(flushOutbox());
  }

  /// Insert a message mirrored from one of my other devices (no re-send).
  Future<void> _insertMirrored(
      String rid, String dir, InnerMessage inner) async {
    // 7.7a rule 8: my root device self-synced the account's latest signed list.
    // Learn it so this device's own-account version keeps pace and an echo of a
    // rogue list stands out.
    if (dir == 'acct') {
      await _applyOwnDeviceList(inner);
      return;
    }
    final outgoing = dir == 'out';
    // Group kinds route by the gid inside the payload, and an invite may
    // introduce contacts this device doesn't hold yet — so handle them before
    // the contacts guard below.
    if (inner.kind == 'ginvite') {
      await _applyGroupInvite(outgoing ? '' : rid, inner.data,
          mirroredOwn: outgoing);
      notifyListeners();
      return;
    }
    if (inner.kind == 'gleave') {
      if (outgoing) {
        final g = groups[inner.data['gid'] as String? ?? ''];
        if (g != null && !g.left) {
          g.left = true;
          await _saveGroups();
          await _insertSystemMessage(g.gid, 'You left the group.');
        }
      } else {
        await _applyGroupLeave(rid, inner.data);
      }
      notifyListeners();
      return;
    }
    if (inner.kind == 'gmsg') {
      final gid = inner.data['gid'] as String?;
      final g = gid == null ? null : groups[gid];
      if (g == null) return;
      if (outgoing) {
        // My own group send, made on another of my devices.
        final body = inner.data['body'] as String? ?? '';
        await vault.db.insert(
            'messages',
            {
              'mid': inner.mid,
              'rid': gid,
              'outgoing': 1,
              'kind': 'gtext',
              'enc_body': await vault.seal(jsonEncode({'b': body})),
              'ts_ms': inner.ts,
              'status': MsgStatus.sent,
              'expire_at_ms': 0,
            },
            conflictAlgorithm: ConflictAlgorithm.ignore);
        _appendLoaded(
            gid!,
            ChatMessage(
              mid: inner.mid,
              rid: gid,
              outgoing: true,
              kind: 'gtext',
              body: body,
              ts: inner.ts,
              status: MsgStatus.sent,
            ));
      } else {
        final c = contacts[rid];
        if (c != null) await _persistGroupText(c, inner, inner.ts);
      }
      notifyListeners();
      return;
    }
    if (inner.kind == 'gfile') {
      final gid = inner.data['gid'] as String?;
      final g = gid == null ? null : groups[gid];
      if (g == null || inner.data['fid'] is! String) return;
      if (outgoing) {
        // My own group attachment, sent from another of my devices: the
        // offer lands in the group thread; the sidecar chunks follow by fid.
        await _insertMirroredFile(gid!, true, inner);
      } else {
        final c = contacts[rid];
        if (c != null) {
          await _persistGroupFile(c, inner, inner.ts);
          notifyListeners();
          await _tryAssemble(inner.data['fid'] as String);
        }
      }
      return;
    }
    if (!contacts.containsKey(rid)) return;
    if (inner.kind == 'file') {
      await _insertMirroredFile(rid, outgoing, inner);
      return;
    }
    if (inner.kind != 'text') return; // only text/file/group self-sync
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

  /// A mirrored file offer from one of my own devices: record the offer (with
  /// its file key, so the sidecar chunks can be assembled) and a placeholder
  /// message, then try to assemble in case those chunks already arrived.
  Future<void> _insertMirroredFile(
      String rid, bool outgoing, InnerMessage inner) async {
    final fid = inner.data['fid'] as String?;
    if (fid == null) return;
    final name = inner.data['name'] as String? ?? 'file';
    final total = (inner.data['chunks'] as num?)?.toInt() ?? 0;
    final voice = inner.data['voice'] == true;
    final durSec = (inner.data['dur'] as num?)?.toInt() ?? 0;
    final status = outgoing ? MsgStatus.sent : MsgStatus.delivered;
    await vault.db.insert(
      'files',
      {
        'fid': fid,
        'rid': rid,
        'mid': inner.mid,
        'enc_meta': await vault.seal(jsonEncode({
          'name': name,
          'size': inner.data['size'],
          'mime': inner.data['mime'],
          'sha256': inner.data['sha256'],
          'fk': inner.data['fk'],
          'fn': inner.data['fn'],
          if (voice) 'voice': true,
          if (durSec > 0) 'dur': durSec,
        })),
        'complete': 0,
        'got_chunks': 0,
        'total_chunks': total,
      },
      conflictAlgorithm: ConflictAlgorithm.ignore,
    );
    await vault.db.insert(
      'messages',
      {
        'mid': inner.mid,
        'rid': rid,
        'outgoing': outgoing ? 1 : 0,
        'kind': 'file',
        'enc_body': await vault.seal(jsonEncode({'fid': fid})),
        'fid': fid,
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
          kind: 'file',
          body: name,
          fid: fid,
          ts: inner.ts,
          status: status,
          expireAtMs: 0,
          file: FileMeta(
            fid: fid,
            name: name,
            size: (inner.data['size'] as num?)?.toInt() ?? 0,
            mime: inner.data['mime'] as String? ?? 'application/octet-stream',
            sha256b64: inner.data['sha256'] as String? ?? '',
            totalChunks: total,
            voice: voice,
            durSec: durSec,
          ),
        ));
    notifyListeners();
    await _tryAssemble(fid); // sidecar chunks may already be here
  }

  // ------------------------------------------------------------------
  // Groups — pairwise-encrypted fan-out over the existing 1:1 ratchets.
  //
  // Every group message is individually end-to-end encrypted to each member
  // over the already-established, authenticated pairwise conversation, with
  // the group id inside the plaintext. There is NO shared group key, so
  // removing a member needs no rekey: senders simply stop sending to them,
  // and anything they send is rejected by the membership check. The creator
  // is the admin; membership updates are applied only when they arrive over
  // the admin's channel with a higher version. Invites carry every member's
  // signature-verified key bundle, so members who aren't each other's
  // contacts yet are added automatically (unverified, verifiable later).
  // ------------------------------------------------------------------

  Future<void> _loadGroups() async {
    final s = await vault.kvGet('groups');
    if (s == null) return;
    for (final j in (jsonDecode(s) as List)) {
      final g = Group.fromJson((j as Map).cast<String, Object?>());
      groups[g.gid] = g;
    }
  }

  /// Persist all groups. Matches the vault's sensitive-kv format so it can be
  /// written inside an inbound transaction (kvPut cannot take a txn).
  Future<void> _saveGroups({DatabaseExecutor? txn}) async {
    final v = await vault
        .seal(jsonEncode([for (final g in groups.values) g.toJson()]));
    await (txn ?? vault.db).insert('kv', {'k': 's:groups', 'v': v},
        conflictAlgorithm: ConflictAlgorithm.replace);
  }

  /// The invite payload for [g]: name, membership version, and every member's
  /// verified bundle (including mine), so recipients can auto-add anyone they
  /// don't know and detect their own removal.
  Future<Map<String, Object?>> _inviteData(Group g) async => {
        'gid': g.gid,
        'name': g.name,
        'ver': g.ver,
        'members': [
          {
            'b': (await identity.bundle(displayName: displayName)).toJson(),
            'n': displayName,
          },
          for (final rid in g.memberRids)
            if (contacts[rid] != null)
              {
                'b': contacts[rid]!.bundle.toJson(),
                'n': contacts[rid]!.name,
              }
        ],
      };

  Future<void> _fanGroupInner(Group g, InnerMessage inner) async {
    for (final rid in g.memberRids.toList()) {
      final c = contacts[rid];
      if (c != null) await _sendInner(c, inner);
    }
  }

  /// Create a group with [memberRids] (existing contacts) and invite them.
  Future<String> createGroup(String name, List<String> memberRids) async {
    final gid = 'g${b64url(randomBytes(12))}';
    final g = Group(
      gid: gid,
      name: name,
      adminRid: '', // I am the admin
      memberRids: memberRids.toSet()..remove(myRid),
    );
    groups[gid] = g;
    await _saveGroups();
    unread[gid] = 0;
    await _insertSystemMessage(gid, 'You created "$name".');
    final inner = InnerMessage(
        kind: 'ginvite',
        mid: newMessageId(),
        ts: _now(),
        data: await _inviteData(g));
    await _fanGroupInner(g, inner);
    unawaited(_sync?.mirror(threadRid: gid, dir: 'out', inner: inner) ??
        Future<void>.value());
    notifyListeners();
    return gid;
  }

  /// Admin only: add members and re-invite everyone at a higher version.
  Future<void> addGroupMembers(String gid, List<String> rids) async {
    final g = groups[gid];
    if (g == null || !g.iAmAdmin || g.left) return;
    final added = rids.where((r) => !g.memberRids.contains(r)).toList();
    if (added.isEmpty) return;
    g.memberRids.addAll(added);
    g.ver += 1;
    await _saveGroups();
    final names = added.map((r) => contacts[r]?.name ?? 'someone').join(', ');
    await _insertSystemMessage(gid, 'You added $names.');
    final inner = InnerMessage(
        kind: 'ginvite',
        mid: newMessageId(),
        ts: _now(),
        data: await _inviteData(g));
    await _fanGroupInner(g, inner);
    unawaited(_sync?.mirror(threadRid: gid, dir: 'out', inner: inner) ??
        Future<void>.value());
    notifyListeners();
  }

  /// Admin only: remove a member. Remaining members get the new list; the
  /// removed member's next invite omits them, which their app reads as
  /// removal. Either way, everyone else now rejects what they send.
  Future<void> removeGroupMember(String gid, String rid) async {
    final g = groups[gid];
    if (g == null || !g.iAmAdmin || g.left) return;
    if (!g.memberRids.remove(rid)) return;
    g.ver += 1;
    await _saveGroups();
    await _insertSystemMessage(
        gid, 'You removed ${contacts[rid]?.name ?? 'a member'}.');
    final inner = InnerMessage(
        kind: 'ginvite',
        mid: newMessageId(),
        ts: _now(),
        data: await _inviteData(g));
    await _fanGroupInner(g, inner);
    // Tell the removed member too, so their app marks the group as left.
    final removed = contacts[rid];
    if (removed != null) await _sendInner(removed, inner);
    unawaited(_sync?.mirror(threadRid: gid, dir: 'out', inner: inner) ??
        Future<void>.value());
    notifyListeners();
  }

  /// Leave a group: everyone is told directly (authenticated by the pairwise
  /// channel), and the local copy is kept read-only for history.
  Future<void> leaveGroup(String gid) async {
    final g = groups[gid];
    if (g == null || g.left) return;
    g.left = true;
    await _saveGroups();
    await _insertSystemMessage(gid, 'You left the group.');
    final inner = InnerMessage(
        kind: 'gleave', mid: newMessageId(), ts: _now(), data: {'gid': gid});
    await _fanGroupInner(g, inner);
    unawaited(_sync?.mirror(threadRid: gid, dir: 'out', inner: inner) ??
        Future<void>.value());
    notifyListeners();
  }

  /// Send a text to every member of [gid], each over their pairwise ratchet.
  Future<void> sendGroupText(String gid, String body) async {
    final g = groups[gid];
    if (g == null || g.left) return;
    final ts = _now();
    final inner = InnerMessage(
        kind: 'gmsg',
        mid: newMessageId(),
        ts: ts,
        data: {'gid': gid, 'body': body});
    await vault.db.insert('messages', {
      'mid': inner.mid,
      'rid': gid,
      'outgoing': 1,
      'kind': 'gtext',
      'enc_body': await vault.seal(jsonEncode({'b': body})),
      'ts_ms': ts,
      'status': MsgStatus.pending,
      'expire_at_ms': 0,
    });
    _appendLoaded(
        gid,
        ChatMessage(
          mid: inner.mid,
          rid: gid,
          outgoing: true,
          kind: 'gtext',
          body: body,
          ts: ts,
          status: MsgStatus.pending,
        ));
    notifyListeners();
    await _fanGroupInner(g, inner);
    unawaited(_sync?.mirror(threadRid: gid, dir: 'out', inner: inner) ??
        Future<void>.value());
  }

  /// Send an attachment to every member of [gid]. One file key, one set of
  /// encrypted chunks; the offer (carrying the key) goes to each member over
  /// their pairwise ratchet and the sealed chunks are queued for each
  /// member's mailbox — so a member removed before the send never receives
  /// the key, and one removed afterwards cannot decrypt the next file.
  /// 7.4: voice note into a group — same pairwise fan-out as any attachment.
  Future<void> sendGroupVoiceNote(String gid, Uint8List bytes, int durSec,
          {String mime = 'audio/mp4'}) =>
      sendGroupFile(gid, _voiceNoteName(mime), bytes, mime,
          voice: true, durSec: durSec);

  Future<void> sendGroupFile(
      String gid, String fileName, Uint8List bytes, String mime,
      {bool voice = false, int durSec = 0}) async {
    final g = groups[gid];
    if (g == null || g.left) return;
    if (bytes.length > maxAttachmentBytes) {
      throw const FormatException(
          'attachment too large (max 24 MB in this build)');
    }
    final ts = _now();
    final km = FileKeyMaterial.generate();
    final chunks = splitChunks(bytes);
    final sha = b64(await sha256Bytes(bytes));
    final inner = InnerMessage(
      kind: 'gfile',
      mid: newMessageId(),
      ts: ts,
      data: {
        'gid': gid,
        'fid': km.fid,
        'name': fileName,
        'size': bytes.length,
        'mime': mime,
        'sha256': sha,
        'fk': b64(km.fk),
        'fn': b64(km.fn),
        'chunks': chunks.length,
        if (voice) 'voice': true,
        if (durSec > 0) 'dur': durSec,
      },
    );
    final keyInfo = await vault.writeBlob(km.fid, bytes);
    final chunkPayloads = <String>[];
    for (var i = 0; i < chunks.length; i++) {
      chunkPayloads.add(await encryptChunk(km, i, chunks[i]));
    }
    // Local copy + placeholder first, so the thread shows the send even if a
    // member's fan-out below fails and is retried from the outbox.
    await vault.db.transaction((txn) async {
      await txn.insert('files', {
        'fid': km.fid,
        'rid': gid,
        'mid': inner.mid,
        'enc_meta': await vault.seal(jsonEncode({
          'name': fileName,
          'size': bytes.length,
          'mime': mime,
          'sha256': sha,
          'local': keyInfo,
          if (voice) 'voice': true,
          if (durSec > 0) 'dur': durSec,
        })),
        'complete': 1,
        'got_chunks': chunks.length,
        'total_chunks': chunks.length,
      });
      await txn.insert('messages', {
        'mid': inner.mid,
        'rid': gid,
        'outgoing': 1,
        'kind': 'file',
        'enc_body': await vault.seal(jsonEncode({'fid': km.fid})),
        'fid': km.fid,
        'ts_ms': ts,
        'status': MsgStatus.pending,
        'expire_at_ms': 0,
      });
    });
    _appendLoaded(
        gid,
        ChatMessage(
          mid: inner.mid,
          rid: gid,
          outgoing: true,
          kind: 'file',
          body: fileName,
          fid: km.fid,
          ts: ts,
          status: MsgStatus.pending,
          file: FileMeta(
            fid: km.fid,
            name: fileName,
            size: bytes.length,
            mime: mime,
            sha256b64: sha,
            complete: true,
            gotChunks: chunks.length,
            totalChunks: chunks.length,
            voice: voice,
            durSec: durSec,
          ),
        ));
    notifyListeners();
    // Fan out: offer over the ratchet + chunks in the durable outbox, per
    // member, sealed to each member's device.
    for (final rid in g.memberRids.toList()) {
      final c = contacts[rid];
      if (c == null) continue;
      await _sendInner(c, inner, also: (txn) async {
        for (final p in chunkPayloads) {
          await txn.insert('outbox', {
            'id': newMessageId(),
            'rid': rid,
            'payload': await _sealFor(rid, p),
            'created_ms': _now(),
          });
        }
      });
    }
    final sync = _sync;
    if (sync != null) {
      unawaited(() async {
        await sync.mirror(threadRid: gid, dir: 'out', inner: inner);
        for (final p in chunkPayloads) {
          await sync.fanChunk(p);
        }
      }());
    }
  }

  /// Apply a group invite. [fromRid] is the authenticated sender ('' when the
  /// invite is a mirror of my own admin action from my other device).
  Future<void> _applyGroupInvite(String fromRid, Map<String, Object?> data,
      {DatabaseExecutor? txn, bool mirroredOwn = false}) async {
    final gid = data['gid'] as String?;
    if (gid == null || gid.isEmpty) return;
    final name = data['name'] as String? ?? 'Group';
    final ver = (data['ver'] as num?)?.toInt() ?? 1;
    final existing = groups[gid];
    if (existing != null) {
      final fromAdmin =
          mirroredOwn ? existing.iAmAdmin : existing.adminRid == fromRid;
      if (!fromAdmin || ver <= existing.ver) return; // not admin, or stale
    }

    // Verify every member bundle; auto-add contacts we don't know yet.
    var includesMe = false;
    final memberRids = <String>{};
    for (final m in (data['members'] as List? ?? const [])) {
      ContactBundle bundle;
      String cname;
      try {
        final e = (m as Map).cast<String, Object?>();
        bundle =
            ContactBundle.fromJson((e['b'] as Map).cast<String, Object?>());
        if (!await bundle.verify()) continue;
        cname = e['n'] as String? ?? 'Unknown';
      } catch (_) {
        continue;
      }
      final rid = await bundle.routingId();
      if (rid == myRid) {
        includesMe = true;
        continue;
      }
      memberRids.add(rid);
      if (!contacts.containsKey(rid)) {
        final createdMs = _now();
        await (txn ?? vault.db).insert(
            'contacts',
            {
              'rid': rid,
              'enc_bundle': await vault.seal(jsonEncode(bundle.toJson())),
              'enc_name': await vault.seal(cname),
              'ttl_seconds': 0,
              'verified': 0,
              'created_ms': createdMs,
            },
            conflictAlgorithm: ConflictAlgorithm.ignore);
        contacts[rid] = Contact(
            rid: rid, bundle: bundle, name: cname, createdMs: createdMs);
        _sealKeys[rid] = bundle.xPub;
        messagesByChat.putIfAbsent(rid, () => []);
        unread.putIfAbsent(rid, () => 0);
      }
    }

    if (!mirroredOwn) {
      if (existing != null && !includesMe) {
        // The admin's new list omits me: I was removed.
        existing.name = name;
        existing.ver = ver;
        existing.left = true;
        await _saveGroups(txn: txn);
        await _insertSystemMessage(gid, 'You were removed from "$name".',
            txn: txn);
        return;
      }
      memberRids.add(fromRid); // the admin is a member too
    }

    final isNew = existing == null;
    groups[gid] = Group(
      gid: gid,
      name: name,
      adminRid: mirroredOwn ? '' : fromRid,
      memberRids: memberRids,
      ver: ver,
    );
    await _saveGroups(txn: txn);
    unread.putIfAbsent(gid, () => 0);
    if (isNew) {
      final by = mirroredOwn
          ? 'You created'
          : '${contacts[fromRid]?.name ?? 'Someone'} added you to';
      await _insertSystemMessage(gid, '$by "$name".', txn: txn);
    } else {
      await _insertSystemMessage(gid, 'Group membership updated.', txn: txn);
    }
  }

  /// Persist an inbound group text from [contact] (any of their devices).
  Future<void> _persistGroupText(Contact contact, InnerMessage inner, int now,
      {DatabaseExecutor? txn}) async {
    final gid = inner.data['gid'] as String?;
    final g = gid == null ? null : groups[gid];
    // Unknown group or non-member sender (e.g. removed): drop silently.
    if (g == null || g.left || !g.memberRids.contains(contact.rid)) return;
    final body = inner.data['body'] as String? ?? '';
    await (txn ?? vault.db).insert(
        'messages',
        {
          'mid': inner.mid,
          'rid': gid,
          'outgoing': 0,
          'kind': 'gtext',
          'enc_body':
              await vault.seal(jsonEncode({'b': body, 'sn': contact.name})),
          'ts_ms': now,
          'status': MsgStatus.delivered,
          'expire_at_ms': 0,
        },
        conflictAlgorithm: ConflictAlgorithm.ignore);
    _appendLoaded(
        gid!,
        ChatMessage(
          mid: inner.mid,
          rid: gid,
          outgoing: false,
          kind: 'gtext',
          body: body,
          ts: now,
          status: MsgStatus.delivered,
          senderName: contact.name,
        ));
    if (openChatRid != gid) unread[gid] = (unread[gid] ?? 0) + 1;
  }

  /// A member told us (over their authenticated channel) that they left.
  Future<void> _applyGroupLeave(String fromRid, Map<String, Object?> data,
      {DatabaseExecutor? txn}) async {
    final gid = data['gid'] as String?;
    final g = gid == null ? null : groups[gid];
    if (g == null) return;
    if (!g.memberRids.remove(fromRid)) return;
    if (g.iAmAdmin) g.ver += 1; // future invites exclude them
    await _saveGroups(txn: txn);
    await _insertSystemMessage(
        gid!, '${contacts[fromRid]?.name ?? 'A member'} left the group.',
        txn: txn);
  }

  // ---- M4: contact device-list distribution + fan-out --------------------

  Future<int> _myDevlistVersion() async =>
      int.tryParse(await vault.kvGet('my_devlist_version') ?? '1') ?? 1;

  /// Every device of MY account (this device + linked ones).
  Future<List<DeviceCertificate>> myFullDeviceList() async =>
      [(await accountIdentity()).deviceCert, ...await _myDevices()];

  /// Tell every contact my current device set (account-signed) so they fan
  /// messages out to all my devices and accept from any of them.
  /// Tell every contact my current device set (account-signed). [alsoOwnDevices]
  /// drives 7.7a rule 8 — self-syncing the same signed list to my own other
  /// devices so they always know the latest legitimate version. It defaults to
  /// true and the app never turns it off; the flag exists so a split-view
  /// adversary (which by definition keeps the owner's devices in the dark) can
  /// be modelled in tests.
  Future<void> broadcastMyDeviceList({bool alsoOwnDevices = true}) async {
    final me = await accountIdentity();
    if (!me.holdsAccountRoot) return; // only a root-holding device can sign
    final list = await me.signDeviceList(
        await myFullDeviceList(), await _myDevlistVersion());
    final data = jsonEncode(list.toJson());
    // 7.7a: this device now KNOWS the latest legitimate (version, fingerprint)
    // of its own account — record it so an echo from a contact carrying a list
    // this device never issued stands out (owner rule).
    await _recordOwnList(list);
    // 7.7a root discipline (rule 8): my own other devices must always know the
    // latest legitimate version, so a rogue enrolment shows up as a version
    // they never saw. Self-sync the signed list to them before (or with) the
    // contacts. No-op when nothing is linked.
    if (alsoOwnDevices) {
      await _sync?.mirror(
          threadRid: '',
          dir: 'acct',
          inner: InnerMessage(
              kind: 'devlist',
              mid: newMessageId(),
              ts: _now(),
              data: {'list': data}));
    }
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
  Future<void> _installContactDeviceList(Contact contact, SignedDeviceList list,
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
      final r = await d.routingId();
      newRids.add(r);
      _sealKeys[r] = d.deviceXPub; // sealed sender to their extra devices too
    }
    // 7.7a removal notice (T3): a device we previously held and that this
    // verified list drops is told once, over the still-open pairwise session,
    // that it was removed — so a device silently excluded by whoever holds the
    // account root hears of it from the people who stopped delivering to it. A
    // rogue cannot suppress this: it is sent by the contact, not the account.
    final removed = [
      for (final r in session.targetRoutingIds.toList())
        if (!newRids.contains(r)) r
    ];
    if (persist && removed.isNotEmpty) {
      final fp = await list.fingerprint();
      for (final r in removed) {
        try {
          final note = InnerMessage.deviceListRemoved(newMessageId(), _now(),
              acct: list.accountEdPub, v: list.version, h: fp);
          final fm = await session.encryptFor(r, note.toBytes());
          await _saveExtra(rid);
          if (fm != null) {
            await transport.send(
                to: r,
                id: newMessageId(),
                payload: await _sealFor(r, fm.payload));
          }
        } catch (_) {}
      }
    }
    for (final r in removed) {
      session.removeTarget(r);
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
      await vault.kvPut('cextra_$rid', jsonEncode(s.toJson()),
          sensitive: false);
    }
  }

  /// Fan a just-sent inner message out to a contact's non-primary devices.
  Future<void> _fanToContactExtras(String rid, InnerMessage inner) async {
    final s = _contactExtras[rid];
    if (s == null || s.targetRoutingIds.isEmpty) return;
    final contact = contacts[rid];
    await _withLock(rid, () async {
      try {
        if (contact != null) await _decorateForWire(inner, contact);
        final fan = await s.encrypt(inner.toBytes());
        await _saveExtra(rid);
        for (final f in fan) {
          try {
            await transport.send(
                to: f.routingId,
                id: newMessageId(),
                payload: await _sealFor(f.routingId, f.payload));
          } catch (_) {}
        }
      } catch (_) {}
    });
  }

  /// Inbound from a contact's non-primary device.
  Future<void> _handleExtraInbound(
      String rid, String fromDeviceRid, String payload, RelayInbound m) async {
    final contact = contacts[rid];
    final s = _contactExtras[rid];
    if (contact == null || s == null) {
      transport.ackReceived(id: m.id, from: m.from);
      return;
    }
    InnerMessage? inner;
    String? offer;
    await _withLock(rid, () async {
      try {
        final dec = await s.decryptFrom(fromDeviceRid, payload);
        await _saveExtra(rid);
        inner = InnerMessage.fromBytes(dec.plaintext);
        offer = dec.pqOfferPayload;
      } catch (_) {}
    });
    if (offer != null) {
      // v2: our post-quantum key offer for that device (best effort, like the
      // rest of the extra-device path).
      try {
        await transport.send(
            to: fromDeviceRid,
            id: newMessageId(),
            payload: await _sealFor(fromDeviceRid, offer!));
      } catch (_) {}
    }
    transport.ackReceived(id: m.id, from: m.from);
    if (inner == null) return;
    // 7.7a: a removal notice about my own account can ride here too.
    if (inner!.kind == 'dlrm') {
      await _handleRemovalNotice(inner!);
    }
    if (inner!.kind == 'devlist') {
      await _applyDevlistInner(contact, inner!);
    } else if (inner!.kind == 'text') {
      await _insertMirrored(rid, 'in', inner!);
    } else if (inner!.kind == 'gmsg') {
      // A group message sent from one of the contact's other devices carries
      // the same authority as their primary (the cert bound it to the account).
      await _persistGroupText(contact, inner!, _now());
      notifyListeners();
    } else if (inner!.kind == 'file' && inner!.data['fid'] is String) {
      // An attachment offered from the contact's other device: same as a
      // mirrored-in offer — record it, chunks arrive by fid.
      await _insertMirroredFile(rid, false, inner!);
    } else if (inner!.kind == 'gfile' && inner!.data['fid'] is String) {
      await _persistGroupFile(contact, inner!, _now());
      notifyListeners();
      await _tryAssemble(inner!.data['fid'] as String);
    } else if (inner!.kind == 'ginvite') {
      await _applyGroupInvite(contact.rid, inner!.data);
      notifyListeners();
    } else if (inner!.kind == 'gleave') {
      await _applyGroupLeave(contact.rid, inner!.data);
      notifyListeners();
    }
    // 7.7a: observe the claim/echo after any devlist install above, so the
    // "held" list this cross-check compares against is current.
    await _observeDevlistGossip(rid, fromDeviceRid, inner!);
  }

  Future<void> _applyDevlistInner(Contact contact, InnerMessage inner) async {
    try {
      final list = SignedDeviceList.fromJson(
          (jsonDecode(inner.data['list'] as String) as Map)
              .cast<String, Object?>());
      await _installContactDeviceList(contact, list, persist: true);
    } catch (_) {}
  }

  // ------------------------------------------------------------------
  // 7.7a device-list transparency (gossip). See docs/adr/0001-key-transparency.md.
  // ------------------------------------------------------------------

  /// Load persisted alerts and per-contact claims at startup.
  Future<void> _loadDevlistState() async {
    ownAccountAlert = await vault.kvGet('own_alert');
    removedDeviceAlert = await vault.kvGet('removed_alert');
    for (final rid in contacts.keys.toList()) {
      final a = await vault.kvGet('cdl_alert_$rid');
      if (a != null) contactDevlistAlerts[rid] = a;
      final c = await vault.kvGet('cdl_claims_$rid');
      if (c == null) continue;
      final m = (jsonDecode(c) as Map).cast<String, Object?>();
      _contactClaims[rid] = {
        for (final e in m.entries)
          e.key: (
            v: ((e.value as Map)['v'] as num).toInt(),
            h: (e.value as Map)['h'] as String,
            mx: ((e.value as Map)['mx'] as num).toInt(),
          )
      };
    }
  }

  /// This device's authenticated (version, fingerprint) claim about its OWN
  /// account's device list. A root device records the exact value it signed; a
  /// linked device records what it learned by self-sync; before either, the
  /// baseline is version 1 over the device set this install knows locally.
  Future<(int, String)> _ownListClaim() async {
    final vs = await vault.kvGet('own_list_v');
    final hs = await vault.kvGet('own_list_h');
    if (vs != null && hs != null) return (int.parse(vs), hs);
    final v = await _myDevlistVersion();
    return (v, b64(await deviceListFingerprint(v, await myFullDeviceList())));
  }

  Future<void> _recordOwnList(SignedDeviceList list) async {
    await vault.kvPut('own_list_v', '${list.version}', sensitive: false);
    await vault.kvPut('own_list_h', b64(await list.fingerprint()),
        sensitive: false);
  }

  /// The newest verified (version, fingerprint) this device holds for a
  /// contact's account. Falls back to the baseline: version 1 over the single
  /// account-key device from their verified contact code.
  Future<(int, String)> _heldClaimFor(Contact c) async {
    final stored = await vault.kvGet('cdev_${c.rid}');
    if (stored != null) {
      final list = SignedDeviceList.fromJson(
          (jsonDecode(stored) as Map).cast<String, Object?>());
      return (list.version, b64(await list.fingerprint()));
    }
    final legacy = DeviceCertificate(
        deviceEdPub: c.bundle.edPub,
        deviceXPub: c.bundle.xPub,
        deviceId: 'legacy-v1',
        sig: c.bundle.bindingSig,
        legacy: true);
    return (1, b64(await deviceListFingerprint(1, [legacy])));
  }

  /// Stamp an outgoing inner with our own-list claim ('dl') and an echo of the
  /// recipient's list ('pdl'). Ignored by v1 clients; observed by v2 ones.
  /// Best-effort: the transparency gossip must never break a send, so a failure
  /// to read local state (e.g. a vault closing on shutdown) just omits it.
  Future<void> _decorateForWire(InnerMessage inner, Contact contact) async {
    try {
      final (v, h) = await _ownListClaim();
      inner.data['dl'] = {'v': v, 'h': h};
      final (pv, ph) = await _heldClaimFor(contact);
      inner.data['pdl'] = {'v': pv, 'h': ph};
    } catch (_) {
      // Leave the message undecorated; gossip resumes on the next send.
    }
  }

  /// A linked device applies the account's latest signed list, self-synced from
  /// the root device (rule 8), keeping its own-account version in step.
  Future<void> _applyOwnDeviceList(InnerMessage inner) async {
    try {
      final list = SignedDeviceList.fromJson(
          (jsonDecode(inner.data['list'] as String) as Map)
              .cast<String, Object?>());
      final me = await accountIdentity();
      if (base64Encode(list.accountEdPub) != base64Encode(me.accountEdPub)) {
        return;
      }
      if (!await list.verify()) return;
      if (list.version < await _myDevlistVersion()) return; // stale
      final others = [
        for (final d in list.devices)
          if (base64Encode(d.deviceEdPub) != base64Encode(me.deviceEdPub)) d
      ];
      await vault.kvPut(
          'my_devices', jsonEncode([for (final d in others) d.toJson()]),
          sensitive: false);
      await vault.kvPut('my_devlist_version', '${list.version}',
          sensitive: false);
      await _recordOwnList(list);
      await _initSync();
      // Catching up may resolve a pending owner-echo (the normal-update case).
      await _reevaluateDevlistPending();
      notifyListeners();
    } catch (_) {}
  }

  /// Cross-check the claim ('dl') and echo ('pdl') carried by an inbound inner
  /// from [deviceRid] of contact [rid].
  Future<void> _observeDevlistGossip(
      String rid, String deviceRid, InnerMessage inner) async {
    if (!contacts.containsKey(rid)) return;
    // Best-effort: never let a transparency cross-check throw out of the
    // inbound path (e.g. the vault closing during shutdown/restart).
    try {
      final dl = inner.data['dl'];
      if (dl is Map && dl['v'] is num && dl['h'] is String) {
        await _observeContactClaim(
            rid, deviceRid, (dl['v'] as num).toInt(), dl['h'] as String);
      }
      final pdl = inner.data['pdl'];
      if (pdl is Map && pdl['v'] is num && pdl['h'] is String) {
        await _observeOwnEcho(
            rid, (pdl['v'] as num).toInt(), pdl['h'] as String);
      }
    } catch (_) {
      // Transient (closed vault, malformed member): skip this observation.
    }
  }

  Future<void> _observeContactClaim(
      String rid, String deviceRid, int v, String h) async {
    final claims = _contactClaims.putIfAbsent(rid, () => {});
    final prev = claims[deviceRid];
    final mx = prev == null ? v : (prev.mx > v ? prev.mx : v);
    claims[deviceRid] = (v: v, h: h, mx: mx);
    await _saveClaims(rid);
    await _evaluateContact(rid);
  }

  /// Owner rule: a contact echoes the list it holds for MY account. A version
  /// higher than this device knows, or the same version with a different
  /// fingerprint, means a device holding my account key issued a list this
  /// device never saw (T1/T2). Deferred through the grace period so a normal
  /// bump seen before my own self-sync arrives does not cry wolf.
  Future<void> _observeOwnEcho(String rid, int echoV, String echoH) async {
    final (knownV, knownH) = await _ownListClaim();
    final consistent = echoV < knownV || (echoV == knownV && echoH == knownH);
    if (consistent) {
      _pendingOwnerEcho.remove(rid);
      return;
    }
    _pendingOwnerEcho[rid] = (
      v: echoV,
      h: echoH,
      seen: _pendingOwnerEcho[rid]?.seen ?? DateTime.now()
    );
    await _reevaluateDevlistPending();
  }

  Future<void> _evaluateContact(String rid) async {
    final claims = _contactClaims[rid];
    final contact = contacts[rid];
    if (claims == null || claims.isEmpty || contact == null) return;
    final (heldV, heldH) = await _heldClaimFor(contact);

    final byVersion = <int, Set<String>>{};
    var maxV = 0;
    var rollback = false;
    for (final c in claims.values) {
      (byVersion[c.v] ??= <String>{}).add(c.h);
      if (c.v > maxV) maxV = c.v;
      if (c.v < c.mx) rollback = true;
    }
    String? conflict;
    for (final hs in byVersion.values) {
      if (hs.length > 1) {
        conflict = 'disagree';
        break;
      }
    }
    conflict ??= rollback ? 'rollback' : null;
    if (conflict == null) {
      for (final c in claims.values) {
        if (c.v == heldV && c.h != heldH) {
          conflict = 'split';
          break;
        }
      }
    }
    if (conflict != null) {
      _pendingContact.remove(rid);
      await _setContactAlert(rid, _conflictMsg(contact.name, conflict));
      return;
    }

    // Deferred (grace) cases:
    //   maxV < heldV → I hold a list newer than any of their devices admits to
    //     (a split view handed to me / T2).
    //   maxV > heldV → a device claims a newer list and the broadcast that
    //     would install it never arrived.
    if (maxV != heldV) {
      final since = _pendingContact.putIfAbsent(rid, () => DateTime.now());
      if (DateTime.now().difference(since) >= devlistGrace) {
        _pendingContact.remove(rid);
        await _setContactAlert(
            rid,
            maxV < heldV
                ? "${contact.name}'s devices don't confirm the device list "
                    'this device was given. One of their devices may not be '
                    'theirs — check with them before continuing.'
                : "${contact.name}'s device list changed but the update never "
                    'arrived. Their new device could not be verified.');
      } else {
        _scheduleDevlistRecheck();
      }
    } else {
      _pendingContact.remove(rid);
      await _setContactAlert(rid, null);
    }
  }

  /// Re-run the deferred checks after the grace period.
  Future<void> _reevaluateDevlistPending() async {
    if (_disposed) return;
    try {
      await _reevaluateDevlistPendingInner();
    } catch (_) {
      // Vault closed or similar: the checks re-run on the next inbound event.
    }
  }

  Future<void> _reevaluateDevlistPendingInner() async {
    final now = DateTime.now();
    var anyPending = false;

    final (knownV, knownH) = await _ownListClaim();
    for (final key in _pendingOwnerEcho.keys.toList()) {
      final ec = _pendingOwnerEcho[key]!;
      final consistent = ec.v < knownV || (ec.v == knownV && ec.h == knownH);
      if (consistent) {
        _pendingOwnerEcho.remove(key);
      } else if (now.difference(ec.seen) >= devlistGrace) {
        ownAccountAlert ??=
            'A contact was given a device list for your account that this '
            'device never issued. A device holding your account key may have '
            "enrolled another device. If that wasn't you, reset your identity "
            'now.';
        await vault.kvPut('own_alert', ownAccountAlert!, sensitive: false);
        _pendingOwnerEcho.remove(key); // recorded; the alert stays until ack
      } else {
        anyPending = true;
      }
    }

    for (final rid in _pendingContact.keys.toList()) {
      await _evaluateContact(rid);
      if (_pendingContact.containsKey(rid)) anyPending = true;
    }
    if (anyPending) _scheduleDevlistRecheck();
    notifyListeners();
  }

  void _scheduleDevlistRecheck() {
    if (_disposed) return;
    _devlistTimer?.cancel();
    _devlistTimer = Timer(devlistGrace + const Duration(milliseconds: 200),
        () => unawaited(_reevaluateDevlistPending()));
  }

  /// A contact told this device it was dropped from its own account's list.
  Future<void> _handleRemovalNotice(InnerMessage inner) async {
    try {
      final acctB64 = inner.data['acct'];
      if (acctB64 is! String) return;
      final me = await accountIdentity();
      if (acctB64 != b64(me.accountEdPub)) return; // not about my account
      final v = (inner.data['v'] as num?)?.toInt() ?? 0;
      removedDeviceAlert =
          'This device was removed from your account (device list v$v). If you '
          'did not do this, your account key may be compromised — reset your '
          'identity.';
      await vault.kvPut('removed_alert', removedDeviceAlert!, sensitive: false);
      notifyListeners();
    } catch (_) {
      // Best-effort; a redelivery will surface it again.
    }
  }

  Future<void> _saveClaims(String rid) async {
    final claims = _contactClaims[rid];
    if (claims == null) return;
    await vault.kvPut(
        'cdl_claims_$rid',
        jsonEncode({
          for (final e in claims.entries)
            e.key: {'v': e.value.v, 'h': e.value.h, 'mx': e.value.mx}
        }),
        sensitive: false);
  }

  Future<void> _setContactAlert(String rid, String? msg) async {
    if (msg == null) {
      contactDevlistAlerts.remove(rid);
      await vault.kvDelete('cdl_alert_$rid');
    } else {
      contactDevlistAlerts[rid] = msg;
      await vault.kvPut('cdl_alert_$rid', msg, sensitive: false);
    }
  }

  String _conflictMsg(String name, String kind) {
    switch (kind) {
      case 'rollback':
        return "$name's device list went backwards a version. One of their "
            'devices may be replaying an old list — check with them.';
      default:
        return "$name's devices disagree about their device list. One of them "
            'may not be theirs — check with them before continuing.';
    }
  }

  /// The version of the device list this device believes is current for its OWN
  /// account. Exposed for diagnostics and tests.
  Future<int> ownDeviceListVersion() async => (await _ownListClaim()).$1;

  /// The version of the newest device list this device holds for [rid]'s
  /// account (1 = the baseline single-device list). Exposed for tests.
  Future<int> heldContactListVersion(String rid) async {
    final c = contacts[rid];
    if (c == null) return 0;
    return (await _heldClaimFor(c)).$1;
  }

  /// Dismiss a contact's device-list banner (until a new inconsistency arises).
  Future<void> acknowledgeContactDevlistAlert(String rid) async {
    await _setContactAlert(rid, null);
    notifyListeners();
  }

  Future<void> acknowledgeOwnAccountAlert() async {
    ownAccountAlert = null;
    await vault.kvDelete('own_alert');
    notifyListeners();
  }

  Future<void> acknowledgeRemovedDeviceAlert() async {
    removedDeviceAlert = null;
    await vault.kvDelete('removed_alert');
    notifyListeners();
  }

  /// Full local wipe: identity, contacts, messages, keys. Irreversible.
  Future<void> wipeEverything() async {
    await transport.stop();
    await vault.wipe();
  }
}

/// A default file name for a recorded voice note, from its container mime.
String _voiceNoteName(String mime) {
  final ext = switch (mime) {
    'audio/mp4' || 'audio/aac' || 'audio/m4a' => 'm4a',
    'audio/ogg' || 'audio/opus' => 'ogg',
    'audio/wav' || 'audio/x-wav' => 'wav',
    _ => 'bin',
  };
  return 'voice-${DateTime.now().millisecondsSinceEpoch}.$ext';
}

/// mm:ss display for a voice-note duration.
String describeDuration(int seconds) {
  final m = seconds ~/ 60, s = seconds % 60;
  return '$m:${s.toString().padLeft(2, '0')}';
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
