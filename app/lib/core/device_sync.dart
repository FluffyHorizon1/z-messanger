import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:z_protocol/z_protocol.dart';

import 'vault.dart';

/// Mirrors your own messages across your linked devices (self-sync).
///
/// This is a SEPARATE per-device channel; the messaging path with contacts is
/// untouched. When you have no linked devices it is completely inert. A message
/// you send or receive is wrapped in a small envelope (which thread, which
/// direction, the inner message) and encrypted to each of your other devices
/// over their own ratchet, then sent to their mailbox. The relay sees only
/// opaque ciphertext to another routing id, exactly like a normal message.
class DeviceSyncService {
  final Vault vault;

  /// Reliable, relay-backed delivery provided by the owner (enqueue to the
  /// durable outbox and flush). Self-sync uses this instead of a raw socket
  /// write so a mirror or file chunk survives a race or a brief disconnect
  /// rather than being dropped — the same guarantee the contact path has.
  final Future<void> Function(String toRid, String payload) reliableSend;
  final AccountIdentity account;
  final List<DeviceCertificate> myDevices; // my OTHER devices

  /// The post-quantum clocks (PROTOCOL §17.4, §17.7) this channel runs on —
  /// the owner's, read whenever the session is built or rebuilt. Until 26.2
  /// this channel was built without them, so it never re-made a withheld
  /// offer and never re-keyed, and it is the one that carries a copy of
  /// every message.
  final PqIntervals Function() pqIntervals;

  /// The session with my other devices and the lock every step on it takes:
  /// this service's own, or those of the service it took over from.
  final _SyncState _state;
  final Set<String> _deviceRids = {};

  /// [replacing] is the service this one takes over from when the device
  /// list changes. The two share one session and one lock, so an envelope
  /// the old one is still handling and whatever the new one does next are
  /// steps on the same ratchet, one after the other. Until 26.2 the new
  /// service read its own copy from the vault while the old one could still
  /// be stepping and saving its copy: two ratchets over one stored state,
  /// each blind to the other's steps. A post-quantum secret the old copy had
  /// just taken on was lost that way, and the root's next message to this
  /// device, mixed with it, could not be read.
  DeviceSyncService({
    required this.vault,
    required this.reliableSend,
    required this.account,
    required this.myDevices,
    required this.pqIntervals,
    DeviceSyncService? replacing,
  }) : _state = replacing?._state ?? _SyncState();

  AccountSession? get _session => _state.session;
  set _session(AccountSession? s) => _state.session = s;
  _Mutex get _lock => _state.lock;

  /// The owner's clocks changed: apply them to the live session.
  void applyPqIntervals() => _session?.pqIntervals = pqIntervals();

  bool get active => myDevices.isNotEmpty;

  /// Routing ids of my other devices — used to recognise self-sync traffic.
  Set<String> get deviceRoutingIds => _deviceRids;

  /// Test seam: the sync session itself, to read its post-quantum state.
  AccountSession? get debugSession => _session;

  /// Test seam: shown every envelope from one of my devices as it would
  /// decrypt — on a COPY of the session, before anything acts on it.
  /// Returning true discards the envelope as though the relay had never
  /// delivered it: the session is left exactly as it was and the caller
  /// acknowledges. That is how a test withholds one envelope by kind, which
  /// it cannot pick out from the sealed bytes on the wire.
  bool Function(String fromDeviceRid, DecryptResult dec)? debugOnDecrypted;

  Future<void> init() async {
    if (!active) return;
    for (final d in myDevices) {
      _deviceRids.add(await d.routingId());
    }
    // Under the lock, behind anything the service this one replaces still
    // has queued — and on its session, when there is one, rather than on a
    // second copy read from the vault.
    await _lock.run(() async {
      var s = _session;
      if (s != null) {
        s.pqIntervals = pqIntervals();
      } else {
        final stored = await vault.kvGet('sync_session');
        if (stored == null) {
          _session = await AccountSession.create(
              account, [for (final d in myDevices) DeviceTarget.fromCert(d)],
              intervals: pqIntervals());
          return;
        }
        s = _session = await AccountSession.fromJson(
            account, (jsonDecode(stored) as Map).cast<String, Object?>(),
            intervals: pqIntervals());
      }
      // Restoring is add-only, and the stored blob holds whatever the last
      // run held — including a device revoked since. `encrypt` fans to every
      // target, so without this a revoked device went on receiving every
      // mirror, decryptable on its still-live ratchet, across restarts: most
      // of what revoking a device means is that it stops reading your mail.
      // Prune before adding, and persist the pruned session, so the removal
      // survives whether or not a mirror is sent afterwards. The same holds
      // for a session taken over from the service this one replaces.
      var pruned = false;
      for (final rid in s.targetRoutingIds) {
        if (!_deviceRids.contains(rid)) {
          s.removeTarget(rid);
          pruned = true;
        }
      }
      for (final d in myDevices) {
        await s.addTarget(DeviceTarget.fromCert(d));
      }
      if (pruned) await _save();
    });
    await prime();
  }

  /// Proactively open the sync ratchet with each of my devices for which I am
  /// the designated initiator, so the session is established deterministically
  /// before any real mirror. Self-sync mirrors are best-effort with no retry,
  /// so without this the first one races session setup and can be lost. Safe to
  /// call repeatedly (on connect): on an already-open session it is just an
  /// extra hello the other side decrypts and ignores.
  Future<void> prime() async {
    await _lock.run(() async {
      // Every step reads the session under the lock: [restore], or a
      // service taking over, may have put another in its place meanwhile.
      final s = _session;
      if (s == null) return;
      final fan = await s.openInitiatorSessions(
          Uint8List.fromList(utf8.encode(_pingEnvelope())));
      if (fan.isEmpty) return;
      await _save();
      for (final f in fan) {
        await reliableSend(f.routingId, f.payload);
      }
    });
  }

  Future<void> _save() async {
    final s = _session;
    if (s != null) {
      // Sealed, like everything else in the vault. This was
      // `sensitive: false` until 2026-09-14 — a plain SQLite cell holding
      // `RatchetState.toJson()` for every one of this account's own devices:
      // root key, ratchet seed, both chain keys and the cached skipped
      // message keys. The mirror carries every message this phone sends or
      // receives, so reading `z.db` was reading the account.
      await vault.kvPut('sync_session', jsonEncode(s.toJson()));
    }
  }

  /// Put the sync ratchet back where [SyncInbound.snapshot] found it, and
  /// persist that. For a caller whose store of a mirrored message failed: the
  /// envelope is not acknowledged, so the relay redelivers it, and this is
  /// what leaves it decryptable when it arrives again.
  Future<void> restore(String snapshot) async {
    await _lock.run(() async {
      _session = await AccountSession.fromJson(
          account, (jsonDecode(snapshot) as Map).cast<String, Object?>(),
          intervals: pqIntervals());
      await _save();
    });
  }

  /// Mirror a message I sent/received in [threadRid] to my other devices.
  /// [dir] is 'out' (I sent it) or 'in' (I received it).
  Future<void> mirror({
    required String threadRid,
    required String dir,
    required InnerMessage inner,
  }) async {
    await _lock.run(() async {
      final s = _session;
      if (s == null) return;
      final envelope = jsonEncode({
        'thread': threadRid,
        'dir': dir,
        'inner': base64Encode(inner.toBytes()),
      });
      final fan = await s.encrypt(Uint8List.fromList(utf8.encode(envelope)));
      // Persist the advanced ratchet BEFORE handing payloads to the reliable
      // outbox, so any redelivery is still decryptable.
      await _save();
      for (final f in fan) {
        await reliableSend(f.routingId, f.payload);
      }
    });
  }

  /// Mirror to ONE of my devices only (7.6b history sync to a newly linked
  /// device): same envelope, encrypted on that device's session alone.
  ///
  /// [onlyPostQuantum] sends nothing unless the message would be mixed with
  /// the channel's post-quantum secret — decided under the lock, in the same
  /// step as the encryption, so the answer cannot go stale between them.
  /// Returns whether it was sent.
  Future<bool> mirrorTo({
    required String deviceRid,
    required String threadRid,
    required String dir,
    required InnerMessage inner,
    bool onlyPostQuantum = false,
  }) async {
    if (!_deviceRids.contains(deviceRid)) return false;
    return _lock.run(() async {
      final s = _session;
      if (s == null) return false;
      final conv = s.targetConversation(deviceRid);
      if (onlyPostQuantum && !(conv?.nextSendIsPostQuantum ?? false)) {
        return false;
      }
      final envelope = jsonEncode({
        'thread': threadRid,
        'dir': dir,
        'inner': base64Encode(inner.toBytes()),
      });
      final f = await s.encryptFor(
          deviceRid, Uint8List.fromList(utf8.encode(envelope)));
      if (f == null) return false;
      await _save();
      await reliableSend(f.routingId, f.payload);
      return true;
    });
  }

  /// Whether what goes to [deviceRid] next would be post-quantum.
  bool isPostQuantumWith(String deviceRid) =>
      _session?.targetConversation(deviceRid)?.nextSendIsPostQuantum ?? false;

  /// Send [deviceRid] this side's post-quantum offer if one is due — the
  /// first, or one said again (§17.4) — rather than wait for it to ride the
  /// next mirror. For a caller that needs the channel post-quantum before it
  /// sends anything (the history replay, §17.8). Nothing when this side is
  /// not the one that offers to that device.
  Future<void> offerPqTo(String deviceRid) async {
    if (!_deviceRids.contains(deviceRid)) return;
    final f = await _lock.run(() async {
      final s = _session;
      if (s == null) return null;
      final f = await s.takePqOfferFor(deviceRid);
      if (f != null) await _save();
      return f;
    });
    if (f != null) await reliableSend(f.routingId, f.payload);
  }

  /// Fan a raw, already-sealed payload (an encrypted file chunk) to each of my
  /// other devices' mailboxes. Unlike [mirror] this does NOT use the sync
  /// ratchet: a chunk is self-contained and sealed under its own file key, so
  /// it is routing-agnostic — any of my devices decrypts it exactly as the
  /// original recipient does, given the offer (which carries the file key) has
  /// been mirrored. Delivered through the reliable outbox so a whole attachment
  /// is never lost to a single dropped chunk.
  Future<void> fanChunk(String payload) async {
    for (final rid in _deviceRids) {
      await reliableSend(rid, payload);
    }
  }

  /// Decrypt a self-sync payload from one of my devices.
  ///
  /// Returns what was mirrored (null if the payload carried no message) and a
  /// [SyncInbound.snapshot] of the ratchet as it was BEFORE the decrypt. The
  /// caller must store the message first and acknowledge the envelope only
  /// then; if the store fails it passes the snapshot to [restore] and does
  /// not acknowledge, so the relay's redelivery is still decryptable.
  ///
  /// Until 2.8.4 the caller acknowledged here and stored afterwards, so a
  /// process killed in that window lost the message from the relay AND from
  /// the device, with an advanced ratchet behind it — the invariant the
  /// contact path has always kept (`ChatService._onInbound` persists inside a
  /// transaction and acknowledges after it), on the one path nobody checked.
  Future<SyncInbound> handleInbound(
      String fromDeviceRid, String payload) async {
    if (!_deviceRids.contains(fromDeviceRid)) {
      return const SyncInbound(null, null);
    }
    String? offer;
    FanoutMessage? answer;
    final out = await _lock.run(() async {
      final s = _session;
      if (s == null) return const SyncInbound(null, null);
      final snapshot = jsonEncode(s.toJson());
      final probe = debugOnDecrypted;
      if (probe != null) {
        try {
          final copy = await AccountSession.fromJson(
              account, (jsonDecode(snapshot) as Map).cast<String, Object?>(),
              intervals: pqIntervals());
          if (probe(fromDeviceRid,
              await copy.decryptFrom(fromDeviceRid, payload))) {
            return const SyncInbound(null, null);
          }
        } catch (_) {
          // Undecryptable on the copy too: the real attempt below says so.
        }
      }
      try {
        final dec = await s.decryptFrom(fromDeviceRid, payload);
        await _save();
        offer = dec.pqOfferPayload;
        // v2: a post-quantum key offer from my other device is consumed by
        // the session layer above; it carries no mirrored message.
        if (InnerMessage.looksLikeKind(dec.plaintext, 'pqek')) {
          // 26.2 (§17.8): and it is answered at once. The other device has
          // no secret until a message of ours carrying the ciphertext
          // arrives, and on this channel nothing else may be said for a
          // long time — a laptop just linked has nothing of its own to
          // mirror, and the history replay waits for exactly this. A ping,
          // which every build ignores on receipt, on the session the offer
          // came on: that session's ciphertext is the one the other device
          // needs, and right after linking it is not always the session
          // this side would otherwise send on.
          final conv = s.targetConversation(fromDeviceRid);
          if (conv != null && conv.pqAnswerOwedOn(dec.sid)) {
            final ping = await s.encryptFor(fromDeviceRid,
                Uint8List.fromList(utf8.encode(_pingEnvelope())),
                sid: dec.sid);
            if (ping != null) {
              await _save(); // before it can leave, as for any send
              answer = ping;
            }
          }
          return const SyncInbound(null, null);
        }
        final j =
            jsonDecode(utf8.decode(dec.plaintext)) as Map<String, Object?>;
        final inner =
            InnerMessage.fromBytes(base64Decode(j['inner'] as String));
        return SyncInbound(
          (
            thread: j['thread'] as String,
            dir: j['dir'] as String,
            inner: inner,
          ),
          snapshot,
        );
      } catch (_) {
        // Undecryptable or malformed: there is nothing to store, and a
        // redelivery would fail the same way, so the caller acknowledges.
        return const SyncInbound(null, null);
      }
    });
    if (offer != null) await reliableSend(fromDeviceRid, offer!);
    if (answer != null) await reliableSend(answer!.routingId, answer!.payload);
    return out;
  }

  /// The proactive opener's envelope (`dir:"ping"`, a `hello` inner), which
  /// the receiving device ignores — what [prime] sends, and what answers an
  /// offer.
  static String _pingEnvelope() => jsonEncode({
        'thread': '',
        'dir': 'ping',
        'inner': base64Encode(InnerMessage.hello(newMessageId(), 0).toBytes()),
      });
}

/// The outcome of [DeviceSyncService.handleInbound].
class SyncInbound {
  /// What was mirrored, or null if this payload carried no message.
  final ({String thread, String dir, InnerMessage inner})? mirrored;

  /// The sync ratchet as it was before the decrypt, for
  /// [DeviceSyncService.restore] if storing [mirrored] fails. Null when there
  /// is nothing to store and so nothing to roll back.
  final String? snapshot;

  const SyncInbound(this.mirrored, this.snapshot);
}

/// What a [DeviceSyncService] built for a new device list takes over from
/// the one it replaces: the session, and the lock that orders steps on it.
class _SyncState {
  AccountSession? session;
  final _Mutex lock = _Mutex();
}

/// Minimal FIFO async mutex so sync ratchet ops never interleave.
class _Mutex {
  Future<void> _last = Future.value();
  Future<T> run<T>(Future<T> Function() op) {
    final done = Completer<void>();
    final prev = _last;
    _last = done.future;
    return prev.then((_) => op()).whenComplete(done.complete);
  }
}
