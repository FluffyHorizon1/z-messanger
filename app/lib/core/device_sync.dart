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

  AccountSession? _session;
  final Set<String> _deviceRids = {};
  final _Mutex _lock = _Mutex();

  DeviceSyncService({
    required this.vault,
    required this.reliableSend,
    required this.account,
    required this.myDevices,
  });

  bool get active => myDevices.isNotEmpty;

  /// Routing ids of my other devices — used to recognise self-sync traffic.
  Set<String> get deviceRoutingIds => _deviceRids;

  Future<void> init() async {
    if (!active) return;
    for (final d in myDevices) {
      _deviceRids.add(await d.routingId());
    }
    final stored = await vault.kvGet('sync_session');
    if (stored != null) {
      _session = await AccountSession.fromJson(
          account, (jsonDecode(stored) as Map).cast<String, Object?>());
      for (final d in myDevices) {
        await _session!.addTarget(DeviceTarget.fromCert(d));
      }
    } else {
      _session = await AccountSession.create(
          account, [for (final d in myDevices) DeviceTarget.fromCert(d)]);
    }
    await prime();
  }

  /// Proactively open the sync ratchet with each of my devices for which I am
  /// the designated initiator, so the session is established deterministically
  /// before any real mirror. Self-sync mirrors are best-effort with no retry,
  /// so without this the first one races session setup and can be lost. Safe to
  /// call repeatedly (on connect): on an already-open session it is just an
  /// extra hello the other side decrypts and ignores.
  Future<void> prime() async {
    final s = _session;
    if (s == null) return;
    await _lock.run(() async {
      final envelope = jsonEncode({
        'thread': '',
        'dir': 'ping',
        'inner': base64Encode(InnerMessage.hello(newMessageId(), 0).toBytes()),
      });
      final fan = await s
          .openInitiatorSessions(Uint8List.fromList(utf8.encode(envelope)));
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
      await vault.kvPut('sync_session', jsonEncode(s.toJson()),
          sensitive: false);
    }
  }

  /// Mirror a message I sent/received in [threadRid] to my other devices.
  /// [dir] is 'out' (I sent it) or 'in' (I received it).
  Future<void> mirror({
    required String threadRid,
    required String dir,
    required InnerMessage inner,
  }) async {
    final s = _session;
    if (s == null) return;
    await _lock.run(() async {
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

  /// Decrypt a self-sync payload from one of my devices. Returns the mirrored
  /// (thread, dir, inner) for the caller to insert, or null if it isn't ours.
  Future<({String thread, String dir, InnerMessage inner})?> handleInbound(
      String fromDeviceRid, String payload) async {
    final s = _session;
    if (s == null || !_deviceRids.contains(fromDeviceRid)) return null;
    String? offer;
    final mirrored = await _lock.run(() async {
      try {
        final dec = await s.decryptFrom(fromDeviceRid, payload);
        await _save();
        offer = dec.pqOfferPayload;
        // v2: a post-quantum key offer from my other device is consumed by
        // the session layer above; it carries no mirrored message.
        if (InnerMessage.looksLikeKind(dec.plaintext, 'pqek')) return null;
        final j =
            jsonDecode(utf8.decode(dec.plaintext)) as Map<String, Object?>;
        final inner =
            InnerMessage.fromBytes(base64Decode(j['inner'] as String));
        return (
          thread: j['thread'] as String,
          dir: j['dir'] as String,
          inner: inner,
        );
      } catch (_) {
        return null;
      }
    });
    if (offer != null) await reliableSend(fromDeviceRid, offer!);
    return mirrored;
  }
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
