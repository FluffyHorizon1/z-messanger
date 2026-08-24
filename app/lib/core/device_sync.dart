import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:z_protocol/z_protocol.dart';

import 'transport.dart';
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
  final Transport transport;
  final AccountIdentity account;
  final List<DeviceCertificate> myDevices; // my OTHER devices

  AccountSession? _session;
  final Set<String> _deviceRids = {};
  final _Mutex _lock = _Mutex();

  DeviceSyncService({
    required this.vault,
    required this.transport,
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
  }

  Future<void> _save() async {
    final s = _session;
    if (s != null) {
      await vault.kvPut('sync_session', jsonEncode(s.toJson()), sensitive: false);
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
      await _save();
      for (final f in fan) {
        try {
          await transport.send(
              to: f.routingId, id: newMessageId(), payload: f.payload);
        } catch (_) {
          // best-effort; the ratchet advanced and is saved, so a retry would
          // desync — a missed mirror simply shows on next message.
        }
      }
    });
  }

  /// Decrypt a self-sync payload from one of my devices. Returns the mirrored
  /// (thread, dir, inner) for the caller to insert, or null if it isn't ours.
  Future<({String thread, String dir, InnerMessage inner})?> handleInbound(
      String fromDeviceRid, String payload) async {
    final s = _session;
    if (s == null || !_deviceRids.contains(fromDeviceRid)) return null;
    return _lock.run(() async {
      try {
        final dec = await s.decryptFrom(fromDeviceRid, payload);
        await _save();
        final j = jsonDecode(utf8.decode(dec.plaintext)) as Map<String, Object?>;
        final inner = InnerMessage.fromBytes(base64Decode(j['inner'] as String));
        return (
          thread: j['thread'] as String,
          dir: j['dir'] as String,
          inner: inner,
        );
      } catch (_) {
        return null;
      }
    });
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
