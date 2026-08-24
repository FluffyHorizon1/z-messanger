import 'dart:typed_data';

import 'identity.dart';
import 'multidevice.dart';
import 'session.dart';
import 'util.dart';

/// Multi-device messaging engine (M2).
///
/// From THIS device's point of view, messaging an account is just running one
/// Double Ratchet per *target device* — where the targets are the contact's
/// devices, plus your OWN other devices (so a message you send is mirrored to
/// your desktop, and one you receive is too). [AccountSession] holds one
/// [Conversation] per target device and does two things:
///
///   * encrypt(plaintext) → fans the message out, producing one opaque payload
///     per target device, each addressed to that device's routing id.
///   * decryptFrom(senderDeviceRid, payload) → routes an inbound payload to the
///     session for the device it came from.
///
/// Every per-device [Conversation] is the existing, audited ratchet — the keys
/// just happen to be device keys instead of identity keys. The relay is
/// untouched: each target routing id is an ordinary mailbox.

/// A device we send to: its public Ed25519 (→ routing id) and X25519 (→ ratchet)
/// keys. Build one from a [DeviceCertificate] in a contact's [AccountBundle].
class DeviceTarget {
  final Uint8List edPub;
  final Uint8List xPub;

  DeviceTarget({required this.edPub, required this.xPub});

  factory DeviceTarget.fromCert(DeviceCertificate c) =>
      DeviceTarget(edPub: c.deviceEdPub, xPub: c.deviceXPub);

  Future<String> routingId() async => b64url(await sha256Bytes(edPub));

  /// A bundle usable by [Conversation]. The binding signature is unused here
  /// (device authenticity is established by the account's [DeviceCertificate]
  /// at the contact layer, not inside the ratchet), so it is left empty.
  ContactBundle asBundle() =>
      ContactBundle(edPub: edPub, xPub: xPub, bindingSig: Uint8List(0));
}

/// One fanned-out ciphertext and the device mailbox it goes to.
class FanoutMessage {
  final String routingId;
  final String payload;
  FanoutMessage(this.routingId, this.payload);
}

class AccountSession {
  /// This device, expressed as a [ZIdentity] over its own device keys.
  final ZIdentity myDevice;

  /// targetDeviceRoutingId → the ratchet with that device.
  final Map<String, Conversation> _convs;

  AccountSession._(this.myDevice, this._convs);

  /// Build (or rebuild) an account session for a set of target devices.
  static Future<AccountSession> create(
    AccountIdentity me,
    List<DeviceTarget> targets,
  ) async {
    final myDevice =
        await ZIdentity.fromSeeds(edSeed: me.deviceEdSeed, xSeed: me.deviceXSeed);
    final convs = <String, Conversation>{};
    for (final t in targets) {
      convs[await t.routingId()] =
          await Conversation.create(myDevice, t.asBundle());
    }
    return AccountSession._(myDevice, convs);
  }

  /// The device mailboxes this session will fan out to.
  List<String> get targetRoutingIds => _convs.keys.toList();

  bool hasTarget(String routingId) => _convs.containsKey(routingId);

  /// Add a newly-learned device (e.g. from a device-list update, M4). No-op if
  /// already present.
  Future<void> addTarget(DeviceTarget t) async {
    final rid = await t.routingId();
    if (_convs.containsKey(rid)) return;
    _convs[rid] = await Conversation.create(myDevice, t.asBundle());
  }

  /// Forget a revoked/removed device.
  void removeTarget(String routingId) => _convs.remove(routingId);

  /// Encrypt once per target device. Returns one payload per mailbox; the
  /// caller sends each to its routing id. Persist this session's state BEFORE
  /// sending (same rule as [Conversation.encrypt]).
  Future<List<FanoutMessage>> encrypt(Uint8List plaintext, {int? nowMs}) async {
    final out = <FanoutMessage>[];
    for (final e in _convs.entries) {
      out.add(FanoutMessage(e.key, await e.value.encrypt(plaintext, nowMs: nowMs)));
    }
    return out;
  }

  /// Decrypt an inbound payload known to have come from [senderDeviceRid].
  /// Throws [UnknownSessionException] if we hold no session for that device.
  Future<DecryptResult> decryptFrom(String senderDeviceRid, String payload,
      {int? nowMs}) async {
    final conv = _convs[senderDeviceRid];
    if (conv == null) {
      throw UnknownSessionException('no device session for $senderDeviceRid');
    }
    return conv.decrypt(payload, nowMs: nowMs);
  }

  /// Wipe every per-device session (an account-wide "reset secure session").
  void resetAll() {
    for (final c in _convs.values) {
      c.resetSessions();
    }
  }

  Map<String, Object?> toJson() => {
        'convs': {
          for (final e in _convs.entries) e.key: e.value.toJson(),
        },
      };

  static Future<AccountSession> fromJson(
      AccountIdentity me, Map<String, Object?> j) async {
    final myDevice =
        await ZIdentity.fromSeeds(edSeed: me.deviceEdSeed, xSeed: me.deviceXSeed);
    final convs = <String, Conversation>{};
    final raw = (j['convs'] as Map).cast<String, Object?>();
    for (final e in raw.entries) {
      convs[e.key] = await Conversation.fromJson(
          myDevice, (e.value as Map).cast<String, Object?>());
    }
    return AccountSession._(myDevice, convs);
  }
}
