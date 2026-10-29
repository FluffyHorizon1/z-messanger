import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'identity.dart';
import 'multidevice.dart';
import 'pairing.dart';
import 'relay_client.dart';
import 'util.dart';

/// Runs the M3 pairing handshake over a real relay (M3 transport).
///
/// Both devices derive two throwaway relay identities from the pairing code —
/// one mailbox for each side — so they can find each other at the rendezvous
/// without either learning the other's real routing id. The new device sends
/// its hello, the existing device replies, both derive the SAS and ask their
/// user to confirm it, then the existing device seals the enrollment blob to
/// the new device. The relay only ever sees opaque, single-use traffic between
/// two ephemeral mailboxes.
///
/// v2 and v3 acknowledge every frame they read, as an ordinary envelope is
/// acknowledged (§12.5): the relay holds a frame until its recipient says it
/// has it, and a ceremony that never said so left its four frames — the
/// whole enrolment among them — on the relay for `QUEUE_TTL_HOURS`. The
/// existing device keeps its connection until the relay reports the new
/// device's acknowledgement of the enrolment, so that the relay's receipt
/// for it is handed over rather than queued at a mailbox nobody reads again.
/// The v1 runners are left as builds before v2 ran them.

const String _relayCtx = 'z-pair-relay:';
// v2 (§10.1) derives its throwaway mailboxes from a different context, so a
// v2 device and a v1 device holding the same code never meet: neither can be
// talked down to the other's ceremony, because neither is listening where the
// other speaks.
const String _relayCtxV2 = 'z-pair-relay-v2:';
// v3 (§10.2) the same way again: v3 transacts only on its own mailboxes.
const String _relayCtxV3 = 'z-pair-relay-v3:';

/// The longest an existing device waits, once its enrolment is sent, for the
/// relay to report that the new device acknowledged it. The new device
/// acknowledges the moment it reads the frame, so the report comes back
/// within a poll or two; a new device that is gone never acknowledges, and
/// the wait ends here rather than at the ceremony's timeout.
const Duration _enrolmentReceiptWait = Duration(seconds: 10);

/// One completed enrollment on the new device.
class PairingResult {
  final AccountIdentity account;
  final EnrollmentData data; // contacts + display name that came across
  PairingResult(this.account, this.data);
}

class RelayPairing {
  /// A throwaway relay identity for one side of a pairing, derived from the
  /// shared code. role is 'i' (initiator / new device) or 'r' (responder /
  /// existing device).
  static Future<ZIdentity> relayIdentity(PairingCode code, String role) =>
      _relayIdentity(code, role, _relayCtx);

  /// The v2 mailbox for one side (§10.1).
  static Future<ZIdentity> relayIdentityV2(PairingCode code, String role) =>
      _relayIdentity(code, role, _relayCtxV2);

  /// The v3 mailbox for one side (§10.2): okm = HKDF(code, ∅,
  /// "z-pair-relay-v3:" || role, 64), split as v1's and v2's are.
  static Future<ZIdentity> relayIdentityV3(PairingCode code, String role) =>
      _relayIdentity(code, role, _relayCtxV3);

  static Future<ZIdentity> _relayIdentity(
      PairingCode code, String role, String ctx) async {
    final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 64);
    final k = await hkdf.deriveKey(
      secretKey: SecretKey(code.secret),
      nonce: Uint8List(0),
      info: utf8.encode('$ctx$role'),
    );
    final b = await k.extractBytes();
    return ZIdentity.fromSeeds(
      edSeed: Uint8List.fromList(b.sublist(0, 32)),
      xSeed: Uint8List.fromList(b.sublist(32, 64)),
    );
  }

  /// NEW device: connect, send hello, await reply, derive the session, show the
  /// SAS via [confirm]; on confirmation, await + install the enrollment.
  /// Returns null if the user rejects the SAS.
  static Future<PairingResult?> runNewDevice({
    required String relayUrl,
    required PairingInitiator n,
    required Future<bool> Function(String sas) confirm,
    Duration timeout = const Duration(seconds: 40),
  }) async {
    final client = await RelayClient.connect(relayUrl, await relayIdentity(n.code, 'i'));
    final inbox = <RelayInbound>[];
    final sub = client.messages.listen(inbox.add);
    try {
      final rMailbox = await (await relayIdentity(n.code, 'r')).routingId();
      await client.send(
          to: rMailbox,
          id: 'z-pair-hello',
          payload: jsonEncode({'k': 'hello', ...n.hello()}));

      final reply = await _awaitKind(inbox, 'reply', timeout);
      final session = await n.complete(reply);
      if (!await confirm(session.sas)) return null;

      final env = await _awaitKind(inbox, 'enroll', timeout);
      final data = await session.openEnrollment(unb64(env['blob'] as String));
      final account = await n.installFromData(data);
      return PairingResult(account, data);
    } finally {
      await sub.cancel();
      await client.close();
    }
  }

  /// EXISTING device: connect, await hello, reply, show the SAS via [confirm];
  /// on confirmation, seal + send the enrollment. Returns the certificate of
  /// the device just linked (for the host to remember), or null if cancelled.
  static Future<DeviceCertificate?> runExistingDevice({
    required String relayUrl,
    required PairingCode code,
    required AccountIdentity me,
    required List<AccountBundle> contacts,
    required bool includeAccountRoot,
    String? displayName,
    required Future<bool> Function(String sas) confirm,
    Duration timeout = const Duration(seconds: 40),
  }) async {
    final client = await RelayClient.connect(relayUrl, await relayIdentity(code, 'r'));
    final inbox = <RelayInbound>[];
    final sub = client.messages.listen(inbox.add);
    try {
      final iMailbox = await (await relayIdentity(code, 'i')).routingId();
      final hello = await _awaitKind(inbox, 'hello', timeout);
      final (reply, session) = await PairingResponder.respond(hello);
      await client.send(
          to: iMailbox,
          id: 'z-pair-reply',
          payload: jsonEncode({'k': 'reply', ...reply}));

      if (!await confirm(session.sas)) return null;

      final newDeviceCert = await session.signedPeerCert(me);
      final sealed = await session.sealEnrollment(me,
          contacts: contacts,
          includeAccountRoot: includeAccountRoot,
          displayName: displayName);
      await client.send(
          to: iMailbox,
          id: 'z-pair-enroll',
          payload: jsonEncode({'k': 'enroll', 'blob': b64(sealed)}));
      return newDeviceCert;
    } finally {
      await sub.cancel();
      await client.close();
    }
  }

  /// NEW device, v2: commit, await the reply, open, show the SAS, install.
  ///
  /// Four frames rather than three. The commitment goes first and the opening
  /// only after the existing device has answered, so neither side can choose
  /// its ephemeral knowing what the SAS will be (§10.1).
  static Future<PairingResult?> runNewDeviceV2({
    required String relayUrl,
    required PairingInitiatorV2 n,
    required Future<bool> Function(String sas) confirm,
    Duration timeout = const Duration(seconds: 40),
  }) async {
    final box =
        await _Mailbox.open(relayUrl, await relayIdentityV2(n.code, 'i'));
    try {
      final rMailbox = await (await relayIdentityV2(n.code, 'r')).routingId();
      await box.client.send(
          to: rMailbox,
          id: 'z-pair-commit',
          payload: jsonEncode({'k': 'commit-v2', ...await n.commit()}));

      final Map<String, Object?> reply;
      try {
        reply = await _awaitFrame(box, 'reply-v2', timeout);
      } on TimeoutException {
        // Nothing answered where a v2 device would. The likeliest reason by
        // far is that the other device is older: it is listening on the v1
        // mailbox, which this one deliberately does not speak on.
        throw const PairingAbort(
            'the other device did not answer — it may be running an older '
            'version of Z, which cannot pair with this one until it is updated');
      }
      final (open, session) = await n.open(reply);
      await box.client.send(
          to: rMailbox,
          id: 'z-pair-open',
          payload: jsonEncode({'k': 'open-v2', ...open}));

      if (!await confirm(session.sas)) return null;

      final env = await _awaitFrame(box, 'enroll-v2', timeout);
      final data = await session.openEnrollment(unb64(env['blob'] as String));
      final account = await n.installFromData(data);
      return PairingResult(account, data);
    } finally {
      await box.close();
    }
  }

  /// EXISTING device, v2: await a commitment, reply, verify the opening, show
  /// the SAS, seal the enrollment.
  ///
  /// It also holds its **v1** mailbox open, and never answers there. That is
  /// the one direction in which an old peer is detectable: a v1 new device
  /// speaks first, so its `hello` arrives and can be recognised for what it
  /// is — [PairingPeerOutdated], version 1. Detect, do not transact —
  /// completing a v1 ceremony here would hand back exactly the assurance v2
  /// exists to replace.
  ///
  /// [contactState] and [hostBundle] are the enrolment's optional members
  /// (§10, phase 33), sealed with the rest when given.
  static Future<DeviceCertificate?> runExistingDeviceV2({
    required String relayUrl,
    required PairingCode code,
    required AccountIdentity me,
    required List<AccountBundle> contacts,
    required bool includeAccountRoot,
    String? displayName,
    List<Map<String, Object?>>? contactState,
    ContactBundle? hostBundle,
    required Future<bool> Function(String sas) confirm,
    Duration timeout = const Duration(seconds: 40),
  }) async {
    // Both connections are made inside the try, one after the other, so a
    // relay that refuses the second still has the first closed. They used
    // to be made before it: a refused second connection threw past the
    // `finally`, and the first stayed open, pinging every 25 s, as a mailbox
    // nobody read, for as long as the app ran.
    _Mailbox? box, v1;
    try {
      box = await _Mailbox.open(relayUrl, await relayIdentityV2(code, 'r'));
      v1 = await _Mailbox.open(relayUrl, await relayIdentity(code, 'r'));
      final iMailbox = await (await relayIdentityV2(code, 'i')).routingId();
      final commit = await _awaitCommit(box, 'commit-v2', timeout, v1: v1);
      await v1.close();
      v1 = null;
      final (reply, pending) = await PairingResponderV2.reply(commit);
      await box.client.send(
          to: iMailbox,
          id: 'z-pair-reply',
          payload: jsonEncode({'k': 'reply-v2', ...reply}));

      final open = await _awaitFrame(box, 'open-v2', timeout);
      final session = await pending.accept(open);

      if (!await confirm(session.sas)) return null;

      final newDeviceCert = await session.signedPeerCert(me);
      final sealed = await session.sealEnrollment(me,
          contacts: contacts,
          includeAccountRoot: includeAccountRoot,
          displayName: displayName,
          contactState: contactState,
          hostBundle: hostBundle);
      await _sendEnrolment(box,
          to: iMailbox,
          payload: jsonEncode({'k': 'enroll-v2', 'blob': b64(sealed)}),
          timeout: timeout);
      return newDeviceCert;
    } finally {
      await box?.close();
      await v1?.close();
    }
  }

  /// NEW device, v3 (§10.2): commit and offer a KEM key, await the reply,
  /// open, show the digits, install.
  ///
  /// Only on v3's mailboxes. Hearing nothing there most likely means an older
  /// existing device, listening where v2 or v1 speak, which this one does
  /// not: there is no fallback.
  static Future<PairingResult?> runNewDeviceV3({
    required String relayUrl,
    required PairingInitiatorV3 n,
    required Future<bool> Function(String sas) confirm,
    Duration timeout = const Duration(seconds: 40),
  }) async {
    final box =
        await _Mailbox.open(relayUrl, await relayIdentityV3(n.code, 'i'));
    try {
      final rMailbox = await (await relayIdentityV3(n.code, 'r')).routingId();
      await box.client.send(
          to: rMailbox,
          id: 'z-pair-commit',
          payload: jsonEncode({'k': 'commit-v3', ...await n.commit()}));

      final Map<String, Object?> reply;
      try {
        reply = await _awaitFrame(box, 'reply-v3', timeout);
      } on TimeoutException {
        throw const PairingAbort(
            'the other device did not answer — it may be running an older '
            'version of Z, which cannot pair with this one until it is updated');
      }
      final (open, session) = await n.open(reply);
      await box.client.send(
          to: rMailbox,
          id: 'z-pair-open',
          payload: jsonEncode({'k': 'open-v3', ...open}));

      if (!await confirm(session.sas)) return null;

      final env = await _awaitFrame(box, 'enroll-v3', timeout);
      final data = await session.openEnrollment(unb64(env['blob'] as String));
      final account = await n.installFromData(data);
      return PairingResult(account, data);
    } finally {
      await box.close();
    }
  }

  /// EXISTING device, v3: await a commitment and its KEM key, answer with an
  /// ephemeral and an encapsulation, verify the opening, show the digits,
  /// seal the enrolment.
  ///
  /// It also holds the **v2 and v1** mailboxes open until the commitment
  /// arrives, and never answers on either: an older new device speaks first,
  /// so its `commit-v2` or `hello` arrives and is recognised —
  /// [PairingPeerOutdated], naming the version, so the person can be told
  /// which device to update. Detect, do not transact: the older frame is
  /// acknowledged, so the relay drops it, and answered with nothing.
  ///
  /// [attest] is asked, once the digits are confirmed, for the new device's
  /// `pqdc` (ADR 0033 §1) — the root's signature over what the session says
  /// the new device opened — and its answer is sealed into the enrolment as
  /// it is; null, or no [attest], sends none. The enrolment never carries
  /// the account root.
  static Future<DeviceCertificate?> runExistingDeviceV3({
    required String relayUrl,
    required PairingCode code,
    required AccountIdentity me,
    required List<AccountBundle> contacts,
    String? displayName,
    List<Map<String, Object?>>? contactState,
    ContactBundle? hostBundle,
    Future<Uint8List?> Function(PairingSessionV3 session)? attest,
    required Future<bool> Function(String sas) confirm,
    Duration timeout = const Duration(seconds: 40),
  }) async {
    // The three connections are made inside the try, one after another, so
    // a relay that refuses the second or the third still has the ones
    // before it closed: nothing is left open, pinging, as a mailbox nobody
    // reads.
    _Mailbox? box, v2, v1;
    try {
      box = await _Mailbox.open(relayUrl, await relayIdentityV3(code, 'r'));
      v2 = await _Mailbox.open(relayUrl, await relayIdentityV2(code, 'r'));
      v1 = await _Mailbox.open(relayUrl, await relayIdentity(code, 'r'));
      final iMailbox = await (await relayIdentityV3(code, 'i')).routingId();
      final commit =
          await _awaitCommit(box, 'commit-v3', timeout, v2: v2, v1: v1);
      // The older mailboxes were held for the first frame alone.
      await v2.close();
      v2 = null;
      await v1.close();
      v1 = null;
      final (reply, pending) =
          await PairingResponderV3.reply(commit, code: code);
      await box.client.send(
          to: iMailbox,
          id: 'z-pair-reply',
          payload: jsonEncode({'k': 'reply-v3', ...reply}));

      final open = await _awaitFrame(box, 'open-v3', timeout);
      final session = await pending.accept(open);

      if (!await confirm(session.sas)) return null;

      final newDeviceCert = await session.signedPeerCert(me);
      final sealed = await session.sealEnrollment(me,
          contacts: contacts,
          displayName: displayName,
          contactState: contactState,
          hostBundle: hostBundle,
          pqdc: attest == null ? null : await attest(session));
      await _sendEnrolment(box,
          to: iMailbox,
          payload: jsonEncode({'k': 'enroll-v3', 'blob': b64(sealed)}),
          timeout: timeout);
      return newDeviceCert;
    } finally {
      await box?.close();
      await v2?.close();
      await v1?.close();
    }
  }

  /// [_awaitFrame] for a ceremony's first frame, of [kind] on [box], with the
  /// older ceremonies' first frames watched for on their own mailboxes —
  /// only read, never answered: a `commit-v2` on [v2], or a `hello` on [v1],
  /// ends the wait with [PairingPeerOutdated] naming the version.
  static Future<Map<String, Object?>> _awaitCommit(
      _Mailbox box, String kind, Duration timeout,
      {_Mailbox? v2, _Mailbox? v1}) async {
    final deadline = DateTime.now().add(timeout);
    while (true) {
      final found = box.take(kind);
      if (found != null) return found;
      if (v2 != null && v2.take('commit-v2') != null) {
        throw const PairingPeerOutdated(2);
      }
      if (v1 != null && v1.take('hello') != null) {
        throw const PairingPeerOutdated(1);
      }
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('pairing: no "$kind" frame arrived', timeout);
      }
      await Future<void>.delayed(const Duration(milliseconds: 25));
    }
  }

  /// Waits for a frame of [kind] on [box], taking — and so acknowledging —
  /// the first that arrives.
  static Future<Map<String, Object?>> _awaitFrame(
      _Mailbox box, String kind, Duration timeout) async {
    final deadline = DateTime.now().add(timeout);
    while (true) {
      final found = box.take(kind);
      if (found != null) return found;
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('pairing: no "$kind" frame arrived', timeout);
      }
      await Future<void>.delayed(const Duration(milliseconds: 25));
    }
  }

  /// The existing device's last frame: the enrolment, sent, and then the
  /// connection held — while it is open, for at most [_enrolmentReceiptWait]
  /// or [timeout], whichever is shorter — until the relay reports that the
  /// new device acknowledged it. The relay's receipt for that acknowledgement
  /// is then handed to this side as it is made, instead of being queued for a
  /// mailbox nobody reads again. Returns either way: this side's part is
  /// done once the relay holds the enrolment.
  static Future<void> _sendEnrolment(_Mailbox box,
      {required String to,
      required String payload,
      required Duration timeout}) async {
    const id = 'z-pair-enroll';
    await box.client.send(to: to, id: id, payload: payload);
    final wait =
        timeout < _enrolmentReceiptWait ? timeout : _enrolmentReceiptWait;
    final deadline = DateTime.now().add(wait);
    while (!box.acknowledged(id) &&
        box.client.isOpen &&
        DateTime.now().isBefore(deadline)) {
      await Future<void>.delayed(const Duration(milliseconds: 25));
    }
  }

  /// Waits for a frame of [kind] (the v1 ceremony's runners).
  static Future<Map<String, Object?>> _awaitKind(
      List<RelayInbound> inbox, String kind, Duration timeout) async {
    final deadline = DateTime.now().add(timeout);
    while (true) {
      final found = _take(inbox, kind);
      if (found != null) return found;
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('pairing: no "$kind" frame arrived', timeout);
      }
      await Future<void>.delayed(const Duration(milliseconds: 25));
    }
  }

  static Map<String, Object?>? _take(List<RelayInbound> inbox, String kind) {
    for (var i = 0; i < inbox.length; i++) {
      Map<String, Object?> j;
      try {
        j = jsonDecode(inbox[i].payload) as Map<String, Object?>;
      } catch (_) {
        continue;
      }
      if (j['k'] == kind) {
        inbox.removeAt(i);
        return j;
      }
    }
    return null;
  }
}

/// One of a ceremony's mailboxes, as one side holds it (v2 and v3): the
/// connection, the frames that have arrived and not been taken, and which of
/// this side's own frames the relay has reported acknowledged.
///
/// A frame is acknowledged the moment it is taken — read, and never to be
/// read again — as an ordinary envelope is once it is stored (`recv` with
/// its id and sender, §12.5), and whatever arrived and was never taken is
/// acknowledged when the mailbox closes: a copy a reconnect flushed again, a
/// frame of a kind this side was not waiting for. Nothing of a ceremony is
/// left on the relay for `QUEUE_TTL_HOURS` by the side that read it.
class _Mailbox {
  final RelayClient client;
  final _inbox = <RelayInbound>[];
  final _acknowledged = <String>{};
  late final StreamSubscription<RelayInbound> _frames;
  late final StreamSubscription<DeliveredReceipt> _receipts;

  _Mailbox._(this.client) {
    _frames = client.messages.listen(_inbox.add);
    _receipts = client.delivered.listen((r) => _acknowledged.add(r.id));
  }

  static Future<_Mailbox> open(String relayUrl, ZIdentity who) async =>
      _Mailbox._(await RelayClient.connect(relayUrl, who));

  /// The first frame of [kind] that has arrived, acknowledged and taken out;
  /// null while none has. Frames of other kinds are left where they are.
  Map<String, Object?>? take(String kind) {
    for (var i = 0; i < _inbox.length; i++) {
      final Object? j;
      try {
        j = jsonDecode(_inbox[i].payload);
      } catch (_) {
        continue;
      }
      if (j is Map && j['k'] == kind) {
        _ack(_inbox.removeAt(i));
        return j.cast<String, Object?>();
      }
    }
    return null;
  }

  /// Whether the relay has reported that the frame this side sent as [id]
  /// was acknowledged by the mailbox it went to.
  bool acknowledged(String id) => _acknowledged.contains(id);

  void _ack(RelayInbound frame) {
    try {
      client.ackReceived(id: frame.id, from: frame.from);
    } catch (_) {
      // The connection has gone, or is going: the relay keeps the frame and
      // flushes it again to the next connection to this mailbox, as for any
      // envelope.
    }
  }

  /// Acknowledges whatever arrived and was not taken, then closes.
  Future<void> close() async {
    for (final frame in _inbox) {
      _ack(frame);
    }
    _inbox.clear();
    await _frames.cancel();
    await _receipts.cancel();
    await client.close();
  }
}
