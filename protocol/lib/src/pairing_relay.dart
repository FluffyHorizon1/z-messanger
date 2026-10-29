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
/// Two frames are acknowledged later in v3, and each acknowledgement is a
/// signal: the new device acknowledges the reply only once its person has
/// said the digits match, and the existing device sends the enrolment only
/// once the relay has reported that; and it acknowledges the enrolment only
/// once it has installed it, and the existing device links it only on that
/// report. A copy of a frame that the relay delivers again is dropped and
/// never acknowledged ([_Mailbox]). The v1 runners are left as builds before
/// v2 ran them.

const String _relayCtx = 'z-pair-relay:';
// v2 (§10.1) derives its throwaway mailboxes from a different context, so a
// v2 device and a v1 device holding the same code never meet: neither can be
// talked down to the other's ceremony, because neither is listening where the
// other speaks.
const String _relayCtxV2 = 'z-pair-relay-v2:';
// v3 (§10.2) the same way again: v3 transacts only on its own mailboxes.
const String _relayCtxV3 = 'z-pair-relay-v3:';

/// The longest a v2 existing device waits, once its enrolment is sent, for
/// the relay to report that the new device acknowledged it. A v2 new device
/// acknowledges the moment it reads the frame, so the report comes back
/// within a poll or two; one that is gone never acknowledges, and the wait
/// ends here rather than at the ceremony's timeout. v3 waits longer, and
/// links on the report alone ([RelayPairing.runExistingDeviceV3]).
const Duration _enrolmentReceiptWait = Duration(seconds: 10);

/// One completed enrollment on the new device.
class PairingResult {
  final AccountIdentity account;
  final EnrollmentData data; // contacts + display name that came across
  PairingResult(this.account, this.data);
}

class RelayPairing {
  /// What v3 allows an enrolment, beyond the ceremony's timeout, to be
  /// sealed, to cross the relay, and to be opened and installed (§10.2):
  /// fifteen seconds. The new device waits for the enrolment the timeout and
  /// this margin from its person's confirmation, and the existing device
  /// sends one only if its own person confirmed within the timeout of that,
  /// so the margin is all an enrolment has to arrive in.
  ///
  /// The enrolment is one relay frame: the app cuts the contacts' state to
  /// 600 KiB of plaintext, and the relay refuses a frame over 1 000 000
  /// bytes (§12.4). Signing the certificate and the `pqdc` and sealing take
  /// well under a second; the rest is the frame going up from the existing
  /// device and then down to the new one, through a relay that holds it whole
  /// before it passes it on. Fifteen seconds moves a frame of the cap's size
  /// at about 1.1 Mbit/s each way, and one of a quarter of it — an account of
  /// some fifty contacts — at about 270 kbit/s. Too little, and an enrolment
  /// arrives after the new device stopped waiting: it is not acknowledged,
  /// and nothing is linked. Too much, and the existing device keeps the
  /// person waiting longer when the new device has gone.
  static const Duration enrolmentMargin = Duration(seconds: 15);

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
        throw const PairingNoAnswer();
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
          wait: timeout < _enrolmentReceiptWait
              ? timeout
              : _enrolmentReceiptWait);
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
  /// not: there is no fallback, and the wait ends in [PairingNoAnswer]. The
  /// first reply is the one it answers (§10.2 rule 5): [n] decapsulates once
  /// and opens no second ceremony. That reply is acknowledged once [confirm]
  /// says the digits match, and not otherwise: the existing device sends
  /// nothing of the account before the relay reports the acknowledgement.
  ///
  /// The enrolment is waited for [timeout] and [margin] from then, and
  /// acknowledged only once it is opened and installed — and, with
  /// [install], kept wherever the caller keeps it: the existing device links
  /// this one on the relay's report of that acknowledgement, so the report
  /// means this device has its account. Anything that fails before it leaves
  /// the enrolment unacknowledged, and the existing device links nothing.
  static Future<PairingResult?> runNewDeviceV3({
    required String relayUrl,
    required PairingInitiatorV3 n,
    required Future<bool> Function(String sas) confirm,
    Duration timeout = const Duration(seconds: 40),
    Duration margin = enrolmentMargin,
    Future<void> Function(PairingResult result)? install,
  }) async {
    final box =
        await _Mailbox.open(relayUrl, await relayIdentityV3(n.code, 'i'));
    try {
      final rMailbox = await (await relayIdentityV3(n.code, 'r')).routingId();
      await box.client.send(
          to: rMailbox,
          id: 'z-pair-commit',
          payload: jsonEncode({'k': 'commit-v3', ...await n.commit()}));

      final (Map<String, Object?>, RelayInbound) replied;
      try {
        replied = await _awaitFrameHeld(box, 'reply-v3', timeout);
      } on TimeoutException {
        throw const PairingNoAnswer();
      }
      final (open, session) = await n.open(replied.$1);
      await box.client.send(
          to: rMailbox,
          id: 'z-pair-open',
          payload: jsonEncode({'k': 'open-v3', ...open}));

      // The reply is acknowledged once this device's person has said the
      // digits match, and not before or otherwise: that acknowledgement,
      // which the relay reports to the existing device, is what lets it send
      // the enrolment (§10.2). A person who says they differ leaves the
      // reply unacknowledged, and is sent nothing of the account.
      if (!await confirm(session.sas)) return null;
      box.acknowledge(replied.$2);

      final enrolment =
          await _awaitFrameHeld(box, 'enroll-v3', timeout + margin);
      final data = await session
          .openEnrollment(unb64(enrolment.$1['blob'] as String));
      final result = PairingResult(await n.installFromData(data), data);
      if (install != null) await install(result);
      box.acknowledge(enrolment.$2);
      return result;
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
  /// Once [confirm] says the digits match it waits, up to [timeout], for the
  /// relay to report that the new device acknowledged its reply, which the
  /// new device does only once its own person has said they match; without
  /// that it sends nothing and returns null, as a cancelled link. When that
  /// report came more than [timeout] before this device's person confirmed,
  /// the new device — which waits [timeout] and [margin] from its own
  /// person's confirmation — would have stopped before an enrolment reached
  /// it: nothing is sent ([PairingPeerGaveUp]).
  ///
  /// [attest] is asked, once both people have said so, for the new device's
  /// `pqdc` (ADR 0033 §1) — the root's signature over what the session says
  /// the new device opened — and its answer is sealed into the enrolment as
  /// it is; null, or no [attest], sends none. The enrolment never carries
  /// the account root.
  ///
  /// The certificate is returned — the caller links the device — only once
  /// the relay reports the new device's acknowledgement of the enrolment,
  /// which it makes once it has opened and installed it: waited for as long
  /// as that can take, the new device's [timeout] and twice [margin]. With
  /// none, the new device did not finish, and nothing is linked
  /// ([PairingPeerUnfinished]).
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
    Duration margin = enrolmentMargin,
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
      // §10 has both people compare the digits before the enrolment goes,
      // and the new device says its person did by acknowledging the reply.
      // Until the relay reports that, nothing of the account leaves here: a
      // new device whose person said they differ is sent no enrolment, and
      // its device is not linked — null, as a cancelled link is.
      if (!await _awaitAcknowledged(box, 'z-pair-reply', timeout)) {
        return null;
      }
      // The new device has waited for the enrolment since it acknowledged
      // the reply, and goes on for [timeout] and [margin] from then. If that
      // was more than [timeout] before this device's person confirmed, an
      // enrolment sent now has less than the margin to reach it: none is.
      final since = box.sinceAcknowledged('z-pair-reply')!;
      if (since > timeout) throw PairingPeerGaveUp(since);

      final newDeviceCert = await session.signedPeerCert(me);
      final sealed = await session.sealEnrollment(me,
          contacts: contacts,
          displayName: displayName,
          contactState: contactState,
          hostBundle: hostBundle,
          pqdc: attest == null ? null : await attest(session));
      if (!await _sendEnrolment(box,
          to: iMailbox,
          payload: jsonEncode({'k': 'enroll-v3', 'blob': b64(sealed)}),
          wait: timeout + margin * 2)) {
        throw const PairingPeerUnfinished();
      }
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

  /// [_awaitFrame] without the acknowledgement: the frame is taken and handed
  /// back with its relay envelope, for the caller to acknowledge when — and
  /// only if — it decides to ([_Mailbox.acknowledge]). Until then the relay
  /// keeps it, and a mailbox that closes does not acknowledge it either.
  static Future<(Map<String, Object?>, RelayInbound)> _awaitFrameHeld(
      _Mailbox box, String kind, Duration timeout) async {
    final deadline = DateTime.now().add(timeout);
    while (true) {
      final found = box.takeHeld(kind);
      if (found != null) return found;
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('pairing: no "$kind" frame arrived', timeout);
      }
      await Future<void>.delayed(const Duration(milliseconds: 25));
    }
  }

  /// Whether the relay reports, within [timeout], that the frame this side
  /// sent as [id] was acknowledged by the mailbox it went to; false when the
  /// time runs out or the connection goes first.
  static Future<bool> _awaitAcknowledged(
      _Mailbox box, String id, Duration timeout) async {
    final deadline = DateTime.now().add(timeout);
    while (!box.acknowledged(id)) {
      if (!box.client.isOpen || DateTime.now().isAfter(deadline)) {
        return false;
      }
      await Future<void>.delayed(const Duration(milliseconds: 25));
    }
    return true;
  }

  /// The existing device's last frame: the enrolment, sent, and then the
  /// connection held — while it is open, for at most [wait] — until the
  /// relay reports that the new device acknowledged it; whether it did. The
  /// relay's receipt for that acknowledgement is handed to this side as it
  /// is made, instead of being queued for a mailbox nobody reads again. v2
  /// waits briefly and ignores the answer; v3 links on it.
  static Future<bool> _sendEnrolment(_Mailbox box,
      {required String to,
      required String payload,
      required Duration wait}) async {
    const id = 'z-pair-enroll';
    await box.client.send(to: to, id: id, payload: payload);
    final deadline = DateTime.now().add(wait);
    while (!box.acknowledged(id) &&
        box.client.isOpen &&
        DateTime.now().isBefore(deadline)) {
      await Future<void>.delayed(const Duration(milliseconds: 25));
    }
    return box.acknowledged(id);
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
/// acknowledged when the mailbox closes: a frame of a kind this side was
/// not waiting for. Nothing of a ceremony is left on the relay for
/// `QUEUE_TTL_HOURS` by the side that read it, but a frame taken to be
/// acknowledged later ([takeHeld]) and never acknowledged — v3's reply, at a
/// new device whose person said the digits differ; v3's enrolment, at one
/// that could not open or install it — and a frame whose acknowledgement
/// tells the other device something ([_signals]), which closing never
/// acknowledges, whatever kept it from being taken.
///
/// A relay delivers at least once (§12.5): it sends a mailbox again on a
/// new connection, and an HA relay sends one again on a live connection when
/// it has not moved for a sweep (`reflushStalled`). A copy of a frame this
/// mailbox holds or has handed out — the same id from the same sender — is
/// dropped as it arrives and never acknowledged: the copy handed out is the
/// one acknowledged, or not, and an acknowledgement of a later copy is the
/// same acknowledgement to the relay. A later copy of a reply taken to be
/// acknowledged later used to sit untaken, and closing acknowledged it: on
/// an HA relay a new device whose person said the digits differ more than a
/// sweep after the reply arrived told the existing device they matched.
class _Mailbox {
  final RelayClient client;
  final _inbox = <RelayInbound>[];
  final _handedOut = <String>{};

  /// When the relay reported each of this side's frames acknowledged, by its
  /// id, on [_clock]: the first report, which is when it was made.
  final _acknowledged = <String, Duration>{};
  final _clock = Stopwatch()..start();
  late final StreamSubscription<RelayInbound> _frames;
  late final StreamSubscription<DeliveredReceipt> _receipts;

  /// The kinds whose acknowledgement is a signal to the other device: v3's
  /// reply, which the new device acknowledges once its person has said the
  /// digits match, and v3's enrolment, which it acknowledges once it has
  /// installed it (§10.2). Acknowledged only by the step that means it;
  /// closing never acknowledges one.
  static const _signals = {'reply-v3', 'enroll-v3'};

  _Mailbox._(this.client) {
    _frames = client.messages.listen(_arrived);
    _receipts = client.delivered
        .listen((r) => _acknowledged.putIfAbsent(r.id, () => _clock.elapsed));
  }

  /// A frame by what the relay knows it by: its id and its sender.
  static String _key(RelayInbound f) => '${f.id}\u0000${f.from}';

  void _arrived(RelayInbound f) {
    final k = _key(f);
    if (_handedOut.contains(k) || _inbox.any((e) => _key(e) == k)) return;
    _inbox.add(f);
  }

  /// The kind (`k`) [frame] says it is, or null.
  static String? _kindOf(RelayInbound frame) {
    try {
      final j = jsonDecode(frame.payload);
      return j is Map && j['k'] is String ? j['k'] as String : null;
    } catch (_) {
      return null;
    }
  }

  static Future<_Mailbox> open(String relayUrl, ZIdentity who) async =>
      _Mailbox._(await RelayClient.connect(relayUrl, who));

  /// The first frame of [kind] that has arrived, acknowledged and taken out;
  /// null while none has. Frames of other kinds are left where they are.
  Map<String, Object?>? take(String kind) {
    final found = takeHeld(kind);
    if (found == null) return null;
    _ack(found.$2);
    return found.$1;
  }

  /// [take] without the acknowledgement: the frame and its envelope, taken
  /// out, for the caller to [acknowledge] when it decides to. A frame taken
  /// this way is no longer this mailbox's to acknowledge when it closes, and
  /// a later copy of it is dropped as it arrives.
  (Map<String, Object?>, RelayInbound)? takeHeld(String kind) {
    for (var i = 0; i < _inbox.length; i++) {
      final Object? j;
      try {
        j = jsonDecode(_inbox[i].payload);
      } catch (_) {
        continue;
      }
      if (j is Map && j['k'] == kind) {
        final frame = _inbox.removeAt(i);
        _handedOut.add(_key(frame));
        return (j.cast<String, Object?>(), frame);
      }
    }
    return null;
  }

  /// Acknowledges [frame], one [takeHeld] handed out.
  void acknowledge(RelayInbound frame) => _ack(frame);

  /// Whether the relay has reported that the frame this side sent as [id]
  /// was acknowledged by the mailbox it went to.
  bool acknowledged(String id) => _acknowledged.containsKey(id);

  /// How long ago the relay reported the frame this side sent as [id]
  /// acknowledged; null while it has not.
  Duration? sinceAcknowledged(String id) {
    final at = _acknowledged[id];
    return at == null ? null : _clock.elapsed - at;
  }

  void _ack(RelayInbound frame) {
    try {
      client.ackReceived(id: frame.id, from: frame.from);
    } catch (_) {
      // The connection has gone, or is going: the relay keeps the frame and
      // flushes it again to the next connection to this mailbox, as for any
      // envelope.
    }
  }

  /// Acknowledges whatever arrived and was not taken, but a frame whose
  /// acknowledgement is a signal ([_signals]), then closes.
  Future<void> close() async {
    for (final frame in _inbox) {
      if (!_signals.contains(_kindOf(frame))) _ack(frame);
    }
    _inbox.clear();
    await _frames.cancel();
    await _receipts.cancel();
    await client.close();
  }
}
