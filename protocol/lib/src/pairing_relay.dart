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
/// never acknowledged ([_Mailbox]). A wait in v2 or v3 ends at once when its
/// connection closes, and says so — [PairingTakenOver] when the relay closed
/// it for another login to the same mailbox, which is anyone else who holds
/// the code. A v3 existing device's attempt can also be stopped from outside
/// it until it sends the enrolment ([PairingCancel]), as its device does
/// before it runs another on the same code. The v1 runners are left as
/// builds before v2 ran them.

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

/// A way to stop a v3 existing device's attempt from outside it
/// ([RelayPairing.runExistingDeviceV3]): the app's link screen stops the
/// attempt it started when its person leaves it, and the app stops an
/// attempt on a code before it starts another on the same code, which would
/// otherwise log in as the same mailbox and have the relay close the first
/// as if someone else held the code. The new device's link screen stops its
/// own attempt the same way when it is left ([RelayPairing.runNewDeviceV3]):
/// until it begins to install the enrolment, after which it runs to its
/// end, so that a device that holds the account is listed.
///
/// The attempt stops at its next step — while it waits for a frame, for the
/// relay or for its person — in [PairingCancelled], until it sends the
/// enrolment: from then on the new device may come to hold the account, and
/// only the report the attempt goes on to wait for can list it, so it runs
/// to its end whatever [cancel] says ([sentEnrolment]). The one wait it sees
/// out is the relay's word on the existing device's reply, once that is on
/// its way: whether the new device can hold the reply is what decides
/// whether the code has a ceremony left ([answered]). What the relay holds
/// for this side that it had not read, or not answered, when it stopped is
/// left unacknowledged, for the next attempt on the code to read.
///
/// A stopped attempt never says it was taken over, since the login that
/// closed its connection may have been its caller's own next attempt; it
/// records whether one had ([closedByAnotherLogin]), and a caller that
/// starts no other attempt on the code until this one is over knows that
/// login was someone else's.
class PairingCancel {
  final _asked = Completer<void>();
  bool _sentEnrolment = false;
  bool _closedByAnotherLogin = false;
  bool _answered = false;
  bool _installing = false;

  /// Asks the attempt to stop.
  void cancel() {
    if (!_asked.isCompleted) _asked.complete();
  }

  /// Whether [cancel] has been called.
  bool get isCancelled => _asked.isCompleted;

  /// Whether the attempt has sent the enrolment, after which it runs to its
  /// end, cancelled or not.
  bool get sentEnrolment => _sentEnrolment;

  /// Whether, when the attempt stopped, the relay had closed its connection
  /// because another connection logged in as its mailbox: someone else
  /// holding the code, unless it was the caller's own next attempt on it.
  bool get closedByAnotherLogin => _closedByAnotherLogin;

  /// Whether the relay has taken the attempt's reply to the new device's
  /// commitment. The new device answers the first reply it gets and no other
  /// (§10.2 rule 5), so once the relay has one for it a later attempt on the
  /// code has no ceremony to run unless this one finished it. A reply the
  /// relay never said it took leaves this false: until 2026-10-31 it was set
  /// before the reply went, and a code whose reply never left the device
  /// could be taken for one answered.
  bool get answered => _answered;

  /// Whether the attempt is to stop: asked to, with the enrolment neither
  /// sent (an existing device) nor being installed (a new device).
  bool get _stops => isCancelled && !_sentEnrolment && !_installing;
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
  /// The enrolment is waited for [timeout] and [margin] from then, and with
  /// none the attempt ends in [PairingNoEnrolment]. It is acknowledged only
  /// once it is opened and installed, and with [install] kept wherever the
  /// caller keeps it: the existing device links this one on the relay's
  /// report of that acknowledgement, so the report means this device has its
  /// account. Anything that fails before it leaves the enrolment
  /// unacknowledged, and the existing device links nothing; an enrolment
  /// that does not open or does not install ends the attempt in
  /// [PairingInstallFailed].
  ///
  /// A connection that closes ends any wait at once, as a [RelayException],
  /// or as [PairingTakenOver] when the relay closed it because another
  /// connection logged in as this device's mailbox — someone else holding
  /// the code — and so does one that closes while the relay has yet to take
  /// a frame this side sent ([_post]). A takeover is also what the attempt
  /// ends in when it happened while [confirm] was asking, whatever the
  /// person answered: that login can acknowledge the reply, and the existing
  /// device may list this device on it (§10.2).
  ///
  /// [cancel] stops the attempt from outside it, at its next step, until it
  /// begins to install the enrolment ([PairingCancel]): it ends in
  /// [PairingCancelled], and acknowledges nothing — not the reply, so the
  /// existing device sends nothing of the account, nor an enrolment it was
  /// sent, so the existing device lists nothing. An install that has begun
  /// runs to its end and is acknowledged: a device that holds the account
  /// is listed.
  static Future<PairingResult?> runNewDeviceV3({
    required String relayUrl,
    required PairingInitiatorV3 n,
    required Future<bool> Function(String sas) confirm,
    Duration timeout = const Duration(seconds: 40),
    Duration margin = enrolmentMargin,
    Future<void> Function(PairingResult result)? install,
    PairingCancel? cancel,
  }) async {
    if (cancel != null && cancel._stops) throw const PairingCancelled();
    final box = await _Mailbox.open(
        relayUrl, await relayIdentityV3(n.code, 'i'),
        cancel: cancel);
    try {
      final rMailbox = await (await relayIdentityV3(n.code, 'r')).routingId();
      await _post(box,
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
      await _post(box,
          to: rMailbox,
          id: 'z-pair-open',
          payload: jsonEncode({'k': 'open-v3', ...open}));

      // The reply is acknowledged once this device's person has said the
      // digits match, and not before or otherwise: that acknowledgement,
      // which the relay reports to the existing device, is what lets it send
      // the enrolment (§10.2). A person who says they differ leaves the
      // reply unacknowledged, and is sent nothing of the account.
      final matched = await _unlessCancelled(box, () => confirm(session.sas));
      // While the person compared, someone else holding the code may have
      // logged in as this mailbox, and the relay closed this connection for
      // it: that login is handed the reply and can acknowledge it, which the
      // existing device takes for this device's word. Said, whatever the
      // person answered — the existing device may list this device on that
      // word — and at once, rather than at the end of a wait for an
      // enrolment that now goes to the other login.
      if (_takenOver(box)) throw const PairingTakenOver();
      if (!matched) return null;
      // Stopped before the reply is acknowledged: the existing device then
      // sends nothing of the account.
      if (box.cancelled) throw const PairingCancelled();
      box.acknowledge(replied.$2);

      final (Map<String, Object?>, RelayInbound) enrolment;
      try {
        enrolment = await _awaitFrameHeld(box, 'enroll-v3', timeout + margin);
      } on TimeoutException catch (e) {
        throw PairingNoEnrolment(e.message ?? 'pairing: no enrolment');
      }
      // An enrolment that does not open, breaks a rule, or fails to install
      // is one failure to this device's person: it is not linked, and the
      // enrolment is not acknowledged.
      final PairingResult result;
      try {
        final blob = enrolment.$1['blob'];
        if (blob is! String) throw const FormatException('no sealed blob');
        final data = await session.openEnrollment(unb64(blob));
        result = PairingResult(await n.installFromData(data), data);
      } catch (e) {
        throw PairingInstallFailed(e);
      }
      // The last point a cancel stops ([PairingCancel]): from here the
      // install writes this device's store, and one that has begun runs to
      // its end and is acknowledged, so that no device holds an account its
      // existing device does not list.
      if (box.cancelled) throw const PairingCancelled();
      cancel?._installing = true;
      try {
        if (install != null) await install(result);
      } catch (e) {
        throw PairingInstallFailed(e);
      }
      box.acknowledge(enrolment.$2);
      return result;
    } on Exception {
      // Stopped on this device ([cancel]), whatever closed the connection
      // meanwhile; whether another login had closed it is kept for the
      // caller.
      if (cancel != null && cancel._stops) {
        cancel._closedByAnotherLogin = _takenOver(box);
        throw const PairingCancelled();
      }
      rethrow;
    } finally {
      // A cancelled attempt acknowledges nothing it did not read.
      await box.close(acknowledge: !(cancel?._stops ?? false));
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
  /// that it sends nothing ([PairingPeerUnconfirmed]). When that report came
  /// more than [timeout] before this device's person confirmed,
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
  /// as that can take, the new device's [timeout] and twice [margin], and
  /// whether or not the relay has said it took the enrolment. With none,
  /// the new device did not finish, and nothing is linked
  /// ([PairingPeerUnfinished]). When this side's connection closes first,
  /// once the enrolment has been handed over, nothing is linked either, and
  /// the attempt says what happened rather than blame the new device: the
  /// enrolment may or may not have reached it ([PairingEnrolmentInterrupted]).
  /// When the relay refuses the frame, nothing reached it
  /// ([PairingEnrolmentRefused]). Every other wait ends at once when the
  /// connection closes, and any of them, that one too, in
  /// [PairingTakenOver] when the relay closed it because another connection
  /// logged in as this device's mailbox. Before it throws that, it logs in
  /// once as the new device's mailbox and leaves, so that a new device
  /// still in the ceremony is closed the same way and says so too, rather
  /// than wait out its timer and name a cause it cannot see (§10.2).
  ///
  /// A takeover is what the attempt ends in, too, when it happened while
  /// [confirm] was asking, whatever the person answered — the digits
  /// differing included — as on the new device.
  ///
  /// [cancel] stops the attempt from outside it, at its next step, until it
  /// sends the enrolment ([PairingCancel]): it ends in [PairingCancelled],
  /// whatever closed its connection meanwhile, and so logs in as no other
  /// mailbox, and leaves unacknowledged what it had not read — and the
  /// commitment, when it had not yet sent its reply — for the next attempt
  /// on the code. Whether another login had closed its connection by then
  /// is kept on [cancel] ([PairingCancel.closedByAnotherLogin]), for the
  /// caller to judge. One that has sent the enrolment runs to its end.
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
    PairingCancel? cancel,
  }) async {
    // The three connections are made inside the try, one after another, so
    // a relay that refuses the second or the third still has the ones
    // before it closed: nothing is left open, pinging, as a mailbox nobody
    // reads.
    _Mailbox? box, v2, v1;
    try {
      if (cancel != null && cancel._stops) throw const PairingCancelled();
      box = await _Mailbox.open(relayUrl, await relayIdentityV3(code, 'r'),
          cancel: cancel);
      v2 = await _Mailbox.open(relayUrl, await relayIdentityV2(code, 'r'));
      v1 = await _Mailbox.open(relayUrl, await relayIdentity(code, 'r'));
      final iMailbox = await (await relayIdentityV3(code, 'i')).routingId();
      final (commit, committed) =
          await _awaitCommitHeld(box, 'commit-v3', timeout, v2: v2, v1: v1);
      // The older mailboxes were held for the first frame alone.
      await v2.close();
      v2 = null;
      await v1.close();
      v1 = null;
      final (Map<String, Object?>, PairingResponderV3) answer;
      try {
        answer = await PairingResponderV3.reply(commit, code: code);
      } catch (_) {
        // A commitment that cannot be answered is nobody's to read again.
        box.acknowledge(committed);
        rethrow;
      }
      // The commitment is acknowledged as its answer is handed over, with
      // nothing between the two: an attempt cancelled before then leaves it
      // at the relay, and the next attempt on the code answers it.
      if (box.cancelled) throw const PairingCancelled();
      box.acknowledge(committed);
      final (reply, pending) = answer;
      // A stop that comes while the reply is going up waits for the relay's
      // word on it: taken, the new device can hold this reply and will take
      // no other, so the code has had its answer ([PairingCancel.answered]);
      // not taken, the next attempt on the code may find the commitment and
      // answer it. Either way the attempt then stops.
      await _post(box,
          to: iMailbox,
          id: 'z-pair-reply',
          payload: jsonEncode({'k': 'reply-v3', ...reply}),
          whole: true);
      cancel?._answered = true;
      if (box.cancelled) throw const PairingCancelled();

      final open = await _awaitFrame(box, 'open-v3', timeout);
      final session = await pending.accept(open);

      final matched = await _unlessCancelled(box, () => confirm(session.sas));
      // While the person compared, someone else holding the code may have
      // logged in as this mailbox, and the relay closed this connection for
      // it: said, whatever the person answered, as the new device says it.
      // An answer that the digits differ used to end the attempt as
      // cancelled, the code not kept and the new device left waiting.
      if (_takenOver(box)) throw const PairingTakenOver();
      if (!matched) return null;
      // §10 has both people compare the digits before the enrolment goes,
      // and the new device says its person did by acknowledging the reply.
      // Until the relay reports that, nothing of the account leaves here: a
      // new device whose person said they differ is sent no enrolment, and
      // its device is not linked.
      if (!await _awaitAcknowledged(box, 'z-pair-reply', timeout)) {
        throw const PairingPeerUnconfirmed();
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
      final (sent, refusal) = await _sendEnrolmentV3(box,
          to: iMailbox,
          payload: jsonEncode({'k': 'enroll-v3', 'blob': b64(sealed)}),
          wait: timeout + margin * 2);
      switch (sent) {
        case _Sent.reported:
          return newDeviceCert;
        case _Sent.cut:
          // This side's connection went before the report, and with it any
          // way of telling whether the enrolment got to the relay: said as
          // that, and not as the new device's failure.
          if (_takenOver(box)) throw const PairingTakenOver();
          throw const PairingEnrolmentInterrupted();
        case _Sent.refused:
          throw PairingEnrolmentRefused(refusal ?? 'refused');
        case _Sent.unreported:
          throw const PairingPeerUnfinished();
      }
    } on Exception catch (e) {
      // Stopped on this device ([cancel]): said as that, whatever closed
      // the connection meanwhile — this device's next attempt on the code
      // may be what logged in as its mailbox — and nothing is done to the
      // new device's mailbox; whether another login had closed it is kept
      // for the caller, which knows whether that could have been its own.
      if (cancel != null && cancel._stops) {
        cancel._closedByAnotherLogin = box != null && _takenOver(box);
        throw const PairingCancelled();
      }
      if (e is PairingTakenOver) {
        // Someone else holding the code logged in as this device's mailbox.
        // The new device, if it is still in the ceremony, cannot see that:
        // it would wait out its timer and then name a cause it has no way
        // to know. Logging in once as its mailbox closes its connection the
        // same way, so that it stops at once, says another connection took
        // the link over, and draws a new code.
        await _closeTheOtherSide(relayUrl, await relayIdentityV3(code, 'i'));
      }
      rethrow;
    } finally {
      // A cancelled attempt leaves what it did not read for the next one.
      final done = !(cancel?._stops ?? false);
      await box?.close(acknowledge: done);
      await v2?.close(acknowledge: done);
      await v1?.close(acknowledge: done);
    }
  }

  /// What an existing device whose attempt was taken over does to the new
  /// device's v3 mailbox for [code] before it says so ([_closeTheOtherSide]),
  /// for a caller that knows of a takeover only once the attempt is over: one
  /// it stopped whose connection another login had closed, when the caller
  /// itself logs in as that mailbox again only after the attempt has ended
  /// ([PairingCancel.closedByAnotherLogin]).
  static Future<void> closeNewDeviceMailboxV3(
          String relayUrl, PairingCode code) async =>
      _closeTheOtherSide(relayUrl, await relayIdentityV3(code, 'i'));

  /// Logs in once as [mailbox], the other side's v3 mailbox, and leaves at
  /// once, reading and acknowledging nothing: the relay closes whatever
  /// connection held that mailbox with [relayCloseReplaced], as it closed
  /// this side's. Best effort: a relay this side cannot reach now changes
  /// nothing, and what the relay holds for that mailbox stays as it was.
  static Future<void> _closeTheOtherSide(
      String relayUrl, ZIdentity mailbox) async {
    try {
      final c = await RelayClient.connect(relayUrl, mailbox,
          timeout: const Duration(seconds: 5));
      await c.close();
    } catch (_) {}
  }

  /// Whether the relay closed [box]'s connection because another connection
  /// logged in as the same mailbox ([relayCloseReplaced]): both mailboxes'
  /// keys derive from the code alone, so that login is someone else who
  /// holds the code.
  static bool _takenOver(_Mailbox box) =>
      !box.client.isOpen && box.client.closeCode == relayCloseReplaced;

  /// What a wait on [box] ends in once its connection has closed:
  /// [PairingTakenOver] when another connection took the mailbox over, and
  /// otherwise a [RelayException] — this side's connection was lost, and the
  /// other device is not to blame for what it never received.
  static Exception _closed(_Mailbox box) => _takenOver(box)
      ? const PairingTakenOver()
      : RelayException('connection closed');

  /// Sends [payload] to [to] as [id] on [box], and waits for the relay to
  /// say it took it. A send that fails because the connection closed ends as
  /// a wait does once its connection has closed ([_closed]) —
  /// [PairingTakenOver] when the relay closed it for another login to the
  /// same mailbox — and not in the send's own words, which say only that the
  /// connection closed: the relay closes a connection for another login
  /// whether or not it has yet taken a frame still going up from it. An
  /// attempt cancelled before or meanwhile stops ([_unlessCancelled]) —
  /// meanwhile, unless [whole]: then a send under way is seen to its end, the
  /// relay's word on it or the connection's failure.
  static Future<void> _post(_Mailbox box,
      {required String to,
      required String id,
      required String payload,
      bool whole = false}) async {
    try {
      if (whole) {
        if (box.cancelled) throw const PairingCancelled();
        await box.client.send(to: to, id: id, payload: payload);
      } else {
        await _unlessCancelled(
            box, () => box.client.send(to: to, id: id, payload: payload));
      }
    } on RelayException {
      if (!box.client.isOpen) throw _closed(box);
      rethrow;
    }
  }

  /// What [step] comes to, or [PairingCancelled] — at once, without
  /// starting it, when [box]'s attempt is to stop already ([PairingCancel]),
  /// and as soon as it is asked to while [step] is under way, whatever
  /// [step] comes to later: a frame the relay has yet to take, or the
  /// person's answer to the digits.
  static Future<T> _unlessCancelled<T>(
      _Mailbox box, Future<T> Function() step) {
    if (box.cancelled) return Future<T>.error(const PairingCancelled());
    final going = step();
    final cancel = box.cancel;
    if (cancel == null) return going;
    return Future.any<T>([
      going,
      cancel._asked.future.then<T>((_) => throw const PairingCancelled()),
    ]);
  }

  /// [_awaitCommitHeld], the frame acknowledged as it is taken (v2).
  static Future<Map<String, Object?>> _awaitCommit(
      _Mailbox box, String kind, Duration timeout,
      {_Mailbox? v2, _Mailbox? v1}) async {
    final (found, frame) =
        await _awaitCommitHeld(box, kind, timeout, v2: v2, v1: v1);
    box.acknowledge(frame);
    return found;
  }

  /// [_awaitFrameHeld] for a ceremony's first frame, of [kind] on [box],
  /// with the older ceremonies' first frames watched for on their own
  /// mailboxes — only read, never answered: a `commit-v2` on [v2], or a
  /// `hello` on [v1], ends the wait with [PairingPeerOutdated] naming the
  /// version, and is acknowledged.
  static Future<(Map<String, Object?>, RelayInbound)> _awaitCommitHeld(
      _Mailbox box, String kind, Duration timeout,
      {_Mailbox? v2, _Mailbox? v1}) async {
    final deadline = DateTime.now().add(timeout);
    while (true) {
      if (box.cancelled) throw const PairingCancelled();
      final found = box.takeHeld(kind);
      if (found != null) return found;
      if (v2 != null && v2.take('commit-v2') != null) {
        throw const PairingPeerOutdated(2);
      }
      if (v1 != null && v1.take('hello') != null) {
        throw const PairingPeerOutdated(1);
      }
      if (!box.client.isOpen) throw _closed(box);
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('pairing: no "$kind" frame arrived', timeout);
      }
      await Future<void>.delayed(const Duration(milliseconds: 25));
    }
  }

  /// Waits for a frame of [kind] on [box], taking — and so acknowledging —
  /// the first that arrives. A connection that closes ends the wait at once
  /// ([_closed]), where it used to run on to its timeout and end as though
  /// the other device had sent nothing; an attempt cancelled stops
  /// ([PairingCancel]), and takes nothing.
  static Future<Map<String, Object?>> _awaitFrame(
      _Mailbox box, String kind, Duration timeout) async {
    final deadline = DateTime.now().add(timeout);
    while (true) {
      if (box.cancelled) throw const PairingCancelled();
      final found = box.take(kind);
      if (found != null) return found;
      if (!box.client.isOpen) throw _closed(box);
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
      if (box.cancelled) throw const PairingCancelled();
      final found = box.takeHeld(kind);
      if (found != null) return found;
      if (!box.client.isOpen) throw _closed(box);
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('pairing: no "$kind" frame arrived', timeout);
      }
      await Future<void>.delayed(const Duration(milliseconds: 25));
    }
  }

  /// Whether the relay reports, within [timeout], that the frame this side
  /// sent as [id] was acknowledged by the mailbox it went to; false when the
  /// time runs out. A connection that goes first ends it ([_closed]):
  /// nothing can be said of the other device then. An attempt cancelled
  /// stops ([PairingCancel]).
  static Future<bool> _awaitAcknowledged(
      _Mailbox box, String id, Duration timeout) async {
    final deadline = DateTime.now().add(timeout);
    while (!box.acknowledged(id)) {
      if (box.cancelled) throw const PairingCancelled();
      if (!box.client.isOpen) throw _closed(box);
      if (DateTime.now().isAfter(deadline)) return false;
      await Future<void>.delayed(const Duration(milliseconds: 25));
    }
    return true;
  }

  /// v2's last frame from the existing device: the enrolment, sent, and then
  /// the connection held — while it is open, for at most [wait] — until the
  /// relay reports that the new device acknowledged it; whether it did. The
  /// relay's receipt for that acknowledgement is handed to this side as it
  /// is made, instead of being queued for a mailbox nobody reads again. v2
  /// waits briefly and ignores the answer; v3 links on it
  /// ([_sendEnrolmentV3]).
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

  /// v3's last frame from the existing device: the enrolment, sent, and the
  /// connection then held — while it is open, for at most [wait] — until the
  /// relay reports that the new device acknowledged it. What ended the wait:
  /// that report; the time running out with none; the relay's refusal of the
  /// frame, with its code; or the connection closing first.
  ///
  /// The report is all that counts, and the relay's `sent` for the frame is
  /// not waited for: it says only that the relay took the frame, once the
  /// whole of it had arrived, and the enrolment can be installed and
  /// acknowledged without this side ever hearing it. An enrolment near the
  /// frame cap on a slow connection takes longer than
  /// [RelayClient.send]'s twenty seconds to go up, and the new device, which
  /// waits the margin for it, installs it all the same. A connection that
  /// closes once the frame has been handed over may have taken all of it to
  /// the relay, and its `sent` with it, or only part: this side cannot tell,
  /// and the caller says so ([PairingEnrolmentInterrupted]).
  ///
  /// It is the last step a cancel stops ([PairingCancel]): once the frame is
  /// handed over, the new device may come to hold the account, and only the
  /// report waited for here can list it, so the wait runs on, cancelled or
  /// not.
  static Future<(_Sent, String?)> _sendEnrolmentV3(_Mailbox box,
      {required String to,
      required String payload,
      required Duration wait}) async {
    const id = 'z-pair-enroll';
    String? refused;
    if (box.cancelled) throw const PairingCancelled();
    // A connection that has already closed would refuse the frame as it is
    // handed over: nothing of the enrolment leaves, and the step ends as any
    // other does when its connection has gone ([_closed]). A refusal after
    // the frame has been handed over fails the send's future, and ends the
    // wait; so does the connection closing, which fails it too.
    if (!box.client.isOpen) throw _closed(box);
    // Nothing between here and the frame's handing over waits on anything.
    box.cancel?._sentEnrolment = true;
    // The send's own timeout is twice the wait, so that it never ends the
    // wait: a `sent` that has not come by the deadline is no refusal.
    unawaited(box.client
        .send(to: to, id: id, payload: payload, timeout: wait * 2)
        .then<void>((_) {}, onError: (Object e) {
      refused = e is RelayException ? e.message : '$e';
    }));
    final deadline = DateTime.now().add(wait);
    while (!box.acknowledged(id) &&
        refused == null &&
        box.client.isOpen &&
        DateTime.now().isBefore(deadline)) {
      await Future<void>.delayed(const Duration(milliseconds: 25));
    }
    if (box.acknowledged(id)) return (_Sent.reported, null);
    // A closed connection fails the send too, so it is asked first: the
    // relay refused the frame only if the connection is still there.
    if (!box.client.isOpen) return (_Sent.cut, null);
    if (refused != null) return (_Sent.refused, refused);
    return (_Sent.unreported, null);
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

/// How a v3 enrolment's send ended ([RelayPairing._sendEnrolmentV3]).
enum _Sent {
  /// The relay reported the new device's acknowledgement of it.
  reported,

  /// The wait ran out with no report, the connection open throughout.
  unreported,

  /// The relay refused the frame.
  refused,

  /// This side's connection closed first.
  cut,
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
/// acknowledges, whatever kept it from being taken. An existing device's
/// attempt cancelled on its device ([PairingCancel]) acknowledges nothing as
/// it closes, nor the commitment it took and had not yet answered: the next
/// attempt on the code reads them.
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

  /// What can stop the attempt this mailbox is a side of from outside it,
  /// when something can ([PairingCancel]).
  final PairingCancel? cancel;
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

  _Mailbox._(this.client, this.cancel) {
    _frames = client.messages.listen(_arrived);
    _receipts = client.delivered
        .listen((r) => _acknowledged.putIfAbsent(r.id, () => _clock.elapsed));
  }

  /// Whether the attempt is to stop at its next step ([PairingCancel]).
  bool get cancelled => cancel?._stops ?? false;

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

  static Future<_Mailbox> open(String relayUrl, ZIdentity who,
          {PairingCancel? cancel}) async =>
      _Mailbox._(await RelayClient.connect(relayUrl, who), cancel);

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
  /// acknowledgement is a signal ([_signals]), then closes — acknowledging
  /// nothing when not to [acknowledge]: an attempt cancelled on this device
  /// leaves what it did not read at the relay for the next attempt on the
  /// code ([PairingCancel]).
  Future<void> close({bool acknowledge = true}) async {
    for (final frame in _inbox) {
      if (acknowledge && !_signals.contains(_kindOf(frame))) _ack(frame);
    }
    _inbox.clear();
    await _frames.cancel();
    await _receipts.cancel();
    await client.close();
  }
}
