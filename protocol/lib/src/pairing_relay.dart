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

const String _relayCtx = 'z-pair-relay:';
// v2 (§10.1) derives its throwaway mailboxes from a different context, so a
// v2 device and a v1 device holding the same code never meet: neither can be
// talked down to the other's ceremony, because neither is listening where the
// other speaks.
const String _relayCtxV2 = 'z-pair-relay-v2:';
// v3 (§10.2) the same way again: v3 transacts only on its own mailboxes.
const String _relayCtxV3 = 'z-pair-relay-v3:';

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
    final client =
        await RelayClient.connect(relayUrl, await relayIdentityV2(n.code, 'i'));
    final inbox = <RelayInbound>[];
    final sub = client.messages.listen(inbox.add);
    try {
      final rMailbox = await (await relayIdentityV2(n.code, 'r')).routingId();
      await client.send(
          to: rMailbox,
          id: 'z-pair-commit',
          payload: jsonEncode({'k': 'commit-v2', ...await n.commit()}));

      final Map<String, Object?> reply;
      try {
        reply = await _awaitKind(inbox, 'reply-v2', timeout);
      } on TimeoutException {
        // Nothing answered where a v2 device would. The likeliest reason by
        // far is that the other device is older: it is listening on the v1
        // mailbox, which this one deliberately does not speak on.
        throw const PairingAbort(
            'the other device did not answer — it may be running an older '
            'version of Z, which cannot pair with this one until it is updated');
      }
      final (open, session) = await n.open(reply);
      await client.send(
          to: rMailbox,
          id: 'z-pair-open',
          payload: jsonEncode({'k': 'open-v2', ...open}));

      if (!await confirm(session.sas)) return null;

      final env = await _awaitKind(inbox, 'enroll-v2', timeout);
      final data = await session.openEnrollment(unb64(env['blob'] as String));
      final account = await n.installFromData(data);
      return PairingResult(account, data);
    } finally {
      await sub.cancel();
      await client.close();
    }
  }

  /// EXISTING device, v2: await a commitment, reply, verify the opening, show
  /// the SAS, seal the enrollment.
  ///
  /// It also holds its **v1** mailbox open, and never answers there. That is
  /// the one direction in which an old peer is detectable: a v1 new device
  /// speaks first, so its `hello` arrives and can be recognised for what it
  /// is. Detect, do not transact — completing a v1 ceremony here would hand
  /// back exactly the assurance v2 exists to replace.
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
    final client =
        await RelayClient.connect(relayUrl, await relayIdentityV2(code, 'r'));
    final legacy =
        await RelayClient.connect(relayUrl, await relayIdentity(code, 'r'));
    final inbox = <RelayInbound>[];
    final legacyInbox = <RelayInbound>[];
    final sub = client.messages.listen(inbox.add);
    final legacySub = legacy.messages.listen(legacyInbox.add);
    try {
      final iMailbox = await (await relayIdentityV2(code, 'i')).routingId();
      final commit = await _awaitKind(inbox, 'commit-v2', timeout,
          alsoWatch: legacyInbox, abortOnKind: 'hello');
      final (reply, pending) = await PairingResponderV2.reply(commit);
      await client.send(
          to: iMailbox,
          id: 'z-pair-reply',
          payload: jsonEncode({'k': 'reply-v2', ...reply}));

      final open = await _awaitKind(inbox, 'open-v2', timeout);
      final session = await pending.accept(open);

      if (!await confirm(session.sas)) return null;

      final newDeviceCert = await session.signedPeerCert(me);
      final sealed = await session.sealEnrollment(me,
          contacts: contacts,
          includeAccountRoot: includeAccountRoot,
          displayName: displayName,
          contactState: contactState,
          hostBundle: hostBundle);
      await client.send(
          to: iMailbox,
          id: 'z-pair-enroll',
          payload: jsonEncode({'k': 'enroll-v2', 'blob': b64(sealed)}));
      return newDeviceCert;
    } finally {
      await sub.cancel();
      await legacySub.cancel();
      await client.close();
      await legacy.close();
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
    final client =
        await RelayClient.connect(relayUrl, await relayIdentityV3(n.code, 'i'));
    final inbox = <RelayInbound>[];
    final sub = client.messages.listen(inbox.add);
    try {
      final rMailbox = await (await relayIdentityV3(n.code, 'r')).routingId();
      await client.send(
          to: rMailbox,
          id: 'z-pair-commit',
          payload: jsonEncode({'k': 'commit-v3', ...await n.commit()}));

      final Map<String, Object?> reply;
      try {
        reply = await _awaitKind(inbox, 'reply-v3', timeout);
      } on TimeoutException {
        throw const PairingAbort(
            'the other device did not answer — it may be running an older '
            'version of Z, which cannot pair with this one until it is updated');
      }
      final (open, session) = await n.open(reply);
      await client.send(
          to: rMailbox,
          id: 'z-pair-open',
          payload: jsonEncode({'k': 'open-v3', ...open}));

      if (!await confirm(session.sas)) return null;

      final env = await _awaitKind(inbox, 'enroll-v3', timeout);
      final data = await session.openEnrollment(unb64(env['blob'] as String));
      final account = await n.installFromData(data);
      return PairingResult(account, data);
    } finally {
      await sub.cancel();
      await client.close();
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
  /// which device to update. Detect, do not transact.
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
    RelayClient? client, v2, v1;
    StreamSubscription<RelayInbound>? sub, v2Sub, v1Sub;
    try {
      client =
          await RelayClient.connect(relayUrl, await relayIdentityV3(code, 'r'));
      v2 =
          await RelayClient.connect(relayUrl, await relayIdentityV2(code, 'r'));
      v1 = await RelayClient.connect(relayUrl, await relayIdentity(code, 'r'));
      final inbox = <RelayInbound>[];
      final v2Inbox = <RelayInbound>[];
      final v1Inbox = <RelayInbound>[];
      sub = client.messages.listen(inbox.add);
      v2Sub = v2.messages.listen(v2Inbox.add);
      v1Sub = v1.messages.listen(v1Inbox.add);
      final iMailbox = await (await relayIdentityV3(code, 'i')).routingId();
      final commit =
          await _awaitV3Commit(inbox, timeout, v2: v2Inbox, v1: v1Inbox);
      final (reply, pending) =
          await PairingResponderV3.reply(commit, code: code);
      await client.send(
          to: iMailbox,
          id: 'z-pair-reply',
          payload: jsonEncode({'k': 'reply-v3', ...reply}));

      final open = await _awaitKind(inbox, 'open-v3', timeout);
      final session = await pending.accept(open);

      if (!await confirm(session.sas)) return null;

      final newDeviceCert = await session.signedPeerCert(me);
      final sealed = await session.sealEnrollment(me,
          contacts: contacts,
          displayName: displayName,
          contactState: contactState,
          hostBundle: hostBundle,
          pqdc: attest == null ? null : await attest(session));
      await client.send(
          to: iMailbox,
          id: 'z-pair-enroll',
          payload: jsonEncode({'k': 'enroll-v3', 'blob': b64(sealed)}));
      return newDeviceCert;
    } finally {
      await sub?.cancel();
      await v2Sub?.cancel();
      await v1Sub?.cancel();
      await client?.close();
      await v2?.close();
      await v1?.close();
    }
  }

  /// [_awaitKind] for v3's first frame, with both older ceremonies' first
  /// frames watched for — only read, never answered: a `commit-v2` on the v2
  /// mailbox, or a `hello` on the v1 one, ends the wait with
  /// [PairingPeerOutdated] naming the version.
  static Future<Map<String, Object?>> _awaitV3Commit(
      List<RelayInbound> inbox, Duration timeout,
      {required List<RelayInbound> v2, required List<RelayInbound> v1}) async {
    final deadline = DateTime.now().add(timeout);
    while (true) {
      final found = _take(inbox, 'commit-v3');
      if (found != null) return found;
      if (_take(v2, 'commit-v2') != null) throw const PairingPeerOutdated(2);
      if (_take(v1, 'hello') != null) throw const PairingPeerOutdated(1);
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('pairing: no "commit-v3" frame arrived', timeout);
      }
      await Future<void>.delayed(const Duration(milliseconds: 25));
    }
  }

  /// Waits for a frame of [kind]. [alsoWatch] is a second inbox that is only
  /// ever read, never answered: a frame of [abortOnKind] there ends the wait
  /// with a [PairingAbort] naming the version problem.
  static Future<Map<String, Object?>> _awaitKind(
      List<RelayInbound> inbox, String kind, Duration timeout,
      {List<RelayInbound>? alsoWatch, String? abortOnKind}) async {
    final deadline = DateTime.now().add(timeout);
    while (true) {
      final found = _take(inbox, kind);
      if (found != null) return found;
      if (alsoWatch != null && abortOnKind != null) {
        if (_take(alsoWatch, abortOnKind) != null) {
          throw const PairingAbort(
              'the other device is running an older version of Z: update it, '
              'then pair again');
        }
      }
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
