import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:z_protocol/z_protocol.dart';

import 'sealing_keys.dart' show pqSealMayRide;
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

  /// ADR 0029: whether this device says, on every envelope it sends its own
  /// devices, which device-list shape it reads ([devlistReaderLevel], the
  /// `dlr` member beside `thread`, `dir` and `inner`). Always, but for a test
  /// running a device as a build from before the member existed. A root
  /// moves its account to v2-only signing only once every one of its linked
  /// devices has said it reads one, and this is where a linked device says
  /// it: every build reads the envelope by its three members and passes the
  /// rest by.
  final bool Function() advertiseReaderLevel;

  /// 44.3 (PROTOCOL §18.11): this device's `pqseal` for one of my devices
  /// when one is owed there — its bytes, as it rides this ratchet bare, the
  /// way an offer does: wrapped like a mirror, its 1 184-byte key would be
  /// encoded twice and leave the 4 096 bucket — or null. Asked as each send
  /// is made; whether it can ride that send is the channel's to say
  /// ([pqSealMayRide]). Null on a service that announces nothing.
  final Uint8List? Function(String deviceRid)? pqSealFor;

  /// 44.3: whether this device holds that device's sealing key, so the
  /// envelope going there says so (`pqs:1`, beside `dlr`).
  final bool Function(String deviceRid)? holdsSealKeyOf;

  /// 44.3: the devices a `pqseal` has just been queued for.
  final void Function(List<String> deviceRids)? onPqSealSent;

  /// 44.3 (§18.11): what an envelope from one of my devices says of sealing
  /// keys, told as it is decrypted, under the lock — so in the order the
  /// ratchet decrypted them: whether it came on a session that device has
  /// just opened ([newSession], which forgets that it holds this device's
  /// key), its `pqseal` when the envelope was one ([seal]), and whether it
  /// says it holds this device's key ([stamped], the wrapper's `pqs`). The
  /// owner keeps it in memory there and writes it down after; it must not
  /// step on this session.
  final void Function(String deviceRid, bool newSession, InnerMessage? seal,
      bool stamped)? onSealNews;

  /// 44.3: the devices a send has just opened a ratchet session to, under
  /// the lock, which forgets that they hold this device's key as one they
  /// open does ([onSealNews]).
  final void Function(String deviceRid)? onSessionOpened;

  /// 4.8.1: a session my device [deviceRid] has just opened, told before
  /// the session is written down, so that what the owner forgets of it
  /// ([onSealNews]'s `newSession`) is written first: if the session's write
  /// then fails, the envelope opens it again on its redelivery, where a
  /// forgetting written after a session that was could be lost with nothing
  /// to do it again. Whatever it throws is that write failing, and the
  /// envelope is left with the relay as for the session's own.
  final Future<void> Function(String deviceRid)? onNewSession;

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
    bool Function()? advertiseReaderLevel,
    this.pqSealFor,
    this.holdsSealKeyOf,
    this.onPqSealSent,
    this.onSealNews,
    this.onSessionOpened,
    this.onNewSession,
    DeviceSyncService? replacing,
  })  : advertiseReaderLevel = advertiseReaderLevel ?? _always,
        _state = replacing?._state ?? _SyncState();

  static bool _always() => true;

  /// 44.3: how many ratchet sessions [s] holds with each of my devices, read
  /// before a step that may open one ([_noteOpened]).
  static Map<String, int> _sessionCounts(AccountSession s) => {
        for (final r in s.targetRoutingIds)
          r: s.targetConversation(r)?.sessions.length ?? 0
      };

  /// 44.3: tells [onSessionOpened] of each device the step since [before]
  /// opened a session to — once the session is written down.
  void _noteOpened(AccountSession s, Map<String, int> before) {
    final tell = onSessionOpened;
    if (tell == null) return;
    for (final r in s.targetRoutingIds) {
      if ((s.targetConversation(r)?.sessions.length ?? 0) > (before[r] ?? 0)) {
        tell(r);
      }
    }
  }

  /// The envelope every mirror, ping and history batch travels in. [pqs]
  /// (44.3) says this device holds the sealing key of the device it goes to;
  /// a receiver reads the wrapper's members by name, so a build that
  /// predates it passes it by as it passes `dlr` by.
  String _envelope(String thread, String dir, InnerMessage inner,
          {bool pqs = false}) =>
      jsonEncode({
        'thread': thread,
        'dir': dir,
        'inner': base64Encode(inner.toBytes()),
        if (advertiseReaderLevel()) 'dlr': devlistReaderLevel,
        if (pqs) 'pqs': 1,
      });

  bool _stamps(String deviceRid) => holdsSealKeyOf?.call(deviceRid) ?? false;

  /// 44.3: this device's `pqseal`, ahead of what is about to be sent, to
  /// each of [to] it is owed by and whose next message would be mixed with
  /// no `pqct` in its header ([pqSealMayRide]) — one envelope each, recorded
  /// in [sent]. Under the lock, in the step that encrypts what it rides.
  Future<List<FanoutMessage>> _sealsAhead(
      AccountSession s, Iterable<String> to, List<String> sent) async {
    final out = <FanoutMessage>[];
    final want = pqSealFor;
    if (want == null) return out;
    for (final rid in to) {
      final conv = s.targetConversation(rid);
      if (conv == null || !pqSealMayRide(conv)) continue;
      final bytes = want(rid);
      if (bytes == null) continue;
      final f = await s.encryptFor(rid, bytes);
      if (f != null) {
        out.add(f);
        sent.add(rid);
      }
    }
    return out;
  }

  /// [inner] wrapped for every one of my devices, each envelope saying
  /// `pqs:1` where this device holds that device's sealing key — one
  /// encryption when they are all alike, two when they differ.
  Future<List<FanoutMessage>> _encryptWrapped(
      AccountSession s, String thread, String dir, InnerMessage inner) async {
    final all = s.targetRoutingIds.toSet();
    final stamped = {for (final r in all) if (_stamps(r)) r};
    Uint8List bytes(bool pqs) =>
        Uint8List.fromList(utf8.encode(_envelope(thread, dir, inner, pqs: pqs)));
    if (stamped.isEmpty || stamped.length == all.length) {
      return s.encrypt(bytes(stamped.isNotEmpty));
    }
    return [
      ...await s.encrypt(bytes(true), except: all.difference(stamped)),
      ...await s.encrypt(bytes(false), except: stamped),
    ];
  }

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
      final before = _sessionCounts(s);
      final fan = await s.openInitiatorSessions(
          Uint8List.fromList(utf8.encode(_pingEnvelope())));
      if (fan.isEmpty) return;
      await _save();
      _noteOpened(s, before);
      for (final f in fan) {
        await reliableSend(f.routingId, f.payload);
      }
    });
  }

  /// Test seam: make the next INBOUND save (the one that persists the ratchet
  /// a self-sync envelope advanced, in [handleInbound]) throw once, to
  /// exercise the transient vault-write failure on the receive path — it must
  /// leave the envelope with the relay, not acknowledge it away. Scoped to
  /// the inbound save so it does not also trip [prime] or [mirror], which run
  /// on reconnect. [debugSaveFailures] counts how many times it has fired, so
  /// a test can wait for the failure before forcing the redelivery.
  bool debugFailNextInboundSave = false;
  int debugSaveFailures = 0;

  /// Persist the inbound-advanced ratchet, failing once under the seam above.
  Future<void> _saveInbound() async {
    if (debugFailNextInboundSave) {
      debugFailNextInboundSave = false;
      debugSaveFailures++;
      throw _SyncSaveException();
    }
    await _save();
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
      final before = _sessionCounts(s);
      final sealed = <String>[];
      final fan = [
        ...await _sealsAhead(s, s.targetRoutingIds, sealed),
        ...await _encryptWrapped(s, threadRid, dir, inner),
      ];
      // Persist the advanced ratchet BEFORE handing payloads to the reliable
      // outbox, so any redelivery is still decryptable.
      await _save();
      _noteOpened(s, before);
      for (final f in fan) {
        await reliableSend(f.routingId, f.payload);
      }
      if (sealed.isNotEmpty) onPqSealSent?.call(sealed);
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
      final before = _sessionCounts(s);
      final sealed = <String>[];
      final ahead = await _sealsAhead(s, [deviceRid], sealed);
      final envelope =
          _envelope(threadRid, dir, inner, pqs: _stamps(deviceRid));
      final f = await s.encryptFor(
          deviceRid, Uint8List.fromList(utf8.encode(envelope)));
      if (f == null) return false;
      await _save();
      _noteOpened(s, before);
      for (final a in ahead) {
        await reliableSend(a.routingId, a.payload);
      }
      await reliableSend(f.routingId, f.payload);
      if (sealed.isNotEmpty) onPqSealSent?.call(sealed);
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
      final before = _sessionCounts(s);
      final f = await s.takePqOfferFor(deviceRid);
      if (f != null) {
        await _save();
        _noteOpened(s, before);
      }
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

  /// 26.3: whether the mirror to my device [deviceRid] — which carries every
  /// message this one sends or receives — is post-quantum both ways right
  /// now. False before the sync session exists.
  bool postQuantumWith(String deviceRid) =>
      _session?.postQuantumWith(deviceRid) ?? false;

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
      final DecryptResult dec;
      try {
        dec = await s.decryptFrom(fromDeviceRid, payload);
      } catch (_) {
        // Undecryptable, an unknown session, or a malformed payload: nothing
        // advanced to persist and nothing to store, and a redelivery fails
        // the same way — so the caller acknowledges.
        return const SyncInbound(null, null);
      }
      // The ratchet advanced; persist it BEFORE the caller acts on what was
      // mirrored. A failure here is transient (the vault busy or closing):
      // roll the ratchet back and tell the caller NOT to acknowledge, so the
      // relay redelivers onto the restored ratchet. Until this split that
      // failure fell into the catch above, which returned "nothing mirrored"
      // and the caller acknowledged — the advanced ratchet was kept in
      // memory, unsaved, and the message was lost from the relay and from
      // this device both.
      try {
        if (dec.createdNewSession) await onNewSession?.call(fromDeviceRid);
        await _saveInbound();
      } catch (_) {
        _session = await AccountSession.fromJson(
            account, (jsonDecode(snapshot) as Map).cast<String, Object?>(),
            intervals: pqIntervals());
        return const SyncInbound.transient();
      }
      // 44.3 (§18.11): whatever the envelope turns out to be, what it says
      // of sealing keys — the session it came on included — is told here,
      // under the lock, as each is decrypted ([onSealNews]).
      SyncInbound told(SyncInbound r) {
        try {
          onSealNews?.call(fromDeviceRid, dec.createdNewSession, r.pqSeal,
              r.holdsMySealKey);
        } catch (_) {
          // What is held in memory; nothing here may cost the envelope.
        }
        return r;
      }

      offer = dec.pqOfferPayload;
      // v2: a post-quantum key offer from my other device is consumed by the
      // session layer above; it carries no mirrored message.
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
        try {
          final conv = s.targetConversation(fromDeviceRid);
          if (conv != null && conv.pqAnswerOwedOn(dec.sid)) {
            final ping = await s.encryptFor(
                fromDeviceRid,
                Uint8List.fromList(
                    utf8.encode(_pingEnvelope(pqs: _stamps(fromDeviceRid)))),
                sid: dec.sid);
            if (ping != null) {
              await _save(); // before it can leave, as for any send
              answer = ping;
            }
          }
        } catch (_) {
          // A courtesy: the offer is taken and saved above, and the other
          // device says it again on its own clock (§17.4). A failure here —
          // the vault busy when the answer is saved — sends nothing, and the
          // envelope, whose offer is already taken, is acknowledged.
        }
        return told(const SyncInbound(null, null));
      }
      // 44.3 (§18.11): one of my devices announcing its sealing key, bare on
      // this ratchet as an offer is ([pqSealFor]), handed to the caller to
      // keep. A build from before 44.3 finds no wrapper in it below and
      // acknowledges it with nothing mirrored, as any envelope it cannot
      // read.
      if (InnerMessage.looksLikeKind(dec.plaintext, 'pqseal')) {
        InnerMessage? seal;
        try {
          seal = InnerMessage.fromBytes(dec.plaintext);
        } on FormatException {
          seal = null;
        }
        return told(SyncInbound(null, null, pqSeal: seal));
      }
      SyncInbound read;
      try {
        final j =
            jsonDecode(utf8.decode(dec.plaintext)) as Map<String, Object?>;
        final inner =
            InnerMessage.fromBytes(base64Decode(j['inner'] as String));
        final thread = j['thread'], dir = j['dir'];
        if (thread is! String || dir is! String) {
          read = const SyncInbound(null, null);
        } else {
          // ADR 0029: what the sending device says it reads. An envelope
          // without the member is from a build that predates it — every
          // envelope this build sends carries it.
          final dlr = j['dlr'];
          read = SyncInbound((thread: thread, dir: dir, inner: inner),
              snapshot,
              readerLevel: dlr is num && dlr.isFinite ? dlr.toInt() : 0,
              holdsMySealKey: j['pqs'] == 1);
        }
      } catch (_) {
        // The ratchet is already saved and a redelivery would parse no
        // better, so the caller acknowledges; there is simply nothing to
        // store.
        read = const SyncInbound(null, null);
      }
      return told(read);
    });
    if (offer != null) await reliableSend(fromDeviceRid, offer!);
    if (answer != null) await reliableSend(answer!.routingId, answer!.payload);
    return out;
  }

  /// The proactive opener's envelope (`dir:"ping"`, a `hello` inner), which
  /// the receiving device ignores — what [prime] sends, what answers an
  /// offer, and what [announce] sends.
  String _pingEnvelope({bool pqs = false}) =>
      _envelope('', 'ping', InnerMessage.hello(newMessageId(), 0), pqs: pqs);

  /// ADR 0029: one ping to every one of my other devices, so each hears what
  /// this device reads ([advertiseReaderLevel]) even when it has nothing to
  /// mirror. A linked device sends it once a run, when it first connects: a
  /// root learns its linked devices' builds from what they send it, and a
  /// laptop that is only switched on to read sends nothing else of its own —
  /// [prime] pings only the devices this one opens sessions with. Every
  /// build ignores a ping on receipt.
  Future<void> announce() => mirror(
      threadRid: '', dir: 'ping', inner: InnerMessage.hello(newMessageId(), 0));
}

/// Thrown by [DeviceSyncService._save] under [DeviceSyncService.debugFailNextSave].
class _SyncSaveException implements Exception {
  @override
  String toString() => '_SyncSaveException';
}

/// The outcome of [DeviceSyncService.handleInbound].
class SyncInbound {
  /// What was mirrored, or null if this payload carried no message.
  final ({String thread, String dir, InnerMessage inner})? mirrored;

  /// The sync ratchet as it was before the decrypt, for
  /// [DeviceSyncService.restore] if storing [mirrored] fails. Null when there
  /// is nothing to store and so nothing to roll back.
  final String? snapshot;

  /// A TRANSIENT failure (the vault write failed): the ratchet has been rolled
  /// back and the caller must NOT acknowledge the envelope, so the relay
  /// redelivers it. Distinct from "nothing mirrored" (ack): that is a decrypt
  /// or parse failure a redelivery would repeat, this is one it would not.
  final bool transientFailure;

  /// ADR 0029: the device-list shape the sending device says it reads — the
  /// envelope's `dlr`, 0 for an envelope without one (a build from before
  /// it). Null when nothing was read: not an envelope at all (a key offer),
  /// or one that did not decrypt or parse.
  final int? readerLevel;

  /// 44.3: the sending device's `pqseal`, when that is what this payload
  /// was — bare, not a mirror.
  final InnerMessage? pqSeal;

  /// 44.3: the envelope said `pqs:1` — the sending device holds this one's
  /// sealing key.
  final bool holdsMySealKey;

  const SyncInbound(this.mirrored, this.snapshot,
      {this.readerLevel, this.pqSeal, this.holdsMySealKey = false})
      : transientFailure = false;

  const SyncInbound.transient()
      : mirrored = null,
        snapshot = null,
        readerLevel = null,
        pqSeal = null,
        holdsMySealKey = false,
        transientFailure = true;
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
