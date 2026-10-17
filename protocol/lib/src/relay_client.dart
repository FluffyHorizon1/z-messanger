import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'identity.dart';
import 'intro_key.dart';
import 'util.dart';

/// The relay's refusal of an `ikey` frame it cannot take — a key or a
/// signature of the wrong length or encoding, or a signature that is not the
/// connection's own key's over that key — or of an `ikey_get` that names no
/// routing id (§12.7). Carries no `id`.
const String relayErrorBadIkey = 'bad_ikey';

/// The relay's answer to `ikey_get` on a connection that authenticated: a
/// fetch is taken only on one that never did (§12.7). Carries no `id`.
const String relayErrorAnonOnly = 'anon_only';

/// A single connection to a Z relay — authenticated, to receive from this
/// device's mailbox; or anonymous ([connectAnonymous]), to send sealed
/// envelopes from a connection the relay cannot attribute to anyone.
///
/// The relay is untrusted: this client hands it only opaque payloads and, on
/// an authenticated connection, an Ed25519 signature over a random challenge
/// (which reveals nothing but possession of the key). A sealed envelope
/// (§8) names no sender, but a connection that authenticated has an
/// identity, and the relay process can attach it to everything that arrives
/// on that connection — so a client that wants the relay not to know who
/// sent what sends sealed envelopes on an anonymous connection (§12.1). What
/// remains attributable is the network address and the timing (R21).
/// Reconnection/backoff policy lives in the caller.
class RelayClient {
  final WebSocket _ws;
  final ZIdentity _identity;

  /// The relay this connection dialled, as the authentication names it.
  final String _authority;

  /// True for a connection that saw the challenge and did not answer it.
  final bool anonymous;

  String routingId = '';
  final _ready = Completer<String>();

  /// Whether this relay's challenge said `ik:1`: it keeps introduction keys
  /// (§12.7). Read from the challenge on every connection, anonymous ones
  /// included. A client publishes and fetches only where it is true.
  bool relayKeepsIntroKeys = false;

  /// What this connection's `ready` named the introduction key the relay
  /// holds for its routing id by — `IntroKeyEntry.hint` of that entry — or
  /// null when it named none: the relay holds none for it, or keeps none.
  String? readyIntroKeyHint;

  /// The `ikey` frame waiting for its `ikey_ok` (§12.7), if one is.
  Completer<void>? _ikeyAck;

  /// The `ikey_get` frames waiting for their `ikey_for`, by the routing id
  /// each asked about.
  final _ikeyGets = <String, List<Completer<IntroKeyAnswer>>>{};

  // Single-subscription controllers: they BUFFER events until the consumer
  // subscribes, so envelopes flushed by the relay immediately after auth are
  // never lost even if the app wires up its listener a beat later.
  final _messages = StreamController<RelayInbound>();
  final _delivered = StreamController<DeliveredReceipt>();
  final _sendAcks = <String, Completer<void>>{};

  /// The `intro` frame waiting for its `intro_ok` (§21.6), if one is.
  Completer<void>? _introAck;

  /// The push frame waiting for its `push-ok`, if one is, and the frames
  /// queued behind it. One at a time: the relay answers a registration and a
  /// withdrawal with the same `push-ok`, and handles frames concurrently, so
  /// with two in flight neither the answer nor the order the relay applied
  /// them in would say which one stands.
  Completer<void>? _pushAck;
  Future<void> _pushQueue = Future<void>.value();
  final void Function()? _onClosed;
  Timer? _pinger;

  /// Set at the start of [close]: frames still buffered in the socket can be
  /// dispatched after the closing handshake began (and after the controllers
  /// are closed), so they are dropped instead of being pushed into a closed
  /// stream.
  bool _closing = false;

  RelayClient._(this._ws, this._identity, this._onClosed, this._authority,
      {this.anonymous = false}) {
    // dart:io WebSockets are single-subscription: this is the ONE listener,
    // covering both the auth phase and normal operation.
    _ws.listen(_onFrame, onDone: _closed, onError: (_) => _closed());
    _pinger = Timer.periodic(const Duration(seconds: 25), (_) {
      try {
        _send({'t': 'ping'});
      } catch (_) {}
    });
  }

  /// Incoming envelopes (opaque payloads — decrypt with the Conversation).
  Stream<RelayInbound> get messages => _messages.stream;

  /// Fired when a recipient's device confirmed persistence of an envelope.
  Stream<DeliveredReceipt> get delivered => _delivered.stream;

  bool get isOpen => _ws.readyState == WebSocket.open;

  /// Lightweight reachability check used by the UI's "Test connection".
  /// Connects, waits for the relay's `challenge` frame (which proves it really
  /// is a Z relay, not just any open socket), then disconnects. Throws a
  /// [RelayException] / [TimeoutException] / socket error on failure.
  static Future<void> probe(String url,
      {Duration timeout = const Duration(seconds: 10)}) async {
    final ws = await WebSocket.connect(url).timeout(timeout);
    try {
      await for (final data
          in ws.timeout(timeout, onTimeout: (sink) => sink.close())) {
        final frame = jsonDecode(data as String) as Map<String, Object?>;
        if (frame['t'] == 'challenge') {
          // It is a Z relay — and one this client can authenticate to, or
          // the test says so now rather than the first connection later.
          if (frame['auth'] != 2) {
            throw RelayException(
                'relay too old: it does not bind authentication to its '
                'address; update the relay');
          }
          return;
        }
        throw RelayException('unexpected first frame from server');
      }
      throw RelayException('server closed connection without a challenge');
    } on FormatException {
      throw RelayException('not a Z relay (unexpected response)');
    } finally {
      try {
        await ws.close();
      } catch (_) {}
    }
  }

  static Future<RelayClient> connect(
    String url,
    ZIdentity identity, {
    Duration timeout = const Duration(seconds: 15),
    void Function()? onClosed,
  }) async {
    final ws = await WebSocket.connect(url).timeout(timeout);
    final client = RelayClient._(ws, identity, onClosed, relayAuthority(url));
    try {
      await client._ready.future.timeout(timeout);
      return client;
    } catch (_) {
      await client.close();
      rethrow;
    }
  }

  /// A connection that never authenticates: usable for [send] of sealed
  /// envelopes only; it receives nothing and [routingId] stays empty. The
  /// relay's challenge is awaited (it proves this is a Z relay) and left
  /// unanswered. [identity] is kept only so the type is one class; it is
  /// never signed with here.
  static Future<RelayClient> connectAnonymous(
    String url,
    ZIdentity identity, {
    Duration timeout = const Duration(seconds: 15),
    void Function()? onClosed,
  }) async {
    final ws = await WebSocket.connect(url).timeout(timeout);
    final client = RelayClient._(ws, identity, onClosed, relayAuthority(url), anonymous: true);
    try {
      await client._ready.future.timeout(timeout);
      return client;
    } catch (_) {
      await client.close();
      rethrow;
    }
  }

  Future<void> _handleAuth(Map<String, Object?> frame) async {
    switch (frame['t']) {
      case 'challenge':
        // `ik:1`: this relay keeps introduction keys (§12.7). Any other value,
        // or none, is a relay that does not.
        relayKeepsIntroKeys = frame['ik'] == 1;
        if (anonymous) {
          // Seen, not answered: the relay has nothing to attach to this
          // connection.
          if (!_ready.isCompleted) _ready.complete('');
          return;
        }
        // Only the bound form is ever signed: a v1 signature obtained by
        // any relay this device talks to would authenticate it at every
        // other, and a client that would fall back to v1 on request could
        // be asked to by exactly the relay that wants the signature. A relay
        // that does not verify v2 says so by not advertising it, and gets a
        // reason rather than a signature.
        if (frame['auth'] != 2) {
          if (!_ready.isCompleted) {
            _ready.completeError(RelayException(
                'relay too old: it does not bind authentication to its '
                'address; update the relay'));
          }
          return;
        }
        final nonce = unb64(frame['nonce'] as String);
        // The challenge nonce is a fixed 32 bytes (PROTOCOL §12.1), and the
        // signature concatenates authority ‖ nonce. A nonce of any other
        // length would let a hostile relay vary where the authority ends and
        // the nonce begins under the signature — a splicing surface the
        // fixed width closes. Every relay since v1.0.0 sends exactly 32
        // bytes, so refusing anything else breaks no real relay; it refuses
        // only one that is trying something.
        if (nonce.length != 32) {
          if (!_ready.isCompleted) {
            _ready.completeError(RelayException(
                'relay sent a ${nonce.length}-byte challenge nonce; '
                'a Z relay sends exactly 32'));
          }
          return;
        }
        final sig = await _identity.signAuthChallengeV2(nonce, _authority);
        _ws.add(jsonEncode({
          't': 'auth',
          'v': 2,
          'pub': b64(_identity.edPub),
          'sig': b64(sig),
        }));
        break;
      case 'ready':
        routingId = frame['id'] as String;
        // The entry the relay holds for this routing id, by its hint (§12.7);
        // anything but a string names none.
        final ik = frame['ik'];
        readyIntroKeyHint = ik is String ? ik : null;
        if (!_ready.isCompleted) _ready.complete(routingId);
        break;
      case 'error':
        if (!_ready.isCompleted) {
          _ready
              .completeError(RelayException('auth failed: ${frame['code']}'));
        }
        break;
      default:
        break; // ignore anything else pre-auth
    }
  }

  void _onFrame(dynamic data) {
    if (_closing) return; // late frame during/after close: nothing to deliver
    Map<String, Object?> frame;
    try {
      frame = jsonDecode(data as String) as Map<String, Object?>;
    } catch (_) {
      return;
    }
    if (!_ready.isCompleted) {
      // Auth phase. Envelope flushes only start after 'ready', so nothing
      // can be missed: the server sends 'ready' before flushing queues.
      unawaited(_handleAuth(frame));
      return;
    }
    // Read every field by type, never by a raw cast. A frame is a relay's
    // word, and a relay (buggy, or hostile toward a client it has drawn in)
    // can put a number where a string belongs; a raw `as String` there throws
    // a `TypeError` inside this stream callback, which is not caught by the
    // `jsonDecode` guard above and takes down the connection (finding 42). A
    // wrong-typed field makes the frame drop instead.
    String? str(String key) => frame[key] is String ? frame[key] as String : null;
    int intOr0(String key) => frame[key] is num ? (frame[key] as num).toInt() : 0;
    switch (frame['t']) {
      case 'msg':
        final id = str('id'), payload = str('payload');
        // No id or no payload: there is nothing deliverable here.
        if (id == null || payload == null) break;
        // An envelope taken into an introduction mailbox carries the stamp it
        // was taken on and the day that stamp met the difficulty under
        // (§21.6), so the mailbox's owner can count the work itself. Either
        // member wrong-typed, or the day not a whole number, reads as absent:
        // the owner then has no stamp to count, which is what it drops.
        final powDay = frame['powDay'];
        _messages.add(RelayInbound(
          id: id,
          // Sealed-sender envelopes arrive with no sender: the relay never
          // knew one. The sender is learned inside the encrypted envelope.
          from: str('from') ?? '',
          payload: payload,
          serverTs: intOr0('ts'),
          pow: str('pow'),
          powDay: powDay is int ? powDay : null,
        ));
        break;
      case 'sent':
        final id = str('id');
        if (id != null) _sendAcks.remove(id)?.complete();
        break;
      case 'intro_ok':
        final c = _introAck;
        _introAck = null;
        if (c != null && !c.isCompleted) c.complete();
        break;
      case 'ikey_ok':
        final c = _ikeyAck;
        _ikeyAck = null;
        if (c != null && !c.isCompleted) c.complete();
        break;
      case 'ikey_for':
        final to = str('to');
        if (to == null) break;
        final waiting = _ikeyGets.remove(to);
        if (waiting == null) break;
        final answer = IntroKeyAnswer._fromFrame(str('ek'), str('iks'));
        for (final c in waiting) {
          if (!c.isCompleted) c.complete(answer);
        }
        break;
      case 'push-ok':
        final p = _pushAck;
        _pushAck = null;
        if (p != null && !p.isCompleted) p.complete();
        break;
      case 'delivered':
        final id = str('id');
        if (id == null) break;
        _delivered.add(DeliveredReceipt(
          id: id,
          to: str('to') ?? '',
        ));
        break;
      case 'error':
        final id = str('id');
        if (id == null) {
          // Only five of the relay's refusals name the envelope they are
          // about (§12.2): `too_large`, `bad_send`, `queue_full`,
          // `store_full` and `pow_required`. The rest — `rate_limited` above all, and
          // `bad_json`, `internal`, `bad_auth`, `not_authed`,
          // `unknown_frame` — arrive with nothing to match a send against,
          // and used to leave the sender's future pending until its
          // twenty-second timeout, holding the outbox flush for all of it.
          //
          // A connection processes frames in order, so an unattributed
          // refusal is about what was just sent. Failing every outstanding
          // send with it is the conservative reading and costs nothing that
          // matters: each row is still in the durable outbox, and the relay
          // dedupes a retry on (id, sender), so re-sending is idempotent.
          final pending = _sendAcks.values.toList();
          _sendAcks.clear();
          // An `intro` frame is refused the same way (`not_authed`,
          // `bad_intro`, and `unknown_frame` from a relay that predates
          // §21.6), and fails with it.
          final intro = _introAck;
          _introAck = null;
          if (intro != null) pending.add(intro);
          // And a push frame (`bad_push`, `push_refused`, `not_authed`, and
          // `unknown_frame` from a relay with no push at all).
          final push = _pushAck;
          _pushAck = null;
          if (push != null) pending.add(push);
          for (final c in pending) {
            if (!c.isCompleted) {
              c.completeError(
                  RelayException(str('code') ?? 'refused'));
            }
          }
          // And an introduction-key frame (§12.7): `bad_ikey`, `not_authed`
          // and `rate_limited` for `ikey`, `anon_only` for `ikey_get`, and
          // `unknown_frame` from a relay that keeps none.
          _failIntroKeyFrames(RelayException(str('code') ?? 'refused'));
          break;
        }
        {
          final code = str('code') ?? '?';
          // §21.6: a send to an introduction mailbox without the work its
          // owner asked for. The frame names the difficulty and the relay's
          // own day, so the sender can stamp again — once — for that day.
          final bits = frame['bits'], day = frame['day'];
          _sendAcks.remove(id)?.completeError(
              code == 'pow_required' && bits is int && day is int
                  ? RelayPowRequired(bits: bits, day: day)
                  : RelayException(code));
        }
        break;
      default:
        break;
    }
  }

  /// Sends an opaque envelope. Resolves once the relay has accepted it —
  /// held until the recipient acknowledges it — and throws on rejection.
  /// It used to resolve to whether the recipient had a socket open at that
  /// moment, which is presence: the relay stopped saying on 2026-09-17
  /// (finding 12), and nothing here ever needed it — delivery is the peer's
  /// own receipt inside the ratchet (§15.3).
  ///
  /// [pow] is a proof-of-work stamp (§21.7), the `b64url` of its nonce: a
  /// send to an introduction mailbox carries one, and the relay refuses it
  /// with [RelayPowRequired] when it does not do the work the mailbox's
  /// owner asked for. Every other send carries none.
  Future<void> send({
    required String to,
    required String id,
    required String payload,
    String? pow,
  }) {
    final completer = Completer<void>();
    _sendAcks[id] = completer;
    _send({
      't': 'send',
      'id': id,
      'to': to,
      'payload': payload,
      if (pow != null) 'pow': pow,
    });
    return completer.future.timeout(const Duration(seconds: 20), onTimeout: () {
      _sendAcks.remove(id);
      throw RelayException('send timeout');
    });
  }

  /// Flags this connection's own mailbox as an introduction mailbox that
  /// takes a send only with a stamp of [bits] leading zero bits (§21.6), and
  /// resolves on the relay's `intro_ok`. Only meaningful on a connection
  /// authenticated as an introduction key; the relay answers `not_authed`
  /// on any other, `bad_intro` for bits outside 16–28, and — a relay that
  /// predates §21.6 — `unknown_frame`, each a [RelayException] here. Sent
  /// after every authentication: the flag lasts the ownership's lifetime
  /// from the last frame that set it.
  Future<void> intro(int bits,
      {Duration timeout = const Duration(seconds: 15)}) {
    final previous = _introAck;
    if (previous != null && !previous.isCompleted) {
      previous.completeError(RelayException('intro superseded'));
    }
    final c = Completer<void>();
    _introAck = c;
    _send({'t': 'intro', 'pow': bits});
    return c.future.timeout(timeout, onTimeout: () {
      if (identical(_introAck, c)) _introAck = null;
      throw RelayException('intro timeout');
    });
  }

  /// Publishes [entry] — this device's sealing key and its signature by the
  /// key this connection authenticated as — as the introduction key of this
  /// connection's own routing id (§12.7), and resolves on the relay's
  /// `ikey_ok`. Only on an authenticated connection to a relay whose
  /// challenge said `ik:1` ([relayKeepsIntroKeys]); anything else is a
  /// [StateError] and nothing is sent. The relay refuses a connection that
  /// authenticated with v1 `not_authed`, an entry it cannot take `bad_ikey`
  /// ([relayErrorBadIkey]) and too many frames in a minute `rate_limited`,
  /// each a [RelayException] here. A device publishes after a login whose
  /// `ready` did not name its entry ([readyIntroKeyHint]). Nothing calls this
  /// before 44.11.
  Future<void> publishIntroKey(IntroKeyEntry entry,
      {Duration timeout = const Duration(seconds: 15)}) {
    if (anonymous || routingId.isEmpty) {
      throw StateError(
          'an introduction key is published on the authenticated connection');
    }
    if (!relayKeepsIntroKeys) {
      throw StateError('this relay keeps no introduction keys (no ik:1)');
    }
    final previous = _ikeyAck;
    if (previous != null && !previous.isCompleted) {
      previous.completeError(RelayException('ikey superseded'));
    }
    final c = Completer<void>();
    _ikeyAck = c;
    _send({'t': 'ikey', 'ek': b64(entry.ek), 'iks': b64(entry.iks)});
    return c.future.timeout(timeout, onTimeout: () {
      if (identical(_ikeyAck, c)) _ikeyAck = null;
      throw RelayException('ikey timeout');
    });
  }

  /// Asks the relay for the introduction key it keeps for [rid] (§12.7), and
  /// resolves on its `ikey_for`: the key and its signature, or
  /// [IntroKeyAnswer.held] false when it keeps neither — an answer that is
  /// the same for a mailbox that does not exist. Only on an ANONYMOUS
  /// connection — the one the envelope it is for will be sent on, just before
  /// it (§8.3) — to a relay whose challenge said `ik:1`; anything else is a
  /// [StateError] and nothing is sent. On the authenticated link the fetch
  /// would name the asking device beside the mailbox it asks about (ADR
  /// 0007), and a relay refuses it there `anon_only` ([relayErrorAnonOnly]).
  /// What it resolves to is not checked here: `checkServedIntroKey` is the
  /// rule a key must pass before anything is sealed to it. Nothing calls this
  /// before 44.12.
  Future<IntroKeyAnswer> ikeyGet(String rid,
      {Duration timeout = const Duration(seconds: 10)}) {
    if (!anonymous) {
      throw StateError(
          'an introduction key is fetched on an anonymous connection only');
    }
    if (!relayKeepsIntroKeys) {
      throw StateError('this relay keeps no introduction keys (no ik:1)');
    }
    final c = Completer<IntroKeyAnswer>();
    _send({'t': 'ikey_get', 'to': rid});
    (_ikeyGets[rid] ??= []).add(c);
    return c.future.timeout(timeout, onTimeout: () {
      final waiting = _ikeyGets[rid];
      waiting?.remove(c);
      if (waiting != null && waiting.isEmpty) _ikeyGets.remove(rid);
      throw RelayException('ikey_get timeout');
    });
  }

  /// Fails every introduction-key frame still waiting with [e].
  void _failIntroKeyFrames(RelayException e) {
    final ack = _ikeyAck;
    _ikeyAck = null;
    if (ack != null && !ack.isCompleted) ack.completeError(e);
    final gets = _ikeyGets.values.expand((l) => l).toList();
    _ikeyGets.clear();
    for (final c in gets) {
      if (!c.isCompleted) c.completeError(e);
    }
  }

  /// Confirm an envelope is safely persisted on this device; the relay then
  /// wipes it from RAM (and, for legacy attributed envelopes, notifies the
  /// sender). For sealed envelopes [from] is empty and the ack is by id alone.
  void ackReceived({required String id, required String from}) {
    _send({'t': 'recv', 'id': id, if (from.isNotEmpty) 'from': from});
  }

  /// Register this device's push token so the relay can send a content-free
  /// wake ping when a message arrives while this identity is offline. The
  /// token is opaque to the relay; no message content or sender is ever put in
  /// a push. Safe to call repeatedly (e.g. on every reconnect or token refresh).
  void registerPush({required String token, String platform = 'android'}) {
    _send({'t': 'push-register', 'token': token, 'platform': platform});
  }

  /// Stop receiving wake pings for this identity (user disabled push / signed out).
  void unregisterPush() {
    _send({'t': 'push-unregister'});
  }

  /// [registerPush], resolving once the relay answers `push-ok` — so a caller
  /// knows the relay HOLDS the token rather than that a frame left. Throws a
  /// [RelayException] when the relay refuses it (`bad_push`, `push_refused`
  /// for an introduction mailbox, `not_authed`), when the connection closes
  /// first, or on [timeout]. Queued behind any push frame still unanswered.
  Future<void> registerPushAcked(
          {required String token,
          String platform = 'android',
          Duration timeout = const Duration(seconds: 15)}) =>
      _pushFrame(
          {'t': 'push-register', 'token': token, 'platform': platform},
          timeout);

  /// [unregisterPush], resolving once the relay answers `push-ok`: the relay
  /// has forgotten this identity's token and will wake nothing for it. A
  /// relay with no push at all answers `unknown_frame`, a [RelayException]
  /// with that message — it holds no token either.
  Future<void> unregisterPushAcked(
          {Duration timeout = const Duration(seconds: 15)}) =>
      _pushFrame({'t': 'push-unregister'}, timeout);

  Future<void> _pushFrame(Map<String, Object?> frame, Duration timeout) {
    final done = _pushQueue.then((_) {
      final c = Completer<void>();
      // Sent first: on a connection that has gone it throws, and nothing is
      // left waiting for an answer that cannot come. The answer itself
      // cannot arrive before this returns to the event loop.
      _send(frame);
      _pushAck = c;
      return c.future.timeout(timeout, onTimeout: () {
        if (identical(_pushAck, c)) _pushAck = null;
        throw RelayException('push timeout');
      });
    });
    _pushQueue = done.then((_) {}, onError: (Object _) {});
    return done;
  }

  void _send(Map<String, Object?> frame) {
    if (!isOpen) throw RelayException('not connected');
    _ws.add(jsonEncode(frame));
  }

  void _closed() {
    _pinger?.cancel();
    for (final c in _sendAcks.values) {
      if (!c.isCompleted) c.completeError(RelayException('connection closed'));
    }
    _sendAcks.clear();
    final intro = _introAck;
    _introAck = null;
    if (intro != null && !intro.isCompleted) {
      intro.completeError(RelayException('connection closed'));
    }
    final push = _pushAck;
    _pushAck = null;
    if (push != null && !push.isCompleted) {
      push.completeError(RelayException('connection closed'));
    }
    _failIntroKeyFrames(RelayException('connection closed'));
    _onClosed?.call();
  }

  Future<void> close() async {
    _closing = true;
    _pinger?.cancel();
    try {
      await _ws.close();
    } catch (_) {}
    // Do not await: a single-subscription controller's close() future only
    // resolves once the done event is delivered to a listener, which may
    // never happen if the consumer already cancelled.
    unawaited(_messages.close());
    unawaited(_delivered.close());
  }
}

class RelayInbound {
  final String id;
  final String from;
  final String payload;
  final int serverTs;

  /// For an envelope an introduction mailbox received (§21.6): the stamp
  /// the send carried — the 22 characters, as sent — and [powDay], the day
  /// the relay found it good under. Null on every other envelope, and on one
  /// from a relay that does not hand stamps on.
  final String? pow;
  final int? powDay;
  RelayInbound(
      {required this.id,
      required this.from,
      required this.payload,
      required this.serverTs,
      this.pow,
      this.powDay});
}

class DeliveredReceipt {
  final String id;
  final String to;
  DeliveredReceipt({required this.id, required this.to});
}

/// A relay's `ikey_for` (§12.7): both halves of the entry it keeps for the
/// mailbox asked about, or neither. An answer that carries one half, or a
/// half that is not base64, is [malformed]: the relay served something no
/// relay may, which a sender treats as a key that was refused. Nothing here
/// is checked beyond that — `checkServedIntroKey` is the acceptance rule.
class IntroKeyAnswer {
  final Uint8List? ek;
  final Uint8List? iks;
  final bool malformed;

  const IntroKeyAnswer._(this.ek, this.iks, {this.malformed = false});

  /// Whether the relay served a key at all.
  bool get held => ek != null && iks != null;

  static IntroKeyAnswer _fromFrame(String? ek, String? iks) {
    if (ek == null && iks == null) return const IntroKeyAnswer._(null, null);
    if (ek == null || iks == null) {
      return const IntroKeyAnswer._(null, null, malformed: true);
    }
    try {
      return IntroKeyAnswer._(unb64(ek), unb64(iks));
    } on FormatException {
      return const IntroKeyAnswer._(null, null, malformed: true);
    }
  }
}

class RelayException implements Exception {
  final String message;
  RelayException(this.message);
  @override
  String toString() => 'RelayException: $message';
}

/// The relay's `pow_required` (§21.6): a send to an introduction mailbox did
/// not carry a stamp of [bits] leading zero bits for the relay's today or
/// yesterday. [day] is the relay's own today (UTC days since the epoch), so
/// a sender whose clock disagrees near midnight can stamp again, once, for
/// it (§21.7). Its [message] is the code, as for every other refusal.
class RelayPowRequired extends RelayException {
  final int bits;
  final int day;
  RelayPowRequired({required this.bits, required this.day})
      : super('pow_required');
  @override
  String toString() => 'RelayPowRequired(bits: $bits, day: $day)';
}
