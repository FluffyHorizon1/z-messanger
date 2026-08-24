import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'identity.dart';
import 'util.dart';

/// A single authenticated connection to a Z relay.
///
/// The relay is untrusted: this client hands it only opaque payloads and an
/// Ed25519 signature over a random challenge (which reveals nothing but
/// possession of the key). Reconnection/backoff policy lives in the caller.
class RelayClient {
  final WebSocket _ws;
  final ZIdentity _identity;

  String routingId = '';
  final _ready = Completer<String>();

  // Single-subscription controllers: they BUFFER events until the consumer
  // subscribes, so envelopes flushed by the relay immediately after auth are
  // never lost even if the app wires up its listener a beat later.
  final _messages = StreamController<RelayInbound>();
  final _delivered = StreamController<DeliveredReceipt>();
  final _sendAcks = <String, Completer<bool>>{};
  final void Function()? _onClosed;
  Timer? _pinger;

  RelayClient._(this._ws, this._identity, this._onClosed) {
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
        if (frame['t'] == 'challenge') return; // it's a Z relay
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
    final client = RelayClient._(ws, identity, onClosed);
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
        final nonce = unb64(frame['nonce'] as String);
        final sig = await _identity.signAuthChallenge(nonce);
        _ws.add(jsonEncode({
          't': 'auth',
          'pub': b64(_identity.edPub),
          'sig': b64(sig),
        }));
        break;
      case 'ready':
        routingId = frame['id'] as String;
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
    switch (frame['t']) {
      case 'msg':
        _messages.add(RelayInbound(
          id: frame['id'] as String,
          from: frame['from'] as String,
          payload: frame['payload'] as String,
          serverTs: (frame['ts'] as num?)?.toInt() ?? 0,
        ));
        break;
      case 'sent':
        _sendAcks
            .remove(frame['id'] as String)
            ?.complete(!(frame['queued'] as bool? ?? false));
        break;
      case 'delivered':
        _delivered.add(DeliveredReceipt(
          id: frame['id'] as String,
          to: frame['to'] as String? ?? '',
        ));
        break;
      case 'error':
        final id = frame['id'] as String?;
        if (id != null) {
          _sendAcks
              .remove(id)
              ?.completeError(RelayException(frame['code'] as String? ?? '?'));
        }
        break;
      default:
        break;
    }
  }

  /// Sends an opaque envelope. Resolves true if delivered to a live socket,
  /// false if queued in relay RAM for later. Throws on relay rejection.
  Future<bool> send({
    required String to,
    required String id,
    required String payload,
  }) {
    final completer = Completer<bool>();
    _sendAcks[id] = completer;
    _send({'t': 'send', 'id': id, 'to': to, 'payload': payload});
    return completer.future.timeout(const Duration(seconds: 20), onTimeout: () {
      _sendAcks.remove(id);
      throw RelayException('send timeout');
    });
  }

  /// Confirm an envelope is safely persisted on this device; the relay then
  /// wipes it from RAM and notifies the sender.
  void ackReceived({required String id, required String from}) {
    _send({'t': 'recv', 'id': id, 'from': from});
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
    _onClosed?.call();
  }

  Future<void> close() async {
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
  RelayInbound(
      {required this.id,
      required this.from,
      required this.payload,
      required this.serverTs});
}

class DeliveredReceipt {
  final String id;
  final String to;
  DeliveredReceipt({required this.id, required this.to});
}

class RelayException implements Exception {
  final String message;
  RelayException(this.message);
  @override
  String toString() => 'RelayException: $message';
}
