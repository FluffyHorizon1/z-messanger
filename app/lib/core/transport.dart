import 'dart:async';
import 'dart:math';

import 'package:flutter/foundation.dart';
import 'package:z_protocol/z_protocol.dart';

import 'models.dart';

/// Maintains the (single) authenticated WebSocket link to the relay with
/// exponential-backoff reconnection. All payloads passing through here are
/// already end-to-end encrypted; losing this link never loses data — unsent
/// messages wait in the device outbox, undelivered ones in relay RAM.
class Transport extends ChangeNotifier {
  final ZIdentity identity;
  String serverUrl;

  LinkStatus status = LinkStatus.disconnected;
  String? lastError;

  RelayClient? _client;
  bool _shouldRun = false;
  int _attempt = 0;
  Timer? _retryTimer;

  /// Opaque FCM push token, if push is enabled. Re-registered on every
  /// (re)connect because the relay holds tokens in RAM only.
  String? _pushToken;

  /// Wired by ChatService.
  void Function(RelayInbound msg)? onMessage;
  void Function(DeliveredReceipt r)? onDelivered;
  void Function()? onConnected;

  Transport({required this.identity, required this.serverUrl});

  bool get isConnected =>
      status == LinkStatus.connected && (_client?.isOpen ?? false);

  void start() {
    _shouldRun = true;
    _connect();
  }

  Future<void> stop() async {
    _shouldRun = false;
    _retryTimer?.cancel();
    final c = _client;
    _client = null;
    if (c != null) await c.close();
    _setStatus(LinkStatus.disconnected);
  }

  /// Change relay and reconnect.
  Future<void> setServer(String url) async {
    serverUrl = url;
    await stop();
    start();
  }

  /// Force an immediate reconnect attempt (e.g. app resumed).
  void nudge() {
    if (!_shouldRun) return;
    if (status == LinkStatus.disconnected) {
      _attempt = 0;
      _retryTimer?.cancel();
      _connect();
    }
  }

  Future<void> _connect() async {
    if (!_shouldRun || status == LinkStatus.connecting || isConnected) return;
    _setStatus(LinkStatus.connecting);
    try {
      final client = await RelayClient.connect(
        serverUrl,
        identity,
        onClosed: _handleClosed,
      );
      _client = client;
      _attempt = 0;
      lastError = null;
      client.messages.listen((m) => onMessage?.call(m));
      client.delivered.listen((r) => onDelivered?.call(r));
      _setStatus(LinkStatus.connected);
      onConnected?.call();
      if (_pushToken != null) {
        try {
          client.registerPush(token: _pushToken!);
        } catch (_) {}
      }
    } catch (e) {
      lastError = e.toString();
      _client = null;
      _setStatus(LinkStatus.disconnected);
      _scheduleRetry();
    }
  }

  void _handleClosed() {
    _client = null;
    if (_shouldRun) {
      _setStatus(LinkStatus.disconnected);
      _scheduleRetry();
    }
  }

  void _scheduleRetry() {
    if (!_shouldRun) return;
    _retryTimer?.cancel();
    final delay = Duration(
        milliseconds:
            (1000 * pow(2, min(_attempt, 5))).toInt() + Random().nextInt(500));
    _attempt++;
    _retryTimer = Timer(delay, _connect);
  }

  /// Sends one envelope. Returns true if it reached a live recipient socket,
  /// false if the relay queued it in RAM. Throws if not connected or the
  /// relay rejected it.
  Future<bool> send(
      {required String to, required String id, required String payload}) {
    final c = _client;
    if (c == null || !c.isOpen) {
      throw RelayException('not connected');
    }
    return c.send(to: to, id: id, payload: payload);
  }

  void ackReceived({required String id, required String from}) {
    try {
      _client?.ackReceived(id: id, from: from);
    } catch (_) {}
  }

  /// Store this device's push token and register it now if connected. It is
  /// re-registered automatically on every future reconnect.
  void setPushToken(String? token) {
    _pushToken = token;
    if (token != null && isConnected) {
      try {
        _client?.registerPush(token: token);
      } catch (_) {}
    }
  }

  /// Turn push off for this identity and tell the relay to forget the token.
  void unregisterPush() {
    _pushToken = null;
    try {
      _client?.unregisterPush();
    } catch (_) {}
  }

  void _setStatus(LinkStatus s) {
    if (status != s) {
      status = s;
      notifyListeners();
    }
  }
}
