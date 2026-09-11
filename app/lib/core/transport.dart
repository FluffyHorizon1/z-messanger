import 'dart:async';
import 'dart:math';

import 'package:flutter/foundation.dart';
import 'package:z_protocol/z_protocol.dart';

import 'models.dart';

/// Maintains this device's links to the relay with exponential-backoff
/// reconnection: the authenticated link, which owns this device's mailbox and
/// carries everything the relay may attribute to it (receiving, acks, push
/// registration, the few unsealed legacy sends); and the anonymous link,
/// which never authenticates and carries every sealed envelope this device
/// sends. The split is what makes sealed sender true against the relay
/// process and not only against its stored data: a sealed envelope names no
/// sender, but a connection that authenticated has an identity, and a relay
/// that logged (connection, destination) would have had the social graph
/// sealed sender exists to withhold (§12.1, THREAT_MODEL R21). A sealed
/// envelope is never sent on the authenticated link — when the anonymous
/// link is down the send fails and the outbox retries, rather than falling
/// back to the link that would attribute it.
///
/// All payloads passing through here are already end-to-end encrypted;
/// losing either link never loses data — unsent messages wait in the device
/// outbox, undelivered ones in relay RAM.
class Transport extends ChangeNotifier {
  final ZIdentity identity;
  String serverUrl;

  /// The authenticated link's state — what the UI shows.
  LinkStatus status = LinkStatus.disconnected;
  String? lastError;

  RelayClient? _client;
  bool _shouldRun = false;
  int _attempt = 0;
  Timer? _retryTimer;

  /// The anonymous sender link.
  RelayClient? _sender;
  bool _senderConnecting = false;
  int _senderAttempt = 0;
  Timer? _senderRetry;
  bool _announcedUp = false;

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

  /// The anonymous link is up: sealed envelopes can go.
  bool get isSenderConnected => _sender?.isOpen ?? false;

  void start() {
    _shouldRun = true;
    _connect();
    _connectSender();
  }

  Future<void> stop() async {
    _shouldRun = false;
    _retryTimer?.cancel();
    _senderRetry?.cancel();
    _announcedUp = false;
    final c = _client;
    _client = null;
    final sn = _sender;
    _sender = null;
    if (c != null) await c.close();
    if (sn != null) await sn.close();
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
    if (!isSenderConnected && !_senderConnecting) {
      _senderAttempt = 0;
      _senderRetry?.cancel();
      _connectSender();
    }
  }

  /// `onConnected` fires once per outage, when BOTH links are up: the
  /// service flushes its outbox on it, and an outbox flushed while the
  /// anonymous link was still down would only fail every sealed row and
  /// wait for the next sweep.
  void _maybeAnnounceUp() {
    if (_announcedUp || !isConnected || !isSenderConnected) return;
    _announcedUp = true;
    onConnected?.call();
  }

  Future<void> _connectSender() async {
    if (!_shouldRun || _senderConnecting || isSenderConnected) return;
    _senderConnecting = true;
    try {
      final sender = await RelayClient.connectAnonymous(
        serverUrl,
        identity,
        onClosed: _handleSenderClosed,
      );
      _sender = sender;
      _senderAttempt = 0;
      _maybeAnnounceUp();
    } catch (_) {
      _sender = null;
      _scheduleSenderRetry();
    } finally {
      _senderConnecting = false;
    }
  }

  void _handleSenderClosed() {
    _sender = null;
    _announcedUp = false;
    if (_shouldRun) _scheduleSenderRetry();
  }

  void _scheduleSenderRetry() {
    if (!_shouldRun) return;
    _senderRetry?.cancel();
    final delay = Duration(
        milliseconds: (1000 * pow(2, min(_senderAttempt, 5))).toInt() +
            Random().nextInt(500));
    _senderAttempt++;
    _senderRetry = Timer(delay, _connectSender);
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
      _maybeAnnounceUp();
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
    _announcedUp = false;
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
  /// false if the relay queued it in RAM. Throws if the link it must use is
  /// not connected or the relay rejected it.
  ///
  /// A sealed envelope goes on the anonymous link and nowhere else. The
  /// unsealed legacy form carries the sender inside the frame already, so
  /// it goes on the authenticated link, which the relay stamps.
  Future<bool> send(
      {required String to, required String id, required String payload}) {
    final c = SealedEnvelope.looksSealed(payload) ? _sender : _client;
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
