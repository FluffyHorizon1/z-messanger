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

  /// The relay may hold a token for this device that it must forget: push
  /// was turned off, or notifications were taken away. Said on this
  /// connection or, offline, on the next one, and again until the relay
  /// answers. Until phase 41 a withdrawal made while the link was down was
  /// dropped on the floor — `unregisterPush` found no socket and returned —
  /// and the relay went on waking the device through Google for every
  /// message until the token aged out, thirty days later.
  bool _pushWithdrawDue = false;

  /// The token the relay acknowledged on THIS connection, if any.
  String? _pushConfirmed;

  /// A token the relay refused for good (`bad_push`, `push_refused`): not
  /// offered again on this run.
  String? _pushRefused;
  Future<void>? _pushOp;
  Timer? _pushRetry;

  /// How long a push frame that failed waits before it is tried again on a
  /// connection that stayed up.
  static const Duration pushRetryDelay = Duration(seconds: 30);

  /// Called once the relay has acknowledged a withdrawal ([unregisterPush]).
  void Function()? onPushWithdrawn;

  /// A withdrawal is waiting for the relay's answer.
  bool get pushWithdrawalPending => _pushWithdrawDue;

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
    _pushRetry?.cancel();
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
      // A new connection: whatever the relay acknowledged on the last one is
      // said again — a registration because the relay keeps tokens in RAM,
      // a withdrawal that never got its answer because that is the point.
      _pushConfirmed = null;
      _syncPush();
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
    _pushRetry?.cancel();
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

  /// Sends one envelope. Resolves once the relay holds it (it stays held
  /// until the recipient acknowledges it). Throws if the link it must use is
  /// not connected or the relay rejected it. It used to say whether the
  /// recipient was online at that moment; the relay no longer tells any
  /// sender, and nothing here read it.
  ///
  /// A sealed envelope goes on the anonymous link and nowhere else. The
  /// unsealed legacy form carries the sender inside the frame already, so
  /// it goes on the authenticated link, which the relay stamps.
  Future<void> send(
      {required String to, required String id, required String payload}) {
    final c = SealedEnvelope.looksSealed(payload) ? _sender : _client;
    if (c == null || !c.isOpen) {
      throw RelayException('not connected');
    }
    return c.send(to: to, id: id, payload: payload);
  }

  /// A request to an introduction mailbox (PROTOCOL §21.7, §21.8): a sealed
  /// envelope with its proof-of-work stamp [pow], on an anonymous connection
  /// opened for it alone and closed after — never the authenticated link,
  /// which would put this account's routing id beside the handle's mailbox,
  /// and not the long-lived anonymous one either: once the request is
  /// accepted, that link carries this account's envelopes to the account the
  /// handle introduced, and one connection sending to both the handle's
  /// mailbox and that account would tell the relay which account holds the
  /// handle. Throws a [RelayPowRequired] when the relay wants another stamp,
  /// and `RelayException('not connected')` when the relay cannot be reached.
  Future<void> sendStamped(
      {required String to,
      required String id,
      required String payload,
      required String pow}) async {
    if (!SealedEnvelope.looksSealed(payload)) {
      throw ArgumentError('a stamped send is a sealed envelope');
    }
    final RelayClient c;
    try {
      c = await RelayClient.connectAnonymous(serverUrl, identity);
    } catch (_) {
      throw RelayException('not connected');
    }
    try {
      await c.send(to: to, id: id, payload: payload, pow: pow);
    } finally {
      await c.close();
    }
  }

  void ackReceived({required String id, required String from}) {
    try {
      _client?.ackReceived(id: id, from: from);
    } catch (_) {}
  }

  /// Store this device's push token and register it now if connected. It is
  /// re-registered automatically on every future reconnect. Null forgets it
  /// here and says nothing to the relay — [unregisterPush] does that.
  void setPushToken(String? token) {
    _pushToken = token;
    if (token != null) _pushWithdrawDue = false;
    _syncPush();
  }

  /// Turn push off for this identity and tell the relay to forget the token —
  /// now if the link is up, otherwise as soon as it is, and again on every
  /// connection until the relay answers ([pushWithdrawalPending],
  /// [onPushWithdrawn]).
  void unregisterPush() {
    _pushToken = null;
    _pushWithdrawDue = true;
    _syncPush();
  }

  /// Bring what the relay holds for this device in line with what it should,
  /// one push frame at a time, on the authenticated link — which is the
  /// identity the relay keys a token by. Re-run when a frame is answered or
  /// fails, on every connection, and when the wanted state changes.
  void _syncPush() {
    if (_pushOp != null) return; // re-run when the frame in flight settles
    final c = _client;
    if (c == null || !c.isOpen || status != LinkStatus.connected) return;
    final token = _pushToken;
    final Future<void> op;
    if (token != null) {
      if (token == _pushConfirmed || token == _pushRefused) return;
      op = c.registerPushAcked(token: token);
    } else if (_pushWithdrawDue) {
      op = c.unregisterPushAcked();
    } else {
      return;
    }
    _pushRetry?.cancel();
    var retry = false;
    _pushOp = op.then((_) {
      if (token != null) {
        _pushConfirmed = token;
      } else {
        _withdrawn();
      }
    }, onError: (Object e) {
      final code = e is RelayException ? e.message : '';
      if (token == null && code == 'unknown_frame') {
        // A relay with no push at all: it holds no token to forget.
        _withdrawn();
      } else if (token != null &&
          (code == 'bad_push' ||
              code == 'push_refused' ||
              code == 'unknown_frame')) {
        // Refused for good — or a relay with no push at all: asking again
        // would be answered the same way.
        _pushRefused = token;
      } else {
        retry = true; // a timeout, a refusal of the moment, a closed link
      }
    }).whenComplete(() {
      _pushOp = null;
      if (retry) {
        // Not at once: a refusal of the moment (`rate_limited`, `internal`)
        // comes straight back, and answering it straight back is a loop.
        // A new connection, or a change in what is wanted, tries sooner.
        if (isConnected && _shouldRun) {
          _pushRetry = Timer(pushRetryDelay, _syncPush);
        }
        return;
      }
      _syncPush(); // the wanted state may have moved while this was out
    });
  }

  void _withdrawn() {
    _pushConfirmed = null;
    if (_pushToken != null || !_pushWithdrawDue) return; // superseded
    _pushWithdrawDue = false;
    try {
      onPushWithdrawn?.call();
    } catch (_) {}
  }

  void _setStatus(LinkStatus s) {
    if (status != s) {
      status = s;
      notifyListeners();
    }
  }
}
