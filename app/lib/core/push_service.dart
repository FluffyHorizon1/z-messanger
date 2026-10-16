import 'dart:async';
import 'dart:io' show Platform;

import 'package:flutter/foundation.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';

import 'transport.dart';
import 'vault.dart';

/// Background isolate handler for a wake ping.
///
/// This runs in its OWN isolate when a message arrives while the app is
/// backgrounded or terminated. It deliberately CANNOT decrypt anything — the
/// vault key lives only in the main isolate — so it shows a generic,
/// content-free notification. The actual messages are drained and shown by the
/// running app when it next connects (foreground) or when the user opens it.
@pragma('vm:entry-point')
Future<void> zPushBackgroundHandler(RemoteMessage message) async {
  try {
    await Firebase.initializeApp();
  } catch (_) {
    // Already initialized in this isolate, or not needed to show a local notif.
  }
  await PushNotifier.showWake();
}

/// Thin wrapper over flutter_local_notifications so both isolates can raise a
/// content-free "you have a new message" alert.
class PushNotifier {
  static final FlutterLocalNotificationsPlugin _fln =
      FlutterLocalNotificationsPlugin();
  static bool _inited = false;

  static Future<void> _ensureInit() async {
    if (_inited) return;
    const android = AndroidInitializationSettings('@mipmap/ic_launcher');
    await _fln.initialize(
      settings: const InitializationSettings(android: android),
    );
    _inited = true;
  }

  static Future<void> showWake() async {
    await _ensureInit();
    const details = NotificationDetails(
      android: AndroidNotificationDetails(
        'z_messages',
        'Messages',
        channelDescription: 'Alerts that a new encrypted message is waiting.',
        importance: Importance.high,
        priority: Priority.high,
      ),
    );
    // Fixed id: repeated pings update the one "new message" alert rather than
    // stacking. No content or sender is included — the app reveals messages
    // only after it decrypts them locally.
    await _fln.show(
      id: 0,
      title: 'New message',
      body: 'Open Z to read your messages.',
      notificationDetails: details,
    );
  }
}

/// The platform's half of push: what the operating system says about this
/// app's notifications, and the Firebase Cloud Messaging token. Production
/// uses [FirebasePushPlatform]; a test passes its own, since Firebase has no
/// implementation on the machines tests run on.
abstract class PushPlatform {
  /// Ask the user to allow notifications, where the system still lets an app
  /// ask; true if they are allowed.
  Future<bool> requestPermission();

  /// Whether notifications are allowed now, without asking.
  Future<bool> permitted();

  /// This install's FCM token, or null when none can be had. Asking for one
  /// also lets FCM renew it by itself again ([forgetToken] stops that).
  Future<String?> token();

  /// Delete this install's FCM token and stop FCM minting a new one by
  /// itself: a token the relay may still hold then wakes nothing, because
  /// Google refuses it, and the relay drops a token Google refuses.
  Future<void> forgetToken();

  /// The new tokens FCM issues for this install.
  Stream<String> get tokenRefresh;

  /// Wake pings that arrive while the app is in front.
  Stream<void> get foregroundWakes;
}

/// [PushPlatform] over Firebase Cloud Messaging.
class FirebasePushPlatform implements PushPlatform {
  Future<FirebaseMessaging>? _ready;

  Future<FirebaseMessaging> _fm() => _ready ??= () async {
        await Firebase.initializeApp();
        return FirebaseMessaging.instance;
      }();

  static bool _allows(NotificationSettings s) =>
      s.authorizationStatus == AuthorizationStatus.authorized ||
      s.authorizationStatus == AuthorizationStatus.provisional;

  @override
  Future<bool> requestPermission() async =>
      _allows(await (await _fm()).requestPermission());

  @override
  Future<bool> permitted() async =>
      _allows(await (await _fm()).getNotificationSettings());

  @override
  Future<String?> token() async {
    final fm = await _fm();
    await fm.setAutoInitEnabled(true);
    return fm.getToken();
  }

  @override
  Future<void> forgetToken() async {
    final fm = await _fm();
    await fm.setAutoInitEnabled(false);
    await fm.deleteToken();
  }

  @override
  Stream<String> get tokenRefresh =>
      Stream.fromFuture(_fm()).asyncExpand((fm) => fm.onTokenRefresh);

  @override
  Stream<void> get foregroundWakes =>
      Stream.fromFuture(_fm()).asyncExpand((_) => FirebaseMessaging.onMessage);
}

/// What push is doing on this device, as Settings says it.
enum PushStatus {
  /// On, and notifications are allowed: the relay holds this device's token.
  on,

  /// On, but notifications are not allowed for the app: nothing is
  /// registered, and the relay has been (or is being) told to forget any
  /// token it held.
  notAllowed,

  /// Turned off in Settings.
  off,
}

/// Registers this device for push — when push is on AND the user allows
/// notifications, and only then — and keeps the relay's copy of the FCM
/// token fresh. Android-only; a safe no-op on desktop (which has no FCM).
///
/// Until phase 41 the token was registered whatever the user had answered
/// about notifications (the 2026-10-03 analysis, P1-20): a device that could
/// show nothing was still woken through Google for every message. Now a
/// device without permission registers nothing, a permission taken away is
/// noticed at the next start or return to the foreground and the token
/// withdrawn, and a withdrawal — that, or push turned off — is said to the
/// relay until it answers, across restarts ([Transport.unregisterPush]).
class PushService extends ChangeNotifier {
  final Transport transport;
  final Vault vault;
  final PushPlatform _platform;
  final bool _supported;

  bool _enabled = false;
  bool get enabled => _enabled;

  /// What the system answered when last asked; null before it was.
  bool? _permitted;

  /// The relay may hold a token for this device: one was handed to it and no
  /// withdrawal has been acknowledged since (`push_relay` in the vault). True
  /// when unknown — an install from before phase 41 registered regardless.
  bool _relayMayHold = true;

  bool _started = false;
  StreamSubscription<String>? _refreshSub;
  StreamSubscription<void>? _wakeSub;
  Future<void> _applying = Future<void>.value();

  /// True only where push is actually available (Android). The Settings toggle
  /// is hidden elsewhere.
  bool get supported => _supported;

  PushStatus get status => !_enabled
      ? PushStatus.off
      : _permitted == false
          ? PushStatus.notAllowed
          : PushStatus.on;

  /// The relay has yet to answer a withdrawal: until it does it may still
  /// wake this device.
  bool get withdrawalPending => transport.pushWithdrawalPending;

  /// [platform] and [supported] are for tests: production passes neither, and
  /// gets Firebase where the app runs on Android and nothing elsewhere.
  PushService(
      {required this.transport,
      required this.vault,
      PushPlatform? platform,
      bool? supported})
      : _platform = platform ?? FirebasePushPlatform(),
        _supported = supported ?? (!kIsWeb && Platform.isAndroid);

  /// Read the saved preference (default ON) and act on it: asks for
  /// notifications when push is on, registers only if they are allowed, and
  /// otherwise withdraws whatever the relay may still hold.
  Future<void> init() async {
    if (!supported) return;
    _enabled = (await vault.kvGet('push_enabled')) != '0';
    _relayMayHold = (await vault.kvGet('push_relay')) != 'off';
    transport.onPushWithdrawn = _onWithdrawn;
    _started = true;
    await _apply(ask: _enabled);
  }

  /// The app came back to the foreground: notifications may have been
  /// allowed or taken away in the system's settings meanwhile.
  Future<void> onResume() async {
    if (!supported || !_started) return;
    await _apply(ask: false);
  }

  /// User toggle in Settings (the "no-push" option from the threat model).
  Future<void> setEnabled(bool on) async {
    if (!supported) return;
    _enabled = on;
    await vault.kvPut('push_enabled', on ? '1' : '0', sensitive: false);
    await _apply(ask: on);
  }

  /// One at a time: a return to the foreground during a start, or a toggle
  /// during either, waits for the decision before it.
  Future<void> _apply({required bool ask}) {
    final run = _applying.then((_) => _decide(ask: ask));
    _applying = run.then((_) {}, onError: (Object _) {});
    return run;
  }

  Future<void> _decide({required bool ask}) async {
    var allowed = false;
    if (_enabled) {
      try {
        allowed = ask
            ? await _platform.requestPermission()
            : await _platform.permitted();
      } catch (_) {
        allowed = false; // a platform that cannot say has not said yes
      }
      _permitted = allowed;
    }
    if (_enabled && allowed) {
      String? token;
      try {
        token = await _platform.token();
      } catch (_) {}
      if (token != null) {
        // Recorded BEFORE the relay can have it, so a start after a crash
        // between the two still knows there may be something to withdraw.
        if (!_relayMayHold) {
          _relayMayHold = true;
          await vault.kvDelete('push_relay');
        }
        transport.setPushToken(token);
      }
      _refreshSub ??= _platform.tokenRefresh.listen((t) async {
        // `_permitted` can be stale here: it is set only on init, resume and
        // the Settings toggle, and FCM can rotate the token while the app is
        // alive but backgrounded, with no resume in between. Registering on
        // the stale flag would re-arm a device whose user has taken
        // notifications away (P1-20, the 2026-10-03 analysis), so permission
        // is re-checked before the refreshed token is handed on.
        if (!_enabled) return;
        bool allowed;
        try {
          allowed = await _platform.permitted();
        } catch (_) {
          allowed = false; // a platform that cannot say has not said yes
        }
        if (_enabled && allowed) transport.setPushToken(t);
      }, onError: (Object _) {});
      // A ping received while the app is foregrounded just nudges the live
      // link to drain immediately — messages then arrive through the normal
      // path.
      _wakeSub ??= _platform.foregroundWakes
          .listen((_) => transport.nudge(), onError: (Object _) {});
    } else {
      transport.setPushToken(null);
      if (_relayMayHold) {
        transport.unregisterPush();
        try {
          await _platform.forgetToken();
        } catch (_) {
          // Offline, or no token to delete: the relay's withdrawal is what
          // stops the wakes, and it is retried until it is answered.
        }
      }
    }
    notifyListeners();
  }

  void _onWithdrawn() {
    if (transport.pushWithdrawalPending) return;
    _relayMayHold = false;
    unawaited(
        vault.kvPut('push_relay', 'off').then((_) {}, onError: (Object _) {}));
    notifyListeners();
  }

  @override
  void dispose() {
    _refreshSub?.cancel();
    _wakeSub?.cancel();
    if (transport.onPushWithdrawn == _onWithdrawn) {
      transport.onPushWithdrawn = null;
    }
    super.dispose();
  }
}
