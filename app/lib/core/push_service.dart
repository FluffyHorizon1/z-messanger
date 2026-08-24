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

/// Registers this device for push and keeps the relay's copy of the FCM token
/// fresh. Android-only; a safe no-op on desktop (which has no FCM).
class PushService extends ChangeNotifier {
  final Transport transport;
  final Vault vault;

  bool _enabled = false;
  bool get enabled => _enabled;

  /// True only where push is actually available (Android). The Settings toggle
  /// is hidden elsewhere.
  bool get supported => !kIsWeb && Platform.isAndroid;

  PushService({required this.transport, required this.vault});

  /// Read the saved preference (default ON) and activate if enabled.
  Future<void> init() async {
    if (!supported) return;
    _enabled = (await vault.kvGet('push_enabled')) != '0';
    if (_enabled) {
      await _activate();
    }
    notifyListeners();
  }

  Future<void> _activate() async {
    await Firebase.initializeApp();
    final fm = FirebaseMessaging.instance;
    await fm.requestPermission();
    final token = await fm.getToken();
    if (token != null) transport.setPushToken(token);
    fm.onTokenRefresh.listen((t) {
      if (_enabled) transport.setPushToken(t);
    });
    // A ping received while the app is foregrounded just nudges the live link
    // to drain immediately — messages then arrive through the normal path.
    FirebaseMessaging.onMessage.listen((_) => transport.nudge());
  }

  /// User toggle in Settings (the "no-push" option from the threat model).
  Future<void> setEnabled(bool on) async {
    if (!supported) return;
    _enabled = on;
    await vault.kvPut('push_enabled', on ? '1' : '0', sensitive: false);
    if (on) {
      await _activate();
    } else {
      transport.unregisterPush();
    }
    notifyListeners();
  }
}
