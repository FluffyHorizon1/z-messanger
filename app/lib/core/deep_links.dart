import 'dart:async';

import 'package:flutter/services.dart';

import 'connect_invites.dart';

/// Invite links arriving from the platform (17.3b).
///
/// Android hands the app `https://zmessengers.com/i#<code>` when someone taps
/// an invite. The code is in the FRAGMENT, which no browser sends to a server:
/// the site that serves the landing page never receives an invite, and neither
/// does anything else on the way — the whole secret goes from the intent
/// straight into [ConnectInvites.open].
///
/// Two ways in, because an intent arrives differently depending on whether the
/// app was running: [start] drains the one the activity was launched with, and
/// the channel pushes any that arrive afterwards. Anything that is not an
/// invite is ignored in silence, because this is a public entry point — any
/// app on the device can send it a VIEW intent, so it must be safe to hand
/// rubbish to.
class DeepLinks {
  DeepLinks(this._invites, {MethodChannel? channel})
      : _channel = channel ?? const MethodChannel(channelName);

  static const String channelName = 'z/deeplink';

  final ConnectInvites _invites;
  final MethodChannel _channel;

  final _opened = StreamController<PendingInvite>.broadcast();

  /// Invites that arrived by link and were accepted. The UI listens so it can
  /// show the ceremony; nothing here navigates on its own.
  Stream<PendingInvite> get opened => _opened.stream;

  /// The last link that was handed over and refused, for a screen that wants
  /// to say why nothing happened.
  String? lastRejected;

  /// Begin listening, and take whatever the app was launched with.
  ///
  /// Safe on every platform: a channel with nothing behind it answers
  /// [MissingPluginException], which is not an error here — it is what "this
  /// build has no deep links" looks like.
  Future<void> start() async {
    _channel.setMethodCallHandler(_onCall);
    try {
      final initial = await _channel.invokeMethod<String>('take');
      if (initial != null) await handle(initial);
    } on MissingPluginException {
      // No platform side (desktop, or a test): nothing to drain.
    } on PlatformException {
      // The platform declined to say. Not worth a crash on start-up.
    }
  }

  Future<void> dispose() async {
    _channel.setMethodCallHandler(null);
    await _opened.close();
  }

  Future<void> _onCall(MethodCall call) async {
    if (call.method != 'link') return;
    final url = call.arguments;
    if (url is String) await handle(url);
  }

  /// Consume one link. Returns the invite it opened, or null if the link was
  /// not one — a foreign VIEW intent, a stale link, or one already open.
  Future<PendingInvite?> handle(String url) async {
    if (ConnectInvites.parseInvite(url) == null) {
      lastRejected = url;
      return null;
    }
    try {
      final invite = await _invites.open(url);
      lastRejected = null;
      if (!_opened.isClosed) _opened.add(invite);
      return invite;
    } on FormatException {
      // Already open, or no longer usable. The tab shows what is pending, so
      // there is nothing to add and nothing to apologise for.
      lastRejected = url;
      return null;
    }
  }
}
