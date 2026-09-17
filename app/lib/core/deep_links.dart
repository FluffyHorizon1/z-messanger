import 'dart:async';

import 'package:flutter/services.dart';

import 'connect_invites.dart';

/// Invite links arriving from the platform (17.3b).
///
/// Android hands the app `https://www.zmessengers.com/i#<code>` when someone taps
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

  /// The link-opened invite no screen has shown yet, if any.
  ///
  /// The launch intent is drained by [start], which the app calls before any
  /// screen exists to listen to [opened] — a broadcast stream drops what
  /// nobody is listening for. So the most recent one is also kept here until
  /// a screen takes it. Until 2026-09-17 nothing consumed either: a tapped
  /// link put an invite in the vault and the app opened on the home screen as
  /// if nothing had happened.
  PendingInvite? _unshown;

  /// Hands over the invite waiting to be shown, once.
  PendingInvite? takeUnshown() {
    final i = _unshown;
    _unshown = null;
    return i;
  }

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
      _unshown = invite;
      if (!_opened.isClosed) _opened.add(invite);
      // Carry it forward at once. Opening records the invite and touches no
      // network; this is the ceremony's first round for this side — the same
      // connect-read-leave a "Check now" does — and without it a link-opened
      // invite sat at "waiting" until somebody found the tab. Awaited, so a
      // caller that is about to tear down (a test, a closing app) is not
      // left with a round in flight; the platform side does not wait on the
      // reply to `link`, and nothing waits on [start].
      await _invites.pump();
      return invite;
    } on FormatException {
      // Already open, or no longer usable. The tab shows what is pending, so
      // there is nothing to add and nothing to apologise for.
      lastRejected = url;
      return null;
    }
  }
}
