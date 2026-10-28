import 'dart:async';

import 'package:flutter/services.dart';
import 'package:z_protocol/z_protocol.dart' show IntroLink, introLinkPath;

import 'app_lock.dart';
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
/// the channel pushes any that arrive afterwards.
///
/// This is a public entry point. The activity is exported, as one that takes
/// App Links must be, so any app on the device can send it a VIEW intent, and
/// an intent that names the activity is never held to the intent filter that
/// keeps a tap to the invite page. So [handle] holds every link to that filter
/// itself ([filterClaims]) and drops anything else in silence, before the
/// vault is touched; and a link that arrives while the app lock is engaged,
/// or due as the app comes back to the front ([AppLock.lockedOrDue]), waits
/// until the lock is open. Until 4.7.2 neither held: any URI that read as an
/// invite was opened into the vault, on any host and by `http` as well as
/// `https`, lock or no lock, and its screen pushed under the lock's.
class DeepLinks {
  DeepLinks(this._invites,
      {MethodChannel? channel, bool Function()? introLinks, AppLock? lock})
      : _channel = channel ?? const MethodChannel(channelName),
        _introLinks = introLinks,
        _lock = lock {
    lock?.addListener(_onLock);
  }

  static const String channelName = 'z/deeplink';

  /// The hosts Android's filter for invite links names, both on `https` and
  /// at the path `/i` exactly (`AndroidManifest.xml`; `deep_link_test` 8
  /// holds the two to each other).
  static const Set<String> filterHosts = {
    'zmessengers.com',
    'www.zmessengers.com',
  };

  /// Whether Android's filter would hand [url] over: `https://`, one of
  /// [filterHosts], and the path `/i`, before an optional query and the
  /// fragment — compared as written, since the filter compares the scheme
  /// and the host exactly, case and all. While public links are on
  /// ([introLinks]), the path `/c` too, which the release that turns them on
  /// adds to the filter (PROTOCOL §21.9). A port or a name before the host,
  /// which the filter would let by and no link Z makes carries, is refused.
  static bool filterClaims(String url, {bool introLinks = false}) {
    for (final host in filterHosts) {
      final origin = 'https://$host';
      if (!url.startsWith(origin)) continue;
      final rest = url.substring(origin.length);
      final end = rest.indexOf(RegExp('[?#]'));
      final path = end < 0 ? rest : rest.substring(0, end);
      return path == '/i' || (introLinks && path == introLinkPath);
    }
    return false;
  }

  final ConnectInvites _invites;
  final MethodChannel _channel;

  /// The app lock, when there is one: what arrives while it is engaged or
  /// due waits for it.
  final AppLock? _lock;

  /// Phase 39 (ADR 0032 §3): whether a public link is taken — the build's
  /// `introLinksEnabled`, through the handle service. Off, or not given, a
  /// `/c#zi1.…` link is ignored like any other foreign link. No build's
  /// Android filter claims `/c` yet (the release that turns links on adds it),
  /// and [filterClaims] takes `/c` only while links are on, so until then
  /// none is taken here.
  final bool Function()? _introLinks;

  final _opened = StreamController<PendingInvite>.broadcast();
  final _openedLinks = StreamController<IntroLink>.broadcast();

  /// Links that arrived while the lock was engaged or due, oldest first, each
  /// once. Kept in memory only: the platform has already handed them over, so
  /// an app killed at the lock forgets them, and a second tap brings one back.
  final _waiting = <String>[];

  /// Links are taken one at a time, in the order they came:
  /// [ConnectInvites.open] looks for an invite already open before it
  /// awaits, so two at once could both pass the look.
  Future<void> _turn = Future<void>.value();
  bool _releasing = false;
  bool _disposed = false;

  bool get _held => _lock?.lockedOrDue ?? false;

  /// Public links that arrived by a tap — HELD: nothing is sent and nothing
  /// connects until their person presses Send request on the screen the UI
  /// puts them in front of (ADR 0032 §3).
  Stream<IntroLink> get openedLinks => _openedLinks.stream;
  IntroLink? _unshownLink;

  /// The tapped link no screen has shown yet, once.
  IntroLink? takeUnshownLink() {
    final l = _unshownLink;
    _unshownLink = null;
    return l;
  }

  /// Invites that arrived by link and were taken — held until their person
  /// says yes (ADR 0024). The UI listens so it can show them; nothing here
  /// navigates on its own.
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
    _disposed = true;
    _lock?.removeListener(_onLock);
    _waiting.clear();
    _channel.setMethodCallHandler(null);
    await _opened.close();
    await _openedLinks.close();
  }

  Future<void> _onCall(MethodCall call) async {
    if (call.method != 'link') return;
    final url = call.arguments;
    if (url is String) await handle(url);
  }

  /// Consume one link. Returns the invite it opened, or null if it opened
  /// none: a link the platform's filter would not have handed over — another
  /// app can name the activity and pass the filter by — one that is not an
  /// invite, a stale one or one already open; a public link, which is handed
  /// to [openedLinks] instead; or one that arrived while the app lock is
  /// engaged or due, which waits, and is opened, [opened] told, once the lock
  /// is open.
  Future<PendingInvite?> handle(String url) async {
    final links = _introLinks?.call() ?? false;
    if (!filterClaims(url, introLinks: links) ||
        (ConnectInvites.parseInvite(url) == null &&
            !(links && IntroLink.tryParse(url) != null))) {
      lastRejected = url;
      return null;
    }
    if (_held) {
      if (!_waiting.contains(url)) _waiting.add(url);
      return null;
    }
    return _inTurn(url);
  }

  Future<PendingInvite?> _inTurn(String url) {
    final done = _turn.then((_) => _take(url));
    _turn = done.then((_) {}, onError: (_) {});
    return done;
  }

  Future<PendingInvite?> _take(String url) async {
    if (_disposed) return null;
    final links = _introLinks;
    if (links != null && links()) {
      final link = IntroLink.tryParse(url);
      if (link != null) {
        // Held, as an invite is: recorded nowhere, sent nowhere, only put in
        // front of its person.
        lastRejected = null;
        _unshownLink = link;
        if (!_openedLinks.isClosed) _openedLinks.add(link);
        return null;
      }
    }
    try {
      // Held (ADR 0024): a tap is not a yes. The invite is recorded and put
      // in front of the person, and nothing of the ceremony leaves the
      // device — no round, not even a connection — until they press
      // Connect. Until 2026-10-09 this stepped the ceremony at once, and the
      // contact code went out in message 4 before anyone had looked; the
      // tab now carries it forward from the yes (`ConnectInvites.consent`).
      final invite = await _invites.open(url, consented: false);
      lastRejected = null;
      _unshown = invite;
      if (!_opened.isClosed) _opened.add(invite);
      return invite;
    } on FormatException {
      // Already open, or no longer usable. The tab shows what is pending, so
      // there is nothing to add and nothing to apologise for.
      lastRejected = url;
      return null;
    }
  }

  void _onLock() {
    if (!_held) unawaited(_release());
  }

  /// The lock is open: the links that waited for it, oldest first, each
  /// once. A lock engaged again part way leaves the rest waiting for the next
  /// time it opens.
  Future<void> _release() async {
    if (_releasing) return;
    _releasing = true;
    try {
      while (_waiting.isNotEmpty && !_held && !_disposed) {
        final url = _waiting.removeAt(0);
        try {
          await _inTurn(url);
        } catch (_) {
          // An error the same link would have met unlocked — a vault closed
          // under it — ends it here too. There is no caller left to hand it
          // to, and the links behind it still go.
          lastRejected = url;
        }
      }
    } finally {
      _releasing = false;
    }
  }
}
