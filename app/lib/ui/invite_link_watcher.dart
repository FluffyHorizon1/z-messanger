import 'dart:async';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../core/connect_invites.dart';
import '../core/deep_links.dart';
import 'add_contact_screen.dart';

/// Shows an invite that arrived by link (17.3b).
///
/// [DeepLinks] opens the invite and pumps it; this is the part that puts it in
/// front of the person. Until 2026-09-17 nothing did: a tapped link wrote an
/// invite into the vault and the app came up on the home screen as if nothing
/// had happened, and the ceremony waited there for somebody to find the
/// CONNECT tab. Sits inside the `MaterialApp`, wrapping the home screen, so it
/// has a navigator to push onto — the launch intent is drained before any
/// screen exists, which is why it also asks for [DeepLinks.takeUnshown] on
/// mount rather than only listening.
class InviteLinkWatcher extends StatefulWidget {
  const InviteLinkWatcher({super.key, required this.child});

  final Widget child;

  @override
  State<InviteLinkWatcher> createState() => _InviteLinkWatcherState();
}

class _InviteLinkWatcherState extends State<InviteLinkWatcher> {
  StreamSubscription<PendingInvite>? _sub;
  bool _showing = false;

  @override
  void initState() {
    super.initState();
    final links = context.read<DeepLinks>();
    _sub = links.opened.listen((_) => _show());
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted) return;
      if (links.takeUnshown() != null) _show();
    });
  }

  @override
  void dispose() {
    _sub?.cancel();
    super.dispose();
  }

  /// One CONNECT screen at a time: a second link while it is open is already
  /// on the list it shows.
  Future<void> _show() async {
    if (_showing || !mounted) return;
    _showing = true;
    // Taken whether or not it was the one that triggered this: the screen
    // shows every pending invite, so there is nothing left to show later.
    context.read<DeepLinks>().takeUnshown();
    try {
      await Navigator.of(context).push(MaterialPageRoute<void>(
          builder: (_) => const AddContactScreen(connect: true)));
    } finally {
      _showing = false;
    }
  }

  @override
  Widget build(BuildContext context) => widget.child;
}
