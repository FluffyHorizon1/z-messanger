// A public link someone else published, opened (phase 39; ADR 0032 §3;
// PROTOCOL §21.9).
//
// HELD: a link tapped, scanned, read from an image, pasted or typed into the
// handle search lands here, and nothing is sent and no connection opened
// until its person presses Send request — on this screen, which says first
// that whoever made the link will see their name and contact code, and that
// a link verifies nothing. A link this account made is recognised and sent
// nothing. A request already sent through it is said, and after 30 days with
// no answer the screen says the link may have been replaced or withdrawn: a
// printed link cannot be updated, so a copy whose owner moved on fails in
// silence. Reached only in a build with links on (`introLinksEnabled`).

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:z_protocol/z_protocol.dart' show IntroLink;

import '../core/chat_service.dart';
import '../core/handles.dart';
import '../l10n/app_localizations.dart';
import '../l10n/handle_text.dart';
import 'theme.dart';

/// Put [link] in front of its person, held.
Future<void> openIntroLink(BuildContext context, IntroLink link) =>
    Navigator.of(context).push(MaterialPageRoute<void>(
        builder: (_) => OpenLinkScreen(link: link)));

class OpenLinkScreen extends StatefulWidget {
  const OpenLinkScreen({super.key, required this.link});

  final IntroLink link;

  @override
  State<OpenLinkScreen> createState() => _OpenLinkScreenState();
}

class _OpenLinkScreenState extends State<OpenLinkScreen> {
  bool _sending = false;
  String? _error;

  /// The link's mailbox, worked out here from the link alone: nothing is
  /// fetched to open a link.
  String? _rid;

  @override
  void initState() {
    super.initState();
    widget.link.introRid().then((r) {
      if (mounted) setState(() => _rid = r);
    });
  }

  Future<void> _send() async {
    if (_sending) return;
    final l = AppLocalizations.of(context);
    final messenger = ScaffoldMessenger.of(context);
    final navigator = Navigator.of(context);
    final h = context.read<ChatService>().handles;
    setState(() {
      _sending = true;
      _error = null;
    });
    try {
      await h.requestLink(widget.link);
      if (!mounted) return;
      messenger.showSnackBar(SnackBar(content: Text(l.plinkRequestSent)));
      navigator.pop();
    } on HandleException catch (e) {
      if (!mounted) return;
      setState(() => _error = handleFailureText(l, e.failure));
    } finally {
      if (mounted) setState(() => _sending = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final svc = context.watch<ChatService>();
    final h = svc.handles;
    final rid = _rid;
    final waiting = h.outgoingFor(widget.link);
    return Scaffold(
      appBar: AppBar(title: Text(l.plinkOpenTitle)),
      body: ListView(
        padding: EdgeInsets.fromLTRB(
            24, 24, 24, 24 + MediaQuery.paddingOf(context).bottom),
        children: [
          SelectableText(widget.link.code,
              style: TextStyle(
                  fontSize: 12,
                  fontFamily: 'monospace',
                  color: context.z.textSecondary)),
          const SizedBox(height: 16),
          if (rid == null)
            const Center(child: CircularProgressIndicator())
          else if (h.isOwnMailbox(rid))
            _Para(l.plinkOwn)
          else ...[
            _Para(l.plinkOpenBody),
            _Para(l.plinkOpenNote, strong: true),
            if (waiting != null)
              _Para(l.plinkOpenSent(
                  ((h.now() - waiting.sentMs) ~/ 86400000).clamp(0, 1 << 30))),
            if (waiting != null && h.linkUnanswered(waiting))
              _Para(l.plinkUnanswered, warn: true),
            if (_error != null) _Para(_error!, danger: true),
            const SizedBox(height: 12),
            FilledButton(
              style: FilledButton.styleFrom(
                backgroundColor: context.z.accent,
                foregroundColor: context.z.onAccent,
                padding: const EdgeInsets.symmetric(vertical: 14),
              ),
              onPressed: _sending ? null : _send,
              child: Text(_sending ? l.hdlSending : l.hdlSendRequest),
            ),
          ],
        ],
      ),
    );
  }
}

class _Para extends StatelessWidget {
  final String text;
  final bool warn;
  final bool danger;
  final bool strong;
  const _Para(this.text,
      {this.warn = false, this.danger = false, this.strong = false});

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 6),
        child: Text(text,
            style: TextStyle(
                height: 1.45,
                fontWeight: strong ? FontWeight.w600 : null,
                color: danger
                    ? context.z.danger
                    : warn
                        ? context.z.warn
                        : strong
                            ? null
                            : context.z.textSecondary)),
      );
}
