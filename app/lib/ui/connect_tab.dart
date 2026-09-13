import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:z_protocol/z_protocol.dart';

import '../core/connect_invites.dart';
import '../core/share_text.dart';
import '../l10n/app_localizations.dart';
import '../l10n/remaining_text.dart';
import 'theme.dart';

/// The CONNECT tab (17.3): adding someone you cannot stand next to.
///
/// The other three tabs hand a code across a gap the user has already
/// decided to trust — a QR between two screens, or a paste over a channel
/// they picked. This one assumes the opposite: the channel carrying the
/// invite may be hostile, so the invite is one-time and short-lived, and the
/// eight digits at the end are what turns "somebody answered" into "the right
/// person answered".
class ConnectTab extends StatefulWidget {
  const ConnectTab({super.key});

  @override
  State<ConnectTab> createState() => _ConnectTabState();
}

class _ConnectTabState extends State<ConnectTab> {
  final _openCtrl = TextEditingController();
  String? _error;
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    // Pending invites survive the app closing, so the first thing this tab
    // does is find out what is already in flight.
    final invites = context.read<ConnectInvites>();
    invites.load().then((_) {
      if (mounted) invites.pump();
    });
  }

  @override
  void dispose() {
    _openCtrl.dispose();
    super.dispose();
  }

  Future<void> _run(Future<void> Function() action) async {
    if (_busy) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await action();
    } on FormatException catch (e) {
      if (mounted) setState(() => _error = e.message);
    } catch (e) {
      if (mounted) setState(() => _error = '$e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _copy(String value) async {
    await Clipboard.setData(ClipboardData(text: value));
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(AppLocalizations.of(context).connectCopied)));
  }

  /// Hand the invite to whatever the two people already use.
  ///
  /// Where there is no share sheet — every platform but Android today — the
  /// link goes to the clipboard and the message says so, rather than a button
  /// that sometimes does nothing.
  Future<void> _share(String link) async {
    if (await ShareText.share(link)) return;
    await Clipboard.setData(ClipboardData(text: link));
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
        content:
            Text(AppLocalizations.of(context).connectSharedToClipboard)));
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final invites = context.watch<ConnectInvites>();
    // A finished ceremony is the only thing worth interrupting the user for.
    final ready = invites.invites.where((i) => i.awaitingConfirmation).toList();

    return SingleChildScrollView(
      padding: EdgeInsets.fromLTRB(
          24, 24, 24, 24 + MediaQuery.paddingOf(context).bottom),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(l.connectIntro,
              style: TextStyle(color: context.z.textSecondary, height: 1.5)),
          const SizedBox(height: 20),
          FilledButton.icon(
            style: FilledButton.styleFrom(
              backgroundColor: context.z.accent,
              foregroundColor: context.z.onAccent,
              padding: const EdgeInsets.symmetric(vertical: 16),
            ),
            icon: const Icon(Icons.person_add_alt),
            onPressed: _busy
                ? null
                : () => _run(() async {
                      await invites.create();
                      await invites.pump();
                    }),
            label: Text(l.connectCreate),
          ),
          const SizedBox(height: 8),
          Text(l.connectOneTime,
              style:
                  TextStyle(color: context.z.textSecondary, fontSize: 12)),
          const Divider(height: 40),
          Text(l.connectOpenTitle,
              style: const TextStyle(fontWeight: FontWeight.w600)),
          const SizedBox(height: 12),
          TextField(
            controller: _openCtrl,
            maxLines: 2,
            style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
            decoration: InputDecoration(labelText: l.connectOpenField),
          ),
          const SizedBox(height: 12),
          FilledButton(
            onPressed: _busy
                ? null
                : () => _run(() async {
                      await invites.open(_openCtrl.text);
                      _openCtrl.clear();
                      await invites.pump();
                    }),
            child: Text(l.connectOpen),
          ),
          if (_error != null) ...[
            const SizedBox(height: 12),
            Text(_error!, style: TextStyle(color: context.z.danger)),
          ],
          const Divider(height: 40),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text(l.connectPendingTitle,
                  style: const TextStyle(fontWeight: FontWeight.w600)),
              TextButton(
                onPressed: _busy ? null : () => _run(invites.pump),
                child: Text(l.connectCheck),
              ),
            ],
          ),
          if (invites.invites.isEmpty)
            Text(l.connectNoInvites,
                style: TextStyle(color: context.z.textSecondary))
          else
            for (final invite in invites.invites)
              _inviteCard(l, invites, invite),
          for (final invite in ready)
            Padding(
              padding: const EdgeInsets.only(top: 16),
              child: ConnectConfirmPanel(invite: invite),
            ),
        ],
      ),
    );
  }

  Widget _inviteCard(
      AppLocalizations l, ConnectInvites invites, PendingInvite invite) {
    final status = switch (invite.progress) {
      ConnectProgress.expired => l.connectExpired,
      ConnectProgress.aborted => l.connectAborted,
      ConnectProgress.spent => l.connectAborted,
      _ => invite.run.session != null
          ? l.connectConfirmTitle
          : (invite.mine ? l.connectPending : l.connectPendingOpened),
    };
    // What is left of the 24 hours (§20, R23).
    //
    // `progress` only moves when something pumps, so an invite that ran out
    // while nobody was looking still reads `waiting` — the clock is what
    // decides whether it is still worth handing to anyone, not the last thing
    // the relay said. The row is shown for any unanswered invite (and says
    // "Expired" when it is), and the renderings below are shown only while it
    // is LIVE: an invite that has been answered, has run out, or was stopped
    // is a bearer token that no longer works, and leaving it on screen to be
    // copied is an invitation to send it to somebody.
    final left = Duration(
        milliseconds: invite.createdMs +
            connectInviteLifetime.inMilliseconds -
            DateTime.now().millisecondsSinceEpoch);
    final unanswered = invite.progress == ConnectProgress.waiting;
    final live = unanswered && left > Duration.zero;
    return Card(
      margin: const EdgeInsets.only(top: 12),
      color: context.z.surfaceAlt,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(status,
                style: TextStyle(
                    color: invite.progress == ConnectProgress.waiting
                        ? context.z.textSecondary
                        : context.z.warn)),
            if (unanswered) ...[
              const SizedBox(height: 4),
              // The one number a person needs to decide whether to send it
              // again. "Pending" said nothing about which hour of the 24 it
              // was in.
              Text(remainingText(l, left),
                  style: TextStyle(
                      fontSize: 12,
                      color: left.inHours < 1
                          ? context.z.warn
                          : context.z.textSecondary)),
            ],
            if (invite.mine && live) ...[
              const SizedBox(height: 12),
              Text(l.connectLinkLabel,
                  style: TextStyle(
                      fontSize: 12, color: context.z.textSecondary)),
              SelectableText(invite.link,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
              const SizedBox(height: 10),
              Text(l.connectCodeLabel,
                  style: TextStyle(
                      fontSize: 12, color: context.z.textSecondary)),
              SelectableText(invite.code,
                  style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 16,
                      letterSpacing: 1.5)),
              const SizedBox(height: 10),
              Text(l.connectQrLabel,
                  style: TextStyle(
                      fontSize: 12, color: context.z.textSecondary)),
              const SizedBox(height: 6),
              // The third rendering of the SAME secret — the link, verbatim,
              // so a photograph of the screen is the same bearer token the
              // link is and not a second one. White quiet zone regardless of
              // theme: a scanner needs the contrast, not the palette.
              Center(child: InviteQr(link: invite.link)),
              const SizedBox(height: 6),
              Text(l.connectSameSecret,
                  style: TextStyle(
                      fontSize: 12, color: context.z.textSecondary)),
              const SizedBox(height: 12),
              Wrap(
                spacing: 8,
                children: [
                  FilledButton.icon(
                    icon: const Icon(Icons.ios_share, size: 18),
                    onPressed: () => _share(invite.link),
                    label: Text(l.connectShareSheet),
                  ),
                  OutlinedButton.icon(
                    icon: const Icon(Icons.link, size: 18),
                    onPressed: () => _copy(invite.link),
                    label: Text(l.connectShareLink),
                  ),
                  OutlinedButton.icon(
                    icon: const Icon(Icons.abc, size: 18),
                    onPressed: () => _copy(invite.code),
                    label: Text(l.connectShareCode),
                  ),
                ],
              ),
            ],
            Align(
              alignment: Alignment.centerRight,
              child: TextButton(
                onPressed: () => invites.discard(invite),
                child: Text(l.connectDiscard),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

/// The comparison, and the three honest ways out of it (17.3, criteria 4–5).
///
/// There is deliberately no fourth button. "They do not match" adds nothing
/// at all — a ceremony that produced two different strings is one an attacker
/// is sitting in, and the only safe thing to do with it is stop. "We have not
/// compared yet" adds the contact but leaves it unverified and says so, which
/// is exactly what the paste flow has always produced; the difference is that
/// here the app knows the comparison was on offer.
class ConnectConfirmPanel extends StatefulWidget {
  const ConnectConfirmPanel({super.key, required this.invite});

  final PendingInvite invite;

  @override
  State<ConnectConfirmPanel> createState() => _ConnectConfirmPanelState();
}

class _ConnectConfirmPanelState extends State<ConnectConfirmPanel> {
  bool _busy = false;

  Future<void> _finish(Future<String?> Function() action) async {
    if (_busy) return;
    setState(() => _busy = true);
    String? said;
    try {
      said = await action();
    } on FormatException catch (e) {
      // The message, not the type name: these reach the user verbatim.
      said = e.message;
    } catch (e) {
      said = '$e';
    }
    if (!mounted) return;
    setState(() => _busy = false);
    if (said != null) {
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text(said)));
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final invites = context.read<ConnectInvites>();
    final invite = widget.invite;
    final sas = invite.sas;
    // Nothing to offer once the user has answered. A panel left standing
    // would still carry a live "they match" button for a ceremony that was
    // stopped — the one button that must never be reachable twice.
    if (sas == null || invite.answered) return const SizedBox.shrink();
    final peerName = invite.peer?.displayName ?? '';

    return Card(
      color: context.z.surface,
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(l.connectConfirmTitle,
                style: const TextStyle(
                    fontSize: 18, fontWeight: FontWeight.w700)),
            const SizedBox(height: 16),
            Center(
              child: SelectableText(
                sas,
                style: TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 32,
                    letterSpacing: 4,
                    color: context.z.accent),
              ),
            ),
            const SizedBox(height: 16),
            Text(l.connectConfirmBody(peerName),
                style:
                    TextStyle(color: context.z.textSecondary, height: 1.5)),
            const SizedBox(height: 20),
            FilledButton(
              style: FilledButton.styleFrom(
                backgroundColor: context.z.ok,
                foregroundColor: context.z.onAccent,
                padding: const EdgeInsets.symmetric(vertical: 16),
              ),
              onPressed: _busy
                  ? null
                  : () => _finish(() async {
                        final c = await invites.confirm(invite);
                        return l.connectAdded(c.name);
                      }),
              child: Text(l.connectMatch),
            ),
            const SizedBox(height: 10),
            OutlinedButton(
              onPressed: _busy
                  ? null
                  : () => _finish(() async {
                        final c = await invites.defer(invite);
                        return l.connectAddedUnverified(c.name);
                      }),
              child: Text(l.connectNotYet),
            ),
            const SizedBox(height: 6),
            Text(l.connectUnverifiedNote,
                style:
                    TextStyle(fontSize: 12, color: context.z.textSecondary)),
            const SizedBox(height: 16),
            OutlinedButton(
              style: OutlinedButton.styleFrom(
                foregroundColor: context.z.danger,
                side: BorderSide(color: context.z.danger),
                padding: const EdgeInsets.symmetric(vertical: 16),
              ),
              onPressed: _busy
                  ? null
                  : () => _finish(() async {
                        await invites.mismatch(invite);
                        return l.connectStopped;
                      }),
              child: Text(l.connectMismatch),
            ),
            const SizedBox(height: 6),
            Text(l.connectMismatchWarning,
                style: TextStyle(fontSize: 12, color: context.z.danger)),
          ],
        ),
      ),
    );
  }
}

/// The invite as a QR: the link, verbatim, and nothing else.
///
/// A wrapper rather than a bare [QrImageView] for two reasons. It keeps the
/// white quiet zone in one place — a scanner needs the contrast whatever the
/// theme is doing — and it exposes [link], because what a test needs to know
/// about this widget is precisely that the thing encoded is the link and not
/// a second secret, and `QrImageView` keeps its data private.
class InviteQr extends StatelessWidget {
  const InviteQr({super.key, required this.link});

  /// Exactly what the QR encodes.
  final String link;

  @override
  Widget build(BuildContext context) => QrImageView(
        data: link,
        version: QrVersions.auto,
        size: 180,
        backgroundColor: const Color(0xFFFFFFFF),
        padding: const EdgeInsets.all(8),
      );
}
