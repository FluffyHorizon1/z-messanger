import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:z_protocol/z_protocol.dart';

import '../core/chat_service.dart';
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
          const ConnectLinkWaits(),
          // Keyed by the invite: each panel holds state of its own — whether
          // to join the group, whether an answer is in flight — and without
          // a key, answering one of two panels handed the one removed's state
          // to the one left, so a switch turned off on one link read on on
          // the other, and "they match" joined the group it had been turned
          // off for.
          for (final invite in ready)
            Padding(
              key: ValueKey('connect-panel-${invite.id}'),
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
          : invite.held
              ? l.connectHeldStatus
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
      // Keyed by the invite, as the comparison panels are, so nothing a card
      // holds (a selection in its link, say) moves to its neighbour when one
      // card goes.
      key: ValueKey('connect-card-${invite.id}'),
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
            // ADR 0020: which of my invites are links to a group, named here
            // on my own screen and nowhere else. Discard below revokes it.
            if (invite.mine && invite.gid != null) ...[
              const SizedBox(height: 4),
              Text(
                  l.connectGroupLinkLabel(
                      context.read<ChatService>().groups[invite.gid]?.name ??
                          ''),
                  style: TextStyle(fontSize: 12, color: context.z.accent)),
            ],
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
            if (live && invite.lastFailure != null) ...[
              const SizedBox(height: 4),
              // Why the last round did not happen. "Waiting for them" was
              // the only thing this card ever said, including when the relay
              // had refused every step since the invite was made.
              Text(l.connectLastFailure(invite.lastFailure!),
                  style: TextStyle(fontSize: 12, color: context.z.warn)),
            ],
            // ADR 0024: opened from a link, and nothing sent yet. What
            // connecting sends, and to whom, said before the person says
            // yes — and the yes is this button, not the tap on the link.
            if (live && invite.held) ...[
              const SizedBox(height: 10),
              Text(l.connectHeldBody,
                  style: const TextStyle(fontSize: 13, height: 1.4)),
              const SizedBox(height: 10),
              Align(
                alignment: Alignment.centerLeft,
                child: FilledButton(
                  key: ValueKey('connect-consent-${invite.id}'),
                  onPressed:
                      _busy ? null : () => _run(() => invites.consent(invite)),
                  child: Text(l.connectHeldGo),
                ),
              ),
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

  /// ADR 0020: for a group link opened here, whether going ahead also joins
  /// the group. On unless the person turns it off: the notice above the
  /// digits has said what going ahead means, and this is how they say "a
  /// contact, not the group" instead.
  bool _join = true;

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
    final gid = invite.gid;
    // Watched, for a group link: a demotion landing while this is on screen
    // changes what going ahead will do, and the screen has to say so.
    final chat = gid == null ? null : context.watch<ChatService>();
    final groupName = chat?.groups[gid]?.name ?? '';
    final canAdd = gid != null && chat!.mayIssueGroupList(gid, '');
    // The link's own 24 hours, by the clock the service judges them by: a
    // link answered after them adds nobody, whatever else holds.
    final open = gid != null && chat!.linkStillOpen(invite.run.issuedMs);
    final joining = invite.offersGroup && _join;

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
            // ADR 0020: an invite that also brings me into a group says so
            // HERE, first, before the digits — going ahead below is what
            // lets my bundle reach that group's members, so this is the
            // moment the choice is made. Which group is not known yet: the
            // link says nothing about it, and the group's own invite names
            // it once there is a session to carry it.
            if (invite.offersGroup) ...[
              const SizedBox(height: 12),
              Container(
                key: const ValueKey('connect-group-notice'),
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: context.z.surfaceAlt,
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: context.z.accent),
                ),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    ExcludeSemantics(
                      child: Icon(Icons.group_add_outlined,
                          size: 20, color: context.z.accent),
                    ),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Text(l.connectGroupNotice,
                          style: const TextStyle(fontSize: 13, height: 1.4)),
                    ),
                  ],
                ),
              ),
            ],
            // ADR 0024: an invite of version 1 — made by a client from before
            // invites were bound to their secret — can be answered by the
            // relay itself, so skipping the comparison trusts it too.
            if (invite.unbound) ...[
              const SizedBox(height: 12),
              Text(l.connectOldInvite,
                  key: const ValueKey('connect-old-invite'),
                  style: TextStyle(
                      fontSize: 13, height: 1.4, color: context.z.warn)),
            ],
            // ADR 0012: who actually took the invite, and the bearer-token
            // caveat — the person who accepted may not be who you sent it to.
            const SizedBox(height: 12),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: context.z.surfaceAlt,
                borderRadius: BorderRadius.circular(8),
              ),
              child: Text(l.connectWhoAccepted(peerName),
                  style: const TextStyle(fontSize: 13, height: 1.4)),
            ),
            // ADR 0020, the inviter's side of a group link: which group, and
            // what going ahead will do — join them to it, or make them a
            // contact only, because their client predates group links and
            // could not have told them, or because this device may no
            // longer add members (asked again when their go-ahead lands).
            if (invite.mine && gid != null) ...[
              const SizedBox(height: 12),
              Text(
                !open
                    ? l.connectGroupLinkExpired(groupName)
                    : !invite.joinerKnowsGroup
                        ? l.connectGroupLinkTooOld(groupName)
                        : canAdd
                            ? l.connectGroupLinkGoAhead(groupName)
                            : l.connectGroupLinkNotAdmin(groupName),
                key: const ValueKey('connect-group-link-outcome'),
                style: TextStyle(
                    fontSize: 13,
                    height: 1.4,
                    color: open && invite.joinerKnowsGroup && canAdd
                        ? null
                        : context.z.warn),
              ),
            ],
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
            // ADR 0020: the joiner's choice, beside the buttons it changes —
            // join the group, or connect as a contact only. The inviter is
            // told which, either way.
            if (invite.offersGroup) ...[
              const SizedBox(height: 12),
              SwitchListTile(
                key: const ValueKey('connect-join-group'),
                contentPadding: EdgeInsets.zero,
                title: Text(l.connectJoinGroup),
                subtitle: _join
                    ? null
                    : Text(l.connectJoinGroupOff(peerName),
                        style: TextStyle(
                            fontSize: 12, color: context.z.textSecondary)),
                value: _join,
                onChanged: _busy ? null : (v) => setState(() => _join = v),
              ),
            ],
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
                        final c = await invites.confirm(invite, join: _join);
                        return invite.peerWasHeld
                            ? joining
                                ? l.connectAlreadyContactJoining(c.name)
                                : l.connectAlreadyContact(c.name)
                            : l.connectAdded(c.name);
                      }),
              child: Text(l.connectMatch),
            ),
            const SizedBox(height: 10),
            OutlinedButton(
              onPressed: _busy
                  ? null
                  : () => _finish(() async {
                        final c = await invites.defer(invite, join: _join);
                        return invite.peerWasHeld
                            ? joining
                                ? l.connectAlreadyContactJoining(c.name)
                                : l.connectAlreadyContact(c.name)
                            : l.connectAddedUnverified(c.name);
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

/// ADR 0020: whoever answered a group link this device made, and is still
/// to be added once their go-ahead arrives — named here, on this device
/// only, with a way to stop waiting. Going ahead finishes the invite, so
/// without this the wait it starts could be seen nowhere until it ended.
class ConnectLinkWaits extends StatelessWidget {
  const ConnectLinkWaits({super.key});

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final chat = context.watch<ChatService>();
    final waits = chat.pendingLinkJoins;
    if (waits.isEmpty) return const SizedBox.shrink();
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const Divider(height: 40),
        Text(l.connectLinkWaitsTitle,
            style: const TextStyle(fontWeight: FontWeight.w600)),
        for (final w in waits)
          ListTile(
            key: ValueKey('connect-link-wait-${w.id}'),
            contentPadding: EdgeInsets.zero,
            title: Text(l.connectLinkWait(chat.contacts[w.rid]?.name ?? '',
                chat.groups[w.gid]?.name ?? '')),
            trailing: TextButton(
              onPressed: () async {
                final name = chat.contacts[w.rid]?.name ?? '';
                final group = chat.groups[w.gid]?.name ?? '';
                final messenger = ScaffoldMessenger.of(context);
                // Their answer can have come, and the add begun, since this
                // row was drawn: then it is too late, and that is what the
                // person is told — not nothing.
                if (await chat.cancelLinkJoin(w.id) == LinkWaitStop.adding) {
                  messenger.showSnackBar(SnackBar(
                      content: Text(l.connectLinkWaitTooLate(name, group))));
                }
              },
              child: Text(l.connectLinkWaitStop),
            ),
          ),
      ],
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
