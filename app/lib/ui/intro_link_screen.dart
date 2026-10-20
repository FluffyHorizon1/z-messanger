// Settings › Your public link (phase 39; ADR 0032 §4; PROTOCOL §21.9).
//
// A public link is the account's introduction mailbox handed out directly —
// on a web page, in an email signature, on a printed card — with no handle
// log between. Made here and nowhere else, never during onboarding, and only
// on the account's main device (v1, as a handle). What the screen has to say
// plainly: what a link lets anyone who has it do, what a request shows
// whoever made it, that a link verifies nothing, and — once one exists — that
// replacing or withdrawing it breaks every copy in silence. Reached only in a
// build with links on (`introLinksEnabled`).

import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show Clipboard, ClipboardData;
import 'package:provider/provider.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:z_protocol/z_protocol.dart' show introLinkDefaultPow;

import '../core/chat_service.dart';
import '../core/handles.dart';
import '../core/intro_links.dart';
import '../l10n/app_localizations.dart';
import '../l10n/handle_text.dart';
import '../l10n/link_text.dart';
import 'theme.dart';

class IntroLinkScreen extends StatefulWidget {
  const IntroLinkScreen({super.key});

  @override
  State<IntroLinkScreen> createState() => _IntroLinkScreenState();
}

class _IntroLinkScreenState extends State<IntroLinkScreen> {
  bool _busy = false;

  /// The work the link about to be made will print.
  int _pow = introLinkDefaultPow;

  /// Run [op] with the screen busy, saying in words why it did not happen.
  Future<void> _run(Future<void> Function() op) async {
    if (_busy) return;
    final messenger = ScaffoldMessenger.of(context);
    final l = AppLocalizations.of(context);
    setState(() => _busy = true);
    try {
      await op();
    } on HandleException catch (e) {
      messenger.showSnackBar(
          SnackBar(content: Text(handleFailureText(l, e.failure))));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<bool> _confirm(String title, String body, String action) async {
    final l = AppLocalizations.of(context);
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(title),
        content: Text(body),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false), child: Text(l.cancel)),
          FilledButton(
              onPressed: () => Navigator.pop(ctx, true), child: Text(action)),
        ],
      ),
    );
    return ok == true;
  }

  /// The work a request costs, from [from] to the most an owner may ask.
  Future<int?> _pickWork(
      {required String title, required String help, required int from,
      required int current}) {
    return showDialog<int>(
      context: context,
      builder: (ctx) => SimpleDialog(
        title: Text(title),
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(24, 0, 24, 8),
            child: Text(help, style: const TextStyle(fontSize: 13, height: 1.4)),
          ),
          RadioGroup<int>(
            groupValue: current,
            onChanged: (v) => Navigator.pop(ctx, v),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                for (final b in introLinkPowLevels)
                  if (b >= from)
                    RadioListTile<int>(
                      value: b,
                      activeColor: context.z.accent,
                      title: Text(handlePowText(AppLocalizations.of(ctx), b)),
                    ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Future<void> _copy(String text, String said) async {
    await Clipboard.setData(ClipboardData(text: text));
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(said)));
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final svc = context.watch<ChatService>();
    final h = svc.handles;
    return Scaffold(
      appBar: AppBar(title: Text(l.plinkYourLink)),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          if (!h.canManageLink)
            _Note(icon: Icons.devices_outlined, text: l.plinkLinkedDevice)
          else ...[
            ..._state(context, l, h),
            if (_busy)
              const Padding(
                padding: EdgeInsets.only(top: 16),
                child: Center(child: CircularProgressIndicator()),
              ),
          ],
        ],
      ),
    );
  }

  List<Widget> _state(BuildContext context, AppLocalizations l, HandleService h) {
    final link = h.link;
    if (link == null) return _none(context, l, h);
    if (link.phase == IntroLinkPhase.held) {
      return [
        _Para(l.plinkHeldBody, warn: true),
        _LinkText(url: link.url),
        _Action(
            icon: Icons.play_circle_outline,
            label: l.plinkUseAgain,
            onTap: _busy ? null : () => _run(h.useLinkAgain)),
        _replace(l, h),
        _withdraw(l, h),
      ];
    }
    return [
      Center(
        child: Semantics(
          label: l.plinkSemQr,
          excludeSemantics: true,
          child: Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: Colors.white,
              borderRadius: BorderRadius.circular(16),
            ),
            child: QrImageView(
                data: link.url, size: 220, backgroundColor: Colors.white),
          ),
        ),
      ),
      const SizedBox(height: 16),
      _LinkText(url: link.url),
      Wrap(
        alignment: WrapAlignment.center,
        spacing: 8,
        children: [
          FilledButton.icon(
            icon: const Icon(Icons.copy),
            label: Text(l.plinkCopy),
            onPressed: () => _copy(link.url, l.plinkCopied),
          ),
          OutlinedButton.icon(
            icon: const Icon(Icons.code),
            label: Text(l.plinkCopyWeb),
            onPressed: () => _copy(link.webAnchor, l.plinkCopiedWeb),
          ),
        ],
      ),
      _Para(l.plinkWebHelp),
      _Para(l.plinkLiveBody),
      _Para(l.plinkNotVerification),
      // The relay's last answer to the link's `intro` (§21.6): when it is not
      // guarding the inbox, say so — and that this phone still counts the
      // work on every request itself.
      if (introLinkRelayGuardText(l, h.linkRelayGuard) case final guard?) ...[
        _Para(guard, warn: true),
        _Para(l.plinkStampsChecked),
      ],
      // What this phone's own checks dropped over the ledger's days: one
      // ledger for the handle and the link, said without naming a door.
      if (h.inboxTally case final t when t.unstamped > 0 || t.copies > 0)
        _Para(l.plinkInboxDrops(t.unstamped, t.copies)),
      if (h.inboxSaturated)
        _Para(l.hdlInboxSaturated(handleStampDayCap), warn: true),
      if (link.askedPow > link.printedPow)
        _Para(l.plinkAskedMore(handlePowText(l, link.printedPow))),
      _Action(
          icon: Icons.speed_outlined,
          label: l.plinkAskMore,
          help: handlePowText(l, link.askedPow),
          onTap: _busy
              ? null
              : () async {
                  final bits = await _pickWork(
                      title: l.plinkAskMore,
                      help: l.plinkAskMoreHelp,
                      from: link.printedPow,
                      current: link.askedPow);
                  if (bits == null || bits == link.askedPow) return;
                  await _run(() => h.askMoreWork(bits));
                }),
      _replace(l, h),
      _withdraw(l, h),
    ];
  }

  Widget _replace(AppLocalizations l, HandleService h) => _Action(
        icon: Icons.autorenew,
        label: l.plinkReplace,
        help: l.plinkReplaceHelp,
        onTap: _busy
            ? null
            : () async {
                if (await _confirm(
                    l.plinkReplace, l.plinkReplaceHelp, l.plinkReplace)) {
                  await _run(h.replaceLink);
                }
              },
      );

  Widget _withdraw(AppLocalizations l, HandleService h) => _Action(
        icon: Icons.link_off,
        label: l.plinkWithdraw,
        danger: true,
        onTap: _busy
            ? null
            : () async {
                if (await _confirm(l.plinkWithdrawConfirmTitle,
                    l.plinkWithdrawConfirmBody, l.plinkWithdraw)) {
                  await _run(h.withdrawLink);
                }
              },
      );

  /// No link yet: what one is, what a request through it shows, and how much
  /// work it asks — then the button. Nothing is sent by making one.
  List<Widget> _none(BuildContext context, AppLocalizations l, HandleService h) {
    return [
      _Para(l.plinkIntro),
      _Para(l.plinkWhatItShows),
      _Action(
          icon: Icons.speed_outlined,
          label: l.hdlDifficulty,
          help: handlePowText(l, _pow),
          onTap: _busy
              ? null
              : () async {
                  final bits = await _pickWork(
                      title: l.hdlDifficulty,
                      help: l.hdlDifficultyHelp,
                      from: introLinkMinPow,
                      current: _pow);
                  if (bits != null && mounted) setState(() => _pow = bits);
                }),
      const SizedBox(height: 8),
      FilledButton.icon(
        icon: const Icon(Icons.add_link),
        label: Text(l.plinkMake),
        onPressed: _busy ? null : () => _run(() => h.makeLink(pow: _pow)),
      ),
    ];
  }
}

/// The link itself, selectable.
class _LinkText extends StatelessWidget {
  final String url;
  const _LinkText({required this.url});

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 8),
        child: SelectableText(url,
            textAlign: TextAlign.center,
            style: TextStyle(
                fontSize: 12,
                fontFamily: 'monospace',
                color: context.z.textSecondary)),
      );
}

class _Para extends StatelessWidget {
  final String text;
  final bool warn;
  const _Para(this.text, {this.warn = false});

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 6),
        child: Text(text,
            style: TextStyle(
                height: 1.45,
                color: warn ? context.z.warn : context.z.textSecondary)),
      );
}

class _Note extends StatelessWidget {
  final IconData icon;
  final String text;
  const _Note({required this.icon, required this.text});

  @override
  Widget build(BuildContext context) => Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(icon, color: context.z.textSecondary),
          const SizedBox(width: 12),
          Expanded(child: Text(text, style: const TextStyle(height: 1.45))),
        ],
      );
}

class _Action extends StatelessWidget {
  final IconData icon;
  final String label;
  final String? help;
  final bool danger;
  final VoidCallback? onTap;
  const _Action(
      {required this.icon,
      required this.label,
      this.help,
      this.danger = false,
      required this.onTap});

  @override
  Widget build(BuildContext context) {
    final color = danger ? context.z.danger : null;
    return ListTile(
      contentPadding: EdgeInsets.zero,
      leading: Icon(icon, color: color),
      title: Text(label, style: TextStyle(color: color)),
      subtitle: help == null
          ? null
          : Text(help!, style: const TextStyle(fontSize: 12)),
      enabled: onTap != null,
      onTap: onTap,
    );
  }
}
