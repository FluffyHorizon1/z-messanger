// Settings › Your handle (phase 38; ADR 0015 revision 2; PROTOCOL §21).
//
// Claiming a handle is offered here and nowhere else — never during
// onboarding (F5): a claim made the moment an account is created would tie
// the two together by their timing. What the screen has to say plainly, in
// order: whether handles exist at all in this build (no handle service is
// configured until one is deployed), whether this device can hold one (only
// the account's main device, in v1), what a handle makes public, and — once
// one is claimed — that the recovery code is shown once and is the stronger
// secret, and that finding someone by a handle verifies nothing.

import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show Clipboard, ClipboardData;
import 'package:provider/provider.dart';
import 'package:z_protocol/z_protocol.dart';

import '../core/chat_service.dart';
import '../core/handles.dart';
import '../l10n/app_localizations.dart';
import '../l10n/handle_text.dart';
import 'theme.dart';

class HandleScreen extends StatefulWidget {
  const HandleScreen({super.key});

  @override
  State<HandleScreen> createState() => _HandleScreenState();
}

class _HandleScreenState extends State<HandleScreen> {
  bool _busy = false;

  /// The claim form is open.
  bool _claiming = false;
  final _nick = TextEditingController();
  final _digits = TextEditingController();
  bool _chooseDigits = false;

  /// The handle last checked, and whether it was free.
  Handle? _checked;
  bool? _free;
  bool _noneFree = false;

  @override
  void initState() {
    super.initState();
    final h = context.read<ChatService>().handles;
    // Read the handle back from the log: its version, its difficulty, and
    // whether it is still this device's to manage.
    if (h.available && h.canManage && h.own != null) unawaited(h.refresh());
  }

  @override
  void dispose() {
    _nick.dispose();
    _digits.dispose();
    super.dispose();
  }

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
    } on HandleFormatException catch (e) {
      messenger.showSnackBar(SnackBar(
          content: Text(
              handleProblemText(l, e.problem, character: e.character))));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  /// What is wrong with the form as typed, or null.
  String? _formProblem(AppLocalizations l) {
    final nick = _nick.text.trim();
    if (nick.isEmpty) return null;
    // Random digits are always two valid ones, so the name alone is judged
    // with a stand-in for them.
    final digits = _chooseDigits ? _digits.text.trim() : '00';
    if (_chooseDigits && digits.isEmpty) return null;
    try {
      Handle.parse('$nick.$digits');
      return null;
    } on HandleFormatException catch (e) {
      return handleProblemText(l, e.problem, character: e.character);
    }
  }

  Future<void> _check() => _run(() async {
        final h = context.read<ChatService>().handles;
        setState(() {
          _checked = null;
          _free = null;
          _noneFree = false;
        });
        if (_chooseDigits) {
          final handle =
              Handle.parse('${_nick.text.trim()}.${_digits.text.trim()}');
          final free = await h.isAvailable(handle);
          if (!mounted) return;
          setState(() {
            _checked = handle;
            _free = free;
          });
        } else {
          final found = await h.availableWithRandomDigits(
              normaliseHandleInput(_nick.text));
          if (!mounted) return;
          setState(() {
            _checked = found;
            _free = found != null;
            _noneFree = found == null;
          });
        }
      });

  Future<void> _otherDigits() async {
    setState(() => _chooseDigits = false);
    await _check();
  }

  /// The claim itself: the code shown once, typed back, and only then kept.
  Future<void> _claim(Handle handle) => _run(() async {
        final h = context.read<ChatService>().handles;
        final draft = await h.prepareClaim(handle);
        if (!mounted) return;
        if (!await _showCodeOnce(draft.handle, draft.code, draft.recoveryCode)) {
          return; // nothing was kept: the draft goes with this frame
        }
        await h.commitClaim(draft);
        if (!mounted) return;
        setState(() {
          _claiming = false;
          _checked = null;
          _free = null;
        });
      });

  /// Show [code] once, then have it typed back. False if the person backed
  /// out at either step.
  Future<bool> _showCodeOnce(
      Handle handle, String code, RecoveryCode expected) async {
    final shown = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => _ShowCodeDialog(handle: handle, code: code),
    );
    if (shown != true || !mounted) return false;
    final confirmed = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => _ConfirmCodeDialog(expected: expected),
    );
    return confirmed == true;
  }

  Future<void> _recover({String? handle}) async {
    final l = AppLocalizations.of(context);
    final input = await showDialog<(String, String)>(
      context: context,
      builder: (ctx) => _RecoverDialog(initialHandle: handle),
    );
    if (input == null || !mounted) return;
    await _run(() async {
      final h = context.read<ChatService>().handles;
      final draft = await h.prepareRecover(input.$1, input.$2);
      if (!mounted) return;
      if (!await _showCodeOnce(draft.handle, draft.code, draft.recoveryCode)) {
        return;
      }
      await h.commitRecover(draft);
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(l.hdlRecovered(draft.handle.canonical))));
    });
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

  Future<void> _difficulty(HandleService h) async {
    final l = AppLocalizations.of(context);
    final current = h.own?.pow ?? handleDefaultPow;
    final bits = await showDialog<int>(
      context: context,
      builder: (ctx) => SimpleDialog(
        title: Text(l.hdlDifficulty),
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(24, 0, 24, 8),
            child: Text(l.hdlDifficultyHelp,
                style: const TextStyle(fontSize: 13, height: 1.4)),
          ),
          RadioGroup<int>(
            groupValue: current,
            onChanged: (v) => Navigator.pop(ctx, v),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                for (final b in handlePowLevels)
                  RadioListTile<int>(
                    value: b,
                    activeColor: context.z.accent,
                    title: Text(handlePowText(l, b)),
                  ),
              ],
            ),
          ),
        ],
      ),
    );
    if (bits == null || bits == current) return;
    await _run(() => h.setDifficulty(bits));
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final svc = context.watch<ChatService>();
    final h = svc.handles;
    return Scaffold(
      appBar: AppBar(title: Text(l.hdlTitle)),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          if (!h.available)
            _Note(icon: Icons.info_outline, text: l.hdlUnavailable)
          else if (!h.canManage)
            _Note(icon: Icons.devices_outlined, text: l.hdlLinkedDevice)
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
    final o = h.own;
    if (o == null) return _none(context, l, h);
    final name = o.handle;
    final problem = handleStoredProblemText(l, o.problem);
    return switch (o.phase) {
      HandlePhase.pending => [
          _Name(handle: name),
          _Para(l.hdlPendingBody(name.canonical,
              ((o.publishAt ?? h.now()) - h.now()).clamp(0, 1 << 31) ~/ 60000)),
          _Para(l.hdlPendingWhy),
          if (problem != null) _Para(problem, warn: true),
          _Action(
              icon: Icons.close,
              label: l.hdlCancelClaim,
              onTap: _busy ? null : () => _run(h.cancelClaim)),
        ],
      HandlePhase.held => [
          _Name(handle: name),
          _Para(l.hdlHeldBody),
          if (problem != null) _Para(problem, warn: true),
          _Action(
              icon: Icons.publish_outlined,
              label: l.hdlPublishNow,
              onTap: _busy ? null : () => _run(h.publishHeld)),
          _Action(
              icon: Icons.close,
              label: l.hdlCancelClaim,
              onTap: _busy ? null : () => _run(h.cancelClaim)),
        ],
      HandlePhase.taken => [
          _Name(handle: name),
          _Para(l.hdlTakenBody(name.canonical), warn: true),
          _Action(
              icon: Icons.casino_outlined,
              label: l.hdlChooseOther,
              onTap: _busy
                  ? null
                  : () async {
                      _nick.text = name.nick;
                      await _run(h.cancelClaim);
                      if (!mounted) return;
                      setState(() => _claiming = true);
                      await _otherDigits();
                    }),
          _Action(
              icon: Icons.close,
              label: l.hdlDismiss,
              onTap: _busy ? null : () => _run(h.cancelClaim)),
        ],
      HandlePhase.live => [
          _Name(handle: name, copyable: true),
          _Para(l.hdlLiveBody),
          _Para(l.hdlNotVerification),
          if (h.relayUnguarded) _Para(l.hdlRelayUnguarded, warn: true),
          if (problem != null) _Para(problem, warn: true),
          _Action(
              icon: Icons.pause_circle_outline,
              label: l.hdlPause,
              help: l.hdlPauseHelp,
              onTap: _busy ? null : () => _run(h.pause)),
          _Action(
              icon: Icons.autorenew,
              label: l.hdlRotate,
              help: l.hdlRotateHelp,
              onTap: _busy
                  ? null
                  : () async {
                      if (await _confirm(l.hdlRotate, l.hdlRotateHelp, l.hdlRotate)) {
                        await _run(h.rotate);
                      }
                    }),
          _Action(
              icon: Icons.speed_outlined,
              label: l.hdlDifficulty,
              help: handlePowText(l, o.pow),
              onTap: _busy ? null : () => _difficulty(h)),
          _retire(l, h, o),
        ],
      HandlePhase.paused => [
          _Name(handle: name, copyable: true),
          _Para(l.hdlPausedBody),
          if (problem != null) _Para(problem, warn: true),
          _Action(
              icon: Icons.play_circle_outline,
              label: l.hdlResume,
              onTap: _busy ? null : () => _run(h.resume)),
          _retire(l, h, o),
        ],
      HandlePhase.lost => [
          _Name(handle: name),
          _Para(l.hdlLostBody(name.canonical), warn: true),
          _Action(
              icon: Icons.key_outlined,
              label: l.hdlRecover,
              onTap: _busy ? null : () => _recover(handle: name.canonical)),
          _Action(
              icon: Icons.close,
              label: l.hdlForget,
              onTap: _busy ? null : () => _run(h.forgetLost)),
        ],
    };
  }

  Widget _retire(AppLocalizations l, HandleService h, OwnHandle o) => _Action(
        icon: Icons.delete_outline,
        label: l.hdlRetire,
        danger: true,
        onTap: _busy
            ? null
            : () async {
                if (await _confirm(l.hdlRetireConfirmTitle(o.handle.canonical),
                    l.hdlRetireConfirmBody, l.hdlRetire)) {
                  await _run(h.retire);
                }
              },
      );

  /// No handle yet: what one is, what it makes public, and the form.
  List<Widget> _none(BuildContext context, AppLocalizations l, HandleService h) {
    final problem = _formProblem(l);
    final checked = _checked;
    return [
      _Para(l.hdlIntro),
      _Para(l.hdlWhatItShows),
      if (!_claiming) ...[
        _Action(
            icon: Icons.alternate_email,
            label: l.hdlClaim,
            onTap: _busy ? null : () => setState(() => _claiming = true)),
        _Action(
            icon: Icons.key_outlined,
            label: l.hdlRecover,
            onTap: _busy ? null : () => _recover()),
      ] else ...[
        const SizedBox(height: 8),
        TextField(
          controller: _nick,
          autofocus: true,
          autocorrect: false,
          enableSuggestions: false,
          decoration: InputDecoration(
            labelText: l.hdlNickLabel,
            helperText: l.hdlNickHelp,
            errorText: problem,
          ),
          onChanged: (_) => setState(() {
            _checked = null;
            _free = null;
            _noneFree = false;
          }),
        ),
        const SizedBox(height: 12),
        SegmentedButton<bool>(
          showSelectedIcon: false,
          segments: [
            ButtonSegment(value: false, label: Text(l.hdlDigitsRandom)),
            ButtonSegment(value: true, label: Text(l.hdlDigitsChoose)),
          ],
          selected: {_chooseDigits},
          onSelectionChanged: (s) => setState(() {
            _chooseDigits = s.first;
            _checked = null;
            _free = null;
          }),
        ),
        if (_chooseDigits) ...[
          const SizedBox(height: 12),
          TextField(
            controller: _digits,
            keyboardType: TextInputType.number,
            decoration: InputDecoration(labelText: l.hdlDigitsLabel),
            onChanged: (_) => setState(() {
              _checked = null;
              _free = null;
            }),
          ),
        ],
        const SizedBox(height: 12),
        FilledButton(
          onPressed: _busy ||
                  problem != null ||
                  _nick.text.trim().isEmpty ||
                  (_chooseDigits && _digits.text.trim().isEmpty)
              ? null
              : _check,
          child: Text(l.hdlCheck),
        ),
        if (_noneFree) _Para(l.hdlNoneFree, warn: true),
        if (checked != null && _free == true) ...[
          _Para(l.hdlAvailable(checked.canonical)),
          FilledButton(
            onPressed: _busy ? null : () => _claim(checked),
            child: Text(l.hdlClaimThis(checked.canonical)),
          ),
        ],
        if (checked != null && _free == false) ...[
          _Para(l.hdlTaken(checked.canonical), warn: true),
          OutlinedButton(
            onPressed: _busy ? null : _otherDigits,
            child: Text(l.hdlTryOtherDigits),
          ),
        ],
      ],
    ];
  }
}

/// The handle itself, large; copyable once it is published.
class _Name extends StatelessWidget {
  final Handle handle;
  final bool copyable;
  const _Name({required this.handle, this.copyable = false});

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        children: [
          Expanded(
            child: Semantics(
              label: l.hdlSemHandle(handle.canonical),
              excludeSemantics: true,
              child: SelectableText(handle.display,
                  style: const TextStyle(
                      fontSize: 24, fontWeight: FontWeight.w700)),
            ),
          ),
          if (copyable)
            IconButton(
              icon: const Icon(Icons.copy),
              tooltip: l.hdlCopy,
              onPressed: () async {
                await Clipboard.setData(ClipboardData(text: handle.display));
                if (!context.mounted) return;
                ScaffoldMessenger.of(context)
                    .showSnackBar(SnackBar(content: Text(l.hdlCopied)));
              },
            ),
        ],
      ),
    );
  }
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

/// The code, once. The same ceremony as a backup's code (`backup_screen.dart`):
/// shown, then typed back.
class _ShowCodeDialog extends StatelessWidget {
  final Handle handle;
  final String code;
  const _ShowCodeDialog({required this.handle, required this.code});

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    return AlertDialog(
      title: Text(l.hdlCodeTitle),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(l.hdlCodeBody(handle.canonical),
              style: const TextStyle(fontSize: 13, height: 1.4)),
          const SizedBox(height: 16),
          Semantics(
            label: l.hdlSemCode,
            child: SelectableText(code,
                style: const TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 16,
                    fontWeight: FontWeight.w600)),
          ),
        ],
      ),
      actions: [
        TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: Text(l.cancel)),
        FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: Text(l.hdlCodeWritten)),
      ],
    );
  }
}

class _ConfirmCodeDialog extends StatefulWidget {
  final RecoveryCode expected;
  const _ConfirmCodeDialog({required this.expected});

  @override
  State<_ConfirmCodeDialog> createState() => _ConfirmCodeDialogState();
}

class _ConfirmCodeDialogState extends State<_ConfirmCodeDialog> {
  final _ctrl = TextEditingController();
  String? _error;

  @override
  void dispose() {
    _ctrl.dispose();
    super.dispose();
  }

  Future<void> _check() async {
    final l = AppLocalizations.of(context);
    try {
      final typed = await parseHandleRecoveryCode(_ctrl.text);
      if (!constantTimeEquals(typed.entropy, widget.expected.entropy)) {
        setState(() => _error = l.hdlCodeWrong);
        return;
      }
      if (mounted) Navigator.pop(context, true);
    } on FormatException {
      setState(() => _error = l.hdlCodeWrong);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    return AlertDialog(
      title: Text(l.hdlCodeConfirmTitle),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(l.hdlCodeConfirmBody,
              style: TextStyle(fontSize: 13, color: context.z.textSecondary)),
          const SizedBox(height: 12),
          TextField(
            controller: _ctrl,
            autofocus: true,
            autocorrect: false,
            enableSuggestions: false,
            textCapitalization: TextCapitalization.characters,
            style: const TextStyle(fontFamily: 'monospace'),
            decoration: InputDecoration(
              labelText: l.hdlCodeLabel,
              errorText: _error,
            ),
            onSubmitted: (_) => _check(),
          ),
        ],
      ),
      actions: [
        TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: Text(l.back)),
        FilledButton(onPressed: _check, child: Text(l.confirm)),
      ],
    );
  }
}

/// The handle and the code a recovery needs.
class _RecoverDialog extends StatefulWidget {
  final String? initialHandle;
  const _RecoverDialog({this.initialHandle});

  @override
  State<_RecoverDialog> createState() => _RecoverDialogState();
}

class _RecoverDialogState extends State<_RecoverDialog> {
  late final _handle = TextEditingController(text: widget.initialHandle ?? '');
  final _code = TextEditingController();

  @override
  void dispose() {
    _handle.dispose();
    _code.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    return AlertDialog(
      title: Text(l.hdlRecoverTitle),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(l.hdlRecoverBody,
                style: TextStyle(fontSize: 13, color: context.z.textSecondary)),
            const SizedBox(height: 12),
            TextField(
              controller: _handle,
              autofocus: widget.initialHandle == null,
              autocorrect: false,
              enableSuggestions: false,
              decoration: InputDecoration(labelText: l.hdlHandleLabel),
            ),
            const SizedBox(height: 8),
            TextField(
              controller: _code,
              autocorrect: false,
              enableSuggestions: false,
              textCapitalization: TextCapitalization.characters,
              style: const TextStyle(fontFamily: 'monospace'),
              decoration: InputDecoration(labelText: l.hdlCodeLabel),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(
            onPressed: () => Navigator.pop(context), child: Text(l.cancel)),
        FilledButton(
            onPressed: () =>
                Navigator.pop(context, (_handle.text, _code.text)),
            child: Text(l.hdlRecoverAction)),
      ],
    );
  }
}
