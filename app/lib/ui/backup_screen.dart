// The backup and recovery ceremony (9.4).
//
// The honest framing is the feature. There is no server-side copy of
// anything, no account to recover, and nobody to appeal to: if the recovery
// code is lost, the archive is a file nobody can open, including us. That is
// the same property that makes the relay safe to distrust, and the screen
// says so rather than burying it.
//
// Which is why the code has to be confirmed by typing it back. It is a
// minute of friction against permanent, unrecoverable data loss, and the
// parser is forgiving of everything except not having written it down —
// case, spacing, dashes and the classic I/1 and O/0 confusions all pass.

import 'dart:async';

import 'package:flutter/material.dart';

import '../l10n/app_localizations.dart';
import 'package:flutter/services.dart' show Clipboard, ClipboardData;
import 'package:provider/provider.dart';
import 'package:z_protocol/z_protocol.dart';

import '../core/backup_store.dart';
import '../core/chat_service.dart';
import '../core/file_export.dart';
import 'theme.dart';

class BackupScreen extends StatefulWidget {
  const BackupScreen({super.key});

  @override
  State<BackupScreen> createState() => _BackupScreenState();
}

class _BackupScreenState extends State<BackupScreen> {
  BackupStore? _store;
  BackupSchedule? _sched;
  StoredBackup? _latest;
  int _intervalDays = 0;
  bool _busy = false;
  String? _stage;

  @override
  void initState() {
    super.initState();
    unawaited(_load());
  }

  Future<void> _load() async {
    final svc = context.read<ChatService>();
    final store = await BackupStore.open(svc.vault);
    final sched = BackupSchedule(svc.vault);
    final latest = await store.latest();
    final days = await sched.intervalDays();
    if (!mounted) return;
    setState(() {
      _store = store;
      _sched = sched;
      _latest = latest;
      _intervalDays = days;
    });
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final z = context.z;
    final latest = _latest;
    return Scaffold(
      backgroundColor: z.bg,
      appBar: AppBar(title: Text(l.backupTitle)),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Card(
            color: z.surface,
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    latest == null
                        ? l.backupNoneYet
                        : l.backupLastTaken(_when(latest.takenAt, l)),
                    style: TextStyle(
                        fontSize: 16,
                        fontWeight: FontWeight.w600,
                        color: z.textPrimary),
                  ),
                  const SizedBox(height: 6),
                  Text(
                    latest == null
                        ? l.backupNoneBody
                        : l.backupExistsBody(_size(latest.bytes, l)),
                    style: TextStyle(fontSize: 13, color: z.textSecondary),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 8),
          if (_busy)
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 24),
              child: Column(children: [
                const CircularProgressIndicator(),
                const SizedBox(height: 12),
                Text(_stage ?? l.backupWorking,
                    style: TextStyle(color: z.textSecondary)),
              ]),
            )
          else ...[
            ListTile(
              leading: Icon(Icons.enhanced_encryption, color: z.accent),
              title: Text(l.backupCreate),
              subtitle: Text(
                  l.backupCreateHelp,
                  style: TextStyle(fontSize: 12)),
              onTap: _createBackup,
            ),
            if (latest != null)
              ListTile(
                leading: const Icon(Icons.save_alt),
                title: Text(l.backupSaveCopy),
                subtitle: Text(
                    l.backupSaveCopyHelp,
                    style: TextStyle(fontSize: 12)),
                onTap: () => _saveCopy(latest),
              ),
            SwitchListTile(
              secondary: Icon(Icons.schedule,
                  color: _intervalDays > 0 ? z.accent : z.textSecondary),
              title: Text(l.backupAuto),
              subtitle: Text(
                  _intervalDays > 0
                      ? l.backupAutoOnHelp(_intervalDays)
                      : l.backupAutoOffHelp,
                  style: const TextStyle(fontSize: 12)),
              value: _intervalDays > 0,
              activeThumbColor: z.accent,
              onChanged: _busy ? null : _toggleSchedule,
            ),
          ],
          const SizedBox(height: 16),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 8),
            child: Text(
              l.backupFootnote,
              style: TextStyle(fontSize: 12, color: z.textSecondary),
            ),
          ),
        ],
      ),
    );
  }

  // ------------------------------------------------------------------
  // The ceremony
  // ------------------------------------------------------------------

  Future<void> _createBackup() async {
    final l = AppLocalizations.of(context);
    final store = _store;
    if (store == null) return;
    final messenger = ScaffoldMessenger.of(context);

    final code = await RecoveryCode.generate();
    final formatted = await code.format();
    if (!mounted) return;

    // 1. Show it.
    final shown = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => _ShowCodeDialog(code: formatted),
    );
    if (shown != true) return;
    if (!mounted) return;

    // 2. Make them prove they wrote it down. This is the only moment at
    //    which a mistake is still recoverable.
    final confirmed = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => _ConfirmCodeDialog(expected: code),
    );
    if (confirmed != true) return;
    if (!mounted) return;

    // 3. Write it.
    setState(() {
      _busy = true;
      _stage = l.backupPreparing;
    });
    try {
      final backup = await store.write(
        code: code,
        onProgress: (p) {
          if (!mounted) return;
          setState(() => _stage = switch (p.stage) {
                'messages' => l.backupPackingMessages,
                'attachments' => l.backupPackingAttachments,
                _ => l.backupFinishing,
              });
        },
      );
      if (!mounted) return;
      setState(() {
        _busy = false;
        _stage = null;
        _latest = backup;
      });
      messenger.showSnackBar(SnackBar(
content: Text(l.backupCreated)));
      await _saveCopy(backup);
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _busy = false;
        _stage = null;
      });
      messenger.showSnackBar(SnackBar(content: Text(l.backupFailed('$e'))));
    }
  }

  /// Turning the schedule on needs the code, because an unattended run
  /// cannot ask for one. Asking the user to type it again also means the
  /// stored copy is the code they actually hold, not one they lost.
  Future<void> _toggleSchedule(bool on) async {
    final l = AppLocalizations.of(context);
    final sched = _sched;
    if (sched == null) return;
    final messenger = ScaffoldMessenger.of(context);
    if (!on) {
      await sched.disable();
      if (!mounted) return;
      setState(() => _intervalDays = 0);
      messenger.showSnackBar(SnackBar(
content: Text(l.backupAutoOff)));
      return;
    }
    final typed = await showDialog<String>(
      context: context,
      builder: (ctx) => _AskCodeDialog(),
    );
    if (typed == null || typed.isEmpty) return;
    try {
      final code = await RecoveryCode.parse(typed);
      await sched.enable(code: code, everyDays: 7);
      if (!mounted) return;
      setState(() => _intervalDays = 7);
      messenger.showSnackBar(SnackBar(
content: Text(l.backupAutoOn)));
    } on FormatException catch (e) {
      if (!mounted) return;
      messenger.showSnackBar(SnackBar(content: Text(e.message)));
    }
  }

  Future<void> _saveCopy(StoredBackup backup) async {
    final l = AppLocalizations.of(context);
    final messenger = ScaffoldMessenger.of(context);
    try {
      final path = await BackupStore.handToUser(backup);
      if (path != null) {
        messenger.showSnackBar(SnackBar(
content: Text(l.backupCopySaved)));
      }
    } on SaveTooLargeException {
      // The backup is fine — only the hand-off failed — so say where it is
      // rather than implying the backup did not happen.
      messenger.showSnackBar(SnackBar(
          content: Text(l.backupTooLargeForPicker(backup.name)),
          duration: const Duration(seconds: 6)));
    } catch (e) {
      messenger.showSnackBar(SnackBar(content: Text(l.backupSaveFailed('$e'))));
    }
  }

  static String _size(int b, AppLocalizations l) => b < 1024 * 1024
      ? l.sizeKb((b / 1024).toStringAsFixed(0))
      : l.sizeMb((b / 1024 / 1024).toStringAsFixed(1));

  static String _when(DateTime t, AppLocalizations l) {
    final d = DateTime.now().difference(t);
    if (d.inMinutes < 1) return l.timeJustNow;
    if (d.inHours < 1) return l.timeMinutesAgo(d.inMinutes);
    if (d.inDays < 1) return l.timeHoursAgo(d.inHours);
    if (d.inDays == 1) return l.timeYesterday;
    return l.timeDaysAgo(d.inDays);
  }
}

/// Step one: the code, and what losing it costs.
class _ShowCodeDialog extends StatelessWidget {
  final String code;
  const _ShowCodeDialog({required this.code});

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final z = context.z;
    return AlertDialog(
      title: Text(l.backupCodeTitle),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(14),
            decoration: BoxDecoration(
              color: z.surfaceAlt,
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: z.accentDim),
            ),
            child: SelectableText(
              code,
              style: const TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 16,
                  letterSpacing: 1.2,
                  fontWeight: FontWeight.w600),
            ),
          ),
          const SizedBox(height: 14),
          Text(
            l.backupCodeWriteDown,
            style: TextStyle(fontSize: 13, color: z.textPrimary),
          ),
          const SizedBox(height: 8),
          Text(
            l.backupCodeNobodyCan,
            style: TextStyle(fontSize: 12, color: z.textSecondary),
          ),
        ],
      ),
      actions: [
        TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: Text(l.cancel)),
        TextButton(
          onPressed: () async {
            await Clipboard.setData(ClipboardData(text: code));
            if (context.mounted) {
              ScaffoldMessenger.of(context)
                  .showSnackBar(SnackBar(
content: Text(l.codeCopied)));
            }
          },
          child: Text(l.copy),
        ),
        FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: Text(l.backupCodeWritten)),
      ],
    );
  }
}

/// Step two: type it back. Anything else is a promise, not a backup.
class _ConfirmCodeDialog extends StatefulWidget {
  final RecoveryCode expected;
  const _ConfirmCodeDialog({required this.expected});

  @override
  State<_ConfirmCodeDialog> createState() => _ConfirmCodeDialogState();
}

class _ConfirmCodeDialogState extends State<_ConfirmCodeDialog> {
  final _ctrl = TextEditingController();
  String? _error;
  bool _checking = false;

  @override
  void dispose() {
    _ctrl.dispose();
    super.dispose();
  }

  Future<void> _check() async {
    final l = AppLocalizations.of(context);
    setState(() {
      _checking = true;
      _error = null;
    });
    try {
      final typed = await RecoveryCode.parse(_ctrl.text);
      final want = widget.expected.entropy;
      var same = typed.entropy.length == want.length;
      for (var i = 0; i < want.length && same; i++) {
        same = typed.entropy[i] == want[i];
      }
      if (!same) {
        setState(() {
          _checking = false;
          _error = l.backupWrongCode;
        });
        return;
      }
      if (mounted) Navigator.pop(context, true);
    } on FormatException catch (e) {
      setState(() {
        _checking = false;
        _error = e.message;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final z = context.z;
    return AlertDialog(
      title: Text(l.backupConfirmTitle),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            l.backupConfirmBody,
            style: TextStyle(fontSize: 13, color: z.textSecondary),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _ctrl,
            autofocus: true,
            autocorrect: false,
            enableSuggestions: false,
            textCapitalization: TextCapitalization.characters,
            style: const TextStyle(fontFamily: 'monospace'),
            decoration: InputDecoration(
              hintText: 'ZBK-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
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
        FilledButton(
            onPressed: _checking ? null : _check, child: Text(l.confirm)),
      ],
    );
  }
}

/// Asks for a recovery code the user already has.
class _AskCodeDialog extends StatelessWidget {
  final TextEditingController _ctrl = TextEditingController();
  _AskCodeDialog();

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    return AlertDialog(
      title: Text(l.backupAskCodeTitle),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(l.backupAskCodeBody,
              style: TextStyle(fontSize: 13, color: context.z.textSecondary)),
          const SizedBox(height: 12),
          TextField(
            controller: _ctrl,
            autofocus: true,
            autocorrect: false,
            textCapitalization: TextCapitalization.characters,
            style: const TextStyle(fontFamily: 'monospace'),
            decoration: const InputDecoration(
                hintText: 'ZBK-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX'),
            onSubmitted: (v) => Navigator.pop(context, v),
          ),
        ],
      ),
      actions: [
        TextButton(
            onPressed: () => Navigator.pop(context), child: Text(l.cancel)),
        FilledButton(
            onPressed: () => Navigator.pop(context, _ctrl.text),
            child: Text(l.backupAskCodeTurnOn)),
      ],
    );
  }
}
