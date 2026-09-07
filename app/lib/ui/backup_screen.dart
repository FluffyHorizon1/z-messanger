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
    final z = context.z;
    final latest = _latest;
    return Scaffold(
      backgroundColor: z.bg,
      appBar: AppBar(title: const Text('Backup')),
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
                        ? 'No backup yet'
                        : 'Last backup ${_when(latest.takenAt)}',
                    style: TextStyle(
                        fontSize: 16,
                        fontWeight: FontWeight.w600,
                        color: z.textPrimary),
                  ),
                  const SizedBox(height: 6),
                  Text(
                    latest == null
                        ? 'Your messages live only on this device. If you lose '
                            'it, they are gone — there is no copy on any server.'
                        : '${_size(latest.bytes)} · kept on this device. Save a '
                            'copy somewhere else so a lost phone does not take '
                            'it with them.',
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
                Text(_stage ?? 'Working…',
                    style: TextStyle(color: z.textSecondary)),
              ]),
            )
          else ...[
            ListTile(
              leading: Icon(Icons.enhanced_encryption, color: z.accent),
              title: const Text('Create a backup'),
              subtitle: const Text(
                  'Every message, contact, group and attachment, encrypted '
                  'with a recovery code only you hold.',
                  style: TextStyle(fontSize: 12)),
              onTap: _createBackup,
            ),
            if (latest != null)
              ListTile(
                leading: const Icon(Icons.save_alt),
                title: const Text('Save a copy…'),
                subtitle: const Text(
                    'Put the latest backup somewhere off this device.',
                    style: TextStyle(fontSize: 12)),
                onTap: () => _saveCopy(latest),
              ),
            SwitchListTile(
              secondary: Icon(Icons.schedule,
                  color: _intervalDays > 0 ? z.accent : z.textSecondary),
              title: const Text('Back up automatically'),
              subtitle: Text(
                  _intervalDays > 0
                      ? 'Every $_intervalDays days, using the recovery code '
                          'you saved. That code is kept on this device to '
                          'make it possible.'
                      : 'Off. Turning it on stores your recovery code on this '
                          'device, so a backup can run without you.',
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
              'A backup restores your history onto a new device. It does not '
              'restore your live conversations — those re-handshake by '
              'themselves the first time you message someone, and the other '
              'person sees nothing unusual.\n\n'
              'The backup never touches the relay. It is encrypted here, on '
              'this device, and only the recovery code opens it. Lose the '
              'code and the file cannot be opened by anyone — there is no '
              'server-side way in, which is the point.',
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
      _stage = 'Preparing…';
    });
    try {
      final backup = await store.write(
        code: code,
        onProgress: (p) {
          if (!mounted) return;
          setState(() => _stage = switch (p.stage) {
                'messages' => 'Packing messages…',
                'attachments' => 'Packing attachments…',
                _ => 'Finishing…',
              });
        },
      );
      if (!mounted) return;
      setState(() {
        _busy = false;
        _stage = null;
        _latest = backup;
      });
      messenger.showSnackBar(const SnackBar(
          content: Text('Backup created. Save a copy somewhere safe.')));
      await _saveCopy(backup);
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _busy = false;
        _stage = null;
      });
      messenger.showSnackBar(SnackBar(content: Text('Backup failed: $e')));
    }
  }

  /// Turning the schedule on needs the code, because an unattended run
  /// cannot ask for one. Asking the user to type it again also means the
  /// stored copy is the code they actually hold, not one they lost.
  Future<void> _toggleSchedule(bool on) async {
    final sched = _sched;
    if (sched == null) return;
    final messenger = ScaffoldMessenger.of(context);
    if (!on) {
      await sched.disable();
      if (!mounted) return;
      setState(() => _intervalDays = 0);
      messenger.showSnackBar(const SnackBar(
          content: Text('Automatic backup off. The stored code was erased.')));
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
      messenger.showSnackBar(const SnackBar(
          content: Text('Z will back up every 7 days with that code.')));
    } on FormatException catch (e) {
      if (!mounted) return;
      messenger.showSnackBar(SnackBar(content: Text(e.message)));
    }
  }

  Future<void> _saveCopy(StoredBackup backup) async {
    final messenger = ScaffoldMessenger.of(context);
    try {
      final path = await BackupStore.handToUser(backup);
      if (path != null) {
        messenger.showSnackBar(const SnackBar(content: Text('Copy saved.')));
      }
    } on SaveTooLargeException {
      // The backup is fine — only the hand-off failed — so say where it is
      // rather than implying the backup did not happen.
      messenger.showSnackBar(SnackBar(
          content: Text('That backup is too large for this device\'s file '
              'picker. It is still saved in the app as ${backup.name}.'),
          duration: const Duration(seconds: 6)));
    } catch (e) {
      messenger.showSnackBar(SnackBar(content: Text('Could not save: $e')));
    }
  }

  static String _size(int b) => b < 1024 * 1024
      ? '${(b / 1024).toStringAsFixed(0)} KB'
      : '${(b / 1024 / 1024).toStringAsFixed(1)} MB';

  static String _when(DateTime t) {
    final d = DateTime.now().difference(t);
    if (d.inMinutes < 1) return 'just now';
    if (d.inHours < 1) return '${d.inMinutes} min ago';
    if (d.inDays < 1) return '${d.inHours} h ago';
    if (d.inDays == 1) return 'yesterday';
    return '${d.inDays} days ago';
  }
}

/// Step one: the code, and what losing it costs.
class _ShowCodeDialog extends StatelessWidget {
  final String code;
  const _ShowCodeDialog({required this.code});

  @override
  Widget build(BuildContext context) {
    final z = context.z;
    return AlertDialog(
      title: const Text('Your recovery code'),
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
            'Write this down and keep it somewhere separate from the backup '
            'file itself. It is the only thing that opens the backup.',
            style: TextStyle(fontSize: 13, color: z.textPrimary),
          ),
          const SizedBox(height: 8),
          Text(
            'Nobody can recover it for you — not us, not the relay, not with '
            'a court order. That is deliberate, and it is the reason nobody '
            'can be compelled to hand over your messages either.',
            style: TextStyle(fontSize: 12, color: z.textSecondary),
          ),
        ],
      ),
      actions: [
        TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('Cancel')),
        TextButton(
          onPressed: () async {
            await Clipboard.setData(ClipboardData(text: code));
            if (context.mounted) {
              ScaffoldMessenger.of(context)
                  .showSnackBar(const SnackBar(content: Text('Code copied')));
            }
          },
          child: const Text('Copy'),
        ),
        FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('I have written it down')),
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
          _error = 'That is a valid code, but not this one.';
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
    final z = context.z;
    return AlertDialog(
      title: const Text('Type it back'),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'So we know it is written down correctly. Capitals, spacing and '
            'dashes do not matter.',
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
            child: const Text('Back')),
        FilledButton(
            onPressed: _checking ? null : _check, child: const Text('Confirm')),
      ],
    );
  }
}

/// Asks for a recovery code the user already has.
class _AskCodeDialog extends StatelessWidget {
  final TextEditingController _ctrl = TextEditingController();
  _AskCodeDialog();

  @override
  Widget build(BuildContext context) => AlertDialog(
        title: const Text('Your recovery code'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
                'Type the code you saved. It is stored on this device so a '
                'backup can run on its own — anyone who can already open this '
                'app could then open your backup files too.',
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
              onPressed: () => Navigator.pop(context),
              child: const Text('Cancel')),
          FilledButton(
              onPressed: () => Navigator.pop(context, _ctrl.text),
              child: const Text('Turn on')),
        ],
      );
}
