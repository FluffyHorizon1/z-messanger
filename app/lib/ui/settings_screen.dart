import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../core/backup.dart';
import '../core/chat_service.dart';
import '../core/models.dart';
import '../core/transport.dart';
import 'theme.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  @override
  Widget build(BuildContext context) {
    final svc = context.watch<ChatService>();
    final transport = context.watch<Transport>();

    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: ListView(
        children: [
          const _SectionHeader('Profile'),
          ListTile(
            leading: const Icon(Icons.badge_outlined),
            title: const Text('Display name'),
            subtitle: Text(svc.displayName),
            onTap: () async {
              final ctrl = TextEditingController(text: svc.displayName);
              final name = await showDialog<String>(
                context: context,
                builder: (ctx) => AlertDialog(
                  title: const Text('Display name'),
                  content: TextField(controller: ctrl, autofocus: true),
                  actions: [
                    TextButton(
                        onPressed: () => Navigator.pop(ctx),
                        child: const Text('Cancel')),
                    FilledButton(
                        onPressed: () => Navigator.pop(ctx, ctrl.text.trim()),
                        child: const Text('Save')),
                  ],
                ),
              );
              if (name != null && name.isNotEmpty) {
                await svc.setDisplayName(name);
                if (context.mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
                      content: Text(
                          'Saved. Share a fresh contact code so new contacts see it.')));
                }
              }
            },
          ),
          const _SectionHeader('Relay'),
          ListTile(
            leading: Icon(
              Icons.cloud_outlined,
              color: transport.status == LinkStatus.connected
                  ? ZTheme.ok
                  : ZTheme.textSecondary,
            ),
            title: const Text('Relay server'),
            subtitle: Text(
              '${transport.serverUrl}\n'
              '${switch (transport.status) {
                LinkStatus.connected => 'connected — zero-knowledge link up',
                LinkStatus.connecting => 'connecting…',
                LinkStatus.disconnected =>
                  'offline${transport.lastError != null ? ' (${transport.lastError})' : ''}',
              }}',
              style: const TextStyle(fontSize: 12),
            ),
            isThreeLine: true,
            onTap: () async {
              final ctrl = TextEditingController(text: transport.serverUrl);
              final url = await showDialog<String>(
                context: context,
                builder: (ctx) => AlertDialog(
                  title: const Text('Relay server URL'),
                  content: TextField(
                    controller: ctrl,
                    autofocus: true,
                    decoration:
                        const InputDecoration(hintText: 'wss://relay.example.com'),
                  ),
                  actions: [
                    TextButton(
                        onPressed: () => Navigator.pop(ctx),
                        child: const Text('Cancel')),
                    FilledButton(
                        onPressed: () => Navigator.pop(ctx, ctrl.text.trim()),
                        child: const Text('Connect')),
                  ],
                ),
              );
              if (url != null && url.isNotEmpty) {
                await svc.setServerUrl(url);
              }
            },
          ),
          const _SectionHeader('Security'),
          if (svc.vault.usedFallbackKeyStore)
            const ListTile(
              leading: Icon(Icons.warning_amber, color: ZTheme.accent),
              title: Text('OS keystore unavailable'),
              subtitle: Text(
                'The vault key is stored in a restricted file instead of the '
                'system keychain. Install/enable a keyring (e.g. GNOME '
                'Keyring / KWallet on Linux) and re-create your identity for '
                'hardware-backed protection.',
                style: TextStyle(fontSize: 12),
              ),
            ),
          const ListTile(
            leading: Icon(Icons.storage_outlined),
            title: Text('Where your messages live'),
            subtitle: Text(
              'Only in this device\'s encrypted vault (XChaCha20-Poly1305, '
              'key in the OS keystore). The relay holds ciphertext in RAM '
              'only until delivery, never on disk.',
              style: TextStyle(fontSize: 12),
            ),
          ),
          ListTile(
            leading: Icon(
              svc.vault.hasPassphrase ? Icons.password : Icons.password_outlined,
              color: svc.vault.hasPassphrase ? ZTheme.ok : ZTheme.textSecondary,
            ),
            title: Text(svc.vault.hasPassphrase
                ? 'App passphrase — on'
                : 'App passphrase — off'),
            subtitle: Text(
              svc.vault.hasPassphrase
                  ? 'This device asks for your passphrase on launch. Tap to change or remove it.'
                  : 'Add a passphrase that unlocks the app on this device. Combined with the device keystore; never sent anywhere.',
              style: const TextStyle(fontSize: 12),
            ),
            onTap: () => _managePassphrase(context, svc),
          ),
          ListTile(
            leading: const Icon(Icons.save_alt),
            title: const Text('Export identity backup (.zid)'),
            subtitle: const Text(
                'Identity keys + contact list, passphrase-encrypted. No messages.',
                style: TextStyle(fontSize: 12)),
            onTap: () => _exportBackup(context, svc),
          ),
          const _SectionHeader('Danger zone'),
          ListTile(
            leading: const Icon(Icons.delete_forever, color: ZTheme.danger),
            title: const Text('Wipe everything',
                style: TextStyle(color: ZTheme.danger)),
            subtitle: const Text(
                'Destroys identity, contacts, messages and keys on this device.',
                style: TextStyle(fontSize: 12)),
            onTap: () => _wipe(context, svc),
          ),
          const SizedBox(height: 24),
          const Center(
            child: Text(
              'Z 1.0.0 — zero-trust messenger\n'
              'No accounts · No analytics · No server storage',
              textAlign: TextAlign.center,
              style: TextStyle(color: ZTheme.textSecondary, fontSize: 12),
            ),
          ),
          const SizedBox(height: 24),
        ],
      ),
    );
  }

  Future<void> _exportBackup(BuildContext context, ChatService svc) async {
    final messenger = ScaffoldMessenger.of(context);
    final pass = await _newPassphrase(context);
    if (pass == null) return;
    final records = <Map<String, Object?>>[
      for (final c in svc.contacts.values)
        {
          'bundle': c.bundle.toJson(),
          'name': c.name,
          'ttl': c.ttlSec,
          'verified': c.verified,
        }
    ];
    final bytes = await BackupFile.export(
      identity: svc.identity,
      displayName: svc.displayName,
      contactRecords: records,
      passphrase: pass,
    );
    final path = await FilePicker.platform.saveFile(
      dialogTitle: 'Save identity backup',
      fileName: 'my-identity.zid',
      bytes: bytes,
    );
    if (path != null && !Platform.isAndroid) {
      await File(path).writeAsBytes(bytes, flush: true);
    }
    if (path != null) {
      messenger.showSnackBar(const SnackBar(
          content: Text('Backup saved. Store it somewhere safe.')));
    }
  }

  Future<String?> _newPassphrase(BuildContext context) async {
    final a = TextEditingController();
    final b = TextEditingController();
    String? error;
    return showDialog<String>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setState) => AlertDialog(
          title: const Text('Backup passphrase'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: a,
                obscureText: true,
                autofocus: true,
                decoration: const InputDecoration(
                    labelText: 'Passphrase (12+ characters)'),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: b,
                obscureText: true,
                decoration: const InputDecoration(labelText: 'Repeat'),
              ),
              if (error != null)
                Padding(
                  padding: const EdgeInsets.only(top: 12),
                  child: Text(error!,
                      style: const TextStyle(color: ZTheme.danger)),
                ),
            ],
          ),
          actions: [
            TextButton(
                onPressed: () => Navigator.pop(ctx),
                child: const Text('Cancel')),
            FilledButton(
              onPressed: () {
                if (a.text.length < 12) {
                  setState(() => error = 'Use at least 12 characters.');
                } else if (a.text != b.text) {
                  setState(() => error = 'Passphrases do not match.');
                } else {
                  Navigator.pop(ctx, a.text);
                }
              },
              child: const Text('Encrypt & save'),
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _managePassphrase(BuildContext context, ChatService svc) async {
    final messenger = ScaffoldMessenger.of(context);
    if (!svc.vault.hasPassphrase) {
      final pass = await _newPassphrase(context);
      if (pass == null) return;
      await svc.vault.setPassphrase(pass);
      if (mounted) setState(() {});
      messenger.showSnackBar(const SnackBar(
          content: Text('Passphrase set. You\'ll be asked for it next launch.')));
      return;
    }
    // Already set: offer change or remove.
    if (!context.mounted) return;
    final action = await showModalBottomSheet<String>(
      context: context,
      backgroundColor: ZTheme.surface,
      builder: (ctx) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: const Icon(Icons.edit_outlined, color: ZTheme.accent),
              title: const Text('Change passphrase'),
              onTap: () => Navigator.pop(ctx, 'change'),
            ),
            ListTile(
              leading: const Icon(Icons.lock_open, color: ZTheme.danger),
              title: const Text('Remove passphrase'),
              onTap: () => Navigator.pop(ctx, 'remove'),
            ),
          ],
        ),
      ),
    );
    if (action == null || !context.mounted) return;

    final current = await _askSecret(context, 'Enter current passphrase');
    if (current == null) return;
    if (!await svc.vault.verifyPassphrase(current)) {
      messenger.showSnackBar(
          const SnackBar(content: Text('Incorrect passphrase.')));
      return;
    }

    if (action == 'change') {
      if (!context.mounted) return;
      final next = await _newPassphrase(context);
      if (next == null) return;
      await svc.vault.setPassphrase(next);
      if (mounted) setState(() {});
      messenger.showSnackBar(
          const SnackBar(content: Text('Passphrase changed.')));
    } else {
      await svc.vault.removePassphrase();
      if (mounted) setState(() {});
      messenger.showSnackBar(const SnackBar(
          content: Text('Passphrase removed. The app opens automatically now.')));
    }
  }

  Future<String?> _askSecret(BuildContext context, String label) {
    final ctrl = TextEditingController();
    return showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(label),
        content: TextField(
          controller: ctrl,
          obscureText: true,
          autofocus: true,
          decoration: const InputDecoration(hintText: 'Passphrase'),
          onSubmitted: (v) => Navigator.pop(ctx, v),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
          FilledButton(
              onPressed: () => Navigator.pop(ctx, ctrl.text),
              child: const Text('OK')),
        ],
      ),
    );
  }

  Future<void> _wipe(BuildContext context, ChatService svc) async {
    final sure = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Wipe everything?'),
        content: const Text(
            'Your identity, contacts, messages and attachments will be '
            'destroyed on this device. Without a .zid backup your identity is '
            'unrecoverable — no server has a copy.'),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Cancel')),
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: ZTheme.danger),
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('Wipe'),
          ),
        ],
      ),
    );
    if (sure == true) {
      await svc.wipeEverything();
      exit(0); // relaunch lands on onboarding with a clean vault
    }
  }
}

class _SectionHeader extends StatelessWidget {
  final String text;
  const _SectionHeader(this.text);

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 20, 16, 4),
      child: Text(
        text.toUpperCase(),
        style: const TextStyle(
          fontSize: 11,
          letterSpacing: 1.2,
          color: ZTheme.accent,
          fontWeight: FontWeight.w700,
        ),
      ),
    );
  }
}
