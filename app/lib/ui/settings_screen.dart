import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../core/app_lock.dart';
import '../core/backup.dart';
import '../core/chat_service.dart';
import '../core/models.dart';
import '../core/prefs.dart';
import '../core/push_service.dart';
import '../core/transport.dart';
import '../core/vault.dart';
import 'link_device_screen.dart';
import 'theme.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  // Whether the OS prompt exists here (false on Linux, or a device with no
  // biometrics and no PIN): decides whether the app-lock rows are shown.
  bool _lockAvailable = false;
  // Whether this device can seal the pass key under a hardware key that
  // only the authenticated user can operate (7.8b, Android).
  bool _boundAvailable = false;

  @override
  void initState() {
    super.initState();
    final lock = context.read<AppLock>();
    lock.available.then((v) {
      if (mounted) setState(() => _lockAvailable = v);
    });
    lock.boundAvailable.then((v) {
      if (mounted) setState(() => _boundAvailable = v);
    });
  }

  String _biometricUnlockCopy(AppLock lock) {
    const lead = 'Open the vault with your fingerprint or face instead of '
        'typing the passphrase. ';
    final boundNow = lock.settings.biometricUnlock
        ? lock.biometricUnlockBound
        : _boundAvailable;
    if (boundNow) {
      return '${lead}The key that opens it is sealed by this device\'s '
          'secure hardware and can only be used right after the system '
          'prompt — copying the app\'s data does not reveal it. Re-enrolling '
          'a fingerprint or face resets it.';
    }
    return '${lead}While this is on, a key derived from your passphrase '
        '(never the passphrase itself) sits in this device\'s keystore — so '
        'on THIS device, someone who can break into the keystore no longer '
        'needs your passphrase. Turning it off deletes that key.';
  }

  @override
  Widget build(BuildContext context) {
    final svc = context.watch<ChatService>();
    final transport = context.watch<Transport>();
    final push = context.watch<PushService>();
    final lock = context.watch<AppLock>();
    final prefs = context.watch<AppPrefs>();

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
          const _SectionHeader('Appearance'),
          ListTile(
            leading: Icon(switch (prefs.themeMode) {
              ThemeMode.light => Icons.light_mode_outlined,
              ThemeMode.dark => Icons.dark_mode_outlined,
              ThemeMode.system => Icons.brightness_auto_outlined,
            }),
            title: const Text('Theme'),
            subtitle: Padding(
              padding: const EdgeInsets.only(top: 8),
              child: SegmentedButton<ThemeMode>(
                showSelectedIcon: false,
                segments: const [
                  ButtonSegment(value: ThemeMode.system, label: Text('System')),
                  ButtonSegment(value: ThemeMode.light, label: Text('Light')),
                  ButtonSegment(value: ThemeMode.dark, label: Text('Dark')),
                ],
                selected: {prefs.themeMode},
                onSelectionChanged: (s) => prefs.setThemeMode(s.first),
              ),
            ),
          ),
          const _SectionHeader('Connection'),
          ListTile(
            leading: Icon(
              Icons.cloud_outlined,
              color: transport.status == LinkStatus.connected
                  ? context.z.ok
                  : context.z.textSecondary,
            ),
            title: const Text('Relay'),
            subtitle: Text(
              switch (transport.status) {
                LinkStatus.connected => 'Connected — zero-knowledge link up',
                LinkStatus.connecting => 'Connecting…',
                LinkStatus.disconnected =>
                  'Offline${transport.lastError != null ? ' (${transport.lastError})' : ''}',
              },
              style: const TextStyle(fontSize: 12),
            ),
          ),
          const _SectionHeader('Devices'),
          ListTile(
            leading: const Icon(Icons.devices_outlined),
            title: const Text('Linked devices'),
            subtitle: const Text(
              'See the devices on your account, link a new one, or revoke one '
              'you no longer use.',
              style: TextStyle(fontSize: 12),
            ),
            onTap: () => Navigator.of(context).push(
                MaterialPageRoute(builder: (_) => const LinkedDevicesScreen())),
          ),
          if (push.supported) ...[
            const _SectionHeader('Notifications'),
            SwitchListTile(
              secondary: Icon(
                push.enabled
                    ? Icons.notifications_active_outlined
                    : Icons.notifications_off_outlined,
                color: push.enabled ? context.z.ok : context.z.textSecondary,
              ),
              title: const Text('Push notifications'),
              subtitle: const Text(
                'Wake this device when a message arrives while Z is closed. The '
                'alert is content-free — messages are fetched and decrypted only '
                'on your device, never inside the notification.',
                style: TextStyle(fontSize: 12),
              ),
              value: push.enabled,
              activeThumbColor: context.z.accent,
              onChanged: (v) => context.read<PushService>().setEnabled(v),
            ),
          ],
          const _SectionHeader('Security'),
          if (svc.vault.usedFallbackKeyStore)
            ListTile(
              leading: Icon(Icons.warning_amber, color: context.z.accent),
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
          if (_lockAvailable) ...[
            SwitchListTile(
              secondary: Icon(
                lock.settings.screenLock
                    ? Icons.fingerprint
                    : Icons.lock_open_outlined,
                color: lock.settings.screenLock
                    ? context.z.ok
                    : context.z.textSecondary,
              ),
              title: const Text('Screen lock'),
              subtitle: Text(
                lock.settings.screenLock
                    ? 'Z asks for your fingerprint, face or device PIN when it '
                        'opens and after ${_lockAfterLabel(lock.settings.lockAfterSec).toLowerCase()} in the background.'
                    : 'Ask for your fingerprint, face or device PIN to open Z. '
                        'Messages still arrive while it is locked.',
                style: const TextStyle(fontSize: 12),
              ),
              value: lock.settings.screenLock,
              activeThumbColor: context.z.accent,
              onChanged: (v) => _toggleScreenLock(context, lock, v),
            ),
            if (lock.settings.screenLock)
              ListTile(
                leading: const Icon(Icons.timer_outlined),
                title: const Text('Lock after'),
                subtitle: Text(_lockAfterLabel(lock.settings.lockAfterSec),
                    style: const TextStyle(fontSize: 12)),
                onTap: () => _pickLockAfter(context, lock),
              ),
          ],
          ListTile(
            leading: Icon(
              svc.vault.hasPassphrase
                  ? Icons.password
                  : Icons.password_outlined,
              color: svc.vault.hasPassphrase
                  ? context.z.ok
                  : context.z.textSecondary,
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
            onTap: () => _managePassphrase(context, svc, lock),
          ),
          if (_lockAvailable && svc.vault.hasPassphrase)
            SwitchListTile(
              secondary: Icon(
                lock.settings.biometricUnlock
                    ? Icons.face
                    : Icons.face_retouching_off,
                color: lock.settings.biometricUnlock
                    ? context.z.ok
                    : context.z.textSecondary,
              ),
              title: Text(lock.biometricUnlockBound
                  ? 'Unlock with biometrics — hardware-bound'
                  : 'Unlock with biometrics'),
              subtitle: Text(
                _biometricUnlockCopy(lock),
                style: const TextStyle(fontSize: 12),
              ),
              value: lock.settings.biometricUnlock,
              activeThumbColor: context.z.accent,
              onChanged: (v) => _toggleBiometricUnlock(context, svc, lock, v),
            ),
          ListTile(
            leading: const Icon(Icons.save_alt),
            title: const Text('Export identity backup (.zid)'),
            subtitle: const Text(
                'Identity keys + contact list, passphrase-encrypted. No messages.',
                style: TextStyle(fontSize: 12)),
            onTap: () => _exportBackup(context, svc),
          ),
          const _SectionHeader('Developer'),
          SwitchListTile(
            secondary: Icon(
              svc.devMode ? Icons.code : Icons.code_off,
              color: svc.devMode ? context.z.accent : context.z.textSecondary,
            ),
            title: const Text('Developer mode'),
            subtitle: const Text(
              'Reveal the custom relay address, for a self-hosted or test relay. '
              'Off by default — Z uses its built-in relay.',
              style: TextStyle(fontSize: 12),
            ),
            value: svc.devMode,
            activeThumbColor: context.z.accent,
            onChanged: (v) => svc.setDevMode(v),
          ),
          if (svc.devMode)
            ListTile(
              leading: const Icon(Icons.dns_outlined),
              title: const Text('Relay address'),
              subtitle: Text(transport.serverUrl,
                  style: const TextStyle(fontSize: 12)),
              onTap: () async {
                final ctrl = TextEditingController(text: transport.serverUrl);
                final url = await showDialog<String>(
                  context: context,
                  builder: (ctx) => AlertDialog(
                    title: const Text('Relay server URL'),
                    content: TextField(
                      controller: ctrl,
                      autofocus: true,
                      decoration: const InputDecoration(
                          hintText: 'wss://relay.example.com'),
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
          const _SectionHeader('Danger zone'),
          ListTile(
            leading: Icon(Icons.delete_forever, color: context.z.danger),
            title: Text('Wipe everything',
                style: TextStyle(color: context.z.danger)),
            subtitle: const Text(
                'Destroys identity, contacts, messages and keys on this device.',
                style: TextStyle(fontSize: 12)),
            onTap: () => _wipe(context, svc),
          ),
          const SizedBox(height: 24),
          Center(
            child: Text(
              'Z 1.0.0 — zero-trust messenger\n'
              'No accounts · No analytics · No server storage',
              textAlign: TextAlign.center,
              style: TextStyle(color: context.z.textSecondary, fontSize: 12),
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
                  child:
                      Text(error!, style: TextStyle(color: context.z.danger)),
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

  static String _lockAfterLabel(int sec) => switch (sec) {
        0 => 'Immediately',
        60 => '1 minute',
        3600 => '1 hour',
        _ => '${sec ~/ 60} minutes',
      };

  Future<void> _toggleScreenLock(
      BuildContext context, AppLock lock, bool on) async {
    final messenger = ScaffoldMessenger.of(context);
    if (!on) {
      await lock.disableScreenLock();
      return;
    }
    final r = await lock.enableScreenLock();
    switch (r) {
      case GateResult.ok:
        messenger.showSnackBar(const SnackBar(
            content: Text('Screen lock on. Z will ask before opening.')));
      case GateResult.unavailable:
        messenger.showSnackBar(const SnackBar(
            content: Text('Set up a fingerprint, face or device PIN in your '
                'system settings first.')));
      case GateResult.cancelled:
      case GateResult.failed:
        messenger.showSnackBar(const SnackBar(
            content: Text('Not enabled — the prompt was not completed.')));
    }
  }

  Future<void> _pickLockAfter(BuildContext context, AppLock lock) async {
    final sec = await showDialog<int>(
      context: context,
      builder: (ctx) => SimpleDialog(
        title: const Text('Lock after'),
        children: [
          RadioGroup<int>(
            groupValue: lock.settings.lockAfterSec,
            onChanged: (v) => Navigator.pop(ctx, v),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                for (final c in LockSettings.lockAfterChoices)
                  RadioListTile<int>(
                    value: c,
                    activeColor: context.z.accent,
                    title: Text(_lockAfterLabel(c)),
                  ),
              ],
            ),
          ),
        ],
      ),
    );
    if (sec != null) await lock.setLockAfter(sec);
  }

  Future<void> _toggleBiometricUnlock(
      BuildContext context, ChatService svc, AppLock lock, bool on) async {
    final messenger = ScaffoldMessenger.of(context);
    if (!on) {
      await lock.disableBiometricUnlock();
      messenger.showSnackBar(const SnackBar(
          content: Text('Biometric unlock off — the stored key was deleted.')));
      return;
    }
    final pass = await _askSecret(context, 'Enter your passphrase');
    if (pass == null || pass.isEmpty) return;
    try {
      final ok = await lock.enrolBiometricUnlock(svc.vault, pass);
      messenger.showSnackBar(SnackBar(
          content: Text(ok
              ? 'Biometric unlock on.'
              : 'Not enabled — the prompt was not completed.')));
    } on WrongPassphraseException {
      messenger
          .showSnackBar(const SnackBar(content: Text('Incorrect passphrase.')));
    } catch (e) {
      messenger.showSnackBar(SnackBar(content: Text('Could not enable: $e')));
    }
  }

  Future<void> _managePassphrase(
      BuildContext context, ChatService svc, AppLock lock) async {
    final messenger = ScaffoldMessenger.of(context);
    if (!svc.vault.hasPassphrase) {
      final pass = await _newPassphrase(context);
      if (pass == null) return;
      await svc.vault.setPassphrase(pass);
      if (mounted) setState(() {});
      messenger.showSnackBar(const SnackBar(
          content:
              Text('Passphrase set. You\'ll be asked for it next launch.')));
      return;
    }
    // Already set: offer change or remove.
    if (!context.mounted) return;
    final action = await showModalBottomSheet<String>(
      context: context,
      backgroundColor: context.z.surface,
      builder: (ctx) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: Icon(Icons.edit_outlined, color: context.z.accent),
              title: const Text('Change passphrase'),
              onTap: () => Navigator.pop(ctx, 'change'),
            ),
            ListTile(
              leading: Icon(Icons.lock_open, color: context.z.danger),
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
      messenger
          .showSnackBar(const SnackBar(content: Text('Incorrect passphrase.')));
      return;
    }

    if (action == 'change') {
      if (!context.mounted) return;
      final next = await _newPassphrase(context);
      if (next == null) return;
      await svc.vault.setPassphrase(next);
      await lock.onPassphraseChanged(svc.vault, next); // re-key biometrics
      if (mounted) setState(() {});
      messenger
          .showSnackBar(const SnackBar(content: Text('Passphrase changed.')));
    } else {
      await svc.vault.removePassphrase();
      await lock.onPassphraseRemoved();
      if (mounted) setState(() {});
      messenger.showSnackBar(const SnackBar(
          content:
              Text('Passphrase removed. The app opens automatically now.')));
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
            style: FilledButton.styleFrom(backgroundColor: context.z.danger),
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
        style: TextStyle(
          fontSize: 11,
          letterSpacing: 1.2,
          color: context.z.accent,
          fontWeight: FontWeight.w700,
        ),
      ),
    );
  }
}
