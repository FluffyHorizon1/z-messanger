import 'dart:io';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../l10n/app_localizations.dart';
import '../l10n/ttl_text.dart';
import '../core/app_lock.dart';
import '../core/chat_service.dart';
import '../core/models.dart';
import '../core/prefs.dart';
import '../core/push_service.dart';
import '../core/transport.dart';
import '../core/vault.dart';
import 'backup_screen.dart';
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

  String _biometricUnlockCopy(AppLocalizations l, AppLock lock) {
    final boundNow = lock.settings.biometricUnlock
        ? lock.biometricUnlockBound
        : _boundAvailable;
    return l.stBiometricLead +
        (boundNow ? l.stBiometricBoundBody : l.stBiometricUnboundBody);
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final svc = context.watch<ChatService>();
    final transport = context.watch<Transport>();
    final push = context.watch<PushService>();
    final lock = context.watch<AppLock>();
    final prefs = context.watch<AppPrefs>();

    return Scaffold(
      appBar: AppBar(title: Text(l.stSettings)),
      body: ListView(
        children: [
          _SectionHeader(l.stProfile),
          ListTile(
            leading: const Icon(Icons.badge_outlined),
            title: Text(l.stDisplayName),
            subtitle: Text(svc.displayName),
            onTap: () async {
              final ctrl = TextEditingController(text: svc.displayName);
              final name = await showDialog<String>(
                context: context,
                builder: (ctx) => AlertDialog(
                  title: Text(l.stDisplayName),
                  content: TextField(controller: ctrl, autofocus: true),
                  actions: [
                    TextButton(
                        onPressed: () => Navigator.pop(ctx),
                        child: Text(l.cancel)),
                    FilledButton(
                        onPressed: () => Navigator.pop(ctx, ctrl.text.trim()),
                        child: Text(l.save)),
                  ],
                ),
              );
              if (name != null && name.isNotEmpty) {
                await svc.setDisplayName(name);
                if (context.mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(content: Text(l.stDisplayNameSaved)));
                }
              }
            },
          ),
          _SectionHeader(l.stAppearance),
          ListTile(
            leading: Icon(switch (prefs.themeMode) {
              ThemeMode.light => Icons.light_mode_outlined,
              ThemeMode.dark => Icons.dark_mode_outlined,
              ThemeMode.system => Icons.brightness_auto_outlined,
            }),
            title: Text(l.stTheme),
            subtitle: Padding(
              padding: const EdgeInsets.only(top: 8),
              child: SegmentedButton<ThemeMode>(
                showSelectedIcon: false,
                segments: [
                  ButtonSegment(
                      value: ThemeMode.system, label: Text(l.stThemeSystem)),
                  ButtonSegment(
                      value: ThemeMode.light, label: Text(l.stThemeLight)),
                  ButtonSegment(
                      value: ThemeMode.dark, label: Text(l.stThemeDark)),
                ],
                selected: {prefs.themeMode},
                onSelectionChanged: (s) => prefs.setThemeMode(s.first),
              ),
            ),
          ),
          _SectionHeader(l.stConnection),
          ListTile(
            leading: Icon(
              Icons.cloud_outlined,
              color: transport.status == LinkStatus.connected
                  ? context.z.ok
                  : context.z.textSecondary,
            ),
            title: Text(l.stRelay),
            subtitle: Text(
              switch (transport.status) {
                LinkStatus.connected => l.stRelayConnected,
                LinkStatus.connecting => l.stRelayConnecting,
                LinkStatus.disconnected => transport.lastError == null
                    ? l.stRelayOffline
                    : l.stRelayOfflineWithError('${transport.lastError}'),
              },
              style: const TextStyle(fontSize: 12),
            ),
          ),
          _SectionHeader(l.stDevices),
          ListTile(
            leading: const Icon(Icons.devices_outlined),
            title: Text(l.stLinkedDevices),
            subtitle: Text(
              l.stLinkedDevicesHelp,
              style: const TextStyle(fontSize: 12),
            ),
            onTap: () => Navigator.of(context).push(
                MaterialPageRoute(builder: (_) => const LinkedDevicesScreen())),
          ),
          if (push.supported) ...[
            _SectionHeader(l.stNotifications),
            SwitchListTile(
              secondary: Icon(
                push.enabled
                    ? Icons.notifications_active_outlined
                    : Icons.notifications_off_outlined,
                color: push.enabled ? context.z.ok : context.z.textSecondary,
              ),
              title: Text(l.stPush),
              subtitle: Text(
                l.stPushHelp,
                style: const TextStyle(fontSize: 12),
              ),
              value: push.enabled,
              activeThumbColor: context.z.accent,
              onChanged: (v) => context.read<PushService>().setEnabled(v),
            ),
          ],
          _SectionHeader(l.stSecurity),
          if (svc.vault.usedFallbackKeyStore)
            ListTile(
              leading: Icon(Icons.warning_amber, color: context.z.warn),
              title: Text(l.stKeystoreUnavailable),
              subtitle: Text(
                l.stKeystoreUnavailableHelp,
                style: const TextStyle(fontSize: 12),
              ),
            ),
          ListTile(
            leading: const Icon(Icons.storage_outlined),
            title: Text(l.stWhereMessagesLive),
            subtitle: Text(
              l.stWhereMessagesLiveHelp,
              style: const TextStyle(fontSize: 12),
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
              title: Text(l.stScreenLock),
              subtitle: Text(
                !lock.settings.screenLock
                    ? l.stScreenLockOffHelp
                    : lock.settings.lockAfterSec == 0
                        ? l.stScreenLockOnImmediateHelp
                        : l.stScreenLockOnHelp(
                            _lockAfterLabel(l, lock.settings.lockAfterSec)),
                style: const TextStyle(fontSize: 12),
              ),
              value: lock.settings.screenLock,
              activeThumbColor: context.z.accent,
              onChanged: (v) => _toggleScreenLock(context, lock, v),
            ),
            if (lock.settings.screenLock)
              ListTile(
                leading: const Icon(Icons.timer_outlined),
                title: Text(l.stLockAfter),
                subtitle: Text(_lockAfterLabel(l, lock.settings.lockAfterSec),
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
            title: Text(
                svc.vault.hasPassphrase ? l.stPassphraseOn : l.stPassphraseOff),
            subtitle: Text(
              svc.vault.hasPassphrase
                  ? l.stPassphraseOnHelp
                  : l.stPassphraseOffHelp,
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
                  ? l.stBiometricBound
                  : l.stBiometric),
              subtitle: Text(
                _biometricUnlockCopy(l, lock),
                style: const TextStyle(fontSize: 12),
              ),
              value: lock.settings.biometricUnlock,
              activeThumbColor: context.z.accent,
              onChanged: (v) => _toggleBiometricUnlock(context, svc, lock, v),
            ),
          ListTile(
            leading: const Icon(Icons.enhanced_encryption),
            title: Text(l.stBackup),
            subtitle:
                Text(l.stBackupHelp, style: const TextStyle(fontSize: 12)),
            onTap: () => Navigator.of(context)
                .push(MaterialPageRoute(builder: (_) => const BackupScreen())),
          ),
          _SectionHeader(l.stDeveloper),
          SwitchListTile(
            secondary: Icon(
              svc.devMode ? Icons.code : Icons.code_off,
              color: svc.devMode ? context.z.accent : context.z.textSecondary,
            ),
            title: Text(l.stDevMode),
            subtitle: Text(
              l.stDevModeHelp,
              style: const TextStyle(fontSize: 12),
            ),
            value: svc.devMode,
            activeThumbColor: context.z.accent,
            onChanged: (v) => svc.setDevMode(v),
          ),
          if (svc.devMode)
            ListTile(
              leading: const Icon(Icons.dns_outlined),
              title: Text(l.stRelayAddress),
              subtitle: Text(transport.serverUrl,
                  style: const TextStyle(fontSize: 12)),
              onTap: () async {
                final ctrl = TextEditingController(text: transport.serverUrl);
                final url = await showDialog<String>(
                  context: context,
                  builder: (ctx) => AlertDialog(
                    title: Text(l.stRelayUrlTitle),
                    content: TextField(
                      controller: ctrl,
                      autofocus: true,
                      decoration: const InputDecoration(
                          hintText: 'wss://relay.example.com'),
                    ),
                    actions: [
                      TextButton(
                          onPressed: () => Navigator.pop(ctx),
                          child: Text(l.cancel)),
                      FilledButton(
                          onPressed: () => Navigator.pop(ctx, ctrl.text.trim()),
                          child: Text(l.stConnect)),
                    ],
                  ),
                );
                if (url != null && url.isNotEmpty) {
                  await svc.setServerUrl(url);
                }
              },
            ),
          _SectionHeader(l.stDangerZone),
          ListTile(
            leading: Icon(Icons.delete_forever, color: context.z.danger),
            title: Text(l.stWipe, style: TextStyle(color: context.z.danger)),
            subtitle: Text(l.stWipeHelp, style: const TextStyle(fontSize: 12)),
            onTap: () => _wipe(context, svc),
          ),
          const SizedBox(height: 24),
          Center(
            child: Text(
              // No version number here: the one that used to be here said
              // 1.0.0 for eighteen releases. The build's real version needs
              // package_info_plus, which is a separate change.
              l.stFooter,
              textAlign: TextAlign.center,
              style: TextStyle(color: context.z.textSecondary, fontSize: 12),
            ),
          ),
          const SizedBox(height: 24),
        ],
      ),
    );
  }

  /// The same words as the disappearing-messages timer for the same
  /// durations, plus "Immediately" for zero.
  static String _lockAfterLabel(AppLocalizations l, int sec) =>
      sec == 0 ? l.lockImmediately : ttlText(l, sec);

  Future<void> _toggleScreenLock(
      BuildContext context, AppLock lock, bool on) async {
    final messenger = ScaffoldMessenger.of(context);
    final l = AppLocalizations.of(context);
    if (!on) {
      await lock.disableScreenLock();
      return;
    }
    final r = await lock.enableScreenLock();
    switch (r) {
      case GateResult.ok:
        messenger.showSnackBar(SnackBar(content: Text(l.stScreenLockOn)));
      case GateResult.unavailable:
        messenger
            .showSnackBar(SnackBar(content: Text(l.stScreenLockUnavailable)));
      case GateResult.cancelled:
      case GateResult.failed:
        messenger.showSnackBar(SnackBar(content: Text(l.stPromptNotCompleted)));
    }
  }

  Future<void> _pickLockAfter(BuildContext context, AppLock lock) async {
    final l = AppLocalizations.of(context);
    final sec = await showDialog<int>(
      context: context,
      builder: (ctx) => SimpleDialog(
        title: Text(l.stLockAfter),
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
                    title: Text(_lockAfterLabel(l, c)),
                  ),
              ],
            ),
          ),
        ],
      ),
    );
    if (sec != null) await lock.setLockAfter(sec);
  }

  Future<String?> _newPassphrase(BuildContext context) async {
    final l = AppLocalizations.of(context);
    final a = TextEditingController();
    final b = TextEditingController();
    String? error;
    return showDialog<String>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setState) => AlertDialog(
          title: Text(l.stBackupPassphraseTitle),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: a,
                obscureText: true,
                autofocus: true,
                decoration: InputDecoration(labelText: l.stPassphraseMinLabel),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: b,
                obscureText: true,
                decoration: InputDecoration(labelText: l.stRepeat),
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
                onPressed: () => Navigator.pop(ctx), child: Text(l.cancel)),
            FilledButton(
              onPressed: () {
                if (a.text.length < 12) {
                  setState(() => error = l.stPassphraseTooShort);
                } else if (a.text != b.text) {
                  setState(() => error = l.stPassphraseMismatch);
                } else {
                  Navigator.pop(ctx, a.text);
                }
              },
              child: Text(l.stEncryptAndSave),
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _toggleBiometricUnlock(
      BuildContext context, ChatService svc, AppLock lock, bool on) async {
    final messenger = ScaffoldMessenger.of(context);
    final l = AppLocalizations.of(context);
    if (!on) {
      await lock.disableBiometricUnlock();
      messenger.showSnackBar(SnackBar(content: Text(l.stBiometricOff)));
      return;
    }
    final pass = await _askSecret(context, l.stEnterPassphrase);
    if (pass == null || pass.isEmpty) return;
    try {
      final ok = await lock.enrolBiometricUnlock(svc.vault, pass);
      messenger.showSnackBar(SnackBar(
          content: Text(ok ? l.stBiometricOn : l.stPromptNotCompleted)));
    } on WrongPassphraseException {
      messenger.showSnackBar(SnackBar(content: Text(l.stIncorrectPassphrase)));
    } catch (e) {
      messenger.showSnackBar(SnackBar(content: Text(l.stCouldNotEnable('$e'))));
    }
  }

  Future<void> _managePassphrase(
      BuildContext context, ChatService svc, AppLock lock) async {
    final messenger = ScaffoldMessenger.of(context);
    final l = AppLocalizations.of(context);
    if (!svc.vault.hasPassphrase) {
      final pass = await _newPassphrase(context);
      if (pass == null) return;
      await svc.vault.setPassphrase(pass);
      if (mounted) setState(() {});
      messenger.showSnackBar(SnackBar(content: Text(l.stPassphraseSet)));
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
              title: Text(l.stChangePassphrase),
              onTap: () => Navigator.pop(ctx, 'change'),
            ),
            ListTile(
              leading: Icon(Icons.lock_open, color: context.z.danger),
              title: Text(l.stRemovePassphrase),
              onTap: () => Navigator.pop(ctx, 'remove'),
            ),
          ],
        ),
      ),
    );
    if (action == null || !context.mounted) return;

    final current = await _askSecret(context, l.stEnterCurrentPassphrase);
    if (current == null) return;
    if (!await svc.vault.verifyPassphrase(current)) {
      messenger.showSnackBar(SnackBar(content: Text(l.stIncorrectPassphrase)));
      return;
    }

    if (action == 'change') {
      if (!context.mounted) return;
      final next = await _newPassphrase(context);
      if (next == null) return;
      await svc.vault.setPassphrase(next);
      await lock.onPassphraseChanged(svc.vault, next); // re-key biometrics
      if (mounted) setState(() {});
      messenger.showSnackBar(SnackBar(content: Text(l.stPassphraseChanged)));
    } else {
      await svc.vault.removePassphrase();
      await lock.onPassphraseRemoved();
      if (mounted) setState(() {});
      messenger.showSnackBar(SnackBar(content: Text(l.stPassphraseRemoved)));
    }
  }

  Future<String?> _askSecret(BuildContext context, String label) {
    final l = AppLocalizations.of(context);
    final ctrl = TextEditingController();
    return showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(label),
        content: TextField(
          controller: ctrl,
          obscureText: true,
          autofocus: true,
          decoration: InputDecoration(hintText: l.passphrase),
          onSubmitted: (v) => Navigator.pop(ctx, v),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx), child: Text(l.cancel)),
          FilledButton(
              onPressed: () => Navigator.pop(ctx, ctrl.text),
              child: Text(l.ok)),
        ],
      ),
    );
  }

  Future<void> _wipe(BuildContext context, ChatService svc) async {
    final l = AppLocalizations.of(context);
    final sure = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(l.stWipeTitle),
        content: Text(l.stWipeBody),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: Text(l.cancel)),
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: context.z.danger),
            onPressed: () => Navigator.pop(ctx, true),
            child: Text(l.stWipeAction),
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
