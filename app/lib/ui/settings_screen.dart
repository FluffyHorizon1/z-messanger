import 'dart:io';

import 'package:flutter/material.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:provider/provider.dart';

import '../core/update_check.dart';
import '../l10n/app_localizations.dart';
import '../l10n/ttl_text.dart';
import '../l10n/when_text.dart';
import '../core/app_lock.dart';
import '../core/chat_service.dart';
import '../core/key_transparency.dart';
import '../core/models.dart';
import '../core/prefs.dart';
import '../core/push_service.dart';
import '../core/relay_url.dart';
import 'relay_warning.dart';
import '../core/transport.dart';
import '../core/vault.dart';
import 'backup_screen.dart';
import 'crypto_bench_screen.dart';
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
  // 24.4: the running build's version, read from the platform bundle. Null
  // until it loads, and stays null where there is no platform to ask (a plain
  // widget test), which is also what keeps the update check from firing there.
  String? _appVersion;

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
    _loadVersionAndMaybeCheck();
  }

  /// 24.4 — read the real version, then (at most once a day) ask the relay's
  /// own `/latest.json` whether a newer build exists. Reading the platform
  /// version first is deliberate: under a widget test it throws, and this
  /// returns before any network, so the check is a no-op there. Every failure
  /// — no platform, unreachable, malformed — is swallowed: a check that cannot
  /// run just shows no notice, it never crashes the screen.
  Future<void> _loadVersionAndMaybeCheck() async {
    final String version;
    try {
      version = (await PackageInfo.fromPlatform()).version;
    } catch (_) {
      return;
    }
    if (!mounted) return;
    setState(() => _appVersion = version);
    try {
      final prefs = context.read<AppPrefs>();
      final now = DateTime.now().millisecondsSinceEpoch;
      const dayMs = 24 * 60 * 60 * 1000;
      if (now - prefs.lastUpdateCheckMs < dayMs) return; // the cached answer stands
      final relayUrl = context.read<Transport>().serverUrl;
      final status = await checkForUpdate(current: version, relayUrl: relayUrl);
      if (!mounted) return;
      await prefs.recordUpdateCheck(
          atMs: now, latestVersion: status.latest, latestUrl: status.url);
    } catch (_) {
      // A check that could not run leaves no notice, and never throws.
    }
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
          // 24.4: a quiet, non-blocking "you're behind" notice. Shown only
          // when the relay's /latest.json reported a strictly-newer version
          // than the one running; recomputed against the running version, so
          // it clears itself once the user updates.
          if (_appVersion != null &&
              prefs.latestVersion != null &&
              isBehind(_appVersion!, prefs.latestVersion!))
            _UpdateNotice(latest: prefs.latestVersion!, url: prefs.latestUrl),
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
          // 7.7b (ADR 0006): the transparency log. Everyone sees its health
          // and can ask for a check; where it is and which key signs it are
          // developer-mode rows, like the relay address — most people should
          // never touch them, and a self-hoster needs them.
          _SectionHeader(l.stTransparency),
          ListTile(
            leading: Icon(_ktIcon(svc.kt.health), color: _ktTone(context, svc.kt.health)),
            title: Text(l.stKtStatus),
            subtitle: Text(_ktHealthText(context, l, svc.kt),
                style: const TextStyle(fontSize: 12)),
          ),
          if (svc.kt.health != KtHealth.off)
            ListTile(
              leading: const Icon(Icons.refresh),
              title: Text(l.stKtCheckNow),
              onTap: () async {
                final messenger = ScaffoldMessenger.of(context);
                await svc.kt.check();
                messenger.showSnackBar(SnackBar(content: Text(l.stKtChecked)));
              },
            ),
          if (svc.devMode) ...[
            ListTile(
              leading: const Icon(Icons.dns_outlined),
              title: Text(l.stKtLogAddress),
              subtitle: Text(svc.kt.config.logUrl.isEmpty ? l.stKtNone : svc.kt.config.logUrl,
                  style: const TextStyle(fontSize: 12)),
              onTap: () => _editKt(context, svc, l.stKtLogUrlTitle, svc.kt.config.logUrl,
                  (v) => KtConfig(
                      logUrl: v,
                      logPubB64: svc.kt.config.logPubB64,
                      witnessUrl: svc.kt.config.witnessUrl,
                      witnessPubB64: svc.kt.config.witnessPubB64)),
            ),
            ListTile(
              leading: const Icon(Icons.key_outlined),
              title: Text(l.stKtLogKey),
              subtitle: Text(svc.kt.config.logPubB64.isEmpty ? l.stKtNone : svc.kt.config.logPubB64,
                  style: const TextStyle(fontSize: 12)),
              onTap: () => _editKt(context, svc, l.stKtLogKeyTitle, svc.kt.config.logPubB64,
                  (v) => KtConfig(
                      logUrl: svc.kt.config.logUrl,
                      logPubB64: v,
                      witnessUrl: svc.kt.config.witnessUrl,
                      witnessPubB64: svc.kt.config.witnessPubB64)),
            ),
            // One row for the pair. They were two, and two rows cannot express
            // the rule: an address with no key is not a weaker witness but a
            // check with nothing behind it, and editing them one at a time
            // means passing through exactly that state to reach a good one.
            ListTile(
              leading: const Icon(Icons.verified_outlined),
              title: Text(l.stKtWitness),
              subtitle: Text(
                  svc.kt.config.witnessUrl.isEmpty && svc.kt.config.witnessPubB64.isEmpty
                      ? l.stKtNone
                      : [svc.kt.config.witnessUrl, svc.kt.config.witnessPubB64].join('\n'),
                  style: const TextStyle(fontSize: 12)),
              onTap: () => _editWitness(context, svc),
            ),
            ListTile(
              leading: Icon(Icons.history_toggle_off, color: context.z.warn),
              title: Text(l.stKtReset),
              subtitle: Text(l.stKtResetHelp, style: const TextStyle(fontSize: 12)),
              onTap: () async {
                final ok = await showDialog<bool>(
                  context: context,
                  builder: (ctx) => AlertDialog(
                    title: Text(l.stKtResetConfirm),
                    content: Text(l.stKtResetHelp),
                    actions: [
                      TextButton(onPressed: () => Navigator.pop(ctx, false), child: Text(l.cancel)),
                      FilledButton(onPressed: () => Navigator.pop(ctx, true), child: Text(l.stKtReset)),
                    ],
                  ),
                );
                if (ok == true) await svc.kt.resetHistory();
              },
            ),
          ],
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
                  if (!context.mounted) return;
                  if (!await confirmInsecureRelay(
                      context, normalizeRelayUrl(url))) {
                    return;
                  }
                  await svc.setServerUrl(url, acceptedInsecure: true);
                }
              },
            ),
          if (svc.devMode)
            ListTile(
              leading: const Icon(Icons.speed_outlined),
              title: Text(l.stCryptoBench),
              subtitle: Text(l.stCryptoBenchHelp,
                  style: const TextStyle(fontSize: 12)),
              onTap: () => Navigator.push(
                context,
                MaterialPageRoute<void>(
                    builder: (_) => const CryptoBenchScreen()),
              ),
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
            // 24.4: the build's real version, read via package_info_plus, so
            // it can no longer drift (this line said 1.0.0 for eighteen
            // releases). Absent under a widget test, where there is no platform
            // version to read; the footer then shows just its text.
            child: Column(
              children: [
                Text(l.stFooter,
                    textAlign: TextAlign.center,
                    style:
                        TextStyle(color: context.z.textSecondary, fontSize: 12)),
                if (_appVersion != null) ...[
                  const SizedBox(height: 4),
                  Text(l.stVersion(_appVersion!),
                      style: TextStyle(
                          color: context.z.textSecondary, fontSize: 12)),
                ],
              ],
            ),
          ),
          const SizedBox(height: 24),
        ],
      ),
    );
  }

  static IconData _ktIcon(KtHealth h) => switch (h) {
        KtHealth.off => Icons.fact_check_outlined,
        KtHealth.unknown => Icons.fact_check_outlined,
        KtHealth.ok => Icons.fact_check,
        KtHealth.unreachable => Icons.cloud_off_outlined,
        KtHealth.fault => Icons.gpp_bad,
      };

  static Color _ktTone(BuildContext context, KtHealth h) => switch (h) {
        KtHealth.ok => context.z.ok,
        KtHealth.unreachable => context.z.warn,
        KtHealth.fault => context.z.danger,
        _ => context.z.textSecondary,
      };

  static String _ktHealthText(BuildContext context, AppLocalizations l, KeyTransparency kt) =>
      switch (kt.health) {
        KtHealth.off => l.stKtHealthOff,
        KtHealth.unknown => l.stKtHealthUnknown,
        KtHealth.ok => l.stKtHealthOk(whenText(context, kt.lastOkMs), kt.head?.size ?? 0),
        KtHealth.unreachable => l.stKtHealthUnreachable(whenText(context, kt.lastOkMs)),
        KtHealth.fault => l.stKtHealthFault(kt.fault?.reason ?? ''),
      };

  Future<void> _editKt(BuildContext context, ChatService svc, String title,
      String current, KtConfig Function(String) update) async {
    final l = AppLocalizations.of(context);
    final ctrl = TextEditingController(text: current);
    final v = await showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(title),
        content: TextField(controller: ctrl, autofocus: true),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: Text(l.cancel)),
          FilledButton(onPressed: () => Navigator.pop(ctx, ctrl.text.trim()), child: Text(l.stKtSave)),
        ],
      ),
    );
    if (v != null) await svc.setKtConfig(update(v));
  }

  /// The witness address and its pinned key, edited and saved together.
  ///
  /// `KeyTransparencyService.setConfig` refuses a half-set pair, and this
  /// dialog exists so that refusal is never a dead end: the fields go in
  /// together, the reason comes back in the user's own language, and the
  /// dialog stays open with what they typed.
  Future<void> _editWitness(BuildContext context, ChatService svc) async {
    final l = AppLocalizations.of(context);
    final url = TextEditingController(text: svc.kt.config.witnessUrl);
    final key = TextEditingController(text: svc.kt.config.witnessPubB64);
    String? error;
    await showDialog<void>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setLocal) => AlertDialog(
          title: Text(l.stKtWitnessEdit),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(l.stKtWitnessHelp, style: const TextStyle(fontSize: 12)),
                const SizedBox(height: 12),
                TextField(
                    controller: url,
                    autofocus: true,
                    decoration: InputDecoration(labelText: l.stKtWitnessTitle)),
                const SizedBox(height: 8),
                TextField(
                    controller: key,
                    decoration: InputDecoration(labelText: l.stKtWitnessKeyTitle)),
                if (error != null) ...[
                  const SizedBox(height: 12),
                  Text(error!,
                      style: TextStyle(fontSize: 12, color: ctx.z.danger)),
                ],
              ],
            ),
          ),
          actions: [
            TextButton(onPressed: () => Navigator.pop(ctx), child: Text(l.cancel)),
            FilledButton(
              onPressed: () async {
                final next = KtConfig(
                  logUrl: svc.kt.config.logUrl,
                  logPubB64: svc.kt.config.logPubB64,
                  witnessUrl: url.text.trim(),
                  witnessPubB64: key.text.trim(),
                );
                try {
                  await svc.setKtConfig(next);
                  if (ctx.mounted) Navigator.pop(ctx);
                } on KtConfigInvalid catch (e) {
                  setLocal(() => error = _witnessReason(l, e.reason));
                }
              },
              child: Text(l.stKtSave),
            ),
          ],
        ),
      ),
    );
    url.dispose();
    key.dispose();
  }

  static String _witnessReason(AppLocalizations l, String reason) {
    switch (reason) {
      case 'urlWithoutKey':
        return l.stKtWitnessNeedsKey;
      case 'keyWithoutUrl':
        return l.stKtWitnessNeedsUrl;
      default:
        return l.stKtWitnessBadKey;
    }
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
    if (sure != true) return;
    if (!context.mounted) return;
    // The biometric entry first: its pass key lives in the platform keystore
    // and its Keystore alias lives outside this app's files, so neither goes
    // when the vault's directory does. Read before the awaits below, so the
    // context is not used across them.
    final lock = context.read<AppLock>();
    try {
      await lock.disableBiometricUnlock();
    } catch (_) {
      // Best effort: the key itself is deleted by the wipe below, which is
      // the part that must not be skipped.
    }
    try {
      await svc.wipeEverything();
    } catch (e) {
      // It did not all go, and the process must NOT end here: saying "wiped"
      // and exiting while `z.db` is still on disk is the one outcome this
      // screen must never produce.
      if (!context.mounted) return;
      await showDialog<void>(
        context: context,
        builder: (ctx) => AlertDialog(
          title: Text(l.stWipeFailedTitle),
          content: Text(l.stWipeFailedBody),
          actions: [
            TextButton(
                onPressed: () => Navigator.pop(ctx), child: Text(l.ok)),
          ],
        ),
      );
      return;
    }
    exit(0); // relaunch lands on onboarding with a clean vault
  }
}

/// 24.4 — the "you're behind" card. There is no in-app updater by design
/// (THREAT_MODEL R8), so this only names the newer version and shows where to
/// get it, as selectable text to copy (no url_launcher dependency).
class _UpdateNotice extends StatelessWidget {
  final String latest;
  final String? url;
  const _UpdateNotice({required this.latest, this.url});

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    return Container(
      margin: const EdgeInsets.fromLTRB(16, 16, 16, 0),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: context.z.surfaceAlt,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: context.z.accent),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(Icons.system_update_alt, size: 18, color: context.z.accent),
              const SizedBox(width: 8),
              Text(l.stUpdateTitle,
                  style: const TextStyle(fontWeight: FontWeight.w700)),
            ],
          ),
          const SizedBox(height: 6),
          Text(l.stUpdateBody(latest),
              style: const TextStyle(fontSize: 13, height: 1.4)),
          if (url != null) ...[
            const SizedBox(height: 6),
            SelectableText(url!,
                style: TextStyle(fontSize: 13, color: context.z.accent)),
          ],
        ],
      ),
    );
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
