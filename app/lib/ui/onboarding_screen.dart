import 'dart:io';
import 'dart:convert';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import '../l10n/app_localizations.dart';
import 'package:z_protocol/z_protocol.dart';

import '../core/restore.dart';
import '../core/relay_url.dart';
import '../core/vault.dart';
import 'link_device_screen.dart';
import 'theme.dart';

class OnboardingScreen extends StatefulWidget {
  final Vault vault;
  final Future<void> Function() onDone;
  const OnboardingScreen(
      {super.key, required this.vault, required this.onDone});

  @override
  State<OnboardingScreen> createState() => _OnboardingScreenState();
}

class _OnboardingScreenState extends State<OnboardingScreen> {
  final _name = TextEditingController();
  final _server = TextEditingController(text: defaultRelayUrl);
  bool _busy = false;
  bool _testing = false;
  bool _showDev = false;
  String? _error;
  String? _testOk; // green message when a probe succeeds
  String? _testWarn; // amber non-TLS notice

  Future<void> _test() async {
    final l = AppLocalizations.of(context);
    final url = normalizeRelayUrl(_server.text);
    if (url.isEmpty) {
      setState(() => _error = l.onbEnterRelayFirst);
      return;
    }
    setState(() {
      _testing = true;
      _error = null;
      _testOk = null;
      _testWarn = null;
    });
    try {
      await RelayClient.probe(url);
      setState(() {
        _testOk = l.onbRelayReachable;
        _testWarn = relayUrlWarning(url);
        _server.text = url; // show the normalized form
      });
    } catch (e) {
      setState(() => _error = l.onbRelayUnreachableAt(url));
    } finally {
      setState(() => _testing = false);
    }
  }

  Future<void> _create() async {
    final l = AppLocalizations.of(context);
    if (_name.text.trim().isEmpty) {
      setState(() =>
          _error = l.onbPickName);
      return;
    }
    final url = normalizeRelayUrl(_server.text);
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final identity = await ZIdentity.generate();
      await widget.vault.kvPut('identity', jsonEncode(identity.toJson()));
      await widget.vault.kvPut('display_name', _name.text.trim());
      await widget.vault.kvPut('server_url', url, sensitive: false);
      await widget.onDone();
    } catch (e) {
      setState(() {
        _busy = false;
        _error = '$e';
      });
    }
  }

  /// One restore path for both artifacts (9.4). The user picks a file; we
  /// work out whether it is a `.zbk` archive or the older `.zid` identity
  /// backup and ask for the matching secret. Nobody should have to know
  /// which kind of file they kept, least of all while replacing a lost phone.
  Future<void> _restore() async {
    final l = AppLocalizations.of(context);
    final picked = await FilePicker.platform.pickFiles(
      dialogTitle: l.onbChooseBackup,
      withData: false,
    );
    final path = picked?.files.single.path;
    if (path == null) return;
    final file = File(path);
    final preview = await Restore.identify(file);
    if (!mounted) return;
    if (preview.kind == BackupKind.unknown) {
      setState(() => _error = l.onbNotABackup);
      return;
    }
    final secret = preview.kind == BackupKind.archive
        ? await _askRecoveryCode(context)
        : await _askPassphrase(context);
    if (secret == null || secret.isEmpty) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await Restore.run(
        vault: widget.vault,
        file: file,
        secret: secret,
        kind: preview.kind,
        serverUrl: _server.text.trim(),
      );
      await widget.onDone();
    } on FormatException catch (e) {
      // The message is the useful part here: a mistyped recovery code is
      // caught by its checksum and says so, which a generic "wrong secret"
      // would throw away.
      setState(() {
        _busy = false;
        _error = e.message;
      });
    } catch (_) {
      setState(() {
        _busy = false;
        _error = l.onbRestoreFailed;
      });
    }
  }

  Future<String?> _askRecoveryCode(BuildContext context) {
    final l = AppLocalizations.of(context);
    final ctrl = TextEditingController();
    return showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(l.onbRecoveryCode),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
                l.onbRecoveryCodeHelp),
            const SizedBox(height: 12),
            TextField(
              controller: ctrl,
              autofocus: true,
              autocorrect: false,
              textCapitalization: TextCapitalization.characters,
              decoration: const InputDecoration(
                  hintText: 'ZBK-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX'),
              onSubmitted: (v) => Navigator.pop(ctx, v),
            ),
          ],
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx), child: Text(l.cancel)),
          FilledButton(
              onPressed: () => Navigator.pop(ctx, ctrl.text),
              child: Text(l.onbRestore)),
        ],
      ),
    );
  }

  Future<String?> _askPassphrase(BuildContext context) {
    final l = AppLocalizations.of(context);
    final ctrl = TextEditingController();
    return showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(l.onbBackupPassphrase),
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
              child: Text(l.unlock)),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    return Scaffold(
      body: SafeArea(
          child: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(32),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 420),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Text('Z',
                    textAlign: TextAlign.center,
                    style: TextStyle(
                        fontSize: 88,
                        fontWeight: FontWeight.w900,
                        color: context.z.accent,
                        height: 1)),
                const SizedBox(height: 8),
                Text(
                  'Zero-trust messaging.\nNo accounts. No phone number. No server storage.',
                  textAlign: TextAlign.center,
                  style: TextStyle(color: context.z.textSecondary, height: 1.5),
                ),
                const SizedBox(height: 40),
                TextField(
                  controller: _name,
                  decoration: InputDecoration(
                    labelText: l.onbDisplayName,
                    helperText:
                        l.onbDisplayNameHelp,
                  ),
                ),
                if (_showDev) ...[
                  const SizedBox(height: 16),
                  TextField(
                    controller: _server,
                    onChanged: (_) => setState(() {
                      _testOk = null;
                      _testWarn = null;
                    }),
                    decoration: InputDecoration(
                      labelText: l.onbRelayAddress,
                      helperText:
                          l.onbRelayHelp,
                      helperMaxLines: 2,
                    ),
                  ),
                  const SizedBox(height: 12),
                  OutlinedButton.icon(
                    onPressed: (_busy || _testing) ? null : _test,
                    icon: _testing
                        ? const SizedBox(
                            width: 16,
                            height: 16,
                            child: CircularProgressIndicator(strokeWidth: 2))
                        : const Icon(Icons.wifi_tethering, size: 18),
                    label: Text(_testing ? l.onbTesting : l.onbTestConnection),
                  ),
                  if (_testOk != null)
                    Padding(
                      padding: const EdgeInsets.only(top: 10),
                      child: Row(
                        children: [
                          Icon(Icons.check_circle,
                              color: context.z.ok, size: 18),
                          const SizedBox(width: 8),
                          Expanded(
                            child: Text(_testOk!,
                                style: TextStyle(color: context.z.ok)),
                          ),
                        ],
                      ),
                    ),
                  if (_testWarn != null)
                    Padding(
                      padding: const EdgeInsets.only(top: 10),
                      child: Text(_testWarn!,
                          style:
                              TextStyle(color: context.z.accent, fontSize: 12)),
                    ),
                ],
                const SizedBox(height: 24),
                if (_error != null)
                  Padding(
                    padding: const EdgeInsets.only(bottom: 16),
                    child: Text(_error!,
                        style: TextStyle(color: context.z.danger)),
                  ),
                FilledButton(
                  style: FilledButton.styleFrom(
                    backgroundColor: context.z.accent,
                    foregroundColor: context.z.onAccent,
                    padding: const EdgeInsets.symmetric(vertical: 16),
                  ),
                  onPressed: _busy ? null : _create,
                  child: _busy
                      ? const SizedBox(
                          width: 20,
                          height: 20,
                          child: CircularProgressIndicator(strokeWidth: 2))
                      : Text(l.onbCreateIdentity),
                ),
                const SizedBox(height: 12),
                OutlinedButton(
                  onPressed: _busy ? null : _restore,
                  child: Text(l.onbRestoreFromBackup),
                ),
                const SizedBox(height: 8),
                TextButton(
                  onPressed: _busy
                      ? null
                      : () => Navigator.of(context).push(MaterialPageRoute(
                          builder: (_) => NewDeviceLinkScreen(
                              vault: widget.vault, onDone: widget.onDone))),
                  child: Text(l.onbLinkExisting),
                ),
                TextButton(
                  onPressed: () => setState(() => _showDev = !_showDev),
                  child: Text(
                    _showDev ? l.onbHideDevOptions : l.onbDevOptions,
                    style:
                        TextStyle(color: context.z.textSecondary, fontSize: 12),
                  ),
                ),
                const SizedBox(height: 24),
                Text(
                  l.onbIdentityNote,
                  textAlign: TextAlign.center,
                  style:
                      TextStyle(color: context.z.textSecondary, fontSize: 12),
                ),
              ],
            ),
          ),
        ),
      )),
    );
  }
}
