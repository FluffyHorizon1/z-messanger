import 'dart:convert';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:z_protocol/z_protocol.dart';

import '../core/backup.dart';
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
    final url = normalizeRelayUrl(_server.text);
    if (url.isEmpty) {
      setState(() => _error = 'Enter your relay address first.');
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
        _testOk = 'Connected — the relay is reachable.';
        _testWarn = relayUrlWarning(url);
        _server.text = url; // show the normalized form
      });
    } catch (e) {
      setState(() => _error = 'Could not reach a relay at $url.\n'
          'Check the address and that it shows Live in your host dashboard.');
    } finally {
      setState(() => _testing = false);
    }
  }

  Future<void> _create() async {
    if (_name.text.trim().isEmpty) {
      setState(() => _error = 'Pick a display name (only your contacts ever see it).');
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

  Future<void> _restore() async {
    final picked = await FilePicker.platform.pickFiles(
      dialogTitle: 'Choose your .zid backup',
      withData: true,
    );
    final data = picked?.files.single.bytes;
    if (data == null) return;
    if (!mounted) return;
    final pass = await _askPassphrase(context);
    if (pass == null || pass.isEmpty) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final restored = await BackupFile.import(data, pass);
      final idJson = (restored['identity'] as Map).cast<String, Object?>();
      await widget.vault.kvPut('identity', jsonEncode(idJson));
      await widget.vault
          .kvPut('display_name', restored['name'] as String? ?? 'Me');
      await widget.vault
          .kvPut('server_url', _server.text.trim(), sensitive: false);
      // Re-insert contacts (sessions start fresh; that is expected).
      final contacts = (restored['contacts'] as List?) ?? [];
      for (final c in contacts) {
        final rec = (c as Map).cast<String, Object?>();
        final bundle =
            ContactBundle.fromJson((rec['bundle'] as Map).cast<String, Object?>());
        if (!await bundle.verify()) continue;
        final rid = await bundle.routingId();
        await widget.vault.db.insert(
            'contacts',
            {
              'rid': rid,
              'enc_bundle':
                  await widget.vault.seal(jsonEncode(bundle.toJson())),
              'enc_name': await widget.vault
                  .seal(rec['name'] as String? ?? 'Unknown'),
              'ttl_seconds': (rec['ttl'] as num?)?.toInt() ?? 0,
              'verified': (rec['verified'] as bool? ?? false) ? 1 : 0,
              'created_ms': DateTime.now().millisecondsSinceEpoch,
            },
            conflictAlgorithm: null);
      }
      await widget.onDone();
    } catch (e) {
      setState(() {
        _busy = false;
        _error = 'Restore failed: wrong passphrase or corrupt file.';
      });
    }
  }

  Future<String?> _askPassphrase(BuildContext context) {
    final ctrl = TextEditingController();
    return showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Backup passphrase'),
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
              child: const Text('Unlock')),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(32),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 420),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const Text('Z',
                    textAlign: TextAlign.center,
                    style: TextStyle(
                        fontSize: 88,
                        fontWeight: FontWeight.w900,
                        color: ZTheme.accent,
                        height: 1)),
                const SizedBox(height: 8),
                const Text(
                  'Zero-trust messaging.\nNo accounts. No phone number. No server storage.',
                  textAlign: TextAlign.center,
                  style: TextStyle(color: ZTheme.textSecondary, height: 1.5),
                ),
                const SizedBox(height: 40),
                TextField(
                  controller: _name,
                  decoration: const InputDecoration(
                    labelText: 'Display name',
                    helperText: 'Shared only inside your encrypted contact code',
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
                    decoration: const InputDecoration(
                      labelText: 'Relay address (developer)',
                      helperText:
                          'Custom or self-hosted relay. Leave as-is to use the '
                          'default zmessengers.com relay.',
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
                    label: Text(_testing ? 'Testing…' : 'Test connection'),
                  ),
                  if (_testOk != null)
                    Padding(
                      padding: const EdgeInsets.only(top: 10),
                      child: Row(
                        children: [
                          const Icon(Icons.check_circle,
                              color: ZTheme.ok, size: 18),
                          const SizedBox(width: 8),
                          Expanded(
                            child: Text(_testOk!,
                                style: const TextStyle(color: ZTheme.ok)),
                          ),
                        ],
                      ),
                    ),
                  if (_testWarn != null)
                    Padding(
                      padding: const EdgeInsets.only(top: 10),
                      child: Text(_testWarn!,
                          style: const TextStyle(
                              color: ZTheme.accent, fontSize: 12)),
                    ),
                ],
                const SizedBox(height: 24),
                if (_error != null)
                  Padding(
                    padding: const EdgeInsets.only(bottom: 16),
                    child: Text(_error!,
                        style: const TextStyle(color: ZTheme.danger)),
                  ),
                FilledButton(
                  style: FilledButton.styleFrom(
                    backgroundColor: ZTheme.accent,
                    foregroundColor: Colors.black,
                    padding: const EdgeInsets.symmetric(vertical: 16),
                  ),
                  onPressed: _busy ? null : _create,
                  child: _busy
                      ? const SizedBox(
                          width: 20,
                          height: 20,
                          child: CircularProgressIndicator(strokeWidth: 2))
                      : const Text('Create my identity'),
                ),
                const SizedBox(height: 12),
                OutlinedButton(
                  onPressed: _busy ? null : _restore,
                  child: const Text('Restore from backup (.zid)'),
                ),
                const SizedBox(height: 8),
                TextButton(
                  onPressed: _busy
                      ? null
                      : () => Navigator.of(context).push(MaterialPageRoute(
                          builder: (_) => NewDeviceLinkScreen(
                              vault: widget.vault, onDone: widget.onDone))),
                  child: const Text('Link to an existing account'),
                ),
                TextButton(
                  onPressed: () => setState(() => _showDev = !_showDev),
                  child: Text(
                    _showDev ? 'Hide developer options' : 'Developer options',
                    style: const TextStyle(
                        color: ZTheme.textSecondary, fontSize: 12),
                  ),
                ),
                const SizedBox(height: 24),
                const Text(
                  'Your identity is a cryptographic key pair generated on this device. '
                  'It never leaves it unencrypted.',
                  textAlign: TextAlign.center,
                  style: TextStyle(color: ZTheme.textSecondary, fontSize: 12),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
