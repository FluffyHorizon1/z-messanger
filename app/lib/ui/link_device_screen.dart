import 'dart:convert';

import 'package:flutter/material.dart';

import '../l10n/app_localizations.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import 'package:z_protocol/z_protocol.dart';

import '../core/chat_service.dart';
import '../core/relay_url.dart';
import '../core/vault.dart';
import 'theme.dart';

/// Blocking dialog: the user compares the safety string on both screens.
Future<bool> confirmSasDialog(BuildContext context, String sas) async {
  final l = AppLocalizations.of(context);
  final ok = await showDialog<bool>(
    context: context,
    barrierDismissible: false,
    builder: (ctx) => AlertDialog(
      title: Text(l.linkCompareTitle),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(l.linkCompareBody),
          const SizedBox(height: 18),
          Text(
            sas,
            style: TextStyle(
                fontSize: 40,
                fontFamily: 'monospace',
                letterSpacing: 6,
                color: context.z.accent),
          ),
          const SizedBox(height: 12),
          Text(
            l.linkCompareWarn,
            textAlign: TextAlign.center,
            style: TextStyle(fontSize: 12, color: context.z.textSecondary),
          ),
        ],
      ),
      actions: [
        TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: Text(l.linkTheyDiffer)),
        FilledButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: Text(l.linkTheyMatch)),
      ],
    ),
  );
  return ok ?? false;
}

/// EXISTING device: host a link by entering the code shown on the new device.
class HostLinkScreen extends StatefulWidget {
  const HostLinkScreen({super.key});
  @override
  State<HostLinkScreen> createState() => _HostLinkScreenState();
}

class _HostLinkScreenState extends State<HostLinkScreen> {
  final _code = TextEditingController();
  bool _busy = false;
  String? _status;
  bool _ok = false;

  Future<void> _link() async {
    final l = AppLocalizations.of(context);
    final chat = context.read<ChatService>();
    setState(() {
      _busy = true;
      _status = null;
      _ok = false;
    });
    try {
      final ok = await chat.hostDeviceLink(
        _code.text.trim(),
        confirmSas: (sas) => confirmSasDialog(context, sas),
      );
      setState(() {
        _busy = false;
        _ok = ok;
        _status = ok
            ? l.linkDone
            : l.linkCancelled;
      });
    } catch (e) {
      setState(() {
        _busy = false;
        _status = l.linkFailed('$e');
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    return Scaffold(
      appBar: AppBar(title: Text(l.linkADevice)),
      body: ListView(
        padding: EdgeInsets.fromLTRB(
            24, 24, 24, 24 + MediaQuery.paddingOf(context).bottom),
        children: [
          Text(
            l.linkHostHelp,
            style: TextStyle(color: context.z.textSecondary, height: 1.5),
          ),
          const SizedBox(height: 24),
          TextField(
            controller: _code,
            autofocus: true,
            textCapitalization: TextCapitalization.characters,
            style: const TextStyle(fontFamily: 'monospace', letterSpacing: 2),
            decoration: InputDecoration(
              labelText: l.linkPairingCode,
              hintText: 'ABCDE-FGHIJ-…',
            ),
          ),
          const SizedBox(height: 20),
          FilledButton(
            style: FilledButton.styleFrom(
              backgroundColor: context.z.accent,
              foregroundColor: context.z.onAccent,
              padding: const EdgeInsets.symmetric(vertical: 16),
            ),
            onPressed: _busy ? null : _link,
            child: _busy
                ? const SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(strokeWidth: 2))
                : Text(l.linkDeviceAction),
          ),
          if (_status != null)
            Padding(
              padding: const EdgeInsets.only(top: 18),
              child: Text(_status!,
                  style: TextStyle(
                      color: _ok ? context.z.ok : context.z.textSecondary)),
            ),
          const SizedBox(height: 24),
          Text(
            l.linkSyncNote,
            style: TextStyle(color: context.z.textSecondary, fontSize: 12),
          ),
        ],
      ),
    );
  }
}

/// NEW device: link to an existing account. Shows a pairing code, runs the
/// handshake, and on success installs the account + contacts locally.
class NewDeviceLinkScreen extends StatefulWidget {
  final Vault vault;
  final Future<void> Function() onDone;
  const NewDeviceLinkScreen(
      {super.key, required this.vault, required this.onDone});
  @override
  State<NewDeviceLinkScreen> createState() => _NewDeviceLinkScreenState();
}

class _NewDeviceLinkScreenState extends State<NewDeviceLinkScreen> {
  final _server = TextEditingController(text: defaultRelayUrl);
  PairingInitiator? _initiator;
  bool _busy = false;
  bool _showDev = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    PairingInitiator.create().then((n) => setState(() => _initiator = n));
  }

  Future<void> _start() async {
    final l = AppLocalizations.of(context);
    final n = _initiator;
    if (n == null) return;
    final url = normalizeRelayUrl(_server.text);
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final result = await RelayPairing.runNewDevice(
        relayUrl: url,
        n: n,
        confirm: (sas) => confirmSasDialog(context, sas),
      );
      if (result == null) {
        setState(() {
          _busy = false;
          _error = l.linkCancelled;
        });
        return;
      }
      final acct = result.account;
      await widget.vault.kvPut(
          'identity',
          jsonEncode({
            'edSeed': b64(acct.deviceEdSeed),
            'xSeed': b64(acct.deviceXSeed)
          }));
      await widget.vault.kvPut('account', jsonEncode(acct.toJson()));
      await widget.vault.kvPut('display_name', result.data.displayName ?? 'Me');
      await widget.vault.kvPut('server_url', url, sensitive: false);
      // Remember the device that linked us, so our messages mirror back to it.
      await widget.vault.kvPut(
          'my_devices', jsonEncode([result.data.hostDeviceCert.toJson()]),
          sensitive: false);
      for (final b in result.data.contacts) {
        final dev = b.devices.first;
        final rid = b64url(await sha256Bytes(dev.deviceEdPub));
        await widget.vault.db.insert(
          'contacts',
          {
            'rid': rid,
            'enc_bundle': await widget.vault.seal(jsonEncode(ContactBundle(
                    edPub: dev.deviceEdPub,
                    xPub: dev.deviceXPub,
                    bindingSig: dev.sig)
                .toJson())),
            'enc_name': await widget.vault.seal(b.displayName ?? 'Unknown'),
            'ttl_seconds': 0,
            'verified': 0,
            'created_ms': DateTime.now().millisecondsSinceEpoch,
          },
          conflictAlgorithm: null,
        );
      }
      await widget.onDone();
    } catch (e) {
      setState(() {
        _busy = false;
        _error = l.linkFailed('$e');
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final code = _initiator?.code.text;
    return Scaffold(
      appBar: AppBar(title: Text(l.linkToAccount)),
      body: ListView(
        padding: EdgeInsets.fromLTRB(
            24, 24, 24, 24 + MediaQuery.paddingOf(context).bottom),
        children: [
          Text(
            l.linkJoinHelp,
            style: TextStyle(color: context.z.textSecondary, height: 1.5),
          ),
          const SizedBox(height: 28),
          Center(
            child: code == null
                ? const CircularProgressIndicator()
                : SelectableText(
                    code,
                    style: TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 26,
                        letterSpacing: 3,
                        color: context.z.accent),
                  ),
          ),
          if (code != null)
            Center(
              child: TextButton.icon(
                icon: const Icon(Icons.copy, size: 16),
                label: Text(l.copyCode),
                onPressed: () => Clipboard.setData(ClipboardData(text: code)),
              ),
            ),
          const SizedBox(height: 28),
          if (_showDev) ...[
            TextField(
              controller: _server,
              decoration: InputDecoration(
                labelText: l.relayAddressDev,
                helperText: l.relayHelpLink,
                helperMaxLines: 2,
              ),
            ),
            const SizedBox(height: 12),
          ],
          Center(
            child: TextButton(
              onPressed: () => setState(() => _showDev = !_showDev),
              child: Text(
                _showDev ? l.hideDevOptions : l.devOptions,
                style: TextStyle(color: context.z.textSecondary, fontSize: 12),
              ),
            ),
          ),
          const SizedBox(height: 12),
          if (_error != null)
            Padding(
              padding: const EdgeInsets.only(bottom: 14),
              child: Text(_error!, style: TextStyle(color: context.z.danger)),
            ),
          FilledButton(
            style: FilledButton.styleFrom(
              backgroundColor: context.z.accent,
              foregroundColor: context.z.onAccent,
              padding: const EdgeInsets.symmetric(vertical: 16),
            ),
            onPressed: (_busy || _initiator == null) ? null : _start,
            child: _busy
                ? const SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(strokeWidth: 2))
                : Text(l.linkStart),
          ),
        ],
      ),
    );
  }
}

/// Manage the devices on this account: this device, any linked devices, with
/// the ability to link a new one or revoke an existing one. Adding and revoking
/// are available only on the root device (the one that created the account).
class LinkedDevicesScreen extends StatefulWidget {
  const LinkedDevicesScreen({super.key});
  @override
  State<LinkedDevicesScreen> createState() => _LinkedDevicesScreenState();
}

class _LinkedDevicesScreenState extends State<LinkedDevicesScreen> {
  bool _loading = true;
  bool _isRoot = false;
  DeviceCertificate? _thisDevice;
  List<DeviceCertificate> _linked = const [];

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final chat = context.read<ChatService>();
    final me = await chat.thisDeviceCert();
    final linked = await chat.linkedDevices();
    final root = await chat.holdsAccountRoot();
    if (!mounted) return;
    setState(() {
      _thisDevice = me;
      _linked = linked;
      _isRoot = root;
      _loading = false;
    });
  }

  Future<void> _linkNew() async {
    await Navigator.of(context)
        .push(MaterialPageRoute(builder: (_) => const HostLinkScreen()));
    if (!mounted) return;
    setState(() => _loading = true);
    await _load();
  }

  Future<void> _remove(DeviceCertificate cert) async {
    final l = AppLocalizations.of(context);
    final chat = context.read<ChatService>();
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(l.linkRevokeTitle),
        content: Text(
          l.linkRevokeBody(cert.deviceId),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: Text(l.cancel)),
          FilledButton(
              style: FilledButton.styleFrom(backgroundColor: context.z.danger),
              onPressed: () => Navigator.pop(ctx, true),
              child: Text(l.revoke)),
        ],
      ),
    );
    if (ok != true) return;
    await chat.removeMyDevice(cert);
    if (!mounted) return;
    setState(() => _loading = true);
    await _load();
  }

  String _fp(DeviceCertificate c) {
    final s = b64url(c.deviceEdPub);
    return s.length <= 12 ? s : s.substring(0, 12);
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    return Scaffold(
      appBar: AppBar(title: Text(l.linkedDevices)),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : ListView(
              padding: EdgeInsets.fromLTRB(
                  20, 20, 20, 20 + MediaQuery.paddingOf(context).bottom),
              children: [
                if (_thisDevice != null)
                  _DeviceTile(
                    title: _thisDevice!.deviceId,
                    fingerprint: _fp(_thisDevice!),
                    isThisDevice: true,
                  ),
                for (final d in _linked)
                  _DeviceTile(
                    title: d.deviceId,
                    fingerprint: _fp(d),
                    onRemove: _isRoot ? () => _remove(d) : null,
                  ),
                if (_linked.isEmpty)
                  Padding(
                    padding: EdgeInsets.symmetric(vertical: 8),
                    child: Text(
                      l.linkNoneYet,
                      style: TextStyle(
                          color: context.z.textSecondary, fontSize: 13),
                    ),
                  ),
                const SizedBox(height: 24),
                if (_isRoot)
                  FilledButton.icon(
                    style: FilledButton.styleFrom(
                      backgroundColor: context.z.accent,
                      foregroundColor: context.z.onAccent,
                      padding: const EdgeInsets.symmetric(vertical: 16),
                    ),
                    icon: const Icon(Icons.add_link),
                    label: Text(l.linkADevice),
                    onPressed: _linkNew,
                  )
                else
                  Text(
                    l.linkNotRoot,
                    style: TextStyle(
                        color: context.z.textSecondary,
                        fontSize: 13,
                        height: 1.5),
                  ),
                const SizedBox(height: 20),
                Text(
                  l.linkRevokeNote,
                  style: TextStyle(
                      color: context.z.textSecondary,
                      fontSize: 12,
                      height: 1.5),
                ),
              ],
            ),
    );
  }
}

class _DeviceTile extends StatelessWidget {
  final String title;
  final String fingerprint;
  final bool isThisDevice;
  final VoidCallback? onRemove;
  const _DeviceTile({
    required this.title,
    required this.fingerprint,
    this.isThisDevice = false,
    this.onRemove,
  });

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    return Card(
      color: context.z.surface,
      margin: const EdgeInsets.only(bottom: 10),
      child: ListTile(
        leading: Icon(
          isThisDevice ? Icons.smartphone : Icons.devices_other,
          color: context.z.accent,
        ),
        title: Row(
          children: [
            Flexible(child: Text(title, overflow: TextOverflow.ellipsis)),
            if (isThisDevice) ...[
              const SizedBox(width: 8),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                decoration: BoxDecoration(
                  color: context.z.accent.withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(6),
                ),
                child: Text(l.linkThisDevice,
                    style: TextStyle(fontSize: 11, color: context.z.accent)),
              ),
            ],
          ],
        ),
        subtitle: Text(l.linkKeyFingerprint(fingerprint),
            style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
        trailing: onRemove == null
            ? null
            : IconButton(
                icon: Icon(Icons.delete_outline, color: context.z.danger),
                tooltip: l.linkRevokeDevice,
                onPressed: onRemove,
              ),
      ),
    );
  }
}
