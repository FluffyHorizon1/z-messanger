import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import 'package:z_protocol/z_protocol.dart';

import '../core/chat_service.dart';
import '../core/relay_url.dart';
import '../core/vault.dart';
import 'theme.dart';

/// Blocking dialog: the user compares the safety string on both screens.
Future<bool> confirmSasDialog(BuildContext context, String sas) async {
  final ok = await showDialog<bool>(
    context: context,
    barrierDismissible: false,
    builder: (ctx) => AlertDialog(
      title: const Text('Compare the safety code'),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const Text('This exact code must show on BOTH devices:'),
          const SizedBox(height: 18),
          Text(
            sas,
            style: const TextStyle(
                fontSize: 40,
                fontFamily: 'monospace',
                letterSpacing: 6,
                color: ZTheme.accent),
          ),
          const SizedBox(height: 12),
          const Text(
            'If they differ, cancel — someone may be intercepting the link.',
            textAlign: TextAlign.center,
            style: TextStyle(fontSize: 12, color: ZTheme.textSecondary),
          ),
        ],
      ),
      actions: [
        TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('They differ — cancel')),
        FilledButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('They match')),
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
            ? 'Device linked. It now carries your account and contacts.'
            : 'Link cancelled.';
      });
    } catch (e) {
      setState(() {
        _busy = false;
        _status = 'Link failed: $e';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Link a device')),
      body: ListView(
        padding: const EdgeInsets.all(24),
        children: [
          const Text(
            'On the device you want to add, install Z and choose '
            '"Link to an existing account". It will show a pairing code — '
            'enter it here.',
            style: TextStyle(color: ZTheme.textSecondary, height: 1.5),
          ),
          const SizedBox(height: 24),
          TextField(
            controller: _code,
            autofocus: true,
            textCapitalization: TextCapitalization.characters,
            style: const TextStyle(fontFamily: 'monospace', letterSpacing: 2),
            decoration: const InputDecoration(
              labelText: 'Pairing code',
              hintText: 'ABCDE-FGHIJ-…',
            ),
          ),
          const SizedBox(height: 20),
          FilledButton(
            style: FilledButton.styleFrom(
              backgroundColor: ZTheme.accent,
              foregroundColor: Colors.black,
              padding: const EdgeInsets.symmetric(vertical: 16),
            ),
            onPressed: _busy ? null : _link,
            child: _busy
                ? const SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(strokeWidth: 2))
                : const Text('Link device'),
          ),
          if (_status != null)
            Padding(
              padding: const EdgeInsets.only(top: 18),
              child: Text(_status!,
                  style: TextStyle(
                      color: _ok ? ZTheme.ok : ZTheme.textSecondary)),
            ),
          const SizedBox(height: 24),
          const Text(
            'Live message sync across your devices arrives in a follow-up '
            'update; linking establishes the trusted, verified connection now.',
            style: TextStyle(color: ZTheme.textSecondary, fontSize: 12),
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
  final _server = TextEditingController(text: 'wss://z-relay.onrender.com');
  PairingInitiator? _initiator;
  bool _busy = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    PairingInitiator.create().then((n) => setState(() => _initiator = n));
  }

  Future<void> _start() async {
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
          _error = 'Link cancelled.';
        });
        return;
      }
      final acct = result.account;
      await widget.vault.kvPut(
          'identity',
          jsonEncode(
              {'edSeed': b64(acct.deviceEdSeed), 'xSeed': b64(acct.deviceXSeed)}));
      await widget.vault.kvPut('account', jsonEncode(acct.toJson()));
      await widget.vault
          .kvPut('display_name', result.data.displayName ?? 'Me');
      await widget.vault.kvPut('server_url', url, sensitive: false);
      // Remember the device that linked us, so our messages mirror back to it.
      await widget.vault.kvPut(
          'my_devices',
          jsonEncode([result.data.hostDeviceCert.toJson()]),
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
        _error = 'Link failed: $e';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final code = _initiator?.code.text;
    return Scaffold(
      appBar: AppBar(title: const Text('Link to an account')),
      body: ListView(
        padding: const EdgeInsets.all(24),
        children: [
          const Text(
            'On your existing device, open Settings → Linked devices → '
            '"Link a device", then enter the code below.',
            style: TextStyle(color: ZTheme.textSecondary, height: 1.5),
          ),
          const SizedBox(height: 28),
          Center(
            child: code == null
                ? const CircularProgressIndicator()
                : SelectableText(
                    code,
                    style: const TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 26,
                        letterSpacing: 3,
                        color: ZTheme.accent),
                  ),
          ),
          if (code != null)
            Center(
              child: TextButton.icon(
                icon: const Icon(Icons.copy, size: 16),
                label: const Text('Copy code'),
                onPressed: () =>
                    Clipboard.setData(ClipboardData(text: code)),
              ),
            ),
          const SizedBox(height: 28),
          TextField(
            controller: _server,
            decoration: const InputDecoration(
              labelText: 'Relay address',
              helperText: 'The same relay your other device uses.',
            ),
          ),
          const SizedBox(height: 20),
          if (_error != null)
            Padding(
              padding: const EdgeInsets.only(bottom: 14),
              child:
                  Text(_error!, style: const TextStyle(color: ZTheme.danger)),
            ),
          FilledButton(
            style: FilledButton.styleFrom(
              backgroundColor: ZTheme.accent,
              foregroundColor: Colors.black,
              padding: const EdgeInsets.symmetric(vertical: 16),
            ),
            onPressed: (_busy || _initiator == null) ? null : _start,
            child: _busy
                ? const SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(strokeWidth: 2))
                : const Text('Start linking'),
          ),
        ],
      ),
    );
  }
}
