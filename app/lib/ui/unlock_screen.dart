import 'package:flutter/material.dart';

import '../l10n/app_localizations.dart';

import 'theme.dart';

/// Shown at launch when the vault is passphrase-protected. The passphrase is
/// combined with the device keystore secret to unwrap the local vault key; it
/// never leaves the device and is never sent to any server. With biometric
/// unlock enabled (7.8) the bootstrapper tries the OS prompt first and
/// [onBiometric] re-offers it here.
class UnlockScreen extends StatefulWidget {
  final Future<void> Function(String passphrase) onUnlock;
  final Future<void> Function()? onBiometric;
  final bool busy;
  final String? error;
  const UnlockScreen(
      {super.key,
      required this.onUnlock,
      this.onBiometric,
      this.busy = false,
      this.error});

  @override
  State<UnlockScreen> createState() => _UnlockScreenState();
}

class _UnlockScreenState extends State<UnlockScreen> {
  final _ctrl = TextEditingController();
  bool _obscure = true;

  void _submit() {
    final p = _ctrl.text;
    if (p.isEmpty) return;
    widget.onUnlock(p);
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
            constraints: const BoxConstraints(maxWidth: 400),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Icon(Icons.lock_outline, size: 56, color: context.z.accent),
                const SizedBox(height: 16),
                Text('Z',
                    textAlign: TextAlign.center,
                    style: TextStyle(
                        fontSize: 56,
                        fontWeight: FontWeight.w900,
                        color: context.z.accent,
                        height: 1)),
                const SizedBox(height: 8),
                Text(
                  l.unlockPrompt,
                  textAlign: TextAlign.center,
                  style: TextStyle(color: context.z.textSecondary),
                ),
                const SizedBox(height: 28),
                TextField(
                  controller: _ctrl,
                  autofocus: true,
                  obscureText: _obscure,
                  enabled: !widget.busy,
                  onSubmitted: (_) => _submit(),
                  decoration: InputDecoration(
                    labelText: l.unlockPassphraseLabel,
                    suffixIcon: IconButton(
                      // The label states what the control DOES, and changes
                      // with the state, because a screen reader announces it
                      // in place of an icon nobody can see. "Visibility" would
                      // describe the glyph rather than the action.
                      tooltip: _obscure ? l.unlockShowPassphrase : l.unlockHidePassphrase,
                      icon: Icon(
                          _obscure ? Icons.visibility : Icons.visibility_off,
                          color: context.z.textSecondary),
                      onPressed: () => setState(() => _obscure = !_obscure),
                    ),
                  ),
                ),
                if (widget.error != null)
                  Padding(
                    padding: const EdgeInsets.only(top: 12),
                    child: Text(widget.error!,
                        style: TextStyle(color: context.z.danger)),
                  ),
                const SizedBox(height: 20),
                FilledButton(
                  style: FilledButton.styleFrom(
                    backgroundColor: context.z.accent,
                    foregroundColor: context.z.onAccent,
                    padding: const EdgeInsets.symmetric(vertical: 16),
                  ),
                  onPressed: widget.busy ? null : _submit,
                  child: widget.busy
                      ? const SizedBox(
                          width: 20,
                          height: 20,
                          child: CircularProgressIndicator(strokeWidth: 2))
                      : Text(l.unlockTitle),
                ),
                if (widget.onBiometric != null) ...[
                  const SizedBox(height: 12),
                  OutlinedButton.icon(
                    onPressed: widget.busy ? null : widget.onBiometric,
                    icon: const Icon(Icons.fingerprint),
                    label: Text(l.unlockUseBiometrics),
                  ),
                ],
                const SizedBox(height: 24),
                Text(
                  l.unlockFootnote,
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
