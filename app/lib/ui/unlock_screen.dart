import 'package:flutter/material.dart';

import '../l10n/app_localizations.dart';

import 'theme.dart';

/// Why the unlock screen is showing an error.
///
/// The bootstrapper raises these above the `MaterialApp`, where
/// `AppLocalizations` is not in scope, so it cannot build the sentence — it
/// says which case it is, and the words are chosen here, where the reader's
/// language is known (the 2026-09-14 review's finding 39: these were built as
/// English in `main.dart`, and `check_l10n.py` never scanned `main.dart`, so a
/// Spanish user met the passphrase and biometric errors in English).
sealed class UnlockError {
  const UnlockError();
}

/// The passphrase did not unwrap the vault.
class WrongPassphrase extends UnlockError {
  const WrongPassphrase();
}

/// The stored biometric pass key is stale (the passphrase changed without
/// re-enrolling); biometric unlock has been turned off.
class BiometricStale extends UnlockError {
  const BiometricStale();
}

/// The hardware key was invalidated (fingerprints or face re-enrolled);
/// biometric unlock is off.
class BiometricInvalidated extends UnlockError {
  const BiometricInvalidated();
}

/// Anything else — carries a raw diagnostic that has no translated form.
class UnexpectedUnlockError extends UnlockError {
  final String detail;
  const UnexpectedUnlockError(this.detail);
}

/// Shown at launch when the vault is passphrase-protected. The passphrase is
/// combined with the device keystore secret to unwrap the local vault key; it
/// never leaves the device and is never sent to any server. With biometric
/// unlock enabled (7.8) the bootstrapper tries the OS prompt first and
/// [onBiometric] re-offers it here.
class UnlockScreen extends StatefulWidget {
  final Future<void> Function(String passphrase) onUnlock;
  final Future<void> Function()? onBiometric;
  final bool busy;
  final UnlockError? error;
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

  /// The error in the reader's language. `WrongPassphrase` reuses the app-lock
  /// overlay's own string; the biometric cases have their own; the unexpected
  /// case shows its raw diagnostic, which has no translation.
  String _errorText(AppLocalizations l, UnlockError e) => switch (e) {
        WrongPassphrase() => l.lockIncorrectPassphrase,
        BiometricStale() => l.unlockBiometricStale,
        BiometricInvalidated() => l.unlockBiometricInvalidated,
        UnexpectedUnlockError(:final detail) => detail,
      };

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
                    child: Text(_errorText(l, widget.error!),
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
