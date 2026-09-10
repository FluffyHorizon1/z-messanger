import 'package:flutter/material.dart';

import '../l10n/app_localizations.dart';

import '../core/app_lock.dart';
import 'theme.dart';

/// The screen-lock gate (7.8). Sits above the whole navigation stack (see
/// the `builder` in `main.dart`), so the chat you were in is still there
/// once the OS prompt succeeds. The prompt is requested as soon as the screen
/// appears; the button re-requests it, and — when the vault has a passphrase
/// — that passphrase works as a fallback for a device whose biometrics are
/// locked out.
class LockScreen extends StatefulWidget {
  final AppLock lock;

  /// Verifies a typed passphrase against the open vault; null when the vault
  /// has no passphrase (or is not open yet), which hides the fallback.
  final Future<bool> Function(String passphrase)? verifyPassphrase;

  const LockScreen({super.key, required this.lock, this.verifyPassphrase});

  @override
  State<LockScreen> createState() => _LockScreenState();
}

class _LockScreenState extends State<LockScreen> {
  final _ctrl = TextEditingController();
  bool _showPassphrase = false;
  bool _checking = false;
  String? _passError;

  @override
  void initState() {
    super.initState();
    // Anything focused underneath (a chat's composer) must not keep the
    // keyboard; the lock owns input now.
    FocusManager.instance.primaryFocus?.unfocus();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) _prompt();
    });
  }

  @override
  void dispose() {
    _ctrl.dispose();
    super.dispose();
  }

  Future<void> _prompt() => widget.lock
      .requestUnlock(passphraseFallback: widget.verifyPassphrase != null);

  Future<void> _submitPassphrase() async {
    final verify = widget.verifyPassphrase;
    final pass = _ctrl.text;
    if (verify == null || pass.isEmpty || _checking) return;
    setState(() {
      _checking = true;
      _passError = null;
    });
    final ok = await verify(pass);
    if (!mounted) return;
    if (ok) {
      _ctrl.clear();
      widget.lock.markAuthenticated();
    } else {
      final l = AppLocalizations.of(context);
      setState(() {
        _checking = false;
        _passError = l.lockIncorrectPassphrase;
      });
    }
  }

  String? _status(AppLock lock, AppLocalizations l) {
    if (lock.authInFlight) return null;
    return switch (lock.lastResult) {
      null || GateResult.ok => null,
      GateResult.cancelled => l.lockCancelled,
      GateResult.failed =>
        l.lockCouldNotVerify,
      GateResult.unavailable =>
        l.lockNoBiometrics,
    };
  }

  @override
  Widget build(BuildContext context) => ListenableBuilder(
      listenable: widget.lock, builder: (context, _) => _build(context));

  Widget _build(BuildContext context) {
    final lock = widget.lock;
    final l = AppLocalizations.of(context);
    final status = _status(lock, l);
    final canFallback = widget.verifyPassphrase != null;
    return Scaffold(
      backgroundColor: context.z.bg,
      body: SafeArea(
          child: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(32),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 400),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Icon(Icons.fingerprint, size: 64, color: context.z.accent),
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
                  l.lockedTitle,
                  textAlign: TextAlign.center,
                  style: TextStyle(color: context.z.textSecondary),
                ),
                if (status != null)
                  Padding(
                    padding: const EdgeInsets.only(top: 16),
                    child: Text(status,
                        textAlign: TextAlign.center,
                        style: TextStyle(color: context.z.warn)),
                  ),
                const SizedBox(height: 28),
                FilledButton.icon(
                  style: FilledButton.styleFrom(
                    backgroundColor: context.z.accent,
                    foregroundColor: context.z.onAccent,
                    padding: const EdgeInsets.symmetric(vertical: 16),
                  ),
                  onPressed: lock.authInFlight ? null : _prompt,
                  icon: const Icon(Icons.lock_open),
                  label: Text(lock.authInFlight ? l.lockWaiting : l.lockUnlock),
                ),
                if (canFallback) ...[
                  const SizedBox(height: 12),
                  if (!_showPassphrase)
                    TextButton(
                      onPressed: () => setState(() => _showPassphrase = true),
                      child: Text(l.lockUsePassphraseInstead,
                          style: TextStyle(color: context.z.textSecondary)),
                    )
                  else ...[
                    TextField(
                      controller: _ctrl,
                      autofocus: true,
                      obscureText: true,
                      enabled: !_checking,
                      onSubmitted: (_) => _submitPassphrase(),
                      decoration: InputDecoration(
                          labelText: l.unlockPassphraseLabel,
                          border: const OutlineInputBorder()),
                    ),
                    if (_passError != null)
                      Padding(
                        padding: const EdgeInsets.only(top: 12),
                        child: Text(_passError!,
                            style: TextStyle(color: context.z.danger)),
                      ),
                    const SizedBox(height: 12),
                    OutlinedButton(
                      onPressed: _checking ? null : _submitPassphrase,
                      child: _checking
                          ? const SizedBox(
                              width: 20,
                              height: 20,
                              child: CircularProgressIndicator(strokeWidth: 2))
                          : Text(l.lockUnlockWithPassphrase),
                    ),
                  ],
                ],
              ],
            ),
          ),
        ),
      )),
    );
  }
}
