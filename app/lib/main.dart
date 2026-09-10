import 'dart:async';
import 'dart:convert';
import 'dart:io' show Platform;
import 'dart:typed_data';

import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:flutter/material.dart';

import 'l10n/app_localizations.dart';
import 'package:flutter/services.dart'
    show SystemChrome, SystemUiMode, SystemUiOverlayStyle;
import 'package:provider/provider.dart';
import 'package:z_protocol/z_protocol.dart';

import 'core/app_lock.dart';
import 'core/chat_service.dart';
import 'core/prefs.dart';
import 'core/push_service.dart';
import 'core/relay_url.dart';
import 'core/transport.dart';
import 'core/vault.dart';
import 'ui/home_screen.dart';
import 'ui/lock_screen.dart';
import 'ui/onboarding_screen.dart';
import 'ui/theme.dart';
import 'ui/unlock_screen.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  if (!kIsWeb && Platform.isAndroid) {
    // Register the background wake-ping handler (desktop has no FCM).
    FirebaseMessaging.onBackgroundMessage(zPushBackgroundHandler);
    // Edge-to-edge on every Android version, not just 15+ where it is the
    // default for apps targeting SDK 35: the system bars become transparent
    // overlays and every screen insets its own content (SafeArea / the
    // MediaQuery padding that ListView and Scaffold apply themselves).
    // The bar icons' brightness follows the theme: see the AnnotatedRegion
    // in _shell.
    SystemChrome.setEnabledSystemUIMode(SystemUiMode.edgeToEdge);
  }
  runApp(const ZApp());
}

class ZApp extends StatelessWidget {
  const ZApp({super.key});

  @override
  Widget build(BuildContext context) {
    // NOTE: the Bootstrapper builds the MaterialApp itself so that, once the
    // service is up, the providers sit ABOVE the Navigator — pushed routes
    // must be able to see ChatService/Transport.
    return const Bootstrapper();
  }
}

/// [overlay] (the screen lock, 7.8) is laid over the Navigator through
/// `builder`, so whatever the user had open survives the lock: the routes
/// underneath are kept, just hidden, unfocused and pointer-blocked. The
/// wrapper chain is always present (only its flags change) so the Navigator
/// keeps its place in the tree — and its stack — when the lock comes and
/// goes. The overlay gets its own Overlay so text fields inside it work
/// without the Navigator's.
MaterialApp _shell(
        {required Widget home, Widget? overlay, required ThemeMode mode}) =>
    MaterialApp(
      title: 'Z',
      debugShowCheckedModeBanner: false,
      // 15.4: strings come from lib/l10n/*.arb. Only the pre-account screens
      // are migrated so far; the rest are still literals in the widgets and
      // `tool/check_l10n.py` reports how many remain per file.
      localizationsDelegates: AppLocalizations.localizationsDelegates,
      supportedLocales: AppLocalizations.supportedLocales,
      theme: ZTheme.light(),
      darkTheme: ZTheme.dark(),
      themeMode: mode,
      builder: (context, child) {
        // Transparent system bars whose icons match the palette in effect
        // (an AppBar overrides this for its own screen, as it should).
        final dark = Theme.of(context).brightness == Brightness.dark;
        return AnnotatedRegion<SystemUiOverlayStyle>(
          value: SystemUiOverlayStyle(
            statusBarColor: Colors.transparent,
            statusBarIconBrightness: dark ? Brightness.light : Brightness.dark,
            statusBarBrightness: dark ? Brightness.dark : Brightness.light,
            systemNavigationBarColor: Colors.transparent,
            systemNavigationBarDividerColor: Colors.transparent,
            systemNavigationBarContrastEnforced: false,
            systemNavigationBarIconBrightness:
                dark ? Brightness.light : Brightness.dark,
          ),
          child: Stack(
            fit: StackFit.expand,
            children: [
              ExcludeFocus(
                excluding: overlay != null,
                child: ExcludeSemantics(
                  excluding: overlay != null,
                  child:
                      IgnorePointer(ignoring: overlay != null, child: child!),
                ),
              ),
              if (overlay != null) Overlay.wrap(child: overlay),
            ],
          ),
        );
      },
      home: home,
    );

/// Opens the encrypted vault, loads (or asks the user to create) an identity,
/// then boots the chat service.
class Bootstrapper extends StatefulWidget {
  const Bootstrapper({super.key});

  @override
  State<Bootstrapper> createState() => _BootstrapperState();
}

class _BootstrapperState extends State<Bootstrapper>
    with WidgetsBindingObserver {
  Vault? _vault;
  ChatService? _service;
  PushService? _push;
  AppLock? _appLock;
  AppPrefs? _prefs;
  bool _needsOnboarding = false;
  bool _locked = false; // vault exists but needs a passphrase
  bool _biometricOffered = false; // biometric unlock is on: offer the prompt
  String? _unlockError;
  bool _unlocking = false;
  Object? _fatal;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _boot();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _appLock?.removeListener(_onLockChanged);
    _prefs?.removeListener(_onLockChanged);
    super.dispose();
  }

  void _onLockChanged() {
    if (mounted) setState(() {});
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    final lock = _appLock;
    final wasLocked = lock?.locked ?? false;
    lock?.onLifecycle(state);
    if (state == AppLifecycleState.resumed) {
      _service?.transport.nudge();
      _service?.flushOutbox();
      // Came back to an app that was already locked (the prompt had been
      // dismissed before leaving): ask again. A lock that was just applied
      // by onLifecycle prompts itself when its screen appears.
      if (lock != null && wasLocked && lock.locked && !lock.authInFlight) {
        lock.requestUnlock(passphraseFallback: _vault?.hasPassphrase ?? false);
      }
    }
  }

  Future<void> _boot() async {
    try {
      final root = await Vault.defaultRoot();
      // Theme first: every screen below, unlock and lock included, uses it.
      final prefs = AppPrefs(root: root);
      await prefs.load();
      prefs.addListener(_onLockChanged);
      _prefs = prefs;

      final lock = AppLock(root: root);
      await lock.load();
      lock.addListener(_onLockChanged);
      _appLock = lock;

      final status = await Vault.inspect();
      if (status.requiresPassphrase) {
        // The passphrase is the gate at launch. With biometric unlock on,
        // try the OS prompt first; the passphrase screen stays the fallback.
        _biometricOffered = lock.settings.biometricUnlock;
        setState(() => _locked = true);
        if (_biometricOffered) await _tryBiometricUnlock();
        return;
      }
      // No passphrase: the screen lock (if on) gates the launch. The vault
      // opens and the service starts underneath the lock screen meanwhile.
      if (lock.settings.screenLock) lock.lockNow();
      await _openAndStart(null);
    } catch (e) {
      setState(() => _fatal = e);
    }
  }

  /// Biometric unlock of a passphrase vault (7.8): the OS prompt releases
  /// the stored pass key, which opens the vault without the passphrase.
  Future<void> _tryBiometricUnlock() async {
    final lock = _appLock;
    if (lock == null || _unlocking) return;
    setState(() {
      _unlocking = true;
      _unlockError = null;
    });
    try {
      final passKey = await lock.passKeyAfterPrompt();
      if (passKey == null) {
        // Cancelled / unavailable / nothing stored: back to the passphrase.
        if (mounted) setState(() => _unlocking = false);
        return;
      }
      await _openAndStart(null, passKey: passKey);
    } on WrongPassphraseException {
      // Stale pass key (passphrase changed without re-enrolling): forget it.
      await lock.disableBiometricUnlock();
      if (mounted) {
        setState(() {
          _unlocking = false;
          _biometricOffered = false;
          _unlockError =
              'Biometric unlock is out of date — enter your passphrase, then '
              'turn it on again in Settings.';
        });
      }
    } on BiometricKeyInvalidatedException {
      // The hardware key was reset (biometrics re-enrolled); already off.
      if (mounted) {
        setState(() {
          _unlocking = false;
          _biometricOffered = false;
          _unlockError =
              'Your fingerprints or face changed, so biometric unlock was '
              'reset. Enter your passphrase, then turn it on again in '
              'Settings.';
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _unlocking = false;
          _unlockError = '$e';
        });
      }
    }
  }

  Future<void> _openAndStart(String? passphrase, {Uint8List? passKey}) async {
    final vault = await Vault.open(passphrase: passphrase, passKey: passKey);
    // Typing the passphrase (or passing the biometric prompt) satisfies the
    // screen lock too — no second prompt at launch.
    if (passphrase != null || passKey != null) _appLock?.markAuthenticated();
    final idJson = await vault.kvGet('identity');
    if (idJson == null) {
      setState(() {
        _vault = vault;
        _locked = false;
        _needsOnboarding = true;
      });
      return;
    }
    await _startService(vault, idJson);
  }

  Future<void> _tryUnlock(String passphrase) async {
    setState(() {
      _unlocking = true;
      _unlockError = null;
    });
    try {
      await _openAndStart(passphrase);
    } on WrongPassphraseException {
      setState(() {
        _unlocking = false;
        _unlockError = 'Incorrect passphrase. Try again.';
      });
    } catch (e) {
      setState(() {
        _unlocking = false;
        _unlockError = '$e';
      });
    }
  }

  Future<void> _startService(Vault vault, String idJson) async {
    final identity = await ZIdentity.fromJson(
        (jsonDecode(idJson) as Map).cast<String, Object?>());
    final name = await vault.kvGet('display_name') ?? 'Me';
    final serverUrl = await vault.kvGet('server_url') ?? defaultRelayUrl;
    final transport = Transport(identity: identity, serverUrl: serverUrl);
    final service = await ChatService.init(
      vault: vault,
      identity: identity,
      displayName: name,
      transport: transport,
    );
    // Preload chat previews (1:1 and group threads).
    for (final rid in [...service.contacts.keys, ...service.groups.keys]) {
      await service.loadMessages(rid);
    }
    // Push (Android): registers this device's wake token with the relay.
    final push = PushService(transport: transport, vault: vault);
    unawaited(push.init());
    setState(() {
      _vault = vault;
      _service = service;
      _push = push;
      _locked = false;
      _needsOnboarding = false;
      _unlocking = false;
    });
  }

  Future<void> _onboardingDone() async {
    final vault = _vault!;
    final idJson = await vault.kvGet('identity');
    await _startService(vault, idJson!);
  }

  @override
  Widget build(BuildContext context) {
    final mode = _prefs?.themeMode ?? ThemeMode.system;
    if (_fatal != null) {
      return _shell(
        mode: mode,
        // Builder: the palette lives in the MaterialApp below this widget.
        home: Builder(
          builder: (ctx) => Scaffold(
            body: Center(
              child: Padding(
                padding: const EdgeInsets.all(24),
                child: Text(
                  'Z could not start:\n$_fatal',
                  textAlign: TextAlign.center,
                  style: TextStyle(color: ctx.z.danger),
                ),
              ),
            ),
          ),
        ),
      );
    }
    if (_locked) {
      return _shell(
        mode: mode,
        home: UnlockScreen(
          onUnlock: _tryUnlock,
          onBiometric: _biometricOffered ? _tryBiometricUnlock : null,
          busy: _unlocking,
          error: _unlockError,
        ),
      );
    }
    if (_needsOnboarding && _vault != null) {
      return _shell(
        mode: mode,
        home: OnboardingScreen(vault: _vault!, onDone: _onboardingDone),
      );
    }
    final lock = _appLock;
    final overlay = lock != null && lock.locked
        ? LockScreen(
            lock: lock,
            verifyPassphrase: (_vault?.hasPassphrase ?? false)
                ? (p) => _vault!.verifyPassphrase(p)
                : null,
          )
        : null;
    final service = _service;
    if (service == null) {
      return _shell(
        mode: mode,
        home: Builder(
          builder: (ctx) => Scaffold(
            body: Center(
              child: Text('Z',
                  style: TextStyle(
                      fontSize: 64,
                      fontWeight: FontWeight.w900,
                      color: ctx.z.accent)),
            ),
          ),
        ),
        overlay: overlay,
      );
    }
    return MultiProvider(
      providers: [
        ChangeNotifierProvider<ChatService>.value(value: service),
        ChangeNotifierProvider<Transport>.value(value: service.transport),
        ChangeNotifierProvider<PushService>.value(value: _push!),
        ChangeNotifierProvider<AppLock>.value(value: lock!),
        ChangeNotifierProvider<AppPrefs>.value(value: _prefs!),
      ],
      child: _shell(mode: mode, home: const HomeScreen(), overlay: overlay),
    );
  }
}
