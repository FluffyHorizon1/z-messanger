import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:z_protocol/z_protocol.dart';

import 'core/chat_service.dart';
import 'core/transport.dart';
import 'core/vault.dart';
import 'ui/home_screen.dart';
import 'ui/onboarding_screen.dart';
import 'ui/theme.dart';
import 'ui/unlock_screen.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
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

MaterialApp _shell({required Widget home}) => MaterialApp(
      title: 'Z',
      debugShowCheckedModeBanner: false,
      theme: ZTheme.dark(),
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
  bool _needsOnboarding = false;
  bool _locked = false; // vault exists but needs a passphrase
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
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      _service?.transport.nudge();
      _service?.flushOutbox();
    }
  }

  Future<void> _boot() async {
    try {
      final status = await Vault.inspect();
      if (status.requiresPassphrase) {
        setState(() => _locked = true); // show the unlock screen
        return;
      }
      await _openAndStart(null);
    } catch (e) {
      setState(() => _fatal = e);
    }
  }

  Future<void> _openAndStart(String? passphrase) async {
    final vault = await Vault.open(passphrase: passphrase);
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
    final serverUrl =
        await vault.kvGet('server_url') ?? 'ws://localhost:8080';
    final transport = Transport(identity: identity, serverUrl: serverUrl);
    final service = await ChatService.init(
      vault: vault,
      identity: identity,
      displayName: name,
      transport: transport,
    );
    // Preload chat previews.
    for (final rid in service.contacts.keys) {
      await service.loadMessages(rid);
    }
    setState(() {
      _vault = vault;
      _service = service;
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
    if (_fatal != null) {
      return _shell(
        home: Scaffold(
          body: Center(
            child: Padding(
              padding: const EdgeInsets.all(24),
              child: Text(
                'Z could not start:\n$_fatal',
                textAlign: TextAlign.center,
                style: const TextStyle(color: ZTheme.danger),
              ),
            ),
          ),
        ),
      );
    }
    if (_locked) {
      return _shell(
        home: UnlockScreen(
          onUnlock: _tryUnlock,
          busy: _unlocking,
          error: _unlockError,
        ),
      );
    }
    if (_needsOnboarding && _vault != null) {
      return _shell(
        home: OnboardingScreen(vault: _vault!, onDone: _onboardingDone),
      );
    }
    final service = _service;
    if (service == null) {
      return _shell(
        home: const Scaffold(
          body: Center(
            child: Text('Z',
                style: TextStyle(
                    fontSize: 64,
                    fontWeight: FontWeight.w900,
                    color: ZTheme.accent)),
          ),
        ),
      );
    }
    return MultiProvider(
      providers: [
        ChangeNotifierProvider<ChatService>.value(value: service),
        ChangeNotifierProvider<Transport>.value(value: service.transport),
      ],
      child: _shell(home: const HomeScreen()),
    );
  }
}
