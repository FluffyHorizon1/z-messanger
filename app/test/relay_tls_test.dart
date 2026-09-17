// A relay that isn't TLS, and one button that said so.
//
// Four things wrote `server_url`: onboarding, linking a device, the
// developer-mode field in Settings, and a restored archive's own `meta`
// record. Exactly one of them ever mentioned that a `ws://` address is not
// TLS — a notice that appeared beside a "Test" button, which nobody has to
// press. So three of the four, plus the one that takes its answer from a
// FILE, dialled a cleartext public relay without a word.
//
// What that costs is not the messages: those are end-to-end encrypted
// whatever the transport, and the app has always said so. It is the routing
// metadata — which mailbox, how much, how often — which is what the rest of
// this design spends its whole effort on (sealed sender, per-device routing
// ids, padding buckets, R15/R18/R19). Handing it to anyone on the path
// because a URL was typed with one `s` missing is not a trade anyone made.
//
// Cleartext to a local or LAN address stays free of charge. That is what
// `cleartextTrafficPermitted` is in the manifest for, and there is nobody on
// that path to hide from.
//
// Criteria, each a test below:
//  1. the funnel refuses a public ws:// address that nobody agreed to, and
//     accepts one that somebody did;
//  2. a TLS or local address is never a question — no confirmation, no
//     friction, for the case cleartext exists for;
//  3. an archive cannot point a restored client at a cleartext relay, because
//     an archive is a file and a file can come from anywhere;
//  4. and the screens ask: the confirmation refuses by default and returns
//     true only when the button is pressed;
//  5. "local" is decided on an address and never on a name. Until 2026-09-17
//     the LAN test was a string prefix on the host, so `ws://10.relay.example.net`
//     was on the LAN: no dialog, adopted, and every envelope's routing
//     metadata sent in the clear to whoever owns that name — from a pasted
//     string and from a restored archive alike, since both doors used the
//     one predicate (the 2026-09-14 review's finding 10; C36).
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/archive.dart';
import 'package:zapp/core/relay_url.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/l10n/app_localizations.dart';
import 'package:zapp/ui/relay_warning.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  final temps = <Directory>[];

  tearDownAll(() {
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<Vault> freshVault(String name) async {
    final d = await Directory.systemTemp.createTemp('z_tls_$name');
    temps.add(d);
    return Vault.open(rootOverride: d);
  }

  /// Addresses with nobody between you and them worth hiding from.
  const localish = <String>[
    'ws://localhost:8080',
    'ws://127.0.0.1:8080',
    'ws://10.0.2.2:8080',
    'ws://192.168.1.50:8080',
    'ws://10.4.4.4:8080',
    'ws://172.20.0.9:8080',
    'ws://fileserver.local:8080',
  ];

  /// Addresses on somebody else's network.
  const public = <String>[
    'ws://relay.example.com',
    'http://relay.example.com',
    'ws://203.0.113.9:8080',
    'ws://172.15.0.1:8080', // just outside the private range
    'ws://172.32.0.1:8080', // and just past the other end
    // Names that begin like addresses, which a prefix test took for one.
    'ws://10.relay.example.net',
    'ws://192.168.attacker.io',
    'ws://172.16.example.com',
    'ws://127.0.0.1.example.com',
    'ws://localhost.example.com',
    'ws://fileserver.local.example.com', // `.local` is a suffix, not a substring
    'ws://10.1', // an address the platform will not parse is not an address
    'ws://[2001:db8::1]:8080', // a public IPv6 address
  ];

  test('5. local is an address, never a name', () async {
    // Every name-shaped impostor above is public, and the archive door
    // — which cannot ask — refuses it too.
    for (final url in public) {
      expect(isSecureOrLocalRelay(normalizeRelayUrl(url)), isFalse, reason: url);
    }
    // And every address that IS local still is, in the forms it is typed:
    // loopback in both families, the three private ranges at their edges,
    // and the emulator alias.
    for (final url in [
      'ws://127.0.0.1:8080',
      'ws://127.255.255.254',
      'ws://[::1]:8080',
      'ws://10.0.0.1',
      'ws://10.255.255.255',
      'ws://10.0.2.2:8080',
      'ws://172.16.0.1',
      'ws://172.31.255.255',
      'ws://192.168.0.1',
      'ws://192.168.255.255',
      'ws://printer.local',
      'ws://localhost:9',
    ]) {
      expect(isSecureOrLocalRelay(normalizeRelayUrl(url)), isTrue, reason: url);
    }
  });

  test('1. a public cleartext relay is refused unless somebody agreed',
      () async {
    final vault = await freshVault('one');
    for (final url in public) {
      expect(await setRelayUrl(vault, url), RelayUrlOutcome.insecureRefused,
          reason: url);
      expect(await vault.kvGet('server_url'), isNull,
          reason: 'nothing was written for $url');
    }
    expect(await setRelayUrl(vault, 'ws://relay.example.com',
            acceptedInsecure: true),
        RelayUrlOutcome.saved,
        reason: 'and it is still possible, once the question has been asked');
    expect(await vault.kvGet('server_url'), 'ws://relay.example.com');
    expect(await setRelayUrl(vault, '  '), RelayUrlOutcome.empty);
    await vault.db.close();
  });

  test('2. TLS and local addresses are never a question', () async {
    final vault = await freshVault('two');
    for (final url in [...localish, 'wss://zmessengers.com', 'relay.example.com']) {
      expect(await setRelayUrl(vault, url), RelayUrlOutcome.saved,
          reason: '$url should need no confirmation');
      expect(isSecureOrLocalRelay(normalizeRelayUrl(url)), isTrue, reason: url);
    }
    // A bare host means TLS, so pasting a Render hostname is not a warning.
    expect(normalizeRelayUrl('relay.example.com'), 'wss://relay.example.com');
    await vault.db.close();
  });

  test('3. an archive cannot point a restored client at a cleartext relay',
      () async {
    Future<String?> restoredUrlFor(String stored, String tag) async {
      final code = await RecoveryCode.generate();
      final salt = randomBytes(16);
      final noncePrefix = randomBytes(16);
      final key = await ZArchive.deriveKey(await code.keyMaterial(), salt);
      final header = ZArchive.buildHeader(
          salt: salt, noncePrefix: noncePrefix, schema: 11, createdMs: 1);
      final d = await Directory.systemTemp.createTemp('z_tls_arc_$tag');
      temps.add(d);
      final file = File('${d.path}/a.zbk');
      final out = file.openWrite();
      out.add(header);
      out.add(const [0x0a]);
      var index = 0;
      Future<void> frame(int kind, List<int> payload) async {
        final sealed = await ZArchive.sealFrame(
            key: key,
            header: header,
            noncePrefix: noncePrefix,
            index: index++,
            kind: kind,
            payload: payload);
        out.add((ByteData(4)..setUint32(0, sealed.length)).buffer.asUint8List());
        out.add(sealed);
      }

      await frame(ZArchive.kindRecord,
          utf8.encode(jsonEncode({'t': 'meta', 'name': 'Me', 'server': stored})));
      await frame(
          ZArchive.kindEnd, utf8.encode(jsonEncode({'t': 'end', 'records': 1})));
      await out.flush();
      await out.close();

      final vault = await freshVault('r_$tag');
      await BackupArchive.import(vault: vault, file: file, code: code);
      final got = await vault.kvGet('server_url');
      await vault.db.close();
      return got;
    }

    expect(await restoredUrlFor('ws://relay.example.com', 'bad'), isNull,
        reason: 'a document does not get to choose a cleartext relay');
    expect(await restoredUrlFor('wss://relay.example.com', 'good'),
        'wss://relay.example.com',
        reason: 'an ordinary archive still restores the relay it was taken on');
    expect(await restoredUrlFor('ws://192.168.1.50:8080', 'lan'),
        'ws://192.168.1.50:8080',
        reason: 'and a LAN deployment restores onto its own LAN');
  });

  testWidgets('4. the confirmation refuses by default and asks only when it '
      'has to', (t) async {
    late BuildContext ctx;
    await t.pumpWidget(MaterialApp(
      localizationsDelegates: AppLocalizations.localizationsDelegates,
      supportedLocales: AppLocalizations.supportedLocales,
      home: Builder(builder: (c) {
        ctx = c;
        return const SizedBox();
      }),
    ));

    // A secure address: no dialog at all, and it does not even pump.
    expect(await confirmInsecureRelay(ctx, 'wss://relay.example.com'), isTrue);
    expect(find.byType(AlertDialog), findsNothing);

    // A public cleartext one: a dialog, and dismissing it is a no.
    final asked = confirmInsecureRelay(ctx, 'ws://relay.example.com');
    await t.pumpAndSettle();
    expect(find.byType(AlertDialog), findsOneWidget);
    expect(find.textContaining('ws://relay.example.com'), findsOneWidget,
        reason: 'the dialog names the address it is about');
    final l = AppLocalizations.of(ctx);
    await t.tap(find.text(l.cancel));
    await t.pumpAndSettle();
    expect(await asked, isFalse, reason: 'cancelling is not consent');

    // Dismissed with a tap outside it, which is how a dialog is closed by
    // accident. An accident is not consent either, and the difference is one
    // `?? false` that nothing would otherwise notice.
    final brushed = confirmInsecureRelay(ctx, 'ws://relay.example.com');
    await t.pumpAndSettle();
    await t.tapAt(const Offset(10, 10));
    await t.pumpAndSettle();
    expect(await brushed, isFalse,
        reason: 'a dialog dismissed without an answer is a no');

    final again = confirmInsecureRelay(ctx, 'ws://relay.example.com');
    await t.pumpAndSettle();
    await t.tap(find.text(l.relayInsecureUseAnyway));
    await t.pumpAndSettle();
    expect(await again, isTrue);
  });
}
