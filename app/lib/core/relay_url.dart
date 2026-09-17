import 'dart:io';

import 'vault.dart';

/// The relay every install dials by default, so a new user types nothing to get
/// started. It can be overridden from the hidden Developer-mode settings for a
/// custom or self-hosted relay. The service must actually be served here
/// (DNS + TLS + WebSocket) for the default to connect.
const String defaultRelayUrl = 'wss://zmessengers.com';

/// Helpers for accepting relay addresses in whatever form the user pastes.
///
/// People will paste their Render URL as `https://z-relay-x.onrender.com`,
/// or just the bare host, or with a trailing slash. Normalize all of it to a
/// WebSocket URL the client can dial.
String normalizeRelayUrl(String input) {
  var s = input.trim();
  if (s.isEmpty) return s;
  // Strip trailing slashes.
  while (s.endsWith('/')) {
    s = s.substring(0, s.length - 1);
  }
  final lower = s.toLowerCase();
  if (lower.startsWith('wss://') || lower.startsWith('ws://')) {
    return s;
  }
  if (lower.startsWith('https://')) {
    return 'wss://${s.substring('https://'.length)}';
  }
  if (lower.startsWith('http://')) {
    return 'ws://${s.substring('http://'.length)}';
  }
  // Bare host → assume TLS (the common Render/Fly case).
  return 'wss://$s';
}

/// True if the URL is either TLS (`wss://`) or a local/LAN address where plain
/// `ws://` is acceptable for testing. Used to decide whether to warn the user.
///
/// The LAN test is made on an ADDRESS, never on a name. Until 2026-09-17 it
/// was a string-prefix test on `u.host`, and a host is a name as often as an
/// address: `ws://10.relay.example.net` began with `10.`, so it was "on the
/// LAN", no warning was shown, and the relay address — the one thing every
/// envelope this app sends goes to — was adopted from a pasted string or a
/// hand-built archive without a word (the 2026-09-14 review's finding 10;
/// C36). A name is never local here. What is: loopback, the three private
/// IPv4 ranges the reference relay's own docs use for LAN testing, the
/// Android emulator's host alias (inside one of them), and `.local` mDNS
/// names, which resolve only on the link.
bool isSecureOrLocalRelay(String normalizedUrl) {
  final u = Uri.tryParse(normalizedUrl);
  if (u == null) return false;
  if (u.scheme == 'wss') return true;
  final host = u.host.toLowerCase();
  if (host == 'localhost') return true;
  // *.local mDNS names: link-local by construction.
  if (host.endsWith('.local')) return true;
  // Everything else must be an address. `Uri.host` strips the brackets from
  // an IPv6 literal, so `::1` parses here as it should.
  final addr = InternetAddress.tryParse(host);
  if (addr == null) return false;
  if (addr.isLoopback) return true;
  if (addr.type == InternetAddressType.IPv4) {
    final b = addr.rawAddress;
    if (b[0] == 10) return true; // 10.0.0.0/8, the emulator's 10.0.2.2 with it
    if (b[0] == 192 && b[1] == 168) return true; // 192.168.0.0/16
    if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true; // 172.16.0.0/12
  }
  return false;
}

/// What happened when something tried to set the relay URL.
enum RelayUrlOutcome {
  /// Written.
  saved,

  /// A public `ws://` address, and nobody had agreed to it. Not written.
  insecureRefused,

  /// Nothing to write.
  empty,
}

/// The one way the relay URL gets written.
///
/// There were four: onboarding, linking a device, the developer-mode field in
/// Settings, and a restored archive's own `meta` record. Exactly one of them
/// ever mentioned that a `ws://` address is not TLS, and it was a *notice*
/// beside a "Test" button nobody has to press — so three of the four, plus
/// the one that takes its answer from a FILE, dialled a cleartext public
/// relay without a word.
///
/// Contents are end-to-end encrypted either way; what cleartext gives an
/// on-path observer is the routing metadata — which mailbox, how much, how
/// often — which is exactly what the rest of this design spends its effort
/// on. Cleartext to a local or LAN address stays free of charge, because
/// that is what it is for and there is no one on that path to hide from.
///
/// [acceptedInsecure] is the user having been asked and having said yes. No
/// caller may pass it because it is convenient; `tool/check_relay_url.py`
/// refuses any other writer of `server_url`.
Future<RelayUrlOutcome> setRelayUrl(Vault vault, String raw,
    {bool acceptedInsecure = false}) async {
  final url = normalizeRelayUrl(raw);
  if (url.isEmpty) return RelayUrlOutcome.empty;
  if (!isSecureOrLocalRelay(url) && !acceptedInsecure) {
    return RelayUrlOutcome.insecureRefused;
  }
  await vault.kvPut('server_url', url, sensitive: false);
  return RelayUrlOutcome.saved;
}
