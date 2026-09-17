import 'dart:io';

import 'vault.dart';

/// The relay every install dials by default, so a new user types nothing to get
/// started. It can be overridden from the hidden Developer-mode settings for a
/// custom or self-hosted relay. The service must actually be served here
/// (DNS + TLS + WebSocket) for the default to connect — and be served here
/// *without a redirect*, which is why this is `www` and not the apex.
///
/// The apex answers `301 → www`, and until 2026-09-17 that was invisible:
/// `WebSocket.connect` follows the redirect, so the socket opened and
/// everything worked. Binding authentication to the relay's authority (§12.1,
/// `z-relay-auth-v2:`) made it fatal — the client signs the host it DIALLED
/// and the relay verifies the Host header it RECEIVED, and a redirect is
/// exactly the case where those two differ. Measured against the live relay:
/// the apex answered `bad_auth`, `www` authenticated. The same 301 had
/// already forced the invite link host to `www` (`connectLinkHost`), and this
/// constant was left behind; `tool/check_relay_url.py` now holds the two
/// together so they cannot drift apart again.
const String defaultRelayUrl = 'wss://www.zmessengers.com';

/// What [defaultRelayUrl] used to be, and what is therefore written into the
/// vault of every install made before 2026-09-17.
///
/// Onboarding does not treat the default as a fallback — it passes whatever
/// is in the address field to `setRelayUrl`, so the apex is a stored value on
/// essentially every existing install rather than something the constant is
/// consulted for. Changing the constant alone would have fixed new installs
/// only. [relayUrlFor] moves the ones that never chose an address of their
/// own; anyone who typed a relay keeps it.
const String legacyDefaultRelayUrl = 'wss://zmessengers.com';

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

/// The address this install should dial, with the superseded default retired.
///
/// Returns the stored `server_url`, except that an install still holding the
/// byte-exact [legacyDefaultRelayUrl] — which is what onboarding wrote for
/// anyone who took the default and never typed anything — is moved to
/// [defaultRelayUrl], and the move is persisted, so it happens once rather
/// than on every start. Any other address is returned untouched: a
/// self-hosted relay, a LAN address, a Render hostname, an address restored
/// from an archive. Retiring a default is not licence to rewrite somebody's
/// relay.
///
/// The apex is the one address not preserved, and someone who typed it
/// deliberately is moved with everyone else. That is not a judgement about
/// their choice: for a v2 client the apex is not a working relay at all, it
/// is the same service one redirect away, and the redirect is the defect.
///
/// Written through the same door as every other writer of `server_url`
/// (`tool/check_relay_url.py` rule 1), and with `acceptedInsecure: false`,
/// which costs nothing: both addresses are `wss:`.
Future<String> relayUrlFor(Vault vault) async {
  final stored = await vault.kvGet('server_url');
  if (stored == null) return defaultRelayUrl;
  if (stored.trim() != legacyDefaultRelayUrl) return stored;
  final out = await setRelayUrl(vault, defaultRelayUrl);
  // A refusal here cannot happen for a `wss:` address, but a write that did
  // not land must not be reported as one: keep dialling what is on disk.
  return out == RelayUrlOutcome.saved ? defaultRelayUrl : stored;
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
