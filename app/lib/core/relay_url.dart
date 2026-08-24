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
bool isSecureOrLocalRelay(String normalizedUrl) {
  final u = Uri.tryParse(normalizedUrl);
  if (u == null) return false;
  if (u.scheme == 'wss') return true;
  final host = u.host.toLowerCase();
  if (host == 'localhost' || host == '127.0.0.1' || host == '::1') return true;
  // Private / LAN ranges where cleartext is reasonable for local testing.
  if (host.startsWith('192.168.') || host.startsWith('10.')) return true;
  if (host.startsWith('172.')) {
    final parts = host.split('.');
    if (parts.length >= 2) {
      final second = int.tryParse(parts[1]);
      if (second != null && second >= 16 && second <= 31) return true;
    }
  }
  // *.local mDNS names, and the Android emulator host alias.
  if (host.endsWith('.local') || host == '10.0.2.2') return true;
  return false;
}

/// A short human explanation when a relay URL isn't secure. Null if fine.
String? relayUrlWarning(String normalizedUrl) {
  if (isSecureOrLocalRelay(normalizedUrl)) return null;
  return 'This relay isn\'t using TLS. It works, but a public relay should use '
      'wss:// so on-path observers can\'t see who you\'re talking to. '
      '(Message contents stay end-to-end encrypted regardless.)';
}
