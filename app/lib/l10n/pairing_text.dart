import 'package:z_protocol/z_protocol.dart'
    show PairingAbort, PairingNoAnswer, PairingPeerOutdated;

import 'app_localizations.dart';

// What each linking screen says when the ceremony stops (§10.2, 44.4), in
// the reader's language, chosen from what the ceremony threw.
//
// From 44.4 linking needs both devices on 44.4 or later, and neither side
// falls back. When the other device is older, the screen says which device
// to update — never a bare failure: the existing device hears the new
// device's older ceremony and knows its version, and the new device hears
// nothing, and says the device it is linking from may be older.

/// The existing device's screen (`HostLinkScreen`): the new device spoke an
/// older ceremony, so it is the new device that needs updating.
String hostLinkFailureText(AppLocalizations l, Object error) =>
    switch (error) {
      PairingPeerOutdated(:final version) => l.linkNewDeviceOlder(version),
      PairingAbort(:final message) => l.linkFailed(message),
      _ => l.linkFailed('$error'),
    };

/// The new device's screen (`NewDeviceLinkScreen`): nothing answered, so the
/// device it is linking from may be older, and that is the one to update.
String newDeviceLinkFailureText(AppLocalizations l, Object error) =>
    switch (error) {
      PairingNoAnswer() => l.linkHostMayBeOlder,
      PairingAbort(:final message) => l.linkFailed(message),
      _ => l.linkFailed('$error'),
    };
