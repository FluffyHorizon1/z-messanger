import 'dart:async' show TimeoutException;

import 'package:z_protocol/z_protocol.dart'
    show
        PairingAbort,
        PairingEnrolmentInterrupted,
        PairingEnrolmentRefused,
        PairingInstallFailed,
        PairingNoAnswer,
        PairingNoEnrolment,
        PairingPeerGaveUp,
        PairingPeerOutdated,
        PairingPeerUnconfirmed,
        PairingPeerUnfinished,
        PairingTakenOver,
        RelayException;

import 'app_localizations.dart';

// What each linking screen says when the ceremony stops (§10.2, 44.4), in
// the reader's language, chosen from what the ceremony threw.
//
// From 44.4 linking needs both devices on 44.4 or later, and neither side
// falls back. When the other device is older, the screen says which device
// to update — never a bare failure: the existing device hears the new
// device's older ceremony and knows its version, and the new device hears
// nothing, and says the device it is linking from may be older. Each way a
// link stops on time — one person's confirmation not answered by the
// other's, an enrolment that never came or was never installed — has words
// of its own, and so do an enrolment that came and could not be opened or
// installed, one the phone's own lost connection cut short or the relay
// refused, a mailbox someone else holding the code logged in as, a timeout
// and a lost connection: none of them is a raw exception in English. A
// phone whose connection drops while it sends the account cannot tell
// whether the account got through, and says that, not that the new device
// failed; the new device, sent nothing, names that among the reasons.

/// The existing device's screen (`HostLinkScreen`): the new device spoke an
/// older ceremony, so it is the new device that needs updating.
String hostLinkFailureText(AppLocalizations l, Object error) =>
    switch (error) {
      PairingPeerOutdated(:final version) => l.linkNewDeviceOlder(version),
      PairingPeerUnconfirmed() => l.linkPeerUnconfirmed,
      PairingPeerGaveUp() => l.linkPeerGaveUp,
      PairingPeerUnfinished() => l.linkPeerUnfinished,
      PairingEnrolmentInterrupted() => l.linkEnrolmentInterrupted,
      PairingEnrolmentRefused() => l.linkEnrolmentRefused,
      PairingTakenOver() => l.linkHostTakenOver,
      PairingAbort(:final message) => l.linkFailed(message),
      TimeoutException() => l.linkTimedOut,
      RelayException() => l.linkConnectionLost,
      _ => l.linkFailed('$error'),
    };

/// The new device's screen (`NewDeviceLinkScreen`): nothing answered, so the
/// device it is linking from may be older, and that is the one to update.
String newDeviceLinkFailureText(AppLocalizations l, Object error) =>
    switch (error) {
      PairingNoAnswer() => l.linkHostMayBeOlder,
      PairingNoEnrolment() => l.linkNoEnrolment,
      PairingInstallFailed() => l.linkInstallFailed,
      PairingTakenOver() => l.linkTakenOver,
      PairingAbort(:final message) => l.linkFailed(message),
      TimeoutException() => l.linkTimedOut,
      RelayException() => l.linkConnectionLost,
      _ => l.linkFailed('$error'),
    };
