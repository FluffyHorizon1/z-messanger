import '../core/connect_invites.dart';
import '../core/models.dart';
import 'app_localizations.dart';
import 'refusal_text.dart';

// What the CONNECT screens say went wrong, in the reader's language, at the
// moment it is shown: the tab's card for a round that could not carry its
// invite forward, and the tab and the comparison for an action that failed.
//
// Nothing here shows an exception's own text. The service names a failure as
// a kind or a type ([ConnectFailure], [ConnectWriteRefused] and the
// refusals of [ConnectInvites.open]), whose English stays the exception's,
// for logs; anything no case names is one line in the reader's language.
// Until 2026-10-31 the card said "Could not reach the relay — will keep
// trying." and then the failure's own text, in English, whatever had failed
// — "SqfliteFfiException(sqlite_error: 1811, …)" for a write the vault
// refused — and the tab and the comparison showed an action's exception as
// it came, but for a refused contact code: its message for a
// FormatException, all of it for anything else.

/// The card's line for why the last round did not carry its invite forward.
String connectRoundFailureText(AppLocalizations l, ConnectFailure failure) =>
    switch (failure) {
      ConnectFailure.relay => l.connectFailedRelay,
      ConnectFailure.vault => l.connectFailedVault,
      ConnectFailure.fault => l.connectFailedOther,
    };

/// What the tab or the comparison says when an action on an invite failed:
/// opening one, making one, saying yes to one, or answering its digits.
String connectActionFailureText(AppLocalizations l, Object error) =>
    switch (error) {
      final ContactCodeRefused refused => contactCodeRefusalText(l, refused),
      ConnectNotAnInvite() => l.connectNotAnInvite,
      ConnectInviteAlreadyOpen() => l.connectAlreadyOpen,
      ConnectNoSealingKey() => l.connectNoSealingKey,
      ConnectWriteRefused() => l.connectSaveFailed,
      _ => l.connectActionFailed,
    };
