import 'dart:async' show TimeoutException;
import 'dart:io'
    show
        FileSystemException,
        HttpException,
        SocketException,
        TlsException,
        WebSocketException;

import 'package:flutter/services.dart' show PlatformException;
import 'package:sqflite_common_ffi/sqflite_ffi.dart' show DatabaseException;
import 'package:z_protocol/z_protocol.dart'
    show RecoveryCodeInvalid, RecoveryCodeProblem, RecoveryCode, RelayException;

import '../core/app_lock.dart' show BoundKeyException;
import '../core/models.dart' show ContactCodeRefused;
import '../core/vault.dart' show VaultTooNewException, WrongPassphraseException;
import 'app_localizations.dart';
import 'refusal_text.dart';

// What the first screen, Add contact, Backup and Settings say when something
// they started fails, in the reader's language, chosen from what failed.
//
// Until 2026-10-31 each of them showed the exception: "Could not save:
// PathNotFoundException: Cannot open file, path = ...", the first screen's
// "DatabaseException(...)", the relay's status "Offline (SocketException:
// Connection refused (OS Error: ...))", and a mistyped recovery code's reason
// in English whatever the reader's language. Nothing here shows an
// exception's own text: what has words of its own says it, and anything
// else is one line in the reader's language. The exception's text stays its
// message, for logs.

/// Whether [error] is this device failing to open a connection to the relay
/// at all: no network or nothing listening, an address that answers but
/// does not upgrade to a WebSocket, a secure connection that could not be
/// made, or no answer in time.
bool _unreachable(Object error) =>
    error is SocketException ||
    error is WebSocketException ||
    error is TlsException ||
    error is HttpException ||
    error is TimeoutException;

/// Why a typed recovery code is not one, wherever a code is asked for: the
/// restore on the first screen, the backup's check that it was written down,
/// and turning automatic backups on. A [FormatException] that is not a
/// [RecoveryCodeInvalid] — no parser of codes throws one — reads as a typo.
String recoveryCodeText(AppLocalizations l, Object error) => switch (error) {
      RecoveryCodeInvalid(problem: RecoveryCodeProblem.length) =>
        l.recoveryCodeLength(RecoveryCode.totalChars, error.length),
      RecoveryCodeInvalid(problem: RecoveryCodeProblem.character) =>
        l.recoveryCodeCharacter(error.character),
      _ => l.recoveryCodeTypo,
    };

/// What the first screen's restore says when the backup does not open: a
/// recovery code that is not one says why ([recoveryCodeText]); one that is
/// but does not open the archive, or a damaged file, says it could not
/// restore.
String restoreFailureText(AppLocalizations l, Object error) => switch (error) {
      RecoveryCodeInvalid() => recoveryCodeText(l, error),
      _ => l.onbRestoreFailed,
    };

/// What Add contact says when a code could not be added: a refused code
/// says why ([contactCodeRefusalText]); one that does not decode says it
/// did not verify; and anything else — the store refusing a write — that
/// this device could not add the contact.
String addContactFailureText(AppLocalizations l, Object error) =>
    switch (error) {
      ContactCodeRefused() => contactCodeRefusalText(l, error),
      FormatException() => l.addRefusedInvalidCode,
      _ => l.addFailedOther,
    };

/// The relay's status in Settings while this device is not connected, from
/// the last try's failure ([error], null when there was none): a relay this
/// device could not reach at all, one it reached but could not sign in to
/// (it refused the sign-in, or is too old to sign in to), or just offline.
String relayOfflineText(AppLocalizations l, Object? error) => switch (error) {
      null => l.stRelayOffline,
      RelayException() => l.stRelayOfflineRefused,
      _ when _unreachable(error) => l.stRelayOfflineUnreachable,
      _ => l.stRelayOffline,
    };

/// Whether [error] is Z's storage on this device — its files or its
/// database — failing to open or to be read.
bool _storage(Object error) =>
    error is FileSystemException || error is DatabaseException;

/// What the full screen says when Z cannot start: data a newer version
/// wrote, a store the key this device keeps for it does not open (with no
/// passphrase set, the only key there is), a store that could not be opened
/// or read, or anything else. Until 2026-10-31 it was "Z could not start:"
/// and the error, as it came.
String startupFailureText(AppLocalizations l, Object error) => switch (error) {
      VaultTooNewException() => l.vaultTooNew,
      WrongPassphraseException() => l.startupFailedKey,
      _ when _storage(error) => l.startupFailedStorage,
      _ => l.startupFailedOther,
    };

/// What the unlock screen says for a failure that is not a wrong passphrase
/// or a biometric key gone stale or reset: a store that could not be opened
/// or read, the system's secure storage or its prompt refusing, or anything
/// else. Until 2026-10-31 it was the error, as it came.
String unlockFailureText(AppLocalizations l, Object error) => switch (error) {
      _ when _storage(error) => l.unlockFailedStorage,
      PlatformException() || BoundKeyException() => l.unlockFailedKeystore,
      _ => l.unlockFailedOther,
    };
