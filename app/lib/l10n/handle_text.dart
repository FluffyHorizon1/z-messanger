import 'package:z_protocol/z_protocol.dart' show HandleProblem;

import '../core/handles.dart';
import 'app_localizations.dart';

/// The words for what the handle service reports (phase 38) — a reason a
/// typed handle is not one, a reason an operation did not happen, where the
/// account's handle stands — in the reader's language. The service reports
/// each as a typed value and never as a sentence, as the chat service does
/// with system messages (`system_text.dart`).

/// Why what was typed is not a handle (PROTOCOL §21.1), said so the person
/// can fix it. [character] is the first character refused, for
/// [HandleProblem.badCharacter].
String handleProblemText(AppLocalizations l, HandleProblem p,
        {String? character}) =>
    switch (p) {
      HandleProblem.empty => l.hdlBadEmpty,
      HandleProblem.badCharacter => l.hdlBadCharacter(character ?? '?'),
      HandleProblem.missingDigits => l.hdlBadMissingDigits,
      HandleProblem.digitsNotDigits => l.hdlBadDigitsNotDigits,
      HandleProblem.reserved => l.hdlBadReserved,
      HandleProblem.nickTooShort => l.hdlBadNickShort,
      HandleProblem.nickTooLong => l.hdlBadNickLong,
      HandleProblem.nickStartsWithNonLetter => l.hdlBadNickStart,
      HandleProblem.nickDoubleUnderscore => l.hdlBadNickDoubleUnderscore,
      HandleProblem.nickEndsWithUnderscore => l.hdlBadNickEndUnderscore,
      HandleProblem.digitsTooShort => l.hdlBadDigitsShort,
      HandleProblem.digitsTooLong => l.hdlBadDigitsLong,
    };

/// Why a handle operation did not happen.
String handleFailureText(AppLocalizations l, HandleFailure f) => switch (f) {
      HandleFailure.unavailable => l.hdlUnavailable,
      HandleFailure.linkedDevice => l.hdlLinkedDevice,
      HandleFailure.unreachable => l.hdlErrUnreachable,
      HandleFailure.badAnswer => l.hdlErrBadAnswer,
      HandleFailure.refused => l.hdlErrRefused,
      HandleFailure.taken => l.hdlErrTaken,
      HandleFailure.changed => l.hdlErrChanged,
      HandleFailure.lost => l.hdlErrLost,
      HandleFailure.notConnected => l.hdlErrNotConnected,
      HandleFailure.powRefused => l.hdlErrPowRefused,
      HandleFailure.relayRefused => l.hdlErrRelayRefused,
      HandleFailure.paused => l.hdlErrPaused,
      HandleFailure.notClaimed => l.hdlErrNotClaimed,
      HandleFailure.wrongCode => l.hdlErrWrongCode,
      HandleFailure.badCode => l.hdlErrBadCode,
      HandleFailure.backupCode => l.hdlErrBackupCode,
      HandleFailure.alreadyHasOne => l.hdlErrAlreadyHasOne,
      HandleFailure.noHandle => l.hdlErrNoHandle,
    };

/// A problem the service recorded on the account's handle, by its code
/// ([HandleFailure]'s name), or null for one this build has no words for —
/// `introUnknown` among them, which marks why a handle is lost and is said
/// by the lost state's own line.
String? handleStoredProblemText(AppLocalizations l, String? code) {
  if (code == null) return null;
  for (final f in HandleFailure.values) {
    if (f.name == code) return handleFailureText(l, f);
  }
  return null;
}

/// What the handle screen says when the relay is not guarding the handle's
/// inbox right now (§21.6), by its answer to the last `intro` frame; null
/// while it is, or before it has been asked.
String? handleRelayGuardText(AppLocalizations l, HandleRelayGuard g) =>
    switch (g) {
      HandleRelayGuard.tooOld => l.hdlRelayUnguarded,
      HandleRelayGuard.full => l.hdlRelayFull,
      HandleRelayGuard.paced => l.hdlRelayPaced,
      HandleRelayGuard.guarded || HandleRelayGuard.unknown => null,
    };

/// The Settings row's line about the account's handle.
String handleRowText(AppLocalizations l, HandleService h) {
  if (!h.available) return l.hdlRowUnavailable;
  if (!h.canManage) return l.hdlRowLinked;
  final o = h.own;
  if (o == null) return l.hdlRowNone;
  final name = o.handle.canonical;
  return switch (o.phase) {
    HandlePhase.pending => l.hdlRowPending(name),
    HandlePhase.held => l.hdlRowHeld(name),
    HandlePhase.live => o.handle.display,
    HandlePhase.paused => l.hdlRowPaused(name),
    HandlePhase.taken => l.hdlRowTaken(name),
    HandlePhase.lost => l.hdlRowLost(name),
  };
}

/// What one of [handlePowLevels] costs a sender, in words.
String handlePowText(AppLocalizations l, int bits) => switch (bits) {
      <= 16 => l.hdlPow16,
      <= 18 => l.hdlPow18,
      <= 20 => l.hdlPow20,
      <= 22 => l.hdlPow22,
      _ => l.hdlPow24,
    };
