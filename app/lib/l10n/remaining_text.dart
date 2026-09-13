import 'app_localizations.dart';

/// How long an invite has left, in words, in the user's language.
///
/// An invite is a bearer token for 24 hours (§20, R23), and "Pending" said
/// nothing about which hour of the 24 it was in — so the one number a person
/// needs in order to decide whether to send it again was the one number the
/// screen did not have.
///
/// Rounded **down**, deliberately: "1 hour left" for anything between one and
/// two hours means the invite never promises more time than it has. The last
/// minute says so in words rather than counting to zero, because a number
/// that reaches 0 and stays there reads as a bug.
String remainingText(AppLocalizations l, Duration left) {
  if (left <= Duration.zero) return l.connectExpired;
  if (left.inHours >= 1) return l.connectExpiresHours(left.inHours);
  if (left.inMinutes >= 1) return l.connectExpiresMinutes(left.inMinutes);
  return l.connectExpiresSoon;
}
