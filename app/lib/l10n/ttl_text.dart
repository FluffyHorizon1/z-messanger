import 'app_localizations.dart';

/// The disappearing-messages timer, in words, in the user's language.
///
/// One function for every place the setting is shown — the picker in the
/// chat, the row on the contact screen — so they cannot drift apart. The
/// unit is chosen the way a person would say it: 300 is "5 minutes", not
/// "300 seconds", and 604800 is "1 week". Anything that does not divide
/// evenly falls back to the largest unit that does, which the fixed set of
/// picker values never needs.
///
/// Pure. The core's `describeTtl` still exists for the English system
/// messages the service stores; this is the display-side counterpart and
/// the one screens should use.
String ttlText(AppLocalizations l, int seconds) {
  if (seconds <= 0) return l.ttlOff;
  if (seconds % 604800 == 0) return l.ttlWeeks(seconds ~/ 604800);
  if (seconds % 86400 == 0) return l.ttlDays(seconds ~/ 86400);
  if (seconds % 3600 == 0) return l.ttlHours(seconds ~/ 3600);
  if (seconds % 60 == 0) return l.ttlMinutes(seconds ~/ 60);
  return l.ttlSeconds(seconds);
}
