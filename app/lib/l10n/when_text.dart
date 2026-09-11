import 'package:flutter/material.dart';

/// A moment, as a date and a time in the device's locale — for notices
/// that say "since when": the transparency log's last accepted head, the
/// hour it became unreachable. One function so every notice formats it the
/// same way, and an em dash when there has never been such a moment.
///
/// Material's own formatters carry the locale, so this holds no words of
/// its own.
String whenText(BuildContext context, int ms) {
  if (ms <= 0) return '—';
  final m = MaterialLocalizations.of(context);
  final t = DateTime.fromMillisecondsSinceEpoch(ms);
  final date = m.formatMediumDate(t);
  final time = m.formatTimeOfDay(TimeOfDay.fromDateTime(t));
  return [date, time].join(' ');
}
