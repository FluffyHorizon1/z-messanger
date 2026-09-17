import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../l10n/app_localizations.dart';
import '../l10n/ttl_text.dart';
import '../core/chat_service.dart';
import 'theme.dart';

/// The disappearing-message timer picker, shared by the chat screen's app-bar
/// icon and the contact screen's row — one bottom sheet, so the two surfaces
/// cannot disagree (which the chat picker's own comment promised, while the
/// contact row was a read-only `ListTile` with no `onTap` and never opened it:
/// the 2026-09-14 review sweep's dead-control finding).
Future<void> pickDisappearingTimer(BuildContext context, String rid) async {
  final svc = context.read<ChatService>();
  final l = AppLocalizations.of(context);
  final current = svc.contacts[rid]?.ttlSec ?? 0;
  // Labelled through the same function that describes the setting elsewhere,
  // so the picker and the contact screen cannot disagree.
  final options = <(int, String)>[
    for (final sec in const [0, 30, 300, 3600, 28800, 86400, 604800])
      (sec, ttlText(l, sec)),
  ];
  final chosen = await showModalBottomSheet<int>(
    context: context,
    backgroundColor: context.z.surface,
    builder: (ctx) => SafeArea(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Padding(
            padding: const EdgeInsets.all(16),
            child: Text(l.disappearingMessages,
                style: const TextStyle(fontWeight: FontWeight.w700)),
          ),
          for (final (sec, label) in options)
            ListTile(
              leading: Icon(
                sec == current
                    ? Icons.radio_button_checked
                    : Icons.radio_button_off,
                color:
                    sec == current ? context.z.accent : context.z.textSecondary,
              ),
              title: Text(label),
              onTap: () => Navigator.pop(ctx, sec),
            ),
        ],
      ),
    ),
  );
  if (chosen != null && chosen != current) {
    await svc.setDisappearingTimer(rid, chosen);
  }
}
