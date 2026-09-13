import 'package:flutter/material.dart';

import '../core/relay_url.dart';
import '../l10n/app_localizations.dart';

/// Ask, once, before dialling a relay address that is not TLS and not local.
///
/// Returns true if the connection may go ahead — immediately, and with no
/// dialog, for a `wss://` address or one on the machine or the local network,
/// because that is the case cleartext exists for and there is nobody on that
/// path to hide from. Everything else is a question, with "Connect anyway"
/// deliberately not the default.
///
/// It exists as one function because there were three screens that accept a
/// relay address and only one of them ever said anything, in a notice next to
/// a button nobody has to press.
Future<bool> confirmInsecureRelay(
    BuildContext context, String normalizedUrl) async {
  if (isSecureOrLocalRelay(normalizedUrl)) return true;
  final l = AppLocalizations.of(context);
  final ok = await showDialog<bool>(
    context: context,
    builder: (ctx) => AlertDialog(
      icon: const Icon(Icons.lock_open_outlined),
      title: Text(l.relayInsecureTitle),
      content: Text(l.relayInsecureBody(normalizedUrl)),
      actions: [
        TextButton(
            onPressed: () => Navigator.pop(ctx, false), child: Text(l.cancel)),
        TextButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: Text(l.relayInsecureUseAnyway)),
      ],
    ),
  );
  return ok ?? false;
}
