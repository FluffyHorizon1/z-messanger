import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../l10n/app_localizations.dart';
import '../core/chat_service.dart';
import '../core/models.dart';
import 'chat_screen.dart';
import 'theme.dart';

/// ADR 0011: the people who have added you and are waiting on your answer.
/// Accepting adds them exactly as a scan would (unverified until you compare
/// safety numbers); declining drops the request in silence; blocking drops it
/// and every future one from them.
class RequestsScreen extends StatelessWidget {
  const RequestsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final service = context.watch<ChatService>();
    final requests = service.requests;

    return Scaffold(
      appBar: AppBar(title: Text(l.requestsTitle)),
      body: requests.isEmpty
          ? Center(
              child: Text(l.requestsEmpty,
                  style: TextStyle(color: context.z.textSecondary)))
          : ListView(
              padding: const EdgeInsets.symmetric(vertical: 8),
              children: [
                Padding(
                  padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
                  child: Text(
                    l.requestsNote,
                    style: TextStyle(
                        color: context.z.textSecondary,
                        fontSize: 12.5,
                        height: 1.4),
                  ),
                ),
                for (final r in requests)
                  _RequestCard(request: r),
              ],
            ),
    );
  }
}

class _RequestCard extends StatelessWidget {
  final PendingRequest request;
  const _RequestCard({required this.request});

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final service = context.read<ChatService>();
    final name = request.name.isNotEmpty ? request.name : '?';

    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      child: Padding(
        padding: const EdgeInsets.fromLTRB(16, 12, 12, 8),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                CircleAvatar(
                  radius: 22,
                  backgroundColor: context.z.surfaceAlt,
                  child: Text(name[0].toUpperCase(),
                      style: TextStyle(
                          color: context.z.accent,
                          fontWeight: FontWeight.w700)),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(name,
                          overflow: TextOverflow.ellipsis,
                          style: const TextStyle(
                              fontWeight: FontWeight.w600, fontSize: 16)),
                      const SizedBox(height: 2),
                      Text(l.requestsWantsToConnect,
                          style: TextStyle(
                              color: context.z.textSecondary, fontSize: 13)),
                    ],
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            Row(
              mainAxisAlignment: MainAxisAlignment.end,
              children: [
                TextButton(
                  onPressed: () => service.blockRequest(request.rid),
                  child: Text(l.requestBlock,
                      style: TextStyle(color: context.z.danger)),
                ),
                TextButton(
                  onPressed: () => service.declineRequest(request.rid),
                  child: Text(l.requestDecline,
                      style: TextStyle(color: context.z.textSecondary)),
                ),
                const SizedBox(width: 4),
                FilledButton(
                  onPressed: () async {
                    final rid = request.rid;
                    await service.acceptRequest(rid);
                    if (!context.mounted) return;
                    Navigator.of(context).push(
                      MaterialPageRoute(builder: (_) => ChatScreen(rid: rid)),
                    );
                  },
                  child: Text(l.requestAccept),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
