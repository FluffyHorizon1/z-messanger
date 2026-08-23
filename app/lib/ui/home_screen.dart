import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';

import '../core/chat_service.dart';
import '../core/models.dart';
import '../core/transport.dart';
import 'add_contact_screen.dart';
import 'chat_screen.dart';
import 'settings_screen.dart';
import 'theme.dart';

class HomeScreen extends StatelessWidget {
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final service = context.watch<ChatService>();
    final transport = context.watch<Transport>();
    final chats = service.chatSummaries();

    return Scaffold(
      appBar: AppBar(
        title: Row(
          children: [
            const Text('Z',
                style: TextStyle(
                    color: ZTheme.accent,
                    fontWeight: FontWeight.w900,
                    fontSize: 26)),
            const SizedBox(width: 12),
            _StatusDot(status: transport.status),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.settings_outlined),
            onPressed: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const SettingsScreen()),
            ),
          ),
        ],
      ),
      body: chats.isEmpty
          ? const _EmptyState()
          : ListView.separated(
              itemCount: chats.length,
              separatorBuilder: (_, __) =>
                  const Divider(height: 1, indent: 76),
              itemBuilder: (context, i) => _ChatTile(summary: chats[i]),
            ),
      floatingActionButton: FloatingActionButton.extended(
        icon: const Icon(Icons.person_add_alt_1),
        label: const Text('Add contact'),
        onPressed: () => Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => const AddContactScreen()),
        ),
      ),
    );
  }
}

class _StatusDot extends StatelessWidget {
  final LinkStatus status;
  const _StatusDot({required this.status});

  @override
  Widget build(BuildContext context) {
    final (color, label) = switch (status) {
      LinkStatus.connected => (ZTheme.ok, 'relay linked'),
      LinkStatus.connecting => (ZTheme.accent, 'linking…'),
      LinkStatus.disconnected => (ZTheme.danger, 'offline'),
    };
    return Row(children: [
      Container(
        width: 8,
        height: 8,
        decoration: BoxDecoration(color: color, shape: BoxShape.circle),
      ),
      const SizedBox(width: 6),
      Text(label,
          style: const TextStyle(fontSize: 12, color: ZTheme.textSecondary)),
    ]);
  }
}

class _EmptyState extends StatelessWidget {
  const _EmptyState();

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: const [
          Icon(Icons.lock_outline, size: 56, color: ZTheme.textSecondary),
          SizedBox(height: 16),
          Text('No conversations yet',
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.w600)),
          SizedBox(height: 8),
          Padding(
            padding: EdgeInsets.symmetric(horizontal: 48),
            child: Text(
              'Exchange contact codes in person or over a channel you trust, '
              'then every message is end-to-end encrypted and stored only on '
              'your two devices.',
              textAlign: TextAlign.center,
              style: TextStyle(color: ZTheme.textSecondary, height: 1.5),
            ),
          ),
        ],
      ),
    );
  }
}

class _ChatTile extends StatelessWidget {
  final ChatSummary summary;
  const _ChatTile({required this.summary});

  String _preview(ChatMessage? m) {
    if (m == null) return 'Say hello — the line is encrypted.';
    return switch (m.kind) {
      'file' => '📎 ${m.body}',
      'system' => m.body,
      _ => m.body,
    };
  }

  String _time(int ts) {
    final dt = DateTime.fromMillisecondsSinceEpoch(ts);
    final now = DateTime.now();
    if (dt.year == now.year && dt.month == now.month && dt.day == now.day) {
      return DateFormat.Hm().format(dt);
    }
    return DateFormat.MMMd().format(dt);
  }

  @override
  Widget build(BuildContext context) {
    final c = summary.contact;
    return ListTile(
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
      leading: CircleAvatar(
        radius: 24,
        backgroundColor: ZTheme.surfaceAlt,
        child: Text(
          c.name.isNotEmpty ? c.name[0].toUpperCase() : '?',
          style: const TextStyle(
              color: ZTheme.accent, fontWeight: FontWeight.w700),
        ),
      ),
      title: Row(
        children: [
          Expanded(
            child: Text(c.name,
                overflow: TextOverflow.ellipsis,
                style: const TextStyle(fontWeight: FontWeight.w600)),
          ),
          if (c.verified)
            const Padding(
              padding: EdgeInsets.only(left: 6),
              child: Icon(Icons.verified_user, size: 14, color: ZTheme.ok),
            ),
          if (c.ttlSec > 0)
            const Padding(
              padding: EdgeInsets.only(left: 6),
              child:
                  Icon(Icons.timer_outlined, size: 14, color: ZTheme.accent),
            ),
        ],
      ),
      subtitle: Text(
        _preview(summary.last),
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
        style: const TextStyle(color: ZTheme.textSecondary),
      ),
      trailing: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          if (summary.last != null)
            Text(_time(summary.last!.ts),
                style: const TextStyle(
                    fontSize: 12, color: ZTheme.textSecondary)),
          const SizedBox(height: 6),
          if (summary.unread > 0)
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
              decoration: BoxDecoration(
                color: ZTheme.accent,
                borderRadius: BorderRadius.circular(12),
              ),
              child: Text('${summary.unread}',
                  style: const TextStyle(
                      color: Colors.black,
                      fontSize: 12,
                      fontWeight: FontWeight.w700)),
            ),
        ],
      ),
      onTap: () => Navigator.push(
        context,
        MaterialPageRoute(builder: (_) => ChatScreen(rid: c.rid)),
      ),
    );
  }
}
