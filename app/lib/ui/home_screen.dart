import 'package:flutter/material.dart';

import '../l10n/app_localizations.dart';
import '../l10n/system_text.dart';
import '../l10n/when_text.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';

import '../core/chat_service.dart';
import '../core/key_transparency.dart';
import '../core/models.dart';
import '../core/transport.dart';
import 'add_contact_screen.dart';
import 'chat_screen.dart';
import 'group_screens.dart';
import 'search_screen.dart';
import 'settings_screen.dart';
import 'theme.dart';

class HomeScreen extends StatelessWidget {
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final service = context.watch<ChatService>();
    final transport = context.watch<Transport>();
    final chats = service.chatSummaries();

    return Scaffold(
      appBar: AppBar(
        title: Row(
          children: [
            Text('Z',
                style: TextStyle(
                    color: context.z.accent,
                    fontWeight: FontWeight.w900,
                    fontSize: 26)),
            const SizedBox(width: 12),
            _StatusDot(status: transport.status),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.search),
            tooltip: l.homeSearch,
            onPressed: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const SearchScreen()),
            ),
          ),
          IconButton(
            icon: const Icon(Icons.group_add_outlined),
            tooltip: l.homeNewGroup,
            onPressed: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const CreateGroupScreen()),
            ),
          ),
          IconButton(
            tooltip: l.homeSettings,
            icon: const Icon(Icons.settings_outlined),
            onPressed: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const SettingsScreen()),
            ),
          ),
        ],
      ),
      body: Column(
        children: [
          if (service.removedDeviceAlert != null)
            _AccountAlertBanner(
              message: service.removedDeviceAlert!,
              onDismiss: service.acknowledgeRemovedDeviceAlert,
            ),
          if (service.ownAccountAlert != null)
            _AccountAlertBanner(
              message: service.ownAccountAlert!,
              onDismiss: service.acknowledgeOwnAccountAlert,
            ),
          // 7.7b (ADR 0006): the log holds a list for this account that this
          // device never issued — the one finding only the owner can act on.
          if (service.kt.ownAlert != null)
            _AccountAlertBanner(
              message: l.homeKtOwnAlert(service.kt.ownAlert!.version),
              onDismiss: service.kt.acknowledgeOwnAlert,
            ),
          // The log misbehaved. Not dismissable: it stands until the history
          // is reset in Settings, which is a deliberate act.
          if (service.kt.health == KtHealth.fault)
            _AccountAlertBanner(
              message: l.homeKtFault(service.kt.fault?.reason ?? ''),
            ),
          if (service.kt.health == KtHealth.unreachable)
            _NoticeBanner(
              message: l.homeKtUnreachable(
                  whenText(context, service.kt.lastOkMs)),
            ),
          Expanded(
            child: chats.isEmpty
                ? const _EmptyState()
                : ListView.separated(
                    itemCount: chats.length,
                    separatorBuilder: (_, __) =>
                        const Divider(height: 1, indent: 76),
                    itemBuilder: (context, i) => _ChatTile(summary: chats[i]),
                  ),
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton.extended(
        icon: const Icon(Icons.person_add_alt_1),
        label: Text(l.homeAddContact),
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
    final l = AppLocalizations.of(context);
    final (color, label) = switch (status) {
      LinkStatus.connected => (context.z.ok, l.relayLinked),
      LinkStatus.connecting => (context.z.accent, l.relayLinking),
      LinkStatus.disconnected => (context.z.danger, l.relayOffline),
    };
    return Row(children: [
      Container(
        width: 8,
        height: 8,
        decoration: BoxDecoration(color: color, shape: BoxShape.circle),
      ),
      const SizedBox(width: 6),
      Text(label,
          style: TextStyle(fontSize: 12, color: context.z.textSecondary)),
    ]);
  }
}

class _EmptyState extends StatelessWidget {
  const _EmptyState();

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.lock_outline, size: 56, color: context.z.textSecondary),
          SizedBox(height: 16),
          Text(l.homeEmptyTitle,
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.w600)),
          SizedBox(height: 8),
          Padding(
            padding: EdgeInsets.symmetric(horizontal: 48),
            child: Text(
              l.homeEmptyBody,
              textAlign: TextAlign.center,
              style: TextStyle(color: context.z.textSecondary, height: 1.5),
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

  String _preview(ChatMessage? m, AppLocalizations l) {
    if (m == null) return l.chatPreviewEmpty;
    return switch (m.kind) {
      'file' => l.chatPreviewFile(m.body),
      'system' => systemText(l, m.body),
      'gtext' when !m.outgoing && m.senderName != null =>
        l.chatPreviewSender(m.senderName!, m.body),
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
    final l = AppLocalizations.of(context);
    final c = summary.contact;
    // The tick tracks the VERIFICATION, not the flag: a contact whose
    // identity was upgraded has a number the user has not compared, and a
    // green shield against it would be a claim the app cannot support (13.3).
    final verification = c == null
        ? VerificationState.unverified
        : context.watch<ChatService>().verificationWith(c.rid);
    return ListTile(
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
      leading: CircleAvatar(
        radius: 24,
        backgroundColor: context.z.surfaceAlt,
        child: summary.isGroup
            ? Icon(Icons.group, color: context.z.accent)
            : Text(
                summary.title.isNotEmpty ? summary.title[0].toUpperCase() : '?',
                style: TextStyle(
                    color: context.z.accent, fontWeight: FontWeight.w700),
              ),
      ),
      title: Row(
        children: [
          Expanded(
            child: Text(summary.title,
                overflow: TextOverflow.ellipsis,
                style: const TextStyle(fontWeight: FontWeight.w600)),
          ),
          if (verification == VerificationState.verified)
            Padding(
              padding: const EdgeInsets.only(left: 6),
              child: Icon(Icons.verified_user, size: 14, color: context.z.ok),
            ),
          if (verification == VerificationState.upgradedReverify)
            Padding(
              padding: const EdgeInsets.only(left: 6),
              child:
                  Icon(Icons.shield_outlined, size: 14, color: context.z.warn),
            ),
          if (verification == VerificationState.changedUnexpectedly)
            Padding(
              padding: const EdgeInsets.only(left: 6),
              child: Icon(Icons.gpp_maybe_outlined,
                  size: 14, color: context.z.danger),
            ),
          if (c != null && c.ttlSec > 0)
            Padding(
              padding: EdgeInsets.only(left: 6),
              child:
                  Icon(Icons.timer_outlined, size: 14, color: context.z.accent),
            ),
        ],
      ),
      subtitle: Text(
        _preview(summary.last, l),
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
        style: TextStyle(color: context.z.textSecondary),
      ),
      trailing: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          if (summary.last != null)
            Text(_time(summary.last!.ts),
                style: TextStyle(fontSize: 12, color: context.z.textSecondary)),
          const SizedBox(height: 6),
          if (summary.unread > 0)
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
              decoration: BoxDecoration(
                color: context.z.accent,
                borderRadius: BorderRadius.circular(12),
              ),
              child: Text('${summary.unread}',
                  style: TextStyle(
                      color: context.z.onAccent,
                      fontSize: 12,
                      fontWeight: FontWeight.w700)),
            ),
        ],
      ),
      onTap: () => Navigator.push(
        context,
        MaterialPageRoute(builder: (_) => ChatScreen(rid: summary.rid)),
      ),
    );
  }
}

/// A serious, dismissible account-level warning shown above the chat list —
/// used for the 7.7a device-list transparency alerts that concern this
/// device's own account (a list it never issued, or this device being removed).
/// A quiet strip for something worth knowing that is not an alarm.
class _NoticeBanner extends StatelessWidget {
  final String message;
  const _NoticeBanner({required this.message});

  @override
  Widget build(BuildContext context) {
    return Material(
      color: context.z.warn.withValues(alpha: 0.10),
      child: SafeArea(
        bottom: false,
        child: Padding(
          padding: const EdgeInsets.fromLTRB(14, 8, 14, 8),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(Icons.cloud_off_outlined, size: 18, color: context.z.warn),
              const SizedBox(width: 10),
              Expanded(
                child: Text(message,
                    style: const TextStyle(fontSize: 12, height: 1.35)),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _AccountAlertBanner extends StatelessWidget {
  final String message;
  final VoidCallback? onDismiss;
  const _AccountAlertBanner({required this.message, this.onDismiss});

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    return Material(
      color: context.z.danger.withValues(alpha: 0.14),
      child: SafeArea(
        bottom: false,
        child: Padding(
          padding: const EdgeInsets.fromLTRB(14, 10, 6, 10),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(Icons.gpp_bad, size: 20, color: context.z.danger),
              const SizedBox(width: 10),
              Expanded(
                child: Text(
                  message,
                  style: const TextStyle(fontSize: 12.5, height: 1.35),
                ),
              ),
              if (onDismiss != null)
                IconButton(
                  icon: const Icon(Icons.close, size: 18),
                  tooltip: l.dismiss,
                  color: context.z.textSecondary,
                  onPressed: onDismiss,
                ),
            ],
          ),
        ),
      ),
    );
  }
}
