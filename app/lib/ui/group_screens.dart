import 'package:flutter/material.dart';

import '../l10n/app_localizations.dart';
import 'package:provider/provider.dart';

import '../core/chat_service.dart';
import 'chat_screen.dart';
import 'theme.dart';

/// Pick a name and members (from existing contacts) and create the group.
class CreateGroupScreen extends StatefulWidget {
  const CreateGroupScreen({super.key});
  @override
  State<CreateGroupScreen> createState() => _CreateGroupScreenState();
}

class _CreateGroupScreenState extends State<CreateGroupScreen> {
  final _name = TextEditingController();
  final Set<String> _selected = {};
  bool _busy = false;

  Future<void> _create() async {
    final l = AppLocalizations.of(context);
    final chat = context.read<ChatService>();
    final nav = Navigator.of(context);
    final messenger = ScaffoldMessenger.of(context);
    final name = _name.text.trim();
    if (name.isEmpty || _selected.isEmpty) {
      messenger.showSnackBar(
          SnackBar(content: Text(l.grpNeedNameAndMember)));
      return;
    }
    setState(() => _busy = true);
    try {
      final gid = await chat.createGroup(name, _selected.toList());
      if (!mounted) return;
      nav.pushReplacement(
          MaterialPageRoute(builder: (_) => ChatScreen(rid: gid)));
    } catch (e) {
      setState(() => _busy = false);
      messenger.showSnackBar(SnackBar(content: Text(l.grpCreateFailed('$e'))));
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final chat = context.watch<ChatService>();
    final contacts = chat.contacts.values.toList()
      ..sort((a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()));

    return Scaffold(
      appBar: AppBar(title: Text(l.grpNew)),
      body: Column(
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 16, 16, 4),
            child: TextField(
              controller: _name,
              autofocus: true,
              decoration: InputDecoration(
                labelText: l.grpName,
                helperText:
                    l.grpNameHelp,
                helperMaxLines: 2,
              ),
            ),
          ),
          Expanded(
            child: contacts.isEmpty
                ? Center(
                    child: Text(l.grpAddContactsFirst,
                        style: TextStyle(color: context.z.textSecondary)),
                  )
                : ListView(
                    children: [
                      for (final c in contacts)
                        CheckboxListTile(
                          value: _selected.contains(c.rid),
                          activeColor: context.z.accent,
                          checkColor: context.z.onAccent,
                          title: Text(c.name),
                          secondary: CircleAvatar(
                            backgroundColor: context.z.surfaceAlt,
                            child: Text(
                              c.name.isNotEmpty ? c.name[0].toUpperCase() : '?',
                              style: TextStyle(
                                  color: context.z.accent,
                                  fontWeight: FontWeight.w700),
                            ),
                          ),
                          onChanged: (v) => setState(() {
                            if (v == true) {
                              _selected.add(c.rid);
                            } else {
                              _selected.remove(c.rid);
                            }
                          }),
                        ),
                    ],
                  ),
          ),
          SafeArea(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: SizedBox(
                width: double.infinity,
                child: FilledButton(
                  style: FilledButton.styleFrom(
                    backgroundColor: context.z.accent,
                    foregroundColor: context.z.onAccent,
                    padding: const EdgeInsets.symmetric(vertical: 16),
                  ),
                  onPressed: _busy ? null : _create,
                  child: _busy
                      ? const SizedBox(
                          width: 20,
                          height: 20,
                          child: CircularProgressIndicator(strokeWidth: 2))
                      : Text(
                          l.grpCreateWithCount(_selected.length)),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

/// Members, admin controls (add/remove) and leave.
class GroupInfoScreen extends StatefulWidget {
  final String gid;
  const GroupInfoScreen({super.key, required this.gid});
  @override
  State<GroupInfoScreen> createState() => _GroupInfoScreenState();
}

class _GroupInfoScreenState extends State<GroupInfoScreen> {
  Future<void> _addMembers(ChatService chat) async {
    final l = AppLocalizations.of(context);
    final g = chat.groups[widget.gid];
    if (g == null) return;
    final candidates = chat.contacts.values
        .where((c) => !g.memberRids.contains(c.rid))
        .toList()
      ..sort((a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()));
    if (candidates.isEmpty) return;
    final picked = <String>{};
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setSt) => AlertDialog(
          title: Text(l.grpAddMembers),
          content: SizedBox(
            width: double.maxFinite,
            child: ListView(
              shrinkWrap: true,
              children: [
                for (final c in candidates)
                  CheckboxListTile(
                    value: picked.contains(c.rid),
                    activeColor: context.z.accent,
                    checkColor: context.z.onAccent,
                    title: Text(c.name),
                    onChanged: (v) => setSt(() {
                      if (v == true) {
                        picked.add(c.rid);
                      } else {
                        picked.remove(c.rid);
                      }
                    }),
                  ),
              ],
            ),
          ),
          actions: [
            TextButton(
                onPressed: () => Navigator.pop(ctx, false),
                child: Text(l.cancel)),
            FilledButton(
                onPressed: () => Navigator.pop(ctx, true),
                child: Text(l.add)),
          ],
        ),
      ),
    );
    if (ok == true && picked.isNotEmpty) {
      await chat.addGroupMembers(widget.gid, picked.toList());
    }
  }

  Future<void> _leave(ChatService chat) async {
    final l = AppLocalizations.of(context);
    final nav = Navigator.of(context);
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(l.grpLeaveTitle),
        content: Text(
            l.grpLeaveBody),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: Text(l.cancel)),
          FilledButton(
              style: FilledButton.styleFrom(backgroundColor: context.z.danger),
              onPressed: () => Navigator.pop(ctx, true),
              child: Text(l.grpLeave)),
        ],
      ),
    );
    if (ok == true) {
      await chat.leaveGroup(widget.gid);
      nav.pop();
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final chat = context.watch<ChatService>();
    final g = chat.groups[widget.gid];
    if (g == null) {
      return Scaffold(body: Center(child: Text(l.grpRemoved)));
    }
    final members = g.memberRids.toList()
      ..sort((a, b) => (chat.contacts[a]?.name ?? '')
          .toLowerCase()
          .compareTo((chat.contacts[b]?.name ?? '').toLowerCase()));

    return Scaffold(
      appBar: AppBar(title: Text(g.name)),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Center(
            child: CircleAvatar(
              radius: 36,
              backgroundColor: context.z.surfaceAlt,
              child: Icon(Icons.group, size: 36, color: context.z.accent),
            ),
          ),
          const SizedBox(height: 10),
          Center(
            child: Text(
              g.left
                  ? l.grpNoLongerIn
                  : l.grpMemberCount(members.length + 1),
              textAlign: TextAlign.center,
              style: TextStyle(fontSize: 12, color: context.z.textSecondary),
            ),
          ),
          const SizedBox(height: 18),
          Card(
            color: context.z.surface,
            child: Column(
              children: [
                ListTile(
                  leading: Icon(Icons.person, color: context.z.accent),
                  title: Text(g.iAmAdmin ? l.grpYouAdmin : l.grpYou),
                ),
                for (final rid in members)
                  ListTile(
                    leading: CircleAvatar(
                      backgroundColor: context.z.surfaceAlt,
                      child: Text(
                        (chat.contacts[rid]?.name ?? '?')[0].toUpperCase(),
                        style: TextStyle(
                            color: context.z.accent,
                            fontWeight: FontWeight.w700),
                      ),
                    ),
                    title: Row(
                      children: [
                        Flexible(
                          child: Text(chat.contacts[rid]?.name ?? l.grpUnknown,
                              overflow: TextOverflow.ellipsis),
                        ),
                        if (rid == g.adminRid)
                          Padding(
                            padding: EdgeInsets.only(left: 6),
                            child: Text(l.grpAdmin,
                                style: TextStyle(
                                    fontSize: 11,
                                    color: context.z.textSecondary)),
                          ),
                      ],
                    ),
                    trailing: (g.iAmAdmin && !g.left)
                        ? IconButton(
                            icon: Icon(Icons.person_remove_outlined,
                                color: context.z.danger, size: 20),
                            tooltip: l.grpRemoveFromGroup,
                            onPressed: () => chat.removeGroupMember(g.gid, rid),
                          )
                        : null,
                  ),
              ],
            ),
          ),
          const SizedBox(height: 14),
          if (g.iAmAdmin && !g.left)
            OutlinedButton.icon(
              icon: const Icon(Icons.group_add_outlined),
              label: Text(l.grpAddMembers),
              onPressed: () => _addMembers(chat),
            ),
          const SizedBox(height: 8),
          if (!g.left)
            OutlinedButton.icon(
              style:
                  OutlinedButton.styleFrom(foregroundColor: context.z.danger),
              icon: const Icon(Icons.logout),
              label: Text(l.grpLeaveGroup),
              onPressed: () => _leave(chat),
            ),
          const SizedBox(height: 20),
          Text(
            l.grpFootnote,
            style: TextStyle(
                fontSize: 12, color: context.z.textSecondary, height: 1.5),
          ),
        ],
      ),
    );
  }
}
