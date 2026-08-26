import 'package:flutter/material.dart';
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
    final chat = context.read<ChatService>();
    final nav = Navigator.of(context);
    final messenger = ScaffoldMessenger.of(context);
    final name = _name.text.trim();
    if (name.isEmpty || _selected.isEmpty) {
      messenger.showSnackBar(const SnackBar(
          content: Text('Pick a group name and at least one member.')));
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
      messenger.showSnackBar(SnackBar(content: Text('Could not create: $e')));
    }
  }

  @override
  Widget build(BuildContext context) {
    final chat = context.watch<ChatService>();
    final contacts = chat.contacts.values.toList()
      ..sort((a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()));

    return Scaffold(
      appBar: AppBar(title: const Text('New group')),
      body: Column(
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 16, 16, 4),
            child: TextField(
              controller: _name,
              autofocus: true,
              decoration: const InputDecoration(
                labelText: 'Group name',
                helperText:
                    'Members see this name. Messages are end-to-end encrypted '
                    'to each member individually.',
                helperMaxLines: 2,
              ),
            ),
          ),
          Expanded(
            child: contacts.isEmpty
                ? const Center(
                    child: Text('Add some contacts first.',
                        style: TextStyle(color: ZTheme.textSecondary)),
                  )
                : ListView(
                    children: [
                      for (final c in contacts)
                        CheckboxListTile(
                          value: _selected.contains(c.rid),
                          activeColor: ZTheme.accent,
                          checkColor: Colors.black,
                          title: Text(c.name),
                          secondary: CircleAvatar(
                            backgroundColor: ZTheme.surfaceAlt,
                            child: Text(
                              c.name.isNotEmpty
                                  ? c.name[0].toUpperCase()
                                  : '?',
                              style: const TextStyle(
                                  color: ZTheme.accent,
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
                    backgroundColor: ZTheme.accent,
                    foregroundColor: Colors.black,
                    padding: const EdgeInsets.symmetric(vertical: 16),
                  ),
                  onPressed: _busy ? null : _create,
                  child: _busy
                      ? const SizedBox(
                          width: 20,
                          height: 20,
                          child: CircularProgressIndicator(strokeWidth: 2))
                      : Text(
                          'Create group (${_selected.length} member${_selected.length == 1 ? '' : 's'})'),
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
          title: const Text('Add members'),
          content: SizedBox(
            width: double.maxFinite,
            child: ListView(
              shrinkWrap: true,
              children: [
                for (final c in candidates)
                  CheckboxListTile(
                    value: picked.contains(c.rid),
                    activeColor: ZTheme.accent,
                    checkColor: Colors.black,
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
                child: const Text('Cancel')),
            FilledButton(
                onPressed: () => Navigator.pop(ctx, true),
                child: const Text('Add')),
          ],
        ),
      ),
    );
    if (ok == true && picked.isNotEmpty) {
      await chat.addGroupMembers(widget.gid, picked.toList());
    }
  }

  Future<void> _leave(ChatService chat) async {
    final nav = Navigator.of(context);
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Leave this group?'),
        content: const Text(
            'You will stop receiving its messages. Your copy of the history '
            'stays on this device.'),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Cancel')),
          FilledButton(
              style: FilledButton.styleFrom(backgroundColor: ZTheme.danger),
              onPressed: () => Navigator.pop(ctx, true),
              child: const Text('Leave')),
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
    final chat = context.watch<ChatService>();
    final g = chat.groups[widget.gid];
    if (g == null) {
      return const Scaffold(body: Center(child: Text('Group removed')));
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
              backgroundColor: ZTheme.surfaceAlt,
              child: const Icon(Icons.group, size: 36, color: ZTheme.accent),
            ),
          ),
          const SizedBox(height: 10),
          Center(
            child: Text(
              g.left
                  ? 'You are no longer in this group'
                  : '${members.length + 1} members · every message is '
                      'end-to-end encrypted to each member',
              textAlign: TextAlign.center,
              style:
                  const TextStyle(fontSize: 12, color: ZTheme.textSecondary),
            ),
          ),
          const SizedBox(height: 18),
          Card(
            color: ZTheme.surface,
            child: Column(
              children: [
                ListTile(
                  leading: const Icon(Icons.person, color: ZTheme.accent),
                  title: Text(g.iAmAdmin ? 'You (admin)' : 'You'),
                ),
                for (final rid in members)
                  ListTile(
                    leading: CircleAvatar(
                      backgroundColor: ZTheme.surfaceAlt,
                      child: Text(
                        (chat.contacts[rid]?.name ?? '?')[0].toUpperCase(),
                        style: const TextStyle(
                            color: ZTheme.accent, fontWeight: FontWeight.w700),
                      ),
                    ),
                    title: Row(
                      children: [
                        Flexible(
                          child: Text(chat.contacts[rid]?.name ?? 'Unknown',
                              overflow: TextOverflow.ellipsis),
                        ),
                        if (rid == g.adminRid)
                          const Padding(
                            padding: EdgeInsets.only(left: 6),
                            child: Text('admin',
                                style: TextStyle(
                                    fontSize: 11,
                                    color: ZTheme.textSecondary)),
                          ),
                      ],
                    ),
                    trailing: (g.iAmAdmin && !g.left)
                        ? IconButton(
                            icon: const Icon(Icons.person_remove_outlined,
                                color: ZTheme.danger, size: 20),
                            tooltip: 'Remove from group',
                            onPressed: () =>
                                chat.removeGroupMember(g.gid, rid),
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
              label: const Text('Add members'),
              onPressed: () => _addMembers(chat),
            ),
          const SizedBox(height: 8),
          if (!g.left)
            OutlinedButton.icon(
              style:
                  OutlinedButton.styleFrom(foregroundColor: ZTheme.danger),
              icon: const Icon(Icons.logout),
              label: const Text('Leave group'),
              onPressed: () => _leave(chat),
            ),
          const SizedBox(height: 20),
          const Text(
            'Groups have no server-side existence: the relay never learns the '
            'group\'s name or member list. Each message is sent as separate '
            'end-to-end encrypted copies over your verified 1:1 channels.',
            style: TextStyle(fontSize: 12, color: ZTheme.textSecondary,
                height: 1.5),
          ),
        ],
      ),
    );
  }
}
