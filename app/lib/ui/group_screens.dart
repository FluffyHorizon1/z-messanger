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

/// What the owner chose in the Leave dialog (ADR 0019).
enum _LeaveChoice { leave, transfer }

/// Members with their roles, admin controls (add/remove, and for the owner
/// promote/demote/transfer — ADR 0019) and leave.
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

  /// 23.1: the admin renames the group. The dialog is prefilled with the
  /// current name; an unchanged or empty name is a no-op in the service.
  Future<void> _rename(ChatService chat) async {
    final l = AppLocalizations.of(context);
    final g = chat.groups[widget.gid];
    if (g == null) return;
    final ctrl = TextEditingController(text: g.name);
    final name = await showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(l.grpRename),
        content: TextField(
          controller: ctrl,
          autofocus: true,
          maxLength: 64,
          decoration: InputDecoration(labelText: l.grpName),
          onSubmitted: (v) => Navigator.pop(ctx, v),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx), child: Text(l.cancel)),
          FilledButton(
              onPressed: () => Navigator.pop(ctx, ctrl.text),
              child: Text(l.save)),
        ],
      ),
    );
    ctrl.dispose();
    if (name != null) await chat.renameGroup(widget.gid, name);
  }

  /// ADR 0019: the owner may hand the group to [rid]. Confirmed first — the
  /// step cannot be taken back from this side — with the choice of staying
  /// on as an admin (the default) or stepping down in the same list.
  Future<void> _transferTo(ChatService chat, String rid) async {
    final l = AppLocalizations.of(context);
    final g = chat.groups[widget.gid];
    final name =
        (g == null ? null : chat.groupMemberName(g, rid)) ?? l.grpUnknown;
    var keep = true;
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setSt) => AlertDialog(
          title: Text(l.grpTransferTitle(name)),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(l.grpTransferBody(name)),
              const SizedBox(height: 8),
              // A member on a build from before roles would not know they
              // own the group; nothing here can tell which build they run.
              Text(l.grpTransferOldBuild(name),
                  style: TextStyle(
                      fontSize: 12, color: context.z.textSecondary)),
              const SizedBox(height: 8),
              CheckboxListTile(
                value: keep,
                activeColor: context.z.accent,
                checkColor: context.z.onAccent,
                contentPadding: EdgeInsets.zero,
                title: Text(l.grpTransferKeepAdmin),
                onChanged: (v) => setSt(() => keep = v ?? true),
              ),
            ],
          ),
          actions: [
            TextButton(
                onPressed: () => Navigator.pop(ctx, false),
                child: Text(l.cancel)),
            FilledButton(
                onPressed: () => Navigator.pop(ctx, true),
                child: Text(l.grpMakeOwner)),
          ],
        ),
      ),
    );
    if (ok == true) {
      await chat.transferOwnership(widget.gid, rid, keepAsAdmin: keep);
    }
  }

  /// Pick a member to hand the group to, then confirm as [_transferTo].
  Future<void> _pickNewOwner(ChatService chat) async {
    final l = AppLocalizations.of(context);
    final g = chat.groups[widget.gid];
    if (g == null || g.memberRids.isEmpty) return;
    final members = g.memberRids.toList()
      ..sort((a, b) => (chat.groupMemberName(g, a) ?? '')
          .toLowerCase()
          .compareTo((chat.groupMemberName(g, b) ?? '').toLowerCase()));
    final rid = await showDialog<String>(
      context: context,
      builder: (ctx) => SimpleDialog(
        title: Text(l.grpPickNewOwner),
        children: [
          for (final m in members)
            SimpleDialogOption(
              onPressed: () => Navigator.pop(ctx, m),
              child: Text(chat.groupMemberName(g, m) ?? l.grpUnknown),
            ),
        ],
      ),
    );
    if (rid != null && mounted) await _transferTo(chat, rid);
  }

  Future<void> _leave(ChatService chat) async {
    final l = AppLocalizations.of(context);
    final nav = Navigator.of(context);
    final g = chat.groups[widget.gid];
    // An owner who leaves without transferring freezes the admin set for
    // everyone else (ADR 0019): say so, and offer the transfer first.
    final warnOwner = g != null && g.iAmOwner && g.memberRids.isNotEmpty;
    // Ownership moves only on the device holding the account root; on a
    // linked device the warning stands and says where to transfer instead.
    final canTransfer = chat.canChangeGroupRolesHere;
    // A choice, not a yes/no: dismissing the dialog (null) is a cancel, so
    // "transfer first" needs a value of its own.
    final choice = await showDialog<_LeaveChoice>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(warnOwner ? l.grpLeaveOwnerTitle : l.grpLeaveTitle),
        content: Text(!warnOwner
            ? l.grpLeaveBody
            : canTransfer
                ? l.grpLeaveOwnerBody
                : l.grpLeaveOwnerBodyLinked),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx), child: Text(l.cancel)),
          if (warnOwner && canTransfer)
            TextButton(
                onPressed: () => Navigator.pop(ctx, _LeaveChoice.transfer),
                child: Text(l.grpTransferFirst)),
          FilledButton(
              style: FilledButton.styleFrom(backgroundColor: context.z.danger),
              onPressed: () => Navigator.pop(ctx, _LeaveChoice.leave),
              child: Text(warnOwner ? l.grpLeaveAnyway : l.grpLeave)),
        ],
      ),
    );
    if (choice == _LeaveChoice.leave) {
      await chat.leaveGroup(widget.gid);
      nav.pop();
    } else if (choice == _LeaveChoice.transfer && mounted) {
      await _pickNewOwner(chat);
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
      ..sort((a, b) => (chat.groupMemberName(g, a) ?? '')
          .toLowerCase()
          .compareTo((chat.groupMemberName(g, b) ?? '').toLowerCase()));
    // ADR 0019: who the admins are changes only on the owner's device that
    // holds the account root.
    final rolesHere = g.iAmOwner && chat.canChangeGroupRolesHere;
    // Admins who have left or were removed keep the role on paper: shown,
    // so the owner can take it away.
    final absentAdmins = [
      for (final a in g.adminRids)
        if (a.isNotEmpty && !g.memberRids.contains(a)) a
    ];

    return Scaffold(
      appBar: AppBar(
        title: Text(g.name),
        actions: [
          if (g.iAmAdmin && !g.left)
            IconButton(
              icon: const Icon(Icons.edit_outlined),
              tooltip: l.grpRename,
              onPressed: () => _rename(chat),
            ),
        ],
      ),
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
                  title: Text(g.iAmOwner
                      ? l.grpYouOwner
                      : g.iAmAdmin
                          ? l.grpYouAdmin
                          : l.grpYou),
                  subtitle: g.iAmOwner && !g.left && !rolesHere
                      ? Text(l.grpRolesOnMainDevice,
                          style: TextStyle(
                              fontSize: 12, color: context.z.textSecondary))
                      : null,
                ),
                for (final rid in members)
                  ListTile(
                    leading: CircleAvatar(
                      backgroundColor: context.z.surfaceAlt,
                      child: Text(
                        (chat.groupMemberName(g, rid) ?? '?')[0].toUpperCase(),
                        style: TextStyle(
                            color: context.z.accent,
                            fontWeight: FontWeight.w700),
                      ),
                    ),
                    title: Row(
                      children: [
                        Flexible(
                          child: Text(
                              chat.groupMemberName(g, rid) ?? l.grpUnknown,
                              overflow: TextOverflow.ellipsis),
                        ),
                        if (rid == g.ownerRid || g.adminRids.contains(rid))
                          Padding(
                            padding: const EdgeInsets.only(left: 6),
                            child: Text(
                                rid == g.ownerRid ? l.grpOwner : l.grpAdmin,
                                style: TextStyle(
                                    fontSize: 11,
                                    color: context.z.textSecondary)),
                          ),
                      ],
                    ),
                    // ADR 0019: the owner changes roles; any admin removes a
                    // member — except an admin, whom only the owner may
                    // remove, that being a change to the admin set.
                    trailing: (g.iAmAdmin && !g.left)
                        ? Row(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              if (rolesHere)
                                PopupMenuButton<String>(
                                  icon: Icon(Icons.manage_accounts_outlined,
                                      color: context.z.accent, size: 20),
                                  tooltip: l.grpChangeRole,
                                  onSelected: (v) async {
                                    switch (v) {
                                      case 'promote':
                                        await chat.promoteAdmin(g.gid, rid);
                                      case 'demote':
                                        await chat.demoteAdmin(g.gid, rid);
                                      case 'owner':
                                        await _transferTo(chat, rid);
                                    }
                                  },
                                  itemBuilder: (_) => [
                                    if (!g.adminRids.contains(rid))
                                      PopupMenuItem(
                                          value: 'promote',
                                          child: Text(l.grpMakeAdmin))
                                    else
                                      PopupMenuItem(
                                          value: 'demote',
                                          child: Text(l.grpRemoveAdmin)),
                                    PopupMenuItem(
                                        value: 'owner',
                                        child: Text(l.grpMakeOwner)),
                                  ],
                                ),
                              if (rolesHere || !g.adminRids.contains(rid))
                                IconButton(
                                  icon: Icon(Icons.person_remove_outlined,
                                      color: context.z.danger, size: 20),
                                  tooltip: l.grpRemoveFromGroup,
                                  // Removing a member is signed and fanned
                                  // out to everyone with no undo; ask first,
                                  // as every other destructive action does
                                  // (the 2026-09-14 review's finding 41).
                                  onPressed: () async {
                                    final name =
                                        chat.groupMemberName(g, rid) ??
                                            l.grpUnknown;
                                    final sure = await showDialog<bool>(
                                      context: context,
                                      builder: (ctx) => AlertDialog(
                                        title: Text(l.grpRemoveTitle),
                                        content: Text(l.grpRemoveBody(name)),
                                        actions: [
                                          TextButton(
                                              onPressed: () =>
                                                  Navigator.pop(ctx, false),
                                              child: Text(l.cancel)),
                                          FilledButton(
                                              style: FilledButton.styleFrom(
                                                  backgroundColor:
                                                      context.z.danger),
                                              onPressed: () =>
                                                  Navigator.pop(ctx, true),
                                              child:
                                                  Text(l.grpRemoveConfirm)),
                                        ],
                                      ),
                                    );
                                    if (sure == true) {
                                      await chat.removeGroupMember(
                                          g.gid, rid);
                                    }
                                  },
                                ),
                            ],
                          )
                        : null,
                  ),
                for (final rid in absentAdmins)
                  ListTile(
                    leading: CircleAvatar(
                      backgroundColor: context.z.surfaceAlt,
                      child: Text(
                        (chat.groupMemberName(g, rid) ?? '?')[0].toUpperCase(),
                        style: TextStyle(
                            color: context.z.textSecondary,
                            fontWeight: FontWeight.w700),
                      ),
                    ),
                    title: Text(chat.groupMemberName(g, rid) ?? l.grpUnknown,
                        overflow: TextOverflow.ellipsis,
                        style: TextStyle(color: context.z.textSecondary)),
                    subtitle: Text(
                        rid == g.ownerRid ? l.grpOwner : l.grpAdminNotMember,
                        style: TextStyle(
                            fontSize: 11, color: context.z.textSecondary)),
                    // The owner of record cannot be demoted; any other
                    // absent admin's role is the owner's to take away.
                    trailing: rolesHere && !g.left && rid != g.ownerRid
                        ? IconButton(
                            icon: Icon(Icons.remove_moderator_outlined,
                                color: context.z.accent, size: 20),
                            tooltip: l.grpRemoveAdmin,
                            onPressed: () => chat.demoteAdmin(g.gid, rid),
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
