import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../core/chat_service.dart';
import 'theme.dart';

class ContactInfoScreen extends StatefulWidget {
  final String rid;
  const ContactInfoScreen({super.key, required this.rid});

  @override
  State<ContactInfoScreen> createState() => _ContactInfoScreenState();
}

class _ContactInfoScreenState extends State<ContactInfoScreen> {
  String? _safety;

  @override
  void initState() {
    super.initState();
    context
        .read<ChatService>()
        .safetyNumberWith(widget.rid)
        .then((s) => mounted ? setState(() => _safety = s) : null);
  }

  @override
  Widget build(BuildContext context) {
    final svc = context.watch<ChatService>();
    final contact = svc.contacts[widget.rid];
    if (contact == null) {
      return const Scaffold(body: Center(child: Text('Contact removed')));
    }

    return Scaffold(
      appBar: AppBar(title: Text(contact.name)),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Center(
            child: CircleAvatar(
              radius: 40,
              backgroundColor: ZTheme.surfaceAlt,
              child: Text(
                contact.name.isNotEmpty ? contact.name[0].toUpperCase() : '?',
                style: const TextStyle(
                    fontSize: 32,
                    color: ZTheme.accent,
                    fontWeight: FontWeight.w700),
              ),
            ),
          ),
          const SizedBox(height: 8),
          Center(
            child: Text(
              'routing id: ${contact.rid.substring(0, 16)}…',
              style: const TextStyle(
                  fontSize: 11,
                  fontFamily: 'monospace',
                  color: ZTheme.textSecondary),
            ),
          ),
          const SizedBox(height: 24),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Row(
                    children: [
                      Icon(Icons.security, size: 18, color: ZTheme.accent),
                      SizedBox(width: 8),
                      Text('Safety number',
                          style: TextStyle(fontWeight: FontWeight.w700)),
                    ],
                  ),
                  const SizedBox(height: 12),
                  if (_safety == null)
                    const Center(child: CircularProgressIndicator())
                  else
                    Center(
                      child: Text(
                        _wrap(_safety!),
                        textAlign: TextAlign.center,
                        style: const TextStyle(
                          fontFamily: 'monospace',
                          fontSize: 16,
                          height: 1.8,
                          letterSpacing: 1,
                        ),
                      ),
                    ),
                  const SizedBox(height: 12),
                  const Text(
                    'Compare these 60 digits with the ones on their device '
                    '(in person or on a call you trust). If they match, no '
                    'one is sitting between you — not even the relay.',
                    style: TextStyle(
                        fontSize: 12, color: ZTheme.textSecondary, height: 1.5),
                  ),
                  SwitchListTile(
                    contentPadding: EdgeInsets.zero,
                    title: const Text('Mark as verified'),
                    value: contact.verified,
                    activeThumbColor: ZTheme.ok,
                    onChanged: (v) => svc.setVerified(widget.rid, v),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 8),
          ListTile(
            leading: const Icon(Icons.timer_outlined),
            title: const Text('Disappearing messages'),
            subtitle: Text(describeTtl(contact.ttlSec)),
          ),
          ListTile(
            leading: const Icon(Icons.edit_outlined),
            title: const Text('Rename'),
            onTap: () async {
              final ctrl = TextEditingController(text: contact.name);
              final name = await showDialog<String>(
                context: context,
                builder: (ctx) => AlertDialog(
                  title: const Text('Rename contact'),
                  content: TextField(controller: ctrl, autofocus: true),
                  actions: [
                    TextButton(
                        onPressed: () => Navigator.pop(ctx),
                        child: const Text('Cancel')),
                    FilledButton(
                        onPressed: () => Navigator.pop(ctx, ctrl.text.trim()),
                        child: const Text('Save')),
                  ],
                ),
              );
              if (name != null && name.isNotEmpty) {
                await svc.renameContact(widget.rid, name);
              }
            },
          ),
          ListTile(
            leading: const Icon(Icons.refresh, color: ZTheme.accent),
            title: const Text('Reset secure session'),
            subtitle: const Text(
                'Start a fresh encryption session (use if messages stop decrypting)'),
            onTap: () async {
              await svc.resetSecureSession(widget.rid);
              if (context.mounted) {
                ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Secure session reset')));
              }
            },
          ),
          ListTile(
            leading: const Icon(Icons.delete_outline, color: ZTheme.danger),
            title: const Text('Delete contact & all messages',
                style: TextStyle(color: ZTheme.danger)),
            onTap: () async {
              final sure = await showDialog<bool>(
                context: context,
                builder: (ctx) => AlertDialog(
                  title: const Text('Delete everything?'),
                  content: const Text(
                      'This wipes the contact, every message and every '
                      'attachment from THIS device. There is no server copy '
                      'to restore from — that is the point.'),
                  actions: [
                    TextButton(
                        onPressed: () => Navigator.pop(ctx, false),
                        child: const Text('Cancel')),
                    FilledButton(
                        style: FilledButton.styleFrom(
                            backgroundColor: ZTheme.danger),
                        onPressed: () => Navigator.pop(ctx, true),
                        child: const Text('Delete')),
                  ],
                ),
              );
              if (sure == true && context.mounted) {
                await svc.deleteContact(widget.rid);
                if (context.mounted) {
                  Navigator.popUntil(context, (r) => r.isFirst);
                }
              }
            },
          ),
        ],
      ),
    );
  }

  String _wrap(String safety) {
    final groups = safety.split(' ');
    final lines = <String>[];
    for (var i = 0; i < groups.length; i += 4) {
      lines.add(groups.skip(i).take(4).join('  '));
    }
    return lines.join('\n');
  }
}
