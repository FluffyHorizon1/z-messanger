import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:z_protocol/z_protocol.dart';

import '../core/chat_service.dart';
import '../core/models.dart';
import 'theme.dart';

class ContactInfoScreen extends StatefulWidget {
  final String rid;
  const ContactInfoScreen({super.key, required this.rid});

  @override
  State<ContactInfoScreen> createState() => _ContactInfoScreenState();
}

class _ContactInfoScreenState extends State<ContactInfoScreen> {
  String? _safety;
  IdentityAssurance? _safetyFor;

  @override
  void initState() {
    super.initState();
    _load(context.read<ChatService>());
  }

  /// The number is not fixed for the life of the screen: it moves the moment
  /// a post-quantum key arrives and matches (§18.5). Recomputing when the
  /// assurance changes is what stops this screen showing the old number while
  /// the rest of the app has moved on — the exact confusion 13.3 exists to
  /// avoid, on the one screen meant to resolve it.
  void _load(ChatService svc) {
    final want = svc.contacts[widget.rid]?.assurance;
    if (want == null || want == _safetyFor) return;
    _safetyFor = want;
    svc.safetyNumberWith(widget.rid).then((s) {
      if (mounted && svc.contacts[widget.rid]?.assurance == want) {
        setState(() => _safety = s);
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    final svc = context.watch<ChatService>();
    final contact = svc.contacts[widget.rid];
    if (contact == null) {
      return const Scaffold(body: Center(child: Text('Contact removed')));
    }
    _load(svc);

    return Scaffold(
      appBar: AppBar(title: Text(contact.name)),
      body: ListView(
        padding: EdgeInsets.fromLTRB(
            16, 16, 16, 16 + MediaQuery.paddingOf(context).bottom),
        children: [
          Center(
            child: CircleAvatar(
              radius: 40,
              backgroundColor: context.z.surfaceAlt,
              child: Text(
                contact.name.isNotEmpty ? contact.name[0].toUpperCase() : '?',
                style: TextStyle(
                    fontSize: 32,
                    color: context.z.accent,
                    fontWeight: FontWeight.w700),
              ),
            ),
          ),
          const SizedBox(height: 8),
          Center(
            child: Text(
              'routing id: ${contact.rid.substring(0, 16)}…',
              style: TextStyle(
                  fontSize: 11,
                  fontFamily: 'monospace',
                  color: context.z.textSecondary),
            ),
          ),
          const SizedBox(height: 24),
          if (contact.pqMismatch) ...[
            _Banner(
              tone: context.z.danger,
              icon: Icons.gpp_bad_outlined,
              title: 'Post-quantum key refused',
              body: 'A post-quantum key arrived for ${contact.name} that does '
                  'not match the code you scanned, so it was rejected and '
                  'their identity was NOT upgraded. Either something is '
                  'broken at their end, or someone is substituting keys. '
                  'Compare the number below before trusting this chat.',
            ),
            const SizedBox(height: 12),
          ],
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Icon(Icons.security, size: 18, color: context.z.accent),
                      const SizedBox(width: 8),
                      const Text('Safety number',
                          style: TextStyle(fontWeight: FontWeight.w700)),
                      const Spacer(),
                      _AssurancePill(assurance: contact.assurance),
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
                  Text(
                    'Compare these 60 digits with the ones on their device '
                    '(in person or on a call you trust). If they match, no '
                    'one is sitting between you — not even the relay.',
                    style: TextStyle(
                        fontSize: 12,
                        color: context.z.textSecondary,
                        height: 1.5),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    _assuranceBlurb(contact.assurance),
                    style: TextStyle(
                        fontSize: 12,
                        color: context.z.textSecondary,
                        height: 1.5),
                  ),
                  if (svc.verificationWith(widget.rid) !=
                      VerificationState.unverified) ...[
                    const SizedBox(height: 12),
                    _VerificationNotice(
                        state: svc.verificationWith(widget.rid),
                        name: contact.name),
                  ],
                  SwitchListTile(
                    contentPadding: EdgeInsets.zero,
                    title: Text(_switchLabel(svc.verificationWith(widget.rid))),
                    value: svc.verificationWith(widget.rid) ==
                        VerificationState.verified,
                    activeThumbColor: context.z.ok,
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
            leading: Icon(Icons.refresh, color: context.z.accent),
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
            leading: Icon(Icons.delete_outline, color: context.z.danger),
            title: Text('Delete contact & all messages',
                style: TextStyle(color: context.z.danger)),
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
                            backgroundColor: context.z.danger),
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

String _assuranceBlurb(IdentityAssurance a) => switch (a) {
      IdentityAssurance.classical =>
        'This identity is signed with Ed25519. Their app has not published a '
            'post-quantum key, so there is nothing further to check.',
      IdentityAssurance.pendingPostQuantum =>
        'The code you scanned promised a post-quantum key that has not '
            'arrived yet. When it does, this number changes ONCE — that is '
            'the upgrade, not tampering, and you will be asked to compare it '
            'again. Until then only the Ed25519 half is covered.',
      IdentityAssurance.hybrid =>
        'Covers both halves of both identities: Ed25519 and ML-DSA-65. The '
            'post-quantum key arrived over the encrypted session and matched '
            'the commitment in the code you scanned.',
    };

String _switchLabel(VerificationState s) => switch (s) {
      VerificationState.verified => 'Verified',
      VerificationState.upgradedReverify => 'I have compared it again',
      VerificationState.changedUnexpectedly => 'I have compared it again',
      VerificationState.unverified => 'Mark as verified',
    };

/// Which of the three states (§18.3) this identity is actually in. Shown
/// rather than inferred, because the classical view of a v3 code works
/// perfectly on its own — which makes it very easy to present an identity as
/// post-quantum when all that has happened is a scan.
class _AssurancePill extends StatelessWidget {
  final IdentityAssurance assurance;
  const _AssurancePill({required this.assurance});

  @override
  Widget build(BuildContext context) {
    final (label, tone) = switch (assurance) {
      IdentityAssurance.classical => ('Classical', context.z.textSecondary),
      IdentityAssurance.pendingPostQuantum => (
          'Post-quantum pending',
          context.z.warn
        ),
      IdentityAssurance.hybrid => ('Post-quantum', context.z.ok),
    };
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: tone.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: tone.withValues(alpha: 0.4)),
      ),
      child: Text(label,
          style: TextStyle(
              fontSize: 11, color: tone, fontWeight: FontWeight.w600)),
    );
  }
}

/// What the tick is worth, in words. The upgrade case is the whole point:
/// a number that changed is indistinguishable from an attack unless the app
/// says which one this is.
class _VerificationNotice extends StatelessWidget {
  final VerificationState state;
  final String name;
  const _VerificationNotice({required this.state, required this.name});

  @override
  Widget build(BuildContext context) {
    return switch (state) {
      VerificationState.verified => _Banner(
          tone: context.z.ok,
          icon: Icons.verified_user_outlined,
          title: 'Verified',
          body: 'This is the number you compared with $name.',
        ),
      VerificationState.upgradedReverify => _Banner(
          tone: context.z.warn,
          icon: Icons.upgrade,
          title: 'The number changed — here is why',
          body: "$name's identity gained a post-quantum key, so the number is "
              'now derived from both halves. That is an upgrade, and it '
              'happens once. It is not a sign that anyone tampered with '
              'anything — but the number you checked before no longer '
              'applies, so please read this one out and compare it again.',
        ),
      VerificationState.changedUnexpectedly => _Banner(
          tone: context.z.danger,
          icon: Icons.gpp_maybe_outlined,
          title: 'The number changed and this app cannot explain why',
          body: 'The number you verified with $name is not the one shown now, '
              'and this is not the one-time post-quantum upgrade. Do not rely '
              'on the previous verification. Compare the number below in '
              'person or on a call you trust before continuing.',
        ),
      VerificationState.unverified => const SizedBox.shrink(),
    };
  }
}

class _Banner extends StatelessWidget {
  final Color tone;
  final IconData icon;
  final String title;
  final String body;
  const _Banner(
      {required this.tone,
      required this.icon,
      required this.title,
      required this.body});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: tone.withValues(alpha: 0.10),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: tone.withValues(alpha: 0.4)),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(icon, size: 18, color: tone),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(title,
                    style: TextStyle(
                        fontSize: 13,
                        fontWeight: FontWeight.w700,
                        color: tone)),
                const SizedBox(height: 4),
                Text(body,
                    style: TextStyle(
                        fontSize: 12,
                        height: 1.5,
                        color: context.z.textPrimary)),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
