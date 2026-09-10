import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:z_protocol/z_protocol.dart';

import '../l10n/app_localizations.dart';
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
    final l = AppLocalizations.of(context);
    final svc = context.watch<ChatService>();
    final contact = svc.contacts[widget.rid];
    if (contact == null) {
      return Scaffold(body: Center(child: Text(l.ciContactRemoved)));
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
              l.ciRoutingId(contact.rid.substring(0, 16)),
              style: TextStyle(
                  fontSize: 11,
                  fontFamily: 'monospace',
                  color: context.z.textSecondary),
            ),
          ),
          const SizedBox(height: 24),
          if (contact.addedByDevice != null) ...[
            // 13.7: this contact arrived from another of the user's own
            // devices rather than from a scan made here. Saying so is the
            // check on the one thing a linked device can assert with no scan
            // behind it — a chat that appears on its own should look like
            // something that happened, not something the user did.
            _Banner(
              tone: context.z.accent,
              icon: Icons.devices_outlined,
              title: l.ciAddedOnDevice(contact.addedByDevice!),
              body: l.ciAddedOnDeviceBody,
            ),
            const SizedBox(height: 12),
          ],
          if (svc.pqListAlerts[widget.rid] != null) ...[
            // §18.9: the signature that makes their device list unforgeable by
            // a quantum adversary was claimed and never arrived. Nothing is
            // broken today, which is exactly why it has to be said out loud —
            // a list that stays classical for ever looks like nothing at all.
            _Banner(
              tone: context.z.warn,
              icon: Icons.cloud_off_outlined,
              title: l.ciPqSigMissing,
              body: svc.pqListAlerts[widget.rid]!,
            ),
            const SizedBox(height: 12),
          ],
          if (contact.pqMismatch) ...[
            _Banner(
              tone: context.z.danger,
              icon: Icons.gpp_bad_outlined,
              title: l.ciPqRefused,
              body: l.ciPqRefusedBody(contact.name),
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
                      Text(l.ciSafetyNumber,
                          style: const TextStyle(fontWeight: FontWeight.w700)),
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
                    l.ciSafetyCompare,
                    style: TextStyle(
                        fontSize: 12,
                        color: context.z.textSecondary,
                        height: 1.5),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    _assuranceBlurb(l, contact.assurance),
                    style: TextStyle(
                        fontSize: 12,
                        color: context.z.textSecondary,
                        height: 1.5),
                  ),
                  if (contact.assurance == IdentityAssurance.hybrid) ...[
                    const SizedBox(height: 8),
                    Text(
                      svc.deviceAssuranceWith(widget.rid) ==
                              DeviceAssurance.hybrid
                          ? l.ciDevListHybrid
                          : l.ciDevListClassical,
                      style: TextStyle(
                          fontSize: 12,
                          color: context.z.textSecondary,
                          height: 1.5),
                    ),
                  ],
                  if (svc.verificationWith(widget.rid) !=
                      VerificationState.unverified) ...[
                    const SizedBox(height: 12),
                    _VerificationNotice(
                        state: svc.verificationWith(widget.rid),
                        name: contact.name),
                  ],
                  SwitchListTile(
                    contentPadding: EdgeInsets.zero,
                    title:
                        Text(_switchLabel(l, svc.verificationWith(widget.rid))),
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
            title: Text(l.ciDisappearing),
            subtitle: Text(describeTtl(contact.ttlSec)),
          ),
          ListTile(
            leading: const Icon(Icons.edit_outlined),
            title: Text(l.ciRename),
            onTap: () async {
              final ctrl = TextEditingController(text: contact.name);
              final name = await showDialog<String>(
                context: context,
                builder: (ctx) => AlertDialog(
                  title: Text(l.ciRenameContact),
                  content: TextField(controller: ctrl, autofocus: true),
                  actions: [
                    TextButton(
                        onPressed: () => Navigator.pop(ctx),
                        child: Text(l.cancel)),
                    FilledButton(
                        onPressed: () => Navigator.pop(ctx, ctrl.text.trim()),
                        child: Text(l.save)),
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
            title: Text(l.ciResetSession),
            subtitle: Text(l.ciResetSessionHelp),
            onTap: () async {
              await svc.resetSecureSession(widget.rid);
              if (context.mounted) {
                ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text(l.ciResetSessionDone)));
              }
            },
          ),
          ListTile(
            leading: Icon(Icons.delete_outline, color: context.z.danger),
            title: Text(l.ciDeleteContact,
                style: TextStyle(color: context.z.danger)),
            onTap: () async {
              final sure = await showDialog<bool>(
                context: context,
                builder: (ctx) => AlertDialog(
                  title: Text(l.ciDeleteTitle),
                  content: Text(l.ciDeleteBody),
                  actions: [
                    TextButton(
                        onPressed: () => Navigator.pop(ctx, false),
                        child: Text(l.cancel)),
                    FilledButton(
                        style: FilledButton.styleFrom(
                            backgroundColor: context.z.danger),
                        onPressed: () => Navigator.pop(ctx, true),
                        child: Text(l.delete)),
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

String _assuranceBlurb(AppLocalizations l, IdentityAssurance a) => switch (a) {
      IdentityAssurance.classical => l.ciBlurbClassical,
      IdentityAssurance.pendingPostQuantum => l.ciBlurbPending,
      IdentityAssurance.hybrid => l.ciBlurbHybrid,
    };

String _switchLabel(AppLocalizations l, VerificationState s) => switch (s) {
      VerificationState.verified => l.ciSwitchVerified,
      VerificationState.upgradedReverify => l.ciSwitchComparedAgain,
      VerificationState.changedUnexpectedly => l.ciSwitchComparedAgain,
      VerificationState.unverified => l.ciSwitchMarkVerified,
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
    final l = AppLocalizations.of(context);
    final (label, tone) = switch (assurance) {
      IdentityAssurance.classical => (
          l.ciPillClassical,
          context.z.textSecondary
        ),
      IdentityAssurance.pendingPostQuantum => (
          l.ciPillPqPending,
          context.z.warn
        ),
      IdentityAssurance.hybrid => (l.ciPillPq, context.z.ok),
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
    final l = AppLocalizations.of(context);
    return switch (state) {
      VerificationState.verified => _Banner(
          tone: context.z.ok,
          icon: Icons.verified_user_outlined,
          title: l.ciNoticeVerified,
          body: l.ciNoticeVerifiedBody(name),
        ),
      VerificationState.upgradedReverify => _Banner(
          tone: context.z.warn,
          icon: Icons.upgrade,
          title: l.ciNoticeUpgraded,
          body: l.ciNoticeUpgradedBody(name),
        ),
      VerificationState.changedUnexpectedly => _Banner(
          tone: context.z.danger,
          icon: Icons.gpp_maybe_outlined,
          title: l.ciNoticeChanged,
          body: l.ciNoticeChangedBody(name),
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
