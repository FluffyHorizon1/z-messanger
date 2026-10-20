// Add contact › Handle: find someone by their handle and send them a request
// (phase 38; ADR 0015 revision 2; PROTOCOL §21.7).
//
// What has to be on this screen, where it is read rather than in a settings
// page (ADR 0015, "Handles as a verification signal"): a handle that matches
// is not a key that matches. Whoever answers a request is the account the
// handle introduced — the acknowledgement proves that much — and who that
// account belongs to is the safety number's question, as for every contact.

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:z_protocol/z_protocol.dart';

import '../core/chat_service.dart';
import '../core/handles.dart';
import '../core/intro_links.dart';
import '../l10n/app_localizations.dart';
import '../l10n/handle_text.dart';
import '../l10n/link_text.dart';
import '../l10n/when_text.dart';
import 'open_link_screen.dart';
import 'theme.dart';

class FindHandleView extends StatefulWidget {
  const FindHandleView({super.key});

  @override
  State<FindHandleView> createState() => _FindHandleViewState();
}

class _FindHandleViewState extends State<FindHandleView> {
  final _input = TextEditingController();
  bool _looking = false;
  bool _sending = false;
  HandleLookup? _found;
  String? _error;

  @override
  void dispose() {
    _input.dispose();
    super.dispose();
  }

  Future<void> _find() async {
    if (_looking || _sending) return;
    final l = AppLocalizations.of(context);
    final h = context.read<ChatService>().handles;
    // Phase 39: a public link typed or pasted here is put in front of its
    // person, held (ADR 0032 §3) — asked after §21.1, since a handle can
    // begin as a link does. With no handle log configured it is the one thing
    // this field can take.
    final (:link, :problem) = introLinkInField(_input.text,
        enabled: h.linksEnabled, handleField: true);
    if (link != null || problem != null || !h.available) {
      setState(() {
        _found = null;
        _error = link != null
            ? null
            : problem != null
                ? introLinkProblemText(l, problem)
                : l.hdlUnavailable;
      });
      if (link != null) await openIntroLink(context, link);
      return;
    }
    setState(() {
      _looking = true;
      _found = null;
      _error = null;
    });
    try {
      final found = await h.find(_input.text);
      if (!mounted) return;
      setState(() => _found = found);
    } on HandleFormatException catch (e) {
      if (!mounted) return;
      setState(() =>
          _error = handleProblemText(l, e.problem, character: e.character));
    } on HandleException catch (e) {
      if (!mounted) return;
      setState(() => _error = handleFailureText(l, e.failure));
    } finally {
      if (mounted) setState(() => _looking = false);
    }
  }

  /// The person's choice after a lookup said the handle changed: forget what
  /// this device found before, and take what the log shows now.
  Future<void> _lookUpAsNew(HandleLookup found) async {
    if (_looking || _sending) return;
    final l = AppLocalizations.of(context);
    final h = context.read<ChatService>().handles;
    setState(() {
      _looking = true;
      _error = null;
    });
    try {
      final again = await h.lookUpAsNew(found);
      if (!mounted) return;
      setState(() => _found = again);
    } on HandleException catch (e) {
      if (!mounted) return;
      setState(() => _error = handleFailureText(l, e.failure));
    } finally {
      if (mounted) setState(() => _looking = false);
    }
  }

  Future<void> _request(HandleLookup found) async {
    if (_sending) return;
    final l = AppLocalizations.of(context);
    final messenger = ScaffoldMessenger.of(context);
    final h = context.read<ChatService>().handles;
    setState(() {
      _sending = true;
      _error = null;
    });
    try {
      await h.request(found);
      if (!mounted) return;
      setState(() {
        _found = null;
        _input.clear();
      });
      messenger.showSnackBar(SnackBar(
          content: Text(l.hdlRequestSent(found.handle.canonical))));
    } on HandleException catch (e) {
      if (!mounted) return;
      setState(() => _error = handleFailureText(l, e.failure));
    } finally {
      if (mounted) setState(() => _sending = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final svc = context.watch<ChatService>();
    final h = svc.handles;
    // Phase 39: with links on, the field takes a link where no handle log is
    // configured; with links off, nothing has changed.
    if (!h.available && !h.linksEnabled) {
      return Padding(
        padding: const EdgeInsets.all(24),
        child: Text(l.hdlUnavailable,
            style: TextStyle(color: context.z.textSecondary, height: 1.5)),
      );
    }
    final found = _found;
    return SingleChildScrollView(
      padding: EdgeInsets.fromLTRB(
          24, 24, 24, 24 + MediaQuery.paddingOf(context).bottom),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (h.available)
            Text(l.hdlFindHelp,
                style: TextStyle(color: context.z.textSecondary, height: 1.5))
          else
            Text(l.hdlUnavailable,
                style: TextStyle(color: context.z.textSecondary, height: 1.5)),
          if (h.linksEnabled)
            Padding(
              padding: const EdgeInsets.only(top: 8),
              child: Text(l.plinkFindAlso,
                  style:
                      TextStyle(color: context.z.textSecondary, height: 1.5)),
            ),
          const SizedBox(height: 16),
          TextField(
            controller: _input,
            autocorrect: false,
            enableSuggestions: false,
            textInputAction: TextInputAction.search,
            decoration: InputDecoration(
              labelText: l.hdlFindLabel,
              hintText: l.hdlFindHint,
            ),
            onSubmitted: (_) => _find(),
          ),
          const SizedBox(height: 12),
          FilledButton(
            style: FilledButton.styleFrom(
              backgroundColor: context.z.accent,
              foregroundColor: context.z.onAccent,
              padding: const EdgeInsets.symmetric(vertical: 14),
            ),
            onPressed: _looking || _sending ? null : _find,
            child: Text(_looking ? l.hdlLookingUp : l.hdlFind),
          ),
          if (_error != null)
            Padding(
              padding: const EdgeInsets.only(top: 12),
              child: Text(_error!, style: TextStyle(color: context.z.danger)),
            ),
          if (found != null) ...[
            const SizedBox(height: 16),
            HandleLookupResult(
                found: found,
                busy: _sending || _looking,
                sending: _sending,
                onRequest: () => _request(found),
                onLookUpAsNew: () => _lookUpAsNew(found)),
          ],
          if (h.outgoing.isNotEmpty) ...[
            const SizedBox(height: 24),
            Text(l.hdlWaiting,
                style: const TextStyle(fontWeight: FontWeight.w600)),
            for (final o in h.outgoing)
              ListTile(
                contentPadding: EdgeInsets.zero,
                // §21.8: a request sent on a lookup found, after the fact, to
                // be a history the handle service's witness never saw says
                // so, in the danger tone, until it is forgotten or answered;
                // one whose answer the witness never confirmed says that, in
                // the warning tone. A request through a public link has no
                // handle log behind it, and after 30 days unanswered says so
                // (ADR 0032 §3).
                leading: o.viaLink
                    ? const Icon(Icons.link)
                    : switch (h.forkWarningForRequest(o)) {
                        null => const Icon(Icons.hourglass_empty),
                        final w when w.isFork =>
                          Icon(Icons.gpp_bad, color: context.z.danger),
                        _ => Icon(Icons.gpp_maybe, color: context.z.warn),
                      },
                title: Text(o.viaLink
                    ? l.plinkWaitingEntry(introLinkShort(o.link!))
                    : '@${o.handle}'),
                subtitle: o.viaLink
                    ? (h.linkUnanswered(o)
                        ? Text(l.plinkUnanswered,
                            style:
                                TextStyle(color: context.z.warn, fontSize: 12))
                        : null)
                    : switch (h.forkWarningForRequest(o)) {
                        final w? => Text(
                            (w.isFork
                                ? l.hdlForkAfterRequest
                                : l.hdlUnconfirmedRequest)(
                                w.handle, whenText(context, w.lookedUpMs)),
                            style: TextStyle(
                                color: w.isFork
                                    ? context.z.danger
                                    : context.z.warn,
                                fontSize: 12.5,
                                height: 1.35)),
                        null => null,
                      },
                trailing: TextButton(
                  onPressed: () => h.forgetOutgoingEntry(o),
                  child: Text(l.hdlForgetRequest),
                ),
              ),
          ],
        ],
      ),
    );
  }
}

/// What the lookup found, and — when it can be asked — the request button,
/// under the line that a handle verifies nothing; for a handle that changed
/// since this device last found it, why it was refused and the choice to
/// look it up as new.
class HandleLookupResult extends StatelessWidget {
  final HandleLookup found;
  final bool busy;
  final bool sending;
  final VoidCallback onRequest;
  final VoidCallback onLookUpAsNew;
  const HandleLookupResult(
      {super.key,
      required this.found,
      required this.busy,
      required this.sending,
      required this.onRequest,
      required this.onLookUpAsNew});

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final name = found.handle.canonical;
    final (text, warn) = switch (found.state) {
      HandleLookupState.found => (l.hdlFound(name), false),
      HandleLookupState.notFound => (l.hdlNotFound(name), true),
      HandleLookupState.paused => (l.hdlFoundPaused(name), true),
      HandleLookupState.invalid => (l.hdlFoundInvalid(name), true),
      HandleLookupState.own => (l.hdlFoundOwn, false),
      HandleLookupState.changed => (
          found.change == HandleChange.history
              ? l.hdlFoundChangedHistory(name)
              : l.hdlFoundChangedOwner(name),
          true
        ),
    };
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Semantics(
              label: l.hdlSemFound(name),
              excludeSemantics: true,
              child: Text(text,
                  style: TextStyle(
                      fontWeight: FontWeight.w600,
                      color: warn ? context.z.warn : null)),
            ),
            if (found.state == HandleLookupState.found) ...[
              const SizedBox(height: 8),
              Text(l.hdlFoundNote,
                  style: TextStyle(
                      color: context.z.textSecondary,
                      fontSize: 13,
                      height: 1.4)),
              const SizedBox(height: 12),
              FilledButton(
                onPressed: busy ? null : onRequest,
                child: Text(sending ? l.hdlSending : l.hdlSendRequest),
              ),
            ],
            if (found.state == HandleLookupState.changed) ...[
              const SizedBox(height: 8),
              Text(l.hdlChangedNote,
                  style: TextStyle(
                      color: context.z.textSecondary,
                      fontSize: 13,
                      height: 1.4)),
              const SizedBox(height: 12),
              OutlinedButton(
                onPressed: busy ? null : onLookUpAsNew,
                child: Text(l.hdlLookUpAsNew),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
