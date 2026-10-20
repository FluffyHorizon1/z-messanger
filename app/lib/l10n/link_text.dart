import 'package:z_protocol/z_protocol.dart' show IntroLinkProblem;

import '../core/handles.dart';
import '../core/intro_links.dart';
import 'app_localizations.dart';

/// Why what was pasted, scanned or typed is a link this build cannot open
/// (PROTOCOL §21.9's refusals), said so the person knows what to do: update
/// Z for a link from a newer one, copy it again for one damaged on its way,
/// and otherwise that it is not a link a request can go through — a link
/// whose keys or work no reader takes.
String introLinkProblemText(AppLocalizations l, IntroLinkProblem p) =>
    switch (p) {
      IntroLinkProblem.newerVersion => l.plinkErrNewer,
      IntroLinkProblem.notBase64url ||
      IntroLinkProblem.wrongLength ||
      IntroLinkProblem.badCheck =>
        l.plinkErrDamaged,
      IntroLinkProblem.notALink ||
      IntroLinkProblem.powOutOfRange ||
      IntroLinkProblem.weakIntro ||
      IntroLinkProblem.weakXintro =>
        l.plinkErrInvalid,
    };

/// The words for where the account's public link stands (phase 39; ADR
/// 0032), in the reader's language. The service reports each as a typed
/// value and never as a sentence, as for a handle (`handle_text.dart`).

/// The Settings row's line about the account's public link.
String introLinkRowText(AppLocalizations l, HandleService h) {
  if (!h.canManage) return l.hdlRowLinked;
  final link = h.link;
  if (link == null) return l.plinkRowNone;
  return switch (link.phase) {
    IntroLinkPhase.live => l.plinkRowLive,
    IntroLinkPhase.held => l.plinkRowHeld,
  };
}

/// What the link screen says when the relay is not guarding the link's
/// inbox right now (§21.6), by its answer to the link's last `intro` frame;
/// null while it is, or before it has been asked.
String? introLinkRelayGuardText(AppLocalizations l, HandleRelayGuard g) =>
    switch (g) {
      HandleRelayGuard.tooOld => l.plinkRelayUnguarded,
      HandleRelayGuard.full => l.plinkRelayFull,
      HandleRelayGuard.paced => l.plinkRelayPaced,
      HandleRelayGuard.guarded || HandleRelayGuard.unknown => null,
    };
