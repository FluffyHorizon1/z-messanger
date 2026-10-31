import '../core/key_transparency.dart' show KtFault, KtFaultKind;
import 'app_localizations.dart';

// What a transparency log fault is about, in the reader's language: one
// sentence for each kind of fault the log client records ([KtFaultKind]).
//
// Until 2026-10-31 Settings' transparency status and the home screen's alert
// showed the client's own English words for the fault — "the log shrank:
// held size 2, served 1", "lookup for this account: ..." — to every reader,
// in Spanish too, and the alert called every fault two different histories.
// Those words are the evidence, and are kept as they were recorded: Settings
// shows them, untranslated, behind "What the log client recorded", with a
// Copy that adds the heads the client compared.

/// The sentence for [fault]'s kind: [KtFaultKind.other] for a fault stored
/// before faults had a kind, or for none.
String ktFaultText(AppLocalizations l, KtFault? fault) =>
    switch (fault?.kind ?? KtFaultKind.other) {
      KtFaultKind.head => l.ktFaultHead,
      KtFaultKind.witness => l.ktFaultWitness,
      KtFaultKind.label => l.ktFaultLabel,
      KtFaultKind.ownAccount => l.ktFaultOwnAccount,
      KtFaultKind.contacts => l.ktFaultContacts,
      KtFaultKind.other => l.ktFaultOther,
    };
