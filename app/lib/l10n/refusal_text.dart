import '../core/models.dart';
import 'app_localizations.dart';

/// The words for a refused contact code, in the reader's language, at the
/// moment it is shown (42.3).
///
/// The service refuses a code as a kind ([ContactCodeRefusal]) and never as a
/// sentence, the way it stores a system message (`system_text.dart`). It
/// used to throw English sentences, and the add screen and the CONNECT tab
/// showed them as they came — so the warnings that a code names a different
/// identity, or a post-quantum key other than the one held, read in English
/// to everyone. The English stays the exception's message, for logs.
String contactCodeRefusalText(AppLocalizations l, ContactCodeRefused e) =>
    switch (e.kind) {
      ContactCodeRefusal.commitStripped => l.addRefusedCommitStripped(e.name),
      ContactCodeRefusal.unsignedCommitMismatch =>
        l.addRefusedUnsignedCommit(e.name),
      ContactCodeRefusal.ownCode => l.addRefusedOwnCode,
      ContactCodeRefusal.alreadyContact => l.addRefusedAlreadyContact(e.name),
      ContactCodeRefusal.otherIdentity => l.addRefusedOtherIdentity(e.name),
      ContactCodeRefusal.commitChanged => l.addRefusedCommitChanged(e.name),
      ContactCodeRefusal.commitMissesConfirmedKey =>
        l.addRefusedCommitMissesKey(e.name),
      ContactCodeRefusal.keyMismatch => l.addRefusedKeyMismatch(e.name),
      ContactCodeRefusal.invalidCode => l.addRefusedInvalidCode,
    };
