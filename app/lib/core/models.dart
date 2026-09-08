import 'dart:typed_data';

import 'package:z_protocol/z_protocol.dart';

class Contact {
  final String rid;
  final ContactBundle bundle;
  String name;
  int ttlSec; // disappearing-messages timer for this chat (0 = off)
  bool verified; // user compared safety numbers
  final int createdMs;

  /// v3 (§18.2): the 32-byte commitment carried by the `zc3.` code that was
  /// scanned, if it was one. Null for a v1/v2 contact — nothing post-quantum
  /// was promised, so nothing is missing.
  Uint8List? pqCommit;

  /// The contact's ML-DSA-65 account key, once it has arrived in-band AND
  /// matched [pqCommit]. Never set from an unverified source: this being
  /// non-null is what [assurance] reports as hybrid.
  Uint8List? pqPub;

  /// The safety number the user actually read aloud and confirmed (13.3).
  ///
  /// [verified] records THAT a number was compared; this records WHICH. The
  /// two come apart exactly once in a contact's life, when the identity gains
  /// its post-quantum half and the number moves — and that moment must not
  /// look like a key substitution, nor be papered over with a tick against a
  /// number nobody checked.
  String? verifiedSn;

  /// The ACCOUNT this contact is, when the code said one (§18.7).
  ///
  /// [bundle] describes the DEVICE that was scanned — its keys open the
  /// session and give the routing id — while this is the identity the user
  /// confirmed. Null for every code that predates §18.7, where the device IS
  /// the account (§3.5); [accountEd] is what code should read, and it returns
  /// the bundle's key in that case, so no existing safety number moves.
  Uint8List? accountEdPub;

  /// The account's certificate for [bundle]'s device, present exactly when
  /// [accountEdPub] is. It is the evidence for the claim, kept because a
  /// device this account vouches for is also what a device list is checked
  /// against and what a newly linked device must be told.
  DeviceCertificate? deviceCert;

  /// The key everything a human confirms is anchored to.
  Uint8List get accountEd => accountEdPub ?? bundle.edPub;

  /// Which of my OWN devices added this contact, when it was not this one
  /// (13.7). Null means the user added it here.
  ///
  /// Kept because propagation is the one thing a linked device can assert
  /// that has no scan behind it. The record is insert-only and never
  /// verified, so the worst a rogue device can do is make a chat appear —
  /// and this is what lets the app say where it came from instead of letting
  /// it look like something the user did.
  String? addedByDevice;

  /// A post-quantum key arrived and did NOT match [pqCommit] (§18.2).
  ///
  /// Durable, because the refusal is a fact about this contact and not just a
  /// line in the transcript: the warning is announced once, the contact
  /// screen keeps showing it, and the identity stays pending forever rather
  /// than being retried into acceptance.
  bool pqMismatch;

  Contact({
    required this.rid,
    required this.bundle,
    required this.name,
    this.ttlSec = 0,
    this.verified = false,
    required this.createdMs,
    this.pqCommit,
    this.pqPub,
    this.verifiedSn,
    this.pqMismatch = false,
    this.accountEdPub,
    this.deviceCert,
    this.addedByDevice,
  });

  /// What is actually known about this identity's authenticity.
  ///
  /// The three states are kept apart on purpose (§18.3). The classical view
  /// of a v3 code is byte-for-byte a v1 bundle, so everything keeps working
  /// the moment a code is scanned — which makes it easy to show the identity
  /// as post-quantum before the key has arrived and been checked. It has not.
  IdentityAssurance get assurance {
    if (pqCommit == null) return IdentityAssurance.classical;
    return pqPub == null
        ? IdentityAssurance.pendingPostQuantum
        : IdentityAssurance.hybrid;
  }

  /// The contact's account key as a hybrid public key, or null until the
  /// post-quantum half is known and verified.
  HybridPublicKey? get hybridKey =>
      pqPub == null ? null : HybridPublicKey(edPub: accountEd, mlPub: pqPub!);
}

class FileMeta {
  final String fid;
  final String name;
  final int size;
  final String mime;
  final String sha256b64;
  bool complete;
  int gotChunks;
  int totalChunks;

  /// 7.4: true when this attachment is a recorded voice message (offer member
  /// `voice`), with its duration in seconds (`dur`). Older clients ignore both
  /// and render a plain audio file attachment.
  final bool voice;
  final int durSec;

  FileMeta({
    required this.fid,
    required this.name,
    required this.size,
    required this.mime,
    required this.sha256b64,
    this.complete = false,
    this.gotChunks = 0,
    this.totalChunks = 0,
    this.voice = false,
    this.durSec = 0,
  });
}

/// Outbound message status progression.
class MsgStatus {
  static const int pending = 0; // waiting in the device outbox
  static const int sent = 1; // accepted by the relay (RAM only)
  static const int delivered = 2; // recipient's device confirmed persistence
  static const int read = 3; // recipient opened the chat (E2E receipt)
}

class ChatMessage {
  final String mid;
  final String rid;
  final bool outgoing;
  final String kind; // 'text' | 'file' | 'system' | 'gtext'
  final String body; // text body, or system notice text
  final String? fid; // for kind == 'file'
  final int ts;
  int status;
  final int expireAtMs; // 0 = never
  FileMeta? file; // populated for file messages when loaded
  final String? senderName; // group messages: display name of the sender

  /// 8.1: the `mid` this message replies to, or null. Only the id is stored
  /// and sent — see [quote] for what is actually shown.
  final String? replyTo;

  /// 8.1c: when the sender last edited this message (0 = never). The
  /// original [ts] is kept, so an edit never reorders a conversation.
  int editedMs;

  /// 8.1c: deleted for everyone — the row survives as a tombstone so the
  /// conversation keeps its shape and replies still resolve.
  bool deleted;

  /// 8.1c: shown as "Forwarded" — set on a message that was passed on rather
  /// than written here.
  final bool forwarded;

  /// 8.1b: reactions on this message, newest sender last. Rebuilt from the
  /// `reactions` table whenever the thread is loaded.
  List<MessageReaction> reactions;

  /// 8.1: a snapshot of the quoted message, resolved locally at load time
  /// from [replyTo]. Null when the quoted message is not (or no longer) in
  /// this device's vault, which renders as an unavailable quote.
  QuotedMessage? quote;

  ChatMessage({
    required this.mid,
    required this.rid,
    required this.outgoing,
    required this.kind,
    required this.body,
    this.fid,
    required this.ts,
    this.status = MsgStatus.pending,
    this.expireAtMs = 0,
    this.file,
    this.senderName,
    this.replyTo,
    this.quote,
    List<MessageReaction>? reactions,
    this.editedMs = 0,
    this.deleted = false,
    this.forwarded = false,
  }) : reactions = reactions ?? [];
}

/// One person's reaction to one message (8.1b).
class MessageReaction {
  final String emoji;
  final String senderRid;
  final bool mine;

  /// Display name of the reacting contact; null for me or an unknown rid.
  final String? senderName;

  const MessageReaction({
    required this.emoji,
    required this.senderRid,
    required this.mine,
    this.senderName,
  });
}

/// What a reply shows of the message it answers (8.1). Built from the
/// receiver's own stored copy — nothing about a quote travels on the wire.
class QuotedMessage {
  final String mid;
  final bool outgoing; // was the quoted message mine?
  final String kind; // 'text' | 'file' | 'gtext'
  final String preview; // body, or the attachment's name
  final String? senderName; // group: who wrote the quoted message

  const QuotedMessage({
    required this.mid,
    required this.outgoing,
    required this.kind,
    required this.preview,
    this.senderName,
  });
}

/// A group chat: pairwise-encrypted fan-out over the existing 1:1 ratchets.
/// The creator is the admin; the member list is versioned and only updates
/// arriving over the admin's authenticated channel are applied.
class Group {
  final String gid; // random id; doubles as the thread key in `messages`
  String name;
  final String adminRid; // routing id of the creator ('' when I am the admin)
  final Set<String> memberRids; // other members (never includes me)
  int ver; // membership version (admin bumps on every change)
  bool left; // I left or was removed — kept for history, no sending

  Group({
    required this.gid,
    required this.name,
    required this.adminRid,
    required this.memberRids,
    this.ver = 1,
    this.left = false,
  });

  bool get iAmAdmin => adminRid.isEmpty;

  Map<String, Object?> toJson() => {
        'gid': gid,
        'name': name,
        'admin': adminRid,
        'members': memberRids.toList(),
        'ver': ver,
        if (left) 'left': true,
      };

  static Group fromJson(Map<String, Object?> j) => Group(
        gid: j['gid'] as String,
        name: j['name'] as String? ?? 'Group',
        adminRid: j['admin'] as String? ?? '',
        memberRids:
            ((j['members'] as List?) ?? const []).cast<String>().toSet(),
        ver: (j['ver'] as num?)?.toInt() ?? 1,
        left: j['left'] == true,
      );
}

class ChatSummary {
  final Contact? contact; // 1:1 chat
  final Group? group; // group chat
  final ChatMessage? last;
  final int unread;
  ChatSummary({this.contact, this.group, this.last, this.unread = 0})
      : assert(contact != null || group != null);

  bool get isGroup => group != null;
  String get rid => group?.gid ?? contact!.rid;
  String get title => group?.name ?? contact!.name;
}

/// A message-search result (7.6). Bodies are decrypted only in memory during
/// the search; nothing about the query or its plaintext is written to disk.
class SearchHit {
  final String rid; // the chat (contact rid or gid)
  final String mid;
  final String title; // chat display name
  final bool isGroup;
  final bool outgoing;
  final String kind; // 'text' | 'gtext' | 'file'
  final String snippet; // a window of the body around the match
  final int ts;
  final String? senderName; // for group messages
  SearchHit({
    required this.rid,
    required this.mid,
    required this.title,
    required this.isGroup,
    required this.outgoing,
    required this.kind,
    required this.snippet,
    required this.ts,
    this.senderName,
  });
}

/// What the tick next to a contact is actually worth (13.3).
///
/// Kept apart from [IdentityAssurance], which is about the identity; this is
/// about the USER's act of checking it, and the two can disagree.
enum VerificationState {
  /// Never compared, or compared by a build that did not record which number.
  unverified,

  /// Compared, and the number shown now is the number that was compared.
  verified,

  /// Compared — but the identity has since gained its post-quantum half, so
  /// the number moved. Expected, one time, for every contact in existence;
  /// the user must be told that plainly and asked to read it again.
  upgradedReverify,

  /// Compared, the number moved, and this build cannot account for it. No
  /// legitimate path produces this: it must be surfaced as the alarming
  /// thing it would be, never smoothed into [upgradedReverify].
  changedUnexpectedly,
}

enum LinkStatus { disconnected, connecting, connected }
