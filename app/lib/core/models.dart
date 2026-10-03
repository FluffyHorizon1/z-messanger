import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/dart.dart' show DartSha256;
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

  /// The contact's ML-DSA-65 account key, once it is ESTABLISHED: it arrived
  /// in-band and matched [pqCommit], or it was a [pqCandidate] the user
  /// confirmed by comparing the post-quantum safety number (ADR 0021). Never
  /// set from an unchecked source: this being non-null is what [assurance]
  /// reports as hybrid, and what device-list and transparency checks use.
  Uint8List? pqPub;

  /// ADR 0021: an ML-DSA-65 key that arrived in-band for a contact we hold NO
  /// commitment for — a classical code, an accepted contact request, or a
  /// record from before v3. It is kept, not dropped, so that the post-quantum
  /// safety number can be shown and compared; the comparison is what confirms
  /// it, and it becomes [pqPub]. Until then it is used for the NUMBER ONLY —
  /// never for [hybridKey], never to verify a device list or a transparency
  /// claim. A quantum adversary forging the classical channel could plant
  /// one; the comparison catches exactly that, the way it catches a classical
  /// substitution.
  Uint8List? pqCandidate;

  /// ADR 0021: the contact has told us they hold OUR post-quantum key — the
  /// `ack` on their `pqid`, or a `pqack`. A [pqCandidate]'s number is shown
  /// only once they have, so the two screens show one number: a peer that
  /// never says so — a build from before this ADR, which drops a key it holds
  /// no commitment for — keeps both screens classical, which is what it shows
  /// itself.
  bool pqAcked;

  /// ADR 0021: we have told THEM we hold their key — a `pqid` sent with `ack`,
  /// or a `pqack`. Until it is set, their next message earns a `pqack`: that
  /// is how a peer whose key we held before either side kept candidates, or
  /// whose ack we were not running new enough code to answer, still learns it.
  bool pqTold;

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

  /// ADR 0011: this contact was added here by us (a scan, a paste) and we are
  /// still waiting for the other side to accept the request. It clears the
  /// moment any traffic from them arrives — their acceptance, or a message.
  /// While set, the chat is shown as "requested". It says nothing about
  /// authenticity; it is purely "have they answered yet".
  bool requested;

  Contact({
    required this.rid,
    required this.bundle,
    required this.name,
    this.ttlSec = 0,
    this.verified = false,
    required this.createdMs,
    this.pqCommit,
    this.pqPub,
    this.pqCandidate,
    this.pqAcked = false,
    this.pqTold = false,
    this.verifiedSn,
    this.pqMismatch = false,
    this.accountEdPub,
    this.deviceCert,
    this.addedByDevice,
    this.requested = false,
  });

  /// What is actually known about this identity's authenticity.
  ///
  /// The three states are kept apart on purpose (§18.3). The classical view
  /// of a v3 code is byte-for-byte a v1 bundle, so everything keeps working
  /// the moment a code is scanned — which makes it easy to show the identity
  /// as post-quantum before the key has arrived and been checked. It has not.
  IdentityAssurance get assurance {
    // An established key is hybrid however it was established — against a
    // scanned commitment, or by the user comparing the post-quantum number
    // it was a candidate for (ADR 0021). A commitment without a key is
    // pending; neither is classical.
    if (pqPub != null) return IdentityAssurance.hybrid;
    return pqCommit == null
        ? IdentityAssurance.classical
        : IdentityAssurance.pendingPostQuantum;
  }

  /// The contact's account key as a hybrid public key, or null until the
  /// post-quantum half is known and verified. A [pqCandidate] is deliberately
  /// NOT here: this is the key every trust decision reads.
  HybridPublicKey? get hybridKey =>
      pqPub == null ? null : HybridPublicKey(edPub: accountEd, mlPub: pqPub!);

  /// ADR 0021: the post-quantum key the safety NUMBER may use — established,
  /// or a candidate awaiting the comparison that confirms it. Null when
  /// nothing is held, or when a key was refused ([pqMismatch]).
  HybridPublicKey? get numberKey {
    if (pqMismatch) return null;
    final k = pqPub ?? pqCandidate;
    return k == null ? null : HybridPublicKey(edPub: accountEd, mlPub: k);
  }

  /// ADR 0021: whether the post-quantum safety number is the one to show.
  ///
  /// An ESTABLISHED key shows it, as it always has: the commitment came from
  /// a code the user scanned, and a peer that scanned ours shows it too. A
  /// CANDIDATE shows it only once the peer has said it holds our key — then
  /// both sides compute the same number, and comparing it is what confirms
  /// the candidate. A candidate the peer has not acknowledged keeps the
  /// classical number, which is what an older peer shows for us.
  bool get showsPostQuantumNumber {
    if (pqMismatch) return false;
    if (pqPub != null) return true;
    return pqCandidate != null && pqAcked;
  }

  /// What the contact screen says about the post-quantum half (ADR 0021).
  PqDisplay get pqDisplay {
    if (pqMismatch) return PqDisplay.mismatch;
    if (pqPub != null) return PqDisplay.postQuantum;
    if (pqCandidate != null) {
      return pqAcked ? PqDisplay.unverified : PqDisplay.waitingForThem;
    }
    if (pqCommit != null) return PqDisplay.pending;
    return PqDisplay.classical;
  }
}

/// How the contact screen presents the post-quantum half (ADR 0021). Distinct
/// from [IdentityAssurance], which is the TRUST model — what the key may be
/// used to check; this is what the number on screen is derived from, and why.
/// They genuinely differ for a candidate: the number is post-quantum while
/// the identity is still classical.
enum PqDisplay {
  /// Classical number shown; no post-quantum key held for them.
  classical,

  /// Classical number shown; a commitment was scanned but the key has not
  /// arrived yet (§18.3 pending).
  pending,

  /// Classical number shown; we hold their key, but they have not said they
  /// hold ours — an older build, or the exchange is still in flight.
  waitingForThem,

  /// Post-quantum number shown, over a candidate: comparing it is the check.
  unverified,

  /// Post-quantum number shown, over an established key.
  postQuantum,

  /// A key was refused (did not match the commitment); the classical number
  /// is shown and the warning stays.
  mismatch,
}

/// ADR 0011: a pending INBOUND contact request — someone who added us and is
/// waiting on our accept/decline. It is not a contact until accepted; the
/// bundle is what they revealed (self-verifying), and accepting adds them from
/// it exactly as a scan would. It carries no assurance of its own: all it says
/// is that whoever holds these keys asked to connect.
class PendingRequest {
  final String rid;
  final String name;
  final ContactBundle bundle;
  final int createdMs;
  PendingRequest({
    required this.rid,
    required this.name,
    required this.bundle,
    required this.createdMs,
  });
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
///
/// Who may change it is carried in the list itself (ADR 0019): an **owner**
/// and a set of co-admins, the owner always among them. Co-admins add and
/// remove members and rename; only the owner changes who the admins are. The
/// member list is versioned, and a list is applied only when it arrives over
/// the authenticated channel of someone the list currently held lets issue
/// one — `ChatService.mayIssueGroupList` is that rule, and
/// `ChatService._applyGroupInvite` the rest of it.
///
/// Routing ids here are the ones THIS device holds people under, and `''`
/// stands for me, as it always did for the creator's `adminRid`.
class Group {
  final String gid; // random id; doubles as the thread key in `messages`
  String name;

  /// The owner's routing id; `''` when I am the owner. Before ADR 0019 this
  /// was `adminRid`, the creator, and a record written then still reads as
  /// "owner = creator, admins = {creator}".
  String ownerRid;

  /// Everyone who may issue a list, the owner included; `''` for me. Only an
  /// owner's list changes it: leaving the group or being removed from it
  /// does not, it only makes the role unusable until someone adds them back.
  final Set<String> adminRids;

  /// Who issued the list currently held: `''` when I did, else the admin it
  /// arrived from — what a list at the same versions has to outrank.
  String by;

  /// The version of the ROLES: moved on by the owner alone, on every change
  /// to [ownerRid] or [adminRids] (ADR 0019, PROTOCOL §11.1). Lists are
  /// ordered by `(rolesVer, ver, by)`, so an owner's role change outranks
  /// any membership version a co-admin has reached — including one a
  /// co-admin reached by sending its lists to everyone but the owner. Within
  /// one [rolesVer] the owner and the admins never change.
  int rolesVer;

  final Set<String> memberRids; // other members (never includes me)
  int ver; // membership version (an admin bumps it on every change)
  bool left; // I left or was removed — kept for history, no sending

  /// [listDigest] of the held list as its issuer sent it. Two lists at one
  /// `(rolesVer, ver)` — two co-admins changing the group at once, or one
  /// admin on two of their devices before those have synced — are ranked by
  /// it unless one of them is the owner's, so every device keeps the same
  /// one, whoever it holds their issuers as (PROTOCOL §11.1). `''` in a
  /// record written before it existed.
  String digest;

  /// Whether the held list is the one that moved the roles version to
  /// [rolesVer]. Only such a list's sibling — the same issuer, the same
  /// versions — may carry roles of its own; every other list at [rolesVer]
  /// must keep the held ones.
  bool opensRoles;

  /// What the list I issued last changed, while it is the list held: the
  /// members it added (`add`), the ones it removed (`rm`), and the `name`
  /// it gave, if it renamed. When another list replaces it and undoes any
  /// of that, I am told my change did not stand — whatever that list's
  /// version. Null once the held list is somebody else's.
  Map<String, Object?>? mine;

  /// Lists that could not be applied yet (ADR 0019 "held back"): one per
  /// sender, at most [maxHeld], tried again whenever the held list changes.
  /// Kept here, sealed with the rest of the record, because the envelopes
  /// that carried them have been acknowledged: held only in memory, a
  /// restart lost them for good.
  final List<HeldList> held;
  static const maxHeld = 8;

  /// Member entries — `{b: bundle, n: name}`, as a list carries them — for
  /// members whose CONTACT I deleted, while they are in a group I am in. My
  /// lists must keep naming them: a list of mine that silently dropped a
  /// member would remove them, and one that dropped an admin would be
  /// refused by every member. Gone when they are out of the group, and when
  /// I am ([trimmed]).
  final Map<String, Map<String, Object?>> orphans;

  /// Set once this record, left, has let go of the people in it who are no
  /// longer my contacts — on my leave or removal, and on deleting a contact
  /// it named — so it no longer says who was in the group as its list did.
  /// A trimmed record is never sent as a list again: answering a member who
  /// asks (`gsync`), it would be a list that drops members, and taken, it
  /// would remove them.
  bool trimmed;

  /// What a record I am out of holds in place of its owner, or of whoever
  /// issued the list it holds, once their contact is deleted: a value that
  /// names nobody — never a routing id (43 characters), and never `''`,
  /// which is me. The record keeps its shape — an owner among the admins,
  /// an issuer — without keeping them; the group's screen shows an unknown
  /// owner.
  static const nobody = '-';

  Group({
    required this.gid,
    required this.name,
    required this.ownerRid,
    Set<String>? adminRids,
    this.by = '',
    this.rolesVer = 0,
    required this.memberRids,
    this.ver = 1,
    this.left = false,
    this.digest = '',
    this.opensRoles = false,
    this.mine,
    List<HeldList>? held,
    Map<String, Map<String, Object?>>? orphans,
    this.trimmed = false,
  })  : adminRids = {...?adminRids, ownerRid},
        held = held ?? [],
        orphans = orphans ?? {};

  bool get iAmOwner => ownerRid.isEmpty;
  bool get iAmAdmin => adminRids.contains('');

  /// The digest a list is ranked by among lists at one version, computed
  /// from the list exactly as it travels (`ginvite`'s data), so every device
  /// that receives the same list computes the same value: the unpadded
  /// base64url of SHA-256 over [listCanonical]'s UTF-8.
  static String listDigest(Map<String, Object?> data) => b64url(
      const DartSha256().hashSync(utf8.encode(listCanonical(data))).bytes);

  /// The bytes [listDigest] hashes, as PROTOCOL §11.1 pins them: the compact
  /// JSON of `[gid, name, ver, rv, owner, admins, members]` — each as the
  /// list has it (`null` where absent), `admins` sorted, and `members`
  /// replaced by the sorted `ed` strings of its entries. Display names are
  /// left out: they say nothing about who is in the group. Sorted by UTF-16
  /// code unit, which is plain byte order for the ASCII an honest list
  /// carries; escaped as `jsonEncode` does, which §11.1 spells out.
  /// `docs/vectors/v1/inner_messages.json` records it for three lists
  /// (`group_roles_test` 28).
  static String listCanonical(Map<String, Object?> data) {
    final ms = data['members'];
    final members = <String>[
      if (ms is List)
        for (final m in ms)
          if (m is Map && m['b'] is Map && (m['b'] as Map)['ed'] is String)
            (m['b'] as Map)['ed'] as String
    ]..sort();
    final as = data['admins'];
    final admins =
        as is List ? ([for (final a in as) if (a is String) a]..sort()) : null;
    return jsonEncode([
      data['gid'],
      data['name'],
      data['ver'],
      data['rv'],
      data['owner'],
      admins,
      members,
    ]);
  }

  Map<String, Object?> toJson() => {
        'gid': gid,
        'name': name,
        // The pre-0019 field, still written: a build from before roles reads
        // the owner as the one admin, which is the nearest thing it has.
        'admin': ownerRid,
        'owner': ownerRid,
        'admins': adminRids.toList(),
        'by': by,
        'rv': rolesVer,
        'members': memberRids.toList(),
        'ver': ver,
        if (left) 'left': true,
        if (digest.isNotEmpty) 'digest': digest,
        if (opensRoles) 'opens': true,
        if (mine != null) 'mine': mine,
        if (held.isNotEmpty) 'held': [for (final h in held) h.toJson()],
        if (orphans.isNotEmpty) 'orphans': orphans,
        if (trimmed) 'trimmed': true,
      };

  static Group fromJson(Map<String, Object?> j) {
    final legacyAdmin = j['admin'] as String? ?? '';
    // A record from before ADR 0019 has `admin` and nothing else: its one
    // admin is the owner, the only admin, and the issuer of what it holds.
    if (!j.containsKey('owner')) {
      return Group(
        gid: j['gid'] as String,
        name: j['name'] as String? ?? 'Group',
        ownerRid: legacyAdmin,
        by: legacyAdmin,
        memberRids:
            ((j['members'] as List?) ?? const []).cast<String>().toSet(),
        ver: (j['ver'] as num?)?.toInt() ?? 1,
        left: j['left'] == true,
      );
    }
    final owner = j['owner'] as String? ?? legacyAdmin;
    final mine = j['mine'];
    final held = j['held'];
    final orphans = j['orphans'];
    return Group(
      gid: j['gid'] as String,
      name: j['name'] as String? ?? 'Group',
      ownerRid: owner,
      adminRids: ((j['admins'] as List?) ?? const []).cast<String>().toSet(),
      by: j['by'] as String? ?? owner,
      rolesVer: (j['rv'] as num?)?.toInt() ?? 0,
      memberRids:
          ((j['members'] as List?) ?? const []).cast<String>().toSet(),
      ver: (j['ver'] as num?)?.toInt() ?? 1,
      left: j['left'] == true,
      digest: j['digest'] as String? ?? '',
      opensRoles: j['opens'] == true,
      mine: mine is Map ? mine.cast<String, Object?>() : null,
      held: [
        if (held is List)
          for (final h in held)
            if (h is Map) HeldList.fromJson(h.cast<String, Object?>())
      ],
      orphans: {
        if (orphans is Map)
          for (final e in orphans.entries)
            if (e.key is String && e.value is Map)
              e.key as String: (e.value as Map).cast<String, Object?>()
      },
      trimmed: j['trimmed'] == true,
    );
  }
}

/// A `ginvite` held back (ADR 0019): who sent it — `''` for my own account's
/// list mirrored from my other device — and its data as it arrived.
class HeldList {
  final String from;
  final Map<String, Object?> data;
  final bool mirrored;
  HeldList(this.from, this.data, this.mirrored);

  /// The sender as the decision names it: `''` for my own account.
  String get sender => mirrored ? '' : from;

  Map<String, Object?> toJson() =>
      {'f': from, 'd': data, if (mirrored) 'm': true};

  static HeldList fromJson(Map<String, Object?> j) => HeldList(
      j['f'] as String? ?? '',
      (j['d'] as Map? ?? const {}).cast<String, Object?>(),
      j['m'] == true);
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

/// Models a network attacker between two accounts, for tests (§18.9).
///
/// The device-list signature is the single easiest thing on the wire to drop:
/// it is the only ~16 KB envelope an ordinary conversation produces. There is
/// no way to test what a client does about that without being able to produce
/// it, and the alternative — trusting that the detection works — is how
/// detection quietly stops working.
enum PqListSuppression {
  /// Normal: sign, send, and claim.
  none,

  /// Send nothing and claim nothing. NOT an attack — this is a client built
  /// before §18.9, which has a post-quantum identity and never signs lists.
  /// A contact must not be accused over it.
  silent,

  /// Claim to have sent it, and send nothing. This is what a dropped envelope
  /// looks like from the other side, whether the cause was a lost connection
  /// or a relay removing it on purpose.
  claimOnly,
}

enum LinkStatus { disconnected, connecting, connected }
