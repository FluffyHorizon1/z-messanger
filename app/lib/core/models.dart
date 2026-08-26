import 'package:z_protocol/z_protocol.dart';

class Contact {
  final String rid;
  final ContactBundle bundle;
  String name;
  int ttlSec; // disappearing-messages timer for this chat (0 = off)
  bool verified; // user compared safety numbers
  final int createdMs;

  Contact({
    required this.rid,
    required this.bundle,
    required this.name,
    this.ttlSec = 0,
    this.verified = false,
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

  FileMeta({
    required this.fid,
    required this.name,
    required this.size,
    required this.mime,
    required this.sha256b64,
    this.complete = false,
    this.gotChunks = 0,
    this.totalChunks = 0,
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
        memberRids: ((j['members'] as List?) ?? const []).cast<String>().toSet(),
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

enum LinkStatus { disconnected, connecting, connected }
