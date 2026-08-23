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
  final String kind; // 'text' | 'file' | 'system'
  final String body; // text body, or system notice text
  final String? fid; // for kind == 'file'
  final int ts;
  int status;
  final int expireAtMs; // 0 = never
  FileMeta? file; // populated for file messages when loaded

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
  });
}

class ChatSummary {
  final Contact contact;
  final ChatMessage? last;
  final int unread;
  ChatSummary({required this.contact, this.last, this.unread = 0});
}

enum LinkStatus { disconnected, connecting, connected }
