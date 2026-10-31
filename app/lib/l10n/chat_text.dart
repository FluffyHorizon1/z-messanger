import 'dart:io' show FileSystemException;

import 'package:flutter/services.dart' show PlatformException;
import 'package:sqflite_common_ffi/sqflite_ffi.dart' show DatabaseException;

import 'app_localizations.dart';

// What a chat or a group screen says when something it was doing failed, in
// the reader's language, at the moment it is shown.
//
// Nothing here shows an exception's own text. A failure is said by what was
// being done and, where it can be told apart, by what refused it: this
// device's storage, or the camera or the photo library refusing Z. Anything
// else is one line in the reader's language for what was being done. Until
// 2026-10-31 these screens put the exception itself on the screen, in
// English whatever the language: after the screen's words for what had
// failed ("Send failed: " and its kin), or with nothing before it when
// attaching — "FormatException: attachment too large (max 24 MB in this
// build)" for a file over the limit, and for a write the vault refused,
// SQLite's message, the statement with every value it was writing, the
// body sealed, and the database's path.

/// What the screen was doing.
enum ChatAction {
  /// Sending a message: text, a voice message or a file.
  send,

  /// Forwarding a message to another conversation.
  forward,

  /// Adding, changing or withdrawing a reaction.
  react,

  /// Taking a photo, or choosing one or a video from the library.
  attach,

  /// Saving an attachment's decrypted copy.
  save,

  /// Making a group.
  createGroup,
}

/// The line for [action] failing with [error].
String chatFailureText(AppLocalizations l, ChatAction action, Object error) {
  // What these actions write goes to the vault (a database) and, for a
  // file, beside it: refused, it is this device's storage that said no.
  final writes = action != ChatAction.attach && action != ChatAction.save;
  if (writes && (error is DatabaseException || error is FileSystemException)) {
    return l.chatFailedStorage;
  }
  // image_picker's codes for a camera or a library Z may not use.
  if (action == ChatAction.attach &&
      error is PlatformException &&
      error.code.endsWith('_access_denied')) {
    return l.chatAttachNoAccess;
  }
  return switch (action) {
    ChatAction.send => l.chatSendFailedOther,
    ChatAction.forward => l.chatForwardFailedOther,
    ChatAction.react => l.chatReactionFailedOther,
    ChatAction.attach => l.chatAttachFailed,
    ChatAction.save => l.chatSaveFailedOther,
    ChatAction.createGroup => l.grpCreateFailedOther,
  };
}
