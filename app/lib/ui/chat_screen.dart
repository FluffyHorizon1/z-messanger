import 'dart:io';
import 'dart:typed_data';

import 'dart:async';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show Clipboard, ClipboardData;
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';
import 'package:record/record.dart';

import '../l10n/app_localizations.dart';
import '../l10n/ttl_text.dart';
import '../core/chat_service.dart';
import '../core/file_export.dart';
import '../core/models.dart';
import '../core/voice.dart';
import 'contact_info_screen.dart';
import 'group_screens.dart';
import 'theme.dart';
import 'voice_widgets.dart';

class ChatScreen extends StatefulWidget {
  final String rid;

  /// 7.6: open with this message on screen (a search hit). When it is too far
  /// back to load directly the chat simply opens at the newest messages.
  final String? focusMid;
  const ChatScreen({super.key, required this.rid, this.focusMid});

  @override
  State<ChatScreen> createState() => _ChatScreenState();
}

class _ChatScreenState extends State<ChatScreen> {
  final _input = TextEditingController();
  final _inputFocus = FocusNode();
  final _scroll = ScrollController();
  bool _sending = false;
  bool _loadingOlder = false;

  // Voice-message capture (7.4): PCM streams into RAM only; the WAV is built
  // in memory and enters the normal encrypted-attachment pipeline.
  final AudioRecorder _recorder = AudioRecorder();
  StreamSubscription<Uint8List>? _recSub;
  final BytesBuilder _pcm = BytesBuilder();
  Timer? _recTimer;
  int _recElapsedMs = 0;
  bool _recording = false;

  // 7.6: the search hit being shown, tinted for a moment so the eye finds it.
  String? _highlightMid;
  Timer? _highlightTimer;

  // Read once: dispose() must not look up ancestors (the element is already
  // deactivated there, which is an assertion failure in debug builds).
  late final ChatService _svc;

  @override
  void initState() {
    super.initState();
    _scroll.addListener(_maybeLoadOlder);
    final svc = _svc = context.read<ChatService>();
    final focus = widget.focusMid;
    if (focus != null) {
      svc.loadMessagesAround(widget.rid, focus).then((found) async {
        if (!found) await svc.loadMessages(widget.rid);
        svc.markChatOpened(widget.rid);
        if (found) {
          _jumpToStart();
          _flashHighlight(focus);
        } else {
          _jumpToEnd();
        }
      });
    } else {
      svc.loadMessages(widget.rid).then((_) {
        svc.markChatOpened(widget.rid);
        _jumpToEnd();
      });
    }
  }

  /// With a reversed list the loaded window's OLDEST message — the search hit
  /// — sits at maxScrollExtent. Jump there once laid out, and once more a
  /// frame later so the estimate settles as the rows are built.
  void _jumpToStart() {
    void jump() {
      if (_scroll.hasClients) _scroll.jumpTo(_scroll.position.maxScrollExtent);
    }

    WidgetsBinding.instance.addPostFrameCallback((_) {
      jump();
      WidgetsBinding.instance.addPostFrameCallback((_) => jump());
    });
  }

  void _flashHighlight(String mid) {
    _highlightTimer?.cancel();
    setState(() => _highlightMid = mid);
    _highlightTimer = Timer(const Duration(milliseconds: 2500), () {
      if (mounted) setState(() => _highlightMid = null);
    });
  }

  /// With a reversed list, scrolling towards maxScrollExtent = scrolling into
  /// the past. Page older history in before the user hits the top.
  Future<void> _maybeLoadOlder() async {
    if (_loadingOlder || !_scroll.hasClients) return;
    if (_scroll.position.pixels < _scroll.position.maxScrollExtent - 400) {
      return;
    }
    final svc = context.read<ChatService>();
    if (svc.hasMoreByChat[widget.rid] != true) return;
    _loadingOlder = true;
    try {
      await svc.loadOlderMessages(widget.rid);
    } finally {
      _loadingOlder = false;
    }
  }

  @override
  void dispose() {
    _svc.markChatClosed(widget.rid);
    _input.dispose();
    _inputFocus.dispose();
    _scroll.dispose();
    _recTimer?.cancel();
    _recSub?.cancel();
    _recorder.dispose();
    _highlightTimer?.cancel();
    super.dispose();
  }

  Future<void> _startRecording() async {
    final messenger = ScaffoldMessenger.of(context);
    final l = AppLocalizations.of(context);
    try {
      if (!await _recorder.hasPermission()) {
        messenger.showSnackBar(SnackBar(content: Text(l.chatMicPermission)));
        return;
      }
      // Stream raw PCM into memory — the recording never touches disk.
      final stream = await _recorder.startStream(const RecordConfig(
        encoder: AudioEncoder.pcm16bits,
        sampleRate: voiceSampleRate,
        numChannels: 1,
      ));
      _pcm.clear();
      _recSub = stream.listen(_pcm.add);
      _recTimer = Timer.periodic(const Duration(milliseconds: 250), (_) {
        if (mounted) setState(() => _recElapsedMs += 250);
      });
      setState(() {
        _recording = true;
        _recElapsedMs = 0;
      });
    } catch (_) {
      messenger
          .showSnackBar(SnackBar(content: Text(l.chatRecordingUnavailable)));
    }
  }

  Future<void> _stopRecording({required bool send}) async {
    final svc = context.read<ChatService>();
    final messenger = ScaffoldMessenger.of(context);
    final l = AppLocalizations.of(context);
    _recTimer?.cancel();
    _recTimer = null;
    try {
      await _recorder.stop();
    } catch (_) {}
    await _recSub?.cancel();
    _recSub = null;
    final pcm = _pcm.takeBytes();
    if (mounted) setState(() => _recording = false);
    if (!send) return;
    // Under half a second of audio is a misfire, not a message.
    if (pcm.length < voiceSampleRate) {
      messenger.showSnackBar(SnackBar(content: Text(l.chatVoiceTooShort)));
      return;
    }
    final wav = wavFromPcm16(pcm);
    final dur = pcm16DurationSec(pcm.length);
    try {
      if (svc.groups.containsKey(widget.rid)) {
        await svc.sendGroupVoiceNote(widget.rid, wav, dur, mime: 'audio/wav');
      } else {
        await svc.sendVoiceNote(widget.rid, wav, dur, mime: 'audio/wav');
      }
      _jumpToEnd();
    } catch (e) {
      messenger.showSnackBar(SnackBar(content: Text(l.chatSendFailed('$e'))));
    }
  }

  void _jumpToEnd() {
    // The list is reversed, so offset 0 IS the newest message.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scroll.hasClients) _scroll.jumpTo(0);
    });
  }

  /// 8.1: the message the composer is currently replying to (null = none).
  /// Only its id is sent; the quote a recipient sees comes from their own
  /// copy of that message.
  ChatMessage? _replyTo;

  void _startReply(ChatMessage msg) {
    setState(() => _replyTo = msg);
    _inputFocus.requestFocus();
  }

  /// Opens the conversation at the quoted message and flashes it, reusing the
  /// jump machinery search results use.
  Future<void> _goToQuoted(String mid) async {
    final svc = context.read<ChatService>();
    final messenger = ScaffoldMessenger.of(context);
    final l = AppLocalizations.of(context);
    if (svc.messagesByChat[widget.rid]?.any((m) => m.mid == mid) ?? false) {
      _flashHighlight(mid);
      return;
    }
    if (await svc.loadMessagesAround(widget.rid, mid)) {
      _jumpToStart();
      _flashHighlight(mid);
    } else {
      messenger.showSnackBar(SnackBar(content: Text(l.chatTooFarBack)));
    }
  }

  Future<void> _editMessage(ChatMessage msg) async {
    final l = AppLocalizations.of(context);
    final ctrl = TextEditingController(text: msg.body);
    final next = await showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(l.chatEditTitle),
        content: TextField(
          controller: ctrl,
          autofocus: true,
          maxLines: 5,
          minLines: 1,
          decoration: InputDecoration(hintText: l.chatEditHint),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx), child: Text(l.cancel)),
          FilledButton(
              onPressed: () => Navigator.pop(ctx, ctrl.text.trim()),
              child: Text(l.save)),
        ],
      ),
    );
    if (!mounted || next == null || next.isEmpty || next == msg.body) return;
    final ok = await context
        .read<ChatService>()
        .editMessage(widget.rid, msg.mid, next);
    if (!ok && mounted) {
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text(l.chatEditExpired)));
    }
  }

  Future<void> _deleteForEveryone(ChatMessage msg) async {
    final l = AppLocalizations.of(context);
    final sure = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(l.chatDeleteEveryoneTitle),
        content: Text(l.chatDeleteEveryoneBody),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: Text(l.cancel)),
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: ctx.z.danger),
            onPressed: () => Navigator.pop(ctx, true),
            child: Text(l.delete),
          ),
        ],
      ),
    );
    if (sure != true || !mounted) return;
    await context.read<ChatService>().deleteForEveryone(widget.rid, [msg.mid]);
  }

  Future<void> _forward(ChatMessage msg) async {
    final svc = context.read<ChatService>();
    final messenger = ScaffoldMessenger.of(context);
    final l = AppLocalizations.of(context);
    final targets = <({String rid, String name, bool group})>[
      for (final g in svc.groups.values)
        if (!g.left && g.gid != widget.rid)
          (rid: g.gid, name: g.name, group: true),
      for (final c in svc.contacts.values)
        if (c.rid != widget.rid) (rid: c.rid, name: c.name, group: false),
    ];
    if (targets.isEmpty) {
      messenger.showSnackBar(SnackBar(content: Text(l.chatNoForwardTarget)));
      return;
    }
    final to = await showModalBottomSheet<String>(
      context: context,
      builder: (ctx) => SafeArea(
        child: ListView(
          shrinkWrap: true,
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 14, 16, 6),
              child: Text(l.chatForwardTo,
                  style: TextStyle(
                      fontWeight: FontWeight.w700, color: ctx.z.accent)),
            ),
            for (final t in targets)
              ListTile(
                leading: Icon(t.group ? Icons.group : Icons.person_outline),
                title: Text(t.name),
                onTap: () => Navigator.pop(ctx, t.rid),
              ),
          ],
        ),
      ),
    );
    if (to == null) return;
    try {
      await svc.forwardMessage(widget.rid, msg.mid, to);
      messenger.showSnackBar(SnackBar(content: Text(l.chatForwarded)));
    } catch (e) {
      messenger
          .showSnackBar(SnackBar(content: Text(l.chatForwardFailed('$e'))));
    }
  }

  Future<void> _react(String mid, String emoji) async {
    final l = AppLocalizations.of(context);
    try {
      await context.read<ChatService>().toggleReaction(widget.rid, mid, emoji);
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text(l.chatReactionFailed('$e'))));
      }
    }
  }

  Future<void> _send() async {
    final text = _input.text.trim();
    if (text.isEmpty || _sending) return;
    final l = AppLocalizations.of(context);
    _input.clear();
    final replyTo = _replyTo?.mid;
    setState(() {
      _sending = true;
      _replyTo = null;
    });
    try {
      final svc = context.read<ChatService>();
      if (svc.groups.containsKey(widget.rid)) {
        await svc.sendGroupText(widget.rid, text, replyTo: replyTo);
      } else {
        await svc.sendText(widget.rid, text, replyTo: replyTo);
      }
      _jumpToEnd();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text(l.chatSendFailed('$e'))));
      }
    } finally {
      if (mounted) setState(() => _sending = false);
    }
  }

  Future<void> _attach() async {
    final svc = context.read<ChatService>();
    final messenger = ScaffoldMessenger.of(context);
    final picked = await FilePicker.platform.pickFiles(withData: true);
    final f = picked?.files.single;
    if (f == null) return;
    Uint8List? bytes = f.bytes;
    if (bytes == null && f.path != null) {
      bytes = await File(f.path!).readAsBytes();
    }
    if (bytes == null) return;
    final mime = _guessMime(f.name);
    try {
      if (svc.groups.containsKey(widget.rid)) {
        await svc.sendGroupFile(widget.rid, f.name, bytes, mime);
      } else {
        await svc.sendFile(widget.rid, f.name, bytes, mime);
      }
      _jumpToEnd();
    } catch (e) {
      messenger.showSnackBar(SnackBar(content: Text('$e')));
    }
  }

  String _guessMime(String name) {
    final ext = name.split('.').last.toLowerCase();
    return switch (ext) {
      'jpg' || 'jpeg' => 'image/jpeg',
      'png' => 'image/png',
      'gif' => 'image/gif',
      'webp' => 'image/webp',
      'pdf' => 'application/pdf',
      'mp4' => 'video/mp4',
      'mp3' => 'audio/mpeg',
      'txt' => 'text/plain',
      _ => 'application/octet-stream',
    };
  }

  Future<void> _pickTimer() async {
    final svc = context.read<ChatService>();
    final l = AppLocalizations.of(context);
    final current = svc.contacts[widget.rid]?.ttlSec ?? 0;
    // Labelled through the same function that describes the setting
    // elsewhere, so the picker and the contact screen cannot disagree.
    final options = <(int, String)>[
      for (final sec in const [0, 30, 300, 3600, 28800, 86400, 604800])
        (sec, ttlText(l, sec)),
    ];
    final chosen = await showModalBottomSheet<int>(
      context: context,
      backgroundColor: context.z.surface,
      builder: (ctx) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Padding(
              padding: const EdgeInsets.all(16),
              child: Text(l.disappearingMessages,
                  style: const TextStyle(fontWeight: FontWeight.w700)),
            ),
            for (final (sec, label) in options)
              ListTile(
                leading: Icon(
                  sec == current
                      ? Icons.radio_button_checked
                      : Icons.radio_button_off,
                  color: sec == current
                      ? context.z.accent
                      : context.z.textSecondary,
                ),
                title: Text(label),
                onTap: () => Navigator.pop(ctx, sec),
              ),
          ],
        ),
      ),
    );
    if (chosen != null && chosen != current) {
      await svc.setDisappearingTimer(widget.rid, chosen);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final svc = context.watch<ChatService>();
    final group = svc.groups[widget.rid];
    final contact = svc.contacts[widget.rid];
    if (contact == null && group == null) {
      return Scaffold(body: Center(child: Text(l.chatConversationRemoved)));
    }
    final isGroup = group != null;
    final title = isGroup ? group.name : contact!.name;
    // "verified" here means the tick still covers the number being shown
    // (13.3). A contact whose identity was upgraded has a tick that no longer
    // does, and saying "verified" anyway is the claim this phase exists to
    // stop making.
    final subtitle = isGroup
        ? l.chatGroupSubtitle(group.memberRids.length + 1)
        : switch (svc.verificationWith(widget.rid)) {
            VerificationState.verified => l.chatSubVerified,
            VerificationState.upgradedReverify => l.chatSubReverify,
            VerificationState.changedUnexpectedly => l.chatSubNumberChanged,
            VerificationState.unverified => l.chatSubEncrypted,
          };
    final messages = svc.messagesByChat[widget.rid] ?? [];

    return Scaffold(
      appBar: AppBar(
        titleSpacing: 0,
        title: InkWell(
          onTap: () => Navigator.push(
            context,
            MaterialPageRoute(
                builder: (_) => isGroup
                    ? GroupInfoScreen(gid: widget.rid)
                    : ContactInfoScreen(rid: widget.rid)),
          ),
          child: Row(
            children: [
              CircleAvatar(
                radius: 18,
                backgroundColor: context.z.surfaceAlt,
                child: isGroup
                    ? Icon(Icons.group, size: 20, color: context.z.accent)
                    : Text(
                        title.isNotEmpty ? title[0].toUpperCase() : '?',
                        style: TextStyle(
                            color: context.z.accent,
                            fontWeight: FontWeight.w700),
                      ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(title,
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(
                            fontSize: 16, fontWeight: FontWeight.w600)),
                    Row(
                      children: [
                        Icon(Icons.lock, size: 10, color: context.z.ok),
                        const SizedBox(width: 4),
                        Flexible(
                          child: Text(
                            subtitle,
                            overflow: TextOverflow.ellipsis,
                            style: TextStyle(
                                fontSize: 11, color: context.z.textSecondary),
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
        actions: [
          if (!isGroup)
            IconButton(
              icon: Icon(
                contact!.ttlSec > 0 ? Icons.timer : Icons.timer_outlined,
                color: contact.ttlSec > 0
                    ? context.z.accent
                    : context.z.textSecondary,
              ),
              tooltip: l.disappearingMessages,
              onPressed: _pickTimer,
            ),
        ],
      ),
      body: Column(
        children: [
          if (!isGroup && svc.contactDevlistAlerts[widget.rid] != null)
            _DevlistBanner(
              message: svc.contactDevlistAlerts[widget.rid]!,
              onDismiss: () => svc.acknowledgeContactDevlistAlert(widget.rid),
            ),
          Expanded(
            child: ListView.builder(
              controller: _scroll,
              // Reversed: index 0 = newest, pinned to the bottom. This keeps
              // the view anchored while older pages prepend, and new messages
              // appear at the bottom without any manual jumping.
              reverse: true,
              padding: const EdgeInsets.symmetric(vertical: 12),
              itemCount: messages.length,
              itemBuilder: (context, i) {
                final msg = messages[messages.length - 1 - i];
                return _MessageRow(
                    msg: msg,
                    key: ValueKey(msg.mid),
                    highlighted: msg.mid == _highlightMid,
                    canReply: !(isGroup && group.left),
                    onReply: () => _startReply(msg),
                    onQuoteTap: _goToQuoted,
                    onReact: (isGroup && group.left)
                        ? null
                        : (emoji) => _react(msg.mid, emoji),
                    onEdit: () => _editMessage(msg),
                    onDelete: () => _deleteForEveryone(msg),
                    onForward: () => _forward(msg));
              },
            ),
          ),
          if (isGroup && group.left)
            SafeArea(
              child: Padding(
                padding: EdgeInsets.all(14),
                child: Text(
                  l.chatLeftGroupNotice,
                  textAlign: TextAlign.center,
                  style:
                      TextStyle(fontSize: 12, color: context.z.textSecondary),
                ),
              ),
            )
          else if (_recording)
            SafeArea(
              child: Padding(
                padding: const EdgeInsets.fromLTRB(16, 4, 8, 8),
                child: Row(
                  children: [
                    Icon(Icons.mic, color: context.z.danger),
                    const SizedBox(width: 10),
                    Text(describeDuration(_recElapsedMs ~/ 1000),
                        style: const TextStyle(
                            fontSize: 15, fontWeight: FontWeight.w600)),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Text(l.chatRecordingHint,
                          overflow: TextOverflow.ellipsis,
                          style: TextStyle(
                              fontSize: 12, color: context.z.textSecondary)),
                    ),
                    IconButton(
                      icon: Icon(Icons.delete_outline,
                          color: context.z.textSecondary),
                      tooltip: l.chatDiscard,
                      onPressed: () => _stopRecording(send: false),
                    ),
                    const SizedBox(width: 4),
                    IconButton.filled(
                      style: IconButton.styleFrom(
                          backgroundColor: context.z.accent,
                          foregroundColor: context.z.onAccent),
                      icon: const Icon(Icons.arrow_upward),
                      tooltip: l.chatSendVoice,
                      onPressed: () => _stopRecording(send: true),
                    ),
                  ],
                ),
              ),
            )
          else
            SafeArea(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  if (_replyTo != null)
                    _ReplyBar(
                      msg: _replyTo!,
                      onCancel: () => setState(() => _replyTo = null),
                    ),
                  Padding(
                    padding: const EdgeInsets.fromLTRB(8, 4, 8, 8),
                    child: Row(
                      crossAxisAlignment: CrossAxisAlignment.end,
                      children: [
                        IconButton(
                          tooltip: l.chatAttachFile,
                          icon: Icon(Icons.attach_file,
                              color: context.z.textSecondary),
                          onPressed: _attach,
                        ),
                        Expanded(
                          child: TextField(
                            controller: _input,
                            focusNode: _inputFocus,
                            minLines: 1,
                            maxLines: 6,
                            textInputAction: TextInputAction.send,
                            onSubmitted: (_) => _send(),
                            decoration: InputDecoration(
                              hintText: _replyTo == null
                                  ? l.chatInputHint
                                  : l.chatReplyHint,
                              contentPadding: const EdgeInsets.symmetric(
                                  horizontal: 16, vertical: 12),
                            ),
                          ),
                        ),
                        IconButton(
                          icon: Icon(Icons.mic_none,
                              color: context.z.textSecondary),
                          tooltip: l.chatRecordVoice,
                          onPressed: _startRecording,
                        ),
                        const SizedBox(width: 4),
                        IconButton.filled(
                          style: IconButton.styleFrom(
                              backgroundColor: context.z.accent,
                              foregroundColor: context.z.onAccent),
                          icon: const Icon(Icons.arrow_upward),
                          onPressed: _send,
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
        ],
      ),
    );
  }
}

class _MessageRow extends StatelessWidget {
  final ChatMessage msg;
  final bool highlighted;

  /// 8.1: false in a group you have left — history stays readable, but
  /// there is nothing to reply into.
  final bool canReply;
  final VoidCallback? onReply;
  final void Function(String mid)? onQuoteTap;

  /// 8.1b: toggles my reaction with the given emoji.
  final void Function(String emoji)? onReact;

  /// 8.1c.
  final VoidCallback? onEdit;
  final VoidCallback? onDelete;
  final VoidCallback? onForward;

  const _MessageRow({
    super.key,
    required this.msg,
    this.highlighted = false,
    this.canReply = true,
    this.onReply,
    this.onQuoteTap,
    this.onReact,
    this.onEdit,
    this.onDelete,
    this.onForward,
  });

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    if (msg.kind == 'system') {
      return Padding(
        padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 32),
        child: Text(
          msg.body,
          textAlign: TextAlign.center,
          style: TextStyle(fontSize: 12, color: context.z.textSecondary),
        ),
      );
    }
    final mine = msg.outgoing;
    final failed = mine && msg.status == -1;
    return Align(
      alignment: mine ? Alignment.centerRight : Alignment.centerLeft,
      child: GestureDetector(
        onTap: failed ? () => _showFailedMenu(context) : null,
        onLongPress:
            (canReply && !msg.deleted) ? () => _showActions(context) : null,
        child: Container(
          margin: EdgeInsets.only(
            left: mine ? 64 : 12,
            right: mine ? 12 : 64,
            top: 2,
            bottom: 2,
          ),
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
          decoration: BoxDecoration(
            color: mine ? context.z.mineBubble : context.z.theirsBubble,
            border: highlighted
                ? Border.all(color: context.z.accent, width: 1.5)
                : null,
            borderRadius: BorderRadius.only(
              topLeft: const Radius.circular(16),
              topRight: const Radius.circular(16),
              bottomLeft: Radius.circular(mine ? 16 : 4),
              bottomRight: Radius.circular(mine ? 4 : 16),
            ),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.end,
            mainAxisSize: MainAxisSize.min,
            children: [
              if (!mine && msg.senderName != null)
                Align(
                  alignment: Alignment.centerLeft,
                  child: Padding(
                    padding: const EdgeInsets.only(bottom: 2),
                    child: Text(
                      msg.senderName!,
                      style: TextStyle(
                          fontSize: 11,
                          fontWeight: FontWeight.w700,
                          color: context.z.accent),
                    ),
                  ),
                ),
              // 8.1: the quote is rendered from THIS device's copy of the
              // message being answered — never from anything the sender sent.
              if (msg.replyTo != null)
                _QuoteBlock(
                  quote: msg.quote,
                  mine: mine,
                  onTap: msg.quote == null
                      ? null
                      : () => onQuoteTap?.call(msg.quote!.mid),
                ),
              if (msg.forwarded && !msg.deleted)
                Align(
                  alignment: Alignment.centerLeft,
                  child: Padding(
                    padding: const EdgeInsets.only(bottom: 3),
                    child: Row(mainAxisSize: MainAxisSize.min, children: [
                      Icon(Icons.shortcut,
                          size: 12, color: context.z.textSecondary),
                      const SizedBox(width: 4),
                      Text(l.chatForwardedLabel,
                          style: TextStyle(
                              fontSize: 11,
                              fontStyle: FontStyle.italic,
                              color: context.z.textSecondary)),
                    ]),
                  ),
                ),
              // Left-aligned: a quote widens the bubble past the body, and
              // text hanging off the right edge reads as a mistake.
              Align(
                alignment: Alignment.centerLeft,
                child: msg.deleted
                    ? Row(mainAxisSize: MainAxisSize.min, children: [
                        Icon(Icons.block,
                            size: 14, color: context.z.textSecondary),
                        const SizedBox(width: 6),
                        Text(
                          mine ? l.chatYouDeleted : l.chatTheyDeleted,
                          style: TextStyle(
                              fontSize: 14,
                              fontStyle: FontStyle.italic,
                              color: context.z.textSecondary),
                        ),
                      ])
                    : (msg.kind == 'file'
                        ? _FileBody(msg: msg)
                        : Text(msg.body,
                            style: const TextStyle(fontSize: 15, height: 1.3))),
              ),
              const SizedBox(height: 4),
              Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  if (msg.expireAtMs > 0) ...[
                    Icon(Icons.timer_outlined,
                        size: 11, color: context.z.textSecondary),
                    const SizedBox(width: 3),
                  ],
                  if (msg.editedMs > 0 && !msg.deleted) ...[
                    Text('edited',
                        style: TextStyle(
                            fontSize: 10,
                            fontStyle: FontStyle.italic,
                            color: context.z.textSecondary)),
                    const SizedBox(width: 4),
                  ],
                  Text(
                    DateFormat.Hm()
                        .format(DateTime.fromMillisecondsSinceEpoch(msg.ts)),
                    style:
                        TextStyle(fontSize: 10, color: context.z.textSecondary),
                  ),
                  if (mine) ...[
                    const SizedBox(width: 4),
                    _StatusTicks(status: msg.status),
                  ],
                ],
              ),
              if (failed)
                Padding(
                  padding: EdgeInsets.only(top: 2),
                  child: Text(l.chatFailedTapRetry,
                      style: TextStyle(fontSize: 10, color: context.z.danger)),
                ),
              if (msg.reactions.isNotEmpty)
                Align(
                  alignment: Alignment.centerLeft,
                  child: _ReactionChips(
                    reactions: msg.reactions,
                    onTap: onReact,
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }

  void _showActions(BuildContext context) {
    final l = AppLocalizations.of(context);
    final mine = msg.reactions.where((r) => r.mine).map((r) => r.emoji).toSet();
    showModalBottomSheet<void>(
      context: context,
      builder: (ctx) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (onReact != null)
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 6),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                  children: [
                    for (final emoji in ChatService.quickReactions)
                      IconButton(
                        // Announced as "React with X", and as selected when it
                        // is the one already on this message — an emoji glyph
                        // alone tells a screen-reader user neither.
                        tooltip: mine.contains(emoji)
                            ? l.chatRemoveReaction(emoji)
                            : l.chatReactWith(emoji),
                        // The one already on this message reads as selected.
                        style: mine.contains(emoji)
                            ? IconButton.styleFrom(
                                backgroundColor: ctx.z.accentDim)
                            : null,
                        onPressed: () {
                          Navigator.pop(ctx);
                          onReact!(emoji);
                        },
                        icon: Text(emoji, style: const TextStyle(fontSize: 22)),
                      ),
                  ],
                ),
              ),
            ListTile(
              leading: Icon(Icons.reply, color: ctx.z.accent),
              title: Text(l.chatReply),
              onTap: () {
                Navigator.pop(ctx);
                onReply?.call();
              },
            ),
            if (msg.kind != 'file')
              ListTile(
                leading: Icon(Icons.copy_outlined, color: ctx.z.textSecondary),
                title: Text(l.chatCopyText),
                onTap: () {
                  Clipboard.setData(ClipboardData(text: msg.body));
                  Navigator.pop(ctx);
                },
              ),
            if (onForward != null)
              ListTile(
                leading: Icon(Icons.shortcut, color: ctx.z.textSecondary),
                title: Text(l.chatForward),
                onTap: () {
                  Navigator.pop(ctx);
                  onForward!();
                },
              ),
            // Editing and deleting for everyone are for my own messages.
            if (msg.outgoing && onEdit != null && msg.kind != 'file')
              ListTile(
                leading: Icon(Icons.edit_outlined, color: ctx.z.textSecondary),
                title: Text(l.chatEdit),
                onTap: () {
                  Navigator.pop(ctx);
                  onEdit!();
                },
              ),
            if (msg.outgoing && onDelete != null)
              ListTile(
                leading: Icon(Icons.delete_outline, color: ctx.z.danger),
                title: Text(l.chatDeleteForEveryone,
                    style: TextStyle(color: ctx.z.danger)),
                onTap: () {
                  Navigator.pop(ctx);
                  onDelete!();
                },
              ),
          ],
        ),
      ),
    );
  }

  void _showFailedMenu(BuildContext context) {
    final chat = context.read<ChatService>();
    final l = AppLocalizations.of(context);
    showModalBottomSheet<void>(
      context: context,
      builder: (ctx) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (msg.kind == 'text')
              ListTile(
                leading: Icon(Icons.refresh, color: context.z.accent),
                title: Text(l.chatRetrySend),
                onTap: () async {
                  Navigator.pop(ctx);
                  final ok = await chat.retryFailedSend(msg.rid, msg.mid);
                  if (!ok && context.mounted) {
                    ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(content: Text(l.chatRetryFailed)));
                  }
                },
              ),
            ListTile(
              leading: Icon(Icons.delete_outline, color: context.z.danger),
              title: Text(l.chatDeleteForMe),
              onTap: () {
                Navigator.pop(ctx);
                chat.deleteMessage(msg.rid, msg.mid);
              },
            ),
          ],
        ),
      ),
    );
  }
}

/// Reaction chips under a bubble (8.1b): one chip per distinct emoji with a
/// count, mine outlined. Tapping toggles my own reaction with that emoji.
class _ReactionChips extends StatelessWidget {
  final List<MessageReaction> reactions;
  final void Function(String emoji)? onTap;
  const _ReactionChips({required this.reactions, this.onTap});

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final counts = <String, int>{};
    final mine = <String>{};
    final who = <String, List<String>>{};
    for (final r in reactions) {
      counts[r.emoji] = (counts[r.emoji] ?? 0) + 1;
      if (r.mine) mine.add(r.emoji);
      who
          .putIfAbsent(r.emoji, () => [])
          .add(r.mine ? l.you : (r.senderName ?? l.chatSomeone));
    }
    return Padding(
      padding: const EdgeInsets.only(top: 6),
      child: Wrap(
        spacing: 4,
        runSpacing: 4,
        children: [
          for (final e in counts.keys)
            Tooltip(
              message: who[e]!.join(', '),
              child: InkWell(
                onTap: onTap == null ? null : () => onTap!(e),
                borderRadius: BorderRadius.circular(12),
                child: Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                  decoration: BoxDecoration(
                    color: context.z.surfaceAlt,
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(
                      color: mine.contains(e)
                          ? context.z.accent
                          : context.z.divider,
                    ),
                  ),
                  child: Text(
                    counts[e]! > 1 ? l.chatReactionChip(e, counts[e]!) : e,
                    style: const TextStyle(fontSize: 12),
                  ),
                ),
              ),
            ),
        ],
      ),
    );
  }
}

/// The bar above the composer while a reply is being written (8.1).
class _ReplyBar extends StatelessWidget {
  final ChatMessage msg;
  final VoidCallback onCancel;
  const _ReplyBar({required this.msg, required this.onCancel});

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    // Three strings, not "Replying to " + a word: "yourself" and a name do
    // not take the same grammar in most languages.
    final heading = msg.outgoing
        ? l.chatReplyingToSelf
        : (msg.senderName == null
            ? l.chatReplyingToThem
            : l.chatReplyingTo(msg.senderName!));
    return Container(
      margin: const EdgeInsets.fromLTRB(12, 6, 12, 0),
      padding: const EdgeInsets.fromLTRB(10, 8, 4, 8),
      decoration: BoxDecoration(
        color: context.z.surfaceAlt,
        borderRadius: BorderRadius.circular(10),
        border: Border(left: BorderSide(color: context.z.accent, width: 3)),
      ),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(heading,
                    style: TextStyle(
                        fontSize: 11,
                        fontWeight: FontWeight.w700,
                        color: context.z.accent)),
                const SizedBox(height: 2),
                Text(
                  msg.kind == 'file' ? l.chatPreviewFile(msg.body) : msg.body,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style:
                      TextStyle(fontSize: 12, color: context.z.textSecondary),
                ),
              ],
            ),
          ),
          IconButton(
            icon: Icon(Icons.close, size: 18, color: context.z.textSecondary),
            tooltip: l.chatCancelReply,
            onPressed: onCancel,
          ),
        ],
      ),
    );
  }
}

/// The quoted message shown inside a reply's bubble (8.1). [quote] is null
/// when this device has no copy of the quoted message — it expired, was never
/// received, or arrived before this feature — which is shown honestly rather
/// than guessed at.
class _QuoteBlock extends StatelessWidget {
  final QuotedMessage? quote;
  final bool mine;
  final VoidCallback? onTap;
  const _QuoteBlock({required this.quote, required this.mine, this.onTap});

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final q = quote;
    final unavailable = q == null;
    final who = unavailable
        ? l.chatMessageUnavailable
        : (q.outgoing ? l.you : (q.senderName ?? l.chatThem));
    return GestureDetector(
      onTap: onTap,
      child: Container(
        width: double.infinity,
        margin: const EdgeInsets.only(bottom: 6),
        padding: const EdgeInsets.fromLTRB(8, 6, 8, 6),
        decoration: BoxDecoration(
          color:
              (mine ? context.z.bg : context.z.surface).withValues(alpha: 0.55),
          borderRadius: BorderRadius.circular(8),
          border: Border(
              left: BorderSide(
                  color:
                      unavailable ? context.z.textSecondary : context.z.accent,
                  width: 3)),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(who,
                style: TextStyle(
                    fontSize: 11,
                    fontWeight: FontWeight.w700,
                    fontStyle: unavailable ? FontStyle.italic : null,
                    color: unavailable
                        ? context.z.textSecondary
                        : context.z.accent)),
            if (!unavailable) ...[
              const SizedBox(height: 2),
              Text(
                q.kind == 'file' ? l.chatPreviewFile(q.preview) : q.preview,
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(fontSize: 12, color: context.z.textSecondary),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

class _StatusTicks extends StatelessWidget {
  final int status;
  const _StatusTicks({required this.status});

  @override
  Widget build(BuildContext context) {
    return switch (status) {
      -1 => Icon(Icons.error_outline, size: 12, color: context.z.danger),
      MsgStatus.pending =>
        Icon(Icons.schedule, size: 12, color: context.z.textSecondary),
      MsgStatus.sent =>
        Icon(Icons.check, size: 12, color: context.z.textSecondary),
      MsgStatus.delivered =>
        Icon(Icons.done_all, size: 12, color: context.z.textSecondary),
      _ => Icon(Icons.done_all, size: 12, color: context.z.accent),
    };
  }
}

class _FileBody extends StatefulWidget {
  final ChatMessage msg;
  const _FileBody({required this.msg});

  @override
  State<_FileBody> createState() => _FileBodyState();
}

class _FileBodyState extends State<_FileBody> {
  Uint8List? _imageBytes;
  bool _loadingPreview = false;

  bool get _isImage =>
      (widget.msg.file?.mime ?? '').startsWith('image/') &&
      (widget.msg.file?.complete ?? false);

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final f = widget.msg.file;
    if (f == null) {
      return Text('…', style: TextStyle(color: context.z.textSecondary));
    }
    // 7.4: a complete voice message renders as an inline player; while chunks
    // are still arriving it shows the ordinary receiving card below.
    if (f.voice && f.complete) {
      return VoiceNoteBody(fid: f.fid, meta: f);
    }
    if (_isImage && _imageBytes == null && !_loadingPreview) {
      _loadingPreview = true;
      context
          .read<ChatService>()
          .readAttachment(f.fid)
          .then((b) => mounted ? setState(() => _imageBytes = b) : null)
          .catchError((_) {});
    }
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisSize: MainAxisSize.min,
      children: [
        if (_imageBytes != null)
          ClipRRect(
            borderRadius: BorderRadius.circular(8),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 260, maxHeight: 260),
              // The file name is the only description we have of an
              // image we cannot see into; it beats "image".
              child: Image.memory(_imageBytes!,
                  fit: BoxFit.cover,
                  semanticLabel: widget.msg.file?.name ?? l.chatImage),
            ),
          )
        else
          Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(Icons.insert_drive_file_outlined,
                  size: 28, color: context.z.accent),
              const SizedBox(width: 8),
              Flexible(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(f.name,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(
                            fontSize: 14, fontWeight: FontWeight.w600)),
                    Text(
                      f.complete
                          ? _size(l, f.size)
                          : 'receiving ${f.gotChunks}/${f.totalChunks}…',
                      style: TextStyle(
                          fontSize: 11, color: context.z.textSecondary),
                    ),
                  ],
                ),
              ),
            ],
          ),
        if (f.complete)
          Padding(
            padding: const EdgeInsets.only(top: 6),
            child: TextButton.icon(
              style: TextButton.styleFrom(
                padding: EdgeInsets.zero,
                minimumSize: const Size(0, 28),
                foregroundColor: context.z.accent,
              ),
              icon: const Icon(Icons.download, size: 14),
              label: Text(l.save, style: const TextStyle(fontSize: 12)),
              onPressed: () => _save(context, f.fid, f.name),
            ),
          ),
      ],
    );
  }

  String _size(AppLocalizations l, int bytes) {
    if (bytes < 1024) return l.sizeB('$bytes');
    if (bytes < 1024 * 1024) return l.sizeKb((bytes / 1024).toStringAsFixed(1));
    return l.sizeMb((bytes / 1024 / 1024).toStringAsFixed(1));
  }

  Future<void> _save(BuildContext context, String fid, String name) async {
    final svc = context.read<ChatService>();
    final messenger = ScaffoldMessenger.of(context);
    final l = AppLocalizations.of(context);
    try {
      final bytes = await svc.readAttachment(fid);
      // Who writes the bytes differs per platform; FileExport knows.
      final path = await FileExport.saveBytes(
        dialogTitle: l.chatSaveDialogTitle,
        fileName: name,
        bytes: bytes,
      );
      if (path != null) {
        messenger.showSnackBar(SnackBar(content: Text(l.chatSavedDecrypted)));
      }
    } catch (e) {
      messenger.showSnackBar(SnackBar(content: Text(l.chatSaveFailed('$e'))));
    }
  }
}

/// A dismissible warning strip shown at the top of a chat when this contact's
/// device-list gossip (7.7a) turned up something the user should check.
class _DevlistBanner extends StatelessWidget {
  final String message;
  final VoidCallback onDismiss;
  const _DevlistBanner({required this.message, required this.onDismiss});

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    return Material(
      color: context.z.warn.withValues(alpha: 0.12),
      child: Padding(
        padding: const EdgeInsets.fromLTRB(14, 10, 6, 10),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(Icons.gpp_maybe, size: 18, color: context.z.warn),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                message,
                style: const TextStyle(fontSize: 12.5, height: 1.35),
              ),
            ),
            IconButton(
              icon: const Icon(Icons.close, size: 18),
              tooltip: l.dismiss,
              color: context.z.textSecondary,
              onPressed: onDismiss,
            ),
          ],
        ),
      ),
    );
  }
}
