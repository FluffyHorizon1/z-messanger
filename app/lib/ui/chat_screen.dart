import 'dart:io';
import 'dart:typed_data';

import 'dart:async';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';
import 'package:record/record.dart';

import '../core/chat_service.dart';
import '../core/models.dart';
import '../core/voice.dart';
import 'contact_info_screen.dart';
import 'group_screens.dart';
import 'theme.dart';
import 'voice_widgets.dart';

class ChatScreen extends StatefulWidget {
  final String rid;
  const ChatScreen({super.key, required this.rid});

  @override
  State<ChatScreen> createState() => _ChatScreenState();
}

class _ChatScreenState extends State<ChatScreen> {
  final _input = TextEditingController();
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

  @override
  void initState() {
    super.initState();
    _scroll.addListener(_maybeLoadOlder);
    final svc = context.read<ChatService>();
    svc.loadMessages(widget.rid).then((_) {
      svc.markChatOpened(widget.rid);
      _jumpToEnd();
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
    context.read<ChatService>().markChatClosed(widget.rid);
    _input.dispose();
    _scroll.dispose();
    _recTimer?.cancel();
    _recSub?.cancel();
    _recorder.dispose();
    super.dispose();
  }

  Future<void> _startRecording() async {
    final messenger = ScaffoldMessenger.of(context);
    try {
      if (!await _recorder.hasPermission()) {
        messenger.showSnackBar(const SnackBar(
            content: Text('Microphone permission is needed to record.')));
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
      messenger.showSnackBar(const SnackBar(
          content: Text("Recording isn't available on this device.")));
    }
  }

  Future<void> _stopRecording({required bool send}) async {
    final svc = context.read<ChatService>();
    final messenger = ScaffoldMessenger.of(context);
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
      messenger.showSnackBar(
          const SnackBar(content: Text('Voice message too short.')));
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
      messenger.showSnackBar(SnackBar(content: Text('Send failed: $e')));
    }
  }

  void _jumpToEnd() {
    // The list is reversed, so offset 0 IS the newest message.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scroll.hasClients) _scroll.jumpTo(0);
    });
  }

  Future<void> _send() async {
    final text = _input.text.trim();
    if (text.isEmpty || _sending) return;
    _input.clear();
    setState(() => _sending = true);
    try {
      final svc = context.read<ChatService>();
      if (svc.groups.containsKey(widget.rid)) {
        await svc.sendGroupText(widget.rid, text);
      } else {
        await svc.sendText(widget.rid, text);
      }
      _jumpToEnd();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('Send failed: $e')));
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
    final current = svc.contacts[widget.rid]?.ttlSec ?? 0;
    final options = <(int, String)>[
      (0, 'Off'),
      (30, '30 seconds'),
      (300, '5 minutes'),
      (3600, '1 hour'),
      (28800, '8 hours'),
      (86400, '1 day'),
      (604800, '1 week'),
    ];
    final chosen = await showModalBottomSheet<int>(
      context: context,
      backgroundColor: ZTheme.surface,
      builder: (ctx) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Padding(
              padding: EdgeInsets.all(16),
              child: Text('Disappearing messages',
                  style: TextStyle(fontWeight: FontWeight.w700)),
            ),
            for (final (sec, label) in options)
              ListTile(
                leading: Icon(
                  sec == current
                      ? Icons.radio_button_checked
                      : Icons.radio_button_off,
                  color: sec == current ? ZTheme.accent : ZTheme.textSecondary,
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
    final svc = context.watch<ChatService>();
    final group = svc.groups[widget.rid];
    final contact = svc.contacts[widget.rid];
    if (contact == null && group == null) {
      return const Scaffold(body: Center(child: Text('Conversation removed')));
    }
    final isGroup = group != null;
    final title = isGroup ? group.name : contact!.name;
    final subtitle = isGroup
        ? '${group.memberRids.length + 1} members · end-to-end encrypted'
        : (contact!.verified
            ? 'end-to-end encrypted · verified'
            : 'end-to-end encrypted');
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
                backgroundColor: ZTheme.surfaceAlt,
                child: isGroup
                    ? const Icon(Icons.group, size: 20, color: ZTheme.accent)
                    : Text(
                        title.isNotEmpty ? title[0].toUpperCase() : '?',
                        style: const TextStyle(
                            color: ZTheme.accent, fontWeight: FontWeight.w700),
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
                        const Icon(Icons.lock, size: 10, color: ZTheme.ok),
                        const SizedBox(width: 4),
                        Flexible(
                          child: Text(
                            subtitle,
                            overflow: TextOverflow.ellipsis,
                            style: const TextStyle(
                                fontSize: 11, color: ZTheme.textSecondary),
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
                color:
                    contact.ttlSec > 0 ? ZTheme.accent : ZTheme.textSecondary,
              ),
              tooltip: 'Disappearing messages',
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
                return _MessageRow(msg: msg, key: ValueKey(msg.mid));
              },
            ),
          ),
          if (isGroup && group.left)
            const SafeArea(
              child: Padding(
                padding: EdgeInsets.all(14),
                child: Text(
                  'You are no longer in this group. History stays on this '
                  'device; no new messages can be sent or received.',
                  textAlign: TextAlign.center,
                  style: TextStyle(fontSize: 12, color: ZTheme.textSecondary),
                ),
              ),
            )
          else if (_recording)
            SafeArea(
              child: Padding(
                padding: const EdgeInsets.fromLTRB(16, 4, 8, 8),
                child: Row(
                  children: [
                    const Icon(Icons.mic, color: ZTheme.danger),
                    const SizedBox(width: 10),
                    Text(describeDuration(_recElapsedMs ~/ 1000),
                        style: const TextStyle(
                            fontSize: 15, fontWeight: FontWeight.w600)),
                    const SizedBox(width: 10),
                    const Expanded(
                      child: Text('Recording… sent encrypted, like everything',
                          overflow: TextOverflow.ellipsis,
                          style: TextStyle(
                              fontSize: 12, color: ZTheme.textSecondary)),
                    ),
                    IconButton(
                      icon: const Icon(Icons.delete_outline,
                          color: ZTheme.textSecondary),
                      tooltip: 'Discard',
                      onPressed: () => _stopRecording(send: false),
                    ),
                    const SizedBox(width: 4),
                    IconButton.filled(
                      style: IconButton.styleFrom(
                          backgroundColor: ZTheme.accent,
                          foregroundColor: Colors.black),
                      icon: const Icon(Icons.arrow_upward),
                      tooltip: 'Send voice message',
                      onPressed: () => _stopRecording(send: true),
                    ),
                  ],
                ),
              ),
            )
          else
            SafeArea(
              child: Padding(
                padding: const EdgeInsets.fromLTRB(8, 4, 8, 8),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.end,
                  children: [
                    IconButton(
                      icon: const Icon(Icons.attach_file,
                          color: ZTheme.textSecondary),
                      onPressed: _attach,
                    ),
                    Expanded(
                      child: TextField(
                        controller: _input,
                        minLines: 1,
                        maxLines: 6,
                        textInputAction: TextInputAction.send,
                        onSubmitted: (_) => _send(),
                        decoration: const InputDecoration(
                          hintText: 'Encrypted message…',
                          contentPadding: EdgeInsets.symmetric(
                              horizontal: 16, vertical: 12),
                        ),
                      ),
                    ),
                    IconButton(
                      icon: const Icon(Icons.mic_none,
                          color: ZTheme.textSecondary),
                      tooltip: 'Record a voice message',
                      onPressed: _startRecording,
                    ),
                    const SizedBox(width: 4),
                    IconButton.filled(
                      style: IconButton.styleFrom(
                          backgroundColor: ZTheme.accent,
                          foregroundColor: Colors.black),
                      icon: const Icon(Icons.arrow_upward),
                      onPressed: _send,
                    ),
                  ],
                ),
              ),
            ),
        ],
      ),
    );
  }
}

class _MessageRow extends StatelessWidget {
  final ChatMessage msg;
  const _MessageRow({super.key, required this.msg});

  @override
  Widget build(BuildContext context) {
    if (msg.kind == 'system') {
      return Padding(
        padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 32),
        child: Text(
          msg.body,
          textAlign: TextAlign.center,
          style: const TextStyle(fontSize: 12, color: ZTheme.textSecondary),
        ),
      );
    }
    final mine = msg.outgoing;
    final failed = mine && msg.status == -1;
    return Align(
      alignment: mine ? Alignment.centerRight : Alignment.centerLeft,
      child: GestureDetector(
        onTap: failed ? () => _showFailedMenu(context) : null,
        child: Container(
          margin: EdgeInsets.only(
            left: mine ? 64 : 12,
            right: mine ? 12 : 64,
            top: 2,
            bottom: 2,
          ),
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
          decoration: BoxDecoration(
            color: mine ? ZTheme.mineBubble : ZTheme.theirsBubble,
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
                      style: const TextStyle(
                          fontSize: 11,
                          fontWeight: FontWeight.w700,
                          color: ZTheme.accent),
                    ),
                  ),
                ),
              if (msg.kind == 'file')
                _FileBody(msg: msg)
              else
                Text(msg.body,
                    style: const TextStyle(fontSize: 15, height: 1.3)),
              const SizedBox(height: 4),
              Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  if (msg.expireAtMs > 0) ...[
                    const Icon(Icons.timer_outlined,
                        size: 11, color: ZTheme.textSecondary),
                    const SizedBox(width: 3),
                  ],
                  Text(
                    DateFormat.Hm()
                        .format(DateTime.fromMillisecondsSinceEpoch(msg.ts)),
                    style: const TextStyle(
                        fontSize: 10, color: ZTheme.textSecondary),
                  ),
                  if (mine) ...[
                    const SizedBox(width: 4),
                    _StatusTicks(status: msg.status),
                  ],
                ],
              ),
              if (failed)
                const Padding(
                  padding: EdgeInsets.only(top: 2),
                  child: Text('Failed to send — tap to retry',
                      style: TextStyle(fontSize: 10, color: ZTheme.danger)),
                ),
            ],
          ),
        ),
      ),
    );
  }

  void _showFailedMenu(BuildContext context) {
    final chat = context.read<ChatService>();
    showModalBottomSheet<void>(
      context: context,
      builder: (ctx) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (msg.kind == 'text')
              ListTile(
                leading: const Icon(Icons.refresh, color: ZTheme.accent),
                title: const Text('Retry send'),
                onTap: () async {
                  Navigator.pop(ctx);
                  final ok = await chat.retryFailedSend(msg.rid, msg.mid);
                  if (!ok && context.mounted) {
                    ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
                        content: Text('Could not retry this message.')));
                  }
                },
              ),
            ListTile(
              leading: const Icon(Icons.delete_outline, color: ZTheme.danger),
              title: const Text('Delete for me'),
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

class _StatusTicks extends StatelessWidget {
  final int status;
  const _StatusTicks({required this.status});

  @override
  Widget build(BuildContext context) {
    return switch (status) {
      -1 => const Icon(Icons.error_outline, size: 12, color: ZTheme.danger),
      MsgStatus.pending =>
        const Icon(Icons.schedule, size: 12, color: ZTheme.textSecondary),
      MsgStatus.sent =>
        const Icon(Icons.check, size: 12, color: ZTheme.textSecondary),
      MsgStatus.delivered =>
        const Icon(Icons.done_all, size: 12, color: ZTheme.textSecondary),
      _ => const Icon(Icons.done_all, size: 12, color: ZTheme.accent),
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
    final f = widget.msg.file;
    if (f == null) {
      return const Text('…', style: TextStyle(color: ZTheme.textSecondary));
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
              child: Image.memory(_imageBytes!, fit: BoxFit.cover),
            ),
          )
        else
          Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.insert_drive_file_outlined,
                  size: 28, color: ZTheme.accent),
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
                          ? _size(f.size)
                          : 'receiving ${f.gotChunks}/${f.totalChunks}…',
                      style: const TextStyle(
                          fontSize: 11, color: ZTheme.textSecondary),
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
                foregroundColor: ZTheme.accent,
              ),
              icon: const Icon(Icons.download, size: 14),
              label: const Text('Save', style: TextStyle(fontSize: 12)),
              onPressed: () => _save(context, f.fid, f.name),
            ),
          ),
      ],
    );
  }

  String _size(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    return '${(bytes / 1024 / 1024).toStringAsFixed(1)} MB';
  }

  Future<void> _save(BuildContext context, String fid, String name) async {
    final svc = context.read<ChatService>();
    final messenger = ScaffoldMessenger.of(context);
    try {
      final bytes = await svc.readAttachment(fid);
      final path = await FilePicker.platform.saveFile(
        dialogTitle: 'Save decrypted copy',
        fileName: name,
        bytes: bytes,
      );
      if (path != null && !Platform.isAndroid) {
        // Desktop platforms return a path but do not write the bytes.
        await File(path).writeAsBytes(bytes, flush: true);
      }
      if (path != null) {
        messenger.showSnackBar(
            const SnackBar(content: Text('Saved (decrypted copy)')));
      }
    } catch (e) {
      messenger.showSnackBar(SnackBar(content: Text('Save failed: $e')));
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
    return Material(
      color: ZTheme.warn.withValues(alpha: 0.12),
      child: Padding(
        padding: const EdgeInsets.fromLTRB(14, 10, 6, 10),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Icon(Icons.gpp_maybe, size: 18, color: ZTheme.warn),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                message,
                style: const TextStyle(fontSize: 12.5, height: 1.35),
              ),
            ),
            IconButton(
              icon: const Icon(Icons.close, size: 18),
              tooltip: 'Dismiss',
              color: ZTheme.textSecondary,
              onPressed: onDismiss,
            ),
          ],
        ),
      ),
    );
  }
}
