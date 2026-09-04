// StreamAudioSource is just_audio's supported route for feeding bytes from
// memory; it is flagged experimental upstream but is the only way to play an
// attachment without writing plaintext to disk.
// ignore_for_file: experimental_member_use

import 'dart:async';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:just_audio/just_audio.dart';
import 'package:provider/provider.dart';

import '../core/chat_service.dart';
import '../core/models.dart';
import 'theme.dart';

/// Serves already-decrypted attachment bytes to the player from memory, so a
/// voice message is never written to disk in plaintext (the vault invariant).
class MemoryAudioSource extends StreamAudioSource {
  final Uint8List bytes;
  final String mime;
  MemoryAudioSource(this.bytes, this.mime);

  @override
  Future<StreamAudioResponse> request([int? start, int? end]) async {
    final s = start ?? 0;
    final e = end ?? bytes.length;
    return StreamAudioResponse(
      sourceLength: bytes.length,
      contentLength: e - s,
      offset: s,
      stream: Stream.value(bytes.sublist(s, e)),
      contentType: mime,
    );
  }
}

/// Inline player for a received/sent voice message: play-pause, progress and
/// duration. Decrypts lazily on first play; playback failures (a desktop
/// platform without an audio backend) degrade to a notice, and the generic
/// file card's Save path still works from the message menu.
class VoiceNoteBody extends StatefulWidget {
  final String fid;
  final FileMeta meta;
  const VoiceNoteBody({super.key, required this.fid, required this.meta});

  @override
  State<VoiceNoteBody> createState() => _VoiceNoteBodyState();
}

class _VoiceNoteBodyState extends State<VoiceNoteBody> {
  AudioPlayer? _player;
  StreamSubscription<PlayerState>? _stateSub;
  bool _loading = false;

  @override
  void dispose() {
    _stateSub?.cancel();
    _player?.dispose();
    super.dispose();
  }

  Future<void> _toggle() async {
    final messenger = ScaffoldMessenger.of(context);
    try {
      var p = _player;
      if (p == null) {
        setState(() => _loading = true);
        final bytes =
            await context.read<ChatService>().readAttachment(widget.fid);
        p = AudioPlayer();
        await p.setAudioSource(MemoryAudioSource(bytes, widget.meta.mime));
        _stateSub = p.playerStateStream.listen((s) {
          if (!mounted) return;
          if (s.processingState == ProcessingState.completed) {
            _player?.pause();
            _player?.seek(Duration.zero);
          }
          setState(() {});
        });
        _player = p;
        if (mounted) setState(() => _loading = false);
        await p.play();
      } else if (p.playing) {
        await p.pause();
      } else {
        await p.play();
      }
    } catch (_) {
      if (mounted) setState(() => _loading = false);
      messenger.showSnackBar(const SnackBar(
          content: Text("Playback isn't available on this device — "
              'save the file instead.')));
    }
  }

  @override
  Widget build(BuildContext context) {
    final p = _player;
    final total = p?.duration ??
        Duration(seconds: widget.meta.durSec > 0 ? widget.meta.durSec : 1);
    return StreamBuilder<Duration>(
      stream: p?.positionStream,
      builder: (context, snap) {
        final pos = snap.data ?? Duration.zero;
        final playing = p?.playing ?? false;
        final frac = total.inMilliseconds == 0
            ? 0.0
            : (pos.inMilliseconds / total.inMilliseconds).clamp(0.0, 1.0);
        final label = describeDuration(
            playing || pos > Duration.zero ? pos.inSeconds : total.inSeconds);
        return Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            SizedBox(
              width: 34,
              height: 34,
              child: _loading
                  ? const Padding(
                      padding: EdgeInsets.all(8),
                      child: CircularProgressIndicator(
                          strokeWidth: 2, color: ZTheme.accent),
                    )
                  : IconButton(
                      padding: EdgeInsets.zero,
                      color: ZTheme.accent,
                      icon: Icon(playing
                          ? Icons.pause_circle_filled
                          : Icons.play_circle_fill),
                      iconSize: 32,
                      onPressed: _toggle,
                    ),
            ),
            const SizedBox(width: 8),
            SizedBox(
              width: 130,
              child: ClipRRect(
                borderRadius: BorderRadius.circular(3),
                child: LinearProgressIndicator(
                  value: frac,
                  minHeight: 4,
                  backgroundColor: ZTheme.surfaceAlt,
                  color: ZTheme.accent,
                ),
              ),
            ),
            const SizedBox(width: 8),
            Text(label,
                style:
                    const TextStyle(fontSize: 12, color: ZTheme.textSecondary)),
          ],
        );
      },
    );
  }
}
