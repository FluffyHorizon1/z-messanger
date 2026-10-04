// StreamAudioSource is just_audio's supported route for feeding bytes from
// memory; it is flagged experimental upstream but is the only way to play an
// attachment without writing plaintext to disk.
// ignore_for_file: experimental_member_use

import 'dart:async';
import 'dart:typed_data';

import 'package:flutter/material.dart';

import '../l10n/app_localizations.dart';
import 'package:just_audio/just_audio.dart';
import 'package:provider/provider.dart';

import '../core/chat_service.dart';
import '../core/desktop_audio.dart';
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

/// Why voice messages cannot play in this run, and what fixes it — when the
/// media_kit backend could not load libmpv (P1-18, core/desktop_audio.dart).
/// On Linux libmpv is a system library the user installs; on Windows it ships
/// beside Z's executable, so the fix is the download, not a package.
String voicePlaybackUnavailableText(AppLocalizations l) =>
    voicePlaybackOs == 'windows' ? l.voiceNoLibmpvWindows : l.voiceNoLibmpvLinux;

/// P1-18 — the strip above every screen when the voice backend could not
/// load: playback is off for this run, and here is what is missing. Laid out
/// like the home screen's account banner; dismissible, and back at the next
/// start for as long as the library is still missing. It sits above the
/// Navigator, where there is no Overlay for a tooltip to open in, so its one
/// control is a labelled text button rather than an icon with a tooltip.
class VoicePlaybackNotice extends StatelessWidget {
  final VoidCallback onDismiss;
  const VoicePlaybackNotice({super.key, required this.onDismiss});

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    return Material(
      color: context.z.surfaceAlt,
      child: SafeArea(
        bottom: false,
        child: Padding(
          padding: const EdgeInsets.fromLTRB(14, 10, 6, 10),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(Icons.volume_off, size: 20, color: context.z.accent),
              const SizedBox(width: 10),
              Expanded(
                child: Text(
                  voicePlaybackUnavailableText(l),
                  style: const TextStyle(fontSize: 12.5, height: 1.35),
                ),
              ),
              TextButton(onPressed: onDismiss, child: Text(l.dismiss)),
            ],
          ),
        ),
      ),
    );
  }
}

/// Inline player for a received/sent voice message: play-pause, progress and
/// duration. Decrypts lazily on first play. Every shipping platform now has a
/// backend — native on Android/iOS/macOS, media_kit on Linux/Windows (24.1,
/// core/desktop_audio.dart) — but any playback failure still shows a notice,
/// and the message's long-press menu keeps a Save action so a note can be taken
/// off the device even where it cannot be played (`saveAttachment`,
/// chat_screen.dart). Where the backend could not load at all (P1-18) the
/// control says playback is off and explains why instead: nothing is
/// decrypted and no player is made.
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
    final l = AppLocalizations.of(context);
    if (voicePlayback == VoicePlayback.unavailable) {
      // P1-18: there is no player to hand the bytes to, so they are not
      // read; say why, and what would fix it.
      messenger.showSnackBar(
          SnackBar(content: Text(voicePlaybackUnavailableText(l))));
      return;
    }
    // Resolved now, not in the catch block: reading it after an await
    // would be a BuildContext used across an async gap.
    final noPlayback = l.voiceNoPlayback;
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
      messenger.showSnackBar(SnackBar(content: Text(noPlayback)));
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final off = voicePlayback == VoicePlayback.unavailable;
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
                  ? Padding(
                      padding: EdgeInsets.all(8),
                      child: CircularProgressIndicator(
                          strokeWidth: 2, color: context.z.accent),
                    )
                  : IconButton(
                      tooltip: off
                          ? l.voicePlaybackOff
                          : playing
                              ? l.voicePause
                              : l.voicePlay,
                      padding: EdgeInsets.zero,
                      color: off ? context.z.textSecondary : context.z.accent,
                      icon: Icon(off
                          ? Icons.volume_off
                          : playing
                              ? Icons.pause_circle_filled
                              : Icons.play_circle_fill),
                      iconSize: off ? 26 : 32,
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
                  backgroundColor: context.z.surfaceAlt,
                  color: context.z.accent,
                ),
              ),
            ),
            const SizedBox(width: 8),
            Text(label,
                style: TextStyle(fontSize: 12, color: context.z.textSecondary)),
          ],
        );
      },
    );
  }
}
