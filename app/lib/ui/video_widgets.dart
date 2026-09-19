import 'dart:async';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:video_player/video_player.dart';

import '../core/chat_service.dart';
import '../core/loopback_media.dart';
import '../core/models.dart';
import '../l10n/app_localizations.dart';
import 'theme.dart';

/// Inline player for a received/sent video (continuous-b, playback half).
///
/// Decrypts lazily on first play — nothing is read until the user asks — and
/// hands the bytes to `video_player` over a [LoopbackMediaServer] rather than a
/// file, so no plaintext ever touches disk (the vault invariant; ADR 0018). The
/// server lives exactly as long as this widget: it is closed in [dispose], and
/// on any failure, after which the message's Save action remains the way to
/// take the video off the device (`saveAttachment`, chat_screen.dart).
class VideoNoteBody extends StatefulWidget {
  final String fid;
  final FileMeta meta;

  /// How the decrypted bytes are obtained. Defaults to the vault
  /// (`ChatService.readAttachment`); a test hands in bytes directly.
  final Future<Uint8List> Function(BuildContext, String fid)? readBytes;

  const VideoNoteBody(
      {super.key, required this.fid, required this.meta, this.readBytes});

  static Future<Uint8List> _fromVault(BuildContext context, String fid) =>
      context.read<ChatService>().readAttachment(fid);

  @override
  State<VideoNoteBody> createState() => _VideoNoteBodyState();
}

class _VideoNoteBodyState extends State<VideoNoteBody> {
  LoopbackMediaServer? _srv;
  VideoPlayerController? _ctrl;
  bool _loading = false;
  bool _failed = false;

  @override
  void dispose() {
    _ctrl?.removeListener(_onTick);
    _ctrl?.dispose();
    // Nothing else references the bytes once the server is gone.
    unawaited(_srv?.close());
    super.dispose();
  }

  void _onTick() {
    if (mounted) setState(() {});
  }

  Future<void> _open() async {
    final messenger = ScaffoldMessenger.of(context);
    // Resolved before the awaits: no BuildContext across an async gap.
    final noPlayback = AppLocalizations.of(context).videoNoPlayback;
    setState(() => _loading = true);
    LoopbackMediaServer? srv;
    VideoPlayerController? ctrl;
    try {
      final bytes = await (widget.readBytes ?? VideoNoteBody._fromVault)(
          context, widget.fid);
      srv = await LoopbackMediaServer.start(bytes, widget.meta.mime);
      ctrl = VideoPlayerController.networkUrl(srv.uri);
      await ctrl.initialize();
      await ctrl.setLooping(false);
      if (!mounted) {
        await ctrl.dispose();
        await srv.close();
        return;
      }
      ctrl.addListener(_onTick);
      setState(() {
        _srv = srv;
        _ctrl = ctrl;
        _loading = false;
      });
      await ctrl.play();
    } catch (_) {
      // A controller whose initialize() failed may never finish disposing —
      // video_player's creation future is left incomplete — so it is not
      // waited on. The server is: it is what holds the bytes.
      if (ctrl != null) unawaited(ctrl.dispose().catchError((_) {}));
      await srv?.close();
      if (mounted) {
        setState(() {
          _loading = false;
          _failed = true;
        });
      }
      messenger.showSnackBar(SnackBar(content: Text(noPlayback)));
    }
  }

  Future<void> _toggle() async {
    final c = _ctrl;
    if (c == null) return _open();
    if (c.value.isPlaying) {
      await c.pause();
    } else {
      if (c.value.position >= c.value.duration) await c.seekTo(Duration.zero);
      await c.play();
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = AppLocalizations.of(context);
    final name = widget.meta.name.isEmpty ? l.chatVideo : widget.meta.name;
    if (_failed) {
      return Text(l.videoNoPlayback,
          style: TextStyle(fontSize: 12, color: context.z.textSecondary));
    }
    final c = _ctrl;
    final playing = c?.value.isPlaying ?? false;
    final Widget surface;
    if (c != null && c.value.isInitialized) {
      surface = AspectRatio(
        aspectRatio: c.value.aspectRatio <= 0 ? 16 / 9 : c.value.aspectRatio,
        child: VideoPlayer(c),
      );
    } else {
      surface = const AspectRatio(
        aspectRatio: 16 / 9,
        child: ColoredBox(color: Colors.black),
      );
    }
    return ClipRRect(
      borderRadius: BorderRadius.circular(8),
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 260),
        // The file name is the only description we have of a video we cannot
        // see into; it beats "video".
        child: Semantics(
          label: name,
          child: Stack(
            alignment: Alignment.center,
            children: [
              surface,
              if (_loading)
                SizedBox(
                  width: 34,
                  height: 34,
                  child: CircularProgressIndicator(
                      strokeWidth: 2, color: context.z.accent),
                )
              else
                IconButton(
                  iconSize: 44,
                  color: Colors.white,
                  tooltip: playing ? l.chatPauseVideo : l.chatPlayVideo,
                  icon: Icon(playing
                      ? Icons.pause_circle_filled
                      : Icons.play_circle_fill),
                  onPressed: _toggle,
                ),
              if (c != null && c.value.isInitialized)
                Positioned(
                  left: 0,
                  right: 0,
                  bottom: 0,
                  child: VideoProgressIndicator(c,
                      allowScrubbing: true,
                      colors: VideoProgressColors(
                          playedColor: context.z.accent)),
                ),
            ],
          ),
        ),
      ),
    );
  }
}
