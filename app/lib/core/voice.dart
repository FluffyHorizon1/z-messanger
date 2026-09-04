import 'dart:typed_data';

/// Voice messages (7.4) — capture is streamed as raw PCM into memory and
/// wrapped in a WAV container HERE, so the recording never exists on disk in
/// plaintext (the vault invariant). WAV needs no codec on any platform and
/// costs ~32 KB/s at the 16 kHz mono capture rate — a one-minute note is
/// under 2 MB, well inside the 24 MB attachment cap.

/// Sample rate used for voice-note capture.
const int voiceSampleRate = 16000;

/// Wrap little-endian 16-bit PCM in a canonical 44-byte WAV header.
Uint8List wavFromPcm16(Uint8List pcm,
    {int sampleRate = voiceSampleRate, int channels = 1}) {
  final byteRate = sampleRate * channels * 2;
  final b = BytesBuilder();
  void u32(int v) =>
      b.add([v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff]);
  void u16(int v) => b.add([v & 0xff, (v >> 8) & 0xff]);
  b.add('RIFF'.codeUnits);
  u32(36 + pcm.length);
  b.add('WAVE'.codeUnits);
  b.add('fmt '.codeUnits);
  u32(16); // PCM fmt chunk size
  u16(1); // audio format: linear PCM
  u16(channels);
  u32(sampleRate);
  u32(byteRate);
  u16(channels * 2); // block align
  u16(16); // bits per sample
  b.add('data'.codeUnits);
  u32(pcm.length);
  b.add(pcm);
  return b.toBytes();
}

/// Whole seconds (rounded up, so a sent note never reads 0:00) of a PCM16
/// buffer at [sampleRate].
int pcm16DurationSec(int pcmByteLength,
    {int sampleRate = voiceSampleRate, int channels = 1}) {
  final bytesPerSec = sampleRate * channels * 2;
  return ((pcmByteLength + bytesPerSec - 1) ~/ bytesPerSec);
}
