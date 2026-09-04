// Integration test for 7.4 voice messages.
//
// A voice note is an ordinary encrypted attachment whose offer carries the
// optional `voice`/`dur` members (PROTOCOL.md §6.2). This drives REAL
// ChatService instances through the REAL Node relay: a direct note and a
// group note, asserting byte-for-byte audio round-trip and that the voice
// metadata (flag + duration) survives the wire, the vault, and a reload.
// The WAV wrapper itself is unit-checked at the bottom — capture streams PCM
// into memory, so plaintext audio never touches disk.
@Tags(['integration'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/models.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/core/voice.dart';
import 'package:z_protocol/z_protocol.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  late Process relay;
  late int port;
  final temps = <Directory>[];
  final services = <ChatService>[];

  setUpAll(() async {
    HttpOverrides.global = null;
    final serverDir =
        '${Directory.current.parent.path}${Platform.pathSeparator}server';
    port = 41000 + DateTime.now().millisecondsSinceEpoch % 20000;
    relay = await Process.start('node', ['server.js'],
        workingDirectory: serverDir,
        environment: {'PORT': '$port', 'LOG_LEVEL': 'silent'});
    for (var i = 0; i < 60; i++) {
      try {
        final res = await (await HttpClient()
                .getUrl(Uri.parse('http://127.0.0.1:$port/health')))
            .close();
        await res.drain<void>();
        if (res.statusCode == 200) return;
      } catch (_) {
        await Future<void>.delayed(const Duration(milliseconds: 100));
      }
    }
    fail('relay did not start');
  });

  tearDownAll(() async {
    for (final s in services) {
      await s.transport.stop();
    }
    relay.kill();
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<ChatService> makeClient(String name) async {
    final dir = await Directory.systemTemp.createTemp('z_$name');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    final identity = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(identity.toJson()));
    final transport =
        Transport(identity: identity, serverUrl: 'ws://127.0.0.1:$port');
    final svc = await ChatService.init(
        vault: vault,
        identity: identity,
        displayName: name,
        transport: transport);
    services.add(svc);
    return svc;
  }

  Future<void> waitUntil(bool Function() cond,
      {Duration timeout = const Duration(seconds: 25)}) async {
    final deadline = DateTime.now().add(timeout);
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met');
      }
      await Future<void>.delayed(const Duration(milliseconds: 30));
    }
  }

  // The "recording": 2.5 s of synthetic 16 kHz mono PCM with a distinctive
  // pattern, wrapped exactly as the record button wraps it.
  Uint8List fakeRecordingPcm() =>
      Uint8List.fromList(List<int>.generate(80000, (i) => (i * 31) % 256));

  ChatMessage? lastVoiceMessage(ChatService svc, String thread) {
    final msgs = svc.messagesByChat[thread] ?? const <ChatMessage>[];
    for (final m in msgs.reversed) {
      if (m.kind == 'file' && m.file != null) return m;
    }
    return null;
  }

  Future<Uint8List?> awaitBytes(ChatService svc, String fid) async {
    final deadline = DateTime.now().add(const Duration(seconds: 25));
    while (DateTime.now().isBefore(deadline)) {
      try {
        return await svc.readAttachment(fid);
      } catch (_) {
        await Future<void>.delayed(const Duration(milliseconds: 50));
      }
    }
    return null;
  }

  test('a voice note round-trips with its flag and duration', () async {
    final alice = await makeClient('alice');
    final bob = await makeClient('bob');
    await waitUntil(
        () => alice.transport.isConnected && bob.transport.isConnected);
    await alice.addContactFromCode(await bob.myContactCode());
    await bob.addContactFromCode(await alice.myContactCode());
    await Future<void>.delayed(const Duration(seconds: 1));

    final pcm = fakeRecordingPcm();
    final wav = wavFromPcm16(pcm);
    final dur = pcm16DurationSec(pcm.length);
    expect(dur, 3); // 2.5 s rounds up

    await alice.sendVoiceNote(bob.myRid, wav, dur, mime: 'audio/wav');

    // Sender's own bubble knows it is a voice note.
    final mine = lastVoiceMessage(alice, bob.myRid)!;
    expect(mine.file!.voice, isTrue);
    expect(mine.file!.durSec, dur);

    // Receiver: offer arrives with the flag, chunks assemble byte-for-byte.
    await waitUntil(() => lastVoiceMessage(bob, alice.myRid) != null);
    final theirs = lastVoiceMessage(bob, alice.myRid)!;
    expect(theirs.file!.voice, isTrue, reason: 'voice flag lost on the wire');
    expect(theirs.file!.durSec, dur);
    expect(theirs.file!.mime, 'audio/wav');
    final got = await awaitBytes(bob, theirs.file!.fid);
    expect(got, isNotNull, reason: 'attachment never assembled');
    expect(got, equals(wav), reason: 'audio bytes corrupted');

    // And the flag survives the vault: reload from disk.
    bob.messagesByChat.remove(alice.myRid);
    final reloaded = await bob.loadMessages(alice.myRid);
    final again = reloaded.lastWhere((m) => m.kind == 'file' && m.file != null);
    expect(again.file!.voice, isTrue, reason: 'voice flag lost in the vault');
    expect(again.file!.durSec, dur);
  }, timeout: const Timeout(Duration(minutes: 2)), retry: 3);

  test('a group voice note reaches every member', () async {
    final ann = await makeClient('ann');
    final ben = await makeClient('ben');
    final cat = await makeClient('cat');
    await waitUntil(() =>
        ann.transport.isConnected &&
        ben.transport.isConnected &&
        cat.transport.isConnected);
    for (final (a, b) in [(ann, ben), (ann, cat), (ben, cat)]) {
      await a.addContactFromCode(await b.myContactCode());
      await b.addContactFromCode(await a.myContactCode());
    }
    await Future<void>.delayed(const Duration(seconds: 1));

    final gid = await ann.createGroup('Voices', [ben.myRid, cat.myRid]);
    await waitUntil(
        () => ben.groups.containsKey(gid) && cat.groups.containsKey(gid));

    final pcm = fakeRecordingPcm();
    final wav = wavFromPcm16(pcm);
    await ann.sendGroupVoiceNote(gid, wav, 3, mime: 'audio/wav');

    for (final member in [ben, cat]) {
      await waitUntil(() => lastVoiceMessage(member, gid) != null);
      final m = lastVoiceMessage(member, gid)!;
      expect(m.file!.voice, isTrue);
      expect(m.file!.durSec, 3);
      final got = await awaitBytes(member, m.file!.fid);
      expect(got, equals(wav));
    }
  }, timeout: const Timeout(Duration(minutes: 2)), retry: 3);

  group('wavFromPcm16 (no relay needed)', () {
    test('produces a canonical 44-byte header over the PCM', () {
      final pcm = Uint8List.fromList(List<int>.filled(32000, 7)); // 1 s
      final wav = wavFromPcm16(pcm);
      expect(wav.length, 44 + pcm.length);
      expect(utf8.decode(wav.sublist(0, 4)), 'RIFF');
      expect(utf8.decode(wav.sublist(8, 12)), 'WAVE');
      final bd = ByteData.sublistView(wav);
      expect(bd.getUint32(4, Endian.little), 36 + pcm.length);
      expect(bd.getUint16(20, Endian.little), 1); // PCM
      expect(bd.getUint16(22, Endian.little), 1); // mono
      expect(bd.getUint32(24, Endian.little), voiceSampleRate);
      expect(bd.getUint32(28, Endian.little), voiceSampleRate * 2);
      expect(bd.getUint32(40, Endian.little), pcm.length);
      expect(wav.sublist(44), pcm);
      expect(pcm16DurationSec(pcm.length), 1);
      expect(pcm16DurationSec(pcm.length + 1), 2); // rounds up
    });
  });
}
