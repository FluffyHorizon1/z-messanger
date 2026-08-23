@Tags(['integration'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

/// Full-stack integration: two REAL protocol clients talking through the
/// REAL Node.js relay, exactly as the shipping apps do.
void main() {
  late Process relay;
  late int port;

  setUpAll(() async {
    final serverDir =
        '${Directory.current.parent.path}${Platform.pathSeparator}server';
    port = 40000 + DateTime.now().millisecondsSinceEpoch % 20000;
    relay = await Process.start(
      'node',
      ['server.js'],
      workingDirectory: serverDir,
      environment: {'PORT': '$port', 'LOG_LEVEL': 'info'},
    );
    relay.stdout
        .transform(utf8.decoder)
        .listen((s) => print('[relay] ${s.trimRight()}'));
    relay.stderr
        .transform(utf8.decoder)
        .listen((s) => print('[relay-err] ${s.trimRight()}'));
    unawaited(
        relay.exitCode.then((c) => print('[relay] exited with code $c')));
    // Wait for the health endpoint.
    for (var i = 0; i < 50; i++) {
      try {
        final req = await HttpClient()
            .getUrl(Uri.parse('http://127.0.0.1:$port/health'));
        final res = await req.close();
        await res.drain<void>();
        if (res.statusCode == 200) return;
      } catch (_) {
        await Future<void>.delayed(const Duration(milliseconds: 100));
      }
    }
    fail('relay did not start');
  });

  tearDownAll(() {
    relay.kill();
  });

  test('complete conversation over the real relay', () async {
    final alice = await ZIdentity.generate();
    final bob = await ZIdentity.generate();
    final aliceConv =
        await Conversation.create(alice, await bob.bundle(displayName: 'Bob'));
    final bobConv = await Conversation.create(
        bob, await alice.bundle(displayName: 'Alice'));

    final aliceNet =
        await RelayClient.connect('ws://127.0.0.1:$port', alice);
    final bobNet = await RelayClient.connect('ws://127.0.0.1:$port', bob);
    final bobRid = await bob.routingId();
    final aliceRid = await alice.routingId();
    expect(bobNet.routingId, bobRid);

    // ---- Alice -> Bob (live) --------------------------------------------
    final inbox = <RelayInbound>[];
    final sub = bobNet.messages.listen(inbox.add);

    final m1 = InnerMessage.text(newMessageId(), 1, 'hello over the wire');
    final live = await aliceNet.send(
      to: bobRid,
      id: m1.mid,
      payload: await aliceConv.encrypt(m1.toBytes()),
    );
    expect(live, isTrue); // bob online -> not queued

    await _until(() => inbox.length == 1);
    final got = inbox.removeAt(0);
    expect(got.from, aliceRid);
    final dec = await bobConv.decrypt(got.payload);
    final inner = InnerMessage.fromBytes(dec.plaintext);
    expect(inner.data['body'], 'hello over the wire');

    // Bob acks -> Alice sees a delivered receipt.
    final deliveredFuture = aliceNet.delivered.first;
    bobNet.ackReceived(id: got.id, from: got.from);
    final receipt = await deliveredFuture
        .timeout(const Duration(seconds: 5));
    expect(receipt.id, m1.mid);

    // ---- Bob -> Alice reply (turns the DH ratchet) -----------------------
    final aliceInbox = <RelayInbound>[];
    final aliceSub = aliceNet.messages.listen(aliceInbox.add);
    final m2 = InnerMessage.text(newMessageId(), 2, 'reply');
    await bobNet.send(
        to: aliceRid, id: m2.mid, payload: await bobConv.encrypt(m2.toBytes()));
    await _until(() => aliceInbox.length == 1);
    final r2 = await aliceConv.decrypt(aliceInbox.removeAt(0).payload);
    expect(InnerMessage.fromBytes(r2.plaintext).data['body'], 'reply');

    // ---- Offline queueing: Bob disconnects, Alice keeps sending ----------
    await sub.cancel();
    await bobNet.close();
    await Future<void>.delayed(const Duration(milliseconds: 200));

    final queuedIds = <String>[];
    for (var i = 0; i < 3; i++) {
      final m = InnerMessage.text(newMessageId(), 10 + i, 'offline $i');
      queuedIds.add(m.mid);
      final wasLive = await aliceNet.send(
          to: bobRid, id: m.mid, payload: await aliceConv.encrypt(m.toBytes()));
      expect(wasLive, isFalse); // relay reports RAM-queued
    }

    // Bob reconnects and receives all three, in order.
    final bobNet2 = await RelayClient.connect('ws://127.0.0.1:$port', bob);
    final flushed = <RelayInbound>[];
    final sub2 = bobNet2.messages.listen(flushed.add);
    await _until(() => flushed.length == 3);
    for (var i = 0; i < 3; i++) {
      expect(flushed[i].id, queuedIds[i]);
      final d = await bobConv.decrypt(flushed[i].payload);
      expect(InnerMessage.fromBytes(d.plaintext).data['body'], 'offline $i');
      bobNet2.ackReceived(id: flushed[i].id, from: flushed[i].from);
    }

    // ---- Attachment: offer through the ratchet, chunks under the file key
    final fileBytes = randomBytes(900 * 1000); // spans 2 chunks
    final km = FileKeyMaterial.generate();
    final chunks = splitChunks(fileBytes);
    final offer = InnerMessage(
      kind: 'file',
      mid: newMessageId(),
      ts: 100,
      data: {
        'fid': km.fid,
        'name': 'photo.jpg',
        'size': fileBytes.length,
        'mime': 'image/jpeg',
        'sha256': b64(await sha256Bytes(fileBytes)),
        'fk': b64(km.fk),
        'fn': b64(km.fn),
        'chunks': chunks.length,
      },
    );
    await aliceNet.send(
        to: bobRid,
        id: offer.mid,
        payload: await aliceConv.encrypt(offer.toBytes()));
    for (var i = 0; i < chunks.length; i++) {
      await aliceNet.send(
          to: bobRid,
          id: newMessageId(),
          payload: await encryptChunk(km, i, chunks[i]));
    }

    await _until(() => flushed.length == 3 + 1 + chunks.length);
    final offerDec = await bobConv.decrypt(flushed[3].payload);
    final offerInner = InnerMessage.fromBytes(offerDec.plaintext);
    expect(offerInner.kind, 'file');
    expect(offerInner.data['name'], 'photo.jpg');

    final gotChunks = List<Uint8List?>.filled(chunks.length, null);
    for (var i = 0; i < chunks.length; i++) {
      final fc = tryParseChunk(flushed[4 + i].payload)!;
      gotChunks[fc.index] = await decryptChunk(
        fk: unb64(offerInner.data['fk'] as String),
        fn: unb64(offerInner.data['fn'] as String),
        fid: offerInner.data['fid'] as String,
        chunk: fc,
      );
    }
    final reassembled =
        Uint8List.fromList(gotChunks.expand((c) => c!).toList());
    expect(b64(await sha256Bytes(reassembled)), offerInner.data['sha256']);

    // ---- The relay never learned anything usable -------------------------
    // Every payload that crossed the wire must be non-JSON noise to the
    // relay: verify none of the transported payloads contain plaintext.
    for (final p in [...flushed.map((f) => f.payload)]) {
      final raw = utf8.decode(base64Decode(p));
      expect(raw.contains('hello over the wire'), isFalse);
      expect(raw.contains('offline'), isFalse);
      expect(raw.contains('photo.jpg'), isFalse);
    }

    await aliceSub.cancel();
    await sub2.cancel();
    await aliceNet.close();
    await bobNet2.close();
  }, timeout: const Timeout(Duration(minutes: 2)));
}

Future<void> _until(bool Function() cond,
    {Duration timeout = const Duration(seconds: 10)}) async {
  final deadline = DateTime.now().add(timeout);
  while (!cond()) {
    if (DateTime.now().isAfter(deadline)) {
      throw TimeoutException('condition not met', timeout);
    }
    await Future<void>.delayed(const Duration(milliseconds: 25));
  }
}
