// The sender chose the filename.
//
// An attachment's `fid` is what PROTOCOL.md §7 calls "an opaque chunk-routing
// id": `b64url(12 random bytes)`, sixteen characters, meaningless. It is also
// what the receiver names the blob's FILE by — `filesDir/$fid.bin` — and it
// arrives in an ordinary inner field that the SENDER filled in.
//
// Nothing checked it. `../..` is a Dart string; so is `/etc/passwd`, and
// `p.join` discards its base entirely when the second part is absolute, so an
// absolute fid was an absolute path. A contact could therefore choose where
// on the device an attachment landed, and a `.bin` file written outside the
// vault directory is one that `Vault.wipe` — "reset identity", the button
// that means everything goes — walks right past.
//
// The bytes are not the attacker's: `writeBlob` seals them under a fresh
// random key, so what lands is ciphertext. What they get is the PLACE, plus
// a delete path (`deleteBlob` zeroes and unlinks) pointed at the same
// arbitrary name. That is a real primitive and a modest one, and it is worth
// being exact about which it is.
//
// The rule was already written down; only the receiver never read it. §7 has
// always said what a file id is.
//
// Criteria, each a test below:
//  1. an offer whose fid is not a file id is refused: no row, no placeholder,
//     and nothing written anywhere outside the vault's files directory;
//  2. a chunk naming one is dropped rather than held — the flood cap is not
//     the only thing standing between a stranger and a filename;
//  3. an archive carrying one restores without it, and restores everything
//     else;
//  4. the vault refuses such an id itself, so a caller that forgets cannot
//     bring it back — and an ordinary attachment still sends, assembles,
//     backs up and restores unchanged;
//  5. and the second door: an offer from a contact's LINKED device takes a
//     different path into the same tables, and that path was not checked
//     when the rule was written.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/archive.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  late Process relay;
  late int port;
  final temps = <Directory>[];
  final live = <ChatService>[];

  setUpAll(() async {
    HttpOverrides.global = null;
    final serverDir =
        '${Directory.current.parent.path}${Platform.pathSeparator}server';
    final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    port = probe.port;
    await probe.close();
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
    for (final s in live) {
      s.dispose();
      await s.transport.stop();
    }
    relay.kill();
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<Directory> tempDir(String name) async {
    final d = await Directory.systemTemp.createTemp('z_fid_$name');
    temps.add(d);
    return d;
  }

  Future<ChatService> start(Directory dir, String name) async {
    final vault = await Vault.open(rootOverride: dir);
    final id = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(id.toJson()));
    final svc = await ChatService.init(
        vault: vault,
        identity: id,
        displayName: name,
        transport: Transport(identity: id, serverUrl: 'ws://127.0.0.1:$port'));
    live.add(svc);
    return svc;
  }

  Future<void> waitUntil(bool Function() cond,
      {Duration timeout = const Duration(seconds: 25), String what = ''}) async {
    final deadline = DateTime.now().add(timeout);
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw StateError('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 30));
    }
  }

  /// The ids §7 forbids and a client used to accept.
  const hostile = <String>[
    '../escaped',
    '/z-absolute-escape',
    'a/b',
    r'..\windows',
    'short',
    'way-too-long-to-be-a-file-id-0000',
    '',
  ];

  /// Every `.bin` file under [dir] that is NOT inside the vault's own
  /// `files/` directory — i.e. every place an attachment should never be.
  List<String> strayBins(Directory dir) => dir
      .listSync(recursive: true)
      .whereType<File>()
      .map((f) => f.path)
      .where((path) => path.endsWith('.bin'))
      .where((path) => !path.contains(
          '${Platform.pathSeparator}files${Platform.pathSeparator}'))
      .toList();

  /// A chunk envelope, as anyone holding a routing id can build one: the wire
  /// shape is public and nothing in it is signed.
  String rawChunkEnvelope(String fid, int idx, Uint8List ct, Uint8List mac) =>
      base64Encode(utf8.encode(jsonEncode({
        'v': 1,
        't': 'f',
        'fid': fid,
        'idx': idx,
        'ct': b64(ct),
        'mac': b64(mac),
      })));

  test('1. a contact cannot choose where an attachment lands', () async {
    final aliceDir = await tempDir('one_a');
    final alice = await start(aliceDir, 'Alice');
    final bob = await start(await tempDir('one_b'), 'Bob');
    await waitUntil(
        () => alice.transport.isConnected && bob.transport.isConnected,
        what: 'connected');
    await alice.addContactFromCode(await bob.myContactCode());
    await bob.addContactFromCode(await alice.myContactCode());
    await Future<void>.delayed(const Duration(milliseconds: 500));

    // A complete, correct attachment in every respect except its id: real
    // key material, a real encrypted chunk, the real SHA-256 of the real
    // bytes. Nothing here is malformed; the id is a path.
    final payload = Uint8List.fromList(List<int>.generate(700, (i) => i % 251));
    final km = FileKeyMaterial(
        fid: '../escaped', fk: randomBytes(32), fn: randomBytes(16));
    final chunkJson = await encryptChunk(km, 0, payload);
    await bob.debugSendRawInner(
        alice.myRid,
        InnerMessage(kind: 'file', mid: newMessageId(), ts: 1, data: {
          'fid': km.fid,
          'name': 'invoice.pdf',
          'size': payload.length,
          'mime': 'application/pdf',
          'sha256': b64(await sha256Bytes(payload)),
          'fk': b64(km.fk),
          'fn': b64(km.fn),
          'chunks': 1,
        }));
    final parsed = tryParseChunk(chunkJson)!;
    final sender = await RelayClient.connect(
        'ws://127.0.0.1:$port', await ZIdentity.generate());
    await sender.send(
        to: alice.myRid,
        id: newMessageId(),
        payload: rawChunkEnvelope(km.fid, 0, parsed.cipherText, parsed.mac));
    await sender.close();
    await Future<void>.delayed(const Duration(seconds: 2));

    expect(strayBins(aliceDir), isEmpty,
        reason: 'nothing was written outside the vault files directory');
    expect(await alice.vault.db.query('files'), isEmpty,
        reason: 'the offer was refused, so there is nothing to assemble');
    expect(await alice.vault.db.query('chunks'), isEmpty,
        reason: 'and the chunk it came with was not held either');
  });

  test('2. a chunk naming a path is not even held, and one that does not is',
      () async {
    final victim = await start(await tempDir('two'), 'Victim');
    await waitUntil(() => victim.transport.isConnected, what: 'connected');
    final sender = await RelayClient.connect(
        'ws://127.0.0.1:$port', await ZIdentity.generate());
    Future<void> post(String fid) => sender.send(
        to: victim.myRid,
        id: newMessageId(),
        payload: rawChunkEnvelope(fid, 0,
            Uint8List.fromList(List.filled(64, 7)),
            Uint8List.fromList(List.filled(32, 9))));

    for (final fid in hostile) {
      if (fid.isEmpty) continue;
      await post(fid);
      await Future<void>.delayed(const Duration(milliseconds: 250));
    }
    await Future<void>.delayed(const Duration(seconds: 1));
    expect(await victim.vault.db.query('chunks'), isEmpty,
        reason: 'a chunk that can belong to no acceptable offer is not stored');

    // The shape check is not the flood cap and must not be mistaken for it:
    // matching the shape costs an attacker nothing, and such a chunk IS held,
    // because it may legitimately precede its offer. What bounds THAT is
    // ChatService.maxHeldChunks (chunk_flood_test.dart).
    await post(b64url(randomBytes(12)));
    await sender.close();
    for (var i = 0; i < 60; i++) {
      if ((await victim.vault.db.query('chunks')).isNotEmpty) break;
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    expect(await victim.vault.db.query('chunks'), hasLength(1),
        reason: 'a well-formed unexplained chunk is still held');
  });

  test('3. an archive carrying one restores without it, and restores the rest',
      () async {
    // Built by hand, because the fixed client will not export one: a hostile
    // exporter is another program, and an archive is a file that arrives from
    // wherever the user got it. Everything here is a correctly sealed frame
    // at the right index under the right key -- the only wrong thing in the
    // file is that one `fid` is a path.
    final code = await RecoveryCode.generate();
    final salt = randomBytes(16);
    final noncePrefix = randomBytes(16);
    final key = await ZArchive.deriveKey(await code.keyMaterial(), salt);
    final header = ZArchive.buildHeader(
        salt: salt,
        noncePrefix: noncePrefix,
        schema: 11,
        createdMs: DateTime.now().millisecondsSinceEpoch);

    final archive = File('${(await tempDir('three_arc')).path}/hostile.zbk');
    final out = archive.openWrite();
    out.add(header);
    out.add(const [0x0a]);
    var index = 0;
    Future<void> frame(int kind, List<int> payload) async {
      final sealed = await ZArchive.sealFrame(
          key: key,
          header: header,
          noncePrefix: noncePrefix,
          index: index++,
          kind: kind,
          payload: payload);
      out.add((ByteData(4)..setUint32(0, sealed.length)).buffer.asUint8List());
      out.add(sealed);
    }

    var records = 0;
    Future<void> record(Map<String, Object?> r) async {
      await frame(ZArchive.kindRecord, utf8.encode(jsonEncode(r)));
      records++;
    }

    final honestFid = b64url(randomBytes(12));
    final honestBytes = Uint8List.fromList(List<int>.filled(512, 4));
    await record({'t': 'meta', 'name': 'Restored', 'schema': 11});
    await record({
      't': 'message',
      'mid': 'm-honest',
      'rid': 'r-1',
      'out': 0,
      'kind': 'text',
      'body': 'the rest of the archive',
      'ts': 1,
      'status': 0,
    });
    for (final f in [
      ('../planted', 'planted.bin'),
      (honestFid, 'real.csv'),
    ]) {
      final bytes = f.$1 == honestFid
          ? honestBytes
          : Uint8List.fromList(List<int>.filled(64, 1));
      await record({
        't': 'file',
        'fid': f.$1,
        'rid': 'r-1',
        'mid': 'm-honest',
        'name': f.$2,
        'size': bytes.length,
        'mime': 'application/octet-stream',
        'sha256': b64(await sha256Bytes(bytes)),
      });
      await frame(ZArchive.kindBlob, ZArchive.blobPayload(f.$1, bytes));
    }
    await frame(ZArchive.kindEnd,
        utf8.encode(jsonEncode({'t': 'end', 'records': records})));
    await out.flush();
    await out.close();

    final freshDir = await tempDir('three_fresh');
    final fresh = await Vault.open(rootOverride: freshDir);
    final summary =
        await BackupArchive.import(vault: fresh, file: archive, code: code);
    expect(summary.messages, 1, reason: 'the honest records came back');
    expect(summary.attachments, 1,
        reason: 'one of the two attachments is not an attachment');
    final fids = [
      for (final r in await fresh.db.query('files')) r['fid'] as String
    ];
    expect(fids, [honestFid],
        reason: 'the planted id did not survive the import: $fids');
    expect(strayBins(freshDir), isEmpty,
        reason: 'and nothing was written where it named');
    expect(File('${fresh.filesDir.path}/$honestFid.bin').existsSync(), isTrue,
        reason: 'while the honest attachment restored normally');
    await fresh.db.close();
  });

  test('4. the vault refuses one itself, and an honest attachment is untouched',
      () async {
    final dir = await tempDir('four_v');
    final vault = await Vault.open(rootOverride: dir);
    for (final fid in hostile) {
      expect(() => vault.blobFile(fid), throwsArgumentError, reason: fid);
      await expectLater(
          vault.writeBlob(fid, Uint8List.fromList([1])), throwsArgumentError,
          reason: fid);
    }
    expect(strayBins(dir), isEmpty,
        reason: 'a caller that forgets the check writes nothing');

    final km = FileKeyMaterial.generate();
    expect(isWellFormedFid(km.fid), isTrue,
        reason: 'what the protocol generates is what the check accepts');
    final keyInfo = await vault.writeBlob(
        km.fid, Uint8List.fromList(List<int>.generate(2048, (i) => i % 251)));
    expect(await vault.readBlob(km.fid, keyInfo), hasLength(2048));
    await vault.deleteBlob(km.fid);
    expect(File('${vault.filesDir.path}/${km.fid}.bin').existsSync(), isFalse);
    await vault.db.close();

    // End to end, through the relay: an ordinary attachment is unaffected.
    final alice = await start(await tempDir('four_a'), 'Alice');
    final bob = await start(await tempDir('four_b'), 'Bob');
    await waitUntil(
        () => alice.transport.isConnected && bob.transport.isConnected,
        what: 'connected');
    await alice.addContactFromCode(await bob.myContactCode());
    await bob.addContactFromCode(await alice.myContactCode());
    await Future<void>.delayed(const Duration(milliseconds: 500));
    await alice.sendFile(bob.myRid, 'still-works.csv',
        Uint8List.fromList(List<int>.filled(3000, 5)), 'text/csv');
    var assembled = false;
    for (var i = 0; i < 250; i++) {
      assembled =
          (await bob.vault.db.query('files', where: 'complete = 1')).isNotEmpty;
      if (assembled) break;
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    expect(assembled, isTrue,
        reason: 'an ordinary attachment still arrives and assembles');
  });

  test('5. an offer from a contact\'s linked device is held to the same rule',
      () async {
    // A contact with two devices. Their laptop's offers arrive through
    // `_dispatchExtraInner`, not through the handler the rule was written in,
    // and the same fid ends up in the same `files` table.
    final victimDir = await tempDir('five_v');
    final victim = await start(victimDir, 'Victim');
    final mallory = await start(await tempDir('five_m'), 'Mallory');
    await waitUntil(
        () => victim.transport.isConnected && mallory.transport.isConnected,
        what: 'connected');
    await victim.addContactFromCode(await mallory.myContactCode());
    await mallory.addContactFromCode(await victim.myContactCode());
    await Future<void>.delayed(const Duration(milliseconds: 500));

    // Mallory enrolls a laptop and tells the victim about it, the ordinary
    // way: a signed device certificate on her own device list.
    final account = await mallory.accountIdentity();
    final laptopId = await ZIdentity.generate();
    final laptopCert = await account.signDeviceCert(
        deviceEdPub: laptopId.edPub,
        deviceXPub: laptopId.xPub,
        deviceId: 'laptop');
    final laptopDir = await tempDir('five_l');
    final laptopVault = await Vault.open(rootOverride: laptopDir);
    await laptopVault.kvPut('identity', jsonEncode(laptopId.toJson()));
    await laptopVault.kvPut(
        'account',
        jsonEncode((await AccountIdentity.fromEnrollment(
          accountEdPub: account.accountEdPub,
          deviceEdSeed: laptopId.edSeed,
          deviceXSeed: laptopId.xSeed,
          deviceId: 'laptop',
          deviceCert: laptopCert,
        ))
            .toJson()));
    await laptopVault.kvPut(
        'my_devices', jsonEncode([account.deviceCert.toJson()]),
        sensitive: false);
    final laptop = await ChatService.init(
        vault: laptopVault,
        identity: laptopId,
        displayName: 'Mallory laptop',
        transport:
            Transport(identity: laptopId, serverUrl: 'ws://127.0.0.1:$port'));
    live.add(laptop);
    await waitUntil(() => laptop.transport.isConnected, what: 'laptop up');
    await mallory.addMyDevice(laptopCert);
    await laptop.addContactFromCode(await victim.myContactCode());
    await Future<void>.delayed(const Duration(seconds: 2));

    final before = (await victim.vault.db.query('files')).length;
    await laptop.debugSendRawInner(
        victim.myRid,
        InnerMessage(kind: 'file', mid: newMessageId(), ts: 1, data: {
          'fid': '../escaped-through-the-laptop',
          'name': 'invoice.pdf',
          'size': 10,
          'mime': 'application/pdf',
          'sha256': '',
          'fk': b64(Uint8List(32)),
          'fn': b64(Uint8List(16)),
          'chunks': 1,
        }));
    await Future<void>.delayed(const Duration(seconds: 2));

    expect((await victim.vault.db.query('files')).length, before,
        reason: 'the second door is the same door');
    expect(strayBins(victimDir), isEmpty);
  });
}
