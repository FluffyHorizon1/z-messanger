#!/usr/bin/env node
'use strict';
// What one published device list costs on the log's disk — the number
// docs/CAPACITY.md turns into "this many accounts at this republish rate fills
// this disk", and the one that matters because entries NEVER expire (R31): a
// log's disk fills in finite time and stays full, so an operator sizes it from
// this and an alarm on diskFreeBytes (SELF_HOSTING.md).
//
// It publishes to a REAL FileStore in a temp directory at two value sizes and
// reads the entries file's growth, so the fixed per-line overhead (the JSON
// envelope: index, label, versions, two hashes, the account key, the account's
// signature) and the marginal cost per byte of value (base64, ~1.33×) come
// apart. A real sealed list is ~1.1 KB for three devices; the protocol cap is
// 256 KiB and this log accepts up to KT_MAX_VALUE_BYTES (32 KiB).
//
//     node bench/disk.js            # 2000 publishes per point
//     N=5000 node bench/disk.js
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { KtLog, FileStore, privateKeyFromSeed, rawPublicKey, sealValue, makePublish } = require('../lib/log.js');

const N = +(process.env.N || 2000);
const logKey = privateKeyFromSeed(crypto.randomBytes(32));

function account() {
  const key = privateKeyFromSeed(crypto.randomBytes(32));
  return { key, pub: rawPublicKey(key) };
}

// One publish from a fresh account, with a sealed value of `valueBytes`.
function perPublish(valueBytes) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'z-ktdisk-'));
  const file = path.join(dir, 'entries.jsonl');
  const log = new KtLog({ store: new FileStore(file), signingKey: logKey });
  for (let i = 0; i < N; i++) {
    const a = account();
    const plaintext = crypto.randomBytes(valueBytes - 28); // nonce + tag make up the rest
    const value = sealValue(a.pub, plaintext);
    const p = makePublish(a.key, { version: 1, fp: crypto.randomBytes(16), value });
    log.publish({ acct: a.pub, version: p.version, fp: p.fp, value: p.value, sig: p.sig });
  }
  log.close();
  const bytes = fs.statSync(file).size;
  fs.rmSync(dir, { recursive: true, force: true });
  return { valueBytes, bytesPerPublish: bytes / N };
}

function main() {
  console.log(`kt disk: ${N} publishes per point, a real FileStore, one machine\n`);
  const small = perPublish(1100); // a real three-device list, sealed
  const big = perPublish(32768); // KT_MAX_VALUE_BYTES — a hundred devices
  const slope = (big.bytesPerPublish - small.bytesPerPublish) / (big.valueBytes - small.valueBytes);
  const fixed = small.bytesPerPublish - slope * small.valueBytes;
  console.log(`  ${small.valueBytes} B value (a real list): ${small.bytesPerPublish.toFixed(0)} B/publish on disk`);
  console.log(`  ${big.valueBytes} B value (the 32 KiB cap): ${big.bytesPerPublish.toFixed(0)} B/publish on disk`);
  console.log(`  => fixed ${fixed.toFixed(0)} B/publish + ${slope.toFixed(3)} B per value byte (base64 is ~1.33×)`);
  console.log(`\n  entries never expire: a disk holds ${(1e9 / small.bytesPerPublish).toFixed(0)} real-list publishes per GB,`);
  console.log(`  or ${(1e9 / big.bytesPerPublish).toFixed(0)} at the 32 KiB cap.`);
}

if (require.main === module) main();
module.exports = { perPublish };
