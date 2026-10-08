#!/usr/bin/env node
'use strict';
// What the log — and a mirror of it — holds in memory per entry: the number
// that sizes the instance (docs/CAPACITY.md (b), SELF_HOSTING.md). Disk is
// what entries cost on the way in; memory is what every one of them costs for
// the life of the process, because a replay rebuilds both trees from the
// whole file before the server listens. A log that has outgrown its instance
// does not slow down — it dies during the replay, and again on every restart.
//
// It writes a log file of N correctly signed entries with a real three-device
// list's sealed size (1.1 KB), then replays it in a FRESH child process and
// reports, per entry, what the replay left behind: heap and external memory
// after a forced collection (what `test/log_memory.test.js` measures), and
// the growth of the resident set (what the host's memory limit kills on).
// Then the same for a mirror loading the same history.
//
//     node bench/memory.js              # 22,094 entries: the live log on 2026-10-03
//     N=50000 node bench/memory.js
//
// Until 2026-10-04 an entry cost ~11.6 KB: its five small fields were slices
// of Node's shared 8 KiB buffer pool, and each entry pinned about a slab of
// its own (log.js, `owned`). Run it one at a time on an otherwise idle
// machine: two benches at once measure each other.

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const {
  KtLog,
  FileStore,
  labelFor,
  sealValue,
  makePublish,
  privateKeyFromSeed,
  rawPublicKey,
  entryToJson,
  sthToJson,
} = require('../lib/log.js');
const { sha256 } = require('../lib/merkle.js');

const VALUE_BYTES = 1100;

/** heap + external after two forced collections, and the resident set. */
function snapshot() {
  global.gc();
  global.gc();
  const m = process.memoryUsage();
  return { retained: m.heapUsed + m.external, heap: m.heapUsed, external: m.external, rss: m.rss };
}

function child(kind, target, pubB64) {
  const before = snapshot();
  const t0 = Date.now();
  let n;
  let keep;
  if (kind === 'log') {
    keep = new KtLog({ store: new FileStore(target), signingKey: null });
    n = keep.size;
  } else {
    const { Mirror } = require('../lib/mirror.js');
    keep = new Mirror({ dir: target, logUrl: 'http://127.0.0.1:9', logPub: Buffer.from(pubB64, 'base64') }).load();
    n = keep.entries.length;
  }
  const ms = Date.now() - t0;
  const after = snapshot();
  const per = (k) => Math.round((after[k] - before[k]) / n);
  process.stdout.write(
    JSON.stringify({ n, ms, retained: per('retained'), heap: per('heap'), external: per('external'), rss: per('rss'), rssMiB: +(after.rss / 1048576).toFixed(1) }) + '\n'
  );
  return keep;
}

function measure(kind, target, pubB64) {
  const r = spawnSync(process.execPath, ['--expose-gc', __filename, '--child', kind, target, pubB64 || ''], { encoding: 'utf8', maxBuffer: 1 << 20 });
  if (r.status !== 0) throw new Error(`${kind}: ${r.stderr}`);
  return JSON.parse(r.stdout.trim().split('\n').pop());
}

function main() {
  const N = +(process.env.N || 22094);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'z-ktmem-'));
  try {
    const file = path.join(dir, 'entries.jsonl');
    const logKey = privateKeyFromSeed(crypto.randomBytes(32));
    // Written as the log writes its lines, without a head: the log records
    // one (with its own key) at its first start, and the replay below opens
    // the file read-only, which signs nothing.
    const fd = fs.openSync(file, 'w');
    let lines = [];
    for (let i = 0; i < N; i++) {
      const key = privateKeyFromSeed(crypto.randomBytes(32));
      const pub = rawPublicKey(key);
      const value = sealValue(pub, crypto.randomBytes(VALUE_BYTES - 28));
      const fp = crypto.randomBytes(16);
      const p = makePublish(key, { version: 1, fp, value });
      lines.push(
        JSON.stringify({
          i,
          label: labelFor(pub).toString('base64'),
          v: 1,
          fp: fp.toString('base64'),
          vh: sha256(value).toString('base64'),
          val: value.toString('base64'),
          acct: pub.toString('base64'),
          ts: 1_790_000_000_000 + i,
          sig: p.sig.toString('base64'),
        }) + '\n'
      );
      if (lines.length === 1000 || i === N - 1) {
        fs.writeSync(fd, lines.join(''));
        lines = [];
      }
    }
    fs.closeSync(fd);

    // The mirror's directory for the same history: its lines are the served
    // form, and its head is one the log signed.
    const mdir = path.join(dir, 'mirror');
    fs.mkdirSync(mdir);
    const log = new KtLog({ store: new FileStore(file), signingKey: logKey });
    const out = fs.openSync(path.join(mdir, 'entries.jsonl'), 'w');
    for (let i = 0; i < log.size; i += 1000) {
      const page = log.range(i, 1000).entries.map((e) => JSON.stringify(entryToJson(e)) + '\n');
      fs.writeSync(out, page.join(''));
    }
    fs.closeSync(out);
    const sth = log.sth();
    fs.writeFileSync(path.join(mdir, 'sth.json'), JSON.stringify({ sth: sthToJson(sth), verifiedAt: sth.ts, size: sth.size }));
    log.close();

    const kb = (b) => `${(b / 1024).toFixed(2)} KB`;
    console.log(`${N} entries of a ${VALUE_BYTES}-byte sealed list; per entry, after a forced collection:`);
    for (const [name, kind, target] of [['log replay', 'log', file], ['mirror load', 'mirror', mdir]]) {
      const r = measure(kind, target, rawPublicKey(logKey).toString('base64'));
      console.log(
        `  ${name.padEnd(11)} retained ${kb(r.retained)} (heap ${kb(r.heap)}, external ${kb(r.external)}), ` +
          `resident +${kb(r.rss)}; ${r.rssMiB} MiB resident in all; ${(r.ms / 1000).toFixed(1)} s`
      );
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

if (process.argv[2] === '--child') child(process.argv[3], process.argv[4], process.argv[5]);
else main();
