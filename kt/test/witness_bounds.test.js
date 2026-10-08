'use strict';

// A witness the log can remove without signing anything.
//
// The witness exists to watch the log's operator, and two findings from the
// 2026-09-13 review (#47, #48 — still open in the 2026-10-03 analysis) said
// the operator being watched could remove it without ever forking:
//
// #47. No request had a deadline. A log — or anything in front of it — that
// accepted the connection and never answered held `sync()` for ever, and
// the witness's /health went on saying `ok`, because it said `ok` whenever
// there had been no divergence.
//
// #48. The mirror read whatever came back into memory before looking at it,
// and fetched as many entries as a signed head said there were. The log signs
// any size it likes, so one answer, or one head, chosen by the party being
// watched ran the witness out of memory — and again after every restart.
//
// What is asserted below:
//   1. a log that accepts the connection and never answers fails the sync at
//      the deadline, as an ordinary error — the head is kept, the mirror is
//      not poisoned, and the next sync against an honest log catches up —
//      and a body that starts and then trickles is cut off the same way;
//   2. the witness says when it has stopped keeping up: /health is `stale`
//      and not `ok` once nothing has verified for --stale-after, and `ok`
//      again once a sync verifies;
//   3. a response past the size a mirror will read is abandoned with that
//      much read, whether it says its length or not;
//   4. a head claiming more entries than the mirror will hold is refused
//      before a single page is asked for, and the mirror keeps its head;
//   5. and an entry whose value is past the protocol's cap is refused, not
//      spooled, and does not poison the mirror.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const { KtLog, MemoryStore, sealValue, makePublish, privateKeyFromSeed, rawPublicKey, MAX_VALUE_BYTES } = require('../lib/log.js');
const { sha256 } = require('../lib/merkle.js');
const { createServer } = require('../server.js');
const { Mirror, Divergence, makeFetchJson } = require('../lib/mirror.js');

const logKey = privateKeyFromSeed(crypto.createHash('sha256').update('witness bounds log').digest());
const witnessSeedHex = crypto.createHash('sha256').update('witness bounds witness').digest('hex');

function account(name) {
  const key = privateKeyFromSeed(crypto.createHash('sha256').update(`acct:${name}`).digest());
  return { key, pub: rawPublicKey(key) };
}

function publishFor(acct, v) {
  const value = sealValue(acct.pub, Buffer.from(`list ${v}`, 'utf8'));
  return makePublish(acct.key, { version: v, fp: crypto.randomBytes(16), value });
}

function tmpdir(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kt-wbound-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/** Listen on a free port; when the test ends, drop every socket it accepted, then close. */
function listen(t, server) {
  const sockets = new Set();
  server.on('connection', (s) => {
    sockets.add(s);
    s.on('close', () => sockets.delete(s));
  });
  t.after(async () => {
    for (const s of sockets) s.destroy();
    await new Promise((r) => server.close(r));
  });
  return new Promise((r) => server.listen(0, '127.0.0.1', () => r(`http://127.0.0.1:${server.address().port}`)));
}

async function honestLog(t, n) {
  const log = new KtLog({ store: new MemoryStore(), signingKey: logKey });
  const a = account('a');
  for (let v = 1; v <= n; v++) log.publish(publishFor(a, v));
  const { httpServer } = createServer({ log });
  return { log, url: await listen(t, httpServer), a };
}

/** [p], or a rejection saying [what] after [ms]: so a test of a wait that never ends fails instead of hanging. */
function within(p, ms, what) {
  let timer;
  return Promise.race([
    p.finally(() => clearTimeout(timer)),
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(`still waiting after ${ms} ms: ${what}`)), ms);
    }),
  ]);
}

/** An awaited poll: [pred] until it holds, or fail saying [what]. */
async function until(pred, what, tries = 300, everyMs = 50) {
  for (let i = 0; i < tries; i++) {
    try {
      if (await pred()) return;
    } catch {
      // not answering yet
    }
    await new Promise((r) => setTimeout(r, everyMs));
  }
  throw new Error(`timed out waiting for: ${what}`);
}

test('1. a log that never answers fails the sync at the deadline, and nothing is lost', { timeout: 60_000 }, async (t) => {
  const h = await honestLog(t, 3);
  const dir = tmpdir(t);
  const fetchJson = makeFetchJson({ timeoutMs: 300 });
  const m = new Mirror({ dir, logUrl: h.url, logPub: h.log.publicKey, fetchJson }).load();
  await m.sync();
  assert.equal(m.head.size, 3);

  // A "log" that accepts the connection and never says a word.
  const silentUrl = await listen(t, net.createServer(() => {}));
  const quiet = new Mirror({ dir, logUrl: silentUrl, logPub: h.log.publicKey, fetchJson }).load();
  await assert.rejects(
    within(quiet.sync(), 10_000, 'a sync against a log that never answers'),
    (e) => !(e instanceof Divergence) && /no complete answer within 300 ms/.test(e.message)
  );
  assert.ok(!quiet.poisoned, 'silence is not evidence of a fork');
  assert.equal(quiet.head.size, 3, 'and the head it had is the head it has');

  // Headers at once, then a byte a while: a body that never ends is the same.
  const trickle = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.write('{"size":');
    const timer = setInterval(() => res.write(' '), 50);
    res.on('close', () => clearInterval(timer));
  });
  const trickleUrl = await listen(t, trickle);
  const slow = new Mirror({ dir, logUrl: trickleUrl, logPub: h.log.publicKey, fetchJson }).load();
  await assert.rejects(
    within(slow.sync(), 10_000, 'a sync against a log that trickles'),
    (e) => !(e instanceof Divergence) && /no complete answer within 300 ms/.test(e.message)
  );
  assert.ok(!slow.poisoned);

  // And the honest log is followed again from the same directory.
  h.log.publish(publishFor(h.a, 4));
  const back = new Mirror({ dir, logUrl: h.url, logPub: h.log.publicKey, fetchJson }).load();
  assert.deepEqual(await back.sync().then((r) => [r.from, r.to]), [3, 4]);
});

test('2. the witness says when it has stopped keeping up', { timeout: 120_000 }, async (t) => {
  const h = await honestLog(t, 3);
  // What the witness is pointed at: the honest log, or — at the flip of a
  // switch — a front that accepts every request and answers none.
  let silent = false;
  const waiting = new Set();
  const front = http.createServer(async (req, res) => {
    if (silent) {
      waiting.add(res);
      res.on('close', () => waiting.delete(res));
      return;
    }
    try {
      const r = await fetch(h.url + req.url);
      res.writeHead(r.status, { 'content-type': 'application/json' });
      res.end(await r.text());
    } catch {
      res.writeHead(502).end();
    }
  });
  const frontUrl = await listen(t, front);
  const dir = tmpdir(t);
  const tool = path.join(__dirname, '..', 'tools', 'mirror.js');
  const child = spawn(
    process.execPath,
    [tool, '--log', frontUrl, '--pub', h.log.publicKey.toString('base64'), '--dir', dir, '--serve', '0', '--every', '1', '--stale-after', '2', '--fetch-timeout', '0.5'],
    { env: { PATH: process.env.PATH, KT_WITNESS_SEED: witnessSeedHex } }
  );
  let out = '';
  let err = '';
  child.stdout.on('data', (d) => (out += d));
  child.stderr.on('data', (d) => (err += d));
  const closed = new Promise((r) => child.on('close', r));
  t.after(async () => {
    child.kill('SIGTERM');
    await closed;
  });
  await until(() => /serving on http:\/\/0\.0\.0\.0:\d+/.test(out), `the witness serving (stderr: ${err})`);
  const port = +out.match(/serving on http:\/\/0\.0\.0\.0:(\d+)/)[1];
  const health = async () => (await fetch(`http://127.0.0.1:${port}/health`)).json();

  await until(async () => (await health()).size === 3, 'the first head verified');
  const ok = await health();
  assert.equal(ok.ok, true);
  assert.equal(ok.stale, false);

  // The front goes quiet. Every sync now fails at its deadline instead of
  // waiting for ever, and within --stale-after the witness says so.
  silent = true;
  await until(async () => (await health()).stale === true, 'the witness reporting that it has stopped keeping up');
  const stale = await health();
  assert.equal(stale.ok, false, 'not ok: nothing verified for longer than it should have been');
  assert.equal(stale.diverged, false, 'and not a divergence: silence is not a fork');
  assert.match(stale.lastError || '', /no complete answer within 500 ms/);
  assert.equal(stale.size, 3, 'it still holds the head it verified');

  // The front comes back; the next sync verifies, and the witness is ok.
  silent = false;
  for (const r of waiting) r.destroy();
  await until(async () => (await health()).ok === true, 'the witness ok again once a sync verifies');
  assert.equal((await health()).stale, false);
});

test('3. a response past what a mirror reads is abandoned with that much read', { timeout: 60_000 }, async (t) => {
  // Sixty-four mebibytes of an answer, pumped as fast as the client takes
  // it; what was taken is counted.
  const JUNK = 64 * 1024 * 1024;
  let sent = 0;
  const big = http.createServer((req, res) => {
    const declare = req.url.includes('declared');
    res.writeHead(200, { 'content-type': 'application/json', ...(declare ? { 'content-length': String(JUNK) } : {}) });
    const chunk = Buffer.alloc(64 * 1024, 0x20);
    let gone = false;
    res.on('close', () => (gone = true));
    const pump = () => {
      while (!gone && sent < JUNK) {
        sent += chunk.length;
        if (!res.write(chunk)) return void res.once('drain', pump);
      }
      if (!gone) res.end();
    };
    pump();
  });
  const url = await listen(t, big);
  const fetchJson = makeFetchJson({ maxBytes: 1024 * 1024 });

  await assert.rejects(within(fetchJson(`${url}/kt/v1/sth`), 20_000, 'a 64 MiB answer'), /passed 1048576 bytes/);
  assert.ok(sent < 16 * 1024 * 1024, `the mirror let ${(sent / 1048576).toFixed(1)} MiB arrive of an answer it reads 1 MiB of`);

  // An answer that says how large it is gets no further than saying so.
  sent = 0;
  await assert.rejects(within(fetchJson(`${url}/kt/v1/sth?declared`), 20_000, 'a declared 64 MiB answer'), /a response of 67108864 bytes/);
  assert.ok(sent < 16 * 1024 * 1024, `${(sent / 1048576).toFixed(1)} MiB arrived`);
});

test('4. a head claiming more than the mirror holds is refused before a page is asked for', { timeout: 60_000 }, async (t) => {
  const h = await honestLog(t, 3);
  const dir = tmpdir(t);
  const asked = [];
  const real = makeFetchJson();
  const spy = async (u) => {
    asked.push(new URL(u).pathname);
    return real(u);
  };
  const m = new Mirror({ dir, logUrl: h.url, logPub: h.log.publicKey, fetchJson: spy, maxEntries: 4 }).load();
  await m.sync();
  assert.equal(m.head.size, 3);

  // The log grows past what this mirror was sized for. A log can sign any
  // size it likes; this one is honest, and the mirror cannot tell which.
  h.log.publish(publishFor(h.a, 4));
  h.log.publish(publishFor(h.a, 5));
  asked.length = 0;
  await assert.rejects(m.sync(), (e) => !(e instanceof Divergence) && /holds at most 4 \(KT_MIRROR_MAX_ENTRIES\)/.test(e.message));
  assert.deepEqual(asked, ['/kt/v1/sth'], 'the head, and nothing it would have had to hold');
  assert.ok(!m.poisoned);
  assert.equal(m.head.size, 3);

  // Sized for it, the same directory catches up.
  const bigger = new Mirror({ dir, logUrl: h.url, logPub: h.log.publicKey, maxEntries: 10 }).load();
  assert.deepEqual(await bigger.sync().then((r) => [r.from, r.to]), [3, 5]);
});

test('5. an entry whose value is past the protocol cap is refused, not spooled', { timeout: 60_000 }, async (t) => {
  const h = await honestLog(t, 3);
  const dir = tmpdir(t);
  // A page whose second entry carries a value past 256 KiB, hashing to its
  // own (new) commitment, so nothing about its shape is wrong.
  const oversize = crypto.randomBytes(MAX_VALUE_BYTES + 4096);
  const fetchJson = async (u) => {
    const j = await (await fetch(u)).json();
    if (new URL(u).pathname === '/kt/v1/entries') {
      j.entries[1].value = oversize.toString('base64');
      j.entries[1].valueHash = sha256(oversize).toString('base64');
    }
    return j;
  };
  const m = new Mirror({ dir, logUrl: h.url, logPub: h.log.publicKey, fetchJson }).load();
  await assert.rejects(m.sync(), (e) => !(e instanceof Divergence) && /past the protocol's 262144/.test(e.message));
  assert.ok(!m.poisoned, 'refused as an answer this mirror will not hold, not as a fork');
  assert.equal(m.head, null);
  assert.ok(!fs.existsSync(path.join(dir, 'entries.jsonl.incoming')), 'the spool is gone');
  assert.ok(!fs.existsSync(path.join(dir, 'entries.jsonl')) || fs.statSync(path.join(dir, 'entries.jsonl')).size === 0, 'and nothing was written');
  // The honest log, unaltered, is followed from the same directory.
  const back = new Mirror({ dir, logUrl: h.url, logPub: h.log.publicKey }).load();
  assert.deepEqual(await back.sync().then((r) => [r.from, r.to]), [0, 3]);
});
