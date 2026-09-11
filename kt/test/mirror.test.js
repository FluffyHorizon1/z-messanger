'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');

const {
  KtLog,
  MemoryStore,
  sealValue,
  makePublish,
  privateKeyFromSeed,
  rawPublicKey,
  verifySth,
  sthFromJson,
  witnessInput,
  verify,
} = require('../lib/log.js');
const { createServer } = require('../server.js');
const { Mirror, Divergence } = require('../lib/mirror.js');

const logKey = privateKeyFromSeed(crypto.createHash('sha256').update('mirror log seed').digest());
const witnessKey = privateKeyFromSeed(crypto.createHash('sha256').update('witness seed').digest());

function account(name) {
  const key = privateKeyFromSeed(crypto.createHash('sha256').update(`acct:${name}`).digest());
  return { key, pub: rawPublicKey(key) };
}

let t = 1_700_000_000_000;
const now = () => t;

function publishFor(acct, v) {
  const value = sealValue(acct.pub, Buffer.from(`list ${v}`, 'utf8'));
  const fp = crypto.createHash('sha256').update(`fp:${v}`).digest().subarray(0, 16);
  return makePublish(acct.key, { version: v, fp, value });
}

async function serve(log) {
  const { httpServer } = createServer({ log });
  await new Promise((res) => httpServer.listen(0, '127.0.0.1', res));
  return {
    url: `http://127.0.0.1:${httpServer.address().port}`,
    stop: async () => {
      httpServer.closeAllConnections();
      await new Promise((res) => httpServer.close(res));
    },
  };
}

function tmpdir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'z-kt-mirror-'));
}

test('a mirror follows the log: first sync, incremental sync, no-op sync, reload from disk, witness signature', async () => {
  const log = new KtLog({ store: new MemoryStore(), signingKey: logKey, now });
  const accts = [account('a'), account('b'), account('c')];
  const publishes = [];
  for (let i = 0; i < 7; i++) publishes.push(publishFor(accts[i % 3], Math.floor(i / 3) + 1));
  for (let i = 0; i < 5; i++) log.publish(publishes[i]);
  const server = await serve(log);
  const dir = tmpdir();
  try {
    const m = new Mirror({ dir, logUrl: server.url + '/', logPub: log.publicKey, witnessKey, pageSize: 2, now }).load();
    assert.equal(m.head, null);
    const r1 = await m.sync();
    assert.deepEqual([r1.from, r1.to], [0, 5]);
    assert.ok(m.tree.root.equals(log.tree.root));
    assert.ok(m.map.root.equals(log.map.root));
    const rec = m.record();
    assert.equal(rec.size, 5);
    const sth = sthFromJson(rec.sth);
    assert.ok(verifySth(sth, log.publicKey));
    assert.ok(Buffer.from(rec.witness.pub, 'base64').equals(rawPublicKey(witnessKey)));
    assert.ok(verify(rawPublicKey(witnessKey), witnessInput(sth), Buffer.from(rec.witness.sig, 'base64')));
    assert.ok(!verify(rawPublicKey(witnessKey), witnessInput({ ...sth, size: 4 }), Buffer.from(rec.witness.sig, 'base64')));
    // Entries on disk: five lines, none with acct.
    const lines = fs.readFileSync(path.join(dir, 'entries.jsonl'), 'utf8').split('\n').filter(Boolean);
    assert.equal(lines.length, 5);
    assert.equal(JSON.parse(lines[0]).acct, undefined);

    // Nothing new: same size, same roots.
    const r2 = await m.sync();
    assert.deepEqual([r2.from, r2.to], [5, 5]);

    // The log grows; the mirror extends.
    log.publish(publishes[5]);
    log.publish(publishes[6]);
    const r3 = await m.sync();
    assert.deepEqual([r3.from, r3.to], [5, 7]);
    assert.ok(m.tree.root.equals(log.tree.root));
    assert.equal(m.record().size, 7);

    // A fresh Mirror over the same directory rebuilds and agrees.
    const again = new Mirror({ dir, logUrl: server.url, logPub: log.publicKey, now }).load();
    assert.equal(again.entries.length, 7);
    assert.ok(again.head.logRoot.equals(log.sth().logRoot));
    assert.deepEqual(await again.sync().then((r) => [r.from, r.to]), [7, 7]);

    // A corrupted directory refuses to load rather than mirror from a wrong base.
    const entriesFile = path.join(dir, 'entries.jsonl');
    const good = fs.readFileSync(entriesFile, 'utf8');
    fs.writeFileSync(entriesFile, good.split('\n').slice(0, 6).join('\n') + '\n');
    assert.throws(() => new Mirror({ dir, logUrl: server.url, logPub: log.publicKey, now }).load(), /head size 7, 6 entries/);
    fs.writeFileSync(entriesFile, good);
    const j = JSON.parse(fs.readFileSync(path.join(dir, 'sth.json'), 'utf8'));
    j.sth.size = 6;
    fs.writeFileSync(path.join(dir, 'sth.json'), JSON.stringify(j));
    assert.throws(() => new Mirror({ dir, logUrl: server.url, logPub: log.publicKey, now }).load(), /not signed by the pinned log key/);
    // The wrong pin.
    fs.writeFileSync(path.join(dir, 'sth.json'), JSON.stringify(m.record()));
    assert.throws(() => new Mirror({ dir, logUrl: server.url, logPub: rawPublicKey(witnessKey), now }).load(), /not signed/);
  } finally {
    await server.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a mirror refuses a fork: same key, different history, and keeps the head it verified', async () => {
  const a = account('a');
  const publishes = [];
  for (let v = 1; v <= 6; v++) publishes.push(publishFor(a, v));
  const honest = new KtLog({ store: new MemoryStore(), signingKey: logKey, now });
  const fork = new KtLog({ store: new MemoryStore(), signingKey: logKey, now });
  for (let i = 0; i < 4; i++) {
    honest.publish(publishes[i]);
    fork.publish(publishes[i]);
  }
  const h = await serve(honest);
  const f = await serve(fork);
  const dir = tmpdir();
  try {
    const m = new Mirror({ dir, logUrl: h.url, logPub: honest.publicKey, now }).load();
    await m.sync();
    // The fork diverges at index 4 and grows past the honest log.
    fork.publish(publishFor(a, 40));
    fork.publish(publishFor(a, 41));
    honest.publish(publishes[4]);
    // A mirror that has only seen the shared prefix (size 4) cannot tell the
    // two apart: both are honest extensions of what it holds. That is not a
    // weakness of the check but what "consistent" means — the fork is caught
    // by whoever saw index 4 before it was rewritten.
    const copy = tmpdir();
    fs.copyFileSync(path.join(dir, 'entries.jsonl'), path.join(copy, 'entries.jsonl'));
    fs.copyFileSync(path.join(dir, 'sth.json'), path.join(copy, 'sth.json'));
    const prefixOnly = new Mirror({ dir: copy, logUrl: f.url, logPub: honest.publicKey, now }).load();
    assert.deepEqual(await prefixOnly.sync().then((r) => [r.from, r.to]), [4, 6]);
    fs.rmSync(copy, { recursive: true, force: true });
    // This mirror saw the honest index 4. Now the fork's size-6 head claims another index 4.
    assert.deepEqual(await m.sync().then((r) => [r.from, r.to]), [4, 5]);
    const before = fs.readFileSync(path.join(dir, 'sth.json'), 'utf8');
    const onFork = new Mirror({ dir, logUrl: f.url, logPub: honest.publicKey, now }).load();
    await assert.rejects(onFork.sync(), (e) => e instanceof Divergence && /does not extend the head of size 5/.test(e.message));
    assert.ok(onFork.poisoned);
    await assert.rejects(onFork.sync(), /diverged; load a fresh one/);
    assert.equal(fs.readFileSync(path.join(dir, 'sth.json'), 'utf8'), before, 'sth.json untouched');
    assert.equal(fs.readFileSync(path.join(dir, 'entries.jsonl'), 'utf8').split('\n').filter(Boolean).length, 5, 'no forked entries written');

    // The honest log is still followed from the same directory.
    honest.publish(publishes[5]);
    const back = new Mirror({ dir, logUrl: h.url, logPub: honest.publicKey, now }).load();
    assert.deepEqual(await back.sync().then((r) => [r.from, r.to]), [5, 6]);

    // Same size, different roots: a fork that stayed the same length.
    const twin = new KtLog({ store: new MemoryStore(), signingKey: logKey, now });
    for (let i = 0; i < 4; i++) twin.publish(publishes[i]);
    twin.publish(publishFor(a, 50));
    twin.publish(publishFor(a, 51));
    const tw = await serve(twin);
    try {
      const onTwin = new Mirror({ dir, logUrl: tw.url, logPub: honest.publicKey, now }).load();
      await assert.rejects(onTwin.sync(), (e) => e instanceof Divergence && /same size 6, different roots/.test(e.message));
    } finally {
      await tw.stop();
    }

    // A log that shrank.
    const shorter = new KtLog({ store: new MemoryStore(), signingKey: logKey, now });
    for (let i = 0; i < 3; i++) shorter.publish(publishes[i]);
    const sh = await serve(shorter);
    try {
      const onShort = new Mirror({ dir, logUrl: sh.url, logPub: honest.publicKey, now }).load();
      await assert.rejects(onShort.sync(), (e) => e instanceof Divergence && /shrank/.test(e.message));
    } finally {
      await sh.stop();
    }

    // A head signed by some other key.
    const impostor = new KtLog({ store: new MemoryStore(), signingKey: witnessKey, now });
    for (let i = 0; i < 5; i++) impostor.publish(publishes[i]);
    const im = await serve(impostor);
    try {
      const onImpostor = new Mirror({ dir, logUrl: im.url, logPub: honest.publicKey, now }).load();
      await assert.rejects(onImpostor.sync(), /not signed by the pinned log key/);
    } finally {
      await im.stop();
    }
  } finally {
    await h.stop();
    await f.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a log that serves a consistent head but entries that do not hash to it is caught by the roots', async () => {
  const a = account('a');
  const honest = new KtLog({ store: new MemoryStore(), signingKey: logKey, now });
  const other = new KtLog({ store: new MemoryStore(), signingKey: logKey, now });
  for (let v = 1; v <= 5; v++) {
    honest.publish(publishFor(a, v));
    other.publish(publishFor(a, v)); // different nonces: different values, different leaves
  }
  const h = await serve(honest);
  const o = await serve(other);
  const dir = tmpdir();
  try {
    // A fetcher that takes heads from the honest log and entries from the other one.
    const split = async (url) => {
      const u = new URL(url);
      const target = u.pathname === '/kt/v1/entries' ? o.url : h.url;
      const res = await fetch(target + u.pathname + u.search);
      return res.json();
    };
    const m = new Mirror({ dir, logUrl: h.url, logPub: honest.publicKey, fetchJson: split, now }).load();
    await assert.rejects(m.sync(), (e) => e instanceof Divergence && /do not hash to the signed log root/.test(e.message));
    assert.ok(!fs.existsSync(path.join(dir, 'sth.json')), 'nothing written');
    assert.ok(!fs.existsSync(path.join(dir, 'entries.jsonl')));
    // A fetcher that serves one entry with a version going backwards.
    const backwards = async (url) => {
      const u = new URL(url);
      const j = await (await fetch(h.url + u.pathname + u.search)).json();
      if (u.pathname === '/kt/v1/entries') j.entries[2].v = 1;
      return j;
    };
    const m2 = new Mirror({ dir, logUrl: h.url, logPub: honest.publicKey, fetchJson: backwards, now }).load();
    await assert.rejects(m2.sync(), (e) => e instanceof Divergence && /does not exceed/.test(e.message));
    // A fetcher that serves an entry whose value does not match its hash.
    const swapped = async (url) => {
      const u = new URL(url);
      const j = await (await fetch(h.url + u.pathname + u.search)).json();
      if (u.pathname === '/kt/v1/entries') j.entries[0].value = Buffer.alloc(40).toString('base64');
      return j;
    };
    const m3 = new Mirror({ dir, logUrl: h.url, logPub: honest.publicKey, fetchJson: swapped, now }).load();
    await assert.rejects(m3.sync(), (e) => e instanceof Divergence && /value hash does not match/.test(e.message));
  } finally {
    await h.stop();
    await o.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('the command-line tool: exit 0 when the head verifies, 2 on divergence, 1 when unreachable', async () => {
  const a = account('a');
  const publishes = [];
  for (let v = 1; v <= 3; v++) publishes.push(publishFor(a, v));
  const honest = new KtLog({ store: new MemoryStore(), signingKey: logKey, now });
  const fork = new KtLog({ store: new MemoryStore(), signingKey: logKey, now });
  for (const p of publishes) {
    honest.publish(p);
    fork.publish(p);
  }
  fork.publish(publishFor(a, 9));
  fork.publish(publishFor(a, 10));
  const h = await serve(honest);
  const f = await serve(fork);
  const dir = tmpdir();
  const tool = path.join(__dirname, '..', 'tools', 'mirror.js');
  const pub = honest.publicKey.toString('base64');
  // The servers live in this process, so the tool must run without blocking
  // the event loop: spawn, not spawnSync.
  const run = (url, extra = [], env = {}) =>
    new Promise((resolve) => {
      const child = spawn(process.execPath, [tool, '--log', url, '--pub', pub, '--dir', dir, ...extra], { env: { ...process.env, ...env } });
      let stdout = '';
      let stderr = '';
      child.stdout.on('data', (d) => (stdout += d));
      child.stderr.on('data', (d) => (stderr += d));
      child.on('close', (status) => resolve({ status, stdout, stderr }));
    });
  try {
    const first = await run(h.url, ['--witness-seed-env', 'W'], { W: crypto.createHash('sha256').update('witness seed').digest('hex') });
    assert.equal(first.status, 0, first.stderr);
    assert.match(first.stdout, /verified head of size 3 \(was 0\)/);
    const rec = JSON.parse(fs.readFileSync(path.join(dir, 'sth.json'), 'utf8'));
    assert.ok(rec.witness.sig);
    honest.publish(publishFor(a, 4));
    const second = await run(h.url);
    assert.equal(second.status, 0, second.stderr);
    assert.match(second.stdout, /size 4 \(was 3\)/);
    const forked = await run(f.url);
    assert.equal(forked.status, 2);
    assert.match(forked.stderr, /DIVERGENCE/);
    assert.equal(JSON.parse(fs.readFileSync(path.join(dir, 'sth.json'), 'utf8')).size, 4, 'the head kept is the honest one');
    await h.stop();
    const down = await run(h.url);
    assert.equal(down.status, 1);
    const badArgs = spawnSync(process.execPath, [tool, '--log', f.url], { encoding: 'utf8' });
    assert.equal(badArgs.status, 1);
    assert.match(badArgs.stderr, /usage/);
  } finally {
    await f.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
