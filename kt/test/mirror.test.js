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

test('a dropped connection mid-pagination is not a fork: the mirror stays where it was and the next sync catches up', async () => {
  const accts = [account('a'), account('b'), account('c')];
  const log = new KtLog({ store: new MemoryStore(), signingKey: logKey, now });
  for (let i = 0; i < 9; i++) log.publish(publishFor(accts[i % 3], Math.floor(i / 3) + 1));
  const server = await serve(log);
  const dir = tmpdir();
  try {
    let pages = 0;
    let dropAt = 2; // the second page of entries, so one page is already in hand
    const flaky = async (url) => {
      if (url.includes('/kt/v1/entries?')) {
        pages += 1;
        if (pages === dropAt) throw new Error('socket hang up');
      }
      const res = await fetch(url, { headers: { accept: 'application/json' } });
      if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
      return res.json();
    };

    // ---- the first sync ever: there is no head to fall back to ----
    const m = new Mirror({ dir, logUrl: server.url, logPub: log.publicKey, pageSize: 3, fetchJson: flaky, now }).load();
    await assert.rejects(m.sync(), (e) => !(e instanceof Divergence) && /socket hang up/.test(e.message));
    assert.equal(m.entries.length, 0, 'nothing was appended: a page in hand is not a page believed');
    assert.equal(m.head, null);
    assert.ok(!m.poisoned, 'a dropped connection is not evidence of a fork');
    assert.ok(!fs.existsSync(path.join(dir, 'sth.json')));
    dropAt = -1;
    assert.deepEqual(await m.sync().then((r) => [r.from, r.to]), [0, 9]);

    // ---- an established mirror: the same drop, with a head to keep ----
    for (let i = 9; i < 15; i++) log.publish(publishFor(accts[i % 3], Math.floor(i / 3) + 1));
    pages = 0;
    dropAt = 2;
    await assert.rejects(m.sync(), (e) => !(e instanceof Divergence) && /socket hang up/.test(e.message));
    assert.equal(m.entries.length, 9, 'still exactly the head it last verified');
    assert.equal(m.head.size, 9);
    assert.ok(!m.poisoned);
    dropAt = -1;
    // Without the fix this is `the head of size 15 does not extend the head of
    // size 12` and `poisoned` latches: in --serve mode the witness stops
    // following the log for ever, from one dropped connection.
    assert.deepEqual(await m.sync().then((r) => [r.from, r.to]), [9, 15]);
    assert.ok(m.tree.root.equals(log.tree.root));
    assert.ok(m.map.root.equals(log.map.root));
  } finally {
    await server.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a malformed response is an ordinary error, not a divergence: a fork is something the log signed', async () => {
  const a = account('a');
  const log = new KtLog({ store: new MemoryStore(), signingKey: logKey, now });
  for (let v = 1; v <= 4; v++) log.publish(publishFor(a, v));
  const server = await serve(log);
  const dir = tmpdir();
  try {
    // An empty page, which is what a cache or an error page in front of the
    // log produces. The head it served is perfectly well signed.
    const empty = async (url) => {
      const j = await (await fetch(url, { headers: { accept: 'application/json' } })).json();
      if (url.includes('/kt/v1/entries?')) return { entries: [] };
      return j;
    };
    const m = new Mirror({ dir, logUrl: server.url, logPub: log.publicKey, fetchJson: empty, now }).load();
    await assert.rejects(m.sync(), (e) => !(e instanceof Divergence) && /served no entries/.test(e.message));
    assert.ok(!m.poisoned, 'poisoning is permanent, so it is reserved for signed evidence');
    // And it recovers on its own once the path is honest again.
    const good = new Mirror({ dir, logUrl: server.url, logPub: log.publicKey, now }).load();
    assert.deepEqual(await good.sync().then((r) => [r.from, r.to]), [0, 4]);

    // An entries page whose elements are malformed: `null`, a missing
    // field, a short label, a non-integer index. Each is what a cache or an
    // error page produces, and each poisoned the mirror permanently until
    // 2026-09-17 — the review's finding 16, and the thing 3.3.9 had been
    // released to stop. The comment on the catch claimed `entryFromJson`
    // only threw for content; it threw for shape too, and both became
    // `Divergence`.
    const mangle = (how) => async (url) => {
      const j = await (await fetch(url, { headers: { accept: 'application/json' } })).json();
      if (url.includes('/kt/v1/entries?')) {
        const e = j.entries[0];
        if (how === 'null') j.entries[0] = null;
        if (how === 'missing') delete e.valueHash;
        if (how === 'short') e.label = Buffer.alloc(8).toString('base64');
        if (how === 'float') e.index = 0.5;
      }
      return j;
    };
    for (const how of ['null', 'missing', 'short', 'float']) {
      const m = new Mirror({ dir: tmpdir(), logUrl: server.url, logPub: log.publicKey, fetchJson: mangle(how), now }).load();
      await assert.rejects(m.sync(), (e) => !(e instanceof Divergence) && /malformed/.test(e.message), `a page mangled by '${how}' is a transport failure`);
      assert.ok(!m.poisoned, `and '${how}' did not poison the mirror`);
    }
    // Whereas a value that does not hash to its commitment IS the log's
    // fault, and still is one.
    const swappedValue = async (url) => {
      const j = await (await fetch(url, { headers: { accept: 'application/json' } })).json();
      if (url.includes('/kt/v1/entries?')) j.entries[0].value = Buffer.alloc(40).toString('base64');
      return j;
    };
    const bad = new Mirror({ dir: tmpdir(), logUrl: server.url, logPub: log.publicKey, fetchJson: swappedValue, now }).load();
    await assert.rejects(bad.sync(), (e) => e instanceof Divergence && /value hash/.test(e.message));
    assert.ok(bad.poisoned);

    // A consistency proof of the wrong shape, once the mirror has a head.
    log.publish(publishFor(a, 5));
    const wrongShape = async (url) => {
      const j = await (await fetch(url, { headers: { accept: 'application/json' } })).json();
      if (url.includes('/kt/v1/consistency')) return { first: 1, second: 2, proof: [] };
      return j;
    };
    const m2 = new Mirror({ dir, logUrl: server.url, logPub: log.publicKey, fetchJson: wrongShape, now }).load();
    await assert.rejects(m2.sync(), (e) => !(e instanceof Divergence) && /wrong shape/.test(e.message));
    assert.ok(!m2.poisoned);
    assert.equal(m2.entries.length, 4, 'and it kept the head it had');
  } finally {
    await server.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('the crash window: entries fsynced and the head not yet renamed loads again, and the surplus is dropped', async () => {
  const accts = [account('a'), account('b'), account('c')];
  const log = new KtLog({ store: new MemoryStore(), signingKey: logKey, now });
  for (let i = 0; i < 9; i++) log.publish(publishFor(accts[i % 3], Math.floor(i / 3) + 1));
  const server = await serve(log);
  const dir = tmpdir();
  const entriesFile = path.join(dir, 'entries.jsonl');
  const sthFile = path.join(dir, 'sth.json');
  try {
    const m = new Mirror({ dir, logUrl: server.url, logPub: log.publicKey, now }).load();
    await m.sync();
    const headAt9 = fs.readFileSync(sthFile);
    for (let i = 9; i < 13; i++) log.publish(publishFor(accts[i % 3], Math.floor(i / 3) + 1));
    await m.sync();
    const bytesAt13 = fs.statSync(entriesFile).size;
    // `sync` fsyncs the entries and only then renames sth.json into place. A
    // machine that dies between the two leaves exactly this.
    fs.writeFileSync(sthFile, headAt9);

    const again = new Mirror({ dir, logUrl: server.url, logPub: log.publicKey, now }).load();
    assert.equal(again.entries.length, 9, 'the stored head is the authority on how many lines count');
    assert.equal(again.head.size, 9);
    assert.ok(again.repaired > 0, 'and it says how much it dropped');
    assert.ok(fs.statSync(entriesFile).size < bytesAt13, 'the surplus is gone from the file, not just from memory');
    // The repair is a repair, not a decision retaken on every start.
    const third = new Mirror({ dir, logUrl: server.url, logPub: log.publicKey, now }).load();
    assert.equal(third.repaired, 0);
    assert.deepEqual(await again.sync().then((r) => [r.from, r.to]), [9, 13]);

    // The other direction is not repairable and still refuses: those entries
    // are under a root the log signed.
    const good = fs.readFileSync(entriesFile, 'utf8').split('\n').filter(Boolean);
    fs.writeFileSync(entriesFile, good.slice(0, 11).join('\n') + '\n');
    assert.throws(() => new Mirror({ dir, logUrl: server.url, logPub: log.publicKey, now }).load(),
                  /head size 13, 11 entries on disk/);
  } finally {
    await server.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a head that cannot be written leaves the mirror on the head it last verified', async () => {
  const accts = [account('a'), account('b'), account('c')];
  const log = new KtLog({ store: new MemoryStore(), signingKey: logKey, now });
  for (let i = 0; i < 6; i++) log.publish(publishFor(accts[i % 3], Math.floor(i / 3) + 1));
  const server = await serve(log);
  const dir = tmpdir();
  try {
    const m = new Mirror({ dir, logUrl: server.url, logPub: log.publicKey, now }).load();
    await m.sync();
    assert.equal(m.head.size, 6);
    for (let i = 6; i < 12; i++) log.publish(publishFor(accts[i % 3], Math.floor(i / 3) + 1));
    // A directory where the temporary file has to go. Every write to it fails,
    // which is a stand-in for the disk that is full or the mount that went
    // read-only — after the entries have already been fsynced.
    fs.mkdirSync(path.join(dir, 'sth.json.tmp'));
    await assert.rejects(m.sync(), (e) => !(e instanceof Divergence));
    assert.equal(m.head.size, 6, 'the head in memory is the one on disk');
    assert.equal(m.entries.length, 6, 'and memory holds nothing the head does not cover');
    assert.equal(m.record().size, 6);
    fs.rmdirSync(path.join(dir, 'sth.json.tmp'));
    // Without the recovery this is a consistency proof from size 12 against a
    // head of size 6, which the log cannot give: a fork, reported by a mirror
    // whose only problem was a write that failed.
    assert.deepEqual(await m.sync().then((r) => [r.from, r.to]), [6, 12]);
    assert.ok(m.tree.root.equals(log.tree.root));
  } finally {
    await server.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a recovery that cannot read the directory refuses to build on what is left', async () => {
  const accts = [account('a'), account('b'), account('c')];
  const log = new KtLog({ store: new MemoryStore(), signingKey: logKey, now });
  for (let i = 0; i < 6; i++) log.publish(publishFor(accts[i % 3], Math.floor(i / 3) + 1));
  const server = await serve(log);
  const dir = tmpdir();
  const sthFile = path.join(dir, 'sth.json');
  try {
    const m = new Mirror({ dir, logUrl: server.url, logPub: log.publicKey, now }).load();
    await m.sync();
    for (let i = 6; i < 12; i++) log.publish(publishFor(accts[i % 3], Math.floor(i / 3) + 1));

    // The recovery path itself fails: the directory it wants to re-read is
    // not readable. Memory is then neither the old state nor a new one, and
    // the only safe thing is to refuse until it is.
    const goodHead = fs.readFileSync(sthFile);
    fs.writeFileSync(sthFile, '{ not json');
    m._recover();
    assert.ok(m.needsReload);
    await assert.rejects(m.sync());
    assert.ok(m.needsReload, 'and it is still true, because nothing was fixed');
    assert.equal(fs.readFileSync(path.join(dir, 'entries.jsonl'), 'utf8').split('\n').filter(Boolean).length, 6,
                 'and it appended nothing to a file it could not account for');

    fs.writeFileSync(sthFile, goodHead);
    assert.deepEqual(await m.sync().then((r) => [r.from, r.to]), [6, 12]);
    assert.ok(!m.needsReload);
    assert.ok(m.tree.root.equals(log.tree.root));
  } finally {
    await server.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// The witness has to survive the log's success too. `log_memory.test.js`
// holds the LOG to a fraction of its file; until 2026-09-17 the mirror read
// its file whole and kept every sealed value in memory for the life of the
// process, and its first sync held the whole delta in an array besides. So a
// witness on the starter instance the Blueprint gives it OOMs on `load()`
// once the log's file passes instance memory — permanently, since the file
// it cannot read is the file it must read to start. Review finding 19; the
// witness is what G3 condition 3 asks somebody else to run. Measured with
// the values kept: 12.1 MiB retained of a 16.0 MiB delta. With the fix: a
// sync retains 0.07 MiB and a load 0.57 MiB.
const v8 = require('node:v8');
const vm = require('node:vm');
v8.setFlagsFromString('--expose_gc');
const gc = vm.runInNewContext('gc');
v8.setFlagsFromString('--no-expose_gc');
function retained() {
  gc();
  gc();
  const m = process.memoryUsage();
  return m.heapUsed + m.external;
}

test('a mirror retains a fraction of its file, on load and across a sync', async () => {
  // 64 entries of 192 KiB: ~12 MiB of values, ~16 MiB on disk. Lopsided on
  // purpose — the cost being measured is per byte of value, not per entry.
  const log = new KtLog({ store: new MemoryStore(), signingKey: logKey, now });
  const a = account('big');
  for (let v = 1; v <= 64; v++) {
    const value = sealValue(a.pub, crypto.randomBytes(192 * 1024 - 28));
    log.publish(makePublish(a.key, { version: v, fp: crypto.randomBytes(16), value }));
  }
  const server = await serve(log);
  const dir = tmpdir();
  try {
    // A first sync: the whole log is the delta.
    const before = retained();
    const m = new Mirror({ dir, logUrl: server.url, logPub: log.publicKey, pageSize: 8, now }).load();
    await m.sync();
    const afterSync = retained() - before;
    const onDisk = fs.statSync(path.join(dir, 'entries.jsonl')).size;
    assert.ok(onDisk > 12 * 1024 * 1024, `the file is ${onDisk} bytes`);
    assert.ok(m.tree.root.equals(log.tree.root));
    assert.ok(!fs.existsSync(path.join(dir, 'entries.jsonl.incoming')), 'the spool is gone once committed');
    assert.ok(
      afterSync < onDisk / 8,
      `a sync of a ${(onDisk / 1048576).toFixed(1)} MiB delta retained ${(afterSync / 1048576).toFixed(1)} MiB`
    );

    // A fresh load of the same directory, which is what a restart does.
    const beforeLoad = retained();
    const again = new Mirror({ dir, logUrl: server.url, logPub: log.publicKey, now }).load();
    const afterLoad = retained() - beforeLoad;
    assert.equal(again.entries.length, 64);
    assert.ok(again.tree.root.equals(log.tree.root), 'and it still hashes to the same head');
    assert.ok(
      afterLoad < onDisk / 8,
      `a load of a ${(onDisk / 1048576).toFixed(1)} MiB file retained ${(afterLoad / 1048576).toFixed(1)} MiB`
    );
    // Values are on disk, not in memory: nothing an entry keeps is the value.
    for (const e of again.entries) assert.equal(e.value, undefined);
  } finally {
    await server.stop();
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

test('the witness service: --serve answers /sth.json and /health, follows the log, is configured from the environment, and keeps serving after a divergence', async () => {
  const a = account('a');
  const honest = new KtLog({ store: new MemoryStore(), signingKey: logKey, now });
  const fork = new KtLog({ store: new MemoryStore(), signingKey: logKey, now });
  for (let v = 1; v <= 3; v++) {
    const p = publishFor(a, v);
    honest.publish(p);
    fork.publish(p);
  }
  fork.publish(publishFor(a, 9)); // the fork: a longer history that shares the first three
  fork.publish(publishFor(a, 10));
  const h = await serve(honest);
  const f = await serve(fork);
  const dir = tmpdir();
  const tool = path.join(__dirname, '..', 'tools', 'mirror.js');
  const witnessSeedHex = crypto.createHash('sha256').update('witness seed').digest('hex');
  const get = async (url) => {
    const res = await fetch(url);
    return { status: res.status, body: await res.json() };
  };
  // Start the tool and resolve with the port it announces; collect its
  // output so a failure has something to say.
  const start = (args, env) =>
    new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [tool, ...args], { env: { ...process.env, ...env } });
      let out = '';
      let err = '';
      child.stdout.on('data', (d) => {
        out += d;
        const m = out.match(/serving on http:\/\/0\.0\.0\.0:(\d+)/);
        if (m) resolve({ child, port: +m[1], out: () => out, err: () => err });
      });
      child.stderr.on('data', (d) => (err += d));
      child.on('close', (status) => reject(new Error(`exited ${status} before serving: ${err}`)));
    });
  const until = async (pred, what) => {
    for (let i = 0; i < 100; i++) {
      if (await pred()) return;
      await new Promise((r) => setTimeout(r, 50));
    }
    throw new Error(`timeout: ${what}`);
  };
  const stopped = (child) => new Promise((res) => child.on('close', res));

  // ---- configured entirely from the environment, serving on a free port ----
  const env = {
    KT_LOG_URL: h.url,
    KT_LOG_PUB: honest.publicKey.toString('base64'),
    KT_MIRROR_DIR: dir,
    KT_WITNESS_SEED: witnessSeedHex,
    KT_EVERY: '1',
    PORT: '0', // what a cloud host injects; 0 lets the OS pick, as a test must
  };
  const w = await start([], env);
  try {
    await until(async () => (await get(`http://127.0.0.1:${w.port}/sth.json`)).status === 200, 'first head served');
    const rec = (await get(`http://127.0.0.1:${w.port}/sth.json`)).body;
    assert.equal(rec.size, 3);
    assert.ok(rec.witness && rec.witness.sig, 'the served head is co-signed');
    assert.equal(rec.witness.pub, rawPublicKey(witnessKey).toString('base64'));
    // The record verifies exactly as a client verifies it: the log's own
    // signature on the head, and the witness's over the same input.
    const sth = sthFromJson(rec.sth);
    assert.ok(verifySth(sth, honest.publicKey));
    assert.ok(verify(rawPublicKey(witnessKey), witnessInput(sth), Buffer.from(rec.witness.sig, 'base64')));
    const health = (await get(`http://127.0.0.1:${w.port}/health`)).body;
    assert.equal(health.ok, true);
    assert.equal(health.size, 3);
    assert.equal(health.diverged, false);
    assert.equal(health.log, h.url);

    // It follows the log without being asked.
    honest.publish(publishFor(a, 4));
    await until(async () => (await get(`http://127.0.0.1:${w.port}/sth.json`)).body.size === 4, 'the fourth entry reaches the witness');

    // A served head nobody co-signed attests nothing: refused up front.
    const noKey = spawnSync(process.execPath, [tool, '--serve', '0'], {
      env: { ...process.env, KT_LOG_URL: h.url, KT_LOG_PUB: env.KT_LOG_PUB, KT_MIRROR_DIR: tmpdir() },
      encoding: 'utf8',
    });
    assert.equal(noKey.status, 1);
    assert.match(noKey.stderr, /witness key/);
  } finally {
    w.child.kill('SIGTERM');
    await stopped(w.child);
  }

  // ---- the same directory, pointed at a fork: diverges, keeps serving ----
  const d = await start(['--log', f.url, '--pub', env.KT_LOG_PUB, '--dir', dir, '--serve', '0', '--every', '1'], { KT_WITNESS_SEED: witnessSeedHex });
  try {
    await until(async () => (await get(`http://127.0.0.1:${d.port}/health`)).body.diverged === true, 'the fork is noticed');
    const health = (await get(`http://127.0.0.1:${d.port}/health`)).body;
    assert.equal(health.ok, false);
    assert.match(health.lastError, /does not extend|different roots/);
    const rec = (await get(`http://127.0.0.1:${d.port}/sth.json`)).body;
    assert.equal(rec.size, 4, 'the last honest head is what it still serves');
    assert.match(d.err(), /DIVERGENCE/);
    assert.match(d.err(), /still serving/);
    // It is still up, and still says so, a moment later.
    await new Promise((r) => setTimeout(r, 1200));
    assert.equal((await get(`http://127.0.0.1:${d.port}/health`)).status, 200);
  } finally {
    d.child.kill('SIGTERM');
    await stopped(d.child);
    await h.stop();
    await f.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a corrupt head is a clear error, not a raw SyntaxError or "entries without a head" (finding 43)', async () => {
  const log = new KtLog({ store: new MemoryStore(), signingKey: logKey, now });
  const accts = [account('x'), account('y')];
  for (let i = 0; i < 4; i++) log.publish(publishFor(accts[i % 2], Math.floor(i / 2) + 1));
  const server = await serve(log);
  const dir = tmpdir();
  try {
    const m = new Mirror({ dir, logUrl: server.url + '/', logPub: log.publicKey, pageSize: 2, now }).load();
    await m.sync();
    const sthFile = path.join(dir, 'sth.json');
    const good = fs.readFileSync(sthFile, 'utf8');
    assert.doesNotThrow(() => JSON.parse(good), 'the durable write produced valid JSON');

    // A torn / corrupt head: valid file, invalid JSON. Before the fix this
    // rethrew a raw SyntaxError (no `.code`), and deleting it then threw
    // "entries without a head" — a dead end. Now it names the situation.
    fs.writeFileSync(sthFile, '{ "sth": { "size": 4, ');
    let err;
    try {
      new Mirror({ dir, logUrl: server.url, logPub: log.publicKey, now }).load();
    } catch (e) {
      err = e;
    }
    assert.ok(err, 'a corrupt head must not load silently');
    assert.match(err.message, /does not parse/);
    assert.doesNotMatch(err.message, /entries without a head/);
    assert.ok(!(err instanceof SyntaxError), 'not a raw SyntaxError');

    // With a valid head back, it loads and agrees again.
    fs.writeFileSync(sthFile, good);
    const again = new Mirror({ dir, logUrl: server.url, logPub: log.publicKey, now }).load();
    assert.equal(again.entries.length, 4);
  } finally {
    await server.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
