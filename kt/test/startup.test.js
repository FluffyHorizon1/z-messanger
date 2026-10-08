'use strict';

// Starting the log: what happens between `node server.js` and a log that
// serves. Three things went wrong in that interval (the 2026-10-03 analysis),
// and none of them showed until it had.
//
// The systemd recipe never started. It ran the service as `z-kt` with
// KT_SEED_FILE=/etc/z-kt/seed, and SELF_HOSTING's own step 1 makes that file
// root's — mode 600, in a directory of mode 700 — so the service's first
// read was EACCES, every time, for everyone who followed the steps.
//
// Nothing answered while the log replayed. The replay rebuilds both trees
// from the whole file before the server listens, which on a large log is
// minutes with a closed port — and a log that had outgrown its instance was
// killed in the middle of it, on every restart, with nothing to show for it
// but a restart counter.
//
// And a restored whole-disk snapshot started like any other day and signed
// a fork (`head_floor.test.js` 7 has the log; here is the server around it).
//
// What is asserted below:
//   1. the recipe gives the service user a seed it can read: the unit hands
//      the root-only seed over as a systemd credential and points
//      KT_SEED_FILE at the copy (%d), the steps create the user it runs as,
//      and the old unit — KT_SEED_FILE at the root-only file — is what this
//      refuses. Where the test runs as root, it also runs both: the server
//      started as an unprivileged user fails EACCES on the root-only file,
//      and starts on the copy systemd's LoadCredential makes;
//   2. /health answers while a log replays — 503, with how far it has got
//      and the memory it holds, everything else 503 too — and then the same
//      port serves the log, /health 200 with the memory beside the size;
//   3. the server refuses a restored snapshot (exit 1, naming the head to
//      confirm), starts when KT_CONFIRM_HEAD names it, and records its head
//      at a clean stop, so the restart after a deploy is an ordinary one.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const {
  KtLog,
  FileStore,
  labelFor,
  sealValue,
  makePublish,
  privateKeyFromSeed,
  rawPublicKey,
} = require('../lib/log.js');
const { sha256 } = require('../lib/merkle.js');

const KT = path.join(__dirname, '..');
const seedHex = crypto.createHash('sha256').update('startup seed').digest('hex');
const logKey = privateKeyFromSeed(Buffer.from(seedHex, 'hex'));
const logPubB64 = rawPublicKey(logKey).toString('base64');

function account(name) {
  const key = privateKeyFromSeed(crypto.createHash('sha256').update(`acct:${name}`).digest());
  return { key, pub: rawPublicKey(key), label: labelFor(rawPublicKey(key)) };
}

function publishFor(acct, v) {
  const value = sealValue(acct.pub, Buffer.from(`list ${v}`, 'utf8'));
  return makePublish(acct.key, { version: v, fp: crypto.randomBytes(16), value });
}

function tmpdir(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kt-start-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/** [n] correctly signed entries, written as the log writes its lines, with no head. */
function writeLines(file, n) {
  const lines = [];
  for (let i = 0; i < n; i++) {
    const a = account(`replay-${i}`);
    const value = sealValue(a.pub, crypto.randomBytes(1100 - 28));
    const fp = crypto.randomBytes(16);
    const p = makePublish(a.key, { version: 1, fp, value });
    lines.push(
      JSON.stringify({
        i,
        label: a.label.toString('base64'),
        v: 1,
        fp: fp.toString('base64'),
        vh: sha256(value).toString('base64'),
        val: value.toString('base64'),
        acct: a.pub.toString('base64'),
        ts: 1_700_000_000_000 + i,
        sig: p.sig.toString('base64'),
      })
    );
  }
  fs.writeFileSync(file, lines.join('\n') + '\n');
}

/**
 * `node server.js` with [env] (and nothing else from this process's), as
 * [user] when given. `waitFor` resolves with the first stdout match, and
 * rejects if the process exits first or [ms] pass; `exited` resolves with the
 * exit code, or rejects after [ms] if it is still running. Every wait is
 * bounded and says what it was waiting for.
 */
function startServer(t, env, user = {}) {
  const child = spawn(process.execPath, ['server.js'], {
    cwd: KT,
    env: { PATH: process.env.PATH, ...env },
    ...user,
  });
  let out = '';
  let err = '';
  let code = null;
  const listeners = new Set();
  child.stdout.on('data', (d) => {
    out += d;
    for (const l of listeners) l();
  });
  child.stderr.on('data', (d) => (err += d));
  const closed = new Promise((resolve) => child.on('close', (c) => resolve((code = c))));
  t.after(() => {
    if (code === null) child.kill('SIGKILL');
  });
  const bounded = (p, what, ms) =>
    Promise.race([
      p,
      new Promise((_, reject) => {
        const timer = setTimeout(() => reject(new Error(`timed out after ${ms} ms: ${what}\nstdout: ${out}\nstderr: ${err}`)), ms);
        timer.unref();
      }),
    ]);
  return {
    child,
    stdout: () => out,
    stderr: () => err,
    exited: (what, ms = 30_000) => bounded(closed, what, ms),
    waitFor: (re, what, ms = 60_000) =>
      bounded(
        new Promise((resolve, reject) => {
          const check = () => {
            const m = re.exec(out);
            if (m) {
              listeners.delete(check);
              resolve(m);
            }
          };
          listeners.add(check);
          closed.then((c) => reject(new Error(`exited ${c} before ${what}\nstdout: ${out}\nstderr: ${err}`)));
          check();
        }),
        what,
        ms
      ),
  };
}

async function getJson(url) {
  const r = await fetch(url);
  return { status: r.status, body: await r.json() };
}

/** An awaited poll: [pred] until it holds, or fail saying [what]. */
async function until(pred, what, tries = 400, everyMs = 50) {
  for (let i = 0; i < tries; i++) {
    try {
      if (await pred()) return;
    } catch {
      // not yet answering
    }
    await new Promise((r) => setTimeout(r, everyMs));
  }
  throw new Error(`timed out waiting for: ${what}`);
}

test('1. the systemd recipe gives the service a seed it can read', async (t) => {
  const unit = fs.readFileSync(path.join(KT, 'deploy', 'z-kt.service'), 'utf8');
  const directives = (key) => [...unit.matchAll(new RegExp(`^${key}=(.*)$`, 'gm'))].map((m) => m[1].trim());
  const split = (v, sep) => {
    const i = v.indexOf(sep);
    return [v.slice(0, i), v.slice(i + 1)];
  };
  const user = directives('User')[0];
  const env = Object.fromEntries(directives('Environment').map((v) => split(v, '=')));
  const creds = Object.fromEntries(directives('LoadCredential').map((v) => split(v, ':')));
  assert.ok(user && user !== 'root', 'the service runs unprivileged');

  // The premise: step 1 makes the seed root's.
  const doc = fs.readFileSync(path.join(KT, '..', 'docs', 'SELF_HOSTING.md'), 'utf8');
  assert.match(doc, /install -d -m 700 \/etc\/z-kt\b/);
  assert.match(doc, /chmod 600 \/etc\/z-kt\/seed/);

  // So the service may not be pointed at that file: it arrives as a
  // credential, and KT_SEED_FILE names the copy.
  assert.notEqual(env.KT_SEED_FILE, '/etc/z-kt/seed', 'an unprivileged service cannot read a root-only file: every start was EACCES');
  const named = /^%d\/(.+)$/.exec(env.KT_SEED_FILE || '');
  assert.ok(named, `KT_SEED_FILE (${env.KT_SEED_FILE}) names the credentials directory`);
  assert.equal(creds[named[1]], '/etc/z-kt/seed', 'and the credential it names is loaded from the seed step 1 made');

  // And the steps create the user the unit runs as, before anything is
  // handed to it — `install -o z-kt` fails on a user that does not exist.
  const optionA = doc.slice(doc.indexOf('**Option A'), doc.indexOf('**Option B'));
  const created = optionA.search(new RegExp(`useradd[^\\n]*\\b${user}\\b`));
  const handed = optionA.indexOf(`-o ${user}`);
  assert.ok(created >= 0, `Option A creates the ${user} user`);
  assert.ok(handed < 0 || created < handed, 'before handing it the data directory');

  // Run both, where this can: it takes root to make a root-only file and
  // then be somebody else.
  if (typeof process.getuid !== 'function' || process.getuid() !== 0) {
    t.diagnostic('not root here, so the run as an unprivileged user is not made; the recipe checks above still hold');
    return;
  }
  const nobody = { uid: 65534, gid: 65534 };
  const root = tmpdir(t);
  fs.chmodSync(root, 0o755); // traversable, as / and /etc are
  const etc = path.join(root, 'etc-z-kt');
  fs.mkdirSync(etc, { mode: 0o700 });
  const seedFile = path.join(etc, 'seed');
  fs.writeFileSync(seedFile, `${seedHex}\n`, { mode: 0o600 });

  // The old unit: the service user reads the seed where step 1 put it.
  const old = startServer(t, { KT_SEED_FILE: seedFile, KT_EPHEMERAL: '1', KT_PORT: '0' }, nobody);
  assert.equal(await old.exited('the old recipe refusing'), 1);
  assert.match(old.stderr(), /EACCES/);

  // What LoadCredential= does: systemd reads the file as root when the unit
  // starts and puts a copy, readable by the service user alone, in a
  // directory only it can open — $CREDENTIALS_DIRECTORY, which %d names.
  const credDir = path.join(root, 'credentials');
  fs.mkdirSync(credDir, { mode: 0o500 });
  const cred = path.join(credDir, named[1]);
  fs.copyFileSync(seedFile, cred);
  fs.chmodSync(cred, 0o400);
  fs.chownSync(cred, nobody.uid, nobody.gid);
  fs.chownSync(credDir, nobody.uid, nobody.gid);
  const fixed = startServer(t, { KT_SEED_FILE: cred, KT_EPHEMERAL: '1', KT_PORT: '0' }, nobody);
  const [, pub] = await fixed.waitFor(/public key (\S+)/, 'the server started from the credential');
  assert.equal(pub, logPubB64, 'with the seed step 1 made');
  fixed.child.kill('SIGTERM');
  assert.equal(await fixed.exited('a clean stop'), 0);
});

test('2. /health answers while the log replays, and the same port then serves it', async (t) => {
  const dir = tmpdir(t);
  const N = 6000;
  writeLines(path.join(dir, 'entries.jsonl'), N);
  const s = startServer(t, { KT_SEED: seedHex, KT_DATA: dir, KT_PORT: '0' });
  const [, port] = await s.waitFor(/replaying; GET http:\/\/127\.0\.0\.1:(\d+)\/health/, 'the replay announcing its port');
  const base = `http://127.0.0.1:${port}`;

  // Asked at once — both together, so both are answered at the same pause in
  // the replay, the first one it reaches.
  const [during, early] = await Promise.all([getJson(`${base}/health`), getJson(`${base}/kt/v1/sth`)]);
  assert.equal(during.status, 503, 'not serving yet, and a health check should say so');
  assert.equal(during.body.state, 'replaying');
  assert.ok(Number.isInteger(during.body.replayed) && during.body.replayed <= N, `replayed ${during.body.replayed}`);
  assert.ok(during.body.rssBytes > 0 && during.body.memLimitBytes >= during.body.rssBytes, 'and the memory it holds, beside what it may');
  assert.equal(early.status, 503, 'nothing is served — nor signed — before every check a start makes has passed');
  assert.equal(early.body.error, 'starting');

  await until(async () => (await getJson(`${base}/health`)).status === 200, 'the same port serving the log');
  const after = await getJson(`${base}/health`);
  assert.equal(after.body.state, 'serving');
  assert.equal(after.body.size, N);
  assert.ok(after.body.rssBytes > 0 && after.body.memLimitBytes >= after.body.rssBytes, 'the memory gauge, beside the size');
  assert.equal((await getJson(`${base}/kt/v1/sth`)).body.size, N);
  s.child.kill('SIGTERM');
  assert.equal(await s.exited('a clean stop'), 0);
});

test('3. a restored snapshot is refused until it is named, and a clean stop is recorded', async (t) => {
  const dir = tmpdir(t);
  const file = path.join(dir, 'entries.jsonl');
  const headFile = `${file}.head.json`;
  // A log last alive two hours ago, which is what a restored snapshot looks
  // like when it starts: a head that agrees with the entries, and is old.
  const then = Date.now() - 2 * 3_600_000;
  const log = new KtLog({ store: new FileStore(file), signingKey: logKey, now: () => then });
  for (let v = 1; v <= 3; v++) log.publish(publishFor(account('alice'), v));
  log.close();
  const ts = JSON.parse(fs.readFileSync(headFile, 'utf8')).ts;
  // KT_MIN_SIZE=1 as the Blueprint ships it; KT_MAX_HEAD_AGE_MIN is left at
  // its default, which is the point.
  const env = { KT_SEED: seedHex, KT_DATA: dir, KT_PORT: '0', KT_MIN_SIZE: '1' };

  const refused = startServer(t, env);
  assert.equal(await refused.exited('a start against a two-hour-old head refusing'), 1);
  assert.match(refused.stderr(), new RegExp(`KT_CONFIRM_HEAD=3@${ts}`));

  const s = startServer(t, { ...env, KT_CONFIRM_HEAD: `3@${ts}` });
  const [, port] = await s.waitFor(/listening on http:\/\/127\.0\.0\.1:(\d+)/, 'the confirmed start serving');
  assert.equal((await getJson(`http://127.0.0.1:${port}/kt/v1/sth`)).body.size, 3);
  const stoppedAt = Date.now();
  s.child.kill('SIGTERM');
  assert.equal(await s.exited('a clean stop'), 0);
  assert.ok(JSON.parse(fs.readFileSync(headFile, 'utf8')).ts >= stoppedAt, 'the head was recorded at the stop');

  // So the next start — a deploy's — needs nothing.
  const again = startServer(t, env);
  await again.waitFor(/listening on/, 'the ordinary restart serving');
  again.child.kill('SIGTERM');
  assert.equal(await again.exited('a clean stop'), 0);
});
