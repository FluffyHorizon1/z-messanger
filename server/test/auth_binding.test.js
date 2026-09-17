'use strict';

// Authentication that names the relay it is for.
//
// The v1 challenge is signed as `"z-relay-auth-v1:" || nonce`, and nothing
// in that says WHICH relay the nonce came from. So a relay the user was
// induced to connect to — Settings › Relay server, an invite, a MITM on a
// `ws://` address — could open its own socket to the honest relay, hand the
// honest relay's nonce to the user as its own challenge, and replay the
// signature it got back: authenticated as that device at the honest relay,
// with the `ready` flush and everything queued from then on, able to
// acknowledge it away (the 2026-09-14 review's finding 13, against
// THREAT_MODEL.md's "only the holder of a device's private key can receive
// that mailbox's queued messages").
//
// v2 signs `"z-relay-auth-v2:" || authority || nonce`, where the authority is
// what the client dialled — the Host header, normalised the same way on
// both ends — so a signature made for one relay verifies at no other. The
// relay accepts v1 for clients that predate v2, counted, until the operator
// turns it off.
//
// Criteria, each asserted below:
//   1. the replay: a signature the honest relay's challenge draws out of a
//      client through a hostile relay authenticates at the honest relay
//      under v1 and does NOT under v2, because the client signed the
//      hostile relay's authority;
//   2. a v2 signature over the wrong authority is refused and counted, one
//      over an authority the operator listed (RELAY_AUTHORITIES) is
//      accepted, and the authority is normalised — case, a default port —
//      the same way a client's Host header is;
//   3. v1 is accepted while RELAY_AUTH_V1 is on and counted every time, and
//      refused when it is off; the challenge advertises v2 either way;
//   4. and the frozen v2 vectors verify here, against the same message the
//      Dart client signs.

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const path = require('path');
const WebSocket = require('ws');

const { createServer, CFG, normalizeAuthority, routingIdFromPub } = require('../server.js');

const V1 = Buffer.from('z-relay-auth-v1:', 'utf8');
const V2 = Buffer.from('z-relay-auth-v2:', 'utf8');

function makeIdentity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const rawPub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  return { publicKey, privateKey, rawPub, rid: routingIdFromPub(rawPub) };
}

function signV1(identity, nonce) {
  return crypto.sign(null, Buffer.concat([V1, nonce]), identity.privateKey);
}
function signV2(identity, authority, nonce) {
  return crypto.sign(null, Buffer.concat([V2, Buffer.from(authority, 'utf8'), nonce]), identity.privateKey);
}

function get(port, p) {
  return new Promise((resolve, reject) => {
    http
      .get({ host: '127.0.0.1', port, path: p }, (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => resolve(body));
      })
      .on('error', reject);
  });
}
function metric(body, name) {
  const m = body.match(new RegExp(`^${name} (\\d+)$`, 'm'));
  return m ? Number(m[1]) : null;
}

/** A raw socket to a relay: the challenge, then whatever auth we choose to send. */
function open(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url, { headers });
    const frames = [];
    const waiters = [];
    ws.on('error', reject);
    ws.on('message', (d) => {
      const f = JSON.parse(d.toString());
      const i = waiters.findIndex((w) => w.pred(f));
      if (i !== -1) waiters.splice(i, 1)[0].resolve(f);
      else frames.push(f);
    });
    ws.on('close', () => {
      for (const w of waiters.splice(0)) w.resolve({ t: 'closed' });
    });
    const next = (pred, ms = 3000) => {
      const i = frames.findIndex(pred);
      if (i !== -1) return Promise.resolve(frames.splice(i, 1)[0]);
      return new Promise((res, rej) => {
        const t = setTimeout(() => rej(new Error('timeout')), ms);
        waiters.push({ pred, resolve: (f) => (clearTimeout(t), res(f)) });
      });
    };
    ws.on('open', () => resolve({ ws, next, send: (o) => ws.send(JSON.stringify(o)), close: () => ws.close() }));
  });
}

async function relay(t, opts = {}) {
  const srv = createServer({ pushSender: null });
  await new Promise((r) => srv.httpServer.listen(0, '127.0.0.1', r));
  const port = srv.httpServer.address().port;
  t.after(() => {
    for (const ws of srv.wss.clients) ws.terminate();
    srv.httpServer.close();
  });
  return { srv, port, url: `ws://127.0.0.1:${port}`, authority: `127.0.0.1:${port}` };
}

test('1. a signature drawn out through a hostile relay authenticates under v1 and not under v2', async (t) => {
  const honest = await relay(t);
  const alice = makeIdentity();
  const before = await get(honest.port, '/metrics');

  // The hostile relay: it opens a socket to the honest relay, takes the
  // honest relay's nonce, and presents it to Alice as its own challenge.
  // Alice's client is modelled directly: what it signs is the question.
  const attackerSocket = await open(honest.url);
  const ch = await attackerSocket.next((f) => f.t === 'challenge');
  assert.strictEqual(ch.auth, 2, 'the honest relay advertises the bound form');
  const nonce = Buffer.from(ch.nonce, 'base64');

  // A v1 client signs the nonce alone: the attacker replays it and is in.
  const v1 = signV1(alice, nonce);
  attackerSocket.send({ t: 'auth', pub: alice.rawPub.toString('base64'), sig: v1.toString('base64') });
  const ready = await attackerSocket.next((f) => f.t === 'ready' || f.t === 'error');
  assert.strictEqual(ready.t, 'ready', 'v1: the replay authenticates — the finding');
  assert.strictEqual(ready.id, alice.rid, 'as Alice');
  attackerSocket.close();

  // A v2 client signs the authority IT dialled — the attacker's — with the
  // nonce. Replayed at the honest relay, that names the wrong relay.
  const attackerSocket2 = await open(honest.url);
  const ch2 = await attackerSocket2.next((f) => f.t === 'challenge');
  const nonce2 = Buffer.from(ch2.nonce, 'base64');
  const v2ForAttacker = signV2(alice, 'evil.example', nonce2);
  attackerSocket2.send({ t: 'auth', v: 2, pub: alice.rawPub.toString('base64'), sig: v2ForAttacker.toString('base64') });
  const refused = await attackerSocket2.next((f) => f.t === 'ready' || f.t === 'error');
  assert.strictEqual(refused.t, 'error', 'v2: a signature made for evil.example is nothing here');
  assert.strictEqual(refused.code, 'bad_auth');
  await attackerSocket2.next((f) => f.t === 'closed');

  // And Alice herself, dialling the honest relay, is in.
  const own = await open(honest.url);
  const ch3 = await own.next((f) => f.t === 'challenge');
  own.send({ t: 'auth', v: 2, pub: alice.rawPub.toString('base64'), sig: signV2(alice, honest.authority, Buffer.from(ch3.nonce, 'base64')).toString('base64') });
  assert.strictEqual((await own.next((f) => f.t === 'ready' || f.t === 'error')).t, 'ready');
  own.close();

  const after = await get(honest.port, '/metrics');
  assert.strictEqual(metric(after, 'z_auth_v1_total') - metric(before, 'z_auth_v1_total'), 1, 'the one v1 authentication counted');
  assert.strictEqual(metric(after, 'z_auth_v2_refused_total') - metric(before, 'z_auth_v2_refused_total'), 1, 'the one replay counted');
});

test('2. the authority is the Host header, normalised as a client normalises it; the operator may list more', async (t) => {
  const r = await relay(t);
  const alice = makeIdentity();
  const tryAuth = async (signed, headers = {}) => {
    const c = await open(r.url, headers);
    const ch = await c.next((f) => f.t === 'challenge');
    c.send({ t: 'auth', v: 2, pub: alice.rawPub.toString('base64'), sig: signV2(alice, signed, Buffer.from(ch.nonce, 'base64')).toString('base64') });
    const res = await c.next((f) => f.t === 'ready' || f.t === 'error');
    c.close();
    return res.t;
  };
  assert.strictEqual(await tryAuth(r.authority), 'ready');
  assert.strictEqual(await tryAuth('RELAY.EXAMPLE', { Host: 'relay.example' }), 'error', 'the signed authority must already be normalised');
  assert.strictEqual(await tryAuth('127.0.0.1'), 'error', 'the port is part of the name when it is not the default');
  assert.strictEqual(await tryAuth('127.0.0.2:' + r.port), 'error');
  // The Host header decides what this relay is called: a client that sends
  // one names the relay by it (through a front that passes Host along, that
  // is the name the user dialled).
  assert.strictEqual(await tryAuth('relay.example', { Host: 'Relay.Example' }), 'ready', 'lower-cased');
  assert.strictEqual(await tryAuth('relay.example', { Host: 'relay.example:443' }), 'ready', 'a default port is not part of the name');
  assert.strictEqual(await tryAuth('relay.example:443', { Host: 'relay.example:443' }), 'error', 'and must not be signed either');
  assert.strictEqual(await tryAuth('relay.example:8443', { Host: 'relay.example:8443' }), 'ready', 'a non-default port is');
  assert.strictEqual(await tryAuth('[::1]:8080', { Host: '[::1]:8080' }), 'ready', 'an IPv6 literal keeps its brackets');
  // The operator's list, for a front that rewrites Host.
  const saved = CFG.authorities;
  CFG.authorities = [normalizeAuthority('Public.Example:443')];
  t.after(() => (CFG.authorities = saved));
  assert.strictEqual(await tryAuth('public.example', { Host: 'internal-name:8080' }), 'ready', 'a listed authority is accepted whatever Host says');
  assert.strictEqual(await tryAuth('internal-name:8080', { Host: 'internal-name:8080' }), 'ready', 'and the Host header still is');
  assert.strictEqual(await tryAuth('other.example'), 'error');
  // The normaliser itself, at its edges.
  assert.strictEqual(normalizeAuthority('Relay.Example:443'), 'relay.example');
  assert.strictEqual(normalizeAuthority('relay.example:80'), 'relay.example');
  assert.strictEqual(normalizeAuthority('relay.example:8080'), 'relay.example:8080');
  assert.strictEqual(normalizeAuthority('[::1]:443'), '[::1]');
  assert.strictEqual(normalizeAuthority(''), '');
  assert.strictEqual(normalizeAuthority(undefined), '');
});

test('3. v1 is accepted and counted while it is on, refused when it is off; v2 is advertised either way', async (t) => {
  const r = await relay(t);
  const alice = makeIdentity();
  const tryV1 = async () => {
    const c = await open(r.url);
    const ch = await c.next((f) => f.t === 'challenge');
    assert.strictEqual(ch.auth, 2);
    c.send({ t: 'auth', pub: alice.rawPub.toString('base64'), sig: signV1(alice, Buffer.from(ch.nonce, 'base64')).toString('base64') });
    const res = await c.next((f) => f.t === 'ready' || f.t === 'error');
    c.close();
    return res.t;
  };
  const before = metric(await get(r.port, '/metrics'), 'z_auth_v1_total');
  assert.strictEqual(await tryV1(), 'ready');
  assert.strictEqual(await tryV1(), 'ready');
  assert.strictEqual(metric(await get(r.port, '/metrics'), 'z_auth_v1_total'), before + 2, 'every v1 authentication is counted: the number that says when to turn it off');
  const saved = CFG.authV1;
  CFG.authV1 = false;
  t.after(() => (CFG.authV1 = saved));
  assert.strictEqual(await tryV1(), 'error', 'off: the unbound form is refused');
  assert.strictEqual(metric(await get(r.port, '/metrics'), 'z_auth_v1_total'), before + 2, 'and not counted as a v1 authentication, since it was not one');
  // v2 unaffected.
  const c = await open(r.url);
  const ch = await c.next((f) => f.t === 'challenge');
  c.send({ t: 'auth', v: 2, pub: alice.rawPub.toString('base64'), sig: signV2(alice, r.authority, Buffer.from(ch.nonce, 'base64')).toString('base64') });
  assert.strictEqual((await c.next((f) => f.t === 'ready' || f.t === 'error')).t, 'ready');
  c.close();
});

test('4. the frozen v2 vectors verify against the message the client signs', () => {
  const file = path.join(__dirname, '..', '..', 'docs', 'vectors', 'relay-auth-v2', 'relay_auth_v2.json');
  const v = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.ok(Array.isArray(v.relay_auth_v2) && v.relay_auth_v2.length >= 2);
  for (const a of v.relay_auth_v2) {
    const nonce = Buffer.from(a.nonce, 'hex');
    const authority = normalizeAuthority(a.host_header);
    assert.strictEqual(authority, a.authority, `${a.url}: the relay normalises the Host header to what the client signed`);
    const msg = Buffer.concat([V2, Buffer.from(authority, 'utf8'), nonce]);
    assert.strictEqual(msg.toString('hex'), a.signed_message);
    const pub = Buffer.from(a.auth_frame.pub, 'base64');
    const key = crypto.createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), pub]), format: 'der', type: 'spki' });
    assert.ok(crypto.verify(null, msg, key, Buffer.from(a.auth_frame.sig, 'base64')), `${a.url}: the recorded signature verifies`);
    assert.strictEqual(a.auth_frame.v, 2);
    assert.strictEqual(a.auth_frame.t, 'auth');
  }
  for (const n of v.normalization) {
    assert.strictEqual(normalizeAuthority(n.host_header), n.authority, `${n.url}`);
  }
});
