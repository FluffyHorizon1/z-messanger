'use strict';
// /metrics requires a bearer token (P1-14); set one before server.js is
// required so CFG picks it up, and send it on the gets below.
process.env.METRICS_TOKEN = process.env.METRICS_TOKEN || 'z-test-metrics-token';


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
//   2. v2 is verified against the relay's CONFIGURED names only, never the
//      Host header the presenter sends (P1-16): a signature made for another
//      relay is refused even when the presenter sets Host to match it (the
//      splice); a configured name is accepted whatever Host says; and an
//      unconfigured relay trusts a dialled loopback/LAN name on a connection
//      from a loopback/private address (dev, LAN, this suite) but refuses a
//      public name — including one that merely starts like an IPv6 prefix —
//      and a local name presented from a public address;
//   3. v1 is accepted while RELAY_AUTH_V1 is on and counted every time, and
//      refused when it is off; the challenge advertises v2 either way;
//   4. the frozen v2 vectors verify here, against the same message the
//      Dart client signs;
//   5. and a refusal on a connection that dialled a name the relay was not
//      told — a list missing a name clients dial, which from the outside is
//      every client failing at once — is counted apart and the name is written
//      to the log, once an hour per name, quoted so that nothing a presenter
//      put in the header reaches the log unescaped; a refusal on a name the
//      relay does know (a replay, a bad signature) is not, since nothing is
//      missing from the list.

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const path = require('path');
const WebSocket = require('ws');

const { createServer, CFG, normalizeAuthority, isLocalAuthority, routingIdFromPub } = require('../server.js');

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
      .get({ host: '127.0.0.1', port, path: p, headers: { authorization: `Bearer ${process.env.METRICS_TOKEN}` } }, (res) => {
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

test('2. v2 is verified against the configured names ONLY, never the presented Host (P1-16)', async (t) => {
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

  // Unconfigured relay (the default): it was told no name, and the connection
  // dialled a loopback address (127.0.0.1:port), which has no MITM boundary
  // to protect — so the dialled name is trusted, which is how the whole test
  // suite authenticates. A public Host with no RELAY_AUTHORITIES is refused.
  assert.strictEqual(CFG.authorities.length, 0, 'default is unconfigured');
  assert.strictEqual(await tryAuth(r.authority), 'ready', 'loopback authority: the dev/LAN fallback');
  assert.strictEqual(await tryAuth('RELAY.EXAMPLE', { Host: 'relay.example' }), 'error',
    'a public Host with nothing configured is refused — the relay will not verify a name it was not told');
  assert.strictEqual(await tryAuth('relay.example', { Host: 'relay.example' }), 'error',
    'signing the public Host does not help: the Host is never what v2 is checked against');
  assert.strictEqual(await tryAuth('127.0.0.2:' + r.port), 'error', 'the wrong loopback name still fails');
  assert.strictEqual(await tryAuth('relay.local:8080', { Host: 'relay.local:8080' }), 'ready', 'a .local (LAN) name is the same case');
  assert.strictEqual(await tryAuth('[fd12:3456::1]:8080', { Host: '[fd12:3456::1]:8080' }), 'ready', 'so is a unique-local IPv6 literal');
  // A public NAME that merely starts like an IPv6 prefix is public.
  assert.strictEqual(await tryAuth('fd.example', { Host: 'fd.example' }), 'error', 'fd.example is a public name');
  assert.strictEqual(await tryAuth('fcbarcelona.example', { Host: 'fcbarcelona.example' }), 'error', 'and so is fc…');
  // The other half: a local name presented from the INTERNET is refused — a
  // signature some victim made for a LAN relay, replayed to this one. (The
  // suite connects over loopback, so this half is exercised directly.)
  assert.strictEqual(isLocalAuthority('192.168.1.50:8080', '203.0.113.9'), false, 'local name, public peer: refused');
  assert.strictEqual(isLocalAuthority('192.168.1.50:8080', '::ffff:203.0.113.9'), false, 'nor via a v4-mapped public peer');
  assert.strictEqual(isLocalAuthority('192.168.1.50:8080', '::ffff:10.0.0.7'), true, 'local name, private peer (a LAN, a container network)');
  assert.strictEqual(isLocalAuthority('127.0.0.1:8080', '::1'), true, 'loopback both ways');
  assert.strictEqual(isLocalAuthority('relay.example', '127.0.0.1'), false, 'a public name is refused even from loopback (a same-host proxy)');
  assert.strictEqual(isLocalAuthority('[2001:db8::1]', '127.0.0.1'), false, 'a public IPv6 literal is public');

  // Configured relay: v2 is verified against CFG.authorities and nothing else.
  const saved = CFG.authorities;
  CFG.authorities = [normalizeAuthority('Honest.Example')];
  t.after(() => (CFG.authorities = saved));
  // THE SPLICE (P1-16): a victim dialled the attacker and signed the
  // attacker's name; the attacker presents that signature to the honest relay
  // with Host set to the attacker's name. The honest relay verifies only
  // against its own configured name, so the victim's signature is nothing
  // here whatever Host the presenter sends.
  assert.strictEqual(await tryAuth('evil.example', { Host: 'evil.example' }), 'error',
    'a signature made for another relay is refused even when the presenter sets Host to match it');
  assert.strictEqual(await tryAuth('honest.example', { Host: 'evil.example' }), 'ready',
    'the configured name is accepted whatever Host says — the Host is not consulted');
  assert.strictEqual(await tryAuth('honest.example'), 'ready', 'and with no Host header at all');
  assert.strictEqual(await tryAuth(r.authority), 'error',
    'once a name is configured, the loopback fallback is off: only the configured name verifies');

  // A front that rewrites Host: the operator lists every name clients dial.
  CFG.authorities = [normalizeAuthority('public.example'), normalizeAuthority('www.public.example')];
  assert.strictEqual(await tryAuth('public.example', { Host: 'internal-upstream:8080' }), 'ready');
  assert.strictEqual(await tryAuth('www.public.example', { Host: 'internal-upstream:8080' }), 'ready');
  assert.strictEqual(await tryAuth('other.example', { Host: 'public.example' }), 'error');

  // The normaliser itself, at its edges (a client signs the normalised form).
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

test('5. a refusal on a name the relay was not told is counted apart and named in the log, once', async (t) => {
  const r = await relay(t);
  const alice = makeIdentity();
  const saved = { authorities: CFG.authorities, logLevel: CFG.logLevel };
  CFG.authorities = [normalizeAuthority('honest.example')];
  CFG.logLevel = 'info';
  const lines = [];
  const realLog = console.log;
  console.log = (...a) => lines.push(a.map(String).join(' '));
  t.after(() => {
    console.log = realLog;
    CFG.authorities = saved.authorities;
    CFG.logLevel = saved.logLevel;
  });
  const tryAuth = async (signed, headers = {}) => {
    const c = await open(r.url, headers);
    const ch = await c.next((f) => f.t === 'challenge');
    c.send({ t: 'auth', v: 2, pub: alice.rawPub.toString('base64'), sig: signV2(alice, signed, Buffer.from(ch.nonce, 'base64')).toString('base64') });
    const res = await c.next((f) => f.t === 'ready' || f.t === 'error');
    c.close();
    return res.t;
  };
  const counts = async () => {
    const body = await get(r.port, '/metrics');
    return { refused: metric(body, 'z_auth_v2_refused_total'), unknown: metric(body, 'z_auth_v2_refused_unknown_name_total') };
  };
  const unknownNameLines = () => lines.filter((l) => l.includes('is not one of this relay\'s names'));

  // The deployment mistake: the list names the bare domain, the client dials
  // www. — signs it, and sends it as Host, as every honest client does.
  const before = await counts();
  assert.strictEqual(await tryAuth('www.honest.example', { Host: 'www.honest.example' }), 'error', 'a name the relay was not told verifies nothing');
  let after = await counts();
  assert.strictEqual(after.refused - before.refused, 1, 'counted as a v2 refusal');
  assert.strictEqual(after.unknown - before.unknown, 1, 'and apart, as a refusal on a name the relay does not know');
  assert.strictEqual(unknownNameLines().length, 1, 'the name is written to the log');
  assert.ok(unknownNameLines()[0].includes('"www.honest.example"'), 'quoted, so the operator reads exactly what clients dial');
  assert.ok(unknownNameLines()[0].includes('RELAY_AUTHORITIES: honest.example'), 'beside the list it is missing from');

  // Again within the hour: counted every time, logged once per name.
  assert.strictEqual(await tryAuth('www.honest.example', { Host: 'www.honest.example' }), 'error');
  after = await counts();
  assert.strictEqual(after.unknown - before.unknown, 2, 'every refusal on the name is counted');
  assert.strictEqual(unknownNameLines().length, 1, 'but the log line is not repeated within the hour');

  // A refusal on a name the relay DOES know is a bad signature — a replay,
  // garbage — and nothing is missing from the list: counted as a refusal,
  // not as an unknown name, and nothing is logged.
  assert.strictEqual(await tryAuth('evil.example', { Host: 'honest.example' }), 'error', 'the splice (criterion 2) is still a refusal');
  const afterReplay = await counts();
  assert.strictEqual(afterReplay.refused - after.refused, 1);
  assert.strictEqual(afterReplay.unknown - after.unknown, 0, 'the presented name is ours: nothing to add to the list');
  assert.strictEqual(unknownNameLines().length, 1, 'and nothing new in the log');

  // The presenter chose the header. The HTTP parser lets no line break or
  // escape byte through, but it does let a tab and bytes above ASCII: those
  // reach the log as JSON escapes, never as themselves, and a long name is
  // cut.
  const nasty = 'www\t.honest.example';
  assert.strictEqual(await tryAuth(nasty, { Host: nasty }), 'error');
  const nastyLines = lines.filter((l) => l.includes('.honest.example"') && l.includes('www\\t'));
  assert.strictEqual(nastyLines.length, 1, 'the name is logged as a JSON string, the tab as \\t');
  assert.ok(!nastyLines[0].includes('\t'), 'the tab itself never reaches the log');
  const long = 'a'.repeat(400) + '.example';
  assert.strictEqual(await tryAuth(long, { Host: long }), 'error');
  const longLine = lines.find((l) => l.includes('"aaaa'));
  assert.ok(longLine && !longLine.includes('a'.repeat(254)), 'cut at 253 characters, the longest host name there is');

  // A known name presented with no Host at all is not an unknown name either.
  assert.strictEqual(await tryAuth('honest.example'), 'ready', 'the configured name still authenticates');
});
