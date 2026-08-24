'use strict';

// Push wiring tests. A fake PushSender is injected via createServer({pushSender}),
// so these run with no network and no real Firebase credentials. The last test
// exercises the real PushSender request-building with a mocked fetch.

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const net = require('net');
const WebSocket = require('ws');

const { createServer, routingIdFromPub, PushSender } = require('../server.js');

const AUTH_CONTEXT = Buffer.from('z-relay-auth-v1:', 'utf8');

function makeIdentity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const rawPub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  return { publicKey, privateKey, rawPub, rid: routingIdFromPub(rawPub) };
}

function freePort() {
  return new Promise((res, rej) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const p = srv.address().port;
      srv.close(() => res(p));
    });
    srv.on('error', rej);
  });
}

class Client {
  constructor(port, identity) {
    this.frames = [];
    this.waiters = [];
    this.ws = new WebSocket(`ws://127.0.0.1:${port}`);
    this.ws.on('message', (d) => {
      const f = JSON.parse(d.toString());
      if (f.t === 'challenge') {
        const nonce = Buffer.from(f.nonce, 'base64');
        const sig = crypto.sign(null, Buffer.concat([AUTH_CONTEXT, nonce]), identity.privateKey);
        this.ws.send(
          JSON.stringify({ t: 'auth', pub: identity.rawPub.toString('base64'), sig: sig.toString('base64') })
        );
      }
      this.frames.push(f);
      for (const w of this.waiters.splice(0)) w();
    });
  }
  async waitFor(pred, ms = 5000) {
    const start = Date.now();
    while (Date.now() - start < ms) {
      const hit = this.frames.find(pred);
      if (hit) return hit;
      await new Promise((r) => {
        this.waiters.push(r);
        setTimeout(r, 100);
      });
    }
    throw new Error('timeout waiting for frame');
  }
  send(obj) {
    this.ws.send(JSON.stringify(obj));
  }
  close() {
    this.ws.close();
  }
}

function startServer(port, pushSender) {
  const { httpServer } = createServer({ pushSender });
  return new Promise((res) => httpServer.listen(port, '127.0.0.1', () => res(httpServer)));
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

test('offline recipient with a registered token gets exactly one wake ping', async () => {
  const port = await freePort();
  const calls = [];
  const fakePush = {
    sendWake: async (token) => {
      calls.push(token);
      return { ok: true, status: 200, retiredToken: false };
    },
  };
  const httpServer = await startServer(port, fakePush);
  try {
    const alice = makeIdentity();
    const bob = makeIdentity();

    const a = new Client(port, alice);
    await a.waitFor((f) => f.t === 'ready');

    const b = new Client(port, bob);
    await b.waitFor((f) => f.t === 'ready');
    b.send({ t: 'push-register', token: 'FCM_BOB_TOKEN', platform: 'android' });
    await b.waitFor((f) => f.t === 'push-ok');

    b.close(); // Bob goes offline; token stays registered.
    await sleep(300);

    a.send({ t: 'send', to: bob.rid, id: 'm1', payload: 'opaque-ciphertext' });
    await a.waitFor((f) => f.t === 'sent' && f.id === 'm1');
    await sleep(300); // let the non-blocking push fire

    assert.deepStrictEqual(calls, ['FCM_BOB_TOKEN']);
    a.close();
  } finally {
    httpServer.close();
  }
});

test('no wake ping when the recipient is online (delivered live)', async () => {
  const port = await freePort();
  const calls = [];
  const fakePush = { sendWake: async (t) => (calls.push(t), { ok: true, status: 200 }) };
  const httpServer = await startServer(port, fakePush);
  try {
    const alice = makeIdentity();
    const bob = makeIdentity();
    const a = new Client(port, alice);
    await a.waitFor((f) => f.t === 'ready');
    const b = new Client(port, bob);
    await b.waitFor((f) => f.t === 'ready');
    b.send({ t: 'push-register', token: 'TOK', platform: 'android' });
    await b.waitFor((f) => f.t === 'push-ok');

    a.send({ t: 'send', to: bob.rid, id: 'm2', payload: 'x' });
    await b.waitFor((f) => f.t === 'msg' && f.id === 'm2');
    await sleep(200);
    assert.strictEqual(calls.length, 0, 'online recipient must not trigger a push');
    a.close();
    b.close();
  } finally {
    httpServer.close();
  }
});

test('PushSender builds a valid, content-free FCM v1 request (mocked fetch)', async () => {
  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const sa = {
    client_email: 'svc@z.iam.gserviceaccount.com',
    private_key: pem,
    project_id: 'z-test-123',
  };

  const seen = {};
  const fetchImpl = async (url, opts) => {
    if (url === 'https://oauth2.googleapis.com/token') {
      seen.tokenBody = opts.body;
      return { ok: true, status: 200, json: async () => ({ access_token: 'ya29.fake', expires_in: 3600 }) };
    }
    seen.fcm = { url, headers: opts.headers, body: JSON.parse(opts.body) };
    return { ok: true, status: 200, json: async () => ({ name: 'projects/z-test-123/messages/1' }) };
  };

  const ps = new PushSender(sa, { fetchImpl });
  const r = await ps.sendWake('DEVICE_TOKEN_XYZ');

  assert.strictEqual(r.ok, true);
  assert.match(seen.tokenBody, /grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer/);
  assert.strictEqual(seen.fcm.url, 'https://fcm.googleapis.com/v1/projects/z-test-123/messages:send');
  assert.match(seen.fcm.headers.authorization, /^Bearer ya29\.fake$/);
  assert.strictEqual(seen.fcm.body.message.token, 'DEVICE_TOKEN_XYZ');
  assert.deepStrictEqual(seen.fcm.body.message.data, { type: 'z-wake' });
  assert.ok(!seen.fcm.body.message.notification, 'must be data-only (no notification/content)');
});

test('a dead token (FCM 404) is reported for retirement', async () => {
  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const sa = { client_email: 'svc@z.iam', private_key: pem, project_id: 'p' };
  const fetchImpl = async (url) =>
    url.endsWith('/token')
      ? { ok: true, status: 200, json: async () => ({ access_token: 't', expires_in: 3600 }) }
      : { ok: false, status: 404, json: async () => ({}) };
  const ps = new PushSender(sa, { fetchImpl });
  const r = await ps.sendWake('DEAD');
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.retiredToken, true);
});
