'use strict';

// The relay doubles as the host for zmessengers.com's public pages: the
// landing page at / and the privacy policy at /privacy (Google Play requires a
// public privacy-policy URL). These must be served without touching disk and
// without disturbing /health or the WebSocket endpoint.

const test = require('node:test');
const assert = require('node:assert');
const http = require('http');

const { createServer } = require('../server.js');

let httpServer, port;

function get(path) {
  return new Promise((resolve, reject) => {
    http
      .get(`http://127.0.0.1:${port}${path}`, (res) => {
        let body = '';
        res.on('data', (d) => (body += d));
        res.on('end', () =>
          resolve({
            status: res.statusCode,
            type: res.headers['content-type'],
            body,
          })
        );
      })
      .on('error', reject);
  });
}

test.before(async () => {
  ({ httpServer } = createServer({ pushSender: null }));
  await new Promise((res) => httpServer.listen(0, '127.0.0.1', res));
  port = httpServer.address().port;
});

test.after(async () => {
  if (httpServer.closeAllConnections) httpServer.closeAllConnections();
  await new Promise((res) => httpServer.close(res));
});

test('/ serves the landing page as HTML', async () => {
  const r = await get('/');
  assert.strictEqual(r.status, 200);
  assert.ok(r.type.includes('text/html'));
  assert.ok(r.body.includes('Zero-trust messaging'), 'landing hero missing');
  assert.ok(r.body.includes('/privacy'), 'privacy link missing');
});

test('/privacy serves the privacy policy as HTML', async () => {
  const r = await get('/privacy');
  assert.strictEqual(r.status, 200);
  assert.ok(r.type.includes('text/html'));
  assert.ok(r.body.includes('Privacy policy'), 'title missing');
  assert.ok(r.body.includes('RAM only'), 'RAM-only statement missing');
  assert.ok(r.body.includes('Firebase'), 'push disclosure missing');
});

test('/health still serves relay stats as JSON', async () => {
  const r = await get('/health');
  assert.strictEqual(r.status, 200);
  const j = JSON.parse(r.body);
  assert.strictEqual(j.ok, true);
  assert.strictEqual(j.storage, 'ram-only');
});

test('unknown paths 404 with the plain relay banner', async () => {
  const r = await get('/nope');
  assert.strictEqual(r.status, 404);
  assert.ok(r.body.includes('Z relay'));
});

test('pages are embedded strings — no fs reads in pages.js', async () => {
  const fs = require('fs');
  const src = fs.readFileSync(require.resolve('../pages.js'), 'utf8');
  assert.ok(!src.includes('readFile'), 'pages.js must not read files');
  assert.ok(!src.includes('writeFile'), 'pages.js must not write files');
});
