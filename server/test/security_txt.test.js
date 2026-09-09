'use strict';

// RFC 9116 security.txt (14.4).
//
// The commonest reason a vulnerability report never arrives is that there was
// nowhere obvious to send it, so the file has to be served — and it has to
// stay true. `Expires` is the field that rots: it is mandatory, it is a
// promise that somebody is still reading the address above it, and an expired
// one is worse than none because it says the project has stopped paying
// attention while still inviting reports.
//
// So the expiry is a TEST, not a comment. This file fails the build once the
// date passes, which is the only mechanism that reliably survives a
// maintainer's memory.

const test = require('node:test');
const assert = require('node:assert');
const http = require('http');

const { createServer } = require('../server.js');
const { SECURITY_TXT } = require('../pages.js');

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

function field(name) {
  const line = SECURITY_TXT.split('\n').find((l) =>
    l.toLowerCase().startsWith(`${name.toLowerCase()}:`)
  );
  return line ? line.slice(line.indexOf(':') + 1).trim() : null;
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

test('/.well-known/security.txt is served as plain text', async () => {
  const r = await get('/.well-known/security.txt');
  assert.strictEqual(r.status, 200);
  assert.ok(r.type.includes('text/plain'), 'must be text/plain');
  assert.ok(r.body.includes('Contact:'), 'Contact field missing');
});

test('/security.txt serves it too — where people actually look', async () => {
  const r = await get('/security.txt');
  assert.strictEqual(r.status, 200);
  assert.strictEqual(r.body, (await get('/.well-known/security.txt')).body);
});

test('it has the fields RFC 9116 requires', () => {
  assert.ok(field('Contact'), 'Contact is mandatory');
  assert.ok(field('Expires'), 'Expires is mandatory');
  // A policy link is what turns a contact address into a disclosure process:
  // without it a reporter cannot tell whether they are safe to look.
  assert.ok(field('Policy'), 'Policy should point at the VDP');
  assert.ok(field('Canonical'), 'Canonical states where this file belongs');
});

test('Expires is in the future — this test is the anti-rot mechanism', () => {
  const raw = field('Expires');
  const when = new Date(raw);
  assert.ok(!Number.isNaN(when.getTime()), `Expires is not a date: ${raw}`);
  const now = Date.now();
  assert.ok(
    when.getTime() > now,
    `security.txt expired on ${raw}. An expired file invites reports to an ` +
      `address it no longer promises anyone is reading. Refresh the date in ` +
      `server/pages.js — and check the contacts still work while you are there.`
  );
  // RFC 9116 says under a year, and it is right: a five-year expiry is a
  // promise nobody can keep and tells a reporter nothing.
  const year = 366 * 24 * 3600 * 1000;
  assert.ok(
    when.getTime() - now < year,
    `Expires is more than a year out (${raw}). That is not a promise anyone ` +
      `can make about a contact address; RFC 9116 asks for under a year.`
  );
});

test('the contacts are reachable routes, not prose', () => {
  const contacts = SECURITY_TXT.split('\n')
    .filter((l) => l.toLowerCase().startsWith('contact:'))
    .map((l) => l.slice(l.indexOf(':') + 1).trim());
  assert.ok(contacts.length >= 1, 'at least one Contact');
  for (const c of contacts) {
    assert.ok(
      /^(https:\/\/|mailto:|tel:)/.test(c),
      `Contact must be a URI, got: ${c}`
    );
  }
  // Two independent channels, deliberately: a reporter who will not open a
  // GitHub account still has somewhere to go, and an email that bounces does
  // not silence everyone.
  assert.ok(
    contacts.some((c) => c.startsWith('https://')) &&
      contacts.some((c) => c.startsWith('mailto:')),
    'keep both a web and an email contact'
  );
});
