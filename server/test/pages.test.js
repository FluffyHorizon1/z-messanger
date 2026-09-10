'use strict';

// The relay doubles as the host for zmessengers.com's public pages: the
// landing page, the privacy policy (Google Play requires a public
// privacy-policy URL) and the pages the search ads link to. These must be
// served without touching disk and without disturbing /health or the
// WebSocket endpoint.
//
// Two failure modes are specifically guarded here. A sitelink pointing at a
// path the relay does not answer is an ad disapproval, so every listed page
// and every internal link is fetched. And the site's palette is the app's
// palette — it is checked against app/lib/ui/theme.dart so the two cannot
// drift apart silently.

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
  // Assert the hero exists, not its wording — copy changes should not fail
  // this, but a landing page that lost its headline should.
  assert.ok(/<h1>[^<]{20,}<\/h1>/.test(r.body), 'landing hero missing');
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

const { PAGES, ROUTES, STYLE } = require('../pages.js');

test('every page in the site list is served as HTML, with nav and footer', async () => {
  for (const [path, label] of PAGES) {
    const r = await get(path);
    assert.strictEqual(r.status, 200, `${path} (${label}) did not serve`);
    assert.ok(r.type.includes('text/html'), `${path} is not HTML`);
    assert.ok(r.body.includes('<nav>'), `${path} has no nav`);
    assert.ok(r.body.includes('<footer>'), `${path} has no footer`);
    assert.ok(
      r.body.includes(`<link rel="canonical" href="https://zmessengers.com${path}">`),
      `${path} has no canonical URL`
    );
    assert.ok(/<meta name="description" content="[^"]{40,}">/.test(r.body),
      `${path} has no usable meta description`);
  }
});

test('trailing-slash forms answer too (a sitelink must not 404 on a slash)', async () => {
  for (const [path] of PAGES) {
    const r = await get(`${path}/`);
    assert.strictEqual(r.status, 200, `${path}/ did not serve`);
  }
});

test('every internal link on every page resolves to a served route', async () => {
  const seen = new Set();
  for (const [path] of [['/'], ...PAGES]) {
    const r = await get(path);
    for (const m of r.body.matchAll(/href="(\/[^"#]*)"/g)) {
      const target = m[1];
      if (seen.has(target)) continue;
      seen.add(target);
      const hit = await get(target);
      assert.strictEqual(hit.status, 200, `${path} links to ${target}, which is ${hit.status}`);
    }
  }
  assert.ok(seen.size >= PAGES.length, 'suspiciously few internal links checked');
});

test('the site palette is the app palette (app/lib/ui/theme.dart)', () => {
  const fs = require('fs');
  const path = require('path');
  const themePath = path.join(__dirname, '..', '..', 'app', 'lib', 'ui', 'theme.dart');
  const theme = fs.readFileSync(themePath, 'utf8');
  // Both palettes appear in theme.dart in order: dark first, then light.
  const tokenPairs = (name) =>
    [...theme.matchAll(new RegExp(`${name}: Color\\(0xFF([0-9A-Fa-f]{6})\\)`, 'g'))].map(
      (m) => `#${m[1].toUpperCase()}`
    );
  const checks = [
    ['bg', '--bg'], ['surface', '--surface'], ['surfaceAlt', '--surface-alt'],
    ['accent', '--accent'], ['onAccent', '--on-accent'],
    ['textPrimary', '--text'], ['textSecondary', '--text-dim'],
    ['divider', '--divider'], ['ok', '--ok'], ['warn', '--warn'], ['danger', '--danger'],
  ];
  const cssValues = (v) =>
    [...STYLE.matchAll(new RegExp(`${v}: (#[0-9A-Fa-f]{6});`, 'g'))].map((m) =>
      m[1].toUpperCase()
    );
  for (const [dartName, cssVar] of checks) {
    const fromDart = tokenPairs(dartName);
    const fromCss = cssValues(cssVar);
    assert.strictEqual(fromDart.length, 2, `${dartName}: expected dark + light in theme.dart`);
    assert.strictEqual(fromCss.length, 2, `${cssVar}: expected dark + light in the stylesheet`);
    assert.deepStrictEqual(fromCss, fromDart, `${cssVar} does not match theme.dart ${dartName}`);
  }
});

test('the stylesheet follows the system colour scheme', async () => {
  const r = await get('/');
  assert.ok(r.body.includes('color-scheme: dark light'), 'color-scheme not declared');
  assert.ok(
    r.body.includes('@media (prefers-color-scheme: light)'),
    'no light-scheme block'
  );
  assert.ok(
    r.body.includes('<meta name="theme-color" media="(prefers-color-scheme: light)"'),
    'no light theme-color'
  );
});

test('the browser chrome colour matches the palette too', async () => {
  const r = await get('/');
  // These are hardcoded in the <head> rather than read from the CSS variables,
  // so the palette test above does not cover them — and they were left on the
  // previous brand when the app rebranded.
  const bgDark = /--bg: (#[0-9A-Fa-f]{6});/.exec(STYLE)[1];
  const bgLight = /--bg: (#[0-9A-Fa-f]{6});/g;
  const both = [...STYLE.matchAll(/--bg: (#[0-9A-Fa-f]{6});/g)].map((m) => m[1]);
  assert.strictEqual(both.length, 2, 'expected a dark and a light --bg');
  assert.ok(
    r.body.includes(`<meta name="theme-color" media="(prefers-color-scheme: dark)" content="${both[0]}">`),
    `dark theme-color does not match --bg ${both[0]}`
  );
  assert.ok(
    r.body.includes(`<meta name="theme-color" media="(prefers-color-scheme: light)" content="${both[1]}">`),
    `light theme-color does not match --bg ${both[1]}`
  );
});

test('the site does not claim an audit it has not had', async () => {
  const r = await get('/security');
  assert.ok(/not yet<\/b> had an external security audit/.test(r.body),
    'the security page must state the audit status plainly');
});

test('the download page routes Android to the live Play listing', async () => {
  const r = await get('/download');
  assert.ok(
    r.body.includes('https://play.google.com/store/apps/details?id=com.zmessenger.www'),
    'no link to the Play listing'
  );
  assert.ok(
    /trademarks of\s+Google LLC/.test(r.body),
    'Play trademark attribution missing'
  );
  assert.ok(
    !/in preparation|coming soon/i.test(r.body),
    'the page still says the listing is pending'
  );
  // The APK stays reachable: Play is a route to the app, not the only one.
  assert.ok(r.body.includes('releases/latest'), 'direct download removed');
});

test('no page claims the Play listing is still pending', async () => {
  for (const [path] of [['/'], ...PAGES]) {
    const r = await get(path);
    assert.ok(
      !/(Play listing|listing) is in preparation|Play listing coming soon/i.test(r.body),
      `${path} still describes Play as pending`
    );
  }
});

test('every repository document the site links to actually exists', () => {
  const fs = require('fs');
  const path = require('path');
  const root = path.join(__dirname, '..', '..');
  const linked = new Set();
  for (const [, html] of ROUTES) {
    for (const m of html.matchAll(/href="[^"]*\/blob\/main\/([^"]+)"/g)) linked.add(m[1]);
  }
  assert.ok(linked.size > 0, 'no repository documents linked — did the links change shape?');
  for (const rel of linked) {
    assert.ok(fs.existsSync(path.join(root, rel)), `the site links to ${rel}, which is not in the repo`);
  }
});

test('nothing the site serves carries a personal address', async () => {
  // The public contact is the company support address on the Play listing,
  // not anyone's personal mailbox. This covers the pages and security.txt.
  for (const [path] of [['/'], ...PAGES]) {
    const r = await get(path);
    assert.ok(
      !/finnianbond|@gmail\.com/i.test(r.body),
      `${path} carries a personal address`
    );
  }
  const sec = await get('/.well-known/security.txt');
  assert.ok(!/finnianbond|@gmail\.com/i.test(sec.body), 'security.txt carries a personal address');
  assert.ok(
    sec.body.includes('mailto:support@securedcybersolutions.co.uk'),
    'security.txt lost its support contact'
  );
});

test('the tab icon is served in both formats, and every page points at it', async () => {
  const svg = await get('/favicon.svg');
  assert.strictEqual(svg.status, 200);
  assert.ok(svg.type.includes('image/svg+xml'), `favicon.svg served as ${svg.type}`);
  assert.ok(svg.body.includes('<svg'), 'favicon.svg is not SVG');

  const ico = await get('/favicon.ico');
  assert.strictEqual(ico.status, 200, 'browsers request /favicon.ico whether or not it is linked');
  assert.ok(ico.type.includes('image/x-icon'), `favicon.ico served as ${ico.type}`);

  for (const [path] of [['/'], ...PAGES]) {
    const r = await get(path);
    assert.ok(
      r.body.includes('<link rel="icon" href="/favicon.svg"'),
      `${path} has no tab icon`
    );
  }
});

test('pages are embedded strings — no fs reads in pages.js', async () => {
  const fs = require('fs');
  const src = fs.readFileSync(require.resolve('../pages.js'), 'utf8');
  assert.ok(!src.includes('readFile'), 'pages.js must not read files');
  assert.ok(!src.includes('writeFile'), 'pages.js must not write files');
});
