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

// Every path that serves a full page, including the ones deliberately absent
// from PAGES (and therefore from the nav and footer): /i is reached from an
// invite link, never by browsing, but it is still a public page and the
// site-wide sweeps below must cover it.
const UNLISTED = ['/i'];
const ALL_PAGES = ['/', ...PAGES.map(([path]) => path), ...UNLISTED];

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
  for (const path of ALL_PAGES) {
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
  for (const path of ALL_PAGES) {
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
  for (const path of ALL_PAGES) {
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

  for (const path of ALL_PAGES) {
    const r = await get(path);
    assert.ok(
      r.body.includes('<link rel="icon" href="/favicon.svg"'),
      `${path} has no tab icon`
    );
  }
});

// ---------------------------------------------------------------------------
// 17.3b — Digital Asset Links, so an invite link opens the app rather than a
// chooser. The fingerprint is not in this repository: it belongs to the Play
// App Signing key, which only the account holder can read out of the Play
// Console, so it arrives as ANDROID_CERT_SHA256. Everything about the shape
// of the answer is testable without knowing the value.

const { androidAssetLinks } = require('../pages.js');
const FAKE_PRINT = new Array(32).fill('AB').join(':');

test('assetlinks: nothing is claimed until a fingerprint is configured',
  async () => {
    delete process.env.ANDROID_CERT_SHA256;
    const r = await get('/.well-known/assetlinks.json');
    assert.strictEqual(r.status, 404,
      'an unverifiable claim about which app owns these links is worse than none');
    assert.strictEqual(androidAssetLinks(undefined), null);
    assert.strictEqual(androidAssetLinks(''), null);
    // Anything that is not a 32-byte colon-separated hex fingerprint is not
    // one, and half a file is worse than no file: Android rejects the lot.
    for (const junk of ['not a fingerprint', 'AA:BB', FAKE_PRINT.slice(0, -1)]) {
      assert.strictEqual(androidAssetLinks(junk), null, junk);
    }
  });

test('assetlinks: with a fingerprint it is the file Android expects',
  async () => {
    process.env.ANDROID_CERT_SHA256 = FAKE_PRINT.toLowerCase();
    try {
      const r = await get('/.well-known/assetlinks.json');
      assert.strictEqual(r.status, 200);
      assert.ok(r.type.includes('application/json'), `served as ${r.type}`);
      const j = JSON.parse(r.body);
      assert.ok(Array.isArray(j) && j.length === 1);
      assert.deepStrictEqual(j[0].relation,
        ['delegate_permission/common.handle_all_urls']);
      assert.strictEqual(j[0].target.namespace, 'android_app');
      assert.strictEqual(j[0].target.package_name, 'com.zmessenger.www');
      // Upper case, as Android publishes it, whatever case it was configured in.
      assert.deepStrictEqual(j[0].target.sha256_cert_fingerprints, [FAKE_PRINT]);

      // A key rotation needs both listed at once, or every install on the old
      // key stops verifying the day the new one ships.
      const other = new Array(32).fill('CD').join(':');
      const two = JSON.parse(androidAssetLinks(`${FAKE_PRINT}, ${other}`));
      assert.deepStrictEqual(two[0].target.sha256_cert_fingerprints,
        [FAKE_PRINT, other]);
    } finally {
      delete process.env.ANDROID_CERT_SHA256;
    }
  });

const { latestJson } = require('../pages.js');

test('/latest.json is not served until a version is configured (24.4)',
  async () => {
    delete process.env.Z_LATEST_VERSION;
    const r = await get('/latest.json');
    assert.strictEqual(r.status, 404,
      'an unset version is no claim, not a claim of 0');
    assert.strictEqual(latestJson(undefined), null);
    assert.strictEqual(latestJson(''), null);
    // A string that is not a plain semver is treated as unset, so a typo
    // cannot ship a junk "latest" to every client.
    for (const junk of ['latest', 'v3.7.0', '3.7', 'three.seven', '3.7.0.1']) {
      assert.strictEqual(latestJson(junk), null, junk);
    }
  });

test('/latest.json with a version is the file the client expects (24.4)',
  async () => {
    process.env.Z_LATEST_VERSION = '3.7.0';
    try {
      const r = await get('/latest.json');
      assert.strictEqual(r.status, 200);
      assert.ok(r.type.includes('application/json'), `served as ${r.type}`);
      const j = JSON.parse(r.body);
      assert.strictEqual(j.version, '3.7.0');
      assert.ok(/\/releases\/latest$/.test(j.url), `url was ${j.url}`);
      // Two keys and nothing else: the body names no user, no routing id,
      // no per-request anything — it is the same file for everyone.
      assert.deepStrictEqual(Object.keys(j).sort(), ['url', 'version']);
    } finally {
      delete process.env.Z_LATEST_VERSION;
    }
  });

test('assetlinks: the app link it authorises is the one the manifest claims',
  () => {
    // Two files, one claim, in different languages and different repositories'
    // worth of tooling. If they drift, the link silently opens a chooser.
    const fs = require('fs');
    const path = require('path');
    const manifest = fs.readFileSync(
      path.join(__dirname, '..', '..', 'app', 'android', 'app', 'src', 'main',
        'AndroidManifest.xml'),
      'utf8'
    );
    assert.ok(manifest.includes('android:host="zmessengers.com"'),
      'the manifest does not claim zmessengers.com');
    assert.ok(manifest.includes('android:pathPrefix="/i"'),
      'the manifest does not claim /i');
    assert.ok(manifest.includes('android:autoVerify="true"'),
      'without autoVerify the assetlinks file is never fetched');
    const pkg = JSON.parse(androidAssetLinks(FAKE_PRINT))[0].target.package_name;
    assert.ok(manifest.includes(`package="${pkg}"`) ||
      fs.readFileSync(
        path.join(__dirname, '..', '..', 'app', 'android', 'app', 'build.gradle.kts'),
        'utf8').includes(pkg),
      `nothing in the Android build declares ${pkg}`);
  });

test('pages are embedded strings — no fs reads in pages.js', async () => {
  const fs = require('fs');
  const src = fs.readFileSync(require.resolve('../pages.js'), 'utf8');
  assert.ok(!src.includes('readFile'), 'pages.js must not read files');
  assert.ok(!src.includes('writeFile'), 'pages.js must not write files');
});

// ---------------------------------------------------------------------------
// 17.4 — the page an invite link lands on when Z is not installed yet.
//
// The invite is the part of the link after the `#`, which no browser sends to
// a server. That is the whole reason this page can exist without weakening
// anything: it is served identically to everyone and cannot know an invite
// exists. Three criteria from the phase plan, one test each.

const PLAY_URL = 'https://play.google.com/store/apps/details?id=com.zmessenger.www';

test('17.4 (1): /i and /i/ both serve the invite page, like every other route',
  async () => {
    for (const path of ['/i', '/i/']) {
      const r = await get(path);
      assert.strictEqual(r.status, 200, `${path} did not serve`);
      assert.ok(r.type.includes('text/html'), `${path} is not HTML`);
      assert.ok(/<h1>[^<]{20,}<\/h1>/.test(r.body), `${path} has no headline`);
      assert.ok(r.body.includes('<nav>'), `${path} has no nav`);
      assert.ok(r.body.includes('<footer>'), `${path} has no footer`);
      assert.ok(/<meta name="description" content="[^"]{40,}">/.test(r.body),
        `${path} has no usable meta description`);
    }
    // Both forms are the same page, and the canonical points at the bare one
    // so a shared invite link cannot split its own indexing.
    const bare = await get('/i');
    const slashed = await get('/i/');
    assert.strictEqual(slashed.body, bare.body);
    assert.ok(
      bare.body.includes('<link rel="canonical" href="https://zmessengers.com/i">'),
      'no canonical URL'
    );
  });

test('17.4 (2): nothing on the site can read an invite fragment, and the relay never reflects one',
  async () => {
    // No page has a script, so no page can read location.hash — asserted over
    // every route rather than just /i, because the guarantee is only worth
    // having if it cannot be lost by someone adding a script elsewhere later.
    for (const [path, html] of ROUTES) {
      assert.ok(!/<script/i.test(html), `${path} has a script tag`);
      assert.ok(!/\son[a-z]+=/i.test(html), `${path} has an inline event handler`);
      assert.ok(!/javascript:/i.test(html), `${path} has a javascript: URL`);
      assert.ok(
        !/location\.hash|document\.location|window\.location/i.test(html),
        `${path} mentions the location object`
      );
    }
    // And nothing about a request comes back in a response, so a fragment
    // forged into the path by hand — the one way it could reach the relay at
    // all — is not echoed into a page, a header or an error.
    for (const forged of ['/i%23SECRETCODE', '/i?c=SECRETCODE', '/SECRETCODE']) {
      const r = await get(forged);
      assert.ok(!r.body.includes('SECRETCODE'), `${forged} was reflected in the body`);
    }
    const missed = await get('/i%23SECRETCODE');
    assert.strictEqual(missed.status, 404);
    assert.strictEqual(
      missed.body,
      'Z relay. Zero-knowledge, RAM-only. Connect via WebSocket.\n',
      'the 404 body must be a constant: anything built from the request could carry an invite'
    );
  });

test('17.4 (3): the invite page links to Play and to how-it-works, and the route text stays unique',
  async () => {
    const r = await get('/i');
    assert.ok(r.body.includes(PLAY_URL), 'no link to the Play listing');
    assert.ok(r.body.includes('href="/how-it-works"'), 'no link to how-it-works');
    assert.ok(/trademarks of Google\s+LLC/.test(r.body),
      'Play trademark attribution missing');

    // Google Ads refuses two sitelinks with the same text, and the nav and
    // footer are generated from PAGES — so a duplicate label or path there is
    // an ad disapproval waiting to happen.
    const labels = PAGES.map(([, label]) => label);
    const paths = PAGES.map(([path]) => path);
    assert.strictEqual(new Set(labels).size, labels.length, 'duplicate route text in PAGES');
    assert.strictEqual(new Set(paths).size, paths.length, 'duplicate route path in PAGES');

    // /i is not one of them: an invite is something you were sent, not a place
    // to browse to, and a sitelink pointing at it would be meaningless.
    assert.ok(!paths.includes('/i'), '/i must not be in the site navigation');
    for (const path of ['/', ...paths]) {
      const page = await get(path);
      assert.ok(!page.body.includes('href="/i"'), `${path} links to /i`);
    }
  });
