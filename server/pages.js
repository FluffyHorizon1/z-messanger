'use strict';

// Static pages the relay serves alongside the WebSocket endpoint.
//
// These exist so zmessengers.com can host the public landing page and the
// privacy policy (Google Play requires a public privacy-policy URL) without
// any extra hosting. Everything is an embedded string — no filesystem reads,
// no templating, nothing dynamic — so the relay's zero-disk guarantees are
// untouched.

const STYLE = `
  :root { color-scheme: dark; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    background: #0c0d10; color: #ededed;
    font: 16px/1.6 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  }
  .wrap { max-width: 760px; margin: 0 auto; padding: 48px 24px 64px; }
  .z { color: #ffb300; font-weight: 900; }
  h1 { font-size: 40px; line-height: 1.15; margin: 18px 0 10px; }
  h2 { font-size: 22px; margin: 36px 0 10px; color: #ffb300; }
  p, li { color: #c8cdd6; }
  .muted { color: #9aa0aa; font-size: 14px; }
  a { color: #ffb300; text-decoration: none; }
  a:hover { text-decoration: underline; }
  ul { padding-left: 22px; margin: 10px 0; }
  li { margin: 6px 0; }
  .card {
    background: #15171c; border: 1px solid #23262e; border-radius: 14px;
    padding: 18px 20px; margin: 14px 0;
  }
  .btns { display: flex; flex-wrap: wrap; gap: 12px; margin: 22px 0 8px; }
  .btn {
    display: inline-block; padding: 12px 20px; border-radius: 10px;
    background: #ffb300; color: #000; font-weight: 700;
  }
  .btn.alt { background: #1c1f26; color: #ededed; border: 1px solid #2a2e37; }
  .btn:hover { text-decoration: none; filter: brightness(1.08); }
  code {
    background: #1c1f26; border-radius: 6px; padding: 2px 7px;
    font-size: 14px; color: #ededed;
  }
  footer { margin-top: 48px; border-top: 1px solid #23262e; padding-top: 18px; }
  .logo { font-size: 64px; font-weight: 900; color: #ffb300; line-height: 1; }
`;

const page = (title, body) => `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="Z — zero-trust end-to-end encrypted messenger. No accounts, no phone number, no server storage.">
<title>${title}</title>
<style>${STYLE}</style>
</head>
<body><div class="wrap">${body}</div></body>
</html>`;

const LANDING_HTML = page(
  'Z — zero-trust messenger',
  `
  <div class="logo">Z</div>
  <h1>Zero-trust messaging.</h1>
  <p>No accounts. No phone number. No server storage. Your identity is a
  cryptographic key pair that never leaves your device unencrypted, and every
  message is end-to-end encrypted with a Signal-style double ratchet.</p>

  <div class="btns">
    <a class="btn" href="https://github.com/FluffyHorizon1/z-messanger/releases/latest">Download for Android</a>
    <a class="btn alt" href="https://github.com/FluffyHorizon1/z-messanger/releases/latest">Windows</a>
    <a class="btn alt" href="https://github.com/FluffyHorizon1/z-messanger/releases/latest">Linux</a>
    <a class="btn alt" href="https://github.com/FluffyHorizon1/z-messanger/releases/latest">macOS</a>
  </div>
  <p class="muted">Google Play listing coming soon. Every release ships with
  SHA-256 checksums (<code>SHA256SUMS.txt</code>) so you can verify your
  download.</p>

  <h2>What makes Z different</h2>
  <div class="card"><b>The server knows nothing.</b>
  <p>This relay holds only ciphertext addressed to opaque mailbox IDs, in RAM,
  until delivery — nothing is ever written to disk, and undelivered mail
  expires. A full copy of the server reveals no messages, no names and no
  account list, because none of that exists here.</p></div>
  <div class="card"><b>All your devices, one identity.</b>
  <p>Link your desktop or a second phone by comparing a short safety code.
  Messages and photos sync across your own devices end-to-end encrypted, and
  you can revoke a lost device instantly — your contacts' apps stop trusting
  it the moment they hear.</p></div>
  <div class="card"><b>Verifiable, not just promised.</b>
  <p>Safety numbers let you verify contacts in person. Disappearing messages,
  encrypted attachments, and an encrypted local vault protected by your
  device's keystore. Or run your own relay with one Docker command — the app
  lets you point at any relay you trust.</p></div>

  <h2>Self-host the relay</h2>
  <p>This very page is served by the open Z relay. Run yours:
  <code>docker compose up</code> from the repository's
  <a href="https://github.com/FluffyHorizon1/z-messanger">server/</a>
  directory, then enter its address in the app's developer options.</p>

  <footer class="muted">
    <a href="/privacy">Privacy policy</a> ·
    <a href="https://github.com/FluffyHorizon1/z-messanger">Source on GitHub</a> ·
    relay status: <a href="/health">/health</a>
  </footer>
`
);

const PRIVACY_HTML = page(
  'Z — privacy policy',
  `
  <div class="logo">Z</div>
  <h1>Privacy policy</h1>
  <p class="muted">Effective 25 August 2026 · applies to the Z app and the
  relay service at zmessengers.com</p>

  <p>Z is built so that we <i>cannot</i> know things about you, rather than
  merely promising not to look. This page describes exactly what data exists,
  where it lives, and what the relay operator can and cannot see.</p>

  <h2>What we never collect</h2>
  <ul>
    <li>No accounts, usernames, passwords, phone numbers or email addresses —
    the app has no registration at all.</li>
    <li>No message content: every message and attachment is end-to-end
    encrypted on your device (double-ratchet, forward-secret). The relay can
    never decrypt it and holds no keys.</li>
    <li>No contact lists, address-book access, or social graph on the server —
    contacts exist only inside your device's encrypted vault.</li>
    <li>No analytics, no advertising, no tracking SDKs, no crash reporting.</li>
  </ul>

  <h2>What exists on your device</h2>
  <p>Your identity keys, contacts, messages and attachments are stored only on
  your device, in a vault encrypted with XChaCha20-Poly1305. The vault key
  lives in your operating system's keystore, optionally protected by an app
  passphrase. "Wipe everything" in Settings destroys all of it
  irreversibly.</p>

  <h2>What the relay handles, and for how long</h2>
  <p>To move a message from you to a recipient, the relay momentarily handles:
  ciphertext (undecryptable to it), the opaque mailbox ID it is addressed to
  (a hash, not a key or a name), and the network connection carrying it. Queued
  ciphertext for offline recipients is held <b>in RAM only</b>, is deleted the
  moment the recipient confirms delivery, and expires after at most 72 hours.
  The relay writes nothing to disk — its code is tested to contain no
  disk-write calls — so restarting it erases everything it held. Operational
  logs contain aggregate connection counts only, never message data.</p>

  <h2>Push notifications (optional, Android)</h2>
  <p>If you enable push, the app registers an opaque Firebase Cloud Messaging
  token with the relay so it can send a <b>content-free wake signal</b> ("you
  have mail") when a message arrives while the app is closed. The notification
  contains no message content and no sender. The token is held in relay RAM
  with a 30-day expiry and is deleted when you disable push. Delivery of the
  wake signal is performed by Google Firebase under
  <a href="https://firebase.google.com/support/privacy">Google's privacy
  terms</a>; Google never receives message content. With push off, none of
  this exists.</p>

  <h2>What the operator could technically observe</h2>
  <p>Honesty requires stating this: like any server on the internet, a running
  relay can transiently observe connection metadata — the IP address of a
  connection and the timing and size of encrypted envelopes passing through
  RAM. Z does not record, store, or analyse this, and its RAM-only design means
  there is no historical record to hand over: a subpoena for stored data would
  yield nothing, because nothing is stored. Reducing even transient metadata
  further (sealed sender, size padding) is on the public roadmap.</p>

  <h2>Your choices</h2>
  <ul>
    <li>Use the app fully without push — it is optional.</li>
    <li>Point the app at your own self-hosted relay (Settings → Developer
    mode) so no traffic touches ours.</li>
    <li>Delete everything at any time with Settings → Wipe everything. There is
    nothing server-side to request deletion of.</li>
  </ul>

  <h2>Children</h2>
  <p>Z is not directed at children under 13, and we do not knowingly collect
  information from anyone — child or adult.</p>

  <h2>Changes & contact</h2>
  <p>Material changes to this policy will be published at this address with an
  updated effective date. Questions:
  <a href="mailto:finnianbond@gmail.com">finnianbond@gmail.com</a>.</p>

  <footer class="muted"><a href="/">← zmessengers.com</a></footer>
`
);

module.exports = { LANDING_HTML, PRIVACY_HTML };
