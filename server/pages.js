'use strict';

// Static pages the relay serves alongside the WebSocket endpoint.
//
// These exist so zmessengers.com can host the public site — landing page,
// privacy policy (Google Play requires a public privacy-policy URL) and the
// pages the ad sitelinks point at — without any extra hosting. Everything is
// an embedded string: no filesystem reads, no templating, nothing dynamic, so
// the relay's zero-disk guarantee is untouched.
//
// COLOURS: the custom properties below are the app's own palettes, copied
// from app/lib/ui/theme.dart. Both are WCAG AA verified by app/tool/contrast.py
// and server/test/pages.test.js fails if the two ever drift apart, so the site
// cannot quietly stop matching the product.

const STYLE = `
  :root {
    color-scheme: dark light;
    --bg: #0C0D10; --surface: #15171C; --surface-alt: #1C1F26;
    --accent: #FFB300; --on-accent: #000000;
    --text: #EDEDED; --text-dim: #9AA0AA; --divider: #23262E;
    --ok: #46A758; --warn: #F5A623; --danger: #F05A5F;
  }
  @media (prefers-color-scheme: light) {
    :root {
      --bg: #F7F7F4; --surface: #FFFFFF; --surface-alt: #EEEEEA;
      --accent: #935C00; --on-accent: #FFFFFF;
      --text: #1B1C1F; --text-dim: #5C6370; --divider: #E1E2E6;
      --ok: #2A742E; --warn: #9A5B00; --danger: #C1272D;
    }
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    background: var(--bg); color: var(--text);
    font: 16px/1.65 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    -webkit-font-smoothing: antialiased;
  }
  .wrap { max-width: 780px; margin: 0 auto; padding: 28px 24px 64px; }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
  nav {
    display: flex; align-items: center; flex-wrap: wrap; gap: 6px 18px;
    padding-bottom: 20px; border-bottom: 1px solid var(--divider);
  }
  nav .mark {
    font-weight: 900; font-size: 26px; color: var(--accent);
    letter-spacing: -1px; margin-right: 6px;
  }
  nav a { color: var(--text-dim); font-size: 14px; }
  nav a:hover, nav a[aria-current] { color: var(--accent); }
  h1 { font-size: 38px; line-height: 1.15; margin: 26px 0 12px; letter-spacing: -0.5px; }
  h2 { font-size: 22px; margin: 34px 0 10px; color: var(--accent); }
  h3 { font-size: 17px; margin: 20px 0 6px; }
  p, li { color: var(--text-dim); }
  p { margin: 10px 0; }
  .lead { font-size: 18px; color: var(--text); }
  .muted { color: var(--text-dim); font-size: 14px; }
  ul { padding-left: 22px; margin: 10px 0; }
  li { margin: 7px 0; }
  b, strong { color: var(--text); }
  .card {
    background: var(--surface); border: 1px solid var(--divider);
    border-radius: 14px; padding: 18px 20px; margin: 14px 0;
  }
  .card h3 { margin-top: 0; }
  .grid { display: grid; gap: 14px; }
  @media (min-width: 640px) { .grid.two { grid-template-columns: 1fr 1fr; } }
  .btns { display: flex; flex-wrap: wrap; gap: 12px; margin: 22px 0 8px; }
  .btn {
    display: inline-block; padding: 12px 20px; border-radius: 10px;
    background: var(--accent); color: var(--on-accent); font-weight: 700;
  }
  .btn.alt {
    background: var(--surface-alt); color: var(--text);
    border: 1px solid var(--divider);
  }
  .btn:hover { text-decoration: none; filter: brightness(1.08); }
  code {
    background: var(--surface-alt); border-radius: 6px; padding: 2px 7px;
    font-size: 14px; color: var(--text);
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  pre {
    background: var(--surface-alt); border: 1px solid var(--divider);
    border-radius: 10px; padding: 14px 16px; margin: 12px 0;
    overflow-x: auto; font-size: 14px;
  }
  pre code { background: none; padding: 0; }
  .steps { counter-reset: s; list-style: none; padding-left: 0; }
  .steps li {
    counter-increment: s; position: relative; padding-left: 40px; margin: 14px 0;
  }
  .steps li::before {
    content: counter(s); position: absolute; left: 0; top: 1px;
    width: 26px; height: 26px; border-radius: 50%;
    background: var(--accent); color: var(--on-accent);
    font-weight: 700; font-size: 14px; text-align: center; line-height: 26px;
  }
  .yes::before, .no::before { font-weight: 700; margin-right: 8px; }
  .yes::before { content: "✓"; color: var(--ok); }
  .no::before  { content: "✕"; color: var(--danger); }
  .note {
    border-left: 3px solid var(--warn); background: var(--surface);
    padding: 12px 16px; margin: 16px 0; border-radius: 0 10px 10px 0;
  }
  footer { margin-top: 52px; border-top: 1px solid var(--divider); padding-top: 20px; }
  footer .cols { display: flex; flex-wrap: wrap; gap: 8px 22px; margin-bottom: 14px; }
  footer a { font-size: 14px; }
  .logo { font-size: 60px; font-weight: 900; color: var(--accent); line-height: 1; letter-spacing: -3px; }
`;

const RELEASES = 'https://github.com/FluffyHorizon1/z-messanger/releases/latest';
const PLAY = 'https://play.google.com/store/apps/details?id=com.zmessenger.www';
const REPO = 'https://github.com/FluffyHorizon1/z-messanger';

// Every page that is served. The footer is generated from this list, so a page
// can never be added without becoming reachable, and the ad sitelinks can never
// point at a path the relay does not answer.
const PAGES = [
  ['/how-it-works', 'How it works'],
  ['/privacy', 'Privacy'],
  ['/download', 'Download'],
  ['/security', 'Security'],
  ['/verify', 'Verify contacts'],
  ['/features', 'Features'],
  ['/self-host', 'Self-host'],
  ['/devices', 'Devices'],
  ['/backup', 'Backup'],
  ['/about', 'About'],
];

const nav = (here) =>
  `<nav><a class="mark" href="/" aria-label="Z home">Z</a>` +
  PAGES.slice(0, 6)
    .map(
      ([href, label]) =>
        `<a href="${href}"${here === href ? ' aria-current="page"' : ''}>${label}</a>`
    )
    .join('') +
  `</nav>`;

const footer = () =>
  `<footer><div class="cols">` +
  PAGES.map(([href, label]) => `<a href="${href}">${label}</a>`).join('') +
  `</div><p class="muted">Z is made by Secured Cyber Solutions in London. ` +
  `<a href="${REPO}">Source on GitHub</a> · relay status <a href="/health">/health</a></p></footer>`;

const page = (path, title, description, body) => `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="${description}">
<meta name="theme-color" media="(prefers-color-scheme: dark)" content="#0C0D10">
<meta name="theme-color" media="(prefers-color-scheme: light)" content="#F7F7F4">
<link rel="canonical" href="https://zmessengers.com${path === '/' ? '/' : path}">
<meta property="og:title" content="${title}">
<meta property="og:description" content="${description}">
<meta property="og:type" content="website">
<title>${title}</title>
<style>${STYLE}</style>
</head>
<body><div class="wrap">${nav(path)}${body}${footer()}</div></body>
</html>`;

// ---------------------------------------------------------------------------

const LANDING_HTML = page(
  '/',
  'Z — zero-trust messenger',
  'Zero-trust end-to-end encrypted messenger. No accounts, no phone number, no server storage.',
  `
  <div class="logo">Z</div>
  <h1>Zero-trust messaging.</h1>
  <p class="lead">No accounts. No phone number. No server storage. Your identity
  is a key pair made on your device that never leaves it unencrypted, and every
  message is end-to-end encrypted with a Signal-style double ratchet.</p>

  <div class="btns">
    <a class="btn" href="/download">Download for Android</a>
    <a class="btn alt" href="/how-it-works">How it works</a>
  </div>
  <p class="muted">On <a href="${PLAY}">Google Play</a>, and as a direct
  download for Android, Windows, macOS and Linux. Every release ships SHA-256
  checksums so you can verify what you downloaded.</p>

  <h2>What makes Z different</h2>
  <div class="grid two">
    <div class="card"><h3>The server knows nothing</h3>
    <p>The relay holds ciphertext addressed to opaque mailbox IDs, in RAM, until
    delivery. It never learns who sent a message, never writes to disk, and
    keeps no account list — because none exists. A full copy of the server
    reveals no messages and no names.</p></div>

    <div class="card"><h3>Verifiable, not just promised</h3>
    <p>The protocol is published in full, pinned by test vectors that three
    independent implementations reproduce on every change. You can check the
    claims rather than take them.</p></div>

    <div class="card"><h3>Ready for quantum</h3>
    <p>Key agreement is hybrid: classical X25519 combined with ML-KEM-768, so
    traffic captured today cannot be unlocked by a future quantum computer.
    Identities are moving to hybrid signatures the same way.</p></div>

    <div class="card"><h3>Your devices, one identity</h3>
    <p>Link a laptop to your phone by comparing a short code. Both send and
    receive, history syncs end-to-end encrypted, and a lost device can be
    revoked — your contacts stop trusting it the moment they hear.</p></div>
  </div>

  <h2>What we don't collect</h2>
  <ul>
    <li class="no">No phone number, email address or username — there is no sign-up.</li>
    <li class="no">No contact list on the server, and no access to your address book.</li>
    <li class="no">No analytics, no advertising SDKs, no crash reporting.</li>
    <li class="yes">Only ciphertext, briefly, in memory. <a href="/privacy">Read the full data map</a>.</li>
  </ul>

  <h2>Run it yourself</h2>
  <p>This page is served by the Z relay itself. Personal self-hosting is
  expressly permitted: <code>docker compose up</code> in the repository's
  <code>server/</code> directory, then point the app at your own address.
  <a href="/self-host">How to self-host</a>.</p>
`
);

const HOW_IT_WORKS_HTML = page(
  '/how-it-works',
  'How Z works — keys, ratchets and a relay that knows nothing',
  'Keys are made on your device. The relay only moves sealed envelopes it cannot read and cannot attribute.',
  `
  <h1>How it works</h1>
  <p class="lead">Z has no accounts, so there is nothing to log into and nothing
  for a server to hold. Everything below happens on the two devices in a
  conversation; the relay is a dumb, forgetful post box in between.</p>

  <h2>Your identity is a key pair, not a record</h2>
  <p>When you first open Z it generates two key pairs on the device: one for
  signing, one for key agreement. They are written into an encrypted vault
  whose key lives in your operating system's keystore. Nothing is registered
  anywhere. Your address on the relay is a <b>hash</b> of your public key — a
  mailbox ID, not a name, not a number.</p>

  <h2>Adding a contact</h2>
  <ol class="steps">
    <li>You share a contact code — a QR code or a short string — in person or
    over any channel you like.</li>
    <li>Their app checks the signature inside the code, which proves the two
    keys in it belong together.</li>
    <li>The first message establishes a shared secret using an X3DH-style
    handshake, combined with an ML-KEM-768 post-quantum key so recorded traffic
    stays safe against a future quantum computer.</li>
    <li>From then on every message advances a <b>double ratchet</b>: keys move
    forward constantly, so a key compromised today unlocks neither yesterday's
    messages nor tomorrow's.</li>
  </ol>

  <h2>What the relay sees</h2>
  <div class="card">
  <p>Each envelope arrives <b>sealed</b>: an anonymous outer layer addressed to
  the recipient's mailbox, with the sender's identity inside the encrypted
  payload. The relay cannot tell who sent it. Envelopes are padded to fixed
  size buckets, so their length says little about their contents. Queued mail
  is held in memory only, dropped the moment the recipient confirms it, and
  expires within 72 hours regardless.</p>
  <p class="muted">The relay never writes to disk — its code is tested to
  contain no disk-write calls — so restarting it erases everything it held.</p>
  </div>

  <h2>Groups, files and voice notes</h2>
  <p>A group has no group key. Each message is encrypted separately to each
  member over the same one-to-one sessions, so group traffic inherits the same
  forward secrecy and is indistinguishable from direct traffic at the relay.
  Files and voice notes are encrypted once under a random per-file key that
  travels inside the conversation, then relayed as fixed-size chunks.</p>

  <h2>What this does not protect against</h2>
  <p>A compromised device. If someone controls your phone, encryption in
  transit is beside the point — they can read what you can read. Disappearing
  messages and the encrypted vault protect a lost or seized device, not one
  running someone else's software. We state the limits plainly on the
  <a href="/security">security page</a>.</p>
`
);

const FEATURES_HTML = page(
  '/features',
  'Z features — voice notes, files, groups and disappearing messages',
  'Voice notes, files and groups. Disappearing messages, replies, reactions and search — all end-to-end encrypted.',
  `
  <h1>Features</h1>
  <p class="lead">Everything here is end-to-end encrypted, including the parts
  most messengers treat as metadata.</p>

  <div class="grid two">
    <div class="card"><h3>Messages</h3>
    <p>Text, replies that quote from your own copy, emoji reactions, editing
    with an honest "edited" marker, delete for everyone, and forwarding.</p></div>

    <div class="card"><h3>Voice notes</h3>
    <p>Record and play voice messages. Audio is captured and played back in
    memory — plaintext audio never touches your disk.</p></div>

    <div class="card"><h3>Files and photos</h3>
    <p>Attachments are encrypted under a per-file key and streamed in uniform
    chunks, in direct chats and in groups.</p></div>

    <div class="card"><h3>Groups</h3>
    <p>Text, attachments and voice notes. No group key to leak: every message
    is encrypted separately to each member.</p></div>

    <div class="card"><h3>Disappearing messages</h3>
    <p>Set a timer per conversation. Messages are deleted on both sides when it
    expires — a convenience against a lost device, not against a compromised
    one.</p></div>

    <div class="card"><h3>Search and jump</h3>
    <p>Search your history locally. Cells stay sealed on disk and are decrypted
    only in memory; a hit opens the chat at the matched message.</p></div>

    <div class="card"><h3>App lock</h3>
    <p>Require a fingerprint, face or your device PIN to open Z, and again after
    a chosen time in the background. On Android the key is bound to the
    hardware keystore.</p></div>

    <div class="card"><h3>Light and dark</h3>
    <p>Follows your system, or pick one. Every text and background pair in both
    palettes clears WCAG AA contrast, checked automatically.</p></div>
  </div>

  <h2>And the parts you can check</h2>
  <ul>
    <li><a href="/devices">Multiple devices</a> on one identity, with revocation.</li>
    <li><a href="/backup">Encrypted backup</a> to a file only your recovery code opens.</li>
    <li><a href="/verify">Safety numbers</a> to catch a key substitution yourself.</li>
    <li><a href="/self-host">Self-hosting</a> the relay on your own hardware.</li>
  </ul>
`
);

const DOWNLOAD_HTML = page(
  '/download',
  'Download Z — free, no account needed',
  'Free, no account needed. Android, Windows, macOS and Linux, with SHA-256 checksums for every build.',
  `
  <h1>Download</h1>
  <p class="lead">Free, and there is no account to create. Install it, and you
  are ready to message in seconds.</p>

  <div class="btns">
    <a class="btn" href="${PLAY}">Android — Google Play</a>
    <a class="btn alt" href="${RELEASES}">Android (APK)</a>
    <a class="btn alt" href="${RELEASES}">Windows</a>
    <a class="btn alt" href="${RELEASES}">macOS</a>
    <a class="btn alt" href="${RELEASES}">Linux</a>
  </div>
  <p class="muted">Android 7.0 or newer. Play keeps you updated automatically;
  the APK is there if you would rather not use Play, and is the same build.
  Desktop builds are unsigned for now, so your system may warn on first
  run.</p>

  <h2>Verify what you downloaded</h2>
  <p>Every release publishes <code>SHA256SUMS.txt</code> alongside the files.
  Checking takes one command and proves the file you have is the file that was
  built:</p>
  <pre><code>sha256sum -c SHA256SUMS.txt --ignore-missing</code></pre>
  <p class="muted">On macOS use <code>shasum -a 256</code>; on Windows,
  <code>Get-FileHash</code> in PowerShell.</p>

  <h2>Google Play</h2>
  <p>Z is on Google Play as
  <a href="${PLAY}">Z Messenger</a>. The Play build and the APK above come from
  the same tagged release and the same CI pipeline, so you can check either
  against the published checksums.</p>
  <p class="muted">Google Play and the Google Play logo are trademarks of
  Google LLC.</p>

  <h2>Or build it yourself</h2>
  <p>The source is published and the protocol is fully specified, so you can
  build from the <a href="${REPO}">repository</a> rather than trusting a binary
  at all. Personal self-hosting of the relay is expressly permitted; see
  <a href="/self-host">self-hosting</a>.</p>
`
);

const SECURITY_HTML = page(
  '/security',
  'Z security design — the published threat model',
  'Read the published threat model, including what Z cannot do. The protocol is specified and pinned by test vectors.',
  `
  <h1>Security design</h1>
  <p class="lead">A security claim you cannot check is marketing. The protocol
  is published in full, the test vectors are in the repository, and the
  threat model states the limits as plainly as the strengths.</p>

  <h2>What Z is designed to withstand</h2>
  <ul>
    <li class="yes">A hostile or seized relay: it holds only ciphertext, in RAM,
    addressed to hashes — and with sealed sender it cannot tell who sent
    what.</li>
    <li class="yes">Recorded traffic decrypted later, including by a quantum
    computer: key agreement is hybrid X25519 + ML-KEM-768.</li>
    <li class="yes">A stolen key: the double ratchet moves keys forward
    constantly, so a compromise reaches neither past nor future messages.</li>
    <li class="yes">A substituted key: safety numbers let two people detect it
    themselves, and device-list changes are gossiped between contacts so a
    silently added device is visible.</li>
    <li class="yes">A lost device: the vault is encrypted, optionally behind
    biometrics or a passphrase, and can be wiped.</li>
  </ul>

  <h2>What it cannot do</h2>
  <div class="note">
  <p>These are real limits, not hypotheticals, and they are in the published
  threat model rather than buried:</p>
  <ul>
    <li class="no"><b>A compromised device defeats everything.</b> Disappearing
    messages and local encryption protect a lost phone, not one running an
    attacker's software.</li>
    <li class="no"><b>The relay sees transient metadata.</b> IP addresses,
    timing and padded sizes pass through memory. Z does not record or analyse
    them, and nothing is stored to hand over — but a network observer still
    sees that a device is talking to a relay.</li>
    <li class="no"><b>Trust starts out of band.</b> If a contact code is
    swapped before it reaches you, you verified the wrong person. That is what
    <a href="/verify">safety numbers</a> exist to catch.</li>
    <li class="no"><b>No public transparency log yet.</b> Device changes are
    gossiped between contacts today; a third-party-auditable log is designed
    but not built.</li>
    <li class="no"><b>Group membership is asserted by the group's admin</b>
    over their authenticated channel — there is no cryptographic group
    state.</li>
  </ul>
  </div>

  <h2>How the claims are checked</h2>
  <p>The wire protocol is frozen and specified byte by byte, and pinned by
  known-answer test vectors. Those vectors are reproduced on every change by
  three independent implementations: the app's own, a clean-room implementation
  written from the specification alone that shares no code with it, and
  reference implementations of the post-quantum primitives. If any of them
  disagrees, the build fails.</p>

  <h2>Independent audit</h2>
  <p>Z has <b>not yet</b> had an external security audit. The scope brief and
  the threat model are published so that one can start from a clear statement
  of what is claimed. We would rather say this plainly than imply an assurance
  that does not exist.</p>

  <div class="btns">
    <a class="btn alt" href="${REPO}/blob/main/docs/THREAT_MODEL.md">Threat model</a>
    <a class="btn alt" href="${REPO}/blob/main/docs/PROTOCOL.md">Protocol spec</a>
    <a class="btn alt" href="${REPO}/blob/main/docs/AUDIT_SCOPE.md">Audit scope</a>
  </div>
`
);

const VERIFY_HTML = page(
  '/verify',
  'Verify your contacts — compare safety numbers',
  'Compare safety numbers to catch a key swap yourself. It takes a few seconds and needs no trust in us.',
  `
  <h1>Verify your contacts</h1>
  <p class="lead">Encryption protects a conversation with whoever holds the
  keys. Verifying is how you confirm that whoever holds them is the person you
  think it is — without trusting us, the relay, or the network.</p>

  <h2>How to compare</h2>
  <ol class="steps">
    <li>Open the conversation, then the contact's name.</li>
    <li>You will each see a <b>safety number</b>: sixty digits derived from
    both identities. It is the same on both devices, in the same order.</li>
    <li>Compare it in person, or over a channel you already trust — read it
    aloud, or scan the QR code, which does the comparison for you.</li>
    <li>Mark them verified. Z remembers, and tells you if it ever changes.</li>
  </ol>

  <h2>What it means when the number changes</h2>
  <p>It means the keys behind the conversation changed. There are innocent
  reasons — a reinstall, a restored backup, a new identity after a lost phone —
  and one that is not: someone substituting their key for your contact's.
  Z cannot tell these apart, which is exactly why it shows you rather than
  deciding for you. Ask them, over a different channel, before continuing.</p>

  <div class="note">
  <p><b>The number is tied to the person, not the device.</b> Linking a laptop
  to your account does not change it, so a change is always worth a question.
  Once a contact's post-quantum identity has arrived and been checked, the
  number covers that too — it never claims more than has actually been
  verified.</p>
  </div>

  <h2>Device changes are visible too</h2>
  <p>Your app tells your contacts which devices belong to you, signed by your
  account key, and their apps compare what they are told against what they hear
  from your other devices. A device added without your knowledge does not stay
  quiet — see <a href="/devices">devices</a>.</p>
`
);

const DEVICES_HTML = page(
  '/devices',
  'Z on multiple devices — phone and desktop, one identity',
  'Phone and desktop on one identity, still end-to-end encrypted, with revocation your contacts respect.',
  `
  <h1>Multiple devices</h1>
  <p class="lead">Use Z on your phone and your desktop at the same time, on one
  identity, with no server-side account to make it work.</p>

  <h2>Linking a device</h2>
  <ol class="steps">
    <li>On the new device, choose to link to an existing one.</li>
    <li>Scan the QR code shown, or type the pairing code.</li>
    <li>Compare the six digits that appear on both screens, then confirm. That
    comparison is what stops a machine in the middle.</li>
    <li>The new device receives your account identity and your contacts over
    that verified channel, plus recent history so it does not start empty.</li>
  </ol>

  <h2>How it stays end-to-end encrypted</h2>
  <p>Each device has its own keys and its own session with each of your
  contacts' devices — there is no shared key copied around, and the relay learns
  nothing about which mailboxes belong to the same person. Messages you send
  and receive are mirrored to your own devices over those same encrypted
  sessions.</p>

  <h2>Your contacts always see one identity</h2>
  <p>The <a href="/verify">safety number</a> is anchored to your account rather
  than to whichever device is in your hand, so linking a laptop does not make
  you look like a different person, and a genuine key substitution still stands
  out.</p>

  <h2>Removing a device</h2>
  <p>Remove a lost or retired device and your app publishes a new signed device
  list. Your contacts stop sending to it as soon as they receive that, and their
  apps flag a device that tries to speak for you afterwards. Removals are
  distributed so that a device cannot suppress the notice of its own
  removal.</p>
`
);

const BACKUP_HTML = page(
  '/backup',
  'Encrypted backup — your history, your recovery code',
  'Your history, your recovery code. We cannot restore it for you, because we never hold it.',
  `
  <h1>Encrypted backup</h1>
  <p class="lead">Back your history up to a single encrypted file, and restore
  it on a new device. The file is protected by a recovery code that only you
  ever see.</p>

  <h2>How it works</h2>
  <ul>
    <li>Z writes a <code>.zbk</code> archive: your messages, attachments,
    contacts and identity, encrypted with a key derived from a 25-character
    recovery code using Argon2id.</li>
    <li>The code is shown once, and you type it back before the archive is
    written — the last moment a mis-copied code can be fixed.</li>
    <li>The archive streams, so a large history never has to fit in memory, and
    a truncated or altered file fails outright rather than restoring a quietly
    incomplete history.</li>
    <li>You choose where it goes. Z does not upload it anywhere.</li>
  </ul>

  <div class="note">
  <p><b>Lose the code and the archive is gone.</b> There is no copy, no reset
  link and no support route, because there is no account and no server-side
  storage to hold one. That is the trade that makes the backup safe to keep
  anywhere — treat the code like a key, not a password.</p>
  </div>

  <h2>Restoring</h2>
  <p>Install Z on the new device, choose restore, pick the file and enter the
  code. History and contacts come back; sessions do not — your device
  re-establishes them with each contact, so no key material is ever replayed.
  Contacts may see your safety number change, which is why
  <a href="/verify">verification</a> exists.</p>

  <h2>Automatic backups</h2>
  <p>Optional, and off by default. Enabling it stores your recovery code in the
  encrypted vault, because an unattended backup cannot ask you for one. That
  is a real trade-off and the app says so where you switch it on rather than
  leaving it implicit.</p>
`
);

const SELF_HOST_HTML = page(
  '/self-host',
  'Self-host the Z relay — one command, your hardware',
  'Run the relay yourself: one command, your hardware, and the app points wherever you tell it.',
  `
  <h1>Self-host the relay</h1>
  <p class="lead">The relay is deliberately small and stateless. Running your
  own means your traffic never touches ours — and the page you are reading is
  served by the relay itself, so you can see what you would be running.</p>

  <h2>One command</h2>
  <pre><code>git clone ${REPO}
cd z-messanger/server
docker compose up -d</code></pre>
  <p>Then in the app: Settings → Developer mode → relay address, and enter
  <code>wss://your-host</code>. Anyone you talk to needs to be reachable
  through the same relay, so point your contacts at it too.</p>

  <h2>What it needs</h2>
  <ul>
    <li>Node 20+ or Docker, and a TLS certificate for a public deployment.</li>
    <li>Memory proportional to queued mail, not to your history: nothing is
    stored, and queues expire.</li>
    <li>No database. No disk. There is nothing to back up, which is the
    point.</li>
  </ul>

  <h2>Worth knowing</h2>
  <ul>
    <li>Queued mail lives in RAM and expires after <code>QUEUE_TTL_HOURS</code>
    (72 by default); restarting the relay drops it.</li>
    <li>Rate limits and queue caps are environment variables, so a small host
    stays bounded under load.</li>
    <li><code>/health</code> reports liveness and <code>/metrics</code> exposes
    aggregate delivery counters only — no per-user data.</li>
    <li>Multiple instances can share presence through Redis if you need more
    than one.</li>
  </ul>

  <div class="note">
  <p>Z is source-available, not open source: personal self-hosting is expressly
  permitted, and commercial use or redistribution needs written permission. The
  licence is in the repository.</p>
  </div>
`
);

const ABOUT_HTML = page(
  '/about',
  'About Z — built in London by Secured Cyber Solutions',
  'Built in London by Secured Cyber Solutions, an independent security company.',
  `
  <h1>About</h1>
  <p class="lead">Z is built by <b>Secured Cyber Solutions</b>, an independent
  security company in London.</p>

  <h2>Why it exists</h2>
  <p>Most messengers ask you to trust an operator: to hold your phone number,
  your contact graph and your account, and not to look. Z is an attempt to
  build one where that trust is not required — where the server is designed to
  be useless to an attacker who takes it, and where the claims are specified
  precisely enough that someone else can check them.</p>

  <h2>How it is built</h2>
  <p>The protocol is published and frozen, the test vectors are in the
  repository, and every change is re-verified by independent implementations
  before it ships. Design decisions that affect the security model are written
  down as records in the open, including the ones that record a mistake and
  its correction.</p>

  <h2>Licence</h2>
  <p>Source-available under the Z Messenger Licence: you may read it, build it
  and self-host it for personal use. Commercial use and redistribution need
  written permission.</p>

  <h2>Contact</h2>
  <p>Security reports and everything else:
  <a href="mailto:finnianbond@gmail.com">finnianbond@gmail.com</a>. If you are
  reporting a vulnerability, say so in the subject line and we will reply
  before doing anything else.</p>
`
);

const PRIVACY_HTML = page(
  '/privacy',
  'Z — privacy policy',
  "No number, email or contacts. See the full data map of what exists and where it lives.",
  `
  <h1>Privacy policy</h1>
  <p class="muted">Effective 8 September 2026 · applies to the Z app and the
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
  passphrase or your device's biometrics. "Wipe everything" in Settings
  destroys all of it irreversibly. An <a href="/backup">encrypted backup</a> is
  written only when you ask for one, and only where you choose to put it.</p>

  <h2>What the relay handles, and for how long</h2>
  <p>To move a message from you to a recipient, the relay momentarily handles:
  ciphertext (undecryptable to it), the opaque mailbox ID it is addressed to
  (a hash, not a key or a name), and the network connection carrying it.
  Envelopes are sealed, so the relay does not learn which mailbox sent them,
  and padded to fixed size buckets. Queued ciphertext for offline recipients is
  held <b>in RAM only</b>, is deleted the moment the recipient confirms
  delivery, and expires after at most 72 hours. The relay writes nothing to
  disk — its code is tested to contain no disk-write calls — so restarting it
  erases everything it held. Operational logs contain aggregate connection
  counts only, never message data.</p>

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
  connection and the timing of encrypted envelopes passing through RAM. Z does
  not record, store, or analyse this, and its RAM-only design means there is no
  historical record to hand over: a subpoena for stored data would yield
  nothing, because nothing is stored. Sealed sender and size padding are
  implemented, so an envelope in transit does not identify its sender and its
  length reveals little; what remains is that a mailbox is active.</p>

  <h2>Your choices</h2>
  <ul>
    <li>Use the app fully without push — it is optional.</li>
    <li><a href="/self-host">Point the app at your own relay</a> so no traffic
    touches ours.</li>
    <li>Delete everything at any time with Settings → Wipe everything. There is
    nothing server-side to request deletion of.</li>
  </ul>

  <h2>Children</h2>
  <p>Z is not directed at children under 13, and we do not knowingly collect
  information from anyone — child or adult.</p>

  <h2>Changes &amp; contact</h2>
  <p>Material changes to this policy will be published at this address with an
  updated effective date. Questions:
  <a href="mailto:finnianbond@gmail.com">finnianbond@gmail.com</a>.</p>
`
);

// path → html, used by the server's request listener and by the tests.
const ROUTES = new Map([
  ['/', LANDING_HTML],
  ['/index.html', LANDING_HTML],
  ['/how-it-works', HOW_IT_WORKS_HTML],
  ['/privacy', PRIVACY_HTML],
  ['/download', DOWNLOAD_HTML],
  ['/security', SECURITY_HTML],
  ['/verify', VERIFY_HTML],
  ['/features', FEATURES_HTML],
  ['/self-host', SELF_HOST_HTML],
  ['/devices', DEVICES_HTML],
  ['/backup', BACKUP_HTML],
  ['/about', ABOUT_HTML],
]);

// Trailing-slash forms answer identically, so a sitelink cannot 404 on a
// stray slash.
for (const [path, html] of [...ROUTES]) {
  if (path !== '/' && !path.endsWith('/')) ROUTES.set(`${path}/`, html);
}

module.exports = { LANDING_HTML, PRIVACY_HTML, ROUTES, PAGES, STYLE };
