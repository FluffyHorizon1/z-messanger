# ADR 0032 — A public introduction link: the introduction mailbox handed out directly, with no registry

**Status:** **Accepted** (2026‑10‑17). Proposed 2026‑10‑16; Finnian's
decisions of 2026‑10‑17 answer its six open questions — folded into the text
where it asked them, and listed under "Decisions". Phase 39. Adds PROTOCOL
§21.9 and `docs/vectors/handles/intro_link.json`; amends §8.1, §15, §20.2,
and §21's title, preamble, §21.0, §21.7 and §21.8 by a sentence or two each;
the relay's protocol (§12) does not change. Settles ADR 0009's deferred
public invite (17.8) as ADR 0015's shape F. R34 and R47–R49 are updated in
place, and a new register row is added when 39.5 lands. Builds on the
handles hardening, landed in 4.3.0; whether the deployed relay runs it is
not yet confirmed (decision 1), and phase 39 does not ship live until it is.
**Built:** 39.1 — the link in the protocol library: `IntroLink`, its code,
its check and its reader, with a named reason for each refusal (PROTOCOL
§21.9, §20.2, §15; `vectors/handles/intro_link.json`). Nothing a client
shows or sends has changed: no build makes, opens or drains a link before
39.2–39.4. The rest of the build plan below is not built.
**Decides:** what a public link carries and how it is read; what the person
who opens one sends, and when; what the owner's device does with what
arrives; how a link is replaced, withdrawn or made dearer; what an older
client does with one.

## Context

ADR 0009 deferred "a deliberately separate public invite" that must never
share a button with a one‑time invite; R34 keeps "anyone can add me" apart
from every default. Someone who wants to be reached from a web page, an
email signature or a printed card has two ways today, and neither fits:

- **Their contact code** names the account: its key is the transparency
  label's input (R20), its routing id a mailbox anyone can fill (R22) or send
  chunks to (R26); a request to it costs nothing, and only an identity reset
  rotates it.
- **A handle** (ADR 0015) needs the handle log and its witness, which no
  build pins yet (R50), the claims bill, and a name.

ADR 0015 kept shape F, the 2026‑10‑03 analysis's durable public introduction
link (§5.3), open as a complement. What shapes this record is that
everything but the registry is built. A request through a handle takes three
values from its record, `intro`, `xintro` and `pow` — 65 bytes — and the
handle log exists to map a guessable name to them. A link has no name to
map, so it carries them, and the introduction mailbox (§21.3), its guard at
the relay (§21.6), the request, stamp and acknowledgement (§21.7) and the
owner's drain (§21.8) are reused as they are. Links therefore come before a
handle log (decision 2): they need no service and no claims bill.

## Decision

### 1. The link

```
introSeed = 32 CSPRNG bytes → intro, xintro, introRid exactly as §21.3
body      = u8(pow) || intro || xintro                  65 bytes; pow 16…28
check     = SHA-256( utf8("z-intro-link-v1:") || body )[0..4]
code      = "zi1." || b64url( body || check )           96 characters (69 bytes: no padding, no spare bits)
link      = "https://" || host || "/c#" || code          126 characters at the default host
```

`host` is the deployment's, as in §20.2. The code rides in the fragment,
which no browser sends, so the `/c` page never receives one. A QR carries
the link: version 6 at the app's level L, where a ~500‑character contact
code needs version 15. Nothing else is in it — no name, relay, expiry
(decision 4) or account. The check catches a damaged copy, not a
substituted one.

### 2. Reading one

A parser trims ASCII whitespace and, given a `#`, reads only what follows
it. That MUST be `zi1.` and exactly 92 base64url characters — no padding, no
case folding — with a matching check, `pow` 16–28, and `intro` and `xintro`
strong by the hardened §21.4 (`handleStrongEdKey`, `handleStrongXKey`). Both
matter: a weak `intro` would let anyone forge `ia`, and a request sealed to
a weak `xintro` would be open to anyone, the relay included. Since
2026‑10‑16 `SealedEnvelope.seal` refuses a key of small order
(`SealRefusedException`, §8), so such a request fails when it is sealed
rather than going out open — but only once its person has said to send it,
and a second spelling of a key, which the sealer takes, makes a request its
owner cannot open; the parser refuses both first. `zi` with another version
is refused as made by a newer Z; anything else is not a link. A client
recognises its own and sends nothing to it.

### 3. The person who opens one

A link tapped, scanned or pasted is **held**: nothing is sent and no
connection opened until its person presses **Send request**, on a screen
saying that whoever made the link will see their name and contact code (R48)
and that a link verifies nothing. Then §21.7 runs unchanged: a `creq` to
`introRid` sealed to `xintro`, kept first in §21.8's outgoing list (20
handles and links together, three ids each), stamped at the link's `pow` and
sent on a connection opened for it alone. One departure: on `pow_required`
the client stamps once more, for the relay's `day`, at the greater of the
link's `pow` and the refusal's `bits` if that is at most 28, then stops — a
printed link cannot learn that its owner asked for more work, and the
refusal is how its holder hears. An acceptance whose `ia` verifies under the
link's `intro` adds the owner unverified: *accepted through their public
link — compare safety numbers to verify*. After 30 days unanswered, the
screen says the link may have been replaced or withdrawn.

### 4. The owner

**Making:** one link per account (decision 3), in Settings › Your public
link, never during setup, on the main device only (v1, as a handle). It
draws `introSeed`, takes `pow` from 16 to 24 (default 20, as a handle's:
decision 5), and shows the link, its QR and a copy for web pages carrying
`rel="noreferrer"`. Nothing is sent: the relay meets the mailbox at its
first drain.

**Draining** is §21.8's — its own connection as the link's identity,
`intro` with the work asked, never push, a timer drawn apart from a
handle's — with one difference: each stamp is counted at the link's printed
`pow`, not the work asked since, because that is all a holder knows and all
that holds once the relay has lost its flags. Requests pass §21.8's ledger
and §8.1's rules, are filed *via your public link*, and share one cap of 100
with a handle's, apart from requests by code. Accepting adds `ia`, signed
with the seed of the mailbox the request reached.

**Managing:** *Ask more work* re‑flags at once, up to 24 bits. *Replace*
draws a new seed; the old mailbox is read once more without `intro`, and its
flag lapses (30 days, then 30 of shadow). *Withdraw* replaces with nothing.
An old seed stays while a pending request needs it.

**Stored**, sealed, as `intro_link`: the seed, the printed and asked work,
when made, whether live, and old seeds; in a backup as record `introlink`,
`"keep":1`. A restore brings a link back **held** until its person says to
use it again: the device the backup came from may have replaced or withdrawn
it, and there is no log to ask.

### 5. Versions meeting

No existing bytes change: a code behind its own prefix is §14's pattern, and
`creq`, the stamp, `ia` and the relay are untouched. An older client refuses
`zi1.` everywhere — the contact‑code parser by prefix; §20's by the path,
which it reads as `/i` alone since 2026‑10‑16, and on `1` and `.` wherever
it reads the fragment, as a build from before then does at a host beginning
`i`; the handle parser on the base64 — and its Android filter does not claim
`/c`, so a tap opens a landing page saying to update and paste it. Only a
link's own requester ever receives the acceptance. The relay must run the
hardened §21.6, which hands each stamp on with its envelope: the owner's
check drops a request that arrives without one, as for a handle. Whether the
deployed relay runs it is not yet confirmed (decision 1), so phase 39 does
not ship live until it is.

### 6. How the constraints hold

- **Zero knowledge:** the link never reaches the relay; requests are sealed
  and sent on throwaway connections; drains run as the link's own identity.
- **Metadata:** request, drain, flag and acknowledgement have a handle's
  shapes and sizes. The relay sees one more pseudonymous mailbox per owner,
  which it can tell from a handle's only by reading the public handle log.
- **No new trusted party:** no registry, no log; the page carrying the link
  was already where a stranger learnt whose it is.
- **Never the account:** the link holds keys made for it; the account
  arrives with the acceptance.
- **Spam:** the same stamp, checked by the relay and again by the owner,
  under the same caps. Phase 45's tokens come beside the stamp, which every
  door always takes (Finnian's decision of 2026‑10‑17 on phase 45), and a
  publicly verifiable token (RFC 9578, type 2) can be handed on and checked
  as a stamp is — no new link format.
- **Federation:** a link names no relay (§21.8). ADR 0008's relay statement,
  signed by the introduction key, would make a `zi2.` link, which a `zi1.`
  client refuses rather than misroute.

## Alternatives rejected

- **The contact code** — it names the account.
- **A reusable connect invite** — its holder can play the inviter (§20.5),
  and a ceremony serves one acceptor; ADR 0020 refused reusable links as
  replayable bearer tokens.
- **A signed link** — whoever substitutes it substitutes the signing key.
- **JSON, like `zc1.`** — half as long again, and its tolerance of unknown
  members is wrong here: what a later link adds (a relay, say) is what an
  older client must not ignore.
- **A name in the link** — shown unchecked, without the grammar and reserved
  nicks that bound a handle's.
- **The `/i` path** — every build claims `/i` (those before 2026‑10‑16 every
  path beginning `/i`) and would open the link as an invite and drop it, and
  ADR 0009 keeps the two apart. `/c` is claimed exactly; a prefix `/p` would
  also take `/privacy`.
- **The handle's mailbox** — every page carrying the link would name the
  handle.
- **A relay "closed" flag** — the owner would have to keep authenticating as
  a dead identity.

## Consequences

- **PROTOCOL:** new §21.9; §21 retitled "Handles and public links (36–39)",
  its preamble and §21.0 (row, `z-intro-link-v1:`); §21.7 (keys from a
  record or a link; the `pow_required` rule); §21.8 (lists, cap and drains
  shared by both doors; no handle log needed); §8.1 (the cap); §20.2 (`zi1.`
  is not an invite); §15.
- **Vectors:** `intro_link.json` — links from seeds at `pow` 16, 20 and 28
  with every intermediate; inputs accepted (bare; default host; a host
  beginning `i`; a query before the fragment; whitespace) and refused by
  reason (a `zc1.` code, both invite versions, a handle, `zi2.`, 91 and 93
  characters, padding, `+` and `/`, flipped case, flipped check, `pow` 15 and
  29, every weak `intro` and `xintro`); a request, stamps at `pow` and at a
  raised `bits`, and `ia`. `handles.json` and `connect/*` stay byte‑identical.
- **Tests:** extended — `protocol/test/handles_test.dart`, `connect_test.dart`
  (each parser refuses the other's codes; a verbatim pre‑0032 copy refuses
  links), `vectors_test.dart`, `server/test/vectors.test.js`,
  `server/test/pages.test.js`, and in `app/test/` `deep_link_test.dart`,
  `handle_inbox_test.dart`, `handle_screens_test.dart`,
  `handle_flow_test.dart`, `restore_truth_test.dart`,
  `contact_erasure_test.dart`, `locale_es_test.dart`; new —
  `app/test/intro_link_test.dart`, two clients over a real relay with a
  recording tap.
- **THREAT_MODEL:** R34 — "anyone can add me" is this link, stamped and
  capped apart. R47 — a published link is crawlable. R48 — whoever controls
  the page, or a sticker over a printed QR, collects requesters. R49 — one
  owner's handle and link are linkable by address; and until App Links
  verify, a browser opening a link tells the relay host and Cloudflare its
  address and, by `Referer`, the site, unless that site set `noreferrer`. A
  new register row when 39.5 lands: a published link cannot be updated — a
  replaced or withdrawn copy fails silently; a raise reaches senders only
  through the relay, so after a relay restart only the printed `pow` holds
  until the next drain; a stolen seed holds every printed copy until each is
  replaced; a link names no relay. R50 has no counterpart.
- **DATA_MAP:** `intro_link` (new); the `handle_in`, `handle_out`,
  `hvia_<rid>`, relay introduction‑mailbox and "what leaves" rows name links;
  the relay host's row gains the `/c` request; erasure gains *Withdraw*.
- **Claims:** no directory and no username — those sentences and the Play
  listing stay true, and Play's Data‑safety form is unchanged (decision 6): a
  link's mailbox is a routing id and a number at the relay, as a handle's.
  USING_Z gains a section; WHAT_Z_CANNOT_DO's handle section covers links.

## What remains

All a handle leaves but R50, and the row 39.5 adds. A link is as good as the
page it is on; the safety number, compared after the add, still catches a
substituted account.

## Decisions (Finnian's, 2026‑10‑17)

1. Land the handles hardening now, its relay deploy included, so links can
   go live while handles stay dormant; phase 39 cannot ship live without
   it. — **Not sure** whether the deployed relay runs it. The hardening
   landed in 4.3.0; this stays open until the deployed relay's version is
   confirmed, which phase 39 needs before it ships live (§5). 39.1, the
   library alone, does not wait for it.
2. Links before a handle log — recommended: no service, no claims bill. —
   **Links first**, as recommended (Context).
3. One link per account in v1 (recommended), or several labelled ones, each
   a mailbox and a drain. — **One** (§4).
4. An expiry in the link — recommended none; it is format, so decide before
   39.1. — **None** (§1): `zi1.` has no expiry field.
5. The default work of a printed link: 20, as a handle's, or higher. — **20
   bits, as a handle's** (§4): the owner chooses 16 to 24, and a link may
   carry 16 to 28.
6. Play's Data‑safety form: confirm unchanged — a link's mailbox is a
   routing id and a number at the relay, as a handle's. — **Unchanged,
   confirmed** (Consequences).

## Build plan

Each patch starts from a failing test on its base.

| # | Patch | Status |
|---|---|---|
| 39.1 | The link in the protocol library: `IntroLink` encode and parse, with a named reason for each refusal and the check (`protocol/lib/src/handles.dart`); `vectors/handles/intro_link.json`; PROTOCOL §21's title, preamble and §21.0, §21.9's format and reading, §20.2, §15 | **built**; nothing makes, opens or drains a link |
| 39.2 | The landing page and the Android app link: a `/c` page in `server/pages.js`, unlisted like `/i`; `android:path="/c"` on both hosts; `server/server.js` does not change | planned |
| 39.3 | The owner's side: the drain, the once‑only record, filing and the acknowledgement take either kind of mailbox, and a link does not depend on a handle log being configured; make, replace, withdraw and *Ask more work*; the stamp counted at the printed `pow`; one cap for handle and link requests; the `introlink` backup record, restored held; Settings › Your public link, in both languages | planned |
| 39.4 | The person who opens a link: held until they say yes; the Paste and Scan tabs, a QR image and the handle search take a link; link entries in the outgoing list, the re‑stamp on `pow_required`, matching `ia` and the 30‑day notice | planned |
| 39.5 | The register and the claims, before any release ships links: R34, R47–R49 and the new row; USING_Z, WHAT_Z_CANNOT_DO, AUDIT_SCOPE; pointers to this record from ADR 0009 and 0015; ROADMAP | planned |
