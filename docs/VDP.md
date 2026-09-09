# Vulnerability disclosure policy

Z makes cryptographic claims about other people's private conversations. The
only thing that makes such a claim worth anything is that people are free to
go and check it — so this document exists to remove every reason not to.

If you have found something, the short version is: **look, report it, and you
will not be threatened for it.** The rest is detail.

---

## Safe harbour

If you follow this policy while researching Z, we will treat your work as
authorised, will not pursue or support any legal action against you for it, and
will say so in writing if a third party ever suggests otherwise.

That covers:

* testing against **your own** accounts and devices, and against a relay you
  run yourself (`docs/SELF_HOSTING.md` — running one takes minutes, and it is
  the right place to test anything intrusive);
* reading, decompiling and instrumenting the published apps and the source;
* accessing **only your own** data on `zmessengers.com`, at a rate that does
  not degrade the service for anyone else.

It does not cover, and cannot cover, things that harm other people: accessing
or modifying data that is not yours, degrading or denying service, social
engineering of users or the maintainer, physical attacks, or holding a finding
to ransom. We would rather say that plainly than imply it.

If you are unsure whether something is in scope, **ask first** — a question
costs nothing and this policy is not a trap. Acting in good faith on a
reasonable reading of it is the standard we will hold ourselves to, including
when you get it wrong.

## How to report

Either channel, whichever you prefer:

* a [private security advisory](https://github.com/FluffyHorizon1/z-messanger/security/advisories/new)
  on the repository — preferred, because it keeps the discussion attached to
  the code and lets us credit you automatically;
* email **finnianbond@gmail.com**.

There are two on purpose: someone who will not open a GitHub account still has
somewhere to go, and an address that bounces should not silence everybody.
`https://zmessengers.com/.well-known/security.txt` carries the same details in
machine-readable form.

Useful in a report, in rough order of how much time it saves:

1. what an attacker gets, in one sentence;
2. the steps to reproduce, and the version or commit;
3. anything that made it easier or harder than you expected.

A proof of concept is welcome and never required. A clear description of a real
weakness beats a working exploit of a theoretical one.

## What happens next

| | target |
|---|---|
| We acknowledge your report | 5 working days |
| We tell you whether we agree it is a vulnerability, and roughly how bad | 10 working days |
| We agree a disclosure date with you | with the triage answer |
| Default coordinated disclosure | 90 days from the report |

These are targets from one maintainer, not a staffed rota, and the honest thing
to say is that they will occasionally slip. If they do, chase — silence from us
is a mistake on our part, never a hint to go away.

**The 90 days is a default, not a deadline we impose on you.** It is yours to
shorten if we are unresponsive or if the issue is being exploited, and yours to
extend if a fix genuinely needs longer. If we disagree about timing we will say
so and explain why, and you are still free to publish; we will not treat
publication after a good-faith disagreement as a breach of this policy.

## What we are most interested in

The claims we make are the things worth attacking. In descending order of how
much a finding would change:

1. **Anything that lets the relay, or someone on the path, read message content
   or work out who is talking to whom.** This is the whole product.
2. **Anything that bypasses the ratchet, sealed sender, or device
   verification** — a forged device certificate, a device list a contact
   accepts that the account never signed, a safety number that fails to move
   when it should or moves when it should not.
3. **Any path that writes plaintext to disk**, on any platform, including
   crash dumps, logs and OS-level backups.
4. **Weaknesses in the post-quantum layer** (`PROTOCOL.md` §17–18): the
   commitment binding a contact code to an ML-DSA key, the hybrid device-list
   signature, and the places where one half can be stripped.
5. **The enrollment ceremony and backup archive** — anything that lets an
   attacker who has the file, but not the passphrase or recovery code, learn
   something.

`docs/AUDIT_SCOPE.md` lists every claim with where it is specified and where it
is tested; it is the most efficient place to start looking for a claim to break.
`docs/THREAT_MODEL.md` lists what Z deliberately does *not* protect against —
those are documented limits rather than findings, though an argument that one
of them is worse than stated is very much a finding.

## Out of scope

Not because they do not matter, but because they are already known, already
documented, or not defects:

* metadata visible to a relay operator (timing, which mailbox, size bucket) —
  a documented limit, and the reason self-hosting exists;
* anything requiring a compromised or unlocked device;
* missing hardening headers, TLS configuration grades, or scanner output with
  no demonstrated impact;
* denial of service against the relay by volume;
* social engineering, phishing of users, and physical attacks;
* vulnerabilities in third-party services (Play, Firebase, the hosting
  provider) — report those to them, though we want to know if our *use* of one
  is what creates the exposure.

## Rewards

**There is no funded bounty, and we will not pretend otherwise.** Z is not a
company and has no budget to pay from. Saying "rewards may be available at our
discretion" when the answer is almost always no wastes the time of the people
this document is trying to attract.

What we can offer:

* credit, by whatever name or handle you choose, in the release notes, the
  advisory and the list below — or no credit at all, if you prefer;
* a straight answer, quickly, from someone who will actually read the report;
* a public advisory that describes the issue accurately rather than minimising
  it.

If that changes and a bounty is funded, it will be stated here with amounts,
not implied.

## Thanks

Nobody yet. When there is somebody, they go here, with what they found and the
release it was fixed in.

---

*This policy applies to the `z-messanger` repository, the published Z apps, and
the relay at `zmessengers.com`. It does not apply to relays other people run.
Last reviewed with the `security.txt` expiry — see
`server/test/security_txt.test.js`, which fails the build if that date passes.*
