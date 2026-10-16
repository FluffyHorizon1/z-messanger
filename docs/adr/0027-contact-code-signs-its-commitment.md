# ADR 0027 — A contact code signs its post‑quantum commitment, and a commitment nothing signs is a candidate

**Status:** **Accepted** (2026‑10‑04) — built (26.3, 4.0.1). Adds §18.10;
amends §18.2, §18.5 and §18.7; extends ADR 0003 and ADR 0021.
**Decides:** how a contact code's post‑quantum commitment (`pqc`) is
protected against anyone who holds the public code; what a client does with a
commitment that is not protected — every code issued before this; and what a
connect ceremony's confirmation is worth when the post‑quantum key it covered
arrives.

## Context

Two findings of the 3 October 2026 analysis (§4.4), both reproduced against
real clients over a real relay before anything here was written.

**Nothing covered `pqc`.** A contact code is `ed`, `x`, `sig` (Ed25519 by
`ed` over `x`, §2.3), the commitment `pqc` (ADR 0003), optionally `acct` and
`cert` (§18.7), and a name. `sig` binds the X25519 key, `cert` binds the
device to the account; the commitment was bound by nothing. Anyone holding a
person's public code — and a contact code is handed to everyone its owner
ever meets — could write any 32 bytes into `pqc`, and the result decoded and
verified. What that bought:

* **Poisoning an existing contact.** ADR 0021 made a re‑scanned code upgrade
  the record it names. Pasted into a contact that holds a candidate key, a
  rewritten `pqc` refused that key — the genuine one, sent by the contact's
  own app — and set a permanent *"Do not rely on this chat"*. Pasted into a
  contact that held nothing yet, it became the commitment, and the genuine key
  was refused when it arrived. There was no way back but deleting the contact
  and its history.
* **A promise the screen could not keep.** Under the add button: *"The
  code's signature is checked before the contact is added — a tampered code
  is rejected."* A tampered `pqc` was not; nor, ever, a tampered name.
* **Silent stripping.** A code with `pqc` removed is a valid classical code.
  Nothing could tell it from the code of a build that never had a
  post‑quantum key.

**Every contact verified by a CONNECT ceremony flipped to "re‑verify".** The
ceremony's eight digits cover both account keys AND both post‑quantum
commitments (§20.4), so a confirmed comparison is a comparison of the
post‑quantum identity too. But the key itself arrives in‑band seconds later;
when it did, the safety number moved to the post‑quantum one (§18.5), the
tick still stood on the classical number recorded at the ceremony, and 13.3's
rule — a tick stands on the number it was made against — reported "the number
changed, compare it again". On 3.9.9 and on the 3.9.1 build Play serves, that
was every connect‑verified contact, a few seconds after being verified.

26.3 also gives the screens a message‑level post‑quantum line and rewords the
device‑list sentence; neither changes the trust model, so neither is recorded
here (PROTOCOL is unchanged by them; `USING_Z.md` describes the line).

## What was rejected

* **A new code version, `zc4.`, carrying the signature.** A prefix is a flag
  day: every build in the field rejects one it does not know (ADR 0003's
  correction), so the code most people could not scan would be the one
  carrying the protection. An optional member reaches everyone who can use it
  and costs nobody else anything (§14).
* **Re‑using `sig` for it.** `sig` is the v1 binding signature over `x`, and
  every client ever built verifies it over exactly those bytes. Its input
  cannot grow.
* **An ML‑DSA signature over the commitment.** The ML‑DSA public key is not
  in the code — that is the whole of ADR 0003 — so nothing could check one at
  scan time, and it is 3 309 bytes besides. The signature is Ed25519; against
  the §18 adversary, who forges Ed25519, it is no protection, and it was never
  meant to be: the commitment exists for that adversary, the signature for
  everyone without the code owner's key.
* **The account key as the signer on a linked device.** A linked device holds
  no account seed. The device's own key signs, over the account's commitment,
  and the certificate already in the code is what lets the device speak for
  the account (§18.7).
* **Treating every unsigned commitment as a candidate, a first add included.**
  Every code in the field today is unsigned. Demoting all of them would end
  ADR 0003's binding — the automatic refusal of a substituted key — for every
  contact added from an older peer's code, to protect a first add from an
  attacker who, able to alter the code before its first scan, could replace
  the whole identity in it instead. That attacker is what comparing the number
  catches (R37).
* **Refusing every unsigned commitment for a contact already held.** It would
  end ADR 0021's second path — re‑scanning to upgrade, for two people in the
  same room — for every pair with a peer on an older build, including when
  the code agrees with the key exactly.
* **For the flip: recording a connect confirmation as unverified until the
  key lands, or not recording it.** Either throws away a comparison that was
  made, and the post‑quantum number cannot be recorded at the ceremony: it
  needs the key, which is not there yet.

## Decision

**1. A code signs its commitment.** A new optional member (§18.10):

```
pqcs       = Ed25519.Sign(ed_sk, input)                    64 bytes, base64
input      = utf8("z-pqc-sig-v1:") || account_ed (32) || pq_commit (32)
account_ed = acct when the code names one (§18.7), else ed
```

A decoder refuses a code whose `pqcs` is present and malformed or does not
verify — checked after `sig` and `cert`, so the account it names is already
proven — and refuses `pqcs` without `pqc` rather than read the code as a
classical one. A code with `pqc` and no `pqcs` decodes, as an **unsigned**
commitment: what every code issued before this looks like.

**2. A signed commitment is evidence, and nothing about it changes.** It is
held, a key is checked against it, a key that misses it is refused, and a
re‑scan whose signed commitment differs from the one held is refused as a
change of identity — today's answers, kept.

**3. An unsigned commitment, for someone already held, is a candidate.**
Anyone could have written it, so it is treated as ADR 0021 treats a key
nothing commits to:

* with a candidate key held, one that matches it is **established** (as
  ADR 0021's re‑scan always did) and one that misses it is not refused — the
  CODE is refused, and nothing held changes;
* with nothing held yet, it is kept (`pqcc_<rid>`) for the key to be checked
  against when it arrives: a key that matches is established, one that misses
  is kept as an ordinary candidate, and the commitment goes;
* it never sets the refusal (`pq_mismatch`), never writes "do not rely on
  this chat", and is never mirrored or carried as a commitment.

**4. Stripping is detectable once a contact is known to sign.** A contact
whose commitment has been seen in a signed code — the one held, or one that
established their key — is recorded as such (`pqcs_<rid>`); a later code for
them with no `pqcs` — `pqc` present or not — is refused, says that it may be
an old code of theirs or one somebody stripped, and changes nothing.

**5. An unsigned commitment on a first add is held as before.** There is
nothing to poison, and for that case the residual is R37's (above).

**6. A connect confirmation carries what it covered.** When the ceremony's
confirmation is recorded, the commitment the digits covered for the contact
is kept beside the tick (`vpqc_<rid>`) if it is the commitment the record
holds. When the key that matches it is established, the tick moves onto the
post‑quantum number in the same write that installs the key — no window in
which "re‑verify" is observable — and the record of the commitment goes. A key
the digits did not cover gets §18.5's answers unchanged: one that misses the
commitment is refused and moves no tick; a key after a ceremony that covered
no commitment (the peer revealed a classical code) is a candidate, and when
its number shows, the tick asks for a comparison.

**7. Where the state lives.** Three sealed `kv` families, `pqcs_`, `pqcc_`
and `vpqc_`, listed in `ChatService.contactKvFamilies` so a deleted contact
takes them with it. No vault schema change.

## Consequences

* **The code is longer.** 64 bytes of signature is ~130 characters once
  encoded twice (base64 inside base64url): a root device's code from 370 to
  500 characters, a linked device's from 742 to 872 (`v3/contact_code_pqc_sig.json`
  records both). At error correction L, as the app draws it, the QR symbol
  goes from version 13 (69×69 modules) to 15 (77×77) for a root device's code
  and from 19 (93×93) to 21 (101×101) for a linked device's — measured with
  the `qr` package the app's QR widget uses. The linked device's code passes
  the ~800 bytes ADR 0003 called comfortable for cheap cameras in bad light,
  and stays far inside what a QR code holds.
* **Connect frames are not padded (§20.5)**, so a reveal's length now says
  whether the revealing app signs its commitment — as it already said whether
  its code is account‑anchored and how long its name is.
* **Not in a backup.** After a restore, whether a contact signs is forgotten
  until their next signed code is seen, and a stripped code is not surfaced in
  the meantime (it is refused or ignored as before: nothing is downgraded). A
  tick that moved is in `verified_sn`, which the archive carries; a
  `vpqc_` matters only for the seconds between a ceremony and the key.
* **Not mirrored to the account's own devices.** §18.8 carries `pqc` and
  `pqk`, not `pqcs`; each device learns that a contact signs from a code it
  sees itself.
* **Wire:** one optional member in a code (§14). Every frozen vector file is
  byte‑identical; `v3/contact_code_pqc_sig.json` is new, reproduced by
  `protocol/tool/vectors.dart` and re‑derived by the clean‑room verifier in
  `server/test/vectors.test.js` with Node's own Ed25519.
* **R37** records what remains: codes issued before this, a first add, and an
  Ed25519 signature against the adversary §18 is about.

## Exit criteria

`app/test/pq_screens_test.dart` criteria 1–6 (criteria 7–9 are 26.3's screens)
and `protocol/test/pqc_signature_test.dart` (8), each shown failing on the
code before it where it could be expressed there.
