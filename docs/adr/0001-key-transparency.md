# ADR 0001 — Key transparency for Z

**Status:** Accepted (2026‑09‑04) · **Roadmap:** 7.7 · **Supersedes:** the
"key transparency, design note first" placeholder in ROADMAP.md.

## Context

Z has **no key directory**. Identities are exchanged out‑of‑band as contact
codes (`zc1.`/`zc2.`), verified by safety numbers, and an account's device set
is an account‑signed list (PROTOCOL.md §3.4) distributed to contacts inside
the ratchet. The relay stores nothing and learns nothing about keys. That is
the whole point of the design — and it means the classic key‑transparency
problem ("is the directory serving me the real key?") does not exist here.

What *does* exist is a set of threats the current design cannot make
visible:

| # | Threat | Today |
|---|---|---|
| T1 | **Silent device enrolment.** Whoever holds an account's root seed (a stolen backup, a compromised device that held the root, a coerced owner) signs a certificate for a rogue device and a new device list. Every contact's app fans every message out to it. | Undetectable by the legitimate user: their own devices keep working. |
| T2 | **Split view.** The same attacker sends the rogue‑inclusive list only to some contacts (or only to contacts, never to the owner's other devices), so no single party sees anything odd. | Undetectable. |
| T3 | **Silent removal.** The attacker publishes a list that omits the owner's honest device; contacts stop delivering to it. | The honest device simply goes quiet. |
| T4 | **Identity reset.** The owner loses every device, generates a new identity and hands out a new code. | Contacts see a changed safety number only if they look. |
| T5 | **Out‑of‑band code substitution** at exchange time. | Safety numbers, if compared. No mechanism can fix an exchange the attacker fully controls. |

The zero‑trust plan (Z‑messanger plan §5.3, flaw F2) calls for an IETF
KEYTRANS‑style log: an append‑only Merkle tree with signed, mirrored tree
heads, inclusion/consistency proofs verified by clients with hard‑fail
semantics, and self‑monitoring. That design assumes a server with durable
storage and an operator. Z's relay is RAM‑only by design, and the project
currently has one operator and no user base. A log also has a cost the
rest of Z was built to avoid: the log operator learns which accounts exist
and when their device sets change.

## Decision

Two phases, designed so the second is a strict add‑on to the first:

**7.7a — Device‑list transparency by gossip (build now).** Make T1–T4
detectable with *no new infrastructure* by having the people who already
receive an account's device list — its contacts and its own devices —
continuously cross‑check what they were told, inside the existing
end‑to‑end channel. The relay stays zero‑knowledge; nothing leaves the
ratchet.

**7.7b — Public transparency log (deferred; trigger: public launch with an
operator committed to durable infrastructure).** A separate service, not
the relay, committing to exactly the values 7.7a already gossips (the
device‑list signing input), so that adding it changes nothing on the wire
except the proofs. Until then, ROADMAP 5.2's auditor scope states plainly
that Z has no directory and no log, and what that does and does not mean.

### 7.7a in detail

All new members are *compatible extensions* under PROTOCOL.md §14: new
optional inner‑message members and one new inner kind, ignored by older
clients.

1. **Fingerprint.** For a signed device list `L` at version `v` (§3.4):
   `fp(L) = SHA256(signingInput(v, devices))[0..16]` — the same bytes an
   account key signs, so a fingerprint commits to the exact device set.
2. **Claim.** Every inner message a device sends carries
   `"dl":{"v":v,"h":b64(fp)}` for the *sender's own account's* current list
   as that device knows it (a one‑device account claims `v = 1` over its
   single legacy device). ~30 bytes, inside the ratchet.
3. **Echo.** Every inner message also carries, for the *recipient's*
   account, the newest verified list the sender holds:
   `"pdl":{"v":v,"h":b64(fp)}`. Omitted if none is held.
4. **Receiver rules, per contact account:**
   * keep the latest `(v, h)` claimed by each of the contact's devices;
   * **conflict** = two devices of the same account claim the same `v` with
     different `h`, or a device claims a `v` *below* one it claimed before →
     surface: *"Alice's devices disagree about her device list. One of them
     may not be hers — check with her before continuing."* Sends are not
     blocked (Z is not the user's guardian) but the thread shows the banner
     until the user acknowledges it or a consistent list arrives at a higher
     version;
   * a claimed `v` higher than the verified list held → wait for the root
     device's broadcast (it goes to every contact); if it has not arrived
     after a grace period, show *"Alice's device list changed but the update
     never arrived"*.
5. **Owner rules, per own device:** on every echo `pdl` received from a
   contact, compare with the list this device last received from the root
   device (its *own* knowledge of its own account):
   * echo `v` higher than known, or same `v` with a different `h` → surface
     loudly: *"A contact was given a device list for your account that this
     device never received. Another device holding your account key may have
     enrolled a device. If that wasn't you, reset your identity now."*
     This is T1/T2 made visible to the one party who can act on it.
6. **Removal notice (T3).** When a contact installs a verified list that
   *removes* devices it previously held, it sends each removed device one
   final inner message of kind `dlrm` `{acct, v, h}` over the still‑known
   pairwise session before forgetting it. A rogue device cannot suppress
   this: it is sent by contacts, not by the account. The removed device
   shows: *"This device was removed from your account at list version v.
   If you did not do this, your account key is compromised."*
7. **Reset visibility (T4).** Already partly covered: a new identity is a
   new account key, so a contact's safety number changes. Add: when a
   contact re‑adds a name that maps to a *different* account key, the
   thread shows *"New identity for Alice — safety number changed"* until
   verified. No new wire format.
8. **Root discipline.** A root‑holding device MUST send every new list to
   the account's own other devices (via self‑sync) before or together with
   contacts, so the owner's devices always know the latest legitimate `v`.
9. **Test vectors / spec.** `dl`, `pdl`, `dlrm` and `fp` are added to
   PROTOCOL.md §6.2/§3.4 and to the `inner_messages` vector suite.

**Definition of done (7.7a):** an integration test in which an account with
two devices has its root seed used by a third, rogue device to publish
version `v+1` (a) to contacts only, and (b) with the honest device removed —
and in both cases the honest device and at least one contact surface the
corresponding alert, while an honest device addition at `v+1` distributed
to everyone raises nothing.

## Options considered

**A. Status quo** — safety numbers and signed device lists only. Rejected:
T1–T3 are exactly the failure mode Wickr's model was criticised for
("trust the directory"), transposed to "trust whoever holds the root".

**B. Gossip (chosen for 7.7a).** No infrastructure, no metadata, works
inside the zero‑knowledge relay model, and the mechanism is precisely the
data the protocol already moves. Limits, stated honestly: detection needs
the honest device to hear from contacts (an attacker who also blocks the
network to that device wins, but then the device notices silence), and a
fully offline attacker who controls *every* channel of a victim can always
present a consistent lie — which no transparency design fixes either
without a globally consistent log.

**C. Public log now (KEYTRANS).** Strongest guarantee; rejected *for now*
because it needs durable infrastructure Z deliberately does not run, an
operator commitment, a mirror/witness, and it introduces a metadata
surface (who exists, when their devices change) that needs VRF‑keyed
entries to mitigate. It remains the plan for 7.7b, and 7.7a's fingerprints
are its leaf values.

**D. Third‑party witnesses / blockchain anchoring.** Rejected: adds a
dependency and a payment/operational surface for a guarantee C provides
more simply once C exists.

## Consequences

* Every inner message grows by roughly 60 bytes (two fingerprints). Padding
  to 256‑byte blocks absorbs this for most messages.
* New user‑facing states (three banners, one alert). The UI must not cry
  wolf: a version bump seen from a contact *before* the root device's list
  arrives is normal for a few seconds and must not alert until the grace
  period elapses.
* PROTOCOL.md gains §6.2 members and §3.6 "device‑list transparency";
  `inner_messages` vectors gain the new members; no version bump.
* 7.7b becomes a service design (Postgres, signed tree heads, git mirror,
  proofs API) with clients treating the log as an *additional* source of the
  same `(v, fp)` facts.

## References

* Z‑messanger Zero Trust Integration Plan §5.3 (F2) and §7 Phase 5.
* IETF Key Transparency architecture / protocol drafts.
* PROTOCOL.md §3.4 (signed device list), §6 (inner messages), §9 (self‑sync).
