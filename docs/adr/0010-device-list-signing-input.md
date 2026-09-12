# ADR 0010 — The device-list signature must cover the ratchet keys

**Status:** **Proposed** 2026‑09‑12 — awaiting a decision, because the
migration is the hard part and its shape depends on when it lands ·
**Roadmap:** revision 48 · **Decides:** what `SignedDeviceList` signs, what
its fingerprint commits to, and how a population that is half upgraded gets
from one to the other without false transparency alarms or invisible devices.

## Context

An independent review of the client (2026‑09‑12) found that the account's signature over a device list does not cover the
devices' ratchet keys. `SignedDeviceList.signingInput` is

```
z-devlist-v1: || "<version>:" || sorted(deviceEdPub)
```

— the version and the membership, and nothing else. Each device's
`deviceXPub` and `deviceId` are covered only by that device's own
`DeviceCertificate`, which is signed with Ed25519 alone.

That is exactly the gap §18 exists to close, one level down. §18's adversary
is one who can forge Ed25519 and cannot forge ML‑DSA: `adr/0004` decided that
the account signs the *list* rather than each certificate, so that such an
adversary cannot present a subset of a genuine list as the whole of it. But
`HybridDeviceListSignature` signs the same bytes as the classical half, so
the post‑quantum half covers the version and the Ed keys too — and nothing
else. Take a genuine hybrid list, keep every device Ed key (so membership,
every routing id, and the fingerprint are untouched), replace one device's
`deviceXPub` with a key the adversary holds, forge the per‑certificate and
list Ed25519 signatures, and ship it with the **original, untouched** ML‑DSA
signature. It verifies. Contacts install it as `hybrid` and open ratchets to
the adversary's key for that device.

`HybridDeviceCertificate` — the one object whose post‑quantum half does cover
`deviceXPub` — exists in `identity_v3.dart` and is never constructed in
shipped code.

Two things make this less urgent than it sounds, and one makes it more so.
Less: it needs an Ed25519 forgery, so it is the future adversary §18 hedges
against rather than one who exists; and the same forgery already buys a lot
elsewhere. More: **the fingerprint is blind to it too.** The 16‑byte
commitment gossiped between contacts (7.7a) and destined for the log (§19) is
`SHA‑256(signingInput)[0..16]`, so two lists differing only in a ratchet key
have the *same* fingerprint. Every transparency mechanism Z has — gossip, the
log, the own‑account monitor — compares fingerprints. None of them can see
this substitution. So the fix is not only "sign more bytes"; it is "commit to
more bytes", and the fingerprint is the value the whole of §19 is built on.

## The decision to make

Not *whether* — the signature and the fingerprint should cover every field a
device certificate binds. What needs deciding is the migration, because the
naive change breaks two things at once, and the second is worse than the bug.

**Changing the fingerprint changes what gossip compares.** A 2.8.5 client
holding a 2.8.4 contact's list must compute the same fingerprint that contact
claims for it, or every pair of differing versions raises
`changedUnexpectedly` — the alarm that tells a user their contact's device
list moved when they were not looking. Making users doubt a true statement is
a real cost, and the mechanism's value is that its alarms mean something.
This one is solvable: the fingerprint follows the format the list was
*signed* under, so a v1 list keeps its v1 fingerprint wherever it is held.

**A v2‑signed list does not verify on any installed client.** This is the
one that decides the shape. Every 2.8.4 and earlier client verifies the
signature over the v1 input; a list signed over a v2 input fails that check
and `_installContactDeviceList` refuses it outright. So the moment a 2.8.5
user adds or removes a device, their new list is invisible to every contact
who has not updated — their new device receives nothing, and no message says
why. A change that makes new devices silently unreachable is worse than the
hole it closes.

### Recommended: dual signatures, one switch-over, before G3

1. **Sign both.** A 2.8.5 list carries `sig` over the v1 input (so installed
   clients keep verifying it) and a new `sig2` over
   ```
   z-devlist-v2: || "<version>:" || for each device, sorted by deviceEdPub:
                    deviceEdPub || deviceXPub || u16be(len(id)) || utf8(id)
   ```
   The id is length‑prefixed because it is variable and is not last within an
   element. `HybridDeviceListSignature` signs the **v2** input, so the
   post‑quantum half is the half that gains the coverage — which is the whole
   point, and it means the substitution above stops working against any list
   a 2.8.5 client produced even while `sig` is still accepted.
2. **Verify strictly where it counts.** A 2.8.5 client requires `sig2` when
   present, and requires it to be present on any list whose version is above
   a floor it records per account (so a downgrade to v1‑only cannot be
   replayed at a higher version). A list with no `sig2` and a version at or
   below the floor verifies on `sig` alone, and is reported as
   `DeviceAssurance.classical` — which is already the state for "no
   post‑quantum signature over this version".
3. **Fingerprint follows the signature.** `fingerprint()` commits to the v2
   input when the list carries `sig2`, and to the v1 input otherwise, so two
   parties holding the same list bytes always agree. The format therefore has
   to be a property of the list object, discovered when it verifies.
4. **Do it before the log goes live (G3).** Nothing is published yet — G3 is
   ❌, "built end to end, not deployed" — so today the only fingerprints in
   existence are gossiped between clients and stored locally. After the log
   is live, every changed fingerprint is a republish and a migration of
   `kt_own_known`, the log's own history, and any mirror. **This is the
   cheapest week this change will ever have**, and that is the strongest
   argument for deciding it now rather than after 17.x.

### Rejected

**Change the input and accept the break.** One context string, no dual
signature. It is the fix the finding literally asks for, and it makes every
2.8.5 user's new devices unreachable by every contact who has not updated,
silently. Rejected on that alone.

**Ship `HybridDeviceCertificate` instead.** Per‑certificate post‑quantum
halves would cover `deviceXPub` — and `adr/0004` already decided against
them for the reason that still holds: a set of individually valid
certificates does not authenticate the *set*, so the subset attack comes
back. It would also add an ML‑DSA signature per device to every list, where
one per list is what 0004 measured and chose. The right answer is to widen
what the list signature covers, not to move it.

**Do nothing until the log is live.** Defensible on urgency — the attack
needs an Ed25519 forgery — and wrong on cost: the same change after G3 has to
migrate published data, and the fingerprint is the value the log's leaves
commit to.

## Consequences if accepted

- One protocol version bump, `z-devlist-v2:`, new vectors beside
  `v3/device_cert_v3.json`, and §3.4/§18.9 gaining the second signature and
  the floor rule.
- `SignedDeviceList` gains a discovered format and a second signature member;
  `verify()` becomes "verify what is there, require what the floor demands".
- Lists already gossiped keep verifying and keep their fingerprints. Nothing
  a user currently sees changes, which is the test of a good migration here.
- The window closes when the floor can be raised unconditionally — one
  release after the population has moved, which `PROVENANCE.md`'s Play
  figures can tell us rather than a guess.
- `HybridDeviceCertificate` stays unused, and should be deleted or marked as
  such: an unused signed object in a crypto library is a loaded gun (the
  review found it because it went looking for what covers `deviceXPub`).

## Why this is an ADR and not a patch

The builder that found the hole also built the pairing fix beside it
(§10.1, shipped in this release) because that one changes no published bytes
and no installed client's ability to verify anything: pairing is a one‑off act
between two devices one person holds, both of which they can update, and
failure is a visible "update the other device" rather than a silent
unreachability. This one is the opposite: the code change is small and the
migration decides whether it is safe. The working rule for exactly this case — the ADR is written before the build so the build
has something to disagree with.
