# ADR 0019 — Group admin roles: an owner, co‑admins, and one rule for who wins a race

**Status:** **Proposed** (2026‑09‑20) — awaiting Finnian's decision before it is built (23.1b).
**Decides:** who may change a group's membership and name besides its creator, how
every member converges on one list when two of them change it at once, and what a
client that predates this does with a list it does not fully understand.

## Context

A group has exactly one admin: its creator. `Group.adminRid` is `''` on the creator's
own devices and the creator's routing id everywhere else, set from whoever sent the
first invite. A member accepts a `ginvite` only from that rid and only at a higher
`ver`; add, remove and (since 23.1) rename are creator‑only. This is simple and it is
safe — nobody but the creator can move the list — and it has one cost that users hit:
**when the creator is gone, the group is frozen.** Lost phone, left the group, stopped
using Z: nobody can add, remove or rename again, ever. That is the whole case for roles.

What must survive any answer:
- **No shared group key** (the standing non‑goal). Roles are about *who may issue a
  list*, not about keys; fan‑out stays pairwise.
- **A member removed before a send never receives it** — membership is snapshotted at
  queue time (15.3, 23.2). Roles must not add a path around that.
- **Only someone already trusted can change the list.** Today the pairwise channel
  authenticates *who sent* the invite and `adminRid` authorises them. Roles widen the
  authorised set; they must not weaken the authentication.

## Decision (proposed)

**An owner plus co‑admins, carried in the list itself, with the owner winning every
tie.** The invite gains two optional members — `owner` (a routing id) and `admins` (a
list of routing ids, always containing the owner) — beside `members`, `name` and `ver`.

- **Who may do what.** Co‑admins may **add and remove members and rename**. Only the
  **owner** may **promote, demote, or transfer ownership**. So changes to the *admin
  set* are serialised through one device, and everything else is not.
- **Authorisation on receipt.** A member accepts an invite only if its sender is in the
  admin set the member *currently holds* (the owner is always in it). A demoted admin
  who still holds the old list cannot re‑admit themselves: the members hold the newer
  list, the sender is not in it, the invite is dropped — exactly what happens to a
  removed member's messages today.
- **Ordering, and the race.** A change is stamped `(ver, by)` — the version and the
  sender. A member accepts an invite if `ver` is higher than what it holds, **or** equal
  and the sender ranks higher, where **the owner outranks every co‑admin, and co‑admins
  rank by routing id**. Two co‑admins who both bump from `N` to `N+1` at once produce
  two lists; every member — including both admins, who are members too — converges on
  the same one, and the loser sees the winner's list arrive and simply redoes their
  change at `N+2` (the screen says "the group changed under you, try again"). Nothing
  is rolled back: an accepted list is only ever *replaced* by a later full list. And the
  case that matters for safety — the owner demoting a co‑admin while that co‑admin
  makes a change — always goes the owner's way, whatever the rids.
- **Ownership transfer** is an owner‑only change of `owner`; the old owner stays a
  co‑admin unless the same invite demotes them.
- **If the owner is gone,** co‑admins can still run the group day to day; the admin
  set is frozen. That is a deliberate, documented limit: the alternative — any admin can
  promote — reopens the demote/re‑admit race with no one to win it. Owners who leave
  should transfer first; the Leave dialog says so when the leaver owns a group.

## What the wire sees, and old clients

`owner` and `admins` are **new optional JSON members** of an existing sealed inner
message — compatible evolution under PROTOCOL §14, no version bump, and the relay sees
the same 4 096‑bucket envelope it always did. But a client from before this ADR treats
whoever sent it its first invite as *the* admin. If a **co‑admin** adds such a client,
that client will thereafter reject the owner's invites as coming from a non‑admin and
drift. Two mitigations, to choose between:

1. **Old clients are only ever added by the owner.** A co‑admin's add is carried out by
   the owner's device when it next sees the change — one extra hop, no drift, but
   "add" from a co‑admin is not immediate for members on old builds.
2. **Accept the drift for old clients** and rely on the version notice (24.4) plus the
   floor: co‑admin adds are enabled only once the operator's `Z_LATEST_VERSION` floor
   is at or above this release. Simpler; leaves a window.

The proposal recommends **(2)** with the floor — the population that would drift is the
one the notice is already nagging — but this is the one point where the answer is
Finnian's.

## Rejected

- **Any admin may promote/demote (a flat admin set).** Convergent under the same
  `(ver, by)` rule, but a co‑admin being demoted can win the race by rid and stay in.
  Serialising admin‑set changes through the owner removes the race that matters.
- **Signed lists (the admin signs the membership with a group key).** Would let a member
  verify an invite without holding the sender's channel — but every member *does* hold
  the sender's channel, that is what makes them a member, and a group signing key is a
  shared key by another name. Rejected on the standing non‑goal.
- **Vector clocks / CRDT merge of member sets.** Converges without dropping anyone's
  change, at the cost of a merge nobody can predict from their screen ("I removed him;
  why is he still here?"). Membership is a security decision; a dropped‑and‑redone
  change is legible, a merged one is not.
- **Proposals to the owner (co‑admins request, the owner applies).** No race at all, and
  no use when the owner is the one who is gone — which is the case this exists for.

## Consequences (if accepted)

- **Wire:** two optional members on `ginvite`; §11 documents them; vectors extended.
- **App:** `Group` gains `ownerRid` and `adminRids`; `iAmAdmin` becomes "I am in the
  admin set"; `addGroupMembers` / `removeGroupMember` / `renameGroup` check it; new
  `promote`, `demote`, `transferOwnership` (owner‑only); the receive path enforces the
  authorisation and ordering rules above; the group info screen shows roles and offers
  the owner the three new actions; the Leave dialog warns an owner.
- **Tests (exit criteria):** a co‑admin's add/remove/rename reaches everyone; a demoted
  admin's invite is dropped by every member; two co‑admins racing converge on one list
  on every device and the loser can redo; the owner beats a co‑admin in a race whatever
  the rids; transfer works and the old owner is demoted or kept as chosen; a member
  removed before a send by a co‑admin never receives it (the snapshot property, again).
- **THREAT_MODEL:** a row for "a co‑admin is a trusted party for membership" — the
  trust the owner extends by promoting, and what a malicious co‑admin can do (add a
  stranger, remove everyone but themselves) and cannot (read history they were not sent,
  or survive demotion).
