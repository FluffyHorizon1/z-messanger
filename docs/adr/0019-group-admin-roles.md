# ADR 0019 — Group admin roles: an owner, co‑admins, and one rule for who wins a race

**Status:** **Accepted** 2026‑09‑30, as proposed, with its one open point decided: old
clients — **accept the drift, no gate** (below). Built in 23.1b, with six departures
from the accepted text — from the first build and the two reviews of it (2026‑10‑02) —
each backed by a test and each for Finnian to confirm; they, and what the build settled
within the text, are under "As built".
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

## Decision

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

`owner` and `admins` — and, as built, a third, `rv` (below) — are **new optional JSON
members** of an existing sealed inner message: compatible evolution under PROTOCOL §14,
no version bump. They are written only when they say something their absence does not:
the owner of a group whose roles have never changed leaves them out, so that group's
invites are byte for byte what they were before this record, and every other list
carries all three (`group_roles_test` 13). This record said the relay sees "the same
4 096‑bucket envelope it always did"; that is exactly true of groups whose roles have
never changed, and only of them. Otherwise the members cost a fixed ~455 bytes on the
wire with three admins — one member's entry — so an invite needs the 16 384‑byte bucket
from 7 members, where a group with no role changes needs it from 8 (`group_roles_test`
11 prints the table).

But a client from before this ADR treats whoever sent it its first invite as *the*
admin. If a **co‑admin** adds such a client, it will thereafter reject the owner's
invites as coming from a non‑admin and drift; and one the owner added rejects every
co‑admin's list, catching up only at the owner's next one. Two mitigations were on the
table:

1. **Old clients are only ever added by the owner.** A co‑admin's add is carried out by
   the owner's device when it next sees the change — one extra hop, no drift, but
   "add" from a co‑admin is not immediate for members on old builds.
2. **Accept the drift for old clients** and rely on the version notice (ADR 0014, 24.4)
   plus the floor: co‑admin adds are enabled only once the operator's
   `Z_LATEST_VERSION` floor is at or above this release.

**Decided (2026‑09‑30): accept the drift, with no gate.** A co‑admin's add works
immediately, offline too. A member still on a pre‑0019 build who is added by a
co‑admin pins that co‑admin as its only admin and ignores the owner's later lists
until it updates; the version notice already nags exactly those builds. There is no
fetch of `/latest.json` and no routing through the owner. The floor gate of (2) was
not built because it would refuse honest adds offline, for clients that never fetched
the floor, and for every self‑hoster who never set one — to close a window that only
ever affects builds the notice is already nagging. THREAT_MODEL R38 records the drift
as a residual, including its sharpest edge: a member a co‑admin removed keeps
receiving such an old client's messages until the owner's next list reaches it.

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

## As built (23.1b)

### Departures from the text accepted on 2026‑09‑30

Six places where the build does not do what was accepted — this record's text, or
the behaviour it was accepted on top of — each because the accepted version fails a
test the departure passes. The first two came with the build; the third replaced one
that did, after the second review found it incomplete; the last three came with the
first review (2026‑10‑02), which found the build's members, linked devices and lost
envelopes splitting or freezing groups. Each is for Finnian to confirm or overrule.

1. **A roles version, `rv`: a third optional member, and `(rv, ver, by)` rather than
   `(ver, by)`.** This record has two members and orders by `(ver, by)`, and that does
   not deliver what it promises above all — that a demoted co‑admin cannot survive. An
   admin chooses whom it sends a list to: a co‑admin that sends its lists to everyone but
   the owner moves every member's `ver` ahead of the owner's, and the owner, never sent
   them, cannot know. The owner's demotion of it is then older than what every member
   holds and is discarded everywhere, and the owner's own device holds back every other
   co‑admin's later list, since those still name the demoted admin. So the owner moves
   `rv` on with every change to the roles, nobody else may, and members rank `rv` first:
   an owner's change to the roles outranks any version a co‑admin has reached, and
   replaces what it sent. **`group_roles_test` 12 fails without it** — ordered by
   `(ver, by)` alone, "the demotion lands everywhere" never comes true. Within one `rv`
   the owner cannot change, which also settles a transfer racing a co‑admin's change:
   both are ranked against the same owner on every device, whichever arrived first.
2. **A leave no longer moves the version.** Until now the admin bumped `ver` on a leave
   ("future invites exclude them"), and the plan accepted with this record kept that for
   every admin. With more than one admin it holds one list a version ahead on admins'
   devices than on members', and a co‑admin's change made before it heard of the leave
   is then refused by every admin and taken by every member — and undone everywhere,
   without a word, by the owner's next list. With one admin the bump never did anything:
   the admin's next list moved the version anyway. **`group_roles_test` 9 fails with the
   bump put back** — Bea's rename never reaches the two admins.
3. **Lists at one version are ranked by digest, the owner's first.** This record ranks
   lists at one version by their senders — the owner first, then co‑admins by routing
   id — and that fails twice. A sender never outranks itself, so of two lists one admin
   issued at one `(rv, ver)`, on two of its devices before they synced, each member
   kept whichever reached it first, and the group stayed split until the next list. And
   a routing id is not a person: a device holds a contact under the id of the device it
   added them from. The first build ranked everyone by the id held, so a co‑admin
   ranked as her laptop where she had been added from its code and as her phone
   elsewhere; ranking by the ACCOUNT instead (the first rework) needs the account, which
   a device knows only for a contact whose code said so (PROTOCOL §18.7) — not for one
   adopted from a list — so a co‑admin added from her laptop's code still ranked as her
   account on the members who had scanned it and as her laptop on those who had
   adopted her, and a tie between her and another co‑admin went one way on some
   devices and the other way on the rest, for good. Nothing a device can check makes
   it know more. So the owner's list still outranks a co‑admin's, and otherwise the
   list whose digest — SHA‑256 of a canonical form of the list as it travels, pinned
   byte for byte in PROTOCOL §11.1 — sorts first wins, whoever sent it: the same on
   every device, however it holds the issuers. A co‑admin can shape a list to win a
   tie, which wins it nothing it could not get by issuing the next version.
   **`group_roles_sync_test` 3 fails without the digest** (Cat and Dan, who heard
   Ann's two lists in opposite orders, keep different names), and **`group_roles_test`
   27 fails ranked by account** — routing ids constructed to split it: Owen and Ana keep
   Cora's list, Bo and Dan keep Dan's (run against the first rework, 2026‑10‑02).
   `group_roles_test` 18 shows the owner's list standing though its digest sorts
   after the co‑admin's.
4. **Roles move on one device of the owner's: the one holding the account root.** This
   record lets the owner promote, demote and transfer; it does not say from which
   device. The owner's phone handing the group to Ada while the owner's laptop, not yet
   synced, makes Bob an admin opened one roles version twice with two role sets, and the
   members holding one refused every list built on the other, for good: the next roles
   version could only come from an owner the two halves no longer agreed on (the review's
   R3b — "distinct owners: 2", never healing). Opened twice at the same version, the
   tie‑break of 3 and 5 converges it; opened at two different versions, nothing a
   member can do does. So the owner's linked devices add, remove and rename, and the
   device that links them changes the roles; the screen says so. The cost: an owner who
   has lost that device — and with it, already, the power to link new ones — cannot
   change the roles again until it is restored from a backup made on it (its identity
   key is the account's); until then the group runs as one whose owner has gone.
   **`group_roles_sync_test` 2** pins the refusal (and what the laptop may still do).
5. **The twin of a list that opened a roles version may carry other roles.** This record
   takes a change to the admin set or the owner only from the owner held. A list from the
   held list's own sender at its own `(rv, ver)`, when the held list opened that `rv`, is
   that owner's other opening of the same roles version; refused by its twin's roles, it
   left members holding different owners for good (the review's R3, two role lists from
   one owner). Such a twin is ranked by digest instead, and every member keeps the same
   one. **`group_roles_sync_test` 4 fails without it.**
6. **A member that had to refuse a list asks for what it lacks (`gsync`, a new inner
   kind).** This record assumes every member eventually hears every list. Delivery is not
   guaranteed (the relay keeps an envelope 72 hours, in memory), and since roles a list
   that never arrives is not always healed by the next: a member that missed one admin's
   leave holds that admin as an admin in the group and refuses every list the others
   issue without them — for good if the one who left was the owner, the case this record
   exists for (the review's R10). So a member that refuses a list for its sender's role or
   its roles asks the owner it holds and any admin the list leaves out; an admin answers
   with the list it holds, and one that has left with its leave too. It is keyless — the
   group id is all it says — and judged like any list. **`group_roles_sync_test` 5 and 6
   fail without it**: Mo never holds Ada's lists, Dee never holds Pia's rename. If the
   departed admin is gone for good, the member stays where it is (THREAT_MODEL R38).

### Decided while building, within the text

- **The tie‑break direction.** The digest that sorts **first** (plain byte order of
  its unpadded base64url) wins.
- **A member is an account.** Every routing id a list carries — member bundles, `owner`,
  `admins` — is mapped to the contact this device holds for that account (any of its
  devices) or to itself; a device names itself by its own routing id — the one id of it
  every receiver of its list has mapped, having mapped the sender; and a linked device
  writes no member entry for itself, the envelope already naming its sender. The first
  build named a co‑admin's laptop by its own bundle, so every member held the laptop as a
  second member and contact, and an owner who then removed the co‑admin kept serving her
  laptop — and her laptop and phone, each still named, never marked themselves removed
  (`group_roles_sync_test` 1).
- **The members only when they say something** (above, and `group_roles_test` 13): an
  omission is a claim — "the sender owns the group, alone, at roles version 0" — and is
  refused from anyone else exactly as that claim written out is: stale where `rv` has
  moved, held back where it has not (`group_roles_test` 14). Once `rv` has moved the owner
  must write them, even with the admin set back to just themselves.
- **An admin acts only from inside the group.** Roles change only through the owner's
  lists: leaving, or being removed, does not take a role away — it makes it unusable
  until an admin adds that person back, and the owner can take it away (the group screen
  lists admins who are no longer in the group; `group_roles_test` 25). That keeps a
  co‑admin's list from being refused for carrying a role another device has already
  dropped on a leave it saw first, and it is what makes an owner who left freeze the
  admin set rather than run it from outside.
- **A co‑admin cannot remove an admin.** Dropping one from the members demotes them as
  surely as dropping them from `admins`; and a co‑admin who could remove the owner could
  never be demoted, since an owner outside the group cannot issue a list. Removing an
  admin is the owner's, and takes the role in the same list.
- **Lists that cannot be applied yet are held back, not dropped.** Inbound envelopes from
  different people are applied in whatever order they decrypt, so a co‑admin's list can
  arrive before the promotion it rests on, or before a leave it reflects. Such a list —
  newer than what is held, refused only for its sender's role or the roles it carries —
  is kept with the group's record (one per sender, that sender's newest, eight at most;
  none from someone not in the group) and tried again whenever the held list changes,
  through every check again (`group_roles_test` 10, 21; `group_roles_sync_test` 7 across
  a restart). That is no more than the network delivering it later; a list that never
  becomes acceptable is never applied. A retry that a change interrupts goes round again
  (`group_roles_test` 24), and a list overtaken while it waited is dropped (19).
- **Lists and leaves are queued like messages.** Sent member by member with nothing
  written down, a list lost its remaining recipients to a kill part‑way — and to a
  transparency conflict with any one member, whose send throws. They go through the
  durable group fan‑out now (`group_roles_sync_test` 8).
- **The decision is atomic.** Two admins' lists can be judged at once (from a contact's
  linked device, or mirrored by my own, they are not serialised by the inbound
  transaction); reading the held list and replacing it with an await between would let
  the second overwrite the first without ever being ranked against it. Everything that
  awaits (verifying the bundles) happens first, and the members a list introduces become
  contacts in the same step as the list is installed (`group_roles_test` 18).
- **A list not shaped as §11 says is refused, never thrown on** — an `owner` or admin that
  is not a 43‑character routing id (an empty one read as "me" on every member), a version
  that is not a whole number, a name or member list of the wrong type (`group_roles_test`
  20).
- **"Changed under you"** (`change_overridden_by`) is said when a list I issued is
  replaced — at any version — by one that undoes what mine did: a member I added
  missing, one I removed back, my name gone. The first build said it only for a list at
  no higher a version than mine, and a co‑admin's second quick change, built on its own
  first, slipped past it: two admins were enough for the owner's removal to be undone
  without a word (`group_roles_test` 22). A change of mine from another of my devices
  says so as such (`change_overridden_mine`). What is still not reported: a change of mine
  carried forward by one admin and then overtaken, at that same version, by a third
  admin's list that never saw it.
- **Deleting a contact is not a change to a group.** A member whose contact I deleted is
  still named in my lists, from their entry kept in the group's record; my lists used to
  drop them, which removed them — and, for an admin, made every member refuse my lists
  (`group_roles_test` 26). The entry — their routing id, public key and name, sealed with
  the group's record — is kept while a group I am in names them (an admin who has left
  included), and goes when they are out of it, when I remove them, and when I leave or
  am removed; a group I am out of keeps nobody I deleted, and a record that has let go
  of someone is never sent as a list again, since it would remove them. A change
  someone else makes to the group meanwhile introduces them as a contact again, as it
  does any member (PROTOCOL §11); the list that removes me does not. The delete dialog
  says all of this when the contact is in a group I am in, and `contact_erasure_test`
  6–13 hold the vault to it, exactly — a group I am out of included, where the owner
  of record or the issuer of the list held, if deleted, becomes a placeholder that
  names nobody. That has a price: a list for the group names its real owner, so the
  record can no longer match its roles, and an admin's list adding me back is refused
  (14) — where it used to be taken, and to bring the deleted owner back as a contact.
  The owner's own list was refused already: deleting them took them out of its members.

## Consequences

- **Wire:** optional members on `ginvite` — `owner` and `admins`, and as built `rv` —
  written only once a group's roles have changed, and one keyless inner kind, `gsync`;
  PROTOCOL §11.1 documents them; `inner_messages.json` gained a vector for each.
- **App:** `Group` gains `ownerRid` and `adminRids`; `iAmAdmin` becomes "I am in the
  admin set"; `addGroupMembers` / `removeGroupMember` / `renameGroup` check it; new
  `promote`, `demote`, `transferOwnership` (owner‑only, and only on the device holding
  the account root); the receive path enforces the authorisation and ordering rules
  above; the group info screen shows roles, admins who are no longer in the group, and
  offers the owner the three new actions; the Leave dialog warns an owner; the transfer
  dialog warns that a member on a build from before roles cannot run the group.
- **Tests (exit criteria):** a co‑admin's add/remove/rename reaches everyone; a demoted
  admin's invite is dropped by every member; two co‑admins racing converge on one list
  on every device and the loser can redo; the owner beats a co‑admin in a race whatever
  the rids; transfer works and the old owner is demoted or kept as chosen; a member
  removed before a send by a co‑admin never receives it (the snapshot property, again)
  — and, as built, `group_roles_test` (28) and `group_roles_sync_test` (8): every rule
  of §11.1 above, one account on several devices, and members a list never reached.
- **THREAT_MODEL:** R38, "a co‑admin is a trusted party for membership" — the trust the
  owner extends by promoting, and what a malicious co‑admin can do (add a stranger,
  remove every member who is not an admin, rename) and cannot (read history they were
  not sent, change the roles, remove an admin, or survive demotion), with the old‑client
  drift as its residual — and, as built, what a lost envelope or a pre‑leave list can
  still do.
