# ADR 0030 — A group's timer is part of its list, and a leave is remembered against lists from before it

**Status:** **Proposed** (2026‑10‑09) — built (23.4–23.5, unreleased). Adds
PROTOCOL §11.2 and a vector file, `docs/vectors/v1/group_state.json`;
extends ADR 0019. THREAT_MODEL R38 is updated in place.
**Decides:** where a group's disappearing‑messages timer lives, who sets it,
what it governs and what a member on an older build does with it; and how a
member who left stays out of the group when a list issued before their leave
reached its issuer still names them.

## Context

**Group messages never expire** (the 2026‑10‑03 analysis, §3: "Disappearing
messages: 1:1 only"). A 1:1 chat has a timer, set by either person, carried
by a `timer` inner message and stamped on every message as `ttl` (§6.1);
since 30.3 it reaches every device of both people. A group had nothing: no
setting, no `ttl` on `gmsg` or `gfile`, and a receiver that stored every
group message with no expiry whatever it carried.

**A leaver was put back by a list issued before their leave reached its
issuer** (THREAT_MODEL R38, as it stood: "that predates roles and is kept").
A leave changes no version (ADR 0019, departure 2, for a reason that still
holds), so an admin who has not heard of it issues the next list naming the
leaver, and every member takes that list — the leaver's own device included,
which showed the group as joined again — until a list without them. Whether
a member held the leaver afterwards depended on which of the two envelopes it
read first, and a member that held them went on sending them every message.
`group_timers_test` 5 reproduces it on `0d00a69`, the base of this change:
the owner's member set, after a co‑admin's rename built before Max left
arrived there after his leave, held Max's routing id again —

    00:13 +0 -1: 5. a list issued before a leave reached its issuer does not put the leaver back [E]
      Owen5: a list issued before the leave reached its issuer does not put the leaver back

What any answer must keep: no group key and no server‑side group (the
standing non‑goals); the snapshot property — a member removed before a send
never receives it (15.3, 23.2) — which ADR 0019 relies on; one list per
version on every device that holds it (ADR 0019's convergence); and wire
evolution that an older client reads as it always did (§14).

## Decision

### 23.4 — the timer is in the list

**A group's timer is a member of its list, `tmr`, and changes the way its
name does.** Whoever may issue a list may set it — the owner and the admins,
as for a rename (ADR 0019) — and setting it is a list at the next version,
ordered, refused, held back and asked for (`gsync`) by exactly the rules
every list is. The list is the only group state Z has, so every member that
holds a list holds its timer; nothing else needed inventing.

* **What it governs.** Every group message a client sends while the timer is
  on carries it as its `ttl`, and §6.1 applies unchanged: the sender's copy
  goes that long after it was sent (its mirror on the sender's other devices
  with it — 30.3's door), every other copy that long after it arrived. Every
  device of every member stamps the timer of the list it holds; a linked
  device holds the list as its account does, so a laptop's message carries
  it as the phone's does. A receiver keeps the `ttl` a message carries, as it
  does in a 1:1 chat, rather than timing it by its own copy of the timer.
* **Absence means off.** A list without `tmr` states that the timer is off,
  so what a member holds is a function of the list it holds and nothing else
  — which is what makes two members holding one list agree. A sender writes
  `tmr` once its group has had a timer, `0` once it is turned off.
* **Ties.** Two admins setting two timers on one list at one version make
  two lists §11.1's digest cannot tell apart: it leaves the timer out. They
  are ranked by a second digest, over the timer and the positions below,
  only between lists the first calls equal — so a client before this record,
  comparing the first alone, ranks every pair it can tell apart exactly as a
  newer one does. The loser is told its change did not stand, as ADR 0019
  tells any admin whose change another list undid.
* **The notice.** The words a 1:1 chat uses — "Ada set disappearing messages
  to 1 hour", "Ada turned off disappearing messages" — on every device of
  every member, the setter's own as "You", and a newcomer to a group with a
  timer told so; each timer notice adds what a member on an older version
  does with it. A list that turns the timer off by carrying none is said as
  that — "Ada's change to the group came without the group's timer" — not as
  "Ada turned off disappearing messages", which she did not choose.

**The honest limit.** A member whose app predates this record ignores `tmr`,
and the `ttl` on a group message. It keeps every group message, and what it
sends carries no timer, so nobody's device times it; and as an admin, its
lists carry no `tmr` and turn the timer off. Nothing a newer client can do
changes what an older one keeps — and nothing in a group tells one client
which build another runs — so the notice says it, every time a timer is
announced: "A member whose app is older than this version keeps the
messages, and theirs do not disappear." The timer is a courtesy among
clients that keep it, as it always was in a 1:1 chat (R13).

### 23.5 — a leave is remembered, by position

**Every member a list adds after the group was made is named, in that list
and every later one, at its position** — the `[rv, ver]` of the list that
added them, an optional `e` on their entry; a member since the group was
made has none, position `[0, 0]`. **A leave is remembered** by every device
that hears it — the leaver's own included — with the position of the
membership it ends, which the leave states (`e`) and the device also holds.

**A list that names someone this device has heard leave, at that position or
an earlier one, was issued before the leave reached its issuer, and is taken
without them.** A list that adds them back names them at its own position,
and that position is later than the one they left: a list is taken only
above the one held, and the list held named them where they left. So the rule
tells the two apart on every device, by what the list says and what the
device heard, whichever arrived first. The list passes ADR 0019's checks as
its issuer wrote it — the issuer's standing, the roles, the admins it keeps —
and only then loses the leaver; everything else it changed stands, and its
issuer's change is not undone.

* **The leaver's own device** stays out. A list naming it at its leave's
  position or earlier is taken there as everywhere, without it: the group
  stays left, and nothing is said, neither "you were removed" nor joined
  again. Taking it, rather than dropping it, is what keeps that device in
  step: the list it holds ranks the next one as every other device's does, so
  a list adding the leaver back that lost to it elsewhere — the owner's list
  from before the leave outranks a co‑admin's re‑add at its version — does
  not bring them back there alone (`group_timers_test` 11). A list naming it
  later is an admin adding it back, and says who did.
* **Against the snapshot property ADR 0019 relies on.** The rule only ever
  takes a member out of what a device holds, never puts one in; every send is
  snapshotted from the list held (15.3); so what a device queues after it has
  heard a leave reaches no one who had left, whichever list it took since.
  Before, the list from before the leave put the leaver back on the members
  that read it after the leave, and their next messages went to the leaver —
  whose own device, joined again, showed them (`group_timers_test` 5 counts
  the queued rows). Convergence is unchanged too: two devices that heard the
  same leave and hold the same list hold the same members, and a list
  replaces the held one wholesale as before; the leave is local memory, as a
  leave always was — it already took the leaver out of this device's copy
  without a new version.
* **Why every add, and not only re-adds.** An admin cannot always know that
  the person it adds once left: it may have missed the leave and taken a
  later list without them, or joined the group after they went. Marking only
  the adds the issuer knows to be re‑adds would leave such an add unmarked,
  and every device that remembers the leave would drop the member again —
  their own device included — for good. Measured, a position costs about ten
  bytes in the list a member added: from five members, a list of a group
  grown one add at a time needs one 256‑byte padding block more than the
  same group made at once (`group_timers_test` 9 prints the table). Lists go
  out only when the group changes.
* **A leave ends the membership it states.** Every leave from a client
  since this record carries `e`, `[0, 0]` included; one without it is from an
  older build, and ends the membership the device holds. A device that holds
  the leaver at a later position than the leave states got the list adding
  them back before the leave: it remembers the leave and keeps them, as a
  device that heard the two the other way round does — where a device that
  read the leave as ending what it held would drop them, and then read every
  later list as one from before the leave, for good (`group_timers_test` 10,
  a member's device and the leaver's own laptop). A device that never got
  the list adding someone back remembers their second leave at the position
  it states, and for someone it holds out of the group too, once it has known
  them in it — so it still reads the lists from before that leave as such. A
  device does not remember a leave for someone it has never known in the
  group: nobody can plant one.

**What a build from before this record does.** It remembers no leave and
reads no position, so it puts a leaver back from a list issued before their
leave, as every build did. As an admin, its lists name every member at no
position: it cannot add a leaver back on a device that remembers the leave,
and any change it makes to the group is read there as a list from before
that leave — a member who left and was added back is taken out by it, on
every such device, their own included, which is told it was removed. That is
the cost of reading a list as the snapshot it is: nothing a newer client
could do with such a list tells it from one issued before the leave, and a
rule that kept the member by what each device had seen before would split
the group whenever a list adding them back raced one from before the leave.
And a leave a device heard before it ran this build was never remembered:
there, a list issued before that leave still puts the leaver back, as it
always did.
The version notice (ADR 0014) is shown to exactly those builds.

## Rejected

* **A timer outside the list** — its own inner kind, sent by an admin. It
  would need an order of its own, and two admins setting it at once would
  split the group; the list already has the order, the authority and the
  catch‑up (`gsync`).
* **Every receiver times every group message by the timer it holds.** A
  message without `ttl` is then ambiguous — sent with the timer off, or by an
  older build — and a member still holding the old timer deletes, in the race
  after an admin turns it off, what everyone else keeps. Stamped by the
  sender, a message carries its own answer, as in a 1:1 chat.
* **A list without `tmr` keeps the timer held.** Then what a member holds
  depends on the lists it read, not on the list it holds: two co‑admins
  racing, one setting the timer and one renaming, left the members who read
  them in different orders on different timers, for good. Absence as off
  keeps one list one timer; its cost, an older admin's change turning the
  timer off, is said in the chat as what it was.
* **Moving the version on a leave again.** ADR 0019's departure 2: with
  several admins it holds one list at two versions, and a co‑admin's change
  made before it heard of the leave is refused by every admin and taken by
  every member (`group_roles_test` 9).
* **Telling a stale list by its version.** A leave moves no version, so the
  list from before the leave and an admin's deliberate re‑add, both built on
  the version the leave happened at, carry the same version.
* **Marking the re‑adding list alone** (say, `back: [rid]`). A member that
  missed that list reads every later one — which does not repeat the mark —
  as from before the leave, and drops the member for good. The mark has to
  persist with the member: that is a position.
* **Merging lists** (ADR 0019's rejected CRDT): membership changes stay
  legible because a list replaces the held one wholesale.

## Consequences

* **Wire** (PROTOCOL §6.2, §11, §11.2): optional members only, no version
  bump — `tmr` on `ginvite`; `e` on a `ginvite` member entry and on `gleave`;
  §6.1's `ttl`, now set on `gmsg` and `gfile`. A client before this record
  reads all of it as it did, with the limits above. The state digest is a
  new derived value, pinned in the new vector file
  `docs/vectors/v1/group_state.json` (generated by `protocol/tool/vectors.dart`
  from §11.2's words; every file already in `v1/` is byte‑identical).
* **App:** `Group` gains the timer (`tmr`), the held list's state digest, the
  members' positions and the leaves heard, all sealed with the group's record
  (`DATA_MAP.md`); `ChatService.setGroupTimer` (owner and admins);
  `sendGroupText` and `sendGroupFile` stamp the timer; every receiving door
  of a group message keeps its `ttl`; the group screen shows the timer — set
  from it by an admin, through the same picker a 1:1 chat uses, which says
  what an older version does — and so does the chat's bar and the chat list.
  New `SystemKind`s: `gttl_set_you`, `gttl_set_by`, `gttl_is`,
  `gttl_dropped_by`; turning a timer off uses the 1:1 kinds. A device added
  back says who added it (`added_to_by`). Deleting a contact lets go of a
  leave of theirs with the rest of them, so a list still naming them may then
  bring them back on that device (R38).
* **Tests:** `app/test/group_timers_test.dart` (11 — the criteria in its
  header: the timer on every device of every member, a laptop included, on
  text and files, deleted on time; only an admin sets it; a member on an
  older build, and its lists; two admins' timers at one version; the leaver
  not put back, on any device; added back, everywhere, and through a member
  that missed that list; both across a restart, a deleted contact's leave
  let go, and a newcomer told of the timer; the vectors; what a position
  costs; a leave arriving after the list adding its leaver back, on a
  member's device and the leaver's own laptop; the owner's list from before
  a leave against a co‑admin's re‑add at its version, the leaver's own
  device included). `group_roles_test` 11 now
  weighs the roles on groups made with all their members, so a position does
  not move the padding it measures.
* **THREAT_MODEL R38:** what a co‑admin can do includes the timer; the
  sentence about a list from before a leave now says what this record does,
  and its residuals: a device that never heard the leave, a member on an
  older build, a deleted contact's leave.
