# Using Z

Everything else in `docs/` is written for people reading the code. This one is
for people using the app.

Z is a messenger with no accounts. There is no sign-up, no phone number, no
email, no password to a server — because no server holds an account for
you. That buys real privacy and it costs a few things that will
surprise you if nobody says them out loud, so they are said out loud here.

---

## Starting

Open Z, choose a display name, and you have an identity. It exists only on
that device. Nothing was registered anywhere.

Your display name is not a username. It is a label you send to people you
add, and two people can pick the same one. What actually identifies you is a
key, and the only way anyone gets it is if you give it to them.

## Adding someone

Scan their QR, or copy the text and send it however you like. On a Mac,
where Z does not scan with the camera, you can instead **open a QR image** on
the Paste tab — a screenshot or photo of their code — and Z reads the code out
of it; Z on Windows and Linux cannot read one, so there you paste the text.
Your own code has **Copy** and **Share** on the My code tab, on every
platform. When you add someone this way, a request appears on their phone —
*someone wants to connect* — and they tap **Accept**, **Decline**, or **Block**.
They do not have to scan you back; accepting is enough.

The code you show is public. Someone who copies it can send you a request, and
that is all: they cannot read anything, impersonate you, or find out who else
you talk to — and a request that names someone really is from them, because it
is signed with their own key, so nobody can put a stranger's face on it. If you
did not want it, **Decline** drops it quietly and **Block** stops any more.
A request you declined does not come back on its own — only a new one, made
later, is shown — and Z ignores a request more than 30 days old. At most 100
wait at a time: when more arrive, the oldest you have not looked at goes
first, never one you have.

Accepting adds them, but it does not confirm *who* they are — for that, compare
safety numbers. What matters, when you *scan* someone in person, is that the
code is really theirs, which is the same thing the safety number checks.

If you cannot get in the same room, use **CONNECT** instead of sending your
code — it is below, and it ends with the two of you verified rather than
hoping.

## Adding someone you cannot meet

The CONNECT tab is for the person who is three time zones away, or just not in
the room. It works like this:

1. You tap **Create an invite**. Z shows one invite in two forms — a link and
   a code — and they are the same thing, so send whichever suits the channel.
2. You send it however you can. WhatsApp, SMS, email, a work chat. **It does
   not have to be a channel you trust**, which is the whole point.
3. They open it. If Z is installed, tapping the link opens the app; otherwise
   the link shows a page telling them where to get Z, and they open it again
   afterwards. They can also paste either form into their own CONNECT tab —
   and if the link opened in a browser even though Z is installed, that is
   the way in: copy the address and paste it under **I have an invite**.
   Z asks them first: nothing of a tapped invite leaves their phone until
   they press **Connect**, under a line saying what connecting sends and to
   whom.
4. From here neither of you has to do anything. While Z is open it carries
   the invite forward on its own, a step every twenty seconds or so, and
   "Check now" only hurries it. An invite the other person has not opened yet
   says so; one they have opened says it is waiting for them.
5. Both screens show the same **eight digits**. Get on a call, or say them in
   person, and compare. If they match, you are added to each other and both
   of you are verified — no safety number to read out afterwards.

Why the digits matter: anyone who sees the invite before your friend does can
answer it, and Z has no way to tell. What they cannot do is show the right
eight digits on your friend's screen. An impostor in the middle produces two
*different* strings, and the comparison is what catches it. Z names whoever
took the invite, right above the digits — so if it is not who you meant to
reach, stop there instead of adding them.

The relay in between cannot answer it at all: the invite is bound to a secret
the relay never sees, so a relay that tried to sit in the middle would stop
the invite rather than finish it. An invite made by an older version of Z
lacks that binding — it still works, and its comparison screen says that until
you compare the digits, even the relay could be in the middle. An older version
of Z cannot open an invite made now, and says it is not a Z invite: ask them to
update.

So:

* **They match** — you are added and verified. Done. A few seconds later
  their post-quantum key arrives and the safety number changes to the
  post-quantum one; the tick stays, because the eight digits covered that key
  too.
* **We have not compared yet** — you are added, and Z says plainly that the
  contact is unverified. You can compare safety numbers later from the chat.
  This is no worse than pasting codes, which is what it replaces; it is just
  honest about it.
* **They do not match** — Z stops, and adds nobody. Do not try the same invite
  again: make a new one and send it another way.

An invite **works once** and **expires after 24 hours**. If it went to the
wrong place, or you are not sure who opened it, discard it and make another —
they cost nothing.

The link is `https://www.zmessengers.com/i#…`, and the part after the `#` is the
invite. Browsers never send that part to a website, so the page it points at
never receives your invite and cannot know one exists. You can check that in
your browser's own network tab.

## Being found by a handle

A handle is a name people can find you by: `@alex.42` — a name you choose, a
dot, and two to six digits. It is optional. Z never offers one when you
start, and nobody needs yours to add you: your code and CONNECT work as they
always did.

Handles need a handle service, and this version of Z has none set up yet, so
Settings › Your handle, and the Handle tab under Add contact, say handles are
not available. The rest of this section is how they work once there is one.

### Claiming one

Settings → **Your handle** → **Claim a handle**. Type a name — 3 to 20
letters, digits or `_`, starting with a letter — and Z picks two random
digits, or choose your own. **Check** asks the handle service whether it is
free. Claim it, and Z shows the handle's **recovery code**, once: write it
down, then type it back. Z does not keep it. It is the only way to get the
handle back if you lose the phone, it is not your backup's code, and anyone
who has it can take the handle.

The handle is then published at a random moment between ten minutes and an
hour later, on purpose: the handle service sees when a handle appears, and
one that appeared the moment you were using Z would be easier to tie to you.
Keep Z open until then — if it is closed, the handle is published 3 to 20
minutes after you next open it; **Cancel claim** drops it, and nothing was
published.
If someone else's claim on the same handle got there first, Z says so and
nothing is published for you — choose other digits.

### Finding someone

Add contact → **Handle**. Type the handle they gave you and tap **Find**. If
it exists and is taking requests, **Send request** sends them an ordinary
contact request — your display name and your key, as when you paste a code
— and takes a few seconds on purpose: each request costs its sender some
work, so nobody can send thousands. If they accept, they appear in your chats
with "@alex.42 accepted. Compare safety numbers to verify."

**A handle is not a verification.** Z checks that the account that answered
is the one the handle sent you to, not who that is. Anyone could have claimed
`@yourfriend.07` before your friend did. Compare safety numbers before you
trust it — and ask people for their handle rather than guessing it, because
whoever holds a handle sees the name and key of everyone who sends it a
request.

### Requests through your handle

They arrive in Requests like any other, marked **Via @alex.42**, and you
**Accept**, **Decline** or **Block** as usual. The handle has an inbox of its
own, separate from your account's: your phone reads it a few seconds after
you open Z and every quarter of an hour or so while Z is open, and never
wakes for it — so a request through your handle waits at the relay until you
next open Z, for up to three days like any message. At most 100 wait at a
time; past that, the oldest you have not yet seen goes.

Only your main device holds a handle and reads its inbox. A linked device can
find people by handle, and the people you meet through yours appear there
too, but it cannot claim or change one.

### Managing it

Settings → **Your handle**:

* **Pause** — people who look it up are told it is paused, and cannot send
  anything. **Resume** undoes it.
* **New inbox** — the handle gets a new inbox, and the old one is read one
  last time and left. Use it to end a wave of unwanted requests; the handle
  stays the same, and requests already waiting stay.
* **Work per request** — how much work a request costs whoever sends it, from
  a fraction of a second to up to a minute on a slow phone. More stops more
  spam and makes everyone who asks wait longer.
* **Give up handle** — nobody can reach you through it any more, and this
  device forgets its keys. The name stays in the public log and nobody else
  can claim it; only its recovery code can bring it back. Wiping Z or
  resetting your identity does not give a handle up: it stays, taking
  requests nobody reads, until its recovery code moves it to a new install —
  so give it up first if you mean it to go.

**Recover a handle**, on a new phone or a new identity, takes the handle and
its recovery code: the handle moves to this account with new keys, you get a
new code, and whoever held it before can no longer change it. A backup
carries the handle too: a restore brings it back as it was, and a claim that
was still waiting to be published comes back waiting for you to tap
**Publish now**.

### Who can see what

* **Anyone** can look up any handle, and learn that it exists, whether it is
  paused, how much work a request costs and the hour it last changed — never
  your account's key or your own mailbox, which a handle does not lead to.
* **Whoever holds a handle** sees the display name and key of everyone who
  sends it a request, before deciding anything — so a stranger who claimed a
  name you guessed learns that you tried.
* **Someone you accept** gets what any contact gets. Someone you decline or
  block gets nothing back.
* **The handle service** sees the internet address your phone claims,
  changes and looks up handles from, and of a lookup only the group of 32 to
  64 handles it was among, not which.
* **The relay** sees how many requests your handle's inbox gets and when, and
  the address your phone reads it from — the same address your own
  connection comes from. Nothing at the relay or the handle service links the
  inbox to your account, but an address is an address: Tor or a VPN hides it.

`THREAT_MODEL.md` R47–R50 is the long version.

## The safety number, and when it changes

Open a contact and you will see a safety number — a string of digits derived
from both your keys. Compare it with them over a channel you already trust (in
person, a phone call you recognise their voice on) and tick "verified". You
are checking that nobody stood between you when you exchanged codes.

**A verified tick that disappears is not a bug.** Z drops it whenever the
number changes, and it tells you which kind of change it was. You will see one
of three things on the contact's screen:

* **"The number changed — here is why"** — a one-time change when a contact's
  identity gains a post-quantum key, so the number is now derived from both
  halves. Z says this only when it can *prove* the old number was the one you
  compared. Compare again; it takes a minute and it happens once.
* **"The number changed and this app cannot explain why"** — exactly what it
  says. Usually the person reinstalled or switched device. Occasionally it is
  what an attack looks like. Ask them, on a different channel, before you
  carry on.
* **"Post-quantum key refused"** — a key arrived that does not match the code
  you originally scanned, so Z rejected it rather than accepting it. Either
  something is broken at their end or someone is substituting keys. This one
  stays on screen until it is resolved; it is not repeated at you every time,
  and it does not go away on its own.

Z will not guess in your favour. A change it cannot account for is reported as
unexplained even when the innocent reading is the likelier one.

**Two labels you may see beside the number.** Which number Z shows depends on
what each of you has of the other, and Z will not move your number until it
knows their screen is moving too — a number that is right on your phone and
wrong on theirs is worse than no number at all.

* **"Waiting for them"** — you have their post-quantum key, they do not yet
  have yours, so you are both still on the older number. Nothing is wrong and
  there is nothing to do. It resolves itself the next time they use the app —
  if their app is 3.9.2 or later (below) — and when it does, both numbers
  change at the same moment.
* **"Post-quantum, unconfirmed"** — you each have the other's key and the
  number you are looking at covers both of them, but Z has never had anything
  to check that key against. You added them from a code that came before this
  existed, or they only sent the key after you added them, so there was no
  advance promise to hold it to. **Comparing the number is that check.** Read
  it out to them the usual way; if the digits match on their screen, the key
  really is theirs, and ticking "verified" records it for good. If you happen
  to be in the same room, scanning their code again does the same job on the
  spot, and you can do either — neither is better than the other. A code from
  an older version of Z does it only when it agrees with the key their app
  sent: nothing in such a code signs its post-quantum part, so when the two
  disagree Z refuses the code and changes nothing, rather than taking a code
  anyone could have edited over their app's word.

Before version 3.9.2 the second situation had no way out at all. One of you
saw one number, the other saw a different one, and no amount of comparing,
re-scanning or waiting would bring them together; deleting the contact and the
conversation with it was the only thing that worked. If you have a contact
stuck like that, the one of you who accepted the other's request needs to be
on 3.9.2 or later (updating both is simplest), and then it sorts itself out
the next time the other sends them anything.

**If one of you is still on an older app.** Google Play was still serving
3.9.1 in October 2026, and an app older than 3.9.2 cannot meet a current one
on the post-quantum number in two common cases:

* **You scanned or pasted their code, and they accepted your request on the
  older app.** Your screen shows the post-quantum number; theirs shows the
  older one and says your app has not published a post-quantum key — it has;
  theirs dropped it. Comparing cannot work until they update. Once they have,
  it sorts itself out the next time you send them anything.
* **They scanned your code with the older app, and you accepted.** You may
  see "Waiting for them" for as long as they stay on it, while their screen
  may already show the post-quantum number — an older app usually never says
  it holds your key. It does not resolve the next time they use the app, only
  when they update.

Until then, numbers that differ between you and someone on an older app are
not by themselves a sign of an attack — and they are not a check either: you
cannot verify each other by the number until you both show the same one.

**Messages, not just identities.** Everything above is about *who* they are.
Below the number, one more line says whether your *messages* are protected by
the post-quantum key exchange right now. **"Messages: post-quantum"** means
every channel this chat uses — to their device, to each of their other
devices, and to each of your own other devices, which get a copy of every
message — has completed it in both directions, so new messages are protected
against someone who records them today and has a quantum computer later.
**"Messages: not post-quantum yet"** names the channels that have not. That is
normal for the first moments of a chat, and of every newly linked device: the
exchange needs messages in both directions. Until it completes, some or all
of those messages rely on the ordinary key exchange alone — enough against
anyone today, not against that future recording. A group's screen says the
same, and names the members whose channels are not post-quantum yet.

## Your other devices

Link a second device from Settings → Linked devices. Both screens show a short
code; they have to match. If they do not, stop — something is on the wire
between them.

A linked device is a full peer, not a mirror. It has its own keys and its own
encrypted sessions, and your contacts see all of them. History from before the
link is copied across. What you do on one — edit or delete a message, react,
set a disappearing timer, read a chat — shows on the others, and your
contacts see it as yours, whichever device it came from.
The link itself goes through the relay — two
throwaway mailboxes the code derives, everything in them end-to-end
encrypted — and the matching code on both screens is what shows nobody is in
between.

A newly linked device knows your contacts as your phone does: each one shows
the same safety number, the same tick if you verified them, the same
post-quantum state, and their other devices — your phone hands all of it over
in the link the matching code protects. Until this version a laptop started
every contact unverified, showed a different number for anyone you had added
from *their* laptop, and could not reach that person's other devices. Linked
from a phone on an older version, the new device gets what that version
sends: every contact under the right account and number, unverified, with
their post-quantum keys arriving as they next write to it.

Contact requests belong to your account, not to a device: one sent to your
phone shows on your laptop too, and accepting, declining or blocking it on
either does it on both — a person you block on your phone cannot reach your
laptop instead. A request you send from your laptop reaches the other person
as yours, so accepting it gives them you — the same number your phone shows
them — and not a separate entry for your laptop.

If your contacts start seeing a device you did not add, Z tells them, and it
tells you. That alert is the whole point of the design, so please do not
dismiss it as noise.

Four banners at the top of the chat list are about your own account, and each
appears only when Z holds a list of your devices signed with your account's
key — something no contact, group member or server can make up:

* *"A contact was given a device list for your account that this device never
  issued"* — a contact holds a list of your devices that none of yours made.
  Z asks their app for that list before saying anything, so the banner comes
  a few seconds after their message, and only if their app is recent enough
  to answer.
* *"Your main device published an older device list"* — your main phone sent
  this device a list older than one it already has, so the newer one was
  signed somewhere else.
* *"This device was removed from your account"* — a list of your devices
  without this one, newer than the one this device has, signed by your
  account. It comes with the notice from a contact who stopped writing to
  this device, or from the transparency log.
* *"A device list you did not issue has been published to the transparency
  log"* — your account's entry in the log is a list your devices never made.

Dismiss one and it stays dismissed for that list, even after a restart; a
different list brings it back. If you cannot explain it — you did not just
link or remove a device — take it seriously: someone may hold your account
key, and resetting your identity is the remedy.

A device belongs to one account. If a contact's device list names a device
that another of your contacts' lists already names — or one of your own
devices — Z does not use that list, and their chat says so, naming both of
them. It cannot tell which of the two is wrong: the list it refused may be
the honest one, if the other arrived first. Ask them both. A device that has
proved which account it is in is different. A device does that with its own
signature, once it and its account's main device both run an app that can
(`adr/0022`); then Z can tell, a list naming that device for anyone else is
not used even if it reached you first, and that contact's chat says whose
the device is. Ask them about it.

Where a public transparency log is configured (Settings › Transparency log
shows whether one is), Z also records every device list your account
publishes in it, and checks your contacts' lists against it. A contact's
screen may then say one of a few things. *Confirmed* means the list their
devices sent you is the one in the log. *Not in the log* means their account
has never published — an older app, most likely — and nothing changes.
*Not in the log yet* means a newer list reached you than the log has; if it
stays that way for a day, the devices only that list added stop getting your
messages until it appears, and the chat says so. A **disagreement** between
the log and their devices holds your messages to them until it resolves or
you choose to send anyway — for that disagreement; a new and different one
asks you again. It is rare and worth a phone call. If the log
itself misbehaves — shows two different histories — Z says so at the top of
the chat list and confirms nothing new until you reset it in Settings; your
conversations continue on the checks that existed before the log.

Checking costs something, and it is worth knowing: Z asks the log about each
of your contacts, from your own internet address, when it starts, every six
hours and soon after a contact's devices change. Whoever runs the log — for
the built-in one, the people who run the relay — therefore learns who your
contacts are. The log is on by default; turning on Developer mode in Settings
lets you point it at another log or at none.

Once every device that reads your device list — each of your contacts'
devices, and each of your own linked devices — has told yours that its app can
read the newer form of the list, your main device moves your account to it by
itself, and the list's post‑quantum signature and fingerprint then cover the
key each of your devices receives messages on, not only which devices there
are. It does not move back. A contact whose app is older and appears afterwards
is named on their screen (*"Their app may not read your device list"*): an app
older than 3.9.9 cannot read the newer form, so it cannot reach your other
devices and may warn them about your account until they update. With Developer
mode on, Settings › Transparency log shows which form your list is signed in
and how many devices it is still waiting for.

## Groups

A group has no shared key. Every message is encrypted separately for every
member's every device.

That is slower and it is deliberate: **someone removed from a group cannot
read anything sent afterwards**, because there was never a group key for them
to keep. It also means nobody — including whoever created the group — can hand
out access without every member's device agreeing.

Whoever creates a group **owns** it. The owner can make other members
**admins**: an admin can add people, remove members who are not admins, and
rename the group. Only the owner decides who the admins are — making someone
an admin, taking that away, or handing the whole group to someone else (you
choose whether to stay on as an admin) — and does so on their main phone, the
one their other devices were linked from; from a linked laptop the owner can
still add, remove and rename. Everyone sees every change.

Make someone an admin only if you would trust them to run the group: an admin
can add anyone, including someone the rest of the group has never met. What an
admin cannot do is read anything sent before they were added, change who the
admins are, or remove you — so you can always take the role back, and once
you have, their changes stop being accepted.

If two admins change the group at the same moment — or you change it on two of
your own devices before they have caught up with each other — one change wins
on every phone; whoever's change did not stand is told so in the chat and can
simply make it again. If you own a group, hand it on before you leave: once the
owner has gone, nobody can change who the admins are (the admins can still
add, remove and rename). An admin who has left keeps the role on paper until
the owner takes it away; the group's screen lists them.

A phone that missed a change — offline for days, say — asks the group's owner
(or the admin it lost track of) for the current list the next time it cannot
make sense of one, and catches up.

A member still on a version of Z from before admins existed follows only the
person who added them, until they update — and Z already tells them they are
behind.

Someone you blocked stays blocked in a group too. If they are in one you are
in, the group lists them, but your messages to it do not reach them and
theirs do not reach you; and if they take an invite of yours — a group link
included — Z refuses it and adds nobody.

### Inviting someone to a group by link

If you can add members to a group — you own it, or you are one of its admins —
its info screen has **Invite to group by link**. That makes an ordinary
CONNECT invite (a link and a code, the same thing) that remembers the group on
the device you made it on and nowhere else. Send it however you can, as with
any invite.

* **The link says nothing about the group** — not its name, not who is in it.
  Anyone who sees it learns only that it is a Z invite.
* **It works once and expires after 24 hours**, like every invite, and whoever
  opens it first is who it reaches. A group link on the CONNECT tab says which
  group it is for (on your screen only); **Discard** revokes it.
* **What they see.** Their screen says, above the eight digits, that the invite
  also adds them to a group, and that they will see which one once you are
  connected. You compare the digits as for any invite. They join the group only
  if they then go ahead on their side — *they match* or *we have not compared
  yet* — and the group tells you *"… joined from your invite link"*. They see
  who added them and to which group, and can leave like any member.
* **They can connect without joining.** Beside those buttons is **Also join the
  group**; if they turn it off they become your contact only, and the group
  tells you at once that they chose not to join.
* **Already contacts?** The link works anyway — even opened on another of their
  devices: whoever already has the other as a contact keeps that contact exactly
  as it was, and they still join. (An ordinary invite between two people who are
  already contacts is still refused.)
* **More than one link for the same person** — say, to two of your groups — is
  fine: each one is answered on its own.
* **If their app is too old** to tell them it is a group invite, your screen
  says so before you go ahead, and they become a contact only; add them to the
  group by hand if you still want to. If they stop at the digits, or do not
  go ahead within the link's 24 hours, the group tells you that too.
* **If you stop being an admin** before they join, the link adds nobody.
* **The device you make it on adds them.** A link made on your laptop is
  answered on your laptop, which has to be online once they have gone ahead
  and before the link's 24 hours are up; your other devices then see the new
  member as they see any change.
* **Changed your mind?** Until they have joined, the CONNECT tab lists them
  under **Waiting to join your groups**. **Stop waiting** there and the link
  adds nobody; they stay your contact. If they had already said yes and your
  phone was already adding them, it tells you it was too late.

Make one link per person. A link that anyone who saw it could use would be a
key to your group, sitting in whatever chat history it ended up in.

## Disappearing messages

Set a timer per conversation and messages delete on both sides when it
expires — on every device on both sides: a copy on your other device, a
message sent from a contact's other device, and the history a newly linked
device receives all keep the timer. A timer set on any device — yours or
theirs — is set on every device of you both, one either of you links later
included, so whatever you send from any of them carries it.

This is a tidiness feature, not a security one. It works because the other
person's app cooperates. Someone who wants a copy can photograph the screen,
and a modified app can simply not delete. Use it to keep your own history
short. Do not use it to send something you would mind existing.

## Ticks, and the receipts behind them

One tick: the relay has your message. Two: the other person's device has it.
Two in colour: they have opened the chat. Each is something their device told
yours, encrypted like a message — and a receipt is the one thing Z sends
because somebody *else* did something, which makes its timing worth hiding.
An answer that went back the moment a message arrived would tell whoever runs
the relay who had written to whom, however sealed the message itself was.

So Z holds every receipt for a moment of its own: never less than five
seconds after the message arrived (or after you read it, or after your phone
came back online), and at the latest at a random moment within about a
minute, everything owed to one person together — or, once those five seconds
are up, with the next message you send them. The second tick turns up to a
minute after the message arrived, or with the reply. That is the cost, and
nothing else changes: a tick still says only what their device actually
said.

It is not invisibility. A relay that watches for days can still notice that
a message to you is often followed, within a minute, by something to the
person who wrote it — and your replies are timing of their own, whatever
receipts do. If you need more, **Settings › Privacy › Delivery and read
receipts** turns them off on that device (each of your devices has its own
switch). Then nobody you talk to sees a second tick from you — not when a
message arrives, not when you read it — so a message from them can sit at one
tick long after it reached you, and in a group, where two ticks wait for every
member, one member with receipts off keeps every message at one. One tick has
only ever meant "the relay has it", never "it has not arrived".

## Locking the app

* **Screen lock** — Z asks for your fingerprint, face or device PIN before it
  opens. Messages still arrive while it is locked.
* **Screen security** (Android) — once Z has opened your vault, the phone
  takes no screenshot or screen recording of it, and the recent‑apps screen
  shows a blank card for Z instead of the chat you were in. It is on until
  you turn it off (Settings › Security), which you can do when you need a
  screenshot of your own chat. Off, the recent‑apps screen shows that chat
  even with the screen lock on: the phone takes the picture as Z leaves the
  screen, before the lock is drawn. And a screenshot is a copy of the chat
  outside Z, in your gallery, which many phones then back up to the cloud.
* **App passphrase** — a separate secret that encrypts the vault key. Without
  it nothing sealed in the database can be read, including by someone who
  copies the file off your disk. The file's structure is not sealed: which
  conversations exist, when each message was sent or received, and the
  routing ids are readable to anyone who has it (`DATA_MAP.md`).

Biometrics alone protect against someone picking up your unlocked phone. A
passphrase protects against someone taking the storage. They are different
problems; turning on both is reasonable.

---

## If something goes wrong

This is the section to read *before* you need it.

### You still have the device, but forgot the app passphrase

There is no reset. The passphrase is not checked against a stored copy — it is
part of the key that decrypts the vault, so a wrong one produces nothing.

If you have a backup archive and its recovery code, restore onto a fresh
install. If you do not, the history on that device is gone.

### You lost the device, and you have a backup

Install Z, restore the `.zbk`, enter the recovery code. You get your identity
and your history.

Your contacts' safety numbers **do not change** — it is the same identity, so
nobody sees an alarm. This is why restoring beats starting over.

What they do see is an ordinary device-list update: before it sends anything,
the restored device signs your account's device list again at its next
version, and your contacts and the transparency log take it as they take
linking a laptop. A device you linked *after* the backup was taken has to be
linked again; one you removed after it stays removed. A backup made on a
linked device (a laptop) comes back as that linked device — and if your phone
has removed it since, it says "this device was removed", and you link it
again. Until this release a restore told you to reset your identity over
nothing; the one case that can still show a contact a conflict is a restore
while the transparency log cannot be reached, after your device list changed
since the backup — so restore while you are online.

The archive restores history but never live session state, on purpose: a
restored device re-handshakes rather than reusing keys that may have been used
since. You may see the first message or two take a moment.

### You lost the device, and you have no backup

The identity is gone. Not recoverable — not by us, not by anyone, because no
copy was ever made.

Start fresh, and tell your contacts to expect a new safety number. **Say it on
a channel they already trust**, because from their side a new identity is
indistinguishable from someone impersonating you. That is not a flaw; it is
the same check working as designed.

### You lost the recovery code

The archive is unreadable. It is 120 bits of entropy stretched with Argon2id;
there is no hint, no reset, and guessing is not on the table.

Write it down when you make the backup. On paper. The recovery code and the
archive should not live in the same place — either alone is harmless.

### You think someone has your device

Assume they can read everything on it, and everything sent to it from now on.
Tell your contacts to stop, on another channel. Then see
`WHAT_Z_CANNOT_DO.md`, which is honest about how little any messenger can do
for you at that point.

### Z will not connect

Check the relay address in Settings → Connection. The default relay holds
queued ciphertext in memory only, and it is forgotten when that memory
restarts — so a message that was in flight during an outage may need
resending, and your app resends it for you from its own outbox. Nothing is
lost from your device.

You can run your own relay: `SELF_HOSTING.md`. It takes a few minutes and it
is the honest answer to "why should I trust yours".

---

## Making a backup

Settings → Backup. You get a `.zbk` file and a 25-character recovery code.

* The **file** is useless without the code.
* The **code** is useless without the file.
* Keep them apart. Both together is your whole history.

Z does not store the archive anywhere or upload it. Where it goes is your
decision, and the file is safe to put somewhere that is not — a cloud drive is
fine, given the code is not there too.

There is no automatic cloud backup and there will not be one, because it would
mean either us holding a key or you holding a password we could reset. Both
defeat the point.

## Staying up to date

Z has no in-app updater — an app that can update itself is an app that can be
made to run someone else's code, and Z does not hold that power over your
device. What it does instead: when you open Settings, at most once a day, it
asks your own relay whether a newer version has been published, and if one has,
it shows a small "Update available" note with the version and where to get it.
Where to get it is Z's own answer, never the relay's: Google Play if that is
where your copy came from, the project's release page otherwise.
Nothing is downloaded or installed for you; you go and get the new build the
same way you got this one. The check talks only to the relay you already use —
not Google, not us, not anyone new — and it sends nothing that says which
install you are. If you run your own relay and do not set a latest version,
nobody on it is ever prompted.

## What Z never asks for

No phone number, no email, no contacts-list upload, no analytics, no crash
reporter, no advertising identifier. The app talks to the relay you configure,
to the transparency log (which learns who your contacts are, above), to a
handle service only when you claim, change or look up a handle (above), and to
your platform's notification service, which learns that a device should wake
and nothing else. On Android push is on unless you turn it off in Settings —
but only if you allow Z notifications: without them the app registers nothing,
and if you take them away later it withdraws its registration the next time
it starts or comes back to the front. Settings › Notifications says which is
true on your phone, what a wake carries (no message and no sender) and who
sees it (the relay, which keeps this device's token, and Google's Firebase
Cloud Messaging, which learns when the device was woken). The relay keeps the
registration until 30 days after the app was last online, or until you turn
push off; turned off while your phone is offline, the relay is told as soon
as it is back, and until then it can still wake it.

The full inventory is `DATA_MAP.md`: every piece of data Z creates, where it
lives, who can read it, how long it lasts.

## Where to read next

* **`WHAT_Z_CANNOT_DO.md`** — the limits, stated plainly. Read it before
  deciding Z is right for a particular risk.
* **`BACKUP.md`** — the archive format, if you want to verify the claims above
  rather than take them.
* **`THREAT_MODEL.md`** — the full model, written for reviewers.
