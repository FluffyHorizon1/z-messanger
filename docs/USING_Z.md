# Using Z

Everything else in `docs/` is written for people reading the code. This one is
for people using the app.

Z is a messenger with no accounts. There is no sign-up, no phone number, no
email, no password to a server — because there is no server that holds
anything about you. That buys real privacy and it costs a few things that will
surprise you if nobody says them out loud, so they are said out loud here.

---

## Starting

Open Z, choose a display name, and you have an identity. It exists only on
that device. Nothing was registered anywhere.

Your display name is not a username. It is a label you send to people you
add, and two people can pick the same one. What actually identifies you is a
key, and the only way anyone gets it is if you give it to them.

## Adding someone

Swap contact codes — scan the QR, or copy the text and send it however you
like. Both of you have to do it; adding someone does not add you to them.

The code you show is public. Someone who copies it can add you, and that is
all: they cannot read anything, impersonate you, or find out who else you talk
to. What matters is that the code you *scan* is really theirs, which is what
the safety number is for.

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

## Your other devices

Link a second device from Settings → Linked devices. Both screens show a short
code; they have to match. If they do not, stop — something is on the wire
between them.

A linked device is a full peer, not a mirror. It has its own keys and its own
encrypted sessions, and your contacts see all of them. History from before the
link is copied across; nothing about the link goes through a server.

If your contacts start seeing a device you did not add, Z tells them, and it
tells you. That alert is the whole point of the design, so please do not
dismiss it as noise.

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
you choose to send anyway; it is rare and worth a phone call. If the log
itself misbehaves — shows two different histories — Z says so at the top of
the chat list and confirms nothing new until you reset it in Settings; your
conversations continue on the checks that existed before the log.

## Groups

A group has no shared key. Every message is encrypted separately for every
member's every device.

That is slower and it is deliberate: **someone removed from a group cannot
read anything sent afterwards**, because there was never a group key for them
to keep. It also means nobody — including whoever created the group — can hand
out access without every member's device agreeing.

The admin manages membership. Everyone sees membership changes.

## Disappearing messages

Set a timer per conversation and messages delete on both sides when it
expires.

This is a tidiness feature, not a security one. It works because the other
person's app cooperates. Someone who wants a copy can photograph the screen,
and a modified app can simply not delete. Use it to keep your own history
short. Do not use it to send something you would mind existing.

## Locking the app

* **Screen lock** — Z asks for your fingerprint, face or device PIN before it
  opens. Messages still arrive while it is locked.
* **App passphrase** — a separate secret that encrypts the vault key. Without
  it the database cannot be opened *at all*, including by someone who copies
  the file off your disk.

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

## What Z never asks for

No phone number, no email, no contacts-list upload, no analytics, no crash
reporter, no advertising identifier. The app talks to the relay you configure
and — if you turn on push — your platform's notification service, which learns
that a device should wake and nothing else.

The full inventory is `DATA_MAP.md`: every piece of data Z creates, where it
lives, who can read it, how long it lasts.

## Where to read next

* **`WHAT_Z_CANNOT_DO.md`** — the limits, stated plainly. Read it before
  deciding Z is right for a particular risk.
* **`BACKUP.md`** — the archive format, if you want to verify the claims above
  rather than take them.
* **`THREAT_MODEL.md`** — the full model, written for reviewers.
