# What Z cannot do

Encryption is easy to oversell. This page is the other half of the sales
pitch, and it exists because a person deciding whether to trust an app with
something dangerous deserves the limits stated as plainly as the promises.

`THREAT_MODEL.md` is the same material for reviewers, with the reasoning and a
risk register. This is the version for someone deciding whether to use Z for
a particular thing.

---

## It cannot protect you from your own device

**This is the big one, and everything else is a footnote to it.**

Z encrypts messages between devices. It decrypts them *on* the device, because
otherwise you could not read them. So anything with access to your unlocked
phone or laptop can read your messages, and no amount of cryptography changes
that.

That includes:

* someone who picks up your unlocked phone;
* someone who compels you to unlock it — a border officer, a court, a person
  standing over you;
* spyware, whether it arrived through a vulnerability or an app you installed;
* anyone with your app passphrase;
* screen recording, keyboard apps, accessibility services on some platforms,
  and backup software that copies the app's data. (Z asks the keyboard not to
  learn a passphrase or a code; a keyboard app sees every key either way.)
* the buttons other apps put in the menu that appears when you select text —
  Translate, a dictionary, a notes app. Tapping one hands that app whatever is
  selected: a recovery code, an invite, a message you are editing. Until 4.7.2
  Z asked Android to offer them. It no longer does, so on Android 11 and later
  one appears only if Android shows Z that app for some other reason; on
  Android 10 and earlier Android offers every one installed, whatever Z asks
  (`THREAT_MODEL.md`, R51).
* the clipboard. Copy puts the text where the phone, your keyboard and the app
  you paste into can read it, and Z neither clears it nor marks it as secret:
  on Android 13 and later the phone shows what you copied at the bottom of the
  screen, a keyboard with a clipboard history keeps it there — some sync that
  history to an account — and a disappearing message you copied outlives the
  message, there and on the clipboard. Write a recovery code down rather than
  copy it (`THREAT_MODEL.md`, R52).
* another app on the phone, which can hand Z a link as if you had tapped it.
  Since 4.7.2 Z takes only an invite link to its own site that way, and only
  once you are past the app lock; an invite another app made still opens, and
  nothing is sent unless you press Connect (`THREAT_MODEL.md`, R53).

What Z does do is make the endpoint the *only* place worth attacking. That is
a real achievement — it means no one can read your conversations by
compromising a server, because no server holds them. But it is a change in
where the risk sits, not a removal of it.

**If your threat model includes device seizure, the answer is not a better
messenger.** It is device encryption, a strong passcode, disabling biometrics
before you cross a border, and knowing what your jurisdiction can compel.

Turning on the app passphrase does help against one specific case: someone who
takes the storage but not an unlocked session. It does nothing against
someone watching you type it, or watching the screen while you show it. On
Android a passphrase shown on the unlock screen is kept out of screenshots and
the recent-apps screen — since 4.7.2; before, either could take it — but not
out of a camera.

## It cannot protect you from the person you are talking to

Anyone you message can screenshot it, photograph the screen, keep notes, or
run a modified app that ignores every delete.

Disappearing messages are a courtesy against accidental retention on honest
clients. They are not a control over another person's copy, and they are
described that way everywhere in the app on purpose.

There is no such thing as a message you can un-send from someone else's
memory.

## It cannot hide that you are using it

Z is not an anonymity network and does not claim to be.

Someone watching your network sees you connect to a relay. Someone running the
relay sees which mailbox an envelope is for, how big it is (rounded to one of
six sizes) and when it arrived. They are not told who sent it or what it
says — sealed sender and the mailbox-as-a-hash design remove those, and the
envelope arrives on a connection that never said whose it is — and no
envelope says who you talk to. What they do see is the network address it
came from, and the same address is holding your own mailbox open. On a
phone network that address is shared with thousands; on your home
connection it is as good as a name (`THREAT_MODEL.md`, R21). But the relay sees *when* each mailbox is busy, and
patterns in that are not nothing: the members of a group all receive their
copy of a message within a fraction of a second of each other, every time,
and so does each of your own devices. We measured it (`THREAT_MODEL.md`, R18
and R19). A relay that keeps timestamps can work out which mailboxes belong
together; it still cannot put a name to any of them. The same timing can
pair a sender with the person they wrote to, despite sealed sender: a delivery
receipt goes back to the sender. Since phase 41 it waits a random five
seconds to a minute rather than a fraction of a second, which turns one
message's giveaway into a pattern a relay has to watch for, and you can turn
receipts off (R41).

Three more parties see some of this. **The transparency log**, which Z uses by
default, is asked about your contacts up to four times a day, from your own
address — since phase 35 by bucket and never by name: each question covers
32 to 64 accounts, your contacts' among decoys the app keeps — so whoever
runs it, and for the built-in log that is the people who run the relay,
learns which buckets you ask about and when you add a contact outside them —
and, because on a phone a check almost always runs a few seconds after you
open the app, roughly when you open it, up to four times a day — but not who
your contacts are; what it learned before phase 35, when the app
asked by name, it keeps (R40). Turning it off
takes Developer mode. **The log's witness** — a copy of the log that
somebody other than its operator runs, there to catch a log showing
different people different histories — is asked for its one record at each
check, from your address: whoever runs it learns your address and when your
app checks, and nothing more. And **Cloudflare**, in front of the built-in relay and
log, ends their encryption in transit (not the messages', which is
end-to-end): it sees your address beside your mailbox, which mailbox each
envelope you send is for, and which buckets you ask the log about (R44).

Handles would add one more. They need a handle service, and this version of
Z has none set up, so it says handles are unavailable: nobody using it as it
ships can claim a handle or find anyone by one. Once a version has one, if
you claim a handle, or look one up, **the handle service** sees the address
each claim, change and lookup comes from — a lookup names up
to four groups of 32 to 64 handles, counted by the app rather than taken from
the service, instead of the one asked about, which hides what was asked and
not who asked (though two of your devices, or a reinstall without a backup,
looking up one handle share only its group); a service that claims handles of
its own makes the groups smaller than they look, and one that changes who holds
a handle is caught only by someone who looked it up before — and the relay sees
how many requests your handle's
inbox receives and the address your phone reads them from, the same address
your own mailbox is held open from (R47, R49).

Someone watching **both ends** can correlate timing and volume regardless of
any of it. That is a property of the internet, not of Z. If being seen to use
an encrypted messenger is itself your risk, you need Tor or something built
for that problem, underneath Z rather than instead of it.

Running your own relay changes who sees the metadata. It does not make the
metadata stop existing.

## It cannot recover anything for you

There is no account, so there is no account recovery. Nobody at Z can reset
your passphrase, restore your history, or prove to a contact that you are you.

If you lose your only device without a backup, the identity and the history
are gone. This is not a support failure — it is the same fact that means a
subpoena to us produces nothing. A handle, once a version of Z lets you claim
one, is the same: lose the phone and its recovery code, and nobody can give
the handle back — or take it from whoever holds that code.

`USING_Z.md` has the recovery guidance. The short version: make a backup,
write the recovery code on paper, keep them apart.

## It cannot stop a relay from refusing to deliver

A hostile or broken relay cannot read your messages or forge them, and no
envelope tells it who is talking to whom (the timing patterns above are what
it has instead). It *can* drop them, or go away entirely.

Availability is the one thing you are trusting the relay operator for, which
is why self-hosting exists and why the address is a setting rather than a
constant.

## It cannot hold a group of more than 128, or broadcast

A group has no shared key. Everything sent to it is encrypted and sent
separately to every member's every device, and every change to who is in it
goes to every member. That is what keeps someone you remove out of
everything sent afterwards, and it is why a group made in Z holds at most 128
people, you included. A group an older version of Z made larger still works,
but can only shrink.

Nor is there a broadcast channel — one writer, many readers. That would be a
different feature, and Z does not have it.

A file to a group can be refused outright. Each copy of it is its own
upload, about 2.4 times the size of the file — one to each member, and one
to each of your own other devices — and when the copies come to more than
256 MB in all, what the public relay can hold for everyone at once, Z does
not send it, and says why. So the largest file Z sends, 24 MiB, cannot go to
more than four recipients, your own devices counted: not to a group of you
and five others, nor to you and four others while you have a linked device.
A 1 MiB photo can go to 91. A file to one person is not limited this way.

A file to a group can wait, too. Every member's copy is its own upload, so Z
hands the members' copies to your phone's queue a member at a time, each
only while the queue holds less than 64 MiB, not counting what waits for a
mailbox the relay is refusing; the others wait their turn. A member whose
mailbox at the relay is full gets no part of a new file until it takes
messages again, however long that is, and while the relay itself is full
nobody does. While a member's copy waits, a change to the group sent to them
after it — who is in it, its name, its admins, its timer — waits behind it,
and so does your next file to the group. Texts, reactions and edits do not.

## It cannot make key verification happen for you

Z shows you a safety number and tells you when it changes. It cannot make you
compare it, and it cannot compare it for you — that would need a directory
that vouches for identities, which is exactly the thing this design refuses
to build; a handle (below) vouches for nothing.

An unverified conversation is still encrypted, but you are trusting that
nobody interfered when you exchanged codes. Verifying takes a minute and it is
the only step that closes that gap. Until you do, adding someone — by their
code, or by accepting their request — trusts whatever arrived first: a code
swapped on its way to you is simply who you added (trust on first use).

A CONNECT invite has the same edge, said differently: until it is used it is
a bearer token, and whoever opens the link first is who it reaches — whoever
saw it in the chat it was pasted into included. The eight digits are what
catch that, and only if the two of you compare them. An invite made by an
older version of Z has a second edge, which its comparison screen states:
until the digits are compared, the relay that carried it could be in the
middle too. One made now is bound to a secret the relay never sees, so the
relay cannot answer it — but the person holding the link still can.

Key transparency (`docs/adr/0006-key-transparency-log.md`) catches some of
this automatically: every device list an account publishes is recorded where
any contact can check it, and a device added behind your back cannot stay
hidden from the people you talk to. It does **not** catch an exchange the
attacker controlled from the start — a substituted code is a different
identity, with its own honest-looking history — so the safety number remains
the check for that, and it only works if someone looks at it. The log is
running and the app checks device lists against it — and, in every version
since 4.4.2, checks the log against its witness, which somebody outside the
project runs (above): the part that catches the log itself showing
different people different histories, rather than the accounts in it
(`docs/GA_CHECKLIST.md`, G3). It does not catch everything. An app that
looks an account up in the log for the first time — a new install, a newly
linked device — cannot tell whether the log has quietly dropped that
account's newest list, or all of them, and the witness cannot either; and
the app reaches the witness through the project's own domain, and says it
has gone quiet only in Settings (`THREAT_MODEL.md`, R7).

## It cannot tell you who is behind a handle

This version of Z has no handle service set up, so nobody using it as it
ships can claim a handle or find anyone by one; what follows is what holds
once a version has one.

A handle — `@alex.42` — is a name someone claimed, first come, first served.
Z checks that the account that answers a request is the one the handle sent
it to; it cannot check whose account that is. Anyone can claim
`@yourfriend.07` before your friend does, and a request to a handle carries
your display name and key to whoever holds it before they decide anything —
so a squatter on a name people expect learns who went looking for it
(`THREAT_MODEL.md`, R48). The safety number is the check, as it is for every
contact.

Nobody vouches for the handle service yet, either. It could show you a
different record for a handle than it shows everyone else, and send your
request to an inbox of its choosing; the app checks everything in an answer
it can check, but only a witness comparing what the service tells different
people would catch that, and not every way of doing it — and the app, as it
ships, checks against none yet: one runs, but no build pins it, as none pins
the service (R50). There too, the safety number is what catches the account
that answered.

## It has not been audited

No external cryptographic review has been performed. The design has been
reviewed by the people who wrote it, which is worth something and is not the
same thing.

The claims are written down with their evidence in `AUDIT_SCOPE.md`, the
vectors are re-derived by independent implementations, and the disclosure
policy (`VDP.md`) grants safe harbour to anyone who wants to go and check. But
until a review happens, "unaudited" is the accurate word.

## It cannot promise the app you installed is the app we wrote

It can get closer than most. The Android release build (the universal APK)
is reproducible on any machine at a stated path — the desktop builds have not
been measured — releases carry signed provenance recorded in a public
transparency log, and anyone can rebuild and compare a single digest
(`REPRODUCIBLE_BUILDS.md`).

What is missing is somebody outside the project actually doing it. Until then
you are trusting a claim we make about ourselves, verifiable in principle.

On Android there is a further gap: Play re-signs the app with Google's key, so
what you install from the store is not byte-identical to what we built. That
is Play's model. Sideloading a release build avoids it.

---

## What is left

Given all of the above, here is the honest summary of what Z buys you:

**Your conversations cannot be read by the operator of the service, by anyone
who compromises it, by anyone on the network between you, or by anyone who
seizes the server — because none of them ever hold anything but padded
ciphertext addressed to a hash, in memory, deleted on delivery and within
seventy‑two hours regardless.** A
recording made today of a conversation's messages after its first round trip
does not become readable when quantum computers arrive — the opening exchange,
contact requests, the CONNECT ceremony, linking a device and the sealed outer
layer of each envelope are classical, and so, today, are the channels to
linked devices — yours and your contacts' — if their first key offer is lost
(`THREAT_MODEL.md`, "The quantum layer's edges"). Who belongs to your account
cannot be forged unnoticed, now or later, without breaking two independent
signature schemes; a session with a device already on it is authenticated
classically.

That is a strong and unusual position, and it is worth being precise about,
because a claim that is too broad gets someone hurt and a claim that is too
narrow gets ignored.

What it is not is protection from the device in your hand, the person you are
talking to, or someone who can watch both ends of the connection.
