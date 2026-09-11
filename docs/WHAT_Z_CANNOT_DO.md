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
  and backup software that copies the app's data.

What Z does do is make the endpoint the *only* place worth attacking. That is
a real achievement — it means no one can read your conversations by
compromising a server, because no server holds them. But it is a change in
where the risk sits, not a removal of it.

**If your threat model includes device seizure, the answer is not a better
messenger.** It is device encryption, a strong passcode, disabling biometrics
before you cross a border, and knowing what your jurisdiction can compel.

Turning on the app passphrase does help against one specific case: someone who
takes the storage but not an unlocked session. It does nothing against
someone watching you type it.

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
six sizes) and when it arrived. They do not see who sent it or what it says —
sealed sender and the mailbox-as-a-hash design remove those — and no envelope
says who you talk to. But the relay sees *when* each mailbox is busy, and
patterns in that are not nothing: the members of a group all receive their
copy of a message within a fraction of a second of each other, every time,
and so does each of your own devices. We measured it (`THREAT_MODEL.md`, R18
and R19). A relay that keeps timestamps can work out which mailboxes belong
together; it still cannot put a name to any of them.

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
subpoena to us produces nothing.

`USING_Z.md` has the recovery guidance. The short version: make a backup,
write the recovery code on paper, keep them apart.

## It cannot stop a relay from refusing to deliver

A hostile or broken relay cannot read your messages or forge them, and no
envelope tells it who is talking to whom (the timing patterns above are what
it has instead). It *can* drop them, or go away entirely.

Availability is the one thing you are trusting the relay operator for, which
is why self-hosting exists and why the address is a setting rather than a
constant.

## It cannot make key verification happen for you

Z shows you a safety number and tells you when it changes. It cannot make you
compare it, and it cannot compare it for you — that would need a directory of
identities, which is exactly the thing this design refuses to build.

An unverified conversation is still encrypted, but you are trusting that
nobody interfered when you exchanged codes. Verifying takes a minute and it is
the only step that closes that gap.

Key transparency (`docs/adr/0006-key-transparency-log.md`) catches some of
this automatically once the public log is running: every device list an
account publishes is recorded where any contact can check it, and a device
added behind your back cannot stay hidden from the people you talk to. It
does **not** catch an exchange the attacker controlled from the start — a
substituted code is a different identity, with its own honest-looking
history — so the safety number remains the check for that, and it only
works if someone looks at it. The log's service and the app's checks are
built; until the log is live (`docs/GA_CHECKLIST.md`, G3) the check is your
contacts' devices alone.

## It has not been audited

No external cryptographic review has been performed. The design has been
reviewed by the people who wrote it, which is worth something and is not the
same thing.

The claims are written down with their evidence in `AUDIT_SCOPE.md`, the
vectors are re-derived by independent implementations, and the disclosure
policy (`VDP.md`) grants safe harbour to anyone who wants to go and check. But
until a review happens, "unaudited" is the accurate word.

## It cannot promise the app you installed is the app we wrote

It can get closer than most. Builds are reproducible on any machine at a
stated path, releases carry signed provenance recorded in a public
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
ciphertext addressed to a hash, and the machine forgets it on restart.** A
recording made today does not become readable when quantum computers arrive.
An identity cannot be forged, now or later, without breaking two independent
signature schemes.

That is a strong and unusual position, and it is worth being precise about,
because a claim that is too broad gets someone hurt and a claim that is too
narrow gets ignored.

What it is not is protection from the device in your hand, the person you are
talking to, or someone who can watch both ends of the connection.
