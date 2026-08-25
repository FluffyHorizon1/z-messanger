# Google Play store listing — copy-paste text

Everything the **Main store listing** page asks for. Paste as-is or tweak.

## App name (max 30 chars)

```
Z Messenger
```

(The package id stays `app.zmessenger.zapp`; the display name on the phone
stays "Z". "Z Messenger" is the searchable store title.)

## Short description (max 80 chars — this one is 79)

```
Zero-trust encrypted messenger — no account, no phone number, no server storage
```

## Full description (max 4000 chars)

```
Z is a messenger built on one idea: the server should know nothing.

There is no sign-up. No phone number, no email, no username, no password. Your
identity is a cryptographic key pair generated on your device the first time
you open the app — it never leaves your device unencrypted, and nobody, not
even us, holds a copy.

END-TO-END ENCRYPTED, ALWAYS
Every message and attachment is encrypted on your device with a Signal-style
double ratchet before it leaves, and only your contact's devices can decrypt
it. There is no "secret chat" mode, because every chat is the secret mode.

A SERVER THAT STORES NOTHING
Messages travel through a relay that holds only undecipherable ciphertext,
addressed to anonymous mailbox IDs, in RAM, until they're delivered — then
they're gone. Nothing is ever written to a database or a disk. A complete copy
of the server would reveal no messages, no names, and no list of users,
because none of that exists there.

ALL YOUR DEVICES, ONE IDENTITY
Link your desktop or a second phone by comparing a short safety code between
the two screens. Your chats, photos and files stay in sync across your own
devices — still end-to-end encrypted. Lost a device? Revoke it with one tap
and every contact's app immediately stops trusting it.

BUILT TO BE VERIFIED, NOT TRUSTED
• Compare safety numbers with a contact in person to rule out interception
• Disappearing messages, from 30 seconds to a week
• Encrypted attachments up to 24 MB, integrity-checked end to end
• Local vault encrypted with XChaCha20-Poly1305, key held in your device's
  hardware keystore, with an optional app passphrase
• Content-free notifications: the push wake-up contains no message and no
  sender — your device fetches and decrypts privately
• Open source, with signed releases and published SHA-256 checksums

RUN IT YOURSELF IF YOU WANT
Don't want to use our relay? Host your own with one Docker command and point
the app at it. The protocol, the server and the app are all open source.

Z is for people who think privacy should be the default, not a feature.
```

## Categorisation & contact

| Field | Value |
|---|---|
| App or game | App |
| Category | Communication |
| Tags | Messenger, Privacy, Encryption |
| Email (support, shown publicly) | finnianbond@gmail.com |
| Website | https://zmessengers.com |
| Privacy policy URL | https://zmessengers.com/privacy |

## Graphics you need to prepare

| Asset | Spec | Notes |
|---|---|---|
| App icon | 512×512 PNG, ≤1 MB | Export the launcher icon (amber Z on dark) at 512 |
| Feature graphic | 1024×500 PNG/JPG | Dark background, big amber "Z", tagline "Zero-trust messaging." |
| Phone screenshots | 2–8, PNG/JPG, 9:16, ≥1080px wide | Take on your phone (below) |

Screenshots to take on your phone (Settings → hide sensitive names first if
needed): 1) the chat list, 2) an open conversation with a photo, 3) the
Linked devices screen, 4) the safety-number/verify screen, 5) onboarding
("Zero-trust messaging" hero). Screenshot with Power+VolDown; crop nothing.
