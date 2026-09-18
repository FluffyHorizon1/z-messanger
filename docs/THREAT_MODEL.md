# Z — Threat Model

This document is deliberately honest about what Z protects, what it does not,
and why. "Zero trust" here means **you do not have to trust the server** to
keep your message contents — or, since sealed sender, who you talk to —
private. It does *not* mean magic. Read this before relying on Z for anything
that matters. The normative wire format is `PROTOCOL.md`; the design
decisions that changed the model are in `adr/`.

## What Z is

An end‑to‑end encrypted messenger — 1:1 and small groups, text, attachments
and voice notes — across a user's several devices. Messages are encrypted on
your device and only ever decrypted on your contacts' devices (and your own
other devices). The server ("relay") is a dumb pipe that shuttles opaque
ciphertext between mailboxes and holds undelivered ciphertext in RAM only —
its own, or a shared RAM‑only store where a deployment runs several
instances — until it is delivered, until it expires, or until that memory
goes.

## Cryptographic design in one paragraph

Each **device** holds an Ed25519 signing key (relay authentication, routing
id = hash of the key) and an X25519 key (session establishment). An
**account** is an Ed25519 root key that signs *device certificates* and a
versioned, signed *device list*; a one‑device account is exactly the original
v1 identity. Two devices establish a session with an X3DH‑style handshake
(no server prekeys — the peer's long‑term X25519 key stands in) and then run
the **Double Ratchet** (Signal's construction): every message uses a fresh
single‑use key, giving forward secrecy and post‑compromise security on every
round trip. Since protocol v2, an **ML‑KEM‑768** (FIPS 203) shared secret
established inside the ratchet is mixed into every message key — a hybrid
that stays confidential against a future quantum adversary who breaks
X25519 — and is **rotated periodically** so a stolen device state does not
keep the quantum‑safe secret forever. Contents are sealed with
XChaCha20‑Poly1305 and padded to 256‑byte blocks. Attachments use a per‑file
key delivered inside the ratchet. Every envelope is **sealed** to the
recipient device so the relay does not learn who sent it.

## Trust boundaries

| Party | What they can do | What they **cannot** do |
|-------|------------------|--------------------------|
| The relay server | See that an opaque blob of a *padded* size was delivered to routing‑id R at time T; hold it in RAM (its own, or the RAM‑only store its instances share) until delivery or expiry; see which routing ids are online, which instance each is connected to, and when they read their mailbox; see the **network address** every socket comes from, and that the anonymous socket a sealed envelope arrives on shares an address with some authenticated one (R21) | Read message text, names, file names or contents; learn **who sent** an envelope — not from the envelope (sealed sender) and not from the connection, which never authenticated (§12.1); forge or replay messages; recover anything once the memory holding it has restarted — every instance's and the store's, which is what "nothing at rest" means here; learn who is in a group, or which devices are one person's, **from any envelope** (no group id, no membership, no account on the wire — but a group message is one envelope per member sent in one burst, and a person's other devices get their copy in the same burst; the bursts are a pattern: R18, R19). **This was untrue until 2026‑09‑13 and is worth recording**: the client used the message's own `mid` as the relay envelope id, so a group's N envelopes arrived bearing one identical string — the recipient set, stated outright, with none of R18's timing analysis — and because a `mid` is plaintext to every member, any one of them could name a message to the operator and be told who else received it. `PROTOCOL.md` §12.2 had specified a fresh id from the start |
| A network eavesdropper (with TLS) | See that you connected to a relay | Read anything (TLS + E2E) |
| A network eavesdropper (without TLS) | See destination routing ids, padded sizes and timing | Read contents or learn senders (still sealed + E2E) |
| Someone who steals your locked device | Hold encrypted bytes | Read messages without your OS user / keystore credentials (and app passphrase, if set). **This was less true than it reads until 2026‑09‑14**: two key‑value cells opted out of the vault's cell‑by‑cell sealing and between them held the session state — `sync_session`, the self‑sync ratchet with this account's own devices, and `cextra_<rid>`, the ratchets with each contact's other devices. Both serialise the root key, the ratchet seed, both chain keys and the cached skipped message keys, base64, in a plain SQLite file, so `z.db` alone decrypted the self‑sync mirror — which carries every message the phone sends or receives — and let a reader forge mirrors back into the owner's own devices. Which keys may be plain is now a declared list the vault enforces, and a vault that holds an undeclared one seals it when it opens |
| Someone who steals your **identity backup** (`.zid`) and its passphrase | Impersonate your account: read *future* messages sent to a device they enrol, sign a new device list | Read *past* messages (backups hold identity and contacts, never messages); enrol a device **silently** — contacts and your honest devices are designed to notice (device‑list transparency, below) |
| Your contact | Read what you send them; screenshot it; keep it forever; add you to a group; fill your mailbox at the relay while you are offline, so that others' envelopes to you are refused until you next connect (R22) | Prove to a third party that *you specifically* wrote something (messages are repudiable); learn your other devices' keys beyond what the signed list states |
| A group admin | Decide membership; the invite is asserted over the admin's authenticated channel | Read messages sent before they were in the group; decrypt anything — there is no group key, every message is pairwise‑encrypted to each member |
| Your own linked device | Everything your primary device can do with messages (it is you) | Enrol further devices or sign a device list unless it was explicitly given the account root at pairing |

## What Z protects against

- **A malicious or compromised relay.** The relay never has keys or
  plaintext. It cannot read, alter, or forge messages, and — with sealed
  sender — it is not told who sent an envelope: not by the envelope, and
  not by the connection it arrived on, which never authenticated (§12.1).
  Until 16.1 the second half was not true: sealed envelopes were sent on
  the device's authenticated connection, and a relay process that logged
  (connection, destination) would have had the graph the envelope withheld
  — nothing *stored* named a sender, and nothing *running* needed to be
  told. What the relay still sees is the network address a socket comes
  from (R21). This is the core guarantee and it holds even if the operator
  is hostile or hacked, to exactly that extent.
- **Server‑side data breaches / subpoenas of stored messages.** Nothing at
  rest to seize. Undelivered messages exist only in memory — the relay
  process's, or the RAM‑only store its instances share (persistence off, no
  public address, `render.ha.yaml`) — and are wiped on delivery, on expiry
  (`QUEUE_TTL_HOURS`, 72, per envelope), or when that memory restarts.
  Delivered messages exist only on the devices.
- **Passive network surveillance of content.** Contents are end‑to‑end
  encrypted regardless of transport; `wss://` hides the routing metadata from
  the network as well. The app will not connect to a public `ws://` relay
  without asking first, in as many words, and it will not adopt one at all on
  the say‑so of a restored backup — from 2026‑09‑13; until then, three of the
  four places that accepted a relay address said nothing about it.
- **Message tampering, replay and sender forgery.** Every message is
  authenticated (AEAD with the ratchet header as associated data); the relay
  no longer attributes a sender, so authenticity rests entirely on the inner
  layer — a forged sender simply fails decryption and is dropped.
- **Machine‑in‑the‑middle key substitution.** Each pair can compare a
  60‑digit **safety number** derived from the two *account* keys; it is stable
  across device changes. Device pairing shows a 6‑digit SAS on both screens
  for the same reason.
- **Forward secrecy and post‑compromise security** (Double Ratchet) —
  classical. **Post‑quantum confidentiality** of everything after the first
  round trip (ML‑KEM‑768 mixed into message keys), and post‑quantum
  post‑compromise security through periodic re‑keying (`PROTOCOL.md` §17.7).
- **Downgrade of the post‑quantum layer.** There is no unauthenticated
  capability flag; the offer is inside the ratchet and the ciphertext is in
  the authenticated header, so an active attacker can only cause a decryption
  failure, never a silent fallback.
- **Silent device enrolment, split views and silent removal** (someone
  holding your account root signs a device list you did not). No key server
  exists to trust, so Z makes these *detectable* instead: every message
  carries the sender's claim about its own device list and an echo of the
  recipient's; contacts and your own devices cross‑check them; a removed
  device is told by the contacts that stopped delivering to it; a root that
  regresses its list is itself a signal (`PROTOCOL.md` §3.6, `adr/0001`).
  Sends are never blocked — the user is shown what disagrees.
- **Plaintext on disk.** The vault is encrypted per cell; attachments are
  encrypted blobs; voice notes are captured into memory and never written
  unencrypted; search decrypts in memory only; history sync to a new device
  travels only over the self‑sync ratchet. Two holes in that sentence were
  found by review on 2026‑09‑12 and closed in 2.8.4, and both were outside
  the code that was being careful. The file picker does not hand an app the
  file the user chose — it copies it into the app's cache directory and hands
  over the copy — so **every attachment ever sent had an unencrypted copy
  outside the vault**, surviving the sweeper, the disappearing‑message timer
  and "reset identity" alike; both picker call sites now delete it, and a
  test refuses a call site that does not. And the app had never set
  `android:allowBackup="false"`, so the platform default put the whole vault
  directory in Android's Auto Backup set: the database seals *cells* and not
  its structure, so the copy carried the contact graph and every message's
  direction and timing in the clear, and before Android 9 Auto Backup had no
  end‑to‑end encryption at all. Both opt‑outs (and, for API 31+ device
  transfer, `dataExtractionRules`) are now set and checked by
  `tool/check_android_data_safety.py` — a default nobody had written down was
  how it shipped for eight releases.

## What Z does **not** protect against (be honest with yourself)

- **Metadata against the relay operator.** The relay learns *which mailboxes
  receive* traffic, when, and in which of six padded size buckets. Sealed
  sender removes the *sender* from that view — from the envelope, and since
  16.1 from the connection too — and per‑device sealing means the relay
  cannot group a person's devices from any envelope. But it sees the
  network address every socket comes from, and a device's anonymous sender
  socket and its authenticated mailbox socket come from the same one (R21);
  it can still observe that a mailbox is active and correlate timing across
  mailboxes; and the mirror to a person's other devices follows every
  message within tens of milliseconds (R19), which is a correlation it does
  not have to work for. How fast timing alone pays off is measured, not
  guessed: an operator who keeps timestamps names a group's mailboxes
  after about eight messages and pairs a person's devices after three, and
  the delays or dummy traffic that would change that are not ones a
  messenger can carry ("Timing patterns", below). If you need
  metadata privacy against the operator, run the relay yourself and/or put it
  behind Tor.
- **A compromised endpoint.** Malware, spyware, or a physically unlocked
  device gives an attacker everything Z can decrypt — no E2E scheme prevents
  this. Z encrypts the local vault, but once your OS user (and passphrase)
  is unlocked the app can read it.
- **A stolen account root, in the window before detection.** Whoever holds
  your identity backup and its passphrase *is* you to the protocol. Device‑list
  transparency makes a rogue enrolment visible to you and your contacts
  within a message or two of it being used — it does not prevent it, and an
  attacker who also keeps your honest devices offline delays the alarm until
  they are back. The remedy is to reset your identity. Do not store the
  backup where the device itself is stored.
- **A malicious contact.** Anyone you message can screenshot, copy, or leak
  what you send. Disappearing messages are a courtesy against accidental
  retention, not an anti‑exfiltration control.
- **A malicious group admin** can add anyone to a group, and every member
  sees the member list; leaving is honoured by honest clients only.
- **Unverified first contact.** If an attacker intercepts the *initial*
  contact‑code exchange and swaps in their own keys, they can machine‑in‑the‑
  middle you until you compare safety numbers. Exchange codes over a channel
  you trust and verify the safety number for anything sensitive. No
  transparency mechanism fixes an exchange the attacker fully controls.
- **Traffic analysis / global passive adversary.** Z is not an anonymity
  network. Timing and volume correlations are possible for someone who can
  watch both ends.
- **Denial of service.** A hostile relay can refuse to deliver, or drop
  queued messages. It cannot read them, but availability depends on the relay
  you choose. A relay (or anyone) can also inject garbage that costs a
  recipient a failed decryption — sealed sender is deliberately
  unauthenticated at the outer layer.
- **Endpoint backups you make elsewhere.** A plaintext device backup to some
  cloud is outside Z's control. Z no longer *opts into* one on your behalf:
  see the on‑disk bullet above. Identity moves between devices one way only,
  through the archive you export deliberately (`BACKUP.md`).
- **Lost keys = lost identity.** There is no server account to recover.
  Losing every device without a `.zid` backup means a new identity and
  re‑verifying contacts. That is the cost of having no server custody.
- **The quantum layer's edges.** The session‑opening `hello`, the key offer
  itself and anything sent before the offer is answered are classical; the
  initial handshake secret stays classical (the mix is applied to message
  keys precisely so that this does not matter after the first round trip).
  ML‑KEM in pure Dart is best‑effort constant‑time; a timing leak there can at
  worst reduce security to v1, never below it.

## Residual risk register

The section above says what Z does not protect against. This says what is
*left over after everything currently built* — including the risks the recent
phases introduced or uncovered, which would otherwise be scattered across five
ADRs and findable only by someone who read all of them.

Two things this register is for. An auditor should be able to start here rather
than reconstruct it. And a claim like "post‑quantum secure" or "signed
releases" should be checkable against a specific line saying what that does and
does not cover — because the dangerous failure is not an unmitigated risk, it
is an unmitigated risk hidden behind a phrase that sounds like it was handled.

**Exposed to** is who actually gets the information or capability.
**Status** is one of: *accepted* (a deliberate trade), *deferred* (a plan
exists, gated on something), *open* (should be closed and is not yet).

| # | Residual risk | Exposed to | Why it remains | What reduces it | Status |
|---|---|---|---|---|---|
| R1 | Which mailbox receives traffic, when, and in which of six size buckets | Relay operator | Delivering a message requires knowing where to deliver it. Sealed sender removes the *sender*; the recipient cannot be removed without a mixnet | Self‑host (`SELF_HOSTING.md`), or front the relay with Tor | accepted |
| R2 | An occasional ~16 KB envelope marks an account as running a v3 client | Relay operator | A 3.3 KB post‑quantum signature does not fit the 1 024‑ and 4 096‑byte buckets ordinary chat occupies, and no arrangement makes it fit (`adr/0004`, addendum: measured, only a text of ~2 000 characters or more shares its bucket) | Its *timing* is decorrelated from any device‑set change, and its size is constant regardless of device count, so it reveals nothing beyond "v3" | accepted |
| R3 | The post‑quantum device‑list signature can be dropped, leaving a list verified classically for ever | On‑path attacker | Not preventable at the network layer: it is the one large envelope in a conversation and therefore the easy one to drop | Detected and surfaced (§18.9) — the sender states inside the ratchet that it sent one, and a claim with nothing behind it is asked about and then reported | accepted |
| R4 | A contact code (QR) is authenticated classically end to end | A future quantum adversary present at the exchange | A hybrid identity is ~9× too large to scan (`adr/0003`). The commitment binds the post‑quantum key to the scan; it does not make the scan itself post‑quantum | Exchange codes in person; the commitment means the *in‑band* key cannot be substituted afterwards | accepted |
| R5 | The session‑opening `hello`, the key offer, and anything before the offer is answered are classical | A future quantum adversary recording now | The first round trip has no shared post‑quantum secret yet, by construction | The mix applies to message keys, so everything after the first round trip is covered; the exposure is bounded to the opening exchange | accepted |
| R6 | Whoever holds an identity backup and its passphrase *is* the account until noticed | Anyone with both | There is no server custody to appeal to — that is the product | Device‑list transparency (7.7a) makes a rogue enrolment visible within a message or two of use; the remedy is an identity reset | accepted |
| R7 | The transparency log runs, and nothing outside this project witnesses it: an account's device lists are cross-checked by its contacts (§3.6) and against the log (§19), which now holds them — but one party signs that log's head, so a head shown to one reader and not another is recorded nowhere either can see | Anyone whose contact is shown a split view they are not part of | `adr/0006` built it end to end — the service (`kt/`), the reader, the client with every state tested against the real service — and since 2026-09-13 it is deployed at `kt.zmessengers.com` under the key the shipped client pins. What it lacks is a mirror or witness run by somebody else (`GA_CHECKLIST.md` G3). A log records what an account published; an exchange the attacker fully controlled from the start it cannot detect, which only safety numbers catch | Safety numbers, which catch a substituted exchange the moment two people compare; gossip (§3.6) for everything after; and the log for the split view — a client refuses a head that does not extend the one it holds, so a fork served to the same client over time is caught with no witness at all. What the witness adds is the fork served to *different* clients, which none of them can see alone. Separately, and worth stating because the operator's power was understated as split views alone: until 2026‑09‑14 anything that could write the log's data directory could forge an entry for any account in it — the publish signature was verified once on arrival and not stored, so a replay re‑checked only fields whoever wrote the line also chose. The signature is stored and re‑verified now, and the log refuses to sign a history smaller than one it has already signed, so appending or truncating is caught; replacing the directory wholesale is not, which is what `KT_MIN_SIZE` and a second person's mirror are for | **deferred** — closes when G3's four conditions hold |
| R8 | A desktop user can be served an older release, with valid provenance | Whoever serves the download | There is no in‑app updater, deliberately — an updater is a code‑execution channel into every install | Play refuses an older `versionCode` on Android. On desktop, the release page and the attestation both name the version, but only if the user looks | **open** — see `PROVENANCE.md` |
| R9 | Build provenance is SLSA **L2**, not L3: a compromised build step could forge provenance about itself | Anyone who can inject into the build | L3 needs the build isolated from the signing material, which is a restructure rather than a setting | Provenance is signed by the hosted build service and publicly logged, so a forged one is at least visible | **open** |
| R10 | Reproducibility is proven on one machine, not across machines | — | *Settled on 2026‑09‑09, and the answer was no.* The first run failed | **Superseded by R16**, which records what was actually measured. Kept here rather than deleted: this row said the first CI run would settle it, and a register that quietly removes a row once its answer turns out to be unwelcome is not a register | superseded |
| R11 | Google holds the Play app‑signing key and can sign an APK as Z | Google, or anyone who compels Google | Play App Signing is a condition of distributing through Play | Reproducible builds plus provenance let anyone compare what Play serves against what the source produces — the substitution is detectable, not preventable | accepted |
| R12 | A push notification tells Google (FCM) that *some* device should wake | Google | Waking a sleeping device requires the platform's push service | Notifications are **contentless** — no text, no sender; the device then fetches from the mailbox as usual, and tokens live in relay RAM and expire | accepted |
| R13 | A malicious contact can retain, screenshot or leak anything sent to them | Your contact | Nothing cryptographic can prevent it | Disappearing messages are a courtesy against accidental retention, and are described as exactly that | accepted |
| R14 | A hostile relay can refuse to deliver, or drop queued ciphertext | Relay operator | Availability depends on the relay you choose | Self‑host; the relay cannot read what it drops. (An *honest* relay no longer drops anything to make room — R22.) Where instances share a store, the store is a second place the same operator can drop the same ciphertext from, and a second thing that must be run without persistence — the same trust, more of its surface: `/health` names the coordinator, and the store's configuration is in the repository's Blueprint rather than in an assurance | accepted |
| R15 | Timing and volume correlation by someone watching both ends | A global passive adversary | Z is not an anonymity network and does not claim to be | Tor for the transport, if that is your threat model | accepted |
| R16 | The shipped APK is reproducible **only at a fixed checkout path**: building in a directory not named `z` changes `libapp.so` and `libdartjni.so` | A verifier who builds somewhere else and reads the mismatch as tampering | The Dart AOT snapshot embeds its absolute build directory as a source URI (`.dart_tool/flutter_build/dart_plugin_registrant.dart`), and the two libraries compiled during the build inherit it. Measured 2026-09-09: two runners at one path are byte-identical, so the **machine is not a variable**; only the path is | The path is stated in the build recipe, as Debian records `Build-Path`. CI asserts machine-independence and asserts that a path change moves those two libraries and no others, so the leak cannot spread unnoticed. `verify_reproducible.py` names what differs, so a verifier who ignores the recipe gets a known deviation rather than a mystery | **accepted** — with the real fix (a relative URI) upstream in the Flutter tool |
| R17 | Two accounts that add each other are pairable at the relay: each mailbox receives one ~16 KB envelope (the `pqid`, §18.2) within seconds of the other | Relay operator | The ML‑DSA key does not fit the code that bound it (`adr/0003`) and the safety number needs it promptly (§18.5), so it travels in‑band at first contact; the size marks the envelope (`adr/0004`, addendum). Measured 2026‑09‑11, a mutual add sent it twice in each direction — four such envelopes inside one round trip | Now one each way: every reason to send is coalesced into one debounced send that says whether the peer's key is held (`ack`), and a key that arrives with `ack` is not answered (`pq_identity_exchange_test.dart`). The pair itself remains; a mixnet or Tor would hide it, `adr/0004`'s rejected fragmentation would not | accepted |
| R18 | Group membership is inferable from the fan‑out's timing: one group message reaches every other member's mailbox in one burst, and the same mailboxes burst together every time anyone in the group speaks | Relay operator | Pairwise encryption means N envelopes per message, sent one after another over the sender's socket. Measured (`group_spread_bench_test.dart`, five members, one relay on loopback): the members' copies are relay‑stamped within 64–135 ms of each other, every message. Only a mixnet breaks the pattern, and Z is not one (R15) | Self‑host, or Tor. Jitter and cover traffic were measured rather than argued about (16.2, below): with nothing done, a relay that keeps three days of timestamps names a five‑member group's mailboxes after 8 messages. A random delay of up to a minute on every copy makes that 50 at ordinary rates; ten minutes — every group message up to ten minutes late for every recipient — is what it takes to pass the 2 000 messages the study stops at, and a quiet population needs an hour. A thousand dummy deliveries a day per mailbox (~1.4 MB/day) makes 8 into 50 on their own, and pass 2 000 only with ten seconds of delay on top. Neither is done: the pattern adds up with every message and chance does not, so a group that keeps talking beats any option a messenger can carry. The trust table said "cannot learn who is in a group" until this was measured; it now says from what | accepted |
| R19 | A person's devices are groupable from timing: every message their phone sends or receives is mirrored to their laptop at once, and a contact who holds their device list fans out to both in one burst | Relay operator | Self‑sync is what makes several devices one account, and it is immediate by design — a laptop that lags its phone by minutes would be a worse product for a smaller leak. Measured (`device_link_spread_bench_test.dart`, one relay on loopback): the laptop's copy is relay‑stamped 15–22 ms after the contact's when the phone sends, 31–53 ms after the phone's when the contact sends, every message. Linking is loud on its own: a mailbox that has just appeared receives the history replay (7.6b) as 65 536‑bucket envelopes — measured, a 250‑message chat is two of them, plus four 4 096 and one 16 384 for the lists and keys — which nothing but linking produces | Self‑host, or Tor; or one device. Measured (16.2, below): the mirror makes the two mailboxes co‑activate on every message, so a relay pairs them after 3 — an hour of ordinary use. A random delay of up to a minute on the mirror makes that 30, still under a day; a thousand dummy deliveries a day per device makes it 20 on its own; only ten minutes of delay keeps the pair apart for the three days modelled, and in a quiet population not even that. A laptop ten minutes behind its phone is not the product, so none of it is done. Per‑device routing ids and sealing still keep the *identity* off the wire — the relay groups two mailboxes, not a name | accepted |
| R20 | Anyone who holds an account's public key can read that account's publish history from the transparency log or a mirror: how many device lists it has published, at which versions, and when | Anyone with the contact code; the log operator additionally learns the public key itself at publish | Labels are `SHA‑256(context ‖ accountEdPub)`, so only a party already holding the key can compute one; a VRF‑blinded label (`adr/0006`, considered and rejected) would hide labels from readers of a *mirror* at the cost of a proof per lookup and a second key, for identifiers that are 256‑bit random and cannot be enumerated. Contacts learn nothing the gossip did not already tell them except timestamps; the sealed value hides the lists themselves from everyone else | Values sealed under a key derived from the account's public key (§19.1) — a mirror sees labels and ciphertext; publish through a durable queue, so timing reflects when the account changed its devices rather than when it was online, only loosely | **accepted** — `adr/0006`, 0001's named cost with the log built |
| R21 | A sealed envelope's sender is attributable by network address: the anonymous socket it arrives on and the device's authenticated mailbox socket come from the same address, and on a home or office connection an address is as good as a name | Relay operator; anyone at the TLS terminator | Sending sealed envelopes on a connection that never authenticated (16.1, §12.1) removes the identity the relay used to be handed with every send; it cannot remove the address a socket comes from. Carrier‑grade NAT puts many phones behind one address and blunts this; a fixed address does not. Two sockets from one address that open together and stay up together are a pair whether or not either says so | Tor or a VPN in front of the app, which the app does not provide; running the relay yourself; the timing study in 16.2 says what jitter would and would not buy | **accepted** — `adr/0007`; before 16.1 this row would have read "attributable by connection identity", which is worse and was not written down |
| R22 | A mailbox can be filled by anyone who holds its routing id: 64 MB of junk sent while its owner is offline, and every honest envelope to that mailbox is refused until the owner drains it or the junk expires (72 h) | Anyone with the routing id (a contact; the relay operator; without TLS, the network) | The relay accepts a sealed envelope from anyone, by design (§16): it cannot tell junk from a message without a sender to hold responsible, and a per‑sender quota would need the sender the envelope withholds. Until 2026‑09‑11 the same flood did something worse — it *evicted* what was queued, silently, after the senders had been told `sent` — and R14 said the operator could drop ciphertext without saying that any contact could too | The cap is per mailbox, so a flood harms one mailbox and never the relay or another user; the refusal is loud (`queue_full`, PROTOCOL §12.4) and the honest sender's outbox retries, so nothing accepted is lost and nothing refused is lost either — it is late; the junk clears the moment the owner connects, since it fails decryption and is acknowledged away like anything else; `z_refused_total` shows an operator that it is happening. The remaining cost is delay, bounded by the owner's next connection. Filling several mailboxes could lock a deployment until 2026‑09‑14, and the reason the healing argument did not cover it is worth stating: healing means the owner connects and drains, and a mailbox addressed to a routing id nobody holds has no owner. `to` is checked for the SHAPE of a routing id and nothing more — the relay cannot know which hashes name a real identity, and a sealed envelope may be sent on a connection that never authenticated (§12.1) — so four hundred random strings filled a 256 MB `noeviction` store in seconds, every real send got `store_full`, and the floor was `QUEUE_TTL_HOURS`: three days. Creating a mailbox is now rate‑limited across all senders (`NEW_MAILBOX_PER_MIN`), which bounds the flood without bounding anybody's conversation, and the single‑instance RAM store has a ceiling of its own (`MAX_STORE_BYTES`) where it previously answered the same flood with an OOM kill (`mailbox_admission.test.js`). "Without bounding anybody's conversation" was untrue between 2026‑09‑11 and 2026‑09‑14 and the shape is worth keeping: the gate was charged whenever the recipient had no mailbox, and a mailbox exists only while it holds unacknowledged mail, so a recipient who is online and acknowledges — the ordinary case, and what §12.5 requires — had none when the next message arrived. Every message paid, and the gate is global, so the relay stopped at `NEW_MAILBOX_PER_MIN` *messages* a minute for everyone, refusing `store_full` with an empty store. It is charged on first contact now, against a bounded set of recipients this instance has queued for, which a refused send never enters — otherwise a flood that was refused would have bought the flood after it. The same window held a second way to lock a deployment that healing did not cover: TTL expiry freed the mail without crediting the store accumulator, so a relay that had once been busy refused the first byte of every send until it was restarted, with `/health` reporting `queuedEnvelopes: 0`. `storeBytes` is published beside it now. A shared store at its own limit refuses sends (`store_full`) but still admits logins and still lets mailboxes drain, so THAT case heals (§12.4). "Never the relay" was briefly untrue in the other direction and is worth recording: between 2026‑09‑11 and 2026‑09‑12 an *acknowledgement* that named nothing made the relay read the acknowledger's whole mailbox to look for it, and acknowledgements had just been exempted from the rate limit — ten frames against a 6 MB mailbox pulled 59 MB out of the store, free. That fallback is gone (a fixed, small number of keyed lookups whatever the frame names), the exemption now covers only an acknowledgement that actually frees an envelope, and `z_ack_miss_total` shows the rest; a sealed sender can also take at most `ID_SLOTS` (8) of a mailbox's slots for any one id before being refused, which the mailbox cap already bounded anyway | **accepted** — the alternative (evict the oldest) was measured against this one in `queue_caps.test.js` and is worse in every case |
| R23 | An invite link is a **bearer token** until it is spent: whoever opens it first completes the ceremony, under whatever name they choose to reveal | Anyone who sees the message that carried it — a group chat it was pasted into, a shoulder, a backed-up SMS, the carrier | The invite has to travel over a channel the two people already have, and Z cannot make that channel confidential; that is the problem it exists to solve rather than one it can assume away. Anything that made the link unusable by a stranger would be a second secret, and the pair have none | One-time (a second attempt on a spent invite does nothing) and 24 hours, so the window is small and closes on use — and from 17.9 the screen says how much of it is left rather than only "Pending", and withdraws the link, the code and the QR the moment the invite is answered or runs out, so a token that no longer works is not still sitting there to be sent to somebody; and the eight digits are what an impostor cannot pass — they are compared over a channel where the two people recognise each other, and an impostor who completes the ceremony shows a *different* string on the other screen. A user who skips the comparison is left explicitly unverified and told so on screen (§20.6) | accepted — `adr/0009` |
| R24 | The relay sees a **pair of ephemeral mailboxes** exchange four envelopes over hours or days and go quiet, which is a shape it can tell from ordinary traffic | Relay operator | The two mailboxes are HKDF'd from the invite secret, so neither is linkable to an account and neither is used again — but they are two mailboxes talking to each other, and R1's "which mailbox, when" applies to them as to everything else. Hiding the shape would need cover traffic the relay does not have (R18, R19) | Nothing in the exchange carries either party's routing id, account key, contact code or name, and the reveals are sealed under a channel whose ephemeral secrets were never posted — asserted against a recording of what the relay actually received, not against what the client meant to send (`connect_relay_test.dart` (5)). The ceremony acknowledges its mailboxes empty when it finishes, so no transcript sits in relay RAM for the 72-hour queue lifetime. What remains is the pair and its timing, which R1/R17/R18 already describe | accepted |
| R25 | A **skipped comparison is trust-on-first-use**: the contact is added on the strength of whoever answered the invite | The user, who may not realise which of the two states they are in | Requiring the comparison would mean refusing to add anyone whose contact cannot take a call at that moment, and the paste flow this replaces has always been trust-on-first-use with no comparison available at all | The difference is that the app says so. Skipping is its own button ("we have not compared yet"), the contact lands at the ordinary unverified state with no tick, and the screen names that state and says where to fix it. A *failed* comparison is not the same thing and offers only "stop": nothing is added, and the invite is spent so it cannot be retried into whoever produced the mismatch (§20.6, `connect_invite_test.dart` (4, 5)) | accepted |
| R26 | Anyone holding a contact code can send **file chunks** to that mailbox: they travel outside the ratchet, sealed under a file key that arrives in the offer, so before the offer there is nothing to check them against and nobody to hold responsible | Anyone with the routing id — which is anyone the code was given to, and the code is meant to be handed out | A chunk legitimately arrives before the offer that explains it (they are sent as sidecars and the relay promises no order), so they cannot simply be refused; and the MAC that would identify them is computed with key material only the offer carries | Until 2026‑09‑13 each was stored unconditionally and **relayed to every linked device**, so a stranger's junk became N envelopes the victim's own phone emitted, and a chunk whose offer never came was never swept. Now: an unexplained chunk is held, the holding is capped (`ChatService.maxHeldChunks`, oldest out first) and trimmed after the insert rather than checked before it, so concurrent arrivals cannot overshoot it; nothing unexplained is relayed onward, which removes the amplification entirely; and once an offer names a fid, an index outside its range or a file already assembled is refused. A chunk whose `fid` is not a file id at all (§7: sixteen base64url characters) is refused before it is held, which closes a separate hole — the value was used unchecked as a filename, so it named a *place* as well as a file (`file_id_test.dart`) — though matching the shape costs an attacker nothing, so the cap, not that check, is what bounds a flood. What remains is a bounded amount of the device's storage — a few hundred chunk rows — which the next offer or the cap reclaims (`chunk_flood_test.dart`) | accepted |
| R27 | A relay that declines to deliver the one envelope carrying the initial ML‑KEM offer delays the post‑quantum layer for that conversation; repeated, it can hold a conversation classical for as long as it is willing to keep dropping | Relay operator | Nothing authenticates an envelope that never arrives, and withholding is indistinguishable from a peer who is offline — §17.4 reasoned about tampering, where the AAD closes it, and treated withholding as the same attack, which it is not. Until 2026‑09‑13 the offer was made once per session, so ONE dropped envelope was permanent and silent on both sides | The offer is repeated while unanswered (`pqOfferRetryMs`, six hours in the app), with the same encapsulation key regenerated from the seed so a late first answer still establishes, so the cost of dropping one envelope is now a delay rather than a downgrade. A relay that drops every copy indefinitely is a relay dropping traffic, which R14 already covers and which the user sees as messages not arriving. Nothing tells the user a conversation is still classical — the assurance badge reports the IDENTITY's state (§18.3), not the session's, which is a gap this row records rather than closes (`pq_downgrade_test.dart`) | accepted |
| R28 | Deleting locally removes the data from the vault; it does not guarantee the underlying storage has forgotten it | Anyone who can image the device's flash below the filesystem — a forensic lab, a recovered or resold device | Flash storage does not overwrite in place. A wear‑levelling controller writes the new page elsewhere and retires the old one, and nothing above the FTL can address the retired copy to clear it; the same is true of a copy‑on‑write filesystem and of any snapshot the OS keeps. This applies to the SQLite file's freed pages, to an attachment blob's bytes, and to the master key file on a platform with no keystore | Everything at rest is sealed cell by cell, so a recovered page is ciphertext unless the keystore is recovered too; SQLite is run with `secure_delete`, so the page the filesystem sees is zeroed rather than abandoned with its contents; `Vault.deleteBlob` overwrites a blob before unlinking it and `Vault.wipe` does the same for every file it removes. Full‑disk encryption with the key destroyed on factory reset is what actually erases flash, and it is the platform's to provide | accepted — the mitigations are defence in depth and are described as that, not as erasure |
| R29 | **Any contact can put you in a group**, name it, and name its other members; you find out when the invite arrives | Any contact | A group is pairwise fan-out with no shared key (§11), so joining one costs the receiver nothing cryptographically and the invite is an ordinary inner message over an existing session. Requiring consent first would mean a group that half exists until everyone answers, and the members a creator lists are people the receiver has to be able to decrypt from anyway | The group is a thread, not a relationship: the members it adds arrive **unverified**, with no tick and the safety number uncompared, exactly as if they had been pasted in. The invite cannot touch anything that already exists — a `gid` is `g` and sixteen base64url characters (§11) and a routing id is 43, so a group can never be filed under a contact's id and take that conversation's name, membership or banners; that was possible until 2026‑09‑13 and is `group_id_test.dart`'s first criterion. Leaving is one tap and the history stays | accepted — the cost is an unwanted thread, and the thing worth preventing was a group that could pretend to be a conversation |
| R30 | **A pending connect invite polls on a fixed cadence**, so the relay sees a regular beat rather than a human's taps: while the app is in the foreground and anything is pending, each invite costs one throwaway identity connecting, reading its mailbox and leaving every 20 s — about 180 an hour, per invite. Nothing new is sent or stored, and the envelopes are the same four the ceremony always exchanged (§20), but a periodic beat is a more distinctive shape than an occasional one, and it marks the interval in which one particular mailbox pair is mid-ceremony. It stops when the app leaves the foreground and when the invite finishes. Jitter or a longer interval would cost the responsiveness the poll exists to buy; see 16.2 for what that trade is worth. | Accepted |
| R31 | **The transparency log's disk can be filled, and entries never expire.** Anyone who can mint Ed25519 keys — anyone — can publish genuine, correctly signed device lists for accounts nobody holds until the log's disk is full, and a log does not forget, so a full disk stays full | Anyone; no account, no invite, no relationship needed | An append‑only log is the property (§19, `adr/0006`): pruning would be a log that can lose an account's history, which is precisely what it exists to prevent. The value cap has to allow a real device list, and account keys cost nothing, so the arithmetic is a rate times a size against a disk. Until 2026‑09‑14 nobody had done it: 341 KB per publish at the protocol's 256 KiB maximum, 3,069 on the Blueprint's 1 GB, one address bucket for the whole internet — **102 minutes and 154 minted accounts to `ENOSPC`**, after which every publish got a 500 until an operator grew a disk that `/health` gave no reason to look at | Four things, none of which is a solution and all of which are stated. `KT_MAX_VALUE_BYTES` (32 KiB — a hundred devices; a real list is a kilobyte) sets entries per gigabyte, eight times what it was. `PUBLISH_NEW_ACCOUNTS_PER_MIN` charges a first publish from an account the log has never held — the R22 shape, since a flood needs accounts and the per‑account budget makes any one of them useless — and asks the index only accepted publishes build, so a refused first publish leaves an account unknown. `KT_MIN_FREE_BYTES` pauses publishing with `503 log_full` while reads continue, so the failure is a read‑only log that says so rather than a 500 mid‑write. And `/health` reports `diskBytes`, `diskFreeBytes` and `full`, because the previous three are worth nothing if nobody sees the floor coming (`publish_limits.test.js` 5–7). At the defaults a flood from one address needs about fourteen hours and 2,200 minted accounts to reach the floor, the per‑address gate binding; with `KT_CLIENT_IP_HEADER` set and a distributed flood it is the first‑publish gate that binds, and the floor is about ten hours and 5,700 accounts away — the total gate is never reached in either case. What remains is the arithmetic itself: a disk of any size fills in finite time at any positive rate, so the answer is an alarm on `diskFreeBytes` and a disk grown before it matters — and a witness (§19.9, G3) that holds the whole history should the operator's disk be lost | **accepted** — the alternative, expiring entries, is a log that forgets, and R20's readers are promised it does not |
| R32 | **The log's availability is attacker‑influenced.** Anyone can send it requests, and a gate that everybody shares is a switch whoever fills it holds: a genuine publish refused for a minute is a device list the log does not hold yet, and `adr/0006`'s table says what a list the log has not confirmed for a day costs its owner's contacts — the devices only that list added stop receiving | Anyone; no account, no invite, no relationship needed | A public log answers the internet, and behind a front that sets no client address every publisher and every reader is one address, so nothing per‑address is per‑client. Until 2026‑09‑17 the per‑address and total publish gates were charged per request, before the body and before the signature: **thirty one‑byte POSTs a minute** from anywhere — no account, no signature — emptied the shared address bucket and every genuine publish got 429 for the rest of the minute (measured, at half a request a second); moving the address gate alone would have left the total as the same switch at two requests a second. Reads had the mirror image: a 48‑byte request for a page of entries returned 3.9 MiB, 85 000:1, stalling the log for 74 ms, as often as anyone liked, behind `no-store` so nothing in front absorbed a repeat | Every publish gate counts publishes and none counts requests — each is taken after the signature verifies and given back if a later gate refuses or the write fails — so junk buys nothing and a signature that costs nothing to make buys nothing it did not write; what a request that publishes nothing can cost is bounded instead (the body cap, a cap on bodies being read at once, the request timeout), and a raw flood past those is the front's to stop as it is for any HTTP service. The mirrors' page is budgeted in bytes a minute, per address and in total, refused with `retry-after` that the mirror honours; the routes a client's check depends on are bounded by the size of one answer and are never refused by a budget, because a budget an attacker could spend on a route a client needs would be a cheaper denial than the one closed; a page below the head and a consistency proof may be cached in front. `KT_CLIENT_IP_HEADER` is what makes any per‑address gate per‑client, and it is the operator's to set once the origin is reachable only through the proxy (`publish_limits.test.js` 8–9, `read_limits.test.js` 5–7). What remains is honest capacity: an attacker who mints accounts and publishes for real spends the total gate at 120 accepted publishes a minute — visible, permanent, and needing accounts at ten a minute — and for that minute genuine publishes wait; the client treats a 429 as a wait rather than a refusal, so a publish is late by at most its next check rather than lost | **accepted** — a log that answers the internet cannot be made unreachable to the internet's traffic; it can be made impossible to stop with junk, which is what this row records |
| R33 | **A relay you were talking to could drain your mailbox at the real one, while the real one still accepts the old signature.** Authenticating to a relay is an Ed25519 signature over its challenge; until 2026‑09‑17 the signed message was the nonce alone, so a relay the user was induced to connect to — a pasted address, an invite, a machine in the middle of a `ws://` address — could open its own socket to the honest relay, present the honest relay's nonce as its own challenge, and replay the answer: authenticated as that device there, with the `ready` flush and everything queued from then on, able to acknowledge it away | Whoever runs a relay the user connects to; on a cleartext address, whoever is on the path | A signature over a nonce says whose key answered and not whose question it was. The client now signs the relay's name with the nonce (`z-relay-auth-v2`, §12.1) and never the bare form, so a current client's answer is good at one relay only. What remains is the window in which the honest relay still accepts the bare form from clients that predate it: for those clients the replay works as before, and nothing a new client does changes that | The relay counts every bare authentication (`z_auth_v1_total`) and its operator turns the form off (`RELAY_AUTH_V1=off`) once the count stays at zero; the public relay's operator decides when, against how many older installs are still connecting, since turning it off locks those out of receiving until they update. A client that meets a relay without the bound form refuses with a reason rather than falling back — a fallback on request is what the hostile relay would request. `auth_binding.test.js` performs the replay and shows it refused; `relay_auth_test.dart` shows the client producing no bare signature for a relay that asks for one | **accepted** for the window; **closed** for clients that sign the bound form |
| R34 | **A contact request reaches you unsolicited.** Anyone who holds your contact code (or a spent connect invite) can now put a request in front of you — "someone wants to connect" — where before their opening hello was dropped in silence and you never knew (ADR 0011). | Anyone who has your code; it needs no relationship, no invite | A request is an ordinary sealed envelope to your mailbox, so the relay learns nothing of it that it does not learn of any message (sealed sender is intact), and it is signed by the requester's own identity key over your routing id, so it cannot name someone who did not send it — a forged "X wants to connect" does not verify (C37). What it can cost is your attention: before this, the same person could already send you traffic; the difference is that now you SEE it, and you get to refuse it. It delivers nothing to you until you accept | A request is a quiet surface, not a per-message notification, and nothing from the requester is shown as a message or reaches a chat until you accept. Decline drops it in silence; Block drops it and every future request and every message from that routing id without a trace. The "anyone can add me" public code stays a separate, differently-worded action (ADR 0009), never the default and never the same button | **accepted** — a request you can see, refuse and block is strictly better than a silent drop you could not; the surface it opens is your attention, and Block bounds it |

### Timing patterns: what a mitigation would buy (16.2)

R18 and R19 record that a group's mailboxes, and a person's devices, light
up together. Until 16.2 the rows said that spreading the traffic out had
been considered and rejected because it "does not survive averaging" — an
argument, not a number. `server/bench/patterns.js` (`npm run
bench:patterns` in `server/`) puts numbers to it: a seeded simulation of
600 mailboxes over three days, twenty groups of five among them, every
mailbox also receiving unrelated one‑to‑one traffic at the rate in the
column heading, and an attacker who does the obvious thing — for every pair
of mailboxes, count how often a delivery to one falls within the jitter
window of a delivery to the other; work out from the two mailboxes'
delivery counts how often that happens by chance; and flag every pair whose
count chance cannot explain, at a threshold chosen so that chance accounts
for at most 5 % of what is flagged. The attacker is told the jitter and
nothing else — not the group size, not who is in a group. A cell is the
number of group messages the relay has to have seen before the attacker
names 95 % of the group's pairs at 95 % precision, in two runs of three.
The burst spread is the measured one (R18, 100 ms); "cover" is dummy
deliveries the relay cannot tell from real ones, added to the busy column.

| jitter D | quiet (5/day) | busy (50/day) | busy + cover 100/day | busy + cover 1 000/day |
|---|---:|---:|---:|---:|
| none | 8 | 8 | 12 | 50 |
| 1 s | 8 | 12 | 20 | 120 |
| 10 s | 8 | 20 | 80 | >2 000 |
| 1 min | 12 | 50 | 120 | >2 000 |
| 10 min | 30 | >2 000 | >2 000 | >2 000 |
| 1 h | >2 000 | >2 000 | >2 000 | >2 000 |

A person's two devices are a group of two that co‑activates on *every*
message the person sends or receives (R19), so the same question is how
many messages the person exchanges before the mailboxes are paired — fifty
such people among the 600, and at fifty messages a day, how long that is:

| mirror jitter D | quiet (5/day) | busy (50/day) | busy + cover 1 000/day |
|---|---:|---:|---:|
| none | 2 (1 h) | 3 (1 h) | 20 (10 h) |
| 1 s | 2 (1 h) | 5 (2 h) | 80 (1.6 d) |
| 10 s | 3 (1 h) | 12 (6 h) | >2 000 |
| 1 min | 8 (4 h) | 30 (14 h) | >2 000 |
| 10 min | 20 (10 h) | >2 000 | >2 000 |

What the tables say:

* **With nothing done, it takes almost nothing.** A relay that keeps three
  days of timestamps names a group after eight messages and pairs a
  person's devices after three. The rows were right that the pattern
  survives averaging; they understated how little averaging it takes.
* **Jitter buys nothing until it is longer than the gaps in ordinary
  traffic.** A second or ten seconds move a cell by a factor of two; a
  minute makes 8 into 50; only ten minutes — every group message up to ten
  minutes late for every recipient, a laptop up to ten minutes behind its
  phone — pushes a busy population past the 2 000 messages the study stops
  at, and a quiet population needs an hour. That is email's delay, and Z
  is not email.
* **Cover traffic buys days, not weeks.** A thousand dummy deliveries a day
  to every mailbox — about 1.4 MB a day per device, sent and received —
  makes 8 into 50 on its own and passes 2 000 only with ten seconds of
  jitter on top; for the device pair it turns an hour into ten. A hundred a
  day (142 KB) is a rounding error.
* **Patience wins every cell.** A real pair's count grows with every
  message; a chance pair's count grows with the background, and its spread
  only with the square root of it. ">2 000" means more than 2 000 messages
  inside the three days modelled; a relay that watches for a month gets
  those cells too, later.

The decision is the one the rows already recorded, now with its price on
it: **no jitter and no cover traffic.** The mitigation that a patient
operator cannot wait out is not in the table, because it is not a
mitigation Z can apply — it is a network that hides *which mailbox* a
delivery reached, which is a mixnet (R15), or a relay that is yours. Both
were the answer before the study and are the answer after it; the study is
what lets this document say so with a number rather than a shrug. The
simulation's chance model was checked against a brute‑force count before
its table was read — three of the study's own bugs were in that model, and
each of them had produced a plausible table (`ROADMAP_8_15.md`, revision
37).

### What is NOT on this list, and why

* **Anything phase 13 closed.** A linked device inventing its own post‑quantum
  identity, a contact code naming a laptop rather than a person, a device list
  a quantum adversary could forge by exclusion — all fixed, all tested, none
  residual. They are in `ROADMAP_8_15.md`'s revision list rather than here.
* **A compromised endpoint.** Not a residual risk so much as the boundary of
  the whole exercise: an attacker who has your unlocked device has whatever you
  can see.

## Design decisions that follow from "zero trust"

- **No accounts, no phone numbers, no directory, no key server.** Nothing to
  correlate you to a real identity server‑side; nothing whose honesty you
  must assume. Your address is a hash of a key; your device set is a
  statement your own account key signs, and its consistency is checked by the
  people who receive it rather than vouched for by a server.
- **RAM‑only relay.** The reference relay never writes message data to disk
  and can run on a read‑only filesystem. Restarting the memory that holds
  the queue is a clean slate — the process's own, or, where instances share
  a store to hand a message to whichever one the recipient reached, that
  store's (run with persistence off, which is a setting the deployment's
  Blueprint states and an operator must not change).
- **Sealed sender by default.** Every envelope is sealed to the recipient
  device; the relay matches acknowledgements by envelope id alone and emits
  no delivery receipts — delivery and read receipts are themselves
  end‑to‑end encrypted messages.
- **Authenticated queue draining.** Only the holder of a device's private
  key can receive that mailbox's queued messages (Ed25519
  challenge/response, signed over the relay's own name, so an answer
  obtained by one relay is good at no other — until 2026‑09‑17 it was
  signed over the nonce alone, and a relay a user was talking to could
  replay the answer at the real one; R33).
- **Pairwise groups.** No shared group key: each group message is encrypted
  separately to each member over the existing authenticated session, so
  removing a member needs no rekey and a member who was never sent a message
  cannot have it.
- **Per‑device sessions, one trust root.** Each of a contact's devices gets
  its own ratchet; the account key is the only thing you verify by hand.
- **Contentless push.** A push notification carries no content and no
  sender — only "you have mail"; the device then connects and drains its
  mailbox as usual. Push tokens live in relay RAM and expire.
- **Local encryption at rest.** The on‑device store is encrypted with
  XChaCha20‑Poly1305 under a key held in the OS keystore (Android Keystore,
  macOS/iOS Keychain, Windows credential store, Linux Secret Service),
  optionally wrapped by an app passphrase. If no keystore is available the
  app falls back to a permission‑restricted key file and warns you.
- **App lock (biometrics / device PIN).** Two optional features, both
  driven by the OS prompt (fingerprint, face, or the device credential as
  fallback):
  - *Screen lock* asks for the prompt when Z opens and again after a chosen
    time in the background. It is a **UI gate**, like the phone's own lock
    screen: the vault stays open underneath so messages keep arriving, and
    it does not change what is stored or how it is encrypted. Someone who
    can read the app's storage is not stopped by it.
  - *Unlock with biometrics* (only when an app passphrase is set) lets the
    prompt open the vault instead of typing the passphrase. To do that, Z
    keeps the Argon2id output for the current passphrase — never the
    passphrase — on the device, and deletes it when the feature is turned
    off or the passphrase is removed. How well that key is protected
    depends on the platform:
    - **Android (hardware‑bound).** The key is sealed under an Android
      Keystore key created with "user authentication required, for every
      use": the keystore itself will not run the decryption unless the user
      has just passed the system prompt, and the prompt is tied to that
      exact operation (`BiometricPrompt` + `CryptoObject`). Copying the
      app's data, or asking the keystore from inside the process, yields
      nothing; re‑enrolling a fingerprint or face permanently invalidates
      the key, and the app falls back to the passphrase. On Android 11+
      the device PIN is accepted as fallback; on 7–10 the key is
      biometric‑only. What remains is an attacker who controls the
      unlocked, running device (a compromised endpoint — see above).
    - **macOS / Windows (software‑gated).** The key is an ordinary keystore
      entry that Z reads only after its own prompt. **The trade‑off:**
      while it is on, the device secret and that key together unwrap the
      vault key, so on *that* machine an attacker who can extract keystore
      entries (an admin, a forensic image of an unlocked machine) no longer
      needs the passphrase. The passphrase becomes a UI gate there; it
      still protects the vault against anyone who does not have the
      keystore. Leave it off on those platforms if the passphrase is your
      defence against exactly that attacker. Binding the entry to the
      Keychain's / Windows Hello's own user‑presence check is planned once
      those builds can be verified.
    The settings screen says which of the two applies on the device in
    front of you.

## Recommendations for high‑risk users

1. Use `wss://` (TLS) always, and prefer a relay **you** control.
2. Verify the safety number in person or over a separately trusted channel,
   and compare the pairing SAS aloud when linking a device.
3. Keep the identity backup somewhere the device thief will not also find;
   treat a device‑list alert as an instruction to reset your identity unless
   you can explain it.
4. Enable disappearing messages for sensitive threads.
5. Keep your OS and device encryption on; use a strong device passcode and
   the app passphrase. Turn on the screen lock; on macOS / Windows leave
   "unlock with biometrics" off if you rely on the passphrase against
   someone who can image the machine (on Android it is hardware‑bound).
6. Understand that metadata (which mailbox, when, how much) is the residual
   risk — treat the relay operator accordingly.

## Cryptography caveat

Z composes well‑studied primitives (Ed25519, X25519, HKDF‑SHA256,
HMAC‑SHA256, XChaCha20‑Poly1305, ChaCha20‑Poly1305, ML‑KEM‑768) into a
Signal‑style Double Ratchet with a post‑quantum hybrid, implemented in Dart
on top of the `cryptography` and `pqcrypto` packages. The wire format is
frozen and specified (`PROTOCOL.md`), with test vectors reproduced by three
independent verifiers. It has **not yet** received an independent third‑party
security audit — see `AUDIT_SCOPE.md` for what one would cover. Do not bet
lives on unaudited software.
