# Google Play Data safety form — answers + rationale

The Data safety section (App content → Data safety) asks a fixed
questionnaire. These are the accurate answers for Z as shipped, with the
reasoning recorded so future-you can defend or update them.

Google's definitions that matter here:

- **"Collected"** = transmitted off the device to you/your server. Data
  processed **ephemerally** — held only in memory, used only to service the
  live request, never stored — does NOT need to be declared as collected.
- **"Shared"** = transferred to a third party, except service providers
  processing it on your behalf (FCM counts as a service provider).

## Section: Data collection and security

| Question | Answer |
|---|---|
| Does your app collect or share any of the required user data types? | **Yes** (one type — see below) |
| Is all of the user data collected by your app encrypted in transit? | **Yes** (TLS to the relay; message content additionally E2E encrypted) |
| Do you provide a way for users to request that their data is deleted? | **Yes** — in-app "Wipe everything"; nothing exists server-side to delete. Choose the in-app-deletion option; account deletion URL is not applicable because there are no accounts. |

## Data types — what to declare

Declare exactly one collected type:

**Device or other IDs → Device or other IDs**
- Collected: **Yes** · Shared: **No** (FCM is a service provider)
- Processed ephemerally: **No** (the push token is held in relay RAM up to 30
  days, which is beyond "ephemeral")
- Required or optional: **Optional** — push notifications are off until the
  user enables them, and the app is fully functional without them
- Purpose: **App functionality** (delivering the content-free push wake-up)

Everything else: **not collected**, with these rationales on record:

| Data type | Answer | Why |
|---|---|---|
| Messages (texts, photos, files) | Not collected | E2E encrypted; relay handles only ciphertext, ephemerally (RAM, deleted on delivery, ≤72 h) and cannot read it. Meets Google's ephemeral-processing carve-out. |
| Name / email / phone / address | Not collected | No registration exists. The display name travels only inside encrypted contact codes and messages. |
| Contacts | Not collected | The app never reads the device address book; Z contacts live only in the local encrypted vault. |
| Location | Not collected | Never requested. |
| Financial, health, calendar, etc. | Not collected | Never requested. |
| App activity / diagnostics / crash logs | Not collected | No analytics or crash-reporting SDKs. |
| Installed apps, browsing history | Not collected | Never touched. |

## Section: Security practices

| Question | Answer |
|---|---|
| Data encrypted in transit | Yes |
| User can request deletion | Yes (in-app wipe) |
| Committed to Play Families policy | Not enrolled (not a kids' app) |
| Independent security review | No (roadmap Phase 5 — update this when the audit lands) |

## Account deletion requirement

Play asks for an account-deletion URL for apps with account creation. Z has
**no account creation** — answer accordingly ("My app does not allow users to
create an account"), and no URL is needed.

## Keep this honest

If any of these change — analytics added, crash reporting added, tokens
persisted to disk, a directory service introduced — this form must be updated
in the console *before* shipping the change. Misdeclarations are a common
suspension reason.
