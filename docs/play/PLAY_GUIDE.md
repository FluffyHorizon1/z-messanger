# Google Play: from zero to installable — the click path

Roadmap Phase 3.1. Everything below is done in a browser at
https://play.google.com/console except taking screenshots. Companion docs:
`LISTING.md` (paste-ready listing text) and `DATA_SAFETY.md` (form answers).

## 0. What you need first

- The application id is **`com.zmessenger.www`** (set in
  `app/android/app/build.gradle.kts`). Play Console binds an app to its
  package name forever, so create the console entry with exactly this id.
  Firebase must know it too: in the Firebase console add an Android app
  with package `com.zmessenger.www`, download its `google-services.json`
  and replace `app/android/app/google-services.json` — otherwise push
  registration for the renamed app is not guaranteed to work.

- The signed `app-release.aab` from the GitHub Release (built by CI with your
  upload key).
- The privacy policy live at https://zmessengers.com/privacy (served by the
  relay — ships with this commit; redeploy the relay first).
- 2+ phone screenshots, a 512×512 icon, a 1024×500 feature graphic
  (specs in LISTING.md).

## 1. Create the developer account (once, $25)

1. Go to play.google.com/console → sign in with your Google account.
2. Choose **Personal** account type → pay the one-time $25 fee.
3. Complete identity verification (ID document; can take a day or two to
   clear). You can prepare everything else while you wait.

> Note for new personal accounts: Google requires a **closed test with at
> least 12 testers opted in for 14 days** before you can apply for production
> (public) access. Internal testing works immediately — that's where you
> start anyway.

## 2. Create the app

Console → **Create app**:

| Field | Value |
|---|---|
| App name | Z Messenger |
| Default language | English (or yours) |
| App or game | App |
| Free or paid | Free |
| Declarations | tick both boxes |

## 3. Work through "Set up your app" (Dashboard checklist)

- **Privacy policy** → `https://zmessengers.com/privacy`
- **App access** → "All functionality is available without special access" —
  true: no login exists. (If review ever asks how to test messaging, reply
  that any two installs can add each other by contact code.)
- **Ads** → No, no ads.
- **Content rating** → start questionnaire → category **Communication** →
  answer honestly: users can communicate with each other: Yes (one-to-one);
  content is private/encrypted; no location sharing; no purchases. Expect an
  Everyone/Teen-ish rating.
- **Target audience** → 18 and over (simplest; avoids Families policy).
  "Appeals to children" → No.
- **News app** → No. **COVID-19 app** → No.
- **Data safety** → copy the answers from `DATA_SAFETY.md` exactly.
- **Government app** → No.

## 4. Upload the build to Internal testing

1. Left menu → **Testing → Internal testing** → **Create new release**.
2. First upload triggers **Play App Signing** setup — accept the default
   ("Use a Google-generated key"). Google holds the *app signing key*; your
   keystore is the *upload key* — exactly the model our CI is built around.
3. Upload `app-release.aab` (download it from the GitHub Release, don't
   rebuild locally).
4. Release name: `1.0.0` — release notes: "First internal build."
5. **Save → Review release → Start rollout to Internal testing.**
6. **Testers** tab → create an email list → add your Gmail + your testers'
   Gmails → save → copy the **opt-in link** and send it to them.

Each tester opens the opt-in link on their phone, accepts, and installs from
Play. Internal testing has no review delay — the build is available within
minutes.

## 5. Iterating

Every new upload needs a **higher versionCode**. In `app/pubspec.yaml` bump
`version: 1.0.0+1` → `1.0.1+2` (the `+N` is the versionCode), commit, tag
`v1.0.1`, and CI produces the next signed `.aab` to upload.

## 6. The road to public

1. **Closed testing**: promote the release to a Closed track, recruit ≥12
   testers, keep them opted in 14 days (new-personal-account rule).
2. Apply for **Production** access from the console when it offers it.
3. Complete the **Main store listing** with the text and graphics from
   `LISTING.md`, then roll out to Production. First production review
   typically takes a few days for a messaging app.

## Faster distribution while that clock runs

The GitHub Release APK is already signed and installable today — anyone can
sideload `app-arm64-v8a-release.apk` and verify it against `SHA256SUMS.txt`.
The landing page at zmessengers.com links to it.
