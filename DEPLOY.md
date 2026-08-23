# Deploy Z in ~5 minutes (no domain, no server admin)

You need **one** thing running in the cloud: the **relay** (the dumb pipe that
passes encrypted messages between phones). It stores nothing readable — it just
needs a public address your devices can reach. We'll put it on **Render's free
tier**, which hands you a `wss://…onrender.com` address automatically.

Then you install the app and paste that address in. That's it.

---

## Part 1 — Put the relay online (one-click)

### Step 1 · Get the code onto GitHub (once)

Render deploys from a GitHub repo, so the code needs to live there first.

**Easiest (if you have the `gh` GitHub CLI):** from the unzipped project folder,
run:

```bash
bash deploy/push-to-github.sh
```

It creates a private repo `z-messenger` on your GitHub and pushes everything.

**Or by hand:**
1. Make a free account at <https://github.com> and click **New repository**
   (name it `z-messenger`, leave it empty, Create).
2. In the unzipped project folder, run the commands GitHub shows you under
   *"…or push an existing repository"* — roughly:
   ```bash
   git init && git add -A && git commit -m "Z"
   git branch -M main
   git remote add origin https://github.com/YOUR_NAME/z-messenger.git
   git push -u origin main
   ```

### Step 2 · Deploy to Render (the one click)

1. Make a free account at <https://render.com> (sign in with GitHub — easiest).
2. Click this button, or go to **Dashboard → New → Blueprint** and pick your
   `z-messenger` repo:

   [![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy)

3. Render reads `render.yaml`, sees the relay, and shows **z-relay**. Click
   **Apply** / **Create**. Wait ~2 minutes for it to go **Live**.
4. At the top of the service page you'll see its URL, like
   `https://z-relay-a1b2.onrender.com`. **Copy it.**

### Step 3 · Check it's alive

Open `https://z-relay-a1b2.onrender.com/health` in a browser. You should see
`{"ok":true,...,"storage":"ram-only"}`. 🎉 Your relay is up.

> **Your relay address for the app is the same URL with `wss://` instead of
> `https://`:** `wss://z-relay-a1b2.onrender.com`
> (The app also accepts the `https://` form and converts it for you.)

---

## Part 2 — Install the app and connect

1. **Android:** copy `z-android-arm64-v8a.apk` to your phone and open it
   (allow "install from unknown sources"). **Desktop:** unzip the Linux/Windows/
   macOS build (or build from source — see `docs/BUILD.md`).
2. On the first screen, enter a display name and paste your relay address:
   `wss://z-relay-a1b2.onrender.com`.
3. Tap **Test connection** — you should get a green ✓. Then **Create my
   identity**.
4. Do the same on the second device (or have your friend do it), pointing at
   the **same** relay address.
5. On one device: **Add contact → My code** (show the QR). On the other:
   **Add contact → Scan** (Android) or **Paste**. Then swap the other way.
6. Message away. Compare **safety numbers** (in a contact's info screen) to
   confirm no one's in the middle.

---

## Good to know about the free tier

Render's **free** relay **sleeps after ~15 minutes of no connections** and
takes ~30 seconds to wake on the next connect. For personal use that's usually
fine — your **delivered messages are safe on your devices regardless**; only
messages *in transit while the relay is asleep* wait until it wakes. To avoid
sleeping entirely, upgrade the service to Render's **Starter** plan (a few
dollars a month) — change `plan: free` to `plan: starter` in `render.yaml`, or
flip it in the dashboard.

Prefer a different host? `docs/SELF_HOSTING.md` covers Fly.io (always-on free
allowance), a one-command VPS install with automatic TLS, and plain Docker.

---

## Troubleshooting

- **App says "offline" / red dot.** Double-check the address starts with
  `wss://` and matches your Render URL exactly. Open the `/health` link to
  confirm the relay is awake.
- **First connect after idle is slow.** That's the free tier waking up. Give it
  ~30 seconds, or upgrade to Starter.
- **"Test connection" fails on a brand-new deploy.** Give Render a minute to
  finish the first build, refresh the service page until it says **Live**.
- **Messages to an offline contact.** They're held encrypted in the relay's RAM
  and delivered when your contact reconnects (up to 72h), then wiped. Nothing is
  ever written to the relay's disk.
