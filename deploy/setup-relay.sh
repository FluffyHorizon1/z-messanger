#!/usr/bin/env bash
#
# Z relay — one-command setup helper.
#
# This automates the technical half of putting your relay online: it puts the
# code on GitHub (which is what Render deploys from) and hands you the exact
# link + steps to finish in the Render dashboard. It changes nothing on your
# machine except creating a git repo here and (with your permission) a PRIVATE
# GitHub repo under your account.
#
# Run it from the project root:   bash deploy/setup-relay.sh
#
# Prereqs it will check for: git, and the GitHub CLI `gh` (https://cli.github.com).
# If `gh` is missing it prints the exact manual git commands instead.

set -euo pipefail

REPO_NAME="${1:-z-messenger}"
BOLD=$'\e[1m'; DIM=$'\e[2m'; GRN=$'\e[32m'; YEL=$'\e[33m'; RED=$'\e[31m'; RST=$'\e[0m'
say()  { printf '%s\n' "$*"; }
step() { printf '\n%s▶ %s%s\n' "$BOLD" "$*" "$RST"; }
ok()   { printf '%s✓ %s%s\n' "$GRN" "$*" "$RST"; }
warn() { printf '%s! %s%s\n' "$YEL" "$*" "$RST"; }

# --- locate project root (must contain render.yaml + server/) ---------------
cd "$(dirname "$0")/.."
if [[ ! -f render.yaml || ! -f server/server.js ]]; then
  printf '%sCould not find render.yaml and server/ — run this from the z-messenger project root.%s\n' "$RED" "$RST"
  exit 1
fi
ok "Found the project (render.yaml + server/)."

# --- git present? -----------------------------------------------------------
if ! command -v git >/dev/null 2>&1; then
  printf '%sgit is not installed. Install it from https://git-scm.com then re-run.%s\n' "$RED" "$RST"
  exit 1
fi

# --- init repo + commit -----------------------------------------------------
step "Preparing the git repository"
if [[ ! -d .git ]]; then
  git init -q
  git branch -M main
  ok "Initialized a git repository."
else
  ok "git repository already present."
fi
git add -A
if git diff --cached --quiet 2>/dev/null; then
  say "  ${DIM}(nothing new to commit)${RST}"
else
  git -c user.email="you@example.com" -c user.name="Z" commit -q -m "Z relay" || true
  ok "Committed the current code."
fi

# --- push to GitHub ---------------------------------------------------------
REMOTE_URL=""
if command -v gh >/dev/null 2>&1; then
  step "Publishing to GitHub with the GitHub CLI"
  if ! gh auth status >/dev/null 2>&1; then
    warn "You're not logged in to GitHub yet — a browser login will open."
    gh auth login
  fi
  if git remote get-url origin >/dev/null 2>&1; then
    ok "Remote 'origin' already set — pushing latest."
    git push -u origin main
  else
    gh repo create "$REPO_NAME" --private --source=. --remote=origin --push
  fi
  REMOTE_URL="$(gh repo view "$REPO_NAME" --json url -q .url 2>/dev/null || git remote get-url origin)"
  ok "Pushed. Repo: $REMOTE_URL"
else
  step "GitHub CLI (gh) not found — finish the push manually"
  cat <<EOF
  1. Create a new EMPTY private repo named "$REPO_NAME" at https://github.com/new
  2. Then run these commands here:

     ${BOLD}git remote add origin https://github.com/YOUR_USERNAME/$REPO_NAME.git
     git push -u origin main${RST}

  (Installing the GitHub CLI from https://cli.github.com makes this automatic.)
EOF
  REMOTE_URL="https://github.com/YOUR_USERNAME/$REPO_NAME"
fi

# --- next steps on Render ---------------------------------------------------
cat <<EOF

$(printf '%s' "$BOLD")────────────────────────────────────────────────────────$(printf '%s' "$RST")
$(ok "Code is on GitHub. Now deploy the relay on Render (2 minutes):")

  1. Sign in at  ${BOLD}https://dashboard.render.com${RST}  (use "Sign in with GitHub").
  2. Click  ${BOLD}New  →  Blueprint${RST}.
  3. Connect / pick the repo:  ${BOLD}${REPO_NAME}${RST}
     (Render auto-detects render.yaml and shows a service called "z-relay".)
  4. Click  ${BOLD}Deploy Blueprint${RST}  and wait until it says ${GRN}Live${RST} (~2 min).
  5. Copy the service URL at the top, e.g.  https://z-relay-xxxx.onrender.com
     Check it works:  open  <that-url>/health  → you should see  {"ok":true,...}

$(printf '%s' "$BOLD")Your relay address for the app$(printf '%s' "$RST") is that URL with ${BOLD}wss://${RST} instead of https://:
     ${BOLD}wss://z-relay-xxxx.onrender.com${RST}
  In the Z app: onboarding screen (or Settings → Relay), paste it, tap ${BOLD}Test connection${RST}.

$(warn "Free tier note: the relay sleeps after 15 min idle and wakes in ~1 min on the")
     next connect (messages aren't lost — they resend). For always-on, change
     ${BOLD}plan: free${RST} to ${BOLD}plan: starter${RST} in render.yaml (or in the dashboard) and redeploy.
────────────────────────────────────────────────────────
EOF
