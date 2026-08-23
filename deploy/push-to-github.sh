#!/usr/bin/env bash
# Push this project to a new private GitHub repo so you can one-click deploy the
# relay on Render. Requires the GitHub CLI (`gh`) — https://cli.github.com
#
# Usage:  bash deploy/push-to-github.sh [repo-name]
set -euo pipefail

REPO="${1:-z-messenger}"
cd "$(dirname "$0")/.."

if ! command -v gh >/dev/null 2>&1; then
  echo "GitHub CLI ('gh') is not installed."
  echo "Install it from https://cli.github.com then run this again,"
  echo "or follow the manual steps in DEPLOY.md."
  exit 1
fi

# Make sure we're authenticated.
gh auth status >/dev/null 2>&1 || gh auth login

# Initialize git if needed.
if [ ! -d .git ]; then
  git init
  git branch -M main
fi

git add -A
git commit -m "Z messenger" >/dev/null 2>&1 || echo "(nothing new to commit)"

echo "Creating private GitHub repo '$REPO' and pushing…"
gh repo create "$REPO" --private --source=. --remote=origin --push

URL=$(gh repo view "$REPO" --json url -q .url)
echo
echo "Done. Your repo: $URL"
echo
echo "Next: open Render → New → Blueprint and pick '$REPO',"
echo "or go straight to:  https://render.com/deploy?repo=$URL"
