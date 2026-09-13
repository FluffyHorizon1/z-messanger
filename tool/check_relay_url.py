#!/usr/bin/env python3
"""Check that the relay address is written in exactly one place.

Four things used to write `server_url`: onboarding, linking a device, the
developer-mode field in Settings, and a restored archive's own `meta` record.
Exactly one of them ever mentioned that a `ws://` address is not TLS, and it
was a notice beside a "Test" button nobody has to press -- so three of the
four, plus the one that takes its answer from a FILE, dialled a cleartext
public relay without a word.

They all go through `setRelayUrl` now, which refuses a public `ws://` address
unless the caller says the user was asked and agreed. That is worth exactly as
much as the guarantee that nobody writes the key some other way, and a
`kvPut('server_url', ...)` is four characters longer to type than the funnel.

Two rules:

  1. Only `relay_url.dart` may write `server_url`.
  2. `acceptedInsecure: true` may only be passed where a human was asked --
     the two account-creating screens, the settings field, and the restore
     path, each of which calls `confirmInsecureRelay` (or is the screen that
     does). A new caller has to be added here on purpose.

Neither rule is clever. Both are the kind a person is sure they will remember.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIB = ROOT / "app" / "lib"

WRITER = "core/relay_url.dart"

# Callers allowed to say the user agreed, and why each one is asked.
ACCEPTORS = {
    "ui/onboarding_screen.dart":
        "creates the account; calls confirmInsecureRelay before it starts",
    "ui/link_device_screen.dart":
        "links this device; calls confirmInsecureRelay before it pairs",
    "core/chat_service.dart":
        "setServerUrl passes through what its own caller was told",
    "core/restore.dart":
        "the address the user typed into the restore screen, which asked",
    "ui/settings_screen.dart":
        "the developer-mode relay field; calls confirmInsecureRelay first",
}


def main():
    problems = []
    for path in sorted(LIB.rglob("*.dart")):
        rel = path.relative_to(LIB).as_posix()
        text = path.read_text(encoding="utf-8")

        if re.search(r"""kvPut\(\s*['"]server_url['"]""", text) and rel != WRITER:
            problems.append(
                f"{rel} writes `server_url` directly. Every writer goes "
                f"through `setRelayUrl` in {WRITER}, which is the one place "
                f"that refuses a public ws:// address nobody agreed to."
            )

        if "acceptedInsecure: true" in text and rel not in ACCEPTORS:
            problems.append(
                f"{rel} claims the user accepted a cleartext relay. That is "
                f"only true where a human was actually asked; add it to "
                f"ACCEPTORS in this script, with the reason, or call "
                f"`confirmInsecureRelay` first."
            )

    # The funnel has to still be doing its job.
    writer = (LIB / WRITER).read_text(encoding="utf-8")
    if "isSecureOrLocalRelay(url) && !acceptedInsecure" not in writer:
        problems.append(
            f"{WRITER} no longer refuses an unaccepted insecure relay; the "
            f"rule the rest of this check enforces has gone."
        )

    if problems:
        print(f"\n{len(problems)} problem(s):\n")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"relay address: written only by {WRITER}; "
          f"{len(ACCEPTORS)} caller(s) may accept a cleartext one.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
