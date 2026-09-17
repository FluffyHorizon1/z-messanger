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

Three rules:

  1. Only `relay_url.dart` may write `server_url`.
  2. `acceptedInsecure: true` may only be passed where a human was asked --
     the two account-creating screens, the settings field, and the restore
     path, each of which calls `confirmInsecureRelay` (or is the screen that
     does). A new caller has to be added here on purpose.
  3. `defaultRelayUrl` and `connectLinkHost` name the same host.

Rule 3 is the 2026-09-17 one. zmessengers.com answers 301 -> www. The invite
link host was moved to `www` when that redirect broke links; the relay
constant was left on the apex, and for a year nothing noticed, because
`WebSocket.connect` FOLLOWS a redirect and the socket opened. Binding
authentication to the relay's authority (`z-relay-auth-v2:`) turned the
follow into a refusal: the client signs the host it dialled, the relay
verifies the Host header it received, and a redirect is precisely the case
where those differ. Every 3.5.2 client was refused by its own default relay.

Two constants describing one deployment, in two packages, with nothing
holding them together -- so this holds them together. They are the same host
or this fails. A deployment whose relay and whose links are genuinely
different hosts would change this rule on purpose, which is the point.

None of the three rules is clever. All are the kind a person is sure they
will remember.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
LIB = ROOT / "app" / "lib"

WRITER = "core/relay_url.dart"

# Rule 3's two constants, each in the package that owns it.
LINK_HOST_FILE = ROOT / "protocol" / "lib" / "src" / "connect.dart"
# The trailing `;` matters: without it `= 'wss://' + _host;` matches on its
# first fragment and rule 3 compares `wss://` against a host, reporting a
# mismatch that is really "this constant stopped being a literal and I can no
# longer read it". Demanding the whole declaration turns that into the right
# message.
CONST_RE = r"""const\s+String\s+%s\s*=\s*['"]([^'"]+)['"]\s*;"""


def host_of(url_or_host: str) -> str:
    """The host of a `wss://h/...`, or of a bare `h` -- lower-case, no port."""
    s = url_or_host.strip()
    if "://" not in s:
        s = "wss://" + s
    return (urlparse(s).hostname or "").lower()


def const_in(text: str, name: str, where: str, problems: list) -> str | None:
    """The single string literal `name` is declared as, or a problem."""
    found = re.findall(CONST_RE % re.escape(name), text)
    if len(found) != 1:
        problems.append(
            f"{where}: `{name}` is declared {len(found)} time(s) as a plain "
            f"string constant. This check reads it as text, so a computed or "
            f"renamed constant makes rule 3 silently unenforceable -- update "
            f"the check with the code."
        )
        return None
    return found[0]


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

    # An exemption for a file that no longer exists is not harmless: it is a
    # name in a list that reads like a reviewed decision, and the reviewed
    # decision is about a path nothing resolves to. `relay_url.dart` itself is
    # read below and would raise if it were gone, which is what keeps the
    # scan from being vacuous; nothing was checking these five.
    for rel in sorted(ACCEPTORS):
        if not (LIB / rel).exists():
            problems.append(
                f"{rel} is listed in ACCEPTORS and does not exist. Either the "
                f"screen moved, in which case the exemption now covers "
                f"nothing and its replacement is unexamined, or it is gone "
                f"and the entry is a decision about a file nobody can read."
            )

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

    # Rule 3: one deployment, one host. A missing file is a failure and not a
    # skip -- rule 3 exists because two constants drifted while everything
    # stayed green, and a check that goes quiet when it cannot find one of
    # them would let them drift again in exactly the same silence.
    relay = None
    if not LINK_HOST_FILE.exists():
        problems.append(
            f"{LINK_HOST_FILE.relative_to(ROOT)} is not there, so the invite "
            f"link host could not be read and rule 3 checked nothing."
        )
    else:
        link = const_in(LINK_HOST_FILE.read_text(encoding="utf-8"),
                        "connectLinkHost",
                        str(LINK_HOST_FILE.relative_to(ROOT)), problems)
        relay = const_in(writer, "defaultRelayUrl", WRITER, problems)
        if link and relay:
            if host_of(relay) != host_of(link):
                problems.append(
                    f"the default relay is `{host_of(relay)}` and invite "
                    f"links point at `{host_of(link)}`. One deployment, two "
                    f"hosts: whichever of them redirects to the other, the "
                    f"client that dials it signs one authority and the relay "
                    f"reads another off the Host header, and v2 auth refuses "
                    f"it (`bad_auth`). This is the 2026-09-17 outage; make "
                    f"them the same host, or change this rule on purpose."
                )
            if not relay.lower().startswith("wss://"):
                problems.append(
                    f"{WRITER}: `defaultRelayUrl` is `{relay}`. The address "
                    f"every install dials out of the box is TLS; a cleartext "
                    f"default is not a thing anyone gets asked about, because "
                    f"nobody typed it."
                )

    if problems:
        print(f"\n{len(problems)} problem(s):\n")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"relay address: written only by {WRITER}; "
          f"{len(ACCEPTORS)} caller(s) may accept a cleartext one; "
          f"relay and invite links both on {host_of(relay or '')}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
