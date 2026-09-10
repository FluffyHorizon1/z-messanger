#!/usr/bin/env python3
"""Track the migration of UI strings out of the widgets and into ARB.

Roughly 480 user-visible strings are hardcoded English across thirteen
screens. Migrating them is mechanical but not small, and much of it is
security wording — the safety-number banners, the "there is no way to recover
it" note — where a careless translation misleads somebody. So it is being done
screen by screen rather than in one pass.

The risk with "screen by screen" is that it stalls at screen two, and the risk
with a half-migrated file is that new literals get added to it because nobody
notices. This makes both visible:

  * A file listed in MIGRATED must contain NO user-visible literals. Adding one
    fails the build, so a migrated screen cannot silently regress.
  * Every other file is counted and reported, so the remaining work is a
    number that goes down rather than a vague intention.

The heuristic for "user-visible" is deliberately crude — a quoted string of
three or more characters containing a space or starting with a capital — and
it is allowed to be, because its only job on a migrated file is to be
suspicious. Anything it flags wrongly goes in ALLOWED with a reason.
"""

import collections
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UI = ROOT / "app" / "lib" / "ui"
ARB = ROOT / "app" / "lib" / "l10n" / "app_en.arb"

# Screens whose strings live in lib/l10n/*.arb. Add a name here when it is
# migrated; the check then holds it to zero.
MIGRATED = {
    "unlock_screen.dart",
    "lock_screen.dart",
    "voice_widgets.dart",
    "search_screen.dart",
    "home_screen.dart",
    "add_contact_screen.dart",
    "onboarding_screen.dart",
    "group_screens.dart",
    "link_device_screen.dart",
    "backup_screen.dart",
}

# Literals that look user-visible and are not.
ALLOWED = {
    "package:flutter/material.dart", "package:flutter/services.dart",
    "theme.dart", "../core/app_lock.dart",
    # A paperclip is a paperclip in every locale.
    "📎 ",
    # The shape of a recovery code, shown as a hint in the field. The format
    # is fixed by BACKUP.md — 25 Crockford base32 characters in five groups —
    # so it is the same in every locale and translating it would be wrong.
    "ZBK-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
    # The shape of a pairing code, shown as a hint in the field. Like the
    # recovery code above it is a fixed format, not prose.
    "ABCDE-FGHIJ-\u2026",
}

# Exemptions that are only safe in one file. A global entry hides a literal in
# all fourteen screens, which is too much reach for a word as ordinary as
# "Unknown": it would stop being flagged in the one place it IS a label.
ALLOWED_IN = {
    "link_device_screen.dart": {
        # NOT a label. This is the value written into a contact's sealed
        # enc_name when the bundle carries no display name, and
        # core/chat_service.dart sets the same default in two other places.
        # Localising this one would make the same missing name appear in two
        # languages depending on which code path created the contact. The real
        # fix is to store the absence and render l.grpUnknown at display time,
        # which is a change to core and to every reader of that column, not to
        # this screen.
        "Unknown",
    },
}


def literals(src: str, name: str = ""):
    """Quoted strings that plausibly reach a user's eyes.

    [name] is the file's basename, used to apply ALLOWED_IN. Omitting it only
    ever over-reports, which is the safe direction.
    """
    here = ALLOWED_IN.get(name, frozenset())
    out = []
    for m in re.finditer(r"'([^'\\\n]{3,})'", src):
        v = m.group(1)
        if v in ALLOWED or v in here:
            continue
        if v.startswith("package:") or "/" in v or v.startswith("z/"):
            continue
        if " " in v or v[0].isupper():
            out.append((src.count("\n", 0, m.start()) + 1, v))
    return out


# Keys allowed to exist without a reference. Nothing is here yet; the entry
# format is "key": "why".
UNUSED_OK = {}


def arb_problems():
    """The ARB's own integrity, independent of any screen.

    Three things go wrong quietly over a migration this long. A key gets
    defined twice and the later one silently wins. A key gets added without a
    description, so a translator sees "confirm" with no idea what is being
    confirmed. And a key outlives its last reference — which costs real money,
    because somebody translates a string nobody will ever see. None of these
    fail a build on their own, so nothing catches them until a translator asks.
    """
    out = []
    raw = ARB.read_text(encoding="utf-8")

    # Parsed JSON cannot show a duplicate — the second silently replaces the
    # first — so the keys are counted in the text.
    keys = re.findall(r'^  "(?!@)([A-Za-z0-9_]+)"\s*:', raw, re.M)
    for key, n in collections.Counter(keys).items():
        if n > 1:
            out.append(f"app/lib/l10n/app_en.arb: \"{key}\" is defined {n} "
                       f"times; the last one silently wins.")

    data = json.loads(raw)
    for key in keys:
        meta = data.get(f"@{key}")
        if not isinstance(meta, dict) or not meta.get("description"):
            out.append(f"app/lib/l10n/app_en.arb: \"{key}\" has no "
                       f"description. A translator cannot render a string "
                       f"whose purpose is not stated.")

    # Flutter has no reflection, so every reference is a static `l.name` or
    # `AppLocalizations.of(context).name` and can be found by reading.
    src = "".join(
        p.read_text(encoding="utf-8")
        for p in sorted((ROOT / "app" / "lib").rglob("*.dart"))
        if "l10n/app_localizations" not in p.as_posix()
    )
    used = set(re.findall(r"\bl\.([A-Za-z0-9_]+)", src))
    used |= set(re.findall(r"AppLocalizations\.of\(context\)\.([A-Za-z0-9_]+)",
                           src))
    for key in sorted(set(keys) - used - set(UNUSED_OK)):
        out.append(f"app/lib/l10n/app_en.arb: \"{key}\" is not referenced "
                   f"anywhere. Delete it, or record why it stays in "
                   f"UNUSED_OK in this script.")
    return out


def main() -> int:
    problems = arb_problems()
    remaining = {}

    for path in sorted(UI.glob("*.dart")):
        found = literals(path.read_text(), path.name)
        if path.name in MIGRATED:
            for line, v in found:
                problems.append(
                    f"app/lib/ui/{path.name}:{line}: hardcoded string in a "
                    f"MIGRATED screen: \"{v[:60]}\". Add it to "
                    f"lib/l10n/app_en.arb and use AppLocalizations, or list it "
                    f"in ALLOWED (or ALLOWED_IN, if it is only safe here) in "
                    f"this script if it never reaches a user."
                )
        elif found:
            remaining[path.name] = len(found)

    done = len(MIGRATED)
    total_files = len(list(UI.glob("*.dart")))
    left = sum(remaining.values())
    print(f"migrated: {done}/{total_files} screens   "
          f"strings still hardcoded: {left}")
    if remaining:
        for name, n in sorted(remaining.items(), key=lambda x: -x[1]):
            print(f"  {n:4d}  app/lib/ui/{name}")

    if problems:
        print(f"\n{len(problems)} problem(s):\n")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("\nno migrated screen has regressed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
