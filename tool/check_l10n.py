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

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UI = ROOT / "app" / "lib" / "ui"

# Screens whose strings live in lib/l10n/*.arb. Add a name here when it is
# migrated; the check then holds it to zero.
MIGRATED = {
    "unlock_screen.dart",
    "lock_screen.dart",
    "voice_widgets.dart",
    "search_screen.dart",
    "home_screen.dart",
    "add_contact_screen.dart",
}

# Literals that look user-visible and are not.
ALLOWED = {
    "package:flutter/material.dart", "package:flutter/services.dart",
    "theme.dart", "../core/app_lock.dart",
    # A paperclip is a paperclip in every locale.
    "📎 ",
}


def literals(src: str):
    """Quoted strings that plausibly reach a user's eyes."""
    out = []
    for m in re.finditer(r"'([^'\\\n]{3,})'", src):
        v = m.group(1)
        if v in ALLOWED or v.startswith("package:") or "/" in v or v.startswith("z/"):
            continue
        if " " in v or v[0].isupper():
            out.append((src.count("\n", 0, m.start()) + 1, v))
    return out


def main() -> int:
    problems = []
    remaining = {}

    for path in sorted(UI.glob("*.dart")):
        found = literals(path.read_text())
        if path.name in MIGRATED:
            for line, v in found:
                problems.append(
                    f"app/lib/ui/{path.name}:{line}: hardcoded string in a "
                    f"MIGRATED screen: \"{v[:60]}\". Add it to "
                    f"lib/l10n/app_en.arb and use AppLocalizations, or list it "
                    f"in ALLOWED in this script if it never reaches a user."
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
