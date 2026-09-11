#!/usr/bin/env python3
"""Keep docs/GA_CHECKLIST.md honest about the repository it describes.

A release checklist is worth having only if it is true on the day somebody
decides to ship. This one has nine criteria, five of which cannot be checked
by a script — whether an audit happened, whether someone outside rebuilt a
release, whether a screen reader was run by a person. Those are left to
people, named as such in the document.

The other four are facts about this tree, and facts drift:

  G3  key transparency: the doc says NOT BUILT. If a KT client appears, the
      doc is wrong and the most load-bearing "we do not have this" statement
      in it has gone stale.
  G7  iOS: the doc says the directory does not exist.
  G9  localization: the doc quotes a number of remaining strings, and that
      number changes with every migrated screen.
  --  and the doc must not claim to be READY while any criterion is ❌.

The last one is the point. The failure mode for a checklist is not that a row
is wrong; it is that the summary at the top says "ready" while a row below it
says otherwise, and the reader believes the summary.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "GA_CHECKLIST.md"


def main() -> int:
    if not DOC.exists():
        print(f"{DOC} is missing")
        return 1
    text = DOC.read_text()
    problems = []

    # G3 — key transparency
    kt_built = bool(list(ROOT.glob("protocol/lib/src/*transparency*")) or
                    list(ROOT.glob("app/lib/core/*key_transparency*")))
    says_not_built = "not built" in text.lower()
    if kt_built and says_not_built:
        problems.append(
            "GA_CHECKLIST.md says key transparency is not built, but a KT "
            "client now exists. G3 is the criterion the whole page turns on — "
            "update it."
        )

    # G7 — iOS
    ios = (ROOT / "app" / "ios").exists()
    says_no_ios = "iOS does not exist" in text
    if ios and says_no_ios:
        problems.append(
            "GA_CHECKLIST.md says iOS does not exist, but app/ios/ is here."
        )
    if not ios and not says_no_ios:
        problems.append(
            "app/ios/ does not exist and GA_CHECKLIST.md no longer says so."
        )

    # G9 — the remaining-strings count, quoted in prose
    # \s+ not " " — the number and the phrase sit either side of a line
    # wrap in the prose, and the first version of this regex matched nothing
    # at all. A guard that silently never fires is worse than no guard.
    m = re.search(r"~(\d+)\s+strings remain", text)
    if m:
        sys.path.insert(0, str(ROOT / "tool"))
        import check_l10n  # noqa: E402
        actual = 0
        for p in sorted((ROOT / "app" / "lib" / "ui").glob("*.dart")):
            if p.name in check_l10n.MIGRATED:
                continue
            actual += len(check_l10n.literals(p.read_text(), p.name))
        stated = int(m.group(1))
        # Prose rounds; a drift of more than a handful means a screen landed.
        if abs(stated - actual) > 5:
            problems.append(
                f"GA_CHECKLIST.md says ~{stated} strings remain; there are "
                f"{actual}. A migrated screen has landed and G9 was not "
                f"updated."
            )

    # G9 — the migrated-screen count, stated twice: once in the summary table
    # and once in the prose. The string count above would not have caught this,
    # because the two numbers move for different reasons: migrating a small
    # screen barely dents the string count but always moves the screen count.
    ui = sorted((ROOT / "app" / "lib" / "ui").glob("*.dart"))
    sys.path.insert(0, str(ROOT / "tool"))
    import check_l10n  # noqa: E402
    done, files = len(check_l10n.MIGRATED), len(ui)
    stated_counts = re.findall(r"(\d+) of (\d+) screens", text)
    if not stated_counts:
        problems.append(
            "GA_CHECKLIST.md no longer states an 'N of M screens' figure for "
            "G9, so nothing checks it."
        )
    for a, b in stated_counts:
        if (int(a), int(b)) != (done, files):
            problems.append(
                f"GA_CHECKLIST.md says {a} of {b} screens are migrated; "
                f"check_l10n.MIGRATED lists {done} of {files}."
            )

    # The summary must not outrun the rows.
    unmet = text.count("❌")
    claims_ready = re.search(r"\*\*Status:\s*READY", text, re.I)
    # ...and the sentence after it must count the same rows the table does.
    # The sentence once said "Three criteria are unmet" above a table with
    # four ❌ rows; this script counted the marks document-wide and checked
    # READY / NOT READY only. A number in prose that nothing compares to the
    # rows it summarises is the kind of number that drifts.
    rows_unmet = sum(
        1 for line in text.splitlines()
        if re.match(r"\|\s*G\d+\s*\|", line) and "❌" in line
    )
    words = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
             "six": 6, "seven": 7, "eight": 8, "nine": 9}
    m = re.search(r"\*\*Status:\s*NOT READY\.\*\*\s+(\w+) criteria are unmet",
                  text, re.I)
    if m:
        said = words.get(m.group(1).lower())
        if said is None:
            problems.append(
                f"GA_CHECKLIST.md's status sentence says '{m.group(1)} criteria "
                f"are unmet'; write the number as a word this script knows."
            )
        elif said != rows_unmet:
            problems.append(
                f"GA_CHECKLIST.md's status sentence says {m.group(1)} criteria "
                f"are unmet; the table has {rows_unmet} ❌ rows. The sentence is "
                f"what a reader believes."
            )
    elif "NOT READY" in text:
        problems.append(
            "GA_CHECKLIST.md's status line is not in the form this script "
            "reads ('**Status: NOT READY.** <N> criteria are unmet …')."
        )
    if unmet and claims_ready:
        problems.append(
            f"GA_CHECKLIST.md says READY while {unmet} criteria are marked ❌. "
            f"That is the specific way a checklist misleads: the reader "
            f"believes the summary and never reaches the rows."
        )
    if not unmet and not claims_ready and "NOT READY" in text:
        problems.append(
            "No criterion is marked ❌ any more, but the page still says NOT "
            "READY. Either a row lost its mark or the summary is stale."
        )

    print(f"criteria marked unmet: {unmet}   "
          f"KT built: {kt_built}   iOS: {ios}")
    if problems:
        print(f"\n{len(problems)} problem(s):\n")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("GA_CHECKLIST.md matches the repository.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
