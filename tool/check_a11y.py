#!/usr/bin/env python3
"""Check the UI for controls a screen reader would announce as nothing.

`app/test/a11y_test.dart` runs Flutter's own guideline checkers, which are
authoritative — but only on screens that stand up without a ChatService, which
is three of thirteen. The rest need a real vault, a real relay and a real
identity to pump, and standing all that up for every screen is a poor trade
for what it would catch.

So this reads the source instead. It is a weaker check than the real thing and
it catches a narrower class of fault, but it covers every screen and it runs
in milliseconds. The two are complementary; neither is sufficient alone, and
this file exists because the alternative was covering three screens and
calling accessibility done.

Two rules, both chosen because they are unambiguous in source:

  1. An `IconButton` has a `tooltip:`. An icon has no text, so without one
     TalkBack and VoiceOver announce "button" and nothing else.
  2. An `Image.asset` / `.file` / `.memory` / `.network` has a
     `semanticLabel:`, or is explicitly marked decorative with
     `excludeFromSemantics: true`. Saying an image is decorative is a
     decision; saying nothing is an oversight, and they should not look the
     same in the source.

Exit 0 if every control announces something.

Both rules are regexes over source, so both have the failure mode every
pattern-based check has: one that matches nothing prints the same thing as
one that matched and was satisfied. `main` refuses when the scan read no
files, and when it found no `IconButton` in a UI whose every screen has an
app bar. Demonstrated by emptying `app/lib/ui`, where this reported
"every icon button and image announces something" over zero files.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UI = ROOT / "app" / "lib"


def balanced_call(text: str, start: int) -> str:
    """The source of a widget call starting at its opening parenthesis."""
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return text[start:]


def line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def main() -> int:
    problems = []
    checked = {"IconButton": 0, "Image": 0}
    files = 0

    for path in sorted(UI.rglob("*.dart")):
        files += 1
        src = path.read_text()
        rel = path.relative_to(ROOT).as_posix()

        for m in re.finditer(r"\bIconButton\s*\(", src):
            call = balanced_call(src, m.end() - 1)
            checked["IconButton"] += 1
            if "tooltip:" not in call:
                problems.append(
                    f"{rel}:{line_of(src, m.start())}: IconButton with no "
                    f"`tooltip:`. A screen reader announces it as \"button\" "
                    f"and nothing else — say what it does, not what the icon "
                    f"looks like."
                )

        for m in re.finditer(r"\bImage\s*\.\s*(asset|file|memory|network)\s*\(",
                             src):
            call = balanced_call(src, m.end() - 1)
            checked["Image"] += 1
            if "semanticLabel:" not in call and \
                    "excludeFromSemantics: true" not in call:
                problems.append(
                    f"{rel}:{line_of(src, m.start())}: Image with neither "
                    f"`semanticLabel:` nor `excludeFromSemantics: true`. "
                    f"Decorative is a fine answer, but it should be a stated "
                    f"one."
                )

    print(f"dart files read: {files}   "
          f"IconButton: {checked['IconButton']}   Image: {checked['Image']}")

    # Both rules are patterns over source, and a pattern that matches nothing
    # produces exactly the output of a pattern that matched and was satisfied.
    # These two floors are what tell the difference.
    if files == 0:
        print(f"{UI.relative_to(ROOT)}: no .dart files at all, so both rules "
              f"below ran over nothing. The screens moved, or this is not a "
              f"checkout — either way fix the check before trusting it.",
              file=sys.stderr)
        return 1
    if checked["IconButton"] == 0:
        print(f"{UI.relative_to(ROOT)}: not one IconButton in {files} files. "
              f"Every screen here has an app bar, so this is the pattern no "
              f"longer matching — a wrapper widget, or a rename — not the app "
              f"running out of buttons. A rule that matches nothing passes "
              f"silently for ever.", file=sys.stderr)
        return 1
    # `Image` gets no floor on purpose: the app ships exactly one, and a check
    # that fails when an app legitimately has no images is a check that asks
    # for a decorative one to be added.

    if problems:
        print(f"\n{len(problems)} problem(s):\n")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("every icon button and image announces something.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
