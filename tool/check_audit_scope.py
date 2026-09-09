#!/usr/bin/env python3
"""Check that docs/AUDIT_SCOPE.md still describes this repository.

The audit brief is the first thing an external reviewer reads, and it is the
document with the shortest half-life in the project: every claim row names
files that get renamed, and every new test suite is a claim the table does
not yet make. A brief that names a file which no longer exists does not merely
look sloppy — it costs the reviewer the hour in which they conclude that
either the file or the claim is missing, and it teaches them to stop trusting
the rest of the table.

So the brief is checked mechanically. Three invariants, each of which has
failed at least once in this repository's history:

  1. Every path the brief names exists.
  2. The claim ids are contiguous, so C1..CN can be cited as a range.
  3. Every test file in the repository is cited by at least one claim.

The third is the one that catches real drift, and it runs in the direction
people forget: not "does the brief point at something real" but "is there
evidence here that the brief never mentions". A test suite no claim cites is
either a claim we forgot to write down or a test that guards nothing we say
publicly, and both are worth knowing before an auditor finds them.

Exit code 0 if the brief is honest, 1 if it is not.
"""

import pathlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BRIEF = ROOT / "docs" / "AUDIT_SCOPE.md"

# Test files that deliberately back no public claim. Each needs a reason: an
# exemption without one is how this check gets hollowed out.
UNCITED_OK = {
    "app/test/screenshots_test.dart":
        "renders theme screenshots for the README; asserts no security property",
    "app/test/widget_test.dart":
        "Flutter's generated smoke test",
    "app/test/edge_to_edge_test.dart":
        "system-bar insets on Android 15+; a layout property, not a secret-carrying path",
    "app/test/paging_test.dart":
        "that a 50,000-message thread opens by loading one page — a performance "
        "property; the sealing of those rows is C11's, not this test's",
    "server/test/pages.test.js":
        "the landing and privacy pages the relay also serves; security.txt, the "
        "one page that carries a security promise, is C27",
}


def claim_rows(text):
    """(id, claim, spec, evidence) for each row of the claims table."""
    rows = []
    for line in text.splitlines():
        m = re.match(r"^\|\s*(C\d+)\s*\|(.*)\|(.*)\|(.*)\|\s*$", line)
        if m:
            rows.append((m.group(1), m.group(2), m.group(3), m.group(4)))
    return rows


def paths_in(text):
    """Repo paths named in backticks. Bare filenames are resolved under docs/."""
    out = set()
    for raw in re.findall(r"`([^`\s]+\.(?:md|dart|js|py|json|yml|yaml|kts|sh))`", text):
        out.add(raw)
    return out


SKIP_DIRS = {".git", "node_modules", "build", ".dart_tool", ".gradle", "linux",
             "windows", "macos", "ios", "web", ".venv"}


def index_basenames():
    """Every file in the repository, by basename.

    The brief names most files by basename alone (`pq_test.dart`, not
    `protocol/test/pq_test.dart`) because a reader with the repository open
    finds them instantly and the full paths would triple the width of an
    already dense table. So resolution here works the way a reader does:
    look for a file with that name anywhere that is not build output.
    """
    idx = {}
    for p in ROOT.rglob("*"):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.relative_to(ROOT).parts[:-1]):
            continue
        idx.setdefault(p.name, []).append(p)
    return idx


BASENAMES = None


def resolve(ref):
    """A reference resolves if it is a real path, or names a real file."""
    if (ROOT / ref).exists():
        return ROOT / ref
    hits = BASENAMES.get(pathlib.PurePosixPath(ref).name, [])
    return hits[0] if hits else None


def main():
    global BASENAMES
    BASENAMES = index_basenames()

    text = BRIEF.read_text()
    rows = claim_rows(text)
    problems = []

    # 1. Everything named exists.
    for ref in sorted(paths_in(text)):
        if resolve(ref) is None:
            problems.append(
                f"AUDIT_SCOPE.md names `{ref}`, which does not exist. Either the "
                f"file moved and the brief was not updated, or the claim it "
                f"backs is no longer evidenced."
            )

    # 2. Contiguous ids, and no empty cells.
    if not rows:
        problems.append("no claim rows found — has the table format changed?")
    for i, (cid, claim, spec, ev) in enumerate(rows, start=1):
        if cid != f"C{i}":
            problems.append(f"claim ids are not contiguous: expected C{i}, found {cid}")
        if not claim.strip():
            problems.append(f"{cid} states no claim")
        if not spec.strip():
            problems.append(f"{cid} names no specification")
        if not ev.strip():
            problems.append(
                f"{cid} names no evidence. A claim with nothing behind it is the "
                f"one an auditor should look at first, so say so explicitly "
                f"rather than leaving the cell blank."
            )

    # 3. Every test file is cited somewhere.
    tests = []
    for pat in ("protocol/test/*.dart", "app/test/*.dart", "server/test/*.js"):
        tests.extend(sorted(ROOT.glob(pat)))
    for t in tests:
        rel = t.relative_to(ROOT).as_posix()
        if rel in UNCITED_OK:
            continue
        if t.name not in text:
            problems.append(
                f"{rel} is not cited by any claim. Either it guards something "
                f"the brief should claim, or it belongs in UNCITED_OK in this "
                f"script with a reason."
            )

    # 4. Stated file counts match reality.
    #
    # These numbers were stale by 19 protocol tests, 5 relay tests and 3 app
    # test files when this check was written, which is what a hand-maintained
    # count does over eight phases. Test *totals* need the suites run and are
    # left to CI; file counts are free, and they are the ones that drift on
    # every commit that adds a suite.
    m = re.search(r"^# App: (\d+) test files", text, re.M)
    if m:
        actual = len(list(ROOT.glob("app/test/*.dart")))
        if int(m.group(1)) != actual:
            problems.append(
                f"AUDIT_SCOPE.md says {m.group(1)} app test files; there are "
                f"{actual}. A count nobody checks is a count nobody should "
                f"believe."
            )
    m = re.search(r"k lines in (\d+) modules", text)
    if m:
        actual = len(list(ROOT.glob("protocol/lib/src/*.dart")))
        if int(m.group(1)) != actual:
            problems.append(
                f"AUDIT_SCOPE.md says the protocol library has {m.group(1)} "
                f"modules; `protocol/lib/src/` holds {actual}."
            )
    m = re.search(r"(\d+) test files \(~[\d.]+ k lines\)", text)
    if m:
        actual = len(list(ROOT.glob("app/test/*.dart")))
        if int(m.group(1)) != actual:
            problems.append(
                f"AUDIT_SCOPE.md's system table says {m.group(1)} app test "
                f"files; there are {actual}."
            )

    print(f"claims: {len(rows)}   paths checked: {len(paths_in(text))}   "
          f"test files: {len(tests)}")
    if problems:
        print(f"\n{len(problems)} problem(s):\n")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("AUDIT_SCOPE.md is consistent with the repository.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
