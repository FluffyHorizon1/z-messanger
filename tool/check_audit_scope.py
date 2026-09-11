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
    "app/test/a11y_test.dart":
        "accessibility — Flutter's own tap-target, label and contrast "
        "guidelines on the pre-account screens. A usability property, and "
        "one Play assesses separately; not a claim about secrecy",
    "app/test/edge_to_edge_test.dart":
        "system-bar insets on Android 15+; a layout property, not a secret-carrying path",
    "app/test/paging_test.dart":
        "that a 50,000-message thread opens by loading one page — a performance "
        "property; the sealing of those rows is C11's, not this test's",
    "app/test/fanout_bench_test.dart":
        "a measurement, not an assertion about behaviour — it times group "
        "fan-out and reports where the cost goes (docs/PERFORMANCE.md). The "
        "one thing it asserts, that fan-out stays linear, is a design "
        "property rather than a security claim",
    "app/test/coldstart_bench_test.dart":
        "a measurement, not an assertion about behaviour — it times "
        "ChatService.init against the number of contacts (docs/PERFORMANCE.md, "
        "'Cold start'). The one thing it asserts, a per-contact budget, is a "
        "cost property rather than a security claim",
    "app/test/device_link_spread_bench_test.dart":
        "a measurement, not an assertion about behaviour — it stamps a "
        "linked device's copy of each message as the relay stamps it, "
        "relative to the contact's copy (THREAT_MODEL.md R19). The one thing "
        "it asserts, that the copies are a burst, exists so R19 is rewritten "
        "if the mirror is ever delayed",
    "app/test/group_spread_bench_test.dart":
        "a measurement, not an assertion about behaviour — it stamps one "
        "group message's copies as the relay stamps them and reports the "
        "spread (THREAT_MODEL.md R18). The one thing it asserts, that the "
        "copies are a burst, exists so R18 is rewritten if that ever changes",
    "app/test/delivery_receipts_test.dart":
        "that delivery receipts go out once per burst rather than once per "
        "message — a cost property (docs/PERFORMANCE.md). That a receipt is "
        "end-to-end encrypted and names only mids is C4's territory",
    "app/test/receive_bench_test.dart":
        "a measurement, not an assertion about behaviour — it times the "
        "inbound path and attributes it (docs/PERFORMANCE.md, 'Receive "
        "side'). The two things it asserts on the way, that an early "
        "arrival caches one key per message skipped and that late arrivals "
        "consume them, are covered as claims by skipped_keys_test.dart",
    "app/test/locale_es_test.dart":
        "the Spanish locale renders: plurals, stored system messages, no "
        "string copied through untranslated — a localisation property "
        "(G9), not a security claim",
    "app/test/system_text_test.dart":
        "that a stored system message renders in the user's language and a "
        "row from before the change still reads as written — a localization "
        "property. The rows themselves are sealed like every other message, "
        "which is C11's claim, not this test's",
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


def suite_map(text):
    """Which claims each test suite backs, read from the brief itself.

    This mapping is not maintained anywhere: it is derived by asking which
    claim rows mention a suite's filename. That keeps `audit_verify.sh` from
    becoming a fifth place where the claim/evidence relationship is written
    down and a fifth place for it to go stale.
    """
    out = {}
    for cid, _claim, _spec, ev in claim_rows(text):
        pat = r"((?:[A-Za-z0-9_]+/)*[A-Za-z0-9_]+(?:_test\.dart|\.test\.js))"
        for name in re.findall(pat, ev):
            # The brief writes basenames; a runner needs to know which suite
            # to attribute the result to, so resolve back to a real path.
            hit = resolve(name)
            key = hit.relative_to(ROOT).as_posix() if hit else name
            if cid not in out.setdefault(key, []):
                out[key].append(cid)
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
    if "--map" in sys.argv:
        # path<TAB>C1,C4 — consumed by tool/audit_verify.sh
        global BASENAMES
        BASENAMES = index_basenames()
        for name, claims in sorted(suite_map(BRIEF.read_text()).items()):
            print(f"{name}\t{','.join(claims)}")
        return 0

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
    for pat in ("protocol/test/*.dart", "app/test/*.dart", "server/test/*.js",
                "kt/test/*.js"):
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

    # 5. An ambiguous name is qualified.
    #
    # `multidevice_test.dart` exists in both protocol/test/ and app/test/,
    # and the brief cited it bare in one row and qualified in another. A
    # reader following the bare one opens whichever they find first and
    # reads the wrong evidence for the claim; so does any tool. Where two
    # files share a name, the brief has to say which.
    ambiguous = {n for n, hits in BASENAMES.items() if len(hits) > 1}
    for cid, _c, _s, ev in rows:
        pat = r"(?<![/\w])([A-Za-z0-9_]+(?:_test\.dart|\.test\.js|\.dart|\.js))"
        for name in re.findall(pat, ev):
            if name in ambiguous:
                where = ", ".join(
                    sorted(h.relative_to(ROOT).as_posix() for h in BASENAMES[name]))
                problems.append(
                    f"{cid} cites `{name}` without a directory, and that name "
                    f"exists in more than one place ({where}). A reader "
                    f"following it reads whichever they find first, which for "
                    f"this claim may be the wrong evidence entirely."
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

    # 6. The size of the residual-risk register, where the brief states it.
    #
    # Added the day R16 was appended and three documents went on claiming
    # fifteen. Counts stated in prose are the most reliable thing in a
    # repository to go stale, which is why four of this script's invariants
    # are about numbers.
    tm = ROOT / "docs" / "THREAT_MODEL.md"
    if tm.exists():
        rows_r = len(re.findall(r"^\| R\d+ \|", tm.read_text(), re.M))
        words = {"twelve": 12, "thirteen": 13, "fourteen": 14, "fifteen": 15,
                 "sixteen": 16, "seventeen": 17, "eighteen": 18, "nineteen": 19,
                 "twenty": 20, "twenty-one": 21, "twenty-two": 22,
                 "twenty-three": 23, "twenty-four": 24, "twenty-five": 25,
                 "twenty-six": 26, "twenty-seven": 27, "twenty-eight": 28,
                 "twenty-nine": 29, "thirty": 30}
        m = re.search(r"\b([a-z]+(?:-[a-z]+)?)-row residual-risk register", text)
        if m:
            said = words.get(m.group(1))
            # An unknown word used to pass: `words.get(...)` was None and
            # None was in the allowed pair. The first row past twenty would
            # have gone unchecked for as long as nobody noticed.
            if said is None:
                problems.append(
                    f"AUDIT_SCOPE.md calls the residual-risk register "
                    f"'{m.group(1)}-row'; write the number as a word this "
                    f"script knows."
                )
            elif said != rows_r:
                problems.append(
                    f"AUDIT_SCOPE.md calls the residual-risk register "
                    f"'{m.group(1)}-row'; THREAT_MODEL.md has {rows_r} rows."
                )
        m = re.search(r"\(R1[–-]R(\d+)\)", text)
        if m and int(m.group(1)) != rows_r:
            problems.append(
                f"AUDIT_SCOPE.md cites the register as R1-R{m.group(1)}; it "
                f"runs to R{rows_r}."
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
