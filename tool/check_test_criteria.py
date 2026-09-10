#!/usr/bin/env python3
"""A test file that lists its exit criteria must have a test for each.

Written after a review found that skipped_keys_test.dart promised four exit
criteria in its header and contained three tests: the fourth — "a failed
send rolls the ratchet back without emptying the cache" — was the one the
commit message spent a paragraph on, and nothing had ever checked it. Every
guard in this repository said clean, because every guard checked that test
FILES existed and were cited, and none checked that a file's stated
criteria and its tests were the same thing.

The rule is deliberately crude. A file whose leading comment block contains
a numbered list of two or more items (`//   1. ...`) is taken to be stating
exit criteria, and must contain at least that many `test(` / `testWidgets(`
calls. One test may legitimately cover two criteria; when it does, the header
says so in words — "criteria 1 and 2 share a test" — and the shortfall is
allowed by exactly that many. Anything subtler than counting would need a
convention nobody would keep.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEST_DIRS = [ROOT / "app" / "test", ROOT / "protocol" / "test"]

SHARE = re.compile(r"criteria\s+(\d+)\s+and\s+(\d+)\s+share\s+(?:a|one)\s+test", re.I)


def header_of(src: str) -> str:
    lines = []
    for line in src.splitlines():
        if line.startswith("//"):
            lines.append(line)
        elif line.strip() == "":
            continue
        else:
            break
    return "\n".join(lines)


def main() -> int:
    problems, checked = [], 0
    for d in TEST_DIRS:
        for p in sorted(d.glob("*.dart")):
            src = p.read_text(encoding="utf-8")
            header = header_of(src)
            criteria = re.findall(r"^//\s+(\d+)\.\s", header, re.M)
            if len(criteria) < 2:
                continue
            checked += 1
            tests = len(re.findall(r"^\s*(?:test|testWidgets)\(", src, re.M))
            shared = len(SHARE.findall(header))
            need = len(criteria) - shared
            if tests < need:
                rel = p.relative_to(ROOT)
                problems.append(
                    f"{rel}: the header lists {len(criteria)} exit criteria"
                    f"{f' ({shared} shared)' if shared else ''} and the file has "
                    f"{tests} tests. A criterion with no test behind it is a "
                    f"promise, not a guard — add the test, or say in the header "
                    f"which two criteria share one."
                )
    print(f"test files stating criteria: {checked}")
    if problems:
        print(f"\n{len(problems)} problem(s):\n")
        for x in problems:
            print(f"  - {x}")
        return 1
    print("every stated exit criterion has a test behind it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
