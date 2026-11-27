#!/usr/bin/env python3
"""Summarise one or more lcov.info files as line coverage.

Used by CI to print a short report and by a reader of the coverage artifact.
A percentage is a map of which lines were executed, not a substitute for the
claims in docs/AUDIT_SCOPE.md.

Exit 0 even when some inputs are missing if --allow-missing is set; otherwise
every name passed after --require must have a readable file.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections import defaultdict


def parse_lcov(path: str) -> dict[str, tuple[int, int]]:
    """Return {source_path: (lines_hit, lines_found)}."""
    out: dict[str, tuple[int, int]] = {}
    current = None
    hit = found = 0
    with open(path, encoding='utf-8', errors='replace') as fh:
        for raw in fh:
            line = raw.rstrip('\n')
            if line.startswith('SF:'):
                current = line[3:]
                hit = found = 0
            elif line.startswith('LH:'):
                hit = int(line[3:] or 0)
            elif line.startswith('LF:'):
                found = int(line[3:] or 0)
            elif line == 'end_of_record' and current is not None:
                out[current] = (hit, found)
                current = None
    return out


def lib_key(source: str) -> str:
    """A stable short path, starting at lib/ when we can."""
    source = source.replace('\\', '/')
    for marker in ('/lib/', '/app/lib/', '/protocol/lib/'):
        i = source.find(marker)
        if i >= 0:
            return source[i + 1:]  # drop the leading slash of the marker's first /
    # marker is '/lib/' → we want 'lib/...'
    i = source.find('/lib/')
    if i >= 0:
        return source[i + 1:]
    return os.path.basename(source)


def total(rows: dict[str, tuple[int, int]]) -> tuple[int, int]:
    hit = sum(h for h, _ in rows.values())
    found = sum(f for _, f in rows.values())
    return hit, found


def pct(hit: int, found: int) -> str:
    if found <= 0:
        return 'n/a'
    return f'{100.0 * hit / found:.1f}%'


def select(rows: dict[str, tuple[int, int]], contains: str) -> dict[str, tuple[int, int]]:
    needle = contains.replace('\\', '/')
    return {
        k: v
        for k, v in rows.items()
        if needle in k.replace('\\', '/')
    }


def print_block(title: str, rows: dict[str, tuple[int, int]], fh) -> None:
    hit, found = total(rows)
    fh.write(f'{title}: {hit}/{found} lines ({pct(hit, found)})\n')


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        '--dir',
        default='coverage-out',
        help='directory of <name>/lcov.info files (default: coverage-out)',
    )
    p.add_argument(
        '--require',
        default='',
        help='comma-separated names that must exist (e.g. protocol,app,server,kt)',
    )
    p.add_argument(
        '--allow-missing',
        action='store_true',
        help='do not fail when a file is absent; print "missing" instead',
    )
    args = p.parse_args(argv)

    names = ['protocol', 'app', 'server', 'kt']
    required = {n.strip() for n in args.require.split(',') if n.strip()}
    missing_required = []

    sys.stdout.write('Z test coverage (line coverage from lcov)\n')
    sys.stdout.write(
        'These numbers are which lines the suites executed, not a substitute '
        'for the claims in docs/AUDIT_SCOPE.md.\n\n'
    )

    for name in names:
        path = os.path.join(args.dir, name, 'lcov.info')
        if not os.path.isfile(path) or os.path.getsize(path) == 0:
            sys.stdout.write(f'{name}: missing\n')
            if name in required and not args.allow_missing:
                missing_required.append(name)
            continue
        rows = parse_lcov(path)
        print_block(name, rows, sys.stdout)
        if name == 'app':
            core = select(rows, '/lib/core/')
            if not core:
                core = select(rows, 'lib/core/')
            print_block('  app/lib/core', core, sys.stdout)
        if name == 'protocol':
            lib = select(rows, '/lib/') or select(rows, 'lib/')
            if lib:
                print_block('  protocol/lib', lib, sys.stdout)

    if missing_required:
        sys.stderr.write(
            'missing required coverage file(s): '
            + ', '.join(missing_required)
            + '\n'
        )
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
