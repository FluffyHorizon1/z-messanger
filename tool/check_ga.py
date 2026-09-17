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

    # G9 the other way round: a ✅ needs a second locale file to exist, and
    # check_l10n.py (run separately) to find it complete.
    g9_row = next((line for line in text.splitlines()
                   if re.match(r"\|\s*G9\s*\|", line)), "")
    arbs = sorted((ROOT / "app" / "lib" / "l10n").glob("app_*.arb"))
    if "✅" in g9_row and len(arbs) < 2:
        problems.append(
            "GA_CHECKLIST.md marks G9 ✅ but app/lib/l10n holds only "
            f"{len(arbs)} locale file(s). Localised means shipped in more "
            "than one language."
        )

    # G3, the other way round: the row may not read ✅ while the client ships
    # without all four transparency values. "Live" (adr/0006) includes the
    # client pinning the log's key AND holding a witness it can check it
    # against; an empty default means that half is not configured and the
    # client is inert in it, whatever the deployment says.
    #
    # This read `KT_LOG_PUB` alone, which is how a build could ship with no
    # witness at all — or with one on Android and not on Windows — and pass
    # every guard in the repository. The witness is condition 2 of G3's own
    # four-row table; nothing was reading it.
    g3_row = next((line for line in text.splitlines()
                   if re.match(r"\|\s*G3\s*\|", line)), "")
    client = ROOT / "app" / "lib" / "core" / "key_transparency.dart"
    # A guard gated on `client.exists()` is a guard an ordinary refactor
    # turns off: move the file and the four-value check below runs zero
    # times while G3 stays ✅. That was this line until 2026-09-17, one
    # release after the four-value check was added to close the same shape
    # of hole — the check read more values and was still gated on a path
    # that could vanish. `build.yml` below already had it right.
    if "✅" in g3_row and not client.exists():
        problems.append(
            f"GA_CHECKLIST.md marks G3 ✅ but {client.relative_to(ROOT)} is "
            f"not where this check reads the four transparency values from. "
            f"If the file moved, move this check with it; a guard that "
            f"cannot find its subject must refuse, not agree."
        )
    if "✅" in g3_row and client.exists():
        src = client.read_text()
        for name, what in (
            ("KT_LOG_URL", "the log's address"),
            ("KT_LOG_PUB", "the log's public key"),
            ("KT_WITNESS_URL", "the witness's record URL"),
            ("KT_WITNESS_PUB", "the witness's public key"),
        ):
            m = re.search(
                rf"String\.fromEnvironment\(\s*'{name}'\s*,\s*defaultValue:\s*'([^']*)'",
                src, re.S)
            if m is None or m.group(1).strip() == "":
                problems.append(
                    f"GA_CHECKLIST.md marks G3 ✅ but {what} ({name}) is empty "
                    f"in app/lib/core/key_transparency.dart. A log nobody's "
                    f"client pins is not live, and a witness nobody's client "
                    f"holds is not a witness."
                )

    # G3, once more, off the checklist entirely: the public /security page and
    # the roadmap must not tell the world the transparency log is unbuilt or
    # undeployed once the shipped client pins a live one. This document's own
    # "not built" line has been guarded since the log was built (top of this
    # function), but the same claim lived in two files nobody guarded, and both
    # drifted — `server/pages.js`'s /security page said "designed but not
    # built" and `ROADMAP.md` "waits on deployment" for weeks after the log
    # went live at kt.zmessengers.com (2026-09-13). A guard on one copy of a
    # claim is not a guard on the claim. The log is pinned when
    # `defaultKtLogPub` has a non-empty default — the value G3's row is checked
    # against above.
    log_pinned = False
    if client.exists():
        mk = re.search(
            r"String\.fromEnvironment\(\s*'KT_LOG_PUB'\s*,\s*defaultValue:\s*'([^']*)'",
            client.read_text(), re.S)
        log_pinned = bool(mk and mk.group(1).strip())
    if log_pinned:
        for rel, phrases in (
            ("server/pages.js",
             ("no public transparency log", "designed but not built")),
            ("ROADMAP.md",
             ("waits on deployment",
              "transparency log going live (a deployment")),
        ):
            p = ROOT / rel
            if not p.exists():
                continue
            flat = re.sub(r"\s+", " ", p.read_text().lower())
            for phrase in phrases:
                if phrase in flat:
                    problems.append(
                        f"{rel} still says the transparency log is unbuilt or "
                        f"undeployed (\"{phrase}\"), but the shipped client "
                        f"pins a live log (defaultKtLogPub is set). It went "
                        f"live 2026-09-13; say so, as GA_CHECKLIST and the docs "
                        f"already do — the open half of G3 is the independent "
                        f"witness, not deployment."
                    )

    # And the values live in the SOURCE, not in a build command.
    #
    # Not a style preference. `reproducible` rebuilds the release APK four
    # ways and compares, PROVENANCE.md asks an outsider to do the same, and
    # neither passes any `--dart-define` — so a value supplied on one build
    # command is a value the rebuild cannot reproduce, and G2 fails on a
    # difference nobody can see by reading the repository. It is also the only
    # thing that keeps five `flutter build` lines across four platform jobs
    # from drifting: a constant in one file cannot ship on Android and not on
    # Windows.
    wf = ROOT / ".github" / "workflows" / "build.yml"
    if not wf.exists():
        problems.append(
            ".github/workflows/build.yml is missing, so the rule below — that "
            "no build passes a transparency value on the command line — was "
            "checked against nothing."
        )
    else:
        wf_text = wf.read_text()
        if "flutter build" not in wf_text:
            problems.append(
                ".github/workflows/build.yml contains no `flutter build`, so "
                "this check has nothing to judge. Fix the check before "
                "trusting it."
            )
        for i, line in enumerate(wf_text.splitlines(), 1):
            if "--dart-define" in line and "KT_" in line:
                problems.append(
                    f".github/workflows/build.yml:{i} passes a transparency "
                    f"value as a --dart-define. The `reproducible` job and "
                    f"every outside rebuild (PROVENANCE.md) build without it, "
                    f"so the artifact they produce is not the one shipped — "
                    f"and a value in a build command can be given to one "
                    f"platform and not another. Put it in "
                    f"app/lib/core/key_transparency.dart, where there is one "
                    f"copy and every job gets it."
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
