#!/usr/bin/env python3
"""The Android manifest opts out of every automatic copy of the app's data.

Written after an independent review found that nothing in the repository had
ever said so, and the platform default is the opposite: without
`android:allowBackup="false"` the vault directory — `z.db`, the wrapped
master key, the attachment blobs — is inside Android's Auto Backup set and is
copied to the user's cloud account, and on API 31+ to a new phone by
device-to-device transfer.

The copy matters because the database seals individual CELLS, not its
structure: `messages.rid/outgoing/kind/ts_ms`, `contacts.rid/verified` and
the plain `kv` rows are cleartext in the file, so a copy carries the whole
contact graph and every message's direction and timing. Before Android 9,
Auto Backup had no end-to-end encryption at all. And a restore is worse than
useless: the wrapped master key comes back without the hardware-backed key
that protects the device secret, so the vault cannot be opened and the
install is dead on every launch.

This is the kind of claim that is true only while someone remembers it — a
default nobody wrote down was how it got here — so it is checked:

  * the <application> element sets allowBackup="false";
  * it names a dataExtractionRules resource, and that file exists;
  * those rules exclude every domain the app writes from BOTH cloud-backup
    and device-transfer (allowBackup alone does not govern the transfer);
  * nothing has re-enabled android:debuggable.
"""
from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "app/android/app/src/main/AndroidManifest.xml"
ANDROID = "{http://schemas.android.com/apk/res/android}"
# Every domain an app can be made to hand over. `root` covers the files
# directory's parent; the rest are named individually because the schema has
# no "everything" token and a missing one is an opt-in.
DOMAINS = {"root", "file", "database", "sharedpref", "external"}


def main() -> int:
    problems: list[str] = []
    if not MANIFEST.exists():
        print(f"{MANIFEST.relative_to(ROOT)}: missing", file=sys.stderr)
        return 1
    app = ET.parse(MANIFEST).getroot().find("application")
    if app is None:
        print("AndroidManifest.xml: no <application> element", file=sys.stderr)
        return 1

    if app.get(f"{ANDROID}allowBackup") != "false":
        problems.append(
            'AndroidManifest.xml: <application> must set android:allowBackup="false" '
            "— the default is true and copies the vault to the user's cloud account"
        )
    if app.get(f"{ANDROID}debuggable") is not None:
        problems.append(
            "AndroidManifest.xml: android:debuggable is set; the build type decides that"
        )

    rules = app.get(f"{ANDROID}dataExtractionRules")
    if rules is None:
        problems.append(
            "AndroidManifest.xml: <application> must name android:dataExtractionRules "
            "— on API 31+ it, and not allowBackup, governs device-to-device transfer"
        )
    else:
        m = re.fullmatch(r"@xml/([A-Za-z0-9_]+)", rules)
        if not m:
            problems.append(f"AndroidManifest.xml: dataExtractionRules={rules!r} is not @xml/<name>")
        else:
            path = MANIFEST.parent / "res" / "xml" / f"{m.group(1)}.xml"
            if not path.exists():
                problems.append(f"AndroidManifest.xml: dataExtractionRules names {path.relative_to(ROOT)}, which is missing")
            else:
                root = ET.parse(path).getroot()
                for section in ("cloud-backup", "device-transfer"):
                    el = root.find(section)
                    if el is None:
                        problems.append(f"{path.relative_to(ROOT)}: no <{section}> section")
                        continue
                    if el.findall("include"):
                        problems.append(
                            f"{path.relative_to(ROOT)}: <{section}> has an <include>; "
                            "nothing in the vault is safe to copy off the device"
                        )
                    excluded = {e.get("domain") for e in el.findall("exclude") if e.get("path") is None}
                    missing = sorted(DOMAINS - excluded)
                    if missing:
                        problems.append(
                            f"{path.relative_to(ROOT)}: <{section}> does not exclude "
                            f"{', '.join(missing)} (a domain left out is opted in)"
                        )

    for p in problems:
        print(p, file=sys.stderr)
    if problems:
        print(f"\n{len(problems)} problem(s). See this script's docstring for why each matters.", file=sys.stderr)
        return 1
    print("android data safety: backup and device transfer are both refused, for every domain")
    return 0


if __name__ == "__main__":
    sys.exit(main())
