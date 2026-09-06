#!/usr/bin/env python3
"""Checks the Z palettes in lib/ui/theme.dart for WCAG AA contrast (4.5:1).

Every text colour is checked against every background it can sit on, and
onAccent against accent. Exit status 1 if any pair falls short, so this can
run in CI next to the vector verifiers.
"""
import re
import sys
from pathlib import Path

THEME = Path(__file__).resolve().parent.parent / "lib" / "ui" / "theme.dart"
TEXT = ("accent", "textPrimary", "textSecondary", "danger", "ok", "warn")
BACKGROUNDS = ("bg", "surface", "surfaceAlt", "mineBubble", "theirsBubble")


def luminance(hex6: str) -> float:
    def channel(c: float) -> float:
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = (int(hex6[i : i + 2], 16) / 255 for i in (0, 2, 4))
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def contrast(a: str, b: str) -> float:
    la, lb = luminance(a), luminance(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def palettes(source: str) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for m in re.finditer(r"static const (\w+) = ZColors\((.*?)\);", source, re.S):
        name, body = m.group(1), m.group(2)
        out[name] = {
            k: v.upper()
            for k, v in re.findall(r"(\w+): Color\(0xFF([0-9A-Fa-f]{6})\)", body)
        }
    return out


def main() -> int:
    bad = 0
    for name, p in palettes(THEME.read_text()).items():
        print(f"{name}:")
        pairs = [(fg, bg) for fg in TEXT for bg in BACKGROUNDS] + [("onAccent", "accent")]
        for fg, bg in pairs:
            ratio = contrast(p[fg], p[bg])
            flag = "" if ratio >= 4.5 else "   <-- below 4.5:1"
            bad += 1 if flag else 0
            print(f"  {fg:14s} on {bg:13s} {ratio:5.2f}{flag}")
    if bad:
        print(f"{bad} pair(s) below AA")
        return 1
    print("all pairs clear WCAG AA")
    return 0


if __name__ == "__main__":
    sys.exit(main())
