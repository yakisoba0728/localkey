#!/usr/bin/env python3
"""Count the behaviour-catalog mapping in docs/catalog/*.md.

Each per-crate file maps bullets of reference/BEHAVIOR_CATALOG.md to one label:
`tested`, `intentional difference` or `deferred`. This script counts them so the
summary in docs/CATALOG_STATUS.md never drifts from the files.

Counting rule (the same for every file):
- Only `## ` sections that map catalog bullets are counted. Sections of notes are
  skipped: model policies or decisions, review notes, interop or host-shape notes,
  and anything before the first `## ` heading.
- Each top-level bullet (`- ` at column 0) is one catalog line. Indented lines belong
  to the bullet above.
- The label is the first of `tested`, `intentional difference`, `deferred` or
  `not a ... item` that follows `—` or `:`. A bullet that leaves part of itself to
  another phase still counts once, under its first label; the rest of the text says
  what is missing.
- `not a ... item` lines (a bullet owned by another crate's file) are counted
  separately and are not part of the crate's totals.
- "Partly deferred or different" counts the `tested` bullets in which a later
  `deferred` or `intentional difference` names a part the engine does not cover.

Usage:
  python3 tools/catalog_status.py            # print the summary table
  python3 tools/catalog_status.py --write    # put the table into docs/CATALOG_STATUS.md
  python3 tools/catalog_status.py --check    # fail if a bullet has no label or the
                                             # table in docs/CATALOG_STATUS.md is stale
  python3 tools/catalog_status.py --list deferred   # list the bullets with a label
                                                    # (also: partial, elsewhere)
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CATALOG = ROOT / "docs" / "catalog"
SUMMARY = ROOT / "docs" / "CATALOG_STATUS.md"
BEGIN = "<!-- BEGIN tools/catalog_status.py -->"
END = "<!-- END tools/catalog_status.py -->"

# Order of the summary table and the crate that owns each file.
FILES = [
    ("fido.md", "lk-fido", "FIDO2 / U2F"),
    ("otp.md", "lk-otp", "OTP"),
    ("oath.md", "lk-oath", "OATH"),
    ("mgmt.md", "lk-mgmt", "Management"),
    ("piv.md", "lk-piv", "PIV"),
    ("openpgp.md", "lk-openpgp", "OpenPGP"),
    ("hsmauth.md", "lk-hsmauth", "YubiHSM Auth"),
    ("sd.md", "lk-sd", "Security Domain / SCP03 / SCP11"),
    ("device.md", "lk-device", "Device / transports / storage"),
]

NOTE_SECTION = re.compile(
    r"model polic|model decision|adversarial review|second review|interop notes|"
    r"host software|host request shapes|behaviours fixed|fixed by|other model decisions",
    re.IGNORECASE,
)

LABEL = re.compile(
    r"(?:—|:)\s*`?(tested|intentional difference|deferred|not an? [\w-]+ item)\b",
    re.IGNORECASE,
)

# A later label inside a `tested` bullet: the part of the bullet still deferred or
# deliberately different (for example "tested: ...; deferred: program phase").
SECONDARY = re.compile(r"(?:[;—.:]|\))\s*`?(intentional difference|deferred)\b", re.IGNORECASE)

LABELS = ("tested", "intentional difference", "deferred", "elsewhere", "unlabelled", "partial")


def bullets(path: pathlib.Path):
    """Yield (section, text) for every top-level bullet of a counted section."""
    section = None
    current = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("#"):
            if current is not None:
                yield current
                current = None
            section = line.lstrip("#").strip() if line.startswith("## ") else None
            continue
        counted = section is not None and not NOTE_SECTION.search(section)
        if line.startswith("- "):
            if current is not None:
                yield current
            current = (section, line[2:].strip()) if counted else None
        elif current is not None and line.startswith((" ", "\t")) and line.strip():
            current = (current[0], current[1] + " " + line.strip())
        elif current is not None and not line.strip():
            yield current
            current = None
    if current is not None:
        yield current


def label_of(text: str) -> str:
    match = LABEL.search(text)
    if not match:
        return "unlabelled"
    word = match.group(1).lower()
    if word.startswith("not a"):
        return "elsewhere"
    return word


def is_partial(text: str) -> bool:
    """A `tested` bullet that names a part still deferred or deliberately different."""
    match = LABEL.search(text)
    return bool(match) and bool(SECONDARY.search(text, match.end()))


def collect():
    rows = []
    for name, crate, title in FILES:
        path = CATALOG / name
        items = [(section, text, label_of(text)) for section, text in bullets(path)]
        counts = {label: 0 for label in LABELS}
        for _, text, label in items:
            counts[label] += 1
            if label == "tested" and is_partial(text):
                counts["partial"] += 1
        rows.append((name, crate, title, counts, items))
    return rows


def table(rows) -> str:
    out = [
        "| Area | Crate | Tested | of which partly deferred or different | Intentional difference "
        "| Deferred | Lines | Mapping |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    total = {label: 0 for label in LABELS}
    for name, crate, title, counts, _ in rows:
        lines = counts["tested"] + counts["intentional difference"] + counts["deferred"]
        out.append(
            f"| {title} | `{crate}` | {counts['tested']} | {counts['partial']} "
            f"| {counts['intentional difference']} | {counts['deferred']} | {lines} "
            f"| [catalog/{name}](catalog/{name}) |"
        )
        for label in LABELS:
            total[label] += counts[label]
    lines = total["tested"] + total["intentional difference"] + total["deferred"]
    out.append(
        f"| **All files** | | **{total['tested']}** | **{total['partial']}** "
        f"| **{total['intentional difference']}** | **{total['deferred']}** | **{lines}** | |"
    )
    return "\n".join(out), total


def main(argv: list[str]) -> int:
    rows = collect()
    if "--list" in argv:
        wanted = argv[argv.index("--list") + 1].lower()
        for name, _, _, _, items in rows:
            for section, text, label in items:
                hit = label == wanted or (wanted == "partial" and label == "tested" and is_partial(text))
                if hit:
                    print(f"{name} [{section}] {text[:200]}")
        return 0
    text, total = table(rows)
    footer = (
        f"Bullets owned by another crate's file (not counted above): {total['elsewhere']}. "
        f"Unlabelled bullets: {total['unlabelled']}."
    )
    block = f"{BEGIN}\n{text}\n\n{footer}\n{END}"
    print(text)
    print()
    print(footer)
    status = 0
    if "--write" in argv:
        current = SUMMARY.read_text(encoding="utf-8")
        start, end = current.index(BEGIN), current.index(END) + len(END)
        SUMMARY.write_text(current[:start] + block + current[end:], encoding="utf-8")
    if "--check" in argv:
        if total["unlabelled"]:
            for name, _, _, _, items in rows:
                for section, item, label in items:
                    if label == "unlabelled":
                        print(f"unlabelled: {name} [{section}] {item[:160]}", file=sys.stderr)
            status = 1
        if block not in SUMMARY.read_text(encoding="utf-8"):
            print(f"{SUMMARY.relative_to(ROOT)} is stale: run with --write", file=sys.stderr)
            status = 1
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
