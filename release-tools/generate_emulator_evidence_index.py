"""Create a navigable inventory of every delivered evidence directory."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


parser = argparse.ArgumentParser()
parser.add_argument("root", type=Path)
args = parser.parse_args()
root = args.root.resolve()
assert (root / "implementation-status.json").is_file()
evidence = root / "evidence"
target = root / "docs/EVIDENCE_INDEX.md"
target.parent.mkdir(exist_ok=True)

lines = [
    "# Delivered evidence index",
    "",
    "All paths below are inside the released package. Read each report's scope, raw logs,",
    "source/binary hashes and limitations before citing a result. A historical result is",
    "not evidence that the newest source was rerun. The current integration gate is",
    "`v64-integration/`; `../implementation-status.json` and",
    "`../compatibility-matrix.json` give the complete claim inventory.",
    "",
    "| Evidence directory | Review entry | Files |",
    "| --- | --- | ---: |",
]

for directory in sorted(evidence.iterdir(), key=lambda p: p.name):
    if not directory.is_dir():
        continue
    if not re.match(r"v\d+", directory.name):
        continue
    readme = directory / "README.md"
    if readme.exists():
        headings = [line.lstrip("# ").strip() for line in readme.read_text(errors="replace").splitlines()
                    if line.startswith("# ")]
        label = headings[0] if headings else "README and raw reports"
        entry = f"[README](../evidence/{directory.name}/README.md): {label}"
    elif (directory / "result.json").exists():
        entry = f"[result.json](../evidence/{directory.name}/result.json)"
    else:
        entry = "raw reports and artifacts"
    count = sum(path.is_file() for path in directory.rglob("*"))
    lines.append(f"| [`{directory.name}/`](../evidence/{directory.name}/) | {entry.replace('|', '/')} | {count} |")

lines += [
    "",
    "Candidate evidence contains focused before/after probes. Integration directories",
    "contain the cross-component test gate; guest `console.log` and `inputs.json`",
    "anchor no-network native USB checks. The software's captured public firmware",
    "metadata does not establish full physical firmware behavior or manufacturer trust.",
    "",
]
target.write_text("\n".join(lines))
print(f"{target}: {len(lines) - 15} directories indexed")
