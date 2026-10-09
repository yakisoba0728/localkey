"""Publish verified v0.64, retaining the previous v0.63 folder and ZIP."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path


base = Path(__file__).resolve().parent.parent
old = base / "outputs/security-key-emulator"
new = base / "work/security-key-emulator-v64-staging/security-key-emulator"
backup = base / "work/security-key-emulator-v63-published-folder"
old_zip = base / "outputs/security-key-emulator.zip"
new_zip = base / "work/security-key-emulator-v64-staging/security-key-emulator.zip"
old_sum = base / "outputs/security-key-emulator.zip.sha256"
new_sum = base / "work/security-key-emulator-v64-staging/security-key-emulator.zip.sha256"
frozen_zip = base / "work/security-key-emulator-v63-frozen.zip"


def version(path: Path) -> str:
    return json.loads((path / "manifest.json").read_text())["version"]


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


assert version(old) == "0.63.0" and version(new) == "0.64.0"
assert not backup.exists() and not frozen_zip.exists()
assert (old / ".venv").exists() and not (new / ".venv").exists()
assert digest(old_zip) == "45ea3716e853e2e56f914225ae241177fe0f2a17639c8eb8c180bf38c222c49c"
expected = json.loads((base / "work/security-key-emulator-v64-staging/package-result.json").read_text())["sha256"]
assert digest(new_zip) == expected
assert new_sum.read_text().split()[0] == expected
verified = json.loads((base / "work/v64-reextract-validation/result.json").read_text())
assert verified["passed"] and verified["archive_sha256"] == expected

subprocess.run(["cp", "-c", str(old_zip), str(frozen_zip)], check=True)
assert digest(frozen_zip) == digest(old_zip)
old.rename(backup)
try:
    new.rename(old)
except BaseException:
    backup.rename(old)
    raise
(backup / ".venv").rename(old / ".venv")
os.replace(new_zip, old_zip)
os.replace(new_sum, old_sum)
assert version(old) == "0.64.0" and version(backup) == "0.63.0"
assert digest(old_zip) == expected
assert old_sum.read_text().split()[0] == expected
print(json.dumps({"published_version": version(old), "zip_sha256": expected,
                  "frozen_previous_version": version(backup)}, indent=2))
