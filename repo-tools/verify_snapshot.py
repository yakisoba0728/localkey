#!/usr/bin/env python3
"""Verify the frozen v0.64.0 repository snapshot and release evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


root = Path(__file__).resolve().parent.parent


def read(path: Path):
    return json.loads(path.read_text())


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


manifest = read(root / "manifest.json")
status = read(root / "implementation-status.json")
matrix = read(root / "compatibility-matrix.json")
assert manifest["version"] == status["version"] == matrix["version"] == "0.64.0"
assert all(item["complete_yubikey_equivalence"] is False
           for item in (manifest, status, matrix))

for name, expected in manifest["files"].items():
    path = root / name
    if not path.is_file() or path.stat().st_size != expected["size"]:
        raise SystemExit(f"Missing or wrong-sized {name}; run git lfs pull if needed")
    if sha(path) != expected["sha256"]:
        raise SystemExit(f"SHA-256 mismatch: {name}")

archive = root / "release/security-key-emulator.zip"
expected_archive = (root / "release/security-key-emulator.zip.sha256").read_text().split()[0]
assert sha(archive) == expected_archive
reextract = read(root / "release/reextract-result.json")
assert reextract["passed"] and reextract["archive_sha256"] == expected_archive
assert reextract["manifest_files_verified"] == len(manifest["files"])

integration = read(root / "evidence/v64-integration/result.json")
guest_dir = root / "evidence/v64-integration/guest"
guest = read(guest_dir / "result.json")
assert integration["passed"] and integration["main_check_count"] == 6029
assert guest["passed"] and guest["retry_success_after_first_failure"]
assert len(guest["exit_markers"]) == 12
assert sha(guest_dir / "console.log") == guest["raw_console_sha256"]
assert sha(guest_dir / "attempt1/console.log") == guest["first_attempt"]["console_sha256"]
assert guest["first_attempt"]["passed"] is False

print(json.dumps({
    "version": manifest["version"],
    "manifest_files_verified": len(manifest["files"]),
    "release_zip_sha256": expected_archive,
    "clean_reextract_passed": True,
    "main_checks": integration["main_check_count"],
    "guest_first_attempt_failed": True,
    "guest_retry_zero_exit_markers": len(guest["exit_markers"]),
    "complete_yubikey_equivalence": False,
}, indent=2))
