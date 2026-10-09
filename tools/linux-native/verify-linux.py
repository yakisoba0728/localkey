#!/usr/bin/env python3
"""Build and test in a private ARM64 Linux guest; never passes host devices."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

helpers = Path(__file__).resolve().parent
root = helpers.parent.parent
artifacts = root / "work/linux-native-artifacts"
artifacts.mkdir(parents=True, exist_ok=True)
image = "ske-linux-native:0.36"
subprocess.run(
    [
        "docker",
        "build",
        "--platform",
        "linux/arm64",
        "--tag",
        image,
        "--file",
        str(helpers / "Dockerfile"),
        str(helpers),
    ],
    check=True,
)


def builder(command, extra_mounts=()):
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/arm64",
            "--mount",
            f"type=bind,source={artifacts},target=/artifacts",
            "--mount",
            f"type=bind,source={helpers},target=/work,readonly",
            *extra_mounts,
            image,
            *command,
        ],
        check=True,
    )


builder(
    ["sh", "/work/build-source.sh"],
    (
        "--mount",
        f"type=bind,source={root / 'source'},target=/src,readonly",
    ),
)
builder(
    [
        "/opt/ske-venv/bin/python",
        "/src-app/tools/verify_ifd.py",
        "--driver",
        "/artifacts/build/ifd-ske.bundle/Contents/Linux/ske-ifd.so",
        "--work-dir",
        "/tmp",
        "--report",
        "/artifacts/linux-ifd-abi-result.json",
    ],
    ("--mount", f"type=bind,source={root},target=/src-app,readonly"),
)
builder(
    ["python3", "/work/build-guest.py"],
    (
        "--mount",
        f"type=bind,source={root / 'tools'},target=/src-tools,readonly",
        "--mount",
        f"type=bind,source={root},target=/src-application,readonly",
    ),
)
subprocess.run(
    [
        sys.executable,
        str(helpers / "run-guest.py"),
        "--artifacts",
        str(artifacts),
        "--image",
        image,
        "--expect-extra",
        "--expect-composite",
    ],
    check=True,
)
print(f"Native Linux report: {artifacts / 'linux-native-result.json'}")
