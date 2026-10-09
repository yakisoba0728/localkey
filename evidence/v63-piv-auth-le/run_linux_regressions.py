#!/usr/bin/env python3
"""Run isolated PIV/smartcard regressions against the candidate in no-NIC guest."""

import subprocess
import sys
from pathlib import Path


ROOT = Path("/case/candidate")
RESULTS = Path("/result")
IFD = Path("/ske-ifd.so")


def run(label, script, *args):
    cmd = [sys.executable, str(script), *map(str, args)]
    print(label, flush=True)
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)


for mode in ("socket", "ifd"):
    ifd = ["--ifd-driver", str(IFD)] if mode == "ifd" else []
    ifd_short = ["--ifd", str(IFD)] if mode == "ifd" else []
    run(
        f"piv-profile-{mode}", ROOT / "tools/verify_piv_profile.py",
        "--report", RESULTS / f"linux-piv-profile-{mode}.json", *ifd,
    )
    run(
        f"piv-management-{mode}", ROOT / "tools/verify_piv_management_header.py",
        "--root", ROOT, "--report", RESULTS / f"linux-piv-management-{mode}.json",
        "--expect-fixed", *ifd_short,
    )
    run(
        f"piv-generate-{mode}", "/case/verify_piv_generate_p1.py",
        "--root", ROOT, "--report", RESULTS / f"linux-piv-generate-{mode}.json",
        "--fixed", *ifd_short,
    )
    run(
        f"smartcard-{mode}", ROOT / "tools/verify_smartcard.py",
        "--work-dir", "/tmp", "--report", RESULTS / f"linux-smartcard-{mode}.json", *ifd,
    )

run(
    "piv-storage-socket", ROOT / "tools/verify_piv_storage.py",
    "--report", RESULTS / "linux-piv-storage-socket.json",
)
print("all Linux regressions passed", flush=True)
