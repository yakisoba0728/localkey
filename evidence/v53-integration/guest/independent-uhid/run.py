#!/usr/bin/env python3
"""Run the existing native UHID/PCSC check in an owned no-NIC QEMU guest."""

from __future__ import annotations

import gzip
import hashlib
import json
import re
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
STAGE = ROOT / "work/security-key-emulator-v53-staging/security-key-emulator"
BASE = ROOT / "work/v52-stage-integrated-guest/uhid/guest-initramfs.gz"
KERNEL = ROOT / "work/v42-second-full-native-kernel-panic/artifacts/guest-kernel"
IMAGE = HERE / "guest-initramfs.gz"
CONSOLE = HERE / "console.log"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha(path: Path) -> str:
    return sha(path.read_bytes())


def member(name: str, data: bytes, mode: int, inode: int) -> bytes:
    name_bytes = name.encode() + b"\0"
    fields = [inode, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name_bytes), 0]
    header = b"070701" + b"".join(f"{value:08x}".encode() for value in fields)
    body = header + name_bytes
    return body + b"\0" * (-len(body) % 4) + data + b"\0" * (-len(data) % 4)


def main() -> None:
    source = {p.name: p.read_bytes() for p in sorted((STAGE / "emucard").glob("*.py"))}
    assert len(source) == 15
    binary_names = (
        "ske-otpd", "ske-usbd", "swpasskeyd", "swpasskeyctl", "swpasskey_tests"
    )
    binaries = {name: (STAGE / "bin/linux-arm64" / name).read_bytes() for name in binary_names}
    ifd_path = STAGE / "bin/linux-arm64/ifd-ske.bundle/Contents/Linux/ske-ifd.so"
    ifd = ifd_path.read_bytes()
    verifier_path = STAGE / "tools/linux-native/verify-native-extra.py"
    verifier = verifier_path.read_bytes()
    init = (ROOT / "work/v52-stage-integrated-guest/uhid/guest-init.sh").read_text()
    assert init.count("SKE_V52_STAGE_UHID_") == 2
    init = init.replace("SKE_V52_STAGE_UHID_", "SKE_V53_FINAL_UHID_")
    (HERE / "guest-init.sh").write_text(init)

    overlays: dict[str, tuple[bytes, int]] = {"init": (init.encode(), 0o100755)}
    overlays.update({f"opt/emucard/{name}": (data, 0o100644) for name, data in source.items()})
    overlays.update({f"opt/{name}": (data, 0o100755) for name, data in binaries.items()})
    overlays["opt/ske-ifd.so"] = (ifd, 0o100755)
    overlays["opt/verification/verify-native-extra.py"] = (verifier, 0o100644)
    payload = b"".join(
        member(name, data, mode, 953900 + i)
        for i, (name, (data, mode)) in enumerate(overlays.items())
    ) + member("TRAILER!!!", b"", 0, 953999)
    with BASE.open("rb") as src, IMAGE.open("wb") as dst:
        while chunk := src.read(1024 * 1024):
            dst.write(chunk)
        dst.write(gzip.compress(payload, compresslevel=1, mtime=0))
    (HERE / "guest-kernel").write_bytes(KERNEL.read_bytes())

    inputs = {
        "stage_card_sha256": {name: sha(data) for name, data in source.items()},
        "stage_binary_sha256": {name: sha(data) for name, data in binaries.items()},
        "stage_ifd_sha256": sha(ifd),
        "stage_native_extra_test_sha256": sha(verifier),
        "base_uhid_guest_sha256": file_sha(BASE),
        "guest_image_sha256": file_sha(IMAGE),
        "kernel_sha256": file_sha(HERE / "guest-kernel"),
        "guest_network_devices": False,
        "host_usb_passthrough": False,
        "host_pcsc_passthrough": False,
        "physical_device_access": False,
    }
    (HERE / "inputs.json").write_text(json.dumps(inputs, indent=2) + "\n")
    command = [
        "docker", "run", "--rm", "--network", "none", "--name", "ske-v53-uhid-final",
        "--mount", f"type=bind,source={HERE},target=/artifacts,readonly",
        "ske-linux-native:0.36", "timeout", "--kill-after=10s", "900s",
        "qemu-system-aarch64", "-machine", "virt", "-cpu", "cortex-a72",
        "-accel", "tcg", "-m", "4096", "-smp", "2",
        "-kernel", "/artifacts/guest-kernel", "-initrd", "/artifacts/guest-initramfs.gz",
        "-append", "console=ttyAMA0 rdinit=/init panic=1", "-nic", "none",
        "-display", "none", "-serial", "stdio", "-monitor", "none", "-no-reboot",
    ]
    (HERE / "run-command.json").write_text(json.dumps(command, indent=2) + "\n")
    with CONSOLE.open("wb") as log:
        runner = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=False)
    raw = CONSOLE.read_text(errors="replace")
    checks = re.findall(r"^PASS (.+)$", raw, flags=re.MULTILINE)
    passed = (
        runner.returncode == 0
        and len(checks) == 25
        and len(set(checks)) == 25
        and raw.count("SKE_V53_FINAL_UHID_START") == 1
        and raw.count("SKE_V53_FINAL_UHID_EXIT=0") == 1
        and raw.count("SKE_NATIVE_EXTRA_BEGIN") == 1
        and raw.count("SKE_NATIVE_EXTRA_END") == 1
        and "Kernel panic" not in raw
        and '"passed": true' in raw
    )
    stage_unchanged = (
        all(file_sha(STAGE / "emucard" / name) == value for name, value in inputs["stage_card_sha256"].items())
        and all(file_sha(STAGE / "bin/linux-arm64" / name) == value for name, value in inputs["stage_binary_sha256"].items())
        and file_sha(ifd_path) == inputs["stage_ifd_sha256"]
        and file_sha(verifier_path) == inputs["stage_native_extra_test_sha256"]
    )
    result = {
        "passed": passed and stage_unchanged,
        "runner_exit": runner.returncode,
        "checks": len(checks),
        "check_names": checks,
        "stage_unchanged": stage_unchanged,
        **inputs,
        "inputs_sha256": file_sha(HERE / "inputs.json"),
        "raw_console_sha256": file_sha(CONSOLE),
        "kernel_panic": "Kernel panic" in raw,
        "limitations": [
            "UHID and PCSC run inside a private ARM64 software guest; no physical YubiKey was measured.",
            "The 25 checks cover OTP HID, evdev keyboard, PCSC SDK and crypto paths, not all native Linux binary features.",
        ],
    }
    (HERE / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"passed": result["passed"], "checks": len(checks),
                      "runner_exit": runner.returncode, "console_sha256": result["raw_console_sha256"]}))
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
