"""Overlay only the candidate ske-usbd on the frozen v0.52 USB guest suite."""

import gzip
import hashlib
import json
from pathlib import Path

here = Path(__file__).resolve().parent
dest = here / "regression"
dest.mkdir(exist_ok=True)
base = Path("work/v53-touch-reset-candidate/full/guest-initramfs.gz")
bridge = here / "artifacts/build/ske-usbd"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def member(name, data, mode, ino):
    name = name.encode() + b"\0"
    fields = [ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name), 0]
    head = b"070701" + b"".join(f"{value:08x}".encode() for value in fields) + name
    return head + b"\0" * (-len(head) % 4) + data + b"\0" * (-len(data) % 4)


payload = member("opt/ske-usbd", bridge.read_bytes(), 0o100755, 957000)
payload += member("TRAILER!!!", b"", 0, 957001)
image = dest / "guest-initramfs.gz"
with base.open("rb") as source, image.open("wb") as target:
    while chunk := source.read(1024 * 1024):
        target.write(chunk)
    target.write(gzip.compress(payload, compresslevel=1, mtime=0))

base_inputs = json.loads(Path("work/v53-touch-reset-candidate/full/inputs.json").read_text())
assert base_inputs["linux_binary_sha256"]["ske-usbd"] == sha(
    "outputs/security-key-emulator/bin/linux-arm64/ske-usbd"
)
(dest / "inputs.json").write_text(json.dumps({
    "base_guest_sha256": sha(base),
    "guest_image_sha256": sha(image),
    "published_bridge_sha256": base_inputs["linux_binary_sha256"]["ske-usbd"],
    "candidate_bridge_sha256": sha(bridge),
    "candidate_source_sha256": {
        "include/swpasskey/usb/composite.hpp": sha(here / "source/include/swpasskey/usb/composite.hpp"),
        "src/usb/composite.cpp": sha(here / "source/src/usb/composite.cpp"),
        "src/usb/backend.hpp": sha(here / "source/src/usb/backend.hpp"),
    },
    "card_file_sha256": base_inputs["card_file_sha256"],
    "other_linux_binary_sha256": {
        key: value for key, value in base_inputs["linux_binary_sha256"].items()
        if key != "ske-usbd"
    },
    "kernel_sha256": base_inputs["kernel_sha256"],
    "guest_network_devices": False,
    "host_usb_passthrough": False,
    "physical_device_access": False,
}, indent=2) + "\n")
print(sha(image))
