"""Build isolated no-NIC ARM64 CCID OUT/IN backpressure guest overlay."""

import gzip
import hashlib
import json
import sys
from pathlib import Path

here = Path(__file__).resolve().parent
mode = sys.argv[1] if len(sys.argv) == 2 else ""
assert mode in ("baseline", "fixed")
dest = here / mode
dest.mkdir(exist_ok=True)
base = Path("work/v53-functionfs-backpressure-candidate/stage-combined/guest-initramfs.gz")
candidate_bridge = here / "artifacts/build/ske-usbd"
init = f"""#!/bin/busybox sh
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
export HOME=/guest-state
export PYTHONUNBUFFERED=1
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /tmp
mkdir -p /dev/pts /guest-state
mount -t devpts devpts /dev/pts
echo SKE_V54_CCID_BACKPRESSURE_{mode.upper()}_START
ip link set lo up
/sbin/modprobe hid-generic || exit 80
mkdir -p /dev/gadget
if /usr/lib/systemd/systemd-udevd --daemon --resolve-names=never && /sbin/modprobe udc-core && /sbin/insmod /opt/dummy_hcd.ko is_high_speed=1 requested_ep_addresses=1 && /sbin/modprobe gadgetfs && /sbin/modprobe usbhid && mount -t gadgetfs gadgetfs /dev/gadget; then
    /sbin/modprobe libcomposite && /sbin/modprobe usb_f_fs && mount -t configfs configfs /sys/kernel/config || exit 82
    mkdir -p /sys/kernel/config/usb_gadget/ske/strings/0x409 /sys/kernel/config/usb_gadget/ske/configs/c.1 /sys/kernel/config/usb_gadget/ske/functions/ffs.ske /dev/ffs-ske
    ln -s /sys/kernel/config/usb_gadget/ske/functions/ffs.ske /sys/kernel/config/usb_gadget/ske/configs/c.1/ske
    mount -t functionfs ske /dev/ffs-ske || exit 83
    /opt/ske-venv/bin/python /opt/verification/verify_ccid_backpressure.py {mode}
    ske_guest_rc=$?
else
    ske_guest_rc=81
fi
echo SKE_V54_CCID_BACKPRESSURE_{mode.upper()}_EXIT=$ske_guest_rc
if [ "$ske_guest_rc" -ne 0 ]; then dmesg | tail -n 55; fi
sync
poweroff -f
"""
(dest / "guest-init.sh").write_text(init)


def member(name, data, file_mode, ino):
    name = name.encode() + b"\0"
    fields = [ino, file_mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name), 0]
    head = b"070701" + b"".join(f"{value:08x}".encode() for value in fields) + name
    return head + b"\0" * (-len(head) % 4) + data + b"\0" * (-len(data) % 4)


files = {
    "init": (init.encode(), 0o100755),
    "opt/verification/verify_ccid_backpressure.py": ((here / "verify_ccid_backpressure.py").read_bytes(), 0o100644),
}
if mode == "fixed":
    files["opt/ske-usbd"] = (candidate_bridge.read_bytes(), 0o100755)
payload = b"".join(member(name, data, file_mode, 960000 + i)
                   for i, (name, (data, file_mode)) in enumerate(files.items()))
payload += member("TRAILER!!!", b"", 0, 960099)
image = dest / "guest-initramfs.gz"
with base.open("rb") as source, image.open("wb") as target:
    while chunk := source.read(1024 * 1024):
        target.write(chunk)
    target.write(gzip.compress(payload, compresslevel=1, mtime=0))


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


published = Path("outputs/security-key-emulator")
base_inputs = json.loads(Path("work/v53-functionfs-backpressure-candidate/stage-combined/inputs.json").read_text())
assert sha(published / "bin/linux-arm64/ske-usbd") == base_inputs["linux_binary_sha256"]["ske-usbd"]
for name, expected in base_inputs["card_file_sha256"].items():
    assert sha(published / "emucard" / name) == expected
(dest / "inputs.json").write_text(json.dumps({
    "mode": mode,
    "published_bridge_sha256": sha(published / "bin/linux-arm64/ske-usbd"),
    "bridge_sha256": sha(candidate_bridge) if mode == "fixed" else sha(published / "bin/linux-arm64/ske-usbd"),
    "probe_sha256": sha(here / "verify_ccid_backpressure.py"),
    "base_guest_sha256": sha(base),
    "guest_image_sha256": sha(image),
    "kernel_sha256": sha("work/v42-second-full-native-kernel-panic/artifacts/guest-kernel"),
    "guest_network_devices": False,
    "host_usb_passthrough": False,
    "physical_device_access": False,
}, indent=2) + "\n")
print(mode, sha(image))
