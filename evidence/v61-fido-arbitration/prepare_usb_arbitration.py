"""Overlay v60/v61 FIDO daemons on one frozen private no-NIC USB guest."""

import gzip
import hashlib
import json
from pathlib import Path

here = Path(__file__).resolve().parent
base_dir = here.parent / "v58-integrated-guest/stage-combined"
base = base_dir / "guest-initramfs.gz"
base_inputs = json.loads((base_dir / "inputs.json").read_text())
template = (here.parent / "v57-usb-candidate/stage-focus/guest-init.sh").read_text()


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def member(name, data, mode, ino):
    encoded = name.encode() + b"\0"
    fields = [ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
    head = b"070701" + b"".join(f"{value:08x}".encode() for value in fields) + encoded
    return head + b"\0" * (-len(head) % 4) + data + b"\0" * (-len(data) % 4)


for mode, binary in [
    ("baseline", Path("outputs/security-key-emulator/bin/linux-arm64/swpasskeyd")),
    ("fixed", here / "linux-build/swpasskeyd"),
]:
    dest = here / ("usb-arbitration-" + mode)
    dest.mkdir(exist_ok=True)
    init = template.replace("SKE_V57_FIDO_RESET_STAGE", "SKE_V61_FIDO_ARBITRATION_" + mode.upper())
    init = init.replace("/opt/verification/verify_fido_reset.py fixed",
                        "/opt/verification/verify_arbitration_usb.py " + mode)
    assert "verify_arbitration_usb.py" in init
    (dest / "guest-init.sh").write_text(init)
    payload = member("init", init.encode(), 0o100755, 990000)
    payload += member("opt/verification/verify_arbitration_usb.py",
                      (here / "verify_arbitration_usb.py").read_bytes(), 0o100644, 990001)
    payload += member("opt/swpasskeyd", binary.read_bytes(), 0o100755, 990002)
    payload += member("TRAILER!!!", b"", 0, 990099)
    image = dest / "guest-initramfs.gz"
    with base.open("rb") as source, image.open("wb") as target:
        while chunk := source.read(1024 * 1024):
            target.write(chunk)
        target.write(gzip.compress(payload, compresslevel=1, mtime=0))
    (dest / "inputs.json").write_text(json.dumps({
        "mode": mode,
        "base_guest_sha256": sha(base),
        "base_guest_inputs_sha256": sha(base_dir / "inputs.json"),
        "base_card_file_sha256": base_inputs.get("card_file_sha256"),
        "base_bridge_sha256": base_inputs.get("linux_binary_sha256", {}).get("ske-usbd"),
        "baseline_published_v60_daemon_sha256": sha("outputs/security-key-emulator/bin/linux-arm64/swpasskeyd"),
        "candidate_v61_daemon_sha256": sha(here / "linux-build/swpasskeyd"),
        "selected_daemon_sha256": sha(binary),
        "source_patch_sha256": sha(here / "source.patch"),
        "probe_sha256": sha(here / "verify_arbitration_usb.py"),
        "guest_image_sha256": sha(image),
        "kernel_sha256": sha(base_dir / "guest-kernel"),
        "guest_network_devices": False,
        "host_usb_passthrough": False,
        "physical_device_access": False,
    }, indent=2) + "\n")
    print(mode, sha(image), sha(binary))
