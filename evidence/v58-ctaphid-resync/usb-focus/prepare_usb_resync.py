"""Build two isolated no-NIC dummy_hcd guests from one frozen v58 stage image."""

import gzip
import hashlib
import json
from pathlib import Path

here = Path(__file__).resolve().parent
base_dir = here.parent / "v58-integrated-guest/stage-combined"
base = base_dir / "guest-initramfs.gz"
base_inputs = json.loads((base_dir / "inputs.json").read_text())
stage = here.parent / "security-key-emulator-v58-staging/security-key-emulator"
published = Path("outputs/security-key-emulator")


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


fixture = (stage / "tools/verify_ctap.py").read_text()
assert fixture.count('                "--testing",\n') == 1
fixture = fixture.replace('                "--testing",\n', '')
assert fixture.count('                "SWPASSKEY_LOG": "warn",\n') == 1
fixture = fixture.replace('                "SWPASSKEY_LOG": "warn",\n',
                          '                "SWPASSKEY_LOG": "warn",\n'
                          '                "SWPASSKEY_PRESENCE": "stdin",\n'
                          '                "SWPASSKEY_TESTING": "",\n')
(here / "verify_ctap_presence_wait.py").write_text(fixture)

template = (here.parent / "v57-usb-candidate/stage-focus/guest-init.sh").read_text()
assert "/opt/verification/verify_fido_reset.py fixed" in template

for mode, binary in [
    ("baseline", published / "bin/linux-arm64/swpasskeyd"),
    ("fixed", stage / "bin/linux-arm64/swpasskeyd"),
]:
    dest = here / ("usb-resync-" + mode)
    dest.mkdir(exist_ok=True)
    init = template.replace("SKE_V57_FIDO_RESET_STAGE", "SKE_V58_FIDO_RESYNC_" + mode.upper())
    init = init.replace("/opt/verification/verify_fido_reset.py fixed",
                        "/opt/verification/verify_fido_init_resync_usb.py " + mode)
    (dest / "guest-init.sh").write_text(init)
    payload = member("init", init.encode(), 0o100755, 980000)
    payload += member("opt/verification/verify_ctap.py", fixture.encode(), 0o100644, 980001)
    payload += member("opt/verification/verify_fido_init_resync_usb.py",
                      (here / "verify_fido_init_resync_usb.py").read_bytes(), 0o100644, 980002)
    payload += member("opt/swpasskeyd", binary.read_bytes(), 0o100755, 980003)
    payload += member("TRAILER!!!", b"", 0, 980099)
    image = dest / "guest-initramfs.gz"
    with base.open("rb") as source, image.open("wb") as target:
        while chunk := source.read(1024 * 1024):
            target.write(chunk)
        target.write(gzip.compress(payload, compresslevel=1, mtime=0))
    (dest / "inputs.json").write_text(json.dumps({
        "mode": mode,
        "base_v58_stage_image_sha256": sha(base),
        "base_v58_stage_inputs_sha256": sha(base_dir / "inputs.json"),
        "stage_card_file_sha256": base_inputs.get("card_file_sha256"),
        "stage_bridge_sha256": base_inputs.get("linux_binary_sha256", {}).get("ske-usbd"),
        "baseline_daemon_sha256": sha(published / "bin/linux-arm64/swpasskeyd"),
        "fixed_stage_daemon_sha256": sha(stage / "bin/linux-arm64/swpasskeyd"),
        "selected_daemon_sha256": sha(binary),
        "presence_wait_fixture_sha256": sha(here / "verify_ctap_presence_wait.py"),
        "probe_sha256": sha(here / "verify_fido_init_resync_usb.py"),
        "guest_image_sha256": sha(image),
        "kernel_sha256": sha(base_dir / "guest-kernel"),
        "guest_network_devices": False,
        "host_usb_passthrough": False,
        "physical_device_access": False,
    }, indent=2) + "\n")
    print(mode, sha(image), sha(binary))
