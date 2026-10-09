"""Seal hashes and counts of the complete v0.64 staged validation."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


base = Path(__file__).resolve().parent.parent
root = base / "work/security-key-emulator-v64-staging/security-key-emulator"
evidence = root / "evidence/v64-integration"


def read(path: Path):
    return json.loads(path.read_text())


def sha(path: Path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


build = read(evidence / "build/result.json")
assert build["passed"] and build["source_unchanged_after_build"]
assert build["platforms"]["macos-arm64"]["cpp_test_cases"] == 140
assert build["platforms"]["linux-arm64"]["cpp_test_cases"] == 140
assert build["platforms"]["macos-arm64"]["cpp_assertions"] == 13748
assert build["platforms"]["linux-arm64"]["cpp_assertions"] == 13748
assert build["platforms"]["linux-arm64"]["python_fido2_checks"] == 82
for name, expected in build["installed_files"].items():
    assert sha(root / name) == expected, name
assert "13748 assertions in 140 test cases" in (evidence / "unit-mac.log").read_text()
assert "13748 assertions in 140 test cases" in (evidence / "unit-linux.log").read_text()
assert "All checks passed." in (evidence / "main-test.log").read_text()
assert read(evidence / "ctap-linux.json")["passed"]
assert len(read(evidence / "ctap-linux.json")["tests"]) == 82

cards = read(evidence / "cards/validation.json")
assert cards["passed"] and cards["focused_passed"] == 12
assert cards["smartcard_checks_passed"] == 388
assert cards["rebuilt_ifd_focused_passed"] == 6
assert cards["rebuilt_ifd_smartcard_checks_passed"] == 194
assert cards["stage_sha256_rebuilt"]["emucard/core.py"] == sha(root / "emucard/core.py")
assert not cards["exact_physical_firmware_5_7_4_equivalence_verified"]

for platform in ("mac", "linux"):
    fido = read(evidence / f"fido/{platform}.json")
    assert fido["passed"] and fido["mode"] == "fixed"
    for command in ("ping", "wink"):
        packet = bytes.fromhex(fido[f"same_cid_{command}_reply_hex"])
        assert packet[4] == 0xBF and packet[7] == 0x06

guest = read(evidence / "guest/result.json")
assert guest["passed"] and len(guest["exit_markers"]) == 12
assert guest["retry_success_after_first_failure"]
assert guest["first_attempt"]["passed"] is False
assert guest["first_attempt"]["console_sha256"] == sha(evidence / "guest/attempt1/console.log")
assert guest["first_attempt"]["run_sha256"] == sha(evidence / "guest/attempt1/run.json")
assert guest["raw_console_sha256"] == sha(evidence / "guest/console.log")
assert guest["inputs_sha256"] == sha(evidence / "guest/inputs.json")
assert not guest["guest_network_devices"] and not guest["host_usb_passthrough"]
assert not guest["physical_device_access"] and not guest["kernel_panic_observed"]

checks = [read(path) for path in (root / "results").glob("*.json")]
checks = [item for item in checks if "tests" in item]
assert len(checks) == 59 and all(item["passed"] for item in checks)
assert sum(len(item["tests"]) for item in checks) == 5889

result = {
    "passed": True,
    "version": "0.64.0",
    "main_python_reports": 59,
    "main_python_checks": 5889,
    "cpp_cases_each_platform": 140,
    "cpp_assertions_each_platform": 13748,
    "main_check_count": 6029,
    "linux_ctap_sdk_checks": 82,
    "usb_guest_exit_markers": 12,
    "usb_guest_retry_success_after_first_failure": True,
    "fido_same_cid_mac_linux_socket_and_usb": True,
    "hsmauth_scp03_piv_mac_linux_socket_and_ifd": True,
    "core_sha256": sha(root / "emucard/core.py"),
    "domain_sha256": sha(root / "emucard/domain.py"),
    "fido_source_sha256": sha(root / "source/src/ctap/hid_device.cpp"),
    "mac_daemon_sha256": sha(root / "bin/macos-arm64/swpasskeyd"),
    "linux_daemon_sha256": sha(root / "bin/linux-arm64/swpasskeyd"),
    "guest_raw_console_sha256": guest["raw_console_sha256"],
    "physical_reference_differential": False,
    "apple_entitled_registration": False,
    "host_or_physical_device_access": False,
}
(evidence / "result.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result, indent=2))
