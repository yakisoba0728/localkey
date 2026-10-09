"""Verify the integrated v0.64 release and create its reproducible archive."""

from __future__ import annotations

import datetime
import hashlib
import json
import zipfile
from pathlib import Path


base = Path(__file__).resolve().parent
root = base / "security-key-emulator-v64-staging/security-key-emulator"
integration = root / "evidence/v64-integration"


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def read(path: Path):
    return json.loads(path.read_text())


def write(path: Path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


status = read(root / "implementation-status.json")
matrix = read(root / "compatibility-matrix.json")
manifest = read(root / "manifest.json")
assert status["version"] == matrix["version"] == manifest["version"] == "0.63.0"
assert not any(item["complete_yubikey_equivalence"] for item in (status, matrix, manifest))
assert not (root / ".venv").exists()
for name in ("CONTINUE_HERE.md", "docs/PROGRESS_HISTORY.md", "docs/EVIDENCE_INDEX.md",
             "docs/OPEN_GAPS.md", "docs/REPRODUCE_VALIDATION.md"):
    assert (root / name).is_file(), name

patches = {
    "v64-fido-same-cid/source.patch": "5a6c155bef6ba47f277bf36474644c45e035b852a6b6f87d915be6385b162933",
    "v64-fido-same-cid/tests.patch": "582a1459ea8a7be4441f3c0032d90a345f40844d041613aed2bdd9358b033220",
    "v64-hsmauth-challenge/source.patch": "6a8e7b7528f96eb8b0f5911d917acd0d05a1cb6c6e9979e194e37953f4080f9c",
    "v64-scp03-init-le/source.patch": "8ed1102893412b93a531957fc8c9bfd4a2118010f81c361279614e913f3c5247",
}
for name, expected in patches.items():
    assert sha(root / "evidence" / name) == expected, name

report = read(integration / "result.json")
assert report["passed"] and report["version"] == "0.64.0"
assert report["main_python_reports"] == 59 and report["main_python_checks"] == 5889
assert report["cpp_cases_each_platform"] == 140
assert report["cpp_assertions_each_platform"] == 13748
assert report["main_check_count"] == 6029
assert report["linux_ctap_sdk_checks"] == 82
assert report["usb_guest_exit_markers"] == 12
assert report["usb_guest_retry_success_after_first_failure"]
assert report["fido_same_cid_mac_linux_socket_and_usb"]
assert report["hsmauth_scp03_piv_mac_linux_socket_and_ifd"]
assert report["core_sha256"] == sha(root / "emucard/core.py")
assert report["domain_sha256"] == sha(root / "emucard/domain.py")
assert report["fido_source_sha256"] == sha(root / "source/src/ctap/hid_device.cpp")
assert not report["physical_reference_differential"]
assert not report["apple_entitled_registration"]
assert "All checks passed." in (integration / "main-test.log").read_text()
for platform in ("mac", "linux"):
    assert "13748 assertions in 140 test cases" in (integration / f"unit-{platform}.log").read_text()
    assert report[f"{platform}_daemon_sha256"] == sha(root / "bin" / ("macos-arm64" if platform == "mac" else "linux-arm64") / "swpasskeyd")

guest_root = integration / "guest"
guest = read(guest_root / "result.json")
assert guest["passed"] and len(guest["exit_markers"]) == 12
assert guest["inputs_sha256"] == sha(guest_root / "inputs.json")
assert guest["raw_console_sha256"] == sha(guest_root / "console.log")
assert guest["raw_console_sha256"] == report["guest_raw_console_sha256"]
assert guest["retry_success_after_first_failure"]
assert guest["first_attempt"]["passed"] is False
assert guest["first_attempt"]["console_sha256"] == sha(guest_root / "attempt1/console.log")
assert guest["first_attempt"]["run_sha256"] == sha(guest_root / "attempt1/run.json")
assert guest["backend_source_sha256"] == sha(root / "source/src/usb/backend.hpp")
for name, expected in guest["card_file_sha256"].items():
    assert sha(root / "emucard" / name) == expected, name
for name, expected in guest["linux_binary_sha256"].items():
    assert sha(root / "bin/linux-arm64" / name) == expected, name
assert not guest["guest_network_devices"] and not guest["host_usb_passthrough"]
assert not guest["physical_device_access"] and not guest["kernel_panic_observed"]

fido = read(root / "evidence/v64-fido-same-cid/validation.json")
assert fido["passed"] and fido["owned_no_nic_usb"]["fixed"]["passed"]
for platform in ("mac", "linux"):
    fixed = read(root / "evidence/v64-fido-same-cid" / f"{platform}-fixed.json")
    assert fixed["passed"]
hsmauth = read(root / "evidence/v64-hsmauth-challenge/validation.json")
assert len(hsmauth["ab"]) == 4 and not hsmauth["exact_physical_5_7_4_behavior_verified"]
scp03 = read(root / "evidence/v64-scp03-init-le/evidence.json")
assert scp03["regression_checks"] == 4004 and not scp03["firmware_5_7_4_differential"]

checks = {}
for path in sorted((root / "results").glob("*.json")):
    item = read(path)
    if "tests" in item:
        assert item["passed"], path.name
        checks[str(path.relative_to(root))] = len(item["tests"])
assert len(checks) == 59 and sum(checks.values()) == 5889
ctap = read(integration / "ctap-linux.json")
assert ctap["passed"] and len(ctap["tests"]) == 82

now = datetime.datetime.now(datetime.timezone.utc).isoformat()
scope = {
    "fido_same_cid_transaction_atomicity": True,
    "hsmauth_symmetric_challenge_without_touch": True,
    "scp03_initialize_update_le_guard": True,
    "mac_linux_socket_ifd_and_owned_usb_verified": True,
    "main_regression_checks": 6029,
    "cpp_cases": 140,
    "cpp_assertions": 13748,
    "no_nic_combined_guest_exit_markers": 12,
    "initial_guest_attempt_failed_then_identical_image_passed": True,
    "physical_firmware_differential_verified": False,
    "macos_entitled_composite_registration_verified": False,
    "evidence": ["evidence/v64-fido-same-cid", "evidence/v64-hsmauth-challenge",
                 "evidence/v64-scp03-init-le", "evidence/v64-integration"],
}
status.update(version="0.64.0", updated_utc=now, cpp_unit_tests=140,
              cpp_assertions=13748, total_main_checks=6029,
              checks=list(checks), complete_yubikey_equivalence=False)
status["implemented_and_verified"]["FIDO"].append(
    "A processing CTAPHID CID rejects an interleaved PING or WINK with CHANNEL_BUSY, while INIT resynchronization, CANCEL, original completion and idle PING remain functional; Mac/Linux private socket and owned no-NIC USB A/B pass. Physical error byte remains unmeasured.")
status["implemented_and_verified"]["YubiHSMAuth"].append(
    "YubiHSM Auth symmetric GET CHALLENGE returns an eight-byte host challenge without touch; CALCULATE still requires touch. Unmodified YubiKit Mac/Linux socket/direct IFD checks pass; physical timing remains unmeasured.")
status["implemented_and_verified"]["SCP03"].append(
    "INITIALIZE UPDATE rejects a non-maximum explicit Le before resetting a session or decrementing authentication retries; an absent or maximum Le and unmodified YubiKit secure-channel exchange pass on Mac/Linux socket/direct IFD. Physical status remains unmeasured.")
status["remaining_work"].append(
    "Version 0.64 adds three protocol/state boundaries. The integrated no-NIC guest passed 12/12 on an identical-image retry after a first 10/12 run failed with a Linux workqueue/FunctionFS warning; repeated transport stability and root cause remain open. Physical YubiKey 5C Nano 5.7.4 differential, real touch/power timing, production USB and external hosts, Apple-entitled macOS registration, manufacturer attestation trust, and secure-element properties remain unverified or unavailable.")
status["v64_fido_hsmauth_scp03"] = scope
write(root / "implementation-status.json", status)

matrix["version"] = "0.64.0"
matrix["complete_yubikey_equivalence"] = False
for name in ("fido_same_cid_transaction", "hsmauth_symmetric_challenge_touch", "scp03_initialize_update_le"):
    matrix["criteria"].append({"id": name,
        "status": "Mac_Linux_software_and_owned_USB_as_applicable_verified; physical_5_7_4_unmeasured",
        "evidence": "evidence/v64-integration/result.json"})
write(root / "compatibility-matrix.json", matrix)

linux = read(root / "linux-build-result.json")
linux.update(package_version="0.64.0", cpp_cases=140, cpp_assertions=13748,
             linux_daemon_sha256=sha(root / "bin/linux-arm64/swpasskeyd"),
             linux_test_binary_sha256=sha(root / "bin/linux-arm64/swpasskey_tests"),
             linux_test_log_sha256=sha(integration / "unit-linux.log"))
write(root / "linux-build-result.json", linux)

start = root / "START_HERE.txt"
start.write_text(
    "소프트웨어 보안키 에뮬레이터 0.64.0 프로토콜 단계\n\n"
    "FIDO 동일 CID 거래 중 PING/WINK 중첩을 차단하고, YubiHSM Auth의\n"
    "대칭형 챌린지 생성과 터치 사용을 분리하며, SCP03 INITIALIZE UPDATE의\n"
    "잘못된 Le가 인증 재시도를 소모하지 않도록 수정했습니다. Mac/Linux\n"
    "C++ 각 140사례·13,748 assertion, 주 회귀 6,029항목, 네트워크 없는\n"
    "USB 게스트 12개 종료 마커를 검증했습니다. 실물 5.7.4, 물리 터치,\n"
    "첫 게스트 실행은 커널 경고 후 10/12 실패했고 동일 이미지 재실행은\n"
    "12/12 통과했습니다. 안정성 원인은 아직 확정되지 않았습니다.\n"
    "외부 호스트, macOS 권한 등록과 제조사 신뢰는 아직 검증하지 못했습니다.\n"
    "자세한 기록은 implementation-status.json과 evidence/v64-integration에 있습니다.\n\n"
    "0.63 및 이전 기록 — 아래는 해당 버전의 역사적 범위입니다.\n\n"
    + start.read_text())

manifest.update(version="0.64.0", generated_utc=now,
    modified_binaries="Mac/Linux FIDO daemons and C++ tests rebuild the same-CID CTAPHID transaction guard; Python card modules add YubiHSM Auth challenge/touch and SCP03 INITIALIZE UPDATE Le guards. Physical firmware equivalence and entitled macOS registration remain unverified.",
    cpp_tests={"passed": True, "cases": 140, "assertions": 13748},
    independent_checks=checks, total_main_checks=6029,
    remaining_work=status["remaining_work"],
    v64_fido_hsmauth_scp03=scope,
    complete_yubikey_equivalence=False)
ignored = {".venv", "work", "__pycache__", ".git", "build", ".ruff_cache", ".pytest_cache", ".mypy_cache"}
files = [p for p in root.rglob("*") if p.is_file() and not set(p.relative_to(root).parts) & ignored
         and p.suffix != ".pyc" and p.name not in {"manifest.json", ".DS_Store"}]
manifest["files"] = {str(p.relative_to(root)): {"size": p.stat().st_size, "sha256": sha(p)} for p in sorted(files)}
write(root / "manifest.json", manifest)

archive = root.parent / "security-key-emulator.zip"
with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as packed:
    for p in sorted(files + [root / "manifest.json"]):
        packed.write(p, "security-key-emulator/" + str(p.relative_to(root)))
with zipfile.ZipFile(archive) as packed:
    assert packed.testzip() is None
    assert len(packed.namelist()) == len(files) + 1
    for name, expected in manifest["files"].items():
        h = hashlib.sha256()
        with packed.open("security-key-emulator/" + name) as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                h.update(block)
        assert h.hexdigest() == expected["sha256"], name
archive_hash = sha(archive)
(root.parent / "security-key-emulator.zip.sha256").write_text(archive_hash + "  security-key-emulator.zip\n")
write(root.parent / "package-result.json", {"version": "0.64.0", "files": len(files) + 1,
    "sha256": archive_hash, "checks": 6029, "integrity_verified": True})
print(json.dumps(read(root.parent / "package-result.json"), indent=2))
