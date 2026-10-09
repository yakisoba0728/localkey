"""Re-extract v0.64 and execute representative public software flows."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile
from pathlib import Path


base = Path(__file__).resolve().parent.parent
archive = base / "work/security-key-emulator-v64-staging/security-key-emulator.zip"
dest = base / "work/security-key-emulator-v64-reextracted"
root = dest / "security-key-emulator"
reports = base / "work/v64-reextract-validation"
python = base / "outputs/security-key-emulator/.venv/bin/python"


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def run(name: str, argv: list[str], env: dict[str, str] | None = None):
    with (reports / f"{name}.log").open("w") as log:
        subprocess.run(argv, check=True, cwd=root, env=env,
                       stdout=log, stderr=subprocess.STDOUT)


assert archive.is_file() and not dest.exists()
reports.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(archive) as packed:
    assert packed.testzip() is None
    assert all(name.startswith("security-key-emulator/") and ".." not in Path(name).parts
               for name in packed.namelist())
    packed.extractall(dest)
    for member in packed.infolist():
        mode = stat.S_IMODE(member.external_attr >> 16)
        if mode and not member.is_dir():
            (dest / member.filename).chmod(mode)
manifest = json.loads((root / "manifest.json").read_text())
assert manifest["version"] == "0.64.0"
assert manifest["complete_yubikey_equivalence"] is False
assert not (root / ".venv").exists()
for name, info in manifest["files"].items():
    path = root / name
    assert path.stat().st_size == info["size"], name
    assert digest(path) == info["sha256"], name
assert len(manifest["files"]) + 1 == json.loads((archive.parent / "package-result.json").read_text())["files"]

run("cpp", [str(root / "bin/macos-arm64/swpasskey_tests"), "--reporter", "compact"])
match = re.search(r"(\d+) assertions in (\d+) test cases", (reports / "cpp.log").read_text())
assert match and tuple(map(int, match.groups())) == (13748, 140)

with tempfile.TemporaryDirectory(prefix="ske62-extracted-", dir="/tmp") as temporary:
    run("ctap", [str(python), str(root / "tools/verify_ctap.py"),
                 "--binary", str(root / "bin/macos-arm64/swpasskeyd"),
                 "--work-dir", temporary, "--report", str(reports / "ctap.json")])
ctap = json.loads((reports / "ctap.json").read_text())
assert ctap["passed"] and len(ctap["tests"]) == 82

run("fido-cancel", [str(python),
     str(root / "evidence/v62-fido-cancel-u2f/verify_cancel_u2f_socket.py"),
     str(root / "bin/macos-arm64/swpasskeyd"), "fixed",
     str(reports / "fido-cancel.json")])
fido = json.loads((reports / "fido-cancel.json").read_text())
assert fido["passed"] and fido["u2f_status_hex"] == "9000" and fido["fresh_ping_ok"]

run("fido-same-cid", [str(python),
    str(root / "evidence/v64-fido-same-cid/verify_same_cid_socket.py"),
    str(root / "bin/macos-arm64/swpasskeyd"), "fixed",
    str(reports / "fido-same-cid.json")])
same_cid = json.loads((reports / "fido-same-cid.json").read_text())
assert same_cid["passed"]
assert bytes.fromhex(same_cid["same_cid_ping_reply_hex"])[4] == 0xbf
assert bytes.fromhex(same_cid["same_cid_wink_reply_hex"])[4] == 0xbf

env = {**os.environ, "SKE_TOOLS_DIR": str(root / "tools")}
run("largeblob", [str(python),
     str(root / "evidence/v62-ctap-largeblob-sequence/verify_sequence.py"),
     str(root / "bin/macos-arm64/swpasskeyd")], env)
blob = json.loads((reports / "largeblob.log").read_text())
assert blob["bad_offset_without_auth"] == blob["resume_after_unauthenticated_restart"] == 4
assert blob["stored_after_finish"] == blob["stored_at_end"]

for route in ("socket", "ifd"):
    piv = [str(python),
           str(root / "evidence/v62-piv-generate-p1/verify_piv_generate_p1.py"),
           "--root", str(root), "--fixed", "--report", str(reports / f"piv-{route}.json")]
    if route == "ifd":
        piv += ["--ifd", str(root / "bin/macos-arm64/ifd-ske.bundle/Contents/MacOS/ske-ifd.dylib")]
    run(f"piv-{route}", piv)
    report = json.loads((reports / f"piv-{route}.json").read_text())
    assert report["passed"] and report["core_sha256"] == digest(root / "emucard/core.py")
    assert len(report["rows"]) == 2 and all(row["malformed_sw"] == "6a86"
                                            for row in report["rows"])

    auth = [str(python),
            str(root / "evidence/v63-piv-auth-le/verify_piv_auth_le.py"),
            "--root", str(root), "--fixed", "--report", str(reports / f"piv-auth-{route}.json")]
    if route == "ifd":
        auth += ["--ifd", str(root / "bin/macos-arm64/ifd-ske.bundle/Contents/MacOS/ske-ifd.dylib")]
    run(f"piv-auth-{route}", auth)
    auth_report = json.loads((reports / f"piv-auth-{route}.json").read_text())
    assert auth_report["passed"] and auth_report["fixed"]
    assert auth_report["core_sha256"] == digest(root / "emucard/core.py")
    assert auth_report["malformed_sw"] == "6700"
    assert auth_report["normal_sdk_after_malformed"] == "9000"

    scp03 = [str(python),
        str(root / "evidence/v64-scp03-init-le/verify_scp03_init_le.py"),
        "--root", str(root), "--fixed", "--report", str(reports / f"scp03-{route}.json")]
    if route == "ifd":
        scp03 += ["--ifd", str(root / "bin/macos-arm64/ifd-ske.bundle/Contents/MacOS/ske-ifd.dylib")]
    run(f"scp03-{route}", scp03)
    scp03_report = json.loads((reports / f"scp03-{route}.json").read_text())
    assert scp03_report["passed"] and scp03_report["fixed"]
    assert scp03_report["malformed_sw"] == "6700"
    assert scp03_report["retries_after_malformed"] == 64
    assert scp03_report["domain_sha256"] == digest(root / "emucard/domain.py")

with tempfile.TemporaryDirectory(prefix="ske64-hsmauth-extract-", dir="/tmp") as temporary:
    fixture = Path(temporary)
    shutil.copy2(root / "evidence/v64-hsmauth-challenge/verify_hsmauth_challenge_touch.py",
                 fixture / "verify_hsmauth_challenge_touch.py")
    (fixture / "fixed").symlink_to(root, target_is_directory=True)
    for route in ("socket", "ifd"):
        command = [str(python), str(fixture / "verify_hsmauth_challenge_touch.py"),
                   "--variant", "fixed", "--platform", "mac",
                   "--result", str(reports / f"hsmauth-{route}.json")]
        if route == "ifd":
            command += ["--ifd-driver", str(root / "bin/macos-arm64/ifd-ske.bundle/Contents/MacOS/ske-ifd.dylib")]
        run(f"hsmauth-{route}", command)
        item = json.loads((reports / f"hsmauth-{route}.json").read_text())
        assert item["passed"] and item["core_sha256"] == digest(root / "emucard/core.py")
        assert item["results"][0]["touch_required_challenge_sw"] == "9000"
        assert item["results"][0]["touch_required_calculate_sw"] == "6985"

with tempfile.TemporaryDirectory(prefix="ske62-oath-extract-", dir="/tmp") as temporary:
    oath_fixture = Path(temporary)
    shutil.copy2(root / "evidence/v62-oath-auth-binding/verify_oath_auth_binding.py",
                 oath_fixture / "verify_oath_auth_binding.py")
    (oath_fixture / "fixed").symlink_to(root, target_is_directory=True)
    for route in ("socket", "ifd"):
        argv = [str(python), str(oath_fixture / "verify_oath_auth_binding.py"),
                "--variant", "fixed", "--platform", "mac",
                "--result", str(reports / f"oath-{route}.json")]
        if route == "ifd":
            argv += ["--ifd-driver", str(root / "bin/macos-arm64/ifd-ske.bundle/Contents/MacOS/ske-ifd.dylib")]
        run(f"oath-{route}", argv)
        report = json.loads((reports / f"oath-{route}.json").read_text())
        assert report["passed"] and report["core_sha256"] == digest(root / "emucard/core.py")
        assert all(row["stale_client_sw"] == "6982" for row in report["phases"])
        assert all(row["status"] == "6982" for row in report["continuations"])

release = json.loads((root / "evidence/v64-integration/result.json").read_text())
assert release["passed"] and release["main_check_count"] == 6029
assert release["mac_daemon_sha256"] == digest(root / "bin/macos-arm64/swpasskeyd")
assert release["linux_daemon_sha256"] == digest(root / "bin/linux-arm64/swpasskeyd")
result = {"passed": True, "version": "0.64.0", "archive_sha256": digest(archive),
          "manifest_files_verified": len(manifest["files"]),
          "cpp_cases": 140, "cpp_assertions": 13748,
          "ctap_sdk_checks": 82,
          "fido_cancel": True, "fido_same_cid": True, "largeblob_sequence": True,
          "piv_socket_ifd": True, "piv_auth_le_socket_ifd": True,
          "scp03_socket_ifd": True, "hsmauth_socket_ifd": True,
          "oath_socket_ifd": True,
          "physical_or_host_device_access": False}
(reports / "result.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result, indent=2))
