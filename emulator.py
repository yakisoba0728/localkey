#!/usr/bin/env python3
"""Run this software security-key emulator with isolated local state."""

import argparse
import hashlib
import os
import platform
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def platform_binary_dir():
    if sys.platform == "darwin":
        return ROOT / "bin" / "macos-arm64"
    if sys.platform == "linux":
        arch = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "x64"}.get(
            platform.machine()
        )
        if arch:
            return ROOT / "bin" / f"linux-{arch}"
    raise SystemExit("native binaries support macOS ARM64 and Linux ARM64/x64")


def platform_ifd_driver(directory):
    contents = directory / "ifd-ske.bundle" / "Contents"
    if sys.platform == "darwin":
        return contents / "MacOS" / "ske-ifd.dylib"
    return contents / "Linux" / "ske-ifd.so"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("fido", "card", "device"):
        p = commands.add_parser(name)
        p.add_argument("--state-dir", type=Path, default=ROOT / "work" / name)
        p.add_argument(
            "--testing",
            action="store_true",
            help="explicitly simulate user presence for local development",
        )
    test = commands.add_parser("test")
    test.add_argument("--binary-dir", type=Path, default=platform_binary_dir())
    test.add_argument(
        "--legacy-binary",
        type=Path,
        help="optional unmodified v0.2 daemon for migration verification",
    )
    commands.add_parser("build")
    usb = commands.add_parser("usb", help="start native composite USB device")
    usb.add_argument("--card-socket", type=Path, required=True)
    usb.add_argument("--fido-socket", type=Path, required=True)
    usb_fs = usb.add_mutually_exclusive_group()
    usb_fs.add_argument("--gadgetfs", type=Path, help="Linux mounted GadgetFS directory")
    usb_fs.add_argument("--functionfs", type=Path, help="Linux mounted FunctionFS directory")
    usb.add_argument("--configfs-gadget", type=Path, help="Linux prepared unbound ConfigFS gadget for FunctionFS")
    usb.add_argument("--controller", help="Linux USB device controller name")
    usb.add_argument(
        "--yubico-usb-ids",
        action="store_true",
        help="public SDK matching IDs, with software identity labels",
    )
    otp_hid = commands.add_parser(
        "otp-hid", help="start native OTP keyboard/feature device"
    )
    otp_hid.add_argument(
        "--socket", type=Path, required=True, help="running card service socket"
    )
    args = parser.parse_args()
    if args.command == "usb":
        if bool(args.functionfs) != bool(args.configfs_gadget):
            parser.error("--functionfs and --configfs-gadget must be supplied together")
        if args.functionfs and not args.controller:
            parser.error("FunctionFS requires the controller name from /sys/class/udc")
        binary = platform_binary_dir() / "ske-usbd"
        if not binary.exists():
            parser.error("build the native composite USB bridge first")
        command = [
            str(binary),
            "--card-socket",
            str(args.card_socket.resolve()),
            "--fido-socket",
            str(args.fido_socket.resolve()),
        ]
        if args.yubico_usb_ids:
            command.append("--yubico-usb-ids")
        if sys.platform == "linux":
            if args.gadgetfs:
                command.extend(["--gadgetfs", str(args.gadgetfs.resolve())])
            if args.functionfs:
                command.extend(["--functionfs", str(args.functionfs.resolve()),
                                "--configfs-gadget", str(args.configfs_gadget.resolve())])
            if args.controller:
                command.extend(["--controller", args.controller])
        elif args.gadgetfs or args.functionfs or args.configfs_gadget or args.controller:
            parser.error("USB filesystem and controller options require Linux")
        os.execv(str(binary), command)
        return
    if args.command == "otp-hid":
        binary = platform_binary_dir() / "ske-otpd"
        if not binary.exists():
            parser.error("build the native OTP bridge first")
        os.execv(str(binary), [str(binary), "--socket", str(args.socket.resolve())])
    if args.command == "build":
        build = ROOT / "work" / "build"
        subprocess.run(
            [
                "uv",
                "run",
                "--no-project",
                "--with",
                "cmake",
                "--with",
                "ninja",
                "cmake",
                "-S",
                str(ROOT / "source"),
                "-B",
                str(build),
                "-G",
                "Ninja",
                "-DCMAKE_BUILD_TYPE=Debug",
                "-DSWPASSKEY_TPM=OFF",
            ],
            check=True,
        )
        subprocess.run(
            [
                "uv",
                "run",
                "--no-project",
                "--with",
                "cmake",
                "--with",
                "ninja",
                "cmake",
                "--build",
                str(build),
            ],
            check=True,
        )
        print(f"Built {build}. Run tests with --binary-dir {build}.")
        return
    if args.command == "test":
        args.binary_dir = args.binary_dir.resolve()
        if args.legacy_binary:
            args.legacy_binary = args.legacy_binary.resolve()
        scratch = tempfile.TemporaryDirectory(prefix="ske-checks-", dir="/tmp")
        work = Path(scratch.name)
        reports = ROOT / "results"
        reports.mkdir(exist_ok=True)
        tests = [
            [str(args.binary_dir / "swpasskey_tests"), "--reporter", "compact"],
            [
                sys.executable,
                str(ROOT / "tools" / "verify_ctap.py"),
                "--binary",
                str(args.binary_dir / "swpasskeyd"),
                "--work-dir",
                str(work),
                "--report",
                str(reports / "ctap.json"),
            ],
            [
                sys.executable,
                str(ROOT / "tools" / "verify_smartcard.py"),
                "--work-dir",
                str(work),
                "--report",
                str(reports / "smartcard.json"),
            ],
            [
                sys.executable,
                str(ROOT / "tools" / "verify_buttons.py"),
                "--report",
                str(reports / "buttons.json"),
            ],
            [
                sys.executable,
                str(ROOT / "tools" / "verify_otp_hmac_boundary.py"),
                "--report",
                str(reports / "otp_hmac_boundary.json"),
            ],
            [
                sys.executable,
                str(ROOT / "tools" / "verify_otp_dual_slot_timing.py"),
                "--report",
                str(reports / "otp_dual_slot_timing.json"),
            ],
        ]
        for name in (
            "domain",
            "domain_profile",
            "domain_metadata",
            "domain_versions",
            "domain_cache",
            "domain_scp11c",
            "domain_shared",
            "domain_handoff",
            "domain_pso",
            "domain_plaintext",
            "domain_allowlist",
            "pgp_extensions",
            "pgp_s2k_short_count",
            "pgp_objects",
            "pgp_algorithms",
            "pgp_attestation",
            "piv_storage",
            "piv_cert_boundary",
            "piv_profile",
            "oath_profile",
        ):
            tests.append(
                [
                    sys.executable,
                    str(ROOT / "tools" / f"verify_{name}.py"),
                    "--work-dir",
                    str(work),
                    "--report",
                    str(reports / f"{name}.json"),
                ]
            )
        tests.extend(
            [
                [
                    sys.executable,
                    str(ROOT / "evidence" / "v56-ctap-options" / "verify_unknown_options.py"),
                    "--binary", str(args.binary_dir / "swpasskeyd"),
                    "--report", str(reports / "ctap_unknown_options.json"),
                    "--expect-fixed",
                ],
                [
                    sys.executable,
                    str(ROOT / "tools" / "verify_piv_f9_delete.py"),
                    "--root", str(ROOT),
                    "--report", str(reports / "piv_f9_delete.json"),
                    "--expect-fixed",
                ],
            ]
        )
        tests.append(
            [
                sys.executable,
                str(ROOT / "tools" / "verify_pgp_apdu_headers.py"),
                "--root",
                str(ROOT),
                "--expect",
                "fixed",
                "--report",
                str(reports / "pgp_apdu_headers.json"),
            ]
        )
        tests.append(
            [
                sys.executable,
                str(ROOT / "tools" / "verify_launchers.py"),
                "--work-dir",
                str(work),
                "--report",
                str(reports / "launchers.json"),
            ]
        )
        for name in ("reference_profile", "nonresident"):
            tests.append(
                [
                    sys.executable,
                    str(ROOT / "tools" / f"verify_{name}.py"),
                    "--binary",
                    str(args.binary_dir / "swpasskeyd"),
                    "--work-dir",
                    str(work),
                    "--report",
                    str(reports / f"{name}.json"),
                ]
            )
        ifd_driver = platform_ifd_driver(args.binary_dir)
        if ifd_driver.exists():
            tests.append(
                [
                    sys.executable,
                    str(ROOT / "tools" / "verify_piv_f9_delete.py"),
                    "--root", str(ROOT),
                    "--ifd", str(ifd_driver),
                    "--report", str(reports / "ifd_piv_f9_delete.json"),
                    "--expect-fixed",
                ]
            )
            for name in (
                "domain",
                "domain_profile",
                "domain_metadata",
                "domain_versions",
                "domain_cache",
                "domain_scp11c",
                "domain_shared",
                "domain_handoff",
                "domain_pso",
                "domain_plaintext",
                "domain_allowlist",
            ):
                tests.append(
                    [
                        sys.executable,
                        str(ROOT / "tools" / f"verify_{name}.py"),
                        "--ifd-driver",
                        str(ifd_driver),
                        "--work-dir",
                        str(work),
                        "--report",
                        str(reports / f"ifd_{name}.json"),
                    ]
                )
            tests.extend(
                [
                    [
                        sys.executable,
                        str(ROOT / "tools" / "verify_ifd.py"),
                        "--driver",
                        str(ifd_driver),
                        "--work-dir",
                        str(work),
                        "--report",
                        str(reports / "ifd.json"),
                    ],
                    [
                        sys.executable,
                        str(ROOT / "tools" / "verify_smartcard.py"),
                        "--ifd-driver",
                        str(ifd_driver),
                        "--work-dir",
                        str(work),
                        "--report",
                        str(reports / "ifd_smartcard.json"),
                    ],
                    [
                        sys.executable,
                        str(ROOT / "tools" / "verify_piv_profile.py"),
                        "--ifd-driver",
                        str(ifd_driver),
                        "--work-dir",
                        str(work),
                        "--report",
                        str(reports / "ifd_piv_profile.json"),
                    ],
                    [
                        sys.executable,
                        str(ROOT / "tools" / "verify_oath_profile.py"),
                        "--ifd-driver",
                        str(ifd_driver),
                        "--work-dir",
                        str(work),
                        "--report",
                        str(reports / "ifd_oath_profile.json"),
                    ],
                    [
                        sys.executable,
                        str(ROOT / "tools" / "verify_pgp_s2k_short_count.py"),
                        "--ifd-driver",
                        str(ifd_driver),
                        "--work-dir",
                        str(work),
                        "--report",
                        str(reports / "ifd_pgp_s2k_short_count.json"),
                    ],
                    [
                        sys.executable,
                        str(ROOT / "tools" / "verify_pgp_apdu_headers.py"),
                        "--root",
                        str(ROOT),
                        "--expect",
                        "fixed",
                        "--ifd-driver",
                        str(ifd_driver),
                        "--report",
                        str(reports / "ifd_pgp_apdu_headers.json"),
                    ],
                    [
                        sys.executable,
                        str(ROOT / "tools" / "verify_pgp_objects.py"),
                        "--ifd-driver",
                        str(ifd_driver),
                        "--work-dir",
                        str(work),
                        "--report",
                        str(reports / "ifd_pgp_objects.json"),
                    ],
                    [
                        sys.executable,
                        str(ROOT / "tools" / "verify_pgp_algorithms.py"),
                        "--ifd-driver",
                        str(ifd_driver),
                        "--work-dir",
                        str(work),
                        "--report",
                        str(reports / "ifd_pgp_algorithms.json"),
                    ],
                    [
                        sys.executable,
                        str(ROOT / "tools" / "verify_pgp_attestation.py"),
                        "--ifd-driver",
                        str(ifd_driver),
                        "--work-dir",
                        str(work),
                        "--report",
                        str(reports / "ifd_pgp_attestation.json"),
                    ],
                ]
            )
        tests.append(
            [
                sys.executable,
                str(ROOT / "tools" / "verify_composite.py"),
                "--binary",
                str(args.binary_dir / "swpasskeyd"),
                "--work-dir",
                str(work),
                "--report",
                str(reports / "composite.json"),
            ]
        )
        if (args.binary_dir / "ske-otpd").exists():
            tests.append(
                [
                    sys.executable,
                    str(ROOT / "tools" / "verify_keyboard_bridge.py"),
                    "--binary",
                    str(args.binary_dir / "ske-otpd"),
                    "--work-dir",
                    str(work),
                    "--report",
                    str(reports / "keyboard_bridge.json"),
                ]
            )
        if (args.binary_dir / "ske-usbd").exists():
            tests.append(
                [
                    sys.executable,
                    str(ROOT / "tools" / "verify_usb_reboot.py"),
                    "--binary",
                    str(args.binary_dir / "ske-usbd"),
                    "--fido-binary",
                    str(args.binary_dir / "swpasskeyd"),
                    "--work-dir",
                    str(work),
                    "--report",
                    str(reports / "usb_reboot.json"),
                ]
            )
            tests.append(
                [
                    sys.executable,
                    str(ROOT / "tools" / "verify_usb_bridge.py"),
                    "--binary",
                    str(args.binary_dir / "ske-usbd"),
                    "--fido-binary",
                    str(args.binary_dir / "swpasskeyd"),
                    "--work-dir",
                    str(work),
                    "--report",
                    str(reports / "usb_bridge.json"),
                ]
            )
            tests.append(
                [
                    sys.executable,
                    str(ROOT / "tools" / "verify_ccid.py"),
                    "--binary",
                    str(args.binary_dir / "ske-usbd"),
                    "--fido-binary",
                    str(args.binary_dir / "swpasskeyd"),
                    "--work-dir",
                    str(work),
                    "--report",
                    str(reports / "ccid.json"),
                ]
            )
            if (
                args.binary_dir / "ifd-ske.bundle/Contents/MacOS/ske-ifd.dylib"
            ).exists():
                tests.append(
                    [
                        sys.executable,
                        str(ROOT / "tools" / "verify_ccid_chaining.py"),
                        "--binary",
                        str(args.binary_dir / "ske-usbd"),
                        "--fido-binary",
                        str(args.binary_dir / "swpasskeyd"),
                        "--driver",
                        str(
                            args.binary_dir
                            / "ifd-ske.bundle/Contents/MacOS/ske-ifd.dylib"
                        ),
                        "--work-dir",
                        str(work),
                        "--report",
                        str(reports / "ccid_chaining.json"),
                    ]
                )
        if args.legacy_binary:
            tests.append(
                [
                    sys.executable,
                    str(ROOT / "tools" / "verify_migration.py"),
                    "--legacy-binary",
                    str(args.legacy_binary),
                    "--binary",
                    str(args.binary_dir / "swpasskeyd"),
                    "--work-dir",
                    str(work),
                    "--report",
                    str(reports / "migration.json"),
                ]
            )
        try:
            for command in tests:
                if Path(command[0]).name == "swpasskey_tests":
                    log_path = reports / "unit-test-result.txt"
                    with log_path.open("w") as log:
                        subprocess.run(
                            command,
                            check=True,
                            cwd=ROOT,
                            stdout=log,
                            stderr=subprocess.STDOUT,
                            env={**os.environ, "SWPASSKEY_LOG": "warn"},
                        )
                    print(f"C++ tests passed: {log_path}", flush=True)
                else:
                    subprocess.run(command, check=True, cwd=ROOT)
        finally:
            scratch.cleanup()
        print(f"All checks passed. Reports: {reports}")
        return
    directory = args.state_dir.resolve()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    # macOS Unix socket paths are limited to 104 bytes; state may live elsewhere.
    transport_dir = Path(tempfile.gettempdir()) / (
        "ske-" + hashlib.sha256(os.fsencode(directory)).hexdigest()[:10]
    )
    transport_dir.mkdir(mode=0o700, exist_ok=True)
    if (
        transport_dir.stat().st_uid != os.getuid()
        or transport_dir.stat().st_mode & 0o077
    ):
        parser.error("transport directory is not private to this user")
    socket_path = transport_dir / "device.sock"
    if len(os.fsencode(socket_path)) > 103:
        parser.error(
            "temporary directory is too long for a macOS Unix socket; choose a shorter TMPDIR"
        )
    if args.command == "device":
        print(f"device state: {directory}", flush=True)
        card_socket, fido_socket = (
            transport_dir / "card.sock",
            transport_dir / "fido.sock",
        )
        binary = platform_binary_dir() / "swpasskeyd"
        if not binary.exists():
            parser.error("build the FIDO daemon first")
        card_command = [
            sys.executable,
            "-m",
            "emucard.service",
            "--state",
            str(directory / "card.bin"),
            "--socket",
            str(card_socket),
        ]
        fido_command = [
            str(binary),
            "--dek-file",
            "--key-backend=software",
            "--store",
            str(directory / "credentials.bin"),
            "--ctl-socket",
            str(transport_dir / "ctl.sock"),
        ]
        if args.testing:
            card_command.append("--testing")
            fido_command.append("--testing")
        processes = []

        def stop_device(*_):
            raise KeyboardInterrupt

        previous = signal.signal(signal.SIGTERM, stop_device)
        try:
            card_process = subprocess.Popen(card_command, cwd=ROOT)
            processes.append(card_process)
            for _ in range(100):
                if card_process.poll() is not None:
                    raise RuntimeError("shared card service failed to start")
                if card_socket.is_socket():
                    break
                time.sleep(0.05)
            else:
                raise RuntimeError("shared card service did not create its socket")
            fido_process = subprocess.Popen(
                fido_command,
                env={
                    **os.environ,
                    "SWPASSKEY_HID_SOCKET": str(fido_socket),
                    "SWPASSKEY_CARD_SOCKET": str(card_socket),
                    "SWPASSKEY_PRESENCE": "stdin",
                },
                cwd=ROOT,
            )
            processes.append(fido_process)
            print(
                f"shared CCID/OTP socket: {card_socket}\nshared-profile FIDO socket: {fido_socket}",
                flush=True,
            )
            while all(p.poll() is None for p in processes):
                time.sleep(0.2)
            raise RuntimeError("an emulator component exited; shutting down the device")
        except KeyboardInterrupt:
            pass
        finally:
            signal.signal(signal.SIGTERM, previous)
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        return
    print(f"{args.command} socket: {socket_path}", flush=True)
    if args.command == "card":
        command = [
            sys.executable,
            "-m",
            "emucard.service",
            "--state",
            str(directory / "card.bin"),
            "--socket",
            str(socket_path),
        ]
        if args.testing:
            command.append("--testing")
        os.chdir(ROOT)
        os.execv(sys.executable, command)
    binary = platform_binary_dir() / "swpasskeyd"
    if not binary.exists():
        parser.error("build the source or use the included binary for this platform")
    command = [
        str(binary),
        "--dek-file",
        "--key-backend=software",
        "--store",
        str(directory / "credentials.bin"),
        "--ctl-socket",
        str(transport_dir / "ctl.sock"),
    ]
    if args.testing:
        command.append("--testing")
    os.environ["SWPASSKEY_HID_SOCKET"] = str(socket_path)
    os.environ["SWPASSKEY_PRESENCE"] = "stdin"
    os.execv(str(binary), command)


if __name__ == "__main__":
    main()
