#!/usr/bin/env python3
"""Create a Linux bundle with notices and checksums. Never publishes or runs its binary."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import subprocess
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parent.parent
TARGETS = {"x86_64-unknown-linux-musl": 62, "aarch64-unknown-linux-musl": 183}


def own_usb_identity():
    profile = (ROOT / "crates/lk-core/src/profile.rs").read_text().split("pub fn own(", 1)[1].split("pub fn ", 1)[0]
    names = {"usb_vendor_id", "otp", "fido", "otp_fido", "ccid", "otp_ccid", "fido_ccid", "otp_fido_ccid"}
    # shortcut: literal fields only; update this reader if the profile starts using constants.
    fields = re.findall(r"\b(" + "|".join(sorted(names)) + r")\s*:\s*(0x[0-9A-Fa-f]+)\b", profile)
    if len(fields) != len(names) or {name for name, _ in fields} != names:
        raise ValueError("own USB identity must contain eight literal identifier fields")
    values = {name: int(value, 16) for name, value in fields}
    if any(value > 0xFFFF for value in values.values()):
        raise ValueError("USB identifiers must fit in 16 bits")
    products = {value for name, value in values.items() if name != "usb_vendor_id"}
    if len(products) != 1:
        raise ValueError("the Linux bundle requires one own PID for all interface combinations")
    return values["usb_vendor_id"], products.pop()


def require_public_identity():
    vendor, product = own_usb_identity()
    if vendor == 0x1209 and product < 0x2000:
        raise ValueError("own profile uses a private-test PID or reserved pid.codes range; only --development is allowed")
    return vendor, product


def validate_binary(binary, target):
    if len(binary) < 64 or binary[:6] != b"\x7fELF\x02\x01":
        raise ValueError("expected a 64-bit little-endian Linux ELF binary")
    if struct.unpack_from("<H", binary, 18)[0] != TARGETS[target]:
        raise ValueError("ELF architecture does not match --target")
    offset = struct.unpack_from("<Q", binary, 32)[0]
    size, count = struct.unpack_from("<HH", binary, 54)
    if size < 56 or not count or offset + size * count > len(binary):
        raise ValueError("invalid ELF program headers")
    for i in range(count):
        if struct.unpack_from("<I", binary, offset + size * i)[0] == 3:
            raise ValueError("binary needs a dynamic loader; build for the static musl target")


def collect_files(binary, target, development, metadata):
    validate_binary(binary, target)
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    vendor, product = own_usb_identity() if development else require_public_identity()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT))
    if dirty and not development:
        raise ValueError("public bundles require a clean committed source tree")
    rustc = subprocess.check_output(["rustc", "--version"], text=True).strip()
    if not rustc.startswith("rustc 1.98.1 "):
        raise ValueError("packaging currently requires Rust 1.98.1; refresh runtime notices when upgrading")
    files = {"bin/localkeyd": (binary, 0o755)}
    for path in ["LICENSE", "NOTICE", "THIRD_PARTY.md"]:
        files[path] = ((ROOT / path).read_bytes(), 0o644)
    files["README.md"] = ((ROOT / "tools/linux/README.md").read_bytes(), 0o644)
    files["install.sh"] = ((ROOT / "tools/linux/install.sh").read_bytes(), 0o755)
    for path in ["localkey-control", "localkey-touch", "localkeyd.service",
                 "localkey-touch.desktop", "org.localkey.control.policy"]:
        files[f"linux/{path}"] = ((ROOT / "tools/linux" / path).read_bytes(),
                                  0o755 if path in {"localkey-control", "localkey-touch"} else 0o644)
    files["linux/70-localkey.rules"] = ((ROOT / "tools/service/70-localkey.rules").read_bytes(), 0o644)
    runtime = Path(subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip()) / "share/doc/rust"
    files["licenses/rust-stdlib/COPYRIGHT-library.html"] = ((runtime / "COPYRIGHT-library.html").read_bytes(), 0o644)
    for path in sorted((runtime / "licenses").glob("*.txt")):
        files[f"licenses/rust-stdlib/licenses/{path.name}"] = (path.read_bytes(), 0o644)
    if "licenses/rust-stdlib/licenses/MIT.txt" not in files:
        raise ValueError("missing Rust standard-library license texts in the selected toolchain")
    files["licenses/musl-1.2.5/COPYRIGHT"] = ((ROOT / "tools/linux/licenses/musl-1.2.5-COPYRIGHT").read_bytes(), 0o644)
    dependencies = []
    for package in sorted(metadata["packages"], key=lambda p: (p["name"], p["version"])):
        if package["source"] is None:
            if package.get("license") != "Apache-2.0":
                raise ValueError(f"workspace crate {package['name']} must inherit Apache-2.0")
            continue
        directory = Path(package["manifest_path"]).parent
        notices = [p for p in sorted(directory.iterdir()) if p.is_file()
                   and p.name.upper().startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE", "AUTHORS"))]
        if not notices:
            raise ValueError(f"missing original license files for {package['name']} {package['version']}")
        for path in notices:
            files[f"licenses/{package['name']}-{package['version']}/{path.name}"] = (path.read_bytes(), 0o644)
        dependencies.append({"name": package["name"], "version": package["version"], "license": package["license"]})
    manifest = {"version": version, "target": target, "development_only": development, "packaging_rustc": rustc,
                "usb_vendor_id": f"{vendor:04x}", "usb_product_id": f"{product:04x}",
                "bundled_musl": "1.2.5",
                "revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                "source_dirty": dirty, "binary_sha256": hashlib.sha256(binary).hexdigest(),
                "dependencies": dependencies}
    files["manifest.json"] = ((json.dumps(manifest, indent=2) + "\n").encode(), 0o644)
    if development:
        files["DEVELOPMENT_ONLY"] = (b"Private testing only. The current own USB PID is not assigned for distribution.\n", 0o644)
    sums = "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, (data, _) in sorted(files.items()))
    files["SHA256SUMS"] = (sums.encode(), 0o644)
    return f"localkey-{version}{'-dev' if development else ''}-{target}", files


def write_archive(path, name, files):
    # Fixed archive metadata; reproducible for identical inputs, including the manifest.
    with path.open("xb") as output, gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
            for relative, (data, mode) in sorted(files.items()):
                entry = tarfile.TarInfo(f"{name}/{relative}")
                entry.size, entry.mode, entry.mtime = len(data), mode, 0
                archive.addfile(entry, io.BytesIO(data))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--target", required=True, choices=TARGETS)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--development", action="store_true", help="private-test bundle, never a public release")
    args = parser.parse_args()
    subprocess.run(["python3", "tools/license_check.py"], cwd=ROOT, check=True)
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--format-version", "1", "--locked", "--offline"], cwd=ROOT))
    name, files = collect_files(args.binary.read_bytes(), args.target, args.development, metadata)
    args.output.mkdir(parents=True, exist_ok=True)
    path = args.output / f"{name}.tar.gz"
    write_archive(path, name, files)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    path.with_suffix(path.suffix + ".sha256").write_text(f"{digest}  {path.name}\n")
    print(path)


if __name__ == "__main__":
    main()
