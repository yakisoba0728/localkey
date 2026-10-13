#!/usr/bin/env python3
"""Require a clean version tag on main and an upstream-assigned own USB identity."""
import argparse
import re
import subprocess
import tomllib
import urllib.request

import package_linux

ROOT = package_linux.ROOT
SOURCE = "https://github.com/yakisoba0728/localkey"


def check_release(tag):
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    if tag != f"v{version}":
        raise ValueError("release tag must match the workspace version")
    vendor, product = package_linux.require_public_identity()
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    tagged = subprocess.check_output(["git", "rev-parse", f"refs/tags/{tag}^{{commit}}"], cwd=ROOT, text=True).strip()
    if tagged != head:
        raise ValueError("checkout must be the exact release tag commit")
    subprocess.run(["git", "merge-base", "--is-ancestor", head, "origin/main"], cwd=ROOT, check=True)
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT):
        raise ValueError("release source tree must be clean")
    if vendor != 0x1209:
        raise ValueError("this release process requires a pid.codes allocation")
    url = f"https://raw.githubusercontent.com/pidcodes/pidcodes.github.com/master/{vendor:04X}/{product:04X}/index.md"
    with urllib.request.urlopen(url, timeout=30) as response:
        page = response.read(65536).decode("utf-8")
    header = page.split("---", 2)
    if len(header) != 3 or header[0].strip():
        raise ValueError("invalid upstream PID page")
    fields = dict(re.findall(r"^([a-z]+):\s*(.*?)\s*$", header[1], re.MULTILINE))
    if fields.get("owner") != "localkey" or fields.get("source") != SOURCE:
        raise ValueError("upstream PID must be assigned to localkey and this source repository")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag")
    check_release(parser.parse_args().tag)
