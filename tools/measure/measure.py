#!/usr/bin/env python3
"""Run probe sets against the engine or the physical key and write raw + redacted runs.

usage:
  measure.py --target engine [--probes SETS] [--out DIR] [--label NAME]
             [--engine-setup fido-pin=PIN] [--engine-setup usb=fido,ccid | usb-enabled=0xNNNN]
             [--wire PATH | --localkeyd PATH [--profile NAME]]
  measure.py --target physical --allow-physical [--probes SETS] [--out DIR] [--label NAME]
  measure.py --list

SETS is a comma list of ccid-basic, ccid-errors, fido-hid, fido-cbor, fido-timing,
fido-presence-timeout, or "all" (every set except the opt-in fido-presence-timeout).

Writes DIR/LABEL-raw.json (every byte; keep it out of the repository) and
DIR/LABEL-redacted.json (normalize.py redaction; the shareable file).
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import platform
import sys
import time
import traceback

import normalize
import probes as probe_catalog
from guard import GuardViolation

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
DEFAULT_LOCALKEYD = os.path.join(REPO, "target", "debug", "localkeyd")


class Context:
    def __init__(self, target, kind):
        self.kind = kind
        if kind == "ccid":
            self.ccid_backend = target.ccid
            self.ccid = probe_catalog.CcidRecorder(self.ccid_backend)
        else:
            self.fido = probe_catalog.FidoRecorder(target.fido)

    @property
    def log(self):
        return self.ccid.log if self.kind == "ccid" else self.fido.log


def expand_sets(text: str) -> list[str]:
    sets = []
    for item in text.split(","):
        item = item.strip()
        if item == "all":
            sets += probe_catalog.DEFAULT_SETS
        elif item:
            sets.append(item)
    return list(dict.fromkeys(sets))


def run_probes(target, selected, progress=True, settle: float = 0.15) -> list[dict]:
    results = []
    for p in selected:
        record = {"set": p.set, "id": p.id, "desc": p.desc, "kind": p.kind, "summary": None, "error": None, "log": []}
        ctx = None
        began = False
        start = time.monotonic()
        try:
            ctx = Context(target, p.kind)
            if p.kind == "ccid":
                ctx.ccid_backend.begin()
                began = True
            record["summary"] = p.fn(ctx)
        except GuardViolation as error:
            record["error"] = f"guard refused: {error}"
        except Exception as error:  # a failing probe must not stop the run
            record["error"] = f"{type(error).__name__}: {error}"
            record["traceback"] = traceback.format_exc(limit=4)
        finally:
            if began:
                try:
                    ctx.ccid_backend.end()
                except Exception as error:
                    record["error"] = (record["error"] or "") + f" (end: {error})"
            if ctx is not None:
                record["log"] = ctx.log
        record["duration_ms"] = round((time.monotonic() - start) * 1000, 1)
        if p.kind == "fido" and settle:
            time.sleep(settle)  # let late packets of this probe arrive before the next drains
        results.append(record)
        if progress:
            status = "ERROR " + record["error"] if record["error"] else "ok"
            print(f"  {p.set:22} {p.id:34} {status}", file=sys.stderr, flush=True)
    return results


def apply_engine_setup(target, items: list[str]) -> list[str]:
    done = []
    for item in items:
        key, _, value = item.partition("=")
        setup = target.setup()
        if key == "fido-pin":
            if not value:
                raise SystemExit("--engine-setup fido-pin needs a PIN")
            setup.set_fido_pin(value)
            done.append("fido-pin=<set>")
        elif key == "usb":
            interfaces = {v.strip() for v in value.split(",") if v.strip()}
            if not interfaces or not interfaces <= {"otp", "fido", "ccid"}:
                raise SystemExit("--engine-setup usb=IFACES takes a comma list of otp, fido, ccid")
            result = setup.set_usb(interfaces=interfaces)
            target.refresh_info()
            done.append(f"usb={','.join(sorted(interfaces))} -> {result['usb_enabled']} ({result['identity_after']['product']})")
        elif key == "usb-enabled":
            result = setup.set_usb(enabled=int(value, 0))
            target.refresh_info()
            done.append(f"usb-enabled={result['usb_enabled']} ({result['identity_after']['product']})")
        else:
            raise SystemExit(f"unknown --engine-setup item {item!r}")
    return done


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", choices=["engine", "physical"])
    parser.add_argument("--probes", default="all")
    parser.add_argument("--out", default=".")
    parser.add_argument("--label")
    parser.add_argument("--engine-setup", action="append", default=[])
    parser.add_argument("--wire", help="attach to a running localkeyd wire socket instead of spawning one")
    parser.add_argument("--localkeyd", default=DEFAULT_LOCALKEYD)
    parser.add_argument("--profile", default="yubikey")
    parser.add_argument("--tmp-base", default=None, help="directory for the spawned daemon's state (short path: sockets are limited to 104 bytes)")
    parser.add_argument("--allow-physical", action="store_true", help="required with --target physical")
    parser.add_argument("--list", action="store_true", help="list the probes per set and exit")
    args = parser.parse_args(argv)

    if args.list:
        for set_name in probe_catalog.ALL_SETS:
            items = [p for p in probe_catalog.PROBES if p.set == set_name]
            print(f"{set_name} ({len(items)})")
            for p in items:
                print(f"  {p.id:34} {p.desc}")
        return 0
    if args.target is None:
        parser.error("--target is required")

    sets = expand_sets(args.probes)
    selected = probe_catalog.select_probes(sets)
    label = args.label or f"{args.target}-{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    os.makedirs(args.out, exist_ok=True)

    daemon = None
    if args.target == "physical":
        if args.engine_setup:
            parser.error("--engine-setup is refused for the physical key")
        if args.wire or args.localkeyd != DEFAULT_LOCALKEYD:
            parser.error("--wire/--localkeyd belong to the engine target")
        if not args.allow_physical:
            parser.error("--target physical needs --allow-physical (read-only probes through the guard)")
        from physical import PhysicalTarget

        target = PhysicalTarget()
    else:
        from engine import Daemon, EngineTarget

        wire = args.wire
        if wire is None:
            daemon = Daemon(args.localkeyd, args.profile, base=args.tmp_base)
            wire = daemon.wire
        target = EngineTarget(wire)

    started = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    meta = {
        "label": label,
        "target": args.target,
        "started_utc": started,
        "sets": sets,
        "setup": [],
        "tool": "tools/measure",
        "python": platform.python_version(),
        "platform": platform.system(),
    }
    try:
        if args.target == "engine":
            meta["setup"] = apply_engine_setup(target, args.engine_setup)
            meta["profile"] = args.profile
        print(f"{label}: {len(selected)} probes in {', '.join(sets)}", file=sys.stderr)
        results = run_probes(target, selected)
        meta["target_info"] = target.info
    finally:
        target.close()
        if daemon is not None:
            meta["localkeyd_exit"] = daemon.stop()
            daemon.cleanup()
    meta["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")

    raw = {"meta": meta, "probes": results}
    raw_path = os.path.join(args.out, f"{label}-raw.json")
    red_path = os.path.join(args.out, f"{label}-redacted.json")
    with open(raw_path, "w") as f:
        json.dump(raw, f, indent=1)
    with open(red_path, "w") as f:
        json.dump(normalize.redact_run(raw), f, indent=1)
    errors = sum(1 for r in results if r["error"])
    print(f"wrote {raw_path} and {red_path} ({len(results)} probes, {errors} with errors)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
