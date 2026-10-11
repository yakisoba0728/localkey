"""The probe catalog. Every probe goes through a target's guarded backend.

A probe gets a context with `ctx.ccid` (a CcidRecorder) or `ctx.fido` (a FidoRecorder),
which log every exchange with timestamps for the raw file; the probe returns a summary of
plain values (status codes, counts, lengths, timings in ms). Summaries never carry
response bytes; normalize.py renders the logged bytes with redaction.

Sets: ccid-basic, ccid-errors, fido-hid, fido-cbor, fido-timing, and the opt-in
fido-presence-timeout.
"""

from __future__ import annotations

import os
import statistics
import struct
import time
from dataclasses import dataclass
from typing import Callable

import cbor
from guard import GuardViolation
from common import (
    BROADCAST,
    CMD_NAMES,
    CONT_DATA,
    CTAP_STATUS,
    HID_ERRORS,
    INIT_DATA,
    MAX_PAYLOAD,
    Cmd,
    apdu,
    cont_packet,
    fragment,
    init_packet,
    parse_packet,
    select,
)

DEFAULT_SETS = ["ccid-basic", "ccid-errors", "fido-hid", "fido-cbor", "fido-timing"]
OPT_IN_SETS = ["fido-presence-timeout"]
ALL_SETS = DEFAULT_SETS + OPT_IN_SETS


@dataclass
class Probe:
    set: str
    id: str
    desc: str
    kind: str  # "ccid" or "fido"
    fn: Callable


PROBES: list[Probe] = []


def probe(set_name: str, probe_id: str, desc: str, kind: str):
    def register(fn):
        PROBES.append(Probe(set_name, probe_id, desc, kind, fn))
        return fn

    return register


def add(set_name, probe_id, desc, kind, fn):
    PROBES.append(Probe(set_name, probe_id, desc, kind, fn))


# --- recorders --------------------------------------------------------------------------


class CcidRecorder:
    def __init__(self, ccid):
        self.ccid = ccid
        self.log: list[dict] = []
        self.applet: str | None = None

    def tx(self, command: bytes, note: str | None = None) -> tuple[bytes, int]:
        """Send one APDU. A transport failure (the host's PC/SC refusing a malformed
        command, or a reply without a status word) is recorded as the observation with
        sw 0, and the applet is selected again so the rest of the probe still runs (the
        guard forgets the selection after a failure). A GuardViolation is never caught."""
        start = time.monotonic()
        try:
            data, sw = self.ccid.transmit(command)
        except GuardViolation:
            raise
        except Exception as error:
            entry = {"apdu": command.hex(), "data": "", "sw": "none", "error": f"{type(error).__name__}: {error}", "ms": round((time.monotonic() - start) * 1000, 3)}
            if note:
                entry["note"] = note
            self.log.append(entry)
            if self.applet is not None and command[1:2] != b"\xa4":
                self.select(self.applet)
            return b"", 0
        entry = {"apdu": command.hex(), "data": data.hex(), "sw": f"{sw:04X}", "ms": round((time.monotonic() - start) * 1000, 3)}
        if note:
            entry["note"] = note
        self.log.append(entry)
        return data, sw

    def select(self, applet: str, p2: int = 0x00):
        self.applet = applet
        return self.tx(select(SELECT_AIDS[applet], p2))

    def select_ok(self, applet: str) -> bool:
        """SELECT the applet; False if it did not answer 9000/61xx (then the probe stops,
        and the guard would refuse the applet's commands anyway)."""
        _, sw = self.select(applet)
        return sw == 0x9000 or sw >> 8 == 0x61

    def chain(self, command: bytes, limit: int = 16) -> tuple[bytes, int, int]:
        """Send and follow 61xx with GET RESPONSE; return (data, final sw, parts)."""
        data, sw = self.tx(command)
        parts = 1
        while sw >> 8 == 0x61 and parts < limit:
            more, sw = self.tx(apdu(0x00, 0xC0, 0x00, 0x00, le=sw & 0xFF))
            data += more
            parts += 1
        return data, sw, parts


class FidoRecorder:
    def __init__(self, fido):
        self.fido = fido
        self.log: list[dict] = []
        fido.drain()
        self.t0 = time.monotonic()
        self.last_keepalives: list = []

    def ms(self, t: float) -> float:
        return round((t - self.t0) * 1000, 3)

    def send(self, pkt: bytes) -> float:
        t = self.fido.send_packet(pkt)
        self.log.append({"t": self.ms(t), "dir": "out", "pkt": pkt.hex()})
        return t

    def send_msg(self, cid: int, command: int, payload: bytes = b"") -> float:
        t = self.fido.send_message(cid, command, payload)
        for pkt in fragment(cid, command, payload):
            self.log.append({"t": self.ms(t), "dir": "out", "pkt": pkt.hex()})
        return t

    def recv(self, timeout: float):
        item = self.fido.recv_packet(timeout)
        if item is not None:
            t, pkt = item
            self.log.append({"t": self.ms(t), "dir": "in", "pkt": bytes(pkt).hex()})
            return t, bytes(pkt)
        return None

    def listen(self, duration: float) -> list[tuple[float, dict]]:
        """Every packet that arrives within `duration` seconds."""
        out = []
        deadline = time.monotonic() + duration
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return out
            item = self.recv(left)
            if item is not None:
                out.append((item[0], parse_packet(item[1])))

    def wait_message(self, cid: int, timeout: float):
        """Wait for one complete message on `cid` (KEEPALIVE packets are collected).

        Returns {"cmd", "payload", "t", "keepalives": [(t, status)]} or None on timeout
        (then "keepalives" of the partial wait are in self.last_keepalives).
        """
        keepalives = []
        deadline = time.monotonic() + timeout
        msg = None
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                self.last_keepalives = keepalives
                return None
            item = self.recv(left)
            if item is None:
                continue
            t, pkt = item
            p = parse_packet(pkt)
            if p["cid"] != cid:
                continue
            if msg is None:
                if not p["init"]:
                    continue
                if p["cmd"] == Cmd.KEEPALIVE:
                    keepalives.append((t, p["data"][0]))
                    continue
                msg = {"cmd": p["cmd"], "bcnt": p["bcnt"], "payload": p["data"][: p["bcnt"]], "t": t, "seq": 0}
            else:
                if p["init"] or p["seq"] != msg["seq"]:
                    msg["broken"] = True
                    break
                msg["seq"] += 1
                msg["payload"] += p["data"][: msg["bcnt"] - len(msg["payload"])]
                msg["t"] = t
            if len(msg["payload"]) >= msg["bcnt"]:
                break
        msg["keepalives"] = keepalives
        self.last_keepalives = keepalives
        return msg

    def init_channel(self, timeout: float = 2.0) -> int:
        nonce = os.urandom(8)
        self.send_msg(BROADCAST, Cmd.INIT, nonce)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            msg = self.wait_message(BROADCAST, deadline - time.monotonic())
            if msg is None:
                break
            if msg["cmd"] == Cmd.INIT and msg["payload"][:8] == nonce:
                return struct.unpack(">I", msg["payload"][8:12])[0]
            if msg["cmd"] == Cmd.ERROR:
                raise ProbeError(f"INIT answered ERROR {msg['payload'][:1].hex()}")
        raise ProbeError("no INIT reply")

    def exchange(self, cid: int, command: int, payload: bytes = b"", timeout: float = 5.0):
        self.send_msg(cid, command, payload)
        return self.wait_message(cid, timeout)


class ProbeError(Exception):
    pass


# --- describing replies (plain values only) ------------------------------------------------


def describe(msg) -> dict:
    if msg is None:
        return {"reply": None}
    name = CMD_NAMES.get(msg["cmd"], f"0x{msg['cmd']:02X}")
    out = {"reply": name, "len": len(msg["payload"])}
    if msg["cmd"] == Cmd.ERROR and msg["payload"]:
        code = msg["payload"][0]
        out["code"] = f"0x{code:02X} {HID_ERRORS.get(code, '?')}"
    if msg["cmd"] == Cmd.CBOR and msg["payload"]:
        status = msg["payload"][0]
        out["status"] = f"0x{status:02X} {CTAP_STATUS.get(status, '?')}"
        if len(msg["payload"]) > 1:
            try:
                body = cbor.decode(msg["payload"][1:])
                out["keys"] = sorted(body) if isinstance(body, dict) else type(body).__name__
            except cbor.CborError as error:
                out["cbor_error"] = str(error)
    if msg["cmd"] == Cmd.MSG and len(msg["payload"]) >= 2:
        out["sw"] = msg["payload"][-2:].hex().upper()
    if msg.get("broken"):
        out["broken"] = True
    return out


def interval_stats(times: list[float]) -> dict:
    if len(times) < 2:
        return {"count": len(times)}
    gaps = [(b - a) * 1000 for a, b in zip(times, times[1:])]
    return {
        "count": len(times),
        "interval_mean_ms": round(statistics.mean(gaps), 2),
        "interval_min_ms": round(min(gaps), 2),
        "interval_max_ms": round(max(gaps), 2),
        "interval_stdev_ms": round(statistics.pstdev(gaps), 2),
    }


def ms_between(a: float, b: float) -> float:
    return round((b - a) * 1000, 2)


def pattern(n: int, seed: int = 0) -> bytes:
    return bytes((i * 7 + seed) & 0xFF for i in range(n))


# --- CCID: ccid-basic -----------------------------------------------------------------------

APPLETS = ["mgmt", "otp", "oath", "piv", "openpgp", "hsmauth", "sd"]
# The AIDs yubikit sends (yubikit.core.smartcard.AID); each starts with the guard's AID.
SELECT_AIDS = {
    "mgmt": bytes.fromhex("A000000527471117"),
    "otp": bytes.fromhex("A0000005272001"),
    "oath": bytes.fromhex("A0000005272101"),
    "piv": bytes.fromhex("A000000308"),
    "openpgp": bytes.fromhex("D27600012401"),
    "hsmauth": bytes.fromhex("A000000527210701"),
    "sd": bytes.fromhex("A000000151000000"),
}
UNKNOWN_AID = bytes.fromhex("A0000005279999")


def ccid_summary(rec: CcidRecorder) -> dict:
    return {"sw": [entry["sw"] for entry in rec.log], "len": [len(entry["data"]) // 2 for entry in rec.log]}


@probe("ccid-basic", "atr", "ATR (PC/SC ATR / IccPowerOn)", "ccid")
def p_atr(ctx):
    return {"atr": ctx.ccid_backend.atr().hex().upper()}


def _select_probe(applet):
    def fn(ctx):
        ctx.ccid.select(applet)
        return ccid_summary(ctx.ccid)

    return fn


for _applet in APPLETS:
    add("ccid-basic", f"select-{_applet}", f"SELECT {_applet} ({SELECT_AIDS[_applet].hex().upper()})", "ccid", _select_probe(_applet))


@probe("ccid-basic", "select-unknown", "SELECT of an unassigned AID A0000005279999", "ccid")
def p_select_unknown(ctx):
    ctx.ccid.tx(select(UNKNOWN_AID))
    return ccid_summary(ctx.ccid)


def skipped(rec) -> dict:
    return dict(ccid_summary(rec), skipped="SELECT failed")


def _seq_probe(applet, commands):
    def fn(ctx):
        if not ctx.ccid.select_ok(applet):
            return skipped(ctx.ccid)
        for command in commands:
            ctx.ccid.tx(command)
        return ccid_summary(ctx.ccid)

    return fn


def _chain_probe(applet, command):
    def fn(ctx):
        if not ctx.ccid.select_ok(applet):
            return skipped(ctx.ccid)
        data, sw, parts = ctx.ccid.chain(command)
        summary = ccid_summary(ctx.ccid)
        summary.update({"total_len": len(data), "final_sw": f"{sw:04X}", "parts": parts})
        return summary

    return fn


add("ccid-basic", "mgmt-read-config", "Management READ CONFIG pages 0 and 1", "ccid", _seq_probe("mgmt", [apdu(0, 0x1D, 0, 0), apdu(0, 0x1D, 1, 0)]))
add("ccid-basic", "otp-serial", "OTP applet INS 01 P1 10 (serial)", "ccid", _seq_probe("otp", [apdu(0, 0x01, 0x10, 0)]))
add("ccid-basic", "otp-capabilities", "OTP applet INS 01 P1 13 (capabilities)", "ccid", _seq_probe("otp", [apdu(0, 0x01, 0x13, 0)]))
add("ccid-basic", "piv-version", "PIV GET VERSION (FD)", "ccid", _seq_probe("piv", [apdu(0, 0xFD, 0, 0)]))
add("ccid-basic", "piv-serial", "PIV GET SERIAL (F8)", "ccid", _seq_probe("piv", [apdu(0, 0xF8, 0, 0)]))
add("ccid-basic", "piv-discovery", "PIV GET DATA discovery object 7E", "ccid", _chain_probe("piv", apdu(0, 0xCB, 0x3F, 0xFF, bytes.fromhex("5C017E"))))
add("ccid-basic", "piv-chuid", "PIV GET DATA CHUID 5FC102", "ccid", _chain_probe("piv", apdu(0, 0xCB, 0x3F, 0xFF, bytes.fromhex("5C035FC102"))))
add("ccid-basic", "piv-ccc", "PIV GET DATA CCC 5FC107", "ccid", _chain_probe("piv", apdu(0, 0xCB, 0x3F, 0xFF, bytes.fromhex("5C035FC107"))))
for _p2 in (0x80, 0x81, 0x9B, 0x9A, 0x9C, 0x9D, 0x9E):
    add("ccid-basic", f"piv-metadata-{_p2:02x}", f"PIV GET METADATA key {_p2:02X}", "ccid", _seq_probe("piv", [apdu(0, 0xF7, 0, _p2)]))
add("ccid-basic", "piv-verify-status-80", "PIV VERIFY PIN status (no data)", "ccid", _seq_probe("piv", [apdu(0, 0x20, 0, 0x80)]))
add("ccid-basic", "piv-verify-status-81", "PIV VERIFY P2 81 status (no data)", "ccid", _seq_probe("piv", [apdu(0, 0x20, 0, 0x81)]))
for _do in (0x006E, 0x0065, 0x007A, 0x00C4, 0x5F52, 0x7F74, 0x004F):
    add("ccid-basic", f"openpgp-get-{_do:04x}", f"OpenPGP GET DATA {_do:04X} (61xx followed)", "ccid", _chain_probe("openpgp", apdu(0, 0xCA, _do >> 8, _do & 0xFF)))
for _p2 in (0x81, 0x82, 0x83):
    add("ccid-basic", f"openpgp-verify-status-{_p2:02x}", f"OpenPGP VERIFY PW status {_p2:02X} (no data)", "ccid", _seq_probe("openpgp", [apdu(0, 0x20, 0, _p2)]))
for _tag in (0x00E0, 0x0066, 0x9F7F):
    add("ccid-basic", f"sd-get-{_tag:04x}", f"Security Domain GET DATA {_tag:04X}", "ccid", _chain_probe("sd", apdu(0, 0xCA, _tag >> 8, _tag & 0xFF)))


# --- CCID: ccid-errors ----------------------------------------------------------------------

for _applet in APPLETS:
    add("ccid-errors", f"undefined-ins-{_applet}", f"{_applet}: undefined INS 5E, 6E, 93", "ccid", _seq_probe(_applet, [apdu(0, ins, 0, 0) for ins in (0x5E, 0x6E, 0x93)]))

READS = {
    "mgmt": (apdu(0, 0x1D, 0, 0), lambda cla: apdu(cla, 0x1D, 0, 0)),
    "otp": (apdu(0, 0x01, 0x10, 0), lambda cla: apdu(cla, 0x01, 0x10, 0)),
    "piv": (apdu(0, 0xCB, 0x3F, 0xFF, bytes.fromhex("5C017E")), lambda cla: apdu(cla, 0xCB, 0x3F, 0xFF, bytes.fromhex("5C017E"))),
    "openpgp": (apdu(0, 0xCA, 0x00, 0xC4), lambda cla: apdu(cla, 0xCA, 0x00, 0xC4)),
    "sd": (apdu(0, 0xCA, 0x00, 0x66), lambda cla: apdu(cla, 0xCA, 0x00, 0x66)),
}
AFTER_CHAIN = {"piv": apdu(0, 0xFD, 0, 0)}


def _cla_probe(applet):
    def fn(ctx):
        rec = ctx.ccid
        if not rec.select_ok(applet):
            return skipped(rec)
        if applet in READS:
            plain, with_cla = READS[applet]
            rec.tx(with_cla(0x80), "CLA 80")
            rec.tx(with_cla(0x0C), "CLA 0C")
            rec.tx(with_cla(0x10), "CLA 10 (chain left open)")
            rec.tx(AFTER_CHAIN.get(applet, apdu(0, 0xC0, 0, 0, le=0)), "other INS while the chain is open")
            if not rec.select_ok(applet):
                return skipped(rec)
            rec.tx(plain, "plain read after reselect")
        else:
            rec.tx(apdu(0x80, 0x5E, 0, 0), "CLA 80, undefined INS")
            rec.tx(apdu(0x0C, 0x5E, 0, 0), "CLA 0C, undefined INS")
        return ccid_summary(rec)

    return fn


for _applet in APPLETS:
    add("ccid-errors", f"cla-variants-{_applet}", f"{_applet}: CLA 80, 0C, 10 on an admitted INS", "ccid", _cla_probe(_applet))

PIV_DISC = bytes.fromhex("5C017E")
add("ccid-errors", "bad-p1p2-mgmt", "READ CONFIG with P2 01, P1 FF, P1 02", "ccid", _seq_probe("mgmt", [apdu(0, 0x1D, 0, 1), apdu(0, 0x1D, 0xFF, 0), apdu(0, 0x1D, 2, 0)]))
add("ccid-errors", "bad-p1p2-otp", "OTP INS 01 P1 10 with P2 01", "ccid", _seq_probe("otp", [apdu(0, 0x01, 0x10, 1)]))
add("ccid-errors", "bad-p1p2-piv", "PIV GET DATA P1P2 3FFE/0000, GET VERSION P1 01, GET SERIAL P2 01, GET METADATA P1 01", "ccid", _seq_probe("piv", [apdu(0, 0xCB, 0x3F, 0xFE, PIV_DISC), apdu(0, 0xCB, 0, 0, PIV_DISC), apdu(0, 0xFD, 1, 0), apdu(0, 0xF8, 0, 1), apdu(0, 0xF7, 1, 0x9A)]))
add("ccid-errors", "bad-p1p2-openpgp", "OpenPGP GET DATA P1P2 0000 and 3FFF", "ccid", _seq_probe("openpgp", [apdu(0, 0xCA, 0, 0), apdu(0, 0xCA, 0x3F, 0xFF)]))
add("ccid-errors", "bad-p1p2-sd", "Security Domain GET DATA P1P2 0000 and 3FFF", "ccid", _seq_probe("sd", [apdu(0, 0xCA, 0, 0), apdu(0, 0xCA, 0x3F, 0xFF)]))

_H = bytes.fromhex
add("ccid-errors", "lc-le-piv-get-data", "PIV GET DATA 7E: Le 00, extended 4E and 3E, Lc too long, Lc too short, Le 01", "ccid", _seq_probe("piv", [
    _H("00CB3FFF035C017E00"),
    _H("00CB3FFF0000035C017E0000"),
    _H("00CB3FFF0000035C017E"),
    _H("00CB3FFF055C017E"),
    _H("00CB3FFF025C017E"),
    _H("00CB3FFF035C017E01"),
]))
add("ccid-errors", "lc-le-piv-version", "PIV GET VERSION: Le 00, extended Le, Le 01", "ccid", _seq_probe("piv", [_H("00FD000000"), _H("00FD0000000000"), _H("00FD000001")]))
add("ccid-errors", "lc-le-mgmt", "READ CONFIG: Le 00, Le 01, extended Le, Lc 1 with one data byte", "ccid", _seq_probe("mgmt", [_H("001D000000"), _H("001D000001"), _H("001D0000000000"), _H("001D00000100")]))
add("ccid-errors", "lc-le-openpgp", "OpenPGP GET DATA C4: Le 00, Le 03, extended Le, Le FF", "ccid", _seq_probe("openpgp", [_H("00CA00C400"), _H("00CA00C403"), _H("00CA00C4000000"), _H("00CA00C4FF")]))
add("ccid-errors", "lc-le-sd", "Security Domain GET DATA 66: Le 00, extended Le", "ccid", _seq_probe("sd", [_H("00CA006600"), _H("00CA0066000000")]))
add("ccid-errors", "lc-le-otp", "OTP INS 01 P1 10: Le 00, Le 04", "ccid", _seq_probe("otp", [_H("0001100000"), _H("0001100004")]))

for _applet in APPLETS:
    add("ccid-errors", f"get-response-idle-{_applet}", f"{_applet}: GET RESPONSE with nothing pending", "ccid", _seq_probe(_applet, [apdu(0, 0xC0, 0, 0, le=0)]))


@probe("ccid-errors", "select-odd-p2", "SELECT PIV with P2 04 (FCP), 0C (no data), 02 (next), 01 (last); Management with Le", "ccid")
def p_select_odd(ctx):
    rec = ctx.ccid
    for p2 in (0x04, 0x0C, 0x02, 0x01):
        rec.tx(select(SELECT_AIDS["piv"], p2), f"P2 {p2:02X}")
    rec.tx(apdu(0, 0xA4, 0x04, 0x00, SELECT_AIDS["mgmt"], le=0), "with Le 00")
    return ccid_summary(rec)


@probe("ccid-errors", "select-partial-aid", "SELECT by partial AIDs A0000005, A000000527, A0000003, D276000124, A0000005272107 (HSM Auth without its last byte)", "ccid")
def p_select_partial(ctx):
    rec = ctx.ccid
    for aid in ("A0000005", "A000000527", "A0000003", "D276000124", "A0000005272107"):
        rec.tx(select(bytes.fromhex(aid)), aid)
    return ccid_summary(rec)


@probe("ccid-errors", "chain-61xx", "OpenPGP 6E with Le 00, GET RESPONSE Le 10 mid-chain, rest, then one more GET RESPONSE", "ccid")
def p_chain(ctx):
    rec = ctx.ccid
    if not rec.select_ok("openpgp"):
        return skipped(rec)
    data, sw = rec.tx(_H("00CA006E00"))
    total = len(data)
    parts = 1
    if sw >> 8 == 0x61:
        more, sw = rec.tx(apdu(0, 0xC0, 0, 0, le=0x10), "partial GET RESPONSE")
        total += len(more)
        parts += 1
        while sw >> 8 == 0x61 and parts < 16:
            more, sw = rec.tx(apdu(0, 0xC0, 0, 0, le=sw & 0xFF))
            total += len(more)
            parts += 1
    rec.tx(apdu(0, 0xC0, 0, 0, le=0), "after the chain")
    summary = ccid_summary(rec)
    summary.update({"total_len": total, "parts": parts})
    return summary


add("ccid-errors", "chain-extended-le", "OpenPGP 6E with extended Le 0000 (no 61xx expected)", "ccid", _seq_probe("openpgp", [_H("00CA006E000000")]))
add("ccid-errors", "chain-piv-chuid-le10", "PIV CHUID with Le 10", "ccid", _seq_probe("piv", [_H("00CB3FFF055C035FC10210")]))


# --- FIDO: fido-hid -------------------------------------------------------------------------


@probe("fido-hid", "init-broadcast", "CTAPHID_INIT on the broadcast CID", "fido")
def p_init(ctx):
    rec = ctx.fido
    nonce = os.urandom(8)
    t = rec.send_msg(BROADCAST, Cmd.INIT, nonce)
    msg = rec.wait_message(BROADCAST, 2)
    out = describe(msg)
    if msg and msg["cmd"] == Cmd.INIT:
        payload = msg["payload"]
        out.update({
            "nonce_ok": payload[:8] == nonce,
            "cid_nonzero": payload[8:12] not in (b"\0\0\0\0", b"\xff\xff\xff\xff"),
            "protocol": payload[12],
            "device_version": ".".join(str(b) for b in payload[13:16]),
            "capabilities": f"0x{payload[16]:02X}",
            "rtt_ms": ms_between(t, msg["t"]),
        })
    return out


@probe("fido-hid", "init-channel", "CTAPHID_INIT on an allocated CID (resynchronisation) and a second broadcast INIT", "fido")
def p_init_channel(ctx):
    rec = ctx.fido
    cid = rec.init_channel()
    nonce = os.urandom(8)
    msg = rec.exchange(cid, Cmd.INIT, nonce, 2)
    out = {"resync": describe(msg)}
    if msg and msg["cmd"] == Cmd.INIT:
        out["resync"]["same_cid"] = struct.unpack(">I", msg["payload"][8:12])[0] == cid
        out["resync"]["nonce_ok"] = msg["payload"][:8] == nonce
    second = rec.init_channel()
    out["second_broadcast_distinct"] = second != cid
    return out


def _ping_probe(size):
    def fn(ctx):
        rec = ctx.fido
        cid = rec.init_channel()
        payload = pattern(size)
        t = rec.send_msg(cid, Cmd.PING, payload)
        msg = rec.wait_message(cid, 5)
        out = describe(msg)
        if msg and msg["cmd"] == Cmd.PING:
            out["echo_ok"] = msg["payload"] == payload
            out["rtt_ms"] = ms_between(t, msg["t"])
        return out

    return fn


for _size in (0, 1, 57, 58, 7609):
    add("fido-hid", f"ping-{_size}", f"PING with {_size} bytes", "fido", _ping_probe(_size))


def _oversize_probe(bcnt):
    def fn(ctx):
        rec = ctx.fido
        cid = rec.init_channel()
        rec.send(init_packet(cid, Cmd.PING, bcnt, pattern(INIT_DATA)))
        msg = rec.wait_message(cid, 1.0)
        out = describe(msg)
        if msg is None:
            out["resync"] = describe(rec.exchange(cid, Cmd.INIT, os.urandom(8), 2))
        return out

    return fn


add("fido-hid", "ping-7610", "PING init with BCNT 7610 (one over the maximum); continuations never sent", "fido", _oversize_probe(7610))
add("fido-hid", "ping-bcnt-ffff", "PING init with BCNT 0xFFFF", "fido", _oversize_probe(0xFFFF))


def _ping_max(ctx):
    """The longest PING the device echoes: bisect between 57 and 7609 bytes. A length the
    device refuses is answered INVALID_LEN at the init packet, before any continuation."""
    rec = ctx.fido
    cid = rec.init_channel()

    def accepted(n: int) -> bool:
        msg = rec.exchange(cid, Cmd.PING, bytes(n), 5)
        if msg is None:
            resync(rec, cid)
            return False
        return msg["cmd"] == Cmd.PING and len(msg["payload"]) == n

    lo, hi = 57, MAX_PAYLOAD
    if accepted(hi):
        return {"max_ping": hi}
    if not accepted(lo):
        return {"max_ping": None}
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if accepted(mid):
            lo = mid
        else:
            hi = mid
    return {"max_ping": lo, "first_refused": hi}


add("fido-hid", "ping-max", "longest PING echoed (bisection)", "fido", _ping_max)


@probe("fido-hid", "wink", "CTAPHID_WINK", "fido")
def p_wink(ctx):
    rec = ctx.fido
    cid = rec.init_channel()
    return describe(rec.exchange(cid, Cmd.WINK, b"", 2))


@probe("fido-hid", "cancel-idle", "CTAPHID_CANCEL on an idle channel, then PING", "fido")
def p_cancel_idle(ctx):
    rec = ctx.fido
    cid = rec.init_channel()
    rec.send(init_packet(cid, Cmd.CANCEL, 0))
    replies = rec.listen(0.5)
    return {"replies_to_cancel": [describe_packet(p) for _, p in replies], "ping_after": describe(rec.exchange(cid, Cmd.PING, b"ok", 2))}


def describe_packet(p: dict) -> dict:
    if p["init"]:
        out = {"init": CMD_NAMES.get(p["cmd"], f"0x{p['cmd']:02X}"), "bcnt": p["bcnt"]}
        if p["cmd"] == Cmd.ERROR:
            out["code"] = f"0x{p['data'][0]:02X} {HID_ERRORS.get(p['data'][0], '?')}"
        return out
    return {"cont": p["seq"]}


def _invalid_cmd_probe(command):
    def fn(ctx):
        rec = ctx.fido
        cid = rec.init_channel()
        rec.send(init_packet(cid, command, 0))
        return describe(rec.wait_message(cid, 1.0))

    return fn


add("fido-hid", "invalid-cmd-3f", "CTAPHID command 0x3F (ERROR, device-to-host only)", "fido", _invalid_cmd_probe(0x3F))
add("fido-hid", "invalid-cmd-3e", "CTAPHID command 0x3E (unassigned)", "fido", _invalid_cmd_probe(0x3E))


@probe("fido-hid", "wrong-seq", "PING of 100 bytes whose first continuation has SEQ 1", "fido")
def p_wrong_seq(ctx):
    rec = ctx.fido
    cid = rec.init_channel()
    payload = pattern(100)
    rec.send(init_packet(cid, Cmd.PING, 100, payload[:INIT_DATA]))
    rec.send(cont_packet(cid, 1, payload[INIT_DATA:]))
    out = describe(rec.wait_message(cid, 1.0))
    out["ping_after"] = describe(rec.exchange(cid, Cmd.PING, b"ok", 2))
    return out


@probe("fido-hid", "skipped-seq", "PING of 200 bytes: continuation SEQ 0 then SEQ 2", "fido")
def p_skipped_seq(ctx):
    rec = ctx.fido
    cid = rec.init_channel()
    payload = pattern(200)
    rec.send(init_packet(cid, Cmd.PING, 200, payload[:INIT_DATA]))
    rec.send(cont_packet(cid, 0, payload[INIT_DATA : INIT_DATA + CONT_DATA]))
    rec.send(cont_packet(cid, 2, payload[INIT_DATA + 2 * CONT_DATA :]))
    out = describe(rec.wait_message(cid, 1.0))
    out["ping_after"] = describe(rec.exchange(cid, Cmd.PING, b"ok", 2))
    return out


@probe("fido-hid", "cont-without-init", "A continuation packet with no message started, then PING", "fido")
def p_cont_without_init(ctx):
    rec = ctx.fido
    cid = rec.init_channel()
    rec.send(cont_packet(cid, 0, pattern(CONT_DATA)))
    replies = rec.listen(0.5)
    return {"replies": [describe_packet(p) for _, p in replies], "ping_after": describe(rec.exchange(cid, Cmd.PING, b"ok", 2))}


@probe("fido-hid", "cid-0", "PING on the reserved CID 0", "fido")
def p_cid0(ctx):
    rec = ctx.fido
    rec.send(init_packet(0, Cmd.PING, 4, b"ping"))
    replies = rec.listen(0.5)
    return {"replies": [dict(describe_packet(p), cid_zero=p["cid"] == 0) for _, p in replies]}


@probe("fido-hid", "ping-broadcast", "PING on the broadcast CID", "fido")
def p_ping_broadcast(ctx):
    rec = ctx.fido
    rec.send(init_packet(BROADCAST, Cmd.PING, 4, b"ping"))
    replies = rec.listen(0.5)
    return {"replies": [dict(describe_packet(p), cid_broadcast=p["cid"] == BROADCAST) for _, p in replies]}


@probe("fido-hid", "busy-two-channels", "Channel A leaves a PING half sent; channel B PINGs; A completes", "fido")
def p_busy(ctx):
    rec = ctx.fido
    a = rec.init_channel()
    b = rec.init_channel()
    payload = pattern(100)
    rec.send(init_packet(a, Cmd.PING, 100, payload[:INIT_DATA]))
    b_reply = rec.exchange(b, Cmd.PING, b"busy?", 1.0)
    rec.send(cont_packet(a, 0, payload[INIT_DATA:]))
    a_reply = rec.wait_message(a, 1.0)
    out = {"b_while_a_assembles": describe(b_reply), "a_after_completion": describe(a_reply)}
    if a_reply and a_reply["cmd"] == Cmd.PING:
        out["a_after_completion"]["echo_ok"] = a_reply["payload"] == payload
    out["b_after"] = describe(rec.exchange(b, Cmd.PING, b"free?", 1.0))
    return out


@probe("fido-hid", "lock", "LOCK 1 s on A: B PING, broadcast INIT, A PING; after expiry B PING; LOCK 1 then LOCK 0", "fido")
def p_lock(ctx):
    rec = ctx.fido
    a = rec.init_channel()
    b = rec.init_channel()
    out = {"lock_1": describe(rec.exchange(a, Cmd.LOCK, b"\x01", 1.0))}
    t_lock = time.monotonic()
    out["b_ping_locked"] = describe(rec.exchange(b, Cmd.PING, b"b", 0.5))
    nonce = os.urandom(8)
    rec.send_msg(BROADCAST, Cmd.INIT, nonce)
    out["broadcast_init_locked"] = describe(rec.wait_message(BROADCAST, 0.5))
    out["a_ping_locked"] = describe(rec.exchange(a, Cmd.PING, b"a", 0.5))
    time.sleep(max(0.0, 1.25 - (time.monotonic() - t_lock)))
    out["b_ping_after_expiry"] = describe(rec.exchange(b, Cmd.PING, b"b", 0.5))
    out["lock_1_again"] = describe(rec.exchange(a, Cmd.LOCK, b"\x01", 1.0))
    out["lock_0"] = describe(rec.exchange(a, Cmd.LOCK, b"\x00", 1.0))
    out["b_ping_after_release"] = describe(rec.exchange(b, Cmd.PING, b"b", 0.5))
    return out


# --- FIDO: fido-cbor ------------------------------------------------------------------------


def resync(rec, cid: int) -> dict:
    """INIT on `cid` aborts whatever transaction it still holds (CTAP 2.1 §11.2.9.1.3), so
    one probe that leaves the device waiting cannot make the next probes see a busy
    device. Returns what the device answered."""
    nonce = os.urandom(8)
    rec.send_msg(cid, Cmd.INIT, nonce)
    return describe(rec.wait_message(cid, 2))


def _cbor_probe(payload_fn):
    def fn(ctx):
        rec = ctx.fido
        cid = rec.init_channel()
        t = rec.send_msg(cid, Cmd.CBOR, payload_fn())
        msg = rec.wait_message(cid, 5)
        out = describe(msg)
        if msg:
            out["rtt_ms"] = ms_between(t, msg["t"])
            out["keepalives"] = len(msg["keepalives"])
        else:
            out["resync"] = resync(rec, cid)
        return out

    return fn


def _empty_cbor(ctx):
    """CTAPHID_CBOR with BCNT 0: what the device answers, whether it holds the channel
    (another channel's PING), whether CANCEL frees it, and INIT on it as the last resort."""
    rec = ctx.fido
    a = rec.init_channel()
    b = rec.init_channel()
    t = rec.send_msg(a, Cmd.CBOR, b"")
    msg = rec.wait_message(a, 2)
    out = {"answer": describe(msg)}
    if msg:
        out["rtt_ms"] = ms_between(t, msg["t"])
    out["other_channel_ping"] = describe(rec.exchange(b, Cmd.PING, b"x", 2))
    rec.send_msg(a, Cmd.CANCEL, b"")
    out["after_cancel_answer"] = describe(rec.wait_message(a, 1))
    out["other_channel_ping_after_cancel"] = describe(rec.exchange(b, Cmd.PING, b"x", 2))
    out["resync"] = resync(rec, a)
    out["other_channel_ping_after_resync"] = describe(rec.exchange(b, Cmd.PING, b"x", 2))
    return out


add("fido-cbor", "get-info", "authenticatorGetInfo", "fido", _cbor_probe(lambda: b"\x04"))
add("fido-cbor", "client-pin-retries", "clientPIN getPINRetries (protocol 2)", "fido", _cbor_probe(lambda: b"\x06" + cbor.encode({1: 2, 2: 1})))
add("fido-cbor", "client-pin-key-agreement-2", "clientPIN getKeyAgreement (protocol 2)", "fido", _cbor_probe(lambda: b"\x06" + cbor.encode({1: 2, 2: 2})))
add("fido-cbor", "client-pin-key-agreement-1", "clientPIN getKeyAgreement (protocol 1)", "fido", _cbor_probe(lambda: b"\x06" + cbor.encode({1: 1, 2: 2})))
add("fido-cbor", "client-pin-uv-retries", "clientPIN getUVRetries (protocol 2)", "fido", _cbor_probe(lambda: b"\x06" + cbor.encode({1: 2, 2: 7})))
add("fido-cbor", "unknown-command-03", "CTAP2 command 0x03 (unassigned)", "fido", _cbor_probe(lambda: b"\x03"))
add("fido-cbor", "unknown-command-05", "CTAP2 command 0x05 (unassigned)", "fido", _cbor_probe(lambda: b"\x05"))
add("fido-cbor", "get-info-trailing-map", "getInfo followed by an empty map A0", "fido", _cbor_probe(lambda: b"\x04\xa0"))
add("fido-cbor", "get-info-trailing-zero", "getInfo followed by 00", "fido", _cbor_probe(lambda: b"\x04\x00"))
add("fido-cbor", "empty-cbor", "CTAPHID_CBOR with BCNT 0, then other-channel PING, CANCEL, INIT resync", "fido", _empty_cbor)
add("fido-cbor", "get-assertion-up-false", "getAssertion, random *.invalid rpId, options {up:false}", "fido", _cbor_probe(
    lambda: b"\x02" + cbor.encode({1: os.urandom(8).hex() + ".invalid", 2: os.urandom(32), 5: {"up": False}})))


def _u2f_probe(payload_fn):
    def fn(ctx):
        rec = ctx.fido
        cid = rec.init_channel()
        t = rec.send_msg(cid, Cmd.MSG, payload_fn())
        msg = rec.wait_message(cid, 5)
        out = describe(msg)
        if msg:
            out["rtt_ms"] = ms_between(t, msg["t"])
        return out

    return fn


def _u2f_authenticate():
    key_handle = os.urandom(64)
    data = os.urandom(32) + os.urandom(32) + bytes([len(key_handle)]) + key_handle
    return bytes([0x00, 0x02, 0x07, 0x00, 0x00]) + struct.pack(">H", len(data)) + data + b"\x00\x00"


add("fido-cbor", "u2f-version", "U2F VERSION (extended encoding as python-fido2 sends it)", "fido", _u2f_probe(lambda: _H("000300000000000000")))
add("fido-cbor", "u2f-authenticate-check-only", "U2F AUTHENTICATE P1 07 with a random key handle", "fido", _u2f_probe(_u2f_authenticate))
add("fido-cbor", "u2f-wrong-cla", "U2F VERSION with CLA 80", "fido", _u2f_probe(lambda: _H("800300000000000000")))
add("fido-cbor", "u2f-unknown-ins", "U2F INS 05", "fido", _u2f_probe(lambda: _H("000500000000000000")))


# --- FIDO: fido-timing ----------------------------------------------------------------------


def _keepalive_summary(keepalives, start):
    out = interval_stats([t for t, _ in keepalives])
    out["statuses"] = sorted({s for _, s in keepalives})
    if keepalives:
        out["first_keepalive_ms"] = ms_between(start, keepalives[0][0])
    return out


@probe("fido-timing", "selection-keepalive-cancel", "selection: KEEPALIVEs for 1.5 s, then CANCEL", "fido")
def p_selection_cancel(ctx):
    rec = ctx.fido
    cid = rec.init_channel()
    t_send = rec.send_msg(cid, Cmd.CBOR, b"\x0b")
    early = rec.wait_message(cid, 1.5)
    keepalives = list(rec.last_keepalives)
    out = {"keepalive": _keepalive_summary(keepalives, t_send)}
    if early is not None:
        out["answered_before_cancel"] = describe(early)
        return out
    t_cancel = rec.send(init_packet(cid, Cmd.CANCEL, 0))
    final = rec.wait_message(cid, 3.0)
    out["final"] = describe(final)
    if final is not None:
        out["cancel_to_answer_ms"] = ms_between(t_cancel, final["t"])
        out["keepalives_after_cancel"] = len(final["keepalives"])
    return out


@probe("fido-timing", "message-timeout", "PING init with BCNT 100, continuation withheld: wait up to 5 s", "fido")
def p_msg_timeout(ctx):
    rec = ctx.fido
    cid = rec.init_channel()
    t = rec.send(init_packet(cid, Cmd.PING, 100, pattern(INIT_DATA)))
    msg = rec.wait_message(cid, 5.0)
    out = describe(msg)
    if msg is not None:
        out["timeout_ms"] = ms_between(t, msg["t"])
    else:
        out["resync"] = describe(rec.exchange(cid, Cmd.INIT, os.urandom(8), 2))
    return out


def _lock_expiry(rec, seconds):
    a = rec.init_channel()
    b = rec.init_channel()
    lock = rec.exchange(a, Cmd.LOCK, bytes([seconds]), 1.0)
    out = {"lock": describe(lock)}
    if lock is None:
        return out
    t_lock = lock["t"]
    busy_codes = set()
    polls = 0
    deadline = time.monotonic() + seconds + 3
    while time.monotonic() < deadline:
        reply = rec.exchange(b, Cmd.PING, b"poll", 0.5)
        polls += 1
        if reply and reply["cmd"] == Cmd.PING:
            out["free_after_ms"] = ms_between(t_lock, reply["t"])
            break
        if reply and reply["cmd"] == Cmd.ERROR:
            busy_codes.add(describe(reply)["code"])
        time.sleep(0.02)
    out["busy_codes"] = sorted(busy_codes)
    out["polls"] = polls
    return out


@probe("fido-timing", "lock-expiry", "LOCK 1 s and 2 s on A; B polls PING every ~20 ms until it gets through", "fido")
def p_lock_expiry(ctx):
    return {"lock_1s": _lock_expiry(ctx.fido, 1), "lock_2s": _lock_expiry(ctx.fido, 2)}


# --- FIDO: fido-presence-timeout (opt-in) -------------------------------------------------


@probe("fido-presence-timeout", "selection-no-touch", "selection without touch until the device answers (max 45 s)", "fido")
def p_presence_timeout(ctx):
    rec = ctx.fido
    cid = rec.init_channel()
    t_send = rec.send_msg(cid, Cmd.CBOR, b"\x0b")
    msg = rec.wait_message(cid, 45.0)
    keepalives = msg["keepalives"] if msg else rec.last_keepalives
    out = {"final": describe(msg), "keepalive": _keepalive_summary(keepalives, t_send)}
    if msg is not None:
        out["timeout_ms"] = ms_between(t_send, msg["t"])
    else:
        rec.send(init_packet(cid, Cmd.CANCEL, 0))
        out["after_cancel"] = describe(rec.wait_message(cid, 3.0))
    return out


def select_probes(sets: list[str]) -> list[Probe]:
    unknown = [s for s in sets if s not in ALL_SETS]
    if unknown:
        raise ValueError(f"unknown probe set(s): {', '.join(unknown)}")
    return [p for p in PROBES if p.set in sets]
