"""Redaction: turn a raw run (scratchpad only) into a shareable one.

Redacted bytes are written as `xx` in hex strings, so lengths and positions survive and
compare.py can still compare everything that was not redacted. The rules are fail-closed:
a CCID response whose command form has no rule here is redacted completely.

CCID
- serial: collected from Management READ CONFIG tag 02, OTP INS 01 P1 10/13, PIV GET
  SERIAL and the OpenPGP AID, then every response is scrubbed of its 4-byte big-endian,
  8-digit BCD and ASCII-decimal forms;
- OATH SELECT: name/device id (71) and challenge (74);
- PIV: CHUID FASC-N (30), GUID (34), signature (3E); CCC card identifier (F0); GET SERIAL;
  GET METADATA public key (04);
- OpenPGP: AID serial bytes (4F bytes 10..13), fingerprints (C5, C6), key generation
  times (CD), cardholder name (5B) and language (5F2D), signature counter (93);
- Security Domain CPLC: everything after the first 10 bytes (OS identity), which covers
  the IC serial, batch and personalisation identifiers;
- 61xx/GET RESPONSE chains are reassembled before the rules apply;
- SELECT by a partial or unknown AID, or with next/last occurrence: whole data.

CTAPHID
- packets are reduced to headers (CID alias, command or SEQ, BCNT); message content is
  rendered only through the rules below: INIT nonces and CIDs become lengths/aliases,
  PING payloads a hash (they are the harness's own patterns), CBOR byte strings `xx`
  except in getInfo (AAGUID kept) and clientPIN retries, text other than in getInfo
  `<text:N>`, the getKeyAgreement COSE key coordinates `xx`, U2F data `xx` except
  "U2F_V2".
"""

from __future__ import annotations

import copy
import hashlib
import struct

import cbor
from common import (
    BROADCAST,
    CMD_NAMES,
    CTAP_STATUS,
    HID_ERRORS,
    Cmd,
    TlvError,
    flat_tlvs,
    parse_packet,
    tlv_items,
)
from guard import CcidGuard

REDACTED = "xx"



def _sw(text: str) -> int:
    """A recorded status word; "none" (the host transport failed, no status word) is 0."""
    return 0 if text == "none" else int(text, 16)

def masked_hex(data: bytes, mask: list[bool]) -> str:
    return "".join(REDACTED if m else f"{b:02x}" for b, m in zip(data, mask))


def simple_tlvs(data: bytes, start: int = 0, end: int | None = None) -> list[tuple[str, int, int]]:
    """One level of Yubico/PIV simple TLVs: single-byte tags, BER lengths."""
    end = len(data) if end is None else end
    items = []
    pos = start
    while pos < end:
        tag = data[pos]
        if pos + 1 >= end:
            raise TlvError("missing length")
        length = data[pos + 1]
        pos += 2
        if length == 0x81 or length == 0x82:
            count = length & 0x7F
            if pos + count > end:
                raise TlvError("bad length")
            length = int.from_bytes(data[pos : pos + count], "big")
            pos += count
        elif length > 0x82:
            raise TlvError("bad length")
        if pos + length > end:
            raise TlvError("value overruns")
        items.append((f"{tag:02X}", pos, pos + length))
        pos += length
    return items


def ber_items(data: bytes, start: int = 0, end: int | None = None, path: tuple = (), stop=frozenset(), depth: int = 0):
    """BER-TLV items with their paths. The top level must parse; a constructed value
    that does not parse as TLVs, or whose tag is in `stop` (redacted), is not entered."""
    items = []
    for _tag, tag_bytes, vs, ve, constructed in tlv_items(data, start, end):
        here = path + (tag_bytes.hex().upper(),)
        items.append(("/".join(here), vs, ve))
        if constructed and ve > vs and here[-1] not in stop and depth < 8:
            try:
                items.extend(ber_items(data, vs, ve, here, stop, depth + 1))
            except TlvError:
                pass
    return items


def piv_object_items(data: bytes) -> list[tuple[str, int, int]]:
    """A PIV data object: an outer BER TLV (53, or 7E for discovery) holding simple TLVs."""
    items = []
    for _tag, tag_bytes, vs, ve, _constructed in tlv_items(data):
        outer = tag_bytes.hex().upper()
        items.append((outer, vs, ve))
        for tag, ivs, ive in simple_tlvs(data, vs, ve):
            items.append((f"{outer}/{tag}", ivs, ive))
    return items


def flat_items(data: bytes) -> list[tuple[str, int, int]]:
    """Management READ CONFIG / OTP capabilities: a length byte, then 1-byte tag and length."""
    if not data or data[0] != len(data) - 1:
        raise TlvError("length byte does not match")
    items = []
    pos = 1
    while pos < len(data):
        if pos + 2 > len(data) or pos + 2 + data[pos + 1] > len(data):
            raise TlvError("value overruns")
        items.append((f"{data[pos]:02X}", pos + 2, pos + 2 + data[pos + 1]))
        pos += 2 + data[pos + 1]
    return items


# rule -> (structure, tags whose values are redacted, {tag: (from, to)} partial redaction)
RULES = {
    "public": ("raw", set(), {}),
    "public-ber": ("ber", set(), {}),
    "select-mgmt": ("raw", set(), {}),
    "select-otp": ("raw", set(), {}),
    "select-hsmauth": ("raw", set(), {}),
    "select-piv": ("ber", set(), {}),
    "select-openpgp": ("ber", set(), {}),
    "select-sd": ("ber", set(), {}),
    "select-oath": ("simple", {"71", "74"}, {}),
    "mgmt-config": ("flat", {"02"}, {}),
    "otp-config": ("flat", {"02"}, {}),
    "piv-version": ("raw", set(), {}),
    "piv-discovery": ("ber", set(), {}),
    "piv-chuid": ("piv-object", {"30", "32", "33", "34", "36", "3E"}, {}),
    "piv-ccc": ("piv-object", {"F0"}, {}),
    "piv-metadata": ("simple", {"04"}, {}),
    "openpgp-6e": ("ber", {"C5", "C6", "CD", "93"}, {"4F": (10, 14)}),
    "openpgp-65": ("ber", {"5B", "5F2D"}, {}),
    "openpgp-7a": ("ber", {"93"}, {}),
    "openpgp-aid": ("raw", set(), {}),
    "sd-cplc": ("ber", set(), {}),
}

STRUCTURES = {"ber": ber_items, "simple": simple_tlvs, "piv-object": piv_object_items, "flat": flat_items}


# --- CCID rules ---------------------------------------------------------------------------

PIV_TAGLISTS = {
    bytes.fromhex("5C017E"): "discovery",
    bytes.fromhex("5C035FC102"): "chuid",
    bytes.fromhex("5C035FC107"): "ccc",
}


def _piv_object(body: bytes):
    for taglist, name in PIV_TAGLISTS.items():
        if taglist in body:
            return name
    return None


def ccid_rule(applet, command: bytes) -> str:
    """The redaction rule for the response to `command` while `applet` is selected."""
    ins, p1, p2 = command[1], command[2], command[3]
    body = command[4:]
    p1p2 = p1 << 8 | p2
    if ins == 0xA4:
        aid = body[1 : 1 + body[0]] if body else b""
        known = CcidGuard.applet_for(aid)
        if known is None or p2 & 0x03:
            return "select-unknown"
        return f"select-{known}"
    if applet == "mgmt" and ins == 0x1D:
        return "mgmt-config"
    if applet == "otp" and ins == 0x01:
        return "otp-serial" if p1 == 0x10 else "otp-config"
    if applet == "piv":
        if ins == 0xFD:
            return "piv-version"
        if ins == 0xF8:
            return "piv-serial"
        if ins == 0xCB:
            name = _piv_object(body)
            return f"piv-{name}" if name else "unknown"
        if ins == 0xF7:
            return "piv-metadata"
    if applet == "openpgp" and ins == 0xCA:
        return {0x006E: "openpgp-6e", 0x0065: "openpgp-65", 0x007A: "openpgp-7a", 0x00C4: "public", 0x5F52: "public", 0x7F74: "public-ber", 0x004F: "openpgp-aid"}.get(p1p2, "unknown")
    if applet == "sd" and ins == 0xCA:
        return {0x00E0: "public-ber", 0x0066: "public-ber", 0x9F7F: "sd-cplc"}.get(p1p2, "unknown")
    return "unknown"


def apply_rule(rule: str, data: bytes) -> tuple[list[bool], list[str] | None]:
    """(mask of redacted bytes, tag paths or None). Unknown rules redact everything."""
    everything = [True] * len(data)
    if not data:
        return [], None
    if rule not in RULES:
        return everything, None
    structure, redact, partial = RULES[rule]
    mask = [False] * len(data)
    items = []
    if structure != "raw":
        try:
            parse = STRUCTURES[structure]
            items = parse(data, stop=frozenset(redact)) if structure == "ber" else parse(data)
        except TlvError:
            return everything, None
    for path, vs, ve in items:
        tag = path.rsplit("/", 1)[-1]
        if tag in redact:
            for i in range(vs, ve):
                mask[i] = True
        if tag in partial:
            lo, hi = partial[tag]
            for i in range(vs + lo, min(vs + hi, ve)):
                mask[i] = True
    if rule == "openpgp-aid":
        if len(data) != 16:
            return everything, None
        for i in range(10, 14):
            mask[i] = True
    if rule == "sd-cplc":
        if not data.startswith(b"\x9f\x7f\x2a") or len(data) != 45:
            return everything, None
        for i in range(3 + 10, len(data)):
            mask[i] = True
    tags = [path for path, _, _ in items] if structure != "raw" else None
    return mask, tags


def _bcd(value: int) -> bytes | None:
    text = f"{value:08d}"
    if len(text) != 8:
        return None
    return bytes(int(text[i]) << 4 | int(text[i + 1]) for i in range(0, 8, 2))


def _from_bcd(data: bytes) -> int | None:
    digits = ""
    for b in data:
        hi, lo = b >> 4, b & 0x0F
        if hi > 9 or lo > 9:
            return None
        digits += f"{hi}{lo}"
    return int(digits)


def serial_forms(serial: int) -> list[bytes]:
    forms = [serial.to_bytes(4, "big"), str(serial).encode()]
    bcd = _bcd(serial)
    if bcd:
        forms.append(bcd)
    return [f for f in forms if len(f) >= 3]


def _ccid_groups(log: list[dict]):
    """Group exchanges into 61xx chains: [(applet, [indices])]."""
    groups = []
    applet = None
    i = 0
    while i < len(log):
        entry = log[i]
        command = bytes.fromhex(entry["apdu"])
        group = [i]
        sw = _sw(entry["sw"])
        j = i
        while sw >> 8 == 0x61 and j + 1 < len(log) and bytes.fromhex(log[j + 1]["apdu"])[1] == 0xC0:
            j += 1
            group.append(j)
            sw = _sw(log[j]["sw"])
        groups.append((applet, command, group))
        if command[1] == 0xA4:
            p2 = command[3]
            aid = command[5 : 5 + command[4]] if len(command) > 4 else b""
            ok = _sw(entry["sw"]) == 0x9000 or _sw(entry["sw"]) >> 8 == 0x61
            applet = CcidGuard.applet_for(aid) if ok and not p2 & 0x03 else None
        i = j + 1
    return groups


def collect_serials(run: dict) -> set[int]:
    serials = set()
    for result in run["probes"]:
        if result.get("kind") != "ccid":
            continue
        for applet, command, group in _ccid_groups(result.get("log", [])):
            data = b"".join(bytes.fromhex(result["log"][k]["data"]) for k in group)
            sw = _sw(result["log"][group[-1]]["sw"])
            if sw != 0x9000 or not data:
                continue
            rule = ccid_rule(applet, command)
            if rule in ("mgmt-config", "otp-config") and data[0] == len(data) - 1:
                value = flat_tlvs(data[1:]).get(0x02)
                if value and len(value) == 4:
                    serials.add(int.from_bytes(value, "big"))
            elif rule in ("otp-serial", "piv-serial") and len(data) == 4:
                serials.add(int.from_bytes(data, "big"))
            elif rule == "openpgp-aid" and len(data) == 16:
                value = _from_bcd(data[10:14])
                if value:
                    serials.add(value)
            elif rule == "openpgp-6e":
                try:
                    for path, vs, ve in ber_items(data):
                        if path.endswith("4F") and ve - vs == 16:
                            value = _from_bcd(data[vs + 10 : vs + 14])
                            if value:
                                serials.add(value)
                except TlvError:
                    pass
    return serials


def _scrub(data: bytes, mask: list[bool], forms: list[bytes]):
    for form in forms:
        start = 0
        while True:
            k = data.find(form, start)
            if k < 0:
                break
            for i in range(k, k + len(form)):
                mask[i] = True
            start = k + 1


def normalize_ccid(log: list[dict], forms: list[bytes]) -> list[dict]:
    out = []
    for applet, command, group in _ccid_groups(log):
        parts = [bytes.fromhex(log[k]["data"]) for k in group]
        data = b"".join(parts)
        rule = ccid_rule(applet, command)
        mask, tags = apply_rule(rule, data)
        _scrub(data, mask, forms)
        pos = 0
        for n, (k, part) in enumerate(zip(group, parts)):
            entry = log[k]
            record = {
                "apdu": entry["apdu"],
                "sw": entry["sw"],
                "len": len(part),
                "data": masked_hex(part, mask[pos : pos + len(part)]),
                "ms": entry["ms"],
            }
            if n == 0:
                record["rule"] = rule
                if tags is not None:
                    record["tags"] = tags
                if len(group) > 1:
                    record["chain_total_len"] = len(data)
            else:
                record["chain_part"] = n
            if "note" in entry:
                record["note"] = entry["note"]
            out.append(record)
            pos += len(part)
    return out


# --- CTAPHID rendering --------------------------------------------------------------------


def render_cbor(value, keep_bytes=False, keep_text=False, redact_keys=frozenset()):
    """CBOR value → JSON-able, with byte strings and text redacted unless kept."""

    def walk(v, key=None):
        if key in redact_keys and isinstance(v, (bytes, str)):
            return REDACTED * len(v if isinstance(v, bytes) else v.encode())
        if isinstance(v, bytes):
            return v.hex() if keep_bytes else REDACTED * len(v)
        if isinstance(v, str):
            return v if keep_text else f"<text:{len(v.encode())}>"
        if isinstance(v, list):
            return [walk(x) for x in v]
        if isinstance(v, dict):
            return {str(k): walk(x, k) for k, x in v.items()}
        return v

    return walk(value)


def _cbor_request(payload: bytes) -> dict:
    if not payload:
        return {"ctap_cmd": None}
    out = {"ctap_cmd": f"0x{payload[0]:02X}"}
    rest = payload[1:]
    if not rest:
        return out
    try:
        value = cbor.decode(rest)
    except cbor.CborError:
        out["trailing"] = rest.hex() if len(rest) <= 16 else REDACTED * len(rest)
        return out
    if payload[0] == 0x02 and isinstance(value, dict):
        rendered = render_cbor(value, keep_text=False)
        if isinstance(value.get(1), str) and value[1].endswith(".invalid"):
            rendered["1"] = f"<random:{len(value[1]) - len('.invalid')}>.invalid"
        out["params"] = rendered
    elif payload[0] == 0x06:
        out["params"] = render_cbor(value)
    else:
        out["params"] = render_cbor(value)
    return out


def _cbor_response(payload: bytes, request: bytes | None) -> dict:
    if not payload:
        return {"status": None}
    status = payload[0]
    out = {"status": f"0x{status:02X} {CTAP_STATUS.get(status, '?')}"}
    rest = payload[1:]
    if not rest:
        return out
    try:
        value = cbor.decode(rest)
    except cbor.CborError as error:
        out["body"] = {"undecodable": str(error), "len": len(rest)}
        return out
    command = request[0] if request else None
    sub = None
    if command == 0x06 and request and len(request) > 1:
        try:
            sub = cbor.decode(request[1:]).get(2)
        except (cbor.CborError, AttributeError):
            sub = None
    if command == 0x04:
        out["body"] = render_cbor(value, keep_bytes=True, keep_text=True)
    elif command == 0x06 and sub in (1, 7):
        out["body"] = render_cbor(value)
    elif command == 0x06 and sub == 2 and isinstance(value, dict) and isinstance(value.get(1), dict):
        key = value[1]
        rendered = {str(k): (REDACTED * len(v) if isinstance(v, bytes) else v) for k, v in key.items()}
        out["body"] = {"1": rendered}
        out["body"].update({str(k): render_cbor(v) for k, v in value.items() if k != 1})
    else:
        out["body"] = render_cbor(value)
    return out


def normalize_fido(log: list[dict]) -> list[dict]:
    aliases: dict[int, str] = {}

    def alias(cid: int) -> str:
        if cid == BROADCAST:
            return "broadcast"
        if cid == 0:
            return "cid0"
        if cid not in aliases:
            aliases[cid] = f"cid{len(aliases) + 1}"
        return aliases[cid]

    assembling = {"out": {}, "in": {}}
    last_request: dict[tuple, bytes] = {}
    out = []
    for entry in log:
        pkt = bytes.fromhex(entry["pkt"])
        direction = entry["dir"]
        p = parse_packet(pkt)
        record = {"t": entry["t"], "dir": direction, "cid": alias(p["cid"])}
        pending = assembling[direction]
        complete = None
        if p["init"]:
            record["cmd"] = CMD_NAMES.get(p["cmd"], f"0x{p['cmd']:02X}")
            record["bcnt"] = p["bcnt"]
            msg = {"cmd": p["cmd"], "bcnt": p["bcnt"], "payload": p["data"][: p["bcnt"]], "next": 0}
            if len(msg["payload"]) >= msg["bcnt"]:
                complete = msg
                pending.pop(p["cid"], None)
            elif p["bcnt"] <= 7609:
                pending[p["cid"]] = msg
            else:
                pending.pop(p["cid"], None)
        else:
            record["seq"] = p["seq"]
            msg = pending.get(p["cid"])
            if msg is not None:
                if p["seq"] != msg["next"]:
                    pending.pop(p["cid"], None)
                else:
                    msg["next"] += 1
                    msg["payload"] += p["data"][: msg["bcnt"] - len(msg["payload"])]
                    if len(msg["payload"]) >= msg["bcnt"]:
                        complete = msg
                        pending.pop(p["cid"], None)
        if complete is not None:
            record.setdefault("cmd", CMD_NAMES.get(complete["cmd"], f"0x{complete['cmd']:02X}"))
            record["message"] = _render_message(direction, p["cid"], complete, last_request, alias)
            if direction == "out":
                last_request[(p["cid"], complete["cmd"])] = complete["payload"]
        out.append(record)
    return out


def _render_message(direction, cid, msg, last_request, alias) -> dict:
    command, payload = msg["cmd"], msg["payload"]
    content: dict = {"len": len(payload)}
    if command == Cmd.INIT:
        if direction == "out":
            content["nonce"] = REDACTED * len(payload)
        elif len(payload) >= 17:
            request = last_request.get((cid, Cmd.INIT))
            content.update({
                "nonce_ok": request is not None and payload[:8] == request[:8],
                "allocated_cid": alias(struct.unpack(">I", payload[8:12])[0]),
                "protocol": payload[12],
                "device_version": ".".join(str(b) for b in payload[13:16]),
                "capabilities": f"0x{payload[16]:02X}",
            })
    elif command == Cmd.PING:
        content["sha256_8"] = hashlib.sha256(payload).hexdigest()[:16]
    elif command == Cmd.CBOR:
        content.update(_cbor_request(payload) if direction == "out" else _cbor_response(payload, last_request.get((cid, Cmd.CBOR))))
    elif command == Cmd.MSG:
        if direction == "out":
            if len(payload) >= 4:
                content.update({"cla": f"{payload[0]:02X}", "ins": f"{payload[1]:02X}", "p1": f"{payload[2]:02X}", "p2": f"{payload[3]:02X}"})
        else:
            request = last_request.get((cid, Cmd.MSG))
            data = payload[:-2]
            content["sw"] = payload[-2:].hex().upper() if len(payload) >= 2 else None
            content["data"] = data.decode() if data == b"U2F_V2" and request and request[1] == 0x03 else REDACTED * len(data)
    elif command == Cmd.ERROR:
        if payload:
            content["code"] = f"0x{payload[0]:02X} {HID_ERRORS.get(payload[0], '?')}"
    elif command == Cmd.KEEPALIVE:
        if payload:
            content["status"] = payload[0]
    elif command == Cmd.LOCK and direction == "out":
        content["seconds"] = payload[0] if payload else None
    return content


# --- whole runs ---------------------------------------------------------------------------


def redact_run(raw: dict) -> dict:
    run = copy.deepcopy(raw)
    serials = collect_serials(raw)
    forms = [form for serial in serials for form in serial_forms(serial)]
    for result in run["probes"]:
        log = result.pop("log", [])
        if result.get("kind") == "ccid":
            result["exchanges"] = normalize_ccid(log, forms)
        elif result.get("kind") == "fido":
            result["packets"] = normalize_fido(log)
    run["meta"]["redacted"] = True
    run["meta"]["serials_scrubbed"] = len(serials)
    return run


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Redact a raw measurement run")
    parser.add_argument("raw")
    parser.add_argument("out")
    args = parser.parse_args()
    with open(args.raw) as f:
        raw = json.load(f)
    with open(args.out, "w") as f:
        json.dump(redact_run(raw), f, indent=1)
