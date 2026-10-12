"""Shared helpers: APDU building, BER-TLV walking, CTAPHID framing constants."""

from __future__ import annotations

import struct

# --- ISO 7816-4 -----------------------------------------------------------------------


def apdu(cla: int, ins: int, p1: int, p2: int, data: bytes = b"", le: int | None = None, extended: bool = False) -> bytes:
    """Encode a well-formed command APDU (short or extended)."""
    header = bytes([cla, ins, p1, p2])
    body = b""
    if extended:
        if data:
            body += b"\x00" + struct.pack(">H", len(data)) + data
        if le is not None:
            body += (b"" if data else b"\x00") + struct.pack(">H", le & 0xFFFF)
    else:
        if data:
            if len(data) > 255:
                raise ValueError("short APDU data too long")
            body += bytes([len(data)]) + data
        if le is not None:
            body += bytes([le & 0xFF])
    return header + body


def select(aid: bytes, p2: int = 0x00) -> bytes:
    return apdu(0x00, 0xA4, 0x04, p2, aid)


def sw_hex(sw: int | None) -> str | None:
    return None if sw is None else f"{sw:04X}"


# --- BER-TLV ----------------------------------------------------------------------------


class TlvError(ValueError):
    pass


def tlv_items(data: bytes, start: int = 0, end: int | None = None):
    """Yield (tag, tag_bytes, value_start, value_end, constructed) for one TLV level."""
    end = len(data) if end is None else end
    pos = start
    while pos < end:
        if data[pos] in (0x00, 0xFF) and pos == end - 1:
            # trailing padding byte
            return
        tag_start = pos
        first = data[pos]
        pos += 1
        if first & 0x1F == 0x1F:
            while True:
                if pos >= end:
                    raise TlvError("truncated tag")
                byte = data[pos]
                pos += 1
                if not byte & 0x80:
                    break
                if pos - tag_start > 4:
                    raise TlvError("tag too long")
        tag_bytes = bytes(data[tag_start:pos])
        if pos >= end:
            raise TlvError("missing length")
        length = data[pos]
        pos += 1
        if length & 0x80:
            count = length & 0x7F
            if count == 0 or count > 3 or pos + count > end:
                raise TlvError("bad length")
            length = int.from_bytes(data[pos : pos + count], "big")
            pos += count
        if pos + length > end:
            raise TlvError("value overruns")
        yield int.from_bytes(tag_bytes, "big"), tag_bytes, pos, pos + length, bool(first & 0x20)
        pos += length


def tlv_walk(data: bytes, start: int = 0, end: int | None = None, path: tuple = (), depth: int = 0):
    """Yield (path, value_start, value_end) for every TLV, recursing into constructed ones.

    Raises TlvError if the data is not BER-TLV. `path` is a tuple of hex tag strings.
    """
    if depth > 8:
        raise TlvError("too deep")
    for tag, tag_bytes, vs, ve, constructed in tlv_items(data, start, end):
        here = path + (tag_bytes.hex().upper(),)
        yield here, vs, ve
        if constructed and ve > vs:
            yield from tlv_walk(data, vs, ve, here, depth + 1)


def tlv_tag_paths(data: bytes) -> list[str] | None:
    """Every tag path as 'A/B/C' strings, or None if not BER-TLV."""
    try:
        return ["/".join(path) for path, _, _ in tlv_walk(data)]
    except TlvError:
        return None


def flat_tlvs(data: bytes) -> dict[int, bytes]:
    """One level of simple TLVs with single-byte tags and lengths (Management/OTP style)."""
    result = {}
    pos = 0
    while pos + 2 <= len(data):
        tag, length = data[pos], data[pos + 1]
        result[tag] = bytes(data[pos + 2 : pos + 2 + length])
        pos += 2 + length
    return result


# --- CTAPHID ----------------------------------------------------------------------------

REPORT = 64
INIT_DATA = REPORT - 7
CONT_DATA = REPORT - 5
MAX_PAYLOAD = INIT_DATA + 128 * CONT_DATA  # 7609
BROADCAST = 0xFFFFFFFF
TYPE_INIT = 0x80


class Cmd:
    PING = 0x01
    MSG = 0x03
    LOCK = 0x04
    INIT = 0x06
    WINK = 0x08
    CBOR = 0x10
    CANCEL = 0x11
    KEEPALIVE = 0x3B
    ERROR = 0x3F


CMD_NAMES = {
    0x01: "PING",
    0x03: "MSG",
    0x04: "LOCK",
    0x06: "INIT",
    0x08: "WINK",
    0x10: "CBOR",
    0x11: "CANCEL",
    0x3B: "KEEPALIVE",
    0x3F: "ERROR",
}

HID_ERRORS = {
    0x01: "INVALID_CMD",
    0x02: "INVALID_PAR",
    0x03: "INVALID_LEN",
    0x04: "INVALID_SEQ",
    0x05: "MSG_TIMEOUT",
    0x06: "CHANNEL_BUSY",
    0x0A: "LOCK_REQUIRED",
    0x0B: "INVALID_CHANNEL",
    0x7F: "OTHER",
}

CTAP_STATUS = {
    0x00: "SUCCESS",
    0x01: "INVALID_COMMAND",
    0x02: "INVALID_PARAMETER",
    0x03: "INVALID_LENGTH",
    0x11: "CBOR_UNEXPECTED_TYPE",
    0x12: "INVALID_CBOR",
    0x14: "MISSING_PARAMETER",
    0x2B: "UNSUPPORTED_OPTION",
    0x2C: "INVALID_OPTION",
    0x2D: "KEEPALIVE_CANCEL",
    0x2E: "NO_CREDENTIALS",
    0x2F: "USER_ACTION_TIMEOUT",
    0x30: "NOT_ALLOWED",
    0x31: "PIN_INVALID",
    0x32: "PIN_BLOCKED",
    0x35: "PIN_NOT_SET",
    0x36: "PUAT_REQUIRED",
    # CTAP 2.1 §8.2. 0x33 (PIN_AUTH_INVALID) stays unnamed ("?"), as in the recorded runs.
    0x3E: "INVALID_SUBCOMMAND",
    0x40: "UNAUTHORIZED_PERMISSION",
    0x7F: "OTHER",
}


def init_packet(cid: int, cmd: int, bcnt: int, data: bytes = b"") -> bytes:
    if len(data) > INIT_DATA:
        raise ValueError("init data too long")
    return (struct.pack(">IBH", cid, TYPE_INIT | cmd, bcnt) + data).ljust(REPORT, b"\0")


def cont_packet(cid: int, seq: int, data: bytes = b"") -> bytes:
    if len(data) > CONT_DATA:
        raise ValueError("continuation data too long")
    if not 0 <= seq <= 0x7F:
        raise ValueError("sequence out of range")
    return (struct.pack(">IB", cid, seq) + data).ljust(REPORT, b"\0")


def fragment(cid: int, cmd: int, payload: bytes) -> list[bytes]:
    """CTAPHID fragmentation (CTAP 2.1 §11.2.4). Payloads over 7609 bytes are refused."""
    if len(payload) > MAX_PAYLOAD:
        raise ValueError(f"payload of {len(payload)} bytes cannot be framed (max {MAX_PAYLOAD})")
    packets = [init_packet(cid, cmd, len(payload), payload[:INIT_DATA])]
    rest = payload[INIT_DATA:]
    seq = 0
    while rest:
        packets.append(cont_packet(cid, seq, rest[:CONT_DATA]))
        rest = rest[CONT_DATA:]
        seq += 1
    return packets


def parse_packet(pkt: bytes) -> dict:
    cid = struct.unpack(">I", pkt[:4])[0]
    if pkt[4] & TYPE_INIT:
        cmd = pkt[4] & 0x7F
        bcnt = struct.unpack(">H", pkt[5:7])[0]
        return {"cid": cid, "init": True, "cmd": cmd, "bcnt": bcnt, "data": bytes(pkt[7:])}
    return {"cid": cid, "init": False, "seq": pkt[4], "data": bytes(pkt[5:])}


class Reassembler:
    """Reassembles CTAPHID messages per CID from a packet stream (lenient)."""

    def __init__(self):
        self.pending: dict[int, dict] = {}

    def push(self, pkt: bytes):
        """Return a complete message dict or None; incomplete ones stay pending."""
        p = parse_packet(pkt)
        cid = p["cid"]
        if p["init"]:
            msg = {"cid": cid, "cmd": p["cmd"], "bcnt": p["bcnt"], "payload": p["data"][: p["bcnt"]], "npkts": 1, "next_seq": 0}
            if len(msg["payload"]) >= msg["bcnt"]:
                self.pending.pop(cid, None)
                return msg
            self.pending[cid] = msg
            return None
        msg = self.pending.get(cid)
        if msg is None:
            return None
        if p["seq"] != msg["next_seq"]:
            self.pending.pop(cid, None)
            return None
        msg["next_seq"] += 1
        msg["npkts"] += 1
        msg["payload"] += p["data"][: msg["bcnt"] - len(msg["payload"])]
        if len(msg["payload"]) >= msg["bcnt"]:
            self.pending.pop(cid, None)
            return msg
        return None
