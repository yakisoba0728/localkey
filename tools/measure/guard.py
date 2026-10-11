"""Allowlist guard for every byte the harness sends to a device.

The physical backends create their guard themselves and call it before any byte leaves;
the engine backends use the same guard so that the engine runs prove every probe is
admitted. Only `--engine-setup` (refused for the physical key) uses an unguarded path.

The guard is an allowlist: anything it does not recognise raises GuardViolation. It is
independent of probes.py, so a wrong probe cannot widen it.

CCID (`CcidGuard`)
- tracks the selected applet from SELECTs it admitted and their status words
  (`observe`): only a first-occurrence SELECT (P2 & 3 == 0) whose data starts with one of
  the AIDs below and that answered 9000/61xx selects that applet; anything else (unknown
  AID, error, next/last occurrence, transmit failure, reconnect, PC/SC transaction start)
  leaves the selection UNKNOWN, where only SELECT and GET RESPONSE pass.
- CLA must be 00, 80, 10 or 0C. 10 (command chaining) only on read INS; after it, the same
  INS is refused until a successful SELECT. SELECT itself is CLA 00, P1 04 only (A4 with
  another P1 is CALCULATE ALL in OATH).
- per applet: the read commands below, a fixed list of undefined INS bytes with no data,
  and GET RESPONSE.

CTAPHID (`FidoGuard`)
- raw packets (`check_packet`): INIT (BCNT 8), PING (any BCNT, any CID: the malformed
  framing probes), WINK (BCNT 0), LOCK (BCNT 1, 0..10 s), CANCEL (BCNT 0), two invalid
  command bytes 0x3F/0x3E (BCNT <= 57), and CBOR/MSG only when the whole payload fits in
  the init packet (BCNT <= 57) and passes the content rules. Continuation packets pass
  unless they belong to an approved multi-packet message (then they must match it
  byte for byte) or to a CID whose approved message was interrupted (tainted).
- whole messages (`approve_message`): the content rules are checked on the complete
  payload, then the exact fragments are registered and each must pass `check_packet`.
"""

from __future__ import annotations

import struct
from collections import deque

import cbor
from common import BROADCAST, INIT_DATA, MAX_PAYLOAD, TYPE_INIT, Cmd, fragment


class GuardViolation(Exception):
    """A command the allowlist does not admit. Nothing was sent."""


# --- CCID -------------------------------------------------------------------------------

AIDS = {
    "mgmt": bytes.fromhex("A000000527471117"),
    "otp": bytes.fromhex("A0000005272001"),
    "oath": bytes.fromhex("A0000005272101"),
    "piv": bytes.fromhex("A000000308"),
    "openpgp": bytes.fromhex("D27600012401"),
    "hsmauth": bytes.fromhex("A0000005272107"),
    "sd": bytes.fromhex("A000000151000000"),
}

UNKNOWN = None

ALLOWED_CLA = {0x00, 0x80, 0x10, 0x0C}
CHAIN_BIT = 0x10

# INS bytes no public source assigns in any YubiKey applet (yubikit, the engine crates,
# ISO 7816-4, GlobalPlatform); 6X and 9X are invalid INS values in ISO 7816-3.
UNDEFINED_INS = {
    "mgmt": (0x5E, 0x6E, 0x93),
    "otp": (0x5E, 0x6E, 0x93),
    "oath": (0x5E, 0x6E, 0x93),
    "piv": (0x5E, 0x6E, 0x93),
    "openpgp": (0x5E, 0x6E, 0x93),
    "hsmauth": (0x5E, 0x6E, 0x93),
    "sd": (0x5E, 0x6E, 0x93),
}

PIV_GET_DATA = (
    bytes.fromhex("5C017E"),  # discovery object
    bytes.fromhex("5C035FC102"),  # CHUID
    bytes.fromhex("5C035FC107"),  # CCC
)
PIV_METADATA_P2 = {0x80, 0x81, 0x9B, 0x9A, 0x9C, 0x9D, 0x9E}
PIV_VERIFY_P2 = {0x80, 0x81}
OPENPGP_GET_DATA = {0x006E, 0x0065, 0x007A, 0x00C4, 0x5F52, 0x7F74, 0x004F}
OPENPGP_VERIFY_P2 = {0x81, 0x82, 0x83}
SD_GET_DATA = {0x00E0, 0x0066, 0x9F7F}
# P1P2 values that name no data object, for the "wrong P1P2" error probes on GET DATA.
INVALID_DO_P1P2 = {0x0000, 0x3FFF}
OTP_READ_P1 = {0x10, 0x13}  # device serial, YubiKey 4 capabilities (device info)

MAX_APDU = 40


def read_body_ok(body: bytes, allowed_data) -> bool:
    """Whether `body` is a (possibly mis-sized) body of a read command.

    With a data field: one header of 1 byte (short Lc) or 3 bytes starting with 00
    (extended Lc), whatever value it claims, then one complete allowed data field, then at
    most 2 bytes (Le). The data field is always complete, so no reading of the bytes can
    name another object. Without a data field: empty, an Le (1 byte, or 00 and 2 bytes),
    or `01 00` (Lc 1 with one zero data byte). This admits the well-formed cases 1-4 in
    short and extended form and the Lc/Le mismatch probes, and nothing else.
    """
    for data in allowed_data:
        if not data:
            if len(body) <= 1 or (len(body) == 3 and body[0] == 0) or body == b"\x01\x00":
                return True
            continue
        for head in (1, 3):
            if head == 3 and (len(body) < 3 or body[0] != 0):
                continue
            if body[head : head + len(data)] == data and 0 <= len(body) - head - len(data) <= 2:
                return True
    return False


def _le_only(body: bytes) -> bool:
    return len(body) == 0 or len(body) == 1 or (len(body) == 3 and body[0] == 0)


class CcidGuard:
    def __init__(self):
        self.applet = UNKNOWN
        self.chain_ins = None

    def reset(self):
        """Reconnect, card reset or another PC/SC client may have run: nothing is known."""
        self.applet = UNKNOWN
        self.chain_ins = None

    @staticmethod
    def applet_for(aid: bytes):
        for name, prefix in AIDS.items():
            if aid.startswith(prefix):
                return name
        return UNKNOWN

    def check(self, command: bytes) -> str:
        """Return the rule that admits `command`, or raise GuardViolation."""
        command = bytes(command)
        if len(command) < 4:
            raise GuardViolation("APDU shorter than its header")
        if len(command) > MAX_APDU:
            raise GuardViolation(f"APDU of {len(command)} bytes; no admitted command is longer than {MAX_APDU}")
        cla, ins, p1, p2 = command[:4]
        body = command[4:]
        if cla not in ALLOWED_CLA:
            raise GuardViolation(f"CLA {cla:02X} not admitted")
        chained = bool(cla & CHAIN_BIT)

        if ins == 0xA4:
            if cla != 0x00:
                raise GuardViolation("SELECT only with CLA 00")
            if p1 != 0x04:
                raise GuardViolation(f"SELECT only by AID (P1 04), not P1 {p1:02X}")
            if not body or not 1 <= body[0] <= 16 or len(body) not in (1 + body[0], 2 + body[0]):
                raise GuardViolation("SELECT needs Lc, an AID of 1..16 bytes and an optional Le")
            return "select"

        if self.chain_ins is not None and ins == self.chain_ins:
            raise GuardViolation(f"INS {ins:02X} while its CLA-10 chain may still be open (SELECT first)")

        if ins == 0xC0:
            if chained:
                raise GuardViolation("GET RESPONSE with the chaining bit")
            if not _le_only(body):
                raise GuardViolation("GET RESPONSE carries no data")
            return "get-response"

        applet = self.applet
        if applet is UNKNOWN:
            raise GuardViolation("no known applet is selected; only SELECT and GET RESPONSE pass")

        if ins in UNDEFINED_INS[applet]:
            if chained:
                raise GuardViolation("undefined INS with the chaining bit")
            if not _le_only(body):
                raise GuardViolation("undefined-INS probes carry no data")
            return f"{applet}:undefined-ins"

        rule = self._applet_rule(applet, cla, ins, p1, p2, body)
        if rule is None:
            raise GuardViolation(f"{applet}: CLA {cla:02X} INS {ins:02X} P1 {p1:02X} P2 {p2:02X} body {body.hex()} not admitted")
        if chained:
            if not rule.endswith(":read"):
                raise GuardViolation("the chaining bit only on read commands")
            self.chain_ins = ins
        return rule

    @staticmethod
    def _applet_rule(applet, cla, ins, p1, p2, body):
        p1p2 = p1 << 8 | p2
        if applet == "mgmt":
            if ins == 0x1D and read_body_ok(body, [b""]):
                return "mgmt:read-config:read"
        elif applet == "otp":
            # INS 01's P1 is the OTP command (01/03 are slot writes): pinned, never varied.
            if ins == 0x01 and p1 in OTP_READ_P1 and read_body_ok(body, [b""]):
                return "otp:read:read"
        elif applet == "piv":
            if ins == 0xCB and read_body_ok(body, PIV_GET_DATA):
                return "piv:get-data:read"
            if ins in (0xFD, 0xF8) and read_body_ok(body, [b""]):
                return "piv:version-serial:read"
            if ins == 0xF7 and p2 in PIV_METADATA_P2 and read_body_ok(body, [b""]):
                return "piv:metadata:read"
            if ins == 0x20 and cla != CHAIN_BIT and p1 == 0x00 and p2 in PIV_VERIFY_P2 and body == b"":
                return "piv:verify-status"
        elif applet == "openpgp":
            if ins == 0xCA and p1p2 in OPENPGP_GET_DATA | INVALID_DO_P1P2 and read_body_ok(body, [b""]):
                return "openpgp:get-data:read"
            if ins == 0x20 and cla != CHAIN_BIT and p1 == 0x00 and p2 in OPENPGP_VERIFY_P2 and body == b"":
                return "openpgp:verify-status"
        elif applet == "sd":
            if ins == 0xCA and p1p2 in SD_GET_DATA | INVALID_DO_P1P2 and read_body_ok(body, [b""]):
                return "sd:get-data:read"
        # oath, hsmauth: SELECT, GET RESPONSE and undefined INS only
        return None

    def observe(self, command: bytes, sw: int | None):
        """Update the selection after a command was sent (sw None: transmit failed)."""
        command = bytes(command)
        if sw is None:
            self.reset()
            return
        if len(command) >= 5 and command[1] == 0xA4:
            p2 = command[3]
            aid = command[5 : 5 + command[4]]
            ok = sw == 0x9000 or (sw >> 8) == 0x61
            if ok and p2 & 0x03 == 0:
                self.applet = self.applet_for(aid)
                self.chain_ins = None
            else:
                self.applet = UNKNOWN


# --- CTAPHID ----------------------------------------------------------------------------

INVALID_HID_CMDS = {0x3F, 0x3E}  # below the vendor range 0x40..0x7F (Yubico uses 0x40-0x43)

CTAP_GET_ASSERTION = 0x02
CTAP_GET_INFO = 0x04
CTAP_CLIENT_PIN = 0x06
CTAP_SELECTION = 0x0B
CTAP_UNKNOWN = {0x03, 0x05}  # never assigned in CTAP 2.0/2.1/2.2
CLIENT_PIN_READS = {1, 2, 7}  # getPINRetries, getKeyAgreement, getUVRetries
HARD_BLOCK_CBOR = {
    0x01: "makeCredential",
    0x07: "reset",
    0x08: "getNextAssertion",
    0x09: "bioEnrollment",
    0x0A: "credentialManagement",
    0x0C: "largeBlobs",
    0x0D: "config",
    0x40: "bioEnrollment (preview)",
    0x41: "credentialManagement (preview)",
}
U2F_UNKNOWN_INS = {0x05, 0x3F}


def check_cbor(payload: bytes) -> str:
    """Content rule for a complete CTAPHID_CBOR payload."""
    payload = bytes(payload)
    if not payload:
        return "cbor:empty"
    command, params = payload[0], payload[1:]
    if command in HARD_BLOCK_CBOR:
        raise GuardViolation(f"CTAP2 {HARD_BLOCK_CBOR[command]} (0x{command:02X}) is hard-blocked")
    if command == CTAP_GET_INFO:
        if len(params) > 16:
            raise GuardViolation("getInfo with more than 16 trailing bytes")
        return "cbor:getInfo" if not params else "cbor:getInfo+trailing"
    if command == CTAP_SELECTION:
        if params:
            raise GuardViolation("selection takes no parameters")
        return "cbor:selection"
    if command in CTAP_UNKNOWN:
        if len(params) > 16:
            raise GuardViolation("unknown-command probe with more than 16 bytes")
        return "cbor:unknown-command"
    try:
        request = cbor.decode(params)
    except cbor.CborError as error:
        raise GuardViolation(f"CTAP2 0x{command:02X} with undecodable parameters: {error}") from error
    if not isinstance(request, dict):
        raise GuardViolation("CTAP2 parameters must be a map")
    if command == CTAP_CLIENT_PIN:
        if not set(request) <= {1, 2}:
            raise GuardViolation(f"clientPIN with keys {sorted(map(str, request))}: only 1 and 2 are admitted")
        if request.get(2) not in CLIENT_PIN_READS or isinstance(request.get(2), bool):
            raise GuardViolation(f"clientPIN subCommand {request.get(2)!r} is not admitted (only 1, 2, 7)")
        if 1 in request and (request[1] not in (1, 2) or isinstance(request[1], bool)):
            raise GuardViolation("clientPIN pinUvAuthProtocol must be 1 or 2")
        return f"cbor:clientPIN:{request[2]}"
    if command == CTAP_GET_ASSERTION:
        if not set(request) <= {1, 2, 3, 5}:
            raise GuardViolation(f"getAssertion with keys {sorted(map(str, request))}: only 1, 2, 3, 5")
        rp = request.get(1)
        if not isinstance(rp, str) or not rp.endswith(".invalid") or len(rp) > 253:
            raise GuardViolation("getAssertion rpId must end in .invalid")
        if not isinstance(request.get(2), bytes):
            raise GuardViolation("getAssertion clientDataHash must be a byte string")
        if request.get(5) != {"up": False} or request[5]["up"] is not False:
            raise GuardViolation("getAssertion options must be exactly {up: false}")
        if 3 in request:
            allow = request[3]
            if not isinstance(allow, list) or len(allow) > 4:
                raise GuardViolation("getAssertion allowList must be a short array")
            for entry in allow:
                if not isinstance(entry, dict) or set(entry) != {"type", "id"} or entry["type"] != "public-key" or not isinstance(entry["id"], bytes):
                    raise GuardViolation("getAssertion allowList entries must be {type, id}")
        return "cbor:getAssertion:up-false"
    raise GuardViolation(f"CTAP2 command 0x{command:02X} is not admitted")


def check_u2f(payload: bytes) -> str:
    """Content rule for a complete CTAPHID_MSG (U2F raw message) payload."""
    payload = bytes(payload)
    if len(payload) < 4:
        raise GuardViolation("U2F message shorter than its header")
    if len(payload) > 4 + 3 + 32 + 32 + 1 + 255 + 2:
        raise GuardViolation("U2F message too long")
    cla, ins, p1, p2 = payload[:4]
    body = payload[4:]
    if ins == 0x01:
        raise GuardViolation("U2F REGISTER is hard-blocked")
    if ins == 0x02:
        if p1 != 0x07:
            raise GuardViolation(f"U2F AUTHENTICATE only check-only (P1 07), not P1 {p1:02X}")
        return "u2f:authenticate-check-only"
    if ins == 0x03:
        if p1 != 0 or p2 != 0 or len(body) > 5 or any(body):
            raise GuardViolation("U2F VERSION carries no data")
        return "u2f:version"
    if ins in U2F_UNKNOWN_INS:
        if len(body) > 5 or any(body):
            raise GuardViolation("unknown-INS probe carries no data")
        return "u2f:unknown-ins"
    raise GuardViolation(f"U2F INS {ins:02X} not admitted")


class FidoGuard:
    def __init__(self):
        self.expected: dict[int, deque] = {}
        self.tainted: set[int] = set()

    def check_packet(self, pkt: bytes) -> str:
        pkt = bytes(pkt)
        if len(pkt) != 64:
            raise GuardViolation(f"CTAPHID packet of {len(pkt)} bytes")
        cid = struct.unpack(">I", pkt[:4])[0]
        queue = self.expected.get(cid)
        if queue is not None:
            if pkt != queue[0]:
                raise GuardViolation(f"CID {cid:08X} is in the middle of an approved message; this packet is not its next fragment")
            queue.popleft()
            if not queue:
                del self.expected[cid]
            return "approved-fragment"
        if pkt[4] & TYPE_INIT:
            command = pkt[4] & 0x7F
            bcnt = pkt[5] << 8 | pkt[6]
            data = pkt[7 : 7 + min(bcnt, INIT_DATA)]
            reserved = cid in (0, BROADCAST)
            if command == Cmd.PING:
                return "hid:ping"
            if cid == 0:
                raise GuardViolation("the reserved CID 0 carries PING only")
            if command == Cmd.INIT:
                if bcnt != 8:
                    raise GuardViolation("INIT needs BCNT 8")
                return "hid:init"
            if command == Cmd.WINK:
                if bcnt != 0:
                    raise GuardViolation("WINK needs BCNT 0")
                return "hid:wink"
            if command == Cmd.CANCEL:
                if bcnt != 0:
                    raise GuardViolation("CANCEL needs BCNT 0")
                return "hid:cancel"
            if command == Cmd.LOCK:
                if bcnt != 1 or data[0] > 10:
                    raise GuardViolation("LOCK needs BCNT 1 and 0..10 seconds")
                return "hid:lock"
            if command in INVALID_HID_CMDS:
                if bcnt > INIT_DATA:
                    raise GuardViolation("invalid-command probes fit in one packet")
                return "hid:invalid-command"
            if command in (Cmd.CBOR, Cmd.MSG):
                if reserved:
                    raise GuardViolation("CBOR/MSG on the broadcast or reserved CID")
                if bcnt > INIT_DATA:
                    raise GuardViolation("a raw CBOR/MSG init packet must hold its whole payload (BCNT <= 57); use send_message")
                return check_cbor(data) if command == Cmd.CBOR else check_u2f(data)
            raise GuardViolation(f"CTAPHID command 0x{command:02X} not admitted")
        if cid in self.tainted:
            raise GuardViolation(f"CID {cid:08X} has an interrupted approved message; raw continuations are refused")
        return "hid:continuation"

    def approve_message(self, cid: int, command: int, payload: bytes) -> list[bytes]:
        """Check a whole message, register its fragments and return them."""
        payload = bytes(payload)
        if cid in self.expected:
            raise GuardViolation(f"CID {cid:08X} already has an approved message in flight")
        if command == Cmd.PING:
            if len(payload) > MAX_PAYLOAD:
                raise GuardViolation("PING longer than 7609 bytes cannot be framed (SEQ would reach 0x80)")
        elif command == Cmd.CBOR:
            if cid in (0, BROADCAST):
                raise GuardViolation("CBOR on the broadcast or reserved CID")
            check_cbor(payload)
        elif command == Cmd.MSG:
            if cid in (0, BROADCAST):
                raise GuardViolation("MSG on the broadcast or reserved CID")
            check_u2f(payload)
        elif command in (Cmd.INIT, Cmd.WINK, Cmd.LOCK, Cmd.CANCEL):
            if len(payload) > INIT_DATA:
                raise GuardViolation("single-packet command with a long payload")
        else:
            raise GuardViolation(f"message command 0x{command:02X} not admitted")
        packets = fragment(cid, command, payload)
        if len(packets) == 1:
            self.check_packet(packets[0])  # single packets go through the raw rules
        else:
            self.expected[cid] = deque(packets)
        return packets

    def abandon(self, cid: int):
        """An approved multi-packet send stopped part-way: taint the CID."""
        if cid in self.expected:
            del self.expected[cid]
            self.tainted.add(cid)


def guard_table() -> list[tuple[str, str]]:
    """The admitted commands, for the README and the report."""
    return [
        ("any applet", "SELECT by AID (CLA 00, A4 04 P2, Lc 1..16, optional Le); GET RESPONSE C0 without data; undefined INS 5E/6E/93 without data; CLA 80/0C on admitted INS; CLA 10 only on read INS, then that INS is refused until a successful SELECT"),
        ("Management A000000527471117", "READ CONFIG 1D (any P1/P2, no data; Lc/Le variants)"),
        ("OTP A0000005272001", "INS 01 with P1 10 (serial) or 13 (capabilities) only; P2 and Le variants"),
        ("OATH A0000005272101", "SELECT, GET RESPONSE, undefined INS only"),
        ("PIV A000000308", "GET DATA CB with data 5C017E / 5C035FC102 / 5C035FC107; GET VERSION FD; GET SERIAL F8; GET METADATA F7 with P2 80 81 9B 9A 9C 9D 9E; VERIFY 20 P1 00 P2 80/81 with an empty body"),
        ("OpenPGP D27600012401", "GET DATA CA with P1P2 006E 0065 007A 00C4 5F52 7F74 004F (and 0000/3FFF as wrong-P1P2 probes); VERIFY 20 P1 00 P2 81/82/83 with an empty body"),
        ("HSM Auth A0000005272107", "SELECT, GET RESPONSE, undefined INS only"),
        ("Security Domain A000000151000000", "GET DATA CA 00E0 / 0066 / 9F7F (and 0000/3FFF as wrong-P1P2 probes)"),
        ("CTAPHID", "INIT (BCNT 8), PING (any length, any CID incl. 0 and broadcast, malformed framing), WINK, LOCK 0..10 s, CANCEL, invalid commands 3F/3E (BCNT <= 57); raw CBOR/MSG only if BCNT <= 57; continuations unless they would continue an approved or interrupted CBOR/MSG"),
        ("CTAP2 (CBOR)", "getInfo (04, up to 16 trailing bytes); clientPIN (06) keys {1,2} with subCommand 1/2/7; selection (0B); getAssertion (02) keys {1,2,3,5}, rpId *.invalid, options exactly {up:false}; unknown commands 03/05; empty payload"),
        ("U2F (MSG)", "VERSION (03, no data); AUTHENTICATE (02) with P1 07 only; unknown INS 05/3F without data; any CLA"),
    ]
