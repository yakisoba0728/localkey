"""Guard tests: every probe is admitted, every dangerous command is refused.

Run: python -m unittest discover -s tools/measure -p 'test_*.py'
No device, socket or daemon is used: the probes run against the engine backends with an
in-process fake link (FakeLink) that answers like a minimal YubiKey.
"""

from __future__ import annotations

import os
import queue
import struct
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cbor  # noqa: E402
import measure  # noqa: E402
import probes  # noqa: E402
from common import BROADCAST, Cmd, apdu, cont_packet, fragment, init_packet, parse_packet, select  # noqa: E402
from engine import CCID_BULK_OUT, FIDO_OUT, EngineCcid, EngineFido  # noqa: E402
from guard import AIDS, CcidGuard, FidoGuard, GuardViolation, check_cbor, check_u2f  # noqa: E402

H = bytes.fromhex


# --- a fake device behind the engine backends ------------------------------------------------


class FakeCard:
    """Answers SELECT by AID prefix like the engine and a 61xx chain for OpenPGP 6E."""

    def __init__(self):
        self.pending = b""
        self.seen: list[bytes] = []

    def process(self, command: bytes) -> bytes:
        self.seen.append(command)
        ins = command[1]
        if ins == 0xA4:
            aid = command[5 : 5 + command[4]]
            ok = any(aid.startswith(prefix) for prefix in AIDS.values())
            return b"\x90\x00" if ok else b"\x6a\x82"
        if ins == 0xCA and command[2:4] == b"\x00\x6e":
            body = bytes(range(256)) + bytes(59)
            self.pending = body[256:]
            return body[:256] + b"\x61" + bytes([len(self.pending)])
        if ins == 0xC0 and self.pending:
            n = command[4] if len(command) > 4 and command[4] else 256
            part, self.pending = self.pending[:n], self.pending[n:]
            return part + (b"\x61" + bytes([len(self.pending)]) if self.pending else b"\x90\x00")
        return b"\x90\x00"


class FakeCtaphid:
    """A small CTAPHID responder: INIT, PING (with assembly, busy, timeout), WINK, LOCK,
    CANCEL, CBOR (selection answers after 0.3 s), MSG, invalid commands."""

    def __init__(self, out_q: queue.Queue):
        self.out_q = out_q
        self.next_cid = 0x100
        self.assembling = None  # (cid, cmd, bcnt, payload, next_seq, started)
        self.selection = None  # (cid, started)
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._timers, daemon=True)
        self.thread.start()

    def _send(self, cid, command, payload=b""):
        for pkt in fragment(cid, command, payload):
            self.out_q.put((time.monotonic(), pkt))

    def _timers(self):
        while not self.stop.is_set():
            with self.lock:
                now = time.monotonic()
                if self.assembling and now - self.assembling[5] > 0.2:
                    self._send(self.assembling[0], Cmd.ERROR, b"\x05")
                    self.assembling = None
                if self.selection and now - self.selection[1] > 0.3:
                    self._send(self.selection[0], Cmd.CBOR, b"\x2f")
                    self.selection = None
            time.sleep(0.01)

    def packet(self, pkt: bytes):
        with self.lock:
            p = parse_packet(pkt)
            cid = p["cid"]
            if not p["init"]:
                a = self.assembling
                if not a or a[0] != cid:
                    return
                if p["seq"] != a[4]:
                    self.assembling = None
                    return self._send(cid, Cmd.ERROR, b"\x04")
                payload = a[3] + p["data"][: a[2] - len(a[3])]
                if len(payload) < a[2]:
                    self.assembling = (cid, a[1], a[2], payload, a[4] + 1, time.monotonic())
                    return
                self.assembling = None
                return self._execute(cid, a[1], payload)
            command, bcnt = p["cmd"], p["bcnt"]
            if command == Cmd.INIT:
                if cid == BROADCAST:
                    self.next_cid += 1
                    new = self.next_cid
                else:
                    new = cid
                return self._send(cid, Cmd.INIT, p["data"][:8] + struct.pack(">I", new) + bytes([2, 5, 7, 4, 5]))
            if cid in (0, BROADCAST):
                return self._send(cid, Cmd.ERROR, b"\x0b")
            if command == Cmd.CANCEL:
                if self.selection and self.selection[0] == cid:
                    self.selection = None
                    self._send(cid, Cmd.CBOR, b"\x2d")
                return
            if self.assembling and self.assembling[0] != cid:
                return self._send(cid, Cmd.ERROR, b"\x06")
            if command not in (Cmd.PING, Cmd.MSG, Cmd.LOCK, Cmd.WINK, Cmd.CBOR):
                return self._send(cid, Cmd.ERROR, b"\x01")
            if bcnt > 7609:
                return self._send(cid, Cmd.ERROR, b"\x03")
            if bcnt > 57:
                self.assembling = (cid, command, bcnt, p["data"], 0, time.monotonic())
                return
            self._execute(cid, command, p["data"][:bcnt])

    def _execute(self, cid, command, payload):
        if command == Cmd.PING:
            return self._send(cid, Cmd.PING, payload)
        if command in (Cmd.WINK, Cmd.LOCK):
            return self._send(cid, command)
        if command == Cmd.MSG:
            return self._send(cid, Cmd.MSG, b"U2F_V2\x90\x00" if payload[1:2] == b"\x03" else b"\x6a\x80")
        if command == Cmd.CBOR:
            if not payload:
                return self._send(cid, Cmd.ERROR, b"\x03")
            if payload[0] == 0x0B:
                self.selection = (cid, time.monotonic())
                return self._send(cid, Cmd.KEEPALIVE, b"\x02")
            if payload[0] == 0x04:
                return self._send(cid, Cmd.CBOR, b"\x00" + cbor.encode({1: ["FIDO_2_0"], 3: bytes(16)}))
            return self._send(cid, Cmd.CBOR, b"\x01")


class FakeLink:
    def __init__(self):
        self.ccid_q: queue.Queue = queue.Queue()
        self.fido_q: queue.Queue = queue.Queue()
        self.identity = {"vid": 0x1050, "pid": 0x0406}
        self.identity_count = 1
        self.card = FakeCard()
        self.hid = FakeCtaphid(self.fido_q)
        self.fido_out: list[bytes] = []

    def send(self, kind: int, payload: bytes):
        if kind == CCID_BULK_OUT:
            seq = payload[6]
            if payload[0] == 0x62:
                data = H("3BFD1300008131FE158073C021C057597562694B657940")
            else:
                data = self.card.process(payload[10:])
            self.ccid_q.put(struct.pack("<BIBB", 0x80, len(data), 0, seq) + b"\x00\x00\x00" + data)
        elif kind == FIDO_OUT:
            self.fido_out.append(payload)
            self.hid.packet(payload)


class FakeTarget:
    name = "fake"

    def __init__(self):
        self.link = FakeLink()
        self.ccid = EngineCcid(self.link)
        self.fido = EngineFido(self.link)
        self.info = {}


# --- every probe passes ----------------------------------------------------------------------


class EveryProbeIsAdmitted(unittest.TestCase):
    def test_every_probe_runs_through_the_guard_without_a_refusal(self):
        target = FakeTarget()
        selected = probes.select_probes(probes.ALL_SETS)
        self.assertEqual(len(selected), len(probes.PROBES))
        results = measure.run_probes(target, selected, progress=False, settle=0)
        target.link.hid.stop.set()
        refused = [(r["id"], r["error"]) for r in results if r["error"]]
        self.assertEqual(refused, [])
        self.assertTrue(target.link.card.seen)
        self.assertTrue(target.link.fido_out)
        # every byte that reached the fake device passes a fresh guard again (replay)
        replay = CcidGuard()
        for command in target.link.card.seen:
            replay.check(command)
            sw = 0x9000 if command[1] != 0xA4 or any(command[5 : 5 + command[4]].startswith(a) for a in AIDS.values()) else 0x6A82
            replay.observe(command, sw)

    def test_sets_and_counts(self):
        counts = {s: sum(1 for p in probes.PROBES if p.set == s) for s in probes.ALL_SETS}
        self.assertEqual(set(counts), set(probes.ALL_SETS))
        self.assertTrue(all(counts.values()))
        ids = [(p.set, p.id) for p in probes.PROBES]
        self.assertEqual(len(ids), len(set(ids)))


# --- CCID refusals ---------------------------------------------------------------------------


def guard_in(applet: str) -> CcidGuard:
    g = CcidGuard()
    command = select(AIDS[applet])
    g.check(command)
    g.observe(command, 0x9000)
    assert g.applet == applet
    return g


DANGEROUS_CCID = {
    "piv": [
        ("VERIFY with a PIN", H("002000800831323334FFFFFFFF")),
        ("VERIFY P1 FF (reset verification)", H("0020FF80")),
        ("VERIFY P2 82", H("00200082")),
        ("VERIFY with CLA 10", H("10200080")),
        ("VERIFY with an Le byte", H("0020008000")),
        ("GENERATE ASYMMETRIC", H("00470009AC03800111")),
        ("PUT DATA", H("00DB3FFF055C035FC102")),
        ("GENERAL AUTHENTICATE", H("00870392047C028100")),
        ("IMPORT KEY", H("00FE119A00")),
        ("RESET", H("00FB0000")),
        ("SET MANAGEMENT KEY", H("00FFFFFF1B")),
        ("SET PIN RETRIES", H("00FA0303")),
        ("CHANGE REFERENCE", H("002400801031323334FFFFFFFF31323334FFFFFFFF")),
        ("RESET RETRY", H("002C00801031323334353637383132333435363738")),
        ("ATTEST", H("00F99A00")),
        ("MOVE/DELETE KEY", H("00F6FF9A")),
        ("GET METADATA of slot 95", H("00F70095")),
        ("GET DATA of the 9A certificate", H("00CB3FFF055C035FC105")),
        ("GET DATA with extra data", H("00CB3FFF0A5C035FC1025C035FC105")),
        ("GET RESPONSE with data", H("00C00000020102")),
    ],
    "openpgp": [
        ("VERIFY with a PIN", H("0020008106313233343536")),
        ("VERIFY P1 FF", H("0020FF81")),
        ("TERMINATE DF", H("00E60000")),
        ("ACTIVATE FILE", H("00440000")),
        ("PUT DATA", H("00DA005B0441424344")),
        ("PUT DATA odd", H("00DB3FFF00")),
        ("PSO", H("002A9E9A00")),
        ("INTERNAL AUTHENTICATE", H("0088000000")),
        ("GENERATE", H("00478000000002B600")),
        ("GET CHALLENGE", H("0084000008")),
        ("CHANGE REFERENCE", H("00240081")),
        ("RESET RETRY COUNTER", H("002C0281")),
        ("Yubico F1", H("00F10000")),
        ("GET DATA login 5E", H("00CA005E")),
        ("GET DATA URL 5F50", H("00CA5F50")),
        ("GET DATA private DO 0101", H("00CA0101")),
    ],
    "sd": [
        ("INITIALIZE UPDATE", H("8050000008" + "00" * 8)),
        ("EXTERNAL AUTHENTICATE", H("8482330010" + "00" * 16)),
        ("INTERNAL AUTHENTICATE", H("80880000")),
        ("PSO", H("802A0000")),
        ("PUT KEY", H("80D80001")),
        ("DELETE", H("80E40000")),
        ("STORE DATA", H("80E20000")),
        ("SET STATUS", H("80F00000")),
        ("GET DATA C1", H("80CA00C1")),
    ],
    "mgmt": [
        ("WRITE CONFIG", H("001C000007060302033A0C00")),
        ("DEVICE RESET", H("001F0000")),
        ("SET MODE", H("0016110000")),
    ],
    "otp": [
        ("slot 1 configure", H("00010100")),
        ("slot 2 configure", H("00010300")),
        ("update slot", H("00010400")),
        ("swap slots", H("00010600")),
        ("device config", H("00011100")),
        ("HMAC challenge slot 2", H("00013800")),
        ("serial with data", H("00011000020102")),
    ],
    "oath": [
        ("PUT", H("00010000")),
        ("DELETE", H("00020000")),
        ("SET CODE", H("00030000")),
        ("RESET", H("0004DEAD")),
        ("CALCULATE", H("00A20001")),
        ("CALCULATE ALL (A4 with P1 00)", H("00A4000100")),
        ("VALIDATE", H("00A30000")),
        ("LIST", H("00A10000")),
        ("SEND REMAINING", H("00A50000")),
    ],
    "hsmauth": [
        ("RESET", H("0006DEAD")),
        ("PUT", H("00010000")),
        ("CALCULATE", H("00030000")),
        ("GET CHALLENGE", H("00040000")),
    ],
}


class CcidRefusals(unittest.TestCase):
    def test_dangerous_commands_are_refused_in_their_applet(self):
        for applet, items in DANGEROUS_CCID.items():
            for name, command in items:
                with self.subTest(applet=applet, command=name):
                    g = guard_in(applet)
                    with self.assertRaises(GuardViolation):
                        g.check(command)

    def test_nothing_but_select_without_a_known_selection(self):
        g = CcidGuard()
        for command in (H("00CB3FFF035C017E"), H("001D0000"), H("00CA006E"), H("005E0000")):
            with self.assertRaises(GuardViolation):
                g.check(command)
        g.check(H("00C0000000"))  # GET RESPONSE passes anywhere

    def test_selection_becomes_unknown_after_failures_and_odd_selects(self):
        cases = [
            (select(AIDS["piv"]), 0x6A82),  # failed SELECT
            (select(AIDS["piv"], 0x02), 0x9000),  # next occurrence
            (select(H("A0000003")), 0x9000),  # partial AID: which applet is unknown
            (select(H("A0000005")), 0x9000),
        ]
        for command, sw in cases:
            with self.subTest(command=command.hex()):
                g = guard_in("piv")
                g.check(command)
                g.observe(command, sw)
                with self.assertRaises(GuardViolation):
                    g.check(H("00CB3FFF035C017E"))
        g = guard_in("piv")
        g.observe(H("00FD0000"), None)  # transmit failure
        with self.assertRaises(GuardViolation):
            g.check(H("00FD0000"))
        g = guard_in("piv")
        g.reset()  # reconnect / PC/SC transaction start
        with self.assertRaises(GuardViolation):
            g.check(H("00FD0000"))

    def test_select_forms(self):
        g = CcidGuard()
        for bad in (H("80A4040005A000000308"), H("00A4000002"), H("00A4000C023F00"), H("10A4040005A000000308"), H("00A40400"), H("00A4040011" + "00" * 17), H("00A4040005A0000003")):
            with self.subTest(command=bad.hex()):
                with self.assertRaises(GuardViolation):
                    g.check(bad)

    def test_cla_rules(self):
        g = guard_in("piv")
        for bad in (H("01CB3FFF035C017E"), H("84CB3FFF035C017E"), H("E0CB3FFF035C017E")):
            with self.assertRaises(GuardViolation):
                g.check(bad)
        g.check(H("80CB3FFF035C017E"))
        g.check(H("0CCB3FFF035C017E"))
        g.check(H("10CB3FFF035C017E"))  # chain left open
        with self.assertRaises(GuardViolation):
            g.check(H("00CB3FFF035C017E"))  # would continue the chain
        with self.assertRaises(GuardViolation):
            g.check(H("10CB3FFF035C017E"))
        g.check(H("00FD0000"))  # another INS is fine
        g.check(select(AIDS["piv"]))
        g.observe(select(AIDS["piv"]), 0x6A82)  # a failed SELECT does not close the chain
        g.check(select(AIDS["piv"]))
        g.observe(select(AIDS["piv"]), 0x9000)
        g.check(H("00CB3FFF035C017E"))
        with self.assertRaises(GuardViolation):
            g.check(H("105E0000"))  # chaining bit on an undefined INS

    def test_length_variants_stay_inside_the_read(self):
        g = guard_in("piv")
        for ok in (H("00CB3FFF035C017E"), H("00CB3FFF035C017E00"), H("00CB3FFF0000035C017E0000"), H("00CB3FFF055C017E"), H("00CB3FFF025C017E")):
            g.check(ok)
        for bad in (H("00CB3FFF085C017E5C017E5C"), H("00CB3FFF03AABBCC0102030405")):
            with self.assertRaises(GuardViolation):
                g.check(bad)
        with self.assertRaises(GuardViolation):
            g.check(H("00CB3FFF" + "00" * 40))  # too long

    def test_otp_p1_is_pinned(self):
        g = guard_in("otp")
        g.check(H("00011000"))
        g.check(H("00011301"))
        for p1 in range(256):
            if p1 not in (0x10, 0x13):
                with self.assertRaises(GuardViolation):
                    g.check(bytes([0x00, 0x01, p1, 0x00]))


# --- CTAPHID refusals ------------------------------------------------------------------------

CID = 0x01020304


def cbor_msg(command: int, params=None) -> bytes:
    return bytes([command]) + (cbor.encode(params) if params is not None else b"")


DANGEROUS_CBOR = [
    ("makeCredential", cbor_msg(0x01, {1: bytes(32), 2: {"id": "example.com"}, 3: {"id": b"u"}, 4: [{"alg": -7, "type": "public-key"}]})),
    ("makeCredential malformed", b"\x01"),
    ("makeCredential with trailing garbage", b"\x01\xff\xff"),
    ("reset", b"\x07"),
    ("getNextAssertion", b"\x08"),
    ("bioEnrollment", cbor_msg(0x09, {1: 1, 2: 1})),
    ("credentialManagement", cbor_msg(0x0A, {1: 1})),
    ("credentialManagement preview", cbor_msg(0x41, {1: 1})),
    ("bioEnrollment preview", b"\x40"),
    ("largeBlobs", cbor_msg(0x0C, {1: 1024, 3: 0})),
    ("config", cbor_msg(0x0D, {1: 1})),
    ("clientPIN getPinToken", cbor_msg(0x06, {1: 2, 2: 5})),
    ("clientPIN setPIN", cbor_msg(0x06, {1: 2, 2: 3})),
    ("clientPIN changePIN", cbor_msg(0x06, {1: 2, 2: 4})),
    ("clientPIN getPinUvAuthTokenUsingUv", cbor_msg(0x06, {1: 2, 2: 6})),
    ("clientPIN subCommand 8", cbor_msg(0x06, {1: 2, 2: 8})),
    ("clientPIN getPinUvAuthTokenUsingPin", cbor_msg(0x06, {1: 2, 2: 9})),
    ("clientPIN subCommand true", cbor_msg(0x06, {1: 2, 2: True})),
    ("clientPIN getKeyAgreement with a key", cbor_msg(0x06, {1: 2, 2: 2, 3: {1: 2}})),
    ("clientPIN with a PIN hash", cbor_msg(0x06, {1: 2, 2: 1, 6: bytes(16)})),
    ("getAssertion up:true", cbor_msg(0x02, {1: "a.invalid", 2: bytes(32), 5: {"up": True}})),
    ("getAssertion without options", cbor_msg(0x02, {1: "a.invalid", 2: bytes(32)})),
    ("getAssertion real rpId", cbor_msg(0x02, {1: "example.com", 2: bytes(32), 5: {"up": False}})),
    ("getAssertion uv option", cbor_msg(0x02, {1: "a.invalid", 2: bytes(32), 5: {"up": False, "uv": True}})),
    ("getAssertion up 0", cbor_msg(0x02, {1: "a.invalid", 2: bytes(32), 5: {"up": 0}})),
    ("getAssertion pinUvAuthParam", cbor_msg(0x02, {1: "a.invalid", 2: bytes(32), 5: {"up": False}, 6: bytes(16), 7: 2})),
    ("getAssertion extensions", cbor_msg(0x02, {1: "a.invalid", 2: bytes(32), 4: {"hmac-secret": {}}, 5: {"up": False}})),
    ("getAssertion trailing bytes", cbor_msg(0x02, {1: "a.invalid", 2: bytes(32), 5: {"up": False}}) + b"\x00"),
    ("selection with parameters", b"\x0b\xa0"),
    ("getInfo with a long tail", b"\x04" + bytes(17)),
    ("vendor command 0x50", b"\x50"),
]

DANGEROUS_U2F = [
    ("REGISTER", H("00010300000040") + bytes(64) + b"\x00\x00"),
    ("REGISTER with wrong CLA", H("80010300000040") + bytes(64) + b"\x00\x00"),
    ("AUTHENTICATE enforce presence", H("00020300000081") + bytes(129) + b"\x00\x00"),
    ("AUTHENTICATE dont-enforce", H("00020800000081") + bytes(129) + b"\x00\x00"),
    ("AUTHENTICATE P1 00", H("00020000000081") + bytes(129) + b"\x00\x00"),
    ("VERSION with data", H("00030000000001AA0000")),
    ("vendor INS 40", H("00400000")),
]


class FidoRefusals(unittest.TestCase):
    def test_hard_blocked_cbor_is_refused_in_every_path(self):
        for name, payload in DANGEROUS_CBOR:
            with self.subTest(command=name):
                with self.assertRaises(GuardViolation):
                    check_cbor(payload)
                g = FidoGuard()
                with self.assertRaises(GuardViolation):
                    g.approve_message(CID, Cmd.CBOR, payload)
                if len(payload) <= 57:
                    with self.assertRaises(GuardViolation):
                        FidoGuard().check_packet(init_packet(CID, Cmd.CBOR, len(payload), payload))

    def test_u2f_writes_are_refused(self):
        for name, payload in DANGEROUS_U2F:
            with self.subTest(command=name):
                with self.assertRaises(GuardViolation):
                    check_u2f(payload)
                with self.assertRaises(GuardViolation):
                    FidoGuard().approve_message(CID, Cmd.MSG, payload)

    def test_make_credential_split_across_raw_packets(self):
        payload = DANGEROUS_CBOR[0][1]
        self.assertGreater(len(payload), 57)
        packets = fragment(CID, Cmd.CBOR, payload)
        g = FidoGuard()
        with self.assertRaises(GuardViolation):
            g.check_packet(packets[0])
        # a raw init that claims a long CBOR message is refused even if it starts like getInfo
        with self.assertRaises(GuardViolation):
            g.check_packet(init_packet(CID, Cmd.CBOR, 100, b"\x04" + bytes(56)))
        with self.assertRaises(GuardViolation):
            g.check_packet(init_packet(CID, Cmd.MSG, 100, H("00030000") + bytes(53)))

    def test_cbor_hidden_in_a_continuation_of_an_approved_message(self):
        g = FidoGuard()
        benign = cbor_msg(0x02, {1: "x" * 40 + ".invalid", 2: bytes(32), 5: {"up": False}})
        packets = g.approve_message(CID, Cmd.CBOR, benign)
        self.assertGreater(len(packets), 1)
        g.check_packet(packets[0])
        evil = cont_packet(CID, 0, cbor.encode({1: bytes(32), 2: {"id": "example.com"}})[:59])
        with self.assertRaises(GuardViolation):
            g.check_packet(evil)
        with self.assertRaises(GuardViolation):
            g.check_packet(init_packet(CID, Cmd.PING, 4, b"ping"))  # nothing else on this CID meanwhile
        g.check_packet(init_packet(CID + 1, Cmd.PING, 4, b"ping"))  # other CIDs are unaffected
        for pkt in packets[1:]:
            g.check_packet(pkt)
        self.assertNotIn(CID, g.expected)

    def test_interrupted_approved_message_taints_the_cid(self):
        g = FidoGuard()
        benign = cbor_msg(0x02, {1: "x" * 40 + ".invalid", 2: bytes(32), 5: {"up": False}})
        packets = g.approve_message(CID, Cmd.CBOR, benign)
        g.check_packet(packets[0])
        g.abandon(CID)
        with self.assertRaises(GuardViolation):
            g.check_packet(packets[1])  # raw framing that would complete the CBOR message
        with self.assertRaises(GuardViolation):
            g.check_packet(cont_packet(CID, 0, bytes(59)))
        g.check_packet(init_packet(CID, Cmd.INIT, 8, bytes(8)))  # INIT still passes

    def test_raw_framing_rules(self):
        g = FidoGuard()
        for bad in (
            init_packet(CID, 0x40, 0),  # Yubico vendor range (device config)
            init_packet(CID, 0x42, 0),
            init_packet(CID, 0x43, 0),
            init_packet(CID, 0x7F, 0),
            init_packet(CID, 0x3F, 58, bytes(57)),  # invalid command must fit one packet
            init_packet(CID, Cmd.LOCK, 1, b"\x0b"),
            init_packet(CID, Cmd.LOCK, 2, b"\x01\x00"),
            init_packet(CID, Cmd.WINK, 1, b"\x00"),
            init_packet(CID, Cmd.INIT, 7, bytes(7)),
            init_packet(CID, Cmd.CANCEL, 1, b"\x00"),
            init_packet(0, Cmd.INIT, 8, bytes(8)),
            init_packet(0, Cmd.CBOR, 1, b"\x04"),
            init_packet(BROADCAST, Cmd.CBOR, 1, b"\x04"),
            init_packet(BROADCAST, Cmd.MSG, 4, H("00030000")),
            bytes(63),
            bytes(65),
        ):
            with self.subTest(packet=bad.hex()[:16]):
                with self.assertRaises(GuardViolation):
                    g.check_packet(bad)
        for ok in (
            init_packet(CID, Cmd.PING, 7610, bytes(57)),
            init_packet(CID, Cmd.PING, 0xFFFF, bytes(57)),
            init_packet(0, Cmd.PING, 4, b"ping"),
            init_packet(BROADCAST, Cmd.PING, 4, b"ping"),
            cont_packet(CID, 5, bytes(59)),
            init_packet(CID, 0x3F, 0),
            init_packet(CID, Cmd.LOCK, 1, b"\x0a"),
            init_packet(CID, Cmd.CBOR, 1, b"\x04"),
            init_packet(CID, Cmd.CBOR, 1, b"\x0b"),
        ):
            g.check_packet(ok)
        with self.assertRaises(GuardViolation):
            g.approve_message(CID, Cmd.PING, bytes(7610))

    def test_admitted_cbor_and_u2f(self):
        for payload in (b"", b"\x04", b"\x04\xa0", b"\x0b", b"\x03", b"\x05", cbor_msg(0x06, {1: 2, 2: 1}), cbor_msg(0x06, {2: 7}),
                        cbor_msg(0x02, {1: "abc.invalid", 2: bytes(32), 5: {"up": False}, 3: [{"type": "public-key", "id": bytes(16)}]})):
            check_cbor(payload)
        for payload in (H("000300000000000000"), H("00030000"), H("800300000000000000"), H("000500000000000000"), H("00020700000081") + bytes(129) + b"\x00\x00"):
            check_u2f(payload)


if __name__ == "__main__":
    unittest.main()
