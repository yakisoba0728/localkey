"""Tests for the physical backend (with fake host modules only), redaction and compare.

No real PC/SC or HID call is made: PhysicalCcid and PhysicalFido receive fake
`smartcard.scard` / `fido2.hid` modules, and the test checks that no fake module function
outside the fakes is reachable.
"""

from __future__ import annotations

import os
import queue
import random
import sys
import time
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cbor  # noqa: E402
import compare  # noqa: E402
import normalize  # noqa: E402
from common import Cmd, fragment, init_packet  # noqa: E402
from guard import AIDS, CcidGuard, GuardViolation, OPENPGP_GET_DATA, PIV_GET_DATA, SD_GET_DATA, UNDEFINED_INS  # noqa: E402
from physical import PhysicalCcid, PhysicalError, PhysicalFido  # noqa: E402

H = bytes.fromhex


# --- fake smartcard.scard ------------------------------------------------------------------


class FakeScard:
    SCARD_S_SUCCESS = 0
    SCARD_E_SHARING_VIOLATION = 0x8010000B
    SCARD_SCOPE_USER = 0
    SCARD_SHARE_EXCLUSIVE = 1
    SCARD_SHARE_SHARED = 2
    SCARD_PROTOCOL_T1 = 2
    SCARD_PCI_T1 = 2
    SCARD_LEAVE_CARD = 0

    def __init__(self, readers=("Yubico YubiKey FIDO+CCID",), exclusive_ok=True):
        self.readers = list(readers)
        self.exclusive_ok = exclusive_ok
        self.calls = []
        self.sent = []
        self.responses = {}

    def SCardEstablishContext(self, scope):
        self.calls.append("establish")
        return 0, "ctx"

    def SCardListReaders(self, ctx, groups):
        self.calls.append("list")
        return 0, self.readers

    def SCardConnect(self, ctx, reader, mode, protocols):
        self.calls.append(("connect", mode))
        if mode == self.SCARD_SHARE_EXCLUSIVE and not self.exclusive_ok:
            return self.SCARD_E_SHARING_VIOLATION, None, 0
        return 0, "card", self.SCARD_PROTOCOL_T1

    def SCardStatus(self, card):
        return 0, self.readers[0], 0x34, self.SCARD_PROTOCOL_T1, list(H("3BFD1300008131FE158073C021C057597562694B657940"))

    def SCardBeginTransaction(self, card):
        self.calls.append("begin")
        return 0

    def SCardEndTransaction(self, card, disposition):
        self.calls.append(("end", disposition))
        return 0

    def SCardTransmit(self, card, pci, command):
        command = bytes(command)
        self.sent.append(command)
        if command in self.responses:
            return self.responses[command]
        if command[1] == 0xA4:
            ok = any(command[5:].startswith(a) for a in AIDS.values())
            return 0, [0x90, 0x00] if ok else [0x6A, 0x82]
        return 0, [0x90, 0x00]

    def SCardDisconnect(self, card, disposition):
        self.calls.append(("disconnect", disposition))
        return 0

    def SCardReleaseContext(self, ctx):
        self.calls.append("release")
        return 0


class PhysicalCcidWithFakes(unittest.TestCase):
    def test_guard_refuses_before_anything_is_sent(self):
        sc = FakeScard()
        card = PhysicalCcid(sc)
        self.assertEqual(card.mode, "exclusive")
        card.begin()
        for command in (H("00200080083132333435363738"), H("001C000003020302"), H("8050000008" + "00" * 8), H("00CB3FFF035C017E")):
            with self.assertRaises(GuardViolation):
                card.transmit(command)
        self.assertEqual(sc.sent, [])
        data, sw = card.transmit(H("00A4040005A000000308"))
        self.assertEqual(sw, 0x9000)
        card.transmit(H("00CB3FFF035C017E"))
        self.assertEqual(len(sc.sent), 2)
        card.close()
        self.assertIn(("disconnect", sc.SCARD_LEAVE_CARD), sc.calls)
        self.assertIn("release", sc.calls)

    def test_no_raw_send_path_and_private_guard(self):
        card = PhysicalCcid(FakeScard())
        public = {name for name in dir(card) if not name.startswith("_")}
        self.assertEqual(public, {"atr", "begin", "end", "transmit", "close", "reader", "mode"})
        self.assertEqual(card.atr()[:2], H("3BFD"))

    def test_shared_mode_uses_transactions_and_resets_the_selection(self):
        sc = FakeScard(exclusive_ok=False)
        card = PhysicalCcid(sc)
        self.assertEqual(card.mode, "shared")
        with self.assertRaises(PhysicalError):
            card.transmit(H("00A4040005A000000308"))  # outside a transaction
        card.begin()
        card.transmit(H("00A4040005A000000308"))
        card.transmit(H("00FD0000"))
        card.end()
        card.begin()  # another client may have selected something meanwhile
        with self.assertRaises(GuardViolation):
            card.transmit(H("00FD0000"))
        card.end()
        self.assertEqual(sc.calls.count("begin"), 2)
        self.assertEqual(sc.calls.count(("end", sc.SCARD_LEAVE_CARD)), 2)
        self.assertEqual(sc.sent, [H("00A4040005A000000308"), H("00FD0000")])

    def test_61xx_stays_visible_and_failures_reset_the_selection(self):
        sc = FakeScard()
        sc.responses[H("00CA006E00")] = (0, [0x01] * 256 + [0x61, 0x3B])
        sc.responses[H("00FD0000")] = (0x80100016, [])
        card = PhysicalCcid(sc)
        card.begin()
        card.transmit(H("00A4040006D27600012401"))
        data, sw = card.transmit(H("00CA006E00"))
        self.assertEqual((len(data), sw), (256, 0x613B))
        card.transmit(H("00A4040005A000000308"))
        with self.assertRaises(PhysicalError):
            card.transmit(H("00FD0000"))
        with self.assertRaises(GuardViolation):
            card.transmit(H("00F80000"))  # selection unknown after the failed transmit

    def test_reader_must_be_unique(self):
        for readers in ((), ("Yubico YubiKey OTP+FIDO+CCID", "Yubico YubiKey FIDO+CCID 01"), ("Other Reader",)):
            sc = FakeScard(readers=readers)
            with self.assertRaises(PhysicalError):
                PhysicalCcid(sc)
            self.assertIn("release", sc.calls)
            self.assertFalse(any(isinstance(c, tuple) and c[0] == "connect" for c in sc.calls))


# --- fake fido2.hid ------------------------------------------------------------------------


class FakeConnection:
    """Mimics fido2.hid.macos.MacCtapHidConnection: an IOKit callback puts reports into
    `read_queue`; read_packet raises OSError after a run-loop pass without data."""

    def __init__(self):
        self.read_queue = queue.Queue()
        self.written = []
        self.closed = False

    def write_packet(self, data):
        self.written.append(bytes(data))
        if data[4] == 0x80 | Cmd.INIT:
            reply = data[:4] + bytes([0x86, 0, 17]) + data[7:15] + H("01020304") + bytes([2, 5, 7, 4, 5])
            self.read_queue.put(reply.ljust(64, b"\0"))  # the callback path

    def read_packet(self):
        try:
            return self.read_queue.get(False)
        except queue.Empty:
            time.sleep(0.05)
            try:
                return self.read_queue.get(False)
            except queue.Empty:
                raise OSError("Failed reading a response")

    def close(self):
        self.closed = True


def fake_hid(descriptors):
    conn = FakeConnection()
    module = SimpleNamespace(list_descriptors=lambda: descriptors, open_connection=lambda d: conn)
    return module, conn


def descriptor(vid=0x1050, pid=0x0406, size=64):
    return SimpleNamespace(path="1", vid=vid, pid=pid, report_size_in=size, report_size_out=size, product_name="YubiKey FIDO+CCID", serial_number=None)


class PhysicalFidoWithFakes(unittest.TestCase):
    def test_guard_refuses_before_anything_is_written(self):
        module, conn = fake_hid([descriptor(vid=0x2581), descriptor()])
        fido = PhysicalFido(module, join_timeout=1)
        try:
            make_credential = b"\x01" + cbor.encode({1: bytes(32), 2: {"id": "example.com"}})
            with self.assertRaises(GuardViolation):
                fido.send_message(0x01020304, Cmd.CBOR, make_credential)
            with self.assertRaises(GuardViolation):
                fido.send_packet(fragment(0x01020304, Cmd.CBOR, make_credential)[0])
            with self.assertRaises(GuardViolation):
                fido.send_packet(init_packet(0x01020304, Cmd.CBOR, 1, b"\x07"))
            self.assertEqual(conn.written, [])
            t_send = fido.send_message(0xFFFFFFFF, Cmd.INIT, bytes(range(8)))
            item = fido.recv_packet(2)
            self.assertIsNotNone(item)
            t_recv, pkt = item
            self.assertEqual(pkt[7:15], bytes(range(8)))
            self.assertGreaterEqual(t_recv, t_send)  # stamped in the callback, after the write began
            fido.send_message(0x01020304, Cmd.PING, bytes(200))
            self.assertEqual(len(conn.written), 1 + 4)
        finally:
            start = time.monotonic()
            fido.close()
            self.assertLess(time.monotonic() - start, 1.5)
        self.assertTrue(conn.closed)

    def test_descriptor_selection(self):
        for descriptors in ([], [descriptor(vid=0x2581)], [descriptor(), descriptor()], [descriptor(size=32)]):
            module, _ = fake_hid(descriptors)
            with self.assertRaises(PhysicalError):
                PhysicalFido(module, join_timeout=1)

    def test_no_raw_send_path(self):
        module, _ = fake_hid([descriptor()])
        fido = PhysicalFido(module, join_timeout=1)
        try:
            public = {name for name in dir(fido) if not name.startswith("_")}
            self.assertEqual(public, {"send_packet", "send_message", "recv_packet", "drain", "close", "info"})
        finally:
            fido.close()


# --- guard fuzz: what passes is always one of the admitted reads -----------------------------


class GuardFuzz(unittest.TestCase):
    def test_random_apdus_never_pass_outside_the_rules(self):
        rng = random.Random(20261011)
        reads = {"mgmt": {0x1D}, "otp": {0x01}, "oath": set(), "piv": {0xCB, 0xFD, 0xF8, 0xF7, 0x20}, "openpgp": {0xCA, 0x20}, "hsmauth": set(), "sd": {0xCA}}
        interesting_ins = [0x01, 0x03, 0x1C, 0x1D, 0x1F, 0x20, 0x24, 0x2A, 0x2C, 0x44, 0x47, 0x50, 0x82, 0x84, 0x87, 0x88, 0xA2, 0xA4, 0xC0, 0xCA, 0xCB, 0xD8, 0xDA, 0xDB, 0xE2, 0xE4, 0xE6, 0xF0, 0xF1, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFD, 0xFE, 0xFF, 0x5E, 0x6E, 0x93]
        admitted = 0
        for _ in range(60000):
            applet = rng.choice(list(AIDS))
            g = CcidGuard()
            sel = H("00A40400") + bytes([len(AIDS[applet])]) + AIDS[applet]
            g.check(sel)
            g.observe(sel, 0x9000)
            cla = rng.choice([0x00, 0x80, 0x10, 0x0C, 0x01, 0x84, 0xFF])
            ins = rng.choice(interesting_ins) if rng.random() < 0.8 else rng.randrange(256)
            p1 = rng.choice([0x00, 0x10, 0x13, 0x3F, 0x5F, 0x7F, 0x9F, 0xFF, rng.randrange(256)])
            p2 = rng.choice([0x00, 0x80, 0x81, 0x82, 0x9A, 0x6E, 0x52, 0x74, 0xE0, 0x66, 0x7F, 0xFF, rng.randrange(256)])
            kind = rng.random()
            if kind < 0.3:
                body = rng.choice(PIV_GET_DATA) if rng.random() < 0.5 else bytes(rng.randrange(256) for _ in range(rng.randrange(1, 6)))
                body = bytes([len(body)]) + body + (b"\x00" if rng.random() < 0.5 else b"")
            else:
                body = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 8)))
            command = bytes([cla, ins, p1, p2]) + body
            try:
                g.check(command)
            except GuardViolation:
                continue
            admitted += 1
            p1p2 = p1 << 8 | p2
            self.assertIn(cla, (0x00, 0x80, 0x10, 0x0C), command.hex())
            self.assertTrue(ins in (0xA4, 0xC0) or ins in UNDEFINED_INS[applet] or ins in reads[applet], command.hex())
            if ins == 0xA4:
                self.assertEqual((cla, p1), (0x00, 0x04), command.hex())
            elif ins in UNDEFINED_INS[applet] or ins == 0xC0:
                self.assertTrue(len(body) <= 1 or (len(body) == 3 and body[0] == 0), command.hex())
            elif ins == 0x20:
                self.assertEqual((p1, body), (0x00, b""), command.hex())
                self.assertIn(p2, {0x80, 0x81} if applet == "piv" else {0x81, 0x82, 0x83}, command.hex())
            elif applet == "otp":
                self.assertIn(p1, (0x10, 0x13), command.hex())
            elif applet == "piv" and ins == 0xCB:
                self.assertTrue(any(tl in body for tl in PIV_GET_DATA), command.hex())
            elif applet == "openpgp":
                self.assertIn(p1p2, OPENPGP_GET_DATA | {0x0000, 0x3FFF}, command.hex())
            elif applet == "sd":
                self.assertIn(p1p2, SD_GET_DATA | {0x0000, 0x3FFF}, command.hex())
        self.assertGreater(admitted, 100)


# --- redaction -----------------------------------------------------------------------------


def ccid_run(log):
    return {"meta": {}, "probes": [{"set": "s", "id": "p", "kind": "ccid", "summary": {}, "error": None, "log": log}]}


def ex(command, data, sw="9000"):
    return {"apdu": command, "data": data, "sw": sw, "ms": 1.0}


SERIAL = 12345678  # 0x00BC614E, BCD 12 34 56 78


def tlv(tag: str, value: str) -> str:
    n = len(value) // 2
    length = f"{n:02x}" if n < 0x80 else (f"81{n:02x}" if n < 0x100 else f"82{n:04x}")
    return tag + length + value


class Redaction(unittest.TestCase):
    def redacted(self, log):
        return normalize.redact_run(ccid_run(log))["probes"][0]["exchanges"]

    def test_serial_is_removed_everywhere(self):
        body = "0102033b" + "020400bc614e" + "0302033a" + "0503050704"
        config = f"{len(body) // 2:02x}" + body
        log = [
            ex("00a4040008a000000527471117", "352e372e34"),
            ex("001d0000", config),
            ex("00a4040006d27600012401", ""),
            ex("00ca004f", "d2760001240103040006" + "12345678" + "0000"),
            ex("00a4040005a000000308", "61114f0600001000010079074f05a000000308"),
            ex("00cb3fff035c017e", "7e124f0ba0000003080000100001005f2f024000" + "00bc614e"),  # serial hidden in a public object
        ]
        out = self.redacted(log)
        joined = " ".join(e["data"] for e in out)
        self.assertNotIn("bc614e", joined)
        self.assertNotIn("12345678", joined)
        self.assertEqual(out[1]["data"], "130102033b0204xxxxxxxx0302033a0503050704")
        self.assertEqual(out[1]["tags"], ["01", "02", "03", "05"])
        self.assertEqual(out[3]["data"], "d2760001240103040006xxxxxxxx0000")
        decimal = normalize.redact_run(ccid_run([
            ex("00a4040008a000000527471117", "352e372e34"),
            ex("001d0000", config),
            ex("00a4040008a000000527471117", "352e372e34" + "3132333435363738"),  # ASCII decimal form
        ]))["probes"][0]["exchanges"]
        self.assertTrue(decimal[2]["data"].endswith("xx" * 8))

    def test_piv_objects(self):
        guid = "00112233445566778899aabbccddeeff"
        fascn = "d4e739da739ced39ce739d836858210842108421c84210c3eb"
        chuid = tlv("53", tlv("30", fascn) + tlv("34", guid) + tlv("35", "3230333030313031") + "3e00fe00")
        card_id = "a000000116ff02" + "aa" * 14
        ccc = tlv("53", tlv("f0", card_id) + "f10121f20121f300f40100f50110f600f700fa00fb00fc00fd00fe00")
        metadata = "010111" + "02020101" + "030101" + tlv("04", tlv("86", "04" + "77" * 64))
        log = [
            ex("00a4040005a000000308", "61114f0600001000010079074f05a000000308"),
            ex("00cb3fff055c035fc102", chuid),
            ex("00cb3fff055c035fc107", ccc),
            ex("00f7009a", metadata),
        ]
        out = self.redacted(log)
        self.assertNotIn(guid, out[1]["data"])
        self.assertNotIn(fascn, out[1]["data"])
        self.assertIn("350832303330303130313e00fe00", out[1]["data"])
        self.assertEqual(out[1]["tags"], ["53", "53/30", "53/34", "53/35", "53/3E", "53/FE"])
        self.assertNotIn("aa" * 14, out[2]["data"])
        self.assertIn("f10121", out[2]["data"])
        self.assertNotIn("77" * 64, out[3]["data"])
        self.assertTrue(out[3]["data"].startswith("010111"))

    def test_oath_openpgp_cplc_and_fail_closed(self):
        cplc_value = "4090" + "1122" + "3344" + "5566" + "7788" + "99aa" + "bbccddee" + "ff00" + "aa" * 24
        self.assertEqual(len(cplc_value) // 2, 42)
        cplc = tlv("9f7f", cplc_value)
        inner = tlv("4f", "d27600012401030400061234567800" + "00") + tlv("73", tlv("c5", "ab" * 10) + tlv("cd", "0102")) + tlv("7a", tlv("93", "0000aa"))
        sixe = tlv("6e", inner)
        log = [
            ex("00a4040007a0000005272101", "790305070471080102030405060708" + "7408a1a2a3a4a5a6a7a8" + "7b0101"),
            ex("00a4040008a000000151000000", "6f178408a000000151000000a50b730906072a864886fc6b01"),
            ex("00ca9f7f", cplc),
            ex("00ca0000", "0102030405"),  # no rule: everything
            ex("00a4040006d27600012401", ""),
            ex("00ca006e00", sixe),
            ex("00a4040004a0000005", "0102"),  # partial AID: everything
        ]
        out = self.redacted(log)
        self.assertEqual(out[0]["data"], "7903050704" + "7108" + "xx" * 8 + "7408" + "xx" * 8 + "7b0101")
        self.assertEqual(out[1]["data"], "6f178408a000000151000000a50b730906072a864886fc6b01")
        self.assertTrue(out[2]["data"].startswith("9f7f2a40901122334455667788"))
        self.assertEqual(out[2]["data"][6 + 20 :], "xx" * 32)
        self.assertEqual(out[3]["data"], "xx" * 5)
        self.assertNotIn("ab" * 10, out[5]["data"])
        self.assertNotIn("12345678", out[5]["data"])
        self.assertTrue(out[5]["data"].endswith("9303xxxxxx"))
        self.assertEqual(out[6]["data"], "xxxx")

    def test_chain_is_reassembled_before_the_rules(self):
        inner = tlv("4f", "d2760001240103040006123456780000") + tlv("73", tlv("c5", "ee" * 80) + tlv("c0", "00" * 0x9A))
        raw = bytes.fromhex(tlv("6e", inner))
        self.assertGreater(len(raw), 256)
        part1, part2 = raw[:256].hex(), raw[256:].hex()
        log = [
            ex("00a4040006d27600012401", ""),
            ex("00ca006e00", part1, "61%02X" % (len(raw) - 256)),
            ex("00c0000000", part2),
        ]
        out = self.redacted(log)
        self.assertNotIn("ee" * 4, out[1]["data"] + out[2]["data"])
        self.assertEqual(out[1]["chain_total_len"], len(raw))
        self.assertEqual(len(out[1]["data"]) + len(out[2]["data"]), 2 * len(raw))

    def test_fido_rendering(self):
        cid = 0x01020304
        nonce = bytes(range(8))
        key_agreement = b"\x00" + cbor.encode({1: {1: 2, 3: -25, -1: 1, -2: b"\x11" * 32, -3: b"\x22" * 32}})
        log = []
        for direction, packets in (
            ("out", fragment(0xFFFFFFFF, Cmd.INIT, nonce)),
            ("in", fragment(0xFFFFFFFF, Cmd.INIT, nonce + cid.to_bytes(4, "big") + bytes([2, 5, 7, 4, 5]))),
            ("out", fragment(cid, Cmd.CBOR, b"\x06" + cbor.encode({1: 2, 2: 2}))),
            ("in", fragment(cid, Cmd.CBOR, key_agreement)),
        ):
            for pkt in packets:
                log.append({"t": 1.0, "dir": direction, "pkt": pkt.hex()})
        run = {"meta": {}, "probes": [{"set": "s", "id": "p", "kind": "fido", "summary": {}, "error": None, "log": log}]}
        out = normalize.redact_run(run)["probes"][0]["packets"]
        text = repr(out)
        self.assertNotIn("1111", text)
        self.assertNotIn("2222", text)
        self.assertNotIn("01020304", text)
        self.assertNotIn("0001020304050607", text)
        self.assertEqual(out[1]["message"]["allocated_cid"], "cid1")
        self.assertTrue(out[1]["message"]["nonce_ok"])
        body = out[-1]["message"]["body"]["1"]
        self.assertEqual(body["-2"], "xx" * 32)
        self.assertEqual(body["3"], -25)


# --- compare -------------------------------------------------------------------------------


class Compare(unittest.TestCase):
    def run_with(self, summary, sw="9000"):
        return {
            "meta": {"redacted": True, "label": "x"},
            "probes": [
                {"set": "fido-timing", "id": "t", "kind": "fido", "summary": summary, "error": None, "packets": []},
                {"set": "ccid-basic", "id": "c", "kind": "ccid", "summary": {}, "error": None, "exchanges": [{"apdu": "00fd0000", "sw": sw, "len": 3, "data": "050704", "ms": 1.0}]},
            ],
        }

    def test_jitter_is_identical_and_real_changes_differ(self):
        a = self.run_with({"keepalive": {"count": 15, "interval_mean_ms": 100.1, "interval_max_ms": 104}, "timeout_ms": 3001})
        b = self.run_with({"keepalive": {"count": 16, "interval_mean_ms": 99.0, "interval_max_ms": 130}, "timeout_ms": 3090})
        report = compare.compare_runs(a, b)
        self.assertEqual(report["counts"], {"identical": 2})
        c = self.run_with({"keepalive": {"count": 15, "interval_mean_ms": 140.0, "interval_max_ms": 104}, "timeout_ms": 500}, sw="6D00")
        report = compare.compare_runs(a, c)
        verdicts = {p["id"]: p for p in report["probes"]}
        self.assertEqual(verdicts["t"]["verdict"], "differs")
        paths = {d["path"] for d in verdicts["t"]["differences"]}
        self.assertEqual(paths, {"summary.keepalive.interval_mean_ms", "summary.timeout_ms"})
        self.assertEqual(verdicts["c"]["verdict"], "differs")
        self.assertIn("# Measurement comparison", compare.to_markdown(report))


if __name__ == "__main__":
    unittest.main()
