#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12"
# dependencies = ["fido2==2.2.1", "cryptography==50.0.2"]
# ///
"""Independent Yubico-client tests of OUR modified C++ daemon, over CTAPHID.
Creates only new, temporary emulator state. Never enumerates physical devices.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from fido2.attestation import PackedAttestation
from fido2.ctap import CtapError
from fido2.ctap1 import Ctap1
from fido2.ctap2 import ClientPin, Config, CredentialManagement, Ctap2, LargeBlobs
from fido2.ctap2.pin import PinProtocolV1, PinProtocolV2
from fido2.hid import CtapHidDevice
from fido2.hid.base import CtapHidConnection, HidDescriptor


class SocketConnection(CtapHidConnection):
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(8)
        self.sock.connect(str(path))

    def read_packet(self):
        out = bytearray()
        while len(out) < 64:
            part = self.sock.recv(64 - len(out))
            if not part:
                raise EOFError("emulator disconnected")
            out.extend(part)
        return bytes(out)

    def write_packet(self, data):
        assert len(data) <= 64
        self.sock.sendall(data.ljust(64, b"\0"))

    def close(self):
        self.sock.close()


class Fixture:
    def __init__(self, binary, directory, card_socket=None):
        self.binary, self.directory = binary, directory
        self.card_socket = card_socket
        self.socket_path = directory / "h.sock"
        self.process = self.device = None

    def start(self):
        self.log = (self.directory / "daemon.log").open("ab")
        self.process = subprocess.Popen(
            [
                str(self.binary),
                "--dek-file",
                "--key-backend=software",
                "--store",
                str(self.directory / "state.bin"),
                "--ctl-socket",
                str(self.directory / "c.sock"),
            ],
            env={
                **os.environ,
                "SWPASSKEY_HID_SOCKET": str(self.socket_path),
                "SWPASSKEY_LOG": "warn",
                "SWPASSKEY_PRESENCE": "stdin",
                "SWPASSKEY_TESTING": "",
                "SWPASSKEY_CARD_SOCKET": str(self.card_socket)
                if self.card_socket
                else "",
            },
            stdout=self.log,
            stderr=self.log,
        )
        connection = None
        for _ in range(100):
            if self.process.poll() is not None:
                raise RuntimeError(
                    "daemon failed: " + (self.directory / "daemon.log").read_text()
                )
            if self.socket_path.exists():
                # bind() creates the path before listen() completes. A real
                # connection, not path existence, is the readiness barrier.
                try:
                    connection = SocketConnection(self.socket_path)
                except ConnectionRefusedError:
                    pass
                else:
                    break
            time.sleep(0.05)
        if connection is None:
            raise RuntimeError("FIDO service did not start listening")
        descriptor = HidDescriptor(
            str(self.socket_path), 0x1209, 0xF1D0, 64, 64, "local emulator", None
        )
        self.device = CtapHidDevice(descriptor, connection)
        self.ctap = Ctap2(self.device)
        return self.ctap

    def stop(self):
        if self.device:
            self.device.close()
            self.device = None
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(5)
            self.process = None
        if hasattr(self, "log"):
            self.log.close()

    def restart(self):
        self.stop()
        return self.start()


def run(binary, directory, report):
    fixture = Fixture(binary, directory)
    results = []

    def check(value, name):
        if not value:
            raise AssertionError(name)
        results.append({"name": name, "passed": True})
        print("PASS", name, flush=True)

    def rejects(code, fn, name):
        try:
            fn()
        except CtapError as e:
            check(int(e.code) == int(code), name + f" (0x{int(e.code):02x})")
        else:
            raise AssertionError("accepted invalid request: " + name)

    rp = {"id": "localhost", "name": "Local emulator fixture"}
    hash1 = hashlib.sha256(b"local new-key test challenge").digest()
    other = hashlib.sha256(b"different challenge").digest()
    credentials = {}
    try:
        ct = fixture.start()
        info = ct.info
        check(
            {x["alg"] for x in info.algorithms} == {-7, -8, -35},
            "GetInfo ES256 / Ed25519 / ES384",
        )
        check(
            set(info.extensions)
            >= {
                "credProtect",
                "credBlob",
                "largeBlobKey",
                "minPinLength",
                "hmac-secret",
            },
            "GetInfo implemented extensions",
        )
        check(
            info.options.get("credMgmt")
            and info.options.get("largeBlobs")
            and info.options.get("authnrCfg"),
            "GetInfo implemented management commands",
        )
        check(set(info.pin_uv_protocols) == {1, 2}, "PIN protocols 1 and 2")
        check(
            fixture.device.call(1, b"fragment" * 150) == b"fragment" * 150,
            "CTAPHID multi-packet PING",
        )
        for alg in [-7, -8, -35]:
            att = ct.make_credential(
                hash1,
                rp,
                {"id": str(alg).encode(), "name": f"user{alg}"},
                [{"type": "public-key", "alg": alg}],
                options={"rk": True},
            )
            cred = att.auth_data.credential_data
            check(
                cred.public_key[3] == alg and att.att_stmt["alg"] == alg,
                f"algorithm negotiation {alg}",
            )
            PackedAttestation().verify(att.att_stmt, att.auth_data, hash1)
            check(True, f"independent packed attestation verification {alg}")
            a = ct.get_assertion(
                "localhost",
                hash1,
                allow_list=[{"type": "public-key", "id": cred.credential_id}],
            )
            cred.public_key.verify(a.auth_data + hash1, a.signature)
            check(True, f"independent assertion verification {alg}")
            try:
                cred.public_key.verify(a.auth_data + other, a.signature)
            except Exception as e:
                from cryptography.exceptions import InvalidSignature

                if not isinstance(e, InvalidSignature):
                    raise
                check(True, f"wrong challenge rejected {alg}")
            else:
                raise AssertionError("wrong challenge verified")
            credentials[alg] = cred
        check(ct.get_info().remaining_disc_creds == 97, "resident capacity accounting")
        nonresident = ct.make_credential(
            hash1,
            rp,
            {"id": b"nonresident"},
            [{"type": "public-key", "alg": -8}],
            options={"rk": False},
        ).auth_data.credential_data
        check(
            ct.get_info().remaining_disc_creds == 97,
            "nonresident does not consume resident slots",
        )
        check(
            nonresident.credential_id
            not in {a.credential["id"] for a in ct.get_assertions("localhost", hash1)},
            "nonresident excluded from discovery",
        )
        a = ct.get_assertion(
            "localhost",
            hash1,
            allow_list=[{"type": "public-key", "id": nonresident.credential_id}],
        )
        nonresident.public_key.verify(a.auth_data + hash1, a.signature)
        check(True, "nonresident allowList signature")
        # Omitted rk is nonresident under CTAP2.
        ct.make_credential(
            hash1,
            rp,
            {"id": b"default-nonresident"},
            [{"type": "public-key", "alg": -7}],
        )
        check(ct.get_info().remaining_disc_creds == 97, "default rk=false")
        att = ct.make_credential(
            hash1,
            rp,
            {"id": b"blob"},
            [{"type": "public-key", "alg": -35}],
            options={"rk": True},
            extensions={"credBlob": b"private local data", "largeBlobKey": True},
        )
        blobcred = att.auth_data.credential_data
        check(
            att.auth_data.extensions["credBlob"] is True
            and len(att.large_blob_key) == 32,
            "credBlob stored and largeBlobKey generated",
        )
        a = ct.get_assertion(
            "localhost",
            hash1,
            allow_list=[{"type": "public-key", "id": blobcred.credential_id}],
            extensions={"getCredBlob": True, "largeBlobKey": True},
        )
        check(
            a.auth_data.extensions["credBlob"] == b"private local data"
            and a.large_blob_key == att.large_blob_key,
            "credential extension retrieval",
        )
        large = LargeBlobs(ct)
        payload = os.urandom(2300)
        large.put_blob(att.large_blob_key, payload)
        check(
            large.get_blob(att.large_blob_key) == payload,
            "fragmented large blob encrypted round trip",
        )
        initial = ct.large_blobs(0, get=1136)[1]
        rejects(
            0x3D,
            lambda: ct.large_blobs(0, set=b"\x80" + b"\0" * 16, length=17),
            "large blob digest failure",
        )
        check(
            ct.large_blobs(0, get=1136)[1] == initial,
            "bad large blob leaves committed data intact",
        )
        rejects(
            0x04, lambda: ct.large_blobs(17, set=b"x"), "out of sequence large blob"
        )
        rejects(
            0x2C,
            lambda: ct.make_credential(
                hash1,
                rp,
                {"id": b"badlb"},
                [{"type": "public-key", "alg": -7}],
                options={"rk": False},
                extensions={"largeBlobKey": True},
            ),
            "largeBlobKey requires resident key",
        )
        # hmac-secret independently encrypts/decrypts protocol 1 and 2 payloads.
        previous_output = None
        for protocol in [PinProtocolV1(), PinProtocolV2()]:
            ka = ct.client_pin(protocol.VERSION, ClientPin.CMD.GET_KEY_AGREEMENT)[1]
            platform, shared = protocol.encapsulate(ka)
            salts = (
                hashlib.sha256(b"local salt 1").digest()
                + hashlib.sha256(b"local salt 2").digest()
            )
            encrypted = protocol.encrypt(shared, salts)
            extension = {
                1: platform,
                2: encrypted,
                3: protocol.authenticate(shared, encrypted),
            }
            if protocol.VERSION == 2:
                extension[4] = 2
            a = ct.get_assertion(
                "localhost",
                hash1,
                allow_list=[
                    {"type": "public-key", "id": credentials[-8].credential_id}
                ],
                extensions={"hmac-secret": extension},
            )
            output = protocol.decrypt(shared, a.auth_data.extensions["hmac-secret"])
            check(
                len(output) == 64 and output[:32] != output[32:],
                f"hmac-secret two salts protocol {protocol.VERSION}",
            )
            if previous_output is not None:
                check(
                    output == previous_output,
                    "hmac-secret protocols produce identical plaintext",
                )
            previous_output = output
            extension[3] = bytes(len(extension[3]))
            rejects(
                0xE0,
                lambda extension=extension: ct.get_assertion(
                    "localhost",
                    hash1,
                    allow_list=[
                        {"type": "public-key", "id": credentials[-8].credential_id}
                    ],
                    extensions={"hmac-secret": extension},
                ),
                f"hmac-secret invalid salt authentication protocol {protocol.VERSION}",
            )
        # PIN v1 setup, v2 token use, v1 change. All on this fixture, never physical.
        p1 = PinProtocolV1()
        p2 = PinProtocolV2()
        ClientPin(ct, p1).set_pin("123456")
        check(ct.get_info().options["clientPin"], "PIN v1 set")
        malformed_authenticator_key = ct.client_pin(2, 2)[1]
        malformed_platform_key, _ = p2.encapsulate(malformed_authenticator_key)
        rejects(
            0x31,
            lambda: ct.client_pin(2, 9, malformed_platform_key,
                                  pin_hash_enc=b"\x01", permissions=4),
            "malformed encrypted PIN proof consumes a retry",
        )
        check(
            ClientPin(ct, p2).get_pin_retries()[0] == 7,
            "malformed encrypted PIN proof decrements durable retry counter",
        )
        ClientPin(ct, p2).get_pin_token("123456", ClientPin.PERMISSION.CREDENTIAL_MGMT)
        check(
            ClientPin(ct, p2).get_pin_retries()[0] == 8,
            "correct PIN restores retries after malformed proof",
        )
        ct.make_credential(
            hash1,
            rp,
            {"id": b"no-uv-nonresident"},
            [{"type": "public-key", "alg": -7}],
            options={"rk": False},
        )
        check(True, "makeCredUvNotRqd permits nonresident without PIN token")
        ClientPin(ct, p2).change_pin("123456", "654321")
        ClientPin(ct, p1).change_pin("654321", "12345678")
        check(True, "PIN changes interoperable across protocol 1 and 2")
        perm = ClientPin.PERMISSION
        token = ClientPin(ct, p2).get_pin_token(
            "12345678", perm.MAKE_CREDENTIAL | perm.GET_ASSERTION, "localhost"
        )
        for protection in [2, 3]:
            attp = ct.make_credential(
                hash1,
                rp,
                {"id": f"protected{protection}".encode()},
                [{"type": "public-key", "alg": -8}],
                options={"rk": True},
                extensions={"credProtect": protection},
                pin_uv_protocol=2,
                pin_uv_param=p2.authenticate(token, hash1),
            )
            check(
                attp.auth_data.extensions["credProtect"] == protection,
                f"credProtect {protection} stored",
            )
            idp = attp.auth_data.credential_data.credential_id
            unauth = {a.credential["id"] for a in ct.get_assertions("localhost", hash1)}
            check(idp not in unauth, f"credProtect {protection} hidden without UV")
            if protection == 3:
                rejects(
                    0x2E,
                    lambda idp=idp: ct.get_assertion(
                        "localhost",
                        hash1,
                        allow_list=[{"type": "public-key", "id": idp}],
                    ),
                    "credProtect 3 rejects allowList without UV",
                )
            else:
                check(
                    ct.get_assertion(
                        "localhost",
                        hash1,
                        allow_list=[{"type": "public-key", "id": idp}],
                    ).credential["id"]
                    == idp,
                    "credProtect 2 permits allowList",
                )
            a = ct.get_assertion(
                "localhost",
                hash1,
                allow_list=[{"type": "public-key", "id": idp}],
                pin_uv_protocol=2,
                pin_uv_param=p2.authenticate(token, hash1),
            )
            check(
                a.auth_data.is_user_verified(),
                f"credProtect {protection} authenticated assertion",
            )
        cm_token = ClientPin(ct, p2).get_pin_token("12345678", perm.CREDENTIAL_MGMT)
        cm = CredentialManagement(ct, p2, cm_token)
        meta = cm.get_metadata()
        check(meta[1] == 6 and meta[2] == 94, "credential management resident metadata")
        rps = cm.enumerate_rps()
        check(
            len(rps) == 1 and rps[0][3]["id"] == "localhost",
            "credential management RP enumeration",
        )
        rows = cm.enumerate_creds(hashlib.sha256(b"localhost").digest())
        check(
            len(rows) == 6 and {x[8][3] for x in rows} == {-7, -8, -35},
            "credential enumeration includes all algorithms",
        )
        descriptor = {"type": "public-key", "id": credentials[-7].credential_id}
        cm.update_user_info(
            descriptor, {"id": b"-7", "name": "renamed", "displayName": "Renamed User"}
        )
        rows = cm.enumerate_creds(hashlib.sha256(b"localhost").digest())
        check(
            any(
                x[7]["id"] == descriptor["id"] and x[6].get("name") == "renamed"
                for x in rows
            ),
            "credential update user metadata",
        )
        rejects(
            0x02,
            lambda: cm.update_user_info(descriptor, {"id": b"different-user"}),
            "credential update cannot replace user ID",
        )
        cm.delete_cred(descriptor)
        check(cm.get_metadata()[1] == 5, "credential deletion durable")
        rejects(
            0x2E,
            lambda: ct.get_assertion("localhost", hash1, allow_list=[descriptor]),
            "deleted credential unavailable",
        )
        rejects(
            0x36,
            lambda: ct.credential_mgmt(1),
            "credential management requires authenticated PIN token",
        )
        legacy_token = ClientPin(ct, p1).get_pin_token("12345678")
        legacy = ct.send_cbor(
            0x41, {1: 1, 3: 1, 4: p1.authenticate(legacy_token, b"\x01")}
        )
        check(
            legacy[1] == 5,
            "credential management preview interoperates with legacy PIN token",
        )
        ga_token = ClientPin(ct, p2).get_pin_token(
            "12345678", perm.GET_ASSERTION, "localhost"
        )
        rejects(
            0x33,
            lambda: CredentialManagement(ct, p2, ga_token).get_metadata(),
            "assertion token cannot manage credentials",
        )
        scoped = ClientPin(ct, p2).get_pin_token(
            "12345678", perm.CREDENTIAL_MGMT, "localhost"
        )
        scoped_cm = CredentialManagement(ct, p2, scoped)
        rejects(
            0x33, scoped_cm.get_metadata, "RP scoped token cannot list all metadata"
        )
        check(
            len(scoped_cm.enumerate_creds(hashlib.sha256(b"localhost").digest())) == 5,
            "RP scoped credential enumeration",
        )
        write_token = ClientPin(ct, p2).get_pin_token("12345678", perm.LARGE_BLOB_WRITE)
        LargeBlobs(ct, p2, write_token).put_blob(
            att.large_blob_key, b"PIN protected write"
        )
        check(
            LargeBlobs(ct).get_blob(att.large_blob_key) == b"PIN protected write",
            "large blob write with correct token permission",
        )
        rejects(
            0x36,
            lambda: ct.large_blobs(
                0, set=b"\x80" + hashlib.sha256(b"\x80").digest()[:16], length=17
            ),
            "large blob write requires PIN after setup",
        )
        cfg_token = ClientPin(ct, p2).get_pin_token("12345678", perm.AUTHENTICATOR_CFG)
        Config(ct, p2, cfg_token).set_min_pin_length(8, ["localhost"])
        check(ct.get_info().min_pin_length == 8, "config minimum PIN length")
        token = ClientPin(ct, p2).get_pin_token(
            "12345678", perm.MAKE_CREDENTIAL | perm.GET_ASSERTION, "localhost"
        )
        attmin = ct.make_credential(
            hash1,
            rp,
            {"id": b"minpin"},
            [{"type": "public-key", "alg": -7}],
            options={"rk": True},
            extensions={"minPinLength": True},
            pin_uv_protocol=2,
            pin_uv_param=p2.authenticate(token, hash1),
        )
        check(
            attmin.auth_data.extensions["minPinLength"] == 8,
            "minimum PIN extension authorized RP",
        )
        cfg_token = ClientPin(ct, p2).get_pin_token("12345678", perm.AUTHENTICATOR_CFG)
        rejects(
            0x37,
            lambda: Config(ct, p2, cfg_token).set_min_pin_length(4),
            "minimum PIN policy cannot decrease",
        )
        Config(ct, p2, cfg_token).toggle_always_uv()
        check(ct.get_info().options["alwaysUv"], "config always UV enabled")
        rejects(
            0x36,
            lambda: ct.get_assertion("localhost", hash1),
            "always UV rejects unverified assertion",
        )
        cfg_token = ClientPin(ct, p2).get_pin_token("12345678", perm.AUTHENTICATOR_CFG)
        Config(ct, p2, cfg_token).toggle_always_uv()
        cfg_token = ClientPin(ct, p2).get_pin_token("12345678", perm.AUTHENTICATOR_CFG)
        Config(ct, p2, cfg_token).set_min_pin_length(9, force_change_pin=True)
        retries_before_forced_change = ClientPin(ct, p2).get_pin_retries()[0]
        rejects(
            0x31,
            lambda: ClientPin(ct, p2).get_pin_token("00000000", perm.CREDENTIAL_MGMT),
            "forced PIN change still checks a wrong PIN",
        )
        check(
            ClientPin(ct, p2).get_pin_retries()[0] == retries_before_forced_change - 1,
            "forced PIN change consumes one durable retry for a wrong PIN",
        )
        rejects(
            0x37,
            lambda: ClientPin(ct, p2).get_pin_token("12345678", perm.CREDENTIAL_MGMT),
            "forced PIN change blocks token issuance",
        )
        check(
            ClientPin(ct, p2).get_pin_retries()[0] == 8,
            "correct PIN under forced change restores durable retries",
        )
        rejects(
            0x31,
            lambda: ClientPin(ct, p1).get_pin_token("12345678"),
            "legacy token reports PIN_INVALID under forced change",
        )
        rejects(
            0x37,
            lambda: ClientPin(ct, p2).change_pin("12345678", "short"),
            "short PIN rejected after policy increase",
        )
        ClientPin(ct, p2).change_pin("12345678", "123456789")
        check(not ct.get_info().force_pin_change, "PIN change clears forced change")
        ct = fixture.restart()
        check(
            ct.get_info().min_pin_length == 9 and ct.get_info().options["clientPin"],
            "PIN policy survives encrypted store restart",
        )
        check(
            LargeBlobs(ct).get_blob(att.large_blob_key) == b"PIN protected write",
            "large blob survives restart",
        )
        for alg in [-8, -35]:
            cred = credentials[alg]
            a = ct.get_assertion(
                "localhost",
                hash1,
                allow_list=[{"type": "public-key", "id": cred.credential_id}],
            )
            cred.public_key.verify(a.auth_data + hash1, a.signature)
            check(
                a.auth_data.counter >= 3,
                f"algorithm {alg} key and counter survive restart",
            )
        # U2F uses software self-attestation and a fresh key, never Yubico identity.
        u2f = Ctap1(fixture.device)
        reg = u2f.register(hash1, hashlib.sha256(b"localhost").digest())
        reg.verify(hashlib.sha256(b"localhost").digest(), hash1)
        sig = u2f.authenticate(
            hash1, hashlib.sha256(b"localhost").digest(), reg.key_handle
        )
        sig.verify(hashlib.sha256(b"localhost").digest(), hash1, reg.public_key)
        check(True, "U2F registration and assertion signatures")
        ct.reset()
        info = ct.get_info()
        check(
            info.remaining_disc_creds == 100
            and info.options["clientPin"] is False
            and info.min_pin_length == 4,
            "fixture reset restores credentials and PIN policy",
        )
        check(
            LargeBlobs(ct).read_blob_array() == [],
            "fixture reset clears large blob array",
        )
        ct = fixture.restart()
        check(
            ct.get_info().remaining_disc_creds == 100
            and not ct.get_info().options["clientPin"],
            "fixture reset persists",
        )
        report.update(
            passed=True,
            tests=results,
            capabilities={
                "versions": info.versions,
                "aaguid": str(info.aaguid),
                "algorithms": info.algorithms,
                "extensions": info.extensions,
                "options": info.options,
                "pin_uv_protocols": info.pin_uv_protocols,
                "max_msg_size": info.max_msg_size,
                "max_creds_in_list": info.max_creds_in_list,
                "max_cred_blob_length": info.max_cred_blob_length,
                "max_large_blob": info.max_large_blob,
                "min_pin_length": info.min_pin_length,
                "remaining_disc_creds": info.remaining_disc_creds,
            },
        )
    except Exception as exc:
        report.update(passed=False, tests=results, error=f"{type(exc).__name__}: {exc}")
        raise
    finally:
        fixture.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    args.work_dir.mkdir(parents=True, exist_ok=True)
    report = {
        "subject": "modified C++ emulator",
        "transport": "local Unix CTAPHID socket",
        "physical_device_access": False,
    }
    try:
        with tempfile.TemporaryDirectory(prefix="e", dir=args.work_dir.resolve()) as d:
            run(args.binary.resolve(), Path(d), report)
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(
                report,
                indent=2,
                default=lambda v: v.hex() if isinstance(v, bytes) else str(v),
            )
            + "\n"
        )


if __name__ == "__main__":
    main()
