#!/usr/bin/env python3
"""python-fido2 against the localkey FIDO HID device (black-box client).

usage: fido2_flow.py --control CONTROL-SOCKET [--pin PIN] [--vendor HEX --product HEX]

1. CtapHidDevice.list_devices(): every CTAP HID device; the one with the given vendor and
   product (default: the only one) is used.
2. Ctap2.get_info().
3. Ctap2 directly: make_credential and get_assertion (with a PIN token when --pin is
   given), touching the sensor from the keepalive callback when the authenticator reports
   UPNEEDED; the attestation and the assertion signature are verified.
4. Fido2Client with Fido2Server (the library's relying-party side): register and
   authenticate, touching from UserInteraction.prompt_up.
Prints "fido2_flow: PASS" and exits 0 when everything worked; any exception fails it.
"""

import argparse
import os
import subprocess
import sys
import time

from fido2.attestation import Attestation
from fido2.client import DefaultClientDataCollector, Fido2Client, UserInteraction
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin
from fido2.hid import CtapHidDevice
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity

LOCALKEYD = "/localkey/bin/localkeyd"
STATUS_UPNEEDED = 2
RETAP_S = 1.0
RELEASED_S = 0.7
RP_ID = "localkey.example"


class Toucher:
    """Taps the sensor once per request, through `localkeyd ctl tap`."""

    def __init__(self, control):
        self.control = control
        self.taps = 0
        self.last = None

    def tap(self, why):
        # A tap holds the sensor for 0.5 s (TAP_SHORT_MS); a tap while it is held is
        # ignored, so wait until the previous one was released.
        if self.last is not None:
            time.sleep(max(0.0, RELEASED_S - (time.monotonic() - self.last)))
        self.last = time.monotonic()
        self.taps += 1
        result = subprocess.run([LOCALKEYD, "ctl", "--control", self.control, "tap"], capture_output=True, text=True)
        print(f"  touch #{self.taps} ({why}): ctl tap -> {result.stdout.strip() or result.stderr.strip()}", flush=True)

    def keepalive(self):
        """A keepalive callback that touches when the authenticator reports UPNEEDED, and
        again while it keeps doing so: a tap holds the sensor for 0.5 s, and a request
        that starts while the previous tap is still held waits for the next touch (as a
        key does), so a second touch follows after the first was released."""
        last = []

        def on_keepalive(status):
            if status == STATUS_UPNEEDED and (not last or time.monotonic() - last[-1] > RETAP_S):
                last.append(time.monotonic())
                self.tap("keepalive UPNEEDED")

        return on_keepalive


class Interaction(UserInteraction):
    def __init__(self, toucher, pin):
        self.toucher = toucher
        self.pin = pin

    def prompt_up(self):
        self.toucher.tap("Fido2Client prompt_up")

    def request_pin(self, permissions, rp_id):
        print(f"  Fido2Client asks for the PIN (permissions {permissions!r}, rp {rp_id})", flush=True)
        return self.pin

    def request_uv(self, permissions, rp_id):
        return True


def pin_param(ctap, pin, permissions, message):
    if pin is None:
        return {}
    client_pin = ClientPin(ctap)
    token = client_pin.get_pin_token(pin, permissions, RP_ID)
    return {
        "pin_uv_param": client_pin.protocol.authenticate(token, message),
        "pin_uv_protocol": client_pin.protocol.VERSION,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--control", required=True)
    parser.add_argument("--pin")
    parser.add_argument("--vendor")
    parser.add_argument("--product")
    args = parser.parse_args()
    toucher = Toucher(args.control)

    print("1. CtapHidDevice.list_devices()")
    devices = list(CtapHidDevice.list_devices())
    for dev in devices:
        d = dev.descriptor
        print(f"  {d.path}: vid {d.vid:04x} pid {d.pid:04x} name {d.product_name!r} serial {d.serial_number!r} "
              f"report sizes in {d.report_size_in} out {d.report_size_out}; CTAPHID version {dev.version}, "
              f"device version {dev.device_version}, capabilities 0x{dev.capabilities:02x}")
    if args.vendor:
        devices = [dev for dev in devices
                   if dev.descriptor.vid == int(args.vendor, 16) and dev.descriptor.pid == int(args.product, 16)]
    if len(devices) != 1:
        raise SystemExit(f"fido2_flow: expected one device, found {len(devices)}")
    dev = devices[0]

    print("2. Ctap2.get_info()")
    ctap = Ctap2(dev)
    info = ctap.get_info()
    print(f"  versions {info.versions}")
    print(f"  extensions {info.extensions}")
    print(f"  aaguid {info.aaguid}")
    print(f"  options {info.options}")
    print(f"  max_msg_size {info.max_msg_size}, pin_uv_protocols {info.pin_uv_protocols}, "
          f"firmware_version {getattr(info, 'firmware_version', None)}")
    if args.pin is not None:
        print(f"  PIN retries {ClientPin(ctap).get_pin_retries()}")

    print("3. Ctap2 make_credential / get_assertion")
    cdh = os.urandom(32)
    user = {"id": os.urandom(16), "name": "bob", "displayName": "Bob"}
    attestation = ctap.make_credential(
        cdh, {"id": RP_ID, "name": "localkey test"}, user, [{"type": "public-key", "alg": -7}],
        on_keepalive=toucher.keepalive(),
        **pin_param(ctap, args.pin, ClientPin.PERMISSION.MAKE_CREDENTIAL, cdh))
    auth = attestation.auth_data
    credential = auth.credential_data
    print(f"  fmt {attestation.fmt}, flags 0x{auth.flags:02x}, counter {auth.counter}, "
          f"credential id {len(credential.credential_id)} bytes, aaguid {credential.aaguid}")
    result = Attestation.for_type(attestation.fmt)().verify(attestation.att_stmt, auth, cdh)
    print(f"  attestation verified: {result.attestation_type.name}")
    cdh = os.urandom(32)
    assertion = ctap.get_assertion(
        RP_ID, cdh, [{"type": "public-key", "id": credential.credential_id}],
        on_keepalive=toucher.keepalive(),
        **pin_param(ctap, args.pin, ClientPin.PERMISSION.GET_ASSERTION, cdh))
    assertion.verify(cdh, credential.public_key)
    print(f"  assertion verified: flags 0x{assertion.auth_data.flags:02x}, counter {assertion.auth_data.counter}")

    print("4. Fido2Client + Fido2Server register / authenticate")
    origin = f"https://{RP_ID}"
    server = Fido2Server(PublicKeyCredentialRpEntity(name="localkey test", id=RP_ID), attestation="direct")
    client = Fido2Client(dev, DefaultClientDataCollector(origin), user_interaction=Interaction(toucher, args.pin))
    options, state = server.register_begin(
        PublicKeyCredentialUserEntity(name="carol", id=b"carol-user-id", display_name="Carol"),
        user_verification="discouraged", authenticator_attachment="cross-platform")
    registration = client.make_credential(options["publicKey"])
    registered = server.register_complete(state, registration)
    print(f"  registered credential {len(registered.credential_data.credential_id)} bytes")
    credentials = [registered.credential_data]
    options, state = server.authenticate_begin(credentials, user_verification="discouraged")
    selection = client.get_assertion(options["publicKey"])
    response = selection.get_response(0)
    server.authenticate_complete(state, credentials, response)
    print("  authentication verified by Fido2Server")
    dev.close()
    print(f"fido2_flow: PASS ({toucher.taps} touches)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
