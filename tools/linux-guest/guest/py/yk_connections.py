#!/usr/bin/env python3
"""Which connections ykman reaches a YubiKey through: one line per connection type.

usage: yk_connections.py

For each of SmartCardConnection (PC/SC readers whose name says "Yubico YubiKey"), OtpConnection
(the OTP HID interface) and FidoConnection (the FIDO HID interface), lists what
`ykman.device.list_all_devices` finds through that connection alone, as
`<type> count=<n> <pid> serial=<serial> version=<version> at=<fingerprint>` (one entry per
device, separated by "; "). A device that ykman finds in a reader but cannot open (a reader
without a card) is not counted. With `--transport uhid,vpcd` all three should name the same
serial: CCID through pcscd and vpcd, OTP and FIDO through UHID.
"""

import logging
import sys

from ykman.device import list_all_devices
from yubikit.core.fido import FidoConnection
from yubikit.core.otp import OtpConnection
from yubikit.core.smartcard import SmartCardConnection


class Counter(logging.Handler):
    """Counts ykman's log records (a reader slot without a card logs "Failed opening
    device" with a traceback) instead of printing them."""

    def __init__(self):
        super().__init__(logging.WARNING)
        self.messages = {}

    def emit(self, record):
        text = record.getMessage()
        self.messages[text] = self.messages.get(text, 0) + 1


def main():
    counter = Counter()
    logging.getLogger().addHandler(counter)
    # Named here: yubikit's FidoConnection is an alias whose __name__ is CtapDevice.
    kinds = (("SmartCardConnection", SmartCardConnection), ("OtpConnection", OtpConnection), ("FidoConnection", FidoConnection))
    for label, kind in kinds:
        try:
            found = list_all_devices([kind])
        except Exception as error:  # report, do not stop: the other types still count
            print("%s error=%s" % (label, error))
            continue
        entries = [
            "%s serial=%s version=%s at=%s"
            % (getattr(dev.pid, "name", dev.pid), info.serial, info.version, getattr(dev, "fingerprint", "?"))
            for dev, info in found
        ]
        print("%s count=%d %s" % (label, len(found), "; ".join(entries)))
    for text, count in sorted(counter.messages.items()):
        print("ykman log: %s (x%d)" % (text, count))
    return 0


if __name__ == "__main__":
    sys.exit(main())
