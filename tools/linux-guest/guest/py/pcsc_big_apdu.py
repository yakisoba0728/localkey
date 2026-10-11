#!/usr/bin/env python3
"""One extended command APDU of a chosen size through pcscd, with pyscard.

usage: pcsc_big_apdu.py READER-SUBSTRING SIZE

Sends SELECT (00 A4 04 00) by DF name with an extended Lc: the name is A0 followed by
SIZE - 8 bytes of EE, so no application's AID begins it and the card answers 6A82 (file or
application not found) after reading the whole command. Then SELECT OATH, which must answer
9000: the card still works after the long command. Prints the size and the status words.

Why pyscard: ykman caps a whole APDU at 3062 bytes (yubikit's largest
`_MaxApduSize`, YK4_3) and chains anything longer, and OpenSC sends no extended APDU to a
card it does not know to take one. A command longer than one CCID message (3062 bytes of
data for the engine's dwMaxCCIDMessageLength) reaches the device as several XfrBlocks only
when the client sends it as one APDU (USB CCID Rev 1.1 §6.1.4, wLevelParameter).
"""

import sys

from smartcard.System import readers


def main():
    name, size = sys.argv[1], int(sys.argv[2])
    if size < 9 or size > 65535:
        print("SIZE must be 9..65535")
        return 2
    matches = [r for r in readers() if name in str(r)]
    if not matches:
        print("no reader matches %r: %s" % (name, [str(r) for r in readers()]))
        return 1
    connection = matches[0].createConnection()
    connection.connect()
    # CLA INS P1 P2, extended Lc (00 hi lo), then the data; no Le.
    data = [0xA0] + [0xEE] * (size - 8)
    apdu = [0x00, 0xA4, 0x04, 0x00, 0x00, len(data) >> 8, len(data) & 0xFF] + data
    assert len(apdu) == size
    response, sw1, sw2 = connection.transmit(apdu)
    print("apdu %d bytes: SW %02X%02X, %d bytes of data" % (len(apdu), sw1, sw2, len(response)))
    oath = [0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01]
    _, sw1, sw2 = connection.transmit(oath)
    print("SELECT OATH afterwards: SW %02X%02X" % (sw1, sw2))
    connection.disconnect()
    return 0


if __name__ == "__main__":
    sys.exit(main())
