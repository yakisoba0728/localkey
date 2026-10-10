#!/usr/bin/env python3
"""Compare two USB descriptor sequences byte for byte and name every difference.

usage: desc_diff.py [--allow FIELD]... EXPECTED-HEX ACTUAL-HEX

Both arguments are hex (spaces allowed): a device descriptor, a configuration descriptor
with its interfaces, class and endpoint descriptors, or the two concatenated (the layout
of /sys/bus/usb/devices/<dev>/descriptors). The expected bytes are walked descriptor by
descriptor (bLength, bDescriptorType), and every offset where the actual bytes differ is
printed with the descriptor it falls in and the field's name (USB 2.0 §9.6, USB HID 1.11
§6.2.1, USB CCID Rev 1.1 §5.1). The last line is

  diff: N byte(s) differ in fields F1,F2,... (allowed: yes|no)

and the exit code is 0 when the sequences are equal or every differing field is one
named by --allow, 1 otherwise.
"""

import argparse
import sys

DEVICE = ["bLength", "bDescriptorType", "bcdUSB.lo", "bcdUSB.hi", "bDeviceClass", "bDeviceSubClass",
          "bDeviceProtocol", "bMaxPacketSize0", "idVendor.lo", "idVendor.hi", "idProduct.lo",
          "idProduct.hi", "bcdDevice.lo", "bcdDevice.hi", "iManufacturer", "iProduct", "iSerialNumber",
          "bNumConfigurations"]
CONFIG = ["bLength", "bDescriptorType", "wTotalLength.lo", "wTotalLength.hi", "bNumInterfaces",
          "bConfigurationValue", "iConfiguration", "bmAttributes", "bMaxPower"]
INTERFACE = ["bLength", "bDescriptorType", "bInterfaceNumber", "bAlternateSetting", "bNumEndpoints",
             "bInterfaceClass", "bInterfaceSubClass", "bInterfaceProtocol", "iInterface"]
ENDPOINT = ["bLength", "bDescriptorType", "bEndpointAddress", "bmAttributes", "wMaxPacketSize.lo",
            "wMaxPacketSize.hi", "bInterval"]
HID = ["bLength", "bDescriptorType", "bcdHID.lo", "bcdHID.hi", "bCountryCode", "bNumDescriptors",
       "bDescriptorType(report)", "wDescriptorLength.lo", "wDescriptorLength.hi"]
# USB CCID Rev 1.1 Table 5.1-1 (offset: name; multi-byte fields by their first byte).
CCID = {0: "bLength", 1: "bDescriptorType", 2: "bcdCCID", 4: "bMaxSlotIndex", 5: "bVoltageSupport",
        6: "dwProtocols", 10: "dwDefaultClock", 14: "dwMaximumClock", 18: "bNumClockSupported",
        19: "dwDataRate", 23: "dwMaxDataRate", 27: "bNumDataRatesSupported", 28: "dwMaxIFSD",
        32: "dwSynchProtocols", 36: "dwMechanical", 40: "dwFeatures", 44: "dwMaxCCIDMessageLength",
        48: "bClassGetResponse", 49: "bClassEnvelope", 50: "wLcdLayout", 52: "bPINSupport",
        53: "bMaxCCIDBusySlots"}


def ccid_field(offset):
    start = max(k for k in CCID if k <= offset)
    return CCID[start] if start == offset else f"{CCID[start]}+{offset - start}"


def walk(data):
    """(offset, descriptor label, field name) for every byte of `data`."""
    out = []
    pos, index, interface_class = 0, 0, None
    while pos < len(data):
        length = data[pos] if data[pos] >= 2 else len(data) - pos
        kind = data[pos + 1] if pos + 1 < len(data) else None
        if kind == 1:
            label, names = "device", DEVICE
        elif kind == 2:
            label, names = "configuration", CONFIG
        elif kind == 4:
            interface_class = data[pos + 5] if pos + 5 < len(data) else None
            label, names = f"interface {data[pos + 2] if pos + 2 < len(data) else '?'}", INTERFACE
        elif kind == 5:
            label, names = "endpoint", ENDPOINT
        elif kind == 0x21 and interface_class == 0x0B:
            label, names = "CCID class", None
        elif kind == 0x21:
            label, names = "HID", HID
        else:
            label, names = f"type 0x{kind:02x}" if kind is not None else "truncated", None
        for i in range(min(length, len(data) - pos)):
            if names is not None and i < len(names):
                name = names[i]
            elif label == "CCID class":
                name = ccid_field(i)
            else:
                name = f"byte {i}"
            out.append((pos + i, f"#{index} {label}", name))
        pos += length
        index += 1
    return out


def parse_hex(text):
    return bytes.fromhex("".join(text.split()))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--allow", action="append", default=[])
    parser.add_argument("expected")
    parser.add_argument("actual")
    args = parser.parse_args()
    expected, actual = parse_hex(args.expected), parse_hex(args.actual)
    fields = []
    count = 0
    for offset, label, name in walk(expected):
        want = expected[offset]
        got = actual[offset] if offset < len(actual) else None
        if got != want:
            count += 1
            base = name.split(".")[0]
            if base not in fields:
                fields.append(base)
            shown = "missing" if got is None else f"{got:02x}"
            print(f"offset {offset:3d}: {label:16s} {name:24s} expected {want:02x} actual {shown}")
    if len(actual) > len(expected):
        count += len(actual) - len(expected)
        fields.append("trailing bytes")
        print(f"actual has {len(actual) - len(expected)} more bytes: {actual[len(expected):].hex(' ')}")
    allowed = all(field in args.allow for field in fields)
    print(f"diff: {count} byte(s) differ in fields {','.join(fields) or '-'} "
          f"({len(expected)} expected, {len(actual)} actual; allowed: {'yes' if allowed else 'no'})")
    return 0 if allowed else 1


if __name__ == "__main__":
    sys.exit(main())
