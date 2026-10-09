"""Eight-byte USB keyboard input reports and OTP navigation/pacing events."""

import string

from .core import require

# US HID usage mapping. Scan-code static passwords keep their stored usage IDs.
US = {c: (0, 4 + i) for i, c in enumerate(string.ascii_lowercase)}
US.update({c: (2, 4 + i) for i, c in enumerate(string.ascii_uppercase)})
US.update({c: (0, 30 + i) for i, c in enumerate("1234567890")})
US.update({c: (2, 30 + i) for i, c in enumerate("!@#$%^&*()")})
US.update({" ": (0, 44), "\t": (0, 43), "\r": (0, 40)})

DESCRIPTOR = bytes.fromhex(
    "05010906a101050719e029e715002501750195088102"
    "950175088101950575010508190129059102950175039101"
    "95067508150025650507190029658100"
    "0600ff090175089508b102c0"
)


SCAN_MAP = "cbdefghijklnrtuvCBDEFGHIJKLNRTUV0123456789!\t\r"


def events(output, config, scan_map=None):
    """Return reports with delays; issuing reports to an OS is a separate transport."""
    ticket_flags = config[46]
    pacing = (10 if config[47] & 4 else 0) + (20 if config[47] & 8 else 0)
    result = []
    if scan_map:
        scan_map = bytes.fromhex(scan_map)
        require(len(scan_map) == len(SCAN_MAP), 0x6A80)

    def emit(modifier, usage):
        require(0 <= modifier <= 255 and 0 <= usage <= 101, 0x6A80)
        result.append(
            {
                "report": bytes([modifier, 0, usage, 0, 0, 0, 0, 0]).hex(),
                "delay_ms": pacing,
            }
        )
        result.append({"report": bytes(8).hex(), "delay_ms": 0})

    def text(value):
        for char in value:
            require(char in US, 0x6A80)
            modifier, usage = US[char]
            if scan_map and char in SCAN_MAP:
                code = scan_map[SCAN_MAP.index(char)]
                modifier, usage = 2 if code & 0x80 else 0, code & 0x7F
            if config[45] & 8 and char.isdigit():
                usage = 98 if char == "0" else 89 + int(char) - 1
            emit(modifier, usage)

    if ticket_flags & 1:
        text("\t")
    if "scan_codes" in output:
        for code in output["scan_codes"]:
            emit(2 if code & 0x80 else 0, code & 0x7F)
    else:
        value = output["text"]
        split = output.get("fixed_chars", 0)
        text(value[:split])
        if ticket_flags & 2:
            text("\t")
        if ticket_flags & 8:
            result.append({"report": bytes(8).hex(), "delay_ms": 500})
        text(value[split:])
    if ticket_flags & 4:
        text("\t")
    if ticket_flags & 16:
        result.append({"report": bytes(8).hex(), "delay_ms": 500})
    if output["append_cr"]:
        text("\r")
    return result


def modhex(value):
    alphabet = "cbdefghijklnrtuv"
    return "".join(alphabet[b >> 4] + alphabet[b & 15] for b in value)


def strong_password(value, flags):
    """Static-ticket policy transforms documented in YubiKey Manual 3.3 §5.5."""
    if flags & 0x40:
        eligible = "cbdefghi"
        replaced = 0
        chars = []
        for char in value:
            if char in eligible and replaced < 2:
                chars.append(str(eligible.index(char) + 1))
                replaced += 1
            else:
                chars.append(char)
        value = "".join(chars)
    if flags & 0x10:
        shifted = 0
        chars = []
        for char in value:
            if char.isalpha() and shifted < 2:
                chars.append(char.upper())
                shifted += 1
            else:
                chars.append(char)
        value = "".join(chars)
    if flags & 1:
        value = ("!" if flags & 0x40 else "cbdefghijklnrtuv") + value
    return value
