"""OpenPGP object limits and access rules from public profile/specification.

Exact firmware rejection status and parsing tolerance at write boundaries have
not been measured. Existing legacy values remain readable; never truncate them.
"""

from .core import require
from .profile import OPENPGP_CERTIFICATE_LENGTH, OPENPGP_SPECIAL_DO_LENGTH

PRIVATE_OBJECTS = (0x101, 0x102, 0x103, 0x104)
FINGERPRINTS = (0xC7, 0xC8, 0xC9, 0xDB, 0xCA, 0xCB, 0xCC, 0xDC)
TIMESTAMPS = (0xCE, 0xCF, 0xD0, 0xDD)
ATTRIBUTES = (0xC1, 0xC2, 0xC3, 0xDA)
UIFS = (0xD6, 0xD7, 0xD8, 0xD9)
VARIABLE_LIMITS = {
    **dict.fromkeys(
        (*PRIVATE_OBJECTS, 0x5E, 0x5F50, *ATTRIBUTES, 0xF9), OPENPGP_SPECIAL_DO_LENGTH
    ),
    0x5B: 39,
    0x5F2D: 8,
    0x7F21: OPENPGP_CERTIFICATE_LENGTH,
    0xFC: OPENPGP_CERTIFICATE_LENGTH,
}
WRITABLE_OBJECTS = frozenset(
    (*VARIABLE_LIMITS, *FINGERPRINTS, *TIMESTAMPS, *UIFS, 0x5F35, 0xC4, 0xD3)
)
READABLE_STORED_OBJECTS = WRITABLE_OBJECTS - {0xD3, 0x7F21}


def validate_write(oid, data):
    # Undeclared/read-only/unsupported objects must never silently succeed.
    require(oid in WRITABLE_OBJECTS, 0x6B00)
    if oid in VARIABLE_LIMITS:
        require(len(data) <= VARIABLE_LIMITS[oid], 0x6A84)
    if oid == 0x5F2D:
        require(len(data) in (0, 2, 4, 6, 8), 0x6A80)
    if oid == 0x5F35:
        require(data in (b"0", b"1", b"2", b"9"), 0x6A80)
    if oid in FINGERPRINTS:
        require(len(data) == 20, 0x6A80)
    if oid in TIMESTAMPS:
        require(len(data) == 4, 0x6A80)
    if oid in UIFS:
        require(len(data) == 2 and data[1] == 0x20, 0x6A80)
