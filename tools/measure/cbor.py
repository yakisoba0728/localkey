"""A small, strict CBOR codec (RFC 8949) for the measurement harness.

Only what CTAP2 uses: unsigned and negative integers, byte and text strings, arrays,
maps, false/true/null. Definite lengths only. `decode` refuses trailing bytes, so the
guard sees exactly one item. Encoding sorts map keys in CTAP2 canonical order (shorter
encoded key first, then bytewise), as CTAP 2.1 §8 requires.
"""

from __future__ import annotations


class CborError(ValueError):
    pass


def _head(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([major << 5 | value])
    for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if value < 1 << (8 * size):
            return bytes([major << 5 | info]) + value.to_bytes(size, "big")
    raise CborError("integer too large")


def encode(value) -> bytes:
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, (bytes, bytearray)):
        return _head(2, len(value)) + bytes(value)
    if isinstance(value, str):
        data = value.encode()
        return _head(3, len(data)) + data
    if isinstance(value, (list, tuple)):
        return _head(4, len(value)) + b"".join(encode(item) for item in value)
    if isinstance(value, dict):
        items = sorted(((encode(k), encode(v)) for k, v in value.items()), key=lambda kv: (len(kv[0]), kv[0]))
        return _head(5, len(items)) + b"".join(k + v for k, v in items)
    raise CborError(f"cannot encode {type(value).__name__}")


def _decode(data: bytes, pos: int, depth: int):
    if depth > 16:
        raise CborError("nesting too deep")
    if pos >= len(data):
        raise CborError("truncated")
    initial = data[pos]
    major, info = initial >> 5, initial & 0x1F
    pos += 1
    if major == 7:
        if info == 20:
            return False, pos
        if info == 21:
            return True, pos
        if info == 22:
            return None, pos
        raise CborError(f"unsupported simple/float 0x{initial:02x}")
    if info < 24:
        value = info
    elif info in (24, 25, 26, 27):
        size = 1 << (info - 24)
        if pos + size > len(data):
            raise CborError("truncated")
        value = int.from_bytes(data[pos : pos + size], "big")
        pos += size
    else:
        raise CborError("indefinite or reserved length")
    if major == 0:
        return value, pos
    if major == 1:
        return -1 - value, pos
    if major in (2, 3):
        if pos + value > len(data):
            raise CborError("truncated string")
        raw = data[pos : pos + value]
        pos += value
        if major == 2:
            return bytes(raw), pos
        try:
            return raw.decode("utf-8"), pos
        except UnicodeDecodeError as error:
            raise CborError("invalid UTF-8") from error
    if major == 4:
        if value > len(data):
            raise CborError("array too long")
        items = []
        for _ in range(value):
            item, pos = _decode(data, pos, depth + 1)
            items.append(item)
        return items, pos
    if major == 5:
        if value > len(data):
            raise CborError("map too long")
        result = {}
        for _ in range(value):
            key, pos = _decode(data, pos, depth + 1)
            if isinstance(key, (list, dict)):
                raise CborError("unhashable map key")
            if key in result:
                raise CborError("duplicate map key")
            item, pos = _decode(data, pos, depth + 1)
            result[key] = item
        return result, pos
    raise CborError(f"unsupported major type {major} (tags are not used by CTAP2)")


def decode(data: bytes):
    """Decode exactly one item; trailing bytes are an error."""
    value, pos = _decode(bytes(data), 0, 0)
    if pos != len(data):
        raise CborError(f"{len(data) - pos} trailing byte(s)")
    return value


def decode_prefix(data: bytes):
    """Decode one item and return it with the number of bytes it used."""
    return _decode(bytes(data), 0, 0)
