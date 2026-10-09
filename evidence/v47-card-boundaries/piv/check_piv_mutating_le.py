"""Isolated before/after PIV mutating-command Le boundaries."""

from __future__ import annotations

import json
import sys
from pathlib import Path


root = Path(sys.argv[1]).resolve()
mode = sys.argv[2]
assert mode in ("baseline", "candidate")
sys.path.insert(0, str(root))

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from emucard.core import Card  # noqa: E402
from emucard.piv_objects import APPLICATION_AID  # noqa: E402


scalar = ec.generate_private_key(ec.SECP256R1()).private_numbers().private_value
commands = {
    "generate": (bytes.fromhex("0047009a"), bytes.fromhex("ac03800111"), "keys"),
    "import": (bytes.fromhex("00fe119a"), bytes.fromhex("0620") + scalar.to_bytes(32, "big"), "keys"),
    "put_data": (bytes.fromhex("00db3fff"), bytes.fromhex("5c035fc10253026162"), "objects"),
}
results = {}
for operation, (header, data, state_key) in commands.items():
    short = header + bytes([len(data)]) + data
    requests = {
        "short_le_one": short + b"\x01",
        "short_le_256": short + b"\x00",
        "extended_le_257": header + b"\0" + len(data).to_bytes(2, "big") + data + bytes.fromhex("0101"),
        "documented_no_le": short,
    }
    for variant, request in requests.items():
        card = Card()
        select = bytes([0, 0xA4, 4, 0, len(APPLICATION_AID)]) + APPLICATION_AID
        assert card.transmit(select)[1] == 0x9000
        card.mgmt_verified = True
        prior = json.dumps(card.state.data["piv"][state_key], sort_keys=True)
        response, status = card.transmit(request)
        after = json.dumps(card.state.data["piv"][state_key], sort_keys=True)
        key = operation + "_" + variant
        results[key] = {
            "status": f"{status:04X}",
            "response_bytes": len(response),
            "state_changed": prior != after,
        }
        if variant == "documented_no_le":
            assert status == 0x9000 and prior != after, (key, results[key])
            assert operation != "generate" or response.startswith(bytes.fromhex("7f49"))
            assert operation == "generate" or not response
        elif mode == "baseline":
            assert status != 0x6700 and prior != after, (key, results[key])
        else:
            assert status == 0x6700 and prior == after and not response, (key, results[key])

print(json.dumps({"passed": True, "mode": mode, "checks": len(results), "cases": results}, indent=2))
