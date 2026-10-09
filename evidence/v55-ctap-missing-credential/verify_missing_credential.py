#!/usr/bin/env python3
"""Private CTAPHID socket regression for absent resident credential management."""
from __future__ import annotations
import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, CredentialManagement
from fido2.ctap2.pin import PinProtocolV2

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from verify_ctap import Fixture

p = argparse.ArgumentParser()
p.add_argument('--binary', type=Path, required=True)
p.add_argument('--report', type=Path, required=True)
a = p.parse_args()
result = {}
with tempfile.TemporaryDirectory(prefix='v55-cm-') as tmp:
    fixture = Fixture(a.binary.resolve(), Path(tmp))
    try:
        ct = fixture.start()
        att = ct.make_credential(hashlib.sha256(b'v55-cm').digest(), {'id': 'example.test'},
                                  {'id': b'v55', 'name': 'tester'}, [{'type': 'public-key', 'alg': -7}],
                                  options={'rk': True})
        desc = {'type': 'public-key', 'id': att.auth_data.credential_data.credential_id}
        pin = PinProtocolV2()
        ClientPin(ct, pin).set_pin('12345678')
        token = ClientPin(ct, pin).get_pin_token('12345678', ClientPin.PERMISSION.CREDENTIAL_MGMT)
        cm = CredentialManagement(ct, pin, token)
        cm.delete_cred(desc)
        result['initial_delete'] = 'ok'
        for label, call in [
            ('second_delete', lambda: cm.delete_cred(desc)),
            ('update_deleted', lambda: cm.update_user_info(desc, {'id': b'v55', 'name': 'new'})),
            ('delete_unknown', lambda: cm.delete_cred({'type': 'public-key', 'id': b'unknown'})),
        ]:
            try:
                call()
                result[label] = 'accepted'
            except CtapError as e:
                result[label] = f'0x{int(e.code):02x}'
    finally:
        fixture.stop()
a.report.parent.mkdir(parents=True, exist_ok=True)
a.report.write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
