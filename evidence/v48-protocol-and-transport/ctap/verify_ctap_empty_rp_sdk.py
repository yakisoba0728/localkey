#!/usr/bin/env python3
"""Exercise CTAP minPinLengthRPIDs over private CTAPHID with unmodified python-fido2."""
from __future__ import annotations
import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

from fido2.ctap2 import ClientPin, Config
from fido2.ctap2.pin import PinProtocolV2


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--expect', required=True, choices=('baseline', 'fixed'))
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    sys.path.insert(0, str(root / 'tools'))
    from verify_ctap import Fixture
    with tempfile.TemporaryDirectory(prefix='ske-ctap-empty-rp-', dir='/tmp') as directory:
        fixture = Fixture(args.binary.resolve(), Path(directory))
        try:
            ctap = fixture.start()
            pin = ClientPin(ctap)
            pin.set_pin('12345678')
            protocol = PinProtocolV2()
            def config():
                token = ClientPin(ctap, protocol).get_pin_token('12345678', ClientPin.PERMISSION.AUTHENTICATOR_CFG)
                return Config(ctap, protocol, token)
            config().set_min_pin_length(8, ['localhost'])
            config().set_min_pin_length(8, [])
            token = ClientPin(ctap, protocol).get_pin_token(
                '12345678', ClientPin.PERMISSION.MAKE_CREDENTIAL, 'localhost'
            )
            challenge = hashlib.sha256(b'isolated empty-rp regression').digest()
            credential = ctap.make_credential(
                challenge,
                {'id': 'localhost', 'name': 'Local fixture'},
                {'id': b'empty-rp-1'},
                [{'type': 'public-key', 'alg': -7}],
                options={'rk': True},
                extensions={'minPinLength': True},
                pin_uv_protocol=2,
                pin_uv_param=protocol.authenticate(token, challenge),
            )
            observed = credential.auth_data.extensions or {}
            retained = observed.get('minPinLength') == 8
        finally:
            fixture.stop()
    expected = args.expect == 'fixed'
    report = {'passed': retained == expected, 'expect': args.expect,
              'minPinLength_extension_after_empty_list': observed.get('minPinLength'),
              'previous_allowlist_retained': retained,
              'transport': 'private Unix CTAPHID; unmodified python-fido2 client',
              'physical_device_access': False}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
    if not report['passed']:
        raise SystemExit(1)

if __name__ == '__main__':
    main()
