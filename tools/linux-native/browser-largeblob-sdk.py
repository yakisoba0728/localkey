"""Independent native HID SDK evidence for a fresh own browser credential.

The caller closes its own browser before these native SDK operations, and
restarts the same profile afterwards. This avoids replacing a browser-cached
PIN token from another client in the middle of an interactive request.
No physical device, manufacturer credential or existing account is used.
"""
import hashlib
from pathlib import Path
from fido2.ctap2 import Ctap2
from fido2.ctap2.blob import LargeBlobs
from fido2.ctap2.pin import ClientPin, PinProtocolV2
from fido2.hid import CtapHidDevice


def compare_and_replace(fixture, row, browser_payload, sdk_payload):
    assert Path('/opt/isolated-ske-usb-guest').exists()
    assert [p.name for p in Path('/sys/class/net').iterdir()] == ['lo']
    own = [d for d in CtapHidDevice.list_devices() if d.descriptor.serial_number == fixture.serial]
    assert len(own) == 1
    with own[0] as device:
        ctap = Ctap2(device)
        protocol = PinProtocolV2()
        pin = ClientPin(ctap, protocol)
        token = pin.get_pin_token('own-browser-pin', ClientPin.PERMISSION.GET_ASSERTION, 'localhost')
        challenge_hash = hashlib.sha256(b'own-largeblob-sdk-reference' + row['user_id']).digest()
        response = ctap.get_assertion(
            'localhost', challenge_hash,
            allow_list=[{'type': 'public-key', 'id': row['credential'].credential_id}],
            extensions={'largeBlobKey': True}, pin_uv_protocol=2,
            pin_uv_param=protocol.authenticate(token, challenge_hash),
        )
        assert response.auth_data.flags & 5 == 5
        assert response.credential['id'] == row['credential'].credential_id
        assert response.user['id'] == row['user_id']
        row['credential'].public_key.verify(response.auth_data + challenge_hash, response.signature)
        assert response.auth_data.counter > row['counter']
        row['counter'] = response.auth_data.counter
        key = response.large_blob_key
        assert isinstance(key, bytes) and len(key) == 32
        before = LargeBlobs(ctap).get_blob(key)
        assert before == browser_payload, 'independent SDK plaintext differs from actual browser write'
        unrelated_key = hashlib.sha256(b'own-unrelated-largeblob-key').digest()
        assert unrelated_key != key and LargeBlobs(ctap).get_blob(unrelated_key) is None
        write_token = pin.get_pin_token('own-browser-pin', ClientPin.PERMISSION.LARGE_BLOB_WRITE)
        LargeBlobs(ctap, protocol, write_token).put_blob(key, sdk_payload)
        assert LargeBlobs(ctap).get_blob(key) == sdk_payload
        return {
            'independent_sdk_signature_verified': True, 'independent_sdk_user_verified': True,
            'independent_sdk_user_handle_verified': True, 'independent_sdk_pin_uv_protocol': 2,
            'independent_sdk_browser_blob_match': True, 'independent_sdk_replacement_verified': True,
            'unrelated_key_has_no_blob': True, 'credential_sha256': hashlib.sha256(row['credential'].credential_id).hexdigest(),
            'large_blob_key_sha256': hashlib.sha256(key).hexdigest(),
            'browser_payload_sha256': hashlib.sha256(browser_payload).hexdigest(),
            'sdk_payload_sha256': hashlib.sha256(sdk_payload).hexdigest(),
            'browser_payload_bytes': len(browser_payload), 'sdk_payload_bytes': len(sdk_payload),
            'sdk_counter': response.auth_data.counter,
        }
