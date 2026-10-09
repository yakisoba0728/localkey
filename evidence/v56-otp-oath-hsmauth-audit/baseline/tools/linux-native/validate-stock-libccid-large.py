"""Independent raw stock CCID, kernel, original-key and archive evidence gate."""
import base64
import hashlib
import hmac
import json
import re
import struct
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fido2 import cbor


def digest(data):
    return hashlib.sha256(data).hexdigest()


def tlv(tag, data):
    n = len(data)
    return bytes([tag]) + (bytes([n]) if n < 128 else b'\x82' + n.to_bytes(2, 'big')) + data


def packets(log):
    result = []
    for line in log.splitlines():
        m = re.fullmatch(r'\d+ (->|<-) ([0-9A-F]{6}) ((?:[0-9A-F]{2} )*)', line)
        if m:
            raw = bytes.fromhex(m[3])
            assert m[2] == '000000', 'unexpected reader index'
            assert len(raw) >= 10, ('empty or truncated stock CCID read', line)
            header = struct.unpack('<BIBBBBB', raw[:10])
            assert header[1] == len(raw) - 10 and header[2] == 0
            assert len(raw) <= 3072, 'stock CCID packet exceeds advertised maximum'
            result.append((m[1], header, raw[10:]))
    assert result and len(result) % 2 == 0
    exchanges = []
    for i in range(0, len(result), 2):
        out, response = result[i:i+2]
        assert out[0] == '->' and response[0] == '<-'
        assert out[1][3] == response[1][3], 'original stock request/response sequence'
        assert response[1][4:6] == (0, 0), 'successful active card transport'
        assert out[1][0] == 0x6f and response[1][0] == 0x80
        assert out[1][4] == out[1][6] == 0
        exchanges.append((out[1], out[2], response[1], response[2]))
    return exchanges


def assembled_transactions(exchanges):
    transactions, incoming, outgoing = [], b'', b''
    active_request = None
    for cmd, data, response, reply in exchanges:
        level, chain = cmd[5], response[6]
        if level in (1, 3):
            assert bool(incoming) == (level == 3)
            assert data and not reply and chain == 0x10
            incoming += data
            continue
        if level == 2:
            assert incoming and not outgoing
            request, incoming = incoming + data, b''
        elif level == 0:
            assert not incoming and not outgoing
            request = data
        else:
            assert level == 0x10 and not data and not incoming and outgoing
            request = active_request
        if chain in (1, 3):
            assert bool(outgoing) == (chain == 3)
            active_request = request
            outgoing += reply
        else:
            assert chain == (2 if outgoing else 0)
            assembled = outgoing + reply
            assert len(assembled) >= 2
            transactions.append((request, assembled))
            outgoing, active_request = b'', None
    assert not incoming and not outgoing
    return transactions


def kernel_completion(c, expected_first_packet_length):
    queued = re.findall(
        r'functionfs_async_queued address=130 tid=(\d+) fd=(\d+) context=(\d+) '
        r'request=(0x[0-9a-f]+) buffer=(0x[0-9a-f]+) bytes=(\d+)', c['usb_log_after_get'])
    assert queued and int(queued[-1][-1]) == expected_first_packet_length
    tid, fd, context, request, buffer, size = queued[-1]
    assert int(fd) > 2 and int(request, 0) and int(buffer, 0)
    trace = c['actual_kernel_trace']
    own = [line for line in trace.splitlines() if re.search(r'\bske-usbd-' + tid + r'\s', line)]
    submits = [line for line in own if 'sys_io_submit(' in line]
    submits_done = [line for line in own if 'sys_io_submit ->' in line]
    waits = [line for line in own if 'sys_io_getevents(' in line]
    waits_done = [line for line in own if 'sys_io_getevents ->' in line]
    assert len(submits) == len(submits_done) == len(waits) == len(waits_done) == 1
    assert 'ctx_id: ' + format(int(context), 'x') + ', nr: 1,' in submits[0]
    assert 'ctx_id: ' + format(int(context), 'x') + ', min_nr: 1, nr: 1,' in waits[0]
    assert submits_done[0].endswith('sys_io_submit -> 0x1')
    assert waits_done[0].endswith('sys_io_getevents -> 0x1')
    zero_entries = [line for line in own if 'sys_write(fd: ' + format(int(fd), 'x') + ', buf: 0, count: 0)' in line]
    assert len(zero_entries) == (1 if expected_first_packet_length % 64 == 0 else 0)
    if zero_entries:
        following = own[own.index(zero_entries[0]) + 1]
        assert following.endswith('sys_write -> 0x0')
    # Trace returns number of events. Raw io_event.res payload is not captured.
    return {'first_native_aio_bytes': expected_first_packet_length,
            'original_submit_count': 1, 'completion_event_count': 1,
            'native_zlp_write_completed': bool(zero_entries),
            'raw_io_event_res_payload_verified': False}


def original_keys(r):
    public_der = bytes.fromhex(r['original_piv_public_key_spki_hex'])
    assert digest(public_der) == r['original_piv_public_key_sha256']
    public_key = serialization.load_der_public_key(public_der)
    assert isinstance(public_key, ec.EllipticCurvePublicKey) and isinstance(public_key.curve, ec.SECP256R1)
    for c, p in zip(r['cycles'], r['piv_signatures'], strict=True):
        assert p['phase'] == c['phase']
        challenge = hashlib.sha256(('own stock large original PIV ' + c['phase']).encode()).digest()
        assert bytes.fromhex(p['digest_hex']) == challenge
        public_key.verify(bytes.fromhex(p['signature_hex']), challenge, ec.ECDSA(hashes.SHA256()))
    phases = ['initial'] + [c['phase'] for c in r['cycles']]
    assert len(r['assertions']) == len(phases)
    assert len({s['credential_id_hex'] for s in r['assertions']}) == 1
    assert len({s['cose_public_key_cbor_hex'] for s in r['assertions']}) == 1
    last_counter = 0
    for phase, s in zip(phases, r['assertions'], strict=True):
        assert s['phase'] == phase and s['pin_uv_protocol'] == 2
        cose = cbor.decode(bytes.fromhex(s['cose_public_key_cbor_hex']))
        assert cose[1] == 2 and cose[3] == -7 and cose[-1] == 1
        key = ec.EllipticCurvePublicNumbers(int.from_bytes(cose[-2], 'big'), int.from_bytes(cose[-3], 'big'), ec.SECP256R1()).public_key()
        auth = bytes.fromhex(s['auth_data_hex'])
        assert len(auth) == 37 and auth[:32] == hashlib.sha256(b'localhost').digest() and auth[32] & 5 == 5
        counter = int.from_bytes(auth[33:], 'big')
        assert counter == s['counter'] and counter > last_counter
        last_counter = counter
        challenge = hashlib.sha256(('own pending management ' + phase).encode()).digest()
        assert s['challenge_sha256'] == challenge.hex()
        assert digest(bytes.fromhex(s['credential_id_hex'])) == s['credential_sha256']
        assert bytes.fromhex(s['user_id_hex']) == b'own-usb-state-user'
        key.verify(bytes.fromhex(s['signature_hex']), auth + challenge, ec.ECDSA(hashes.SHA256()))


def validate(r, *, preserved_six=False):
    if preserved_six:
        assert not r['passed'] and r['error'] == 'ApduError: APDU error: SW=0x6700 (WRONG_LENGTH)'
        assert r['active_cycle']['total_response_bytes'] == 4095 and r['test_count'] == 64
        sizes = [2047, 2048, 2049, 3071, 3072, 3073]
    else:
        assert r['passed'] and not r.get('host_gate_error')
        sizes = [2047, 2048, 2049, 3071, 3072, 3073, 3078, 3079, 3080, 4095, 4096, 8192]
        assert r['final_hotp_counter'] == 12
    assert not r.get('cleanup_error') and r['test_count'] == len(r['tests']) and all(t['passed'] for t in r['tests'])
    for key in ['physical_device_access', 'host_device_passthrough', 'host_hid_drivers_unbound',
                'native_macos_registration_verified', 'production_udc_verified', 'physical_touch_verified',
                'manufacturer_trust_reproduced', 'card_testing_auto_allow', 'own_native_ccid_driver_used',
                'sdk_or_stock_driver_binary_patched',
                'opaque_piv_object_is_valid_chuid']:
        assert r[key] is False, key
    if 'production_source_modified_for_this_original_trial' in r:
        assert r['production_source_modified_for_this_original_trial'] is False
    if r.get('current_release_transport_verification') is True:
        assert r['source_transport_changed_for_this_test'] is False and r['test_count'] == 122
    if not preserved_six:
        for key in ['physical_piv_buffer_exact_header_boundary_verified', 'stock_sdk_formatter_used_for_raw_extended_put', 'full_platform_sleep_verified']:
            assert r[key] is False
    assert r['stock_piv_oath_sdk_unmodified'] and r['fido_testing_auto_allow_only_for_owned_fixture']
    assert len(set(r['service_pids'])) == 4 and all(v is None for v in r['final_service_status'].values())
    assert 'libccid.so' in r['pcscd.log'] and 'ske-ifd.so' not in r['pcscd.log']
    assert 'Driver version: 1.5.5' in r['pcscd.log'] and 'DriverOptions: 0x0000' in r['pcscd.log']
    provenance = r['stock_driver_provenance']
    assert provenance['packages'] == {'libccid': '1.5.5-1', 'pcscd': '2.0.3-1build1', 'libpcsclite1': '2.0.3-1build1'}
    assert provenance['sdk_versions'] == r['stock_sdk_versions'] == {'fido2': '2.2.1', 'yubikey-manager': '5.9.2', 'pyscard': '2.3.1'}
    driver = provenance['files']['/usr/lib/pcsc/drivers/ifd-ccid.bundle/Contents/Linux/libccid.so']
    assert driver == r['driver_binary_sha256_before']
    if not preserved_six:
        assert driver == r['driver_binary_sha256_after']
    logging = r['driver_info_plist_logging_only']
    assert logging['all_other_parsed_fields_unchanged'] and logging['before_value'] == '0x0003' and logging['after_value'] == '0x0007'
    assert logging['before_sha256'] == provenance['files']['/usr/lib/pcsc/drivers/ifd-ccid.bundle/Contents/Info.plist']
    initial, identity = r['original_identity'], r['profile6_identity']
    assert initial['vid'] == identity['vid'] == 0x1050 and initial['pid'] == 0x407 and identity['pid'] == 0x406
    assert initial['serial'] == identity['serial'] and initial['address'] != identity['address']
    assert 'dummy_hcd' in identity['path'] and identity['host_visible_endpoint_addresses'] == [4, 0x84, 2, 0x82, 0x83]
    assert identity['serial'] in r['reader_name']
    assert re.findall(r'functionfs_reenumerated generation=(\d+)', r['usb.log']) == ['1']
    assert len(r['cycles']) == len(sizes)
    wire = []
    retained = None
    for index, (c, total) in enumerate(zip(r['cycles'], sizes, strict=True)):
        negative = index >= 8
        opaque = bytes((offset * 29 + total) & 255 for offset in range(total - 16))
        expected_reply = tlv(0x53, opaque) + b'\x90\x00'
        assert c['index'] == index and c['total_response_bytes'] == total and c['opaque_bytes'] == len(opaque)
        assert c['opaque_sha256'] == digest(opaque) and bytes.fromhex(c['expected_get_apdu_hex']) == expected_reply
        if not preserved_six:
            assert c['oversized_piv_request'] is negative
            assert c['put_transport_method'] == ('stock_connection_raw_extended' if index >= 6 else 'unmodified_piv_sdk')
        exchanges = packets(c['stock_pcscd_log'])
        transactions = assembled_transactions(exchanges)
        actual_object = retained if negative else opaque
        actual_reply = tlv(0x53, actual_object) + b'\x90\x00'
        assert bytes.fromhex(c['actual_sdk_object_hex']) == actual_object and c['actual_sdk_object_sha256'] == digest(actual_object)
        assert c['after_put_plaintext_sha256'] == c['after_get_plaintext_sha256']
        get = [(q, response) for q, response in transactions if q[1:4] == b'\xcb\x3f\xff']
        assert len(get) == 1 and get[0][1] == actual_reply
        assert len(get[0][0]) in (10, 12)
        assert c['before_usb'] == c['after_usb'] == identity
        if index >= 6:
            body = tlv(0x5c, bytes.fromhex('5fc102')) + tlv(0x53, opaque)
            raw = b'\x00\xdb\x3f\xff\x00' + len(body).to_bytes(2, 'big') + body
            assert bytes.fromhex(c['stock_raw_put_apdu_hex']) == raw and c['assembled_piv_put_data_bytes'] == len(body)
            assert c['raw_put_response_hex'] == '' and c['raw_put_status_word'] == (0x6700 if negative else 0x9000)
            put = [(q, response) for q, response in transactions if q[1:4] == b'\xdb\x3f\xff']
            assert put == [(raw, struct.pack('>H', c['raw_put_status_word']))]
            levels = [cmd[5] for cmd, data, response, reply in exchanges if cmd[5] != 0x10 and (cmd[5] or data[1:4] == b'\xdb\x3f\xff')]
            pieces = (len(raw) + 3061) // 3062
            assert levels == [1] + [3] * (pieces - 2) + [2] and pieces >= 2
            if negative:
                assert len(body) > 3072 and c['before_put_plaintext_sha256'] == c['after_put_plaintext_sha256']
                assert bytes.fromhex(c['retained_object_hex']) == retained
            else:
                assert len(body) in (3071, 3072)
        n = c['hotp_before_counter']
        mac = hmac.new(base64.b32decode('JBSWY3DPEHPK3PXP'), n.to_bytes(8, 'big'), 'sha1').digest()
        off = mac[-1] & 15
        expected = str((int.from_bytes(mac[off:off+4], 'big') & 0x7fffffff) % 1000000).zfill(6)
        assert n == index and c['hotp_after_counter'] == index + 1
        assert c['hotp_actual_value'] == c['hotp_independent_expected_value'] == expected
        native = kernel_completion(c, min(len(actual_reply) + 10, 3072))
        response_packets = [h[1] + 10 for cmd, data, h, reply in exchanges if reply and (reply.startswith(b'\x53\x82') or cmd[5] == 0x10)]
        assert response_packets == ([len(actual_reply) + 10] if len(actual_reply) <= 3062 else [3072, len(actual_reply) - 3062 + 10])
        wire.append({'phase': c['phase'], 'stock_ccid_exchange_count': len(exchanges),
                     'actual_get_response_packet_lengths': response_packets, **native})
        if not negative:
            retained = opaque
    original_keys(r)
    return wire


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('artifacts', type=Path)
    parser.add_argument('--preserved-six', action='store_true')
    args = parser.parse_args()
    r = json.loads((args.artifacts / 'result.json').read_text())
    assert digest((args.artifacts / 'console.log').read_bytes()) == r['console_sha256']
    s = (args.artifacts / 'console.log').read_text(errors='replace')
    a, b = 'SKE_STOCK_LIBCCID_LARGE_PROBE_BEGIN', 'SKE_STOCK_LIBCCID_LARGE_PROBE_END'
    assert s.count(a) == s.count(b) == 1
    actual = json.loads(s.split(a)[1].split(b)[0].strip())
    for k, value in actual.items():
        assert r[k] == value, ('raw guest report differs', k)
    assert r['runner_exit'] == 0
    assert 'SKE_STOCK_LIBCCID_LARGE_PROBE_GUEST_EXIT=' + ('1' if args.preserved_six else '0') in s
    wire = validate(r, preserved_six=args.preserved_six)
    assert json.loads((args.artifacts / 'stock-driver-provenance.json').read_text()) == r['stock_driver_provenance']
    print(json.dumps({'passed': True, 'preserved_original_failure': args.preserved_six,
                      'native_cycles_independently_verified': len(wire),
                      'raw_original_fido_signatures_verified': len(r['assertions']),
                      'raw_original_piv_signatures_verified': len(r['piv_signatures']),
                      'wire': wire}, indent=2))


if __name__ == '__main__':
    main()
