"""Strict gate for native original-prefix64, one IO, interrupted completion waits."""
import hashlib
import importlib.util
import re
import struct
from pathlib import Path

spec = importlib.util.spec_from_file_location('native_ccid_io_gate', Path(__file__).with_name('validate-native-ccid-io.py'))
native_io = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native_io)


def validate(report):
    assert report['passed'], report.get('error')
    assert report['test_count'] == len(report['tests']) == 108
    assert all(row['passed'] for row in report['tests']) and not report.get('cleanup_error')
    assert report['same_generation_continuation_verified'] is True
    assert report['stock_piv_oath_sdk_unmodified'] is True
    assert report['fido_testing_auto_allow_only_for_owned_fixture'] is True
    for name in ['physical_device_access', 'host_device_passthrough', 'host_hid_drivers_unbound',
                 'native_macos_registration_verified', 'production_udc_verified', 'physical_touch_verified',
                 'manufacturer_trust_reproduced', 'card_testing_auto_allow',
                 'stock_libccid_transport_used_for_this_fixture', 'opaque_piv_object_is_valid_chuid']:
        assert report[name] is False, name
    assert len(set(report['service_pids'])) == 3
    initial, identity = report['original_identity'], report['profile6_identity']
    assert initial['vid'] == identity['vid'] == 0x1050
    assert initial['pid'] == 0x407 and identity['pid'] == 0x406
    assert initial['serial'] == identity['serial'] and initial['address'] != identity['address']
    assert identity['host_visible_endpoint_addresses'] == [4, 0x84, 2, 0x82, 0x83]
    assert 'dummy_hcd' in identity['path']
    sizes = [2047, 2048, 2049, 3071, 3072, 3073]
    assert len(report['cycles']) == 6 and report['final_hotp_counter'] == 6
    for index, (row, size) in enumerate(zip(report['cycles'], sizes)):
        assert row['index'] == index and row['phase'] == str(size) + '-partial64-signal'
        assert row['total_response_bytes'] == size and row['same_generation_exact_continuation_verified']
        assert row['before_usb'] == row['after_native_tail_usb'] == identity
        assert row['tgkill_result'] == row['tgkill_errno'] == 0
        assert row['bridge_status_before_tail'] is None
        assert set(row['service_status_after_tail']) == {'bridge', 'fido', 'card'}
        assert all(value is None for value in row['service_status_after_tail'].values())
        opaque = bytes((offset * 17 + size) & 255 for offset in range(size - 16))
        apdu = b'\x53\x82' + len(opaque).to_bytes(2, 'big') + opaque + b'\x90\x00'
        assert row['opaque_object_sha256'] == hashlib.sha256(opaque).hexdigest()
        length = min(size, 3072)
        packet = struct.pack('<BIBBBBB', 0x80, length - 10, 0, row['original_sequence'], 0, 0, 1 if size > 3072 else 0) + apdu[:length - 10]
        assert row['original_packet_bytes'] == length
        assert row['expected_original_packet_sha256'] == hashlib.sha256(packet).hexdigest()
        assert bytes.fromhex(row['original_prefix_hex']) == packet[:64]
        actual = row['native_tail_read']
        assert actual['libusb_result'] == 0 and actual['actual_length'] == length - 64
        assert actual['requested_length'] == length
        assert bytes.fromhex(actual['data_hex']) == packet[64:]
        assert actual['data_sha256'] == hashlib.sha256(packet[64:]).hexdigest()
        assert bytes.fromhex(row['actual_whole_data_hex']) == packet
        assert row['actual_whole_data_sha256'] == hashlib.sha256(packet).hexdigest()
        target = row['original_worker']
        assert row['worker_after_prefix64'] == target
        own = native_io.validate(target, row['original_write_entry'], row['actual_trace_after_tail'], report['service_pids'][0], length)
        waits = [line for line in own if 'sys_io_getevents(' in line or 'sys_enter_io_getevents:' in line]
        assert len(waits) == 2
        assert all('ctx_id: ' + format(target['context'], 'x') + ', min_nr: 1, nr: 1' in line for line in waits)
        exits = [line for line in own if re.search(r'(?:sys_exit_io_getevents:|sys_io_getevents ->)\s', line)]
        assert len(exits) == 2
        assert re.search(r'(?:sys_exit_io_getevents:|sys_io_getevents ->)\s*(?:0xfffffffffffffffc|-4)\b', exits[0])
        assert re.search(r'(?:sys_exit_io_getevents:|sys_io_getevents ->)\s*(?:0x1|1)\b', exits[1])
        assert row['original_tid_write_returns'] == exits[:1]
        signals = [line for line in own if re.search(r'signal_deliver:\s+sig=10\b', line)]
        assert len(signals) == 1 and row['actual_signal_deliveries'] == signals
        assert own.index(exits[0]) < own.index(signals[0]) < own.index(waits[1]) < own.index(exits[1])
        if size == 3073:
            assert row['continuation_header'][6] == 2
            assert packet[10:] + bytes.fromhex(row['continuation_hex']) == apdu
        else:
            assert packet[10:] == apdu
    signatures = report['assertions']
    assert len(signatures) == 7
    assert [row['phase'] for row in signatures] == ['initial'] + [str(size) + '-partial64-signal' for size in sizes]
    assert len({row['credential_sha256'] for row in signatures}) == 1
    assert len({row['challenge_sha256'] for row in signatures}) == 7
    assert all(row['signature_verified'] and row['rp_user_uv_verified'] and row['pin_uv_protocol'] == 2 for row in signatures)
    assert all(after['counter'] > before['counter'] for before, after in zip(signatures, signatures[1:]))
    assert re.findall(r'functionfs_reenumerated generation=(\d+)', report['usb.log']) == ['1']
    for name in ['emulator_binary_sha256', 'usb_bridge_binary_sha256', 'card_service_sha256', 'helper_sha256',
                 'shared_helper_sha256', 'long_cutover_helper_sha256', 'native_io_observer_sha256']:
        assert re.fullmatch('[0-9a-f]{64}', report[name])
