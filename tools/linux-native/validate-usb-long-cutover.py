"""Strict gate for actual native multi-packet/partial CCID generation cutover."""
import importlib.util
from pathlib import Path
import hashlib
import re
import struct


spec = importlib.util.spec_from_file_location('native_ccid_io_gate', Path(__file__).with_name('validate-native-ccid-io.py'))
native_io = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native_io)

def validate(report):
    assert report['passed'], report.get('error')
    assert report['test_count'] == len(report['tests']) == 328
    assert all(row['passed'] for row in report['tests'])
    assert not report.get('cleanup_error')
    assert report['native_large_partial_ccid_cutover_verified'] is True
    assert report['stock_piv_oath_sdk_unmodified'] is True
    assert report['owned_ccid_driver_handles_command_and_response_chaining'] is True
    assert report['unread_reply_reboot_grace_is_private_model_not_physical_timing'] is True
    assert report['fido_testing_auto_allow_only_for_owned_fixture'] is True
    for name in ['physical_device_access', 'host_device_passthrough', 'host_hid_drivers_unbound',
                 'native_macos_registration_verified', 'manufacturer_trust_reproduced',
                 'production_udc_verified', 'physical_touch_verified', 'physical_firmware_reboot_timing_verified',
                 'card_testing_auto_allow', 'stock_libccid_transport_used_for_this_fixture', 'opaque_piv_object_is_valid_chuid']:
        assert report[name] is False, name
    assert len(set(report['service_pids'])) == 3
    assert set(report['final_process_status']) == {'bridge', 'fido', 'card'}
    assert all(value is None for value in report['final_process_status'].values())
    original, identity = report['original_identity'], report['profile6_identity']
    assert original['pid'] == 0x407 and identity['pid'] == 0x406
    assert original['vid'] == identity['vid'] == 0x1050
    assert original['serial'] == identity['serial']
    assert 'dummy_hcd' in identity['path']
    assert identity['host_visible_endpoint_addresses'] == [4, 0x84, 2, 0x82, 0x83]
    cases = [(size, mode) for size in [2047, 2048, 2049, 3071, 3072, 3073]
             for mode in (['unread', 'partial64', 'zlp'] if size in (2048, 3072) else ['unread', 'partial64'])]
    assert len(report['cycles']) == len(cases) == 14
    addresses = [original['address'], identity['address']]
    for index, (row, (size, mode)) in enumerate(zip(report['cycles'], cases)):
        assert row['index'] == index and row['phase'] == str(size) + '-' + mode
        assert row['mode'] == mode and row['total_response_bytes'] == size
        assert row['opaque_object_bytes'] == size - 16
        opaque = bytes((offset * 17 + size) & 255 for offset in range(size - 16))
        digest = hashlib.sha256(opaque).hexdigest()
        assert row['opaque_object_sha256'] == row['restored_object_sha256'] == digest
        apdu = b'\x53\x82' + len(opaque).to_bytes(2, 'big') + opaque + b'\x90\x00'
        packet_size = min(size, 3072)
        chain = 1 if size > 3072 else 0
        expected = struct.pack('<BIBBBBB', 0x80, packet_size - 10, 0, row['original_sequence'], 0, 0, chain) + apdu[:packet_size - 10]
        assert row['original_packet_bytes'] == packet_size and row['original_ccid_response_chain_level'] == chain
        assert row['expected_original_packet_sha256'] == hashlib.sha256(expected).hexdigest()
        assert row['hotp_counter_before'] == index and row['hotp_counter_after_fresh_sdk'] == index + 1
        assert row['old_handle_errno'] == 19 and row['native_management_ack_seconds'] > 0
        for flag in ['retained_card_plaintext_verified', 'original_services_alive',
                     'fresh_sdk_no_stale_response_verified', 'old_worker_absent_in_new_generation_verified']:
            assert row[flag] is True, (index, flag)
        before, after, restored = (row[name] for name in ['before_usb', 'after_fido_only_usb', 'restored_usb'])
        assert before == (identity if not index else report['cycles'][index - 1]['restored_usb'])
        assert before['serial'] == after['serial'] == restored['serial'] == identity['serial']
        assert after['pid'] == 0x402 and after['classes'] == [3]
        assert after['host_visible_endpoint_addresses'] == [4, 0x84]
        assert restored['pid'] == 0x406
        assert restored['host_visible_configuration_descriptor_hex'] == identity['host_visible_configuration_descriptor_hex']
        addresses += [after['address'], restored['address']]
        target = row['original_worker']
        assert target['tgid'] == report['service_pids'][0]
        assert target['fd'] == 10 and target['bytes'] == packet_size
        entry = row['original_write_entry_before_host_read']
        if target.get('kind') == 'native-aio':
            own = native_io.validate(target, entry, row['actual_cutover_write_trace'], report['service_pids'][0], packet_size)
            context = 'ctx_id: ' + format(target['context'], 'x')
            assert any('sys_io_destroy(ctx: ' + format(target['context'], 'x') + ')' in line for line in own)
            assert any(re.search(r'(?:sys_exit_io_destroy:|sys_io_destroy ->)\s*(?:0x0|0)\b', line) for line in own)
            if mode != 'zlp':
                assert any('sys_io_cancel(' in line and context in line for line in own)
        else:
            assert target['endpoint'] == '/dev/ffs-ske/ep4' and target['wchan'] == 'ffs_epfile_io'
            assert target['syscall'].split()[0] == '64' and int(target['buffer'], 0) > 0
            assert re.search(r'\bske-usbd-' + str(target['tid']) + r'\s', entry)
            assert 'fd: a, buf: ' + format(int(target['buffer'], 0), 'x') + ', count: ' + format(packet_size, 'x') in entry
            assert entry in row['actual_cutover_write_trace']
        if mode == 'partial64':
            assert row['host_original_data_bytes_read_before_configuration'] == 64
            assert bytes.fromhex(row['original_prefix_hex']) == expected[:64]
        elif mode == 'unread':
            assert row['host_original_data_bytes_read_before_configuration'] == 0
        else:
            assert row['host_original_data_bytes_read_before_configuration'] == packet_size
            assert bytes.fromhex(row['original_data_packet_hex']) == expected
            assert row['positive_control_full_response_and_native_zlp_verified']
            assert row['original_zero_length_representation'] in ['blocked', 'kernel-buffered']
            if row['original_zero_length_representation'] == 'kernel-buffered':
                evidence = row['completed_original_zero_write']
                assert evidence['tid'] == target['tid'] and evidence['fd'] == 10 and evidence['bytes'] == 0
                assert evidence['kernel_write_completed_before_any_host_ZLP_read']
                assert 'fd: a, buf: 0, count: 0' in evidence['entry']
                assert re.search(r'(?:sys_exit_write:|sys_write ->)\s*(?:0x0|0)\b', evidence['exit'])
                assert evidence['entry'] in evidence['actual_trace'] and evidence['exit'] in evidence['actual_trace']
            else:
                zero = row['original_zlp_worker']
                assert zero['tid'] == target['tid'] and zero['bytes'] == 0 and int(zero['buffer'], 0) == 0
                assert zero['endpoint'] == target['endpoint'] and zero['wchan'] == 'ffs_epfile_io'
                assert row['original_zlp_write_entry_before_configuration'] in row['actual_cutover_write_trace']
        assert row['stock_sdk_force_short_for_large_provisioning'] is (size >= 3071)
        history = row['native_raw_large_command_history']
        if size >= 3071:
            outgoing = [item for item in history if item['direction'] == 'out']
            incoming = [item for item in history if item['direction'] == 'in' and 'header' in item]
            assert [(item['level'], item['bytes']) for item in outgoing] == [(1, 3072), (2, size - 3062 + 10)]
            assert [item['header'][6] for item in incoming] == [0x10, 0]
            assert incoming[0]['header'][1] == 0 and incoming[1]['header'][1] == 2
        else:
            assert history == []
        restored_history = row['native_restored_object_sdk_history']
        restored_levels = [item['header'][6] for item in restored_history if item['direction'] == 'in' and 'header' in item]
        if size == 3073:
            assert restored_levels.count(1) == restored_levels.count(2) == 1
            assert any(item.get('terminator') and item['bytes'] == 0 for item in restored_history)
    assert len(addresses) == len(set(addresses)) == 30
    assert report['final_hotp_counter'] == 14
    visibility = report['libusb_generation_visibility']
    assert len(visibility) == 15
    assert [row['expected_address'] for row in visibility] == [identity['address']] + [row['restored_usb']['address'] for row in report['cycles']]
    for row in visibility:
        assert row['selected_address'] == row['expected_address'] and row['selected_serial_matches']
        assert row['attempts'] and any(item['address'] == row['selected_address'] and item.get('serial_matches') for item in row['attempts'][-1])
    assertions = report['assertions']
    assert len(assertions) == 29
    assert [row['phase'] for row in assertions] == ['initial'] + [str(size) + '-' + mode + suffix for size, mode in cases for suffix in ['-fido-only', '-restored']]
    assert len({row['credential_sha256'] for row in assertions}) == 1
    assert len({row['challenge_sha256'] for row in assertions}) == 29
    assert all(row['signature_verified'] and row['rp_user_uv_verified'] and row['pin_uv_protocol'] == 2 for row in assertions)
    counters = [row['counter'] for row in assertions]
    assert all(b > a for a, b in zip(counters, counters[1:]))
    assert re.findall(r'functionfs_reenumerated generation=(\d+)', report['usb.log']) == [str(value) for value in range(1, 30)]
    assert re.findall(r'functionfs_configured endpoints=(\d+)', report['usb.log']) == ['6', '5'] + ['2', '5'] * 14
    for name in ['emulator_binary_sha256', 'usb_bridge_binary_sha256', 'card_service_sha256', 'helper_sha256', 'shared_helper_sha256']:
        assert re.fullmatch('[0-9a-f]{64}', report[name])
