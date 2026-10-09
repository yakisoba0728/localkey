"""Validate actual queued CCID/native FIDO configuration-generation cutover."""
import re
import struct


def validate(report):
    assert report['passed'], report.get('error')
    assert report['test_count'] == len(report['tests']) == 86
    assert all(row['passed'] for row in report['tests'])
    assert not report.get('cleanup_error')
    assert report['native_pending_management_cutover_verified'] is True
    assert report['card_testing_auto_allow'] is False
    assert report['fido_testing_auto_allow_only_for_owned_fixture'] is True
    assert report['unread_reply_reboot_grace_is_private_model_not_physical_timing'] is True
    for key in ['physical_device_access', 'host_device_passthrough',
                'host_hid_drivers_unbound', 'manufacturer_trust_reproduced',
                'native_macos_registration_verified', 'production_udc_verified',
                'physical_touch_verified', 'physical_firmware_reboot_timing_verified',
                'host_cid_router_changes_response_bytes',
                'unmodified_multiple_separate_sdk_processes_verified']:
        assert report[key] is False, key
    assert len(set(report['service_pids'])) == 3
    assert set(report['final_process_status']) == {'bridge', 'fido', 'card'}
    assert all(value is None for value in report['final_process_status'].values())
    original, identity = report['original_identity'], report['profile6_identity']
    assert original['pid'] == 0x407 and identity['pid'] == 0x406
    assert original['vid'] == identity['vid'] == 0x1050
    assert original['serial'] == identity['serial']
    assert original['address'] != identity['address']
    assert 'dummy_hcd' in identity['path']
    assert identity['host_visible_endpoint_addresses'] == [4, 0x84, 2, 0x82, 0x83]
    cycles = report['cycles']
    assert [row['mode'] for row in cycles] == [
        'kernel-buffered-data', 'blocked-data', 'blocked-zlp', 'pending-terminal-abort']
    assert [row['counter_before_request'] for row in cycles] == [0, 2, 4, 5]
    assert [row['counter_at_cutover'] for row in cycles] == [1, 3, 4, 5]
    assert [row['counter_after_fresh_sdk'] for row in cycles] == [2, 4, 5, 6]
    assert [row['touch_counter_after'] for row in cycles] == [0, 0, 0, 1]
    assert report['final_hotp_counter'] == 6 and report['final_touch_counter'] == 1
    all_addresses = [original['address'], identity['address']]
    for index, row in enumerate(cycles):
        before, after, restored = (row[name] for name in [
            'before_usb', 'after_fido_only_usb', 'restored_usb'])
        assert before == (identity if index == 0 else cycles[index - 1]['restored_usb'])
        assert after['pid'] == 0x402 and after['classes'] == [3]
        assert after['host_visible_endpoint_addresses'] == [4, 0x84]
        assert before['serial'] == after['serial'] == restored['serial'] == identity['serial']
        assert restored['pid'] == 0x406
        assert restored['host_visible_configuration_descriptor_hex'] == identity['host_visible_configuration_descriptor_hex']
        assert row['old_handle_errno'] == 19
        assert row['native_management_ack_seconds'] > 0
        for key in ['original_services_alive', 'retained_card_plaintext_verified',
                    'new_generation_sdk_no_stale_response_verified',
                    'old_worker_absent_in_new_generation_verified']:
            assert row[key] is True, (index, key)
        all_addresses += [after['address'], restored['address']]
        if index:
            worker = row['original_worker']
            assert worker['tgid'] == report['service_pids'][0]
            assert worker['fd'] == 10 and worker['endpoint'] == '/dev/ffs-ske/ep4'
            assert worker['wchan'] == 'ffs_epfile_io' and worker['syscall'].split()[0] == '64'
            assert worker['bytes'] == [None, 19, 0, 10][index]
            entry = row['original_write_entry_before_configuration']
            expected = 'fd: a, buf: ' + format(int(worker['buffer'], 0), 'x') + ', count: ' + format(worker['bytes'], 'x')
            assert expected in entry
            assert re.search(r'\bske-usbd-' + str(worker['tid']) + r'\s', entry)
            assert entry in row['actual_cutover_write_trace']
    assert len(all_addresses) == len(set(all_addresses)) == 10

    def completed(evidence, size):
        assert evidence['fd'] == 10 and evidence['bytes'] == size
        assert evidence['kernel_write_completed_before_any_host_IN_read'] is True
        assert 'fd: a, buf: ' in evidence['entry']
        assert 'count: ' + format(size, 'x') in evidence['entry']
        assert re.search(r'\bske-usbd-' + str(evidence['tid']) + r'\s', evidence['entry'])
        assert re.search(r'(?:sys_exit_write:|sys_write ->)\s*(?:0x' + format(size, 'x') + '|' + str(size) + r')\b', evidence['exit'])
        assert evidence['entry'] in evidence['actual_trace']
        assert evidence['exit'] in evidence['actual_trace']

    completed(cycles[0]['completed_original_write'], 19)
    completed(cycles[1]['kernel_buffered_prior_slot_reply'], 10)
    zlp = cycles[2]
    packet = bytes.fromhex(zlp['original_data_packet_hex'])
    assert len(packet) == 64
    assert struct.unpack('<BIBBBBB', packet[:10]) == (0x80, 54, 0, zlp['original_sequence'], 0, 0, 0)
    assert packet[10:] == b'\x53\x32' + bytes(range(50)) + b'\x90\x00'
    assert int(zlp['original_worker']['buffer'], 0) == 0
    touch = cycles[3]
    assert touch['original_touch_canceled_without_approval'] is True
    assert touch['fresh_terminal_approval_verified'] is True
    assert touch['abort_control_seconds'] > 0
    assert touch['peer_native_getinfo_error'] == 6
    assert touch['host_cid_demultiplexing_used'] is True
    assert touch['stock_sdk_single_transaction_method_used_for_busy'] is True
    frames = touch['actual_native_hid_mux_frames']
    assert len(frames) >= 10
    for frame in frames:
        raw = bytes.fromhex(frame['hex'])
        assert len(raw) == 64 and raw[:4].hex() == frame['cid_hex']
        assert frame['direction'] in ['in', 'out']
    outgoing = [bytes.fromhex(frame['hex']) for frame in frames if frame['direction'] == 'out']
    incoming = [bytes.fromhex(frame['hex']) for frame in frames if frame['direction'] == 'in']
    busy = [packet for packet in incoming if packet[4:8] == b'\xbf\x00\x01\x06']
    assert len(busy) == 1
    cid = busy[0][:4]
    assert any(packet[:8] == cid + b'\x90\x00\x01\x04' for packet in outgoing)
    ping = b'own actual pending config peer'
    expected = cid + b'\x81' + len(ping).to_bytes(2, 'big') + ping
    assert any(packet.startswith(expected) for packet in outgoing)
    assert any(packet.startswith(expected) for packet in incoming)
    assert len({packet[:4] for packet in outgoing if packet[:4] != b'\xff' * 4}) == 2

    assertions = report['assertions']
    assert [row['phase'] for row in assertions] == ['initial'] + [
        mode + suffix for mode in [row['mode'] for row in cycles]
        for suffix in ['-fido-only', '-restored']]
    assert len({row['credential_sha256'] for row in assertions}) == 1
    assert len({row['challenge_sha256'] for row in assertions}) == 9
    for row in assertions:
        assert row['pin_uv_protocol'] == 2
        assert row['signature_verified'] and row['rp_user_uv_verified']
    counters = [row['counter'] for row in assertions]
    assert all(b > a for a, b in zip(counters, counters[1:]))
    assert report['usb.log'].count('functionfs_reenumerated generation=') == 9
    assert re.findall(r'functionfs_reenumerated generation=(\d+)', report['usb.log']) == [str(n) for n in range(1, 10)]
    assert re.findall(r'functionfs_configured endpoints=(\d+)', report['usb.log']) == ['6', '5'] + ['2', '5'] * 4
    for key in ['emulator_binary_sha256', 'usb_bridge_binary_sha256', 'card_service_sha256', 'helper_sha256']:
        assert re.fullmatch(r'[a-f0-9]{64}', report[key])
