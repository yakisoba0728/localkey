"""Gate native USB state observations without expanding their hardware scope."""


def validate(report):
    assert report['passed'], report.get('error')
    assert report['test_count'] == len(report['tests']) == 91
    assert all(item['passed'] for item in report['tests'])
    assert not report.get('cleanup_error')
    assert all(report[key] for key in [
        'native_all_six_endpoint_halt_recovery_verified',
        'native_usbdevfs_reset_recovery_verified',
        'native_unconfigure_configure_recovery_verified',
    ])
    assert all(report[key] is False for key in [
        'physical_device_access', 'host_device_passthrough',
        'manufacturer_trust_reproduced', 'native_macos_registration_verified',
        'production_hardware_udcs_verified',
        'physical_firmware_reset_or_pin_token_semantics_verified',
    ])
    assert [row['endpoint'] for row in report['halts']] == [0x81, 4, 0x84, 2, 0x82, 0x83]
    assert all(row['halt_status'] == 1 and row['host_errno'] == 32
               and row['cleared_status'] == 0 for row in report['halts'])
    assert [row['index'] for row in report['resets']] == [0, 1, 2]
    assert all(row['same_three_services'] for row in report['resets'])
    for row in report['resets'] + [report['configuration_cycle'], report['pending_ccid']]:
        assert row['same_three_services']
        assert row['before']['serial'] == row['after']['serial']
        assert row['before']['host_visible_configuration_descriptor_hex'] == row['after']['host_visible_configuration_descriptor_hex']
        for snapshot in [row['before'], row['after']]:
            assert 'dummy_hcd' in snapshot['path'] and snapshot['vid'] == 0x1050 and snapshot['pid'] == 0x0407
            assert snapshot['host_visible_endpoint_addresses'] == [0x81, 4, 0x84, 2, 0x82, 0x83]
    assert [row['phase'] for row in report['assertions']] == [
        'initial', 'six-endpoint-halts', 'usb-reset-0', 'usb-reset-1',
        'usb-reset-2', 'configuration-cycle', 'pending-ccid-reset',
    ]
    assert all(row[key] for row in report['assertions'] for key in [
        'signature_verified', 'user_verified', 'user_handle_verified', 'rp_id_hash_verified',
    ])
    assert all(row['pin_uv_protocol'] == 2 for row in report['assertions'])
    assert len({row['credential_sha256'] for row in report['assertions']}) == 1
    assert len({row['challenge_sha256'] for row in report['assertions']}) == 7
    counters = [row['counter'] for row in report['assertions']]
    assert all(b > a for a, b in zip(counters, counters[1:]))
    pending = report['pending_ccid']
    assert all(pending[key] for key in [
        'native_terminal_presence_wait_observed', 'native_time_extension_observed',
        'native_fido_sdk_getinfo_during_wait_verified', 'native_fido_ping_during_wait_verified',
        'reset_cancels_without_counter_mutation', 'new_sequence_sdk_recovery_without_stale_response_verified',
        'fresh_terminal_approval_and_independent_hotp_verified',
    ])
    assert pending['counter_before'] == 0 and pending['counter_after'] == 1
    assert pending['physical_touch_verified'] is False and pending['card_testing_auto_allow'] is False
    assert report['controller']['requested_ep_addresses_enabled'] is True
    assert set(report['helper_sha256']) == {'verify-usb-state.py', 'usb-state-pending.py'}
    for digest in list(report['helper_sha256'].values()) + [
        report['emulator_binary_sha256'], report['usb_bridge_binary_sha256'], report['card_service_sha256'],
    ]:
        assert len(digest) == 64 and all(c in '0123456789abcdef' for c in digest)
