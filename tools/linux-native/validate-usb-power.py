"""Gate actual kernel device PM observations with explicit UDC scope."""

def validate(report):
    assert report['passed'],report.get('error')
    assert report['test_count']==len(report['tests'])==50
    assert all(row['passed'] for row in report['tests'])
    assert not report.get('cleanup_error')
    assert report['native_kernel_device_pm_test_suspend_resume_verified'] is True
    assert report['fido_presence_auto_approved_only_for_owned_fixture'] is True
    for key in ['physical_device_access','host_device_passthrough','physical_touch_verified',
                'production_hardware_udcs_verified','native_macos_registration_verified',
                'manufacturer_trust_reproduced','physical_firmware_power_timing_or_pin_token_semantics_verified',
                'native_runtime_pm_verified','full_platform_sleep_verified','host_hid_drivers_unbound',
                'card_testing_auto_allow']:
        assert report[key] is False,key
    assert len(set(report['service_pids']))==3
    assert set(report['final_process_status'])=={'bridge','fido','card'}
    assert all(value is None for value in report['final_process_status'].values())
    assert report['usbfs_capabilities']&0x100
    assert [row['index'] for row in report['cycles']]==[0,1,2]
    pending=report['pending_ccid']
    assert len(report['assertions'])==4
    assert [row['phase'] for row in report['assertions']]==['initial']+[f'kernel-device-pm-{i}' for i in range(3)]
    for row in report['assertions']:
        assert row['pin_uv_protocol']==2
        assert all(row[k] for k in ['signature_verified','user_verified','user_handle_verified','rp_id_hash_verified'])
    assert len({row['credential_sha256'] for row in report['assertions']})==1
    assert len({row['challenge_sha256'] for row in report['assertions']})==4
    counters=[row['counter'] for row in report['assertions']]
    assert all(b>a for a,b in zip(counters,counters[1:]))
    for row in report['cycles']+[pending]:
        assert row['same_three_services'] and row['duration_seconds']>=4.5
        text=row['actual_trace']
        assert all(word in text for word in ['device_pm_callback_start:','device_pm_callback_end:','dpm_suspend','dpm_resume'])
        assert 'dummy_hcd.0' in text and 'dummy_udc.0' in text and 'usb 1-1' in text
        a,b=row['before_usb'],row['after_usb']
        assert a['address']!=b['address']
        assert a['serial']==b['serial']
        assert a['host_visible_configuration_descriptor_hex']==b['host_visible_configuration_descriptor_hex']
        for snapshot in [a,b]:
            assert 'dummy_hcd' in snapshot['path'] and snapshot['vid']==0x1050 and snapshot['pid']==0x0407
            assert snapshot['host_visible_endpoint_addresses']==[0x81,4,0x84,2,0x82,0x83]
    assert all(row['stock_hid_bindings_unchanged'] and row['udc_disconnect_and_reenumeration_observed'] for row in report['cycles'])
    for key in ['real_terminal_presence','actual_kernel_bulk_in_eshutdown_recovered',
                'old_handle_enodev_verified','new_sequence_sdk_recovery_without_stale_response_verified',
                'fresh_terminal_approval_required','independent_hotp_verified',
                'persistent_unchanged_while_pending','disconnect_cancels_pending_request_without_counter_mutation']:
        assert pending[key] is True,key
    assert pending['card_testing_auto_allow'] is False
    assert pending['counter_before']==0 and pending['counter_after']==1
    assert set(report['helper_sha256'])=={'verify-usb-power.py','usb-state-pending.py','verify-usb-state.py'}
    for digest in list(report['helper_sha256'].values())+[report['emulator_binary_sha256'],report['usb_bridge_binary_sha256'],report['card_service_sha256']]:
        assert len(digest)==64 and all(c in '0123456789abcdef' for c in digest)
