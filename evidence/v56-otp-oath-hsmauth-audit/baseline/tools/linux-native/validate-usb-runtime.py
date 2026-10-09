"""Gate actual stock runtime-PM observations; no physical power claims."""
import re

def validate(report):
    assert report['passed'],report.get('error')
    assert report['test_count']==len(report['tests'])==52
    assert all(row['passed'] for row in report['tests'])
    assert not report.get('cleanup_error') and not report.get('power_restore_error')
    assert report['native_runtime_pm_verified'] is True
    assert report['fido_and_card_testing_auto_allow_for_owned_fixture'] is True
    for key in ['physical_device_access','host_device_passthrough','production_udc_verified',
                'physical_touch_verified','host_hid_drivers_unbound','manufacturer_trust_reproduced',
                'native_macos_registration_verified','full_platform_sleep_verified',
                'physical_firmware_power_timing_or_pin_token_semantics_verified']:
        assert report[key] is False,key
    assert report['kernel_probe_symbols']==['autosuspend_check','usb_runtime_idle','usb_runtime_suspend','usb_runtime_resume']
    assert report['usbfs_capabilities']&0x100
    assert len(set(report['service_pids']))==3
    assert set(report['final_process_status'])=={'bridge','fido','card'}
    assert all(v is None for v in report['final_process_status'].values())
    assert report['exact_state_preserved'] and report['same_three_services_alive']
    assert report['identity']['vid']==report['profile6_identity']['vid']==0x1050
    assert report['identity']['pid']==0x407 and report['profile6_identity']['pid']==0x406
    assert report['identity']['address']!=report['profile6_identity']['address']
    assert report['identity']['serial']==report['profile6_identity']['serial']
    assert report['profile6_identity']['host_visible_endpoint_addresses']==[4,0x84,2,0x82,0x83]
    assert report['final']['device']['runtime_status']=='active'
    assert report['final']['device']['runtime_usage']=='0'
    assert report['final']['device']['runtime_suspended_time']=='0'
    assert 'usb 1-1: remote wakeup needed for autosuspend' in report['actual_kernel_log']
    assert re.search(r'autosuspend_check:.*result=4294967201(?=\s|$)',report['actual_kernel_trace'])
    assert re.search(r'rpm_return_int: rpm_suspend\+[^:]+:1-1 ret=-11(?=\s|$)',report['actual_kernel_trace'])
    assert len(report['observations'])==4
    for row in report['observations']:
        assert row['device']['runtime_status']=='active' and row['device']['runtime_usage']=='0'
        assert row['device']['control']=='auto' and row['device']['autosuspend_delay_ms']=='0'
        assert row['device']['runtime_suspended_time']=='0'
    assert [row['mode'] for row in report['cycles']]==['manual-on','native-fido-sdk','native-ccid-sdk']
    for index,row in enumerate(report['cycles']):
        assert row['index']==index and row['persistent_bytes_unchanged_during_suspend']
        assert row['same_three_services_alive'] and row['wait_for_resume_return']==[0]
        assert row['suspended']['runtime_status']==row['still_suspended']['runtime_status']=='suspended'
        assert row['suspended']['runtime_usage']==row['still_suspended']['runtime_usage']=='0'
        assert row['suspended']['control']==row['still_suspended']['control']=='auto'
        assert int(row['still_suspended']['runtime_suspended_time'])>int(row['before']['device']['runtime_suspended_time'])
        assert row['resumed']['runtime_status']=='active'
        assert row['after']==report['profile6_identity']
        for name in ['suspend','resume']:
            assert re.search(r'rpm_return_int: rpm_'+name+r'\+[^:]+:1-1 ret=0(?=\s|$)',row['actual_trace'])
            assert 'usb_runtime_'+name+':' in row['actual_trace']
        assert row['counter_before']==0
        assert row['counter_after']==(1 if index==2 else 0)
    assert [row['phase'] for row in report['assertions']]==['initial','manual-on','native-fido-sdk','native-ccid-sdk']
    for row in report['assertions']:
        assert row['pin_uv_protocol']==2
        assert all(row[k] for k in ['signature_verified','user_verified','user_handle_verified','rp_id_hash_verified'])
    assert len({row['credential_sha256'] for row in report['assertions']})==1
    assert len({row['challenge_sha256'] for row in report['assertions']})==4
    counters=[row['counter'] for row in report['assertions']]
    assert all(b>a for a,b in zip(counters,counters[1:]))
    assert set(report['helper_sha256'])=={'verify-usb-runtime.py','usb-state-pending.py','verify-usb-state.py'}
    for digest in list(report['helper_sha256'].values())+[report['emulator_binary_sha256'],report['usb_bridge_binary_sha256'],report['card_service_sha256']]:
        assert len(digest)==64 and all(c in '0123456789abcdef' for c in digest)
