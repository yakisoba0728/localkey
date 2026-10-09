"""Gate actual same-generation queued CCID data/ZLP runtime PM evidence."""
import re

def validate(report):
    assert report['passed'],report.get('error')
    assert report['test_count']==len(report['tests'])==205
    assert all(row['passed'] for row in report['tests'])
    assert not report.get('cleanup_error') and not report.get('power_restore_error')
    assert report['native_queued_runtime_pm_verified'] is True
    assert report['fido_testing_auto_allow_for_owned_fixture'] is True
    assert report['card_testing_auto_allow'] is False
    assert report['native_ccid_resume_slot_lifecycle_verified'] is True
    for key in ['physical_device_access','host_device_passthrough','manufacturer_trust_reproduced',
                'native_macos_registration_verified','production_udc_verified','physical_touch_verified',
                'full_platform_sleep_verified','host_hid_drivers_unbound']:assert report[key] is False,key
    assert report['kernel_probe_symbols']==['autosuspend_check','usb_runtime_idle','usb_runtime_suspend','usb_runtime_resume']
    assert report['usbfs_capabilities']&0x100 and report['borrowed_usbfs_fd']>=0
    identity=report['profile6_identity'];original=report['original_identity']
    assert identity['vid']==original['vid']==0x1050 and identity['pid']==0x406 and original['pid']==0x407
    assert identity['serial']==original['serial'] and identity['address']!=original['address']
    assert 'dummy_hcd' in identity['path']
    assert identity['host_visible_endpoint_addresses']==[4,0x84,2,0x82,0x83]
    assert report['borrowed_usbfs_node']==f'/dev/bus/usb/001/{identity["address"]:03d}'
    assert len(set(report['service_pids']))==3
    assert set(report['final_process_status'])=={'bridge','fido','card'}
    assert all(v is None for v in report['final_process_status'].values())
    cycles=report['cycles']
    assert [r['phase'] for r in cycles]==['data-0','data-1','data-2']
    assert [r['mode'] for r in cycles]==['manual-on','native-fido-sdk','new-usbfs-open']
    for index,row in enumerate(cycles):
        assert row['index']==index and row['counter_before_request']==index
        assert row['counter_before']==row['counter_after_resume']==row['counter_after_drain']==index+1
        assert row['independent_hotp_verified'] and row['following_sdk_no_stale_response_verified']
    zlp=report['zlp'];assert zlp['phase']=='zlp' and zlp['mode']=='manual-on'
    assert zlp['counter_before']==zlp['counter_after_resume']==zlp['counter_after_drain']==3
    assert zlp['data_packet_bytes']==64 and zlp['object_payload_bytes']==50 and zlp['zero_length_terminator_bytes']==0
    assert zlp['following_sdk_no_stale_response_verified'] and zlp['following_sdk_persistent_plaintext_unchanged']
    assert zlp['object_is_opaque_transport_fixture_not_valid_chuid'] is True
    assert zlp['following_read_reencrypts_unchanged_plaintext'] is True
    assert len({row['sequence'] for row in cycles+[zlp]})==4
    for row in cycles+[zlp]:
        assert row['before_usb']==row['after_usb']==identity
        assert row['persistent_bytes_unchanged_during_suspend'] and row['same_three_services_alive']
        assert row['native_fido_while_ccid_unread_verified'] and row['wait_for_resume_return']==[0]
        for observation in [row['suspended'],row['still_suspended']]:
            assert observation['runtime_status']=='suspended' and observation['runtime_usage']=='0'
            assert observation['control']=='auto' and observation['autosuspend_delay_ms']=='0'
        assert int(row['still_suspended']['runtime_suspended_time'])>int(row['before']['device']['runtime_suspended_time'])
        assert row['resumed']['runtime_status']=='active'
        before=row['before_worker']
        assert before['bytes']==(0 if row is zlp else 19)
        assert before['tgid']==report['service_pids'][0] and before['endpoint']=='/dev/ffs-ske/ep4'
        assert before['wchan']=='ffs_epfile_io' and before['syscall'].split()[0]=='64'
        if row is zlp:assert int(before['buffer'],0)==0
        else:assert int(before['buffer'],0)>0
        for worker in [row['suspended_worker'],row['resumed_worker']]:
            assert all(worker[k]==before[k] for k in ['tid','tgid','fd','bytes','buffer','endpoint','wchan'])
            assert worker['syscall'].split()[0]=='64'
        for name in ['suspend','resume']:
            assert re.search(r'rpm_return_int: rpm_'+name+r'\+[^:]+:1-1 ret=0(?=\s|$)',row['actual_trace'])
            assert 'usb_runtime_'+name+':' in row['actual_trace']
    assert [row['phase'] for row in report['assertions']]==['initial','data-0','data-1','data-2','zlp','kernel-buffered-hotp','terminal-presence']
    for row in report['assertions']:
        assert row['pin_uv_protocol']==2
        assert all(row[k] for k in ['signature_verified','credential_verified','user_verified','user_handle_verified','rp_id_hash_verified'])
    assert len({r['credential_sha256'] for r in report['assertions']})==1
    assert len({r['challenge_sha256'] for r in report['assertions']})==7
    counters=[row['counter'] for row in report['assertions']];assert all(b>a for a,b in zip(counters,counters[1:]))
    assert set(report['helper_sha256'])=={'verify-usb-runtime-pending.py','verify-usb-runtime.py','verify-usb-state.py','usb-state-pending.py'}
    for digest in list(report['helper_sha256'].values())+[report['emulator_binary_sha256'],report['usb_bridge_binary_sha256'],report['card_service_sha256']]:
        assert len(digest)==64 and all(c in '0123456789abcdef' for c in digest)
    # Only management's initial profile switch should create a new FunctionFS generation.
    assert report['usb.log'].count('functionfs_reenumerated generation=')==1

    buffered=report['kernel_buffered_hotp'];touch=report['pending_terminal_presence']
    assert buffered['phase']=='kernel-buffered-hotp' and buffered['response_representation']=='kernel-buffered'
    assert buffered['before_worker']['bytes']==19 and buffered['before_worker']['fd']==10
    assert buffered['before_worker']['kernel_write_completed_before_host_read']
    assert buffered['suspended_worker'] is None and buffered['resumed_worker'] is None
    assert buffered['counter_before_request']==3 and buffered['counter_before']==buffered['counter_after_resume']==buffered['counter_after_drain']==4
    assert buffered['independent_hotp_verified'] and buffered['following_sdk_no_stale_response_verified']
    assert touch['phase']=='terminal-presence' and touch['real_terminal_presence_verified']
    assert touch['card_testing_auto_allow'] is False and touch['fresh_actual_terminal_approval_required']
    assert touch['counter_before_request']==touch['counter_after_cancel']==0 and touch['counter_after_fresh_approval']==1
    assert touch['counter_before']==touch['counter_after_resume']==4
    assert touch['aborted_header']==[0x80,0,0,touch['sequence'],0x40,0xff,0]
    assert len(touch['original_wtx_headers'])>=2
    assert all(h==[0x80,0,0,touch['sequence'],0x80,1,0] for h in touch['original_wtx_headers'])
    assert touch['independent_hotp_verified'] and touch['following_sdk_no_stale_response_verified']
    assert touch['before_worker']['bytes']==10 and touch['before_worker']['tgid']==report['service_pids'][0]
    for worker in [touch['suspended_worker'],touch['resumed_worker']]:
        assert all(worker[k]==touch['before_worker'][k] for k in ['tid','tgid','fd','bytes','buffer','endpoint','wchan'])
    for row in cycles+[zlp,buffered,touch]:
        life=row['resume_card_lifecycle']
        assert life['notification_hex']=='5003'
        assert life['inactive_header'][0:3]==[0x81,0,0] and life['inactive_header'][4:]==[1,0,3]
        assert life['denied_unpowered_apdu_header'][0:3]==[0x80,0,0] and life['denied_unpowered_apdu_header'][4:]==[0x41,0xfe,0]
        assert life['poweron_header'][0:3]==[0x80,7,0] and life['poweron_header'][4:]==[0,0,0]
        assert life['atr_hex']=='3bf011000001e0' and life['active_header'][4:]==[0,0,0]
        assert life['explicit_poweron_required_verified'] and life['exact_persistent_state_unchanged_during_lifecycle']
        assert row['before_usb']==row['after_usb']==identity
        assert row['persistent_bytes_unchanged_during_suspend'] and row['same_three_services_alive']
        assert row['native_fido_while_ccid_unread_verified'] and row['wait_for_resume_return']==[0]
        for observation in [row['suspended'],row['still_suspended']]:
            assert observation['runtime_status']=='suspended' and observation['runtime_usage']=='0'
        assert int(row['still_suspended']['runtime_suspended_time'])>int(row['before']['device']['runtime_suspended_time'])
        assert row['resumed']['runtime_status']=='active'
        for name in ['suspend','resume']:
            assert re.search(r'rpm_return_int: rpm_'+name+r'\+[^:]+:1-1 ret=0(?=\s|$)',row['actual_trace'])
            assert 'usb_runtime_'+name+':' in row['actual_trace']
    def completed(evidence,size):
        assert evidence['fd']==10 and evidence['bytes']==size and evidence['kernel_write_completed_before_host_read']
        assert re.search(r'\bske-usbd-'+str(evidence['tid'])+r'\s',evidence['entry'])
        assert 'fd: a, buf: ' in evidence['entry'] and 'count: '+format(size,'x') in evidence['entry']
        assert re.search(r'(?:sys_exit_write:|sys_write ->)\s*(?:0x'+format(size,'x')+'|'+str(size)+r')\b',evidence['exit'])
        assert evidence['entry'] in evidence['actual_trace'] and evidence['exit'] in evidence['actual_trace']
    for row in cycles:
        primer=row['kernel_buffered_prior_reply'];completed(primer,10)
        assert primer['header']==[0x81,0,0,primer['sequence'],0,0,0] and primer['payload_hex']==''
    completed(buffered['before_worker'],19)
    assert zlp['piv_pin_and_management_authorization_revoked_verified'] and zlp['fresh_piv_pin_original_key_signature_verified']
    assert report['dummy_hcd_shared_fifo_occupied_by_kernel_buffered_prior_slot_reply_for_blocked_data']
    assert len(report['notifications'])==7
    assert [n['origin'] for n in report['notifications']]==['initial configuration']+['current resume']*6
    assert all(n['hex']=='5003' for n in report['notifications'])
    assert report['usb.log'].count('functionfs_suspend\n')==report['usb.log'].count('functionfs_resume\n')==6
    assert report['usb.log'].count('ccid_resume_inactive preserved_transfer_generation=1\n')==6
