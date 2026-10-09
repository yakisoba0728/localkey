"""Gate real native interruption evidence without extending its hardware scope."""
import re

def validate(report):
    assert report['passed'],report.get('error')
    assert report['mode']=='full'
    assert report['test_count']==len(report['tests'])==113
    assert all(row['passed'] for row in report['tests'])
    assert not report.get('cleanup_error')
    assert all(report[key] is True for key in [
        'actual_native_ccid_in_eintr_recovery_verified',
        'actual_native_bulk_zlp_eintr_recovery_verified',
        'actual_native_fido_isolation_verified','same_usb_generation_retained',
        'fido_presence_auto_approved_only_for_owned_fixture'])
    assert all(report[key] is False for key in [
        'physical_device_access','host_device_passthrough','manufacturer_trust_reproduced',
        'native_macos_registration_verified','production_hardware_udcs_verified',
        'physical_touch_verified','card_testing_auto_allow'])
    assert len(set(report['service_pids']))==3
    assert report['trace_events_armed_before_original_data_and_zlp_write'] is True
    assert 'name: sys_enter_write' in report['write_entry_format']
    assert 'name: sys_exit_write' in report['write_exit_format']
    assert 'name: signal_deliver' in report['signal_delivery_format']
    assert [row['index'] for row in report['cycles']]==[0,1,2]
    assert len(report['signals'])==12
    assert len({row['before']['tid'] for row in report['signals']})==1
    for row in report['signals']:
        a,b=row['before'],row['after']
        assert a['tgid']==b['tgid']==report['service_pids'][0]
        assert a['tid']==b['tid'] and a['tid']!=a['tgid']
        assert a['fd']==b['fd'] and a['buffer']==b['buffer']
        assert a['bytes']==b['bytes']==(0 if row['cycle']=='zlp' else 19)
        assert (int(a['buffer'],0)==0)==(row['cycle']=='zlp')
        assert a['syscall'].split()[0]=='64' and b['syscall'].split()[0]=='64'
        assert row['actual_kernel_write_errno']==4 and row['signal']==10
        text=row['actual_trace']
        assert len(re.findall(r'(?:sys_exit_write:|sys_write ->)\s*(?:0xfffffffffffffffc|-4)\b',text))==row['attempt']+1
        assert len(re.findall(r'signal_deliver: sig=10 .*sa_flags=0\b',text))==row['attempt']+1
        assert 'ske-usbd-'+str(a['tid']) in text
    for cycle in report['cycles']+[report['zlp']]:
        assert cycle['same_three_services']
        a,b=cycle['before_usb'],cycle['after_usb']
        assert a['address']==b['address'] and a['serial']==b['serial']
        assert a['host_visible_configuration_descriptor_hex']==b['host_visible_configuration_descriptor_hex']
        for snapshot in [a,b]:
            assert 'dummy_hcd' in snapshot['path'] and snapshot['vid']==0x1050 and snapshot['pid']==0x0407
            assert snapshot['host_visible_endpoint_addresses']==[0x81,4,0x84,2,0x82,0x83]
    for cycle in report['cycles']+[report['zlp']]:
        signals=[r for r in report['signals'] if r['cycle']==('zlp' if cycle is report['zlp'] else cycle['index'])]
        target=signals[0]['before'];entry=cycle['original_write_entry_before_signal']
        wanted='fd: '+format(target['fd'],'x')+', buf: '+format(int(target['buffer'],0),'x')+', count: '+format(target['bytes'],'x')
        assert wanted in entry and 'ske-usbd-'+str(target['tid']) in entry
        for row in signals:
            assert entry in row['actual_trace']
            assert row['actual_trace'].index(entry)<row['actual_trace'].index('signal_deliver:')
    for row in report['cycles']:
        assert row['counter_before']==row['index'] and row['counter_after']==row['index']+1
        assert row['independent_hotp_verified'] and row['following_sdk_no_stale_response_verified']
    zlp=report['zlp']
    assert zlp['data_packet_bytes']==64 and zlp['object_payload_bytes']==50 and zlp['zero_length_terminator_bytes']==0
    assert zlp['counter_before']==zlp['counter_after']==3
    assert all(zlp[key] for key in [
        'independent_original_object_bytes_verified','only_zero_length_retried_without_duplicate_data',
        'following_native_sdk_no_stale_response_verified','exact_ciphertext_unchanged_during_interruptions',
        'following_sdk_persistent_plaintext_unchanged'])
    assert [row['phase'] for row in report['assertions']]==['initial','interrupt-0','interrupt-1','interrupt-2','zlp-interrupt']
    assert all(row['pin_uv_protocol']==2 for row in report['assertions'])
    assert all(row[key] for row in report['assertions'] for key in [
        'signature_verified','user_verified','user_handle_verified','rp_id_hash_verified'])
    assert len({row['credential_sha256'] for row in report['assertions']})==1
    assert len({row['challenge_sha256'] for row in report['assertions']})==5
    counters=[row['counter'] for row in report['assertions']]
    assert all(b>a for a,b in zip(counters,counters[1:]))
    assert set(report['helper_sha256'])=={'verify-usb-interrupt.py','verify-usb-state.py','usb-state-pending.py'}
    for digest in list(report['helper_sha256'].values())+[
        report['emulator_binary_sha256'],report['usb_bridge_binary_sha256'],report['card_service_sha256']]:
        assert len(digest)==64 and all(c in '0123456789abcdef' for c in digest)
