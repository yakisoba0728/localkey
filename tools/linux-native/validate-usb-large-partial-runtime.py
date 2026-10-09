"""Strict current native large-prefix64 runtime-PM, lifecycle and original-key gate."""
import hashlib,importlib.util,re,struct
from pathlib import Path

def validate(r):
    assert r['passed']
    assert r['test_count']==len(r['tests'])==534 and all(row['passed'] for row in r['tests'])
    assert not r.get('cleanup_error') and not r.get('host_gate_error')
    for field in ['physical_device_access','host_device_passthrough','host_hid_drivers_unbound','native_macos_registration_verified',
                  'production_udc_verified','physical_touch_verified','manufacturer_trust_reproduced','card_testing_auto_allow',
                  'stock_libccid_transport_used_for_this_fixture','opaque_piv_object_is_valid_chuid','full_platform_sleep_verified']:
        assert r[field] is False,field
    assert r['stock_piv_oath_sdk_unmodified'] and r['fido_testing_auto_allow_only_for_owned_fixture']
    assert r['same_generation_continuation_verified'] and len(set(r['service_pids']))==3
    assert r['usbfs_capabilities']&0x100
    spec=importlib.util.spec_from_file_location('pending_aio',Path(__file__).with_name('validate-native-ccid-io.py'))
    gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
    initial,identity=r['original_identity'],r['profile6_identity']
    assert initial['vid']==identity['vid']==0x1050 and initial['pid']==0x407 and identity['pid']==0x406
    assert initial['serial']==identity['serial'] and initial['address']!=identity['address']
    assert identity['host_visible_endpoint_addresses']==[4,0x84,2,0x82,0x83] and 'dummy_hcd' in identity['path']
    sizes=[2047,2048,2049,3071,3072,3073]
    matrix=[(size,mode) for size in sizes for mode in ['manual-on','native-fido-sdk','new-usbfs-open']]
    assert len(r['cycles'])==18 and r['final_hotp_counter']==18
    assert r['runtime_mode_matrix']==[{'total_response_bytes':size,'mode':mode} for size,mode in matrix]
    for index,(c,(size,mode)) in enumerate(zip(r['cycles'],matrix)):
        assert c['index']==index and c['total_response_bytes']==size and c['runtime_mode']==mode
        assert c['phase']==str(size)+'-partial64-runtime-'+mode
        assert c['before_usb']==c['after_native_tail_usb']==identity
        assert c['same_generation_exact_continuation_verified'] and c['exact_native_original_tail_verified']
        assert c['bridge_status_before_tail'] is None
        assert all(v is None for v in c['service_status_while_suspended'].values())
        assert all(v is None for v in c['service_status_after_tail'].values())
        target=c['original_worker']
        assert c['worker_after_prefix64']==c['worker_while_suspended']==c['worker_after_resume']==target
        opaque=bytes((offset*17+size)&255 for offset in range(size-16))
        apdu=b'\x53\x82'+len(opaque).to_bytes(2,'big')+opaque+b'\x90\x00'
        length=min(size,3072)
        packet=struct.pack('<BIBBBBB',0x80,length-10,0,c['original_sequence'],0,0,1 if size>3072 else 0)+apdu[:length-10]
        assert c['original_packet_bytes']==length
        assert c['opaque_object_sha256']==hashlib.sha256(opaque).hexdigest()
        assert c['expected_original_packet_sha256']==hashlib.sha256(packet).hexdigest()
        assert bytes.fromhex(c['original_prefix_hex'])==packet[:64]
        actual=c['native_tail_read']
        assert actual['libusb_result']==0 and actual['actual_length']==length-64 and actual['requested_length']==length
        assert bytes.fromhex(actual['data_hex'])==packet[64:]
        assert actual['data_sha256']==hashlib.sha256(packet[64:]).hexdigest()
        assert bytes.fromhex(c['actual_whole_data_hex'])==packet and c['actual_whole_data_sha256']==hashlib.sha256(packet).hexdigest()
        assert not c['repeated_original_header_observed']
        own=gate.validate(target,c['original_write_entry'],c['actual_trace_after_tail'],r['service_pids'][0],length)
        waits=[line for line in own if 'sys_io_getevents(' in line or 'sys_enter_io_getevents:' in line]
        exits=[line for line in own if re.search(r'(?:sys_exit_io_getevents:|sys_io_getevents ->)\s',line)]
        assert len(waits)==len(exits)==1
        assert 'ctx_id: '+format(target['context'],'x')+', min_nr: 1, nr: 1' in waits[0]
        assert re.search(r'(?:sys_exit_io_getevents:|sys_io_getevents ->)\s*(?:0x1|1)\b',exits[0])
        before=c['runtime_before']['device'];suspended=c['runtime_suspended'];still=c['runtime_still_suspended'];resumed=c['runtime_resumed']
        assert before['runtime_status']==resumed['runtime_status']=='active'
        assert suspended['runtime_status']==still['runtime_status']=='suspended' and still['runtime_usage']=='0'
        assert int(still['runtime_suspended_time'])>int(before['runtime_suspended_time'])
        assert c['allow_suspend_return']==0 and c['wait_for_resume_returns']==[0] and not c['wait_for_resume_thread_alive']
        assert c['plaintext_while_suspended_sha256']==c['durable_plaintext_sha256'] and c['counter_while_suspended']==index
        trace=c['runtime_trace_before_tail']
        for action in ['suspend','resume']:
            assert re.search(r'rpm_return_int: rpm_'+action+r'\+[^:]+:1-1 ret=0(?=\s|$)',trace)
            assert 'usb_runtime_'+action+':' in trace
        assert c['resume_notification_hex']=='5003'
        assert c['inactive_header'][0]==0x81 and c['inactive_header'][4:]==[1,0,3]
        assert c['poweron_header'][0]==0x80 and c['poweron_header'][4:]==[0,0,0]
        assert c['atr_hex']=='3bf011000001e0'
        assert c['unauthorized_post_resume_sign_sw']==c['unauthorized_post_resume_put_sw']==0x6982
        assert c['fresh_piv_pin_original_key_signature_verified'] is True
        if size==3073:
            assert c['post_resume_original_chain_complete'] is False
            assert c['post_resume_original_chain_inactive_denied'] is True
            header=c['post_resume_chain_header']
            assert header[0]==0x80 and header[1]==0 and header[4:]==[0x41,0xfe,0]
            assert c['post_resume_chain_payload_hex']==''
        else:assert packet[10:]==apdu
    signatures=r['assertions']
    assert len(signatures)==19 and [v['phase'] for v in signatures]==['initial']+[c['phase'] for c in r['cycles']]
    assert len({v['credential_sha256'] for v in signatures})==1 and len({v['challenge_sha256'] for v in signatures})==19
    assert all(v['signature_verified'] and v['rp_user_uv_verified'] and v['pin_uv_protocol']==2 for v in signatures)
    assert all(after['counter']>before['counter'] for before,after in zip(signatures,signatures[1:]))
    assert re.findall(r'functionfs_reenumerated generation=(\d+)',r['usb.log'])==['1']
    # Verify raw PIV signatures using the original own public key, independently of SDK results.
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    public_der=bytes.fromhex(r['original_piv_public_key_spki_hex'])
    assert hashlib.sha256(public_der).hexdigest()==r['original_piv_public_key_sha256']
    public_key=serialization.load_der_public_key(public_der)
    assert isinstance(public_key,ec.EllipticCurvePublicKey) and public_key.curve.name=='secp256r1'
    piv_signatures=r['piv_signatures']
    assert len(piv_signatures)==19 and [v['phase'] for v in piv_signatures]==['initial']+[c['phase'] for c in r['cycles']]
    for index,sig in enumerate(piv_signatures):
        expected=hashlib.sha256(b'own large-runtime initial original PIV key' if index==0 else ('own original PIV post large-runtime '+sig['phase']).encode()).digest()
        assert bytes.fromhex(sig['digest_hex'])==expected and sig['original_key_signature_verified'] is True
        public_key.verify(bytes.fromhex(sig['signature_hex']),expected,ec.ECDSA(hashes.SHA256()))

    if r.get('current_release_transport_verification') is True:
        assert r['source_transport_changed_for_this_test'] is False
        assert r['all_boundary_resume_mode_combinations_verified'] is True
        assert r['complete_original_chained_APDU_across_runtime_reset_verified'] is False
        assert r['chained_response_after_runtime_reset_inactive_denied'] is True
        assert r['raw_io_event_completion_res_payload_recorded'] is False
