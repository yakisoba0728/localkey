"""Verify actual same-generation CCID data/ZLP EINTR recovery in own guest.

Targets only the identified owned endpoint thread in the private no-NIC test
guest. No host process, hardware key or browser authentication API is modified.
"""
import base64
import ctypes
import hashlib
import hmac
import json
import os
import platform
import re
import shutil
import signal
import struct
import subprocess
import tempfile
import time
import traceback
from pathlib import Path
import usb.util
import verify_composite as base
import verify_usb_state as state
import usb_state_pending as pending
from emucard.core import EncryptedState
from fido2.ctap2 import ClientPin, PinProtocolV2
from yubikit.core import Tlv
from yubikit.core.otp import OtpConnection
from yubikit.oath import CredentialData, OathSession
from yubikit.piv import DEFAULT_MANAGEMENT_KEY, OBJECT_ID, PivSession
from yubikit.yubiotp import SLOT, HmacSha1SlotConfiguration, YubiOtpSession
from ykman.hid.linux import list_devices as list_otp

checks=[]
def check(value,name):
    assert value,name
    checks.append({'name':name,'passed':True})
    print('PASS',name,flush=True)

def blocked_write(pid,size):
    for task in (Path('/proc')/str(pid)/'task').iterdir():
        try:
            text=(task/'syscall').read_text().strip()
            words=text.split()
            if words[0]!='64':continue  # Validated native ARM64 write syscall.
            fd=int(words[1],0)
            if os.readlink(Path('/proc')/str(pid)/'fd'/str(fd))!='/dev/ffs-ske/ep5':continue
            if int(words[3],0)!=size:continue
            status=(task/'status').read_text()
            assert re.search(r'^Tgid:\s+'+str(pid)+r'$',status,re.M)
            return {'tid':int(task.name),'tgid':pid,'fd':fd,'bytes':size,
                    'buffer':words[2],'syscall':text,'wchan':(task/'wchan').read_text().strip()}
        except (FileNotFoundError,ProcessLookupError):continue
    return None

def wait_write(pid,size,seconds=3):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        found=blocked_write(pid,size)
        if found:return found
        time.sleep(.01)
    return None

def main():
    f=None;temporary=None;trace=None;d=None
    report={'passed':False,'tests':checks,'signals':[],'cycles':[],'assertions':[],
        'scope':'actual same-generation queued FunctionFS CCID IN interruption in isolated ARM64 guest',
        'physical_device_access':False,'host_device_passthrough':False,'manufacturer_trust_reproduced':False,
        'native_macos_registration_verified':False,'production_hardware_udcs_verified':False,
        'physical_touch_verified':False,'card_testing_auto_allow':False,
        'fido_presence_auto_approved_only_for_owned_fixture':True}
    try:
        check(Path('/opt/isolated-ske-usb-guest').exists(),'private native interrupt guest marker')
        check(platform.release()=='6.8.0-146-generic' and platform.machine()=='aarch64'
              and [p.name for p in Path('/sys/class/net').iterdir()]==['lo'],
              'actual ARM64 kernel and only loopback for interruption probe')
        temporary=Path(tempfile.mkdtemp(prefix='usb-interrupt-',dir='/guest-state'))
        os.environ['SKE_TRACE_USB']='1'
        f=base.CompositeFixture(Path('/opt/swpasskeyd'),temporary)
        f.card=pending.PromptCardFixture(Path('/opt'),temporary/'card',startup_timeout=30)
        ct=f.start();pids=(f.bridge.pid,f.process.pid,f.card.process.pid)
        report['observed_version']=subprocess.check_output(['/opt/swpasskeyd','--version'],text=True).strip()
        report['emulator_binary_sha256']=hashlib.sha256(Path('/opt/swpasskeyd').read_bytes()).hexdigest()
        report['usb_bridge_binary_sha256']=hashlib.sha256(Path('/opt/ske-usbd').read_bytes()).hexdigest()
        protocol=PinProtocolV2();ClientPin(ct,protocol).set_pin(state.PIN)
        token=ClientPin(ct,protocol).get_pin_token(state.PIN,
            ClientPin.PERMISSION.MAKE_CREDENTIAL|ClientPin.PERMISSION.GET_ASSERTION,state.RP)
        digest=hashlib.sha256(b'own native EINTR registration').digest()
        response=ct.make_credential(digest,{'id':state.RP},{'id':state.USER,'name':'own-interrupt'},
            [{'type':'public-key','alg':-7}],options={'rk':True},
            pin_uv_protocol=2,pin_uv_param=protocol.authenticate(token,digest))
        credential=response.auth_data.credential_data
        check(response.auth_data.flags&5==5 and credential.public_key[3]==-7,
              'fresh owned resident ES256 PIN/UV credential for interruption fixture')
        state.close_hid(f);devices=list_otp();assert len(devices)==1
        with devices[0].open_connection(OtpConnection) as connection:
            YubiOtpSession(connection).put_configuration(SLOT.TWO,HmacSha1SlotConfiguration(state.KEY).serial_api_visible(True))
        state.check=check
        state.prove_sdk(f,credential,'initial',report)
        d,before=state.own_usb(f.serial)
        connection=pending.NativeCcid(d);oath=OathSession(connection)
        own=oath.put_credential(CredentialData.parse_uri(
            'otpauth://hotp/USBInterrupt:owned?secret=JBSWY3DPEHPK3PXP&counter=0'))
        counter=lambda:EncryptedState(f.directory/'card/state.bin').data['oath']['credentials'][own.id.hex()]['counter']
        check(counter()==0,'fresh owned native OATH HOTP counter zero')
        trace=Path('/sys/kernel/tracing');trace.mkdir(parents=True,exist_ok=True)
        mounted_tracefs=any(line.split(' - ',1)[1].split()[0]=='tracefs'
            and line.split(' - ',1)[0].split()[4]==str(trace)
            for line in Path('/proc/self/mountinfo').read_text().splitlines())
        if not mounted_tracefs:
            subprocess.run(['/bin/mount','-t','tracefs','tracefs',str(trace)],check=True)
        (trace/'buffer_size_kb').write_text('256\n')
        exit_event=trace/'events/syscalls/sys_exit_write'
        delivery=trace/'events/signal/signal_deliver'
        entry_event=trace/'events/syscalls/sys_enter_write'
        check(exit_event.exists() and delivery.exists() and entry_event.exists(),'actual kernel exposes write-exit and signal-delivery trace events')
        report['write_exit_format']=(exit_event/'format').read_text()
        report['signal_delivery_format']=(delivery/'format').read_text()
        report['write_entry_format']=(entry_event/'format').read_text()
        def arm_before_packet():
            # Register syscall tracing before the endpoint enters write. A
            # /proc syscall snapshot alone does not prove that a late-enabled
            # tracepoint observes this already executing syscall.
            threads=[int(path.name) for path in (Path('/proc')/str(f.bridge.pid)/'task').iterdir()]
            own_filter=' || '.join('common_pid == '+str(tid) for tid in threads)
            for event in [entry_event,exit_event,delivery]:
                (event/'filter').write_text(own_filter+'\n')
                (event/'enable').write_text('1\n')
            (trace/'trace').write_text('');(trace/'tracing_on').write_text('1\n')
        def original_entry(target):
            actual=(trace/'trace').read_text()
            lines=[line for line in actual.splitlines() if re.search(r'\bske-usbd-'+str(target['tid'])+r'\s',line)
                   and ('sys_write(' in line or 'sys_enter_write:' in line)]
            wanted='fd: '+format(target['fd'],'x')+', buf: '+format(int(target['buffer'],0),'x')+', count: '+format(target['bytes'],'x')
            selected=[line for line in lines if wanted in line]
            assert len(selected)==1,('original endpoint write entry not observed before signal',wanted,lines)
            return selected[0]
        report['trace_events_armed_before_original_data_and_zlp_write']=True

        libc=ctypes.CDLL(None,use_errno=True)
        libc.tgkill.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_int];libc.tgkill.restype=ctypes.c_int
        zlp_only=Path('/opt/ske-usb-interrupt-zlp-only').exists()
        report['mode']='zlp-only' if zlp_only else 'full'
        for index in range(0 if zlp_only else 3):
            arm_before_packet()
            payload=Tlv(0x71,own.id)+Tlv(0x74,bytes(8))
            sequence=connection.write(0x6f,bytes([0,0xa2,0,1,len(payload)])+payload)
            target=wait_write(f.bridge.pid,19)
            check(target is not None,'actual unread CCID response blocks native endpoint write '+str(index))
            check(counter()==index+1,'native HOTP commits once before unread response '+str(index))
            original_write_entry=original_entry(target)
            saved=state.hashes(f);report['counter_at_queued_response']=counter()
            for event in [exit_event,delivery]:
                (event/'filter').write_text('common_pid == '+str(target['tid'])+'\n')
                (event/'enable').write_text('1\n')
            for attempt in range(3):
                report['selected_worker']=target
                current=blocked_write(f.bridge.pid,19)
                check(current is not None and current['tid']==target['tid']
                      and current['buffer']==target['buffer'] and current['fd']==target['fd'],
                      'same actual queued CCID buffer before targeted signal '+str(index)+'/'+str(attempt))
                check(libc.tgkill(f.bridge.pid,target['tid'],signal.SIGUSR1)==0,
                      'kernel accepts SIGUSR1 only for owned endpoint thread '+str(index)+'/'+str(attempt))
                deadline=time.monotonic()+2
                while True:
                    actual=(trace/'trace').read_text()
                    report['last_actual_trace']=actual
                    exits=re.findall(r'(?:sys_exit_write:|sys_write ->)\s*(?:0xfffffffffffffffc|-4)\b',actual)
                    deliveries=re.findall(r'signal_deliver:\s+sig=10\b',actual)
                    # The write-exit event precedes signal delivery. A trace read
                    # can observe one before the handler is dispatched.
                    if len(exits)>attempt and len(deliveries)>attempt:break
                    assert time.monotonic()<deadline,'actual kernel EINTR/signal delivery pair not observed'
                    time.sleep(.01)
                check('signal_deliver:' in actual and 'sig=10' in actual,
                      'actual kernel signal delivery and write EINTR observed '+str(index)+'/'+str(attempt))
                after=wait_write(f.bridge.pid,19,.6)
                row={'cycle':index,'attempt':attempt,'before':current,'after':after,
                     'actual_kernel_write_errno':4,'signal':10,'actual_trace':actual}
                report['signals'].append(row)
                if after is None:break  # Still attempt actual USB read to expose lost response.
                check(after['buffer']==target['buffer'] and after['tid']==target['tid'],
                      'actual EINTR requeues same native CCID buffer '+str(index)+'/'+str(attempt))
                check(state.hashes(f)==saved and counter()==index+1,
                      'signal retry leaves exact persistent bytes and HOTP unchanged '+str(index)+'/'+str(attempt))
            (trace/'tracing_on').write_text('0\n')
            actual=(trace/'trace').read_text()
            ct=state.fresh_hid(f)
            check('FIDO_2_1' in ct.get_info().versions and f.device.ping(b'own-IN-interrupted')==b'own-IN-interrupted',
                  'native FIDO GetInfo and PING unaffected by queued CCID signal '+str(index))
            state.close_hid(f)
            header,data=connection.read(sequence)
            check(header[0]==0x80 and header[4]&0xc0==0 and header[5]==0 and data[-2:]==b'\x90\x00',
                  'native USB delivers one complete original CCID sequence after signal '+str(index))
            digest=hmac.new(base64.b32decode('JBSWY3DPEHPK3PXP'),index.to_bytes(8,'big'),'sha1').digest()
            offset=digest[-1]&15;expected=int.from_bytes(digest[offset:offset+4],'big')&0x7fffffff
            check(Tlv.parse_dict(data[:-2])[0x76]==bytes([6])+expected.to_bytes(4,'big')
                  and counter()==index+1,'original native response independently matches HOTP and single commit '+str(index))
            check(oath.list_credentials()[0].id==own.id and counter()==index+1,
                  'following native SDK request has no duplicate stale CCID response '+str(index))
            state.alive(f,pids,'after native CCID interruption '+str(index))
            after_usb=state.reboot.snapshot(f.serial)
            check(after_usb['address']==before['address'] and after_usb['serial']==before['serial']
                  and after_usb['host_visible_configuration_descriptor_hex']==before['host_visible_configuration_descriptor_hex'],
                  'interruption retains same actual USB address configuration and identity '+str(index))
            report['cycles'].append({'index':index,'sequence':sequence,'counter_before':index,'counter_after':counter(),
                'same_three_services':True,'before_usb':before,'after_usb':after_usb,'actual_trace':actual,
                'independent_hotp_verified':True,'following_sdk_no_stale_response_verified':True,
                'original_write_entry_before_signal':original_write_entry})
            state.prove_sdk(f,credential,'interrupt-'+str(index),report)
        if not zlp_only:
            check(len(report['signals'])==9,'nine real kernel EINTR results across three original responses')
        # Exact 64-byte CCID response: 10-byte CCID header, 52-byte PIV TLV,
        # and two status bytes. Read exactly one packet to leave the ZLP queued.
        piv=PivSession(connection);piv.authenticate(DEFAULT_MANAGEMENT_KEY)
        owned_payload=bytes(range(50));piv.put_object(OBJECT_ID.CHUID,owned_payload)
        check(piv.get_object(OBJECT_ID.CHUID)==owned_payload,
              'unmodified native PIV SDK verifies own fifty-byte object before ZLP interruption')
        body=Tlv(0x5c,int(OBJECT_ID.CHUID).to_bytes(3,'big'))
        arm_before_packet()
        sequence=connection.write(0x6f,bytes([0,0xcb,0x3f,0xff,len(body)])+body)
        packet=bytes(d.read(0x82,64,timeout=1500))
        header=struct.unpack('<BIBBBBB',packet[:10])
        check(len(packet)==64 and header[0]==0x80 and header[1]==54 and header[3]==sequence
              and header[4]&0xc0==0 and packet[-2:]==b'\x90\x00'
              and Tlv.parse_dict(packet[10:-2])[0x53]==owned_payload,
              'actual USB receives original complete sixty-four-byte CCID object response once')
        target=wait_write(f.bridge.pid,0)
        check(target is not None and int(target['buffer'],0)==0,
              'real CCID ZLP write blocks separately after data packet is delivered')
        original_write_entry=original_entry(target)
        saved=state.hashes(f);before_counter=counter()
        for event in [exit_event,delivery]:
            (event/'filter').write_text('common_pid == '+str(target['tid'])+'\n')
            (event/'enable').write_text('1\n')
        for attempt in range(3):
            current=blocked_write(f.bridge.pid,0)
            check(current is not None and current['tid']==target['tid'] and int(current['buffer'],0)==0,
                  'same actual queued zero-length transfer before signal '+str(attempt))
            check(libc.tgkill(f.bridge.pid,target['tid'],signal.SIGUSR1)==0,
                  'kernel accepts own targeted ZLP thread SIGUSR1 '+str(attempt))
            deadline=time.monotonic()+2
            while True:
                actual=(trace/'trace').read_text();report['last_actual_trace']=actual
                exits=re.findall(r'(?:sys_exit_write:|sys_write ->)\s*(?:0xfffffffffffffffc|-4)\b',actual)
                deliveries=re.findall(r'signal_deliver:\s+sig=10\b',actual)
                if len(exits)>attempt and len(deliveries)>attempt:break
                assert time.monotonic()<deadline,'actual kernel zero-length EINTR/signal delivery pair not observed'
                time.sleep(.01)
            check('signal_deliver:' in actual and 'sig=10' in actual,
                  'actual kernel ZLP write EINTR and signal delivery observed '+str(attempt))
            after=wait_write(f.bridge.pid,0,.6)
            report['signals'].append({'cycle':'zlp','attempt':attempt,'before':current,'after':after,
                'actual_kernel_write_errno':4,'signal':10,'actual_trace':actual})
            if after is None:break
            check(after['tid']==target['tid'] and int(after['buffer'],0)==0 and after['bytes']==0,
                  'actual EINTR requeues only ZLP and retains endpoint thread '+str(attempt))
            check(state.hashes(f)==saved and counter()==before_counter,
                  'ZLP retry leaves exact persistent bytes and HOTP unchanged '+str(attempt))
        (trace/'tracing_on').write_text('0\n');actual=(trace/'trace').read_text()
        # A retransmitted 64-byte payload would produce data here, not a ZLP.
        terminator=bytes(d.read(0x82,1,timeout=1500))
        check(terminator==b'','actual USB receives recovered zero-length terminator without duplicate data packet')
        check(state.hashes(f)==saved and counter()==before_counter,
              'completed recovered ZLP leaves exact persistent bytes unchanged')
        logical=lambda:hashlib.sha256(json.dumps(EncryptedState(f.directory/'card/state.bin').data,sort_keys=True).encode()).hexdigest()
        before_logical=logical()
        check(piv.get_object(OBJECT_ID.CHUID)==owned_payload,
              'following unmodified PIV SDK request has correct new sequence and no stale data or ZLP')
        state.alive(f,pids,'after native CCID ZLP interruption')
        after_usb=state.reboot.snapshot(f.serial)
        check(after_usb['address']==before['address'] and logical()==before_logical and counter()==before_counter,
              'following SDK read retains same USB generation and persistent plaintext state')
        report['zlp']={'sequence':sequence,'data_packet_bytes':64,'object_payload_bytes':50,
            'zero_length_terminator_bytes':len(terminator),'same_three_services':True,
            'before_usb':before,'after_usb':after_usb,'actual_trace':actual,
            'independent_original_object_bytes_verified':True,'only_zero_length_retried_without_duplicate_data':True,
            'following_native_sdk_no_stale_response_verified':True,'counter_before':before_counter,'counter_after':counter(),
            'exact_ciphertext_unchanged_during_interruptions':True,'original_write_entry_before_signal':original_write_entry,
            'following_sdk_persistent_plaintext_unchanged':True,
            'following_sdk_read_transaction_reencrypts_unchanged_plaintext':state.hashes(f)!=saved}
        state.prove_sdk(f,credential,'zlp-interrupt',report)
        check(len(report['signals'])==(3 if zlp_only else 12),
              'all real kernel EINTR results accounted for full data and zero-length transfers')

        report['helper_sha256']={name:hashlib.sha256((Path(__file__).parent/file).read_bytes()).hexdigest()
            for name,file in [('verify-usb-interrupt.py','verify-usb-interrupt.py'),('verify-usb-state.py','verify_usb_state.py'),('usb-state-pending.py','usb_state_pending.py')]}
        report['card_service_sha256']=hashlib.sha256(Path('/opt/emucard/service.py').read_bytes()).hexdigest()
        report.update(passed=True,controller=f.controller,service_pids=list(pids),
            actual_native_ccid_in_eintr_recovery_verified=True,
            actual_native_fido_isolation_verified=True,same_usb_generation_retained=True,
            actual_native_bulk_zlp_eintr_recovery_verified=True)
    except Exception as exc:
        report.update(error=f'{type(exc).__name__}: {exc}',traceback=traceback.format_exc())
        if f:
            report['failure_process_status']={name:proc.poll() for name,proc in [('bridge',f.bridge),('fido',f.process),('card',f.card.process)]}
    finally:
        if trace and (trace/'tracing_on').exists():(trace/'tracing_on').write_text('0\n')
        if trace:
            for name in ['events/syscalls/sys_enter_write','events/syscalls/sys_exit_write','events/signal/signal_deliver']:
                event=trace/name/'enable'
                if event.exists():event.write_text('0\n')
        if d is not None:usb.util.dispose_resources(d)
        if f:
            report['card_log']=(f.directory/'card/log.txt').read_text()
            report['bridge_log']=(f.directory/'usb.log').read_text()[-10000:]
            try:f.stop()
            except Exception as exc:report.update(passed=False,cleanup_error=str(exc))
        if temporary and temporary.exists():shutil.rmtree(temporary)
        report['test_count']=len(checks)
        print('SKE_USB_INTERRUPT_BEGIN\n'+json.dumps(report)+'\nSKE_USB_INTERRUPT_END',flush=True)
    return 0 if report['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
