"""Verify actual kernel device PM, UDC re-enumeration and queued CCID recovery.

Requires the private no-NIC/no-host-device Linux test guest. Kernel devices
PM testing does not prove runtime autosuspend or full platform sleep.
"""
import array
import base64
import hmac
from concurrent.futures import ThreadPoolExecutor
import fcntl
import hashlib
import json
import os
import platform
import shutil
import subprocess
import tempfile
import time
import traceback
from pathlib import Path
import verify_composite as base
import verify_usb_state as state
import usb_state_pending as pending
from emucard.core import EncryptedState
from yubikit.core import Tlv
from yubikit.oath import CredentialData, OathSession
from fido2.ctap2 import ClientPin, PinProtocolV2
from ykman.hid.linux import list_devices as list_otp
from yubikit.core.otp import OtpConnection
from yubikit.yubiotp import SLOT, HmacSha1SlotConfiguration, YubiOtpSession
import usb.util

checks=[]

def check(value,name):
    assert value,name
    checks.append({'name':name,'passed':True})
    print('PASS',name,flush=True)

def status(power):
    names=['control','runtime_status','runtime_active_time','runtime_suspended_time',
           'runtime_usage','autosuspend_delay_ms','wakeup']
    return {name:(power/name).read_text().strip() for name in names if (power/name).exists()}

def main():
    f=None;temporary=None;fd=None;power=None;original=None;trace=None;pm_original=None
    report={'passed':False,'tests':checks,'scope':'actual isolated guest kernel device PM / dummy UDC disconnect and re-enumeration',
        'cycles':[],'assertions':[],'physical_device_access':False,'host_device_passthrough':False,
        'physical_touch_verified':False,'production_hardware_udcs_verified':False,
        'native_macos_registration_verified':False,'manufacturer_trust_reproduced':False,
        'physical_firmware_power_timing_or_pin_token_semantics_verified':False,
        'fido_presence_auto_approved_only_for_owned_fixture':True,
        'native_runtime_pm_verified':False,'host_hid_drivers_unbound':False,
        'full_platform_sleep_verified':False,'card_testing_auto_allow':False}
    try:
        check(Path('/opt/isolated-ske-usb-guest').exists(),'private USB power guest marker')
        check(platform.release()=='6.8.0-146-generic' and platform.machine()=='aarch64'
              and [p.name for p in Path('/sys/class/net').iterdir()]==['lo'],'actual power ARM64 kernel and only loopback')
        temporary=Path(tempfile.mkdtemp(prefix='usb-power-',dir='/guest-state'))
        os.environ['SKE_TRACE_USB']='1'
        f=base.CompositeFixture(Path('/opt/swpasskeyd'),temporary)
        f.card=pending.PromptCardFixture(Path('/opt'),temporary/'card',startup_timeout=30)
        ct=f.start()
        pids=(f.bridge.pid,f.process.pid,f.card.process.pid)
        protocol=PinProtocolV2();ClientPin(ct,protocol).set_pin(state.PIN)
        token=ClientPin(ct,protocol).get_pin_token(state.PIN,
            ClientPin.PERMISSION.MAKE_CREDENTIAL|ClientPin.PERMISSION.GET_ASSERTION,state.RP)
        digest=hashlib.sha256(b'own USB power registration').digest()
        response=ct.make_credential(digest,{'id':state.RP},
            {'id':state.USER,'name':'own-usb-power'},[{'type':'public-key','alg':-7}],
            options={'rk':True},pin_uv_protocol=2,pin_uv_param=protocol.authenticate(token,digest))
        credential=response.auth_data.credential_data
        check(response.auth_data.flags&5==5 and credential.public_key[3]==-7,'own native power fixture resident ES256 PIN/UV credential')
        state.close_hid(f)
        devices=list_otp();assert len(devices)==1
        with devices[0].open_connection(OtpConnection) as connection:
            YubiOtpSession(connection).put_configuration(SLOT.TWO,HmacSha1SlotConfiguration(state.KEY).serial_api_visible(True))
        # Reuse already independent SDK signature/RP/userHandle/HMAC checks.
        state.check=check
        state.prove_sdk(f,credential,'initial',report)
        device,before=state.own_usb(f.serial)
        node=Path('/dev/bus/usb')/f'{device.bus:03d}'/f'{device.address:03d}'
        power=Path(before['path'])/'power'
        check('dummy_hcd' in str(power) and device.serial_number==f.serial,'only own dummy USB power attributes and usbfs node selected')
        usb.util.dispose_resources(device)
        fd=os.open(node,os.O_RDWR|os.O_CLOEXEC)
        cap=array.array('I',[0]);fcntl.ioctl(fd,0x8004551a,cap,True)
        check(bool(cap[0]&0x100),'actual kernel usbfs reports suspend capability')
        report['usbfs_capabilities']=cap[0];report['initial_usb_snapshot']=before
        original=status(power);report['initial_power']=original
        (power/'autosuspend_delay_ms').write_text('0\n')
        (power/'control').write_text('auto\n')
        fcntl.ioctl(fd,0x5522)
        time.sleep(.5)
        report['stock_runtime_auto_observation']=status(power)
        # Record the real outcome without claiming an unobserved runtime suspend.
        fcntl.ioctl(fd,0x5521)
        (power/'control').write_text('on\n')
        os.close(fd);fd=None
        pm=Path('/sys/power')
        pm_original=(pm/'pm_test').read_text().strip()
        check('devices' in pm_original.split() and 'freeze' in (pm/'state').read_text().split(),
              'actual kernel supports PM devices test and freeze request')
        (pm/'pm_test').write_text('devices\n')
        trace=Path('/sys/kernel/tracing')
        trace.mkdir(parents=True,exist_ok=True)
        subprocess.run(['/bin/mount','-t','tracefs','tracefs',str(trace)],check=True)
        (trace/'buffer_size_kb').write_text('1024\n')
        for event in ['device_pm_callback_start','device_pm_callback_end','suspend_resume']:
            (trace/'events/power'/event/'enable').write_text('1\n')
        (trace/'tracing_on').write_text('1\n')
        bindings=lambda:{n:(Path(before['path'])/(Path(before['path']).name+':1.'+str(n))/'driver').resolve().name for n in [0,1]}
        original_bindings=bindings()
        check(set(original_bindings.values())=={'usbhid'},'stock kernel HID drivers bound before system PM devices test')
        for index in range(3):
            saved=state.hashes(f)
            (trace/'trace').write_text('')
            active=state.reboot.snapshot(f.serial)
            started=time.monotonic()
            (pm/'state').write_text('freeze\n')
            duration=time.monotonic()-started
            observed=(trace/'trace').read_text()
            report['last_actual_pm_trace']=observed
            report['process_status_after_pm']={name:process.poll() for name,process in [('bridge',f.bridge),('fido',f.process),('card',f.card.process)]}
            print('USB_POWER_PM_TRACE_SHA256',index,hashlib.sha256(observed.encode()).hexdigest(),flush=True)
            check(duration>=4.5,'real kernel PM devices test waits before resuming '+str(index))
            check('device_pm_callback_start:' in observed and 'device_pm_callback_end:' in observed
                  and 'dpm_suspend' in observed and 'dpm_resume' in observed,
                  'actual kernel PM callback trace has suspend and resume '+str(index))
            state.alive(f,pids,'after actual kernel device PM '+str(index))
            check(state.hashes(f)==saved,'kernel device PM preserves exact persistent bytes '+str(index))
            state.prove_sdk(f,credential,'kernel-device-pm-'+str(index),report)
            after=state.reboot.snapshot(f.serial)
            check(after and after['serial']==before['serial']
                  and after['host_visible_configuration_descriptor_hex']==before['host_visible_configuration_descriptor_hex'],
                  'kernel device PM recovers same descriptor and own identity '+str(index))
            check(bindings()==original_bindings,'stock HID driver bindings retained after kernel device PM '+str(index))
            report['cycles'].append({'index':index,'mode':'kernel pm_test=devices / state=freeze',
                'duration_seconds':duration,'actual_trace':observed,'same_three_services':True,
                'stock_hid_bindings_unchanged':True,'before_usb':active,'after_usb':after,
                'udc_disconnect_and_reenumeration_observed':active['address']!=after['address']})
        # Hold a real touch-gated CCID request and leave its next WTX IN
        # transfer unread, so the actual kernel cancels a queued bulk request.
        d,_=state.own_usb(f.serial)
        connection=pending.NativeCcid(d)
        oath=OathSession(connection)
        own=oath.put_credential(CredentialData.parse_uri(
            'otpauth://hotp/USBPower:owned?secret=JBSWY3DPEHPK3PXP&counter=0'),touch_required=True)
        counter=lambda:EncryptedState(f.directory/'card/state.bin').data['oath']['credentials'][own.id.hex()]['counter']
        payload=Tlv(0x71,own.id)+Tlv(0x74,bytes(8))
        previous=(f.directory/'card/log.txt').read_text().count('approve user presence')
        saved=state.hashes(f)
        sequence=connection.write(0x6f,bytes([0,0xa2,0,1,len(payload)])+payload)
        deadline=time.monotonic()+5
        while (f.directory/'card/log.txt').read_text().count('approve user presence')<=previous:
            assert time.monotonic()<deadline,'actual CCID terminal prompt not reached'
            time.sleep(.03)
        header,data=connection.read(sequence)
        check(header[0]==0x80 and header[4]&0xc0==0x80 and not data,
              'real CCID WTX and terminal presence wait before kernel PM')
        check(counter()==0 and state.hashes(f)==saved,'pending real presence leaves HOTP and exact persistent bytes unchanged')
        ct=state.fresh_hid(f)
        check('FIDO_2_1' in ct.get_info().versions and f.device.ping(b'own-pm-pending')==b'own-pm-pending',
              'native FIDO GetInfo and PING complete during actual pending CCID')
        state.close_hid(f)
        time.sleep(.65)
        active=state.reboot.snapshot(f.serial)
        log_before=(f.directory/'usb.log').read_text()
        (trace/'trace').write_text('')
        started=time.monotonic();(pm/'state').write_text('freeze\n');duration=time.monotonic()-started
        observed=(trace/'trace').read_text()
        check(duration>=4.5 and 'dpm_suspend' in observed and 'dpm_resume' in observed,
              'actual kernel device PM cycle with unread CCID IN and real presence pending')
        time.sleep(.1)
        state.alive(f,pids,'after pending CCID actual kernel device PM')
        check(counter()==0 and state.hashes(f)==saved,'kernel device PM cancels pending HOTP without premature persistent commit')
        log_after=(f.directory/'usb.log').read_text()[len(log_before):]
        check('functionfs_endpoint_shutdown_retry address=130' in log_after,
              'real kernel ESHUTDOWN on submitted bulk CCID IN does not terminate bridge')
        ct=state.fresh_hid(f)
        check('FIDO_2_1' in ct.get_info().versions and f.device.ping(b'own-pm-resumed')==b'own-pm-resumed',
              'native FIDO GetInfo and PING recover after CCID cancellation by UDC disconnect')
        state.close_hid(f)
        after_pending=state.reboot.snapshot(f.serial)
        check(after_pending['address']!=active['address'],
              'actual dummy UDC PM disconnect and re-enumeration requires fresh USB handle')
        try:
            connection.read(sequence)
        except usb.core.USBError as exc:
            check(exc.errno==19,'old disconnected CCID handle fails with actual ENODEV')
        else:raise AssertionError('old CCID handle unexpectedly survived UDC disconnect')
        usb.util.dispose_resources(d)
        d,_=state.own_usb(f.serial)
        connection=pending.NativeCcid(d)
        oath=OathSession(connection)
        check(oath.list_credentials()[0].id==own.id and counter()==0,
              'fresh USB CCID SDK session recovers without stale response or HOTP mutation')
        previous_new=(f.directory/'card/log.txt').read_text().count('approve user presence')
        with ThreadPoolExecutor(max_workers=1) as executor:
            future=executor.submit(oath.calculate_code,own)
            deadline=time.monotonic()+5
            while (f.directory/'card/log.txt').read_text().count('approve user presence')<=previous_new:
                assert time.monotonic()<deadline,'new post-PM native SDK prompt not reached'
                time.sleep(.03)
            check(not future.done() and counter()==0,
                  'new post-PM native OATH SDK request waits for fresh real terminal approval')
            f.card.process.stdin.write('y\n');f.card.process.stdin.flush()
            code=future.result(3).value
        digest=hmac.new(base64.b32decode('JBSWY3DPEHPK3PXP'),bytes(8),'sha1').digest()
        offset=digest[-1]&15;expected=str((int.from_bytes(digest[offset:offset+4],'big')&0x7fffffff)%1000000).zfill(6)
        check(code==expected and counter()==1,
              'post-PM native SDK response independently matches HOTP counter zero and commits once')
        check(oath.list_credentials()[0].id==own.id and counter()==1,
              'following native SDK command has no duplicate CCID response or HOTP commit')
        report['pending_ccid']={'real_terminal_presence':True,'card_testing_auto_allow':False,
            'actual_kernel_bulk_in_eshutdown_recovered':True,'old_handle_enodev_verified':True,
            'new_sequence_sdk_recovery_without_stale_response_verified':True,
            'fresh_terminal_approval_required':True,'independent_hotp_verified':True,'counter_before':0,'counter_after':1,
            'actual_trace':observed,'duration_seconds':duration,'before_usb':active,'after_usb':after_pending,
            'same_three_services':True,'persistent_unchanged_while_pending':True,
            'disconnect_cancels_pending_request_without_counter_mutation':True}
        usb.util.dispose_resources(d)
        report['native_kernel_device_pm_test_suspend_resume_verified']=True
        report['full_platform_sleep_verified']=False
        report['helper_sha256']={name:hashlib.sha256((Path(__file__).parent/file).read_bytes()).hexdigest()
            for name,file in [('verify-usb-power.py','verify-usb-power.py'),('usb-state-pending.py','usb_state_pending.py'),('verify-usb-state.py','verify_usb_state.py')]}
        report['card_service_sha256']=hashlib.sha256(Path('/opt/emucard/service.py').read_bytes()).hexdigest()
        report['service_pids']=list(pids)
        report['final_process_status']={name:process.poll() for name,process in [('bridge',f.bridge),('fido',f.process),('card',f.card.process)]}
        report.update(passed=True,controller=f.controller,
            emulator_binary_sha256=hashlib.sha256(Path('/opt/swpasskeyd').read_bytes()).hexdigest(),
            usb_bridge_binary_sha256=hashlib.sha256(Path('/opt/ske-usbd').read_bytes()).hexdigest())
    except Exception as exc:report.update(error=f'{type(exc).__name__}: {exc}',traceback=traceback.format_exc())
    finally:
        if trace and (trace/"tracing_on").exists():(trace/"tracing_on").write_text("0\n")
        if pm_original:
            import re
            restored=re.search(r"\[([^]]+)\]",pm_original).group(1)
            Path("/sys/power/pm_test").write_text(restored+"\n")
        if power and power.exists():
            report['final_power_before_restore']=status(power)
            try:
                (power/'control').write_text('on\n')
                if original:(power/'autosuspend_delay_ms').write_text(original['autosuspend_delay_ms']+'\n')
            except Exception as exc:report.update(passed=False,power_restore_error=str(exc))
        if fd is not None:os.close(fd)
        if f:
            for name in ['usb.log','daemon.log','card/log.txt']:
                p=f.directory/name
                if p.exists():print('USB_POWER_DIAGNOSTIC',name,p.read_text(errors='replace')[-10000:],flush=True)
            try:f.stop()
            except Exception as exc:report.update(passed=False,cleanup_error=str(exc))
        if temporary and temporary.exists():shutil.rmtree(temporary)
        report['test_count']=len(checks)
        print('SKE_USB_POWER_BEGIN\n'+json.dumps(report)+'\nSKE_USB_POWER_END',flush=True)
    return 0 if report['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
