#!/usr/bin/env python3
"""Exercise only a fresh owned device on the isolated guest USB bus."""
import errno
import importlib.util
import hashlib
import hmac
import json
import platform
import shutil
import struct
import tempfile
import time
import traceback
from pathlib import Path
import usb.core
import usb.backend.libusb1
import usb.util
import verify_composite as base
spec=importlib.util.spec_from_file_location('owned_reboot_helpers','/opt/verification/verify-composite-reboot.py')
reboot=importlib.util.module_from_spec(spec);spec.loader.exec_module(reboot)
import usb_state_pending as pending
from fido2.ctap2 import Ctap2, ClientPin, PinProtocolV2
from fido2.hid import CtapHidDevice
from fido2.hid.linux import list_descriptors
from ykman.hid.linux import list_devices as list_otp
from yubikit.core.otp import OtpConnection
from yubikit.yubiotp import SLOT, HmacSha1SlotConfiguration, YubiOtpSession

checks=[]
RP='localhost'
USER=b'own-usb-state-user'
PIN='own-usb-state-pin'
KEY=b'own USB state key!!!'

def check(value,name):
    assert value,name
    checks.append({'name':name,'passed':True})
    print('PASS',name,flush=True)

def hashes(f):
    return {name:hashlib.sha256((f.directory/name).read_bytes()).hexdigest()
            for name in ['state.bin','card/state.bin']}

def own_usb(serial):
    backend=usb.backend.libusb1.get_backend(find_library=lambda name:'/usr/lib/aarch64-linux-gnu/libusb-1.0.so.0')
    assert backend is not None,'actual guest libusb runtime failed to load'
    devices=list(usb.core.find(find_all=True,idVendor=0x1050,idProduct=0x0407,backend=backend))
    assert len(devices)==1 and devices[0].serial_number==serial
    d=devices[0]
    snapshot=reboot.snapshot(serial)
    assert snapshot and 'dummy_hcd' in snapshot['path'] and snapshot['address']==d.address
    return d,snapshot

def alive(f,pids,label):
    check((f.bridge.pid,f.process.pid,f.card.process.pid)==pids and
          all(p.poll() is None for p in [f.bridge,f.process,f.card.process]),
          'same three live services '+label)

def close_hid(f):
    if f.device:
        f.device.close();f.device=None

def fresh_hid(f):
    desc=base.wait_for(lambda:next((d for d in list_descriptors() if d.serial_number==f.serial),None),
                       'own HID not restored')
    devices=[d for d in CtapHidDevice.list_devices() if d.descriptor==desc]
    assert len(devices)==1
    f.device=devices[0];f.ctap=Ctap2(f.device)
    return f.ctap

def prove_sdk(f,credential,label,report):
    ct=fresh_hid(f) if f.device is None else f.ctap
    protocol=PinProtocolV2()
    token=ClientPin(ct,protocol).get_pin_token(PIN,ClientPin.PERMISSION.GET_ASSERTION,RP)
    digest=hashlib.sha256(('own actual USB '+label).encode()).digest()
    response=ct.get_assertion(RP,digest,allow_list=[{'type':'public-key','id':credential.credential_id}],
        pin_uv_protocol=2,pin_uv_param=protocol.authenticate(token,digest))
    credential.public_key.verify(response.auth_data+digest,response.signature)
    check(response.credential['id']==credential.credential_id and response.user['id']==USER
          and response.auth_data.flags&5==5 and response.auth_data.rp_id_hash==hashlib.sha256(RP.encode()).digest(),'native SDK UV signature and user binding '+label)
    if report['assertions']:
        check(response.auth_data.counter>report['assertions'][-1]['counter'],'counter increases '+label)
    report['assertions'].append({'phase':label,'signature_verified':True,'user_verified':True,
        'user_handle_verified':True,'rp_id_hash_verified':True,'counter':response.auth_data.counter,'pin_uv_protocol':2,
        'challenge_sha256':digest.hex(),'credential_sha256':hashlib.sha256(credential.credential_id).hexdigest()})
    close_hid(f)
    devices=list_otp();assert len(devices)==1
    with devices[0].open_connection(OtpConnection) as conn:
        result=YubiOtpSession(conn).calculate_hmac_sha1(SLOT.TWO,b'own persistent USB challenge')
    check(result==hmac.new(KEY,b'own persistent USB challenge','sha1').digest(),
          'native OTP SDK independently verifies retained key '+label)


def claim_all(d):
    detached=[]
    for number in [0,1,2]:
        if d.is_kernel_driver_active(number):
            d.detach_kernel_driver(number);detached.append(number)
        usb.util.claim_interface(d,number)
    return detached

def release_all(d,detached):
    for number in [0,1,2]:
        usb.util.release_interface(d,number)
    for number in detached:d.attach_kernel_driver(number)
    usb.util.dispose_resources(d)

def status(d,ep):
    value=bytes(d.ctrl_transfer(0x82,0,0,ep,2,timeout=1000))
    assert len(value)==2
    return int.from_bytes(value,'little')

def halts(f,report,pids):
    d,before=own_usb(f.serial)
    detached=claim_all(d)
    saved=hashes(f)
    endpoints=base.expected_endpoint_addresses(7)
    try:
        for ep in endpoints:
            check(status(d,ep)==0,f'initial native endpoint {ep:02x} not halted')
            d.ctrl_transfer(0x02,3,0,ep,None,timeout=1000)
            check(status(d,ep)==1,f'actual SET_FEATURE halts endpoint {ep:02x}')
            for sibling in endpoints:
                if sibling!=ep:assert status(d,sibling)==0
            check(True,f'endpoint {ep:02x} halt isolated from other endpoints')
            try:
                if ep&0x80:d.read(ep,64 if ep in [0x84,0x82] else 8,timeout=300)
                else:
                    if ep==4:payload=(bytes.fromhex('ffffffff860008')+b'own-init').ljust(64,b'\0')
                    else:payload=bytes.fromhex('62000000000017000000')
                    d.write(ep,payload,timeout=300)
            except usb.core.USBError as exc:
                check(exc.errno==errno.EPIPE,f'host transfer receives real EPIPE from halted endpoint {ep:02x}')
            else:raise AssertionError(f'halted endpoint {ep:02x} accepted host transfer')
            d.clear_halt(ep)
            check(status(d,ep)==0,f'libusb CLEAR_HALT restores endpoint {ep:02x}')
            # Repeat CLEAR_FEATURE on an already clear endpoint.
            d.clear_halt(ep)
            check(status(d,ep)==0,f'repeated CLEAR_HALT idempotent for endpoint {ep:02x}')
            alive(f,pids,f'after endpoint {ep:02x}')
            report['halts'].append({'endpoint':ep,'halt_status':1,'host_errno':errno.EPIPE,'cleared_status':0})
        check(hashes(f)==saved,'all six halt cycles leave persistent state bytes unchanged')
    finally:
        release_all(d,detached)
    report['halt_usb_snapshot']=before


def resets(f,credential,report,pids):
    for index in range(3):
        d,before=own_usb(f.serial)
        saved=hashes(f)
        d.reset()
        usb.util.dispose_resources(d)
        alive(f,pids,f'after USBDEVFS_RESET {index}')
        base.wait_for(lambda:reboot.snapshot(f.serial),'own USB reset did not restore configuration')
        # Recovery must leave the exact credentials/OTP key bytes untouched.
        check(hashes(f)==saved,f'USBDEVFS_RESET {index} leaves persistent state bytes unchanged')
        after=reboot.snapshot(f.serial)
        check(before['host_visible_configuration_descriptor_hex']==after['host_visible_configuration_descriptor_hex'],
              f'USBDEVFS_RESET {index} retains actual host configuration descriptor')
        report['resets'].append({'index':index,'before':before,'after':after,'same_three_services':True})
        prove_sdk(f,credential,f'usb-reset-{index}',report)


def configuration(f,credential,report,pids):
    d,before=own_usb(f.serial)
    detached=claim_all(d)
    for number in [0,1,2]:usb.util.release_interface(d,number)
    saved=hashes(f)
    try:
        d.set_configuration(0)
        check(bytes(d.ctrl_transfer(0x80,8,0,0,1,timeout=1000))==b'\0','actual SET_CONFIGURATION zero disables configuration')
        alive(f,pids,'while USB unconfigured')
        d.set_configuration(1)
        check(bytes(d.ctrl_transfer(0x80,8,0,0,1,timeout=1000))==b'\1','actual SET_CONFIGURATION one restores configuration')
    finally:usb.util.dispose_resources(d)
    base.wait_for(lambda:next((x for x in list_descriptors() if x.serial_number==f.serial),None),
                  'kernel HID not restored after configuration cycle')
    check(hashes(f)==saved,'configuration zero/one leaves persistent state bytes unchanged')
    alive(f,pids,'after configuration zero/one')
    report['configuration_cycle']={'before':before,'after':reboot.snapshot(f.serial),'same_three_services':True}
    prove_sdk(f,credential,'configuration-cycle',report)


def main():
    f=None
    temporary=None
    report={'passed':False,'tests':checks,'scope':'native USB state verification on own dummy_hcd only',
        'physical_device_access':False,'host_device_passthrough':False,'manufacturer_trust_reproduced':False,
        'native_macos_registration_verified':False,'production_hardware_udcs_verified':False,
        'physical_firmware_reset_or_pin_token_semantics_verified':False,
        'halts':[],'resets':[],'assertions':[]}
    try:
        check(Path('/opt/isolated-ske-usb-guest').exists(),'private isolated USB guest marker')
        check(platform.release()=='6.8.0-146-generic' and platform.machine()=='aarch64'
              and [p.name for p in Path('/sys/class/net').iterdir()]==['lo'],
              'actual ARM64 distro kernel and only own loopback')
        temporary=Path(tempfile.mkdtemp(prefix='usb-state-',dir='/guest-state'))
        tmp=temporary
        f=base.CompositeFixture(Path('/opt/swpasskeyd'),Path(tmp))
        f.card=pending.PromptCardFixture(Path('/opt'),f.directory/'card',startup_timeout=30)
        ct=f.start()
        pids=(f.bridge.pid,f.process.pid,f.card.process.pid)
        report['controller']=f.controller
        protocol=PinProtocolV2();ClientPin(ct,protocol).set_pin(PIN)
        token=ClientPin(ct,protocol).get_pin_token(PIN,
            ClientPin.PERMISSION.MAKE_CREDENTIAL|ClientPin.PERMISSION.GET_ASSERTION,RP)
        digest=hashlib.sha256(b'own USB state registration').digest()
        response=ct.make_credential(digest,{'id':RP,'name':'Own USB state'},
            {'id':USER,'name':'own-usb-state-user'},[{'type':'public-key','alg':-7}],
            options={'rk':True},pin_uv_protocol=2,pin_uv_param=protocol.authenticate(token,digest))
        credential=response.auth_data.credential_data
        check(response.auth_data.flags&5==5 and credential.public_key[3]==-7,
              'own resident ES256 credential created on actual native USB with PIN UV')
        close_hid(f)
        devices=list_otp();assert len(devices)==1
        with devices[0].open_connection(OtpConnection) as conn:
            YubiOtpSession(conn).put_configuration(SLOT.TWO,HmacSha1SlotConfiguration(KEY).serial_api_visible(True))
        prove_sdk(f,credential,'initial',report)
        halts(f,report,pids)
        prove_sdk(f,credential,'six-endpoint-halts',report)
        resets(f,credential,report,pids)
        configuration(f,credential,report,pids)
        pending.run(f,report,check,own_usb,alive,hashes,fresh_hid,close_hid,pids)
        prove_sdk(f,credential,'pending-ccid-reset',report)
        report.update(passed=True,native_all_six_endpoint_halt_recovery_verified=True,
            native_usbdevfs_reset_recovery_verified=True,native_unconfigure_configure_recovery_verified=True,
            emulator_binary_sha256=hashlib.sha256(Path('/opt/swpasskeyd').read_bytes()).hexdigest(),
            usb_bridge_binary_sha256=hashlib.sha256(Path('/opt/ske-usbd').read_bytes()).hexdigest(),
            card_service_sha256=hashlib.sha256(Path('/opt/emucard/service.py').read_bytes()).hexdigest(),
            helper_sha256={name:hashlib.sha256(Path(path).read_bytes()).hexdigest() for name,path in [
                ('verify-usb-state.py',__file__),('usb-state-pending.py',pending.__file__)]})
    except Exception as exc:
        report.update(error=f'{type(exc).__name__}: {exc}',traceback=traceback.format_exc())
    finally:
        if f:
            for name in ['usb.log','daemon.log','card/log.txt']:
                p=f.directory/name
                if p.exists():print('USB_STATE_DIAGNOSTIC',name,p.read_text(errors='replace')[-10000:],flush=True)
            try:f.stop()
            except Exception as exc:report.update(passed=False,cleanup_error=str(exc))
        if temporary and temporary.exists():shutil.rmtree(temporary)
        report['test_count']=len(checks)
        print('SKE_USB_STATE_BEGIN\n'+json.dumps(report)+'\nSKE_USB_STATE_END',flush=True)
    return 0 if report['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
