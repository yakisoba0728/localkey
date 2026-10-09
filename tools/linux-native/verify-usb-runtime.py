"""Observe stock kernel USB runtime-PM decisions in an owned no-NIC guest."""
import array, base64, fcntl, hashlib, hmac, json, os, platform, re, shutil, subprocess, tempfile, threading, time, traceback
from pathlib import Path
import verify_composite as base
import verify_usb_state as state
import usb.util
from emucard.core import EncryptedState
from fido2.ctap2 import ClientPin, PinProtocolV2
from yubikit.core import TRANSPORT
from yubikit.management import CAPABILITY, DeviceConfig, ManagementSession
from yubikit.oath import CredentialData, OathSession
import usb_state_pending as pending

def wait_status(power,wanted):
    deadline=time.monotonic()+5
    while time.monotonic()<deadline:
        current=status(power)
        if current['runtime_status']==wanted:return current
        time.sleep(.02)
    raise AssertionError(('actual runtime state not reached',wanted,status(power)))

def prove_fido(f,credential,label,result):
    ct=state.fresh_hid(f)
    protocol=PinProtocolV2();token=ClientPin(ct,protocol).get_pin_token(state.PIN,ClientPin.PERMISSION.GET_ASSERTION,state.RP)
    digest=hashlib.sha256(('own runtime USB '+label).encode()).digest()
    response=ct.get_assertion(state.RP,digest,allow_list=[{'type':'public-key','id':credential.credential_id}],pin_uv_protocol=2,pin_uv_param=protocol.authenticate(token,digest))
    credential.public_key.verify(response.auth_data+digest,response.signature)
    check(response.user['id']==state.USER and response.auth_data.flags&5==5,'native runtime PIN UVp2 signed user and flags '+label)
    check(response.auth_data.rp_id_hash==hashlib.sha256(state.RP.encode()).digest(),'native runtime signature has correct RP hash '+label)
    if result['assertions']:check(response.auth_data.counter>result['assertions'][-1]['counter'],'native runtime FIDO counter increases '+label)
    result['assertions'].append({'phase':label,'counter':response.auth_data.counter,'signature_verified':True,'user_verified':True,'rp_id_hash_verified':True,'pin_uv_protocol':2,'challenge_sha256':digest.hex(),'credential_sha256':hashlib.sha256(credential.credential_id).hexdigest(),'user_handle_verified':True})
    state.close_hid(f)

checks=[]
def check(value,name):
    assert value,name
    checks.append({'name':name,'passed':True})
    print('PASS',name,flush=True)

def ensure_mount(kind,path):
    path.mkdir(exist_ok=True)
    mounts=Path('/proc/self/mountinfo').read_text().splitlines()
    mounted=any(line.split(' - ',1)[0].split()[4]==str(path) and line.split(' - ',1)[1].split()[0]==kind for line in mounts)
    if not mounted:subprocess.run(['/bin/mount','-t',kind,kind,str(path)],check=True)

def trace_return(text,name,result):
    return bool(re.search(r'rpm_return_int: rpm_'+name+r'\+[^:]+:1-1 ret='+str(result)+r'(?=\s|$)',text))

def status(directory):
    names=['control','runtime_status','runtime_active_time','runtime_suspended_time','runtime_usage','runtime_active_kids','runtime_enabled','autosuspend_delay_ms','wakeup','runtime_error']
    return {name:(directory/name).read_text().strip() for name in names if (directory/name).exists()}

def snapshot(device):
    result={'device':status(device/'power'),'interfaces':{}}
    for p in sorted(device.glob(device.name+':*')):
        result['interfaces'][p.name]={'power':status(p/'power'),'driver':str((p/'driver').resolve()) if (p/'driver').exists() else None}
    return result

def main():
    f=None;tmp=None;fd=None;trace=None;debug=None
    result={'passed':False,'physical_device_access':False,'host_device_passthrough':False,'production_udc_verified':False,'native_runtime_pm_verified':False,'host_hid_drivers_unbound':False,'physical_touch_verified':False,'tests':checks,'manufacturer_trust_reproduced':False,'native_macos_registration_verified':False,'full_platform_sleep_verified':False,'physical_firmware_power_timing_or_pin_token_semantics_verified':False,'observations':[],'cycles':[],'assertions':[],'fido_and_card_testing_auto_allow_for_owned_fixture':True}
    try:
        check(Path('/opt/isolated-ske-usb-guest').exists(),'private runtime USB guest marker')
        check(platform.release()=='6.8.0-146-generic' and platform.machine()=='aarch64','actual runtime ARM64 distro kernel')
        check([p.name for p in Path('/sys/class/net').iterdir()]==['lo'],'only loopback for runtime USB guest')
        trace=Path('/sys/kernel/tracing');ensure_mount('tracefs',trace)
        debug=Path('/sys/kernel/debug');ensure_mount('debugfs',debug)
        symbols=Path('/proc/kallsyms').read_text()
        selected=['autosuspend_check','usb_runtime_idle','usb_runtime_suspend','usb_runtime_resume']
        available=[name for name in selected if any(line.split()[-1]==name for line in symbols.splitlines() if line.split())]
        check(available==selected,'actual USB runtime kernel probe symbols available')
        result['kernel_probe_symbols']=available
        for name in available:
            probe_fd=os.open(trace/'kprobe_events',os.O_WRONLY|os.O_APPEND)
            try:os.write(probe_fd,('r:ske_runtime/'+name+' '+name+' result=$retval:s64\n').encode())
            finally:os.close(probe_fd)
        for name in available:(trace/'events/ske_runtime'/name/'enable').write_text('1\n')
        for group in ['rpm','power']:
            if (trace/'events'/group/'enable').exists():(trace/'events'/group/'enable').write_text('1\n')
        (trace/'buffer_size_kb').write_text('2048\n');(trace/'tracing_on').write_text('1\n')
        control=debug/'dynamic_debug/control'
        if control.exists():control.write_text('file drivers/usb/core/driver.c +p\n')
        tmp=Path(tempfile.mkdtemp(prefix='own-usb-runtime-',dir='/guest-state'))
        f=base.CompositeFixture(Path('/opt/swpasskeyd'),tmp);ct=f.start()
        result['service_pids']=[f.bridge.pid,f.process.pid,f.card.process.pid];result['controller']=f.controller
        protocol=PinProtocolV2();ClientPin(ct,protocol).set_pin(state.PIN)
        token=ClientPin(ct,protocol).get_pin_token(state.PIN,ClientPin.PERMISSION.MAKE_CREDENTIAL|ClientPin.PERMISSION.GET_ASSERTION,state.RP)
        digest=hashlib.sha256(b'own runtime USB registration').digest()
        response=ct.make_credential(digest,{'id':state.RP},{'id':state.USER,'name':'own-runtime'},[{'type':'public-key','alg':-7}],options={'rk':True},pin_uv_protocol=2,pin_uv_param=protocol.authenticate(token,digest))
        credential=response.auth_data.credential_data
        check(response.auth_data.flags&5==5 and credential.public_key[3]==-7,'owned resident ES256 credential created with PIN UVp2')
        state.close_hid(f);prove_fido(f,credential,'initial',result)
        device,identity=state.own_usb(f.serial);devicepath=Path(identity['path'])
        check('dummy_hcd' in str(devicepath) and device.serial_number==f.serial,'own runtime dummy USB identity')
        node=Path('/dev/bus/usb')/f'{device.bus:03d}'/f'{device.address:03d}'
        result['identity']=identity;result['initial']=snapshot(devicepath)
        result['owned_open_fds']={}
        for pid in [os.getpid(),f.process.pid,f.bridge.pid,f.card.process.pid]:
            result['owned_open_fds'][str(pid)]={}
            for p in (Path('/proc')/str(pid)/'fd').iterdir():
                try:target=os.readlink(p)
                except FileNotFoundError:continue
                if any(s in target for s in ['hidraw','/dev/input','/dev/bus/usb']):result['owned_open_fds'][str(pid)][p.name]=target
        oath=OathSession(pending.NativeCcid(device))
        hotp=oath.put_credential(CredentialData.parse_uri('otpauth://hotp/USBRuntime:owned?secret=JBSWY3DPEHPK3PXP&counter=0'))
        counter=lambda:EncryptedState(f.directory/'card/state.bin').data['oath']['credentials'][hotp.id.hex()]['counter']
        check(counter()==0,'own native OATH HOTP starts at zero')
        usb.util.dispose_resources(device)
        fd=os.open(node,os.O_RDWR|os.O_CLOEXEC)
        cap=array.array('I',[0]);fcntl.ioctl(fd,0x8004551a,cap,True);result['usbfs_capabilities']=cap[0];check(bool(cap[0]&0x100),'actual usbfs supports runtime suspend UAPI')
        saved=state.hashes(f)
        (trace/'trace').write_text('')
        (devicepath/'power/autosuspend_delay_ms').write_text('0\n')
        (devicepath/'power/control').write_text('auto\n')
        fcntl.ioctl(fd,0x5522)
        for delay in [.1,.5,1,2]:
            time.sleep(delay);result['observations'].append(snapshot(devicepath))
        result['actual_kernel_trace']=(trace/'trace').read_text()
        result['actual_kernel_log']=subprocess.run(['/bin/dmesg'],capture_output=True,text=True,check=True).stdout[-24000:]
        result['exact_state_preserved']=state.hashes(f)==saved
        result['same_three_services_alive']=all(p.poll() is None for p in [f.process,f.bridge,f.card.process])
        check(result['exact_state_preserved'] and result['same_three_services_alive'],'stock runtime policy observation preserves own state and three processes')
        result['final']=snapshot(devicepath)
        check(result['final']['device']['runtime_status']=='active' and result['final']['device']['runtime_usage']=='0' and result['final']['device']['runtime_suspended_time']=='0','stock OTP FIDO CCID remains active despite zero usage')
        check('usb 1-1: remote wakeup needed for autosuspend' in result['actual_kernel_log'],'kernel explicitly reports missing remote wakeup for stock profile7')
        check('autosuspend_check:' in result['actual_kernel_trace'] and 'result=4294967201' in result['actual_kernel_trace'] and trace_return(result['actual_kernel_trace'],'suspend',-11),'actual autosuspend check EOPNOTSUPP and own USB suspend EAGAIN observed')
        (devicepath/'power/control').write_text('on\n');os.close(fd);fd=None
        with state.reboot.connection('FIDO',f.serial) as connection:
            ManagementSession(connection).write_device_config(DeviceConfig({TRANSPORT.USB:CAPABILITY(0x33A)}),reboot=True)
        identity6=base.wait_for(lambda: (lambda x:x if x and x['address']!=identity['address'] and x['pid']==0x406 else None)(state.reboot.snapshot(f.serial)), 'own FIDO CCID profile did not reenumerate')
        reference=json.loads(Path('/opt/usb-reference-observation.json').read_text())
        check(identity6['host_visible_configuration_descriptor_hex']==reference['configuration_descriptor_hex'],'actual runtime FIDO CCID configuration equals saved physical reference')
        result['profile6_identity']=identity6;devicepath=Path(identity6['path']);power=devicepath/'power'
        bus=int((devicepath/'busnum').read_text())
        check(bus==1 and identity6['pid']==0x406 and identity6['host_visible_endpoint_addresses']==[4,0x84,2,0x82,0x83],'own actual runtime FIDO CCID bus and requested endpoints')
        node=Path('/dev/bus/usb')/f"{bus:03d}/{identity6['address']:03d}"
        fd=os.open(node,os.O_RDWR|os.O_CLOEXEC)
        for index,mode in enumerate(['manual-on','native-fido-sdk','native-ccid-sdk']):
            before=snapshot(devicepath);saved=state.hashes(f);previous_counter=counter()
            (trace/'trace').write_text('')
            (power/'autosuspend_delay_ms').write_text('0\n');(power/'control').write_text('auto\n');fcntl.ioctl(fd,0x5522)
            suspended=wait_status(power,'suspended');time.sleep(.2);still=status(power)
            check(still['runtime_status']=='suspended' and int(still['runtime_suspended_time'])>int(before['device']['runtime_suspended_time']),'actual suspended status and increasing kernel time '+mode)
            check(state.hashes(f)==saved and counter()==previous_counter,'runtime suspend preserves exact bytes and HOTP counter '+mode)
            check(all(p.poll() is None for p in [f.process,f.bridge,f.card.process]),'three original processes remain alive while runtime suspended '+mode)
            replies=[]
            def waiter():
                try:replies.append(fcntl.ioctl(fd,0x5523))
                except Exception as exc:replies.append(str(exc))
            thread=threading.Thread(target=waiter,daemon=True);thread.start()
            if mode=='manual-on':(power/'control').write_text('on\n')
            if mode=='native-ccid-sdk':
                backend=usb.backend.libusb1.get_backend(find_library=lambda name:'/usr/lib/aarch64-linux-gnu/libusb-1.0.so.0')
                devices=list(usb.core.find(find_all=True,idVendor=0x1050,idProduct=0x0406,backend=backend))
                check(len(devices)==1 and devices[0].serial_number==f.serial,'only own suspended USB is opened by actual native CCID SDK')
                code=OathSession(pending.NativeCcid(devices[0])).calculate_code(hotp).value
                digest=hmac.new(base64.b32decode('JBSWY3DPEHPK3PXP'),previous_counter.to_bytes(8,'big'),'sha1').digest();offset=digest[-1]&15
                expected=str((int.from_bytes(digest[offset:offset+4],'big')&0x7fffffff)%1000000).zfill(6)
                check(code==expected and counter()==previous_counter+1,'independent native HOTP after runtime autoresume commits once')
                usb.util.dispose_resources(devices[0])
            prove_fido(f,credential,mode,result)
            thread.join(3);check(replies==[0] and not thread.is_alive(),'actual usbfs WAIT_FOR_RESUME completes '+mode)
            resumed=wait_status(power,'active');after=state.reboot.snapshot(f.serial)
            check(after==identity6 and all(p.poll() is None for p in [f.process,f.bridge,f.card.process]),'runtime resume retains same USB address and original three processes '+mode)
            actual=(trace/'trace').read_text()
            check(trace_return(actual,'suspend',0) and trace_return(actual,'resume',0),'actual own USB runtime suspend and resume kernel return zero '+mode)
            check('usb_runtime_suspend:' in actual and 'usb_runtime_resume:' in actual,'actual runtime callback probes observed '+mode)
            check(snapshot(devicepath)['interfaces']==before['interfaces'],'stock HID driver bindings retained across runtime cycle '+mode)
            result['cycles'].append({'index':index,'mode':mode,'before':before,'suspended':suspended,'still_suspended':still,'resumed':resumed,'after':after,'actual_trace':actual,'persistent_bytes_unchanged_during_suspend':True,'counter_before':previous_counter,'counter_after':counter(),'wait_for_resume_return':replies,'same_three_services_alive':True})
        result['native_runtime_pm_verified']=True
        result['final_process_status']={name:process.poll() for name,process in [('bridge',f.bridge),('fido',f.process),('card',f.card.process)]}
        check(all(value is None for value in result['final_process_status'].values()),'all original runtime services healthy before teardown')
        result['passed']=True
    except Exception as exc:result.update(error=f'{type(exc).__name__}: {exc}',traceback=traceback.format_exc())
    finally:
        if trace and (trace/'tracing_on').exists():(trace/'tracing_on').write_text('0\n')
        if trace:
            for name in locals().get('available',[]):
                event=trace/'events/ske_runtime'/name/'enable'
                if event.exists():
                    event.write_text('0\n')
                    probe_fd=os.open(trace/'kprobe_events',os.O_WRONLY|os.O_APPEND)
                    try:os.write(probe_fd,('-:ske_runtime/'+name+'\n').encode())
                    finally:os.close(probe_fd)
            if (trace/'events/rpm/enable').exists():(trace/'events/rpm/enable').write_text('0\n')
        if debug and (debug/'dynamic_debug/control').exists():
            (debug/'dynamic_debug/control').write_text('file drivers/usb/core/driver.c -p\n')
        if f and 'devicepath' in locals() and devicepath.exists():
            try:(devicepath/'power/control').write_text('on\n')
            except Exception as exc:result.update(passed=False,power_restore_error=str(exc))
        if fd is not None:os.close(fd)
        if f:
            for name in ['usb.log','daemon.log','card/log.txt']:
                p=f.directory/name
                if p.exists():result[name]=p.read_text(errors='replace')[-6000:]
            try:f.stop()
            except Exception as exc:result.update(passed=False,cleanup_error=str(exc))
        if tmp and tmp.exists():shutil.rmtree(tmp)
        for name,key in [('swpasskeyd','emulator_binary_sha256'),('ske-usbd','usb_bridge_binary_sha256')]:result[key]=hashlib.sha256(Path('/opt',name).read_bytes()).hexdigest()
        result['card_service_sha256']=hashlib.sha256(Path('/opt/emucard/service.py').read_bytes()).hexdigest()
        result['helper_sha256']={name:hashlib.sha256(Path(path).read_bytes()).hexdigest() for name,path in [('verify-usb-runtime.py',__file__),('verify-usb-state.py','/opt/verification/verify_usb_state.py'),('usb-state-pending.py','/opt/verification/usb_state_pending.py')]}
        result['test_count']=len(checks)
        print('SKE_USB_RUNTIME_BEGIN\n'+json.dumps(result)+'\nSKE_USB_RUNTIME_END',flush=True)
    return 0 if result['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
