"""Actual CCID resume lifecycle, retained replies and canceled touch in an owned guest."""
import array,base64,fcntl,hashlib,hmac,json,os,platform,re,shutil,stat,struct,tempfile,threading,time,traceback
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import usb.core,usb.backend.libusb1,usb.util
import verify_composite as base
import verify_usb_state as state
import verify_usb_runtime as runtime
import usb_state_pending as pending
from emucard.core import EncryptedState
from fido2.ctap2 import ClientPin,PinProtocolV2
from yubikit.core import TRANSPORT,Tlv
from yubikit.management import CAPABILITY,DeviceConfig,ManagementSession
from yubikit.oath import CredentialData,OathSession
from yubikit.piv import DEFAULT_MANAGEMENT_KEY,KEY_TYPE,OBJECT_ID,SLOT,PivSession
from yubikit.core.smartcard import ApduError

checks=[]
write_observations=[]
def check(value,name):
    assert value,name
    checks.append({'name':name,'passed':True});print('PASS',name,flush=True)
runtime.check=check

def prove_fido(f,credential,label,report):
    ct=state.fresh_hid(f);protocol=PinProtocolV2()
    token=ClientPin(ct,protocol).get_pin_token(state.PIN,ClientPin.PERMISSION.GET_ASSERTION,state.RP)
    digest=hashlib.sha256(('own queued runtime USB '+label).encode()).digest()
    response=ct.get_assertion(state.RP,digest,allow_list=[{'type':'public-key','id':credential.credential_id}],
        pin_uv_protocol=2,pin_uv_param=protocol.authenticate(token,digest))
    credential.public_key.verify(response.auth_data+digest,response.signature)
    check(response.credential['id']==credential.credential_id and response.user['id']==state.USER and response.auth_data.flags&5==5,
          'native queued runtime PIN UVp2 signed credential user and flags '+label)
    check(response.auth_data.rp_id_hash==hashlib.sha256(state.RP.encode()).digest(),'native queued runtime correct RP hash '+label)
    if report['assertions']:check(response.auth_data.counter>report['assertions'][-1]['counter'],'native queued runtime FIDO counter increases '+label)
    report['assertions'].append({'phase':label,'counter':response.auth_data.counter,'signature_verified':True,'credential_verified':True,
        'user_verified':True,'user_handle_verified':True,'rp_id_hash_verified':True,'pin_uv_protocol':2,
        'challenge_sha256':digest.hex(),'credential_sha256':hashlib.sha256(credential.credential_id).hexdigest()})
    state.close_hid(f)

def blocked_write(pid,size):
    for task in (Path('/proc')/str(pid)/'task').iterdir():
        try:
            text=(task/'syscall').read_text().strip();words=text.split()
            if not words or words[0]!='64':continue
            fd=int(words[1],0)
            if os.readlink(Path('/proc')/str(pid)/'fd'/str(fd))!='/dev/ffs-ske/ep4':continue
            if int(words[3],0)!=size:continue
            assert re.search(r'^Tgid:\s+'+str(pid)+r'$',(task/'status').read_text(),re.M)
            return {'tid':int(task.name),'tgid':pid,'fd':fd,'bytes':size,'buffer':words[2],
                    'syscall':text,'wchan':(task/'wchan').read_text().strip(),'endpoint':'/dev/ffs-ske/ep4'}
        except (FileNotFoundError,ProcessLookupError):continue
    return None

def wait_write(pid,size):
    deadline=time.monotonic()+3
    while time.monotonic()<deadline:
        found=blocked_write(pid,size)
        if found:
            write_observations.append(found)
            if found['wchan']=='ffs_epfile_io':return found
        time.sleep(.01)
    return None

def same_write(a,b):
    return b is not None and all(a[k]==b[k] for k in ['tid','tgid','fd','bytes','buffer','endpoint']) and b['wchan']=='ffs_epfile_io'

def own_borrowed_fd(node):
    found=[]
    for path in Path('/proc/self/fd').iterdir():
        try:
            if os.readlink(path)==str(node):found.append(int(path.name))
        except FileNotFoundError:continue
    check(len(found)==1,'one owned preexisting libusb usbfs file holds runtime reference')
    fd=found[0];actual=os.fstat(fd);expected=node.stat()
    check(stat.S_ISCHR(actual.st_mode) and actual.st_rdev==expected.st_rdev and
          fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE==os.O_RDWR,
          'borrowed usbfs descriptor is own writable character device')
    return fd

def main():
    f=None;tmp=None;trace=None;d=None;extra_fd=None
    report={'passed':False,'tests':checks,'cycles':[],'assertions':[],
            'scope':'same-generation queued FunctionFS CCID data and ZLP across real profile6 runtime PM',
            'physical_device_access':False,'host_device_passthrough':False,'manufacturer_trust_reproduced':False,
            'native_macos_registration_verified':False,'production_udc_verified':False,
            'physical_touch_verified':False,'full_platform_sleep_verified':False,
            'host_hid_drivers_unbound':False,'fido_testing_auto_allow_for_owned_fixture':True,'card_testing_auto_allow':False,
            'native_queued_runtime_pm_verified':False,'native_ccid_resume_slot_lifecycle_verified':False,'notifications':[]}
    try:
        check(Path('/opt/isolated-ske-usb-guest').exists(),'private queued runtime USB guest marker')
        check(platform.release()=='6.8.0-146-generic' and platform.machine()=='aarch64' and
              [p.name for p in Path('/sys/class/net').iterdir()]==['lo'],'actual ARM64 distro kernel and only loopback')
        trace=Path('/sys/kernel/tracing');runtime.ensure_mount('tracefs',trace)
        symbols=Path('/proc/kallsyms').read_text();selected=['autosuspend_check','usb_runtime_idle','usb_runtime_suspend','usb_runtime_resume']
        available=[name for name in selected if any(line.split()[-1]==name for line in symbols.splitlines() if line.split())]
        check(available==selected,'actual queued runtime kernel probe symbols available');report['kernel_probe_symbols']=available
        for name in available:
            p=os.open(trace/'kprobe_events',os.O_WRONLY|os.O_APPEND)
            try:os.write(p,('r:ske_pending_runtime/'+name+' '+name+' result=$retval:s64\n').encode())
            finally:os.close(p)
            (trace/'events/ske_pending_runtime'/name/'enable').write_text('1\n')
        (trace/'events/power/enable').write_text('0\n')
        (trace/'events/rpm/enable').write_text('1\n')
        for name in ['device_pm_callback_start','device_pm_callback_end']:
            (trace/'events/power'/name/'enable').write_text('1\n')
        (trace/'buffer_size_kb').write_text('2048\n');(trace/'tracing_on').write_text('1\n')
        tmp=Path(tempfile.mkdtemp(prefix='own-queued-runtime-',dir='/guest-state'))
        os.environ['SKE_TRACE_USB']='1'
        f=base.CompositeFixture(Path('/opt/swpasskeyd'),tmp)
        f.card=pending.PromptCardFixture(Path('/opt'),tmp/'card',startup_timeout=30)
        ct=f.start()
        report['service_pids']=[f.bridge.pid,f.process.pid,f.card.process.pid];report['controller']=f.controller
        protocol=PinProtocolV2();ClientPin(ct,protocol).set_pin(state.PIN)
        token=ClientPin(ct,protocol).get_pin_token(state.PIN,ClientPin.PERMISSION.MAKE_CREDENTIAL|ClientPin.PERMISSION.GET_ASSERTION,state.RP)
        digest=hashlib.sha256(b'own queued runtime registration').digest()
        response=ct.make_credential(digest,{'id':state.RP},{'id':state.USER,'name':'own-queued-runtime'},[{'type':'public-key','alg':-7}],
            options={'rk':True},pin_uv_protocol=2,pin_uv_param=protocol.authenticate(token,digest))
        credential=response.auth_data.credential_data
        check(response.auth_data.flags&5==5 and credential.public_key[3]==-7,'owned resident ES256 credential created using PIN UVp2')
        state.close_hid(f);prove_fido(f,credential,'initial',report)
        original=state.reboot.snapshot(f.serial);report['original_identity']=original
        with state.reboot.connection('FIDO',f.serial) as connection:
            ManagementSession(connection).write_device_config(DeviceConfig({TRANSPORT.USB:CAPABILITY(0x33A)}),reboot=True)
        identity=base.wait_for(lambda:(lambda x:x if x and x['address']!=original['address'] and x['pid']==0x406 else None)(state.reboot.snapshot(f.serial)),
                                'own queued runtime profile6 did not reenumerate')
        devicepath=Path(identity['path']);power=devicepath/'power';report['profile6_identity']=identity
        reference=json.loads(Path('/opt/usb-reference-observation.json').read_text())
        check(identity['host_visible_configuration_descriptor_hex']==reference['configuration_descriptor_hex'],
              'owned profile6 configuration is byte equal to preserved physical reference')
        check('dummy_hcd' in str(devicepath) and identity['host_visible_endpoint_addresses']==[4,0x84,2,0x82,0x83],
              'only owned dummy USB profile6 with original requested endpoint addresses')
        backend=usb.backend.libusb1.get_backend(find_library=lambda name:'/usr/lib/aarch64-linux-gnu/libusb-1.0.so.0')
        devices=list(usb.core.find(find_all=True,idVendor=0x1050,idProduct=0x0406,backend=backend))
        check(len(devices)==1 and devices[0].serial_number==f.serial and devices[0].address==identity['address'],
              'actual libusb opens only own profile6 device')
        d=devices[0];connection=pending.NativeCcid(d)
        oath=OathSession(connection)
        own=oath.put_credential(CredentialData.parse_uri('otpauth://hotp/QueuedRuntime:owned?secret=JBSWY3DPEHPK3PXP&counter=0'))
        counter=lambda:EncryptedState(f.directory/'card/state.bin').data['oath']['credentials'][own.id.hex()]['counter']
        check(counter()==0,'fresh native HOTP counter zero')
        notification=bytes(d.read(0x83,8,timeout=1500))
        check(notification==b'\x50\x03','actual initial occupied slot notification')
        report['notifications'].append({'read_phase':'initial','hex':notification.hex(),'origin':'initial configuration'})
        bus=int((devicepath/'busnum').read_text());check(bus==1,'own queued runtime USB bus one')
        node=Path('/dev/bus/usb')/f'{bus:03d}/{identity["address"]:03d}'
        fd=own_borrowed_fd(node);report['borrowed_usbfs_fd']=fd;report['borrowed_usbfs_node']=str(node)
        cap=array.array('I',[0]);fcntl.ioctl(fd,0x8004551a,cap,True);report['usbfs_capabilities']=cap[0]
        check(bool(cap[0]&0x100),'actual borrowed usbfs supports runtime suspend UAPI')

        entry_event=trace/'events/syscalls/sys_enter_write';exit_event=trace/'events/syscalls/sys_exit_write'
        def arm_write():
            threads=[int(t.name) for t in (Path('/proc')/str(f.bridge.pid)/'task').iterdir()]
            own_filter=' || '.join('common_pid == '+str(tid) for tid in threads)
            for event in [entry_event,exit_event]:
                (event/'filter').write_text(own_filter+'\n');(event/'enable').write_text('1\n')
            (trace/'trace').write_text('')
        def completed_write(size):
            deadline=time.monotonic()+3
            while time.monotonic()<deadline:
                actual=(trace/'trace').read_text();lines=actual.splitlines()
                for i,line in enumerate(lines):
                    if not ('sys_write(' in line or 'sys_enter_write:' in line):continue
                    if not re.search(r'fd: a, buf: [0-9a-f]+, count: '+format(size,'x')+r'\b',line):continue
                    match=re.search(r'\bske-usbd-(\d+)\s',line)
                    if not match:continue
                    tid=int(match[1]);following=[x for x in lines[i+1:] if re.search(r'\bske-usbd-'+str(tid)+r'\s',x)]
                    if following and re.search(r'(?:sys_exit_write:|sys_write ->)\s*(?:0x'+format(size,'x')+'|'+str(size)+r')\b',following[0]):
                        return {'tid':tid,'fd':10,'bytes':size,'entry':line,'exit':following[0],'actual_trace':actual,
                                'kernel_write_completed_before_host_read':True}
                time.sleep(.01)
            raise AssertionError('owned endpoint completed write trace missing '+str(size))

        def cycle(mode,label,target,saved,expected_counter,kernel_buffered=False):
            nonlocal extra_fd
            size=target['bytes'];before=runtime.snapshot(devicepath)
            check(blocked_write(f.bridge.pid,size) is None if kernel_buffered else same_write(target,blocked_write(f.bridge.pid,size)),
                  ('original write already completed into kernel before suspend ' if kernel_buffered else 'same original blocked endpoint before suspend ')+label)
            (trace/'trace').write_text('');(power/'autosuspend_delay_ms').write_text('0\n');(power/'control').write_text('auto\n')
            fcntl.ioctl(fd,0x5522)
            suspended=runtime.wait_status(power,'suspended');time.sleep(.2);still=runtime.status(power)
            report['last_suspended_observation']=still;report['last_suspended_worker']=blocked_write(f.bridge.pid,size)
            check(still['runtime_status']=='suspended' and still['runtime_usage']=='0' and
                  int(still['runtime_suspended_time'])>int(before['device']['runtime_suspended_time']),
                  'real queued endpoint runtime suspend and increasing kernel time '+label)
            check(report['last_suspended_worker'] is None if kernel_buffered else same_write(target,report['last_suspended_worker']),
                  ('completed original kernel write remains completed while suspended ' if kernel_buffered else 'original endpoint thread buffer and file retained while suspended ')+label)
            check(state.hashes(f)==saved and counter()==expected_counter,'exact persisted bytes and HOTP unchanged while suspended '+label)
            check(all(p.poll() is None for p in [f.bridge,f.process,f.card.process]),'all three original services alive while suspended '+label)
            replies=[]
            def waiter():
                try:replies.append(fcntl.ioctl(fd,0x5523))
                except Exception as exc:replies.append(str(exc))
            thread=threading.Thread(target=waiter,daemon=True);thread.start()
            if mode=='manual-on':(power/'control').write_text('on\n')
            elif mode=='native-fido-sdk':state.fresh_hid(f)
            elif mode=='new-usbfs-open':extra_fd=os.open(node,os.O_RDWR|os.O_CLOEXEC)
            else:raise AssertionError(mode)
            thread.join(3);check(replies==[0] and not thread.is_alive(),'actual borrowed usbfs WAIT_FOR_RESUME returns zero '+label)
            resumed=runtime.wait_status(power,'active');actual=(trace/'trace').read_text()
            ct=f.ctap if f.device is not None else state.fresh_hid(f)
            ping=('own unread CCID '+label).encode()
            check('FIDO_2_1' in ct.get_info().versions and f.device.ping(ping)==ping,
                  'native FIDO GetInfo and PING succeed with original CCID still unread '+label)
            state.close_hid(f)
            check(blocked_write(f.bridge.pid,size) is None if kernel_buffered else same_write(target,blocked_write(f.bridge.pid,size)),
                  ('original completed write has no duplicate nineteen-byte write after resume and FIDO ' if kernel_buffered else 'original endpoint response remains queued after resume and FIDO ')+label)
            check(state.hashes(f)==saved and counter()==expected_counter,'resume and independent FIDO do not recommit HOTP '+label)
            after=state.reboot.snapshot(f.serial)
            check(after==identity and all(p.poll() is None for p in [f.bridge,f.process,f.card.process]),
                  'runtime cycle retains actual USB generation and all three original services '+label)
            check(runtime.trace_return(actual,'suspend',0) and runtime.trace_return(actual,'resume',0),
                  'actual own USB runtime suspend and resume kernel returns zero '+label)
            check('usb_runtime_suspend:' in actual and 'usb_runtime_resume:' in actual,
                  'actual USB runtime callback kretprobes recorded '+label)
            check(runtime.snapshot(devicepath)['interfaces']==before['interfaces'],'stock HID interface drivers retained '+label)
            if extra_fd is not None:os.close(extra_fd);extra_fd=None
            return {'mode':mode,'phase':label,'response_representation':'kernel-buffered' if kernel_buffered else 'blocked-userspace-write',
                    'before':before,'suspended':suspended,'still_suspended':still,'resumed':resumed,
                    'before_worker':target,'suspended_worker':report['last_suspended_worker'],'resumed_worker':blocked_write(f.bridge.pid,size),
                    'before_usb':identity,'after_usb':after,'actual_trace':actual,'wait_for_resume_return':replies,
                    'persistent_bytes_unchanged_during_suspend':True,'same_three_services_alive':True,
                    'native_fido_while_ccid_unread_verified':True,'counter_before':expected_counter,'counter_after_resume':counter()}

        def reactivate(label,saved,expected_counter):
            notification=bytes(d.read(0x83,8,timeout=1500))
            report['notifications'].append({'read_phase':label,'hex':notification.hex(),'origin':'current resume'})
            check(notification==b'\x50\x03','current resume occupied slot insertion notification received once '+label)
            header,data=connection.exchange(0x65)
            report['actual_post_resume_slot_status']={'header':list(header),'data_hex':data.hex(),'phase':label}
            check(header[0]==0x81 and header[4]==1 and header[5]==0 and header[6]==3 and not data,
                  'actual CCID slot occupied inactive with stopped clock after resume '+label)
            sequence=connection.write(0x6f,bytes.fromhex('00a4040007a0000005272101'))
            denied,payload=connection.read(sequence)
            check(denied[0]==0x80 and denied[4]==0x41 and denied[5]==0xfe and not payload,
                  'real USB denies APDU before explicit PowerOn '+label)
            check(state.hashes(f)==saved and counter()==expected_counter,
                  'resume inactive status and denied unpowered APDU retain exact state '+label)
            powered,atr=connection.exchange(0x62)
            check(powered[0]==0x80 and powered[4]==0 and powered[5]==0 and atr==bytes.fromhex('3bf011000001e0'),
                  'explicit native PowerOn receives original ATR and active slot '+label)
            active,empty=connection.exchange(0x65)
            check(active[0]==0x81 and active[4]==0 and active[5]==0 and active[6]==0 and not empty,
                  'actual activated slot and running clock only after PowerOn '+label)
            check(state.hashes(f)==saved and counter()==expected_counter,
                  'explicit card lifecycle does not mutate durable state or HOTP '+label)
            return {'notification_hex':notification.hex(),'inactive_header':list(header),'denied_unpowered_apdu_header':list(denied),
                    'poweron_header':list(powered),'atr_hex':atr.hex(),'active_header':list(active),
                    'explicit_poweron_required_verified':True,'exact_persistent_state_unchanged_during_lifecycle':True,
                    'counter':counter()}

        for index,mode in enumerate(['manual-on','native-fido-sdk','new-usbfs-open']):
            arm_write();primer_sequence=connection.write(0x65)
            primer=completed_write(10)
            check(primer['kernel_write_completed_before_host_read'],'actual original slot reply buffered in kernel before host read '+str(index))
            payload=Tlv(0x71,own.id)+Tlv(0x74,bytes(8));sequence=connection.write(0x6f,bytes([0,0xa2,0,1,len(payload)])+payload)
            target=wait_write(f.bridge.pid,19)
            if target is None:
                report['diagnostic_hotp_counter']=counter()
                report['diagnostic_worker_syscalls']={t.name:{'syscall':(t/'syscall').read_text(),'wchan':(t/'wchan').read_text()} for t in (Path('/proc')/str(f.bridge.pid)/'task').iterdir()}
                report['diagnostic_native_fds']={p.name:os.readlink(p) for p in (Path('/proc')/str(f.bridge.pid)/'fd').iterdir()}
                try:report['diagnostic_pending_packet_hex']=bytes(d.read(0x82,3072,timeout=1500)).hex()
                except Exception as exc:report['diagnostic_packet_read_error']=str(exc)
            check(target is not None and target['wchan']=='ffs_epfile_io','actual original nineteen-byte CCID data write blocked '+str(index))
            check(counter()==index+1,'native HOTP committed once before unread response '+str(index))
            saved=state.hashes(f);row=cycle(mode,'data-'+str(index),target,saved,index+1)
            primer_header,primer_data=connection.read(primer_sequence)
            check(primer_header[0]==0x81 and primer_header[4:]==(0,0,0) and not primer_data,
                  'original kernel buffered pre-suspend active slot response retains sequence and bytes '+str(index))
            row['kernel_buffered_prior_reply']={**primer,'sequence':primer_sequence,'header':list(primer_header),'payload_hex':primer_data.hex()}
            header,data=connection.read(sequence)
            check(header[0]==0x80 and header[4]&0xc0==0 and header[5]==0 and data[-2:]==b'\x90\x00',
                  'original native CCID sequence delivered once after runtime resume '+str(index))
            digest=hmac.new(base64.b32decode('JBSWY3DPEHPK3PXP'),index.to_bytes(8,'big'),'sha1').digest();offset=digest[-1]&15
            expected=int.from_bytes(digest[offset:offset+4],'big')&0x7fffffff
            check(Tlv.parse_dict(data[:-2])[0x76]==bytes([6])+expected.to_bytes(4,'big') and counter()==index+1,
                  'independent original HOTP response and single counter commit '+str(index))
            row['resume_card_lifecycle']=reactivate('data-'+str(index),saved,index+1)
            oath=OathSession(connection)
            check(oath.list_credentials()[0].id==own.id and counter()==index+1,
                  'following unmodified OATH SDK request has no stale duplicate response '+str(index))
            row.update(index=index,sequence=sequence,counter_before_request=index,counter_after_drain=counter(),
                       independent_hotp_verified=True,following_sdk_no_stale_response_verified=True)
            report['cycles'].append(row);prove_fido(f,credential,'data-'+str(index),report)

        piv=PivSession(connection);piv.authenticate(DEFAULT_MANAGEMENT_KEY);owned_payload=bytes(range(50))
        piv.put_object(OBJECT_ID.CHUID,owned_payload)
        check(piv.get_object(OBJECT_ID.CHUID)==owned_payload,'native PIV SDK verifies own opaque fifty-byte transport object')
        piv_key=piv.generate_key(SLOT.AUTHENTICATION,KEY_TYPE.ECCP256);piv.verify_pin('123456')
        piv_digest=hashlib.sha256(b'own native card resume PIV').digest()
        piv_key.verify(piv.sign(SLOT.AUTHENTICATION,KEY_TYPE.ECCP256,piv_digest,hashes.SHA256()),piv_digest,ec.ECDSA(hashes.SHA256()))
        check(True,'native PIV SDK original key and pre-resume PIN signature independently verified')
        body=Tlv(0x5c,int(OBJECT_ID.CHUID).to_bytes(3,'big'));sequence=connection.write(0x6f,bytes([0,0xcb,0x3f,0xff,len(body)])+body)
        target=wait_write(f.bridge.pid,0)
        check(target is not None and target['wchan']=='ffs_epfile_io','original zero-length terminator entered before host drains sixty-four-byte packet')
        packet=bytes(d.read(0x82,64,timeout=1500));header=struct.unpack('<BIBBBBB',packet[:10])
        check(len(packet)==64 and header[0]==0x80 and header[1]==54 and header[3]==sequence and header[4]&0xc0==0 and
              packet[-2:]==b'\x90\x00' and Tlv.parse_dict(packet[10:-2])[0x53]==owned_payload,
              'actual USB receives complete original sixty-four-byte CCID packet once')
        target=wait_write(f.bridge.pid,0)
        check(target is not None and int(target['buffer'],0)==0 and target['wchan']=='ffs_epfile_io',
              'separate actual zero-length CCID terminator blocked after data packet')
        saved=state.hashes(f);before_counter=counter();row=cycle('manual-on','zlp',target,saved,before_counter)
        terminator=bytes(d.read(0x82,1,timeout=1500))
        check(terminator==b'','actual USB receives only original zero-length terminator after runtime resume')
        check(state.hashes(f)==saved and counter()==before_counter,'completed ZLP preserves exact persisted bytes and HOTP')
        row['resume_card_lifecycle']=reactivate('zlp',saved,before_counter)
        for operation,label in [
            (lambda:piv.sign(SLOT.AUTHENTICATION,KEY_TYPE.ECCP256,piv_digest,hashes.SHA256()),'PIN verification'),
            (lambda:piv.generate_key(SLOT.SIGNATURE,KEY_TYPE.ECCP256),'management authentication')]:
            try:operation()
            except ApduError as exc:check(exc.sw==0x6982,'real USB resume revokes previous PIV '+label)
            else:raise AssertionError('PIV authorization survived real resume '+label)
        piv.verify_pin('123456')
        piv_key.verify(piv.sign(SLOT.AUTHENTICATION,KEY_TYPE.ECCP256,piv_digest,hashes.SHA256()),piv_digest,ec.ECDSA(hashes.SHA256()))
        check(True,'fresh native PIV PIN independently verifies original persisted key signature after resume')
        row['piv_pin_and_management_authorization_revoked_verified']=True
        row['fresh_piv_pin_original_key_signature_verified']=True
        piv=PivSession(connection)
        logical=lambda:hashlib.sha256(json.dumps(EncryptedState(f.directory/'card/state.bin').data,sort_keys=True).encode()).hexdigest()
        before_logical=logical()
        check(piv.get_object(OBJECT_ID.CHUID)==owned_payload,'following unmodified PIV SDK has new sequence and no stale data or ZLP')
        check(logical()==before_logical and counter()==before_counter,'following PIV read retains own card plaintext state and HOTP')
        row.update(sequence=sequence,data_packet_bytes=64,object_payload_bytes=50,zero_length_terminator_bytes=len(terminator),
                   counter_after_drain=counter(),following_sdk_no_stale_response_verified=True,
                   following_sdk_persistent_plaintext_unchanged=True,following_read_reencrypts_unchanged_plaintext=state.hashes(f)!=saved,
                   object_is_opaque_transport_fixture_not_valid_chuid=True)
        report['zlp']=row;prove_fido(f,credential,'zlp',report)
        oath=OathSession(connection);arm_write()
        payload=Tlv(0x71,own.id)+Tlv(0x74,bytes(8));sequence=connection.write(0x6f,bytes([0,0xa2,0,1,len(payload)])+payload)
        completed=completed_write(19)
        check(completed['kernel_write_completed_before_host_read'] and counter()==4,
              'original nineteen-byte HOTP response kernel write completes before any host IN read and commits once')
        saved=state.hashes(f);row=cycle('manual-on','kernel-buffered-hotp',completed,saved,4,kernel_buffered=True)
        header,data=connection.read(sequence)
        digest=hmac.new(base64.b32decode('JBSWY3DPEHPK3PXP'),(3).to_bytes(8,'big'),'sha1').digest();offset=digest[-1]&15
        expected=int.from_bytes(digest[offset:offset+4],'big')&0x7fffffff
        check(header[0]==0x80 and header[4]==0 and header[5]==0 and data[-2:]==b'\x90\x00' and
              Tlv.parse_dict(data[:-2])[0x76]==bytes([6])+expected.to_bytes(4,'big') and counter()==4,
              'original kernel buffered HOTP retains exact sequence independently verified bytes and single commit across real resume')
        row['resume_card_lifecycle']=reactivate('kernel-buffered-hotp',saved,4)
        oath=OathSession(connection)
        check(oath.list_credentials()[0].id==own.id and counter()==4,'following SDK sequence after kernel buffered HOTP has no stale duplicate')
        row.update(sequence=sequence,counter_before_request=3,counter_after_drain=4,independent_hotp_verified=True,
                   following_sdk_no_stale_response_verified=True)
        report['kernel_buffered_hotp']=row;prove_fido(f,credential,'kernel-buffered-hotp',report)
        touch_own=oath.put_credential(CredentialData.parse_uri(
            'otpauth://hotp/ResumeTouch:owned?secret=JBSWY3DPEHPK3PXP&counter=0'),touch_required=True)
        touch_counter=lambda:EncryptedState(f.directory/'card/state.bin').data['oath']['credentials'][touch_own.id.hex()]['counter']
        check(touch_counter()==0,'fresh native resume touch HOTP counter zero')
        previous=(f.directory/'card/log.txt').read_text().count('approve user presence')
        saved=state.hashes(f);payload=Tlv(0x71,touch_own.id)+Tlv(0x74,bytes(8))
        sequence=connection.write(0x6f,bytes([0,0xa2,0,1,len(payload)])+payload)
        deadline=time.monotonic()+5
        while (f.directory/'card/log.txt').read_text().count('approve user presence')<=previous:
            assert time.monotonic()<deadline,'actual pending resume terminal prompt not reached'
            time.sleep(.03)
        check(touch_counter()==0 and state.hashes(f)==saved,'actual terminal presence waits without touching persistent state')
        target=wait_write(f.bridge.pid,10)
        check(target is not None,'actual original WTX write waits while terminal presence remains pending')
        row=cycle('manual-on','terminal-presence',target,saved,4)
        extensions=[]
        while True:
            header,data=connection.read(sequence)
            if header[4]&0xc0==0x80:
                assert header[0]==0x80 and not data and header[5]==1,'invalid original WTX during cancellation'
                extensions.append(list(header));continue
            break
        check(len(extensions)>=2,'original kernel buffered and blocked WTX replies both preserved through runtime resume')
        check(all(h[3]==sequence and h[4]==0x80 and h[5]==1 for h in extensions),'all original WTX sequences and time extension fields preserved')
        check(header[0]==0x80 and header[4]==0x40 and header[5]==0xff and not data,
              'original uncommitted native touch command returns CMD_ABORTED after runtime resume')
        check(touch_counter()==0 and state.hashes(f)==saved,'resume cancels original terminal touch without HOTP or persistent mutation')
        row['resume_card_lifecycle']=reactivate('terminal-presence',saved,4)
        oath=OathSession(connection)
        check(any(c.id==touch_own.id for c in oath.list_credentials()) and touch_counter()==0,
              'fresh powered OATH SDK recovers without stale aborted response')
        previous=(f.directory/'card/log.txt').read_text().count('approve user presence')
        with ThreadPoolExecutor(max_workers=1) as executor:
            future=executor.submit(oath.calculate_code,touch_own)
            deadline=time.monotonic()+5
            while (f.directory/'card/log.txt').read_text().count('approve user presence')<=previous:
                assert time.monotonic()<deadline,'fresh post-resume terminal prompt not reached'
                time.sleep(.03)
            check(not future.done() and touch_counter()==0,'new native touch request needs fresh actual terminal approval')
            f.card.process.stdin.write('y\n');f.card.process.stdin.flush();code=future.result(3).value
        digest=hmac.new(base64.b32decode('JBSWY3DPEHPK3PXP'),bytes(8),'sha1').digest();offset=digest[-1]&15
        expected=str((int.from_bytes(digest[offset:offset+4],'big')&0x7fffffff)%1000000).zfill(6)
        check(code==expected and touch_counter()==1,'fresh actual terminal approval yields independently verified HOTP and one commit')
        check(any(c.id==touch_own.id for c in oath.list_credentials()) and touch_counter()==1,
              'following native touch SDK sequence has no duplicate response or commit')
        row.update(sequence=sequence,original_wtx_headers=extensions,aborted_header=list(header),
                   real_terminal_presence_verified=True,card_testing_auto_allow=False,counter_before_request=0,
                   counter_after_cancel=0,counter_after_fresh_approval=1,independent_hotp_verified=True,
                   following_sdk_no_stale_response_verified=True,fresh_actual_terminal_approval_required=True)
        report['pending_terminal_presence']=row;prove_fido(f,credential,'terminal-presence',report)
        check(len(report['notifications'])==7,'one initial plus six resume insertion notifications delivered without losing held response')
        try:d.read(0x83,8,timeout=150)
        except usb.core.USBError as exc:check(exc.errno==110,'no duplicate slot insertion remains after all six actual resumes')
        else:raise AssertionError('unexpected extra slot insertion notification')
        actual_usb_log=(f.directory/'usb.log').read_text()
        check(actual_usb_log.count('functionfs_suspend\n')==actual_usb_log.count('functionfs_resume\n')==
              actual_usb_log.count('ccid_resume_inactive preserved_transfer_generation=1\n')==6,
              'six real FunctionFS suspend resume events deactivate card while preserving original transfer generation')
        report['dummy_hcd_shared_fifo_occupied_by_kernel_buffered_prior_slot_reply_for_blocked_data']=True
        report['final_process_status']={name:process.poll() for name,process in [('bridge',f.bridge),('fido',f.process),('card',f.card.process)]}
        check(all(value is None for value in report['final_process_status'].values()),'all original queued runtime services healthy before teardown')
        check(state.reboot.snapshot(f.serial)==identity and counter()==4 and touch_counter()==1,
              'final same USB generation exactly four original HOTP commits and one fresh approved touch commit')
        report['native_queued_runtime_pm_verified']=True;report['native_ccid_resume_slot_lifecycle_verified']=True;report['passed']=True
    except Exception as exc:
        report.update(error=f'{type(exc).__name__}: {exc}',traceback=traceback.format_exc())
        if trace and (trace/'trace').exists():report['failure_actual_trace']=(trace/'trace').read_text()
    finally:
        if extra_fd is not None:os.close(extra_fd)
        if trace and (trace/'tracing_on').exists():(trace/'tracing_on').write_text('0\n')
        if trace:
            for event in [trace/'events/syscalls/sys_enter_write',trace/'events/syscalls/sys_exit_write']:
                if (event/'enable').exists():(event/'enable').write_text('0\n')
            for name in locals().get('available',[]):
                event=trace/'events/ske_pending_runtime'/name/'enable'
                if event.exists():
                    event.write_text('0\n');p=os.open(trace/'kprobe_events',os.O_WRONLY|os.O_APPEND)
                    try:os.write(p,('-:ske_pending_runtime/'+name+'\n').encode())
                    finally:os.close(p)
            for group in ['rpm','power']:
                if (trace/'events'/group/'enable').exists():(trace/'events'/group/'enable').write_text('0\n')
        if f and 'devicepath' in locals() and devicepath.exists():
            try:(devicepath/'power/control').write_text('on\n')
            except Exception as exc:report.update(passed=False,power_restore_error=str(exc))
        if d is not None:usb.util.dispose_resources(d) # borrowed fd remains libusb-owned
        if f:
            for name in ['usb.log','daemon.log','card/log.txt']:
                p=f.directory/name
                if p.exists():report[name]=p.read_text(errors='replace')[-6000:]
            try:f.stop()
            except Exception as exc:report.update(passed=False,cleanup_error=str(exc))
        if tmp and tmp.exists():shutil.rmtree(tmp)
        for name,key in [('swpasskeyd','emulator_binary_sha256'),('ske-usbd','usb_bridge_binary_sha256')]:report[key]=hashlib.sha256(Path('/opt',name).read_bytes()).hexdigest()
        report['card_service_sha256']=hashlib.sha256(Path('/opt/emucard/service.py').read_bytes()).hexdigest()
        report['helper_sha256']={name:hashlib.sha256(Path(path).read_bytes()).hexdigest() for name,path in
            [('verify-usb-runtime-pending.py',__file__),('verify-usb-runtime.py','/opt/verification/verify_usb_runtime.py'),
             ('verify-usb-state.py','/opt/verification/verify_usb_state.py'),('usb-state-pending.py','/opt/verification/usb_state_pending.py')]}
        report['write_observations']=write_observations
        report['test_count']=len(checks)
        print('SKE_USB_RUNTIME_PENDING_BEGIN\n'+json.dumps(report)+'\nSKE_USB_RUNTIME_PENDING_END',flush=True)
    return 0 if report['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
