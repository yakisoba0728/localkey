"""Verify original large prefix64 across actual owned runtime PM."""
import array
import base64
import fcntl
import threading
import copy
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
import tempfile
import time
import traceback
from pathlib import Path

import usb.backend.libusb1
import usb.core
import usb.util
import verify_composite as base
import verify_usb_state as state
import verify_usb_runtime as runtime
import verify_usb_runtime_pending as queued_runtime
import verify_usb_reboot_pending as shared
import verify_usb_long_cutover as long
import usb_state_pending as pending
import native_ccid_io as native_io
from emucard.core import EncryptedState
from emucard.profile import CCID_MESSAGE_LENGTH
from fido2.ctap2 import ClientPin, PinProtocolV2
from yubikit.core import TRANSPORT, Tlv
from yubikit.core.smartcard import SmartCardProtocol
from yubikit.management import CAPABILITY, DeviceConfig, ManagementSession
from yubikit.oath import CredentialData, OathSession
from yubikit.piv import DEFAULT_MANAGEMENT_KEY, KEY_TYPE, OBJECT_ID, SLOT, PivSession
from yubikit.core.smartcard import ApduError
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec

check, wait, worker = shared.check, shared.wait, native_io.worker
runtime.check=check
queued_runtime.check=check
checks = shared.checks


def observed_bulk_read(device, request, timeout=1800):
    """Actual owned libusb read, retaining actual_length even on a timeout/error."""
    buffer = (ctypes.c_ubyte * request)()
    count = ctypes.c_int()
    result = device._ctx.backend.lib.libusb_bulk_transfer(
        device._ctx.handle.handle, 0x82, buffer, request, ctypes.byref(count), timeout)
    assert 0 <= count.value <= request
    data = bytes(buffer[:count.value])
    return {'libusb_result': result, 'actual_length': count.value,
            'requested_length': request, 'data_hex': data.hex(),
            'data_sha256': hashlib.sha256(data).hexdigest()}, data


def main():
    f = tmp = d = trace = extra_fd = None
    report = {'passed': False, 'tests': checks, 'cycles': [], 'assertions': [],
              'scope': 'actual current-source original large CCID AIO prefix64 then USB runtime suspend/resume',
              'physical_device_access': False, 'host_device_passthrough': False,
              'host_hid_drivers_unbound': False, 'native_macos_registration_verified': False,
              'production_udc_verified': False, 'physical_touch_verified': False,
              'manufacturer_trust_reproduced': False, 'card_testing_auto_allow': False,
              'fido_testing_auto_allow_only_for_owned_fixture': True,
              'stock_libccid_transport_used_for_this_fixture': False,
              'stock_piv_oath_sdk_unmodified': True, 'opaque_piv_object_is_valid_chuid': False,
              'current_release_transport_verification': True,
              'source_transport_changed_for_this_test': False,
              'all_boundary_resume_mode_combinations_verified': True,
              'complete_original_chained_APDU_across_runtime_reset_verified': False,
              'chained_response_after_runtime_reset_inactive_denied': True,
              'raw_io_event_completion_res_payload_recorded': False,
              'full_platform_sleep_verified': False,
              'same_generation_continuation_verified': False}
    try:
        check(Path('/opt/isolated-ske-usb-guest').exists() and platform.release() == '6.8.0-146-generic'
              and platform.machine() == 'aarch64' and [p.name for p in Path('/sys/class/net').iterdir()] == ['lo'],
              'actual private ARM64 kernel USB guest with only loopback')
        trace=Path('/sys/kernel/tracing');runtime.ensure_mount('tracefs',trace)
        selected=['autosuspend_check','usb_runtime_idle','usb_runtime_suspend','usb_runtime_resume']
        symbols=Path('/proc/kallsyms').read_text().splitlines()
        available=[name for name in selected if any(line.split()[-1]==name for line in symbols if line.split())]
        check(available==selected,'original40 runtime kernel callback probe symbols available')
        report['kernel_probe_symbols']=available
        for name in available:
            descriptor=os.open(trace/'kprobe_events',os.O_WRONLY|os.O_APPEND)
            try:os.write(descriptor,('r:ske_large_partial_runtime/'+name+' '+name+' result=$retval:s64\n').encode())
            finally:os.close(descriptor)
            (trace/'events/ske_large_partial_runtime'/name/'enable').write_text('1\n')
        (trace/'events/power/enable').write_text('0\n')
        (trace/'events/rpm/enable').write_text('1\n')
        for name in ['device_pm_callback_start','device_pm_callback_end']:
            (trace/'events/power'/name/'enable').write_text('1\n')
        tmp = Path(tempfile.mkdtemp(prefix='own-large-partial-runtime-', dir='/guest-state'))
        os.environ['SKE_TRACE_USB'] = '1'
        f = base.CompositeFixture(Path('/opt/swpasskeyd'), tmp)
        f.card = pending.PromptCardFixture(Path('/opt'), tmp / 'card', startup_timeout=30)
        ct = f.start()
        report['service_pids'] = [f.bridge.pid, f.process.pid, f.card.process.pid]
        report['controller'] = f.controller
        protocol = PinProtocolV2()
        ClientPin(ct, protocol).set_pin(state.PIN)
        token = ClientPin(ct, protocol).get_pin_token(state.PIN, ClientPin.PERMISSION.MAKE_CREDENTIAL, state.RP)
        response = ct.make_credential(hashlib.sha256(b'own partial interruption registration').digest(),
            {'id': state.RP}, {'id': state.USER, 'name': 'own-partial-interrupt'},
            [{'type': 'public-key', 'alg': -7}], options={'rk': True}, pin_uv_protocol=2,
            pin_uv_param=protocol.authenticate(token, hashlib.sha256(b'own partial interruption registration').digest()))
        credential = response.auth_data.credential_data
        check(response.auth_data.flags & 5 == 5, 'original native resident key created with PIN UVp2')
        state.close_hid(f)
        shared.prove_fido(f, credential, 'initial', report)
        initial = state.reboot.snapshot(f.serial)
        report['original_identity'] = initial
        with state.reboot.connection('FIDO', f.serial) as conn:
            ManagementSession(conn).write_device_config(DeviceConfig({TRANSPORT.USB: CAPABILITY(0x33a)}), reboot=True)
        identity = wait(lambda: (lambda value: value if value and value['pid'] == 0x406 and value['address'] != initial['address'] else None)
                        (state.reboot.snapshot(f.serial)), 'initial native profile6', 8)
        report['profile6_identity'] = identity
        reference = json.loads(Path('/opt/usb-reference-observation.json').read_text())
        check(identity['host_visible_configuration_descriptor_hex'] == reference['configuration_descriptor_hex'],
              'initial native profile6 byte equal saved reference configuration')
        backend = usb.backend.libusb1.get_backend(find_library=lambda name: '/usr/lib/aarch64-linux-gnu/libusb-1.0.so.0')

        def owned_device():
            matches = list(usb.core.find(find_all=True, idVendor=0x1050, idProduct=0x406, backend=backend))
            owned = [candidate for candidate in matches if candidate.address == identity['address']
                     and candidate.serial_number == f.serial]
            assert len(owned) < 2
            return owned[0] if owned else None

        d = wait(owned_device, 'exact owned profile6 address and serial', 4)
        connection = long.NativeLongCcid(d)
        devicepath=Path(identity['path']);power=devicepath/'power'
        check('dummy_hcd' in str(devicepath),'only original owned dummy USB runtime path')
        node=Path('/dev/bus/usb')/f'{d.bus:03d}/{d.address:03d}'
        usbfs_fd=queued_runtime.own_borrowed_fd(node)
        report['borrowed_usbfs_node']=str(node);report['borrowed_usbfs_fd']=usbfs_fd
        capabilities=array.array('I',[0]);fcntl.ioctl(usbfs_fd,0x8004551a,capabilities,True)
        report['usbfs_capabilities']=capabilities[0]
        check(bool(capabilities[0]&0x100),'original owned usbfs supports actual runtime suspend')

        piv=PivSession(connection);piv.authenticate(DEFAULT_MANAGEMENT_KEY)
        original_piv_key=piv.generate_key(SLOT.AUTHENTICATION,KEY_TYPE.ECCP256)
        original_piv_der=original_piv_key.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        report['original_piv_public_key_spki_hex']=original_piv_der.hex()
        report['original_piv_public_key_sha256']=hashlib.sha256(original_piv_der).hexdigest()
        piv.verify_pin('123456')
        initial_piv_digest=hashlib.sha256(b'own large-runtime initial original PIV key').digest()
        initial_piv_signature=piv.sign(SLOT.AUTHENTICATION,KEY_TYPE.ECCP256,initial_piv_digest,hashes.SHA256())
        original_piv_key.verify(initial_piv_signature,initial_piv_digest,ec.ECDSA(hashes.SHA256()))
        report['piv_signatures']=[{'phase':'initial','digest_hex':initial_piv_digest.hex(),'signature_hex':initial_piv_signature.hex(),
                                   'original_key_signature_verified':True}]
        check(True,'independent original native PIV key signature before all runtime cycles')

        oath = OathSession(connection)
        own = oath.put_credential(CredentialData.parse_uri('otpauth://hotp/PartialInterrupt:owned?secret=JBSWY3DPEHPK3PXP&counter=0'))
        counter = lambda: EncryptedState(f.directory / 'card/state.bin').data['oath']['credentials'][own.id.hex()]['counter']

        def durable():
            data = copy.deepcopy(EncryptedState(f.directory / 'card/state.bin').data)
            data.pop('management', None)
            data['otp'].pop('sequence', None)
            return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

        check(counter() == 0, 'original owned HOTP counter zero')
        check(bytes(d.read(0x83, 8, timeout=1500)) == b'\x50\x03', 'initial actual occupied slot notification')
        trace = Path('/sys/kernel/tracing')
        runtime.ensure_mount('tracefs', trace)
        (trace / 'buffer_size_kb').write_text('2048\n')
        syscall_events = ['sys_enter_write', 'sys_exit_write', 'sys_enter_io_submit', 'sys_exit_io_submit',
                          'sys_enter_io_getevents', 'sys_exit_io_getevents']
        events = [trace / 'events/syscalls' / name for name in syscall_events] + [trace / 'events/signal/signal_deliver']
        report['trace_formats'] = {event.name: (event / 'format').read_text() for event in events}

        def arm():
            tids = [int(p.name) for p in (Path('/proc') / str(f.bridge.pid) / 'task').iterdir()]
            own_filter = ' || '.join('common_pid == ' + str(tid) for tid in tids)
            for event in events:
                (event / 'filter').write_text(own_filter + '\n')
                (event / 'enable').write_text('1\n')
            (trace / 'trace').write_text('')
            (trace / 'tracing_on').write_text('1\n')

        matrix=[(size,mode) for size in [2047,2048,2049,3071,3072,3073] for mode in ['manual-on','native-fido-sdk','new-usbfs-open']]
        report['runtime_mode_matrix']=[{'total_response_bytes':size,'mode':mode} for size,mode in matrix]
        for index,(total_size,mode) in enumerate(matrix):
            label = str(total_size) + '-partial64-runtime-'+mode
            row = {'index': index, 'phase': label, 'total_response_bytes': total_size,
                   'before_usb': state.reboot.snapshot(f.serial),'runtime_mode':mode}
            report['active_cycle'] = row
            opaque = bytes((offset * 17 + total_size) & 255 for offset in range(total_size - 16))
            response_data = bytes(Tlv(0x53, opaque)) + b'\x90\x00'
            check(len(response_data) + 10 == total_size, 'actual encoded TLV APDU CCID boundary ' + label)
            piv = PivSession(connection)
            if total_size >= 3071:
                piv.protocol = SmartCardProtocol(connection)
                piv.protocol.configure(piv.version, force_short=True)
            piv.authenticate(DEFAULT_MANAGEMENT_KEY)
            piv.verify_pin('123456')
            piv.put_object(OBJECT_ID.CHUID, opaque)
            check(piv.get_object(OBJECT_ID.CHUID) == opaque, 'native stock PIV SDK original object before interruption ' + label)
            saved = durable()
            arm()
            body = Tlv(0x5c, int(OBJECT_ID.CHUID).to_bytes(3, 'big'))
            sequence = connection.write(0x6f, bytes([0, 0xcb, 0x3f, 0xff, len(body)]) + body)
            packet_size = min(total_size, CCID_MESSAGE_LENGTH)
            expected = struct.pack('<BIBBBBB', 0x80, packet_size - 10, 0, sequence, 0, 0,
                                   1 if total_size > CCID_MESSAGE_LENGTH else 0) + response_data[:packet_size - 10]
            target = wait(lambda: worker(f.bridge.pid, packet_size), 'original full large write blocked ' + label, 3)
            entry = native_io.original_entry((trace / 'trace').read_text(), target)
            check(bool(entry), 'trace armed before original large write entry ' + label)
            row.update(original_worker=target, original_sequence=sequence, original_packet_bytes=packet_size,
                       original_write_entry=entry, expected_original_packet_sha256=hashlib.sha256(expected).hexdigest(),
                       opaque_object_sha256=hashlib.sha256(opaque).hexdigest(), durable_plaintext_sha256=saved)
            prefix = bytes(d.read(0x82, 64, timeout=1500))
            row['original_prefix_hex'] = prefix.hex()
            row['worker_after_prefix64'] = worker(f.bridge.pid, packet_size)
            check(prefix == expected[:64], 'actual original prefix64 header sequence and object bytes ' + label)
            check(row['worker_after_prefix64'] == target, 'same original write TID FD buffer after prefix64 ' + label)
            check(durable() == saved and counter() == index, 'prefix64 GET has no durable or HOTP mutation ' + label)
            row['runtime_before']=runtime.snapshot(devicepath)
            (power/'autosuspend_delay_ms').write_text('0\n');(power/'control').write_text('auto\n')
            row['allow_suspend_return']=fcntl.ioctl(usbfs_fd,0x5522)
            row['runtime_suspended']=runtime.wait_status(power,'suspended')
            time.sleep(.2)
            row['runtime_still_suspended']=runtime.status(power)
            row['worker_while_suspended']=worker(f.bridge.pid,packet_size) if f.bridge.poll() is None else None
            row['service_status_while_suspended']={name:process.poll() for name,process in [('bridge',f.bridge),('fido',f.process),('card',f.card.process)]}
            row['plaintext_while_suspended_sha256']=durable()
            row['counter_while_suspended']=counter()
            replies=[]
            def resume_waiter():
                try:replies.append(fcntl.ioctl(usbfs_fd,0x5523))
                except Exception as exc:replies.append(f'{type(exc).__name__}: {exc}')
            waiter=threading.Thread(target=resume_waiter,daemon=True);waiter.start()
            if mode=='manual-on':(power/'control').write_text('on\n')
            elif mode=='native-fido-sdk':state.fresh_hid(f)
            elif mode=='new-usbfs-open':extra_fd=os.open(node,os.O_RDWR|os.O_CLOEXEC)
            else:raise AssertionError(mode)
            waiter.join(3)
            row['wait_for_resume_returns']=replies
            row['wait_for_resume_thread_alive']=waiter.is_alive()
            row['runtime_resumed']=runtime.wait_status(power,'active')
            (power/'control').write_text('on\n')
            row['runtime_trace_before_tail']=(trace/'trace').read_text()
            row['bridge_status_before_tail']=f.bridge.poll()
            row['worker_after_resume']=worker(f.bridge.pid,packet_size) if f.bridge.poll() is None else None
            if extra_fd is not None:
                os.close(extra_fd);extra_fd=None
            state.close_hid(f)
            row['native_tail_read'], tail = observed_bulk_read(d, packet_size)
            row['actual_whole_data_hex'] = (prefix + tail).hex()
            row['actual_whole_data_sha256'] = hashlib.sha256(prefix + tail).hexdigest()
            row['after_native_tail_usb'] = state.reboot.snapshot(f.serial)
            row['service_status_after_tail'] = {name: process.poll() for name, process in [('bridge', f.bridge), ('fido', f.process), ('card', f.card.process)]}
            row['actual_trace_after_tail'] = (trace / 'trace').read_text()
            row['usb_log_after_tail'] = (f.directory / 'usb.log').read_text(errors='replace')[-12000:]
            row['exact_native_original_tail_verified']=row['native_tail_read']['libusb_result']==0 and tail==expected[64:]
            row['repeated_original_header_observed']=tail.startswith(prefix[:10])
            check(row['runtime_still_suspended']['runtime_status']=='suspended' and row['runtime_still_suspended']['runtime_usage']=='0',
                  'actual original large request suspended with zero usage '+label)
            check(int(row['runtime_still_suspended']['runtime_suspended_time'])>int(row['runtime_before']['device']['runtime_suspended_time']),
                  'actual original kernel runtime suspended time increases '+label)
            check(replies==[0] and not waiter.is_alive(),'actual borrowed usbfs WAIT_FOR_RESUME returns zero '+label)
            check(runtime.trace_return(row['runtime_trace_before_tail'],'suspend',0) and runtime.trace_return(row['runtime_trace_before_tail'],'resume',0),
                  'actual original owned USB suspend and resume return zero '+label)
            check('usb_runtime_suspend:' in row['runtime_trace_before_tail'] and 'usb_runtime_resume:' in row['runtime_trace_before_tail'],
                  'actual original native USB runtime callbacks recorded '+label)
            check(row['plaintext_while_suspended_sha256']==saved and row['counter_while_suspended']==index,
                  'actual original durable state and HOTP unchanged while suspended '+label)
            check(all(v is None for v in row['service_status_while_suspended'].values()),'original three services alive while suspended '+label)
            check(row['native_tail_read']['libusb_result'] == 0 and tail == expected[64:],
                  'same-generation runtime native tail exactly original remaining bytes without repeated prefix ' + label)
            check(all(value is None for value in row['service_status_after_tail'].values()), 'same three original services alive after partial interruption ' + label)
            check(row['after_native_tail_usb'] == row['before_usb'], 'same native USB generation and descriptors after partial interruption ' + label)
            if total_size>CCID_MESSAGE_LENGTH:
                continuation_sequence=connection.write(0x6f,level=0x10)
                header,continuation=connection.read(continuation_sequence)
                row['post_resume_chain_header']=list(header);row['post_resume_chain_payload_hex']=continuation.hex()
                row['post_resume_original_chain_complete']=header[6]==2 and prefix[10:]+tail+continuation==response_data
                row['post_resume_original_chain_inactive_denied']=header[4]==0x41 and header[5]==0xfe and not continuation
                check(row['post_resume_original_chain_complete'] or row['post_resume_original_chain_inactive_denied'],
                      'post-resume actual original chain either complete or explicitly inactive after poweroff '+label)
            else:
                check(prefix[10:]+tail==response_data,'actual original APDU exact reconstruction after runtime '+label)
            row['resume_notification_hex']=bytes(d.read(0x83,8,timeout=1500)).hex()
            check(row['resume_notification_hex']=='5003','actual one occupied insertion notification after runtime '+label)
            inactive,empty=connection.exchange(0x65)
            row['inactive_header']=list(inactive)
            check(inactive[0]==0x81 and inactive[4]==1 and inactive[5]==0 and inactive[6]==3 and not empty,
                  'actual native CCID inactive occupied slot after runtime '+label)
            powered,atr=connection.exchange(0x62);row['poweron_header']=list(powered);row['atr_hex']=atr.hex()
            check(powered[0]==0x80 and powered[4]==0 and powered[5]==0 and atr==bytes.fromhex('3bf011000001e0'),
                  'actual explicit PowerOn before new native SDK sequence '+label)
            piv=PivSession(connection)
            if total_size>=3071:
                piv.protocol=SmartCardProtocol(connection);piv.protocol.configure(piv.version,force_short=True)
            post_piv_digest=hashlib.sha256(('own original PIV post large-runtime '+label).encode()).digest()
            try:piv.sign(SLOT.AUTHENTICATION,KEY_TYPE.ECCP256,post_piv_digest,hashes.SHA256())
            except ApduError as exc:row['unauthorized_post_resume_sign_sw']=exc.sw
            else:raise AssertionError('original runtime PIN authorization was not revoked '+label)
            check(row['unauthorized_post_resume_sign_sw']==0x6982,'actual original PIV PIN authorization revoked by runtime '+label)
            try:piv.put_object(OBJECT_ID.CHUID,opaque)
            except ApduError as exc:row['unauthorized_post_resume_put_sw']=exc.sw
            else:raise AssertionError('original runtime management authorization was not revoked '+label)
            check(row['unauthorized_post_resume_put_sw']==0x6982,'actual original PIV management authorization revoked by runtime '+label)
            check(durable()==saved and counter()==index,'denied native post-resume authorization leaves card state unchanged '+label)
            piv.verify_pin('123456')
            post_piv_signature=piv.sign(SLOT.AUTHENTICATION,KEY_TYPE.ECCP256,post_piv_digest,hashes.SHA256())
            original_piv_key.verify(post_piv_signature,post_piv_digest,ec.ECDSA(hashes.SHA256()))
            report['piv_signatures'].append({'phase':label,'digest_hex':post_piv_digest.hex(),'signature_hex':post_piv_signature.hex(),
                                           'original_key_signature_verified':True})
            row['fresh_piv_pin_original_key_signature_verified']=True
            check(True,'independent original PIV key signature only after fresh PIN '+label)
            check(durable() == saved and counter() == index, 'interrupted GET preserves card plaintext and HOTP ' + label)
            check(piv.get_object(OBJECT_ID.CHUID) == opaque, 'following stock PIV SDK GET has no stale original tail or ZLP ' + label)
            oath = OathSession(connection)
            value = oath.calculate_code(own).value
            digest = hmac.new(base64.b32decode('JBSWY3DPEHPK3PXP'), index.to_bytes(8, 'big'), 'sha1').digest()
            offset = digest[-1] & 15
            expected_hotp = str((int.from_bytes(digest[offset:offset + 4], 'big') & 0x7fffffff) % 1000000).zfill(6)
            check(value == expected_hotp and counter() == index + 1, 'independent following native HOTP result and one commit ' + label)
            shared.prove_fido(f, credential, label, report)
            row['same_generation_exact_continuation_verified'] = True
            report['cycles'].append(row)
            report.pop('active_cycle')
        report['same_generation_continuation_verified'] = True
        report['final_hotp_counter'] = counter()
        report['passed'] = True
    except Exception as exc:
        report.update(error=f'{type(exc).__name__}: {exc}', traceback=traceback.format_exc())
        if trace and (trace / 'trace').exists():
            report['last_actual_trace'] = (trace / 'trace').read_text()[-24000:]
    finally:
        if trace:
            for event in ['events/syscalls/' + name for name in ['sys_enter_write', 'sys_exit_write', 'sys_enter_io_submit', 'sys_exit_io_submit', 'sys_enter_io_getevents', 'sys_exit_io_getevents']] + ['events/signal/signal_deliver']:
                if (trace / event / 'enable').exists():
                    (trace / event / 'enable').write_text('0\n')
            if (trace / 'tracing_on').exists():
                (trace / 'tracing_on').write_text('0\n')
        if trace:
            for name in ['autosuspend_check','usb_runtime_idle','usb_runtime_suspend','usb_runtime_resume']:
                event=trace/'events/ske_large_partial_runtime'/name/'enable'
                if event.exists():event.write_text('0\n')
            for group in ['rpm','power']:
                event=trace/'events'/group/'enable'
                if event.exists():event.write_text('0\n')
        if extra_fd is not None:
            os.close(extra_fd);extra_fd=None
        if d is not None:
            usb.util.dispose_resources(d)
        if f:
            for name in ['usb.log', 'daemon.log', 'card/log.txt']:
                p = f.directory / name
                if p.exists():
                    report[name] = p.read_text(errors='replace')[-18000:]
            try:
                f.stop()
            except Exception as exc:
                report.update(passed=False, cleanup_error=str(exc))
        if tmp and tmp.exists():
            shutil.rmtree(tmp)
        report['test_count'] = len(checks)
        for name, key in [('swpasskeyd', 'emulator_binary_sha256'), ('ske-usbd', 'usb_bridge_binary_sha256')]:
            report[key] = hashlib.sha256(Path('/opt', name).read_bytes()).hexdigest()
        report['card_service_sha256'] = hashlib.sha256(Path('/opt/emucard/service.py').read_bytes()).hexdigest()
        report['helper_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        report['shared_helper_sha256'] = hashlib.sha256(Path(shared.__file__).read_bytes()).hexdigest()
        report['long_cutover_helper_sha256'] = hashlib.sha256(Path(long.__file__).read_bytes()).hexdigest()
        report['native_io_observer_sha256'] = hashlib.sha256(Path(native_io.__file__).read_bytes()).hexdigest()
        report['queued_runtime_helper_sha256']=hashlib.sha256(Path(queued_runtime.__file__).read_bytes()).hexdigest()
        report['native_io_observer_attempts'] = native_io.observations
        print('SKE_USB_LARGE_PARTIAL_RUNTIME_BEGIN\n' + json.dumps(report) + '\nSKE_USB_LARGE_PARTIAL_RUNTIME_END', flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
