"""Real terminal presence cancellation through owned native USB CCID."""
import base64
import hashlib
import hmac
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from yubikit.core import TRANSPORT
from yubikit.core.smartcard import SmartCardConnection
from yubikit.oath import CredentialData,OathSession
import verify_composite as base
from emucard.core import EncryptedState


class PromptCardFixture(base.verify_smartcard.Fixture):
    def start(self):
        self.log=(self.directory/'log.txt').open('ab')
        # Existing service implementation and actual stdin prompt, no --testing.
        self.process=subprocess.Popen([sys.executable,'-m','emucard.service',
            '--state',str(self.directory/'state.bin'),'--socket',str(self.directory/'s.sock')],
            cwd=self.root,stdin=subprocess.PIPE,stdout=self.log,stderr=self.log,text=True)
        deadline=time.monotonic()+30
        while time.monotonic()<deadline:
            if self.process.poll() is not None:raise RuntimeError((self.directory/'log.txt').read_text())
            if (self.directory/'s.sock').exists():
                try:ready=base.verify_smartcard.CcidSocketConnection(self.directory/'s.sock')
                except ConnectionRefusedError:pass
                else:ready.close();break
            time.sleep(.03)
        else:raise AssertionError('own prompt card startup')
        self.connection=base.verify_smartcard.CcidSocketConnection(self.directory/'s.sock')
        return self.connection
    def stop(self):
        process=self.process
        try:super().stop()
        finally:
            if process and process.stdin:process.stdin.close()


class NativeCcid(SmartCardConnection):
    def __init__(self,device):
        self.device=device;self.sequence=0
        header,atr=self.exchange(0x62)
        assert header[0]==0x80 and header[4]&0xc0==0 and atr==bytes.fromhex('3bf011000001e0')
    @property
    def transport(self):return TRANSPORT.USB
    def write(self,kind,payload=b''):
        self.sequence=(self.sequence+1)&255
        packet=struct.pack('<BIBBBBB',kind,len(payload),0,self.sequence,0,0,0)+payload
        assert self.device.write(2,packet,timeout=1000)==len(packet)
        return self.sequence
    def read(self,sequence):
        packet=bytes(self.device.read(0x82,3072,timeout=1500))
        assert len(packet)>=10
        header=struct.unpack('<BIBBBBB',packet[:10])
        assert header[1]==len(packet)-10 and header[2]==0 and header[3]==sequence,(header,sequence)
        return header,packet[10:]
    def exchange(self,kind,payload=b''):
        sequence=self.write(kind,payload)
        while True:
            header,data=self.read(sequence)
            if header[4]&0xc0==0x80:continue
            assert header[4]&0xc0==0 and header[5]==0,(header,data.hex())
            return header,data
    def send_and_receive(self,apdu):
        header,data=self.exchange(0x6f,apdu)
        assert header[0]==0x80 and len(data)>=2
        return data[:-2],int.from_bytes(data[-2:],'big')
    def close(self):pass


def run(f,report,check,own_usb,alive,hashes,fresh_hid,close_hid,pids):
    d,before=own_usb(f.serial)
    connection=NativeCcid(d)
    oath=OathSession(connection)
    credential=oath.put_credential(CredentialData.parse_uri(
        'otpauth://hotp/USBCancel:owned?secret=JBSWY3DPEHPK3PXP&counter=0'),touch_required=True)
    check(connection.transport==TRANSPORT.USB,'unmodified OATH SDK provisions touch credential over actual USB CCID')
    count=lambda:EncryptedState(f.directory/'card/state.bin').data['oath']['credentials'][credential.id.hex()]['counter']
    check(count()==0,'fresh own HOTP counter zero before pending USB request')
    from yubikit.core import Tlv
    payload=Tlv(0x71,credential.id)+Tlv(0x74,bytes(8))
    apdu=bytes([0,0xa2,0,1,len(payload)])+payload
    previous=(f.directory/'card/log.txt').read_text().count('approve user presence')
    saved=hashes(f)
    sequence=connection.write(0x6f,apdu)
    deadline=time.monotonic()+5
    while time.monotonic()<deadline:
        if (f.directory/'card/log.txt').read_text().count('approve user presence')>previous:break
        time.sleep(.03)
    else:raise AssertionError('real stdin prompt was not reached by native USB CCID request')
    check(count()==0 and hashes(f)==saved,'pending real terminal presence has not committed HOTP counter')
    header,data=connection.read(sequence)
    check(header[0]==0x80 and header[4]&0xc0==0x80 and not data,
          'actual USB CCID emits time-extension response while terminal presence is pending')
    ct=fresh_hid(f)
    check('FIDO_2_1' in ct.get_info().versions,
          'unmodified native FIDO SDK GetInfo completes during CCID terminal presence wait')
    message=b'own USB CCID pending'
    check(f.device.ping(message)==message,'actual native FIDO PING completes during CCID presence wait')
    close_hid(f)
    d.reset()
    alive(f,pids,'after USB reset with pending CCID presence')
    check(hashes(f)==saved and count()==0,'actual USB reset cancels pending HOTP without persistent mutation')
    # A fresh sequence must never receive a response from the old USB generation.
    connection=NativeCcid(d)
    oath=OathSession(connection)
    check(oath.list_credentials()[0].id==credential.id,'native CCID OATH SDK recovers after reset without stale response')
    previous=(f.directory/'card/log.txt').read_text().count('approve user presence')
    with ThreadPoolExecutor(max_workers=1) as executor:
        future=executor.submit(oath.calculate_code,credential)
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            if (f.directory/'card/log.txt').read_text().count('approve user presence')>previous:break
            time.sleep(.03)
        else:raise AssertionError('new post-reset native SDK request did not ask for actual presence')
        check(not future.done() and count()==0,'new native SDK request waits for fresh terminal approval')
        f.card.process.stdin.write('y\n');f.card.process.stdin.flush()
        code=future.result(3).value
    digest=hmac.new(base64.b32decode('JBSWY3DPEHPK3PXP'),bytes(8),'sha1').digest()
    offset=digest[-1]&15
    expected=str((int.from_bytes(digest[offset:offset+4],'big')&0x7fffffff)%1000000).zfill(6)
    check(code==expected and count()==1,'terminal-approved native OATH SDK result matches independent HOTP counter zero and commits once')
    report['pending_ccid']={'native_terminal_presence_wait_observed':True,'native_time_extension_observed':True,
        'native_fido_sdk_getinfo_during_wait_verified':True,
        'native_fido_ping_during_wait_verified':True,'reset_cancels_without_counter_mutation':True,
        'new_sequence_sdk_recovery_without_stale_response_verified':True,
        'fresh_terminal_approval_and_independent_hotp_verified':True,'counter_before':0,'counter_after':1,
        'before':before,'after':own_usb(f.serial)[1],'same_three_services':True,
        'physical_touch_verified':False,'card_testing_auto_allow':False,'cancelled_sequence':sequence}
    import usb.util
    usb.util.dispose_resources(d)
