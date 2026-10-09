#!/usr/bin/env python3
"""Stock Chromium USB largeBlob validation with actual accessibility UI.

Only own fresh emulator state and an exact own localhost RP are used. CDP
invokes the page API and never enables a virtual authenticator. X/AT-SPI
operate exclusively inside the network-isolated guest.
"""
import base64
import hashlib
import importlib.util
import json
import os
import platform
import re
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path[:0] = ['/opt/verification', '/opt', '/usr/lib/python3/dist-packages']
spec = importlib.util.spec_from_file_location('resident', '/opt/verification/verify-browser-resident.py')
resident = importlib.util.module_from_spec(spec)
spec.loader.exec_module(resident)
base = resident.base
from fido2.ctap2 import Ctap2
from fido2.ctap2.blob import LargeBlobs
from fido2.ctap2.pin import ClientPin, PinProtocolV2
from fido2.webauthn import AuthenticatorData, PublicKeyCredentialRpEntity
import pyatspi
from gi.repository import Gio, GLib

BROWSER_ROOT = Path('/opt/chromium-root')
PAYLOAD = b'own-browser-largeBlob\x00\xff' + bytes(range(256)) * 3
SDK_PAYLOAD = b'own-independent-sdk-largeBlob\x00\xfe' + bytes(range(255, -1, -1)) * 4


class CDP:
    def __init__(self, url):
        import urllib.parse
        u = urllib.parse.urlparse(url)
        assert u.scheme == 'ws' and u.hostname in ['localhost', '127.0.0.1']
        self.sock = socket.create_connection((u.hostname, u.port), timeout=30)
        self.sock.settimeout(90)
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall((f'GET {u.path} HTTP/1.1\r\nHost: {u.hostname}:{u.port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n').encode())
        headers = b''
        while not headers.endswith(b'\r\n\r\n'):
            headers += self.sock.recv(1)
            assert len(headers) < 65536
        assert headers.startswith(b'HTTP/1.1 101'), headers
        accept = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
        assert f'Sec-WebSocket-Accept: {accept}'.lower() in headers.decode().lower()
        self.seq, self.commands = 0, []

    def exact(self, n):
        result = b''
        while len(result) < n:
            value = self.sock.recv(n - len(result))
            if not value:
                raise EOFError('CDP socket closed')
            result += value
        return result

    def send(self, payload, opcode=1):
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        n = len(data)
        header = bytes([0x80 | opcode, 0x80 | (n if n < 126 else 126 if n <= 65535 else 127)])
        if n >= 126:
            header += struct.pack('>H' if n <= 65535 else '>Q', n)
        mask = os.urandom(4)
        self.sock.sendall(header + mask + bytes(x ^ mask[i % 4] for i, x in enumerate(data)))

    def receive(self):
        first, second = self.exact(2)
        assert first & 0x80 and not second & 0x80
        n = second & 127
        if n == 126:
            n = struct.unpack('>H', self.exact(2))[0]
        elif n == 127:
            n = struct.unpack('>Q', self.exact(8))[0]
        assert n < 8 * 1024 * 1024
        data = self.exact(n)
        if first & 15 == 9:
            self.send(data, 10)
            return self.receive()
        assert first & 15 == 1, first
        return json.loads(data)

    def call(self, method, params=None):
        assert method in ['Browser.getVersion', 'Page.navigate', 'Runtime.evaluate'], method
        self.seq += 1
        self.commands.append(method)
        self.send({'id': self.seq, 'method': method, 'params': params or {}})
        while True:
            value = self.receive()
            if value.get('id') == self.seq:
                assert 'error' not in value, value
                return value['result']

    def evaluate(self, expression):
        result = self.call('Runtime.evaluate', {'expression': expression, 'returnByValue': True})
        assert 'exceptionDetails' not in result, result
        return result['result'].get('value')


checks = []

def check(value, name):
    assert value, name
    checks.append({'name': name, 'passed': True})
    print('PASS', name, flush=True)


class BlobRP(resident.ResidentRP):
    def do_POST(self):
        if self.path == '/browser-error':
            size = int(self.headers['Content-Length'])
            assert 0 < size < 4096
            value = json.loads(self.rfile.read(size))
            assert isinstance(value['error'], str) and isinstance(value['message'], str)
            self.server.browser_errors.append(value)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"recorded":true}')
            return
        return super().do_POST()

    def do_GET(self):
        s = self.server
        row = s.current_account
        if self.path == '/register':
            options, s.registration = s.rp.register_begin(
                {'id': row['user_id'], 'name': row['name'], 'displayName': row['name']},
                resident_key_requirement='required', user_verification='required',
                authenticator_attachment='cross-platform',
            )
            options = dict(options)
            options['publicKey']['extensions'] = {'largeBlob': {'support': 'required'}, 'credProps': True}
            if getattr(s, 'negative_request', False):
                options['publicKey']['timeout'] = 15000
            s.creation_options = options
        elif self.path == '/login':
            options, s.authentication = s.rp.authenticate_begin(
                [s.records[s.current]['credential']], user_verification='required',
            )
            options = dict(options)
            options['publicKey']['extensions'] = {
                'largeBlob': {'write': base.websafe_encode(s.current_account['browser_payload'])} if s.blob_mode == 'write' else {'read': True}
            }
            s.request_options = options
        else:
            return super().do_GET()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(options).encode())


def nodes():
    context = GLib.MainContext.default()
    for _ in range(64):
        if not context.pending():
            break
        context.iteration(False)
    desktop = pyatspi.Registry.getDesktop(0)
    result = []
    def walk(node, depth=0):
        if depth > 12 or len(result) >= 800:
            return
        try:
            role, name = node.getRoleName(), node.name or ''
            result.append((node, role, name))
            for child in node:
                if child:
                    walk(child, depth + 1)
        except Exception:
            return
    for app in desktop:
        if app and 'chrom' in (app.name or '').lower():
            walk(app)
    return result



def observe_pin_input(report, state, node, phase, editable_error=None):
    t=node.queryText()
    value={'phase':state['phase'],'mode':state['mode'],'account':state['account'],
           'input_stage':phase,'actual_character_count':t.characterCount,
           'focused':node.getState().contains(pyatspi.STATE_FOCUSED),
           'selection_count':t.getNSelections(),'editable_error':editable_error,
           'monotonic_time':time.monotonic()}
    if value['selection_count']:
        value['first_selection']=t.getSelection(0)
    report.setdefault('actual_pin_input_detail',[]).append(value)
    print('CHROMIUM_OWN_PIN_INPUT_DETAIL',json.dumps(value),flush=True)


class OwnDisplayRepeatGuard:
    """Set and restore only private guest Xvfb global repeat around real key events."""
    def __init__(self, report, state):
        import ctypes
        assert Path('/opt/isolated-ske-usb-guest').exists() and os.environ.get('DISPLAY') == ':99'
        class KeyboardState(ctypes.Structure):
            _fields_=[('key_click_percent',ctypes.c_int),('bell_percent',ctypes.c_int),
                      ('bell_pitch',ctypes.c_uint),('bell_duration',ctypes.c_uint),
                      ('led_mask',ctypes.c_ulong),('global_auto_repeat',ctypes.c_int),
                      ('auto_repeats',ctypes.c_ubyte*32)]
        self.ctypes,self.KeyboardState=ctypes,KeyboardState
        self.x=ctypes.CDLL('libX11.so.6')
        self.x.XOpenDisplay.argtypes=[ctypes.c_char_p];self.x.XOpenDisplay.restype=ctypes.c_void_p
        self.x.XGetKeyboardControl.argtypes=[ctypes.c_void_p,ctypes.POINTER(KeyboardState)]
        for name in ['XAutoRepeatOff','XAutoRepeatOn','XCloseDisplay']:
            getattr(self.x,name).argtypes=[ctypes.c_void_p]
        self.x.XSync.argtypes=[ctypes.c_void_p,ctypes.c_int]
        self.display=self.x.XOpenDisplay(b':99');assert self.display
        self.record={'phase':state['phase'],'mode':state['mode'],'account':state['account'],
                     'display':':99','scope':'owned private guest Xvfb only',
                     'real_x_key_events_used':True,'browser_or_authenticator_callbacks_replaced':False,
                     'before':self.read()}
        assert self.record['before']['global_auto_repeat'] in [0,1]
        self.report=report
    def read(self):
        value=self.KeyboardState();self.x.XGetKeyboardControl(self.display,self.ctypes.byref(value))
        return {'global_auto_repeat':value.global_auto_repeat,'auto_repeats_hex':bytes(value.auto_repeats).hex(),
                'key_click_percent':value.key_click_percent,'bell_percent':value.bell_percent,
                'bell_pitch':value.bell_pitch,'bell_duration':value.bell_duration,'led_mask':value.led_mask}
    def __enter__(self):
        self.x.XAutoRepeatOff(self.display);self.x.XSync(self.display,0)
        self.record['during']=self.read();assert self.record['during']['global_auto_repeat']==0
        assert {k:v for k,v in self.record['before'].items() if k!='global_auto_repeat'}=={k:v for k,v in self.record['during'].items() if k!='global_auto_repeat'}
        return self
    def __exit__(self, kind, value, trace):
        try:
            if self.record['before']['global_auto_repeat']:self.x.XAutoRepeatOn(self.display)
            else:self.x.XAutoRepeatOff(self.display)
            self.x.XSync(self.display,0);self.record['after']=self.read()
            assert self.record['after']==self.record['before']
            self.report.setdefault('own_display_repeat_controls',[]).append(self.record)
            print('CHROMIUM_OWN_DISPLAY_REPEAT_CONTROL',json.dumps(self.record),flush=True)
        finally:self.x.XCloseDisplay(self.display)

def ui_step(report, state):
    tree = nodes()
    summary = [(role, name[:180]) for _, role, name in tree if name or role == 'password text']
    digest = hashlib.sha256(json.dumps(summary).encode()).hexdigest()
    if digest != state.get('last_tree'):
        print('CHROMIUM_ACTUAL_AX_TREE', json.dumps(summary[:160]), flush=True)
        state['last_tree'] = digest
    now = time.monotonic()
    if now - state.get('last_action', 0) < 1:
        return
    for node, role, name in tree:
        if role != 'password text' or state.get('pin_started'):
            continue
        if not node.getState().contains(pyatspi.STATE_ENABLED):
            continue
        state['pin_started'] = True
        assert node.queryComponent().grabFocus()
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and not node.getState().contains(pyatspi.STATE_FOCUSED):
            time.sleep(.05)
        assert node.getState().contains(pyatspi.STATE_FOCUSED), 'own actual PIN field is not focused'
        observe_pin_input(report,state,node,'before-editable')
        try:
            assert node.queryEditableText().setTextContents('own-browser-pin')
            method = 'actual-at-spi-editable-text'
        except Exception as editable_exc:
            observe_pin_input(report,state,node,'after-editable-error',f'{type(editable_exc).__name__}: {editable_exc}')
            with OwnDisplayRepeatGuard(report,state):
                subprocess.run(['xdotool', 'key', '--clearmodifiers', 'ctrl+a'], check=True)
                observe_pin_input(report,state,node,'after-select-all')
                # Wait for actual selection before replacing any existing field text.
                selection_deadline=time.monotonic()+8
                selected=node.queryText()
                while selected.characterCount and time.monotonic()<selection_deadline:
                    if selected.getNSelections() and tuple(selected.getSelection(0))==(0,selected.characterCount):break
                    time.sleep(.05)
                assert not selected.characterCount or (selected.getNSelections() and tuple(selected.getSelection(0))==(0,selected.characterCount)), 'own PIN selection did not cover the current field'
                assert node.getState().contains(pyatspi.STATE_FOCUSED)
                subprocess.run(['xdotool', 'type', '--clearmodifiers', '--delay', '35', 'own-browser-pin'], check=True)
                deadline=time.monotonic()+8
                typed=node.queryText()
                while time.monotonic()<deadline and typed.characterCount!=len('own-browser-pin'):time.sleep(.05)
                observe_pin_input(report,state,node,'after-x-key-events')
                assert typed.characterCount==len('own-browser-pin'), 'own actual PIN field incomplete with repeat disabled'
            method = 'actual-guest-x-key-events'
        deadline = time.monotonic() + 8
        text = node.queryText()
        while time.monotonic() < deadline and text.characterCount != len('own-browser-pin'):
            time.sleep(.05)
        observed_content = text.getText(0, -1)
        observed = {'phase': state['phase'], 'mode': state['mode'], 'account': state['account'],
                    'method': method, 'actual_character_count': text.characterCount,
                    'actual_content_length': len(observed_content),
                    'actual_content_matches_own_fixture': observed_content == 'own-browser-pin',
                    'actual_content_masked': bool(observed_content) and set(observed_content) <= {'•','●','*'},
                    'focused': node.getState().contains(pyatspi.STATE_FOCUSED),
                    'enabled': node.getState().contains(pyatspi.STATE_ENABLED),
                    'monotonic_time': time.monotonic()}
        report.setdefault('actual_pin_observations', []).append(observed)
        print('CHROMIUM_OWN_PIN_OBSERVATION', json.dumps(observed), flush=True)
        assert text.characterCount == len('own-browser-pin'), 'own actual PIN field incomplete'
        content = text.getText(0, -1)
        assert content == 'own-browser-pin' or (len(content) == len('own-browser-pin') and set(content) <= {'•','●','*'}), 'own PIN field content differs'
        state['pin_ready'] = True
        report['ui_actions'].append({'role': role, 'name': name, 'method': method, 'actual_character_count': text.characterCount, 'account':state['account'], 'phase':state['phase'], 'mode':state['mode']})
        break
    preferred = ['Security key', 'USB security key', 'Use a security key', 'Use your security key', state['account']]
    if state.get('pin_ready'):
        preferred += ['Next', 'OK', 'Continue']
    for label in preferred:
        for node, role, name in tree:
            if name != label or role not in ['push button', 'button', 'list item']:
                continue
            if not node.getState().contains(pyatspi.STATE_ENABLED):
                continue
            action = node.queryAction()
            if not action.nActions:
                continue
            assert action.doAction(0), (role, name)
            report['ui_actions'].append({'role': role, 'name': name, 'method': 'actual-at-spi-action', 'account':state['account'], 'phase':state['phase'], 'mode':state['mode']})
            state['last_action'] = now
            state['pin_ready'] = False
            return


def operation(driver, mode, server, report):
    assert driver.evaluate('location.origin') == server.origin
    before = len(server.completed)
    script = resident.begin.replace('const mode=arguments[0];', 'const mode=' + json.dumps(mode) + ';')
    driver.evaluate('(function(){' + script + '})()')
    deadline = time.monotonic() + 120
    state = {'account': server.current_account['name'], 'phase': server.phase, 'mode': mode}
    while time.monotonic() < deadline:
        assert not server.failures, server.failures
        if len(server.completed) > before:
            value = driver.evaluate('document.documentElement.dataset.ownResult')
            if value in [None, 'pending']:
                time.sleep(.2)
                continue
            assert json.loads(value) == {'verified': True}, value
            return server.last_response
        ui_step(report, state)
        time.sleep(.3)
    error = driver.evaluate('document.documentElement.dataset.ownResult')
    raise AssertionError(f'actual Chromium WebAuthn/UI timeout: {error}')


def launch(directory, origin):
    log = (directory / 'chromium.log').open('ab')
    process = subprocess.Popen([
        '/bin/busybox', 'chroot', str(BROWSER_ROOT), '/usr/lib/chromium/chromium',
        '--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
        '--disable-background-networking', '--disable-component-update', '--disable-sync',
        '--password-store=basic', '--force-renderer-accessibility', '--lang=en-US',
        '--user-data-dir=/tmp/ske-chromium-profile', '--remote-debugging-address=127.0.0.1',
        '--remote-debugging-port=9222', origin,
    ], stdout=log, stderr=log, env=dict(os.environ))
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError((directory / 'chromium.log').read_text())
        try:
            pages = json.load(urllib.request.urlopen('http://127.0.0.1:9222/json/list', timeout=2))
            page = next(p for p in pages if p['type'] == 'page' and p['url'] == origin + '/')
            driver = CDP(page['webSocketDebuggerUrl'])
            last = None
            while time.monotonic() < deadline:
                state = driver.evaluate('({secure:isSecureContext,href:location.href,origin:location.origin,ready:document.readyState,body:document.body?.innerText?.slice(0,300)})')
                if state != last:
                    print('CHROMIUM_PAGE_READINESS', json.dumps(state), flush=True)
                    last = state
                if state['secure'] is True and state['origin'] == origin and state['ready'] == 'complete':
                    return process, driver, log
                time.sleep(.2)
            driver.sock.close()
            raise AssertionError(f'own secure page did not become ready: {last}')
        except (OSError, StopIteration):
            time.sleep(.2)
    raise AssertionError('stock Chromium localhost CDP readiness')


def close_browser(browser):
    if browser:
        browser[1].sock.close()
        browser[0].terminate()
        try:
            browser[0].wait(15)
        except subprocess.TimeoutExpired:
            browser[0].kill()
            browser[0].wait(5)
        browser[2].close()


def ensure_accessibility(report):
    props = Gio.DBusProxy.new_for_bus_sync(
        Gio.BusType.SESSION, Gio.DBusProxyFlags.NONE, None,
        'org.a11y.Bus', '/org/a11y/bus', 'org.freedesktop.DBus.Properties', None,
    )
    props.call_sync('Set', GLib.Variant('(ssv)', ('org.a11y.Status', 'IsEnabled', GLib.Variant('b', True))),
                    Gio.DBusCallFlags.NONE, 10000, None)
    enabled = props.call_sync('Get', GLib.Variant('(ss)', ('org.a11y.Status', 'IsEnabled')),
                              Gio.DBusCallFlags.NONE, 10000, None).unpack()[0]
    assert enabled is True
    bus = Gio.DBusProxy.new_for_bus_sync(
        Gio.BusType.SESSION, Gio.DBusProxyFlags.NONE, None,
        'org.a11y.Bus', '/org/a11y/bus', 'org.a11y.Bus', None,
    )
    address = bus.call_sync('GetAddress', None, Gio.DBusCallFlags.NONE, 10000, None).unpack()[0]
    assert address.startswith('unix:')
    report['own_guest_accessibility_enabled_before_browser_launch'] = True
    print('CHROMIUM_OWN_ACCESSIBILITY_READY', enabled, address, flush=True)


def es384_boundary(driver, server, directory, fixture, report):
    account = {'algorithm': -35, 'index': 0,
               'user_id': b'own-chromium-rejected-es384', 'name': 'own-chromium-rejected-es384'}
    resident.select(server, account)
    server.negative_request = True
    server.browser_errors = []
    assert driver.evaluate('location.origin') == server.origin
    driver.evaluate("""(async()=>{
      try{
        const raw=await(await fetch('/register')).json();
        const options=PublicKeyCredential.parseCreationOptionsFromJSON(raw.publicKey);
        const credential=await navigator.credentials.create({publicKey:options});
        await fetch('/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(credential.toJSON())});
      }catch(e){
        await fetch('/browser-error',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({error:e.name,message:e.message})});
      }
    })();true;""")
    state = {'account': account['name'], 'phase': 'es384-negative', 'mode': 'register'}
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline and not server.browser_errors:
        assert len(server.registrations) == 2, 'stock Chromium unexpectedly accepted ES384'
        ui_step(report, state)
        time.sleep(.3)
    check(len(server.browser_errors) == 1 and server.browser_errors[0]['error'] == 'NotAllowedError',
          'actual stock Chromium ES384 API failure recorded without changing device algorithm')
    log = (directory/'chromium.log').read_text(errors='replace')
    candidates = re.findall(r"rejected CBOR structure[^\n]*?2: h'([0-9A-Fa-f]+)'", log)
    check(len(candidates) == 1 and len(server.registrations) == 2,
          'actual ES384 CTAP response rejected by stock browser parser before RP registration')
    raw = bytes.fromhex(candidates[0])
    assert len(raw) < 4096
    data = AuthenticatorData(raw)
    credential = data.credential_data
    key = credential.public_key
    check(key[1] == 2 and key[3] == -35 and key[-1] == 2 and len(key[-2]) == len(key[-3]) == 48
          and data.rp_id_hash == hashlib.sha256(b'localhost').digest() and data.flags & 5 == 5,
          'independent SDK decodes valid own P384 curve and 48-byte coordinates from rejected browser response')
    report['es384_rejection'] = {'browser_error':server.browser_errors[0],
        'cose_algorithm':-35, 'cose_curve':2, 'coordinate_bytes':48,
        'credential_sha256':hashlib.sha256(credential.credential_id).hexdigest(),
        'authenticator_data_sha256':hashlib.sha256(raw).hexdigest()}
    server.negative_request = False
    return report['es384_rejection'], credential, account


def verify_rejected_es384_sdk(fixture, rejection, credential, account):
    own = [d for d in base.CtapHidDevice.list_devices() if d.descriptor.serial_number == fixture.serial]
    assert len(own) == 1
    with own[0] as device:
        ctap = Ctap2(device)
        protocol = PinProtocolV2()
        token = ClientPin(ctap, protocol).get_pin_token('own-browser-pin', ClientPin.PERMISSION.GET_ASSERTION, 'localhost')
        challenge = hashlib.sha256(b'own-rejected-es384-sdk-proof').digest()
        response = ctap.get_assertion('localhost', challenge,
            allow_list=[{'type':'public-key','id':credential.credential_id}],
            pin_uv_protocol=2, pin_uv_param=protocol.authenticate(token, challenge))
        assert response.auth_data.flags & 5 == 5
        assert response.credential['id'] == credential.credential_id and response.user['id'] == account['user_id']
        credential.public_key.verify(response.auth_data + challenge, response.signature)
        check(True, 'independent UV-bound SDK verifies actual rejected own ES384 credential signature and user handle')
        rejection.update(independent_sdk_signature_verified=True, independent_sdk_user_verified=True,
                         independent_sdk_user_handle_verified=True, pin_uv_protocol=2,
                         sdk_counter=response.auth_data.counter)


def main():
    fixture = server = browser = None
    report = {'passed': False, 'scope': 'stock Chromium actual Linux USB: ES256/Ed25519 largeBlob SDK/restart proof; explicit ES384 parser rejection with independent device signature proof',
              'physical_device_access': False, 'host_usb_passthrough': False,
              'virtual_authenticator_enabled': False, 'webauthn_api_replaced': False,
              'browser_webauthn_service_callbacks_invoked_directly': False,
              'physical_touch_verified': False, 'manufacturer_trust_reproduced': False,
              'tests': checks, 'all_browser_extensions_verified': False, 'all_browser_algorithms_verified': False,
              'native_macos_registration_verified': False, 'ui_actions': [], 'cdp_commands': [], 'independent_sdk_references': []}
    sdk_spec = importlib.util.spec_from_file_location('blob_reference', '/opt/verification/browser-largeblob-sdk.py')
    sdk = importlib.util.module_from_spec(sdk_spec)
    sdk_spec.loader.exec_module(sdk)
    with tempfile.TemporaryDirectory(prefix='chromium-own-', dir='/guest-state') as temporary:
        directory = Path(temporary)
        try:
            check(Path('/opt/isolated-ske-usb-guest').exists(), 'private own largeBlob USB guest marker')
            check([p.name for p in Path('/sys/class/net').iterdir()] == ['lo'] and platform.release() == '6.8.0-146-generic' and platform.machine() == 'aarch64', 'actual isolated ARM64 distro kernel with only loopback')
            ensure_accessibility(report)
            check(report['own_guest_accessibility_enabled_before_browser_launch'], 'actual own guest accessibility bus enabled and ready before native browser')
            fixture = base.verify_composite.CompositeFixture(Path('/opt/swpasskeyd'), directory)
            fixture.start()
            report['controller'] = fixture.controller
            report['usb_discovery'] = base.verify_composite.observations[-1]
            ClientPin(fixture.ctap, PinProtocolV2()).set_pin('own-browser-pin')
            fixture.device.close()
            fixture.device = None
            processes = (fixture.bridge.pid, fixture.process.pid, fixture.card.process.pid)
            server = ThreadingHTTPServer(('127.0.0.1', 0), BlobRP)
            server.origin = f'http://localhost:{server.server_port}'
            server.rp = base.Fido2Server(PublicKeyCredentialRpEntity(id='localhost', name='Own Chromium largeBlob RP'), verify_origin=lambda value: value == server.origin)
            server.records, server.completed, server.failures = {}, [], []
            server.registrations, server.assertions = [], []
            server.phase, server.blob_mode = 'initial', 'write'
            accounts = [{'algorithm': alg, 'index': 0, 'user_id': f'own-chromium-blob-{alg}'.encode(),
                         'name': f'own-chromium-blob-{alg}', 'browser_payload': PAYLOAD + bytes([abs(alg)]),
                         'sdk_payload': SDK_PAYLOAD + bytes([abs(alg)])} for alg in [-7,-8]]
            resident.select(server, accounts[0])
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            browser = launch(directory, server.origin)
            report['browser_version'] = browser[1].call('Browser.getVersion')
            check(report['browser_version']['product'] == 'Chrome/154.0.8037.92' and hashlib.sha256((BROWSER_ROOT/'usr/lib/chromium/chromium').read_bytes()).hexdigest() == '4f8459f639cd128f701fc84b04bbdc496a56202cdd78beec5db721bdda260911', 'actual pinned stock Chromium runtime and ELF byte hash')
            for account in accounts:
                resident.select(server, account)
                response = operation(browser[1], 'register', server, report)
                print('CHROMIUM_REGISTRATION_EXTENSIONS', account['algorithm'], json.dumps(response.get('clientExtensionResults')), flush=True)
                assert response['clientExtensionResults']['largeBlob']['supported'] is True
                assert response['clientExtensionResults']['credProps']['rk'] is True
                check(True, f'actual largeBlob-supported resident creation with required PIN UV {account["algorithm"]}')
                response = operation(browser[1], 'login', server, report)
                check(response['clientExtensionResults']['largeBlob']['written'] is True, f'actual browser largeBlob write and independently RP-verified assertion {account["algorithm"]}')
                print('CHROMIUM_WRITE_VERIFIED', account['algorithm'], flush=True)
            report['initial_metrics'] = base.metrics(directory)
            assert report['initial_metrics']['pin_fail'] == 0, 'own GUI PIN automation introduced an unintended rejection'
            assert report['initial_metrics']['make_cred_ok'] == report['initial_metrics']['store_creds'] == 2
            check(True, 'two actual browser resident credentials and zero unintended PIN failures before SDK references')
            report['cdp_commands'] += browser[1].commands
            close_browser(browser)
            browser = None
            for account in accounts:
                resident.select(server, account)
                row = server.records[server.current]
                reference = sdk.compare_and_replace(fixture, row, account['browser_payload'], account['sdk_payload'])
                report['independent_sdk_references'].append({'algorithm': account['algorithm'], **reference})
                check(reference['independent_sdk_signature_verified'] and reference['independent_sdk_user_verified'] and reference['independent_sdk_user_handle_verified'], f'independent native UV-bound SDK credential signature and user binding {account["algorithm"]}')
                check(reference['independent_sdk_browser_blob_match'] and reference['unrelated_key_has_no_blob'], f'independent SDK decrypts actual browser blob and rejects unrelated key {account["algorithm"]}')
                check(reference['independent_sdk_replacement_verified'], f'independent SDK encrypted blob replacement verified {account["algorithm"]}')
                print('CHROMIUM_INDEPENDENT_SDK_REFERENCE', json.dumps(reference), flush=True)
            browser = launch(directory, server.origin)
            server.blob_mode = 'read'
            for phase in ['browser-restart-after-sdk-write', 'live-usb-reboot']:
                if phase == 'live-usb-reboot':
                    report['before_reboot_metrics'] = base.metrics(directory)
                    assert report['before_reboot_metrics']['pin_fail'] == 0
                    before = base.snapshot(fixture.serial)
                    own = [d for d in base.CtapHidDevice.list_devices() if d.descriptor.serial_number == fixture.serial]
                    assert len(own) == 1
                    with own[0] as device:
                        base.ManagementSession(device).write_device_config(reboot=True)
                    def changed():
                        value = base.snapshot(fixture.serial)
                        hid = [d for d in base.list_descriptors() if d.serial_number == fixture.serial]
                        return value if value and value['address'] != before['address'] and len(hid) == 1 else None
                    after = base.verify_composite.wait_for(changed, 'Chromium own USB reboot did not reenumerate')
                    assert processes == (fixture.bridge.pid, fixture.process.pid, fixture.card.process.pid)
                    assert all(p.poll() is None for p in [fixture.bridge,fixture.process,fixture.card.process])
                    report['usb_reboot'] = {'before':before,'after':after,'same_three_service_processes':True}
                    check(True, 'live own USB reboot changes device address while retaining all three service processes')
                server.phase = phase
                for account in accounts:
                    resident.select(server, account)
                    response = operation(browser[1], 'login', server, report)
                    value = base.websafe_decode(response['clientExtensionResults']['largeBlob']['blob'])
                    assert value == account['sdk_payload'], 'browser read differs from independent SDK replacement'
                    server.assertions[-1].update(large_blob_payload_sha256=hashlib.sha256(value).hexdigest(),
                                                 independent_sdk_blob_match=True,large_blob_payload_bytes=len(value))
                    check(True, f'actual browser independent SDK blob read and RP signature/UV/userHandle after {phase} {account["algorithm"]}')
                    print('CHROMIUM_READ_VERIFIED', account['algorithm'], phase, flush=True)
            final = base.metrics(directory)
            assert final['make_cred_ok'] == final['store_creds'] == 2 and final['pin_retries'] == 8
            assert final['pin_fail'] == 0
            assert len(server.registrations) == 2 and len(server.assertions) == 6
            assert len({x['challenge_sha256'] for x in server.assertions}) == 6
            check(True, 'largeBlob browser and SDK state preserved with zero unintended PIN failures and full retries')
            check(True, 'six actual browser assertion challenges are distinct')
            pins = [a for a in report['ui_actions'] if a['role'] == 'password text']
            check(bool(pins) and all(a['actual_character_count'] == 15 for a in pins), 'actual focused PIN fields contain all fifteen characters before single submission')
            rejection, rejected_credential, rejected_account = es384_boundary(browser[1], server, directory, fixture, report)
            report['cdp_commands'] += browser[1].commands
            close_browser(browser)
            browser = None
            verify_rejected_es384_sdk(fixture, rejection, rejected_credential, rejected_account)
            final = base.metrics(directory)
            check(final['make_cred_ok'] == final['store_creds'] == 3 and final['remaining'] == 97 and final['get_assert_ok'] >= 9 and final['pin_fail'] == 0 and final['pin_retries'] == 8,
                  'rejected browser ES384 key remains a valid device credential without damaging two largeBlob keys or PIN state')
            check(all(cmd in ['Browser.getVersion','Runtime.evaluate','Page.navigate'] for cmd in report['cdp_commands']), 'only ordinary own page CDP commands; no virtual authenticator or direct WebAuthn service callbacks')
            report.update(passed=True, registrations=server.registrations, assertions=server.assertions,
                          browser_large_blob_write_verified=True, browser_large_blob_read_verified=True,
                          browser_large_blob_independent_sdk_verified=True, browser_large_blob_restart_verified=True,
                          browser_large_blob_live_usb_reboot_verified=True, stock_chromium_es384_parser_boundary_verified=True,
                          browser_algorithms_verified=[-7,-8], browser_algorithms_rejected=[-35],
                          modeled_user_presence_auto_approved_for_own_test_state=True, final_metrics=final,
                          emulator_binary_sha256=hashlib.sha256(Path('/opt/swpasskeyd').read_bytes()).hexdigest(),
                          browser_binary_sha256=hashlib.sha256((BROWSER_ROOT/'usr/lib/chromium/chromium').read_bytes()).hexdigest())
        except Exception as exc:
            report['error'] = f'{type(exc).__name__}: {exc}'
            raise
        finally:
            if server:
                report['registrations'] = server.registrations
                report['assertions'] = server.assertions
                if fixture and fixture.process and fixture.process.poll() is None:
                    try:
                        report['final_metrics'] = base.metrics(directory)
                    except Exception as exc:
                        report['metrics_collection_error'] = f'{type(exc).__name__}: {exc}'
            close_browser(browser)
            if server:
                server.shutdown()
                thread.join(5)
                server.server_close()
            for name in ['chromium.log', 'daemon.log', 'usb.log']:
                p = directory / name
                if p.exists(): print('CHROMIUM_PROBE_DIAGNOSTIC', name, p.read_text(errors='replace')[-15000:], flush=True)
            if fixture: fixture.stop()
            report['test_count'] = len(checks)
            print('SKE_BROWSER_LARGE_BLOB_BEGIN', flush=True)
            print(json.dumps(report), flush=True)
            print('SKE_BROWSER_LARGE_BLOB_END', flush=True)

if __name__ == '__main__':
    main()
