"""Own packed self-attestation and real Firefox consent UI, on isolated USB.

The own model AAGUID is retained when Firefox removes the attestation
statement after denial. No manufacturer identity or trust is reproduced."""

import copy
import hashlib
import importlib.util
import json
import platform
import sys
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, '/opt/verification')
sys.path.insert(0, '/opt')
spec = importlib.util.spec_from_file_location('resident_base', '/opt/verification/verify-browser-resident.py')
resident = importlib.util.module_from_spec(spec)
spec.loader.exec_module(resident)
base = resident.base
check, checks = base.check, base.checks
from fido2.attestation import AttestationType, PackedAttestation
from fido2.attestation.base import InvalidAttestation
from fido2.ctap2.pin import ClientPin, PinProtocolV2
from fido2.webauthn import PublicKeyCredentialParameters, PublicKeyCredentialRpEntity, RegistrationResponse


def verify_attestation(server, att, client_hash):
    row = server.current_account
    observation = {'account': row['name'], 'consent': row['consent'], 'format': att.fmt,
                   'statement_fields': sorted(att.att_stmt),
                   'aaguid_hex': bytes(att.auth_data.credential_data.aaguid).hex()}
    server.attestation_observations.append(observation)
    print('SKE_OWN_ATTESTATION_OBSERVATION', json.dumps(observation), flush=True)
    if row['consent']:
        assert att.fmt == 'packed' and 'x5c' not in att.att_stmt
        assert bytes(att.auth_data.credential_data.aaguid) == server.own_aaguid
        result = PackedAttestation().verify(att.att_stmt, att.auth_data, client_hash)
        assert result.attestation_type == AttestationType.SELF and result.trust_path == []
    else:
        assert att.fmt == 'none' and att.att_stmt == {}, observation
        # Firefox's anonymize removes the statement but retains model AAGUID.
        assert bytes(att.auth_data.credential_data.aaguid) == server.own_aaguid, observation


class ConsentRP(resident.ResidentRP):
    def do_GET(self):
        if self.path != '/register':
            return super().do_GET()
        row = self.server.current_account
        options, self.server.registration = self.server.rp.register_begin(
            {'id': row['user_id'], 'name': row['name'], 'displayName': row['name']},
            resident_key_requirement='required', user_verification='required',
            authenticator_attachment='cross-platform',
        )
        options = dict(options)
        assert options['publicKey']['attestation'] == 'direct'
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(options).encode())

    def do_POST(self):
        if self.path != '/register':
            return super().do_POST()
        try:
            size = int(self.headers['Content-Length'])
            assert 0 < size < 65536
            response = json.loads(self.rfile.read(size))
            self.server.last_response = response
            row = self.server.current_account
            parsed = RegistrationResponse.from_dict(response)
            auth = self.server.rp.register_complete(self.server.registration, response)
            assert auth.flags & 5 == 5 and auth.credential_data.public_key[3] == row['algorithm']
            assert parsed.response.client_data.origin == self.server.origin
            assert response['authenticatorAttachment'] == 'cross-platform'
            assert response['response']['transports'] == ['usb']
            self.server.records[self.server.current] = {
                **row, 'credential': auth.credential_data, 'counter': auth.counter,
            }
            att = parsed.response.attestation_object
            check(True, f"independent own packed self signature or denied anonymization {row['name']}")
            if row['consent']:
                for field in ['signature', 'client-data-hash']:
                    statement = copy.deepcopy(att.att_stmt)
                    client_hash = parsed.response.client_data.hash
                    if field == 'signature':
                        signature = bytearray(statement['sig']); signature[-1] ^= 1
                        statement['sig'] = bytes(signature)
                    else:
                        client_hash = hashlib.sha256(b'wrong-own-attestation-challenge').digest()
                    try:
                        PackedAttestation().verify(statement, att.auth_data, client_hash)
                    except InvalidAttestation:
                        check(True, f"own packed verifier rejects altered {field} {row['name']}")
                    else:
                        raise AssertionError('modified own attestation accepted')
            self.server.registrations.append({
                'account': row['name'], 'algorithm': row['algorithm'], 'consent': row['consent'],
                'format': att.fmt, 'aaguid_hex': bytes(auth.credential_data.aaguid).hex(),
                'own_self_attestation_verified': row['consent'],
                'anonymization_verified': not row['consent'],
                'model_aaguid_retained': True,
                'manufacturer_chain_present': False, 'user_verified': True,
                'credential_sha256': hashlib.sha256(auth.credential_data.credential_id).hexdigest(),
            })
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"verified":true}')
            self.server.completed.append(self.path)
        except Exception as exc:
            self.server.failures.append(f'{type(exc).__name__}: {exc}')
            self.send_error(400, 'own attestation RP validation failed')


install_ui = resident.install_ui.replace(
    'const state={pins:[],selections:[],menus:[],error:null,seenLabels:[]};',
    'const state={pins:[],selections:[],menus:[],consents:[],error:null,seenLabels:[]};'
).replace(
    "  if(!account || state.selections.length) return;",
    """
  const consentNode=document.getElementById('webauthn-prompt-register-direct-notification');
  if(consentNode && !consentNode.hidden && !state.consents.length){
   if(consentNode.notification?.browser!==browser) throw new Error('consent targets another browser');
   if(Services.focus.activeWindow!==window){window.focus();return;}
   const delay=Services.prefs.getIntPref('security.notification_enable_delay');
   if(!consentNode.notification?.timeShown || ChromeUtils.now()-consentNode.notification.timeShown<delay) return;
   const allow=arguments[3], button=allow?consentNode.button:consentNode.secondaryButton;
   if(!button || button.disabled) return;
   const label=button.label || button.getAttribute('label') || button.textContent.trim();
   if(label!==(allow?'Allow':'Block')) throw new Error('unexpected consent button label '+label);
   state.consents.push({allow,label,control:allow?'primary-button':'secondary-button',notification:consentNode.id});save();
   (button.buttonEl || button).click();
  }
  if(!account || state.selections.length) return;
"""
)


def operation(driver, mode, server, report):
    driver.call('Marionette:SetContext', {'value': 'chrome'})
    choice = server.current_account['name'] if mode == 'login' else ''
    assert driver.script(install_ui, [server.origin, False, choice, server.current_account['consent']])
    before = len(server.completed)
    driver.call('Marionette:SetContext', {'value': 'content'})
    value = driver.script(resident.begin, [mode])
    assert value is True or value is None
    deadline = time.monotonic() + 85
    while time.monotonic() < deadline:
        assert not server.failures, server.failures
        if len(server.completed) > before:
            driver.call('Marionette:SetContext', {'value': 'chrome'})
            ui = driver.script(resident.collect_ui)
            assert not ui['error'], ui
            if mode == 'register':
                assert len(ui['consents']) == 1 and ui['consents'][0]['allow'] is server.current_account['consent'], ui
            else:
                assert ui['consents'] == [] and len(ui['selections']) == 1 and ui['selections'][0]['label'] == choice, ui
            driver.call('Marionette:SetContext', {'value': 'content'})
            result = driver.script('return document.documentElement.dataset.ownResult;')
            if result is None or result == 'pending':
                time.sleep(0.1); continue
            assert json.loads(result) == {'verified': True}, result
            report['ui_operations'].append({'mode': mode, 'account': server.current_account['name'], 'phase': server.phase, **ui})
            return
        time.sleep(0.1)
    driver.call('Marionette:SetContext', {'value': 'chrome'})
    raise AssertionError(f'actual consent UI operation timed out: {driver.script(resident.collect_ui)}')


def main():
    fixture = browser = server = thread = None
    report = {
        'passed': False, 'tests': checks, 'ui_operations': [],
        'physical_device_access': False, 'host_usb_passthrough': False,
        'virtual_authenticator_enabled': False, 'webauthn_api_replaced': False,
        'browser_webauthn_service_callbacks_invoked_directly': False,
        'manufacturer_trust_reproduced': False, 'physical_touch_verified': False,
        'own_test_presence_auto_approved': True,
    }
    with tempfile.TemporaryDirectory(prefix='browser-attestation-', dir='/guest-state') as temporary:
        directory = Path(temporary)
        try:
            check(Path('/opt/isolated-ske-usb-guest').exists(), 'own consent USB guest marker')
            check(platform.release() == '6.8.0-146-generic' and platform.machine() == 'aarch64', 'actual consent ARM64 distro kernel')
            check([p.name for p in Path('/sys/class/net').iterdir()] == ['lo'], 'consent guest has only loopback')
            fixture = base.verify_composite.CompositeFixture(Path('/opt/swpasskeyd'), directory)
            fixture.start()
            aaguid = bytes(fixture.ctap.get_info().aaguid)
            assert aaguid != bytes(16)
            ClientPin(fixture.ctap, PinProtocolV2()).set_pin('own-browser-pin')
            fixture.device.close(); fixture.device = None
            report['controller'] = fixture.controller
            server = ThreadingHTTPServer(('127.0.0.1', 0), ConsentRP)
            server.origin = f'http://localhost:{server.server_port}'
            server.own_aaguid = aaguid
            server.rp = base.Fido2Server(
                PublicKeyCredentialRpEntity(id='localhost', name='Own attestation-consent RP'),
                attestation='direct', verify_origin=lambda value: value == server.origin,
                verify_attestation=lambda att, client_hash: verify_attestation(server, att, client_hash),
            )
            server.records, server.completed, server.failures = {}, [], []
            server.registrations, server.assertions = [], []
            server.attestation_observations = []
            server.phase = 'register'
            accounts = [
                {'algorithm': alg, 'index': int(allow), 'user_id': f'own-consent-{alg}-{allow}'.encode(),
                 'name': f'own-consent-{alg}-{allow}', 'consent': allow}
                for alg in [-7, -8, -35] for allow in [True, False]
            ]
            resident.select(server, accounts[0])
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            profile = directory / 'profile'; profile.mkdir()
            prefs = {'marionette.port': 2828, 'security.webauth.webauthn_enable_usbtoken': True,
                     'security.webauth.webauthn_enable_softtoken': False, 'security.webauthn.ctap2': True,
                     'browser.shell.checkDefaultBrowser': False, 'browser.aboutwelcome.enabled': False,
                     'datareporting.policy.dataSubmissionEnabled': False, 'toolkit.telemetry.enabled': False}
            (profile / 'user.js').write_text('\n'.join(f'user_pref({json.dumps(k)}, {json.dumps(v)});' for k, v in prefs.items()))
            browser = base.launch(directory, profile, server.origin)
            report['first_browser'] = browser[4]
            browser[2].call('Marionette:SetContext', {'value': 'chrome'})
            bypass = browser[2].script("return Services.prefs.getBoolPref('security.webauthn.always_allow_direct_attestation');")
            check(bypass is False, 'actual direct-attestation bypass preference is disabled')
            report['direct_attestation_bypass_pref'] = bypass
            for account in accounts:
                resident.select(server, account)
                operation(browser[2], 'register', server, report)
                check(True, f"actual consent button and RP-verified creation {account['name']}")
            for phase in ['initial', 'browser-restart']:
                if phase == 'browser-restart':
                    report['first_commands'] = browser[2].commands
                    base.close_browser(browser); browser = None
                    browser = base.launch(directory, profile, server.origin)
                    report['second_browser'] = browser[4]
                server.phase = phase
                for account in accounts:
                    resident.select(server, account)
                    operation(browser[2], 'login', server, report)
                    check(True, f"granted and denied resident key still signs with UV and userHandle {account['name']} {phase}")
            final = base.metrics(directory)
            check(final['make_cred_ok'] == final['store_creds'] == 6 and final['get_assert_ok'] >= 12 and final['remaining'] == 94,
                  'actual modified core stores all granted/denied keys and processes twelve browser assertions')
            check(all(not n.startswith('WebAuthn:') for n in report['first_commands'] + browser[2].commands),
                  'consent test creates no browser virtual authenticator')
            report.update(passed=True, browser_attestation_consent_verified=True,
                          browser_granted_self_attestation_verified=True, browser_denied_attestation_anonymized_verified=True,
                          browser_aaguid_retained_after_denial_verified=True,
                          browser_granted_and_denied_keys_after_restart_verified=True,
                          registrations=server.registrations, assertions=server.assertions, final_metrics=final,
                          own_aaguid_hex=aaguid.hex(), second_commands=browser[2].commands)
        except Exception as exc:
            report['error'] = f'{type(exc).__name__}: {exc}'
            raise
        finally:
            base.close_browser(browser)
            if server:
                server.shutdown(); thread.join(5); server.server_close()
            for name in ['firefox.log', 'daemon.log', 'usb.log', 'card/log.txt']:
                p = directory / name
                if p.exists(): print('SKE_BROWSER_ATTESTATION_DIAGNOSTIC', name, p.read_text(), flush=True)
            if fixture: fixture.stop()
            if server: report['attestation_observations'] = server.attestation_observations
            report['test_count'] = len(checks)
            print('SKE_BROWSER_ATTESTATION_BEGIN', flush=True)
            print(json.dumps(report), flush=True)
            print('SKE_BROWSER_ATTESTATION_END', flush=True)


if __name__ == '__main__':
    main()
