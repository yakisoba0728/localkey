#!/usr/bin/env python3
"""Own resident/PIN/UV WebAuthn through stock Firefox and actual guest USB.

Fresh own test PINs enter the real password dialog. Account selection uses
the existing notification button/menu, with no WebAuthn service callbacks.
Only the isolated fixture auto approves modeled presence; physical touch and
manufacturer trust are not reproduced.
"""

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

sys.path.insert(0, "/opt/verification")
sys.path.insert(0, "/opt")
spec = importlib.util.spec_from_file_location(
    "browser_base", "/opt/verification/verify-browser.py"
)
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
from fido2.ctap2.pin import ClientPin, PinProtocolV2
from fido2.webauthn import (
    AuthenticationResponse,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRpEntity,
    RegistrationResponse,
)

checks = base.checks
check = base.check


def validate_assertion(server, response, *, commit=False):
    """RP crypto and credential/account binding, independent of the emulator."""
    credential = server.rp.authenticate_complete(
        server.authentication,
        [row["credential"] for row in server.records.values()],
        response,
    )
    parsed = AuthenticationResponse.from_dict(response)
    row = server.records[server.current]
    if credential != row["credential"]:
        raise ValueError("RP selected credential differs from chosen account")
    if parsed.response.user_handle != row["user_id"]:
        raise ValueError("RP userHandle does not belong to validated credential")
    assert parsed.response.authenticator_data.flags & 5 == 5
    assert parsed.response.client_data.origin == server.origin
    if commit:
        assert parsed.response.authenticator_data.counter > row["counter"]
        row["counter"] = parsed.response.authenticator_data.counter
    return parsed


class ResidentRP(base.RP):
    def do_GET(self):
        row = self.server.current_account
        if self.path == "/register":
            options, self.server.registration = self.server.rp.register_begin(
                {"id": row["user_id"], "name": row["name"], "displayName": row["name"]},
                resident_key_requirement="required",
                user_verification="required",
                authenticator_attachment="cross-platform",
            )
            self.server.creation_options = dict(options)
        elif self.path == "/login":
            options, self.server.authentication = self.server.rp.authenticate_begin(
                None, user_verification="required"
            )
            self.server.request_options = dict(options)
            assert "allowCredentials" not in self.server.request_options["publicKey"]
        else:
            return super().do_GET()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(dict(options)).encode())

    def do_POST(self):
        try:
            size = int(self.headers["Content-Length"])
            assert 0 < size < 65536
            response = json.loads(self.rfile.read(size))
            self.server.last_response = response
            row = self.server.current_account
            if self.path == "/register":
                parsed = RegistrationResponse.from_dict(response)
                auth = self.server.rp.register_complete(self.server.registration, response)
                assert auth.flags & 5 == 5
                assert auth.credential_data.public_key[3] == row["algorithm"]
                assert parsed.response.client_data.origin == self.server.origin
                assert response["authenticatorAttachment"] == "cross-platform"
                assert response["response"]["transports"] == ["usb"]
                self.server.records[self.server.current] = {
                    **row, "credential": auth.credential_data, "counter": auth.counter
                }
                self.server.registrations.append({
                    "account": row["name"], "algorithm": row["algorithm"],
                    "credential_sha256": hashlib.sha256(auth.credential_data.credential_id).hexdigest(),
                    "credential_id_bytes": len(auth.credential_data.credential_id),
                    "user_verified": True, "transports": ["usb"],
                })
            elif self.path == "/login":
                parsed = validate_assertion(self.server, response, commit=True)
                self.server.assertions.append({
                    "account": row["name"], "algorithm": row["algorithm"],
                    "phase": self.server.phase, "signature_verified": True,
                    "user_verified": True, "user_handle_verified": True,
                    "counter": parsed.response.authenticator_data.counter,
                    "origin": parsed.response.client_data.origin,
                    "challenge_sha256": hashlib.sha256(parsed.response.client_data.challenge).hexdigest(),
                })
            else:
                raise ValueError("unknown own RP operation")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"verified":true}')
            self.server.completed.append(self.path)
        except Exception as exc:
            self.server.failures.append(f"{type(exc).__name__}: {exc}")
            self.send_error(400, "own RP validation failed")


begin = """
document.documentElement.dataset.ownResult='pending';
const mode=arguments[0];
(async()=>{
 const options=await (await fetch('/'+mode)).json();
 const parsed=mode==='register'?PublicKeyCredential.parseCreationOptionsFromJSON(options.publicKey):PublicKeyCredential.parseRequestOptionsFromJSON(options.publicKey);
 const credential=mode==='register'?await navigator.credentials.create({publicKey:parsed}):await navigator.credentials.get({publicKey:parsed});
 return await (await fetch('/'+mode,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(credential.toJSON())})).json();
})().then(x=>document.documentElement.dataset.ownResult=JSON.stringify(x)).catch(e=>document.documentElement.dataset.ownResult=JSON.stringify({error:e.name,message:e.message}));
return true;
"""

# Install before requesting WebAuthn: classic WebDriver commands during a
# promptPassword dialog can dismiss it, even with unhandledPromptBehavior ignore.
# The timer enters only fresh own PINs in existing UI and selects an own label.
# Neither the browser service nor WebAuthn results are replaced or invoked here.
install_ui = """
const browser=gBrowser.selectedBrowser, origin=arguments[0], wrongFirst=arguments[1], account=arguments[2];
if(browser.currentURI.spec!==origin+'/') throw new Error('unexpected own RP');
const state={pins:[],selections:[],menus:[],error:null,seenLabels:[]};
const save=()=>browser.setAttribute('data-own-resident-ui',JSON.stringify(state));
save();
const timer=window.setInterval(()=>{
 try{
  if(browser.currentURI.spec!==origin+'/') throw new Error('own RP changed');
  for(const item of gBrowser.getTabDialogBox(browser)._tabDialogManager.dialogs){
   const win=item.frameContentWindow;
   if(!win || win.args?.promptType!=='promptPassword') continue;
   const doc=win.document, input=doc.getElementById('password1Textbox'), form=doc.getElementById('commonDialog');
   if(!input || !form || input.closest('[hidden]') || form.hasAttribute('data-own-pin-submitted')) continue;
   const button=form.getButton('accept'), text=doc.getElementById('infoBody').textContent, url=doc.documentURI;
   if(button.disabled) continue;
   if(!text.includes('PIN') || !url.startsWith('chrome://global/content/commonDialog')) throw new Error('unexpected PIN dialog');
   if(state.pins.length>=(wrongFirst?2:1)) throw new Error('unexpected additional PIN dialog');
   input.value=wrongFirst && state.pins.length===0?'wrong-own-pin':'own-browser-pin';
   input.dispatchEvent(new win.Event('input',{bubbles:true}));
   form.setAttribute('data-own-pin-submitted','1');
   state.pins.push({text,url});save();button.click();
  }
  if(!account || state.selections.length) return;
  const node=document.getElementById('webauthn-prompt-select-sign-result-notification');
  if(!node || node.hidden || !node.secondaryButton || node.secondaryButton.disabled) return;
  if(Services.focus.activeWindow!==window){window.focus();return;}
  const delay=Services.prefs.getIntPref('security.notification_enable_delay');
  if(!node.notification?.timeShown || ChromeUtils.now()-node.notification.timeShown<delay) return;
  const label=node.secondaryButton.label || node.secondaryButton.getAttribute('label') || node.secondaryButton.textContent.trim();
  const items=[...node.menupopup.querySelectorAll('menuitem')];
  state.seenLabels=[label,...items.map(x=>x.getAttribute('label'))];save();
  if(label===account){
   state.selections.push({label,control:'secondary-button'});save();
   (node.secondaryButton.buttonEl || node.secondaryButton).click();
  }else{
   if(node.menupopup.state!=='open'){
    if(!state.menus.length){state.menus.push('opened-account-menu');save();
     const chevron=node.secondaryButton.chevronButtonEl;
     if(!chevron) throw new Error('account menu button unavailable');
     chevron.click();}
    return;
   }
   const item=items.find(x=>x.getAttribute('label')===account);
   if(!item) throw new Error('chosen account missing from actual menu');
   state.selections.push({label:account,control:'menu-item'});save();item.doCommand();
  }
 }catch(e){state.error=e.name+': '+e.message;save();window.clearInterval(timer);}
},100);
browser.setAttribute('data-own-resident-timer',String(timer));
return true;
"""

collect_ui = """
const b=gBrowser.selectedBrowser;
window.clearInterval(Number(b.getAttribute('data-own-resident-timer')));
return JSON.parse(b.getAttribute('data-own-resident-ui'));
"""


def operation(driver, mode, server, report, *, wrong_first=False):
    driver.call("Marionette:SetContext", {"value": "chrome"})
    choice = server.current_account["name"] if mode == "login" else ""
    assert driver.script(install_ui, [server.origin, wrong_first, choice])
    before = len(server.completed)
    driver.call("Marionette:SetContext", {"value": "content"})
    value = driver.script(begin, [mode])
    assert value is True or value is None
    deadline = time.monotonic() + 85
    while time.monotonic() < deadline:
        assert not server.failures, server.failures
        if len(server.completed) > before:
            assert server.completed[-1] == "/" + mode
            driver.call("Marionette:SetContext", {"value": "chrome"})
            ui = driver.script(collect_ui)
            assert not ui["error"], ui
            if wrong_first:
                assert len(ui["pins"]) == 2 and "Incorrect PIN" in ui["pins"][1]["text"], ui
            else:
                assert len(ui["pins"]) <= 1, ui
            if mode == "login":
                assert len(ui["selections"]) == 1 and ui["selections"][0]["label"] == choice, ui
            driver.call("Marionette:SetContext", {"value": "content"})
            result = driver.script("return document.documentElement.dataset.ownResult;")
            if result is None or result == "pending":
                time.sleep(0.1)
                continue
            assert json.loads(result) == {"verified": True}, result
            report["ui_operations"].append({
                "mode": mode, "account": server.current_account["name"],
                "phase": server.phase, **ui,
            })
            return
        time.sleep(0.1)
    driver.call("Marionette:SetContext", {"value": "chrome"})
    ui = driver.script(collect_ui)
    raise AssertionError(f"real WebAuthn/PIN/account selection timed out: {ui}")


def reject_tampering(server):
    assert validate_assertion(server, server.last_response)
    for field in ["challenge", "origin", "signature", "uv", "userHandle"]:
        changed = copy.deepcopy(server.last_response)
        if field in ["challenge", "origin"]:
            data = json.loads(base.websafe_decode(changed["response"]["clientDataJSON"]))
            data[field] = "wrong-own-challenge" if field == "challenge" else "http://wrong-own-origin.invalid"
            changed["response"]["clientDataJSON"] = base.websafe_encode(json.dumps(data).encode())
        elif field == "signature":
            data = bytearray(base.websafe_decode(changed["response"][field]))
            data[-1] ^= 1
            changed["response"][field] = base.websafe_encode(data)
        elif field == "uv":
            data = bytearray(base.websafe_decode(changed["response"]["authenticatorData"]))
            data[32] &= ~4
            changed["response"]["authenticatorData"] = base.websafe_encode(data)
        else:
            changed["response"][field] = base.websafe_encode(b"wrong-own-user-handle")
        try:
            validate_assertion(server, changed)
        except (ValueError, AssertionError):
            check(True, f"resident RP rejects modified {field} for {server.current_account['name']}")
        else:
            raise AssertionError(f"resident RP accepted modified {field}")


def select(server, account):
    server.current = (account["algorithm"], account["index"])
    server.current_account = account
    server.rp.allowed_algorithms = [
        PublicKeyCredentialParameters(type="public-key", alg=account["algorithm"])
    ]


def main():
    fixture = browser = server = thread = None
    report = {
        "passed": False, "tests": checks, "kernel": platform.release(),
        "architecture": platform.machine(), "physical_device_access": False,
        "host_usb_passthrough": False, "guest_network_devices": False,
        "virtual_authenticator_enabled": False, "webauthn_api_replaced": False,
        "browser_webauthn_service_callbacks_invoked_directly": False,
        "physical_touch_verified": False, "manufacturer_trust_reproduced": False,
        "modeled_user_presence_auto_approved_for_own_test_state": True,
        "browser_extensions_verified": False, "browser_attestation_consent_verified": False,
        "native_macos_registration_verified": False, "ui_operations": [],
    }
    with tempfile.TemporaryDirectory(prefix="browser-resident-", dir="/guest-state") as temporary:
        directory = Path(temporary)
        try:
            check(Path("/opt/isolated-ske-usb-guest").exists(), "private USB resident guest marker")
            check(platform.release() == "6.8.0-146-generic" and platform.machine() == "aarch64", "actual resident ARM64 distro kernel")
            check([p.name for p in Path("/sys/class/net").iterdir()] == ["lo"], "resident guest has only loopback")
            fixture = base.verify_composite.CompositeFixture(Path("/opt/swpasskeyd"), directory)
            fixture.start()
            ClientPin(fixture.ctap, PinProtocolV2()).set_pin("own-browser-pin")
            fixture.device.close()
            fixture.device = None
            report["controller"] = fixture.controller
            report["usb_discovery"] = base.verify_composite.observations[-1]
            processes = (fixture.bridge.pid, fixture.process.pid, fixture.card.process.pid)
            server = ThreadingHTTPServer(("127.0.0.1", 0), ResidentRP)
            server.origin = f"http://localhost:{server.server_port}"
            server.rp = base.Fido2Server(
                PublicKeyCredentialRpEntity(id="localhost", name="Own resident browser RP"),
                verify_origin=lambda value: value == server.origin,
            )
            server.records, server.completed, server.failures = {}, [], []
            server.registrations, server.assertions = [], []
            server.phase = "register"
            accounts = [
                {"algorithm": alg, "index": index, "user_id": f"own-resident-{alg}-{index}".encode(),
                 "name": f"own-resident-{alg}-{index}"}
                for alg in [-7, -8, -35] for index in [0, 1]
            ]
            select(server, accounts[0])
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            profile = directory / "profile"
            profile.mkdir()
            prefs = {
                "marionette.port": 2828, "security.webauth.webauthn_enable_usbtoken": True,
                "security.webauth.webauthn_enable_softtoken": False, "security.webauthn.ctap2": True,
                "browser.shell.checkDefaultBrowser": False, "browser.aboutwelcome.enabled": False,
                "datareporting.policy.dataSubmissionEnabled": False, "toolkit.telemetry.enabled": False,
            }
            (profile / "user.js").write_text("\n".join(
                f"user_pref({json.dumps(k)}, {json.dumps(v)});" for k, v in prefs.items()
            ))
            browser = base.launch(directory, profile, server.origin)
            report["first_browser"] = browser[4]
            for index, account in enumerate(accounts):
                select(server, account)
                operation(browser[2], "register", server, report, wrong_first=index == 0)
                check(True, f"real PIN dialog resident registration and RP-required UV {account['name']}")
            initial = base.metrics(directory)
            check(initial["make_cred_ok"] == initial["store_creds"] == 6 and initial["remaining"] == 94,
                  "six browser-created resident credentials occupy actual modified store")
            check(initial["pin_fail"] == 1 and initial["errors"]["0x31"] == 1 and initial["pin_retries"] == 8,
                  "real wrong PIN rejected then correct GUI PIN restores retries")
            report["initial_metrics"] = initial
            for phase in ["initial", "browser-restart", "live-usb-reboot"]:
                if phase == "browser-restart":
                    report["first_commands"] = browser[2].commands
                    base.close_browser(browser)
                    browser = None
                    browser = base.launch(directory, profile, server.origin)
                    report["second_browser"] = browser[4]
                elif phase == "live-usb-reboot":
                    before = base.snapshot(fixture.serial)
                    own = [d for d in base.CtapHidDevice.list_devices() if d.descriptor.serial_number == fixture.serial]
                    assert len(own) == 1
                    with own[0] as device:
                        base.ManagementSession(device).write_device_config(reboot=True)
                    def changed():
                        value = base.snapshot(fixture.serial)
                        hid = [d for d in base.list_descriptors() if d.serial_number == fixture.serial]
                        return value if value and value["address"] != before["address"] and len(hid) == 1 else None
                    after = base.verify_composite.wait_for(changed, "resident USB reboot did not reenumerate")
                    report["usb_reboot"] = {"before": before, "after": after}
                    check(processes == (fixture.bridge.pid, fixture.process.pid, fixture.card.process.pid)
                          and all(p.poll() is None for p in [fixture.bridge, fixture.process, fixture.card.process]),
                          "resident USB reboot retains all three live services")
                server.phase = phase
                for account in accounts:
                    select(server, account)
                    operation(browser[2], "login", server, report)
                    check(True, f"actual account selection/discovery/RP signature/UV/userHandle {account['name']} {phase}")
                    if phase == "initial":
                        reject_tampering(server)
            final = base.metrics(directory)
            check(final["make_cred_ok"] == final["store_creds"] == 6 and final["remaining"] == 94 and final["get_assert_ok"] >= 18,
                  "modified core retains six resident keys and processes eighteen verified browser assertions")
            hashes = [r["challenge_sha256"] for r in server.assertions]
            check(len(hashes) == len(set(hashes)) == 18, "eighteen resident assertions have distinct RP challenges")
            controls = {selection["control"] for operation in report["ui_operations"] for selection in operation["selections"]}
            check(controls == {"secondary-button", "menu-item"}, "resident account selection exercises both actual primary choice and account menu")
            check(all(not n.startswith("WebAuthn:") for n in report["first_commands"] + browser[2].commands),
                  "resident tests create no browser virtual authenticator")
            report.update(
                passed=True, browser_pin_uv_resident_verified=True,
                browser_multiple_account_selection_verified=True,
                browser_resident_restart_verified=True, browser_resident_live_usb_reboot_verified=True,
                final_metrics=final, registrations=server.registrations, assertions=server.assertions,
                second_commands=browser[2].commands, algorithms=[-7, -8, -35],
            )
        except Exception as exc:
            report.update(error=f"{type(exc).__name__}: {exc}")
            raise
        finally:
            base.close_browser(browser)
            if server:
                server.shutdown()
                thread.join(5)
                server.server_close()
            for name in ["firefox.log", "daemon.log", "usb.log", "card/log.txt"]:
                p = directory / name
                if p.exists():
                    print("SKE_BROWSER_RESIDENT_DIAGNOSTIC", name, p.read_text(), flush=True)
            if fixture:
                fixture.stop()
            report["test_count"] = len(checks)
            print("SKE_BROWSER_RESIDENT_BEGIN", flush=True)
            print(json.dumps(report), flush=True)
            print("SKE_BROWSER_RESIDENT_END", flush=True)


if __name__ == "__main__":
    main()
