#!/usr/bin/env python3
"""Stock Firefox WebAuthn over actual guest USB with an own RP and new keys.

Marionette only navigates, reads preferences and invokes real page WebAuthn.
Own testing state auto approves modeled presence; physical touch is unverified.
"""

import copy
import hashlib
import json
import os
import platform
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, "/opt/verification")
sys.path.insert(0, "/opt")
import verify_composite
from fido2.hid import CtapHidDevice
from fido2.hid.linux import list_descriptors
from fido2.server import Fido2Server
from fido2.utils import websafe_decode, websafe_encode
from fido2.webauthn import (
    AuthenticationResponse,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRpEntity,
)
from yubikit.management import ManagementSession


class Marionette:
    def __init__(self, sock):
        self.sock = sock
        self.seq = 0
        self.commands = []
        print("MARIONETTE_HELLO", self.read(), flush=True)

    def read(self):
        prefix = b""
        while True:
            value = self.sock.recv(1)
            if not value:
                raise EOFError()
            if value == b":":
                break
            prefix += value
            assert len(prefix) < 10
        size = int(prefix)
        assert size < 8 * 1024 * 1024
        data = b""
        while len(data) < size:
            value = self.sock.recv(size - len(data))
            if not value:
                raise EOFError()
            data += value
        return json.loads(data)

    def call(self, name, args=None):
        assert not name.startswith("WebAuthn:"), (
            "browser virtual authenticator forbidden"
        )
        self.commands.append(name)
        self.seq += 1
        request = json.dumps([0, self.seq, name, args or {}]).encode()
        self.sock.sendall(str(len(request)).encode() + b":" + request)
        response = self.read()
        assert response[0] == 1 and response[1] == self.seq, response
        if response[2]:
            raise AssertionError(response[2])
        return response[3]

    def script(self, script, args=(), asynchronous=False):
        result = self.call(
            "WebDriver:ExecuteAsyncScript"
            if asynchronous
            else "WebDriver:ExecuteScript",
            {"script": script, "args": list(args), "newSandbox": True},
        )
        return result.get("value", result) if isinstance(result, dict) else result


class RP(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                b'<!doctype html><title>Own USB WebAuthn Test</title><button id="run">Own WebAuthn test</button>'
            )
            return
        if self.path == "/register":
            options, self.server.registration = self.server.rp.register_begin(
                {
                    "id": b"own-browser-user",
                    "name": "own-browser-user",
                    "displayName": "own-browser-user",
                },
                resident_key_requirement="discouraged",
                user_verification="discouraged",
                authenticator_attachment="cross-platform",
            )
        elif self.path == "/login":
            options, self.server.authentication = self.server.rp.authenticate_begin(
                [self.server.credential], user_verification="discouraged"
            )
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(dict(options)).encode())

    def do_POST(self):
        response = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.last_response = response
        if self.path == "/register":
            auth = self.server.rp.register_complete(self.server.registration, response)
            self.server.credential = auth.credential_data
            assert self.server.credential.public_key[3] == self.server.algorithm
            assert response["authenticatorAttachment"] == "cross-platform"
            assert response["response"]["transports"] == ["usb"]
            self.server.counter = auth.counter
        else:
            credential = self.server.rp.authenticate_complete(
                self.server.authentication, [self.server.credential], response
            )
            assert credential == self.server.credential
            parsed = AuthenticationResponse.from_dict(response)
            assert parsed.response.authenticator_data.counter > self.server.counter
            self.server.counter = parsed.response.authenticator_data.counter
            self.server.assertions.append(
                {
                    "algorithm": self.server.algorithm,
                    "counter": self.server.counter,
                    "origin": parsed.response.client_data.origin,
                    "challenge_sha256": hashlib.sha256(
                        parsed.response.client_data.challenge
                    ).hexdigest(),
                    "signature_verified": True,
                }
            )
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"verified":true}')


script = """
const done=arguments[arguments.length-1];
(async()=>{
 const mode=arguments[0];
 const options=await (await fetch('/'+mode)).json();
 const parsed=mode==='register'?PublicKeyCredential.parseCreationOptionsFromJSON(options.publicKey):PublicKeyCredential.parseRequestOptionsFromJSON(options.publicKey);
 const credential=mode==='register'?await navigator.credentials.create({publicKey:parsed}):await navigator.credentials.get({publicKey:parsed});
 return await (await fetch('/'+mode,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(credential.toJSON())})).json();
})().then(done).catch(e=>done({error:e.name,message:e.message,stack:e.stack}));
"""

checks = []


def check(value, name):
    if not value:
        raise AssertionError(name)
    checks.append({"name": name, "passed": True})
    print("PASS", name, flush=True)


def metrics(directory):
    result = subprocess.run(
        ["/opt/swpasskeyctl", "--socket", str(directory / "c.sock"), "stats"],
        capture_output=True,
        text=True,
        check=True,
        timeout=5,
    )
    value = json.loads(result.stdout)
    assert value["ok"]
    return value


def snapshot(serial):
    for path in Path("/sys/bus/usb/devices").iterdir():
        try:
            if (path / "serial").read_text().strip() == serial:
                return {
                    "serial": serial,
                    "address": int((path / "devnum").read_text()),
                    "path": str(path.resolve()),
                }
        except (OSError, ValueError):
            pass
    return None


def launch(directory, profile, origin):
    log = (directory / "firefox.log").open("ab")
    process = subprocess.Popen(
        [
            "/opt/ske-browser/firefox/firefox",
            "--headless",
            "--marionette",
            "--remote-allow-system-access",
            "--no-remote",
            "--profile",
            str(profile),
            "about:blank",
        ],
        stdout=log,
        stderr=log,
        env={**os.environ, "MOZ_HEADLESS": "1", "RUST_LOG": "authenticator=debug"},
    )
    conn = None
    try:
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise AssertionError((directory / "firefox.log").read_text())
            try:
                conn = socket.create_connection(("127.0.0.1", 2828), timeout=1)
                break
            except OSError:
                time.sleep(0.05)
        assert conn, "Firefox Marionette readiness"
        conn.settimeout(120)
        driver = Marionette(conn)
        session = driver.call(
            "WebDriver:NewSession", {"capabilities": {"alwaysMatch": {}}}
        )
        driver.call(
            "WebDriver:SetTimeouts", {"script": 70000, "pageLoad": 70000, "implicit": 0}
        )
        driver.call("Marionette:SetContext", {"value": "chrome"})
        prefs = driver.script(
            "return {usb:Services.prefs.getBoolPref('security.webauth.webauthn_enable_usbtoken'),soft:Services.prefs.getBoolPref('security.webauth.webauthn_enable_softtoken'),ctap2:Services.prefs.getBoolPref('security.webauthn.ctap2')};"
        )
        driver.call("Marionette:SetContext", {"value": "content"})
        driver.call("WebDriver:Navigate", {"url": origin})
        page = driver.script(
            "return {focus:document.hasFocus(),secure:isSecureContext,origin:location.origin};"
        )
        check(
            prefs == {"usb": True, "soft": False, "ctap2": True},
            "actual Firefox preferences use native USB with software authenticator disabled",
        )
        check(
            page == {"focus": True, "secure": True, "origin": origin},
            "own focused localhost secure context",
        )
        print("FIREFOX_SESSION", session, prefs, page, flush=True)
        return (
            process,
            conn,
            driver,
            log,
            {"capabilities": session["capabilities"], "prefs": prefs, "page": page},
        )
    except Exception:
        process.terminate()
        process.wait(15)
        if conn:
            conn.close()
        log.close()
        raise


def close_browser(browser):
    if browser:
        process, conn, _driver, log, _meta = browser
        process.terminate()
        try:
            process.wait(15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(5)
        conn.close()
        log.close()


def reject_tampering(server, alg):
    for field in ["challenge", "origin", "signature"]:
        changed = copy.deepcopy(server.last_response)
        if field == "signature":
            value = bytearray(websafe_decode(changed["response"]["signature"]))
            value[-1] ^= 1
            changed["response"]["signature"] = websafe_encode(value)
        else:
            value = json.loads(websafe_decode(changed["response"]["clientDataJSON"]))
            value[field] = (
                "wrong-own-challenge"
                if field == "challenge"
                else "http://wrong-own-origin.invalid"
            )
            changed["response"]["clientDataJSON"] = websafe_encode(
                json.dumps(value).encode()
            )
        try:
            server.rp.authenticate_complete(
                server.authentication, [server.credential], changed
            )
        except ValueError:
            check(True, f"own RP rejects modified {field} algorithm {alg}")
        else:
            raise AssertionError(f"own RP accepted modified {field}")


def main():
    fixture = browser = server = thread = None
    report = {
        "passed": False,
        "tests": checks,
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "physical_device_access": False,
        "host_usb_passthrough": False,
        "guest_network_devices": False,
        "own_loopback_rp": True,
        "virtual_authenticator_enabled": False,
        "webauthn_api_replaced": False,
        "browser_sandbox_explicitly_disabled": False,
        "modeled_user_presence_auto_approved_for_own_test_state": True,
        "physical_touch_verified": False,
        "browser_pin_uv_discoverable_verified": False,
        "manufacturer_trust_reproduced": False,
        "native_macos_registration_verified": False,
    }
    with tempfile.TemporaryDirectory(
        prefix="browser-", dir="/guest-state"
    ) as temporary:
        directory = Path(temporary)
        try:
            check(
                Path("/opt/isolated-ske-usb-guest").exists(), "private USB guest marker"
            )
            check(
                platform.release() == "6.8.0-146-generic"
                and platform.machine() == "aarch64",
                "actual ARM64 distro kernel",
            )
            check(
                [p.name for p in Path("/sys/class/net").iterdir()] == ["lo"],
                "only guest loopback network interface",
            )
            fixture = verify_composite.CompositeFixture(
                Path("/opt/swpasskeyd"), directory
            )
            fixture.start()
            fixture.device.close()
            fixture.device = None
            report["usb_discovery"] = verify_composite.observations[-1]
            check(
                "dummy_hcd" in report["usb_discovery"]["kernel_link"],
                "actual guest USB hidraw path",
            )
            processes = (
                fixture.bridge.pid,
                fixture.process.pid,
                fixture.card.process.pid,
            )
            baseline = metrics(directory)
            check(
                baseline["make_cred_ok"] == baseline["get_assert_ok"] == 0,
                "fresh modified core has zero credential and assertion successes",
            )
            server = ThreadingHTTPServer(("127.0.0.1", 0), RP)
            origin = f"http://localhost:{server.server_port}"
            server.rp = Fido2Server(
                PublicKeyCredentialRpEntity(id="localhost", name="own browser RP"),
                verify_origin=lambda value: value == origin,
            )
            server.assertions = []
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            profile = directory / "profile"
            profile.mkdir()
            prefs = {
                "marionette.port": 2828,
                "security.webauth.webauthn_enable_usbtoken": True,
                "security.webauth.webauthn_enable_softtoken": False,
                "security.webauthn.ctap2": True,
                "browser.shell.checkDefaultBrowser": False,
                "browser.aboutwelcome.enabled": False,
                "browser.startup.homepage": "about:blank",
                "datareporting.policy.dataSubmissionEnabled": False,
                "toolkit.telemetry.enabled": False,
            }
            (profile / "user.js").write_text(
                "\n".join(
                    f"user_pref({json.dumps(k)}, {json.dumps(v)});"
                    for k, v in prefs.items()
                )
            )
            browser = launch(directory, profile, origin)
            report["first_browser"] = browser[4]
            credentials = {}
            counters = {}
            registrations = []
            for alg in [-7, -8, -35]:
                server.algorithm = alg
                server.rp.allowed_algorithms = [
                    PublicKeyCredentialParameters(type="public-key", alg=alg)
                ]
                before = metrics(directory)
                result = browser[2].script(script, ["register"], True)
                check(
                    result == {"verified": True},
                    f"browser USB registration and independent RP validation algorithm {alg}",
                )
                credentials[alg] = server.credential
                registrations.append(
                    {
                        "algorithm": alg,
                        "credential_sha256": hashlib.sha256(
                            server.credential.credential_id
                        ).hexdigest(),
                        "credential_id_bytes": len(server.credential.credential_id),
                        "transports": server.last_response["response"]["transports"],
                    }
                )
                check(
                    metrics(directory)["make_cred_ok"] == before["make_cred_ok"] + 1,
                    f"modified core processed browser registration algorithm {alg}",
                )
                for iteration in [1, 2]:
                    result = browser[2].script(script, ["login"], True)
                    check(
                        result == {"verified": True},
                        f"browser USB signature and increasing counter algorithm {alg} login {iteration}",
                    )
                check(
                    metrics(directory)["get_assert_ok"] >= before["get_assert_ok"] + 2,
                    f"modified core processed both browser assertions algorithm {alg}",
                )
                reject_tampering(server, alg)
                counters[alg] = server.counter
            report["first_metrics"] = metrics(directory)
            report["first_commands"] = browser[2].commands
            close_browser(browser)
            browser = None
            browser = launch(directory, profile, origin)
            report["second_browser"] = browser[4]
            for alg in [-7, -8, -35]:
                server.algorithm = alg
                server.credential = credentials[alg]
                server.counter = counters[alg]
                result = browser[2].script(script, ["login"], True)
                check(
                    result == {"verified": True},
                    f"same own credential verifies after browser restart algorithm {alg}",
                )
                counters[alg] = server.counter
            before = snapshot(fixture.serial)
            check(before is not None, "own USB present before management reboot")
            own = []
            for device in CtapHidDevice.list_devices():
                if device.descriptor.serial_number == fixture.serial:
                    own.append(device)
                else:
                    device.close()
            assert len(own) == 1
            with own[0] as connection:
                ManagementSession(connection).write_device_config(reboot=True)

            def reenumerated():
                value = snapshot(fixture.serial)
                descriptors = [
                    d for d in list_descriptors() if d.serial_number == fixture.serial
                ]
                return (
                    value
                    if value
                    and value["address"] != before["address"]
                    and len(descriptors) == 1
                    else None
                )

            after = verify_composite.wait_for(
                reenumerated, "USB reboot did not reenumerate"
            )
            report["usb_reboot"] = {"before": before, "after": after}
            check(
                processes
                == (fixture.bridge.pid, fixture.process.pid, fixture.card.process.pid)
                and all(
                    p.poll() is None
                    for p in [fixture.bridge, fixture.process, fixture.card.process]
                ),
                "USB reboot preserves all three emulator processes",
            )
            for alg in [-7, -8, -35]:
                server.algorithm = alg
                server.credential = credentials[alg]
                server.counter = counters[alg]
                result = browser[2].script(script, ["login"], True)
                check(
                    result == {"verified": True},
                    f"live browser verifies retained own credential after USB reboot algorithm {alg}",
                )
            final = metrics(directory)
            check(
                final["make_cred_ok"] == 3 and final["get_assert_ok"] >= 12,
                "modified core processed three registrations and at least twelve CTAP assertions for twelve verified browser responses",
            )
            challenges = [item["challenge_sha256"] for item in server.assertions]
            check(
                len(challenges) == len(set(challenges)) == 12,
                "every verified assertion uses a fresh RP challenge",
            )
            report["core_metrics_include_browser_internal_preflight_requests"] = True
            report.update(
                passed=True,
                browser_native_usb_webauthn_verified=True,
                browser_restart_verified=True,
                browser_live_usb_reboot_verified=True,
                final_metrics=final,
                registrations=registrations,
                assertions=server.assertions,
                second_commands=browser[2].commands,
            )
        except Exception as exc:
            report.update(passed=False, error=f"{type(exc).__name__}: {exc}")
            raise
        finally:
            close_browser(browser)
            if server:
                server.shutdown()
                thread.join(5)
                server.server_close()
            for name in ["firefox.log", "daemon.log", "usb.log"]:
                if (directory / name).exists():
                    print(
                        "SKE_BROWSER_DIAGNOSTIC",
                        name,
                        (directory / name).read_text(),
                        flush=True,
                    )
            if fixture:
                try:
                    fixture.stop()
                except Exception as exc:
                    report.update(
                        passed=False, cleanup_error=f"{type(exc).__name__}: {exc}"
                    )
                    for process in [
                        fixture.bridge,
                        fixture.process,
                        fixture.card.process,
                    ]:
                        if process and process.poll() is None:
                            process.terminate()
                            process.wait(10)
            report["test_count"] = len(checks)
            print("SKE_BROWSER_RESULT_BEGIN", flush=True)
            print(json.dumps(report), flush=True)
            print("SKE_BROWSER_RESULT_END", flush=True)
        if not report["passed"]:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
