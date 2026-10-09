# /// script
# requires-python = ">=3.11"
# dependencies = ["fido2==2.2.1", "playwright==1.63.0"]
# ///
"""Verify a browser authenticator using navigator.credentials and Fido2Server.

Modes:
  virtual: Chrome's development virtual authenticator, with simulated presence.
  native:  OS HID authenticator; no CDP authenticator is injected. The user
           chooses Security key in Chrome and approves the swpasskey dialog.

Requires the installed Google Chrome application. Uses a fresh browser profile
and a server bound only to 127.0.0.1. No real account or physical YubiKey is
selected by this script. Native registration may offer other attached devices:
approve the swpasskey dialog to choose the software device.
"""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import tempfile
import threading

from fido2.server import Fido2Server
from fido2.webauthn import AuthenticationResponse, PublicKeyCredentialRpEntity
from playwright.sync_api import sync_playwright


PAGE = """<!doctype html><html lang="ko"><meta charset="utf-8">
<title>로컬 보안키 테스트</title>
<style>body{max-width:680px;margin:70px auto;font:17px system-ui;background:#f6f7f9;color:#17202a}
button{font:inherit;padding:12px 20px;margin:0 12px 20px 0;border:1px solid #888;border-radius:7px;cursor:pointer}
pre{padding:20px;background:white;border-radius:8px;white-space:pre-wrap;line-height:1.6}</style>
<h1>로컬 보안키 테스트</h1><p>테스트 계정의 보안키를 등록하고, 새 로그인 요청의 서명을 검증합니다.</p>
<button id="register">1. 보안키 등록</button><button id="login">2. 인증 서명 검증</button>
<pre id="log">준비됨</pre>
<script>
window.results={}; window.errors=[];
const log=document.getElementById('log');
function decode(s){return Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));}
function encode(b){return btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');}
async function post(path,body={}){
  const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const value=await r.json(); if(!r.ok)throw Error(value.error); return value;
}
function options(value){
  const p=value.publicKey;p.challenge=decode(p.challenge);
  if(p.user)p.user.id=decode(p.user.id);
  for(const name of ['allowCredentials','excludeCredentials'])if(p[name])p[name]=p[name].map(c=>({...c,id:decode(c.id)}));
  return value;
}
function serialize(c){
  const response={clientDataJSON:encode(c.response.clientDataJSON)};
  if(c.response.attestationObject)response.attestationObject=encode(c.response.attestationObject);
  else{response.authenticatorData=encode(c.response.authenticatorData);response.signature=encode(c.response.signature);
    response.userHandle=c.response.userHandle?encode(c.response.userHandle):null;}
  return {id:c.id,rawId:encode(c.rawId),type:c.type,response,authenticatorAttachment:c.authenticatorAttachment,
    clientExtensionResults:c.getClientExtensionResults()};
}
async function run(kind){
  try{
    log.textContent+='\\n'+(kind==='register'?'등록 요청 중…':'인증 요청 중…');
    const begin=await post('/'+kind+'/options');
    const credential=kind==='register'?await navigator.credentials.create(options(begin.options)):await navigator.credentials.get(options(begin.options));
    const end=await post('/'+kind+'/finish',{requestId:begin.requestId,credential:serialize(credential)});
    window.results[kind]=end;log.textContent+='\\n'+(kind==='register'?'등록 성공':'인증 서명 검증 성공');
  }catch(e){window.errors.push(String(e));log.textContent+='\\n실패: '+e;}
}
document.getElementById('register').onclick=()=>run('register');
document.getElementById('login').onclick=()=>run('login');
</script></html>"""


def run_browser(mode: str, report_path: Path, screenshot_path: Path | None):
    pending = {}
    credential = None
    origin = None
    events = []
    server_verifier = Fido2Server(
        PublicKeyCredentialRpEntity(id="localhost", name="Local security-key test"),
        attestation="none", verify_origin=lambda value: value == origin,
    )

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def send_json(self, value, status=200):
            data = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path != "/":
                self.send_error(404)
                return
            data = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            nonlocal credential
            try:
                length = int(self.headers.get("Content-Length", 0))
                if not 0 <= length <= 128_000:
                    raise ValueError("Invalid body length")
                data = json.loads(self.rfile.read(length))
                if self.path == "/register/options":
                    options, state = server_verifier.register_begin(
                        {"id": b"local-fixture-user", "name": "local-fixture-user", "displayName": "Local fixture"},
                        resident_key_requirement="required", user_verification="discouraged",
                        authenticator_attachment="cross-platform",
                    )
                elif self.path == "/login/options":
                    if credential is None:
                        raise ValueError("Register first")
                    options, state = server_verifier.authenticate_begin([credential], user_verification="discouraged")
                elif self.path == "/register/finish":
                    kind, state = pending.pop(data["requestId"])
                    if kind != "/register/options":
                        raise ValueError("Unexpected request type")
                    auth_data = server_verifier.register_complete(state, data["credential"])
                    credential = auth_data.credential_data
                    value = {"result": "PASS", "credential_id": credential.credential_id.hex(), "aaguid": str(credential.aaguid)}
                    events.append({"operation": "registration", **value})
                    self.send_json(value)
                    return
                elif self.path == "/login/finish":
                    kind, state = pending.pop(data["requestId"])
                    if kind != "/login/options":
                        raise ValueError("Unexpected request type")
                    response = AuthenticationResponse.from_dict(data["credential"])
                    server_verifier.authenticate_complete(state, [credential], response)
                    value = {"result": "PASS", "signature_verified": True, "user_presence": response.response.authenticator_data.is_user_present(), "counter": response.response.authenticator_data.counter}
                    events.append({"operation": "authentication", **value})
                    self.send_json(value)
                    return
                else:
                    self.send_json({"error": "Unknown endpoint"}, 404)
                    return
                request_id = secrets.token_hex(16)
                pending[request_id] = (self.path, state)
                serializable = dict(options)
                serializable["publicKey"]["timeout"] = 120_000
                serializable["publicKey"]["hints"] = ["security-key"]
                self.send_json({"requestId": request_id, "options": serializable})
            except Exception as exc:
                self.send_json({"error": str(exc)}, 400)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    origin = f"http://localhost:{httpd.server_port}"
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    root = Path(__file__).resolve().parents[2]
    scratch = root / "work"
    scratch.mkdir(exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix="browser-fixture-", dir=scratch) as profile:
            with sync_playwright() as playwright:
                context = playwright.chromium.launch_persistent_context(
                    profile,
                    executable_path="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                    headless=mode == "virtual", chromium_sandbox=True,
                    viewport={"width": 1000, "height": 700},
                )
                page = context.pages[0]
                if mode == "virtual":
                    cdp = context.new_cdp_session(page)
                    cdp.send("WebAuthn.enable", {"enableUI": False})
                    cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
                        "protocol": "ctap2", "ctap2Version": "ctap2_1", "transport": "usb",
                        "hasResidentKey": True, "hasUserVerification": True,
                        "isUserVerified": True, "automaticPresenceSimulation": True,
                    }})
                page.goto(origin)
                print(f"BROWSER_READY: mode={mode}; {origin}", flush=True)
                for button, result_name in [("register", "register"), ("login", "login")]:
                    page.click("#" + button)
                    print(f"REQUEST_STARTED: {button}", flush=True)
                    page.wait_for_function(
                        "name => window.results[name] || window.errors.length",
                        arg=result_name, timeout=150_000,
                    )
                    errors = page.evaluate("window.errors")
                    if errors:
                        raise RuntimeError("; ".join(errors))
                    print(f"BROWSER_{button.upper()}_PASS", flush=True)
                report = {"result": "PASS", "mode": mode, "origin": origin,
                    "browser": context.browser.version if context.browser else "Google Chrome",
                    "verification": "navigator.credentials plus Yubico Fido2Server",
                    "cdp_virtual_authenticator_used": mode == "virtual", "events": events}
                if screenshot_path:
                    page.screenshot(path=str(screenshot_path))
                report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
                context.close()
                print(f"Report: {report_path}", flush=True)
    finally:
        httpd.shutdown()
        httpd.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["virtual", "native"], default="virtual")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--screenshot", type=Path)
    args = parser.parse_args()
    run_browser(args.mode, args.report, args.screenshot)
