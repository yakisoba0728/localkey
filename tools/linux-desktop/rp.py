#!/usr/bin/python3
"""Loopback-only relying party used by the real-browser VM tests."""
import json
from base64 import b64decode, b64encode
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from fido2 import features
from fido2.attestation import Attestation
from fido2.server import Fido2Server
from fido2.webauthn import AttestedCredentialData, PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity

features.webauthn_json_mapping.enabled = True
ORIGIN = "http://localhost:8000"
OWN_AAGUID = bytes.fromhex("6c6b65792d4c4b018f3a546e67696e65")
STATE = Path("/home/lkdesktop/localkey-rp-state.json")


def verify_attestation(obj, client_hash):
    Attestation.for_type(obj.fmt)().verify(obj.att_stmt, obj.auth_data, client_hash)
    if bytes(obj.auth_data.credential_data.aaguid) != OWN_AAGUID:
        raise ValueError("registration did not come from the own localkey profile")


class Party:
    def __init__(self, state_path=STATE):
        self.state_path = state_path
        self.server = Fido2Server(PublicKeyCredentialRpEntity(id="localhost", name="localkey VM test"),
                                 attestation="direct", verify_origin=lambda origin: origin == ORIGIN,
                                 verify_attestation=verify_attestation)
        self.server.timeout = 120000
        self.credentials = {}
        self.counters = {}
        self.pending = {}
        self.verified = []
        if state_path.exists():
            saved = json.loads(state_path.read_text())
            self.credentials = {user: AttestedCredentialData(b64decode(data, validate=True))
                                for user, data in saved["credentials"].items()}
            self.counters = saved["counters"]
            self.verified = saved["verified"]
            assert self.credentials.keys() == self.counters.keys()
            assert all(isinstance(counter, int) and counter >= 0 for counter in self.counters.values())

    def save(self):
        # Persist only RP public keys and acknowledged counters, never authenticator secrets.
        temporary = self.state_path.with_suffix(".tmp")
        temporary.write_text(json.dumps({"credentials": {user: b64encode(data).decode()
                                                        for user, data in self.credentials.items()},
                                         "counters": self.counters, "verified": self.verified}))
        temporary.replace(self.state_path)

    def handle(self, path, body):
        user = body["user"]
        if path == "/register/begin":
            options, state = self.server.register_begin(
                PublicKeyCredentialUserEntity(id=user.encode(), name=user, display_name=user),
                user_verification=body.get("uv", "discouraged"),
                resident_key_requirement=body.get("resident", "discouraged"),
                authenticator_attachment="cross-platform")
            self.pending[user] = {"state": state, "discoverable": False}
            return dict(options)
        if path == "/register/complete":
            auth = self.server.register_complete(self.pending.pop(user)["state"], body["credential"])
            self.credentials[user] = auth.credential_data
            self.counters[user] = auth.counter
            result = {"operation": "register", "user": user, "flags": int(auth.flags),
                      "aaguid": str(auth.credential_data.aaguid), "counter": auth.counter}
        elif path == "/login/begin":
            options, state = self.server.authenticate_begin(
                None if body.get("discoverable") else [self.credentials[user]],
                user_verification=body.get("uv", "discouraged"))
            self.pending[user] = {"state": state, "discoverable": bool(body.get("discoverable"))}
            return dict(options)
        elif path == "/login/complete":
            from fido2.webauthn import AuthenticationResponse
            response = AuthenticationResponse.from_dict(body["credential"])
            pending = self.pending.pop(user)
            if pending["discoverable"]:
                if response.response.user_handle is None:
                    raise ValueError("discoverable login did not return a user handle")
                user = response.response.user_handle.decode()
            if response.response.user_handle is not None and response.response.user_handle != user.encode():
                raise ValueError("user handle does not match the selected account")
            self.server.authenticate_complete(pending["state"], [self.credentials[user]], response)
            auth = response.response.authenticator_data
            if auth.counter and auth.counter <= self.counters[user]:
                raise ValueError("signature counter did not increase; possible stale backup or cloned key")
            self.counters[user] = auth.counter
            result = {"operation": "login", "user": user, "flags": int(auth.flags), "counter": auth.counter}
            if pending["discoverable"]:
                result["discoverable"] = True
                result["user_handle"] = user
        else:
            raise ValueError("unknown path")
        self.verified.append(result)
        self.save()
        return result


class Handler(BaseHTTPRequestHandler):
    def send(self, status, data, content_type="application/json"):
        encoded = data if isinstance(data, bytes) else json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        if self.path == "/":
            self.send(200, Path(__file__).with_name("rp.html").read_bytes(), "text/html; charset=utf-8")
        elif self.path == "/verified":
            self.send(200, PARTY.verified)
        else:
            self.send(404, {"error": "unknown path"})

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 65536 or self.headers.get("Origin") != ORIGIN:
                raise ValueError("invalid request length or origin")
            result = PARTY.handle(self.path, json.loads(self.rfile.read(length)))
            self.send(200, result)
        except (ValueError, KeyError, TypeError) as error:
            self.send(400, {"error": str(error)})


if __name__ == "__main__":
    PARTY = Party()
    HTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
