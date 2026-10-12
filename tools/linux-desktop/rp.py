#!/usr/bin/python3
"""Loopback-only relying party used by the real-browser VM tests."""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from fido2 import features
from fido2.attestation import Attestation
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity

features.webauthn_json_mapping.enabled = True
ORIGIN = "http://localhost:8000"
OWN_AAGUID = bytes.fromhex("6c6b65792d4c4b018f3a546e67696e65")


def verify_attestation(obj, client_hash):
    Attestation.for_type(obj.fmt)().verify(obj.att_stmt, obj.auth_data, client_hash)
    if bytes(obj.auth_data.credential_data.aaguid) != OWN_AAGUID:
        raise ValueError("registration did not come from the own localkey profile")


class Party:
    def __init__(self):
        self.server = Fido2Server(PublicKeyCredentialRpEntity(id="localhost", name="localkey VM test"),
                                 attestation="direct", verify_origin=lambda origin: origin == ORIGIN,
                                 verify_attestation=verify_attestation)
        self.server.timeout = 120000
        self.credentials = {}
        self.counters = {}
        self.pending = {}
        self.verified = []

    def handle(self, path, body):
        user = body["user"]
        if path == "/register/begin":
            options, state = self.server.register_begin(
                PublicKeyCredentialUserEntity(id=user.encode(), name=user, display_name=user),
                user_verification=body.get("uv", "discouraged"),
                resident_key_requirement=body.get("resident", "discouraged"),
                authenticator_attachment="cross-platform")
            self.pending[user] = state
            return dict(options)
        if path == "/register/complete":
            auth = self.server.register_complete(self.pending.pop(user), body["credential"])
            self.credentials[user] = auth.credential_data
            self.counters[user] = auth.counter
            result = {"operation": "register", "user": user, "flags": int(auth.flags),
                      "aaguid": str(auth.credential_data.aaguid), "counter": auth.counter}
        elif path == "/login/begin":
            options, state = self.server.authenticate_begin(
                None if body.get("discoverable") else [self.credentials[user]],
                user_verification=body.get("uv", "discouraged"))
            self.pending[user] = state
            return dict(options)
        elif path == "/login/complete":
            from fido2.webauthn import AuthenticationResponse
            response = AuthenticationResponse.from_dict(body["credential"])
            self.server.authenticate_complete(self.pending.pop(user), [self.credentials[user]], response)
            auth = response.response.authenticator_data
            if auth.counter and auth.counter <= self.counters[user]:
                raise ValueError("signature counter did not increase; possible stale backup or cloned key")
            self.counters[user] = auth.counter
            result = {"operation": "login", "user": user, "flags": int(auth.flags), "counter": auth.counter}
        else:
            raise ValueError("unknown path")
        self.verified.append(result)
        return result


PARTY = Party()


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
    HTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
