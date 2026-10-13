"""Fixture RP persistence and counter rejection, using the VM's python-fido2."""
import tempfile
from pathlib import Path
from unittest import TestCase, main, mock

from fido2.cose import ES256
from fido2.webauthn import Aaguid, AttestedCredentialData

from rp import Party


class PartyTests(TestCase):
    def test_restart_preserves_public_credentials_and_acknowledged_counters(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rp.json"
            party = Party(path)
            credential = AttestedCredentialData.create(Aaguid.NONE, b"fixture", ES256(
                {1: 2, 3: -7, -1: 1, -2: b"x" * 32, -3: b"y" * 32}))
            party.credentials["account"] = credential
            party.counters["account"] = 17
            party.pending["account"] = {"state": "unfinished"}
            party.verified = [{"user": "account", "counter": 17}]
            party.save()
            restarted = Party(path)
            self.assertEqual(restarted.credentials, party.credentials)
            self.assertEqual(restarted.counters, {"account": 17})
            self.assertEqual(restarted.verified, party.verified)
            self.assertEqual(restarted.pending, {})
            self.assertFalse(path.with_suffix(".tmp").exists())
            response = mock.Mock()
            response.response.user_handle = b"account"
            response.response.authenticator_data.counter = 17
            restarted.pending["account"] = {"state": {}, "discoverable": False}
            with mock.patch("fido2.webauthn.AuthenticationResponse.from_dict", return_value=response), \
                 mock.patch.object(restarted.server, "authenticate_complete"):
                with self.assertRaisesRegex(ValueError, "counter did not increase"):
                    restarted.handle("/login/complete", {"user": "account", "credential": {}})
            self.assertEqual(Party(path).counters, {"account": 17})
            response.response.authenticator_data.counter = 18
            response.response.authenticator_data.flags = 5
            restarted.pending["untrusted-label"] = {"state": {}, "discoverable": True}
            with mock.patch("fido2.webauthn.AuthenticationResponse.from_dict", return_value=response), \
                 mock.patch.object(restarted.server, "authenticate_complete"):
                result = restarted.handle("/login/complete", {"user": "untrusted-label", "credential": {}})
            self.assertEqual(result["user_handle"], "account")
            self.assertEqual(Party(path).counters, {"account": 18})
            response.response.user_handle = None
            restarted.pending["account"] = {"state": {}, "discoverable": True}
            with mock.patch("fido2.webauthn.AuthenticationResponse.from_dict", return_value=response):
                with self.assertRaisesRegex(ValueError, "did not return a user handle"):
                    restarted.handle("/login/complete", {"user": "account", "credential": {}})


if __name__ == "__main__":
    main()
