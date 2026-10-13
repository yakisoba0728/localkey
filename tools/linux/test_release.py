"""Release trust boundaries; no network, tags, allocation or publishing is performed."""
from pathlib import Path
import subprocess
import sys
import tomllib
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import package_linux
import release_check

PROFILE = (package_linux.ROOT / "crates/lk-core/src/profile.rs").read_text()
VERSION = tomllib.loads((package_linux.ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
PAGE = b"---\nlayout: pid\nowner: localkey\nsource: https://github.com/yakisoba0728/localkey\n---\nSoftware key.\n"


class ReleaseTests(unittest.TestCase):
    def test_identity_reader_refuses_missing_mixed_and_oversized_identifiers(self):
        for source in [PROFILE.replace("fido: 0x0001", "fido: OTHER", 1),
                       PROFILE.replace("fido: 0x0001", "fido: 0x4c4b", 1),
                       PROFILE.replace("usb_vendor_id: 0x1209", "usb_vendor_id: 0x11209", 1)]:
            with self.subTest(source=source[:40]), mock.patch.object(Path, "read_text", return_value=source):
                with self.assertRaises(ValueError):
                    package_linux.own_usb_identity()

    def test_public_identity_rejects_reserved_ranges(self):
        for product in [0, 1, 0x1000, 0x1FFF]:
            with mock.patch.object(package_linux, "own_usb_identity", return_value=(0x1209, product)):
                with self.assertRaisesRegex(ValueError, "private-test PID"):
                    package_linux.require_public_identity()
        with mock.patch.object(package_linux, "own_usb_identity", return_value=(0x1209, 0x4C4B)):
            self.assertEqual(package_linux.require_public_identity(), (0x1209, 0x4C4B))

    def check(self, *, git=None, page=PAGE, tag=None, ancestor_error=None):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = page
        with mock.patch.object(package_linux, "require_public_identity", return_value=(0x1209, 0x4C4B)), \
             mock.patch.object(subprocess, "check_output", side_effect=git or ["abc\n", "abc\n", b""]), \
             mock.patch.object(subprocess, "run", side_effect=ancestor_error) as ancestor, \
             mock.patch.object(release_check.urllib.request, "urlopen", return_value=response) as opened:
            release_check.check_release(tag or f"v{VERSION}")
            ancestor.assert_called_once_with(["git", "merge-base", "--is-ancestor", "abc", "origin/main"],
                                             cwd=release_check.ROOT, check=True)
            self.assertIn("/1209/4C4B/index.md", opened.call_args.args[0])

    def test_clean_tag_and_matching_upstream_allocation_pass(self):
        self.check()

    def test_wrong_version_moved_tag_and_dirty_checkout_fail(self):
        for options in [{"tag": "v999.0.0"}, {"git": ["abc\n", "def\n"]},
                        {"git": ["abc\n", "abc\n", b" M README.md\n"]}]:
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.check(**options)

    def test_unmerged_tag_fails(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.check(ancestor_error=subprocess.CalledProcessError(1, "git"))

    def test_wrong_allocation_owner_source_or_page_fail(self):
        for page in [PAGE.replace(b"owner: localkey", b"owner: someone-else"),
                     PAGE.replace(b"/yakisoba0728/localkey", b"/someone/other"), b"not an allocation"]:
            with self.subTest(page=page), self.assertRaises(ValueError):
                self.check(page=page)


if __name__ == "__main__":
    unittest.main()
