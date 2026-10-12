"""No real host devices or privileged installation: helper, format and bundle checks."""
import hashlib
import importlib.machinery
import importlib.util
import io
import os
from pathlib import Path
import socket
import struct
import subprocess
import tarfile
import tempfile
import threading
import unittest
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


control = load("localkey_control", HERE / "localkey-control")
packaging = load("package_linux", HERE.parent / "package_linux.py")


class DesktopTests(unittest.TestCase):
    def test_vm_disk_refuses_repository_before_changing_its_permissions(self):
        root = HERE.parent.parent
        with tempfile.NamedTemporaryFile() as archive:
            for directory in (root, Path("/")):
                with self.subTest(directory=directory):
                    before = directory.stat().st_mode
                    environment = {**os.environ, "LK_DESKTOP_DIR": str(directory), "LK_GECKODRIVER_TAR": archive.name}
                    result = subprocess.run(["bash", str(HERE.parent / "linux-desktop/build-disk.sh")],
                                            env=environment, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 2)
                    self.assertIn("outside the repository", result.stderr)
                    self.assertEqual(directory.stat().st_mode, before)

    def test_helper_rejects_paths_extra_arguments_and_destructive_commands(self):
        for words in [[], ["shutdown"], ["power-cycle"], ["down"], ["tap", "long", "extra"],
                      ["status", "--control", "/tmp/socket"], ["tap; shutdown"]]:
            with self.subTest(words=words), self.assertRaises(ValueError):
                control.relay(words, "/does-not-exist", None, None)

    def test_helper_sends_only_the_allowed_request_and_reports_errors(self):
        for words, reply, code in [(["tap", "long"], b"ok\n", 0),
                                   (["status"], b"presence=idle\nok\n", 0),
                                   (["tap"], b"error runner stopped\n", 1),
                                   (["tap"], b"", 1)]:
            with self.subTest(words=words, reply=reply), tempfile.TemporaryDirectory() as directory:
                path = str(Path(directory) / "control")
                with socket.socket(socket.AF_UNIX) as listener:
                    listener.bind(path)
                    listener.listen(1)
                    received = []

                    def server():
                        with listener.accept()[0] as peer:
                            received.append(peer.recv(256))
                            peer.sendall(reply)

                    thread = threading.Thread(target=server)
                    thread.start()
                    output = io.BytesIO()
                    self.assertEqual(control.relay(words, path, None, output), code)
                    thread.join(2)
                    self.assertFalse(thread.is_alive())
                    request = "tap pending" if words == ["tap"] else " ".join(words)
                    self.assertEqual(received, [(request + "\n").encode()])
                    self.assertEqual(output.getvalue(), reply)

    def test_watch_closes_when_the_ui_pipe_closes_even_without_presence_changes(self):
        with tempfile.TemporaryDirectory() as directory, socket.socket(socket.AF_UNIX) as listener:
            path = str(Path(directory) / "control")
            listener.bind(path)
            listener.listen(1)
            read_fd, write_fd = os.pipe()
            with os.fdopen(read_fd, "rb") as lifetime:
                output = io.BytesIO()
                thread = threading.Thread(target=control.relay, args=(["watch"], path, lifetime, output))
                thread.start()
                with listener.accept()[0] as peer:
                    self.assertEqual(peer.recv(256), b"watch\n")
                    peer.sendall(b"presence idle\n")
                    os.close(write_fd)
                    thread.join(2)
                    self.assertFalse(thread.is_alive(), "idle root watcher must retire on UI exit")
                    peer.settimeout(2)
                    self.assertEqual(peer.recv(1), b"")

    def test_polkit_allows_only_authenticated_active_sessions_and_fixed_helper(self):
        policy = ET.parse(HERE / "org.localkey.control.policy").getroot()
        action = policy.find("action")
        self.assertEqual(action.attrib["id"], "org.localkey.control")
        defaults = action.find("defaults")
        self.assertEqual([defaults.find(n).text for n in ("allow_any", "allow_inactive", "allow_active")],
                         ["no", "no", "auth_admin_keep"])
        self.assertEqual(action.find("annotate").text, "/usr/local/libexec/localkey-control")

    @staticmethod
    def binary(machine=183, program_type=1):
        data = bytearray(120)
        data[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", data, 18, machine)
        struct.pack_into("<Q", data, 32, 64)
        struct.pack_into("<HH", data, 54, 56, 1)
        struct.pack_into("<I", data, 64, program_type)
        return data

    def test_packager_rejects_wrong_architecture_dynamic_loader_and_truncation(self):
        target = "aarch64-unknown-linux-musl"
        packaging.validate_binary(self.binary(), target)
        for data in [b"not ELF", self.binary(62), self.binary(program_type=3), self.binary()[:70]]:
            with self.subTest(data=data[:6]), self.assertRaises(ValueError):
                packaging.validate_binary(data, target)

    def test_public_packaging_rejects_current_test_pid(self):
        with self.assertRaisesRegex(ValueError, "private-test PID"):
            packaging.collect_files(self.binary(), "aarch64-unknown-linux-musl", False, {})

    def test_archive_is_deterministic_and_never_overwrites(self):
        files = {"bin/localkeyd": (b"binary", 0o755), "README.md": (b"read me", 0o644)}
        with tempfile.TemporaryDirectory() as directory:
            first, second = [Path(directory) / name for name in ("a.tgz", "b.tgz")]
            packaging.write_archive(first, "localkey-test", files)
            packaging.write_archive(second, "localkey-test", files)
            self.assertEqual(hashlib.sha256(first.read_bytes()).digest(), hashlib.sha256(second.read_bytes()).digest())
            with self.assertRaises(FileExistsError):
                packaging.write_archive(first, "localkey-test", files)
            with tarfile.open(first) as archive:
                self.assertEqual(archive.getmember("localkey-test/bin/localkeyd").mode, 0o755)
                self.assertTrue(all(entry.uid == entry.gid == entry.mtime == 0 for entry in archive))

    def test_bundle_includes_standard_library_and_static_libc_notices(self):
        _, files = packaging.collect_files(self.binary(), "aarch64-unknown-linux-musl", True, {"packages": []})
        self.assertIn("licenses/rust-stdlib/COPYRIGHT-library.html", files)
        self.assertIn("licenses/rust-stdlib/licenses/MIT.txt", files)
        self.assertIn(b"Rich Felker", files["licenses/musl-1.2.5/COPYRIGHT"][0])


if __name__ == "__main__":
    unittest.main()
