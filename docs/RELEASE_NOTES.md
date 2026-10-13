# localkey Linux desktop preview — unreleased

This release candidate is not ready for publication. Replace this paragraph with
the assigned VID/PID, final tag/commit and verification report before dispatching
the release workflow. PID application: https://github.com/pidcodes/pidcodes.github.com/pull/1310.

Linux x86_64 and aarch64 bundles provide the `localkeyd` CLI, systemd service,
desktop touch window, restricted polkit helper and state-preserving installer.
Prerequisites: systemd/logind, UHID, udev, Python 3.11+ with Tk, pkexec and a desktop
polkit authentication agent. The default profile is localkey's own identity.

Verify the archive checksum and signed build provenance before installation;
instructions are in `docs/RELEASE.md`. The bundle includes Apache-2.0 and original
third-party license notices. The manifest identifies the source commit, Rust
toolchain, CPU target, own VID/PID and binary checksum.

Back up `/etc/localkey/storage.key` and `/var/lib/localkey` together before updating.
Installation and uninstall preserve them. An old backup may rewind FIDO counters
and lose newer credentials; keep an independent account recovery method.

This is a software security key. It provides no hardware key isolation, physical
touch sensor or manufacturer-trusted attestation. The touch window cannot show
the relying party or origin; check the request in the calling app before touching.
The recorded tests cover Debian 13 desktop VMs with real Chromium and Firefox on
both architectures; report additional physical desktop coverage only after testing.
The 2026-10-13 private-test verification passed 43 checks per architecture,
including real inactive-local/SSH polkit denial, retained-grant reauthentication,
native browser account selection and full reboot with saved RP records. Repeat
these with the assigned identity before replacing this unreleased template.

Ubuntu GNOME/Wayland verification is still in progress. Stable Snapd 2.77.1
blocks the own UHID key in confined Chromium/Firefox. Signed Snapd 2.78 candidate
has the generic FIDO rule; candidate results must be stated separately from
stable Ubuntu support. See `docs/UBUNTU_DESKTOP_VERIFICATION.md` and verify the
stable fix and actual browser access before claiming that support.
