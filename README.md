# localkey

An unofficial software security-key emulator project. Its current compatibility target is the externally observable behavior of a YubiKey 5C Nano running firmware 5.7.4 on macOS and Linux. **Full equivalence has not been established.** It cannot reproduce manufacturer attestation trust, a secure element, or a physical touch sensor.

The repository starts from the verified v0.64.0 release. It contains the C++ and Python source, Mac/Linux compiled artifacts, versioned evidence, full file-hash manifest, documentation, and the release ZIP. The original reference is [`madeye/swpasskey`](https://github.com/madeye/swpasskey) at commit `59f08259202028888934597513515fc3cb8ca8c9`; its MIT notice is retained in [LICENSE](LICENSE). This project is not affiliated with Yubico or certified as a hardware authenticator.

Read [the repository handoff](REPOSITORY_HANDOFF.md) first when continuing work. [Implementation status](implementation-status.json) and the [compatibility matrix](compatibility-matrix.json) define what has and has not been verified. [Progress history](docs/PROGRESS_HISTORY.md), [evidence index](docs/EVIDENCE_INDEX.md), [validation procedure](docs/REPRODUCE_VALIDATION.md), and [open gaps](docs/OPEN_GAPS.md) preserve the prior work.

The release was verified with 59 Python reports containing 5,889 checks, Mac/Linux C++ suites of 140 cases and 13,748 assertions each, 82 independent Linux FIDO SDK checks, and an isolated no-NIC USB guest. The USB guest passed all 12 flows on an identical-image retry; its first run failed after 10 flows with a kernel/FunctionFS warning. Both raw logs are preserved in [v0.64 integration evidence](evidence/v64-integration/README.md), and the transport stability issue remains open. These checks do not establish identical physical firmware responses or timing.

The [release ZIP](release/security-key-emulator.zip) and one historical guest image use Git LFS because they exceed GitHub's regular Git file limit. Run `git lfs pull` after cloning. The ZIP SHA-256 is recorded in [the checksum file](release/security-key-emulator.zip.sha256), and [manifest.json](manifest.json) hashes every file in the original v0.64.0 release snapshot. `README.md`, `REPOSITORY_HANDOFF.md`, `.gitattributes`, and `release-tools/` are repository additions; they are outside that frozen manifest.

Run `python3 repo-tools/verify_snapshot.py` to check the complete release snapshot, ZIP and both USB guest attempts without contacting a device.

`pyproject.toml` and `source/CMakeLists.txt` retain older internal version strings from development. The authoritative delivered snapshot version is `manifest.json: 0.64.0`.
