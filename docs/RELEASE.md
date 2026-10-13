# Linux release procedure

The [Linux preview workflow](https://github.com/yakisoba0728/localkey/actions/workflows/linux-preview.yml)
checks x86_64 and aarch64 natively on Ubuntu 24.04. Each job runs engine tests,
Clippy, license/catalog checks, measurement tests, desktop/installer tests and
static-musl bundle staging. Verify both jobs for the exact final source commit.

The own PID request is [pid.codes #1310](https://github.com/pidcodes/pidcodes.github.com/pull/1310).
It requests `1209:4c4b`; submission is not allocation. The application still uses
private-test `1209:0001`, so no public binary can be built by this release process.
Source remains public under Apache-2.0.

## Before the first release tag

1. Wait for upstream allocation. Update all seven own product IDs together, the
   udev rule and identity fixtures. Keep the Yubico profile as an explicit test
   option. Verify the upstream PID page names `localkey` and this source repository.
2. Rebuild both architectures and repeat the recorded desktop and USB gadget
   checks using that assigned identity. Update the evidence and checksums in
   `docs/LINUX_DESKTOP_VERIFICATION.md`; the old private-test results do not verify
   the new identity.
3. The remaining Debian desktop flows passed on 2026-10-13: live inactive/SSH polkit denial,
   browser discoverable-account selection, expired-grant reauthentication and a full
   reboot with the same saved RP credentials/counters (43 checks per architecture).
   Repeat these with the assigned identity. Physical desktop/distro coverage remains
   limited; state the tested platforms accurately in the release notes.
   Ubuntu's stable Snapd 2.77.1 blocks the own UHID device. Candidate Snapd 2.78
   has the generic FIDO rule; its results must be reported separately. Before
   claiming default Ubuntu Snap support, verify the fix is in the stable channel
   and repeat actual confined browser access. PID allocation alone cannot fix
   this platform restriction.
4. Update `docs/RELEASE_NOTES.md` with the allocation, verified evidence and known
   limits. Run Linux preview CI on the final commit and wait for both jobs to pass.
   Review the final diff and commit it on `main`.

## Build a release candidate

No release tag or release is created by ordinary pushes. The manual
`.github/workflows/linux-release.yml` requires a version tag whose commit is on
`main` and matches `workspace.package.version`. Its preflight rejects dirty trees,
reserved/private-test PID ranges, mixed own PIDs and an upstream allocation that
belongs to another owner or source. It checks upstream without executing page content.

After the checks above, create the reviewed tag and dispatch from that tag, for
example for workspace version `0.1.0`:

```sh
git tag -a v0.1.0 -m 'localkey 0.1.0 Linux desktop preview'
git push origin v0.1.0
gh workflow run linux-release.yml --ref v0.1.0
```

Both native jobs rerun the checks, compile their own static-musl binary from the
tag, generate the public bundle without `--development`, verify both checksum
layers and stage install/uninstall without creating keys. Each archive receives
a GitHub OIDC/Sigstore build-provenance attestation, which is verified against the
repository, release workflow, tag and commit before upload. Actions are pinned to
commit SHAs. See [GitHub's attestation documentation](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).

The workflow creates a **draft prerelease**, with both archives, archive checksums
and provenance bundles. It never publishes the draft. Once allocation is valid,
the workflow's uploaded Actions artifacts are downloadable before publication;
dispatch only after the release checks above. Review the assets and notes, then
publish the draft through GitHub Releases. Do not upload development bundles,
VM disks, storage keys or sealed records.

## Verify a downloaded archive

Use the archive matching your CPU. Check provenance before extracting or running it:

```sh
sha256sum --check localkey-0.1.0-x86_64-unknown-linux-musl.tar.gz.sha256
gh attestation verify localkey-0.1.0-x86_64-unknown-linux-musl.tar.gz \
  --bundle provenance-x86_64-unknown-linux-musl.sigstore.json \
  --repo yakisoba0728/localkey \
  --signer-workflow yakisoba0728/localkey/.github/workflows/linux-release.yml \
  --source-ref refs/tags/v0.1.0 --deny-self-hosted-runners
```

The checksum detects corruption; the signed attestation identifies the CI build.
It does not establish hardware key protection or certify the software's security.
The packager alone records source metadata but cannot prove where an arbitrary
input binary came from. Follow this tagged CI build when claiming provenance.
