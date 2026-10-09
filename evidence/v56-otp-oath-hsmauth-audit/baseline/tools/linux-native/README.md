Current0.41 adds the original large-prefix64 runtime-PM fixture and gate. The
534 native checks cover six response boundaries across manual-on, native FIDO
SDK and new-usbfs-open wake paths (18 same-generation cycles), original AIO
request preservation, exact remaining first-packet bytes, original PIV/FIDO
keys with19 signatures each, revoked PIN/admin authorization and HOTP18.
A3073 reply retains its original first3072 packet, while the later response
chain is denied as inactive after card session reset. Complete original
chained APDU survival and raw io_event.res capture are not claimed. These
checks do not verify stock-libccid large IO, physical behavior or macOS
registration. Prior source40/161/534 prototype evidence is preserved separately.

# Linux native verification

From the package root, with local Docker available:

```sh
python3 tools/linux-native/verify-linux.py
```

This builds the source with GCC 14 for Linux ARM64, runs C++ tests, then boots
Ubuntu kernel 6.8.0-146-generic under QEMU TCG. The guest has no network adapter
or host device passthrough. It creates only fresh software credentials inside
the guest. Artifacts and logs go to `work/linux-native-artifacts`.

The unmodified python-fido2 2.2.1 client enumerates real kernel UHID/hidraw
devices. The OTP client uses native feature-report ioctls; keyboard checks read
actual guest evdev events. PC/SC checks run a private pcscd with the compiled
Linux IFD provider and use stock pyscard/Yubico client connections.

The delivered checkpoint has 75 native FIDO checks and 25 native OTP,
keyboard and PC/SC checks. Linux C++ tests repeat the same 120 cases and 11,620
assertions used on macOS; these counts are not distinct firmware behaviors.

The guest also creates one full-speed USB OTP/FIDO/CCID composite device with
Linux FunctionFS/ConfigFS and an own dummy_hcd controller. It repeats the 75 FIDO checks
through actual USB HID, then verifies stock ykman discovery/grouping, native
OTP feature/HMAC and keyboard events, and actual USB CCID through the unmodified
libccid/pcscd/pyscard clients. PIV, OATH, OpenPGP, SCP03, long APDUs and restart
use the same own software card. The exact additional count is in the report.

Management requests through stock native FIDO, OTP and CCID clients now
reenumerate the same running USB controller. The 49 reboot checks cover all
seven interface combinations, an unchanged-profile reboot, rejected unlocks,
settings without reboot, preserved own credentials/PIN/OTP key/serial and
invalidated FIDO PIN tokens/key agreement. The guest runs the standard
systemd-udevd service so pcscd receives real USB removal/addition notifications.
Reboot response grace (100 ms), unread-reply limit (2 seconds) and Linux
disconnect interval (100 ms) are software timing models, not firmware measurements.
The portable `tools/verify_usb_reboot.py` additionally checks persistence failure
rollback and peer PIV authorization revocation on private software state.

Stock Firefox 157.0.1 for Linux ARM64 is verified through that actual USB path.
Its running preferences enable USB and disable the browser software token.
An own localhost RP checks ES256, Ed25519 and ES384 registrations and twelve
assertions, including browser restart and USB management reboot while the
browser remains running. Challenge, exact origin, signature and increasing
counters are independently verified; altered responses are rejected. Core
success metrics are recorded separately because Firefox also sends internal
CTAP preflight requests. No browser virtual authenticator or replacement
WebAuthn JavaScript is used. The own test fixture explicitly auto approves
modeled presence. This basic suite does not cover PIN/UV or discoverable
credentials; those are covered by the separate resident suite below.
The official archive checksum and runtime binary hashes are recorded.

The v0.29 resident browser suite adds 68 checks through the same real USB path.
Two own accounts for each of ES256, Ed25519 and ES384 create six resident keys
with PIN and user verification required. The first real password dialog rejects
an incorrect own PIN, then accepts the correct PIN. The initial core PIN-error
metrics and restored retry count are checked before USB reboot; the failure
counter resets when the PIN manager is reconstructed at reboot.

Eighteen assertions omit `allowCredentials` and select the requested account
using the existing notification button or account menu. All six accounts are
checked initially, after restarting Firefox with the same profile, and after
USB management reboot in the same live browser and three live emulator services.
The independent RP validates signatures, challenges, exact origins, UV,
user handles and increasing counters. Thirty modified challenge/origin/signature/
UV/userHandle responses must be rejected. Real browser security-notification
delay and active-window conditions are respected without changing them.

Classic WebDriver commands can dismiss an open password prompt. A guarded
own-origin chrome-window timer is installed before the request; it fills the
existing own PIN dialog and clicks existing UI controls. The host waits on
its independently validating RP while that dialog is open. No WebAuthn service
callback is invoked directly, no JavaScript WebAuthn API is replaced and no
browser virtual authenticator is created. Both actual account-button and
menu-item selection are required. `linux-browser-resident-result.json` records
the 68 checks, UI evidence, initial/final metrics and all three phases separately
from the original 43-check `linux-browser-result.json` suite.
The resident suite does not cover extensions or attestation consent; separate
suites below cover PRF and consent. LargeBlob, other browsers, macOS modified
runtime integration and physical touch remain unverified. Modeled presence is auto
approved only in fresh own test state; manufacturer trust is not reproduced.

The v0.30 PRF suite adds 123 checks with six own resident keys and thirty
independently verified browser assertions. An unmodified python-fido2 client
performs UV-bound `hmac-secret` operations for six reference assertions;
credential signatures and ECDH/AES/HMAC processing are verified independently.
WebAuthn inputs are converted to CTAP salts with the specified
`SHA256("WebAuthn PRF" || NUL || input)` encoding. Eighteen dual-output browser
assertions, spanning initial operation, browser restart and live USB reboot,
must match those SDK outputs. Six single-output assertions must match the
first reference and omit the second output. Six `evalByCredential` assertions
must select per-credential inputs over a deliberately different global fallback.
`credProps.rk` and PRF enabled output are verified at registration; all six keys
have distinct PRF outputs. Browser assertions and SDK references are recorded
separately, including their effect on core success counts.

`linux-browser-prf-result.json` and `native.browser_prf_usb` preserve this
scope separately from the basic and resident suites. Remaining extension edge
cases, largeBlob, attestation consent and other browsers are not claimed by
this PRF suite. The guest budget is 1800 seconds for the complete isolated TCG
pipeline; this is a test-runtime limit, not a physical firmware timing claim.

The separate v0.30 attestation suite performs 40 checks using the actual
Firefox Allow and Block notification buttons. Each of the three algorithms
creates one granted and one denied resident credential. Granted packed own
self-attestation signatures are independently verified, and six modified
signature/client-hash cases are rejected. Denial produces the empty `none`
attestation statement while Firefox retains the own model AAGUID, matching
its public `AttestationObject::anonymize` implementation. The initial test
assumption that denial zeroed the AAGUID was corrected after source inspection;
its failed scratch evidence is retained outside the delivered archive.

All six granted/denied keys still authenticate with RP-verified signatures,
UV, user handles, challenges, exact origins and increasing counters before
and after browser restart (twelve assertions). The running direct-attestation
bypass preference must be false. Existing consent UI controls, focus and
security-notification delay are used without direct service callbacks or
response replacement. `linux-browser-attestation-result.json` preserves this
scope separately. No manufacturer chain or manufacturer trust is reproduced;
other attestation edge cases, browsers and macOS runtime remain unverified.

Persistent private card RPC connections now survive idle periods; an absolute
30-second deadline starts when an incomplete frame begins. The portable CCID
checks accelerate that deadline to test idle reuse, truncated headers/bodies,
fragmented requests, session cleanup and unchanged state on rejection. This
corrects the expired CCID connection exposed by the live-browser USB reboot.

Public SDK matching IDs are explicitly selected by the guest fixture. USB
strings, serial, AAGUID, keys and attestation are independent software identities.
The stock CCID driver substitutes its built-in reader name for these public
IDs; that name is not evidence of a physical device or manufacturer trust.
The independent valid T=1 ATR `3bf011000001e0` is classified USB by the SDK.

The upstream v6.8 dummy_hcd source is SHA-256 pinned in Dockerfile and compiled
against exact 6.8.0-146-generic headers/symbol versions. A separately licensed
GPL patch adds the optional `requested_ep_addresses` parameter, disabled by
default. The private initializer explicitly enables it; the callback allocates
existing virtual-controller resources at function-requested endpoint addresses.
No identity or credentials are contained in that allocation policy.
The source, patch and module hashes are recorded and verified at runtime.
All seven interface profiles and unchanged-profile reboot preserve requested
addresses. Actual kernel FIDO+CCID configuration125 and HID report34 bytes
match the saved public reference, without opening that physical device.
The earlier unmodified-controller five-byte remapping observation is preserved
in `linux-functionfs-descriptor-comparison-v27.json`. Other/default UDC
address allocation remains unverified. Only the isolated guest
loads that unsigned test module. The host loads no module or virtual keyboard.
GadgetFS cannot stall a nonzero control OUT transfer after receiving its data;
that rejection behavior, additional UDCs, bus state changes and timing remain
conformance gaps. Four GadgetFS native USB OTP attempts failed at different feature
operations, including an assembled HMAC frame with an invalid CRC. The FunctionFS path verifies 128 consecutive fixed-64-byte HMAC requests with
diagnostic tracing disabled and no SDK retries or explicit transport delay.
GadgetFS remains unreliable; production timing and the exact kernel race are
unverified. The optional controller policy establishes captured configuration
equivalence only on that private virtual UDC. Other controllers can remap
endpoint numbers; the comparison report records this scope. See
`linux-otp-timing-observation.json`. Reference firmware equivalence,
manufacturer attestation, physical touch, OS keychain storage and modified
macOS registration remain unverified.

The device fixture scripts require the private guest marker before they run.
They are not intended to install a driver or change an existing host pcscd.
Ubuntu repository availability and an ARM64 Docker runtime are needed to
rebuild the guest; source compilation alone does not prove native recognition.

API references: [Linux GadgetFS ABI](https://github.com/torvalds/linux/blob/v6.8/include/uapi/linux/usb/gadgetfs.h),
[GadgetFS implementation](https://github.com/torvalds/linux/blob/v6.8/drivers/usb/gadget/legacy/inode.c),
[dummy_hcd](https://github.com/torvalds/linux/blob/v6.8/drivers/usb/gadget/udc/dummy_hcd.c),
[endpoint autoconfiguration callback](https://github.com/torvalds/linux/blob/v6.8/drivers/usb/gadget/epautoconf.c).
[Yubico management configuration](https://developers.yubico.com/yubikey-manager/Config_Reference.html),
[PC/SC udev notifications](https://github.com/LudovicRousseau/PCSC/blob/master/src/hotplug_libudev.c).
[Mozilla Marionette protocol](https://firefox-source-docs.mozilla.org/remote/marionette/Protocol.html),
[Firefox USB/softtoken preferences](https://github.com/mozilla-firefox/firefox/blob/release/modules/libpref/init/StaticPrefList.yaml),
[Firefox CTAP preflight](https://github.com/mozilla-firefox/firefox/blob/release/third_party/rust/authenticator/src/ctap2/mod.rs).

FunctionFS launch on an operator-prepared Linux UDC uses:

```sh
python3 emulator.py usb --card-socket /path/card.sock --fido-socket /path/fido.sock \
  --functionfs /dev/ffs-ske --configfs-gadget /sys/kernel/config/usb_gadget/ske \
  --controller YOUR_UDC_NAME
```

Prepare one `functions/ffs.ske` function linked into `configs/c.1`, the
`strings/0x409` directory, and a FunctionFS mount named `ske`. The supplied
gadget must be unbound. The transport publishes software identity/settings,
binds the specified controller and unbinds it on shutdown or management
reboot. It does not install kernel modules or mount filesystems on a host.
The isolated guest initializer demonstrates this setup on its own dummy UDC.
Host endpoint numbers may differ from logical protocol-model addresses on
controllers without the verified optional allocation policy.
[FunctionFS](https://docs.kernel.org/usb/functionfs.html),
[ConfigFS gadget setup](https://docs.kernel.org/usb/gadget_configfs.html),
[Linux 6.8 FunctionFS implementation](https://github.com/torvalds/linux/blob/v6.8/drivers/usb/gadget/function/f_fs.c).


The v0.31 Chromium suite uses the stock Debian ARM64 browser154.0.8037.92
(package154.0.8037.92-1~deb13u1). Signed APT installation, the Debian base image
digest and the browser ELF SHA-256 are pinned in Dockerfile. A separate Debian
chroot keeps its libc ABI separate from the Ubuntu guest. No host device,
browser profile or credential store is copied. Guest assembly uses a private
case-sensitive container directory, then exports kernel/initramfs/manifest;
this handles Debian PAM/pam manpage names even on case-folding macOS volumes.
The full two-browser guest uses4GiB RAM under TCG. Browser runtime packages are
not bundled in the source ZIP, and future APT retention is not guaranteed.

The29 checks register ES256/Ed25519 own resident credentials, write792-byte
blobs from the actual browser and independently validate PIN/UV protocol2
SDK signatures, user handles, credential binding, decrypted browser blobs and
wrong-key isolation. The SDK replaces each blob with1056 bytes; four actual
browser reads after same-profile restart/liveUSB reboot must match its hashes
and lengths. Six browser assertions and two SDK reference assertions are
counted separately. The three service processes persist acrossUSB addresses.
Own guest AT-SPI focuses the real PIN field; AT-SPI text or guest XTest key
events type it and actual Next buttons submit it only after all15 characters
are present. Zero PIN failures and8 retries are checked before/after reboot.
Session D-Bus uses its --fork readiness barrier before starting accessibility,
which explicitly sets/reads IsEnabled and obtains its real bus address.
Xvfb/XTest run only inside this guest; no host keyboard is accessed. Chromium
sandbox is disabled only in this isolated no-NIC test guest. Localhost CDP is
restricted to Browser.getVersion, Runtime.evaluate and Page.navigate; no
WebAuthn virtual authenticator, API replacement or direct service callback.

The suite also records a real ES384 creation request rejected by this stock
Chromium parser as NotAllowedError. Its actual rejected COSE key is EC2,
algorithm-35, curve2,48-byte coordinates. An independent UV-bound SDK assertion
verifies that same device-created credential, signature and user handle. Thus
there are two successful RP registrations but three credentials on the device.
The exact upstream revision's EC2 parser accepts P256 curve1/32-byte coordinates;
Debian patches were not independently reproduced. The emulator never substitutes
P256 or falsely marks ES384 successful. The report and compatibility matrix
preserve this client boundary and do not claim all algorithms/extensions/OSes.
`validate-browser-largeblob.py` joins the browser reads to independent SDK
references, checks actual UI actions/error/counts and validates explicit scope.
Host result gates join runtime/helper/binary/controller hashes to guest metadata.

Evidence: `linux-browser-largeblob-result.json`, `linux-native-result.json`,
`chromium-es384-parser-observation.json`.
Primary references: [WebAuthn largeBlob](https://www.w3.org/TR/webauthn-3/#largeBlob-extension),
[pinned Chromium EC2 parser](https://raw.githubusercontent.com/chromium/chromium/334b65d254ccc35df4fca82706d1753227b01039/device/fido/public_key.cc).


The v0.32 USB state suite adds91 checks using real kernel control/bulk/interrupt
transfers to a fresh owned device. All six endpoints independently pass native
GET_STATUS, SET_FEATURE HALT, host EPIPE and repeated libusb CLEAR_HALT checks.
Three USBDEVFS_RESET calls and SET_CONFIGURATION0/1 preserve the same three
service processes and exact persisted state bytes. Seven independent native
PIN/UV protocol2 assertions verify the retained ES256 credential, RP hash,
user handle, signature and increasing counters; native OTP SDK HMAC outputs
match the independently calculated retained key across recovery phases.

A real card-service stdin prompt (without --testing) holds an OATH HOTP
request. Actual USB CCID waiting-time extension is observed while a fresh
python-fido2 client completes GetInfo and FIDO PING. A fourth actual USB reset
cancels the pending request without committing its HOTP counter. New CCID
sequence, unmodified SDK recovery and a new terminal approval verify no stale
response and require a fresh approval; independent HMAC dynamic truncation matches the
one newly committed HOTP result. Terminal approval models software presence;
the separate owned FIDO fixture uses its explicit --testing presence mode.
This does not verify physical touch. No host keyboard or device is passed.

Version0.31 failed GetInfo during this pending request: its private capability
query waited for the shared card-state lock and returned CTAP OTHER after the
RPC timeout. Version0.32 reads the existing committed USB snapshot for this
strictly validated read-only request, without taking the transaction lock or
flushing card state. Portable regressions additionally prove failed/in-flight
settings writes never publish the candidate mask and a successful commit does.
All other mutating card operations retain their transaction serialization.

`validate-usb-state.py` checks scope, all91 cases, descriptor/serial retention,
seven independently verified assertions and pending-operation recovery. Host
gates require four actual kernel reset events and join service, helper, native
binary and optional-controller hashes to the build manifest. Evidence is in
`linux-usb-state-result.json`, `ccid-fido-concurrency-observation.json`,
`ccid-result.json`, `usb-reboot-result.json` and `linux-native-result.json`.
The observed UDC is dummy_hcd with requested_ep_addresses=1; production UDCs,
additional power-management/backpressure paths, physical firmware reset/PIN-token semantics,
exact timing, default-controller equivalence and macOS registration remain
unverified. These counts are transport scenarios, not distinct firmware features.

Version0.33 separately verifies50 actual kernel device-PM checks, including
dummy UDC disconnect/re-enumeration and a pending CCID request. Version0.34
verifies113 same-generation data/ZLP interruption checks with12 real kernel
write EINTR returns and owned-thread SIGUSR1 deliveries. The0.35 verifier waits
for both events: a read after write-exit can precede the signal-delivery event.
The first failing snapshot and the correction are preserved in
`linux-usb-interrupt-prior-v35-trace-failure.json` and
`usb-interrupt-trace-observation.json`. This correction changes the observer;
the USB bridge implementation remains the0.33 correction.

Version0.35 adds52 actual runtime-PM checks in `verify-usb-runtime.py` and
`validate-usb-runtime.py`. The reference-equal FIDO+CCID profile6 reaches
kernel runtime status suspended with increasing suspended time. Manual-on,
native FIDO SDK access and native CCID/OATH SDK access each resume it, with
USBDEVFS_WAIT_FOR_RESUME returning zero. Owned-device rpm_suspend/rpm_resume
returns and USB callback probes independently confirm the real kernel path.
The same processes, USB address, configuration and HID bindings survive;
persistent files are unchanged while suspended. Four PIN/UVp2 assertions
verify with the original software credential, and a native OATH result
matches independent HOTP counter0 and commits once.

The stock OTP+FIDO+CCID profile7 remains active at zero usage. Its actual
kernel diagnostic reports remote wakeup needed for autosuspend, with
autosuspend_check returning EOPNOTSUPP and the owned USB runtime suspend
returning EAGAIN. The test retains stock drivers and descriptors. Only
profile6 runtime PM and profile7 refusal are established here; other
profiles, remote wakeup, broader concurrent/cancelled pending-transfer runtime PM, full platform sleep,
production UDCs and physical timing/token behavior remain unverified.
Evidence: `linux-usb-runtime-result.json`, `usb-runtime-power-observation.json`,
`linux-usb-runtime-reference-provenance.json` and `linux-native-result.json`.


Version0.36 adds102 actual queued profile6 runtime-PM checks in
`verify-usb-runtime-pending.py` and `validate-usb-runtime-pending.py`. Three
original unread19-byte HOTP responses survive real autosuspend and manual-on,
native FIDO SDK, or new usbfs-open resume. The preexisting libusb usbfs file is
borrowed only after validating its unique owned device node and writable
character-device identity; ALLOW_SUSPEND releases its runtime-PM reference and
WAIT_FOR_RESUME restores it. No extra file remains open to prevent suspension.
Native FIDO GetInfo/PING executes while the original CCID response remains
unread. The same ARM64 write thread/fd/buffer, USB generation, stock driver
bindings, three services and exact persisted bytes survive each suspension.
Original sequence responses independently match HMAC and commit HOTP0→3 once
per request; following unchanged SDK requests expose stale/duplicate data.

A separate cycle first receives one exact64-byte CCID response, then suspends
with the original zero-length terminator queued. Resume delivers only that
terminator; a following unchanged PIV SDK request retains the correct new
sequence and persistent plaintext. The50-byte opaque object is a transport
fixture, not a valid CHUID. Ordinary PIV reads reencrypt unchanged plaintext;
byte preservation is asserted during suspension and ZLP completion rather than
after a new read transaction. Five PIN/UV protocol2 ES256 signatures verify
against the original own public key with explicit credential/user/RP binding.
The USB source/bridge remain byte equal to the corrected33 implementation.

This scope is the private no-NIC dummy_hcd profile6 fixture. It does not verify
other profiles/UDCs, full-message concurrency/cancellation/configuration races,
remote wakeup, physical timing/touch/token semantics, full platform sleep or
macOS native registration. Both presence paths explicitly auto approve only
fresh owned fixtures. No real key or host device enters the guest.
Evidence: `linux-usb-runtime-pending-result.json`,
`usb-runtime-pending-observation.json` and `linux-native-result.json`.
The exact35 host-gate correction execution is retained separately in
`linux-native-prior-v35-host-console.txt` and
`linux-native-prior-v35-validated-result.json`;36 runs a fresh full guest.

The first full36 run's interruption observer captured SIGUSR1 delivery but no
matching EINTR exit after enabling tracing during an already executing write;
it stopped before draining the original response. The omitted exit's exact
kernel cause is not uniquely established, and the observation is not treated
as proof of response loss. The corrected observer arms entry/exit/signal
tracepoints before sending each original packet, requires the actual original
endpoint fd/buffer/size entry, retains owned-thread filters and requires all12
EINTR/signal pairs. A separate real guest passes113 checks; the same helper is
required by the full run. `linux-usb-interrupt-prior-v36-trace-arm-failure.json`
and `usb-interrupt-trace-arm-observation.json` preserve this distinction. The
transfer source and bridge remain unchanged.

A separate actual36 conformance probe fails after31 passing checks: following
one real queued runtime cycle and the correct original HOTP response,
GetSlotStatus reports occupied-active0 before any new IccPowerOn. CCID Rev1.1
sections3.3 and6.3.1 model occupied-inactive status, insertion notification and
explicit reactivation after resume. This lifecycle remains unimplemented in36;
the102 transport checks do not prove it. No physical YubiKey resume behavior
was measured. The active goal retains the exact known failure in
`linux-usb-runtime-slot-prior-v36-failure.json` and
`usb-runtime-slot-conformance-observation.json`. Do not mark36 complete.
