# PID request

Submitted on 2026-10-13: [pid.codes #1310](https://github.com/pidcodes/pidcodes.github.com/pull/1310).
The request is for `1209:4C4B` ("LK"). It is awaiting upstream review, not assigned,
reserved or used by the application. The own profile retains private-test
`1209:0001`; public binary packaging remains blocked.

`org/localkey/index.md` and `1209/4C4B/index.md` are the submitted pages;
`PR_BODY.md` records the request and its evidence. Upstream requires uppercase PID
directory names. The complete tree at `39bfde8f3f8520b74c276e6a5c7f0c95c0098d33`
and open PRs were checked immediately before submission, with no conflict. The
public main source, Apache-2.0 LICENSE, NOTICE, USB implementation and verification
reports were readable without login. Both native Linux jobs passed:
[CI run](https://github.com/yakisoba0728/localkey/actions/runs/38323529249).

The request explains why this software-only project needs a common identity and
names the actual Linux ConfigFS/FunctionFS composite USB device implementation.
It does not imply a PCB or hardware security chip. pid.codes may ask for additional
justification or decline the request; submission is not approval.
[Rules and format](https://pid.codes/howto/).

After approval, change the own profile's seven product IDs together, the udev rule
and identity fixtures. Retain a migration rule only if a published test release
needs one. Rebuild and repeat desktop and gadget verification using the assigned
identity; leave the Yubico compatibility profile as an explicit test option.
The tagged release preflight reads the upstream PID page and requires its owner
and source to match this project. Release gates and the draft release procedure
are documented in [docs/RELEASE.md](../../docs/RELEASE.md).
