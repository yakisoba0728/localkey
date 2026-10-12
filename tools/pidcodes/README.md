# PID request preparation

These are **unsubmitted draft files** to copy into a fork of
<https://github.com/pidcodes/pidcodes.github.com>. The candidate is `1209:4c4b`
("LK"); it is not assigned, reserved or used by the application. The current
private-test `1209:0001` remains in the own profile until an allocation is accepted.

On 2026-10-12 the complete upstream tree (not truncated) contained neither
`org/localkey/index.md` nor `1209/4c4b/`, and the open-PR search for `4c4b` had no
matches. Recheck both immediately before submission; an unused number is not an
allocation. Rules and application format: <https://pid.codes/howto/>.

Source prerequisites are the public main branch, current implementation,
`LICENSE` (Apache-2.0), `NOTICE`, deployment documentation and
[`docs/LINUX_DESKTOP_VERIFICATION.md`](../../docs/LINUX_DESKTOP_VERIFICATION.md).
Verify that all are readable without login before submission. `PR_BODY.md` is
the accompanying submission draft; copy only the organization and PID page files
into the upstream fork.

The draft explains why this software-only project needs a common PID, and names
the actual USB ConfigFS/FunctionFS gadget path rather than implying it is a
hardware security chip. pid.codes may request further justification or decline
the request. Do not treat submission or this candidate as approval.

After approval, change the own profile's seven product IDs together, its udev
rule and identity fixtures; retain a narrowly scoped migration rule only if a
published test release needs one. Rebuild and rerun desktop and gadget tests,
then remove the test-identity release block with a regression check for the
assigned identity. Leave the Yubico compatibility profile as an explicit test
option. No messages or pull requests have been sent to pid.codes by this work.
