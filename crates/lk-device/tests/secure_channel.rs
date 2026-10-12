//! SCP03 through the device's CCID interface (GP Card Specification v2.3.1
//! Amendment D; Yubico yk5-apps-scp; lk-sd's integration notes for lk-device).

#![allow(clippy::unwrap_used)]

mod common;

use common::*;

/// YKOATH LIST.
const OATH_LIST: [u8; 4] = [0x00, 0xA1, 0x00, 0x00];

fn oath_session() -> (Rig, Scp03) {
    let mut rig = Rig::new();
    rig.power_on();
    assert_eq!(sw(&rig.select(AID_OATH)), 0x9000);
    let session = Scp03::open(&mut rig);
    (rig, session)
}

/// lk-sd: handshakes go to the Security Domain whichever applet is selected; wrapped
/// commands then reach that applet unwrapped with the CLA secure-messaging bits cleared
/// (docs/CONTRACTS.md "Applications A"; lk-oath answers `6882` to SM bits), and the
/// responses carry a valid R-MAC.
#[test]
fn handshake_while_oath_is_selected_then_wrapped_commands() {
    let (mut rig, mut session) = oath_session();
    let put = oath_put(b"scp", false);
    let wrapped = session.wrap(0x00, 0x01, 0x00, 0x00, &put[5..], None);
    assert_eq!(session.unwrap(&rig.apdu(&wrapped)), (vec![], 0x9000));
    let wrapped = session.wrap(0x00, 0xA1, 0x00, 0x00, &[], Some(0));
    let (data, status) = session.unwrap(&rig.apdu(&wrapped));
    assert_eq!(status, 0x9000);
    assert_eq!(&data[..2], &[0x72, 0x04], "LIST entry for the new credential");
    assert_eq!(&data[3..], b"scp");
}

/// Yubico yk5-apps-scp: "Sending a command in plain text will not be accepted and
/// immediately ends the session"; catalog SecurityDomain_plaintext: rejection before
/// dispatch revokes local authorization ("PIV verified PIN/admin ... revoked").
#[test]
fn plaintext_command_is_rejected_and_revokes_piv_pin() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_PIV);
    let mut session = Scp03::open(&mut rig);
    let verify = session.wrap(0x00, 0x20, 0x00, 0x80, &[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF], None);
    assert_eq!(session.unwrap(&rig.apdu(&verify)), (vec![], 0x9000));
    // Plaintext inside the channel: rejected before it reaches PIV.
    assert_eq!(rig.apdu(&[0x00, 0x20, 0x00, 0x80]), vec![0x69, 0x82]);
    // The channel is gone and the PIN verification with it.
    assert_eq!(rig.apdu(&[0x00, 0x20, 0x00, 0x80]), vec![0x63, 0xC3]);
    let status = session.wrap(0x00, 0x20, 0x00, 0x80, &[], None);
    assert_eq!(rig.apdu(&status), vec![0x68, 0x82], "PIV sees SM bits: no channel unwrapped it");
}

/// A wrong C-MAC ends the session with a bare error status (Amd D §6.2.5: no R-MAC on
/// an error status).
#[test]
fn bad_mac_ends_the_channel() {
    let (mut rig, mut session) = oath_session();
    let mut wrapped = session.wrap(0x00, 0xA1, 0x00, 0x00, &[], Some(0));
    let last = wrapped.len() - 2;
    wrapped[last] ^= 0x01;
    assert_eq!(rig.apdu(&wrapped), vec![0x69, 0x82]);
    let wrapped = session.wrap(0x00, 0xA1, 0x00, 0x00, &[], Some(0));
    assert_eq!(rig.apdu(&wrapped), vec![0x68, 0x82]);
}

/// Yubico: "When a new applet is selected, the session is terminated". A plaintext
/// SELECT is processed normally and ends the channel.
#[test]
fn plaintext_select_ends_the_channel() {
    let (mut rig, mut session) = oath_session();
    assert_eq!(sw(&rig.select(AID_OATH)), 0x9000);
    let wrapped = session.wrap(0x00, 0xA1, 0x00, 0x00, &[], Some(0));
    assert_eq!(rig.apdu(&wrapped), vec![0x68, 0x82]);
    assert_eq!(rig.apdu(&OATH_LIST), vec![0x90, 0x00], "plaintext works again");
}

/// lk-sd channel docs: an encrypted SELECT is unwrapped, its answer is wrapped, and the
/// session ends after it (catalog SecurityDomain_metadata: "old response remains SDK
/// MAC-verified while ... encrypted SELECT terminate authorization for subsequent
/// commands").
#[test]
fn encrypted_select_answer_is_wrapped_then_the_channel_ends() {
    let (mut rig, mut session) = oath_session();
    let wrapped = session.wrap(0x00, 0xA4, 0x04, 0x00, AID_OATH, Some(0));
    let (data, status) = session.unwrap(&rig.apdu(&wrapped));
    assert_eq!(status, 0x9000);
    assert_eq!(&data[..2], &[0x79, 0x03], "OATH SELECT answer (version tag)");
    let wrapped = session.wrap(0x00, 0xA1, 0x00, 0x00, &[], Some(0));
    assert_eq!(rig.apdu(&wrapped), vec![0x68, 0x82]);
}

/// docs/CONTRACTS.md "Applications B": the device reassembles ISO-chained
/// secure-messaging commands before `unwrap_command`; intermediate parts answer a plain
/// `9000` (yubikit `ScpProcessor` chains the protected command).
#[test]
fn chained_secure_messaging_is_reassembled() {
    let (mut rig, mut session) = oath_session();
    let put = oath_put(b"chained", false);
    let wrapped = session.wrap(0x00, 0x01, 0x00, 0x00, &put[5..], None);
    let body = &wrapped[5..];
    let split = 20;
    let mut first = vec![0x14, 0x01, 0x00, 0x00, split as u8];
    first.extend_from_slice(&body[..split]);
    let mut last = vec![0x04, 0x01, 0x00, 0x00, (body.len() - split) as u8];
    last.extend_from_slice(&body[split..]);
    assert_eq!(rig.apdu(&first), vec![0x90, 0x00]);
    assert_eq!(session.unwrap(&rig.apdu(&last)), (vec![], 0x9000));
    let wrapped = session.wrap(0x00, 0xA1, 0x00, 0x00, &[], Some(0));
    let (data, _) = session.unwrap(&rig.apdu(&wrapped));
    assert_eq!(&data[3..], b"chained");
}

/// lk-sd channel docs: the device wraps the complete response and serves the wrapped
/// bytes with GET RESPONSE itself. OATH's own `61xx` chaining is followed internally
/// with SEND REMAINING; the host fetches the wrapped remainder with plaintext
/// `00 C0` / `00 A5` and verifies one R-MAC over the whole response (yubikit
/// `ScpProcessor` unmacs the reassembled response).
#[test]
fn long_wrapped_response_is_split_and_fetched() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_OATH);
    let names: Vec<Vec<u8>> = (0..20u8).map(|i| [vec![b'a' + i; 1], vec![b'x'; 59]].concat()).collect();
    for name in &names {
        assert_eq!(rig.apdu(&oath_put(name, false)), vec![0x90, 0x00]);
    }
    let mut session = Scp03::open(&mut rig);
    let wrapped = session.wrap(0x00, 0xA1, 0x00, 0x00, &[], Some(0));
    let mut response = rig.apdu(&wrapped);
    let mut assembled = Vec::new();
    let mut fetches = 0;
    while sw(&response) >> 8 == 0x61 {
        assert_eq!(response.len(), 258, "pieces of Ne = 256");
        assembled.extend_from_slice(&response[..response.len() - 2]);
        // Alternate the two continuation commands the device accepts with OATH.
        let ins = if fetches % 2 == 0 { 0xC0 } else { 0xA5 };
        response = rig.apdu(&[0x00, ins, 0x00, 0x00, 0x00]);
        fetches += 1;
    }
    assert!(fetches >= 4);
    assembled.extend_from_slice(&response);
    let (data, status) = session.unwrap(&assembled);
    assert_eq!(status, 0x9000);
    let entries = lk_codec::tlv::parse_all(&data).unwrap();
    assert_eq!(entries.len(), 20);
    for (entry, name) in entries.iter().zip(&names) {
        assert_eq!(&entry.value[1..], name.as_slice());
    }
}

/// Catalog SecurityDomain_handoff: "not-yet-authenticated SCP03 INIT retain outer
/// transport": a wrapped INITIALIZE UPDATE is answered under the current channel, which
/// stays usable.
#[test]
fn nested_initialize_update_keeps_the_outer_channel() {
    let (mut rig, mut session) = oath_session();
    let init = session.wrap(0x80, 0x50, 0x00, 0x00, &[0x01; 8], None);
    let (data, status) = session.unwrap(&rig.apdu(&init));
    assert_eq!(status, 0x9000);
    assert_eq!(data.len(), 29, "INITIALIZE UPDATE response");
    let wrapped = session.wrap(0x00, 0xA1, 0x00, 0x00, &[], Some(0));
    assert_eq!(session.unwrap(&rig.apdu(&wrapped)), (vec![], 0x9000));
}

/// lk-sd: commands for the selected Security Domain go through
/// `SecurityDomain::process_secure` (GET DATA key information, GP 2.3.1 §11.3).
/// `84 CA 00 E0` is a GlobalPlatform-class command, so the `C0` entries come inside the
/// `E0` template (GP 2.3.1 §11.3.3.1, §11.3.3.1.1; they came bare before, and the
/// reference key's GP-class form is unmeasured); `04 CA 00 E0`, as yubikit sends it,
/// gets the bare entries.
#[test]
fn security_domain_commands_under_its_own_channel() {
    let mut rig = Rig::new();
    rig.power_on();
    assert_eq!(sw(&rig.select(AID_SD)), 0x9000);
    let mut session = Scp03::open(&mut rig);
    let get = session.wrap(0x80, 0xCA, 0x00, 0xE0, &[], Some(0));
    let (whole, status) = session.unwrap(&rig.apdu(&get));
    assert_eq!(status, 0x9000);
    let get = session.wrap(0x00, 0xCA, 0x00, 0xE0, &[], Some(0));
    let (data, status) = session.unwrap(&rig.apdu(&get));
    assert_eq!(status, 0x9000);
    // The reference schema: `C0` key information entries, the first for SCP03 set 1
    // (`reference/physical-key/security-domain-reference-observation.json`).
    assert_eq!(&data[..6], &[0xC0, 0x04, 0x01, 0xFF, 0x88, 0x10]);
    assert_eq!(whole, [&[0xE0, data.len() as u8][..], &data].concat());
}

/// ISO/IEC 7816-4:1995 §5.5.2: an encrypted SELECT whose (unwrapped) class codes logical
/// channel 1 (`05`, unwrapped to `01`) is refused with `6881` (Table 16) before anything
/// is selected (`card.rs` step 4): the selection, the PIV PIN verified under the channel
/// and the channel itself stay, and the next wrapped command passes its R-MAC check.
/// Before, any SELECT ended the session whatever its class. Unmeasured on the reference
/// key.
#[test]
fn encrypted_select_on_another_logical_channel_keeps_the_session() {
    let mut rig = Rig::new();
    rig.power_on();
    rig.select(AID_PIV);
    let mut session = Scp03::open(&mut rig);
    let verify = session.wrap(0x00, 0x20, 0x00, 0x80, &[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF], None);
    assert_eq!(session.unwrap(&rig.apdu(&verify)), (vec![], 0x9000));
    let select = session.wrap(0x01, 0xA4, 0x04, 0x00, AID_SD, Some(0));
    assert_eq!(select[0], 0x05);
    assert_eq!(rig.apdu(&select), vec![0x68, 0x81], "an error status comes back bare");
    // Still PIV, still verified, still the same channel.
    let status = session.wrap(0x00, 0x20, 0x00, 0x80, &[], None);
    assert_eq!(session.unwrap(&rig.apdu(&status)), (vec![], 0x9000));
    // A SELECT of the basic channel still ends the session after its response.
    let select = session.wrap(0x00, 0xA4, 0x04, 0x00, AID_PIV, Some(0));
    assert_eq!(session.unwrap(&rig.apdu(&select)).1, 0x9000);
    assert_eq!(rig.apdu(&[0x00, 0x20, 0x00, 0x80]), vec![0x63, 0xC3], "the PIN status in plaintext: not verified");

    // A plaintext SELECT on channel 1 inside a channel is still plaintext: it ends the
    // session and its authorization (Yubico yk5-apps-scp), then answers `6881` and
    // selects nothing (PIV stays selected, its PIN no longer verified).
    let mut session = Scp03::open(&mut rig);
    let verify = session.wrap(0x00, 0x20, 0x00, 0x80, &[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF], None);
    assert_eq!(session.unwrap(&rig.apdu(&verify)), (vec![], 0x9000));
    assert_eq!(rig.apdu(&apdu(0x01, 0xA4, 0x04, 0x00, AID_SD, Some(0))), vec![0x68, 0x81]);
    assert_eq!(rig.apdu(&[0x00, 0x20, 0x00, 0x80]), vec![0x63, 0xC3], "PIV selected, PIN verification gone");
    let status = session.wrap(0x00, 0x20, 0x00, 0x80, &[], None);
    assert_eq!(rig.apdu(&status), vec![0x68, 0x82], "no channel left to unwrap it");
}

/// Catalog SecurityDomain_plaintext: plaintext handshake commands inside an established
/// channel are rejected before dispatch.
#[test]
fn plaintext_handshake_inside_a_channel_is_rejected() {
    let (mut rig, mut session) = oath_session();
    assert_eq!(rig.apdu(&apdu(0x80, 0x50, 0x00, 0x00, &[0x01; 8], None)), vec![0x69, 0x82]);
    let wrapped = session.wrap(0x00, 0xA1, 0x00, 0x00, &[], Some(0));
    assert_eq!(rig.apdu(&wrapped), vec![0x68, 0x82]);
}

/// A card power-off drops the secure channel (lk-sd: the device ends the session on
/// card power-off).
#[test]
fn power_off_drops_the_channel() {
    let (mut rig, mut session) = oath_session();
    rig.power_off();
    rig.power_on();
    rig.select(AID_OATH);
    let wrapped = session.wrap(0x00, 0xA1, 0x00, 0x00, &[], Some(0));
    assert_eq!(rig.apdu(&wrapped), vec![0x68, 0x82]);
}
