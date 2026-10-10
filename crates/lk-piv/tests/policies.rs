//! PIN and touch policies of slot keys (Yubico PIV extensions, "PIN and touch policy":
//! PIN never / once / always, touch never / always / cached for 15 s) enforced by
//! GENERAL AUTHENTICATE (SP 800-73-4 Part 2 §3.2.4), with the touch flow of
//! `lk_core::Outcome::NeedTouch` and `CardApplet::touch_resolved`.

#![allow(clippy::unwrap_used)]

mod common;

use common::*;
use lk_core::{CardApplet, Outcome, Record, ResetKind};

const DIGEST: [u8; 32] = [0x6B; 32];

fn card_with(slot: u8, pin: u8, touch: u8) -> (Card, Public) {
    let mut card = Card::new();
    card.auth_default();
    let public = card.generate(slot, P256, Some(pin), Some(touch));
    // Start from a fresh session: no PIN, no management key (SP 800-73-4 Part 2 §3.1.1:
    // selecting another application clears the security status).
    card.piv.deselect();
    card.piv.select(&hex(SELECT), &mut card.host);
    (card, public)
}

fn sign(card: &mut Card, slot: u8) -> (Vec<u8>, u16) {
    card.ga(slot, P256, 0x81, &DIGEST)
}

fn signs(card: &mut Card, slot: u8, public: &Public) -> bool {
    let (sig, sw) = sign(card, slot);
    sw == 0x9000 && ecdsa_ok(P256, public.point(), &DIGEST, &sig)
}

#[test]
fn pin_policy_never_needs_no_pin() {
    let (mut card, public) = card_with(0x9A, PIN_NEVER, TOUCH_NEVER);
    assert!(signs(&mut card, 0x9A, &public));
    assert!(signs(&mut card, 0x9A, &public));
}

#[test]
fn pin_policy_once_needs_the_pin_in_this_session() {
    let (mut card, public) = card_with(0x9A, PIN_ONCE, TOUCH_NEVER);
    assert_eq!(sign(&mut card, 0x9A).1, 0x6982);
    card.verify_default_pin();
    assert!(signs(&mut card, 0x9A, &public));
    assert!(signs(&mut card, 0x9A, &public), "once per session, not per use");
    // VERIFY P1 FF resets the PIN status (SP 800-73-4 Part 2 §3.2.1).
    assert_eq!(card.send("0020FF80").1, 0x9000);
    assert_eq!(sign(&mut card, 0x9A).1, 0x6982);
    card.verify_default_pin();
    // A wrong PIN clears the verified status.
    assert_eq!(card.verify_pin(&pad(b"000000")), 0x63C2);
    assert_eq!(sign(&mut card, 0x9A).1, 0x6982);
    card.verify_default_pin();
    // Session ends: deselect and every reset kind (SP 800-73-4 Part 1 §3.5).
    card.piv.deselect();
    assert_eq!(sign(&mut card, 0x9A).1, 0x6982);
    for kind in [ResetKind::CardPowerOff, ResetKind::UsbReset, ResetKind::PowerCycle] {
        card.verify_default_pin();
        card.piv.reset(kind);
        assert_eq!(sign(&mut card, 0x9A).1, 0x6982, "{kind:?}");
    }
}

#[test]
fn pin_policy_always_needs_a_verify_before_each_use() {
    // Yubico: "PIN is verified just before operation"; slot 9C defaults to it.
    let (mut card, public) = card_with(0x9C, PIN_DEFAULT, TOUCH_NEVER);
    assert_eq!(card.slot_info(0x9C).unwrap().pin, PIN_ALWAYS);
    assert_eq!(sign(&mut card, 0x9C).1, 0x6982);
    card.verify_default_pin();
    assert!(signs(&mut card, 0x9C, &public));
    assert_eq!(sign(&mut card, 0x9C).1, 0x6982, "the authorization was used");
    assert_eq!(card.pin_status(), 0x9000, "the PIN itself stays verified");
    card.verify_default_pin();
    assert!(signs(&mut card, 0x9C, &public));
}

#[test]
fn pin_always_authorization_is_not_consumed_by_rejected_requests() {
    // Catalog: GENERAL AUTHENTICATE checks happen "before ... consuming PIN_ALWAYS
    // signing authorization". Requests rejected by those checks, on any slot, keep it.
    let mut card = Card::new();
    card.auth_default();
    let always = card.generate(0x9C, P256, Some(PIN_ALWAYS), None);
    card.generate(0x9A, P256, Some(PIN_ONCE), None);
    card.verify_default_pin();
    assert_eq!(card.ga(0x9C, P256, 0x81, &[0; 33]).1, 0x6A80, "digest too long");
    assert_eq!(card.ga(0x9C, P384, 0x81, &DIGEST).1, 0x6A86, "algorithm mismatch");
    assert_eq!(card.cmd(0x87, P256, 0x9C, &hex("7C028200"), None).1, 0x6A80, "no challenge");
    assert_eq!(card.ga(0x9C, P256, 0x85, &[4; 65]).1, 0x6A80, "invalid point");
    assert_eq!(card.ga(0x9D, P256, 0x81, &DIGEST).1, 0x6A88, "empty slot");
    assert_eq!(card.ga(0x9A, P384, 0x81, &DIGEST).1, 0x6A86, "other slot, wrong algorithm");
    assert!(signs(&mut card, 0x9C, &always), "still armed");
    assert_eq!(sign(&mut card, 0x9C).1, 0x6982);
}

#[test]
fn pin_always_needs_the_verify_immediately_before() {
    // SP 800-73-4 Part 1 §3.2.1: for PIN Always "the PIN ... must be submitted and
    // verified every time immediately before a digital signature key operation". Any
    // other command in between drops the authorization, except a VERIFY status query,
    // GET RESPONSE and the intermediate parts of the operation's own command chain.
    let mut card = Card::new();
    card.auth_default();
    let always = card.generate(0x9C, P256, Some(PIN_ALWAYS), None);
    let once = card.generate(0x9A, P256, Some(PIN_ONCE), None);
    let rsa = card.generate(0x9D, RSA2048, Some(PIN_ALWAYS), None);
    type Between = fn(&mut Card);
    let interrupting: [(&str, Between); 8] = [
        ("GET DATA", |c| assert_eq!(c.send("00CB3FFF035C017E00").1, 0x9000)),
        ("GET VERSION", |c| assert_eq!(c.send("00FD0000").1, 0x9000)),
        ("operation on another slot", |c| assert_eq!(sign(c, 0x9A).1, 0x9000)),
        ("re-SELECT", |c| {
            c.piv.select(&hex(SELECT), &mut c.host);
        }),
        ("SELECT command", |c| assert_eq!(c.send("00A4040005A00000030800").1, 0x9000)),
        ("malformed APDU", |c| assert_eq!(c.raw(&[0x00, 0x20]).1, 0x6700)),
        ("wrong class", |c| assert_eq!(c.send("80FD0000").1, 0x6E00)),
        ("VERIFY P1 FF", |c| assert_eq!(c.send("0020FF80").1, 0x9000)),
    ];
    for (what, between) in interrupting {
        card.verify_default_pin();
        between(&mut card);
        assert_eq!(sign(&mut card, 0x9C).1, 0x6982, "{what}");
        if what != "VERIFY P1 FF" {
            // Only the PIN-always authorization is gone; the PIN stays verified.
            assert!(signs(&mut card, 0x9A, &once), "{what}");
        }
    }
    // A status query does not drop it (yubico-piv-tool and piv-go probe the PIN state
    // with an empty VERIFY).
    card.verify_default_pin();
    assert_eq!(card.pin_status(), 0x9000);
    assert_eq!(card.send("0020008000").1, 0x9000);
    assert!(signs(&mut card, 0x9C, &always));
    // The intermediate parts of a chained operation belong to the operation itself.
    card.verify_default_pin();
    let m = representative(rsa.modulus(), 0x5A);
    let (s, sw) = card.ga(0x9D, RSA2048, 0x81, &m);
    assert_eq!(sw, 0x9000);
    assert_eq!(lk_crypto::rsa_public_op(rsa.modulus(), &[1, 0, 1], &s).unwrap(), m);
    // GET RESPONSE after the VERIFY does not drop it either.
    card.verify_default_pin();
    assert_eq!(card.send("00C0000000").1, 0x6985, "nothing pending");
    assert!(signs(&mut card, 0x9C, &always));
}

#[test]
fn touch_policy_always_waits_for_every_use() {
    let (mut card, public) = card_with(0x9E, PIN_NEVER, TOUCH_ALWAYS);
    for _ in 0..2 {
        assert_eq!(card.ga_outcome(0x9E, P256, 0x81, &DIGEST), Outcome::NeedTouch { timeout_ms: 15_000 });
        let (sig, sw) = card.touch(true);
        assert_eq!(sw, 0x9000);
        assert!(ecdsa_ok(P256, public.point(), &DIGEST, &sig));
    }
    // No touch (timeout or cancel): 6982, nothing produced.
    assert!(matches!(card.ga_outcome(0x9E, P256, 0x81, &DIGEST), Outcome::NeedTouch { .. }));
    assert_eq!(card.touch(false), (vec![], 0x6982));
    // Nothing is pending afterwards.
    assert_eq!(card.touch(true).1, 0x6985);
}

#[test]
fn touch_policy_cached_reuses_a_touch_for_15_seconds() {
    // Yubico: "Touch is cached for 15s after use".
    let (mut card, public) = card_with(0x9E, PIN_NEVER, TOUCH_CACHED);
    assert!(matches!(card.ga_outcome(0x9E, P256, 0x81, &DIGEST), Outcome::NeedTouch { .. }));
    assert_eq!(card.touch(true).1, 0x9000);
    card.host.advance(14_999);
    assert!(signs(&mut card, 0x9E, &public), "within the window");
    // Selection changes keep the cache.
    card.piv.deselect();
    card.piv.select(&hex(SELECT), &mut card.host);
    assert!(signs(&mut card, 0x9E, &public));
    card.host.advance(1);
    assert!(matches!(card.ga_outcome(0x9E, P256, 0x81, &DIGEST), Outcome::NeedTouch { .. }), "expired");
    assert_eq!(card.touch(true).1, 0x9000);
    assert!(signs(&mut card, 0x9E, &public));
    // A declined touch does not refresh the cache; resets clear it.
    card.piv.reset(ResetKind::CardPowerOff);
    assert!(matches!(card.ga_outcome(0x9E, P256, 0x81, &DIGEST), Outcome::NeedTouch { .. }), "reset clears it");
    assert_eq!(card.touch(false).1, 0x6982);
    assert!(matches!(card.ga_outcome(0x9E, P256, 0x81, &DIGEST), Outcome::NeedTouch { .. }));
    assert_eq!(card.touch(true).1, 0x9000);
}

#[test]
fn touch_on_another_slot_fills_the_cache() {
    let mut card = Card::new();
    card.auth_default();
    card.generate(0x9A, P256, Some(PIN_NEVER), Some(TOUCH_ALWAYS));
    let cached = card.generate(0x9E, P256, Some(PIN_NEVER), Some(TOUCH_CACHED));
    assert!(matches!(card.ga_outcome(0x9A, P256, 0x81, &DIGEST), Outcome::NeedTouch { .. }));
    assert_eq!(card.touch(true).1, 0x9000);
    assert!(signs(&mut card, 0x9E, &cached));
}

#[test]
fn pin_is_checked_before_touch_and_pin_always_is_spent_on_a_timeout() {
    let (mut card, public) = card_with(0x9C, PIN_ALWAYS, TOUCH_ALWAYS);
    assert_eq!(sign(&mut card, 0x9C).1, 0x6982, "no touch request without the PIN");
    card.verify_default_pin();
    assert!(matches!(card.ga_outcome(0x9C, P256, 0x81, &DIGEST), Outcome::NeedTouch { .. }));
    assert_eq!(card.touch(false).1, 0x6982);
    assert_eq!(sign(&mut card, 0x9C).1, 0x6982, "consumed before the touch wait");
    card.verify_default_pin();
    assert!(matches!(card.ga_outcome(0x9C, P256, 0x81, &DIGEST), Outcome::NeedTouch { .. }));
    let (sig, sw) = card.touch(true);
    assert_eq!(sw, 0x9000);
    assert!(ecdsa_ok(P256, public.point(), &DIGEST, &sig));
}

#[test]
fn a_new_command_abandons_a_pending_touch() {
    let (mut card, _) = card_with(0x9E, PIN_NEVER, TOUCH_ALWAYS);
    assert!(matches!(card.ga_outcome(0x9E, P256, 0x81, &DIGEST), Outcome::NeedTouch { .. }));
    assert_eq!(card.send("00FD0000").1, 0x9000);
    assert_eq!(card.touch(true).1, 0x6985, "nothing pending");
    // A reset drops it too.
    assert!(matches!(card.ga_outcome(0x9E, P256, 0x81, &DIGEST), Outcome::NeedTouch { .. }));
    card.piv.reset(ResetKind::UsbReset);
    assert_eq!(card.touch(true).1, 0x6985);
}

#[test]
fn touched_result_uses_response_chaining() {
    let mut card = Card::new();
    card.auth_default();
    let public = card.generate(0x9D, RSA2048, Some(PIN_NEVER), Some(TOUCH_ALWAYS));
    let m = representative(public.modulus(), 0x21);
    assert!(matches!(card.ga_outcome(0x9D, RSA2048, 0x81, &m), Outcome::NeedTouch { .. }));
    let resp = card.piv.touch_resolved(true, &mut card.host);
    assert_eq!(resp.len(), 258);
    assert_eq!(resp[256..], [0x61, 0x08]);
    let (rest, sw) = card.send("00C0000000");
    assert_eq!((rest.len(), sw), (8, 0x9000));
    let mut all = resp[..256].to_vec();
    all.extend(rest);
    let s = dyn_auth_item(&all, 0x82);
    assert_eq!(lk_crypto::rsa_public_op(public.modulus(), &[1, 0, 1], &s).unwrap(), m);
}

#[test]
fn policies_persist_across_restart() {
    let (mut card, public) = card_with(0x9A, PIN_ALWAYS, TOUCH_CACHED);
    card.restart();
    let info = card.slot_info(0x9A).unwrap();
    assert_eq!((info.pin, info.touch, info.public.clone()), (PIN_ALWAYS, TOUCH_CACHED, public.clone()));
    assert_eq!(sign(&mut card, 0x9A).1, 0x6982);
    card.verify_default_pin();
    assert!(matches!(card.ga_outcome(0x9A, P256, 0x81, &DIGEST), Outcome::NeedTouch { .. }));
    assert_eq!(card.touch(true).1, 0x9000);
    // Operations persist nothing.
    let before = card.host.persisted(Record::Piv);
    let count = card.host.persist_count();
    card.verify_default_pin();
    assert!(signs(&mut card, 0x9A, &public));
    assert_eq!(card.host.persist_count(), count + 2, "only the VERIFY commits");
    assert_eq!(card.host.persisted(Record::Piv), before);
}
