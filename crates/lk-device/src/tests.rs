//! Unit tests of internal routing pieces (the public behaviour is tested end to end in
//! `crates/lk-device/tests/`).

#![allow(clippy::unwrap_used)]

use lk_core::{Capabilities, DeviceProfile, Host, Record};
use lk_otp::MgmtBridge;
use lk_testkit::{MemoryStore, SeededEntropy};

use crate::apps::{AppId, Bridge};
use crate::host::{DeviceHost, Loaded};
use crate::presence::{CardWait, FidoWait, OtpWait, U2fWindow, Waits};
use crate::{Device, fido};

const KEY: [u8; 32] = [7; 32];

fn device() -> Device {
    Device::open(
        DeviceProfile::yubikey_5c_nano_5_7_4(4242),
        Box::new(MemoryStore::new()),
        Box::new(SeededEntropy::new(9)),
        KEY,
    )
}

/// The AID table the device routes SELECT with equals each applet's own
/// `CardApplet::aid` (docs/CONTRACTS.md "Application crates").
#[test]
fn aid_table_matches_the_applets() {
    let mut dev = device();
    for id in AppId::ALL {
        assert_eq!(id.aid(), dev.apps.card(id).aid(), "{id:?}");
    }
}

/// `card.rs` step 4: the longest matching AID wins, a longer DF name still selects,
/// and an application whose capability is disabled is not found. A DF name that is a
/// prefix of an applet's AID selects the first such applet in `AppId::ALL` order
/// (docs/MEASUREMENT.md, probe `select-partial-aid`; before the measurement truncated
/// names were not supported and `A00000052721` was not found).
#[test]
fn applet_lookup_by_df_name() {
    let mut dev = device();
    assert_eq!(dev.find_applet_for_test(&[0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00]), Some(AppId::Piv));
    assert_eq!(dev.find_applet_for_test(&[0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04]), Some(AppId::OpenPgp));
    assert_eq!(dev.find_applet_for_test(&[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21]), Some(AppId::Oath), "OATH comes before HSM Auth");
    assert_eq!(dev.find_applet_for_test(&[0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00]), Some(AppId::SecurityDomain));
    assert_eq!(dev.find_applet_for_test(&[0xA0, 0x00, 0x00, 0x01, 0x51]), Some(AppId::SecurityDomain));
    assert_eq!(dev.find_applet_for_test(&[]), None, "an empty DF name selects nothing");
    assert_eq!(dev.find_applet_for_test(&[0xA0, 0x00, 0x00, 0x05, 0x27, 0x99]), None);
    dev.caps = Capabilities(Capabilities::ALL.0 & !Capabilities::OATH);
    assert_eq!(dev.find_applet_for_test(lk_oath::AID), None);
    assert_eq!(dev.find_applet_for_test(&[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21]), Some(AppId::HsmAuth), "OATH disabled");
    assert_eq!(dev.find_applet_for_test(lk_mgmt::AID), Some(AppId::Management));
}

/// docs/MEASUREMENT.md, probe `select-partial-aid`, with the key's enabled set (`031A`:
/// OTP and OATH disabled): `A0000005` and `A000000527` select Management, `A0000003`
/// PIV, `D276000124` OpenPGP and `A0000005272107` HSM Auth (whose AID is the 8-byte
/// `A000000527210701`).
#[test]
fn partial_df_names_select_as_measured() {
    let mut dev = device();
    dev.caps = Capabilities(0x031A);
    for (name, want) in [
        (&[0xA0, 0x00, 0x00, 0x05][..], AppId::Management),
        (&[0xA0, 0x00, 0x00, 0x05, 0x27], AppId::Management),
        (&[0xA0, 0x00, 0x00, 0x03], AppId::Piv),
        (&[0xD2, 0x76, 0x00, 0x01, 0x24], AppId::OpenPgp),
        (&[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x07], AppId::HsmAuth),
    ] {
        assert_eq!(dev.find_applet_for_test(name), Some(want), "{name:02X?}");
    }
    assert_eq!(dev.find_applet_for_test(&[0xA0, 0x00, 0x00, 0x05, 0x27, 0x20]), None, "OTP disabled");
}

/// CTAP 2.1 §11.2.9.1.3 capability flags per enabled FIDO application (`fido.rs`).
#[test]
fn ctaphid_capability_flags() {
    let all = Capabilities::ALL;
    assert_eq!(fido::ctaphid_capabilities(all), 0x05);
    assert_eq!(fido::ctaphid_capabilities(Capabilities(all.0 & !Capabilities::FIDO2)), 0x01);
    assert_eq!(fido::ctaphid_capabilities(Capabilities(all.0 & !Capabilities::U2F)), 0x0D);
    assert_eq!(fido::ctaphid_capabilities(Capabilities(Capabilities::OTP)), 0x09);
}

/// docs/DESIGN.md §5: the earliest waiting request gets the touch, whatever its kind.
#[test]
fn earliest_wait_is_chosen_by_order() {
    let mut waits = Waits::default();
    assert!(!waits.any());
    waits.card = Some(CardWait { seq: 1, app: AppId::Oath, order: 5, started: 0, deadline: 0, wtx_at: 0, wrap: false, max: 256 });
    waits.u2f = Some(U2fWindow { order: 3, until: 0 });
    waits.fido = Some(FidoWait { cid: 1, order: 7, started: 0, deadline: 0, keepalive_at: 0 });
    waits.otp = Some(OtpWait { order: 4, deadline: 0 });
    assert!(waits.any());
    assert_eq!(waits.earliest_for_test(), Some("u2f"));
    waits.u2f = None;
    assert_eq!(waits.earliest_for_test(), Some("otp"));
    waits.otp = None;
    assert_eq!(waits.earliest_for_test(), Some("card"));
    waits.card = None;
    assert_eq!(waits.earliest_for_test(), Some("fido"));
}

/// docs/CONTRACTS.md "Applications A" `MgmtBridge` mapping.
#[test]
fn management_bridge_mapping() {
    let mut dev = device();
    let mgmt = dev.apps.mgmt.management_mut();
    let expected_page = mgmt.device_info_page(0, &dev.host);
    let mut bridge = Bridge::new(mgmt);
    assert_eq!(bridge.serial(&mut dev.host), Some(4242));
    assert_eq!(bridge.device_info(0, &mut dev.host), expected_page);
    assert_eq!(bridge.challenge_response_timeout_s(), 15);
    assert_eq!(bridge.write_device_config(&[0x06, 0, 0, 0], &mut dev.host), Err(0x6D00));
    assert!(!bridge.reboot_requested());
    // `len || TLVs` with the REBOOT tag (`0C`).
    assert_eq!(bridge.write_device_info(&[0x02, 0x0C, 0x00], &mut dev.host), Ok(()));
    assert!(bridge.reboot_requested());
    assert_eq!(bridge.write_device_info(&[0x05, 0x0C, 0x00], &mut dev.host), Err(0x6A80));
}

/// `host.rs`: `persist` seals under the storage key and the record id; `load` opens it;
/// time and wall-clock time come from the device.
#[test]
fn host_persists_sealed_and_reports_time() {
    let store = MemoryStore::new();
    let mut host = DeviceHost::new(
        DeviceProfile::own(1),
        Box::new(store.clone()),
        Box::new(SeededEntropy::new(1)),
        KEY,
        42,
    );
    assert_eq!(host.now(), 42);
    assert_eq!(host.unix_time(), None);
    host.unix_time = Some(1_800_000_000);
    assert_eq!(host.unix_time(), Some(1_800_000_000));
    assert_eq!(host.load(Record::Piv), Loaded::Absent);
    host.persist(Record::Piv, b"\x01piv").unwrap();
    assert_eq!(crate::storage::open(&KEY, Record::Piv, &store.get(Record::Piv).unwrap()), Ok(b"\x01piv".to_vec()));
    assert_eq!(host.load(Record::Piv), Loaded::Opened(b"\x01piv".to_vec()));
    store.insert(Record::Oath, b"garbage");
    assert_eq!(host.load(Record::Oath), Loaded::Unreadable);
    store.fail_next_saves(1);
    assert!(host.persist(Record::Piv, b"\x01new").is_err());
    assert_eq!(host.load(Record::Piv), Loaded::Opened(b"\x01piv".to_vec()));
}

/// `Device::set_unix_time` backs `Host::unix_time` (docs/CONTRACTS.md "Applications B":
/// lk-device exposes a way for the program to set it).
#[test]
fn unix_time_is_lent_to_applications() {
    let mut dev = device();
    assert_eq!(dev.host.unix_time(), None);
    dev.set_unix_time(Some(1_900_000_000));
    assert_eq!(dev.host.unix_time(), Some(1_900_000_000));
    dev.set_unix_time(None);
    assert_eq!(dev.host.unix_time(), None);
}

/// `Device::handle`: time never goes backwards.
#[test]
fn time_is_monotonic() {
    let mut dev = device();
    dev.handle(1_000, crate::Input::Tick);
    dev.handle(500, crate::Input::Tick);
    assert_eq!(dev.host.now(), 1_000);
}

/// `host.rs` `begin_construction`: during construction an unreadable record is never
/// written, and a save the store rejects is kept and saved by `retry_deferred` once the
/// store works; a later successful save of the record supersedes it; outside
/// construction a failed save is the application's to handle and is not kept
/// (`docs/DESIGN.md` §7 commit rule).
#[test]
fn constructor_saves_are_protected_or_retried() {
    let store = MemoryStore::new();
    let mut host = DeviceHost::new(
        DeviceProfile::own(1),
        Box::new(store.clone()),
        Box::new(SeededEntropy::new(1)),
        KEY,
        0,
    );
    host.begin_construction(&[Record::Oath]);
    assert!(host.persist(Record::Oath, b"\x01factory").is_ok());
    assert_eq!(store.get(Record::Oath), None, "an unreadable record is never overwritten");
    store.fail_next_saves(2);
    assert!(host.persist(Record::Piv, b"\x01piv").is_err());
    assert!(host.persist(Record::SecurityDomain, b"\x01sd").is_err());
    host.end_construction();
    assert_eq!(host.deferred_records(), vec![Record::Piv, Record::SecurityDomain]);
    store.fail_next_saves(1);
    host.retry_deferred();
    assert_eq!(host.deferred_records(), vec![Record::Piv], "the PIV retry failed, the Security Domain one worked");
    assert_eq!(host.load(Record::SecurityDomain), Loaded::Opened(b"\x01sd".to_vec()));
    // A newer state of the record replaces the deferred one.
    host.persist(Record::Piv, b"\x01piv-newer").unwrap();
    assert!(host.deferred_records().is_empty());
    host.retry_deferred();
    assert_eq!(host.load(Record::Piv), Loaded::Opened(b"\x01piv-newer".to_vec()));
    // Outside construction a failed save is not kept.
    store.fail_next_saves(1);
    assert!(host.persist(Record::Fido, b"\x01fido").is_err());
    assert!(host.deferred_records().is_empty());
    assert!(host.persist(Record::Oath, b"\x01oath").is_ok());
    assert_eq!(host.load(Record::Oath), Loaded::Opened(b"\x01oath".to_vec()), "protection ends with construction");
}

/// `presence.rs` module documentation: a periodic message processed at `now` is next
/// due at the first point of `started + k * interval` after `now`, whatever the
/// lateness (CTAP 2.1 §11.2.9.1.7 cadence without drift; one message per late Tick).
#[test]
fn periodic_messages_follow_the_grid() {
    use crate::presence::next_on_grid;
    assert_eq!(next_on_grid(1_000, 100, 1_000), 1_100);
    assert_eq!(next_on_grid(1_000, 100, 1_099), 1_100);
    assert_eq!(next_on_grid(1_000, 100, 1_100), 1_200);
    assert_eq!(next_on_grid(1_000, 100, 1_107), 1_200, "7 ms late: the grid does not move");
    assert_eq!(next_on_grid(1_000, 500, 5_050), 5_500, "several intervals late: one step past now");
}

/// `apps::protected_at_open` (second device review): unreadable records are always
/// protected at open; every record is when none opened (the storage key is
/// unconfirmed); a fresh store protects nothing.
#[test]
fn records_protected_at_open() {
    use crate::apps::protected_at_open;
    use crate::host::RECORDS;
    assert_eq!(protected_at_open(0, &[]), Vec::<Record>::new(), "fresh store");
    assert_eq!(protected_at_open(0, &[Record::Oath]), RECORDS.to_vec(), "key unconfirmed");
    assert_eq!(protected_at_open(0, &RECORDS), RECORDS.to_vec());
    assert_eq!(protected_at_open(1, &[Record::Oath]), vec![Record::Oath], "key confirmed by one record");
    assert_eq!(protected_at_open(3, &[]), Vec::<Record>::new());
}
