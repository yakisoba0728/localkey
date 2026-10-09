//! The CCID class descriptor of the reference device, decoded field by field
//! (USB CCID Rev 1.1 §5.1), and the reader model limits taken from it.
//!
//! Source: `reference/yubikey-5c-nano-5.7.4/usb-reference-observation.json`,
//! `configuration_descriptor_hex`: the 54-byte descriptor of type 0x21 that follows the
//! interface descriptor of class 0x0B (Smart Card) in the configuration.

use lk_ccid::descriptor::{ClassDescriptor, ExchangeLevel, YUBIKEY_5C_NANO, feature};

const OBSERVATION: &str =
    include_str!("../../../reference/yubikey-5c-nano-5.7.4/usb-reference-observation.json");

/// The CCID class descriptor as it appears in `configuration_descriptor_hex`.
const CCID_DESCRIPTOR_HEX: &str = "36210001000702000000a00f0000a00f00000000b0040000b0040000\
                                   f60b00000000000000000000fe000400000c0000ffff00000001";

fn hex(s: &str) -> Vec<u8> {
    let digits: Vec<u8> = s.bytes().filter(u8::is_ascii_hexdigit).collect();
    digits
        .chunks(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("ascii");
            u8::from_str_radix(text, 16).expect("hex digit pair")
        })
        .collect()
}

/// `configuration_descriptor_hex` from the observation file.
fn configuration_descriptor() -> Vec<u8> {
    let key = "\"configuration_descriptor_hex\"";
    let start = OBSERVATION.find(key).expect("key present") + key.len();
    let rest = &OBSERVATION[start..];
    let open = rest.find('"').expect("opening quote") + 1;
    let close = rest[open..].find('"').expect("closing quote") + open;
    hex(&rest[open..close])
}

/// Walk the configuration (USB 2.0 §9.6) and return the 0x21 descriptor that follows
/// the interface descriptor with bInterfaceClass 0x0B.
fn ccid_descriptor(config: &[u8]) -> Vec<u8> {
    let mut in_ccid_interface = false;
    let mut pos = 0;
    while pos + 1 < config.len() {
        let (len, kind) = (usize::from(config[pos]), config[pos + 1]);
        assert!(len >= 2, "descriptor length at {pos}");
        let desc = &config[pos..pos + len];
        match kind {
            0x04 => in_ccid_interface = desc[5] == 0x0B,
            0x21 if in_ccid_interface => return desc.to_vec(),
            _ => {}
        }
        pos += len;
    }
    panic!("no CCID class descriptor");
}

#[test]
fn reference_configuration_holds_the_ccid_descriptor() {
    let config = configuration_descriptor();
    let descriptor = ccid_descriptor(&config);
    assert_eq!(descriptor, hex(CCID_DESCRIPTOR_HEX));
    assert_eq!(ClassDescriptor::parse(&descriptor), Some(YUBIKEY_5C_NANO));
    assert_eq!(YUBIKEY_5C_NANO.to_bytes().to_vec(), descriptor);
}

#[test]
fn decoded_values_of_the_reference_descriptor() {
    let d = ClassDescriptor::parse(&hex(CCID_DESCRIPTOR_HEX)).expect("valid descriptor");
    assert_eq!(d.bcd_ccid, 0x0100, "bcdCCID: CCID 1.00");
    assert_eq!(d.max_slot_index, 0, "bMaxSlotIndex: one slot");
    assert_eq!(
        d.voltage_support, 0x07,
        "bVoltageSupport: 5 V, 3 V and 1.8 V"
    );
    assert_eq!(d.protocols, 0x0000_0002, "dwProtocols: T=1 only");
    assert_eq!(d.default_clock_khz, 4000, "dwDefaultClock: 4 MHz");
    assert_eq!(d.maximum_clock_khz, 4000, "dwMaximumClock: 4 MHz");
    assert_eq!(
        d.num_clock_supported, 0,
        "bNumClockSupported: default/maximum only"
    );
    assert_eq!(d.data_rate_bps, 307_200, "dwDataRate");
    assert_eq!(d.max_data_rate_bps, 307_200, "dwMaxDataRate");
    assert_eq!(
        d.num_data_rates_supported, 0,
        "bNumDataRatesSupported: default/maximum only"
    );
    assert_eq!(d.max_ifsd, 3062, "dwMaxIFSD");
    assert_eq!(d.synch_protocols, 0, "dwSynchProtocols");
    assert_eq!(d.mechanical, 0, "dwMechanical: no mechanics");
    assert_eq!(d.features, 0x0004_00FE, "dwFeatures");
    assert_eq!(d.max_message_length, 3072, "dwMaxCCIDMessageLength");
    assert_eq!(
        d.class_get_response, 0xFF,
        "bClassGetResponse: echo the APDU class"
    );
    assert_eq!(
        d.class_envelope, 0xFF,
        "bClassEnvelope: echo the APDU class"
    );
    assert_eq!(d.lcd_layout, 0, "wLcdLayout: no LCD");
    assert_eq!(d.pin_support, 0, "bPINSupport: no PIN pad");
    assert_eq!(d.max_busy_slots, 1, "bMaxCCIDBusySlots");
}

#[test]
fn features_advertise_extended_apdu_level_and_automatic_parameters() {
    let f = YUBIKEY_5C_NANO.features;
    assert_eq!(
        YUBIKEY_5C_NANO.exchange_level(),
        ExchangeLevel::ExtendedApdu
    );
    for bit in [
        feature::AUTO_PARAMETERS_FROM_ATR,
        feature::AUTO_ACTIVATION,
        feature::AUTO_VOLTAGE,
        feature::AUTO_CLOCK,
        feature::AUTO_BAUD_RATE,
        feature::AUTO_NEGOTIATION,
        feature::AUTO_PPS,
        feature::EXTENDED_APDU_LEVEL,
    ] {
        assert_ne!(f & bit, 0, "{bit:#010x} set");
    }
    for bit in [
        feature::CLOCK_STOP,
        feature::NAD_NOT_ZERO,
        feature::AUTO_IFSD,
        feature::TPDU_LEVEL,
        feature::SHORT_APDU_LEVEL,
        feature::USB_WAKE_UP,
    ] {
        assert_eq!(f & bit, 0, "{bit:#010x} clear");
    }
    assert_eq!(YUBIKEY_5C_NANO.max_data_len(), 3062);
}
