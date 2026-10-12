//! authenticatorGetInfo (CTAP 2.1 §6.4) against the public GetInfo read from a real
//! reference key: `reference/physical-key/reference-observation.json`.

use super::json::{self, Json};
use super::*;

const REFERENCE: &str =
    include_str!("../../../../reference/physical-key/reference-observation.json");

fn reference() -> Json {
    json::parse(REFERENCE).get("reference").clone()
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn text_array(items: &Json) -> Value {
    Value::Array(
        items
            .as_array()
            .iter()
            .map(|s| Value::from(s.as_str()))
            .collect(),
    )
}

fn int(n: &Json) -> Value {
    Value::int_key(n.as_i64())
}

/// The reference GetInfo fields as CTAP 2.1 §6.4 map entries (JSON names follow
/// python-fido2's `Info` attribute names).
fn expected(fields: &Json) -> Vec<(i64, Value)> {
    let options = Value::Map(
        fields
            .get("options")
            .as_object()
            .iter()
            .map(|(k, v)| (Value::from(k.as_str()), Value::Bool(v.as_bool())))
            .collect(),
    );
    let algorithms = Value::Array(
        fields
            .get("algorithms")
            .as_array()
            .iter()
            .map(|a| {
                MapBuilder::new()
                    .insert("alg", a.get("alg").as_i64())
                    .insert("type", a.get("type").as_str())
                    .build()
            })
            .collect(),
    );
    vec![
        (0x01, text_array(fields.get("versions"))),
        (0x02, text_array(fields.get("extensions"))),
        (0x03, Value::Bytes(hex(fields.get("aaguid").as_str()))),
        (0x04, options),
        (0x05, int(fields.get("max_msg_size"))),
        (
            0x06,
            Value::Array(
                fields
                    .get("pin_uv_protocols")
                    .as_array()
                    .iter()
                    .map(int)
                    .collect(),
            ),
        ),
        (0x07, int(fields.get("max_creds_in_list"))),
        (0x08, int(fields.get("max_cred_id_length"))),
        (0x09, text_array(fields.get("transports"))),
        (0x0A, algorithms),
        (0x0B, int(fields.get("max_large_blob"))),
        (0x0C, Value::Bool(fields.get("force_pin_change").as_bool())),
        (0x0D, int(fields.get("min_pin_length"))),
        (0x0E, int(fields.get("firmware_version"))),
        (0x0F, int(fields.get("max_cred_blob_length"))),
        (0x10, int(fields.get("max_rpids_for_min_pin"))),
        (0x14, int(fields.get("remaining_disc_creds"))),
    ]
}

fn keys(info: &Value) -> Vec<i64> {
    info.as_map()
        .unwrap()
        .iter()
        .map(|(k, _)| k.as_i64().unwrap())
        .collect()
}

fn option(info: &Value, name: &str) -> Option<bool> {
    info.map_get_int(4)
        .unwrap()
        .map_get_text(name)
        .and_then(Value::as_bool)
}

#[test]
fn golden_get_info_key_set_and_values_match_reference_device() {
    // Source: reference/physical-key/reference-observation.json ("present_cbor_keys",
    // "get_info_fields"). The observed key had a PIN set and one discoverable credential.
    let reference = reference();
    let present: Vec<i64> = reference
        .get("present_cbor_keys")
        .as_array()
        .iter()
        .map(Json::as_i64)
        .collect();
    let expected = expected(reference.get("get_info_fields"));

    // Factory state: everything equal except the two state-dependent values.
    let (mut auth, mut host) = yubikey_device();
    let info = get_info(&mut auth, &mut host);
    assert_eq!(keys(&info), present);
    for (key, want) in &expected {
        let got = info.map_get_int(*key).unwrap();
        match key {
            0x04 => {
                let want_map = want.as_map().unwrap();
                let got_map = got.as_map().unwrap();
                assert_eq!(got_map.len(), want_map.len());
                for ((gk, gv), (wk, wv)) in got_map.iter().zip(want_map) {
                    assert_eq!(gk, wk, "option order");
                    if gk.as_text() == Some("clientPin") {
                        assert_eq!(gv, &Value::Bool(false), "no PIN set at factory");
                    } else {
                        assert_eq!(gv, wv, "option {gk:?}");
                    }
                }
            }
            0x14 => assert_eq!(got, &Value::from(100u8), "empty device"),
            _ => assert_eq!(got, want, "GetInfo key {key:#04x}"),
        }
    }

    // Same state as the observed key, reached through the real commands: one
    // discoverable credential, then a PIN set with authenticatorClientPIN setPIN
    // (CTAP 2.1 §6.5.5.5). The encoding is then byte-identical to the reference.
    register(&mut auth, &mut host, &Mc::new().rk());
    super::platform::set_pin(&mut auth, &mut host, 2, super::platform::PIN);
    let info = get_info(&mut auth, &mut host);
    assert_eq!(keys(&info), present);
    let want = MapBuilder::new();
    let want = expected
        .iter()
        .fold(want, |m, (k, v)| m.insert(*k, v.clone()))
        .build();
    assert_eq!(info, want);
    assert_eq!(cbor::encode(&info), cbor::encode(&want));
    // And it survives a restart.
    let mut auth = restart(&mut host);
    assert_eq!(
        cbor::encode(&get_info(&mut auth, &mut host)),
        cbor::encode(&want)
    );
}

#[test]
fn own_profile_reports_own_aaguid_and_firmware() {
    // CTAP 2.1 §6.4 aaguid / firmwareVersion come from DeviceProfile (docs/DESIGN.md §9).
    let (mut auth, mut host) = device();
    let info = get_info(&mut auth, &mut host);
    assert_eq!(
        info.map_get_int(3).and_then(Value::as_bytes),
        Some(&DeviceProfile::own(0).aaguid[..])
    );
    assert_eq!(info.map_get_int(14).and_then(Value::as_u64), Some(0x050704));
    host.profile_mut().firmware = lk_core::Version::new(5, 8, 1);
    let info = get_info(&mut auth, &mut host);
    assert_eq!(info.map_get_int(14).and_then(Value::as_u64), Some(0x050801));
}

#[test]
fn client_pin_option_and_remaining_credentials_follow_state() {
    // CTAP 2.1 §6.4: clientPin false = capable but no PIN; remainingDiscoverableCredentials.
    let (mut auth, mut host) = device();
    assert_eq!(
        option(&get_info(&mut auth, &mut host), "clientPin"),
        Some(false)
    );
    register(&mut auth, &mut host, &Mc::new().rk().user(&[1]));
    register(&mut auth, &mut host, &Mc::new().rk().user(&[2]));
    let mut auth = with_state(&mut host, |s| {
        s.pin.hash = Some(SecretBytes::from_slice(&[1; 16]));
        s.pin.force_change = true;
        s.pin.min_length = 6;
    });
    let info = get_info(&mut auth, &mut host);
    assert_eq!(option(&info, "clientPin"), Some(true));
    assert_eq!(info.map_get_int(0x14).and_then(Value::as_u64), Some(98));
    assert_eq!(info.map_get_int(0x0C), Some(&Value::Bool(true)));
    assert_eq!(info.map_get_int(0x0D).and_then(Value::as_u64), Some(6));
}

#[test]
fn get_info_ignores_trailing_parameters_and_needs_no_touch() {
    // CTAP 2.1 §6.4 has no parameters; unknown input is ignored (§8).
    let (mut auth, mut host) = device();
    let plain = send_untouched(&mut auth, &mut host, &[0x04]);
    let extra = send_untouched(&mut auth, &mut host, &[0x04, 0xA0]);
    assert_eq!(plain, extra);
    assert_eq!(host.persist_attempts(), 0, "GetInfo never persists");
}
