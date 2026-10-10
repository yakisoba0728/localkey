//! authenticatorLargeBlobs (CTAP 2.1 §6.10).

use super::platform::{PIN, Token, perm, set_pin, token};
use super::*;
use crate::state::INITIAL_LARGE_BLOB;
use crate::status;

/// maxFragmentLength = maxMsgSize (1536, reference-observation.json) - 64 (§6.10.2).
const MAX_FRAGMENT: usize = 1536 - 64;

/// A serialized large-blob array: `contents || LEFT(SHA-256(contents), 16)` (§6.10.2).
fn array_with(contents: &[u8]) -> Vec<u8> {
    let mut out = contents.to_vec();
    out.extend_from_slice(&sha256(contents)[..16]);
    out
}

/// The pinUvAuthParam message: 32 × 0xff || h'0c00' || uint32LittleEndian(offset) ||
/// SHA-256(fragment) (§6.10.2).
fn lbw_message(offset: u32, fragment: &[u8]) -> Vec<u8> {
    let mut m = vec![0xFF; 32];
    m.extend_from_slice(&[0x0C, 0x00]);
    m.extend_from_slice(&offset.to_le_bytes());
    m.extend_from_slice(&sha256(fragment));
    m
}

fn set_request(
    fragment: &[u8],
    offset: usize,
    length: Option<usize>,
    auth: Option<&Token>,
) -> Vec<u8> {
    let mut m = MapBuilder::new()
        .insert(2, fragment.to_vec())
        .insert(3, offset);
    if let Some(length) = length {
        m.set(4, length);
    }
    if let Some(t) = auth {
        m.set(5, t.sign(&lbw_message(offset as u32, fragment)));
        m.set(6, t.protocol);
    }
    encode_request(0x0C, &m.build())
}

/// Send one `set` fragment and return the response.
pub(super) fn write_fragment(
    auth: &mut Authenticator,
    host: &mut TestHost,
    fragment: &[u8],
    offset: usize,
    length: Option<usize>,
    token: Option<&Token>,
) -> Vec<u8> {
    send_untouched(auth, host, &set_request(fragment, offset, length, token))
}

/// Write `array` in fragments of at most `chunk` bytes.
fn write_all(
    auth: &mut Authenticator,
    host: &mut TestHost,
    array: &[u8],
    chunk: usize,
    token: Option<&Token>,
) {
    for (i, fragment) in array.chunks(chunk).enumerate() {
        let offset = i * chunk;
        let length = (offset == 0).then_some(array.len());
        let r = write_fragment(auth, host, fragment, offset, length, token);
        assert_eq!(r, vec![status::OK], "fragment at {offset}");
    }
}

fn get(auth: &mut Authenticator, host: &mut TestHost, count: usize, offset: usize) -> Vec<u8> {
    let m = MapBuilder::new().insert(1, count).insert(3, offset).build();
    send_untouched(auth, host, &encode_request(0x0C, &m))
}

fn read_all(auth: &mut Authenticator, host: &mut TestHost) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let r = get(auth, host, MAX_FRAGMENT, out.len());
        let part = body(&r)
            .map_get_int(1)
            .and_then(Value::as_bytes)
            .unwrap()
            .to_vec();
        let done = part.len() < MAX_FRAGMENT;
        out.extend(part);
        if done {
            return out;
        }
    }
}

#[test]
fn the_initial_array_and_read_boundaries() {
    // CTAP 2.1 §6.10.2 "get": the initial array 80 76be8b528d0075f7aae98d6fa57a6d3c;
    // get above maxFragmentLength → INVALID_LENGTH; offset past the end → INVALID_PARAMETER;
    // length with get, both or neither of get/set → INVALID_PARAMETER; offset required.
    let (mut auth, mut host) = device();
    let initial = [
        0x80, 0x76, 0xbe, 0x8b, 0x52, 0x8d, 0x00, 0x75, 0xf7, 0xaa, 0xe9, 0x8d, 0x6f, 0xa5, 0x7a,
        0x6d, 0x3c,
    ];
    assert_eq!(read_all(&mut auth, &mut host), initial.to_vec());
    let r = get(&mut auth, &mut host, 5, 2);
    assert_eq!(
        body(&r).map_get_int(1).and_then(Value::as_bytes),
        Some(&initial[2..7])
    );
    let r = get(&mut auth, &mut host, 5, 17);
    assert_eq!(
        body(&r).map_get_int(1).and_then(Value::as_bytes),
        Some(&[][..])
    );
    assert_eq!(
        get(&mut auth, &mut host, 5, 18),
        vec![status::INVALID_PARAMETER]
    );
    assert_eq!(
        get(&mut auth, &mut host, MAX_FRAGMENT + 1, 0),
        vec![status::INVALID_LENGTH]
    );
    let send_map = |auth: &mut Authenticator, host: &mut TestHost, m: Value| {
        send_untouched(auth, host, &encode_request(0x0C, &m))
    };
    let both = MapBuilder::new()
        .insert(1, 5)
        .insert(2, vec![0u8])
        .insert(3, 0)
        .build();
    assert_eq!(
        send_map(&mut auth, &mut host, both),
        vec![status::INVALID_PARAMETER]
    );
    let neither = MapBuilder::new().insert(3, 0).build();
    assert_eq!(
        send_map(&mut auth, &mut host, neither),
        vec![status::INVALID_PARAMETER]
    );
    // §6.10.2 step 1: "If offset is not present in the input map, return
    // CTAP1_ERR_INVALID_PARAMETER" (for get and set alike).
    let no_offset = MapBuilder::new().insert(1, 5).build();
    assert_eq!(
        send_map(&mut auth, &mut host, no_offset),
        vec![status::INVALID_PARAMETER]
    );
    let no_offset_set = MapBuilder::new()
        .insert(2, INITIAL_LARGE_BLOB.to_vec())
        .insert(4, 17)
        .build();
    assert_eq!(
        send_map(&mut auth, &mut host, no_offset_set),
        vec![status::INVALID_PARAMETER]
    );
    // §6.10.2 step 4.2: "If either of pinUvAuthParam or pinUvAuthProtocol are present,
    // return CTAP1_ERR_INVALID_PARAMETER" (reads are never authenticated).
    for (key, value) in [(5i64, Value::Bytes(vec![0; 32])), (6, Value::from(2u8))] {
        let m = MapBuilder::new()
            .insert(1, 5)
            .insert(3, 0)
            .insert(key, value)
            .build();
        assert_eq!(
            send_map(&mut auth, &mut host, m),
            vec![status::INVALID_PARAMETER],
            "get with key {key}"
        );
    }
    // Extreme values: offset far past the end, get far above maxFragmentLength.
    assert_eq!(
        send_map(
            &mut auth,
            &mut host,
            MapBuilder::new().insert(1, 1).insert(3, u64::MAX).build()
        ),
        vec![status::INVALID_PARAMETER]
    );
    assert_eq!(
        send_map(
            &mut auth,
            &mut host,
            MapBuilder::new().insert(1, u64::MAX).insert(3, 0).build()
        ),
        vec![status::INVALID_LENGTH]
    );
    let with_length = MapBuilder::new()
        .insert(1, 5)
        .insert(3, 0)
        .insert(4, 17)
        .build();
    assert_eq!(
        send_map(&mut auth, &mut host, with_length),
        vec![status::INVALID_PARAMETER]
    );
    let wrong_type = MapBuilder::new().insert(1, "5").insert(3, 0).build();
    assert_eq!(
        send_map(&mut auth, &mut host, wrong_type),
        vec![status::CBOR_UNEXPECTED_TYPE]
    );
    assert_eq!(host.persist_attempts(), 0);
}

#[test]
fn write_and_read_across_fragments_without_a_pin() {
    // CTAP 2.1 §6.10.2: without a PIN no pinUvAuthParam is needed; the array is persisted
    // only after its last fragment and survives a restart.
    let (mut auth, mut host) = device();
    let array = array_with(&(0..2984u32).map(|i| (i * 7) as u8).collect::<Vec<_>>());
    assert_eq!(array.len(), 3000);
    let mut fragments = array.chunks(MAX_FRAGMENT);
    let first = fragments.next().unwrap();
    assert_eq!(
        write_fragment(&mut auth, &mut host, first, 0, Some(3000), None),
        vec![0]
    );
    assert_eq!(host.persist_attempts(), 0, "nothing persisted mid-sequence");
    assert_eq!(read_all(&mut auth, &mut host), INITIAL_LARGE_BLOB.to_vec());
    let second = fragments.next().unwrap();
    assert_eq!(
        write_fragment(&mut auth, &mut host, second, MAX_FRAGMENT, None, None),
        vec![0]
    );
    let third = fragments.next().unwrap();
    assert_eq!(third.len(), 56);
    assert_eq!(
        write_fragment(&mut auth, &mut host, third, 2 * MAX_FRAGMENT, None, None),
        vec![0]
    );
    assert_eq!(host.persist_count(), 1);
    assert_eq!(read_all(&mut auth, &mut host), array);
    let mut auth = restart(&mut host);
    assert_eq!(read_all(&mut auth, &mut host), array);
    // A further fragment after completion is out of sequence.
    assert_eq!(
        write_fragment(&mut auth, &mut host, &[1], 3000, None, None),
        vec![status::INVALID_SEQ]
    );
}

#[test]
fn fragment_and_length_boundaries() {
    // BEHAVIOR_CATALOG FIDO: "1472-byte large-blob fragments with boundary checks";
    // CTAP 2.1 §6.10.2: fragment > maxFragmentLength → INVALID_LENGTH; length >
    // maxSerializedLargeBlobArray (4096) → LARGE_BLOB_STORAGE_FULL; length < 17, offset 0
    // without length, length with a non-zero offset, or a fragment beyond the declared
    // length → INVALID_PARAMETER.
    let (mut auth, mut host) = device();
    set_pin(&mut auth, &mut host, 2, PIN);
    let t = token(&mut auth, &mut host, 2, perm::LBW, None);
    // A full 1472-byte fragment with protocol-2 authorization fits in one message.
    let full = vec![0xAB; MAX_FRAGMENT];
    let request = set_request(&full, 0, Some(4096), Some(&t));
    assert!(request.len() <= 1536, "request is {} bytes", request.len());
    assert_eq!(
        send_untouched(&mut auth, &mut host, &request),
        vec![status::OK]
    );
    let over = vec![0xAB; MAX_FRAGMENT + 1];
    assert_eq!(
        write_fragment(&mut auth, &mut host, &over, 0, Some(4096), Some(&t)),
        vec![status::INVALID_LENGTH]
    );
    assert_eq!(
        write_fragment(&mut auth, &mut host, &full, 0, Some(4097), Some(&t)),
        vec![status::LARGE_BLOB_STORAGE_FULL]
    );
    assert_eq!(
        write_fragment(&mut auth, &mut host, &[0x80], 0, Some(16), Some(&t)),
        vec![status::INVALID_PARAMETER]
    );
    assert_eq!(
        write_fragment(&mut auth, &mut host, &[0x80], 0, None, Some(&t)),
        vec![status::INVALID_PARAMETER]
    );
    let array = array_with(&[0x80]);
    assert_eq!(
        write_fragment(&mut auth, &mut host, &array[..10], 0, Some(17), Some(&t)),
        vec![0]
    );
    assert_eq!(
        write_fragment(&mut auth, &mut host, &array[10..], 10, Some(17), Some(&t)),
        vec![status::INVALID_PARAMETER],
        "length only at offset 0"
    );
    assert_eq!(
        write_fragment(&mut auth, &mut host, &[0; 8], 10, None, Some(&t)),
        vec![status::INVALID_PARAMETER],
        "beyond the declared length"
    );
    assert_eq!(
        write_fragment(&mut auth, &mut host, &array[10..], 10, None, Some(&t)),
        vec![0]
    );
    assert_eq!(read_all(&mut auth, &mut host), array);
    // The largest array is accepted.
    let biggest = array_with(&vec![0x5A; 4096 - 16]);
    write_all(&mut auth, &mut host, &biggest, MAX_FRAGMENT, Some(&t));
    assert_eq!(read_all(&mut auth, &mut host), biggest);
}

#[test]
fn a_pin_requires_a_token_with_the_large_blob_write_permission() {
    // CTAP 2.1 §6.10.2: with a PIN, pinUvAuthParam absent → PUAT_REQUIRED; protocol absent
    // → MISSING_PARAMETER, unsupported → INVALID_PARAMETER; wrong MAC or no lbw permission
    // → PIN_AUTH_INVALID.
    for protocol in [1u8, 2] {
        let (mut auth, mut host) = device();
        set_pin(&mut auth, &mut host, protocol, PIN);
        let array = array_with(b"\xA1\x01\x02");
        assert_eq!(
            write_fragment(&mut auth, &mut host, &array, 0, Some(array.len()), None),
            vec![status::PUAT_REQUIRED]
        );
        let t = token(&mut auth, &mut host, protocol, perm::LBW, None);
        let mut m = MapBuilder::new()
            .insert(2, array.clone())
            .insert(3, 0)
            .insert(4, array.len())
            .insert(5, t.sign(&lbw_message(0, &array)));
        let r = send_untouched(
            &mut auth,
            &mut host,
            &encode_request(0x0C, &m.clone().build()),
        );
        assert_eq!(r, vec![status::MISSING_PARAMETER]);
        m.set(6, 3);
        let r = send_untouched(&mut auth, &mut host, &encode_request(0x0C, &m.build()));
        assert_eq!(r, vec![status::INVALID_PARAMETER]);
        // The MAC covers the offset: a MAC for offset 1 does not verify at offset 0.
        let wrong = MapBuilder::new()
            .insert(2, array.clone())
            .insert(3, 0)
            .insert(4, array.len())
            .insert(5, t.sign(&lbw_message(1, &array)))
            .insert(6, protocol)
            .build();
        let r = send_untouched(&mut auth, &mut host, &encode_request(0x0C, &wrong));
        assert_eq!(r, vec![status::PIN_AUTH_INVALID]);
        let no_lbw = token(
            &mut auth,
            &mut host,
            protocol,
            perm::GA | perm::CM | perm::ACFG,
            None,
        );
        assert_eq!(
            write_fragment(
                &mut auth,
                &mut host,
                &array,
                0,
                Some(array.len()),
                Some(&no_lbw)
            ),
            vec![status::PIN_AUTH_INVALID]
        );
        let t = token(&mut auth, &mut host, protocol, perm::LBW, None);
        write_all(&mut auth, &mut host, &array, 4, Some(&t));
        assert_eq!(read_all(&mut auth, &mut host), array);
        // Reading never needs a token.
        assert_eq!(status_of(&get(&mut auth, &mut host, 1, 0)), status::OK);
    }
}

#[test]
fn the_sequence_is_checked_before_authorization_and_restarts_at_offset_zero() {
    // BEHAVIOR_CATALOG FIDO: "large-blob write validates fragment sequence before PIN/UV
    // auth and restarts a sequence on offset zero" (CTAP 2.1 §6.10.2 step order).
    let (mut auth, mut host) = device();
    set_pin(&mut auth, &mut host, 2, PIN);
    // No sequence in progress: a non-zero offset is INVALID_SEQ even without a token.
    assert_eq!(
        write_fragment(&mut auth, &mut host, &[1, 2, 3], 100, None, None),
        vec![status::INVALID_SEQ]
    );
    let t = token(&mut auth, &mut host, 2, perm::LBW, None);
    let old = array_with(&[0x61; 40]);
    assert_eq!(
        write_fragment(&mut auth, &mut host, &old[..20], 0, Some(56), Some(&t)),
        vec![0]
    );
    assert_eq!(
        write_fragment(&mut auth, &mut host, &old[20..], 21, None, None),
        vec![status::INVALID_SEQ],
        "wrong offset reported before PUAT_REQUIRED"
    );
    assert_eq!(
        write_fragment(&mut auth, &mut host, &old[20..], 20, None, None),
        vec![status::PUAT_REQUIRED],
        "right offset, then authorization"
    );
    // A new sequence at offset 0 discards the old one.
    let new = array_with(&[0x62; 30]);
    assert_eq!(
        write_fragment(&mut auth, &mut host, &new[..30], 0, Some(46), Some(&t)),
        vec![0]
    );
    assert_eq!(
        write_fragment(&mut auth, &mut host, &old[20..], 20, None, Some(&t)),
        vec![status::INVALID_SEQ],
        "the old sequence is gone"
    );
    assert_eq!(
        write_fragment(&mut auth, &mut host, &new[30..], 30, None, Some(&t)),
        vec![0]
    );
    assert_eq!(read_all(&mut auth, &mut host), new);
}

#[test]
fn offset_and_length_abuse_never_corrupts_a_pending_write() {
    // CTAP 2.1 §6.10.2 step 5 order: fragment > maxFragmentLength (5.1, INVALID_LENGTH);
    // at offset 0, length absent / above capacity / below 17 (5.2.1-5.2.3) end the request
    // *before* expectedLength and expectedNextOffset are reset (5.2.4-5.2.5), so a pending
    // sequence survives them; length with a non-zero offset (5.3.1, INVALID_PARAMETER) comes
    // before the sequence check (5.4, INVALID_SEQ); a fragment overrunning expectedLength
    // (5.6, INVALID_PARAMETER) changes nothing.
    let (mut auth, mut host) = device();
    set_pin(&mut auth, &mut host, 2, PIN);
    let t = token(&mut auth, &mut host, 2, perm::LBW, None);
    let array = array_with(&[0x63; 50]);
    assert_eq!(
        write_fragment(&mut auth, &mut host, &array[..30], 0, Some(66), Some(&t)),
        vec![0]
    );
    let rejected: [(Vec<u8>, usize, Option<usize>, u8); 6] = [
        (
            vec![0; MAX_FRAGMENT + 1],
            0,
            Some(66),
            status::INVALID_LENGTH,
        ),
        (vec![0; 17], 0, None, status::INVALID_PARAMETER),
        (vec![0; 17], 0, Some(4097), status::LARGE_BLOB_STORAGE_FULL),
        (vec![0; 16], 0, Some(16), status::INVALID_PARAMETER),
        (
            array[30..].to_vec(),
            30,
            Some(66),
            status::INVALID_PARAMETER,
        ),
        (vec![0; 37], 30, None, status::INVALID_PARAMETER),
    ];
    for (fragment, offset, length, want) in &rejected {
        assert_eq!(
            write_fragment(&mut auth, &mut host, fragment, *offset, *length, Some(&t)),
            vec![*want],
            "offset {offset} length {length:?}"
        );
    }
    // Offsets that cannot be the next one, including ones beyond u32 and u64::MAX.
    for offset in [1u64, 29, 31, 66, 0xFFFF_FFFF, 0x1_0000_001E, u64::MAX] {
        let m = MapBuilder::new()
            .insert(2, array[30..].to_vec())
            .insert(3, offset)
            .build();
        assert_eq!(
            send_untouched(&mut auth, &mut host, &encode_request(0x0C, &m)),
            vec![status::INVALID_SEQ],
            "offset {offset:#x}"
        );
    }
    // The pending sequence is intact: the right fragment completes it.
    assert_eq!(
        write_fragment(&mut auth, &mut host, &array[30..], 30, None, Some(&t)),
        vec![0]
    );
    assert_eq!(read_all(&mut auth, &mut host), array);

    // A well-formed offset-0 request resets the sequence even when its authorization then
    // fails (5.2.4-5.2.5 precede 5.5): the earlier sequence's next fragment is INVALID_SEQ.
    // This is the spec order (and the catalog's "restarts a sequence on offset zero").
    let next = array_with(&[0x64; 40]);
    assert_eq!(
        write_fragment(&mut auth, &mut host, &next[..20], 0, Some(56), Some(&t)),
        vec![0]
    );
    assert_eq!(
        write_fragment(&mut auth, &mut host, &next[..20], 0, Some(56), None),
        vec![status::PUAT_REQUIRED]
    );
    assert_eq!(
        write_fragment(&mut auth, &mut host, &next[20..], 20, None, Some(&t)),
        vec![status::INVALID_SEQ]
    );
    assert_eq!(
        read_all(&mut auth, &mut host),
        array,
        "stored array unchanged"
    );
}

#[test]
fn integrity_and_storage_failures_keep_the_previous_array() {
    // CTAP 2.1 §6.10.2: a wrong trailer → INTEGRITY_FAILURE; docs/CONTRACTS.md: a storage
    // failure → CTAP1_ERR_OTHER with the previous state kept.
    let (mut auth, mut host) = device();
    let mut bad = array_with(&[0x80; 20]);
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert_eq!(
        write_fragment(&mut auth, &mut host, &bad, 0, Some(bad.len()), None),
        vec![status::INTEGRITY_FAILURE]
    );
    assert_eq!(read_all(&mut auth, &mut host), INITIAL_LARGE_BLOB.to_vec());
    assert_eq!(
        write_fragment(&mut auth, &mut host, &[0], 36, None, None),
        vec![status::INVALID_SEQ],
        "a failed sequence is over"
    );
    let good = array_with(&[0x81; 20]);
    assert_eq!(
        write_fragment(&mut auth, &mut host, &good[..10], 0, Some(36), None),
        vec![0]
    );
    host.fail_next_saves(1);
    assert_eq!(
        write_fragment(&mut auth, &mut host, &good[10..], 10, None, None),
        vec![status::OTHER]
    );
    assert_eq!(read_all(&mut auth, &mut host), INITIAL_LARGE_BLOB.to_vec());
    assert_eq!(
        write_fragment(&mut auth, &mut host, &good[10..], 10, None, None),
        vec![0]
    );
    assert_eq!(read_all(&mut auth, &mut host), good);
}

#[test]
fn power_cycle_drops_a_pending_write_and_reset_restores_the_initial_array() {
    // The pending sequence is volatile (docs/DESIGN.md §7); CTAP 2.1 §6.6 reset wipes the
    // large-blob array back to its initial value.
    let (mut auth, mut host) = device();
    let array = array_with(&[0x99; 30]);
    write_all(&mut auth, &mut host, &array, 100, None);
    assert_eq!(
        write_fragment(&mut auth, &mut host, &array[..20], 0, Some(46), None),
        vec![0]
    );
    // Other commands leave the sequence alone.
    get_info(&mut auth, &mut host);
    assert_eq!(status_of(&get(&mut auth, &mut host, 4, 0)), status::OK);
    auth.power_cycle(&mut host);
    assert_eq!(
        write_fragment(&mut auth, &mut host, &array[20..], 20, None, None),
        vec![status::INVALID_SEQ]
    );
    assert_eq!(read_all(&mut auth, &mut host), array);
    assert_eq!(send(&mut auth, &mut host, &[0x07]), vec![status::OK]);
    assert_eq!(read_all(&mut auth, &mut host), INITIAL_LARGE_BLOB.to_vec());
    assert_eq!(
        persisted_state(&host).large_blob,
        INITIAL_LARGE_BLOB.to_vec()
    );
}

#[test]
fn a_write_sequence_ends_when_its_token_expires() {
    // CTAP 2.1 §6 stateful commands: the authenticatorLargeBlobs set sequence "MUST" be
    // discarded once the pinUvAuthToken that authenticated its offset-0 fragment expires.
    // A token replaced by a new issuance (resetPinUvAuthToken, §6.5.5.7.2 step 12) or past
    // its 600 s max usage time period (§6.5.2.1) has expired; the next fragment then finds
    // no sequence (INVALID_SEQ, §6.10.2 step 5.4) even with a valid new token.
    let (mut auth, mut host) = device();
    set_pin(&mut auth, &mut host, 2, PIN);
    let array = array_with(&[0x65; 60]);
    // Replaced by a new token.
    let t1 = token(&mut auth, &mut host, 2, perm::LBW, None);
    assert_eq!(
        write_fragment(&mut auth, &mut host, &array[..40], 0, Some(76), Some(&t1)),
        vec![0]
    );
    let t2 = token(&mut auth, &mut host, 2, perm::LBW, None);
    assert_eq!(
        write_fragment(&mut auth, &mut host, &array[40..], 40, None, Some(&t2)),
        vec![status::INVALID_SEQ]
    );
    // Past the max usage time period.
    let start = host.now();
    assert_eq!(
        write_fragment(&mut auth, &mut host, &array[..40], 0, Some(76), Some(&t2)),
        vec![0]
    );
    host.set_now(start + 600_001);
    assert_eq!(
        write_fragment(&mut auth, &mut host, &array[40..], 40, None, Some(&t2)),
        vec![status::INVALID_SEQ]
    );
    // Within the token's lifetime the sequence completes, other commands in between.
    let t3 = token(&mut auth, &mut host, 2, perm::LBW, None);
    assert_eq!(
        write_fragment(&mut auth, &mut host, &array[..40], 0, Some(76), Some(&t3)),
        vec![0]
    );
    get_info(&mut auth, &mut host);
    host.advance(599_000);
    assert_eq!(
        write_fragment(&mut auth, &mut host, &array[40..], 40, None, Some(&t3)),
        vec![0]
    );
    assert_eq!(read_all(&mut auth, &mut host), array);
}
