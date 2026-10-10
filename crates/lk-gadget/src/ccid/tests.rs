use super::*;

const PACKET: usize = 64;
/// `dwMaxCCIDMessageLength` of the reference descriptor: the whole message, header
/// included (USB CCID Rev 1.1 §5.1).
const MAX_MESSAGE: usize = 3072;
/// The largest `abData` that fits.
const MAX_DATA: usize = MAX_MESSAGE - HEADER_LEN;

/// A `PC_to_RDR_XfrBlock` (CCID Rev 1.1 §6.1.4) with `data_length` bytes of `abData`.
fn message(data_length: usize, seq: u8) -> Vec<u8> {
    let length = u32::try_from(data_length).expect("test sizes fit").to_le_bytes();
    let mut out = vec![0x6F, length[0], length[1], length[2], length[3], 0, seq, 0, 0, 0];
    out.extend((0..data_length).map(|i| (i % 251) as u8));
    out
}

/// A header announcing `data_length`, padded to `size` bytes.
fn header_announcing(data_length: u32, size: usize) -> Vec<u8> {
    let length = data_length.to_le_bytes();
    let mut out = vec![0x6F, length[0], length[1], length[2], length[3], 0, 1, 0, 0, 0];
    out.resize(size, 0xAA);
    out
}

/// Push a message packet by packet; the results.
fn push_all(reassembler: &mut Reassembler, bytes: &[u8]) -> Vec<Assembled> {
    bytes.chunks(PACKET).map(|packet| reassembler.push(packet)).collect()
}

fn reassembler() -> Reassembler {
    Reassembler::new(PACKET, MAX_MESSAGE)
}

#[test]
fn a_message_in_one_short_packet_is_complete_at_once() {
    let mut r = reassembler();
    let m = message(5, 1);
    assert_eq!(r.push(&m), Assembled::Message(m.clone()));
    assert!(r.is_idle());
    assert_eq!(r.read_len(), PACKET);
}

#[test]
fn a_message_in_two_packets_is_complete_after_the_short_second_one() {
    let mut r = reassembler();
    let m = message(100, 2);
    assert_eq!(push_all(&mut r, &m), [Assembled::Pending, Assembled::Message(m.clone())]);
    assert!(r.is_idle());
}

#[test]
fn a_message_that_fills_one_packet_exactly_needs_no_zero_length_packet() {
    let mut r = reassembler();
    let m = message(54, 3);
    assert_eq!(m.len(), PACKET);
    assert_eq!(r.push(&m), Assembled::Message(m.clone()));
    // A zero-length packet a host might still send is ignored.
    assert_eq!(r.push(&[]), Assembled::Pending);
    let next = message(1, 4);
    assert_eq!(r.push(&next), Assembled::Message(next.clone()));
}

#[test]
fn a_message_that_fills_two_packets_exactly_is_complete_after_the_second_full_packet() {
    let mut r = reassembler();
    let m = message(118, 5);
    assert_eq!(m.len(), 2 * PACKET);
    assert_eq!(push_all(&mut r, &m), [Assembled::Pending, Assembled::Message(m.clone())]);
    assert!(r.is_idle());
}

#[test]
fn a_message_of_the_largest_accepted_length_is_assembled() {
    let mut r = reassembler();
    let m = message(MAX_DATA, 6);
    assert_eq!(m.len(), MAX_MESSAGE, "the cap counts the header");
    let results = push_all(&mut r, &m);
    assert_eq!(results.last(), Some(&Assembled::Message(m.clone())));
    assert!(results[..results.len() - 1].iter().all(|a| *a == Assembled::Pending));
}

#[test]
fn an_oversize_message_is_dropped_and_its_transfer_discarded_before_the_next_message() {
    let mut r = reassembler();
    let oversize = message(MAX_DATA + 1, 7);
    let results = push_all(&mut r, &oversize);
    assert_eq!(results[0], Assembled::Dropped(DropReason::Oversize { announced: (MAX_DATA + 11) as u64 }));
    assert!(results[1..].iter().all(|a| *a == Assembled::Pending));
    assert!(r.is_idle());
    let next = message(20, 8);
    assert_eq!(r.push(&next), Assembled::Message(next.clone()));
}

#[test]
fn the_discard_of_an_oversize_message_ends_at_a_short_packet() {
    let mut r = reassembler();
    assert_eq!(
        r.push(&header_announcing(u32::MAX, PACKET)),
        Assembled::Dropped(DropReason::Oversize { announced: 10 + u64::from(u32::MAX) })
    );
    assert_eq!(r.push(&[0x55; PACKET]), Assembled::Pending);
    assert!(!r.is_idle());
    assert_eq!(r.push(&[0x55; 12]), Assembled::Pending);
    assert!(r.is_idle());
    let next = message(3, 9);
    assert_eq!(r.push(&next), Assembled::Message(next.clone()));
}

#[test]
fn an_oversize_header_in_a_short_packet_discards_nothing_more() {
    let mut r = reassembler();
    assert!(matches!(r.push(&header_announcing(5000, 20)), Assembled::Dropped(DropReason::Oversize { .. })));
    assert!(r.is_idle());
}

#[test]
fn a_runt_first_packet_is_dropped_and_the_next_packet_starts_a_message() {
    let mut r = reassembler();
    assert_eq!(r.push(&[0x6F, 1, 0, 0, 0]), Assembled::Dropped(DropReason::Runt { length: 5 }));
    let next = message(0, 10);
    assert_eq!(r.push(&next), Assembled::Message(next.clone()));
}

#[test]
fn a_short_packet_before_the_announced_length_truncates_the_message() {
    let mut r = reassembler();
    let m = message(200, 11);
    assert_eq!(r.push(&m[..64]), Assembled::Pending);
    assert_eq!(r.push(&m[64..100]), Assembled::Dropped(DropReason::Truncated { expected: 210, received: 100 }));
    assert!(r.is_idle());
    let next = message(2, 12);
    assert_eq!(r.push(&next), Assembled::Message(next.clone()));
}

#[test]
fn a_short_first_packet_below_the_announced_length_is_truncated() {
    let mut r = reassembler();
    assert_eq!(
        r.push(&header_announcing(100, 30)),
        Assembled::Dropped(DropReason::Truncated { expected: 110, received: 30 })
    );
}

#[test]
fn a_zero_length_packet_inside_a_message_truncates_it() {
    let mut r = reassembler();
    let m = message(100, 13);
    assert_eq!(r.push(&m[..64]), Assembled::Pending);
    assert_eq!(r.push(&[]), Assembled::Dropped(DropReason::Truncated { expected: 110, received: 64 }));
    assert!(r.is_idle());
}

#[test]
fn bytes_after_the_announced_length_in_the_last_packet_are_dropped() {
    let mut r = reassembler();
    let m = message(4, 14);
    let mut packet = m.clone();
    packet.extend_from_slice(&[0xEE; 20]);
    assert_eq!(r.push(&packet), Assembled::Message(m));
    let long = message(70, 15);
    let mut second = long[64..].to_vec();
    second.extend_from_slice(&[0xEE; 10]);
    assert_eq!(r.push(&long[..64]), Assembled::Pending);
    assert_eq!(r.push(&second), Assembled::Message(long));
}

#[test]
fn a_reset_drops_a_message_in_progress() {
    let mut r = reassembler();
    assert_eq!(r.reset(), None);
    let m = message(100, 16);
    assert_eq!(r.push(&m[..64]), Assembled::Pending);
    assert_eq!(r.reset(), Some(DropReason::Interrupted { received: 64 }));
    assert!(r.is_idle());
    let _ = r.push(&header_announcing(u32::MAX, PACKET));
    assert_eq!(r.reset(), None);
    assert!(r.is_idle());
}

#[test]
fn debug_output_shows_sizes_and_state_not_bytes() {
    let mut r = reassembler();
    let m = message(100, 0x5A);
    let _ = r.push(&m[..64]);
    let debug = format!("{r:?}");
    assert!(debug.contains("64 of 110 bytes"), "{debug}");
    assert_eq!(format!("{:?}", Assembled::Message(m)), "Message(110 bytes)");
}
