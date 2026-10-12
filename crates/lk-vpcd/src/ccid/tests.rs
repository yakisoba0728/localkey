//! CCID host tests: the exact bytes of every bulk-out message, every `bStatus` class, the
//! `bSeq` wrap, the message limit from the class descriptor, and APDU exchanges with and
//! without command and response chaining (USB CCID Rev 1.1 §5.1, §6.1, §6.2).

use super::*;

/// A bulk-in message written by hand from §6.2: type, `dwLength`, slot 0, `seq`, status,
/// error, byte 9, data.
fn bulk_in(kind: u8, seq: u8, status: u8, error: u8, specific: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&[0, seq, status, error, specific]);
    out.extend_from_slice(data);
    out
}

fn reply(kind: u8, seq: u8, status: u8, error: u8, specific: u8, data: &[u8]) -> Reply {
    Reply::parse(&bulk_in(kind, seq, status, error, specific, data)).expect("hand-built replies parse")
}

fn data_block(seq: u8, chain: u8, data: &[u8]) -> Reply {
    reply(0x80, seq, 0x00, 0x00, chain, data)
}

/// The class descriptor of the reference key (54 bytes, §5.1), `dwMaxCCIDMessageLength`
/// 3072 at offset 44.
fn reference_descriptor() -> Vec<u8> {
    let mut descriptor = vec![0; 54];
    descriptor[0] = 0x36;
    descriptor[1] = 0x21;
    descriptor[44..48].copy_from_slice(&3072u32.to_le_bytes());
    descriptor
}

/// A descriptor whose `dwMaxCCIDMessageLength` is `value`.
fn descriptor_with(value: u32) -> Vec<u8> {
    let mut descriptor = reference_descriptor();
    descriptor[44..48].copy_from_slice(&value.to_le_bytes());
    descriptor
}

/// `(wLevelParameter, abData)` of an XfrBlock built by this crate, with its header checked.
fn xfr_parts(message: &[u8], seq: u8) -> (u16, Vec<u8>) {
    assert_eq!(message[0], 0x6F, "XfrBlock");
    let length = u32::from_le_bytes([message[1], message[2], message[3], message[4]]) as usize;
    assert_eq!(length, message.len() - 10, "dwLength");
    assert_eq!((message[5], message[6], message[7]), (0, seq, 0), "slot, seq, bBWI");
    (u16::from_le_bytes([message[8], message[9]]), message[10..].to_vec())
}

#[test]
fn icc_power_on_is_type_62_with_automatic_voltage() {
    assert_eq!(icc_power_on(0x00), [0x62, 0, 0, 0, 0, 0, 0x00, 0, 0, 0]);
    assert_eq!(icc_power_on(0x7E), [0x62, 0, 0, 0, 0, 0, 0x7E, 0, 0, 0]);
}

#[test]
fn icc_power_off_is_type_63() {
    assert_eq!(icc_power_off(0x05), [0x63, 0, 0, 0, 0, 0, 0x05, 0, 0, 0]);
}

#[test]
fn abort_is_type_72_with_no_data() {
    assert_eq!(abort(0x09), [0x72, 0, 0, 0, 0, 0, 0x09, 0, 0, 0]);
    assert_eq!(abort(0xFF), [0x72, 0, 0, 0, 0, 0, 0xFF, 0, 0, 0]);
}

#[test]
fn an_xfr_block_carries_its_length_little_endian_and_the_level_parameter() {
    let data: Vec<u8> = (0..300u16).map(|i| i as u8).collect();
    let block = xfr_block(0x11, level::CONTINUE, &data);
    assert_eq!(&block[..10], &[0x6F, 0x2C, 0x01, 0, 0, 0, 0x11, 0, 0x03, 0x00]);
    assert_eq!(&block[10..], &data[..]);
    let fetch = xfr_block(0x12, level::RESPONSE_CONTINUATION, &[]);
    assert_eq!(fetch, [0x6F, 0, 0, 0, 0, 0, 0x12, 0, 0x10, 0x00]);
}

#[test]
fn the_sequence_counts_up_and_wraps_after_ff() {
    let mut seq = Sequence::default();
    assert_eq!((seq.take(), seq.take(), seq.take()), (0, 1, 2));
    let mut seq = Sequence::starting_at(0xFE);
    assert_eq!((seq.take(), seq.take(), seq.take()), (0xFE, 0xFF, 0x00));
}

#[test]
fn a_reply_is_parsed_field_by_field() {
    let parsed = Reply::parse(&bulk_in(0x80, 9, 0x00, 0x00, 0x01, &[0x3B, 0xFD])).expect("valid");
    assert_eq!(
        parsed,
        Reply { kind: 0x80, slot: 0, seq: 9, status: 0, error: 0, specific: 0x01, data: vec![0x3B, 0xFD] }
    );
    let status = Reply::parse(&bulk_in(0x81, 3, 0x01, 0x00, 0x00, &[])).expect("valid");
    assert_eq!((status.kind, status.seq, status.data.len()), (0x81, 3, 0));
}

#[test]
fn a_reply_shorter_than_its_header_or_with_a_wrong_length_is_refused() {
    for len in 0..10 {
        assert_eq!(Reply::parse(&vec![0x80; len]), Err(ReplyError::TooShort { len }));
    }
    let mut long = bulk_in(0x80, 0, 0, 0, 0, &[1, 2, 3]);
    long.push(4);
    assert_eq!(Reply::parse(&long), Err(ReplyError::LengthMismatch { announced: 3, actual: 4 }));
    let mut short = bulk_in(0x80, 0, 0, 0, 0, &[1, 2, 3]);
    short.pop();
    assert_eq!(Reply::parse(&short), Err(ReplyError::LengthMismatch { announced: 3, actual: 2 }));
    assert!(ReplyError::TooShort { len: 3 }.to_string().contains("3 bytes"));
}

#[test]
fn every_command_status_and_icc_status_is_read_from_bstatus() {
    let status = |byte: u8| reply(0x80, 0, byte, 0, 0, &[]);
    assert_eq!(status(0x00).command_status(), CommandStatus::Ok);
    assert_eq!(status(0x40).command_status(), CommandStatus::Failed);
    assert_eq!(status(0x80).command_status(), CommandStatus::TimeExtension);
    assert_eq!(status(0xC0).command_status(), CommandStatus::Reserved);
    assert_eq!(status(0x40).icc_status(), IccStatus::Active);
    assert_eq!(status(0x41).icc_status(), IccStatus::Inactive);
    assert_eq!(status(0x42).icc_status(), IccStatus::Absent);
    assert_eq!(status(0x43).icc_status(), IccStatus::Reserved);
    assert!(status(0x80).is_time_extension());
    assert!(status(0x81).is_time_extension(), "the ICC bits do not matter");
    assert!(!status(0x00).is_time_extension());
    assert!(!status(0x40).is_time_extension());
}

#[test]
fn reply_debug_shows_the_size_of_the_data_never_its_bytes() {
    let text = format!("{:?}", data_block(1, 0, &[0xDE, 0xAD, 0xBE, 0xEF]));
    assert!(text.contains("4 bytes"), "{text}");
    for byte in ["0xde", "0xad", "0xbe", "0xef", "222", "173", "190", "239"] {
        assert!(!text.to_lowercase().contains(byte), "{byte} in {text}");
    }
    let text = format!("{:?}", Response(vec![0x31, 0x32, 0x33, 0x90, 0x00]));
    assert_eq!(text, "Response(5 bytes)");
    let exchange = ApduExchange::new(&[0x00, 0x20, 0x00, 0x80, 0x02, 0x31, 0x32], 261);
    let text = format!("{exchange:?}");
    assert!(text.contains("7 bytes"), "{text}");
}

#[test]
fn the_atr_comes_from_a_successful_data_block() {
    let atr = [0x3B, 0xFD, 0x13, 0x00];
    assert_eq!(power_on_atr(&data_block(0, 0, &atr)), Ok(atr.to_vec()));
    assert_eq!(power_on_atr(&data_block(0, 0, &[])), Err(Fault::NoAtr));
    assert_eq!(
        power_on_atr(&reply(0x80, 0, 0x42, 0xFE, 0, &[])),
        Err(Fault::Failed { error: 0xFE, icc: IccStatus::Absent })
    );
    assert_eq!(power_on_atr(&reply(0x81, 0, 0, 0, 0, &[])), Err(Fault::UnexpectedType { kind: 0x81 }));
    assert_eq!(power_on_atr(&reply(0x80, 0, 0x80, 1, 0, &[])), Err(Fault::TimeExtension));
}

#[test]
fn power_off_is_done_with_a_successful_slot_status() {
    assert_eq!(power_off_done(&reply(0x81, 0, 0x01, 0, 0, &[])), Ok(()));
    assert_eq!(
        power_off_done(&reply(0x81, 0, 0x41, 0xE0, 0, &[])),
        Err(Fault::Failed { error: 0xE0, icc: IccStatus::Inactive })
    );
    assert_eq!(power_off_done(&reply(0x80, 0, 0, 0, 0, &[])), Err(Fault::UnexpectedType { kind: 0x80 }));
}

#[test]
fn the_message_limit_comes_from_dw_max_ccid_message_length() {
    assert_eq!(max_data_len(&reference_descriptor()), 3062, "3072 minus the header");
    assert_eq!(max_data_len(&descriptor_with(271)), 261);
    assert_eq!(max_data_len(&descriptor_with(1000)), 990);
}

#[test]
fn the_message_limit_stays_within_the_bounds_of_section_5_1() {
    assert_eq!(max_data_len(&descriptor_with(0)), 261, "below 261 + 10");
    assert_eq!(max_data_len(&descriptor_with(64)), 261);
    assert_eq!(max_data_len(&descriptor_with(u32::MAX)), 65_544, "above 65544 + 10");
    assert_eq!(max_data_len(&[]), 261, "no descriptor");
    assert_eq!(max_data_len(&reference_descriptor()[..47]), 261, "a descriptor cut inside the field");
}

#[test]
fn a_short_apdu_is_one_xfr_block_answered_by_one_data_block() {
    let apdu = [0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];
    let mut exchange = ApduExchange::new(&apdu, 3062);
    let block = exchange.message(4);
    assert_eq!(xfr_parts(&block, 4), (level::BEGIN_AND_END, apdu.to_vec()));
    assert_eq!(exchange.accept(&data_block(4, 0x00, &[0x90, 0x00])), Next::Done(Response(vec![0x90, 0x00])));
}

#[test]
fn an_apdu_of_exactly_the_limit_is_still_one_block() {
    let apdu = vec![0x5A; 261];
    let mut exchange = ApduExchange::new(&apdu, 261);
    assert_eq!(xfr_parts(&exchange.message(0), 0), (level::BEGIN_AND_END, apdu));
    assert_eq!(exchange.accept(&data_block(0, 0, &[0x6A, 0x82])), Next::Done(Response(vec![0x6A, 0x82])));
}

#[test]
fn a_long_apdu_goes_in_begin_continue_and_end_parts() {
    let apdu: Vec<u8> = (0..600u16).map(|i| i as u8).collect();
    let mut exchange = ApduExchange::new(&apdu, 261);
    let (level_1, part_1) = xfr_parts(&exchange.message(1), 1);
    assert_eq!((level_1, part_1.as_slice()), (level::BEGIN, &apdu[..261]));
    assert_eq!(exchange.accept(&data_block(1, 0x10, &[])), Next::Send);
    let (level_2, part_2) = xfr_parts(&exchange.message(2), 2);
    assert_eq!((level_2, part_2.as_slice()), (level::CONTINUE, &apdu[261..522]));
    assert_eq!(exchange.accept(&data_block(2, 0x10, &[])), Next::Send);
    let (level_3, part_3) = xfr_parts(&exchange.message(3), 3);
    assert_eq!((level_3, part_3.as_slice()), (level::END, &apdu[522..]));
    assert_eq!(exchange.accept(&data_block(3, 0x00, &[0x90, 0x00])), Next::Done(Response(vec![0x90, 0x00])));
}

#[test]
fn an_apdu_of_twice_the_limit_has_no_continue_part() {
    let apdu = vec![0x11; 522];
    let mut exchange = ApduExchange::new(&apdu, 261);
    assert_eq!(xfr_parts(&exchange.message(0), 0).0, level::BEGIN);
    assert_eq!(exchange.accept(&data_block(0, 0x10, &[])), Next::Send);
    let (level, part) = xfr_parts(&exchange.message(1), 1);
    assert_eq!((level, part.len()), (level::END, 261));
}

#[test]
fn a_command_part_must_be_answered_by_an_empty_continuation_block() {
    for wrong in [data_block(0, 0x00, &[0x90, 0x00]), data_block(0, 0x10, &[0x01]), data_block(0, 0x01, &[])] {
        let mut exchange = ApduExchange::new(&[0; 300], 261);
        exchange.message(0);
        let chain = wrong.specific;
        assert_eq!(exchange.accept(&wrong), Next::Failed(Fault::UnexpectedChain { chain }));
    }
}

#[test]
fn a_chained_response_is_fetched_with_empty_level_10_blocks() {
    let mut exchange = ApduExchange::new(&[0x00, 0xCB, 0x3F, 0xFF], 261);
    exchange.message(7);
    assert_eq!(exchange.accept(&data_block(7, 0x01, &[1; 261])), Next::Send);
    assert_eq!(xfr_parts(&exchange.message(8), 8), (level::RESPONSE_CONTINUATION, vec![]));
    assert_eq!(exchange.accept(&data_block(8, 0x03, &[2; 261])), Next::Send);
    assert_eq!(xfr_parts(&exchange.message(9), 9), (level::RESPONSE_CONTINUATION, vec![]));
    let mut expected = vec![1; 261];
    expected.extend([2; 261]);
    expected.extend([3, 0x90, 0x00]);
    assert_eq!(exchange.accept(&data_block(9, 0x02, &[3, 0x90, 0x00])), Next::Done(Response(expected)));
}

#[test]
fn a_chained_command_can_have_a_chained_response() {
    let mut exchange = ApduExchange::new(&[0x22; 400], 261);
    exchange.message(0);
    assert_eq!(exchange.accept(&data_block(0, 0x10, &[])), Next::Send);
    assert_eq!(xfr_parts(&exchange.message(1), 1).0, level::END);
    assert_eq!(exchange.accept(&data_block(1, 0x01, &[0xAA; 10])), Next::Send);
    assert_eq!(xfr_parts(&exchange.message(2), 2).0, level::RESPONSE_CONTINUATION);
    let done = exchange.accept(&data_block(2, 0x02, &[0x90, 0x00]));
    let Next::Done(Response(ref response)) = done else { panic!("expected the response, got {done:?}") };
    assert_eq!(response.len(), 12);
}

#[test]
fn chain_parameters_out_of_order_fail_the_exchange() {
    // The first response part cannot be a continuation or an end.
    for chain in [0x02, 0x03, 0x10, 0x04] {
        let mut exchange = ApduExchange::new(&[0, 0, 0, 0], 261);
        exchange.message(0);
        let failed = Next::Failed(Fault::UnexpectedChain { chain });
        assert_eq!(exchange.accept(&data_block(0, chain, &[0x90, 0x00])), failed);
    }
    // A later part cannot begin again or be complete on its own.
    for chain in [0x00, 0x01, 0x10] {
        let mut exchange = ApduExchange::new(&[0, 0, 0, 0], 261);
        exchange.message(0);
        assert_eq!(exchange.accept(&data_block(0, 0x01, &[1])), Next::Send);
        exchange.message(1);
        let failed = Next::Failed(Fault::UnexpectedChain { chain });
        assert_eq!(exchange.accept(&data_block(1, chain, &[0x90, 0x00])), failed);
    }
}

#[test]
fn a_failed_reply_fails_the_exchange_with_the_slot_error() {
    let mut exchange = ApduExchange::new(&[0, 0xA4, 4, 0], 261);
    exchange.message(0);
    let failed = reply(0x80, 0, 0x41, 0xFE, 0, &[]);
    assert_eq!(exchange.accept(&failed), Next::Failed(Fault::Failed { error: 0xFE, icc: IccStatus::Inactive }));
    assert_eq!(Fault::Failed { error: 0xFE, icc: IccStatus::Inactive }.reason(), "the card is not powered");
    assert_eq!(Fault::Failed { error: 0x05, icc: IccStatus::Absent }.reason(), "the reader reports no card");

    let mut exchange = ApduExchange::new(&[0, 0xA4, 4, 0], 261);
    exchange.message(0);
    assert_eq!(exchange.accept(&reply(0x81, 0, 0, 0, 0, &[])), Next::Failed(Fault::UnexpectedType { kind: 0x81 }));
    let mut exchange = ApduExchange::new(&[0, 0xA4, 4, 0], 261);
    exchange.message(0);
    let reserved = reply(0x80, 0, 0xC0, 0, 0, &[]);
    assert_eq!(exchange.accept(&reserved), Next::Failed(Fault::Failed { error: 0, icc: IccStatus::Active }));
}

#[test]
fn a_time_extension_is_not_a_reply_to_the_exchange() {
    let mut exchange = ApduExchange::new(&[0, 0xA2, 0, 1], 261);
    exchange.message(0);
    assert_eq!(exchange.accept(&reply(0x80, 0, 0x80, 0x01, 0, &[])), Next::Failed(Fault::TimeExtension));
}

#[test]
fn an_empty_response_apdu_fails_the_exchange() {
    let mut exchange = ApduExchange::new(&[0, 0xA4, 4, 0], 261);
    exchange.message(0);
    assert_eq!(exchange.accept(&data_block(0, 0x00, &[])), Next::Failed(Fault::EmptyResponse));
}

#[test]
fn a_response_chain_longer_than_an_extended_response_fails_the_exchange() {
    let mut exchange = ApduExchange::new(&[0, 0xCB, 0x3F, 0xFF], 65_544);
    exchange.message(0);
    assert_eq!(exchange.accept(&data_block(0, 0x01, &vec![0; 65_000])), Next::Send);
    exchange.message(1);
    assert_eq!(exchange.accept(&data_block(1, 0x03, &[0; 538])), Next::Send, "65 538 bytes are the most");
    exchange.message(2);
    assert_eq!(exchange.accept(&data_block(2, 0x02, &[0])), Next::Failed(Fault::ResponseTooLong));
}

#[test]
fn an_empty_apdu_is_passed_on_as_an_empty_block() {
    let mut exchange = ApduExchange::new(&[], 261);
    assert_eq!(xfr_parts(&exchange.message(0), 0), (level::BEGIN_AND_END, vec![]));
    assert_eq!(exchange.accept(&data_block(0, 0, &[0x67, 0x00])), Next::Done(Response(vec![0x67, 0x00])));
}

#[test]
fn fault_messages_name_the_detail() {
    assert!(Fault::UnexpectedType { kind: 0x81 }.to_string().contains("0x81"));
    assert!(Fault::Failed { error: 0xE0, icc: IccStatus::Active }.to_string().contains("0xe0"));
    assert!(Fault::UnexpectedChain { chain: 0x03 }.to_string().contains("0x03"));
    assert_eq!(Fault::EmptyResponse.to_string(), "the response APDU is empty");
}
