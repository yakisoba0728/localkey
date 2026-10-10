use lk_device::BusEvent;
use lk_run::HostInput;

use super::*;
use crate::descriptor::Layout;
use crate::ffs::{CtrlRequest, Event};
use crate::test_support::{ALL, FIDO_CCID, identity};

/// Interfaces of the three-interface layout.
const OTP: u16 = 0;
const FIDO: u16 = 1;
const CCID: u16 = 2;

fn all() -> Control {
    Control::new(&Layout::from_identity(&identity(ALL, None)).expect("layout"))
}

fn fido_ccid() -> Control {
    Control::new(&Layout::from_identity(&identity(FIDO_CCID, None)).expect("layout"))
}

fn req(request_type: u8, request: u8, value: u16, index: u16, length: u16) -> CtrlRequest {
    CtrlRequest { request_type, request, value, index, length }
}

const HID_DESCRIPTOR: [u8; 9] = [9, 0x21, 0x10, 0x01, 0, 1, 0x22, 34, 0];

#[test]
fn get_descriptor_report_on_the_fido_interface_returns_the_fido_report_descriptor() {
    let expected = Action::Reply(lk_device::FIDO_REPORT_DESCRIPTOR.to_vec());
    assert_eq!(all().setup(&req(0x81, 0x06, 0x2200, FIDO, 0x22)), expected);
    assert_eq!(fido_ccid().setup(&req(0x81, 0x06, 0x2200, 0, 0xFF)), expected);
}

#[test]
fn get_descriptor_report_on_the_otp_interface_returns_the_keyboard_report_descriptor() {
    assert_eq!(
        all().setup(&req(0x81, 0x06, 0x2200, OTP, 0x4D)),
        Action::Reply(lk_device::OTP_REPORT_DESCRIPTOR.to_vec())
    );
}

#[test]
fn get_descriptor_hid_returns_the_nine_byte_hid_descriptor_of_the_interface() {
    assert_eq!(fido_ccid().setup(&req(0x81, 0x06, 0x2100, 0, 9)), Action::Reply(HID_DESCRIPTOR.to_vec()));
    let otp = all().setup(&req(0x81, 0x06, 0x2100, OTP, 64));
    assert_eq!(otp, Action::Reply(vec![9, 0x21, 0x10, 0x01, 0, 1, 0x22, 77, 0]));
}

#[test]
fn descriptor_replies_are_cut_to_the_requested_length() {
    assert_eq!(
        all().setup(&req(0x81, 0x06, 0x2200, FIDO, 8)),
        Action::Reply(lk_device::FIDO_REPORT_DESCRIPTOR[..8].to_vec())
    );
    assert_eq!(all().setup(&req(0x81, 0x06, 0x2100, FIDO, 0)), Action::Reply(Vec::new()));
}

#[test]
fn get_descriptor_with_another_index_or_type_or_on_the_ccid_interface_is_stalled() {
    let mut control = all();
    for request in [
        req(0x81, 0x06, 0x2201, FIDO, 64),
        req(0x81, 0x06, 0x2101, FIDO, 64),
        req(0x81, 0x06, 0x2300, FIDO, 64),
        req(0x81, 0x06, 0x0200, FIDO, 64),
        req(0x81, 0x06, 0x2200, CCID, 64),
        req(0x81, 0x06, 0x2100, CCID, 64),
        req(0xA1, 0x06, 0x2200, FIDO, 64),
    ] {
        assert_eq!(control.setup(&request), Action::Stall, "{request:?}");
    }
}

#[test]
fn idle_rates_default_per_interface_and_set_idle_is_kept_per_interface() {
    let mut control = all();
    assert_eq!(control.setup(&req(0xA1, 0x02, 0, OTP, 1)), Action::Reply(vec![125]));
    assert_eq!(control.setup(&req(0xA1, 0x02, 0, FIDO, 1)), Action::Reply(vec![0]));
    assert_eq!(control.setup(&req(0x21, 0x0A, 0x0000, OTP, 0)), Action::Ack(None));
    assert_eq!(control.setup(&req(0x21, 0x0A, 0x2A00, FIDO, 0)), Action::Ack(None));
    assert_eq!(control.setup(&req(0xA1, 0x02, 0, OTP, 1)), Action::Reply(vec![0]));
    assert_eq!(control.setup(&req(0xA1, 0x02, 0, FIDO, 4)), Action::Reply(vec![0x2A]));
    assert_eq!(control.hid_state(1), Some((0x2A, 1)));
}

#[test]
fn set_idle_with_a_report_id_or_a_data_stage_and_get_idle_with_a_report_id_are_stalled() {
    let mut control = all();
    assert_eq!(control.setup(&req(0x21, 0x0A, 0x2A01, FIDO, 0)), Action::Stall);
    assert_eq!(control.setup(&req(0x21, 0x0A, 0x2A00, FIDO, 1)), Action::Stall);
    assert_eq!(control.setup(&req(0xA1, 0x02, 0x0001, FIDO, 1)), Action::Stall);
    assert_eq!(control.setup(&req(0xA1, 0x02, 0, FIDO, 0)), Action::Stall);
    assert_eq!(control.hid_state(1), Some((0, 1)));
}

#[test]
fn protocols_default_to_report_and_set_protocol_is_kept_per_interface() {
    let mut control = all();
    assert_eq!(control.setup(&req(0xA1, 0x03, 0, OTP, 1)), Action::Reply(vec![1]));
    assert_eq!(control.setup(&req(0x21, 0x0B, 0, OTP, 0)), Action::Ack(None));
    assert_eq!(control.setup(&req(0xA1, 0x03, 0, OTP, 1)), Action::Reply(vec![0]));
    assert_eq!(control.setup(&req(0xA1, 0x03, 0, FIDO, 1)), Action::Reply(vec![1]));
    assert_eq!(control.setup(&req(0x21, 0x0B, 2, OTP, 0)), Action::Stall);
    assert_eq!(control.setup(&req(0x21, 0x0B, 1, OTP, 1)), Action::Stall);
    assert_eq!(control.setup(&req(0xA1, 0x03, 1, OTP, 1)), Action::Stall);
    assert_eq!(control.setup(&req(0xA1, 0x03, 0, OTP, 0)), Action::Stall);
}

#[test]
fn a_reset_returns_idle_and_protocol_to_their_defaults() {
    let mut control = all();
    let _ = control.setup(&req(0x21, 0x0B, 0, OTP, 0));
    let _ = control.setup(&req(0x21, 0x0A, 0x0100, OTP, 0));
    assert_eq!(control.hid_state(0), Some((1, 0)));
    control.reset();
    assert_eq!(control.hid_state(0), Some((125, 1)));
    assert_eq!(control.hid_state(2), Some((0, 1)));
    assert_eq!(control.hid_state(3), None);
}

#[test]
fn otp_get_report_feature_asks_the_runner_for_the_feature_report() {
    let mut control = all();
    assert_eq!(control.setup(&req(0xA1, 0x01, 0x0300, OTP, 8)), Action::OtpGetFeature { length: 8 });
    assert_eq!(control.setup(&req(0xA1, 0x01, 0x0300, OTP, 255)), Action::OtpGetFeature { length: 255 });
}

#[test]
fn other_get_reports_are_stalled() {
    let mut control = all();
    for request in [
        req(0xA1, 0x01, 0x0301, OTP, 8),
        req(0xA1, 0x01, 0x0100, OTP, 8),
        req(0xA1, 0x01, 0x0200, OTP, 8),
        req(0xA1, 0x01, 0x0300, OTP, 0),
        req(0xA1, 0x01, 0x0300, FIDO, 8),
        req(0xA1, 0x01, 0x0100, FIDO, 64),
        req(0xA1, 0x01, 0x0300, CCID, 8),
    ] {
        assert_eq!(control.setup(&request), Action::Stall, "{request:?}");
    }
}

#[test]
fn otp_set_report_feature_of_eight_bytes_is_read_as_the_feature_report() {
    let mut control = all();
    assert_eq!(
        control.setup(&req(0x21, 0x09, 0x0300, OTP, 8)),
        Action::Receive { length: 8, then: Received::OtpSetFeature }
    );
    for request in [req(0x21, 0x09, 0x0300, OTP, 9), req(0x21, 0x09, 0x0300, OTP, 7), req(0x21, 0x09, 0x0301, OTP, 8)] {
        assert_eq!(control.setup(&request), Action::Stall, "{request:?}");
    }
}

#[test]
fn keyboard_set_report_output_is_read_and_ignored() {
    let mut control = all();
    assert_eq!(control.setup(&req(0x21, 0x09, 0x0200, OTP, 1)), Action::Receive { length: 1, then: Received::Ignore });
    assert_eq!(
        control.setup(&req(0x21, 0x09, 0x0200, OTP, 64)),
        Action::Receive { length: 64, then: Received::Ignore }
    );
    assert_eq!(control.setup(&req(0x21, 0x09, 0x0200, OTP, 0)), Action::Stall);
    assert_eq!(control.setup(&req(0x21, 0x09, 0x0200, OTP, 65)), Action::Stall);
    assert_eq!(control.setup(&req(0x21, 0x09, 0x0100, OTP, 8)), Action::Stall);
}

#[test]
fn fido_set_report_output_of_sixty_four_bytes_is_read_as_a_fido_report() {
    let mut control = all();
    assert_eq!(
        control.setup(&req(0x21, 0x09, 0x0200, FIDO, 64)),
        Action::Receive { length: 64, then: Received::FidoReport }
    );
    for request in [
        req(0x21, 0x09, 0x0200, FIDO, 65),
        req(0x21, 0x09, 0x0200, FIDO, 63),
        req(0x21, 0x09, 0x0201, FIDO, 64),
        req(0x21, 0x09, 0x0300, FIDO, 8),
        req(0x21, 0x09, 0x0200, CCID, 64),
    ] {
        assert_eq!(control.setup(&request), Action::Stall, "{request:?}");
    }
}

#[test]
fn ccid_abort_becomes_a_control_abort_with_slot_and_sequence_from_w_value() {
    let mut control = all();
    assert_eq!(
        control.setup(&req(0x21, 0x01, 0x0700, CCID, 0)),
        Action::Ack(Some(HostInput::CcidControlAbort { slot: 0, seq: 7 }))
    );
    assert_eq!(
        fido_ccid().setup(&req(0x21, 0x01, 0xFE01, 1, 0)),
        Action::Ack(Some(HostInput::CcidControlAbort { slot: 1, seq: 0xFE }))
    );
}

#[test]
fn ccid_clock_frequencies_data_rates_and_malformed_aborts_are_stalled() {
    let mut control = all();
    for request in [
        req(0xA1, 0x02, 0, CCID, 4),
        req(0xA1, 0x03, 0, CCID, 8),
        req(0x21, 0x01, 0x0700, CCID, 1),
        req(0xA1, 0x01, 0x0700, CCID, 0),
        req(0x21, 0x0A, 0, CCID, 0),
        req(0x21, 0x01, 0x0700, FIDO, 0),
        req(0x21, 0x01, 0x0700, OTP, 0),
    ] {
        assert_eq!(control.setup(&request), Action::Stall, "{request:?}");
    }
}

#[test]
fn requests_for_interface_numbers_outside_the_layout_are_stalled() {
    let mut control = fido_ccid();
    // FIDO+CCID numbers FIDO 0 and CCID 1: 2 does not exist here, 0x0100 has a high byte.
    for request in [
        req(0x81, 0x06, 0x2200, 2, 64),
        req(0x21, 0x01, 0x0700, 2, 0),
        req(0x81, 0x06, 0x2200, 0x0100, 64),
        req(0x21, 0x0A, 0, 0xFFFF, 0),
    ] {
        assert_eq!(control.setup(&request), Action::Stall, "{request:?}");
    }
    // In this layout interface 0 is FIDO, so the OTP feature report is not there.
    assert_eq!(control.setup(&req(0xA1, 0x01, 0x0300, 0, 8)), Action::Stall);
}

#[test]
fn device_endpoint_vendor_and_unnamed_standard_requests_are_stalled() {
    let mut control = all();
    for request in [
        req(0x80, 0x06, 0x0100, 0, 18),
        req(0x82, 0x00, 0, 0x81, 2),
        req(0x02, 0x01, 0, 0x81, 0),
        req(0xC1, 0x01, 0, FIDO, 8),
        req(0x41, 0x01, 0, FIDO, 0),
        req(0x81, 0x00, 0, FIDO, 2),
        req(0x01, 0x0B, 0, FIDO, 0),
        req(0xA3, 0x01, 0x0300, OTP, 8),
    ] {
        assert_eq!(control.setup(&request), Action::Stall, "{request:?}");
    }
}

#[test]
fn received_data_becomes_an_input_only_at_the_report_size() {
    assert_eq!(Received::OtpSetFeature.input(&[1; 8]), Some(HostInput::OtpSetFeature([1; 8])));
    assert_eq!(Received::OtpSetFeature.input(&[1; 7]), None);
    assert_eq!(Received::FidoReport.input(&[2; 64]), Some(HostInput::FidoReport([2; 64])));
    assert_eq!(Received::FidoReport.input(&[2; 65]), None);
    assert_eq!(Received::Ignore.input(&[3]), None);
}

#[test]
fn action_debug_shows_sizes_not_bytes() {
    let debug = format!("{:?}", Action::Reply(vec![0xAB; 34]));
    assert_eq!(debug, "Reply(34 bytes)");
    let debug = format!("{:?}", Action::Ack(Some(HostInput::OtpSetFeature([0x5A; 8]))));
    assert!(!debug.contains("90"), "{debug}");
}

#[test]
fn the_first_enable_is_a_power_cycle_and_later_enables_after_a_disable_are_resets() {
    let mut bus = BusTracker::default();
    assert_eq!(bus.event(&Event::Bind), None);
    assert_eq!(bus.event(&Event::Enable), Some(BusEvent::PowerCycle));
    assert!(bus.enabled());
    assert_eq!(bus.event(&Event::Disable), None);
    assert!(!bus.enabled());
    assert_eq!(bus.event(&Event::Enable), Some(BusEvent::Reset));
}

#[test]
fn enables_while_enabled_are_no_bus_events() {
    let mut bus = BusTracker::default();
    assert_eq!(bus.event(&Event::Enable), Some(BusEvent::PowerCycle));
    // One SET_CONFIGURATION of a three-interface function: three ENABLEs.
    assert_eq!(bus.event(&Event::Enable), None);
    assert_eq!(bus.event(&Event::Enable), None);
    assert_eq!(bus.event(&Event::Unbind), None);
    assert_eq!(bus.event(&Event::Enable), Some(BusEvent::Reset));
}

#[test]
fn suspend_is_passed_once_and_resume_always() {
    let mut bus = BusTracker::default();
    let _ = bus.event(&Event::Enable);
    assert_eq!(bus.event(&Event::Suspend), Some(BusEvent::Suspend));
    assert_eq!(bus.event(&Event::Suspend), None);
    assert_eq!(bus.event(&Event::Resume), Some(BusEvent::Resume));
    // A RESUME whose SUSPEND f_fs discarded unread.
    assert_eq!(bus.event(&Event::Resume), Some(BusEvent::Resume));
    assert_eq!(bus.event(&Event::Suspend), Some(BusEvent::Suspend));
    // A bus reset while suspended ends the suspension.
    assert_eq!(bus.event(&Event::Disable), None);
    assert_eq!(bus.event(&Event::Enable), Some(BusEvent::Reset));
    assert_eq!(bus.event(&Event::Suspend), Some(BusEvent::Suspend));
}

#[test]
fn setup_and_unknown_events_are_no_bus_events() {
    let mut bus = BusTracker::default();
    let request = req(0x81, 0x06, 0x2200, 0, 64);
    assert_eq!(bus.event(&Event::Setup(request)), None);
    assert_eq!(bus.event(&Event::Unknown(9)), None);
    assert!(!bus.enabled());
}
