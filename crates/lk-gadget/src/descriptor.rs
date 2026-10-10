//! The engine's configuration descriptor, parsed, and the gadget layout derived from it
//! (`docs/PROGRAM.md` "lk-gadget", FunctionFS: "the interface, class and endpoint
//! descriptors are the engine's configuration descriptor minus its 9-byte configuration
//! header, in the same order").
//!
//! [`ConfigDescriptor::parse`] splits `UsbIdentity::configuration_descriptor()` into its
//! header and the interface, class-specific and endpoint descriptors, and re-encodes them
//! byte for byte. [`Layout::from_identity`] names each interface (OTP keyboard, FIDO HID,
//! CCID) and each endpoint (its role and its FunctionFS file `ep<N>`), which is all the
//! transport needs to route control requests and endpoint data.
//!
//! Field layouts are those of `struct usb_config_descriptor`, `usb_interface_descriptor`
//! and `usb_endpoint_descriptor` in `include/uapi/linux/usb/ch9.h` (USB 2.0 §9.6.3,
//! §9.6.5, §9.6.6).

use std::fmt;

use lk_core::UsbInterfaces;
use lk_device::UsbIdentity;

/// `USB_DT_CONFIG_SIZE` (`include/uapi/linux/usb/ch9.h`): the configuration header.
pub const CONFIG_HEADER_LEN: usize = 9;
/// `USB_DT_INTERFACE_SIZE` (`ch9.h`).
const INTERFACE_LEN: usize = 9;
/// `USB_DT_ENDPOINT_SIZE` (`ch9.h`); FunctionFS also accepts the 9-byte audio form, which
/// the engine never uses.
const ENDPOINT_LEN: usize = 7;
/// `USB_DT_DEVICE`, `USB_DT_CONFIG`, `USB_DT_STRING`, `USB_DT_INTERFACE`,
/// `USB_DT_ENDPOINT` (`ch9.h`).
const DT_DEVICE: u8 = 0x01;
const DT_CONFIG: u8 = 0x02;
const DT_STRING: u8 = 0x03;
const DT_INTERFACE: u8 = 0x04;
const DT_ENDPOINT: u8 = 0x05;
/// `USB_DIR_IN` / `USB_ENDPOINT_DIR_MASK` (`ch9.h`).
const DIR_IN: u8 = 0x80;
/// `USB_ENDPOINT_XFERTYPE_MASK`, `USB_ENDPOINT_XFER_BULK`, `USB_ENDPOINT_XFER_INT`
/// (`ch9.h`).
const XFERTYPE_MASK: u8 = 0x03;
const XFER_BULK: u8 = 0x02;
const XFER_INT: u8 = 0x03;
/// `USB_CLASS_HID` and `USB_CLASS_CSCID` (`ch9.h`); `USB_INTERFACE_SUBCLASS_BOOT` and
/// `USB_INTERFACE_PROTOCOL_KEYBOARD` (`include/uapi/linux/hid.h`).
const CLASS_HID: u8 = 0x03;
const CLASS_CCID: u8 = 0x0B;
const SUBCLASS_BOOT: u8 = 0x01;
const PROTOCOL_KEYBOARD: u8 = 0x01;
/// Offset of `dwMaxCCIDMessageLength` in the CCID class descriptor (USB CCID Rev 1.1
/// §5.1, Table 5.1-1: bytes 44..48).
const CCID_MAX_MESSAGE_OFFSET: usize = 44;

/// The configuration header (`struct usb_config_descriptor`, `ch9.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigHeader {
    /// `wTotalLength`.
    pub total_length: u16,
    /// `bNumInterfaces`.
    pub num_interfaces: u8,
    /// `bConfigurationValue`.
    pub configuration_value: u8,
    /// `iConfiguration`.
    pub configuration_string: u8,
    /// `bmAttributes`.
    pub attributes: u8,
    /// `bMaxPower`, in 2 mA units below SuperSpeed (USB 2.0 §9.6.3).
    pub max_power: u8,
}

/// An interface descriptor (`struct usb_interface_descriptor`, `ch9.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceDescriptor {
    pub number: u8,
    pub alternate_setting: u8,
    pub num_endpoints: u8,
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
    /// `iInterface`; the engine's interfaces have none (0).
    pub string: u8,
}

/// An endpoint descriptor (`struct usb_endpoint_descriptor`, `ch9.h`, 7-byte form).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointDescriptor {
    /// `bEndpointAddress`: bit 7 is the direction (`USB_DIR_IN`).
    pub address: u8,
    /// `bmAttributes`: bits 0..2 are the transfer type.
    pub attributes: u8,
    pub max_packet_size: u16,
    pub interval: u8,
}

impl EndpointDescriptor {
    /// Whether this is an IN (device to host) endpoint.
    pub fn is_in(&self) -> bool {
        self.address & DIR_IN != 0
    }

    /// The transfer type (`USB_ENDPOINT_XFER_*`).
    pub fn transfer_type(&self) -> u8 {
        self.attributes & XFERTYPE_MASK
    }
}

/// One descriptor after the configuration header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Descriptor {
    Interface(InterfaceDescriptor),
    Endpoint(EndpointDescriptor),
    /// A class-specific descriptor (HID `0x21`, CCID `0x21`), starting at `bLength`.
    Class(Vec<u8>),
}

impl Descriptor {
    /// Append the descriptor's bytes, exactly as parsed.
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Descriptor::Interface(d) => out.extend_from_slice(&[
                INTERFACE_LEN as u8,
                DT_INTERFACE,
                d.number,
                d.alternate_setting,
                d.num_endpoints,
                d.class,
                d.subclass,
                d.protocol,
                d.string,
            ]),
            Descriptor::Endpoint(d) => {
                let [size_lo, size_hi] = d.max_packet_size.to_le_bytes();
                out.extend_from_slice(&[
                    ENDPOINT_LEN as u8,
                    DT_ENDPOINT,
                    d.address,
                    d.attributes,
                    size_lo,
                    size_hi,
                    d.interval,
                ]);
            }
            Descriptor::Class(bytes) => out.extend_from_slice(bytes),
        }
    }
}

/// Why a configuration descriptor (or the identity around it) cannot be presented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescriptorError {
    /// Shorter than the 9-byte header, or not a configuration header.
    BadHeader,
    /// `wTotalLength` differs from the number of bytes.
    TotalLength { declared: u16, actual: usize },
    /// The descriptor at this offset is truncated, has a `bLength` below 2 or the wrong
    /// length for its type.
    Malformed { offset: usize },
    /// A device, configuration or string descriptor inside the configuration (FunctionFS
    /// refuses them: `ffs_do_single_desc` in `drivers/usb/gadget/function/f_fs.c`).
    Reserved { offset: usize, descriptor_type: u8 },
    /// A class or endpoint descriptor before the first interface descriptor.
    Orphan { offset: usize },
    /// An interface declares a different number of endpoints than follow it.
    EndpointCount { interface: u8 },
    /// `bNumInterfaces` differs from the interfaces present.
    InterfaceCount { declared: u8, actual: usize },
    /// An interface that is neither the OTP keyboard, FIDO HID nor CCID, or one of them
    /// twice.
    UnknownInterface { number: u8 },
    /// An endpoint whose direction or type does not fit its interface, or a missing one.
    UnexpectedEndpoint { address: u8 },
    /// A function lacks a required endpoint.
    MissingEndpoint { function: Function },
    /// The descriptor's interfaces differ from `UsbIdentity::interfaces`, or there are
    /// none.
    InterfaceSet,
    /// The CCID class descriptor is too short to hold `dwMaxCCIDMessageLength`, or names 0.
    CcidClassDescriptor,
    /// A HID interface lacks its HID descriptor, or the descriptor's report entry (type
    /// `22`, `wDescriptorLength`) does not match the report descriptor the identity
    /// supplies: the host sizes GET_DESCRIPTOR(report) by that length (USB HID 1.11
    /// §6.2.1).
    ReportLength { interface: u8 },
}

impl fmt::Display for DescriptorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DescriptorError::BadHeader => f.write_str("not a configuration descriptor"),
            DescriptorError::TotalLength { declared, actual } => {
                write!(f, "wTotalLength {declared} but {actual} bytes")
            }
            DescriptorError::Malformed { offset } => write!(f, "malformed descriptor at offset {offset}"),
            DescriptorError::Reserved { offset, descriptor_type } => {
                write!(f, "descriptor type 0x{descriptor_type:02x} at offset {offset} cannot be part of a function")
            }
            DescriptorError::Orphan { offset } => write!(f, "descriptor at offset {offset} precedes every interface"),
            DescriptorError::EndpointCount { interface } => {
                write!(f, "interface {interface} declares a different number of endpoints")
            }
            DescriptorError::InterfaceCount { declared, actual } => {
                write!(f, "bNumInterfaces {declared} but {actual} interfaces")
            }
            DescriptorError::UnknownInterface { number } => write!(f, "interface {number} is not OTP, FIDO or CCID"),
            DescriptorError::UnexpectedEndpoint { address } => {
                write!(f, "endpoint 0x{address:02x} does not fit its interface")
            }
            DescriptorError::MissingEndpoint { function } => write!(f, "{function:?} interface lacks an endpoint"),
            DescriptorError::InterfaceSet => f.write_str("descriptor interfaces differ from the identity's"),
            DescriptorError::CcidClassDescriptor => f.write_str("CCID class descriptor has no dwMaxCCIDMessageLength"),
            DescriptorError::ReportLength { interface } => {
                write!(f, "interface {interface}: HID descriptor and report descriptor length disagree")
            }
        }
    }
}

impl std::error::Error for DescriptorError {}

/// A parsed configuration descriptor: the header and the descriptors after it, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigDescriptor {
    pub header: ConfigHeader,
    pub descriptors: Vec<Descriptor>,
}

impl ConfigDescriptor {
    /// Parse a whole configuration descriptor as GET_DESCRIPTOR(CONFIGURATION) returns it.
    ///
    /// Checks the header (`bLength` 9, type `02`, `wTotalLength`), every `bLength`
    /// (at least 2, inside the buffer; 9 for an interface, 7 for an endpoint), that no
    /// device, configuration or string descriptor appears (FunctionFS refuses those), that
    /// every class and endpoint descriptor follows an interface, that each interface's
    /// `bNumEndpoints` matches, and `bNumInterfaces`.
    pub fn parse(bytes: &[u8]) -> Result<ConfigDescriptor, DescriptorError> {
        let head: &[u8; CONFIG_HEADER_LEN] =
            bytes.get(..CONFIG_HEADER_LEN).and_then(|head| head.try_into().ok()).ok_or(DescriptorError::BadHeader)?;
        if usize::from(head[0]) != CONFIG_HEADER_LEN || head[1] != DT_CONFIG {
            return Err(DescriptorError::BadHeader);
        }
        let header = ConfigHeader {
            total_length: u16::from_le_bytes([head[2], head[3]]),
            num_interfaces: head[4],
            configuration_value: head[5],
            configuration_string: head[6],
            attributes: head[7],
            max_power: head[8],
        };
        if usize::from(header.total_length) != bytes.len() {
            return Err(DescriptorError::TotalLength { declared: header.total_length, actual: bytes.len() });
        }
        let mut descriptors = Vec::new();
        let mut offset = CONFIG_HEADER_LEN;
        // The interface being walked and the endpoints seen after it.
        let mut current: Option<(InterfaceDescriptor, u8)> = None;
        let mut interfaces = 0usize;
        while offset < bytes.len() {
            let length = usize::from(bytes[offset]);
            let raw = bytes
                .get(offset..offset + length.max(2))
                .filter(|_| length >= 2)
                .ok_or(DescriptorError::Malformed { offset })?;
            let descriptor_type = raw[1];
            let descriptor = match descriptor_type {
                DT_DEVICE | DT_CONFIG | DT_STRING => {
                    return Err(DescriptorError::Reserved { offset, descriptor_type });
                }
                DT_INTERFACE => {
                    if length != INTERFACE_LEN {
                        return Err(DescriptorError::Malformed { offset });
                    }
                    close_interface(current.take())?;
                    let interface = InterfaceDescriptor {
                        number: raw[2],
                        alternate_setting: raw[3],
                        num_endpoints: raw[4],
                        class: raw[5],
                        subclass: raw[6],
                        protocol: raw[7],
                        string: raw[8],
                    };
                    if interface.alternate_setting == 0 {
                        interfaces += 1;
                    }
                    current = Some((interface, 0));
                    Descriptor::Interface(interface)
                }
                DT_ENDPOINT => {
                    if length != ENDPOINT_LEN {
                        return Err(DescriptorError::Malformed { offset });
                    }
                    let Some((_, endpoints)) = current.as_mut() else {
                        return Err(DescriptorError::Orphan { offset });
                    };
                    *endpoints = endpoints.saturating_add(1);
                    Descriptor::Endpoint(EndpointDescriptor {
                        address: raw[2],
                        attributes: raw[3],
                        max_packet_size: u16::from_le_bytes([raw[4], raw[5]]),
                        interval: raw[6],
                    })
                }
                _ => {
                    if current.is_none() {
                        return Err(DescriptorError::Orphan { offset });
                    }
                    Descriptor::Class(raw.to_vec())
                }
            };
            descriptors.push(descriptor);
            offset += length;
        }
        close_interface(current)?;
        if usize::from(header.num_interfaces) != interfaces {
            return Err(DescriptorError::InterfaceCount { declared: header.num_interfaces, actual: interfaces });
        }
        Ok(ConfigDescriptor { header, descriptors })
    }

    /// The descriptors after the header, concatenated: the engine's configuration
    /// descriptor minus its first 9 bytes.
    pub fn body(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for descriptor in &self.descriptors {
            descriptor.encode(&mut out);
        }
        out
    }

    /// The whole descriptor again (header and body).
    pub fn to_bytes(&self) -> Vec<u8> {
        let h = &self.header;
        let [total_lo, total_hi] = h.total_length.to_le_bytes();
        let mut out = vec![
            CONFIG_HEADER_LEN as u8,
            DT_CONFIG,
            total_lo,
            total_hi,
            h.num_interfaces,
            h.configuration_value,
            h.configuration_string,
            h.attributes,
            h.max_power,
        ];
        out.extend_from_slice(&self.body());
        out
    }
}

/// End the walk of one interface: its endpoint count must match `bNumEndpoints`.
fn close_interface(current: Option<(InterfaceDescriptor, u8)>) -> Result<(), DescriptorError> {
    match current {
        Some((interface, seen)) if seen != interface.num_endpoints => {
            Err(DescriptorError::EndpointCount { interface: interface.number })
        }
        _ => Ok(()),
    }
}

/// The `wDescriptorLength` of the report descriptor named by a HID descriptor (USB HID
/// 1.11 §6.2.1: `bLength`, `bDescriptorType` `21`, `bcdHID`, `bCountryCode`,
/// `bNumDescriptors`, then `bDescriptorType` `22` and `wDescriptorLength` little endian).
fn hid_report_length(hid: &[u8]) -> Option<usize> {
    match hid {
        [_, 0x21, _, _, _, count, 0x22, lo, hi, ..] if *count >= 1 => Some(usize::from(u16::from_le_bytes([*lo, *hi]))),
        _ => None,
    }
}

/// The three functions of the composite device (`lk_device::UsbIdentity`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Function {
    /// The OTP HID interface: a boot keyboard with the OTP feature report.
    Otp,
    /// The FIDO (CTAPHID) HID interface.
    Fido,
    /// The CCID smart-card interface.
    Ccid,
}

/// What an endpoint carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// OTP keyboard interrupt IN (8-byte boot reports).
    OtpIn,
    /// FIDO interrupt OUT (64-byte CTAPHID reports from the host).
    FidoOut,
    /// FIDO interrupt IN (64-byte CTAPHID reports to the host).
    FidoIn,
    /// CCID bulk OUT (`PC_to_RDR_*` messages).
    CcidBulkOut,
    /// CCID bulk IN (`RDR_to_PC_*` messages).
    CcidBulkIn,
    /// CCID interrupt IN (`RDR_to_PC_NotifySlotChange`).
    CcidInterruptIn,
}

impl Role {
    /// Whether the endpoint sends to the host.
    pub fn is_in(self) -> bool {
        !matches!(self, Role::FidoOut | Role::CcidBulkOut)
    }

    /// A short name for logs and thread names.
    pub fn name(self) -> &'static str {
        match self {
            Role::OtpIn => "otp-in",
            Role::FidoOut => "fido-out",
            Role::FidoIn => "fido-in",
            Role::CcidBulkOut => "ccid-out",
            Role::CcidBulkIn => "ccid-in",
            Role::CcidInterruptIn => "ccid-int",
        }
    }

    /// The role of an endpoint of `function` with this direction and transfer type.
    fn of(function: Function, endpoint: &EndpointDescriptor) -> Option<Role> {
        match (function, endpoint.is_in(), endpoint.transfer_type()) {
            (Function::Otp, true, XFER_INT) => Some(Role::OtpIn),
            (Function::Fido, false, XFER_INT) => Some(Role::FidoOut),
            (Function::Fido, true, XFER_INT) => Some(Role::FidoIn),
            (Function::Ccid, false, XFER_BULK) => Some(Role::CcidBulkOut),
            (Function::Ccid, true, XFER_BULK) => Some(Role::CcidBulkIn),
            (Function::Ccid, true, XFER_INT) => Some(Role::CcidInterruptIn),
            _ => None,
        }
    }
}

/// One interface of the layout.
#[derive(Clone, PartialEq, Eq)]
pub struct InterfaceLayout {
    /// `bInterfaceNumber` as in the engine's descriptor. FunctionFS hands it to the
    /// composite framework, which allocates interface numbers in order of appearance
    /// (`__ffs_func_bind_do_nums` → `usb_interface_id`), so with this one function in the
    /// configuration the host sees the same numbers; SETUP events carry them in `wIndex`
    /// (`ffs_func_setup` rewrites `wIndex` back to the function's own numbering).
    pub number: u8,
    pub function: Function,
    /// The first class-specific descriptor after the interface descriptor: the 9-byte
    /// HID descriptor (USB HID 1.11 §6.2.1) or the 54-byte CCID descriptor.
    pub class_descriptor: Vec<u8>,
    /// The HID report descriptor (empty for CCID).
    pub report_descriptor: Vec<u8>,
}

impl fmt::Debug for InterfaceLayout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InterfaceLayout")
            .field("number", &self.number)
            .field("function", &self.function)
            .field("class_descriptor", &format_args!("{} bytes", self.class_descriptor.len()))
            .field("report_descriptor", &format_args!("{} bytes", self.report_descriptor.len()))
            .finish()
    }
}

/// One endpoint of the layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointLayout {
    /// The FunctionFS file `ep<file_index>`: endpoints are numbered from 1 in descriptor
    /// order (`ffs_epfiles_create`, `drivers/usb/gadget/function/f_fs.c`, without
    /// `FUNCTIONFS_VIRTUAL_ADDR`).
    pub file_index: usize,
    /// `bEndpointAddress` as in the engine's descriptor. The UDC may assign another
    /// number (`usb_ep_autoconfig`, see the crate docs).
    pub address: u8,
    pub max_packet_size: u16,
    pub role: Role,
}

/// The interfaces and endpoints of one enumeration, derived from the engine's
/// descriptors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub config: ConfigDescriptor,
    /// In descriptor order (OTP, FIDO, CCID; enabled ones only).
    pub interfaces: Vec<InterfaceLayout>,
    /// In descriptor order.
    pub endpoints: Vec<EndpointLayout>,
    /// `dwMaxCCIDMessageLength` of the CCID class descriptor (0 without CCID).
    pub ccid_max_message_length: usize,
}

impl Layout {
    /// The layout of `identity.configuration_descriptor()`.
    ///
    /// Interfaces are recognised by class: HID boot keyboard → OTP, other HID → FIDO,
    /// smart card → CCID; each at most once, and the set must equal
    /// `identity.interfaces`. Endpoints are recognised by interface, direction and
    /// transfer type; FIDO needs interrupt OUT and IN, OTP interrupt IN, CCID bulk OUT and
    /// IN (its interrupt IN is optional, CCID Rev 1.1 §3.2).
    pub fn from_identity(identity: &UsbIdentity) -> Result<Layout, DescriptorError> {
        Layout::from_descriptor(&identity.configuration_descriptor(), identity)
    }

    /// [`Layout::from_identity`] for a given configuration descriptor (the identity
    /// supplies the report descriptors and the expected interface set).
    pub fn from_descriptor(bytes: &[u8], identity: &UsbIdentity) -> Result<Layout, DescriptorError> {
        let config = ConfigDescriptor::parse(bytes)?;
        let mut interfaces: Vec<InterfaceLayout> = Vec::new();
        let mut endpoints: Vec<EndpointLayout> = Vec::new();
        let mut function = None;
        for descriptor in &config.descriptors {
            match descriptor {
                Descriptor::Interface(d) => {
                    let kind = match (d.class, d.subclass, d.protocol) {
                        (CLASS_HID, SUBCLASS_BOOT, PROTOCOL_KEYBOARD) => Function::Otp,
                        (CLASS_HID, _, _) => Function::Fido,
                        (CLASS_CCID, _, _) => Function::Ccid,
                        _ => return Err(DescriptorError::UnknownInterface { number: d.number }),
                    };
                    if d.alternate_setting != 0 || interfaces.iter().any(|i| i.function == kind) {
                        return Err(DescriptorError::UnknownInterface { number: d.number });
                    }
                    let report_descriptor = match kind {
                        Function::Otp => identity.otp_report_descriptor.clone(),
                        Function::Fido => identity.fido_report_descriptor.clone(),
                        Function::Ccid => Vec::new(),
                    };
                    interfaces.push(InterfaceLayout {
                        number: d.number,
                        function: kind,
                        class_descriptor: Vec::new(),
                        report_descriptor,
                    });
                    function = Some(kind);
                }
                Descriptor::Class(bytes) => {
                    if let Some(last) = interfaces.last_mut()
                        && last.class_descriptor.is_empty()
                    {
                        last.class_descriptor = bytes.clone();
                    }
                }
                Descriptor::Endpoint(d) => {
                    let role = function
                        .and_then(|kind| Role::of(kind, d))
                        .ok_or(DescriptorError::UnexpectedEndpoint { address: d.address })?;
                    if endpoints.iter().any(|e| e.role == role) {
                        return Err(DescriptorError::UnexpectedEndpoint { address: d.address });
                    }
                    endpoints.push(EndpointLayout {
                        file_index: endpoints.len() + 1,
                        address: d.address,
                        max_packet_size: d.max_packet_size,
                        role,
                    });
                }
            }
        }
        for interface in interfaces.iter().filter(|i| i.function != Function::Ccid) {
            if hid_report_length(&interface.class_descriptor) != Some(interface.report_descriptor.len()) {
                return Err(DescriptorError::ReportLength { interface: interface.number });
            }
        }
        let has = |kind| interfaces.iter().any(|i| i.function == kind);
        let set = UsbInterfaces { otp: has(Function::Otp), fido: has(Function::Fido), ccid: has(Function::Ccid) };
        if interfaces.is_empty() || set != identity.interfaces {
            return Err(DescriptorError::InterfaceSet);
        }
        let required: [(Function, &[Role]); 3] = [
            (Function::Otp, &[Role::OtpIn]),
            (Function::Fido, &[Role::FidoOut, Role::FidoIn]),
            (Function::Ccid, &[Role::CcidBulkOut, Role::CcidBulkIn]),
        ];
        for (kind, roles) in required {
            if has(kind) && !roles.iter().all(|role| endpoints.iter().any(|e| e.role == *role)) {
                return Err(DescriptorError::MissingEndpoint { function: kind });
            }
        }
        let ccid_max_message_length = interfaces
            .iter()
            .find(|i| i.function == Function::Ccid)
            .and_then(|i| i.class_descriptor.get(CCID_MAX_MESSAGE_OFFSET..CCID_MAX_MESSAGE_OFFSET + 4))
            .and_then(|field| <[u8; 4]>::try_from(field).ok())
            .map(|field| usize::try_from(u32::from_le_bytes(field)).unwrap_or(usize::MAX))
            .unwrap_or(0);
        if has(Function::Ccid) && ccid_max_message_length == 0 {
            return Err(DescriptorError::CcidClassDescriptor);
        }
        Ok(Layout { config, interfaces, endpoints, ccid_max_message_length })
    }

    /// The interface with this number (a SETUP's `wIndex`).
    pub fn interface(&self, number: u16) -> Option<&InterfaceLayout> {
        self.interfaces.iter().find(|i| u16::from(i.number) == number)
    }

    /// The endpoint with this role.
    pub fn endpoint(&self, role: Role) -> Option<&EndpointLayout> {
        self.endpoints.iter().find(|e| e.role == role)
    }

    /// The interface set.
    pub fn interface_set(&self) -> UsbInterfaces {
        let has = |kind| self.interfaces.iter().any(|i| i.function == kind);
        UsbInterfaces { otp: has(Function::Otp), fido: has(Function::Fido), ccid: has(Function::Ccid) }
    }
}

#[cfg(test)]
mod tests;
