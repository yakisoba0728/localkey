//! The CCID class-specific descriptor (USB CCID Rev 1.1 §5.1).
//!
//! [`YUBIKEY_5C_NANO`] holds the values decoded from the device's configuration
//! descriptor (`reference/yubikey-5c-nano-5.7.4/usb-reference-observation.json`, the
//! `0x21` descriptor after the interface descriptor of class `0x0B`). The slot model in
//! this crate takes its limits from it: one slot, T=1 only, short and extended APDU
//! level exchange, 3072-byte messages, one busy slot, no PIN pad, no mechanics.

/// `dwFeatures` bits (§5.1).
pub mod feature {
    /// Automatic parameter configuration based on ATR data.
    pub const AUTO_PARAMETERS_FROM_ATR: u32 = 0x0000_0002;
    /// Automatic activation of the ICC on inserting.
    pub const AUTO_ACTIVATION: u32 = 0x0000_0004;
    /// Automatic ICC voltage selection.
    pub const AUTO_VOLTAGE: u32 = 0x0000_0008;
    /// Automatic ICC clock frequency change according to the active parameters.
    pub const AUTO_CLOCK: u32 = 0x0000_0010;
    /// Automatic baud rate change according to the active parameters.
    pub const AUTO_BAUD_RATE: u32 = 0x0000_0020;
    /// Automatic parameter negotiation made by the CCID.
    pub const AUTO_NEGOTIATION: u32 = 0x0000_0040;
    /// Automatic PPS made by the CCID according to the active parameters.
    pub const AUTO_PPS: u32 = 0x0000_0080;
    /// The CCID can set the ICC in clock stop mode.
    pub const CLOCK_STOP: u32 = 0x0000_0100;
    /// A NAD value other than `00` is accepted (T=1).
    pub const NAD_NOT_ZERO: u32 = 0x0000_0200;
    /// Automatic IFSD exchange as first exchange (T=1).
    pub const AUTO_IFSD: u32 = 0x0000_0400;
    /// TPDU level exchange.
    pub const TPDU_LEVEL: u32 = 0x0001_0000;
    /// Short APDU level exchange.
    pub const SHORT_APDU_LEVEL: u32 = 0x0002_0000;
    /// Short and extended APDU level exchange.
    pub const EXTENDED_APDU_LEVEL: u32 = 0x0004_0000;
    /// USB wake-up signalling on card insertion and removal.
    pub const USB_WAKE_UP: u32 = 0x0010_0000;
}

/// The exchange level a CCID advertises in `dwFeatures` (§5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExchangeLevel {
    /// Character level: none of the level bits is set.
    Character,
    /// TPDU level.
    Tpdu,
    /// Short APDU level.
    ShortApdu,
    /// Short and extended APDU level, with `wLevelParameter` chaining.
    ExtendedApdu,
}

/// The CCID class-specific descriptor, field by field (§5.1). Multi-byte fields are
/// little endian on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassDescriptor {
    /// `bcdCCID`: the CCID specification release the device claims.
    pub bcd_ccid: u16,
    /// `bMaxSlotIndex`: index of the highest slot (number of slots minus one).
    pub max_slot_index: u8,
    /// `bVoltageSupport`: bit 0 5.0 V, bit 1 3.0 V, bit 2 1.8 V.
    pub voltage_support: u8,
    /// `dwProtocols`: bit 0 T=0, bit 1 T=1.
    pub protocols: u32,
    /// `dwDefaultClock` in kHz.
    pub default_clock_khz: u32,
    /// `dwMaximumClock` in kHz.
    pub maximum_clock_khz: u32,
    /// `bNumClockSupported`; 0 means only the default and maximum clock.
    pub num_clock_supported: u8,
    /// `dwDataRate` in bps.
    pub data_rate_bps: u32,
    /// `dwMaxDataRate` in bps.
    pub max_data_rate_bps: u32,
    /// `bNumDataRatesSupported`; 0 means only the default and maximum data rate.
    pub num_data_rates_supported: u8,
    /// `dwMaxIFSD`: the largest IFSD the CCID supports for T=1.
    pub max_ifsd: u32,
    /// `dwSynchProtocols`.
    pub synch_protocols: u32,
    /// `dwMechanical`.
    pub mechanical: u32,
    /// `dwFeatures`, see [`feature`].
    pub features: u32,
    /// `dwMaxCCIDMessageLength`: the largest message including the 10-byte header.
    pub max_message_length: u32,
    /// `bClassGetResponse` (`FF`: echo the class of the APDU).
    pub class_get_response: u8,
    /// `bClassEnvelope` (`FF`: echo the class of the APDU).
    pub class_envelope: u8,
    /// `wLcdLayout` (0: no LCD).
    pub lcd_layout: u16,
    /// `bPINSupport` (0: no PIN verification or modification).
    pub pin_support: u8,
    /// `bMaxCCIDBusySlots`.
    pub max_busy_slots: u8,
}

/// The CCID descriptor of a YubiKey 5C Nano, firmware 5.7.4, decoded from
/// `reference/yubikey-5c-nano-5.7.4/usb-reference-observation.json`.
pub const YUBIKEY_5C_NANO: ClassDescriptor = ClassDescriptor {
    bcd_ccid: 0x0100,
    max_slot_index: 0,
    voltage_support: 0x07,
    protocols: 0x0000_0002,
    default_clock_khz: 4000,
    maximum_clock_khz: 4000,
    num_clock_supported: 0,
    data_rate_bps: 307_200,
    max_data_rate_bps: 307_200,
    num_data_rates_supported: 0,
    max_ifsd: 3062,
    synch_protocols: 0,
    mechanical: 0,
    features: 0x0004_00FE,
    max_message_length: 3072,
    class_get_response: 0xFF,
    class_envelope: 0xFF,
    lcd_layout: 0,
    pin_support: 0,
    max_busy_slots: 1,
};

impl ClassDescriptor {
    /// `bLength` of the descriptor.
    pub const LEN: usize = 0x36;
    /// `bDescriptorType` of the CCID functional descriptor.
    pub const DESCRIPTOR_TYPE: u8 = 0x21;

    /// Parse a complete descriptor, starting at `bLength`.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader { bytes, pos: 0 };
        if usize::from(r.u8()?) != Self::LEN || r.u8()? != Self::DESCRIPTOR_TYPE {
            return None;
        }
        if bytes.len() != Self::LEN {
            return None;
        }
        Some(Self {
            bcd_ccid: r.u16()?,
            max_slot_index: r.u8()?,
            voltage_support: r.u8()?,
            protocols: r.u32()?,
            default_clock_khz: r.u32()?,
            maximum_clock_khz: r.u32()?,
            num_clock_supported: r.u8()?,
            data_rate_bps: r.u32()?,
            max_data_rate_bps: r.u32()?,
            num_data_rates_supported: r.u8()?,
            max_ifsd: r.u32()?,
            synch_protocols: r.u32()?,
            mechanical: r.u32()?,
            features: r.u32()?,
            max_message_length: r.u32()?,
            class_get_response: r.u8()?,
            class_envelope: r.u8()?,
            lcd_layout: r.u16()?,
            pin_support: r.u8()?,
            max_busy_slots: r.u8()?,
        })
    }

    /// Encode the descriptor, starting at `bLength`.
    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut out = Vec::with_capacity(Self::LEN);
        out.extend_from_slice(&[0x36, Self::DESCRIPTOR_TYPE]);
        out.extend_from_slice(&self.bcd_ccid.to_le_bytes());
        out.extend_from_slice(&[self.max_slot_index, self.voltage_support]);
        for v in [
            self.protocols,
            self.default_clock_khz,
            self.maximum_clock_khz,
        ] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.push(self.num_clock_supported);
        for v in [self.data_rate_bps, self.max_data_rate_bps] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.push(self.num_data_rates_supported);
        for v in [
            self.max_ifsd,
            self.synch_protocols,
            self.mechanical,
            self.features,
            self.max_message_length,
        ] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(&[self.class_get_response, self.class_envelope]);
        out.extend_from_slice(&self.lcd_layout.to_le_bytes());
        out.extend_from_slice(&[self.pin_support, self.max_busy_slots]);
        let mut fixed = [0u8; Self::LEN];
        fixed.copy_from_slice(&out);
        fixed
    }

    /// The exchange level advertised in `dwFeatures`; the highest level bit wins.
    pub fn exchange_level(&self) -> ExchangeLevel {
        if self.features & feature::EXTENDED_APDU_LEVEL != 0 {
            ExchangeLevel::ExtendedApdu
        } else if self.features & feature::SHORT_APDU_LEVEL != 0 {
            ExchangeLevel::ShortApdu
        } else if self.features & feature::TPDU_LEVEL != 0 {
            ExchangeLevel::Tpdu
        } else {
            ExchangeLevel::Character
        }
    }

    /// The largest `abData` of one message: `dwMaxCCIDMessageLength` minus the header.
    pub fn max_data_len(&self) -> usize {
        usize::try_from(self.max_message_length)
            .unwrap_or(usize::MAX)
            .saturating_sub(crate::message::HEADER_LEN)
    }
}

/// Little-endian field reader for [`ClassDescriptor::parse`].
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        let end = self.pos.checked_add(N)?;
        let field = self.bytes.get(self.pos..end)?.try_into().ok()?;
        self.pos = end;
        Some(field)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take::<1>().map(|[b]| b)
    }

    fn u16(&mut self) -> Option<u16> {
        self.take().map(u16::from_le_bytes)
    }

    fn u32(&mut self) -> Option<u32> {
        self.take().map(u32::from_le_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_round_trips() {
        let bytes = YUBIKEY_5C_NANO.to_bytes();
        assert_eq!(bytes[0], 0x36);
        assert_eq!(bytes[1], 0x21);
        assert_eq!(ClassDescriptor::parse(&bytes), Some(YUBIKEY_5C_NANO));
    }

    #[test]
    fn parse_rejects_wrong_length_or_type() {
        let mut bytes = YUBIKEY_5C_NANO.to_bytes();
        assert_eq!(ClassDescriptor::parse(&bytes[..53]), None);
        bytes[1] = 0x22;
        assert_eq!(ClassDescriptor::parse(&bytes), None);
    }

    #[test]
    fn exchange_level_takes_highest_bit() {
        // CCID Rev 1.1 §5.1 dwFeatures: 0x00010000 TPDU, 0x00020000 short APDU,
        // 0x00040000 short and extended APDU, none of them: character level.
        let with = |features| ClassDescriptor {
            features,
            ..YUBIKEY_5C_NANO
        };
        assert_eq!(with(0x0000_00FE).exchange_level(), ExchangeLevel::Character);
        assert_eq!(with(0x0001_00FE).exchange_level(), ExchangeLevel::Tpdu);
        assert_eq!(with(0x0002_00FE).exchange_level(), ExchangeLevel::ShortApdu);
        assert_eq!(
            with(0x0004_00FE).exchange_level(),
            ExchangeLevel::ExtendedApdu
        );
        assert_eq!(YUBIKEY_5C_NANO.max_data_len(), 3062);
    }
}
