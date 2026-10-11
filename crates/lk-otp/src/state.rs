//! Persistent state and its record format (`docs/CONTRACTS.md` "Persisted state").
//!
//! Format: version byte `0x01`, then BER-TLV objects (ISO/IEC 7816-4 §5.2) via
//! `lk_codec::tlv`:
//!
//! | Tag | Value |
//! | --- | --- |
//! | `01` | programming sequence (1 byte) |
//! | `02` | scan map (45 bytes) |
//! | `03` / `04` | slot 1 / slot 2 configuration (52 bytes, CRC-protected) |
//! | `05` / `06` | slot 1 / slot 2 counter (4 bytes, big-endian): HOTP moving factor or Yubico OTP usage counter |
//!
//! Unknown tags are kept verbatim and written back. Anything unreadable (wrong
//! version, malformed TLV, bad configuration CRC, a configuration without its counter)
//! means factory state.

use lk_codec::tlv;
use lk_crypto::SecretBytes;

use crate::config::{CONFIG_SIZE, SlotConfig};
use crate::keyboard::{DEFAULT_SCAN_MAP, SCAN_MAP_SIZE};

const FORMAT_VERSION: u8 = 0x01;
const TAG_PGM_SEQ: u32 = 0x01;
const TAG_SCAN_MAP: u32 = 0x02;
const TAG_CONFIG: [u32; 2] = [0x03, 0x04];
const TAG_COUNTER: [u32; 2] = [0x05, 0x06];

/// One configured slot.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SlotState {
    pub(crate) config: SlotConfig,
    /// HOTP moving factor, or the Yubico OTP usage counter.
    pub(crate) counter: u32,
}

impl core::fmt::Debug for SlotState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SlotState")
            .field("config", &self.config)
            .field("counter", &self.counter)
            .finish()
    }
}

/// Everything that survives a restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Persistent {
    pub(crate) slots: [Option<SlotState>; 2],
    pub(crate) pgm_seq: u8,
    pub(crate) scan_map: [u8; SCAN_MAP_SIZE],
    /// Unknown TLV objects from a newer format, written back unchanged.
    pub(crate) unknown: Vec<u8>,
}

impl Default for Persistent {
    fn default() -> Self {
        Self {
            slots: [None, None],
            pgm_seq: 0,
            scan_map: DEFAULT_SCAN_MAP,
            unknown: Vec::new(),
        }
    }
}

impl Persistent {
    pub(crate) fn any_configured(&self) -> bool {
        self.slots.iter().any(Option::is_some)
    }

    /// The record bytes. They hold the slot secrets, so they come in [`SecretBytes`],
    /// in a buffer allocated at its final size (no growing `Vec` frees an unwiped
    /// copy), and the encoded configuration is wiped after use (`docs/DESIGN.md` §8).
    pub(crate) fn serialize(&self) -> SecretBytes {
        let mut out = Vec::with_capacity(self.record_len());
        out.push(FORMAT_VERSION);
        tlv::encode_into(&mut out, TAG_PGM_SEQ, &[self.pgm_seq]);
        tlv::encode_into(&mut out, TAG_SCAN_MAP, &self.scan_map);
        for (index, slot) in self.slots.iter().enumerate() {
            if let Some(slot) = slot {
                let (config_tag, counter_tag) = (TAG_CONFIG[index], TAG_COUNTER[index]);
                let mut config = slot.config.to_bytes();
                tlv::encode_into(&mut out, config_tag, &config);
                lk_crypto::wipe(&mut config);
                tlv::encode_into(&mut out, counter_tag, &slot.counter.to_be_bytes());
            }
        }
        out.extend_from_slice(&self.unknown);
        SecretBytes::new(out)
    }

    /// The length of [`serialize`](Self::serialize)'s output: the version byte, `01 01
    /// seq`, `02 2D map`, per configured slot `0x 34 config` and `0x 04 counter`, then
    /// the unknown objects.
    fn record_len(&self) -> usize {
        let slots = self.slots.iter().flatten().count();
        1 + 3 + 2 + SCAN_MAP_SIZE + slots * (2 + CONFIG_SIZE + 2 + 4) + self.unknown.len()
    }

    /// Decode a record; `None` if anything is unreadable.
    pub(crate) fn deserialize(bytes: &[u8]) -> Option<Self> {
        let (&version, body) = bytes.split_first()?;
        if version != FORMAT_VERSION {
            return None;
        }
        let items = tlv::parse_all(body).ok()?;
        let mut state = Self::default();
        let mut configs: [Option<SlotConfig>; 2] = [None, None];
        let mut counters: [Option<u32>; 2] = [None, None];
        for item in &items {
            match item.tag {
                TAG_PGM_SEQ => {
                    let [seq] = <[u8; 1]>::try_from(item.value).ok()?;
                    state.pgm_seq = seq;
                }
                TAG_SCAN_MAP => {
                    state.scan_map = <[u8; SCAN_MAP_SIZE]>::try_from(item.value).ok()?
                }
                tag if TAG_CONFIG.contains(&tag) => {
                    let index = usize::from(tag == TAG_CONFIG[1]);
                    *configs.get_mut(index)? = Some(SlotConfig::parse(item.value)?);
                }
                tag if TAG_COUNTER.contains(&tag) => {
                    let index = usize::from(tag == TAG_COUNTER[1]);
                    let value = u32::from_be_bytes(<[u8; 4]>::try_from(item.value).ok()?);
                    *counters.get_mut(index)? = Some(value);
                }
                _ => state.unknown.extend_from_slice(item.raw),
            }
        }
        for index in 0..2 {
            let config = configs.get_mut(index)?.take();
            let counter = counters.get(index).copied().flatten();
            let slot = match (config, counter) {
                (Some(config), Some(counter)) => Some(SlotState { config, counter }),
                (None, _) => None,
                (Some(_), None) => return None,
            };
            *state.slots.get_mut(index)? = slot;
        }
        Some(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{SlotConfig, ext};

    fn config() -> SlotConfig {
        SlotConfig {
            fixed: [9; 16],
            uid: [8; 6],
            key: [7; 16],
            acc_code: [1, 2, 3, 4, 5, 6],
            fixed_size: 4,
            ext_flags: ext::ALLOW_UPDATE,
            tkt_flags: 0,
            cfg_flags: 0,
            rfu: [0; 2],
        }
    }

    #[test]
    fn round_trip_keeps_unknown_tags() {
        let mut state = Persistent {
            pgm_seq: 7,
            ..Persistent::default()
        };
        state.slots[1] = Some(SlotState {
            config: config(),
            counter: 0x0102_0304,
        });
        let mut bytes = state.serialize().to_vec();
        bytes.extend_from_slice(&[0x1E, 0x02, 0xAA, 0xBB]);
        let back = Persistent::deserialize(&bytes).expect("readable");
        assert_eq!(back.slots, state.slots);
        assert_eq!(back.pgm_seq, 7);
        assert_eq!(back.unknown, vec![0x1E, 0x02, 0xAA, 0xBB]);
        assert_eq!(back.serialize().as_slice(), bytes.as_slice());
    }

    /// The record buffer is allocated at its final size, so it is never reallocated
    /// (which would free an unwiped copy of the slot secrets).
    #[test]
    fn record_length_is_known_before_encoding() {
        let mut state = Persistent::default();
        assert_eq!(state.serialize().len(), state.record_len());
        state.slots[0] = Some(SlotState {
            config: config(),
            counter: 1,
        });
        assert_eq!(state.serialize().len(), state.record_len());
        state.slots[1] = Some(SlotState {
            config: config(),
            counter: 2,
        });
        state.unknown = vec![0x1E, 0x02, 0xAA, 0xBB];
        assert_eq!(state.serialize().len(), state.record_len());
    }

    #[test]
    fn unreadable_records_are_rejected() {
        let mut state = Persistent::default();
        state.slots[0] = Some(SlotState {
            config: config(),
            counter: 1,
        });
        let bytes = state.serialize();
        assert!(Persistent::deserialize(&bytes).is_some());
        assert!(Persistent::deserialize(&[]).is_none());
        assert!(Persistent::deserialize(&[0x02]).is_none());
        assert!(Persistent::deserialize(&bytes[..bytes.len() - 1]).is_none());
        // A configuration without its counter is unreadable.
        let mut no_counter = vec![0x01];
        no_counter.extend(tlv::encode(0x03, &config().to_bytes()));
        assert!(Persistent::deserialize(&no_counter).is_none());
        // A configuration with a broken CRC is unreadable.
        let mut bad = config().to_bytes();
        bad[0] ^= 1;
        let mut bad_crc = vec![0x01];
        bad_crc.extend(tlv::encode(0x03, &bad));
        bad_crc.extend(tlv::encode(0x05, &[0, 0, 0, 0]));
        assert!(Persistent::deserialize(&bad_crc).is_none());
    }
}
