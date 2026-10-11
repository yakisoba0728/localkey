//! GET DATA and PUT DATA (SP 800-73-4 Part 2 §3.1.2 and §3.3.1).

use lk_codec::apdu::{Command, sw};
use lk_codec::tlv;
use lk_core::Host;

use crate::objects::{self, DISCOVERY, ObjectId, TAG_DATA, TAG_TAG_LIST};
use crate::{Piv, Reply, explicit_le};

/// P1-P2 of GET DATA and PUT DATA (SP 800-73-4 Part 2 §3.1.2, §3.3.1).
const P1P2_DATA: (u8, u8) = (0x3F, 0xFF);

/// Parse the leading `5C` tag list of a GET/PUT DATA data field and return the named
/// object with the bytes after the tag list. A missing or malformed `5C`, or a tag that
/// names no object, is `6A80` (SP 800-73-4 Part 2 §3.1.2 status words). GET DATA first
/// answers a tag list cut short `6A82` ([`tag_list_cut_short`]).
fn parse_tag_list(data: &[u8]) -> Result<(ObjectId, &[u8]), u16> {
    let (list, rest) = tlv::parse_one(data).map_err(|_| sw::INCORRECT_DATA)?;
    if list.tag != TAG_TAG_LIST {
        return Err(sw::INCORRECT_DATA);
    }
    let id = ObjectId::from_tag_list(list.value).ok_or(sw::INCORRECT_DATA)?;
    Ok((id, rest))
}

/// Whether `data` starts with a `5C` tag list whose one-byte length announces more value
/// bytes than the data field holds, as in `5C 01` with the tag missing. GET DATA answers
/// it `6A82`: measured on a YubiKey 5C Nano 5.7.4 for `00 CB 3F FF 02 5C 01 7E`
/// (docs/MEASUREMENT.md, probe `lc-le-piv-get-data`). Other malformed tag lists (no
/// length byte, a long-form length, a bad tag) are unmeasured and stay `6A80`.
fn tag_list_cut_short(data: &[u8]) -> bool {
    match data {
        [tag, len, value @ ..] if u32::from(*tag) == TAG_TAG_LIST && *len < 0x80 => {
            usize::from(*len) > value.len()
        }
        _ => false,
    }
}

impl Piv {
    /// GET DATA (`INS CB`, SP 800-73-4 Part 2 §3.1.2).
    ///
    /// - P1-P2 must be `3FFF`; any other value is `6A82` (measured on a YubiKey 5C Nano
    ///   5.7.4 for `3FFE` and `0000`, docs/MEASUREMENT.md, probe `bad-p1p2-piv`; Part 2
    ///   §3.1.2 does not name a status for it). A tag list cut short is `6A82`
    ///   ([`tag_list_cut_short`]); otherwise the data field must be exactly one `5C` tag
    ///   list (`6A80`). Le may be present or absent.
    /// - `7E` returns the fixed Discovery Object as is; `7F61` (BIT group template) is not
    ///   supported and returns `6A82`.
    /// - A container returns `53 L value`, or `6A82` when nothing is stored. A stored
    ///   container whose read access rule is PIN (Part 1 Table 3) answers `6982` until
    ///   the PIN is verified. An empty one answers `6A82` with or without the PIN: OpenSC
    ///   (`card-piv.c`, `CI_LEAKS_FILE_NOT_FOUND`, set for every YubiKey 4 and 5 PIV
    ///   applet) records that YubiKeys answer "GET DATA of empty object ... 6A 82 even if
    ///   PIN not verified". Part 2 §3.1.2 lists both status words without an order.
    pub(crate) fn get_data(&self, cmd: &Command) -> Reply {
        if (cmd.p1, cmd.p2) != P1P2_DATA {
            return Err(sw::FILE_NOT_FOUND);
        }
        if tag_list_cut_short(&cmd.data) {
            return Err(sw::FILE_NOT_FOUND);
        }
        let (id, rest) = parse_tag_list(&cmd.data)?;
        if !rest.is_empty() {
            return Err(sw::INCORRECT_DATA);
        }
        match id {
            ObjectId::Discovery => Ok(DISCOVERY.to_vec()),
            ObjectId::Bitgt => Err(sw::FILE_NOT_FOUND),
            ObjectId::Container(tag) => {
                let value = self.state.objects.get(tag).ok_or(sw::FILE_NOT_FOUND)?;
                if objects::read_requires_pin(tag) && !self.session.pin_verified {
                    return Err(sw::SECURITY_STATUS);
                }
                Ok(tlv::encode(TAG_DATA, value))
            }
        }
    }

    /// PUT DATA (`INS DB`, SP 800-73-4 Part 2 §3.3.1).
    ///
    /// Checks, in order, each leaving the stored state untouched:
    ///
    /// 1. P1-P2 `3FFF` (`6A86`, model policy: unlike GET DATA's measured `6A82`, PUT
    ///    DATA was not measured); no non-zero Le (`6700`; Part 2 §3.3.1 lists Le as
    ///    empty; catalog "PIV generate/import/PUT DATA absent-Le guards", in the device
    ///    section). Le `00`, which yubico-piv-tool appends on T=1, is accepted
    ///    (`crate::explicit_le`).
    /// 2. Card management key authenticated (`6982`; Part 2 §3.3.1 access rule).
    /// 3. Data `5C L tag || 53 L value` with nothing after it (`6A80`). `7E` and `7F61`
    ///    are read-only (`6A80`; profile `readonly_objects`, catalog "read-only object PUT
    ///    rejection with unchanged persistent state").
    /// 4. A certificate (tag `70`) over 3052 bytes in a certificate container is `6700`
    ///    (catalog "published 3052-byte tag70 certificate limit"; the legacy model answered
    ///    oversized PIV PUTs with `6700`; the physical status is unmeasured).
    /// 5. The new total of stored values must stay within 51200 bytes, judged after
    ///    releasing the old value (`6A84`; catalog "atomic out-of-space
    ///    replacement/deletion and restart accounting").
    ///
    /// An empty `53` deletes the object (python yubikit `put_object(object_id, None)` and
    /// yubico-piv-tool `ykpiv_save_object` with no data delete this way). The Printed
    /// Information container `5FC109` is writable: `reference/piv-printed-source-conflict.md`
    /// records conflicting Yubico statements, and this model follows the low-level
    /// GET/PUT DATA page, which says the raw command is accepted. Persist failure: `6581`,
    /// state unchanged.
    pub(crate) fn put_data(&mut self, cmd: &Command, host: &mut dyn Host) -> Reply {
        if (cmd.p1, cmd.p2) != P1P2_DATA {
            return Err(sw::INCORRECT_P1P2);
        }
        if explicit_le(cmd) {
            return Err(sw::WRONG_LENGTH);
        }
        if !self.session.mgmt_authenticated {
            return Err(sw::SECURITY_STATUS);
        }
        let (id, rest) = parse_tag_list(&cmd.data)?;
        let ObjectId::Container(tag) = id else {
            return Err(sw::INCORRECT_DATA);
        };
        let (object, tail) = tlv::parse_one(rest).map_err(|_| sw::INCORRECT_DATA)?;
        if object.tag != TAG_DATA || !tail.is_empty() {
            return Err(sw::INCORRECT_DATA);
        }
        let value = object.value;
        if objects::certificate_too_large(tag, value) {
            return Err(sw::WRONG_LENGTH);
        }
        if !self.state.objects.fits(tag, value.len()) {
            return Err(sw::NO_SPACE);
        }
        let value = value.to_vec();
        self.modify(host, |s| s.objects.put(tag, value))?;
        Ok(Vec::new())
    }
}
