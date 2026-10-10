//! GET DATA and PUT DATA (SP 800-73-4 Part 2 §3.1.2 and §3.3.2).

use lk_codec::apdu::{Command, sw};
use lk_codec::tlv;
use lk_core::Host;

use crate::objects::{self, DISCOVERY, ObjectId, TAG_DATA, TAG_TAG_LIST};
use crate::{Piv, Reply, explicit_le};

/// P1-P2 of GET DATA and PUT DATA (SP 800-73-4 Part 2 §3.1.2, §3.3.2).
const P1P2_DATA: (u8, u8) = (0x3F, 0xFF);

/// Parse the leading `5C` tag list of a GET/PUT DATA data field and return the named
/// object with the bytes after the tag list. A missing or malformed `5C`, or a tag that
/// names no object, is `6A80` (SP 800-73-4 Part 2 §3.1.2 status words).
fn parse_tag_list(data: &[u8]) -> Result<(ObjectId, &[u8]), u16> {
    let (list, rest) = tlv::parse_one(data).map_err(|_| sw::INCORRECT_DATA)?;
    if list.tag != TAG_TAG_LIST {
        return Err(sw::INCORRECT_DATA);
    }
    let id = ObjectId::from_tag_list(list.value).ok_or(sw::INCORRECT_DATA)?;
    Ok((id, rest))
}

impl Piv {
    /// GET DATA (`INS CB`, SP 800-73-4 Part 2 §3.1.2).
    ///
    /// - P1-P2 must be `3FFF` (`6A86`). The data field must be exactly one `5C` tag list
    ///   (`6A80`). Le may be present or absent.
    /// - `7E` returns the fixed Discovery Object as is; `7F61` (BIT group template) is not
    ///   supported and returns `6A82`.
    /// - A container returns `53 L value`, or `6A82` when nothing is stored. Containers
    ///   whose read access rule is PIN (Part 1 Table 3) answer `6982` until the PIN is
    ///   verified, whether or not they hold data.
    pub(crate) fn get_data(&self, cmd: &Command) -> Reply {
        if (cmd.p1, cmd.p2) != P1P2_DATA {
            return Err(sw::INCORRECT_P1P2);
        }
        let (id, rest) = parse_tag_list(&cmd.data)?;
        if !rest.is_empty() {
            return Err(sw::INCORRECT_DATA);
        }
        match id {
            ObjectId::Discovery => Ok(DISCOVERY.to_vec()),
            ObjectId::Bitgt => Err(sw::FILE_NOT_FOUND),
            ObjectId::Container(tag) => {
                if objects::read_requires_pin(tag) && !self.session.pin_verified {
                    return Err(sw::SECURITY_STATUS);
                }
                let value = self.state.objects.get(tag).ok_or(sw::FILE_NOT_FOUND)?;
                Ok(tlv::encode(TAG_DATA, value))
            }
        }
    }

    /// PUT DATA (`INS DB`, SP 800-73-4 Part 2 §3.3.2).
    ///
    /// Checks, in order, each leaving the stored state untouched:
    ///
    /// 1. P1-P2 `3FFF` (`6A86`); Le absent (`6700`; Part 2 §3.3.2 lists Le as empty;
    ///    catalog "PIV generate/import/PUT DATA absent-Le guards").
    /// 2. Card management key authenticated (`6982`; Part 2 §3.3.2 access rule).
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
    /// An empty `53` deletes the object. The Printed Information container `5FC109` is
    /// writable: `reference/piv-printed-source-conflict.md` records conflicting Yubico
    /// statements, and this model follows the low-level GET/PUT DATA page, which says
    /// the raw command is accepted. Persist failure: `6581`, state unchanged.
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
