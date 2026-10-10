//! `authenticatorLargeBlobs` (CTAP 2.1 §6.10).
//!
//! The serialized large-blob array is opaque to the authenticator except for its
//! integrity trailer (`LEFT(SHA-256(contents), 16)`, §6.10.2). It is persisted in
//! `Record::Fido` and starts as [`crate::state::INITIAL_LARGE_BLOB`].
//!
//! - Fragments are at most `maxFragmentLength = maxMsgSize - 64` = 1472 bytes (§6.10.2;
//!   `reference/BEHAVIOR_CATALOG.md` FIDO: "1472-byte large-blob fragments with boundary
//!   checks"); the whole array at most `maxSerializedLargeBlobArray` = 4096 bytes.
//! - A write is a sequence of `set` fragments. The first, at offset 0, declares the total
//!   `length` and restarts any sequence in progress; each later fragment must start at the
//!   expected next offset. The sequence check comes **before** pinUvAuthParam
//!   verification (`reference/BEHAVIOR_CATALOG.md` FIDO: "large-blob write validates
//!   fragment sequence before PIN/UV auth and restarts a sequence on offset zero").
//! - Fragments are buffered in volatile memory; nothing is persisted until the last one
//!   arrives and the integrity check passes. The pending sequence survives other commands
//!   and is dropped by power cycle and reset, and when the pinUvAuthToken that
//!   authenticated its offset-0 fragment expires (§6, stateful commands: the state "MUST"
//!   then be discarded), so every fragment of one sequence is authorized by one token.

use lk_codec::cbor::MapBuilder;
use lk_core::Host;
use lk_crypto::sha256;

use crate::client_pin::{permission, supported_protocol};
use crate::get_info::{MAX_MSG_SIZE, MAX_SERIALIZED_LARGE_BLOB_ARRAY};
use crate::request::{CtapResult, Params, bytes, required, unsigned};
use crate::state::INITIAL_LARGE_BLOB;
use crate::{Authenticator, ok, status};

/// `maxFragmentLength` (§6.10.2).
pub(crate) const MAX_FRAGMENT_LENGTH: usize = MAX_MSG_SIZE - 64;
/// The integrity trailer length (§6.10.2).
const TRAILER: usize = 16;

/// A write sequence in progress: the declared `length` and the fragments received so far
/// (their length is the expected next offset).
#[derive(Debug)]
pub(crate) struct PendingWrite {
    expected_length: usize,
    buffer: Vec<u8>,
    /// The pinUvAuthToken that authenticated the offset-0 fragment, when one was needed:
    /// the sequence ends when it expires (CTAP 2.1 §6, stateful commands).
    token: Option<u64>,
}

impl Authenticator {
    pub(crate) fn large_blobs(&mut self, params: &[u8], host: &mut dyn Host) -> Vec<u8> {
        match self.large_blobs_inner(params, host) {
            Ok(response) => response,
            Err(code) => vec![code],
        }
    }

    fn large_blobs_inner(&mut self, params: &[u8], host: &mut dyn Host) -> CtapResult<Vec<u8>> {
        // §6.10.1 parameters.
        let p = Params::decode(params)?;
        let get = p.get(0x01).map(unsigned).transpose()?;
        let set = p.get(0x02).map(bytes).transpose()?;
        let offset = p.get(0x03).map(unsigned).transpose()?;
        let length = p.get(0x04).map(unsigned).transpose()?;
        let param = p.get(0x05).map(bytes).transpose()?;
        let protocol = p.get(0x06).map(unsigned).transpose()?;
        // Step 1: "If offset is not present in the input map, return
        // CTAP1_ERR_INVALID_PARAMETER" (not MISSING_PARAMETER: §6.10.2 names the status).
        let offset = offset.ok_or(status::INVALID_PARAMETER)?;
        match (get, set) {
            (Some(get), None) => {
                let authenticated = param.is_some() || protocol.is_some();
                self.large_blob_get(get, offset, length, authenticated)
            }
            (None, Some(fragment)) => {
                self.large_blob_set(fragment, offset, length, param, protocol, host)
            }
            // Steps 2-3: "If neither get nor set are present ... If both get and set are
            // present ..., return CTAP1_ERR_INVALID_PARAMETER."
            _ => Err(status::INVALID_PARAMETER),
        }
    }

    /// Read `get` bytes from `offset` (§6.10.2 step 4), in the step order: `length`
    /// present, then pinUvAuthParam or pinUvAuthProtocol present
    /// (`authenticated`), `CTAP1_ERR_INVALID_PARAMETER`; `get` above maxFragmentLength
    /// `CTAP1_ERR_INVALID_LENGTH`; `offset` past the end `CTAP1_ERR_INVALID_PARAMETER`.
    fn large_blob_get(
        &self,
        get: u64,
        offset: u64,
        length: Option<u64>,
        authenticated: bool,
    ) -> CtapResult<Vec<u8>> {
        if length.is_some() || authenticated {
            return Err(status::INVALID_PARAMETER);
        }
        let get = usize::try_from(get)
            .ok()
            .filter(|&g| g <= MAX_FRAGMENT_LENGTH)
            .ok_or(status::INVALID_LENGTH)?;
        let array = &self.state.large_blob;
        let offset = usize::try_from(offset)
            .ok()
            .filter(|&o| o <= array.len())
            .ok_or(status::INVALID_PARAMETER)?;
        let end = offset.saturating_add(get).min(array.len());
        let slice = array.get(offset..end).ok_or(status::INVALID_PARAMETER)?;
        Ok(ok(MapBuilder::new().insert(0x01, slice.to_vec()).build()))
    }

    /// Write one fragment (§6.10.2 "set").
    fn large_blob_set(
        &mut self,
        fragment: &[u8],
        offset: u64,
        length: Option<u64>,
        param: Option<&[u8]>,
        protocol: Option<u64>,
        host: &mut dyn Host,
    ) -> CtapResult<Vec<u8>> {
        if fragment.len() > MAX_FRAGMENT_LENGTH {
            return Err(status::INVALID_LENGTH);
        }
        // §6: "An authenticator MUST discard the state for a stateful command if the
        // pinUvAuthToken that authenticated the state initializing command expires".
        let now = host.now();
        if self
            .large_blob_write
            .as_ref()
            .and_then(|w| w.token)
            .is_some_and(|serial| !self.pin.token_still_valid(serial, now))
        {
            self.large_blob_write = None;
        }
        if offset == 0 {
            let length = length.ok_or(status::INVALID_PARAMETER)?;
            let length = usize::try_from(length)
                .ok()
                .filter(|&l| l <= MAX_SERIALIZED_LARGE_BLOB_ARRAY)
                .ok_or(status::LARGE_BLOB_STORAGE_FULL)?;
            if length < INITIAL_LARGE_BLOB.len() {
                return Err(status::INVALID_PARAMETER);
            }
            // expectedLength = length, expectedNextOffset = 0: a new sequence.
            self.large_blob_write = Some(PendingWrite {
                expected_length: length,
                buffer: Vec::with_capacity(length),
                token: None,
            });
        } else if length.is_some() {
            return Err(status::INVALID_PARAMETER);
        }
        let expected_next = self.large_blob_write.as_ref().map_or(0, |w| w.buffer.len());
        let offset32 = u32::try_from(offset).map_err(|_| status::INVALID_SEQ)?;
        if usize::try_from(offset).ok() != Some(expected_next) {
            return Err(status::INVALID_SEQ);
        }
        // §6.10.2: authorization only when the authenticator is protected by a PIN or
        // alwaysUv is on.
        if self.state.pin_is_set() || self.state.pin.always_uv {
            let param = param.ok_or(status::PUAT_REQUIRED)?;
            let protocol = supported_protocol(required(protocol)?)?;
            // 32 × 0xff || h'0c00' || uint32LittleEndian(offset) || SHA-256(fragment).
            let mut message = vec![0xFF; 32];
            message.extend_from_slice(&[0x0C, 0x00]);
            message.extend_from_slice(&offset32.to_le_bytes());
            message.extend_from_slice(&sha256(fragment));
            let token = self.verified_token(protocol, &message, param, now)?;
            if token.permissions & permission::LBW == 0 {
                return Err(status::PIN_AUTH_INVALID);
            }
            if offset == 0
                && let Some(write) = self.large_blob_write.as_mut()
            {
                write.token = self.pin.token_serial();
            }
        }
        let write = self.large_blob_write.as_mut().ok_or(status::INVALID_SEQ)?;
        if expected_next.saturating_add(fragment.len()) > write.expected_length {
            return Err(status::INVALID_PARAMETER);
        }
        write.buffer.extend_from_slice(fragment);
        if write.buffer.len() < write.expected_length {
            return Ok(vec![status::OK]);
        }
        // The last fragment: check the trailer, then persist the new array.
        let Some(write) = self.large_blob_write.take() else {
            return Err(status::OTHER);
        };
        let split = write.buffer.len().saturating_sub(TRAILER);
        let (contents, trailer) = write.buffer.split_at(split);
        if sha256(contents).get(..TRAILER) != Some(trailer) {
            return Err(status::INTEGRITY_FAILURE);
        }
        let mut next = self.state.clone();
        next.large_blob = write.buffer.clone();
        if let Err(code) = self.commit(next, host) {
            // Keep the sequence as it was before this fragment.
            let mut buffer = write.buffer;
            buffer.truncate(expected_next);
            self.large_blob_write = Some(PendingWrite {
                expected_length: write.expected_length,
                buffer,
                token: write.token,
            });
            return Err(code);
        }
        Ok(vec![status::OK])
    }
}
