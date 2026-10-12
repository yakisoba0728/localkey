//! ISO/IEC 7816-4 command/response APDUs, status words and chaining helpers.
//!
//! - [`Command`] parses and builds command APDUs in the short and extended forms of
//!   ISO/IEC 7816-4 §5.1 (cases 1, 2S, 3S, 4S, 2E, 3E and 4E).
//! - [`sw`] holds the status words (§5.1.3) used across the applets. A response APDU is
//!   `data || SW1 SW2`; see [`response`] and [`status`].
//! - [`CommandChain`] reassembles command chaining (§5.1.1.1, CLA bit b5).
//! - [`ResponseQueue`] serves long responses in pieces with `61xx` for GET RESPONSE
//!   (§7.6.1) or an applet's own continuation command.
//!
//! Section numbers follow ISO/IEC 7816-4:2005.
//!
//! Command data and response data carry PINs, management keys and imported key
//! material, so every buffer of this module is wiped (`docs/DESIGN.md` §8): a
//! [`Command`]'s data when the command is dropped, a [`CommandChain`]'s buffered data
//! when the chain completes, is cleared or is dropped (and before a growing buffer is
//! reallocated), and a [`ResponseQueue`]'s data when it is replaced, cleared, fully
//! served or dropped. Their `Debug` output shows lengths, never bytes. This crate may
//! not depend on `zeroize` (only `lk-crypto` may), so the wipe is the same best effort
//! as in lk-sd and lk-hsmauth: plain zero stores kept observable with
//! [`std::hint::black_box`]. Copies made outside these types (the bytes returned by
//! [`Command::to_bytes`], [`Command::into_data`], [`response`] or
//! [`ResponseQueue::next`]) belong to the caller.
//!
//! The `Drop` on [`Command`] is an intentional API change: a caller can no longer move
//! the public `data` field out of a command (E0509) and uses [`Command::into_data`]
//! (or a clone) instead. Every other use of the public fields compiles unchanged.

use std::fmt;

/// CLA bit b5: command chaining, "not the last command of a chain" (§5.1.1.1).
const CHAIN_BIT: u8 = 0x10;

/// Largest Ne of a short command, written as `Le = 00` (§5.1).
const SHORT_MAX_NE: u32 = 256;

/// Largest Ne of an extended command, written as `Le = 00 00` (§5.1).
const EXTENDED_MAX_NE: u32 = 65_536;

/// Largest Nc of an extended command (§5.1).
const EXTENDED_MAX_NC: usize = 0xFFFF;

/// Status words (ISO/IEC 7816-4 §5.1.3), as `SW1 << 8 | SW2`.
pub mod sw {
    /// Normal processing.
    pub const OK: u16 = 0x9000;
    /// Memory failure (persisting state failed).
    pub const MEMORY_FAILURE: u16 = 0x6581;
    /// Wrong length (Lc or Le, or a malformed APDU).
    pub const WRONG_LENGTH: u16 = 0x6700;
    /// Logical channel not supported.
    pub const LOGICAL_CHANNEL_NOT_SUPPORTED: u16 = 0x6881;
    /// Secure messaging not supported.
    pub const SM_NOT_SUPPORTED: u16 = 0x6882;
    /// Last command of the chain expected.
    pub const LAST_COMMAND_EXPECTED: u16 = 0x6883;
    /// Command chaining not supported.
    pub const CHAINING_NOT_SUPPORTED: u16 = 0x6884;
    /// Security status not satisfied.
    pub const SECURITY_STATUS: u16 = 0x6982;
    /// Authentication method blocked.
    pub const AUTH_BLOCKED: u16 = 0x6983;
    /// Reference data not usable (invalid data).
    pub const DATA_INVALID: u16 = 0x6984;
    /// Conditions of use not satisfied.
    pub const CONDITIONS: u16 = 0x6985;
    /// Command not allowed (no current EF).
    pub const COMMAND_NOT_ALLOWED: u16 = 0x6986;
    /// Expected secure messaging data objects missing.
    pub const SM_DATA_MISSING: u16 = 0x6987;
    /// Incorrect secure messaging data objects.
    pub const SM_DATA_INCORRECT: u16 = 0x6988;
    /// Incorrect parameters in the command data field.
    pub const INCORRECT_DATA: u16 = 0x6A80;
    /// Function not supported.
    pub const FUNC_NOT_SUPPORTED: u16 = 0x6A81;
    /// File or application not found.
    pub const FILE_NOT_FOUND: u16 = 0x6A82;
    /// Not enough memory space in the file.
    pub const NO_SPACE: u16 = 0x6A84;
    /// Incorrect parameters P1-P2.
    pub const INCORRECT_P1P2: u16 = 0x6A86;
    /// Referenced data or reference data not found.
    pub const REF_NOT_FOUND: u16 = 0x6A88;
    /// Wrong parameters P1-P2.
    pub const WRONG_P1P2: u16 = 0x6B00;
    /// Instruction code not supported or invalid.
    pub const INS_NOT_SUPPORTED: u16 = 0x6D00;
    /// Class not supported.
    pub const CLA_NOT_SUPPORTED: u16 = 0x6E00;
    /// No precise diagnosis.
    pub const UNKNOWN: u16 = 0x6F00;

    /// `61xx`: `remaining` more response bytes are available (§5.1.3).
    ///
    /// SW2 is `remaining` for 1..=255 and `00` for 256 or more. `remaining` should be
    /// non-zero; `0` also yields `6100`.
    pub const fn more_data(remaining: usize) -> u16 {
        if remaining >= 256 {
            0x6100
        } else {
            0x6100 | remaining as u16
        }
    }

    /// `63Cx`: verification failed, `x` tries left (§5.1.3). Values above 15 are
    /// written as 15.
    pub const fn retries(left: u8) -> u16 {
        let x = if left > 0x0F { 0x0F } else { left };
        0x63C0 | x as u16
    }

    /// `6Cxx`: wrong Le field; `available` bytes are available (§5.1.3). SW2 is `00`
    /// for 256 or more.
    pub const fn wrong_le(available: usize) -> u16 {
        if available >= 256 {
            0x6C00
        } else {
            0x6C00 | available as u16
        }
    }
}

/// A response APDU: `data || SW1 SW2`.
pub fn response(data: &[u8], sw: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 2);
    out.extend_from_slice(data);
    out.extend_from_slice(&sw.to_be_bytes());
    out
}

/// A response APDU without data: `SW1 SW2`.
pub fn status(sw: u16) -> Vec<u8> {
    sw.to_be_bytes().to_vec()
}

/// Split a response APDU into its data and status word; `None` if it is shorter than
/// two bytes.
pub fn split_response(resp: &[u8]) -> Option<(&[u8], u16)> {
    let (data, sw) = resp.split_last_chunk::<2>()?;
    Some((data, u16::from_be_bytes(*sw)))
}

/// Why a command APDU could not be parsed. Every variant is answered with
/// [`sw::WRONG_LENGTH`] (see [`ApduError::sw`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApduError {
    /// Fewer than the four header bytes.
    TooShort,
    /// The body after the header matches none of the cases of §5.1: Lc disagrees with
    /// the data length, an Le field has the wrong size, or an extended Lc is zero.
    LengthMismatch,
}

impl ApduError {
    /// The status word for this error: [`sw::WRONG_LENGTH`].
    pub const fn sw(self) -> u16 {
        sw::WRONG_LENGTH
    }
}

impl From<ApduError> for u16 {
    fn from(err: ApduError) -> u16 {
        err.sw()
    }
}

impl fmt::Display for ApduError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::TooShort => "command APDU shorter than its 4-byte header",
            Self::LengthMismatch => "command APDU length fields do not match its body",
        };
        f.write_str(text)
    }
}

impl std::error::Error for ApduError {}

/// Overwrite every byte of `buf`'s allocation with zeros, the spare capacity beyond its
/// length included, leaving `buf` as `capacity` zero bytes (module documentation: best
/// effort without `unsafe` volatile writes; `black_box` keeps the stores from being
/// proven dead).
fn zero_allocation(buf: &mut Vec<u8>) {
    let capacity = buf.capacity();
    buf.fill(0);
    buf.resize(capacity, 0);
    std::hint::black_box(buf.as_mut_slice());
}

/// [`zero_allocation`], then leave the buffer empty with its capacity.
fn wipe_vec(buf: &mut Vec<u8>) {
    zero_allocation(buf);
    buf.clear();
}

/// Append `more` to a buffer holding secret bytes without leaving a copy behind: when
/// the allocation is too small, the data moves to a larger one and the old one is wiped
/// before it is freed (`Vec` growth would free it unwiped).
fn extend_wiping(buf: &mut Vec<u8>, more: &[u8]) {
    let needed = buf.len().saturating_add(more.len());
    if needed > buf.capacity() {
        let mut grown = Vec::with_capacity(needed.max(buf.capacity().saturating_mul(2)));
        grown.extend_from_slice(buf);
        wipe_vec(buf);
        *buf = grown;
    }
    buf.extend_from_slice(more);
}

/// A command APDU (ISO/IEC 7816-4 §5.1).
///
/// `le` holds the Le field as written: `None` when absent (cases 1 and 3), otherwise
/// its value. `Some(0)` is the encoding of the maximum, meaning Ne = 256 for a short
/// command and Ne = 65 536 for an extended one; [`Command::expected_len`] resolves it.
/// `extended` records whether the command used the extended length form.
///
/// The data field is wiped when the command is dropped, and its `Debug` output shows
/// the data length only (module documentation).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Command {
    /// Class byte (§5.1.1).
    pub cla: u8,
    /// Instruction byte (§5.1.2).
    pub ins: u8,
    /// First parameter byte.
    pub p1: u8,
    /// Second parameter byte.
    pub p2: u8,
    /// Command data field (Nc = `data.len()`).
    pub data: Vec<u8>,
    /// Le as written: `None` if absent, `Some(0)` for the maximum (256 or 65 536).
    pub le: Option<u32>,
    /// Whether the extended length form was used.
    pub extended: bool,
}

impl Drop for Command {
    fn drop(&mut self) {
        wipe_vec(&mut self.data);
    }
}

impl fmt::Debug for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Command")
            .field("cla", &format_args!("{:#04x}", self.cla))
            .field("ins", &format_args!("{:#04x}", self.ins))
            .field("p1", &format_args!("{:#04x}", self.p1))
            .field("p2", &format_args!("{:#04x}", self.p2))
            .field("data_len", &self.data.len())
            .field("le", &self.le)
            .field("extended", &self.extended)
            .finish()
    }
}

impl Command {
    /// A case 1 command with the given header.
    pub fn new(cla: u8, ins: u8, p1: u8, p2: u8) -> Self {
        Self {
            cla,
            ins,
            p1,
            p2,
            data: Vec::new(),
            le: None,
            extended: false,
        }
    }

    /// Set the command data field (the previous data is wiped).
    pub fn with_data(mut self, data: impl Into<Vec<u8>>) -> Self {
        wipe_vec(&mut self.data);
        self.data = data.into();
        self
    }

    /// Take the data field out of the command without copying it. Because `Command`
    /// wipes its data in `Drop`, the field can no longer be moved out
    /// (`command.data`, error E0509); this is the replacement. The returned bytes
    /// belong to the caller, which wipes them if they are secret.
    pub fn into_data(mut self) -> Vec<u8> {
        std::mem::take(&mut self.data)
    }

    /// Set the Le field (`0` means the maximum; see [`Command`]).
    pub fn with_le(mut self, le: u32) -> Self {
        self.le = Some(le);
        self
    }

    /// Parse a command APDU (ISO/IEC 7816-4 §5.1).
    ///
    /// With `L` the number of bytes after the four header bytes:
    ///
    /// - `L = 0`: case 1.
    /// - `L = 1`: case 2S; the byte is Le (`00` means 256). A five-byte APDU is never
    ///   case 3, since a short Lc of zero does not exist.
    /// - First body byte `B1 != 00`: B1 is a short Lc. `L = 1 + Lc` is case 3S and
    ///   `L = 2 + Lc` is case 4S with a one-byte Le.
    /// - `B1 = 00` and `L = 3`: case 2E with a two-byte Le (`00 00` means 65 536).
    /// - `B1 = 00` and `L > 3`: the next two bytes are an extended Lc, which must not be
    ///   zero. `L = 3 + Lc` is case 3E and `L = 5 + Lc` is case 4E with a two-byte Le.
    ///
    /// Every other length is [`ApduError::LengthMismatch`].
    pub fn parse(apdu: &[u8]) -> Result<Self, ApduError> {
        let (header, body) = apdu.split_first_chunk::<4>().ok_or(ApduError::TooShort)?;
        let [cla, ins, p1, p2] = *header;
        let mut cmd = Self::new(cla, ins, p1, p2);
        match body {
            // Case 1.
            [] => {}
            // Case 2S.
            [le] => cmd.le = Some(u32::from(*le)),
            // Extended forms start with a 00 byte.
            [0, rest @ ..] => {
                cmd.extended = true;
                let (data, le) = parse_extended_body(rest)?;
                cmd.data = data.to_vec();
                cmd.le = le;
            }
            // Cases 3S and 4S.
            [lc, rest @ ..] => {
                let (data, le) = split_data_and_le(rest, usize::from(*lc), 1)?;
                cmd.data = data.to_vec();
                cmd.le = le;
            }
        }
        Ok(cmd)
    }

    /// Ne, the maximum number of response data bytes expected: `None` without an Le
    /// field, 256 or 65 536 for `Le = 0`, otherwise the Le value.
    pub fn expected_len(&self) -> Option<usize> {
        let le = self.le?;
        let ne = match (le, self.extended) {
            (0, false) => SHORT_MAX_NE,
            (0, true) => EXTENDED_MAX_NE,
            (n, _) => n,
        };
        usize::try_from(ne).ok()
    }

    /// Whether CLA bit b5 (`0x10`) is set: more commands of this chain follow
    /// (§5.1.1.1).
    pub fn is_chained(&self) -> bool {
        self.cla & CHAIN_BIT != 0
    }

    /// Whether the CLA indicates secure messaging.
    ///
    /// Only the first interindustry class (CLA `0x00..=0x1F`) is interpreted; there
    /// bits b4-b3 (`0x0C`) are the secure messaging indication (§5.1.1). For other
    /// classes (further interindustry `0x40..=0x7F`, proprietary `0x80..=0xFE`, such
    /// as GlobalPlatform's `0x84`) this returns `false` and the applet decides.
    pub fn secure_messaging(&self) -> bool {
        self.sm_indication() != 0
    }

    /// The two-bit secure messaging indication of a first-interindustry CLA (§5.1.1):
    /// `0` none, `1` proprietary format, `2` §6 format without header authentication,
    /// `3` §6 format with the header authenticated. `0` for every other class.
    pub fn sm_indication(&self) -> u8 {
        if self.cla & 0xE0 == 0 {
            (self.cla & 0x0C) >> 2
        } else {
            0
        }
    }

    /// Encode this command as APDU bytes (the inverse of [`Command::parse`]).
    ///
    /// The extended form is used when `extended` is set, when the data is longer than
    /// 255 bytes, or when Ne ([`Command::expected_len`]) exceeds 256. Ne is preserved:
    /// it is written as zero bytes when it is the form's maximum (256 short, 65 536
    /// extended) or more, so a short `le = Some(0)` (Ne = 256) that must go out in the
    /// extended form becomes `01 00`. Data beyond 65 535 bytes cannot be expressed;
    /// only the first 65 535 bytes are written.
    pub fn to_bytes(&self) -> Vec<u8> {
        let data = self.data.get(..EXTENDED_MAX_NC).unwrap_or(&self.data);
        let ne = self.expected_len();
        let extended =
            self.extended || data.len() > 0xFF || ne.is_some_and(|n| n > SHORT_MAX_NE as usize);
        let mut out = Vec::with_capacity(4 + 3 + data.len() + 2);
        out.extend_from_slice(&[self.cla, self.ins, self.p1, self.p2]);
        if extended {
            if !data.is_empty() || ne.is_some() {
                out.push(0x00);
            }
            if !data.is_empty() {
                out.extend_from_slice(&be16(data.len()));
            }
            out.extend_from_slice(data);
            if let Some(n) = ne {
                let n = if n >= EXTENDED_MAX_NE as usize { 0 } else { n };
                out.extend_from_slice(&be16(n));
            }
        } else {
            if !data.is_empty() {
                out.push(data.len() as u8);
            }
            out.extend_from_slice(data);
            if let Some(n) = ne {
                out.push(if n >= SHORT_MAX_NE as usize {
                    0
                } else {
                    n as u8
                });
            }
        }
        out
    }
}

/// Parse the body of an extended command after its leading `00` byte.
fn parse_extended_body(rest: &[u8]) -> Result<(&[u8], Option<u32>), ApduError> {
    match rest {
        // Case 2E.
        [hi, lo] => Ok((&[], Some(u32::from(u16::from_be_bytes([*hi, *lo]))))),
        // Cases 3E and 4E; Lc = 0 is not allowed.
        [hi, lo, body @ ..] => match usize::from(u16::from_be_bytes([*hi, *lo])) {
            0 => Err(ApduError::LengthMismatch),
            lc => split_data_and_le(body, lc, 2),
        },
        _ => Err(ApduError::LengthMismatch),
    }
}

/// Split `body` into `lc` data bytes followed by an optional Le field of `le_size`
/// bytes (big-endian).
fn split_data_and_le(
    body: &[u8],
    lc: usize,
    le_size: usize,
) -> Result<(&[u8], Option<u32>), ApduError> {
    let (data, le_field) = body.split_at_checked(lc).ok_or(ApduError::LengthMismatch)?;
    match le_field.len() {
        0 => Ok((data, None)),
        n if n == le_size => {
            let le = le_field
                .iter()
                .fold(0u32, |acc, &b| (acc << 8) | u32::from(b));
            Ok((data, Some(le)))
        }
        _ => Err(ApduError::LengthMismatch),
    }
}

/// The low 16 bits of `n`, big-endian.
fn be16(n: usize) -> [u8; 2] {
    [(n >> 8) as u8, n as u8]
}

/// Why [`CommandChain::push`] refused a command. The chain is discarded in both cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainError {
    /// CLA (apart from the chaining bit), INS, P1 or P2 differ from the commands
    /// already in the chain.
    HeaderChanged,
    /// The chained data would exceed the configured limit.
    TooLong,
}

impl ChainError {
    /// A default status word: [`sw::LAST_COMMAND_EXPECTED`] for a changed header and
    /// [`sw::WRONG_LENGTH`] for too much data. Applets may answer differently.
    pub const fn sw(self) -> u16 {
        match self {
            Self::HeaderChanged => sw::LAST_COMMAND_EXPECTED,
            Self::TooLong => sw::WRONG_LENGTH,
        }
    }
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::HeaderChanged => "command header changed in the middle of a chain",
            Self::TooLong => "chained command data exceeds the limit",
        };
        f.write_str(text)
    }
}

impl std::error::Error for ChainError {}

/// Reassembles command chaining (ISO/IEC 7816-4 §5.1.1.1).
///
/// Commands with CLA bit b5 (`0x10`) set are buffered; the next command with the bit
/// clear ends the chain and yields one [`Command`] holding the concatenated data, the
/// final command's CLA, Le and length form. The Le field and length form of the
/// non-final commands are ignored: a host may send `Le` on every command of a chain,
/// but only the response to the last one carries the command's response data. A command that arrives with no chain
/// in progress and the bit clear is returned unchanged (the limit applies only to
/// chained data).
///
/// Buffered data is wiped when the chain is cleared, discarded or dropped; its `Debug`
/// output shows the buffered length only (module documentation).
#[derive(Clone, PartialEq, Eq)]
pub struct CommandChain {
    max: usize,
    pending: Option<Pending>,
}

impl fmt::Debug for CommandChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommandChain")
            .field("max", &self.max)
            .field("active", &self.is_active())
            .field("buffered_len", &self.buffered_len())
            .finish()
    }
}

/// The header and data of an unfinished chain.
#[derive(Clone, PartialEq, Eq)]
struct Pending {
    /// CLA with the chaining bit cleared.
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: Vec<u8>,
}

impl Drop for Pending {
    fn drop(&mut self) {
        wipe_vec(&mut self.data);
    }
}

impl CommandChain {
    /// An empty chain accepting at most `max` bytes of chained data in total.
    pub fn new(max: usize) -> Self {
        Self { max, pending: None }
    }

    /// The configured limit on the total chained data.
    pub fn max_len(&self) -> usize {
        self.max
    }

    /// Whether a chain is in progress (its last command has not arrived).
    pub fn is_active(&self) -> bool {
        self.pending.is_some()
    }

    /// The number of data bytes buffered so far.
    pub fn buffered_len(&self) -> usize {
        self.pending.as_ref().map_or(0, |p| p.data.len())
    }

    /// Discard any chain in progress.
    pub fn clear(&mut self) {
        self.pending = None;
    }

    /// Feed one command.
    ///
    /// Returns `Ok(None)` while the chain continues and `Ok(Some(command))` when a
    /// complete command is ready. On error the chain is discarded, so the next command
    /// starts afresh.
    pub fn push(&mut self, mut cmd: Command) -> Result<Option<Command>, ChainError> {
        let Some(mut pending) = self.pending.take() else {
            if !cmd.is_chained() {
                return Ok(Some(cmd));
            }
            if cmd.data.len() > self.max {
                return Err(ChainError::TooLong);
            }
            self.pending = Some(Pending {
                cla: cmd.cla & !CHAIN_BIT,
                ins: cmd.ins,
                p1: cmd.p1,
                p2: cmd.p2,
                data: std::mem::take(&mut cmd.data),
            });
            return Ok(None);
        };
        let same_header = pending.cla == cmd.cla & !CHAIN_BIT
            && pending.ins == cmd.ins
            && pending.p1 == cmd.p1
            && pending.p2 == cmd.p2;
        if !same_header {
            return Err(ChainError::HeaderChanged);
        }
        if pending.data.len().saturating_add(cmd.data.len()) > self.max {
            return Err(ChainError::TooLong);
        }
        extend_wiping(&mut pending.data, &cmd.data);
        if cmd.is_chained() {
            self.pending = Some(pending);
            return Ok(None);
        }
        Ok(Some(Command {
            data: std::mem::take(&mut pending.data),
            ..cmd
        }))
    }
}

/// Response data waiting to be fetched in pieces (ISO/IEC 7816-4 §5.1.3, `61xx`).
///
/// An applet hands a full response to [`ResponseQueue::start`]. If it fits in `max`
/// bytes the whole response goes out with its final status word. Otherwise the first
/// `max` bytes go out with `61xx` (SW2 = bytes left, `00` for 256 or more), and each
/// GET RESPONSE (§7.6.1) or applet-specific continuation command calls
/// [`ResponseQueue::next`] for the following piece; the last piece carries the final
/// status word.
///
/// The held data is wiped when it is replaced, cleared, served to the end or dropped;
/// `Debug` shows the remaining length only (module documentation).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ResponseQueue {
    data: Vec<u8>,
    offset: usize,
    sw: u16,
}

impl Drop for ResponseQueue {
    fn drop(&mut self) {
        wipe_vec(&mut self.data);
    }
}

impl fmt::Debug for ResponseQueue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseQueue")
            .field("remaining", &self.remaining())
            .field("sw", &format_args!("{:#06x}", self.sw))
            .finish()
    }
}

impl ResponseQueue {
    /// An empty queue.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace any pending data with `data` and return the first response APDU, at
    /// most `max` data bytes long (`max` of 0 is treated as 1).
    pub fn start(&mut self, data: Vec<u8>, sw: u16, max: usize) -> Vec<u8> {
        wipe_vec(&mut self.data);
        self.data = data;
        self.offset = 0;
        self.sw = sw;
        self.serve(max)
    }

    /// The next response APDU, at most `max` data bytes long, or `None` when nothing
    /// is pending (the applet then answers with its own error status word).
    pub fn next(&mut self, max: usize) -> Option<Vec<u8>> {
        self.is_pending().then(|| self.serve(max))
    }

    /// Whether data is waiting to be fetched.
    pub fn is_pending(&self) -> bool {
        self.remaining() > 0
    }

    /// The number of data bytes still waiting.
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.offset)
    }

    /// Drop any pending data, wiping it first.
    pub fn clear(&mut self) {
        wipe_vec(&mut self.data);
        self.data = Vec::new();
        self.offset = 0;
    }

    /// Emit the next piece and advance; the last piece clears the queue.
    fn serve(&mut self, max: usize) -> Vec<u8> {
        let start = self.offset.min(self.data.len());
        let end = start.saturating_add(max.max(1)).min(self.data.len());
        let chunk = self.data.get(start..end).unwrap_or(&[]);
        let left = self.data.len() - end;
        if left == 0 {
            let out = response(chunk, self.sw);
            self.clear();
            out
        } else {
            let out = response(chunk, sw::more_data(left));
            self.offset = end;
            out
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Decode a hex string (test helper).
    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn bytes(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 7 + 3) as u8).collect()
    }

    fn apdu(header: &str, tail: &[&[u8]]) -> Vec<u8> {
        let mut out = hex(header);
        for part in tail {
            out.extend_from_slice(part);
        }
        out
    }

    // --- Command parsing: the cases of ISO/IEC 7816-4 §5.1 ---

    #[test]
    fn case_1() {
        // §5.1 case 1: header only (e.g. OpenPGP Card 3.4 ACTIVATE FILE 00 44 00 00).
        let cmd = Command::parse(&hex("00440000")).unwrap();
        assert_eq!(cmd, Command::new(0x00, 0x44, 0x00, 0x00));
        assert_eq!(cmd.le, None);
        assert_eq!(cmd.expected_len(), None);
        assert!(!cmd.extended);
    }

    #[test]
    fn case_2s_from_device_trace() {
        // reference/physical-key/openpgp-reference-observation.json, commands:
        // "00ca5f5200" (GET DATA 5F52) and "00f1000000"; §5.1: short Le 00 = 256.
        let cmd = Command::parse(&hex("00ca5f5200")).unwrap();
        assert_eq!((cmd.cla, cmd.ins, cmd.p1, cmd.p2), (0x00, 0xCA, 0x5F, 0x52));
        assert!(cmd.data.is_empty());
        assert_eq!(cmd.le, Some(0));
        assert_eq!(cmd.expected_len(), Some(256));
        assert!(!cmd.extended);

        let cmd = Command::parse(&hex("00f1000000")).unwrap();
        assert_eq!(cmd.ins, 0xF1);
        assert_eq!(cmd.le, Some(0));
    }

    #[test]
    fn case_2s_le_values() {
        // §5.1: short Le 01..FF = Ne 1..255.
        let cmd = Command::parse(&hex("00CA006E01")).unwrap();
        assert_eq!(cmd.le, Some(1));
        assert_eq!(cmd.expected_len(), Some(1));
        let cmd = Command::parse(&hex("00CA006EFF")).unwrap();
        assert_eq!(cmd.le, Some(255));
        assert_eq!(cmd.expected_len(), Some(255));
    }

    #[test]
    fn five_byte_apdu_with_zero_is_case_2s_not_3s() {
        // §5.1: Lc = 0 does not exist in the short form; header + 00 is case 2S.
        let cmd = Command::parse(&hex("00DB3FFF00")).unwrap();
        assert!(cmd.data.is_empty());
        assert_eq!(cmd.le, Some(0));
        assert!(!cmd.extended);
    }

    #[test]
    fn case_3s() {
        // §5.1 case 3S; NIST SP 800-73-4 Part 2 VERIFY with an 8-byte PIN block.
        let cmd = Command::parse(&hex("00200080 08 313233343536FFFF")).unwrap();
        assert_eq!(cmd.ins, 0x20);
        assert_eq!(cmd.data, hex("313233343536FFFF"));
        assert_eq!(cmd.le, None);
        assert!(!cmd.extended);
    }

    #[test]
    fn case_4s_from_device_trace() {
        // reference/.../openpgp-reference-observation.json, commands[0]
        // "00a4040006d2760001240100": SELECT the OpenPGP AID, Lc 06, Le 00.
        let cmd = Command::parse(&hex("00a4040006d2760001240100")).unwrap();
        assert_eq!((cmd.ins, cmd.p1, cmd.p2), (0xA4, 0x04, 0x00));
        assert_eq!(cmd.data, hex("d27600012401"));
        assert_eq!(cmd.le, Some(0));
        assert_eq!(cmd.expected_len(), Some(256));

        // reference/.../security-domain-reference-observation.json, commands[2]
        // "00a4040008a00000015100000000": SELECT the ISD AID.
        let cmd = Command::parse(&hex("00a4040008a00000015100000000")).unwrap();
        assert_eq!(cmd.data, hex("a000000151000000"));
        assert_eq!(cmd.le, Some(0));
        assert!(!cmd.extended);
    }

    #[test]
    fn case_4s_minimum_lc() {
        // §5.1 case 4S with Lc = 1 and Le = 01.
        let cmd = Command::parse(&hex("00870000 01 AA 01")).unwrap();
        assert_eq!(cmd.data, [0xAA]);
        assert_eq!(cmd.le, Some(1));
    }

    #[test]
    fn short_lc_255_boundary() {
        // §5.1: the largest short Nc is 255 (Lc = FF).
        let data = bytes(255);
        let cmd = Command::parse(&apdu("00DB3FFF FF", &[&data])).unwrap();
        assert_eq!(cmd.data, data);
        assert_eq!(cmd.le, None);
        assert!(!cmd.extended);

        let cmd = Command::parse(&apdu("00DB3FFF FF", &[&data, &[0x00]])).unwrap();
        assert_eq!(cmd.data, data);
        assert_eq!(cmd.le, Some(0));
        assert!(!cmd.extended);
    }

    #[test]
    fn nc_256_needs_extended_form() {
        // §5.1: Nc = 256 cannot be short; extended Lc = 00 01 00.
        let data = bytes(256);
        let cmd = Command::parse(&apdu("00DB3FFF 000100", &[&data])).unwrap();
        assert_eq!(cmd.data, data);
        assert_eq!(cmd.le, None);
        assert!(cmd.extended);
        assert_eq!(
            Command::new(0, 0xDB, 0x3F, 0xFF)
                .with_data(data.clone())
                .to_bytes(),
            apdu("00DB3FFF 000100", &[&data])
        );
        // There is no short Lc for 256: a leading 00 starts the extended form, so
        // header + 00 + 256 data bytes reads 03 0A as Lc (778) and does not fit.
        assert_eq!(
            Command::parse(&apdu("00DB3FFF 00", &[&data])),
            Err(ApduError::LengthMismatch)
        );
    }

    #[test]
    fn case_2e() {
        // §5.1 case 2E: 00 then a two-byte Le; 00 00 = 65 536.
        let cmd = Command::parse(&hex("00CA0000 000000")).unwrap();
        assert!(cmd.extended);
        assert!(cmd.data.is_empty());
        assert_eq!(cmd.le, Some(0));
        assert_eq!(cmd.expected_len(), Some(65_536));

        let cmd = Command::parse(&hex("00CA0000 000100")).unwrap();
        assert_eq!(cmd.le, Some(256));
        assert_eq!(cmd.expected_len(), Some(256));

        let cmd = Command::parse(&hex("00CA0000 00FFFF")).unwrap();
        assert_eq!(cmd.le, Some(65_535));

        let cmd = Command::parse(&hex("00CA0000 000001")).unwrap();
        assert_eq!(cmd.le, Some(1));
    }

    #[test]
    fn case_3e() {
        // §5.1 case 3E: extended Lc 00 00 01 .. 00 FF FF; a small Nc may still use it.
        let cmd = Command::parse(&hex("00DB3FFF 000001 AA")).unwrap();
        assert!(cmd.extended);
        assert_eq!(cmd.data, [0xAA]);
        assert_eq!(cmd.le, None);

        let data = bytes(0xFFFF);
        let cmd = Command::parse(&apdu("00DB3FFF 00FFFF", &[&data])).unwrap();
        assert_eq!(cmd.data.len(), 0xFFFF);
        assert_eq!(cmd.data, data);
        assert_eq!(cmd.le, None);
    }

    #[test]
    fn case_4e() {
        // §5.1 case 4E: extended Lc, data, then a two-byte Le (no second 00 marker).
        let cmd = Command::parse(&hex("00870000 000003 010203 0100")).unwrap();
        assert!(cmd.extended);
        assert_eq!(cmd.data, [1, 2, 3]);
        assert_eq!(cmd.le, Some(256));

        let data = bytes(256);
        let cmd = Command::parse(&apdu("00870000 000100", &[&data, &[0, 0]])).unwrap();
        assert_eq!(cmd.data, data);
        assert_eq!(cmd.le, Some(0));
        assert_eq!(cmd.expected_len(), Some(65_536));

        let data = bytes(0xFFFF);
        let cmd = Command::parse(&apdu("00870000 00FFFF", &[&data, &[0xFF, 0xFF]])).unwrap();
        assert_eq!(cmd.data.len(), 0xFFFF);
        assert_eq!(cmd.le, Some(0xFFFF));
    }

    #[test]
    fn too_short() {
        // §5.1: the header is four bytes.
        for len in 0..4 {
            assert_eq!(Command::parse(&[0u8; 4][..len]), Err(ApduError::TooShort));
        }
    }

    #[test]
    fn short_length_mismatches() {
        // §5.1: only L = 1 + Lc (3S) or L = 2 + Lc (4S) are valid for a short Lc.
        let bad = [
            "00DB3FFF 05 010203",    // Lc 5, 3 data bytes
            "00DB3FFF 02 0102 0000", // two trailing bytes after the data
            "00DB3FFF 02 AA",        // Lc 2, one data byte
            "00DB3FFF 01 AA BB CC",  // Lc 1, three bytes follow
            "00DB3FFF FF 00",        // Lc 255, one byte
        ];
        for case in bad {
            assert_eq!(
                Command::parse(&hex(case)),
                Err(ApduError::LengthMismatch),
                "{case}"
            );
        }
    }

    #[test]
    fn extended_length_mismatches() {
        // §5.1: an extended body is 00 + Le(2), or 00 + Lc(2, non-zero) + data [+ Le(2)].
        let bad = [
            "00CA0000 00 01",            // 00 marker then a single byte
            "00DB3FFF 000000 AA",        // extended Lc = 0 with data
            "00DB3FFF 000000 0000",      // extended Lc = 0, two bytes
            "00DB3FFF 000005 01020304",  // Lc 5, four data bytes
            "00DB3FFF 000001 AA BB",     // 4E with a one-byte Le
            "00DB3FFF 000001 AA BBCCDD", // 4E with a three-byte Le
            "00DB3FFF 000002 AABB 00",   // 4E with a one-byte Le
        ];
        for case in bad {
            assert_eq!(
                Command::parse(&hex(case)),
                Err(ApduError::LengthMismatch),
                "{case}"
            );
        }
        // Lc FF followed by 257 bytes is neither 3S (255) nor 4S (255 + Le).
        assert_eq!(
            Command::parse(&apdu("00DB3FFF FF", &[&bytes(257)])),
            Err(ApduError::LengthMismatch)
        );
    }

    #[test]
    fn errors_map_to_wrong_length() {
        // docs/CONTRACTS.md: ApduError maps to sw::WRONG_LENGTH (6700).
        assert_eq!(ApduError::TooShort.sw(), 0x6700);
        assert_eq!(u16::from(ApduError::LengthMismatch), 0x6700);
        assert!(!ApduError::TooShort.to_string().is_empty());
    }

    // --- CLA byte (ISO/IEC 7816-4 §5.1.1) ---

    #[test]
    fn chaining_bit() {
        // §5.1.1: b5 set = not the last command of a chain.
        let chained = |cla| Command::new(cla, 0xDB, 0x3F, 0xFF).is_chained();
        assert!(!chained(0x00));
        assert!(chained(0x10));
        assert!(chained(0x1C));
        assert!(chained(0x90)); // GlobalPlatform proprietary class with b5
        assert!(!chained(0x84));
    }

    #[test]
    fn secure_messaging_indication() {
        // §5.1.1 first interindustry class: b4-b3 = SM indication.
        let sm = |cla| {
            let cmd = Command::new(cla, 0, 0, 0);
            (cmd.secure_messaging(), cmd.sm_indication())
        };
        assert_eq!(sm(0x00), (false, 0));
        assert_eq!(sm(0x04), (true, 1));
        assert_eq!(sm(0x08), (true, 2));
        assert_eq!(sm(0x0C), (true, 3));
        assert_eq!(sm(0x1C), (true, 3)); // chained, header authenticated
        assert_eq!(sm(0x03), (false, 0)); // logical channel 3, no SM
        // Classes outside 0x00..=0x1F are not interpreted.
        assert_eq!(sm(0x84), (false, 0));
        assert_eq!(sm(0x6C), (false, 0));
        assert_eq!(sm(0x2C), (false, 0));
    }

    // --- Status words (ISO/IEC 7816-4 §5.1.3) ---

    #[test]
    fn status_word_constants() {
        // docs/CONTRACTS.md values, from ISO/IEC 7816-4 §5.1.3.
        assert_eq!(sw::OK, 0x9000);
        assert_eq!(sw::WRONG_LENGTH, 0x6700);
        assert_eq!(sw::SECURITY_STATUS, 0x6982);
        assert_eq!(sw::AUTH_BLOCKED, 0x6983);
        assert_eq!(sw::DATA_INVALID, 0x6984);
        assert_eq!(sw::CONDITIONS, 0x6985);
        assert_eq!(sw::INCORRECT_DATA, 0x6A80);
        assert_eq!(sw::FUNC_NOT_SUPPORTED, 0x6A81);
        assert_eq!(sw::FILE_NOT_FOUND, 0x6A82);
        assert_eq!(sw::NO_SPACE, 0x6A84);
        assert_eq!(sw::INCORRECT_P1P2, 0x6A86);
        assert_eq!(sw::REF_NOT_FOUND, 0x6A88);
        assert_eq!(sw::INS_NOT_SUPPORTED, 0x6D00);
        assert_eq!(sw::CLA_NOT_SUPPORTED, 0x6E00);
        assert_eq!(sw::UNKNOWN, 0x6F00);
        assert_eq!(sw::MEMORY_FAILURE, 0x6581);
        assert_eq!(sw::LAST_COMMAND_EXPECTED, 0x6883);
    }

    #[test]
    fn status_word_helpers() {
        // §5.1.3: 61xx (xx = bytes available, 00 = 256 or more), 63Cx, 6Cxx.
        assert_eq!(sw::more_data(1), 0x6101);
        assert_eq!(sw::more_data(0x58), 0x6158);
        assert_eq!(sw::more_data(255), 0x61FF);
        assert_eq!(sw::more_data(256), 0x6100);
        assert_eq!(sw::more_data(100_000), 0x6100);
        assert_eq!(sw::retries(0), 0x63C0);
        assert_eq!(sw::retries(3), 0x63C3);
        assert_eq!(sw::retries(15), 0x63CF);
        assert_eq!(sw::retries(200), 0x63CF);
        assert_eq!(sw::wrong_le(8), 0x6C08);
        assert_eq!(sw::wrong_le(256), 0x6C00);
    }

    #[test]
    fn response_and_status() {
        // docs/CONTRACTS.md: a response is data || SW1 SW2.
        assert_eq!(response(&[1, 2, 3], sw::OK), [1, 2, 3, 0x90, 0x00]);
        assert_eq!(response(&[], sw::FILE_NOT_FOUND), [0x6A, 0x82]);
        assert_eq!(status(sw::retries(2)), [0x63, 0xC2]);
        assert_eq!(split_response(&[1, 0x90, 0x00]), Some((&[1u8][..], 0x9000)));
        assert_eq!(split_response(&[0x6A, 0x82]), Some((&[][..], 0x6A82)));
        assert_eq!(split_response(&[0x90]), None);
    }

    // --- Encoding ---

    #[test]
    fn to_bytes_short_cases() {
        // §5.1 short encodings.
        let base = Command::new(0x00, 0xCA, 0x5F, 0x52);
        assert_eq!(base.to_bytes(), hex("00CA5F52"));
        assert_eq!(base.clone().with_le(0).to_bytes(), hex("00CA5F5200"));
        assert_eq!(base.clone().with_le(256).to_bytes(), hex("00CA5F5200"));
        assert_eq!(base.clone().with_le(255).to_bytes(), hex("00CA5F52FF"));
        let sel = Command::new(0x00, 0xA4, 0x04, 0x00)
            .with_data(hex("d27600012401"))
            .with_le(0);
        assert_eq!(sel.to_bytes(), hex("00a4040006d2760001240100"));
        let data_only = Command::new(0x00, 0x20, 0x00, 0x80).with_data(vec![0x31; 8]);
        assert_eq!(data_only.to_bytes(), apdu("00200080 08", &[&[0x31; 8]]));
    }

    #[test]
    fn to_bytes_extended_cases() {
        // §5.1 extended encodings.
        let mut cmd = Command::new(0x00, 0xCA, 0x00, 0x00).with_le(0);
        cmd.extended = true;
        assert_eq!(cmd.to_bytes(), hex("00CA0000 000000"));
        // Le 257 forces the extended form.
        assert_eq!(
            Command::new(0, 0xCA, 0, 0).with_le(257).to_bytes(),
            hex("00CA0000 000101")
        );
        assert_eq!(
            Command::new(0, 0xCA, 0, 0).with_le(65_536).to_bytes(),
            hex("00CA0000 000000")
        );
        // 256 data bytes force the extended form; a short Le 0 (Ne = 256) is kept as
        // Ne = 256, written 01 00.
        let cmd = Command::new(0, 0x87, 0, 0).with_data(bytes(256)).with_le(0);
        assert_eq!(
            cmd.to_bytes(),
            apdu("00870000 000100", &[&bytes(256), &[1, 0]])
        );
        let mut cmd = cmd;
        cmd.extended = true;
        assert_eq!(
            cmd.to_bytes(),
            apdu("00870000 000100", &[&bytes(256), &[0, 0]])
        );
        let mut cmd = Command::new(0, 0x87, 0, 0)
            .with_data(vec![1, 2, 3])
            .with_le(256);
        cmd.extended = true;
        assert_eq!(cmd.to_bytes(), hex("00870000 000003 010203 0100"));
    }

    #[test]
    fn parse_to_bytes_round_trip_at_boundaries() {
        // §5.1 boundaries: Nc 0/1/255/256/65535, Ne absent/1/255/256/257/65535/65536.
        for nc in [0usize, 1, 255, 256, 0xFFFF] {
            for le in [
                None,
                Some(1u32),
                Some(255),
                Some(0),
                Some(257),
                Some(0xFFFF),
            ] {
                for extended in [false, true] {
                    let cmd = Command {
                        cla: 0x00,
                        ins: 0xDB,
                        p1: 0x3F,
                        p2: 0xFF,
                        data: bytes(nc),
                        le,
                        extended,
                    };
                    let wire = cmd.to_bytes();
                    let back = Command::parse(&wire).unwrap();
                    let ctx = format!("nc {nc} le {le:?} ext {extended}");
                    assert_eq!(back.data, cmd.data, "{ctx}");
                    assert_eq!(back.expected_len(), cmd.expected_len(), "{ctx}");
                    let wants_ext = extended && (nc > 0 || le.is_some())
                        || nc > 255
                        || le.is_some_and(|n| n > 256);
                    assert_eq!(back.extended, wants_ext, "{ctx}");
                    if back.extended == extended {
                        assert_eq!(back.le, cmd.le, "{ctx}");
                    }
                    assert_eq!(back.to_bytes(), wire);
                }
            }
        }
    }

    // --- Command chaining (ISO/IEC 7816-4 §5.1.1.1) ---

    fn put(cla: u8, data: &[u8]) -> Command {
        // NIST SP 800-73-4 Part 2 PUT DATA (INS DB, P1-P2 3FFF), chained with CLA 10.
        Command::new(cla, 0xDB, 0x3F, 0xFF).with_data(data.to_vec())
    }

    #[test]
    fn unchained_command_passes_through() {
        // §5.1.1.1: a command with CLA b5 clear and no chain in progress stands alone.
        let mut chain = CommandChain::new(16);
        let cmd = put(0x00, &[1, 2, 3]).with_le(0);
        assert_eq!(chain.push(cmd.clone()), Ok(Some(cmd)));
        assert!(!chain.is_active());
        // The limit applies only to chained data.
        let big = put(0x00, &bytes(100));
        assert_eq!(chain.push(big.clone()), Ok(Some(big)));
    }

    #[test]
    fn chain_assembles_data() {
        // §5.1.1.1: CLA b5 set on every command except the last.
        let mut chain = CommandChain::new(3072);
        assert_eq!(chain.push(put(0x10, &[1, 2])), Ok(None));
        assert!(chain.is_active());
        assert_eq!(chain.buffered_len(), 2);
        assert_eq!(chain.push(put(0x10, &[])), Ok(None));
        assert_eq!(chain.push(put(0x10, &[3])), Ok(None));
        let done = chain.push(put(0x00, &[4, 5]).with_le(0)).unwrap().unwrap();
        assert_eq!(done.cla, 0x00);
        assert_eq!((done.ins, done.p1, done.p2), (0xDB, 0x3F, 0xFF));
        assert_eq!(done.data, [1, 2, 3, 4, 5]);
        assert_eq!(done.le, Some(0));
        assert!(!done.extended);
        assert!(!chain.is_active());
        assert_eq!(chain.buffered_len(), 0);
        assert_eq!(chain.max_len(), 3072);
    }

    #[test]
    fn chain_keeps_final_length_form_and_class() {
        // GlobalPlatform proprietary class 80 with b5 (90) for chained commands.
        let mut chain = CommandChain::new(1024);
        let first = Command::new(0x90, 0xE2, 0x90, 0x00).with_data(bytes(300));
        assert_eq!(chain.push(first), Ok(None));
        let mut last = Command::new(0x80, 0xE2, 0x90, 0x00)
            .with_data(vec![9])
            .with_le(0);
        last.extended = true;
        let done = chain.push(last).unwrap().unwrap();
        assert_eq!(done.cla, 0x80);
        assert_eq!(done.data.len(), 301);
        assert!(done.extended);
        assert_eq!(done.expected_len(), Some(65_536));
    }

    #[test]
    fn chain_header_change_is_an_error() {
        // §5.1.1.1: commands of one chain share INS, P1, P2 (and the class).
        let changed = [
            Command::new(0x10, 0xDA, 0x3F, 0xFF), // INS
            Command::new(0x10, 0xDB, 0x3E, 0xFF), // P1
            Command::new(0x00, 0xDB, 0x3F, 0xFE), // P2 on the final command
            Command::new(0x0C, 0xDB, 0x3F, 0xFF), // SM bits in CLA
            Command::new(0x00, 0xC0, 0x00, 0x00), // GET RESPONSE mid-chain
        ];
        for next in changed {
            let mut chain = CommandChain::new(64);
            assert_eq!(chain.push(put(0x10, &[1])), Ok(None));
            assert_eq!(
                chain.push(next.clone()),
                Err(ChainError::HeaderChanged),
                "{next:?}"
            );
            assert!(!chain.is_active());
            // The chain was discarded: the next standalone command passes through.
            let fresh = put(0x00, &[7]);
            assert_eq!(chain.push(fresh.clone()), Ok(Some(fresh)));
        }
        assert_eq!(ChainError::HeaderChanged.sw(), 0x6883);
    }

    #[test]
    fn chain_limit() {
        // §5.1.1.1 chaining with this module's configurable total-data limit.
        let mut chain = CommandChain::new(4);
        // Exactly the limit is accepted.
        assert_eq!(chain.push(put(0x10, &[1, 2])), Ok(None));
        let done = chain.push(put(0x00, &[3, 4])).unwrap().unwrap();
        assert_eq!(done.data, [1, 2, 3, 4]);
        // One byte more is refused and discards the chain.
        assert_eq!(chain.push(put(0x10, &[1, 2, 3])), Ok(None));
        assert_eq!(chain.push(put(0x10, &[4, 5])), Err(ChainError::TooLong));
        assert!(!chain.is_active());
        // A first chained command larger than the limit is refused too.
        assert_eq!(chain.push(put(0x10, &bytes(5))), Err(ChainError::TooLong));
        assert!(!chain.is_active());
        // The final command counts.
        assert_eq!(chain.push(put(0x10, &[1, 2, 3, 4])), Ok(None));
        assert_eq!(chain.push(put(0x00, &[5])), Err(ChainError::TooLong));
        assert_eq!(ChainError::TooLong.sw(), sw::WRONG_LENGTH);
        assert!(!ChainError::TooLong.to_string().is_empty());
    }

    #[test]
    fn chain_clear() {
        // §5.1.1.1: an abandoned chain (e.g. after a reset) must not leak into the next.
        let mut chain = CommandChain::new(64);
        assert_eq!(chain.push(put(0x10, &[1])), Ok(None));
        chain.clear();
        assert!(!chain.is_active());
        let cmd = put(0x00, &[2]);
        assert_eq!(chain.push(cmd.clone()), Ok(Some(cmd)));
    }

    // --- Response queue (ISO/IEC 7816-4 §5.1.3 61xx, §7.6.1 GET RESPONSE) ---

    #[test]
    fn response_that_fits() {
        // §5.1.3: a response within Ne goes out whole with its final status word.
        let mut q = ResponseQueue::new();
        assert_eq!(q.start(vec![1, 2, 3], sw::OK, 256), [1, 2, 3, 0x90, 0x00]);
        assert!(!q.is_pending());
        assert_eq!(q.next(256), None);
        // Exactly max bytes still fits.
        let data = bytes(256);
        assert_eq!(q.start(data.clone(), sw::OK, 256), response(&data, sw::OK));
        assert!(!q.is_pending());
        // No data, error status.
        assert_eq!(q.start(Vec::new(), sw::FILE_NOT_FOUND, 256), [0x6A, 0x82]);
    }

    #[test]
    fn response_257_bytes() {
        // §5.1.3: 61 01 = one more byte available via GET RESPONSE (§7.6.1).
        let data = bytes(257);
        let mut q = ResponseQueue::new();
        assert_eq!(
            q.start(data.clone(), sw::OK, 256),
            response(&data[..256], 0x6101)
        );
        assert!(q.is_pending());
        assert_eq!(q.remaining(), 1);
        assert_eq!(q.next(256), Some(response(&data[256..], sw::OK)));
        assert!(!q.is_pending());
        assert_eq!(q.next(256), None);
    }

    #[test]
    fn response_600_bytes() {
        // 600 = 256 + 256 + 88: 6100 (344 left), 6158 (88 left), then 9000.
        let data = bytes(600);
        let mut q = ResponseQueue::new();
        assert_eq!(
            q.start(data.clone(), sw::OK, 256),
            response(&data[..256], 0x6100)
        );
        assert_eq!(q.next(256), Some(response(&data[256..512], 0x6158)));
        assert_eq!(q.next(256), Some(response(&data[512..], 0x9000)));
        assert_eq!(q.next(256), None);
    }

    #[test]
    fn response_exactly_256_left() {
        // 512 bytes: after the first piece 256 remain, written as 6100.
        let data = bytes(512);
        let mut q = ResponseQueue::new();
        assert_eq!(
            q.start(data.clone(), sw::OK, 256),
            response(&data[..256], 0x6100)
        );
        assert_eq!(q.remaining(), 256);
        assert_eq!(q.next(256), Some(response(&data[256..], sw::OK)));
    }

    #[test]
    fn response_smaller_pieces_and_final_status() {
        // 250 bytes in pieces of 100: 6196 (150 left), 6132 (50 left), then the final
        // status word, here a warning 6282 (§5.1.3: end of data reached).
        let data = bytes(250);
        let mut q = ResponseQueue::new();
        assert_eq!(
            q.start(data.clone(), 0x6282, 100),
            response(&data[..100], 0x6196)
        );
        assert_eq!(q.next(100), Some(response(&data[100..200], 0x6132)));
        assert_eq!(q.next(100), Some(response(&data[200..], 0x6282)));
        // A GET RESPONSE may ask for a different size.
        assert_eq!(
            q.start(data.clone(), sw::OK, 10),
            response(&data[..10], 0x61F0)
        );
        assert_eq!(q.next(1000), Some(response(&data[10..], sw::OK)));
    }

    #[test]
    fn response_queue_clear_and_restart() {
        // §7.6.1: GET RESPONSE has nothing to return once the pending data is dropped.
        let mut q = ResponseQueue::new();
        let _ = q.start(bytes(300), sw::OK, 256);
        assert!(q.is_pending());
        q.clear();
        assert!(!q.is_pending());
        assert_eq!(q.remaining(), 0);
        assert_eq!(q.next(256), None);
        // A new response replaces a pending one.
        let _ = q.start(bytes(300), sw::OK, 256);
        assert_eq!(q.start(vec![1], sw::OK, 256), [1, 0x90, 0x00]);
        assert!(!q.is_pending());
    }

    #[test]
    fn response_queue_zero_max_makes_progress() {
        // §5.1.3 61xx chunking; a zero piece size is raised to one byte.
        let mut q = ResponseQueue::new();
        assert_eq!(q.start(vec![1, 2], sw::OK, 0), [1, 0x61, 0x01]);
        assert_eq!(q.next(0), Some(vec![2, 0x90, 0x00]));
    }

    // --- Review: ambiguous body lengths (ISO/IEC 7816-4:2005 §5.1 decoding table) ---

    #[test]
    fn ambiguous_body_lengths_resolve_per_iso_table() {
        // §5.1: B1 = 00 with L = 3 is case 2E. B1 != 00 is a short Lc. B1 = 00 with
        // L > 3 is an extended Lc. Each line is one way the same body length could be
        // misread. Columns: wire, data, Le as written, extended.
        let cases: &[(&str, &str, Option<u32>, bool)] = &[
            // Seven bytes (L = 3).
            ("00CA0000 000005", "", Some(5), true), // 2E, not a short "Lc 00"
            ("00CA0000 0001AA", "", Some(0x01AA), true), // 2E with Le 426
            ("00CA0000 000000", "", Some(0), true), // 2E, Ne = 65536
            ("00CA0000 02AABB", "AABB", None, false), // 3S
            ("00CA0000 01AA00", "AA", Some(0), false), // 4S, not extended Lc 01AA
            // Six bytes (L = 2).
            ("00CA0000 01AA", "AA", None, false), // 3S
            // Eight bytes (L = 4).
            ("00CA0000 000001AA", "AA", None, true), // 3E
            ("00CA0000 03AABBCC", "AABBCC", None, false), // 3S
            ("00CA0000 02AABB10", "AABB", Some(0x10), false), // 4S
            // Ten bytes (L = 6): 4E with the smallest Lc.
            ("00CA0000 000001AA0010", "AA", Some(0x10), true),
        ];
        for &(wire, data, le, extended) in cases {
            let cmd = Command::parse(&hex(wire)).unwrap();
            assert_eq!(cmd.data, hex(data), "{wire}");
            assert_eq!(cmd.le, le, "{wire}");
            assert_eq!(cmd.extended, extended, "{wire}");
            assert_eq!(cmd.to_bytes(), hex(wire), "{wire}");
        }
        // And the lengths that fit no case.
        for wire in [
            "00CA0000 0005",       // L = 2 with B1 = 00: neither 2S nor 2E
            "00CA0000 000000AA",   // L = 4, extended Lc 0
            "00CA0000 0000000100", // L = 5, extended Lc 0 followed by an Le
            "00CA0000 000001AA00", // L = 5, 4E with a one-byte Le
        ] {
            assert_eq!(
                Command::parse(&hex(wire)),
                Err(ApduError::LengthMismatch),
                "{wire}"
            );
        }
    }

    #[test]
    fn maximum_extended_sizes() {
        // §5.1: Nc <= 65535 and Ne <= 65536, so the longest command APDU is
        // 4 + 3 + 65535 + 2 = 65544 bytes.
        let data = bytes(0xFFFF);
        let max = apdu("00DB3FFF 00FFFF", &[&data, &[0x00, 0x00]]);
        assert_eq!(max.len(), 65_544);
        let cmd = Command::parse(&max).unwrap();
        assert_eq!(cmd.data.len(), 0xFFFF);
        assert_eq!(cmd.expected_len(), Some(65_536));
        assert_eq!(cmd.to_bytes(), max);
        // One byte more, one byte less, or a one-byte Le: no case fits.
        let mut longer = max.clone();
        longer.push(0x00);
        assert_eq!(Command::parse(&longer), Err(ApduError::LengthMismatch));
        let short_by_one = apdu("00DB3FFF 00FFFF", &[&data[1..]]);
        assert_eq!(
            Command::parse(&short_by_one),
            Err(ApduError::LengthMismatch)
        );
        let one_byte_le = apdu("00DB3FFF 00FFFF", &[&data, &[0x00]]);
        assert_eq!(Command::parse(&one_byte_le), Err(ApduError::LengthMismatch));
    }

    // --- Review: chaining with Le on intermediate commands (§5.1.1.1) ---

    #[test]
    fn chain_ignores_le_and_form_of_intermediate_commands() {
        // §5.1.1.1 chaining: the intermediate commands below carry Le fields (short
        // 00, then extended 1234); only the final command's Le and form count
        // (CommandChain docs).
        let mut chain = CommandChain::new(1024);
        let first = Command::parse(&hex("10DB3FFF 01 AA 00")).unwrap();
        assert_eq!(first.le, Some(0));
        assert_eq!(chain.push(first), Ok(None));
        let second = Command::parse(&hex("10DB3FFF 000001 BB 1234")).unwrap();
        assert!(second.extended);
        assert_eq!(chain.push(second), Ok(None));
        let last = Command::parse(&hex("00DB3FFF 01 CC")).unwrap();
        let done = chain.push(last).unwrap().unwrap();
        assert_eq!(done.data, [0xAA, 0xBB, 0xCC]);
        assert_eq!(done.le, None);
        assert!(!done.extended);
        assert_eq!(done.expected_len(), None);

        // When the final command has Le, it wins; a short 00 there means Ne = 256 even
        // though the assembled data is longer than 255 bytes.
        assert_eq!(chain.push(put(0x10, &bytes(200)).with_le(5)), Ok(None));
        let last = Command::parse(&apdu("00DB3FFF 64", &[&bytes(100), &[0x00]])).unwrap();
        let done = chain.push(last).unwrap().unwrap();
        assert_eq!(done.data.len(), 300);
        assert_eq!(done.le, Some(0));
        assert_eq!(done.expected_len(), Some(256));
    }

    // --- Review: response chunking at every SW2 boundary (§5.1.3, §7.6.1) ---

    #[test]
    fn response_queue_chunk_boundaries() {
        // §5.1.3: SW2 of 61xx is the number of bytes still available, 00 meaning 256
        // or more; the last piece carries the final status word.
        for total in [0usize, 1, 255, 256, 257, 511, 512, 513, 600, 1000] {
            for max in [1usize, 16, 255, 256, 257] {
                if max == 1 && total > 600 {
                    continue;
                }
                let data = bytes(total);
                let mut q = ResponseQueue::new();
                let mut out = q.start(data.clone(), sw::OK, max);
                let mut got = Vec::new();
                let mut pieces = 0;
                loop {
                    pieces += 1;
                    let (piece, word) = split_response(&out).unwrap();
                    assert!(piece.len() <= max, "total {total} max {max}");
                    got.extend_from_slice(piece);
                    let left = total - got.len();
                    assert_eq!(q.remaining(), left);
                    if left == 0 {
                        assert_eq!(word, sw::OK, "total {total} max {max}");
                        break;
                    }
                    assert_eq!(piece.len(), max, "only the last piece may be short");
                    assert_eq!(word, 0x6100 | (left.min(256) % 256) as u16);
                    out = q.next(max).unwrap();
                }
                assert_eq!(got, data);
                assert_eq!(
                    pieces,
                    total.div_ceil(max).max(1),
                    "total {total} max {max}"
                );
                assert!(!q.is_pending());
                assert_eq!(q.next(max), None);
            }
        }
    }

    // --- Review: fixed-seed pseudo-random robustness ---

    /// SplitMix64 (Steele, Lea and Flood, "Fast Splittable Pseudorandom Number
    /// Generators", OOPSLA 2014): a tiny fixed-seed generator for reproducible inputs.
    struct SplitMix64(u64);

    impl SplitMix64 {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        fn below(&mut self, n: usize) -> usize {
            (self.next_u64() % n as u64) as usize
        }

        fn byte(&mut self) -> u8 {
            self.next_u64() as u8
        }

        /// A byte biased towards the values that steer the §5.1 case decision.
        fn length_byte(&mut self) -> u8 {
            const INTERESTING: [u8; 8] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0xFF, 0xFE];
            if self.below(2) == 0 {
                INTERESTING[self.below(INTERESTING.len())]
            } else {
                self.byte()
            }
        }
    }

    /// ISO/IEC 7816-4:2005 §5.1 body decoding, transcribed line by line as an oracle:
    /// `(data, Le as written, extended)` or `None` when no case matches.
    fn spec_decode(body: &[u8]) -> Option<(Vec<u8>, Option<u32>, bool)> {
        let l = body.len();
        let be = |hi: u8, lo: u8| usize::from(hi) << 8 | usize::from(lo);
        if l == 0 {
            return Some((Vec::new(), None, false)); // case 1
        }
        let b1 = usize::from(body[0]);
        if l == 1 {
            return Some((Vec::new(), Some(b1 as u32), false)); // case 2S
        }
        if b1 != 0 && l == 1 + b1 {
            return Some((body[1..].to_vec(), None, false)); // case 3S
        }
        if b1 != 0 && l == 2 + b1 {
            return Some((body[1..l - 1].to_vec(), Some(u32::from(body[l - 1])), false)); // 4S
        }
        if b1 == 0 && l == 3 {
            return Some((Vec::new(), Some(be(body[1], body[2]) as u32), true)); // case 2E
        }
        if b1 == 0 && l > 3 {
            let lc = be(body[1], body[2]);
            if lc != 0 && l == 3 + lc {
                return Some((body[3..].to_vec(), None, true)); // case 3E
            }
            if lc != 0 && l == 5 + lc {
                let le = be(body[l - 2], body[l - 1]) as u32;
                return Some((body[3..l - 2].to_vec(), Some(le), true)); // case 4E
            }
        }
        None
    }

    /// Compare [`Command::parse`] with the oracle and check the round trip.
    fn check_against_spec(wire: &[u8]) {
        let parsed = Command::parse(wire);
        let Some((header, body)) = wire.split_first_chunk::<4>() else {
            assert_eq!(parsed, Err(ApduError::TooShort));
            return;
        };
        match (parsed, spec_decode(body)) {
            (Ok(cmd), Some((data, le, extended))) => {
                assert_eq!([cmd.cla, cmd.ins, cmd.p1, cmd.p2], *header);
                assert_eq!((&cmd.data, cmd.le, cmd.extended), (&data, le, extended));
                // Parsing is injective and to_bytes is its exact inverse.
                assert_eq!(cmd.to_bytes(), wire);
            }
            (Err(ApduError::LengthMismatch), None) => {}
            (got, want) => panic!(
                "{:02X?}: parse {got:?}, ISO table {want:?}",
                &wire[..wire.len().min(16)]
            ),
        }
    }

    #[test]
    fn seeded_random_apdus_match_the_iso_table() {
        // Fixed seed so failures reproduce; oracle is the §5.1 decoding table.
        let mut rng = SplitMix64(0x7816_0004_0501_0001);
        for i in 0..20_000 {
            let wire = match i % 4 {
                // Short random bodies over the bytes that decide the case.
                0 | 1 => {
                    let n = rng.below(14);
                    (0..n).map(|_| rng.length_byte()).collect::<Vec<u8>>()
                }
                // A valid command from random fields, sometimes damaged.
                _ => {
                    let nc = match rng.below(400) {
                        0 => 0xFF00 + rng.below(0x100),
                        1..=20 => 0x100 + rng.below(0x200),
                        _ => rng.below(0x100),
                    };
                    let le = match rng.below(5) {
                        0 => None,
                        1 => Some(0),
                        2 => Some(rng.below(0x100) as u32),
                        3 => Some(rng.below(0x1_0001) as u32),
                        _ => Some(256),
                    };
                    let cmd = Command {
                        cla: rng.byte(),
                        ins: rng.byte(),
                        p1: rng.byte(),
                        p2: rng.byte(),
                        data: (0..nc).map(|_| rng.byte()).collect(),
                        le,
                        extended: rng.below(4) == 0,
                    };
                    let mut wire = cmd.to_bytes();
                    let back = Command::parse(&wire).unwrap();
                    assert_eq!(back.data, cmd.data);
                    assert_eq!(back.expected_len(), cmd.expected_len());
                    match rng.below(6) {
                        0 => wire.truncate(rng.below(wire.len())),
                        1 => wire.push(rng.length_byte()),
                        2 if wire.len() > 4 => {
                            let at = 4 + rng.below(wire.len() - 4);
                            wire[at] = rng.length_byte();
                        }
                        _ => {}
                    }
                    wire
                }
            };
            check_against_spec(&wire);
        }
    }

    // --- Wiping and redaction (docs/DESIGN.md §8) ---

    #[test]
    fn zeroing_covers_the_spare_capacity_of_a_buffer() {
        // A buffer that held 32 secret bytes and was truncated to 8 still holds the
        // other 24 in its allocation; all 32 are overwritten.
        let mut buf = vec![0xA5u8; 32];
        buf.truncate(8);
        let capacity = buf.capacity();
        zero_allocation(&mut buf);
        assert_eq!(buf.len(), capacity);
        assert!(buf.iter().all(|&b| b == 0));
        wipe_vec(&mut buf);
        assert!(buf.is_empty());
        assert_eq!(buf.capacity(), capacity, "the allocation is kept");
    }

    #[test]
    fn growing_a_secret_buffer_keeps_its_contents() {
        let mut buf = Vec::with_capacity(4);
        buf.extend_from_slice(&[1, 2, 3]);
        extend_wiping(&mut buf, &[4, 5, 6, 7, 8]);
        assert_eq!(buf, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(buf.capacity() >= 8);
        extend_wiping(&mut buf, &[]);
        assert_eq!(buf.len(), 8);
    }

    #[test]
    fn debug_output_shows_lengths_but_no_data_bytes() {
        // A PIV VERIFY with the PIN "123456" (SP 800-73-4 Part 2 §3.2.1).
        let verify = Command::parse(&hex("0020008008313233343536FFFF")).unwrap();
        assert_eq!(verify.le, None);
        let text = format!("{verify:?}");
        assert!(text.contains("data_len: 8"), "{text}");
        assert!(
            !text.contains("49") && !text.contains("0x31") && !text.contains("255"),
            "{text}"
        );

        let mut chain = CommandChain::new(64);
        assert_eq!(
            chain.push(Command::parse(&hex("102000800431323334")).unwrap()),
            Ok(None)
        );
        let text = format!("{chain:?}");
        assert!(
            text.contains("buffered_len: 4") && text.contains("active: true"),
            "{text}"
        );
        assert!(!text.contains("49"), "{text}");

        let mut queue = ResponseQueue::new();
        queue.start(vec![0x31; 300], sw::OK, 256);
        let text = format!("{queue:?}");
        assert!(
            text.contains("remaining: 44") && text.contains("0x9000"),
            "{text}"
        );
        assert!(!text.contains("49"), "{text}");
    }

    #[test]
    fn into_data_hands_the_data_field_over_without_a_copy() {
        let cmd = Command::parse(&hex("0020008008313233343536FFFF")).unwrap();
        let address = cmd.data.as_ptr();
        let data = cmd.into_data();
        assert_eq!(data, hex("313233343536FFFF"));
        assert_eq!(data.as_ptr(), address, "the same allocation, not a copy");
    }

    #[test]
    fn clearing_a_response_queue_leaves_no_data_to_serve() {
        let mut q = ResponseQueue::new();
        let first = q.start(vec![0x5A; 600], sw::OK, 256);
        assert_eq!(&first[256..], &[0x61, 0x00]);
        q.clear();
        assert!(!q.is_pending());
        assert_eq!(q.remaining(), 0);
        assert_eq!(q.next(256), None);
        // A response started after the clear serves only its own bytes.
        assert_eq!(
            q.start(vec![0x01, 0x02], sw::OK, 256),
            [0x01, 0x02, 0x90, 0x00]
        );
        assert_eq!(q.next(256), None);
        // Replacing pending data with `start` drops the old remainder too.
        q.start(vec![0x5A; 600], sw::OK, 256);
        assert_eq!(q.start(vec![0x07], sw::OK, 256), [0x07, 0x90, 0x00]);
        assert_eq!(q.next(256), None);
    }

    #[test]
    fn a_discarded_chain_leaves_nothing_buffered() {
        let mut chain = CommandChain::new(64);
        assert_eq!(
            chain.push(Command::parse(&hex("1020008002AABB")).unwrap()),
            Ok(None)
        );
        assert_eq!(chain.buffered_len(), 2);
        chain.clear();
        assert_eq!((chain.is_active(), chain.buffered_len()), (false, 0));
        // A header change discards the chain as well.
        assert_eq!(
            chain.push(Command::parse(&hex("1020008002AABB")).unwrap()),
            Ok(None)
        );
        assert_eq!(
            chain.push(Command::parse(&hex("0024008002CCDD")).unwrap()),
            Err(ChainError::HeaderChanged)
        );
        assert_eq!((chain.is_active(), chain.buffered_len()), (false, 0));
        // A completed chain hands its data over and keeps none.
        assert_eq!(
            chain.push(Command::parse(&hex("1020008002AABB")).unwrap()),
            Ok(None)
        );
        let done = chain
            .push(Command::parse(&hex("0020008002CCDD")).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(done.data, [0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(
            (done.cla, done.ins, done.p1, done.p2),
            (0x00, 0x20, 0x00, 0x80)
        );
        assert_eq!(chain.buffered_len(), 0);
    }
}
