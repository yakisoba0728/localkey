//! Reassembly of frames from a byte stream, shared by the server's reader threads and
//! [`crate::Client`].

use std::fmt;
use std::io::{self, Read};

use crate::codec::{self, Frame, FrameError, HEADER_LEN, Origin};

/// Bytes per read. A frame larger than this arrives over several reads.
const CHUNK: usize = 8192;

/// Bytes read from a stream that do not form a whole frame yet. The decoder refuses a
/// bad header as soon as it arrives, so the buffer never holds more than one valid frame
/// and one read.
///
/// `Debug` shows how many bytes wait, never the bytes: they are frame payloads (PINs in
/// CCID messages, CTAP payloads), and [`crate::Client`]'s `Debug` includes its inbox
/// (`docs/PROGRAM.md` "Rules for program crates", Secrets).
#[derive(Default)]
pub(crate) struct Inbox {
    buffer: Vec<u8>,
}

impl fmt::Debug for Inbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Inbox").field("buffered", &format_args!("{} bytes", self.buffer.len())).finish()
    }
}

impl Inbox {
    /// The next whole frame sent by `origin` and its payload size, if the buffer holds one.
    pub(crate) fn next(&mut self, origin: Origin) -> Result<Option<(Frame, usize)>, FrameError> {
        let Some((frame, used)) = codec::decode(&self.buffer, origin)? else {
            return Ok(None);
        };
        let remaining = self.buffer.len() - used;
        self.buffer.copy_within(used.., 0);
        lk_crypto::wipe(&mut self.buffer[remaining..]);
        self.buffer.truncate(remaining);
        Ok(Some((frame, used - HEADER_LEN)))
    }

    /// One read from `reader` into the buffer; `Ok(0)` is the end of the stream.
    pub(crate) fn fill(&mut self, reader: &mut impl Read) -> io::Result<usize> {
        let mut chunk = lk_crypto::SecretBytes::zeroed(CHUNK);
        let read = reader.read(&mut chunk)?;
        lk_crypto::extend_secret(&mut self.buffer, &chunk[..read]);
        Ok(read)
    }
}

impl Drop for Inbox {
    fn drop(&mut self) {
        lk_crypto::wipe_vec(&mut self.buffer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_shows_the_buffered_size_never_the_bytes() -> io::Result<()> {
        let mut inbox = Inbox::default();
        // The start of a CCID_BULK_OUT frame carrying VERIFY with the PIN "123456".
        let partial: &[u8] =
            &[0, 0, 0, 24, 0x04, 0x6F, 13, 0, 0, 0, 0, 0x07, 0, 0, 0, 0x00, 0x20, 0x00, 0x80, 0x08, b'1', b'2'];
        assert_eq!(inbox.fill(&mut { partial })?, partial.len());
        assert_eq!(inbox.next(Origin::Host), Ok(None));
        assert_eq!(format!("{inbox:?}"), "Inbox { buffered: 22 bytes }");
        Ok(())
    }
}
