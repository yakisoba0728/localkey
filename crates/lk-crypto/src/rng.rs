//! Adapter from the host's [`Entropy`] to the RNG traits some RustCrypto calls require.

use core::convert::Infallible;

use lk_core::Entropy;
use rand_core::{TryCryptoRng, TryRng};

pub(crate) struct EntropyRng<'a>(pub(crate) &'a mut dyn Entropy);

impl TryRng for EntropyRng<'_> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut bytes = [0; 4];
        self.0.fill(&mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut bytes = [0; 8];
        self.0.fill(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.0.fill(dst);
        Ok(())
    }
}

// The host contract requires cryptographically secure entropy (lk_core::Entropy).
impl TryCryptoRng for EntropyRng<'_> {}
