//! Channel identifier allocation (CTAP 2.1 §11.2.9.1.3).

use crate::protocol::BROADCAST_CID;

/// The first identifier handed out; 0 is reserved (CTAP 2.1 §11.2.4).
const FIRST_CID: u32 = 1;

/// Channel identifiers handed out by broadcast `CTAPHID_INIT`.
///
/// Model policy: `Ctaphid::new` receives no entropy, so identifiers are allocated
/// sequentially from 1. The allocated set is the range `floor..next`; it never contains
/// the reserved identifier 0 or the broadcast identifier. A USB reset moves `floor` up
/// to `next`, so identifiers from before the reset are rejected with
/// `ERR_INVALID_CHANNEL` instead of colliding with channels allocated afterwards.
/// When the 32-bit space is exhausted the allocator starts again from 1 and forgets
/// every earlier channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CidAllocator {
    floor: u32,
    next: u32,
}

impl CidAllocator {
    pub(crate) const fn new() -> Self {
        Self {
            floor: FIRST_CID,
            next: FIRST_CID,
        }
    }

    /// Hands out a fresh channel identifier.
    pub(crate) fn allocate(&mut self) -> u32 {
        if self.next == BROADCAST_CID {
            *self = Self::new();
        }
        let cid = self.next;
        self.next += 1;
        cid
    }

    /// Whether `cid` was handed out since the last reset.
    pub(crate) fn is_allocated(&self, cid: u32) -> bool {
        (self.floor..self.next).contains(&cid)
    }

    /// Forgets every channel handed out so far (USB reset).
    pub(crate) fn forget_all(&mut self) {
        self.floor = self.next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_sequentially_and_never_reserved_ids() {
        let mut cids = CidAllocator::new();
        assert!(!cids.is_allocated(0));
        assert!(!cids.is_allocated(1));
        assert_eq!(cids.allocate(), 1);
        assert_eq!(cids.allocate(), 2);
        assert!(cids.is_allocated(1) && cids.is_allocated(2));
        assert!(!cids.is_allocated(0) && !cids.is_allocated(3));
        assert!(!cids.is_allocated(BROADCAST_CID));
    }

    #[test]
    fn reset_invalidates_old_ids_without_reusing_them() {
        let mut cids = CidAllocator::new();
        let old = cids.allocate();
        cids.forget_all();
        assert!(!cids.is_allocated(old));
        let new = cids.allocate();
        assert_ne!(new, old);
        assert!(cids.is_allocated(new));
    }

    #[test]
    fn exhaustion_restarts_from_one() {
        let mut cids = CidAllocator {
            floor: 5,
            next: BROADCAST_CID - 1,
        };
        assert_eq!(cids.allocate(), BROADCAST_CID - 1);
        assert!(!cids.is_allocated(BROADCAST_CID));
        assert_eq!(cids.allocate(), 1);
        assert!(!cids.is_allocated(5));
        assert!(!cids.is_allocated(BROADCAST_CID - 1));
        assert!(!cids.is_allocated(BROADCAST_CID));
    }
}
