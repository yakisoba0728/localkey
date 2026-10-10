//! PERFORM SECURITY OPERATION for OCE certificates and the volatile OCE cache.
//!
//! Sources: GP Card Specification v2.3.1 Amendment F (SCP11) §7.5 ("Amd F"): the OCE
//! sends its certificate chain one certificate per command; P1 is the key version and
//! P2 the key identifier of the CA-KLOC public key that anchors the chain, P2 b8 set
//! when more certificates follow. Each certificate is verified against the previous
//! one (the first against the CA-KLOC key) and the leaf's public key is kept for the
//! following MUTUAL AUTHENTICATE (SCP11a/c). Yubico's SDK sends exactly this (yubikit
//! `scp.py`: `80 2A <kvn> <kid | 80 while more follow> <DER certificate>`), with KID and
//! KVN `00` when the host names no CA ("wildcard").
//!
//! Catalog decisions (`reference/BEHAVIOR_CATALOG.md` SecurityDomain_incremental_pso,
//! SecurityDomain_allowlist, SecurityDomain_oce_cache):
//! - every certificate is checked when it arrives, before it is acknowledged:
//!   signature, role (CA for every certificate that is followed by another, OCE
//!   key-agreement certificate for the last), key type, validity (order, and not
//!   expired before the earliest possible current time, `cert::earliest_now`), critical
//!   extensions, accumulated path length and, if the CA has an allowlist, its serial;
//! - the CA reference of the first command binds the chain; later P1/P2 are ignored
//!   except for the "more follow" bit; with a wildcard every matching CA stays a
//!   candidate as long as the chain verifies under it, and allowlists of different CAs
//!   are never combined;
//! - a malformed certificate (DER/X.509 structure, duplicate extension) uses one try of
//!   each CA the first command selected and answers `6A80`; a certificate that is
//!   well-formed but fails a check answers `6982` and changes no persistent state;
//!   either way the chain and any cached OCE are dropped;
//! - starting a new chain drops the cached OCE (a new partial chain cannot reuse the
//!   previous host); a completed chain replaces it;
//! - a CA with no tries left is deleted when it is next named (`6983`), as yubikit's
//!   reset expects (it sends `80 2A <kvn> <kid> 08 00..00` until `6983`).
//!
//! The cache is volatile: SELECT, resets, allowlist updates and a channel that ends on
//! a rejected command drop it.

use lk_codec::apdu::{self, Command, sw};
use lk_core::Host;

use crate::SecurityDomain;
use crate::cert::{Certificate, Link, earliest_now};
use crate::channel::Shared;
use crate::handshake::KeyRow;
use crate::state::{AUTH_TRIES, MAX_CERTIFICATES, is_ca_kid};

/// P2 b8 of PERFORM SECURITY OPERATION: more certificates follow.
const MORE_FOLLOW: u8 = 0x80;

/// A CA that the chain presented so far verifies under.
#[derive(Debug, Clone)]
pub(crate) struct Candidate {
    kid: u8,
    kvn: u8,
    link: Link,
}

/// An OCE certificate chain being uploaded.
#[derive(Debug, Clone)]
pub(crate) struct Chain {
    /// The CA keys the first command selected (charged for malformed certificates).
    initial: Vec<(u8, u8)>,
    candidates: Vec<Candidate>,
    count: usize,
}

/// A verified OCE: the leaf's key-agreement key (PK.OCE.ECKA) and the CA it chains to.
#[derive(Debug, Clone)]
pub(crate) struct Oce {
    pub(crate) point: Vec<u8>,
    pub(crate) anchor: (u8, u8),
    /// [`Shared::revocations`] when the chain was verified.
    revocations: u64,
}

impl SecurityDomain {
    /// The cached OCE, unless a channel ended on a rejected command since it was
    /// verified (catalog SecurityDomain_plaintext: plaintext revokes all authorization).
    pub(crate) fn current_oce(&self) -> Option<&Oce> {
        let now = Shared::load(&self.shared.revocations);
        self.oce.as_ref().filter(|o| o.revocations == now)
    }

    /// Drop the cached OCE and any partial chain.
    pub(crate) fn clear_oce(&mut self) {
        self.oce = None;
        self.oce_chain = None;
    }

    /// PERFORM SECURITY OPERATION `80 2A <CA KVN> <CA KID | 80>` with one DER
    /// certificate (Amd F §7.5).
    pub(crate) fn perform_security_operation(&mut self, cmd: &Command, host: &mut dyn Host) -> Vec<u8> {
        self.pending = None;
        let more = cmd.p2 & MORE_FOLLOW != 0;
        let mut chain = match self.oce_chain.take() {
            Some(chain) => chain,
            None => {
                self.oce = None;
                match self.start_chain(cmd.p2 & !MORE_FOLLOW, cmd.p1, host) {
                    Ok(chain) => chain,
                    Err(status) => return apdu::status(status),
                }
            }
        };
        chain.count += 1;
        if chain.count > MAX_CERTIFICATES {
            return apdu::status(sw::SECURITY_STATUS);
        }
        let Ok(cert) = Certificate::parse(&cmd.data) else {
            return apdu::status(match self.charge_anchors(&chain.initial, host) {
                Ok(()) => sw::INCORRECT_DATA,
                Err(status) => status,
            });
        };
        if !cert.role_allows(more, earliest_now(&host.profile().cert_not_before)) {
            return apdu::status(sw::SECURITY_STATUS);
        }
        let next: Vec<Candidate> = chain
            .candidates
            .iter()
            .filter_map(|c| {
                let list = self.state.allowlist(c.kid, c.kvn).map_or(&[][..], |l| l.serials.as_slice());
                cert.link(&c.link, more, list).map(|link| Candidate { kid: c.kid, kvn: c.kvn, link })
            })
            .collect();
        let Some(chosen) = next.first() else {
            return apdu::status(sw::SECURITY_STATUS);
        };
        if more {
            chain.candidates = next;
            self.oce_chain = Some(chain);
            return apdu::status(sw::OK);
        }
        // The chain is complete: a successful verification restores the CA's tries.
        let anchor = (chosen.kid, chosen.kvn);
        let row = KeyRow::Ca { kid: anchor.0, kvn: anchor.1 };
        if row.tries(&self.state).is_some_and(|t| t != AUTH_TRIES) {
            let mut next_state = self.state.clone();
            row.set_tries(&mut next_state, AUTH_TRIES);
            if let Err(status) = self.commit(next_state, host) {
                return apdu::status(status);
            }
        }
        let Some(point) = cert.public_key.clone() else {
            return apdu::status(sw::SECURITY_STATUS);
        };
        self.oce = Some(Oce { point, anchor, revocations: Shared::load(&self.shared.revocations) });
        apdu::status(sw::OK)
    }

    /// Select the CA keys a first PSO names: KID `00` or `10`/`20`-`2F` (`6A86`
    /// otherwise), KVN `00` for any version. No match: `6A88`. Matching keys without
    /// tries are deleted, and if no usable one remains the command answers `6983`.
    fn start_chain(&mut self, kid: u8, kvn: u8, host: &mut dyn Host) -> Result<Chain, u16> {
        if kid != 0 && !is_ca_kid(kid) {
            return Err(sw::INCORRECT_P1P2);
        }
        let matching: Vec<(u8, u8, u8)> = self
            .state
            .ec_public
            .iter()
            .filter(|k| (kid == 0 || k.kid == kid) && (kvn == 0 || k.kvn == kvn))
            .map(|k| (k.kid, k.kvn, k.tries))
            .collect();
        if matching.is_empty() {
            return Err(sw::REF_NOT_FOUND);
        }
        let usable: Vec<(u8, u8)> = matching.iter().filter(|m| m.2 > 0).map(|m| (m.0, m.1)).collect();
        if usable.is_empty() {
            let rows: Vec<KeyRow> = matching.iter().map(|m| KeyRow::Ca { kid: m.0, kvn: m.1 }).collect();
            self.remove_rows(&rows, host)?;
            return Err(sw::AUTH_BLOCKED);
        }
        let candidates = usable
            .iter()
            .filter_map(|&(k, v)| {
                let key = self.state.public_key(k, v)?;
                let ski = self.state.ca_identifier(k, v).map(|c| c.ski.clone());
                Some(Candidate { kid: k, kvn: v, link: Link { point: key.point.clone(), ski, budget: None } })
            })
            .collect();
        Ok(Chain { initial: usable, candidates, count: 0 })
    }

    /// A malformed certificate uses one try of each CA the chain started with
    /// (persisted before the answer).
    fn charge_anchors(&mut self, anchors: &[(u8, u8)], host: &mut dyn Host) -> Result<(), u16> {
        let mut next = self.state.clone();
        let mut changed = false;
        for &(kid, kvn) in anchors {
            let row = KeyRow::Ca { kid, kvn };
            if let Some(t) = row.tries(&next).filter(|&t| t > 0) {
                row.set_tries(&mut next, t - 1);
                changed = true;
            }
        }
        if changed { self.commit(next, host) } else { Ok(()) }
    }
}
