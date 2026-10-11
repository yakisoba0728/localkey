//! Who is on the other end: the peer check made after every connection to vpcd, before
//! anything is read or written.
//!
//! # Why
//!
//! The vpcd link has no authentication. The card connects to whatever listens on the
//! configured address, and the listener then drives the card: it can send any APDU (burn
//! PIN retry counters, read the OATH codes of credentials without an access key, read
//! public objects). vpcd's port 35963 is not a privileged port, so on a machine with several
//! users any of them can listen on `127.0.0.1:35963` whenever vpcd does not (pcscd not
//! running, restarting, or exited with `--auto-exit`), and the transport, which retries
//! every second, would connect to it. So the transport asks a [`PeerCheck`] about every new
//! connection; a peer it refuses gets the connection closed before a byte is sent or read.
//!
//! # On Linux: the owner of the peer's socket
//!
//! [`ProcNetPeerCheck`] finds the socket on the other end of the connection in the
//! kernel's TCP socket tables, `/proc/net/tcp` (IPv4) and `/proc/net/tcp6` (IPv6, and the
//! IPv4 clients of a dual-stack IPv6 listener, as IPv4-mapped addresses), and takes its
//! owner's uid. The format is the kernel's (`net/ipv4/tcp_ipv4.c`: `tcp4_seq_show`,
//! `get_tcp4_sock`, `get_openreq4`, `get_timewait4_sock`; `net/ipv6/tcp_ipv6.c`:
//! `tcp6_seq_show`, `get_tcp6_sock`, `get_openreq6`, `get_timewait6_sock`; Linux master,
//! read 2026-10-11):
//!
//! - A header line (`  sl  local_address rem_address   st tx_queue rx_queue ...`), then one
//!   line per socket with whitespace-separated fields: `sl:` (a slot number and a colon),
//!   `local_address`, `rem_address`, `st`, `tx_queue:rx_queue`, `tr:tm->when`,
//!   `retrnsmt`, `uid`, `timeout`, `inode` and more. The uid is the eighth field.
//! - An address and port is `ADDRESS:PORT`. The address is `%08X` of the `__be32`
//!   (`inet_rcv_saddr`, `inet_daddr`) for IPv4, and `%08X%08X%08X%08X` of the four
//!   `s6_addr32` words for IPv6: each 32-bit word, in network byte order in memory, printed
//!   as a host-order number. On a little-endian machine `127.0.0.1` is `0100007F`, `::1` is
//!   `00000000000000000000000001000000` and `::ffff:127.0.0.1` is
//!   `0000000000000000FFFF00000100007F`. The port is `%04X` of `ntohs(...)`, the port
//!   number itself: 35963 is `8C7B`.
//! - `st` is the TCP state in hex (`include/net/tcp_states.h`: `01` ESTABLISHED, `03`
//!   SYN_RECV, `05` FIN_WAIT2, `06` TIME_WAIT, `0A` LISTEN).
//! - `uid` is the socket's owner, `from_kuid_munged(seq_user_ns(..), sk_uid(sk))`: in the
//!   user namespace of the reader. A connection request the listener's kernel holds before
//!   the handshake completes (`get_openreq4`, shown as SYN_RECV) shows its listener's
//!   owner. A TIME_WAIT socket (`get_timewait4_sock`, whose `st` is its substate: `06`, or
//!   `05` for an orphaned FIN_WAIT2) shows a literal `0`.
//!
//! The peer's socket is the line whose local address and port are this connection's peer
//! address and whose remote address and port are this connection's local address, compared
//! in canonical form (an IPv4-mapped address as the IPv4 address). Only ESTABLISHED and
//! SYN_RECV lines count ([`LIVE_STATES`]): a TIME_WAIT line's `0` would pass for root, and
//! a peer in any other state has closed or is closing its side. A socket the listener has
//! not accepted yet is a copy of the listening socket, owner included (`sk_clone_lock`);
//! `accept` gives it the accepting process's (`sock_graft` → `sk_set_socket`,
//! `include/net/sock.h`). Either way the uid is that of the program listening on vpcd's
//! port, which an unprivileged program cannot change (`fchown` on a socket needs
//! `CAP_CHOWN`). Every matching line must be owned by an allowed uid, and at least one
//! must exist; otherwise the peer is refused.
//!
//! `connect` can return before the listener's kernel has put the peer's socket into the
//! table (a listener answering with a SYN cookie keeps nothing until the final ACK
//! arrives), so a connection without a line is looked up again, [`LOOKUPS`] times in all,
//! [`LOOKUP_PAUSE`] apart, before it is refused.
//!
//! The default allowed set ([`ProcNetPeerCheck::default_uids`]) is:
//!
//! - root, for a pcscd started by hand or by a distribution that runs it as root;
//! - the uid of the local system user `pcscd` ([`PCSCD_USER`]) when `/etc/passwd` has one:
//!   Ubuntu 26.04's pcscd 2.4.1-1 runs pcscd, and with it vpcd and its listener, as that
//!   user (`pcscd.service`: `User=pcscd`, `PrivateUsers=identity`; the user comes from
//!   `/usr/lib/sysusers.d/pcscd.conf`, `u! pcscd - "PC/SC Smart Card Daemon"`, so its uid
//!   is allocated per machine: 990 in the test guest). Only root can create that user;
//!   with root alone, the packaged vpcd was refused (`owned by uid 990, not an allowed uid
//!   (0)`, seen in the guest);
//! - this process's real uid (the first number of the `Uid:` line of `/proc/self/status`,
//!   `Documentation/filesystems/proc.rst`), for a vpcd the same user runs.
//!
//! # Elsewhere, and remote peers
//!
//! macOS has no `/proc`. [`default_peer_check`] is [`NoPeerCheck`] on every system but
//! Linux: the peer is not checked, and the transport says so once. There any local user who
//! listens on vpcd's address while vpcd does not gets the card; only the address rule holds
//! (a loopback address unless a remote one is allowed explicitly, [`crate::check_addr`]).
//! A peer that is not on a loopback address (possible only with a remote address allowed)
//! is on another machine whose sockets this one cannot see: [`ProcNetPeerCheck`] leaves it
//! unchecked too.

use std::fmt;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::connect::is_loopback;

/// The kernel's IPv4 TCP socket table.
pub const PROC_NET_TCP: &str = "/proc/net/tcp";
/// The local user pcscd runs as where its packaging gives it one of its own (see the
/// module docs); its uid, from `/etc/passwd`, is in the default allowed set.
pub const PCSCD_USER: &str = "pcscd";
/// The local user database the default allowed set reads [`PCSCD_USER`] from.
pub const ETC_PASSWD: &str = "/etc/passwd";
/// The kernel's IPv6 TCP socket table.
pub const PROC_NET_TCP6: &str = "/proc/net/tcp6";
/// TCP_ESTABLISHED (`include/net/tcp_states.h`).
pub const ESTABLISHED: u8 = 0x01;
/// TCP_SYN_RECV: a connection request not yet a full socket (`get_openreq4`).
pub const SYN_RECV: u8 = 0x03;
/// The states of a peer's socket that count (see the module docs).
pub const LIVE_STATES: [u8; 2] = [ESTABLISHED, SYN_RECV];
/// How many times [`ProcNetPeerCheck`] looks for the peer's socket before it refuses a
/// connection whose peer it cannot find.
pub const LOOKUPS: u32 = 5;
/// The pause between two lookups.
pub const LOOKUP_PAUSE: Duration = Duration::from_millis(10);

/// Decides whether a new connection to vpcd may be used. Called on the connection thread
/// right after each connect, before anything is read or written, with the connection's
/// own addresses (`TcpStream::local_addr`, `TcpStream::peer_addr`).
pub trait PeerCheck: Send + Sync + fmt::Debug {
    fn check(&self, local: SocketAddr, peer: SocketAddr) -> PeerVerdict;
}

/// What a [`PeerCheck`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerVerdict {
    /// The peer's socket is owned by `uid`, an allowed uid: the connection is used.
    Allowed { uid: u32 },
    /// The peer was not checked, for `reason`: the connection is used.
    Unchecked { reason: String },
    /// The connection is closed unused.
    Refused(PeerRefusal),
}

/// Why a peer was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerRefusal {
    /// The peer's socket is owned by `uid`, which is not among `allowed`.
    NotAllowed { uid: u32, allowed: Vec<u32> },
    /// No live socket on the peer's side of the connection was found.
    NotFound,
    /// The check could not be made (a socket table that cannot be read, a connection
    /// whose addresses are unknown).
    Failed(String),
}

impl fmt::Display for PeerRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerRefusal::NotAllowed { uid, allowed } => {
                write!(f, "is owned by uid {uid}, not an allowed uid ({})", uid_list(allowed))
            }
            PeerRefusal::NotFound => f.write_str(
                "has no owner to check: no live socket on its side of the connection in /proc/net/tcp or \
                 /proc/net/tcp6",
            ),
            PeerRefusal::Failed(reason) => write!(f, "cannot be checked: {reason}"),
        }
    }
}

/// `0, 1000`: uids as the notices list them.
pub fn uid_list(uids: &[u32]) -> String {
    uids.iter().map(u32::to_string).collect::<Vec<_>>().join(", ")
}

/// The check every system but Linux gets ([`default_peer_check`]): no check.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoPeerCheck;

impl PeerCheck for NoPeerCheck {
    fn check(&self, _local: SocketAddr, _peer: SocketAddr) -> PeerVerdict {
        PeerVerdict::Unchecked {
            reason: "its owner is looked up in /proc/net/tcp, which only Linux has; on this system any local \
                     user listening on the address while vpcd does not gets the card"
                .to_owned(),
        }
    }
}

/// [`ProcNetPeerCheck::with_default_uids`] on Linux, [`NoPeerCheck`] elsewhere (decided at
/// run time with `cfg!`, so both compile and are tested everywhere).
pub fn default_peer_check() -> Arc<dyn PeerCheck> {
    if cfg!(target_os = "linux") { Arc::new(ProcNetPeerCheck::with_default_uids()) } else { Arc::new(NoPeerCheck) }
}

/// The Linux peer check: the owner of the peer's socket, from the kernel's TCP socket
/// tables, must be an allowed uid (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcNetPeerCheck {
    /// Sorted, without duplicates.
    allowed: Vec<u32>,
    /// [`PROC_NET_TCP`] and [`PROC_NET_TCP6`]; fixture files in tests.
    tables: [PathBuf; 2],
}

impl ProcNetPeerCheck {
    /// A check that allows exactly `allowed` (an empty set refuses every peer).
    pub fn new(allowed: impl IntoIterator<Item = u32>) -> ProcNetPeerCheck {
        ProcNetPeerCheck::with_tables(allowed, [PathBuf::from(PROC_NET_TCP), PathBuf::from(PROC_NET_TCP6)])
    }

    /// A check that allows [`ProcNetPeerCheck::default_uids`].
    pub fn with_default_uids() -> ProcNetPeerCheck {
        ProcNetPeerCheck::new(ProcNetPeerCheck::default_uids())
    }

    /// Root, the uid of the user [`PCSCD_USER`] in [`ETC_PASSWD`] if there is one, and this
    /// process's real uid (`Uid:` of `/proc/self/status`), sorted, without duplicates (see
    /// the module docs). What cannot be read is left out; root is always in.
    pub fn default_uids() -> Vec<u32> {
        let read = |path: &str| fs::read_to_string(path).ok();
        default_uid_set(read(ETC_PASSWD).as_deref(), read("/proc/self/status").as_deref())
    }

    fn with_tables(allowed: impl IntoIterator<Item = u32>, tables: [PathBuf; 2]) -> ProcNetPeerCheck {
        let mut allowed: Vec<u32> = allowed.into_iter().collect();
        allowed.sort_unstable();
        allowed.dedup();
        ProcNetPeerCheck { allowed, tables }
    }

    /// The allowed uids, sorted.
    pub fn allowed(&self) -> &[u32] {
        &self.allowed
    }

    /// Every socket of both tables. A missing table is empty (no IPv6: no `tcp6`), unless
    /// both are missing (no `/proc`); any other read error fails the check.
    fn sockets(&self) -> Result<Vec<TcpSocket>, String> {
        let mut sockets = Vec::new();
        let mut missing = None;
        let mut read = 0;
        for table in &self.tables {
            match fs::read_to_string(table) {
                Ok(text) => {
                    read += 1;
                    sockets.extend(parse_tcp_table(&text));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    missing.get_or_insert_with(|| format!("cannot read {}: {error}", table.display()));
                }
                Err(error) => return Err(format!("cannot read {}: {error}", table.display())),
            }
        }
        match (read, missing) {
            (0, Some(reason)) => Err(reason),
            _ => Ok(sockets),
        }
    }
}

impl PeerCheck for ProcNetPeerCheck {
    fn check(&self, local: SocketAddr, peer: SocketAddr) -> PeerVerdict {
        if !is_loopback(&peer) {
            let reason = format!(
                "{} is not a loopback address, and the owner of a socket on another machine cannot be looked up",
                peer.ip()
            );
            return PeerVerdict::Unchecked { reason };
        }
        for lookup in 0..LOOKUPS {
            if lookup > 0 {
                thread::sleep(LOOKUP_PAUSE);
            }
            let sockets = match self.sockets() {
                Ok(sockets) => sockets,
                Err(reason) => return PeerVerdict::Refused(PeerRefusal::Failed(reason)),
            };
            let found = peer_sockets(&sockets, local, peer);
            if !found.is_empty() {
                return judge(&found, &self.allowed);
            }
        }
        PeerVerdict::Refused(PeerRefusal::NotFound)
    }
}

/// The verdict on the peer's sockets `found` (at least one): every one must be owned by an
/// allowed uid.
fn judge(found: &[TcpSocket], allowed: &[u32]) -> PeerVerdict {
    match found.iter().find(|socket| !allowed.contains(&socket.uid)) {
        Some(offender) => {
            PeerVerdict::Refused(PeerRefusal::NotAllowed { uid: offender.uid, allowed: allowed.to_vec() })
        }
        None => PeerVerdict::Allowed { uid: found[0].uid },
    }
}

/// One socket line of `/proc/net/tcp` or `/proc/net/tcp6`: what the peer check needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSocket {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    /// `st`: the TCP state ([`ESTABLISHED`], [`SYN_RECV`], ...).
    pub state: u8,
    pub uid: u32,
}

/// The sockets of a `/proc/net/tcp` or `/proc/net/tcp6` text, addresses read in this
/// machine's byte order. The header line and lines that do not parse are skipped.
pub fn parse_tcp_table(text: &str) -> Vec<TcpSocket> {
    parse_table(text, cfg!(target_endian = "little"))
}

/// [`parse_tcp_table`] for a machine of the given byte order (fixtures are little-endian).
fn parse_table(text: &str, little_endian: bool) -> Vec<TcpSocket> {
    text.lines().filter_map(|line| parse_line(line, little_endian)).collect()
}

fn parse_line(line: &str, little_endian: bool) -> Option<TcpSocket> {
    let mut fields = line.split_ascii_whitespace();
    let slot = fields.next()?.strip_suffix(':')?;
    if !digits(slot, 10) {
        return None;
    }
    let local = parse_endpoint(fields.next()?, little_endian)?;
    let remote = parse_endpoint(fields.next()?, little_endian)?;
    let state = fields.next()?;
    if state.len() != 2 || !digits(state, 16) {
        return None;
    }
    let state = u8::from_str_radix(state, 16).ok()?;
    // tx_queue:rx_queue, tr:tm->when, retrnsmt.
    fields.nth(2)?;
    let uid = fields.next()?;
    if !digits(uid, 10) {
        return None;
    }
    Some(TcpSocket { local, remote, state, uid: uid.parse().ok()? })
}

/// Whether `text` is non-empty and all digits of `radix` (10 or 16); `from_str_radix`
/// alone would take a sign.
fn digits(text: &str, radix: u32) -> bool {
    !text.is_empty() && text.chars().all(|c| c.is_digit(radix))
}

/// `ADDRESS:PORT` as the kernel prints it (see the module docs).
fn parse_endpoint(text: &str, little_endian: bool) -> Option<SocketAddr> {
    let (address, port) = text.split_once(':')?;
    if port.len() != 4 || !digits(port, 16) || !digits(address, 16) {
        return None;
    }
    let port = u16::from_str_radix(port, 16).ok()?;
    let ip = match address.len() {
        8 => IpAddr::V4(Ipv4Addr::from(word(address, little_endian)?)),
        32 => {
            let mut bytes = [0; 16];
            for (index, chunk) in bytes.as_chunks_mut::<4>().0.iter_mut().enumerate() {
                *chunk = word(&address[index * 8..index * 8 + 8], little_endian)?;
            }
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// The four bytes, in memory (network) order, of a 32-bit word the kernel printed as a
/// host-order number.
fn word(hex: &str, little_endian: bool) -> Option<[u8; 4]> {
    let value = u32::from_str_radix(hex, 16).ok()?;
    Some(if little_endian { value.to_le_bytes() } else { value.to_be_bytes() })
}

/// The sockets on the peer's side of the connection from `local` to `peer`: local address
/// `peer`, remote address `local`, compared in canonical form, in a live state
/// ([`LIVE_STATES`]).
pub fn peer_sockets(sockets: &[TcpSocket], local: SocketAddr, peer: SocketAddr) -> Vec<TcpSocket> {
    let (local, peer) = (canonical(local), canonical(peer));
    sockets
        .iter()
        .filter(|socket| {
            LIVE_STATES.contains(&socket.state) && canonical(socket.local) == peer && canonical(socket.remote) == local
        })
        .copied()
        .collect()
}

/// `addr` with an IPv4-mapped IPv6 address as IPv4, and without IPv6 flow and scope.
fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// The default allowed set from the texts of `/etc/passwd` and `/proc/self/status` (either
/// may be missing): root, [`PCSCD_USER`]'s uid, the real uid.
fn default_uid_set(passwd: Option<&str>, status: Option<&str>) -> Vec<u32> {
    let mut uids = vec![0];
    uids.extend(passwd.and_then(|text| passwd_uid(text, PCSCD_USER)));
    uids.extend(status.and_then(real_uid));
    uids.sort_unstable();
    uids.dedup();
    uids
}

/// The uid of user `name` in an `/etc/passwd` text (`passwd(5)`: `name:password:uid:gid:
/// gecos:home:shell`): the first line whose first field is exactly `name` and whose third
/// is a decimal number. Other lines (comments, NIS `+`/`-` entries, garbled ones) are
/// skipped. Users known only to other name services are not seen.
pub fn passwd_uid(passwd: &str, name: &str) -> Option<u32> {
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        if fields.next()? != name {
            return None;
        }
        let uid = fields.nth(1)?;
        if !digits(uid, 10) {
            return None;
        }
        uid.parse().ok()
    })
}

/// The real uid in a `/proc/<pid>/status` text: the first number of its `Uid:` line (real,
/// effective, saved set, file system; `Documentation/filesystems/proc.rst`).
pub fn real_uid(status: &str) -> Option<u32> {
    let rest = status.lines().find_map(|line| line.strip_prefix("Uid:"))?;
    let real = rest.split_ascii_whitespace().next()?;
    if !digits(real, 10) {
        return None;
    }
    real.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A `/proc/net/tcp` of a little-endian machine: the header, vpcd's two listeners, the
    /// card's connection to 35963 from port 0xA1B2 (41394) in both directions, a TIME_WAIT
    /// line of an older connection, a line cut short, a garbled one and an empty one.
    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:8C7B 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 31200 1 0000000000000000 100 0 0 10 0
   1: 00000000:8C7C 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 31201 1 0000000000000000 100 0 0 10 0
   2: 0100007F:8C7B 0100007F:A1B2 01 00000000:00000000 00:00000000 00000000     0        0 31310 1 0000000000000000 20 4 30 10 -1
   3: 0100007F:A1B2 0100007F:8C7B 01 00000000:00000000 00:00000000 00000000  1000        0 31309 1 0000000000000000 20 4 29 10 -1
   4: 0100007F:8C7B 0100007F:A1B3 06 00000000:00000000 03:00000F2A 00000000     0        0 0 3 0000000000000000
   5: 0100007F:8C7B 0100007F:A1B4 01 00000000:00000000
  xx: 0100007F:8C7B 0100007F:A1B5 01 00000000:00000000 00:00000000 00000000  1001        0 31311 1
   7: 0100007G:8C7B 0100007F:A1B6 01 00000000:00000000 00:00000000 00000000  1001        0 31312 1

";

    /// A `/proc/net/tcp6`: an impostor (uid 1001) on `[::1]:35963` with a client on
    /// `[::1]:45056`, and a dual-stack impostor on `[::]:35963` with an IPv4 client
    /// `127.0.0.1:41394` (IPv4-mapped).
    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:8C7B 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 41000 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:8C7B 00000000000000000000000001000000:B000 01 00000000:00000000 00:00000000 00000000  1001        0 41001 1 0000000000000000 20 4 30 10 -1
   2: 0000000000000000FFFF00000100007F:8C7B 0000000000000000FFFF00000100007F:A1B2 01 00000000:00000000 00:00000000 00000000  1001        0 41002 1 0000000000000000 20 4 30 10 -1
";

    fn addr(text: &str) -> SocketAddr {
        text.parse().expect("a valid address")
    }

    fn little(text: &str) -> Vec<TcpSocket> {
        parse_table(text, true)
    }

    #[test]
    fn ipv4_lines_parse_with_little_endian_addresses_and_plain_hex_ports() {
        let sockets = little(TCP);
        assert_eq!(sockets.len(), 5, "the header and the four bad lines are skipped: {sockets:#?}");
        assert_eq!(
            sockets[0],
            TcpSocket { local: addr("0.0.0.0:35963"), remote: addr("0.0.0.0:0"), state: 0x0A, uid: 0 }
        );
        assert_eq!(sockets[1].local, addr("0.0.0.0:35964"));
        assert_eq!(
            sockets[2],
            TcpSocket { local: addr("127.0.0.1:35963"), remote: addr("127.0.0.1:41394"), state: ESTABLISHED, uid: 0 }
        );
        assert_eq!(
            sockets[3],
            TcpSocket { local: addr("127.0.0.1:41394"), remote: addr("127.0.0.1:35963"), state: ESTABLISHED, uid: 1000 }
        );
        assert_eq!((sockets[4].state, sockets[4].uid), (0x06, 0), "TIME_WAIT prints uid 0");
    }

    #[test]
    fn a_big_endian_machine_prints_addresses_in_network_order() {
        let line = "   0: 7F000001:8C7B C0000201:0050 01 00000000:00000000 00:00000000 00000000   42        0 1 1";
        let sockets = parse_table(line, false);
        assert_eq!(sockets.len(), 1);
        assert_eq!((sockets[0].local, sockets[0].remote), (addr("127.0.0.1:35963"), addr("192.0.2.1:80")));
    }

    #[test]
    fn ipv6_lines_parse_as_four_little_endian_words_including_ipv4_mapped_addresses() {
        let sockets = little(TCP6);
        assert_eq!(sockets.len(), 3, "{sockets:#?}");
        assert_eq!((sockets[0].local, sockets[0].state, sockets[0].uid), (addr("[::]:35963"), 0x0A, 1001));
        assert_eq!((sockets[1].local, sockets[1].remote), (addr("[::1]:35963"), addr("[::1]:45056")));
        assert_eq!(
            (sockets[2].local, sockets[2].remote),
            (addr("[::ffff:127.0.0.1]:35963"), addr("[::ffff:127.0.0.1]:41394"))
        );
    }

    #[test]
    fn this_machines_byte_order_reads_a_table_written_in_it() {
        let encode = |ip: Ipv4Addr| format!("{:08X}", u32::from_ne_bytes(ip.octets()));
        let line = format!(
            "   0: {}:8C7B {}:A1B2 01 00000000:00000000 00:00000000 00000000     7        0 1 1",
            encode(Ipv4Addr::LOCALHOST),
            encode(Ipv4Addr::new(127, 0, 0, 2))
        );
        let sockets = parse_tcp_table(&line);
        assert_eq!(sockets.len(), 1);
        assert_eq!((sockets[0].local, sockets[0].remote), (addr("127.0.0.1:35963"), addr("127.0.0.2:41394")));
    }

    #[test]
    fn the_peers_socket_is_the_live_line_with_the_connection_reversed() {
        let sockets = little(TCP);
        let ours = (addr("127.0.0.1:41394"), addr("127.0.0.1:35963"));
        let found = peer_sockets(&sockets, ours.0, ours.1);
        assert_eq!(found, [sockets[2]], "vpcd's side, not ours, not the listener");
        // The TIME_WAIT line (uid 0) never counts.
        assert!(peer_sockets(&sockets, addr("127.0.0.1:41395"), ours.1).is_empty());
        // No line at all for another port.
        assert!(peer_sockets(&sockets, addr("127.0.0.1:50000"), ours.1).is_empty());
    }

    #[test]
    fn an_ipv4_connection_to_a_dual_stack_listener_is_found_in_tcp6_and_ipv6_in_tcp6() {
        let mut sockets = little(TCP);
        sockets.extend(little(TCP6));
        // The IPv4 connection matches vpcd's line in tcp and the mapped line in tcp6: two
        // owners, one of them not allowed.
        let found = peer_sockets(&sockets, addr("127.0.0.1:41394"), addr("127.0.0.1:35963"));
        assert_eq!(found.iter().map(|socket| socket.uid).collect::<Vec<_>>(), [0, 1001]);
        assert_eq!(
            judge(&found, &[0, 1000]),
            PeerVerdict::Refused(PeerRefusal::NotAllowed { uid: 1001, allowed: vec![0, 1000] }),
            "every match must be allowed"
        );
        // An IPv4-mapped connection (an IPv6 socket to ::ffff:127.0.0.1) matches the same.
        let mapped = peer_sockets(&sockets, addr("[::ffff:127.0.0.1]:41394"), addr("[::ffff:127.0.0.1]:35963"));
        assert_eq!(mapped, found);
        let ipv6 = peer_sockets(&sockets, addr("[::1]:45056"), addr("[::1]:35963"));
        assert_eq!(ipv6.iter().map(|socket| socket.uid).collect::<Vec<_>>(), [1001]);
    }

    #[test]
    fn the_verdict_allows_only_when_every_match_is_allowed() {
        let socket = |uid| TcpSocket { local: addr("127.0.0.1:1"), remote: addr("127.0.0.1:2"), state: 1, uid };
        assert_eq!(judge(&[socket(0)], &[0, 1000]), PeerVerdict::Allowed { uid: 0 });
        assert_eq!(judge(&[socket(1000), socket(1000)], &[0, 1000]), PeerVerdict::Allowed { uid: 1000 });
        assert_eq!(
            judge(&[socket(0), socket(65534)], &[0]),
            PeerVerdict::Refused(PeerRefusal::NotAllowed { uid: 65534, allowed: vec![0] })
        );
        assert_eq!(
            judge(&[socket(0)], &[]),
            PeerVerdict::Refused(PeerRefusal::NotAllowed { uid: 0, allowed: vec![] })
        );
    }

    #[test]
    fn the_real_uid_is_the_first_number_of_the_uid_line() {
        let status = "Name:\tlocalkeyd\nUmask:\t0077\nState:\tS (sleeping)\nUid:\t1000\t0\t0\t0\nGid:\t100\t100\t100\t100\n";
        assert_eq!(real_uid(status), Some(1000));
        assert_eq!(real_uid("Uid:\t0\t0\t0\t0\n"), Some(0));
        assert_eq!(real_uid("Name:\tx\n"), None);
        assert_eq!(real_uid("Uid:\t-1\n"), None);
        assert_eq!(real_uid("Uid:\n"), None);
    }

    /// An `/etc/passwd` as the test guest's Ubuntu 26.04 has it, around the sysusers user.
    const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
# a comment
pcscd-old:x:991:991::/:/usr/sbin/nologin
+pcscd::::::
garbled line
pcscd:x:990:990:PC/SC Smart Card Daemon:/:/usr/sbin/nologin
pcscd:x:992:992:a second entry is never read:/:/usr/sbin/nologin
";

    #[test]
    fn the_pcscd_user_is_found_by_its_exact_name() {
        assert_eq!(passwd_uid(PASSWD, "pcscd"), Some(990));
        assert_eq!(passwd_uid(PASSWD, "root"), Some(0));
        assert_eq!(passwd_uid(PASSWD, "nobody"), Some(65534));
        assert_eq!(passwd_uid(PASSWD, "pcsc"), None, "a prefix is not the name");
        assert_eq!(passwd_uid(PASSWD, "+pcscd"), None, "a NIS line has no uid");
        assert_eq!(passwd_uid("pcscd:x:-1:0::/:\npcscd:x::0::/:\n", "pcscd"), None);
        assert_eq!(passwd_uid("", "pcscd"), None);
    }

    #[test]
    fn the_default_set_is_root_the_pcscd_user_and_the_real_uid() {
        let status = "Name:\tlocalkeyd\nUid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(default_uid_set(Some(PASSWD), Some(status)), [0, 990, 1000]);
        assert_eq!(default_uid_set(Some(PASSWD), Some("Uid:\t0\t0\t0\t0\n")), [0, 990], "root once");
        assert_eq!(default_uid_set(Some("root:x:0:0::/:\n"), Some(status)), [0, 1000], "no pcscd user");
        assert_eq!(default_uid_set(None, None), [0], "root is always in");
    }

    #[test]
    fn refusals_read_as_notice_text() {
        let refusal = PeerRefusal::NotAllowed { uid: 1001, allowed: vec![0, 1000] };
        assert_eq!(refusal.to_string(), "is owned by uid 1001, not an allowed uid (0, 1000)");
        assert!(PeerRefusal::NotFound.to_string().contains("/proc/net/tcp"));
        assert_eq!(PeerRefusal::Failed("no".into()).to_string(), "cannot be checked: no");
        assert_eq!(uid_list(&[0]), "0");
    }

    /// Fixture tables in a fresh directory under the temporary directory.
    struct Tables(PathBuf);

    impl Tables {
        fn new(tcp: Option<&str>, tcp6: Option<&str>) -> Tables {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir()
                .join(format!("lkvpcd-peer{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst)));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir(&dir).expect("a test directory");
            for (name, text) in [("tcp", tcp), ("tcp6", tcp6)] {
                if let Some(text) = text {
                    fs::write(dir.join(name), text).expect("a fixture file");
                }
            }
            Tables(dir)
        }

        fn check(&self, allowed: &[u32]) -> ProcNetPeerCheck {
            ProcNetPeerCheck::with_tables(allowed.iter().copied(), [self.0.join("tcp"), self.0.join("tcp6")])
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Tables {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn the_check_reads_both_tables_and_refuses_a_peer_it_cannot_find() {
        let ours = (addr("127.0.0.1:41394"), addr("127.0.0.1:35963"));
        let both = Tables::new(Some(TCP), Some(TCP6));
        assert_eq!(
            both.check(&[1000, 0]).check(ours.0, ours.1),
            PeerVerdict::Refused(PeerRefusal::NotAllowed { uid: 1001, allowed: vec![0, 1000] })
        );
        assert_eq!(both.check(&[0, 1001, 0]).allowed(), [0, 1001], "sorted, without duplicates");
        assert_eq!(both.check(&[0, 1001]).check(ours.0, ours.1), PeerVerdict::Allowed { uid: 0 });
        // Without IPv6 there is no tcp6.
        let v4 = Tables::new(Some(TCP), None);
        assert_eq!(v4.check(&[0]).check(ours.0, ours.1), PeerVerdict::Allowed { uid: 0 });
        let started = std::time::Instant::now();
        assert_eq!(
            v4.check(&[0]).check(addr("127.0.0.1:41395"), ours.1),
            PeerVerdict::Refused(PeerRefusal::NotFound),
            "only a TIME_WAIT line"
        );
        assert!(started.elapsed() >= LOOKUP_PAUSE * (LOOKUPS - 1), "looked up {LOOKUPS} times");
        // No /proc at all.
        let none = Tables::new(None, None);
        let PeerVerdict::Refused(PeerRefusal::Failed(reason)) = none.check(&[0]).check(ours.0, ours.1) else {
            panic!("a check without tables refuses");
        };
        assert!(reason.starts_with("cannot read ") && reason.contains(&none.path().display().to_string()), "{reason}");
    }

    #[test]
    fn a_peer_on_another_machine_is_left_unchecked() {
        let tables = Tables::new(Some(TCP), Some(TCP6));
        let verdict = tables.check(&[0]).check(addr("192.0.2.7:50000"), addr("192.0.2.1:35963"));
        assert!(matches!(verdict, PeerVerdict::Unchecked { ref reason } if reason.contains("192.0.2.1")), "{verdict:?}");
    }

    #[test]
    fn other_systems_do_not_check_and_say_why() {
        let verdict = NoPeerCheck.check(addr("127.0.0.1:1"), addr("127.0.0.1:2"));
        assert!(matches!(verdict, PeerVerdict::Unchecked { ref reason } if reason.contains("only Linux")), "{verdict:?}");
    }

    /// The real tables of a real kernel: the owner of a loopback listener of this process
    /// is found before and after `accept`, for IPv4, for an IPv4 client of a dual-stack
    /// IPv6 listener (an IPv4-mapped line in tcp6) and for IPv6, where the system has them.
    #[cfg(target_os = "linux")]
    #[test]
    fn on_linux_the_owner_of_a_loopback_listener_of_this_process_is_found() {
        use std::net::{TcpListener, TcpStream};

        let status = fs::read_to_string("/proc/self/status").expect("Linux has /proc/self/status");
        let own = real_uid(&status).expect("a Uid line");
        let allowed = ProcNetPeerCheck::new([own]);
        let other = ProcNetPeerCheck::new([own.wrapping_add(1)]);
        let connect = |listener: &TcpListener, host: &str| {
            let port = listener.local_addr().expect("bound").port();
            TcpStream::connect((host, port)).ok()
        };
        let ends = |stream: &TcpStream| (stream.local_addr().expect("bound"), stream.peer_addr().expect("connected"));

        let listener = TcpListener::bind("127.0.0.1:0").expect("an ephemeral loopback port");
        let stream = connect(&listener, "127.0.0.1").expect("loopback connects");
        let (local, peer) = ends(&stream);
        assert_eq!(allowed.check(local, peer), PeerVerdict::Allowed { uid: own }, "before accept");
        let accepted = listener.accept().expect("the listener accepts");
        assert_eq!(allowed.check(local, peer), PeerVerdict::Allowed { uid: own }, "after accept");
        assert_eq!(
            other.check(local, peer),
            PeerVerdict::Refused(PeerRefusal::NotAllowed { uid: own, allowed: vec![own.wrapping_add(1)] })
        );
        drop((stream, accepted));

        match TcpListener::bind("[::]:0") {
            Ok(dual) => match connect(&dual, "127.0.0.1") {
                Some(stream) => {
                    let (local, peer) = ends(&stream);
                    assert_eq!(allowed.check(local, peer), PeerVerdict::Allowed { uid: own }, "IPv4-mapped in tcp6");
                }
                None => eprintln!("skipped: [::] does not take IPv4 clients here (bindv6only)"),
            },
            Err(error) => eprintln!("skipped: no IPv6 listener ({error})"),
        }
        match TcpListener::bind("[::1]:0") {
            Ok(v6) => {
                let stream = connect(&v6, "::1").expect("[::1] connects");
                let (local, peer) = ends(&stream);
                assert_eq!(allowed.check(local, peer), PeerVerdict::Allowed { uid: own }, "IPv6");
            }
            Err(error) => eprintln!("skipped: no IPv6 loopback ({error})"),
        }
    }

    #[test]
    fn the_default_uids_are_root_the_pcscd_user_and_this_process() {
        let uids = ProcNetPeerCheck::default_uids();
        assert_eq!(uids.first(), Some(&0));
        if let Some(pcscd) = fs::read_to_string(ETC_PASSWD).ok().and_then(|text| passwd_uid(&text, PCSCD_USER)) {
            assert!(uids.contains(&pcscd), "{uids:?} has {pcscd}");
        }
        if cfg!(target_os = "linux") {
            let status = fs::read_to_string("/proc/self/status").expect("Linux has /proc/self/status");
            let own = real_uid(&status).expect("a Uid line");
            assert!(uids.contains(&own), "{uids:?} has {own}");
        }
    }
}
