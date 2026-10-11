//! Connecting to vpcd (`docs/PROGRAM.md` "lk-vpcd": an I/O seam whose real implementation
//! is `TcpStream::connect` with a timeout to the configured address).
//!
//! The card is the TCP client: vpcd "opens a socket for vpicc and waits for incoming
//! connections" (virtualsmartcard README; `opensock` binds and listens, `vicc_connect`
//! accepts, `vpcd.c`). vpcd's other mode, where it connects to a listening card
//! (`DEVICENAME host:port`, vicc `--reversed`), is not supported.

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// How long one connection attempt may take. vpcd on this machine accepts or refuses at
/// once; the bound matters for a remote address that does not answer.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Opens connections to vpcd. Each call is one new connection: one card insertion.
pub trait Connector: Send + fmt::Debug {
    /// Connect to vpcd.
    fn connect(&mut self) -> io::Result<TcpStream>;
    /// The address connected to, for notices and the loopback check.
    fn addr(&self) -> SocketAddr;
}

/// The real [`Connector`]: `TcpStream::connect_timeout` to one address, with
/// `TCP_NODELAY` set as vpcd sets it on its side (`opensock`, `vpcd.c`): every message is
/// one small write that waits for an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpConnector {
    addr: SocketAddr,
    timeout: Duration,
}

impl TcpConnector {
    /// Connect to `addr` with [`CONNECT_TIMEOUT`].
    pub fn new(addr: SocketAddr) -> TcpConnector {
        TcpConnector { addr, timeout: CONNECT_TIMEOUT }
    }

    /// Connect to `addr`, giving up on an attempt after `timeout` (at least 1 ms).
    pub fn with_timeout(addr: SocketAddr, timeout: Duration) -> TcpConnector {
        TcpConnector { addr, timeout: timeout.max(Duration::from_millis(1)) }
    }

    /// The timeout of one attempt.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

impl Connector for TcpConnector {
    fn connect(&mut self) -> io::Result<TcpStream> {
        let stream = TcpStream::connect_timeout(&self.addr, self.timeout)?;
        stream.set_nodelay(true)?;
        Ok(stream)
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }
}

/// Whether `addr` stays on this machine: a loopback address, also as an IPv4-mapped IPv6
/// address. Anything else carries the APDUs unencrypted over a network
/// (`docs/PROGRAM.md` "lk-vpcd": allowed, with a warning).
pub fn is_loopback(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => ip.to_canonical().is_loopback(),
    }
}

/// The address of `--vpcd-addr HOST:PORT`: a numeric address, or a host name resolved
/// once, preferring IPv4 because vpcd listens on IPv4 only (`opensock` binds an
/// `AF_INET` socket to `INADDR_ANY`, `vpcd.c`).
pub fn resolve(text: &str) -> io::Result<SocketAddr> {
    if let Ok(addr) = text.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let addrs: Vec<SocketAddr> = text.to_socket_addrs()?.collect();
    addrs
        .iter()
        .find(|addr| addr.is_ipv4())
        .or_else(|| addrs.first())
        .copied()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{text} has no address")))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{Ipv4Addr, Ipv6Addr, TcpListener};

    #[test]
    fn loopback_addresses_are_recognised_in_every_form() {
        let loopback = ["127.0.0.1:35963", "127.1.2.3:1", "[::1]:35963", "[::ffff:127.0.0.1]:35963"];
        for text in loopback {
            let addr: SocketAddr = text.parse().expect("a valid address");
            assert!(is_loopback(&addr), "{text}");
        }
        let remote = ["192.0.2.1:35963", "0.0.0.0:35963", "[2001:db8::1]:35963", "[::ffff:192.0.2.1]:35963", "[::]:1"];
        for text in remote {
            let addr: SocketAddr = text.parse().expect("a valid address");
            assert!(!is_loopback(&addr), "{text}");
        }
    }

    #[test]
    fn numeric_addresses_resolve_without_a_lookup() {
        assert_eq!(resolve("127.0.0.1:35963").ok(), Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 35963))));
        assert_eq!(resolve("[::1]:9").ok(), Some(SocketAddr::from((Ipv6Addr::LOCALHOST, 9))));
    }

    #[test]
    fn an_address_without_a_port_is_refused() {
        assert!(resolve("127.0.0.1").is_err());
        assert!(resolve("").is_err());
    }

    #[test]
    fn localhost_resolves_to_a_loopback_address() {
        // Resolved from the hosts file; no network involved.
        let addr = resolve("localhost:35963").expect("localhost resolves");
        assert!(is_loopback(&addr), "{addr}");
        assert_eq!(addr.port(), 35963);
    }

    #[test]
    fn the_real_connector_connects_with_nodelay_and_names_its_address() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("an ephemeral port on loopback");
        let addr = listener.local_addr().expect("bound");
        let mut connector = TcpConnector::new(addr);
        assert_eq!(connector.addr(), addr);
        assert_eq!(connector.timeout(), CONNECT_TIMEOUT);
        let stream = connector.connect().expect("the listener accepts");
        assert!(stream.nodelay().expect("readable"));
        assert_eq!(stream.peer_addr().ok(), Some(addr));
    }

    #[test]
    fn the_real_connector_reports_a_refused_connection() {
        let addr = {
            let listener = TcpListener::bind("127.0.0.1:0").expect("an ephemeral port on loopback");
            listener.local_addr().expect("bound")
        };
        // The listener is gone: nothing listens on the port.
        let error = TcpConnector::with_timeout(addr, Duration::from_secs(10)).connect().expect_err("nothing listens");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        assert_eq!(TcpConnector::with_timeout(addr, Duration::ZERO).timeout(), Duration::from_millis(1));
    }
}
