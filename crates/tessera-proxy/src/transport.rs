//! Pluggable outbound transport for the onward leg of a tunnel.
//!
//! [`Dialer`] abstracts *how* the next TCP hop to a `host:port` is opened:
//! directly ([`TcpDialer`]) or through a SOCKS5 proxy such as Tor
//! ([`TorSocksDialer`]). The exit uses it for the destination hop; the client
//! uses [`TorSocksDialer`] to reach an exit's `.onion` address (the onion lane).
//!
//! Each impl decides whether to resolve the name locally — the SOCKS5 dialer
//! deliberately passes the hostname **unresolved** so the proxy resolves it from
//! its own vantage point (no local DNS leak), which is why [`Dialer::connect`]
//! takes a `&str` host rather than a resolved [`std::net::SocketAddr`].
//!
//! Std-only, blocking. Every dialer applies the crate's connect/idle timeouts so
//! a black-holed destination or a hung proxy cannot pin a handler thread (S3).

use std::io::{Error, Read, Result, Write};
use std::net::{TcpStream, ToSocketAddrs};

use crate::{CONNECT_TIMEOUT, SOCKET_TIMEOUT};

/// Opens the onward TCP leg of a tunnel to `host:port`.
///
/// `host` is the target verbatim — an IP literal or a name. A [`TcpDialer`]
/// resolves it locally and connects; a [`TorSocksDialer`] passes it **unresolved**
/// to the SOCKS5 proxy. Implementors MUST apply the crate timeouts so a stalled
/// peer cannot pin a handler. `Send + Sync` because a dialer is cloned/shared
/// across the proxy's per-connection worker threads.
pub trait Dialer: Send + Sync {
    /// Connect to `host:port`, returning a stream positioned for the data phase.
    fn connect(&self, host: &str, port: u16) -> Result<TcpStream>;
}

/// Dials the destination directly over TCP, bounded by the crate's connect
/// timeout and armed with the idle socket timeout.
///
/// Does NO SSRF/target gating of its own — the caller is responsible for the
/// target policy (and, for a name, resolve-then-pin) *before* handing a host
/// here. In the exit's gated path it is only ever given an already-pinned IP
/// literal, so its `to_socket_addrs` performs no DNS.
pub struct TcpDialer;

impl Dialer for TcpDialer {
    fn connect(&self, host: &str, port: u16) -> Result<TcpStream> {
        let addr = (host, port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| Error::other("dial target resolved to no address"))?;
        let s = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)?;
        let _ = s.set_read_timeout(Some(SOCKET_TIMEOUT));
        let _ = s.set_write_timeout(Some(SOCKET_TIMEOUT));
        Ok(s)
    }
}

/// Dials every target through a SOCKS5 proxy (e.g. Tor at `127.0.0.1:9050`),
/// passing the hostname **unresolved** so the proxy resolves it (no local DNS
/// leak). This is also the dialer the client uses to reach an exit's `.onion`.
pub struct TorSocksDialer {
    proxy: String,
}

impl TorSocksDialer {
    /// `proxy` is a `HOST:PORT` SOCKS5 endpoint; it is resolved per-dial.
    pub fn new(proxy: impl Into<String>) -> Self {
        Self {
            proxy: proxy.into(),
        }
    }
}

impl Dialer for TorSocksDialer {
    fn connect(&self, host: &str, port: u16) -> Result<TcpStream> {
        socks5_connect(&self.proxy, host, port)
    }
}

/// Minimal SOCKS5 CONNECT (no auth, domain target) — enough to reach any host
/// (including a `.onion` or `api.anthropic.com`) through a SOCKS5/Tor port.
fn socks5_connect(proxy: &str, host: &str, port: u16) -> Result<TcpStream> {
    // Bound both the proxy dial and the handshake reads (S3): a black-holed or
    // hung SOCKS proxy must not pin this handler.
    let addr = proxy
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| Error::other("SOCKS5: proxy address resolved to nothing"))?;
    let mut s = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)?;
    let _ = s.set_read_timeout(Some(SOCKET_TIMEOUT));
    let _ = s.set_write_timeout(Some(SOCKET_TIMEOUT));
    s.write_all(&[0x05, 0x01, 0x00])?;
    let mut method = [0u8; 2];
    s.read_exact(&mut method)?;
    if method != [0x05, 0x00] {
        return Err(Error::other("SOCKS5: no acceptable method"));
    }
    let host_bytes = host.as_bytes();
    if host_bytes.len() > 255 {
        return Err(Error::other("SOCKS5: host too long"));
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8];
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head)?;
    if head[1] != 0x00 {
        return Err(Error::other(format!(
            "SOCKS5 connect failed (REP={})",
            head[1]
        )));
    }
    let bnd = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l)?;
            l[0] as usize
        }
        _ => return Err(Error::other("SOCKS5: bad ATYP")),
    };
    let mut skip = vec![0u8; bnd + 2];
    s.read_exact(&mut skip)?;
    Ok(s)
}
