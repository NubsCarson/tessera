//! Target/egress policy for the credential-gated exit: the cheap,
//! pre-credential admission step that decides whether the exit is even allowed
//! to open a tunnel to a requested `CONNECT host:port`.
//!
//! [`tessera_origin::OriginGuard`] answers "is this credential valid?" and
//! deliberately never looks at the destination — that is the project's
//! "admit on the credential, never the IP" thesis. This module answers the
//! orthogonal *transport* question: "is this destination one this exit may
//! dial at all?" Keeping the two separate preserves the guard's thesis (the
//! credential is judged blind to the target) while still refusing to let the
//! exit become an SSRF oracle for its own private network / cloud-metadata
//! endpoint.
//!
//! The gate is two-phase, mirroring `OriginGuard::check`'s cheap-before-expensive
//! ordering:
//!
//! 1. `TargetPolicy::precheck` — **no network**. Enforces the port allowlist
//!    and, for an IP literal in the `CONNECT` target, classifies it immediately.
//!    Runs *before* the expensive credential verification, so an unauthenticated
//!    peer cannot force crypto work with a junk target.
//! 2. `TargetPolicy::resolve_pinned` — **does DNS**. Runs *after* a request is
//!    credentialed, so an unauthenticated peer can never make the exit perform a
//!    lookup. Resolves the hostname, rejects the whole request if **any** resolved
//!    address is blocked, and returns the single pinned [`IpAddr`] to dial — so
//!    the address that was checked is the address that is connected to (DNS
//!    rebinding defense).
//!
//! Address classification ([`is_blocked_addr`]) is pure, deterministic, and
//! covers the IANA special-purpose ranges for IPv4 and IPv6, including the
//! embedded-IPv4 forms (IPv4-mapped, NAT64, 6to4) that defeat naive checks. The
//! classifier is enumerate-special-then-block: the IANA special-purpose registry
//! is exhaustive, so the complement is exactly the globally-routable space.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Why the target policy refused a `CONNECT` target.
///
/// Distinct from [`tessera_origin::RejectReason`], which is about the
/// *credential*. These are *transport* refusals — the credential may be perfectly
/// valid — and the exit surfaces them to the client as `403 Forbidden`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetReject {
    /// The target port is not in this exit's allowed-port set.
    DisallowedPort,
    /// The target address is, or resolves to, a private / loopback / link-local /
    /// reserved / cloud-metadata address an exit must never dial (SSRF guard).
    BlockedAddress,
    /// The target host could not be resolved to any address (or resolution
    /// exceeded the bounded timeout — failing closed).
    Unresolvable,
    /// The `CONNECT` target was syntactically unusable (no host, bad/empty port).
    MalformedTarget,
}

impl TargetReject {
    /// A short, human-facing label, interpolated into the `403` status line.
    pub fn label(&self) -> &'static str {
        match self {
            TargetReject::DisallowedPort => "disallowed port",
            TargetReject::BlockedAddress => "blocked address",
            TargetReject::Unresolvable => "unresolvable host",
            TargetReject::MalformedTarget => "malformed target",
        }
    }
}

impl std::fmt::Display for TargetReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

impl std::error::Error for TargetReject {}

/// Which destination ports an exit is willing to open a tunnel to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortRule {
    /// Any port. The permissive library/demo default; preserves existing tests
    /// and the local relay loop, which tunnel to ephemeral loopback ports.
    Any,
    /// Only these ports. The secure default is `{443}`.
    Only(Vec<u16>),
}

impl PortRule {
    /// Whether `port` is permitted under this rule.
    pub fn allows(&self, port: u16) -> bool {
        match self {
            PortRule::Any => true,
            PortRule::Only(ports) => ports.contains(&port),
        }
    }
}

/// The result of the cheap, no-network `TargetPolicy::precheck` phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Precheck {
    /// The target was an IP literal, already classified as allowed. Dial this.
    Pinned(IpAddr),
    /// The target was a hostname; resolution is deferred to after the credential
    /// check (see `TargetPolicy::resolve_pinned`).
    Hostname(String),
}

/// The exit's target/egress policy: the port allowlist, the SSRF address guard
/// toggle, the bounded-resolution knobs, and the optional per-tunnel caps.
///
/// Build [`TargetPolicy::unrestricted`] for the demo/library default (any port,
/// no address blocking — preserves existing behavior), or
/// [`TargetPolicy::secure`] for a deployed exit (only `:443`, block private/
/// reserved addresses, resolve-then-pin).
#[derive(Debug, Clone)]
pub struct TargetPolicy {
    ports: PortRule,
    block_private: bool,
    resolve_timeout: Duration,
    max_resolved_addrs: usize,
    max_tunnel_bytes: Option<u64>,
    max_tunnel_duration: Option<Duration>,
}

impl TargetPolicy {
    /// No restrictions: any port, no address classification, no caps. This is the
    /// library/demo default and exactly preserves the pre-policy behavior (so the
    /// existing in-process tests and the 2-hop relay loop, which tunnel to
    /// ephemeral loopback ports, keep passing unchanged).
    pub fn unrestricted() -> Self {
        Self {
            ports: PortRule::Any,
            block_private: false,
            resolve_timeout: Duration::from_secs(5),
            max_resolved_addrs: 16,
            max_tunnel_bytes: None,
            max_tunnel_duration: None,
        }
    }

    /// Secure-by-default for a deployed exit: only `:443`, block private /
    /// loopback / link-local / reserved / cloud-metadata addresses, and
    /// resolve-then-pin hostnames against DNS rebinding. Per-tunnel byte/time caps
    /// are off by default (opt in with [`with_caps`](Self::with_caps)).
    pub fn secure() -> Self {
        Self {
            ports: PortRule::Only(vec![443]),
            block_private: true,
            resolve_timeout: Duration::from_secs(5),
            max_resolved_addrs: 16,
            max_tunnel_bytes: None,
            max_tunnel_duration: None,
        }
    }

    /// Override the allowed-port rule (e.g. from `TESSERA_ALLOWED_PORTS`).
    pub fn with_ports(mut self, ports: PortRule) -> Self {
        self.ports = ports;
        self
    }

    /// Override the per-tunnel caps: a total-bytes ceiling and/or a wall-clock
    /// lifetime. `None` leaves a cap disabled.
    pub fn with_caps(mut self, max_bytes: Option<u64>, max_duration: Option<Duration>) -> Self {
        self.max_tunnel_bytes = max_bytes;
        self.max_tunnel_duration = max_duration;
        self
    }

    /// The optional per-tunnel byte ceiling.
    pub fn max_tunnel_bytes(&self) -> Option<u64> {
        self.max_tunnel_bytes
    }

    /// The optional per-tunnel wall-clock lifetime.
    pub fn max_tunnel_duration(&self) -> Option<Duration> {
        self.max_tunnel_duration
    }

    /// A short label for the operator-facing `--check` summary.
    pub fn label(&self) -> String {
        let ports = match &self.ports {
            PortRule::Any => "any".to_string(),
            PortRule::Only(p) => p
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(","),
        };
        let addr = if self.block_private {
            "block-private"
        } else {
            "allow-any-addr"
        };
        format!("ports={ports},{addr}")
    }

    /// Phase 1 — cheap, no network. Enforce the port allowlist and classify an IP
    /// literal immediately. A hostname is returned for deferred resolution.
    pub(crate) fn precheck(&self, host: &str, port: u16) -> Result<Precheck, TargetReject> {
        if !self.ports.allows(port) {
            return Err(TargetReject::DisallowedPort);
        }
        // Strip the brackets of an IPv6 literal (`[::1]` -> `::1`).
        let h = host
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(host);
        if h.is_empty() {
            return Err(TargetReject::MalformedTarget);
        }
        // An IP literal can be classified right now, with no DNS.
        if let Ok(ip) = h.parse::<IpAddr>() {
            if self.block_private && is_blocked_addr(ip) {
                return Err(TargetReject::BlockedAddress);
            }
            return Ok(Precheck::Pinned(ip));
        }
        Ok(Precheck::Hostname(h.to_string()))
    }

    /// Phase 2 — does DNS (call only after the credential check passed). Resolve
    /// the hostname under a bounded timeout, reject the whole request if **any**
    /// resolved address is blocked, and return the single pinned address to dial.
    ///
    /// Returning one concrete [`IpAddr`] is the rebinding defense: the caller
    /// connects to *this* address, not by re-resolving the name, so the address
    /// that was classified is the address that is dialed.
    pub(crate) fn resolve_pinned(&self, host: &str, port: u16) -> Result<IpAddr, TargetReject> {
        let addrs = self.resolve_bounded(host, port)?;
        if addrs.is_empty() {
            return Err(TargetReject::Unresolvable);
        }
        // Fail closed on the union: a multi-record answer with one private IP is a
        // rebinding/SSRF attempt — deny the whole request, do not cherry-pick.
        if self.block_private && first_blocked(&addrs).is_some() {
            return Err(TargetReject::BlockedAddress);
        }
        Ok(addrs[0])
    }

    /// Resolve `host:port` to a bounded set of IPs under a hard timeout, using the
    /// std resolver in a worker thread. `std::net::ToSocketAddrs` has no timeout
    /// knob, so a slow/hostile authoritative server could otherwise pin the
    /// handler thread; we cap our own wait and fail closed on timeout. Resolution
    /// only runs post-credential, so the worker volume is rate-limited. On our
    /// timeout the worker is detached and runs until the OS resolver gives up, so
    /// the live-thread ceiling is not `MAX_INFLIGHT` but
    /// `MAX_INFLIGHT * (os_resolver_timeout / resolve_timeout)` — still bounded,
    /// but a multiple; tighten `resolve_timeout` or add a resolver-thread
    /// semaphore if that ceiling matters for a given deployment.
    fn resolve_bounded(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, TargetReject> {
        let host = host.to_string();
        let timeout = self.resolve_timeout;
        let max = self.max_resolved_addrs;
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let resolved = (host.as_str(), port)
                .to_socket_addrs()
                .map(|it| it.map(|s| s.ip()).take(max).collect::<Vec<_>>());
            let _ = tx.send(resolved);
        });
        match rx.recv_timeout(timeout) {
            Ok(Ok(addrs)) => Ok(addrs),
            // Resolver error, or timeout / worker gone: fail closed.
            Ok(Err(_)) | Err(_) => Err(TargetReject::Unresolvable),
        }
    }
}

/// The first address in `addrs` that [`is_blocked_addr`] rejects, if any. This is
/// the resolve-then-pin union check: a hostname is refused if **any** resolved
/// address is blocked (fail-closed on the union, never cherry-pick a good one).
fn first_blocked(addrs: &[IpAddr]) -> Option<IpAddr> {
    addrs.iter().copied().find(|ip| is_blocked_addr(*ip))
}

/// Whether `ip` is in an IANA special-purpose range an exit must never dial:
/// private, loopback, link-local (incl. the `169.254.169.254` cloud-metadata
/// endpoint), CGNAT, benchmarking, documentation, reserved, multicast,
/// broadcast, ULA, and the embedded-IPv4 IPv6 forms (IPv4-mapped, NAT64, 6to4).
///
/// Pure and deterministic. The complement is the globally-routable space.
pub fn is_blocked_addr(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_blocked(v4),
        IpAddr::V6(v6) => v6_blocked(v6),
    }
}

/// IPv4 special-purpose classification (IANA registry, exhaustive).
fn v4_blocked(a: Ipv4Addr) -> bool {
    let [a0, a1, a2, _a3] = a.octets();
    // 0.0.0.0/8 — "this host on this network"
    a0 == 0
        // 10.0.0.0/8 — RFC1918 private
        || a0 == 10
        // 100.64.0.0/10 — RFC6598 CGNAT / shared address space
        || (a0 == 100 && (a1 & 0xC0) == 64)
        // 127.0.0.0/8 — loopback (the whole /8, not just 127.0.0.1)
        || a0 == 127
        // 169.254.0.0/16 — link-local (incl. 169.254.169.254 cloud metadata)
        || (a0 == 169 && a1 == 254)
        // 172.16.0.0/12 — RFC1918 private
        || (a0 == 172 && (a1 & 0xF0) == 16)
        // 192.0.0.0/24 — IETF protocol assignments (incl. NAT64 well-known)
        || (a0 == 192 && a1 == 0 && a2 == 0)
        // 192.0.2.0/24 — TEST-NET-1
        || (a0 == 192 && a1 == 0 && a2 == 2)
        // 192.31.196.0/24 — AS112-v4
        || (a0 == 192 && a1 == 31 && a2 == 196)
        // 192.52.193.0/24 — AMT
        || (a0 == 192 && a1 == 52 && a2 == 193)
        // 192.88.99.0/24 — deprecated 6to4 relay anycast
        || (a0 == 192 && a1 == 88 && a2 == 99)
        // 192.168.0.0/16 — RFC1918 private
        || (a0 == 192 && a1 == 168)
        // 192.175.48.0/24 — AS112 direct delegation
        || (a0 == 192 && a1 == 175 && a2 == 48)
        // 198.18.0.0/15 — benchmarking
        || (a0 == 198 && (a1 & 0xFE) == 18)
        // 198.51.100.0/24 — TEST-NET-2
        || (a0 == 198 && a1 == 51 && a2 == 100)
        // 203.0.113.0/24 — TEST-NET-3
        || (a0 == 203 && a1 == 0 && a2 == 113)
        // 224.0.0.0/4 — multicast
        || (a0 & 0xF0) == 224
        // 240.0.0.0/4 — reserved / future use (incl. 255.255.255.255 broadcast)
        || (a0 & 0xF0) == 240
}

/// IPv6 special-purpose classification. Canonicalizes embedded-IPv4 forms first
/// (IPv4-mapped / NAT64 / 6to4) and re-classifies the inner address as IPv4, so
/// e.g. `::ffff:127.0.0.1` and `2002:7f00:1::` are blocked.
fn v6_blocked(a: Ipv6Addr) -> bool {
    // ::ffff:0:0/96 — IPv4-mapped: classify purely as the embedded IPv4.
    if let Some(v4) = a.to_ipv4_mapped() {
        return v4_blocked(v4);
    }
    // ::/128 unspecified, ::1/128 loopback (handle before the ::/96 branch).
    if a == Ipv6Addr::UNSPECIFIED || a == Ipv6Addr::LOCALHOST {
        return true;
    }
    let seg = a.segments();
    // ::/96 — deprecated IPv4-compatible addresses (e.g. ::127.0.0.1). Block all.
    if seg[..6].iter().all(|&s| s == 0) {
        return true;
    }
    // 64:ff9b::/96 (NAT64 well-known) + 64:ff9b:1::/48 (local NAT64).
    if seg[0] == 0x0064 && seg[1] == 0xff9b {
        if seg[2] == 0 && seg[3] == 0 && seg[4] == 0 && seg[5] == 0 {
            return v4_blocked(embedded_v4(seg[6], seg[7]));
        }
        return true;
    }
    // 2002::/16 — 6to4. Deprecated (RFC7526), so block the whole range; no
    // legitimate egress target is reachable via 6to4, and blocking all of it also
    // closes every embedded-IPv4 SSRF path (e.g. 2002:7f00:1:: == 127.0.0.1).
    if seg[0] == 0x2002 {
        return true;
    }
    // 100::/64 — discard-only.
    if seg[0] == 0x0100 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0 {
        return true;
    }
    // 2001::/23 — IETF protocol assignments (Teredo, benchmarking, ORCHID...).
    if seg[0] == 0x2001 && (seg[1] & 0xFE00) == 0 {
        return true;
    }
    // 2001:db8::/32 — documentation.
    if seg[0] == 0x2001 && seg[1] == 0x0db8 {
        return true;
    }
    // 3fff::/20 — documentation (RFC9637).
    if seg[0] == 0x3fff && (seg[1] & 0xF000) == 0 {
        return true;
    }
    // 5f00::/16 — SRv6 SIDs (RFC9602).
    if seg[0] == 0x5f00 {
        return true;
    }
    // fc00::/7 — Unique Local Addresses (ULA), covers fc00::/8 and fd00::/8.
    if (seg[0] & 0xFE00) == 0xFC00 {
        return true;
    }
    // fe80::/10 — link-local unicast.
    if (seg[0] & 0xFFC0) == 0xFE80 {
        return true;
    }
    // fec0::/10 — deprecated site-local.
    if (seg[0] & 0xFFC0) == 0xFEC0 {
        return true;
    }
    // ff00::/8 — multicast.
    if (seg[0] & 0xFF00) == 0xFF00 {
        return true;
    }
    false
}

/// Reconstruct the IPv4 address embedded in two IPv6 segments (NAT64 low 32 bits,
/// or 6to4 middle 32 bits).
fn embedded_v4(hi: u16, lo: u16) -> Ipv4Addr {
    Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn must_block_ipv4_special_ranges() {
        for s in [
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "100.127.255.255",
            "127.0.0.1",
            "127.1.2.3",
            "169.254.0.1",
            "169.254.169.254", // cloud metadata — the #1 SSRF target
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.170", // NAT64 well-known
            "192.0.2.1",   // TEST-NET-1
            "192.88.99.1", // 6to4 relay anycast
            "192.168.1.1",
            "198.18.0.1", // benchmarking
            "198.19.255.255",
            "198.51.100.7", // TEST-NET-2
            "203.0.113.7",  // TEST-NET-3
            "224.0.0.1",    // multicast
            "239.255.255.255",
            "240.0.0.1", // reserved
            "255.255.255.255",
        ] {
            assert!(is_blocked_addr(ip(s)), "{s} must be blocked");
        }
    }

    #[test]
    fn must_allow_public_ipv4() {
        for s in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "172.15.255.255",  // just below 172.16/12
            "172.32.0.1",      // just above 172.16/12
            "100.63.255.255",  // just below CGNAT
            "100.128.0.1",     // just above CGNAT
            "198.20.0.1",      // just above benchmarking
            "192.0.1.1",       // between 192.0.0/24 and 192.0.2/24
            "223.255.255.255", // just below multicast
        ] {
            assert!(!is_blocked_addr(ip(s)), "{s} must be allowed");
        }
    }

    #[test]
    fn must_block_ipv6_special_ranges() {
        for s in [
            "::",                     // unspecified
            "::1",                    // loopback
            "::ffff:127.0.0.1",       // IPv4-mapped loopback (the classic bypass)
            "::ffff:169.254.169.254", // IPv4-mapped metadata
            "::ffff:10.0.0.1",        // IPv4-mapped private
            "::127.0.0.1",            // IPv4-compatible (deprecated)
            "64:ff9b::7f00:1",        // NAT64 well-known of 127.0.0.1
            "64:ff9b:1::1",           // local NAT64
            "2002:7f00:1::",          // 6to4 of 127.0.0.1
            "2002:c0a8:101::",        // 6to4 of 192.168.1.1
            "2002:0808:0808::",       // 6to4 of public 8.8.8.8 — 6to4 is deprecated, block all
            "100::1",                 // discard
            "2001::1",                // Teredo / IETF protocol
            "2001:2::1",              // benchmarking
            "2001:db8::1",            // documentation
            "3fff::1",                // documentation (RFC9637)
            "5f00::1",                // SRv6
            "fc00::1",                // ULA
            "fd00::1",                // ULA
            "fe80::1",                // link-local
            "fec0::1",                // site-local (deprecated)
            "ff02::1",                // multicast
        ] {
            assert!(is_blocked_addr(ip(s)), "{s} must be blocked");
        }
    }

    #[test]
    fn must_allow_public_ipv6() {
        for s in [
            "2606:4700:4700::1111", // Cloudflare DNS
            "2001:4860:4860::8888", // Google DNS
            "::ffff:8.8.8.8",       // IPv4-mapped public
            "2000::1",              // global unicast
        ] {
            assert!(!is_blocked_addr(ip(s)), "{s} must be allowed");
        }
    }

    #[test]
    fn ipv4_mapped_does_not_bypass_the_v4_check() {
        // The whole point: a v6-shaped target whose embedded v4 is private must be
        // blocked, even though the v6 literal itself is not loopback/ULA/etc.
        assert!(is_blocked_addr(ip("::ffff:192.168.0.1")));
        assert!(is_blocked_addr(ip("::ffff:172.16.5.5")));
    }

    #[test]
    fn precheck_port_allowlist() {
        let p = TargetPolicy::secure();
        assert_eq!(p.precheck("1.1.1.1", 80), Err(TargetReject::DisallowedPort));
        assert_eq!(p.precheck("1.1.1.1", 22), Err(TargetReject::DisallowedPort));
        assert_eq!(
            p.precheck("1.1.1.1", 443),
            Ok(Precheck::Pinned(ip("1.1.1.1")))
        );
    }

    #[test]
    fn precheck_blocks_private_ip_literals() {
        let p = TargetPolicy::secure();
        assert_eq!(
            p.precheck("127.0.0.1", 443),
            Err(TargetReject::BlockedAddress)
        );
        assert_eq!(
            p.precheck("169.254.169.254", 443),
            Err(TargetReject::BlockedAddress)
        );
        // Bracketed v6 literal is unwrapped then classified.
        assert_eq!(p.precheck("[::1]", 443), Err(TargetReject::BlockedAddress));
        assert_eq!(
            p.precheck("[::ffff:10.0.0.1]", 443),
            Err(TargetReject::BlockedAddress)
        );
    }

    #[test]
    fn precheck_admits_public_target_on_allowed_port() {
        // The non-vacuous admit case: a real public IP on :443 clears secure().
        // Guards against an inverted classifier that would block everything (which
        // the block-only tests can't catch).
        let p = TargetPolicy::secure();
        assert_eq!(
            p.precheck("93.184.216.34", 443),
            Ok(Precheck::Pinned(ip("93.184.216.34")))
        );
        assert_eq!(
            p.precheck("1.1.1.1", 443),
            Ok(Precheck::Pinned(ip("1.1.1.1")))
        );
    }

    #[test]
    fn first_blocked_is_fail_closed_on_the_union() {
        // Mixed public+private answer => the private one is the rebinding attempt.
        assert_eq!(
            first_blocked(&[ip("8.8.8.8"), ip("127.0.0.1")]),
            Some(ip("127.0.0.1"))
        );
        assert_eq!(
            first_blocked(&[ip("8.8.8.8"), ip("169.254.169.254")]),
            Some(ip("169.254.169.254"))
        );
        // All-public answer => nothing blocked (the request is admitted, pins [0]).
        assert_eq!(first_blocked(&[ip("8.8.8.8"), ip("1.1.1.1")]), None);
        assert_eq!(first_blocked(&[]), None);
    }

    #[test]
    fn precheck_defers_hostnames() {
        let p = TargetPolicy::secure();
        assert_eq!(
            p.precheck("example.com", 443),
            Ok(Precheck::Hostname("example.com".to_string()))
        );
    }

    #[test]
    fn precheck_malformed_target() {
        let p = TargetPolicy::secure();
        assert_eq!(p.precheck("[]", 443), Err(TargetReject::MalformedTarget));
        assert_eq!(p.precheck("", 443), Err(TargetReject::MalformedTarget));
    }

    #[test]
    fn unrestricted_allows_any_port_and_addr() {
        let p = TargetPolicy::unrestricted();
        // Any port, and a loopback literal is NOT blocked (preserves the demo /
        // the in-process tests that tunnel to ephemeral loopback ports).
        assert_eq!(
            p.precheck("127.0.0.1", 9999),
            Ok(Precheck::Pinned(ip("127.0.0.1")))
        );
    }

    #[test]
    fn resolve_pinned_blocks_localhost() {
        // `localhost` resolves to loopback (127.0.0.1 / ::1) on every platform we
        // build on; resolve-then-pin must reject it under a secure policy.
        let p = TargetPolicy::secure();
        assert_eq!(
            p.resolve_pinned("localhost", 443),
            Err(TargetReject::BlockedAddress)
        );
    }

    #[test]
    fn resolve_pinned_rejects_unresolvable() {
        let p = TargetPolicy::secure();
        // RFC2606 .invalid TLD never resolves.
        assert_eq!(
            p.resolve_pinned("nonexistent.invalid", 443),
            Err(TargetReject::Unresolvable)
        );
    }

    #[test]
    fn port_rule_label_and_allows() {
        assert!(PortRule::Any.allows(8080));
        assert!(PortRule::Only(vec![443]).allows(443));
        assert!(!PortRule::Only(vec![443]).allows(80));
        assert_eq!(TargetPolicy::secure().label(), "ports=443,block-private");
        assert_eq!(
            TargetPolicy::unrestricted().label(),
            "ports=any,allow-any-addr"
        );
    }
}
