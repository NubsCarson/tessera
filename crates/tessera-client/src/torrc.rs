//! Client-side Tor `torrc` generation, including optional pluggable-transport /
//! bridge entry for reaching the network from a censored environment.
//!
//! This emits configuration for the **real Tor binary** — it does not
//! reimplement Tor. Pluggable transports (obfs4, Snowflake, WebTunnel) and the
//! bridges they front are Tor's own; Tessera only writes the `torrc` lines that
//! point Tor at them. Reaching the network past a censor is delegated entirely
//! to Tor; Tessera's contribution (the unlinkable ARC credential + the clean
//! exit) rides on top of whatever circuit Tor establishes.
//!
//! The base (no-bridge) output is byte-identical to the plain SOCKS torrc the
//! client used before, so adding bridge support is purely additive — when no
//! bridge is configured the transport path is unchanged.

use std::fmt::Write as _;

/// A pluggable transport Tessera knows how to point Tor at. These are *Tor's*
/// transports, not Tessera's (see the module docs): each disguises traffic so a
/// censor's deep-packet inspection cannot fingerprint and block the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluggableTransport {
    /// obfs4 — the connection looks like a stream of uniformly random bytes.
    Obfs4,
    /// Snowflake — the connection looks like a WebRTC (video-call) data channel.
    Snowflake,
    /// WebTunnel — the connection looks like an ordinary HTTPS website.
    WebTunnel,
}

impl PluggableTransport {
    /// The transport name Tor expects in `ClientTransportPlugin` and as the
    /// first token of every `Bridge` line.
    pub fn torrc_name(self) -> &'static str {
        match self {
            PluggableTransport::Obfs4 => "obfs4",
            PluggableTransport::Snowflake => "snowflake",
            PluggableTransport::WebTunnel => "webtunnel",
        }
    }

    /// Parse a `TESSERA_PT` value (case-insensitive). Returns a clear error
    /// listing the accepted set rather than silently picking a default.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "obfs4" => Ok(PluggableTransport::Obfs4),
            "snowflake" => Ok(PluggableTransport::Snowflake),
            "webtunnel" => Ok(PluggableTransport::WebTunnel),
            other => Err(format!(
                "unknown pluggable transport {other:?}; expected one of: obfs4 | snowflake | webtunnel"
            )),
        }
    }
}

/// Bridge / pluggable-transport entry configuration for the client's Tor.
///
/// A `BridgeConfig` says: run `plugin_path` as the `transport` plugin, and reach
/// Tor through these `bridge_lines` (each the text *after* the `Bridge` keyword,
/// e.g. `obfs4 192.0.2.1:443 <FINGERPRINT> cert=… iat-mode=0`). Multiple lines
/// are kept so the client can fail over between bridges.
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// Which Tor pluggable transport to use.
    pub transport: PluggableTransport,
    /// Filesystem path to the transport plugin binary (e.g. `obfs4proxy`,
    /// `snowflake-client`). These ship with Tor / Tor Project builds — Tessera
    /// does not provide them.
    pub plugin_path: String,
    /// One or more `Bridge` lines (the text after the `Bridge ` keyword).
    pub bridge_lines: Vec<String>,
}

impl BridgeConfig {
    /// Validate the configuration before it is rendered into a `torrc`.
    ///
    /// Rejects: an empty plugin path; zero bridge lines; any field carrying a
    /// CR/LF (which would inject extra torrc directives); and a `Bridge` line
    /// whose first token is not the configured transport name (Tor requires
    /// `Bridge <transport> …`, and a mismatch is a silent misconfiguration that
    /// fails opaquely at Tor start otherwise).
    pub fn validate(&self) -> Result<(), String> {
        let plugin = self.plugin_path.trim();
        if plugin.is_empty() {
            return Err("bridge config: plugin_path is empty".to_string());
        }
        if contains_newline(&self.plugin_path) {
            return Err("bridge config: plugin_path contains a newline".to_string());
        }
        if self.bridge_lines.is_empty() {
            return Err("bridge config: no Bridge lines provided".to_string());
        }
        let name = self.transport.torrc_name();
        for (i, line) in self.bridge_lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return Err(format!("bridge config: Bridge line {i} is empty"));
            }
            if contains_newline(line) {
                return Err(format!("bridge config: Bridge line {i} contains a newline"));
            }
            let first = trimmed.split_whitespace().next().unwrap_or("");
            if !first.eq_ignore_ascii_case(name) {
                return Err(format!(
                    "bridge config: Bridge line {i} starts with {first:?} but transport is {name:?} \
                     (a Bridge line must read: Bridge {name} <addr> <fingerprint> …)"
                ));
            }
        }
        Ok(())
    }
}

fn contains_newline(s: &str) -> bool {
    s.contains('\n') || s.contains('\r')
}

/// Build a client `torrc`.
///
/// With `bridge == None` the output is the plain SOCKS torrc (SOCKS port, data
/// directory, log) — byte-identical to what the client used before bridge
/// support, so there is no transport regression. With a `BridgeConfig`, the
/// `UseBridges 1` + `ClientTransportPlugin` + one `Bridge` line per entry are
/// appended; the SOCKS port is unchanged because the pluggable transport runs
/// *inside* Tor — the client still dials a plain local SOCKS5 port.
///
/// Returns an error only if the `BridgeConfig` fails [`BridgeConfig::validate`]
/// or a path argument contains a newline.
pub fn client_torrc(
    socks_port: u16,
    data_dir: &str,
    log_path: &str,
    bridge: Option<&BridgeConfig>,
) -> Result<String, String> {
    if contains_newline(data_dir) {
        return Err("torrc: data_dir contains a newline".to_string());
    }
    if contains_newline(log_path) {
        return Err("torrc: log_path contains a newline".to_string());
    }

    let mut out = String::new();
    let _ = writeln!(out, "SocksPort 127.0.0.1:{socks_port}");
    let _ = writeln!(out, "DataDirectory {data_dir}");
    let _ = writeln!(out, "Log notice file {log_path}");

    if let Some(bridge) = bridge {
        bridge.validate()?;
        let _ = writeln!(out, "UseBridges 1");
        let _ = writeln!(
            out,
            "ClientTransportPlugin {} exec {}",
            bridge.transport.torrc_name(),
            bridge.plugin_path.trim()
        );
        for line in &bridge.bridge_lines {
            let _ = writeln!(out, "Bridge {}", line.trim());
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obfs4(lines: &[&str]) -> BridgeConfig {
        BridgeConfig {
            transport: PluggableTransport::Obfs4,
            plugin_path: "/usr/bin/obfs4proxy".to_string(),
            bridge_lines: lines.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn no_bridge_is_the_plain_socks_torrc() {
        let got = client_torrc(9050, "/var/data", "/var/tor.log", None).unwrap();
        assert_eq!(
            got,
            "SocksPort 127.0.0.1:9050\nDataDirectory /var/data\nLog notice file /var/tor.log\n"
        );
        // No bridge directives leak into the base config.
        assert!(!got.contains("UseBridges"));
        assert!(!got.contains("ClientTransportPlugin"));
        assert!(!got.contains("Bridge "));
    }

    #[test]
    fn transport_names_map_to_tor_tokens() {
        assert_eq!(PluggableTransport::Obfs4.torrc_name(), "obfs4");
        assert_eq!(PluggableTransport::Snowflake.torrc_name(), "snowflake");
        assert_eq!(PluggableTransport::WebTunnel.torrc_name(), "webtunnel");
        assert_eq!(
            PluggableTransport::parse("OBFS4").unwrap(),
            PluggableTransport::Obfs4
        );
        assert_eq!(
            PluggableTransport::parse(" snowflake ").unwrap(),
            PluggableTransport::Snowflake
        );
        assert!(PluggableTransport::parse("shadowsocks").is_err());
    }

    #[test]
    fn obfs4_with_multiple_bridges_emits_each_line() {
        let cfg = obfs4(&[
            "obfs4 192.0.2.1:443 0000000000000000000000000000000000000000 cert=abc iat-mode=0",
            "obfs4 198.51.100.2:9001 1111111111111111111111111111111111111111 cert=def iat-mode=1",
        ]);
        let got = client_torrc(19250, "/d", "/l", Some(&cfg)).unwrap();
        assert!(got.contains("SocksPort 127.0.0.1:19250\n"));
        assert!(got.contains("UseBridges 1\n"));
        assert!(got.contains("ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy\n"));
        // Both bridges present, one Bridge line each.
        assert_eq!(got.matches("\nBridge ").count(), 2);
        assert!(got.contains("\nBridge obfs4 192.0.2.1:443 0000"));
        assert!(got.contains("\nBridge obfs4 198.51.100.2:9001 1111"));
    }

    #[test]
    fn snowflake_and_webtunnel_render() {
        for (t, name) in [
            (PluggableTransport::Snowflake, "snowflake"),
            (PluggableTransport::WebTunnel, "webtunnel"),
        ] {
            let cfg = BridgeConfig {
                transport: t,
                plugin_path: "/x".to_string(),
                bridge_lines: vec![format!("{name} 192.0.2.1:443 ABCD")],
            };
            let got = client_torrc(9, "/d", "/l", Some(&cfg)).unwrap();
            assert!(got.contains(&format!("ClientTransportPlugin {name} exec /x\n")));
            assert!(got.contains(&format!("\nBridge {name} 192.0.2.1:443 ABCD\n")));
        }
    }

    #[test]
    fn validate_rejects_bad_config() {
        // empty plugin path
        let mut c = obfs4(&["obfs4 1.2.3.4:1 AAAA"]);
        c.plugin_path = "  ".to_string();
        assert!(client_torrc(9, "/d", "/l", Some(&c)).is_err());

        // no bridge lines
        let c = BridgeConfig {
            transport: PluggableTransport::Obfs4,
            plugin_path: "/x".to_string(),
            bridge_lines: vec![],
        };
        assert!(client_torrc(9, "/d", "/l", Some(&c)).is_err());

        // bridge line for the wrong transport
        let c = BridgeConfig {
            transport: PluggableTransport::Obfs4,
            plugin_path: "/x".to_string(),
            bridge_lines: vec!["snowflake 1.2.3.4:1 AAAA".to_string()],
        };
        let err = client_torrc(9, "/d", "/l", Some(&c)).unwrap_err();
        assert!(err.contains("transport is \"obfs4\""), "got: {err}");

        // CRLF injection in a bridge line
        let c = obfs4(&["obfs4 1.2.3.4:1 AAAA\nExitNodes evil"]);
        assert!(client_torrc(9, "/d", "/l", Some(&c)).is_err());

        // CRLF injection via a path argument
        assert!(client_torrc(9, "/d\nSocksPort 9999", "/l", None).is_err());
    }
}
