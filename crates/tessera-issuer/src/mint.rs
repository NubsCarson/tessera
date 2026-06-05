//! Paid-mint gate: issue ARC credentials against an **on-chain TokenMint
//! entitlement** instead of (or beside) proof of work. A buyer pays ETH to
//! [`TokenMint`](../../../contracts/src/TokenMint.sol) and earns `entitled[buyer]`
//! tokens; to turn those into credentials it **proves control of `buyer`** (an
//! `ecrecover` over a fresh issuer challenge) and the issuer issues against the
//! on-chain balance, tracking what it has issued so an entitlement becomes
//! credentials at most once.
//!
//! This is std-only and uses the same EVM-native crypto as the channel court —
//! keccak256 ([`sha3`]) for the ABI selectors + the control digest, secp256k1
//! `ecrecover` ([`k256`]) to bind a request to an Ethereum address. The live
//! read is a minimal JSON-RPC `eth_call` over a blocking socket (no async/RPC
//! crate). Consuming the entitlement on-chain (`TokenMint.redeem`) is the
//! operator's submit step; this module produces its calldata and tracks
//! redemptions durably for the single-issuer case (see [`RedemptionLedger`]).

use std::collections::HashMap;
use std::io::{Error, ErrorKind, Read, Result, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::Mutex;

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};

/// One ARC credential grants `LIMIT` presentations; treating one presentation as
/// one paid "token", a credential costs this many tokens of entitlement.
pub const TOKENS_PER_CREDENTIAL: u128 = 64;

/// Domain separator for the proof-of-control digest (distinct from every other
/// keccak use, so a control signature can never be replayed as another message).
const CONTROL_DOMAIN: &[u8] = b"tessera-mint-control-v1";

// ───────────────────────────────── ABI ─────────────────────────────────────

/// The 4-byte function selector `keccak256(sig)[..4]`.
pub fn selector(sig: &str) -> [u8; 4] {
    let d = Keccak256::digest(sig.as_bytes());
    [d[0], d[1], d[2], d[3]]
}

/// Calldata for `entitled(address)` (selector + 32-byte left-padded address).
pub fn encode_entitled(buyer: &[u8; 20]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32);
    out.extend_from_slice(&selector("entitled(address)"));
    out.extend_from_slice(&[0u8; 12]);
    out.extend_from_slice(buyer);
    out
}

/// Calldata for `redeem(address,uint256)` — the issuer's on-chain consume step
/// (the operator submits this tx after the issuer has issued the credentials).
pub fn encode_redeem(buyer: &[u8; 20], tokens: u128) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 64);
    out.extend_from_slice(&selector("redeem(address,uint256)"));
    out.extend_from_slice(&[0u8; 12]);
    out.extend_from_slice(buyer);
    let mut word = [0u8; 32];
    word[16..].copy_from_slice(&tokens.to_be_bytes());
    out.extend_from_slice(&word);
    out
}

/// Decode a 32-byte big-endian `uint256` ABI word into a `u128`, rejecting a
/// value that overflows `u128` (an entitlement count never legitimately does).
pub fn decode_uint256(word: &[u8]) -> Result<u128> {
    if word.len() != 32 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "uint256 must be 32 bytes",
        ));
    }
    if word[..16].iter().any(|&b| b != 0) {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "entitlement exceeds u128",
        ));
    }
    Ok(u128::from_be_bytes(word[16..].try_into().unwrap()))
}

// ───────────────────────── proof of address control ─────────────────────────

/// The digest a buyer signs to prove control of its address:
/// `keccak256(domain ‖ issuer_pk ‖ challenge)`.
///
/// Binding `issuer_pk` makes a control signature **non-transferable** between
/// issuers: a signature produced for issuer A cannot be wormholed to a different
/// issuer B (its `pk` differs), so a MITM/relay cannot steal a victim's
/// entitlement into a credential at another issuer. Combined with the client
/// **pinning** the issuer pk (required in paid mode), the victim only ever signs
/// for its intended issuer. `challenge` is a fresh per-connection nonce
/// (anti-replay within an issuer).
pub fn control_digest(issuer_pk: &[u8], challenge: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(CONTROL_DOMAIN);
    h.update(issuer_pk);
    h.update(challenge);
    h.finalize().into()
}

/// The 20-byte Ethereum address of an uncompressed-pubkey verifying key:
/// `keccak256(pubkey[1..])[12..]`.
fn eth_address(vk: &VerifyingKey) -> [u8; 20] {
    let pt = vk.to_encoded_point(false);
    let bytes = pt.as_bytes(); // 0x04 ‖ X ‖ Y
    let h = Keccak256::digest(&bytes[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&h[12..]);
    addr
}

/// Recover the Ethereum address that signed the issuer-bound `challenge` with
/// the 65-byte recoverable signature `r‖s‖v` (`v ∈ {27,28}`). `None` if it
/// doesn't recover. `issuer_pk` must be the issuer's advertised key (binds the
/// signature to this issuer).
pub fn recover_buyer(issuer_pk: &[u8], challenge: &[u8], sig: &[u8; 65]) -> Option<[u8; 20]> {
    let signature = Signature::from_slice(&sig[..64]).ok()?;
    let v = sig[64].checked_sub(27)?;
    if v > 1 {
        return None; // only the canonical recid ∈ {0,1} (v ∈ {27,28}) accepted
    }
    let recid = RecoveryId::from_byte(v)?;
    let digest = control_digest(issuer_pk, challenge);
    let vk = VerifyingKey::recover_from_prehash(&digest, &signature, recid).ok()?;
    Some(eth_address(&vk))
}

/// Sign the issuer-bound `challenge` recoverably as a buyer would — for clients
/// and tests. Returns `r‖s‖v` with `v ∈ {27,28}`.
pub fn sign_control(issuer_pk: &[u8], challenge: &[u8], secret: &[u8; 32]) -> Option<[u8; 65]> {
    let sk = SigningKey::from_bytes(secret.into()).ok()?;
    let digest = control_digest(issuer_pk, challenge);
    let (sig, recid) = sk.sign_prehash_recoverable(&digest).ok()?;
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(&sig.to_bytes());
    out[64] = recid.to_byte() + 27;
    Some(out)
}

/// The Ethereum address controlled by `secret` (for clients/tests).
pub fn address_of(secret: &[u8; 32]) -> Option<[u8; 20]> {
    let sk = SigningKey::from_bytes(secret.into()).ok()?;
    Some(eth_address(sk.verifying_key()))
}

// ──────────────────────────── entitlement source ────────────────────────────

/// A read of a buyer's on-chain `entitled[buyer]` balance. Abstracted so the
/// gate is testable in-process ([`InMemoryEntitlement`]) and live ([`EthRpc`]).
pub trait EntitlementSource {
    /// The buyer's current total entitled token count.
    fn entitled(&self, buyer: &[u8; 20]) -> Result<u128>;
}

/// A fixed in-memory entitlement table (tests / a trusted off-chain ledger).
#[derive(Debug, Default)]
pub struct InMemoryEntitlement(pub HashMap<[u8; 20], u128>);

impl EntitlementSource for InMemoryEntitlement {
    fn entitled(&self, buyer: &[u8; 20]) -> Result<u128> {
        Ok(self.0.get(buyer).copied().unwrap_or(0))
    }
}

/// Live `entitled[buyer]` via a minimal JSON-RPC `eth_call` over a blocking
/// socket — no async/RPC dependency. `url` is `http://host:port[/path]`.
pub struct EthRpc {
    url: String,
    contract: [u8; 20],
}

impl EthRpc {
    /// A reader against the JSON-RPC endpoint `url` for the TokenMint at `contract`.
    pub fn new(url: impl Into<String>, contract: [u8; 20]) -> Self {
        Self {
            url: url.into(),
            contract,
        }
    }

    /// One `eth_call`, returning the raw 32-byte result word.
    fn eth_call(&self, data: &[u8]) -> Result<[u8; 32]> {
        // Parse http://host:port/path (default port 80, path "/").
        let rest = self.url.strip_prefix("http://").ok_or_else(|| {
            Error::new(ErrorKind::InvalidInput, "only http:// RPC URLs supported")
        })?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let host_port = if authority.contains(':') {
            authority.to_string()
        } else {
            format!("{authority}:80")
        };

        let to = format!("0x{}", hex::encode(self.contract));
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{{"to":"{to}","data":"0x{}"}},"latest"]}}"#,
            hex::encode(data)
        );
        let req = format!(
            "POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );

        let mut stream = TcpStream::connect(&host_port)?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(15)))?;
        stream.set_write_timeout(Some(std::time::Duration::from_secs(15)))?;
        stream.write_all(req.as_bytes())?;
        stream.flush()?;
        // Bound the read: a JSON-RPC eth_call reply is tiny; cap it so a hostile
        // or MITM'd plaintext RPC can't stream unbounded data and OOM the issuer.
        // (Assumes the endpoint honours `Connection: close`; anvil/geth/hardhat do.)
        const MAX_RPC_RESP: u64 = 64 * 1024;
        let mut bytes = Vec::new();
        stream.take(MAX_RPC_RESP).read_to_end(&mut bytes)?;
        let resp = String::from_utf8_lossy(&bytes).into_owned();

        // Extract "result":"0x...." from the JSON body (errors carry "error").
        if let Some(e) = resp.find("\"error\"") {
            return Err(Error::other(format!(
                "RPC error: {}",
                &resp[e..].chars().take(160).collect::<String>()
            )));
        }
        let key = "\"result\":\"0x";
        let start = resp
            .find(key)
            .ok_or_else(|| Error::other("RPC response had no result"))?
            + key.len();
        let end = resp[start..]
            .find('"')
            .ok_or_else(|| Error::other("malformed RPC result"))?
            + start;
        let hexstr = &resp[start..end];
        let raw = hex::decode(hexstr).map_err(|_| Error::other("non-hex RPC result"))?;
        if raw.len() != 32 {
            return Err(Error::other("eth_call result was not a 32-byte word"));
        }
        let mut word = [0u8; 32];
        word.copy_from_slice(&raw);
        Ok(word)
    }
}

impl EntitlementSource for EthRpc {
    fn entitled(&self, buyer: &[u8; 20]) -> Result<u128> {
        let word = self.eth_call(&encode_entitled(buyer))?;
        decode_uint256(&word)
    }
}

// ─────────────────────────── redemption ledger ──────────────────────────────

/// Durable per-buyer accounting of tokens already turned into credentials, so a
/// single issuer never issues more than the buyer paid for. Persists to a file
/// (rewritten on each change) so it survives a restart, mirroring the spent-tag
/// store. (A multi-issuer deployment should instead consume on-chain via
/// `TokenMint.redeem` — [`encode_redeem`] — the shared authoritative guard.)
#[derive(Debug, Default)]
pub struct RedemptionLedger {
    issued: Mutex<HashMap<[u8; 20], u128>>,
    path: Option<PathBuf>,
}

impl RedemptionLedger {
    /// An in-memory ledger (lost on restart).
    pub fn in_memory() -> Self {
        Self::default()
    }

    /// A file-backed ledger, loading any prior state from `path`.
    pub fn at(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let mut issued = HashMap::new();
        if let Ok(s) = std::fs::read_to_string(&path) {
            for line in s.lines() {
                let mut it = line.split_whitespace();
                if let (Some(a), Some(n)) = (it.next(), it.next()) {
                    if let (Ok(addr), Ok(tokens)) = (hex::decode(a), n.parse::<u128>()) {
                        if addr.len() == 20 {
                            let mut k = [0u8; 20];
                            k.copy_from_slice(&addr);
                            issued.insert(k, tokens);
                        }
                    }
                }
            }
        }
        Self {
            issued: Mutex::new(issued),
            path: Some(path),
        }
    }

    /// Atomically reserve `cost` tokens for `buyer` against `entitled_on_chain`,
    /// returning `true` iff `already_issued + cost <= entitled_on_chain`. On
    /// success the issued count is incremented and persisted.
    pub fn try_reserve(&self, buyer: &[u8; 20], entitled_on_chain: u128, cost: u128) -> bool {
        let mut g = self.issued.lock().unwrap_or_else(|p| p.into_inner());
        let already = g.get(buyer).copied().unwrap_or(0);
        let after = match already.checked_add(cost) {
            Some(v) => v,
            None => return false,
        };
        if after > entitled_on_chain {
            return false;
        }
        g.insert(*buyer, after);
        self.persist(&g);
        true
    }

    /// Refund a prior [`try_reserve`](Self::try_reserve) (e.g. the credential was
    /// never delivered): decrement `buyer`'s issued count by `cost` (saturating).
    pub fn release(&self, buyer: &[u8; 20], cost: u128) {
        let mut g = self.issued.lock().unwrap_or_else(|p| p.into_inner());
        let after = g.get(buyer).copied().unwrap_or(0).saturating_sub(cost);
        if after == 0 {
            g.remove(buyer);
        } else {
            g.insert(*buyer, after);
        }
        self.persist(&g);
    }

    /// Persist the issued map by an atomic temp-write + fsync + rename, so a clean
    /// crash/power-loss can't revert an issued count (and re-issue an entitlement).
    fn persist(&self, map: &HashMap<[u8; 20], u128>) {
        let Some(path) = &self.path else { return };
        let dump: String = map
            .iter()
            .map(|(a, n)| format!("{} {}\n", hex::encode(a), n))
            .collect();
        // Unique temp per writer + fsync before the atomic rename.
        let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
        match std::fs::File::create(&tmp).and_then(|mut f| {
            use std::io::Write as _;
            f.write_all(dump.as_bytes())?;
            f.sync_all()
        }) {
            Ok(()) => {
                if let Err(e) = std::fs::rename(&tmp, path) {
                    eprintln!("tessera-issuer: WARN redemption ledger rename failed: {e}");
                    let _ = std::fs::remove_file(&tmp);
                }
            }
            Err(e) => {
                eprintln!("tessera-issuer: WARN redemption ledger persist failed: {e}");
                let _ = std::fs::remove_file(&tmp);
            }
        }
    }
}

// ─────────────────────────────── the gate ───────────────────────────────────

/// Authorizes paid issuance: prove control of `buyer`, then reserve `cost`
/// tokens against the buyer's on-chain entitlement.
pub struct PaymentGate<E: EntitlementSource> {
    source: E,
    ledger: RedemptionLedger,
    cost: u128,
}

impl<E: EntitlementSource> PaymentGate<E> {
    /// A gate reading entitlement from `source`, tracking redemptions in
    /// `ledger`, charging `cost` tokens per credential.
    pub fn new(source: E, ledger: RedemptionLedger, cost: u128) -> Self {
        Self {
            source,
            ledger,
            cost,
        }
    }

    /// Reserve `cost` tokens against `buyer`'s on-chain entitlement (call this
    /// only once a credential is certain to be issued). `Err` if the buyer hasn't
    /// enough unspent entitlement.
    pub fn reserve(&self, buyer: &[u8; 20]) -> Result<()> {
        let entitled = self.source.entitled(buyer)?;
        if !self.ledger.try_reserve(buyer, entitled, self.cost) {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                "insufficient paid entitlement",
            ));
        }
        Ok(())
    }

    /// Refund a prior [`reserve`](Self::reserve) — e.g. the credential could not
    /// be delivered to the buyer, so its entitlement must not be burned.
    pub fn release(&self, buyer: &[u8; 20]) {
        self.ledger.release(buyer, self.cost);
    }

    /// Convenience: verify control (proof over `issuer_pk` ‖ `challenge`) **and**
    /// reserve, returning the buyer. The networked handler instead recovers the
    /// buyer, builds the credential, and only *then* reserves (so a malformed
    /// request can't burn entitlement) — see `serve_issuance_paid`.
    pub fn authorize(
        &self,
        issuer_pk: &[u8],
        challenge: &[u8],
        sig: &[u8; 65],
    ) -> Result<[u8; 20]> {
        let buyer = recover_buyer(issuer_pk, challenge, sig)
            .ok_or_else(|| Error::new(ErrorKind::PermissionDenied, "bad control signature"))?;
        self.reserve(&buyer)?;
        Ok(buyer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_match_cast() {
        // Pinned with `cast sig` (Foundry) — the contract's real selectors.
        assert_eq!(selector("entitled(address)"), [0x6e, 0x1e, 0xde, 0x72]);
        assert_eq!(
            selector("redeem(address,uint256)"),
            [0x1e, 0x9a, 0x69, 0x50]
        );
    }

    #[test]
    fn entitled_calldata_shape() {
        let buyer = [0x11u8; 20];
        let cd = encode_entitled(&buyer);
        assert_eq!(cd.len(), 36);
        assert_eq!(&cd[..4], &[0x6e, 0x1e, 0xde, 0x72]);
        assert_eq!(&cd[4..16], &[0u8; 12]); // left pad
        assert_eq!(&cd[16..], &buyer);
    }

    #[test]
    fn redeem_calldata_shape() {
        let cd = encode_redeem(&[0x22u8; 20], 64);
        assert_eq!(cd.len(), 68);
        assert_eq!(&cd[..4], &[0x1e, 0x9a, 0x69, 0x50]);
        assert_eq!(decode_uint256(&cd[36..]).unwrap(), 64);
    }

    #[test]
    fn uint256_decode_bounds() {
        let mut w = [0u8; 32];
        w[31] = 9;
        assert_eq!(decode_uint256(&w).unwrap(), 9);
        w[0] = 1; // high bit set => overflows u128
        assert!(decode_uint256(&w).is_err());
        assert!(decode_uint256(&[0u8; 31]).is_err());
    }

    #[test]
    fn proof_of_control_roundtrips_and_binds() {
        let secret = [7u8; 32];
        let addr = address_of(&secret).unwrap();
        let issuer_pk = [0xABu8; 99];
        let challenge = b"fresh-issuer-challenge";
        let sig = sign_control(&issuer_pk, challenge, &secret).unwrap();
        assert_eq!(
            recover_buyer(&issuer_pk, challenge, &sig),
            Some(addr),
            "recovers the signer"
        );
        // A different challenge must NOT recover the same address (replay-bound).
        assert_ne!(
            recover_buyer(&issuer_pk, b"other-challenge", &sig),
            Some(addr)
        );
        // A DIFFERENT issuer pk must NOT recover the same address (wormhole-bound):
        // the signature is non-transferable between issuers.
        let other_issuer = [0xCDu8; 99];
        assert_ne!(recover_buyer(&other_issuer, challenge, &sig), Some(addr));
        // A tampered signature fails to recover the buyer.
        let mut bad = sig;
        bad[10] ^= 0xff;
        assert_ne!(recover_buyer(&issuer_pk, challenge, &bad), Some(addr));
    }

    #[test]
    fn eth_rpc_builds_call_and_parses_result() {
        // A mock JSON-RPC server: assert the eth_call carries entitled(buyer)
        // calldata to the right contract, then reply with entitled = 64.
        use std::net::TcpListener;
        let buyer = [0x11u8; 20];
        let contract = [0x22u8; 20];
        let want_data = format!("0x{}", hex::encode(encode_entitled(&buyer)));
        let want_to = format!("0x{}", hex::encode(contract));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 8192];
            let n = s.read(&mut buf).unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
            assert!(req.contains("eth_call"), "must be an eth_call");
            assert!(req.contains(&want_to), "must target the contract");
            assert!(
                req.contains(&want_data),
                "must carry entitled(buyer) calldata"
            );
            let body = r#"{"jsonrpc":"2.0","id":1,"result":"0x0000000000000000000000000000000000000000000000000000000000000040"}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            s.write_all(resp.as_bytes()).unwrap();
            s.flush().unwrap();
        });

        let rpc = EthRpc::new(format!("http://127.0.0.1:{port}"), contract);
        assert_eq!(
            rpc.entitled(&buyer).unwrap(),
            64,
            "parses the uint256 result"
        );
        h.join().unwrap();
    }

    #[test]
    fn redemption_ledger_persists_across_reload() {
        let path = std::env::temp_dir().join(format!(
            "tessera-ledger-{}-{}.txt",
            std::process::id(),
            // a per-test-unique-ish suffix
            line!()
        ));
        let _ = std::fs::remove_file(&path);
        let buyer = [0xABu8; 20];
        {
            let l = RedemptionLedger::at(&path);
            assert!(l.try_reserve(&buyer, 100, 64)); // 64/100
            assert!(!l.try_reserve(&buyer, 100, 64)); // 128 > 100 -> reject
        }
        // Reload: the 64 already issued must survive.
        let l = RedemptionLedger::at(&path);
        assert!(
            !l.try_reserve(&buyer, 100, 64),
            "persisted issued count blocks overdraw"
        );
        assert!(
            l.try_reserve(&buyer, 200, 64),
            "more entitlement unlocks more"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn gate_admits_paid_rejects_unpaid_and_overdraw() {
        let buyer_secret = [3u8; 32];
        let buyer = address_of(&buyer_secret).unwrap();
        let mut table = HashMap::new();
        table.insert(buyer, 128u128); // paid for 128 tokens = 2 credentials @64
        let gate = PaymentGate::new(
            InMemoryEntitlement(table),
            RedemptionLedger::in_memory(),
            64,
        );

        let issuer_pk = [0x01u8; 99];
        let challenge = b"c1";
        let sig = sign_control(&issuer_pk, challenge, &buyer_secret).unwrap();
        assert_eq!(gate.authorize(&issuer_pk, challenge, &sig).unwrap(), buyer); // 1st ok
        assert!(gate.authorize(&issuer_pk, challenge, &sig).is_ok()); // 2nd ok (128/64)
        assert!(gate.authorize(&issuer_pk, challenge, &sig).is_err()); // 3rd overdraws

        // release() refunds, so a delivery failure doesn't burn entitlement.
        gate.release(&buyer);
        assert!(
            gate.authorize(&issuer_pk, challenge, &sig).is_ok(),
            "refunded slot reusable"
        );

        // A buyer who never paid is rejected.
        let broke = [9u8; 32];
        let bsig = sign_control(&issuer_pk, challenge, &broke).unwrap();
        assert!(gate.authorize(&issuer_pk, challenge, &bsig).is_err());
    }
}
