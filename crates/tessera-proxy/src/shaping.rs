//! Per-egress-IP **human-volume shaping** (M5) — the foundational clean-egress
//! mechanism from `docs/IP_EGRESS_IDEAS.md` §4.
//!
//! ## The problem it attacks
//!
//! A clean, residential-class egress IP is the scarcest resource in the whole
//! system (no code manufactures one — see `IP_EGRESS_IDEAS.md`). The fastest way
//! to *burn* one is to make it behave unlike a human: a single IP fanning out to
//! a thousand unrelated domains in a minute, hundreds of concurrent connections,
//! perfectly machine-timed. Anti-abuse systems flag exactly that shape. So the
//! exit must **shape its own egress to a human-plausible envelope** — and when
//! traffic exceeds the envelope it must **slow down gracefully, never hard-block**:
//! a hard refusal (a sudden burst of resets / 4xx) is itself an anomalous,
//! fingerprintable signal, whereas pacing looks like a busy-but-human client.
//!
//! ## What this is (and is not)
//!
//! [`VolumeShaper`] is a **metadata-only** governor: it sees only the SNI-level
//! destination host (which the exit already knows, to open the tunnel) and timing
//! — never content (the tunnel is end-to-end TLS; the exit can't see plaintext
//! anyway). It enforces four caps from the IP-egress portfolio:
//!
//!   * **distinct destinations per window** — a human visits a bounded number of
//!     distinct domains per hour; new distinct destinations past the cap are paced;
//!   * **concurrency** — bounded simultaneous tunnels; excess is paced;
//!   * **sticky session** — re-visiting an already-seen destination is free (it
//!     refreshes recency, never counts against the distinct cap), matching how a
//!     human reloads/keeps using the same sites;
//!   * **jitter** — a small randomized pre-connect delay so requests are not
//!     machine-gun-timed.
//!
//! Over-envelope traffic is **throttled** (a bounded, graceful delay), never
//! denied — [`ShapingDecision`] has no "reject" variant by construction.
//!
//! It is keyed to **one egress identity** (the exit's outbound IP). A multi-IP
//! exit holds one shaper per egress IP and routes a tunnel to the IP whose shaper
//! has the most human headroom; that pooling/selection is the deployment layer.
//!
//! The clock is injected ([`VolumeShaper::decide`] takes `now_ms`) so the policy
//! is deterministically testable; [`VolumeShaper::decide_now`] uses a real
//! monotonic clock for the live proxy.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Human-volume envelope for a single egress IP. The defaults are deliberately
/// conservative human-plausible values; a deployment tunes them to its IP's
/// reputation and the destinations it serves.
#[derive(Clone, Debug)]
pub struct ShapingConfig {
    /// Sliding window over which distinct destinations are counted.
    pub window: Duration,
    /// Max distinct destination hosts within `window` before new ones are paced.
    pub max_distinct_destinations: usize,
    /// Max simultaneous in-flight tunnels before new ones are paced.
    pub max_concurrency: usize,
    /// Upper bound on the randomized pre-connect jitter (0 disables jitter).
    pub jitter: Duration,
    /// Delay added per unit over a cap (the throttle slope).
    pub throttle_step: Duration,
    /// Ceiling on the throttle delay — keeps it *graceful* (a bounded pause),
    /// never an effective block. Jitter is added on top of this.
    pub max_throttle: Duration,
}

impl Default for ShapingConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(3600), // 1 hour
            max_distinct_destinations: 100,    // a busy human hour
            max_concurrency: 12,
            jitter: Duration::from_millis(150),
            throttle_step: Duration::from_millis(250),
            max_throttle: Duration::from_secs(10),
        }
    }
}

/// The shaper's verdict for one tunnel request. **There is no reject variant** —
/// the request always proceeds, possibly after `delay`. That is the whole point:
/// shape, don't block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShapingDecision {
    /// How long to pace this request before connecting (jitter + any throttle).
    /// Zero means go immediately.
    pub delay: Duration,
    /// The destination was already seen in the window (a sticky-session re-visit):
    /// it does not count against the distinct-destination cap.
    pub sticky: bool,
    /// This request is outside the human-volume envelope (distinct cap and/or
    /// concurrency cap exceeded). It still proceeds — just throttled.
    pub over_envelope: bool,
}

/// A per-egress-IP human-volume governor. Not internally synchronized; the proxy
/// wraps it in an `Arc<Mutex<…>>` (one per egress IP).
#[derive(Debug)]
pub struct VolumeShaper {
    cfg: ShapingConfig,
    /// destination host -> last-seen timestamp (ms on the injected clock).
    seen: HashMap<String, u64>,
    /// Tunnels currently in flight on this egress IP.
    in_flight: usize,
    /// Monotonic reference for [`decide_now`](Self::decide_now).
    start: Instant,
    /// Deterministic jitter source (xorshift64) — pseudo-random, not crypto.
    jitter_state: u64,
}

impl VolumeShaper {
    /// Create a shaper with the given envelope. `jitter_seed` seeds the (non-crypto)
    /// jitter PRNG; pass any nonzero value (a per-IP constant is fine).
    pub fn new(cfg: ShapingConfig, jitter_seed: u64) -> Self {
        Self {
            cfg,
            seen: HashMap::new(),
            in_flight: 0,
            start: Instant::now(),
            // xorshift64 must not be seeded with 0.
            jitter_state: if jitter_seed == 0 {
                0x9E3779B97F4A7C15
            } else {
                jitter_seed
            },
        }
    }

    /// Milliseconds on the shaper's monotonic clock — what [`decide_now`](Self::decide_now)
    /// feeds [`decide`](Self::decide).
    pub fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// Decide how to pace a tunnel to `dest_host` at time `now_ms` (injected clock).
    ///
    /// Prunes the distinct-destination window to `[now_ms - window, now_ms]`, then:
    ///   * a **sticky** re-visit (host already in the window) is free — recency is
    ///     refreshed, the distinct count is unchanged, no distinct-throttle;
    ///   * a **new** distinct host past `max_distinct_destinations` is paced by
    ///     `throttle_step` per host over the cap (capped at `max_throttle`);
    ///   * being at/over `max_concurrency` adds the same graceful pacing;
    ///   * `jitter` (uniform in `[0, jitter)`) is always added.
    ///
    /// The host is recorded as seen at `now_ms` regardless — the request proceeds.
    pub fn decide(&mut self, dest_host: &str, now_ms: u64) -> ShapingDecision {
        let window_ms = self.cfg.window.as_millis() as u64;
        let cutoff = now_ms.saturating_sub(window_ms);
        self.seen.retain(|_, &mut ts| ts >= cutoff);

        let sticky = self.seen.contains_key(dest_host);
        let distinct = self.seen.len();

        let step = self.cfg.throttle_step;
        let mut throttle = Duration::ZERO;

        // Distinct-destination cap: only NEW distinct hosts past the cap are paced.
        if !sticky && distinct >= self.cfg.max_distinct_destinations {
            let over = (distinct - self.cfg.max_distinct_destinations + 1) as u32;
            throttle += step.saturating_mul(over);
        }
        // Concurrency cap: in-flight at/over the cap is paced too.
        if self.in_flight >= self.cfg.max_concurrency {
            let over = (self.in_flight - self.cfg.max_concurrency + 1) as u32;
            throttle += step.saturating_mul(over);
        }
        let over_envelope = throttle > Duration::ZERO;
        // Cap the throttle so it stays graceful (never an effective block)…
        if throttle > self.cfg.max_throttle {
            throttle = self.cfg.max_throttle;
        }
        // …then add jitter on top.
        let delay = throttle + self.next_jitter();

        // Record the visit (new or refreshed) — the request always proceeds.
        self.seen.insert(dest_host.to_string(), now_ms);

        ShapingDecision {
            delay,
            sticky,
            over_envelope,
        }
    }

    /// Like [`decide`](Self::decide) but reads the shaper's real monotonic clock —
    /// what the live proxy calls.
    pub fn decide_now(&mut self, dest_host: &str) -> ShapingDecision {
        let now = self.now_ms();
        self.decide(dest_host, now)
    }

    /// Mark a tunnel as opened (the proxy calls this after a `Proceed` decision,
    /// just before connecting). Affects the concurrency cap seen by later requests.
    pub fn note_open(&mut self) {
        self.in_flight += 1;
    }

    /// Mark a tunnel as closed (the proxy calls this when the tunnel ends).
    pub fn note_close(&mut self) {
        self.in_flight = self.in_flight.saturating_sub(1);
    }

    /// Current in-flight tunnel count (for tests / metrics).
    pub fn in_flight(&self) -> usize {
        self.in_flight
    }

    /// Distinct destinations currently in the window *as of the last `decide`*.
    /// (Does not prune; call after a `decide` for an accurate figure.)
    pub fn distinct_destinations(&self) -> usize {
        self.seen.len()
    }

    /// Next jitter delay, uniform in `[0, cfg.jitter)`. Zero if jitter is disabled.
    fn next_jitter(&mut self) -> Duration {
        let jitter_ms = self.cfg.jitter.as_millis() as u64;
        if jitter_ms == 0 {
            return Duration::ZERO;
        }
        // xorshift64
        let mut x = self.jitter_state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.jitter_state = x;
        Duration::from_millis(x % jitter_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_no_jitter(max_distinct: usize, max_concurrency: usize) -> ShapingConfig {
        ShapingConfig {
            window: Duration::from_secs(3600),
            max_distinct_destinations: max_distinct,
            max_concurrency,
            jitter: Duration::ZERO, // isolate throttle behavior
            throttle_step: Duration::from_millis(100),
            max_throttle: Duration::from_secs(5),
        }
    }

    /// THE headline DoD: one egress IP fanning out to 1000 unrelated domains is
    /// rate-limited *gracefully* — the first `max_distinct` go immediately, the
    /// rest are throttled with a bounded delay, and NONE is ever hard-blocked.
    #[test]
    fn thousand_distinct_domains_are_throttled_never_blocked() {
        let mut sh = VolumeShaper::new(cfg_no_jitter(50, 10_000), 1);
        let mut throttled = 0;
        for i in 0..1000 {
            let host = format!("site-{i}.example"); // all distinct
            let d = sh.decide(&host, 0); // same instant: nothing leaves the window
            if i < 50 {
                assert_eq!(d.delay, Duration::ZERO, "within envelope #{i} is immediate");
                assert!(!d.over_envelope);
            } else {
                assert!(d.delay > Duration::ZERO, "over-envelope #{i} is throttled");
                assert!(d.over_envelope);
                assert!(
                    d.delay <= Duration::from_secs(5),
                    "throttle stays graceful (capped)"
                );
                throttled += 1;
            }
            // The invariant that matters: it ALWAYS proceeds (no reject variant exists).
        }
        assert_eq!(throttled, 950);
        // The delay is monotone-ish increasing then capped — confirm the cap holds
        // at the extreme.
        let last = sh.decide("late.example", 0);
        assert_eq!(
            last.delay,
            Duration::from_secs(5),
            "throttle saturates at max_throttle"
        );
    }

    /// Sticky sessions: re-visiting seen hosts is free and never trips the cap,
    /// so a human reloading the same few sites is never throttled.
    #[test]
    fn sticky_revisits_are_free() {
        let mut sh = VolumeShaper::new(cfg_no_jitter(3, 10_000), 1);
        for h in ["a.com", "b.com", "c.com"] {
            assert_eq!(sh.decide(h, 0).delay, Duration::ZERO);
        }
        // The window is now full (3 distinct). Re-visiting any of them is sticky,
        // free, and not over-envelope — even though we're at the distinct cap.
        for _ in 0..100 {
            let d = sh.decide("b.com", 0);
            assert!(d.sticky, "re-visit is sticky");
            assert_eq!(
                d.delay,
                Duration::ZERO,
                "sticky re-visit is never throttled"
            );
            assert!(!d.over_envelope);
        }
        // A brand-new 4th distinct host IS throttled.
        let d = sh.decide("d.com", 0);
        assert!(!d.sticky);
        assert!(d.over_envelope);
        assert!(d.delay > Duration::ZERO);
    }

    /// The sliding window forgets old destinations, restoring headroom — exactly
    /// human behavior across hours.
    #[test]
    fn window_expiry_restores_headroom() {
        let mut sh = VolumeShaper::new(cfg_no_jitter(2, 10_000), 1);
        assert_eq!(sh.decide("a.com", 0).delay, Duration::ZERO);
        assert_eq!(sh.decide("b.com", 0).delay, Duration::ZERO);
        // 3rd within the window → throttled.
        assert!(sh.decide("c.com", 1000).over_envelope);
        // Far in the future: a.com/b.com/c.com have all aged out of the 1h window.
        let now = 3_600_001 + 1000;
        let d = sh.decide("d.com", now);
        assert!(
            !d.over_envelope,
            "old destinations expired → headroom restored"
        );
        assert_eq!(d.delay, Duration::ZERO);
        assert_eq!(
            sh.distinct_destinations(),
            1,
            "only d.com remains in the window"
        );
    }

    /// Concurrency cap: being at/over the in-flight limit paces new tunnels, and
    /// closing tunnels relieves the pressure — never a hard block.
    #[test]
    fn concurrency_cap_paces_then_relieves() {
        let mut sh = VolumeShaper::new(cfg_no_jitter(10_000, 2), 1);
        // Two tunnels open → at the cap.
        sh.note_open();
        sh.note_open();
        let d = sh.decide("x.com", 0);
        assert!(
            d.over_envelope,
            "at the concurrency cap, new tunnels are paced"
        );
        assert!(d.delay > Duration::ZERO);
        // Close both → pressure relieved, next request immediate (distinct cap huge).
        sh.note_close();
        sh.note_close();
        assert_eq!(sh.in_flight(), 0);
        let d2 = sh.decide("y.com", 0);
        assert_eq!(d2.delay, Duration::ZERO, "concurrency relieved → immediate");
    }

    /// Jitter is always within `[0, jitter)` and varies — never zero-config when
    /// enabled, never exceeding the bound.
    #[test]
    fn jitter_is_bounded_and_varies() {
        let mut cfg = cfg_no_jitter(10_000, 10_000);
        cfg.jitter = Duration::from_millis(200);
        let mut sh = VolumeShaper::new(cfg, 0xABCDEF);
        let mut seen_nonzero = false;
        let mut values = std::collections::HashSet::new();
        for i in 0..200 {
            let d = sh.decide(&format!("h{i}.com"), 0);
            // all within-envelope here (caps are huge), so delay == jitter only
            assert!(
                d.delay < Duration::from_millis(200),
                "jitter strictly below bound"
            );
            if d.delay > Duration::ZERO {
                seen_nonzero = true;
            }
            values.insert(d.delay.as_millis());
        }
        assert!(seen_nonzero, "jitter produced nonzero delays");
        assert!(values.len() > 5, "jitter varies across requests");
    }

    /// `note_close` underflow-safe; default config is sane.
    #[test]
    fn close_without_open_is_safe_and_defaults_sane() {
        let mut sh = VolumeShaper::new(ShapingConfig::default(), 1);
        sh.note_close(); // no panic, saturates at 0
        assert_eq!(sh.in_flight(), 0);
        let cfg = ShapingConfig::default();
        assert!(cfg.max_distinct_destinations > 0 && cfg.max_concurrency > 0);
    }
}
