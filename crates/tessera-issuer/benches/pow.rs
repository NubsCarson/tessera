//! Criterion benchmarks for the proof-of-work issuance gate (S33): solving a
//! challenge (the cost the client pays) across a few difficulties, and verifying
//! a solution (the cheap check the server runs).
//!
//! Run with `cargo bench -p tessera-issuer`.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use rand_core::OsRng;
use tessera_issuer::{solve, PowChallenge};

/// Modest difficulties (leading zero bits) so the bench finishes quickly:
/// solving costs ~2^difficulty hashes in expectation.
const DIFFICULTIES: &[u32] = &[8, 12, 16];

fn bench_pow(c: &mut Criterion) {
    let mut rng = OsRng;

    // Solve: each iteration brute-forces a fresh challenge, since cost is
    // randomized per nonce (~2^difficulty hashes) and a solved counter would
    // otherwise be reused for free.
    for &difficulty in DIFFICULTIES {
        c.bench_function(&format!("solve (difficulty {difficulty})"), |b| {
            b.iter_batched(
                || PowChallenge::new(&mut rng, difficulty),
                |challenge| solve(&challenge),
                BatchSize::SmallInput,
            )
        });
    }

    // Verify a fixed pre-solved challenge (verification is one hash, independent
    // of difficulty).
    let challenge = PowChallenge::new(&mut rng, 16);
    let solution = solve(&challenge);
    c.bench_function("verify solution", |b| {
        b.iter(|| challenge.verify(&solution))
    });
}

criterion_group!(benches, bench_pow);
criterion_main!(benches);
