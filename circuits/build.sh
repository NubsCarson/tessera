#!/usr/bin/env bash
# =============================================================================
# circuits/build.sh — LOCAL R_dec build + DEV/TEST trusted setup (Phase 2b-i).
#
# This compiles R_dec.circom, runs a *single-party, test-only* Groth16/BN254
# ceremony with snarkjs, exports the Solidity verifier, generates a witness +
# proof for the pinned vector, and verifies it. CI does NOT run this — CI only
# `forge test`s the committed verifier against the committed pinned proof
# vector. This script is the developer step that (re)generates them.
#
#   !!! DEV-CEREMONY HONESTY !!!
#   The phase-2 contribution below is a SINGLE party (this script) with PUBLIC,
#   non-secret entropy. That is NOT a secure setup: anyone who knows the toxic
#   waste can forge proofs. A real deployment needs a MULTI-PARTY phase-2
#   ceremony (many independent contributors; at least one honest). This is
#   flagged in circuits/README.md and is intentionally not faked here.
#
# Requirements (NOT in CI): circom (>=2.1) and snarkjs (>=0.7) on PATH, plus
# `npm install` in this dir (circomlib). See README for install.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

CIRCOM="${CIRCOM:-circom}"
SNARKJS="${SNARKJS:-snarkjs}"
BUILD=build
PTAU="$BUILD/pot14_final.ptau"
# 2^14 = 16384 constraints capacity; R_dec is ~3.4k, comfortably under.
POT_POWER=14

mkdir -p "$BUILD"

echo "==> [1/7] compile R_dec.circom"
"$CIRCOM" R_dec.circom --r1cs --wasm --sym -o "$BUILD" -l node_modules/circomlib/circuits

echo "==> [1b] constraint count"
"$SNARKJS" r1cs info "$BUILD/R_dec.r1cs"

echo "==> [2/7] powersOfTau (phase 1, test entropy)"
if [ ! -f "$PTAU" ]; then
  "$SNARKJS" powersoftau new bn128 "$POT_POWER" "$BUILD/pot_0000.ptau" -v
  # DEV entropy — NOT secret. A real ceremony takes many independent contribs.
  "$SNARKJS" powersoftau contribute "$BUILD/pot_0000.ptau" "$BUILD/pot_0001.ptau" \
    --name="tessera-dev-1" -v -e="tessera dev phase1 entropy (NOT SECRET)"
  "$SNARKJS" powersoftau prepare phase2 "$BUILD/pot_0001.ptau" "$PTAU" -v
fi

echo "==> [3/7] groth16 setup (phase 2, test entropy) + verifier export"
"$SNARKJS" groth16 setup "$BUILD/R_dec.r1cs" "$PTAU" "$BUILD/R_dec_0000.zkey"
"$SNARKJS" zkey contribute "$BUILD/R_dec_0000.zkey" "$BUILD/R_dec_final.zkey" \
  --name="tessera-dev-phase2-1" -v -e="tessera dev phase2 entropy (NOT SECRET)"
"$SNARKJS" zkey export verificationkey "$BUILD/R_dec_final.zkey" "$BUILD/verification_key.json"

echo "==> [4/7] export Solidity verifier -> ../contracts/src/RDecVerifier.sol"
"$SNARKJS" zkey export solidityverifier "$BUILD/R_dec_final.zkey" "$BUILD/RDecVerifier.raw.sol"
# Normalize the pragma/name so it drops into the dependency-free Foundry project.
python3 fixup_verifier.py "$BUILD/RDecVerifier.raw.sol" ../contracts/src/RDecVerifier.sol

echo "==> [5/7] generate the PINNED input vector from Rust (tessera-channel)"
# The Rust example prints input.json for a real spend (and the Solidity vector
# constants). It also self-checks the Poseidon commitments cross-language.
( cd .. && cargo run -q -p tessera-channel --example rdec_vector ) > "$BUILD/rdec_vector.out"
sed -n '/^>>>INPUT_JSON_BEGIN<<</,/^>>>INPUT_JSON_END<<</p' "$BUILD/rdec_vector.out" \
  | sed '1d;$d' > "$BUILD/input.json"
echo "    wrote $BUILD/input.json"

echo "==> [6/7] witness + proof + local verify"
node "$BUILD/R_dec_js/generate_witness.js" "$BUILD/R_dec_js/R_dec.wasm" \
  "$BUILD/input.json" "$BUILD/witness.wtns"
"$SNARKJS" groth16 prove "$BUILD/R_dec_final.zkey" "$BUILD/witness.wtns" \
  "$BUILD/proof.json" "$BUILD/public.json"
"$SNARKJS" groth16 verify "$BUILD/verification_key.json" \
  "$BUILD/public.json" "$BUILD/proof.json"

echo "==> [7/7] emit the Solidity calldata + pin block for RDecVerifier.t.sol"
echo "--- snarkjs generatecall (paste into contracts/test/RDecVerifier.t.sol) ---"
"$SNARKJS" zkey export soliditycalldata "$BUILD/public.json" "$BUILD/proof.json"
echo
echo "==> done. public.json:"
cat "$BUILD/public.json"
echo
echo "Remember: this ceremony is TEST-ONLY / single-party. Do NOT trust these"
echo "keys for anything real. Re-run regenerates the pinned vector + verifier."
