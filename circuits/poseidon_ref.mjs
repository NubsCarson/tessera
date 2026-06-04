// Cross-language Poseidon sanity check. Prints circomlibjs `poseidon([..])` for
// the same inputs the Rust `tessera_channel::poseidon` known-answer test pins
// (and that the circom `Poseidon(n)` template computes). If these three ever
// disagree, the Rust-derived commitment would not match the circuit/chain.
//   run: node poseidon_ref.mjs   (after `npm install`)
import { buildPoseidon } from "circomlibjs";
const poseidon = await buildPoseidon();
const F = poseidon.F;
console.log("poseidon([1,2])            =", F.toString(poseidon([1n, 2n])));
console.log("poseidon([1,2,3,4])        =", F.toString(poseidon([1n, 2n, 3n, 4n])));
console.log("poseidon([10,20,30,40,50]) =", F.toString(poseidon([10n, 20n, 30n, 40n, 50n])));
