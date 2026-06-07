# Tessera — next steps and non-goals

This is the short, current answer to: "what is left?"

The repository does not have a known hidden hygiene/correctness blocker. The
mainline artifact is code-complete for the local, self-hostable protocol demo:
credential issuance, paid mint, client proxy, split-trust relay/exit loop,
directory verification/selection, per-exit key domains, the exit target/SSRF
policy, the client→exit `.onion` lane, the onion-aware directory v2, docs, CI,
fuzz smoke, coverage, Foundry, Slither, audit/deny gates.

What remains is either forward product work or an external hand-off. Do not
rewrite shipped code just to look busy; pick one of these only when it advances a
real deployment, audit, or user workflow.

## Recently landed (the clean onion egress lane)

Built and tested (see [`CLEAN_ONION_EGRESS.md`](./CLEAN_ONION_EGRESS.md)):
secure-by-default exit target/SSRF policy + per-tunnel caps; a pluggable
`transport::Dialer` seam; the single-hop client→exit `.onion` route (relay
bypassed, cold-start retry, startup self-skip when Tor is down); and the signed
directory **v2** `.onion`/`clean_egress` advertisement + selection. The
remaining lane work is below — and it is the *external* half: a clean egress IP,
a real Tor crowd, routing issuance over Tor, and wiring the directory's signed
onion endpoint into the client's automatic route selection.

## Best local follow-ups

These can be started in this repo, but they are new scope rather than unfinished
cleanup.

| Track | Why it matters | Local done-when | External dependency |
|---|---|---|---|
| Browser extension final mile | Makes the system usable by a human, not just by tests and curl. | MV3 UI/config, issuer/directory setup flow, packaged extension, manual-browser checklist. | Real browser/manual install and live origin test. |
| dstack KMS + attestation UX | Turns the TEE path from "reserved/fail-closed" into an operator flow. | Implement `dstack-kms`, document quote verification, add fail-closed tests/mocks. | Live TDX/dstack/KMS environment to prove sealing and attestation end to end. |
| Distributed spent-tag backend | Required before a multi-exit deployment can share replay state safely. | A concrete `SpentTagStore` backend or protocol sketch with race tests and failure semantics. | Multi-node ops validation; production datastore choice. |
| Mirrored directory ops | Moves signed directory verification from local artifact to real operation. | Publisher/runbook, rotation drills, monitoring, stale-snapshot recovery docs/tests. | Multiple independent operators and hosted mirrors. |
| Clean-egress experiment | The highest-signal proof for the access thesis. The lane *software* is now built (onion route + SSRF gate + directory v2); this is the live run. | Runbook and instrumentation for "Tor-blocked site returns 200 through Tessera exit." | A clean residential/ISP egress IP. |
| Directory-driven onion selection | Let the client consume the directory's signed `onion_addr` instead of the env var. | Wire the selected entry's `onion_addr` into `ClientRoute::Onion`; lift the env/directory mutual-exclusion. | None (local). |
| S34 egress lanes | Future clean-egress efficiency: PIR/cacheable reads, green routing, x402 lanes. | A scoped design/prototype that does not overclaim production unblock. | Real destinations and clean-egress data to know what helps. |
| Staking economics decision | Needed before any tokenomics or Solidity beyond the current testnet rail. | Decision doc choosing scarcity curve vs clean-IP supply vs no staking yet. | Your product/economic call; should not be guessed in code. |

## External hand-offs

These cannot be made true by local code alone:

- Third-party security audit and constant-time review.
- Clean residential/ISP egress IPs at useful scale.
- Tor/Nym anonymity crowd and live transport operations.
- Live replicated multi-exit directory operation.
- Distributed spent-tag consistency under real multi-node load.
- Multi-party Groth16 ceremony if the optional ZK court tier ever carries real value.
- Mainnet deployment with real funds.
- Legal/liability model for operating exits.

## Guardrails

- Do not call the current artifact production-safe or audited.
- Do not build speculative staking/tokenomics until the economics are chosen.
- Do not present dstack KMS as implemented until `dstack-kms` stops failing closed
  and is proven against a live or faithful test environment.
- Do not present directory verification as live replicated directory operation.
  The verifier/client selector is built; operations are still deployment work.
- Do not present durable local spent tags as distributed replay prevention.
  `FileTagStore` is restart durability, not multi-node consistency.
- Do not treat NICE-tier items as blockers. They are polish/research unless a
  deployment or audit specifically needs them.
