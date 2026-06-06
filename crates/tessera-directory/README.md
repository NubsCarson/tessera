# tessera-directory

Signed, off-band exit-directory snapshots for Tessera clients, plus the
`tessera-directory` operator CLI.

A directory maps an `exit_id` to `{issuer_addr, relay_addr, exit_addr,
issuer_pk, weight, accepting flag, capacity, key_epoch}`. Clients pin a
directory signer set, verify a threshold of signatures and the validity window,
reject sequence/key-epoch rollback with optional local state, skip closed or
capacity-exhausted entries, select one exit key domain, and then pin the selected
issuer public key before issuance.

The CLI supports:

- `keygen` / `pin` for secp256k1 directory signer keys
- `snapshot` for deterministic unsigned directory text
- `sign` for threshold-signable snapshots
- `verify` for signer threshold, validity-window, and rollback-state checks
- `select` for inspecting the client-selected route

This crate is not a mirror protocol and not a distributed spent-tag store. It is
the local, deterministic verification and selection layer that mirrored directory
distribution can replicate later.
