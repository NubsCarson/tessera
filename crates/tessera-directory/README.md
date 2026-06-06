# tessera-directory

Signed, off-band exit-directory snapshots for Tessera clients.

A directory maps an `exit_id` to `{issuer_addr, relay_addr, exit_addr,
issuer_pk}`. Clients pin a directory signer set, verify a threshold of signatures,
select one exit key domain, and then pin the selected issuer public key before
issuance.

This crate is not a mirror protocol and not a distributed spent-tag store. It is
the local, deterministic verification and selection layer that mirrored directory
distribution can replicate later.
