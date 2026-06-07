# Running Tessera nodes under systemd (hardened)

Example **hardened** systemd units for running the Tessera nodes turnkey on a
Linux host (the alternative to the Docker Compose topology in
[`../docker-compose.yaml`](../docker-compose.yaml)). Research-grade, **UNAUDITED** —
read [`../../docs/DEPLOYMENT_TOPOLOGY.md`](../../docs/DEPLOYMENT_TOPOLOGY.md) first
(notably: running relay **and** exit as one operator gives no relationship
anonymity), and supply a genuinely clean egress IP (no code manufactures one).

## What's here
- `tessera-issuer.service`, `tessera-exit.service` — share a fixed `tessera` user
  and `/var/lib/tessera` so the issuer's ARC key is the one the exit loads.
- `tessera-relay.service`, `tessera-client.service` — stateless; run as an
  ephemeral `DynamicUser`.

Every unit drops **all** capabilities, forbids privilege escalation, makes the
system read-only, restricts syscalls to `@system-service` and address families to
INET/INET6/UNIX — these are user-space network apps that need nothing more.

## Install
1. Install the binaries to `/usr/local/bin/` (e.g. `cargo build --release` then
   copy `tessera-{issuer,proxy,relay,client}`), and create the shared user:
   ```sh
   sudo useradd -r -s /usr/sbin/nologin tessera
   ```
2. Create the env files under `/etc/tessera/` (mode `0640`, owner `tessera`). The
   key file + durable spent-tag log live in the unit's `StateDirectory`
   (`/var/lib/tessera`). Examples:

   `/etc/tessera/issuer.env`
   ```sh
   TESSERA_ISSUER_LISTEN=0.0.0.0:8121
   TESSERA_KEY_FILE=/var/lib/tessera/server.key
   TESSERA_POW_DIFFICULTY=18
   ```
   `/etc/tessera/exit.env`
   ```sh
   TESSERA_LISTEN=0.0.0.0:8118
   TESSERA_UPSTREAM=direct
   TESSERA_KEY_FILE=/var/lib/tessera/server.key
   TESSERA_SPENT_TAG_FILE=/var/lib/tessera/spent-tags.log   # or TESSERA_SPENT_TAG_REDIS=host:6379 for multi-node
   TESSERA_TARGET_POLICY=secure
   TESSERA_HEALTH_LISTEN=127.0.0.1:9118                     # counts-only /healthz /readyz /metrics
   ```
   `/etc/tessera/relay.env`
   ```sh
   TESSERA_RELAY_LISTEN=0.0.0.0:8119
   TESSERA_EXIT_ADDR=exit-host:8118
   ```
   `/etc/tessera/client.env`
   ```sh
   TESSERA_ISSUER=issuer-host:8121
   TESSERA_EXIT_ONION=<exit>.onion:443    # or TESSERA_RELAY/TESSERA_EXIT for the clearnet loop
   TESSERA_CLIENT_LISTEN=127.0.0.1:8120
   TESSERA_ISSUER_PK=<issuer pk fingerprint>
   # censored network? add TESSERA_PT=obfs4 + TESSERA_BRIDGE_LINES=... (see docs/CENSORSHIP_RESISTANCE.md)
   ```
3. Enable + start:
   ```sh
   sudo cp tessera-*.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now tessera-issuer tessera-exit   # + relay/client where applicable
   ```
4. Healthcheck / monitoring: scrape `http://127.0.0.1:9118/metrics` (counts only,
   no identifiers — [`OBSERVABILITY.md`](../../docs/OBSERVABILITY.md) §5);
   `/readyz` returns 200 once the exit is serving.
