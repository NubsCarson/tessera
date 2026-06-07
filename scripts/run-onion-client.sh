#!/usr/bin/env bash
# run-onion-client.sh — the CLIENT role (run this on your laptop).
#
# Starts a client-only Tor (SOCKS, no onion service of its own) and the local
# tessera-client proxy on the onion route. Point a browser / curl at the proxy;
# every request mints a fresh single-use ARC token and is tunneled over Tor to the
# exit's `.onion` — the exit never sees your IP (rendezvous), TLS stays end to end.
#
#   curl ─▶ tessera-client (127.0.0.1:$CLIENT_LISTEN) ─Tor SOCKS─▶ EXIT.onion:443 ─▶ site
#
# Required env (printed by run-onion-exit.sh):
#   TESSERA_EXIT_ONION   the exit's <onion>:443
#   TESSERA_ISSUER       host:port to obtain a credential from
#
# HONESTY: obtaining the credential connects you DIRECTLY to the issuer, so the
# issuer sees your IP at issuance time (ARC still keeps it unlinkable from your
# browsing). Routing issuance over Tor too is a documented next step. Tor must be
# running — this is Tor-native; it will NOT silently fall back to clearnet unless
# you set TESSERA_ALLOW_CLEARNET_FALLBACK=1.
set -euo pipefail
cd "$(dirname "$0")/.."

: "${TESSERA_EXIT_ONION:?set TESSERA_EXIT_ONION=<onion>:443 (from run-onion-exit.sh)}"
: "${TESSERA_ISSUER:?set TESSERA_ISSUER=<host>:<port> (from run-onion-exit.sh)}"
CLIENT_LISTEN=${TESSERA_CLIENT_LISTEN:-127.0.0.1:8120}
# Default OFF the distro tor's 9050: an `apt install tor` daemon already owns 9050,
# so the script's own tor would fail to bind and we'd silently ride the system tor.
SOCKS=${SOCKS_PORT:-19250}
STATE_DIR=${TESSERA_STATE_DIR:-./.onion-client-state}

command -v tor >/dev/null || { echo "error: no 'tor' on PATH"; exit 1; }
# Build the release tessera-client if absent (it lives in the tessera-relay pkg).
[ -x target/release/tessera-client ] || {
  echo "building release tessera-client (cargo build --release -p tessera-relay)…"
  cargo build --release -p tessera-relay
}
mkdir -p "$STATE_DIR/tor-data"; chmod 700 "$STATE_DIR" "$STATE_DIR/tor-data"

# Client torrc: SOCKS only — the asymmetry is the point. The exit PUBLISHES an
# onion service; the client just DIALS one over SOCKS.
cat >"$STATE_DIR/torrc" <<EOF
SocksPort 127.0.0.1:$SOCKS
DataDirectory $(realpath "$STATE_DIR/tor-data")
Log notice file $(realpath "$STATE_DIR")/tor.log
EOF

echo "starting client Tor (SOCKS on 127.0.0.1:$SOCKS)…"
tor -f "$STATE_DIR/torrc" & TOR_PID=$!
trap 'kill $TOR_PID ${CLIENT_PID:-} 2>/dev/null; pkill -P $$ 2>/dev/null; true' EXIT

# Wait for real circuits, not a fixed `sleep`: the onion dial fails until Tor is
# bootstrapped (and if SOCKS failed to bind, this times out and warns instead of
# silently riding a system tor).
printf 'waiting for Tor to bootstrap'
for _ in $(seq 1 60); do
  grep -q 'Bootstrapped 100%' "$STATE_DIR/tor.log" 2>/dev/null && break
  printf '.'; sleep 1
done
echo
grep -q 'Bootstrapped 100%' "$STATE_DIR/tor.log" 2>/dev/null \
  || echo "warning: Tor did not report 'Bootstrapped 100%' within 60s; first requests may fail until circuits build (and the descriptor publish adds ~30-90s)."

echo "starting tessera-client on the onion route…"
TESSERA_EXIT_ONION="$TESSERA_EXIT_ONION" TESSERA_ISSUER="$TESSERA_ISSUER" \
  TESSERA_TOR_SOCKS="127.0.0.1:$SOCKS" TESSERA_CLIENT_LISTEN="$CLIENT_LISTEN" \
  target/release/tessera-client & CLIENT_PID=$!

cat <<EOF

============================================================================
  Tessera onion client is UP. Browse through it:

    curl -x http://$CLIENT_LISTEN https://api.ipify.org   # shows the EXIT's IP
    curl -x http://$CLIENT_LISTEN https://example.com

  The destination sees the exit's clean IP, never yours; the exit sees the Tor
  rendezvous circuit, never your IP.
============================================================================
EOF
wait
