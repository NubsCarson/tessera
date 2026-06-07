#!/usr/bin/env bash
# run-onion-exit.sh — the GATEWAY role (run this on the clean-IP box / droplet).
#
# Publishes the Tessera exit as a Tor onion service and runs the issuer beside it.
# The exit egresses to the clearnet from THIS host's IP; clients reach it over the
# `.onion` (no exit node, rendezvous hides the client). Admission is a single-use,
# unlinkable ARC credential; the secure target policy refuses private/metadata
# targets and non-:443 ports before any dial.
#
#   client.onion request ──▶ Tor ──▶ EXIT.onion:443 ──▶ 127.0.0.1:$EXIT_PORT (the exit)
#                                                    ──clean egress──▶ the internet
#
# Persisted state ($STATE_DIR) keeps the .onion address STABLE across restarts.
#
# HONESTY: the onion service secret key under HiddenServiceDir is a PLAIN on-disk
# file. A non-logging TEE must seal it to the enclave (the reserved dstack-kms
# path) — do not treat this on-disk key as enclave-protected. Research-grade,
# UNAUDITED; you must supply a genuinely clean egress IP (no code manufactures it).
set -euo pipefail
cd "$(dirname "$0")/.."

EXIT_PORT=${EXIT_PORT:-8118}                 # exit loopback bind (Tor maps .onion:443 here)
ISSUER_LISTEN=${ISSUER_LISTEN:-0.0.0.0:8121} # issuer bind (clients reach it for credentials)
STATE_DIR=${TESSERA_STATE_DIR:-./.onion-exit-state}
KEY_FILE=${TESSERA_KEY_FILE:-$STATE_DIR/arc.key}
TAG_FILE=${TESSERA_SPENT_TAG_FILE:-$STATE_DIR/spent-tags}
POW=${TESSERA_POW_DIFFICULTY:-16}

command -v tor >/dev/null || { echo "error: no 'tor' on PATH (prefer deb.torproject.org for pow:yes)"; exit 1; }

# This gateway role runs the RELEASE binaries; the one-box demo builds DEBUG. Build
# them if absent so a fresh checkout that only ran `cargo build` doesn't exec a
# missing binary (the error would otherwise be swallowed by the log filter below).
for bin in tessera-issuer tessera-proxy; do
  [ -x "target/release/$bin" ] && continue
  echo "building release binaries (cargo build --release -p tessera-issuer -p tessera-proxy)…"
  cargo build --release -p tessera-issuer -p tessera-proxy
  break
done

mkdir -p "$STATE_DIR" "$STATE_DIR/tor-data" "$STATE_DIR/hs"
chmod 700 "$STATE_DIR" "$STATE_DIR/tor-data" "$STATE_DIR/hs"

# Onion-service torrc. SocksPort 0: the exit egresses Direct, it needs no SOCKS.
# HiddenServicePoWDefensesEnabled raises the cost of onion-flooding the gateway —
# but only if THIS tor build compiled the PoW code in (a distro build may accept
# the option yet leave the defense inert; check tor.log, prefer deb.torproject.org).
cat >"$STATE_DIR/torrc" <<EOF
SocksPort 0
DataDirectory $(realpath "$STATE_DIR/tor-data")
HiddenServiceDir $(realpath "$STATE_DIR/hs")
HiddenServicePort 443 127.0.0.1:$EXIT_PORT
HiddenServicePoWDefensesEnabled 1
Log notice file $(realpath "$STATE_DIR")/tor.log
EOF

echo "starting tor (publishing the exit onion service)…"
tor -f "$STATE_DIR/torrc" & TOR_PID=$!
# Kill the tracked PIDs, then pkill any stragglers (process-substitution log
# filters) so nothing — least of all the exit holding the durable spent-tag file
# — is orphaned on Ctrl-C, which would block a re-run with "address already in use".
trap 'kill $TOR_PID ${ISSUER_PID:-} ${EXIT_PID:-} 2>/dev/null; pkill -P $$ 2>/dev/null; true' EXIT
for _ in $(seq 1 60); do [ -f "$STATE_DIR/hs/hostname" ] && break; sleep 0.5; done
ONION=$(tr -d '\n' <"$STATE_DIR/hs/hostname")

echo "starting issuer (shared ARC key, PoW difficulty $POW)…"
# `> >(sed …) 2>&1 & PID=$!` captures the BINARY's PID (a `… | sed &` pipeline
# would capture sed's, orphaning the binary on cleanup). The log prefix is kept.
TESSERA_KEY_PROVIDER=file TESSERA_KEY_FILE="$KEY_FILE" TESSERA_ISSUER_LISTEN="$ISSUER_LISTEN" \
  TESSERA_POW_DIFFICULTY="$POW" target/release/tessera-issuer > >(sed 's/^/[issuer] /') 2>&1 & ISSUER_PID=$!
sleep 1

echo "starting exit (tessera-proxy, SAME key, secure target policy, durable spent-tags)…"
TESSERA_KEY_PROVIDER=file TESSERA_KEY_FILE="$KEY_FILE" TESSERA_LISTEN="127.0.0.1:$EXIT_PORT" \
  TESSERA_TARGET_POLICY=secure TESSERA_SPENT_TAG_FILE="$TAG_FILE" \
  target/release/tessera-proxy > >(sed 's/^/[exit] /') 2>&1 & EXIT_PID=$!

cat <<EOF

============================================================================
  Tessera onion egress is UP.

  exit onion : $ONION
  issuer     : <this host's reachable address>:${ISSUER_LISTEN##*:}

  On the client box, run:
    TESSERA_EXIT_ONION=$ONION:443 \\
    TESSERA_ISSUER=<this-host>:${ISSUER_LISTEN##*:} \\
    scripts/run-onion-client.sh

  (firewall the exit's $EXIT_PORT to loopback only — it must be reachable solely
   through the onion, never this host's public IP.)
============================================================================
EOF
wait
