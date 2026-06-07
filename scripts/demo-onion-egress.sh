#!/usr/bin/env bash
# demo-onion-egress.sh — stand up the whole Tessera Tor-native onion egress on ONE
# box and pull a live HTTPS site through it, end to end:
#
#   curl ──▶ tessera-client (local proxy) ──Tor SOCKS──▶ EXIT.onion:443
#                                          (single hop, no exit node)
#   EXIT (ARC-gated, SSRF-hardened) ──clean egress──▶ the live site (TLS e2e)
#
# It proves the full datapath with REAL Tor: the request traverses a real onion
# circuit, is admitted on a single-use ARC credential, clears the secure target
# policy, and reaches the live internet.
#
# Honest caveat: on one machine the egress IP equals your own IP (the exit
# egresses from this box). The *clean egress IP* is a two-machine concern — run
# the exit on a separate clean-IP host (see scripts/run-onion-exit.sh +
# scripts/run-onion-client.sh). This script proves the datapath, not a clean IP.
#
# Requires: a `tor` binary on PATH, outbound internet, and a built workspace
# (`cargo build`). Research-grade, UNAUDITED.
set -euo pipefail

cd "$(dirname "$0")/.."
EXITPORT=${EXITPORT:-18443}
SOCKS=${SOCKS:-19250}
ISSUER=${ISSUER:-18121}
CLIENT=${CLIENT:-18120}
TARGET=${1:-https://api.ipify.org}   # a live HTTPS site to pull through the egress
DIFFICULTY=${TESSERA_POW_DIFFICULTY:-8}

command -v tor >/dev/null || { echo "error: no 'tor' on PATH (apt install tor)"; exit 1; }
for b in tessera-issuer tessera-proxy tessera-client; do
  [ -x "target/debug/$b" ] || { echo "building $b…"; cargo build -q -p "${b/tessera-client/tessera-relay}" -p tessera-issuer -p tessera-proxy; break; }
done

WORK=$(mktemp -d /tmp/tessera-onion-XXXX); HS="$WORK/hs"; DATA="$WORK/data"; KEY="$WORK/arc.key"
mkdir -p "$HS" "$DATA"; chmod 700 "$HS" "$DATA"
PIDS=()
cleanup(){ kill "${PIDS[@]}" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT
echo "workdir: $WORK"

echo "1) issuer — establishes the shared ARC key (PoW difficulty $DIFFICULTY for the demo)"
TESSERA_KEY_PROVIDER=file TESSERA_KEY_FILE="$KEY" TESSERA_ISSUER_LISTEN="127.0.0.1:$ISSUER" \
  TESSERA_POW_DIFFICULTY="$DIFFICULTY" target/debug/tessera-issuer >"$WORK/issuer.out" 2>&1 & PIDS+=($!)
for _ in $(seq 1 40); do [ -f "$KEY" ] && break; sleep 0.4; done

echo "2) exit — tessera-proxy, SAME key, secure SSRF/target policy"
TESSERA_KEY_PROVIDER=file TESSERA_KEY_FILE="$KEY" TESSERA_LISTEN="127.0.0.1:$EXITPORT" \
  TESSERA_TARGET_POLICY=secure target/debug/tessera-proxy >"$WORK/exit.out" 2>&1 & PIDS+=($!)
for _ in $(seq 1 40); do grep -q 'live on' "$WORK/exit.out" && break; sleep 0.4; done

echo "3) tor — publish the exit as an onion service (.onion:443 -> the exit's loopback)"
cat >"$WORK/torrc" <<EOF
SocksPort 127.0.0.1:$SOCKS
DataDirectory $DATA
HiddenServiceDir $HS
HiddenServicePort 443 127.0.0.1:$EXITPORT
Log notice file $WORK/tor.log
EOF
tor -f "$WORK/torrc" >/dev/null 2>&1 & PIDS+=($!)
for _ in $(seq 1 60); do [ -f "$HS/hostname" ] && break; sleep 0.5; done
ONION=$(tr -d '\n' <"$HS/hostname"); echo "   onion: $ONION"

echo "4) tessera-client — obtains a credential, routes over the onion (Tor-native)"
TESSERA_ISSUER="127.0.0.1:$ISSUER" TESSERA_EXIT_ONION="$ONION:443" TESSERA_TOR_SOCKS="127.0.0.1:$SOCKS" \
  TESSERA_CLIENT_LISTEN="127.0.0.1:$CLIENT" target/debug/tessera-client >"$WORK/client.out" 2>&1 & PIDS+=($!)
for _ in $(seq 1 60); do grep -qi 'route:' "$WORK/client.out" && break; sleep 0.5; done

echo
echo "=== pulling $TARGET through the onion egress (retrying past the ~30-90s descriptor publish) ==="
OUT=""
for i in $(seq 1 25); do
  OUT=$(curl -s --max-time 25 -x "http://127.0.0.1:$CLIENT" "$TARGET" 2>/dev/null || true)
  [ -n "$OUT" ] && break
  printf ' try%d' "$i"; sleep 4
done
echo
echo "------------------------------------------------------------"
echo "response through the onion egress:"
echo "${OUT:-<no response — descriptor may still be publishing; re-run>}" | head -20
echo "------------------------------------------------------------"
echo "(one box, so the egress IP is this host's; on a two-machine deploy it is the exit's clean IP)"
