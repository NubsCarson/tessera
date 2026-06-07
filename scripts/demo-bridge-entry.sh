#!/usr/bin/env bash
# demo-bridge-entry.sh — prove the UNBLOCKABLE-ENTRY half end to end on ONE box:
# the client reaches the network through a Tor **obfs4 bridge** (disguised entry),
# then over Tor to the Tessera exit's .onion, and pulls a live site through the
# credential-gated egress.
#
#   curl ─▶ tessera-client ──obfs4──▶ LOCAL obfs4 bridge ──Tor──▶ EXIT.onion ─▶ site
#                          (disguised)                    (rendezvous, no exit node)
#
# obfs4 is Tor's own pluggable transport — this script only *configures* real Tor +
# obfs4proxy (it reimplements neither). The bridge is a LOCAL bridge relay we run
# ourselves: it proves the obfs4 entry DATAPATH works, NOT that it defeats a real
# nation-state censor (that needs a real, censor-unknown bridge population + real
# users + the ongoing arms race — all external). Research-grade, UNAUDITED.
#
# Requires: tor + obfs4proxy on PATH, outbound internet (the bridge relays into the
# real Tor network), and a built workspace.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

OBFS4PROXY=${TESSERA_PT_OBFS4PROXY:-$(command -v obfs4proxy || true)}
command -v tor >/dev/null || { echo "error: no 'tor' on PATH (apt install tor)"; exit 1; }
[ -n "$OBFS4PROXY" ] && [ -x "$OBFS4PROXY" ] || { echo "error: no obfs4proxy (apt install obfs4proxy)"; exit 1; }
for b in tessera-issuer tessera-proxy tessera-client; do
  [ -x "target/debug/$b" ] || { echo "building…"; cargo build -q -p tessera-relay -p tessera-issuer -p tessera-proxy; break; }
done

EXITPORT=${EXITPORT:-18443}; ISSUER=${ISSUER:-18121}; CLIENT=${CLIENT:-18120}
ESOCKS=${ESOCKS:-19350}        # the exit-side tor SOCKS (publishes the onion)
CSOCKS=${CSOCKS:-19360}        # the client-side tor SOCKS (enters via the bridge)
ORPORT=${ORPORT:-19370}        # the local bridge relay's ORPort
PTPORT=${PTPORT:-19380}        # the bridge's obfs4 listen port
TARGET=${1:-https://api.ipify.org}
WORK=$(mktemp -d /tmp/tessera-bridge-XXXX)
PIDS=(); cleanup(){ kill "${PIDS[@]}" 2>/dev/null||true; pkill -P $$ 2>/dev/null||true; rm -rf "$WORK"; }
trap cleanup EXIT
mkdir -p "$WORK"/{br,brdata,exit-data,exit-hs,cli-data}; chmod 700 "$WORK"/br "$WORK"/exit-hs
echo "workdir: $WORK"
KEY="$WORK/arc.key"

echo "1) local obfs4 BRIDGE relay (tor runs obfs4proxy; private, unpublished)"
cat >"$WORK/bridge.torrc" <<EOF
DataDirectory $WORK/brdata
SocksPort 0
ORPort 127.0.0.1:$ORPORT
BridgeRelay 1
AssumeReachable 1
PublishServerDescriptor 0
ServerTransportPlugin obfs4 exec $OBFS4PROXY
ServerTransportListenAddr obfs4 127.0.0.1:$PTPORT
ExtORPort auto
Log notice file $WORK/bridge.log
EOF
tor -f "$WORK/bridge.torrc" >/dev/null 2>&1 & PIDS+=($!)
echo -n "   waiting for the obfs4 cert + bridge fingerprint"
for _ in $(seq 1 60); do
  [ -f "$WORK/brdata/pt_state/obfs4_bridgeline.txt" ] && [ -f "$WORK/brdata/fingerprint" ] && break
  printf '.'; sleep 1
done; echo
FP=$(awk '{print $2}' "$WORK/brdata/fingerprint" 2>/dev/null)
CERTLINE=$(grep -oE 'cert=[^ ]+ iat-mode=[0-9]' "$WORK/brdata/pt_state/obfs4_bridgeline.txt" 2>/dev/null)
[ -n "$FP" ] && [ -n "$CERTLINE" ] || { echo "   error: bridge did not produce a bridgeline; see $WORK/bridge.log"; tail -5 "$WORK/bridge.log"; exit 1; }
BRIDGE_LINE="obfs4 127.0.0.1:$PTPORT $FP $CERTLINE"
echo "   bridge line: ${BRIDGE_LINE:0:70}…"

echo "2) issuer (shared ARC key, low PoW for the demo)"
TESSERA_KEY_PROVIDER=file TESSERA_KEY_FILE="$KEY" TESSERA_ISSUER_LISTEN="127.0.0.1:$ISSUER" \
  TESSERA_POW_DIFFICULTY=8 target/debug/tessera-issuer >"$WORK/issuer.out" 2>&1 & PIDS+=($!)
for _ in $(seq 1 40); do [ -f "$KEY" ] && break; sleep 0.4; done

echo "3) exit (SAME key, secure SSRF policy) + its own tor publishing the .onion"
TESSERA_KEY_PROVIDER=file TESSERA_KEY_FILE="$KEY" TESSERA_LISTEN="127.0.0.1:$EXITPORT" \
  TESSERA_TARGET_POLICY=secure target/debug/tessera-proxy >"$WORK/exit.out" 2>&1 & PIDS+=($!)
for _ in $(seq 1 40); do grep -q 'live on' "$WORK/exit.out" && break; sleep 0.4; done
cat >"$WORK/exit.torrc" <<EOF
SocksPort 127.0.0.1:$ESOCKS
DataDirectory $WORK/exit-data
HiddenServiceDir $WORK/exit-hs
HiddenServicePort 443 127.0.0.1:$EXITPORT
Log notice file $WORK/exit-tor.log
EOF
tor -f "$WORK/exit.torrc" >/dev/null 2>&1 & PIDS+=($!)
for _ in $(seq 1 90); do [ -f "$WORK/exit-hs/hostname" ] && break; sleep 0.5; done
ONION=$(tr -d '\n' <"$WORK/exit-hs/hostname"); echo "   exit onion: $ONION"

echo "4) client — enters via the obfs4 bridge, routes over Tor to the exit .onion"
TESSERA_ISSUER="127.0.0.1:$ISSUER" TESSERA_EXIT_ONION="$ONION:443" \
  TESSERA_TOR_SOCKS="127.0.0.1:$CSOCKS" TESSERA_CLIENT_LISTEN="127.0.0.1:$CLIENT" \
  SOCKS_PORT="$CSOCKS" TESSERA_PT=obfs4 TESSERA_BRIDGE_LINES="$BRIDGE_LINE" \
  TESSERA_PT_OBFS4PROXY="$OBFS4PROXY" TESSERA_STATE_DIR="$WORK/cli" \
  bash scripts/run-onion-client.sh >"$WORK/client.out" 2>&1 & PIDS+=($!)
for _ in $(seq 1 90); do grep -qi 'route:' "$WORK/client.out" && break; sleep 1; done

echo
echo "=== pulling $TARGET through obfs4 → Tor → .onion (retrying past bootstrap/descriptor) ==="
OUT=""
for i in $(seq 1 30); do
  OUT=$(curl -s --max-time 25 -x "http://127.0.0.1:$CLIENT" "$TARGET" 2>/dev/null || true)
  [ -n "$OUT" ] && break
  printf ' try%d' "$i"; sleep 5
done
echo; echo "------------------------------------------------------------"
echo "response through the obfs4 bridge → Tor → onion egress:"
echo "${OUT:-<no response — bridge/onion may still be bootstrapping; re-run>}" | head -5
echo "------------------------------------------------------------"
echo "(a self-run local bridge proves the obfs4 ENTRY datapath — NOT resistance to a"
echo " real censor; that needs a real censor-unknown bridge population + users, external.)"
[ -n "$OUT" ] || exit 1
