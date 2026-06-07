#!/usr/bin/env bash
# backup-spent-tags.sh — safely back up / restore the durable spent-tag ledger
# (TESSERA_SPENT_TAG_FILE) so an exit's double-spend protection survives a host
# loss, not just a process restart.
#
#   scripts/backup-spent-tags.sh backup  <tag-file> [backup-dir]
#   scripts/backup-spent-tags.sh restore <backup-file> <tag-file>
#
# The backup is a consistent point-in-time copy (copy to a temp file in the same
# dir, then atomic rename) — the exit only ever APPENDS to the ledger, so a copy
# taken mid-write is a valid prefix (it can only MISS the most recent tag, never
# corrupt one; missing a just-written tag fails CLOSED — at worst a re-issue).
#
# NOTE on ROTATION (intentionally NOT provided): you must never just truncate or
# drop the ledger to bound its growth — a dropped tag becomes replayable within
# the credential's validity window. Safe shrinking is *epoch-scoped* (drop only
# tags whose key-epoch has fully expired), which needs per-tag epoch metadata the
# file store does not keep. For multi-node / bounded growth use the Redis store
# (TESSERA_SPENT_TAG_REDIS) with a TTL >= the credential validity window instead.
set -euo pipefail

usage() { sed -n '2,20p' "$0"; exit 2; }
[ $# -ge 1 ] || usage

case "$1" in
  backup)
    [ $# -ge 2 ] || usage
    src=$2; dir=${3:-.}
    [ -f "$src" ] || { echo "error: tag file '$src' not found" >&2; exit 1; }
    mkdir -p "$dir"
    ts=$(date -u +%Y%m%dT%H%M%SZ 2>/dev/null || echo backup)
    out="$dir/$(basename "$src").$ts.bak"
    tmp="$out.tmp.$$"
    cp -- "$src" "$tmp" && mv -- "$tmp" "$out"
    lines=$(wc -l <"$out" | tr -d ' ')
    echo "backed up $lines spent tags -> $out"
    ;;
  restore)
    [ $# -ge 3 ] || usage
    bak=$2; dst=$3
    [ -f "$bak" ] || { echo "error: backup '$bak' not found" >&2; exit 1; }
    if [ -f "$dst" ]; then
      echo "refusing to overwrite existing '$dst' (move it aside first)" >&2
      exit 1
    fi
    tmp="$dst.tmp.$$"
    cp -- "$bak" "$tmp" && mv -- "$tmp" "$dst"
    echo "restored $(wc -l <"$dst" | tr -d ' ') spent tags -> $dst"
    ;;
  *) usage ;;
esac
