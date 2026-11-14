#!/usr/bin/env bash
# Sustained GitHub Code Search collection+scan loop — find provider key markers in public code, fetch, scan
# with the full cascade, catch LIVE keys. Mirrors scale_pkgs.sh but source = GitHub (needs `gh` CLI auth).
# Prints a line only when a batch yields LIVE keys (-> Monitor notification) + a progress line every 5 batches.
# Live keys are deduped across batches via analyze_keys --seen so the same leak isn't re-reported forever.
#
#   PROWL=./prowl OUT=/tmp/gh_corpus ./scale_github.sh
set -uo pipefail
cd "$(dirname "$0")"
PROWL="${PROWL:-$PWD/prowl}"
OUT="${OUT:-/tmp/gh_corpus}"
PER="${PER:-40}" # results per provider pattern per batch (GitHub Code Search is ~10 req/min)
mkdir -p "$OUT"

total=0
i=$(ls "$OUT"/scan_*.json 2>/dev/null | sed -E 's#.*/scan_([0-9]+)\.json#\1#' | sort -n | tail -1)
i=${i:-0}
echo "scaled GitHub code-search collector started (per-pattern ${PER}, resuming at batch $((i+1)))"
while true; do
  i=$((i + 1))
  b="$OUT/batch_$i"
  python3 collect_codesearch.py -n "$PER" -o "$b" >/dev/null 2>>"$OUT/err.log"
  fc=$(ls "$b" 2>/dev/null | grep -vc manifest || echo 0)
  total=$((total + fc))
  "$PROWL" scan "$b" --ml --verify --show-secrets --max-size 2000000 --format json -o "$OUT/scan_$i.json" 2>/dev/null
  python3 analyze_keys.py "$OUT/scan_$i.json" "$b/manifest.jsonl" --disclose "$OUT/live_$i.json" --seen "$OUT/seen.txt" >/dev/null 2>&1
  if [ -s "$OUT/live_$i.json" ]; then
    echo "LIVE KEYS (batch $i): $(jq -r '.[]|"["+.provider+"] "+.repo' "$OUT/live_$i.json" 2>/dev/null | tr '\n' '; ')"
  fi
  rm -rf "$b" # free disk; scan_$i.json kept for the corpus
  [ $((i % 5)) -eq 0 ] && echo "progress: $i batches, ~$total files scanned, live files: $(ls "$OUT"/live_*.json 2>/dev/null | wc -l | tr -d ' ')"
  sleep 30
done
