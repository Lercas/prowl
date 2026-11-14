#!/usr/bin/env bash
# Sustained GitHub bulk leak hunt via GH Archive — NO GitHub REST-API rate limit.
# Each batch pulls one hourly GH Archive (public gzip), extracts recently-pushed repos, and clone+scan+verifies
# them (git clone is not the REST API), so the API budget is left entirely to the real-time watcher. Walks
# backward through recent hours. Prints a line only on LIVE keys (-> Monitor) + progress every 3 hours.
# Live keys deduped across batches via analyze_multi --seen.
#
#   PROWL=./prowl OUT=/tmp/gha_corpus ./scale_gharchive.sh
set -uo pipefail
cd "$(dirname "$0")"
PROWL="${PROWL:-$PWD/prowl}"
OUT="${OUT:-/tmp/gha_corpus}"
REPOS="${REPOS:-120}" # repos per hourly batch
WORKERS="${WORKERS:-6}"
mkdir -p "$OUT"
off=$(cat "$OUT/offset" 2>/dev/null || echo 3) # start ~3h ago (GH Archive lags)
echo "GH Archive collector started (${REPOS} repos/hour via clone, no API rate limit, from -${off}h)"
n=0
while true; do
  n=$((n + 1))
  python3 collect_gharchive.py --hours-ago "$off" -n "$REPOS" -o "$OUT/repos.txt" >/dev/null 2>>"$OUT/err.log"
  OUTDIR="$OUT/f" WORKERS="$WORKERS" PROWL="$PROWL" bash scan.sh "$OUT/repos.txt" >/dev/null 2>>"$OUT/err.log" || true
  python3 analyze_multi.py "$OUT/f" --disclose "$OUT/live_$n.json" --seen "$OUT/seen.txt" >/dev/null 2>&1
  if [ -s "$OUT/live_$n.json" ]; then
    echo "LIVE KEYS (hour -${off}h): $(jq -r '.[]|"["+.provider+"] "+.source' "$OUT/live_$n.json" 2>/dev/null | tr '\n' '; ')"
  fi
  rm -rf "$OUT/f" # free disk (clones + per-repo findings); live_*.json + seen ledger kept
  off=$((off + 1))
  echo "$off" >"$OUT/offset"
  [ $((n % 3)) -eq 0 ] && echo "progress: $n hours scanned, now at -${off}h, live files: $(ls "$OUT"/live_*.json 2>/dev/null | wc -l | tr -d ' ')"
  sleep 15
done
