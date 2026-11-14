#!/usr/bin/env bash
# Sustained npm + PyPI collection+scan loop — accumulate package-leak volume + catch live keys over time.
# Prints a line only when a batch yields LIVE keys (-> Monitor notification) plus a progress line every 10
# batches. Per-batch tarballs are deleted after scanning (disk-bounded); scan JSONs + live_*.json are kept.
#
#   PROWL=./prowl OUT=/tmp/pkg_corpus ./scale_pkgs.sh
set -uo pipefail
cd "$(dirname "$0")"
PROWL="${PROWL:-$PWD/prowl}"
OUT="${OUT:-/tmp/pkg_corpus}"
PYPI="${PYPI:-100}"
NPM="${NPM:-200}"
mkdir -p "$OUT"

total=0
# resume from the MAX existing index, not the count — a deleted scan_K.json would otherwise collide & overwrite
i=$(ls "$OUT"/scan_*.json 2>/dev/null | sed -E 's#.*/scan_([0-9]+)\.json#\1#' | sort -n | tail -1)
i=${i:-0}
echo "scaled package collector started (PyPI ${PYPI} + npm ${NPM} per batch, resuming at batch $((i+1)))"
while true; do
  i=$((i + 1))
  b="$OUT/batch_$i"
  python3 collect_pkgs.py --pypi "$PYPI" --npm "$NPM" -o "$b" >/dev/null 2>>"$OUT/err.log"
  pk=$(python3 -c "import json;print(len({json.loads(l)['package'] for l in open('$b/manifest.jsonl')}))" 2>/dev/null || echo 0)
  total=$((total + pk))
  "$PROWL" scan "$b" --ml --verify --show-secrets --max-size 2000000 --format json -o "$OUT/scan_$i.json" 2>/dev/null
  python3 analyze_keys.py "$OUT/scan_$i.json" "$b/manifest.jsonl" --disclose "$OUT/live_$i.json" >/dev/null 2>&1
  if [ -s "$OUT/live_$i.json" ]; then
    echo "LIVE KEYS (batch $i): $(jq -r '.[]|"["+.provider+"] "+.repo' "$OUT/live_$i.json" 2>/dev/null | tr '\n' '; ')"
  fi
  rm -rf "$b" # free disk; scan_$i.json kept for the corpus
  [ $((i % 10)) -eq 0 ] && echo "progress: $i batches, ~$total packages scanned, live files: $(ls "$OUT"/live_*.json 2>/dev/null | wc -l | tr -d ' ')"
  sleep 20
done
