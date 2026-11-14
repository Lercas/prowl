#!/usr/bin/env bash
# Scan repos' FULL git history with `prowl repo --history` — keys committed then "deleted" often survive in
# old commits (still live if never rotated), and are invisible to GitHub Code Search (which indexes HEAD only).
#
#   PROWL=./prowl WORKERS=4 ./scan_history.sh repos.txt       # repos.txt = clone URLs, one per line
set -uo pipefail
PROWL="${PROWL:-prowl}"
OUT="${OUT:-/tmp/hist_scan}"
WORKERS="${WORKERS:-4}"
mkdir -p "$OUT"
LIST="${1:-repos.txt}"

scan_one() {
  local url="$1"
  local name; name=$(printf '%s' "$url" | sed -E 's#^https?://[^/]+/##; s#\.git$##; s#/#__#g')
  local out="$OUT/$name.json"
  [ -s "$out" ] && return 0 # resumable
  "$PROWL" repo "$url" --history --ml --verify --show-secrets --format json -o "$out" 2>>"$OUT/hist.log"
  code=$?
  if [ "$code" -ge 2 ]; then # >=2 = real clone/parse error; exit 0/1 (clean or findings) is kept
    rm -f "$out"             # don't cache a failed clone as a clean scan — resume retries it
    echo "FAIL($code) $url" >>"$OUT/hist.log"
  fi
}
export -f scan_one
export PROWL OUT

grep . "$LIST" | xargs -P "$WORKERS" -I {} bash -c 'scan_one "$@"' _ {}
echo "done -> $OUT/  (one JSON per repo; repo = the disclosure source)"
