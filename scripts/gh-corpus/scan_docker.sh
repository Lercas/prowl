#!/usr/bin/env bash
# Scan Docker Hub images for baked-in secrets with `prowl image` (self-pulls via the registry — no docker
# daemon needed). Image layers are not covered by GitHub's secret-scanning, so keys here stay live.
#
#   QUERY=nodejs N=40 PROWL=./prowl ./scan_docker.sh          # search Docker Hub, scan the results
#   PROWL=./prowl ./scan_docker.sh images.txt                 # scan an explicit image list
set -uo pipefail
PROWL="${PROWL:-prowl}"
OUT="${OUT:-/tmp/docker_scan}"
mkdir -p "$OUT"
LIST="${1:-$OUT/images.txt}"

if [ -n "${QUERY:-}" ]; then
  curl -s "https://hub.docker.com/v2/search/repositories/?query=${QUERY}&page_size=${N:-40}" \
    | python3 -c "import sys,json;[print(r['repo_name']) for r in json.load(sys.stdin).get('results',[])]" >"$LIST"
fi

n=0
while read -r img; do
  [ -z "$img" ] && continue
  out="$OUT/$(printf '%s' "$img" | tr '/:@' '___').json"
  [ -s "$out" ] && continue # resumable
  ref="$img"
  case "$img" in *:* | *@*) ;; *) ref="${img}:latest" ;; esac # tag only when untagged (don't corrupt a tag/digest)
  "$PROWL" image "$ref" --ml --verify --show-secrets --max-size 2000000 --format json -o "$out" 2>>"$OUT/docker.log"
  code=$?
  if [ "$code" -ge 2 ]; then # >=2 = real pull/parse error; exit 0/1 (clean or findings) is kept
    rm -f "$out"             # don't cache a failed pull as a clean scan — resume retries it
    echo "FAIL($code) $img" >>"$OUT/docker.log"
  else
    n=$((n + 1))
  fi
done <"$LIST"
echo "scanned $n images -> $OUT/  (one JSON per image; image ref = the disclosure source)"
