#!/usr/bin/env bash
# Scan a list of repo clone URLs with Prowl: shallow-clone HEAD, scan the working tree, delete. Resumable
# (skips repos already in OUTDIR), parallel, bounded, read-only. Findings land in OUTDIR/<owner__repo>.json.
#
#   PROWL=./prowl WORKERS=8 ./scan.sh repos.txt
#
# The safe default is a redacted, no-network ML pass. Live verification and raw output require an
# explicit SCAN_FLAGS override, for example SCAN_FLAGS="--ml --verify --show-secrets".
# Disclose any LIVE secret responsibly — never exploit it.
set -uo pipefail

REPOS="${1:-repos.txt}"
OUTDIR="${OUTDIR:-findings}"
WORKERS="${WORKERS:-8}"
PROWL="${PROWL:-prowl}"
# Safe default: L2 ML denoising, no provider requests, redacted output. Authorized research can opt
# into live verification and raw values through an explicit SCAN_FLAGS override.
SCAN_FLAGS="${SCAN_FLAGS:---ml}"
CLONE_TIMEOUT="${CLONE_TIMEOUT:-120}"
SCAN_TIMEOUT="${SCAN_TIMEOUT:-300}" # an explicit --verify override adds provider round-trips
MAXSIZE="${MAXSIZE:-5242880}" # 5 MiB per file
# GNU timeout is `timeout` on Linux, `gtimeout` (coreutils) on macOS; run without a bound if neither.
TIMEOUT_BIN="$(command -v gtimeout || command -v timeout || true)"

mkdir -p "$OUTDIR" "$OUTDIR/.tmp"
LOG="$OUTDIR/scan.log"

scan_one() {
  local url="$1"
  local name; name=$(printf '%s' "$url" | sed -E 's#^https?://[^/]+/##; s#\.git$##; s#/#__#g')
  local out="$OUTDIR/$name.json"
  [ -s "$out" ] && return 0 # resumable: already scanned
  local dir="$OUTDIR/.tmp/$name"
  rm -rf "$dir"
  if ! ${TIMEOUT_BIN:+$TIMEOUT_BIN $CLONE_TIMEOUT} git clone --depth 1 --filter=blob:limit=1m --quiet "$url" "$dir" 2>>"$LOG"; then
    echo "CLONE_FAIL $url" >>"$LOG"; rm -rf "$dir"; return 0
  fi
  rm -rf "$dir/.git" # working tree only — no history/pack noise, less disk
  ${TIMEOUT_BIN:+$TIMEOUT_BIN $SCAN_TIMEOUT} "$PROWL" scan "$dir" $SCAN_FLAGS --max-size "$MAXSIZE" --format json -o "$out" 2>>"$LOG"
  local code=$?
  [ "$code" -ge 2 ] && echo "SCAN_FAIL($code) $url" >>"$LOG" # 0=clean,1=findings,>=2=error/timeout
  rm -rf "$dir"
}
export -f scan_one
export OUTDIR PROWL SCAN_FLAGS CLONE_TIMEOUT SCAN_TIMEOUT MAXSIZE LOG TIMEOUT_BIN

n=$(grep -c . "$REPOS")
echo "[$(date '+%H:%M:%S')] scanning $n repos with $WORKERS workers (flags: $SCAN_FLAGS)" | tee -a "$LOG"
grep . "$REPOS" | xargs -P "$WORKERS" -I {} bash -c 'scan_one "$@"' _ {}
rm -rf "$OUTDIR/.tmp"
echo "[$(date '+%H:%M:%S')] done — $(ls "$OUTDIR"/*.json 2>/dev/null | wc -l | tr -d ' ') result files in $OUTDIR/" | tee -a "$LOG"
