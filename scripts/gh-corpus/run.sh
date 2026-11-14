#!/usr/bin/env bash
# End-to-end: collect N recent public repos -> scan with Prowl -> analyze the findings.
#
#   PROWL=/path/to/prowl ./run.sh 5000
#
set -euo pipefail
cd "$(dirname "$0")"

N="${1:-5000}"
: "${PROWL:?set PROWL to the prowl binary, e.g. PROWL=\$(go build -o ./prowl ../../tool/cmd/prowl && echo ./prowl)}"

echo "== 1/3 collect $N repos =="
python3 collect.py -n "$N" -o repos.txt

echo "== 2/3 scan =="
# Do not pin SCAN_FLAGS here: scan.sh applies its safe redacted default, or an explicit env override.
WORKERS="${WORKERS:-8}" PROWL="$PROWL" bash scan.sh repos.txt

echo "== 3/3 analyze =="
python3 analyze.py findings | tee analysis.txt
echo "report -> $(pwd)/analysis.txt"
