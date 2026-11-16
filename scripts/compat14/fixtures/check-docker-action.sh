#!/bin/sh
set -eu

image=${1:?usage: check-docker-action.sh IMAGE}
workspace=$(mktemp -d "${TMPDIR:-/tmp}/prowl-action-qa.XXXXXXXX")
printf 'aws_access_key_id = "AKIANAFGYOEYPXU1DSYP"\n' > "$workspace/production.env"
docker run --rm --network none "$image" selftest --ml | \
    python3 -c 'import json,sys; assert json.load(sys.stdin)["passed"]'

for mode in default explicit-user; do
    report="$mode.sarif"
    if [ "$mode" = explicit-user ]; then
        set -- --user "$(id -u):$(id -g)"
    else
        set --
    fi
    code=0
    docker run --rm --network none "$@" -v "$workspace:/github/workspace" \
        -w /github/workspace "$image" scan . --strict --bundled --reconstruct \
        --format sarif --fail-on high --output "$report" || code=$?
    [ "$code" -eq 1 ] || { echo "Unexpected exit code: $code" >&2; exit 1; }
    python3 - "$workspace/$report" <<'PY'
import json
import os
import stat
import sys

path = sys.argv[1]
info = os.stat(path)
assert info.st_uid == os.getuid(), (info.st_uid, os.getuid())
assert stat.S_IMODE(info.st_mode) == 0o600, oct(info.st_mode)
with open(path, encoding='utf-8') as stream:
    report = json.load(stream)
assert report['version'] == '2.1.0' and report['runs'][0]['results']
assert 'AKIANAFGYOEYPXU1DSYP' not in json.dumps(report)
print('SARIF ownership, permissions, findings, and redaction: PASS')
PY
done
printf 'Action test inputs retained: %s\n' "$workspace"
