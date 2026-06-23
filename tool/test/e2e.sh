#!/usr/bin/env bash
# End-to-end test: every Prowl feature against a realistic repo + all usage scenarios.
# Run from tool/:  bash test/e2e.sh
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${PROWL_BIN:-/tmp/prowl_e2e}"
PASS=0; FAIL=0; FAILED=()
ok(){ PASS=$((PASS+1)); }
bad(){ FAIL=$((FAIL+1)); FAILED+=("$1"); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
# rep: report only (stderr/logs dropped) | cli: stdout+stderr (CLI messages)
rep(){ local o; o="$(eval "$1" 2>/dev/null)"; grep -qiF -- "$2" <<<"$o" && ok || bad "$3 | want '$2' in: $(head -c150 <<<"$o" | tr '\n' ' ')"; }
norep(){ local o; o="$(eval "$1" 2>/dev/null)"; grep -qiF -- "$2" <<<"$o" && bad "$3 | unwanted '$2'" || ok; }
cli(){ local o; o="$(eval "$1" 2>&1)"; grep -qiF -- "$2" <<<"$o" && ok || bad "$3 | want '$2' in: $(head -c150 <<<"$o" | tr '\n' ' ')"; }
exits(){ eval "$1" >/dev/null 2>&1; [ "$?" = "$2" ] && ok || bad "$3 | exit != $2"; }

echo "==> building"; ( cd "$ROOT" && go build -o "$BIN" ./cmd/prowl ) 2>&1 | grep -vE 'corpus_|carriers' || true
[ -x "$BIN" ] || { echo "build failed"; exit 1; }
GHP="ghp_$(python3 -c "import random;random.seed(1);print(''.join(random.choice('abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789') for _ in range(36)))")"

R="$(mktemp -d)"; trap 'rm -rf "$R"; [ -n "${MOCK:-}" ] && kill "$MOCK" 2>/dev/null; [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null' EXIT
export PROWL_HOME="$R/.prowl"   # isolate installed templates from the real home
export PROWL_ALLOW_PRIVATE_IPS=1  # the verify mock runs on 127.0.0.1; let the SSRF guard reach it
mkdir -p "$R/src" "$R/config" "$R/tests" "$R/docs" "$R/vf"
cat > "$R/src/app.py" <<EOF
aws_access_key_id = "AKIA4MNQ2RST7UVWX9YZ"
github_token = "$GHP"
stripe_secret = "sk_live_4eC39HqLyjWDarjtT1zdp7Xc28aZqK9b"
database_url = "postgres://admin:Sup3rS3cretPw@db.internal:5432/prod"
password = "Str0ngP@ssw0rd!"
EOF
cat > "$R/config/settings.yaml" <<'EOF'
slack_webhook: https://hooks.slack.com/services/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
jwt_token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmNkZWZnIn0.dozjgNryP4Jq3mNHl9wYZ
EOF
printf -- '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEArqndmkeymaterialbaseSIXfourhereXYZqpwoeiruty\n-----END RSA PRIVATE KEY-----\n' > "$R/config/id_rsa"
echo 'Hallo, willkommen. Ihr Passwort lautet F4QPE91sc6iN, bitte aufbewahren.' > "$R/docs/welcome_de.md"
cat > "$R/src/util.go" <<'EOF'
const commitSHA = "a3f9c2e8b1d6045a9e3f7c1b8d2046e5a9f3c7e1"
var version = "3.6.18"
EOF
cat > "$R/tests/fixtures.py" <<'EOF'
secret_key = "AKIA4MNQ2RST7UVWX9YZ"
test_password = "Hunt3rPass!!"
EOF
echo "OLD = \"$GHP\"  # prowl:allow" > "$R/src/legacy.py"
# Dependency-lock files: their package hashes must NOT flood generic findings, but the file is NOT
# blind-skipped (that hid real creds people leak in lockfiles) — it is scanned with only the generic
# hash NOISE dropped. So a go.sum of pure hashes yields nothing, while a TYPED secret in a lockfile
# (a real AWS key in package-lock.json) is still reported. A secret in a real source file beside it
# must also still be found.
mkdir -p "$R/lockrepo/src"
printf 'github.com/a/b v1.2.3 h1:vj9j2Cgf8Vt3vZh7M3DM6vL7c8jc7E0YQ8Ksa8yLU=\ngithub.com/c/d v0.4.0/go.mod h1:J7Y8YcW2NihsgmVoMwmyI2Eam5Voxch5oWtZ1bpc8=\n' > "$R/lockrepo/go.sum"
echo '{"dependencies":{"x":{"k":"AKIA4MNQ2RST7UVWX9YZ"}}}' > "$R/lockrepo/package-lock.json"
echo 'aws_access_key_id = "AKIA4MNQ2RST7UVWX9YZ"' > "$R/lockrepo/src/real.py"

echo "==> 1. core scan + types"
rep   "$BIN scan $R"               "AKIA"               "finds aws key"
rep   "$BIN scan $R"               "stripe_secret_key"  "finds stripe key"
rep   "$BIN scan $R"               "private_key"        "finds private key"
rep   "$BIN scan $R"               "slack_webhook"      "finds slack webhook"
rep   "$BIN scan $R"               "generic_password"   "finds password"
norep "$BIN scan $R/src/legacy.py" "[" 	            "inline pragma suppresses the only finding"
norep "$BIN scan $R/lockrepo"      "go.sum"             "go.sum hash noise dropped (not flooded as generic)"
rep   "$BIN scan $R/lockrepo"      "package-lock.json"  "typed secret IN a lockfile still found (no blind skip)"
rep   "$BIN scan $R/lockrepo"      "real.py"            "real secret beside a lockfile still found"

echo "==> 2. negatives & demotion"
rep   "$BIN scan $R/src/util.go"   "no secrets"          "git-sha + version are not secrets"
norep "$BIN scan $R/tests"         "critical"         "example/test-path secrets demoted below critical"
rep   "$BIN scan $R/tests"         "medium"           "test-path aws key demoted to medium"

echo "==> 3. output formats"
rep   "$BIN scan $R --format json" '"type"'             "json findings"
rep   "$BIN scan $R --format json | python3 -c 'import sys,json;json.load(sys.stdin);print(1)'" "1" "json valid"
rep   "$BIN scan $R --format sarif | python3 -c 'import sys,json;print(json.load(sys.stdin)[\"runs\"][0][\"tool\"][\"driver\"][\"name\"])'" "prowl" "sarif valid"

echo "==> 4. severity gate / exit codes"
exits "$BIN scan $R --fail-on critical"               1  "fail-on critical exits 1"
exits "$BIN scan $R/src/util.go --fail-on critical"   0  "clean file passes gate"
exits "$BIN scan $R --silence --fail-on critical"     1  "silence still gates via exit code"

echo "==> 5. multilingual prose password"
rep   "$BIN scan $R/docs"          "generic_password"   "german prose password caught via cue"

echo "==> 6. config: disable + allowlist stopwords"
printf 'detectors:\n  disable: [stripe_secret_key]\nallowlist:\n  stopwords: [Sup3rS3cretPw]\n' > "$R/.prowl.yaml"
norep "(cd $R && $BIN scan . --config .prowl.yaml)" "stripe_secret_key" "config disables a detector"
norep "(cd $R && $BIN scan . --config .prowl.yaml)" "Sup3r"             "stopword suppresses db password"
rm -f "$R/.prowl.yaml"

echo "==> 7. git modes"
( cd "$R" && git init -q && git add -A && git -c user.email=a@b.c -c user.name=t commit -qm init ) 2>/dev/null
echo 'leaked = "AKIA9ZZ8YY7XX6WW5VV4"' > "$R/src/new.py"
rep   "(cd $R && git add -A && $BIN scan --staged)" "AKIA"  "git --staged scans staged files"
rep   "(cd $R && $BIN scan --since HEAD)"           "AKIA"  "git --since scans the diff"

echo "==> 8. rules lifecycle + import"
exits "$BIN rules validate $ROOT/rules"               0  "shipped rule templates valid"
cli   "$BIN rules stats $ROOT/rules"   "top tags"         "rules stats grouped"
cli   "$BIN rules list $ROOT/rules"    "cloud"            "rules list grouped by category"
rep   "$BIN scan $R --rules-dir $ROOT/rules" "github-personal-access-token" "rules-dir github template fires"
rep   "$BIN scan $R --rules-dir $ROOT/rules --rule-severity critical" "critical" "severity filter"
cli   "$BIN rules show stripe-secret-key" "match ("    "rules show detail"
rep   "$BIN rules test 'k=sk_live_4eC39HqLyjWDarjtT1zdp7dc28aZqK9bX'" "matched"  "rules test fires"
printf 'title="t"\n[[rules]]\nid="acme-key"\ndescription="Acme"\nregex='"'''"'acme_[a-z]{24}'"'''"'\nkeywords=["acme_"]\n' > "$R/gl.toml"
echo 'k = "acme_qwfpgjluyarstdhneiozxcvb"' > "$R/src/acme.py"
rep   "$BIN scan $R/src/acme.py --rules $R/gl.toml" "acme_key" "gitleaks .toml import detects"

echo "==> 9. verifiers (data-driven, mock provider)"
exits "$BIN verifiers validate $ROOT/verifiers"       0  "shipped verifiers valid"
cli   "$BIN verifiers list $ROOT/verifiers" "github"     "verifiers list"
python3 - <<PY &
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self): self.send_response(200 if self.headers.get("Authorization")=="token $GHP" else 401); self.end_headers()
    def log_message(self,*a): pass
http.server.HTTPServer(("127.0.0.1",8799),H).serve_forever()
PY
MOCK=$!; sleep 1
cat > "$R/vf/mock.yaml" <<'EOF'
id: ghmock
match: [github, ghp_]
requests:
  - url: http://127.0.0.1:8799/user
    headers: { Authorization: "token {{secret}}" }
    matchers: [{type: status, status: [200]}]
EOF
rep "$BIN scan $R/src/app.py --rules-dir $ROOT/rules --verify --verifiers $R/vf --format json | python3 -c 'import sys,json;print([f.get(\"verified\") for f in (json.load(sys.stdin).get(\"findings\") or []) if f.get(\"verified\") is not None])'" "True" "verify confirms LIVE token"
kill "$MOCK" 2>/dev/null; MOCK=""

echo "==> 10. CLI UX"
cli   "$BIN scan --help"   "Examples"        "per-command help"
cli   "$BIN help rules"    "validate"        "help <cmd>"
cli   "$BIN scna"          "did you mean"    "did-you-mean (command typo)"
cli   "$BIN scan . --verfy" "did you mean"   "did-you-mean (flag typo)"
cli   "$BIN scan $R/src/app.py --format=json" "redacted" "--key=value flag form"
cli   "$BIN scan $R/src/app.py --workers 0 --no-color" "aws_access_key_id" "--workers 0 = auto"
cli   "printf 'k=AKIA4MNQ2RST7UVWX9YZ' | $BIN scan -" "aws_access_key_id" "scan stdin (-)"
cli   "$BIN repo 'ext::sh -c id'" "unsupported repo URL" "repo blocks ext:: RCE"
cli   "$BIN org notaplatform:x" "unknown platform" "org rejects bad platform"
cli   "$BIN org badspec" "<platform>:<name>" "org rejects malformed target"
cli   "$BIN bucket ftp://x/y" "unsupported bucket URI" "bucket rejects bad scheme"
cli   "$BIN bucket" "usage: prowl bucket" "bucket usage"
exits "$BIN frobnicate"     2                "unknown command exits 2"
exits "$BIN scan . --bogusflag" 2            "unknown flag exits 2"
cli   "$BIN --version"     "prowl"        "--version"

echo "==> 11. doctor / detectors / serve"
cli   "$BIN detectors"     "aws"             "detectors lists types"
exits "$BIN doctor"         0                "doctor passes"
"$BIN" serve --addr 127.0.0.1:8798 >/dev/null 2>&1 & SRV=$!; sleep 1
cli   "curl -s http://127.0.0.1:8798/healthz" "ok" "serve /healthz"
cli   "curl -s -XPOST http://127.0.0.1:8798/scan -d '{\"content\":\"k=AKIA4MNQ2RST7UVWX9YZ\",\"path\":\"a.py\"}'" "AKIA" "serve POST /scan"
kill "$SRV" 2>/dev/null; SRV=""

echo "==> 12. domain safety + edge cases"
exits "$BIN domain example.com"  2           "domain refuses without --authorized"
printf '' > "$R/empty.txt";   rep "$BIN scan $R/empty.txt" "no secrets" "empty file"
head -c 4000 /dev/urandom > "$R/bin.dat"; exits "$BIN scan $R/bin.dat" 0 "binary file does not crash"
$BIN scan $R --write-baseline "$R/bl.json" >/dev/null 2>&1
exits "test -s $R/bl.json"       0           "baseline written"
norep "$BIN scan $R --baseline $R/bl.json"   "[" "baseline suppresses all known findings"

echo "==> 13. nuclei-style install / update / auto-discovery"
cli   "$BIN version"                          "not installed"   "version before install"
# Security: an explicit --source is an UNTRUSTED third party. It is REFUSED without --allow-unsigned even
# when it ships its OWN matching MANIFEST.sha256 (a self-signed manifest authenticates nothing — exactly
# the attacker's `sha256sum > MANIFEST.sha256`). Reproduce the closed theater with a self-signed evil dir.
EVIL="$(mktemp -d)"
printf 'id: aws-key\ninfo:\n  name: AWS\n  severity: info\nmatchers:\n  - type: regex\n    regex: ["NEVER_MATCH_ZZZ"]\n' > "$EVIL/aws.yaml"
( cd "$EVIL" && { sha256sum aws.yaml 2>/dev/null || shasum -a 256 aws.yaml | sed 's/ /  /'; } > MANIFEST.sha256 )
exits "$BIN rules update --source $EVIL"                    2  "self-signed untrusted rules --source REFUSED without --allow-unsigned (theater closed)"
cli   "$BIN rules update --source $EVIL"  "allow-unsigned"     "refusal names the --allow-unsigned opt-in"
EVILV="$(mktemp -d)"
printf 'id: ghmock\nmatch: [github, ghp_]\nrequests:\n  - url: http://127.0.0.1:1/user\n    headers: { Authorization: "token {{secret}}" }\n    matchers: [{type: status, status: [404]}]\n' > "$EVILV/m.yaml"
( cd "$EVILV" && { sha256sum m.yaml 2>/dev/null || shasum -a 256 m.yaml | sed 's/ /  /'; } > MANIFEST.sha256 )
exits "$BIN verifiers update --source $EVILV"               2  "self-signed untrusted verifiers --source REFUSED without --allow-unsigned (theater closed)"
rm -rf "$EVIL" "$EVILV"
# A local --source is legitimately installable by the operator's EXPLICIT opt-in (--allow-unsigned). The
# bundled rules/verifiers dirs are themselves an explicit (therefore untrusted) --source, so opt in here.
( cd "$ROOT" && "$BIN" rules update --source rules --allow-unsigned >/dev/null 2>&1; "$BIN" verifiers update --source verifiers --allow-unsigned >/dev/null 2>&1 )
cli   "$BIN version"                          "rules:"          "version shows installed templates"
cli   "$BIN version"                          "1.0.0"           "installed template version reported"
# After a blessed install the on-disk set carries a freshly-written manifest; re-running the same
# --source --check against the (now self-consistent) installed tree must still need the opt-in, but the
# bundled rules/ source re-installs idempotently with it. --check + --allow-unsigned is a no-op confirm.
exits "$BIN rules update --source $ROOT/rules --check --allow-unsigned"  0  "update --check idempotent after install"
echo 'tok = "ghp_wjBTdeLgzPdJpcfDCerfMDdNhqSSPdNPBdqc"' > "$R/auto.py"
rep   "$BIN scan $R/auto.py"                   "github-personal-access-token" "scan auto-loads installed templates (no --rules-dir)"

echo "==> 14. serve coverage + --rules-only isolation (with installed templates)"
# serve must run the rule-TEMPLATE engine, not just the embedded taxonomy. The installed datadog
# template fires on a dd_api_key context (hyphenated type 'datadog-api-key'); the embedded taxonomy's
# 'datadog_api_key' needs the literal word "datadog" and does NOT match this string — so a hit proves
# the engine is wired through serve, same coverage as the CLI. Without the engine, serve returns count 0.
"$BIN" serve --addr 127.0.0.1:8797 >/dev/null 2>&1 & SRV=$!; sleep 1
cli   "curl -s -XPOST http://127.0.0.1:8797/scan -d '{\"content\":\"dd_api_key = \\\"acde070d8c4c4f0d9b8e3f1a2b6c5d7e\\\"\",\"path\":\"a.py\"}'" "datadog-api-key" "serve finds a template detector (engine wired through, not just taxonomy)"
kill "$SRV" 2>/dev/null; SRV=""
# --rules-only isolates: ONLY the passed --rules file fires, and the installed templates are NOT loaded
# (no "loaded rule templates count=" line). The custom acme rule fires as the sole source. The
# "count=" log is on stderr, so capture 2>&1 and assert it is ABSENT.
rep   "$BIN scan $R/src/acme.py --rules $R/gl.toml --rules-only" "acme_key" "--rules-only fires the passed rule as the only source"
cli   "{ $BIN scan $R/src/acme.py --rules $R/gl.toml --rules-only -v 2>&1 | grep -q 'loaded rule templates' && echo LEAKED || echo ISOLATED; }" "ISOLATED" "--rules-only does NOT auto-load installed ~/.prowl/rules"

echo ""
echo "================ E2E: $PASS passed, $FAIL failed ================"
[ "$FAIL" = 0 ] || { printf '%s\n' "${FAILED[@]}"; exit 1; }
