#!/usr/bin/env python3
"""Qualify typed verdict transport against an owned loopback HTTP fixture only."""

import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading


LIVE = "AKIANAFGYOEYPXU1DSYP"
DEAD = "AKIANAFGYOEYPXU2DSYP"
ERROR = "AKIANAFGYOEYPXU3DSYP"
STRIPE = "sk_live_Q5t7U9i2O4p6A8s0D3f5G7h9"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix="prowl-verdict-native-"))
    home = root / "home"
    home.mkdir()
    env = dict(os.environ, PROWL_HOME=str(home), PROWL_ALLOW_PRIVATE_IPS="1")
    checks = []
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            value = self.headers.get("Authorization", "").removeprefix("Bearer ")
            requests.append(1)
            self.send_response(200 if value == LIVE else 401 if value == DEAD else 429)
            self.end_headers()
        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    rule = root / "owned.yaml"
    rule.write_text("id: owned\nmatch: [aws_access_key_id]\ninfo: {name: owned local fixture}\nrequests:\n  - url: http://127.0.0.1:" + str(server.server_port) + "/check\n    capability: read\n    headers:\n      Authorization: 'Bearer {{secret}}'\n    matchers:\n      - type: status\n        status: [200]\n")

    def run(args, data=b""):
        return subprocess.run([str(binary), *args], cwd=root, env=env, input=data,
                              capture_output=True, timeout=20)

    def findings(report, fmt):
        if fmt == "json":
            return [f for f in report["findings"] if f["type"] in ("aws_access_key_id", "stripe_secret_key")], report["truncated"]
        r = report["runs"][0]
        return [f["properties"] for f in r["results"] if f["ruleId"] in ("aws_access_key_id", "stripe_secret_key")], r.get("properties", {}).get("truncated", False)

    try:
        for status, value in [("verified", LIVE), ("invalid", DEAD), ("error", ERROR), ("unsupported", STRIPE), ("off", LIVE)]:
            text = ("TOKEN=" + value + "\n") * 2
            for stdin in (False, True):
                for ml in (False, True):
                    path = root / "production.env"
                    sentinel = b"logical input must not be read"
                    path.write_bytes(sentinel if stdin else text.encode())
                    command = ["scan", "--silence", "--timeout=3s", "--verifiers=" + str(rule)]
                    command += ["--verify"] if status != "off" else []
                    command += ["--ml"] if ml else []
                    command += ["--stdin-name=production.env"] if stdin else ["production.env"]
                    for fmt in ("json", "sarif"):
                        before = len(requests)
                        result = run([*command, "--no-dedupe", "--format=" + fmt], text.encode() if stdin else b"")
                        fs, truncated = findings(json.loads(result.stdout), fmt)
                        details = [f.get("verification") for f in fs]
                        valid = len(fs) == 2
                        if status == "off":
                            valid = valid and all(d is None for d in details) and len(requests) == before
                        else:
                            valid = valid and all(d and d["status"] == status for d in details)
                            if valid and status == "unsupported":
                                valid = len(requests) == before and all(not d.get("checked_at") for d in details)
                            elif valid:
                                valid = all(d.get("checked_at") and d.get("verifier") == "owned" for d in details)
                                if status in ("verified", "invalid"):
                                    valid = valid and len(requests) - before == 1 and details[0]["checked_at"] == details[1]["checked_at"]
                                if status == "verified":
                                    valid = valid and all(d.get("capabilities") == ["read"] for d in details)
                                if status == "error":
                                    valid = valid and all(d.get("reason") and value not in d["reason"] for d in details)
                        ok = (valid and result.returncode == (2 if status == "error" else 0)
                              and bool(truncated) == (status == "error") and value.encode() not in result.stdout
                              and (not stdin or path.read_bytes() == sentinel))
                        checks.append(dict(status=status, stdin=stdin, ml=ml, format=fmt, passed=ok))
            # Default dedupe must retain the detailed source checks as occurrences.
            path = root / "production.env"
            path.write_text(text)
            if status != "off":
                for fmt in ("json", "sarif"):
                    result = run(["scan", path.name, "--verify", "--verifiers=" + str(rule), "--timeout=3s", "--silence", "--format=" + fmt])
                    fs, _ = findings(json.loads(result.stdout), fmt)
                    occurrences = fs[0].get("occurrences", []) if len(fs) == 1 else []
                    checks.append(dict(status=status, case="default-dedupe", format=fmt,
                                       passed=len(occurrences) == 2 and all(o.get("verification", {}).get("status") == status for o in occurrences)))
        baseline = root / "baseline.json"
        sentinel = b'["owned sentinel"]'
        baseline.write_bytes(sentinel)
        (root / "production.env").write_text("TOKEN=" + ERROR)
        result = run(["scan", "production.env", "--verify", "--verifiers=" + str(rule), "--timeout=3s", "--write-baseline=baseline.json", "--min-severity=critical", "--silence", "--format=json"])
        checks.append(dict(case="provider-error-preserves-baseline", passed=result.returncode == 2
                           and json.loads(result.stdout)["truncated"] and baseline.read_bytes() == sentinel))
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
    report = dict(binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(), passed=sum(c["passed"] for c in checks), total=len(checks), checks=checks)
    output = root / "qualification.json"
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(dict(report=str(output), passed=report["passed"], total=report["total"], failures=[c for c in checks if not c["passed"]])))
    return int(report["passed"] != report["total"])


if __name__ == "__main__":
    raise SystemExit(main())
