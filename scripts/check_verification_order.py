#!/usr/bin/env python3
"""Check provider call counts, gate semantics and private index retention offline."""

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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix="prowl-verification-order-"))
    (root / "home").mkdir()
    env = dict(os.environ, PROWL_HOME=str(root / "home"), PROWL_ALLOW_PRIVATE_IPS="1")
    requests, checks = [], []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(1)
            value = self.headers.get("Authorization", "").removeprefix("Bearer ")
            self.send_response(200 if value == LIVE else 401 if value == DEAD else 429)
            self.end_headers()
        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    rule = root / "owned.yaml"
    rule.write_text("id: owned\nmatch: [aws_access_key_id]\nrequests:\n  - url: http://127.0.0.1:" + str(server.server_port) + "/check\n    headers:\n      Authorization: 'Bearer {{secret}}'\n    matchers:\n      - type: status\n        status: [200]\n")

    def run(args, data=b""):
        return subprocess.run([str(binary), *args], cwd=root, env=env, input=data,
                              capture_output=True, timeout=20)

    try:
        for status, value in [("live", LIVE), ("dead", DEAD), ("error", ERROR)]:
            for mode in ("default", "all", "gate", "index"):
                for stdin in (False, True):
                    for fmt in ("json", "sarif"):
                        text = "AWS=" + value + "\n"
                        path = root / "production.env"
                        sentinel = b"logical name must not be read"
                        path.write_bytes(sentinel if stdin else text.encode())
                        args = ["scan", "--verify", "--verifiers=" + str(rule), "--ml", "--ml-threshold=1", "--timeout=3s", "--silence", "--format=" + fmt]
                        if mode == "all":
                            args.append("--verify-all")
                        if mode == "gate":
                            args.append("--fail-on-verified")
                        index = root / ("index-" + str(len(checks)))
                        if mode == "index":
                            args += ["--index=" + str(index), "--scope=owned"]
                        args += ["--stdin-name=production.env"] if stdin else [path.name]
                        before = len(requests)
                        result = run(args, text.encode() if stdin else b"")
                        report = json.loads(result.stdout)
                        if fmt == "json":
                            fs = [f for f in report["findings"] if f["type"] == "aws_access_key_id"]
                            truncated = report["truncated"]
                        else:
                            r = report["runs"][0]
                            fs = [f for f in r["results"] if f["ruleId"] == "aws_access_key_id"]
                            truncated = r.get("properties", {}).get("truncated", False)
                        expected_calls = 0 if mode == "default" else 2 if status == "error" else 1
                        expected_findings = int(mode != "default" and status == "live")
                        expected_exit = 2 if mode != "default" and status == "error" else 1 if mode == "gate" and status == "live" else 0
                        ok = (len(requests) - before == expected_calls and len(fs) == expected_findings
                              and result.returncode == expected_exit and bool(truncated) == (expected_exit == 2)
                              and value.encode() not in result.stdout
                              and (not stdin or path.read_bytes() == sentinel))
                        if mode == "index":
                            view = run(["index", "--index=" + str(index), "--format=json"])
                            secrets = json.loads(view.stdout)["secrets"]
                            if status in ("live", "dead"):
                                ok = ok and view.returncode == 0 and len(secrets) == 1 and secrets[0]["last_confirmed_state"] == status
                            else:
                                ok = ok and view.returncode == 0 and all(s["last_confirmed_state"] == "unknown" for s in secrets)
                        checks.append(dict(status=status, mode=mode, stdin=stdin, format=fmt, provider_calls=len(requests) - before,
                                           exit=result.returncode, passed=ok))
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
