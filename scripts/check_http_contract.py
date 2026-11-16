#!/usr/bin/env python3
"""Qualify the native HTTP worker on owned loopback with disposable state."""

import argparse
from contextlib import closing
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix="prowl-http-native-"))
    (root / "home").mkdir()
    rules = root / "rules"
    rules.mkdir()
    (rules / "owned.yaml").write_text("id: owned-custom\ninfo:\n  name: Owned custom rule\n  severity: high\nmatchers:\n  - type: word\n    words: ['CUSTOM=']\nextractors:\n  - type: regex\n    regex: ['CUSTOM=([A-Z0-9]+)']\n")
    with socket.socket() as selected:
        selected.bind(("127.0.0.1", 0))
        port = selected.getsockname()[1]
    env = dict(os.environ, PROWL_HOME=str(root / "home"))
    checks = []
    value = "AKIANAFGYOEYPXU1DSYP"

    def request(path, body=None):
        with closing(http.client.HTTPConnection("127.0.0.1", port, timeout=30)) as client:
            client.request("GET" if body is None else "POST", path, body,
                           {"Content-Type": "application/json"})
            response = client.getresponse()
            raw = response.read()
            return response.status, json.loads(raw) if path != "/healthz" else raw, raw

    with (root / "worker.log").open("wb") as log:
        worker = subprocess.Popen([str(binary), "serve", "--addr=127.0.0.1:" + str(port), "--rules-dir=" + str(rules)],
                                  cwd=root, env=env, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 20
            while True:
                if worker.poll() is not None:
                    raise RuntimeError("owned worker exited; inspect " + str(root / "worker.log"))
                try:
                    if request("/healthz")[0] == 200:
                        break
                except OSError:
                    pass
                if time.monotonic() > deadline:
                    raise TimeoutError("owned worker did not become healthy")
                time.sleep(.05)

            status, caps, _ = request("/capabilities")
            checks.append(dict(case="capabilities", passed=status == 200 and caps["schema_version"] == "1.4"
                               and caps["redacted"] and caps["required_fields"] == ["content"]
                               and caps["stages"]["l1"] and caps["stages"]["rules"] and not any(caps["stages"][k] for k in
                                                                      ["ml", "verification", "ocr", "semantic", "reconstruction"])))
            invalid = [b"null", b"{}", b'{"content":null}', b'{"content":1}',
                       b'{"content":"clean","content":"other"}', b'{"content":"clean","CONTENT":"other"}',
                       b'{"content":"clean","cont\\u0065nt":"other"}',
                       b'{"content":"clean","source":"code","source":"file"}',
                       b'{"content":"clean","path":null}', b'{"content":"\\ud800"}',
                       b'{"content":"\\udc00"}', b'{"content":"\xff"}',
                       b'{"content":"clean"} {"content":"other"}']
            invalid += [json.dumps(dict(content="clean", **{key: False})).encode()
                        for key in ["verify", "ml", "ocr", "show_secrets", "SHOW_SECRETS"]]
            for i, body in enumerate(invalid):
                for batch in (False, True):
                    status, data, raw = request("/scan/batch" if batch else "/scan", b"[" + body + b"]" if batch else body)
                    checks.append(dict(case="invalid-" + str(i), batch=batch,
                                       passed=status == 400 and "error" in data and value.encode() not in raw))

            cases = [
                ("empty", "", "production.env", True, False, 0),
                ("plain", "AWS=" + value, "production.env", True, False, 1),
                ("custom-rule", "CUSTOM=OWNEDVALUE42", "production.env", True, False, 1),
                ("structured", '{"key":"\\u0041' + value[1:] + '"}', "production.json", True, False, 1),
                ("unicode", "Пароль🚀\nAWS=" + value, "Конфиг.env", True, False, 1),
                ("pragma", "AWS=" + value + " # prowl:allow", "production.env", True, True, 0),
                ("parser-error", '{"key":"' + value + '\\q"}', "production.json", False, False, None),
            ]
            for name, content, path, complete, filtered, count in cases:
                for batch in (False, True):
                    item = dict(content=content, path=path, future={"content": 123})
                    status, data, raw = request("/scan/batch" if batch else "/scan",
                                               json.dumps([item] if batch else item).encode())
                    ok = (status == 200 and data["schema_version"] == "1.4" and data["complete"] == complete
                          and data["filtered"] == filtered and not data["secrets_revealed"]
                          and data["stats"]["processed"] == 1 and data["stats"]["bytes"] == len(content.encode())
                          and {s["kind"] for s in data["scope"]} == {"detection_policy", "rules", "detector_config", "http-input"}
                          and (count is None or data["count"] == count) and value.encode() not in raw
                          and (complete or data["diagnostics"] and data["truncated"]))
                    if name == "custom-rule":
                        ok = ok and b"OWNEDVALUE42" not in raw and data["findings"][0]["type"] == "owned-custom"
                    checks.append(dict(case=name, batch=batch, passed=bool(ok)))
            status, data, _ = request("/scan/batch", b"[]")
            checks.append(dict(case="empty-batch", passed=status == 200 and data["complete"]
                               and data["findings"] == [] and data["stats"]["processed"] == 0
                               and {s["kind"] for s in data["scope"]} == {"detection_policy", "rules", "detector_config"}))
            status, data, _ = request("/scan/batch", b"[" + b'{"content":""},' * 10000 + b'{"content":""}]')
            checks.append(dict(case="batch-item-limit", passed=status == 413 and "error" in data))
            large = "x" * ((4 << 20) + 1)
            status, data, _ = request("/scan", json.dumps(dict(content=large)).encode())
            checks.append(dict(case="item-limit", passed=status == 413 and "error" in data))
            status, data, _ = request("/scan/batch", json.dumps([dict(content=large), dict(content="ordinary")]).encode())
            checks.append(dict(case="batch-item-limit-ledger", passed=status == 200 and not data["complete"]
                               and data["truncated"] and data["stats"]["processed"] == 1
                               and data["stats"]["bytes"] == len("ordinary") and data["stats"]["skipped"] == 1))
            dense = ("AWS=" + value + "\n") * 5000
            status, data, raw = request("/scan/batch", json.dumps([
                dict(content=dense, path="production.env"), dict(content="ordinary", path="later.env")]).encode())
            checks.append(dict(case="response-limit-ledger", passed=status == 200 and not data["complete"]
                               and data["truncated"] and data["count"] == 5000
                               and data["stats"]["processed"] == 1 and data["stats"]["bytes"] == len(dense.encode())
                               and any(d["code"] == "batch_truncated" for d in data["diagnostics"])
                               and value.encode() not in raw))
            status, data, _ = request("/metrics")
            checks.append(dict(case="released-slots", passed=status == 200 and data["inflight"] == 0 and data["truncated"] >= 3))
        finally:
            worker.terminate()
            try:
                worker.wait(timeout=15)
            except subprocess.TimeoutExpired:
                worker.kill()
                worker.wait(timeout=5)
    report = dict(binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  passed=sum(c["passed"] for c in checks), total=len(checks), checks=checks)
    output = root / "qualification.json"
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(dict(report=str(output), passed=report["passed"], total=report["total"],
                          failures=[c for c in checks if not c["passed"]])))
    return int(report["passed"] != report["total"])


if __name__ == "__main__":
    raise SystemExit(main())
