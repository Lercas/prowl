#!/usr/bin/env python3
"""Qualify released MCP stdio behavior using owned local scanner fixtures."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import subprocess
import tempfile
import threading
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix="prowl-mcp-native-"))
    (root / "home").mkdir()
    verifiers = root / "home" / "verifiers"
    verifiers.mkdir()
    # No matching candidate is supplied with verification enabled in this matrix.
    (verifiers / "owned.yaml").write_text("id: owned-unused\nmatch: [owned_unused_type]\nrequests:\n  - url: http://127.0.0.1:9/check\n    matchers:\n      - type: status\n        status: [200]\n")
    env = dict(os.environ, PROWL_HOME=str(root / "home"))
    value = "AKIANAFGYOEYPXU1DSYP"
    cases = [
        ("clean", "clean.env", "ordinary text", {}, True, 0),
        ("typed", "production.env", "AWS=" + value, {}, True, 1),
        ("spaces", "  production.env  ", "AWS=" + value, {}, True, 1),
        ("structured", "production.json", '{"key":"\\u0041' + value[1:] + '"}', {}, True, 1),
        ("pragma", "pragma.env", "AWS=" + value + " # prowl:allow", {}, True, 0),
        ("ml", "ml.env", "AWS=" + value, {"ml": True}, True, 1),
        ("reconstruct", "bundle.js", "const head='AKIA';const key=head+'" + value[4:] + "';", {"reconstruct": True}, True, 1),
        ("malformed", "malformed.json", '{"key":"' + value + '\\q"}', {}, False, None),
        ("reveal", "reveal.env", "AWS=" + value, {"show_secrets": True}, True, 1),
        ("verified-only-empty", "empty.env", "ordinary text", {"verified_only": True}, True, 0),
    ]
    for _, path, text, _, _, _ in cases:
        (root / path).write_text(text)
    with zipfile.ZipFile(root / "owned.apk", "w") as archive:
        archive.writestr("config.txt", "AWS=" + value)
    cancel_tree = root / "cancel-tree"
    cancel_tree.mkdir()
    for i in range(64):
        (cancel_tree / (str(i) + ".env")).write_text(("AWS=" + value + "\n") * 2000)
    checks = []
    for protocol in ["2024-11-05", "2025-03-26", "2025-06-18", "2026-07-28"]:
        modern = protocol == "2026-07-28"
        replies = queue.Queue()
        counter = 0
        with (root / (protocol + ".log")).open("wb") as log:
            worker = subprocess.Popen([str(binary), "mcp"], cwd=root, env=env, stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, stderr=log)

            def read_output():
                for line in worker.stdout:
                    try:
                        replies.put(json.loads(line))
                    except ValueError:
                        replies.put({"invalid_json": True})

            reader = threading.Thread(target=read_output, daemon=True)
            reader.start()

            def exchange(method, params=None):
                nonlocal counter
                counter += 1
                params = dict(params or {})
                if modern:
                    params.setdefault("_meta", {"io.modelcontextprotocol/protocolVersion": protocol,
                                                 "io.modelcontextprotocol/clientCapabilities": {}})
                worker.stdin.write((json.dumps(dict(jsonrpc="2.0", id=counter, method=method, params=params)) + "\n").encode())
                worker.stdin.flush()
                response = replies.get(timeout=30)
                if response.get("id") != counter:
                    raise RuntimeError("MCP response identity mismatch")
                return response

            def check(name, passed):
                checks.append(dict(case=name, protocol=protocol, passed=bool(passed)))

            try:
                response = exchange("server/discover" if modern else "initialize", dict(protocolVersion=protocol))
                result = response.get("result", {})
                check("negotiation", protocol in result.get("supportedVersions", []) if modern else result.get("protocolVersion") == protocol)
                tools = exchange("tools/list").get("result", {}).get("tools", [])
                check("tool-schemas", len(tools) == 5 and all(t["inputSchema"].get("additionalProperties") is False
                                                             and "complete" in t["outputSchema"]["required"] for t in tools))
                for name, path, _, flags, complete, count in cases:
                    response = exchange("tools/call", dict(name="prowl_scan", arguments=dict(path=path, **flags)))
                    result = response.get("result", {})
                    data = result.get("structuredContent", {})
                    text = result.get("content", [{}])[0].get("text", "")
                    ok = (data.get("schema_version") == "1.4" and data.get("complete") == complete
                          and result.get("isError") == (not complete) and json.loads(text) == data
                          and (count is None or data["count"] == count)
                          and data.get("secrets_revealed") == flags.get("show_secrets", False)
                          and (flags.get("show_secrets") or value not in json.dumps(result)))
                    if modern:
                        ok = ok and result.get("resultType") == "complete" and "_meta" in result
                    else:
                        ok = ok and "resultType" not in result
                    check(name, ok)
                mobile = exchange("tools/call", dict(name="prowl_mobile", arguments=dict(path="owned.apk"))).get("result", {})
                check("mobile", not mobile.get("isError", True) and mobile.get("structuredContent", {}).get("count") == 1)
                for name, args in [
                    ("unknown-argument", dict(path="production.env", typo=True)),
                    ("wrong-type", dict(path="production.env", ml="true")),
                    ("flag-injection", dict(path="--show-secrets")),
                ]:
                    result = exchange("tools/call", dict(name="prowl_scan", arguments=args)).get("result", {})
                    check(name, result.get("isError") and "structuredContent" not in result)
                result = exchange("tools/call", dict(name="prowl_domain", arguments=dict(target="example.invalid", authorized=False))).get("result", {})
                check("authorization", result.get("isError") and "structuredContent" not in result)
                response = exchange("ping")
                check("ping", "result" in response)
                if modern:
                    response = exchange("server/discover", {"_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2099-01-01",
                        "io.modelcontextprotocol/clientCapabilities": {}}})
                    check("unsupported-version", response.get("error", {}).get("code") == -32022)
                    response = exchange("server/discover", {"_meta": {"io.modelcontextprotocol/protocolVersion": protocol}})
                    check("missing-capabilities", response.get("error", {}).get("code") == -32602)
                    meta = {"io.modelcontextprotocol/protocolVersion": protocol,
                            "io.modelcontextprotocol/clientCapabilities": {}}
                    call = dict(jsonrpc="2.0", id="owned-cancel", method="tools/call",
                                params=dict(name="prowl_scan", arguments=dict(path=str(cancel_tree)), _meta=meta))
                    cancel = dict(jsonrpc="2.0", method="notifications/cancelled", params=dict(requestId="owned-cancel"))
                    worker.stdin.write((json.dumps(call) + "\n" + json.dumps(cancel) + "\n").encode())
                    worker.stdin.flush()
                    response = exchange("ping")
                    check("early-cancel-ping", "result" in response)
            finally:
                worker.stdin.close()
                try:
                    worker.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    worker.terminate()
                    worker.wait(timeout=5)
                reader.join(timeout=5)
                worker.stdout.close()
            check("clean-session-close", worker.returncode == 0)
    result = subprocess.run([str(binary), "mcp", "unexpected"], cwd=root, env=env, capture_output=True, timeout=10)
    checks.append(dict(case="startup-arguments", passed=result.returncode == 2 and not result.stdout))
    report = dict(binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  passed=sum(c["passed"] for c in checks), total=len(checks), checks=checks)
    output = root / "qualification.json"
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(dict(report=str(output), passed=report["passed"], total=report["total"],
                          failures=[c for c in checks if not c["passed"]])))
    return int(report["passed"] != report["total"])


if __name__ == "__main__":
    raise SystemExit(main())
