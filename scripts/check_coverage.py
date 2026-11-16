#!/usr/bin/env python3
"""Check CLI coverage metadata in JSON, SARIF, stdout and atomic output files."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


VALUE = "AKIANAFGYOEYPXU1DSYP"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix="prowl-coverage-native-"))
    (root / "home").mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PROWL_", "GIT_"))
           and not k.upper().endswith("_PROXY")}
    env.update(PROWL_HOME=str(root / "home"), GIT_CONFIG_GLOBAL=os.devnull,
               GIT_CONFIG_SYSTEM=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    checks = []
    rules = root / "owned-rules"
    rules.mkdir()
    (rules / "policy.yaml").write_text(
        "id: owned-policy\ninfo:\n  name: Owned policy\n  severity: high\n"
        "matchers:\n  - type: word\n    words: ['CUSTOM=']\n    min: .nan\n")

    def run(args, data=b""):
        return subprocess.run([str(binary), *args], cwd=root, env=env, input=data,
                              capture_output=True, timeout=20)

    cases = [
        dict(name="clean", text="message=ordinary\n", complete=True, filtered=False, processed=1),
        dict(name="finding", text="AWS=" + VALUE + "\n", complete=True, filtered=False, processed=1),
        dict(name="aggregate", text=("AWS=" + VALUE + "\n") * 2, complete=True, filtered=False, processed=1),
        dict(name="pragma", text="AWS=" + VALUE + " # prowl:allow\n", complete=True, filtered=True, processed=1),
        dict(name="report-filter", text="AWS=" + VALUE, flags=["--min-severity=critical"], complete=True, filtered=True, processed=1),
        dict(name="reveal", text="AWS=" + VALUE, flags=["--show-secrets"], complete=True, filtered=False, processed=1, revealed=True),
        dict(name="malformed", ext=".json", text='{"key":"' + VALUE + '\\q"}', complete=False, filtered=False, processed=1),
        dict(name="limit", text="AWS=" + VALUE, flags=["--max-size=8"], complete=False, filtered=False, processed=0),
        dict(name="missing", text=None, complete=False, filtered=False, processed=0),
        dict(name="structured", ext=".json", text=json.dumps({"key": VALUE}), complete=True, filtered=False, processed=1),
        dict(name="empty-directory", text=None, directory=True, complete=True, filtered=False, processed=0),
        dict(name="invalid-policy", text="ordinary text", flags=["--rules-dir", str(rules)],
             complete=False, filtered=False, processed=1, diagnostic="rules_policy_failed"),
    ]
    for case in cases:
        name = case["name"] + case.get("ext", ".env")
        for stdin in (False, True):
            if stdin and case["text"] is None:
                continue
            for stored in (False, True):
                scopes = None
                for fmt in ("json", "sarif"):
                    path = root / name
                    if case.get("directory"):
                        path.mkdir(exist_ok=True)
                    sentinel = b"logical input must not be read"
                    if case["text"] is not None:
                        path.write_bytes(sentinel if stdin else case["text"].encode())
                    args = ["scan", "--silence", "--format=" + fmt, *case.get("flags", [])]
                    args += ["--stdin-name=" + name] if stdin else [name]
                    output = root / ("report-" + str(len(checks)))
                    if stored:
                        args.append("--output=" + str(output))
                    result = run(args, case["text"].encode() if stdin else b"")
                    data = output.read_bytes() if stored else result.stdout
                    assert data, (case["name"], fmt, stdin, stored, result.returncode, "missing report")
                    report = json.loads(data)
                    meta = report if fmt == "json" else report["runs"][0]["properties"]
                    expected_bytes = len(case["text"].encode()) if case["processed"] else 0
                    ok = (result.returncode == (0 if case["complete"] else 2)
                          and meta["schema_version"] == "1.4" and meta["complete"] == case["complete"]
                          and meta["completion_reason"] == ("completed" if case["complete"] else "incomplete")
                          and meta["filtered"] == case["filtered"]
                          and meta["secrets_revealed"] == case.get("revealed", False)
                          and meta["stats"]["processed"] == case["processed"] and meta["stats"]["bytes"] == expected_bytes
                          and isinstance(meta["scope"], list) and isinstance(meta["diagnostics"], list)
                          and {s["kind"] for s in meta["scope"]} == {"command", "pipeline", "detection_policy", "rules", "stdin" if stdin else "filesystem"}
                          and sum(s["kind"] == "detection_policy" and s["target"] == "1.5.0" for s in meta["scope"]) == 1
                          and sum(s["kind"] == "rules" for s in meta["scope"]) == 1
                          and all(len(s["policy"]) == 64 for s in meta["scope"])
                          and (case["complete"] or meta["diagnostics"] and meta["truncated"])
                          and (case.get("revealed") or VALUE.encode() not in data)
                          and (not stdin or path.read_bytes() == sentinel))
                    if case.get("diagnostic"):
                        ok = ok and case["diagnostic"] in {d["code"] for d in meta["diagnostics"]}
                    if fmt == "sarif":
                        ok = ok and report["runs"][0]["invocations"][0]["executionSuccessful"] == case["complete"]
                        ok = ok and scopes == meta["scope"]
                    else:
                        scopes = meta["scope"]
                    checks.append(dict(case=case["name"], stdin=stdin, stored=stored, format=fmt, passed=bool(ok)))
    for fmt in ("json", "sarif"):
        baseline = root / ("baseline-" + fmt)
        sentinel = b"owned baseline sentinel"
        baseline.write_bytes(sentinel)
        result = run(["scan", "invalid-policy.env", "--rules-dir", str(rules),
                      "--write-baseline", str(baseline), "--format", fmt, "--silence"])
        checks.append(dict(case="invalid-policy-baseline", format=fmt,
                           passed=result.returncode == 2 and baseline.read_bytes() == sentinel))
    report = dict(binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(), passed=sum(c["passed"] for c in checks), total=len(checks), checks=checks)
    output = root / "qualification.json"
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(dict(report=str(output), passed=report["passed"], total=report["total"], failures=[c for c in checks if not c["passed"]])))
    return int(report["passed"] != report["total"])


if __name__ == "__main__":
    raise SystemExit(main())
