#!/usr/bin/env python3
"""Offline native reconstruction checks; retain artifacts in a private directory."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix="prowl-reconstruction-native-"))
    home = root / "home"
    home.mkdir()
    env = dict(os.environ, PROWL_HOME=str(home))
    cases = [
        ("concat", "const head='AKIA';\nconst key=head+'NAFGYOEYPXU1DSYP';", True),
        ("join", "const key=['AKIA','NAFGYOEYPXU1DSYP'].join('');", True),
        ("template", "const head='AKIA';\nconst key=`${head}NAFGYOEYPXU1DSYP`;", True),
        ("unknown", "const key=unknown+'NAFGYOEYPXU1DSYP';", False),
        ("mutable", "let head='AKIA';\nconst key=head+'NAFGYOEYPXU1DSYP';", False),
        ("pragma", "const head='AKIA';\nconst key=head+'NAFGYOEYPXU1DSYP'; // prowl:allow", False),
    ]
    checks = []
    for name, text, expected in cases:
        for ml in (False, True):
            for stdin in (False, True):
                path = root / (name + ".js")
                sentinel = b"logical stdin must not be read"
                path.write_bytes(sentinel if stdin else text.encode())
                cmd = [str(binary), "scan", "--reconstruct", "--format=json", "--silence"]
                if ml:
                    cmd.append("--ml")
                cmd += ["--stdin-name=" + path.name] if stdin else [path.name]
                run = subprocess.run(cmd, input=text.encode() if stdin else b"", cwd=root,
                                     env=env, capture_output=True, timeout=20)
                report = json.loads(run.stdout)
                found = [f for f in report["findings"] if f["type"] == "aws_access_key_id"]
                correct = len(found) == int(expected)
                safe = b"AKIANAFGYOEYPXU1DSYP" not in run.stdout
                if expected and correct:
                    f = found[0]
                    correct = (f["stage"].startswith("reconstructed/") and len(f.get("evidence", [])) >= 2
                               and f["fingerprint"] == hashlib.sha256(("aws_access_key_id\0" + path.name + "\0AKIANAFGYOEYPXU1DSYP").encode()).hexdigest())
                ok = run.returncode == 0 and not report["truncated"] and correct and safe
                if stdin:
                    ok = ok and path.read_bytes() == sentinel
                checks.append(dict(case=name, ml=ml, stdin=stdin, passed=ok))
    report = dict(binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(), checks=checks,
                  passed=sum(c["passed"] for c in checks), total=len(checks))
    output = root / "qualification.json"
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(dict(report=str(output), passed=report["passed"], total=report["total"])))
    return int(report["passed"] != report["total"])


if __name__ == "__main__":
    raise SystemExit(main())
