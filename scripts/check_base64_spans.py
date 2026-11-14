#!/usr/bin/env python3
"""Qualify mapped Base64 spans, proof chains and retained decoded occurrences."""

import argparse
import base64
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
    root = Path(tempfile.mkdtemp(prefix="prowl-base64-native-"))
    (root / "home").mkdir()
    env = dict(os.environ, PROWL_HOME=str(root / "home"))

    def run(args, data=b""):
        return subprocess.run([str(binary), *args], cwd=root, env=env, input=data,
                              capture_output=True, timeout=30)

    if run(["identity", "init", "-o", "owned.key"]).returncode:
        raise RuntimeError("cannot create disposable identity key")
    checks = []
    cases = [("padded", VALUE, 1, False), ("raw-url", "aws_secret??=" + VALUE, 1, False),
             ("repeat", "first=" + VALUE + "\nsecond=" + VALUE, 1, False),
             ("nested-two", VALUE, 2, False), ("nested-four", VALUE, 4, False),
             ("json-escaped", VALUE, 1, True)]
    for name, decoded, depth, structured in cases:
        spans = [(i, i + len(VALUE)) for i in range(len(decoded)) if decoded.startswith(VALUE, i)]
        blob = decoded
        for _ in range(depth):
            blob = base64.urlsafe_b64encode(blob.encode()).decode() if name == "raw-url" else base64.b64encode(blob.encode()).decode()
            if name == "raw-url":
                blob = blob.rstrip("=")
            spans = [(a // 3 * 4, min(len(blob), (b + 2) // 3 * 4)) for a, b in spans]
        if structured:
            prefix = '{"note":"🚀","payload":"'
            blob = "\\u%04x" % ord(blob[0]) + blob[1:]
            spans = [(a + (5 if a else 0), b + 5) for a, b in spans]
            text = prefix + blob + '"}'
        else:
            prefix = "# 🚀\nPAYLOAD=\""
            text = prefix + blob + '"'
        filename = name + (".json" if structured else ".env")
        line = prefix.count("\n") + 1
        byte_col = len(prefix.rsplit("\n", 1)[-1].encode()) + 1
        utf16_col = len(prefix.rsplit("\n", 1)[-1].encode("utf-16-le")) // 2 + 1
        expected = {(line, byte_col + a) for a, _ in spans}
        proof = (len(prefix.encode()), len(prefix.encode()) + len(blob.encode()))
        for keyed in (False, True):
            for ml in (False, True):
                for stdin in (False, True):
                    path = root / filename
                    sentinel = b"logical input must not be opened"
                    path.write_bytes(sentinel if stdin else text.encode())
                    for dedupe in (False, True):
                        args = ["scan", "--silence"]
                        args += ["--identity-key-file=owned.key"] if keyed else []
                        args += ["--ml"] if ml else []
                        args += [] if dedupe else ["--no-dedupe"]
                        args += ["--stdin-name=" + filename] if stdin else [filename]
                        for fmt in ("json", "sarif"):
                            result = run([*args, "--format=" + fmt], text.encode() if stdin else b"")
                            report = json.loads(result.stdout)
                            meta = report if fmt == "json" else report["runs"][0]["properties"]
                            fs = report["findings"] if fmt == "json" else [dict(f["properties"], type=f["ruleId"],
                                line=f["locations"][0]["physicalLocation"]["region"]["startLine"],
                                col=f["locations"][0]["physicalLocation"]["region"]["startColumn"]-utf16_col+byte_col)
                                for f in report["runs"][0]["results"]]
                            fs = [f for f in fs if f["type"] == "aws_access_key_id"]
                            occurrences = [o for f in fs for o in f.get("occurrences", [dict(f, id=f.get("occurrence_id"))])]
                            actual = {(o["line"], o["col"]) for o in occurrences}
                            ok = (result.returncode == 0 and meta["complete"] and not meta["truncated"]
                                  and len(occurrences) == len(spans) and actual == expected
                                  and VALUE.encode() not in result.stdout and blob.encode() not in result.stdout
                                  and (not keyed or all(o.get("id") for o in occurrences))
                                  and (not stdin or path.read_bytes() == sentinel))
                            for o in occurrences:
                                layers = [e for e in o.get("evidence", []) if e["transform"].startswith("base64-decode")]
                                ok = ok and len(layers) == depth and (layers[0]["start"], layers[0]["end"]) == proof
                            if fmt == "sarif":
                                for item in report["runs"][0]["results"]:
                                    if item["ruleId"] == "aws_access_key_id":
                                        region = item["locations"][0]["physicalLocation"]["region"]
                                        ok = ok and region["startLine"] == line and region["startColumn"] in {utf16_col+a for a, _ in spans}
                            checks.append(dict(case=name, keyed=keyed, ml=ml, stdin=stdin, dedupe=dedupe, format=fmt, passed=bool(ok)))
    fifth = VALUE
    for _ in range(5):
        fifth = base64.b64encode(fifth.encode()).decode()
    for name, blob, complete in [("depth-limit", fifth, False), ("size-limit", "A" * 8193, False),
                                 ("noncanonical", "QUtJQU5BRkdZT0VZUFhVMURTWVB=", True)]:
        result = run(["scan", "--stdin-name=" + name + ".env", "--format=json", "--silence"], ('payload="' + blob + '"').encode())
        report = json.loads(result.stdout)
        checks.append(dict(case=name, passed=result.returncode == (0 if complete else 2)
                           and report["complete"] == complete and not any(f["type"] == "aws_access_key_id" for f in report["findings"])))
        if not complete:
            baseline = root / (name + ".baseline")
            baseline.write_bytes(b"owned baseline sentinel")
            result = run(["scan", "--stdin-name=" + name + ".env", "--format=json", "--silence", "--write-baseline=" + str(baseline)], ('payload="' + blob + '"').encode())
            checks.append(dict(case=name + "-baseline", passed=result.returncode == 2 and baseline.read_bytes() == b"owned baseline sentinel"))
    report = dict(binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  passed=sum(c["passed"] for c in checks), total=len(checks), checks=checks)
    output = root / "qualification.json"
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(dict(report=str(output), passed=report["passed"], total=report["total"],
                          failures=[c for c in checks if not c["passed"]])))
    return int(report["passed"] != report["total"])


if __name__ == "__main__":
    raise SystemExit(main())
