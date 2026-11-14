#!/usr/bin/env python3
"""Compare default aggregate evidence with the native no-dedupe source inventory."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile


VALUE = "AKIANAFGYOEYPXU1DSYP"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix="prowl-occurrences-native-"))
    home = root / "home"
    home.mkdir()
    env = dict(os.environ, PROWL_HOME=str(home))
    checks = []

    def run(args, data=b""):
        return subprocess.run([str(binary), *args], cwd=root, env=env, input=data,
                              capture_output=True, timeout=30)

    def normalized(o):
        return json.dumps({k: o.get(k) for k in ("id", "source", "path", "line", "col", "evidence", "provenance", "verification")}, sort_keys=True)

    def inventory(report, fmt):
        if fmt == "json":
            return [f for f in report["findings"] if f["type"] == "aws_access_key_id"], report["truncated"]
        run = report["runs"][0]
        return [r["properties"] for r in run["results"] if r["ruleId"] == "aws_access_key_id"], run.get("properties", {}).get("truncated", False)

    created = run(["identity", "init", "-o", "owned.key"])
    if created.returncode != 0:
        raise SystemExit("cannot prepare disposable identity key")
    cases = [
        ("production.env", ("AWS=" + VALUE + "\n") * 3, 3, []),
        ("production.json", json.dumps({"one": VALUE, "two": VALUE, "three": VALUE}), 3, []),
        ("production.yaml", "definition: &a " + VALUE + "\none: {key: *a}\ntwo: {key: *a}\n", 3, []),
        ("bundle.js", "const head='AKIA';\n/*🚀*/ const a=head+'NAFGYOEYPXU1DSYP';\nconst b=head+'NAFGYOEYPXU1DSYP';", 2, ["--reconstruct"]),
    ]
    for name, text, count, extra in cases:
        for keyed in (False, True):
            for ml in (False, True):
                for stdin in (False, True):
                    path = root / name
                    sentinel = b"logical stdin must never be read or changed"
                    path.write_bytes(sentinel if stdin else text.encode())
                    command = ["scan", "--silence", *extra]
                    command += ["--identity-key-file=owned.key"] if keyed else []
                    command += ["--ml"] if ml else []
                    command += ["--stdin-name=" + name] if stdin else [name]
                    payload = text.encode() if stdin else b""
                    raw = run([*command, "--no-dedupe", "--format=json"], payload)
                    raw_fs, raw_truncated = inventory(json.loads(raw.stdout), "json")
                    expected = set()
                    for f in raw_fs:
                        o = dict(f, id=f.get("occurrence_id"))
                        expected.add(normalized(o))
                    for fmt in ("json", "sarif"):
                        result = run([*command, "--format=" + fmt], payload)
                        fs, truncated = inventory(json.loads(result.stdout), fmt)
                        actual = fs[0].get("occurrences", []) if len(fs) == 1 else []
                        ok = (raw.returncode == 0 and not raw_truncated and len(raw_fs) == count
                              and result.returncode == 0 and not truncated and len(fs) == 1
                              and len(actual) == count and {normalized(o) for o in actual} == expected
                              and VALUE.encode() not in result.stdout
                              and (not stdin or path.read_bytes() == sentinel))
                        checks.append(dict(case=name, keyed=keyed, ml=ml, stdin=stdin, format=fmt, passed=ok))

    # Two physical entries can have the same TAR member name and secret. The
    # final entry must represent the group without erasing its overwritten copy.
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w") as archive:
        for _ in range(2):
            data = ("AWS=" + VALUE).encode()
            header = tarfile.TarInfo("prod.env")
            header.size = len(data)
            archive.addfile(header, io.BytesIO(data))
    layer_bytes = layer.getvalue()
    config = json.dumps(dict(architecture="amd64", os="linux", config={},
                             rootfs=dict(type="layers", diff_ids=["sha256:" + hashlib.sha256(layer_bytes).hexdigest()]),
                             history=[dict(created_by="owned fixture")])).encode()
    manifest = json.dumps([dict(Config="config.json", RepoTags=["owned:fixture"], Layers=["layer.tar"])]).encode()
    with tarfile.open(root / "owned-image.tar", "w") as archive:
        for name, data in [("config.json", config), ("manifest.json", manifest), ("layer.tar", layer_bytes)]:
            header = tarfile.TarInfo(name)
            header.size = len(data)
            archive.addfile(header, io.BytesIO(data))
    for keyed in (False, True):
        command = ["image", "owned-image.tar", "--image-input=tar", "--silence"]
        command += ["--identity-key-file=owned.key"] if keyed else []
        raw = run([*command, "--no-dedupe", "--format=json"])
        raw_fs, raw_truncated = inventory(json.loads(raw.stdout), "json")
        expected = {normalized(dict(f, id=f.get("occurrence_id"))) for f in raw_fs}
        for fmt in ("json", "sarif"):
            result = run([*command, "--format=" + fmt])
            fs, truncated = inventory(json.loads(result.stdout), fmt)
            actual = fs[0].get("occurrences", []) if len(fs) == 1 else []
            checks.append(dict(case="repeated-image-entry", keyed=keyed, format=fmt,
                               passed=raw.returncode == 0 and not raw_truncated and len(raw_fs) == 2
                               and result.returncode == 0 and not truncated and len(fs) == 1 and len(actual) == 2
                               and {normalized(o) for o in actual} == expected
                               and (not keyed or len({o.get("id") for o in actual}) == 2)
                               and (fmt != "json" or fs[0].get("in_final_image") is True)))

    (root / "overflow.env").write_text(("AWS=" + VALUE + "\n") * 2049)
    for fmt in ("json", "sarif"):
        result = run(["scan", "overflow.env", "--format=" + fmt, "--silence"])
        fs, truncated = inventory(json.loads(result.stdout), fmt)
        checks.append(dict(case="overflow", format=fmt, passed=result.returncode == 2 and truncated
                           and len(fs) == 1 and len(fs[0].get("occurrences", [])) == 2048))
    baseline = root / "baseline.json"
    sentinel = b'["owned sentinel"]'
    baseline.write_bytes(sentinel)
    result = run(["scan", "overflow.env", "--write-baseline=baseline.json", "--min-severity=critical", "--format=json", "--silence"])
    checks.append(dict(case="overflow-preserves-baseline", passed=result.returncode == 2
                       and json.loads(result.stdout)["truncated"] and baseline.read_bytes() == sentinel))
    report = dict(binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  passed=sum(c["passed"] for c in checks), total=len(checks), checks=checks)
    output = root / "qualification.json"
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(dict(report=str(output), passed=report["passed"], total=report["total"], failures=[c for c in checks if not c["passed"]])))
    return int(report["passed"] != report["total"])


if __name__ == "__main__":
    raise SystemExit(main())
