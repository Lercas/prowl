#!/usr/bin/env python3
"""Qualify released keyed report identities offline with a private disposable home."""

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import subprocess
import tempfile


VALUE = "AKIANAFGYOEYPXU1DSYP"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix="prowl-report-identity-"))
    home = root / "home"
    home.mkdir()
    env = dict(os.environ, PROWL_HOME=str(home))
    checks = []

    def run(arguments, data=b"", cwd=root):
        return subprocess.run([str(binary), *arguments], input=data, cwd=cwd, env=env,
                              capture_output=True, timeout=30)

    def check(name, condition):
        checks.append(dict(case=name, passed=bool(condition)))

    (root / "production.env").write_text("AWS=" + VALUE)
    initial = run(["scan", "production.env", "--format=json", "--silence"])
    first = json.loads(initial.stdout)["findings"][0]
    check("keyless-baseline", initial.returncode == 0 and not first.get("secret_id")
          and first["fingerprint"] == hashlib.sha256(("aws_access_key_id\0production.env\0" + VALUE).encode()).hexdigest())
    keys = []
    for name in ("a.key", "b.key"):
        created = run(["identity", "init", "-o", name])
        path = root / name
        encoded = path.read_bytes()
        key = bytes.fromhex(encoded.decode().strip())
        check("create-" + name, created.returncode == 0 and len(key) == 32
              and (os.name == "nt" or path.stat().st_mode & 0o777 == 0o600))
        repeated = run(["identity", "init", "-o", name])
        check("exclusive-" + name, repeated.returncode == 2 and path.read_bytes() == encoded)
        keys.append(key)

    cases = [
        ("production.env", "AWS=" + VALUE, 1, []),
        ("production.json", '{"key":"' + "".join("\\u%04x" % ord(c) for c in VALUE) + '"}', 1, []),
        ("production.yaml", "definition: &a " + VALUE + "\none: {key: *a}\ntwo: {key: *a}\n", 3, []),
        ("bundle.js", "const head='AKIA';\nconst a=head+'NAFGYOEYPXU1DSYP';\nconst b=head+'NAFGYOEYPXU1DSYP';", 2, ["--reconstruct"]),
    ]
    for name, text, count, extra in cases:
        for key_name, key in zip(("a.key", "b.key"), keys):
            for ml in (False, True):
                for stdin in (False, True):
                    path = root / name
                    sentinel = b"logical input must never be read or changed"
                    path.write_bytes(sentinel if stdin else text.encode())
                    command = ["scan", "--identity-key-file=" + key_name, "--format=json", "--silence", "--no-dedupe", *extra]
                    command += ["--ml"] if ml else []
                    command += ["--stdin-name=" + name] if stdin else [name]
                    result = run(command, text.encode() if stdin else b"")
                    report = json.loads(result.stdout)
                    fs = [f for f in report["findings"] if f["type"] == "aws_access_key_id"]
                    expected = hmac.new(key, VALUE.encode(), hashlib.sha256).hexdigest()
                    fingerprint = hmac.new(key, ("fingerprint\0aws_access_key_id\0" + name + "\0" + VALUE).encode(), hashlib.sha256).hexdigest()
                    correct = (len(fs) == count and len({f.get("occurrence_id") for f in fs}) == count
                               and all(f.get("secret_id") == expected and f.get("fingerprint") == fingerprint
                                       and f.get("identity_scope") == hashlib.sha256(key).hexdigest()[:16]
                                       and f.get("occurrence_id") and f.get("context") is None for f in fs))
                    safe = VALUE.encode() not in result.stdout and key.hex().encode() not in result.stdout
                    check(f"{name}/{key_name}/ml={ml}/stdin={stdin}", result.returncode == 0
                          and not report["truncated"] and correct and safe
                          and (not stdin or path.read_bytes() == sentinel))

    # A real local Git source must preserve immutable blob provenance and timeline
    # identity even though the report identity is now keyed.
    repo = root / "repository"
    repo.mkdir()
    git_env = dict(env, GIT_AUTHOR_NAME="Owned fixture", GIT_AUTHOR_EMAIL="fixture@example.invalid",
                   GIT_COMMITTER_NAME="Owned fixture", GIT_COMMITTER_EMAIL="fixture@example.invalid")
    def git(*arguments):
        subprocess.run(["git", *arguments], cwd=repo, env=git_env, check=True, capture_output=True, timeout=20)
    git("init")
    for n in range(2):
        (repo / "prod.env").write_text("# revision " + str(n) + "\nAWS=" + VALUE)
        git("add", "prod.env")
        git("commit", "-m", "owned fixture " + str(n))
    result = run(["scan", "--git-timeline", "--identity-key-file=" + str(root / "a.key"), "--no-dedupe", "--format=json", "--silence"], cwd=repo)
    fs = json.loads(result.stdout)["findings"]
    check("git-source-provenance", result.returncode == 0 and len(fs) == 2
          and all(len(f.get("provenance", {}).get("blob", "")) in (40, 64)
                  and f.get("git", {}).get("complete") and f.get("occurrence_id") for f in fs))

    (root / "production.env").write_text("AWS=" + VALUE)
    created = run(["identity", "init"])
    default_key = bytes.fromhex((home / "identity.key").read_text().strip())
    auto = run(["scan", "production.env", "--format=json", "--silence"])
    fs = json.loads(auto.stdout)["findings"]
    check("optional-default-key", created.returncode == 0 and auto.returncode == 0
          and len(fs) == 1 and fs[0].get("secret_id") == hmac.new(default_key, VALUE.encode(), hashlib.sha256).hexdigest())
    report = dict(binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  passed=sum(c["passed"] for c in checks), total=len(checks), checks=checks)
    output = root / "qualification.json"
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(dict(report=str(output), passed=report["passed"], total=report["total"], failures=[c for c in checks if not c["passed"]])))
    return int(report["passed"] != report["total"])


if __name__ == "__main__":
    raise SystemExit(main())
