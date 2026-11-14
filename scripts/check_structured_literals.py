#!/usr/bin/env python3
"""Offline native qualification of structured literals and the embedded L2 model.

Retain all artifacts in a new private temporary directory. Exit nonzero if any
expected credential, identity, diagnostic or redaction check fails, including ML.
Fixtures are synthetic and no live verification is requested.
"""

import argparse
import base64
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

AWS = "AKIANAFGYOEYPXU1DSYP"
STRIPE = "sk_live_Q5t7U9i2O4p6A8s0D3f5G7h9"
PASSWORD = "Winter42!Autumn"


def fixtures():
    cases = []

    def add(name, extension, text, values=(), incomplete=False):
        cases.append(dict(name=name, extension=extension, text=text, values=values, incomplete=incomplete))

    for index, (name, value, typ) in enumerate([
        ("password", PASSWORD, "generic_password"),
        ("пароль", "ЖукЖук🚀", "generic_password"),
        ("password", '"Winter42"\nAutumn\\53', "generic_password"),
        ("password", "Winter<42>Autumn", "generic_password"),
        ("password", "Winter${42}Autumn", "generic_password"),
        ("password", "Winter{{42}}Autumn", "generic_password"),
        ("api_key", AWS, "aws_access_key_id"),
        ("token", STRIPE, "stripe_secret_key"),
    ]):
        encoded = value.encode("utf-16-be")
        escaped = "".join("\\u%04x" % int.from_bytes(encoded[i:i + 2], "big") for i in range(0, len(encoded), 2))
        add(f"json-{index}", ".json", "{" + json.dumps(name) + ':"' + escaped + '"}', [(typ, value)])
        add(f"yaml-canonical-{index}", ".yaml", json.dumps({name: value}, ensure_ascii=False) + "\n", [(typ, value)])
        add(f"toml-canonical-{index}", ".toml", json.dumps(name, ensure_ascii=False) + "=" + json.dumps(value, ensure_ascii=False) + "\n", [(typ, value)])

    add("yaml-plain", ".yaml", "password: " + PASSWORD + "\n", [("generic_password", PASSWORD)])
    add("yaml-escaped", ".yaml", 'password: "Winter\\u0034\\u0032!Autumn"\n', [("generic_password", PASSWORD)])
    add("yaml-block", ".yaml", "password: |-\n  Winter42!Autumn\n  Spring53\n", [("generic_password", PASSWORD + "\nSpring53")])
    add("yaml-folded", ".yaml", "password: >-\n  Winter42!Autumn\n  Spring53\n", [("generic_password", PASSWORD + " Spring53")])
    add("yaml-scalar-alias", ".yaml", "definition: &a " + PASSWORD + "\npassword: *a\n", [("generic_password", PASSWORD)])
    add("yaml-object-alias", ".yaml", "definition: &a {password: " + PASSWORD + "}\ncopy: *a\n", [("generic_password", PASSWORD)] * 2)
    add("yaml-merge-override", ".yaml", "base: &a {password: " + PASSWORD + "}\ncopy: {<<: *a, password: Spring53!Summer}\n", [("generic_password", PASSWORD), ("generic_password", "Spring53!Summer")])
    add("yaml-binary", ".yaml", "key: !!binary |\n  " + base64.b64encode(AWS.encode()).decode() + "\n", [("aws_access_key_id", AWS)])
    add("yaml-comment", ".yaml", "# " + AWS + "\nvalue: ordinary\n", [("aws_access_key_id", AWS)])
    add("yaml-unicode-crlf", ".yaml", "note: 🚀\r\nkey: " + AWS + "\r\n", [("aws_access_key_id", AWS)])
    add("yaml-data-pragma", ".yaml", "key: '" + AWS + " # prowl:allow'\n", [("aws_access_key_id", AWS)])
    add("yaml-comment-pragma", ".yaml", "key: " + AWS + " # prowl:allow\n")
    add("toml-literal", ".toml", "password='Winter42\\'\n", [("generic_password", "Winter42\\")])
    add("toml-escaped", ".toml", 'password="Winter\\u0034\\u0032!Autumn"\n', [("generic_password", PASSWORD)])
    add("toml-literal-escape", ".toml", "password='Winter\\u0034\\u0032!Autumn'\n", [("generic_password", "Winter\\u0034\\u0032!Autumn")])
    add("toml-block", ".toml", 'password="""\nWinter42!Autumn\nSpring53"""\n', [("generic_password", PASSWORD + "\nSpring53")])
    add("toml-folded", ".toml", 'password="""Winter\\\n  42!Autumn"""\n', [("generic_password", PASSWORD)])
    add("toml-unicode-key", ".toml", '"\\u0070assword"="' + PASSWORD + '"\n', [("generic_password", PASSWORD)])
    add("toml-dotted", ".toml", 'auth.password="' + PASSWORD + '"\n', [("generic_password", PASSWORD)])
    add("toml-array-tables", ".toml", '[[accounts]]\nkey="' + AWS + '"\n[[accounts]]\nkey="' + AWS + '"\n', [("aws_access_key_id", AWS)] * 2)
    add("toml-comment", ".toml", "# " + AWS + "\nvalue='ordinary'\n", [("aws_access_key_id", AWS)])
    add("toml-data-pragma", ".toml", "key='" + AWS + " # prowl:allow'\n", [("aws_access_key_id", AWS)])
    add("toml-comment-pragma", ".toml", "key='" + AWS + "' # prowl:allow\n")
    for ext, text in [
        (".json", '{"token":"' + STRIPE + '\\ud800"}'),
        (".toml", 'token="' + STRIPE + '\\q"'),
        (".yaml", 'token: "' + STRIPE + '\\q"\n'),
        (".yaml", "password: !env PASSWORD\n"),
    ]:
        add("incomplete-" + str(len(cases)), ext, text, incomplete=True)
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--model", type=Path, help="qualify an explicit candidate without replacing the installed model")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    candidate = args.model.resolve(strict=True) if args.model else None
    root = Path(tempfile.mkdtemp(prefix="prowl-structured-native-"))
    home = root / "home"
    home.mkdir()
    env = dict(os.environ, PROWL_HOME=str(home))
    cases = fixtures()
    (root / "fixtures.json").write_text(json.dumps(cases, ensure_ascii=False, indent=2) + "\n")
    checks = []
    for case in cases:
        name = case["name"] + case["extension"]
        path = root / name
        payload = case["text"].encode()
        for ml in (False, True):
            for stdin in (False, True):
                sentinel = b"logical stdin name must never be read or modified"
                path.write_bytes(sentinel if stdin else payload)
                command = [str(binary), "scan", "--format=json", "--silence", "--no-dedupe"]
                command += ["--ml"] if ml else []
                if ml and candidate:
                    command += ["--ml-model=" + str(candidate)]
                command += ["--stdin-name=" + name] if stdin else [name]
                result = subprocess.run(command, input=payload if stdin else b"", cwd=root, env=env, capture_output=True, timeout=20)
                report = json.loads(result.stdout)
                found = [f for f in report["findings"] if f["type"] not in ("source_error", "response_truncated", "results_truncated", "item_too_large")]
                expected = Counter((typ, hashlib.sha256((typ + "\0" + name + "\0" + value).encode()).hexdigest()) for typ, value in case["values"])
                actual = Counter((f["type"], f.get("fingerprint")) for f in found)
                safe = all(f.get("context") is None and all(f["redacted"] != value for _, value in case["values"]) for f in found)
                ok = result.returncode == (2 if case["incomplete"] else 0) and bool(report["truncated"]) == case["incomplete"] and safe
                if not case["incomplete"]:
                    ok = ok and actual == expected
                if stdin:
                    ok = ok and path.read_bytes() == sentinel
                checks.append(dict(case=case["name"], ml=ml, stdin=stdin, passed=ok, expected=sum(expected.values()), found=len(found), exit=result.returncode))
    report = dict(binary=str(binary), sha256=hashlib.sha256(binary.read_bytes()).hexdigest(), artifact_dir=str(root), checks=checks)
    if candidate:
        report.update(model=str(candidate), model_sha256=hashlib.sha256(candidate.read_bytes()).hexdigest())
    report["passed"] = sum(c["passed"] for c in checks)
    report["total"] = len(checks)
    output = root / "qualification.json"
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(dict(report=str(output), passed=report["passed"], total=report["total"], failures=[c for c in checks if not c["passed"]])))
    return int(report["passed"] != report["total"])


if __name__ == "__main__":
    raise SystemExit(main())
