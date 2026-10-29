"""Compare local scanners on synthetic credential representations, without live verification."""
import argparse
import base64
import hashlib
import json
import os
import random
import shutil
import subprocess
import time
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", type=Path, required=True)
    ap.add_argument("--output-dir", type=Path, required=True)
    ap.add_argument("--competitors", action="store_true")
    args = ap.parse_args()
    root = args.output_dir.resolve()
    root.mkdir(exist_ok=False)
    cases = root / "cases"
    cases.mkdir()
    rng = random.Random(1400)
    rows = []
    for provider, prefix, tail_length in [("aws", "AKIA", 16), ("stripe", "sk_live_", 24)]:
        tail = "".join(rng.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=tail_length))
        value = prefix + tail
        quoted_prefix, quoted_tail = json.dumps(prefix), json.dumps(tail)
        encoded = base64.b64encode(value.encode()).decode()
        variants = {
            "plain": (json.dumps(value), True),
            "concat": (f"{quoted_prefix}+{quoted_tail}", True),
            "constant_binding": (f"prefix+{quoted_tail}", True),
            "escaped_literal": ("'" + "".join(f"\\x{ord(c):02x}" for c in value) + "'", True),
            "atob": (f"atob({json.dumps(encoded)})", True),
            "atob_unpadded": (f"atob({json.dumps(encoded.rstrip('='))})", True),
            "uri_decode": (f"decodeURIComponent({json.dumps(''.join('%'+format(ord(c),'02x') for c in value))})", True),
            "template": ("`${prefix}" + tail + "`", True),
            "join": (f"[{quoted_prefix},{quoted_tail}].join('')", True),
            "arrow_shadow": (f"(prefix)=>prefix+{quoted_tail}", False),
            "regex_data": (f"/[{quoted_prefix}+{quoted_tail}]/", False),
            "tagged_raw": ("String.raw`" + "".join(f"\\x{ord(c):02x}" for c in value) + "`", False),
        }
        for kind, (expression, expected) in variants.items():
            name = provider + "_" + kind
            directory = cases / name
            directory.mkdir()
            code = f"const prefix={quoted_prefix};const api_key={expression};\n"
            if provider == "aws":
                secret = "".join(rng.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", k=40))
                code += f"const aws_secret_access_key={json.dumps(secret)};\n"
            (directory / "app.js").write_text(code)
            rows.append({"case": name, "provider": provider, "expected": expected, "needle": value})
    env = {k: v for k, v in os.environ.items() if k not in ["GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML"]}
    env.update(PROWL_HOME=str(root / "clean-home"), NO_COLOR="1")
    commands = {
        "prowl": [str(args.binary.resolve()), "scan", str(cases), "--reconstruct", "--strict", "--show-secrets", "--format", "json"],
    }
    if args.competitors:
        for name in ["gitleaks", "trufflehog"]:
            if not shutil.which(name):
                raise RuntimeError(f"requested local competitor is unavailable: {name}")
        commands["gitleaks"] = ["gitleaks", "dir", str(cases), "--no-banner", "--no-color", "--redact=0", "--report-format", "json", "--report-path", str(root / "gitleaks.json")]
        commands["trufflehog"] = ["trufflehog", "filesystem", "--no-verification", "--no-update", "--json", str(cases)]
    results = {}
    for name, command in commands.items():
        start = time.monotonic()
        process = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, timeout=180)
        elapsed = time.monotonic() - start
        (root / (name + ".stdout")).write_text(process.stdout)
        (root / (name + ".stderr")).write_text(process.stderr)
        if process.returncode not in [0, 1]:
            raise RuntimeError(f"{name} failed: exit {process.returncode}")
        if name == "prowl":
            report = json.loads(process.stdout)
            if not report["complete"]:
                raise RuntimeError("Prowl benchmark scan is incomplete")
            observations = [{"path": f["path"], "values": [f["redacted"]]} for f in report["findings"]]
            version = subprocess.check_output([command[0], "version"], env=env, text=True).splitlines()[0]
        elif name == "gitleaks":
            observations = [{"path": f["File"], "values": [f["Secret"]]} for f in json.loads((root / "gitleaks.json").read_text())]
            version = subprocess.check_output(["gitleaks", "version"], text=True).strip()
        else:
            observations = []
            for line in process.stdout.splitlines():
                f = json.loads(line)
                path = f.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", "")
                observations.append({"path": path, "values": [str(f.get("RawV2", "")), str(f.get("Raw", ""))]})
            version = subprocess.check_output(["trufflehog", "--version"], stderr=subprocess.STDOUT, text=True).strip()
        statuses = {}
        for row in rows:
            statuses[row["case"]] = any(row["case"] in o["path"].replace("\\", "/").split("/") and any(row["needle"] in value for value in o["values"]) for o in observations)
        executable = Path(command[0] if name == "prowl" else shutil.which(name))
        results[name] = {"version": version, "binary_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(), "command": command, "exit": process.returncode, "one_run_wall_seconds": elapsed,
                         "positive_cases_found": sum(statuses[r["case"]] for r in rows if r["expected"]),
                         "unsupported_contexts_reported": sum(statuses[r["case"]] for r in rows if not r["expected"]), "cases": statuses}
    fixture_hashes = {str(p.relative_to(cases)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(cases.rglob("app.js"))}
    output = {"seed": 1400, "positive_cases": sum(r["expected"] for r in rows), "unsupported_contexts": sum(not r["expected"] for r in rows),
              "fixture_sha256": fixture_hashes, "results": results,
              "boundary": "Synthetic representation coverage, not a market precision/recall benchmark. No LIVE credentials. Verification and TruffleHog updates disabled. Default competitor decoding; no custom rules. Raw outputs retained locally."}
    (root / "benchmark.json").write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({name: {k: v for k, v in result.items() if k not in ["cases", "command"]} for name, result in results.items()}, indent=2))


if __name__ == "__main__":
    main()
