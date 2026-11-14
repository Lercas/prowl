"""Compare the actual per-item Go pipeline against a fixed, reviewable revision.

Builds and logs stay in a new output directory; the caller's checkout is never
modified. No corpus values or findings are retained in the JSON report.
"""

import argparse
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import statistics
import subprocess
import tarfile


ROOT = Path(__file__).resolve().parents[2]
POLICY = Path(__file__).with_name("policy.json")
HARNESS = "tool/internal/scan/corpus_bench_test.go"
REQUIRED = ("ns/op", "B/op", "allocs/op", "corpus-files", "corpus-bytes", "findings/op")


def validate_policy(policy):
    if type(policy["pairs"]) is not int or policy["pairs"] < 3:
        raise ValueError("at least three complete pairs are required")
    for key in ("max_time_ratio", "max_bytes_ratio", "max_allocs_ratio"):
        value = policy[key]
        if type(value) not in (int, float) or not math.isfinite(value) or value < 1:
            raise ValueError("invalid performance threshold")
    for key in ("min_corpus_files", "min_corpus_bytes"):
        if type(policy[key]) is not int or policy[key] <= 0:
            raise ValueError("invalid corpus minimum")
    if not re.fullmatch(r"go\d+\.\d+\.\d+", policy["go"]) or not re.fullmatch(r"[0-9a-f]{40,64}", policy["reference"]):
        raise ValueError("toolchain and baseline must be pinned")


def corpus_manifest(root):
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("corpus must be a directory")
    digest = hashlib.sha256()
    files = size = 0

    def visit(directory):
        nonlocal files, size
        for path in sorted(directory.iterdir()):
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                visit(path)
            elif stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 10 << 20:
                raw = path.read_bytes()
                if len(raw) != info.st_size:
                    raise ValueError("corpus changed while reading")
                name = path.relative_to(root).as_posix().encode()
                digest.update(len(name).to_bytes(8, "big") + name)
                digest.update(len(raw).to_bytes(8, "big") + raw)
                files += 1
                size += len(raw)

    visit(root)
    if not files:
        raise ValueError("corpus is empty")
    return {"files": files, "bytes": size, "sha256": digest.hexdigest()}


def parse_benchmark(output, manifest):
    rows = re.findall(r"^BenchmarkFindingsCorpus(?:-\d+)?\s+(\d+)\s+(.+)$", output, re.M)
    if len(rows) != 1 or not re.search(r"^PASS$", output, re.M) or re.search(r"^FAIL", output, re.M):
        raise ValueError("expected one successful BenchmarkFindingsCorpus sample")
    count, body = rows[0]
    fields = body.split()
    if count != "1" or len(fields) % 2:
        raise ValueError("benchmark must run one complete corpus iteration")
    metrics = {}
    for value, unit in zip(fields[::2], fields[1::2]):
        if unit in metrics:
            raise ValueError("duplicate benchmark metric")
        number = float(value)
        if not math.isfinite(number) or number < 0:
            raise ValueError("invalid benchmark metric")
        metrics[unit] = number
    if any(unit not in metrics for unit in REQUIRED) or metrics["ns/op"] <= 0 or metrics["findings/op"] <= 0:
        raise ValueError("missing metrics or pipeline produced no findings")
    if metrics["corpus-files"] != manifest["files"] or metrics["corpus-bytes"] != manifest["bytes"]:
        raise ValueError("benchmark did not consume the complete corpus")
    return {unit: metrics[unit] for unit in REQUIRED}


def evaluate(samples, policy):
    if any(len(samples.get(side, [])) != policy["pairs"] for side in ("reference", "candidate")):
        raise ValueError("paired samples are incomplete")
    medians = {side: {unit: statistics.median(row[unit] for row in samples[side]) for unit in REQUIRED}
               for side in ("reference", "candidate")}
    ratios, failures = {}, []
    for unit, threshold in (("ns/op", "max_time_ratio"), ("B/op", "max_bytes_ratio"),
                            ("allocs/op", "max_allocs_ratio")):
        before, after = medians["reference"][unit], medians["candidate"][unit]
        ratio = after / before if before else (1.0 if not after else None)
        ratios[unit] = ratio
        if ratio is None or ratio > policy[threshold]:
            failures.append(unit)
    return {"medians": medians, "ratios": ratios, "regressions": failures,
            "status": "regression" if failures else "passed"}


def revision(root, ref):
    value = subprocess.check_output(["git", "rev-parse", "--verify", "--end-of-options", ref + "^{commit}"],
                                    cwd=root, text=True).strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", value):
        raise ValueError("reference must identify one commit")
    return value


def export(root, sha, destination, harness):
    raw = subprocess.check_output(["git", "archive", sha], cwd=root)
    destination.mkdir()
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        archive.extractall(destination, filter="data")
    target = destination / HARNESS
    if target.is_symlink():
        raise ValueError("benchmark harness must not be a symlink")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(harness)


def run_logged(command, cwd, env, log, timeout):
    with log.open("x") as output:
        result = subprocess.run(command, cwd=cwd, env=env, stdout=output,
                                stderr=subprocess.STDOUT, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}); see {log}")
    return log.read_text()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", help="override the pinned revision for an explicit local comparison")
    parser.add_argument("--candidate", default="HEAD")
    parser.add_argument("--corpus", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    policy = json.loads(POLICY.read_text())
    validate_policy(policy)
    output = args.output_dir.absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("output directory must not already exist")
    output.mkdir(parents=True)
    report = {"policy": policy, "samples": {"reference": [], "candidate": []}, "status": "error"}
    try:
        env = os.environ | {"GOTOOLCHAIN": policy["go"], "CGO_ENABLED": "0", "GOMAXPROCS": "2",
                            "GOGC": "100", "GOWORK": "off"}
        env.pop("PROWL_BENCH_NORULES", None)
        git_root = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], cwd=ROOT, text=True).strip())
        if git_root.resolve() != ROOT:
            raise ValueError("unexpected Git checkout")
        info = json.loads(subprocess.check_output(["go", "env", "-json", "GOVERSION", "GOHOSTOS", "GOHOSTARCH", "GOROOT"],
                                                  cwd=ROOT / "tool", env=env, text=True))
        if info["GOVERSION"] != policy["go"]:
            raise ValueError("unexpected Go toolchain")
        env["GOOS"], env["GOARCH"] = info["GOHOSTOS"], info["GOHOSTARCH"]
        report["runtime"] = {"go": info["GOVERSION"], "os": env["GOOS"], "arch": env["GOARCH"], "gomaxprocs": 2}
        corpus = args.corpus or Path(info["GOROOT"]) / "src"
        corpus = corpus.resolve(strict=True)
        manifest = corpus_manifest(corpus)
        if manifest["files"] < policy["min_corpus_files"] or manifest["bytes"] < policy["min_corpus_bytes"]:
            raise ValueError("corpus is too small for the release performance gate")
        report["corpus"] = manifest
        harness = (ROOT / HARNESS).read_bytes()
        report["harness_sha256"] = hashlib.sha256(harness).hexdigest()
        shas = {"reference": revision(ROOT, args.reference or policy["reference"]),
                "candidate": revision(ROOT, args.candidate)}
        report["commits"] = shas
        env["PROWL_BENCH_CORPUS"] = str(corpus)
        for side, sha in shas.items():
            directory = output / side
            export(ROOT, sha, directory, harness)
            run_logged(["go", "test", "-mod=readonly", "-c", "-o", str(output / (side + ".test")),
                        "./internal/scan"], directory / "tool", env, output / (side + "-build.log"), 300)
        for pair in range(policy["pairs"]):
            order = ("reference", "candidate") if pair % 2 == 0 else ("candidate", "reference")
            for side in order:
                text = run_logged([str(output / (side + ".test")), "-test.run=^$",
                                   "-test.bench=^BenchmarkFindingsCorpus$", "-test.benchtime=1x", "-test.timeout=5m"],
                                  output / side / "tool/internal/scan", env, output / f"{side}-{pair}.log", 330)
                metrics = parse_benchmark(text, manifest)
                report["samples"][side].append(metrics)
                print(f"pair={pair + 1} side={side} seconds={metrics['ns/op'] / 1e9:.3f}", flush=True)
        if corpus_manifest(corpus) != manifest:
            raise ValueError("corpus changed during comparison")
        report.update(evaluate(report["samples"], policy))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2), flush=True)
    return {"passed": 0, "regression": 1, "error": 2}[report["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
