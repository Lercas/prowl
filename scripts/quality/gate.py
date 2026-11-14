#!/usr/bin/env python3
"""Run the pinned ProwlBench subset through the static CLI without user configuration."""

import argparse
from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import tempfile

POLICY = Path(__file__).with_name("policy.json")
EXTENSIONS = {"code": "py", "log": "log", "confluence": "md"}
MAX_DATASET_BYTES = 16 << 20
MAX_REPORT_BYTES = 64 << 20


class GateError(Exception):
    """Invalid qualification evidence, rather than a quality regression."""


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise GateError("duplicate JSON key")
            result[key] = value
        return result
    def constant(_):
        raise GateError("non-finite JSON number")
    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, TypeError, UnicodeError) as error:
        raise GateError("invalid JSON") from error


def read_bounded(path, limit):
    try:
        with path.open("rb") as stream:
            data = stream.read(limit + 1)
    except OSError as error:
        raise GateError("required input is unavailable") from error
    if len(data) > limit:
        raise GateError("input size limit exceeded")
    return data


def load_cases(path, policy):
    data = read_bounded(path, MAX_DATASET_BYTES)
    spec = policy["dataset"]
    if hashlib.sha256(data).hexdigest() != spec["sha256"]:
        raise GateError("dataset digest mismatch")
    rows = [strict_json(line) for line in data.splitlines()]
    if len(rows) != spec["rows"]:
        raise GateError("dataset row count mismatch")
    seen = set()
    for row in rows:
        if (not isinstance(row, dict) or not isinstance(row.get("id"), str)
                or not re.fullmatch(r"pb-(?:cur-)?[0-9]+", row["id"])
                or row["id"] in seen or type(row.get("label")) is not int
                or row["label"] not in (0, 1) or not isinstance(row.get("text"), str)
                or not isinstance(row.get("source"), str)):
            raise GateError("invalid or duplicate dataset row")
        seen.add(row["id"])
    cases = rows[::spec["selection_stride"]]
    counts = Counter(row["label"] for row in cases)
    if len(cases) != spec["selected_rows"] or counts[1] != spec["secrets"] or counts[0] != spec["hard_negatives"]:
        raise GateError("subset composition mismatch")
    return cases


def evaluate(cases, report, baseline, inputs):
    if (not isinstance(report, dict) or report.get("complete") is not True
            or report.get("truncated") is not False or report.get("completion_reason") != "completed"
            or report.get("secrets_revealed") is not False or not isinstance(report.get("findings"), list)
            or not isinstance(report.get("stats"), dict)
            or report["stats"].get("processed") != len(cases)
            or report["stats"].get("bytes") != sum(len(row["text"].encode("utf-8")) for row in cases)):
        raise GateError("scan did not provide complete redacted coverage of every case")
    flagged = set()
    for finding in report["findings"]:
        if not isinstance(finding, dict) or finding.get("path") not in inputs:
            raise GateError("finding has an unknown source path")
        flagged.add(inputs[finding["path"]])
    counts = Counter(row["label"] for row in cases)
    hits = Counter(row["label"] for row in cases if row["id"] in flagged)
    recall, fp = hits[1] / counts[1], hits[0] / counts[0]
    for key in ("recall", "t4_fp_rate", "tolerance"):
        if type(baseline.get(key)) not in (int, float) or not math.isfinite(baseline[key]) or not 0 <= baseline[key] <= 1:
            raise GateError("invalid quality threshold")
    passed = recall >= baseline["recall"] - baseline["tolerance"] and fp <= baseline["t4_fp_rate"] + baseline["tolerance"]
    return {"passed": passed, "recall": recall, "t4_fp_rate": fp,
            "secret_hits": hits[1], "secrets": counts[1], "hard_negative_hits": hits[0], "hard_negatives": counts[0],
            "missed_positive_ids": [row["id"] for row in cases if row["label"] == 1 and row["id"] not in flagged],
            "false_positive_ids": [row["id"] for row in cases if row["label"] == 0 and row["id"] in flagged]}


def qualify(binary, dataset, policy, root):
    cases = load_cases(dataset, policy)
    source = root / "cases"
    source.mkdir()
    inputs = {}
    for row in cases:
        path = source / (row["id"] + "." + EXTENSIONS.get(row["source"], "txt"))
        path.write_text(row["text"], encoding="utf-8")
        inputs[str(path)] = row["id"]
    # Do not inherit installed models, overlays, identity keys, API endpoints or operator config.
    env = {key: value for key, value in os.environ.items() if not key.startswith("PROWL_")}
    env["PROWL_HOME"] = str(root / "home")
    command = [str(binary), "scan", str(source), "--bundled", "--ml", "--format=json", "--silence",
               "--no-color", "--log-level=error", "--max-size=2000000", "--max-per-file=0", "--no-dedupe"]
    try:
        with (root / "stdout.json").open("wb") as stdout, (root / "stderr.log").open("wb") as stderr:
            result = subprocess.run(command, cwd=root, env=env, stdin=subprocess.DEVNULL,
                                    stdout=stdout, stderr=stderr, timeout=180, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise GateError("scanner failed to execute or timed out") from error
    if result.returncode != 0:
        raise GateError("scanner exited unsuccessfully; metrics are not qualified")
    report = strict_json(read_bounded(root / "stdout.json", MAX_REPORT_BYTES))
    return evaluate(cases, report, policy["baseline"], inputs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    policy = strict_json(read_bounded(POLICY, 16384))
    result = {"schema_version": "prowl-quality-v1", "dataset": policy["dataset"], "baseline": policy["baseline"]}
    # Keep raw subprocess reports private and outside published metrics. TemporaryDirectory removes
    # only this invocation's own scratch files, including public benchmark texts and masked reports.
    with tempfile.TemporaryDirectory(prefix="prowl-quality-") as directory:
        root = Path(directory)
        try:
            binary = args.binary.resolve(strict=True)
            result["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
            result.update(qualify(binary, args.dataset.resolve(), policy, root))
            result["status"] = "passed" if result["passed"] else "regression"
            code = 0 if result["passed"] else 1
        except (GateError, OSError) as error:
            result.update(status="invalid", passed=False, error=str(error) if isinstance(error, GateError) else "required input is unavailable")
            code = 2
    # Exclusive output prevents accidentally replacing prior evidence or a user-selected input.
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps({key: result[key] for key in ("status", "passed", "recall", "t4_fp_rate", "error") if key in result}))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
