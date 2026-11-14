"""Проверка выпущенных границ ввода на текущем CLI 1.5.0 на собственных синтетических входах без сети и удаления файлов."""
import argparse
import hashlib
import io
import json
import os
import subprocess
import zipfile
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", type=Path, required=True)
    ap.add_argument("--baseline-binary", type=Path)
    ap.add_argument("--output-dir", type=Path, required=True)
    args = ap.parse_args()
    root = args.output_dir.resolve()
    root.mkdir(mode=0o700, exist_ok=False)
    env = {**os.environ, "PROWL_HOME": str(root / "home"), "NO_COLOR": "1"}
    key = "\x41KIANAFGYOEYPXU1DSYP"  # Synthetic; never verified with a provider.
    rows = []

    def git(directory, *argv, input=None):
        return subprocess.run(["git", *argv], cwd=directory, env=env, input=input,
                              capture_output=True, text=True, check=True).stdout

    def case_repo(name):
        directory = root / name
        directory.mkdir()
        git(directory, "init", "-q")
        return directory

    def check(name, directory, argv, expected_exit, predicate):
        row = {"case": name, "command_arguments": argv, "working_directory": str(directory)}
        for label, binary in ([("before", args.baseline_binary)] if args.baseline_binary else []) + [("after", args.binary)]:
            p = subprocess.run([str(binary.resolve()), *argv], cwd=directory, env=env,
                               capture_output=True, text=True, timeout=30)
            (root / f"{name}-{label}.stdout").write_text(p.stdout)
            (root / f"{name}-{label}.stderr").write_text(p.stderr)
            report = json.loads(p.stdout) if p.stdout.strip() else None
            row[label] = {"exit": p.returncode, "complete": report.get("complete") if report else None,
                          "has_envelope": report is not None,
                          "target_findings": sum(f.get("type") == "aws_access_key_id" for f in report.get("findings", [])) if report else 0}
            if label == "after":
                row["passed"] = p.returncode == expected_exit and bool(predicate(report))
        rows.append(row)
        (root / "observations.json").write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n")


    scan = ["scan", "--strict", "--format", "json", "--fail-on", "high"]
    directory = case_repo("status_shaped_name")
    for name, text in [("R100", f"AWS_KEY={key}\n"), ("a.env", "clean\n"), ("b.env", "clean\n")]:
        (directory / name).write_text(text)
        git(directory, "add", "--", name)
    (directory / "R100").write_text("Clean working copy\n")
    typed = lambda r: r is not None and any(f["type"] == "aws_access_key_id" for f in r["findings"])
    check("status_shaped_name", directory, scan + ["--staged"], 1, lambda r: r["complete"] and typed(r))

    directory = case_repo("unmerged_index")
    sha = git(directory, "hash-object", "-w", "--stdin", input="synthetic conflict\n").strip()
    git(directory, "update-index", "--index-info", input="".join(f"100644 {sha} {stage}\tconflict.env\n" for stage in [1, 2, 3]))
    check("unmerged_index", directory, scan + ["--staged"], 2, lambda r: not r["complete"] and any(d["code"] == "git_index_unmerged" for d in r["diagnostics"]))

    directory = case_repo("empty_index")
    check("empty_index", directory, scan + ["--staged"], 0, lambda r: r["complete"] and r["findings"] == [] and r["scope"])

    directory = case_repo("subdirectory")
    sub = directory / "sub"
    sub.mkdir()
    (sub / "key.env").write_text(f"AWS_KEY={key}\n")
    git(directory, "add", "sub/key.env")
    check("subdirectory", sub, scan + ["--staged"], 1, lambda r: r["complete"] and typed(r))

    directory = root / "archives"
    directory.mkdir()
    data, member = f"AWS_KEY={key}\n".encode(), "secret.env"
    for _ in range(4):
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(member, data)
        data, member = out.getvalue(), "nested.zip"
    (directory / "nested.zip").write_bytes(data)
    check("archive_depth", directory, scan + ["nested.zip"], 2, lambda r: not r["complete"] and any(d["code"] == "archive_depth_limit" for d in r["diagnostics"]))
    (directory / "corrupt.zip").write_text(f"AWS_KEY={key}\n")
    check("malformed_archive", directory, scan + ["corrupt.zip"], 2, lambda r: not r["complete"] and typed(r))

    for mode, filename, diagnostic, want_typed in [
        ("malformed", "corrupt.zip", "archive_incomplete", True),
        ("depth", "nested.zip", "archive_depth_limit", False),
    ]:
        for ml in (False, True):
            for fmt in ("json", "sarif"):
                baseline = directory / f"{mode}-{ml}-{fmt}.baseline"
                baseline.write_text("owned baseline sentinel")
                argv = ["scan", filename, "--strict", "--format=" + fmt,
                        "--write-baseline=" + str(baseline), *(["--ml"] if ml else [])]
                p = subprocess.run([str(args.binary.resolve()), *argv], cwd=directory, env=env,
                                   capture_output=True, text=True, timeout=30)
                case = f"{mode}-{ml}-{fmt}"
                (root / f"{case}.stdout").write_text(p.stdout)
                (root / f"{case}.stderr").write_text(p.stderr)
                report = json.loads(p.stdout)
                meta = report if fmt == "json" else report["runs"][0]["properties"]
                findings = report["findings"] if fmt == "json" else report["runs"][0]["results"]
                typed_hit = any(f.get("type", f.get("ruleId")) == "aws_access_key_id" for f in findings)
                passed = (p.returncode == 2 and not meta["complete"] and
                          any(d["code"] == diagnostic for d in meta["diagnostics"]) and
                          typed_hit == want_typed and key not in p.stdout and
                          baseline.read_text() == "owned baseline sentinel")
                rows.append({"case": case, "passed": passed, "exit": p.returncode,
                             "complete": meta["complete"], "typed_hit": typed_hit,
                             "baseline_preserved": baseline.read_text() == "owned baseline sentinel"})
                (root / "observations.json").write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n")

    directory = root / "expressions"
    directory.mkdir()
    (directory / "application.js").write_text("const head='AKIA';const key=`\\x24{head}NAFGYOEYPXU1DSYP`;\n")
    check("escaped_template", directory, scan + ["application.js", "--reconstruct"], 0, lambda r: r["complete"] and not typed(r))
    (directory / "ambiguous.js").write_text("x/[" * 10000)
    check("regex_work_budget", directory, scan + ["ambiguous.js", "--reconstruct"], 2, lambda r: not r["complete"] and any(d["code"] == "reconstruction_limit" for d in r["diagnostics"]))

    directory = root / "correlation"
    directory.mkdir()
    finding = {"type": "vendor_token", "secret_id": "b" * 64, "identity_scope": "a" * 16,
               "occurrence_id": "c" * 64, "redacted": "abcd********wxyz", "provenance": {"digest": "d" * 64}}
    finding["occurrences"] = [{"id": f"{i+1:064x}", "provenance": finding["provenance"]} for i in range(258)]
    report = {"schema_version": "1.4", "identity_scope": "a" * 16, "complete": True,
              "completion_reason": "completed", "count": 1, "findings": [finding]}
    (directory / "before.json").write_text(json.dumps(report))
    report.update(count=0, findings=[])
    (directory / "after.json").write_text(json.dumps(report))
    check("correlation_link_cap", directory, ["correlate", "before.json", "after.json"], 2,
          lambda r: not r["complete"] and r["groups"][0]["links_truncated"] and len(r["groups"][0]["links"]) == 256)

    evidence = {"version": "1.5.0", "cases": rows, "binary_sha256": {
        label: hashlib.sha256(binary.read_bytes()).hexdigest() for label, binary in ([("before", args.baseline_binary)] if args.baseline_binary else []) + [("after", args.binary)]},
        "boundary": "Own synthetic inputs. No network verification. Correlation identity IDs are simulated metadata, not real organization keys. Inputs and outputs retained.",
        "inputs_retained": str(root)}
    (root / "boundaries.json").write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"passed": sum(r["passed"] for r in rows), "total": len(rows), "cases": [r["case"] for r in rows], "inputs_retained": str(root)}, indent=2))
    assert all(r["passed"] for r in rows), "released boundary regression; inspect retained observations"


if __name__ == "__main__":
    main()
