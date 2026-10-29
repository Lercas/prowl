"""Проверка границ 1.4.0 на собственных синтетических входах без сети и удаления файлов."""
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
    ap.add_argument("--baseline-binary", type=Path, required=True)
    ap.add_argument("--output-dir", type=Path, required=True)
    args = ap.parse_args()
    root = args.output_dir.resolve()
    root.mkdir(exist_ok=False)
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
        for label, binary in [("before", args.baseline_binary), ("after", args.binary)]:
            p = subprocess.run([str(binary.resolve()), *argv], cwd=directory, env=env,
                               capture_output=True, text=True, timeout=30)
            (root / f"{name}-{label}.stdout").write_text(p.stdout)
            (root / f"{name}-{label}.stderr").write_text(p.stderr)
            report = json.loads(p.stdout) if p.stdout.strip() else None
            row[label] = {"exit": p.returncode, "complete": report.get("complete") if report else None,
                          "has_envelope": report is not None,
                          "target_findings": sum(f.get("type") == "aws_access_key_id" for f in report.get("findings", [])) if report else 0}
            if label == "after":
                assert p.returncode == expected_exit and predicate(report), name
        rows.append(row)

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

    evidence = {"version": "1.4.0", "cases": rows, "binary_sha256": {
        label: hashlib.sha256(binary.read_bytes()).hexdigest() for label, binary in [("before", args.baseline_binary), ("after", args.binary)]},
        "boundary": "Own synthetic inputs. No network verification. Correlation identity IDs are simulated metadata, not real organization keys. Inputs and outputs retained.",
        "inputs_retained": str(root)}
    (root / "boundaries.json").write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"passed": len(rows), "cases": [r["case"] for r in rows], "inputs_retained": str(root)}, indent=2))


if __name__ == "__main__":
    main()
