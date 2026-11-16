"""Локальная приёмка 1.4.0 на синтетических данных без обращения к провайдерам."""
import argparse
import json
import os
import subprocess
import tarfile
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", type=Path, required=True)
    ap.add_argument("--baseline-binary", type=Path)
    ap.add_argument("--output-dir", type=Path, required=True)
    ap.add_argument("--check-hook", action="store_true")
    args = ap.parse_args()
    root = args.output_dir.resolve()
    root.mkdir(parents=True, exist_ok=False)
    repo = root / "consumer"
    repo.mkdir()
    env = {**os.environ, "PROWL_HOME": str(root / "home"), "NO_COLOR": "1"}
    results = []

    def run(argv, expected, *, cwd=repo):
        p = subprocess.run(list(map(str, argv)), cwd=cwd, env=env, capture_output=True, text=True, timeout=180)
        if p.returncode != expected:
            raise AssertionError(f"{argv[0]} exit={p.returncode}, expected={expected}: {p.stderr[:1000]}")
        return p.stdout

    binary = args.binary.resolve()
    old = args.baseline_binary.resolve() if args.baseline_binary else None
    run(["git", "init", "-q"], 0)
    sample = repo / "credential.env"
    sample.write_text("No credentials here\n")
    run(["git", "add", "credential.env"], 0)
    run(["git", "-c", "user.name=Prowl acceptance", "-c", "user.email=offline@example.invalid", "commit", "-qm", "test: synthetic baseline"], 0)
    run([binary, "identity", "init"], 0)
    secret = "\x41KIANAFGYOEYPXU1DSYP"  # Synthetic, no provider verification.
    sample.write_text(f"AWS_KEY={secret}\n")
    run(["git", "add", "credential.env"], 0)
    sample.write_text("Working copy is clean\n")
    scan_args = ["scan", "--staged", "--format", "json", "--fail-on", "high"]
    staged = json.loads(run([binary, *scan_args, "--strict"], 1))
    assert any(f["type"] == "aws_access_key_id" for f in staged["findings"])
    assert staged["complete"] and staged["findings"][0]["provenance"]["blob"]
    prior = json.loads(run([old, *scan_args], 0)) if old else None
    results.append({"case": "partial_staging", "new_detected": True, "old_findings": len(prior["findings"]) if prior else None})
    js = repo / "bundle.js"
    js.write_text("const prefix='AKIA';const key=prefix+'NAFGYOEYPXU1DSYP';\n")
    reconstructed = json.loads(run([binary, "scan", js, "--reconstruct", "--strict", "--format", "json"], 0))
    hit = next(f for f in reconstructed["findings"] if f["type"] == "aws_access_key_id")
    assert len(hit["evidence"]) >= 2 and hit["secret_id"]
    prior = json.loads(run([old, "scan", js, "--format", "json"], 0)) if old else None
    results.append({"case": "split_js", "new_detected": True, "old_typed_detected": any(f["type"] == "aws_access_key_id" for f in prior["findings"]) if prior else None})
    oversized = json.loads(run([binary, "scan", js, "--max-size", "4", "--strict", "--format", "json"], 2))
    assert not oversized["complete"] and any(d["code"] == "max_size" for d in oversized["diagnostics"])
    if old:
        run([old, "scan", js, "--max-size", "4", "--format", "json"], 0)
    results.append({"case": "oversized_fail_closed", "new_exit": 2, "old_exit": 0 if old else None})
    sample.write_text(f"AWS_KEY={secret}\n")
    before = root / "before.json"
    after = root / "after.json"
    report = json.loads(run([binary, "scan", sample, "--ml", "--strict", "--format", "json"], 0))
    assert report["complete"] and any(f["type"] == "aws_access_key_id" for f in report["findings"])
    before.write_text(json.dumps(report))
    if old:
        run([old, "scan", sample, "--ml", "--format", "json"], 2)
    results.append({"case": "static_ml", "new_exit": 0, "old_exit": 2 if old else None})
    sample.write_text("No credentials here\n")
    report = json.loads(run([binary, "scan", sample, "--ml", "--strict", "--format", "json"], 0))
    after.write_text(json.dumps(report))
    remediation = json.loads(run([binary, "remediation-check", before, after], 0))
    assert remediation["comparable"] and remediation["items"][0]["presence"] == "absent_in_scope"
    assert remediation["items"][0]["revocation"] == "not_checked" and not remediation["items"][0]["closed"]
    results.append({"case": "absence_is_not_revocation", "passed": True})
    selftest = json.loads(run([binary, "selftest", "--ml"], 0))
    assert selftest["passed"]
    results.append({"case": "offline_selftest_ml", "passed": True})
    if args.check_hook:
        source_repo = Path(__file__).resolve().parent.parent
        archive = root / "hook-source.tar"
        with archive.open("xb") as output:
            subprocess.run(["git", "archive", "--format=tar", "HEAD", "tool", "scripts/precommit-prowl"],
                           cwd=source_repo, stdout=output, check=True)
        checkout = root / "hook-checkout"
        checkout.mkdir()
        with tarfile.open(archive) as source:
            source.extractall(checkout, filter="data")
        # The worktree is clean while the index still contains the credential planted above.
        hook = checkout / "scripts/precommit-prowl"
        # A damaged installed overlay must not replace this release's bundled hook rules.
        overlay = root / "home" / "rules"
        overlay.mkdir(exist_ok=False)
        (overlay / "broken.yaml").write_text("id: [invalid\n")
        report = json.loads(run([hook, "--format", "json"], 1))
        assert report["complete"] and any(f["type"] == "aws_access_key_id" for f in report["findings"])
        results.append({"case": "precommit_hook_consumer_index", "passed": True,
                        "source_revision": run(["git", "rev-parse", "HEAD"], 0, cwd=source_repo).strip()})
        run(["git", "add", "bundle.js"], 0)
        js.write_text("Working copy is clean\n")
        report = json.loads(run([hook, "--format", "json", "--no-dedupe"], 1))
        assert report["complete"] and any(f["type"] == "aws_access_key_id" and
            f["stage"].startswith("reconstructed/") for f in report["findings"])
        assert (overlay / "broken.yaml").read_text() == "id: [invalid\n"
        results.append({"case": "precommit_bundled_reconstruction_preserves_overlay", "passed": True})
    evidence = {"candidate_version": run([binary, "version"], 0).splitlines()[0], "checks": results,
                "boundary": "local synthetic inputs; no provider calls or publication", "inputs_retained": str(root)}
    (root / "acceptance.json").write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(evidence, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
