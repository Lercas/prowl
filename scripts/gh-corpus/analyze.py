#!/usr/bin/env python3
"""Aggregate Prowl findings across a scanned corpus and characterize types / false-positive classes.

  ./analyze.py findings            # human report
  ./analyze.py findings --json     # machine-readable summary
"""
import argparse
import glob
import json
import re
from collections import Counter

GENERIC = re.compile(r"generic|high_entropy")  # low-confidence catch-all types = likely FP/noise


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir", nargs="?", default="findings")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    files = glob.glob(f"{args.dir}/*.json")
    repos = with_findings = total = typed = generic = 0
    by_type, by_sev, verify, by_ext = Counter(), Counter(), Counter(), Counter()
    by_type_live = Counter()
    per_repo, noisy, live = [], [], []
    for fp in files:
        try:
            fs = json.load(open(fp)).get("findings", [])
        except Exception:
            continue
        repo = fp.split("/")[-1][:-5]
        repos += 1
        per_repo.append(len(fs))
        if fs:
            with_findings += 1
        if len(fs) > 50:
            noisy.append((repo, len(fs)))
        for f in fs:
            total += 1
            t = f.get("type", "?")
            by_type[t] += 1
            by_sev[f.get("severity", "?")] += 1
            v = f.get("verified")
            verify["live" if v is True else "dead" if v is False else "unverified"] += 1
            if v is True:  # a confirmed live, exposed secret
                by_type_live[t] += 1
                live.append((repo, t, f.get("severity", "?"), f.get("path", ""), f.get("rationale", "")))
            generic += bool(GENERIC.search(t))
            typed += not bool(GENERIC.search(t))
            m = re.search(r"\.([a-z0-9]{1,6})$", f.get("path", "").lower())
            if m:
                by_ext[m.group(1)] += 1

    per_repo.sort()
    summary = {
        "repos_scanned": repos, "repos_with_findings": with_findings, "total_findings": total,
        "typed_likely_real": typed, "generic_likely_fp": generic,
        "verify": dict(verify), "live_secrets": len(live), "live_by_type": by_type_live.most_common(),
        "by_severity": dict(by_sev),
        "top_types": by_type.most_common(25), "top_extensions": by_ext.most_common(15),
        "per_repo_max": per_repo[-1] if per_repo else 0,
        "per_repo_median": per_repo[len(per_repo) // 2] if per_repo else 0,
        "noisy_repos_gt50": len(noisy),
    }
    if args.json:
        print(json.dumps(summary, indent=2))
        return

    print(f"repos scanned: {repos} | with findings: {with_findings} | total findings: {total}")
    pct = 100 * generic / total if total else 0
    print(f"  typed (likely real): {typed}  |  generic catch-all (likely FP/noise): {generic} ({pct:.0f}%)")
    print(f"  verification: {dict(verify)}")

    # the headline: confirmed-live exposed secrets (the actionable ones — disclose, do not exploit)
    print(f"\n=== LIVE exposed secrets: {len(live)} (verified by the provider) ===")
    for t, c in by_type_live.most_common():
        print(f"  {c:5} {t}")
    for repo, t, sev, path, why in live[:40]:
        print(f"    [{sev}] {t}  {repo}  {path}  — {why[:60]}")
    if len(live) > 40:
        print(f"    … and {len(live) - 40} more (see findings/*.json)")
    print("\nby severity:", dict(by_sev))
    print("\ntop finding types:")
    for t, c in by_type.most_common(25):
        tag = "  (generic/FP)" if GENERIC.search(t) else ""
        print(f"  {c:8} {t}{tag}")
    print("\ntop file extensions:")
    for e, c in by_ext.most_common(15):
        print(f"  {c:8} .{e}")
    if per_repo:
        print(f"\nper-repo findings: max={per_repo[-1]} median={per_repo[len(per_repo)//2]} "
              f"mean={sum(per_repo)/len(per_repo):.1f} | noisy(>50): {len(noisy)}")
        for name, c in sorted(noisy, key=lambda x: -x[1])[:10]:
            print(f"    {c:6} {name}")


if __name__ == "__main__":
    main()
