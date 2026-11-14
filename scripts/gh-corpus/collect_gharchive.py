#!/usr/bin/env python3
"""Collect recently-pushed repos from GH Archive (data.gharchive.org) — NO GitHub REST-API rate limit.

Streams one hourly public event archive (gzip), extracts unique PushEvent repos as clone URLs. Content is
then scanned by cloning (git protocol, also not the REST API), so the GitHub API budget is left entirely to
the real-time watcher. GH Archive lags ~1-2h, so use --hours-ago >= 2.

  ./collect_gharchive.py --hours-ago 3 -n 150 -o /tmp/gha_repos.txt
"""
import argparse
import gzip
import json
import sys
import urllib.request
from datetime import datetime, timedelta, timezone


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours-ago", type=int, default=3)
    ap.add_argument("-n", "--max-repos", type=int, default=150)
    ap.add_argument("-o", "--out", default="/tmp/gha_repos.txt")
    a = ap.parse_args()
    t = datetime.now(timezone.utc) - timedelta(hours=a.hours_ago)
    url = f"https://data.gharchive.org/{t.year:04d}-{t.month:02d}-{t.day:02d}-{t.hour}.json.gz"
    repos, seen = [], set()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "prowl-research"})
        with urllib.request.urlopen(req, timeout=90) as resp:
            for line in gzip.GzipFile(fileobj=resp):  # stream-decompress; stop early once we have enough
                if len(repos) >= a.max_repos:
                    break
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                if e.get("type") != "PushEvent":
                    continue
                r = (e.get("repo") or {}).get("name")
                if r and r not in seen:
                    seen.add(r)
                    repos.append(f"https://github.com/{r}.git")
    except Exception as ex:
        sys.stderr.write(f"gharchive fetch failed ({url}): {ex}\n")
        return 1
    with open(a.out, "w") as f:
        f.write("\n".join(repos) + "\n")
    print(f"{len(repos)} repos from {url} -> {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
