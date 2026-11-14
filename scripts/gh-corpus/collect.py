#!/usr/bin/env python3
"""Collect N recent public GitHub repos (clone URLs) into a list for a Prowl scanning corpus.

Uses the GitHub Search API (via `gh api`) sorted by most-recently-pushed. The Search API caps a single
query at 1000 results, so we page backward through `pushed:<cursor>` date windows to reach N.

  ./collect.py -n 5000 -o repos.txt        # needs `gh auth login` (token raises the search rate limit)
"""
import argparse
import json
import subprocess
import sys
import time


def gh_search(query, page, retries=5):
    # the Search API has a strict secondary rate limit; back off and retry rather than abort the run
    for attempt in range(retries):
        r = subprocess.run(
            ["gh", "api", "-X", "GET", "search/repositories",
             "-f", f"q={query}", "-f", "sort=updated", "-f", "order=desc",
             "-f", "per_page=100", "-f", f"page={page}"],
            capture_output=True, text=True)
        if r.returncode == 0:
            try:
                return json.loads(r.stdout)
            except json.JSONDecodeError:
                pass
        wait = 15 * (attempt + 1)
        sys.stderr.write(f"  search retry {attempt+1}/{retries} (p{page}) in {wait}s: {r.stderr[:120].strip()}\n")
        time.sleep(wait)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", "--count", type=int, default=5000)
    ap.add_argument("-o", "--out", default="repos.txt")
    ap.add_argument("--min-size", type=int, default=10, help="skip repos smaller than this (KB)")
    ap.add_argument("--query", default="is:public fork:false", help="extra search qualifiers")
    args = ap.parse_args()

    seen = set()
    cursor = None  # pushed-date upper bound, moved backward each window
    with open(args.out, "w") as f:
        while len(seen) < args.count:
            q = f"{args.query} size:>={args.min_size}"
            if cursor:
                q += f" pushed:<{cursor}"
            oldest = None
            before = len(seen)
            for page in range(1, 11):  # up to 1000 per date window
                data = gh_search(q, page)
                if not data or not data.get("items"):
                    break
                for r in data["items"]:
                    name = r["full_name"]
                    if name not in seen:
                        seen.add(name)
                        f.write(r["clone_url"] + "\n")
                        oldest = r["pushed_at"]
                        if len(seen) >= args.count:
                            break
                if len(seen) >= args.count:
                    break
                time.sleep(2)  # stay under the 30 req/min search limit
            if len(seen) == before or not oldest:
                break  # no progress / exhausted
            cursor = oldest
            sys.stderr.write(f"  collected {len(seen)} (cursor {cursor})\n")
    print(f"collected {len(seen)} repos -> {args.out}")


if __name__ == "__main__":
    main()
