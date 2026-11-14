#!/usr/bin/env python3
"""Collect candidate files that leak AI/cloud keys via GitHub Code Search, for a Prowl validation corpus.

Searches public code for provider key markers, fetches each matching file, and records provenance
(repo, path, html_url) in a manifest so a confirmed-LIVE finding can be responsibly disclosed to the
PROVIDER (Anthropic/OpenAI/Google) — never via a public issue.

  ./collect_codesearch.py -n 300 -o candidates       # needs `gh auth login`

Code Search is capped at 10 req/min and 1000 results/query; the script paces itself.
candidates/ holds RAW leaked keys — never commit it; delete when done.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.request


# safe_name: collision-free on-disk filename (sanitized + hash of the FULL original) so two distinct
# results never overwrite each other or share a manifest "file" key (which would misattribute on disclosure).
def safe_name(s, cap=180):
    h = hashlib.sha1(s.encode("utf-8", "ignore")).hexdigest()[:10]
    return re.sub(r"[^A-Za-z0-9._-]", "__", s)[: cap - 11] + "__" + h

# high-signal markers that pin the provider (confirmed to return results via the Search API)
PATTERNS = {
    "anthropic": "sk-ant-api03",
    "openai": "sk-proj-",
    "openai_svc": "sk-svcacct-",
    "google": "AIzaSy",
}


def gh_code_search(query, page, retries=4):
    for attempt in range(retries):
        r = subprocess.run(
            ["gh", "api", "-X", "GET", "search/code", "-H", "Accept: application/vnd.github+json",
             "-f", f"q={query}", "-f", "per_page=100", "-f", f"page={page}"],
            capture_output=True, text=True)
        if r.returncode == 0:
            try:
                return json.loads(r.stdout)
            except json.JSONDecodeError:
                pass
        wait = 20 * (attempt + 1)
        sys.stderr.write(f"  code-search retry {attempt+1} (p{page}) in {wait}s: {r.stderr[:100].strip()}\n")
        time.sleep(wait)
    return None


def raw_url(item):  # html_url: https://github.com/o/r/blob/<ref>/path -> raw.githubusercontent.com
    h = item.get("html_url", "")
    return h.replace("github.com/", "raw.githubusercontent.com/", 1).replace("/blob/", "/", 1)


def fetch(url, cap=1_000_000):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "prowl-research"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.read(cap)
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", "--per-pattern", type=int, default=200)
    ap.add_argument("-o", "--out", default="/tmp/prowl-candidates")  # raw keys: keep OUT of the repo tree
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    man = open(os.path.join(args.out, "manifest.jsonl"), "a")
    seen = set()
    for prov, pat in PATTERNS.items():
        got = 0
        for page in range(1, 11):  # 1000-result cap
            if got >= args.per_pattern:
                break
            data = gh_code_search(pat, page)
            time.sleep(7)  # 10 req/min
            if data is None:  # hard failure after retries — not exhaustion; say so, results are partial
                sys.stderr.write(f"  WARN {prov} ({pat}): code-search failed after retries; results partial\n")
                break
            if not data.get("items"):
                break
            for it in data["items"]:
                repo, path = it["repository"]["full_name"], it["path"]
                key = f"{repo}/{path}"
                if key in seen:
                    continue
                seen.add(key)
                body = fetch(raw_url(it))
                if not body:
                    continue
                name = safe_name(f"{prov}__{repo}__{path}")
                with open(os.path.join(args.out, name), "wb") as f:
                    f.write(body)
                man.write(json.dumps({"provider": prov, "repo": repo, "path": path,
                                      "html_url": it.get("html_url"), "file": name}) + "\n")
                man.flush()
                got += 1
                if got >= args.per_pattern:
                    break
        sys.stderr.write(f"  {prov} ({pat}): {got} files\n")
    man.close()
    print(f"collected -> {args.out}/ (+ manifest.jsonl)")


if __name__ == "__main__":
    main()
