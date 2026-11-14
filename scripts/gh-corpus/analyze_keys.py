#!/usr/bin/env python3
"""Analyze a Code-Search candidate scan: live AI/cloud keys by provider, mapped to source for disclosure.

Attributes by the FINDING TYPE (not the search pattern), so generic noise in a candidate file is ignored.
A confirmed-LIVE key is mapped via the manifest to its repo + URL, written to a PRIVATE disclosure file
for reporting to the PROVIDER — never to a public issue.

  ./analyze_keys.py /tmp/cand_scan.json /tmp/cand/manifest.jsonl --disclose /tmp/live_disclosure.json
"""
import argparse
import hashlib
import json
import os
from collections import Counter


def value_key(f):
    # PATH-INDEPENDENT identity for dedup: hash(type + full secret value). prowl's `fingerprint` mixes in
    # the file path, so the same key in two repos/targets would NOT collapse; the raw value (which `redacted`
    # holds under --show-secrets) does. Hashed so the persisted ledger never stores raw keys at rest.
    val = f.get("redacted", "")
    return hashlib.sha256((f.get("type", "") + "\x00" + val).encode()).hexdigest() if val else ""

# finding type -> provider (the real typed AI/cloud detectors, not generic_* noise)
PROV = {
    "anthropic_api_key": "anthropic",
    "openai_api_key": "openai",
    "google_api_key": "google",
    "google-gemini-api-key": "google",
    "gcp-service-account-private-key-id": "google",
    "aws-access-key-id": "aws",
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scan", help="prowl scan JSON")
    ap.add_argument("manifest", nargs="?", help="collect manifest.jsonl (file -> repo/url)")
    ap.add_argument("--disclose", help="write full live keys + sources here (PRIVATE, never commit)")
    ap.add_argument("--seen", help="append-only ledger of disclosed fingerprints — dedup across batches")
    a = ap.parse_args()

    F = json.load(open(a.scan))["findings"]
    man = {}
    if a.manifest and os.path.exists(a.manifest):
        for line in open(a.manifest):
            d = json.loads(line)
            man[d["file"]] = d
    seen_fp = {ln.strip() for ln in open(a.seen)} if a.seen and os.path.exists(a.seen) else set()

    agg = Counter()
    live = []
    for f in F:
        prov = PROV.get(f.get("type", ""))
        v = f.get("verified")
        if not prov:
            if v is True:  # a confirmed-LIVE key of an unlisted type must NOT be dropped from disclosure
                prov = f.get("type", "unknown")
            else:
                continue
        if v is not True:
            agg[(prov, "dead" if v is False else "unverif")] += 1
            continue
        val = f.get("redacted", "")
        if "**" in val:  # masked -> scan lacked --show-secrets; can't dedup or disclose a masked key
            raise SystemExit("ERROR: findings are masked — re-run the prowl scan with --show-secrets "
                             "(disclosure + cross-target dedup need the full key value)")
        vk = value_key(f)  # path-independent full-value identity; collapses the same key across files/repos
        if not vk or vk in seen_fp:
            continue  # already disclosed this run or a prior batch — don't re-spam the provider
        seen_fp.add(vk)
        agg[(prov, "live")] += 1  # count AFTER dedup so the printed live-rate matches the disclosure list
        src = man.get(f.get("path", "").split("/")[-1], {})
        live.append({"provider": prov, "type": f.get("type"), "value_hash": vk,
                     "repo": src.get("repo", "?"), "url": src.get("html_url", "?"), "key": val})

    print("=== AI/cloud keys by provider × verify ===")
    provs = sorted({p for p, _ in agg})
    for p in provs:
        l, d, u = agg[(p, "live")], agg[(p, "dead")], agg[(p, "unverif")]
        print(f"  {p:10} live={l:<4} dead={d:<4} unverified={u:<5} (live-rate {100*l/max(l+d+u,1):.1f}%)")
    print(f"\n=== LIVE exposed keys: {len(live)} (disclose to provider, never exploit) ===")
    for L in live:
        k = L["key"]
        mask = f"{k[:8]}…{k[-4:]}" if len(k) > 14 else "***"
        print(f"  [{L['provider']}] {L['repo']}  {mask}  {L['url']}")
    if a.disclose and live:
        json.dump(live, open(a.disclose, "w"), indent=2)
        print(f"\n  PRIVATE disclosure file (FULL keys) -> {a.disclose}")
        print("  → submit to provider security channels / GitHub Secret Scanning Partner Program; never commit, never post publicly")
    if a.seen and live:
        with open(a.seen, "a") as sf:
            sf.writelines(L["value_hash"] + "\n" for L in live)


if __name__ == "__main__":
    main()
