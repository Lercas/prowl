#!/usr/bin/env python3
"""Aggregate per-target Prowl JSONs (one per Docker image / repo) into live AI/cloud keys by provider.

The source (image ref or repo) is the JSON filename, so a live key maps straight to its target for
provider disclosure.

  ./analyze_multi.py /tmp/docker_scan --disclose /tmp/live_docker.json
"""
import argparse
import glob
import hashlib
import json
import os
from collections import Counter


def value_key(f):
    # path-independent dedup identity: hash(type + full value). prowl's `fingerprint` mixes in the path, so
    # the same key in two images/repos would not collapse; the raw value (redacted under --show-secrets) does.
    val = f.get("redacted", "")
    return hashlib.sha256((f.get("type", "") + "\x00" + val).encode()).hexdigest() if val else ""

PROV = {
    "anthropic_api_key": "anthropic", "openai_api_key": "openai",
    "google_api_key": "google", "google-gemini-api-key": "google",
    "gcp-service-account-private-key-id": "google", "aws-access-key-id": "aws",
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("--disclose")
    ap.add_argument("--seen", help="append-only ledger of disclosed fingerprints — dedup across targets/batches")
    a = ap.parse_args()

    seen_fp = {ln.strip() for ln in open(a.seen)} if a.seen and os.path.exists(a.seen) else set()
    agg = Counter()
    live = []
    targets = 0
    for fp in glob.glob(os.path.join(a.dir, "*.json")):
        targets += 1
        src = os.path.basename(fp)[:-5]  # image ref / repo (with __ for / and :)
        try:
            F = json.load(open(fp))["findings"]
        except Exception:
            continue
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
            vk = value_key(f)  # path-independent full-value identity; collapses the same key across targets
            if not vk or vk in seen_fp:
                continue
            seen_fp.add(vk)
            agg[(prov, "live")] += 1  # count AFTER dedup so live-rate matches the disclosure list
            live.append({"provider": prov, "type": f.get("type"), "source": src, "value_hash": vk,
                         "path": f.get("path", ""), "key": val})

    print(f"targets scanned: {targets}")
    print("=== AI/cloud keys by provider × verify ===")
    for p in sorted({k[0] for k in agg}):
        l, d, u = agg[(p, "live")], agg[(p, "dead")], agg[(p, "unverif")]
        print(f"  {p:10} live={l:<4} dead={d:<4} unverified={u:<5} (live-rate {100*l/max(l+d+u,1):.1f}%)")
    print(f"\n=== LIVE exposed keys: {len(live)} ===")
    for L in live:
        k = L["key"]
        print(f"  [{L['provider']}] {L['source']}  {(k[:8]+'…'+k[-4:]) if len(k)>14 else '***'}  ({L['path']})")
    if a.disclose and live:
        json.dump(live, open(a.disclose, "w"), indent=2)
        print(f"\n  PRIVATE disclosure -> {a.disclose} (full keys) — report to providers, never commit/post")
    if a.seen and live:
        with open(a.seen, "a") as sf:
            sf.writelines(L["value_hash"] + "\n" for L in live)


if __name__ == "__main__":
    main()
