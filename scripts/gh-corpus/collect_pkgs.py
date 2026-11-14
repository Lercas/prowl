#!/usr/bin/env python3
"""Collect recent npm + PyPI package contents into a candidates dir for Prowl scanning.

Packages are where keys actually stay LIVE: registries are not covered by GitHub's secret-scanning
partner program, so an accidentally-published .env survives. Records package+version+url provenance so a
live key can be reported to the PROVIDER (and the registry / author privately) — never via a public issue.

  ./collect_pkgs.py --pypi 200 --npm 200 -o /tmp/cand_pkgs

candidates/ holds RAW leaked keys — never commit it.
"""
import argparse
import hashlib
import io
import json
import os
import re
import tarfile
import urllib.request
import xml.etree.ElementTree as ET


# safe_name maps an arbitrary prefix+member to a collision-free on-disk filename: sanitized + a hash of
# the FULL original, so two distinct members never overwrite each other or share a manifest "file" key
# (which would misattribute a live key to the wrong source on disclosure).
def safe_name(s, cap=190):
    h = hashlib.sha1(s.encode("utf-8", "ignore")).hexdigest()[:10]
    return re.sub(r"[^A-Za-z0-9._-]", "__", s)[: cap - 11] + "__" + h

TEXT_EXT = re.compile(r"\.(env|js|jsx|ts|tsx|py|json|ya?ml|toml|ini|cfg|conf|sh|rb|go|java|properties|txt|md|xml|php|cs)$", re.I)
SKIP = re.compile(r"node_modules/|/dist/|/build/|\.min\.js|/vendor/|/test/fixtures/", re.I)


def get(url, max_bytes=30_000_000):
    # read fully (truncating a tarball corrupts the gzip); skip anything over the cap rather than truncate
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "prowl-research"})
        with urllib.request.urlopen(req, timeout=25) as r:
            data = r.read(max_bytes + 1)
        return None if len(data) > max_bytes else data
    except Exception:
        return None


def extract_zip(body, out, prefix, man, src, pkg, version, url, max_files=40, cap=1_000_000):
    import zipfile
    try:
        zf = zipfile.ZipFile(io.BytesIO(body))
        names = zf.namelist()
    except Exception:
        return 0
    n = 0
    for nm in names:
        if n >= max_files:
            break
        try:
            info = zf.getinfo(nm)
        except Exception:
            continue
        if info.is_dir() or info.file_size > cap or SKIP.search(nm):
            continue
        if not (TEXT_EXT.search(nm) or nm.startswith(".") or "/." in nm):
            continue
        try:
            data = zf.read(nm)[:cap]
        except Exception:
            continue
        name = safe_name(f"{prefix}__{nm}")
        with open(os.path.join(out, name), "wb") as f:
            f.write(data)
        man.write(json.dumps({"source": src, "package": pkg, "version": version, "url": url, "file": name}) + "\n")
        n += 1
    return n


def extract_tgz(body, out, prefix, man, src, pkg, version, url, max_files=40, cap=1_000_000):
    try:
        tf = tarfile.open(fileobj=io.BytesIO(body), mode="r:*")
        members = tf.getmembers()
    except Exception:
        return 0
    n = 0
    for m in members:
        if n >= max_files or not m.isfile() or m.size > cap:
            continue
        if SKIP.search(m.name) or not (TEXT_EXT.search(m.name) or "/." in m.name or m.name.startswith(".")):
            continue
        try:
            data = tf.extractfile(m).read(cap)
        except Exception:
            continue
        name = safe_name(f"{prefix}__{m.name}")
        with open(os.path.join(out, name), "wb") as f:
            f.write(data)
        man.write(json.dumps({"source": src, "package": pkg, "version": version, "url": url, "file": name}) + "\n")
        n += 1
    return n


def pypi(limit, out, man):
    body = get("https://pypi.org/rss/updates.xml")
    if not body:
        return 0
    names = []
    for it in ET.fromstring(body).iter("item"):
        t = it.findtext("title") or ""
        if " " in t:
            names.append(t.split(" ")[0])
    total = 0
    for pkg in names[:limit]:
        meta = get(f"https://pypi.org/pypi/{pkg}/json")
        if not meta:
            continue
        try:
            d = json.loads(meta)
            ver = d["info"]["version"]
            sdist = next((u["url"] for u in d["urls"] if u["packagetype"] == "sdist"), None)
            wheel = next((u["url"] for u in d["urls"] if u["packagetype"] == "bdist_wheel"), None)
        except Exception:
            continue
        purl = d["info"]["package_url"]
        if sdist and (body := get(sdist)):
            total += extract_tgz(body, out, f"pypi__{pkg}", man, "pypi", pkg, ver, purl)
        elif wheel and (body := get(wheel)):  # wheel = zip; many packages ship no sdist
            total += extract_zip(body, out, f"pypi__{pkg}", man, "pypi", pkg, ver, purl)
    return total


def npm(limit, out, man):
    total = 0
    seeds = ["api", "client", "config", "sdk", "bot", "deploy", "test", "server", "auth", "data"]
    seen = set()
    per = max(limit // len(seeds), 10)
    for seed in seeds:
        meta = get(f"https://registry.npmjs.org/-/v1/search?text={seed}&size={per}")
        if not meta:
            continue
        for obj in json.loads(meta).get("objects", []):
            p = obj["package"]
            name, ver = p["name"], p["version"]
            if name in seen:
                continue
            seen.add(name)
            tb = p.get("links", {}).get("npm")
            reg = get(f"https://registry.npmjs.org/{name.replace('/', '%2f')}/{ver}")
            if not reg:
                continue
            try:
                tarball = json.loads(reg)["dist"]["tarball"]
            except Exception:
                continue
            body = get(tarball)
            if body:
                total += extract_tgz(body, out, f"npm__{name}", man, "npm", name, ver,
                                     f"https://www.npmjs.com/package/{name}/v/{ver}")
    return total


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pypi", type=int, default=0)
    ap.add_argument("--npm", type=int, default=0)
    ap.add_argument("-o", "--out", default="/tmp/cand_pkgs")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    man = open(os.path.join(a.out, "manifest.jsonl"), "a")
    np = pypi(a.pypi, a.out, man) if a.pypi else 0
    nn = npm(a.npm, a.out, man) if a.npm else 0
    man.close()
    print(f"extracted files -> {a.out}/  (pypi files: {np}, npm files: {nn})")


if __name__ == "__main__":
    main()
