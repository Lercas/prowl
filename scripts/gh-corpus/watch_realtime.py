#!/usr/bin/env python3
"""Real-time leak monitor — catch keys in the leak->revocation window.

Polls the GitHub public push-event timeline and PyPI's recent-release feed, scans freshly-pushed/published
content immediately, and validates with the full cascade. Prints one LIVE line per confirmed live key (so a
Monitor turns each into a notification) plus a periodic heartbeat. Live keys -> /tmp/live_realtime.jsonl,
to be disclosed to the PROVIDER — never posted publicly.

  PROWL=./prowl python3 watch_realtime.py
"""
import hashlib
import io
import json
import os
import subprocess
import tarfile
import tempfile
import time
import urllib.request
import xml.etree.ElementTree as ET

PROWL = os.environ.get("PROWL", "prowl")
LOG = open("/tmp/live_realtime.jsonl", "a")
LEDGER_PATH = os.environ.get("SEEN_LEDGER", "/tmp/live_realtime_seen.txt")
seen_keys = {ln.strip() for ln in open(LEDGER_PATH)} if os.path.exists(LEDGER_PATH) else set()
LEDGER = open(LEDGER_PATH, "a")  # persist disclosed fingerprints so a restart doesn't re-report the same key
seen_ev, seen_pypi = set(), set()
scanned = live = 0
t0 = time.time()


def gh(path, retries=2):
    for attempt in range(retries + 1):
        try:
            r = subprocess.run(["gh", "api", path], capture_output=True, text=True, timeout=25)
        except subprocess.TimeoutExpired:  # a hung request (huge compare diff / network hang) must not block the loop
            if attempt < retries:
                time.sleep(1.5)
                continue
            return None
        if r.returncode == 0:
            try:
                return json.loads(r.stdout)
            except Exception:
                return None
        if attempt < retries:  # transient TLS/network blip (not rate-limit) — brief retry before giving up
            time.sleep(1.5)
    return None


def http(url, cap=8_000_000):
    try:
        return urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "prowl-research"}), timeout=20).read(cap)
    except Exception:
        return None


def scan(text):
    global scanned
    if not text or not text.strip():
        return []
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write(text)
        p = f.name
    try:
        r = subprocess.run([PROWL, "scan", p, "--ml", "--verify", "--show-secrets", "--format", "json"],
                           capture_output=True, text=True)
    finally:
        os.unlink(p)  # remove the spool even if PROWL is missing / subprocess raises (no /tmp leak per poll)
    scanned += 1
    try:
        return json.loads(r.stdout).get("findings", [])
    except Exception:
        return []


def record(fnd, source, url):
    global live
    if fnd.get("verified") is not True:
        return
    k = fnd.get("redacted", "")
    # path-INDEPENDENT identity: hash(type + full value). prowl's fingerprint hashes the (random temp) path,
    # so the same key would get a new id every poll + after restart; the value does not. Ledger stores hashes.
    vk = hashlib.sha256((fnd.get("type", "") + "\x00" + k).encode()).hexdigest() if k else ""
    if not vk or vk in seen_keys:
        return
    seen_keys.add(vk)
    LEDGER.write(vk + "\n")
    LEDGER.flush()
    live += 1
    LOG.write(json.dumps({"type": fnd.get("type"), "source": source, "url": url, "key": k, "value_hash": vk}) + "\n")
    LOG.flush()
    print(f"LIVE [{fnd.get('type')}] {source} {k[:8]}…{k[-4:]} {url}", flush=True)


def poll_github(budget=8):  # 8 commits + 1 events poll per 10s ~= 3240/hr, margin under the 5000/hr limit
    used = 0
    evs = gh("events")
    if evs is None:  # rate-limited/transient — surface it (don't silently look idle) and skip this round
        print("WARN github events fetch failed (network/transient after retries), skipping this round", flush=True)
        return
    if len(seen_ev) > 100_000:  # bound memory over a multi-day run (old event ids never replay)
        seen_ev.clear()
    for ev in evs:
        if used >= budget:
            break
        if ev["id"] in seen_ev or ev.get("type") != "PushEvent":
            continue
        seen_ev.add(ev["id"])
        repo = ev["repo"]["name"]
        pl = ev.get("payload", {})
        head, before = pl.get("head"), pl.get("before")
        if not head:
            continue
        # The live /events firehose no longer inlines commits — fetch the pushed diff via compare
        # (before..head), falling back to the head commit when before is unset/all-zeros (new branch).
        if before and set(before) != {"0"}:
            diff = gh(f"repos/{repo}/compare/{before}...{head}")
        else:
            diff = gh(f"repos/{repo}/commits/{head}")
        used += 1
        if not diff:
            continue
        parts, total = [], 0
        for f in diff.get("files", []):
            if total > 1_000_000:  # bound the scanned diff — secrets live in small files, not huge generated ones
                break
            a = "\n".join(l[1:] for l in (f.get("patch") or "").splitlines()
                          if l.startswith("+") and not l.startswith("+++"))
            parts.append(a)
            total += len(a)
        added = "\n".join(parts)
        for fnd in scan(added):
            record(fnd, f"github:{repo}", f"https://github.com/{repo}/commit/{head}")


def poll_pypi():
    b = http("https://pypi.org/rss/updates.xml")
    if not b:
        return
    if len(seen_pypi) > 100_000:  # bound memory over a multi-day run
        seen_pypi.clear()
    for it in ET.fromstring(b).iter("item"):
        name = (it.findtext("title") or "").split(" ")[0]
        if not name or name in seen_pypi:
            continue
        seen_pypi.add(name)
        meta = http(f"https://pypi.org/pypi/{name}/json")
        if not meta:
            continue
        try:
            d = json.loads(meta)
            sd = next((u["url"] for u in d["urls"] if u["packagetype"] == "sdist"), None)
        except Exception:
            continue
        body = http(sd) if sd else None
        if not body:
            continue
        try:
            tf = tarfile.open(fileobj=io.BytesIO(body), mode="r:*")
            txt = "\n".join(tf.extractfile(m).read(200_000).decode("utf-8", "ignore")
                            for m in tf.getmembers()[:30] if m.isfile() and m.size < 200_000)
        except Exception:
            continue
        for fnd in scan(txt):
            record(fnd, f"pypi:{name}", d["info"]["package_url"])


print(f"watcher started (github push events + pypi releases). PROWL={PROWL}", flush=True)
last_hb = time.time()
while True:
    try:
        poll_github()
        poll_pypi()
    except Exception as e:
        print(f"WARN {type(e).__name__}: {e}", flush=True)
    if time.time() - last_hb > 3600:
        print(f"heartbeat: scanned={scanned} live={live} elapsed={int(time.time()-t0)}s", flush=True)
        last_hb = time.time()
    time.sleep(10)
