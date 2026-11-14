#!/usr/bin/env python3
"""Qualify source scopes and policy diagnostics with owned local acquisitions."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    root = Path(tempfile.mkdtemp(prefix="prowl-source-coverage-native-"))
    (root / "home").mkdir()
    env = dict(os.environ, PROWL_HOME=str(root / "home"))
    value = "AKIANAFGYOEYPXU1DSYP"
    payload = ("AWS=" + value + "\n").encode()
    repo = root / "repo"
    repo.mkdir()
    for args in (["init", "-q"], ["config", "user.email", "fixture@example.invalid"],
                 ["config", "user.name", "Owned Fixture"], ["config", "core.hooksPath", "/dev/null"]):
        subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)
    (repo / "input.env").write_bytes(payload)
    subprocess.run(["git", "add", "input.env"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "owned fixture"], cwd=repo, check=True)
    (repo / "input.env").write_bytes(payload * 2)
    subprocess.run(["git", "add", "input.env"], cwd=repo, check=True)
    (repo / "asset.png").write_bytes(b"unsupported extension")
    (repo / "binary.env").write_bytes(b"\x00\x00\x00")
    (repo / "node_modules").mkdir()
    (repo / "link.env").symlink_to("input.env")
    agent = root / "agent"
    agent.mkdir()
    (agent / ".mcp.json").write_text(json.dumps({"key": value}))
    with zipfile.ZipFile(root / "app.apk", "w") as archive:
        archive.writestr("config.txt", payload)
        archive.writestr("icon.png", b"ignored asset")
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w") as archive:
        header = tarfile.TarInfo("prod.env")
        header.size = len(payload)
        archive.addfile(header, io.BytesIO(payload))
    layer_bytes = layer.getvalue()
    config = json.dumps(dict(architecture="amd64", os="linux", config={},
                             rootfs=dict(type="layers", diff_ids=["sha256:" + hashlib.sha256(layer_bytes).hexdigest()]),
                             history=[dict(created_by="owned fixture")])).encode()
    manifest = json.dumps([dict(Config="config.json", RepoTags=["owned:fixture"], Layers=["layer.tar"])]).encode()
    with tarfile.open(root / "image.tar", "w") as archive:
        for name, data in [("config.json", config), ("manifest.json", manifest), ("layer.tar", layer_bytes)]:
            header = tarfile.TarInfo(name)
            header.size = len(data)
            archive.addfile(header, io.BytesIO(data))
    cases = [
        ("filesystem-policy", repo, ["scan", ".", "--exclude=binary.env"], "filesystem", True,
         {"excluded_path", "unsupported_extension", "excluded_directory", "symlink"}),
        ("index", repo, ["scan", "--staged"], "git-index", True, set()),
        ("worktree", repo, ["scan", "--since=HEAD"], "git-worktree", True, set()),
        ("history", repo, ["scan", "--history"], "git-history", True, set()),
        ("timeline", repo, ["scan", "--git-timeline"], "git-timeline", True, set()),
        ("mobile", root, ["mobile", "app.apk"], "mobile", True, {"unsupported_mobile_entry"}),
        ("mobile-limit", root, ["mobile", "app.apk", "--max-size=8"], "mobile", False, set()),
        ("image", root, ["image", "image.tar", "--image-input=tar"], "image", True, set()),
        ("agents", root, ["agents", str(agent)], "agent-project", True, set()),
    ]
    checks = []
    for name, cwd, args, kind, complete, codes in cases:
        for stored in (False, True):
            scopes = None
            for fmt in ("json", "sarif"):
                output = root / ("report-" + str(len(checks)))
                flags = ["--silence", "--format=" + fmt]
                if stored:
                    flags.append("--output=" + str(output))
                result = subprocess.run([str(binary), *args, *flags], cwd=cwd, env=env,
                                        capture_output=True, timeout=30)
                data = output.read_bytes() if stored else result.stdout
                report = json.loads(data)
                meta = report if fmt == "json" else report["runs"][0]["properties"]
                ok = (result.returncode == (0 if complete else 2) and meta["complete"] == complete
                      and kind in {s["kind"] for s in meta["scope"]}
                      and codes <= {d["code"] for d in meta["diagnostics"]}
                      and all(len(s["policy"]) == 64 for s in meta["scope"])
                      and value.encode() not in data)
                if fmt == "sarif":
                    ok = ok and meta["scope"] == scopes
                else:
                    scopes = meta["scope"]
                checks.append(dict(case=name, stored=stored, format=fmt, passed=bool(ok)))
    report = dict(binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  passed=sum(c["passed"] for c in checks), total=len(checks), checks=checks)
    path = root / "qualification.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(dict(report=str(path), passed=report["passed"], total=report["total"],
                          failures=[c for c in checks if not c["passed"]])))
    return int(report["passed"] != report["total"])


if __name__ == "__main__":
    raise SystemExit(main())
