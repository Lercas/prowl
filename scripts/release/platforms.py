"""Select exactly the two published Linux platform manifests, excluding attestations."""

import json
from pathlib import Path
import re
import sys


def platforms(index):
    result = {}
    for manifest in index["manifests"]:
        platform = manifest.get("platform", {})
        if platform.get("os") != "linux":
            continue
        arch = platform.get("architecture")
        digest = manifest["digest"]
        if arch not in ("amd64", "arm64") or arch in result or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("unexpected or duplicate Linux platform manifest")
        result[arch] = digest
    if set(result) != {"amd64", "arm64"}:
        raise ValueError("both Linux platform manifests are required")
    return result


if __name__ == "__main__":
    for arch, digest in sorted(platforms(json.loads(Path(sys.argv[1]).read_text())).items()):
        print(arch, digest)
