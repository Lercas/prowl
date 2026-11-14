"""Run the real release config into a new snapshot directory, without publication or deletion."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--version", default="0.0.0-ci")
    args = parser.parse_args()
    destination = args.dist.absolute()
    if destination.exists() or destination.is_symlink():
        raise SystemExit("snapshot destination must not already exist")
    root = Path(__file__).resolve().parents[2]
    config = (root / "tool/.goreleaser.yaml").read_text()
    if config.count("\ndist: dist\n") != 1:
        raise SystemExit("unexpected release dist configuration")
    # dist does not support GoReleaser templates. Only this output directory is
    # changed; build, archive, SBOM and checksum settings remain the real config.
    config = config.replace("\ndist: dist\n", f"\ndist: {json.dumps(str(destination))}\n", 1)
    temporary = Path(tempfile.mkdtemp(prefix="prowl-snapshot-config-")) / "goreleaser.yaml"
    temporary.write_text(config)
    subprocess.run(["goreleaser", "release", "--config", str(temporary), "--snapshot",
                    "--skip=sign", "--parallelism", "2"], cwd=root / "tool", check=True,
                   env=dict(os.environ, PROWL_SNAPSHOT_VERSION=args.version))


if __name__ == "__main__":
    main()
