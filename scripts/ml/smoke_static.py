"""Exercise release-style embedded ML without user configuration or provider calls."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--legacy-model", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    legacy = args.legacy_model.resolve() if args.legacy_model else None
    with tempfile.TemporaryDirectory(prefix="prowl-static-ml-") as tmp:
        root = Path(tmp)
        source = root / "production.env"
        source.write_text('aws_access_key_id = "AKIA4MNQ2RST7UVWX9YZ"\n')
        env = dict(os.environ, PROWL_HOME=str(root / "home"))
        command = [str(binary), "scan", str(source), "--ml", "--format", "json"]
        result = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            raise SystemExit(f"Static embedded ML failed (exit {result.returncode}): {result.stderr}")
        report = json.loads(result.stdout)
        assert not report.get("truncated"), "smoke scan is incomplete"
        assert any(f["type"] == "aws_access_key_id" for f in report["findings"]), "typed candidate lost"
        assert "AKIA4MNQ2RST7UVWX9YZ" not in result.stdout, "default output exposed the value"
        if legacy:
            incompatible = subprocess.run(command + ["--ml-model", str(legacy)], cwd=root, env=env,
                                          capture_output=True, text=True, timeout=30)
            assert incompatible.returncode == 2, "legacy zlib model was accepted"
            assert "retrain" in incompatible.stderr, "missing actionable migration error"
    print("Static embedded ML scan, redaction and legacy-model rejection: OK")


if __name__ == "__main__":
    main()
