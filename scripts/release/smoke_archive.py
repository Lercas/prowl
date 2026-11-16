"""Execute a verified snapshot archive on its native CI runner, without rebuilding."""

import argparse
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile

# Isolated Python omits the script directory from the import path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_artifacts import verify


def require_host(os_name, arch):
    system = {"Linux": "linux", "Darwin": "darwin", "Windows": "windows"}.get(platform.system())
    machine = {"amd64": "amd64", "x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(platform.machine().lower())
    if (system, machine) != (os_name, arch):
        raise ValueError(f"native runner mismatch: expected {os_name}/{arch}, got {system}/{machine}")


def smoke(directory, version, os_name, arch):
    require_host(os_name, arch)
    verify(directory)
    extension = "zip" if os_name == "windows" else "tar.gz"
    # Select only an already verified, checksummed name; never interpolate a path.
    candidates = [path for path in directory.iterdir()
                  if path.name == f"prowl_{version}_{os_name}_{arch}.{extension}"]
    if len(candidates) != 1:
        raise ValueError("expected snapshot version is absent")
    archive_path = candidates[0]
    executable = "prowl.exe" if os_name == "windows" else "prowl"
    root = Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix="prowl-archive-smoke-") as temporary:
        working = Path(temporary)
        binary = working / executable
        # Extract only the verified executable member, never archive paths.
        if extension == "zip":
            with zipfile.ZipFile(archive_path) as archive, archive.open(executable) as source, binary.open("xb") as destination:
                shutil.copyfileobj(source, destination)
        else:
            with tarfile.open(archive_path) as archive, archive.extractfile(executable) as source, binary.open("xb") as destination:
                shutil.copyfileobj(source, destination)
        if os_name != "windows":
            binary.chmod(0o700)
        env = dict(os.environ, PROWL_HOME=str(working / "home"))
        result = subprocess.run([str(binary), "version", "--bundled"], cwd=working,
                                env=env, capture_output=True, text=True, timeout=30, check=True)
        if result.stdout.splitlines()[0] != f"prowl {version}":
            raise ValueError("archive executable reports a different version")
        subprocess.run([sys.executable, "-I", str(root / "scripts/ml/smoke_static.py"),
                        "--binary", str(binary), "--legacy-model",
                        str(root / "tool/internal/mlmodel/model_binary.json")],
                       cwd=working, env=env, check=True, timeout=90)
        subprocess.run([str(binary), "selftest", "--ml"], cwd=working, env=env,
                       check=True, timeout=90)
    print(f"Native archive runtime: {os_name}/{arch} {version}: OK")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--os", choices=("linux", "darwin", "windows"), required=True)
    parser.add_argument("--arch", choices=("amd64", "arm64"), required=True)
    args = parser.parse_args()
    smoke(args.directory.resolve(), args.version, args.os, args.arch)
