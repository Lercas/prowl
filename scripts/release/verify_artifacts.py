"""Verify complete downloaded or snapshot release contents; signatures are checked by cosign first."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import tarfile
import zipfile


def verify_archive(path, extension, executable):
    required = {executable, "README.md", "README.ru.md", "LICENSE", "docs/README.md"}
    seen = set()

    def member(name, regular, directory, size):
        canonical = "docs" if name in ("docs", "docs/") else name
        if canonical in seen:
            raise ValueError(f"duplicate archive member: {name}")
        seen.add(canonical)
        if canonical == "docs":
            if not directory or size != 0:
                raise ValueError("docs archive member must be an empty directory")
        elif name in required:
            if not regular or directory or size <= 0:
                raise ValueError(f"required archive member must be a nonempty regular file: {name}")
        else:
            raise ValueError(f"unexpected archive member: {name}")

    if extension == "zip":
        with zipfile.ZipFile(path) as archive:
            for entry in archive.infolist():
                mode = stat.S_IFMT(entry.external_attr >> 16)
                directory = entry.is_dir() or mode == stat.S_IFDIR or bool(entry.external_attr & 0x10)
                member(entry.filename, mode in (0, stat.S_IFREG) and not directory,
                       directory and mode in (0, stat.S_IFDIR), entry.file_size)
    else:
        with tarfile.open(path) as archive:
            for entry in archive:
                member(entry.name, entry.isfile(), entry.isdir(), entry.size)
    if not required <= seen:
        raise ValueError(f"incomplete archive: {path.name}")


def verify_checksums(root, name):
    files = set()
    for line in (root / name).read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^/\\\s]+)", line)
        if not match or match[2] in files:
            raise ValueError("invalid or duplicate checksum entry")
        path = root / match[2]
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"missing or linked release asset: {match[2]}")
        with path.open("rb") as asset:
            digest = hashlib.file_digest(asset, "sha256").hexdigest()
        if digest != match[1]:
            raise ValueError(f"checksum mismatch: {match[2]}")
        files.add(match[2])
    if not files:
        raise ValueError("empty checksum list")
    return files


def verify_sbom(path):
    document = json.loads(path.read_text())
    packages = {package["name"] for package in document.get("packages", [])}
    if not document.get("spdxVersion", "").startswith("SPDX-"):
        raise ValueError(f"not an SPDX document: {path.name}")
    if not {"github.com/Lercas/prowl/tool", "github.com/klauspost/compress"} <= packages:
        raise ValueError(f"SBOM does not inventory Prowl and its portable compressor: {path.name}")


def verify(root, image_sboms=False):
    files = verify_checksums(root, "checksums.txt")
    platforms = set()
    versions = set()
    expected_files = set()
    for name in sorted(files):
        match = re.fullmatch(r"prowl_(.+)_(darwin|linux|windows)_(amd64|arm64)\.(tar\.gz|zip)", name)
        if not match:
            continue
        version, os_name, arch, extension = match.groups()
        if (os_name == "windows") != (extension == "zip") or (os_name, arch) in platforms:
            raise ValueError("unexpected or duplicate platform archive")
        platforms.add((os_name, arch))
        versions.add(version)
        path = root / name
        verify_archive(path, extension, "prowl.exe" if os_name == "windows" else "prowl")
        sbom = name + ".spdx.json"
        if sbom not in files:
            raise ValueError(f"SBOM is not checksum-protected: {sbom}")
        verify_sbom(root / sbom)
        expected_files.update((name, sbom))
    if platforms != {(os_name, arch) for os_name in ("linux", "darwin", "windows") for arch in ("amd64", "arm64")} or len(versions) != 1:
        raise ValueError("expected six archives of one version")
    if files != expected_files:
        raise ValueError("unexpected checksummed release asset")
    if image_sboms:
        image_files = verify_checksums(root, "prowl-image-checksums.txt")
        expected = {"prowl-image-digest.txt", "prowl-image-linux-amd64.spdx.json", "prowl-image-linux-arm64.spdx.json"}
        if image_files != expected:
            raise ValueError("incomplete image checksum list")
        digest = (root / "prowl-image-digest.txt").read_text().strip()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("invalid image digest")
        for arch in ("amd64", "arm64"):
            verify_sbom(root / f"prowl-image-linux-{arch}.spdx.json")
    print(f"Verified six archives, six SBOMs and checksums (version {versions.pop()})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--image-sboms", action="store_true")
    args = parser.parse_args()
    verify(args.directory, args.image_sboms)
