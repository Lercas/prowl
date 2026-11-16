"""Verify complete downloaded or snapshot release contents; signatures are checked by cosign first."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import tarfile
import zipfile


MAX_BINARY_HEADER = 64 << 10


def verify_binary_header(header, os_name, arch):
    """Bind the expected executable container and 64-bit machine, without executing it."""
    if os_name not in ("linux", "darwin", "windows") or arch not in ("amd64", "arm64"):
        raise ValueError("unsupported release platform")
    if os_name == "linux":
        if len(header) < 64 or header[:7] != b"\x7fELF\x02\x01\x01" or header[7] not in (0, 3):
            raise ValueError("expected little-endian ELF64 executable")
        machine = int.from_bytes(header[18:20], "little")
        if machine != {"amd64": 62, "arm64": 183}[arch]:
            raise ValueError("ELF machine does not match archive architecture")
        if int.from_bytes(header[16:18], "little") not in (2, 3) or int.from_bytes(header[20:24], "little") != 1 or int.from_bytes(header[52:54], "little") != 64:
            raise ValueError("invalid ELF64 executable header")
    elif os_name == "darwin":
        if len(header) < 32 or header[:4] != b"\xcf\xfa\xed\xfe":
            raise ValueError("expected a thin little-endian Mach-O 64 executable")
        if int.from_bytes(header[4:8], "little") != {"amd64": 0x01000007, "arm64": 0x0100000c}[arch]:
            raise ValueError("Mach-O CPU does not match archive architecture")
        if int.from_bytes(header[12:16], "little") != 2:
            raise ValueError("Mach-O is not an executable")
    else:
        if len(header) < 64 or header[:2] != b"MZ":
            raise ValueError("expected a PE32+ executable")
        offset = int.from_bytes(header[60:64], "little")
        if offset < 64 or offset + 24 > len(header) or offset + 24 > MAX_BINARY_HEADER or header[offset:offset + 4] != b"PE\0\0":
            raise ValueError("invalid or oversized PE header offset")
        if int.from_bytes(header[offset + 4:offset + 6], "little") != {"amd64": 0x8664, "arm64": 0xaa64}[arch]:
            raise ValueError("PE machine does not match archive architecture")
        optional_size = int.from_bytes(header[offset + 20:offset + 22], "little")
        characteristics = int.from_bytes(header[offset + 22:offset + 24], "little")
        optional = offset + 24
        if not characteristics & 2 or characteristics & 0x2000 or optional_size < 112 or optional + optional_size > len(header) or optional + optional_size > MAX_BINARY_HEADER:
            raise ValueError("invalid PE executable or optional header")
        if int.from_bytes(header[optional:optional + 2], "little") != 0x20b or int.from_bytes(header[optional + 68:optional + 70], "little") != 3:
            raise ValueError("expected a PE32+ console executable")


def verify_archive(path, extension, executable, os_name, arch):
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
                if entry.filename == executable:
                    with archive.open(entry) as binary:
                        verify_binary_header(binary.read(MAX_BINARY_HEADER), os_name, arch)
    else:
        with tarfile.open(path) as archive:
            for entry in archive:
                member(entry.name, entry.isfile(), entry.isdir(), entry.size)
                if entry.name == executable:
                    if not entry.mode & 0o111:
                        raise ValueError("archive binary lacks executable permission")
                    with archive.extractfile(entry) as binary:
                        verify_binary_header(binary.read(MAX_BINARY_HEADER), os_name, arch)
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
        verify_archive(path, extension, "prowl.exe" if os_name == "windows" else "prowl", os_name, arch)
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
