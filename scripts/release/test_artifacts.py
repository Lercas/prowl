import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import warnings
import zipfile

from platforms import platforms
from verify_artifacts import verify, verify_checksums, verify_sbom


def executable_header(os_name, arch):
    # Minimal headers exercise the binding gate, not loader/runtime correctness.
    data = bytearray(512)
    if os_name == "linux":
        data[:7] = b"\x7fELF\x02\x01\x01"
        data[16:24] = (2).to_bytes(2, "little") + {"amd64": 62, "arm64": 183}[arch].to_bytes(2, "little") + (1).to_bytes(4, "little")
        data[52:54] = (64).to_bytes(2, "little")
    elif os_name == "darwin":
        data[:4] = b"\xcf\xfa\xed\xfe"
        data[4:8] = {"amd64": 0x01000007, "arm64": 0x0100000c}[arch].to_bytes(4, "little")
        data[12:16] = (2).to_bytes(4, "little")
    else:
        data[:2] = b"MZ"
        data[60:64] = (128).to_bytes(4, "little")
        data[128:132] = b"PE\0\0"
        data[132:134] = {"amd64": 0x8664, "arm64": 0xaa64}[arch].to_bytes(2, "little")
        data[148:150] = (240).to_bytes(2, "little")
        data[150:152] = (2).to_bytes(2, "little")
        data[152:154] = (0x20b).to_bytes(2, "little")
        data[220:222] = (3).to_bytes(2, "little")
    return bytes(data)


class ArtifactTests(unittest.TestCase):
    def test_archive_members_require_unique_regular_nonempty_files(self):
        from verify_artifacts import verify_archive

        for extension in ("tar.gz", "zip"):
            for mode in ("valid", "docs-directory", "duplicate", "directory-binary", "special-binary", "empty-binary", "file-docs", "duplicate-docs", "linked-binary", "linked-docs", "special-docs"):
                with self.subTest(extension=extension, mode=mode), tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / ("archive." + extension)
                    executable = "prowl.exe" if extension == "zip" else "prowl"
                    os_name = "windows" if extension == "zip" else "linux"
                    required = {executable, "README.md", "README.ru.md", "LICENSE", "docs/README.md"}
                    names = sorted(required)
                    if mode == "duplicate": names.append(executable)
                    if mode in ("docs-directory", "file-docs", "duplicate-docs"): names.insert(0, "docs")
                    if mode == "duplicate-docs": names.append("docs/")
                    if mode in ("linked-docs", "special-docs"): names.insert(0, "docs/")
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", UserWarning)
                        if extension == "zip":
                            with zipfile.ZipFile(path, "w") as archive:
                                for name in names:
                                    kind = 0o100000
                                    body = executable_header(os_name, "amd64") if name == executable else b"fixture"
                                    if name.rstrip("/") == "docs" and mode != "file-docs": kind, body = 0o040000, b""
                                    if name.rstrip("/") == "docs" and mode == "linked-docs": kind = 0o120000
                                    if name.rstrip("/") == "docs" and mode == "special-docs": kind = 0o010000
                                    if name == executable:
                                        if mode == "directory-binary": kind, body = 0o040000, b""
                                        if mode == "special-binary": kind = 0o010000
                                        if mode == "linked-binary": kind = 0o120000
                                        if mode == "empty-binary": body = b""
                                    info = zipfile.ZipInfo(name)
                                    info.create_system = 3
                                    info.external_attr = (kind | 0o644) << 16
                                    archive.writestr(info, body)
                        else:
                            with tarfile.open(path, "w:gz") as archive:
                                for name in names:
                                    info, body = tarfile.TarInfo(name), executable_header(os_name, "amd64") if name == executable else b"fixture"
                                    if name == executable: info.mode = 0o755
                                    if name.rstrip("/") == "docs" and mode != "file-docs": info.type, body = tarfile.DIRTYPE, b""
                                    if name.rstrip("/") == "docs" and mode == "linked-docs": info.type, info.linkname = tarfile.SYMTYPE, "elsewhere"
                                    if name.rstrip("/") == "docs" and mode == "special-docs": info.type = tarfile.FIFOTYPE
                                    if name == executable:
                                        if mode == "directory-binary": info.type, body = tarfile.DIRTYPE, b""
                                        if mode == "special-binary": info.type, body = tarfile.FIFOTYPE, b""
                                        if mode == "linked-binary": info.type, info.linkname, body = tarfile.SYMTYPE, "elsewhere", b""
                                        if mode == "empty-binary": body = b""
                                    info.size = len(body)
                                    archive.addfile(info, io.BytesIO(body))
                    if mode in ("valid", "docs-directory"):
                        verify_archive(path, extension, executable, os_name, "amd64")
                    else:
                        with self.assertRaises(ValueError): verify_archive(path, extension, executable, os_name, "amd64")

    def test_binary_headers_bind_all_six_platforms(self):
        from verify_artifacts import verify_binary_header
        for os_name in ("linux", "darwin", "windows"):
            for arch in ("amd64", "arm64"):
                other_arch = "arm64" if arch == "amd64" else "amd64"
                other_os = {"linux": "darwin", "darwin": "windows", "windows": "linux"}[os_name]
                variants = {"valid": executable_header(os_name, arch),
                            "wrong-arch": executable_header(os_name, other_arch),
                            "wrong-format": executable_header(other_os, arch),
                            "plain-text": b"not an executable", "truncated": executable_header(os_name, arch)[:20]}
                for mode, header in variants.items():
                    with self.subTest(os=os_name, arch=arch, mode=mode):
                        if mode == "valid":
                            verify_binary_header(header, os_name, arch)
                        else:
                            with self.assertRaises(ValueError): verify_binary_header(header, os_name, arch)

    def test_executable_header_variants_fail_closed(self):
        from verify_artifacts import verify_binary_header
        variants = []
        for offset, value in ((60, (0).to_bytes(4, "little")), (60, (65536).to_bytes(4, "little")),
                              (128, b"BAD!"), (148, (0).to_bytes(2, "little")),
                              (150, (0).to_bytes(2, "little")), (150, (0x2002).to_bytes(2, "little")),
                              (152, (0x10b).to_bytes(2, "little")), (220, (2).to_bytes(2, "little"))):
            body = bytearray(executable_header("windows", "amd64")); body[offset:offset + len(value)] = value
            variants.append(("windows", bytes(body)))
        for offset, value in ((4, b"\x01"), (5, b"\x02"), (7, b"\x09"), (16, b"\x01\x00"), (52, b"\x20\x00")):
            body = bytearray(executable_header("linux", "amd64")); body[offset:offset + len(value)] = value
            variants.append(("linux", bytes(body)))
        for offset, value in ((0, b"\xca\xfe\xba\xbe"), (12, (6).to_bytes(4, "little"))):
            body = bytearray(executable_header("darwin", "amd64")); body[offset:offset + len(value)] = value
            variants.append(("darwin", bytes(body)))
        for index, (os_name, body) in enumerate(variants):
            with self.subTest(os=os_name, variant=index):
                with self.assertRaises(ValueError): verify_binary_header(body, os_name, "amd64")

    def test_complete_six_platform_contract_and_missing_sbom(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checksums = []
            sbom = json.dumps({"spdxVersion": "SPDX-2.3", "packages": [
                {"name": "github.com/Lercas/prowl/tool"}, {"name": "github.com/klauspost/compress"}]}).encode()
            for os_name in ("linux", "darwin", "windows"):
                for arch in ("amd64", "arm64"):
                    extension = "zip" if os_name == "windows" else "tar.gz"
                    name = f"prowl_1.5.0_{os_name}_{arch}.{extension}"
                    members = {"prowl.exe" if os_name == "windows" else "prowl", "README.md", "README.ru.md", "LICENSE", "docs/README.md"}
                    if extension == "zip":
                        with zipfile.ZipFile(root / name, "w") as archive:
                            for member in members:
                                archive.writestr(member, executable_header(os_name, arch) if member == "prowl.exe" else b"fixture")
                    else:
                        with tarfile.open(root / name, "w:gz") as archive:
                            for member in members:
                                info = tarfile.TarInfo(member)
                                body = executable_header(os_name, arch) if member == "prowl" else b"fixture"
                                if member == "prowl": info.mode = 0o755
                                info.size = len(body)
                                archive.addfile(info, io.BytesIO(body))
                    (root / (name + ".spdx.json")).write_bytes(sbom)
                    for asset in (name, name + ".spdx.json"):
                        checksums.append(f"{hashlib.sha256((root / asset).read_bytes()).hexdigest()}  {asset}")
            (root / "checksums.txt").write_text("\n".join(checksums))
            verify(root)
            target = root / "prowl_1.5.0_linux_amd64.tar.gz"
            original = target.read_bytes()
            for mode in ("directory-binary", "duplicate-binary", "wrong-arch", "wrong-format", "nonexec-binary"):
                with self.subTest(mode=mode):
                    with tarfile.open(target, "w:gz") as archive:
                        for member in ("prowl", "README.md", "README.ru.md", "LICENSE", "docs/README.md"):
                            info = tarfile.TarInfo(member)
                            body = executable_header("linux", "amd64") if member == "prowl" else b"fixture"
                            if member == "prowl":
                                info.mode = 0o644 if mode == "nonexec-binary" else 0o755
                                if mode == "wrong-arch": body = executable_header("linux", "arm64")
                                if mode == "wrong-format": body = executable_header("darwin", "amd64")
                            if member == "prowl" and mode == "directory-binary": info.type, body = tarfile.DIRTYPE, b""
                            info.size = len(body)
                            archive.addfile(info, io.BytesIO(body))
                        if mode == "duplicate-binary":
                            info = tarfile.TarInfo("prowl")
                            info.size = len(b"replacement")
                            archive.addfile(info, io.BytesIO(b"replacement"))
                    modified = [f"{hashlib.sha256(target.read_bytes()).hexdigest()}  {target.name}" if line.endswith("  " + target.name) else line for line in checksums]
                    (root / "checksums.txt").write_text("\n".join(modified))
                    try:
                        with self.assertRaises(ValueError): verify(root)
                    finally:
                        target.write_bytes(original)
                        (root / "checksums.txt").write_text("\n".join(checksums))
            (root / "checksums.txt").write_text("\n".join(line for line in checksums if not line.endswith("windows_arm64.zip.spdx.json")))
            with self.assertRaisesRegex(ValueError, "not checksum-protected"):
                verify(root)

    def test_corrupt_duplicate_and_traversal_checksums_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "asset").write_bytes(b"actual")
            valid = f"{hashlib.sha256(b'actual').hexdigest()}  asset"
            for content in (f"{'0' * 64}  asset", valid + "\n" + valid, f"{'0' * 64}  ../asset", ""):
                (root / "checksums.txt").write_text(content)
                with self.assertRaises(ValueError):
                    verify_checksums(root, "checksums.txt")
            (root / "empty.spdx.json").write_text('{"spdxVersion":"SPDX-2.3","packages":[]}')
            with self.assertRaises(ValueError):
                verify_sbom(root / "empty.spdx.json")

    def test_platform_index_excludes_attestations_and_requires_both_architectures(self):
        manifests = [{"platform": {"os": "linux", "architecture": arch}, "digest": "sha256:" + "a" * 64}
                     for arch in ("amd64", "arm64")]
        manifests.append({"platform": {"os": "unknown", "architecture": "unknown"}, "digest": "attestation"})
        self.assertEqual(set(platforms({"manifests": manifests})), {"amd64", "arm64"})
        with self.assertRaises(ValueError):
            platforms({"manifests": manifests[:1]})
        with self.assertRaises(ValueError):
            platforms({"manifests": manifests + [manifests[0]]})


if __name__ == "__main__":
    unittest.main()
