import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

from platforms import platforms
from verify_artifacts import verify, verify_checksums, verify_sbom


class ArtifactTests(unittest.TestCase):
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
                                archive.writestr(member, b"fixture")
                    else:
                        with tarfile.open(root / name, "w:gz") as archive:
                            for member in members:
                                info = tarfile.TarInfo(member)
                                info.size = len(b"fixture")
                                archive.addfile(info, io.BytesIO(b"fixture"))
                    (root / (name + ".spdx.json")).write_bytes(sbom)
                    for asset in (name, name + ".spdx.json"):
                        checksums.append(f"{hashlib.sha256((root / asset).read_bytes()).hexdigest()}  {asset}")
            (root / "checksums.txt").write_text("\n".join(checksums))
            verify(root)
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
