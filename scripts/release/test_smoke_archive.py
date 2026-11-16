from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from smoke_archive import require_host, smoke


class NativeArchiveTests(unittest.TestCase):
    def test_native_platform_aliases_and_foreign_architecture(self):
        for system, os_name in (("Linux", "linux"), ("Darwin", "darwin"), ("Windows", "windows")):
            for machine, arch in (("AMD64", "amd64"), ("x86_64", "amd64"), ("arm64", "arm64"), ("aarch64", "arm64")):
                with self.subTest(system=system, machine=machine), patch("smoke_archive.platform.system", return_value=system), patch("smoke_archive.platform.machine", return_value=machine):
                    require_host(os_name, arch)
                    with self.assertRaisesRegex(ValueError, "runner mismatch"):
                        require_host(os_name, "arm64" if arch == "amd64" else "amd64")

    def test_foreign_host_never_verifies_or_executes(self):
        with patch("smoke_archive.platform.system", return_value="Windows"), patch("smoke_archive.platform.machine", return_value="AMD64"), patch("smoke_archive.verify") as verify, patch("smoke_archive.subprocess.run") as run:
            with self.assertRaisesRegex(ValueError, "runner mismatch"):
                smoke(Path("unused"), "0.0.0-ci", "linux", "amd64")
            verify.assert_not_called()
            run.assert_not_called()

    def test_invalid_checksums_prevent_extraction_and_execution(self):
        with tempfile.TemporaryDirectory() as directory, patch("smoke_archive.require_host"), patch("smoke_archive.subprocess.run") as run, patch("smoke_archive.tarfile.open") as archive:
            root = Path(directory)
            (root / "checksums.txt").write_text("0" * 64 + "  prowl_0.0.0-ci_linux_amd64.tar.gz\n")
            (root / "prowl_0.0.0-ci_linux_amd64.tar.gz").write_bytes(b"corrupt archive")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                smoke(root, "0.0.0-ci", "linux", "amd64")
            archive.assert_not_called()
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
