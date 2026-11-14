import unittest

from homebrew import formula


class FormulaTests(unittest.TestCase):
    def checksums(self):
        return "\n".join(f"{'a' * 64}  prowl_1.5.0_{os_name}_{arch}.tar.gz"
                         for os_name in ("darwin", "linux") for arch in ("amd64", "arm64"))

    def test_all_platforms_use_release_archives(self):
        rendered = formula("v1.5.0", self.checksums())
        self.assertEqual(rendered.count("      url "), 4)
        self.assertIn('version "1.5.0"', rendered)
        self.assertIn('bin.install "prowl"', rendered)

    def test_missing_platform_duplicate_or_unsafe_input_fails(self):
        for bad in (self.checksums().splitlines()[0], self.checksums() + "\n" + self.checksums(),
                    f"{'a' * 64}  ../prowl.tar.gz", "invalid"):
            with self.assertRaises(ValueError):
                formula("v1.5.0", bad)
        with self.assertRaises(ValueError):
            formula('v1.5.0"; system("invalid")', self.checksums())


if __name__ == "__main__":
    unittest.main()
