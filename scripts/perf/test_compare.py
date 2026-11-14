"""Fail-closed checks for the corpus performance gate, without slow benchmarks."""

import json
from pathlib import Path
import tempfile
import unittest

from compare import POLICY, corpus_manifest, evaluate, parse_benchmark, validate_policy


class PerformanceGateTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads(POLICY.read_text())
        self.manifest = {"files": 12044, "bytes": 132407542}
        self.output = (
            "goos: linux\ngoarch: amd64\n"
            "BenchmarkFindingsCorpus-2 1 1000000 ns/op 132.4 MB/s 4096 B/op 12 allocs/op "
            "132407542 corpus-bytes 12044 corpus-files 9 findings/op\nPASS\n"
        )

    def test_parser_requires_complete_corpus_and_success(self):
        sample = parse_benchmark(self.output, self.manifest)
        self.assertEqual(sample["ns/op"], 1000000)
        invalid = [
            self.output.replace("PASS", "FAIL"),
            self.output.replace("BenchmarkFindingsCorpus-2", "BenchmarkOther-2"),
            self.output + self.output,
            self.output.replace("-2 1 ", "-2 2 "),
            self.output.replace("12044 corpus-files", "12043 corpus-files"),
            self.output.replace("132407542 corpus-bytes", "132407541 corpus-bytes"),
            self.output.replace("9 findings/op", "0 findings/op"),
            self.output.replace("1000000 ns/op", "NaN ns/op"),
            self.output.replace("4096 B/op", "Inf B/op"),
            self.output.replace("12 allocs/op", "-1 allocs/op"),
            self.output.replace("12 allocs/op", "12 allocs/op 10 allocs/op"),
            self.output.replace("9 findings/op", ""),
            "PASS\n", "",
        ]
        for output in invalid:
            with self.subTest(output=output), self.assertRaises(ValueError):
                parse_benchmark(output, self.manifest)

    def test_median_and_real_regressions(self):
        sample = parse_benchmark(self.output, self.manifest)
        reference = [sample.copy() for _ in range(3)]
        candidate = [sample.copy() for _ in range(3)]
        candidate[0]["ns/op"] *= 100  # One noisy sample does not set the median.
        self.assertEqual(evaluate({"reference": reference, "candidate": candidate}, self.policy)["status"], "passed")
        for metric in ("ns/op", "B/op", "allocs/op"):
            slower = [sample | {metric: sample[metric] * 1.5} for _ in range(3)]
            result = evaluate({"reference": reference, "candidate": slower}, self.policy)
            self.assertEqual(result["status"], "regression")
            self.assertIn(metric, result["regressions"])
        with self.assertRaises(ValueError):
            evaluate({"reference": reference, "candidate": candidate[:2]}, self.policy)

    def test_nonfinite_or_unpinned_policy_is_rejected(self):
        validate_policy(self.policy)
        for key, value in [("pairs", 1), ("pairs", True), ("go", "latest"), ("reference", "HEAD"),
                           ("min_corpus_files", 0), ("max_time_ratio", float("nan")),
                           ("max_time_ratio", float("inf")), ("max_time_ratio", True), ("max_bytes_ratio", .9)]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                validate_policy(self.policy | {key: value})

    def test_manifest_detects_empty_missing_and_changed_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(ValueError):
                corpus_manifest(root)
            with self.assertRaises(FileNotFoundError):
                corpus_manifest(root / "missing")
            (root / "a.go").write_bytes(b"package a\n")
            (root / "empty").touch()
            first = corpus_manifest(root)
            self.assertEqual(first["files"], 1)
            self.assertEqual(first["bytes"], 10)
            self.assertEqual(first, corpus_manifest(root))
            (root / "a.go").write_bytes(b"package b\n")
            self.assertNotEqual(first["sha256"], corpus_manifest(root)["sha256"])
            try:
                (root / "link").symlink_to(root / "a.go")
            except OSError:
                return
            self.assertEqual(corpus_manifest(root)["files"], 1)


if __name__ == "__main__":
    unittest.main()
