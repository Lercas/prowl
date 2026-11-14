import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from gate import GateError, evaluate, load_cases, qualify, strict_json


class QualityGateTests(unittest.TestCase):
    def setUp(self):
        self.cases = [{"id": "pb-00000", "text": "owned synthetic candidate", "label": 1, "source": "code"},
                      {"id": "pb-00001", "text": "ordinary", "label": 0, "source": "log"}]
        self.baseline = {"recall": .7469, "t4_fp_rate": .058, "tolerance": .005}
        self.inputs = {"/owned/positive.py": "pb-00000", "/owned/negative.log": "pb-00001"}
        self.report = {"complete": True, "truncated": False, "completion_reason": "completed",
                       "secrets_revealed": False, "stats": {"processed": 2, "bytes": sum(len(row["text"].encode()) for row in self.cases)},
                       "findings": [{"path": "/owned/positive.py"}]}

    def test_exact_counts_and_regression_thresholds(self):
        good = evaluate(self.cases, self.report, self.baseline, self.inputs)
        self.assertTrue(good["passed"])
        self.assertEqual(good["secret_hits"], 1)
        self.assertEqual(good["false_positive_ids"], [])
        self.report["findings"] = []
        bad = evaluate(self.cases, self.report, self.baseline, self.inputs)
        self.assertFalse(bad["passed"])
        self.assertEqual(bad["missed_positive_ids"], ["pb-00000"])
        self.report["findings"] = [{"path": path} for path in self.inputs]
        self.assertFalse(evaluate(self.cases, self.report, self.baseline, self.inputs)["passed"])

    def test_diagnostics_and_wrong_coverage_cannot_be_scored(self):
        for key, value in [("complete", False), ("complete", None), ("truncated", True),
                           ("completion_reason", "incomplete"), ("secrets_revealed", True),
                           ("findings", {}), ("stats", {"processed": 1})]:
            with self.subTest(key=key):
                report = dict(self.report, **{key: value})
                with self.assertRaises(GateError):
                    evaluate(self.cases, report, self.baseline, self.inputs)
        self.report["findings"] = [{"path": "/owned/unrelated.py"}]
        with self.assertRaises(GateError):
            evaluate(self.cases, self.report, self.baseline, self.inputs)

    def test_duplicate_findings_count_once_per_file(self):
        self.report["findings"] *= 3
        self.assertEqual(evaluate(self.cases, self.report, self.baseline, self.inputs)["secret_hits"], 1)

    def test_json_is_strict(self):
        for raw in [b'{"complete":true,"complete":false}', b'{"score":NaN}', b'{"score":Infinity}', b'not JSON']:
            with self.subTest(raw=raw), self.assertRaises(GateError):
                strict_json(raw)

    def fixture(self, directory):
        path = Path(directory) / "corpus.jsonl"
        data = ("\n".join(json.dumps(row) for row in self.cases) + "\n").encode()
        path.write_bytes(data)
        spec = {"sha256": hashlib.sha256(data).hexdigest(), "rows": 2, "selection_stride": 1,
                "selected_rows": 2, "secrets": 1, "hard_negatives": 1}
        return path, {"dataset": spec, "baseline": self.baseline}

    def test_corpus_identity_and_composition_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            path, policy = self.fixture(directory)
            self.assertEqual(load_cases(path, policy), self.cases)
            for key, value in [("sha256", "0" * 64), ("rows", 3), ("secrets", 0), ("selected_rows", 1)]:
                changed = copy.deepcopy(policy)
                changed["dataset"][key] = value
                with self.subTest(key=key), self.assertRaises(GateError):
                    load_cases(path, changed)
            with self.assertRaises(GateError):
                load_cases(Path(directory) / "missing", policy)
            path.write_bytes(b"")
            with self.assertRaises(GateError):
                load_cases(path, policy)

    def test_subprocess_environment_and_exit_status(self):
        with tempfile.TemporaryDirectory() as directory:
            path, policy = self.fixture(directory)
            root = Path(directory) / "run"
            root.mkdir()
            def process(command, **kwargs):
                self.assertEqual(command[1], "scan")
                for flag in ("--ml", "--bundled", "--format=json", "--no-dedupe"):
                    self.assertIn(flag, command)
                self.assertFalse(any(flag.startswith("--verify") for flag in command))
                self.assertNotIn("PROWL_SEMANTIC_URL", kwargs["env"])
                self.assertNotIn("PROWL_ML_URL", kwargs["env"])
                self.assertEqual(kwargs["env"]["PROWL_HOME"], str(root / "home"))
                self.assertEqual(kwargs["cwd"], root)
                report = dict(self.report, findings=[{"path": str(root / "cases/pb-00000.py")}])
                kwargs["stdout"].write(json.dumps(report).encode())
                return type("Result", (), {"returncode": 0})()
            with patch.dict("os.environ", {"PROWL_SEMANTIC_URL": "private", "PROWL_ML_URL": "private"}), patch("gate.subprocess.run", side_effect=process):
                self.assertTrue(qualify(Path("/owned/binary"), path, policy, root)["passed"])
        for code in (1, 2, -9):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                path, policy = self.fixture(directory)
                root = Path(directory) / "run"
                root.mkdir()
                with patch("gate.subprocess.run", return_value=type("Result", (), {"returncode": code})()), self.assertRaises(GateError):
                    qualify(Path("/owned/binary"), path, policy, root)

    def test_workflows_pin_the_same_corpus_and_run_the_gate(self):
        root = Path(__file__).resolve().parents[2]
        policy = strict_json((Path(__file__).with_name("policy.json")).read_bytes())
        for name in ("ci.yml", "release.yml"):
            workflow = (root / ".github/workflows" / name).read_text()
            self.assertIn("repository: " + policy["dataset"]["repository"], workflow)
            self.assertIn("ref: " + policy["dataset"]["revision"], workflow)
            self.assertIn("python3 scripts/quality/gate.py", workflow)
            self.assertIn("--dataset .quality-corpus/" + policy["dataset"]["file"], workflow)

    def test_nonfinite_or_invalid_thresholds_fail(self):
        for value in (float("nan"), float("inf"), -1, 1.01, "0.5", True):
            baseline = dict(self.baseline, recall=value)
            with self.subTest(value=value), self.assertRaises(GateError):
                evaluate(self.cases, self.report, baseline, self.inputs)


if __name__ == "__main__":
    unittest.main()
