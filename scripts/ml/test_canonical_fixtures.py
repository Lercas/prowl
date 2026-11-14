"""Checks for synthetic canonical-data provenance and evaluation isolation."""

import collections
import unittest

from canonical_fixtures import HELD_OUT, NAMES, annotations


class CanonicalFixturesTests(unittest.TestCase):
    def test_deterministic_balanced_and_evaluation_values_are_absent(self):
        rows = list(annotations(per_family=24))
        self.assertEqual(rows, list(annotations(per_family=24)))
        self.assertEqual(collections.Counter(row["label_binary"] for row in rows), {0: 1152, 1: 720})
        self.assertEqual(collections.Counter(row["path"].split(".")[-1] for row in rows), {"json": 624, "yaml": 624, "toml": 624})
        self.assertFalse({row["value"] for row in rows} & HELD_OUT)
        self.assertTrue(all(row["text"] and row["value"] and row["label_type"] for row in rows))

    def test_positive_values_cover_each_rare_family_and_negative_namespace_is_explicit(self):
        rows = list(annotations(per_family=24))
        positive = [r for r in rows if r["label_binary"]]
        for predicate in [lambda v: not v.isascii(), lambda v: "\n" in v,
                          lambda v: "<" in v and ">" in v, lambda v: "${" in v,
                          lambda v: "{{" in v]:
            self.assertTrue(any(predicate(row["value"]) for row in positive))
        for namespace in ("settings", "validation"):
            self.assertTrue(any(namespace in row["text"] for row in rows if row["label_binary"]))
            self.assertTrue(any(namespace in row["text"] for row in rows if not row["label_binary"]))
        for name in NAMES:
            self.assertTrue(any(name in row["text"] or name.encode("unicode_escape").decode() in row["text"] for row in positive))


if __name__ == "__main__":
    unittest.main()
