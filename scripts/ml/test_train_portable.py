"""Regression checks for leakage-safe portable-model qualification."""

import unittest

from train_portable import partition


class PartitionTests(unittest.TestCase):
    def test_transitive_value_and_template_links_stay_together(self):
        records = [
            {"value": "a", "text": 'key="a"', "label_type": "secret"},
            {"value": "b", "text": 'key="b"', "label_type": "secret"},
            {"value": "b", "text": 'other="b"', "label_type": "secret"},
            {"value": "c", "text": 'other="c"', "label_type": "secret"},
        ]
        records += [{"value": f"sample{i}", "text": f"template{i}=sample{i}",
                     "label_type": "secret"} for i in range(30)]
        split = partition(records, 13)
        assignment = {int(index): bucket for bucket, indices in split.items() for index in indices}
        self.assertEqual(len(assignment), len(records))
        self.assertEqual(len({assignment[i] for i in range(4)}), 1)
        again = partition(records, 13)
        self.assertTrue(all((indices == again[key]).all() for key, indices in split.items()))


if __name__ == "__main__":
    unittest.main()
