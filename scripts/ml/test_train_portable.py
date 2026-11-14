"""Regression checks for leakage-safe portable-model qualification."""

import unittest

from train_portable import partition, select_candidate


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


class SelectionTests(unittest.TestCase):
    def test_negligible_validation_gain_prefers_smaller_tree(self):
        self.assertEqual(select_candidate({31: {"f1": .98813},
                                           63: {"f1": .98903},
                                           127: {"f1": .98905}}), 63)

    def test_substantial_validation_gain_is_retained(self):
        self.assertEqual(select_candidate({31: {"f1": .98},
                                           63: {"f1": .99},
                                           127: {"f1": .991}}), 127)


if __name__ == "__main__":
    unittest.main()
