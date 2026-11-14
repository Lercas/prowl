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


class FrozenAugmentationTests(unittest.TestCase):
    def test_original_buckets_and_transitive_links_are_preserved(self):
        from train_portable import extend_partition
        base = [
            {"value": "train-value", "text": "train-carrier=train-value", "label_type": "secret"},
            {"value": "val-value", "text": "val-carrier=val-value", "label_type": "secret"},
            {"value": "test-value", "text": "test-carrier=test-value", "label_type": "secret"},
        ]
        frozen = {"train": [0], "val": [1], "test": [2]}
        augmentation = [
            {"value": "train-value", "text": "new=train-value", "label_type": "secret"},
            {"value": "extra", "text": "new=extra", "label_type": "secret"},
            {"value": "test-value", "text": "other=test-value", "label_type": "secret"},
            {"value": "val-value", "text": "bridge=val-value", "label_type": "secret"},
            {"value": "test-value", "text": "bridge=test-value", "label_type": "secret"},
        ]
        split, excluded = extend_partition(base, frozen, augmentation, 13)
        self.assertEqual(list(split["train"]), [0, 3, 4])
        self.assertEqual(list(split["val"]), [1])
        self.assertEqual(list(split["test"]), [2])
        self.assertEqual(sorted(excluded), [2, 3, 4])

    def test_multibyte_character_spans_mask_the_same_carrier(self):
        from train_portable import record_template
        records = [{"value": value, "text": '"пароль":"' + value + '"',
                    "span": [10, 10 + len(value)]} for value in ["ЖукЖук🦋", "КитКит🐳"]]
        self.assertEqual(record_template(records[0]), record_template(records[1]))


if __name__ == "__main__":
    unittest.main()
